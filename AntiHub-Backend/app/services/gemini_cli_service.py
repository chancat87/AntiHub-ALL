"""
GeminiCLI 账号服务

功能范围：
- 生成 Google OAuth 登录链接（带 state）
- 解析回调 URL，交换 token
- 执行 Onboarding 流程（loadCodeAssist/onboardUser）
- 启用 cloudaicompanion API
- 导入/导出账号凭证（JSON）
- Token 刷新
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
import json
import logging
import os
import secrets
from urllib.parse import urlencode, urlparse, parse_qs

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache import RedisClient
from app.repositories.gemini_cli_account_repository import GeminiCLIAccountRepository
from app.utils.encryption import encrypt_api_key as encrypt_secret
from app.utils.encryption import decrypt_api_key as decrypt_secret

# Google OAuth 配置（使用 Gemini CLI 官方配置）
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# Gemini CLI 官方 OAuth 配置（可用环境变量覆盖，默认值对齐参考项目 CLIProxyAPI）
# 注意：OAuth client_id/client_secret 只用于“发起 OAuth / 交换 token”，并不会让普通用户越权访问任何内部数据；
#      真实权限仍由用户账号本身的授权与 GCP 项目侧开关决定。
GOOGLE_CLIENT_ID = os.getenv(
    "GEMINI_CLI_OAUTH_CLIENT_ID",
    "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com",
)
GOOGLE_CLIENT_SECRET = os.getenv(
    "GEMINI_CLI_OAUTH_CLIENT_SECRET",
    "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",
)

# OAuth 回调（兼容 CLIProxyAPI 的 8085 端口）
GOOGLE_REDIRECT_URI = os.getenv(
    "GEMINI_CLI_OAUTH_REDIRECT_URI",
    "http://localhost:8085/oauth2callback",
)

# OAuth Scopes（获取邮箱信息、offline_access 以及支持 onboarding/启用 API 的权限）
# - openid email profile: 获取用户基本信息
# - https://www.googleapis.com/auth/cloud-platform: 覆盖列项目/启用 API 所需权限（最少踩坑）
# - https://www.googleapis.com/auth/userinfo.email / userinfo.profile: 获取邮箱/头像等信息
OAUTH_SCOPE = os.getenv(
    "GEMINI_CLI_OAUTH_SCOPE",
    "https://www.googleapis.com/auth/cloud-platform "
    "https://www.googleapis.com/auth/userinfo.email "
    "https://www.googleapis.com/auth/userinfo.profile",
)
OAUTH_SESSION_TTL_SECONDS = 10 * 60

# Gemini CLI (cloudcode-pa) API
CLOUDCODE_PA_BASE_URL = "https://cloudcode-pa.googleapis.com/v1internal"
SERVICE_USAGE_BASE_URL = "https://serviceusage.googleapis.com/v1"

# 必需的 Header
DEFAULT_USER_AGENT = "google-api-nodejs-client/9.15.1"
DEFAULT_X_GOOG_API_CLIENT = "gl-node/22.17.0"
DEFAULT_CLIENT_METADATA = "ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI"

logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _generate_state() -> str:
    # gem- 开头的 state，与参考项目一致
    return f"gem-{secrets.token_hex(8)}"


def _parse_oauth_callback(input_str: str) -> Dict[str, str]:
    """
    解析 OAuth 回调 URL（兼容用户粘贴的多种形式）
    """
    trimmed = (input_str or "").strip()
    if not trimmed:
        raise ValueError("callback_url 不能为空")

    # 兼容各种格式的输入
    candidate = trimmed
    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = "http://localhost" + candidate
        elif "=" in candidate:
            candidate = "http://localhost/?" + candidate
        else:
            raise ValueError("callback_url 不是合法的 URL 或 query")

    parsed = urlparse(candidate)
    q = parse_qs(parsed.query)

    code = (q.get("code", [""])[0] or "").strip()
    state = (q.get("state", [""])[0] or "").strip()
    err = (q.get("error", [""])[0] or "").strip()
    err_desc = (q.get("error_description", [""])[0] or "").strip()

    if not err and err_desc:
        err = err_desc

    if not code and not err:
        raise ValueError("callback_url 缺少 code")
    if not state:
        raise ValueError("callback_url 缺少 state")

    return {"code": code, "state": state, "error": err, "error_description": err_desc}


def _default_account_name(email: Optional[str]) -> str:
    """默认账号名称：邮箱前缀"""
    if not email:
        return "GeminiCLI Account"
    local = email.split("@", 1)[0]
    return f"gemini-{local[:8]}" if len(local) > 8 else f"gemini-{local}"


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    """解析 ISO8601 格式的日期时间字符串"""
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    s = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _extract_project_id(value: Any) -> str:
    """
    从 cloudcode-pa 返回的字段中提取 project_id

    兼容格式：
    - "my-project-id"
    - {"id":"my-project-id"}
    - {"projectId":"my-project-id"} / {"project_id":"my-project-id"}
    """
    if not value:
        return ""

    if isinstance(value, str):
        return value.strip()

    if isinstance(value, dict):
        for key in ("id", "projectId", "project_id"):
            v = value.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()

    return ""


def _pick_first_project_id(value: Optional[str]) -> Optional[str]:
    """
    从 project_id 字符串中选择一个可用的项目 ID。

    约定：
    - 支持逗号分隔（多项目）
    - 返回第一个非空且不是 "ALL" 的值
    """
    if not isinstance(value, str):
        return None
    for part in value.split(","):
        candidate = part.strip()
        if not candidate:
            continue
        if candidate.upper() == "ALL":
            continue
        return candidate
    return None


def _to_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return float(value)
        except Exception:
            return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if s.endswith("%"):
            try:
                return float(s[:-1]) / 100.0
            except Exception:
                return None
        try:
            return float(s)
        except Exception:
            return None
    return None


def _default_tier_id(load_code_assist_resp: Dict[str, Any]) -> str:
    """
    从 loadCodeAssist 返回值中解析默认 tierId

    与参考项目 CLIProxyAPI / AntiHub-plugin 保持一致：fallback 为 legacy-tier
    """
    fallback = "legacy-tier"
    tiers = load_code_assist_resp.get("allowedTiers")
    if not isinstance(tiers, list):
        return fallback

    for tier in tiers:
        if not isinstance(tier, dict):
            continue
        if tier.get("isDefault") is True:
            tier_id = tier.get("id")
            if isinstance(tier_id, str) and tier_id.strip():
                return tier_id.strip()

    return fallback


class GeminiCLIService:
    def __init__(self, db: AsyncSession, redis: RedisClient):
        self.db = db
        self.redis = redis
        self.repo = GeminiCLIAccountRepository(db)

    async def create_oauth_authorize_url(
        self,
        user_id: int,
        *,
        is_shared: int = 0,
        account_name: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        生成 Google OAuth 登录链接

        关键参数：
        - access_type=offline: 获取 refresh_token
        - prompt=consent: 强制弹出同意屏幕
        """
        if is_shared not in (0, 1):
            raise ValueError("is_shared 必须是 0 或 1")

        state = _generate_state()

        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "scope": OAUTH_SCOPE,
            "state": state,
            "access_type": "offline",  # 关键：获取 refresh_token
            "prompt": "consent",  # 关键：确保返回 refresh_token
        }

        auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"

        expires_in = OAUTH_SESSION_TTL_SECONDS
        now = _now_utc()
        session_payload = {
            "user_id": user_id,
            "is_shared": is_shared,
            "account_name": (account_name or "").strip() or None,
            "project_id": (project_id or "").strip() or None,
            "created_at": _iso(now),
            "expires_at": _iso(now + timedelta(seconds=expires_in)),
        }
        await self.redis.set_json(
            f"gemini_cli_oauth:{state}",
            session_payload,
            expire=expires_in,
        )

        return {
            "success": True,
            "data": {
                "auth_url": auth_url,
                "state": state,
                "expires_in": expires_in,
            },
        }

    async def submit_oauth_callback(
        self,
        user_id: int,
        callback_url: str,
    ) -> Dict[str, Any]:
        """
        提交 OAuth 回调 URL 并落库

        流程：
        1. 解析回调 URL 获取 code 和 state
        2. 验证 state
        3. 用 code 换取 token
        4. 获取用户信息
        5. 自动选择/校验 project_id，并执行 onboarding（loadCodeAssist/onboardUser/启用 API）
        6. 落库保存
        """
        parsed = _parse_oauth_callback(callback_url)
        state = parsed["state"]
        code = parsed["code"]
        err = parsed["error"]
        if err:
            raise ValueError(f"OAuth 登录失败: {err}")

        # 验证 state
        key = f"gemini_cli_oauth:{state}"
        session = await self.redis.get_json(key)
        if not session:
            raise ValueError("state 不存在或已过期，请重新生成登录链接")
        if int(session.get("user_id") or 0) != int(user_id):
            raise ValueError("state 不属于当前用户")

        # 交换 token
        token_resp = await self._exchange_code_for_tokens(code)

        now = _now_utc()
        expires_in = int(token_resp.get("expires_in") or 3600)
        expires_at = now + timedelta(seconds=expires_in)

        # 获取用户信息
        access_token = (token_resp.get("access_token") or "").strip()
        userinfo = await self._get_userinfo(access_token)
        email = userinfo.get("email", "")

        # 存储 token（转换为 map 格式）
        storage_payload = {
            "access_token": access_token,
            "refresh_token": (token_resp.get("refresh_token") or "").strip(),
            "token_type": token_resp.get("token_type", "Bearer"),
            "expires_at": _iso(expires_at),
            "issued_at": _iso(now),
        }
        encrypted_credentials = encrypt_secret(
            json.dumps(storage_payload, ensure_ascii=False)
        )

        account_name = (session.get("account_name") or "").strip()
        if not account_name:
            account_name = _default_account_name(email)

        project_id = (session.get("project_id") or "").strip() or None
        is_all_projects = isinstance(project_id, str) and project_id.strip().upper() == "ALL"
        explicit_project = bool(project_id) and not is_all_projects

        # 检查是否已存在
        existing = await self.repo.get_by_user_id_and_email(user_id, email)

        # project_id 留空时自动获取（并标记 auto_project）
        auto_project = (not explicit_project) and (not is_all_projects)
        checked = False

        try:
            if is_all_projects:
                project_id, checked = await self._perform_onboarding_all_projects(access_token)
            else:
                resolved_project_id, checked = await self._perform_onboarding(
                    access_token,
                    project_id=project_id,
                    explicit_project=explicit_project,
                )
                # 未指定 project_id 时，以 onboarding 返回/推断结果为准
                if not explicit_project and resolved_project_id:
                    project_id = resolved_project_id
        except Exception as e:
            logger.warning(
                "gemini_cli onboarding failed: email=%s project=%s error=%s",
                email,
                project_id,
                str(e),
            )
            # onboarding 失败不影响落库，只是 checked=False

        if existing:
            updated = await self.repo.update_credentials_and_profile(
                existing.id,
                user_id,
                account_name=account_name,
                credentials=encrypted_credentials,
                email=email,
                project_id=project_id,
                auto_project=auto_project,
                checked=checked,
                token_expires_at=expires_at,
                last_refresh_at=now,
            )
            account = updated or existing
        else:
            account = await self.repo.create(
                user_id=user_id,
                account_name=account_name,
                is_shared=int(session.get("is_shared") or 0),
                status=1,
                credentials=encrypted_credentials,
                email=email,
                project_id=project_id,
                auto_project=auto_project,
                checked=checked,
                token_expires_at=expires_at,
                last_refresh_at=now,
            )

        # 消耗 state
        await self.redis.delete(key)

        return {"success": True, "data": account}

    async def import_account(
        self,
        user_id: int,
        *,
        credential_json: str,
        is_shared: int = 0,
        account_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        导入 GeminiCLI 账号凭证 JSON

        支持格式：
        1. 嵌套格式（GeminiCLI 导出）：
           {
               "token": {
                   "access_token": "...",
                   "refresh_token": "...",
                   ...
               },
               "project_id": "...",
               "email": "...",
               ...
           }
        2. 扁平格式：
           {
               "access_token": "...",
               "refresh_token": "...",
               ...
           }

        导入后立即使用 refresh_token 刷新 access_token
        """
        if is_shared not in (0, 1):
            raise ValueError("is_shared 必须是 0 或 1")

        raw = (credential_json or "").strip()
        if not raw:
            raise ValueError("credential_json 不能为空")

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError("credential_json 不是合法 JSON") from e
        if not isinstance(payload, dict):
            raise ValueError("credential_json 必须是 JSON object")

        # 支持 token 字段嵌套
        token_obj = payload.get("token", {})
        if isinstance(token_obj, dict) and token_obj:
            # 嵌套格式：提取 token 内的字段到外层
            nested = token_obj
        else:
            # 扁平格式：直接使用 payload
            nested = payload

        access_token = (nested.get("access_token") or "").strip()
        refresh_token = (nested.get("refresh_token") or "").strip()
        email = (payload.get("email") or nested.get("email") or "").strip() or None
        project_id = (payload.get("project_id") or nested.get("project_id") or "").strip() or None
        token_type = nested.get("token_type", "Bearer")
        client_id = nested.get("client_id", "").strip()
        client_secret = nested.get("client_secret", "").strip()

        # 必须有 refresh_token 才能导入和刷新
        if not refresh_token:
            raise ValueError("credential_json 缺少 refresh_token（刷新 token 所需）")

        # 如果没有指定 client_id/client_secret，使用 Gemini CLI 官方配置
        if not client_id:
            client_id = GOOGLE_CLIENT_ID
        if not client_secret:
            client_secret = GOOGLE_CLIENT_SECRET

        now = _now_utc()

        # 立即用 refresh_token 刷新 access_token
        refreshed = False
        try:
            form = {
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    GOOGLE_TOKEN_URL,
                    data=form,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "application/json",
                    },
                )

            if resp.status_code != 200:
                raise ValueError(f"token 刷新失败: HTTP {resp.status_code}")

            data = resp.json()
            if "error" in data:
                err_desc = data.get("error_description", data.get("error"))
                raise ValueError(f"刷新 token 时 OAuth 错误: {err_desc}")

            # 使用刷新后的 token
            access_token = (data.get("access_token") or "").strip()
            new_refresh_token = (data.get("refresh_token") or refresh_token).strip()
            token_type = data.get("token_type", "Bearer")

            expires_in = int(data.get("expires_in") or 3600)
            token_expires_at = now + timedelta(seconds=expires_in)
            refreshed = True

            logger.info(
                "gemini_cli import: refreshed token successfully email=%s",
                email or "unknown",
            )

        except Exception as e:
            # 刷新失败，但仍然允许导入（使用原始凭证）
            logger.warning(
                "gemini_cli import: refresh token failed, using original token email=%s error=%s",
                email or "unknown",
                str(e),
            )

            # 解析原始 token 过期时间
            token_expires_at = None
            expires_in = nested.get("expires_in")
            if isinstance(expires_in, (int, float, str)):
                try:
                    expires_in_seconds = int(expires_in)
                    if expires_in_seconds > 0:
                        token_expires_at = now + timedelta(seconds=expires_in_seconds)
                except (ValueError, TypeError):
                    pass

            if token_expires_at is None:
                expires_at_str = (
                    nested.get("expires_at")
                    or nested.get("expired")
                    or nested.get("expiry")
                    or ""
                )
                if isinstance(expires_at_str, str):
                    token_expires_at = _parse_iso_datetime(expires_at_str)
                elif isinstance(expires_at_str, (int, float)):
                    try:
                        token_expires_at = datetime.fromtimestamp(
                            int(expires_at_str), tz=timezone.utc
                        )
                    except (ValueError, TypeError, OSError):
                        pass

            new_refresh_token = refresh_token

        # 规范化并加密存储（使用刷新后的凭证）
        normalized = {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": token_type,
            "email": email or "",
            "project_id": project_id or "",
        }
        encrypted_credentials = encrypt_secret(
            json.dumps(normalized, ensure_ascii=False)
        )

        final_name = (account_name or "").strip()
        if not final_name:
            final_name = _default_account_name(email)

        existing = None
        if email:
            existing = await self.repo.get_by_user_id_and_email(user_id, email)

        if existing:
            updated = await self.repo.update_credentials_and_profile(
                existing.id,
                user_id,
                account_name=final_name,
                credentials=encrypted_credentials,
                email=email,
                project_id=project_id,
                token_expires_at=token_expires_at,
                last_refresh_at=now if refreshed else None,
            )
            account = updated or existing
        else:
            account = await self.repo.create(
                user_id=user_id,
                account_name=final_name,
                is_shared=is_shared,
                status=1,
                credentials=encrypted_credentials,
                email=email,
                project_id=project_id,
                token_expires_at=token_expires_at,
                last_refresh_at=now if refreshed else None,
            )

        return {"success": True, "data": account}

    async def list_accounts(self, user_id: int) -> Dict[str, Any]:
        accounts = await self.repo.list_by_user_id(user_id)
        return {"success": True, "data": list(accounts)}

    async def get_account(
        self,
        user_id: int,
        account_id: int,
    ) -> Dict[str, Any]:
        account = await self.repo.get_by_id_and_user_id(account_id, user_id)
        if not account:
            raise ValueError("账号不存在")
        return {"success": True, "data": account}

    async def export_account_credentials(
        self,
        user_id: int,
        account_id: int,
    ) -> Dict[str, Any]:
        account = await self.repo.get_by_id_and_user_id(account_id, user_id)
        if not account:
            raise ValueError("账号不存在")
        decrypted = decrypt_secret(account.credentials)
        try:
            credential_obj = json.loads(decrypted)
        except Exception:
            credential_obj = {"raw": decrypted}
        return {"success": True, "data": credential_obj}

    async def update_account_status(
        self,
        user_id: int,
        account_id: int,
        status: int,
    ) -> Dict[str, Any]:
        if status not in (0, 1):
            raise ValueError("status 必须是 0 或 1")
        account = await self.repo.update_status(account_id, user_id, status)
        if not account:
            raise ValueError("账号不存在")
        return {"success": True, "data": account}

    async def update_account_name(
        self,
        user_id: int,
        account_id: int,
        account_name: str,
    ) -> Dict[str, Any]:
        name = (account_name or "").strip()
        if not name:
            raise ValueError("account_name 不能为空")
        account = await self.repo.update_name(account_id, user_id, name)
        if not account:
            raise ValueError("账号不存在")
        return {"success": True, "data": account}

    async def update_account_project(
        self,
        user_id: int,
        account_id: int,
        project_id: Optional[str],
    ) -> Dict[str, Any]:
        account = await self.repo.update_project(account_id, user_id, project_id)
        if not account:
            raise ValueError("账号不存在")
        return {"success": True, "data": account}

    async def delete_account(
        self,
        user_id: int,
        account_id: int,
    ) -> Dict[str, Any]:
        ok = await self.repo.delete(account_id, user_id)
        if not ok:
            raise ValueError("账号不存在")
        return {"success": True, "data": {"deleted": True}}

    async def _exchange_code_for_tokens(
        self,
        code: str,
    ) -> Dict[str, Any]:
        """用授权码换取 access_token 和 refresh_token"""
        form = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                GOOGLE_TOKEN_URL,
                data=form,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )

        if resp.status_code != 200:
            raise ValueError(f"token 交换失败: HTTP {resp.status_code}")

        data = resp.json()
        if not isinstance(data, dict):
            raise ValueError("token 响应格式异常")

        if "error" in data:
            err_desc = data.get("error_description", data.get("error"))
            raise ValueError(f"OAuth 错误: {err_desc}")

        return data

    async def _get_userinfo(self, access_token: str) -> Dict[str, Any]:
        """获取 Google 用户信息"""
        url = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json"
        headers = {"Authorization": f"Bearer {access_token}"}

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=headers)

        if resp.status_code != 200:
            logger.warning("get userinfo failed: HTTP %s", resp.status_code)
            return {}

        return resp.json()

    async def _perform_onboarding(
        self,
        access_token: str,
        *,
        project_id: Optional[str],
        explicit_project: bool,
    ) -> Tuple[Optional[str], bool]:
        """
        执行 Gemini CLI Onboarding 流程

        步骤：
        1. loadCodeAssist - 加载代码助手
        2. onboardUser - 用户入驻（可能需要轮询）
        3. enableCloudAIAPI - 启用 Cloud AI API
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "User-Agent": DEFAULT_USER_AGENT,
            "X-Goog-Api-Client": DEFAULT_X_GOOG_API_CLIENT,
            "Client-Metadata": DEFAULT_CLIENT_METADATA,
        }

        resolved_project_id: Optional[str] = (project_id or "").strip() or None

        # 1. loadCodeAssist（project_id 可选）
        load_resp = await self._call_load_code_assist(headers, project_id=resolved_project_id)
        tier_id = _default_tier_id(load_resp)

        if not resolved_project_id:
            resolved_project_id = _extract_project_id(load_resp.get("cloudaicompanionProject")) or None

        # 2. onboardUser（project_id 可选；done 轮询）
        onboard_resp = await self._call_onboard_user(
            headers,
            tier_id=tier_id,
            project_id=resolved_project_id,
        )

        onboard_project_id = _extract_project_id(
            (onboard_resp.get("response") or {}).get("cloudaicompanionProject")
            or onboard_resp.get("cloudaicompanionProject")
        )

        # 若用户未显式指定 project_id，则优先使用 onboardUser 返回的真实 project_id
        if not explicit_project and onboard_project_id:
            resolved_project_id = onboard_project_id

        # 兜底：仍然拿不到 project_id 时，尝试通过 Cloud Resource Manager 拉项目列表选第一个
        if not resolved_project_id:
            resolved_project_id = await self._try_pick_first_gcp_project(access_token)

        if not resolved_project_id:
            return None, False

        # 3. enable Cloud AI API，并回读确认
        checked = await self._ensure_cloud_ai_api_enabled(access_token, resolved_project_id)
        return resolved_project_id, checked

    async def _perform_onboarding_all_projects(
        self,
        access_token: str,
    ) -> Tuple[Optional[str], bool]:
        """
        project_id=ALL：对该账号可见的所有 GCP Project 逐个执行 onboarding。

        返回值：
        - project_id: 逗号分隔的 projectId 列表（仅保留 onboarding + Cloud AI API 校验成功的项目）
        - checked: 是否成功获得至少一个可用项目
        """
        project_ids = await self._fetch_gcp_project_ids(access_token)
        if not project_ids:
            return None, False

        enabled: List[str] = []
        for pid in project_ids:
            try:
                resolved, ok = await self._perform_onboarding(
                    access_token,
                    project_id=pid,
                    explicit_project=True,
                )
                if resolved and ok:
                    enabled.append(resolved)
            except Exception as e:
                logger.warning(
                    "gemini_cli onboard all projects failed: project=%s error=%s",
                    pid,
                    str(e),
                )

        # 去重但保序
        uniq_enabled: List[str] = []
        seen = set()
        for pid in enabled:
            if pid in seen:
                continue
            uniq_enabled.append(pid)
            seen.add(pid)

        if not uniq_enabled:
            return None, False

        return ",".join(uniq_enabled), True

    async def _call_load_code_assist(
        self,
        headers: Dict[str, str],
        *,
        project_id: Optional[str],
    ) -> Dict[str, Any]:
        """调用 loadCodeAssist 接口（返回 JSON）"""
        url = f"{CLOUDCODE_PA_BASE_URL}:loadCodeAssist"
        body = {
            "metadata": {
                "ideType": "IDE_UNSPECIFIED",
                "platform": "PLATFORM_UNSPECIFIED",
                "pluginType": "GEMINI",
            },
        }
        if project_id:
            body["cloudaicompanionProject"] = project_id

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(url, json=body, headers=headers)

        if resp.status_code == 204:
            return {}

        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, dict) else {}

        if resp.status_code not in (200, 204):
            logger.warning(
                "loadCodeAssist failed: HTTP %s, response: %s",
                resp.status_code,
                resp.text[:500],
            )
        return {}

    async def _call_onboard_user(
        self,
        headers: Dict[str, str],
        *,
        tier_id: str,
        project_id: Optional[str],
    ) -> Dict[str, Any]:
        """
        调用 onboardUser 接口

        使用 loadCodeAssist 的默认 tier，可能需要轮询等待完成
        """
        url = f"{CLOUDCODE_PA_BASE_URL}:onboardUser"
        body = {
            "tierId": tier_id,
            "metadata": {
                "ideType": "IDE_UNSPECIFIED",
                "platform": "PLATFORM_UNSPECIFIED",
                "pluginType": "GEMINI",
            },
        }
        if project_id:
            body["cloudaicompanionProject"] = project_id

        last_payload: Dict[str, Any] = {}
        max_attempts = 5
        retry_delay_seconds = 2.0

        async with httpx.AsyncClient(timeout=60.0) as client:
            for attempt in range(1, max_attempts + 1):
                resp = await client.post(url, json=body, headers=headers)

                if resp.status_code == 204:
                    return {}

                if resp.status_code != 200:
                    logger.warning(
                        "onboardUser failed: HTTP %s, response: %s",
                        resp.status_code,
                        resp.text[:500],
                    )
                    return {}

                data = resp.json() if resp.status_code == 200 else {}
                last_payload = data if isinstance(data, dict) else {}

                if last_payload.get("done") is True:
                    return last_payload

                if attempt < max_attempts:
                    await asyncio.sleep(retry_delay_seconds)

        return last_payload

    async def _check_cloud_ai_api_enabled(
        self,
        access_token: str,
        project_id: str,
    ) -> bool:
        """检查 cloudaicompanion.googleapis.com 是否已启用"""
        service_name = "cloudaicompanion.googleapis.com"
        url = f"{SERVICE_USAGE_BASE_URL}/projects/{project_id}/services/{service_name}"
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.get(url, headers=headers)
        except Exception:
            return False

        if resp.status_code != 200:
            return False

        try:
            data = resp.json()
        except Exception:
            return False

        if not isinstance(data, dict):
            return False

        return (data.get("state") or "").upper() == "ENABLED"

    async def _ensure_cloud_ai_api_enabled(
        self,
        access_token: str,
        project_id: str,
    ) -> bool:
        """
        尝试启用 cloudaicompanion.googleapis.com，并回读确认是否启用成功

        注意：启用 API 可能需要项目已开通计费、账号具备足够权限。
        """
        if await self._check_cloud_ai_api_enabled(access_token, project_id):
            return True

        service_name = "cloudaicompanion.googleapis.com"
        url = f"{SERVICE_USAGE_BASE_URL}/projects/{project_id}/services/{service_name}:enable"
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(url, headers=headers)
        except Exception as e:
            logger.warning("enable Cloud AI API failed: project=%s error=%s", project_id, str(e))
            return False

        if resp.status_code not in (200, 204):
            logger.warning(
                "enable Cloud AI API failed: HTTP %s, response: %s",
                resp.status_code,
                resp.text[:500],
            )
            return False

        return await self._check_cloud_ai_api_enabled(access_token, project_id)

    async def _fetch_gcp_project_ids(self, access_token: str) -> List[str]:
        """从 Cloud Resource Manager 拉取项目列表，返回 projectId 列表（去重、保序）"""
        url = "https://cloudresourcemanager.googleapis.com/v1/projects"
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.get(url, headers=headers)
        except Exception as e:
            logger.warning("fetch gcp projects failed: %s", str(e))
            return []

        if resp.status_code != 200:
            logger.warning(
                "fetch gcp projects failed: HTTP %s, response: %s",
                resp.status_code,
                resp.text[:500],
            )
            return []

        try:
            data = resp.json()
        except Exception:
            return []

        if not isinstance(data, dict):
            return []

        projects = data.get("projects")
        if not isinstance(projects, list):
            return []

        out: List[str] = []
        seen = set()
        for p in projects:
            if not isinstance(p, dict):
                continue
            pid = p.get("projectId")
            if not isinstance(pid, str):
                continue
            pid = pid.strip()
            if not pid or pid in seen:
                continue
            out.append(pid)
            seen.add(pid)

        return out

    async def _try_pick_first_gcp_project(self, access_token: str) -> Optional[str]:
        """兜底：从 Cloud Resource Manager 拉取项目列表并选择第一个 projectId"""
        project_ids = await self._fetch_gcp_project_ids(access_token)
        return project_ids[0] if project_ids else None

    def _load_account_credentials(self, account: Any) -> Dict[str, Any]:
        """加载账号凭证（解密）"""
        decrypted = decrypt_secret(account.credentials)
        try:
            obj = json.loads(decrypted)
        except Exception:
            obj = {}
        return obj if isinstance(obj, dict) else {}

    async def _try_refresh_account(
        self,
        account: Any,
        creds: Dict[str, Any],
    ) -> bool:
        """尝试刷新 access_token"""
        refresh_token = creds.get("refresh_token", "").strip()
        if not refresh_token:
            return False

        try:
            form = {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    GOOGLE_TOKEN_URL,
                    data=form,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "application/json",
                    },
                )

            if resp.status_code != 200:
                return False

            data = resp.json()
            if "error" in data:
                return False

            now = _now_utc()
            expires_in = int(data.get("expires_in") or 3600)
            expires_at = now + timedelta(seconds=expires_in)

            # 更新凭证
            storage_payload = {
                "access_token": (data.get("access_token") or "").strip(),
                "refresh_token": (
                    data.get("refresh_token") or refresh_token
                ).strip(),
                "token_type": data.get("token_type", "Bearer"),
                "expires_at": _iso(expires_at),
                "issued_at": _iso(now),
            }

            encrypted_credentials = encrypt_secret(
                json.dumps(storage_payload, ensure_ascii=False)
            )

            await self.repo.update_credentials_and_profile(
                account.id,
                account.user_id,
                credentials=encrypted_credentials,
                token_expires_at=expires_at,
                last_refresh_at=now,
            )
            await self.db.flush()
            await self.db.commit()
            return True

        except Exception as e:
            logger.warning(
                "refresh gemini_cli token failed: account_id=%s error=%s",
                account.id,
                str(e),
            )
            return False

    async def get_valid_access_token(
        self,
        user_id: int,
        account_id: int,
    ) -> str:
        """
        获取有效的 access_token（自动刷新）

        用于运行时调用 Gemini CLI 接口

        支持仅包含 refresh_token 的账号（会自动刷新）
        """
        account = await self.repo.get_by_id_and_user_id(account_id, user_id)
        if not account:
            raise ValueError("账号不存在")

        creds = self._load_account_credentials(account)

        # 检查是否需要刷新
        now = _now_utc()
        expires_at = account.token_expires_at
        need_refresh = False

        # 情况1: access_token 为空或缺失 - 强制刷新
        access_token = creds.get("access_token", "").strip()
        if not access_token:
            need_refresh = True
        # 情况2: access_token 即将过期 - 提前刷新
        elif isinstance(expires_at, datetime):
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            # 提前 60 秒刷新
            if expires_at <= now + timedelta(seconds=60):
                need_refresh = True

        if need_refresh:
            refreshed = await self._try_refresh_account(account, creds)
            if not refreshed:
                # 刷新失败，尝试使用现有的 access_token
                access_token = creds.get("access_token", "").strip()
                if not access_token:
                    raise ValueError("无法获取有效的 access_token（刷新失败且无可用 token）")
            # 重新加载
            account = await self.repo.get_by_id_and_user_id(account_id, user_id)
            creds = self._load_account_credentials(account)

        access_token = creds.get("access_token", "").strip()
        if not access_token:
            raise ValueError("账号缺少 access_token")

        return access_token

    async def get_account_quota(
        self,
        user_id: int,
        account_id: int,
        *,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        查询 Gemini CLI 剩余额度（cloudcode-pa retrieveUserQuota）。

        说明：
        - 使用账号保存的 OAuth refresh_token 自动刷新 access_token
        - 默认使用账号的 project_id（支持逗号分隔多项目，取第一个）
        - 可通过 project_id 参数覆盖（例如临时查询其它项目）
        """
        account = await self.repo.get_by_id_and_user_id(account_id, user_id)
        if not account:
            raise ValueError("账号不存在")

        project_id_used = _pick_first_project_id(project_id) or _pick_first_project_id(
            getattr(account, "project_id", None)
        )
        if not project_id_used:
            raise ValueError("账号未设置 project_id，请先在账号里填写 GCP Project ID")

        fetched_at = _now_utc()

        async def _request(access_token: str) -> httpx.Response:
            url = f"{CLOUDCODE_PA_BASE_URL}:retrieveUserQuota"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "User-Agent": DEFAULT_USER_AGENT,
                "X-Goog-Api-Client": DEFAULT_X_GOOG_API_CLIENT,
                "Client-Metadata": DEFAULT_CLIENT_METADATA,
            }
            body = {"project": project_id_used}
            async with httpx.AsyncClient(timeout=30.0) as client:
                return await client.post(url, json=body, headers=headers)

        resp: Optional[httpx.Response] = None
        try:
            for attempt in range(2):
                access_token = await self.get_valid_access_token(user_id, account_id)
                resp = await _request(access_token)
                if resp.status_code == 200:
                    break
                if resp.status_code in (401, 403) and attempt == 0:
                    try:
                        creds = self._load_account_credentials(account)
                        await self._try_refresh_account(account, creds)
                        refreshed = await self.repo.get_by_id_and_user_id(account_id, user_id)
                        if refreshed:
                            account = refreshed
                    except Exception:
                        pass
                    continue
                break

            if resp is None:
                raise ValueError("查询额度失败：请求未发出")

            if resp.status_code != 200:
                raise ValueError(
                    f"查询额度失败：上游返回 HTTP {resp.status_code}（{resp.text[:300]}）"
                )

            try:
                raw = resp.json()
            except Exception as e:
                raise ValueError("查询额度失败：上游响应不是合法 JSON") from e

            if not isinstance(raw, dict):
                raise ValueError("查询额度失败：上游响应格式异常（非对象）")

            buckets_raw = raw.get("buckets")
            buckets_in = buckets_raw if isinstance(buckets_raw, list) else []
            buckets: List[Dict[str, Any]] = []
            for entry in buckets_in:
                if not isinstance(entry, dict):
                    continue
                model_id = entry.get("modelId") or entry.get("model_id")
                token_type = entry.get("tokenType") or entry.get("token_type")
                remaining_fraction = _to_float(
                    entry.get("remainingFraction") or entry.get("remaining_fraction")
                )
                remaining_amount = _to_float(
                    entry.get("remainingAmount") or entry.get("remaining_amount")
                )
                reset_time = entry.get("resetTime") or entry.get("reset_time")
                if isinstance(model_id, str):
                    model_id = model_id.strip()
                else:
                    model_id = ""
                if not model_id:
                    continue
                if isinstance(token_type, str):
                    token_type = token_type.strip() or None
                else:
                    token_type = None
                if isinstance(reset_time, str):
                    reset_time = reset_time.strip() or None
                else:
                    reset_time = None

                # 兜底：有些返回可能给的是百分比整数（0-100）
                if remaining_fraction is not None and remaining_fraction > 1.0 and remaining_fraction <= 100.0:
                    remaining_fraction = remaining_fraction / 100.0

                buckets.append(
                    {
                        "model_id": model_id,
                        "token_type": token_type,
                        "remaining_fraction": remaining_fraction,
                        "remaining_amount": remaining_amount,
                        "reset_time": reset_time,
                    }
                )

            return {
                "success": True,
                "data": {
                    "fetched_at": fetched_at,
                    "project_id": project_id_used,
                    "raw": raw,
                    "buckets": buckets,
                },
            }
        finally:
            if resp is not None:
                try:
                    await resp.aclose()
                except Exception:
                    pass
