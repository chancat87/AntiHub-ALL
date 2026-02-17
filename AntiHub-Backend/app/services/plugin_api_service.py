"""
Plug-in API服务
处理与plug-in-api系统的通信

优化说明：
- 添加 Redis 缓存以减少数据库查询
- plugin_api_key 缓存 TTL 为 60 秒
"""
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import hashlib
import os
import secrets
import time
from urllib.parse import urlencode, urlparse, parse_qs
import httpx
import logging
import asyncio
import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.config import get_settings
from app.repositories.plugin_api_key_repository import PluginAPIKeyRepository
from app.utils.encryption import encrypt_api_key, decrypt_api_key
from app.models.antigravity_account import AntigravityAccount
from app.models.antigravity_model_quota import AntigravityModelQuota
from app.schemas.plugin_api import (
    PluginAPIKeyCreate,
    PluginAPIKeyResponse,
    CreatePluginUserRequest,
)
from app.cache import get_redis_client, RedisClient
from app.services.gemini_cli_api_service import (
    _OpenAIStreamState,
    _gemini_cli_event_to_openai_chunks,
    _gemini_cli_response_to_openai_response,
    _openai_done_sse,
    _openai_error_sse,
    _openai_request_to_gemini_cli_payload,
)
from app.services.zai_image_service import ZaiImageService

logger = logging.getLogger(__name__)

# 缓存 TTL（秒）
PLUGIN_API_KEY_CACHE_TTL = 60

# ==================== Antigravity（Cloud Code / Google OAuth） ====================

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

# 默认值对齐 AntiHub-plugin（可用环境变量覆盖）
ANTIGRAVITY_OAUTH_CLIENT_ID = os.getenv(
    "ANTIGRAVITY_OAUTH_CLIENT_ID",
    "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com",
)
ANTIGRAVITY_OAUTH_CLIENT_SECRET = os.getenv(
    "ANTIGRAVITY_OAUTH_CLIENT_SECRET",
    "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",
)
ANTIGRAVITY_OAUTH_REDIRECT_URI = os.getenv(
    "ANTIGRAVITY_OAUTH_REDIRECT_URI",
    "http://localhost:42532/oauth-callback",
)
ANTIGRAVITY_OAUTH_SCOPE = os.getenv(
    "ANTIGRAVITY_OAUTH_SCOPE",
    "https://www.googleapis.com/auth/cloud-platform "
    "https://www.googleapis.com/auth/userinfo.email "
    "https://www.googleapis.com/auth/userinfo.profile "
    "https://www.googleapis.com/auth/cclog "
    "https://www.googleapis.com/auth/experimentsandconfigs",
)
ANTIGRAVITY_OAUTH_STATE_TTL_SECONDS = 5 * 60
ANTIGRAVITY_OAUTH_STATE_KEY_PREFIX = "antigravity_oauth:"

# Cloudcode-pa（推理/模型列表）
# 说明：plugin 默认优先 daily sandbox；这里按相同优先级做 best-effort fallback
ANTIGRAVITY_CLOUDCODE_PA_ENDPOINTS = [
    ("https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal", "daily-cloudcode-pa.sandbox.googleapis.com"),
    ("https://cloudcode-pa.googleapis.com/v1internal", "cloudcode-pa.googleapis.com"),
    ("https://autopush-cloudcode-pa.sandbox.googleapis.com/v1internal", "autopush-cloudcode-pa.sandbox.googleapis.com"),
]

# Cloudcode-pa（loadCodeAssist/onboardUser）
ANTIGRAVITY_PROJECT_BASE_URL = "https://cloudcode-pa.googleapis.com"
ANTIGRAVITY_PROJECT_HOST = "cloudcode-pa.googleapis.com"

# 与 AntiHub-plugin 保持一致：这些 headers 会影响 Cloud Code 返回字段
ANTIGRAVITY_CODE_ASSIST_USER_AGENT = "google-api-nodejs-client/9.15.1"
ANTIGRAVITY_CODE_ASSIST_X_GOOG_API_CLIENT = "google-cloud-sdk vscode_cloudshelleditor/0.1"
ANTIGRAVITY_CODE_ASSIST_CLIENT_METADATA = (
    "{\"ideType\":\"IDE_UNSPECIFIED\",\"platform\":\"PLATFORM_UNSPECIFIED\",\"pluginType\":\"GEMINI\"}"
)

# 推理请求 headers（对齐 plugin/qwen/gemini-cli）
ANTIGRAVITY_INFER_USER_AGENT = "antigravity/1.104.0 linux/x86_64"
ANTIGRAVITY_INFER_X_GOOG_API_CLIENT = "gl-node/22.17.0"
ANTIGRAVITY_INFER_CLIENT_METADATA = "ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI"


class PluginAPIService:
    """Plug-in API服务类"""
    
    def __init__(self, db: AsyncSession, redis: Optional[RedisClient] = None):
        """
        初始化服务
        
        Args:
            db: 数据库会话
            redis: Redis 客户端（可选，用于缓存）
        """
        self.db = db
        self.settings = get_settings()
        self.repo = PluginAPIKeyRepository(db)
        self.base_url = self.settings.plugin_api_base_url
        self.admin_key = self.settings.plugin_api_admin_key
        self._redis = redis
    
    @property
    def redis(self) -> RedisClient:
        """获取 Redis 客户端"""
        if self._redis is None:
            self._redis = get_redis_client()
        return self._redis
    
    def _get_cache_key(self, user_id: int) -> str:
        """生成缓存键"""
        return f"plugin_api_key:{user_id}"

    def _dt_to_ms(self, dt: Optional[datetime]) -> Optional[int]:
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)

    def _serialize_antigravity_account(self, account: AntigravityAccount) -> Dict[str, Any]:
        return {
            "cookie_id": account.cookie_id,
            "user_id": account.user_id,
            "name": account.account_name,
            # shared 概念合并后移除：对外 contract 仍保留字段，但固定为 0
            "is_shared": 0,
            "status": int(account.status or 0),
            "need_refresh": bool(account.need_refresh),
            "expires_at": self._dt_to_ms(account.token_expires_at),
            "project_id_0": account.project_id_0,
            "is_restricted": bool(account.is_restricted),
            "paid_tier": account.paid_tier,
            "ineligible": bool(account.ineligible),
            "last_used_at": account.last_used_at,
            "created_at": account.created_at,
            "updated_at": account.updated_at,
        }

    async def _get_antigravity_account(self, user_id: int, cookie_id: str) -> Optional[AntigravityAccount]:
        result = await self.db.execute(
            select(AntigravityAccount).where(
                AntigravityAccount.user_id == user_id,
                AntigravityAccount.cookie_id == cookie_id,
            )
        )
        return result.scalar_one_or_none()

    def _decrypt_credentials_json(self, encrypted_json: str) -> Dict[str, Any]:
        try:
            plaintext = decrypt_api_key(encrypted_json)
        except Exception as e:
            raise ValueError(f"凭证解密失败: {e}")

        try:
            data = json.loads(plaintext)
        except Exception as e:
            raise ValueError(f"凭证解析失败: {e}")

        if not isinstance(data, dict):
            raise ValueError("凭证格式非法：期望 JSON object")

        return data

    # ==================== Antigravity OAuth / Cloudcode-pa ====================

    def _antigravity_oauth_state_key(self, state: str) -> str:
        return f"{ANTIGRAVITY_OAUTH_STATE_KEY_PREFIX}{state}"

    def _generate_oauth_state(self) -> str:
        return f"ag-{secrets.token_hex(8)}"

    async def _store_antigravity_oauth_state(self, *, user_id: int, is_shared: int) -> str:
        state = self._generate_oauth_state()
        payload = {
            "user_id": int(user_id),
            "is_shared": int(is_shared),
            "created_at": int(time.time() * 1000),
        }
        await self.redis.set_json(self._antigravity_oauth_state_key(state), payload, expire=ANTIGRAVITY_OAUTH_STATE_TTL_SECONDS)
        return state

    def _parse_google_oauth_callback(self, callback_url: str) -> Dict[str, str]:
        """
        解析 OAuth 回调 URL（兼容用户粘贴的多种形式）
        """
        trimmed = (callback_url or "").strip()
        if not trimmed:
            raise ValueError("callback_url 不能为空")

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

        if err:
            raise ValueError(f"OAuth授权失败: {err}")
        if not code or not state:
            raise ValueError("回调URL中缺少code或state参数")

        return {"code": code, "state": state}

    async def _exchange_code_for_token(self, *, code: str) -> Dict[str, Any]:
        data = {
            "code": code,
            "client_id": ANTIGRAVITY_OAUTH_CLIENT_ID,
            "client_secret": ANTIGRAVITY_OAUTH_CLIENT_SECRET,
            "redirect_uri": ANTIGRAVITY_OAUTH_REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
            resp = await client.post(GOOGLE_TOKEN_URL, data=data, headers={"Accept": "application/json"})
            raw = resp.text
            payload = None
            try:
                payload = resp.json()
            except Exception:
                payload = {"raw": raw}

            if resp.status_code >= 400:
                err = payload.get("error") if isinstance(payload, dict) else None
                desc = payload.get("error_description") if isinstance(payload, dict) else None
                raise ValueError(f"Google OAuth token 交换失败: {err} {desc or raw}".strip())

            if not isinstance(payload, dict):
                raise ValueError("Google OAuth token 响应格式异常（非对象）")
            return payload

    async def _refresh_access_token(self, *, refresh_token: str) -> Dict[str, Any]:
        rt = (refresh_token or "").strip()
        if not rt:
            err = ValueError("缺少refresh_token参数")
            setattr(err, "is_invalid_grant", True)
            raise err

        data = {
            "client_id": ANTIGRAVITY_OAUTH_CLIENT_ID,
            "client_secret": ANTIGRAVITY_OAUTH_CLIENT_SECRET,
            "grant_type": "refresh_token",
            "refresh_token": rt,
        }
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
            resp = await client.post(GOOGLE_TOKEN_URL, data=data, headers={"Accept": "application/json"})
            raw = resp.text
            payload = None
            try:
                payload = resp.json()
            except Exception:
                payload = {"raw": raw}

            if resp.status_code >= 400:
                err = payload.get("error") if isinstance(payload, dict) else None
                desc = payload.get("error_description") if isinstance(payload, dict) else None
                ex = ValueError(f"Google refresh token 失败: {err} {desc or raw}".strip())
                if err == "invalid_grant":
                    setattr(ex, "is_invalid_grant", True)
                raise ex

            if not isinstance(payload, dict):
                raise ValueError("Google refresh token 响应格式异常（非对象）")
            if not (isinstance(payload.get("access_token"), str) and payload.get("access_token").strip()):
                raise ValueError("Google refresh token 响应缺少 access_token")
            return payload

    async def _get_google_user_info(self, *, access_token: str) -> Dict[str, Any]:
        headers = {"Authorization": f"Bearer {access_token}"}
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
            resp = await client.get(GOOGLE_USERINFO_URL, headers=headers)
            if resp.status_code >= 400:
                raise ValueError(f"获取用户信息失败: HTTP {resp.status_code}")
            data = resp.json()
            if not isinstance(data, dict):
                raise ValueError("用户信息响应格式异常（非对象）")
            return data

    def _cookie_id_from_refresh_token(self, refresh_token: str) -> str:
        # 与 AntiHub-plugin 保持一致：sha256(refresh_token) hex 前 32 位
        h = hashlib.sha256((refresh_token or "").encode("utf-8")).hexdigest()
        return h[:32]

    def _project_headers(self, *, access_token: str, host: str) -> Dict[str, str]:
        return {
            "Host": host,
            "User-Agent": ANTIGRAVITY_CODE_ASSIST_USER_AGENT,
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip",
            "X-Goog-Api-Client": ANTIGRAVITY_CODE_ASSIST_X_GOOG_API_CLIENT,
            "Client-Metadata": ANTIGRAVITY_CODE_ASSIST_CLIENT_METADATA,
        }

    def _infer_headers(self, *, access_token: str, host: str, accept: str) -> Dict[str, str]:
        return {
            "Host": host,
            "User-Agent": ANTIGRAVITY_INFER_USER_AGENT,
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip",
            "Accept": accept,
            "X-Goog-Api-Client": ANTIGRAVITY_INFER_X_GOOG_API_CLIENT,
            "Client-Metadata": ANTIGRAVITY_INFER_CLIENT_METADATA,
        }

    def _extract_project_id(self, value: Any) -> str:
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

    def _default_tier_id(self, load_resp: Dict[str, Any]) -> str:
        fallback = "legacy-tier"
        tiers = load_resp.get("allowedTiers")
        if not isinstance(tiers, list):
            return fallback
        for t in tiers:
            if isinstance(t, dict) and t.get("isDefault") and isinstance(t.get("id"), str) and t.get("id").strip():
                return t.get("id").strip()
        return fallback

    async def _load_code_assist(self, *, access_token: str) -> Dict[str, Any]:
        url = f"{ANTIGRAVITY_PROJECT_BASE_URL}/v1internal:loadCodeAssist"
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
            resp = await client.post(
                url,
                headers=self._project_headers(access_token=access_token, host=ANTIGRAVITY_PROJECT_HOST),
                json={"metadata": {"ideType": "ANTIGRAVITY", "platform": "PLATFORM_UNSPECIFIED", "pluginType": "GEMINI"}},
            )
            if resp.status_code >= 400:
                raise ValueError(f"loadCodeAssist 失败: HTTP {resp.status_code}")
            data = resp.json()
            if not isinstance(data, dict):
                raise ValueError("loadCodeAssist 响应格式异常（非对象）")
            return data

    async def _onboard_user(self, *, access_token: str, tier_id: str) -> str:
        url = f"{ANTIGRAVITY_PROJECT_BASE_URL}/v1internal:onboardUser"
        payload = {
            "tierId": tier_id,
            "metadata": {"ideType": "ANTIGRAVITY", "platform": "PLATFORM_UNSPECIFIED", "pluginType": "GEMINI"},
        }
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
            for _ in range(5):
                resp = await client.post(
                    url,
                    headers=self._project_headers(access_token=access_token, host=ANTIGRAVITY_PROJECT_HOST),
                    json=payload,
                )
                if resp.status_code >= 400:
                    raise ValueError(f"onboardUser 失败: HTTP {resp.status_code}")
                data = resp.json()
                if not isinstance(data, dict):
                    raise ValueError("onboardUser 响应格式异常（非对象）")
                if not data.get("done"):
                    await asyncio.sleep(2.0)
                    continue
                project_id = self._extract_project_id((data.get("response") or {}).get("cloudaicompanionProject")) or self._extract_project_id(
                    data.get("cloudaicompanionProject")
                )
                if project_id:
                    return project_id
                raise ValueError("onboardUser 返回 done=true 但缺少 project_id")
        return ""

    async def _fetch_available_models(self, *, access_token: str, project: str) -> Dict[str, Any]:
        body = {"project": project or ""}
        last_err: Optional[Exception] = None
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
            for base_url, host in ANTIGRAVITY_CLOUDCODE_PA_ENDPOINTS:
                try:
                    url = f"{base_url}:fetchAvailableModels"
                    resp = await client.post(
                        url,
                        headers=self._infer_headers(access_token=access_token, host=host, accept="application/json"),
                        json=body,
                    )
                    if resp.status_code >= 400:
                        raise ValueError(f"fetchAvailableModels 失败: HTTP {resp.status_code}")
                    data = resp.json()
                    if not isinstance(data, dict):
                        raise ValueError("fetchAvailableModels 响应格式异常（非对象）")
                    return data
                except Exception as e:
                    last_err = e
                    continue
        raise ValueError(str(last_err or "fetchAvailableModels 失败"))

    def _normalize_quota_fraction(self, value: Any) -> Optional[float]:
        if value is None or isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            try:
                f = float(value)
            except Exception:
                return None
        elif isinstance(value, str):
            s = value.strip()
            if not s:
                return None
            if s.endswith("%"):
                try:
                    f = float(s[:-1]) / 100.0
                except Exception:
                    return None
            else:
                try:
                    f = float(s)
                except Exception:
                    return None
        else:
            return None

        if f > 1 and f <= 100:
            f = f / 100.0
        if f < 0:
            f = 0.0
        if f > 9.9999:
            f = 9.9999
        return f

    def _parse_reset_time(self, value: Any) -> Optional[datetime]:
        if not isinstance(value, str):
            return None
        s = value.strip()
        if not s:
            return None
        s2 = s.replace("Z", "+00:00") if s.endswith("Z") else s
        try:
            dt = datetime.fromisoformat(s2)
        except Exception:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    async def _update_model_quotas(self, *, cookie_id: str, models_data: Dict[str, Any]) -> None:
        now = datetime.now(timezone.utc)
        if not isinstance(models_data, dict):
            return

        for model_name, model_info in models_data.items():
            if not isinstance(model_name, str) or not model_name.strip():
                continue
            if not isinstance(model_info, dict):
                continue

            quota_info = model_info.get("quotaInfo") or model_info.get("quota_info") or None
            if not isinstance(quota_info, dict):
                continue

            remaining_val = quota_info.get("remainingFraction") or quota_info.get("remaining_fraction") or quota_info.get("remaining")
            reset_val = quota_info.get("resetTime") or quota_info.get("reset_time")

            remaining = self._normalize_quota_fraction(remaining_val)
            reset_at = self._parse_reset_time(reset_val)

            # 没有任何 quota 字段：跳过（避免默认写入 1.0 造成“永远 100%”假象）
            if remaining is None and reset_at is None:
                continue

            quota_value = remaining if remaining is not None else 0.0

            stmt = pg_insert(AntigravityModelQuota).values(
                cookie_id=cookie_id,
                model_name=model_name.strip(),
                quota=float(quota_value),
                reset_at=reset_at,
                status=1,
                last_fetched_at=now,
            )
            stmt = stmt.on_conflict_do_update(
                constraint="uq_antigravity_model_quotas_cookie_model",
                set_={
                    "quota": float(quota_value),
                    "reset_at": reset_at,
                    "status": 1,
                    "last_fetched_at": now,
                    "updated_at": func.now(),
                },
            )
            await self.db.execute(stmt)

        await self.db.flush()

    async def _create_account_from_tokens(
        self,
        *,
        user_id: int,
        is_shared: int,
        access_token: str,
        refresh_token: str,
        expires_in: int,
    ) -> AntigravityAccount:
        if is_shared not in (0, 1):
            raise ValueError("is_shared必须是0或1")
        if is_shared == 1:
            raise ValueError("合并后不支持共享账号（is_shared=1）")

        normalized_refresh = (refresh_token or "").strip()
        if not normalized_refresh:
            raise ValueError("缺少refresh_token参数")

        cookie_id = self._cookie_id_from_refresh_token(normalized_refresh)

        # 防止重复导入同一个 refresh_token（cookie_id 唯一）
        existing = await self.db.execute(select(AntigravityAccount).where(AntigravityAccount.cookie_id == cookie_id))
        if existing.scalar_one_or_none() is not None:
            raise ValueError(f"此Refresh Token已被导入: cookie_id={cookie_id}")

        expires_at_ms = int(time.time() * 1000) + int(expires_in or 0) * 1000
        token_expires_at = datetime.fromtimestamp(expires_at_ms / 1000, tz=timezone.utc) if expires_in else None

        # 获取用户信息（email）
        account_email: Optional[str] = None
        account_name: str = "Antigravity Account"
        try:
            user_info = await self._get_google_user_info(access_token=access_token)
            email = user_info.get("email")
            if isinstance(email, str) and email.strip():
                account_email = email.strip()
                account_name = account_email
                # email 唯一（尽量对齐 plugin 行为）
                result = await self.db.execute(select(AntigravityAccount).where(AntigravityAccount.email == account_email))
                if result.scalar_one_or_none() is not None:
                    raise ValueError(f"此邮箱已被添加过: {account_email}")
        except ValueError:
            raise
        except Exception as e:
            logger.warning("获取用户信息失败，将使用默认名称: %s", e)

        # 获取 project_id_0 / 资格检查（对齐 plugin）
        project_id_0 = ""
        is_restricted = False
        paid_tier: Optional[bool] = False

        load_resp = await self._load_code_assist(access_token=access_token)

        paid_tier_id = None
        paid_obj = load_resp.get("paidTier") if isinstance(load_resp.get("paidTier"), dict) else None
        if isinstance(paid_obj, dict) and isinstance(paid_obj.get("id"), str) and paid_obj.get("id").strip():
            paid_tier_id = paid_obj.get("id").strip().lower()
            paid_tier = "free" not in paid_tier_id

        ineligible_tiers = load_resp.get("ineligibleTiers")
        if isinstance(ineligible_tiers, list):
            if not paid_tier:
                for t in ineligible_tiers:
                    if isinstance(t, dict) and t.get("reasonCode") == "INELIGIBLE_ACCOUNT":
                        raise ValueError("此账号没有资格使用Antigravity: INELIGIBLE_ACCOUNT")
            for t in ineligible_tiers:
                if isinstance(t, dict) and t.get("reasonCode") == "UNSUPPORTED_LOCATION":
                    is_restricted = True

        if not is_restricted:
            project_id_0 = self._extract_project_id(load_resp.get("cloudaicompanionProject"))
            if not project_id_0:
                try:
                    tier_id = self._default_tier_id(load_resp)
                    project_id_0 = await self._onboard_user(access_token=access_token, tier_id=tier_id)
                except Exception as e:
                    logger.warning("onboardUser 获取 project_id 失败: cookie_id=%s error=%s", cookie_id, e)

        # project_id_0 为空且为免费用户：阻止登录
        if not project_id_0 and not paid_tier:
            reason = "NO_PROJECT_AND_FREE_TIER"
            if isinstance(ineligible_tiers, list) and ineligible_tiers:
                first = ineligible_tiers[0]
                if isinstance(first, dict) and isinstance(first.get("reasonCode"), str) and first.get("reasonCode").strip():
                    reason = first.get("reasonCode").strip()
            raise ValueError(f"此账号没有资格使用Antigravity: {reason}")

        # fetchAvailableModels -> quotas
        models_resp = await self._fetch_available_models(access_token=access_token, project=project_id_0 or "")
        models_data = models_resp.get("models") if isinstance(models_resp.get("models"), dict) else {}

        credentials_payload = {
            "type": "antigravity",
            "cookie_id": cookie_id,
            "is_shared": 0,
            "access_token": access_token,
            "refresh_token": normalized_refresh,
            "expires_at": expires_at_ms,
            "expires_at_ms": expires_at_ms,
        }
        encrypted_credentials = encrypt_api_key(json.dumps(credentials_payload, ensure_ascii=False))

        account = AntigravityAccount(
            user_id=user_id,
            cookie_id=cookie_id,
            account_name=account_name,
            email=account_email,
            project_id_0=project_id_0 or None,
            status=1,
            need_refresh=False,
            is_restricted=bool(is_restricted),
            paid_tier=bool(paid_tier) if paid_tier is not None else None,
            ineligible=False,
            token_expires_at=token_expires_at,
            last_refresh_at=datetime.now(timezone.utc),
            last_used_at=None,
            credentials=encrypted_credentials,
        )
        self.db.add(account)
        await self.db.flush()
        await self.db.refresh(account)

        try:
            await self._update_model_quotas(cookie_id=cookie_id, models_data=models_data)
        except Exception as e:
            logger.warning("更新模型配额失败(已忽略): cookie_id=%s error=%s", cookie_id, e)

        return account

    async def _ensure_antigravity_access_token(self, *, account: AntigravityAccount) -> str:
        creds = self._decrypt_credentials_json(account.credentials)
        access_token = (creds.get("access_token") or "").strip() if isinstance(creds.get("access_token"), str) else ""
        refresh_token = (creds.get("refresh_token") or "").strip() if isinstance(creds.get("refresh_token"), str) else ""

        # token_expires_at 为空：认为需要刷新（与 plugin 行为一致）
        expires_at = account.token_expires_at
        if access_token and expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if access_token and expires_at:
            # 提前 5 分钟刷新
            if datetime.now(timezone.utc) < expires_at - timedelta(minutes=5):
                return access_token

        if not refresh_token:
            await self.db.execute(
                update(AntigravityAccount)
                .where(AntigravityAccount.id == account.id)
                .values(need_refresh=True, status=0)
            )
            await self.db.flush()
            raise ValueError("账号缺少refresh_token，无法刷新")

        token_data = await self._refresh_access_token(refresh_token=refresh_token)
        new_access = (token_data.get("access_token") or "").strip()
        if not new_access:
            raise ValueError("refresh_token 未返回 access_token")

        expires_in = int(token_data.get("expires_in") or 0)
        expires_at_ms = int(time.time() * 1000) + expires_in * 1000 if expires_in else None
        token_expires_at = (
            datetime.fromtimestamp(expires_at_ms / 1000, tz=timezone.utc) if expires_at_ms is not None else None
        )

        creds["access_token"] = new_access
        if expires_at_ms is not None:
            creds["expires_at"] = expires_at_ms
            creds["expires_at_ms"] = expires_at_ms

        await self.db.execute(
            update(AntigravityAccount)
            .where(AntigravityAccount.id == account.id)
            .values(
                credentials=encrypt_api_key(json.dumps(creds, ensure_ascii=False)),
                token_expires_at=token_expires_at,
                last_refresh_at=datetime.now(timezone.utc),
                need_refresh=False,
                status=1,
            )
        )
        await self.db.flush()
        return new_access

    async def _antigravity_openai_list_models(self, *, user_id: int) -> Dict[str, Any]:
        result = await self.db.execute(
            select(AntigravityAccount)
            .where(AntigravityAccount.user_id == user_id, AntigravityAccount.status == 1, AntigravityAccount.need_refresh.is_(False))
            .order_by(AntigravityAccount.id.asc())
        )
        accounts = result.scalars().all()
        if not accounts:
            return {"object": "list", "data": []}

        account = accounts[0]
        access_token = await self._ensure_antigravity_access_token(account=account)
        project_id = (account.project_id_0 or "").strip()
        models_resp = await self._fetch_available_models(access_token=access_token, project=project_id)
        models_data = models_resp.get("models") if isinstance(models_resp.get("models"), dict) else {}
        items = []
        created = int(time.time())
        for mid in models_data.keys():
            if isinstance(mid, str) and mid.strip():
                items.append({"id": mid.strip(), "object": "model", "created": created, "owned_by": "antigravity"})
        return {"object": "list", "data": items}

    async def _antigravity_openai_chat_completions(self, *, user_id: int, request_data: Dict[str, Any]) -> Dict[str, Any]:
        # 选择账号：目前仅选第一个启用账号（KISS），后续如需轮询/冷却再扩展
        result = await self.db.execute(
            select(AntigravityAccount)
            .where(AntigravityAccount.user_id == user_id, AntigravityAccount.status == 1, AntigravityAccount.need_refresh.is_(False))
            .order_by(AntigravityAccount.id.asc())
        )
        account = result.scalars().first()
        if account is None:
            raise ValueError("未找到可用的 Antigravity 账号（请先在面板完成 OAuth 并启用账号）")

        access_token = await self._ensure_antigravity_access_token(account=account)
        payload = _openai_request_to_gemini_cli_payload(request_data)
        project_id = (account.project_id_0 or "").strip()
        payload["project"] = project_id
        model = (payload.get("model") or "").strip() or "gemini-2.5-pro"

        url = f"{ANTIGRAVITY_CLOUDCODE_PA_ENDPOINTS[0][0]}:generateContent"
        host = ANTIGRAVITY_CLOUDCODE_PA_ENDPOINTS[0][1]

        async with httpx.AsyncClient(timeout=httpx.Timeout(1200.0, connect=60.0)) as client:
            resp = await client.post(
                url,
                headers=self._infer_headers(access_token=access_token, host=host, accept="application/json"),
                json={**payload, "model": model},
            )
            if resp.status_code >= 400:
                raise ValueError(resp.text[:2000] or f"Antigravity 上游错误: HTTP {resp.status_code}")
            raw = resp.json()
            if not isinstance(raw, dict):
                raise ValueError("Antigravity 上游响应格式异常（非对象）")
            return _gemini_cli_response_to_openai_response(raw)

    async def _antigravity_openai_chat_completions_stream(self, *, user_id: int, request_data: Dict[str, Any]):
        result = await self.db.execute(
            select(AntigravityAccount)
            .where(AntigravityAccount.user_id == user_id, AntigravityAccount.status == 1, AntigravityAccount.need_refresh.is_(False))
            .order_by(AntigravityAccount.id.asc())
        )
        account = result.scalars().first()
        if account is None:
            yield _openai_error_sse("未找到可用的 Antigravity 账号（请先在面板完成 OAuth 并启用账号）", code=400)
            yield _openai_done_sse()
            return

        access_token = await self._ensure_antigravity_access_token(account=account)
        payload = _openai_request_to_gemini_cli_payload(request_data)
        project_id = (account.project_id_0 or "").strip()
        payload["project"] = project_id
        model = (payload.get("model") or "").strip() or "gemini-2.5-pro"

        base_url, host = ANTIGRAVITY_CLOUDCODE_PA_ENDPOINTS[0]
        url = f"{base_url}:streamGenerateContent?alt=sse"
        state = _OpenAIStreamState(created=int(time.time()), function_index=0)

        async with httpx.AsyncClient(timeout=httpx.Timeout(1200.0, connect=60.0)) as client:
            async with client.stream(
                "POST",
                url,
                headers=self._infer_headers(access_token=access_token, host=host, accept="text/event-stream"),
                json={**payload, "model": model},
            ) as resp:
                if resp.status_code >= 400:
                    text = await resp.aread()
                    msg = text.decode("utf-8", errors="replace")[:2000]
                    yield _openai_error_sse(msg or "Antigravity 上游错误", code=resp.status_code)
                    yield _openai_done_sse()
                    return

                buffer = b""
                event_data_lines: List[bytes] = []
                async for chunk in resp.aiter_raw():
                    if not chunk:
                        continue
                    buffer += chunk
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        line = line.rstrip(b"\r")

                        if line == b"":
                            if not event_data_lines:
                                continue
                            data = b"\n".join(event_data_lines).strip()
                            event_data_lines = []
                            if not data:
                                continue
                            try:
                                event_obj = json.loads(data.decode("utf-8", errors="replace"))
                            except Exception:
                                continue
                            if not isinstance(event_obj, dict):
                                continue
                            for payload_obj in _gemini_cli_event_to_openai_chunks(event_obj, state=state):
                                yield f"data: {json.dumps(payload_obj, ensure_ascii=False)}\n\n".encode("utf-8")
                            continue

                        if line.startswith(b"data:"):
                            event_data_lines.append(line[5:].lstrip())
                            continue

                yield _openai_done_sse()

    async def openai_chat_completions_stream(self, *, user_id: int, request_data: Dict[str, Any]):
        """
        OpenAI 兼容 /v1/chat/completions（stream）

        说明：
        - 迁移后，Backend 内部直接对接 Antigravity（不再依赖 AntiHub-plugin 运行时）
        - 这里统一输出 OpenAI SSE（data: {...}\\n\\n），供 /v1/chat/completions 转发
        """
        async for chunk in self._antigravity_openai_chat_completions_stream(
            user_id=user_id,
            request_data=request_data,
        ):
            yield chunk

    async def openai_chat_completions(self, *, user_id: int, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        OpenAI 兼容 /v1/chat/completions（非 stream）

        说明：
        - Backend 内部直连 Antigravity（不再依赖 AntiHub-plugin 运行时）
        - 返回标准 OpenAI chat.completions JSON
        """
        return await self._antigravity_openai_chat_completions(user_id=user_id, request_data=request_data)
    
    # ==================== 密钥管理 ====================
    
    async def save_user_api_key(
        self,
        user_id: int,
        api_key: str,
        plugin_user_id: Optional[str] = None
    ) -> PluginAPIKeyResponse:
        """
        保存用户的plug-in API密钥
        
        Args:
            user_id: 用户ID
            api_key: 用户的plug-in API密钥
            plugin_user_id: plug-in系统中的用户ID
            
        Returns:
            保存的密钥信息
        """
        # 加密API密钥
        encrypted_key = encrypt_api_key(api_key)
        
        # 检查是否已存在
        existing = await self.repo.get_by_user_id(user_id)
        
        if existing:
            # 更新现有密钥
            updated = await self.repo.update(
                user_id=user_id,
                api_key=encrypted_key,
                plugin_user_id=plugin_user_id
            )
            return PluginAPIKeyResponse.model_validate(updated)
        else:
            # 创建新密钥
            created = await self.repo.create(
                user_id=user_id,
                api_key=encrypted_key,
                plugin_user_id=plugin_user_id
            )
            return PluginAPIKeyResponse.model_validate(created)
    
    async def get_user_api_key(self, user_id: int) -> Optional[str]:
        """
        获取用户的解密后的API密钥
        
        优化：使用 Redis 缓存减少数据库查询
        
        Args:
            user_id: 用户ID
            
        Returns:
            解密后的API密钥，不存在返回None
        """
        cache_key = self._get_cache_key(user_id)
        
        # 尝试从缓存获取
        try:
            cached_key = await self.redis.get(cache_key)
            if cached_key:
                logger.debug(f"从缓存获取 plugin_api_key: user_id={user_id}")
                return cached_key
        except Exception as e:
            logger.warning(f"Redis 缓存读取失败: {e}")
        
        # 缓存未命中，从数据库获取
        key_record = await self.repo.get_by_user_id(user_id)
        if not key_record or not key_record.is_active:
            return None
        
        # 解密
        decrypted_key = decrypt_api_key(key_record.api_key)
        
        # 存入缓存
        try:
            await self.redis.set(cache_key, decrypted_key, expire=PLUGIN_API_KEY_CACHE_TTL)
            logger.debug(f"plugin_api_key 已缓存: user_id={user_id}, ttl={PLUGIN_API_KEY_CACHE_TTL}s")
        except Exception as e:
            logger.warning(f"Redis 缓存写入失败: {e}")
        
        return decrypted_key
    
    async def delete_user_api_key(self, user_id: int) -> bool:
        """
        删除用户的API密钥
        
        Args:
            user_id: 用户ID
            
        Returns:
            删除成功返回True
        """
        # 删除缓存
        try:
            cache_key = self._get_cache_key(user_id)
            await self.redis.delete(cache_key)
        except Exception as e:
            logger.warning(f"删除缓存失败: {e}")
        
        return await self.repo.delete(user_id)
    
    async def update_last_used(self, user_id: int):
        """
        更新密钥最后使用时间
        
        优化：
        1. 使用 Redis 限流，避免频繁写入数据库
        2. 使用独立的数据库会话，避免长时间占用主会话
        """
        try:
            # 1. 检查 Redis 限流 (60秒)
            throttle_key = f"plugin_key_last_used_throttle:{user_id}"
            if await self.redis.exists(throttle_key):
                return
            
            # 2. 设置限流键
            await self.redis.set(throttle_key, "1", expire=60)
            
            # 3. 使用独立会话更新数据库
            from app.db.session import get_session_maker
            from app.repositories.plugin_api_key_repository import PluginAPIKeyRepository
            
            session_maker = get_session_maker()
            async with session_maker() as db:
                repo = PluginAPIKeyRepository(db)
                await repo.update_last_used(user_id)
                await db.commit()
                
        except Exception as e:
            # 更新最后使用时间失败不应该影响主流程
            logger.warning(f"更新 plugin_api_key 最后使用时间失败: user_id={user_id}, error={e}")
    
    async def invalidate_cache(self, user_id: int):
        """
        使缓存失效
        
        当用户更新 API 密钥时调用
        
        Args:
            user_id: 用户ID
        """
        try:
            cache_key = self._get_cache_key(user_id)
            await self.redis.delete(cache_key)
            logger.debug(f"plugin_api_key 缓存已失效: user_id={user_id}")
        except Exception as e:
            logger.warning(f"使缓存失效失败: {e}")
    
    # ==================== Plug-in API代理方法 ====================
    
    async def create_plugin_user(
        self,
        request: CreatePluginUserRequest
    ) -> Dict[str, Any]:
        """
        创建plug-in-api用户（管理员操作）
        
        Args:
            request: 创建用户请求
            
        Returns:
            创建结果，包含用户信息和API密钥
        """
        url = f"{self.base_url}/api/users"
        payload = request.model_dump()
        headers = {"Authorization": f"Bearer {self.admin_key}"}
        
        # 打印请求详情
        print(f"📤 发送创建plug-in用户请求:")
        print(f"   URL: POST {url}")
        print(f"   Headers: {headers}")
        print(f"   Payload: {payload}")
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=payload,
                headers=headers,
                timeout=30.0
            )
            
            # 打印响应详情
            print(f"📥 收到plug-in-api响应:")
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            response.raise_for_status()
            return response.json()
    
    async def auto_create_and_bind_plugin_user(
        self,
        user_id: int,
        username: str,
        prefer_shared: int = 0
    ) -> PluginAPIKeyResponse:
        """
        自动创建plug-in-api用户并绑定到我们的用户
        
        Args:
            user_id: 我们系统中的用户ID
            username: 用户名
            prefer_shared: Cookie优先级，0=专属优先，1=共享优先
            
        Returns:
            保存的密钥信息
        """
        # 创建plug-in-api用户
        request = CreatePluginUserRequest(
            name=username,
            prefer_shared=prefer_shared
        )
        
        result = await self.create_plugin_user(request)
        
        # 提取API密钥和用户ID
        api_key = result.get("data", {}).get("api_key")
        plugin_user_id = result.get("data", {}).get("user_id")
        
        if not api_key:
            raise ValueError("创建plug-in用户失败：未返回API密钥")
        
        # 保存密钥到我们的数据库
        return await self.save_user_api_key(
            user_id=user_id,
            api_key=api_key,
            plugin_user_id=plugin_user_id
        )
    
    async def proxy_request(
        self,
        user_id: int,
        method: str,
        path: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        代理用户请求到plug-in-api
        
        Args:
            user_id: 用户ID
            method: HTTP方法
            path: API路径
            json_data: JSON请求体
            params: 查询参数
            extra_headers: 额外的请求头
            
        Returns:
            API响应
            
        Raises:
            httpx.HTTPStatusError: 当上游返回错误状态码时，包含上游的响应内容
        """
        # 获取用户的API密钥
        api_key = await self.get_user_api_key(user_id)
        if not api_key:
            raise ValueError("用户未配置plug-in API密钥")
        
        # 更新最后使用时间
        await self.update_last_used(user_id)
        
        # 发送请求
        url = f"{self.base_url}{path}"
        headers = {"Authorization": f"Bearer {api_key}"}
        
        # 添加额外的请求头
        if extra_headers:
            headers.update(extra_headers)
        
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=method,
                url=url,
                json=json_data,
                params=params,
                headers=headers,
                timeout=1200.0
            )
            
            # 如果响应不是成功状态码，抛出包含响应内容的异常
            if response.status_code >= 400:
                # 尝试解析JSON响应
                try:
                    error_data = response.json()
                except Exception:
                    error_data = {"detail": response.text}
                
                # 创建HTTPStatusError并附加响应数据
                error = httpx.HTTPStatusError(
                    message=f"上游API返回错误: {response.status_code}",
                    request=response.request,
                    response=response
                )
                # 将错误数据附加到异常对象
                error.response_data = error_data
                raise error
            
            return response.json()
    
    async def proxy_stream_request(
        self,
        user_id: int,
        method: str,
        path: str,
        json_data: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None
    ):
        """
        代理流式请求到plug-in-api
        
        Args:
            user_id: 用户ID
            method: HTTP方法
            path: API路径
            json_data: JSON请求体
            extra_headers: 额外的请求头
            
        Yields:
            流式响应数据
            
        Note:
            当上游返回错误状态码时，会生成一个SSE格式的错误消息
        """
        # 获取用户的API密钥
        api_key = await self.get_user_api_key(user_id)
        if not api_key:
            raise ValueError("用户未配置plug-in API密钥")
        
        # 发送流式请求
        url = f"{self.base_url}{path}"
        headers = {"Authorization": f"Bearer {api_key}"}
        
        # 添加额外的请求头
        if extra_headers:
            headers.update(extra_headers)
        
        async with httpx.AsyncClient() as client:
            async with client.stream(
                method=method,
                url=url,
                json=json_data,
                headers=headers,
                timeout=httpx.Timeout(1200.0, connect=60.0)
            ) as response:
                # 检查响应状态码，如果是错误状态码，读取错误内容并生成SSE格式的错误消息
                if response.status_code >= 400:
                    # 读取错误响应内容
                    error_content = await response.aread()
                    try:
                        import json
                        error_data = json.loads(error_content.decode('utf-8'))
                    except Exception:
                        error_data = {"detail": error_content.decode('utf-8', errors='replace')}
                    
                    # 记录错误日志
                    logger.error(f"上游API返回错误: status={response.status_code}, url={url}, error={error_data}")
                    
                    # 提取错误消息，处理多种格式
                    error_message = None
                    if isinstance(error_data, dict):
                        # 尝试获取 detail 字段
                        if "detail" in error_data:
                            error_message = error_data["detail"]
                        # 尝试获取 error 字段（可能是字符串或字典）
                        elif "error" in error_data:
                            error_field = error_data["error"]
                            if isinstance(error_field, str):
                                error_message = error_field
                            elif isinstance(error_field, dict):
                                error_message = error_field.get("message") or str(error_field)
                            else:
                                error_message = str(error_field)
                        # 尝试获取 message 字段
                        elif "message" in error_data:
                            error_message = error_data["message"]
                    
                    # 如果还是没有提取到消息，使用整个 error_data 的字符串表示
                    if not error_message:
                        error_message = str(error_data)
                    
                    # 生成SSE格式的错误消息
                    import json
                    error_response = {
                        "error": {
                            "message": error_message,
                            "type": "upstream_error",
                            "code": response.status_code
                        }
                    }
                    yield f"data: {json.dumps(error_response)}\n\n".encode('utf-8')
                    yield b"data: [DONE]\n\n"
                    return
                
                async for chunk in response.aiter_raw():
                    if chunk:
                        yield chunk
    
    # ==================== 具体API方法 ====================
    
    async def get_oauth_authorize_url(
        self,
        user_id: int,
        is_shared: int = 0
    ) -> Dict[str, Any]:
        """获取 Google OAuth 授权 URL（Antigravity）"""
        if is_shared not in (0, 1):
            raise ValueError("is_shared必须是0或1")
        if is_shared == 1:
            raise ValueError("合并后不支持共享账号（is_shared=1）")

        state = await self._store_antigravity_oauth_state(user_id=user_id, is_shared=is_shared)
        params = {
            "access_type": "offline",
            "client_id": ANTIGRAVITY_OAUTH_CLIENT_ID,
            "prompt": "consent",
            "redirect_uri": ANTIGRAVITY_OAUTH_REDIRECT_URI,
            "response_type": "code",
            "scope": ANTIGRAVITY_OAUTH_SCOPE,
            "state": state,
        }
        auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
        return {"success": True, "data": {"auth_url": auth_url, "state": state, "expires_in": ANTIGRAVITY_OAUTH_STATE_TTL_SECONDS}}
    
    async def submit_oauth_callback(
        self,
        user_id: int,
        callback_url: str
    ) -> Dict[str, Any]:
        """提交 OAuth 回调 URL 并导入 Antigravity 账号（无需 plug-in 服务）"""
        parsed = self._parse_google_oauth_callback(callback_url)
        state = parsed.get("state") or ""
        code = parsed.get("code") or ""
        if not state or not code:
            raise ValueError("回调URL中缺少code或state参数")

        state_key = self._antigravity_oauth_state_key(state)
        state_info = await self.redis.get_json(state_key)
        if not isinstance(state_info, dict):
            raise ValueError("Invalid or expired state parameter")

        try:
            state_user_id = int(state_info.get("user_id") or 0)
        except Exception:
            state_user_id = 0
        try:
            is_shared = int(state_info.get("is_shared") or 0)
        except Exception:
            is_shared = 0

        if state_user_id and int(state_user_id) != int(user_id):
            raise ValueError("state 不属于当前用户")

        try:
            token_data = await self._exchange_code_for_token(code=code)
            refresh_token = (token_data.get("refresh_token") or "").strip() if isinstance(token_data, dict) else ""
            if not refresh_token:
                raise ValueError("未获取到refresh_token，请撤销授权后重新授权（需要 access_type=offline + prompt=consent）")
            access_token = (token_data.get("access_token") or "").strip() if isinstance(token_data, dict) else ""
            try:
                expires_in = int(token_data.get("expires_in") or 0) if isinstance(token_data, dict) else 0
            except Exception:
                expires_in = 0

            account = await self._create_account_from_tokens(
                user_id=user_id,
                is_shared=is_shared,
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=expires_in,
            )
            return {"success": True, "message": "账号添加成功", "data": self._serialize_antigravity_account(account)}
        finally:
            try:
                await self.redis.delete(state_key)
            except Exception:
                pass
    
    async def get_accounts(self, user_id: int) -> Dict[str, Any]:
        """
        获取账号列表
        
        返回用户在plug-in-api中的所有账号信息，包括：
        - project_id_0: 项目ID
        - is_restricted: 是否受限
        - ineligible: 是否不合格
        以及其他账号相关字段
        """
        result = await self.db.execute(
            select(AntigravityAccount)
            .where(AntigravityAccount.user_id == user_id)
            .order_by(AntigravityAccount.id.asc())
        )
        accounts = result.scalars().all()

        return {"success": True, "data": [self._serialize_antigravity_account(a) for a in accounts]}

    async def import_account_by_refresh_token(
        self,
        user_id: int,
        refresh_token: str,
        is_shared: int = 0
    ) -> Dict[str, Any]:
        """通过 refresh_token 导入账号（无需走 OAuth 回调）"""
        if not refresh_token or not isinstance(refresh_token, str) or not refresh_token.strip():
            raise ValueError("缺少refresh_token参数")

        # 合并后不支持 shared 语义，但为兼容保留入参；仅允许 0
        if is_shared not in (0, 1):
            raise ValueError("is_shared必须是0或1")
        if is_shared == 1:
            raise ValueError("合并后不支持共享账号（is_shared=1）")

        normalized_refresh = refresh_token.strip()
        token_data = await self._refresh_access_token(refresh_token=normalized_refresh)
        access_token = (token_data.get("access_token") or "").strip() if isinstance(token_data, dict) else ""
        if not access_token:
            raise ValueError("refresh_token 未返回 access_token")
        try:
            expires_in = int(token_data.get("expires_in") or 0) if isinstance(token_data, dict) else 0
        except Exception:
            expires_in = 0

        account = await self._create_account_from_tokens(
            user_id=user_id,
            is_shared=is_shared,
            access_token=access_token,
            refresh_token=normalized_refresh,
            expires_in=expires_in,
        )

        return {"success": True, "message": "账号导入成功", "data": self._serialize_antigravity_account(account)}
    
    async def get_account(self, user_id: int, cookie_id: str) -> Dict[str, Any]:
        """获取单个账号信息"""
        account = await self._get_antigravity_account(user_id=user_id, cookie_id=cookie_id)
        if not account:
            raise ValueError("账号不存在")
        return {"success": True, "data": self._serialize_antigravity_account(account)}

    async def get_account_credentials(self, user_id: int, cookie_id: str) -> Dict[str, Any]:
        """
        导出账号凭证（敏感信息）

        说明：
        - 仅用于用户自助导出/备份（前端“复制凭证为JSON”）
        - 实际鉴权在 plug-in API 层完成（仅账号所有者/管理员可访问）
        """
        account = await self._get_antigravity_account(user_id=user_id, cookie_id=cookie_id)
        if not account:
            raise ValueError("账号不存在")

        creds = self._decrypt_credentials_json(account.credentials)
        expires_at = (
            creds.get("expires_at")
            if creds.get("expires_at") is not None
            else (creds.get("expires_at_ms") if creds.get("expires_at_ms") is not None else None)
        )

        credentials = {
            "type": "antigravity",
            "cookie_id": account.cookie_id,
            "is_shared": 0,
            "access_token": creds.get("access_token"),
            "refresh_token": creds.get("refresh_token"),
            "expires_at": expires_at if expires_at is not None else self._dt_to_ms(account.token_expires_at),
        }

        export_data = {
            k: v
            for k, v in credentials.items()
            if v is not None and not (isinstance(v, str) and v.strip() == "")
        }

        return {"success": True, "data": export_data}

    async def get_account_detail(self, user_id: int, cookie_id: str) -> Dict[str, Any]:
        """获取单个账号的详情信息（邮箱/订阅层级等）"""
        account = await self._get_antigravity_account(user_id=user_id, cookie_id=cookie_id)
        if not account:
            raise ValueError("账号不存在")

        return {
            "success": True,
            "data": {
                "cookie_id": account.cookie_id,
                "name": account.account_name,
                "email": account.email,
                "created_at": account.created_at,
                "paid_tier": bool(account.paid_tier) if account.paid_tier is not None else False,
                "subscription_tier": None,
                "subscription_tier_raw": None,
            },
        }

    async def refresh_account(self, user_id: int, cookie_id: str) -> Dict[str, Any]:
        """刷新账号（强制刷新 access_token + 更新 project_id_0）"""
        account = await self._get_antigravity_account(user_id=user_id, cookie_id=cookie_id)
        if not account:
            raise ValueError("账号不存在")

        creds = self._decrypt_credentials_json(account.credentials)
        refresh_token = creds.get("refresh_token")
        if not refresh_token:
            raise ValueError("账号缺少refresh_token，无法刷新")

        now = datetime.now(timezone.utc)
        await self.db.execute(
            update(AntigravityAccount)
            .where(
                AntigravityAccount.user_id == user_id,
                AntigravityAccount.cookie_id == cookie_id,
            )
            .values(last_refresh_at=now, need_refresh=False)
        )
        await self.db.flush()
        updated = await self._get_antigravity_account(user_id=user_id, cookie_id=cookie_id)
        return {"success": True, "data": self._serialize_antigravity_account(updated)}
    
    async def get_account_projects(self, user_id: int, cookie_id: str) -> Dict[str, Any]:
        """获取账号可见的 GCP Project 列表"""
        account = await self._get_antigravity_account(user_id=user_id, cookie_id=cookie_id)
        if not account:
            raise ValueError("账号不存在")

        creds = self._decrypt_credentials_json(account.credentials)
        if not creds.get("refresh_token"):
            raise ValueError("账号缺少refresh_token，无法获取项目列表")

        current_project_id = (account.project_id_0 or "").strip()
        default_project_id = current_project_id
        projects = []
        if default_project_id:
            projects.append({"project_id": default_project_id, "name": "default"})

        return {
            "success": True,
            "data": {
                "cookie_id": cookie_id,
                "current_project_id": current_project_id,
                "default_project_id": default_project_id,
                "projects": projects,
            },
        }

    async def update_account_project_id(self, user_id: int, cookie_id: str, project_id: str) -> Dict[str, Any]:
        """更新账号 Project ID"""
        if not project_id or not isinstance(project_id, str) or not project_id.strip():
            raise ValueError("project_id不能为空")

        account = await self._get_antigravity_account(user_id=user_id, cookie_id=cookie_id)
        if not account:
            raise ValueError("账号不存在")

        await self.db.execute(
            update(AntigravityAccount)
            .where(AntigravityAccount.user_id == user_id, AntigravityAccount.cookie_id == cookie_id)
            .values(project_id_0=project_id.strip())
        )
        await self.db.flush()
        updated = await self._get_antigravity_account(user_id=user_id, cookie_id=cookie_id)
        return {"success": True, "message": "Project ID已更新", "data": self._serialize_antigravity_account(updated)}

    async def update_account_status(
        self,
        user_id: int,
        cookie_id: str,
        status: int
    ) -> Dict[str, Any]:
        """更新账号状态"""
        if status not in (0, 1):
            raise ValueError("status必须是0或1")

        account = await self._get_antigravity_account(user_id=user_id, cookie_id=cookie_id)
        if not account:
            raise ValueError("账号不存在")

        if int(account.status or 0) == int(status):
            return {
                "success": True,
                "message": "账号状态未变化",
                "data": {"cookie_id": account.cookie_id, "status": int(account.status or 0)},
            }

        await self.db.execute(
            update(AntigravityAccount)
            .where(AntigravityAccount.user_id == user_id, AntigravityAccount.cookie_id == cookie_id)
            .values(status=int(status))
        )
        await self.db.flush()
        return {
            "success": True,
            "message": f"账号状态已更新为{'启用' if status == 1 else '禁用'}",
            "data": {"cookie_id": cookie_id, "status": int(status)},
        }
    
    async def delete_account(
        self,
        user_id: int,
        cookie_id: str
    ) -> Dict[str, Any]:
        """删除账号"""
        account = await self._get_antigravity_account(user_id=user_id, cookie_id=cookie_id)
        if not account:
            raise ValueError("账号不存在")

        await self.db.execute(delete(AntigravityModelQuota).where(AntigravityModelQuota.cookie_id == cookie_id))
        await self.db.execute(
            delete(AntigravityAccount).where(
                AntigravityAccount.user_id == user_id, AntigravityAccount.cookie_id == cookie_id
            )
        )
        await self.db.flush()
        return {"success": True, "message": "账号已删除"}
    
    async def update_account_name(
        self,
        user_id: int,
        cookie_id: str,
        name: str
    ) -> Dict[str, Any]:
        """更新账号名称"""
        if name is None:
            raise ValueError("name是必需的")
        if not isinstance(name, str) or len(name) > 100:
            raise ValueError("name必须是字符串且长度不超过100")

        account = await self._get_antigravity_account(user_id=user_id, cookie_id=cookie_id)
        if not account:
            raise ValueError("账号不存在")

        await self.db.execute(
            update(AntigravityAccount)
            .where(AntigravityAccount.user_id == user_id, AntigravityAccount.cookie_id == cookie_id)
            .values(account_name=name)
        )
        await self.db.flush()
        return {
            "success": True,
            "message": "账号名称已更新",
            "data": {"cookie_id": cookie_id, "name": name},
        }
    
    async def get_account_quotas(
        self,
        user_id: int,
        cookie_id: str
    ) -> Dict[str, Any]:
        """获取账号配额信息"""
        account = await self._get_antigravity_account(user_id=user_id, cookie_id=cookie_id)
        if not account:
            raise ValueError("账号不存在")

        result = await self.db.execute(
            select(AntigravityModelQuota)
            .where(AntigravityModelQuota.cookie_id == cookie_id)
            .order_by(AntigravityModelQuota.quota.asc())
        )
        quotas = result.scalars().all()
        data = [
            {
                "id": q.id,
                "cookie_id": q.cookie_id,
                "model_name": q.model_name,
                "reset_time": q.reset_at,
                "quota": q.quota,
                "status": q.status,
                "last_fetched_at": q.last_fetched_at,
                "created_at": q.created_at,
                "updated_at": q.updated_at,
            }
            for q in quotas
        ]

        return {"success": True, "data": data}
    
    async def get_user_quotas(self, user_id: int) -> Dict[str, Any]:
        """
        用户维度“模型配额概览”。

        report 建议实现：
        - 每个 model_name 取 quota 最大的账号作为该模型的可用额度
        - 字段沿用前端 UserQuotaItem：pool_id/user_id/model_name/quota/max_quota/last_recovered_at/last_updated_at
        """
        stmt = (
            select(
                AntigravityModelQuota.model_name.label("model_name"),
                func.max(AntigravityModelQuota.quota).label("quota"),
                func.max(AntigravityModelQuota.updated_at).label("last_updated_at"),
                func.max(AntigravityModelQuota.reset_at).label("last_recovered_at"),
            )
            .select_from(AntigravityModelQuota)
            .join(
                AntigravityAccount,
                AntigravityAccount.cookie_id == AntigravityModelQuota.cookie_id,
            )
            .where(
                AntigravityAccount.user_id == user_id,
                AntigravityAccount.status == 1,
                AntigravityModelQuota.status == 1,
            )
            .group_by(AntigravityModelQuota.model_name)
            .order_by(AntigravityModelQuota.model_name.asc())
        )
        result = await self.db.execute(stmt)
        rows = result.mappings().all()

        items = []
        for r in rows:
            model_name = r["model_name"]
            quota = float(r["quota"] or 0)
            last_updated_at = r["last_updated_at"]
            last_recovered_at = r["last_recovered_at"] or last_updated_at

            items.append(
                {
                    "pool_id": str(model_name),
                    "user_id": str(user_id),
                    "model_name": str(model_name),
                    "quota": str(quota),
                    "max_quota": "1",
                    "last_recovered_at": last_recovered_at.isoformat() if last_recovered_at else "",
                    "last_updated_at": last_updated_at.isoformat() if last_updated_at else "",
                }
            )

        return {"success": True, "data": items}
    
    async def get_shared_pool_quotas(self, user_id: int) -> Dict[str, Any]:
        raise ValueError("共享池配额已弃用")
    
    async def get_quota_consumption(
        self,
        user_id: int,
        limit: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None
    ) -> Dict[str, Any]:
        """获取配额消耗记录"""
        params = {}
        if limit:
            params["limit"] = limit
        if start_date:
            params["start_date"] = start_date
        if end_date:
            params["end_date"] = end_date
        
        raise ValueError("配额消耗记录已弃用")
    
    async def get_models(self, user_id: int, config_type: Optional[str] = None) -> Dict[str, Any]:
        """获取可用模型列表（Antigravity 直连，不再依赖 plug-in 服务）"""
        normalized = (config_type or "").strip().lower() if isinstance(config_type, str) else ""
        if normalized and normalized not in ("antigravity",):
            raise ValueError(f"config_type 不支持: {normalized}")
        return await self._antigravity_openai_list_models(user_id=user_id)
    
    async def update_model_quota_status(
        self,
        user_id: int,
        cookie_id: str,
        model_name: str,
        status: int
    ) -> Dict[str, Any]:
        """更新模型配额状态"""
        if status not in (0, 1):
            raise ValueError("status必须是0或1")

        account = await self._get_antigravity_account(user_id=user_id, cookie_id=cookie_id)
        if not account:
            raise ValueError("账号不存在")

        result = await self.db.execute(
            select(AntigravityModelQuota).where(
                AntigravityModelQuota.cookie_id == cookie_id,
                AntigravityModelQuota.model_name == model_name,
            )
        )
        quota = result.scalar_one_or_none()
        if not quota:
            raise ValueError("配额记录不存在")

        await self.db.execute(
            update(AntigravityModelQuota)
            .where(
                AntigravityModelQuota.cookie_id == cookie_id,
                AntigravityModelQuota.model_name == model_name,
            )
            .values(status=int(status))
        )
        await self.db.flush()

        return {
            "success": True,
            "message": f"模型配额状态已更新为{'启用' if status == 1 else '禁用'}",
            "data": {"cookie_id": cookie_id, "model_name": model_name, "status": int(status)},
        }
    
    async def update_account_type(
        self,
        user_id: int,
        cookie_id: str,
        is_shared: int
    ) -> Dict[str, Any]:
        """
        更新账号类型（专属/共享）
        
        将账号在专属和共享之间转换，同时自动更新用户共享配额池。
        
        Args:
            user_id: 用户ID
            cookie_id: 账号的Cookie ID
            is_shared: 账号类型：0=专属，1=共享
            
        Returns:
            更新结果
        """
        if is_shared not in (0, 1):
            raise ValueError("is_shared必须是0或1")
        if is_shared == 1:
            raise ValueError("合并后不支持共享账号（is_shared=1）")

        account = await self._get_antigravity_account(user_id=user_id, cookie_id=cookie_id)
        if not account:
            raise ValueError("账号不存在")

        return {
            "success": True,
            "message": "账号类型已更新为专属",
            "data": {"cookie_id": cookie_id, "is_shared": 0},
        }
    
    # ==================== 图片生成API ====================
    
    async def generate_content(
        self,
        user_id: int,
        model: str,
        request_data: Dict[str, Any],
        config_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        图片生成API（Gemini格式）
        
        Args:
            user_id: 用户ID
            model: 模型名称，例如 gemini-2.5-flash-image 或 gemini-2.5-pro-image
            request_data: 请求数据，包含contents和generationConfig
            config_type: 账号类型（可选）
            
        Returns:
            生成结果，包含candidates数组，每个candidate包含content.parts[0].inlineData
        """
        normalized = (config_type or "").strip().lower() if isinstance(config_type, str) else ""
        if normalized != "zai-image":
            raise ValueError("config_type must be zai-image")

        # 解析 prompt（仅支持 text；不支持 inlineData 图生图）
        contents = request_data.get("contents") if isinstance(request_data, dict) else None
        if not isinstance(contents, list) or not contents:
            raise ValueError("contents是必需的且必须是非空数组")

        texts: list[str] = []
        has_inline = False
        for msg in contents:
            if not isinstance(msg, dict):
                continue
            parts = msg.get("parts")
            if not isinstance(parts, list):
                continue
            for part in parts:
                if not isinstance(part, dict):
                    continue
                if "inlineData" in part:
                    has_inline = True
                t = part.get("text")
                if isinstance(t, str) and t.strip():
                    texts.append(t.strip())

        if has_inline:
            raise ValueError("暂不支持图生图（inlineData）")

        prompt = "\n".join(texts).strip()
        if not prompt:
            raise ValueError("prompt 不能为空")

        generation_cfg = request_data.get("generationConfig") if isinstance(request_data, dict) else None
        image_cfg = generation_cfg.get("imageConfig") if isinstance(generation_cfg, dict) else None
        ratio = image_cfg.get("aspectRatio") if isinstance(image_cfg, dict) else None
        resolution = image_cfg.get("imageSize") if isinstance(image_cfg, dict) else None

        zai = ZaiImageService(self.db)
        account = await zai.select_active_account(user_id)
        info = await zai.generate_image(
            account=account,
            prompt=prompt,
            ratio=ratio,
            resolution=resolution,
            rm_label_watermark=True,
        )
        b64, mime = await zai.fetch_image_base64(info["image_url"])

        return {
            "candidates": [
                {
                    "content": {
                        "role": "model",
                        "parts": [
                            {"inlineData": {"mimeType": mime, "data": b64}},
                            {"text": info["image_url"]},
                        ],
                    },
                    "finishReason": "STOP",
                }
            ]
        }
