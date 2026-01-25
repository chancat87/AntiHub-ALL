"""
GeminiCLI 账号管理 API

目标：
- 生成登录链接（Google OAuth）
- 解析回调 URL 并落库
- 导入/导出账号凭证（JSON）
- 账号列表/详情/启用禁用/改名/删除/更新项目
"""

from __future__ import annotations

import logging

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db_session, get_redis
from app.cache import RedisClient
from app.models.user import User
from app.schemas.gemini_cli import (
    GeminiCLIOAuthAuthorizeRequest,
    GeminiCLIOAuthCallbackRequest,
    GeminiCLIAccountImportRequest,
    GeminiCLIAccountUpdateStatusRequest,
    GeminiCLIAccountUpdateNameRequest,
    GeminiCLIAccountUpdateProjectRequest,
    GeminiCLIAccountResponse,
)
from app.services.gemini_cli_service import GeminiCLIService


router = APIRouter(prefix="/api/gemini-cli", tags=["GeminiCLI账号管理"])
logger = logging.getLogger(__name__)


def get_gemini_cli_service(
    db: AsyncSession = Depends(get_db_session),
    redis: RedisClient = Depends(get_redis),
) -> GeminiCLIService:
    return GeminiCLIService(db, redis)


def _serialize_account(account) -> dict:
    return GeminiCLIAccountResponse.model_validate(account).model_dump(by_alias=False)


@router.post("/oauth/authorize", summary="生成 GeminiCLI OAuth 登录链接")
async def gemini_cli_oauth_authorize(
    request: GeminiCLIOAuthAuthorizeRequest,
    current_user: User = Depends(get_current_user),
    service: GeminiCLIService = Depends(get_gemini_cli_service),
):
    try:
        return await service.create_oauth_authorize_url(
            user_id=current_user.id,
            is_shared=request.is_shared,
            account_name=request.account_name,
            project_id=request.project_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("create oauth authorize url failed: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="生成登录链接失败",
        )


@router.post("/oauth/callback", summary="提交 GeminiCLI OAuth 回调 URL 并落库")
async def gemini_cli_oauth_callback(
    request: GeminiCLIOAuthCallbackRequest,
    current_user: User = Depends(get_current_user),
    service: GeminiCLIService = Depends(get_gemini_cli_service),
):
    try:
        result = await service.submit_oauth_callback(
            user_id=current_user.id,
            callback_url=request.callback_url,
        )
        result["data"] = _serialize_account(result["data"])
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("oauth callback failed: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="处理 OAuth 回调失败",
        )


@router.post("/accounts/import", summary="导入 GeminiCLI 凭证 JSON 并落库")
async def import_gemini_cli_account(
    request: GeminiCLIAccountImportRequest,
    current_user: User = Depends(get_current_user),
    service: GeminiCLIService = Depends(get_gemini_cli_service),
):
    try:
        result = await service.import_account(
            user_id=current_user.id,
            credential_json=request.credential_json,
            is_shared=request.is_shared,
            account_name=request.account_name,
        )
        result["data"] = _serialize_account(result["data"])
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("import account failed: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="导入账号失败",
        )


@router.get("/accounts", summary="获取 GeminiCLI 账号列表")
async def list_gemini_cli_accounts(
    current_user: User = Depends(get_current_user),
    service: GeminiCLIService = Depends(get_gemini_cli_service),
):
    try:
        result = await service.list_accounts(current_user.id)
        result["data"] = [_serialize_account(a) for a in result["data"]]
        return result
    except Exception as e:
        logger.error("list accounts failed: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="获取账号列表失败",
        )


@router.get("/accounts/{account_id}", summary="获取单个 GeminiCLI 账号详情")
async def get_gemini_cli_account(
    account_id: int,
    current_user: User = Depends(get_current_user),
    service: GeminiCLIService = Depends(get_gemini_cli_service),
):
    try:
        result = await service.get_account(current_user.id, account_id)
        result["data"] = _serialize_account(result["data"])
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.error("get account failed: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="获取账号详情失败",
        )


@router.get("/accounts/{account_id}/credentials", summary="导出 GeminiCLI 账号凭证（敏感）")
async def export_gemini_cli_account_credentials(
    account_id: int,
    current_user: User = Depends(get_current_user),
    service: GeminiCLIService = Depends(get_gemini_cli_service),
):
    try:
        return await service.export_account_credentials(current_user.id, account_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.error("export credentials failed: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="导出凭证失败",
        )


@router.get("/accounts/{account_id}/quota", summary="查询 GeminiCLI 剩余额度（retrieveUserQuota）")
async def get_gemini_cli_account_quota(
    account_id: int,
    project_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    service: GeminiCLIService = Depends(get_gemini_cli_service),
):
    try:
        return await service.get_account_quota(
            current_user.id, account_id, project_id=project_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(
            "get gemini_cli quota failed: user_id=%s account_id=%s error=%s",
            current_user.id,
            account_id,
            type(e).__name__,
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="查询额度失败",
        )


@router.put("/accounts/{account_id}/status", summary="启用/禁用 GeminiCLI 账号")
async def update_gemini_cli_account_status(
    account_id: int,
    request: GeminiCLIAccountUpdateStatusRequest,
    current_user: User = Depends(get_current_user),
    service: GeminiCLIService = Depends(get_gemini_cli_service),
):
    try:
        result = await service.update_account_status(
            current_user.id, account_id, request.status
        )
        result["data"] = _serialize_account(result["data"])
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("update status failed: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="更新账号状态失败",
        )


@router.put("/accounts/{account_id}/name", summary="更新 GeminiCLI 账号名称")
async def update_gemini_cli_account_name(
    account_id: int,
    request: GeminiCLIAccountUpdateNameRequest,
    current_user: User = Depends(get_current_user),
    service: GeminiCLIService = Depends(get_gemini_cli_service),
):
    try:
        result = await service.update_account_name(
            current_user.id, account_id, request.account_name
        )
        result["data"] = _serialize_account(result["data"])
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("update name failed: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="更新账号名称失败",
        )


@router.put("/accounts/{account_id}/project", summary="更新 GeminiCLI 账号 GCP Project ID")
async def update_gemini_cli_account_project(
    account_id: int,
    request: GeminiCLIAccountUpdateProjectRequest,
    current_user: User = Depends(get_current_user),
    service: GeminiCLIService = Depends(get_gemini_cli_service),
):
    try:
        result = await service.update_account_project(
            current_user.id, account_id, request.project_id
        )
        result["data"] = _serialize_account(result["data"])
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("update project failed: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="更新项目ID失败",
        )


@router.delete("/accounts/{account_id}", summary="删除 GeminiCLI 账号")
async def delete_gemini_cli_account(
    account_id: int,
    current_user: User = Depends(get_current_user),
    service: GeminiCLIService = Depends(get_gemini_cli_service),
):
    try:
        return await service.delete_account(current_user.id, account_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.error("delete account failed: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="删除账号失败",
        )
