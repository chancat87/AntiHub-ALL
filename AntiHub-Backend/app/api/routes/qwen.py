"""
Qwen 账号管理 API 路由

设计：
- 账号数据存储在 AntiHub-plugin（Node 服务）的数据库中；
- 后端仅负责鉴权、转发请求、以及把错误信息透传给前端。
"""

from fastapi import APIRouter, Depends, HTTPException, status
import httpx

from app.api.deps import get_current_user, get_plugin_api_service
from app.models.user import User
from app.services.plugin_api_service import PluginAPIService
from app.schemas.qwen import (
    QwenAccountImportRequest,
    QwenAccountUpdateStatusRequest,
    QwenAccountUpdateNameRequest,
    QwenOAuthAuthorizeRequest,
)


router = APIRouter(prefix="/api/qwen", tags=["Qwen账号管理"])


def _raise_upstream_http_error(e: httpx.HTTPStatusError):
    error_data = getattr(e, "response_data", {"detail": str(e)})
    if isinstance(error_data, dict):
        detail = error_data.get("detail") or error_data.get("error") or error_data
    else:
        detail = error_data
    raise HTTPException(status_code=e.response.status_code, detail=detail)


@router.post(
    "/oauth/authorize",
    summary="生成 Qwen OAuth 登录链接",
    description="使用 Qwen OAuth Device Flow 生成授权链接，并由 plug-in 在后台轮询完成登录后落库。",
)
async def qwen_oauth_authorize(
    request: QwenOAuthAuthorizeRequest,
    current_user: User = Depends(get_current_user),
    service: PluginAPIService = Depends(get_plugin_api_service),
):
    try:
        if request.is_shared not in (0, 1):
            raise ValueError("is_shared 必须是 0 或 1")
        result = await service.proxy_request(
            user_id=current_user.id,
            method="POST",
            path="/api/qwen/oauth/authorize",
            json_data={
                "is_shared": request.is_shared,
                "account_name": request.account_name,
            },
        )
        return result
    except httpx.HTTPStatusError as e:
        _raise_upstream_http_error(e)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="生成 Qwen OAuth 登录链接失败",
        )


@router.get(
    "/oauth/status/{state}",
    summary="轮询 Qwen OAuth 登录状态",
    description="轮询 plug-in 内部的 Qwen OAuth 登录状态，不返回敏感 token。",
)
async def qwen_oauth_status(
    state: str,
    current_user: User = Depends(get_current_user),
    service: PluginAPIService = Depends(get_plugin_api_service),
):
    try:
        if not state or not state.strip():
            raise ValueError("state 不能为空")
        return await service.proxy_request(
            user_id=current_user.id,
            method="GET",
            path=f"/api/qwen/oauth/status/{state.strip()}",
        )
    except httpx.HTTPStatusError as e:
        _raise_upstream_http_error(e)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="查询 Qwen OAuth 登录状态失败",
        )


@router.post(
    "/accounts/import",
    summary="导入 QwenCli JSON",
    description="将 QwenCli 导出的 JSON 凭证导入到 plug-in 数据库中",
)
async def import_qwen_account(
    request: QwenAccountImportRequest,
    current_user: User = Depends(get_current_user),
    service: PluginAPIService = Depends(get_plugin_api_service),
):
    try:
        if request.is_shared not in (0, 1):
            raise ValueError("is_shared 必须是 0 或 1")
        result = await service.proxy_request(
            user_id=current_user.id,
            method="POST",
            path="/api/qwen/accounts/import",
            json_data={
                "is_shared": request.is_shared,
                "credential_json": request.credential_json,
                "account_name": request.account_name,
            },
        )
        return result
    except httpx.HTTPStatusError as e:
        _raise_upstream_http_error(e)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="导入 Qwen 账号失败",
        )


@router.get(
    "/accounts",
    summary="获取 Qwen 账号列表",
    description="获取当前用户的所有 Qwen 账号",
)
async def list_qwen_accounts(
    current_user: User = Depends(get_current_user),
    service: PluginAPIService = Depends(get_plugin_api_service),
):
    try:
        return await service.proxy_request(
            user_id=current_user.id,
            method="GET",
            path="/api/qwen/accounts",
        )
    except httpx.HTTPStatusError as e:
        _raise_upstream_http_error(e)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="获取 Qwen 账号列表失败",
        )


@router.get(
    "/accounts/{account_id}",
    summary="获取单个 Qwen 账号",
    description="获取指定 Qwen 账号详情（不包含敏感 token）",
)
async def get_qwen_account(
    account_id: str,
    current_user: User = Depends(get_current_user),
    service: PluginAPIService = Depends(get_plugin_api_service),
):
    try:
        return await service.proxy_request(
            user_id=current_user.id,
            method="GET",
            path=f"/api/qwen/accounts/{account_id}",
        )
    except httpx.HTTPStatusError as e:
        _raise_upstream_http_error(e)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="获取 Qwen 账号失败",
        )


@router.get(
    "/accounts/{account_id}/credentials",
    summary="导出 Qwen 凭证",
    description="导出指定 Qwen 账号保存的凭证信息（敏感），用于前端复制为 JSON",
)
async def get_qwen_account_credentials(
    account_id: str,
    current_user: User = Depends(get_current_user),
    service: PluginAPIService = Depends(get_plugin_api_service),
):
    try:
        return await service.proxy_request(
            user_id=current_user.id,
            method="GET",
            path=f"/api/qwen/accounts/{account_id}/credentials",
        )
    except httpx.HTTPStatusError as e:
        _raise_upstream_http_error(e)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="导出 Qwen 凭证失败",
        )


@router.put(
    "/accounts/{account_id}/status",
    summary="更新 Qwen 账号状态",
    description="启用/禁用 Qwen 账号",
)
async def update_qwen_account_status(
    account_id: str,
    request: QwenAccountUpdateStatusRequest,
    current_user: User = Depends(get_current_user),
    service: PluginAPIService = Depends(get_plugin_api_service),
):
    try:
        if request.status not in (0, 1):
            raise ValueError("status 必须是 0 或 1")
        return await service.proxy_request(
            user_id=current_user.id,
            method="PUT",
            path=f"/api/qwen/accounts/{account_id}/status",
            json_data={"status": request.status},
        )
    except httpx.HTTPStatusError as e:
        _raise_upstream_http_error(e)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="更新 Qwen 账号状态失败",
        )


@router.put(
    "/accounts/{account_id}/name",
    summary="更新 Qwen 账号名称",
    description="修改 Qwen 账号显示名称",
)
async def update_qwen_account_name(
    account_id: str,
    request: QwenAccountUpdateNameRequest,
    current_user: User = Depends(get_current_user),
    service: PluginAPIService = Depends(get_plugin_api_service),
):
    try:
        if not request.account_name or not request.account_name.strip():
            raise ValueError("account_name 不能为空")
        return await service.proxy_request(
            user_id=current_user.id,
            method="PUT",
            path=f"/api/qwen/accounts/{account_id}/name",
            json_data={"account_name": request.account_name},
        )
    except httpx.HTTPStatusError as e:
        _raise_upstream_http_error(e)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="更新 Qwen 账号名称失败",
        )


@router.delete(
    "/accounts/{account_id}",
    summary="删除 Qwen 账号",
    description="删除指定 Qwen 账号",
)
async def delete_qwen_account(
    account_id: str,
    current_user: User = Depends(get_current_user),
    service: PluginAPIService = Depends(get_plugin_api_service),
):
    try:
        return await service.proxy_request(
            user_id=current_user.id,
            method="DELETE",
            path=f"/api/qwen/accounts/{account_id}",
        )
    except httpx.HTTPStatusError as e:
        _raise_upstream_http_error(e)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="删除 Qwen 账号失败",
        )
