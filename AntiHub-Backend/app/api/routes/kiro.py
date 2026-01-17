"""
Kiro账号管理API路由
提供Kiro账号的管理操作，通过插件API实现
"""
import secrets
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session, get_redis, get_current_user, get_current_admin_user
from app.models.user import User
from app.services.kiro_service import KiroService, UpstreamAPIError
from app.schemas.kiro import (
    KiroOAuthAuthorizeRequest,
    KiroOAuthCallbackRequest,
    KiroSubscriptionModelRuleUpdateRequest,
)
from app.cache import RedisClient

router = APIRouter(prefix="/api/kiro", tags=["Kiro账号管理"])


def get_kiro_service(
    db: AsyncSession = Depends(get_db_session),
    redis: RedisClient = Depends(get_redis)
) -> KiroService:
    """获取Kiro服务实例（带Redis缓存支持）"""
    return KiroService(db, redis)


# ==================== Kiro OAuth ====================

@router.post(
    "/oauth/authorize",
    summary="获取Kiro OAuth授权URL",
    description="获取Kiro账号OAuth授权URL"
)
async def get_oauth_authorize_url(
    request: KiroOAuthAuthorizeRequest,
    current_user: User = Depends(get_current_user),
    service: KiroService = Depends(get_kiro_service)
):
    """
    获取Kiro OAuth授权URL
    
    - **provider**: OAuth提供商（Google 或 Github）
    - **is_shared**: 0=专属cookie，1=共享cookie
    """
    try:
        result = await service.get_oauth_authorize_url(
            user_id=current_user.id,
            provider=request.provider,
            is_shared=request.is_shared
        )
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取OAuth授权URL失败: {str(e)}"
        )


@router.post(
    "/oauth/callback",
    summary="提交 Kiro OAuth 回调 (AntiHook)",
    description="用于桌面端 AntiHook 将 kiro:// 回调转发到服务器；后端会代理到 plug-in API 完成处理。"
)
async def submit_oauth_callback(
    request: KiroOAuthCallbackRequest,
    service: KiroService = Depends(get_kiro_service)
):
    """
    AntiHook 回调入口（不需要用户鉴权）：
    - OAuth state 信息由 plug-in API 在授权阶段写入 Redis
    - callback 阶段只需要把 kiro:// 回调 URL 转发给 plug-in API 即可
    """
    try:
        if not request.callback_url or not request.callback_url.lower().startswith("kiro://"):
            raise ValueError("callback_url 必须是完整的 kiro:// 回调 URL")

        return await service.submit_oauth_callback(callback_url=request.callback_url)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"处理 OAuth 回调失败: {str(e)}"
        )


@router.get(
    "/oauth/status/{state}",
    summary="轮询Kiro OAuth授权状态",
    description="轮询Kiro账号OAuth授权状态"
)
async def get_oauth_status(
    state: str,
    current_user: User = Depends(get_current_user),
    service: KiroService = Depends(get_kiro_service)
):
    """
    轮询Kiro OAuth授权状态
    
    - **state**: 从authorize接口获取的state值
    """
    try:
        result = await service.get_oauth_status(
            user_id=current_user.id,
            state=state
        )
        return result
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取OAuth授权状态失败: {str(e)}"
        )


# ==================== Kiro账号管理 ====================

@router.post(
    "/accounts",
    summary="创建Kiro账号",
    description="创建新的Kiro账号"
)
async def create_account(
    account_data: dict,
    current_user: User = Depends(get_current_user),
    service: KiroService = Depends(get_kiro_service)
):
    """
    创建Kiro账号
    
    - **account_name**: 账号名称
    - **auth_method**: 认证方法（Social 或 IdC）
    - **refresh_token**: AWS刷新令牌
    - **client_id**: IdC客户端ID（IdC认证时必填）
    - **client_secret**: IdC客户端密钥（IdC认证时必填）
    """
    try:
        if "refresh_token" not in account_data and "refreshToken" in account_data:
            account_data["refresh_token"] = account_data.get("refreshToken")
        if "auth_method" not in account_data and "authMethod" in account_data:
            account_data["auth_method"] = account_data.get("authMethod")
        if "account_name" not in account_data and "accountName" in account_data:
            account_data["account_name"] = account_data.get("accountName")
        if "client_id" not in account_data and "clientId" in account_data:
            account_data["client_id"] = account_data.get("clientId")
        if "client_secret" not in account_data and "clientSecret" in account_data:
            account_data["client_secret"] = account_data.get("clientSecret")
        if "machineid" not in account_data and "machineId" in account_data:
            account_data["machineid"] = account_data.get("machineId")
        if "is_shared" not in account_data and "isShared" in account_data:
            account_data["is_shared"] = account_data.get("isShared")

        auth_method = (account_data.get("auth_method") or "Social").strip()
        if auth_method.lower() == "social":
            auth_method = "Social"
        elif auth_method.lower() == "idc":
            auth_method = "IdC"
        account_data["auth_method"] = auth_method

        refresh_token = account_data.get("refresh_token")
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="missing refresh_token"
            )

        if auth_method not in ("Social", "IdC"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="auth_method must be Social or IdC"
            )

        if auth_method == "IdC" and (not account_data.get("client_id") or not account_data.get("client_secret")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="IdC requires client_id and client_secret"
            )

        if not account_data.get("machineid"):
            account_data["machineid"] = secrets.token_hex(32)

        is_shared = account_data.get("is_shared")
        if is_shared is None:
            is_shared = 0
        if isinstance(is_shared, bool):
            is_shared = 1 if is_shared else 0
        try:
            is_shared = int(is_shared)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="is_shared must be 0 or 1"
            )
        if is_shared not in (0, 1):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="is_shared must be 0 or 1"
            )
        account_data["is_shared"] = is_shared

        if not account_data.get("account_name"):
            account_data["account_name"] = "Kiro Account"

        result = await service.create_account(current_user.id, account_data)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"创建账号失败: {str(e)}"
        )


@router.get(
    "/accounts",
    summary="获取Kiro账号列表",
    description="获取当前用户的所有Kiro账号"
)
async def list_accounts(
    current_user: User = Depends(get_current_user),
    service: KiroService = Depends(get_kiro_service)
):
    """获取用户的所有Kiro账号"""
    try:
        result = await service.get_accounts(current_user.id)
        return result
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取账号列表失败: {str(e)}"
        )


@router.get(
    "/accounts/{account_id}",
    summary="获取单个Kiro账号",
    description="获取指定Kiro账号的详细信息"
)
async def get_account(
    account_id: str,
    current_user: User = Depends(get_current_user),
    service: KiroService = Depends(get_kiro_service)
):
    """获取单个账号信息"""
    try:
        result = await service.get_account(current_user.id, account_id)
        return result
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"账号不存在: {str(e)}"
        )


@router.get(
    "/accounts/{account_id}/credentials",
    summary="导出账号凭证",
    description="导出指定Kiro账号保存的凭证信息（敏感），用于前端复制为 JSON",
)
async def get_account_credentials(
    account_id: str,
    current_user: User = Depends(get_current_user),
    service: KiroService = Depends(get_kiro_service),
):
    """导出Kiro账号凭证（敏感信息）"""
    try:
        return await service.get_account_credentials(current_user.id, account_id)
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error",
            },
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"导出账号凭证失败: {str(e)}",
        )


@router.put(
    "/accounts/{account_id}/status",
    summary="更新账号状态",
    description="启用或禁用Kiro账号"
)
async def update_account_status(
    account_id: str,
    update_data: dict,
    current_user: User = Depends(get_current_user),
    service: KiroService = Depends(get_kiro_service)
):
    """
    更新账号状态
    
    - **status**: 0=禁用，1=启用
    """
    try:
        status_value = update_data.get("status")
        if status_value not in [0, 1]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="status必须是0或1"
            )
        
        result = await service.update_account_status(current_user.id, account_id, status_value)
        return result
    except HTTPException:
        raise
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"更新状态失败: {str(e)}"
        )


@router.put(
    "/accounts/{account_id}/name",
    summary="更新账号名称",
    description="修改Kiro账号的显示名称"
)
async def update_account_name(
    account_id: str,
    update_data: dict,
    current_user: User = Depends(get_current_user),
    service: KiroService = Depends(get_kiro_service)
):
    """
    更新账号名称
    
    - **account_name**: 新的账号名称
    """
    try:
        account_name = update_data.get("account_name")
        if not account_name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="account_name不能为空"
            )
        
        result = await service.update_account_name(current_user.id, account_id, account_name)
        return result
    except HTTPException:
        raise
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"更新名称失败: {str(e)}"
        )


@router.get(
    "/accounts/{account_id}/balance",
    summary="获取账号余额",
    description="获取Kiro账号的使用量和余额信息"
)
async def get_account_balance(
    account_id: str,
    current_user: User = Depends(get_current_user),
    service: KiroService = Depends(get_kiro_service)
):
    """获取账号余额"""
    try:
        result = await service.get_account_balance(current_user.id, account_id)
        return result
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取余额失败: {str(e)}"
        )


@router.get(
    "/accounts/{account_id}/consumption",
    summary="获取账号消费记录",
    description="获取Kiro账号的消费记录和统计"
)
async def get_account_consumption(
    account_id: str,
    limit: int = Query(100, description="每页数量"),
    offset: int = Query(0, description="偏移量"),
    start_date: Optional[str] = Query(None, description="开始日期（ISO格式）"),
    end_date: Optional[str] = Query(None, description="结束日期（ISO格式）"),
    current_user: User = Depends(get_current_user),
    service: KiroService = Depends(get_kiro_service)
):
    """获取账号消费记录"""
    try:
        result = await service.get_account_consumption(
            user_id=current_user.id,
            account_id=account_id,
            limit=limit,
            offset=offset,
            start_date=start_date,
            end_date=end_date
        )
        return result
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取消费记录失败: {str(e)}"
        )


@router.get(
    "/consumption/stats",
    summary="获取用户总消费统计",
    description="获取用户所有Kiro账号的总消费统计"
)
async def get_user_consumption_stats(
    start_date: Optional[str] = Query(None, description="开始日期（ISO格式）"),
    end_date: Optional[str] = Query(None, description="结束日期（ISO格式）"),
    current_user: User = Depends(get_current_user),
    service: KiroService = Depends(get_kiro_service)
):
    """获取用户总消费统计"""
    try:
        result = await service.get_user_consumption_stats(
            user_id=current_user.id,
            start_date=start_date,
            end_date=end_date
        )
        return result
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取统计数据失败: {str(e)}"
        )


@router.delete(
    "/accounts/{account_id}",
    summary="删除Kiro账号",
    description="删除指定的Kiro账号"
)
async def delete_account(
    account_id: str,
    current_user: User = Depends(get_current_user),
    service: KiroService = Depends(get_kiro_service)
):
    """删除Kiro账号"""
    try:
        result = await service.delete_account(current_user.id, account_id)
        return result
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error"
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"删除账号失败: {str(e)}"
        )


# ==================== 订阅层 -> 可用模型（管理员配置） ====================

@router.get(
    "/admin/subscription-models",
    summary="获取订阅层可用模型配置",
    description="获取 Kiro 不同订阅层可用的模型白名单配置（需要管理员权限）",
)
async def get_subscription_model_rules(
    _: User = Depends(get_current_admin_user),
    service: KiroService = Depends(get_kiro_service),
):
    try:
        return await service.get_subscription_model_rules()
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error",
            },
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取订阅层可用模型配置失败: {str(e)}",
        )


@router.put(
    "/admin/subscription-models",
    summary="设置订阅层可用模型配置",
    description="设置 Kiro 不同订阅层可用的模型白名单配置（需要管理员权限）",
)
async def upsert_subscription_model_rule(
    request: KiroSubscriptionModelRuleUpdateRequest,
    _: User = Depends(get_current_admin_user),
    service: KiroService = Depends(get_kiro_service),
):
    try:
        return await service.upsert_subscription_model_rule(
            subscription=request.subscription,
            model_ids=request.model_ids,
        )
    except UpstreamAPIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.extracted_message,
                "type": "api_error",
            },
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"设置订阅层可用模型配置失败: {str(e)}",
        )
