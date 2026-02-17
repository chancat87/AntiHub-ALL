"""
认证相关的 API 路由
提供登录、登出、Token 刷新等端点
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request

from app.api.deps import (
    get_auth_service,
    get_user_service,
    get_current_user,
)
from app.services.auth_service import AuthService
from app.services.user_service import UserService
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    LogoutResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
)
from app.schemas.user import UserResponse, JoinBetaResponse
from app.core.config import get_settings
from app.core.exceptions import (
    InvalidCredentialsError,
    AccountDisabledError,
    InvalidTokenError,
    TokenExpiredError,
    TokenBlacklistedError,
    UserNotFoundError,
)


router = APIRouter(prefix="/auth", tags=["认证"])


# ==================== 传统登录 ====================

@router.post(
    "/login",
    response_model=LoginResponse,
    summary="用户名密码登录",
    description="使用用户名和密码进行传统登录，返回 access_token 和 refresh_token"
)
async def login(
    request: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    """
    传统用户名密码登录

    - **username**: 用户名
    - **password**: 密码

    返回 JWT 访问令牌、刷新令牌和用户信息
    """
    settings = get_settings()
    try:
        # 登录
        access_token, refresh_token, user = await auth_service.login(
            username=request.username,
            password=request.password
        )

        # 返回响应
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.jwt_expire_seconds,
            user=UserResponse.model_validate(user)
        )
        
    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message
        )
    except AccountDisabledError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=e.message
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"登录失败"
        )


# ==================== Token 刷新 ====================

@router.post(
    "/refresh",
    response_model=RefreshTokenResponse,
    summary="刷新访问令牌",
    description="使用 refresh_token 获取新的 access_token 和 refresh_token（无感刷新）"
)
async def refresh_token(
    request: RefreshTokenRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    刷新访问令牌
    
    使用有效的 refresh_token 获取新的令牌对，实现无感刷新
    
    - **refresh_token**: 刷新令牌
    
    返回新的 access_token 和 refresh_token
    
    注意：每次刷新后，旧的 refresh_token 将失效（Token 轮换机制）
    """
    settings = get_settings()
    try:
        # 刷新令牌
        new_access_token, new_refresh_token, user = await auth_service.refresh_tokens(
            refresh_token=request.refresh_token
        )
        
        # 返回响应
        return RefreshTokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            expires_in=settings.jwt_expire_seconds
        )
        
    except TokenExpiredError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh Token 已过期，请重新登录",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except (InvalidTokenError, TokenBlacklistedError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh Token 无效或已被撤销",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except UserNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户不存在"
        )
    except AccountDisabledError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=e.message
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"刷新令牌失败"
        )


# ==================== 登出 ====================

@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="用户登出",
    description="登出当前用户,删除会话并将令牌加入黑名单"
)
async def logout(
    request: Request,
    logout_request: LogoutRequest = None,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    用户登出
    
    需要在请求头中提供有效的 JWT 令牌:
    ```
    Authorization: Bearer <your_token>
    ```
    
    可选提供 refresh_token 以使其失效
    
    登出后 access_token 和 refresh_token 都将失效
    """
    try:
        # 从请求头中提取 access token
        auth_header = request.headers.get("Authorization", "")
        access_token = ""
        if auth_header.startswith("Bearer "):
            access_token = auth_header[7:]
        
        # 获取 refresh token（如果提供）
        refresh_token = None
        if logout_request and logout_request.refresh_token:
            refresh_token = logout_request.refresh_token
        
        # 执行登出
        await auth_service.logout(
            user_id=current_user.id,
            access_token=access_token,
            refresh_token=refresh_token
        )
        
        return LogoutResponse(
            message="登出成功",
            success=True
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"登出失败"
        )


@router.post(
    "/logout-all",
    response_model=LogoutResponse,
    summary="登出所有设备",
    description="登出当前用户的所有设备,撤销所有 refresh token"
)
async def logout_all_devices(
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    登出所有设备
    
    需要在请求头中提供有效的 JWT 令牌:
    ```
    Authorization: Bearer <your_token>
    ```
    
    此操作将撤销用户的所有 refresh token，使所有设备都需要重新登录
    """
    try:
        await auth_service.logout_all_devices(current_user.id)
        
        return LogoutResponse(
            message="已登出所有设备",
            success=True
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"登出失败"
        )


# ==================== 获取当前用户信息 ====================

@router.get(
    "/me",
    response_model=UserResponse,
    summary="获取当前用户信息",
    description="获取当前登录用户的详细信息"
)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """
    获取当前用户信息
    
    需要在请求头中提供有效的 JWT 令牌:
    ```
    Authorization: Bearer <your_token>
    ```
    
    返回当前用户的详细信息
    """
    try:
        return UserResponse.model_validate(current_user)
    except Exception as e:
        # 记录详细错误信息
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"获取用户信息失败: {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取用户信息失败: {str(e)}"
        )


# ==================== 用户验证 ====================

@router.get(
    "/check-username",
    summary="检查用户名是否存在",
    description="检查指定的用户名是否已在系统中注册（无需登录）"
)
async def check_username(
    username: str = Query(..., description="要检查的用户名"),
    user_service: UserService = Depends(get_user_service)
):
    """
    检查用户名是否存在
    
    用于登录前验证用户是否已注册
    
    - **username**: 要检查的用户名
    
    返回用户是否存在的信息
    """
    try:
        # 通过用户名查找用户
        user = await user_service.get_user_by_username(username)
        
        if user:
            return {
                "exists": True,
                "message": "用户名已存在",
                "username": username
            }
        else:
            return {
                "exists": False,
                "message": "用户名不存在",
                "username": username
            }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"检查用户名失败"
        )


# ==================== Beta 计划 ====================

@router.post(
    "/join-beta",
    response_model=JoinBetaResponse,
    summary="加入 Beta 计划",
    description="当前用户加入 Beta 计划"
)
async def join_beta(
    current_user: User = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    """
    加入 Beta 计划
    
    需要在请求头中提供有效的 JWT 令牌:
    ```
    Authorization: Bearer <your_token>
    ```
    
    将当前用户的 beta 字段设置为 1
    """
    try:
        # 先从数据库获取最新的用户状态
        latest_user = await user_service.get_user_by_id(current_user.id)
        if not latest_user:
            raise UserNotFoundError(
                message=f"用户 ID {current_user.id} 不存在",
                details={"user_id": current_user.id}
            )
        
        # 检查用户是否已经加入 beta
        if latest_user.beta == 1:
            return JoinBetaResponse(
                success=True,
                message="您已经加入了 Beta 计划",
                beta=latest_user.beta
            )
        
        # 加入 beta 计划
        updated_user = await user_service.join_beta(current_user.id)
        
        return JoinBetaResponse(
            success=True,
            message="成功加入 Beta 计划",
            beta=updated_user.beta
        )
        
    except UserNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=e.message
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"加入 Beta 计划失败"
        )


@router.get(
    "/beta-status",
    response_model=JoinBetaResponse,
    summary="获取 Beta 计划状态",
    description="获取当前用户的 Beta 计划状态"
)
async def get_beta_status(
    current_user: User = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    """
    获取 Beta 计划状态
    
    需要在请求头中提供有效的 JWT 令牌:
    ```
    Authorization: Bearer <your_token>
    ```
    
    返回当前用户的 beta 状态
    """
    # 从数据库获取最新状态
    latest_user = await user_service.get_user_by_id(current_user.id)
    if not latest_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )
    
    return JoinBetaResponse(
        success=True,
        message="已加入 Beta 计划" if latest_user.beta == 1 else "未加入 Beta 计划",
        beta=latest_user.beta
    )
