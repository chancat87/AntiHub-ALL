"""
管理员账号初始化

根据环境变量 `ADMIN_USERNAME` / `ADMIN_PASSWORD` 在启动时确保管理员账号存在。
"""

from __future__ import annotations

import logging

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import hash_password
from app.repositories.user_repository import UserRepository
from app.cache import get_redis_client

logger = logging.getLogger(__name__)


async def ensure_admin_user(db: AsyncSession) -> bool:
    """
    确保管理员账号存在（幂等）。

    Returns:
        True 表示本次启动新创建了管理员账号；False 表示跳过/已存在。
    """

    settings = get_settings()

    admin_username = (settings.admin_username or "").strip()
    admin_password = settings.admin_password or ""

    if not admin_username or not admin_password:
        logger.info("未配置管理员账号信息（ADMIN_USERNAME 或 ADMIN_PASSWORD），跳过管理员初始化")
        return False

    repo = UserRepository(db)
    existing_user = await repo.get_by_username(admin_username)
    if existing_user:
        logger.info("管理员账号已存在: %s (ID: %s)", existing_user.username, existing_user.id)
        return False

    try:
        user = await repo.create(
            username=admin_username,
            password_hash=hash_password(admin_password),
            trust_level=3,
            is_active=True,
            is_silenced=False,
            beta=1,
        )
        await db.commit()

        logger.info("管理员账号创建成功: %s (ID: %s)", user.username, user.id)

        # 自动创建 plug-in-api 账号并绑定
        try:
            from app.services.plugin_api_service import PluginAPIService
            redis = get_redis_client()
            plugin_service = PluginAPIService(db, redis)

            result = await plugin_service.auto_create_and_bind_plugin_user(
                user_id=user.id,
                username=user.username,
                prefer_shared=0  # 默认专属优先
            )
            logger.info("管理员 plug-in API 密钥创建成功: plugin_user_id=%s", result.plugin_user_id)
        except Exception as e:
            # 记录错误但不影响管理员创建
            logger.warning("管理员 plug-in API 密钥创建失败（不影响管理员账号使用）: %s", str(e))

        return True

    except IntegrityError:
        # 多进程/多副本并发启动时，可能会出现竞态：同时创建同名用户导致唯一约束冲突。
        await db.rollback()
        existing_user = await repo.get_by_username(admin_username)
        if existing_user:
            logger.info("管理员账号已被其他进程创建: %s (ID: %s)", existing_user.username, existing_user.id)
            return False
        raise
    except Exception:
        await db.rollback()
        raise

