#!/usr/bin/env python3
"""
管理员账号初始化脚本
在应用首次启动时自动创建管理员账号
"""
import asyncio
import sys
import logging
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.security import hash_password, verify_password
from app.models.user import User

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

MIN_ADMIN_PASSWORD_LENGTH = 6


async def init_admin():
    """初始化管理员账号"""
    try:
        # 加载配置
        settings = get_settings()

        # 检查是否配置了管理员账号
        if not settings.admin_username or not settings.admin_password:
            logger.info("未配置管理员账号信息（ADMIN_USERNAME 或 ADMIN_PASSWORD），跳过管理员初始化")
            return

        if len(settings.admin_password) < MIN_ADMIN_PASSWORD_LENGTH:
            logger.error(
                "ADMIN_PASSWORD 长度至少 %s 位（当前 %s 位），请修改 .env 后重试",
                MIN_ADMIN_PASSWORD_LENGTH,
                len(settings.admin_password),
            )
            raise ValueError(f"ADMIN_PASSWORD must be at least {MIN_ADMIN_PASSWORD_LENGTH} characters")

        logger.info(f"开始检查管理员账号: {settings.admin_username}")

        # 创建数据库引擎
        engine = create_async_engine(
            settings.database_url,
            echo=False,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10
        )

        # 创建异步会话
        async_session = sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

        async with async_session() as session:
            # 检查管理员账号是否已存在
            from sqlalchemy import select
            stmt = select(User).where(User.username == settings.admin_username)
            result = await session.execute(stmt)
            existing_user = result.scalar_one_or_none()

            if existing_user:
                if not existing_user.password_hash or not verify_password(
                    settings.admin_password,
                    existing_user.password_hash,
                ):
                    existing_user.password_hash = hash_password(settings.admin_password)
                    await session.commit()
                    logger.info(f"管理员账号密码已更新: {settings.admin_username} (ID: {existing_user.id})")
                    return

                logger.info(f"管理员账号已存在: {settings.admin_username} (ID: {existing_user.id})")
                return

            # 创建管理员账号
            logger.info(f"正在创建管理员账号: {settings.admin_username}")

            admin_user = User(
                username=settings.admin_username,
                password_hash=hash_password(settings.admin_password),
                trust_level=3,  # 设置为最高信任等级
                is_active=True,
                is_silenced=False,
                beta=1  # 默认加入beta计划
            )

            session.add(admin_user)
            await session.commit()
            await session.refresh(admin_user)

            logger.info(f"✅ 管理员账号创建成功!")
            logger.info(f"   用户名: {admin_user.username}")
            logger.info(f"   用户ID: {admin_user.id}")
            logger.info(f"   信任等级: {admin_user.trust_level}")
            logger.info(f"   账号状态: {'已激活' if admin_user.is_active else '未激活'}")

        await engine.dispose()

    except Exception as e:
        logger.error(f"❌ 初始化管理员账号失败: {type(e).__name__}: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(init_admin())
