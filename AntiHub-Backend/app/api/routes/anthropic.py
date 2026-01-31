"""
Anthropic兼容的API端点
支持Anthropic Messages API格式 (/v1/messages)
将请求转换为OpenAI格式后调用plug-in-api
"""
from typing import Optional
import uuid
import logging
import json
import os
import tempfile
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request, Header
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps_flexible import get_user_flexible_with_x_api_key
from app.api.deps import get_plugin_api_service, get_db_session, get_redis
from app.core.spec_guard import ensure_spec_allowed
from app.models.user import User
from app.services.plugin_api_service import PluginAPIService
from app.services.kiro_service import KiroService
from app.services.anthropic_adapter import AnthropicAdapter
from app.services.kiro_anthropic_converter import KiroAnthropicConverter
from app.utils.kiro_converters import is_thinking_enabled
from app.schemas.anthropic import (
    AnthropicMessagesRequest,
    AnthropicMessagesResponse,
    AnthropicErrorResponse,
)
from app.cache import RedisClient
from app.utils.token_counter import count_all_tokens

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["Anthropic兼容API"])
cc_router = APIRouter(prefix="/cc/v1", tags=["Claude Code兼容API"])

# 错误dump文件路径
ERROR_DUMP_FILE = os.path.join(tempfile.gettempdir(), "error_dumps.json")


def dump_error_to_file(
    error_type: str,
    user_request: dict,
    error_info: dict,
    endpoint: str = "/v1/messages"
):
    """
    将错误信息dump到JSON文件
    
    Args:
        error_type: 错误类型（如 "upstream_error", "validation_error"）
        user_request: 用户的原始请求体
        error_info: 错误详情
        endpoint: API端点
    """
    try:
        error_record = {
            "timestamp": datetime.now().isoformat(),
            "endpoint": endpoint,
            "error_type": error_type,
            "user_request": user_request,
            "error_info": error_info
        }
        
        # 读取现有的错误记录
        existing_errors = []
        if os.path.exists(ERROR_DUMP_FILE):
            try:
                with open(ERROR_DUMP_FILE, "r", encoding="utf-8") as f:
                    existing_errors = json.load(f)
            except (json.JSONDecodeError, IOError):
                existing_errors = []
        
        # 添加新的错误记录
        existing_errors.append(error_record)
        
        # 只保留最近100条记录
        if len(existing_errors) > 100:
            existing_errors = existing_errors[-100:]
        
        # 写入文件
        with open(ERROR_DUMP_FILE, "w", encoding="utf-8") as f:
            json.dump(existing_errors, f, ensure_ascii=False, indent=2)
        
        logger.info(f"错误信息已dump到 {ERROR_DUMP_FILE}")
        
    except Exception as e:
        logger.error(f"dump错误信息失败: {str(e)}")


def get_kiro_service(
    db: AsyncSession = Depends(get_db_session),
    redis: RedisClient = Depends(get_redis)
) -> KiroService:
    """获取Kiro服务实例（带Redis缓存支持）"""
    return KiroService(db, redis)


async def _create_message_impl(
    request: AnthropicMessagesRequest,
    raw_request: Request,
    current_user: User,
    antigravity_service: PluginAPIService,
    kiro_service: KiroService,
    anthropic_version: Optional[str],
    anthropic_beta: Optional[str],
    *,
    endpoint: str,
    buffer_for_claude_code: bool,
):
    """
    /v1/messages 与 /cc/v1/messages 共用逻辑。

    buffer_for_claude_code=True 时，会缓冲 SSE 直到拿到真实 usage，
    再把 tokens 写入 message_start（用于 Claude Code 2.1.9+ 上下文压缩逻辑）。
    """
    try:
        if not anthropic_version:
            anthropic_version = "2023-06-01"

        # 生成请求ID
        request_id = uuid.uuid4().hex[:24]

        # 判断使用哪个服务
        config_type = getattr(current_user, "_config_type", None)

        # 如果是 API key 模式（有 _config_type），按 Spec 白名单拦截（避免非白名单悄悄走 plug-in 默认通道）。
        if isinstance(config_type, str) and config_type.strip():
            config_type = config_type.strip().lower()
            ensure_spec_allowed("Claude", config_type)
        else:
            config_type = None

            # 如果是 JWT token 认证（无 _config_type），检查请求头（保持现有约束）
            api_type = raw_request.headers.get("X-Api-Type")
            if api_type in ["kiro", "antigravity", "qwen"]:
                config_type = api_type

        use_kiro = config_type == "kiro"

        if use_kiro:
            # 检查beta权限
            if current_user.beta != 1:
                error_response = AnthropicAdapter.create_error_response(
                    error_type="permission_error",
                    message="Kiro配置仅对beta计划用户开放",
                )
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content=error_response.model_dump(),
                )

        # 提取thinking配置
        thinking_config = getattr(request, "thinking", None)
        thinking_enabled = is_thinking_enabled(thinking_config)

        # Kiro 通道：直接把 Anthropic Messages 转为 conversationState（参考 kiro.rs 结构）
        # 其它通道：继续走 Anthropic -> OpenAI 转换，转发到 plug-in chat/completions
        if use_kiro:
            upstream_request = KiroAnthropicConverter.to_kiro_chat_completions_request(request)
        else:
            upstream_request = AnthropicAdapter.anthropic_to_openai_request(request)

        # 准备额外的请求头
        extra_headers = {}
        if config_type:
            extra_headers["X-Account-Type"] = config_type

        # 如果是流式请求
        if request.stream:
            async def generate():
                try:
                    if use_kiro:
                        # 使用Kiro服务
                        openai_stream = kiro_service.chat_completions_stream(
                            user_id=current_user.id,
                            request_data=upstream_request,
                        )
                    else:
                        # 使用Antigravity服务
                        openai_stream = antigravity_service.proxy_stream_request(
                            user_id=current_user.id,
                            method="POST",
                            path="/v1/chat/completions",
                            json_data=upstream_request,
                            extra_headers=extra_headers if extra_headers else None,
                        )

                    # 转换流式响应为Anthropic格式
                    converter = (
                        AnthropicAdapter.convert_openai_stream_to_anthropic_cc
                        if buffer_for_claude_code
                        else AnthropicAdapter.convert_openai_stream_to_anthropic
                    )

                    async for event in converter(
                        openai_stream,
                        model=request.model,
                        request_id=request_id,
                        thinking_enabled=thinking_enabled,
                    ):
                        yield event

                except Exception as e:
                    logger.error(f"流式响应错误: {str(e)}")
                    error_event = {
                        "type": "error",
                        "error": {
                            "type": "api_error",
                            "message": str(e),
                        },
                    }
                    yield f"event: error\ndata: {json.dumps(error_event)}\n\n"

            # 构建响应头
            response_headers = {
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
                "anthropic-version": anthropic_version,
            }

            # 如果有beta头，也返回
            if anthropic_beta:
                response_headers["anthropic-beta"] = anthropic_beta

            return StreamingResponse(
                generate(),
                media_type="text/event-stream",
                headers=response_headers,
            )

        # 非流式请求
        # 上游总是返回流式响应，所以使用流式接口获取并收集响应
        if use_kiro:
            # 使用Kiro服务的流式接口
            openai_stream = kiro_service.chat_completions_stream(
                user_id=current_user.id,
                request_data=upstream_request,
            )
        else:
            # 使用Antigravity服务的流式接口
            openai_stream = antigravity_service.proxy_stream_request(
                user_id=current_user.id,
                method="POST",
                path="/v1/chat/completions",
                json_data=upstream_request,
                extra_headers=extra_headers if extra_headers else None,
            )

        # 收集流式响应并转换为完整的OpenAI响应
        openai_response = await AnthropicAdapter.collect_openai_stream_to_response(
            openai_stream,
            thinking_enabled=thinking_enabled,
        )

        # 转换响应为Anthropic格式
        anthropic_response = AnthropicAdapter.openai_to_anthropic_response(
            openai_response,
            model=request.model,
        )

        # 构建响应，添加必需的头
        response = JSONResponse(
            content=anthropic_response.model_dump(),
            headers={
                "anthropic-version": anthropic_version,
            },
        )

        # 如果有beta头，也返回
        if anthropic_beta:
            response.headers["anthropic-beta"] = anthropic_beta

        return response

    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"请求验证错误: {str(e)}")

        # Dump错误信息
        dump_error_to_file(
            error_type="validation_error",
            user_request=request.model_dump(),
            error_info={
                "error_message": str(e),
                "error_class": type(e).__name__,
            },
            endpoint=endpoint,
        )

        error_response = AnthropicAdapter.create_error_response(
            error_type="invalid_request_error",
            message=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=error_response.model_dump(),
        )
    except Exception as e:
        logger.error(f"消息创建失败: {str(e)}")

        # 尝试获取上游错误信息
        upstream_error = None
        if hasattr(e, "response_data"):
            upstream_error = e.response_data
        elif hasattr(e, "response"):
            try:
                upstream_error = (
                    e.response.json()
                    if hasattr(e.response, "json")
                    else str(
                        e.response.text
                        if hasattr(e.response, "text")
                        else e.response
                    )
                )
            except Exception:
                upstream_error = str(e.response) if hasattr(e, "response") else None

        # Dump错误信息
        dump_error_to_file(
            error_type="upstream_error",
            user_request=request.model_dump(),
            error_info={
                "error_message": str(e),
                "error_class": type(e).__name__,
                "upstream_response": upstream_error,
            },
            endpoint=endpoint,
        )

        error_response = AnthropicAdapter.create_error_response(
            error_type="api_error",
            message=f"消息创建失败: {str(e)}",
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_response.model_dump(),
        )


@router.post(
    "/messages",
    summary="创建消息",
    description="使用Anthropic Messages API格式创建消息（Anthropic兼容）。内部转换为OpenAI格式调用plug-in-api",
    responses={
        200: {
            "description": "成功响应",
            "model": AnthropicMessagesResponse
        },
        400: {
            "description": "请求错误",
            "model": AnthropicErrorResponse
        },
        401: {
            "description": "认证失败",
            "model": AnthropicErrorResponse
        },
        500: {
            "description": "服务器错误",
            "model": AnthropicErrorResponse
        }
    }
)
async def create_message(
    request: AnthropicMessagesRequest,
    raw_request: Request,
    current_user: User = Depends(get_user_flexible_with_x_api_key),
    antigravity_service: PluginAPIService = Depends(get_plugin_api_service),
    kiro_service: KiroService = Depends(get_kiro_service),
    anthropic_version: Optional[str] = Header(None, alias="anthropic-version"),
    anthropic_beta: Optional[str] = Header(None, alias="anthropic-beta")
):
    """
    创建消息 (Anthropic Messages API兼容)
    
    支持三种认证方式：
    1. X-Api-Key 标头 - Anthropic 官方认证方式
    2. Authorization Bearer API key - 用于程序调用，根据API key的config_type自动选择配置
    3. Authorization Bearer JWT token - 用于网页聊天，默认使用Antigravity配置，但可以通过X-Api-Type请求头指定配置
    
    **配置选择:**
    - 使用API key时，仅允许 config_type=antigravity/kiro（其它类型会 403：不支持的规范）
    - 使用JWT token时，默认使用Antigravity配置，但可以通过X-Api-Type请求头指定配置（antigravity/kiro/qwen）
    - Kiro配置需要beta权限（qwen不需要）
    
    **格式转换:**
    - 接收Anthropic Messages API格式的请求
    - 内部转换为OpenAI格式调用plug-in-api
    - 将响应转换回Anthropic格式返回
    """
    return await _create_message_impl(
        request=request,
        raw_request=raw_request,
        current_user=current_user,
        antigravity_service=antigravity_service,
        kiro_service=kiro_service,
        anthropic_version=anthropic_version,
        anthropic_beta=anthropic_beta,
        endpoint="/v1/messages",
        buffer_for_claude_code=False,
    )


@cc_router.post(
    "/messages",
    summary="创建消息（Claude Code兼容）",
    description="Claude Code 2.1.9+ 兼容端点：将真实 tokens 写入 message_start（通过缓冲 SSE 实现）。",
    responses={
        200: {
            "description": "成功响应",
            "model": AnthropicMessagesResponse
        },
        400: {
            "description": "请求错误",
            "model": AnthropicErrorResponse
        },
        401: {
            "description": "认证失败",
            "model": AnthropicErrorResponse
        },
        500: {
            "description": "服务器错误",
            "model": AnthropicErrorResponse
        }
    }
)
async def create_message_cc(
    request: AnthropicMessagesRequest,
    raw_request: Request,
    current_user: User = Depends(get_user_flexible_with_x_api_key),
    antigravity_service: PluginAPIService = Depends(get_plugin_api_service),
    kiro_service: KiroService = Depends(get_kiro_service),
    anthropic_version: Optional[str] = Header(None, alias="anthropic-version"),
    anthropic_beta: Optional[str] = Header(None, alias="anthropic-beta")
):
    """
    Claude Code 兼容端点：/cc/v1/messages

    Claude Code 新版会从 message_start 读取 input_tokens（而不是 message_delta），
    但上游 usage 往往在流末尾才返回，因此此端点会缓冲 SSE 流直至拿到 usage，
    然后再输出完整事件序列，确保上下文压缩逻辑正常。
    """
    return await _create_message_impl(
        request=request,
        raw_request=raw_request,
        current_user=current_user,
        antigravity_service=antigravity_service,
        kiro_service=kiro_service,
        anthropic_version=anthropic_version,
        anthropic_beta=anthropic_beta,
        endpoint="/cc/v1/messages",
        buffer_for_claude_code=True,
    )


@cc_router.post(
    "/messages/count_tokens",
    summary="计算Token数量（Claude Code兼容）",
    description="计算消息的token数量（与 /v1/messages/count_tokens 相同）"
)
@router.post(
    "/messages/count_tokens",
    summary="计算Token数量",
    description="计算消息的token数量（Anthropic兼容）"
)
async def count_tokens(
    raw_request: Request
):
    """
    计算消息的token数量

    参考 kiro.rs 的实现：
    - 非西文字符：每个计 4 个字符单位
    - 西文字符：每个计 1 个字符单位
    - 4 个字符单位 = 1 token
    - 根据 token 数量应用系数调整
    - 计算 system、messages、tools 的 token
    """
    try:
        body = await raw_request.json()

        # 验证必需字段
        if "model" not in body:
            raise ValueError("缺少必需字段: model")
        if "messages" not in body:
            raise ValueError("缺少必需字段: messages")

        messages = body.get("messages", [])
        system = body.get("system")
        tools = body.get("tools")

        # 使用优化后的 token 计算
        estimated_tokens = count_all_tokens(
            messages=messages,
            system=system,
            tools=tools
        )

        return {
            "input_tokens": estimated_tokens
        }

    except ValueError as e:
        logger.error(f"Token计数请求验证失败: {str(e)}")
        error_response = AnthropicAdapter.create_error_response(
            error_type="invalid_request_error",
            message=str(e)
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=error_response.model_dump()
        )
    except Exception as e:
        logger.error(f"Token计数失败: {str(e)}")
        error_response = AnthropicAdapter.create_error_response(
            error_type="api_error",
            message=f"Token计数失败: {str(e)}"
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_response.model_dump()
        )
