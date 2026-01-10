"""
Qwen 账号相关的数据模型

说明：
- 本后端不直接与 Qwen 通信；所有账号数据与请求转发都通过 AntiHub-plugin 完成。
- 这里的 API 只是把用户输入的 QwenCli 导出 JSON 代理给 plug-in 做落库与校验。
"""

from typing import Optional
from pydantic import BaseModel, Field


class QwenAccountImportRequest(BaseModel):
    """导入 QwenCli 导出的 JSON 凭证"""

    credential_json: str = Field(..., description="QwenCli 导出的 JSON 字符串")
    is_shared: int = Field(0, description="0=专属账号，1=共享账号")
    account_name: Optional[str] = Field(None, description="账号显示名称（可选）")


class QwenAccountUpdateStatusRequest(BaseModel):
    """更新 Qwen 账号状态"""

    status: int = Field(..., description="0=禁用，1=启用")


class QwenAccountUpdateNameRequest(BaseModel):
    """更新 Qwen 账号名称"""

    account_name: str = Field(..., description="账号显示名称")


class QwenOAuthAuthorizeRequest(BaseModel):
    """生成 Qwen OAuth（Device Flow）授权链接"""

    is_shared: int = Field(0, description="0=专属账号，1=共享账号")
    account_name: Optional[str] = Field(None, description="账号显示名称（可选）")
