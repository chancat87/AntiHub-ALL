"""
Token 计算模块

参考 kiro.rs 的实现，提供文本 token 数量计算功能。

计算规则：
- 非西文字符：每个计 4 个字符单位
- 西文字符：每个计 1 个字符单位
- 4 个字符单位 = 1 token
- 根据 token 数量应用系数调整（小文本有更高的开销比例）
"""

import json
from typing import Any, Optional


def is_non_western_char(char: str) -> bool:
    """
    判断字符是否为非西文字符

    西文字符包括：
    - ASCII 字符 (U+0000..U+007F)
    - 拉丁字母扩展 (U+0080..U+024F)
    - 拉丁字母扩展附加 (U+1E00..U+1EFF)
    - 拉丁字母扩展-C/D/E

    返回 True 表示该字符是非西文字符（如中文、日文、韩文、阿拉伯文等）
    """
    code = ord(char)

    # 基本 ASCII
    if 0x0000 <= code <= 0x007F:
        return False
    # 拉丁字母扩展-A (Latin Extended-A)
    if 0x0080 <= code <= 0x00FF:
        return False
    # 拉丁字母扩展-B (Latin Extended-B)
    if 0x0100 <= code <= 0x024F:
        return False
    # 拉丁字母扩展附加 (Latin Extended Additional)
    if 0x1E00 <= code <= 0x1EFF:
        return False
    # 拉丁字母扩展-C
    if 0x2C60 <= code <= 0x2C7F:
        return False
    # 拉丁字母扩展-D
    if 0xA720 <= code <= 0xA7FF:
        return False
    # 拉丁字母扩展-E
    if 0xAB30 <= code <= 0xAB6F:
        return False

    return True


def count_tokens(text: str) -> int:
    """
    计算文本的 token 数量

    计算规则：
    - 非西文字符：每个计 4 个字符单位
    - 西文字符：每个计 1 个字符单位
    - 4 个字符单位 = 1 token
    - 根据 token 数量应用系数调整

    Args:
        text: 要计算的文本

    Returns:
        估算的 token 数量
    """
    if not text:
        return 0

    # 计算字符单位
    char_units = sum(4.0 if is_non_western_char(c) else 1.0 for c in text)

    # 转换为 token
    tokens = char_units / 4.0

    # 根据 token 数量应用系数调整（小文本有更高的开销比例）
    if tokens < 100:
        acc_token = tokens * 1.5
    elif tokens < 200:
        acc_token = tokens * 1.3
    elif tokens < 300:
        acc_token = tokens * 1.25
    elif tokens < 800:
        acc_token = tokens * 1.2
    else:
        acc_token = tokens * 1.0

    return max(1, int(acc_token))


def count_message_tokens(content: Any) -> int:
    """
    计算消息内容的 token 数量

    支持：
    - 字符串内容
    - ContentBlock 数组（包含 text、tool_use、tool_result 等）

    Args:
        content: 消息内容，可以是字符串或数组

    Returns:
        估算的 token 数量
    """
    if content is None:
        return 0

    if isinstance(content, str):
        return count_tokens(content)

    if isinstance(content, list):
        total = 0
        for block in content:
            if isinstance(block, dict):
                block_type = block.get("type", "")

                # 文本块
                if block_type == "text" and "text" in block:
                    total += count_tokens(block["text"])

                # thinking 块
                elif block_type == "thinking" and "thinking" in block:
                    total += count_tokens(block["thinking"])

                # 工具调用块
                elif block_type == "tool_use":
                    if "name" in block:
                        total += count_tokens(block["name"])
                    if "input" in block:
                        input_str = json.dumps(block["input"], ensure_ascii=False) if not isinstance(block["input"], str) else block["input"]
                        total += count_tokens(input_str)

                # 工具结果块
                elif block_type == "tool_result":
                    if "content" in block:
                        # tool_result 的 content 可以是字符串或数组
                        total += count_message_tokens(block["content"])

                # 图片块（base64 数据不计入 token，但有固定开销）
                elif block_type == "image":
                    # 图片有固定的 token 开销，这里用一个估算值
                    total += 85  # 大约 85 tokens 的基础开销

            elif isinstance(block, str):
                total += count_tokens(block)

        return total

    return 0


def count_system_tokens(system: Any) -> int:
    """
    计算系统消息的 token 数量

    支持：
    - 字符串格式
    - SystemMessage 数组格式 [{"type": "text", "text": "..."}]

    Args:
        system: 系统消息

    Returns:
        估算的 token 数量
    """
    if system is None:
        return 0

    if isinstance(system, str):
        return count_tokens(system)

    if isinstance(system, list):
        total = 0
        for msg in system:
            if isinstance(msg, dict):
                if "text" in msg:
                    total += count_tokens(msg["text"])
            elif isinstance(msg, str):
                total += count_tokens(msg)
        return total

    return 0


def count_tools_tokens(tools: Optional[list]) -> int:
    """
    计算工具定义的 token 数量

    Args:
        tools: 工具定义列表

    Returns:
        估算的 token 数量
    """
    if not tools:
        return 0

    total = 0
    for tool in tools:
        if isinstance(tool, dict):
            # 工具名称
            if "name" in tool:
                total += count_tokens(tool["name"])

            # 工具描述
            if "description" in tool:
                total += count_tokens(tool["description"])

            # 输入 schema
            if "input_schema" in tool:
                schema_str = json.dumps(tool["input_schema"], ensure_ascii=False)
                total += count_tokens(schema_str)

    return total


def count_all_tokens(
    messages: list,
    system: Any = None,
    tools: Optional[list] = None
) -> int:
    """
    计算完整请求的 token 数量

    Args:
        messages: 消息列表
        system: 系统消息（可选）
        tools: 工具定义列表（可选）

    Returns:
        估算的总 token 数量
    """
    total = 0

    # 系统消息
    total += count_system_tokens(system)

    # 用户消息
    for msg in messages:
        if isinstance(msg, dict):
            content = msg.get("content")
            total += count_message_tokens(content)

    # 工具定义
    total += count_tools_tokens(tools)

    return max(1, total)
