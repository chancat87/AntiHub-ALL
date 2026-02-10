import unittest

from app.services.anthropic_adapter import AnthropicAdapter


class TestClaudeCodeToolAliases(unittest.TestCase):
    def test_read_tool_path_alias_to_file_path(self) -> None:
        input_data = {"path": "/Users/xxx/scripts/delete-user.ts", "read_range": [14, 55]}

        normalized = AnthropicAdapter._normalize_claude_code_tool_input("Read", input_data)
        self.assertEqual(normalized.get("file_path"), input_data["path"])

        missing = AnthropicAdapter._missing_required_args_for_claude_code_tool("Read", normalized)
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()

