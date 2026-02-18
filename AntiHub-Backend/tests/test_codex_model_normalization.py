import unittest

from app.services.codex_service import _resolve_codex_model_name


class TestCodexModelNormalization(unittest.TestCase):
    def test_openai_compact_suffix_stripped(self) -> None:
        self.assertEqual(_resolve_codex_model_name("gpt-5.2-openai-compact"), "gpt-5.2")
        self.assertEqual(_resolve_codex_model_name("gpt-5.2-openai-compact-high"), "gpt-5.2")

    def test_thinking_suffix_stripped(self) -> None:
        self.assertEqual(_resolve_codex_model_name("gpt-5.3-codex-high"), "gpt-5.3-codex")
        self.assertEqual(_resolve_codex_model_name("gpt-5.1-codex-mini-medium"), "gpt-5.1-codex-mini")


if __name__ == "__main__":
    unittest.main()

