import unittest

from app.services.codex_service import _normalize_codex_responses_request


class TestCodexNormalizeRequest(unittest.TestCase):
    def test_system_role_converted_to_developer(self) -> None:
        req = {
            "model": "gpt-5-codex",
            "input": [
                {
                    "type": "message",
                    "role": "system",
                    "content": [{"type": "input_text", "text": "You are helpful."}],
                },
                {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "Hi"}],
                },
            ],
        }

        out = _normalize_codex_responses_request(req)

        # Codex upstream rejects role=system in input array; it must be developer.
        self.assertEqual(out["input"][0]["role"], "developer")
        self.assertEqual(out["input"][1]["role"], "user")
        self.assertEqual(out["input"][0]["content"][0]["text"], "You are helpful.")

        # Ensure normalization does not mutate the original request object.
        self.assertEqual(req["input"][0]["role"], "system")

        # Basic required defaults
        self.assertEqual(out.get("stream"), True)
        self.assertEqual(out.get("store"), False)
        self.assertEqual(out.get("parallel_tool_calls"), True)
        self.assertEqual(out.get("include"), ["reasoning.encrypted_content"])
        self.assertEqual(out.get("instructions"), "")


if __name__ == "__main__":
    unittest.main()

