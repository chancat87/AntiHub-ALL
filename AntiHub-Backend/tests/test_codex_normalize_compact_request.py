import unittest

from app.services.codex_service import _normalize_codex_responses_compact_request


class TestCodexNormalizeCompactRequest(unittest.TestCase):
    def test_system_role_converted_and_store_removed(self) -> None:
        req = {
            "model": "gpt-5-codex",
            "stream": True,
            "store": True,
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

        out = _normalize_codex_responses_compact_request(req)

        # Codex upstream rejects role=system in input array; it must be developer.
        self.assertEqual(out["input"][0]["role"], "developer")
        self.assertEqual(out["input"][1]["role"], "user")
        self.assertEqual(out["input"][0]["content"][0]["text"], "You are helpful.")

        # Ensure normalization does not mutate the original request object.
        self.assertEqual(req["input"][0]["role"], "system")

        # Compact endpoint is non-streaming JSON and strips unsupported fields.
        self.assertNotIn("stream", out)
        self.assertNotIn("store", out)

        # Compact normalization avoids injecting optional fields unless the client provides them.
        self.assertNotIn("parallel_tool_calls", out)
        self.assertNotIn("include", out)
        self.assertEqual(out.get("instructions"), "")

    def test_input_string_converted(self) -> None:
        req = {"model": "gpt-5-codex", "input": "hello", "store": False, "stream": False}
        out = _normalize_codex_responses_compact_request(req)

        self.assertIsInstance(out["input"], list)
        self.assertEqual(out["input"][0]["type"], "message")
        self.assertEqual(out["input"][0]["role"], "user")
        self.assertEqual(out["input"][0]["content"][0]["text"], "hello")
        self.assertNotIn("stream", out)
        self.assertNotIn("store", out)


if __name__ == "__main__":
    unittest.main()
