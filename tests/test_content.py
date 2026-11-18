"""Content sealing, plaintext shaping and the confirmation-prompt summary."""

import base64
import json
import os
import re
import unittest
import unittest.mock

import hook

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return handle.read()


class ChaCha20Poly1305Tests(unittest.TestCase):
    def test_rfc_8439_section_2_8_2_vector(self):
        key = bytes(range(0x80, 0xA0))
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: If I could offer you only"
            b" one tip for the future, sunscreen would be it."
        )
        sealed = hook.chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
        self.assertEqual(
            sealed.hex(),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116"
            "1ae10b594f09e26a7e902ecbd0600691",
        )


class PlaintextTests(unittest.TestCase):
    def test_values_are_utf8_json_with_control_characters_removed(self):
        plaintext = hook.content_plaintext(
            {
                "agent": "\x00claude\x1f",
                "workspace": "herd\x7fsight\x9f",
                "tab": "ma\x85in",
                "title": "Fix it",
                "prompt": "Proceed?",
            }
        )
        self.assertEqual(
            plaintext.decode("utf-8"),
            '{"v":1,"agent":"claude","workspace":"herdsight","tab":"main",'
            '"title":"Fix it","prompt":"Proceed?"}',
        )

    def test_limits_count_utf8_bytes_and_keep_the_ellipsis_inside(self):
        plaintext = hook.content_plaintext(
            {
                "agent": "あ" * 11,
                "workspace": "😀" * 17,
                "tab": "b" * 65,
                "title": "t" * 121,
                "prompt": "p" * 201,
            }
        )
        values = json.loads(plaintext)
        for key, limit in hook.CONTENT_LIMITS:
            self.assertLessEqual(len(values[key].encode("utf-8")), limit, key)
            self.assertTrue(values[key].endswith("…"), key)
        self.assertEqual(values["agent"], "あ" * 9 + "…")
        self.assertEqual(values["workspace"], "😀" * 15 + "…")
        self.assertEqual(values["tab"], "b" * 61 + "…")

    def test_prompt_is_dropped_first_when_the_json_is_too_long(self):
        plaintext = hook.content_plaintext(
            {
                "agent": "a" * 32,
                "workspace": "b" * 64,
                "tab": "c" * 64,
                "title": "\\" * 120,
                "prompt": "\\" * 200,
            }
        )
        self.assertLessEqual(len(plaintext), hook.CONTENT_JSON_MAX_BYTES)
        values = json.loads(plaintext)
        self.assertIsNone(values["prompt"])
        self.assertIsNotNone(values["title"])

    def test_title_is_dropped_after_prompt(self):
        with unittest.mock.patch.object(hook, "CONTENT_JSON_MAX_BYTES", 200):
            plaintext = hook.content_plaintext(
                {"agent": "a" * 32, "workspace": "b" * 64, "tab": "c" * 64}
            )
        values = json.loads(plaintext)
        self.assertIsNone(values["prompt"])
        self.assertIsNone(values["title"])

    def test_missing_values_are_null(self):
        self.assertEqual(
            json.loads(hook.content_plaintext({})),
            {
                "v": 1,
                "agent": None,
                "workspace": None,
                "tab": None,
                "title": None,
                "prompt": None,
            },
        )


class SealTests(unittest.TestCase):
    def test_sealed_is_unpadded_base64url_at_most_1024_characters(self):
        key = bytes(32)
        fields = {
            "agent": "claude",
            "workspace": "herdsight",
            "tab": "main",
            "title": "Fix it",
            "prompt": "Proceed?",
        }
        first = hook.seal_content(key, "needs_input", hook.content_plaintext(fields))
        second = hook.seal_content(key, "needs_input", hook.content_plaintext(fields))
        self.assertRegex(first, re.compile(r"^[A-Za-z0-9_-]{38,1024}$"))
        self.assertNotEqual(first, second)
        self.assertLessEqual(len(first), 1024)

    def test_shared_fixture_matches_the_plugin(self):
        # 同じ実装で作り直して比べているだけ。CryptoKit との一致はアプリ側の
        # SealedContent テスト（spec 8 節）で確かめる。
        data = json.loads(fixture("sealed_v1.json"))
        key = base64.urlsafe_b64decode(data["key"] + "=" * (-len(data["key"]) % 4))
        nonce = base64.urlsafe_b64decode(
            data["nonce"] + "=" * (-len(data["nonce"]) % 4)
        )
        self.assertEqual(len(key), 32)
        self.assertEqual(len(nonce), 12)
        self.assertEqual(data["aad"], "herdsight-content-v1:needs_input")
        plaintext = hook.content_plaintext(
            {
                "agent": "claude",
                "workspace": "herdsight",
                "tab": "main",
                "title": "Fix the login flow",
                "prompt": "テストを直してよいですか？",
            }
        )
        self.assertEqual(plaintext.decode("utf-8"), data["plaintext"])
        self.assertEqual(
            hook.seal_content(key, "needs_input", plaintext, nonce), data["sealed"]
        )

    def test_finished_fixture_uses_the_finished_aad_and_a_null_prompt(self):
        data = json.loads(fixture("sealed_v1_finished.json"))
        key = base64.urlsafe_b64decode(data["key"] + "=" * (-len(data["key"]) % 4))
        nonce = base64.urlsafe_b64decode(
            data["nonce"] + "=" * (-len(data["nonce"]) % 4)
        )
        self.assertEqual(data["aad"], "herdsight-content-v1:finished")
        self.assertIsNone(json.loads(data["plaintext"])["prompt"])
        plaintext = hook.content_plaintext(
            {
                "agent": "claude",
                "workspace": "herdsight",
                "tab": "main",
                "title": "Fix the login flow",
                "prompt": None,
            }
        )
        self.assertEqual(
            hook.seal_content(key, "finished", plaintext, nonce), data["sealed"]
        )
        self.assertNotEqual(
            hook.seal_content(key, "needs_input", plaintext, nonce), data["sealed"]
        )


class FakeHerdr:
    """`pane read` は JSON ではなく ANSI 付きの生テキストを返す（herdr 0.9.5）。"""

    def __init__(self, read=b"\x1b[0mPick one\r\n\x1b[36m1. a\x1b[0m\r\n2. b", code=0):
        self.calls = []
        self.read = read
        self.code = code

    def run(self, command, **_kwargs):
        args = tuple(command[1:])
        self.calls.append((args, _kwargs.get("timeout")))
        if self.code != 0:
            return type("Proc", (), {"returncode": self.code, "stdout": b""})()
        replies = {
            ("pane", "get", "w9:p1"): {
                "result": {
                    "pane": {
                        "agent": "claude",
                        "terminal_id": "term-1",
                        "terminal_title_stripped": "Fix it",
                        "workspace_id": "w9",
                        "tab_id": "w9:t1",
                    }
                }
            },
            ("workspace", "get", "w9"): {
                "result": {"workspace": {"label": "herdsight"}}
            },
            ("tab", "get", "w9:t1"): {"result": {"tab": {"label": "main"}}},
        }
        stdout = self.read if args[:2] == ("pane", "read") else json.dumps(
            replies[args]
        ).encode("utf-8")
        return type("Proc", (), {"returncode": 0, "stdout": stdout})()


class HerdrContentTests(unittest.TestCase):
    def test_reads_pane_workspace_tab_title_and_prompt_with_three_second_budget(self):
        herdr = FakeHerdr()
        with unittest.mock.patch("hook.subprocess.run", side_effect=herdr.run):
            content = hook.herdr_content("w9:p1")

        self.assertEqual(
            content,
            {
                "agent": "claude",
                "workspace": "herdsight",
                "tab": "main",
                "title": "Fix it",
                "prompt": "Pick one",
            },
        )
        self.assertEqual(len(herdr.calls), 4)
        self.assertIn(
            (
                "pane",
                "read",
                "w9:p1",
                "--source",
                "recent-unwrapped",
                "--lines",
                "200",
                "--format",
                "ansi",
            ),
            [args for args, _timeout in herdr.calls],
        )
        self.assertTrue(all(0 < timeout <= 3 for _args, timeout in herdr.calls))

    def test_every_lookup_failure_is_null(self):
        herdr = FakeHerdr(code=1)
        with unittest.mock.patch("hook.subprocess.run", side_effect=herdr.run):
            content = hook.herdr_content("w9:p1")
        self.assertEqual(
            content,
            {
                "agent": None,
                "workspace": None,
                "tab": None,
                "title": None,
                "prompt": None,
            },
        )

    def test_undecodable_pane_read_is_null(self):
        herdr = FakeHerdr(read=b"\xff\xfe")
        with unittest.mock.patch("hook.subprocess.run", side_effect=herdr.run):
            content = hook.herdr_content("w9:p1")
        self.assertIsNone(content["prompt"])
        self.assertEqual(content["title"], "Fix it")

    def test_finished_does_not_read_the_pane(self):
        herdr = FakeHerdr()
        with unittest.mock.patch("hook.subprocess.run", side_effect=herdr.run):
            content = hook.herdr_content("w9:p1", kind="finished")
        self.assertIsNone(content["prompt"])
        self.assertEqual(content["title"], "Fix it")
        self.assertFalse(
            any(args[:2] == ("pane", "read") for args, _timeout in herdr.calls)
        )

    def test_a_known_pane_is_not_fetched_again(self):
        herdr = FakeHerdr()
        pane = {
            "agent": "claude",
            "terminal_id": "term-1",
            "terminal_title_stripped": "Fix it",
            "workspace_id": "w9",
            "tab_id": "w9:t1",
        }
        with unittest.mock.patch("hook.subprocess.run", side_effect=herdr.run):
            content = hook.herdr_content("w9:p1", pane=pane)
        self.assertEqual(content["workspace"], "herdsight")
        self.assertFalse(
            any(args[:2] == ("pane", "get") for args, _timeout in herdr.calls)
        )

    def test_exhausted_budget_takes_nothing(self):
        herdr = FakeHerdr()
        with unittest.mock.patch("hook.subprocess.run", side_effect=herdr.run):
            self.assertIsNone(hook.herdr_content("w9:p1", remaining=0))
        self.assertEqual(herdr.calls, [])

    def test_timeouts_are_capped_by_the_remaining_budget(self):
        herdr = FakeHerdr()
        with unittest.mock.patch("hook.subprocess.run", side_effect=herdr.run):
            content = hook.herdr_content("w9:p1", remaining=1)
        self.assertIsNotNone(content)
        self.assertTrue(all(0 < timeout <= 1 for _args, timeout in herdr.calls))


class ConfirmationSummaryTests(unittest.TestCase):
    """Swift の ConfirmationPromptTests と同じ値を固定する。"""

    def test_fixture_summaries(self):
        expected = {
            "prompt_claude_ask_single.txt": "色: 好きな色はどちらですか？",
            "prompt_claude_ask_multi.txt": "好きな色はどれですか？",
            "prompt_claude_ask_multiselect.txt": "有効にしたい機能はどれですか？（複数選択可）",
            "prompt_claude_ask_review.txt": "Ready to submit your answers?",
        }
        for name, summary in expected.items():
            with self.subTest(name=name):
                self.assertEqual(hook.confirmation_summary(fixture(name)), summary)

    def test_boxed_bash_confirmation(self):
        text = (
            "⏺ project.yml changed — regenerating the project.\n\n"
            "╭──────────────────────────────────────╮\n"
            "│ Bash command                         │\n"
            "│                                      │\n"
            "│   xcodegen generate                  │\n"
            "│   Regenerate the Xcode project       │\n"
            "│                                      │\n"
            "│ Do you want to proceed?              │\n"
            "│ ❯ 1. Yes                             │\n"
            "│   2. Yes, and don't ask again        │\n"
            "│   3. No, and tell Claude what to do  │\n"
            "╰──────────────────────────────────────╯\n\n"
        )
        self.assertEqual(hook.confirmation_summary(text), "Bash: xcodegen generate")

    def test_codex_choice_and_wrapped_description(self):
        text = (
            "Would you like to run the following command?\n\n"
            "$ xcodebuild -scheme Herdsight build\n\n"
            "› 1. Yes, proceed (y)\n"
            "  2. No, and tell Codex what to do differently\n"
            "     (esc)\n\n"
            "Press enter to confirm or esc to cancel\n"
        )
        self.assertEqual(
            hook.confirmation_summary(text), "$ xcodebuild -scheme Herdsight build"
        )

    def test_yes_no_and_plain_output(self):
        self.assertEqual(
            hook.confirmation_summary("$ ./apply\nApply changes to 4 files? [y/N] "),
            "Apply changes to 4 files? [y/N]",
        )
        self.assertIsNone(hook.confirmation_summary("$ echo hello\nhello\n$ "))
        self.assertIsNone(hook.confirmation_summary(""))

    def test_crlf_and_ansi_are_normalized(self):
        colorless = hook.confirmation_summary("Pick one\r\n1. a\r\n2. b")
        colored = hook.confirmation_summary(
            "\x1b[36mPick one\x1b[0m\r\n\x1b[36m1. a\x1b[0m\r\n2. b"
        )
        self.assertEqual(colorless, "Pick one")
        self.assertEqual(colored, "Pick one")

    def test_escapes_follow_ansitext_read_escape(self):
        self.assertEqual(hook.ansi_plain("\x1b[1 qPick one"), "Pick one")
        self.assertEqual(hook.ansi_plain("\x1b[>4;2mRed"), "Red")
        self.assertEqual(hook.ansi_plain("A\x1b]0;title\x07B"), "AB")
        # 終端の無い OSC は末尾まで捨てる。
        self.assertEqual(hook.ansi_plain("A\x1b]0;unterminated"), "A")

    def test_borderless_edit_box_uses_the_question(self):
        text = (
            "────────────────────────────────────────\n"
            " Edit file\n"
            " App/Views/PaneView.swift\n"
            " - old\n"
            " + new\n\n"
            " Do you want to make this edit to PaneView.swift?\n"
            " ❯ 1. Yes\n"
            "   2. No, and tell Claude what to do differently (esc)\n"
        )
        self.assertEqual(
            hook.confirmation_summary(text),
            "Do you want to make this edit to PaneView.swift?",
        )

    def test_heading_after_a_blank_line_and_without_a_heading(self):
        self.assertEqual(hook.confirmation_summary("done\n\nPick one\n1. a\n2. b"), "Pick one")
        self.assertEqual(hook.confirmation_summary("\n1. a\n2. b"), "1. a")

    def test_output_after_the_choices_is_not_a_confirmation(self):
        self.assertIsNone(hook.confirmation_summary("1. a\n2. b\nx\ny\nz\nw"))

    def test_choices_must_start_at_one(self):
        self.assertIsNone(hook.confirmation_summary("2. a\n3. b"))
        self.assertEqual(hook.confirmation_summary("1. a\n3. b"), "1. a")

    def test_a_wrapped_question_is_joined(self):
        screen = fixture("prompt_claude_ask_single.txt").replace(
            "好きな色はどちらですか？", "好きな色は\nどちらですか？"
        )
        self.assertEqual(hook.confirmation_summary(screen), "色: 好きな色はどちらですか？")
        self.assertEqual(
            hook._joined(["Which color do", "you like?"]), "Which color do you like?"
        )


if __name__ == "__main__":
    unittest.main()
