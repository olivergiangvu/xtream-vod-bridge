"""Dry-run simulation of the guarded HomeDocker username-login promotion."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts" / "promote_username_login.py"


def load_module():
    spec = importlib.util.spec_from_file_location("username_login_promotion", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipIf((Path(__file__).resolve().parents[1] / "user_sources.py").exists(),
                 "Archived v0.4 one-time promoter fixture; source evolved in v0.5")
class PromotionTests(unittest.TestCase):
    def test_guarded_promotion_preserves_same_origin_and_existing_endpoints(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            reviewed_ui = (ROOT / "admin_ui.py").read_text()
            # This promoter is intentionally pinned to the prior Login UX
            # release; remove only the new v0.4.3 endpoint from this fixture
            # to recover the exact reviewed source for its checksum gate.
            new_start = reviewed_ui.index(
                '@console.get("/api/manifest", dependencies=[Depends(authorize)])'
            )
            new_end = reviewed_ui.index(
                '@console.get("/api/events", dependencies=[Depends(authorize)])',
                new_start,
            )
            reviewed_ui = reviewed_ui[:new_start] + reviewed_ui[new_end:]
            reviewed_auth = (ROOT / "admin_auth.py").read_text()
            source_dir = root / "reviewed"
            local_dir = root / "local"
            source_dir.mkdir()
            local_dir.mkdir()
            (source_dir / "admin_ui.py").write_text(reviewed_ui)
            (source_dir / "admin_auth.py").write_text(reviewed_auth)

            a = reviewed_ui.index('def _gate_page(')
            b = reviewed_ui.index('@console.get("/gateway/"', a)
            legacy_form = (
                'def _gate_page(message: str, nonce: str):\n'
                '    return """<meta name="referrer" content="same-origin">\n'
                '<form method="post" action="/admin-signin/">\n'
                '<input name="nonce"><input name="password"></form>"""\n\n\n'
            )
            local_ui = reviewed_ui[:a] + legacy_form + reviewed_ui[b:]
            local_ui = local_ui.replace(
                'response.headers["Referrer-Policy"] = (\n'
                '        "strict-origin-when-cross-origin" if request.url.path.startswith("/gateway/")\n'
                '        else "no-referrer"\n'
                '    )',
                'response.headers["Referrer-Policy"] = "same-origin"',
            )
            reverse_ui = [
                (
                    '        fields = parse_qs(body.decode("utf-8"), strict_parsing=True,\n'
                    '                          keep_blank_values=True, max_num_fields=3)',
                    '        fields = parse_qs(body.decode("utf-8"), strict_parsing=True,\n'
                    '                          max_num_fields=3)',
                ),
                (
                    'if set(fields) not in ({"password", "nonce"}, {"password", "nonce", "username"}) or any(len(v) != 1 for v in fields.values()):',
                    'if set(fields) != {"password", "nonce"} or any(len(v) != 1 for v in fields.values()):',
                ),
                (
                    '        # Backwards-compatible with an already-open, password-only form.\n'
                    '        username = fields.get("username", ["owner"])[0]\n'
                    '        if not nonce or not password:\n'
                    '            raise ValueError("Invalid form")\n',
                    '',
                ),
                ('admin_auth.login(password, username=username)',
                 'admin_auth.login(password)'),
                ('_gate_page("Incorrect username or password.", new_nonce, username)',
                 '_gate_page("Incorrect password.", new_nonce)'),
                (
                    'if set(payload) not in ({"password"}, {"password", "username"}):\n'
                    '        raise HTTPException(status_code=422, detail="Expected password and optional username")',
                    'if set(payload) != {"password"}:\n'
                    '        raise HTTPException(status_code=422, detail="Expected password only")',
                ),
                ('admin_auth.login(payload["password"], username=payload.get("username", "owner"))',
                 'admin_auth.login(payload["password"])'),
            ]
            for new, old in reverse_ui:
                self.assertEqual(local_ui.count(new), 1, new[:50])
                local_ui = local_ui.replace(new, old)
            (local_dir / "admin_ui.py").write_text(local_ui)

            local_auth = reviewed_auth.replace(
                'def login(password, username="owner"):\n'
                '    # Existing single Owner account. Keep the username check inside the\n'
                '    # password-verification flow so invalid usernames share rate limiting.\n',
                'def login(password):\n',
            ).replace(
                '        valid_username = (isinstance(username, str) and len(username) <= 64\n'
                '                          and hmac.compare_digest(username.encode("utf-8"), b"owner"))\n'
                '        good = _verify(password, account) and valid_username\n',
                '        good = _verify(password, account)\n',
            )
            (local_dir / "admin_auth.py").write_text(local_auth)

            prepared = module.prepare(local_dir, source_dir)
            self.assertEqual(set(prepared), {"admin_ui.py", "admin_auth.py"})
            self.assertIn('autocomplete="username"', prepared["admin_ui.py"])
            self.assertIn('autocomplete="current-password"', prepared["admin_ui.py"])
            self.assertIn('<meta name="referrer" content="same-origin">', prepared["admin_ui.py"])
            self.assertIn('response.headers["Referrer-Policy"] = "same-origin"', prepared["admin_ui.py"])
            self.assertIn('valid_username = (isinstance(username, str)', prepared["admin_auth.py"])
            self.assertEqual(
                (local_dir / "admin_ui.py").read_text(), local_ui,
                "Preflight must not modify live files",
            )
            self.assertEqual(
                (local_dir / "admin_auth.py").read_text(), local_auth,
                "Preflight must not modify live files",
            )

            prepared_ui = prepared["admin_ui.py"]
            # The only expected difference from reviewed source is live Safari policy.
            expected_ui = reviewed_ui.replace(
                'response.headers["Referrer-Policy"] = (\n'
                '        "strict-origin-when-cross-origin" if request.url.path.startswith("/gateway/")\n'
                '        else "no-referrer"\n'
                '    )',
                'response.headers["Referrer-Policy"] = "same-origin"',
            ).replace(
                '<meta name="referrer" content="strict-origin-when-cross-origin">',
                '<meta name="referrer" content="same-origin">',
            )
            self.assertEqual(prepared_ui, expected_ui)
            self.assertEqual(prepared["admin_auth.py"], reviewed_auth)

    def test_checksum_guard_rejects_modified_reviewed_source(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temp:
            source_dir = Path(temp)
            (source_dir / "admin_ui.py").write_text("# forged")
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                module.read_reviewed(source_dir, "admin_ui.py")


if __name__ == "__main__":
    unittest.main()
