"""v0.5D frontend safety contract and Admin/User split.

These tests validate the actual HTML/JS shipped in the Docker image; they
cannot replace real Safari and nginx auth-request canary tests.
"""
import re
import unittest
from pathlib import Path
from html.parser import HTMLParser

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "admin/index.html").read_text()
APP = (ROOT / "admin/assets/app.js").read_text()
WORKSPACE = (ROOT / "admin/assets/workspace.js").read_text()
CSS = (ROOT / "admin/assets/style.css").read_text()


class Document(HTMLParser):
    VOID = {"meta", "input", "link", "hr", "br", "img", "source"}
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.ids = {}
        self.errors = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            ident = attrs["id"]
            if ident in self.ids:
                self.errors.append(f"Duplicate id {ident}")
            self.ids[ident] = {
                "tag": tag,
                "attrs": attrs,
                "ancestors": tuple(v[1].get("id") for v in self.stack),
            }
        if tag not in self.VOID:
            self.stack.append((tag, attrs))

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack or self.stack[-1][0] != tag:
            self.errors.append(f"Unbalanced tag </{tag}>")
            return
        self.stack.pop()


class TestUserWorkspace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = Document()
        cls.document.feed(HTML)
        cls.document.close()

    def test_html_tag_balance_and_unique_ids(self):
        self.assertEqual(self.document.errors, [])
        self.assertEqual(self.document.stack, [])
        ids = self.document.ids
        for code in (APP, WORKSPACE):
            for ident in re.findall(r"\$\('([a-zA-Z0-9]+)'\)", code):
                self.assertIn(ident, ids, f"JS refers to missing element id={ident}")

    def test_safari_username_password_and_private_link_masked(self):
        ids = self.document.ids
        self.assertEqual(ids["localUsername"]["attrs"]["autocomplete"], "username")
        self.assertEqual(ids["secret"]["attrs"]["autocomplete"], "current-password")
        self.assertEqual(ids["secret"]["attrs"]["type"], "password")
        self.assertEqual(ids["issuedManifestUrl"]["attrs"]["type"], "password")
        self.assertEqual(ids["issuedManifestUrl"]["attrs"].get("readonly"), None)
        self.assertIn("assets/workspace.js", HTML)
        self.assertIn("assets/app.js", HTML)
        self.assertNotIn("v5_", HTML)
        self.assertNotIn("SOURCE_SECRETS_KEY", HTML)
        self.assertNotIn("ADDON_TOKEN", HTML)
        self.assertIn("autocomplete=\"new-password\"", HTML)
        self.assertIn("role=\"status\"", HTML)

    def test_two_roles_and_protected_system_nav(self):
        ids = self.document.ids
        self.assertIn("personalWorkspace", ids)
        self.assertIn("adminWorkspace", ids)
        self.assertIn("adminWorkspace", ids["usersPanel"]["ancestors"])
        self.assertNotIn("personalWorkspace", ids["usersPanel"]["ancestors"])
        self.assertEqual(ids["navSystem"]["attrs"].get("hidden"), None)
        self.assertEqual(ids["adminWorkspace"]["attrs"].get("hidden"), None)
        self.assertIn("account.role !== 'admin'", WORKSPACE)
        self.assertIn("if (!window.VODWorkspace.isAdmin()) return;", APP)
        self.assertIn("await window.VODWorkspace.activate(identity, api)", APP)
        self.assertIn("if (!result.role)", APP)
        self.assertIn("await refresh(true)", APP)  # Admin-only navigation
        self.assertIn("openPersonal();", APP)

    def test_private_secrets_never_persist_or_render_untrusted_html(self):
        self.assertIn("oneTimeUrl = ''", WORKSPACE)
        self.assertIn("function clearSensitive()", WORKSPACE)
        self.assertIn("navigator.clipboard.writeText(oneTimeUrl)", WORKSPACE)
        self.assertIn("input.value = isHidden ? oneTimeUrl : ''", WORKSPACE)
        self.assertIn("status('personalManifestStatus'", WORKSPACE)
        self.assertIn("window.VODWorkspace.clearSensitive();", APP)
        self.assertNotIn("localStorage", WORKSPACE)
        self.assertNotIn("sessionStorage", WORKSPACE)
        self.assertNotIn("innerHTML", WORKSPACE)
        self.assertNotIn("outerHTML", WORKSPACE)
        self.assertNotIn("window.prompt", WORKSPACE)
        self.assertIn("resetInput.type = 'password'", WORKSPACE)
        self.assertIn("document.createTextNode", WORKSPACE)
        self.assertIn("source_id", WORKSPACE)
        self.assertIn("SOURCE", HTML.upper())

    def test_sources_and_manifests_not_stored_in_global_settings(self):
        for action in (
            "'/api/my/sources'", "'/api/my/manifests'",
            "'/api/system/users'",
        ):
            self.assertIn(action, WORKSPACE)
        self.assertIn("'/api/settings'", APP)
        self.assertNotIn("'/api/settings'", WORKSPACE)
        self.assertIn("sourceConfig()", WORKSPACE)
        self.assertIn("resetSourceForm()", WORKSPACE)
        self.assertIn("editingSource", WORKSPACE)
        self.assertIn("SOURCE", HTML.upper())
        self.assertIn(".workspace-grid", CSS)
        self.assertIn("@media(max-width:1040px)", CSS)

    def test_explicit_user_role_does_not_fetch_admin_overview(self):
        # A normal User goes to My Workspace; the only automatic
        # /api/overview fetch happens inside openSystem (Admin guarded).
        start = APP.index("async function showDashboard(identity)")
        finish = APP.index("$('loginForm').addEventListener", start)
        on_login = APP[start:finish]
        self.assertNotIn("refresh(true)", on_login)
        self.assertNotIn("prepareManifest()", on_login)
        self.assertIn("openPersonal()", on_login)
        self.assertIn("window.VODWorkspace.activate", on_login)
        self.assertIn("account.role === 'admin' ? [refreshUsers()]", WORKSPACE)

    def test_delete_and_rotate_require_explicit_confirmation(self):
        for label in (
            "Rotate this addon URL?",
            "Permanently delete this manifest",
            "Delete this source",
            "Disable this manifest now",
        ):
            self.assertIn(label, WORKSPACE)
        self.assertIn("source_ids: picked", WORKSPACE)
        self.assertIn("replaceSourceConfig", WORKSPACE)


if __name__ == "__main__":
    unittest.main()
