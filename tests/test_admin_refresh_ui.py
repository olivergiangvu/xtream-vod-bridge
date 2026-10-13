"""Regression checks for visible, read-only Admin stats refresh.

Runtime HomeDocker acceptance still requires Safari/Edge manual testing.
"""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "admin/assets/app.js"
HTML = ROOT / "admin/index.html"


class RefreshFeedbackTests(unittest.TestCase):
    def test_refresh_button_has_accessible_feedback(self):
        html = HTML.read_text(encoding="utf-8")
        self.assertIn('id="refresh" class="ghost" type="button"', html)
        self.assertIn('id="refreshStatus"', html)
        self.assertIn('role="status" aria-live="polite"', html)
        self.assertIn('aria-atomic="true"', html)

    def test_manual_refresh_is_visible_and_read_only(self):
        js = JS.read_text(encoding="utf-8")
        self.assertIn("button.textContent = 'Refreshing…'", js)
        self.assertIn("button.disabled = true", js)
        self.assertIn("refreshFeedback('Checking latest stats…')", js)
        self.assertIn("refreshFeedback('Refreshed at '", js)
        self.assertIn("refreshFeedback('Refresh failed: '", js)
        self.assertIn("button.textContent = 'Refresh stats'", js)
        self.assertIn("await refresh(false);", js)
        self.assertIn("const data = await api('/api/overview')", js.replace(
            "const current = api('/api/overview').then(data => {",
            "const data = await api('/api/overview')"
        ))
        # A manual stats refresh never submits or overwrites unsaved settings.
        click = js.split("$('refresh').addEventListener('click', async () => {", 1)[1].split(
            "\n});", 1
        )[0]
        self.assertNotIn("api('/api/settings'", click)
        self.assertNotIn("draw(data, true)", click)

    def test_overlapping_poll_and_manual_refresh_are_coalesced(self):
        js = JS.read_text(encoding="utf-8")
        self.assertIn("let refreshInFlight = null", js)
        self.assertIn("if (!setForm) return refreshInFlight", js)
        self.assertIn("if (refreshInFlight) return;", js)
        self.assertIn("15000", js)

    def test_expired_gateway_session_redirects_instead_of_parsing_html(self):
        js = JS.read_text(encoding="utf-8")
        self.assertIn("response.redirected", js)
        self.assertIn("response.url", js)
        self.assertIn("window.location.replace('/admin-signin/')", js)
        self.assertIn("Unexpected API response (expected JSON)", js)

    @unittest.skipUnless(shutil.which("node"), "Node.js not present")
    def test_js_syntax(self):
        subprocess.run(["node", "--check", str(JS)], check=True,
                       capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
