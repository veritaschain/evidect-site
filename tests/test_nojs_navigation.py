"""Contract for the no-JavaScript header fallback, not accessibility certification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NoJavaScriptNavigationTests(unittest.TestCase):
    def test_small_unenhanced_header_scrolls_with_document(self):
        css = (ROOT / 'assets/css/evidect-site.css').read_text()
        self.assertIn('@media(max-width:1100px){.ev-header:not([data-enhanced]){position:static}}', css)

    def test_default_sticky_header_is_preserved(self):
        css = (ROOT / 'assets/css/evidect-site.css').read_text()
        self.assertIn('.ev-header{position:sticky;', css)
        self.assertIn('.ev-header[data-enhanced] .ev-menu[aria-expanded=false]+.ev-nav{display:none}', css)

    def test_keyboard_focus_and_reduced_motion_are_preserved(self):
        css = (ROOT / 'assets/css/evidect-site.css').read_text()
        self.assertIn('.ev-skip:focus{top:12px}', css)
        self.assertIn('@media(prefers-reduced-motion:reduce)', css)


if __name__ == '__main__':
    unittest.main()
