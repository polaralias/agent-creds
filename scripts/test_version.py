import tempfile
from pathlib import Path
import unittest
from version import check, set_version


class ReleaseVersionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "VERSION").write_text("0.1.0\n")
        (self.root / "Cargo.toml").write_text('[package]\nname = "agent-creds"\nversion = "0.1.0"\n')
        (self.root / "Cargo.lock").write_text('version = 4\n\n[[package]]\nname = "agent-creds"\nversion = "0.1.0"\n\n[[package]]\nname = "dependency"\nversion = "0.1.0"\n')

    def test_release_tag_and_mirrors_must_match(self):
        self.assertEqual(check(self.root, "v0.1.0"), "0.1.0")
        with self.assertRaises(ValueError):
            check(self.root, "v0.2.0")
        (self.root / "VERSION").write_text("0.2.0\n")
        with self.assertRaises(ValueError):
            check(self.root)

    def test_bump_preserves_dependency_versions(self):
        set_version("0.2.0", self.root)
        self.assertEqual(check(self.root, "v0.2.0"), "0.2.0")
        self.assertIn('name = "dependency"\nversion = "0.1.0"', (self.root / "Cargo.lock").read_text())

    def test_invalid_bump_changes_nothing(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        for value in ("01.2.3", "v1.2.3", "1.2.3\n", "1.2", "../escape"):
            with self.assertRaises(ValueError):
                set_version(value, self.root)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})


if __name__ == "__main__":
    unittest.main()
