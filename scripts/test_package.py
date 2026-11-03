import unittest
from check_package import ROOT_FILES, validate_paths


class PackageBoundaryTests(unittest.TestCase):
    def test_expected_source_and_notices_are_accepted(self):
        validate_paths([*ROOT_FILES, "src/main.rs", "docs/security.md"])
        validate_paths([*ROOT_FILES, "src\\main.rs", "docs\\security.md"])

    def test_private_and_traversal_paths_are_rejected(self):
        baseline = [*ROOT_FILES, "src/main.rs"]
        for private in ["local-docs/README.md", "local-docs/tool/docs/security.md", "target/debug/agent-creds", "dist/archive.zip", "src/../private", "/absolute"]:
            with self.assertRaises(ValueError):
                validate_paths([*baseline, private])


if __name__ == "__main__":
    unittest.main()
