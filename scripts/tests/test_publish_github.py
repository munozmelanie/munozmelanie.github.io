import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

from test_crypto_vault import PASSWORD, bundle

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("publisher", ROOT / "scripts" / "publish-github.py")
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.remote = self.root / "remote.git"
        self.source = self.root / "local-bundle"
        bundle(self.source)
        self.command("git", "init", "--bare", str(self.remote))
        self.command("git", "init", "--initial-branch=main", str(self.repo))
        self.run_git("config", "user.email", "fixture@example.invalid")
        self.run_git("config", "user.name", "Synthetic test")
        (self.repo / "public").mkdir()
        (self.repo / "public/index.html").write_text("<p>Public test shell</p>")
        self.run_git("add", "public/index.html")
        self.run_git("commit", "-m", "Initial synthetic shell")
        self.run_git("remote", "add", "origin", str(self.remote))
        self.run_git("push", "-u", "origin", "main")

    def tearDown(self):
        self.temp.cleanup()

    def command(self, *args):
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def run_git(self, *args):
        return self.command("git", "-C", str(self.repo), *args)

    def test_non_github_origin_rejected_without_mutation(self):
        before = self.run_git("rev-parse", "HEAD")
        with self.assertRaisesRegex(publisher.vault.VaultError, "origine Git"):
            publisher.publish(self.repo, self.source, PASSWORD)
        self.assertEqual(before, self.run_git("rev-parse", "HEAD"))
        self.assertFalse((self.repo / "public/vault.json").exists())

    def test_preexisting_staging_is_preserved(self):
        self.run_git("remote", "set-url", "origin", "https://github.com/munozmelanie/munozmelanie.github.io.git")
        (self.repo / "work.txt").write_text("Unrelated user work")
        self.run_git("add", "work.txt")
        with self.assertRaisesRegex(publisher.vault.VaultError, "déjà indexés"):
            publisher.publish(self.repo, self.source, PASSWORD)
        self.assertEqual(self.run_git("diff", "--cached", "--name-only").strip(), "work.txt")

    def test_atomic_commit_contains_only_encrypted_generated_data(self):
        private = self.repo / ".private"
        private.mkdir()
        (private / "secret-fixture.txt").write_text("Never commit this synthetic plaintext")
        previous = self.run_git("rev-parse", "HEAD").strip()
        # The production origin verifier is separately tested above. Use an
        # isolated local bare remote here so this integration test has no network.
        with mock.patch.object(publisher, "verify_repository"):
            result = publisher.publish(self.repo, self.source, PASSWORD)
        self.assertTrue(result["pushed"])
        changed = self.run_git("diff", "--name-only", previous, "HEAD").splitlines()
        self.assertTrue(changed)
        self.assertTrue(all(publisher.generated(path) for path in changed))
        tree = self.run_git("ls-tree", "-r", "--name-only", "HEAD")
        self.assertNotIn("secret-fixture", tree)
        self.assertNotIn("day.json", tree)
        self.assertNotIn(".pdf", tree)
        remote_head = self.command("git", "--git-dir=" + str(self.remote), "rev-parse", "main").strip()
        self.assertEqual(result["commit"], remote_head)
        self.assertFalse(self.run_git("diff", "--cached", "--name-only").strip())

    def test_prepare_only_never_commits_or_pushes(self):
        previous = self.run_git("rev-parse", "HEAD")
        result = publisher.publish(self.repo, self.source, PASSWORD, prepare_only=True)
        self.assertTrue(result["preparedOnly"])
        self.assertEqual(previous, self.run_git("rev-parse", "HEAD"))
        self.assertFalse(self.run_git("diff", "--cached", "--name-only").strip())


if __name__ == "__main__":
    unittest.main()
