import importlib.util
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("vault", ROOT / "scripts" / "crypto-vault.py")
vault = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vault)
PASSWORD = "rivière-lumière-papillon-citron-42"  # Synthetic fixture only.


def bundle(folder, date="2026-11-19", marker="Synthetic private classroom title", revision="test-v1"):
    files = []
    for name, payload in (("fiche.pdf", b"%PDF-1.7\nSynthetic exercise\n%%EOF"),
                          ("chant.mp3", b"ID3\x04\x00\x00Synthetic music fixture")):
        relative = date + "/" + revision + "/" + name
        path = folder / "files" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        files.append({"id": "fiche" if name.endswith("pdf") else "chant", "title": marker + name,
                      "kind": "worksheet" if name.endswith("pdf") else "other", "path": relative,
                      "mime": vault.FILE_TYPES[path.suffix], "sizeBytes": len(payload), "sha256": vault.digest(payload)})
    day = {"schemaVersion": 1, "date": date, "updatedAt": date + "T16:00:00Z", "title": marker,
           "status": "ready", "intro": "Synthetic fixture, not real classroom content.", "documents": files,
           "sessions": [{"id": "lecture", "subject": "Français", "title": "Lecture", "instructions": [],
                         "materials": [], "documentIds": ["fiche"]}], "missing": [], "notes": []}
    (folder / "day.json").write_text(json.dumps(day), encoding="utf-8")
    return day


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = pathlib.Path(self.temp.name)
        self.source = self.folder / "bundle"
        self.public = self.folder / "public"
        self.day = bundle(self.source)

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self):
        return vault.prepare_vault(self.source, self.public, PASSWORD)

    def test_roundtrip_all_content_encrypted_and_wrong_password_rejected(self):
        self.prepare()
        _, manifest, key = vault.open_vault(self.public, PASSWORD)
        self.assertEqual(manifest["days"][self.day["date"]], self.day)
        for doc in self.day["documents"]:
            raw = vault.decrypt_asset(self.public, key, manifest["assets"][doc["path"]])
            self.assertEqual(raw, (self.source / "files" / doc["path"]).read_bytes())
        for path in self.public.rglob("*"):
            if path.is_file():
                self.assertNotIn(self.day["title"].encode(), path.read_bytes())
                self.assertNotIn(PASSWORD.encode(), path.read_bytes())
        with self.assertRaisesRegex(vault.VaultError, "Mot de passe incorrect"):
            vault.open_vault(self.public, "incorrect-password-123456")

    def test_authenticated_tamper_and_context_swap_rejected(self):
        self.prepare()
        _, manifest, key = vault.open_vault(self.public, PASSWORD)
        desc = dict(next(iter(manifest["assets"].values())))
        ciphertext = bytearray((self.public / desc["path"]).read_bytes())
        ciphertext[-1] ^= 1
        desc["path"] = "data/" + vault.digest(ciphertext) + ".bin"
        (self.public / desc["path"]).write_bytes(ciphertext)
        with self.assertRaisesRegex(vault.VaultError, "Authentification"):
            vault.decrypt_asset(self.public, key, desc)
        desc = dict(next(iter(manifest["assets"].values())))
        desc["id"] = "f" * 32 if desc["id"] != "f" * 32 else "e" * 32
        with self.assertRaisesRegex(vault.VaultError, "Authentification"):
            vault.decrypt_asset(self.public, key, desc)

    def test_nonce_uniqueness_reuse_and_new_revision(self):
        self.prepare()
        header, manifest, _ = vault.open_vault(self.public, PASSWORD)
        ivs = [header["manifest"]["iv"]] + [a["iv"] for a in manifest["assets"].values()]
        self.assertEqual(len(ivs), len(set(ivs)))
        paths = {a["path"] for a in manifest["assets"].values()}
        bundle(self.source, revision="test-v2")
        result = self.prepare()
        updated_header, updated, _ = vault.open_vault(self.public, PASSWORD)
        self.assertEqual(result["reusedAssets"], 2)
        self.assertEqual(paths, {a["path"] for a in updated["assets"].values()})
        self.assertEqual(header["kdf"]["salt"], updated_header["kdf"]["salt"])
        self.assertNotIn(updated_header["manifest"]["iv"], ivs)

    def test_missing_file_failure_keeps_current_vault(self):
        self.prepare()
        old_header = (self.public / "vault.json").read_bytes()
        (self.source / "files" / self.day["documents"][0]["path"]).unlink()
        with self.assertRaises(vault.VaultError):
            self.prepare()
        self.assertEqual(old_header, (self.public / "vault.json").read_bytes())
        vault.open_vault(self.public, PASSWORD)

    def test_archive_retention_and_path_traversal(self):
        self.prepare()
        bundle(self.source, date="2026-12-10")
        self.prepare()
        _, manifest, _ = vault.open_vault(self.public, PASSWORD)
        self.assertEqual(list(manifest["days"]), ["2026-12-10"])
        invalid = bundle(self.source)
        invalid["documents"][0]["path"] = "2026-11-19/../../secret.pdf"
        (self.source / "day.json").write_text(json.dumps(invalid))
        with self.assertRaises(vault.VaultError):
            self.prepare()

    def sparse_document(self, size):
        """Use real file sizes without writing tens of MiB of padding."""
        document = self.day["documents"][0]
        source = self.source / "files" / document["path"]
        with source.open("r+b") as stream:
            stream.truncate(size)
        document["sizeBytes"] = size
        document.pop("sha256", None)
        (self.source / "day.json").write_text(json.dumps(self.day))
        return source

    def test_bundle_larger_than_previous_25_mib_limit_is_accepted(self):
        size = 26 * 1024 * 1024
        self.sparse_document(size)
        day, files = vault.load_bundle(self.source)
        document, data = files[0]
        self.assertEqual(len(data), size)
        self.assertEqual(document["sizeBytes"], size)
        self.assertEqual(document["sha256"], vault.digest(data))
        self.assertEqual(day["documents"][0], document)

    def test_bundle_90_mib_boundary_checked_before_reading_file(self):
        self.assertEqual(vault.MAX_FILE, 90 * 1024 * 1024)
        original_read = pathlib.Path.read_bytes

        class ReachedFileRead(Exception):
            pass

        for size, accepted in ((vault.MAX_FILE, True), (vault.MAX_FILE + 1, False)):
            with self.subTest(size=size):
                source = self.sparse_document(size).resolve()
                def read_bytes(path):
                    if path == source:
                        raise ReachedFileRead()
                    return original_read(path)
                # Real stat, document metadata and sparse size agree. Stop only
                # after validation, before a needless 90 MiB read/hash.
                with mock.patch.object(pathlib.Path, "read_bytes", read_bytes):
                    if accepted:
                        with self.assertRaises(ReachedFileRead):
                            vault.load_bundle(self.source)
                    else:
                        with self.assertRaisesRegex(vault.VaultError, "Type ou taille"):
                            vault.load_bundle(self.source)

    def test_ciphertext_boundary_includes_authentication_tag(self):
        path = self.public / "data" / ("a" * 64 + ".bin")
        path.parent.mkdir(parents=True)

        class ReachedCipherRead(Exception):
            pass

        for size, accepted in ((vault.MAX_FILE + 16, True), (vault.MAX_FILE + 17, False)):
            with self.subTest(size=size):
                with path.open("wb") as stream:
                    stream.truncate(size)
                descriptor = {"path": "data/" + path.name, "cipherSizeBytes": size}
                with mock.patch.object(pathlib.Path, "read_bytes", side_effect=ReachedCipherRead):
                    if accepted:
                        with self.assertRaises(ReachedCipherRead):
                            vault.read_cipher(self.public, descriptor, "cipherSizeBytes")
                    else:
                        with self.assertRaisesRegex(vault.VaultError, "Taille du fichier chiffré"):
                            vault.read_cipher(self.public, descriptor, "cipherSizeBytes")

    def test_webcrypto_interoperability_and_unicode_nfc(self):
        self.prepare()
        node = shutil.which("node")
        if not node:
            self.fail("Node is required for WebCrypto interoperability validation.")
        result = subprocess.run([node, str(ROOT / "scripts" / "tests" / "webcrypto-fixture.mjs"), str(self.public)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("2 assets verified", result.stdout)


if __name__ == "__main__":
    unittest.main()
