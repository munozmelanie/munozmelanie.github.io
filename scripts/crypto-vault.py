#!/usr/bin/env python3
"""Encrypt a reviewed local day bundle for the public static site.

No password, document, or decrypted manifest is written to the public directory.
The public salt is stable so unchanged encrypted assets can be reused.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = pathlib.Path(__file__).resolve().parents[1]
ITERATIONS = 600_000
# Embedded classroom videos can exceed 25 MiB. Keep ciphertext (including its
# 16-byte authentication tag) below GitHub's 100 MiB per-file Git limit.
MAX_FILE = 90 * 1024 * 1024
MAX_DAY = 256 * 1024
MAX_MANIFEST = 4 * 1024 * 1024
DATA_PATTERN = re.compile(r"data/[0-9a-f]{64}\.bin\Z")
DATE_PATTERN = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}\Z")
PART_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
ID_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,79}\Z")
FILE_TYPES = {
    ".pdf": "application/pdf",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".zip": "application/zip",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".mp3": "audio/mpeg",
}
MANIFEST_AAD = b"relais-cm1:v1:manifest"


class VaultError(Exception):
    """A safe, user-readable failure without secret material."""


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: str, length: int) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (TypeError, ValueError):
        raise VaultError("Encodage du coffre incorrect.") from None
    if len(raw) != length:
        raise VaultError("Longueur cryptographique incorrecte.")
    return raw


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def serialize(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = unicodedata.normalize("NFC", password).encode("utf-8")
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(password_bytes)


def keychain_password(helper: pathlib.Path | None = None) -> str:
    helper = helper or ROOT / ".private" / "keychain-helper"
    if not helper.is_file():
        raise VaultError("L’utilitaire du trousseau est absent.")
    result = subprocess.run([str(helper), "get", "relais-cm1-reader", "munozmelanie.github.io"], capture_output=True)
    if result.returncode:
        raise VaultError("Lecture du mot de passe dans le trousseau impossible.")
    try:
        password = result.stdout.decode("utf-8")
    except UnicodeError:
        raise VaultError("Format du mot de passe incorrect.") from None
    if not 16 <= len(password) <= 512 or any(c in password for c in "\r\n\x00"):
        raise VaultError("Le mot de passe du trousseau doit contenir entre 16 et 512 caractères.")
    return password


def valid_date(value) -> dt.date:
    if not isinstance(value, str) or not DATE_PATTERN.fullmatch(value):
        raise VaultError("Date de journée incorrecte.")
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        raise VaultError("Date de journée incorrecte.") from None


def validate_file(data: bytes, extension: str) -> bool:
    if extension == ".pdf":
        return data.startswith(b"%PDF-")
    if extension in (".pptx", ".zip"):
        return data.startswith(b"PK\x03\x04")
    if extension == ".png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if extension in (".jpg", ".jpeg"):
        return data.startswith(b"\xff\xd8\xff")
    if extension == ".mp3":
        return data.startswith(b"ID3") or (len(data) >= 2 and data[0] == 0xFF and data[1] & 0xE0 == 0xE0)
    return False


def load_bundle(folder: pathlib.Path):
    folder = folder.resolve()
    raw = (folder / "day.json").read_bytes()
    if len(raw) > MAX_DAY:
        raise VaultError("Le programme dépasse la taille maximale.")
    day = json.loads(raw)
    if not isinstance(day, dict) or day.get("schemaVersion") != 1:
        raise VaultError("Format de journée incorrect.")
    valid_date(day.get("date"))
    if day.get("status") not in ("ready", "partial", "missing"):
        raise VaultError("État de journée incorrect.")
    documents = day.get("documents")
    sessions = day.get("sessions")
    if not isinstance(documents, list) or len(documents) > 100 or not isinstance(sessions, list) or len(sessions) > 100:
        raise VaultError("Liste de documents ou de séances incorrecte.")
    files_root = (folder / "files").resolve()
    files, ids, paths = [], set(), set()
    for document in documents:
        if not isinstance(document, dict) or not ID_PATTERN.fullmatch(document.get("id", "")) or document["id"] in ids:
            raise VaultError("Identifiant de document incorrect ou répété.")
        ids.add(document["id"])
        path = document.get("path", "")
        if not isinstance(path, str):
            raise VaultError("Chemin de document incorrect.")
        parts = path.split("/")
        if len(parts) != 3 or parts[0] != day["date"] or any(not PART_PATTERN.fullmatch(p) or ".." in p for p in parts) or path in paths:
            raise VaultError("Chemin de document incorrect ou répété.")
        paths.add(path)
        source = (files_root / path).resolve()
        if not source.is_relative_to(files_root) or not source.is_file():
            raise VaultError("Un document est absent ou sort du dossier autorisé.")
        extension = source.suffix.lower()
        size = source.stat().st_size
        if extension not in FILE_TYPES or document.get("mime") != FILE_TYPES[extension] or not 0 < size <= MAX_FILE or document.get("sizeBytes") != size:
            raise VaultError("Type ou taille de document incorrect.")
        data = source.read_bytes()
        if not validate_file(data, extension):
            raise VaultError("Le contenu d’un document ne correspond pas à son type.")
        actual_hash = digest(data)
        if document.get("sha256") and document["sha256"] != actual_hash:
            raise VaultError("Le contenu d’un document a changé depuis sa préparation.")
        document["sha256"] = actual_hash
        files.append((document, data))
    for session in sessions:
        if not isinstance(session, dict) or not isinstance(session.get("documentIds"), list) or any(i not in ids for i in session["documentIds"]):
            raise VaultError("Une séance référence un document absent.")
    return day, files


def asset_aad(asset_id: str) -> bytes:
    if not isinstance(asset_id, str) or not re.fullmatch(r"[0-9a-f]{32}", asset_id):
        raise VaultError("Identifiant chiffré incorrect.")
    return ("relais-cm1:v1:asset:" + asset_id).encode("ascii")


def read_cipher(public: pathlib.Path, descriptor: dict, size_key: str) -> bytes:
    path = descriptor.get("path", "")
    if not isinstance(path, str) or not DATA_PATTERN.fullmatch(path):
        raise VaultError("Chemin chiffré incorrect.")
    source = public / path
    if source.is_symlink() or not source.resolve().is_relative_to(public.resolve()):
        raise VaultError("Lien de fichier chiffré interdit.")
    expected_size = descriptor.get(size_key)
    maximum = MAX_MANIFEST + 16 if size_key == "sizeBytes" else MAX_FILE + 16
    if not isinstance(expected_size, int) or not 16 <= expected_size <= maximum or source.stat().st_size != expected_size:
        raise VaultError("Taille du fichier chiffré incorrecte.")
    ciphertext = source.read_bytes()
    if digest(ciphertext) != source.stem:
        raise VaultError("L’empreinte d’un fichier chiffré est incorrecte.")
    return ciphertext


def decrypt_asset(public: pathlib.Path, key: bytes, descriptor: dict) -> bytes:
    ciphertext = read_cipher(public, descriptor, "cipherSizeBytes")
    try:
        plaintext = AESGCM(key).decrypt(unb64(descriptor.get("iv"), 12), ciphertext, asset_aad(descriptor.get("id")))
    except InvalidTag:
        raise VaultError("Authentification d’un document chiffré refusée.") from None
    if len(plaintext) != descriptor.get("sizeBytes") or digest(plaintext) != descriptor.get("sha256"):
        raise VaultError("La vérification d’un document déchiffré a échoué.")
    return plaintext


def open_vault(public: pathlib.Path, password: str):
    vault_path = public / "vault.json"
    raw = vault_path.read_bytes()
    if len(raw) > 8192:
        raise VaultError("En-tête du coffre trop volumineux.")
    vault = json.loads(raw)
    if not isinstance(vault, dict) or vault.get("format") != "relais-cm1-vault" or vault.get("version") != 1:
        raise VaultError("Version du coffre non reconnue.")
    kdf = vault.get("kdf", {})
    if kdf.get("name") != "PBKDF2" or kdf.get("hash") != "SHA-256" or kdf.get("iterations") != ITERATIONS:
        raise VaultError("Paramètres de dérivation du coffre incorrects.")
    if vault.get("cipher") != {"name": "AES-GCM", "keyBits": 256, "tagBits": 128}:
        raise VaultError("Paramètres de chiffrement incorrects.")
    key = derive_key(password, unb64(kdf.get("salt"), 16))
    descriptor = vault.get("manifest", {})
    ciphertext = read_cipher(public, descriptor, "sizeBytes")
    try:
        plaintext = AESGCM(key).decrypt(unb64(descriptor.get("iv"), 12), ciphertext, MANIFEST_AAD)
    except InvalidTag:
        raise VaultError("Mot de passe incorrect ou coffre altéré.") from None
    manifest = json.loads(plaintext)
    if not isinstance(manifest, dict) or manifest.get("version") != 1 or not isinstance(manifest.get("days"), dict) or not isinstance(manifest.get("assets"), dict):
        raise VaultError("Programme chiffré incorrect.")
    return vault, manifest, key


def atomic_write(path: pathlib.Path, data: bytes):
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_vault(bundle: pathlib.Path, public: pathlib.Path, password: str, retain_days: int = 14):
    if not 1 <= retain_days <= 31:
        raise VaultError("La conservation doit couvrir entre 1 et 31 jours.")
    day, files = load_bundle(bundle)
    public = public.resolve()
    public.mkdir(parents=True, exist_ok=True)
    data_dir = public / "data"
    if data_dir.is_symlink():
        raise VaultError("Le dossier chiffré ne peut pas être un lien.")
    data_dir.mkdir(exist_ok=True)
    if any(p.is_symlink() or not p.is_file() or not re.fullmatch(r"[0-9a-f]{64}\.bin", p.name) for p in data_dir.iterdir()):
        raise VaultError("Le dossier public/data contient un fichier non autorisé.")
    if (public / "vault.json").exists():
        vault, previous, key = open_vault(public, password)
    else:
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        vault = {"format": "relais-cm1-vault", "version": 1,
                 "kdf": {"name": "PBKDF2", "hash": "SHA-256", "iterations": ITERATIONS, "salt": b64(salt)},
                 "cipher": {"name": "AES-GCM", "keyBits": 256, "tagBits": 128}}
        previous = {"days": {}, "assets": {}}
    aes = AESGCM(key)
    used_ivs = {entry.get("iv") for entry in previous["assets"].values()}
    if "manifest" in vault:
        used_ivs.add(vault["manifest"].get("iv"))

    def nonce():
        while True:
            iv = secrets.token_bytes(12)
            if b64(iv) not in used_ivs:
                used_ivs.add(b64(iv))
                return iv

    days = dict(previous["days"])
    days[day["date"]] = day
    latest = max(days)
    cutoff = valid_date(latest) - dt.timedelta(days=retain_days - 1)
    if valid_date(day["date"]) < cutoff:
        raise VaultError("Cette journée est antérieure à la période de conservation.")
    days = {date: value for date, value in days.items() if valid_date(date) >= cutoff}
    required = {doc["path"] for value in days.values() for doc in value["documents"]}
    assets = {path: value for path, value in previous["assets"].items() if path in required}
    reusable = {(entry.get("sha256"), entry.get("mime"), entry.get("sizeBytes")): entry
                for entry in previous["assets"].values()}
    writes, reused = {}, 0
    for document, plaintext in files:
        path = document["path"]
        old = reusable.get((document["sha256"], document["mime"], len(plaintext)))
        if old and old.get("sha256") == document["sha256"] and old.get("sizeBytes") == len(plaintext) and old.get("mime") == document["mime"]:
            if decrypt_asset(public, key, old) != plaintext:
                raise VaultError("La vérification d’un document conservé a échoué.")
            assets[path] = {**old, "filename": pathlib.PurePosixPath(path).name}
            reused += 1
            continue
        asset_id = secrets.token_hex(16)
        iv = nonce()
        aad = asset_aad(asset_id)
        ciphertext = aes.encrypt(iv, plaintext, aad)
        if aes.decrypt(iv, ciphertext, aad) != plaintext:
            raise VaultError("La vérification du chiffrement a échoué.")
        cipher_path = "data/" + digest(ciphertext) + ".bin"
        assets[path] = {"id": asset_id, "path": cipher_path, "iv": b64(iv), "mime": document["mime"],
                        "filename": pathlib.PurePosixPath(path).name, "sizeBytes": len(plaintext),
                        "sha256": digest(plaintext), "cipherSizeBytes": len(ciphertext)}
        writes[cipher_path] = ciphertext
    # Verify retained documents too: a broken old archive must not be republished.
    for path, descriptor in assets.items():
        if descriptor["path"] not in writes:
            decrypt_asset(public, key, descriptor)
    if set(assets) != required:
        raise VaultError("Des documents nécessaires au programme sont absents du coffre.")
    manifest = {"version": 1, "updatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                "latestDate": latest, "days": days, "assets": assets}
    plaintext = serialize(manifest)
    if len(plaintext) > MAX_MANIFEST:
        raise VaultError("Le programme chiffré dépasse la taille maximale.")
    iv = nonce()
    ciphertext = aes.encrypt(iv, plaintext, MANIFEST_AAD)
    if aes.decrypt(iv, ciphertext, MANIFEST_AAD) != plaintext:
        raise VaultError("La vérification du programme a échoué.")
    manifest_path = "data/" + digest(ciphertext) + ".bin"
    writes[manifest_path] = ciphertext
    vault["manifest"] = {"path": manifest_path, "iv": b64(iv), "sizeBytes": len(ciphertext)}
    for path, data in writes.items():
        target = public / path
        if target.exists() and target.read_bytes() != data:
            raise VaultError("Collision de nom chiffré détectée.")
        if not target.exists():
            atomic_write(target, data)
    atomic_write(public / "vault.json", serialize(vault) + b"\n")
    keep = {entry["path"] for entry in assets.values()} | {manifest_path}
    for path in data_dir.iterdir():
        if "data/" + path.name not in keep:
            path.unlink()
    check_vault, check_manifest, check_key = open_vault(public, password)
    if check_manifest != manifest or check_key != key or check_vault != vault:
        raise VaultError("La relecture du coffre préparé a échoué.")
    for descriptor in assets.values():
        decrypt_asset(public, key, descriptor)
    return {"ok": True, "date": day["date"], "days": len(days), "documents": len(files),
            "reusedAssets": reused, "encryptedAssets": len(assets), "verified": True,
            "manifestSha256": digest(ciphertext)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=pathlib.Path, required=True)
    parser.add_argument("--public", type=pathlib.Path, default=ROOT / "public")
    parser.add_argument("--keychain-helper", type=pathlib.Path)
    parser.add_argument("--retain-days", type=int, default=14)
    args = parser.parse_args()
    try:
        result = prepare_vault(args.bundle, args.public, keychain_password(args.keychain_helper), args.retain_days)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (VaultError, OSError, ValueError, TypeError, KeyError) as error:
        print("Préparation impossible : " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
