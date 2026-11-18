#!/usr/bin/env python3
"""Prepare encrypted day files, then commit and push their atomic Git snapshot.

The initial --prepare-only run never commits, pushes, or creates a repository.
Credentials are read by macOS Keychain and the existing Git credential helper.
"""
from __future__ import annotations

import argparse
import fcntl
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("crypto_vault", ROOT / "scripts" / "crypto-vault.py")
vault = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vault)
DEFAULT_REPOSITORY = "munozmelanie/munozmelanie.github.io"


def generated(path: str) -> bool:
    return path == "public/vault.json" or bool(re.fullmatch(r"public/data/[0-9a-f]{64}\.bin", path))


def git(repo: pathlib.Path, *args: str, allow_failure: bool = False):
    environment = dict(os.environ)
    environment.update({"GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "Never"})
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=environment)
    if result.returncode and not allow_failure:
        # Git's diagnostic can contain credential URLs; never echo it into logs.
        raise vault.VaultError("Git a refusé l’étape « %s » (code %s)." % (args[0], result.returncode))
    return result


def names(repo: pathlib.Path, *args: str) -> list[str]:
    return [p.decode("utf-8") for p in git(repo, *args, "-z").stdout.split(b"\0") if p]


def verify_repository(repo: pathlib.Path, repository: str, branch: str):
    if not re.fullmatch(r"munozmelanie/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_/-]*", branch) or ".." in branch:
        raise vault.VaultError("Dépôt ou branche non autorisés.")
    root = pathlib.Path(git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip()).resolve()
    if root != repo.resolve():
        raise vault.VaultError("Le dossier doit être la racine exacte du dépôt.")
    expected = {"https://github.com/" + repository, "https://github.com/" + repository + ".git",
                "git@github.com:" + repository + ".git", "ssh://git@github.com/" + repository + ".git"}
    fetch_urls = git(repo, "remote", "get-url", "--all", "origin").stdout.decode().splitlines()
    push_urls = git(repo, "remote", "get-url", "--push", "--all", "origin").stdout.decode().splitlines()
    if len(fetch_urls) != 1 or len(push_urls) != 1 or fetch_urls[0] not in expected or push_urls[0] not in expected:
        raise vault.VaultError("L’origine Git ne correspond pas exactement au dépôt prévu.")
    actual_branch = git(repo, "symbolic-ref", "--short", "HEAD").stdout.decode().strip()
    if actual_branch != branch:
        raise vault.VaultError("La branche active ne correspond pas à la branche de publication.")
    if names(repo, "diff", "--cached", "--name-only"):
        raise vault.VaultError("Des changements sont déjà indexés ; publication arrêtée pour les préserver.")
    if any(not generated(path) for path in names(repo, "diff", "--name-only")):
        raise vault.VaultError("Le code comporte des modifications locales non validées.")
    git(repo, "fetch", "--no-tags", "origin", branch)
    remote_ref = "refs/remotes/origin/" + branch
    if git(repo, "merge-base", "--is-ancestor", remote_ref, "HEAD", allow_failure=True).returncode:
        raise vault.VaultError("Le dépôt distant a changé ; synchronisez le code avant de publier.")
    # A previous failed push can be retried only if its local commits changed
    # encrypted generated files. Never publish an unrelated source commit.
    if any(not generated(path) for path in names(repo, "diff", "--name-only", remote_ref + "..HEAD")):
        raise vault.VaultError("Des commits locaux de code attendent une publication manuelle.")


def publish(repo: pathlib.Path, bundle: pathlib.Path, password: str, repository: str = DEFAULT_REPOSITORY,
            branch: str = "main", prepare_only: bool = False, retain_days: int = 14):
    repo = repo.resolve()
    if not prepare_only:
        verify_repository(repo, repository, branch)
    result = vault.prepare_vault(bundle, repo / "public", password, retain_days)
    if prepare_only:
        return {**result, "preparedOnly": True}
    # Only the ciphertext directory and the nonsecret format header are staged.
    git(repo, "add", "--", "public/vault.json", "public/data")
    staged = names(repo, "diff", "--cached", "--name-only")
    if not staged or any(not generated(path) for path in staged):
        raise vault.VaultError("La liste des fichiers à publier n’est pas celle attendue.")
    git(repo, "commit", "-m", "Update encrypted classroom day " + result["date"])
    git(repo, "push", "origin", "HEAD:refs/heads/" + branch)
    commit = git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    remote = git(repo, "ls-remote", "--exit-code", "origin", "refs/heads/" + branch).stdout.decode().split()
    if not remote or remote[0] != commit:
        raise vault.VaultError("La relecture du commit distant a échoué.")
    return {**result, "preparedOnly": False, "pushed": True, "commit": commit,
            "deploymentPending": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=pathlib.Path, default=ROOT)
    parser.add_argument("--bundle", type=pathlib.Path, required=True)
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    parser.add_argument("--branch", default="main")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--keychain-helper", type=pathlib.Path)
    parser.add_argument("--retain-days", type=int, default=14)
    args = parser.parse_args()
    private = args.repo / ".private"
    private.mkdir(parents=True, exist_ok=True)
    try:
        with (private / "publish.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise vault.VaultError("Une publication locale est déjà en cours.") from None
            helper = args.keychain_helper or args.repo / ".private" / "keychain-helper"
            result = publish(args.repo, args.bundle, vault.keychain_password(helper), args.repository,
                             args.branch, args.prepare_only, args.retain_days)
            print(json.dumps(result, ensure_ascii=False))
        return 0
    except (vault.VaultError, OSError, ValueError, TypeError, KeyError) as error:
        print("Publication impossible : " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
