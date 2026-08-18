#!/usr/bin/env python3
"""Tokenize sensitive values in JSON files and encrypt the restore manifest."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


TOKEN_ALPHABET = string.ascii_uppercase
TOKEN_LENGTH = 20
DEFAULT_PHONE_KEYS = ("phone", "phoneNumber", "mobilePhone", "msisdn")
DEFAULT_INN_KEYS = ("inn", "tax_id")
DEFAULT_KPP_KEYS = ("kpp",)
DEFAULT_FIO_KEYS = ("last_name", "first_name", "middle_name", "full_name", "fio")
DEFAULT_ACCOUNT_KEYS = (
    "account",
    "accountNumber",
    "account_number",
    "beneficiaryAccount",
    "payerAccount",
    "recipientAccount",
)
TOKEN_PREFIXES = {
    "phone": "PHONE_",
    "inn": "INN_",
    "kpp": "KPP_",
    "fio": "FIO_",
    "account": "ACCOUNT_",
    "bank_email": "BANK_EMAIL_",
    "email": "EMAIL_",
    "ip": "IP_",
    "user": "USER_",
}
EMAIL_PATTERN = re.compile(
    r"(?<![\w.+-])"
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+"
    r"(?![\w.-])",
    re.IGNORECASE,
)
IPV4_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
GPBU_LOGIN_PATTERN = re.compile(
    r"(?<![A-Z0-9_.-])GPBU[A-Z0-9](?:[A-Z0-9_.-]*[A-Z0-9])?"
    r"(?![A-Z0-9_-])",
    re.IGNORECASE,
)
PRIVATE_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class TokenizerError(RuntimeError):
    """Raised when tokenization or restoration cannot be completed safely."""


@dataclass
class PreparedFile:
    path: Path
    content: str


def normalize_phone(value: Any) -> str | None:
    """Return a canonical Russian phone number or None for non-phone values."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None

    digits = re.sub(r"\D", "", str(value))
    if len(digits) == 10 and digits.startswith("9"):
        digits = "7" + digits
    elif len(digits) == 11 and digits.startswith("8"):
        digits = "7" + digits[1:]

    if len(digits) != 11 or not digits.startswith("7"):
        return None
    return "+" + digits


def normalize_sensitive_value(kind: str, value: Any) -> str | None:
    if isinstance(value, str) and re.fullmatch(
        rf"{re.escape(TOKEN_PREFIXES[kind])}[A-Z]{{{TOKEN_LENGTH}}}", value
    ):
        return None
    if kind == "phone":
        return normalize_phone(value)
    if kind == "fio":
        if not isinstance(value, str) or not value.strip():
            return None
        return " ".join(value.split()).casefold()
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    normalized = re.sub(r"\s", "", str(value)).casefold()
    if kind == "inn" and not re.fullmatch(r"\d{10}|\d{12}", normalized):
        return None
    if kind == "kpp" and not re.fullmatch(r"[0-9a-zа-я]{9}", normalized):
        return None
    if kind == "account" and not re.fullmatch(r"\d{20}", normalized):
        return None
    return normalized


def new_token(kind: str, used_tokens: set[str]) -> str:
    while True:
        suffix = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(TOKEN_LENGTH))
        token = TOKEN_PREFIXES[kind] + suffix
        if token not in used_tokens:
            return token


def pointer_get(document: Any, pointer: list[str | int]) -> Any:
    current = document
    for part in pointer:
        current = current[part]
    return current


def pointer_set(document: Any, pointer: list[str | int], value: Any) -> None:
    if not pointer:
        raise TokenizerError("Replacing the JSON document root is not supported")
    parent = pointer_get(document, pointer[:-1])
    parent[pointer[-1]] = value


def detect_indent(source: str) -> int:
    match = re.search(r"\n( +)\S", source)
    return len(match.group(1)) if match else 2


def serialize_json(document: Any, source: str) -> str:
    trailing_newline = "\n" if source.endswith("\n") else ""
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            indent=detect_indent(source),
            allow_nan=False,
        )
        + trailing_newline
    )


def transform_document(
    document: Any,
    field_types: dict[str, str],
    tokens_by_value: dict[str, str],
    occurrences: list[dict[str, Any]],
    root_index: int,
    relative_file: str,
) -> int:
    """Replace configured sensitive fields and append exact restore locations."""
    used_tokens = set(tokens_by_value.values())
    replacements = 0

    def token_for(kind: str, canonical: str) -> str:
        registry_key = f"{kind}:{canonical}"
        token = tokens_by_value.get(registry_key)
        if token is None:
            token = new_token(kind, used_tokens)
            used_tokens.add(token)
            tokens_by_value[registry_key] = token
        return token

    def record_occurrence(
        pointer: list[str | int],
        kind: str,
        original: Any,
        token: Any,
        count: int = 1,
    ) -> None:
        occurrences.append(
            {
                "root": root_index,
                "file": relative_file,
                "pointer": pointer,
                "kind": kind,
                "original": original,
                "token": token,
                "count": count,
            }
        )

    def replace_value(value: Any, pointer: list[str | int], kind: str) -> Any:
        nonlocal replacements

        if isinstance(value, list):
            return [
                replace_value(item, pointer + [index], kind)
                for index, item in enumerate(value)
            ]

        canonical = normalize_sensitive_value(kind, value)
        if canonical is None:
            return value

        token = token_for(kind, canonical)
        record_occurrence(pointer, kind, value, token)
        replacements += 1
        return token

    def replace_embedded(value: str, pointer: list[str | int]) -> str:
        nonlocal replacements
        original = value
        match_count = 0

        def replace_email(match: re.Match[str]) -> str:
            nonlocal match_count
            email = match.group(0)
            domain = email.rsplit("@", 1)[1].casefold()
            kind = "bank_email" if domain == "int.gazprombank.ru" else "email"
            match_count += 1
            return token_for(kind, email.casefold())

        def replace_ip(match: re.Match[str]) -> str:
            nonlocal match_count
            candidate = match.group(0)
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                return candidate
            if not any(address in network for network in PRIVATE_IPV4_NETWORKS):
                return candidate
            match_count += 1
            return token_for("ip", str(address))

        def replace_user(match: re.Match[str]) -> str:
            nonlocal match_count
            login = match.group(0)
            match_count += 1
            return token_for("user", login.casefold())

        masked = EMAIL_PATTERN.sub(replace_email, value)
        masked = IPV4_PATTERN.sub(replace_ip, masked)
        masked = GPBU_LOGIN_PATTERN.sub(replace_user, masked)
        if masked != original:
            record_occurrence(
                pointer, "embedded", original, masked, count=match_count
            )
            replacements += match_count
        return masked

    def walk(value: Any, pointer: list[str | int]) -> Any:
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key, child in value.items():
                child_pointer = pointer + [key]
                kind = field_types.get(key.casefold())
                if kind:
                    result[key] = replace_value(child, child_pointer, kind)
                else:
                    result[key] = walk(child, child_pointer)
            return result
        if isinstance(value, list):
            return [walk(item, pointer + [index]) for index, item in enumerate(value)]
        if isinstance(value, str):
            return replace_embedded(value, pointer)
        return value

    transformed = walk(document, [])
    if isinstance(document, dict):
        document.clear()
        document.update(transformed)
    elif isinstance(document, list):
        document[:] = transformed
    return replacements


def iter_json_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*.json")):
        if ".git" not in path.parts and path.is_file() and not path.is_symlink():
            yield path


def prepare_masking(
    roots: list[Path],
    phone_keys: set[str] | None = None,
    field_types: dict[str, str] | None = None,
) -> tuple[list[PreparedFile], dict[str, Any], int]:
    if field_types is None:
        field_types = {key.casefold(): "phone" for key in (phone_keys or set())}
    tokens_by_value: dict[str, str] = {}
    occurrences: list[dict[str, Any]] = []
    prepared: list[PreparedFile] = []
    replacement_count = 0

    for root_index, root in enumerate(roots):
        for path in iter_json_files(root):
            source = path.read_text(encoding="utf-8")
            try:
                document = json.loads(source)
            except json.JSONDecodeError as error:
                raise TokenizerError(f"Invalid JSON in {path}: {error}") from error

            count = transform_document(
                document=document,
                field_types=field_types,
                tokens_by_value=tokens_by_value,
                occurrences=occurrences,
                root_index=root_index,
                relative_file=path.relative_to(root).as_posix(),
            )
            if count:
                prepared.append(PreparedFile(path, serialize_json(document, source)))
                replacement_count += count

    manifest = {
        "version": 3,
        "roots": [root.name for root in roots],
        "fields": dict(sorted(field_types.items())),
        "tokens": tokens_by_value,
        "occurrences": occurrences,
    }
    return prepared, manifest, replacement_count


def run_age(arguments: list[str], input_data: bytes | None = None) -> bytes:
    if shutil.which("age") is None:
        raise TokenizerError("The 'age' executable was not found in PATH")
    try:
        process = subprocess.run(
            ["age", *arguments],
            input=input_data,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        message = error.stderr.decode("utf-8", errors="replace").strip()
        raise TokenizerError(f"age failed: {message}") from error
    return process.stdout


def encrypt_manifest(
    manifest: dict[str, Any], recipient_file: Path, output_file: Path
) -> None:
    if output_file.exists():
        raise TokenizerError(f"Refusing to overwrite existing {output_file}")
    payload = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
    run_age(["-R", str(recipient_file), "-o", str(output_file)], payload)


def decrypt_manifest(identity_file: Path, encrypted_file: Path) -> dict[str, Any]:
    payload = run_age(["-d", "-i", str(identity_file), str(encrypted_file)])
    try:
        manifest = json.loads(payload)
    except json.JSONDecodeError as error:
        raise TokenizerError("The decrypted manifest is not valid JSON") from error
    if manifest.get("version") not in (1, 2, 3):
        raise TokenizerError("Unsupported manifest version")
    return manifest


def atomic_write(path: Path, content: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def write_prepared_files(prepared: list[PreparedFile]) -> None:
    for item in prepared:
        atomic_write(item.path, item.content)


def prepare_restoration(
    roots: list[Path], manifest: dict[str, Any]
) -> tuple[list[PreparedFile], int]:
    expected_roots = manifest.get("roots")
    actual_roots = [root.name for root in roots]
    if expected_roots != actual_roots:
        raise TokenizerError(
            f"Root order/name mismatch: expected {expected_roots}, got {actual_roots}"
        )

    grouped: dict[tuple[int, str], list[dict[str, Any]]] = defaultdict(list)
    for occurrence in manifest.get("occurrences", []):
        grouped[(occurrence["root"], occurrence["file"])].append(occurrence)

    prepared: list[PreparedFile] = []
    restored_count = 0
    for (root_index, relative_file), occurrences in grouped.items():
        path = roots[root_index] / relative_file
        source = path.read_text(encoding="utf-8")
        document = json.loads(source)

        for occurrence in occurrences:
            pointer = occurrence["pointer"]
            current = pointer_get(document, pointer)
            if current == occurrence["original"]:
                continue
            if current != occurrence["token"]:
                raise TokenizerError(
                    f"Unexpected value at {path}:{pointer}; refusing to overwrite it"
                )
            pointer_set(document, pointer, occurrence["original"])
            restored_count += occurrence.get("count", 1)

        prepared.append(PreparedFile(path, serialize_json(document, source)))

    return prepared, restored_count


def existing_directory(value: str) -> Path:
    path = Path(value).resolve()
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"Not a directory: {value}")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Tokenize sensitive JSON fields and encrypt the restore manifest"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    mask = subparsers.add_parser(
        "mask", help="Mask sensitive values in one or more repositories"
    )
    mask.add_argument("roots", nargs="+", type=existing_directory)
    mask.add_argument("--recipient-file", required=True, type=Path)
    mask.add_argument("--mapping", required=True, type=Path)
    mask.add_argument(
        "--phone-keys",
        default=",".join(DEFAULT_PHONE_KEYS),
        help="Comma-separated JSON field names",
    )
    mask.add_argument(
        "--inn-keys",
        default=",".join(DEFAULT_INN_KEYS),
        help="Comma-separated INN field names",
    )
    mask.add_argument(
        "--kpp-keys",
        default=",".join(DEFAULT_KPP_KEYS),
        help="Comma-separated KPP field names",
    )
    mask.add_argument(
        "--fio-keys",
        default=",".join(DEFAULT_FIO_KEYS),
        help="Comma-separated FIO field names",
    )
    mask.add_argument(
        "--account-keys",
        default=",".join(DEFAULT_ACCOUNT_KEYS),
        help="Comma-separated bank account field names",
    )
    mask.add_argument(
        "--dry-run", action="store_true", help="Report replacements without writing files"
    )

    restore = subparsers.add_parser(
        "restore", help="Restore original sensitive values"
    )
    restore.add_argument("roots", nargs="+", type=existing_directory)
    restore.add_argument("--identity-file", required=True, type=Path)
    restore.add_argument("--mapping", required=True, type=Path)
    restore.add_argument(
        "--dry-run", action="store_true", help="Validate without writing files"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "mask":
            field_types: dict[str, str] = {}
            for kind, raw_keys in (
                ("phone", args.phone_keys),
                ("inn", args.inn_keys),
                ("kpp", args.kpp_keys),
                ("fio", args.fio_keys),
                ("account", args.account_keys),
            ):
                for key in raw_keys.split(","):
                    if key.strip():
                        field_types[key.strip().casefold()] = kind
            if not field_types:
                raise TokenizerError("At least one sensitive field key is required")

            prepared, manifest, count = prepare_masking(
                args.roots, field_types=field_types
            )
            if args.dry_run:
                print(
                    f"Would replace {count} sensitive value(s) "
                    f"in {len(prepared)} file(s)"
                )
                return 0

            encrypt_manifest(manifest, args.recipient_file, args.mapping)
            write_prepared_files(prepared)
            print(f"Replaced {count} sensitive value(s) in {len(prepared)} file(s)")
            print(f"Encrypted restore manifest: {args.mapping}")
            return 0

        manifest = decrypt_manifest(args.identity_file, args.mapping)
        prepared, count = prepare_restoration(args.roots, manifest)
        if not args.dry_run:
            write_prepared_files(prepared)
        verb = "Would restore" if args.dry_run else "Restored"
        print(f"{verb} {count} sensitive value(s) in {len(prepared)} file(s)")
        return 0
    except (OSError, KeyError, IndexError, TypeError, TokenizerError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
