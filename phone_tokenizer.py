#!/usr/bin/env python3
"""Irreversibly depersonalize sensitive values in JSON and XML files."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import string
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


TOKEN_ALPHABET = string.ascii_uppercase
TOKEN_LENGTH = 20
REPEATED_DIGIT_KINDS = {
    "phone",
    "inn",
    "kpp",
    "account",
    "passport_series",
    "passport_number",
    "ogrn",
    "card_number",
}
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
DEFAULT_PASSPORT_SERIES_KEYS = ("passport_series", "passportSeries")
DEFAULT_PASSPORT_NUMBER_KEYS = ("passport_number", "passportNumber")
DEFAULT_OGRN_KEYS = ("ogrn", "ogrn_number", "ogrnNumber")
DEFAULT_CARD_NUMBER_KEYS = ("cardNumber", "card_number")
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
    "passport_series": "PASSPORT_SERIES_",
    "passport_number": "PASSPORT_NUMBER_",
    "ogrn": "OGRN_",
    "card_number": "CARD_",
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
    if kind in ("passport_series", "passport_number", "ogrn", "card_number"):
        normalized = re.sub(r"[\s-]", "", str(value))
        patterns = {
            "passport_series": r"\d{4}",
            "passport_number": r"\d{6}",
            "ogrn": r"\d{13}",
            "card_number": r"\d{13,19}",
        }
        return normalized if re.fullmatch(patterns[kind], normalized) else None
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


def get_or_create_token(
    kind: str, canonical: str, tokens_by_value: dict[str, str]
) -> str:
    registry_key = f"{kind}:{canonical}"
    token = tokens_by_value.get(registry_key)
    if token is None:
        if kind in REPEATED_DIGIT_KINDS:
            token = secrets.choice(string.digits)
        else:
            token = new_token(kind, set(tokens_by_value.values()))
        tokens_by_value[registry_key] = token
    return token


def mask_structured_value(
    kind: str, value: Any, tokens_by_value: dict[str, str]
) -> str | None:
    canonical = normalize_sensitive_value(kind, value)
    if canonical is None:
        return None
    token = get_or_create_token(kind, canonical, tokens_by_value)
    if kind in REPEATED_DIGIT_KINDS:
        return token * len(str(value))
    return token


def mask_embedded_text(
    value: str, tokens_by_value: dict[str, str]
) -> tuple[str, int]:
    match_count = 0

    def replace_email(match: re.Match[str]) -> str:
        nonlocal match_count
        email = match.group(0)
        domain = email.rsplit("@", 1)[1].casefold()
        kind = "bank_email" if domain == "int.gazprombank.ru" else "email"
        match_count += 1
        return get_or_create_token(kind, email.casefold(), tokens_by_value)

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
        return "127.0.0.1"

    def replace_user(match: re.Match[str]) -> str:
        nonlocal match_count
        login = match.group(0)
        match_count += 1
        return get_or_create_token("user", login.casefold(), tokens_by_value)

    masked = EMAIL_PATTERN.sub(replace_email, value)
    masked = IPV4_PATTERN.sub(replace_ip, masked)
    masked = GPBU_LOGIN_PATTERN.sub(replace_user, masked)
    return masked, match_count


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
) -> int:
    """Replace configured sensitive fields irreversibly."""
    replacements = 0

    def replace_value(value: Any, pointer: list[str | int], kind: str) -> Any:
        nonlocal replacements

        if isinstance(value, list):
            return [
                replace_value(item, pointer + [index], kind)
                for index, item in enumerate(value)
            ]

        masked = mask_structured_value(kind, value, tokens_by_value)
        if masked is None:
            return value

        replacements += 1
        return masked

    def replace_embedded(value: str, pointer: list[str | int]) -> str:
        nonlocal replacements
        masked, match_count = mask_embedded_text(value, tokens_by_value)
        if masked != value:
            replacements += match_count
        return masked

    def walk(value: Any, pointer: list[str | int]) -> Any:
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            document_type = str(value.get("type", "")).casefold()
            parent_key = str(pointer[-1]).casefold() if pointer else ""
            is_passport = document_type in {
                "passport",
                "passport_rf",
                "russian_passport",
            } or parent_key in {"passport", "passport_data"}
            for key, child in value.items():
                child_pointer = pointer + [key]
                kind = field_types.get(key.casefold())
                if is_passport and key.casefold() == "series":
                    kind = "passport_series"
                elif is_passport and key.casefold() == "number":
                    kind = "passport_number"
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


def xml_local_name(name: Any) -> str:
    if not isinstance(name, str):
        return ""
    return name.rsplit("}", 1)[-1].casefold()


def parse_xml_document(source: str, path: Path | None = None) -> ET.Element:
    if re.search(r"<!DOCTYPE", source, re.IGNORECASE):
        location = f" in {path}" if path else ""
        raise TokenizerError(f"XML documents with DOCTYPE are not supported{location}")

    for prefix, uri in re.findall(
        r"""\sxmlns(?::([A-Za-z_][\w.-]*))?=["']([^"']+)["']""", source
    ):
        try:
            ET.register_namespace(prefix or "", uri)
        except ValueError:
            pass

    parser = ET.XMLParser(
        target=ET.TreeBuilder(insert_comments=True, insert_pis=True)
    )
    try:
        return ET.fromstring(source, parser=parser)
    except ET.ParseError as error:
        location = f" in {path}" if path else ""
        raise TokenizerError(f"Invalid XML{location}: {error}") from error


def serialize_xml(document: ET.Element, source: str) -> str:
    body = ET.tostring(document, encoding="unicode", short_empty_elements=True)
    declaration = re.match(r"\s*(<\?xml[^>]+\?>)(?:\r?\n)?", source)
    prefix = declaration.group(1) + "\n" if declaration else ""
    trailing_newline = "\n" if source.endswith("\n") else ""
    return prefix + body + trailing_newline


def transform_xml_document(
    document: ET.Element,
    field_types: dict[str, str],
    tokens_by_value: dict[str, str],
) -> int:
    replacements = 0

    def replace_structured(
        value: str,
        pointer: list[int],
        slot: str,
        kind: str,
        attribute: str | None = None,
    ) -> str:
        nonlocal replacements
        masked = mask_structured_value(kind, value, tokens_by_value)
        if masked is None:
            return value
        replacements += 1
        return masked

    def replace_embedded(
        value: str,
        pointer: list[int],
        slot: str,
        attribute: str | None = None,
    ) -> str:
        nonlocal replacements
        masked, count = mask_embedded_text(value, tokens_by_value)
        if masked != value:
            replacements += count
        return masked

    def walk(
        element: ET.Element,
        pointer: list[int],
        forced_kind: str | None = None,
    ) -> None:
        document_type = ""
        for attribute_name, attribute_value in element.attrib.items():
            if xml_local_name(attribute_name) == "type":
                document_type = attribute_value.casefold()
                break
        if not document_type:
            for child in element:
                if xml_local_name(child.tag) == "type" and child.text:
                    document_type = child.text.strip().casefold()
                    break

        element_name = xml_local_name(element.tag)
        is_passport = document_type in {
            "passport",
            "passport_rf",
            "russian_passport",
        } or element_name in {"passport", "passport_data"}

        for attribute_name, attribute_value in list(element.attrib.items()):
            attribute_local_name = xml_local_name(attribute_name)
            kind = field_types.get(attribute_local_name)
            if is_passport and attribute_local_name == "series":
                kind = "passport_series"
            elif is_passport and attribute_local_name == "number":
                kind = "passport_number"
            if kind:
                element.attrib[attribute_name] = replace_structured(
                    attribute_value,
                    pointer,
                    "attribute",
                    kind,
                    attribute=attribute_name,
                )
            else:
                element.attrib[attribute_name] = replace_embedded(
                    attribute_value,
                    pointer,
                    "attribute",
                    attribute=attribute_name,
                )

        kind = forced_kind or field_types.get(element_name)
        if element.text is not None:
            if kind:
                element.text = replace_structured(
                    element.text, pointer, "text", kind
                )
            else:
                element.text = replace_embedded(element.text, pointer, "text")

        for index, child in enumerate(element):
            child_name = xml_local_name(child.tag)
            child_kind = None
            if is_passport and child_name == "series":
                child_kind = "passport_series"
            elif is_passport and child_name == "number":
                child_kind = "passport_number"
            walk(child, pointer + [index], forced_kind=child_kind)
            if child.tail is not None:
                child.tail = replace_embedded(
                    child.tail, pointer + [index], "tail"
                )

    walk(document, [])
    return replacements


def iter_data_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if (
            path.suffix.casefold() in {".json", ".xml"}
            and ".git" not in path.parts
            and path.is_file()
            and not path.is_symlink()
        ):
            yield path


def prepare_masking(
    roots: list[Path],
    phone_keys: set[str] | None = None,
    field_types: dict[str, str] | None = None,
) -> tuple[list[PreparedFile], int]:
    if field_types is None:
        field_types = {key.casefold(): "phone" for key in (phone_keys or set())}
    tokens_by_value: dict[str, str] = {}
    prepared: list[PreparedFile] = []
    replacement_count = 0

    for root in roots:
        for path in iter_data_files(root):
            source = path.read_text(encoding="utf-8")
            if path.suffix.casefold() == ".json":
                try:
                    document = json.loads(source)
                except json.JSONDecodeError as error:
                    raise TokenizerError(f"Invalid JSON in {path}: {error}") from error
                count = transform_document(
                    document=document,
                    field_types=field_types,
                    tokens_by_value=tokens_by_value,
                )
                serialized = serialize_json(document, source)
            else:
                document = parse_xml_document(source, path)
                count = transform_xml_document(
                    document=document,
                    field_types=field_types,
                    tokens_by_value=tokens_by_value,
                )
                serialized = serialize_xml(document, source)
            if count:
                prepared.append(PreparedFile(path, serialized))
                replacement_count += count

    return prepared, replacement_count


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


def existing_directory(value: str) -> Path:
    path = Path(value).resolve()
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"Not a directory: {value}")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Irreversibly depersonalize sensitive JSON/XML values"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    mask = subparsers.add_parser(
        "mask", help="Mask sensitive values in one or more repositories"
    )
    mask.add_argument("roots", nargs="+", type=existing_directory)
    mask.add_argument(
        "--phone-keys",
        default=",".join(DEFAULT_PHONE_KEYS),
        help="Comma-separated JSON/XML field names",
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
        "--passport-series-keys",
        default=",".join(DEFAULT_PASSPORT_SERIES_KEYS),
        help="Comma-separated passport series field names",
    )
    mask.add_argument(
        "--passport-number-keys",
        default=",".join(DEFAULT_PASSPORT_NUMBER_KEYS),
        help="Comma-separated passport number field names",
    )
    mask.add_argument(
        "--ogrn-keys",
        default=",".join(DEFAULT_OGRN_KEYS),
        help="Comma-separated OGRN field names",
    )
    mask.add_argument(
        "--card-number-keys",
        default=",".join(DEFAULT_CARD_NUMBER_KEYS),
        help="Comma-separated payment card number field names",
    )
    mask.add_argument(
        "--dry-run", action="store_true", help="Report replacements without writing files"
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        field_types: dict[str, str] = {}
        for kind, raw_keys in (
            ("phone", args.phone_keys),
            ("inn", args.inn_keys),
            ("kpp", args.kpp_keys),
            ("fio", args.fio_keys),
            ("account", args.account_keys),
            ("passport_series", args.passport_series_keys),
            ("passport_number", args.passport_number_keys),
            ("ogrn", args.ogrn_keys),
            ("card_number", args.card_number_keys),
        ):
            for key in raw_keys.split(","):
                if key.strip():
                    field_types[key.strip().casefold()] = kind
        if not field_types:
            raise TokenizerError("At least one sensitive field key is required")

        prepared, count = prepare_masking(args.roots, field_types=field_types)
        if args.dry_run:
            print(
                f"Would replace {count} sensitive value(s) "
                f"in {len(prepared)} file(s)"
            )
            return 0

        write_prepared_files(prepared)
        print(f"Replaced {count} sensitive value(s) in {len(prepared)} file(s)")
        return 0
    except (OSError, KeyError, IndexError, TypeError, TokenizerError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
