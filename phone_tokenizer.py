#!/usr/bin/env python3
"""Irreversibly depersonalize sensitive values in JSON, XML, and SQL files."""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import stat
import string
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Literal


SUPPORTED_SUFFIXES = {".json", ".xml", ".sql", ".java"}
IGNORED_DIRECTORIES = {".git", ".idea", "unimock-dictionaries"}
TOKEN_ALPHABET = string.ascii_uppercase
TOKEN_LENGTH = 20
LOGGER = logging.getLogger(__name__)
REPEATED_DIGIT_KINDS = {
    "phone",
    "inn",
    "kpp",
    "account",
    "passport_series",
    "passport_number",
    "ogrn",
    "card_number",
    "organization",
    "address",
    "fio",
    "orgCode",
    "orgName",
    "okfs",
    "opfCode",
    "org",
}
DEFAULT_PHONE_KEYS = (
    "phone",
    "phoneNumber",
    "mobilePhone",
    "msisdn",
    "PhoneNumber",
    "cellPhone",
    "mainPhone",
    "DealerPhone",
    "office_phone",
)
DEFAULT_INN_KEYS = ("inn", "tax_id")
DEFAULT_KPP_KEYS = ("kpp",)
DEFAULT_FIO_KEYS = (
    "signerFio",
    "last_name",
    "first_name",
    "middle_name",
    "full_name",
    "fio",
    "lastName",
    "firstName",
    "middleName",
    "patronymic",
    "name",
    "surname",
    "employeeName",
    "changeEmployeeName",
    "shortName",
    "fullName",
    "shortName",
    "chiefName",
    "chiefPosition",
    "office_user_name",
)
DEFAULT_ACCOUNT_KEYS = (
    "account",
    "accountNum",
    "accountNumber",
    "account_number",
    "beneficiaryAccount",
    "payerAccount",
    "recipientAccount",
    "applicationNum",
    "clientNum",
    "applicationNumber",
    "appNum",
    "appNums",
    "appId",
    "esflId",
    "appSequence",
    "businessKey",
    "accNumber",
    "cardAppSequence",
    "appIkarNumber",
    "cardNumberOut",
    "snils",
    "number",
    "guid",
    "applicationSeq",
    "Key",
    "corr_acc",
    "directorate_cardoffice_id",
    "instance_5nt_database_link",
    "OfficeCode",
    "database_link",
    "result",
)
DEFAULT_PASSPORT_SERIES_KEYS = (
    "passport_series",
    "passportSeries",
    "passportSeria",
    "series",
    "docSeries",
)
DEFAULT_PASSPORT_NUMBER_KEYS = (
    "passport_number",
    "passportNumber",
    "passportId",
    "docNum",
    "birthday",
    "birth_day",
    "birthDay",
    "birth",
    "departCode",
)
DEFAULT_OGRN_KEYS = ("ogrn", "ogrn_number", "ogrnNumber")
DEFAULT_CARD_NUMBER_KEYS = ("cardNumber", "card_number")
DEFAULT_ORGANIZATION_KEYS = (
    "organization",
    "organizationName",
    "organizationFullName",
    "organisationName",
    "company",
    "companyName",
    "employer",
    "employerName",
    "employer_name",
    "legalName",
    "legal_name",
    "issuedBy",
    "userFullName",
    "fiveNtContractNumber",
    "employee_name",
    "contractNum",
    "branch_short_name",
    "directorate_name",
    "DealerCenterName",
    "office_short_name",
    "court_name",
    "FullCompanyName",
    "Court",
)
DEFAULT_ADDRESS_KEYS = (
    "address",
    "rawSource",
    "cityArea",
    "registrationAddress",
    "registration_address",
    "legalAddress",
    "legal_address",
    "actualAddress",
    "actual_address",
    "postalAddress",
    "postal_address",
    "residentialAddress",
    "residential_address",
    "birth_place",
    "region",
    "streetName",
    "home",
    "building",
    "regionCode",
    "regionName",
    "postIndex",
    "regionType",
    "district",
    "streetType",
    "street",
    "house",
    "flat",
    "kladr",
    "orgName",
    "city",
    "country",
    "streat",
    "birthPlace",
    "legalAddress",
    "district",
    "countryName",
    "changeEmloyeeLogin",
    "employeeLogin",
    "fioAR",
    "issuedBy",
    "adr",
    "Nnp",
    "Ind",
    "Rgn",
    "RegN",
    "branch_address",
    "street_with_type",
    "city_district",
    "fiascode",
    "address_name",
    "directorate_address",
    "CityName",
    "signing_address",
    "federal_district",
    "signing_place",
    "Locality",
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
    "passport_series": "PASSPORT_SERIES_",
    "passport_number": "PASSPORT_NUMBER_",
    "ogrn": "OGRN_",
    "card_number": "CARD_",
    "organization": "ORGANIZATION_",
    "address": "ADDRESS_",
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
RUSSIAN_PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:\+7|8)(?:[\s\-()]*\d){10}(?!\d)"
)
PRIVATE_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class TokenizerError(RuntimeError):
    """Raised when depersonalization cannot be completed safely."""


@dataclass
class PreparedFile:
    path: Path
    temporary_path: Path


@dataclass
class SqlToken:
    kind: str
    start: int
    end: int


SQL_TRIVIA_KINDS = {"whitespace", "line_comment", "block_comment"}


def tokenize_postgresql(source: str, path: Path | None = None) -> list[SqlToken]:
    tokens: list[SqlToken] = []
    index = 0
    length = len(source)

    def add(kind: str, start: int, end: int) -> None:
        tokens.append(SqlToken(kind, start, end))

    while index < length:
        start = index
        character = source[index]

        if character.isspace():
            index += 1
            while index < length and source[index].isspace():
                index += 1
            add("whitespace", start, index)
            continue

        if source.startswith("--", index):
            newline = source.find("\n", index + 2)
            index = length if newline == -1 else newline
            add("line_comment", start, index)
            continue

        if source.startswith("/*", index):
            depth = 1
            index += 2
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                raise TokenizerError(
                    f"Unterminated SQL comment{sql_location(source, start, path)}"
                )
            add("block_comment", start, index)
            continue

        if character == "'":
            escape_string = (
                start > 0
                and source[start - 1] in {"e", "E"}
                and (start == 1 or not source[start - 2].isalnum())
            )
            index += 1
            while index < length:
                if escape_string and source[index] == "\\":
                    index += 2
                    continue
                if source[index] != "'":
                    index += 1
                    continue
                if index + 1 < length and source[index + 1] == "'":
                    index += 2
                    continue
                index += 1
                break
            else:
                raise TokenizerError(
                    f"Unterminated SQL string{sql_location(source, start, path)}"
                )
            add("string", start, index)
            continue

        if character == '"':
            index += 1
            while index < length:
                if source[index] != '"':
                    index += 1
                    continue
                if index + 1 < length and source[index + 1] == '"':
                    index += 2
                    continue
                index += 1
                break
            else:
                raise TokenizerError(
                    f"Unterminated SQL identifier"
                    f"{sql_location(source, start, path)}"
                )
            add("quoted_identifier", start, index)
            continue

        if character == "[":
            index += 1
            while index < length:
                if source[index] != "]":
                    index += 1
                    continue
                if index + 1 < length and source[index + 1] == "]":
                    index += 2
                    continue
                index += 1
                break
            else:
                raise TokenizerError(
                    f"Unterminated bracketed SQL identifier"
                    f"{sql_location(source, start, path)}"
                )
            add("bracket_identifier", start, index)
            continue

        if character == "$":
            delimiter_match = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", source[index:])
            if delimiter_match:
                delimiter = delimiter_match.group(0)
                content_start = index + len(delimiter)
                close = source.find(delimiter, content_start)
                if close == -1:
                    raise TokenizerError(
                        f"Unterminated dollar-quoted SQL string"
                        f"{sql_location(source, start, path)}"
                    )
                index = close + len(delimiter)
                add("dollar_string", start, index)
                continue

        if character.isalpha() or character == "_" or ord(character) >= 128:
            index += 1
            while index < length and (
                source[index].isalnum()
                or source[index] in {"_", "$"}
                or ord(source[index]) >= 128
            ):
                index += 1
            add("word", start, index)
            continue

        if character.isdigit():
            index += 1
            while index < length and (source[index].isdigit() or source[index] == "."):
                index += 1
            add("number", start, index)
            continue

        index += 1
        add("symbol", start, index)

    return tokens


def sql_location(source: str, offset: int, path: Path | None) -> str:
    line = source.count("\n", 0, offset) + 1
    prefix = f" in {path}" if path else ""
    return f"{prefix} at line {line}"


def sql_token_text(source: str, token: SqlToken) -> str:
    return source[token.start : token.end]


def iter_postgresql_statements(stream: Any) -> Iterable[str]:
    parts: list[str] = []
    state = "normal"
    block_depth = 0
    dollar_delimiter = ""
    escape_string = False

    for line in stream:
        if state == "normal" and re.fullmatch(
            r"\s*GO(?:\s*--[^\r\n]*)?\s*(?:\r?\n)?", line, re.IGNORECASE
        ):
            parts.append(line)
            batch = "".join(parts)
            parts.clear()
            yield batch
            continue

        segment_start = 0
        index = 0
        while index < len(line):
            if state == "line_comment":
                newline = line.find("\n", index)
                if newline == -1:
                    index = len(line)
                    continue
                index = newline + 1
                state = "normal"
                continue

            if state == "block_comment":
                if line.startswith("/*", index):
                    block_depth += 1
                    index += 2
                elif line.startswith("*/", index):
                    block_depth -= 1
                    index += 2
                    if block_depth == 0:
                        state = "normal"
                else:
                    index += 1
                continue

            if state == "single_quote":
                if escape_string and line[index] == "\\":
                    index += 2
                elif line[index] != "'":
                    index += 1
                elif index + 1 < len(line) and line[index + 1] == "'":
                    index += 2
                else:
                    index += 1
                    state = "normal"
                continue

            if state == "double_quote":
                if line[index] != '"':
                    index += 1
                elif index + 1 < len(line) and line[index + 1] == '"':
                    index += 2
                else:
                    index += 1
                    state = "normal"
                continue

            if state == "dollar_quote":
                close = line.find(dollar_delimiter, index)
                if close == -1:
                    index = len(line)
                else:
                    index = close + len(dollar_delimiter)
                    state = "normal"
                continue

            if line.startswith("--", index):
                state = "line_comment"
                index += 2
                continue
            if line.startswith("/*", index):
                state = "block_comment"
                block_depth = 1
                index += 2
                continue
            if line[index] == "'":
                prefix = line[max(0, index - 2) : index]
                escape_string = (
                    prefix.endswith(("e", "E"))
                    and (len(prefix) == 1 or not prefix[-2].isalnum())
                )
                state = "single_quote"
                index += 1
                continue
            if line[index] == '"':
                state = "double_quote"
                index += 1
                continue
            if line[index] == "$":
                delimiter_match = re.match(
                    r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", line[index:]
                )
                if delimiter_match:
                    dollar_delimiter = delimiter_match.group(0)
                    state = "dollar_quote"
                    index += len(dollar_delimiter)
                    continue
            if line[index] == ";":
                parts.append(line[segment_start : index + 1])
                statement = "".join(parts)
                parts.clear()
                segment_start = index + 1
                yield statement
            index += 1

        if state == "line_comment":
            state = "normal"
        parts.append(line[segment_start:])

    if parts:
        trailing = "".join(parts)
        if trailing:
            yield trailing


def normalize_phone(value: Any) -> str | None:
    """Return a canonical Russian phone number or None for non-phone values."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None

    digits = re.sub(r"\D", "", str(value))
    if len(digits) == 10:
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
        canonical = normalize_phone(value)
        if canonical is not None:
            return canonical
        if isinstance(value, str) and value.strip():
            return " ".join(value.split()).casefold()
        return None
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
    if kind == "account":
        return normalized or None
    if kind == "inn" and not re.fullmatch(r"\d{10}|\d{12}", normalized):
        return None
    if kind == "kpp" and not re.fullmatch(r"[0-9a-zа-я]{9}", normalized):
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
        token = new_token(kind, set(tokens_by_value.values()))
        tokens_by_value[registry_key] = token
    return token


def mask_structured_value(
    kind: str, value: Any, tokens_by_value: dict[str, str]
) -> str | None:
    canonical = normalize_sensitive_value(kind, value)
    if canonical is None:
        return None
    if kind in REPEATED_DIGIT_KINDS:
        raw_value = str(value)
        first_symbol = next(
            (
                symbol
                for symbol in raw_value
                if symbol.isalnum() or (kind == "phone" and symbol == "+")
            ),
            None,
        )
        return first_symbol * len(raw_value) if first_symbol else None
    token = get_or_create_token(kind, canonical, tokens_by_value)
    return token


def mask_embedded_text(
    value: str, tokens_by_value: dict[str, str]
) -> tuple[str, int]:
    match_count = 0

    def replace_email(match: re.Match[str]) -> str:
        nonlocal match_count
        match_count += 1
        return ""

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

    def replace_phone(match: re.Match[str]) -> str:
        nonlocal match_count
        raw = match.group(0)
        first_symbol = next(
            (symbol for symbol in raw if symbol.isalnum() or symbol == "+"),
            None,
        )
        if first_symbol is None:
            return raw
        match_count += 1
        return first_symbol * len(raw)

    masked = EMAIL_PATTERN.sub(replace_email, value)
    masked = IPV4_PATTERN.sub(replace_ip, masked)
    masked = GPBU_LOGIN_PATTERN.sub(replace_user, masked)
    masked = RUSSIAN_PHONE_PATTERN.sub(replace_phone, masked)
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
        if isinstance(value, dict):
            return {
                key: replace_value(child, pointer + [key], kind)
                for key, child in value.items()
            }

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
            child_kind = kind
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


def next_sql_token(tokens: list[SqlToken], index: int) -> int | None:
    while index < len(tokens):
        if tokens[index].kind not in SQL_TRIVIA_KINDS:
            return index
        index += 1
    return None


def sql_word(source: str, token: SqlToken, value: str) -> bool:
    return token.kind == "word" and sql_token_text(
        source, token
    ).casefold() == value.casefold()


def matching_sql_parenthesis(
    source: str, tokens: list[SqlToken], opening: int
) -> int:
    depth = 0
    for index in range(opening, len(tokens)):
        token = tokens[index]
        if token.kind != "symbol":
            continue
        token_text = sql_token_text(source, token)
        if token_text == "(":
            depth += 1
        elif token_text == ")":
            depth -= 1
            if depth == 0:
                return index
    raise TokenizerError("Unbalanced parentheses in SQL INSERT")


def split_sql_expressions(
    source: str, tokens: list[SqlToken], start: int, end: int
) -> list[tuple[int, int]]:
    expressions: list[tuple[int, int]] = []
    expression_start = start
    depth = 0
    for index in range(start, end):
        token = tokens[index]
        if token.kind != "symbol":
            continue
        token_text = sql_token_text(source, token)
        if token_text == "(":
            depth += 1
        elif token_text == ")":
            depth -= 1
        elif token_text == "," and depth == 0:
            expressions.append((expression_start, index))
            expression_start = index + 1
    expressions.append((expression_start, end))
    return expressions


def decode_sql_identifier(source: str, token: SqlToken) -> str:
    token_text = sql_token_text(source, token)
    if token.kind == "quoted_identifier":
        return token_text[1:-1].replace('""', '"')
    if token.kind == "bracket_identifier":
        return token_text[1:-1].replace("]]", "]")
    return token_text


def decode_sql_literal(source: str, token: SqlToken) -> str:
    token_text = sql_token_text(source, token)
    if token.kind == "string":
        return token_text[1:-1].replace("''", "'")
    if token.kind == "dollar_string":
        delimiter_match = re.match(
            r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", token_text
        )
        if not delimiter_match:
            return token_text
        delimiter = delimiter_match.group(0)
        return token_text[len(delimiter) : -len(delimiter)]
    return token_text


def encode_sql_literal(source: str, token: SqlToken, value: str) -> str:
    if token.kind == "string":
        return "'" + value.replace("'", "''") + "'"
    if token.kind == "dollar_string":
        delimiter_match = re.match(
            r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$",
            sql_token_text(source, token),
        )
        delimiter = delimiter_match.group(0) if delimiter_match else "$$"
        return delimiter + value + delimiter
    return "'" + value.replace("'", "''") + "'"


def significant_sql_tokens(
    tokens: list[SqlToken], start: int, end: int
) -> list[int]:
    return [
        index
        for index in range(start, end)
        if tokens[index].kind not in SQL_TRIVIA_KINDS
    ]


def sql_statement_end(source: str, tokens: list[SqlToken], start: int) -> int:
    depth = 0
    for index in range(start, len(tokens)):
        token = tokens[index]
        if token.kind != "symbol":
            continue
        token_text = sql_token_text(source, token)
        if token_text == "(":
            depth += 1
        elif token_text == ")":
            depth = max(depth - 1, 0)
        elif token_text == ";" and depth == 0:
            return index
    return len(tokens)


def parse_insert_columns(
    source: str,
    path: Path,
    tokens: list[SqlToken],
    insert_index: int,
) -> tuple[list[str], int, int] | Literal["default_values", "missing_columns"]:
    into_index = next_sql_token(tokens, insert_index + 1)
    if into_index is None or not sql_word(source, tokens[into_index], "into"):
        raise TokenizerError(
            f"Unsupported INSERT syntax"
            f"{sql_location(source, tokens[insert_index].start, path)}"
        )

    statement_end = sql_statement_end(source, tokens, insert_index)
    index = next_sql_token(tokens, into_index + 1)
    opening = None
    while index is not None and index < statement_end:
        token = tokens[index]
        if token.kind == "symbol" and sql_token_text(source, token) == "(":
            opening = index
            break
        if sql_word(source, token, "values") or sql_word(source, token, "select"):
            break
        if sql_word(source, token, "default"):
            values_index = next_sql_token(tokens, index + 1)
            if values_index is not None and sql_word(
                source, tokens[values_index], "values"
            ):
                return "default_values"
        index = next_sql_token(tokens, index + 1)

    if opening is None:
        return "missing_columns"

    closing = matching_sql_parenthesis(source, tokens, opening)
    column_ranges = split_sql_expressions(source, tokens, opening + 1, closing)
    columns: list[str] = []
    for start, end in column_ranges:
        indexes = significant_sql_tokens(tokens, start, end)
        identifiers = [
            tokens[token_index]
            for token_index in indexes
            if tokens[token_index].kind
            in {"word", "quoted_identifier", "bracket_identifier"}
        ]
        if len(identifiers) != 1:
            raise TokenizerError(
                f"Unsupported target column syntax"
                f"{sql_location(source, tokens[start].start, path)}"
            )
        columns.append(
            decode_sql_identifier(source, identifiers[0]).casefold()
        )

    source_index = next_sql_token(tokens, closing + 1)
    depth = 0
    while source_index is not None and source_index < statement_end:
        token = tokens[source_index]
        if token.kind == "symbol":
            token_text = sql_token_text(source, token)
            if token_text == "(":
                depth += 1
            elif token_text == ")":
                depth = max(depth - 1, 0)
        elif depth == 0 and (
            sql_word(source, token, "values")
            or sql_word(source, token, "select")
        ):
            break
        source_index = next_sql_token(tokens, source_index + 1)
    if source_index is None or source_index >= statement_end:
        raise TokenizerError(
            f"INSERT source must use VALUES or SELECT"
            f"{sql_location(source, tokens[insert_index].start, path)}"
        )
    return columns, source_index, statement_end


def insert_expression_groups(
    source: str,
    path: Path,
    tokens: list[SqlToken],
    source_index: int,
    statement_end: int,
    column_count: int,
) -> list[list[tuple[int, int]]]:
    if sql_word(source, tokens[source_index], "values"):
        groups: list[list[tuple[int, int]]] = []
        index = next_sql_token(tokens, source_index + 1)
        while index is not None and index < statement_end:
            token = tokens[index]
            if sql_word(source, token, "on") or sql_word(
                source, token, "returning"
            ):
                break
            if token.kind == "symbol" and sql_token_text(source, token) == ",":
                index = next_sql_token(tokens, index + 1)
                continue
            if (
                token.kind != "symbol"
                or sql_token_text(source, token) != "("
            ):
                if groups:
                    break
                raise TokenizerError(
                    f"Unsupported INSERT VALUES syntax"
                    f"{sql_location(source, token.start, path)}"
                )
            closing = matching_sql_parenthesis(source, tokens, index)
            expressions = split_sql_expressions(
                source, tokens, index + 1, closing
            )
            if len(expressions) != column_count:
                raise TokenizerError(
                    f"INSERT has {column_count} target columns but "
                    f"{len(expressions)} VALUES expressions"
                    f"{sql_location(source, token.start, path)}"
                )
            groups.append(expressions)
            index = next_sql_token(tokens, closing + 1)
        return groups

    start = next_sql_token(tokens, source_index + 1)
    if start is None:
        return []
    if sql_word(source, tokens[start], "distinct") or sql_word(
        source, tokens[start], "all"
    ):
        start = next_sql_token(tokens, start + 1)
        if start is None:
            return []

    depth = 0
    case_depth = 0
    top_level_commas = 0
    previous_significant: SqlToken | None = None
    end = statement_end
    for index in range(start, statement_end):
        token = tokens[index]
        if token.kind in SQL_TRIVIA_KINDS:
            continue
        if token.kind == "symbol":
            token_text = sql_token_text(source, token)
            if token_text == "(":
                depth += 1
            elif token_text == ")":
                depth -= 1
            elif token_text == "," and depth == 0 and case_depth == 0:
                top_level_commas += 1
        elif depth == 0:
            if sql_word(source, token, "case"):
                case_depth += 1
            elif sql_word(source, token, "end") and case_depth:
                case_depth -= 1
            elif case_depth == 0 and (
                sql_word(source, token, "from")
                or sql_word(source, token, "union")
                or sql_word(source, token, "intersect")
                or sql_word(source, token, "except")
                or sql_word(source, token, "returning")
            ):
                end = index
                break
            elif (
                case_depth == 0
                and top_level_commas >= column_count - 1
                and previous_significant is not None
                and "\n"
                in source[previous_significant.end : token.start]
                and any(
                    sql_word(source, token, keyword)
                    for keyword in {
                        "insert",
                        "select",
                        "update",
                        "delete",
                        "merge",
                        "if",
                        "else",
                        "begin",
                        "end",
                        "set",
                        "declare",
                        "exec",
                        "execute",
                        "create",
                        "alter",
                        "drop",
                        "truncate",
                        "print",
                        "return",
                        "throw",
                        "raiserror",
                        "with",
                    }
                )
            ):
                end = index
                break
        previous_significant = token
    expressions = split_sql_expressions(source, tokens, start, end)
    if len(expressions) != column_count:
        has_literal = any(
            tokens[index].kind in {"string", "dollar_string", "number"}
            for expression_start, expression_end in expressions
            for index in range(expression_start, expression_end)
        )
        if has_literal:
            raise TokenizerError(
                f"Cannot map {len(expressions)} SELECT expressions to "
                f"{column_count} target columns"
                f"{sql_location(source, tokens[source_index].start, path)}"
            )
        return []
    return [expressions]


def transform_sql_document(
    source: str,
    path: Path,
    field_types: dict[str, str],
    tokens_by_value: dict[str, str],
    statement_start_line: int = 1,
) -> tuple[str, int]:
    tokens = tokenize_postgresql(source, path)
    replacements: dict[int, tuple[int, str]] = {}
    replacement_count = 0

    for insert_index, token in enumerate(tokens):
        if not sql_word(source, token, "insert"):
            continue
        into_index = next_sql_token(tokens, insert_index + 1)
        if into_index is None or not sql_word(
            source, tokens[into_index], "into"
        ):
            continue
        insert_columns = parse_insert_columns(
            source, path, tokens, insert_index
        )
        if insert_columns == "default_values":
            continue
        if insert_columns == "missing_columns":
            line = statement_start_line + source.count(
                "\n", 0, token.start
            )
            LOGGER.warning(
                "Skipping SQL INSERT without an explicit target column list "
                "in %s at line %d",
                path,
                line,
            )
            continue
        columns, source_index, statement_end = insert_columns
        groups = insert_expression_groups(
            source,
            path,
            tokens,
            source_index,
            statement_end,
            len(columns),
        )
        for expressions in groups:
            for column, (start, end) in zip(columns, expressions):
                kind = field_types.get(column)
                if kind is None:
                    continue
                literal_indexes = [
                    index
                    for index in range(start, end)
                    if tokens[index].kind in {"string", "dollar_string", "number"}
                ]
                for literal_index in literal_indexes:
                    literal = tokens[literal_index]
                    original = decode_sql_literal(source, literal)
                    masked = mask_structured_value(
                        kind, original, tokens_by_value
                    )
                    if masked is None:
                        continue
                    replacements[literal.start] = (
                        literal.end,
                        encode_sql_literal(source, literal, masked),
                    )
                    replacement_count += 1

    for token in tokens:
        if token.kind not in {"string", "dollar_string"}:
            continue
        if token.start in replacements:
            continue
        original = decode_sql_literal(source, token)
        masked, count = mask_embedded_text(original, tokens_by_value)
        if masked != original:
            replacements[token.start] = (
                token.end,
                encode_sql_literal(source, token, masked),
            )
            replacement_count += count

    if not replacements:
        return source, replacement_count

    parts: list[str] = []
    cursor = 0
    for start in sorted(replacements):
        end, replacement = replacements[start]
        parts.append(source[cursor:start])
        parts.append(replacement)
        cursor = end
    parts.append(source[cursor:])
    return "".join(parts), replacement_count


def snake_to_java_camel(key: str) -> str:
    parts = [part for part in key.split("_") if part]
    if not parts:
        return key
    first, *rest = parts
    camel = first[:1].lower() + first[1:]
    for part in rest:
        camel += part[:1].upper() + part[1:]
    return camel


def java_setter_name(field_name: str) -> str:
    if not field_name:
        return field_name
    return "set" + field_name[:1].upper() + field_name[1:]


def java_method_kinds(source_keys: dict[str, str]) -> dict[str, str]:
    methods: dict[str, str] = {}
    for key, kind in source_keys.items():
        names = {key, snake_to_java_camel(key)}
        for name in names:
            if not name:
                continue
            methods[name] = kind
            methods[java_setter_name(name)] = kind
            methods[name[:1].upper() + name[1:]] = kind
    return methods


def java_field_key_kinds(source_keys: dict[str, str]) -> dict[str, str]:
    kinds: dict[str, str] = {}
    for key, kind in source_keys.items():
        camel = snake_to_java_camel(key)
        for variant in (key, camel, key.casefold(), camel.casefold()):
            if variant:
                kinds[variant] = kind
    return kinds


def kind_for_java_key_literal(text: str, key_kinds: dict[str, str]) -> str | None:
    candidate = text.strip()
    if candidate.startswith("$."):
        candidate = candidate[2:]
    candidate = candidate.rsplit(".", 1)[-1]
    return key_kinds.get(candidate) or key_kinds.get(candidate.casefold())


def is_java_identifier_start(character: str) -> bool:
    return character.isalpha() or character == "_" or ord(character) > 127


def is_java_identifier_part(character: str) -> bool:
    return character.isalnum() or character in {"_", "$"} or ord(character) > 127


def skip_java_line_comment(source: str, index: int) -> int:
    newline = source.find("\n", index)
    return len(source) if newline == -1 else newline + 1


def skip_java_block_comment(source: str, index: int, path: Path | None) -> int:
    close = source.find("*/", index + 2)
    if close == -1:
        raise TokenizerError(
            f"Unterminated Java comment{sql_location(source, index, path)}"
        )
    return close + 2


def skip_java_string(source: str, index: int, path: Path | None) -> int:
    index += 1
    while index < len(source):
        character = source[index]
        if character == "\\":
            index += 2
            continue
        if character == '"':
            return index + 1
        if character == "\n":
            break
        index += 1
    raise TokenizerError(
        f"Unterminated Java string{sql_location(source, index, path)}"
    )


def skip_java_text_block(source: str, index: int, path: Path | None) -> int:
    close = source.find('"""', index + 3)
    if close == -1:
        raise TokenizerError(
            f"Unterminated Java text block{sql_location(source, index, path)}"
        )
    return close + 3


def skip_java_char(source: str, index: int, path: Path | None) -> int:
    index += 1
    while index < len(source):
        character = source[index]
        if character == "\\":
            index += 2
            continue
        if character == "'":
            return index + 1
        if character == "\n":
            break
        index += 1
    raise TokenizerError(
        f"Unterminated Java character literal{sql_location(source, index, path)}"
    )


def skip_java_whitespace_and_comments(
    source: str, index: int, path: Path | None
) -> int:
    length = len(source)
    while index < length:
        character = source[index]
        if character.isspace():
            index += 1
            continue
        if source.startswith("//", index):
            index = skip_java_line_comment(source, index)
            continue
        if source.startswith("/*", index):
            index = skip_java_block_comment(source, index, path)
            continue
        break
    return index


def decode_java_string(literal: str) -> str:
    inner = literal[1:-1]
    decoded: list[str] = []
    index = 0
    while index < len(inner):
        character = inner[index]
        if character != "\\":
            decoded.append(character)
            index += 1
            continue
        if index + 1 >= len(inner):
            break
        escape = inner[index + 1]
        escapes = {
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "\\": "\\",
            '"': '"',
            "'": "'",
        }
        if escape in escapes:
            decoded.append(escapes[escape])
            index += 2
            continue
        decoded.append(escape)
        index += 2
    return "".join(decoded)


def encode_java_string(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return '"' + escaped + '"'


def read_java_number(source: str, index: int) -> tuple[int, str, str]:
    start = index
    length = len(source)
    if source.startswith(("0x", "0X"), index):
        index += 2
        while index < length and (
            source[index] in string.hexdigits or source[index] == "_"
        ):
            index += 1
    else:
        while index < length and (source[index].isdigit() or source[index] in "._"):
            index += 1
    digits = source[start:index]
    suffix_start = index
    if index < length and source[index] in {"L", "l", "F", "f", "D", "d"}:
        index += 1
    return index, digits.replace("_", ""), source[suffix_start:index]


def mask_java_value(
    source: str,
    path: Path,
    index: int,
    kind: str,
    tokens_by_value: dict[str, str],
) -> tuple[int, dict[int, tuple[int, str]], int]:
    if index >= len(source):
        return index, {}, 0
    if source.startswith('"""', index):
        end = skip_java_text_block(source, index, path)
        original = source[index + 3 : end - 3]
        masked = mask_structured_value(kind, original, tokens_by_value)
        if masked is None:
            return end, {}, 0
        return end, {index: (end, encode_java_string(masked))}, 1
    if source[index] == '"':
        end = skip_java_string(source, index, path)
        original = decode_java_string(source[index:end])
        masked = mask_structured_value(kind, original, tokens_by_value)
        if masked is None:
            return end, {}, 0
        return end, {index: (end, encode_java_string(masked))}, 1
    if source[index].isdigit():
        end, digits, suffix = read_java_number(source, index)
        masked = mask_structured_value(kind, digits, tokens_by_value)
        if masked is None:
            return end, {}, 0
        replacement = (
            masked + suffix
            if re.fullmatch(r"-?\d+", masked)
            else encode_java_string(masked)
        )
        return end, {index: (end, replacement)}, 1
    return index, {}, 0


def mask_java_arguments(
    source: str,
    path: Path,
    open_paren: int,
    kind: str | None,
    tokens_by_value: dict[str, str],
    key_kinds: dict[str, str] | None = None,
) -> tuple[int, dict[int, tuple[int, str]], int]:
    replacements: dict[int, tuple[int, str]] = {}
    replacement_count = 0
    index = open_paren + 1
    depth = 1
    length = len(source)
    argument_kind = kind
    next_argument_kind: str | None = None
    key_kinds = key_kinds or {}

    while index < length and depth:
        if source.startswith("//", index):
            index = skip_java_line_comment(source, index)
            continue
        if source.startswith("/*", index):
            index = skip_java_block_comment(source, index, path)
            continue
        character = source[index]
        if character == "'":
            index = skip_java_char(source, index, path)
            continue
        if source.startswith('"""', index) or character == '"':
            is_text_block = source.startswith('"""', index)
            end = (
                skip_java_text_block(source, index, path)
                if is_text_block
                else skip_java_string(source, index, path)
            )
            original = (
                source[index + 3 : end - 3]
                if is_text_block
                else decode_java_string(source[index:end])
            )
            kind_to_use = kind if depth >= 1 and kind else None
            if depth == 1 and argument_kind:
                kind_to_use = argument_kind
            if kind_to_use:
                masked = mask_structured_value(
                    kind_to_use, original, tokens_by_value
                )
                if masked is not None:
                    replacements[index] = (end, encode_java_string(masked))
                    replacement_count += 1
            elif depth == 1:
                looked_up = kind_for_java_key_literal(original, key_kinds)
                if looked_up:
                    next_argument_kind = looked_up
            index = end
            continue
        if depth == 1 and character.isdigit():
            if argument_kind or kind:
                end, local_replacements, count = mask_java_value(
                    source,
                    path,
                    index,
                    argument_kind or kind,
                    tokens_by_value,
                )
                replacements.update(local_replacements)
                replacement_count += count
                index = end if end != index else index + 1
            else:
                index = read_java_number(source, index)[0]
            continue
        if character == ",":
            if depth == 1:
                argument_kind = next_argument_kind or kind
                next_argument_kind = None
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index + 1, replacements, replacement_count
        index += 1

    raise TokenizerError(
        f"Unterminated Java method call{sql_location(source, open_paren, path)}"
    )


def transform_java_document(
    source: str,
    path: Path,
    method_kinds: dict[str, str],
    tokens_by_value: dict[str, str],
    key_kinds: dict[str, str] | None = None,
) -> tuple[str, int]:
    replacements: dict[int, tuple[int, str]] = {}
    replacement_count = 0
    index = 0
    length = len(source)
    key_kinds = key_kinds or {}

    while index < length:
        if source.startswith("//", index):
            index = skip_java_line_comment(source, index)
            continue
        if source.startswith("/*", index):
            index = skip_java_block_comment(source, index, path)
            continue
        if source.startswith('"""', index):
            end = skip_java_text_block(source, index, path)
            original = source[index + 3 : end - 3]
            masked, count = mask_embedded_text(original, tokens_by_value)
            if masked != original:
                replacements[index] = (end, encode_java_string(masked))
                replacement_count += count
            index = end
            continue
        character = source[index]
        if character == '"':
            end = skip_java_string(source, index, path)
            original = decode_java_string(source[index:end])
            masked, count = mask_embedded_text(original, tokens_by_value)
            if masked != original:
                replacements[index] = (end, encode_java_string(masked))
                replacement_count += count
            index = end
            continue
        if character == "'":
            index = skip_java_char(source, index, path)
            continue
        if is_java_identifier_start(character):
            ident_start = index
            index += 1
            while index < length and is_java_identifier_part(source[index]):
                index += 1
            method_name = source[ident_start:index]
            kind = method_kinds.get(method_name)
            next_index = skip_java_whitespace_and_comments(source, index, path)
            if next_index < length and source[next_index] == "(":
                close, local_replacements, count = mask_java_arguments(
                    source,
                    path,
                    next_index,
                    kind,
                    tokens_by_value,
                    key_kinds,
                )
                replacements.update(local_replacements)
                replacement_count += count
                index = close
                continue
            if (
                kind is not None
                and next_index < length
                and source[next_index] == "="
                and not source.startswith("==", next_index)
            ):
                value_index = skip_java_whitespace_and_comments(
                    source, next_index + 1, path
                )
                close, local_replacements, count = mask_java_value(
                    source, path, value_index, kind, tokens_by_value
                )
                replacements.update(local_replacements)
                replacement_count += count
                index = close
                continue
            continue
        index += 1

    if not replacements:
        return source, replacement_count

    parts: list[str] = []
    cursor = 0
    for start in sorted(replacements):
        end, replacement = replacements[start]
        parts.append(source[cursor:start])
        parts.append(replacement)
        cursor = end
    parts.append(source[cursor:])
    return "".join(parts), replacement_count


def iter_data_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return

    for current_directory, directory_names, file_names in os.walk(root):
        directory_names[:] = sorted(
            name for name in directory_names if name not in IGNORED_DIRECTORIES
        )
        current_path = Path(current_directory)
        for file_name in sorted(file_names):
            path = current_path / file_name
            if (
                path.suffix.casefold() in SUPPORTED_SUFFIXES
                and path.is_file()
                and not path.is_symlink()
            ):
                yield path


def failed_sql_line(statement: str, error: Exception) -> tuple[int, str]:
    """Return the statement-relative line and source text for an SQL error."""
    location = re.search(r"\bat line (\d+)\b", str(error))
    line_number = int(location.group(1)) if location else 1
    lines = statement.splitlines()
    if line_number <= len(lines):
        return line_number, lines[line_number - 1].rstrip()
    return line_number, "<SQL line unavailable>"


def prepare_sql_file(
    path: Path,
    field_types: dict[str, str],
    tokens_by_value: dict[str, str],
) -> tuple[PreparedFile | None, int]:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary_path = Path(temporary_name)
    replacement_count = 0
    try:
        with path.open("r", encoding="utf-8", newline="") as source_stream:
            with os.fdopen(
                descriptor, "w", encoding="utf-8", newline=""
            ) as output_stream:
                statement_start_line = 1
                for statement in iter_postgresql_statements(source_stream):
                    try:
                        masked, count = transform_sql_document(
                            statement,
                            path,
                            field_types,
                            tokens_by_value,
                            statement_start_line,
                        )
                    except Exception as error:
                        failed_line_number, failed_line = failed_sql_line(
                            statement, error
                        )
                        LOGGER.exception(
                            "Unable to process SQL in %s at line %d: %s",
                            path,
                            statement_start_line + failed_line_number - 1,
                            failed_line,
                        )
                        raise
                    output_stream.write(masked)
                    replacement_count += count
                    statement_start_line += statement.count("\n")
                output_stream.flush()
                os.fsync(output_stream.fileno())
        if replacement_count == 0:
            temporary_path.unlink(missing_ok=True)
            return None, 0
        return PreparedFile(path=path, temporary_path=temporary_path), replacement_count
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary_path.unlink(missing_ok=True)
        raise


def prepare_masking(
    roots: list[Path],
    phone_keys: set[str] | None = None,
    field_types: dict[str, str] | None = None,
    source_keys: dict[str, str] | None = None,
) -> tuple[list[PreparedFile], int]:
    if field_types is None:
        field_types = {key.casefold(): "phone" for key in (phone_keys or set())}
    if source_keys is None:
        source_keys = (
            {key: "phone" for key in phone_keys}
            if phone_keys
            else dict(field_types)
        )
    java_methods = java_method_kinds(source_keys)
    java_keys = java_field_key_kinds(source_keys)
    tokens_by_value: dict[str, str] = {}
    prepared: list[PreparedFile] = []
    replacement_count = 0

    try:
        for root in roots:
            for path in iter_data_files(root):
                if path.suffix.casefold() == ".sql":
                    prepared_sql, count = prepare_sql_file(
                        path, field_types, tokens_by_value
                    )
                    if prepared_sql is not None:
                        prepared.append(prepared_sql)
                        replacement_count += count
                    continue

                source = path.read_text(encoding="utf-8")
                suffix = path.suffix.casefold()
                if suffix == ".java":
                    serialized, count = transform_java_document(
                        source, path, java_methods, tokens_by_value, java_keys
                    )
                elif suffix == ".json":
                    if not source.strip():
                        LOGGER.warning("Skipping empty JSON file %s", path)
                        continue
                    try:
                        document = json.loads(source)
                    except json.JSONDecodeError as error:
                        raise TokenizerError(
                            f"Invalid JSON in {path}: {error}"
                        ) from error
                    count = transform_document(
                        document=document,
                        field_types=field_types,
                        tokens_by_value=tokens_by_value,
                    )
                    serialized = serialize_json(document, source)
                else:
                    if not source.strip():
                        LOGGER.warning("Skipping empty XML file %s", path)
                        continue
                    document = parse_xml_document(source, path)
                    count = transform_xml_document(
                        document=document,
                        field_types=field_types,
                        tokens_by_value=tokens_by_value,
                    )
                    serialized = serialize_xml(document, source)
                if count:
                    prepared.append(prepare_content_file(path, serialized))
                    replacement_count += count
    except BaseException:
        discard_prepared_files(prepared)
        raise

    return prepared, replacement_count


def prepare_content_file(path: Path, content: str) -> PreparedFile:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        return PreparedFile(path=path, temporary_path=temporary_path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def make_path_writable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IWUSR | stat.S_IWRITE)


def replace_file(temporary_path: Path, path: Path) -> None:
    try:
        os.replace(temporary_path, path)
        return
    except PermissionError:
        LOGGER.warning(
            "Atomic replace of %s was denied; clearing the read-only flag",
            path,
        )
    make_path_writable(path)
    try:
        os.replace(temporary_path, path)
        return
    except PermissionError:
        LOGGER.warning("Overwriting %s in place", path)
    make_path_writable(path)
    with temporary_path.open("rb") as source:
        with path.open("wb") as destination:
            shutil.copyfileobj(source, destination)
            destination.flush()
            os.fsync(destination.fileno())
    temporary_path.unlink(missing_ok=True)


def write_prepared_files(prepared: list[PreparedFile]) -> None:
    try:
        for item in prepared:
            replace_file(item.temporary_path, item.path)
    finally:
        discard_prepared_files(prepared)


def discard_prepared_files(prepared: list[PreparedFile]) -> None:
    for item in prepared:
        item.temporary_path.unlink(missing_ok=True)


def existing_mask_path(value: str) -> Path:
    path = Path(value).resolve()
    if path.is_dir():
        return path
    if (
        path.is_file()
        and not path.is_symlink()
        and path.suffix.casefold() in SUPPORTED_SUFFIXES
    ):
        return path
    raise argparse.ArgumentTypeError(
        f"Not a directory or JSON/XML/SQL/Java file: {value}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Irreversibly depersonalize sensitive JSON/XML/SQL values"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    mask = subparsers.add_parser(
        "mask", help="Mask sensitive values in repositories or individual files"
    )
    mask.add_argument(
        "roots",
        nargs="+",
        type=existing_mask_path,
        metavar="PATH",
        help="Directory to scan or a JSON/XML/SQL/Java file to mask",
    )
    mask.add_argument(
        "--phone-keys",
        default=",".join(DEFAULT_PHONE_KEYS),
        help="Comma-separated JSON/XML/SQL field names",
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
        "--organization-keys",
        default=",".join(DEFAULT_ORGANIZATION_KEYS),
        help="Comma-separated organization name field names",
    )
    mask.add_argument(
        "--address-keys",
        default=",".join(DEFAULT_ADDRESS_KEYS),
        help="Comma-separated address field names",
    )
    mask.add_argument(
        "--dry-run", action="store_true", help="Report replacements without writing files"
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        field_types: dict[str, str] = {}
        source_keys: dict[str, str] = {}
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
            ("organization", args.organization_keys),
            ("address", args.address_keys),
        ):
            for key in raw_keys.split(","):
                if key.strip():
                    original_key = key.strip()
                    field_types[original_key.casefold()] = kind
                    source_keys[original_key] = kind
        if not field_types:
            raise TokenizerError("At least one sensitive field key is required")

        prepared, count = prepare_masking(
            args.roots, field_types=field_types, source_keys=source_keys
        )
        if args.dry_run:
            print(
                f"Would replace {count} sensitive value(s) "
                f"in {len(prepared)} file(s)"
            )
            discard_prepared_files(prepared)
            return 0

        write_prepared_files(prepared)
        print(f"Replaced {count} sensitive value(s) in {len(prepared)} file(s)")
        return 0
    except (OSError, KeyError, IndexError, TypeError, TokenizerError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
