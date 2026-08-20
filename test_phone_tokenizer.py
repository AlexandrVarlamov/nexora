import io
import json
import re
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from phone_tokenizer import (
    iter_postgresql_statements,
    main,
    normalize_phone,
    prepare_masking,
    write_prepared_files,
)


def assert_repeated_digit(
    test_case: unittest.TestCase, value: object, length: int
) -> None:
    test_case.assertIsInstance(value, str)
    test_case.assertEqual(len(value), length)
    test_case.assertRegex(value, r"^\d+$")
    test_case.assertEqual(len(set(value)), 1)


class PhoneTokenizerTest(unittest.TestCase):
    def test_normalizes_common_russian_phone_formats(self) -> None:
        self.assertEqual(normalize_phone("89992102974"), "+79992102974")
        self.assertEqual(normalize_phone("+7 (999) 210-29-74"), "+79992102974")
        self.assertEqual(normalize_phone("9992102974"), "+79992102974")
        self.assertEqual(normalize_phone("(4722)588292"), "+74722588292")
        self.assertIsNone(normalize_phone("12345"))

    def test_depersonalizes_numeric_fields_with_one_repeated_digit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repo"
            root.mkdir()
            data_file = root / "client.json"
            document = {
                "phone": "89992102974",
                "PhoneNumber": "(4722)588292",
                "inn": "999999999999",
                "kpp": "770001001",
                "account": "40817810000001234567",
                "account_number": 729182,
                "clientNum": 2008861610,
                "esflId": "FA6CFEA093F941BEA7DA17A26C63A450",
                "passport_series": "45 10",
                "passport_number": "123456",
                "ogrn": "1027700132195",
                "cardNumber": "4111 1111 1111 1111",
                "fio": "Варламов Александр Сергеевич",
            }
            data_file.write_text(
                json.dumps(document, ensure_ascii=False), encoding="utf-8"
            )
            field_types = {
                "phone": "phone",
                "phonenumber": "phone",
                "inn": "inn",
                "kpp": "kpp",
                "account": "account",
                "account_number": "account",
                "clientnum": "account",
                "esflid": "account",
                "passport_series": "passport_series",
                "passport_number": "passport_number",
                "ogrn": "ogrn",
                "cardnumber": "card_number",
                "fio": "fio",
            }

            prepared, count = prepare_masking([root], field_types=field_types)
            self.assertEqual(count, 13)
            write_prepared_files(prepared)
            masked = json.loads(data_file.read_text(encoding="utf-8"))

            for key in (
                "phone",
                "PhoneNumber",
                "inn",
                "kpp",
                "account",
                "account_number",
                "clientNum",
                "esflId",
                "passport_series",
                "passport_number",
                "ogrn",
                "cardNumber",
            ):
                raw_value = str(document[key])
                first_symbol = next(
                    symbol for symbol in raw_value if symbol.isalnum()
                )
                self.assertEqual(
                    masked[key], first_symbol * len(raw_value)
                )
            self.assertRegex(masked["fio"], r"^FIO_[A-Z]{20}$")

    def test_same_value_uses_same_digit_across_repositories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            mocks = base / "mocks"
            tests = base / "tests"
            mocks.mkdir()
            tests.mkdir()
            (mocks / "data.json").write_text(
                '{"phone": "89992102974"}', encoding="utf-8"
            )
            (tests / "expected.json").write_text(
                '{"mobilePhone": "89992102974"}', encoding="utf-8"
            )

            prepared, count = prepare_masking(
                [mocks, tests],
                field_types={"phone": "phone", "mobilephone": "phone"},
            )
            self.assertEqual(count, 2)
            write_prepared_files(prepared)

            mock_phone = json.loads(
                (mocks / "data.json").read_text(encoding="utf-8")
            )["phone"]
            expected_phone = json.loads(
                (tests / "expected.json").read_text(encoding="utf-8")
            )["mobilePhone"]
            self.assertEqual(mock_phone, expected_phone)
            assert_repeated_digit(self, mock_phone, 11)

    def test_masks_emails_logins_and_private_ips_in_any_string(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repo"
            root.mkdir()
            data_file = root / "security.json"
            data_file.write_text(
                json.dumps(
                    {
                        "text": (
                            "worker@int.gazprombank.ru client@gmail.com "
                            "gpbu123 10.0.0.1 172.16.1.2 192.168.1.3 8.8.8.8"
                        )
                    }
                ),
                encoding="utf-8",
            )

            prepared, count = prepare_masking([root], field_types={})
            self.assertEqual(count, 6)
            write_prepared_files(prepared)
            text = json.loads(data_file.read_text(encoding="utf-8"))["text"]

            self.assertNotIn("@", text)
            self.assertNotIn("worker", text)
            self.assertNotIn("client", text)
            self.assertIn("USER_", text)
            self.assertEqual(text.count("127.0.0.1"), 3)
            self.assertIn("8.8.8.8", text)

    def test_applies_same_rules_to_xml_elements_and_attributes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repo"
            root.mkdir()
            json_file = root / "client.json"
            xml_file = root / "client.xml"
            json_file.write_text('{"phone": "89992102974"}', encoding="utf-8")
            xml_file.write_text(
                """<?xml version="1.0" encoding="UTF-8"?>
<client login="gpbu777">
  <phone>89992102974</phone>
  <network>10.20.30.40</network>
  <identity_document>
    <type>passport_rf</type>
    <series>4510</series>
    <number>123456</number>
  </identity_document>
  <payment cardNumber="4111 1111 1111 1111" />
  <fio>Варламов Александр Сергеевич</fio>
</client>
""",
                encoding="utf-8",
            )
            field_types = {
                "phone": "phone",
                "cardnumber": "card_number",
                "fio": "fio",
            }

            prepared, count = prepare_masking([root], field_types=field_types)
            self.assertEqual(count, 8)
            write_prepared_files(prepared)
            masked_json = json.loads(json_file.read_text(encoding="utf-8"))
            masked_xml = ET.fromstring(xml_file.read_text(encoding="utf-8"))

            self.assertEqual(masked_json["phone"], masked_xml.findtext("phone"))
            self.assertRegex(masked_xml.attrib["login"], r"^USER_[A-Z]{20}$")
            self.assertEqual(masked_xml.findtext("network"), "127.0.0.1")
            assert_repeated_digit(
                self, masked_xml.findtext("identity_document/series"), 4
            )
            assert_repeated_digit(
                self, masked_xml.findtext("identity_document/number"), 6
            )
            assert_repeated_digit(
                self, masked_xml.find("payment").attrib["cardNumber"], 19
            )
            self.assertRegex(masked_xml.findtext("fio"), r"^FIO_[A-Z]{20}$")

    def test_ignores_git_and_idea_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repo"
            root.mkdir()
            (root / ".git").mkdir()
            (root / ".idea").mkdir()
            visible_file = root / "data.json"
            git_file = root / ".git" / "data.json"
            idea_file = root / ".idea" / "data.xml"
            visible_file.write_text('{"phone": "89992102974"}', encoding="utf-8")
            git_file.write_text('{"phone": "89992102974"}', encoding="utf-8")
            idea_file.write_text(
                "<root><phone>89992102974</phone></root>", encoding="utf-8"
            )

            prepared, count = prepare_masking(
                [root], field_types={"phone": "phone"}
            )
            self.assertEqual(count, 1)
            self.assertEqual([item.path for item in prepared], [visible_file])
            write_prepared_files(prepared)

            self.assertEqual(
                git_file.read_text(encoding="utf-8"),
                '{"phone": "89992102974"}',
            )
            self.assertEqual(
                idea_file.read_text(encoding="utf-8"),
                "<root><phone>89992102974</phone></root>",
            )

    def test_masks_postgresql_insert_values_and_select(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repo"
            root.mkdir()
            sql_file = root / "clients.sql"
            sql_file.write_text(
                """-- comments remain unchanged
INSERT INTO clients ("PhoneNumber", inn, fio, note, clientNum)
VALUES (
    '(4722)588292',
    '123456789012',
    'Иванов Иван Иванович',
    'worker@int.gazprombank.ru 10.20.30.40',
    2008861610
);

INSERT INTO cards (cardNumber, esflId, note)
SELECT
    '4111 1111 1111 1111',
    'FA6CFEA093F941BEA7DA17A26C63A450',
    'client@gmail.com gpbu12345';

INSERT INTO client_archive (phone)
SELECT phone FROM staging_clients;
""",
                encoding="utf-8",
            )
            field_types = {
                "phonenumber": "phone",
                "phone": "phone",
                "inn": "inn",
                "fio": "fio",
                "clientnum": "account",
                "cardnumber": "card_number",
                "esflid": "account",
            }

            prepared, count = prepare_masking(
                [root], field_types=field_types
            )
            self.assertEqual(count, 10)
            self.assertEqual([item.path for item in prepared], [sql_file])
            self.assertTrue(prepared[0].temporary_path.exists())
            self.assertIn(
                "'(4722)588292'", sql_file.read_text(encoding="utf-8")
            )
            write_prepared_files(prepared)
            masked = sql_file.read_text(encoding="utf-8")

            self.assertIn("-- comments remain unchanged", masked)
            self.assertIn("'444444444444'", masked)
            self.assertIn("'111111111111'", masked)
            self.assertRegex(masked, r"'FIO_[A-Z]{20}'")
            self.assertNotIn("@", masked)
            self.assertIn("127.0.0.1", masked)
            self.assertIn("'2222222222'", masked)
            self.assertIn("'4444444444444444444'", masked)
            self.assertIn("'" + "F" * 32 + "'", masked)
            self.assertIn("USER_", masked)
            self.assertIn("SELECT phone FROM staging_clients", masked)

    def test_masks_organization_names_and_addresses_in_all_formats(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repo"
            root.mkdir()
            json_file = root / "client.json"
            xml_file = root / "client.xml"
            sql_file = root / "client.sql"
            organization = "ООО «Альфа Технологии»"
            address = "Москва, Новослободская улица, 24"
            json_file.write_text(
                json.dumps(
                    {
                        "employer_name": organization,
                        "registration_address": {
                            "city": "Москва",
                            "street": "Новослободская улица",
                            "house": 24,
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            xml_file.write_text(
                f"""<client organizationName="{organization}">
  <postalAddress>
    <city>Москва</city>
    <street>Новослободская улица</street>
  </postalAddress>
</client>""",
                encoding="utf-8",
            )
            sql_file.write_text(
                "INSERT INTO clients (companyName, address) VALUES "
                f"('{organization}', '{address}');\n",
                encoding="utf-8",
            )

            self.assertEqual(main(["mask", str(root)]), 0)

            masked_json = json.loads(json_file.read_text(encoding="utf-8"))
            masked_xml = ET.fromstring(xml_file.read_text(encoding="utf-8"))
            masked_sql = sql_file.read_text(encoding="utf-8")
            self.assertEqual(masked_json["employer_name"], "О" * len(organization))
            self.assertEqual(
                masked_json["registration_address"]["city"], "М" * len("Москва")
            )
            self.assertEqual(
                masked_json["registration_address"]["street"],
                "Н" * len("Новослободская улица"),
            )
            self.assertEqual(masked_json["registration_address"]["house"], "22")
            self.assertEqual(
                masked_xml.attrib["organizationName"], "О" * len(organization)
            )
            self.assertEqual(
                masked_xml.findtext("postalAddress/city"), "М" * len("Москва")
            )
            self.assertEqual(
                masked_xml.findtext("postalAddress/street"),
                "Н" * len("Новослободская улица"),
            )
            self.assertIn("'О" + "О" * (len(organization) - 1) + "'", masked_sql)
            self.assertIn("'М" + "М" * (len(address) - 1) + "'", masked_sql)

    def test_skips_sql_insert_without_explicit_columns_with_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repo"
            root.mkdir()
            sql_file = root / "invalid.sql"
            original = (
                "-- A preceding comment verifies the global line number.\n"
                "INSERT INTO clients VALUES ('89992102974');\n"
            )
            sql_file.write_text(original, encoding="utf-8")

            with self.assertLogs("phone_tokenizer", level="WARNING") as logs:
                prepared, count = prepare_masking(
                    [root], field_types={"phone": "phone"}
                )
            self.assertEqual(count, 0)
            self.assertEqual(prepared, [])
            self.assertIn(
                f"Skipping SQL INSERT without an explicit target column list "
                f"in {sql_file} at line 2",
                logs.output[0],
            )
            self.assertEqual(sql_file.read_text(encoding="utf-8"), original)
            self.assertEqual(list(root.glob(".*.tmp")), [])

    def test_skips_sql_insert_default_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repo"
            root.mkdir()
            sql_file = root / "defaults.sql"
            original = (
                "INSERT INTO pGPB_AccNumber DEFAULT VALUES;\n"
                "INSERT INTO clients (phone) VALUES ('89992102974');\n"
            )
            sql_file.write_text(original, encoding="utf-8")

            prepared, count = prepare_masking(
                [root], field_types={"phone": "phone"}
            )

            self.assertEqual(count, 1)
            write_prepared_files(prepared)
            masked = sql_file.read_text(encoding="utf-8")
            self.assertIn("INSERT INTO pGPB_AccNumber DEFAULT VALUES;", masked)
            self.assertIn("'88888888888'", masked)

    def test_streams_sql_statements_without_splitting_quoted_semicolons(
        self,
    ) -> None:
        source = (
            "-- semicolon ; in comment\n"
            "INSERT INTO notes (fio) VALUES ('Иванов; Иван');\n"
            "DO $$ BEGIN RAISE NOTICE 'a;b'; END $$;\n"
        )
        statements = list(iter_postgresql_statements(io.StringIO(source)))
        nonempty_statements = [
            statement for statement in statements if statement.strip()
        ]
        self.assertEqual(len(nonempty_statements), 2)
        self.assertIn("'Иванов; Иван'", nonempty_statements[0])
        self.assertIn("RAISE NOTICE 'a;b'", nonempty_statements[1])

    def test_streams_many_sql_statements_through_a_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repo"
            root.mkdir()
            sql_file = root / "large.sql"
            statement = (
                "INSERT INTO clients (phone) VALUES ('89992102974');\n"
            )
            original = statement * 2000
            sql_file.write_text(original, encoding="utf-8")

            prepared, count = prepare_masking(
                [root], field_types={"phone": "phone"}
            )
            self.assertEqual(count, 2000)
            self.assertEqual(sql_file.read_text(encoding="utf-8"), original)
            self.assertTrue(prepared[0].temporary_path.exists())

            write_prepared_files(prepared)
            masked = sql_file.read_text(encoding="utf-8")
            self.assertNotIn("89992102974", masked)
            self.assertEqual(masked.count("'88888888888'"), 2000)

    def test_masks_tsql_batches_without_semicolons(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repo"
            root.mkdir()
            sql_file = root / "init_mssql.sql"
            sql_file.write_text(
                """if replace(db_name(), 'retail', '') = '000'
    insert into pGPB_BranchSet (DealSuff, AccountSuff, BranchCode) values ('23', '30137', '000')
else
    begin
        if replace(db_name(), 'retail', '') = '007'
            insert into pGPB_BranchSet (DealSuff, AccountSuff, BranchCode) values ('17', '30207', '007')
        else
            insert into pGPB_BranchSet (DealSuff, AccountSuff, BranchCode) values ('34', '30314', '314')
    end
GO

INSERT INTO [clients] ([PhoneNumber]) VALUES (N'(4722)588292')
GO
""",
                encoding="utf-8",
            )

            prepared, count = prepare_masking(
                [root],
                field_types={
                    "accountsuff": "account",
                    "phonenumber": "phone",
                },
            )
            self.assertEqual(count, 4)
            write_prepared_files(prepared)
            masked = sql_file.read_text(encoding="utf-8")

            self.assertNotIn("'30137'", masked)
            self.assertNotIn("'30207'", masked)
            self.assertNotIn("'30314'", masked)
            self.assertEqual(masked.count("'33333'"), 3)
            self.assertIn("N'444444444444'", masked)
            self.assertEqual(
                len(re.findall(r"(?mi)^\s*GO\s*$", masked)), 2
            )

    def test_stops_tsql_insert_select_at_the_next_statement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repo"
            root.mkdir()
            sql_file = root / "select_mssql.sql"
            sql_file.write_text(
                """insert into obpo (EnterpriseID, code, obpo, name, inn) select 10000201927, '12217z', '1198', N'Общество с ограниченной ответственностью "ГПМ Технолоджи"', '7703754438'
insert into obpo (EnterpriseID, code, obpo, name, inn) select 10000201928, '12218z', '1199', N'Другая организация', '7703754439'
GO
""",
                encoding="utf-8",
            )

            prepared, count = prepare_masking(
                [root], field_types={"inn": "inn"}
            )
            self.assertEqual(count, 2)
            write_prepared_files(prepared)
            masked = sql_file.read_text(encoding="utf-8")

            self.assertNotIn("7703754438", masked)
            self.assertNotIn("7703754439", masked)
            self.assertEqual(masked.count("'7777777777'"), 2)


if __name__ == "__main__":
    unittest.main()
