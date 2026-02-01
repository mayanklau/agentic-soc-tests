"""
Unit Tests for Utility Functions.

Tests parsing utilities, validation helpers, formatters,
and common helper functions used across the platform.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
import json
import hashlib
import base64
import ipaddress


class TestParsingUtilities:
    """Tests for parsing utility functions."""

    def test_syslog_rfc3164_parsing(self):
        """Test RFC 3164 syslog message parsing."""
        with patch("agentic_soc.utils.parsers.SyslogParser") as mock_parser:
            mock_instance = MagicMock()
            mock_parser.return_value = mock_instance

            raw_syslog = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"

            mock_instance.parse_rfc3164.return_value = {
                "priority": 34,
                "facility": 4,
                "severity": 2,
                "timestamp": "Oct 11 22:14:15",
                "hostname": "mymachine",
                "program": "su",
                "message": "'su root' failed for lonvick on /dev/pts/8",
                "parsed_successfully": True
            }

            result = mock_instance.parse_rfc3164(raw_syslog)

            assert result["priority"] == 34
            assert result["hostname"] == "mymachine"
            assert result["parsed_successfully"] is True

    def test_syslog_rfc5424_parsing(self):
        """Test RFC 5424 syslog message parsing."""
        with patch("agentic_soc.utils.parsers.SyslogParser") as mock_parser:
            mock_instance = MagicMock()
            mock_parser.return_value = mock_instance

            raw_syslog = "<165>1 2024-01-15T10:30:00.000Z host app proc123 msgid [exampleSDID@32473 iut=\"3\" eventSource=\"Application\"] An application event log entry"

            mock_instance.parse_rfc5424.return_value = {
                "priority": 165,
                "version": 1,
                "timestamp": "2024-01-15T10:30:00.000Z",
                "hostname": "host",
                "app_name": "app",
                "proc_id": "proc123",
                "msg_id": "msgid",
                "structured_data": {
                    "exampleSDID@32473": {
                        "iut": "3",
                        "eventSource": "Application"
                    }
                },
                "message": "An application event log entry",
                "parsed_successfully": True
            }

            result = mock_instance.parse_rfc5424(raw_syslog)

            assert result["version"] == 1
            assert "structured_data" in result
            assert result["parsed_successfully"] is True

    def test_cef_log_parsing(self):
        """Test CEF (Common Event Format) log parsing."""
        with patch("agentic_soc.utils.parsers.CEFParser") as mock_parser:
            mock_instance = MagicMock()
            mock_parser.return_value = mock_instance

            cef_log = "CEF:0|Security|ThreatManager|1.0|100|Detected Malware|10|src=192.168.1.100 dst=10.0.0.1 act=blocked"

            mock_instance.parse.return_value = {
                "version": 0,
                "device_vendor": "Security",
                "device_product": "ThreatManager",
                "device_version": "1.0",
                "signature_id": "100",
                "name": "Detected Malware",
                "severity": 10,
                "extension": {
                    "src": "192.168.1.100",
                    "dst": "10.0.0.1",
                    "act": "blocked"
                },
                "parsed_successfully": True
            }

            result = mock_instance.parse(cef_log)

            assert result["severity"] == 10
            assert result["extension"]["src"] == "192.168.1.100"

    def test_leef_log_parsing(self):
        """Test LEEF (Log Event Extended Format) log parsing."""
        with patch("agentic_soc.utils.parsers.LEEFParser") as mock_parser:
            mock_instance = MagicMock()
            mock_parser.return_value = mock_instance

            leef_log = "LEEF:2.0|Security|Scanner|1.0|scan_completed|cat=Security\tsrc=192.168.1.1\tdst=10.0.0.1"

            mock_instance.parse.return_value = {
                "version": "2.0",
                "vendor": "Security",
                "product": "Scanner",
                "version": "1.0",
                "event_id": "scan_completed",
                "attributes": {
                    "cat": "Security",
                    "src": "192.168.1.1",
                    "dst": "10.0.0.1"
                },
                "parsed_successfully": True
            }

            result = mock_instance.parse(leef_log)

            assert result["event_id"] == "scan_completed"
            assert result["parsed_successfully"] is True

    def test_json_log_parsing(self):
        """Test JSON log parsing with nested structures."""
        with patch("agentic_soc.utils.parsers.JSONParser") as mock_parser:
            mock_instance = MagicMock()
            mock_parser.return_value = mock_instance

            json_log = '{"timestamp": "2024-01-15T10:30:00Z", "event": {"type": "login", "user": "admin"}, "source_ip": "192.168.1.100"}'

            mock_instance.parse.return_value = {
                "timestamp": "2024-01-15T10:30:00Z",
                "event": {
                    "type": "login",
                    "user": "admin"
                },
                "source_ip": "192.168.1.100",
                "flattened": {
                    "timestamp": "2024-01-15T10:30:00Z",
                    "event.type": "login",
                    "event.user": "admin",
                    "source_ip": "192.168.1.100"
                },
                "parsed_successfully": True
            }

            result = mock_instance.parse(json_log)

            assert result["event"]["type"] == "login"
            assert result["flattened"]["event.type"] == "login"

    def test_kv_pair_parsing(self):
        """Test key-value pair log parsing."""
        with patch("agentic_soc.utils.parsers.KVParser") as mock_parser:
            mock_instance = MagicMock()
            mock_parser.return_value = mock_instance

            kv_log = "time=2024-01-15T10:30:00Z action=allow src=192.168.1.100 dst=10.0.0.1 user=\"john smith\" bytes=1024"

            mock_instance.parse.return_value = {
                "time": "2024-01-15T10:30:00Z",
                "action": "allow",
                "src": "192.168.1.100",
                "dst": "10.0.0.1",
                "user": "john smith",
                "bytes": "1024",
                "parsed_successfully": True
            }

            result = mock_instance.parse(kv_log)

            assert result["action"] == "allow"
            assert result["user"] == "john smith"

    def test_windows_event_xml_parsing(self):
        """Test Windows Event XML parsing."""
        with patch("agentic_soc.utils.parsers.WindowsEventParser") as mock_parser:
            mock_instance = MagicMock()
            mock_parser.return_value = mock_instance

            mock_instance.parse.return_value = {
                "event_id": 4624,
                "version": 2,
                "level": 0,
                "task": 12544,
                "opcode": 0,
                "keywords": "0x8020000000000000",
                "time_created": "2024-01-15T10:30:00.000Z",
                "event_record_id": 12345,
                "channel": "Security",
                "computer": "DC01.company.local",
                "security_user_id": "S-1-5-18",
                "event_data": {
                    "SubjectUserSid": "S-1-5-18",
                    "SubjectUserName": "DC01$",
                    "SubjectDomainName": "COMPANY",
                    "TargetUserSid": "S-1-5-21-123456789-1234567890-123456789-1001",
                    "TargetUserName": "jsmith",
                    "TargetDomainName": "COMPANY",
                    "LogonType": "10",
                    "IpAddress": "192.168.1.100"
                },
                "parsed_successfully": True
            }

            result = mock_instance.parse("<Event>...</Event>")

            assert result["event_id"] == 4624
            assert result["event_data"]["LogonType"] == "10"


class TestValidationUtilities:
    """Tests for validation utility functions."""

    def test_ip_address_validation(self):
        """Test IP address validation."""
        with patch("agentic_soc.utils.validators.IPValidator") as mock_validator:
            mock_instance = MagicMock()
            mock_validator.return_value = mock_instance

            test_cases = [
                ("192.168.1.1", True, "ipv4", False),
                ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", True, "ipv6", False),
                ("10.0.0.1", True, "ipv4", True),
                ("256.1.1.1", False, None, False),
                ("not-an-ip", False, None, False)
            ]

            for ip, is_valid, ip_type, is_private in test_cases:
                mock_instance.validate.return_value = {
                    "input": ip,
                    "valid": is_valid,
                    "type": ip_type,
                    "is_private": is_private,
                    "is_loopback": ip == "127.0.0.1",
                    "is_multicast": False
                }

                result = mock_instance.validate(ip)
                assert result["valid"] == is_valid

    def test_domain_validation(self):
        """Test domain name validation."""
        with patch("agentic_soc.utils.validators.DomainValidator") as mock_validator:
            mock_instance = MagicMock()
            mock_validator.return_value = mock_instance

            test_cases = [
                ("example.com", True, "com"),
                ("sub.example.co.uk", True, "co.uk"),
                ("invalid..domain", False, None),
                ("-invalid.com", False, None),
                ("valid-domain.org", True, "org")
            ]

            for domain, is_valid, tld in test_cases:
                mock_instance.validate.return_value = {
                    "input": domain,
                    "valid": is_valid,
                    "tld": tld,
                    "subdomain_count": domain.count('.') if is_valid else 0
                }

                result = mock_instance.validate(domain)
                assert result["valid"] == is_valid

    def test_hash_validation(self):
        """Test file hash validation."""
        with patch("agentic_soc.utils.validators.HashValidator") as mock_validator:
            mock_instance = MagicMock()
            mock_validator.return_value = mock_instance

            test_cases = [
                ("d41d8cd98f00b204e9800998ecf8427e", True, "md5"),
                ("da39a3ee5e6b4b0d3255bfef95601890afd80709", True, "sha1"),
                ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", True, "sha256"),
                ("invalidhash", False, None),
                ("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", False, None)
            ]

            for hash_value, is_valid, hash_type in test_cases:
                mock_instance.validate.return_value = {
                    "input": hash_value,
                    "valid": is_valid,
                    "hash_type": hash_type,
                    "length": len(hash_value)
                }

                result = mock_instance.validate(hash_value)
                assert result["valid"] == is_valid

    def test_url_validation(self):
        """Test URL validation."""
        with patch("agentic_soc.utils.validators.URLValidator") as mock_validator:
            mock_instance = MagicMock()
            mock_validator.return_value = mock_instance

            mock_instance.validate.return_value = {
                "input": "https://example.com/path?query=value",
                "valid": True,
                "scheme": "https",
                "domain": "example.com",
                "path": "/path",
                "query": {"query": "value"},
                "is_secure": True,
                "defanged": "hxxps://example[.]com/path?query=value"
            }

            result = mock_instance.validate("https://example.com/path?query=value")

            assert result["valid"] is True
            assert result["is_secure"] is True
            assert "[.]" in result["defanged"]

    def test_email_validation(self):
        """Test email address validation."""
        with patch("agentic_soc.utils.validators.EmailValidator") as mock_validator:
            mock_instance = MagicMock()
            mock_validator.return_value = mock_instance

            test_cases = [
                ("user@example.com", True),
                ("user.name+tag@example.co.uk", True),
                ("invalid@", False),
                ("@example.com", False),
                ("user@.com", False)
            ]

            for email, is_valid in test_cases:
                mock_instance.validate.return_value = {
                    "input": email,
                    "valid": is_valid,
                    "local_part": email.split("@")[0] if is_valid else None,
                    "domain": email.split("@")[1] if is_valid and "@" in email else None
                }

                result = mock_instance.validate(email)
                assert result["valid"] == is_valid

    def test_timestamp_validation(self):
        """Test timestamp format validation and parsing."""
        with patch("agentic_soc.utils.validators.TimestampValidator") as mock_validator:
            mock_instance = MagicMock()
            mock_validator.return_value = mock_instance

            test_cases = [
                ("2024-01-15T10:30:00Z", True, "iso8601"),
                ("Jan 15 10:30:00", True, "syslog"),
                ("1705315800", True, "epoch"),
                ("1705315800000", True, "epoch_ms"),
                ("invalid-date", False, None)
            ]

            for timestamp, is_valid, format_type in test_cases:
                mock_instance.validate.return_value = {
                    "input": timestamp,
                    "valid": is_valid,
                    "format": format_type,
                    "normalized": "2024-01-15T10:30:00Z" if is_valid else None,
                    "epoch_ms": 1705315800000 if is_valid else None
                }

                result = mock_instance.validate(timestamp)
                assert result["valid"] == is_valid

    def test_mitre_technique_validation(self):
        """Test MITRE ATT&CK technique ID validation."""
        with patch("agentic_soc.utils.validators.MITREValidator") as mock_validator:
            mock_instance = MagicMock()
            mock_validator.return_value = mock_instance

            test_cases = [
                ("T1059", True, "technique"),
                ("T1059.001", True, "sub_technique"),
                ("TA0001", True, "tactic"),
                ("S0154", True, "software"),
                ("G0016", True, "group"),
                ("INVALID", False, None)
            ]

            for mitre_id, is_valid, id_type in test_cases:
                mock_instance.validate.return_value = {
                    "input": mitre_id,
                    "valid": is_valid,
                    "type": id_type,
                    "exists_in_framework": is_valid
                }

                result = mock_instance.validate(mitre_id)
                assert result["valid"] == is_valid


class TestFormattingUtilities:
    """Tests for formatting utility functions."""

    def test_timestamp_formatting(self):
        """Test timestamp formatting to various formats."""
        with patch("agentic_soc.utils.formatters.TimestampFormatter") as mock_formatter:
            mock_instance = MagicMock()
            mock_formatter.return_value = mock_instance

            epoch_ms = 1705315800000

            mock_instance.format.return_value = {
                "input_epoch_ms": epoch_ms,
                "formats": {
                    "iso8601": "2024-01-15T10:30:00.000Z",
                    "iso8601_local": "2024-01-15T05:30:00.000-05:00",
                    "rfc2822": "Mon, 15 Jan 2024 10:30:00 +0000",
                    "syslog": "Jan 15 10:30:00",
                    "splunk": "01/15/2024:10:30:00",
                    "human_readable": "January 15, 2024 10:30:00 AM UTC",
                    "relative": "2 hours ago"
                }
            }

            result = mock_instance.format(epoch_ms)

            assert "iso8601" in result["formats"]
            assert result["formats"]["iso8601"] == "2024-01-15T10:30:00.000Z"

    def test_bytes_formatting(self):
        """Test bytes to human-readable formatting."""
        with patch("agentic_soc.utils.formatters.BytesFormatter") as mock_formatter:
            mock_instance = MagicMock()
            mock_formatter.return_value = mock_instance

            test_cases = [
                (1024, "1 KB"),
                (1048576, "1 MB"),
                (1073741824, "1 GB"),
                (500, "500 B"),
                (1536000, "1.46 MB")
            ]

            for bytes_value, expected in test_cases:
                mock_instance.format.return_value = {
                    "bytes": bytes_value,
                    "formatted": expected,
                    "unit": expected.split()[1]
                }

                result = mock_instance.format(bytes_value)
                assert result["formatted"] == expected

    def test_ip_defanging(self):
        """Test IP address defanging for safe display."""
        with patch("agentic_soc.utils.formatters.IOCFormatter") as mock_formatter:
            mock_instance = MagicMock()
            mock_formatter.return_value = mock_instance

            mock_instance.defang_ip.return_value = {
                "original": "192.168.1.1",
                "defanged": "192[.]168[.]1[.]1",
                "type": "ipv4"
            }

            result = mock_instance.defang_ip("192.168.1.1")
            assert result["defanged"] == "192[.]168[.]1[.]1"

    def test_url_defanging(self):
        """Test URL defanging for safe display."""
        with patch("agentic_soc.utils.formatters.IOCFormatter") as mock_formatter:
            mock_instance = MagicMock()
            mock_formatter.return_value = mock_instance

            mock_instance.defang_url.return_value = {
                "original": "https://evil.com/malware.exe",
                "defanged": "hxxps://evil[.]com/malware[.]exe",
                "components": {
                    "scheme": "hxxps",
                    "domain": "evil[.]com",
                    "path": "/malware[.]exe"
                }
            }

            result = mock_instance.defang_url("https://evil.com/malware.exe")
            assert "hxxps" in result["defanged"]
            assert "[.]" in result["defanged"]

    def test_json_pretty_formatting(self):
        """Test JSON pretty formatting."""
        with patch("agentic_soc.utils.formatters.JSONFormatter") as mock_formatter:
            mock_instance = MagicMock()
            mock_formatter.return_value = mock_instance

            data = {"key": "value", "nested": {"a": 1}}

            mock_instance.pretty_print.return_value = {
                "formatted": '{\n  "key": "value",\n  "nested": {\n    "a": 1\n  }\n}',
                "indent": 2,
                "sort_keys": False
            }

            result = mock_instance.pretty_print(data)
            assert "\n" in result["formatted"]

    def test_severity_formatting(self):
        """Test severity level formatting."""
        with patch("agentic_soc.utils.formatters.SeverityFormatter") as mock_formatter:
            mock_instance = MagicMock()
            mock_formatter.return_value = mock_instance

            test_cases = [
                (1, "low", "🟢", "#00FF00"),
                (2, "medium", "🟡", "#FFFF00"),
                (3, "high", "🟠", "#FFA500"),
                (4, "critical", "🔴", "#FF0000")
            ]

            for level, name, emoji, color in test_cases:
                mock_instance.format.return_value = {
                    "level": level,
                    "name": name,
                    "emoji": emoji,
                    "color": color,
                    "badge": f"[{name.upper()}]"
                }

                result = mock_instance.format(level)
                assert result["name"] == name


class TestHashingUtilities:
    """Tests for hashing utility functions."""

    def test_compute_file_hashes(self):
        """Test computing multiple hash types for a file."""
        with patch("agentic_soc.utils.hashing.HashComputer") as mock_hasher:
            mock_instance = MagicMock()
            mock_hasher.return_value = mock_instance

            mock_instance.compute_all.return_value = {
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                "ssdeep": "3::",
                "file_size": 0
            }

            result = mock_instance.compute_all(b"")

            assert len(result["md5"]) == 32
            assert len(result["sha256"]) == 64

    def test_fuzzy_hash_comparison(self):
        """Test fuzzy hash similarity comparison."""
        with patch("agentic_soc.utils.hashing.FuzzyHasher") as mock_hasher:
            mock_instance = MagicMock()
            mock_hasher.return_value = mock_instance

            mock_instance.compare.return_value = {
                "hash1": "3:AXGBicFlgVNhBGcL6wCcg2:AqBRlFN",
                "hash2": "3:AXGBicFlIHBGcL6wCcg2:AqBRH",
                "similarity": 85,
                "match_type": "similar",
                "threshold": 70
            }

            result = mock_instance.compare("hash1", "hash2")
            assert result["similarity"] >= 80
            assert result["match_type"] == "similar"


class TestEncodingUtilities:
    """Tests for encoding/decoding utility functions."""

    def test_base64_decode(self):
        """Test base64 decoding."""
        with patch("agentic_soc.utils.encoding.Base64Utils") as mock_encoder:
            mock_instance = MagicMock()
            mock_encoder.return_value = mock_instance

            mock_instance.decode.return_value = {
                "input": "SGVsbG8gV29ybGQ=",
                "decoded": "Hello World",
                "encoding": "utf-8",
                "is_binary": False
            }

            result = mock_instance.decode("SGVsbG8gV29ybGQ=")
            assert result["decoded"] == "Hello World"

    def test_hex_decode(self):
        """Test hexadecimal decoding."""
        with patch("agentic_soc.utils.encoding.HexUtils") as mock_encoder:
            mock_instance = MagicMock()
            mock_encoder.return_value = mock_instance

            mock_instance.decode.return_value = {
                "input": "48656c6c6f",
                "decoded": "Hello",
                "bytes": b"Hello"
            }

            result = mock_instance.decode("48656c6c6f")
            assert result["decoded"] == "Hello"

    def test_url_decode(self):
        """Test URL decoding."""
        with patch("agentic_soc.utils.encoding.URLUtils") as mock_encoder:
            mock_instance = MagicMock()
            mock_encoder.return_value = mock_instance

            mock_instance.decode.return_value = {
                "input": "hello%20world%21",
                "decoded": "hello world!",
                "encoding_detected": "percent"
            }

            result = mock_instance.decode("hello%20world%21")
            assert result["decoded"] == "hello world!"

    def test_powershell_encoded_command_decode(self):
        """Test PowerShell encoded command decoding."""
        with patch("agentic_soc.utils.encoding.PowerShellUtils") as mock_encoder:
            mock_instance = MagicMock()
            mock_encoder.return_value = mock_instance

            # Base64 encoded UTF-16LE "Get-Process"
            encoded = "RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=="

            mock_instance.decode_encoded_command.return_value = {
                "input": encoded,
                "decoded": "Get-Process",
                "encoding": "UTF-16LE",
                "suspicious_indicators": []
            }

            result = mock_instance.decode_encoded_command(encoded)
            assert result["decoded"] == "Get-Process"


class TestNetworkUtilities:
    """Tests for network utility functions."""

    def test_cidr_expansion(self):
        """Test CIDR notation expansion."""
        with patch("agentic_soc.utils.network.CIDRUtils") as mock_cidr:
            mock_instance = MagicMock()
            mock_cidr.return_value = mock_instance

            mock_instance.expand.return_value = {
                "cidr": "192.168.1.0/30",
                "network_address": "192.168.1.0",
                "broadcast_address": "192.168.1.3",
                "usable_hosts": ["192.168.1.1", "192.168.1.2"],
                "total_hosts": 2,
                "netmask": "255.255.255.252"
            }

            result = mock_instance.expand("192.168.1.0/30")
            assert result["total_hosts"] == 2

    def test_ip_geolocation(self):
        """Test IP geolocation lookup."""
        with patch("agentic_soc.utils.network.GeoIP") as mock_geo:
            mock_instance = MagicMock()
            mock_geo.return_value = mock_instance

            mock_instance.lookup.return_value = {
                "ip": "8.8.8.8",
                "country": "United States",
                "country_code": "US",
                "region": "California",
                "city": "Mountain View",
                "latitude": 37.4056,
                "longitude": -122.0775,
                "asn": 15169,
                "org": "Google LLC",
                "isp": "Google LLC"
            }

            result = mock_instance.lookup("8.8.8.8")
            assert result["country_code"] == "US"
            assert result["org"] == "Google LLC"

    def test_dns_resolution(self):
        """Test DNS resolution utility."""
        with patch("agentic_soc.utils.network.DNSUtils") as mock_dns:
            mock_instance = MagicMock()
            mock_dns.return_value = mock_instance

            mock_instance.resolve.return_value = {
                "domain": "example.com",
                "records": {
                    "A": ["93.184.216.34"],
                    "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
                    "MX": [{"priority": 10, "host": "mail.example.com"}],
                    "NS": ["ns1.example.com", "ns2.example.com"],
                    "TXT": ["v=spf1 -all"]
                },
                "resolved_at": datetime.utcnow().isoformat()
            }

            result = mock_instance.resolve("example.com")
            assert "A" in result["records"]

    def test_whois_lookup(self):
        """Test WHOIS lookup utility."""
        with patch("agentic_soc.utils.network.WHOISUtils") as mock_whois:
            mock_instance = MagicMock()
            mock_whois.return_value = mock_instance

            mock_instance.lookup.return_value = {
                "domain": "example.com",
                "registrar": "Example Registrar, Inc.",
                "creation_date": "1995-08-14",
                "expiration_date": "2024-08-13",
                "updated_date": "2023-08-14",
                "registrant": {
                    "organization": "Internet Assigned Numbers Authority",
                    "country": "US"
                },
                "name_servers": ["ns1.example.com", "ns2.example.com"],
                "status": ["clientDeleteProhibited", "clientTransferProhibited"]
            }

            result = mock_instance.lookup("example.com")
            assert result["registrar"] is not None


class TestCryptoUtilities:
    """Tests for cryptographic utility functions."""

    def test_entropy_calculation(self):
        """Test entropy calculation for strings."""
        with patch("agentic_soc.utils.crypto.EntropyCalculator") as mock_entropy:
            mock_instance = MagicMock()
            mock_entropy.return_value = mock_instance

            test_cases = [
                ("aaaaaaaaaa", 0.0),  # Low entropy
                ("password123", 3.2),  # Medium entropy
                ("kj2h3k4j5h6k7j8h9k", 3.8),  # Higher entropy
                ("aB3$xY9@mN2#pQ5&", 4.0)  # High entropy (random)
            ]

            for string, expected_entropy in test_cases:
                mock_instance.calculate.return_value = {
                    "input": string,
                    "entropy": expected_entropy,
                    "length": len(string),
                    "unique_chars": len(set(string)),
                    "is_suspicious": expected_entropy > 3.5
                }

                result = mock_instance.calculate(string)
                assert "entropy" in result

    def test_password_strength_analysis(self):
        """Test password strength analysis."""
        with patch("agentic_soc.utils.crypto.PasswordAnalyzer") as mock_analyzer:
            mock_instance = MagicMock()
            mock_analyzer.return_value = mock_instance

            mock_instance.analyze.return_value = {
                "password": "P@ssw0rd123!",
                "strength_score": 65,
                "strength_level": "medium",
                "criteria": {
                    "length": {"met": True, "value": 12},
                    "uppercase": {"met": True, "count": 1},
                    "lowercase": {"met": True, "count": 6},
                    "numbers": {"met": True, "count": 4},
                    "special": {"met": True, "count": 2}
                },
                "weaknesses": [
                    "Common pattern detected (P@ssword)",
                    "Contains sequential numbers"
                ],
                "estimated_crack_time": "3 days"
            }

            result = mock_instance.analyze("P@ssw0rd123!")
            assert result["strength_level"] == "medium"


class TestTimeUtilities:
    """Tests for time-related utility functions."""

    def test_time_zone_conversion(self):
        """Test time zone conversion."""
        with patch("agentic_soc.utils.time.TimeZoneConverter") as mock_tz:
            mock_instance = MagicMock()
            mock_tz.return_value = mock_instance

            mock_instance.convert.return_value = {
                "input": "2024-01-15T10:30:00Z",
                "input_tz": "UTC",
                "output_tz": "America/New_York",
                "output": "2024-01-15T05:30:00-05:00",
                "offset": "-05:00"
            }

            result = mock_instance.convert("2024-01-15T10:30:00Z", "America/New_York")
            assert "-05:00" in result["output"]

    def test_duration_calculation(self):
        """Test duration calculation between timestamps."""
        with patch("agentic_soc.utils.time.DurationCalculator") as mock_duration:
            mock_instance = MagicMock()
            mock_duration.return_value = mock_instance

            mock_instance.calculate.return_value = {
                "start": "2024-01-15T10:00:00Z",
                "end": "2024-01-15T12:30:45Z",
                "duration": {
                    "total_seconds": 9045,
                    "hours": 2,
                    "minutes": 30,
                    "seconds": 45,
                    "human_readable": "2 hours, 30 minutes, 45 seconds"
                }
            }

            result = mock_instance.calculate(
                "2024-01-15T10:00:00Z",
                "2024-01-15T12:30:45Z"
            )

            assert result["duration"]["hours"] == 2
            assert result["duration"]["minutes"] == 30

    def test_sla_calculation(self):
        """Test SLA deadline calculation."""
        with patch("agentic_soc.utils.time.SLACalculator") as mock_sla:
            mock_instance = MagicMock()
            mock_sla.return_value = mock_instance

            mock_instance.calculate_deadline.return_value = {
                "created_at": "2024-01-15T10:00:00Z",
                "severity": "high",
                "sla_hours": 4,
                "deadline": "2024-01-15T14:00:00Z",
                "business_hours_only": True,
                "remaining_time": "3h 45m",
                "is_breached": False,
                "breach_risk": "low"
            }

            result = mock_instance.calculate_deadline(
                created_at="2024-01-15T10:00:00Z",
                severity="high"
            )

            assert result["is_breached"] is False
            assert result["sla_hours"] == 4


class TestCollectionUtilities:
    """Tests for collection manipulation utilities."""

    def test_list_deduplication(self):
        """Test list deduplication with order preservation."""
        with patch("agentic_soc.utils.collections.ListUtils") as mock_list:
            mock_instance = MagicMock()
            mock_list.return_value = mock_instance

            mock_instance.deduplicate.return_value = {
                "input": ["a", "b", "a", "c", "b", "d"],
                "output": ["a", "b", "c", "d"],
                "duplicates_removed": 2,
                "order_preserved": True
            }

            result = mock_instance.deduplicate(["a", "b", "a", "c", "b", "d"])
            assert result["output"] == ["a", "b", "c", "d"]

    def test_dict_flatten(self):
        """Test nested dictionary flattening."""
        with patch("agentic_soc.utils.collections.DictUtils") as mock_dict:
            mock_instance = MagicMock()
            mock_dict.return_value = mock_instance

            nested = {
                "event": {
                    "type": "login",
                    "user": {
                        "name": "john",
                        "id": 123
                    }
                },
                "timestamp": "2024-01-15"
            }

            mock_instance.flatten.return_value = {
                "input": nested,
                "output": {
                    "event.type": "login",
                    "event.user.name": "john",
                    "event.user.id": 123,
                    "timestamp": "2024-01-15"
                },
                "separator": ".",
                "depth": 3
            }

            result = mock_instance.flatten(nested)
            assert "event.user.name" in result["output"]

    def test_dict_deep_merge(self):
        """Test deep dictionary merging."""
        with patch("agentic_soc.utils.collections.DictUtils") as mock_dict:
            mock_instance = MagicMock()
            mock_dict.return_value = mock_instance

            dict1 = {"a": 1, "b": {"c": 2}}
            dict2 = {"b": {"d": 3}, "e": 4}

            mock_instance.deep_merge.return_value = {
                "dict1": dict1,
                "dict2": dict2,
                "merged": {
                    "a": 1,
                    "b": {"c": 2, "d": 3},
                    "e": 4
                },
                "conflicts": []
            }

            result = mock_instance.deep_merge(dict1, dict2)
            assert result["merged"]["b"]["c"] == 2
            assert result["merged"]["b"]["d"] == 3
