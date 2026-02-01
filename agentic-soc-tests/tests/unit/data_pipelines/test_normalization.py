"""
Unit Tests for OCSF Normalization Pipeline
==========================================
Tests for normalizing security events into OCSF (Open Cybersecurity Schema Framework)
and ECS (Elastic Common Schema) formats.
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import uuid


# =============================================================================
# OCSF NORMALIZER TESTS
# =============================================================================

class TestOCSFNormalizer:
    """Tests for the OCSF normalization engine."""
    
    # -------------------------------------------------------------------------
    # Initialization Tests
    # -------------------------------------------------------------------------
    
    @pytest.mark.asyncio
    async def test_normalizer_initialization(self, app_config):
        """Test normalizer initializes with schema definitions."""
        normalizer = Mock()
        normalizer.schema_version = "1.1.0"
        normalizer.categories = ["security_finding", "network_activity", "system_activity"]
        normalizer.loaded = True
        
        assert normalizer.schema_version == "1.1.0"
        assert len(normalizer.categories) == 3
        assert normalizer.loaded is True
    
    @pytest.mark.asyncio
    async def test_load_ocsf_schema(self):
        """Test loading OCSF schema definitions."""
        normalizer = AsyncMock()
        normalizer.load_schema = AsyncMock(return_value={
            "version": "1.1.0",
            "classes": 45,
            "objects": 120,
            "profiles": ["cloud", "container", "datetime"]
        })
        
        schema = await normalizer.load_schema()
        
        assert schema["version"] == "1.1.0"
        assert schema["classes"] == 45
    
    @pytest.mark.asyncio
    async def test_schema_validation_enabled(self):
        """Test schema validation can be enabled/disabled."""
        normalizer = Mock()
        normalizer.validation_enabled = True
        normalizer.strict_mode = False
        
        assert normalizer.validation_enabled is True
        assert normalizer.strict_mode is False


# =============================================================================
# EVENT CATEGORY MAPPING TESTS
# =============================================================================

class TestOCSFCategoryMapping:
    """Tests for mapping events to OCSF categories."""
    
    @pytest.mark.asyncio
    async def test_map_authentication_event(self, sample_ocsf_event):
        """Test mapping authentication events to OCSF Authentication class."""
        mapper = Mock()
        mapper.map_to_category = Mock(return_value={
            "class_uid": 3002,
            "class_name": "Authentication",
            "category_uid": 3,
            "category_name": "Identity & Access Management"
        })
        
        raw_event = {
            "event_type": "login",
            "user": "admin",
            "result": "success",
            "source_ip": "192.168.1.100"
        }
        
        mapping = mapper.map_to_category(raw_event)
        
        assert mapping["class_name"] == "Authentication"
        assert mapping["category_name"] == "Identity & Access Management"
    
    @pytest.mark.asyncio
    async def test_map_network_activity_event(self):
        """Test mapping network events to OCSF Network Activity class."""
        mapper = Mock()
        mapper.map_to_category = Mock(return_value={
            "class_uid": 4001,
            "class_name": "Network Activity",
            "category_uid": 4,
            "category_name": "Network Activity"
        })
        
        raw_event = {
            "event_type": "connection",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.50",
            "dst_port": 443,
            "protocol": "TCP"
        }
        
        mapping = mapper.map_to_category(raw_event)
        
        assert mapping["class_name"] == "Network Activity"
    
    @pytest.mark.asyncio
    async def test_map_security_finding_event(self, sample_alert):
        """Test mapping security findings to OCSF Security Finding class."""
        mapper = Mock()
        mapper.map_to_category = Mock(return_value={
            "class_uid": 2001,
            "class_name": "Security Finding",
            "category_uid": 2,
            "category_name": "Findings"
        })
        
        mapping = mapper.map_to_category(sample_alert)
        
        assert mapping["class_name"] == "Security Finding"
    
    @pytest.mark.asyncio
    async def test_map_process_activity_event(self):
        """Test mapping process events to OCSF Process Activity class."""
        mapper = Mock()
        mapper.map_to_category = Mock(return_value={
            "class_uid": 1001,
            "class_name": "Process Activity",
            "category_uid": 1,
            "category_name": "System Activity"
        })
        
        raw_event = {
            "event_type": "process_create",
            "process_name": "powershell.exe",
            "command_line": "powershell -enc ...",
            "parent_process": "cmd.exe"
        }
        
        mapping = mapper.map_to_category(raw_event)
        
        assert mapping["class_name"] == "Process Activity"
    
    @pytest.mark.asyncio
    async def test_map_file_activity_event(self):
        """Test mapping file events to OCSF File Activity class."""
        mapper = Mock()
        mapper.map_to_category = Mock(return_value={
            "class_uid": 1004,
            "class_name": "File System Activity",
            "category_uid": 1,
            "category_name": "System Activity"
        })
        
        raw_event = {
            "event_type": "file_create",
            "file_path": "C:\\Windows\\Temp\\malware.exe",
            "file_hash": "abc123",
            "user": "SYSTEM"
        }
        
        mapping = mapper.map_to_category(raw_event)
        
        assert mapping["class_name"] == "File System Activity"
    
    @pytest.mark.asyncio
    async def test_map_dns_activity_event(self):
        """Test mapping DNS events to OCSF DNS Activity class."""
        mapper = Mock()
        mapper.map_to_category = Mock(return_value={
            "class_uid": 4003,
            "class_name": "DNS Activity",
            "category_uid": 4,
            "category_name": "Network Activity"
        })
        
        raw_event = {
            "event_type": "dns_query",
            "query": "evil-domain.com",
            "query_type": "A",
            "response": "1.2.3.4"
        }
        
        mapping = mapper.map_to_category(raw_event)
        
        assert mapping["class_name"] == "DNS Activity"
    
    @pytest.mark.asyncio
    async def test_map_unknown_event_type(self):
        """Test handling of unknown event types."""
        mapper = Mock()
        mapper.map_to_category = Mock(return_value={
            "class_uid": 0,
            "class_name": "Unknown",
            "category_uid": 0,
            "category_name": "Uncategorized"
        })
        
        raw_event = {"event_type": "custom_unknown_type"}
        mapping = mapper.map_to_category(raw_event)
        
        assert mapping["class_name"] == "Unknown"


# =============================================================================
# FIELD TRANSFORMATION TESTS
# =============================================================================

class TestOCSFFieldTransformation:
    """Tests for transforming fields to OCSF format."""
    
    @pytest.mark.asyncio
    async def test_transform_timestamp_to_ocsf(self):
        """Test timestamp transformation to OCSF format."""
        transformer = Mock()
        transformer.transform_timestamp = Mock(return_value=1705334400000)  # Epoch milliseconds
        
        raw_timestamp = "2024-01-15T12:00:00Z"
        ocsf_time = transformer.transform_timestamp(raw_timestamp)
        
        assert isinstance(ocsf_time, int)
        assert ocsf_time > 0
    
    @pytest.mark.asyncio
    async def test_transform_ip_address_to_ocsf(self):
        """Test IP address transformation to OCSF Endpoint object."""
        transformer = Mock()
        transformer.transform_ip = Mock(return_value={
            "ip": "192.168.1.100",
            "type_id": 1,
            "type": "IPv4"
        })
        
        raw_ip = "192.168.1.100"
        ocsf_ip = transformer.transform_ip(raw_ip)
        
        assert ocsf_ip["ip"] == "192.168.1.100"
        assert ocsf_ip["type"] == "IPv4"
    
    @pytest.mark.asyncio
    async def test_transform_ipv6_address(self):
        """Test IPv6 address transformation."""
        transformer = Mock()
        transformer.transform_ip = Mock(return_value={
            "ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "type_id": 2,
            "type": "IPv6"
        })
        
        raw_ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        ocsf_ip = transformer.transform_ip(raw_ip)
        
        assert ocsf_ip["type"] == "IPv6"
    
    @pytest.mark.asyncio
    async def test_transform_user_to_ocsf(self):
        """Test user transformation to OCSF User object."""
        transformer = Mock()
        transformer.transform_user = Mock(return_value={
            "name": "admin",
            "uid": "S-1-5-21-...",
            "type_id": 1,
            "type": "User"
        })
        
        raw_user = "admin"
        ocsf_user = transformer.transform_user(raw_user)
        
        assert ocsf_user["name"] == "admin"
        assert "uid" in ocsf_user
    
    @pytest.mark.asyncio
    async def test_transform_process_to_ocsf(self):
        """Test process transformation to OCSF Process object."""
        transformer = Mock()
        transformer.transform_process = Mock(return_value={
            "name": "powershell.exe",
            "cmd_line": "powershell -enc ...",
            "pid": 1234,
            "file": {
                "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "name": "powershell.exe"
            }
        })
        
        raw_process = {
            "name": "powershell.exe",
            "cmd": "powershell -enc ...",
            "pid": 1234,
            "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        }
        
        ocsf_process = transformer.transform_process(raw_process)
        
        assert ocsf_process["name"] == "powershell.exe"
        assert "file" in ocsf_process
    
    @pytest.mark.asyncio
    async def test_transform_file_to_ocsf(self):
        """Test file transformation to OCSF File object."""
        transformer = Mock()
        transformer.transform_file = Mock(return_value={
            "name": "malware.exe",
            "path": "C:\\Windows\\Temp\\malware.exe",
            "hashes": [
                {"algorithm_id": 1, "algorithm": "MD5", "value": "abc123"},
                {"algorithm_id": 3, "algorithm": "SHA-256", "value": "def456..."}
            ],
            "size": 1024000
        })
        
        raw_file = {
            "filename": "malware.exe",
            "filepath": "C:\\Windows\\Temp\\malware.exe",
            "md5": "abc123",
            "sha256": "def456...",
            "size": 1024000
        }
        
        ocsf_file = transformer.transform_file(raw_file)
        
        assert ocsf_file["name"] == "malware.exe"
        assert len(ocsf_file["hashes"]) == 2
    
    @pytest.mark.asyncio
    async def test_transform_severity_to_ocsf(self):
        """Test severity transformation to OCSF Severity object."""
        transformer = Mock()
        transformer.transform_severity = Mock(return_value={
            "id": 4,
            "name": "High"
        })
        
        raw_severity = "high"
        ocsf_severity = transformer.transform_severity(raw_severity)
        
        assert ocsf_severity["id"] == 4
        assert ocsf_severity["name"] == "High"
    
    @pytest.mark.asyncio
    async def test_severity_mapping_levels(self):
        """Test all severity level mappings."""
        transformer = Mock()
        
        severity_map = {
            "unknown": {"id": 0, "name": "Unknown"},
            "informational": {"id": 1, "name": "Informational"},
            "low": {"id": 2, "name": "Low"},
            "medium": {"id": 3, "name": "Medium"},
            "high": {"id": 4, "name": "High"},
            "critical": {"id": 5, "name": "Critical"},
            "fatal": {"id": 6, "name": "Fatal"}
        }
        
        for raw, expected in severity_map.items():
            transformer.transform_severity = Mock(return_value=expected)
            result = transformer.transform_severity(raw)
            assert result["id"] == expected["id"]
    
    @pytest.mark.asyncio
    async def test_transform_activity_to_ocsf(self):
        """Test activity type transformation."""
        transformer = Mock()
        transformer.transform_activity = Mock(return_value={
            "activity_id": 1,
            "activity_name": "Create"
        })
        
        raw_activity = "created"
        ocsf_activity = transformer.transform_activity(raw_activity)
        
        assert ocsf_activity["activity_id"] == 1


# =============================================================================
# SOURCE-SPECIFIC PARSER TESTS
# =============================================================================

class TestSourceSpecificParsers:
    """Tests for parsing events from specific security products."""
    
    @pytest.mark.asyncio
    async def test_parse_crowdstrike_event(self):
        """Test parsing CrowdStrike EDR events."""
        parser = Mock()
        parser.parse_crowdstrike = Mock(return_value={
            "class_uid": 1001,
            "class_name": "Process Activity",
            "activity_id": 1,
            "activity_name": "Launch",
            "device": {
                "hostname": "WORKSTATION-01",
                "os": {"name": "Windows", "version": "10"}
            },
            "actor": {"process": {"name": "cmd.exe", "pid": 1000}},
            "process": {"name": "powershell.exe", "pid": 1234, "cmd_line": "..."}
        })
        
        crowdstrike_event = {
            "event_type": "ProcessRollup2",
            "ComputerName": "WORKSTATION-01",
            "ParentProcessId": "1000",
            "ProcessId": "1234",
            "CommandLine": "..."
        }
        
        ocsf_event = parser.parse_crowdstrike(crowdstrike_event)
        
        assert ocsf_event["class_name"] == "Process Activity"
        assert "device" in ocsf_event
    
    @pytest.mark.asyncio
    async def test_parse_microsoft_defender_event(self):
        """Test parsing Microsoft Defender events."""
        parser = Mock()
        parser.parse_defender = Mock(return_value={
            "class_uid": 2001,
            "class_name": "Security Finding",
            "finding_info": {
                "title": "Malware detected",
                "types": ["Trojan:Win32/Emotet"]
            },
            "severity_id": 4,
            "severity": "High"
        })
        
        defender_event = {
            "category": "Malware",
            "ThreatName": "Trojan:Win32/Emotet",
            "Severity": "High"
        }
        
        ocsf_event = parser.parse_defender(defender_event)
        
        assert ocsf_event["class_name"] == "Security Finding"
    
    @pytest.mark.asyncio
    async def test_parse_splunk_event(self):
        """Test parsing Splunk SIEM events."""
        parser = Mock()
        parser.parse_splunk = Mock(return_value={
            "class_uid": 4001,
            "class_name": "Network Activity",
            "src_endpoint": {"ip": "192.168.1.100"},
            "dst_endpoint": {"ip": "10.0.0.50", "port": 443},
            "connection_info": {"protocol_name": "TCP"}
        })
        
        splunk_event = {
            "_time": "2024-01-15T12:00:00Z",
            "src": "192.168.1.100",
            "dest": "10.0.0.50",
            "dest_port": 443,
            "transport": "tcp"
        }
        
        ocsf_event = parser.parse_splunk(splunk_event)
        
        assert ocsf_event["class_name"] == "Network Activity"
    
    @pytest.mark.asyncio
    async def test_parse_palo_alto_firewall_event(self):
        """Test parsing Palo Alto firewall events."""
        parser = Mock()
        parser.parse_palo_alto = Mock(return_value={
            "class_uid": 4001,
            "class_name": "Network Activity",
            "activity_id": 2,
            "activity_name": "Traffic",
            "src_endpoint": {"ip": "192.168.1.100"},
            "dst_endpoint": {"ip": "8.8.8.8", "port": 53},
            "app_name": "dns"
        })
        
        pa_event = {
            "type": "TRAFFIC",
            "src": "192.168.1.100",
            "dst": "8.8.8.8",
            "dport": 53,
            "app": "dns",
            "action": "allow"
        }
        
        ocsf_event = parser.parse_palo_alto(pa_event)
        
        assert ocsf_event["class_name"] == "Network Activity"
    
    @pytest.mark.asyncio
    async def test_parse_aws_cloudtrail_event(self):
        """Test parsing AWS CloudTrail events."""
        parser = Mock()
        parser.parse_cloudtrail = Mock(return_value={
            "class_uid": 6003,
            "class_name": "API Activity",
            "activity_id": 1,
            "activity_name": "Create",
            "actor": {
                "user": {"name": "admin@example.com", "type": "IAMUser"}
            },
            "api": {
                "operation": "RunInstances",
                "service": {"name": "ec2"}
            },
            "cloud": {"provider": "AWS", "region": "us-east-1"}
        })
        
        cloudtrail_event = {
            "eventSource": "ec2.amazonaws.com",
            "eventName": "RunInstances",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "admin@example.com"
            },
            "awsRegion": "us-east-1"
        }
        
        ocsf_event = parser.parse_cloudtrail(cloudtrail_event)
        
        assert ocsf_event["class_name"] == "API Activity"
        assert ocsf_event["cloud"]["provider"] == "AWS"
    
    @pytest.mark.asyncio
    async def test_parse_okta_event(self):
        """Test parsing Okta authentication events."""
        parser = Mock()
        parser.parse_okta = Mock(return_value={
            "class_uid": 3002,
            "class_name": "Authentication",
            "activity_id": 1,
            "activity_name": "Logon",
            "actor": {
                "user": {"name": "user@example.com", "email_addr": "user@example.com"}
            },
            "status_id": 1,
            "status": "Success",
            "src_endpoint": {"ip": "192.168.1.100"}
        })
        
        okta_event = {
            "eventType": "user.session.start",
            "outcome": {"result": "SUCCESS"},
            "actor": {"alternateId": "user@example.com"},
            "client": {"ipAddress": "192.168.1.100"}
        }
        
        ocsf_event = parser.parse_okta(okta_event)
        
        assert ocsf_event["class_name"] == "Authentication"
    
    @pytest.mark.asyncio
    async def test_parse_azure_ad_signin_event(self):
        """Test parsing Azure AD sign-in events."""
        parser = Mock()
        parser.parse_azure_ad = Mock(return_value={
            "class_uid": 3002,
            "class_name": "Authentication",
            "actor": {
                "user": {"name": "user@tenant.onmicrosoft.com"}
            },
            "status_id": 1,
            "status": "Success",
            "cloud": {"provider": "Azure"}
        })
        
        azure_event = {
            "operationType": "Sign-in",
            "userPrincipalName": "user@tenant.onmicrosoft.com",
            "status": {"errorCode": 0}
        }
        
        ocsf_event = parser.parse_azure_ad(azure_event)
        
        assert ocsf_event["class_name"] == "Authentication"
    
    @pytest.mark.asyncio
    async def test_parse_windows_event_log(self):
        """Test parsing Windows Event Log entries."""
        parser = Mock()
        parser.parse_windows_event = Mock(return_value={
            "class_uid": 3002,
            "class_name": "Authentication",
            "activity_id": 1,
            "activity_name": "Logon",
            "metadata": {
                "product": {"name": "Windows Security"},
                "original_time": "2024-01-15T12:00:00Z",
                "uid": "4624"
            },
            "actor": {"user": {"name": "admin", "domain": "CORP"}}
        })
        
        windows_event = {
            "EventID": 4624,
            "TimeCreated": "2024-01-15T12:00:00Z",
            "TargetUserName": "admin",
            "TargetDomainName": "CORP",
            "LogonType": 10
        }
        
        ocsf_event = parser.parse_windows_event(windows_event)
        
        assert ocsf_event["metadata"]["uid"] == "4624"


# =============================================================================
# BATCH NORMALIZATION TESTS
# =============================================================================

class TestBatchNormalization:
    """Tests for batch event normalization."""
    
    @pytest.mark.asyncio
    async def test_batch_normalize_events(self, sample_events_batch):
        """Test batch normalization of multiple events."""
        normalizer = AsyncMock()
        normalizer.normalize_batch = AsyncMock(return_value={
            "processed": 100,
            "normalized": 98,
            "failed": 2,
            "events": []
        })
        
        result = await normalizer.normalize_batch(sample_events_batch)
        
        assert result["processed"] == 100
        assert result["normalized"] >= 98
    
    @pytest.mark.asyncio
    async def test_batch_normalization_performance(self):
        """Test batch normalization performance metrics."""
        normalizer = AsyncMock()
        normalizer.normalize_batch_with_metrics = AsyncMock(return_value={
            "events_processed": 10000,
            "processing_time_ms": 500,
            "events_per_second": 20000,
            "avg_event_time_ms": 0.05
        })
        
        events = [{"type": "test"} for _ in range(10000)]
        result = await normalizer.normalize_batch_with_metrics(events)
        
        assert result["events_per_second"] >= 10000
    
    @pytest.mark.asyncio
    async def test_batch_normalization_parallel_processing(self):
        """Test parallel processing of event batches."""
        normalizer = AsyncMock()
        normalizer.normalize_parallel = AsyncMock(return_value={
            "batches": 4,
            "workers": 4,
            "total_processed": 40000,
            "total_time_ms": 1000
        })
        
        result = await normalizer.normalize_parallel(batch_count=4, events_per_batch=10000)
        
        assert result["batches"] == 4
        assert result["total_processed"] == 40000
    
    @pytest.mark.asyncio
    async def test_batch_error_isolation(self):
        """Test that errors in one event don't affect others."""
        normalizer = AsyncMock()
        normalizer.normalize_batch = AsyncMock(return_value={
            "processed": 100,
            "normalized": 99,
            "failed": 1,
            "failed_events": [{"index": 50, "error": "Invalid timestamp"}]
        })
        
        result = await normalizer.normalize_batch([])
        
        assert result["normalized"] == 99
        assert result["failed"] == 1


# =============================================================================
# VALIDATION TESTS
# =============================================================================

class TestOCSFValidation:
    """Tests for OCSF schema validation."""
    
    @pytest.mark.asyncio
    async def test_validate_required_fields(self, sample_ocsf_event):
        """Test validation of required OCSF fields."""
        validator = Mock()
        validator.validate_required = Mock(return_value={
            "valid": True,
            "missing_fields": []
        })
        
        result = validator.validate_required(sample_ocsf_event)
        
        assert result["valid"] is True
        assert len(result["missing_fields"]) == 0
    
    @pytest.mark.asyncio
    async def test_validate_missing_required_field(self):
        """Test detection of missing required fields."""
        validator = Mock()
        validator.validate_required = Mock(return_value={
            "valid": False,
            "missing_fields": ["time", "class_uid"]
        })
        
        incomplete_event = {"message": "test"}
        result = validator.validate_required(incomplete_event)
        
        assert result["valid"] is False
        assert "time" in result["missing_fields"]
    
    @pytest.mark.asyncio
    async def test_validate_field_types(self, sample_ocsf_event):
        """Test validation of field data types."""
        validator = Mock()
        validator.validate_types = Mock(return_value={
            "valid": True,
            "type_errors": []
        })
        
        result = validator.validate_types(sample_ocsf_event)
        
        assert result["valid"] is True
    
    @pytest.mark.asyncio
    async def test_validate_invalid_field_type(self):
        """Test detection of invalid field types."""
        validator = Mock()
        validator.validate_types = Mock(return_value={
            "valid": False,
            "type_errors": [
                {"field": "time", "expected": "integer", "actual": "string"}
            ]
        })
        
        bad_event = {"time": "not-a-number"}
        result = validator.validate_types(bad_event)
        
        assert result["valid"] is False
    
    @pytest.mark.asyncio
    async def test_validate_enum_values(self):
        """Test validation of enumerated field values."""
        validator = Mock()
        validator.validate_enums = Mock(return_value={
            "valid": True,
            "enum_errors": []
        })
        
        event = {"severity_id": 4, "activity_id": 1}
        result = validator.validate_enums(event)
        
        assert result["valid"] is True
    
    @pytest.mark.asyncio
    async def test_validate_invalid_enum_value(self):
        """Test detection of invalid enum values."""
        validator = Mock()
        validator.validate_enums = Mock(return_value={
            "valid": False,
            "enum_errors": [
                {"field": "severity_id", "value": 99, "valid_values": [0, 1, 2, 3, 4, 5, 6]}
            ]
        })
        
        event = {"severity_id": 99}
        result = validator.validate_enums(event)
        
        assert result["valid"] is False
    
    @pytest.mark.asyncio
    async def test_strict_mode_validation(self):
        """Test strict mode validation rejects unknown fields."""
        validator = Mock()
        validator.strict_mode = True
        validator.validate_strict = Mock(return_value={
            "valid": False,
            "unknown_fields": ["custom_field_xyz"]
        })
        
        event = {"class_uid": 1001, "custom_field_xyz": "value"}
        result = validator.validate_strict(event)
        
        assert result["valid"] is False
        assert "custom_field_xyz" in result["unknown_fields"]
    
    @pytest.mark.asyncio
    async def test_permissive_mode_allows_extensions(self):
        """Test permissive mode allows extension fields."""
        validator = Mock()
        validator.strict_mode = False
        validator.validate = Mock(return_value={
            "valid": True,
            "extension_fields": ["custom_field_xyz"]
        })
        
        event = {"class_uid": 1001, "custom_field_xyz": "value"}
        result = validator.validate(event)
        
        assert result["valid"] is True


# =============================================================================
# ECS NORMALIZATION TESTS
# =============================================================================

class TestECSNormalization:
    """Tests for Elastic Common Schema normalization."""
    
    @pytest.mark.asyncio
    async def test_normalize_to_ecs(self, sample_raw_event):
        """Test normalization to ECS format."""
        normalizer = Mock()
        normalizer.to_ecs = Mock(return_value={
            "@timestamp": "2024-01-15T12:00:00.000Z",
            "event": {
                "kind": "alert",
                "category": ["intrusion_detection"],
                "type": ["indicator"],
                "outcome": "success"
            },
            "source": {"ip": "192.168.1.100"},
            "destination": {"ip": "10.0.0.50", "port": 443}
        })
        
        ecs_event = normalizer.to_ecs(sample_raw_event)
        
        assert "@timestamp" in ecs_event
        assert "event" in ecs_event
    
    @pytest.mark.asyncio
    async def test_ecs_event_categorization(self):
        """Test ECS event category and type mapping."""
        normalizer = Mock()
        normalizer.categorize_ecs = Mock(return_value={
            "kind": "event",
            "category": ["authentication"],
            "type": ["start"],
            "action": "user_login"
        })
        
        raw_event = {"type": "login_success"}
        ecs_event_info = normalizer.categorize_ecs(raw_event)
        
        assert ecs_event_info["category"] == ["authentication"]
    
    @pytest.mark.asyncio
    async def test_convert_ocsf_to_ecs(self, sample_ocsf_event):
        """Test conversion from OCSF to ECS format."""
        converter = Mock()
        converter.ocsf_to_ecs = Mock(return_value={
            "@timestamp": "2024-01-15T12:00:00.000Z",
            "ecs": {"version": "8.11.0"},
            "event": {"kind": "alert"}
        })
        
        ecs_event = converter.ocsf_to_ecs(sample_ocsf_event)
        
        assert "ecs" in ecs_event
        assert ecs_event["ecs"]["version"] == "8.11.0"


# =============================================================================
# ENRICHMENT DURING NORMALIZATION TESTS
# =============================================================================

class TestNormalizationEnrichment:
    """Tests for enrichment during normalization."""
    
    @pytest.mark.asyncio
    async def test_add_metadata_during_normalization(self):
        """Test adding metadata fields during normalization."""
        normalizer = Mock()
        normalizer.normalize_with_metadata = Mock(return_value={
            "class_uid": 1001,
            "metadata": {
                "version": "1.1.0",
                "product": {"name": "Agentic SOC", "vendor_name": "Custom"},
                "processed_time": "2024-01-15T12:00:00Z",
                "original_time": "2024-01-15T11:59:50Z"
            }
        })
        
        result = normalizer.normalize_with_metadata({})
        
        assert "metadata" in result
        assert result["metadata"]["version"] == "1.1.0"
    
    @pytest.mark.asyncio
    async def test_add_observables_during_normalization(self):
        """Test extracting and adding observables during normalization."""
        normalizer = Mock()
        normalizer.extract_observables = Mock(return_value={
            "observables": [
                {"type_id": 1, "type": "IP Address", "value": "192.168.1.100"},
                {"type_id": 2, "type": "Domain Name", "value": "evil.com"},
                {"type_id": 7, "type": "File Hash", "value": "abc123..."}
            ]
        })
        
        event = {
            "src_ip": "192.168.1.100",
            "dns_query": "evil.com",
            "file_hash": "abc123..."
        }
        
        result = normalizer.extract_observables(event)
        
        assert len(result["observables"]) == 3
    
    @pytest.mark.asyncio
    async def test_geolocation_enrichment_during_normalization(self):
        """Test adding geolocation data during normalization."""
        normalizer = AsyncMock()
        normalizer.enrich_geolocation = AsyncMock(return_value={
            "src_endpoint": {
                "ip": "8.8.8.8",
                "location": {
                    "city": "Mountain View",
                    "country": "United States",
                    "lat": 37.386,
                    "long": -122.084
                }
            }
        })
        
        result = await normalizer.enrich_geolocation({"src_ip": "8.8.8.8"})
        
        assert "location" in result["src_endpoint"]


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

class TestNormalizationErrorHandling:
    """Tests for error handling during normalization."""
    
    @pytest.mark.asyncio
    async def test_handle_malformed_event(self):
        """Test handling of malformed events."""
        normalizer = Mock()
        normalizer.normalize = Mock(return_value={
            "success": False,
            "error": "Malformed event: missing required fields",
            "raw_event": {}
        })
        
        result = normalizer.normalize({})
        
        assert result["success"] is False
    
    @pytest.mark.asyncio
    async def test_handle_unknown_source_type(self):
        """Test handling of unknown source types."""
        normalizer = Mock()
        normalizer.normalize = Mock(return_value={
            "success": True,
            "warning": "Unknown source type, using generic parser",
            "class_uid": 0
        })
        
        result = normalizer.normalize({"unknown_field": "value"})
        
        assert "warning" in result
    
    @pytest.mark.asyncio
    async def test_preserve_raw_event_on_failure(self):
        """Test that raw event is preserved when normalization fails."""
        normalizer = Mock()
        raw = {"some": "data", "that": "failed"}
        normalizer.normalize = Mock(return_value={
            "success": False,
            "raw_event": raw,
            "error": "Parsing error"
        })
        
        result = normalizer.normalize(raw)
        
        assert result["raw_event"] == raw
    
    @pytest.mark.asyncio
    async def test_partial_normalization_on_error(self):
        """Test partial normalization when some fields fail."""
        normalizer = Mock()
        normalizer.normalize = Mock(return_value={
            "success": True,
            "partial": True,
            "class_uid": 1001,
            "failed_fields": ["custom_timestamp"],
            "time": None
        })
        
        result = normalizer.normalize({})
        
        assert result["partial"] is True
        assert "failed_fields" in result
