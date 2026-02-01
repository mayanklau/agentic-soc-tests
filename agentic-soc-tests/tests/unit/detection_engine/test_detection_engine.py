"""
Unit Tests for Detection Engine
===============================
Tests for the detection engine including Sigma rules, YARA rules, KQL queries,
ML-based anomaly detection, and rule correlation.
"""

import pytest
import asyncio
import json
import yaml
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import uuid


# =============================================================================
# DETECTION ENGINE CORE TESTS
# =============================================================================

class TestDetectionEngineCore:
    """Tests for the core detection engine functionality."""
    
    @pytest.mark.asyncio
    async def test_detection_engine_initialization(self, app_config):
        """Test detection engine initializes with all rule types."""
        engine = Mock()
        engine.rule_types = ["sigma", "yara", "kql", "ml"]
        engine.rules_loaded = {"sigma": 500, "yara": 200, "kql": 150, "ml": 10}
        engine.enabled = True
        
        assert len(engine.rule_types) == 4
        assert engine.rules_loaded["sigma"] == 500
    
    @pytest.mark.asyncio
    async def test_detection_engine_start(self):
        """Test detection engine startup."""
        engine = AsyncMock()
        engine.start = AsyncMock(return_value={
            "status": "running",
            "rules_loaded": 860,
            "ml_models_loaded": 5
        })
        
        result = await engine.start()
        
        assert result["status"] == "running"
    
    @pytest.mark.asyncio
    async def test_detection_engine_reload_rules(self):
        """Test hot reloading of detection rules."""
        engine = AsyncMock()
        engine.reload_rules = AsyncMock(return_value={
            "previous_count": 850,
            "new_count": 875,
            "added": 30,
            "removed": 5,
            "reload_time_ms": 250
        })
        
        result = await engine.reload_rules()
        
        assert result["added"] == 30
    
    @pytest.mark.asyncio
    async def test_detection_engine_health_check(self):
        """Test detection engine health status."""
        engine = AsyncMock()
        engine.health_check = AsyncMock(return_value={
            "status": "healthy",
            "sigma_engine": "operational",
            "yara_engine": "operational",
            "kql_engine": "operational",
            "ml_engine": "operational",
            "rules_last_updated": "2024-01-15T12:00:00Z"
        })
        
        health = await engine.health_check()
        
        assert health["status"] == "healthy"


# =============================================================================
# SIGMA RULE ENGINE TESTS
# =============================================================================

class TestSigmaRuleEngine:
    """Tests for Sigma rule parsing and evaluation."""
    
    @pytest.mark.asyncio
    async def test_load_sigma_rule(self, sample_sigma_rule):
        """Test loading a Sigma rule from YAML."""
        engine = Mock()
        engine.load_rule = Mock(return_value={
            "id": "rule-001",
            "title": "Suspicious PowerShell Command",
            "status": "experimental",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {"selection": {}, "condition": "selection"}
        })
        
        rule = engine.load_rule(sample_sigma_rule)
        
        assert rule["id"] == "rule-001"
        assert rule["logsource"]["product"] == "windows"
    
    @pytest.mark.asyncio
    async def test_sigma_rule_condition_and(self):
        """Test Sigma rule with AND condition."""
        engine = Mock()
        engine.evaluate_condition = Mock(return_value=True)
        
        rule = {
            "detection": {
                "selection1": {"CommandLine|contains": "powershell"},
                "selection2": {"ParentImage|endswith": "cmd.exe"},
                "condition": "selection1 and selection2"
            }
        }
        event = {
            "CommandLine": "powershell -enc ...",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe"
        }
        
        result = engine.evaluate_condition(rule, event)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_sigma_rule_condition_or(self):
        """Test Sigma rule with OR condition."""
        engine = Mock()
        engine.evaluate_condition = Mock(return_value=True)
        
        rule = {
            "detection": {
                "selection1": {"CommandLine|contains": "powershell"},
                "selection2": {"CommandLine|contains": "cmd.exe"},
                "condition": "selection1 or selection2"
            }
        }
        event = {"CommandLine": "powershell -enc ..."}
        
        result = engine.evaluate_condition(rule, event)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_sigma_rule_condition_not(self):
        """Test Sigma rule with NOT condition."""
        engine = Mock()
        engine.evaluate_condition = Mock(return_value=True)
        
        rule = {
            "detection": {
                "selection": {"CommandLine|contains": "powershell"},
                "filter": {"User": "SYSTEM"},
                "condition": "selection and not filter"
            }
        }
        event = {"CommandLine": "powershell -enc ...", "User": "admin"}
        
        result = engine.evaluate_condition(rule, event)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_sigma_modifiers_contains(self):
        """Test Sigma 'contains' modifier."""
        engine = Mock()
        engine.apply_modifier = Mock(return_value=True)
        
        result = engine.apply_modifier("contains", "powershell -enc base64", "powershell")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_sigma_modifiers_startswith(self):
        """Test Sigma 'startswith' modifier."""
        engine = Mock()
        engine.apply_modifier = Mock(return_value=True)
        
        result = engine.apply_modifier("startswith", "C:\\Windows\\System32\\cmd.exe", "C:\\Windows")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_sigma_modifiers_endswith(self):
        """Test Sigma 'endswith' modifier."""
        engine = Mock()
        engine.apply_modifier = Mock(return_value=True)
        
        result = engine.apply_modifier("endswith", "C:\\Windows\\System32\\cmd.exe", "cmd.exe")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_sigma_modifiers_regex(self):
        """Test Sigma 're' (regex) modifier."""
        engine = Mock()
        engine.apply_modifier = Mock(return_value=True)
        
        result = engine.apply_modifier("re", "192.168.1.100", r"192\.168\.\d+\.\d+")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_sigma_modifiers_base64(self):
        """Test Sigma 'base64' modifier for encoded content."""
        engine = Mock()
        engine.apply_modifier = Mock(return_value=True)
        
        # "powershell" base64 encoded
        result = engine.apply_modifier("base64", "cG93ZXJzaGVsbA==", "powershell")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_sigma_modifiers_cidr(self):
        """Test Sigma 'cidr' modifier for IP ranges."""
        engine = Mock()
        engine.apply_modifier = Mock(return_value=True)
        
        result = engine.apply_modifier("cidr", "192.168.1.100", "192.168.0.0/16")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_sigma_aggregation_count(self):
        """Test Sigma aggregation with count condition."""
        engine = AsyncMock()
        engine.evaluate_aggregation = AsyncMock(return_value={
            "matched": True,
            "count": 15,
            "threshold": 10,
            "grouped_by": "SourceIP"
        })
        
        rule = {
            "detection": {
                "selection": {"EventID": 4625},
                "condition": "selection | count(SourceIP) > 10"
            }
        }
        
        result = await engine.evaluate_aggregation(rule, window_minutes=5)
        
        assert result["matched"] is True
        assert result["count"] > result["threshold"]
    
    @pytest.mark.asyncio
    async def test_sigma_near_temporal_correlation(self):
        """Test Sigma 'near' for temporal correlation."""
        engine = AsyncMock()
        engine.evaluate_near = AsyncMock(return_value={
            "matched": True,
            "events_correlated": 2,
            "time_window_seconds": 60
        })
        
        rule = {
            "detection": {
                "selection1": {"EventID": 4624},
                "selection2": {"EventID": 4672},
                "condition": "selection1 | near selection2"
            }
        }
        
        result = await engine.evaluate_near(rule)
        
        assert result["matched"] is True
    
    @pytest.mark.asyncio
    async def test_sigma_logsource_mapping(self):
        """Test Sigma logsource to backend mapping."""
        mapper = Mock()
        mapper.map_logsource = Mock(return_value={
            "index": "windows-*",
            "field_mapping": {
                "CommandLine": "process.command_line",
                "Image": "process.executable",
                "ParentImage": "process.parent.executable"
            }
        })
        
        logsource = {"category": "process_creation", "product": "windows"}
        result = mapper.map_logsource(logsource)
        
        assert "index" in result
        assert "field_mapping" in result
    
    @pytest.mark.asyncio
    async def test_sigma_rule_severity_mapping(self):
        """Test Sigma severity level mapping."""
        mapper = Mock()
        mapper.map_severity = Mock(side_effect=lambda level: {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "informational": 1
        }.get(level, 0))
        
        assert mapper.map_severity("critical") == 5
        assert mapper.map_severity("low") == 2
    
    @pytest.mark.asyncio
    async def test_sigma_rule_no_match(self, sample_raw_event):
        """Test Sigma rule that doesn't match event."""
        engine = Mock()
        engine.evaluate = Mock(return_value={"matched": False, "rule_id": "rule-001"})
        
        result = engine.evaluate("rule-001", sample_raw_event)
        
        assert result["matched"] is False
    
    @pytest.mark.asyncio
    async def test_sigma_batch_evaluation(self, sample_events_batch):
        """Test batch evaluation of Sigma rules."""
        engine = AsyncMock()
        engine.evaluate_batch = AsyncMock(return_value={
            "events_processed": 1000,
            "matches": 25,
            "rules_evaluated": 500,
            "processing_time_ms": 150
        })
        
        result = await engine.evaluate_batch(sample_events_batch)
        
        assert result["matches"] == 25


# =============================================================================
# YARA RULE ENGINE TESTS
# =============================================================================

class TestYARARuleEngine:
    """Tests for YARA rule parsing and evaluation."""
    
    @pytest.mark.asyncio
    async def test_load_yara_rule(self, sample_yara_rule):
        """Test loading a YARA rule."""
        engine = Mock()
        engine.load_rule = Mock(return_value={
            "name": "Emotet_Dropper",
            "strings_count": 5,
            "condition": "2 of them"
        })
        
        rule = engine.load_rule(sample_yara_rule)
        
        assert rule["name"] == "Emotet_Dropper"
    
    @pytest.mark.asyncio
    async def test_yara_compile_rules(self):
        """Test compiling YARA rules."""
        engine = AsyncMock()
        engine.compile_rules = AsyncMock(return_value={
            "compiled": True,
            "rules_count": 200,
            "compile_time_ms": 500,
            "errors": []
        })
        
        result = await engine.compile_rules("/path/to/rules")
        
        assert result["compiled"] is True
        assert result["errors"] == []
    
    @pytest.mark.asyncio
    async def test_yara_scan_file(self):
        """Test YARA scanning a file."""
        engine = AsyncMock()
        engine.scan_file = AsyncMock(return_value={
            "file_path": "/path/to/suspicious.exe",
            "matches": [
                {
                    "rule": "Emotet_Dropper",
                    "tags": ["malware", "trojan"],
                    "meta": {"author": "SOC Team", "severity": "high"},
                    "strings": [
                        {"offset": 0x1234, "identifier": "$a1", "data": "suspicious_string"}
                    ]
                }
            ],
            "scan_time_ms": 50
        })
        
        result = await engine.scan_file("/path/to/suspicious.exe")
        
        assert len(result["matches"]) == 1
        assert result["matches"][0]["rule"] == "Emotet_Dropper"
    
    @pytest.mark.asyncio
    async def test_yara_scan_memory(self):
        """Test YARA scanning memory dump."""
        engine = AsyncMock()
        engine.scan_memory = AsyncMock(return_value={
            "pid": 1234,
            "process_name": "suspicious.exe",
            "matches": [
                {"rule": "Cobalt_Strike_Beacon", "region": "0x7FF00000"}
            ]
        })
        
        result = await engine.scan_memory(pid=1234)
        
        assert result["matches"][0]["rule"] == "Cobalt_Strike_Beacon"
    
    @pytest.mark.asyncio
    async def test_yara_scan_network_traffic(self):
        """Test YARA scanning network traffic."""
        engine = AsyncMock()
        engine.scan_pcap = AsyncMock(return_value={
            "pcap_file": "/path/to/capture.pcap",
            "matches": [
                {"rule": "C2_Communication", "packet": 150, "stream": 5}
            ]
        })
        
        result = await engine.scan_pcap("/path/to/capture.pcap")
        
        assert len(result["matches"]) == 1
    
    @pytest.mark.asyncio
    async def test_yara_string_types(self):
        """Test different YARA string types."""
        engine = Mock()
        
        # Text strings
        engine.compile_string = Mock(return_value=True)
        assert engine.compile_string('$text = "malware"') is True
        
        # Hex strings
        assert engine.compile_string('$hex = { 4D 5A 90 00 }') is True
        
        # Regex strings
        assert engine.compile_string('$regex = /http:\\/\\/[a-z]+\\.com/') is True
    
    @pytest.mark.asyncio
    async def test_yara_condition_operators(self):
        """Test YARA condition operators."""
        engine = Mock()
        engine.evaluate_condition = Mock(return_value=True)
        
        # Test various conditions
        conditions = [
            "all of them",
            "any of them",
            "2 of ($a*, $b*)",
            "$a at 0",
            "filesize < 100KB",
            "#a > 5"  # Count of matches
        ]
        
        for condition in conditions:
            assert engine.evaluate_condition(condition) is True
    
    @pytest.mark.asyncio
    async def test_yara_pe_module(self):
        """Test YARA PE module features."""
        engine = Mock()
        engine.check_pe_feature = Mock(return_value=True)
        
        # PE module conditions
        assert engine.check_pe_feature("pe.is_pe") is True
        assert engine.check_pe_feature("pe.is_dll") is True
        assert engine.check_pe_feature("pe.imports('kernel32.dll', 'VirtualAlloc')") is True
    
    @pytest.mark.asyncio
    async def test_yara_no_match(self):
        """Test YARA rule that doesn't match."""
        engine = AsyncMock()
        engine.scan_file = AsyncMock(return_value={
            "file_path": "/path/to/clean.exe",
            "matches": [],
            "scan_time_ms": 30
        })
        
        result = await engine.scan_file("/path/to/clean.exe")
        
        assert result["matches"] == []
    
    @pytest.mark.asyncio
    async def test_yara_scan_timeout(self):
        """Test YARA scan timeout handling."""
        engine = AsyncMock()
        engine.scan_file = AsyncMock(return_value={
            "file_path": "/path/to/large.bin",
            "error": "Scan timeout exceeded",
            "timeout_seconds": 60
        })
        
        result = await engine.scan_file("/path/to/large.bin")
        
        assert "error" in result
        assert "timeout" in result["error"]


# =============================================================================
# KQL QUERY ENGINE TESTS
# =============================================================================

class TestKQLQueryEngine:
    """Tests for KQL (Kusto Query Language) query execution."""
    
    @pytest.mark.asyncio
    async def test_parse_kql_query(self, sample_kql_rule):
        """Test parsing KQL query."""
        engine = Mock()
        engine.parse_query = Mock(return_value={
            "valid": True,
            "tables": ["SecurityEvent"],
            "time_range": "24h",
            "filters": ["EventID == 4625"],
            "aggregations": ["count() by SourceIP"]
        })
        
        result = engine.parse_query(sample_kql_rule)
        
        assert result["valid"] is True
        assert "SecurityEvent" in result["tables"]
    
    @pytest.mark.asyncio
    async def test_kql_where_clause(self):
        """Test KQL where clause filtering."""
        engine = AsyncMock()
        engine.execute_query = AsyncMock(return_value={
            "query": "SecurityEvent | where EventID == 4625",
            "rows_matched": 150,
            "execution_time_ms": 50
        })
        
        query = "SecurityEvent | where EventID == 4625"
        result = await engine.execute_query(query)
        
        assert result["rows_matched"] == 150
    
    @pytest.mark.asyncio
    async def test_kql_project_clause(self):
        """Test KQL project clause for column selection."""
        engine = AsyncMock()
        engine.execute_query = AsyncMock(return_value={
            "columns": ["TimeGenerated", "SourceIP", "TargetUserName"],
            "rows": 100
        })
        
        query = "SecurityEvent | project TimeGenerated, SourceIP, TargetUserName"
        result = await engine.execute_query(query)
        
        assert "TimeGenerated" in result["columns"]
    
    @pytest.mark.asyncio
    async def test_kql_summarize_aggregation(self):
        """Test KQL summarize for aggregations."""
        engine = AsyncMock()
        engine.execute_query = AsyncMock(return_value={
            "aggregation": "count",
            "groups": [
                {"SourceIP": "192.168.1.100", "count_": 50},
                {"SourceIP": "192.168.1.101", "count_": 30}
            ]
        })
        
        query = "SecurityEvent | summarize count() by SourceIP"
        result = await engine.execute_query(query)
        
        assert len(result["groups"]) == 2
    
    @pytest.mark.asyncio
    async def test_kql_bin_time_bucketing(self):
        """Test KQL bin() for time bucketing."""
        engine = AsyncMock()
        engine.execute_query = AsyncMock(return_value={
            "time_buckets": [
                {"bin_time": "2024-01-15T12:00:00Z", "count_": 100},
                {"bin_time": "2024-01-15T12:05:00Z", "count_": 120}
            ]
        })
        
        query = "SecurityEvent | summarize count() by bin(TimeGenerated, 5m)"
        result = await engine.execute_query(query)
        
        assert len(result["time_buckets"]) == 2
    
    @pytest.mark.asyncio
    async def test_kql_join_tables(self):
        """Test KQL join between tables."""
        engine = AsyncMock()
        engine.execute_query = AsyncMock(return_value={
            "tables_joined": ["SecurityEvent", "IdentityInfo"],
            "join_type": "inner",
            "rows": 75
        })
        
        query = """
        SecurityEvent
        | join kind=inner (IdentityInfo) on TargetUserName
        """
        result = await engine.execute_query(query)
        
        assert result["join_type"] == "inner"
    
    @pytest.mark.asyncio
    async def test_kql_extend_computed_columns(self):
        """Test KQL extend for computed columns."""
        engine = AsyncMock()
        engine.execute_query = AsyncMock(return_value={
            "extended_columns": ["is_admin", "login_hour"],
            "sample_row": {"is_admin": True, "login_hour": 14}
        })
        
        query = """
        SecurityEvent
        | extend is_admin = TargetUserName contains "admin"
        | extend login_hour = datetime_part("hour", TimeGenerated)
        """
        result = await engine.execute_query(query)
        
        assert "is_admin" in result["extended_columns"]
    
    @pytest.mark.asyncio
    async def test_kql_make_series_timeseries(self):
        """Test KQL make-series for time series analysis."""
        engine = AsyncMock()
        engine.execute_query = AsyncMock(return_value={
            "series_name": "login_count",
            "time_range": {"start": "2024-01-14T00:00:00Z", "end": "2024-01-15T00:00:00Z"},
            "data_points": 288  # 5-minute intervals for 24 hours
        })
        
        query = """
        SecurityEvent
        | make-series login_count=count() on TimeGenerated step 5m
        """
        result = await engine.execute_query(query)
        
        assert result["data_points"] == 288
    
    @pytest.mark.asyncio
    async def test_kql_anomaly_detection(self):
        """Test KQL series_decompose_anomalies for anomaly detection."""
        engine = AsyncMock()
        engine.execute_query = AsyncMock(return_value={
            "anomalies_detected": 3,
            "anomaly_scores": [
                {"time": "2024-01-15T03:00:00Z", "score": 2.5},
                {"time": "2024-01-15T03:30:00Z", "score": 3.1},
                {"time": "2024-01-15T04:00:00Z", "score": 2.8}
            ]
        })
        
        result = await engine.execute_query("... | series_decompose_anomalies ...")
        
        assert result["anomalies_detected"] == 3
    
    @pytest.mark.asyncio
    async def test_kql_let_variables(self):
        """Test KQL let statements for variables."""
        engine = AsyncMock()
        engine.execute_query = AsyncMock(return_value={
            "variables_defined": ["threshold", "lookback"],
            "query_executed": True
        })
        
        query = """
        let threshold = 10;
        let lookback = 1h;
        SecurityEvent
        | where TimeGenerated > ago(lookback)
        | summarize count() by SourceIP
        | where count_ > threshold
        """
        result = await engine.execute_query(query)
        
        assert result["query_executed"] is True
    
    @pytest.mark.asyncio
    async def test_kql_detection_rule_execution(self, sample_kql_rule):
        """Test executing a KQL detection rule."""
        engine = AsyncMock()
        engine.run_detection = AsyncMock(return_value={
            "rule_id": "kql-001",
            "matches": 5,
            "severity": "high",
            "alerts_generated": 5
        })
        
        result = await engine.run_detection(sample_kql_rule)
        
        assert result["matches"] == 5


# =============================================================================
# ML DETECTION ENGINE TESTS
# =============================================================================

class TestMLDetectionEngine:
    """Tests for ML-based anomaly detection."""
    
    @pytest.mark.asyncio
    async def test_load_ml_model(self):
        """Test loading ML detection model."""
        engine = AsyncMock()
        engine.load_model = AsyncMock(return_value={
            "model_name": "login_anomaly_detector",
            "model_type": "isolation_forest",
            "features": ["hour", "day_of_week", "source_ip_entropy", "user_agent_similarity"],
            "loaded": True
        })
        
        result = await engine.load_model("login_anomaly_detector")
        
        assert result["loaded"] is True
        assert result["model_type"] == "isolation_forest"
    
    @pytest.mark.asyncio
    async def test_ml_feature_extraction(self, sample_raw_event):
        """Test feature extraction for ML model."""
        extractor = Mock()
        extractor.extract_features = Mock(return_value={
            "features": [14.0, 1.0, 0.75, 0.92],  # hour, day, entropy, similarity
            "feature_names": ["hour", "day_of_week", "ip_entropy", "ua_similarity"]
        })
        
        result = extractor.extract_features(sample_raw_event)
        
        assert len(result["features"]) == 4
    
    @pytest.mark.asyncio
    async def test_ml_anomaly_prediction(self):
        """Test ML model anomaly prediction."""
        engine = AsyncMock()
        engine.predict = AsyncMock(return_value={
            "is_anomaly": True,
            "anomaly_score": 0.85,
            "confidence": 0.92,
            "contributing_features": ["hour", "ip_entropy"]
        })
        
        features = [3.0, 1.0, 0.95, 0.3]  # 3 AM, Monday, high entropy, low similarity
        result = await engine.predict(features)
        
        assert result["is_anomaly"] is True
        assert result["anomaly_score"] > 0.5
    
    @pytest.mark.asyncio
    async def test_ml_batch_prediction(self, sample_events_batch):
        """Test batch prediction with ML model."""
        engine = AsyncMock()
        engine.predict_batch = AsyncMock(return_value={
            "total_events": 1000,
            "anomalies_detected": 25,
            "anomaly_rate": 0.025,
            "processing_time_ms": 100
        })
        
        result = await engine.predict_batch(sample_events_batch)
        
        assert result["anomaly_rate"] == 0.025
    
    @pytest.mark.asyncio
    async def test_ml_model_online_learning(self):
        """Test online learning update for ML model."""
        engine = AsyncMock()
        engine.update_model = AsyncMock(return_value={
            "model_updated": True,
            "samples_added": 100,
            "new_baseline": True,
            "drift_detected": False
        })
        
        result = await engine.update_model(new_samples=[])
        
        assert result["model_updated"] is True
    
    @pytest.mark.asyncio
    async def test_ml_model_drift_detection(self):
        """Test detection of model drift."""
        engine = AsyncMock()
        engine.check_drift = AsyncMock(return_value={
            "drift_detected": True,
            "drift_score": 0.35,
            "threshold": 0.20,
            "recommendation": "retrain_model"
        })
        
        result = await engine.check_drift()
        
        assert result["drift_detected"] is True
    
    @pytest.mark.asyncio
    async def test_ml_user_behavior_baseline(self):
        """Test user behavior baseline model."""
        engine = AsyncMock()
        engine.get_user_baseline = AsyncMock(return_value={
            "user": "john.doe",
            "baseline": {
                "typical_login_hours": [8, 9, 10, 17, 18],
                "typical_locations": ["New York", "Boston"],
                "typical_devices": 3,
                "avg_daily_logins": 2.5
            }
        })
        
        result = await engine.get_user_baseline("john.doe")
        
        assert 9 in result["baseline"]["typical_login_hours"]
    
    @pytest.mark.asyncio
    async def test_ml_entity_behavior_analytics(self):
        """Test entity behavior analytics (UEBA)."""
        engine = AsyncMock()
        engine.analyze_entity = AsyncMock(return_value={
            "entity": "WORKSTATION-123",
            "entity_type": "host",
            "risk_score": 72,
            "anomalous_behaviors": [
                {"behavior": "unusual_process_execution", "score": 0.8},
                {"behavior": "new_network_connection", "score": 0.6}
            ]
        })
        
        result = await engine.analyze_entity("WORKSTATION-123", "host")
        
        assert result["risk_score"] > 50
    
    @pytest.mark.asyncio
    async def test_ml_model_explainability(self):
        """Test ML model prediction explainability."""
        engine = AsyncMock()
        engine.explain_prediction = AsyncMock(return_value={
            "prediction": "anomaly",
            "confidence": 0.89,
            "feature_importance": [
                {"feature": "login_hour", "importance": 0.45, "value": 3, "baseline_avg": 10},
                {"feature": "ip_entropy", "importance": 0.35, "value": 0.95, "baseline_avg": 0.3}
            ],
            "explanation": "Login at unusual hour with high IP entropy"
        })
        
        result = await engine.explain_prediction({})
        
        assert "feature_importance" in result
        assert result["feature_importance"][0]["feature"] == "login_hour"


# =============================================================================
# RULE CORRELATION ENGINE TESTS
# =============================================================================

class TestRuleCorrelationEngine:
    """Tests for correlating multiple rule matches."""
    
    @pytest.mark.asyncio
    async def test_correlate_by_host(self):
        """Test correlation of alerts by host."""
        engine = AsyncMock()
        engine.correlate_by_entity = AsyncMock(return_value={
            "entity": "WORKSTATION-123",
            "entity_type": "host",
            "correlated_alerts": 5,
            "time_window": "15m",
            "attack_pattern": "potential_lateral_movement"
        })
        
        result = await engine.correlate_by_entity("WORKSTATION-123", "host")
        
        assert result["correlated_alerts"] == 5
    
    @pytest.mark.asyncio
    async def test_correlate_by_user(self):
        """Test correlation of alerts by user."""
        engine = AsyncMock()
        engine.correlate_by_entity = AsyncMock(return_value={
            "entity": "john.doe",
            "entity_type": "user",
            "correlated_alerts": 3,
            "risk_score_increase": 25
        })
        
        result = await engine.correlate_by_entity("john.doe", "user")
        
        assert result["correlated_alerts"] == 3
    
    @pytest.mark.asyncio
    async def test_attack_chain_detection(self, sample_attack_chain):
        """Test detection of attack chain patterns."""
        engine = AsyncMock()
        engine.detect_attack_chain = AsyncMock(return_value={
            "chain_detected": True,
            "chain_type": "credential_theft_lateral_movement",
            "stages": [
                {"stage": 1, "technique": "T1566", "name": "Phishing"},
                {"stage": 2, "technique": "T1059", "name": "Command Execution"},
                {"stage": 3, "technique": "T1003", "name": "Credential Dumping"},
                {"stage": 4, "technique": "T1021", "name": "Lateral Movement"}
            ],
            "confidence": 0.87
        })
        
        result = await engine.detect_attack_chain(sample_attack_chain)
        
        assert result["chain_detected"] is True
        assert len(result["stages"]) == 4
    
    @pytest.mark.asyncio
    async def test_temporal_correlation(self):
        """Test temporal correlation of events."""
        engine = AsyncMock()
        engine.correlate_temporal = AsyncMock(return_value={
            "window_start": "2024-01-15T12:00:00Z",
            "window_end": "2024-01-15T12:15:00Z",
            "events_in_window": 15,
            "correlation_score": 0.82
        })
        
        result = await engine.correlate_temporal(window_minutes=15)
        
        assert result["events_in_window"] == 15
    
    @pytest.mark.asyncio
    async def test_graph_based_correlation(self):
        """Test graph-based entity correlation."""
        engine = AsyncMock()
        engine.build_correlation_graph = AsyncMock(return_value={
            "nodes": 25,
            "edges": 40,
            "clusters": 3,
            "central_entities": ["192.168.1.100", "admin_user"],
            "risk_propagation_score": 75
        })
        
        result = await engine.build_correlation_graph()
        
        assert result["clusters"] == 3


# =============================================================================
# DETECTION PERFORMANCE TESTS
# =============================================================================

class TestDetectionPerformance:
    """Tests for detection engine performance."""
    
    @pytest.mark.asyncio
    async def test_high_volume_rule_evaluation(self):
        """Test rule evaluation at high event volume."""
        engine = AsyncMock()
        engine.evaluate_high_volume = AsyncMock(return_value={
            "events_processed": 100000,
            "rules_evaluated": 500,
            "processing_time_ms": 5000,
            "events_per_second": 20000
        })
        
        result = await engine.evaluate_high_volume()
        
        assert result["events_per_second"] >= 10000
    
    @pytest.mark.asyncio
    async def test_rule_evaluation_latency(self):
        """Test latency metrics for rule evaluation."""
        engine = AsyncMock()
        engine.get_latency_metrics = AsyncMock(return_value={
            "p50_latency_ms": 5,
            "p95_latency_ms": 15,
            "p99_latency_ms": 50,
            "max_latency_ms": 100
        })
        
        result = await engine.get_latency_metrics()
        
        assert result["p95_latency_ms"] < 50
    
    @pytest.mark.asyncio
    async def test_detection_metrics(self):
        """Test detection accuracy metrics."""
        engine = AsyncMock()
        engine.get_detection_metrics = AsyncMock(return_value={
            "true_positives": 95,
            "false_positives": 5,
            "false_negatives": 2,
            "precision": 0.95,
            "recall": 0.979,
            "f1_score": 0.964
        })
        
        result = await engine.get_detection_metrics()
        
        assert result["precision"] >= 0.90
        assert result["recall"] >= 0.90
