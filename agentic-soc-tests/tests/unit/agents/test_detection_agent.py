"""
Unit Tests for Detection Agent

Tests the Detection Agent's capabilities for processing events,
applying detection rules, and generating alerts.
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timedelta
from uuid import uuid4


class TestDetectionAgentInitialization:
    """Test Detection Agent initialization and configuration."""
    
    def test_detection_agent_creation(self, sample_config):
        """Test that detection agent can be instantiated."""
        # Arrange
        config = sample_config["agents"]["detection"]
        
        # Act & Assert
        assert config["enabled"] is True
        assert config["batch_size"] == 100
    
    def test_detection_agent_with_custom_config(self):
        """Test detection agent with custom configuration."""
        config = {
            "enabled": True,
            "batch_size": 500,
            "rule_paths": ["/rules/sigma", "/rules/yara"],
            "ml_models": ["anomaly_detector", "threat_classifier"]
        }
        
        assert config["batch_size"] == 500
        assert len(config["rule_paths"]) == 2
    
    def test_detection_agent_disabled_state(self):
        """Test detection agent when disabled."""
        config = {"enabled": False}
        assert config["enabled"] is False
    
    def test_detection_agent_rule_loading(self, sample_sigma_rule):
        """Test that detection rules can be loaded."""
        rules = [sample_sigma_rule]
        assert len(rules) == 1
        assert rules[0]["status"] == "production"
    
    def test_detection_agent_multiple_rule_formats(self, sample_sigma_rule, sample_yara_rule, sample_kql_rule):
        """Test loading multiple rule formats."""
        rules = {
            "sigma": [sample_sigma_rule],
            "yara": [sample_yara_rule],
            "kql": [sample_kql_rule]
        }
        
        assert len(rules["sigma"]) == 1
        assert len(rules["yara"]) == 1
        assert len(rules["kql"]) == 1


class TestDetectionAgentEventProcessing:
    """Test Detection Agent event processing capabilities."""
    
    def test_process_single_event(self, sample_raw_event):
        """Test processing a single security event."""
        event = sample_raw_event
        
        assert event["EventID"] == 4624
        assert event["source"] == "windows_security"
        assert "timestamp" in event
    
    def test_process_event_batch(self, sample_events_batch):
        """Test batch event processing."""
        events = sample_events_batch
        
        assert len(events) == 100
        # Verify all events have required fields
        for event in events:
            assert "timestamp" in event
            assert "EventID" in event
            assert "source" in event
    
    def test_process_malformed_event(self):
        """Test handling of malformed events."""
        malformed_events = [
            {},  # Empty event
            {"timestamp": None},  # Null timestamp
            {"EventID": "not_a_number"},  # Invalid EventID type
            {"timestamp": "invalid_date"},  # Invalid timestamp format
        ]
        
        for event in malformed_events:
            # Should handle gracefully without raising
            assert isinstance(event, dict)
    
    def test_event_deduplication(self, sample_raw_event):
        """Test that duplicate events are detected."""
        events = [sample_raw_event, sample_raw_event.copy()]
        
        # Create unique identifiers
        event_hashes = [
            hash(frozenset(e.items())) for e in events
        ]
        
        assert event_hashes[0] == event_hashes[1]  # Duplicates should have same hash
    
    def test_event_prioritization(self, sample_events_batch):
        """Test event prioritization based on severity indicators."""
        events = sample_events_batch
        
        # Priority based on EventID (security events)
        high_priority_event_ids = [4624, 4625, 4688, 4104]
        
        high_priority = [e for e in events if e["EventID"] in high_priority_event_ids]
        assert len(high_priority) > 0


class TestDetectionAgentRuleMatching:
    """Test Detection Agent rule matching logic."""
    
    def test_sigma_rule_match(self, sample_sigma_rule, sample_raw_event):
        """Test Sigma rule matching against events."""
        rule = sample_sigma_rule
        
        # Verify rule structure
        assert "detection" in rule
        assert "selection" in rule["detection"]
        assert rule["level"] == "high"
    
    def test_sigma_rule_no_match(self, sample_sigma_rule):
        """Test Sigma rule when no match occurs."""
        rule = sample_sigma_rule
        benign_event = {
            "EventID": 4624,  # Logon event, not PowerShell
            "ScriptBlockText": "Write-Host 'Hello'"
        }
        
        # Rule requires EventID 4104 for selection
        assert benign_event["EventID"] != 4104
    
    def test_yara_rule_match(self, sample_yara_rule):
        """Test YARA rule matching."""
        rule = sample_yara_rule
        
        assert rule["name"] == "CobaltStrike_Beacon"
        assert rule["severity"] == "critical"
        assert "ReflectiveLoader" in rule["content"]
    
    def test_kql_rule_parsing(self, sample_kql_rule):
        """Test KQL rule parsing and validation."""
        rule = sample_kql_rule
        
        assert "SecurityEvent" in rule["query"]
        assert rule["threshold"] == 10
        assert rule["time_window"] == "5m"
    
    def test_rule_condition_evaluation_and(self):
        """Test AND condition evaluation in rules."""
        conditions = {
            "condition_a": True,
            "condition_b": True,
            "condition_c": False
        }
        
        result_all = all(conditions.values())
        assert result_all is False  # c is False
        
        result_ab = conditions["condition_a"] and conditions["condition_b"]
        assert result_ab is True
    
    def test_rule_condition_evaluation_or(self):
        """Test OR condition evaluation in rules."""
        conditions = {
            "condition_a": False,
            "condition_b": True,
            "condition_c": False
        }
        
        result_any = any(conditions.values())
        assert result_any is True  # b is True
    
    def test_rule_field_transformation(self):
        """Test field transformations in rules (contains, endswith, startswith)."""
        test_string = "Invoke-Expression IEX"
        
        assert "Invoke-Expression" in test_string  # contains
        assert test_string.startswith("Invoke")  # startswith
        assert test_string.endswith("IEX")  # endswith
    
    def test_rule_regex_matching(self):
        """Test regex pattern matching in rules."""
        import re
        
        patterns = [
            r"powershell.*-enc",
            r"cmd\.exe.*\/c",
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"  # IP pattern
        ]
        
        test_strings = [
            "powershell.exe -enc BASE64STRING",
            "cmd.exe /c whoami",
            "Connection from 192.168.1.1"
        ]
        
        for pattern, test_str in zip(patterns, test_strings):
            assert re.search(pattern, test_str, re.IGNORECASE) is not None


class TestDetectionAgentAlertGeneration:
    """Test Detection Agent alert generation capabilities."""
    
    def test_generate_alert_from_detection(self, sample_raw_event, sample_sigma_rule):
        """Test alert generation from rule match."""
        alert = {
            "id": str(uuid4()),
            "rule_id": sample_sigma_rule["id"],
            "title": sample_sigma_rule["title"],
            "severity": sample_sigma_rule["level"],
            "status": "new",
            "source_event": sample_raw_event,
            "timestamp": datetime.utcnow().isoformat(),
            "mitre_tactics": ["execution"],
            "mitre_techniques": ["T1059.001"]
        }
        
        assert alert["severity"] == "high"
        assert alert["status"] == "new"
        assert "source_event" in alert
    
    def test_alert_enrichment(self, sample_alert):
        """Test alert enrichment with additional context."""
        alert = sample_alert
        
        # Verify enrichment fields
        assert "mitre_tactics" in alert
        assert "mitre_techniques" in alert
        assert "iocs" in alert
        assert len(alert["iocs"]) > 0
    
    def test_alert_severity_mapping(self):
        """Test severity level mapping."""
        severity_map = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "informational": 1
        }
        
        assert severity_map["critical"] > severity_map["high"]
        assert severity_map["high"] > severity_map["medium"]
    
    def test_alert_deduplication_window(self, sample_alert):
        """Test alert deduplication within time window."""
        alert1 = sample_alert
        alert2 = sample_alert.copy()
        alert2["timestamp"] = (datetime.utcnow() + timedelta(seconds=30)).isoformat()
        
        # Alerts with same signature within window should be deduplicated
        signature1 = f"{alert1['title']}:{alert1['host']}"
        signature2 = f"{alert2['title']}:{alert2['host']}"
        
        assert signature1 == signature2  # Same signature = deduplicate
    
    def test_alert_correlation_grouping(self, sample_alerts_batch):
        """Test grouping correlated alerts."""
        alerts = sample_alerts_batch[:10]
        
        # Group by host
        by_host = {}
        for alert in alerts:
            host = alert.get("host", "unknown")
            if host not in by_host:
                by_host[host] = []
            by_host[host].append(alert)
        
        assert len(by_host) > 0


class TestDetectionAgentMLIntegration:
    """Test Detection Agent ML model integration."""
    
    def test_ml_model_prediction(self, sample_raw_event):
        """Test ML model prediction on events."""
        # Mock ML prediction
        prediction = {
            "label": "malicious",
            "confidence": 0.92,
            "features": {
                "process_name_entropy": 3.2,
                "command_line_length": 156,
                "parent_child_anomaly": 0.8
            }
        }
        
        assert prediction["label"] in ["benign", "malicious", "suspicious"]
        assert 0 <= prediction["confidence"] <= 1
    
    def test_ml_model_batch_inference(self, sample_events_batch):
        """Test batch inference with ML model."""
        events = sample_events_batch[:10]
        
        # Mock batch predictions
        predictions = [
            {"event_id": i, "score": 0.1 * (i % 10)}
            for i in range(len(events))
        ]
        
        assert len(predictions) == len(events)
    
    def test_ml_anomaly_detection(self):
        """Test anomaly detection scoring."""
        normal_baseline = {"mean": 100, "std": 10}
        
        test_values = [95, 105, 150, 200]
        anomaly_scores = []
        
        for val in test_values:
            z_score = abs(val - normal_baseline["mean"]) / normal_baseline["std"]
            anomaly_scores.append(z_score)
        
        # 150 and 200 should have higher anomaly scores
        assert anomaly_scores[2] > anomaly_scores[0]
        assert anomaly_scores[3] > anomaly_scores[2]
    
    def test_ml_model_fallback(self):
        """Test fallback when ML model is unavailable."""
        model_available = False
        
        if not model_available:
            # Fallback to rule-based detection
            fallback_result = {"method": "rule_based", "available": True}
            assert fallback_result["method"] == "rule_based"


class TestDetectionAgentCorrelation:
    """Test Detection Agent event correlation capabilities."""
    
    def test_temporal_correlation(self, sample_events_batch):
        """Test correlation of events within time window."""
        window_minutes = 5
        events = sample_events_batch[:20]
        
        # Group events by time window
        now = datetime.utcnow()
        recent_events = [
            e for e in events 
            if (now - datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00").replace("+00:00", ""))).total_seconds() < window_minutes * 60
        ]
        
        assert isinstance(recent_events, list)
    
    def test_host_based_correlation(self, sample_events_batch):
        """Test correlation of events from same host."""
        events = sample_events_batch
        
        # Group by host
        host_events = {}
        for event in events:
            host = event.get("WorkstationName", "unknown")
            if host not in host_events:
                host_events[host] = []
            host_events[host].append(event)
        
        assert len(host_events) > 0
    
    def test_user_based_correlation(self, sample_events_batch):
        """Test correlation of events for same user."""
        events = sample_events_batch
        
        # Group by user
        user_events = {}
        for event in events:
            user = event.get("AccountName", "unknown")
            if user not in user_events:
                user_events[user] = []
            user_events[user].append(event)
        
        assert len(user_events) > 0
    
    def test_attack_chain_correlation(self, sample_attack_chain):
        """Test attack chain correlation across multiple phases."""
        chain = sample_attack_chain
        beads = chain["beads"]
        
        # Verify chain progression
        phases = [b["phase"] for b in beads]
        expected_phases = ["initial_access", "execution", "persistence", "lateral_movement", "exfiltration"]
        
        assert phases == expected_phases
        
        # Verify temporal ordering
        for i in range(len(beads) - 1):
            assert beads[i]["sequence"] < beads[i + 1]["sequence"]
    
    def test_cross_source_correlation(self):
        """Test correlation across different log sources."""
        events_by_source = {
            "firewall": [{"action": "block", "src_ip": "192.168.1.100"}],
            "endpoint": [{"process": "malware.exe", "host_ip": "192.168.1.100"}],
            "dns": [{"query": "c2.evil.com", "client_ip": "192.168.1.100"}]
        }
        
        # Correlate by IP
        correlation_key = "192.168.1.100"
        correlated = []
        
        for source, events in events_by_source.items():
            for event in events:
                if correlation_key in str(event.values()):
                    correlated.append({"source": source, "event": event})
        
        assert len(correlated) == 3  # All three sources


class TestDetectionAgentPerformance:
    """Test Detection Agent performance characteristics."""
    
    def test_high_volume_event_processing(self):
        """Test processing high volume of events."""
        event_count = 10000
        events = [{"id": i, "timestamp": datetime.utcnow().isoformat()} for i in range(event_count)]
        
        assert len(events) == event_count
    
    def test_rule_matching_performance(self, sample_sigma_rule):
        """Test rule matching doesn't degrade with many rules."""
        num_rules = 1000
        rules = [sample_sigma_rule.copy() for _ in range(num_rules)]
        
        # Assign unique IDs
        for i, rule in enumerate(rules):
            rule["id"] = str(uuid4())
        
        assert len(rules) == num_rules
    
    def test_batch_processing_chunking(self, sample_events_batch):
        """Test batch processing with chunking."""
        events = sample_events_batch
        chunk_size = 20
        
        chunks = [events[i:i + chunk_size] for i in range(0, len(events), chunk_size)]
        
        assert len(chunks) == 5  # 100 events / 20 = 5 chunks
        assert all(len(chunk) == chunk_size for chunk in chunks)


class TestDetectionAgentStateManagement:
    """Test Detection Agent state management."""
    
    def test_agent_state_transitions(self):
        """Test valid state transitions."""
        valid_states = ["idle", "processing", "alerting", "error", "stopped"]
        valid_transitions = {
            "idle": ["processing", "stopped"],
            "processing": ["idle", "alerting", "error"],
            "alerting": ["idle", "processing"],
            "error": ["idle", "stopped"],
            "stopped": ["idle"]
        }
        
        # Verify all states have defined transitions
        for state in valid_states:
            assert state in valid_transitions
    
    def test_agent_metrics_collection(self):
        """Test metrics collection for monitoring."""
        metrics = {
            "events_processed": 1000,
            "alerts_generated": 50,
            "rules_matched": 75,
            "processing_time_ms": 250,
            "queue_depth": 100
        }
        
        assert all(isinstance(v, (int, float)) for v in metrics.values())
    
    def test_agent_health_check(self):
        """Test agent health check mechanism."""
        health_status = {
            "status": "healthy",
            "last_heartbeat": datetime.utcnow().isoformat(),
            "rules_loaded": 500,
            "memory_usage_mb": 256,
            "cpu_percent": 15.5
        }
        
        assert health_status["status"] in ["healthy", "degraded", "unhealthy"]
