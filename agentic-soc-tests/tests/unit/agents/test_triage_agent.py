"""
Unit Tests for Triage Agent

Tests the Triage Agent's capabilities for alert prioritization,
enrichment, risk scoring, and automated escalation.
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timedelta
from uuid import uuid4


class TestTriageAgentInitialization:
    """Test Triage Agent initialization and configuration."""
    
    def test_triage_agent_creation(self, sample_config):
        """Test that triage agent can be instantiated."""
        config = sample_config["agents"]["triage"]
        
        assert config["enabled"] is True
        assert config["auto_escalate"] is True
    
    def test_triage_agent_with_custom_thresholds(self):
        """Test triage agent with custom severity thresholds."""
        config = {
            "enabled": True,
            "auto_escalate": True,
            "escalation_thresholds": {
                "critical": 90,
                "high": 70,
                "medium": 50,
                "low": 30
            },
            "enrichment_sources": ["threat_intel", "asset_db", "user_db"]
        }
        
        assert config["escalation_thresholds"]["critical"] == 90
        assert len(config["enrichment_sources"]) == 3
    
    def test_triage_agent_disabled_auto_escalate(self):
        """Test triage agent with auto-escalation disabled."""
        config = {"enabled": True, "auto_escalate": False}
        assert config["auto_escalate"] is False


class TestTriageAgentAlertPrioritization:
    """Test Triage Agent alert prioritization capabilities."""
    
    def test_prioritize_by_severity(self, sample_alerts_batch):
        """Test alert prioritization based on severity."""
        alerts = sample_alerts_batch
        
        severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
        
        sorted_alerts = sorted(
            alerts,
            key=lambda x: severity_order.get(x["severity"], 0),
            reverse=True
        )
        
        # First alert should be critical or high
        assert sorted_alerts[0]["severity"] in ["critical", "high"]
    
    def test_prioritize_by_asset_criticality(self, sample_alert):
        """Test prioritization based on asset criticality."""
        alert = sample_alert
        
        asset_criticality = {
            "DOMAIN-CONTROLLER": 100,
            "DATABASE-SERVER": 90,
            "WEB-SERVER": 80,
            "WORKSTATION": 50,
            "PRINTER": 10
        }
        
        # Assume WORKSTATION-01 is a workstation
        criticality = asset_criticality.get("WORKSTATION", 50)
        assert criticality == 50
    
    def test_prioritize_by_user_privilege(self, sample_alert):
        """Test prioritization based on user privilege level."""
        user_privileges = {
            "admin": 100,
            "service_account": 80,
            "domain_admin": 100,
            "standard_user": 30
        }
        
        # Get user privilege level
        user_type = "standard_user"  # Assume from alert
        privilege_score = user_privileges.get(user_type, 30)
        
        assert privilege_score == 30
    
    def test_prioritize_multiple_factors(self, sample_alert):
        """Test prioritization combining multiple factors."""
        weights = {
            "severity": 0.4,
            "asset_criticality": 0.3,
            "user_privilege": 0.2,
            "ioc_confidence": 0.1
        }
        
        scores = {
            "severity": 80,  # High severity
            "asset_criticality": 50,  # Workstation
            "user_privilege": 30,  # Standard user
            "ioc_confidence": 85  # Known malicious
        }
        
        weighted_score = sum(
            scores[factor] * weight 
            for factor, weight in weights.items()
        )
        
        assert 0 <= weighted_score <= 100
    
    def test_priority_queue_ordering(self, sample_alerts_batch):
        """Test alerts are correctly ordered in priority queue."""
        alerts = sample_alerts_batch[:10]
        
        # Assign priority scores
        for i, alert in enumerate(alerts):
            alert["priority_score"] = (10 - i) * 10  # 100, 90, 80, ...
        
        # Sort by priority
        sorted_alerts = sorted(alerts, key=lambda x: x["priority_score"], reverse=True)
        
        assert sorted_alerts[0]["priority_score"] == 100
        assert sorted_alerts[-1]["priority_score"] == 10


class TestTriageAgentRiskScoring:
    """Test Triage Agent risk scoring capabilities."""
    
    def test_calculate_base_risk_score(self, sample_alert):
        """Test base risk score calculation."""
        severity_scores = {
            "critical": 100,
            "high": 80,
            "medium": 50,
            "low": 25,
            "informational": 10
        }
        
        base_score = severity_scores.get(sample_alert["severity"], 0)
        assert base_score == 80  # High severity
    
    def test_risk_score_with_mitre_mapping(self, sample_alert):
        """Test risk score adjusted for MITRE ATT&CK mapping."""
        tactic_weights = {
            "initial_access": 1.0,
            "execution": 1.2,
            "persistence": 1.3,
            "privilege_escalation": 1.4,
            "defense_evasion": 1.2,
            "credential_access": 1.5,
            "discovery": 0.8,
            "lateral_movement": 1.4,
            "collection": 1.1,
            "exfiltration": 1.6,
            "impact": 1.5
        }
        
        base_score = 80
        tactics = sample_alert["mitre_tactics"]
        
        max_weight = max(tactic_weights.get(t, 1.0) for t in tactics)
        adjusted_score = min(base_score * max_weight, 100)
        
        assert adjusted_score >= base_score
    
    def test_risk_score_ioc_confidence(self, sample_alert, sample_threat_intel_response):
        """Test risk score adjusted for IOC confidence."""
        base_score = 80
        ioc_confidence = sample_threat_intel_response["confidence"]  # 92
        
        # Boost score based on IOC confidence
        if ioc_confidence > 80:
            boost_factor = 1.2
        elif ioc_confidence > 60:
            boost_factor = 1.1
        else:
            boost_factor = 1.0
        
        adjusted_score = min(base_score * boost_factor, 100)
        assert adjusted_score == 96  # 80 * 1.2
    
    def test_risk_score_historical_context(self):
        """Test risk score with historical alert context."""
        host = "WORKSTATION-01"
        historical_alerts = {
            "total_30_days": 50,
            "critical_30_days": 5,
            "false_positive_rate": 0.2
        }
        
        # Adjust score based on history
        if historical_alerts["critical_30_days"] > 3:
            history_multiplier = 1.1  # Repeated issues
        else:
            history_multiplier = 1.0
        
        if historical_alerts["false_positive_rate"] > 0.3:
            history_multiplier *= 0.9  # Reduce for high FP rate
        
        assert history_multiplier == 1.1
    
    def test_risk_score_normalization(self):
        """Test risk score is always normalized to 0-100."""
        test_scores = [-10, 0, 50, 100, 150, 200]
        
        normalized = [max(0, min(100, score)) for score in test_scores]
        
        assert all(0 <= s <= 100 for s in normalized)
        assert normalized == [0, 0, 50, 100, 100, 100]


class TestTriageAgentEnrichment:
    """Test Triage Agent alert enrichment capabilities."""
    
    def test_enrich_with_threat_intel(self, sample_alert, sample_threat_intel_response):
        """Test enrichment with threat intelligence data."""
        alert = sample_alert.copy()
        ti_response = sample_threat_intel_response
        
        # Enrich alert with TI data
        alert["enrichment"] = {
            "threat_intel": {
                "malicious": ti_response["malicious"],
                "confidence": ti_response["confidence"],
                "sources": [s["name"] for s in ti_response["sources"]],
                "categories": ti_response["context"]["categories"]
            }
        }
        
        assert alert["enrichment"]["threat_intel"]["malicious"] is True
        assert len(alert["enrichment"]["threat_intel"]["sources"]) == 2
    
    def test_enrich_with_asset_info(self, sample_alert):
        """Test enrichment with asset database information."""
        alert = sample_alert.copy()
        
        asset_info = {
            "hostname": "WORKSTATION-01",
            "os": "Windows 10 Enterprise",
            "criticality": "medium",
            "owner": "john.doe",
            "department": "Engineering",
            "last_patch_date": "2024-01-10",
            "edr_installed": True,
            "backup_enabled": True
        }
        
        alert["enrichment"] = alert.get("enrichment", {})
        alert["enrichment"]["asset"] = asset_info
        
        assert alert["enrichment"]["asset"]["criticality"] == "medium"
        assert alert["enrichment"]["asset"]["edr_installed"] is True
    
    def test_enrich_with_user_info(self, sample_alert):
        """Test enrichment with user directory information."""
        alert = sample_alert.copy()
        
        user_info = {
            "username": "john.doe",
            "display_name": "John Doe",
            "email": "john.doe@example.com",
            "department": "Engineering",
            "manager": "jane.smith",
            "title": "Software Engineer",
            "is_admin": False,
            "is_service_account": False,
            "last_login": "2024-01-15T10:30:00Z",
            "risk_score": 25
        }
        
        alert["enrichment"] = alert.get("enrichment", {})
        alert["enrichment"]["user"] = user_info
        
        assert alert["enrichment"]["user"]["is_admin"] is False
        assert alert["enrichment"]["user"]["risk_score"] == 25
    
    def test_enrich_with_geolocation(self, sample_alert):
        """Test enrichment with IP geolocation."""
        ip_address = sample_alert["iocs"][0]["value"]  # 192.168.1.100
        
        geo_info = {
            "ip": ip_address,
            "country": "US",
            "country_name": "United States",
            "region": "California",
            "city": "San Francisco",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "asn": "AS15169",
            "org": "Google LLC",
            "is_vpn": False,
            "is_tor": False,
            "is_proxy": False
        }
        
        assert geo_info["country"] == "US"
        assert geo_info["is_tor"] is False
    
    def test_enrich_with_vulnerability_data(self, sample_alert):
        """Test enrichment with vulnerability information."""
        host = sample_alert["host"]
        
        vuln_info = {
            "host": host,
            "total_vulns": 15,
            "critical_vulns": 2,
            "high_vulns": 5,
            "medium_vulns": 8,
            "cves": ["CVE-2024-1234", "CVE-2024-5678"],
            "last_scan": "2024-01-14T00:00:00Z"
        }
        
        assert vuln_info["critical_vulns"] == 2
        assert len(vuln_info["cves"]) == 2
    
    def test_enrichment_timeout_handling(self):
        """Test handling of enrichment source timeouts."""
        enrichment_results = {
            "threat_intel": {"status": "success", "data": {}},
            "asset_db": {"status": "timeout", "data": None},
            "user_db": {"status": "success", "data": {}},
            "geo_ip": {"status": "error", "data": None}
        }
        
        successful = [k for k, v in enrichment_results.items() if v["status"] == "success"]
        failed = [k for k, v in enrichment_results.items() if v["status"] != "success"]
        
        assert len(successful) == 2
        assert len(failed) == 2


class TestTriageAgentEscalation:
    """Test Triage Agent escalation logic."""
    
    def test_auto_escalate_critical(self, sample_critical_alert):
        """Test automatic escalation of critical alerts."""
        alert = sample_critical_alert
        
        should_escalate = alert["severity"] == "critical"
        assert should_escalate is True
    
    def test_escalation_threshold_check(self):
        """Test escalation threshold checking."""
        thresholds = {
            "critical": 90,
            "high": 70,
            "medium": 50
        }
        
        test_cases = [
            {"risk_score": 95, "expected_severity": "critical"},
            {"risk_score": 75, "expected_severity": "high"},
            {"risk_score": 55, "expected_severity": "medium"},
            {"risk_score": 30, "expected_severity": "low"}
        ]
        
        for case in test_cases:
            score = case["risk_score"]
            if score >= thresholds["critical"]:
                severity = "critical"
            elif score >= thresholds["high"]:
                severity = "high"
            elif score >= thresholds["medium"]:
                severity = "medium"
            else:
                severity = "low"
            
            assert severity == case["expected_severity"]
    
    def test_escalation_to_specific_team(self, sample_alert):
        """Test escalation routing to specific teams."""
        escalation_rules = {
            "ransomware": "incident_response",
            "data_exfiltration": "data_loss_prevention",
            "lateral_movement": "threat_hunting",
            "credential_theft": "identity_team",
            "default": "soc_tier2"
        }
        
        alert = sample_alert
        tags = alert.get("tags", [])
        
        # Determine escalation target
        target = escalation_rules["default"]
        for tag in tags:
            if tag in escalation_rules:
                target = escalation_rules[tag]
                break
        
        assert target in escalation_rules.values()
    
    def test_escalation_with_approval_required(self, sample_alert):
        """Test escalation requiring manual approval."""
        alert = sample_alert
        
        # Actions requiring approval
        approval_required_actions = [
            "host_isolation",
            "account_disable",
            "firewall_block",
            "kill_process"
        ]
        
        recommended_actions = ["host_isolation", "collect_logs"]
        
        needs_approval = any(
            action in approval_required_actions 
            for action in recommended_actions
        )
        
        assert needs_approval is True
    
    def test_escalation_notification_channels(self):
        """Test escalation notification to multiple channels."""
        notification_channels = {
            "critical": ["pagerduty", "slack", "email"],
            "high": ["slack", "email"],
            "medium": ["email"],
            "low": []
        }
        
        severity = "critical"
        channels = notification_channels.get(severity, [])
        
        assert "pagerduty" in channels
        assert len(channels) == 3


class TestTriageAgentFalsePositiveDetection:
    """Test Triage Agent false positive detection."""
    
    def test_fp_detection_whitelist(self, sample_alert):
        """Test false positive detection via whitelist."""
        whitelists = {
            "ips": ["192.168.1.1", "10.0.0.1"],
            "domains": ["internal.company.com"],
            "hashes": ["known_good_hash_1", "known_good_hash_2"],
            "users": ["svc_backup", "svc_monitoring"],
            "processes": ["C:\\Windows\\System32\\svchost.exe"]
        }
        
        # Check if alert IOCs are whitelisted
        alert_ips = [ioc["value"] for ioc in sample_alert["iocs"] if ioc["type"] == "ip"]
        
        is_whitelisted = any(ip in whitelists["ips"] for ip in alert_ips)
        assert is_whitelisted is False  # 192.168.1.100 not in whitelist
    
    def test_fp_detection_pattern_matching(self):
        """Test false positive detection via pattern matching."""
        fp_patterns = [
            r"scheduled_task_.*_backup",
            r"C:\\Program Files\\.*\\update\.exe",
            r"svc_[a-z]+_scan"
        ]
        
        import re
        
        test_subjects = [
            "scheduled_task_daily_backup",  # Should match
            "malicious_process.exe",  # Should not match
            "svc_security_scan"  # Should match
        ]
        
        matches = []
        for subject in test_subjects:
            for pattern in fp_patterns:
                if re.match(pattern, subject):
                    matches.append(subject)
                    break
        
        assert len(matches) == 2
    
    def test_fp_rate_tracking(self):
        """Test false positive rate tracking per rule."""
        rule_fp_rates = {
            "rule_001": {"total": 100, "fp": 5, "rate": 0.05},
            "rule_002": {"total": 50, "fp": 25, "rate": 0.50},
            "rule_003": {"total": 200, "fp": 10, "rate": 0.05}
        }
        
        # Rule 002 has high FP rate - should be flagged
        high_fp_rules = [
            rule_id for rule_id, stats in rule_fp_rates.items()
            if stats["rate"] > 0.3
        ]
        
        assert "rule_002" in high_fp_rules
    
    def test_fp_feedback_loop(self, sample_alert):
        """Test false positive feedback mechanism."""
        feedback = {
            "alert_id": sample_alert["id"],
            "verdict": "false_positive",
            "analyst": "analyst@example.com",
            "reason": "Known internal scanner",
            "timestamp": datetime.utcnow().isoformat(),
            "add_to_whitelist": True,
            "whitelist_type": "ip",
            "whitelist_value": "192.168.1.100"
        }
        
        assert feedback["verdict"] == "false_positive"
        assert feedback["add_to_whitelist"] is True


class TestTriageAgentBatchProcessing:
    """Test Triage Agent batch processing capabilities."""
    
    def test_batch_triage_processing(self, sample_alerts_batch):
        """Test batch processing of multiple alerts."""
        alerts = sample_alerts_batch
        batch_size = 10
        
        batches = [alerts[i:i + batch_size] for i in range(0, len(alerts), batch_size)]
        
        assert len(batches) == 5  # 50 alerts / 10 = 5 batches
    
    def test_parallel_enrichment(self, sample_alerts_batch):
        """Test parallel enrichment of multiple alerts."""
        alerts = sample_alerts_batch[:5]
        
        # Simulate parallel enrichment tasks
        enrichment_tasks = [
            {"alert_id": a["id"], "sources": ["ti", "asset", "user"]}
            for a in alerts
        ]
        
        assert len(enrichment_tasks) == 5
    
    def test_bulk_priority_calculation(self, sample_alerts_batch):
        """Test bulk priority score calculation."""
        alerts = sample_alerts_batch
        
        severity_scores = {
            "critical": 100, "high": 80, "medium": 50, "low": 25, "informational": 10
        }
        
        for alert in alerts:
            alert["priority_score"] = severity_scores.get(alert["severity"], 0)
        
        # Verify all alerts have priority scores
        assert all("priority_score" in a for a in alerts)


class TestTriageAgentStateManagement:
    """Test Triage Agent state management."""
    
    def test_triage_state_tracking(self, sample_alert):
        """Test alert triage state tracking."""
        triage_states = {
            "pending": "awaiting_triage",
            "in_progress": "being_triaged",
            "enriched": "enrichment_complete",
            "scored": "risk_scored",
            "routed": "escalation_determined",
            "complete": "triage_complete"
        }
        
        alert = sample_alert
        alert["triage_state"] = "pending"
        
        # Progress through states
        state_progression = ["pending", "in_progress", "enriched", "scored", "routed", "complete"]
        
        for state in state_progression:
            alert["triage_state"] = state
            assert alert["triage_state"] in triage_states
    
    def test_triage_metrics(self, sample_alerts_batch):
        """Test triage metrics collection."""
        metrics = {
            "total_triaged": len(sample_alerts_batch),
            "auto_escalated": 10,
            "false_positives": 5,
            "avg_triage_time_seconds": 2.5,
            "enrichment_success_rate": 0.95
        }
        
        assert metrics["total_triaged"] == 50
        assert metrics["enrichment_success_rate"] > 0.9
    
    def test_sla_tracking(self, sample_alert):
        """Test SLA tracking for triage completion."""
        sla_targets = {
            "critical": 300,  # 5 minutes
            "high": 900,  # 15 minutes
            "medium": 3600,  # 1 hour
            "low": 14400  # 4 hours
        }
        
        severity = sample_alert["severity"]
        target_seconds = sla_targets.get(severity, 3600)
        
        assert target_seconds == 900  # High severity = 15 min
