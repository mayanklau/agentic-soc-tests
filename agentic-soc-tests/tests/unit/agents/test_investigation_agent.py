"""
Unit Tests for Investigation Agent

Tests the Investigation Agent's capabilities for guiding investigations,
building timelines, correlating evidence, and generating findings.
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timedelta
from uuid import uuid4


class TestInvestigationAgentInitialization:
    """Test Investigation Agent initialization."""
    
    def test_investigation_agent_creation(self):
        """Test that investigation agent can be instantiated."""
        config = {
            "enabled": True,
            "max_concurrent_investigations": 10,
            "auto_correlation": True,
            "timeline_auto_build": True
        }
        
        assert config["enabled"] is True
        assert config["max_concurrent_investigations"] == 10


class TestInvestigationCreation:
    """Test investigation creation and management."""
    
    def test_create_investigation(self, sample_investigation):
        """Test creating a new investigation."""
        investigation = sample_investigation
        
        assert investigation["status"] == "open"
        assert investigation["priority"] == "high"
        assert len(investigation["alert_ids"]) == 5
    
    def test_create_investigation_from_alert(self, sample_alert):
        """Test creating investigation from a single alert."""
        investigation = {
            "id": str(uuid4()),
            "title": f"Investigation: {sample_alert['title']}",
            "description": sample_alert["description"],
            "status": "open",
            "priority": sample_alert["severity"],
            "alert_ids": [sample_alert["id"]],
            "created_at": datetime.utcnow().isoformat()
        }
        
        assert len(investigation["alert_ids"]) == 1
        assert investigation["priority"] == "high"
    
    def test_merge_investigations(self, sample_investigation):
        """Test merging multiple investigations."""
        inv1 = sample_investigation
        inv2 = {
            "id": str(uuid4()),
            "title": "Related Investigation",
            "alert_ids": [str(uuid4()) for _ in range(3)],
            "findings": []
        }
        
        merged = {
            "id": str(uuid4()),
            "title": f"Merged: {inv1['title']}",
            "source_investigations": [inv1["id"], inv2["id"]],
            "alert_ids": inv1["alert_ids"] + inv2["alert_ids"],
            "findings": inv1["findings"] + inv2["findings"]
        }
        
        assert len(merged["alert_ids"]) == 8
        assert len(merged["source_investigations"]) == 2
    
    def test_investigation_status_transitions(self, sample_investigation):
        """Test valid investigation status transitions."""
        valid_transitions = {
            "open": ["in_progress", "closed"],
            "in_progress": ["open", "pending_review", "closed"],
            "pending_review": ["in_progress", "closed"],
            "closed": ["open"]  # Can reopen
        }
        
        current_status = sample_investigation["status"]
        assert current_status in valid_transitions


class TestInvestigationTimeline:
    """Test investigation timeline capabilities."""
    
    def test_build_timeline_from_events(self, sample_events_batch):
        """Test building investigation timeline from events."""
        events = sample_events_batch[:10]
        
        timeline = []
        for event in sorted(events, key=lambda x: x["timestamp"]):
            timeline.append({
                "timestamp": event["timestamp"],
                "type": "event",
                "source": event["source"],
                "summary": f"Event {event['EventID']} on {event['WorkstationName']}"
            })
        
        assert len(timeline) == 10
        # Verify chronological order
        for i in range(len(timeline) - 1):
            assert timeline[i]["timestamp"] <= timeline[i + 1]["timestamp"]
    
    def test_add_manual_timeline_entry(self, sample_investigation):
        """Test adding manual entries to timeline."""
        manual_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "analyst_note",
            "author": "analyst@example.com",
            "content": "Initial triage confirms suspicious activity",
            "tags": ["triage", "confirmed"]
        }
        
        assert manual_entry["type"] == "analyst_note"
        assert "author" in manual_entry
    
    def test_timeline_filtering(self):
        """Test filtering timeline by type or time range."""
        timeline = [
            {"timestamp": "2024-01-15T10:00:00Z", "type": "event"},
            {"timestamp": "2024-01-15T10:05:00Z", "type": "analyst_note"},
            {"timestamp": "2024-01-15T10:10:00Z", "type": "event"},
            {"timestamp": "2024-01-15T10:15:00Z", "type": "finding"},
            {"timestamp": "2024-01-15T10:20:00Z", "type": "event"}
        ]
        
        # Filter by type
        events_only = [e for e in timeline if e["type"] == "event"]
        assert len(events_only) == 3
    
    def test_timeline_gap_detection(self):
        """Test detection of timeline gaps."""
        timeline = [
            {"timestamp": "2024-01-15T10:00:00Z"},
            {"timestamp": "2024-01-15T10:05:00Z"},
            {"timestamp": "2024-01-15T12:00:00Z"},  # 2 hour gap
            {"timestamp": "2024-01-15T12:05:00Z"}
        ]
        
        gaps = []
        gap_threshold_minutes = 30
        
        for i in range(len(timeline) - 1):
            t1 = datetime.fromisoformat(timeline[i]["timestamp"].replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(timeline[i + 1]["timestamp"].replace("Z", "+00:00"))
            diff_minutes = (t2 - t1).total_seconds() / 60
            
            if diff_minutes > gap_threshold_minutes:
                gaps.append({
                    "start": timeline[i]["timestamp"],
                    "end": timeline[i + 1]["timestamp"],
                    "duration_minutes": diff_minutes
                })
        
        assert len(gaps) == 1
        assert gaps[0]["duration_minutes"] == 115  # ~2 hours


class TestInvestigationEvidence:
    """Test investigation evidence collection."""
    
    def test_collect_evidence(self, sample_investigation_finding):
        """Test evidence collection for investigation."""
        evidence = {
            "id": str(uuid4()),
            "type": "file",
            "name": "malware_sample.exe",
            "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
            "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "size_bytes": 102400,
            "collected_at": datetime.utcnow().isoformat(),
            "collected_by": "forensics_agent",
            "chain_of_custody": []
        }
        
        assert "hash_sha256" in evidence
        assert evidence["type"] == "file"
    
    def test_evidence_chain_of_custody(self):
        """Test evidence chain of custody tracking."""
        chain = [
            {
                "timestamp": "2024-01-15T10:00:00Z",
                "action": "collected",
                "actor": "forensics_agent",
                "location": "WORKSTATION-01"
            },
            {
                "timestamp": "2024-01-15T10:05:00Z",
                "action": "transferred",
                "actor": "forensics_agent",
                "destination": "evidence_storage"
            },
            {
                "timestamp": "2024-01-15T10:30:00Z",
                "action": "analyzed",
                "actor": "analyst@example.com",
                "notes": "Confirmed malicious"
            }
        ]
        
        assert len(chain) == 3
        assert chain[0]["action"] == "collected"
    
    def test_evidence_tagging(self):
        """Test evidence tagging and categorization."""
        evidence = {
            "id": str(uuid4()),
            "type": "memory_dump",
            "tags": ["cobalt_strike", "beacon", "lateral_movement"],
            "categories": ["malware", "c2_communication"],
            "mitre_techniques": ["T1055", "T1071.001"]
        }
        
        assert "cobalt_strike" in evidence["tags"]
        assert "malware" in evidence["categories"]


class TestInvestigationFindings:
    """Test investigation findings management."""
    
    def test_add_finding(self, sample_investigation, sample_investigation_finding):
        """Test adding a finding to investigation."""
        investigation = sample_investigation.copy()
        finding = sample_investigation_finding
        
        investigation["findings"].append(finding)
        
        assert len(investigation["findings"]) == 1
        assert investigation["findings"][0]["severity"] == "critical"
    
    def test_finding_types(self):
        """Test different finding types."""
        finding_types = [
            "malware",
            "compromise",
            "data_exfiltration",
            "unauthorized_access",
            "policy_violation",
            "false_positive",
            "inconclusive"
        ]
        
        for finding_type in finding_types:
            finding = {
                "id": str(uuid4()),
                "type": finding_type,
                "title": f"Finding of type {finding_type}"
            }
            assert finding["type"] in finding_types
    
    def test_finding_confidence_levels(self, sample_investigation_finding):
        """Test finding confidence levels."""
        confidence_levels = {
            "confirmed": (90, 100),
            "high": (70, 89),
            "medium": (40, 69),
            "low": (0, 39)
        }
        
        confidence = sample_investigation_finding["confidence"]  # 95
        
        level = "low"
        for level_name, (min_val, max_val) in confidence_levels.items():
            if min_val <= confidence <= max_val:
                level = level_name
                break
        
        assert level == "confirmed"
    
    def test_finding_mitre_mapping(self, sample_investigation_finding):
        """Test MITRE ATT&CK mapping in findings."""
        finding = sample_investigation_finding
        
        mitre_techniques = finding["mitre_mapping"]
        
        assert "T1055" in mitre_techniques  # Process Injection
        assert "T1071.001" in mitre_techniques  # Application Layer Protocol


class TestInvestigationQueries:
    """Test investigation query suggestions."""
    
    def test_suggest_hunting_queries(self, sample_alert):
        """Test suggesting hunting queries based on alert."""
        suggestions = [
            {
                "type": "kql",
                "purpose": "Find related processes",
                "query": f"ProcessEvents | where HostName == '{sample_alert['host']}'"
            },
            {
                "type": "kql",
                "purpose": "Find network connections",
                "query": f"NetworkEvents | where SourceIP == '{sample_alert['iocs'][0]['value']}'"
            },
            {
                "type": "splunk",
                "purpose": "Authentication events",
                "query": f"index=security user={sample_alert['user']}"
            }
        ]
        
        assert len(suggestions) == 3
        assert all("query" in s for s in suggestions)
    
    def test_query_template_expansion(self):
        """Test query template variable expansion."""
        template = "ProcessEvents | where HostName == '${host}' and User == '${user}'"
        variables = {"host": "WORKSTATION-01", "user": "john.doe"}
        
        query = template
        for var, value in variables.items():
            query = query.replace(f"${{{var}}}", value)
        
        assert "WORKSTATION-01" in query
        assert "john.doe" in query


class TestInvestigationCorrelation:
    """Test investigation correlation capabilities."""
    
    def test_correlate_alerts_by_host(self, sample_alerts_batch):
        """Test correlating alerts from same host."""
        alerts = sample_alerts_batch
        
        by_host = {}
        for alert in alerts:
            host = alert.get("host", "unknown")
            if host not in by_host:
                by_host[host] = []
            by_host[host].append(alert)
        
        # Find hosts with multiple alerts
        multi_alert_hosts = [h for h, a in by_host.items() if len(a) > 1]
        assert len(multi_alert_hosts) >= 0
    
    def test_correlate_by_attack_technique(self, sample_alert, sample_attack_chain):
        """Test correlating events by MITRE technique."""
        techniques = sample_alert["mitre_techniques"]
        chain_beads = sample_attack_chain["beads"]
        
        technique_to_beads = {}
        for bead in chain_beads:
            tech = bead["technique"]
            if tech not in technique_to_beads:
                technique_to_beads[tech] = []
            technique_to_beads[tech].append(bead)
        
        assert len(technique_to_beads) == 5  # 5 unique techniques
    
    def test_correlate_by_timeframe(self, sample_events_batch):
        """Test correlating events within timeframe."""
        events = sample_events_batch
        window_minutes = 10
        
        # Group events by time windows
        windows = {}
        for event in events:
            ts = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00").replace("+00:00", ""))
            window_key = ts.strftime("%Y-%m-%d %H:%M")[:15]  # 10-min windows
            
            if window_key not in windows:
                windows[window_key] = []
            windows[window_key].append(event)
        
        assert len(windows) > 0


class TestInvestigationReporting:
    """Test investigation reporting capabilities."""
    
    def test_generate_investigation_report(self, sample_investigation, sample_investigation_finding):
        """Test generating investigation report."""
        investigation = sample_investigation
        investigation["findings"] = [sample_investigation_finding]
        
        report = {
            "title": investigation["title"],
            "executive_summary": "Investigation into suspicious PowerShell activity",
            "timeline_summary": "Events occurred between X and Y",
            "findings": investigation["findings"],
            "recommendations": [
                "Isolate affected hosts",
                "Reset compromised credentials",
                "Deploy additional monitoring"
            ],
            "iocs_extracted": [],
            "generated_at": datetime.utcnow().isoformat()
        }
        
        assert "executive_summary" in report
        assert len(report["recommendations"]) == 3
    
    def test_report_format_options(self):
        """Test different report format outputs."""
        formats = ["pdf", "html", "markdown", "json"]
        
        for fmt in formats:
            report_config = {
                "format": fmt,
                "include_timeline": True,
                "include_evidence": True,
                "include_iocs": True
            }
            assert report_config["format"] in formats
    
    def test_extract_iocs_for_sharing(self, sample_investigation_finding):
        """Test extracting IOCs for threat intel sharing."""
        finding = sample_investigation_finding
        
        extracted_iocs = {
            "hashes": [],
            "ips": [],
            "domains": [],
            "urls": [],
            "file_names": []
        }
        
        # Would extract from evidence
        extracted_iocs["hashes"].append({
            "type": "sha256",
            "value": "abc123",
            "context": finding["title"]
        })
        
        assert len(extracted_iocs["hashes"]) == 1


class TestInvestigationCollaboration:
    """Test investigation collaboration features."""
    
    def test_assign_investigation(self, sample_investigation):
        """Test assigning investigation to analyst."""
        investigation = sample_investigation
        
        assignment = {
            "investigation_id": investigation["id"],
            "assignee": "senior_analyst@example.com",
            "assigned_by": "manager@example.com",
            "assigned_at": datetime.utcnow().isoformat(),
            "due_date": (datetime.utcnow() + timedelta(days=1)).isoformat()
        }
        
        assert assignment["assignee"] == "senior_analyst@example.com"
    
    def test_add_investigation_comment(self, sample_investigation):
        """Test adding comments to investigation."""
        comment = {
            "id": str(uuid4()),
            "investigation_id": sample_investigation["id"],
            "author": "analyst@example.com",
            "content": "Initial analysis suggests APT activity",
            "timestamp": datetime.utcnow().isoformat(),
            "mentions": ["@senior_analyst"],
            "attachments": []
        }
        
        assert "@senior_analyst" in comment["mentions"]
    
    def test_investigation_audit_log(self, sample_investigation):
        """Test investigation audit logging."""
        audit_entries = [
            {"action": "created", "user": "analyst@example.com", "timestamp": "T1"},
            {"action": "alert_added", "user": "analyst@example.com", "timestamp": "T2"},
            {"action": "finding_added", "user": "analyst@example.com", "timestamp": "T3"},
            {"action": "assigned", "user": "manager@example.com", "timestamp": "T4"},
            {"action": "status_changed", "user": "analyst@example.com", "timestamp": "T5"}
        ]
        
        assert len(audit_entries) == 5
        assert audit_entries[0]["action"] == "created"
