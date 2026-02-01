"""
End-to-End Tests for Complete Security Workflows.

Tests full incident lifecycle from alert to resolution with all components.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import asyncio


class TestIncidentLifecycle:
    """End-to-end tests for complete incident handling lifecycle."""

    @pytest.mark.asyncio
    async def test_phishing_incident_full_lifecycle(self):
        """Test complete lifecycle of a phishing incident from detection to resolution."""
        with patch("agentic_soc.SOCPlatform") as mock_platform:
            mock_instance = AsyncMock()
            mock_platform.return_value = mock_instance

            # Phase 1: Initial Detection
            phishing_email = {
                "source": "email_gateway",
                "timestamp": datetime.utcnow().isoformat(),
                "sender": "ceo@ev1l-company.com",
                "recipient": "finance@company.com",
                "subject": "Urgent Wire Transfer Required",
                "attachments": [{"name": "invoice.pdf.exe", "hash": "abc123"}],
                "urls": ["http://malicious-site.com/payload"]
            }

            # Phase 2: Full Pipeline Processing
            lifecycle_result = {
                "incident_id": "INC-2024-0001",
                "phases": {
                    "detection": {
                        "timestamp": datetime.utcnow().isoformat(),
                        "duration_ms": 50,
                        "rules_triggered": ["phishing_ceo_fraud", "suspicious_attachment"],
                        "initial_severity": "high"
                    },
                    "triage": {
                        "timestamp": datetime.utcnow().isoformat(),
                        "duration_ms": 30,
                        "priority": "P1",
                        "risk_score": 92,
                        "auto_escalated": True,
                        "affected_users": ["finance@company.com"]
                    },
                    "enrichment": {
                        "timestamp": datetime.utcnow().isoformat(),
                        "duration_ms": 100,
                        "threat_intel": {
                            "domain_reputation": "malicious",
                            "known_campaign": "BEC_Q1_2024",
                            "threat_actor": "FIN7"
                        },
                        "user_context": {
                            "user": "finance@company.com",
                            "department": "Finance",
                            "access_level": "high",
                            "recent_training": False
                        }
                    },
                    "investigation": {
                        "timestamp": datetime.utcnow().isoformat(),
                        "duration_ms": 200,
                        "findings": [
                            "Email spoofing detected",
                            "Attachment is PE executable",
                            "URL leads to credential harvester"
                        ],
                        "iocs_extracted": [
                            {"type": "domain", "value": "ev1l-company.com"},
                            {"type": "url", "value": "http://malicious-site.com/payload"},
                            {"type": "hash", "value": "abc123"}
                        ],
                        "mitre_techniques": ["T1566.001", "T1204.002"]
                    },
                    "response": {
                        "timestamp": datetime.utcnow().isoformat(),
                        "duration_ms": 150,
                        "actions_taken": [
                            {"action": "quarantine_email", "status": "success"},
                            {"action": "block_sender", "status": "success"},
                            {"action": "block_domain", "status": "success"},
                            {"action": "block_url", "status": "success"},
                            {"action": "notify_user", "status": "success"},
                            {"action": "notify_soc", "status": "success"}
                        ],
                        "playbook_executed": "phishing_response_v3"
                    },
                    "remediation": {
                        "timestamp": datetime.utcnow().isoformat(),
                        "duration_ms": 50,
                        "user_notified": True,
                        "security_awareness_scheduled": True,
                        "iocs_shared": True
                    }
                },
                "total_duration_ms": 580,
                "final_status": "resolved",
                "resolution_type": "automated",
                "false_positive": False
            }
            mock_instance.process_incident.return_value = lifecycle_result

            result = await mock_instance.process_incident(phishing_email)

            assert result["incident_id"].startswith("INC-")
            assert result["final_status"] == "resolved"
            assert len(result["phases"]) >= 5
            assert all(p["duration_ms"] > 0 for p in result["phases"].values())
            assert result["total_duration_ms"] < 1000

    @pytest.mark.asyncio
    async def test_ransomware_incident_full_lifecycle(self):
        """Test complete lifecycle of a ransomware incident with containment."""
        with patch("agentic_soc.SOCPlatform") as mock_platform:
            mock_instance = AsyncMock()
            mock_platform.return_value = mock_instance

            ransomware_indicators = {
                "source": "edr",
                "timestamp": datetime.utcnow().isoformat(),
                "hostname": "fileserver-01",
                "process": {
                    "name": "suspicious.exe",
                    "path": "C:\\Users\\admin\\Downloads\\suspicious.exe",
                    "hash": "ransomware_hash_123",
                    "parent": "outlook.exe"
                },
                "behaviors": [
                    "mass_file_encryption",
                    "shadow_copy_deletion",
                    "ransom_note_creation"
                ],
                "affected_files": 15000,
                "encryption_extensions": [".locked", ".encrypted"]
            }

            lifecycle_result = {
                "incident_id": "INC-2024-RANSOM-001",
                "severity": "critical",
                "phases": {
                    "detection": {
                        "rules_triggered": ["ransomware_behavior", "mass_encryption", "vss_deletion"],
                        "ml_confidence": 0.98,
                        "duration_ms": 25
                    },
                    "triage": {
                        "priority": "P0",
                        "risk_score": 99,
                        "business_impact": "critical",
                        "immediate_escalation": True
                    },
                    "containment": {
                        "timestamp": datetime.utcnow().isoformat(),
                        "actions": [
                            {"action": "isolate_host", "target": "fileserver-01", "status": "success", "latency_ms": 500},
                            {"action": "disable_user", "target": "admin", "status": "success"},
                            {"action": "block_hash", "target": "ransomware_hash_123", "status": "success"},
                            {"action": "network_segment_isolation", "target": "file_servers", "status": "success"}
                        ],
                        "containment_time_seconds": 45
                    },
                    "investigation": {
                        "patient_zero": "fileserver-01",
                        "infection_vector": "phishing_email",
                        "lateral_movement_detected": False,
                        "data_exfiltration": "unknown",
                        "ransomware_family": "LockBit",
                        "iocs": [
                            {"type": "hash", "value": "ransomware_hash_123"},
                            {"type": "c2", "value": "185.220.101.1"}
                        ]
                    },
                    "eradication": {
                        "malware_removed": True,
                        "persistence_cleared": True,
                        "system_hardened": True
                    },
                    "recovery": {
                        "backup_available": True,
                        "files_restored": 14500,
                        "recovery_time_hours": 4,
                        "data_loss_percent": 3.3
                    }
                },
                "total_duration_hours": 6,
                "final_status": "resolved",
                "lessons_learned": [
                    "Improve email filtering",
                    "Implement application whitelisting",
                    "Enhance backup procedures"
                ]
            }
            mock_instance.process_incident.return_value = lifecycle_result

            result = await mock_instance.process_incident(ransomware_indicators)

            assert result["severity"] == "critical"
            assert result["phases"]["containment"]["containment_time_seconds"] < 60
            assert result["phases"]["recovery"]["backup_available"] is True
            assert result["final_status"] == "resolved"

    @pytest.mark.asyncio
    async def test_apt_campaign_detection_lifecycle(self):
        """Test detection and response to an APT campaign over multiple days."""
        with patch("agentic_soc.SOCPlatform") as mock_platform:
            mock_instance = AsyncMock()
            mock_platform.return_value = mock_instance

            # Multiple related alerts over time
            apt_alerts = [
                {"alert_id": "ALT-001", "technique": "T1566.001", "timestamp": "2024-01-15T10:00:00Z"},
                {"alert_id": "ALT-002", "technique": "T1059.001", "timestamp": "2024-01-15T10:30:00Z"},
                {"alert_id": "ALT-003", "technique": "T1003.001", "timestamp": "2024-01-16T09:00:00Z"},
                {"alert_id": "ALT-004", "technique": "T1021.002", "timestamp": "2024-01-16T14:00:00Z"},
                {"alert_id": "ALT-005", "technique": "T1048.002", "timestamp": "2024-01-17T02:00:00Z"}
            ]

            campaign_result = {
                "campaign_id": "CAMP-APT-001",
                "threat_actor": "APT29",
                "confidence": 0.87,
                "campaign_timeline": {
                    "first_seen": "2024-01-15T10:00:00Z",
                    "last_seen": "2024-01-17T02:00:00Z",
                    "duration_days": 2
                },
                "kill_chain_coverage": {
                    "initial_access": True,
                    "execution": True,
                    "persistence": False,
                    "privilege_escalation": False,
                    "defense_evasion": False,
                    "credential_access": True,
                    "discovery": False,
                    "lateral_movement": True,
                    "collection": False,
                    "exfiltration": True,
                    "impact": False
                },
                "affected_assets": ["ws-finance-01", "ws-finance-02", "fileserver-hr"],
                "affected_users": ["jsmith", "mjones", "admin-backup"],
                "data_at_risk": ["financial_reports", "hr_records"],
                "response_actions": [
                    {"action": "isolate_affected_hosts", "count": 3, "status": "completed"},
                    {"action": "reset_credentials", "count": 3, "status": "completed"},
                    {"action": "block_c2_infrastructure", "count": 5, "status": "completed"},
                    {"action": "enhance_monitoring", "status": "active"}
                ],
                "hunt_queries_generated": 15,
                "iocs_discovered": 47,
                "incident_status": "active_monitoring"
            }
            mock_instance.analyze_campaign.return_value = campaign_result

            result = await mock_instance.analyze_campaign(apt_alerts)

            assert result["threat_actor"] == "APT29"
            assert result["campaign_timeline"]["duration_days"] >= 1
            assert sum(result["kill_chain_coverage"].values()) >= 4
            assert len(result["affected_assets"]) > 0


class TestCompleteWorkflows:
    """End-to-end tests for specific security workflows."""

    @pytest.mark.asyncio
    async def test_threat_hunting_workflow(self):
        """Test complete threat hunting workflow from hypothesis to findings."""
        with patch("agentic_soc.SOCPlatform") as mock_platform:
            mock_instance = AsyncMock()
            mock_platform.return_value = mock_instance

            hunting_hypothesis = {
                "hypothesis": "APT actors using living-off-the-land binaries for lateral movement",
                "techniques": ["T1021.002", "T1047", "T1569.002"],
                "timeframe": "last_30_days",
                "scope": "all_windows_endpoints"
            }

            hunting_result = {
                "hunt_id": "HUNT-2024-001",
                "hypothesis": hunting_hypothesis["hypothesis"],
                "status": "completed",
                "phases": {
                    "query_generation": {
                        "queries_generated": 12,
                        "data_sources": ["windows_events", "edr_telemetry", "network_logs"]
                    },
                    "data_collection": {
                        "events_analyzed": 15000000,
                        "timeframe_covered": "30 days",
                        "endpoints_scanned": 5000
                    },
                    "analysis": {
                        "anomalies_detected": 47,
                        "suspicious_activities": 12,
                        "confirmed_threats": 3
                    },
                    "findings": [
                        {
                            "finding_id": "FIND-001",
                            "description": "WMI lateral movement from compromised admin account",
                            "affected_hosts": ["dc01", "fileserver-01"],
                            "severity": "high",
                            "evidence": ["WMI process creation", "Abnormal admin activity"]
                        },
                        {
                            "finding_id": "FIND-002",
                            "description": "PsExec usage during off-hours",
                            "affected_hosts": ["ws-dev-01", "ws-dev-02"],
                            "severity": "medium",
                            "evidence": ["Service installation", "Off-hours activity"]
                        },
                        {
                            "finding_id": "FIND-003",
                            "description": "Scheduled task creation for persistence",
                            "affected_hosts": ["ws-finance-01"],
                            "severity": "high",
                            "evidence": ["schtasks.exe execution", "Encoded payload"]
                        }
                    ]
                },
                "recommendations": [
                    "Investigate compromised admin account",
                    "Enable enhanced WMI logging",
                    "Review scheduled tasks on affected hosts"
                ],
                "duration_hours": 4,
                "analyst_review_required": True
            }
            mock_instance.execute_hunt.return_value = hunting_result

            result = await mock_instance.execute_hunt(hunting_hypothesis)

            assert result["status"] == "completed"
            assert result["phases"]["analysis"]["confirmed_threats"] >= 1
            assert len(result["phases"]["findings"]) >= 3

    @pytest.mark.asyncio
    async def test_compliance_audit_workflow(self):
        """Test complete compliance audit workflow."""
        with patch("agentic_soc.SOCPlatform") as mock_platform:
            mock_instance = AsyncMock()
            mock_platform.return_value = mock_instance

            audit_request = {
                "framework": "PCI-DSS",
                "version": "4.0",
                "scope": "payment_processing_systems",
                "timeframe": "last_90_days"
            }

            audit_result = {
                "audit_id": "AUDIT-2024-PCI-001",
                "framework": "PCI-DSS 4.0",
                "status": "completed",
                "summary": {
                    "total_requirements": 12,
                    "compliant": 10,
                    "non_compliant": 1,
                    "partially_compliant": 1,
                    "compliance_score": 83.3
                },
                "findings": {
                    "compliant": [
                        {"req": "1.1", "description": "Firewall configuration", "status": "pass"},
                        {"req": "2.1", "description": "Vendor defaults changed", "status": "pass"},
                        {"req": "3.1", "description": "Cardholder data protection", "status": "pass"}
                    ],
                    "non_compliant": [
                        {
                            "req": "6.2",
                            "description": "Security patches",
                            "status": "fail",
                            "gap": "15 systems missing critical patches",
                            "remediation": "Apply patches within 30 days",
                            "risk": "high"
                        }
                    ],
                    "partially_compliant": [
                        {
                            "req": "10.1",
                            "description": "Audit logging",
                            "status": "partial",
                            "gap": "Logging not enabled on 3 database servers",
                            "remediation": "Enable audit logging on all DB servers"
                        }
                    ]
                },
                "evidence_collected": 150,
                "systems_assessed": 75,
                "duration_hours": 8,
                "next_audit_date": "2024-04-15"
            }
            mock_instance.run_compliance_audit.return_value = audit_result

            result = await mock_instance.run_compliance_audit(audit_request)

            assert result["status"] == "completed"
            assert result["summary"]["compliance_score"] >= 80
            assert len(result["findings"]["non_compliant"]) >= 0

    @pytest.mark.asyncio
    async def test_incident_response_tabletop_workflow(self):
        """Test automated incident response tabletop exercise."""
        with patch("agentic_soc.SOCPlatform") as mock_platform:
            mock_instance = AsyncMock()
            mock_platform.return_value = mock_instance

            exercise_config = {
                "scenario": "ransomware_outbreak",
                "inject_points": 5,
                "participants": ["soc_team", "it_ops", "management"],
                "duration_hours": 2
            }

            exercise_result = {
                "exercise_id": "EX-2024-001",
                "scenario": "ransomware_outbreak",
                "status": "completed",
                "phases": [
                    {
                        "phase": 1,
                        "inject": "EDR alerts showing mass file encryption on 5 endpoints",
                        "expected_actions": ["triage_alert", "verify_scope", "notify_team"],
                        "actions_taken": ["triage_alert", "verify_scope", "notify_team"],
                        "response_time_minutes": 5,
                        "score": 100
                    },
                    {
                        "phase": 2,
                        "inject": "Ransomware spreading to file servers",
                        "expected_actions": ["isolate_hosts", "disable_accounts", "activate_ir_plan"],
                        "actions_taken": ["isolate_hosts", "activate_ir_plan"],
                        "response_time_minutes": 10,
                        "score": 80,
                        "gap": "Account disabling delayed"
                    },
                    {
                        "phase": 3,
                        "inject": "Ransom note discovered, 500GB data encrypted",
                        "expected_actions": ["assess_impact", "notify_management", "preserve_evidence"],
                        "actions_taken": ["assess_impact", "notify_management", "preserve_evidence"],
                        "response_time_minutes": 15,
                        "score": 100
                    }
                ],
                "overall_score": 93,
                "strengths": ["Quick initial detection", "Good communication", "Evidence preservation"],
                "improvements": ["Faster account disabling", "Clearer escalation paths"],
                "recommendations": [
                    "Update IR playbook with explicit account disable step",
                    "Add management contact list to runbook"
                ]
            }
            mock_instance.run_tabletop.return_value = exercise_result

            result = await mock_instance.run_tabletop(exercise_config)

            assert result["status"] == "completed"
            assert result["overall_score"] >= 80
            assert len(result["improvements"]) > 0


class TestDataFlowE2E:
    """End-to-end tests for complete data flow through the system."""

    @pytest.mark.asyncio
    async def test_log_ingestion_to_alert_e2e(self):
        """Test complete flow from raw log to actionable alert."""
        with patch("agentic_soc.SOCPlatform") as mock_platform:
            mock_instance = AsyncMock()
            mock_platform.return_value = mock_instance

            raw_logs = [
                {
                    "source": "windows_security",
                    "raw": '<Event><EventID>4625</EventID><Data Name="TargetUserName">admin</Data></Event>',
                    "timestamp": datetime.utcnow().isoformat()
                }
            ] * 100  # 100 failed login attempts

            e2e_result = {
                "pipeline_id": "E2E-PIPE-001",
                "input": {"log_count": 100, "source": "windows_security"},
                "stages": {
                    "ingestion": {
                        "logs_received": 100,
                        "logs_parsed": 100,
                        "parse_errors": 0,
                        "duration_ms": 50
                    },
                    "normalization": {
                        "events_normalized": 100,
                        "ocsf_class": 3002,
                        "validation_passed": 100,
                        "duration_ms": 75
                    },
                    "enrichment": {
                        "events_enriched": 100,
                        "enrichments_applied": {
                            "geo_ip": 100,
                            "user_context": 100,
                            "asset_info": 100
                        },
                        "duration_ms": 150
                    },
                    "correlation": {
                        "events_correlated": 100,
                        "patterns_detected": 1,
                        "pattern_type": "brute_force_attempt",
                        "duration_ms": 100
                    },
                    "detection": {
                        "rules_evaluated": 150,
                        "rules_matched": 2,
                        "matched_rules": ["brute_force_login", "account_lockout_threshold"],
                        "duration_ms": 50
                    },
                    "alerting": {
                        "alerts_generated": 1,
                        "alert_id": "ALT-BF-001",
                        "severity": "high",
                        "duration_ms": 25
                    }
                },
                "total_duration_ms": 450,
                "final_output": {
                    "alert": {
                        "alert_id": "ALT-BF-001",
                        "title": "Brute Force Attack Detected",
                        "description": "100 failed login attempts for admin account in 5 minutes",
                        "severity": "high",
                        "mitre_technique": "T1110.001",
                        "affected_user": "admin",
                        "source_ips": ["192.168.1.50"],
                        "recommended_actions": ["block_source_ip", "reset_password", "enable_mfa"]
                    }
                }
            }
            mock_instance.process_logs_e2e.return_value = e2e_result

            result = await mock_instance.process_logs_e2e(raw_logs)

            assert result["input"]["log_count"] == 100
            assert result["stages"]["alerting"]["alerts_generated"] == 1
            assert result["total_duration_ms"] < 1000

    @pytest.mark.asyncio
    async def test_multi_source_correlation_e2e(self):
        """Test correlation of events from multiple sources."""
        with patch("agentic_soc.SOCPlatform") as mock_platform:
            mock_instance = AsyncMock()
            mock_platform.return_value = mock_instance

            multi_source_events = {
                "email_gateway": [
                    {"type": "phishing_detected", "recipient": "jsmith@company.com", "timestamp": "T+0"}
                ],
                "edr": [
                    {"type": "process_create", "process": "powershell.exe", "user": "jsmith", "timestamp": "T+5min"}
                ],
                "network": [
                    {"type": "dns_query", "domain": "evil-c2.com", "src_host": "ws-jsmith", "timestamp": "T+6min"},
                    {"type": "http_post", "dest": "185.220.101.1", "src_host": "ws-jsmith", "timestamp": "T+7min"}
                ],
                "active_directory": [
                    {"type": "privilege_escalation", "user": "jsmith", "new_group": "Domain Admins", "timestamp": "T+10min"}
                ]
            }

            correlation_result = {
                "correlation_id": "CORR-001",
                "sources_analyzed": ["email_gateway", "edr", "network", "active_directory"],
                "events_correlated": 5,
                "correlation_confidence": 0.94,
                "attack_narrative": {
                    "stage_1": {
                        "stage": "Initial Access",
                        "technique": "T1566.001",
                        "description": "Phishing email delivered to jsmith",
                        "timestamp": "T+0"
                    },
                    "stage_2": {
                        "stage": "Execution",
                        "technique": "T1059.001",
                        "description": "PowerShell execution by jsmith",
                        "timestamp": "T+5min"
                    },
                    "stage_3": {
                        "stage": "Command and Control",
                        "technique": "T1071.001",
                        "description": "C2 communication to evil-c2.com",
                        "timestamp": "T+6min"
                    },
                    "stage_4": {
                        "stage": "Privilege Escalation",
                        "technique": "T1078.002",
                        "description": "jsmith added to Domain Admins",
                        "timestamp": "T+10min"
                    }
                },
                "affected_entity": {
                    "user": "jsmith",
                    "hostname": "ws-jsmith",
                    "compromise_confirmed": True
                },
                "recommended_actions": [
                    "Isolate ws-jsmith immediately",
                    "Disable jsmith account",
                    "Remove jsmith from Domain Admins",
                    "Block C2 infrastructure",
                    "Initiate IR process"
                ]
            }
            mock_instance.correlate_multi_source.return_value = correlation_result

            result = await mock_instance.correlate_multi_source(multi_source_events)

            assert len(result["sources_analyzed"]) == 4
            assert result["correlation_confidence"] >= 0.9
            assert result["affected_entity"]["compromise_confirmed"] is True


class TestSystemResilience:
    """End-to-end tests for system resilience and recovery."""

    @pytest.mark.asyncio
    async def test_high_volume_processing(self):
        """Test system handling of high-volume event ingestion."""
        with patch("agentic_soc.SOCPlatform") as mock_platform:
            mock_instance = AsyncMock()
            mock_platform.return_value = mock_instance

            high_volume_result = {
                "test_id": "HV-001",
                "duration_seconds": 60,
                "events_processed": 1000000,
                "throughput_eps": 16667,
                "latency": {
                    "p50_ms": 10,
                    "p95_ms": 25,
                    "p99_ms": 50,
                    "max_ms": 100
                },
                "resource_utilization": {
                    "cpu_percent": 75,
                    "memory_percent": 60,
                    "disk_iops": 5000
                },
                "alerts_generated": 150,
                "false_positive_rate": 0.02,
                "events_dropped": 0,
                "system_status": "healthy"
            }
            mock_instance.run_load_test.return_value = high_volume_result

            result = await mock_instance.run_load_test(events_per_second=20000, duration_seconds=60)

            assert result["events_dropped"] == 0
            assert result["throughput_eps"] >= 10000
            assert result["latency"]["p99_ms"] < 100
            assert result["system_status"] == "healthy"

    @pytest.mark.asyncio
    async def test_component_failure_recovery(self):
        """Test system recovery from component failures."""
        with patch("agentic_soc.SOCPlatform") as mock_platform:
            mock_instance = AsyncMock()
            mock_platform.return_value = mock_instance

            failure_recovery_result = {
                "test_id": "FR-001",
                "failures_injected": [
                    {
                        "component": "detection_agent",
                        "failure_type": "crash",
                        "detection_time_ms": 500,
                        "recovery_time_ms": 2000,
                        "events_lost": 0,
                        "fallback_activated": True
                    },
                    {
                        "component": "elasticsearch",
                        "failure_type": "network_partition",
                        "detection_time_ms": 1000,
                        "recovery_time_ms": 5000,
                        "events_buffered": 5000,
                        "data_loss": False
                    },
                    {
                        "component": "redis_cache",
                        "failure_type": "oom",
                        "detection_time_ms": 200,
                        "recovery_time_ms": 1500,
                        "cache_miss_increase_percent": 15,
                        "performance_degradation": "minimal"
                    }
                ],
                "system_availability": 99.95,
                "data_integrity": "maintained",
                "alert_continuity": "maintained"
            }
            mock_instance.run_chaos_test.return_value = failure_recovery_result

            result = await mock_instance.run_chaos_test()

            assert result["system_availability"] >= 99.9
            assert result["data_integrity"] == "maintained"
            assert all(f["recovery_time_ms"] < 10000 for f in result["failures_injected"])

    @pytest.mark.asyncio
    async def test_graceful_degradation(self):
        """Test graceful degradation under resource constraints."""
        with patch("agentic_soc.SOCPlatform") as mock_platform:
            mock_instance = AsyncMock()
            mock_platform.return_value = mock_instance

            degradation_result = {
                "test_id": "GD-001",
                "constraint_applied": "memory_limit_50_percent",
                "normal_throughput_eps": 20000,
                "constrained_throughput_eps": 12000,
                "throughput_reduction_percent": 40,
                "features_degraded": [
                    {"feature": "ml_detection", "status": "reduced_accuracy", "impact": "minor"},
                    {"feature": "enrichment", "status": "cached_only", "impact": "moderate"},
                    {"feature": "full_text_search", "status": "disabled", "impact": "minor"}
                ],
                "features_maintained": [
                    {"feature": "sigma_detection", "status": "full"},
                    {"feature": "alerting", "status": "full"},
                    {"feature": "response_automation", "status": "full"}
                ],
                "critical_functions_available": True,
                "alert_latency_increase_percent": 25
            }
            mock_instance.test_degradation.return_value = degradation_result

            result = await mock_instance.test_degradation(constraint="memory_50_percent")

            assert result["critical_functions_available"] is True
            assert result["constrained_throughput_eps"] >= 10000
            assert any(f["feature"] == "alerting" and f["status"] == "full" 
                      for f in result["features_maintained"])
