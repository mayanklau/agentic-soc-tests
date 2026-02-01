"""
Unit Tests for Knowledge Base Components.

Tests MITRE ATT&CK knowledge, threat intelligence knowledge base,
playbook repository, and case management knowledge.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import json


class TestMITREKnowledgeBase:
    """Tests for MITRE ATT&CK knowledge base."""

    @pytest.mark.asyncio
    async def test_technique_lookup(self):
        """Test MITRE technique lookup by ID."""
        with patch("agentic_soc.knowledge.MITREKnowledgeBase") as mock_mitre:
            mock_instance = MagicMock()
            mock_mitre.return_value = mock_instance

            mock_instance.get_technique.return_value = {
                "technique_id": "T1059.001",
                "name": "PowerShell",
                "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
                "tactic": "execution",
                "platforms": ["Windows"],
                "permissions_required": ["User", "Administrator"],
                "data_sources": [
                    "Command: Command Execution",
                    "Process: Process Creation",
                    "Script: Script Execution",
                    "Module: Module Load"
                ],
                "detection": "Monitor for PowerShell execution, especially with encoded commands.",
                "mitigations": [
                    {"id": "M1042", "name": "Disable or Remove Feature or Program"},
                    {"id": "M1045", "name": "Code Signing"},
                    {"id": "M1026", "name": "Privileged Account Management"}
                ],
                "sub_techniques": [
                    {"id": "T1059.001", "name": "PowerShell"}
                ],
                "version": "1.4",
                "last_modified": "2023-10-15"
            }

            result = mock_instance.get_technique("T1059.001")

            assert result["technique_id"] == "T1059.001"
            assert result["tactic"] == "execution"
            assert "Windows" in result["platforms"]

    @pytest.mark.asyncio
    async def test_tactic_techniques_listing(self):
        """Test listing all techniques for a tactic."""
        with patch("agentic_soc.knowledge.MITREKnowledgeBase") as mock_mitre:
            mock_instance = MagicMock()
            mock_mitre.return_value = mock_instance

            mock_instance.get_techniques_by_tactic.return_value = {
                "tactic": "initial_access",
                "tactic_id": "TA0001",
                "description": "Techniques that use various entry vectors to gain their initial foothold.",
                "techniques_count": 9,
                "techniques": [
                    {"id": "T1189", "name": "Drive-by Compromise"},
                    {"id": "T1190", "name": "Exploit Public-Facing Application"},
                    {"id": "T1133", "name": "External Remote Services"},
                    {"id": "T1200", "name": "Hardware Additions"},
                    {"id": "T1566", "name": "Phishing"},
                    {"id": "T1091", "name": "Replication Through Removable Media"},
                    {"id": "T1195", "name": "Supply Chain Compromise"},
                    {"id": "T1199", "name": "Trusted Relationship"},
                    {"id": "T1078", "name": "Valid Accounts"}
                ]
            }

            result = mock_instance.get_techniques_by_tactic("initial_access")

            assert result["tactic"] == "initial_access"
            assert result["techniques_count"] == 9

    @pytest.mark.asyncio
    async def test_attack_pattern_search(self):
        """Test searching for attack patterns."""
        with patch("agentic_soc.knowledge.MITREKnowledgeBase") as mock_mitre:
            mock_instance = MagicMock()
            mock_mitre.return_value = mock_instance

            mock_instance.search_techniques.return_value = {
                "query": "credential dumping",
                "results_count": 5,
                "results": [
                    {
                        "id": "T1003",
                        "name": "OS Credential Dumping",
                        "relevance_score": 0.95,
                        "sub_techniques": [
                            "T1003.001 - LSASS Memory",
                            "T1003.002 - Security Account Manager",
                            "T1003.003 - NTDS",
                            "T1003.004 - LSA Secrets",
                            "T1003.005 - Cached Domain Credentials"
                        ]
                    },
                    {
                        "id": "T1555",
                        "name": "Credentials from Password Stores",
                        "relevance_score": 0.82
                    },
                    {
                        "id": "T1552",
                        "name": "Unsecured Credentials",
                        "relevance_score": 0.78
                    }
                ]
            }

            result = mock_instance.search_techniques("credential dumping")

            assert result["results_count"] >= 3
            assert result["results"][0]["relevance_score"] > 0.9

    @pytest.mark.asyncio
    async def test_mitigation_recommendations(self):
        """Test getting mitigation recommendations for a technique."""
        with patch("agentic_soc.knowledge.MITREKnowledgeBase") as mock_mitre:
            mock_instance = MagicMock()
            mock_mitre.return_value = mock_instance

            mock_instance.get_mitigations.return_value = {
                "technique_id": "T1566.001",
                "technique_name": "Spearphishing Attachment",
                "mitigations": [
                    {
                        "id": "M1049",
                        "name": "Antivirus/Antimalware",
                        "description": "Use antimalware software capable of detecting malicious attachments.",
                        "effectiveness": "high"
                    },
                    {
                        "id": "M1031",
                        "name": "Network Intrusion Prevention",
                        "description": "Use IDS/IPS to detect malicious attachments.",
                        "effectiveness": "medium"
                    },
                    {
                        "id": "M1017",
                        "name": "User Training",
                        "description": "Train users to be aware of phishing techniques.",
                        "effectiveness": "medium"
                    },
                    {
                        "id": "M1054",
                        "name": "Software Configuration",
                        "description": "Disable Office macros by default.",
                        "effectiveness": "high"
                    }
                ],
                "detection_recommendations": [
                    "Monitor for unusual attachment types",
                    "Check for macro execution in Office documents",
                    "Correlate email events with process creation"
                ]
            }

            result = mock_instance.get_mitigations("T1566.001")

            assert len(result["mitigations"]) >= 4
            assert any(m["effectiveness"] == "high" for m in result["mitigations"])

    @pytest.mark.asyncio
    async def test_attack_group_mapping(self):
        """Test mapping attack groups to techniques."""
        with patch("agentic_soc.knowledge.MITREKnowledgeBase") as mock_mitre:
            mock_instance = MagicMock()
            mock_mitre.return_value = mock_instance

            mock_instance.get_group.return_value = {
                "group_id": "G0016",
                "name": "APT29",
                "aliases": ["Cozy Bear", "The Dukes", "YTTRIUM"],
                "description": "APT29 is threat group attributed to Russia's Foreign Intelligence Service.",
                "techniques_used": [
                    {"id": "T1059.001", "name": "PowerShell"},
                    {"id": "T1566.001", "name": "Spearphishing Attachment"},
                    {"id": "T1053.005", "name": "Scheduled Task"},
                    {"id": "T1071.001", "name": "Web Protocols"},
                    {"id": "T1027", "name": "Obfuscated Files or Information"}
                ],
                "software_used": [
                    {"id": "S0154", "name": "Cobalt Strike"},
                    {"id": "S0386", "name": "Ursnif"}
                ],
                "target_sectors": ["Government", "Defense", "Healthcare"],
                "first_seen": "2008",
                "last_activity": "2024"
            }

            result = mock_instance.get_group("G0016")

            assert result["name"] == "APT29"
            assert "Cozy Bear" in result["aliases"]
            assert len(result["techniques_used"]) >= 5

    @pytest.mark.asyncio
    async def test_technique_procedure_examples(self):
        """Test getting procedure examples for techniques."""
        with patch("agentic_soc.knowledge.MITREKnowledgeBase") as mock_mitre:
            mock_instance = MagicMock()
            mock_mitre.return_value = mock_instance

            mock_instance.get_procedure_examples.return_value = {
                "technique_id": "T1003.001",
                "technique_name": "LSASS Memory",
                "procedure_examples": [
                    {
                        "group": "APT28",
                        "description": "APT28 has used Mimikatz to dump LSASS memory.",
                        "tools": ["Mimikatz"]
                    },
                    {
                        "group": "APT29",
                        "description": "APT29 used procdump to extract LSASS memory.",
                        "tools": ["ProcDump"]
                    },
                    {
                        "software": "Cobalt Strike",
                        "description": "Cobalt Strike can dump LSASS memory via hashdump command.",
                        "tools": ["Cobalt Strike"]
                    }
                ],
                "common_tools": ["Mimikatz", "ProcDump", "comsvcs.dll", "Task Manager"]
            }

            result = mock_instance.get_procedure_examples("T1003.001")

            assert len(result["procedure_examples"]) >= 3
            assert "Mimikatz" in result["common_tools"]


class TestThreatIntelKnowledgeBase:
    """Tests for threat intelligence knowledge base."""

    @pytest.mark.asyncio
    async def test_ioc_database_lookup(self):
        """Test IOC database lookup."""
        with patch("agentic_soc.knowledge.ThreatIntelKB") as mock_ti:
            mock_instance = MagicMock()
            mock_ti.return_value = mock_instance

            mock_instance.lookup_ioc.return_value = {
                "ioc": "evil-domain.com",
                "ioc_type": "domain",
                "found": True,
                "threat_score": 95,
                "classifications": ["malware", "c2"],
                "associated_campaigns": ["emotet-2024", "qakbot-resurgence"],
                "first_seen": "2024-01-15T00:00:00Z",
                "last_seen": "2024-01-20T12:00:00Z",
                "sources": [
                    {"name": "VirusTotal", "score": 45, "total": 70},
                    {"name": "AbuseIPDB", "confidence": 100},
                    {"name": "MISP", "threat_level": "high"}
                ],
                "related_iocs": [
                    {"ioc": "192.168.100.1", "type": "ip", "relationship": "resolves_to"},
                    {"ioc": "abc123hash", "type": "hash", "relationship": "delivers"}
                ],
                "tags": ["emotet", "banking-trojan", "loader"]
            }

            result = mock_instance.lookup_ioc("evil-domain.com")

            assert result["found"] is True
            assert result["threat_score"] >= 90
            assert "malware" in result["classifications"]

    @pytest.mark.asyncio
    async def test_campaign_tracking(self):
        """Test threat campaign tracking."""
        with patch("agentic_soc.knowledge.ThreatIntelKB") as mock_ti:
            mock_instance = MagicMock()
            mock_ti.return_value = mock_instance

            mock_instance.get_campaign.return_value = {
                "campaign_id": "CAMP-2024-001",
                "name": "Operation CloudHopper",
                "description": "Large-scale cyber espionage campaign targeting MSPs.",
                "threat_actor": "APT10",
                "status": "active",
                "first_observed": "2024-01-01T00:00:00Z",
                "target_sectors": ["Technology", "Healthcare", "Finance"],
                "target_regions": ["North America", "Europe", "Asia Pacific"],
                "ttps": [
                    {"technique": "T1566.001", "usage": "Initial access via phishing"},
                    {"technique": "T1078", "usage": "Valid accounts from compromised MSPs"},
                    {"technique": "T1199", "usage": "Trusted relationship abuse"}
                ],
                "iocs": {
                    "domains": 45,
                    "ips": 23,
                    "hashes": 156,
                    "urls": 89
                },
                "detection_rules": ["SIGMA-APT10-001", "YARA-CloudHopper"]
            }

            result = mock_instance.get_campaign("CAMP-2024-001")

            assert result["status"] == "active"
            assert result["threat_actor"] == "APT10"

    @pytest.mark.asyncio
    async def test_threat_actor_profile(self):
        """Test threat actor profile retrieval."""
        with patch("agentic_soc.knowledge.ThreatIntelKB") as mock_ti:
            mock_instance = MagicMock()
            mock_ti.return_value = mock_instance

            mock_instance.get_threat_actor.return_value = {
                "actor_id": "TA-001",
                "name": "Lazarus Group",
                "aliases": ["Hidden Cobra", "Zinc", "APT38"],
                "attribution": "North Korea (DPRK)",
                "motivation": ["financial", "espionage"],
                "sophistication": "advanced",
                "capabilities": [
                    "Custom malware development",
                    "Zero-day exploitation",
                    "Supply chain attacks",
                    "Cryptocurrency theft"
                ],
                "target_sectors": ["Finance", "Cryptocurrency", "Defense"],
                "active_since": "2009",
                "recent_activity": {
                    "last_campaign": "2024-01-15",
                    "recent_targets": ["Cryptocurrency exchanges", "Banks"]
                },
                "associated_malware": [
                    {"name": "AppleJeus", "type": "backdoor"},
                    {"name": "FASTCash", "type": "ATM malware"}
                ],
                "mitre_mapping": {
                    "primary_tactics": ["initial-access", "execution", "collection"],
                    "technique_count": 45
                }
            }

            result = mock_instance.get_threat_actor("TA-001")

            assert result["name"] == "Lazarus Group"
            assert "financial" in result["motivation"]

    @pytest.mark.asyncio
    async def test_vulnerability_intelligence(self):
        """Test vulnerability intelligence lookup."""
        with patch("agentic_soc.knowledge.ThreatIntelKB") as mock_ti:
            mock_instance = MagicMock()
            mock_ti.return_value = mock_instance

            mock_instance.get_vulnerability.return_value = {
                "cve_id": "CVE-2024-21762",
                "description": "Fortinet FortiOS SSL VPN Out-of-bounds Write Vulnerability",
                "cvss_v3": {
                    "score": 9.8,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "severity": "critical"
                },
                "affected_products": [
                    {"vendor": "Fortinet", "product": "FortiOS", "versions": "7.0.0-7.0.13"}
                ],
                "exploit_available": True,
                "exploit_in_wild": True,
                "patch_available": True,
                "patch_released": "2024-02-08",
                "cisa_kev": True,
                "cisa_due_date": "2024-02-16",
                "threat_intelligence": {
                    "active_exploitation": True,
                    "ransomware_related": True,
                    "nation_state_interest": True
                },
                "references": [
                    {"type": "vendor_advisory", "url": "https://fortiguard.com/..."},
                    {"type": "cisa_advisory", "url": "https://cisa.gov/..."}
                ]
            }

            result = mock_instance.get_vulnerability("CVE-2024-21762")

            assert result["cvss_v3"]["score"] >= 9.0
            assert result["exploit_in_wild"] is True
            assert result["cisa_kev"] is True

    @pytest.mark.asyncio
    async def test_malware_analysis_knowledge(self):
        """Test malware analysis knowledge retrieval."""
        with patch("agentic_soc.knowledge.ThreatIntelKB") as mock_ti:
            mock_instance = MagicMock()
            mock_ti.return_value = mock_instance

            mock_instance.get_malware_info.return_value = {
                "malware_id": "MAL-001",
                "name": "Emotet",
                "type": "loader",
                "aliases": ["Heodo", "Geodo"],
                "description": "Banking trojan turned modular loader and botnet.",
                "capabilities": [
                    "Email harvesting",
                    "Credential theft",
                    "Malware delivery",
                    "Network spreading"
                ],
                "delivery_methods": ["Malicious email attachments", "Malicious links"],
                "file_indicators": {
                    "file_types": [".doc", ".docm", ".zip"],
                    "typical_names": ["Invoice_*.doc", "Report_*.docm"],
                    "yara_rules": ["emotet_loader", "emotet_payload"]
                },
                "network_indicators": {
                    "c2_protocol": "HTTPS",
                    "c2_ports": [443, 8080, 7080],
                    "dga": True
                },
                "persistence_mechanisms": [
                    "Registry run keys",
                    "Scheduled tasks",
                    "Windows services"
                ],
                "associated_payloads": ["TrickBot", "Qakbot", "Ryuk"],
                "mitre_techniques": ["T1566.001", "T1059.005", "T1547.001"]
            }

            result = mock_instance.get_malware_info("MAL-001")

            assert result["name"] == "Emotet"
            assert result["type"] == "loader"
            assert "TrickBot" in result["associated_payloads"]


class TestPlaybookKnowledgeBase:
    """Tests for playbook and response knowledge base."""

    @pytest.mark.asyncio
    async def test_playbook_retrieval(self):
        """Test incident response playbook retrieval."""
        with patch("agentic_soc.knowledge.PlaybookKB") as mock_pb:
            mock_instance = MagicMock()
            mock_pb.return_value = mock_instance

            mock_instance.get_playbook.return_value = {
                "playbook_id": "PB-PHISHING-001",
                "name": "Phishing Email Response",
                "description": "Standard response procedure for phishing incidents.",
                "category": "email_threats",
                "severity_applicable": ["low", "medium", "high"],
                "sla": {
                    "low": {"response": "4h", "resolution": "24h"},
                    "medium": {"response": "1h", "resolution": "8h"},
                    "high": {"response": "15m", "resolution": "4h"}
                },
                "steps": [
                    {
                        "step_number": 1,
                        "name": "Initial Assessment",
                        "actions": [
                            "Verify phishing indicators",
                            "Check email headers",
                            "Extract URLs and attachments"
                        ],
                        "automated": True,
                        "tools": ["email_analyzer", "url_scanner"]
                    },
                    {
                        "step_number": 2,
                        "name": "Scope Determination",
                        "actions": [
                            "Search for similar emails",
                            "Identify affected users",
                            "Check for clicks/interactions"
                        ],
                        "automated": True,
                        "tools": ["email_gateway_search", "proxy_logs"]
                    },
                    {
                        "step_number": 3,
                        "name": "Containment",
                        "actions": [
                            "Block sender domain",
                            "Delete emails from mailboxes",
                            "Block malicious URLs"
                        ],
                        "automated": True,
                        "approval_required": True
                    },
                    {
                        "step_number": 4,
                        "name": "Eradication",
                        "actions": [
                            "Reset credentials for clicked users",
                            "Scan endpoints for malware"
                        ],
                        "automated": False
                    },
                    {
                        "step_number": 5,
                        "name": "Recovery & Communication",
                        "actions": [
                            "Notify affected users",
                            "Update awareness training"
                        ],
                        "automated": False
                    }
                ],
                "automation_coverage": 0.6,
                "last_updated": "2024-01-15",
                "version": "2.3"
            }

            result = mock_instance.get_playbook("PB-PHISHING-001")

            assert result["name"] == "Phishing Email Response"
            assert len(result["steps"]) == 5
            assert result["automation_coverage"] >= 0.5

    @pytest.mark.asyncio
    async def test_playbook_recommendation(self):
        """Test playbook recommendation based on alert."""
        with patch("agentic_soc.knowledge.PlaybookKB") as mock_pb:
            mock_instance = MagicMock()
            mock_pb.return_value = mock_instance

            alert_context = {
                "alert_type": "malware_detected",
                "severity": "high",
                "indicators": ["suspicious_process", "c2_communication"],
                "mitre_techniques": ["T1059.001", "T1071.001"]
            }

            mock_instance.recommend_playbooks.return_value = {
                "alert_context": alert_context,
                "recommendations": [
                    {
                        "playbook_id": "PB-MALWARE-001",
                        "name": "Malware Incident Response",
                        "relevance_score": 0.95,
                        "match_reasons": [
                            "matches alert_type: malware_detected",
                            "covers T1059.001",
                            "covers T1071.001"
                        ]
                    },
                    {
                        "playbook_id": "PB-C2-001",
                        "name": "Command & Control Response",
                        "relevance_score": 0.85,
                        "match_reasons": [
                            "matches indicator: c2_communication",
                            "covers T1071.001"
                        ]
                    }
                ],
                "combined_actions": [
                    "Isolate affected endpoint",
                    "Collect memory dump",
                    "Block C2 communication",
                    "Analyze malware sample"
                ]
            }

            result = mock_instance.recommend_playbooks(alert_context)

            assert len(result["recommendations"]) >= 2
            assert result["recommendations"][0]["relevance_score"] > 0.9

    @pytest.mark.asyncio
    async def test_runbook_execution_history(self):
        """Test runbook execution history for effectiveness tracking."""
        with patch("agentic_soc.knowledge.PlaybookKB") as mock_pb:
            mock_instance = MagicMock()
            mock_pb.return_value = mock_instance

            mock_instance.get_execution_stats.return_value = {
                "playbook_id": "PB-PHISHING-001",
                "total_executions": 150,
                "time_period": "last_30_days",
                "success_rate": 0.94,
                "average_duration": {
                    "total": "45m",
                    "automated_steps": "5m",
                    "manual_steps": "40m"
                },
                "outcomes": {
                    "resolved": 141,
                    "escalated": 6,
                    "false_positive": 3
                },
                "bottlenecks": [
                    {"step": 4, "name": "Credential Reset", "avg_duration": "25m"}
                ],
                "improvement_suggestions": [
                    "Automate credential reset for low-risk users",
                    "Pre-approve containment actions for high-confidence detections"
                ]
            }

            result = mock_instance.get_execution_stats("PB-PHISHING-001")

            assert result["success_rate"] > 0.9
            assert result["total_executions"] == 150


class TestCaseKnowledgeBase:
    """Tests for case management knowledge base."""

    @pytest.mark.asyncio
    async def test_similar_case_lookup(self):
        """Test looking up similar historical cases."""
        with patch("agentic_soc.knowledge.CaseKB") as mock_case:
            mock_instance = MagicMock()
            mock_case.return_value = mock_instance

            current_case = {
                "indicators": ["encoded_powershell", "scheduled_task", "lateral_movement"],
                "mitre_techniques": ["T1059.001", "T1053.005", "T1021.001"],
                "affected_systems": ["workstation"],
                "severity": "high"
            }

            mock_instance.find_similar_cases.return_value = {
                "query_case": current_case,
                "similar_cases": [
                    {
                        "case_id": "CASE-2024-0045",
                        "similarity_score": 0.92,
                        "title": "PowerShell-based Lateral Movement",
                        "outcome": "contained",
                        "resolution_time": "4h",
                        "key_actions": [
                            "Isolated affected endpoints",
                            "Reset service accounts",
                            "Blocked C2 domains"
                        ],
                        "lessons_learned": "Early detection of scheduled tasks prevented spread"
                    },
                    {
                        "case_id": "CASE-2024-0032",
                        "similarity_score": 0.85,
                        "title": "Cobalt Strike Beacon Activity",
                        "outcome": "contained",
                        "resolution_time": "6h",
                        "key_actions": [
                            "Memory forensics on affected hosts",
                            "Network segmentation",
                            "Credential rotation"
                        ]
                    }
                ],
                "recommended_actions_from_history": [
                    {"action": "Isolate endpoint", "success_rate": 0.95},
                    {"action": "Memory dump collection", "success_rate": 0.88},
                    {"action": "Service account audit", "success_rate": 0.92}
                ]
            }

            result = mock_instance.find_similar_cases(current_case)

            assert len(result["similar_cases"]) >= 2
            assert result["similar_cases"][0]["similarity_score"] > 0.9

    @pytest.mark.asyncio
    async def test_case_metrics_aggregation(self):
        """Test case metrics aggregation for reporting."""
        with patch("agentic_soc.knowledge.CaseKB") as mock_case:
            mock_instance = MagicMock()
            mock_case.return_value = mock_instance

            mock_instance.get_metrics.return_value = {
                "period": "last_30_days",
                "total_cases": 245,
                "by_severity": {
                    "critical": 12,
                    "high": 45,
                    "medium": 98,
                    "low": 90
                },
                "by_category": {
                    "malware": 67,
                    "phishing": 89,
                    "unauthorized_access": 34,
                    "data_exfiltration": 12,
                    "other": 43
                },
                "mttr": {
                    "overall": "3.5h",
                    "critical": "1.2h",
                    "high": "2.8h",
                    "medium": "4.5h",
                    "low": "6h"
                },
                "mttd": "15m",
                "false_positive_rate": 0.08,
                "automation_rate": 0.65,
                "analyst_efficiency": {
                    "cases_per_analyst_day": 8.2,
                    "escalation_rate": 0.12
                }
            }

            result = mock_instance.get_metrics("last_30_days")

            assert result["total_cases"] == 245
            assert result["false_positive_rate"] < 0.1


class TestDetectionKnowledgeBase:
    """Tests for detection rule knowledge base."""

    @pytest.mark.asyncio
    async def test_sigma_rule_lookup(self):
        """Test Sigma rule lookup and metadata."""
        with patch("agentic_soc.knowledge.DetectionKB") as mock_det:
            mock_instance = MagicMock()
            mock_det.return_value = mock_instance

            mock_instance.get_sigma_rule.return_value = {
                "rule_id": "win_susp_powershell_enc_cmd",
                "title": "Suspicious Encoded PowerShell Command Line",
                "status": "production",
                "level": "high",
                "description": "Detects encoded PowerShell command line parameters.",
                "author": "Security Team",
                "date": "2024-01-15",
                "references": [
                    "https://attack.mitre.org/techniques/T1059/001/"
                ],
                "logsource": {
                    "category": "process_creation",
                    "product": "windows"
                },
                "detection": {
                    "selection": {
                        "CommandLine|contains": ["-enc", "-EncodedCommand", "-ec"]
                    },
                    "condition": "selection"
                },
                "mitre_attack": {
                    "tactics": ["execution"],
                    "techniques": ["T1059.001"]
                },
                "false_positives": [
                    "Legitimate admin scripts",
                    "Software deployment tools"
                ],
                "performance": {
                    "events_per_day": 50,
                    "true_positive_rate": 0.85,
                    "tuning_recommendations": [
                        "Exclude known admin accounts",
                        "Whitelist deployment tools"
                    ]
                }
            }

            result = mock_instance.get_sigma_rule("win_susp_powershell_enc_cmd")

            assert result["level"] == "high"
            assert "T1059.001" in result["mitre_attack"]["techniques"]

    @pytest.mark.asyncio
    async def test_detection_coverage_analysis(self):
        """Test MITRE ATT&CK detection coverage analysis."""
        with patch("agentic_soc.knowledge.DetectionKB") as mock_det:
            mock_instance = MagicMock()
            mock_det.return_value = mock_instance

            mock_instance.get_coverage_analysis.return_value = {
                "framework": "MITRE ATT&CK v14",
                "total_techniques": 201,
                "covered_techniques": 156,
                "coverage_percentage": 0.776,
                "by_tactic": {
                    "initial_access": {"total": 9, "covered": 8, "percentage": 0.89},
                    "execution": {"total": 14, "covered": 12, "percentage": 0.86},
                    "persistence": {"total": 19, "covered": 15, "percentage": 0.79},
                    "privilege_escalation": {"total": 13, "covered": 10, "percentage": 0.77},
                    "defense_evasion": {"total": 42, "covered": 28, "percentage": 0.67},
                    "credential_access": {"total": 17, "covered": 14, "percentage": 0.82},
                    "discovery": {"total": 31, "covered": 22, "percentage": 0.71},
                    "lateral_movement": {"total": 9, "covered": 8, "percentage": 0.89},
                    "collection": {"total": 17, "covered": 13, "percentage": 0.76},
                    "exfiltration": {"total": 9, "covered": 7, "percentage": 0.78},
                    "impact": {"total": 14, "covered": 11, "percentage": 0.79}
                },
                "gaps": [
                    {"technique": "T1027.004", "name": "Compile After Delivery", "priority": "high"},
                    {"technique": "T1218.014", "name": "MMC", "priority": "medium"}
                ],
                "recommendations": [
                    "Add detection for T1027.004 - high-priority gap",
                    "Improve defense_evasion coverage (67%)"
                ]
            }

            result = mock_instance.get_coverage_analysis()

            assert result["coverage_percentage"] > 0.7
            assert len(result["gaps"]) > 0

    @pytest.mark.asyncio
    async def test_rule_effectiveness_metrics(self):
        """Test detection rule effectiveness metrics."""
        with patch("agentic_soc.knowledge.DetectionKB") as mock_det:
            mock_instance = MagicMock()
            mock_det.return_value = mock_instance

            mock_instance.get_rule_effectiveness.return_value = {
                "rule_id": "win_susp_powershell_enc_cmd",
                "period": "last_30_days",
                "total_triggers": 450,
                "true_positives": 382,
                "false_positives": 68,
                "precision": 0.849,
                "recall": 0.91,
                "f1_score": 0.878,
                "mean_time_to_triage": "5m",
                "auto_closed": 45,
                "escalated_to_investigation": 337,
                "severity_distribution": {
                    "critical": 12,
                    "high": 245,
                    "medium": 125,
                    "low": 0
                },
                "top_false_positive_sources": [
                    {"source": "admin_workstations", "count": 35},
                    {"source": "deployment_servers", "count": 20}
                ],
                "tuning_suggestions": [
                    "Exclude admin_workstations from rule",
                    "Add whitelist for deployment_servers"
                ]
            }

            result = mock_instance.get_rule_effectiveness("win_susp_powershell_enc_cmd")

            assert result["precision"] > 0.8
            assert result["f1_score"] > 0.85


class TestContextKnowledgeBase:
    """Tests for environmental context knowledge base."""

    @pytest.mark.asyncio
    async def test_asset_criticality_lookup(self):
        """Test asset criticality and context lookup."""
        with patch("agentic_soc.knowledge.ContextKB") as mock_ctx:
            mock_instance = MagicMock()
            mock_ctx.return_value = mock_instance

            mock_instance.get_asset_context.return_value = {
                "hostname": "dc01.company.local",
                "asset_type": "domain_controller",
                "criticality": "critical",
                "criticality_score": 100,
                "business_context": {
                    "owner": "IT Infrastructure",
                    "applications": ["Active Directory", "DNS", "DHCP"],
                    "data_classification": "highly_confidential"
                },
                "network_context": {
                    "segment": "core_infrastructure",
                    "vlan": 10,
                    "internet_facing": False
                },
                "compliance": {
                    "frameworks": ["PCI-DSS", "SOX", "HIPAA"],
                    "last_audit": "2024-01-01"
                },
                "security_controls": {
                    "edr_agent": True,
                    "vulnerability_scan": "weekly",
                    "privileged_access": ["domain_admins"]
                },
                "incident_history": {
                    "total_incidents": 2,
                    "last_incident": "2023-06-15",
                    "types": ["unauthorized_access_attempt"]
                }
            }

            result = mock_instance.get_asset_context("dc01.company.local")

            assert result["criticality"] == "critical"
            assert result["criticality_score"] == 100
            assert result["asset_type"] == "domain_controller"

    @pytest.mark.asyncio
    async def test_user_risk_profile(self):
        """Test user risk profile lookup."""
        with patch("agentic_soc.knowledge.ContextKB") as mock_ctx:
            mock_instance = MagicMock()
            mock_ctx.return_value = mock_instance

            mock_instance.get_user_risk_profile.return_value = {
                "user_id": "jsmith@company.com",
                "display_name": "John Smith",
                "department": "Finance",
                "title": "CFO",
                "risk_score": 85,
                "risk_factors": [
                    {"factor": "privileged_access", "weight": 0.3},
                    {"factor": "sensitive_data_access", "weight": 0.25},
                    {"factor": "external_communication", "weight": 0.15},
                    {"factor": "high_value_target", "weight": 0.3}
                ],
                "privileged_accounts": [
                    "admin_finance_systems",
                    "banking_portal_admin"
                ],
                "data_access": {
                    "financial_records": True,
                    "pii": True,
                    "intellectual_property": False
                },
                "behavioral_baseline": {
                    "typical_login_times": "08:00-18:00 EST",
                    "typical_locations": ["HQ", "Home Office"],
                    "typical_applications": ["SAP", "Excel", "Outlook"]
                },
                "security_training": {
                    "last_completed": "2024-01-10",
                    "phishing_simulation_score": 0.9
                },
                "recent_alerts": 0
            }

            result = mock_instance.get_user_risk_profile("jsmith@company.com")

            assert result["risk_score"] >= 80
            assert result["title"] == "CFO"
            assert len(result["privileged_accounts"]) > 0

    @pytest.mark.asyncio
    async def test_network_segment_context(self):
        """Test network segment context and criticality."""
        with patch("agentic_soc.knowledge.ContextKB") as mock_ctx:
            mock_instance = MagicMock()
            mock_ctx.return_value = mock_instance

            mock_instance.get_network_context.return_value = {
                "segment_name": "PCI_Zone",
                "vlan_ids": [100, 101, 102],
                "subnet": "10.100.0.0/16",
                "criticality": "critical",
                "compliance_scope": ["PCI-DSS"],
                "assets": {
                    "total": 45,
                    "by_type": {
                        "payment_servers": 5,
                        "databases": 3,
                        "workstations": 30,
                        "network_devices": 7
                    }
                },
                "security_controls": {
                    "firewall_rules": "strict",
                    "ids_enabled": True,
                    "dlp_enabled": True,
                    "encryption_required": True
                },
                "allowed_communications": {
                    "inbound": ["management_zone"],
                    "outbound": ["logging_zone", "backup_zone"]
                },
                "monitoring": {
                    "network_tap": True,
                    "full_packet_capture": True,
                    "log_retention": "365d"
                }
            }

            result = mock_instance.get_network_context("PCI_Zone")

            assert result["criticality"] == "critical"
            assert "PCI-DSS" in result["compliance_scope"]
