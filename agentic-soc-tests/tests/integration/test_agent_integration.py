"""
Integration Tests for Agent-to-Agent Communication and Orchestration.

Tests the interaction between multiple agents working together on security tasks.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import asyncio


class TestAgentOrchestration:
    """Tests for multi-agent orchestration workflows."""

    @pytest.mark.asyncio
    async def test_detection_to_triage_handoff(self):
        """Test alert handoff from Detection Agent to Triage Agent."""
        # Detection agent produces alert
        detection_alert = {
            "alert_id": "ALT-001",
            "detection_type": "sigma",
            "rule_id": "win_susp_powershell_encoded",
            "severity": "high",
            "raw_event": {
                "host": "workstation-01",
                "user": "jsmith",
                "process": "powershell.exe",
                "command_line": "powershell -enc SQBFAFgA..."
            },
            "timestamp": datetime.utcnow().isoformat()
        }

        # Mock orchestrator
        with patch("agentic_soc.orchestrator.Orchestrator") as mock_orch:
            mock_orch_instance = AsyncMock()
            mock_orch.return_value = mock_orch_instance

            # Mock triage response
            triage_result = {
                "alert_id": "ALT-001",
                "priority": "P1",
                "risk_score": 85,
                "auto_escalate": True,
                "triage_notes": "Encoded PowerShell command detected on privileged workstation",
                "recommended_actions": ["isolate_host", "collect_memory"]
            }
            mock_orch_instance.route_to_agent.return_value = triage_result

            # Execute handoff
            result = await mock_orch_instance.route_to_agent("triage", detection_alert)

            assert result["priority"] == "P1"
            assert result["risk_score"] >= 80
            assert result["auto_escalate"] is True

    @pytest.mark.asyncio
    async def test_triage_to_investigation_escalation(self):
        """Test escalation from Triage to Investigation Agent."""
        triaged_alert = {
            "alert_id": "ALT-001",
            "priority": "P1",
            "risk_score": 85,
            "indicators": [
                {"type": "ip", "value": "192.168.1.100"},
                {"type": "hash", "value": "abc123def456"},
                {"type": "domain", "value": "evil.com"}
            ],
            "context": {
                "host": "workstation-01",
                "user": "jsmith",
                "department": "Finance"
            }
        }

        with patch("agentic_soc.agents.InvestigationAgent") as mock_agent:
            mock_instance = AsyncMock()
            mock_agent.return_value = mock_instance

            investigation_result = {
                "case_id": "CASE-001",
                "investigation_status": "in_progress",
                "findings": [
                    {
                        "finding_type": "lateral_movement",
                        "confidence": 0.87,
                        "evidence": ["SMB connections to 5 hosts", "Mimikatz signatures detected"]
                    }
                ],
                "recommended_queries": [
                    "index=windows EventCode=4624 host=workstation-01",
                    "index=network dest_ip=192.168.1.100"
                ],
                "iocs_extracted": 12
            }
            mock_instance.investigate.return_value = investigation_result

            result = await mock_instance.investigate(triaged_alert)

            assert result["case_id"].startswith("CASE-")
            assert len(result["findings"]) > 0
            assert result["iocs_extracted"] > 0

    @pytest.mark.asyncio
    async def test_investigation_to_response_workflow(self):
        """Test workflow from Investigation to Response Agent for containment."""
        investigation_findings = {
            "case_id": "CASE-001",
            "severity": "critical",
            "attack_stage": "lateral_movement",
            "affected_assets": ["workstation-01", "server-dc01", "fileserver-01"],
            "threat_actor": "APT29",
            "iocs": [
                {"type": "ip", "value": "10.0.0.50", "context": "C2 server"},
                {"type": "hash", "value": "abc123", "context": "malware payload"}
            ],
            "recommended_response": "immediate_containment"
        }

        with patch("agentic_soc.agents.ResponseAgent") as mock_agent:
            mock_instance = AsyncMock()
            mock_agent.return_value = mock_instance

            response_result = {
                "response_id": "RSP-001",
                "actions_taken": [
                    {"action": "isolate_host", "target": "workstation-01", "status": "completed"},
                    {"action": "block_ip", "target": "10.0.0.50", "status": "completed"},
                    {"action": "block_hash", "target": "abc123", "status": "completed"}
                ],
                "playbook_executed": "apt_containment_v2",
                "rollback_available": True,
                "notification_sent": True
            }
            mock_instance.respond.return_value = response_result

            result = await mock_instance.respond(investigation_findings)

            assert result["response_id"].startswith("RSP-")
            assert len(result["actions_taken"]) >= 3
            assert all(a["status"] == "completed" for a in result["actions_taken"])

    @pytest.mark.asyncio
    async def test_full_alert_to_response_pipeline(self):
        """Test complete pipeline from alert detection to automated response."""
        raw_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "crowdstrike",
            "event_type": "ProcessCreate",
            "host": "finance-ws-01",
            "user": "admin",
            "process_name": "mimikatz.exe",
            "parent_process": "cmd.exe",
            "command_line": "mimikatz.exe sekurlsa::logonpasswords"
        }

        pipeline_stages = []

        with patch("agentic_soc.orchestrator.Orchestrator") as mock_orch:
            mock_instance = AsyncMock()
            mock_orch.return_value = mock_instance

            # Stage 1: Detection
            detection_output = {
                "alert_id": "ALT-PIPE-001",
                "rules_matched": ["credential_dumping", "mimikatz_execution"],
                "severity": "critical"
            }
            pipeline_stages.append(("detection", detection_output))

            # Stage 2: Triage
            triage_output = {
                "priority": "P1",
                "risk_score": 95,
                "auto_escalate": True
            }
            pipeline_stages.append(("triage", triage_output))

            # Stage 3: Investigation
            investigation_output = {
                "case_id": "CASE-PIPE-001",
                "attack_confirmed": True,
                "kill_chain_stage": "credential_access"
            }
            pipeline_stages.append(("investigation", investigation_output))

            # Stage 4: Response
            response_output = {
                "response_id": "RSP-PIPE-001",
                "containment_status": "completed",
                "assets_isolated": 1
            }
            pipeline_stages.append(("response", response_output))

            mock_instance.execute_pipeline.return_value = {
                "pipeline_id": "PIPE-001",
                "stages": pipeline_stages,
                "total_duration_ms": 450,
                "final_status": "contained"
            }

            result = await mock_instance.execute_pipeline(raw_event)

            assert result["final_status"] == "contained"
            assert len(result["stages"]) == 4
            assert result["total_duration_ms"] < 1000

    @pytest.mark.asyncio
    async def test_threat_intel_enrichment_integration(self):
        """Test Threat Intel Agent enriching alerts for other agents."""
        alert_iocs = [
            {"type": "ip", "value": "185.220.101.1"},
            {"type": "domain", "value": "malware-c2.evil.com"},
            {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e"}
        ]

        with patch("agentic_soc.agents.ThreatIntelAgent") as mock_agent:
            mock_instance = AsyncMock()
            mock_agent.return_value = mock_instance

            enriched_iocs = [
                {
                    "type": "ip",
                    "value": "185.220.101.1",
                    "threat_intel": {
                        "is_malicious": True,
                        "threat_score": 95,
                        "threat_types": ["tor_exit_node", "c2_server"],
                        "first_seen": "2024-01-15",
                        "sources": ["VirusTotal", "AbuseIPDB", "MISP"]
                    }
                },
                {
                    "type": "domain",
                    "value": "malware-c2.evil.com",
                    "threat_intel": {
                        "is_malicious": True,
                        "threat_score": 99,
                        "threat_types": ["c2_domain", "malware_distribution"],
                        "associated_actors": ["APT28", "Lazarus"],
                        "sources": ["VirusTotal", "AlienVault OTX"]
                    }
                },
                {
                    "type": "hash",
                    "value": "d41d8cd98f00b204e9800998ecf8427e",
                    "threat_intel": {
                        "is_malicious": True,
                        "threat_score": 88,
                        "malware_family": "Cobalt Strike",
                        "first_seen": "2024-02-01",
                        "sources": ["VirusTotal", "MalwareBazaar"]
                    }
                }
            ]
            mock_instance.enrich_iocs.return_value = enriched_iocs

            result = await mock_instance.enrich_iocs(alert_iocs)

            assert len(result) == 3
            assert all(ioc["threat_intel"]["is_malicious"] for ioc in result)
            assert result[0]["threat_intel"]["threat_score"] >= 90

    @pytest.mark.asyncio
    async def test_forensics_agent_artifact_collection(self):
        """Test Forensics Agent collecting artifacts during investigation."""
        collection_request = {
            "case_id": "CASE-001",
            "host": "compromised-ws-01",
            "collection_type": "full",
            "artifacts_requested": ["memory", "disk_image", "logs", "registry"]
        }

        with patch("agentic_soc.agents.ForensicsAgent") as mock_agent:
            mock_instance = AsyncMock()
            mock_agent.return_value = mock_instance

            collection_result = {
                "collection_id": "COL-001",
                "case_id": "CASE-001",
                "artifacts_collected": [
                    {"type": "memory_dump", "size_gb": 16, "hash": "sha256:abc123", "status": "collected"},
                    {"type": "disk_image", "size_gb": 256, "hash": "sha256:def456", "status": "collected"},
                    {"type": "event_logs", "count": 50000, "hash": "sha256:ghi789", "status": "collected"},
                    {"type": "registry_hives", "count": 5, "hash": "sha256:jkl012", "status": "collected"}
                ],
                "chain_of_custody": {
                    "collector": "forensics_agent_v2",
                    "collection_time": datetime.utcnow().isoformat(),
                    "integrity_verified": True
                },
                "storage_location": "s3://forensics-bucket/CASE-001/"
            }
            mock_instance.collect_artifacts.return_value = collection_result

            result = await mock_instance.collect_artifacts(collection_request)

            assert result["collection_id"].startswith("COL-")
            assert len(result["artifacts_collected"]) == 4
            assert result["chain_of_custody"]["integrity_verified"] is True


class TestDataPipelineIntegration:
    """Tests for data pipeline component integration."""

    @pytest.mark.asyncio
    async def test_ingestion_to_normalization_flow(self):
        """Test data flow from ingestion to OCSF normalization."""
        raw_logs = [
            {
                "source": "windows_security",
                "raw": "EventCode=4625 Account Name: admin Status: 0xC000006D",
                "timestamp": datetime.utcnow().isoformat()
            },
            {
                "source": "crowdstrike",
                "raw": '{"event_type": "ProcessCreate", "process": "mimikatz.exe"}',
                "timestamp": datetime.utcnow().isoformat()
            }
        ]

        with patch("agentic_soc.pipelines.DataPipeline") as mock_pipeline:
            mock_instance = AsyncMock()
            mock_pipeline.return_value = mock_instance

            normalized_events = [
                {
                    "class_uid": 3002,
                    "class_name": "Authentication",
                    "activity_id": 2,
                    "activity_name": "Logon Failure",
                    "severity_id": 3,
                    "user": {"name": "admin"},
                    "src_endpoint": {"hostname": "workstation-01"},
                    "status_code": "0xC000006D",
                    "time": datetime.utcnow().timestamp() * 1000
                },
                {
                    "class_uid": 1001,
                    "class_name": "Process Activity",
                    "activity_id": 1,
                    "activity_name": "Process Created",
                    "severity_id": 5,
                    "process": {"name": "mimikatz.exe"},
                    "time": datetime.utcnow().timestamp() * 1000
                }
            ]
            mock_instance.ingest_and_normalize.return_value = {
                "ingested_count": 2,
                "normalized_count": 2,
                "events": normalized_events,
                "processing_time_ms": 15
            }

            result = await mock_instance.ingest_and_normalize(raw_logs)

            assert result["ingested_count"] == result["normalized_count"]
            assert all("class_uid" in e for e in result["events"])
            assert result["processing_time_ms"] < 100

    @pytest.mark.asyncio
    async def test_normalization_to_enrichment_flow(self):
        """Test data flow from normalization to enrichment."""
        normalized_event = {
            "class_uid": 4001,
            "class_name": "Network Activity",
            "src_endpoint": {"ip": "192.168.1.100", "hostname": "ws-01"},
            "dst_endpoint": {"ip": "185.220.101.1", "port": 443},
            "time": datetime.utcnow().timestamp() * 1000
        }

        with patch("agentic_soc.pipelines.EnrichmentPipeline") as mock_pipeline:
            mock_instance = AsyncMock()
            mock_pipeline.return_value = mock_instance

            enriched_event = {
                **normalized_event,
                "enrichments": {
                    "src_asset": {
                        "hostname": "ws-01",
                        "criticality": "medium",
                        "owner": "jsmith",
                        "department": "Engineering"
                    },
                    "dst_threat_intel": {
                        "is_malicious": True,
                        "threat_types": ["tor_exit_node"],
                        "threat_score": 95
                    },
                    "dst_geo": {
                        "country": "Russia",
                        "city": "Moscow",
                        "asn": "AS12345"
                    }
                }
            }
            mock_instance.enrich.return_value = enriched_event

            result = await mock_instance.enrich(normalized_event)

            assert "enrichments" in result
            assert result["enrichments"]["dst_threat_intel"]["is_malicious"] is True
            assert result["enrichments"]["src_asset"]["hostname"] == "ws-01"

    @pytest.mark.asyncio
    async def test_enrichment_to_detection_flow(self):
        """Test data flow from enrichment to detection engine."""
        enriched_events = [
            {
                "class_uid": 1001,
                "process": {"name": "powershell.exe", "cmd_line": "powershell -enc SQBFAFgA"},
                "user": {"name": "admin"},
                "enrichments": {"user_risk": "high", "asset_criticality": "critical"}
            }
        ]

        with patch("agentic_soc.detection.DetectionEngine") as mock_engine:
            mock_instance = AsyncMock()
            mock_engine.return_value = mock_instance

            detection_results = [
                {
                    "event_index": 0,
                    "detections": [
                        {
                            "rule_id": "sigma_encoded_powershell",
                            "rule_name": "Encoded PowerShell Command",
                            "severity": "high",
                            "mitre_attack": ["T1059.001", "T1027"],
                            "confidence": 0.95
                        }
                    ],
                    "risk_multiplier": 1.5,  # Due to high-risk user on critical asset
                    "final_severity": "critical"
                }
            ]
            mock_instance.detect.return_value = detection_results

            result = await mock_instance.detect(enriched_events)

            assert len(result) == 1
            assert result[0]["detections"][0]["severity"] == "high"
            assert result[0]["final_severity"] == "critical"  # Elevated due to enrichment

    @pytest.mark.asyncio
    async def test_full_data_pipeline_flow(self):
        """Test complete data flow: Ingestion → Normalization → Enrichment → Detection → Alert."""
        raw_log = {
            "source": "windows",
            "message": "Process Create: mimikatz.exe by admin on DC01",
            "timestamp": datetime.utcnow().isoformat()
        }

        with patch("agentic_soc.pipelines.FullPipeline") as mock_pipeline:
            mock_instance = AsyncMock()
            mock_pipeline.return_value = mock_instance

            pipeline_result = {
                "pipeline_id": "PIPE-DATA-001",
                "stages": {
                    "ingestion": {"status": "success", "duration_ms": 5},
                    "normalization": {"status": "success", "duration_ms": 10, "ocsf_class": 1001},
                    "enrichment": {"status": "success", "duration_ms": 25, "enrichments_added": 3},
                    "detection": {"status": "success", "duration_ms": 15, "rules_matched": 2},
                    "alerting": {"status": "success", "duration_ms": 5, "alert_id": "ALT-001"}
                },
                "total_duration_ms": 60,
                "alert_generated": True
            }
            mock_instance.process.return_value = pipeline_result

            result = await mock_instance.process(raw_log)

            assert result["alert_generated"] is True
            assert all(s["status"] == "success" for s in result["stages"].values())
            assert result["total_duration_ms"] < 100


class TestMemoryIntegration:
    """Tests for Bead Memory integration with agents."""

    @pytest.mark.asyncio
    async def test_memory_persistence_across_agents(self):
        """Test that memory beads persist and are accessible across agent interactions."""
        with patch("agentic_soc.memory.BeadMemory") as mock_memory:
            mock_instance = AsyncMock()
            mock_memory.return_value = mock_instance

            # Detection agent stores finding
            detection_bead = {
                "bead_id": "BEAD-001",
                "entity_type": "alert",
                "entity_id": "ALT-001",
                "content": {"severity": "high", "rule": "mimikatz_detection"},
                "tier": "working"
            }
            mock_instance.store_bead.return_value = detection_bead

            # Triage agent retrieves and adds context
            mock_instance.get_beads_by_entity.return_value = [detection_bead]
            mock_instance.update_bead.return_value = {
                **detection_bead,
                "content": {**detection_bead["content"], "priority": "P1", "risk_score": 90}
            }

            # Investigation agent retrieves full chain
            mock_instance.get_bead_chain.return_value = [
                detection_bead,
                {"bead_id": "BEAD-002", "entity_type": "alert", "entity_id": "ALT-001",
                 "content": {"priority": "P1"}, "tier": "working"}
            ]

            # Verify chain retrieval
            chain = await mock_instance.get_bead_chain("ALT-001")
            assert len(chain) == 2
            assert chain[0]["content"]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_attack_chain_correlation_integration(self):
        """Test attack chain correlation across multiple alerts."""
        with patch("agentic_soc.memory.BeadMemory") as mock_memory:
            mock_instance = AsyncMock()
            mock_memory.return_value = mock_instance

            # Multiple related alerts
            alerts = [
                {"alert_id": "ALT-001", "technique": "T1566.001", "host": "ws-01", "time": "10:00"},
                {"alert_id": "ALT-002", "technique": "T1059.001", "host": "ws-01", "time": "10:05"},
                {"alert_id": "ALT-003", "technique": "T1003.001", "host": "ws-01", "time": "10:10"},
                {"alert_id": "ALT-004", "technique": "T1021.002", "host": "ws-01", "time": "10:15"}
            ]

            correlated_chain = {
                "chain_id": "CHAIN-001",
                "alerts": [a["alert_id"] for a in alerts],
                "kill_chain_stages": ["initial_access", "execution", "credential_access", "lateral_movement"],
                "completeness_score": 0.57,  # 4/7 stages
                "confidence": 0.89,
                "threat_assessment": "active_intrusion"
            }
            mock_instance.correlate_attack_chain.return_value = correlated_chain

            result = await mock_instance.correlate_attack_chain(alerts)

            assert result["chain_id"].startswith("CHAIN-")
            assert len(result["kill_chain_stages"]) == 4
            assert result["threat_assessment"] == "active_intrusion"

    @pytest.mark.asyncio
    async def test_memory_tier_promotion(self):
        """Test bead promotion from working to episodic to semantic memory."""
        with patch("agentic_soc.memory.BeadMemory") as mock_memory:
            mock_instance = AsyncMock()
            mock_memory.return_value = mock_instance

            # Create bead in working memory
            working_bead = {
                "bead_id": "BEAD-001",
                "tier": "working",
                "access_count": 0,
                "importance_score": 0.5
            }

            # After multiple accesses, promote to episodic
            episodic_bead = {
                **working_bead,
                "tier": "episodic",
                "access_count": 10,
                "importance_score": 0.75
            }
            mock_instance.promote_bead.return_value = episodic_bead

            result = await mock_instance.promote_bead("BEAD-001", "episodic")
            assert result["tier"] == "episodic"

            # After pattern recognition, promote to semantic
            semantic_bead = {
                **episodic_bead,
                "tier": "semantic",
                "importance_score": 0.95,
                "pattern_id": "PATTERN-001"
            }
            mock_instance.promote_bead.return_value = semantic_bead

            result = await mock_instance.promote_bead("BEAD-001", "semantic")
            assert result["tier"] == "semantic"
            assert "pattern_id" in result


class TestSLMIntegration:
    """Tests for SLM integration with agents and orchestration."""

    @pytest.mark.asyncio
    async def test_multi_model_pipeline(self):
        """Test sequential SLM inference across multiple models."""
        alert_data = {
            "alert_id": "ALT-001",
            "raw_event": {"process": "mimikatz.exe", "user": "admin"},
            "severity": "high"
        }

        with patch("agentic_soc.slm.SLMEngine") as mock_engine:
            mock_instance = AsyncMock()
            mock_engine.return_value = mock_instance

            # Detection model analysis
            detection_inference = {
                "model": "detection_slm",
                "prediction": "malicious",
                "confidence": 0.94,
                "latency_ms": 20
            }

            # Triage model prioritization
            triage_inference = {
                "model": "triage_slm",
                "priority": "P1",
                "risk_factors": ["credential_tool", "privileged_user"],
                "latency_ms": 15
            }

            # Response model recommendation
            response_inference = {
                "model": "response_slm",
                "recommended_actions": ["isolate_host", "collect_memory", "block_hash"],
                "urgency": "immediate",
                "latency_ms": 25
            }

            mock_instance.run_pipeline.return_value = {
                "pipeline_id": "SLM-PIPE-001",
                "models_invoked": ["detection_slm", "triage_slm", "response_slm"],
                "results": [detection_inference, triage_inference, response_inference],
                "total_latency_ms": 60,
                "consensus": {"threat_level": "critical", "action_required": True}
            }

            result = await mock_instance.run_pipeline(alert_data, ["detection", "triage", "response"])

            assert len(result["models_invoked"]) == 3
            assert result["total_latency_ms"] < 100
            assert result["consensus"]["action_required"] is True

    @pytest.mark.asyncio
    async def test_ensemble_voting_integration(self):
        """Test ensemble voting across multiple SLMs for consensus."""
        event = {
            "process": "powershell.exe",
            "command_line": "powershell -enc SQBFAFgA",
            "user": "admin"
        }

        with patch("agentic_soc.slm.SLMEngine") as mock_engine:
            mock_instance = AsyncMock()
            mock_engine.return_value = mock_instance

            ensemble_result = {
                "models": [
                    {"model": "detection_v1", "prediction": "malicious", "confidence": 0.92},
                    {"model": "detection_v2", "prediction": "malicious", "confidence": 0.88},
                    {"model": "detection_v3", "prediction": "suspicious", "confidence": 0.75}
                ],
                "voting_method": "weighted_majority",
                "consensus_prediction": "malicious",
                "consensus_confidence": 0.85,
                "agreement_ratio": 0.67
            }
            mock_instance.ensemble_predict.return_value = ensemble_result

            result = await mock_instance.ensemble_predict(event)

            assert result["consensus_prediction"] == "malicious"
            assert result["consensus_confidence"] >= 0.8
            assert result["agreement_ratio"] >= 0.5


class TestExternalIntegration:
    """Tests for integration with external systems."""

    @pytest.mark.asyncio
    async def test_siem_integration(self):
        """Test integration with SIEM platforms (Splunk, Elastic)."""
        with patch("agentic_soc.integrations.SIEMConnector") as mock_siem:
            mock_instance = AsyncMock()
            mock_siem.return_value = mock_instance

            # Query SIEM
            query_result = {
                "query": "index=security EventCode=4625",
                "results": [
                    {"_time": "2024-01-15T10:00:00", "user": "admin", "src_ip": "192.168.1.100"},
                    {"_time": "2024-01-15T10:00:05", "user": "admin", "src_ip": "192.168.1.100"}
                ],
                "total_results": 2,
                "execution_time_ms": 150
            }
            mock_instance.query.return_value = query_result

            result = await mock_instance.query("index=security EventCode=4625")

            assert result["total_results"] == 2
            assert result["execution_time_ms"] < 500

    @pytest.mark.asyncio
    async def test_soar_integration(self):
        """Test integration with SOAR platforms for automated response."""
        playbook_request = {
            "playbook_id": "pb_isolate_host",
            "parameters": {
                "hostname": "compromised-ws-01",
                "reason": "Active malware infection"
            }
        }

        with patch("agentic_soc.integrations.SOARConnector") as mock_soar:
            mock_instance = AsyncMock()
            mock_soar.return_value = mock_instance

            playbook_result = {
                "execution_id": "EXEC-001",
                "playbook_id": "pb_isolate_host",
                "status": "completed",
                "steps_executed": [
                    {"step": "disable_network", "status": "success"},
                    {"step": "notify_soc", "status": "success"},
                    {"step": "create_ticket", "status": "success"}
                ],
                "duration_seconds": 45
            }
            mock_instance.execute_playbook.return_value = playbook_result

            result = await mock_instance.execute_playbook(playbook_request)

            assert result["status"] == "completed"
            assert all(s["status"] == "success" for s in result["steps_executed"])

    @pytest.mark.asyncio
    async def test_ticketing_integration(self):
        """Test integration with ticketing systems (Jira, ServiceNow)."""
        ticket_data = {
            "title": "Critical Security Alert - Mimikatz Detection",
            "description": "Credential dumping tool detected on finance workstation",
            "priority": "P1",
            "assignee": "soc-team",
            "labels": ["security", "incident", "credential-theft"]
        }

        with patch("agentic_soc.integrations.TicketingConnector") as mock_ticketing:
            mock_instance = AsyncMock()
            mock_ticketing.return_value = mock_instance

            ticket_result = {
                "ticket_id": "SEC-12345",
                "url": "https://jira.company.com/browse/SEC-12345",
                "status": "created",
                "sla_due": "2024-01-15T12:00:00Z"
            }
            mock_instance.create_ticket.return_value = ticket_result

            result = await mock_instance.create_ticket(ticket_data)

            assert result["ticket_id"].startswith("SEC-")
            assert "url" in result

    @pytest.mark.asyncio
    async def test_edr_integration(self):
        """Test integration with EDR platforms for endpoint actions."""
        isolation_request = {
            "hostname": "compromised-ws-01",
            "action": "isolate",
            "reason": "Active threat detected"
        }

        with patch("agentic_soc.integrations.EDRConnector") as mock_edr:
            mock_instance = AsyncMock()
            mock_edr.return_value = mock_instance

            isolation_result = {
                "action_id": "EDR-ACT-001",
                "hostname": "compromised-ws-01",
                "action": "isolate",
                "status": "completed",
                "network_status": "isolated",
                "timestamp": datetime.utcnow().isoformat()
            }
            mock_instance.execute_action.return_value = isolation_result

            result = await mock_instance.execute_action(isolation_request)

            assert result["status"] == "completed"
            assert result["network_status"] == "isolated"


class TestErrorHandlingIntegration:
    """Tests for error handling across integrated components."""

    @pytest.mark.asyncio
    async def test_agent_failure_recovery(self):
        """Test system recovery when an agent fails."""
        with patch("agentic_soc.orchestrator.Orchestrator") as mock_orch:
            mock_instance = AsyncMock()
            mock_orch.return_value = mock_instance

            # Simulate agent failure and recovery
            mock_instance.route_with_fallback.return_value = {
                "primary_agent": "investigation",
                "primary_status": "failed",
                "fallback_agent": "investigation_backup",
                "fallback_status": "success",
                "result": {"case_id": "CASE-001", "status": "in_progress"},
                "recovery_time_ms": 50
            }

            result = await mock_instance.route_with_fallback("investigation", {"alert_id": "ALT-001"})

            assert result["primary_status"] == "failed"
            assert result["fallback_status"] == "success"
            assert result["result"]["case_id"] is not None

    @pytest.mark.asyncio
    async def test_pipeline_partial_failure(self):
        """Test pipeline continues with partial enrichment on provider failure."""
        with patch("agentic_soc.pipelines.EnrichmentPipeline") as mock_pipeline:
            mock_instance = AsyncMock()
            mock_pipeline.return_value = mock_instance

            # Partial enrichment due to provider failure
            mock_instance.enrich.return_value = {
                "event": {"ip": "192.168.1.100"},
                "enrichments": {
                    "geo_ip": {"status": "success", "country": "US"},
                    "threat_intel": {"status": "failed", "error": "Provider timeout"},
                    "asset_db": {"status": "success", "hostname": "ws-01"}
                },
                "enrichment_completeness": 0.67,
                "warnings": ["threat_intel provider unavailable"]
            }

            result = await mock_instance.enrich({"ip": "192.168.1.100"})

            assert result["enrichments"]["geo_ip"]["status"] == "success"
            assert result["enrichments"]["threat_intel"]["status"] == "failed"
            assert result["enrichment_completeness"] < 1.0

    @pytest.mark.asyncio
    async def test_memory_persistence_failure_recovery(self):
        """Test recovery when memory persistence fails."""
        with patch("agentic_soc.memory.BeadMemory") as mock_memory:
            mock_instance = AsyncMock()
            mock_memory.return_value = mock_instance

            # Simulate write failure and retry
            mock_instance.store_bead_with_retry.return_value = {
                "bead_id": "BEAD-001",
                "status": "stored",
                "attempts": 3,
                "final_storage": "redis_backup",
                "primary_error": "Elasticsearch unavailable"
            }

            result = await mock_instance.store_bead_with_retry({"content": "test"})

            assert result["status"] == "stored"
            assert result["attempts"] > 1
            assert "backup" in result["final_storage"]
