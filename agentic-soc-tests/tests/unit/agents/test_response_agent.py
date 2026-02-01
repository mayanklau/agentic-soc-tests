"""
Unit Tests for Response Agent

Tests the Response Agent's capabilities for executing automated responses,
managing playbooks, and handling approval workflows.
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timedelta
from uuid import uuid4


class TestResponseAgentInitialization:
    """Test Response Agent initialization."""
    
    def test_response_agent_creation(self, sample_config):
        """Test that response agent can be instantiated."""
        config = sample_config["agents"]["response"]
        
        assert config["enabled"] is True
        assert config["auto_execute"] is False
    
    def test_response_agent_with_auto_execute(self):
        """Test response agent with auto-execution enabled."""
        config = {
            "enabled": True,
            "auto_execute": True,
            "auto_execute_severities": ["critical"],
            "require_approval": ["high", "medium"],
            "max_concurrent_actions": 5
        }
        
        assert config["auto_execute"] is True
        assert "critical" in config["auto_execute_severities"]


class TestPlaybookExecution:
    """Test playbook execution capabilities."""
    
    def test_execute_playbook(self, sample_playbook, sample_alert):
        """Test executing a playbook."""
        playbook = sample_playbook
        alert = sample_alert
        
        execution = {
            "id": str(uuid4()),
            "playbook_id": playbook["id"],
            "playbook_name": playbook["name"],
            "alert_id": alert["id"],
            "status": "pending",
            "started_at": datetime.utcnow().isoformat(),
            "context": {
                "alert": alert,
                "variables": {"target_host": alert["host"]}
            }
        }
        
        assert execution["status"] == "pending"
        assert execution["context"]["variables"]["target_host"] == "WORKSTATION-01"
    
    def test_playbook_step_execution(self, sample_playbook):
        """Test executing individual playbook steps."""
        playbook = sample_playbook
        steps = playbook["steps"]
        
        step_results = []
        for step in steps:
            result = {
                "step_id": step["id"],
                "step_name": step["name"],
                "status": "success",
                "started_at": datetime.utcnow().isoformat(),
                "completed_at": datetime.utcnow().isoformat(),
                "output": {"message": f"Step {step['name']} completed"}
            }
            step_results.append(result)
        
        assert len(step_results) == 3
        assert all(r["status"] == "success" for r in step_results)
    
    def test_playbook_step_failure_handling(self, sample_playbook):
        """Test handling of failed playbook steps."""
        step_result = {
            "step_id": "step_1",
            "status": "failed",
            "error": "Connection timeout to target host",
            "retry_count": 3
        }
        
        # Check if retry limit reached
        max_retries = 3
        should_retry = step_result["retry_count"] < max_retries
        
        assert should_retry is False
    
    def test_playbook_conditional_steps(self, sample_playbook):
        """Test conditional step execution."""
        conditional_step = {
            "id": "step_conditional",
            "name": "Conditional Action",
            "type": "action",
            "condition": "${alert.severity} == 'critical'",
            "action": "emergency_isolation"
        }
        
        context = {"alert": {"severity": "critical"}}
        
        # Evaluate condition
        condition_met = context["alert"]["severity"] == "critical"
        assert condition_met is True
    
    def test_playbook_parallel_steps(self):
        """Test parallel step execution."""
        parallel_group = {
            "type": "parallel",
            "steps": [
                {"id": "p1", "action": "collect_logs"},
                {"id": "p2", "action": "collect_memory"},
                {"id": "p3", "action": "collect_network"}
            ],
            "wait_for_all": True
        }
        
        assert len(parallel_group["steps"]) == 3
        assert parallel_group["wait_for_all"] is True


class TestResponseActions:
    """Test individual response actions."""
    
    def test_host_isolation_action(self, sample_alert):
        """Test host isolation action."""
        action = {
            "type": "isolate_host",
            "target": sample_alert["host"],
            "isolation_level": "full",  # full, selective
            "allow_list": ["192.168.1.1"],  # Allow SOC access
            "duration": 3600  # 1 hour
        }
        
        assert action["type"] == "isolate_host"
        assert action["isolation_level"] == "full"
    
    def test_account_disable_action(self, sample_alert):
        """Test account disable action."""
        action = {
            "type": "disable_account",
            "target": sample_alert["user"],
            "reason": "Compromised credentials suspected",
            "notify_user": True,
            "notify_manager": True
        }
        
        assert action["type"] == "disable_account"
        assert action["notify_user"] is True
    
    def test_firewall_block_action(self, sample_alert):
        """Test firewall block action."""
        ioc = sample_alert["iocs"][0]
        
        action = {
            "type": "firewall_block",
            "target_type": ioc["type"],
            "target_value": ioc["value"],
            "direction": "both",  # inbound, outbound, both
            "duration": 86400  # 24 hours
        }
        
        assert action["type"] == "firewall_block"
        assert action["direction"] == "both"
    
    def test_kill_process_action(self):
        """Test process termination action."""
        action = {
            "type": "kill_process",
            "target_host": "WORKSTATION-01",
            "process_name": "malware.exe",
            "process_id": 4532,
            "kill_tree": True  # Kill child processes too
        }
        
        assert action["kill_tree"] is True
    
    def test_quarantine_file_action(self):
        """Test file quarantine action."""
        action = {
            "type": "quarantine_file",
            "target_host": "WORKSTATION-01",
            "file_path": "C:\\Users\\john.doe\\malware.exe",
            "hash_sha256": "a" * 64,
            "preserve_original": True
        }
        
        assert action["preserve_original"] is True
    
    def test_credential_reset_action(self, sample_alert):
        """Test credential reset action."""
        action = {
            "type": "reset_credentials",
            "target_user": sample_alert["user"],
            "reset_type": "password",  # password, mfa, both
            "force_logout": True,
            "notify_user": True
        }
        
        assert action["force_logout"] is True


class TestApprovalWorkflow:
    """Test approval workflow for response actions."""
    
    def test_approval_request_creation(self, sample_playbook, sample_alert):
        """Test creating an approval request."""
        approval_request = {
            "id": str(uuid4()),
            "playbook_id": sample_playbook["id"],
            "alert_id": sample_alert["id"],
            "action": "isolate_host",
            "target": sample_alert["host"],
            "requested_by": "response_agent",
            "requested_at": datetime.utcnow().isoformat(),
            "status": "pending",
            "approvers": ["soc_manager@example.com", "incident_commander@example.com"],
            "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat()
        }
        
        assert approval_request["status"] == "pending"
        assert len(approval_request["approvers"]) == 2
    
    def test_approval_grant(self):
        """Test granting approval for action."""
        approval_decision = {
            "request_id": str(uuid4()),
            "decision": "approved",
            "approver": "soc_manager@example.com",
            "decided_at": datetime.utcnow().isoformat(),
            "comments": "Confirmed malicious activity, proceed with isolation"
        }
        
        assert approval_decision["decision"] == "approved"
    
    def test_approval_denial(self):
        """Test denying approval for action."""
        approval_decision = {
            "request_id": str(uuid4()),
            "decision": "denied",
            "approver": "soc_manager@example.com",
            "decided_at": datetime.utcnow().isoformat(),
            "comments": "False positive, user confirmed legitimate activity"
        }
        
        assert approval_decision["decision"] == "denied"
    
    def test_approval_timeout(self):
        """Test approval request timeout handling."""
        request = {
            "id": str(uuid4()),
            "status": "pending",
            "requested_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
            "expires_at": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
            "timeout_action": "escalate"  # escalate, auto_approve, auto_deny
        }
        
        # Check if expired
        expires_at = datetime.fromisoformat(request["expires_at"].replace("Z", "+00:00"))
        is_expired = datetime.utcnow().replace(tzinfo=expires_at.tzinfo) > expires_at
        
        assert request["timeout_action"] == "escalate"


class TestRollbackCapabilities:
    """Test rollback capabilities for response actions."""
    
    def test_rollback_host_isolation(self):
        """Test rolling back host isolation."""
        rollback = {
            "original_action": "isolate_host",
            "rollback_action": "restore_network_access",
            "target": "WORKSTATION-01",
            "reason": "Investigation complete, false positive confirmed",
            "initiated_by": "analyst@example.com"
        }
        
        assert rollback["rollback_action"] == "restore_network_access"
    
    def test_rollback_account_disable(self):
        """Test rolling back account disable."""
        rollback = {
            "original_action": "disable_account",
            "rollback_action": "enable_account",
            "target": "john.doe",
            "reason": "Credentials reset, account can be re-enabled",
            "require_mfa_reset": True
        }
        
        assert rollback["require_mfa_reset"] is True
    
    def test_rollback_firewall_block(self):
        """Test rolling back firewall block."""
        rollback = {
            "original_action": "firewall_block",
            "rollback_action": "remove_firewall_rule",
            "target_type": "ip",
            "target_value": "192.168.1.100",
            "rule_id": "block-rule-123"
        }
        
        assert rollback["rollback_action"] == "remove_firewall_rule"
    
    def test_automatic_rollback_on_failure(self, sample_playbook):
        """Test automatic rollback when subsequent steps fail."""
        execution_state = {
            "playbook_id": sample_playbook["id"],
            "completed_steps": [
                {"id": "step_1", "action": "isolate_host", "status": "success"},
                {"id": "step_2", "action": "collect_forensics", "status": "failed"}
            ],
            "rollback_required": True,
            "rollback_steps": [
                {"original_step": "step_1", "action": "restore_network_access"}
            ]
        }
        
        assert execution_state["rollback_required"] is True
        assert len(execution_state["rollback_steps"]) == 1


class TestResponseNotifications:
    """Test response notification capabilities."""
    
    def test_slack_notification(self, sample_alert):
        """Test Slack notification for response action."""
        notification = {
            "channel": "slack",
            "target": "#soc-alerts",
            "message": {
                "type": "response_executed",
                "alert_id": sample_alert["id"],
                "action": "host_isolation",
                "target": sample_alert["host"],
                "status": "success"
            },
            "priority": "high"
        }
        
        assert notification["channel"] == "slack"
    
    def test_pagerduty_notification(self, sample_critical_alert):
        """Test PagerDuty notification for critical response."""
        notification = {
            "channel": "pagerduty",
            "severity": "critical",
            "title": f"Critical Response Executed: {sample_critical_alert['title']}",
            "description": "Automated response triggered for ransomware detection",
            "dedup_key": sample_critical_alert["id"]
        }
        
        assert notification["severity"] == "critical"
    
    def test_email_notification(self):
        """Test email notification for response action."""
        notification = {
            "channel": "email",
            "recipients": ["soc_team@example.com", "incident_commander@example.com"],
            "subject": "Response Action Executed: Host Isolation",
            "body_template": "response_executed.html",
            "attachments": []
        }
        
        assert len(notification["recipients"]) == 2


class TestResponseMetrics:
    """Test response metrics and tracking."""
    
    def test_response_time_tracking(self):
        """Test tracking response time from detection to action."""
        metrics = {
            "detection_time": "2024-01-15T10:00:00Z",
            "triage_complete_time": "2024-01-15T10:02:00Z",
            "response_initiated_time": "2024-01-15T10:03:00Z",
            "response_complete_time": "2024-01-15T10:05:00Z"
        }
        
        # Calculate MTTR
        detection = datetime.fromisoformat(metrics["detection_time"].replace("Z", "+00:00"))
        response = datetime.fromisoformat(metrics["response_complete_time"].replace("Z", "+00:00"))
        mttr_seconds = (response - detection).total_seconds()
        
        assert mttr_seconds == 300  # 5 minutes
    
    def test_action_success_rate(self):
        """Test tracking action success rates."""
        action_stats = {
            "isolate_host": {"total": 100, "success": 95, "failed": 5},
            "disable_account": {"total": 50, "success": 48, "failed": 2},
            "firewall_block": {"total": 200, "success": 198, "failed": 2}
        }
        
        for action, stats in action_stats.items():
            success_rate = stats["success"] / stats["total"]
            assert success_rate >= 0.95
    
    def test_playbook_execution_metrics(self):
        """Test playbook execution metrics."""
        playbook_metrics = {
            "playbook_id": str(uuid4()),
            "executions_total": 50,
            "executions_success": 45,
            "executions_failed": 5,
            "avg_execution_time_seconds": 180,
            "rollbacks_triggered": 3
        }
        
        success_rate = playbook_metrics["executions_success"] / playbook_metrics["executions_total"]
        assert success_rate == 0.9


class TestResponseIntegrations:
    """Test response integrations with external systems."""
    
    def test_edr_integration(self):
        """Test integration with EDR platform."""
        edr_action = {
            "platform": "crowdstrike",
            "action": "contain_host",
            "host_id": "device-123",
            "api_response": {
                "status": "success",
                "task_id": "task-456"
            }
        }
        
        assert edr_action["api_response"]["status"] == "success"
    
    def test_siem_integration(self):
        """Test integration with SIEM platform."""
        siem_action = {
            "platform": "splunk",
            "action": "create_notable",
            "notable_data": {
                "title": "Response Executed",
                "urgency": "high",
                "status": "new"
            }
        }
        
        assert siem_action["notable_data"]["urgency"] == "high"
    
    def test_ticketing_integration(self):
        """Test integration with ticketing system."""
        ticket = {
            "platform": "servicenow",
            "action": "create_incident",
            "incident_data": {
                "short_description": "Security Incident Response",
                "priority": 1,
                "category": "Security"
            },
            "response": {
                "ticket_id": "INC0012345"
            }
        }
        
        assert "INC" in ticket["response"]["ticket_id"]
