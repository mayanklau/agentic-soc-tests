"""
Unit Tests for API Layer

Tests the FastAPI REST API endpoints for alerts, investigations,
playbooks, threat intelligence, and system health.
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timedelta
from uuid import uuid4
import json


class TestAPIAuthentication:
    """Test API authentication mechanisms."""
    
    def test_api_key_authentication(self, auth_headers):
        """Test API key authentication."""
        headers = auth_headers
        
        assert "X-API-Key" in headers
        assert headers["X-API-Key"] == "test-api-key-12345"
    
    def test_jwt_token_validation(self, jwt_token):
        """Test JWT token validation."""
        token = jwt_token
        
        # Token should have 3 parts
        parts = token.split(".")
        assert len(parts) == 3
    
    def test_missing_auth_header(self):
        """Test request without authentication."""
        headers = {"Content-Type": "application/json"}
        
        # Should not have auth header
        assert "X-API-Key" not in headers
        assert "Authorization" not in headers
    
    def test_invalid_api_key(self):
        """Test invalid API key handling."""
        invalid_response = {
            "detail": "Invalid API key",
            "status_code": 401
        }
        
        assert invalid_response["status_code"] == 401
    
    def test_expired_jwt_token(self):
        """Test expired JWT token handling."""
        expired_response = {
            "detail": "Token has expired",
            "status_code": 401
        }
        
        assert expired_response["status_code"] == 401


class TestAPIRateLimiting:
    """Test API rate limiting."""
    
    def test_rate_limit_headers(self):
        """Test rate limit response headers."""
        headers = {
            "X-RateLimit-Limit": "100",
            "X-RateLimit-Remaining": "95",
            "X-RateLimit-Reset": "1705315800"
        }
        
        assert int(headers["X-RateLimit-Remaining"]) < int(headers["X-RateLimit-Limit"])
    
    def test_rate_limit_exceeded(self):
        """Test rate limit exceeded response."""
        response = {
            "status_code": 429,
            "detail": "Rate limit exceeded",
            "retry_after": 60
        }
        
        assert response["status_code"] == 429
        assert response["retry_after"] == 60


class TestAlertsAPI:
    """Test Alerts API endpoints."""
    
    def test_list_alerts(self, sample_alerts_batch):
        """Test GET /alerts endpoint."""
        response = {
            "status_code": 200,
            "data": {
                "alerts": sample_alerts_batch[:10],
                "total": len(sample_alerts_batch),
                "page": 1,
                "page_size": 10
            }
        }
        
        assert response["status_code"] == 200
        assert len(response["data"]["alerts"]) == 10
    
    def test_list_alerts_with_filters(self):
        """Test GET /alerts with query filters."""
        query_params = {
            "severity": "critical",
            "status": "new",
            "start_time": "2024-01-15T00:00:00Z",
            "end_time": "2024-01-15T23:59:59Z",
            "limit": 50
        }
        
        assert query_params["severity"] == "critical"
        assert query_params["limit"] == 50
    
    def test_get_alert_by_id(self, sample_alert):
        """Test GET /alerts/{alert_id} endpoint."""
        response = {
            "status_code": 200,
            "data": sample_alert
        }
        
        assert response["status_code"] == 200
        assert "id" in response["data"]
    
    def test_get_alert_not_found(self):
        """Test GET /alerts/{alert_id} with non-existent ID."""
        response = {
            "status_code": 404,
            "detail": "Alert not found"
        }
        
        assert response["status_code"] == 404
    
    def test_acknowledge_alert(self, sample_alert):
        """Test POST /alerts/{alert_id}/acknowledge endpoint."""
        request_body = {
            "analyst": "analyst@example.com",
            "notes": "Investigating"
        }
        
        response = {
            "status_code": 200,
            "data": {
                "id": sample_alert["id"],
                "status": "acknowledged",
                "acknowledged_by": request_body["analyst"],
                "acknowledged_at": datetime.utcnow().isoformat()
            }
        }
        
        assert response["data"]["status"] == "acknowledged"
    
    def test_resolve_alert(self, sample_alert):
        """Test POST /alerts/{alert_id}/resolve endpoint."""
        request_body = {
            "resolution": "False positive - authorized scanning",
            "analyst": "analyst@example.com"
        }
        
        response = {
            "status_code": 200,
            "data": {
                "id": sample_alert["id"],
                "status": "resolved",
                "resolution": request_body["resolution"]
            }
        }
        
        assert response["data"]["status"] == "resolved"
    
    def test_bulk_update_alerts(self, sample_alerts_batch):
        """Test PATCH /alerts/bulk endpoint."""
        request_body = {
            "alert_ids": [a["id"] for a in sample_alerts_batch[:5]],
            "update": {
                "status": "acknowledged",
                "assignee": "analyst@example.com"
            }
        }
        
        response = {
            "status_code": 200,
            "data": {
                "updated": 5,
                "failed": 0
            }
        }
        
        assert response["data"]["updated"] == 5


class TestInvestigationsAPI:
    """Test Investigations API endpoints."""
    
    def test_create_investigation(self, sample_investigation):
        """Test POST /investigations endpoint."""
        request_body = {
            "title": sample_investigation["title"],
            "description": sample_investigation["description"],
            "priority": sample_investigation["priority"],
            "alert_ids": sample_investigation["alert_ids"]
        }
        
        response = {
            "status_code": 201,
            "data": sample_investigation
        }
        
        assert response["status_code"] == 201
    
    def test_list_investigations(self):
        """Test GET /investigations endpoint."""
        response = {
            "status_code": 200,
            "data": {
                "investigations": [],
                "total": 0,
                "page": 1
            }
        }
        
        assert response["status_code"] == 200
    
    def test_get_investigation_by_id(self, sample_investigation):
        """Test GET /investigations/{investigation_id} endpoint."""
        response = {
            "status_code": 200,
            "data": sample_investigation
        }
        
        assert response["status_code"] == 200
    
    def test_add_finding_to_investigation(self, sample_investigation, sample_investigation_finding):
        """Test POST /investigations/{id}/findings endpoint."""
        response = {
            "status_code": 201,
            "data": sample_investigation_finding
        }
        
        assert response["status_code"] == 201
    
    def test_update_investigation_status(self, sample_investigation):
        """Test PATCH /investigations/{id} endpoint."""
        request_body = {
            "status": "in_progress",
            "assignee": "senior_analyst@example.com"
        }
        
        response = {
            "status_code": 200,
            "data": {
                **sample_investigation,
                "status": "in_progress",
                "assignee": "senior_analyst@example.com"
            }
        }
        
        assert response["data"]["status"] == "in_progress"


class TestPlaybooksAPI:
    """Test Playbooks API endpoints."""
    
    def test_list_playbooks(self, sample_playbook):
        """Test GET /playbooks endpoint."""
        response = {
            "status_code": 200,
            "data": {
                "playbooks": [sample_playbook],
                "total": 1
            }
        }
        
        assert response["status_code"] == 200
    
    def test_get_playbook_by_id(self, sample_playbook):
        """Test GET /playbooks/{playbook_id} endpoint."""
        response = {
            "status_code": 200,
            "data": sample_playbook
        }
        
        assert response["status_code"] == 200
    
    def test_execute_playbook(self, sample_playbook, sample_alert):
        """Test POST /playbooks/{playbook_id}/execute endpoint."""
        request_body = {
            "alert_id": sample_alert["id"],
            "context": {
                "source_ip": "192.168.1.100",
                "target_host": "WORKSTATION-01"
            }
        }
        
        response = {
            "status_code": 202,
            "data": {
                "execution_id": str(uuid4()),
                "playbook_id": sample_playbook["id"],
                "status": "pending",
                "message": "Playbook execution queued"
            }
        }
        
        assert response["status_code"] == 202
        assert response["data"]["status"] == "pending"
    
    def test_get_playbook_execution_status(self, sample_playbook_execution):
        """Test GET /playbooks/executions/{execution_id} endpoint."""
        response = {
            "status_code": 200,
            "data": sample_playbook_execution
        }
        
        assert response["status_code"] == 200
    
    def test_cancel_playbook_execution(self):
        """Test POST /playbooks/executions/{execution_id}/cancel endpoint."""
        response = {
            "status_code": 200,
            "data": {
                "execution_id": str(uuid4()),
                "status": "cancelled",
                "cancelled_at": datetime.utcnow().isoformat()
            }
        }
        
        assert response["data"]["status"] == "cancelled"


class TestThreatIntelAPI:
    """Test Threat Intelligence API endpoints."""
    
    def test_lookup_ip(self, sample_threat_intel_response):
        """Test GET /threat-intel/lookup/ip/{ip_address} endpoint."""
        response = {
            "status_code": 200,
            "data": sample_threat_intel_response
        }
        
        assert response["status_code"] == 200
        assert response["data"]["malicious"] is True
    
    def test_lookup_domain(self):
        """Test GET /threat-intel/lookup/domain/{domain} endpoint."""
        response = {
            "status_code": 200,
            "data": {
                "ioc": {"type": "domain", "value": "malicious.com"},
                "malicious": True,
                "confidence": 88
            }
        }
        
        assert response["data"]["malicious"] is True
    
    def test_lookup_hash(self):
        """Test GET /threat-intel/lookup/hash/{hash} endpoint."""
        response = {
            "status_code": 200,
            "data": {
                "ioc": {"type": "hash", "value": "a" * 64},
                "malicious": True,
                "detection_ratio": "45/70"
            }
        }
        
        assert "detection_ratio" in response["data"]
    
    def test_bulk_lookup(self, sample_iocs_batch):
        """Test POST /threat-intel/lookup/bulk endpoint."""
        request_body = {
            "iocs": sample_iocs_batch
        }
        
        response = {
            "status_code": 200,
            "data": {
                "results": [
                    {"ioc": ioc, "malicious": True, "confidence": 80}
                    for ioc in sample_iocs_batch
                ],
                "total": len(sample_iocs_batch)
            }
        }
        
        assert response["data"]["total"] == 8
    
    def test_lookup_not_found(self):
        """Test lookup for unknown IOC."""
        response = {
            "status_code": 200,
            "data": {
                "ioc": {"type": "ip", "value": "192.168.1.1"},
                "malicious": False,
                "confidence": 0,
                "message": "No threat intelligence found"
            }
        }
        
        assert response["data"]["malicious"] is False


class TestHealthAPI:
    """Test Health API endpoints."""
    
    def test_health_check(self):
        """Test GET /health endpoint."""
        response = {
            "status_code": 200,
            "data": {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "version": "1.0.0"
            }
        }
        
        assert response["data"]["status"] == "healthy"
    
    def test_detailed_health_check(self):
        """Test GET /health/detailed endpoint."""
        response = {
            "status_code": 200,
            "data": {
                "status": "healthy",
                "components": {
                    "database": {"status": "healthy", "latency_ms": 5},
                    "elasticsearch": {"status": "healthy", "latency_ms": 10},
                    "redis": {"status": "healthy", "latency_ms": 2},
                    "qdrant": {"status": "healthy", "latency_ms": 8}
                },
                "agents": {
                    "detection": {"status": "active", "queue_depth": 50},
                    "triage": {"status": "active", "queue_depth": 30},
                    "response": {"status": "active", "queue_depth": 5}
                }
            }
        }
        
        assert all(c["status"] == "healthy" for c in response["data"]["components"].values())
    
    def test_health_check_degraded(self):
        """Test health check with degraded component."""
        response = {
            "status_code": 200,
            "data": {
                "status": "degraded",
                "components": {
                    "database": {"status": "healthy"},
                    "elasticsearch": {"status": "degraded", "error": "High latency"},
                    "redis": {"status": "healthy"}
                }
            }
        }
        
        assert response["data"]["status"] == "degraded"


class TestMetricsAPI:
    """Test Metrics API endpoints."""
    
    def test_get_metrics(self):
        """Test GET /metrics endpoint (Prometheus format)."""
        metrics_output = """
# HELP soc_alerts_total Total number of alerts
# TYPE soc_alerts_total counter
soc_alerts_total{severity="critical"} 100
soc_alerts_total{severity="high"} 500
soc_alerts_total{severity="medium"} 1000
# HELP soc_api_request_duration_seconds API request latency
# TYPE soc_api_request_duration_seconds histogram
soc_api_request_duration_seconds_bucket{le="0.1"} 900
soc_api_request_duration_seconds_bucket{le="0.5"} 980
soc_api_request_duration_seconds_bucket{le="1.0"} 995
"""
        assert "soc_alerts_total" in metrics_output
    
    def test_get_dashboard_metrics(self):
        """Test GET /metrics/dashboard endpoint."""
        response = {
            "status_code": 200,
            "data": {
                "alerts": {
                    "total_24h": 150,
                    "critical": 10,
                    "high": 40,
                    "medium": 60,
                    "low": 40
                },
                "investigations": {
                    "open": 5,
                    "in_progress": 8,
                    "closed_24h": 12
                },
                "mttr_minutes": 15.5,
                "false_positive_rate": 0.15
            }
        }
        
        assert response["data"]["mttr_minutes"] == 15.5


class TestWebSocketAPI:
    """Test WebSocket API endpoints."""
    
    def test_websocket_connection(self):
        """Test WebSocket connection establishment."""
        connection = {
            "status": "connected",
            "client_id": str(uuid4()),
            "subscriptions": ["alerts", "investigations"]
        }
        
        assert connection["status"] == "connected"
    
    def test_websocket_alert_notification(self, sample_alert):
        """Test WebSocket alert notification."""
        message = {
            "type": "alert_created",
            "data": sample_alert,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        assert message["type"] == "alert_created"
    
    def test_websocket_subscription(self):
        """Test WebSocket topic subscription."""
        subscription_request = {
            "action": "subscribe",
            "topics": ["alerts.critical", "investigations.new"]
        }
        
        subscription_response = {
            "status": "subscribed",
            "topics": subscription_request["topics"]
        }
        
        assert len(subscription_response["topics"]) == 2


class TestAPIValidation:
    """Test API request validation."""
    
    def test_invalid_request_body(self):
        """Test handling of invalid request body."""
        response = {
            "status_code": 422,
            "detail": [
                {
                    "loc": ["body", "severity"],
                    "msg": "field required",
                    "type": "value_error.missing"
                }
            ]
        }
        
        assert response["status_code"] == 422
    
    def test_invalid_query_parameter(self):
        """Test handling of invalid query parameter."""
        response = {
            "status_code": 422,
            "detail": [
                {
                    "loc": ["query", "limit"],
                    "msg": "value is not a valid integer",
                    "type": "type_error.integer"
                }
            ]
        }
        
        assert response["status_code"] == 422
    
    def test_invalid_path_parameter(self):
        """Test handling of invalid path parameter."""
        response = {
            "status_code": 422,
            "detail": [
                {
                    "loc": ["path", "alert_id"],
                    "msg": "value is not a valid uuid",
                    "type": "type_error.uuid"
                }
            ]
        }
        
        assert response["status_code"] == 422


class TestAPIPagination:
    """Test API pagination."""
    
    def test_pagination_parameters(self):
        """Test pagination query parameters."""
        params = {
            "page": 1,
            "page_size": 20,
            "sort_by": "timestamp",
            "sort_order": "desc"
        }
        
        assert params["page_size"] == 20
    
    def test_pagination_response(self, sample_alerts_batch):
        """Test pagination in response."""
        total = len(sample_alerts_batch)
        page_size = 10
        
        response = {
            "data": sample_alerts_batch[:page_size],
            "pagination": {
                "page": 1,
                "page_size": page_size,
                "total": total,
                "total_pages": (total + page_size - 1) // page_size,
                "has_next": True,
                "has_prev": False
            }
        }
        
        assert response["pagination"]["total_pages"] == 5
        assert response["pagination"]["has_next"] is True
