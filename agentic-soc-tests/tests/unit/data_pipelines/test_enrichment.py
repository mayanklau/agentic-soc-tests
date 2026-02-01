"""
Unit Tests for Data Enrichment Pipeline
=======================================
Tests for enriching security events with threat intelligence, asset information,
geolocation, user directory data, and vulnerability context.
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import uuid


# =============================================================================
# ENRICHMENT ENGINE TESTS
# =============================================================================

class TestEnrichmentEngine:
    """Tests for the main enrichment engine."""
    
    @pytest.mark.asyncio
    async def test_enrichment_engine_initialization(self, app_config):
        """Test enrichment engine initializes with configured providers."""
        engine = Mock()
        engine.providers = ["threat_intel", "asset_db", "geo_ip", "user_directory", "vuln_db"]
        engine.enabled = True
        engine.cache_enabled = True
        
        assert len(engine.providers) == 5
        assert engine.enabled is True
    
    @pytest.mark.asyncio
    async def test_enrichment_engine_start(self):
        """Test enrichment engine starts all providers."""
        engine = AsyncMock()
        engine.start = AsyncMock(return_value={
            "status": "running",
            "providers_started": 5,
            "providers_failed": 0
        })
        
        result = await engine.start()
        
        assert result["status"] == "running"
        assert result["providers_started"] == 5
    
    @pytest.mark.asyncio
    async def test_enrichment_pipeline_order(self):
        """Test enrichment providers execute in correct order."""
        engine = Mock()
        engine.pipeline_order = ["asset_db", "user_directory", "geo_ip", "threat_intel", "vuln_db"]
        
        assert engine.pipeline_order[0] == "asset_db"  # Asset info first
        assert engine.pipeline_order[-1] == "vuln_db"  # Vuln DB last
    
    @pytest.mark.asyncio
    async def test_enrichment_health_check(self):
        """Test enrichment engine health check."""
        engine = AsyncMock()
        engine.health_check = AsyncMock(return_value={
            "status": "healthy",
            "providers": {
                "threat_intel": "connected",
                "asset_db": "connected",
                "geo_ip": "connected",
                "user_directory": "degraded",
                "vuln_db": "connected"
            },
            "cache_hit_rate": 0.85
        })
        
        health = await engine.health_check()
        
        assert health["status"] == "healthy"
        assert health["providers"]["threat_intel"] == "connected"


# =============================================================================
# THREAT INTELLIGENCE ENRICHMENT TESTS
# =============================================================================

class TestThreatIntelEnrichment:
    """Tests for threat intelligence enrichment."""
    
    @pytest.mark.asyncio
    async def test_enrich_ip_with_threat_intel(self, mock_threat_intel_response):
        """Test enriching IP address with threat intelligence."""
        enricher = AsyncMock()
        enricher.enrich_ip = AsyncMock(return_value={
            "ip": "192.168.1.100",
            "threat_intel": {
                "is_malicious": True,
                "confidence": 0.95,
                "categories": ["C2", "malware"],
                "first_seen": "2024-01-01T00:00:00Z",
                "last_seen": "2024-01-15T12:00:00Z",
                "sources": ["VirusTotal", "AbuseIPDB"]
            }
        })
        
        result = await enricher.enrich_ip("192.168.1.100")
        
        assert result["threat_intel"]["is_malicious"] is True
        assert result["threat_intel"]["confidence"] >= 0.9
    
    @pytest.mark.asyncio
    async def test_enrich_domain_with_threat_intel(self):
        """Test enriching domain with threat intelligence."""
        enricher = AsyncMock()
        enricher.enrich_domain = AsyncMock(return_value={
            "domain": "evil-domain.com",
            "threat_intel": {
                "is_malicious": True,
                "categories": ["phishing", "malware_distribution"],
                "registrar": "Suspicious Registrar Inc.",
                "creation_date": "2024-01-10T00:00:00Z",
                "whois_privacy": True
            }
        })
        
        result = await enricher.enrich_domain("evil-domain.com")
        
        assert result["threat_intel"]["is_malicious"] is True
        assert "phishing" in result["threat_intel"]["categories"]
    
    @pytest.mark.asyncio
    async def test_enrich_hash_with_threat_intel(self):
        """Test enriching file hash with threat intelligence."""
        enricher = AsyncMock()
        enricher.enrich_hash = AsyncMock(return_value={
            "hash": "abc123def456",
            "hash_type": "sha256",
            "threat_intel": {
                "is_malicious": True,
                "malware_family": "Emotet",
                "first_seen": "2023-06-01T00:00:00Z",
                "detection_ratio": "58/72",
                "av_labels": ["Trojan.GenericKD", "Win32/Emotet"]
            }
        })
        
        result = await enricher.enrich_hash("abc123def456")
        
        assert result["threat_intel"]["malware_family"] == "Emotet"
    
    @pytest.mark.asyncio
    async def test_enrich_url_with_threat_intel(self):
        """Test enriching URL with threat intelligence."""
        enricher = AsyncMock()
        enricher.enrich_url = AsyncMock(return_value={
            "url": "http://malicious-site.com/download.exe",
            "threat_intel": {
                "is_malicious": True,
                "categories": ["malware_download"],
                "final_url": "http://malicious-site.com/payload.exe",
                "redirects": 2
            }
        })
        
        result = await enricher.enrich_url("http://malicious-site.com/download.exe")
        
        assert result["threat_intel"]["is_malicious"] is True
    
    @pytest.mark.asyncio
    async def test_threat_intel_cache_hit(self, mock_redis_client):
        """Test threat intel cache hit returns cached data."""
        enricher = AsyncMock()
        enricher.enrich_ip_cached = AsyncMock(return_value={
            "ip": "192.168.1.100",
            "threat_intel": {"is_malicious": False},
            "cache_hit": True,
            "cache_age_seconds": 300
        })
        
        result = await enricher.enrich_ip_cached("192.168.1.100")
        
        assert result["cache_hit"] is True
    
    @pytest.mark.asyncio
    async def test_threat_intel_provider_timeout(self):
        """Test handling of threat intel provider timeout."""
        enricher = AsyncMock()
        enricher.enrich_ip = AsyncMock(return_value={
            "ip": "192.168.1.100",
            "threat_intel": None,
            "error": "Provider timeout after 5s",
            "provider": "VirusTotal"
        })
        
        result = await enricher.enrich_ip("192.168.1.100")
        
        assert result["threat_intel"] is None
        assert "timeout" in result["error"]
    
    @pytest.mark.asyncio
    async def test_aggregate_threat_intel_from_multiple_sources(self):
        """Test aggregating threat intel from multiple providers."""
        enricher = AsyncMock()
        enricher.aggregate_intel = AsyncMock(return_value={
            "ip": "192.168.1.100",
            "aggregated_intel": {
                "is_malicious": True,
                "confidence": 0.92,
                "source_count": 3,
                "sources": ["VirusTotal", "AbuseIPDB", "MISP"],
                "consensus": "malicious"
            }
        })
        
        result = await enricher.aggregate_intel("192.168.1.100")
        
        assert result["aggregated_intel"]["source_count"] == 3


# =============================================================================
# ASSET ENRICHMENT TESTS
# =============================================================================

class TestAssetEnrichment:
    """Tests for asset database enrichment."""
    
    @pytest.mark.asyncio
    async def test_enrich_with_asset_info(self):
        """Test enriching event with asset information."""
        enricher = AsyncMock()
        enricher.enrich_asset = AsyncMock(return_value={
            "ip": "10.0.0.50",
            "asset_info": {
                "hostname": "DB-SERVER-01",
                "asset_type": "server",
                "criticality": "high",
                "owner": "DBA Team",
                "department": "IT Infrastructure",
                "os": "Ubuntu 22.04 LTS",
                "location": "DC1-Rack-A12"
            }
        })
        
        result = await enricher.enrich_asset("10.0.0.50")
        
        assert result["asset_info"]["criticality"] == "high"
        assert result["asset_info"]["asset_type"] == "server"
    
    @pytest.mark.asyncio
    async def test_enrich_with_hostname_lookup(self):
        """Test asset enrichment via hostname."""
        enricher = AsyncMock()
        enricher.enrich_by_hostname = AsyncMock(return_value={
            "hostname": "WORKSTATION-123",
            "asset_info": {
                "ip": "192.168.1.123",
                "asset_type": "workstation",
                "assigned_user": "john.doe",
                "department": "Engineering",
                "last_scan": "2024-01-14T00:00:00Z"
            }
        })
        
        result = await enricher.enrich_by_hostname("WORKSTATION-123")
        
        assert result["asset_info"]["assigned_user"] == "john.doe"
    
    @pytest.mark.asyncio
    async def test_enrich_unknown_asset(self):
        """Test handling of unknown/unregistered assets."""
        enricher = AsyncMock()
        enricher.enrich_asset = AsyncMock(return_value={
            "ip": "10.0.0.99",
            "asset_info": None,
            "warning": "Asset not found in inventory",
            "risk_indicator": "unregistered_asset"
        })
        
        result = await enricher.enrich_asset("10.0.0.99")
        
        assert result["asset_info"] is None
        assert result["risk_indicator"] == "unregistered_asset"
    
    @pytest.mark.asyncio
    async def test_enrich_with_asset_tags(self):
        """Test enriching with asset tags and labels."""
        enricher = AsyncMock()
        enricher.enrich_asset = AsyncMock(return_value={
            "ip": "10.0.0.50",
            "asset_info": {
                "hostname": "WEB-SERVER-01",
                "tags": ["production", "pci-scope", "internet-facing", "high-value"],
                "compliance_scope": ["PCI-DSS", "SOC2"]
            }
        })
        
        result = await enricher.enrich_asset("10.0.0.50")
        
        assert "pci-scope" in result["asset_info"]["tags"]
    
    @pytest.mark.asyncio
    async def test_enrich_with_network_segment(self):
        """Test enriching with network segment information."""
        enricher = AsyncMock()
        enricher.enrich_asset = AsyncMock(return_value={
            "ip": "10.0.0.50",
            "asset_info": {
                "network_segment": "DMZ",
                "vlan": "100",
                "subnet": "10.0.0.0/24",
                "zone": "external-facing"
            }
        })
        
        result = await enricher.enrich_asset("10.0.0.50")
        
        assert result["asset_info"]["network_segment"] == "DMZ"


# =============================================================================
# GEOLOCATION ENRICHMENT TESTS
# =============================================================================

class TestGeolocationEnrichment:
    """Tests for geolocation enrichment."""
    
    @pytest.mark.asyncio
    async def test_enrich_ip_with_geolocation(self):
        """Test enriching IP with geolocation data."""
        enricher = AsyncMock()
        enricher.enrich_geo = AsyncMock(return_value={
            "ip": "8.8.8.8",
            "geolocation": {
                "country_code": "US",
                "country_name": "United States",
                "region": "California",
                "city": "Mountain View",
                "latitude": 37.386,
                "longitude": -122.084,
                "timezone": "America/Los_Angeles",
                "isp": "Google LLC",
                "asn": "AS15169"
            }
        })
        
        result = await enricher.enrich_geo("8.8.8.8")
        
        assert result["geolocation"]["country_code"] == "US"
        assert result["geolocation"]["city"] == "Mountain View"
    
    @pytest.mark.asyncio
    async def test_enrich_private_ip_no_geolocation(self):
        """Test that private IPs return no geolocation."""
        enricher = AsyncMock()
        enricher.enrich_geo = AsyncMock(return_value={
            "ip": "192.168.1.100",
            "geolocation": None,
            "reason": "Private IP address"
        })
        
        result = await enricher.enrich_geo("192.168.1.100")
        
        assert result["geolocation"] is None
    
    @pytest.mark.asyncio
    async def test_detect_geo_anomaly(self):
        """Test detection of geographic anomalies."""
        enricher = AsyncMock()
        enricher.check_geo_anomaly = AsyncMock(return_value={
            "user": "john.doe",
            "current_location": {"country": "Russia", "city": "Moscow"},
            "expected_locations": [{"country": "US", "city": "New York"}],
            "anomaly_detected": True,
            "anomaly_type": "impossible_travel",
            "time_since_last_login": "1 hour"
        })
        
        result = await enricher.check_geo_anomaly("john.doe", "1.2.3.4")
        
        assert result["anomaly_detected"] is True
        assert result["anomaly_type"] == "impossible_travel"
    
    @pytest.mark.asyncio
    async def test_enrich_with_geo_distance(self):
        """Test calculating geo distance from expected location."""
        enricher = AsyncMock()
        enricher.calculate_distance = AsyncMock(return_value={
            "source_location": {"lat": 40.7128, "lon": -74.0060},  # NYC
            "destination_location": {"lat": 51.5074, "lon": -0.1278},  # London
            "distance_km": 5570,
            "expected_travel_time_hours": 7
        })
        
        result = await enricher.calculate_distance("source_ip", "dest_ip")
        
        assert result["distance_km"] > 5000


# =============================================================================
# USER DIRECTORY ENRICHMENT TESTS
# =============================================================================

class TestUserDirectoryEnrichment:
    """Tests for user directory (AD/LDAP) enrichment."""
    
    @pytest.mark.asyncio
    async def test_enrich_with_user_info(self):
        """Test enriching with user directory information."""
        enricher = AsyncMock()
        enricher.enrich_user = AsyncMock(return_value={
            "username": "john.doe",
            "user_info": {
                "full_name": "John Doe",
                "email": "john.doe@company.com",
                "department": "Engineering",
                "title": "Senior Developer",
                "manager": "jane.smith",
                "location": "New York Office",
                "employee_type": "Full-Time"
            }
        })
        
        result = await enricher.enrich_user("john.doe")
        
        assert result["user_info"]["department"] == "Engineering"
    
    @pytest.mark.asyncio
    async def test_enrich_with_user_groups(self):
        """Test enriching with user group memberships."""
        enricher = AsyncMock()
        enricher.enrich_user_groups = AsyncMock(return_value={
            "username": "john.doe",
            "groups": [
                "Domain Users",
                "Engineering",
                "VPN Users",
                "AWS-Admins"
            ],
            "privileged_groups": ["AWS-Admins"],
            "is_privileged": True
        })
        
        result = await enricher.enrich_user_groups("john.doe")
        
        assert result["is_privileged"] is True
        assert "AWS-Admins" in result["privileged_groups"]
    
    @pytest.mark.asyncio
    async def test_enrich_with_user_risk_score(self):
        """Test enriching with user behavior risk score."""
        enricher = AsyncMock()
        enricher.get_user_risk = AsyncMock(return_value={
            "username": "john.doe",
            "risk_score": 75,
            "risk_factors": [
                {"factor": "recent_password_change", "weight": 10},
                {"factor": "accessing_sensitive_data", "weight": 30},
                {"factor": "unusual_login_hours", "weight": 35}
            ],
            "risk_level": "high"
        })
        
        result = await enricher.get_user_risk("john.doe")
        
        assert result["risk_score"] == 75
        assert result["risk_level"] == "high"
    
    @pytest.mark.asyncio
    async def test_enrich_service_account(self):
        """Test enriching service account information."""
        enricher = AsyncMock()
        enricher.enrich_user = AsyncMock(return_value={
            "username": "svc_backup",
            "user_info": {
                "account_type": "service",
                "owner": "IT Operations",
                "purpose": "Backup service",
                "allowed_hosts": ["backup-server-01", "backup-server-02"],
                "last_password_rotation": "2024-01-01T00:00:00Z"
            }
        })
        
        result = await enricher.enrich_user("svc_backup")
        
        assert result["user_info"]["account_type"] == "service"
    
    @pytest.mark.asyncio
    async def test_enrich_disabled_user(self):
        """Test enriching disabled/terminated user accounts."""
        enricher = AsyncMock()
        enricher.enrich_user = AsyncMock(return_value={
            "username": "former.employee",
            "user_info": {
                "status": "disabled",
                "disabled_date": "2024-01-01T00:00:00Z",
                "reason": "Termination"
            },
            "risk_indicator": "disabled_account_activity"
        })
        
        result = await enricher.enrich_user("former.employee")
        
        assert result["user_info"]["status"] == "disabled"
        assert result["risk_indicator"] == "disabled_account_activity"


# =============================================================================
# VULNERABILITY ENRICHMENT TESTS
# =============================================================================

class TestVulnerabilityEnrichment:
    """Tests for vulnerability data enrichment."""
    
    @pytest.mark.asyncio
    async def test_enrich_asset_with_vulnerabilities(self):
        """Test enriching asset with vulnerability data."""
        enricher = AsyncMock()
        enricher.get_asset_vulns = AsyncMock(return_value={
            "ip": "10.0.0.50",
            "vulnerabilities": {
                "total": 15,
                "critical": 2,
                "high": 5,
                "medium": 6,
                "low": 2,
                "cves": ["CVE-2024-1234", "CVE-2024-5678"]
            },
            "last_scan": "2024-01-14T00:00:00Z"
        })
        
        result = await enricher.get_asset_vulns("10.0.0.50")
        
        assert result["vulnerabilities"]["critical"] == 2
    
    @pytest.mark.asyncio
    async def test_enrich_cve_details(self):
        """Test enriching with CVE details."""
        enricher = AsyncMock()
        enricher.get_cve_details = AsyncMock(return_value={
            "cve_id": "CVE-2024-1234",
            "details": {
                "cvss_score": 9.8,
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "critical",
                "description": "Remote code execution vulnerability",
                "affected_products": ["Product A", "Product B"],
                "exploit_available": True,
                "patch_available": True
            }
        })
        
        result = await enricher.get_cve_details("CVE-2024-1234")
        
        assert result["details"]["cvss_score"] == 9.8
        assert result["details"]["exploit_available"] is True
    
    @pytest.mark.asyncio
    async def test_enrich_with_exploit_info(self):
        """Test enriching with exploit availability information."""
        enricher = AsyncMock()
        enricher.check_exploits = AsyncMock(return_value={
            "cve_id": "CVE-2024-1234",
            "exploit_info": {
                "exploits_available": True,
                "exploit_count": 3,
                "exploit_sources": ["ExploitDB", "Metasploit"],
                "in_wild": True,
                "weaponized": True
            }
        })
        
        result = await enricher.check_exploits("CVE-2024-1234")
        
        assert result["exploit_info"]["in_wild"] is True
    
    @pytest.mark.asyncio
    async def test_correlate_vuln_with_attack(self):
        """Test correlating vulnerabilities with attack techniques."""
        enricher = AsyncMock()
        enricher.correlate_vuln_attack = AsyncMock(return_value={
            "cve_id": "CVE-2024-1234",
            "attack_correlation": {
                "mitre_techniques": ["T1190", "T1059"],
                "attack_patterns": ["Exploit Public-Facing Application"],
                "threat_actors": ["APT28", "Lazarus Group"],
                "campaigns": ["Operation ShadowStrike"]
            }
        })
        
        result = await enricher.correlate_vuln_attack("CVE-2024-1234")
        
        assert "T1190" in result["attack_correlation"]["mitre_techniques"]


# =============================================================================
# BATCH ENRICHMENT TESTS
# =============================================================================

class TestBatchEnrichment:
    """Tests for batch event enrichment."""
    
    @pytest.mark.asyncio
    async def test_batch_enrich_events(self, sample_events_batch):
        """Test batch enrichment of multiple events."""
        enricher = AsyncMock()
        enricher.enrich_batch = AsyncMock(return_value={
            "processed": 100,
            "enriched": 98,
            "failed": 2,
            "avg_enrichment_time_ms": 15
        })
        
        result = await enricher.enrich_batch(sample_events_batch)
        
        assert result["enriched"] >= 98
    
    @pytest.mark.asyncio
    async def test_batch_enrichment_parallel_lookups(self):
        """Test parallel lookups during batch enrichment."""
        enricher = AsyncMock()
        enricher.enrich_batch_parallel = AsyncMock(return_value={
            "events_processed": 1000,
            "parallel_workers": 10,
            "total_time_ms": 500,
            "lookups_per_second": 2000
        })
        
        result = await enricher.enrich_batch_parallel([])
        
        assert result["parallel_workers"] == 10
    
    @pytest.mark.asyncio
    async def test_batch_enrichment_deduplication(self):
        """Test deduplication of enrichment lookups in batch."""
        enricher = AsyncMock()
        enricher.enrich_batch_dedupe = AsyncMock(return_value={
            "events": 100,
            "unique_ips": 25,
            "unique_domains": 10,
            "unique_hashes": 5,
            "lookups_saved": 60
        })
        
        result = await enricher.enrich_batch_dedupe([])
        
        assert result["lookups_saved"] == 60


# =============================================================================
# ENRICHMENT CACHING TESTS
# =============================================================================

class TestEnrichmentCaching:
    """Tests for enrichment result caching."""
    
    @pytest.mark.asyncio
    async def test_cache_enrichment_result(self, mock_redis_client):
        """Test caching of enrichment results."""
        cache = AsyncMock()
        cache.set_enrichment = AsyncMock(return_value=True)
        
        enrichment_data = {"ip": "8.8.8.8", "geo": {"country": "US"}}
        result = await cache.set_enrichment("geo:8.8.8.8", enrichment_data, ttl=3600)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_get_cached_enrichment(self, mock_redis_client):
        """Test retrieving cached enrichment data."""
        cache = AsyncMock()
        cache.get_enrichment = AsyncMock(return_value={
            "ip": "8.8.8.8",
            "geo": {"country": "US"},
            "cached_at": "2024-01-15T12:00:00Z"
        })
        
        result = await cache.get_enrichment("geo:8.8.8.8")
        
        assert result["geo"]["country"] == "US"
    
    @pytest.mark.asyncio
    async def test_cache_ttl_by_enrichment_type(self):
        """Test different TTL values for different enrichment types."""
        cache = Mock()
        cache.get_ttl = Mock(side_effect=lambda type: {
            "geo": 86400,      # 24 hours
            "asset": 3600,     # 1 hour
            "threat_intel": 1800,  # 30 minutes
            "user": 900        # 15 minutes
        }.get(type, 300))
        
        assert cache.get_ttl("geo") == 86400
        assert cache.get_ttl("threat_intel") == 1800
    
    @pytest.mark.asyncio
    async def test_cache_invalidation(self, mock_redis_client):
        """Test cache invalidation."""
        cache = AsyncMock()
        cache.invalidate = AsyncMock(return_value=True)
        
        result = await cache.invalidate("geo:8.8.8.8")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_cache_metrics(self, mock_redis_client):
        """Test cache performance metrics."""
        cache = AsyncMock()
        cache.get_metrics = AsyncMock(return_value={
            "hits": 8500,
            "misses": 1500,
            "hit_rate": 0.85,
            "avg_lookup_time_ms": 0.5,
            "memory_usage_mb": 256
        })
        
        metrics = await cache.get_metrics()
        
        assert metrics["hit_rate"] == 0.85


# =============================================================================
# ENRICHMENT PRIORITY AND ORDERING TESTS
# =============================================================================

class TestEnrichmentPriority:
    """Tests for enrichment priority and ordering."""
    
    @pytest.mark.asyncio
    async def test_high_severity_enrichment_priority(self):
        """Test high severity events get priority enrichment."""
        enricher = AsyncMock()
        enricher.enrich_with_priority = AsyncMock(return_value={
            "event_id": "evt-123",
            "severity": "critical",
            "priority": 1,
            "enrichment_depth": "full",
            "providers_used": ["all"]
        })
        
        result = await enricher.enrich_with_priority({"severity": "critical"})
        
        assert result["priority"] == 1
        assert result["enrichment_depth"] == "full"
    
    @pytest.mark.asyncio
    async def test_low_severity_minimal_enrichment(self):
        """Test low severity events get minimal enrichment."""
        enricher = AsyncMock()
        enricher.enrich_with_priority = AsyncMock(return_value={
            "event_id": "evt-456",
            "severity": "low",
            "priority": 3,
            "enrichment_depth": "minimal",
            "providers_used": ["geo", "asset"]
        })
        
        result = await enricher.enrich_with_priority({"severity": "low"})
        
        assert result["priority"] == 3
        assert result["enrichment_depth"] == "minimal"
    
    @pytest.mark.asyncio
    async def test_enrichment_timeout_handling(self):
        """Test handling of enrichment timeouts."""
        enricher = AsyncMock()
        enricher.enrich_with_timeout = AsyncMock(return_value={
            "event_id": "evt-789",
            "completed_enrichments": ["geo", "asset"],
            "timed_out_enrichments": ["threat_intel"],
            "partial": True
        })
        
        result = await enricher.enrich_with_timeout({}, timeout=5)
        
        assert result["partial"] is True
        assert "threat_intel" in result["timed_out_enrichments"]


# =============================================================================
# ENRICHMENT ERROR HANDLING TESTS
# =============================================================================

class TestEnrichmentErrorHandling:
    """Tests for enrichment error handling."""
    
    @pytest.mark.asyncio
    async def test_provider_failure_fallback(self):
        """Test fallback when primary provider fails."""
        enricher = AsyncMock()
        enricher.enrich_with_fallback = AsyncMock(return_value={
            "ip": "8.8.8.8",
            "provider_status": {
                "VirusTotal": "failed",
                "AbuseIPDB": "success"
            },
            "result": {"is_malicious": False},
            "fallback_used": True
        })
        
        result = await enricher.enrich_with_fallback("8.8.8.8")
        
        assert result["fallback_used"] is True
    
    @pytest.mark.asyncio
    async def test_all_providers_failure(self):
        """Test handling when all providers fail."""
        enricher = AsyncMock()
        enricher.enrich_ip = AsyncMock(return_value={
            "ip": "8.8.8.8",
            "threat_intel": None,
            "error": "All providers failed",
            "provider_errors": {
                "VirusTotal": "timeout",
                "AbuseIPDB": "rate_limited",
                "MISP": "connection_error"
            }
        })
        
        result = await enricher.enrich_ip("8.8.8.8")
        
        assert result["threat_intel"] is None
        assert "All providers failed" in result["error"]
    
    @pytest.mark.asyncio
    async def test_partial_enrichment_on_error(self):
        """Test partial enrichment when some providers fail."""
        enricher = AsyncMock()
        enricher.enrich_event = AsyncMock(return_value={
            "event_id": "evt-123",
            "enrichments": {
                "geo": {"status": "success", "data": {"country": "US"}},
                "threat_intel": {"status": "failed", "error": "timeout"},
                "asset": {"status": "success", "data": {"hostname": "server1"}}
            },
            "partial": True,
            "success_rate": 0.67
        })
        
        result = await enricher.enrich_event({})
        
        assert result["partial"] is True
        assert result["enrichments"]["geo"]["status"] == "success"


# =============================================================================
# MITRE ATT&CK ENRICHMENT TESTS
# =============================================================================

class TestMITREEnrichment:
    """Tests for MITRE ATT&CK enrichment."""
    
    @pytest.mark.asyncio
    async def test_enrich_with_mitre_technique(self, sample_alert):
        """Test enriching with MITRE ATT&CK technique details."""
        enricher = AsyncMock()
        enricher.enrich_mitre = AsyncMock(return_value={
            "technique_id": "T1059.001",
            "mitre_info": {
                "name": "PowerShell",
                "tactic": "Execution",
                "description": "Adversaries may abuse PowerShell...",
                "platforms": ["Windows"],
                "data_sources": ["Process", "Command", "Script"],
                "mitigations": ["M1045", "M1042"],
                "detection": "Monitor for loading of PowerShell..."
            }
        })
        
        result = await enricher.enrich_mitre("T1059.001")
        
        assert result["mitre_info"]["name"] == "PowerShell"
        assert result["mitre_info"]["tactic"] == "Execution"
    
    @pytest.mark.asyncio
    async def test_map_detection_to_mitre(self):
        """Test mapping detection patterns to MITRE techniques."""
        mapper = AsyncMock()
        mapper.map_to_mitre = AsyncMock(return_value={
            "detection_rule": "Suspicious PowerShell Download",
            "mapped_techniques": [
                {"id": "T1059.001", "confidence": 0.9},
                {"id": "T1105", "confidence": 0.7}
            ]
        })
        
        result = await mapper.map_to_mitre("Suspicious PowerShell Download")
        
        assert len(result["mapped_techniques"]) == 2
    
    @pytest.mark.asyncio
    async def test_get_related_techniques(self):
        """Test getting related MITRE techniques."""
        enricher = AsyncMock()
        enricher.get_related = AsyncMock(return_value={
            "technique_id": "T1059.001",
            "related_techniques": [
                {"id": "T1059", "relationship": "parent"},
                {"id": "T1059.003", "relationship": "sibling"},
                {"id": "T1105", "relationship": "often_used_with"}
            ]
        })
        
        result = await enricher.get_related("T1059.001")
        
        assert len(result["related_techniques"]) > 0
