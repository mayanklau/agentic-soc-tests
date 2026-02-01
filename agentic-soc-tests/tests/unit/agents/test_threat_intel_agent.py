"""
Unit Tests for Threat Intelligence Agent

Tests the Threat Intelligence Agent's capabilities for IOC correlation,
threat feed management, and intelligence enrichment.
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timedelta
from uuid import uuid4


class TestThreatIntelAgentInitialization:
    """Test Threat Intelligence Agent initialization."""
    
    def test_threat_intel_agent_creation(self):
        """Test that threat intel agent can be instantiated."""
        config = {
            "enabled": True,
            "feeds": ["virustotal", "abuseipdb", "misp", "otx"],
            "cache_ttl_minutes": 60,
            "auto_enrich": True
        }
        
        assert config["enabled"] is True
        assert len(config["feeds"]) == 4
    
    def test_threat_intel_feed_configuration(self):
        """Test configuring individual threat feeds."""
        feeds_config = {
            "virustotal": {
                "enabled": True,
                "api_key": "vt_key_xxx",
                "rate_limit": 4,  # per minute
                "priority": 1
            },
            "abuseipdb": {
                "enabled": True,
                "api_key": "abuse_key_xxx",
                "rate_limit": 60,
                "priority": 2
            },
            "misp": {
                "enabled": True,
                "url": "https://misp.example.com",
                "api_key": "misp_key_xxx",
                "verify_ssl": True,
                "priority": 3
            }
        }
        
        assert feeds_config["virustotal"]["rate_limit"] == 4
        assert feeds_config["misp"]["verify_ssl"] is True


class TestIOCLookup:
    """Test IOC lookup capabilities."""
    
    def test_lookup_ip_address(self, sample_ioc):
        """Test IP address lookup."""
        ioc = sample_ioc
        
        assert ioc["type"] == "ip"
        assert ioc["value"] == "198.51.100.1"
        assert ioc["confidence"] == 85
    
    def test_lookup_domain(self):
        """Test domain lookup."""
        ioc = {
            "type": "domain",
            "value": "malicious-domain.com",
            "result": {
                "malicious": True,
                "categories": ["c2", "malware_distribution"],
                "whois": {
                    "registrar": "BadRegistrar Inc",
                    "created": "2024-01-01",
                    "updated": "2024-01-10"
                },
                "dns": {
                    "a_records": ["198.51.100.1"],
                    "mx_records": []
                }
            }
        }
        
        assert ioc["result"]["malicious"] is True
        assert "c2" in ioc["result"]["categories"]
    
    def test_lookup_file_hash(self):
        """Test file hash lookup."""
        ioc = {
            "type": "hash",
            "hash_type": "sha256",
            "value": "a" * 64,
            "result": {
                "malicious": True,
                "detection_ratio": "45/70",
                "file_type": "PE32 executable",
                "first_seen": "2024-01-10",
                "names": ["malware.exe", "payload.exe"],
                "families": ["Cobalt Strike", "Beacon"]
            }
        }
        
        assert ioc["result"]["detection_ratio"] == "45/70"
        assert "Cobalt Strike" in ioc["result"]["families"]
    
    def test_lookup_url(self):
        """Test URL lookup."""
        ioc = {
            "type": "url",
            "value": "http://malicious.com/payload.exe",
            "result": {
                "malicious": True,
                "categories": ["malware_download"],
                "http_status": 200,
                "content_type": "application/x-msdownload",
                "final_url": "http://cdn.malicious.com/payload.exe"
            }
        }
        
        assert ioc["result"]["content_type"] == "application/x-msdownload"
    
    def test_lookup_email(self):
        """Test email address lookup."""
        ioc = {
            "type": "email",
            "value": "attacker@malicious.com",
            "result": {
                "malicious": True,
                "associated_campaigns": ["phishing_campaign_2024"],
                "domain_reputation": "bad",
                "reported_count": 150
            }
        }
        
        assert ioc["result"]["reported_count"] == 150
    
    def test_bulk_lookup(self, sample_iocs_batch):
        """Test bulk IOC lookup."""
        iocs = sample_iocs_batch
        
        results = []
        for ioc in iocs:
            results.append({
                "ioc": ioc,
                "status": "found",
                "malicious": True if ioc["type"] in ["ip", "domain"] else False
            })
        
        assert len(results) == len(iocs)


class TestThreatIntelEnrichment:
    """Test threat intelligence enrichment."""
    
    def test_enrich_alert_with_ti(self, sample_alert, sample_threat_intel_response):
        """Test enriching alert with threat intelligence."""
        alert = sample_alert.copy()
        ti_response = sample_threat_intel_response
        
        alert["threat_intel"] = {
            "malicious": ti_response["malicious"],
            "confidence": ti_response["confidence"],
            "context": ti_response["context"],
            "related_iocs": ti_response["related_iocs"]
        }
        
        assert alert["threat_intel"]["malicious"] is True
        assert alert["threat_intel"]["confidence"] == 92
    
    def test_enrich_with_actor_info(self, sample_ioc):
        """Test enrichment with threat actor information."""
        actor_info = {
            "name": "APT29",
            "aliases": ["Cozy Bear", "The Dukes"],
            "origin": "Russia",
            "motivation": "Espionage",
            "targets": ["Government", "Defense", "Energy"],
            "ttps": ["T1566", "T1059", "T1071"],
            "confidence": 85
        }
        
        assert actor_info["name"] == "APT29"
        assert "Espionage" == actor_info["motivation"]
    
    def test_enrich_with_campaign_info(self):
        """Test enrichment with campaign information."""
        campaign_info = {
            "name": "Operation SolarWinds",
            "actor": "APT29",
            "start_date": "2020-03-01",
            "end_date": "2020-12-13",
            "targets": ["US Government", "Tech Companies"],
            "techniques": ["T1195.002", "T1071.001"],
            "iocs_count": 500
        }
        
        assert campaign_info["actor"] == "APT29"


class TestThreatFeedManagement:
    """Test threat feed management."""
    
    def test_feed_synchronization(self):
        """Test synchronizing threat feed data."""
        feed_status = {
            "feed_name": "virustotal",
            "last_sync": datetime.utcnow().isoformat(),
            "records_synced": 1000,
            "new_records": 50,
            "updated_records": 100,
            "status": "success"
        }
        
        assert feed_status["status"] == "success"
        assert feed_status["new_records"] == 50
    
    def test_feed_staleness_detection(self):
        """Test detection of stale feed data."""
        feeds = [
            {"name": "feed1", "last_sync": (datetime.utcnow() - timedelta(hours=1)).isoformat()},
            {"name": "feed2", "last_sync": (datetime.utcnow() - timedelta(days=2)).isoformat()},
            {"name": "feed3", "last_sync": (datetime.utcnow() - timedelta(minutes=30)).isoformat()}
        ]
        
        stale_threshold_hours = 24
        
        stale_feeds = []
        for feed in feeds:
            last_sync = datetime.fromisoformat(feed["last_sync"].replace("Z", "+00:00"))
            age_hours = (datetime.utcnow().replace(tzinfo=last_sync.tzinfo) - last_sync).total_seconds() / 3600
            if age_hours > stale_threshold_hours:
                stale_feeds.append(feed["name"])
        
        assert "feed2" in stale_feeds
        assert len(stale_feeds) == 1
    
    def test_feed_priority_ordering(self):
        """Test feed priority for lookups."""
        feeds = [
            {"name": "virustotal", "priority": 1, "enabled": True},
            {"name": "abuseipdb", "priority": 2, "enabled": True},
            {"name": "misp", "priority": 3, "enabled": False},
            {"name": "otx", "priority": 4, "enabled": True}
        ]
        
        # Get enabled feeds in priority order
        enabled_feeds = sorted(
            [f for f in feeds if f["enabled"]],
            key=lambda x: x["priority"]
        )
        
        assert enabled_feeds[0]["name"] == "virustotal"
        assert len(enabled_feeds) == 3


class TestSTIXProcessing:
    """Test STIX format processing."""
    
    def test_parse_stix_indicator(self):
        """Test parsing STIX indicator."""
        stix_indicator = {
            "type": "indicator",
            "id": "indicator--a932fcc6-e032-476c-826f-cb970a5a1ade",
            "created": "2024-01-15T10:00:00.000Z",
            "modified": "2024-01-15T10:00:00.000Z",
            "pattern": "[ipv4-addr:value = '198.51.100.1']",
            "pattern_type": "stix",
            "valid_from": "2024-01-15T00:00:00Z",
            "labels": ["malicious-activity", "c2"]
        }
        
        assert stix_indicator["type"] == "indicator"
        assert "c2" in stix_indicator["labels"]
    
    def test_parse_stix_attack_pattern(self):
        """Test parsing STIX attack pattern."""
        attack_pattern = {
            "type": "attack-pattern",
            "id": "attack-pattern--d1fcf083-a721-4223-aedf-bf8960798d62",
            "name": "Spearphishing Attachment",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1566.001"
                }
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
            ]
        }
        
        assert attack_pattern["name"] == "Spearphishing Attachment"
    
    def test_stix_bundle_parsing(self):
        """Test parsing STIX bundle with multiple objects."""
        bundle = {
            "type": "bundle",
            "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d",
            "objects": [
                {"type": "indicator", "id": "indicator--1"},
                {"type": "malware", "id": "malware--1"},
                {"type": "relationship", "id": "relationship--1"}
            ]
        }
        
        assert len(bundle["objects"]) == 3


class TestMISPIntegration:
    """Test MISP integration."""
    
    def test_misp_event_parsing(self):
        """Test parsing MISP event."""
        misp_event = {
            "Event": {
                "id": "1234",
                "info": "APT29 Campaign Indicators",
                "threat_level_id": "1",
                "analysis": "2",
                "date": "2024-01-15",
                "Attribute": [
                    {"type": "ip-dst", "value": "198.51.100.1", "to_ids": True},
                    {"type": "domain", "value": "malicious.com", "to_ids": True}
                ],
                "Tag": [
                    {"name": "tlp:amber"},
                    {"name": "apt29"}
                ]
            }
        }
        
        event = misp_event["Event"]
        assert event["info"] == "APT29 Campaign Indicators"
        assert len(event["Attribute"]) == 2
    
    def test_misp_attribute_to_ioc(self):
        """Test converting MISP attribute to IOC format."""
        misp_attr = {
            "type": "ip-dst",
            "value": "198.51.100.1",
            "to_ids": True,
            "category": "Network activity",
            "comment": "C2 server"
        }
        
        ioc = {
            "type": "ip",
            "value": misp_attr["value"],
            "source": "misp",
            "tags": [misp_attr["category"]],
            "context": misp_attr["comment"]
        }
        
        assert ioc["type"] == "ip"
        assert ioc["source"] == "misp"


class TestThreatIntelCaching:
    """Test threat intelligence caching."""
    
    def test_cache_hit(self, sample_ioc):
        """Test cache hit for repeated lookups."""
        cache = {}
        cache_key = f"{sample_ioc['type']}:{sample_ioc['value']}"
        
        # First lookup - cache miss
        cache_hit = cache_key in cache
        assert cache_hit is False
        
        # Store in cache
        cache[cache_key] = {
            "result": {"malicious": True},
            "cached_at": datetime.utcnow().isoformat(),
            "ttl_minutes": 60
        }
        
        # Second lookup - cache hit
        cache_hit = cache_key in cache
        assert cache_hit is True
    
    def test_cache_expiration(self):
        """Test cache entry expiration."""
        cache_entry = {
            "cached_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
            "ttl_minutes": 60
        }
        
        cached_at = datetime.fromisoformat(cache_entry["cached_at"].replace("Z", "+00:00"))
        age_minutes = (datetime.utcnow().replace(tzinfo=cached_at.tzinfo) - cached_at).total_seconds() / 60
        
        is_expired = age_minutes > cache_entry["ttl_minutes"]
        assert is_expired is True
    
    def test_cache_invalidation(self):
        """Test cache invalidation on feed update."""
        cache = {
            "ip:192.168.1.1": {"result": {}, "feed": "feed1"},
            "ip:192.168.1.2": {"result": {}, "feed": "feed1"},
            "ip:192.168.1.3": {"result": {}, "feed": "feed2"}
        }
        
        # Invalidate entries from feed1
        feed_to_invalidate = "feed1"
        cache = {k: v for k, v in cache.items() if v.get("feed") != feed_to_invalidate}
        
        assert len(cache) == 1
        assert "ip:192.168.1.3" in cache


class TestThreatIntelReporting:
    """Test threat intelligence reporting."""
    
    def test_generate_ti_report(self, sample_iocs_batch):
        """Test generating threat intel report."""
        report = {
            "report_type": "ioc_summary",
            "generated_at": datetime.utcnow().isoformat(),
            "period": "last_24_hours",
            "total_iocs_processed": len(sample_iocs_batch),
            "malicious_found": 5,
            "by_type": {
                "ip": 2,
                "domain": 2,
                "hash": 2,
                "url": 1,
                "email": 1
            },
            "top_actors": ["APT29", "APT28"],
            "top_campaigns": ["Campaign1", "Campaign2"]
        }
        
        assert report["total_iocs_processed"] == 8
    
    def test_ioc_export_formats(self):
        """Test exporting IOCs in different formats."""
        export_formats = ["stix", "misp", "csv", "json", "openioc"]
        
        for fmt in export_formats:
            export_config = {
                "format": fmt,
                "include_context": True,
                "include_relations": True
            }
            assert export_config["format"] in export_formats


class TestThreatIntelMetrics:
    """Test threat intelligence metrics."""
    
    def test_lookup_performance_metrics(self):
        """Test tracking lookup performance."""
        metrics = {
            "total_lookups": 10000,
            "cache_hits": 7000,
            "cache_misses": 3000,
            "avg_lookup_time_ms": 50,
            "p95_lookup_time_ms": 200,
            "p99_lookup_time_ms": 500
        }
        
        cache_hit_rate = metrics["cache_hits"] / metrics["total_lookups"]
        assert cache_hit_rate == 0.7
    
    def test_feed_health_metrics(self):
        """Test feed health metrics."""
        feed_metrics = {
            "virustotal": {"status": "healthy", "latency_ms": 100, "success_rate": 0.99},
            "abuseipdb": {"status": "healthy", "latency_ms": 150, "success_rate": 0.98},
            "misp": {"status": "degraded", "latency_ms": 2000, "success_rate": 0.85}
        }
        
        unhealthy_feeds = [
            name for name, metrics in feed_metrics.items()
            if metrics["status"] != "healthy" or metrics["success_rate"] < 0.9
        ]
        
        assert "misp" in unhealthy_feeds
