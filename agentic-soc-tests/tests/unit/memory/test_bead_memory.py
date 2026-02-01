"""
Unit Tests for Bead Memory Architecture
=======================================
Tests for the novel Bead Memory system used for attack chain correlation,
context retention, and multi-tier memory management.
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import uuid


# =============================================================================
# MEMORY BEAD CORE TESTS
# =============================================================================

class TestMemoryBeadCore:
    """Tests for core memory bead functionality."""
    
    @pytest.mark.asyncio
    async def test_create_memory_bead(self, sample_memory_bead):
        """Test creating a new memory bead."""
        memory = Mock()
        memory.create_bead = Mock(return_value={
            "bead_id": "bead-001",
            "created_at": "2024-01-15T12:00:00Z",
            "entity_type": "attack_chain",
            "entity_id": "chain-001",
            "content": {"stage": 1, "technique": "T1566"},
            "ttl_seconds": 3600
        })
        
        bead = memory.create_bead(
            entity_type="attack_chain",
            entity_id="chain-001",
            content={"stage": 1}
        )
        
        assert bead["bead_id"] == "bead-001"
        assert bead["entity_type"] == "attack_chain"
    
    @pytest.mark.asyncio
    async def test_memory_bead_structure(self, sample_memory_bead):
        """Test memory bead has correct structure."""
        assert "bead_id" in sample_memory_bead
        assert "entity_type" in sample_memory_bead
        assert "entity_id" in sample_memory_bead
        assert "content" in sample_memory_bead
        assert "created_at" in sample_memory_bead
        assert "updated_at" in sample_memory_bead
    
    @pytest.mark.asyncio
    async def test_update_memory_bead(self, sample_memory_bead):
        """Test updating a memory bead."""
        memory = AsyncMock()
        memory.update_bead = AsyncMock(return_value={
            "bead_id": sample_memory_bead["bead_id"],
            "updated_at": "2024-01-15T12:05:00Z",
            "content": {"stage": 2, "technique": "T1059"},
            "version": 2
        })
        
        result = await memory.update_bead(
            sample_memory_bead["bead_id"],
            content={"stage": 2}
        )
        
        assert result["version"] == 2
    
    @pytest.mark.asyncio
    async def test_delete_memory_bead(self, sample_memory_bead):
        """Test deleting a memory bead."""
        memory = AsyncMock()
        memory.delete_bead = AsyncMock(return_value={
            "deleted": True,
            "bead_id": sample_memory_bead["bead_id"]
        })
        
        result = await memory.delete_bead(sample_memory_bead["bead_id"])
        
        assert result["deleted"] is True
    
    @pytest.mark.asyncio
    async def test_memory_bead_ttl_expiration(self):
        """Test memory bead TTL expiration."""
        memory = AsyncMock()
        memory.check_expired = AsyncMock(return_value={
            "bead_id": "bead-001",
            "expired": True,
            "created_at": "2024-01-15T10:00:00Z",
            "ttl_seconds": 3600,
            "expired_at": "2024-01-15T11:00:00Z"
        })
        
        result = await memory.check_expired("bead-001")
        
        assert result["expired"] is True
    
    @pytest.mark.asyncio
    async def test_memory_bead_refresh_ttl(self):
        """Test refreshing memory bead TTL."""
        memory = AsyncMock()
        memory.refresh_ttl = AsyncMock(return_value={
            "bead_id": "bead-001",
            "new_expiry": "2024-01-15T14:00:00Z",
            "ttl_seconds": 3600
        })
        
        result = await memory.refresh_ttl("bead-001", ttl_seconds=3600)
        
        assert "new_expiry" in result


# =============================================================================
# BEAD CHAIN TESTS
# =============================================================================

class TestBeadChain:
    """Tests for chaining memory beads together."""
    
    @pytest.mark.asyncio
    async def test_create_bead_chain(self, sample_attack_chain):
        """Test creating a chain of memory beads."""
        memory = AsyncMock()
        memory.create_chain = AsyncMock(return_value={
            "chain_id": "chain-001",
            "beads": [
                {"bead_id": "bead-001", "position": 0},
                {"bead_id": "bead-002", "position": 1},
                {"bead_id": "bead-003", "position": 2}
            ],
            "chain_type": "attack_chain",
            "created_at": "2024-01-15T12:00:00Z"
        })
        
        result = await memory.create_chain(
            chain_type="attack_chain",
            beads=["bead-001", "bead-002", "bead-003"]
        )
        
        assert len(result["beads"]) == 3
        assert result["chain_type"] == "attack_chain"
    
    @pytest.mark.asyncio
    async def test_append_bead_to_chain(self):
        """Test appending a bead to an existing chain."""
        memory = AsyncMock()
        memory.append_to_chain = AsyncMock(return_value={
            "chain_id": "chain-001",
            "bead_id": "bead-004",
            "position": 3,
            "chain_length": 4
        })
        
        result = await memory.append_to_chain("chain-001", "bead-004")
        
        assert result["position"] == 3
        assert result["chain_length"] == 4
    
    @pytest.mark.asyncio
    async def test_get_chain_by_entity(self):
        """Test retrieving chain by entity."""
        memory = AsyncMock()
        memory.get_chain_by_entity = AsyncMock(return_value={
            "chain_id": "chain-001",
            "entity_type": "host",
            "entity_id": "WORKSTATION-123",
            "beads": [
                {"bead_id": "bead-001", "content": {"event": "login"}},
                {"bead_id": "bead-002", "content": {"event": "process_create"}}
            ]
        })
        
        result = await memory.get_chain_by_entity("host", "WORKSTATION-123")
        
        assert len(result["beads"]) == 2
    
    @pytest.mark.asyncio
    async def test_chain_traversal_forward(self):
        """Test forward traversal of bead chain."""
        memory = AsyncMock()
        memory.traverse_chain = AsyncMock(return_value={
            "chain_id": "chain-001",
            "direction": "forward",
            "beads_traversed": [
                {"position": 0, "bead_id": "bead-001"},
                {"position": 1, "bead_id": "bead-002"},
                {"position": 2, "bead_id": "bead-003"}
            ]
        })
        
        result = await memory.traverse_chain("chain-001", direction="forward")
        
        assert result["beads_traversed"][0]["position"] == 0
    
    @pytest.mark.asyncio
    async def test_chain_traversal_backward(self):
        """Test backward traversal of bead chain."""
        memory = AsyncMock()
        memory.traverse_chain = AsyncMock(return_value={
            "chain_id": "chain-001",
            "direction": "backward",
            "beads_traversed": [
                {"position": 2, "bead_id": "bead-003"},
                {"position": 1, "bead_id": "bead-002"},
                {"position": 0, "bead_id": "bead-001"}
            ]
        })
        
        result = await memory.traverse_chain("chain-001", direction="backward")
        
        assert result["beads_traversed"][0]["position"] == 2
    
    @pytest.mark.asyncio
    async def test_merge_chains(self):
        """Test merging two bead chains."""
        memory = AsyncMock()
        memory.merge_chains = AsyncMock(return_value={
            "merged_chain_id": "chain-merged-001",
            "source_chains": ["chain-001", "chain-002"],
            "total_beads": 7,
            "deduplication": {"removed": 1}
        })
        
        result = await memory.merge_chains(["chain-001", "chain-002"])
        
        assert result["total_beads"] == 7
    
    @pytest.mark.asyncio
    async def test_split_chain(self):
        """Test splitting a bead chain."""
        memory = AsyncMock()
        memory.split_chain = AsyncMock(return_value={
            "original_chain": "chain-001",
            "new_chains": [
                {"chain_id": "chain-001a", "beads": 3},
                {"chain_id": "chain-001b", "beads": 4}
            ],
            "split_at_position": 3
        })
        
        result = await memory.split_chain("chain-001", at_position=3)
        
        assert len(result["new_chains"]) == 2


# =============================================================================
# MULTI-TIER MEMORY TESTS
# =============================================================================

class TestMultiTierMemory:
    """Tests for multi-tier memory architecture."""
    
    @pytest.mark.asyncio
    async def test_working_memory_storage(self):
        """Test working memory (short-term) storage."""
        memory = AsyncMock()
        memory.store_working = AsyncMock(return_value={
            "tier": "working",
            "bead_id": "bead-001",
            "stored": True,
            "ttl_seconds": 300  # 5 minutes
        })
        
        result = await memory.store_working("bead-001", {"context": "active_investigation"})
        
        assert result["tier"] == "working"
        assert result["ttl_seconds"] == 300
    
    @pytest.mark.asyncio
    async def test_episodic_memory_storage(self):
        """Test episodic memory (medium-term) storage."""
        memory = AsyncMock()
        memory.store_episodic = AsyncMock(return_value={
            "tier": "episodic",
            "bead_id": "bead-001",
            "stored": True,
            "ttl_seconds": 86400  # 24 hours
        })
        
        result = await memory.store_episodic("bead-001", {"incident": "inc-001"})
        
        assert result["tier"] == "episodic"
        assert result["ttl_seconds"] == 86400
    
    @pytest.mark.asyncio
    async def test_semantic_memory_storage(self):
        """Test semantic memory (long-term) storage."""
        memory = AsyncMock()
        memory.store_semantic = AsyncMock(return_value={
            "tier": "semantic",
            "bead_id": "bead-001",
            "stored": True,
            "ttl_seconds": None,  # Permanent
            "indexed": True
        })
        
        result = await memory.store_semantic("bead-001", {"attack_pattern": "T1566"})
        
        assert result["tier"] == "semantic"
        assert result["ttl_seconds"] is None
    
    @pytest.mark.asyncio
    async def test_memory_tier_promotion(self):
        """Test promoting bead from working to episodic memory."""
        memory = AsyncMock()
        memory.promote_bead = AsyncMock(return_value={
            "bead_id": "bead-001",
            "from_tier": "working",
            "to_tier": "episodic",
            "promoted": True,
            "reason": "investigation_opened"
        })
        
        result = await memory.promote_bead("bead-001", "episodic")
        
        assert result["to_tier"] == "episodic"
    
    @pytest.mark.asyncio
    async def test_memory_tier_demotion(self):
        """Test demoting bead from episodic to working memory."""
        memory = AsyncMock()
        memory.demote_bead = AsyncMock(return_value={
            "bead_id": "bead-001",
            "from_tier": "episodic",
            "to_tier": "working",
            "demoted": True,
            "reason": "investigation_closed_false_positive"
        })
        
        result = await memory.demote_bead("bead-001", "working")
        
        assert result["to_tier"] == "working"
    
    @pytest.mark.asyncio
    async def test_memory_consolidation(self):
        """Test memory consolidation from episodic to semantic."""
        memory = AsyncMock()
        memory.consolidate = AsyncMock(return_value={
            "consolidated_beads": 50,
            "from_tier": "episodic",
            "to_tier": "semantic",
            "patterns_extracted": 5,
            "processing_time_ms": 500
        })
        
        result = await memory.consolidate()
        
        assert result["consolidated_beads"] == 50
    
    @pytest.mark.asyncio
    async def test_memory_retrieval_cascade(self):
        """Test cascading retrieval across memory tiers."""
        memory = AsyncMock()
        memory.retrieve_cascade = AsyncMock(return_value={
            "query": "attack_pattern:T1566",
            "results": [
                {"tier": "working", "beads": 2},
                {"tier": "episodic", "beads": 5},
                {"tier": "semantic", "beads": 10}
            ],
            "total_beads": 17
        })
        
        result = await memory.retrieve_cascade("attack_pattern:T1566")
        
        assert result["total_beads"] == 17


# =============================================================================
# ATTACK CHAIN CORRELATION TESTS
# =============================================================================

class TestAttackChainCorrelation:
    """Tests for attack chain correlation using bead memory."""
    
    @pytest.mark.asyncio
    async def test_detect_attack_chain_start(self, sample_alert):
        """Test detecting the start of a potential attack chain."""
        correlator = AsyncMock()
        correlator.detect_chain_start = AsyncMock(return_value={
            "chain_started": True,
            "initial_bead": "bead-001",
            "trigger_event": sample_alert,
            "potential_techniques": ["T1566", "T1190"]
        })
        
        result = await correlator.detect_chain_start(sample_alert)
        
        assert result["chain_started"] is True
    
    @pytest.mark.asyncio
    async def test_correlate_event_to_chain(self, sample_alert):
        """Test correlating a new event to an existing chain."""
        correlator = AsyncMock()
        correlator.correlate_to_chain = AsyncMock(return_value={
            "correlated": True,
            "chain_id": "chain-001",
            "new_bead_id": "bead-005",
            "correlation_score": 0.87,
            "matching_factors": ["same_host", "same_user", "temporal_proximity"]
        })
        
        result = await correlator.correlate_to_chain("chain-001", sample_alert)
        
        assert result["correlated"] is True
        assert result["correlation_score"] > 0.5
    
    @pytest.mark.asyncio
    async def test_attack_chain_stage_progression(self):
        """Test tracking attack chain stage progression."""
        correlator = AsyncMock()
        correlator.get_chain_progression = AsyncMock(return_value={
            "chain_id": "chain-001",
            "stages_completed": [
                {"stage": "initial_access", "technique": "T1566", "time": "12:00:00Z"},
                {"stage": "execution", "technique": "T1059", "time": "12:05:00Z"},
                {"stage": "credential_access", "technique": "T1003", "time": "12:10:00Z"}
            ],
            "current_stage": "credential_access",
            "predicted_next_stage": "lateral_movement"
        })
        
        result = await correlator.get_chain_progression("chain-001")
        
        assert len(result["stages_completed"]) == 3
        assert result["predicted_next_stage"] == "lateral_movement"
    
    @pytest.mark.asyncio
    async def test_attack_chain_completeness_score(self):
        """Test calculating attack chain completeness score."""
        correlator = AsyncMock()
        correlator.calculate_completeness = AsyncMock(return_value={
            "chain_id": "chain-001",
            "attack_pattern": "APT_standard_intrusion",
            "expected_stages": 7,
            "observed_stages": 4,
            "completeness_score": 0.57,
            "missing_stages": ["persistence", "defense_evasion", "exfiltration"]
        })
        
        result = await correlator.calculate_completeness("chain-001")
        
        assert result["completeness_score"] == 0.57
    
    @pytest.mark.asyncio
    async def test_cross_entity_chain_correlation(self):
        """Test correlating chains across different entities."""
        correlator = AsyncMock()
        correlator.correlate_cross_entity = AsyncMock(return_value={
            "primary_chain": "chain-001",
            "related_chains": [
                {"chain_id": "chain-002", "entity": "user:john.doe", "relation": "same_user"},
                {"chain_id": "chain-003", "entity": "host:SERVER-02", "relation": "lateral_movement"}
            ],
            "combined_risk_score": 85
        })
        
        result = await correlator.correlate_cross_entity("chain-001")
        
        assert len(result["related_chains"]) == 2
    
    @pytest.mark.asyncio
    async def test_attack_chain_kill_chain_mapping(self):
        """Test mapping attack chain to Cyber Kill Chain."""
        correlator = AsyncMock()
        correlator.map_to_kill_chain = AsyncMock(return_value={
            "chain_id": "chain-001",
            "kill_chain_stages": {
                "reconnaissance": False,
                "weaponization": False,
                "delivery": True,
                "exploitation": True,
                "installation": True,
                "command_and_control": False,
                "actions_on_objectives": False
            },
            "furthest_stage": "installation"
        })
        
        result = await correlator.map_to_kill_chain("chain-001")
        
        assert result["furthest_stage"] == "installation"


# =============================================================================
# VECTOR MEMORY TESTS
# =============================================================================

class TestVectorMemory:
    """Tests for vector-based memory storage and retrieval."""
    
    @pytest.mark.asyncio
    async def test_store_bead_embedding(self, mock_qdrant_client):
        """Test storing bead with vector embedding."""
        memory = AsyncMock()
        memory.store_with_embedding = AsyncMock(return_value={
            "bead_id": "bead-001",
            "embedding_stored": True,
            "vector_dimensions": 768,
            "collection": "bead_embeddings"
        })
        
        result = await memory.store_with_embedding("bead-001", embedding=[0.1] * 768)
        
        assert result["embedding_stored"] is True
        assert result["vector_dimensions"] == 768
    
    @pytest.mark.asyncio
    async def test_semantic_similarity_search(self, mock_qdrant_client):
        """Test semantic similarity search for beads."""
        memory = AsyncMock()
        memory.search_similar = AsyncMock(return_value={
            "query_bead": "bead-001",
            "similar_beads": [
                {"bead_id": "bead-010", "similarity": 0.95},
                {"bead_id": "bead-015", "similarity": 0.88},
                {"bead_id": "bead-023", "similarity": 0.82}
            ],
            "threshold": 0.7
        })
        
        result = await memory.search_similar("bead-001", top_k=3)
        
        assert len(result["similar_beads"]) == 3
        assert result["similar_beads"][0]["similarity"] > 0.9
    
    @pytest.mark.asyncio
    async def test_cluster_similar_beads(self, mock_qdrant_client):
        """Test clustering similar beads."""
        memory = AsyncMock()
        memory.cluster_beads = AsyncMock(return_value={
            "clusters": [
                {"cluster_id": 0, "beads": ["bead-001", "bead-002", "bead-003"], "centroid": "bead-001"},
                {"cluster_id": 1, "beads": ["bead-010", "bead-011"], "centroid": "bead-010"}
            ],
            "total_clusters": 2,
            "algorithm": "kmeans"
        })
        
        result = await memory.cluster_beads()
        
        assert result["total_clusters"] == 2
    
    @pytest.mark.asyncio
    async def test_contextual_retrieval(self, mock_qdrant_client):
        """Test contextual retrieval based on current context."""
        memory = AsyncMock()
        memory.retrieve_contextual = AsyncMock(return_value={
            "context": {"entity": "WORKSTATION-123", "technique": "T1059"},
            "retrieved_beads": [
                {"bead_id": "bead-050", "relevance": 0.92, "content": {"similar_incident": True}},
                {"bead_id": "bead-051", "relevance": 0.87, "content": {"playbook": "ps_execution"}}
            ]
        })
        
        result = await memory.retrieve_contextual(
            context={"entity": "WORKSTATION-123", "technique": "T1059"}
        )
        
        assert len(result["retrieved_beads"]) == 2


# =============================================================================
# MEMORY INDEXING AND SEARCH TESTS
# =============================================================================

class TestMemoryIndexing:
    """Tests for memory indexing and search functionality."""
    
    @pytest.mark.asyncio
    async def test_index_bead_by_entity(self, mock_elasticsearch_client):
        """Test indexing bead by entity."""
        memory = AsyncMock()
        memory.index_by_entity = AsyncMock(return_value={
            "bead_id": "bead-001",
            "indexed": True,
            "entity_types": ["host", "user", "ip"],
            "entity_values": ["WORKSTATION-123", "john.doe", "192.168.1.100"]
        })
        
        result = await memory.index_by_entity("bead-001")
        
        assert result["indexed"] is True
        assert len(result["entity_types"]) == 3
    
    @pytest.mark.asyncio
    async def test_search_by_entity(self, mock_elasticsearch_client):
        """Test searching beads by entity."""
        memory = AsyncMock()
        memory.search_by_entity = AsyncMock(return_value={
            "entity_type": "host",
            "entity_value": "WORKSTATION-123",
            "beads": [
                {"bead_id": "bead-001", "timestamp": "2024-01-15T12:00:00Z"},
                {"bead_id": "bead-005", "timestamp": "2024-01-15T12:05:00Z"}
            ],
            "total": 2
        })
        
        result = await memory.search_by_entity("host", "WORKSTATION-123")
        
        assert result["total"] == 2
    
    @pytest.mark.asyncio
    async def test_search_by_time_range(self, mock_elasticsearch_client):
        """Test searching beads by time range."""
        memory = AsyncMock()
        memory.search_by_time = AsyncMock(return_value={
            "start_time": "2024-01-15T12:00:00Z",
            "end_time": "2024-01-15T13:00:00Z",
            "beads": 150,
            "chains": 5
        })
        
        result = await memory.search_by_time(
            start="2024-01-15T12:00:00Z",
            end="2024-01-15T13:00:00Z"
        )
        
        assert result["beads"] == 150
    
    @pytest.mark.asyncio
    async def test_search_by_technique(self, mock_elasticsearch_client):
        """Test searching beads by MITRE technique."""
        memory = AsyncMock()
        memory.search_by_technique = AsyncMock(return_value={
            "technique": "T1059.001",
            "beads": [
                {"bead_id": "bead-010", "chain_id": "chain-001"},
                {"bead_id": "bead-025", "chain_id": "chain-003"}
            ],
            "total": 2,
            "related_techniques": ["T1059", "T1059.003"]
        })
        
        result = await memory.search_by_technique("T1059.001")
        
        assert result["total"] == 2
    
    @pytest.mark.asyncio
    async def test_full_text_search(self, mock_elasticsearch_client):
        """Test full-text search across beads."""
        memory = AsyncMock()
        memory.full_text_search = AsyncMock(return_value={
            "query": "powershell encoded command",
            "results": [
                {"bead_id": "bead-001", "score": 15.5, "highlight": "...powershell -enc..."},
                {"bead_id": "bead-015", "score": 12.3, "highlight": "...encoded command line..."}
            ],
            "total": 2
        })
        
        result = await memory.full_text_search("powershell encoded command")
        
        assert result["total"] == 2


# =============================================================================
# MEMORY LIFECYCLE TESTS
# =============================================================================

class TestMemoryLifecycle:
    """Tests for memory lifecycle management."""
    
    @pytest.mark.asyncio
    async def test_memory_garbage_collection(self):
        """Test garbage collection of expired beads."""
        memory = AsyncMock()
        memory.garbage_collect = AsyncMock(return_value={
            "expired_beads_removed": 150,
            "orphaned_chains_removed": 5,
            "storage_freed_mb": 50,
            "execution_time_ms": 500
        })
        
        result = await memory.garbage_collect()
        
        assert result["expired_beads_removed"] == 150
    
    @pytest.mark.asyncio
    async def test_memory_compaction(self):
        """Test memory compaction for optimization."""
        memory = AsyncMock()
        memory.compact = AsyncMock(return_value={
            "beads_compacted": 1000,
            "chains_optimized": 50,
            "storage_before_mb": 500,
            "storage_after_mb": 350,
            "compression_ratio": 0.70
        })
        
        result = await memory.compact()
        
        assert result["compression_ratio"] < 1.0
    
    @pytest.mark.asyncio
    async def test_memory_snapshot(self):
        """Test creating memory snapshot for backup."""
        memory = AsyncMock()
        memory.create_snapshot = AsyncMock(return_value={
            "snapshot_id": "snap-001",
            "created_at": "2024-01-15T12:00:00Z",
            "beads_included": 10000,
            "chains_included": 500,
            "size_mb": 250
        })
        
        result = await memory.create_snapshot()
        
        assert result["beads_included"] == 10000
    
    @pytest.mark.asyncio
    async def test_memory_restore_from_snapshot(self):
        """Test restoring memory from snapshot."""
        memory = AsyncMock()
        memory.restore_snapshot = AsyncMock(return_value={
            "snapshot_id": "snap-001",
            "restored": True,
            "beads_restored": 10000,
            "chains_restored": 500,
            "restore_time_ms": 5000
        })
        
        result = await memory.restore_snapshot("snap-001")
        
        assert result["restored"] is True


# =============================================================================
# MEMORY METRICS AND MONITORING TESTS
# =============================================================================

class TestMemoryMetrics:
    """Tests for memory metrics and monitoring."""
    
    @pytest.mark.asyncio
    async def test_memory_usage_metrics(self):
        """Test memory usage metrics."""
        memory = AsyncMock()
        memory.get_usage_metrics = AsyncMock(return_value={
            "total_beads": 50000,
            "total_chains": 2500,
            "storage_used_mb": 1024,
            "storage_limit_mb": 4096,
            "usage_percentage": 25.0
        })
        
        result = await memory.get_usage_metrics()
        
        assert result["usage_percentage"] == 25.0
    
    @pytest.mark.asyncio
    async def test_memory_tier_distribution(self):
        """Test memory tier distribution metrics."""
        memory = AsyncMock()
        memory.get_tier_distribution = AsyncMock(return_value={
            "working": {"beads": 500, "percentage": 1.0},
            "episodic": {"beads": 9500, "percentage": 19.0},
            "semantic": {"beads": 40000, "percentage": 80.0}
        })
        
        result = await memory.get_tier_distribution()
        
        assert result["semantic"]["percentage"] == 80.0
    
    @pytest.mark.asyncio
    async def test_memory_access_patterns(self):
        """Test tracking memory access patterns."""
        memory = AsyncMock()
        memory.get_access_patterns = AsyncMock(return_value={
            "reads_per_second": 1000,
            "writes_per_second": 100,
            "cache_hit_rate": 0.85,
            "avg_read_latency_ms": 5,
            "avg_write_latency_ms": 15
        })
        
        result = await memory.get_access_patterns()
        
        assert result["cache_hit_rate"] > 0.8
    
    @pytest.mark.asyncio
    async def test_chain_statistics(self):
        """Test chain statistics metrics."""
        memory = AsyncMock()
        memory.get_chain_stats = AsyncMock(return_value={
            "total_chains": 2500,
            "active_chains": 150,
            "avg_chain_length": 5.2,
            "max_chain_length": 25,
            "chains_by_type": {
                "attack_chain": 100,
                "investigation": 40,
                "correlation": 10
            }
        })
        
        result = await memory.get_chain_stats()
        
        assert result["avg_chain_length"] > 5
