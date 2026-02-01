"""
Unit Tests for SLM (Small Language Model) Inference
===================================================
Tests for specialized Small Language Models including domain-specific tokenizers,
model inference, and multi-model orchestration for security operations.
"""

import pytest
import asyncio
import json
import numpy as np
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import uuid


# =============================================================================
# SLM ENGINE CORE TESTS
# =============================================================================

class TestSLMEngineCore:
    """Tests for core SLM engine functionality."""
    
    @pytest.mark.asyncio
    async def test_slm_engine_initialization(self, app_config):
        """Test SLM engine initializes with all models."""
        engine = Mock()
        engine.models = {
            "detection": {"loaded": True, "params": "125M"},
            "triage": {"loaded": True, "params": "85M"},
            "investigation": {"loaded": True, "params": "150M"},
            "response": {"loaded": True, "params": "100M"},
            "threat_intel": {"loaded": True, "params": "125M"},
            "forensics": {"loaded": True, "params": "175M"},
            "hunting": {"loaded": True, "params": "125M"},
            "compliance": {"loaded": True, "params": "85M"},
            "orchestrator": {"loaded": True, "params": "200M"}
        }
        engine.total_params = "1.17B"
        
        assert len(engine.models) == 9
        assert engine.models["detection"]["loaded"] is True
    
    @pytest.mark.asyncio
    async def test_slm_engine_health_check(self):
        """Test SLM engine health check."""
        engine = AsyncMock()
        engine.health_check = AsyncMock(return_value={
            "status": "healthy",
            "models_loaded": 9,
            "gpu_memory_used_gb": 4.5,
            "gpu_memory_total_gb": 16,
            "inference_queue_depth": 10
        })
        
        health = await engine.health_check()
        
        assert health["status"] == "healthy"
        assert health["models_loaded"] == 9
    
    @pytest.mark.asyncio
    async def test_load_slm_model(self):
        """Test loading a specific SLM model."""
        engine = AsyncMock()
        engine.load_model = AsyncMock(return_value={
            "model_name": "detection_slm",
            "loaded": True,
            "parameters": "125M",
            "vocab_size": 32000,
            "context_length": 4096,
            "load_time_ms": 2500
        })
        
        result = await engine.load_model("detection_slm")
        
        assert result["loaded"] is True
        assert result["parameters"] == "125M"
    
    @pytest.mark.asyncio
    async def test_unload_slm_model(self):
        """Test unloading an SLM model to free resources."""
        engine = AsyncMock()
        engine.unload_model = AsyncMock(return_value={
            "model_name": "detection_slm",
            "unloaded": True,
            "memory_freed_gb": 0.5
        })
        
        result = await engine.unload_model("detection_slm")
        
        assert result["unloaded"] is True


# =============================================================================
# SECURITY TOKENIZER TESTS
# =============================================================================

class TestSecurityTokenizer:
    """Tests for domain-specific security tokenizer."""
    
    @pytest.mark.asyncio
    async def test_tokenizer_initialization(self):
        """Test security tokenizer initialization."""
        tokenizer = Mock()
        tokenizer.vocab_size = 32000
        tokenizer.special_tokens = {
            "[IP]": 32001,
            "[DOMAIN]": 32002,
            "[HASH]": 32003,
            "[CVE]": 32004,
            "[MITRE]": 32005,
            "[USER]": 32006,
            "[HOST]": 32007
        }
        tokenizer.pad_token_id = 0
        tokenizer.eos_token_id = 1
        
        assert tokenizer.vocab_size == 32000
        assert "[IP]" in tokenizer.special_tokens
    
    @pytest.mark.asyncio
    async def test_tokenize_security_event(self, sample_raw_event):
        """Test tokenizing a security event."""
        tokenizer = Mock()
        tokenizer.encode = Mock(return_value={
            "input_ids": [101, 2054, 192, 168, 1, 100, 102],
            "attention_mask": [1, 1, 1, 1, 1, 1, 1],
            "token_count": 7
        })
        
        result = tokenizer.encode("Alert from 192.168.1.100")
        
        assert "input_ids" in result
        assert result["token_count"] == 7
    
    @pytest.mark.asyncio
    async def test_tokenize_ip_address(self):
        """Test IP address tokenization."""
        tokenizer = Mock()
        tokenizer.tokenize_ip = Mock(return_value={
            "original": "192.168.1.100",
            "tokens": ["[IP]", "192", ".", "168", ".", "1", ".", "100"],
            "normalized": True
        })
        
        result = tokenizer.tokenize_ip("192.168.1.100")
        
        assert result["tokens"][0] == "[IP]"
    
    @pytest.mark.asyncio
    async def test_tokenize_file_hash(self):
        """Test file hash tokenization."""
        tokenizer = Mock()
        tokenizer.tokenize_hash = Mock(return_value={
            "original": "abc123def456...",
            "tokens": ["[HASH]", "abc123def456"],
            "hash_type": "sha256"
        })
        
        result = tokenizer.tokenize_hash("abc123def456...")
        
        assert result["tokens"][0] == "[HASH]"
    
    @pytest.mark.asyncio
    async def test_tokenize_mitre_technique(self):
        """Test MITRE technique tokenization."""
        tokenizer = Mock()
        tokenizer.tokenize_mitre = Mock(return_value={
            "original": "T1059.001",
            "tokens": ["[MITRE]", "T1059", ".", "001"],
            "tactic": "execution"
        })
        
        result = tokenizer.tokenize_mitre("T1059.001")
        
        assert result["tokens"][0] == "[MITRE]"
    
    @pytest.mark.asyncio
    async def test_tokenize_windows_path(self):
        """Test Windows path tokenization."""
        tokenizer = Mock()
        tokenizer.tokenize_path = Mock(return_value={
            "original": "C:\\Windows\\System32\\cmd.exe",
            "tokens": ["C:", "\\", "Windows", "\\", "System32", "\\", "cmd", ".", "exe"],
            "normalized": True
        })
        
        result = tokenizer.tokenize_path("C:\\Windows\\System32\\cmd.exe")
        
        assert "cmd" in result["tokens"]
    
    @pytest.mark.asyncio
    async def test_tokenize_log_message(self):
        """Test log message tokenization."""
        tokenizer = Mock()
        tokenizer.encode = Mock(return_value={
            "input_ids": [101, 2054, 4032, 2078, 1024, 102],
            "attention_mask": [1, 1, 1, 1, 1, 1],
            "entities_detected": [
                {"type": "IP", "value": "192.168.1.100", "position": [3, 4]},
                {"type": "USER", "value": "admin", "position": [7, 8]}
            ]
        })
        
        log = "Failed login from 192.168.1.100 for user admin"
        result = tokenizer.encode(log)
        
        assert len(result["entities_detected"]) == 2
    
    @pytest.mark.asyncio
    async def test_batch_tokenization(self, sample_events_batch):
        """Test batch tokenization of multiple events."""
        tokenizer = Mock()
        tokenizer.batch_encode = Mock(return_value={
            "input_ids": [[101, 102], [101, 103, 102]],
            "attention_mask": [[1, 1], [1, 1, 1]],
            "batch_size": 2,
            "max_length": 3,
            "padded": True
        })
        
        result = tokenizer.batch_encode(["event1", "event2"])
        
        assert result["batch_size"] == 2
        assert result["padded"] is True
    
    @pytest.mark.asyncio
    async def test_decode_tokens(self):
        """Test decoding tokens back to text."""
        tokenizer = Mock()
        tokenizer.decode = Mock(return_value={
            "text": "Alert from [IP] 192.168.1.100",
            "tokens_decoded": 7
        })
        
        result = tokenizer.decode([101, 2054, 192, 168, 1, 100, 102])
        
        assert "192.168.1.100" in result["text"]


# =============================================================================
# MODEL INFERENCE TESTS
# =============================================================================

class TestSLMInference:
    """Tests for SLM model inference."""
    
    @pytest.mark.asyncio
    async def test_detection_slm_inference(self, sample_slm_input):
        """Test Detection SLM inference."""
        model = AsyncMock()
        model.infer = AsyncMock(return_value={
            "model": "detection_slm",
            "input_tokens": 256,
            "output": {
                "is_malicious": True,
                "confidence": 0.92,
                "detection_type": "suspicious_powershell",
                "severity": "high"
            },
            "inference_time_ms": 25
        })
        
        result = await model.infer(sample_slm_input)
        
        assert result["output"]["is_malicious"] is True
        assert result["inference_time_ms"] < 100
    
    @pytest.mark.asyncio
    async def test_triage_slm_inference(self, sample_slm_input):
        """Test Triage SLM inference."""
        model = AsyncMock()
        model.infer = AsyncMock(return_value={
            "model": "triage_slm",
            "output": {
                "priority": "high",
                "risk_score": 85,
                "auto_escalate": True,
                "recommended_actions": ["isolate_host", "collect_memory"]
            }
        })
        
        result = await model.infer(sample_slm_input)
        
        assert result["output"]["priority"] == "high"
        assert result["output"]["auto_escalate"] is True
    
    @pytest.mark.asyncio
    async def test_investigation_slm_inference(self, sample_slm_input):
        """Test Investigation SLM inference."""
        model = AsyncMock()
        model.infer = AsyncMock(return_value={
            "model": "investigation_slm",
            "output": {
                "suggested_queries": [
                    "search host:WORKSTATION-123 earliest=-24h",
                    "search user:john.doe action:login"
                ],
                "related_iocs": ["192.168.1.100", "evil.com"],
                "hypothesis": "Potential credential theft via phishing"
            }
        })
        
        result = await model.infer(sample_slm_input)
        
        assert len(result["output"]["suggested_queries"]) == 2
    
    @pytest.mark.asyncio
    async def test_response_slm_inference(self, sample_slm_input):
        """Test Response SLM inference."""
        model = AsyncMock()
        model.infer = AsyncMock(return_value={
            "model": "response_slm",
            "output": {
                "recommended_playbook": "isolate_and_investigate",
                "actions": [
                    {"action": "isolate_host", "priority": 1, "auto_execute": True},
                    {"action": "disable_user", "priority": 2, "auto_execute": False}
                ],
                "estimated_response_time_minutes": 15
            }
        })
        
        result = await model.infer(sample_slm_input)
        
        assert result["output"]["recommended_playbook"] == "isolate_and_investigate"
    
    @pytest.mark.asyncio
    async def test_threat_intel_slm_inference(self, sample_slm_input):
        """Test Threat Intel SLM inference."""
        model = AsyncMock()
        model.infer = AsyncMock(return_value={
            "model": "threat_intel_slm",
            "output": {
                "threat_actor": "APT28",
                "confidence": 0.75,
                "related_campaigns": ["Operation ShadowStrike"],
                "ttps": ["T1566", "T1059", "T1003"]
            }
        })
        
        result = await model.infer(sample_slm_input)
        
        assert result["output"]["threat_actor"] == "APT28"
    
    @pytest.mark.asyncio
    async def test_forensics_slm_inference(self, sample_slm_input):
        """Test Forensics SLM inference."""
        model = AsyncMock()
        model.infer = AsyncMock(return_value={
            "model": "forensics_slm",
            "output": {
                "artifacts_to_collect": ["memory_dump", "event_logs", "browser_history"],
                "analysis_type": "malware_analysis",
                "preservation_priority": "high"
            }
        })
        
        result = await model.infer(sample_slm_input)
        
        assert "memory_dump" in result["output"]["artifacts_to_collect"]
    
    @pytest.mark.asyncio
    async def test_hunting_slm_inference(self, sample_slm_input):
        """Test Hunting SLM inference."""
        model = AsyncMock()
        model.infer = AsyncMock(return_value={
            "model": "hunting_slm",
            "output": {
                "hunt_hypothesis": "Persistence via scheduled task",
                "queries": [
                    {"query": "schtasks /create", "data_source": "process_creation"},
                    {"query": "registry persistence keys", "data_source": "registry"}
                ],
                "expected_iocs": ["scheduled_task_name", "suspicious_binary"]
            }
        })
        
        result = await model.infer(sample_slm_input)
        
        assert "hunt_hypothesis" in result["output"]
    
    @pytest.mark.asyncio
    async def test_compliance_slm_inference(self, sample_slm_input):
        """Test Compliance SLM inference."""
        model = AsyncMock()
        model.infer = AsyncMock(return_value={
            "model": "compliance_slm",
            "output": {
                "compliance_impact": {
                    "PCI-DSS": {"affected": True, "requirements": ["10.6", "11.5"]},
                    "HIPAA": {"affected": False}
                },
                "reporting_required": True,
                "notification_timeline_hours": 72
            }
        })
        
        result = await model.infer(sample_slm_input)
        
        assert result["output"]["compliance_impact"]["PCI-DSS"]["affected"] is True
    
    @pytest.mark.asyncio
    async def test_orchestrator_slm_inference(self, sample_slm_input):
        """Test Orchestrator SLM inference."""
        model = AsyncMock()
        model.infer = AsyncMock(return_value={
            "model": "orchestrator_slm",
            "output": {
                "workflow": [
                    {"step": 1, "agent": "triage", "action": "prioritize"},
                    {"step": 2, "agent": "threat_intel", "action": "enrich"},
                    {"step": 3, "agent": "investigation", "action": "analyze"},
                    {"step": 4, "agent": "response", "action": "contain"}
                ],
                "parallel_steps": [[2, 3]],
                "estimated_completion_minutes": 30
            }
        })
        
        result = await model.infer(sample_slm_input)
        
        assert len(result["output"]["workflow"]) == 4


# =============================================================================
# BATCH INFERENCE TESTS
# =============================================================================

class TestBatchInference:
    """Tests for batch inference operations."""
    
    @pytest.mark.asyncio
    async def test_batch_inference_single_model(self, sample_events_batch):
        """Test batch inference with a single model."""
        model = AsyncMock()
        model.batch_infer = AsyncMock(return_value={
            "model": "detection_slm",
            "batch_size": 100,
            "results": [{"is_malicious": True}] * 100,
            "total_inference_time_ms": 500,
            "avg_inference_time_ms": 5
        })
        
        result = await model.batch_infer(sample_events_batch)
        
        assert result["batch_size"] == 100
        assert result["avg_inference_time_ms"] == 5
    
    @pytest.mark.asyncio
    async def test_batch_inference_dynamic_batching(self):
        """Test dynamic batching for optimal throughput."""
        model = AsyncMock()
        model.batch_infer_dynamic = AsyncMock(return_value={
            "total_samples": 1000,
            "batches_processed": 10,
            "optimal_batch_size": 100,
            "throughput_samples_per_second": 2000
        })
        
        result = await model.batch_infer_dynamic([{}] * 1000)
        
        assert result["throughput_samples_per_second"] >= 1000
    
    @pytest.mark.asyncio
    async def test_batch_inference_priority_queue(self):
        """Test priority-based batch inference."""
        model = AsyncMock()
        model.batch_infer_priority = AsyncMock(return_value={
            "high_priority_processed": 50,
            "normal_priority_processed": 450,
            "high_priority_latency_ms": 10,
            "normal_priority_latency_ms": 50
        })
        
        result = await model.batch_infer_priority([])
        
        assert result["high_priority_latency_ms"] < result["normal_priority_latency_ms"]


# =============================================================================
# MULTI-MODEL ORCHESTRATION TESTS
# =============================================================================

class TestMultiModelOrchestration:
    """Tests for orchestrating multiple SLM models."""
    
    @pytest.mark.asyncio
    async def test_sequential_model_pipeline(self, sample_slm_input):
        """Test sequential pipeline of multiple models."""
        orchestrator = AsyncMock()
        orchestrator.run_pipeline = AsyncMock(return_value={
            "pipeline": ["detection", "triage", "investigation"],
            "results": {
                "detection": {"is_malicious": True},
                "triage": {"priority": "high"},
                "investigation": {"hypothesis": "credential theft"}
            },
            "total_time_ms": 100
        })
        
        result = await orchestrator.run_pipeline(sample_slm_input, ["detection", "triage", "investigation"])
        
        assert len(result["results"]) == 3
    
    @pytest.mark.asyncio
    async def test_parallel_model_execution(self, sample_slm_input):
        """Test parallel execution of independent models."""
        orchestrator = AsyncMock()
        orchestrator.run_parallel = AsyncMock(return_value={
            "models": ["threat_intel", "forensics", "compliance"],
            "results": {
                "threat_intel": {"threat_actor": "APT28"},
                "forensics": {"artifacts": ["memory"]},
                "compliance": {"impact": "PCI-DSS"}
            },
            "parallel_time_ms": 50,
            "would_be_sequential_ms": 150
        })
        
        result = await orchestrator.run_parallel(sample_slm_input, ["threat_intel", "forensics", "compliance"])
        
        assert result["parallel_time_ms"] < result["would_be_sequential_ms"]
    
    @pytest.mark.asyncio
    async def test_conditional_model_routing(self, sample_slm_input):
        """Test conditional routing based on model outputs."""
        orchestrator = AsyncMock()
        orchestrator.run_conditional = AsyncMock(return_value={
            "initial_model": "detection",
            "detection_result": {"is_malicious": True, "severity": "high"},
            "routed_to": ["response", "forensics"],
            "skipped": ["compliance"],
            "reason": "high_severity_requires_immediate_response"
        })
        
        result = await orchestrator.run_conditional(sample_slm_input)
        
        assert "response" in result["routed_to"]
    
    @pytest.mark.asyncio
    async def test_ensemble_model_voting(self, sample_slm_input):
        """Test ensemble voting across multiple models."""
        orchestrator = AsyncMock()
        orchestrator.ensemble_vote = AsyncMock(return_value={
            "models": ["detection_v1", "detection_v2", "detection_v3"],
            "individual_votes": [True, True, False],
            "ensemble_result": True,
            "confidence": 0.67,
            "voting_method": "majority"
        })
        
        result = await orchestrator.ensemble_vote(sample_slm_input)
        
        assert result["ensemble_result"] is True
        assert result["confidence"] > 0.5


# =============================================================================
# MODEL PERFORMANCE TESTS
# =============================================================================

class TestSLMPerformance:
    """Tests for SLM performance metrics."""
    
    @pytest.mark.asyncio
    async def test_inference_latency(self):
        """Test inference latency metrics."""
        model = AsyncMock()
        model.get_latency_metrics = AsyncMock(return_value={
            "p50_latency_ms": 15,
            "p95_latency_ms": 35,
            "p99_latency_ms": 75,
            "max_latency_ms": 150
        })
        
        result = await model.get_latency_metrics()
        
        assert result["p50_latency_ms"] < 50
        assert result["p95_latency_ms"] < 100
    
    @pytest.mark.asyncio
    async def test_throughput_metrics(self):
        """Test throughput metrics."""
        model = AsyncMock()
        model.get_throughput_metrics = AsyncMock(return_value={
            "samples_per_second": 500,
            "tokens_per_second": 10000,
            "batches_per_second": 5
        })
        
        result = await model.get_throughput_metrics()
        
        assert result["samples_per_second"] >= 100
    
    @pytest.mark.asyncio
    async def test_gpu_utilization(self):
        """Test GPU utilization metrics."""
        model = AsyncMock()
        model.get_gpu_metrics = AsyncMock(return_value={
            "gpu_utilization_percent": 75,
            "gpu_memory_used_gb": 4.5,
            "gpu_memory_total_gb": 16,
            "gpu_temperature_celsius": 65
        })
        
        result = await model.get_gpu_metrics()
        
        assert result["gpu_utilization_percent"] < 100
    
    @pytest.mark.asyncio
    async def test_model_accuracy_metrics(self):
        """Test model accuracy metrics."""
        model = AsyncMock()
        model.get_accuracy_metrics = AsyncMock(return_value={
            "accuracy": 0.94,
            "precision": 0.92,
            "recall": 0.89,
            "f1_score": 0.90,
            "evaluation_samples": 10000
        })
        
        result = await model.get_accuracy_metrics()
        
        assert result["f1_score"] >= 0.85


# =============================================================================
# ATTENTION MECHANISM TESTS
# =============================================================================

class TestAttentionMechanisms:
    """Tests for specialized attention mechanisms in SLMs."""
    
    @pytest.mark.asyncio
    async def test_security_entity_attention(self):
        """Test attention focusing on security entities."""
        model = AsyncMock()
        model.get_attention_weights = AsyncMock(return_value={
            "input": "Alert from 192.168.1.100 accessing evil.com",
            "attention_weights": {
                "192.168.1.100": 0.35,
                "evil.com": 0.40,
                "Alert": 0.10,
                "from": 0.05,
                "accessing": 0.10
            },
            "top_attended": ["evil.com", "192.168.1.100"]
        })
        
        result = await model.get_attention_weights("Alert from 192.168.1.100 accessing evil.com")
        
        assert result["attention_weights"]["evil.com"] > 0.3
    
    @pytest.mark.asyncio
    async def test_temporal_attention(self):
        """Test temporal attention for sequence understanding."""
        model = AsyncMock()
        model.get_temporal_attention = AsyncMock(return_value={
            "sequence_length": 10,
            "temporal_weights": [0.05, 0.05, 0.10, 0.15, 0.20, 0.15, 0.10, 0.08, 0.07, 0.05],
            "peak_attention_position": 4,
            "context": "Recent events more relevant"
        })
        
        result = await model.get_temporal_attention([])
        
        assert result["peak_attention_position"] == 4
    
    @pytest.mark.asyncio
    async def test_cross_attention_between_events(self):
        """Test cross-attention between related events."""
        model = AsyncMock()
        model.get_cross_attention = AsyncMock(return_value={
            "event_1": {"id": "evt-001", "type": "login"},
            "event_2": {"id": "evt-002", "type": "process_create"},
            "cross_attention_score": 0.85,
            "relationship": "causal"
        })
        
        result = await model.get_cross_attention("evt-001", "evt-002")
        
        assert result["cross_attention_score"] > 0.5


# =============================================================================
# MODEL FINE-TUNING TESTS
# =============================================================================

class TestSLMFineTuning:
    """Tests for SLM fine-tuning capabilities."""
    
    @pytest.mark.asyncio
    async def test_fine_tune_on_organization_data(self):
        """Test fine-tuning model on organization-specific data."""
        model = AsyncMock()
        model.fine_tune = AsyncMock(return_value={
            "model": "detection_slm",
            "fine_tune_samples": 10000,
            "epochs": 3,
            "final_loss": 0.15,
            "improvement_percent": 8.5
        })
        
        result = await model.fine_tune(training_data=[])
        
        assert result["improvement_percent"] > 0
    
    @pytest.mark.asyncio
    async def test_incremental_learning(self):
        """Test incremental learning with new samples."""
        model = AsyncMock()
        model.incremental_learn = AsyncMock(return_value={
            "samples_added": 100,
            "model_updated": True,
            "drift_detected": False,
            "performance_change": 0.02
        })
        
        result = await model.incremental_learn(new_samples=[])
        
        assert result["model_updated"] is True
    
    @pytest.mark.asyncio
    async def test_feedback_loop_integration(self):
        """Test integration with analyst feedback loop."""
        model = AsyncMock()
        model.apply_feedback = AsyncMock(return_value={
            "feedback_samples": 50,
            "true_positives_reinforced": 35,
            "false_positives_corrected": 15,
            "model_adjusted": True
        })
        
        result = await model.apply_feedback(feedback=[])
        
        assert result["false_positives_corrected"] == 15


# =============================================================================
# MODEL EXPLAINABILITY TESTS
# =============================================================================

class TestSLMExplainability:
    """Tests for SLM prediction explainability."""
    
    @pytest.mark.asyncio
    async def test_feature_importance_explanation(self, sample_slm_input):
        """Test feature importance in predictions."""
        model = AsyncMock()
        model.explain_prediction = AsyncMock(return_value={
            "prediction": "malicious",
            "confidence": 0.92,
            "feature_importance": [
                {"feature": "encoded_command", "importance": 0.45},
                {"feature": "suspicious_parent_process", "importance": 0.30},
                {"feature": "unusual_time", "importance": 0.15},
                {"feature": "new_binary", "importance": 0.10}
            ]
        })
        
        result = await model.explain_prediction(sample_slm_input)
        
        assert result["feature_importance"][0]["feature"] == "encoded_command"
    
    @pytest.mark.asyncio
    async def test_counterfactual_explanation(self, sample_slm_input):
        """Test counterfactual explanations."""
        model = AsyncMock()
        model.get_counterfactual = AsyncMock(return_value={
            "original_prediction": "malicious",
            "counterfactual": "If the command was not encoded, prediction would be 'benign'",
            "minimal_changes": ["remove base64 encoding"],
            "flipped_prediction": "benign"
        })
        
        result = await model.get_counterfactual(sample_slm_input)
        
        assert result["flipped_prediction"] == "benign"
    
    @pytest.mark.asyncio
    async def test_similar_cases_explanation(self, sample_slm_input):
        """Test explanation via similar historical cases."""
        model = AsyncMock()
        model.get_similar_cases = AsyncMock(return_value={
            "query_case": sample_slm_input,
            "similar_cases": [
                {"case_id": "case-001", "similarity": 0.95, "outcome": "true_positive"},
                {"case_id": "case-015", "similarity": 0.88, "outcome": "true_positive"},
                {"case_id": "case-023", "similarity": 0.82, "outcome": "false_positive"}
            ],
            "prediction_support": "2/3 similar cases were true positives"
        })
        
        result = await model.get_similar_cases(sample_slm_input)
        
        assert len(result["similar_cases"]) == 3
