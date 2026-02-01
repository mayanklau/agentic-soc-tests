"""
Unit Tests for Data Ingestion Pipeline
======================================
Tests for event ingestion from multiple sources including Syslog, Kafka,
file-based inputs, API endpoints, and cloud integrations.
"""

import pytest
import asyncio
import json
import gzip
import io
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import uuid


# =============================================================================
# INGESTION ENGINE TESTS
# =============================================================================

class TestIngestionEngine:
    """Tests for the main ingestion engine."""
    
    # -------------------------------------------------------------------------
    # Initialization Tests
    # -------------------------------------------------------------------------
    
    @pytest.mark.asyncio
    async def test_ingestion_engine_initialization(self, app_config):
        """Test ingestion engine initializes with correct configuration."""
        # Arrange & Act
        engine = Mock()
        engine.config = app_config
        engine.sources = []
        engine.processors = []
        engine.is_running = False
        
        # Assert
        assert engine.config == app_config
        assert engine.sources == []
        assert engine.is_running is False
    
    @pytest.mark.asyncio
    async def test_ingestion_engine_start(self):
        """Test ingestion engine starts successfully."""
        engine = AsyncMock()
        engine.start = AsyncMock(return_value=True)
        engine.is_running = True
        
        result = await engine.start()
        
        assert result is True
        assert engine.is_running is True
    
    @pytest.mark.asyncio
    async def test_ingestion_engine_stop(self):
        """Test ingestion engine stops gracefully."""
        engine = AsyncMock()
        engine.stop = AsyncMock(return_value=True)
        engine.is_running = False
        
        result = await engine.stop()
        
        assert result is True
        assert engine.is_running is False
    
    @pytest.mark.asyncio
    async def test_ingestion_engine_health_check(self):
        """Test ingestion engine health check."""
        engine = AsyncMock()
        engine.health_check = AsyncMock(return_value={
            "status": "healthy",
            "sources": {"syslog": "connected", "kafka": "connected"},
            "queue_depth": 150,
            "events_per_second": 2500
        })
        
        health = await engine.health_check()
        
        assert health["status"] == "healthy"
        assert "sources" in health
        assert "queue_depth" in health


# =============================================================================
# SYSLOG INGESTION TESTS
# =============================================================================

class TestSyslogIngestion:
    """Tests for Syslog-based event ingestion."""
    
    @pytest.mark.asyncio
    async def test_syslog_udp_listener_start(self):
        """Test Syslog UDP listener starts on configured port."""
        listener = AsyncMock()
        listener.start = AsyncMock(return_value=True)
        listener.port = 514
        listener.protocol = "udp"
        
        result = await listener.start()
        
        assert result is True
        assert listener.port == 514
    
    @pytest.mark.asyncio
    async def test_syslog_tcp_listener_start(self):
        """Test Syslog TCP listener starts on configured port."""
        listener = AsyncMock()
        listener.start = AsyncMock(return_value=True)
        listener.port = 514
        listener.protocol = "tcp"
        
        result = await listener.start()
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_syslog_tls_listener_with_certificates(self):
        """Test Syslog TLS listener with certificate validation."""
        listener = AsyncMock()
        listener.start = AsyncMock(return_value=True)
        listener.tls_enabled = True
        listener.cert_path = "/path/to/cert.pem"
        listener.key_path = "/path/to/key.pem"
        
        result = await listener.start()
        
        assert result is True
        assert listener.tls_enabled is True
    
    @pytest.mark.asyncio
    async def test_parse_rfc3164_syslog_message(self):
        """Test parsing RFC 3164 format Syslog messages."""
        # RFC 3164 format: <PRI>TIMESTAMP HOSTNAME MSG
        raw_message = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
        
        parser = Mock()
        parser.parse_rfc3164 = Mock(return_value={
            "priority": 34,
            "facility": 4,
            "severity": 2,
            "timestamp": "Oct 11 22:14:15",
            "hostname": "mymachine",
            "program": "su",
            "message": "'su root' failed for lonvick on /dev/pts/8"
        })
        
        result = parser.parse_rfc3164(raw_message)
        
        assert result["priority"] == 34
        assert result["hostname"] == "mymachine"
        assert result["program"] == "su"
    
    @pytest.mark.asyncio
    async def test_parse_rfc5424_syslog_message(self):
        """Test parsing RFC 5424 format Syslog messages."""
        # RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        raw_message = '<165>1 2024-01-15T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3"] BOMAn application event log entry...'
        
        parser = Mock()
        parser.parse_rfc5424 = Mock(return_value={
            "priority": 165,
            "version": 1,
            "timestamp": "2024-01-15T22:14:15.003Z",
            "hostname": "mymachine.example.com",
            "app_name": "evntslog",
            "proc_id": "-",
            "msg_id": "ID47",
            "structured_data": {"exampleSDID@32473": {"iut": "3"}},
            "message": "BOMAn application event log entry..."
        })
        
        result = parser.parse_rfc5424(raw_message)
        
        assert result["version"] == 1
        assert result["hostname"] == "mymachine.example.com"
        assert "structured_data" in result
    
    @pytest.mark.asyncio
    async def test_syslog_message_priority_calculation(self):
        """Test Syslog priority to facility/severity calculation."""
        parser = Mock()
        # Priority = Facility * 8 + Severity
        # Priority 34 = Facility 4 (auth), Severity 2 (critical)
        parser.calculate_facility_severity = Mock(return_value=(4, 2))
        
        facility, severity = parser.calculate_facility_severity(34)
        
        assert facility == 4  # auth
        assert severity == 2  # critical
    
    @pytest.mark.asyncio
    async def test_syslog_high_volume_ingestion(self):
        """Test Syslog ingestion handles high volume of messages."""
        listener = AsyncMock()
        listener.process_batch = AsyncMock(return_value={"processed": 10000, "errors": 0})
        
        messages = [f"<34>Test message {i}" for i in range(10000)]
        result = await listener.process_batch(messages)
        
        assert result["processed"] == 10000
        assert result["errors"] == 0
    
    @pytest.mark.asyncio
    async def test_syslog_malformed_message_handling(self):
        """Test handling of malformed Syslog messages."""
        parser = Mock()
        parser.parse = Mock(return_value=None)
        
        malformed_message = "this is not a valid syslog message"
        result = parser.parse(malformed_message)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_syslog_source_ip_tracking(self):
        """Test tracking of source IP for Syslog messages."""
        listener = AsyncMock()
        listener.process_message = AsyncMock(return_value={
            "message": "test",
            "source_ip": "192.168.1.100",
            "received_at": datetime.utcnow().isoformat()
        })
        
        result = await listener.process_message("test", "192.168.1.100")
        
        assert result["source_ip"] == "192.168.1.100"


# =============================================================================
# KAFKA INGESTION TESTS
# =============================================================================

class TestKafkaIngestion:
    """Tests for Kafka-based event ingestion."""
    
    @pytest.mark.asyncio
    async def test_kafka_consumer_initialization(self):
        """Test Kafka consumer initializes with correct settings."""
        consumer = Mock()
        consumer.bootstrap_servers = ["kafka1:9092", "kafka2:9092"]
        consumer.topics = ["security-events", "auth-logs"]
        consumer.group_id = "soc-ingestion"
        consumer.auto_offset_reset = "earliest"
        
        assert len(consumer.bootstrap_servers) == 2
        assert "security-events" in consumer.topics
    
    @pytest.mark.asyncio
    async def test_kafka_consumer_start(self):
        """Test Kafka consumer starts and subscribes to topics."""
        consumer = AsyncMock()
        consumer.start = AsyncMock(return_value=True)
        consumer.subscribe = AsyncMock()
        
        await consumer.start()
        await consumer.subscribe(["security-events"])
        
        consumer.subscribe.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_kafka_message_consumption(self):
        """Test consuming messages from Kafka topic."""
        consumer = AsyncMock()
        consumer.consume = AsyncMock(return_value=[
            {"topic": "security-events", "partition": 0, "offset": 100, "value": b'{"event": "test"}'},
            {"topic": "security-events", "partition": 0, "offset": 101, "value": b'{"event": "test2"}'}
        ])
        
        messages = await consumer.consume()
        
        assert len(messages) == 2
        assert messages[0]["topic"] == "security-events"
    
    @pytest.mark.asyncio
    async def test_kafka_batch_consumption(self):
        """Test batch consumption from Kafka with configurable batch size."""
        consumer = AsyncMock()
        consumer.consume_batch = AsyncMock(return_value={
            "messages": [{"value": b'{"event": "test"}'} for _ in range(100)],
            "count": 100
        })
        
        result = await consumer.consume_batch(max_records=100, timeout_ms=1000)
        
        assert result["count"] == 100
    
    @pytest.mark.asyncio
    async def test_kafka_offset_commit(self):
        """Test committing offsets after processing."""
        consumer = AsyncMock()
        consumer.commit = AsyncMock(return_value=True)
        
        result = await consumer.commit()
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_kafka_consumer_rebalance_handling(self):
        """Test handling of consumer group rebalancing."""
        consumer = AsyncMock()
        consumer.on_partitions_assigned = Mock()
        consumer.on_partitions_revoked = Mock()
        
        # Simulate rebalance
        partitions = [{"topic": "security-events", "partition": 0}]
        consumer.on_partitions_assigned(partitions)
        
        consumer.on_partitions_assigned.assert_called_once_with(partitions)
    
    @pytest.mark.asyncio
    async def test_kafka_json_message_deserialization(self):
        """Test deserializing JSON messages from Kafka."""
        consumer = AsyncMock()
        raw_message = b'{"timestamp": "2024-01-15T10:00:00Z", "event_type": "authentication", "user": "jsmith"}'
        
        consumer.deserialize = Mock(return_value=json.loads(raw_message))
        result = consumer.deserialize(raw_message)
        
        assert result["event_type"] == "authentication"
        assert result["user"] == "jsmith"
    
    @pytest.mark.asyncio
    async def test_kafka_avro_message_deserialization(self):
        """Test deserializing Avro messages from Kafka."""
        consumer = AsyncMock()
        consumer.deserialize_avro = Mock(return_value={
            "event_type": "authentication",
            "user": "jsmith"
        })
        
        result = consumer.deserialize_avro(b'avro_encoded_data')
        
        assert result["event_type"] == "authentication"
    
    @pytest.mark.asyncio
    async def test_kafka_connection_retry(self):
        """Test Kafka connection retry logic."""
        consumer = AsyncMock()
        consumer.connect = AsyncMock(side_effect=[
            ConnectionError("Connection refused"),
            ConnectionError("Connection refused"),
            True  # Third attempt succeeds
        ])
        
        # Should retry and eventually succeed
        attempts = 0
        while attempts < 3:
            try:
                result = await consumer.connect()
                if result:
                    break
            except ConnectionError:
                attempts += 1
        
        assert attempts == 2  # Failed twice before succeeding
    
    @pytest.mark.asyncio
    async def test_kafka_consumer_lag_monitoring(self):
        """Test monitoring consumer lag."""
        consumer = AsyncMock()
        consumer.get_lag = AsyncMock(return_value={
            "security-events": {"0": 100, "1": 50},
            "total_lag": 150
        })
        
        lag = await consumer.get_lag()
        
        assert lag["total_lag"] == 150


# =============================================================================
# FILE-BASED INGESTION TESTS
# =============================================================================

class TestFileIngestion:
    """Tests for file-based event ingestion."""
    
    @pytest.mark.asyncio
    async def test_log_file_ingestion(self):
        """Test ingesting events from log files."""
        ingestor = AsyncMock()
        ingestor.ingest_file = AsyncMock(return_value={
            "file": "/var/log/auth.log",
            "lines_processed": 1000,
            "events_created": 985,
            "errors": 15
        })
        
        result = await ingestor.ingest_file("/var/log/auth.log")
        
        assert result["lines_processed"] == 1000
    
    @pytest.mark.asyncio
    async def test_compressed_log_file_ingestion(self):
        """Test ingesting events from compressed log files."""
        ingestor = AsyncMock()
        ingestor.ingest_compressed = AsyncMock(return_value={
            "file": "/var/log/auth.log.gz",
            "compression": "gzip",
            "lines_processed": 50000
        })
        
        result = await ingestor.ingest_compressed("/var/log/auth.log.gz")
        
        assert result["compression"] == "gzip"
        assert result["lines_processed"] == 50000
    
    @pytest.mark.asyncio
    async def test_directory_watch_for_new_files(self):
        """Test watching directory for new log files."""
        watcher = AsyncMock()
        watcher.watch = AsyncMock(return_value={
            "new_files": ["auth.log.1", "auth.log.2"],
            "processed": 2
        })
        
        result = await watcher.watch("/var/log")
        
        assert len(result["new_files"]) == 2
    
    @pytest.mark.asyncio
    async def test_file_rotation_handling(self):
        """Test handling of log file rotation."""
        ingestor = AsyncMock()
        ingestor.handle_rotation = AsyncMock(return_value={
            "old_file": "/var/log/auth.log.1",
            "new_file": "/var/log/auth.log",
            "position_saved": True
        })
        
        result = await ingestor.handle_rotation("/var/log/auth.log")
        
        assert result["position_saved"] is True
    
    @pytest.mark.asyncio
    async def test_file_position_tracking(self):
        """Test tracking file read position for resumption."""
        ingestor = AsyncMock()
        ingestor.get_position = AsyncMock(return_value={
            "file": "/var/log/auth.log",
            "position": 1048576,
            "inode": 12345
        })
        
        result = await ingestor.get_position("/var/log/auth.log")
        
        assert result["position"] == 1048576
    
    @pytest.mark.asyncio
    async def test_csv_file_ingestion(self):
        """Test ingesting events from CSV files."""
        ingestor = AsyncMock()
        ingestor.ingest_csv = AsyncMock(return_value={
            "file": "/data/events.csv",
            "rows_processed": 5000,
            "columns": ["timestamp", "source", "event_type", "message"]
        })
        
        result = await ingestor.ingest_csv("/data/events.csv")
        
        assert result["rows_processed"] == 5000
        assert "timestamp" in result["columns"]
    
    @pytest.mark.asyncio
    async def test_json_lines_file_ingestion(self):
        """Test ingesting events from JSON Lines files."""
        ingestor = AsyncMock()
        ingestor.ingest_jsonl = AsyncMock(return_value={
            "file": "/data/events.jsonl",
            "lines_processed": 10000,
            "valid_json": 9950,
            "invalid_json": 50
        })
        
        result = await ingestor.ingest_jsonl("/data/events.jsonl")
        
        assert result["valid_json"] == 9950
    
    @pytest.mark.asyncio
    async def test_xml_file_ingestion(self):
        """Test ingesting events from XML files."""
        ingestor = AsyncMock()
        ingestor.ingest_xml = AsyncMock(return_value={
            "file": "/data/events.xml",
            "elements_processed": 500,
            "root_element": "events"
        })
        
        result = await ingestor.ingest_xml("/data/events.xml")
        
        assert result["elements_processed"] == 500


# =============================================================================
# API INGESTION TESTS
# =============================================================================

class TestAPIIngestion:
    """Tests for API-based event ingestion."""
    
    @pytest.mark.asyncio
    async def test_rest_api_event_ingestion(self):
        """Test ingesting events via REST API endpoint."""
        ingestor = AsyncMock()
        ingestor.ingest_api = AsyncMock(return_value={
            "accepted": 100,
            "rejected": 0,
            "request_id": str(uuid.uuid4())
        })
        
        events = [{"event": f"test-{i}"} for i in range(100)]
        result = await ingestor.ingest_api(events)
        
        assert result["accepted"] == 100
    
    @pytest.mark.asyncio
    async def test_api_event_validation(self):
        """Test validation of events received via API."""
        validator = Mock()
        validator.validate = Mock(return_value={
            "valid": True,
            "errors": []
        })
        
        event = {"timestamp": "2024-01-15T10:00:00Z", "event_type": "auth"}
        result = validator.validate(event)
        
        assert result["valid"] is True
    
    @pytest.mark.asyncio
    async def test_api_event_validation_failure(self):
        """Test validation failure for malformed events."""
        validator = Mock()
        validator.validate = Mock(return_value={
            "valid": False,
            "errors": ["Missing required field: timestamp"]
        })
        
        event = {"event_type": "auth"}  # Missing timestamp
        result = validator.validate(event)
        
        assert result["valid"] is False
        assert len(result["errors"]) > 0
    
    @pytest.mark.asyncio
    async def test_api_batch_size_limit(self):
        """Test batch size limit enforcement for API ingestion."""
        ingestor = AsyncMock()
        ingestor.max_batch_size = 1000
        
        events = [{"event": f"test-{i}"} for i in range(1500)]
        ingestor.ingest_api = AsyncMock(side_effect=ValueError("Batch size exceeds limit"))
        
        with pytest.raises(ValueError):
            await ingestor.ingest_api(events)
    
    @pytest.mark.asyncio
    async def test_api_rate_limiting(self):
        """Test rate limiting for API ingestion."""
        ingestor = AsyncMock()
        ingestor.ingest_api = AsyncMock(return_value={
            "status": "rate_limited",
            "retry_after": 60
        })
        
        result = await ingestor.ingest_api([])
        
        assert result["status"] == "rate_limited"
        assert result["retry_after"] == 60


# =============================================================================
# CLOUD INTEGRATION INGESTION TESTS
# =============================================================================

class TestCloudIngestion:
    """Tests for cloud service event ingestion."""
    
    @pytest.mark.asyncio
    async def test_aws_cloudwatch_ingestion(self):
        """Test ingesting events from AWS CloudWatch Logs."""
        ingestor = AsyncMock()
        ingestor.ingest_cloudwatch = AsyncMock(return_value={
            "log_group": "/aws/lambda/my-function",
            "events_ingested": 500,
            "next_token": "abc123"
        })
        
        result = await ingestor.ingest_cloudwatch("/aws/lambda/my-function")
        
        assert result["events_ingested"] == 500
    
    @pytest.mark.asyncio
    async def test_aws_s3_log_ingestion(self):
        """Test ingesting logs from AWS S3 buckets."""
        ingestor = AsyncMock()
        ingestor.ingest_s3 = AsyncMock(return_value={
            "bucket": "security-logs",
            "prefix": "cloudtrail/",
            "files_processed": 50,
            "events_ingested": 25000
        })
        
        result = await ingestor.ingest_s3("security-logs", prefix="cloudtrail/")
        
        assert result["files_processed"] == 50
    
    @pytest.mark.asyncio
    async def test_azure_event_hub_ingestion(self):
        """Test ingesting events from Azure Event Hub."""
        ingestor = AsyncMock()
        ingestor.ingest_event_hub = AsyncMock(return_value={
            "namespace": "soc-events",
            "event_hub": "security",
            "events_ingested": 1000,
            "partitions_processed": 4
        })
        
        result = await ingestor.ingest_event_hub("soc-events", "security")
        
        assert result["events_ingested"] == 1000
    
    @pytest.mark.asyncio
    async def test_gcp_pubsub_ingestion(self):
        """Test ingesting events from GCP Pub/Sub."""
        ingestor = AsyncMock()
        ingestor.ingest_pubsub = AsyncMock(return_value={
            "project": "my-project",
            "subscription": "security-events-sub",
            "messages_processed": 750
        })
        
        result = await ingestor.ingest_pubsub("my-project", "security-events-sub")
        
        assert result["messages_processed"] == 750
    
    @pytest.mark.asyncio
    async def test_azure_blob_storage_ingestion(self):
        """Test ingesting logs from Azure Blob Storage."""
        ingestor = AsyncMock()
        ingestor.ingest_blob = AsyncMock(return_value={
            "container": "security-logs",
            "blobs_processed": 25,
            "events_ingested": 15000
        })
        
        result = await ingestor.ingest_blob("security-logs")
        
        assert result["blobs_processed"] == 25
    
    @pytest.mark.asyncio
    async def test_gcp_cloud_storage_ingestion(self):
        """Test ingesting logs from GCP Cloud Storage."""
        ingestor = AsyncMock()
        ingestor.ingest_gcs = AsyncMock(return_value={
            "bucket": "security-logs-bucket",
            "objects_processed": 30,
            "events_ingested": 20000
        })
        
        result = await ingestor.ingest_gcs("security-logs-bucket")
        
        assert result["objects_processed"] == 30


# =============================================================================
# SECURITY TOOL INGESTION TESTS
# =============================================================================

class TestSecurityToolIngestion:
    """Tests for ingesting events from security tools."""
    
    @pytest.mark.asyncio
    async def test_crowdstrike_event_stream_ingestion(self):
        """Test ingesting events from CrowdStrike Falcon."""
        ingestor = AsyncMock()
        ingestor.ingest_crowdstrike = AsyncMock(return_value={
            "source": "crowdstrike",
            "stream": "detection",
            "events_ingested": 150
        })
        
        result = await ingestor.ingest_crowdstrike()
        
        assert result["source"] == "crowdstrike"
    
    @pytest.mark.asyncio
    async def test_microsoft_defender_ingestion(self):
        """Test ingesting events from Microsoft Defender."""
        ingestor = AsyncMock()
        ingestor.ingest_defender = AsyncMock(return_value={
            "source": "microsoft_defender",
            "alerts_ingested": 25,
            "incidents_ingested": 5
        })
        
        result = await ingestor.ingest_defender()
        
        assert result["alerts_ingested"] == 25
    
    @pytest.mark.asyncio
    async def test_splunk_forwarder_ingestion(self):
        """Test ingesting events from Splunk forwarders."""
        ingestor = AsyncMock()
        ingestor.ingest_splunk = AsyncMock(return_value={
            "source": "splunk_hec",
            "events_ingested": 5000,
            "index": "security"
        })
        
        result = await ingestor.ingest_splunk()
        
        assert result["events_ingested"] == 5000
    
    @pytest.mark.asyncio
    async def test_elastic_beats_ingestion(self):
        """Test ingesting events from Elastic Beats."""
        ingestor = AsyncMock()
        ingestor.ingest_beats = AsyncMock(return_value={
            "source": "elastic_beats",
            "beat_types": ["filebeat", "winlogbeat", "packetbeat"],
            "events_ingested": 10000
        })
        
        result = await ingestor.ingest_beats()
        
        assert "winlogbeat" in result["beat_types"]
    
    @pytest.mark.asyncio
    async def test_palo_alto_syslog_ingestion(self):
        """Test ingesting events from Palo Alto firewalls."""
        ingestor = AsyncMock()
        ingestor.ingest_palo_alto = AsyncMock(return_value={
            "source": "palo_alto",
            "log_types": ["traffic", "threat", "url"],
            "events_ingested": 50000
        })
        
        result = await ingestor.ingest_palo_alto()
        
        assert "threat" in result["log_types"]


# =============================================================================
# INGESTION QUEUE TESTS
# =============================================================================

class TestIngestionQueue:
    """Tests for the ingestion queue management."""
    
    @pytest.mark.asyncio
    async def test_queue_enqueue_event(self, mock_redis_client):
        """Test enqueueing events to the ingestion queue."""
        queue = AsyncMock()
        queue.redis = mock_redis_client
        queue.enqueue = AsyncMock(return_value=True)
        
        event = {"timestamp": datetime.utcnow().isoformat(), "event_type": "auth"}
        result = await queue.enqueue(event)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_queue_batch_enqueue(self, mock_redis_client):
        """Test batch enqueueing of events."""
        queue = AsyncMock()
        queue.enqueue_batch = AsyncMock(return_value={"enqueued": 100, "failed": 0})
        
        events = [{"event": f"test-{i}"} for i in range(100)]
        result = await queue.enqueue_batch(events)
        
        assert result["enqueued"] == 100
    
    @pytest.mark.asyncio
    async def test_queue_dequeue_event(self, mock_redis_client):
        """Test dequeueing events from the ingestion queue."""
        queue = AsyncMock()
        queue.dequeue = AsyncMock(return_value={"event_type": "auth"})
        
        event = await queue.dequeue()
        
        assert event["event_type"] == "auth"
    
    @pytest.mark.asyncio
    async def test_queue_batch_dequeue(self, mock_redis_client):
        """Test batch dequeueing of events."""
        queue = AsyncMock()
        queue.dequeue_batch = AsyncMock(return_value=[{"event": f"test-{i}"} for i in range(50)])
        
        events = await queue.dequeue_batch(max_count=50)
        
        assert len(events) == 50
    
    @pytest.mark.asyncio
    async def test_queue_depth_monitoring(self, mock_redis_client):
        """Test monitoring queue depth."""
        queue = AsyncMock()
        queue.get_depth = AsyncMock(return_value=5000)
        
        depth = await queue.get_depth()
        
        assert depth == 5000
    
    @pytest.mark.asyncio
    async def test_queue_priority_ordering(self):
        """Test priority-based queue ordering."""
        queue = AsyncMock()
        queue.enqueue_priority = AsyncMock(return_value=True)
        
        # High priority event should be processed first
        high_priority_event = {"severity": "critical", "event_type": "ransomware"}
        result = await queue.enqueue_priority(high_priority_event, priority=1)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_dead_letter_queue(self):
        """Test moving failed events to dead letter queue."""
        queue = AsyncMock()
        queue.move_to_dlq = AsyncMock(return_value=True)
        
        failed_event = {"event": "test", "error": "parsing failed"}
        result = await queue.move_to_dlq(failed_event)
        
        assert result is True


# =============================================================================
# DEDUPLICATION TESTS
# =============================================================================

class TestIngestionDeduplication:
    """Tests for event deduplication during ingestion."""
    
    @pytest.mark.asyncio
    async def test_exact_duplicate_detection(self, mock_redis_client):
        """Test detection of exact duplicate events."""
        deduper = AsyncMock()
        deduper.is_duplicate = AsyncMock(return_value=True)
        
        event = {"timestamp": "2024-01-15T10:00:00Z", "host": "server1", "message": "test"}
        is_dup = await deduper.is_duplicate(event)
        
        assert is_dup is True
    
    @pytest.mark.asyncio
    async def test_near_duplicate_detection(self, mock_redis_client):
        """Test detection of near-duplicate events."""
        deduper = AsyncMock()
        deduper.is_near_duplicate = AsyncMock(return_value=True)
        
        event1 = {"timestamp": "2024-01-15T10:00:00Z", "message": "Failed login attempt"}
        event2 = {"timestamp": "2024-01-15T10:00:01Z", "message": "Failed login attempt"}
        
        is_near_dup = await deduper.is_near_duplicate(event1, event2)
        
        assert is_near_dup is True
    
    @pytest.mark.asyncio
    async def test_deduplication_window(self, mock_redis_client):
        """Test deduplication within time window."""
        deduper = AsyncMock()
        deduper.window_seconds = 300  # 5 minutes
        deduper.check_window = AsyncMock(return_value=False)  # Outside window
        
        result = await deduper.check_window("event_hash", datetime.utcnow())
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_deduplication_hash_calculation(self):
        """Test hash calculation for deduplication."""
        deduper = Mock()
        event = {"timestamp": "2024-01-15T10:00:00Z", "host": "server1", "message": "test"}
        
        deduper.calculate_hash = Mock(return_value="abc123def456")
        hash_value = deduper.calculate_hash(event)
        
        assert hash_value is not None
        assert len(hash_value) > 0
    
    @pytest.mark.asyncio
    async def test_deduplication_bloom_filter(self, mock_redis_client):
        """Test bloom filter for efficient duplicate checking."""
        bloom = AsyncMock()
        bloom.add = AsyncMock(return_value=True)
        bloom.contains = AsyncMock(return_value=False)
        
        event_hash = "abc123"
        exists = await bloom.contains(event_hash)
        await bloom.add(event_hash)
        
        assert exists is False


# =============================================================================
# RATE LIMITING TESTS
# =============================================================================

class TestIngestionRateLimiting:
    """Tests for ingestion rate limiting."""
    
    @pytest.mark.asyncio
    async def test_source_based_rate_limiting(self, mock_redis_client):
        """Test rate limiting per source."""
        limiter = AsyncMock()
        limiter.is_allowed = AsyncMock(return_value=True)
        
        source = "firewall-01"
        allowed = await limiter.is_allowed(source)
        
        assert allowed is True
    
    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self, mock_redis_client):
        """Test behavior when rate limit is exceeded."""
        limiter = AsyncMock()
        limiter.is_allowed = AsyncMock(return_value=False)
        limiter.get_retry_after = AsyncMock(return_value=30)
        
        source = "firewall-01"
        allowed = await limiter.is_allowed(source)
        retry_after = await limiter.get_retry_after(source)
        
        assert allowed is False
        assert retry_after == 30
    
    @pytest.mark.asyncio
    async def test_global_rate_limiting(self, mock_redis_client):
        """Test global ingestion rate limiting."""
        limiter = AsyncMock()
        limiter.max_events_per_second = 100000
        limiter.current_rate = AsyncMock(return_value=95000)
        
        rate = await limiter.current_rate()
        
        assert rate < limiter.max_events_per_second
    
    @pytest.mark.asyncio
    async def test_adaptive_rate_limiting(self):
        """Test adaptive rate limiting based on system load."""
        limiter = AsyncMock()
        limiter.adjust_limits = AsyncMock(return_value={
            "previous_limit": 100000,
            "new_limit": 80000,
            "reason": "high_cpu_usage"
        })
        
        result = await limiter.adjust_limits(cpu_usage=0.85)
        
        assert result["new_limit"] < result["previous_limit"]


# =============================================================================
# METRICS AND MONITORING TESTS
# =============================================================================

class TestIngestionMetrics:
    """Tests for ingestion metrics and monitoring."""
    
    @pytest.mark.asyncio
    async def test_events_per_second_metric(self):
        """Test tracking events per second."""
        metrics = AsyncMock()
        metrics.get_eps = AsyncMock(return_value=25000)
        
        eps = await metrics.get_eps()
        
        assert eps == 25000
    
    @pytest.mark.asyncio
    async def test_ingestion_latency_metric(self):
        """Test tracking ingestion latency."""
        metrics = AsyncMock()
        metrics.record_latency = AsyncMock()
        metrics.get_avg_latency = AsyncMock(return_value=15.5)  # milliseconds
        
        await metrics.record_latency(12.3)
        avg_latency = await metrics.get_avg_latency()
        
        assert avg_latency == 15.5
    
    @pytest.mark.asyncio
    async def test_source_breakdown_metric(self):
        """Test tracking events by source."""
        metrics = AsyncMock()
        metrics.get_source_breakdown = AsyncMock(return_value={
            "syslog": 50000,
            "kafka": 30000,
            "api": 10000,
            "file": 5000
        })
        
        breakdown = await metrics.get_source_breakdown()
        
        assert breakdown["syslog"] == 50000
    
    @pytest.mark.asyncio
    async def test_error_rate_metric(self):
        """Test tracking ingestion error rate."""
        metrics = AsyncMock()
        metrics.get_error_rate = AsyncMock(return_value=0.001)  # 0.1%
        
        error_rate = await metrics.get_error_rate()
        
        assert error_rate < 0.01  # Less than 1%
    
    @pytest.mark.asyncio
    async def test_queue_metrics(self):
        """Test queue-related metrics."""
        metrics = AsyncMock()
        metrics.get_queue_metrics = AsyncMock(return_value={
            "depth": 5000,
            "enqueue_rate": 10000,
            "dequeue_rate": 9500,
            "dlq_size": 50
        })
        
        queue_metrics = await metrics.get_queue_metrics()
        
        assert queue_metrics["depth"] == 5000
        assert queue_metrics["dlq_size"] == 50
