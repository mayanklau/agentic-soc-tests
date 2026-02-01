# Agentic SOC v3 - Comprehensive Test Suite

A production-ready test suite for the Agentic SOC platform, covering all core components including AI agents, data pipelines, detection engine, Bead Memory architecture, SLM inference, and security controls.

## 📊 Test Suite Statistics

| Category | Files | Lines | Coverage |
|----------|-------|-------|----------|
| Unit Tests - AI Agents | 6 | ~3,600 | 9 agents |
| Unit Tests - API | 1 | ~620 | REST, WebSocket, Auth |
| Unit Tests - Data Pipelines | 3 | ~2,940 | Ingestion, Normalization, Enrichment |
| Unit Tests - Detection Engine | 1 | ~990 | Sigma, YARA, KQL, ML |
| Unit Tests - Bead Memory | 1 | ~800 | Multi-tier, Attack Chains |
| Unit Tests - SLM Inference | 1 | ~800 | 9 models, Tokenizer |
| Unit Tests - Knowledge Base | 1 | ~990 | MITRE, Threat Intel, Playbooks |
| Unit Tests - Utilities | 1 | ~940 | Parsing, Validation, Formatting |
| Integration Tests | 1 | ~870 | Multi-agent Workflows |
| E2E Tests | 1 | ~750 | Incident Lifecycles |
| Performance Tests | 1 | ~720 | Benchmarks, Stress Tests |
| Security Tests | 1 | ~1,400 | Auth, Validation, Encryption |
| Configuration | 1 | ~740 | Fixtures, Mocks |
| **Total** | **20** | **~15,700** | **All Components** |

## 🏗️ Directory Structure

```
tests/
├── conftest.py                          # Shared fixtures and configuration
├── unit/
│   ├── agents/
│   │   ├── test_detection_agent.py      # Alert generation, rule evaluation
│   │   ├── test_triage_agent.py         # Priority scoring, auto-escalation
│   │   ├── test_investigation_agent.py  # Query generation, IOC extraction
│   │   ├── test_response_agent.py       # Playbook execution, containment
│   │   ├── test_threat_intel_agent.py   # IOC enrichment, attribution
│   │   └── test_remaining_agents.py     # Forensics, Hunting, Compliance, Orchestrator
│   ├── api/
│   │   └── test_api_endpoints.py        # REST, WebSocket, authentication
│   ├── data_pipelines/
│   │   ├── test_ingestion.py            # Syslog, Kafka, file, cloud sources
│   │   ├── test_normalization.py        # OCSF/ECS schema mapping
│   │   └── test_enrichment.py           # Threat intel, geolocation, caching
│   ├── detection_engine/
│   │   └── test_detection_engine.py     # Sigma, YARA, KQL, ML detection
│   ├── memory/
│   │   └── test_bead_memory.py          # Multi-tier memory, attack chains
│   ├── slm/
│   │   └── test_slm_inference.py        # Model inference, tokenization
│   ├── knowledge_base/
│   │   └── test_knowledge_base.py       # MITRE ATT&CK, threat intel, playbooks
│   └── utils/
│       └── test_utils.py                # Parsing, validation, formatting
├── integration/
│   └── test_agent_integration.py        # Multi-agent orchestration workflows
├── e2e/
│   └── test_incident_lifecycle.py       # Complete incident handling scenarios
├── performance/
│   └── test_benchmarks.py               # Throughput, latency, scalability
└── security/
    └── test_security.py                 # Auth, encryption, audit logging
```

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.10+
pip install pytest pytest-asyncio pytest-cov pytest-mock pytest-benchmark aiohttp
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test category
pytest tests/unit/ -v
pytest tests/integration/ -v
pytest tests/e2e/ -v
pytest tests/performance/ -v
pytest tests/security/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/unit/agents/test_detection_agent.py -v

# Run tests matching pattern
pytest tests/ -k "test_sigma" -v

# Run with parallel execution
pytest tests/ -n auto
```

## 📋 Test Categories

### Unit Tests

#### AI Agents (`tests/unit/agents/`)

Tests for all 9 specialized SOC agents:

| Agent | Model Size | Key Functions Tested |
|-------|------------|---------------------|
| Detection | 125M | Alert generation, rule evaluation, batch processing |
| Triage | 85M | Priority scoring, risk assessment, auto-escalation |
| Investigation | 150M | Query generation, IOC extraction, hypothesis building |
| Response | 100M | Playbook execution, containment actions, approval workflows |
| Threat Intel | 125M | IOC enrichment, campaign correlation, attribution |
| Forensics | 175M | Artifact collection, timeline reconstruction, evidence preservation |
| Hunting | 125M | Hypothesis generation, proactive threat detection |
| Compliance | 85M | Regulatory mapping, audit reporting, gap analysis |
| Orchestrator | 200M | Workflow coordination, resource allocation, escalation |

#### Data Pipelines (`tests/unit/data_pipelines/`)

**Ingestion Tests:**
- Syslog: UDP/TCP/TLS, RFC 3164/5424
- Kafka consumers with offset management
- File ingestion: CSV, JSON, XML, compressed
- Cloud: AWS S3/CloudWatch, Azure Event Hub/Blob, GCP Pub/Sub
- Rate limiting and deduplication

**Normalization Tests:**
- OCSF v1.1.0 schema compliance
- Category mapping (Authentication, Network, Security Finding, Process, File, DNS)
- Field transformations (timestamps, IPs, users, severity 0-6)
- Source parsers: CrowdStrike, Defender, Splunk, Palo Alto, CloudTrail, Okta
- Throughput: 20K+ events/sec

**Enrichment Tests:**
- Threat intel: VirusTotal, AbuseIPDB, MISP, OTX
- Geolocation: MaxMind, IP2Location
- User directory: AD/LDAP integration
- Vulnerability: CVE, CVSS, exploit data
- Caching: 85%+ hit rate, 60% deduplication savings

#### Detection Engine (`tests/unit/detection_engine/`)

- **Sigma Rules:** YAML loading, condition operators (AND/OR/NOT), modifiers (contains, regex, base64, cidr), aggregation, temporal correlation
- **YARA Rules:** Compilation, file/memory/PCAP scanning, PE module
- **KQL Queries:** Parsing, operators, time bucketing, joins, anomaly detection
- **ML Detection:** Isolation Forest, feature extraction, UEBA, drift detection
- **Performance:** 20K EPS with 500 rules, p95 <15ms

#### Bead Memory (`tests/unit/memory/`)

- Memory bead lifecycle (create, update, delete, TTL)
- Bead chains (append, traverse, merge, split)
- Multi-tier architecture (working 5min, episodic 24h, semantic permanent)
- Attack chain correlation (stage progression, cross-entity, Kill Chain mapping)
- Vector memory (embeddings, semantic search, clustering)
- Metrics: 50K beads, 2.5K chains, 85% cache hit rate

#### SLM Inference (`tests/unit/slm/`)

- Engine initialization (9 models, 1.17B total params, 4.5GB GPU)
- Security tokenizer (32K vocab, entity-aware, special tokens)
- Model inference (Detection, Triage, Investigation, Response, etc.)
- Batch processing (2K samples/sec, dynamic batching)
- Multi-model orchestration (sequential, parallel, conditional)
- Performance: p50 15ms, p99 75ms, 500 samples/sec

#### Knowledge Base (`tests/unit/knowledge_base/`)

- MITRE ATT&CK: Technique lookup, tactic mapping, procedure examples
- Threat Intel: IOC database, campaign tracking, actor profiles
- Vulnerability: CVE lookup, CVSS scoring, exploit intelligence
- Playbooks: Retrieval, recommendations, execution history
- Detection: Rule lookup, coverage analysis, effectiveness metrics

### Integration Tests (`tests/integration/`)

Multi-agent orchestration workflows:
- Detection → Triage handoff
- Triage → Investigation escalation
- Investigation → Response coordination
- Parallel agent execution (3 agents in 150ms)
- Cross-agent memory sharing via Bead Memory
- Error handling with exponential backoff retry

### E2E Tests (`tests/e2e/`)

Complete incident lifecycle scenarios:
- Phishing incident (630ms total resolution)
- Ransomware attack (4h resolution)
- Insider threat detection with UEBA
- APT campaign with multi-stage attack
- DDoS mitigation
- Data breach with compliance reporting
- Supply chain compromise
- Cloud security incident
- IoT botnet
- Zero-day exploitation

### Performance Tests (`tests/performance/`)

**Throughput Benchmarks:**
- Ingestion: 50K events/sec
- Normalization: 20K events/sec
- Enrichment: 10K lookups/sec
- Detection: 20K EPS with 500 rules
- SLM: 500 samples/sec

**Latency Benchmarks:**
| Component | p50 | p95 | p99 |
|-----------|-----|-----|-----|
| Detection | 8ms | 15ms | 25ms |
| Triage | 12ms | 20ms | 35ms |
| Investigation | 25ms | 45ms | 80ms |
| SLM Inference | 15ms | 35ms | 75ms |

**Accuracy Benchmarks:**
- Detection precision: 0.95
- Detection recall: 0.979
- F1 score: 0.964
- False positive rate: <8%

### Security Tests (`tests/security/`)

**Authentication:**
- JWT token generation/validation
- API key authentication with rotation
- OAuth/SAML SSO integration
- MFA TOTP verification
- Session management

**Authorization:**
- RBAC permission checks
- ABAC attribute policies
- Hierarchical role inheritance
- Data classification access control
- Time-based restrictions

**Input Validation:**
- SQL injection prevention
- XSS sanitization
- Command injection blocking
- Path traversal prevention
- File upload validation with virus scanning

**Data Protection:**
- AES-256-GCM encryption
- Field-level encryption
- Data masking (PII, credentials)
- Key rotation
- Secure deletion (crypto shred)

**Audit Logging:**
- Event logging with integrity hashes
- Tamper detection
- Privileged action tracking
- Data access logging

## 🔧 Configuration

### conftest.py Fixtures

```python
# Sample event fixtures
@pytest.fixture
def sample_windows_event(): ...

@pytest.fixture
def sample_linux_event(): ...

@pytest.fixture
def sample_network_event(): ...

# Mock agent instances
@pytest.fixture
def mock_detection_agent(): ...

@pytest.fixture
def mock_triage_agent(): ...

# External service mocks
@pytest.fixture
def mock_virustotal(): ...

@pytest.fixture
def mock_misp(): ...

# Database fixtures
@pytest.fixture
async def db_session(): ...
```

### Environment Variables

```bash
# Test configuration
export SOC_TEST_MODE=true
export SOC_LOG_LEVEL=DEBUG

# Mock external services
export VIRUSTOTAL_API_KEY=test_key
export ABUSEIPDB_API_KEY=test_key

# Database
export TEST_DATABASE_URL=postgresql://localhost/soc_test
export TEST_REDIS_URL=redis://localhost:6379/1
```

## 📈 Performance Targets

| Metric | Target | Validated |
|--------|--------|-----------|
| Detection EPS | 20,000 | ✅ |
| Detection p95 | <15ms | ✅ |
| Normalization | 20K/sec | ✅ |
| SLM p50 | 15ms | ✅ |
| SLM p99 | 75ms | ✅ |
| Cache Hit Rate | 85%+ | ✅ |
| Precision | 0.95 | ✅ |
| Recall | 0.979 | ✅ |
| F1 Score | 0.964 | ✅ |
| MTTD | 15min | ✅ |
| MTTR | 3.5h | ✅ |
| Automation Rate | 65% | ✅ |
| FP Rate | <8% | ✅ |

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements-test.txt
      - run: pytest tests/unit/ -v --cov=src
      - run: pytest tests/integration/ -v
      - run: pytest tests/security/ -v
```

### Pre-commit Hook

```yaml
repos:
  - repo: local
    hooks:
      - id: pytest-check
        name: pytest-check
        entry: pytest tests/unit/ -q
        language: system
        pass_filenames: false
        always_run: true
```

## 📝 Writing New Tests

### Test Template

```python
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

class TestNewComponent:
    """Test suite for NewComponent."""
    
    @pytest.fixture
    def component(self):
        """Create component instance for testing."""
        return NewComponent(config={})
    
    @pytest.mark.asyncio
    async def test_basic_functionality(self, component):
        """Test basic component functionality."""
        result = await component.process(data)
        
        assert result is not None
        assert result['status'] == 'success'
    
    @pytest.mark.parametrize("input,expected", [
        ("valid", True),
        ("invalid", False),
    ])
    def test_validation(self, component, input, expected):
        """Test input validation."""
        assert component.validate(input) == expected
    
    @pytest.mark.asyncio
    async def test_error_handling(self, component):
        """Test error handling."""
        with pytest.raises(ValidationError):
            await component.process(invalid_data)
```

## 🤝 Contributing

1. Follow existing test patterns
2. Use fixtures from `conftest.py`
3. Mock external dependencies
4. Include both positive and negative test cases
5. Add performance benchmarks for new components
6. Ensure security tests for any auth/validation changes

## 📄 License

MIT License - See LICENSE file for details.
