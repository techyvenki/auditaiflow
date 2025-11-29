"""
AuditAIFlow - Enterprise Multi-Agent Auditing System

A production-ready multi-agent system for automating enterprise compliance verification,
data validation, and anomaly detection using Google's Agent Development Kit.

Level: 3+ (Multi-agent orchestration with A2A delegation)

Usage:
    from auditaiflow import OrchestratorAgent, ComplianceAgent, DataValidationAgent, AnomalyDetectionAgent
    from auditaiflow.agent_utils import SharedAuditSession, AuditRecord
    
    # Create shared session
    session = SharedAuditSession(session_id="AUDIT_001")
    
    # Create orchestrator and specialists
    orchestrator = OrchestratorAgent(session)
    compliance_agent = ComplianceAgent()
    
    orchestrator.register_specialist(compliance_agent)
    
    # Execute audit
    results = orchestrator.execute_audit(mission="Perform comprehensive audit", audit_records=data)

Concepts Demonstrated:
    ✅ Multi-Agent Systems (4 agents: 1 orchestrator + 3 specialists)
    ✅ A2A Protocol (Goal delegation via AgentGoal/AgentFinding)
    ✅ Sessions & Memory (SharedAuditSession for coordination)
    ✅ Tools (3 audit functions with concise outputs)
    ✅ Context Engineering (Dynamic memory compaction)
    ✅ Observability (Trajectory tracking & coordination events)
"""

from .config import (
    COMPLIANCE_RULES,
    AUDIT_CONFIG,
    LOG_CONFIG,
)

from .agent_utils import (
    AuditRecord,
    ComplianceRule,
    AgentGoal,
    AgentFinding,
    SharedAuditSession,
    AuditAgentSession,
)

from .tools import (
    verify_compliance,
    validate_data_integrity,
    detect_anomalies,
    audit_record_to_dict,
)

from .agent import (
    SpecialistAgent,
    OrchestratorAgent,
)

from .validation_check import (
    validate_audit_record,
    validate_audit_records_batch,
    validate_finding,
    validate_findings_batch,
    validate_session_state,
    validate_audit_result,
    check_compliance_with_schema,
)

from .sub_agents.compliance_agent import ComplianceAgent
from .sub_agents.data_validation_agent import DataValidationAgent
from .sub_agents.anomaly_detection_agent import AnomalyDetectionAgent

# Optional: Google ADK integration (requires google-adk package)
try:
    from .agent_adk import (
        GoogleADKOrchestratorAgent,
        create_audit_agent,
    )
    __all_with_adk__ = True
except ImportError:
    __all_with_adk__ = False

__version__ = "1.0.0"
__author__ = "AuditAIFlow Team"

__all__ = [
    # Configuration
    "COMPLIANCE_RULES",
    "AUDIT_CONFIG",
    "LOG_CONFIG",
    # Data Models
    "AuditRecord",
    "ComplianceRule",
    "AgentGoal",
    "AgentFinding",
    "SharedAuditSession",
    "AuditAgentSession",
    # Tools
    "verify_compliance",
    "validate_data_integrity",
    "detect_anomalies",
    "audit_record_to_dict",
    # Core Agents
    "SpecialistAgent",
    "OrchestratorAgent",
    # Specialist Agents
    "ComplianceAgent",
    "DataValidationAgent",
    "AnomalyDetectionAgent",
    # Validation
    "validate_audit_record",
    "validate_audit_records_batch",
    "validate_finding",
    "validate_findings_batch",
    "validate_session_state",
    "validate_audit_result",
    "check_compliance_with_schema",
    # Optional: Google ADK (if installed)
    "GoogleADKOrchestratorAgent",
    "create_audit_agent",
]
