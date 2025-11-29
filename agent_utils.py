"""
Shared data models, utilities, and session management for the multi-agent system.

Includes:
- Data models for audit records, compliance rules, goals, findings
- Session classes for single-agent and multi-agent coordination
- Utility functions and helpers
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid
import logging

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class AuditRecord:
    """Represents a single audit record from enterprise systems."""
    record_id: str
    timestamp: str
    system: str  # ERP, CRM, Billing, HR, etc.
    action: str  # CREATE, UPDATE, DELETE, READ
    user: str  # User who performed action
    data_changed: Dict[str, Any]  # What changed
    status: str  # SUCCESS, FAILED, PENDING

@dataclass
class ComplianceRule:
    """Defines a compliance requirement to verify."""
    rule_id: str
    rule_name: str
    description: str
    rule_type: str  # AUTHORIZATION, RETENTION, LOGGING, ACCESS_CONTROL
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW

@dataclass
class AgentGoal:
    """
    Goal delegated from orchestrator to specialist agent (A2A Protocol).
    
    This is the message structure for agent-to-agent communication.
    """
    goal_id: str
    goal_type: str  # COMPLIANCE_CHECK, DATA_VALIDATION, ANOMALY_DETECTION
    description: str  # Human-readable: "Verify compliance for all records"
    assigned_agent: str  # Target specialist agent name
    audit_records: List[Dict]  # Input data for goal
    timestamp: str  # When goal was created
    status: str = "PENDING"  # PENDING, DELEGATED, IN_PROGRESS, COMPLETED, FAILED

@dataclass
class AgentFinding:
    """
    Finding returned by specialist agent (A2A Response).
    
    This is the response message from agent-to-agent communication.
    """
    finding_id: str
    agent_name: str  # Which specialist found this
    goal_id: str  # Which goal produced this
    finding_type: str  # COMPLIANCE, DATA_VALIDATION, ANOMALY_DETECTION
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    summary: str  # One-liner for reporting
    details: Dict[str, Any]  # Structured findings (tool output)
    timestamp: str  # When finding was generated
    confidence: float = 0.95  # Confidence score (0.0-1.0)

# ============================================================================
# SESSION MANAGEMENT
# ============================================================================

@dataclass
class AuditAgentSession:
    """
    Session for single-agent audit workflow (Level 2).
    
    Working memory container that tracks:
    - Events: Structured audit trail (Think→Act→Observe chain)
    - State: Key-value pairs (audit_id, findings, status, etc.)
    """
    session_id: str
    created_at: str
    events: List[Dict] = field(default_factory=list)
    state: Dict[str, Any] = field(default_factory=dict)
    
    def add_event(self, event_type: str, details: Dict):
        """Add structured event to working memory."""
        event = {
            "type": event_type,
            "timestamp": datetime.now().isoformat(),
            "details": details
        }
        self.events.append(event)
    
    def get_context_summary(self) -> str:
        """Return compact context for agent reasoning."""
        return f"Session {self.session_id}: " \
               f"events={len(self.events)}, " \
               f"audit_id={self.state.get('audit_id')}, " \
               f"status={self.state.get('status')}"

@dataclass
class SharedAuditSession:
    """
    Shared session for multi-agent coordination (Level 3+).
    
    Coordination hub that all agents can read/write to:
    - shared_goals: Track A2A delegations
    - findings_by_agent: Consolidate results per specialist
    - coordination_events: Full inter-agent communication log
    
    Pattern: "Shared history" - all agents read/write to session
    No explicit message passing; all communication through session
    """
    session_id: str
    created_at: str
    agents: List[str] = field(default_factory=list)
    shared_goals: List[AgentGoal] = field(default_factory=list)
    findings_by_agent: Dict[str, List[AgentFinding]] = field(default_factory=dict)
    coordination_events: List[Dict] = field(default_factory=list)
    
    def add_agent(self, agent_name: str):
        """Register agent in session."""
        if agent_name not in self.agents:
            self.agents.append(agent_name)
            self.findings_by_agent[agent_name] = []
    
    def delegate_goal(self, goal: AgentGoal):
        """
        Orchestrator delegates goal to specialist agent (A2A).
        Records goal in shared state.
        """
        self.shared_goals.append(goal)
        self.log_coordination_event(
            "GOAL_DELEGATED",
            {
                "goal_id": goal.goal_id,
                "goal_type": goal.goal_type,
                "assigned_agent": goal.assigned_agent,
                "status": goal.status
            }
        )
    
    def receive_finding(self, finding: AgentFinding):
        """
        Specialist returns finding to shared session.
        Records finding in findings_by_agent map.
        """
        if finding.agent_name not in self.findings_by_agent:
            self.findings_by_agent[finding.agent_name] = []
        
        self.findings_by_agent[finding.agent_name].append(finding)
        
        self.log_coordination_event(
            "FINDING_RECEIVED",
            {
                "finding_id": finding.finding_id,
                "agent_name": finding.agent_name,
                "goal_id": finding.goal_id,
                "severity": finding.severity,
                "confidence": finding.confidence
            }
        )
    
    def log_coordination_event(self, event_type: str, details: Dict):
        """
        Log inter-agent coordination event.
        
        Creates audit trail of all A2A communication:
        - GOAL_DELEGATED
        - FINDING_RECEIVED
        - CONSOLIDATION_STARTED
        - etc.
        """
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "details": details
        }
        self.coordination_events.append(event)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get high-level session summary."""
        total_findings = sum(len(findings) for findings in self.findings_by_agent.values())
        critical_findings = sum(
            len([f for f in findings if f.severity == "CRITICAL"])
            for findings in self.findings_by_agent.values()
        )
        
        return {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "agents_count": len(self.agents),
            "agent_names": self.agents,
            "goals_delegated": len(self.shared_goals),
            "total_findings": total_findings,
            "critical_findings": critical_findings,
            "coordination_events": len(self.coordination_events)
        }

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def generate_unique_id(prefix: str = "") -> str:
    """Generate a unique identifier."""
    unique_part = uuid.uuid4().hex[:8]
    return f"{prefix}_{unique_part}" if prefix else unique_part

def record_to_dict(record: AuditRecord) -> Dict[str, Any]:
    """Convert AuditRecord dataclass to dict."""
    return asdict(record)

def dict_to_record(data: Dict[str, Any]) -> AuditRecord:
    """Convert dict to AuditRecord dataclass."""
    return AuditRecord(**data)

def consolidate_findings(findings: List[AgentFinding]) -> Dict[str, Any]:
    """
    Consolidate findings from multiple agents.
    
    Context Engineering at System Level:
    - Returns counts, not raw findings
    - Summarizes by severity
    - Prevents context bloat
    """
    if not findings:
        return {
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "findings_by_agent": {},
            "overall_status": "PASS"
        }
    
    critical = [f for f in findings if f.severity == "CRITICAL"]
    high = [f for f in findings if f.severity == "HIGH"]
    medium = [f for f in findings if f.severity == "MEDIUM"]
    
    # Group by agent
    findings_by_agent = {}
    for finding in findings:
        if finding.agent_name not in findings_by_agent:
            findings_by_agent[finding.agent_name] = 0
        findings_by_agent[finding.agent_name] += 1
    
    # Determine overall status
    if critical:
        overall_status = "CRITICAL_ISSUES"
    elif high or medium:
        overall_status = "FINDINGS_REQUIRE_REVIEW"
    else:
        overall_status = "PASS"
    
    return {
        "total_findings": len(findings),
        "critical_count": len(critical),
        "high_count": len(high),
        "medium_count": len(medium),
        "findings_by_agent": findings_by_agent,
        "critical_findings_summary": [
            {"agent": f.agent_name, "type": f.finding_type, "summary": f.summary}
            for f in critical
        ],
        "overall_status": overall_status
    }

def get_logger(name: str) -> logging.Logger:
    """Get a configured logger for an agent."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - [%(name)s] - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
