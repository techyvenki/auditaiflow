"""
ComplianceAgent: Specialist for compliance rule verification.

Executes autonomous ReAct loop:
- THINK: Plan compliance verification strategy
- ACT: Call verify_compliance tool
- OBSERVE: Interpret results and generate finding
"""

from typing import Dict, Any, List
from ..agent import SpecialistAgent
from ..agent_utils import (
    AgentGoal,
    AgentFinding,
    AuditRecord,
    generate_unique_id,
    get_logger,
)
from ..tools import verify_compliance, audit_record_to_dict


class ComplianceAgent(SpecialistAgent):
    """
    Specialist agent for compliance verification.
    
    Responsibilities:
    - Verify audit records against compliance rules
    - Identify compliance violations
    - Assess violation severity
    - Generate structured findings
    """
    
    def __init__(self):
        super().__init__(
            agent_name="ComplianceAgent",
            agent_type="COMPLIANCE_VERIFICATION"
        )
        self.rules_checked = []
        self.violations_found = 0
    
    def think(self, goal: AgentGoal) -> str:
        """
        THINK: Plan compliance verification strategy.
        
        Analyze the audit records and determine which compliance rules to check.
        """
        strategy = (
            f"Analyzing {len(goal.audit_records)} records for compliance violations. "
            "Will check authorization, approval workflows, and data protection rules."
        )
        
        self.logger.info(f"Compliance verification strategy: {strategy}")
        return strategy
    
    def act(self, goal: AgentGoal) -> Dict[str, Any]:
        """
        ACT: Execute compliance verification tool.
        
        Call verify_compliance for each audit record.
        """
        self.logger.info("Executing compliance verification tool")
        
        records = goal.audit_records
        
        # Convert to AuditRecord objects if needed
        audit_records = []
        for record_data in records:
            if isinstance(record_data, dict):
                # Create AuditRecord from dict
                record = AuditRecord(
                    record_id=record_data.get("record_id", generate_unique_id("REC")),
                    timestamp=record_data.get("timestamp", ""),
                    operation=record_data.get("operation", ""),
                    user=record_data.get("user", ""),
                    status=record_data.get("status", "SUCCESS"),
                    metadata=record_data.get("metadata", {})
                )
            else:
                record = record_data
            audit_records.append(record)
        
        # Apply compliance verification
        verification_result = verify_compliance(audit_records, "DEFAULT_COMPLIANCE")
        
        # Store rules checked
        self.rules_checked.extend(verification_result.get("rules_checked", []))
        self.violations_found = verification_result.get("violations_found", 0)
        
        self.logger.info(
            f"Compliance check complete: {verification_result.get('violations_found', 0)} violations"
        )
        
        return verification_result
    
    def observe(self, result: Dict[str, Any]) -> AgentFinding:
        """
        OBSERVE: Interpret compliance verification results.
        
        Transform raw tool output into structured AgentFinding.
        """
        violations_found = result.get("violations_found", 0)
        severity_breakdown = result.get("severity_breakdown", {})
        details = result.get("details", [])
        
        # Determine finding severity based on violation count
        if violations_found == 0:
            severity = "INFO"
            description = "All compliance rules satisfied - no violations detected"
        elif violations_found <= 2:
            severity = "HIGH"
            description = f"Compliance violations detected: {violations_found} records violate policy"
        else:
            severity = "CRITICAL"
            description = f"Critical compliance failures: {violations_found} records violate policy"
        
        # Calculate confidence based on evidence
        confidence = min(
            1.0,
            0.7 + (len(details) * 0.05)  # More details = higher confidence
        )
        
        finding = AgentFinding(
            finding_id=generate_unique_id("FIND"),
            agent_name=self.agent_name,
            finding_type="COMPLIANCE_VIOLATION",
            severity=severity,
            description=description,
            details={
                "violations_found": violations_found,
                "severity_breakdown": severity_breakdown,
                "rules_checked": len(self.rules_checked),
                "sample_violations": details[:3]  # Limit to top 3 for context
            },
            confidence=confidence
        )
        
        self.logger.info(
            f"Generated compliance finding: {finding.finding_id} "
            f"(severity={severity}, violations={violations_found})"
        )
        
        return finding
