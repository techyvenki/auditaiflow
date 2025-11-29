"""
DataValidationAgent: Specialist for data quality and integrity checks.

Executes autonomous ReAct loop:
- THINK: Plan data validation strategy
- ACT: Call validate_data_integrity tool
- OBSERVE: Interpret results and generate finding
"""

from typing import Dict, Any
from ..agent import SpecialistAgent
from ..agent_utils import (
    AgentGoal,
    AgentFinding,
    AuditRecord,
    generate_unique_id,
    get_logger,
)
from ..tools import validate_data_integrity, audit_record_to_dict


class DataValidationAgent(SpecialistAgent):
    """
    Specialist agent for data quality and integrity verification.
    
    Responsibilities:
    - Validate audit record structure and completeness
    - Check data types and value ranges
    - Verify referential integrity
    - Generate quality metrics
    """
    
    def __init__(self):
        super().__init__(
            agent_name="DataValidationAgent",
            agent_type="DATA_VALIDATION"
        )
        self.validation_checks_performed = 0
        self.records_analyzed = 0
    
    def think(self, goal: AgentGoal) -> str:
        """
        THINK: Plan data validation strategy.
        
        Analyze audit records and plan validation approach.
        """
        strategy = (
            f"Validating data integrity for {len(goal.audit_records)} records. "
            "Will check required fields, data types, value ranges, and relationships."
        )
        
        self.logger.info(f"Data validation strategy: {strategy}")
        self.records_analyzed = len(goal.audit_records)
        return strategy
    
    def act(self, goal: AgentGoal) -> Dict[str, Any]:
        """
        ACT: Execute data validation tool.
        
        Call validate_data_integrity for the audit records.
        """
        self.logger.info("Executing data validation tool")
        
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
        
        # Apply data validation
        validation_result = validate_data_integrity(audit_records)
        
        self.validation_checks_performed = validation_result.get("checks_performed", 0)
        
        self.logger.info(
            f"Data validation complete: "
            f"passed={validation_result.get('validation_passed', False)}, "
            f"quality_score={validation_result.get('data_quality_score', 0):.1f}%"
        )
        
        return validation_result
    
    def observe(self, result: Dict[str, Any]) -> AgentFinding:
        """
        OBSERVE: Interpret data validation results.
        
        Transform raw tool output into structured AgentFinding.
        """
        validation_passed = result.get("validation_passed", False)
        quality_score = result.get("data_quality_score", 0)
        failure_count = result.get("failure_count", 0)
        
        # Determine finding severity based on quality score
        if quality_score >= 95:
            severity = "INFO"
            description = f"Data validation successful - quality score: {quality_score:.1f}%"
        elif quality_score >= 80:
            severity = "MEDIUM"
            description = f"Data quality issues detected - score: {quality_score:.1f}%"
        else:
            severity = "HIGH"
            description = f"Significant data quality issues - score: {quality_score:.1f}%"
        
        # Calculate confidence based on record count and validation checks
        confidence = min(
            1.0,
            0.6 + (self.records_analyzed / 1000.0) * 0.3 +  # More records = higher confidence
            (self.validation_checks_performed / 50.0) * 0.1   # More checks = higher confidence
        )
        
        finding = AgentFinding(
            finding_id=generate_unique_id("FIND"),
            agent_name=self.agent_name,
            finding_type="DATA_QUALITY_ISSUE",
            severity=severity,
            description=description,
            details={
                "validation_passed": validation_passed,
                "data_quality_score": quality_score,
                "failure_count": failure_count,
                "records_analyzed": self.records_analyzed,
                "validation_checks": self.validation_checks_performed
            },
            confidence=confidence
        )
        
        self.logger.info(
            f"Generated data validation finding: {finding.finding_id} "
            f"(severity={severity}, quality_score={quality_score:.1f}%)"
        )
        
        return finding
