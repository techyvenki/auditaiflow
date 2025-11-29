"""
AnomalyDetectionAgent: Specialist for pattern and anomaly detection.

Executes autonomous ReAct loop:
- THINK: Plan anomaly detection strategy
- ACT: Call detect_anomalies tool
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
from ..tools import detect_anomalies, audit_record_to_dict


class AnomalyDetectionAgent(SpecialistAgent):
    """
    Specialist agent for anomaly and pattern detection.
    
    Responsibilities:
    - Detect suspicious patterns in audit records
    - Identify unusual user behavior
    - Flag abnormal operation sequences
    - Score anomaly severity
    """
    
    def __init__(self):
        super().__init__(
            agent_name="AnomalyDetectionAgent",
            agent_type="ANOMALY_DETECTION"
        )
        self.patterns_analyzed = 0
        self.high_severity_anomalies = 0
    
    def think(self, goal: AgentGoal) -> str:
        """
        THINK: Plan anomaly detection strategy.
        
        Determine detection approach for the audit records.
        """
        strategy = (
            f"Analyzing {len(goal.audit_records)} records for anomalies. "
            "Will check for unusual patterns, frequency spikes, and suspicious sequences."
        )
        
        self.logger.info(f"Anomaly detection strategy: {strategy}")
        return strategy
    
    def act(self, goal: AgentGoal) -> Dict[str, Any]:
        """
        ACT: Execute anomaly detection tool.
        
        Call detect_anomalies for the audit records.
        """
        self.logger.info("Executing anomaly detection tool")
        
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
        
        # Apply anomaly detection
        detection_result = detect_anomalies(audit_records)
        
        self.patterns_analyzed = len(audit_records)
        self.high_severity_anomalies = detection_result.get("high_severity_count", 0)
        
        self.logger.info(
            f"Anomaly detection complete: "
            f"anomalies_detected={detection_result.get('anomalies_detected', False)}, "
            f"count={detection_result.get('anomaly_count', 0)}"
        )
        
        return detection_result
    
    def observe(self, result: Dict[str, Any]) -> AgentFinding:
        """
        OBSERVE: Interpret anomaly detection results.
        
        Transform raw tool output into structured AgentFinding.
        """
        anomalies_detected = result.get("anomalies_detected", False)
        anomaly_count = result.get("anomaly_count", 0)
        high_severity_count = result.get("high_severity_count", 0)
        summary = result.get("summary", "")
        
        # Determine finding severity based on anomaly count and severity distribution
        if not anomalies_detected:
            severity = "INFO"
            description = "No anomalies detected - audit records appear normal"
        elif high_severity_count > 0:
            severity = "CRITICAL"
            description = f"Critical anomalies detected: {high_severity_count} high-severity patterns identified"
        elif anomaly_count <= 2:
            severity = "MEDIUM"
            description = f"Minor anomalies detected: {anomaly_count} suspicious patterns found"
        else:
            severity = "HIGH"
            description = f"Multiple anomalies detected: {anomaly_count} suspicious patterns require investigation"
        
        # Calculate confidence based on evidence
        confidence = min(
            1.0,
            0.5 + (anomaly_count / 10.0) * 0.3 +  # More anomalies = higher confidence
            (len(summary) / 500.0) * 0.2            # More detailed summary = higher confidence
        )
        
        finding = AgentFinding(
            finding_id=generate_unique_id("FIND"),
            agent_name=self.agent_name,
            finding_type="ANOMALY",
            severity=severity,
            description=description,
            details={
                "anomalies_detected": anomalies_detected,
                "anomaly_count": anomaly_count,
                "high_severity_count": high_severity_count,
                "patterns_analyzed": self.patterns_analyzed,
                "summary": summary
            },
            confidence=confidence
        )
        
        self.logger.info(
            f"Generated anomaly finding: {finding.finding_id} "
            f"(severity={severity}, anomalies={anomaly_count})"
        )
        
        return finding
