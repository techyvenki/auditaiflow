"""
Validation framework for audit records and findings.

Provides deterministic validation logic for:
- Audit record structure and content validation
- Finding completeness and consistency checks
- Session state validation
- Result quality assurance
"""

from typing import List, Dict, Any, Tuple
from datetime import datetime
from .agent_utils import AuditRecord, AgentFinding, get_logger

logger = get_logger("ValidationCheck")


# ============================================================================
# AUDIT RECORD VALIDATION
# ============================================================================

def validate_audit_record(record: AuditRecord) -> Tuple[bool, List[str]]:
    """
    Validate a single audit record for completeness and structure.
    
    Args:
        record: AuditRecord to validate
        
    Returns:
        (is_valid: bool, errors: List[str])
    """
    errors = []
    
    # Check required fields
    if not record.record_id:
        errors.append("Missing record_id")
    
    if not record.timestamp:
        errors.append("Missing timestamp")
    
    if not record.system:
        errors.append("Missing system")
    
    if not record.action:
        errors.append("Missing action")
    
    if not record.user:
        errors.append("Missing user")
    
    if record.status not in ["SUCCESS", "FAILED", "PENDING"]:
        errors.append(f"Invalid status: {record.status}")
    
    # Validate timestamp format
    if record.timestamp:
        try:
            datetime.fromisoformat(record.timestamp)
        except (ValueError, TypeError):
            errors.append(f"Invalid timestamp format: {record.timestamp}")
    
    # Validate data_changed is dict
    if record.data_changed and not isinstance(record.data_changed, dict):
        errors.append("data_changed must be a dictionary")
    
    is_valid = len(errors) == 0
    return is_valid, errors


def validate_audit_records_batch(records: List[AuditRecord]) -> Dict[str, Any]:
    """
    Validate a batch of audit records.
    
    Returns detailed validation report.
    """
    if not records:
        return {
            "batch_valid": False,
            "total_records": 0,
            "valid_records": 0,
            "invalid_records": 0,
            "validation_errors": ["No records provided"],
            "error_rate": 0.0
        }
    
    total = len(records)
    valid_count = 0
    all_errors = []
    invalid_record_ids = []
    
    for record in records:
        is_valid, errors = validate_audit_record(record)
        if is_valid:
            valid_count += 1
        else:
            all_errors.extend(errors)
            invalid_record_ids.append(record.record_id)
    
    error_rate = (total - valid_count) / total if total > 0 else 0.0
    batch_valid = valid_count == total
    
    logger.info(
        f"Batch validation: {valid_count}/{total} records valid "
        f"({100*valid_count/total:.1f}%)"
    )
    
    return {
        "batch_valid": batch_valid,
        "total_records": total,
        "valid_records": valid_count,
        "invalid_records": total - valid_count,
        "error_rate": error_rate,
        "validation_errors": all_errors[:10],  # Limit to first 10 errors
        "invalid_record_ids": invalid_record_ids,
        "status": "PASS" if batch_valid else "FAIL"
    }


# ============================================================================
# FINDING VALIDATION
# ============================================================================

def validate_finding(finding: AgentFinding) -> Tuple[bool, List[str]]:
    """
    Validate a single agent finding for completeness.
    
    Args:
        finding: AgentFinding to validate
        
    Returns:
        (is_valid: bool, errors: List[str])
    """
    errors = []
    
    # Check required fields
    if not finding.finding_id:
        errors.append("Missing finding_id")
    
    if not finding.agent_name:
        errors.append("Missing agent_name")
    
    if not finding.finding_type:
        errors.append("Missing finding_type")
    
    if finding.severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        errors.append(f"Invalid severity: {finding.severity}")
    
    if not finding.summary:
        errors.append("Missing summary")
    
    # Validate confidence is 0-1
    if finding.confidence is not None:
        if not (0 <= finding.confidence <= 1):
            errors.append(f"Confidence must be 0-1, got {finding.confidence}")
    
    # Validate finding type is reasonable
    valid_types = ["COMPLIANCE", "DATA_VALIDATION", "ANOMALY_DETECTION", 
                   "AUDIT_COMPLETE", "WARNING", "INFO"]
    if finding.finding_type not in valid_types:
        logger.warning(f"Unusual finding_type: {finding.finding_type}")
    
    is_valid = len(errors) == 0
    return is_valid, errors


def validate_findings_batch(findings: List[AgentFinding]) -> Dict[str, Any]:
    """
    Validate a batch of findings.
    
    Returns detailed validation report.
    """
    if not findings:
        return {
            "batch_valid": True,
            "total_findings": 0,
            "valid_findings": 0,
            "invalid_findings": 0,
            "validation_errors": [],
            "critical_count": 0,
            "high_count": 0,
            "status": "PASS"
        }
    
    total = len(findings)
    valid_count = 0
    all_errors = []
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    
    for finding in findings:
        is_valid, errors = validate_finding(finding)
        if is_valid:
            valid_count += 1
        else:
            all_errors.extend(errors)
        
        # Count severity
        if finding.severity in severity_counts:
            severity_counts[finding.severity] += 1
    
    batch_valid = valid_count == total
    critical_count = severity_counts["CRITICAL"]
    high_count = severity_counts["HIGH"]
    
    logger.info(
        f"Findings validation: {valid_count}/{total} findings valid. "
        f"Critical: {critical_count}, High: {high_count}"
    )
    
    return {
        "batch_valid": batch_valid,
        "total_findings": total,
        "valid_findings": valid_count,
        "invalid_findings": total - valid_count,
        "validation_errors": all_errors[:10],
        "severity_breakdown": severity_counts,
        "critical_count": critical_count,
        "high_count": high_count,
        "status": "PASS" if batch_valid else "FAIL"
    }


# ============================================================================
# SESSION STATE VALIDATION
# ============================================================================

def validate_session_state(session_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate session state for consistency and completeness.
    
    Ensures session contains expected data structures.
    """
    issues = []
    warnings = []
    
    # Check required fields
    required_fields = ["session_id", "audit_id", "state", "coordination_events"]
    for field in required_fields:
        if field not in session_data:
            issues.append(f"Missing required field: {field}")
    
    # Check state structure
    if "state" in session_data:
        state = session_data["state"]
        expected_keys = ["findings", "coordination_complete", "status"]
        for key in expected_keys:
            if key not in state:
                warnings.append(f"Missing state key: {key}")
    
    # Check coordination events exist
    events = session_data.get("coordination_events", [])
    if len(events) == 0:
        warnings.append("No coordination events recorded")
    
    is_valid = len(issues) == 0
    
    logger.info(
        f"Session validation: {'VALID' if is_valid else 'INVALID'} "
        f"({len(issues)} issues, {len(warnings)} warnings)"
    )
    
    return {
        "session_valid": is_valid,
        "issues": issues,
        "warnings": warnings,
        "event_count": len(events),
        "status": "PASS" if is_valid else "FAIL"
    }


# ============================================================================
# RESULT QUALITY ASSURANCE
# ============================================================================

def validate_audit_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Comprehensive validation of audit execution result.
    
    Validates:
    - Required result fields
    - Specialist execution
    - Finding completeness
    - Session state
    """
    logger.info("Performing comprehensive result validation...")
    
    all_valid = True
    validation_report = {
        "overall_valid": True,
        "validations": {}
    }
    
    # 1. Check required result fields
    required_fields = ["mission", "session_id", "orchestrator_plan", 
                       "delegated_goals", "specialist_findings", "consolidation"]
    result_validation = {"required_fields_ok": True, "missing": []}
    for field in required_fields:
        if field not in result:
            result_validation["required_fields_ok"] = False
            result_validation["missing"].append(field)
            all_valid = False
    
    validation_report["validations"]["result_structure"] = result_validation
    
    # 2. Validate findings
    findings = result.get("specialist_findings", [])
    findings_validation = validate_findings_batch(findings)
    validation_report["validations"]["findings"] = findings_validation
    
    if not findings_validation["batch_valid"]:
        all_valid = False
    
    # 3. Validate consolidation
    consolidation = result.get("consolidation", {})
    consolidation_validation = {
        "has_summary": "overall_status" in consolidation,
        "has_counts": "total_findings" in consolidation,
        "has_severity": "severity_breakdown" in consolidation
    }
    if not all(consolidation_validation.values()):
        all_valid = False
    
    validation_report["validations"]["consolidation"] = consolidation_validation
    
    # 4. Validate goal delegation matches execution
    goals_delegated = result.get("delegated_goals", 0)
    findings_received = len(findings)
    execution_validation = {
        "goals_delegated": goals_delegated,
        "findings_received": findings_received,
        "match": goals_delegated == findings_received
    }
    if not execution_validation["match"]:
        all_valid = False
    
    validation_report["validations"]["execution"] = execution_validation
    
    validation_report["overall_valid"] = all_valid
    validation_report["status"] = "PASS" if all_valid else "FAIL"
    
    logger.info(
        f"Audit result validation: {validation_report['status']} "
        f"({'all checks passed' if all_valid else 'some checks failed'})"
    )
    
    return validation_report


# ============================================================================
# COMPLIANCE CHECK
# ============================================================================

def check_compliance_with_schema(
    records: List[AuditRecord],
    schema_rules: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Check audit records against a compliance schema.
    
    Validates records conform to specific compliance requirements.
    """
    results = {
        "total_records": len(records),
        "compliant_records": 0,
        "non_compliant_records": 0,
        "violations": []
    }
    
    if not records:
        results["status"] = "PASS"
        return results
    
    for record in records:
        compliant = True
        
        # Example schema checks
        if schema_rules.get("require_user_field") and not record.user:
            results["violations"].append(f"Record {record.record_id} missing user")
            compliant = False
        
        if schema_rules.get("require_operation_field") and not record.operation:
            results["violations"].append(f"Record {record.record_id} missing operation")
            compliant = False
        
        if schema_rules.get("require_success_status") and record.status != "SUCCESS":
            results["violations"].append(
                f"Record {record.record_id} has status {record.status}"
            )
            compliant = False
        
        if compliant:
            results["compliant_records"] += 1
        else:
            results["non_compliant_records"] += 1
    
    compliance_rate = (results["compliant_records"] / len(records)) * 100
    results["compliance_rate"] = compliance_rate
    results["status"] = "PASS" if compliance_rate >= 95 else "FAIL"
    
    logger.info(
        f"Schema compliance: {compliance_rate:.1f}% "
        f"({results['compliant_records']}/{len(records)} records)"
    )
    
    return results
