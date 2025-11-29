"""
Integration test for AuditAIFlow package.

Verifies:
- All modules import correctly
- Agents can be instantiated
- Tools are accessible
- Validation functions work
"""

import sys
from pathlib import Path

# Add submission folder to path
project_root = Path(__file__).parent / "submission"
sys.path.insert(0, str(project_root))

def test_imports():
    """Test all package imports."""
    print("\n" + "="*70)
    print("TEST 1: Verifying all imports...")
    print("="*70)
    
    try:
        from auditaiflow import (
            OrchestratorAgent,
            ComplianceAgent,
            DataValidationAgent,
            AnomalyDetectionAgent,
            SharedAuditSession,
            AuditRecord,
            AgentGoal,
            AgentFinding,
            verify_compliance,
            validate_data_integrity,
            detect_anomalies,
            validate_audit_record,
            validate_findings_batch,
            validate_audit_result,
            AUDIT_CONFIG,
        )
        print("✅ All core imports successful")
        return True
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False


def test_instantiation():
    """Test agent instantiation."""
    print("\n" + "="*70)
    print("TEST 2: Verifying agent instantiation...")
    print("="*70)
    
    try:
        from auditaiflow import (
            OrchestratorAgent,
            ComplianceAgent,
            DataValidationAgent,
            AnomalyDetectionAgent,
            SharedAuditSession,
        )
        from datetime import datetime
        
        # Create session with all required parameters
        session = SharedAuditSession(
            session_id="TEST_001",
            created_at=datetime.now().isoformat()
        )
        print(f"✅ SharedAuditSession created: {session.session_id}")
        
        # Create orchestrator
        orchestrator = OrchestratorAgent(session)
        print(f"✅ OrchestratorAgent created: {orchestrator.agent_name}")
        
        # Create specialists
        compliance = ComplianceAgent()
        data_val = DataValidationAgent()
        anomaly = AnomalyDetectionAgent()
        
        print(f"✅ ComplianceAgent created: {compliance.agent_name}")
        print(f"✅ DataValidationAgent created: {data_val.agent_name}")
        print(f"✅ AnomalyDetectionAgent created: {anomaly.agent_name}")
        
        # Register specialists
        orchestrator.register_specialist(compliance)
        orchestrator.register_specialist(data_val)
        orchestrator.register_specialist(anomaly)
        
        print(f"✅ All specialists registered with orchestrator")
        return True
        
    except Exception as e:
        print(f"❌ Instantiation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_data_models():
    """Test data model creation."""
    print("\n" + "="*70)
    print("TEST 3: Verifying data models...")
    print("="*70)
    
    try:
        from auditaiflow import (
            AuditRecord,
            AgentGoal,
            AgentFinding,
        )
        from datetime import datetime
        
        # Create audit record (matching actual dataclass definition)
        record = AuditRecord(
            record_id="REC001",
            timestamp=datetime.now().isoformat(),
            system="ERP",
            action="CREATE",
            user="admin@example.com",
            data_changed={"field": "value"},
            status="SUCCESS"
        )
        print(f"✅ AuditRecord created: {record.record_id}")
        
        # Create goal
        goal = AgentGoal(
            goal_id="GOAL001",
            goal_type="COMPLIANCE_CHECK",
            description="Verify compliance rules",
            assigned_agent="ComplianceAgent",
            audit_records=[],
            timestamp=datetime.now().isoformat(),
            status="PENDING"
        )
        print(f"✅ AgentGoal created: {goal.goal_id}")
        
        # Create finding
        finding = AgentFinding(
            finding_id="FIND001",
            agent_name="ComplianceAgent",
            goal_id="GOAL001",
            finding_type="COMPLIANCE",
            severity="HIGH",
            summary="Compliance check complete",
            details={"test": "data"},
            timestamp=datetime.now().isoformat(),
            confidence=0.95
        )
        print(f"✅ AgentFinding created: {finding.finding_id}")
        
        return True
        
    except Exception as e:
        print(f"❌ Data model creation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_tools():
    """Test tool functions."""
    print("\n" + "="*70)
    print("TEST 4: Verifying tools...")
    print("="*70)
    
    try:
        from auditaiflow import (
            verify_compliance,
            validate_data_integrity,
            detect_anomalies,
            AuditRecord,
        )
        from datetime import datetime
        
        # Create sample records (matching actual dataclass definition)
        records = [
            AuditRecord(
                record_id="REC001",
                timestamp=datetime.now().isoformat(),
                system="ERP",
                action="CREATE",
                user="admin@example.com",
                data_changed={"field": "value"},
                status="SUCCESS"
            ),
            AuditRecord(
                record_id="REC002",
                timestamp=datetime.now().isoformat(),
                system="CRM",
                action="UPDATE",
                user="admin@example.com",
                data_changed={"field2": "value2"},
                status="SUCCESS"
            )
        ]
        
        # Convert to dicts for tools
        records_dicts = [
            {
                "record_id": r.record_id,
                "timestamp": r.timestamp,
                "system": r.system,
                "action": r.action,
                "user": r.user,
                "data_changed": r.data_changed,
                "status": r.status
            }
            for r in records
        ]
        
        # Test verify_compliance
        result = verify_compliance(records_dicts, "DEFAULT_COMPLIANCE")
        print(f"✅ verify_compliance tool executed: violations={result.get('violations_found', 0)}")
        
        # Test validate_data_integrity
        result = validate_data_integrity(records_dicts)
        print(f"✅ validate_data_integrity tool executed: quality={result.get('data_quality_score', 0):.1f}%")
        
        # Test detect_anomalies
        result = detect_anomalies(records_dicts)
        print(f"✅ detect_anomalies tool executed: anomalies={result.get('total_anomalies', 0)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Tool execution failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_validation():
    """Test validation functions."""
    print("\n" + "="*70)
    print("TEST 5: Verifying validation functions...")
    print("="*70)
    
    try:
        from auditaiflow import (
            validate_audit_record,
            validate_findings_batch,
            validate_audit_result,
            AuditRecord,
            AgentFinding,
        )
        from datetime import datetime
        
        # Test validate_audit_record
        record = AuditRecord(
            record_id="REC001",
            timestamp=datetime.now().isoformat(),
            system="ERP",
            action="CREATE",
            user="admin@example.com",
            data_changed={"field": "value"},
            status="SUCCESS"
        )
        valid, errors = validate_audit_record(record)
        print(f"✅ validate_audit_record executed: valid={valid}")
        
        # Test validate_findings_batch
        findings = [
            AgentFinding(
                finding_id="FIND001",
                agent_name="ComplianceAgent",
                goal_id="GOAL001",
                finding_type="COMPLIANCE",
                severity="HIGH",
                summary="Test finding",
                details={},
                timestamp=datetime.now().isoformat(),
                confidence=0.95
            )
        ]
        result = validate_findings_batch(findings)
        print(f"✅ validate_findings_batch executed: status={result.get('status', 'UNKNOWN')}")
        
        # Test validate_audit_result
        audit_result = {
            "mission": "Test Audit",
            "session_id": "SESSION001",
            "orchestrator_plan": ["ComplianceAgent"],
            "delegated_goals": 1,
            "specialist_findings": findings,
            "consolidation": {
                "overall_status": "COMPLETE",
                "total_findings": 1,
                "severity_breakdown": {"HIGH": 1}
            }
        }
        result = validate_audit_result(audit_result)
        print(f"✅ validate_audit_result executed: status={result.get('status', 'UNKNOWN')}")
        
        return True
        
    except Exception as e:
        print(f"❌ Validation function test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("AUDITAIFLOW PACKAGE INTEGRATION TEST")
    print("="*70)
    
    results = []
    results.append(("Imports", test_imports()))
    results.append(("Instantiation", test_instantiation()))
    results.append(("Data Models", test_data_models()))
    results.append(("Tools", test_tools()))
    results.append(("Validation", test_validation()))
    
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    all_passed = all(result[1] for result in results)
    
    print("\n" + "="*70)
    if all_passed:
        print("✅ ALL TESTS PASSED - Package is production-ready!")
    else:
        print("❌ SOME TESTS FAILED - Review errors above")
    print("="*70 + "\n")
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    exit(main())
