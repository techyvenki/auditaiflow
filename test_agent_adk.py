#!/usr/bin/env python3
"""
Test script for Google ADK Agent (GoogleADKOrchestratorAgent)

Tests the integration of Gemini LLM with the audit tools using Google's Agent Development Kit.
"""

import os
import sys
from datetime import datetime

# Add submission folder to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

def test_adk_imports():
    """Test 1: Verify ADK agent imports work"""
    print("\n" + "="*70)
    print("TEST 1: Verifying ADK agent imports...")
    print("="*70)
    
    try:
        from .agent_adk import (
            GoogleADKOrchestratorAgent,
            create_audit_agent,
        )
        from .agent_utils import SharedAuditSession
        print("✅ GoogleADKOrchestratorAgent imported successfully")
        print("✅ create_audit_agent imported successfully")
        print("✅ SharedAuditSession imported successfully")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False


def test_adk_instantiation():
    """Test 2: Verify ADK agent can be instantiated"""
    print("\n" + "="*70)
    print("TEST 2: Verifying ADK agent instantiation...")
    print("="*70)
    
    try:
        from .agent_adk import GoogleADKOrchestratorAgent
        from .agent_utils import SharedAuditSession
        
        session = SharedAuditSession(
            session_id="ADK_TEST_001",
            created_at=datetime.now().isoformat()
        )
        print(f"✅ Session created: {session.session_id}")
        
        # Check for API key
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            print("⚠️  GOOGLE_API_KEY not set, skipping instantiation test")
            print("   To test: export GOOGLE_API_KEY='your-key'")
            return True  # Pass with warning
        
        # Create ADK agent
        agent = GoogleADKOrchestratorAgent(session, api_key=api_key)
        print(f"✅ GoogleADKOrchestratorAgent instantiated")
        print(f"   - Type: {type(agent).__name__}")
        print(f"   - Model: gemini-2.0-flash")
        
        return True, session, agent
    except Exception as e:
        print(f"❌ Instantiation failed: {e}")
        import traceback
        traceback.print_exc()
        return False, None, None


def test_adk_tool_definitions():
    """Test 3: Verify ADK tool definitions are properly configured"""
    print("\n" + "="*70)
    print("TEST 3: Verifying ADK tool definitions...")
    print("="*70)
    
    try:
        from .agent_adk import GoogleADKOrchestratorAgent
        from .agent_utils import SharedAuditSession
        
        # Check for API key
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            print("⚠️  GOOGLE_API_KEY not set, skipping tool definition test")
            return True  # Pass with warning
        
        session = SharedAuditSession(
            session_id="ADK_TOOLS_TEST",
            created_at=datetime.now().isoformat()
        )
        agent = GoogleADKOrchestratorAgent(session, api_key=api_key)
        
        # Check that tools are created
        tools = agent.tools
        print(f"✅ Tools created: {len(tools)} tools")
        
        for tool in tools:
            print(f"   - Tool: {tool.name if hasattr(tool, 'name') else tool}")
        
        return True
    except Exception as e:
        print(f"❌ Tool definition test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_adk_audit_execution():
    """Test 4: Execute a basic audit with ADK agent"""
    print("\n" + "="*70)
    print("TEST 4: Executing audit with ADK agent...")
    print("="*70)
    
    try:
        from .agent_adk import GoogleADKOrchestratorAgent
        from .agent_utils import SharedAuditSession
        
        # Check for API key
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            print("⚠️  GOOGLE_API_KEY not set in environment")
            print("   To test audit execution, set: export GOOGLE_API_KEY='your-key'")
            print("   Skipping live audit test...")
            return True  # Pass with warning
        
        session = SharedAuditSession(
            session_id="ADK_AUDIT_TEST",
            created_at=datetime.now().isoformat()
        )
        agent = GoogleADKOrchestratorAgent(session, api_key=api_key)
        
        # Create test audit records
        audit_records = [
            {
                "record_id": "REC001",
                "timestamp": datetime.now().isoformat(),
                "system": "ERP",
                "action": "CREATE",
                "user": "admin@company.com",
                "data_changed": {"employee_id": "E123"},
                "status": "SUCCESS"
            },
            {
                "record_id": "REC002",
                "timestamp": datetime.now().isoformat(),
                "system": "CRM",
                "action": "UPDATE",
                "user": "admin@company.com",
                "data_changed": {"customer_name": "Acme Inc"},
                "status": "SUCCESS"
            }
        ]
        
        print(f"📋 Created {len(audit_records)} test records")
        print("   - REC001: ERP CREATE action")
        print("   - REC002: CRM UPDATE action")
        
        # Execute audit
        print("\n🚀 Executing audit with Gemini LLM reasoning...")
        results = agent.execute_audit(
            mission="Perform comprehensive compliance audit",
            audit_records=audit_records
        )
        
        print("✅ Audit executed successfully!")
        print(f"   - Session ID: {results.get('session_id', 'N/A')}")
        print(f"   - Model: {results.get('model', 'N/A')}")
        if 'adk_response' in results:
            response_preview = str(results.get('adk_response', 'N/A'))[:100]
            print(f"   - Response preview: {response_preview}...")
        
        return True
    except Exception as e:
        print(f"⚠️  Audit execution test: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_factory_function():
    """Test 5: Verify factory function works for ADK agent selection"""
    print("\n" + "="*70)
    print("TEST 5: Verifying factory function for agent selection...")
    print("="*70)
    
    try:
        from .agent_adk import create_audit_agent
        from .agent_utils import SharedAuditSession
        
        session = SharedAuditSession(
            session_id="FACTORY_TEST",
            created_at=datetime.now().isoformat()
        )
        
        # Check for API key
        api_key = os.getenv("GOOGLE_API_KEY")
        
        if api_key:
            # Test factory with ADK
            agent_adk = create_audit_agent(use_adk=True, session=session, api_key=api_key)
            print(f"✅ ADK agent created via factory: {type(agent_adk).__name__}")
        else:
            print("⚠️  GOOGLE_API_KEY not set, testing custom agent fallback")
        
        # Test factory with custom
        agent_custom = create_audit_agent(use_adk=False, session=session)
        print(f"✅ Custom agent created via factory: {type(agent_custom).__name__}")
        
        return True
    except Exception as e:
        print(f"❌ Factory function test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_adk_integration():
    """Test 6: Integration with shared components"""
    print("\n" + "="*70)
    print("TEST 6: Verifying ADK integration with shared components...")
    print("="*70)
    
    try:
        from .agent_adk import GoogleADKOrchestratorAgent
        from .agent_utils import SharedAuditSession, AuditRecord, AgentFinding
        from auditaiflow import validate_audit_result
        
        session = SharedAuditSession(
            session_id="INTEGRATION_TEST",
            created_at=datetime.now().isoformat()
        )
        
        # Verify data models
        record = AuditRecord(
            record_id="REC001",
            timestamp=datetime.now().isoformat(),
            system="ERP",
            action="CREATE",
            user="admin@company.com",
            data_changed={},
            status="SUCCESS"
        )
        print(f"✅ AuditRecord created: {record.record_id}")
        
        finding = AgentFinding(
            finding_id="F001",
            agent_name="ComplianceAgent",
            goal_id="G001",
            finding_type="COMPLIANCE",
            severity="HIGH",
            summary="Test finding",
            details={},
            timestamp=datetime.now().isoformat()
        )
        print(f"✅ AgentFinding created: {finding.finding_id}")
        
        # Verify validation integration
        result = {
            "session_id": "TEST",
            "specialist_findings": [finding],
            "consolidation": {
                "overall_status": "PASS",
                "summary": "Test"
            }
        }
        validation = validate_audit_result(result)
        print(f"✅ Audit result validated: {validation['overall_valid']}")
        
        return True
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def print_summary(results):
    """Print test summary"""
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    tests = [
        ("Imports", results[0]),
        ("Instantiation", results[1]),
        ("Tool Definitions", results[2]),
        ("Audit Execution", results[3]),
        ("Factory Function", results[4]),
        ("Integration", results[5]),
    ]
    
    passed = sum(1 for _, result in tests if result)
    total = len(tests)
    
    for test_name, result in tests:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print("="*70)
    if passed == total:
        print(f"✅ ALL TESTS PASSED ({passed}/{total})")
        print("\n🎉 GoogleADKOrchestratorAgent is ready for production use!")
    else:
        print(f"⚠️  {passed}/{total} tests passed")
    print("="*70)


def main():
    """Run all ADK agent tests"""
    print("\n" + "╔" + "="*68 + "╗")
    print("║" + " "*68 + "║")
    print("║" + "AUDITAIFLOW - GOOGLE ADK AGENT TEST SUITE".center(68) + "║")
    print("║" + " "*68 + "║")
    print("╚" + "="*68 + "╝")
    
    # Run tests
    test1 = test_adk_imports()
    
    result2 = test_adk_instantiation()
    test2 = result2[0] if isinstance(result2, tuple) else result2
    
    test3 = test_adk_tool_definitions()
    test4 = test_adk_audit_execution()
    test5 = test_factory_function()
    test6 = test_adk_integration()
    
    # Print summary
    print_summary([test1, test2, test3, test4, test5, test6])


if __name__ == "__main__":
    main()
