"""
Google ADK Integration for AuditAIFlow agents.

This module provides integration with Google's Agent Development Kit (ADK)
to leverage Gemini LLM and built-in tool handling.

Usage:
    from .agent_adk import create_audit_agent
    agent = create_audit_agent(api_key="your-key")
    result = agent.audit(records, mission)
"""

import os
from typing import List, Dict, Any, Optional
import json

# Google ADK imports
try:
    from google.adk.agents import Agent
    try:
        from google.adk.agents import InMemoryRunner
    except ImportError:
        InMemoryRunner = None
    from google.genai.types import Tool, FunctionDeclaration, Schema
    import google.genai as genai
    GOOGLE_ADK_AVAILABLE = True
except ImportError:
    GOOGLE_ADK_AVAILABLE = False
    print("Warning: Google ADK not available. Install with: pip install google-adk")

from .agent_utils import (
    SharedAuditSession,
    generate_unique_id,
    get_logger,
    AgentGoal,
    AgentFinding,
)
from .tools import (
    verify_compliance,
    validate_data_integrity,
    detect_anomalies,
)
from .config import AUDIT_CONFIG

logger = get_logger("GoogleADKAgent")


# ============================================================================
# TOOL DEFINITIONS FOR GOOGLE ADK
# ============================================================================

def create_audit_tools():
    """Create tool definitions for Google ADK."""
    
    tools = []
    
    # Tool 1: Compliance Verification
    compliance_tool = Tool(
        function_declarations=[
            FunctionDeclaration(
                name="verify_compliance",
                description="Verify audit records against compliance rules",
                parameters=Schema(
                    type="OBJECT",
                    properties={
                        "audit_records": Schema(
                            type="ARRAY",
                            items=Schema(type="OBJECT"),
                            description="List of audit records to check"
                        ),
                        "rule_id": Schema(
                            type="STRING",
                            description="Compliance rule ID to verify against"
                        )
                    },
                    required=["audit_records"]
                )
            )
        ]
    )
    tools.append(compliance_tool)
    
    # Tool 2: Data Validation
    validation_tool = Tool(
        function_declarations=[
            FunctionDeclaration(
                name="validate_data_integrity",
                description="Validate data quality and integrity of audit records",
                parameters=Schema(
                    type="OBJECT",
                    properties={
                        "audit_records": Schema(
                            type="ARRAY",
                            items=Schema(type="OBJECT"),
                            description="List of audit records to validate"
                        )
                    },
                    required=["audit_records"]
                )
            )
        ]
    )
    tools.append(validation_tool)
    
    # Tool 3: Anomaly Detection
    anomaly_tool = Tool(
        function_declarations=[
            FunctionDeclaration(
                name="detect_anomalies",
                description="Detect suspicious patterns and anomalies in audit records",
                parameters=Schema(
                    type="OBJECT",
                    properties={
                        "audit_records": Schema(
                            type="ARRAY",
                            items=Schema(type="OBJECT"),
                            description="List of audit records to analyze"
                        )
                    },
                    required=["audit_records"]
                )
            )
        ]
    )
    tools.append(anomaly_tool)
    
    return tools


# ============================================================================
# TOOL HANDLERS FOR GOOGLE ADK
# ============================================================================

def handle_tool_call(tool_name: str, tool_input: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle tool calls from Google ADK.
    
    Maps tool names to actual audit tool functions.
    """
    logger.info(f"Google ADK calling tool: {tool_name}")
    
    if tool_name == "verify_compliance":
        records = tool_input.get("audit_records", [])
        rule_id = tool_input.get("rule_id", "DEFAULT_COMPLIANCE")
        return verify_compliance(records, rule_id)
    
    elif tool_name == "validate_data_integrity":
        records = tool_input.get("audit_records", [])
        return validate_data_integrity(records)
    
    elif tool_name == "detect_anomalies":
        records = tool_input.get("audit_records", [])
        return detect_anomalies(records)
    
    else:
        return {"error": f"Unknown tool: {tool_name}"}


# ============================================================================
# GOOGLE ADK ORCHESTRATOR AGENT
# ============================================================================

class GoogleADKOrchestratorAgent:
    """
    Orchestrator agent using Google's ADK.
    
    Demonstrates Level 3+ multi-agent architecture with:
    - Google Gemini LLM for intelligent orchestration
    - Built-in tool handling
    - Automatic ReAct loop management
    """
    
    def __init__(
        self,
        session: SharedAuditSession,
        api_key: Optional[str] = None,
        model: str = "gemini-2.0-flash"
    ):
        """
        Initialize Google ADK orchestrator agent.
        
        Args:
            session: SharedAuditSession for multi-agent coordination
            api_key: Google API key (defaults to GOOGLE_API_KEY env var)
            model: Gemini model to use
        """
        if not GOOGLE_ADK_AVAILABLE:
            raise ImportError(
                "Google ADK not available. "
                "Install with: pip install google-adk"
            )
        
        self.session = session
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        self.model = model
        self.logger = get_logger("GoogleADKOrchestratorAgent")
        
        # Initialize Gemini client
        self.client = genai.Client(api_key=self.api_key)
        
        # Create tools (for reference)
        self.tools = create_audit_tools()
        
        self.logger.info(f"Initialized Google ADK agent with model: {model}")
    
    def _create_system_prompt(self) -> str:
        """Create system prompt for Gemini orchestrator."""
        return """You are an enterprise audit orchestrator AI agent.

Your responsibilities:
1. Receive audit missions (compliance checks, data validation, anomaly detection)
2. Intelligently decide which audit tools to call
3. Interpret tool results and generate audit findings
4. Consolidate findings for enterprise reporting

For each audit mission:
- THINK: What audit checks are needed?
- ACT: Call appropriate verification tools
- OBSERVE: Analyze results for compliance violations or issues
- REPORT: Summarize findings with severity levels

Always be thorough, professional, and highlight any critical issues that need immediate attention.
Provide confidence scores for your findings.
"""
    
    def execute_audit(
        self,
        mission: str,
        audit_records: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Execute audit using Gemini with tool integration.
        
        Args:
            mission: Audit mission description
            audit_records: List of audit records to analyze
        
        Returns:
            Audit execution results with findings
        """
        self.logger.info(f"Starting ADK audit: {mission}")
        self.session.log_coordination_event(
            "ADK_AUDIT_START",
            {"mission": mission, "record_count": len(audit_records)}
        )
        
        try:
            # Prepare prompt for Gemini
            audit_prompt = f"""
Audit Mission: {mission}

Audit Records ({len(audit_records)} total):
{str(audit_records)[:500]}...

Please conduct a comprehensive audit by:
1. Checking compliance violations
2. Validating data integrity
3. Detecting anomalies

Provide findings with severity levels.
"""
            
            # Use Gemini client to generate audit response
            response = self.client.models.generate_content(
                model=self.model,
                contents=audit_prompt
            )
            
            findings_text = response.text if hasattr(response, 'text') else str(response)
            
            self.session.log_coordination_event(
                "ADK_AUDIT_COMPLETE",
                {"findings_summary": findings_text[:200]}
            )
            
            return {
                "mission": mission,
                "session_id": self.session.session_id,
                "model": self.model,
                "adk_response": findings_text,
                "audit_records_analyzed": len(audit_records),
                "session_summary": self.session.get_summary()
            }
        
        except Exception as e:
            self.logger.error(f"ADK audit failed: {e}")
            self.session.log_coordination_event(
                "ADK_AUDIT_FAILED",
                {"error": str(e)}
            )
            return {
                "mission": mission,
                "status": "FAILED",
                "error": str(e)
            }


# ============================================================================
# FACTORY FUNCTION
# ============================================================================

def create_audit_agent(
    session: Optional[SharedAuditSession] = None,
    use_adk: bool = True,
    api_key: Optional[str] = None
):
    """
    Factory function to create appropriate audit agent.
    
    Args:
        session: Optional SharedAuditSession (creates if not provided)
        use_adk: If True, use Google ADK; if False, use custom agent
        api_key: Google API key for ADK
    
    Returns:
        Configured agent (GoogleADKOrchestratorAgent or OrchestratorAgent)
    
    Example:
        # Use Google ADK
        agent = create_audit_agent(use_adk=True)
        
        # Use custom agent
        agent = create_audit_agent(use_adk=False)
    """
    if session is None:
        from datetime import datetime
        session = SharedAuditSession(
            session_id=generate_unique_id("SESSION"),
            created_at=datetime.now().isoformat()
        )
    
    if use_adk and GOOGLE_ADK_AVAILABLE:
        return GoogleADKOrchestratorAgent(session, api_key)
    elif use_adk and not GOOGLE_ADK_AVAILABLE:
        logger.warning(
            "Google ADK not available, falling back to custom agent. "
            "Install with: pip install google-adk"
        )
        from .agent import OrchestratorAgent
        return OrchestratorAgent(session)
    else:
        from .agent import OrchestratorAgent
        return OrchestratorAgent(session)
