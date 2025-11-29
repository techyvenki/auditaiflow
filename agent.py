"""
Core agent implementations: OrchestratorAgent and SpecialistAgent base class.

Demonstrates:
- ReAct pattern (Think→Act→Observe)
- Multi-agent orchestration
- A2A (Agent-to-Agent) delegation protocol
- Shared session coordination
"""

from typing import List, Dict, Any
from datetime import datetime
import uuid

# Handle both package and script imports
try:
    from .agent_utils import (
        AgentGoal,
        AgentFinding,
        SharedAuditSession,
        generate_unique_id,
        consolidate_findings,
        get_logger,
    )
except ImportError:
    from agent_utils import (
        AgentGoal,
        AgentFinding,
        SharedAuditSession,
        generate_unique_id,
        consolidate_findings,
        get_logger,
    )

# ============================================================================
# BASE SPECIALIST AGENT CLASS
# ============================================================================

class SpecialistAgent:
    """
    Base class for specialist agents.
    
    Each agent is autonomous and can execute its own ReAct loop:
    - THINK: Plan strategy
    - ACT: Execute tool
    - OBSERVE: Interpret results
    
    Subclasses: ComplianceAgent, DataValidationAgent, AnomalyDetectionAgent
    """
    
    def __init__(self, agent_name: str, agent_type: str):
        self.agent_name = agent_name
        self.agent_type = agent_type
        self.logger = get_logger(agent_name)
        self.findings = []
        self.completed_goals = []
    
    def think(self, goal: AgentGoal) -> str:
        """
        THINK: Agent reasoning phase.
        
        Plan strategy before acting.
        
        Subclasses override with domain-specific logic.
        """
        self.logger.info(f"THINK: Planning strategy for goal {goal.goal_id}")
        return f"Will execute {goal.goal_type}"
    
    def act(self, goal: AgentGoal) -> Dict[str, Any]:
        """
        ACT: Execute audit tool.
        
        Call the appropriate tool based on goal type.
        
        Subclasses override with tool invocation.
        """
        raise NotImplementedError(f"{self.agent_name} must implement act()")
    
    def observe(self, result: Dict[str, Any]) -> AgentFinding:
        """
        OBSERVE: Interpret tool results and create finding.
        
        Transform raw tool output into structured AgentFinding.
        
        Subclasses override with interpretation logic.
        """
        raise NotImplementedError(f"{self.agent_name} must implement observe()")
    
    def receive_goal(self, goal: AgentGoal) -> AgentFinding:
        """
        Full ReAct cycle: THINK → ACT → OBSERVE.
        
        Called by Orchestrator when delegating a goal.
        
        Returns an AgentFinding with results.
        """
        self.logger.info(f"Received goal: {goal.description}")
        
        # THINK
        strategy = self.think(goal)
        self.logger.info(f"Strategy: {strategy}")
        
        # ACT
        self.logger.info("ACT: Executing tool")
        result = self.act(goal)
        self.logger.info(f"Tool returned: {result.get('summary', 'result')}")
        
        # OBSERVE
        self.logger.info("OBSERVE: Interpreting results")
        finding = self.observe(result)
        finding.goal_id = goal.goal_id
        
        # Track completion
        self.findings.append(finding)
        self.completed_goals.append(goal.goal_id)
        
        self.logger.info(f"Generated finding {finding.finding_id} with severity {finding.severity}")
        
        return finding

# ============================================================================
# ORCHESTRATOR AGENT CLASS
# ============================================================================

class OrchestratorAgent:
    """
    Primary agent that coordinates specialist agents.
    
    Implements the orchestration pattern:
    1. THINK: Plan which specialists to activate
    2. ACT: Delegate goals to specialists (A2A protocol)
    3. ACT: Execute specialists in parallel
    4. OBSERVE: Consolidate findings
    
    Manages shared session for coordination.
    """
    
    def __init__(self, audit_session: SharedAuditSession):
        self.agent_name = "OrchestratorAgent"
        self.logger = get_logger("OrchestratorAgent")
        self.session = audit_session
        self.specialist_agents: Dict[str, SpecialistAgent] = {}
    
    def register_specialist(self, agent: SpecialistAgent):
        """Register a specialist agent with the orchestrator."""
        self.specialist_agents[agent.agent_name] = agent
        self.session.add_agent(agent.agent_name)
        self.logger.info(f"Registered specialist: {agent.agent_name}")
    
    def think(self, mission: str, audit_records: List[Dict]) -> List[str]:
        """
        THINK: Reasoning phase - plan which specialists to activate.
        
        Analyzes the mission and determines which agents are needed.
        """
        self.logger.info(f"THINK: Planning audit strategy for mission: {mission}")
        self.session.log_coordination_event(
            "ORCHESTRATOR_THINK",
            {"mission": mission, "records_count": len(audit_records)}
        )
        
        # Determine specialists needed based on mission
        specialists_needed = []
        mission_lower = mission.lower()
        
        if "compliance" in mission_lower or "authorize" in mission_lower or "approve" in mission_lower:
            specialists_needed.append("ComplianceAgent")
        
        if "data" in mission_lower or "validation" in mission_lower or "quality" in mission_lower:
            specialists_needed.append("DataValidationAgent")
        
        if "anomaly" in mission_lower or "pattern" in mission_lower or "suspicious" in mission_lower:
            specialists_needed.append("AnomalyDetectionAgent")
        
        # If comprehensive audit, activate all available specialists
        if "comprehensive" in mission_lower or not specialists_needed:
            specialists_needed = list(self.specialist_agents.keys())
        
        # Remove duplicates and filter to registered agents
        specialists_needed = list(set(specialists_needed))
        specialists_needed = [s for s in specialists_needed if s in self.specialist_agents]
        
        self.logger.info(f"Specialists needed: {specialists_needed}")
        return specialists_needed
    
    def act_delegate_goals(self, specialists: List[str], audit_records: List[Dict]) -> List[AgentGoal]:
        """
        ACT: Delegate goals to specialist agents (A2A delegation).
        
        Creates structured AgentGoal objects and adds them to shared session.
        """
        self.logger.info("ACT: Delegating goals to specialist agents")
        self.session.log_coordination_event(
            "ORCHESTRATOR_ACT_DELEGATE",
            {"specialists": specialists, "count": len(specialists)}
        )
        
        delegated_goals = []
        
        for specialist_name in specialists:
            if specialist_name not in self.specialist_agents:
                self.logger.warning(f"Specialist {specialist_name} not registered")
                continue
            
            # Create goal for this specialist
            goal = AgentGoal(
                goal_id=generate_unique_id("GOAL"),
                goal_type=specialist_name.replace("Agent", "").upper(),
                description=f"Execute {specialist_name} analysis on audit records",
                assigned_agent=specialist_name,
                audit_records=audit_records,
                timestamp=datetime.now().isoformat(),
                status="DELEGATED"
            )
            
            # Delegate via shared session (A2A protocol)
            self.session.delegate_goal(goal)
            delegated_goals.append(goal)
            
            self.logger.info(f"Delegated goal {goal.goal_id} to {specialist_name}")
        
        return delegated_goals
    
    def act_execute_parallel(self, delegated_goals: List[AgentGoal]) -> List[AgentFinding]:
        """
        ACT: Execute specialist agents.
        
        In a real system with async support, this would execute specialists in parallel.
        For now, we execute sequentially but specialists are autonomous.
        """
        self.logger.info(f"ACT: Executing {len(delegated_goals)} specialist agents")
        self.session.log_coordination_event(
            "ORCHESTRATOR_ACT_EXECUTE",
            {"goal_count": len(delegated_goals)}
        )
        
        findings = []
        
        for goal in delegated_goals:
            specialist = self.specialist_agents.get(goal.assigned_agent)
            if not specialist:
                self.logger.warning(f"Specialist {goal.assigned_agent} not found")
                continue
            
            self.logger.info(f"Executing specialist: {goal.assigned_agent}")
            
            # Specialist executes its full ReAct loop autonomously
            finding = specialist.receive_goal(goal)
            
            # Add finding to shared session
            self.session.receive_finding(finding)
            
            findings.append(finding)
        
        return findings
    
    def observe_consolidate(self, findings: List[AgentFinding]) -> Dict[str, Any]:
        """
        OBSERVE: Consolidate findings from all specialists.
        
        Context Engineering at System Level:
        - Summarizes findings (prevents context bloat)
        - Returns counts and summaries, not raw findings
        - Enables agent to reason on high-level status
        """
        self.logger.info(f"OBSERVE: Consolidating {len(findings)} specialist findings")
        self.session.log_coordination_event(
            "ORCHESTRATOR_OBSERVE_CONSOLIDATE",
            {"finding_count": len(findings)}
        )
        
        # Use utility function to consolidate
        consolidation = consolidate_findings(findings)
        
        self.logger.info(
            f"Consolidated: {consolidation['total_findings']} findings, "
            f"{consolidation['critical_count']} critical, "
            f"status={consolidation['overall_status']}"
        )
        
        return consolidation
    
    def execute_audit(self, mission: str, audit_records: List[Dict]) -> Dict[str, Any]:
        """
        Execute full orchestrated audit workflow.
        
        ReAct cycle at orchestrator level:
        THINK → ACT (delegate) → ACT (execute) → OBSERVE (consolidate)
        """
        self.logger.info("="*70)
        self.logger.info("STARTING ORCHESTRATED AUDIT WORKFLOW")
        self.logger.info("="*70)
        
        # THINK: Plan strategy
        specialists_needed = self.think(mission, audit_records)
        
        # ACT: Delegate goals
        delegated_goals = self.act_delegate_goals(specialists_needed, audit_records)
        
        # ACT: Execute specialists
        findings = self.act_execute_parallel(delegated_goals)
        
        # OBSERVE: Consolidate results
        consolidation = self.observe_consolidate(findings)
        
        self.logger.info("="*70)
        self.logger.info("AUDIT WORKFLOW COMPLETE")
        self.logger.info("="*70)
        
        return {
            "mission": mission,
            "session_id": self.session.session_id,
            "orchestrator_plan": specialists_needed,
            "delegated_goals": len(delegated_goals),
            "specialist_findings": findings,
            "consolidation": consolidation,
            "coordination_events": len(self.session.coordination_events),
            "session_summary": self.session.get_summary()
        }
