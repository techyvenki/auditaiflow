"""
Configuration and constants for AuditAIFlow system.

Defines compliance rules, audit parameters, logging setup, and system-wide settings.
"""

from dataclasses import dataclass
from typing import Dict, List
import logging

# ============================================================================
# COMPLIANCE RULES CONFIGURATION
# ============================================================================

COMPLIANCE_RULES = [
    {
        "rule_id": "CR001",
        "rule_name": "User Authorization",
        "description": "All CREATE actions require manager approval",
        "rule_type": "AUTHORIZATION",
        "severity": "CRITICAL"
    },
    {
        "rule_id": "CR002",
        "rule_name": "Data Retention",
        "description": "Delete operations must be logged and archived",
        "rule_type": "RETENTION",
        "severity": "HIGH"
    },
    {
        "rule_id": "CR003",
        "rule_name": "Audit Trail Integrity",
        "description": "All system changes must be recorded with timestamps",
        "rule_type": "LOGGING",
        "severity": "CRITICAL"
    },
    {
        "rule_id": "CR004",
        "rule_name": "Access Control",
        "description": "Non-admin users cannot modify system settings",
        "rule_type": "ACCESS_CONTROL",
        "severity": "HIGH"
    },
]

# ============================================================================
# AUDIT CONFIGURATION
# ============================================================================

@dataclass
class AuditConfig:
    """System-wide audit configuration."""
    
    # Audit parameters
    max_records_per_batch: int = 1000
    quality_score_threshold: float = 90.0  # Minimum acceptable data quality
    anomaly_confidence_threshold: float = 0.85  # Minimum confidence for flagging anomalies
    
    # Agent parameters
    num_specialist_agents: int = 3
    enable_parallel_execution: bool = True
    context_window_size: int = 4096  # Maximum tokens for agent context
    
    # Session parameters
    session_timeout_seconds: int = 3600  # 1 hour
    max_findings_per_agent: int = 100
    consolidation_window: int = 50  # Consolidate every N findings
    
    # Thresholds
    large_transaction_threshold: float = 200000.0
    failed_operation_threshold: int = 3  # Flag if N+ failed operations
    admin_activity_threshold: int = 2  # Flag if N+ admin operations

AUDIT_CONFIG = AuditConfig()

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

LOG_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s - [%(name)s] - %(levelname)s - %(message)s"
        },
        "detailed": {
            "format": "%(asctime)s - [%(name)s] - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "standard",
            "stream": "ext://sys.stdout"
        },
        "file": {
            "class": "logging.FileHandler",
            "level": "DEBUG",
            "formatter": "detailed",
            "filename": "auditaiflow.log"
        },
    },
    "loggers": {
        "auditaiflow": {
            "level": "INFO",
            "handlers": ["console", "file"]
        },
        "OrchestratorAgent": {
            "level": "INFO",
            "handlers": ["console", "file"]
        },
        "ComplianceAgent": {
            "level": "INFO",
            "handlers": ["console"]
        },
        "DataValidationAgent": {
            "level": "INFO",
            "handlers": ["console"]
        },
        "AnomalyDetectionAgent": {
            "level": "INFO",
            "handlers": ["console"]
        },
    }
}

# ============================================================================
# SYSTEM STATUS CONSTANTS
# ============================================================================

class AuditStatus:
    """Audit status constants."""
    PASS = "PASS"
    FINDINGS_REQUIRE_REVIEW = "FINDINGS_REQUIRE_REVIEW"
    CRITICAL_ISSUES = "CRITICAL_ISSUES"
    IN_PROGRESS = "IN_PROGRESS"

class GoalStatus:
    """Agent goal status constants."""
    PENDING = "PENDING"
    DELEGATED = "DELEGATED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class FindingSeverity:
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"

class FindingType:
    """Types of findings from agents."""
    COMPLIANCE = "COMPLIANCE"
    DATA_VALIDATION = "DATA_VALIDATION"
    DATA_QUALITY = "DATA_QUALITY"
    ANOMALY_DETECTION = "ANOMALY"

# ============================================================================
# AGENT TYPE MAPPING
# ============================================================================

AGENT_TYPE_MAPPING = {
    "ComplianceAgent": "COMPLIANCE_VERIFIER",
    "DataValidationAgent": "DATA_VALIDATOR",
    "AnomalyDetectionAgent": "ANOMALY_DETECTOR",
    "OrchestratorAgent": "ORCHESTRATOR",
}

SPECIALIST_AGENTS = [
    "ComplianceAgent",
    "DataValidationAgent",
    "AnomalyDetectionAgent",
]

# ============================================================================
# SAMPLE AUDIT DATA (FOR TESTING)
# ============================================================================

SAMPLE_AUDIT_RECORDS = [
    {
        "record_id": "AR001",
        "timestamp": "2025-11-23T10:00:00Z",
        "system": "ERP",
        "action": "CREATE",
        "user": "user123",
        "data_changed": {"amount": 50000},
        "status": "SUCCESS"
    },
    {
        "record_id": "AR002",
        "timestamp": "2025-11-23T10:05:00Z",
        "system": "CRM",
        "action": "UPDATE",
        "user": "user456",
        "data_changed": {"status": "active"},
        "status": "SUCCESS"
    },
    {
        "record_id": "AR003",
        "timestamp": "2025-11-23T10:10:00Z",
        "system": "Billing",
        "action": "DELETE",
        "user": "user789",
        "data_changed": {"invoice_id": "INV-001"},
        "status": "FAILED"
    },
    {
        "record_id": "AR004",
        "timestamp": "2025-11-23T10:15:00Z",
        "system": "ERP",
        "action": "CREATE",
        "user": "admin001",
        "data_changed": {"amount": 500000},
        "status": "SUCCESS"
    },
]
