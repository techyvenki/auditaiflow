"""
Smart import helper for handling both package and script execution modes.
"""

import sys
import os

def smart_import(module_name, from_list=None):
    """
    Try to import a module using relative imports first (for package mode),
    then fallback to absolute imports (for script mode).
    
    Args:
        module_name: Module name (e.g., 'agent_utils')
        from_list: List of items to import (e.g., ['AuditRecord', 'AgentGoal'])
    
    Returns:
        Module or imported items
    """
    try:
        # Try relative import (package mode)
        if from_list:
            exec_globals = {}
            exec(f"from .{module_name} import {', '.join(from_list)}", exec_globals)
            return {item: exec_globals[item] for item in from_list}
        else:
            exec_globals = {}
            exec(f"from . import {module_name}", exec_globals)
            return exec_globals[module_name]
    except ImportError:
        # Fallback to absolute import (script mode)
        if from_list:
            module = __import__(module_name, fromlist=from_list)
            return {item: getattr(module, item) for item in from_list}
        else:
            return __import__(module_name)
