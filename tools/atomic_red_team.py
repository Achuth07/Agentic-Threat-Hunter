import subprocess
import json
import logging
from typing import List, Dict, Optional
from langchain.tools import BaseTool
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class AtomicRedTeamTool(BaseTool):
    name: str = "atomic_red_team"
    description: str = (
        "Executes Atomic Red Team tests on the Windows host via PowerShell. "
        "Use this to simulate attacks. "
        "Input should be a JSON string with 'action' ('list_tests' or 'execute_test'), "
        "and optionally 'technique_id' (e.g., 'T1033') and 'test_number' (e.g., 1)."
    )

    def _run(self, query: str) -> str:
        """Use the tool."""
        try:
            params = json.loads(query)
        except json.JSONDecodeError:
            return "Error: Input must be a valid JSON string."

        action = params.get("action")
        
        if action == "list_tests":
            return self.list_tests()
        elif action == "execute_test":
            technique_id = params.get("technique_id")
            test_number = params.get("test_number")
            if not technique_id:
                return "Error: 'technique_id' is required for execute_test."
            return self.execute_test(technique_id, test_number)
        else:
            return f"Error: Unknown action '{action}'. Valid actions are 'list_tests', 'execute_test'."

    def _check_prerequisites(self) -> bool:
        """Check if Invoke-AtomicRedTeam is available on the Windows host."""
        # Try to import from known location first
        import_cmd = "Import-Module 'C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1' -ErrorAction SilentlyContinue; Get-Module Invoke-AtomicRedTeam"
        cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", import_cmd]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if "Invoke-AtomicRedTeam" in result.stdout:
                return True
            return False
        except FileNotFoundError:
            return False

    def list_tests(self) -> str:
        """List available Atomic Red Team tests."""
        if not self._check_prerequisites():
            return "Error: Invoke-AtomicRedTeam module not found on Windows host. Please install it."

        # Import module and list tests
        # Invoke-AtomicTest -ShowDetailsBrief is too slow. Let's list the technique IDs from the atomics folder.
        ps_command = "Get-ChildItem 'C:\\AtomicRedTeam\\atomics' -Directory | Select-Object -ExpandProperty Name"
        
        cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", ps_command]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                return f"Error listing tests: {result.stderr}"
            
            output = "Available Atomic Red Team Techniques:\n" + result.stdout
            if len(output) > 4000:
                return output[:4000] + "\n... (output truncated)"
            return output
        except Exception as e:
            return f"Error executing PowerShell command: {str(e)}"

    def execute_test(self, technique_id: str, test_number: Optional[int] = None) -> str:
        """Execute a specific Atomic Red Team test."""
        if not self._check_prerequisites():
            return "Error: Invoke-AtomicRedTeam module not found on Windows host. Please install it."

        ps_command = "Import-Module 'C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1' -ErrorAction SilentlyContinue; "
        ps_command += f"Invoke-AtomicTest {technique_id}"
        if test_number:
            ps_command += f" -TestNumbers {test_number}"
        
        # Add -GetPrereqs to ensure prerequisites are met? Maybe separate step.
        # For now, just run it.
        
        cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", ps_command]
        try:
            logger.info(f"Executing Atomic Test: {ps_command}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            output = f"Execution Result for {technique_id} (Test {test_number}):\n"
            output += f"Return Code: {result.returncode}\n"
            output += f"Stdout:\n{result.stdout}\n"
            if result.stderr:
                output += f"Stderr:\n{result.stderr}\n"
            
            return output
        except Exception as e:
            return f"Error executing PowerShell command: {str(e)}"
