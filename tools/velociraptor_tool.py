from __future__ import annotations

import json
import os
from typing import Optional

try:
    # LangChain tool decorator (optional for future agent orchestration)
    from langchain_core.tools import tool  # type: ignore
except Exception:  # pragma: no cover - decorator optional at runtime
    def tool(func=None, **_kwargs):
        # No-op fallback if langchain not present at import time
        return func if func else (lambda f: f)


@tool
def run_velociraptor_query(vql_query: str, config_path: Optional[str] = None) -> str:
    """
    Execute a Velociraptor VQL query against the local Velociraptor server over gRPC.

    Use this tool for deep endpoint forensics on a local endpoint, such as listing
    processes (e.g., SELECT * FROM pslist()), enumerating files, registry keys, etc.

    Inputs:
      - vql_query: A valid VQL statement (e.g., 'SELECT * FROM pslist()').
      - config_path (optional): Path to Velociraptor API config YAML. If omitted,
        uses the VELOCIRAPTOR_CONFIG environment variable, or 'api.config.yaml' in
        the current working directory.

    Returns:
      - A JSON string. On success, this is a JSON array of result rows (objects).
        On failure, a JSON object with keys: {"error": str, "message": str}.

    Notes:
      - Requires the 'pyvelociraptor' package and a valid Velociraptor API config.
      - This function is defensive and will return JSON errors instead of raising.
    """
    try:
        cfg = (
            config_path
            or os.getenv("VELOCIRAPTOR_CONFIG")
            or os.path.join(os.getcwd(), "api.config.yaml")
        )
        if not os.path.isfile(cfg):
            return json.dumps({
                "error": "config_not_found",
                "message": f"Velociraptor API config not found at: {cfg}",
            })

        try:
            from pyvelociraptor import LoadConfigFile
            from pyvelociraptor.velo_pandas import DataFrameQuery
        except Exception as ie:
            return json.dumps({
                "error": "pyvelociraptor_import",
                "message": f"pyvelociraptor not installed or failed to import: {ie}",
            })

        try:
            # Load the configuration
            config = LoadConfigFile(config_file=cfg)
        except Exception as e:
            return json.dumps({
                "error": "config_load_failed",
                "message": f"Failed to load Velociraptor config: {e}",
            })

        rows = []
        try:
            # Execute query using DataFrameQuery
            # It returns a dict with column names as keys and lists of values
            result_dict = DataFrameQuery(vql_query, config=config, timeout=30)
            
            if not result_dict:
                return json.dumps([])  # Empty result is valid
            
            # Convert the column-oriented dict to row-oriented list of dicts
            # result_dict = {'col1': [val1, val2], 'col2': [val3, val4]}
            # becomes rows = [{'col1': val1, 'col2': val3}, {'col1': val2, 'col2': val4}]
            if isinstance(result_dict, dict):
                # Get the length from the first column
                if result_dict:
                    first_key = next(iter(result_dict))
                    num_rows = len(result_dict[first_key])
                    
                    for i in range(num_rows):
                        row = {}
                        for col_name, col_values in result_dict.items():
                            row[col_name] = col_values[i]
                        rows.append(row)
            else:
                return json.dumps({
                    "error": "unexpected_format",
                    "message": f"DataFrameQuery returned unexpected type: {type(result_dict)}",
                })
            
        except Exception as qe:
            return json.dumps({
                "error": "query_execution_failed",
                "message": str(qe),
            })

        return json.dumps(rows)
    except Exception as e:  # Last resort safeguard
        return json.dumps({
            "error": "unexpected",
            "message": str(e),
        })
