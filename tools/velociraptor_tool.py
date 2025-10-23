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
            # pyvelociraptor API has changed over releases; try common entrypoints.
            from pyvelociraptor import api_client as vapi  # type: ignore
        except Exception as ie:
            return json.dumps({
                "error": "pyvelociraptor_import",
                "message": f"pyvelociraptor not installed or failed to import: {ie}",
            })

        client = None
        try:
            # Preferred: factory from config file
            if hasattr(vapi, "VeloGrpcClient") and hasattr(vapi.VeloGrpcClient, "FromConfigFile"):
                client = vapi.VeloGrpcClient.FromConfigFile(cfg)  # type: ignore[attr-defined]
            elif hasattr(vapi, "from_config"):
                client = vapi.from_config(cfg)  # type: ignore[attr-defined]
            else:
                return json.dumps({
                    "error": "client_init_unavailable",
                    "message": "pyvelociraptor API does not expose a known factory. Update package.",
                })
        except Exception as e:
            return json.dumps({
                "error": "client_init_failed",
                "message": str(e),
            })

        rows = []
        try:
            # Execute query; normalize rows to dicts if possible
            if hasattr(client, "Query"):
                iterator = client.Query(vql_query)  # type: ignore[attr-defined]
            elif hasattr(client, "query"):
                iterator = client.query(vql_query)  # type: ignore[attr-defined]
            else:
                return json.dumps({
                    "error": "query_method_missing",
                    "message": "Client does not expose Query/query method.",
                })

            for row in iterator:
                if isinstance(row, dict):
                    rows.append(row)
                else:
                    try:
                        rows.append(dict(row))
                    except Exception:
                        rows.append({"value": str(row)})
        except Exception as qe:
            return json.dumps({
                "error": "query_failed",
                "message": str(qe),
            })
        finally:
            try:
                if hasattr(client, "Close"):
                    client.Close()  # type: ignore[attr-defined]
                elif hasattr(client, "close"):
                    client.close()  # type: ignore[attr-defined]
            except Exception:
                pass

        return json.dumps(rows)
    except Exception as e:  # Last resort safeguard
        return json.dumps({
            "error": "unexpected",
            "message": str(e),
        })
