import os
import json
import yaml
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path
from langchain.tools import BaseTool

logger = logging.getLogger(__name__)

class SigmaTool(BaseTool):
    name: str = "sigma_rule"
    description: str = (
        "Search, parse, and convert Sigma detection rules to SPL (Splunk) or VQL (Velociraptor) queries. "
        "Use this to leverage community threat detection rules for automated hunting. "
        "Input should be a JSON string with 'action' ('list_rules', 'get_rule', 'convert_to_spl', 'convert_to_vql', 'search_rules'), "
        "and optionally 'rule_id', 'category', 'technique_id', or 'query'."
    )
    sigma_repo_path: str = ""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.sigma_repo_path = os.getenv("SIGMA_RULES_PATH", "/opt/sigma/rules")
        self._check_dependencies()
    
    def _check_dependencies(self) -> Dict[str, bool]:
        """Check if required dependencies are available."""
        deps = {
            "pysigma": False,
            "yaml": False,
            "sigma_repo": False
        }
        
        try:
            import sigma
            deps["pysigma"] = True
        except ImportError:
            pass
        
        try:
            import yaml
            deps["yaml"] = True
        except ImportError:
            pass
        
        if os.path.isdir(self.sigma_repo_path):
            deps["sigma_repo"] = True
        
        return deps
    
    def _run(self, query: str) -> str:
        """Execute the Sigma tool."""
        try:
            params = json.loads(query)
        except json.JSONDecodeError:
            return json.dumps({"error": "Input must be a valid JSON string"})
        
        action = params.get("action")
        
        if action == "list_rules":
            category = params.get("category")
            technique_id = params.get("technique_id")
            return self.list_rules(category=category, technique_id=technique_id)
        elif action == "get_rule":
            rule_id = params.get("rule_id")
            if not rule_id:
                return json.dumps({"error": "'rule_id' is required for get_rule"})
            return self.get_rule(rule_id)
        elif action == "convert_to_spl":
            rule_id = params.get("rule_id")
            if not rule_id:
                return json.dumps({"error": "'rule_id' is required for convert_to_spl"})
            return self.convert_to_spl(rule_id)
        elif action == "convert_to_vql":
            rule_id = params.get("rule_id")
            if not rule_id:
                return json.dumps({"error": "'rule_id' is required for convert_to_vql"})
            return self.convert_to_vql(rule_id)
        elif action == "search_rules":
            search_query = params.get("query")
            if not search_query:
                return json.dumps({"error": "'query' is required for search_rules"})
            return self.search_rules(search_query)
        else:
            return json.dumps({
                "error": f"Unknown action '{action}'",
                "valid_actions": ["list_rules", "get_rule", "convert_to_spl", "convert_to_vql", "search_rules"]
            })
    
    def _find_sigma_rules(self, category: Optional[str] = None, technique_id: Optional[str] = None) -> List[Path]:
        """Find Sigma rule files in the repository."""
        if not os.path.isdir(self.sigma_repo_path):
            return []
        
        rules_path = Path(self.sigma_repo_path)
        rule_files = []
        
        # Search for .yml and .yaml files
        for ext in ["*.yml", "*.yaml"]:
            rule_files.extend(rules_path.rglob(ext))
        
        # Filter by category or technique if specified
        if category or technique_id:
            filtered = []
            for rule_file in rule_files:
                if category and category.lower() in str(rule_file).lower():
                    filtered.append(rule_file)
                elif technique_id and technique_id.upper() in str(rule_file).upper():
                    filtered.append(rule_file)
            return filtered
        
        return rule_files
    
    def _parse_sigma_rule(self, rule_path: Path) -> Optional[Dict[str, Any]]:
        """Parse a Sigma rule YAML file."""
        try:
            with open(rule_path, 'r', encoding='utf-8') as f:
                rule_data = yaml.safe_load(f)
            
            if not rule_data or not isinstance(rule_data, dict):
                return None
            
            # Extract key metadata
            metadata = {
                "id": rule_data.get("id", str(rule_path.stem)),
                "title": rule_data.get("title", "Untitled"),
                "description": rule_data.get("description", ""),
                "status": rule_data.get("status", "unknown"),
                "level": rule_data.get("level", "medium"),
                "tags": rule_data.get("tags", []),
                "logsource": rule_data.get("logsource", {}),
                "detection": rule_data.get("detection", {}),
                "falsepositives": rule_data.get("falsepositives", []),
                "references": rule_data.get("references", []),
                "path": str(rule_path)
            }
            
            return metadata
        except Exception as e:
            logger.error(f"Error parsing Sigma rule {rule_path}: {e}")
            return None
    
    def list_rules(self, category: Optional[str] = None, technique_id: Optional[str] = None) -> str:
        """List available Sigma rules."""
        deps = self._check_dependencies()
        if not deps["sigma_repo"]:
            return json.dumps({
                "error": "Sigma rules repository not found",
                "message": f"Repository path not found: {self.sigma_repo_path}",
                "hint": "Set SIGMA_RULES_PATH environment variable or clone https://github.com/SigmaHQ/sigma"
            })
        
        rule_files = self._find_sigma_rules(category=category, technique_id=technique_id)
        
        rules_list = []
        for rule_file in rule_files[:100]:  # Limit to 100 rules
            metadata = self._parse_sigma_rule(rule_file)
            if metadata:
                rules_list.append({
                    "id": metadata["id"],
                    "title": metadata["title"],
                    "level": metadata["level"],
                    "tags": metadata["tags"][:5],  # Limit tags
                    "path": metadata["path"]
                })
        
        return json.dumps({
            "success": True,
            "count": len(rules_list),
            "total_found": len(rule_files),
            "rules": rules_list,
            "category": category,
            "technique_id": technique_id
        })
    
    def get_rule(self, rule_id: str) -> str:
        """Get detailed information about a specific Sigma rule."""
        deps = self._check_dependencies()
        if not deps["sigma_repo"]:
            return json.dumps({
                "error": "Sigma rules repository not found",
                "message": f"Repository path not found: {self.sigma_repo_path}"
            })
        
        # Search for rule by ID or filename
        rule_files = self._find_sigma_rules()
        
        for rule_file in rule_files:
            metadata = self._parse_sigma_rule(rule_file)
            if metadata and (metadata["id"] == rule_id or rule_file.stem == rule_id):
                return json.dumps({
                    "success": True,
                    "rule": metadata
                })
        
        return json.dumps({
            "error": "Rule not found",
            "message": f"No rule found with ID or filename: {rule_id}"
        })
    
    def convert_to_spl(self, rule_id: str) -> str:
        """Convert a Sigma rule to Splunk SPL query."""
        deps = self._check_dependencies()
        if not deps["pysigma"]:
            return json.dumps({
                "error": "pySigma library not installed",
                "message": "Install with: pip install pysigma pysigma-backend-splunk"
            })
        
        if not deps["sigma_repo"]:
            return json.dumps({
                "error": "Sigma rules repository not found",
                "message": f"Repository path not found: {self.sigma_repo_path}"
            })
        
        try:
            from sigma.collection import SigmaCollection
            from sigma.backends.splunk import SplunkBackend
            from sigma.pipelines.splunk import splunk_windows_pipeline
        except ImportError as e:
            return json.dumps({
                "error": "pySigma import failed",
                "message": str(e),
                "hint": "Install with: pip install pysigma pysigma-backend-splunk pysigma-pipeline-sysmon"
            })
        
        # Find the rule file
        rule_files = self._find_sigma_rules()
        rule_path = None
        
        for rf in rule_files:
            metadata = self._parse_sigma_rule(rf)
            if metadata and (metadata["id"] == rule_id or rf.stem == rule_id):
                rule_path = rf
                break
        
        if not rule_path:
            return json.dumps({
                "error": "Rule not found",
                "message": f"No rule found with ID or filename: {rule_id}"
            })
        
        try:
            # Load and convert the rule
            with open(rule_path, 'r', encoding='utf-8') as f:
                rule_content = f.read()
            
            sigma_rule = SigmaCollection.from_yaml(rule_content)
            backend = SplunkBackend(processing_pipeline=splunk_windows_pipeline())
            spl_queries = backend.convert(sigma_rule)
            
            # Get rule metadata
            metadata = self._parse_sigma_rule(rule_path)
            
            return json.dumps({
                "success": True,
                "rule_id": rule_id,
                "title": metadata.get("title", ""),
                "spl_queries": spl_queries if isinstance(spl_queries, list) else [spl_queries],
                "metadata": {
                    "level": metadata.get("level"),
                    "tags": metadata.get("tags", [])[:5]
                }
            })
        except Exception as e:
            return json.dumps({
                "error": "Conversion failed",
                "message": str(e),
                "rule_id": rule_id
            })
    
    def convert_to_vql(self, rule_id: str) -> str:
        """Convert a Sigma rule to Velociraptor VQL query (limited support)."""
        # VQL conversion is limited because Sigma is primarily for log analysis
        # We can only convert rules that target endpoint artifacts
        
        deps = self._check_dependencies()
        if not deps["sigma_repo"]:
            return json.dumps({
                "error": "Sigma rules repository not found",
                "message": f"Repository path not found: {self.sigma_repo_path}"
            })
        
        # Find the rule
        rule_files = self._find_sigma_rules()
        rule_path = None
        
        for rf in rule_files:
            metadata = self._parse_sigma_rule(rf)
            if metadata and (metadata["id"] == rule_id or rf.stem == rule_id):
                rule_path = rf
                break
        
        if not rule_path:
            return json.dumps({
                "error": "Rule not found",
                "message": f"No rule found with ID or filename: {rule_id}"
            })
        
        metadata = self._parse_sigma_rule(rule_path)
        logsource = metadata.get("logsource", {})
        category = logsource.get("category", "").lower()
        product = logsource.get("product", "").lower()
        
        # Check if rule is convertible to VQL
        vql_compatible = category in ["process_creation", "file_event", "registry_event", "network_connection"]
        
        if not vql_compatible:
            return json.dumps({
                "error": "VQL conversion not supported",
                "message": f"Rule category '{category}' is not compatible with VQL. Use SPL conversion instead.",
                "rule_id": rule_id,
                "hint": "VQL conversion only supports: process_creation, file_event, registry_event, network_connection"
            })
        
        # Basic VQL conversion for process creation rules
        if category == "process_creation":
            detection = metadata.get("detection", {})
            selection = detection.get("selection", {})
            
            # Build a simple VQL query
            vql_parts = ["SELECT * FROM pslist()"]
            
            # Add WHERE clauses based on detection logic
            where_clauses = []
            if "CommandLine" in selection:
                cmd = selection["CommandLine"]
                if isinstance(cmd, list):
                    cmd = cmd[0]
                where_clauses.append(f"CommandLine =~ '{cmd}'")
            
            if "Image" in selection:
                img = selection["Image"]
                if isinstance(img, list):
                    img = img[0]
                where_clauses.append(f"Exe =~ '{img}'")
            
            if where_clauses:
                vql_parts.append("WHERE " + " AND ".join(where_clauses))
            
            vql_query = " ".join(vql_parts)
            
            return json.dumps({
                "success": True,
                "rule_id": rule_id,
                "title": metadata.get("title", ""),
                "vql_query": vql_query,
                "warning": "VQL conversion is basic and may not capture all detection logic. Review before use.",
                "metadata": {
                    "level": metadata.get("level"),
                    "tags": metadata.get("tags", [])[:5]
                }
            })
        
        return json.dumps({
            "error": "VQL conversion not implemented",
            "message": f"VQL conversion for category '{category}' is not yet implemented",
            "rule_id": rule_id
        })
    
    def search_rules(self, query: str) -> str:
        """Search Sigma rules by keyword."""
        deps = self._check_dependencies()
        if not deps["sigma_repo"]:
            return json.dumps({
                "error": "Sigma rules repository not found",
                "message": f"Repository path not found: {self.sigma_repo_path}"
            })
        
        rule_files = self._find_sigma_rules()
        matching_rules = []
        
        query_lower = query.lower()
        
        for rule_file in rule_files[:500]:  # Limit search scope
            metadata = self._parse_sigma_rule(rule_file)
            if not metadata:
                continue
            
            # Search in title, description, and tags
            title = metadata.get("title", "").lower()
            description = metadata.get("description", "").lower()
            tags = " ".join(metadata.get("tags", [])).lower()
            
            if query_lower in title or query_lower in description or query_lower in tags:
                matching_rules.append({
                    "id": metadata["id"],
                    "title": metadata["title"],
                    "level": metadata["level"],
                    "tags": metadata["tags"][:5],
                    "description": metadata["description"][:200]
                })
        
        return json.dumps({
            "success": True,
            "query": query,
            "count": len(matching_rules),
            "rules": matching_rules[:50]  # Limit results
        })
