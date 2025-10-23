"""
VirusTotal integration tool for threat intelligence lookups.
Supports IP addresses, file hashes (MD5/SHA1/SHA256), and URLs.
"""
import os
import requests
from typing import Literal


def check_virustotal(
    ioc: str,
    ioc_type: Literal["ip", "hash", "url"] = "hash",
    api_key: str | None = None
) -> dict:
    """
    Query VirusTotal for threat intelligence on an IP, hash, or URL.
    
    Args:
        ioc: The indicator of compromise (IP address, file hash, or URL).
        ioc_type: One of "ip", "hash", or "url".
        api_key: VirusTotal API key. If not provided, reads from VT_API_KEY env var.
    
    Returns:
        dict with:
        - success: bool
        - ioc: str (the queried IOC)
        - ioc_type: str
        - malicious: int (number of vendors flagging as malicious)
        - total: int (total vendors scanned)
        - permalink: str (link to VirusTotal report)
        - error: str (if request failed)
    """
    if api_key is None:
        api_key = os.getenv("VT_API_KEY")
    
    if not api_key:
        return {
            "success": False,
            "error": "VT_API_KEY not set",
            "ioc": ioc,
            "ioc_type": ioc_type,
        }
    
    headers = {"x-apikey": api_key}
    base_url = "https://www.virustotal.com/api/v3"
    
    # Determine endpoint based on IOC type
    if ioc_type == "ip":
        endpoint = f"{base_url}/ip_addresses/{ioc}"
    elif ioc_type == "url":
        # URL lookups require URL-safe base64 encoding (no padding)
        import base64
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        endpoint = f"{base_url}/urls/{url_id}"
    else:  # hash
        endpoint = f"{base_url}/files/{ioc}"
    
    try:
        resp = requests.get(endpoint, headers=headers, timeout=10)
        if resp.status_code == 404:
            return {
                "success": True,
                "ioc": ioc,
                "ioc_type": ioc_type,
                "malicious": 0,
                "total": 0,
                "permalink": "",
                "message": "Not found in VirusTotal database",
            }
        resp.raise_for_status()
        data = resp.json()
        
        # Extract last_analysis_stats
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total_vendors = sum(stats.values()) if stats else 0
        
        # Permalink (if available in links)
        permalink = data.get("data", {}).get("links", {}).get("self", "")
        
        return {
            "success": True,
            "ioc": ioc,
            "ioc_type": ioc_type,
            "malicious": malicious,
            "total": total_vendors,
            "permalink": permalink,
            "stats": stats,
        }
    except requests.exceptions.HTTPError as e:
        return {
            "success": False,
            "error": f"HTTP {e.response.status_code}: {e.response.text}",
            "ioc": ioc,
            "ioc_type": ioc_type,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "ioc": ioc,
            "ioc_type": ioc_type,
        }
