"""
Test script for Sigma tool integration.
Tests rule parsing, SPL conversion, and agent routing.
"""

import json
from tools.sigma_tool import SigmaTool


def test_sigma_tool_basic():
    """Test basic Sigma tool functionality."""
    print("=" * 60)
    print("Testing Sigma Tool Integration")
    print("=" * 60)
    
    sigma_tool = SigmaTool()
    
    # Test 1: List rules
    print("\n[TEST 1] Listing Sigma rules...")
    list_query = json.dumps({"action": "list_rules"})
    result = sigma_tool._run(list_query)
    result_data = json.loads(result)
    
    if "error" in result_data:
        print(f"❌ Error: {result_data['error']}")
        print(f"   Message: {result_data.get('message', 'N/A')}")
        print(f"   Hint: {result_data.get('hint', 'N/A')}")
    else:
        print(f"✅ Success: Found {result_data.get('count', 0)} rules")
        if result_data.get('rules'):
            print(f"   Sample rule: {result_data['rules'][0].get('title', 'N/A')}")
    
    # Test 2: Search rules
    print("\n[TEST 2] Searching for 'lateral movement' rules...")
    search_query = json.dumps({"action": "search_rules", "query": "lateral movement"})
    result = sigma_tool._run(search_query)
    result_data = json.loads(result)
    
    if "error" in result_data:
        print(f"❌ Error: {result_data['error']}")
    else:
        print(f"✅ Success: Found {result_data.get('count', 0)} matching rules")
        if result_data.get('rules'):
            for i, rule in enumerate(result_data['rules'][:3], 1):
                print(f"   {i}. {rule.get('title', 'N/A')} (Level: {rule.get('level', 'N/A')})")
    
    # Test 3: Convert to SPL (if rules are available)
    print("\n[TEST 3] Testing SPL conversion...")
    if result_data.get('success') and result_data.get('rules'):
        # Try to convert the first rule
        rule_id = result_data['rules'][0].get('id')
        convert_query = json.dumps({"action": "convert_to_spl", "rule_id": rule_id})
        result = sigma_tool._run(convert_query)
        result_data = json.loads(result)
        
        if "error" in result_data:
            print(f"❌ Conversion error: {result_data['error']}")
            print(f"   Message: {result_data.get('message', 'N/A')}")
        else:
            print(f"✅ Successfully converted rule to SPL")
            print(f"   Rule: {result_data.get('title', 'N/A')}")
            if result_data.get('spl_queries'):
                print(f"   SPL: {result_data['spl_queries'][0][:100]}...")
    else:
        print("⚠️  Skipping SPL conversion (no rules available)")
    
    # Test 4: Check dependencies
    print("\n[TEST 4] Checking dependencies...")
    deps = sigma_tool._check_dependencies()
    print(f"   pySigma installed: {'✅' if deps['pysigma'] else '❌'}")
    print(f"   YAML support: {'✅' if deps['yaml'] else '❌'}")
    print(f"   Sigma repository: {'✅' if deps['sigma_repo'] else '❌'}")
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    print("Sigma tool integration is ready for use.")
    print("\nNext steps:")
    print("1. Install dependencies: pip install pysigma pysigma-backend-splunk pysigma-pipeline-sysmon")
    print("2. Clone Sigma rules: git clone https://github.com/SigmaHQ/sigma /opt/sigma")
    print("3. Or set SIGMA_RULES_PATH environment variable to your Sigma rules directory")
    print("\nOnce configured, you can:")
    print("- List rules: 'List sigma rules'")
    print("- Search rules: 'Show me sigma rules for credential dumping'")
    print("- Convert rules: 'Convert sigma rule <rule_id> to SPL'")
    print("=" * 60)


if __name__ == "__main__":
    test_sigma_tool_basic()
