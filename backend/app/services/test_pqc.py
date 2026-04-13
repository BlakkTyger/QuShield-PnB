import json
from app.services.pqcscan_client import run_pqcscan_tls

def test_domain(domain):
    print(f"--- Scanning {domain} for PQC Support ---")
    
    # Run the scan
    result = run_pqcscan_tls(domain, 443)
    
    if result.get("subprocess_error"):
        print(f"Subprocess Error: {result['subprocess_error']}")
        return

    # Check findings
    print(f"Status: {'Success' if result['ok'] else 'Failed'}")
    print(f"PQC Supported: {result['pqc_supported']}")
    print(f"Hybrid Algos: {result['hybrid_algos']}")
    print(f"Pure PQC Algos: {result['pqc_algos']}")
    
    # Print the full command used for debugging
    print(f"Command run: {' '.join(result.get('command', []))}")

if __name__ == "__main__":
    # Test a known domain or a local target
    test_domain("google.com")