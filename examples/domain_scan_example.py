#!/usr/bin/env python3
"""
Domain Scanning Example - Security Assessment Demonstrations
"""

from src.modules.vuln_scanner import VulnerabilityScanner
from src.config.settings import load_settings

def main():
    """Demonstrate domain vulnerability scanning capabilities"""

    print("🌐 Domain Vulnerability Scanner - Examples")
    print("=" * 45)

    # Initialize vulnerability scanner
    config = load_settings()
    scanner = VulnerabilityScanner(config)

    # Example domains for scanning (use responsibly!)
    example_domains = [
        "example.com",      # Safe test domain
        "httpforever.com",  # HTTP-only test site
        "badssl.com",       # SSL testing site
        "testfire.net"      # Security testing site
    ]

    print("\n⚠️ IMPORTANT NOTICE:")
    print("Only scan domains you own or have explicit permission to test!")
    print("These examples use publicly available test domains.")
    print("=" * 60)

    for domain in example_domains:
        print(f"\n🔍 Scanning Domain: {domain}")
        print("-" * 40)

        try:
            result = scanner.scan_domain(domain)
            print(result)
        except Exception as e:
            print(f"❌ Scan failed for {domain}: {e}")

        print("\n" + "="*60)

    # Demonstrate individual scan components
    print("\n🔧 Individual Scan Component Examples:")
    print("-" * 45)

    test_domain = "example.com"

    # DNS resolution test
    print(f"\n1️⃣ DNS Resolution for {test_domain}:")
    dns_info = scanner._get_dns_info(test_domain)
    print(f"Result: {dns_info}")

    # SSL analysis test
    print(f"\n2️⃣ SSL Analysis for {test_domain}:")
    ssl_info = scanner._analyze_ssl(test_domain)
    print(f"Result: {ssl_info}")

    print("\n✅ Domain scanning examples completed!")
    print("\n🔒 Remember: Always scan responsibly and ethically!")

if __name__ == "__main__":
    main()
