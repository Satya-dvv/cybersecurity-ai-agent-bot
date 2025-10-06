#!/usr/bin/env python3
"""
CVE Query Example - Cybersecurity AI Agent Bot

This example demonstrates advanced CVE (Common Vulnerabilities and Exposures)
query capabilities including batch lookups, filtering, and detailed analysis.

Author: Satya Jagannadh
Project: Cybersecurity AI Agent Bot
"""

import sys
import os
from datetime import datetime, timedelta

# Add the src directory to the path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.modules.cve_lookup import CVELookup
from src.utils.logger import setup_logger


def single_cve_lookup(cve_lookup):
    """
    Demonstrates single CVE lookup with detailed information
    """
    print("=" * 70)
    print("Single CVE Lookup Example")
    print("=" * 70)
    
    # Example CVE ID - Replace with actual CVE IDs for real queries
    cve_id = "CVE-2024-1234"
    
    print(f"\nQuerying CVE: {cve_id}")
    print("-" * 70)
    
    cve_data = cve_lookup.get_cve_details(cve_id)
    
    if cve_data:
        print(f"\nCVE ID: {cve_data.get('id', 'N/A')}")
        print(f"Description: {cve_data.get('description', 'N/A')}")
        print(f"\nSeverity: {cve_data.get('severity', 'N/A')}")
        print(f"CVSS Score: {cve_data.get('cvss_score', 'N/A')}")
        print(f"CVSS Vector: {cve_data.get('cvss_vector', 'N/A')}")
        print(f"\nPublished Date: {cve_data.get('published_date', 'N/A')}")
        print(f"Last Modified: {cve_data.get('last_modified', 'N/A')}")
        
        # Affected products
        if 'affected_products' in cve_data:
            print(f"\nAffected Products:")
            for product in cve_data['affected_products'][:5]:  # Show first 5
                print(f"  - {product}")
        
        # References
        if 'references' in cve_data:
            print(f"\nReferences:")
            for ref in cve_data['references'][:3]:  # Show first 3
                print(f"  - {ref}")
    else:
        print(f"No information found for {cve_id}")
    
    print("\n" + "=" * 70 + "\n")


def batch_cve_lookup(cve_lookup):
    """
    Demonstrates batch CVE lookup for multiple vulnerabilities
    """
    print("=" * 70)
    print("Batch CVE Lookup Example")
    print("=" * 70)
    
    # List of CVE IDs to query
    cve_ids = [
        "CVE-2024-1234",
        "CVE-2024-5678",
        "CVE-2023-9012",
        "CVE-2023-3456",
        "CVE-2022-7890"
    ]
    
    print(f"\nQuerying {len(cve_ids)} CVEs...\n")
    
    results = cve_lookup.batch_lookup(cve_ids)
    
    # Display summary
    print(f"Results found: {len(results)}")
    print("-" * 70)
    
    for cve_id, data in results.items():
        if data:
            severity = data.get('severity', 'N/A')
            cvss_score = data.get('cvss_score', 'N/A')
            
            # Color code by severity (terminal colors)
            severity_indicator = "●"  # Bullet point
            if severity.lower() == 'critical':
                severity_indicator = "🔴"  # Red circle
            elif severity.lower() == 'high':
                severity_indicator = "🟠"  # Orange circle
            elif severity.lower() == 'medium':
                severity_indicator = "🟡"  # Yellow circle
            elif severity.lower() == 'low':
                severity_indicator = "🟢"  # Green circle
            
            print(f"\n{severity_indicator} {cve_id}")
            print(f"   Severity: {severity} | CVSS: {cvss_score}")
            print(f"   {data.get('description', 'N/A')[:100]}...")
        else:
            print(f"\n⚪ {cve_id} - No data found")
    
    print("\n" + "=" * 70 + "\n")


def search_cves_by_keyword(cve_lookup):
    """
    Demonstrates searching for CVEs by keyword or product
    """
    print("=" * 70)
    print("CVE Search by Keyword Example")
    print("=" * 70)
    
    keywords = ["SQL injection", "Apache", "WordPress", "OpenSSL"]
    
    for keyword in keywords:
        print(f"\nSearching for CVEs related to: '{keyword}'")
        print("-" * 70)
        
        results = cve_lookup.search_by_keyword(keyword, limit=5)
        
        if results:
            print(f"Found {len(results)} CVEs (showing first 5):\n")
            for idx, cve in enumerate(results, 1):
                print(f"{idx}. {cve.get('id', 'N/A')}")
                print(f"   Severity: {cve.get('severity', 'N/A')} | Score: {cve.get('cvss_score', 'N/A')}")
                print(f"   {cve.get('description', 'N/A')[:80]}...\n")
        else:
            print(f"No CVEs found for '{keyword}'\n")
    
    print("=" * 70 + "\n")


def filter_cves_by_severity(cve_lookup):
    """
    Demonstrates filtering CVEs by severity level
    """
    print("=" * 70)
    print("Filter CVEs by Severity Example")
    print("=" * 70)
    
    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    
    for severity in severities:
        print(f"\nQuerying {severity} severity CVEs...")
        print("-" * 70)
        
        # Get recent CVEs of this severity
        results = cve_lookup.get_recent_cves(severity=severity, days=30, limit=5)
        
        if results:
            print(f"Found {len(results)} {severity} CVEs in the last 30 days:\n")
            for idx, cve in enumerate(results, 1):
                print(f"{idx}. {cve.get('id', 'N/A')} (Score: {cve.get('cvss_score', 'N/A')})")
                print(f"   Published: {cve.get('published_date', 'N/A')}")
                print(f"   {cve.get('description', 'N/A')[:70]}...\n")
        else:
            print(f"No {severity} CVEs found\n")
    
    print("=" * 70 + "\n")


def get_cve_statistics(cve_lookup):
    """
    Demonstrates getting statistics about CVEs
    """
    print("=" * 70)
    print("CVE Statistics Example")
    print("=" * 70)
    
    # Get statistics for the last 30 days
    stats = cve_lookup.get_statistics(days=30)
    
    print(f"\nCVE Statistics (Last 30 Days):\n")
    print(f"Total CVEs: {stats.get('total', 0)}")
    print(f"\nBy Severity:")
    severity_counts = stats.get('by_severity', {})
    for severity, count in severity_counts.items():
        print(f"  {severity}: {count}")
    
    print(f"\nTop Affected Vendors:")
    top_vendors = stats.get('top_vendors', [])
    for idx, vendor in enumerate(top_vendors[:5], 1):
        print(f"  {idx}. {vendor['name']}: {vendor['count']} CVEs")
    
    print(f"\nAverage CVSS Score: {stats.get('average_cvss', 'N/A')}")
    
    print("\n" + "=" * 70 + "\n")


def analyze_cve_trends(cve_lookup):
    """
    Demonstrates CVE trend analysis
    """
    print("=" * 70)
    print("CVE Trend Analysis Example")
    print("=" * 70)
    
    # Analyze trends over different time periods
    periods = [7, 30, 90, 365]
    
    print(f"\nCVE Trends Over Time:\n")
    
    for days in periods:
        trends = cve_lookup.get_trend_analysis(days=days)
        
        period_label = f"{days} days" if days < 365 else "1 year"
        print(f"\nLast {period_label}:")
        print(f"  Total CVEs: {trends.get('total', 0)}")
        print(f"  Critical: {trends.get('critical', 0)}")
        print(f"  High: {trends.get('high', 0)}")
        print(f"  Average per day: {trends.get('avg_per_day', 0):.1f}")
        
        # Show trend direction
        trend_direction = trends.get('trend', 'stable')
        trend_emoji = "⬆️" if trend_direction == 'increasing' else "⬇️" if trend_direction == 'decreasing' else "➡️"
        print(f"  Trend: {trend_direction} {trend_emoji}")
    
    print("\n" + "=" * 70 + "\n")


def cve_comparison(cve_lookup):
    """
    Demonstrates comparing multiple CVEs side by side
    """
    print("=" * 70)
    print("CVE Comparison Example")
    print("=" * 70)
    
    # CVEs to compare
    cve_ids = ["CVE-2024-1234", "CVE-2024-5678", "CVE-2023-9012"]
    
    print(f"\nComparing {len(cve_ids)} CVEs:\n")
    
    comparison = cve_lookup.compare_cves(cve_ids)
    
    # Display comparison table
    print(f"{'Attribute':<20} | {' | '.join(cve_ids)}")
    print("-" * 70)
    
    attributes = ['severity', 'cvss_score', 'published_date', 'exploitability']
    
    for attr in attributes:
        values = [str(comparison[cve].get(attr, 'N/A')) for cve in cve_ids]
        print(f"{attr.title():<20} | {' | '.join(values)}")
    
    print("\n" + "=" * 70 + "\n")


def main():
    """
    Main function to run all CVE query examples
    """
    print("\n" + "=" * 70)
    print(" " * 20 + "CVE Query Examples")
    print(" " * 15 + "Cybersecurity AI Agent Bot")
    print("=" * 70 + "\n")
    
    try:
        # Set up logging
        logger = setup_logger('cve_query_example')
        logger.info("Starting CVE query examples")
        
        # Initialize CVE Lookup module
        cve_lookup = CVELookup()
        print("✓ CVE Lookup module initialized\n")
        
        # Run examples
        single_cve_lookup(cve_lookup)
        batch_cve_lookup(cve_lookup)
        search_cves_by_keyword(cve_lookup)
        filter_cves_by_severity(cve_lookup)
        get_cve_statistics(cve_lookup)
        analyze_cve_trends(cve_lookup)
        cve_comparison(cve_lookup)
        
        logger.info("CVE query examples completed successfully")
        
    except Exception as e:
        print(f"\nError occurred: {str(e)}")
        import traceback
        traceback.print_exc()
    
    finally:
        print("\n" + "=" * 70)
        print(" " * 25 + "Examples Complete")
        print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
