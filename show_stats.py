#!/usr/bin/env python3
"""
CAPE Noise Filter - Report Summary Tool
Displays a concise comparison of kept (malicious/unknown) vs. filtered (noise) 
artifacts from a CAPEv2 analysis report.

Usage:
  python3 show_stats.py <path_to_report.json>
  
Example:
  python3 show_stats.py /srv/cape/storage/analyses/12/reports/report.json
"""

import json
import sys
import os

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 show_stats.py <path_to_report.json>")
        sys.exit(1)

    report_path = sys.argv[1]
    
    if not os.path.exists(report_path):
        print(f"Error: File not found - {report_path}")
        sys.exit(1)

    try:
        with open(report_path, "r") as f:
            data = json.load(f)
            
        nf = data.get("noise_filter", {})
        filtered_art = nf.get("filtered_artifacts", {}).get("behavior", {})
        behavior_summary = data.get("behavior", {}).get("summary", {})
        
        # Calculate totals
        remaining_count = sum(len(v) for v in behavior_summary.values() if isinstance(v, list))
        filtered_count = sum(len(v) for v in filtered_art.values() if isinstance(v, list))
        before_count = remaining_count + filtered_count
        
        print("\n" + "="*60)
        print(" 🔍 CAPE NOISE FILTER : INTERNAL DATA COMPARISON")
        print("="*60)
        print(f"Total API/Artifacts BEFORE Filtering : {before_count}")
        print(f"Noise Artifacts FILTERED OUT         : {filtered_count}")
        print(f"Total Artifacts AFTER Filtering      : {remaining_count}")
        print("="*60)
        
        # 1. Compare Write Files
        print("\n[📁 File Writes - write_files]")
        remaining_files = behavior_summary.get("write_files", [])
        filtered_files = filtered_art.get("write_files", [])
        
        print(f"  ✅ KEPT (Clean/Malicious Potential): {len(remaining_files)} items")
        for f in remaining_files[:5]:
            print(f"      + {f}")
        if len(remaining_files) > 5:
            print("      ... (more)")
            
        print(f"\n  ❌ FILTERED OUT (Windows Noise): {len(filtered_files)} items")
        for f in filtered_files[:5]:
            print(f"      - {f}")
        if len(filtered_files) > 5:
            print("      ... (more)")


        # 2. Compare Read Keys
        print("\n[🔑 Registry Reads - read_keys]")
        remaining_keys = behavior_summary.get("read_keys", [])
        filtered_keys = filtered_art.get("read_keys", [])
        
        print(f"  ✅ KEPT (Clean/Malicious Potential): {len(remaining_keys)} items")
        for k in remaining_keys[:5]:
            print(f"      + {k}")
        if len(remaining_keys) > 5:
            print("      ... (more)")
            
        print(f"\n  ❌ FILTERED OUT (Windows Noise): {len(filtered_keys)} items")
        for k in filtered_keys[:5]:
            print(f"      - {k}")
        if len(filtered_keys) > 5:
            print("      ... (more)")

        # 3. Compare Mutexes
        print("\n[🔒 Mutexes - mutexes]")
        remaining_mutex = behavior_summary.get("mutexes", [])
        filtered_mutex = filtered_art.get("mutexes", [])
        
        print(f"  ✅ KEPT (Clean/Malicious Potential): {len(remaining_mutex)} items")
        for m in remaining_mutex[:5]:
            print(f"      + {m}")
        if len(remaining_mutex) > 5:
            print("      ... (more)")
            
        print(f"\n  ❌ FILTERED OUT (Windows Noise): {len(filtered_mutex)} items")
        for m in filtered_mutex[:5]:
            print(f"      - {m}")
        if len(filtered_mutex) > 5:
            print("      ... (more)")

        print("\n" + "="*60)
                
    except Exception as e:
        print(f"Error parsing report: {e}")

if __name__ == "__main__":
    main()
