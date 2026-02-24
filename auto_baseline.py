#!/usr/bin/env python3
import sys
import json
import yaml
import os

WHITELIST_PATH = "/opt/CAPEv2/modules/processing/whitelist.yaml"
REPORTS_DIR = "/opt/CAPEv2/storage/analyses"

def extract_baseline(task_id):
    report_path = os.path.join(REPORTS_DIR, str(task_id), "reports", "report.json")
    if not os.path.exists(report_path):
        print(f"[-] Report not found for task {task_id}: {report_path}")
        sys.exit(1)

    print(f"[*] Reading report from task {task_id}...")
    with open(report_path, "r") as f:
        try:
            report = json.load(f)
        except Exception as e:
            print(f"[-] Failed to parse JSON: {e}")
            sys.exit(1)

    print("[*] Loading existing whitelist...")
    if os.path.exists(WHITELIST_PATH):
        with open(WHITELIST_PATH, "r") as f:
            whitelist = yaml.safe_load(f) or {}
    else:
        whitelist = {}

    def add_to_whitelist(category, item):
        if category not in whitelist:
            whitelist[category] = {"exact_match": [], "regex": []}
        if "exact_match" not in whitelist[category]:
            whitelist[category]["exact_match"] = []
            
        if item not in whitelist[category]["exact_match"]:
            whitelist[category]["exact_match"].append(item)
            return True
        return False

    added_count = 0

    # Extract Behavior
    summary = report.get("behavior", {}).get("summary", {})
    behavior_keys = [
        "read_keys", "write_keys", "delete_keys", 
        "read_files", "write_files", "delete_files",
        "mutexes", "executed_commands"
    ]
    for key in behavior_keys:
        items = summary.get(key, [])
        for item in items:
            if add_to_whitelist(key, item):
                added_count += 1

    # Extract Network
    network = report.get("network", {})
    
    for domain_obj in network.get("domains", []):
        if isinstance(domain_obj, dict) and "domain" in domain_obj:
            if add_to_whitelist("network_domains", domain_obj["domain"]):
                added_count += 1
            
    for host_obj in network.get("hosts", []):
        if isinstance(host_obj, dict) and "ip" in host_obj:
            if add_to_whitelist("network_hosts", host_obj["ip"]):
                added_count += 1

    for http_obj in network.get("http", []):
        if isinstance(http_obj, dict) and "uri" in http_obj:
            if add_to_whitelist("network_http", http_obj["uri"]):
                added_count += 1

    print(f"[*] Added {added_count} new exact_match items to baseline.")

    # Save back
    with open(WHITELIST_PATH, "w") as f:
        yaml.dump(whitelist, f, default_flow_style=False, sort_keys=False)
    print(f"[+] Updated {WHITELIST_PATH}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: auto_baseline.py <task_id>")
        sys.exit(1)
    extract_baseline(sys.argv[1])
