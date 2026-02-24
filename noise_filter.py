import re
import yaml
import logging
import os

from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)

class NoiseFilter(Processing):
    """Filter out known OS and VM baseline noise from behavioral and network data."""

    order = 3
    key = "noise_filter"

    def load_whitelist(self):
        rule_path = "/opt/CAPEv2/modules/processing/whitelist.yaml"
        try:
            if os.path.exists(rule_path):
                with open(rule_path, "r") as f:
                    return yaml.safe_load(f) or {}
            return {}
        except Exception as e:
            log.error(f"Failed to load whitelist.yaml: {e}")
            return {}

    def match_rule(self, item, rules):
        if not item or not rules:
            return False
        
        check_val = item
        if isinstance(item, dict):
            if 'domain' in item: check_val = item['domain']
            elif 'ip' in item: check_val = item['ip']
            elif 'uri' in item: check_val = item['uri']
            elif 'host' in item: check_val = item['host']
            else: check_val = str(item)

        exact_matches = rules.get("exact_match") or []
        if check_val in exact_matches:
            return True
            
        for pattern in rules.get("regex", []):
            try:
                if re.match(pattern, check_val, re.IGNORECASE):
                    return True
            except re.error:
                continue
        return False

    def run(self):
        results = {
            "status": "skipped",
            "filtered_items_count": 0,
            "filtered_artifacts": {}
        }

        rules = self.load_whitelist()
        if not rules:
            results["reason"] = "No whitelist loaded"
            return results

        filtered_total = 0

        # 1. Behavior Summary Filtering
        if "behavior" in self.results and "summary" in self.results["behavior"]:
            summary = self.results["behavior"]["summary"]
            behavior_keys = [
                "read_keys", "write_keys", "delete_keys", 
                "read_files", "write_files", "delete_files",
                "mutexes", "executed_commands"
            ]

            for b_key in behavior_keys:
                if b_key in summary and isinstance(summary[b_key], list):
                    new_items = []
                    filtered_items = []
                    rule_category = b_key
                    
                    for item in summary[b_key]:
                        if self.match_rule(item, rules.get(rule_category, {})):
                            filtered_items.append(item)
                            filtered_total += 1
                        else:
                            new_items.append(item)
                    
                    if filtered_items:
                        self.results["behavior"]["summary"][b_key] = new_items
                        if "behavior" not in results["filtered_artifacts"]:
                            results["filtered_artifacts"]["behavior"] = {}
                        results["filtered_artifacts"]["behavior"][b_key] = filtered_items

        # 2. Network Filtering
        if "network" in self.results:
            network = self.results["network"]
            network_keys = ["domains", "hosts", "http"]

            for n_key in network_keys:
                if n_key in network and isinstance(network[n_key], list):
                    new_items = []
                    filtered_items = []
                    rule_category = f"network_{n_key}"
                    
                    for item in network[n_key]:
                        if self.match_rule(item, rules.get(rule_category, {})):
                            filtered_items.append(item)
                            filtered_total += 1
                        else:
                            new_items.append(item)
                    
                    if filtered_items:
                        self.results["network"][n_key] = new_items
                        if "network" not in results["filtered_artifacts"]:
                            results["filtered_artifacts"]["network"] = {}
                        results["filtered_artifacts"]["network"][n_key] = filtered_items

        results["status"] = "success"
        results["filtered_items_count"] = filtered_total
        
        log.info(f"Noise Filter applied. Removed {filtered_total} noisy items safely.")
        return results