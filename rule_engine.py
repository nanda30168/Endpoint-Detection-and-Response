import json

class RuleEngine:
    def __init__(self, rules, debug=False):
        self.rules = rules
        self.debug = debug

    def evaluate(self, log_entry):
        alerts = []
        for rule in self.rules:
            if self._matches_condition(log_entry, rule['condition']):
                alerts.append({
                    "rule_id": rule['id'],
                    "rule_name": rule['name'],
                    "severity": rule['severity'],
                    "log_entry": log_entry
                })
        return alerts

    def _matches_condition(self, log_entry, condition):
        try:
            condition_dict = json.loads(condition)
            for key, value in condition_dict.items():
                if key not in log_entry or log_entry[key] != value:
                    return False
            return True
        except Exception as e:
            if self.debug:
                print(f"Error evaluating condition: {e}")
            return False