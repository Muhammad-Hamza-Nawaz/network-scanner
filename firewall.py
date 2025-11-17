from typing import List, Optional
from pydantic import BaseModel


class Rule(BaseModel):
    id: Optional[int] = None
    action: str  # 'allow' or 'deny'
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    priority: int = 100


class Packet(BaseModel):
    src_ip: str
    dst_ip: str
    port: int
    protocol: str


class Firewall:
    def __init__(self):
        # rules stored sorted by priority ascending (lower number = higher priority)
        self._rules: List[Rule] = []
        self._next_id: int = 1
        self.default_action: str = 'allow'
        self._persist_file: Optional[str] = None

    def add_rule(self, rule: Rule) -> Rule:
        # assign an id if missing
        if rule.id is None:
            rule.id = self._next_id
            self._next_id += 1
        # append and sort by priority
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)
        # persist after change
        self._save()
        return rule

    def list_rules(self) -> List[Rule]:
        return self._rules

    def remove_rule(self, rule_id: int) -> bool:
        for i, r in enumerate(self._rules):
            if r.id == rule_id:
                del self._rules[i]
                self._save()
                return True
        return False

    def update_rule(self, rule_id: int, **kwargs) -> Optional[Rule]:
        for r in self._rules:
            if r.id == rule_id:
                # update allowed fields
                for k, v in kwargs.items():
                    if hasattr(r, k) and v is not None:
                        setattr(r, k, v)
                # re-sort by priority in case it changed
                self._rules.sort(key=lambda rr: rr.priority)
                self._save()
                return r
        return None

    def clear_rules(self):
        self._rules = []
        self._save()

    def set_default_action(self, action: str):
        self.default_action = action
        self._save()

    def _match(self, rule: Rule, packet: Packet) -> bool:
        # None or missing fields are wildcards
        if rule.src_ip and rule.src_ip != packet.src_ip:
            return False
        if rule.dst_ip and rule.dst_ip != packet.dst_ip:
            return False
        if rule.port and rule.port != packet.port:
            return False
        if rule.protocol and rule.protocol.lower() != packet.protocol.lower():
            return False
        return True

    def evaluate(self, packet: Packet) -> str:
        # Evaluate rules in priority order. First match wins.
        for r in self._rules:
            if self._match(r, packet):
                return r.action
        # Default action: configurable (default 'allow')
        return self.default_action

    # Persistence helpers
    def enable_persistence(self, filepath: str):
        """Enable persistence to the given JSON file. Loads existing rules if present."""
        import json
        self._persist_file = filepath
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self._rules = [Rule(**r) for r in data.get('rules', [])]
            # compute next id
            max_id = 0
            for r in self._rules:
                if r.id and r.id > max_id:
                    max_id = r.id
            self._next_id = max_id + 1
            self.default_action = data.get('default_action', self.default_action)
            # ensure rules sorted
            self._rules.sort(key=lambda r: r.priority)
        except FileNotFoundError:
            # no existing file, create on first save
            self._save()

    def _save(self):
        import json
        if not self._persist_file:
            return
        data = {
            'default_action': self.default_action,
            'rules': [r.dict() for r in self._rules]
        }
        with open(self._persist_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
