"""
Zero-Trust Autonomous Agent Sandbox (ZT-AAS) - Core Sandbox Runtime
"""

from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
from datetime import datetime
import hashlib

# --- Types and Enums ---

class ActionType(Enum):
    READ = "read"
    WRITE = "write"
    CALL = "call"
    EMIT = "emit"
    MUTATE = "mutate"
    NETWORK = "network"
    FILE = "file"

class ActionStatus(Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    QUARANTINED = "quarantined"
    TERMINATED = "terminated"

@dataclass
class Capability:
    id: str
    action_type: ActionType
    target: str
    constraints: Dict[str, Any] = field(default_factory=dict)
    duration: Optional[int] = None  # seconds
    issued_at: datetime = field(default_factory=datetime.now)
    revoked: bool = False

@dataclass
class ActionRequest:
    capability_id: str
    agent_id: str
    action_type: ActionType
    target: str
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class ActionOutcome:
    request: ActionRequest
    status: ActionStatus
    result: Optional[Any] = None
    error: Optional[str] = None
    side_effects: List[str] = field(default_factory=list)
    resource_usage: Dict[str, Any] = field(default_factory=dict)
    sequence_number: int = 0  # For audit log integrity
    hash_chain: str = ""  # Hash of previous entry + current

# --- Core Sandbox Runtime ---

class SandboxRuntime:
    def __init__(self):
        self.capabilities: Dict[str, Capability] = {}
        self.policy_engine = PolicyEngine()
        self.mediator = ActionMediator()
        self.audit_log = AuditLog()
        self.active_agents: Dict[str, bool] = {}
        self.quarantined_agents: Dict[str, bool] = {}

    def register_agent(self, agent_id: str) -> None:
        """Register an agent with the sandbox."""
        if agent_id in self.active_agents:
            raise ValueError(f"Agent {agent_id} already registered")
        self.active_agents[agent_id] = True

    def issue_capability(self, capability: Capability) -> None:
        """Issue a new capability to the sandbox."""
        if capability.id in self.capabilities:
            raise ValueError(f"Capability {capability.id} already exists")
        self.capabilities[capability.id] = capability

    def execute_action(self, request: ActionRequest) -> ActionOutcome:
        """Execute an action on behalf of an agent."""
        # Check quarantine status first
        if request.agent_id in self.quarantined_agents:
            return self._quarantine_action(request, "Agent is quarantined")

        # Validate agent
        if request.agent_id not in self.active_agents:
            return self._deny_action(request, "Agent not registered")

        # Check capability exists and is valid
        capability = self.capabilities.get(request.capability_id)
        if not capability:
            return self._deny_action(request, "Capability not found")

        # Check expiration
        if capability.duration is not None:
            elapsed = (datetime.now() - capability.issued_at).total_seconds()
            if elapsed > capability.duration:
                self._revoke_capability(capability.id)
                return self._deny_action(request, "Capability expired")

        # Validate scope strictly
        if not self._validate_scope(request, capability):
            return self._deny_action(request, "Scope violation: action type or target mismatch")

        # Validate policy
        policy_result = self.policy_engine.validate_request(request, capability)
        if not policy_result.is_allowed:
            return self._deny_action(request, f"Policy violation: {policy_result.reason}")

        # Mediate action
        outcome = self.mediator.handle_action(request, capability)
        
        # Log outcome
        self.audit_log.log(outcome)
        
        return outcome

    def _validate_scope(self, request: ActionRequest, capability: Capability) -> bool:
        """Strictly validate that the request matches the capability scope."""
        if request.action_type != capability.action_type:
            return False
        # For file operations, check exact match or prefix match
        if capability.action_type in [ActionType.FILE, ActionType.READ, ActionType.WRITE]:
            return request.target == capability.target
        # For network, allow domain-based matching
        elif capability.action_type == ActionType.NETWORK:
            return request.target == capability.target
        # For other actions, exact match
        else:
            return request.target == capability.target

    def _deny_action(self, request: ActionRequest, reason: str) -> ActionOutcome:
        outcome = ActionOutcome(
            request=request,
            status=ActionStatus.DENIED,
            error=reason
        )
        self.audit_log.log(outcome)
        return outcome

    def _quarantine_action(self, request: ActionRequest, reason: str) -> ActionOutcome:
        outcome = ActionOutcome(
            request=request,
            status=ActionStatus.QUARANTINED,
            error=reason
        )
        self.audit_log.log(outcome)
        return outcome

    def _revoke_capability(self, capability_id: str) -> bool:
        """Revoke a capability immediately."""
        if capability_id in self.capabilities:
            self.capabilities[capability_id].revoked = True
            return True
        return False

    def quarantine_agent(self, agent_id: str) -> None:
        """Quarantine an agent from further actions."""
        self.quarantined_agents[agent_id] = True

# --- Policy Engine ---

@dataclass
class PolicyValidationResult:
    is_allowed: bool
    reason: Optional[str] = None

class PolicyEngine:
    def validate_request(self, request: ActionRequest, capability: Capability) -> PolicyValidationResult:
        # Example policy checks
        if capability.action_type == ActionType.NETWORK:
            if not self._is_network_allowed(capability.target):
                return PolicyValidationResult(False, "Network access not permitted")
        
        if capability.action_type == ActionType.FILE:
            if not self._is_file_access_allowed(capability.target):
                return PolicyValidationResult(False, "File access not permitted")

        # Check constraints
        if 'max_size' in capability.constraints:
            if request.action_type == ActionType.WRITE and len(str(request.target)) > capability.constraints['max_size']:
                return PolicyValidationResult(False, "Write exceeds size limit")

        return PolicyValidationResult(True)

    def _is_network_allowed(self, domain: str) -> bool:
        # Example: only allow specific domains
        allowed_domains = ["api.example.com", "data.example.com"]
        return any(domain.endswith(allowed) for allowed in allowed_domains)

    def _is_file_access_allowed(self, path: str) -> bool:
        # Example: only allow access to specific directories
        allowed_prefixes = ["/tmp/", "/data/"]
        return any(path.startswith(prefix) for prefix in allowed_prefixes)

# --- Action Mediator ---

class ActionMediator:
    def handle_action(self, request: ActionRequest, capability: Capability) -> ActionOutcome:
        try:
            # Simulate action execution
            if request.action_type == ActionType.READ:
                result = self._read_file(request.target)
            elif request.action_type == ActionType.WRITE:
                result = self._write_file(request.target)
            elif request.action_type == ActionType.CALL:
                result = self._call_tool(request.target)
            elif request.action_type == ActionType.NETWORK:
                result = self._make_network_request(request.target)
            else:
                raise NotImplementedError(f"Action type {request.action_type} not implemented")

            return ActionOutcome(
                request=request,
                status=ActionStatus.ALLOWED,
                result=result,
                side_effects=[f"Performed {request.action_type.value} on {request.target}"],
                resource_usage={"cpu": 0.1, "memory": 1024}
            )
        except Exception as e:
            return ActionOutcome(
                request=request,
                status=ActionStatus.DENIED,
                error=str(e)
            )

    def _read_file(self, path: str) -> str:
        # Simulate file read
        return f"Content of {path}"

    def _write_file(self, path: str) -> str:
        # Simulate file write
        return f"Wrote to {path}"

    def _call_tool(self, tool_name: str) -> str:
        # Simulate tool call
        return f"Called tool {tool_name}"

    def _make_network_request(self, url: str) -> str:
        # Simulate network request
        return f"Made request to {url}"

# --- Audit Log ---

class AuditLog:
    def __init__(self):
        self.entries: List[ActionOutcome] = []
        self.sequence_counter = 0
        self.head_hash = ""

    def log(self, outcome: ActionOutcome) -> None:
        # Assign sequence number
        outcome.sequence_number = self.sequence_counter
        self.sequence_counter += 1
        
        # Compute hash chain
        if not self.entries:
            outcome.hash_chain = hashlib.sha256(b"").hexdigest()
        else:
            prev_entry = self.entries[-1]
            combined_data = f"{prev_entry.hash_chain}{str(outcome)}".encode('utf-8')
            outcome.hash_chain = hashlib.sha256(combined_data).hexdigest()
        
        self.entries.append(outcome)

    def get_trace(self, agent_id: str) -> List[ActionOutcome]:
        return [e for e in self.entries if e.request.agent_id == agent_id]

    def export_trace(self, agent_id: str) -> str:
        trace = self.get_trace(agent_id)
        lines = []
        for entry in trace:
            lines.append(f"[{entry.request.timestamp}] {entry.request.action_type.value} {entry.request.target}")
            if entry.status == ActionStatus.DENIED:
                lines.append(f"  DENIED: {entry.error}")
            elif entry.status == ActionStatus.QUARANTINED:
                lines.append(f"  QUARANTINED: {entry.error}")
            else:
                lines.append(f"  ALLOWED: {entry.result}")
        return "\n".join(lines)

    def get_head_hash(self) -> str:
        """Get the current head hash for tamper-evidence."""
        if not self.entries:
            return ""
        return self.entries[-1].hash_chain

# --- Example Usage ---

if __name__ == "__main__":
    # Initialize sandbox
    sandbox = SandboxRuntime()

    # Register agent
    agent_id = "agent-123"
    sandbox.register_agent(agent_id)

    # Issue capabilities
    read_cap = Capability(
        id="read-file-cap",
        action_type=ActionType.READ,
        target="/tmp/data.txt",
        constraints={"max_size": 1024}
    )
    sandbox.issue_capability(read_cap)

    write_cap = Capability(
        id="write-file-cap",
        action_type=ActionType.WRITE,
        target="/data/output.txt",
        constraints={"max_size": 2048}
    )
    sandbox.issue_capability(write_cap)

    # Execute actions
    read_request = ActionRequest(
        capability_id="read-file-cap",
        agent_id=agent_id,
        action_type=ActionType.READ,
        target="/tmp/data.txt"
    )

    write_request = ActionRequest(
        capability_id="write-file-cap",
        agent_id=agent_id,
        action_type=ActionType.WRITE,
        target="/data/output.txt"
    )

    # Allow actions
    read_result = sandbox.execute_action(read_request)
    print(f"Read result: {read_result}")

    write_result = sandbox.execute_action(write_request)
    print(f"Write result: {write_result}")

    # Try to execute unauthorized action
    unauthorized_request = ActionRequest(
        capability_id="nonexistent-cap",
        agent_id=agent_id,
        action_type=ActionType.READ,
        target="/etc/passwd"
    )
    unauthorized_result = sandbox.execute_action(unauthorized_request)
    print(f"Unauthorized result: {unauthorized_result}")

    # Export audit trace
    trace = sandbox.audit_log.export_trace(agent_id)
    print("\nAudit Trace:")
    print(trace)

    # Show head hash for tamper evidence
    print(f"\nHead Hash: {sandbox.audit_log.get_head_hash()}")