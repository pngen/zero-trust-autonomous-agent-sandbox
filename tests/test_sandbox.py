import unittest
from datetime import datetime, timedelta
import time
from zt_aas.core.sandbox import (
    SandboxRuntime, 
    Capability, 
    ActionType, 
    ActionRequest,
    ActionStatus
)

class TestSandbox(unittest.TestCase):
    
    def setUp(self):
        self.sandbox = SandboxRuntime()
        self.agent_id = "test-agent"
        self.sandbox.register_agent(self.agent_id)
        
    def test_register_agent(self):
        # Should register agent successfully
        self.assertIn(self.agent_id, self.sandbox.active_agents)
        
        # Should not allow duplicate registration
        with self.assertRaises(ValueError):
            self.sandbox.register_agent(self.agent_id)
            
    def test_issue_capability(self):
        cap = Capability(
            id="test-cap",
            action_type=ActionType.READ,
            target="/tmp/test.txt"
        )
        self.sandbox.issue_capability(cap)
        
        self.assertIn("test-cap", self.sandbox.capabilities)
        
        # Should not allow duplicate capability IDs
        with self.assertRaises(ValueError):
            self.sandbox.issue_capability(cap)
            
    def test_execute_allowed_action(self):
        cap = Capability(
            id="read-cap",
            action_type=ActionType.READ,
            target="/tmp/test.txt"
        )
        self.sandbox.issue_capability(cap)
        
        request = ActionRequest(
            capability_id="read-cap",
            agent_id=self.agent_id,
            action_type=ActionType.READ,
            target="/tmp/test.txt"
        )
        
        outcome = self.sandbox.execute_action(request)
        self.assertEqual(outcome.status, ActionStatus.ALLOWED)
        
    def test_execute_denied_action(self):
        # No capability issued
        request = ActionRequest(
            capability_id="nonexistent",
            agent_id=self.agent_id,
            action_type=ActionType.READ,
            target="/tmp/test.txt"
        )
        
        outcome = self.sandbox.execute_action(request)
        self.assertEqual(outcome.status, ActionStatus.DENIED)
        
    def test_revoke_capability(self):
        cap = Capability(
            id="revoke-cap",
            action_type=ActionType.READ,
            target="/tmp/test.txt"
        )
        self.sandbox.issue_capability(cap)
        
        # Should be able to revoke
        self.assertTrue(self.sandbox._revoke_capability("revoke-cap"))
        
        # Verify capability is marked as revoked
        self.assertTrue(self.sandbox.capabilities["revoke-cap"].revoked)
        
        # Should not be able to revoke non-existent capability
        self.assertFalse(self.sandbox._revoke_capability("nonexistent"))
        
        # Revoked capability should be denied
        request = ActionRequest(
            capability_id="revoke-cap",
            agent_id=self.agent_id,
            action_type=ActionType.READ,
            target="/tmp/test.txt"
        )
        
        outcome = self.sandbox.execute_action(request)
        self.assertEqual(outcome.status, ActionStatus.DENIED)

    def test_scope_enforcement(self):
        cap = Capability(
            id="scope-cap",
            action_type=ActionType.READ,
            target="/tmp/test.txt"
        )
        self.sandbox.issue_capability(cap)
        
        # Correct scope should work
        request = ActionRequest(
            capability_id="scope-cap",
            agent_id=self.agent_id,
            action_type=ActionType.READ,
            target="/tmp/test.txt"
        )
        outcome = self.sandbox.execute_action(request)
        self.assertEqual(outcome.status, ActionStatus.ALLOWED)
        
        # Wrong target should be denied
        request = ActionRequest(
            capability_id="scope-cap",
            agent_id=self.agent_id,
            action_type=ActionType.READ,
            target="/tmp/wrong.txt"
        )
        outcome = self.sandbox.execute_action(request)
        self.assertEqual(outcome.status, ActionStatus.DENIED)
        
        # Wrong action type should be denied
        request = ActionRequest(
            capability_id="scope-cap",
            agent_id=self.agent_id,
            action_type=ActionType.WRITE,
            target="/tmp/test.txt"
        )
        outcome = self.sandbox.execute_action(request)
        self.assertEqual(outcome.status, ActionStatus.DENIED)

    def test_capability_expiration(self):
        cap = Capability(
            id="expiring-cap",
            action_type=ActionType.READ,
            target="/tmp/test.txt",
            duration=1  # 1 second
        )
        self.sandbox.issue_capability(cap)
        
        # First request should work
        request = ActionRequest(
            capability_id="expiring-cap",
            agent_id=self.agent_id,
            action_type=ActionType.READ,
            target="/tmp/test.txt"
        )
        outcome = self.sandbox.execute_action(request)
        self.assertEqual(outcome.status, ActionStatus.ALLOWED)
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Second request should be denied due to expiration
        outcome = self.sandbox.execute_action(request)
        self.assertEqual(outcome.status, ActionStatus.DENIED)

    def test_quarantine_behavior(self):
        cap = Capability(
            id="quarantine-cap",
            action_type=ActionType.READ,
            target="/tmp/test.txt"
        )
        self.sandbox.issue_capability(cap)
        
        # Quarantine agent
        self.sandbox.quarantine_agent(self.agent_id)
        
        # Any action should be quarantined
        request = ActionRequest(
            capability_id="quarantine-cap",
            agent_id=self.agent_id,
            action_type=ActionType.READ,
            target="/tmp/test.txt"
        )
        outcome = self.sandbox.execute_action(request)
        self.assertEqual(outcome.status, ActionStatus.QUARANTINED)

    def test_agent_active_status(self):
        # Register agent
        agent_id = "active-agent"
        self.sandbox.register_agent(agent_id)
        
        # Should be able to execute action
        cap = Capability(
            id="active-cap",
            action_type=ActionType.READ,
            target="/tmp/test.txt"
        )
        self.sandbox.issue_capability(cap)
        
        request = ActionRequest(
            capability_id="active-cap",
            agent_id=agent_id,
            action_type=ActionType.READ,
            target="/tmp/test.txt"
        )
        outcome = self.sandbox.execute_action(request)
        self.assertEqual(outcome.status, ActionStatus.ALLOWED)
        
        # Deactivate agent (correct way)
        with self.sandbox._lock:
            self.sandbox.active_agents[agent_id] = False
        
        # Should be denied now
        outcome = self.sandbox.execute_action(request)
        self.assertEqual(outcome.status, ActionStatus.DENIED)

if __name__ == '__main__':
    unittest.main()