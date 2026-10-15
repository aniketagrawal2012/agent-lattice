"""
Agent-Lattice: Types and Schema Definitions
Formal Pydantic data models for Decentralized Information-Flow Lattice,
Token-Level Taint Tracking, and Capability Attenuation.
"""

from enum import Enum
from typing import List, Dict, Any, Optional, Set
from pydantic import BaseModel, Field
import time
import uuid


class IntegrityLevel(int, Enum):
    """
    Totally ordered Integrity Lattice components (Biba Model):
    UNTRUSTED (0) < SANITIZED (1) < VERIFIED (2) < SYSTEM_AUTHORIZED (3)
    Higher means more trusted / higher integrity.
    Information flow requires: I_source >= I_target (cannot write up / cannot read down without declassification)
    """
    UNTRUSTED = 0          # Raw user inputs, external web scrapes, unverified emails
    SANITIZED = 1          # Passed schema validation, regex filtering, or prompt guard
    VERIFIED = 2           # Cryptographically attested, internal microservice return, certified LLM output
    SYSTEM_AUTHORIZED = 3  # Root orchestrator, kernel dispatch, admin-signed policy


class ConfidentialityCompartment(str, Enum):
    """
    Partially ordered Confidentiality Lattice (Bell-LaPadula / Decentralized Label Model):
    Set of security compartments: INTERNAL, PII, FINANCIAL, PAYMENT_GATEWAY, SYSTEM_CONFIG, SECOPS_TELEMETRY.
    Confidentiality is a powerset lattice P(K).
    Unclassified public data corresponds to the empty set of compartments: set() = bot_conf.
    C_1 <= C_2 iff C_1 is a subset of C_2.
    Information flow requires: C_source <= C_target (cannot read up / cannot write down without declassification).
    """
    INTERNAL = "INTERNAL"
    PII = "PII"
    FINANCIAL = "FINANCIAL"
    PAYMENT_GATEWAY = "PAYMENT_GATEWAY"
    SYSTEM_CONFIG = "SYSTEM_CONFIG"
    SECOPS_TELEMETRY = "SECOPS_TELEMETRY"


class SecurityLabel(BaseModel):
    """
    Dual-tuple security label L = (C, I) in L_conf x L_integ
    """
    confidentiality: Set[ConfidentialityCompartment] = Field(default_factory=lambda: {ConfidentialityCompartment.INTERNAL})
    integrity: IntegrityLevel = Field(default=IntegrityLevel.SYSTEM_AUTHORIZED)

    def is_dominated_by(self, other: "SecurityLabel") -> bool:
        """
        Flow relation: L1 -> L2 is permitted iff:
        1. C1 <= C2 (No read up / No write down in confidentiality: C1 is subset of C2)
        2. I1 >= I2 (No write up / No read down in integrity: I1 >= I2)
        """
        conf_ok = self.confidentiality.issubset(other.confidentiality)
        integ_ok = self.integrity.value >= other.integrity.value
        return conf_ok and integ_ok

    def join(self, other: "SecurityLabel") -> "SecurityLabel":
        """
        Least Upper Bound (LUB / \\sqcup):
        Accumulates maximum confidentiality (union of compartments)
        and least upper bound of integrity (in standard IFC, join takes min integrity / worst taint).
        """
        return SecurityLabel(
            confidentiality=self.confidentiality.union(other.confidentiality),
            integrity=IntegrityLevel(min(self.integrity.value, other.integrity.value))
        )

    def meet(self, other: "SecurityLabel") -> "SecurityLabel":
        """
        Greatest Lower Bound (GLB / \\sqcap):
        Intersection of confidentiality and max of integrity.
        """
        return SecurityLabel(
            confidentiality=self.confidentiality.intersection(other.confidentiality),
            integrity=IntegrityLevel(max(self.integrity.value, other.integrity.value))
        )

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            Set: list
        }


class TokenSpan(BaseModel):
    """
    Represents an atomic substring or token range with causal provenance.
    """
    span_id: str = Field(default_factory=lambda: f"tok_{uuid.uuid4().hex[:8]}")
    text: str
    source_agent_or_tool: str
    label: SecurityLabel
    is_endorsement_boundary: bool = False
    created_at_epoch: float = Field(default_factory=time.time)


class ToolContract(BaseModel):
    """
    Formal static security contract associated with an enterprise tool / API.
    """
    tool_id: str
    tool_name: str
    target_backend: str  # e.g., "SAP_S4HANA", "CLOUD_SPANNER", "POSTGRES_PAYMENTS", "WEB_BROWSER"
    is_idempotent: bool
    is_state_mutating: bool
    min_required_integrity: IntegrityLevel
    max_permitted_confidentiality: Set[ConfidentialityCompartment]
    attenuation_supported: bool = True  # Can arguments be attenuated/sanitized or downgraded?
    compensating_tool_id: Optional[str] = None  # Inverse compensating tool ID for saga rollback (IDF-GGL-2026-AGENTSAGA)
    param_integrity_thresholds: Dict[str, IntegrityLevel] = Field(default_factory=dict)  # Parameter-specific integrity floors
    schema_params: Dict[str, Any] = Field(default_factory=dict)


class AttenuationAction(str, Enum):
    """
    Policy resolution actions when a non-interference violation is detected.
    """
    PERMIT = "PERMIT"
    ATTENUATE_SANITIZE = "ATTENUATE_SANITIZE"      # Strip/rewrite tainted parameters
    QUARANTINE_ESCROW = "QUARANTINE_ESCROW"        # Isolate mutation to an uncommitted review queue
    DOWNGRADE_READONLY = "DOWNGRADE_READONLY"      # Reroute to read-only replica
    CATEGORICAL_BLOCK = "CATEGORICAL_BLOCK"        # Hard block with security alert


class EscrowReceipt(BaseModel):
    """
    Structured synthetic return payload returned synchronously to calling agent runtime
    when a state-mutating tool invocation is diverted to asynchronous quarantine escrow.
    Prevents agent reasoning stalls, infinite retry loops, or timeout exceptions.
    Includes provisional transaction identifier (tx_id) for speculative saga staging.
    """
    escrow_id: str = Field(default_factory=lambda: f"escrow_{uuid.uuid4().hex[:12]}")
    tx_id: Optional[str] = Field(default_factory=lambda: f"tx_{uuid.uuid4().hex[:12]}")
    status: str = "PENDING_HUMAN_APPROVAL"
    target_tool: str
    target_backend: str
    reason: str
    provisional_acknowledgment: str = "State mutation diverted to isolated quarantine escrow pending administrator review."
    ttl_seconds: int = 900
    voucher_id: str
    created_at_epoch: float = Field(default_factory=time.time)


class AttenuationVoucher(BaseModel):
    """
    Cryptographic/auditable voucher certifying an attenuation decision.
    Preserves raw arguments immutably alongside sanitized arguments for forensic integrity.
    """
    voucher_id: str = Field(default_factory=lambda: f"vouch_{uuid.uuid4().hex[:10]}")
    timestamp_ns: int = Field(default_factory=time.time_ns)
    caller_agent_id: str
    tool_id: str
    action: AttenuationAction
    incoming_label: SecurityLabel
    required_label_summary: str
    raw_arguments: Dict[str, Any] = Field(default_factory=dict)
    sanitized_params: Dict[str, Any] = Field(default_factory=dict)
    security_reason: str
    escrow_receipt: Optional[EscrowReceipt] = None
    audit_signature: str = ""


class ExecutionTrace(BaseModel):
    """
    Trace representing a complete multi-agent turn including prompts, tool calls, and decisions.
    """
    trace_id: str
    stratum: str  # e.g., "COMPLIANT", "PROMPT_INJECTION_CONFUSED_DEPUTY", "EXFILTRATION", etc.
    caller_agent: str
    target_tool: str
    prompt_payload: str
    argument_payload: Dict[str, Any]
    context_tokens: List[TokenSpan]
    true_label_is_attack: bool
    description: str
