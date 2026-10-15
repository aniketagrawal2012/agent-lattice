"""
Agent-Lattice: Deterministic Tool Gateway & Capability Attenuation Engine
Inspects outgoing tool dispatches, enforces non-interference invariants,
and applies dynamic capability attenuation or quarantine against Confused Deputy attacks.
"""

from typing import Dict, Any, Tuple, Optional, Set
import hashlib
import time
import re
from agent_lattice.types import (
    SecurityLabel,
    IntegrityLevel,
    ConfidentialityCompartment,
    ToolContract,
    AttenuationAction,
    AttenuationVoucher,
    EscrowReceipt
)
from agent_lattice.lattice import SecurityLattice
from agent_lattice.provenance import CausalProvenanceTracker


class ToolSecurityGateway:
    """
    Physical API / Microservice gateway enforcing information-flow lattice policies.
    Intercepts agent tool requests before serialization and network transmission.
    """

    def __init__(self, registered_tools: Optional[Dict[str, ToolContract]] = None):
        self.registered_tools: Dict[str, ToolContract] = registered_tools or {}
        self.issued_vouchers: List[AttenuationVoucher] = []

    def register_tool(self, contract: ToolContract):
        self.registered_tools[contract.tool_id] = contract

    def evaluate_and_enforce(
        self,
        caller_agent_id: str,
        tool_id: str,
        arguments: Dict[str, Any],
        provenance_tracker: CausalProvenanceTracker,
        intent_integrity: Optional[IntegrityLevel] = None
    ) -> Tuple[AttenuationAction, Dict[str, Any], AttenuationVoucher]:
        """
        Evaluates tool call against registered ToolContract using current provenance context.
        Supports control-flow intent binding (intent_integrity) and parameter-specific integrity thresholds.
        Returns:
            (DecisionAction, SanitizedOrOriginalArguments, AttenuationVoucher)
        """
        contract = self.registered_tools.get(tool_id)
        if not contract:
            # Default fail-secure: unregistered tools are blocked
            voucher = self._create_voucher(
                caller_agent_id=caller_agent_id,
                tool_id=tool_id,
                action=AttenuationAction.CATEGORICAL_BLOCK,
                incoming_label=provenance_tracker.compute_effective_context_label(),
                required_summary="UNREGISTERED_TOOL",
                sanitized_params={},
                reason="Unregistered tool ID - rejected by fail-secure default policy.",
                raw_arguments=arguments
            )
            return AttenuationAction.CATEGORICAL_BLOCK, {}, voucher

        # Compute effective context label and argument-specific slice label
        effective_context_label = provenance_tracker.compute_effective_context_label()
        arg_slice_label = provenance_tracker.compute_backward_slice_label(
            arguments,
            is_mutating=contract.is_state_mutating
        )

        # Control-Flow Intent Binding: effective invocation integrity considers initiating intent
        effective_intent = intent_integrity if intent_integrity is not None else effective_context_label.integrity

        # Check Non-Interference Invariants:
        # 1. Confidentiality Invariant: Can context and argument data flow to this tool's destination?
        effective_conf = effective_context_label.confidentiality | arg_slice_label.confidentiality
        conf_violation = not effective_conf.issubset(contract.max_permitted_confidentiality)

        # 2. Integrity Invariant: Check parameter-specific thresholds or global argument slice integrity
        # Decouple execution-control parameters from passive payload parameters to prevent unendorsed notes from collapsing I_inv
        ctrl_params = {
            p_name: p_val for p_name, p_val in arguments.items()
            if contract.param_integrity_thresholds.get(p_name, contract.min_required_integrity).value >= IntegrityLevel.SANITIZED.value
        }
        if ctrl_params:
            ctrl_slice_label = provenance_tracker.compute_backward_slice_label(ctrl_params, is_mutating=contract.is_state_mutating)
            i_a_ctrl = ctrl_slice_label.integrity
        elif arguments:
            # S_ctrl is empty and arguments != empty: all arguments are passive payload fields (I_req(p) < SANITIZED).
            # Default to SYSTEM_AUTHORIZED (3) so invocation integrity defers cleanly to caller intent:
            # I_inv = min(3, I_intent) = I_intent
            i_a_ctrl = IntegrityLevel.SYSTEM_AUTHORIZED
        else:
            i_a_ctrl = arg_slice_label.integrity

        # Effective invocation integrity binds control parameter integrity and initiating intent:
        # I_inv = min(I_{a,ctrl}, I_{intent})
        i_inv = IntegrityLevel(min(i_a_ctrl.value, effective_intent.value))

        if contract.param_integrity_thresholds and arguments:
            integ_violation = False
            for p_name, p_val in arguments.items():
                p_req = contract.param_integrity_thresholds.get(p_name, contract.min_required_integrity)
                p_label = provenance_tracker.compute_backward_slice_label({p_name: p_val}, is_mutating=contract.is_state_mutating)
                if p_label.integrity.value < p_req.value:
                    integ_violation = True
                    break
        else:
            integ_violation = arg_slice_label.integrity.value < contract.min_required_integrity.value

        # Control-Flow Intent Invariant: Mutating operations require invocation integrity >= tool-level threshold
        # Routine user-facing mutations set Ctr.min_required_integrity = UNTRUSTED (0) while execution-control parameters
        # enforce SANITIZED (1). Administrative tools enforce SYSTEM_AUTHORIZED (3).
        if contract.is_state_mutating and i_inv.value < contract.min_required_integrity.value:
            integ_violation = True

        # Combined effective label for voucher reporting (fail-closed for parameterless mutating tools)
        if not arguments and contract.is_state_mutating:
            effective_label = SecurityLabel(
                confidentiality=effective_context_label.confidentiality,
                integrity=effective_context_label.integrity
            )
        else:
            effective_label = SecurityLabel(
                confidentiality=effective_conf,
                integrity=i_inv
            )

        # CASE 1: Full Non-Interference Satisfied (Compliant Flow)
        if not conf_violation and not integ_violation:
            voucher = self._create_voucher(
                caller_agent_id=caller_agent_id,
                tool_id=tool_id,
                action=AttenuationAction.PERMIT,
                incoming_label=effective_label,
                required_summary=f"MinInteg={contract.min_required_integrity.name}, MaxConf={list(contract.max_permitted_confidentiality)}",
                sanitized_params=arguments,
                reason="Non-interference invariants satisfied; execution permitted.",
                raw_arguments=arguments
            )
            return AttenuationAction.PERMIT, arguments, voucher

        # Composite Non-Interference Evaluation
        working_args = dict(arguments)
        is_attenuated = False
        reasons = []

        # 1. Evaluate Confidentiality First (A3J 74/91 Unnesting & Leakage Elimination)
        if conf_violation:
            leaked_compartments = effective_conf - contract.max_permitted_confidentiality
            arg_leaks = arg_slice_label.confidentiality - contract.max_permitted_confidentiality

            if not contract.attenuation_supported:
                # If tool does not support attenuation and confidentiality exceeds clearance -> categorical block
                voucher = self._create_voucher(
                    caller_agent_id=caller_agent_id,
                    tool_id=tool_id,
                    action=AttenuationAction.CATEGORICAL_BLOCK,
                    incoming_label=effective_label,
                    required_summary=f"MaxConf={list(contract.max_permitted_confidentiality)}, AttenSupported=False",
                    sanitized_params={},
                    reason=f"Categorical block: Tool does not support attenuation and confidentiality compartments exceed destination clearance ({[c.value for c in leaked_compartments]} -> {contract.target_backend}).",
                    raw_arguments=arguments
                )
                return AttenuationAction.CATEGORICAL_BLOCK, {}, voucher
            else:
                scrubbed_args, scrub_success = self._scrub_confidential_parameters(working_args, leaked_compartments)
                # Soundness Check: If scrubbing fails OR (for argument leaks) leaves arguments unaltered
                # (e.g. semantic paraphrase, indirect summary, or unknown encoding), Categorical Block immediately!
                if not scrub_success or (arg_leaks and scrubbed_args == working_args):
                    voucher = self._create_voucher(
                        caller_agent_id=caller_agent_id,
                        tool_id=tool_id,
                        action=AttenuationAction.CATEGORICAL_BLOCK,
                        incoming_label=effective_label,
                        required_summary=f"MaxConf={list(contract.max_permitted_confidentiality)}",
                        sanitized_params={},
                        reason=f"Categorical block: Unauthorized confidentiality flow ({[c.value for c in leaked_compartments]} -> {contract.target_backend}) that could not be syntactically scrubbed.",
                        raw_arguments=arguments
                    )
                    return AttenuationAction.CATEGORICAL_BLOCK, {}, voucher

                if scrubbed_args != working_args:
                    working_args = scrubbed_args
                    is_attenuated = True
                    reasons.append(f"Confidentiality scrubbed ({[c.value for c in leaked_compartments]})")

        # 2. Evaluate Integrity Next (DO NOT return early; mutating actions must be escrowed/blocked)
        if integ_violation:
            if not contract.is_state_mutating:
                if not contract.attenuation_supported:
                    voucher = self._create_voucher(
                        caller_agent_id=caller_agent_id,
                        tool_id=tool_id,
                        action=AttenuationAction.CATEGORICAL_BLOCK,
                        incoming_label=effective_label,
                        required_summary=f"MinInteg={contract.min_required_integrity.name}, AttenSupported=False",
                        sanitized_params={},
                        reason=f"Categorical block: Read-only tool does not support attenuation under integrity deficit ({effective_label.integrity.name} < {contract.min_required_integrity.name}).",
                        raw_arguments=arguments
                    )
                    return AttenuationAction.CATEGORICAL_BLOCK, {}, voucher
                # Read-only query: sanitize delimiters and permit under attenuation
                sanitized_args = self._sanitize_read_parameters(working_args)
                reasons.append(f"Read-only query sanitized under integrity deficit ({effective_label.integrity.name} < {contract.min_required_integrity.name})")
                voucher = self._create_voucher(
                    caller_agent_id=caller_agent_id,
                    tool_id=tool_id,
                    action=AttenuationAction.ATTENUATE_SANITIZE,
                    incoming_label=effective_label,
                    required_summary=f"MinInteg={contract.min_required_integrity.name}",
                    sanitized_params=sanitized_args,
                    reason="; ".join(reasons),
                    raw_arguments=arguments
                )
                return AttenuationAction.ATTENUATE_SANITIZE, sanitized_args, voucher

            # State-mutating operation with integrity deficit -> MANDATORY ESCROW OR BLOCK
            has_injection, cleaned_args = self._detect_and_clean_injection(working_args)
            if contract.attenuation_supported:
                reasons.append(f"State mutation intercepted under integrity deficit ({effective_label.integrity.name} < {contract.min_required_integrity.name}) -> Routed to Quarantine Escrow")
                cleaned_params = cleaned_args if has_injection else working_args
                voucher = self._create_voucher(
                    caller_agent_id=caller_agent_id,
                    tool_id=tool_id,
                    action=AttenuationAction.QUARANTINE_ESCROW,
                    incoming_label=effective_label,
                    required_summary=f"MinInteg={contract.min_required_integrity.name}",
                    sanitized_params=cleaned_params,
                    reason="; ".join(reasons),
                    raw_arguments=arguments
                )
                receipt = EscrowReceipt(
                    target_tool=tool_id,
                    target_backend=contract.target_backend,
                    reason="; ".join(reasons),
                    voucher_id=voucher.voucher_id,
                    ttl_seconds=900
                )
                voucher.escrow_receipt = receipt
                return AttenuationAction.QUARANTINE_ESCROW, cleaned_params, voucher
            else:
                reasons.append(f"Categorical block on non-attenuable mutating tool {contract.tool_id}")
                voucher = self._create_voucher(
                    caller_agent_id=caller_agent_id,
                    tool_id=tool_id,
                    action=AttenuationAction.CATEGORICAL_BLOCK,
                    incoming_label=effective_label,
                    required_summary=f"MinInteg={contract.min_required_integrity.name}",
                    sanitized_params={},
                    reason="; ".join(reasons),
                    raw_arguments=arguments
                )
                return AttenuationAction.CATEGORICAL_BLOCK, {}, voucher

        # 3. If confidentiality was scrubbed and integrity was satisfied:
        if is_attenuated:
            if contract.is_state_mutating:
                reasons.append("State mutation with scrubbed confidential parameters routed to Quarantine Escrow")
                voucher = self._create_voucher(
                    caller_agent_id=caller_agent_id,
                    tool_id=tool_id,
                    action=AttenuationAction.QUARANTINE_ESCROW,
                    incoming_label=effective_label,
                    required_summary=f"MaxConf={list(contract.max_permitted_confidentiality)}",
                    sanitized_params=working_args,
                    reason="; ".join(reasons),
                    raw_arguments=arguments
                )
                receipt = EscrowReceipt(
                    target_tool=tool_id,
                    target_backend=contract.target_backend,
                    reason="; ".join(reasons),
                    voucher_id=voucher.voucher_id,
                    ttl_seconds=900
                )
                voucher.escrow_receipt = receipt
                return AttenuationAction.QUARANTINE_ESCROW, working_args, voucher
            else:
                voucher = self._create_voucher(
                    caller_agent_id=caller_agent_id,
                    tool_id=tool_id,
                    action=AttenuationAction.ATTENUATE_SANITIZE,
                    incoming_label=effective_label,
                    required_summary=f"MaxConf={list(contract.max_permitted_confidentiality)}",
                    sanitized_params=working_args,
                    reason="; ".join(reasons),
                    raw_arguments=arguments
                )
                return AttenuationAction.ATTENUATE_SANITIZE, working_args, voucher

        # 4. If arguments were clean and integrity was satisfied:
        voucher = self._create_voucher(
            caller_agent_id=caller_agent_id,
            tool_id=tool_id,
            action=AttenuationAction.PERMIT,
            incoming_label=effective_label,
            required_summary=f"MinInteg={contract.min_required_integrity.name}, MaxConf={list(contract.max_permitted_confidentiality)}",
            sanitized_params=working_args,
            reason="Arguments clean; execution permitted without redaction.",
            raw_arguments=arguments
        )
        return AttenuationAction.PERMIT, working_args, voucher


    def _scrub_confidential_parameters(
        self,
        arguments: Dict[str, Any],
        leaked_compartments: Set[ConfidentialityCompartment]
    ) -> Tuple[Dict[str, Any], bool]:
        """
        Redacts PII/Financial values from parameters matching sensitive patterns.
        """
        scrubbed = {}
        # Patterns for SSN, credit cards, emails, passwords
        sensitive_patterns = [
            (r'\b\d{3}-\d{2}-\d{4}\b', "[REDACTED_SSN]"),
            (r'\b(?:\d{4}-){3}\d{4}\b', "[REDACTED_CARD]"),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b', "[REDACTED_EMAIL]"),
            (r'(?i)password\s*=\s*[\'"][^\'"]+[\'"]', "password='[REDACTED]'")
        ]

        for k, v in arguments.items():
            if isinstance(v, str):
                val_clean = v
                for pattern, repl in sensitive_patterns:
                    val_clean = re.sub(pattern, repl, val_clean)
                scrubbed[k] = val_clean
            elif isinstance(v, dict):
                nested_scrub, _ = self._scrub_confidential_parameters(v, leaked_compartments)
                scrubbed[k] = nested_scrub
            else:
                scrubbed[k] = v

        return scrubbed, True

    def _detect_and_clean_injection(self, arguments: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Detects prompt injection or command escape sequences in parameters and neutralizes them.
        """
        injection_patterns = [
            r'(?i)ignore\s+(?:all\s+)?previous\s+instructions',
            r'(?i)drop\s+table',
            r'(?i)delete\s+from',
            r'(?i);\s*--',
            r'(?i)union\s+select',
            r'(?i)/bin/sh',
            r'(?i)chmod\s+\+x',
            r'(?i)curl\s+http'
        ]

        found_injection = False
        cleaned = {}

        for k, v in arguments.items():
            if isinstance(v, str):
                val_clean = v
                for pat in injection_patterns:
                    if re.search(pat, val_clean):
                        found_injection = True
                        val_clean = re.sub(pat, "[SANITIZED_INJECTION_PATTERN]", val_clean)
                cleaned[k] = val_clean
            else:
                cleaned[k] = v

        return found_injection, cleaned

    def _sanitize_read_parameters(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensures read queries do not smuggle subqueries or stacked commands.
        """
        cleaned = {}
        for k, v in arguments.items():
            if isinstance(v, str):
                # Remove semicolons and comment tokens
                val_clean = re.sub(r';', ' ', v)
                val_clean = re.sub(r'--', ' ', val_clean)
                cleaned[k] = val_clean.strip()
            else:
                cleaned[k] = v
        return cleaned

    def _create_voucher(
        self,
        caller_agent_id: str,
        tool_id: str,
        action: AttenuationAction,
        incoming_label: SecurityLabel,
        required_summary: str,
        sanitized_params: Dict[str, Any],
        reason: str,
        raw_arguments: Optional[Dict[str, Any]] = None,
        escrow_receipt: Optional[EscrowReceipt] = None
    ) -> AttenuationVoucher:
        voucher = AttenuationVoucher(
            caller_agent_id=caller_agent_id,
            tool_id=tool_id,
            action=action,
            incoming_label=incoming_label,
            required_label_summary=required_summary,
            raw_arguments=dict(raw_arguments) if raw_arguments is not None else {},
            sanitized_params=sanitized_params,
            security_reason=reason,
            escrow_receipt=escrow_receipt
        )
        # Compute SHA-256 HMAC / signature digest
        digest_input = f"{voucher.voucher_id}:{voucher.timestamp_ns}:{caller_agent_id}:{tool_id}:{action.value}:{reason}"
        voucher.audit_signature = hashlib.sha256(digest_input.encode('utf-8')).hexdigest()
        self.issued_vouchers.append(voucher)
        return voucher
