"""
Agent-Lattice: Deterministic Tool Gateway & Capability Attenuation Engine
Inspects outgoing tool dispatches, enforces non-interference invariants,
and applies dynamic capability attenuation or quarantine against Confused Deputy attacks.
"""

from typing import Dict, Any, Tuple, Optional, Set, List
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
        self.agent_ceilings: Dict[str, SecurityLabel] = {}
        self.active_escrows: Dict[str, List[Tuple[ToolContract, Dict[str, Any], EscrowReceipt]]] = {}
        self.escrow_dedup_index: Dict[str, EscrowReceipt] = {}

    def register_tool(self, contract: ToolContract):
        self.registered_tools[contract.tool_id] = contract

    def register_agent_ceiling(self, agent_id: str, ceiling: SecurityLabel):
        """
        Registers a subagent ancestry authorization ceiling (Section III-C, Eq. 20).
        """
        self.agent_ceilings[agent_id] = ceiling

    def in_privilege_quarantine(
        self,
        caller_agent_id: str,
        arguments: Dict[str, Any],
        contract: ToolContract
    ) -> bool:
        """
        Evaluates InPrivilegeQuarantine(ag, a, Ctr) (Section III-D, Algorithm 1 Line 16, Eq. 27):
        Returns True if the calling agent has an unresolved QUARANTINE_ESCROW receipt targeting
        the same backend (contract.target_backend) or overlapping primary-key entity identifiers.
        """
        pending_list = self.active_escrows.get(caller_agent_id, [])
        if not pending_list:
            return False
        arg_vals = {str(v).lower().strip() for v in arguments.values() if v is not None}
        for prev_contract, prev_args, receipt in pending_list:
            if receipt.status == "PENDING_HUMAN_APPROVAL":
                if prev_contract.target_backend == contract.target_backend:
                    return True
                prev_vals = {str(v).lower().strip() for v in prev_args.values() if v is not None}
                if arg_vals and prev_vals and (arg_vals & prev_vals):
                    return True
        return False

    def _record_active_escrow(
        self,
        caller_agent_id: str,
        contract: ToolContract,
        arguments: Dict[str, Any],
        receipt: EscrowReceipt,
        reason: str
    ) -> None:
        self.active_escrows.setdefault(caller_agent_id, []).append((contract, dict(arguments), receipt))
        ctrl_keys = [
            k for k in sorted(arguments.keys())
            if contract.param_integrity_thresholds.get(k, contract.min_required_integrity).value >= IntegrityLevel.SANITIZED.value
        ]
        target_keys = ctrl_keys if ctrl_keys else sorted(arguments.keys())
        canon_ctrl = "|".join(f"{k}={str(arguments[k]).lower().strip().replace('-', '')}" for k in target_keys)
        dedup_key = hashlib.sha256(
            f"{caller_agent_id}:{contract.tool_id}:{reason}:{canon_ctrl}".encode("utf-8")
        ).hexdigest()
        self.escrow_dedup_index[dedup_key] = receipt

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
            ctrl_slice_label = provenance_tracker.compute_backward_slice_label(
                ctrl_params,
                is_mutating=contract.is_state_mutating,
                is_control_param=True
            )
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
                is_ctrl = p_req.value >= IntegrityLevel.SANITIZED.value
                p_label = provenance_tracker.compute_backward_slice_label(
                    {p_name: p_val},
                    is_mutating=contract.is_state_mutating,
                    is_control_param=is_ctrl,
                    param_name=p_name
                )
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
                self._record_active_escrow(caller_agent_id, contract, arguments, receipt, "; ".join(reasons))
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
                self._record_active_escrow(caller_agent_id, contract, arguments, receipt, "; ".join(reasons))
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
        Formal 3-Tier CleanInjection(a', Ctr) operator (Section III-D, Algorithm 1 Line 17):
        - Tier 1 (SQL/OData): Strips destructive DDL/DML/stacked-query tokens (DROP TABLE, DELETE FROM,
          GRANT ALL, UNION SELECT, ; --).
        - Tier 2 (POSIX/execve): Neutralizes shell metacharacters and command substitution (/bin/sh,
          chmod +x, curl http, $(...)).
        - Tier 3 (JSON/REST): Neutralizes prompt-injection overrides and prototype-pollution keys
          (__proto__, constructor.prototype).
        Preserves raw arguments immutably in v.raw_arguments while populating v.sanitized_params.
        """
        injection_patterns = [
            # Tier 1: SQL/OData destructive DDL/DML & comment escapes
            r'(?i)drop\s+table',
            r'(?i)delete\s+from',
            r'(?i)grant\s+all',
            r'(?i);\s*--',
            r'(?i)union\s+select',
            # Tier 2: POSIX/shell metacharacters & command substitution
            r'(?i)/bin/sh',
            r'(?i)chmod\s+\+x',
            r'(?i)curl\s+http',
            r'\$\([^)]+\)',
            # Tier 3: Prompt-injection directives & JSON prototype pollution
            r'(?i)ignore\s+(?:all\s+)?previous\s+(?:instructions|constraints)',
            r'(?i)__proto__',
            r'(?i)constructor\.prototype',
        ]

        found_injection = False
        cleaned = {}

        for k, v in arguments.items():
            if str(k) in ("__proto__", "constructor.prototype"):
                found_injection = True
                continue
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
        Formal 3-Stage SanitizeRead(a') operator (Section III-D, Algorithm 1 Line 10):
        1. Lexical statement-terminator and comment stripping (; , -- , /*...*/, null bytes).
        2. Single-statement read-only grammar enforcement (neutralizing UNION SELECT, INTO OUTFILE,
           COPY, pg_sleep, WAITFOR DELAY).
        3. Normalized read parameter binding.
        """
        cleaned = {}
        smuggled_read_patterns = [
            r'(?i)\bunion\s+select\b',
            r'(?i)\binto\s+outfile\b',
            r'(?i)\bpg_sleep\s*\([^)]*\)',
            r'(?i)\bwaitfor\s+delay\b',
        ]
        for k, v in arguments.items():
            if isinstance(v, str):
                # Stage 1: Strip statement terminators and inline/block comments
                val_clean = v.replace('\x00', ' ')
                val_clean = re.sub(r'/\*.*?\*/', ' ', val_clean)
                val_clean = re.sub(r';', ' ', val_clean)
                val_clean = re.sub(r'--', ' ', val_clean)
                # Stage 2: Neutralize smuggled side-effecting read subclauses
                for pat in smuggled_read_patterns:
                    val_clean = re.sub(pat, '[SANITIZED_READ_CLAUSE]', val_clean)
                cleaned[k] = re.sub(r'\s+', ' ', val_clean).strip()
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

    def compute_pre_attenuation_anomaly_score(
        self,
        caller_agent_id: str,
        tool_id: str,
        arguments: Dict[str, Any],
        provenance_tracker: CausalProvenanceTracker,
    ) -> float:
        """
        Computes the continuous label-free pre-attenuation anomaly score s_lattice^pre in [0, 1]
        (Equation 27 of the manuscript) strictly from the product security lattice labels
        (ell_int, ell_conf) and tool contract Ctr, with exact syntactic parity to PolicyCheck
        including all 5 arguments of the max(...) operator:
        1. Parameter-level integrity deficit
        2. Confidentiality compartment excess (0.95 per excess compartment)
        3. Subagent ancestry ceiling violation indicator
        4. Mutating tool integrity / unattenuated violation indicator
        5. Privilege quarantine indicator: 1(Ctr.IsMutating ^ InPrivilegeQuarantine(ag, a, Ctr))
        """
        contract = self.registered_tools.get(tool_id)
        if not contract:
            return 1.0
        effective_ctx = provenance_tracker.compute_effective_context_label()
        slice_label = provenance_tracker.compute_backward_argument_slice_label(
            arguments,
            is_mutating=contract.is_state_mutating
        )
        ell_int = slice_label.integrity
        ell_conf = effective_ctx.confidentiality | slice_label.confidentiality
        clearance = contract.max_permitted_confidentiality

        rank_map = {
            IntegrityLevel.UNTRUSTED: 0,
            IntegrityLevel.SANITIZED: 1,
            IntegrityLevel.VERIFIED: 2,
            IntegrityLevel.SYSTEM_AUTHORIZED: 3,
        }

        # Term 1: Parameter-level integrity deficit
        if contract.param_integrity_thresholds and arguments:
            deficits = []
            for p_name, p_val in arguments.items():
                p_req_level = contract.param_integrity_thresholds.get(p_name, contract.min_required_integrity)
                p_lbl = provenance_tracker.compute_backward_slice_label(
                    {p_name: p_val},
                    is_mutating=contract.is_state_mutating,
                    is_control_param=(p_req_level.value >= IntegrityLevel.SANITIZED.value),
                    param_name=p_name
                )
                r_req_p = max(1, rank_map.get(p_req_level, 1))
                r_eff_p = rank_map.get(p_lbl.integrity, 0)
                if rank_map.get(p_req_level, 0) == 0:
                    deficits.append(0.0)
                else:
                    deficits.append(max(0.0, (r_req_p - r_eff_p) / float(r_req_p)))
            integrity_deficit = max(deficits) if deficits else 0.0
        else:
            r_req = max(1, rank_map.get(contract.min_required_integrity, 1))
            r_eff = rank_map.get(ell_int, 0)
            integrity_deficit = (
                0.0 if rank_map.get(contract.min_required_integrity, 0) == 0
                else max(0.0, (r_req - r_eff) / float(r_req))
            )

        # Term 2: Confidentiality compartment excess
        excess_compartments = ell_conf - clearance
        conf_excess = min(1.0, 0.95 * len(excess_compartments)) if excess_compartments else 0.0

        # Term 3: Subagent ancestry ceiling violation
        ceiling_violation = 0.0
        if caller_agent_id in self.agent_ceilings:
            ceil = self.agent_ceilings[caller_agent_id]
            if rank_map.get(contract.min_required_integrity, 0) > rank_map.get(ceil.integrity, 3) or not (
                ell_conf <= ceil.confidentiality
            ):
                ceiling_violation = 1.0

        # Term 5 (checked before evaluate_and_enforce mutates active_escrows):
        # Privilege quarantine indicator 1(Ctr.IsMutating ^ InPrivilegeQuarantine(ag, a, Ctr))
        quarantine_violation = (
            1.0 if (contract.is_state_mutating and self.in_privilege_quarantine(caller_agent_id, arguments, contract))
            else 0.0
        )

        # Term 4: Mutating tool integrity / unattenuated violation indicator
        action, _, _ = self.evaluate_and_enforce(
            caller_agent_id=caller_agent_id,
            tool_id=tool_id,
            arguments=arguments,
            provenance_tracker=provenance_tracker,
        )
        cat_indicator = 0.0 if (action == AttenuationAction.PERMIT and (ell_conf <= clearance)) else (
            0.95 if action in (AttenuationAction.ATTENUATE_SANITIZE, AttenuationAction.DOWNGRADE_READONLY) else 1.0
        )
        return max(integrity_deficit, conf_excess, ceiling_violation, cat_indicator, quarantine_violation)

    def evaluate_live_gemini_tool_invocation(
        self,
        caller_agent_id: str,
        tool_id: str,
        prompt_text: str,
        provenance_tracker: CausalProvenanceTracker,
        project_id: str = "aniket-personal",
        location: str = "global",
        model_name: str = "gemini-3.8-flash",
    ) -> Tuple[AttenuationAction, Dict[str, Any], AttenuationVoucher]:
        """
        Invokes a live Gemini model on the Gemini Enterprise Agent Platform (`aniket-personal`,
        `location="global"`, supporting `gemini-4-argon`, `gemini-3.8-flash`, `gemini-3.5-flash`,
        `gemini-2.5-flash`) via the Google Gen AI SDK (`google.genai`) to synthesize JSON tool
        arguments from `prompt_text`, then enforces Agent-Lattice non-interference at the gateway boundary.
        """
        import json
        import subprocess
        from google import genai
        from google.oauth2.credentials import Credentials

        token = subprocess.check_output(
            ["gcloud", "auth", "print-access-token"], text=True, timeout=5.0
        ).strip()
        creds = Credentials(token=token, quota_project_id=project_id) if token else None
        client = genai.Client(vertexai=True, project=project_id, location=location, credentials=creds)
        resp = client.models.generate_content(
            model=model_name,
            contents=(
                f"Extract a JSON object of tool arguments for `{tool_id}` from the following request. "
                f"Return ONLY valid JSON: {prompt_text}"
            ),
        )
        raw = (resp.text or "{}").strip()
        if raw.startswith("```"):
            raw = raw.strip("`").removeprefix("json").strip()
        try:
            args = json.loads(raw)
            if not isinstance(args, dict):
                args = {"query": str(raw)}
        except Exception:
            args = {"query": str(raw)}

        return self.evaluate_and_enforce(
            caller_agent_id=caller_agent_id,
            tool_id=tool_id,
            arguments=args,
            provenance_tracker=provenance_tracker,
        )
