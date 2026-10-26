"""
Agent-Lattice: Causal Provenance & Token-Level Taint Tracking Engine
Maintains causal dependency graphs over prompt token spans and tracks
dynamic taint propagation across multi-agent message passing and tool returns.
"""

from typing import List, Dict, Any, Optional, Set, Tuple, Callable
from collections import Counter
import math
import re
from agent_lattice.types import (
    SecurityLabel,
    IntegrityLevel,
    ConfidentialityCompartment,
    TokenSpan
)
from agent_lattice.lattice import SecurityLattice

#Deterministic regex word-token lexer matching Section III-B.1: \w+|[^\w\s]
WORD_TOKEN_REGEX = re.compile(r"\w+|[^\w\s]")


def compute_empirical_bit_entropy(v: str) -> float:
    r"""
    Computes empirical Shannon bit-entropy \hat{H}_{bit}(v) = |v| * H_2(v)
    where H_2(v) = - \sum_{c \in \Sigma(v)} (count(c)/|v|) \log_2(count(c)/|v|).
    High-entropy identifiers satisfy \hat{H}_{bit}(v) >= 24.0 bits, |v| >= 8, |\Sigma(v)| >= 6.
    """
    if not v:
        return 0.0
    n = len(v)
    counts = Counter(v)
    h2 = -sum((cnt / n) * math.log2(cnt / n) for cnt in counts.values())
    return float(n * h2)


def is_high_entropy_literal(v: str) -> bool:
    r"""
    Checks all three high-entropy identifier invariants (Section III-B.1):
    1. |v| >= 8 characters
    2. |\Sigma(v)| >= 6 distinct characters
    3. \hat{H}_{bit}(v) >= 24.0 bits
    """
    if len(v) < 8 or len(set(v)) < 6:
        return False
    return compute_empirical_bit_entropy(v) >= 24.0


class CausalProvenanceTracker:
    """
    Maintains fine-grained causal provenance and security labels for agent working memory.
    Tracks taint injection from untrusted sources (e.g. web search, external emails, unverified user input)
    and confidentiality tags from internal databases (e.g. customer PII, financial ledgers).
    """

    def __init__(self, agent_id: str, baseline_clearance: Optional[SecurityLabel] = None):
        self.agent_id = agent_id
        # Baseline capability granted by system (static clearance)
        self.baseline_clearance = baseline_clearance or SecurityLabel(
            confidentiality={ConfidentialityCompartment.INTERNAL},
            integrity=IntegrityLevel.SYSTEM_AUTHORIZED
        )
        self.token_spans: List[TokenSpan] = []
        # Optional fine-grained source integrity overrides (e.g., 5-level refinement I_user = 0.5)
        self.span_fine_integrity: Dict[str, float] = {}
        # Registered deterministic expression canonicalizers \phi_{canon} \in C_{schema}(p)
        self.expression_canonicalizers: Dict[str, List[Callable[[str], List[str]]]] = {}

    def register_expression_canonicalizer(
        self,
        param_name: str,
        canonicalizer_fn: Callable[[str], List[str]]
    ) -> None:
        r"""
        Registers a deterministic schema-bound expression canonicalizer \phi_{canon} \in C_{schema}(p)
        (e.g., ISO-8601 date normalizer, currency/unit converter, or arithmetic/concatenation reducer)
        that maps source spans into canonical candidate target strings during backward slicing.
        """
        self.expression_canonicalizers.setdefault(param_name, []).append(canonicalizer_fn)

    def ingest_token_span(
        self,
        text: str,
        source: str,
        label: SecurityLabel,
        fine_integrity: Optional[float] = None
    ) -> TokenSpan:
        """
        Ingests a new chunk or token span into the agent's context window.
        """
        span = TokenSpan(
            text=text,
            source_agent_or_tool=source,
            label=label
        )
        self.token_spans.append(span)
        self.span_fine_integrity[span.span_id] = (
            float(fine_integrity) if fine_integrity is not None else float(label.integrity.value)
        )
        return span

    def ingest_untrusted_input(self, text: str, source: str = "EXTERNAL_INPUT") -> TokenSpan:
        """
        Convenience method to ingest completely untrusted external text (I_untrusted = 0.0).
        Unclassified public data has an empty set of confidentiality compartments (bot_conf = set()).
        """
        label = SecurityLabel(
            confidentiality=set(),
            integrity=IntegrityLevel.UNTRUSTED
        )
        return self.ingest_token_span(text, source, label, fine_integrity=0.0)

    def ingest_authenticated_user_input(self, text: str, source: str = "AUTHENTICATED_USER_PROMPT") -> TokenSpan:
        """
        Ingests an authenticated user prompt under the 5-level integrity refinement (I_user = 0.5),
        partitioning direct authenticated user intent (0.5) from unverified third-party external data (0.0).
        """
        label = SecurityLabel(
            confidentiality=set(),
            integrity=IntegrityLevel.UNTRUSTED
        )
        return self.ingest_token_span(text, source, label, fine_integrity=0.5)

    def ingest_internal_tool_output(
        self,
        text: str,
        tool_id: str,
        compartments: Set[ConfidentialityCompartment],
        integrity: IntegrityLevel = IntegrityLevel.VERIFIED
    ) -> TokenSpan:
        """
        Ingests output returned from an internal tool (e.g. Spanner or SAP).
        """
        label = SecurityLabel(
            confidentiality=compartments,
            integrity=integrity
        )
        return self.ingest_token_span(text, tool_id, label, fine_integrity=float(integrity.value))

    def compute_effective_context_label(self) -> SecurityLabel:
        """
        Computes the effective runtime security label of the agent's current working memory:
            L_context = \\bigsqcup_{t \\in TokenSpans} Label(t)
        Under the product lattice join:
            C_effective = \\bigcup C_t  (Union of all confidentiality tags present)
            I_effective = \\min I_t     (Degrades to the least trusted token in context)
        If no spans exist, returns baseline clearance.
        """
        if not self.token_spans:
            return self.baseline_clearance

        effective = self.token_spans[0].label
        for span in self.token_spans[1:]:
            effective = SecurityLattice.join(effective, span.label)

        return effective

    @staticmethod
    def _check_token_proximity(span_text: str, key_alias: str, val_norm: str, window: int = 12) -> bool:
        """
        Verifies whether a low-entropy literal `val_norm` occurs within +/- `window` (default 12)
        word tokens (defined by WORD_TOKEN_REGEX = r'\\w+|[^\\w\\s]') of `key_alias` in `span_text`.
        """
        tokens = [t.lower() for t in WORD_TOKEN_REGEX.findall(span_text)]
        key_tokens = [t.lower() for t in WORD_TOKEN_REGEX.findall(key_alias)]
        val_tokens = [t.lower() for t in WORD_TOKEN_REGEX.findall(val_norm)]
        if not key_tokens or not val_tokens:
            return False

        key_positions = [
            i for i in range(len(tokens))
            if tokens[i:i + len(key_tokens)] == key_tokens or tokens[i] == key_tokens[0]
        ]
        val_positions = [
            j for j in range(len(tokens))
            if tokens[j:j + len(val_tokens)] == val_tokens or tokens[j] == val_tokens[0]
        ]
        if not key_positions or not val_positions:
            return False
        return any(abs(kp - vp) <= window for kp in key_positions for vp in val_positions)

    def compute_backward_slice_label(
        self,
        param_value: Any,
        is_mutating: bool = False,
        is_control_param: bool = False,
        param_name: Optional[str] = None,
        min_endorse_integrity: float = 0.0
    ) -> SecurityLabel:
        """
        Argument-Level Backward Causal Provenance Slicing (Decoupled Dimensions):
        Determines the security label of an outgoing argument string by tracing which
        token spans in the context window causally contributed to its substring or tokens.

        Universal Priority-Tiered Span Resolution (Section III-B.1):
        For execution-control parameters (is_control_param=True, p in S_ctrl), both the high-entropy
        (H_bit >= 24 bits, |v| >= 8, |Sigma(v)| >= 6) and low-entropy (+/-12-word-token proximity)
        matching regimes apply priority-tiered span resolution:
          - Tier 1: Spans from the eliciting user/system turn or carrying I(t) >= min_endorse_integrity
            (or endorsed spans) take precedence for integrity projection over unreferenced untrusted
            tool observations (I = 0) that echo the same literal or key alias, preventing adversarial
            taint-contamination DoS.
          - Confidentiality projection continues to traverse across all matching spans to preserve
            strict Bell-LaPadula non-interference.
        """
        if isinstance(param_value, dict) and len(param_value) == 1 and param_name is None:
            only_k, only_v = next(iter(param_value.items()))
            param_name = str(only_k)
            val_raw_str = str(only_v) if only_v is not None else ""
        else:
            val_raw_str = str(param_value) if param_value is not None else ""

        val_str = val_raw_str.lower().strip().replace("-", "") if param_value is not None else ""
        matched_spans: List[TokenSpan] = []

        if val_str and val_str not in ("{}", "[]", "none", "''", '""'):
            high_entropy = is_high_entropy_literal(val_str)
            for span in self.token_spans:
                span_norm = span.text.lower().replace("-", "")
                words = [w for w in re.findall(r'\b\w{3,}\b', span_norm)]
                direct_match = any(w in val_str for w in words) or (val_str in span_norm)

                # Check registered deterministic expression canonicalizers \phi_{canon} \in C_{schema}(p)
                canon_match = False
                if not direct_match and param_name and param_name in self.expression_canonicalizers:
                    for canon_fn in self.expression_canonicalizers[param_name]:
                        try:
                            candidates = [c.lower().strip().replace("-", "") for c in canon_fn(span.text)]
                            if any(c and (c in val_str or val_str in c) for c in candidates):
                                canon_match = True
                                break
                        except Exception:
                            pass

                if direct_match or canon_match:
                    # For low-entropy control parameters where param_name appears in the span,
                    # verify +/-12 word-token proximity when key alias is present
                    if is_control_param and not high_entropy and param_name:
                        key_norm = param_name.lower().replace("_", " ")
                        if key_norm in span.text.lower() or param_name.lower() in span.text.lower():
                            if not (
                                self._check_token_proximity(span.text, param_name, val_raw_str, window=12)
                                or self._check_token_proximity(span.text, key_norm, val_raw_str, window=12)
                            ):
                                continue
                    matched_spans.append(span)

        if not matched_spans:
            # Explicit fail-closed boundary condition for empty or unreferenced argument slices
            effective = self.compute_effective_context_label()
            if is_mutating or is_control_param:
                return SecurityLabel(
                    confidentiality=effective.confidentiality if is_mutating else set(),
                    integrity=IntegrityLevel.UNTRUSTED if is_control_param else effective.integrity
                )
            return SecurityLabel(
                confidentiality=set(),
                integrity=effective.integrity
            )

        # 1. Integrity Projection: Halts at endorsement cuts and applies universal priority-tiered
        # resolution for execution-control parameters (p in S_ctrl) across high- and low-entropy regimes
        endorsed_spans = [s for s in matched_spans if s.is_endorsement_boundary]
        if endorsed_spans:
            integrity_spans = endorsed_spans
        elif is_control_param:
            # Tier 1: Spans with fine_integrity >= max(min_endorse_integrity, 0.5) or integer integrity >= 1
            tier1_spans = [
                s for s in matched_spans
                if self.span_fine_integrity.get(s.span_id, float(s.label.integrity.value)) >= max(min_endorse_integrity, 0.5)
                or s.label.integrity.value >= IntegrityLevel.SANITIZED.value
            ]
            integrity_spans = tier1_spans if tier1_spans else matched_spans
        else:
            integrity_spans = matched_spans

        min_integrity = min(s.label.integrity.value for s in integrity_spans)

        # 2. Confidentiality Projection: Traverses through cuts to aggregate all active compartments
        all_confidentiality = set()
        for s in matched_spans:
            all_confidentiality.update(s.label.confidentiality)

        return SecurityLabel(
            confidentiality=all_confidentiality,
            integrity=IntegrityLevel(min_integrity)
        )

    def compute_backward_argument_slice_label(
        self,
        param_value: Any,
        is_mutating: bool = False
    ) -> SecurityLabel:
        """
        Alias for compute_backward_slice_label used by pre-attenuation scoring (Eq. 27).
        """
        return self.compute_backward_slice_label(param_value=param_value, is_mutating=is_mutating)

    def endorse_token_span(
        self,
        span_id: str,
        new_integrity: IntegrityLevel = IntegrityLevel.SANITIZED,
        min_endorse_integrity: float = 0.0
    ) -> bool:
        """
        Dynamic Endorsement Operator (\\nabla_{endorse}):
        Signature: (L x V) x M_schema -> L
        Declassifies/elevates the integrity of an untrusted token span once its concrete value v
        passes strict schema validation m(v) = True over non-instructional primitive types
        (UUIDs, enums, numeric quantities, boolean flags) AND its pre-endorsement integrity
        satisfies I_{a,p}^{raw} >= I_{min}^{endorse} (supporting the 5-level refinement
        where I_user = 0.5 >= I_min^endorse = 0.5 while third-party I_untrusted = 0.0 is barred).
        """
        for span in self.token_spans:
            if span.span_id == span_id:
                raw_fine_integ = self.span_fine_integrity.get(span.span_id, float(span.label.integrity.value))
                if raw_fine_integ < min_endorse_integrity:
                    return False
                span.label.integrity = new_integrity
                span.is_endorsement_boundary = True
                self.span_fine_integrity[span.span_id] = float(new_integrity.value)
                return True
        return False

    def spawn_subagent(
        self,
        child_agent_id: str,
        requested_clearance: Optional[SecurityLabel] = None,
        requested_tools: Optional[Set[str]] = None,
        parent_tools: Optional[Set[str]] = None
    ) -> Tuple["CausalProvenanceTracker", Set[str]]:
        """
        Subagent Ancestry Authorization Ceiling (Section III-C, Eq. 20, Claim 7):
        When a parent agent A_parent spawns a child subagent A_child:
        1. Inherits ambient data taint from parent under lattice domination (L_parent <= L_child).
        2. Restricts child clearance within ancestry ceiling:
           - C_clearance(A_child) subseteq C_clearance(A_parent)
           - Tools(A_child) subseteq Tools(A_parent)
           - I_clearance(A_child) <=_trust I_clearance(A_parent)
        """
        if requested_clearance is None:
            child_conf = set(self.baseline_clearance.confidentiality)
            child_integ = self.baseline_clearance.integrity
        else:
            child_conf = requested_clearance.confidentiality.intersection(self.baseline_clearance.confidentiality)
            child_integ = IntegrityLevel(min(requested_clearance.integrity.value, self.baseline_clearance.integrity.value))

        child_clearance = SecurityLabel(confidentiality=child_conf, integrity=child_integ)

        if parent_tools is not None and requested_tools is not None:
            permitted_tools = requested_tools.intersection(parent_tools)
        elif parent_tools is not None:
            permitted_tools = set(parent_tools)
        elif requested_tools is not None:
            permitted_tools = set(requested_tools)
        else:
            permitted_tools = set()

        child_tracker = CausalProvenanceTracker(agent_id=child_agent_id, baseline_clearance=child_clearance)
        for span in self.token_spans:
            copied_span = TokenSpan(
                span_id=span.span_id,
                text=span.text,
                source_agent_or_tool=span.source_agent_or_tool,
                label=SecurityLabel(
                    confidentiality=set(span.label.confidentiality),
                    integrity=span.label.integrity
                ),
                is_endorsement_boundary=span.is_endorsement_boundary,
                created_at_epoch=span.created_at_epoch
            )
            child_tracker.token_spans.append(copied_span)
            child_tracker.span_fine_integrity[span.span_id] = self.span_fine_integrity.get(
                span.span_id, float(span.label.integrity.value)
            )

        return child_tracker, permitted_tools

    def deserialize_inbound_response(
        self,
        response_payload: Dict[str, Any],
        source: str = "STORED_STATE_OR_TOOL_OUTPUT",
        endpoint_max_integrity: IntegrityLevel = IntegrityLevel.SYSTEM_AUTHORIZED
    ) -> List[TokenSpan]:
        """
        Inbound Tool Response Deserialization Operator (D_inbound):
        Maps persisted schema metadata (_lattice_conf, _lattice_integ) from stored database records
        or API response payloads to newly resident token spans in context memory, bounded by
        the target endpoint trust ceiling: I(t_j) = min(I_deserialized, Ctr.I_endpoint_max).
        """
        conf_raw = response_payload.get("_lattice_conf", [])
        if isinstance(conf_raw, (list, tuple, set)):
            conf_set = {
                ConfidentialityCompartment(c) if isinstance(c, str) and c in ConfidentialityCompartment.__members__ else c
                for c in conf_raw
            }
        else:
            conf_set = set()

        integ_raw = response_payload.get("_lattice_integ", IntegrityLevel.UNTRUSTED)
        if isinstance(integ_raw, str):
            integ_level = IntegrityLevel[integ_raw] if integ_raw in IntegrityLevel.__members__ else IntegrityLevel.UNTRUSTED
        elif isinstance(integ_raw, int):
            integ_level = IntegrityLevel(integ_raw)
        elif isinstance(integ_raw, IntegrityLevel):
            integ_level = integ_raw
        else:
            integ_level = IntegrityLevel.UNTRUSTED

        bounded_integ = IntegrityLevel(min(integ_level.value, endpoint_max_integrity.value))

        created_spans = []
        text_content = (
            response_payload.get("content")
            or response_payload.get("data")
            or response_payload.get("text")
            or str({k: v for k, v in response_payload.items() if not k.startswith("_lattice_")})
        )
        span = self.ingest_token_span(
            text=str(text_content),
            source=source,
            label=SecurityLabel(confidentiality=conf_set, integrity=bounded_integ)
        )
        created_spans.append(span)
        return created_spans

    def reset_context(self):
        """
        Resets token spans for a fresh session.
        """
        self.token_spans.clear()
        self.span_fine_integrity.clear()
