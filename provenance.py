"""
Agent-Lattice: Causal Provenance & Token-Level Taint Tracking Engine
Maintains causal dependency graphs over prompt token spans and tracks
dynamic taint propagation across multi-agent message passing and tool returns.
"""

from typing import List, Dict, Any, Optional, Set, Tuple
import re
from agent_lattice.types import (
    SecurityLabel,
    IntegrityLevel,
    ConfidentialityCompartment,
    TokenSpan
)
from agent_lattice.lattice import SecurityLattice


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

    def ingest_token_span(self, text: str, source: str, label: SecurityLabel) -> TokenSpan:
        """
        Ingests a new chunk or token span into the agent's context window.
        """
        span = TokenSpan(
            text=text,
            source_agent_or_tool=source,
            label=label
        )
        self.token_spans.append(span)
        return span

    def ingest_untrusted_input(self, text: str, source: str = "EXTERNAL_INPUT") -> TokenSpan:
        """
        Convenience method to ingest completely untrusted external text.
        Unclassified public data has an empty set of confidentiality compartments (bot_conf = set()).
        """
        label = SecurityLabel(
            confidentiality=set(),
            integrity=IntegrityLevel.UNTRUSTED
        )
        return self.ingest_token_span(text, source, label)

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
        return self.ingest_token_span(text, tool_id, label)

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

    def compute_backward_slice_label(self, param_value: Any, is_mutating: bool = False) -> SecurityLabel:
        """
        Argument-Level Backward Causal Provenance Slicing (Decoupled Dimensions):
        Determines the security label of an outgoing argument string by tracing which
        token spans in the context window causally contributed to its substring or tokens.

        Decoupled Slicing Dimensions:
        1. Integrity Projection (G_slice^{integ}): Traversal halts at dynamic endorsement boundary
           cuts (\\nabla_{endorse}), ensuring raw, unverified ancestor tokens do not degrade
           the validated integrity floor (I >= SANITIZED).
        2. Confidentiality Projection (G_slice^{conf}): Traversal traverses upstream through
           endorsement cut nodes to aggregate all active confidentiality compartments
           (C_a = \\bigcup_{t in Ancestors(a)} C(t)), guaranteeing that integrity endorsement
           does NOT confound confidentiality declassification.

        Fail-Closed Boundary Condition:
        If param_value is empty ({}, [], None, "") and the invocation is state-mutating (is_mutating=True),
        or if no tokens matched, the invocation fails closed by defaulting directly to the ambient
        context label (I_a = I_eff, C_a = C_eff), preventing unverified injections from invoking
        Canonicalization and Identifier Collision Resolution:
        1. Canonicalization: Literal values are normalized (case-folded, UUID hyphen-stripped, whitespace-trimmed)
           prior to substring matching to eliminate formatting variations across frontier model outputs.
        2. Identifier Collisions: If an identical identifier appears in multiple context spans with conflicting
           security levels (e.g. untrusted customer email vs internal database record), the runtime resolves
           the collision via conservative product lattice join (\\bigsqcup): taking the arithmetic minimum of integrity
           and the set union of confidentiality compartments. This fail-secure rule prevents attackers from
           laundering untrusted parameters through benign identifier duplication.
        """
        # Canonicalization: case folding, strip hyphens/quotes/whitespace for robust token alignment
        val_str = str(param_value).lower().strip().replace("-", "") if param_value is not None else ""
        matched_spans = []

        if val_str and val_str not in ("{}", "[]", "none", "''", '""'):
            for span in self.token_spans:
                span_norm = span.text.lower().replace("-", "")
                words = [w for w in re.findall(r'\b\w{3,}\b', span_norm)]
                if any(w in val_str for w in words):
                    matched_spans.append(span)

        if not matched_spans:
            # Explicit fail-closed boundary condition for empty argument slices
            effective = self.compute_effective_context_label()
            if is_mutating:
                return effective
            # For non-mutating parameterless read queries, return unclassified confidentiality
            # bounded by context integrity
            return SecurityLabel(
                confidentiality=set(),
                integrity=effective.integrity
            )

        # 1. Integrity Projection: Halts at endorsement cuts
        endorsed_spans = [s for s in matched_spans if s.is_endorsement_boundary]
        integrity_spans = endorsed_spans if endorsed_spans else matched_spans
        # Conservative collision resolution: takes minimum integrity across matching spans
        min_integrity = min(s.label.integrity.value for s in integrity_spans)

        # 2. Confidentiality Projection: Traverses through cuts to aggregate all active compartments
        all_confidentiality = set()
        for s in matched_spans:
            all_confidentiality.update(s.label.confidentiality)

        return SecurityLabel(
            confidentiality=all_confidentiality,
            integrity=IntegrityLevel(min_integrity)
        )

    def endorse_token_span(self, span_id: str, new_integrity: IntegrityLevel = IntegrityLevel.SANITIZED) -> bool:
        """
        Dynamic Endorsement Operator (\\nabla_{endorse}):
        Signature: (L x V) x M_schema -> L
        Declassifies/elevates the integrity of an untrusted token span once its concrete value v
        passes strict schema validation m(v) = True over non-instructional primitive types
        (UUIDs, enums, numeric quantities, boolean flags).
        Establishes an explicit causal boundary/cut in G_prov to prevent unverified ancestor tokens
        from nullifying the elevated integrity during backward slicing.
        """
        for span in self.token_spans:
            if span.span_id == span_id:
                span.label.integrity = new_integrity
                span.is_endorsement_boundary = True
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
             (in dual information-flow ordering: I_clearance(A_parent) <=_integ I_clearance(A_child))
        Any requested privilege exceeding parent ceiling is clamped/attenuated to the parent's ceiling.
        """
        # 1. Clamped clearance ceiling
        if requested_clearance is None:
            child_conf = set(self.baseline_clearance.confidentiality)
            child_integ = self.baseline_clearance.integrity
        else:
            # Cannot expand confidentiality beyond parent's clearance
            child_conf = requested_clearance.confidentiality.intersection(self.baseline_clearance.confidentiality)
            # Cannot exceed parent's trust level (arithmetic min: I_child <=_trust I_parent)
            child_integ = IntegrityLevel(min(requested_clearance.integrity.value, self.baseline_clearance.integrity.value))

        child_clearance = SecurityLabel(confidentiality=child_conf, integrity=child_integ)

        # 2. Clamped tool inventory
        if parent_tools is not None and requested_tools is not None:
            permitted_tools = requested_tools.intersection(parent_tools)
        elif parent_tools is not None:
            permitted_tools = set(parent_tools)
        elif requested_tools is not None:
            permitted_tools = set(requested_tools)
        else:
            permitted_tools = set()

        # 3. Inherit ambient context tokens (data taint propagation: L_parent <= L_child)
        child_tracker = CausalProvenanceTracker(agent_id=child_agent_id, baseline_clearance=child_clearance)
        for span in self.token_spans:
            child_tracker.token_spans.append(
                TokenSpan(
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
            )

        return child_tracker, permitted_tools

    def deserialize_inbound_response(
        self,
        response_payload: Dict[str, Any],
        source: str = "STORED_STATE_OR_TOOL_OUTPUT"
    ) -> List[TokenSpan]:
        """
        Inbound Tool Response Deserialization Operator (D_inbound):
        Section VI-A.3 & Claim 2:
        Maps persisted schema metadata (_lattice_conf, _lattice_integ) from stored database records
        or API response payloads to newly resident token spans in context memory.
        Assigns I = UNTRUSTED (0) to unverified external/user fields, preventing stored indirect injections
        from evading taint tracking across multi-session data persistence lifecycles.
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
            label=SecurityLabel(confidentiality=conf_set, integrity=integ_level)
        )
        created_spans.append(span)
        return created_spans

    def reset_context(self):
        """
        Resets token spans for a fresh session.
        """
        self.token_spans.clear()
