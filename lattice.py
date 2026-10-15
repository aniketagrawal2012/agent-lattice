"""
Agent-Lattice: Mathematical Security Lattice Engine
Formal algebraic implementation of Decentralized Information-Flow Control (DIFC)
over Product Lattice L = (P(K), subseteq) x (I_ord, >=).
"""

from typing import Set, Tuple, List
from agent_lattice.types import (
    SecurityLabel,
    IntegrityLevel,
    ConfidentialityCompartment
)


class SecurityLattice:
    """
    Formal algebraic engine for Information-Flow Control in Multi-Agent Swarms.
    Operates over the product lattice:
        L = L_conf x L_integ
    where:
        L_conf = (P(K), subseteq) is the boolean lattice of security compartments.
        L_integ = (I, >=) is the totally ordered lattice of trust levels.
    """

    ALL_COMPARTMENTS: Set[ConfidentialityCompartment] = set(ConfidentialityCompartment)

    @classmethod
    def bottom(cls) -> SecurityLabel:
        """
        Bottom element (\\bot):
        Zero confidentiality compartments (fully public), maximum integrity (system authorized).
        Dominates all flows; safe to send anywhere and trust unconditionally.
        """
        return SecurityLabel(
            confidentiality=set(),
            integrity=IntegrityLevel.SYSTEM_AUTHORIZED
        )

    @classmethod
    def top(cls) -> SecurityLabel:
        """
        Top element (\\top):
        All confidentiality compartments (top secret), minimum integrity (completely untrusted).
        Cannot flow to any standard sink without declassification / sanitization.
        """
        return SecurityLabel(
            confidentiality=set(cls.ALL_COMPARTMENTS),
            integrity=IntegrityLevel.UNTRUSTED
        )

    @classmethod
    def can_flow(cls, source_label: SecurityLabel, sink_label: SecurityLabel) -> bool:
        """
        Fundamental Non-Interference Invariant:
        Information at source_label may flow to sink_label iff source_label is dominated by sink_label:
            source_label \\sqsubseteq sink_label
        <=> C_source \\subseteq C_sink  (Confidentiality: No Read Up / No Write Down)
        and I_source >= I_sink          (Integrity: No Write Up / No Read Down)
        """
        return source_label.is_dominated_by(sink_label)

    @classmethod
    def join(cls, label_a: SecurityLabel, label_b: SecurityLabel) -> SecurityLabel:
        """
        Least Upper Bound (LUB / a \\sqcup b):
        Represents combining information from two sources.
        Confidentiality accumulates: C_new = C_a \\cup C_b
        Integrity degrades to worst: I_new = min(I_a, I_b)
        """
        return label_a.join(label_b)

    @classmethod
    def meet(cls, label_a: SecurityLabel, label_b: SecurityLabel) -> SecurityLabel:
        """
        Greatest Lower Bound (GLB / a \\sqcap b):
        Represents highest common permission required to satisfy both.
        Confidentiality relaxes: C_new = C_a \\cap C_b
        Integrity elevates: I_new = max(I_a, I_b)
        """
        return label_a.meet(label_b)

    @classmethod
    def verify_lattice_axioms(cls) -> bool:
        """
        Formal mathematical verification of lattice axioms across all combinations:
        1. Idempotence: a \\sqcup a = a, a \\sqcap a = a
        2. Commutativity: a \\sqcup b = b \\sqcup a, a \\sqcap b = b \\sqcap a
        3. Associativity: (a \\sqcup b) \\sqcup c = a \\sqcup (b \\sqcup c)
        4. Absorption: a \\sqcup (a \\sqcap b) = a, a \\sqcap (a \\sqcup b) = a
        5. Monotonicity: a \\sqsubseteq b ==> a \\sqcup c \\sqsubseteq b \\sqcup c
        """
        test_labels = [
            SecurityLabel(confidentiality=set(), integrity=IntegrityLevel.SYSTEM_AUTHORIZED),
            SecurityLabel(confidentiality={ConfidentialityCompartment.PII}, integrity=IntegrityLevel.VERIFIED),
            SecurityLabel(confidentiality={ConfidentialityCompartment.FINANCIAL, ConfidentialityCompartment.PII}, integrity=IntegrityLevel.SANITIZED),
            SecurityLabel(confidentiality={ConfidentialityCompartment.SYSTEM_CONFIG}, integrity=IntegrityLevel.UNTRUSTED),
            cls.bottom(),
            cls.top()
        ]

        for a in test_labels:
            # 1. Idempotence
            if cls.join(a, a).confidentiality != a.confidentiality or cls.join(a, a).integrity != a.integrity:
                return False
            if cls.meet(a, a).confidentiality != a.confidentiality or cls.meet(a, a).integrity != a.integrity:
                return False

            for b in test_labels:
                # 2. Commutativity
                j1 = cls.join(a, b)
                j2 = cls.join(b, a)
                if j1.confidentiality != j2.confidentiality or j1.integrity != j2.integrity:
                    return False

                m1 = cls.meet(a, b)
                m2 = cls.meet(b, a)
                if m1.confidentiality != m2.confidentiality or m1.integrity != m2.integrity:
                    return False

                # 4. Absorption
                abs1 = cls.join(a, cls.meet(a, b))
                if abs1.confidentiality != a.confidentiality or abs1.integrity != a.integrity:
                    return False

                abs2 = cls.meet(a, cls.join(a, b))
                if abs2.confidentiality != a.confidentiality or abs2.integrity != a.integrity:
                    return False

                for c in test_labels:
                    # 3. Associativity
                    j_assoc1 = cls.join(cls.join(a, b), c)
                    j_assoc2 = cls.join(a, cls.join(b, c))
                    if j_assoc1.confidentiality != j_assoc2.confidentiality or j_assoc1.integrity != j_assoc2.integrity:
                        return False

                    m_assoc1 = cls.meet(cls.meet(a, b), c)
                    m_assoc2 = cls.meet(a, cls.meet(b, c))
                    if m_assoc1.confidentiality != m_assoc2.confidentiality or m_assoc1.integrity != m_assoc2.integrity:
                        return False

                    # 5. Monotonicity: a <= b ==> (a join c <= b join c) and (a meet c <= b meet c)
                    if cls.can_flow(a, b):
                        ac_j = cls.join(a, c)
                        bc_j = cls.join(b, c)
                        if not cls.can_flow(ac_j, bc_j):
                            return False

                        ac_m = cls.meet(a, c)
                        bc_m = cls.meet(b, c)
                        if not cls.can_flow(ac_m, bc_m):
                            return False

        return True
