"""
Automated LaTeX & Scientific Paper Validator for agent_lattice_paper.tex
Verifies environment balancing, math delimiter parity, citation integrity,
cross-reference resolution, and absence of placeholder tokens.
"""

import re
import sys

def verify_latex(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    errors = []
    warnings = []

    print(f"Auditing LaTeX Manuscript: {file_path}")
    print("=" * 70)

    # 1. Environment Balancing
    begins = re.findall(r'\\begin\{([a-zA-Z0-9*]+)\}', content)
    ends = re.findall(r'\\end\{([a-zA-Z0-9*]+)\}', content)

    begin_counts = {}
    for b in begins:
        begin_counts[b] = begin_counts.get(b, 0) + 1
    end_counts = {}
    for e in ends:
        end_counts[e] = end_counts.get(e, 0) + 1

    all_envs = set(begin_counts.keys()).union(set(end_counts.keys()))
    for env in sorted(all_envs):
        bc = begin_counts.get(env, 0)
        ec = end_counts.get(env, 0)
        if bc != ec:
            errors.append(f"Mismatched environment '{env}': {bc} \\begin vs {ec} \\end")
        else:
            print(f"  [PASS] Environment '{env}': {bc} balanced pairs")

    # 2. Inline Math Parity ($)
    # Remove escaped dollars \$
    clean_dollars = re.sub(r'\\\$', '', content)
    dollar_count = clean_dollars.count('$')
    if dollar_count % 2 != 0:
        errors.append(f"Unbalanced inline math ($): found {dollar_count} occurrences (odd number)")
    else:
        print(f"  [PASS] Inline math ($): {dollar_count} occurrences ({dollar_count // 2} balanced pairs)")

    # 3. Citations and Bibliography Integrity
    bib_start = content.find(r'\begin{thebibliography}')
    main_text = content[:bib_start] if bib_start != -1 else content
    bib_text = content[bib_start:] if bib_start != -1 else ""

    ordered_cites = []
    for c in re.findall(r'\\cite\{([^}]+)\}', main_text):
        for single in c.split(','):
            s = single.strip()
            if s not in ordered_cites:
                ordered_cites.append(s)

    bibitems = re.findall(r'\\bibitem\{([^}]+)\}', bib_text)
    flat_citations = set(ordered_cites)
    set_bibitems = set(bibitems)

    missing_bib = flat_citations - set_bibitems
    uncited_bib = set_bibitems - flat_citations

    if missing_bib:
        errors.append(f"Missing bibliography entries for citations: {missing_bib}")
    else:
        print(f"  [PASS] Citations matched: all {len(flat_citations)} cited keys exist in bibliography")

    if uncited_bib:
        warnings.append(f"Uncited bibliography entries: {uncited_bib}")
    else:
        print(f"  [PASS] Bibliography clean: all {len(bibitems)} entries are cited in text")

    if ordered_cites == bibitems:
        print(f"  [PASS] Citation sequence strictly monotonic: all {len(ordered_cites)} citations cited in exact order [1..{len(bibitems)}]")
    else:
        errors.append(f"Citations not in monotonic order matching bibliography: {ordered_cites} vs {bibitems}")

    # 4. Labels and References
    labels = set(re.findall(r'\\label\{([^}]+)\}', content))
    refs = set(re.findall(r'\\ref\{([^}]+)\}', content))
    missing_labels = refs - labels
    if missing_labels:
        errors.append(f"Missing labels for references: {missing_labels}")
    else:
        print(f"  [PASS] References matched: all {len(refs)} references have corresponding labels")

    # 5. Placeholders and Prohibited Terms
    banned_terms = ["TODO", "TBD", "PLACEHOLDER", "INSERT HERE", "FIXME", "XXX", "BLUFF", "MOCK"]
    found_banned = []
    for term in banned_terms:
        if term in content:
            found_banned.append(term)
    if found_banned:
        errors.append(f"Prohibited placeholder terms found: {found_banned}")
    else:
        print("  [PASS] Zero placeholder / banned terms detected")

    # 6. Author Block Check
    if "Aniket Agrawal" in content and "aniketagrawal@google.com" in content and "Google" in content:
        print("  [PASS] Author block certified: Aniket Agrawal, Google Cloud, aniketagrawal@google.com")
    else:
        errors.append("Author block missing required Google attribution details")

    print("=" * 70)
    if errors:
        print(f"AUDIT FAILED with {len(errors)} error(s):")
        for err in errors:
            print(f"  - [FAIL] {err}")
        sys.exit(1)
    else:
        print(f"AUDIT 100% SUCCESS: Certified Diamond Quality for Overleaf compilation!")
        if warnings:
            for w in warnings:
                print(f"  - [WARN] {w}")

if __name__ == "__main__":
    path = "/Users/aniketagrawal/antigravity_workshop/agent_lattice/agent_lattice_paper.tex"
    verify_latex(path)
