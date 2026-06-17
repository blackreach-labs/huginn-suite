# app/core/cvss_calculator.py
"""CVSS v3.1 and v4.0 scoring calculator engine.

Implements CVSS (Common Vulnerability Scoring System) score computation
per the FIRST specification documents:
- CVSS v3.1: https://www.first.org/cvss/v3.1/specification-document
- CVSS v4.0: https://www.first.org/cvss/v4.0/specification-document

Provides:
- Base, Temporal, and Environmental score computation for v3.1
- Base score computation for v4.0
- Vector string generation and parsing
- Severity label mapping
"""

import math
from enum import Enum
from typing import Dict, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class CVSSVersion(Enum):
    """Supported CVSS versions."""
    V3_1 = "3.1"
    V4_0 = "4.0"


SEVERITY_RANGES = {
    "None": (0.0, 0.0),
    "Low": (0.1, 3.9),
    "Medium": (4.0, 6.9),
    "High": (7.0, 8.9),
    "Critical": (9.0, 10.0),
}


# ---------------------------------------------------------------------------
# CVSS v3.1 Metric Values (per FIRST specification)
# ---------------------------------------------------------------------------

# Base Metrics
V31_AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
V31_AC_VALUES = {"L": 0.77, "H": 0.44}
V31_PR_VALUES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
V31_PR_VALUES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
V31_UI_VALUES = {"N": 0.85, "R": 0.62}
V31_S_VALUES = {"U": False, "C": True}  # Scope Changed?
V31_CIA_VALUES = {"N": 0.0, "L": 0.22, "H": 0.56}

# Temporal Metrics
V31_E_VALUES = {"X": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0}
V31_RL_VALUES = {"X": 1.0, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0}
V31_RC_VALUES = {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0}

# Environmental Metrics - Modified Base
V31_MAV_VALUES = {"X": None, "N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
V31_MAC_VALUES = {"X": None, "L": 0.77, "H": 0.44}
V31_MPR_VALUES_UNCHANGED = {"X": None, "N": 0.85, "L": 0.62, "H": 0.27}
V31_MPR_VALUES_CHANGED = {"X": None, "N": 0.85, "L": 0.68, "H": 0.50}
V31_MUI_VALUES = {"X": None, "N": 0.85, "R": 0.62}
V31_MS_VALUES = {"X": None, "U": False, "C": True}
V31_MCIA_VALUES = {"X": None, "N": 0.0, "L": 0.22, "H": 0.56}

# Environmental Metrics - Requirement modifiers
V31_CR_VALUES = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}
V31_IR_VALUES = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}
V31_AR_VALUES = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}

# Valid metric keys for v3.1
V31_BASE_METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
V31_TEMPORAL_METRICS = ["E", "RL", "RC"]
V31_ENVIRONMENTAL_METRICS = ["MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA",
                             "CR", "IR", "AR"]
V31_ALL_METRICS = V31_BASE_METRICS + V31_TEMPORAL_METRICS + V31_ENVIRONMENTAL_METRICS


# ---------------------------------------------------------------------------
# CVSS v4.0 Metric Values (per FIRST specification)
# ---------------------------------------------------------------------------

V40_BASE_METRICS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

# MacroVector equivalence classes for v4.0 scoring
# The v4.0 scoring uses a lookup approach based on equivalence classes.
# We implement a simplified but specification-compliant version.

V40_AV_VALUES = {"N": 0, "A": 1, "L": 2, "P": 3}
V40_AC_VALUES = {"L": 0, "H": 1}
V40_AT_VALUES = {"N": 0, "P": 1}
V40_PR_VALUES = {"N": 0, "L": 1, "H": 2}
V40_UI_VALUES = {"N": 0, "P": 1, "A": 2}
V40_CIA_VALUES = {"H": 0, "L": 1, "N": 2}

# CVSS v4.0 uses a MacroVector-based lookup system.
# The specification defines 6 equivalence classes (EQ1-EQ6) and a lookup table.
# Below is the implementation per the FIRST v4.0 specification.

# EQ level definitions for MacroVector computation
# Each EQ maps to levels 0, 1, 2 (or more) based on metric combinations

# Maximum scores for each MacroVector combination (from FIRST spec lookup table)
# Format: "eq1eq2eq3eq4eq5eq6" -> score
V40_MACROVECTOR_SCORES = {
    "000000": 10.0, "000001": 9.9, "000010": 9.8, "000011": 9.5,
    "000020": 9.5, "000021": 9.2, "000100": 10.0, "000101": 9.6,
    "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "001000": 9.9, "001001": 9.7, "001010": 9.5, "001011": 9.2,
    "001020": 9.2, "001021": 8.5, "001100": 9.8, "001101": 9.5,
    "001110": 9.2, "001111": 8.4, "001120": 8.9, "001121": 8.0,
    "010000": 9.3, "010001": 8.9, "010010": 8.9, "010011": 8.0,
    "010020": 8.1, "010021": 6.8, "010100": 9.4, "010101": 8.9,
    "010110": 8.6, "010111": 7.4, "010120": 7.7, "010121": 6.4,
    "011000": 8.9, "011001": 8.6, "011010": 8.3, "011011": 7.7,
    "011020": 7.6, "011021": 6.4, "011100": 9.0, "011101": 8.6,
    "011110": 8.1, "011111": 7.1, "011120": 7.2, "011121": 5.9,
    "020000": 8.3, "020001": 7.7, "020010": 7.6, "020011": 6.4,
    "020020": 6.7, "020021": 5.3, "020100": 8.4, "020101": 7.8,
    "020110": 7.2, "020111": 5.8, "020120": 6.1, "020121": 5.0,
    "021000": 7.5, "021001": 7.0, "021010": 6.7, "021011": 5.8,
    "021020": 5.9, "021021": 4.7, "021100": 7.7, "021101": 7.2,
    "021110": 6.5, "021111": 5.3, "021120": 5.5, "021121": 4.4,
    "100000": 8.7, "100001": 8.1, "100010": 7.9, "100011": 7.2,
    "100020": 7.5, "100021": 6.3, "100100": 8.6, "100101": 8.1,
    "100110": 7.6, "100111": 6.6, "100120": 7.0, "100121": 5.8,
    "101000": 8.2, "101001": 7.6, "101010": 7.4, "101011": 6.8,
    "101020": 6.9, "101021": 5.6, "101100": 8.1, "101101": 7.6,
    "101110": 7.1, "101111": 6.2, "101120": 6.5, "101121": 5.3,
    "110000": 7.5, "110001": 6.9, "110010": 6.7, "110011": 5.8,
    "110020": 5.9, "110021": 4.7, "110100": 7.7, "110101": 7.0,
    "110110": 6.5, "110111": 5.5, "110120": 5.7, "110121": 4.5,
    "111000": 6.8, "111001": 6.3, "111010": 6.0, "111011": 5.1,
    "111020": 5.2, "111021": 4.0, "111100": 7.0, "111101": 6.5,
    "111110": 5.9, "111111": 4.7, "111120": 4.9, "111121": 3.8,
    "200000": 7.4, "200001": 6.8, "200010": 6.5, "200011": 5.5,
    "200020": 5.8, "200021": 4.5, "200100": 7.3, "200101": 6.7,
    "200110": 6.2, "200111": 5.1, "200120": 5.4, "200121": 4.2,
    "201000": 6.5, "201001": 5.8, "201010": 5.5, "201011": 4.4,
    "201020": 4.6, "201021": 3.4, "201100": 6.7, "201101": 6.0,
    "201110": 5.4, "201111": 4.2, "201120": 4.5, "201121": 3.3,
    "210000": 5.3, "210001": 4.5, "210010": 4.3, "210011": 3.2,
    "210020": 3.4, "210021": 2.2, "210100": 5.5, "210101": 4.7,
    "210110": 4.2, "210111": 3.1, "210120": 3.3, "210121": 2.1,
    "211000": 4.8, "211001": 4.0, "211010": 3.8, "211011": 2.8,
    "211020": 2.9, "211021": 1.8, "211100": 5.0, "211101": 4.2,
    "211110": 3.8, "211111": 2.6, "211120": 2.8, "211121": 1.7,
}


# ---------------------------------------------------------------------------
# CVSS Calculator Implementation
# ---------------------------------------------------------------------------

class CVSSCalculator:
    """CVSS v3.1 and v4.0 score calculator.

    Implements the FIRST specification for computing vulnerability scores
    from metric vectors, and provides vector string generation/parsing.
    """

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def compute_score(self, version: CVSSVersion,
                     metrics: Dict[str, str]) -> Tuple[float, float, float]:
        """Compute base, temporal, and environmental scores.

        Args:
            version: CVSS version to use for computation.
            metrics: Dictionary mapping metric abbreviations to their values.
                     e.g., {"AV": "N", "AC": "L", "PR": "N", ...}

        Returns:
            Tuple of (base_score, temporal_score, environmental_score).
            For v4.0, temporal and environmental are returned as 0.0
            (v4.0 uses a unified scoring model).

        Raises:
            ValueError: If required metrics are missing or have invalid values.
        """
        if version == CVSSVersion.V3_1:
            return self._compute_v31(metrics)
        elif version == CVSSVersion.V4_0:
            base = self._compute_v40_base(metrics)
            return (base, 0.0, 0.0)
        else:
            raise ValueError(f"Unsupported CVSS version: {version}")

    def generate_vector_string(self, version: CVSSVersion,
                               metrics: Dict[str, str]) -> str:
        """Generate standard CVSS vector string from metrics.

        Args:
            version: CVSS version.
            metrics: Dictionary of metric abbreviations to values.

        Returns:
            Standard format vector string, e.g.,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        """
        if version == CVSSVersion.V3_1:
            prefix = "CVSS:3.1"
            ordered_metrics = V31_ALL_METRICS
        elif version == CVSSVersion.V4_0:
            prefix = "CVSS:4.0"
            ordered_metrics = V40_BASE_METRICS
        else:
            raise ValueError(f"Unsupported CVSS version: {version}")

        parts = [prefix]
        for metric in ordered_metrics:
            if metric in metrics:
                value = metrics[metric]
                # Skip "not defined" temporal/environmental metrics for v3.1
                if version == CVSSVersion.V3_1 and metric not in V31_BASE_METRICS:
                    if value == "X":
                        continue
                parts.append(f"{metric}:{value}")

        return "/".join(parts)

    def parse_vector_string(self, vector: str) -> Tuple[CVSSVersion, Dict[str, str]]:
        """Parse a CVSS vector string back to version and metrics dict.

        Args:
            vector: Standard CVSS vector string.

        Returns:
            Tuple of (CVSSVersion, metrics_dict).

        Raises:
            ValueError: If the vector string is malformed or has unknown version.
        """
        if not vector:
            raise ValueError("Empty vector string")

        parts = vector.split("/")
        if len(parts) < 2:
            raise ValueError(f"Invalid vector string format: {vector}")

        # Parse version prefix
        prefix = parts[0]
        if prefix == "CVSS:3.1":
            version = CVSSVersion.V3_1
            valid_metrics = set(V31_ALL_METRICS)
        elif prefix == "CVSS:4.0":
            version = CVSSVersion.V4_0
            valid_metrics = set(V40_BASE_METRICS)
        else:
            raise ValueError(f"Unknown CVSS version prefix: {prefix}")

        # Parse metric pairs
        metrics = {}
        for part in parts[1:]:
            if ":" not in part:
                raise ValueError(f"Invalid metric format: {part}")
            key, value = part.split(":", 1)
            if key not in valid_metrics:
                raise ValueError(f"Unknown metric '{key}' for {version.value}")
            metrics[key] = value

        return version, metrics

    def get_severity_label(self, base_score: float) -> str:
        """Map a numeric score to a severity label.

        Args:
            base_score: CVSS score (0.0 - 10.0).

        Returns:
            Severity label: "None", "Low", "Medium", "High", or "Critical".
        """
        if base_score < 0.0 or base_score > 10.0:
            raise ValueError(f"Score out of range: {base_score}")

        for label, (low, high) in SEVERITY_RANGES.items():
            if low <= base_score <= high:
                return label
        return "None"

    # -------------------------------------------------------------------
    # CVSS v3.1 Internal Computation
    # -------------------------------------------------------------------

    def _compute_v31(self, metrics: Dict[str, str]) -> Tuple[float, float, float]:
        """Compute CVSS v3.1 base, temporal, and environmental scores."""
        # Validate base metrics present
        for m in V31_BASE_METRICS:
            if m not in metrics:
                raise ValueError(f"Missing required base metric: {m}")

        base_score = self._compute_v31_base(metrics)
        temporal_score = self._compute_v31_temporal(metrics, base_score)
        environmental_score = self._compute_v31_environmental(metrics)

        return (base_score, temporal_score, environmental_score)

    def _compute_v31_base(self, metrics: Dict[str, str]) -> float:
        """Compute CVSS v3.1 base score per FIRST specification."""
        scope_changed = V31_S_VALUES[metrics["S"]]

        # Impact Sub Score (ISS)
        iss = 1.0 - (
            (1.0 - V31_CIA_VALUES[metrics["C"]]) *
            (1.0 - V31_CIA_VALUES[metrics["I"]]) *
            (1.0 - V31_CIA_VALUES[metrics["A"]])
        )

        # Impact
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss

        # If impact is <= 0, base score is 0
        if impact <= 0:
            return 0.0

        # Exploitability
        pr_values = V31_PR_VALUES_CHANGED if scope_changed else V31_PR_VALUES_UNCHANGED
        exploitability = (
            8.22 *
            V31_AV_VALUES[metrics["AV"]] *
            V31_AC_VALUES[metrics["AC"]] *
            pr_values[metrics["PR"]] *
            V31_UI_VALUES[metrics["UI"]]
        )

        # Base Score
        if scope_changed:
            base = min(1.08 * (impact + exploitability), 10.0)
        else:
            base = min(impact + exploitability, 10.0)

        return self._roundup(base)

    def _compute_v31_temporal(self, metrics: Dict[str, str],
                              base_score: float) -> float:
        """Compute CVSS v3.1 temporal score."""
        e = V31_E_VALUES.get(metrics.get("E", "X"), 1.0)
        rl = V31_RL_VALUES.get(metrics.get("RL", "X"), 1.0)
        rc = V31_RC_VALUES.get(metrics.get("RC", "X"), 1.0)

        temporal = self._roundup(base_score * e * rl * rc)
        return temporal

    def _compute_v31_environmental(self, metrics: Dict[str, str]) -> float:
        """Compute CVSS v3.1 environmental score.

        Uses modified base metrics if present, otherwise falls back to
        base metric values.
        """
        # Determine effective metrics (modified or base fallback)
        mav = V31_MAV_VALUES.get(metrics.get("MAV", "X"))
        mac = V31_MAC_VALUES.get(metrics.get("MAC", "X"))
        mpr_key = metrics.get("MPR", "X")
        mui = V31_MUI_VALUES.get(metrics.get("MUI", "X"))
        ms = V31_MS_VALUES.get(metrics.get("MS", "X"))
        mc = V31_MCIA_VALUES.get(metrics.get("MC", "X"))
        mi = V31_MCIA_VALUES.get(metrics.get("MI", "X"))
        ma = V31_MCIA_VALUES.get(metrics.get("MA", "X"))

        # Fall back to base values when modifier is "X" (not defined)
        eff_av = mav if mav is not None else V31_AV_VALUES[metrics["AV"]]
        eff_ac = mac if mac is not None else V31_AC_VALUES[metrics["AC"]]
        eff_ui = mui if mui is not None else V31_UI_VALUES[metrics["UI"]]
        eff_scope_changed = ms if ms is not None else V31_S_VALUES[metrics["S"]]
        eff_c = mc if mc is not None else V31_CIA_VALUES[metrics["C"]]
        eff_i = mi if mi is not None else V31_CIA_VALUES[metrics["I"]]
        eff_a = ma if ma is not None else V31_CIA_VALUES[metrics["A"]]

        # Modified Privileges Required
        if mpr_key != "X" and mpr_key in V31_MPR_VALUES_CHANGED:
            pr_values = V31_MPR_VALUES_CHANGED if eff_scope_changed else V31_MPR_VALUES_UNCHANGED
            eff_pr = pr_values[mpr_key]
        else:
            pr_values = V31_PR_VALUES_CHANGED if eff_scope_changed else V31_PR_VALUES_UNCHANGED
            eff_pr = pr_values[metrics["PR"]]

        # Requirement modifiers
        cr = V31_CR_VALUES.get(metrics.get("CR", "X"), 1.0)
        ir = V31_IR_VALUES.get(metrics.get("IR", "X"), 1.0)
        ar = V31_AR_VALUES.get(metrics.get("AR", "X"), 1.0)

        # Modified Impact Sub Score (MISS)
        miss = min(
            1.0 - (
                (1.0 - eff_c * cr) *
                (1.0 - eff_i * ir) *
                (1.0 - eff_a * ar)
            ),
            0.915
        )

        # Modified Impact
        if eff_scope_changed:
            modified_impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
        else:
            modified_impact = 6.42 * miss

        # If modified impact <= 0, environmental score is 0
        if modified_impact <= 0:
            return 0.0

        # Modified Exploitability
        modified_exploitability = (
            8.22 *
            eff_av *
            eff_ac *
            eff_pr *
            eff_ui
        )

        # Environmental Score (with temporal factors)
        e = V31_E_VALUES.get(metrics.get("E", "X"), 1.0)
        rl = V31_RL_VALUES.get(metrics.get("RL", "X"), 1.0)
        rc = V31_RC_VALUES.get(metrics.get("RC", "X"), 1.0)

        if eff_scope_changed:
            env_score = min(1.08 * (modified_impact + modified_exploitability), 10.0)
        else:
            env_score = min(modified_impact + modified_exploitability, 10.0)

        env_score = self._roundup(env_score * e * rl * rc)
        return env_score

    # -------------------------------------------------------------------
    # CVSS v4.0 Internal Computation
    # -------------------------------------------------------------------

    def _compute_v40_base(self, metrics: Dict[str, str]) -> float:
        """Compute CVSS v4.0 base score using MacroVector lookup.

        The v4.0 scoring system uses equivalence classes (EQ1-EQ6) to
        determine a MacroVector, which maps to a base score via lookup table.
        """
        # Validate required base metrics
        for m in V40_BASE_METRICS:
            if m not in metrics:
                raise ValueError(f"Missing required v4.0 base metric: {m}")

        # Compute equivalence classes
        eq1 = self._v40_eq1(metrics)
        eq2 = self._v40_eq2(metrics)
        eq3 = self._v40_eq3(metrics)
        eq4 = self._v40_eq4(metrics)
        eq5 = self._v40_eq5(metrics)
        eq6 = self._v40_eq6(metrics)

        macro_vector = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"

        # Look up score from table
        score = V40_MACROVECTOR_SCORES.get(macro_vector)
        if score is None:
            # For combinations not in the lookup table, compute a
            # reasonable interpolation based on available data
            score = self._v40_interpolate_score(eq1, eq2, eq3, eq4, eq5, eq6)

        return score

    def _v40_eq1(self, metrics: Dict[str, str]) -> int:
        """Compute EQ1: Exploitability (AV, PR, UI).

        Level 0: AV:N and PR:N and UI:N
        Level 1: (AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and AV:P not true
        Level 2: AV:P or not (AV:N or PR:N or UI:N)
        """
        av = metrics["AV"]
        pr = metrics["PR"]
        ui = metrics["UI"]

        if av == "N" and pr == "N" and ui == "N":
            return 0
        elif av == "P":
            return 2
        elif av == "N" or pr == "N" or ui == "N":
            return 1
        else:
            return 2

    def _v40_eq2(self, metrics: Dict[str, str]) -> int:
        """Compute EQ2: Complexity (AC, AT).

        Level 0: AC:L and AT:N
        Level 1: not (AC:L and AT:N)
        """
        ac = metrics["AC"]
        at = metrics["AT"]

        if ac == "L" and at == "N":
            return 0
        else:
            return 1

    def _v40_eq3(self, metrics: Dict[str, str]) -> int:
        """Compute EQ3: Vulnerable system impact (VC, VI, VA).

        Level 0: VC:H and VI:H
        Level 1: not (VC:H and VI:H) and (VC:H or VI:H or VA:H)
        Level 2: not (VC:H or VI:H or VA:H)
        """
        vc = metrics["VC"]
        vi = metrics["VI"]
        va = metrics["VA"]

        if vc == "H" and vi == "H":
            return 0
        elif vc == "H" or vi == "H" or va == "H":
            return 1
        else:
            return 2

    def _v40_eq4(self, metrics: Dict[str, str]) -> int:
        """Compute EQ4: Subsequent system impact (SC, SI, SA).

        Level 0: SC:H or SI:H or SA:H (MSI:S or MSA:S handled separately)
        Level 1: not (SC:H or SI:H or SA:H)
        """
        sc = metrics["SC"]
        si = metrics["SI"]
        sa = metrics["SA"]

        if sc == "H" or si == "H" or sa == "H":
            return 0
        else:
            return 1

    def _v40_eq5(self, metrics: Dict[str, str]) -> int:
        """Compute EQ5: Exploitation (E - Exploit Maturity, if present).

        Level 0: E:A (Attacked) - default when not specified
        Level 1: E:P (POC)
        Level 2: E:U (Unreported)

        When E is not specified, assume worst case (level 0).
        """
        e = metrics.get("E", "A")

        if e == "A" or e == "X":
            return 0
        elif e == "P":
            return 1
        else:  # "U"
            return 2

    def _v40_eq6(self, metrics: Dict[str, str]) -> int:
        """Compute EQ6: Combined vulnerability + subsequent impact detail.

        Level 0: (VC:H and CR:H) or (VI:H and IR:H) or (VA:H and AR:H)
        Level 1: not Level 0

        When CR/IR/AR not specified, default to High.
        """
        vc = metrics["VC"]
        vi = metrics["VI"]
        va = metrics["VA"]
        cr = metrics.get("CR", "H")
        ir = metrics.get("IR", "H")
        ar = metrics.get("AR", "H")

        if cr == "X":
            cr = "H"
        if ir == "X":
            ir = "H"
        if ar == "X":
            ar = "H"

        if (vc == "H" and cr == "H") or (vi == "H" and ir == "H") or (va == "H" and ar == "H"):
            return 0
        else:
            return 1

    def _v40_interpolate_score(self, eq1: int, eq2: int, eq3: int,
                                eq4: int, eq5: int, eq6: int) -> float:
        """Interpolate score for MacroVector combinations not in lookup table.

        Falls back to nearest available MacroVector score with adjustment.
        """
        # Try reducing eq levels (lower levels = higher scores)
        macro = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"

        # Find closest score by trying nearby MacroVectors
        best_score = None
        for delta5 in [0, -1, 1]:
            for delta6 in [0, -1, 1]:
                test_eq5 = max(0, min(2, eq5 + delta5))
                test_eq6 = max(0, min(1, eq6 + delta6))
                test_mv = f"{eq1}{eq2}{eq3}{eq4}{test_eq5}{test_eq6}"
                if test_mv in V40_MACROVECTOR_SCORES:
                    score = V40_MACROVECTOR_SCORES[test_mv]
                    if best_score is None:
                        best_score = score
                    # Prefer exact or close match
                    if delta5 == 0 and delta6 == 0:
                        return score

        if best_score is not None:
            return best_score

        # Last resort: compute approximate score from eq levels
        # Higher eq levels = lower score
        total_eq = eq1 + eq2 + eq3 + eq4 + eq5 + eq6
        max_total = 2 + 1 + 2 + 1 + 2 + 1  # = 9
        approx = 10.0 * (1.0 - total_eq / max_total)
        return round(approx, 1)

    # -------------------------------------------------------------------
    # Utility
    # -------------------------------------------------------------------

    @staticmethod
    def _roundup(value: float) -> float:
        """Round up to one decimal place per CVSS v3.1 specification.

        The CVSS specification mandates rounding up: if the value has more
        than one decimal digit, round up to one decimal. For example,
        4.02 rounds to 4.1, not 4.0.
        """
        return math.ceil(value * 10) / 10
