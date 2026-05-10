# app/core/autonomous_agent.py
"""
Autonomous Security Agent — 7-state self-directed testing framework.

IMPORTANT — SIMULATION MODE
----------------------------
By default this agent runs in ``simulation_mode=True``.  In simulation mode
**no real network requests are made** and all findings are clearly labelled
``[SIMULATED]``.  Simulation mode is safe for demos, training, and unit tests.

To run against a real target, pass ``simulation_mode=False`` when constructing
the agent.  In that mode the agent dispatches to real scanner modules.  You are
responsible for ensuring you have authorisation to test the target.

Every result dict produced by this agent includes a ``simulated`` boolean key
so callers can always distinguish real findings from training data.
"""

import asyncio
import time
from enum import Enum
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from app.core.logger import logger


# ---------------------------------------------------------------------------
# Simulation warning — embedded in every result when simulation_mode=True
# ---------------------------------------------------------------------------
SIMULATION_WARNING = (
    "[SIMULATED] This result was produced by the autonomous agent in "
    "simulation mode. No real network requests were made. Do NOT treat "
    "these findings as real vulnerabilities."
)


class AgentState(Enum):
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PERSISTENCE = "persistence"
    REPORTING = "reporting"


@dataclass
class AgentMemory:
    discovered_assets: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    exploitation_results: List[Dict] = field(default_factory=list)
    learned_patterns: Dict[str, Any] = field(default_factory=dict)
    success_rate: float = 0.0
    confidence_level: float = 0.5


@dataclass
class AgentDecision:
    action: str
    target: str
    method: str
    confidence: float
    reasoning: str


class AutonomousSecurityAgent:
    """7-state autonomous security testing agent.

    Parameters
    ----------
    simulation_mode:
        When ``True`` (default) the agent produces clearly-labelled simulated
        results without making any real network connections.  Set to ``False``
        only when you have explicit authorisation to test the target.
    """

    def __init__(self, simulation_mode: bool = True):
        self.simulation_mode = simulation_mode
        self.current_state = AgentState.RECONNAISSANCE
        self.memory = AgentMemory()
        self.state_transitions = {
            AgentState.RECONNAISSANCE: [AgentState.ENUMERATION, AgentState.VULNERABILITY_DISCOVERY],
            AgentState.ENUMERATION: [AgentState.VULNERABILITY_DISCOVERY, AgentState.EXPLOITATION],
            AgentState.VULNERABILITY_DISCOVERY: [AgentState.EXPLOITATION, AgentState.ENUMERATION],
            AgentState.EXPLOITATION: [AgentState.POST_EXPLOITATION, AgentState.VULNERABILITY_DISCOVERY],
            AgentState.POST_EXPLOITATION: [AgentState.PERSISTENCE, AgentState.REPORTING],
            AgentState.PERSISTENCE: [AgentState.REPORTING, AgentState.ENUMERATION],
            AgentState.REPORTING: [AgentState.RECONNAISSANCE],
        }
        self.mission_objectives: List[str] = []
        self.current_target: Optional[str] = None
        self.learning_rate = 0.1

        if simulation_mode:
            logger.info(
                "AutonomousSecurityAgent initialised in SIMULATION MODE. "
                "All results are synthetic training data."
            )
        else:
            logger.warning(
                "AutonomousSecurityAgent initialised in LIVE MODE. "
                "Ensure you have authorisation to test the target."
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def execute_autonomous_mission(
        self, target: str, objectives: List[str]
    ) -> Dict[str, Any]:
        """Execute an autonomous security testing mission.

        Returns a result dict.  When ``simulation_mode=True`` every finding
        carries ``simulated=True`` and a ``simulation_warning`` string.
        """
        self.current_target = target
        self.mission_objectives = objectives
        start_time = time.time()

        mission_results: Dict[str, Any] = {
            "target": target,
            "objectives": objectives,
            "simulated": self.simulation_mode,
            "simulation_warning": SIMULATION_WARNING if self.simulation_mode else None,
            "states_executed": [],
            "discoveries": [],
            "exploitations": [],
            "recommendations": [],
            "mission_success": False,
            "duration": 0.0,
        }

        if self.simulation_mode:
            logger.info(
                f"[SIMULATION] Starting simulated mission against {target}. "
                "No real network requests will be made."
            )

        max_iterations = 20
        iteration = 0

        while iteration < max_iterations and not self._mission_complete():
            state_result = await self._execute_current_state()
            mission_results["states_executed"].append(
                {
                    "state": self.current_state.value,
                    "result": state_result,
                    "timestamp": time.time(),
                    "simulated": self.simulation_mode,
                }
            )
            self._update_memory(state_result)
            self.current_state = self._decide_next_state()
            iteration += 1

        mission_results["discoveries"] = self.memory.vulnerabilities
        mission_results["exploitations"] = self.memory.exploitation_results
        mission_results["recommendations"] = self._generate_recommendations()
        mission_results["mission_success"] = self._evaluate_mission_success()
        mission_results["duration"] = time.time() - start_time

        if self.simulation_mode:
            logger.info(
                f"[SIMULATION] Mission complete. "
                f"{len(self.memory.vulnerabilities)} simulated findings. "
                "These are NOT real vulnerabilities."
            )

        return mission_results

    # ------------------------------------------------------------------
    # State execution
    # ------------------------------------------------------------------

    async def _execute_current_state(self) -> Dict[str, Any]:
        handlers = {
            AgentState.RECONNAISSANCE: self._execute_reconnaissance,
            AgentState.ENUMERATION: self._execute_enumeration,
            AgentState.VULNERABILITY_DISCOVERY: self._execute_vulnerability_discovery,
            AgentState.EXPLOITATION: self._execute_exploitation,
            AgentState.POST_EXPLOITATION: self._execute_post_exploitation,
            AgentState.PERSISTENCE: self._execute_persistence,
            AgentState.REPORTING: self._execute_reporting,
        }
        handler = handlers.get(self.current_state)
        if handler:
            return await handler()
        return {"status": "unknown_state", "actions": [], "simulated": self.simulation_mode}

    async def _execute_reconnaissance(self) -> Dict[str, Any]:
        actions = []
        discoveries = []
        techniques = [
            "subdomain_enumeration",
            "certificate_transparency",
            "dns_enumeration",
            "social_media_osint",
            "technology_fingerprinting",
        ]
        for technique in techniques:
            result = await self._execute_technique(technique)
            actions.append(result)
            if result["success"]:
                discoveries.extend(result.get("discoveries", []))

        self.memory.discovered_assets.extend(discoveries)
        return {
            "state": "reconnaissance",
            "actions_taken": len(actions),
            "discoveries": discoveries,
            "success_rate": sum(1 for a in actions if a["success"]) / len(actions) if actions else 0,
            "simulated": self.simulation_mode,
        }

    async def _execute_enumeration(self) -> Dict[str, Any]:
        actions = []
        findings = []
        techniques = [
            "port_scanning",
            "service_enumeration",
            "directory_bruteforcing",
            "parameter_discovery",
            "api_endpoint_enumeration",
        ]
        for technique in techniques:
            result = await self._execute_technique(technique)
            actions.append(result)
            if result["success"]:
                findings.extend(result.get("findings", []))

        return {
            "state": "enumeration",
            "actions_taken": len(actions),
            "findings": findings,
            "attack_surface_expanded": len(findings) > 0,
            "simulated": self.simulation_mode,
        }

    async def _execute_vulnerability_discovery(self) -> Dict[str, Any]:
        actions = []
        vulnerabilities = []
        techniques = [
            "automated_scanning",
            "manual_testing",
            "fuzzing",
            "code_analysis",
            "configuration_review",
        ]
        for technique in techniques:
            result = await self._execute_technique(technique)
            actions.append(result)
            if result["success"]:
                vulns = result.get("vulnerabilities", [])
                vulnerabilities.extend(vulns)
                self.memory.vulnerabilities.extend(vulns)

        return {
            "state": "vulnerability_discovery",
            "actions_taken": len(actions),
            "vulnerabilities_found": len(vulnerabilities),
            "critical_vulns": len([v for v in vulnerabilities if v.get("severity") == "CRITICAL"]),
            "simulated": self.simulation_mode,
        }

    async def _execute_exploitation(self) -> Dict[str, Any]:
        actions = []
        successful_exploits = []
        exploitable = [v for v in self.memory.vulnerabilities if v.get("exploitable", False)]

        for vuln in exploitable[:3]:
            result = await self._attempt_exploitation(vuln)
            actions.append(result)
            if result["success"]:
                successful_exploits.append(result)
                self.memory.exploitation_results.append(result)

        return {
            "state": "exploitation",
            "attempts": len(actions),
            "successful_exploits": len(successful_exploits),
            "compromise_level": self._assess_compromise_level(successful_exploits),
            "simulated": self.simulation_mode,
        }

    async def _execute_post_exploitation(self) -> Dict[str, Any]:
        if not self.memory.exploitation_results:
            return {
                "state": "post_exploitation",
                "actions_taken": 0,
                "reason": "no_successful_exploits",
                "simulated": self.simulation_mode,
            }
        actions = []
        activities = [
            "privilege_escalation",
            "lateral_movement",
            "data_exfiltration_test",
            "persistence_establishment",
            "evidence_collection",
        ]
        for activity in activities:
            result = await self._execute_technique(activity)
            actions.append(result)

        return {
            "state": "post_exploitation",
            "actions_taken": len(actions),
            "successful_actions": sum(1 for a in actions if a["success"]),
            "impact_assessment": self._assess_impact(),
            "simulated": self.simulation_mode,
        }

    async def _execute_persistence(self) -> Dict[str, Any]:
        # Persistence techniques are only attempted in live mode AND only when
        # success_rate is high enough to indicate a real compromise.
        if self.simulation_mode:
            return {
                "state": "persistence",
                "actions_taken": 0,
                "persistence_established": False,
                "simulated": True,
                "note": "Persistence techniques skipped in simulation mode.",
            }
        actions = []
        techniques = [
            "scheduled_task_creation",
            "registry_modification",
            "service_installation",
            "startup_folder_placement",
        ]
        for technique in techniques:
            if self.memory.success_rate > 0.7:
                result = await self._execute_technique(technique)
                actions.append(result)

        return {
            "state": "persistence",
            "actions_taken": len(actions),
            "persistence_established": any(a["success"] for a in actions),
            "simulated": False,
        }

    async def _execute_reporting(self) -> Dict[str, Any]:
        return {
            "state": "reporting",
            "mission_summary": {
                "target": self.current_target,
                "objectives_met": self._count_objectives_met(),
                "vulnerabilities_found": len(self.memory.vulnerabilities),
                "successful_exploits": len(self.memory.exploitation_results),
                "overall_success_rate": self.memory.success_rate,
                "simulated": self.simulation_mode,
            },
            "recommendations": self._generate_recommendations(),
            "lessons_learned": self._extract_lessons_learned(),
            "simulated": self.simulation_mode,
        }

    # ------------------------------------------------------------------
    # Technique execution — real vs simulated
    # ------------------------------------------------------------------

    async def _execute_technique(
        self, technique: str, safe_mode: bool = True
    ) -> Dict[str, Any]:
        """Dispatch a technique to a real scanner or return a labelled simulation.

        In simulation mode: returns clearly-labelled synthetic data.
        In live mode: attempts to call the real scanner module; falls back to
        a labelled simulation if the module is unavailable.
        """
        if self.simulation_mode:
            return self._simulated_technique_result(technique)

        # --- Live mode: dispatch to real scanners ---
        try:
            if technique == "port_scanning":
                return await self._real_port_scan()
            elif technique == "subdomain_enumeration":
                return await self._real_subdomain_enum()
            elif technique == "dns_enumeration":
                return await self._real_dns_enum()
            elif technique == "service_enumeration":
                return await self._real_service_enum()
            elif technique == "automated_scanning":
                return await self._real_vuln_scan()
            else:
                # Technique not yet wired to a real scanner — return a clearly
                # labelled placeholder so the caller knows it wasn't executed.
                logger.debug(
                    f"Technique '{technique}' has no real scanner implementation. "
                    "Returning not-executed result."
                )
                return {
                    "technique": technique,
                    "success": False,
                    "simulated": False,
                    "executed": False,
                    "note": f"No real scanner implementation for '{technique}'.",
                    "timestamp": time.time(),
                }
        except Exception as e:
            logger.warning(
                f"Real scanner for '{technique}' failed: {e}. "
                "Returning failure result (not simulated).",
                exc_info=True,
            )
            return {
                "technique": technique,
                "success": False,
                "simulated": False,
                "executed": True,
                "error": str(e),
                "timestamp": time.time(),
            }

    def _simulated_technique_result(self, technique: str) -> Dict[str, Any]:
        """Return a clearly-labelled synthetic result for training/demo use."""
        # Deterministic based on technique name so results are reproducible
        # within a session (no random — avoids non-deterministic fake findings).
        result: Dict[str, Any] = {
            "technique": technique,
            "success": True,   # Simulation always "succeeds" for demo purposes
            "simulated": True,
            "simulation_warning": SIMULATION_WARNING,
            "timestamp": time.time(),
        }

        if "enumeration" in technique or "discovery" in technique:
            result["findings"] = [
                f"[SIMULATED] {technique}_finding_{i}" for i in range(2)
            ]
        elif "vulnerability" in technique or "scanning" in technique or "fuzzing" in technique:
            result["vulnerabilities"] = [
                {
                    "type": f"[SIMULATED] {technique}_vuln",
                    "severity": "MEDIUM",
                    "exploitable": False,
                    "simulated": True,
                    "simulation_warning": SIMULATION_WARNING,
                }
            ]
        elif technique == "subdomain_enumeration":
            result["discoveries"] = [
                f"[SIMULATED] sub{i}.{self.current_target}" for i in range(2)
            ]

        return result

    async def _attempt_exploitation(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt exploitation — real or simulated."""
        if self.simulation_mode:
            return {
                "vulnerability": vulnerability,
                "success": False,   # Simulation never claims successful exploitation
                "impact": "NONE",
                "simulated": True,
                "simulation_warning": SIMULATION_WARNING,
                "timestamp": time.time(),
            }

        # Live mode — real exploitation is out of scope for this framework.
        # Return a not-executed result; actual exploitation requires dedicated
        # tools (Metasploit, manual testing) with explicit operator action.
        logger.info(
            f"Exploitation of {vulnerability.get('type', 'unknown')} skipped — "
            "automated exploitation is not implemented. Use dedicated tools."
        )
        return {
            "vulnerability": vulnerability,
            "success": False,
            "impact": "NONE",
            "simulated": False,
            "executed": False,
            "note": "Automated exploitation not implemented. Use dedicated tools.",
            "timestamp": time.time(),
        }

    # ------------------------------------------------------------------
    # Real scanner integrations (live mode only)
    # ------------------------------------------------------------------

    async def _real_port_scan(self) -> Dict[str, Any]:
        """Run a real port scan using the nmap scanner module."""
        from app.tools.nmap_scanner import NmapScanner
        scanner = NmapScanner(self.current_target)
        # Run in a thread to avoid blocking the event loop
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, scanner.quick_scan)
        open_ports = results.get("open_ports", [])
        return {
            "technique": "port_scanning",
            "success": bool(open_ports),
            "simulated": False,
            "findings": [f"Port {p['port']}/{p.get('service','unknown')}" for p in open_ports],
            "raw": results,
            "timestamp": time.time(),
        }

    async def _real_subdomain_enum(self) -> Dict[str, Any]:
        """Run real subdomain enumeration."""
        try:
            from app.core.cert_transparency import CertificateTransparencyClient
            client = CertificateTransparencyClient()
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                None, client.search_certificates, self.current_target
            )
            subdomains = results.get("subdomains", [])
            return {
                "technique": "subdomain_enumeration",
                "success": bool(subdomains),
                "simulated": False,
                "discoveries": subdomains,
                "timestamp": time.time(),
            }
        except ImportError:
            return {
                "technique": "subdomain_enumeration",
                "success": False,
                "simulated": False,
                "executed": False,
                "note": "cert_transparency module not available.",
                "timestamp": time.time(),
            }

    async def _real_dns_enum(self) -> Dict[str, Any]:
        """Run real DNS enumeration."""
        try:
            from app.tools.dns_scanner import DNSScanner
            scanner = DNSScanner(self.current_target)
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(None, scanner.enumerate)
            records = results.get("records", [])
            return {
                "technique": "dns_enumeration",
                "success": bool(records),
                "simulated": False,
                "findings": records,
                "timestamp": time.time(),
            }
        except ImportError:
            return {
                "technique": "dns_enumeration",
                "success": False,
                "simulated": False,
                "executed": False,
                "note": "dns_scanner module not available.",
                "timestamp": time.time(),
            }

    async def _real_service_enum(self) -> Dict[str, Any]:
        """Run real service enumeration via HTTP fingerprinting."""
        try:
            from app.tools.http_fingerprint import HTTPFingerprinter
            fp = HTTPFingerprinter()
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                None, fp.basic_fingerprint, self.current_target
            )
            return {
                "technique": "service_enumeration",
                "success": "error" not in results,
                "simulated": False,
                "findings": [results.get("server", ""), results.get("content_type", "")],
                "raw": results,
                "timestamp": time.time(),
            }
        except ImportError:
            return {
                "technique": "service_enumeration",
                "success": False,
                "simulated": False,
                "executed": False,
                "note": "http_fingerprint module not available.",
                "timestamp": time.time(),
            }

    async def _real_vuln_scan(self) -> Dict[str, Any]:
        """Run real vulnerability scanning."""
        try:
            from app.core.vuln_scanner import VulnerabilityScanner
            scanner = VulnerabilityScanner()
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                None, scanner.scan, self.current_target
            )
            vulns = results.get("vulnerabilities", [])
            return {
                "technique": "automated_scanning",
                "success": bool(vulns),
                "simulated": False,
                "vulnerabilities": vulns,
                "timestamp": time.time(),
            }
        except ImportError:
            return {
                "technique": "automated_scanning",
                "success": False,
                "simulated": False,
                "executed": False,
                "note": "vuln_scanner module not available.",
                "timestamp": time.time(),
            }

    # ------------------------------------------------------------------
    # State machine helpers
    # ------------------------------------------------------------------

    def _decide_next_state(self) -> AgentState:
        if self.current_state == AgentState.RECONNAISSANCE:
            return (
                AgentState.ENUMERATION
                if self.memory.discovered_assets
                else AgentState.VULNERABILITY_DISCOVERY
            )
        elif self.current_state == AgentState.ENUMERATION:
            return AgentState.VULNERABILITY_DISCOVERY
        elif self.current_state == AgentState.VULNERABILITY_DISCOVERY:
            return (
                AgentState.EXPLOITATION
                if self.memory.vulnerabilities
                else AgentState.ENUMERATION
            )
        elif self.current_state == AgentState.EXPLOITATION:
            return (
                AgentState.POST_EXPLOITATION
                if self.memory.exploitation_results
                else AgentState.VULNERABILITY_DISCOVERY
            )
        elif self.current_state == AgentState.POST_EXPLOITATION:
            return (
                AgentState.PERSISTENCE
                if self.memory.success_rate > 0.8
                else AgentState.REPORTING
            )
        elif self.current_state == AgentState.PERSISTENCE:
            return AgentState.REPORTING
        else:
            return AgentState.REPORTING

    def _mission_complete(self) -> bool:
        """Mission is complete when all objectives have been attempted.

        Previously this used a random count threshold which caused the mission
        to terminate prematurely with fabricated results.  Now it checks
        whether the state machine has reached REPORTING.
        """
        return self.current_state == AgentState.REPORTING

    def _count_objectives_met(self) -> int:
        met = 0
        if "find_vulnerabilities" in self.mission_objectives and self.memory.vulnerabilities:
            met += 1
        if "test_exploits" in self.mission_objectives and self.memory.exploitation_results:
            met += 1
        if "assess_impact" in self.mission_objectives:
            met += 1  # Impact assessment always runs in reporting phase
        return met

    def _assess_compromise_level(self, exploits: List[Dict]) -> str:
        if not exploits:
            return "NONE"
        if any(e.get("impact") == "CRITICAL" for e in exploits):
            return "CRITICAL"
        if len(exploits) > 2:
            return "HIGH"
        return "MEDIUM"

    def _assess_impact(self) -> str:
        n = len(self.memory.exploitation_results)
        if n >= 3:
            return "HIGH"
        if n >= 1:
            return "MEDIUM"
        return "LOW"

    def _update_memory(self, state_result: Dict[str, Any]):
        if "success_rate" in state_result:
            old = self.memory.success_rate
            new = state_result["success_rate"]
            self.memory.success_rate = old + self.learning_rate * (new - old)

        recent_success = state_result.get("success_rate", 0.5)
        self.memory.confidence_level = min(
            1.0, self.memory.confidence_level + 0.1 * recent_success
        )

        for action in state_result.get("actions", []):
            if isinstance(action, dict) and "technique" in action:
                technique = action["technique"]
                success = action.get("success", False)
                if technique not in self.memory.learned_patterns:
                    self.memory.learned_patterns[technique] = {
                        "success_rate": 0.5,
                        "attempts": 0,
                    }
                pattern = self.memory.learned_patterns[technique]
                pattern["attempts"] += 1
                pattern["success_rate"] += self.learning_rate * (
                    float(success) - pattern["success_rate"]
                )

    def _generate_recommendations(self) -> List[str]:
        recs = []
        real_vulns = [v for v in self.memory.vulnerabilities if not v.get("simulated")]
        if real_vulns:
            recs.append("Implement vulnerability management program")
            recs.append("Conduct regular security assessments")
        if self.memory.exploitation_results:
            recs.append("Implement defence-in-depth security controls")
            recs.append("Enhance monitoring and incident response capabilities")
        if self.simulation_mode:
            recs.append(
                "[SIMULATION] Run in live mode against an authorised target "
                "for real recommendations."
            )
        return recs

    def _extract_lessons_learned(self) -> List[str]:
        lessons = []
        successful = [
            t
            for t, data in self.memory.learned_patterns.items()
            if data["success_rate"] > 0.7
        ]
        if successful:
            lessons.append(f"Most effective techniques: {', '.join(successful[:3])}")
        if self.simulation_mode:
            lessons.append(
                "[SIMULATION] Lessons are based on synthetic data. "
                "Run in live mode for real insights."
            )
        return lessons

    def _evaluate_mission_success(self) -> bool:
        if self.simulation_mode:
            # Simulation never claims mission success — avoids false confidence
            return False
        return (
            len(self.memory.vulnerabilities) > 0
            and self._count_objectives_met() > 0
        )
