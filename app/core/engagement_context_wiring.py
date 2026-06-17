"""Engagement context wiring helpers.

This module provides helper functions that connect all new platform modules
to the engagement lifecycle. When an engagement is opened, the active
engagement database is injected into each module. Signal connections are
also wired here so that timeline logging and attack surface updates happen
automatically.
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def wire_engagement_context(engagement_manager, modules_dict: Dict[str, Any]) -> None:
    """Connect engagement_manager.engagement_opened to inject the active DB.

    When an engagement is opened, the handler reads the active_db from the
    engagement manager and calls set_database() on each module that supports
    it. Modules that are missing from the dict are silently skipped.

    Args:
        engagement_manager: An EngagementManager instance with an
            ``engagement_opened(str)`` signal and an ``active_db`` attribute.
        modules_dict: Dictionary mapping module names to their instances.
            Expected keys (all optional):
              - evidence_manager
              - note_system
              - timeline_logger
              - retest_workflow
              - attack_mapper
              - attack_surface_mapper
              - import_export_engine
              - physical_security_engine
              - mobile_testing_engine
    """

    def _on_engagement_opened(engagement_id: str) -> None:
        """Inject the active engagement DB into all registered modules."""
        eng_db = getattr(engagement_manager, "active_db", None)
        if eng_db is None:
            logger.warning(
                "engagement_opened emitted but active_db is None "
                f"(engagement_id={engagement_id})"
            )
            return

        logger.info(
            f"Injecting engagement DB into modules for engagement {engagement_id}"
        )

        # Modules that receive set_database(eng_db)
        db_modules = [
            "evidence_manager",
            "note_system",
            "timeline_logger",
            "retest_workflow",
            "attack_mapper",
            "physical_security_engine",
            "mobile_testing_engine",
        ]

        for name in db_modules:
            module = modules_dict.get(name)
            if module is None:
                continue
            try:
                module.set_database(eng_db)
                logger.debug(f"  {name}.set_database() OK")
            except Exception as e:
                logger.warning(f"  {name}.set_database() failed: {e}")

        # attack_surface_mapper gets set_database + rebuild_from_database
        asm = modules_dict.get("attack_surface_mapper")
        if asm is not None:
            try:
                asm.set_database(eng_db)
                asm.rebuild_from_database()
                logger.debug("  attack_surface_mapper.set_database() + rebuild OK")
            except Exception as e:
                logger.warning(
                    f"  attack_surface_mapper wiring failed: {e}"
                )

        # import_export_engine does not need set_database — it receives
        # the engagement DB per-call, so nothing to do here.

    try:
        engagement_manager.engagement_opened.connect(_on_engagement_opened)
        logger.info("Engagement context wiring connected to engagement_opened signal")
    except Exception as e:
        logger.error(f"Failed to wire engagement context: {e}")


def wire_timeline_signals(timeline_logger, modules_dict: Dict[str, Any]) -> None:
    """Connect timeline auto-logging signals from other modules.

    Wires:
      - engagement_manager.state_changed → timeline_logger.log_state_transition
      - evidence_manager.evidence_stored → timeline_logger.log_evidence_captured
      - scanner signals (scan_started/scan_completed) when available

    All connections are wrapped with try/except for graceful fallback when
    signals are unavailable or signatures do not match.

    Args:
        timeline_logger: A TimelineLogger instance.
        modules_dict: Dictionary mapping module names to instances.
            Expected keys (all optional):
              - engagement_manager
              - evidence_manager
              - scanner (or any object with scan_started/scan_completed signals)
              - scheduling_engine
    """

    # engagement_manager.state_changed → log_state_transition
    engagement_manager = modules_dict.get("engagement_manager")
    if engagement_manager is not None:
        try:
            engagement_manager.state_changed.connect(
                timeline_logger.log_state_transition
            )
            logger.info(
                "Timeline: connected engagement_manager.state_changed"
            )
        except (AttributeError, TypeError) as e:
            logger.warning(
                f"Timeline: failed to connect state_changed: {e}"
            )

    # evidence_manager.evidence_stored → log_evidence_captured
    evidence_manager = modules_dict.get("evidence_manager")
    if evidence_manager is not None:
        try:
            evidence_manager.evidence_stored.connect(
                timeline_logger.log_evidence_captured
            )
            logger.info(
                "Timeline: connected evidence_manager.evidence_stored"
            )
        except (AttributeError, TypeError) as e:
            logger.warning(
                f"Timeline: failed to connect evidence_stored: {e}"
            )

    # Scanner signals (graceful fallback)
    scanner = modules_dict.get("scanner")
    if scanner is not None:
        try:
            if hasattr(scanner, "scan_started"):
                scanner.scan_started.connect(timeline_logger.log_scan_start)
                logger.info("Timeline: connected scanner.scan_started")
        except (AttributeError, TypeError) as e:
            logger.warning(f"Timeline: failed to connect scan_started: {e}")

        try:
            if hasattr(scanner, "scan_completed"):
                scanner.scan_completed.connect(timeline_logger.log_scan_complete)
                logger.info("Timeline: connected scanner.scan_completed")
        except (AttributeError, TypeError) as e:
            logger.warning(
                f"Timeline: failed to connect scan_completed: {e}"
            )

    # scheduling_engine.scan_triggered → timeline logging
    scheduling_engine = modules_dict.get("scheduling_engine")
    if scheduling_engine is not None:
        try:
            if hasattr(scheduling_engine, "scan_triggered"):
                scheduling_engine.scan_triggered.connect(
                    timeline_logger.log_scan_start
                )
                logger.info(
                    "Timeline: connected scheduling_engine.scan_triggered"
                )
        except (AttributeError, TypeError) as e:
            logger.warning(
                f"Timeline: failed to connect scan_triggered: {e}"
            )


def wire_attack_surface_signals(
    attack_surface_mapper, modules_dict: Dict[str, Any]
) -> None:
    """Connect signals that feed the attack surface mapper.

    Wires:
      - centralized_scan_data.result_added → attack_surface_mapper.on_result_added
        (only if centralized_scan_data exposes a result_added signal)

    All connections are wrapped with try/except for graceful fallback.

    Args:
        attack_surface_mapper: An AttackSurfaceMapper instance.
        modules_dict: Dictionary mapping module names to instances.
            Expected keys (all optional):
              - centralized_scan_data
    """

    scan_data = modules_dict.get("centralized_scan_data")
    if scan_data is not None:
        try:
            if hasattr(scan_data, "result_added"):
                scan_data.result_added.connect(
                    attack_surface_mapper.on_result_added
                )
                logger.info(
                    "AttackSurface: connected centralized_scan_data.result_added"
                )
            else:
                logger.debug(
                    "AttackSurface: centralized_scan_data has no result_added signal, skipping"
                )
        except (AttributeError, TypeError) as e:
            logger.warning(
                f"AttackSurface: failed to connect result_added: {e}"
            )
