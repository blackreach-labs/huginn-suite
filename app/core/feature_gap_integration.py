"""Feature Gap Integration Module.

Wires all new platform capability modules into the existing main window
without modifying main_window_refactored.py directly. Call
``FeatureGapIntegration.integrate(main_window)`` after the main window
has finished its own ``_initialize_components()`` setup.

All component imports are deferred (lazy) so missing optional
dependencies don't crash the application on startup.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import QDockWidget

from app.core.logger import logger

if TYPE_CHECKING:
    from app.main_window.main_window_refactored import MainWindow


# ---------------------------------------------------------------------------
# Core engine singletons (lazy-created on first access)
# ---------------------------------------------------------------------------

class _EngineRegistry:
    """Holds lazily-instantiated engine singletons."""

    def __init__(self) -> None:
        self._instances: dict[str, object] = {}

    # ------------------------------------------------------------------
    # Public accessors — each engine is created once on first call.
    # ------------------------------------------------------------------

    @property
    def engagement_manager(self):
        return self._get_or_create("engagement_manager", self._make_engagement_manager)

    @property
    def evidence_manager(self):
        return self._get_or_create("evidence_manager", self._make_evidence_manager)

    @property
    def note_system(self):
        return self._get_or_create("note_system", self._make_note_system)

    @property
    def finding_template_library(self):
        return self._get_or_create("finding_template_library", self._make_finding_template_library)

    @property
    def cvss_calculator(self):
        return self._get_or_create("cvss_calculator", self._make_cvss_calculator)

    @property
    def timeline_logger(self):
        return self._get_or_create("timeline_logger", self._make_timeline_logger)

    @property
    def attack_mapper(self):
        return self._get_or_create("attack_mapper", self._make_attack_mapper)

    @property
    def retest_workflow(self):
        return self._get_or_create("retest_workflow", self._make_retest_workflow)

    @property
    def import_export_engine(self):
        return self._get_or_create("import_export_engine", self._make_import_export_engine)

    @property
    def collaboration_manager(self):
        return self._get_or_create("collaboration_manager", self._make_collaboration_manager)

    @property
    def knowledge_base(self):
        return self._get_or_create("knowledge_base", self._make_knowledge_base)

    @property
    def report_customizer(self):
        return self._get_or_create("report_customizer", self._make_report_customizer)

    @property
    def attack_surface_mapper(self):
        return self._get_or_create("attack_surface_mapper", self._make_attack_surface_mapper)

    @property
    def scheduling_engine(self):
        return self._get_or_create("scheduling_engine", self._make_scheduling_engine)

    @property
    def api_pentest_engine(self):
        return self._get_or_create("api_pentest_engine", self._make_api_pentest_engine)

    @property
    def container_assessment_engine(self):
        return self._get_or_create("container_assessment_engine", self._make_container_assessment_engine)

    @property
    def mobile_testing_engine(self):
        return self._get_or_create("mobile_testing_engine", self._make_mobile_testing_engine)

    @property
    def physical_security_engine(self):
        return self._get_or_create("physical_security_engine", self._make_physical_security_engine)

    @property
    def gcp_pentest_engine(self):
        return self._get_or_create("gcp_pentest_engine", self._make_gcp_pentest_engine)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_create(self, key: str, factory):
        if key not in self._instances:
            try:
                self._instances[key] = factory()
            except Exception as exc:
                logger.warning(f"[FeatureGapIntegration] Failed to create {key}: {exc}")
                self._instances[key] = None
        return self._instances[key]

    # --- Factory methods (import at call-time) ---

    @staticmethod
    def _make_engagement_manager():
        from app.core.engagement_manager import EngagementManager
        return EngagementManager()

    @staticmethod
    def _make_evidence_manager():
        from app.core.evidence_manager import EvidenceManager
        return EvidenceManager()

    @staticmethod
    def _make_note_system():
        from app.core.note_system import NoteSystem
        return NoteSystem()

    @staticmethod
    def _make_finding_template_library():
        from app.core.finding_template_library import FindingTemplateLibrary
        return FindingTemplateLibrary()

    @staticmethod
    def _make_cvss_calculator():
        from app.core.cvss_calculator import CVSSCalculator
        return CVSSCalculator()

    @staticmethod
    def _make_timeline_logger():
        from app.core.timeline_logger import TimelineLogger
        return TimelineLogger()

    @staticmethod
    def _make_attack_mapper():
        from app.core.attack_mapper import ATTACKMapper
        return ATTACKMapper()

    @staticmethod
    def _make_retest_workflow():
        from app.core.retest_workflow import RetestWorkflow
        return RetestWorkflow()

    @staticmethod
    def _make_import_export_engine():
        from app.core.import_export_engine import ImportExportEngine
        return ImportExportEngine()

    @staticmethod
    def _make_collaboration_manager():
        from app.core.collaboration_manager import CollaborationManager
        return CollaborationManager()

    @staticmethod
    def _make_knowledge_base():
        from app.core.knowledge_base import KnowledgeBase
        return KnowledgeBase()

    @staticmethod
    def _make_report_customizer():
        from app.core.report_customizer import ReportCustomizer
        return ReportCustomizer()

    @staticmethod
    def _make_attack_surface_mapper():
        from app.core.attack_surface_mapper import AttackSurfaceMapper
        return AttackSurfaceMapper()

    @staticmethod
    def _make_scheduling_engine():
        from app.core.scheduling_engine import SchedulingEngine
        from app.core.database_pool import DatabaseConnectionPool
        from pathlib import Path
        # Use the engagement manager's master DB pool if available
        project_root = Path(__file__).resolve().parent.parent.parent
        master_db_path = str(project_root / "resources" / "huginn_master_index.db")
        pool = DatabaseConnectionPool(master_db_path, pool_size=3)
        return SchedulingEngine(pool)

    @staticmethod
    def _make_api_pentest_engine():
        from app.core.api_pentest_engine import APIPentestEngine
        return APIPentestEngine()

    @staticmethod
    def _make_container_assessment_engine():
        from app.core.container_assessment_engine import ContainerAssessmentEngine
        return ContainerAssessmentEngine()

    @staticmethod
    def _make_mobile_testing_engine():
        from app.core.mobile_testing_engine import MobileTestingEngine
        return MobileTestingEngine()

    @staticmethod
    def _make_physical_security_engine():
        from app.core.physical_security_engine import PhysicalSecurityEngine
        return PhysicalSecurityEngine()

    @staticmethod
    def _make_gcp_pentest_engine():
        from app.core.gcp_pentest_engine import GCPPentestEngine
        return GCPPentestEngine()


# ---------------------------------------------------------------------------
# Integration class
# ---------------------------------------------------------------------------

class FeatureGapIntegration:
    """Integrates all new platform modules into the existing main window.

    Usage::

        from app.core.feature_gap_integration import FeatureGapIntegration
        FeatureGapIntegration.integrate(main_window)
    """

    # Shared engine registry — survives across calls.
    engines = _EngineRegistry()

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------

    @classmethod
    def integrate(cls, main_window: "MainWindow") -> None:
        """Wire all new modules into *main_window*.

        Safe to call multiple times (idempotent).
        """
        if getattr(main_window, "_feature_gap_integrated", False):
            return
        main_window._feature_gap_integrated = True

        # Store reference for sub-tab injection
        cls._main_window = main_window

        # 1. Register lazy page factories
        cls._register_page_factories(main_window)

        # 2. Add menu entries
        cls._add_menu_entries(main_window)

        # 3. Inject sub-tabs into existing pages
        cls._inject_sub_tabs(main_window)

        # 4. Add floating Notes dock widget
        cls._add_notes_dock(main_window)

        # 5. Wire engagement lifecycle → inject DB into modules on open
        cls._wire_engagement_context()

        logger.info("[FeatureGapIntegration] All new modules integrated successfully.")

    # ------------------------------------------------------------------
    # 1. Page factory registration (lazy loading)
    # ------------------------------------------------------------------

    @classmethod
    def _register_page_factories(cls, mw: "MainWindow") -> None:
        """Register page factories for new standalone pages."""
        pm = mw.page_manager

        pm.register_page("engagement_setup", cls._create_engagement_setup_page)
        pm.register_page("finding_templates", cls._create_finding_templates_page)
        pm.register_page("attack_matrix", cls._create_attack_matrix_page)
        pm.register_page("retest_workflow", cls._create_retest_workflow_page)
        pm.register_page("attack_surface_graph", cls._create_attack_surface_graph_page)

    # --- Page factory callables ---

    @classmethod
    def _create_engagement_setup_page(cls):
        try:
            from app.components.engagement_setup_component import EngagementSetupComponent
            return EngagementSetupComponent(cls._main_window)
        except ImportError as exc:
            logger.warning(f"[FeatureGapIntegration] engagement_setup unavailable: {exc}")
            return None

    @classmethod
    def _create_finding_templates_page(cls):
        try:
            from app.components.finding_templates_component import FindingTemplatesComponent
            return FindingTemplatesComponent(cls._main_window)
        except ImportError as exc:
            logger.warning(f"[FeatureGapIntegration] finding_templates unavailable: {exc}")
            return None

    @classmethod
    def _create_attack_matrix_page(cls):
        try:
            from app.components.attack_matrix_component import AttackMatrixComponent
            return AttackMatrixComponent(cls._main_window)
        except ImportError as exc:
            logger.warning(f"[FeatureGapIntegration] attack_matrix unavailable: {exc}")
            return None

    @classmethod
    def _create_retest_workflow_page(cls):
        try:
            from app.components.retest_workflow_component import RetestWorkflowComponent
            return RetestWorkflowComponent(cls._main_window)
        except ImportError as exc:
            logger.warning(f"[FeatureGapIntegration] retest_workflow unavailable: {exc}")
            return None

    @classmethod
    def _create_attack_surface_graph_page(cls):
        try:
            from app.components.attack_surface_graph_component import AttackSurfaceGraphComponent
            return AttackSurfaceGraphComponent(cls._main_window)
        except ImportError as exc:
            logger.warning(f"[FeatureGapIntegration] attack_surface_graph unavailable: {exc}")
            return None

    # ------------------------------------------------------------------
    # 2. Menu entries
    # ------------------------------------------------------------------

    @classmethod
    def _add_menu_entries(cls, mw: "MainWindow") -> None:
        """Add new entries to the Tools and File menus."""
        menubar = mw.menuBar()

        # Locate existing menus by title
        tools_menu = cls._find_menu(menubar, "&Tools")
        file_menu = cls._find_menu(menubar, "&File")

        # --- Tools menu additions ---
        if tools_menu:
            tools_menu.addSeparator()
            cls._add_action(
                tools_menu, mw, "Scan &Scheduler", "F5",
                "Configure recurring and scheduled scans",
                cls._open_scan_scheduler,
            )

        # --- Help menu additions ---
        help_menu = cls._find_menu(menubar, "&Help")
        if help_menu:
            # Insert Knowledge Base directly after "Tool Help" (first action)
            actions = help_menu.actions()
            kb_action = QAction("&Knowledge Base", mw)
            kb_action.setShortcut(QKeySequence("F2"))
            kb_action.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
            kb_action.setStatusTip("Browse and manage knowledge base articles")
            kb_action.triggered.connect(cls._open_knowledge_base)
            if len(actions) > 1:
                help_menu.insertAction(actions[1], kb_action)
            else:
                help_menu.addAction(kb_action)

        # --- File menu additions (before Exit) ---
        # (Team Collaboration is now in menu_manager.py directly)

    # --- Menu action callbacks ---

    @classmethod
    def _open_import_export(cls):
        try:
            from app.components.import_export_component import ImportExportComponent
            engine = cls.engines.import_export_engine
            dlg = ImportExportComponent(engine, cls._main_window)
            dlg.setWindowTitle("Import / Export")
            dlg.setWindowFlags(Qt.WindowType.Window)
            dlg.resize(900, 650)
            dlg.setMinimumSize(700, 500)
            dlg.show()
            dlg.raise_()
        except (ImportError, Exception) as exc:
            logger.warning(f"[FeatureGapIntegration] import_export unavailable: {exc}")

    @classmethod
    def _open_knowledge_base(cls):
        try:
            from app.components.knowledge_base_component import KnowledgeBaseComponent
            mw = cls._main_window

            # Register the knowledge base page if not already done
            if not hasattr(mw, '_kb_page') or mw._kb_page is None:
                kb = cls.engines.knowledge_base
                mw._kb_page = KnowledgeBaseComponent(kb, mw)
                mw.stack.addWidget(mw._kb_page)

            mw.stack.setCurrentWidget(mw._kb_page)
            mw.status_bar.showMessage("Knowledge Base")
        except (ImportError, Exception) as exc:
            logger.warning(f"[FeatureGapIntegration] knowledge_base unavailable: {exc}")

    @classmethod
    def _open_scan_scheduler(cls):
        try:
            from app.components.scan_scheduler_component import ScanSchedulerComponent
            mw = cls._main_window

            # Register the scan scheduler page if not already done
            if not hasattr(mw, '_scan_scheduler_page') or mw._scan_scheduler_page is None:
                engine = cls.engines.scheduling_engine
                mw._scan_scheduler_page = ScanSchedulerComponent(engine, mw)
                mw.stack.addWidget(mw._scan_scheduler_page)

            mw.stack.setCurrentWidget(mw._scan_scheduler_page)
            mw.status_bar.showMessage("Scan Scheduler")
        except (ImportError, Exception) as exc:
            logger.warning(f"[FeatureGapIntegration] scan_scheduler unavailable: {exc}")

    @classmethod
    def _open_collaboration(cls):
        try:
            from app.components.collaboration_component import CollaborationComponent
            collab = cls.engines.collaboration_manager
            dlg = CollaborationComponent(collab, cls._main_window)

            # Inject active engagement context
            eng_mgr = cls.engines.engagement_manager
            if eng_mgr.active_engagement_id:
                from pathlib import Path
                eng_data = eng_mgr.get_engagement(eng_mgr.active_engagement_id)
                if eng_data:
                    base_path = str(
                        Path(eng_mgr.master_db_path).parent / Path(eng_data["db_path"]).parent
                    )
                    dlg.set_engagement_context(
                        engagement_id=eng_mgr.active_engagement_id,
                        engagement_base_path=base_path,
                    )

            dlg.setWindowTitle("Team Collaboration")
            dlg.setWindowFlags(Qt.WindowType.Window)
            dlg.resize(800, 600)
            dlg.setMinimumSize(600, 400)
            dlg.show()
            dlg.raise_()
        except (ImportError, Exception) as exc:
            logger.warning(f"[FeatureGapIntegration] collaboration unavailable: {exc}")

    # ------------------------------------------------------------------
    # 3. Sub-tab injection into existing pages
    # ------------------------------------------------------------------

    @classmethod
    def _inject_sub_tabs(cls, mw: "MainWindow") -> None:
        """Inject new sub-tabs into existing pages after they are created.

        Because pages are lazily loaded, we monkey-patch the page_manager's
        ``get_page`` to inject tabs on first access of the relevant pages.
        """
        original_get_page = mw.page_manager.get_page

        def _patched_get_page(name: str):
            page = original_get_page(name)
            if page is not None:
                cls._maybe_inject_tabs(name, page)
            return page

        mw.page_manager.get_page = _patched_get_page

    @classmethod
    def _maybe_inject_tabs(cls, page_name: str, page) -> None:
        """Inject sub-tabs if the page has a tab_widget and hasn't been patched yet."""
        marker = f"_fgi_tabs_injected_{page_name}"
        if getattr(page, marker, False):
            return
        setattr(page, marker, True)

        tab_widget = getattr(page, "tab_widget", None)
        if tab_widget is None:
            return

        if page_name == "vuln_scanning":
            cls._inject_vuln_scanning_tabs(tab_widget)
        elif page_name == "web_exploits":
            cls._inject_exploitation_tabs(tab_widget)
        elif page_name == "recon_enumeration":
            cls._inject_recon_tabs(tab_widget)
        elif page_name == "attack_chain_home":
            cls._inject_engagement_setup_tabs(tab_widget, page)

    # --- Vulnerability Analysis → API Pentest ---

    @classmethod
    def _inject_vuln_scanning_tabs(cls, tab_widget) -> None:
        try:
            from app.components.api_pentest_component import APIPentestComponent
            engine = cls.engines.api_pentest_engine
            component = APIPentestComponent(engine)
            tab_widget.addTab(component, "🔌 API Pentest")
        except (ImportError, Exception) as exc:
            logger.debug(f"[FeatureGapIntegration] API Pentest tab unavailable: {exc}")

    # --- Exploitation → Container Assessment, Mobile Testing ---

    @classmethod
    def _inject_exploitation_tabs(cls, tab_widget) -> None:
        try:
            from app.components.container_assessment_component import ContainerAssessmentComponent
            engine = cls.engines.container_assessment_engine
            component = ContainerAssessmentComponent(engine)
            tab_widget.addTab(component, "🐳 Container Assessment")
        except (ImportError, Exception) as exc:
            logger.debug(f"[FeatureGapIntegration] Container Assessment tab unavailable: {exc}")

        try:
            from app.components.mobile_testing_component import MobileTestingComponent
            engine = cls.engines.mobile_testing_engine
            component = MobileTestingComponent(engine)
            tab_widget.addTab(component, "📱 Mobile Testing")
        except (ImportError, Exception) as exc:
            logger.debug(f"[FeatureGapIntegration] Mobile Testing tab unavailable: {exc}")

    # --- Recon → GCP Pentest ---

    @classmethod
    def _inject_recon_tabs(cls, tab_widget) -> None:
        try:
            from app.components.gcp_pentest_component import GCPPentestComponent
            engine = cls.engines.gcp_pentest_engine
            component = GCPPentestComponent(engine)
            tab_widget.addTab(component, "☁️ GCP Pentest")
        except (ImportError, Exception) as exc:
            logger.debug(f"[FeatureGapIntegration] GCP Pentest tab unavailable: {exc}")

    # --- Engagement Setup → Physical Security, Timeline ---

    @classmethod
    def _inject_engagement_setup_tabs(cls, tab_widget, page) -> None:
        """If the engagement setup page has a tab_widget, add Physical Security and Timeline."""
        try:
            from app.components.physical_security_component import PhysicalSecurityComponent
            engine = cls.engines.physical_security_engine
            component = PhysicalSecurityComponent(engine)
            tab_widget.addTab(component, "🏢 Physical Security")
        except (ImportError, Exception) as exc:
            logger.debug(f"[FeatureGapIntegration] Physical Security tab unavailable: {exc}")

        try:
            from app.components.timeline_component import TimelineComponent
            tl = cls.engines.timeline_logger
            component = TimelineComponent(tl)
            tab_widget.addTab(component, "📅 Timeline")
        except (ImportError, Exception) as exc:
            logger.debug(f"[FeatureGapIntegration] Timeline tab unavailable: {exc}")

    # ------------------------------------------------------------------
    # 4. Floating Notes panel (QDockWidget)
    # ------------------------------------------------------------------

    @classmethod
    def _add_notes_dock(cls, mw: "MainWindow") -> None:
        """Add a toggleable floating Notes panel as a QDockWidget."""
        try:
            from app.components.notes_panel_component import NotesPanelComponent

            note_system = cls.engines.note_system
            notes_widget = NotesPanelComponent(note_system, mw)

            dock = QDockWidget("📝 Notes", mw)
            dock.setObjectName("NotesPanelDock")
            dock.setWidget(notes_widget)
            dock.setAllowedAreas(
                Qt.DockWidgetArea.RightDockWidgetArea
                | Qt.DockWidgetArea.LeftDockWidgetArea
                | Qt.DockWidgetArea.BottomDockWidgetArea
            )
            dock.setFeatures(
                QDockWidget.DockWidgetFeature.DockWidgetMovable
                | QDockWidget.DockWidgetFeature.DockWidgetFloatable
                | QDockWidget.DockWidgetFeature.DockWidgetClosable
            )
            # Start hidden — user toggles via View menu or toolbar
            dock.setVisible(False)

            mw.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)

            # Store reference for later access
            mw._notes_dock = dock

            # Add toggle action to View menu
            view_menu = cls._find_menu(mw.menuBar(), "&View")
            if view_menu:
                toggle_action = dock.toggleViewAction()
                toggle_action.setText("📝 &Notes Panel")
                toggle_action.setStatusTip("Toggle the floating notes panel")
                view_menu.addSeparator()
                view_menu.addAction(toggle_action)

        except ImportError as exc:
            logger.warning(f"[FeatureGapIntegration] Notes panel unavailable: {exc}")

    # ------------------------------------------------------------------
    # 5. Engagement context wiring
    # ------------------------------------------------------------------

    @classmethod
    def _wire_engagement_context(cls) -> None:
        """Wire engagement lifecycle signals to inject the active DB into modules.

        Connects to both:
        - engagement_manager.engagement_opened (formal engagement workflow)
        - tenant_aware_updater.tenant_changed (profile selection workflow)
        """
        # 1. Wire formal engagement_opened signal
        try:
            from app.core.engagement_context_wiring import wire_engagement_context

            engagement_manager = cls.engines.engagement_manager
            modules_dict = {
                "evidence_manager": cls.engines.evidence_manager,
                "note_system": cls.engines.note_system,
                "timeline_logger": cls.engines.timeline_logger,
                "retest_workflow": cls.engines.retest_workflow,
                "attack_mapper": cls.engines.attack_mapper,
                "attack_surface_mapper": cls.engines.attack_surface_mapper,
                "physical_security_engine": cls.engines.physical_security_engine,
                "mobile_testing_engine": cls.engines.mobile_testing_engine,
            }
            wire_engagement_context(engagement_manager, modules_dict)
        except Exception as exc:
            logger.warning(f"[FeatureGapIntegration] Engagement context wiring failed: {exc}")

        # 2. Wire tenant/profile change to open the engagement via EngagementManager.
        # When the tenant changes (i.e., user selects an engagement), the
        # engagement_manager.open_engagement() call in the UI already emits
        # engagement_opened which injects the DB into all modules via step 1.
        # This handler is a safety net for cases where tenant_changed fires
        # without an explicit open_engagement() call (e.g., startup restore).
        try:
            from app.core.tenant_aware_updater import tenant_aware_updater

            engagement_manager = cls.engines.engagement_manager

            def _on_tenant_changed(_old_tenant: str, new_tenant: str) -> None:
                """Ensure the engagement is opened when tenant changes."""
                if not new_tenant or new_tenant == "default":
                    return

                # If the engagement is already open, nothing to do
                if engagement_manager.active_engagement_id == new_tenant:
                    return

                # new_tenant may be an engagement_id (UUID) — try opening directly
                try:
                    eng = engagement_manager.get_engagement(new_tenant)
                    if eng:
                        engagement_manager.open_engagement(new_tenant)
                        logger.info(
                            f"[FeatureGapIntegration] Engagement opened via tenant change: {new_tenant}"
                        )
                        return
                except Exception:
                    pass

                # Fallback: try finding by name
                try:
                    eng = engagement_manager.find_by_name(new_tenant)
                    if eng:
                        engagement_manager.open_engagement(eng["id"])
                        logger.info(
                            f"[FeatureGapIntegration] Engagement opened by name via tenant change: {new_tenant}"
                        )
                except Exception as e:
                    logger.debug(
                        f"[FeatureGapIntegration] Could not open engagement "
                        f"for tenant '{new_tenant}': {e}"
                    )

            tenant_aware_updater.tenant_changed.connect(_on_tenant_changed)

            # If a tenant is already active, initialize immediately
            current = tenant_aware_updater.get_current_tenant()
            if current and current != "default":
                _on_tenant_changed("", current)

            logger.debug("[FeatureGapIntegration] Tenant→Engagement wiring connected.")
        except Exception as exc:
            logger.warning(
                f"[FeatureGapIntegration] Tenant→Engagement wiring failed: {exc}"
            )

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_menu(menubar, title: str) -> Optional["QMenu"]:
        """Find an existing menu by its title text (with ampersand)."""
        for action in menubar.actions():
            if action.text() == title:
                return action.menu()
        return None

    @staticmethod
    def _add_action(menu, parent, text: str, shortcut: Optional[str],
                    status_tip: str, callback) -> QAction:
        """Add a QAction to *menu*."""
        action = QAction(text, parent)
        if shortcut:
            action.setShortcut(QKeySequence(shortcut))
            action.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
        action.setStatusTip(status_tip)
        action.triggered.connect(callback)
        menu.addAction(action)
        return action
