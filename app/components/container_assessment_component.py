# app/components/container_assessment_component.py
"""Container Assessment UI Component.

Provides Docker and Kubernetes security assessment interface with:
- Docker target configuration (daemon URL, TLS cert/key/CA file pickers)
- Kubernetes cluster configuration (kubeconfig path, API server URL, token)
- CIS Benchmark check results table with pass/fail indicators
- Kubernetes resource enumeration tree view (namespaces → pods/services/roles)
- Container image scan interface (image ref input + scan button + results list)
- Escape technique guidance panel based on container context

Integrates as a sub-tab within the Exploitation page.

Requirements: 15.1, 15.2, 15.3, 15.4, 15.6, 15.7
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.container_assessment_engine import ContainerAssessmentEngine


class ContainerAssessmentComponent(QWidget):
    """Container security assessment UI component.

    Provides Docker/Kubernetes security testing interfaces including
    target configuration, CIS Benchmark checks, resource enumeration,
    image scanning, and escape technique guidance.

    Signals:
        finding_selected(dict): Emitted when a finding is clicked in results.
        assessment_started(str): Emitted with assessment type when started.
        assessment_completed(str, int): Emitted with type and finding count.
    """

    finding_selected = pyqtSignal(dict)
    assessment_started = pyqtSignal(str)
    assessment_completed = pyqtSignal(str, int)

    def __init__(self, engine: ContainerAssessmentEngine, parent=None):
        """Initialize the ContainerAssessmentComponent.

        Args:
            engine: The ContainerAssessmentEngine instance providing assessment logic.
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self.engine = engine
        self._docker_findings: List[Dict] = []
        self._k8s_findings: List[Dict] = []
        self._image_findings: List[Dict] = []
        self._k8s_resources: Dict[str, Any] = {}

        self._setup_ui()
        self._apply_theme()
        self._connect_signals()

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def _setup_ui(self):
        """Build the main layout with sub-tabs for each assessment area."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Tab widget for different assessment areas
        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_docker_tab(), "Docker Config")
        self.tabs.addTab(self._create_k8s_tab(), "Kubernetes Config")
        self.tabs.addTab(self._create_cis_results_tab(), "CIS Benchmarks")
        self.tabs.addTab(self._create_k8s_tree_tab(), "K8s Resources")
        self.tabs.addTab(self._create_image_scan_tab(), "Image Scan")
        self.tabs.addTab(self._create_escape_tab(), "Escape Guidance")
        layout.addWidget(self.tabs, 1)

    # ------------------------------------------------------------------
    # Docker Target Configuration Tab
    # ------------------------------------------------------------------

    def _create_docker_tab(self) -> QWidget:
        """Build Docker daemon target configuration panel."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Daemon URL
        url_group = QGroupBox("Docker Daemon Connection")
        url_layout = QVBoxLayout(url_group)

        url_row = QHBoxLayout()
        url_row.addWidget(QLabel("Daemon URL:"))
        self.docker_url_input = QLineEdit()
        self.docker_url_input.setPlaceholderText("http://localhost:2375")
        self.docker_url_input.setText("http://localhost:2375")
        url_row.addWidget(self.docker_url_input)
        url_layout.addLayout(url_row)

        layout.addWidget(url_group)

        # TLS Configuration
        tls_group = QGroupBox("TLS Authentication (optional)")
        tls_layout = QVBoxLayout(tls_group)

        # TLS Cert
        cert_row = QHBoxLayout()
        cert_row.addWidget(QLabel("Client Cert:"))
        self.tls_cert_input = QLineEdit()
        self.tls_cert_input.setPlaceholderText("/path/to/cert.pem")
        cert_row.addWidget(self.tls_cert_input)
        self.tls_cert_browse_btn = QPushButton("Browse...")
        self.tls_cert_browse_btn.setFixedWidth(90)
        cert_row.addWidget(self.tls_cert_browse_btn)
        tls_layout.addLayout(cert_row)

        # TLS Key
        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("Client Key:"))
        self.tls_key_input = QLineEdit()
        self.tls_key_input.setPlaceholderText("/path/to/key.pem")
        key_row.addWidget(self.tls_key_input)
        self.tls_key_browse_btn = QPushButton("Browse...")
        self.tls_key_browse_btn.setFixedWidth(90)
        key_row.addWidget(self.tls_key_browse_btn)
        tls_layout.addLayout(key_row)

        # TLS CA
        ca_row = QHBoxLayout()
        ca_row.addWidget(QLabel("CA Cert:"))
        self.tls_ca_input = QLineEdit()
        self.tls_ca_input.setPlaceholderText("/path/to/ca.pem")
        ca_row.addWidget(self.tls_ca_input)
        self.tls_ca_browse_btn = QPushButton("Browse...")
        self.tls_ca_browse_btn.setFixedWidth(90)
        ca_row.addWidget(self.tls_ca_browse_btn)
        tls_layout.addLayout(ca_row)

        layout.addWidget(tls_group)

        # Action buttons
        btn_row = QHBoxLayout()
        self.docker_apply_btn = QPushButton("Apply Configuration")
        self.docker_apply_btn.setMinimumHeight(34)
        btn_row.addWidget(self.docker_apply_btn)

        self.docker_check_btn = QPushButton("Run Docker Check")
        self.docker_check_btn.setMinimumHeight(34)
        btn_row.addWidget(self.docker_check_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Status
        self.docker_status_label = QLabel("Status: Not connected")
        self.docker_status_label.setObjectName("countLabel")
        layout.addWidget(self.docker_status_label)

        layout.addStretch()
        return container

    # ------------------------------------------------------------------
    # Kubernetes Configuration Tab
    # ------------------------------------------------------------------

    def _create_k8s_tab(self) -> QWidget:
        """Build Kubernetes cluster configuration panel."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Kubeconfig
        kube_group = QGroupBox("Kubernetes Cluster Connection")
        kube_layout = QVBoxLayout(kube_group)

        # Kubeconfig path
        kubeconfig_row = QHBoxLayout()
        kubeconfig_row.addWidget(QLabel("Kubeconfig:"))
        self.kubeconfig_input = QLineEdit()
        self.kubeconfig_input.setPlaceholderText("~/.kube/config")
        kubeconfig_row.addWidget(self.kubeconfig_input)
        self.kubeconfig_browse_btn = QPushButton("Browse...")
        self.kubeconfig_browse_btn.setFixedWidth(90)
        kubeconfig_row.addWidget(self.kubeconfig_browse_btn)
        kube_layout.addLayout(kubeconfig_row)

        # API Server URL
        api_row = QHBoxLayout()
        api_row.addWidget(QLabel("API Server:"))
        self.k8s_api_input = QLineEdit()
        self.k8s_api_input.setPlaceholderText("https://localhost:6443")
        api_row.addWidget(self.k8s_api_input)
        kube_layout.addLayout(api_row)

        # Bearer Token
        token_row = QHBoxLayout()
        token_row.addWidget(QLabel("Token:"))
        self.k8s_token_input = QLineEdit()
        self.k8s_token_input.setPlaceholderText("Bearer token for authentication")
        self.k8s_token_input.setEchoMode(QLineEdit.EchoMode.Password)
        token_row.addWidget(self.k8s_token_input)
        kube_layout.addLayout(token_row)

        # CA Cert
        ca_row = QHBoxLayout()
        ca_row.addWidget(QLabel("CA Cert:"))
        self.k8s_ca_input = QLineEdit()
        self.k8s_ca_input.setPlaceholderText("/path/to/ca.crt (optional)")
        ca_row.addWidget(self.k8s_ca_input)
        self.k8s_ca_browse_btn = QPushButton("Browse...")
        self.k8s_ca_browse_btn.setFixedWidth(90)
        ca_row.addWidget(self.k8s_ca_browse_btn)
        kube_layout.addLayout(ca_row)

        layout.addWidget(kube_group)

        # Action buttons
        btn_row = QHBoxLayout()
        self.k8s_apply_btn = QPushButton("Apply Configuration")
        self.k8s_apply_btn.setMinimumHeight(34)
        btn_row.addWidget(self.k8s_apply_btn)

        self.k8s_enumerate_btn = QPushButton("Enumerate Cluster")
        self.k8s_enumerate_btn.setMinimumHeight(34)
        btn_row.addWidget(self.k8s_enumerate_btn)

        self.k8s_rbac_btn = QPushButton("Check RBAC Misconfigs")
        self.k8s_rbac_btn.setMinimumHeight(34)
        btn_row.addWidget(self.k8s_rbac_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Status
        self.k8s_status_label = QLabel("Status: Not connected")
        self.k8s_status_label.setObjectName("countLabel")
        layout.addWidget(self.k8s_status_label)

        layout.addStretch()
        return container

    # ------------------------------------------------------------------
    # CIS Benchmark Results Tab
    # ------------------------------------------------------------------

    def _create_cis_results_tab(self) -> QWidget:
        """Build CIS Benchmark check results table with pass/fail indicators."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Header row
        header_row = QHBoxLayout()
        header_label = QLabel("CIS Benchmark Results")
        header_label.setObjectName("sectionLabel")
        header_row.addWidget(header_label)
        header_row.addStretch()

        self.cis_summary_label = QLabel("No checks run yet")
        self.cis_summary_label.setObjectName("countLabel")
        header_row.addWidget(self.cis_summary_label)
        layout.addLayout(header_row)

        # Results table
        self.cis_table = QTableWidget()
        self.cis_table.setColumnCount(4)
        self.cis_table.setHorizontalHeaderLabels(
            ["Status", "CIS ID", "Check Description", "Severity"]
        )
        self.cis_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self.cis_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.cis_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.cis_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        self.cis_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.cis_table.setAlternatingRowColors(True)
        self.cis_table.verticalHeader().setVisible(False)
        layout.addWidget(self.cis_table, 1)

        return container

    # ------------------------------------------------------------------
    # Kubernetes Resource Tree Tab
    # ------------------------------------------------------------------

    def _create_k8s_tree_tab(self) -> QWidget:
        """Build K8s resource enumeration tree view (namespaces → pods/services/roles)."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Header
        header_row = QHBoxLayout()
        header_label = QLabel("Kubernetes Resource Tree")
        header_label.setObjectName("sectionLabel")
        header_row.addWidget(header_label)
        header_row.addStretch()

        self.k8s_tree_stats_label = QLabel("No resources enumerated")
        self.k8s_tree_stats_label.setObjectName("countLabel")
        header_row.addWidget(self.k8s_tree_stats_label)

        self.k8s_tree_refresh_btn = QPushButton("Refresh")
        self.k8s_tree_refresh_btn.setMinimumHeight(30)
        header_row.addWidget(self.k8s_tree_refresh_btn)
        layout.addLayout(header_row)

        # Tree widget
        self.k8s_tree = QTreeWidget()
        self.k8s_tree.setHeaderLabels(["Resource", "Status", "Details"])
        self.k8s_tree.setColumnCount(3)
        self.k8s_tree.header().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.k8s_tree.header().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.k8s_tree.header().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self.k8s_tree.setAlternatingRowColors(True)
        layout.addWidget(self.k8s_tree, 1)

        return container

    # ------------------------------------------------------------------
    # Container Image Scan Tab
    # ------------------------------------------------------------------

    def _create_image_scan_tab(self) -> QWidget:
        """Build container image scan interface."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Image reference input
        input_group = QGroupBox("Image Scan")
        input_layout = QVBoxLayout(input_group)

        ref_row = QHBoxLayout()
        ref_row.addWidget(QLabel("Image Ref:"))
        self.image_ref_input = QLineEdit()
        self.image_ref_input.setPlaceholderText(
            "e.g., nginx:latest, ubuntu:22.04, sha256:abc..."
        )
        ref_row.addWidget(self.image_ref_input)

        self.image_scan_btn = QPushButton("Scan Image")
        self.image_scan_btn.setMinimumHeight(34)
        self.image_scan_btn.setMinimumWidth(120)
        ref_row.addWidget(self.image_scan_btn)
        input_layout.addLayout(ref_row)

        layout.addWidget(input_group)

        # Scan status
        self.image_scan_status_label = QLabel("Enter an image reference and click Scan")
        self.image_scan_status_label.setObjectName("countLabel")
        layout.addWidget(self.image_scan_status_label)

        # Results list
        results_label = QLabel("Scan Results")
        results_label.setObjectName("sectionLabel")
        layout.addWidget(results_label)

        self.image_results_list = QListWidget()
        layout.addWidget(self.image_results_list, 1)

        return container

    # ------------------------------------------------------------------
    # Escape Technique Guidance Tab
    # ------------------------------------------------------------------

    def _create_escape_tab(self) -> QWidget:
        """Build escape technique guidance panel with container context checkboxes."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Container context checkboxes
        context_group = QGroupBox("Container Security Context")
        context_layout = QVBoxLayout(context_group)

        self.chk_privileged = QCheckBox("Privileged mode (--privileged)")
        self.chk_docker_socket = QCheckBox(
            "Docker socket mounted (/var/run/docker.sock)"
        )
        self.chk_host_pid = QCheckBox("Host PID namespace (--pid=host)")
        self.chk_host_network = QCheckBox("Host network namespace (--net=host)")
        self.chk_cap_sys_admin = QCheckBox("CAP_SYS_ADMIN capability")

        context_layout.addWidget(self.chk_privileged)
        context_layout.addWidget(self.chk_docker_socket)
        context_layout.addWidget(self.chk_host_pid)
        context_layout.addWidget(self.chk_host_network)
        context_layout.addWidget(self.chk_cap_sys_admin)

        layout.addWidget(context_group)

        # Action button
        btn_row = QHBoxLayout()
        self.escape_guidance_btn = QPushButton("Get Escape Guidance")
        self.escape_guidance_btn.setMinimumHeight(34)
        btn_row.addWidget(self.escape_guidance_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Guidance results
        guidance_label = QLabel("Applicable Escape Techniques")
        guidance_label.setObjectName("sectionLabel")
        layout.addWidget(guidance_label)

        self.escape_results_area = QScrollArea()
        self.escape_results_area.setWidgetResizable(True)
        self.escape_results_content = QWidget()
        self.escape_results_layout = QVBoxLayout(self.escape_results_content)
        self.escape_results_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.escape_results_area.setWidget(self.escape_results_content)
        layout.addWidget(self.escape_results_area, 1)

        return container

    # ------------------------------------------------------------------
    # Signal Connections
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect UI signals to handler slots."""
        # Docker tab
        self.tls_cert_browse_btn.clicked.connect(
            lambda: self._browse_file(self.tls_cert_input, "Select TLS Certificate")
        )
        self.tls_key_browse_btn.clicked.connect(
            lambda: self._browse_file(self.tls_key_input, "Select TLS Key")
        )
        self.tls_ca_browse_btn.clicked.connect(
            lambda: self._browse_file(self.tls_ca_input, "Select CA Certificate")
        )
        self.docker_apply_btn.clicked.connect(self._apply_docker_config)
        self.docker_check_btn.clicked.connect(self._run_docker_check)

        # Kubernetes tab
        self.kubeconfig_browse_btn.clicked.connect(
            lambda: self._browse_file(self.kubeconfig_input, "Select Kubeconfig")
        )
        self.k8s_ca_browse_btn.clicked.connect(
            lambda: self._browse_file(self.k8s_ca_input, "Select CA Certificate")
        )
        self.k8s_apply_btn.clicked.connect(self._apply_k8s_config)
        self.k8s_enumerate_btn.clicked.connect(self._run_k8s_enumeration)
        self.k8s_rbac_btn.clicked.connect(self._run_rbac_check)

        # K8s tree tab
        self.k8s_tree_refresh_btn.clicked.connect(self._run_k8s_enumeration)

        # Image scan tab
        self.image_scan_btn.clicked.connect(self._run_image_scan)

        # Escape guidance tab
        self.escape_guidance_btn.clicked.connect(self._run_escape_guidance)

        # Engine signals
        self.engine.assessment_event.connect(self._on_assessment_event)
        self.engine.finding_discovered.connect(self._on_finding_discovered)

    # ------------------------------------------------------------------
    # Action Handlers
    # ------------------------------------------------------------------

    def _browse_file(self, target_input: QLineEdit, title: str):
        """Open a file dialog and set the selected path into the target input."""
        path, _ = QFileDialog.getOpenFileName(
            self, title, "", "All Files (*.*)"
        )
        if path:
            target_input.setText(path)

    def _apply_docker_config(self):
        """Apply the Docker daemon configuration to the engine."""
        url = self.docker_url_input.text().strip() or "http://localhost:2375"
        cert = self.tls_cert_input.text().strip() or None
        key = self.tls_key_input.text().strip() or None
        ca = self.tls_ca_input.text().strip() or None

        self.engine.configure_docker(
            daemon_url=url, tls_cert=cert, tls_key=key, tls_ca=ca
        )
        self.docker_status_label.setText(f"Status: Configured → {url}")

    def _apply_k8s_config(self):
        """Apply the Kubernetes configuration to the engine."""
        api_server = self.k8s_api_input.text().strip() or "https://localhost:6443"
        token = self.k8s_token_input.text().strip()
        ca_cert = self.k8s_ca_input.text().strip() or None

        self.engine.configure_kubernetes(
            api_server=api_server, token=token, ca_cert=ca_cert
        )
        self.k8s_status_label.setText(f"Status: Configured → {api_server}")

    def _run_docker_check(self):
        """Run Docker daemon misconfiguration checks."""
        self.assessment_started.emit("docker")
        self.docker_status_label.setText("Status: Running Docker checks...")
        self._docker_findings = self.engine.check_docker_daemon()
        self._update_cis_table()
        self.docker_status_label.setText(
            f"Status: Complete — {len(self._docker_findings)} findings"
        )
        self.assessment_completed.emit("docker", len(self._docker_findings))

    def _run_k8s_enumeration(self):
        """Run Kubernetes cluster enumeration."""
        self.assessment_started.emit("kubernetes_enum")
        self.k8s_status_label.setText("Status: Enumerating cluster...")

        kubeconfig = self.kubeconfig_input.text().strip() or None
        api_server = self.k8s_api_input.text().strip() or None

        self._k8s_resources = self.engine.enumerate_kubernetes(
            kubeconfig=kubeconfig, api_server=api_server
        )
        self._populate_k8s_tree()
        ns_count = len(self._k8s_resources.get("namespaces", []))
        pod_count = len(self._k8s_resources.get("pods", []))
        svc_count = len(self._k8s_resources.get("services", []))
        self.k8s_status_label.setText(
            f"Status: {ns_count} namespaces, {pod_count} pods, {svc_count} services"
        )
        self.k8s_tree_stats_label.setText(
            f"{ns_count} namespaces | {pod_count} pods | {svc_count} services"
        )
        self.assessment_completed.emit("kubernetes_enum", pod_count + svc_count)

    def _run_rbac_check(self):
        """Run RBAC misconfiguration checks."""
        self.assessment_started.emit("rbac")
        self.k8s_status_label.setText("Status: Checking RBAC misconfigurations...")

        resources = self._k8s_resources if self._k8s_resources else None
        self._k8s_findings = self.engine.check_rbac_misconfigs(resources)
        self._update_cis_table()
        self.k8s_status_label.setText(
            f"Status: RBAC check complete — {len(self._k8s_findings)} findings"
        )
        self.assessment_completed.emit("rbac", len(self._k8s_findings))

    def _run_image_scan(self):
        """Run container image vulnerability scan."""
        image_ref = self.image_ref_input.text().strip()
        if not image_ref:
            self.image_scan_status_label.setText("Please enter an image reference")
            return

        self.assessment_started.emit("image_scan")
        self.image_scan_status_label.setText(f"Scanning: {image_ref}...")
        self.image_results_list.clear()

        self._image_findings = self.engine.scan_container_image(image_ref)
        self._populate_image_results()
        self.image_scan_status_label.setText(
            f"Scan complete: {len(self._image_findings)} findings for {image_ref}"
        )
        self.assessment_completed.emit("image_scan", len(self._image_findings))

    def _run_escape_guidance(self):
        """Get escape technique guidance based on selected context."""
        context = {
            "privileged": self.chk_privileged.isChecked(),
            "docker_socket_mounted": self.chk_docker_socket.isChecked(),
            "host_pid": self.chk_host_pid.isChecked(),
            "host_network": self.chk_host_network.isChecked(),
            "capabilities": (
                ["CAP_SYS_ADMIN"] if self.chk_cap_sys_admin.isChecked() else []
            ),
            "mounts": [],
        }

        guidance = self.engine.get_escape_guidance(context)
        self._populate_escape_guidance(guidance)

    # ------------------------------------------------------------------
    # UI Population Helpers
    # ------------------------------------------------------------------

    def _update_cis_table(self):
        """Populate the CIS Benchmark results table from findings."""
        all_findings = self._docker_findings + self._k8s_findings
        self.cis_table.setRowCount(len(all_findings))

        pass_count = 0
        fail_count = 0

        for row, finding in enumerate(all_findings):
            # Status indicator (all findings represent failures)
            status_item = QTableWidgetItem("✗ FAIL")
            status_item.setForeground(Qt.GlobalColor.red)
            self.cis_table.setItem(row, 0, status_item)
            fail_count += 1

            # CIS ID
            cis_id_item = QTableWidgetItem(finding.get("cis_reference", "N/A"))
            self.cis_table.setItem(row, 1, cis_id_item)

            # Description
            desc_item = QTableWidgetItem(finding.get("title", ""))
            self.cis_table.setItem(row, 2, desc_item)

            # Severity
            severity = finding.get("severity", "info")
            severity_item = QTableWidgetItem(severity.upper())
            if severity == "critical":
                severity_item.setForeground(Qt.GlobalColor.red)
            elif severity == "high":
                severity_item.setForeground(Qt.GlobalColor.darkRed)
            elif severity == "medium":
                severity_item.setForeground(Qt.GlobalColor.yellow)
            else:
                severity_item.setForeground(Qt.GlobalColor.cyan)
            self.cis_table.setItem(row, 3, severity_item)

        self.cis_summary_label.setText(
            f"Results: {fail_count} failed | {pass_count} passed"
        )

    def _populate_k8s_tree(self):
        """Populate the K8s resource tree view from enumerated resources."""
        self.k8s_tree.clear()

        namespaces = self._k8s_resources.get("namespaces", [])
        pods = self._k8s_resources.get("pods", [])
        services = self._k8s_resources.get("services", [])
        roles = self._k8s_resources.get("roles", [])

        # Build tree by namespace
        for ns in namespaces:
            ns_name = ns.get("name", "unknown")
            ns_status = ns.get("status", "")
            ns_item = QTreeWidgetItem([ns_name, ns_status, "Namespace"])
            ns_item.setExpanded(False)

            # Pods in this namespace
            ns_pods = [p for p in pods if p.get("namespace") == ns_name]
            if ns_pods:
                pods_folder = QTreeWidgetItem(["Pods", "", f"{len(ns_pods)} pods"])
                for pod in ns_pods:
                    pod_name = pod.get("name", "")
                    pod_status = pod.get("status", "")
                    containers = ", ".join(pod.get("containers", []))
                    pod_item = QTreeWidgetItem(
                        [pod_name, pod_status, containers or "—"]
                    )
                    pods_folder.addChild(pod_item)
                ns_item.addChild(pods_folder)

            # Services in this namespace
            ns_services = [s for s in services if s.get("namespace") == ns_name]
            if ns_services:
                svc_folder = QTreeWidgetItem(
                    ["Services", "", f"{len(ns_services)} services"]
                )
                for svc in ns_services:
                    svc_name = svc.get("name", "")
                    svc_type = svc.get("type", "ClusterIP")
                    ports_str = ", ".join(
                        f"{p.get('port', '')}/{p.get('protocol', '')}"
                        for p in svc.get("ports", [])
                    )
                    svc_item = QTreeWidgetItem(
                        [svc_name, svc_type, ports_str or "—"]
                    )
                    svc_folder.addChild(svc_item)
                ns_item.addChild(svc_folder)

            # Roles in this namespace
            ns_roles = [r for r in roles if r.get("namespace") == ns_name]
            if ns_roles:
                roles_folder = QTreeWidgetItem(
                    ["Roles", "", f"{len(ns_roles)} roles"]
                )
                for role in ns_roles:
                    role_name = role.get("name", "")
                    rules_count = len(role.get("rules", []))
                    role_item = QTreeWidgetItem(
                        [role_name, "", f"{rules_count} rules"]
                    )
                    roles_folder.addChild(role_item)
                ns_item.addChild(roles_folder)

            self.k8s_tree.addTopLevelItem(ns_item)

        # Cluster-wide resources
        cluster_roles = self._k8s_resources.get("cluster_roles", [])
        if cluster_roles:
            cluster_item = QTreeWidgetItem(
                ["Cluster-wide", "", "ClusterRoles & Bindings"]
            )
            cr_folder = QTreeWidgetItem(
                ["ClusterRoles", "", f"{len(cluster_roles)} roles"]
            )
            for cr in cluster_roles:
                cr_name = cr.get("name", "")
                rules_count = len(cr.get("rules", []))
                cr_child = QTreeWidgetItem([cr_name, "", f"{rules_count} rules"])
                cr_folder.addChild(cr_child)
            cluster_item.addChild(cr_folder)

            crb_list = self._k8s_resources.get("cluster_role_bindings", [])
            if crb_list:
                crb_folder = QTreeWidgetItem(
                    ["ClusterRoleBindings", "", f"{len(crb_list)} bindings"]
                )
                for crb in crb_list:
                    crb_name = crb.get("name", "")
                    role_ref = crb.get("role_ref", {}).get("name", "")
                    crb_child = QTreeWidgetItem(
                        [crb_name, "", f"→ {role_ref}"]
                    )
                    crb_folder.addChild(crb_child)
                cluster_item.addChild(crb_folder)

            self.k8s_tree.addTopLevelItem(cluster_item)

    def _populate_image_results(self):
        """Populate image scan results list."""
        self.image_results_list.clear()
        for finding in self._image_findings:
            severity = finding.get("severity", "info").upper()
            title = finding.get("title", "Unknown")
            cis_ref = finding.get("cis_reference", "")
            text = f"[{severity}] {title}"
            if cis_ref:
                text += f"  ({cis_ref})"

            item = QListWidgetItem(text)
            # Color-code by severity
            if finding.get("severity") == "critical":
                item.setForeground(Qt.GlobalColor.red)
            elif finding.get("severity") == "high":
                item.setForeground(Qt.GlobalColor.darkRed)
            elif finding.get("severity") == "medium":
                item.setForeground(Qt.GlobalColor.yellow)
            else:
                item.setForeground(Qt.GlobalColor.cyan)

            item.setData(Qt.ItemDataRole.UserRole, finding)
            self.image_results_list.addItem(item)

    def _populate_escape_guidance(self, guidance: List[Dict]):
        """Populate the escape guidance results panel."""
        # Clear previous results
        while self.escape_results_layout.count():
            child = self.escape_results_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        if not guidance:
            no_results = QLabel(
                "No applicable escape techniques for the selected context.\n"
                "Check at least one container context option above."
            )
            no_results.setWordWrap(True)
            no_results.setObjectName("countLabel")
            self.escape_results_layout.addWidget(no_results)
            return

        for technique in guidance:
            card = self._create_escape_card(technique)
            self.escape_results_layout.addWidget(card)

    def _create_escape_card(self, technique: Dict) -> QFrame:
        """Create a styled card for a single escape technique."""
        card = QFrame()
        card.setFrameShape(QFrame.Shape.Box)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(10, 10, 10, 10)
        card_layout.setSpacing(6)

        # Technique name
        name_label = QLabel(technique.get("name", "Unknown Technique"))
        name_label.setObjectName("sectionLabel")
        name_label.setWordWrap(True)
        card_layout.addWidget(name_label)

        # MITRE reference
        mitre = technique.get("mitre_technique", "")
        if mitre:
            mitre_label = QLabel(f"MITRE ATT&CK: {mitre}")
            mitre_label.setObjectName("countLabel")
            card_layout.addWidget(mitre_label)

        # Description
        desc_label = QLabel(technique.get("description", ""))
        desc_label.setWordWrap(True)
        card_layout.addWidget(desc_label)

        # Commands
        commands = technique.get("commands", [])
        if commands:
            cmd_label = QLabel("Commands:")
            cmd_label.setObjectName("countLabel")
            card_layout.addWidget(cmd_label)

            cmd_text = QTextEdit()
            cmd_text.setReadOnly(True)
            cmd_text.setMaximumHeight(80)
            cmd_text.setPlainText("\n".join(commands))
            card_layout.addWidget(cmd_text)

        # Condition tag
        condition = technique.get("applicable_because", "")
        if condition:
            tag_label = QLabel(f"Trigger: {condition}")
            tag_label.setStyleSheet(
                "color: #64C8FF; font-style: italic; border: none; background: transparent;"
            )
            card_layout.addWidget(tag_label)

        return card

    # ------------------------------------------------------------------
    # Event Handlers
    # ------------------------------------------------------------------

    def _on_assessment_event(self, event_type: str, message: str):
        """Handle assessment engine events for status updates."""
        # Route status updates to appropriate labels
        if "docker" in event_type:
            self.docker_status_label.setText(f"Status: {message}")
        elif "k8s" in event_type or "rbac" in event_type:
            self.k8s_status_label.setText(f"Status: {message}")
        elif "image" in event_type:
            self.image_scan_status_label.setText(message)

    def _on_finding_discovered(self, finding: Dict):
        """Handle real-time finding discovery from the engine."""
        self.finding_selected.emit(finding)

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass
