# app/components/attack_surface_graph_component.py
"""Attack Surface Graph UI Component.

Provides an interactive graph visualization of the attack surface with:
- Graph canvas displaying nodes (targets, services, vulnerabilities) and edges
- Layout options: hierarchical, force-directed, radial
- Node click detail panel showing entity record
- Filter toolbar (subnet, service type, severity, date range)
- Attack path highlighting overlay
- Export controls (SVG, PNG) with save file dialog

Integrates as a new tab within the Reporting page.

Requirements: 13.1, 13.3, 13.4, 13.5, 13.6, 13.7
"""

from __future__ import annotations

import io
from typing import Dict, List, Optional, Set

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QComboBox,
    QDateEdit,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from app.core.attack_surface_mapper import AttackSurfaceMapper, GraphNode, GraphEdge


# Node type color constants (matching engine export colors)
COLOR_TARGET = "#4A90D9"
COLOR_SERVICE = "#7BC67E"
COLOR_VULNERABILITY = "#E74C3C"
COLOR_HIGHLIGHT_PATH = "#FFD700"  # Gold for attack path highlighting


class AttackSurfaceGraphComponent(QWidget):
    """Interactive attack surface graph visualization component.

    Displays the attack surface as a graph with zoom/pan, filtering,
    attack path highlighting, and export capabilities.

    Signals:
        node_selected(str): Emitted with node_id when a node is clicked.
        path_highlighted(list): Emitted with list of node IDs for highlighted path.
    """

    node_selected = pyqtSignal(str)
    path_highlighted = pyqtSignal(list)

    def __init__(self, mapper: AttackSurfaceMapper, parent=None):
        """Initialize the AttackSurfaceGraphComponent.

        Args:
            mapper: The AttackSurfaceMapper instance providing graph data.
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self.mapper = mapper
        self._current_layout = "force-directed"
        self._zoom_level = 1.0
        self._highlighted_path: List[str] = []
        self._selected_node_id: Optional[str] = None
        self._filtered_nodes: Optional[List[GraphNode]] = None
        self._filtered_edges: Optional[List[GraphEdge]] = None

        self.setup_ui()
        self.apply_theme()
        self._connect_signals()
        self.refresh_graph()

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def setup_ui(self):
        """Build the layout: top toolbar, left graph canvas, right detail panel."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Top filter/controls toolbar
        layout.addWidget(self._create_toolbar())

        # Main content: graph canvas (left) + detail panel (right)
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: graph canvas with zoom controls
        self.main_splitter.addWidget(self._create_graph_panel())

        # Right: detail panel + attack path panel
        self.main_splitter.addWidget(self._create_right_panel())

        # Set initial splitter sizes (70/30 split)
        self.main_splitter.setSizes([700, 300])
        layout.addWidget(self.main_splitter, 1)

    # ------------------------------------------------------------------
    # Toolbar
    # ------------------------------------------------------------------

    def _create_toolbar(self) -> QWidget:
        """Create the filter and layout controls toolbar."""
        container = QFrame()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(10)

        # Title
        title_label = QLabel("Attack Surface Graph")
        title_label.setObjectName("sectionLabel")
        layout.addWidget(title_label)

        layout.addSpacing(12)

        # Layout selector
        layout.addWidget(QLabel("Layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Force-Directed", "Hierarchical", "Radial"])
        self.layout_combo.setMinimumWidth(130)
        layout.addWidget(self.layout_combo)

        layout.addSpacing(8)

        # Subnet filter
        layout.addWidget(QLabel("Subnet:"))
        self.subnet_input = QLineEdit()
        self.subnet_input.setPlaceholderText("e.g. 192.168.1")
        self.subnet_input.setMaximumWidth(140)
        layout.addWidget(self.subnet_input)

        # Service type filter
        layout.addWidget(QLabel("Service:"))
        self.service_combo = QComboBox()
        self.service_combo.addItem("All", None)
        self.service_combo.addItems([
            "ssh", "http", "https", "ftp", "smb", "rdp",
            "mysql", "mssql", "dns", "smtp",
        ])
        self.service_combo.setMinimumWidth(100)
        layout.addWidget(self.service_combo)

        # Severity filter
        layout.addWidget(QLabel("Severity:"))
        self.severity_combo = QComboBox()
        self.severity_combo.addItem("All", None)
        self.severity_combo.addItems(["critical", "high", "medium", "low", "info"])
        self.severity_combo.setMinimumWidth(100)
        layout.addWidget(self.severity_combo)

        # Date range filters
        layout.addWidget(QLabel("From:"))
        self.date_start_edit = QDateEdit()
        self.date_start_edit.setCalendarPopup(True)
        self.date_start_edit.setDisplayFormat("yyyy-MM-dd")
        self.date_start_edit.setSpecialValueText("Any")
        self.date_start_edit.setMinimumWidth(110)
        layout.addWidget(self.date_start_edit)

        layout.addWidget(QLabel("To:"))
        self.date_end_edit = QDateEdit()
        self.date_end_edit.setCalendarPopup(True)
        self.date_end_edit.setDisplayFormat("yyyy-MM-dd")
        self.date_end_edit.setSpecialValueText("Any")
        self.date_end_edit.setMinimumWidth(110)
        layout.addWidget(self.date_end_edit)

        # Apply filter button
        self.apply_filter_btn = QPushButton("Apply Filter")
        self.apply_filter_btn.setMinimumHeight(30)
        layout.addWidget(self.apply_filter_btn)

        # Clear filter button
        self.clear_filter_btn = QPushButton("Clear")
        self.clear_filter_btn.setMinimumHeight(30)
        layout.addWidget(self.clear_filter_btn)

        layout.addStretch()

        # Node count stats
        self.stats_label = QLabel("Nodes: 0 | Edges: 0")
        self.stats_label.setObjectName("countLabel")
        layout.addWidget(self.stats_label)

        return container

    # ------------------------------------------------------------------
    # Graph Panel
    # ------------------------------------------------------------------

    def _create_graph_panel(self) -> QWidget:
        """Create the graph canvas with zoom/pan controls."""
        container = QFrame()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(8, 8, 8, 8)
        container_layout.setSpacing(6)

        # Zoom controls bar
        zoom_bar = QHBoxLayout()
        zoom_bar.setSpacing(6)

        self.zoom_in_btn = QPushButton("+")
        self.zoom_in_btn.setFixedSize(32, 32)
        self.zoom_in_btn.setToolTip("Zoom In")
        zoom_bar.addWidget(self.zoom_in_btn)

        self.zoom_out_btn = QPushButton("−")
        self.zoom_out_btn.setFixedSize(32, 32)
        self.zoom_out_btn.setToolTip("Zoom Out")
        zoom_bar.addWidget(self.zoom_out_btn)

        self.zoom_reset_btn = QPushButton("1:1")
        self.zoom_reset_btn.setFixedSize(40, 32)
        self.zoom_reset_btn.setToolTip("Reset Zoom")
        zoom_bar.addWidget(self.zoom_reset_btn)

        self.zoom_label = QLabel("100%")
        self.zoom_label.setObjectName("countLabel")
        zoom_bar.addWidget(self.zoom_label)

        zoom_bar.addStretch()

        # Export controls
        self.export_svg_btn = QPushButton("Export SVG")
        self.export_svg_btn.setMinimumHeight(30)
        zoom_bar.addWidget(self.export_svg_btn)

        self.export_png_btn = QPushButton("Export PNG")
        self.export_png_btn.setMinimumHeight(30)
        zoom_bar.addWidget(self.export_png_btn)

        # Refresh button
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setMinimumHeight(30)
        zoom_bar.addWidget(self.refresh_btn)

        container_layout.addLayout(zoom_bar)

        # Legend
        container_layout.addWidget(self._create_legend())

        # Scrollable graph canvas (QLabel displaying rendered PNG)
        self.graph_scroll = QScrollArea()
        self.graph_scroll.setWidgetResizable(True)
        self.graph_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.graph_scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.graph_canvas = QLabel()
        self.graph_canvas.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.graph_canvas.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.graph_canvas.setMinimumSize(400, 300)
        self.graph_canvas.setText("Loading graph...")
        self.graph_canvas.setObjectName("graphCanvas")
        self.graph_canvas.setMouseTracking(True)

        self.graph_scroll.setWidget(self.graph_canvas)
        container_layout.addWidget(self.graph_scroll, 1)

        return container

    def _create_legend(self) -> QWidget:
        """Create the color-coded node type legend."""
        legend_widget = QWidget()
        legend_layout = QHBoxLayout(legend_widget)
        legend_layout.setContentsMargins(0, 2, 0, 2)
        legend_layout.setSpacing(16)

        # Target
        target_dot = QLabel("●")
        target_dot.setStyleSheet(
            f"color: {COLOR_TARGET}; font-size: 14px; border: none; background: transparent;"
        )
        legend_layout.addWidget(target_dot)
        legend_layout.addWidget(QLabel("Target"))

        # Service
        service_dot = QLabel("●")
        service_dot.setStyleSheet(
            f"color: {COLOR_SERVICE}; font-size: 14px; border: none; background: transparent;"
        )
        legend_layout.addWidget(service_dot)
        legend_layout.addWidget(QLabel("Service"))

        # Vulnerability
        vuln_dot = QLabel("●")
        vuln_dot.setStyleSheet(
            f"color: {COLOR_VULNERABILITY}; font-size: 14px; border: none; background: transparent;"
        )
        legend_layout.addWidget(vuln_dot)
        legend_layout.addWidget(QLabel("Vulnerability"))

        # Attack path highlight
        path_dot = QLabel("●")
        path_dot.setStyleSheet(
            f"color: {COLOR_HIGHLIGHT_PATH}; font-size: 14px; border: none; background: transparent;"
        )
        legend_layout.addWidget(path_dot)
        legend_layout.addWidget(QLabel("Attack Path"))

        legend_layout.addStretch()
        return legend_widget

    # ------------------------------------------------------------------
    # Right Panel (Detail + Attack Paths)
    # ------------------------------------------------------------------

    def _create_right_panel(self) -> QWidget:
        """Create the right panel with node details and attack path controls."""
        container = QFrame()
        right_layout = QVBoxLayout(container)
        right_layout.setContentsMargins(8, 8, 8, 8)
        right_layout.setSpacing(8)

        # Node detail panel
        right_layout.addWidget(self._create_detail_panel(), 2)

        # Attack path panel
        right_layout.addWidget(self._create_attack_path_panel(), 1)

        return container

    def _create_detail_panel(self) -> QWidget:
        """Create the node detail panel showing entity record."""
        container = QFrame()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(8, 8, 8, 8)
        container_layout.setSpacing(6)

        detail_label = QLabel("Node Details")
        detail_label.setObjectName("sectionLabel")
        container_layout.addWidget(detail_label)

        # Node name/label
        self.node_label = QLabel("Click a node to view details")
        self.node_label.setObjectName("nodeNameLabel")
        self.node_label.setWordWrap(True)
        container_layout.addWidget(self.node_label)

        # Node type
        self.node_type_label = QLabel("")
        self.node_type_label.setObjectName("countLabel")
        container_layout.addWidget(self.node_type_label)

        # Node ID
        self.node_id_label = QLabel("")
        self.node_id_label.setObjectName("countLabel")
        container_layout.addWidget(self.node_id_label)

        # Properties list
        container_layout.addSpacing(4)
        props_label = QLabel("Properties")
        props_label.setObjectName("sectionLabel")
        container_layout.addWidget(props_label)

        self.properties_list = QListWidget()
        self.properties_list.setMaximumHeight(160)
        container_layout.addWidget(self.properties_list)

        # Connected nodes list
        container_layout.addSpacing(4)
        connections_label = QLabel("Connections")
        connections_label.setObjectName("sectionLabel")
        container_layout.addWidget(connections_label)

        self.connections_list = QListWidget()
        self.connections_list.setMaximumHeight(140)
        container_layout.addWidget(self.connections_list)

        container_layout.addStretch()
        return container

    def _create_attack_path_panel(self) -> QWidget:
        """Create the attack path highlighting panel."""
        container = QFrame()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(8, 8, 8, 8)
        container_layout.setSpacing(6)

        path_label = QLabel("Attack Paths")
        path_label.setObjectName("sectionLabel")
        container_layout.addWidget(path_label)

        # Entry node selector
        entry_layout = QHBoxLayout()
        entry_layout.addWidget(QLabel("Entry:"))
        self.entry_node_combo = QComboBox()
        self.entry_node_combo.setMinimumWidth(140)
        entry_layout.addWidget(self.entry_node_combo, 1)
        container_layout.addLayout(entry_layout)

        # Target node selector
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.target_node_combo = QComboBox()
        self.target_node_combo.setMinimumWidth(140)
        target_layout.addWidget(self.target_node_combo, 1)
        container_layout.addLayout(target_layout)

        # Find paths button
        self.find_paths_btn = QPushButton("Find Attack Paths")
        self.find_paths_btn.setMinimumHeight(32)
        container_layout.addWidget(self.find_paths_btn)

        # Discovered paths list
        self.paths_list = QListWidget()
        self.paths_list.setMaximumHeight(120)
        container_layout.addWidget(self.paths_list)

        # Clear highlight button
        self.clear_highlight_btn = QPushButton("Clear Highlight")
        self.clear_highlight_btn.setMinimumHeight(30)
        self.clear_highlight_btn.setEnabled(False)
        container_layout.addWidget(self.clear_highlight_btn)

        return container

    # ------------------------------------------------------------------
    # Signal Connections
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect widget signals to handler methods."""
        # Layout and zoom
        self.layout_combo.currentIndexChanged.connect(self._on_layout_changed)
        self.zoom_in_btn.clicked.connect(self._on_zoom_in)
        self.zoom_out_btn.clicked.connect(self._on_zoom_out)
        self.zoom_reset_btn.clicked.connect(self._on_zoom_reset)

        # Filters
        self.apply_filter_btn.clicked.connect(self._on_apply_filter)
        self.clear_filter_btn.clicked.connect(self._on_clear_filter)

        # Export
        self.export_svg_btn.clicked.connect(self._on_export_svg)
        self.export_png_btn.clicked.connect(self._on_export_png)

        # Refresh
        self.refresh_btn.clicked.connect(self.refresh_graph)

        # Attack paths
        self.find_paths_btn.clicked.connect(self._on_find_paths)
        self.paths_list.currentItemChanged.connect(self._on_path_selected)
        self.clear_highlight_btn.clicked.connect(self._on_clear_highlight)

        # Connections list click to select connected node
        self.connections_list.itemDoubleClicked.connect(self._on_connection_double_clicked)

        # Mapper signals
        self.mapper.graph_updated.connect(self._on_graph_updated)

    # ------------------------------------------------------------------
    # Graph Rendering
    # ------------------------------------------------------------------

    def refresh_graph(self):
        """Render and display the graph on the canvas."""
        try:
            png_data = self._render_graph_png()
            if png_data:
                pixmap = QPixmap()
                pixmap.loadFromData(png_data)

                # Apply zoom
                if self._zoom_level != 1.0:
                    scaled_w = int(pixmap.width() * self._zoom_level)
                    scaled_h = int(pixmap.height() * self._zoom_level)
                    pixmap = pixmap.scaled(
                        scaled_w, scaled_h,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )

                self.graph_canvas.setPixmap(pixmap)
                self.graph_canvas.setMinimumSize(pixmap.size())
            else:
                self.graph_canvas.setText("No graph data available.\nAdd nodes to the attack surface to visualize.")
                self.graph_canvas.setPixmap(QPixmap())
        except Exception as e:
            self.graph_canvas.setText(f"Error rendering graph:\n{e}")
            self.graph_canvas.setPixmap(QPixmap())

        # Update stats
        self._update_stats()
        # Refresh node combos for attack path selectors
        self._populate_node_combos()

    def _render_graph_png(self) -> Optional[bytes]:
        """Render the current graph (or filtered subgraph) as PNG bytes.

        Applies the selected layout algorithm and attack path highlighting.

        Returns:
            PNG image bytes, or None if graph is empty.
        """
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import networkx as nx

        # Determine which nodes/edges to render
        if self._filtered_nodes is not None:
            nodes_to_draw = {n.node_id: n for n in self._filtered_nodes}
            edges_to_draw = self._filtered_edges or []
        else:
            nodes_to_draw = self.mapper.nodes
            edges_to_draw = self.mapper.edges

        if not nodes_to_draw:
            return None

        # Build a subgraph for rendering
        G = nx.DiGraph()
        for node_id, node in nodes_to_draw.items():
            G.add_node(node_id, node_type=node.node_type, label=node.label)

        for edge in edges_to_draw:
            if edge.source_id in nodes_to_draw and edge.target_id in nodes_to_draw:
                G.add_edge(edge.source_id, edge.target_id, edge_type=edge.edge_type)

        if G.number_of_nodes() == 0:
            return None

        # Compute layout based on selected algorithm
        pos = self._compute_layout(G)

        # Create figure with dark background
        fig, ax = plt.subplots(1, 1, figsize=(14, 10), facecolor="#1A1E2E")
        ax.set_facecolor("#1A1E2E")

        # Node colors
        color_map = {
            "target": COLOR_TARGET,
            "service": COLOR_SERVICE,
            "vulnerability": COLOR_VULNERABILITY,
        }
        node_colors = []
        node_sizes = []
        for n in G.nodes():
            ntype = G.nodes[n].get("node_type", "target")
            # Highlight nodes in attack path
            if n in self._highlighted_path:
                node_colors.append(COLOR_HIGHLIGHT_PATH)
                node_sizes.append(1200)
            else:
                node_colors.append(color_map.get(ntype, "#888888"))
                node_sizes.append(800)

        # Edge colors - highlight attack path edges
        edge_colors = []
        edge_widths = []
        for u, v in G.edges():
            if (u in self._highlighted_path and v in self._highlighted_path):
                # Check if they are consecutive in the path
                try:
                    u_idx = self._highlighted_path.index(u)
                    v_idx = self._highlighted_path.index(v)
                    if abs(u_idx - v_idx) == 1:
                        edge_colors.append(COLOR_HIGHLIGHT_PATH)
                        edge_widths.append(3.0)
                        continue
                except (ValueError, IndexError):
                    pass
            edge_colors.append("#556677")
            edge_widths.append(1.5)

        # Labels
        labels = {n: G.nodes[n].get("label", n) for n in G.nodes()}

        # Draw the graph
        nx.draw(
            G, pos, ax=ax,
            with_labels=True,
            labels=labels,
            node_color=node_colors,
            node_size=node_sizes,
            font_size=7,
            font_color="#DCDCDC",
            edge_color=edge_colors,
            width=edge_widths,
            arrows=True,
            arrowsize=12,
            connectionstyle="arc3,rad=0.1",
        )

        ax.set_title(
            "Attack Surface Map",
            color="#64C8FF",
            fontsize=14,
            fontweight="bold",
            pad=10,
        )
        ax.margins(0.1)

        # Render to PNG bytes
        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight", dpi=100, facecolor=fig.get_facecolor())
        plt.close(fig)
        return buf.getvalue()

    def _compute_layout(self, G) -> Dict:
        """Compute node positions based on selected layout algorithm.

        Args:
            G: networkx DiGraph to compute layout for.

        Returns:
            Dictionary mapping node_id to (x, y) position.
        """
        import networkx as nx

        layout_name = self.layout_combo.currentText().lower()

        if "hierarchical" in layout_name:
            # Use topological/layered layout
            try:
                # Attempt a hierarchical layout using multipartite
                # Assign layers by node type: targets → services → vulnerabilities
                layer_map = {"target": 0, "service": 1, "vulnerability": 2}
                for node in G.nodes():
                    ntype = G.nodes[node].get("node_type", "target")
                    G.nodes[node]["subset"] = layer_map.get(ntype, 0)
                pos = nx.multipartite_layout(G, subset_key="subset", align="horizontal")
            except Exception:
                pos = nx.spring_layout(G, seed=42, k=2.0)

        elif "radial" in layout_name:
            # Use shell layout (concentric circles)
            try:
                # Group nodes by type into shells
                targets = [n for n in G.nodes() if G.nodes[n].get("node_type") == "target"]
                services = [n for n in G.nodes() if G.nodes[n].get("node_type") == "service"]
                vulns = [n for n in G.nodes() if G.nodes[n].get("node_type") == "vulnerability"]
                shells = []
                if targets:
                    shells.append(targets)
                if services:
                    shells.append(services)
                if vulns:
                    shells.append(vulns)
                if not shells:
                    shells = [list(G.nodes())]
                pos = nx.shell_layout(G, nlist=shells)
            except Exception:
                pos = nx.spring_layout(G, seed=42)

        else:
            # Force-directed (default)
            pos = nx.spring_layout(G, seed=42, k=1.5, iterations=50)

        return pos

    # ------------------------------------------------------------------
    # Event Handlers
    # ------------------------------------------------------------------

    def _on_layout_changed(self):
        """Handle layout combo box change."""
        self.refresh_graph()

    def _on_zoom_in(self):
        """Increase zoom level."""
        self._zoom_level = min(self._zoom_level + 0.25, 4.0)
        self.zoom_label.setText(f"{int(self._zoom_level * 100)}%")
        self.refresh_graph()

    def _on_zoom_out(self):
        """Decrease zoom level."""
        self._zoom_level = max(self._zoom_level - 0.25, 0.25)
        self.zoom_label.setText(f"{int(self._zoom_level * 100)}%")
        self.refresh_graph()

    def _on_zoom_reset(self):
        """Reset zoom to 100%."""
        self._zoom_level = 1.0
        self.zoom_label.setText("100%")
        self.refresh_graph()

    def _on_apply_filter(self):
        """Apply the filter toolbar criteria to the graph."""
        subnet = self.subnet_input.text().strip() or None

        service_type = self.service_combo.currentText()
        if service_type == "All":
            service_type = None

        severity = self.severity_combo.currentText()
        if severity == "All":
            severity = None

        # Date range
        date_start = None
        date_end = None
        if self.date_start_edit.date() != self.date_start_edit.minimumDate():
            date_start = self.date_start_edit.date().toString("yyyy-MM-dd")
        if self.date_end_edit.date() != self.date_end_edit.minimumDate():
            date_end = self.date_end_edit.date().toString("yyyy-MM-dd")

        # Apply filter through mapper
        try:
            filtered_nodes, filtered_edges = self.mapper.filter_graph(
                subnet=subnet,
                service_type=service_type,
                severity=severity,
                date_start=date_start,
                date_end=date_end,
            )
            self._filtered_nodes = filtered_nodes
            self._filtered_edges = filtered_edges
        except Exception as e:
            self._show_error(f"Filter error: {e}")
            return

        self.refresh_graph()

    def _on_clear_filter(self):
        """Clear all filters and show full graph."""
        self.subnet_input.clear()
        self.service_combo.setCurrentIndex(0)
        self.severity_combo.setCurrentIndex(0)
        self.date_start_edit.setDate(self.date_start_edit.minimumDate())
        self.date_end_edit.setDate(self.date_end_edit.minimumDate())
        self._filtered_nodes = None
        self._filtered_edges = None
        self.refresh_graph()

    def _on_export_svg(self):
        """Export graph as SVG with save file dialog."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Attack Surface Graph (SVG)",
            "attack_surface_graph.svg",
            "SVG Files (*.svg);;All Files (*)",
        )
        if not file_path:
            return

        try:
            svg_data = self.mapper.export_svg()
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(svg_data)
            self._show_info("Export Successful", f"SVG saved to:\n{file_path}")
        except Exception as e:
            self._show_error(f"SVG export failed: {e}")

    def _on_export_png(self):
        """Export graph as PNG with save file dialog."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Attack Surface Graph (PNG)",
            "attack_surface_graph.png",
            "PNG Files (*.png);;All Files (*)",
        )
        if not file_path:
            return

        try:
            png_data = self.mapper.export_png()
            with open(file_path, "wb") as f:
                f.write(png_data)
            self._show_info("Export Successful", f"PNG saved to:\n{file_path}")
        except Exception as e:
            self._show_error(f"PNG export failed: {e}")

    def _on_find_paths(self):
        """Find attack paths between selected entry and target nodes."""
        entry_id = self.entry_node_combo.currentData()
        target_id = self.target_node_combo.currentData()

        if not entry_id or not target_id:
            self._show_error("Select both an entry node and a target node.")
            return

        if entry_id == target_id:
            self._show_error("Entry and target nodes must be different.")
            return

        try:
            paths = self.mapper.find_attack_paths(entry_id, target_id, max_depth=10)
        except ValueError as e:
            self._show_error(str(e))
            return
        except Exception as e:
            self._show_error(f"Path analysis failed: {e}")
            return

        self.paths_list.clear()

        if not paths:
            placeholder = QListWidgetItem("No attack paths found")
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            self.paths_list.addItem(placeholder)
            return

        for i, path in enumerate(paths, 1):
            # Build a readable path description
            path_labels = []
            for node_id in path:
                node = self.mapper.nodes.get(node_id)
                if node:
                    path_labels.append(node.label)
                else:
                    path_labels.append(node_id)

            display = f"Path {i} ({len(path)} hops): {' → '.join(path_labels)}"
            item = QListWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, path)
            item.setToolTip(" → ".join(path_labels))
            self.paths_list.addItem(item)

    def _on_path_selected(self, current: QListWidgetItem, previous: QListWidgetItem):
        """Handle attack path selection - highlight on graph."""
        if current is None:
            return

        path = current.data(Qt.ItemDataRole.UserRole)
        if path and isinstance(path, list):
            self._highlighted_path = path
            self.clear_highlight_btn.setEnabled(True)
            self.path_highlighted.emit(path)
            self.refresh_graph()

    def _on_clear_highlight(self):
        """Clear the attack path highlight."""
        self._highlighted_path = []
        self.clear_highlight_btn.setEnabled(False)
        self.refresh_graph()

    def _on_graph_updated(self):
        """Handle mapper.graph_updated signal."""
        self.refresh_graph()

    def _on_connection_double_clicked(self, item: QListWidgetItem):
        """Handle double-click on connection list to navigate to that node."""
        node_id = item.data(Qt.ItemDataRole.UserRole)
        if node_id:
            self._select_node(node_id)

    # ------------------------------------------------------------------
    # Node Selection & Detail
    # ------------------------------------------------------------------

    def select_node_by_id(self, node_id: str):
        """Programmatically select and display a node.

        Args:
            node_id: The ID of the node to select.
        """
        self._select_node(node_id)

    def _select_node(self, node_id: str):
        """Select a node and populate the detail panel."""
        node = self.mapper.nodes.get(node_id)
        if not node:
            return

        self._selected_node_id = node_id
        self.node_selected.emit(node_id)

        # Update detail panel
        self.node_label.setText(node.label)
        self.node_type_label.setText(f"Type: {node.node_type}")
        self.node_id_label.setText(f"ID: {node.node_id}")

        # Populate properties
        self.properties_list.clear()
        for key, value in node.properties.items():
            item = QListWidgetItem(f"{key}: {value}")
            self.properties_list.addItem(item)

        if self.properties_list.count() == 0:
            placeholder = QListWidgetItem("No properties")
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            self.properties_list.addItem(placeholder)

        # Populate connections
        self.connections_list.clear()
        for edge in self.mapper.edges:
            if edge.source_id == node_id:
                target_node = self.mapper.nodes.get(edge.target_id)
                label = target_node.label if target_node else edge.target_id
                item = QListWidgetItem(f"→ [{edge.edge_type}] {label}")
                item.setData(Qt.ItemDataRole.UserRole, edge.target_id)
                self.connections_list.addItem(item)
            elif edge.target_id == node_id:
                source_node = self.mapper.nodes.get(edge.source_id)
                label = source_node.label if source_node else edge.source_id
                item = QListWidgetItem(f"← [{edge.edge_type}] {label}")
                item.setData(Qt.ItemDataRole.UserRole, edge.source_id)
                self.connections_list.addItem(item)

        if self.connections_list.count() == 0:
            placeholder = QListWidgetItem("No connections")
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            self.connections_list.addItem(placeholder)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _update_stats(self):
        """Update the node/edge count label."""
        if self._filtered_nodes is not None:
            node_count = len(self._filtered_nodes)
            edge_count = len(self._filtered_edges) if self._filtered_edges else 0
            self.stats_label.setText(
                f"Nodes: {node_count} | Edges: {edge_count} (filtered)"
            )
        else:
            self.stats_label.setText(
                f"Nodes: {self.mapper.node_count()} | Edges: {self.mapper.edge_count()}"
            )

    def _populate_node_combos(self):
        """Populate the entry/target node combo boxes for attack path analysis."""
        self.entry_node_combo.clear()
        self.target_node_combo.clear()

        nodes = self.mapper.nodes
        for node_id, node in sorted(nodes.items(), key=lambda x: x[1].label):
            display = f"[{node.node_type}] {node.label}"
            self.entry_node_combo.addItem(display, node_id)
            self.target_node_combo.addItem(display, node_id)

    def _show_error(self, message: str):
        """Show an error message box."""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Error")
        msg.setText(message)
        msg.setStyleSheet("""
            QMessageBox {
                background-color: rgba(20, 30, 40, 240);
                color: #DCDCDC;
            }
            QLabel { color: #DCDCDC; }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px 15px;
            }
        """)
        msg.exec()

    def _show_info(self, title: str, message: str):
        """Show an informational message box."""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setStyleSheet("""
            QMessageBox {
                background-color: rgba(20, 30, 40, 240);
                color: #DCDCDC;
            }
            QLabel { color: #DCDCDC; }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px 15px;
            }
        """)
        msg.exec()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_mapper(self, mapper: AttackSurfaceMapper):
        """Set or update the AttackSurfaceMapper instance.

        Args:
            mapper: An AttackSurfaceMapper instance.
        """
        # Disconnect old mapper signal if connected
        try:
            self.mapper.graph_updated.disconnect(self._on_graph_updated)
        except (TypeError, RuntimeError):
            pass

        self.mapper = mapper
        self.mapper.graph_updated.connect(self._on_graph_updated)
        self.refresh_graph()

    def highlight_path(self, path: List[str]):
        """Programmatically highlight an attack path on the graph.

        Args:
            path: List of node IDs representing the path to highlight.
        """
        self._highlighted_path = path
        self.clear_highlight_btn.setEnabled(bool(path))
        self.path_highlighted.emit(path)
        self.refresh_graph()

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def apply_theme(self):
        """Apply the dark theme with cyan accents matching project conventions."""
        self.setStyleSheet("""
            QWidget {
                background-color: transparent;
                color: #DCDCDC;
            }
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 6px 10px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QPushButton:disabled {
                background-color: rgba(20, 25, 30, 100);
                border: 1px solid rgba(100, 200, 255, 30);
                color: rgba(220, 220, 220, 80);
            }
            QLineEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QLineEdit:focus {
                border: 2px solid #64C8FF;
            }
            QComboBox {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox QAbstractItemView {
                background-color: rgba(20, 30, 40, 240);
                border: 1px solid rgba(100, 200, 255, 100);
                color: #DCDCDC;
                selection-background-color: rgba(100, 200, 255, 80);
            }
            QListWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
                color: #DCDCDC;
            }
            QListWidget::item {
                padding: 4px 4px;
                border-bottom: 1px solid rgba(100, 200, 255, 20);
            }
            QListWidget::item:selected {
                background-color: rgba(100, 200, 255, 60);
            }
            QListWidget::item:hover {
                background-color: rgba(100, 200, 255, 30);
            }
            QScrollArea {
                border: none;
                background: transparent;
            }
            QLabel {
                color: #DCDCDC;
                border: none;
                background: transparent;
            }
            QLabel#sectionLabel {
                color: #64C8FF;
                font-weight: bold;
                font-size: 14px;
                border: none;
                background: transparent;
            }
            QLabel#countLabel {
                color: #A0A0A0;
                font-size: 11px;
                border: none;
                background: transparent;
            }
            QLabel#nodeNameLabel {
                color: #FFFFFF;
                font-weight: bold;
                font-size: 13px;
                border: none;
                background: transparent;
            }
            QLabel#graphCanvas {
                background-color: rgba(26, 30, 46, 200);
                border: 1px solid rgba(100, 200, 255, 30);
                border-radius: 5px;
                color: #A0A0A0;
                font-size: 12px;
            }
            QDateEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 4px;
            }
            QDateEdit::drop-down {
                border: none;
                width: 20px;
            }
            QSplitter::handle {
                background-color: rgba(100, 200, 255, 40);
                width: 3px;
            }
            QSplitter::handle:hover {
                background-color: #64C8FF;
            }
        """)
