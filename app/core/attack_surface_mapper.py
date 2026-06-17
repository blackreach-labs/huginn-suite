# app/core/attack_surface_mapper.py
"""Attack surface mapping engine with graph model and path analysis.

Provides an interactive graph representation of targets, services, and
vulnerabilities with edges representing relationships such as
hosts/has_vulnerability/lateral_movement/exploits. Uses networkx for the
underlying graph model and supports BFS-based attack path discovery,
filtering, and SVG/PNG export for report inclusion.

Connects to centralized_scan_data and pentest_database events to keep
the graph in sync with engagement data.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx
from PyQt6.QtCore import QObject, pyqtSignal

from app.core.engagement_database import EngagementDatabase


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class GraphNode:
    """Represents a node in the attack surface graph.

    Attributes:
        node_id: Unique identifier for the node.
        node_type: Category of the node (target, service, vulnerability).
        label: Human-readable display label.
        properties: Arbitrary metadata dictionary.
    """

    node_id: str
    node_type: str  # target | service | vulnerability
    label: str
    properties: Dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Represents an edge (relationship) in the attack surface graph.

    Attributes:
        source_id: ID of the source node.
        target_id: ID of the destination node.
        edge_type: Relationship type (hosts, has_vulnerability, lateral_movement, exploits).
        properties: Arbitrary metadata dictionary.
    """

    source_id: str
    target_id: str
    edge_type: str  # hosts | has_vulnerability | lateral_movement | exploits
    properties: Dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Valid constants
# ---------------------------------------------------------------------------

VALID_NODE_TYPES = frozenset(["target", "service", "vulnerability"])
VALID_EDGE_TYPES = frozenset([
    "hosts",
    "has_vulnerability",
    "lateral_movement",
    "exploits",
])


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class AttackSurfaceMapper(QObject):
    """Graph-based attack surface mapping engine.

    Maintains a directed graph of targets, services, and vulnerabilities.
    Supports attack path discovery via BFS/DFS, subgraph filtering, and
    image export (SVG/PNG) for reports.

    Signals:
        graph_updated: Emitted whenever the graph structure changes.
        path_discovered(list): Emitted with a path (list of node IDs) when
            a new attack path is found between entry and target nodes.
    """

    graph_updated = pyqtSignal()
    path_discovered = pyqtSignal(list)  # list of node_id strings

    def __init__(self, parent=None):
        """Initialize the AttackSurfaceMapper.

        Args:
            parent: Optional QObject parent.
        """
        super().__init__(parent)
        self._graph: nx.DiGraph = nx.DiGraph()
        self._db: Optional[EngagementDatabase] = None
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []

    # ------------------------------------------------------------------
    # Database connection
    # ------------------------------------------------------------------

    @property
    def database(self) -> Optional[EngagementDatabase]:
        """The currently connected engagement database."""
        return self._db

    def set_database(self, db: EngagementDatabase) -> None:
        """Set the engagement database to operate against.

        Args:
            db: A connected EngagementDatabase instance.
        """
        self._db = db

    def _require_db(self) -> EngagementDatabase:
        """Return the active database or raise if not set.

        Raises:
            RuntimeError: If no database has been set.
        """
        if self._db is None:
            raise RuntimeError("No database set. Call set_database() first.")
        return self._db

    # ------------------------------------------------------------------
    # Graph property accessors
    # ------------------------------------------------------------------

    @property
    def graph(self) -> nx.DiGraph:
        """The underlying networkx directed graph."""
        return self._graph

    @property
    def nodes(self) -> Dict[str, GraphNode]:
        """Dictionary of all graph nodes keyed by node_id."""
        return self._nodes

    @property
    def edges(self) -> List[GraphEdge]:
        """List of all graph edges."""
        return self._edges

    # ------------------------------------------------------------------
    # Node/edge operations
    # ------------------------------------------------------------------

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph.

        If a node with the same node_id already exists, it is updated.

        Args:
            node: The GraphNode to add.

        Raises:
            ValueError: If node_type is not valid.
        """
        if node.node_type not in VALID_NODE_TYPES:
            raise ValueError(
                f"Invalid node_type '{node.node_type}'. "
                f"Must be one of: {sorted(VALID_NODE_TYPES)}"
            )
        self._nodes[node.node_id] = node
        self._graph.add_node(
            node.node_id,
            node_type=node.node_type,
            label=node.label,
            **node.properties,
        )
        self.graph_updated.emit()

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge (relationship) between two nodes.

        Both source and target nodes must already exist in the graph.

        Args:
            edge: The GraphEdge to add.

        Raises:
            ValueError: If edge_type is invalid or if source/target nodes
                do not exist in the graph.
        """
        if edge.edge_type not in VALID_EDGE_TYPES:
            raise ValueError(
                f"Invalid edge_type '{edge.edge_type}'. "
                f"Must be one of: {sorted(VALID_EDGE_TYPES)}"
            )
        if edge.source_id not in self._nodes:
            raise ValueError(f"Source node '{edge.source_id}' not in graph.")
        if edge.target_id not in self._nodes:
            raise ValueError(f"Target node '{edge.target_id}' not in graph.")

        self._edges.append(edge)
        self._graph.add_edge(
            edge.source_id,
            edge.target_id,
            edge_type=edge.edge_type,
            **edge.properties,
        )
        self.graph_updated.emit()

    def remove_node(self, node_id: str) -> None:
        """Remove a node and all its incident edges from the graph.

        Args:
            node_id: The ID of the node to remove.

        Raises:
            ValueError: If the node does not exist.
        """
        if node_id not in self._nodes:
            raise ValueError(f"Node '{node_id}' not in graph.")

        # Remove edges that reference this node
        self._edges = [
            e for e in self._edges
            if e.source_id != node_id and e.target_id != node_id
        ]
        del self._nodes[node_id]
        self._graph.remove_node(node_id)
        self.graph_updated.emit()

    # ------------------------------------------------------------------
    # Attack path analysis
    # ------------------------------------------------------------------

    def find_attack_paths(
        self,
        entry_node_id: str,
        target_node_id: str,
        max_depth: int = 10,
    ) -> List[List[str]]:
        """Find all simple paths from entry to target using BFS-style traversal.

        Uses networkx all_simple_paths with a cutoff depth. Emits
        path_discovered for each path found.

        Args:
            entry_node_id: Starting node ID (e.g., external entry point).
            target_node_id: Destination node ID (e.g., high-value target).
            max_depth: Maximum path length (number of edges).

        Returns:
            List of paths, where each path is a list of node IDs.

        Raises:
            ValueError: If either node does not exist in the graph.
        """
        if entry_node_id not in self._nodes:
            raise ValueError(f"Entry node '{entry_node_id}' not in graph.")
        if target_node_id not in self._nodes:
            raise ValueError(f"Target node '{target_node_id}' not in graph.")

        paths: List[List[str]] = []
        try:
            for path in nx.all_simple_paths(
                self._graph,
                source=entry_node_id,
                target=target_node_id,
                cutoff=max_depth,
            ):
                paths.append(list(path))
                self.path_discovered.emit(list(path))
        except nx.NetworkXError:
            # No path exists
            pass

        return paths

    # ------------------------------------------------------------------
    # Graph filtering
    # ------------------------------------------------------------------

    def filter_graph(
        self,
        subnet: Optional[str] = None,
        service_type: Optional[str] = None,
        severity: Optional[str] = None,
        date_start: Optional[str] = None,
        date_end: Optional[str] = None,
    ) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Filter the graph by criteria, returning matching subgraph.

        All filter parameters are optional. If multiple are provided, they
        are combined with AND logic (all must match for a node to be included).
        Edges are included only if both their source and target nodes pass.

        Args:
            subnet: IP subnet prefix to match (e.g., "192.168.1").
            service_type: Service name/type to match (e.g., "ssh", "http").
            severity: Vulnerability severity level to match (e.g., "high").
            date_start: ISO date string; include nodes discovered on or after.
            date_end: ISO date string; include nodes discovered on or before.

        Returns:
            Tuple of (matching_nodes, matching_edges).
        """
        matching_node_ids: Set[str] = set()

        for node_id, node in self._nodes.items():
            if not self._node_matches_filter(
                node, subnet, service_type, severity, date_start, date_end
            ):
                continue
            matching_node_ids.add(node_id)

        matching_nodes = [
            self._nodes[nid] for nid in matching_node_ids
        ]
        matching_edges = [
            e for e in self._edges
            if e.source_id in matching_node_ids and e.target_id in matching_node_ids
        ]

        return matching_nodes, matching_edges

    def _node_matches_filter(
        self,
        node: GraphNode,
        subnet: Optional[str],
        service_type: Optional[str],
        severity: Optional[str],
        date_start: Optional[str],
        date_end: Optional[str],
    ) -> bool:
        """Check whether a single node passes the filter criteria."""
        props = node.properties

        # Subnet filter — applies to target nodes
        if subnet is not None:
            node_ip = props.get("ip", "")
            if not node_ip.startswith(subnet):
                # Also check the label as fallback
                if not node.label.startswith(subnet):
                    return False

        # Service type filter — applies to service nodes
        if service_type is not None:
            node_service = props.get("service", "")
            if node.node_type == "service" and service_type.lower() not in node_service.lower():
                return False
            elif node.node_type != "service":
                # Non-service nodes don't match a service_type filter
                # unless they're connected to one — include them anyway
                pass

        # Severity filter — applies to vulnerability nodes
        if severity is not None:
            node_severity = props.get("severity", "")
            if node.node_type == "vulnerability" and node_severity.lower() != severity.lower():
                return False
            elif node.node_type != "vulnerability":
                pass

        # Date range filter
        if date_start is not None or date_end is not None:
            node_date = props.get("discovered_at", props.get("created_at", ""))
            if node_date:
                try:
                    dt = datetime.fromisoformat(node_date)
                    if date_start and dt < datetime.fromisoformat(date_start):
                        return False
                    if date_end and dt > datetime.fromisoformat(date_end):
                        return False
                except (ValueError, TypeError):
                    pass

        return True

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_svg(self) -> str:
        """Export the current graph as an SVG string.

        Uses matplotlib with the Agg backend to render the networkx graph.

        Returns:
            SVG markup string.
        """
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(1, 1, figsize=(12, 8))
        pos = nx.spring_layout(self._graph, seed=42)

        # Color map by node type
        color_map = {
            "target": "#4A90D9",
            "service": "#7BC67E",
            "vulnerability": "#E74C3C",
        }
        node_colors = [
            color_map.get(self._graph.nodes[n].get("node_type", "target"), "#888888")
            for n in self._graph.nodes()
        ]
        labels = {
            n: self._graph.nodes[n].get("label", n)
            for n in self._graph.nodes()
        }

        nx.draw(
            self._graph,
            pos,
            ax=ax,
            with_labels=True,
            labels=labels,
            node_color=node_colors,
            node_size=800,
            font_size=8,
            edge_color="#666666",
            arrows=True,
        )
        ax.set_title("Attack Surface Map")

        buf = io.StringIO()
        fig.savefig(buf, format="svg", bbox_inches="tight")
        plt.close(fig)
        return buf.getvalue()

    def export_png(self) -> bytes:
        """Export the current graph as PNG bytes.

        Uses matplotlib with the Agg backend to render the networkx graph.

        Returns:
            PNG image data as bytes.
        """
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(1, 1, figsize=(12, 8))
        pos = nx.spring_layout(self._graph, seed=42)

        color_map = {
            "target": "#4A90D9",
            "service": "#7BC67E",
            "vulnerability": "#E74C3C",
        }
        node_colors = [
            color_map.get(self._graph.nodes[n].get("node_type", "target"), "#888888")
            for n in self._graph.nodes()
        ]
        labels = {
            n: self._graph.nodes[n].get("label", n)
            for n in self._graph.nodes()
        }

        nx.draw(
            self._graph,
            pos,
            ax=ax,
            with_labels=True,
            labels=labels,
            node_color=node_colors,
            node_size=800,
            font_size=8,
            edge_color="#666666",
            arrows=True,
        )
        ax.set_title("Attack Surface Map")

        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        plt.close(fig)
        return buf.getvalue()

    # ------------------------------------------------------------------
    # Database rebuild
    # ------------------------------------------------------------------

    def rebuild_from_database(self) -> None:
        """Reconstruct the graph from engagement database data.

        Queries the engagement database for targets (from findings table),
        services (via service_id in findings), and vulnerabilities, then
        builds the complete graph with appropriate edges.

        Raises:
            RuntimeError: If no database is set.
        """
        db = self._require_db()

        # Clear existing graph
        self._graph.clear()
        self._nodes.clear()
        self._edges.clear()

        # --- Load targets ---
        targets = db.execute_query(
            "SELECT DISTINCT target_id FROM findings WHERE target_id IS NOT NULL"
        )
        target_ids: Set[int] = set()
        for (target_id,) in targets:
            if target_id is None:
                continue
            target_ids.add(target_id)
            node_id = f"target_{target_id}"
            node = GraphNode(
                node_id=node_id,
                node_type="target",
                label=f"Target {target_id}",
                properties={"target_id": target_id},
            )
            self._nodes[node_id] = node
            self._graph.add_node(
                node_id,
                node_type=node.node_type,
                label=node.label,
                **node.properties,
            )

        # --- Load services (via service_id in findings) ---
        services = db.execute_query(
            """SELECT DISTINCT service_id, target_id FROM findings
               WHERE service_id IS NOT NULL AND target_id IS NOT NULL"""
        )
        service_ids: Set[int] = set()
        for service_id, target_id in services:
            if service_id is None:
                continue
            service_ids.add(service_id)
            node_id = f"service_{service_id}"
            if node_id not in self._nodes:
                node = GraphNode(
                    node_id=node_id,
                    node_type="service",
                    label=f"Service {service_id}",
                    properties={"service_id": service_id, "target_id": target_id},
                )
                self._nodes[node_id] = node
                self._graph.add_node(
                    node_id,
                    node_type=node.node_type,
                    label=node.label,
                    **node.properties,
                )

            # Edge: target -> hosts -> service
            target_node_id = f"target_{target_id}"
            if target_node_id in self._nodes:
                edge = GraphEdge(
                    source_id=target_node_id,
                    target_id=node_id,
                    edge_type="hosts",
                )
                self._edges.append(edge)
                self._graph.add_edge(
                    target_node_id, node_id, edge_type="hosts"
                )

        # --- Load vulnerabilities (findings) ---
        findings = db.execute_query(
            """SELECT id, title, severity, target_id, service_id, created_at
               FROM findings"""
        )
        for row in findings:
            finding_id, title, severity, target_id, service_id, created_at = row
            node_id = f"vuln_{finding_id}"
            node = GraphNode(
                node_id=node_id,
                node_type="vulnerability",
                label=title or f"Finding {finding_id}",
                properties={
                    "finding_id": finding_id,
                    "severity": severity or "info",
                    "target_id": target_id,
                    "service_id": service_id,
                    "created_at": created_at or "",
                },
            )
            self._nodes[node_id] = node
            self._graph.add_node(
                node_id,
                node_type=node.node_type,
                label=node.label,
                **node.properties,
            )

            # Edge: service -> has_vulnerability -> vuln (if service exists)
            if service_id is not None:
                service_node_id = f"service_{service_id}"
                if service_node_id in self._nodes:
                    edge = GraphEdge(
                        source_id=service_node_id,
                        target_id=node_id,
                        edge_type="has_vulnerability",
                    )
                    self._edges.append(edge)
                    self._graph.add_edge(
                        service_node_id, node_id, edge_type="has_vulnerability"
                    )
            # Fallback: target -> has_vulnerability -> vuln
            elif target_id is not None:
                target_node_id = f"target_{target_id}"
                if target_node_id in self._nodes:
                    edge = GraphEdge(
                        source_id=target_node_id,
                        target_id=node_id,
                        edge_type="has_vulnerability",
                    )
                    self._edges.append(edge)
                    self._graph.add_edge(
                        target_node_id, node_id, edge_type="has_vulnerability"
                    )

        self.graph_updated.emit()

    # ------------------------------------------------------------------
    # Signal handlers for external integration
    # ------------------------------------------------------------------

    def on_result_added(self, scan_type: str, result_data: dict) -> None:
        """Handle centralized_scan_data.result_added signal.

        Creates or updates graph nodes based on incoming scan results.

        Args:
            scan_type: Type of scan that produced the result.
            result_data: Dictionary containing result details.
        """
        target_ip = result_data.get("target", result_data.get("ip", ""))
        if not target_ip:
            return

        # Ensure target node exists
        target_node_id = f"target_{target_ip}"
        if target_node_id not in self._nodes:
            node = GraphNode(
                node_id=target_node_id,
                node_type="target",
                label=target_ip,
                properties={"ip": target_ip},
            )
            self.add_node(node)

        # If result contains a service, add service node and edge
        port = result_data.get("port")
        service_name = result_data.get("service", "")
        if port:
            service_node_id = f"service_{target_ip}:{port}"
            if service_node_id not in self._nodes:
                svc_node = GraphNode(
                    node_id=service_node_id,
                    node_type="service",
                    label=f"{service_name or 'unknown'}:{port}",
                    properties={
                        "ip": target_ip,
                        "port": port,
                        "service": service_name,
                    },
                )
                self.add_node(svc_node)
                edge = GraphEdge(
                    source_id=target_node_id,
                    target_id=service_node_id,
                    edge_type="hosts",
                )
                self.add_edge(edge)

    def on_target_added(self, target_data: dict) -> None:
        """Handle pentest_database.target_added signal.

        Creates a target node in the graph when a new target is added.

        Args:
            target_data: Dictionary containing target details (ip, hostname, etc.).
        """
        ip = target_data.get("ip", "")
        hostname = target_data.get("hostname", "")
        label = hostname if hostname else ip
        if not ip:
            return

        node_id = f"target_{ip}"
        if node_id not in self._nodes:
            node = GraphNode(
                node_id=node_id,
                node_type="target",
                label=label,
                properties={
                    "ip": ip,
                    "hostname": hostname,
                    "os": target_data.get("os", ""),
                },
            )
            self.add_node(node)

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Remove all nodes and edges from the graph."""
        self._graph.clear()
        self._nodes.clear()
        self._edges.clear()
        self.graph_updated.emit()

    def node_count(self) -> int:
        """Return the number of nodes in the graph."""
        return len(self._nodes)

    def edge_count(self) -> int:
        """Return the number of edges in the graph."""
        return len(self._edges)
