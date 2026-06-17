# tests/test_attack_surface_mapper.py
"""Tests for the attack surface mapper engine."""

import pytest

from app.core.engagement_database import EngagementDatabase
from app.core.attack_surface_mapper import (
    AttackSurfaceMapper,
    GraphNode,
    GraphEdge,
    VALID_NODE_TYPES,
    VALID_EDGE_TYPES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engagement_db(tmp_path):
    """Create a temporary engagement database for testing."""
    db_path = str(tmp_path / "test_engagement.db")
    db = EngagementDatabase(db_path)
    db.connect()
    db.create_schema()
    yield db
    db.close()


@pytest.fixture
def mapper():
    """Create an AttackSurfaceMapper instance."""
    return AttackSurfaceMapper()


@pytest.fixture
def mapper_with_db(mapper, engagement_db):
    """Create an AttackSurfaceMapper with a connected database."""
    mapper.set_database(engagement_db)
    return mapper


@pytest.fixture
def populated_mapper(mapper):
    """Create a mapper with a small graph for testing."""
    # Add nodes
    mapper.add_node(GraphNode("t1", "target", "192.168.1.1", {"ip": "192.168.1.1"}))
    mapper.add_node(GraphNode("t2", "target", "192.168.1.2", {"ip": "192.168.1.2"}))
    mapper.add_node(GraphNode("s1", "service", "SSH:22", {"service": "ssh", "port": 22}))
    mapper.add_node(GraphNode("s2", "service", "HTTP:80", {"service": "http", "port": 80}))
    mapper.add_node(GraphNode("v1", "vulnerability", "SQLi", {"severity": "high"}))
    mapper.add_node(GraphNode("v2", "vulnerability", "XSS", {"severity": "medium"}))

    # Add edges: t1 hosts s1, t2 hosts s2, s2 has_vulnerability v1, s1 has_vulnerability v2
    mapper.add_edge(GraphEdge("t1", "s1", "hosts"))
    mapper.add_edge(GraphEdge("t2", "s2", "hosts"))
    mapper.add_edge(GraphEdge("s2", "v1", "has_vulnerability"))
    mapper.add_edge(GraphEdge("s1", "v2", "has_vulnerability"))

    return mapper


# ---------------------------------------------------------------------------
# Node operations
# ---------------------------------------------------------------------------


class TestNodeOperations:
    """Tests for add_node and remove_node."""

    def test_add_node_basic(self, mapper):
        """Adding a valid node increments the node count."""
        node = GraphNode("n1", "target", "Test Target")
        mapper.add_node(node)
        assert mapper.node_count() == 1
        assert "n1" in mapper.nodes

    def test_add_node_all_types(self, mapper):
        """All valid node types can be added."""
        for i, ntype in enumerate(VALID_NODE_TYPES):
            mapper.add_node(GraphNode(f"n{i}", ntype, f"Node {i}"))
        assert mapper.node_count() == len(VALID_NODE_TYPES)

    def test_add_node_invalid_type(self, mapper):
        """Invalid node_type raises ValueError."""
        with pytest.raises(ValueError, match="Invalid node_type"):
            mapper.add_node(GraphNode("n1", "invalid_type", "Bad"))

    def test_add_node_updates_existing(self, mapper):
        """Adding a node with existing ID updates it."""
        mapper.add_node(GraphNode("n1", "target", "Original"))
        mapper.add_node(GraphNode("n1", "target", "Updated"))
        assert mapper.node_count() == 1
        assert mapper.nodes["n1"].label == "Updated"

    def test_add_node_with_properties(self, mapper):
        """Node properties are stored correctly."""
        props = {"ip": "10.0.0.1", "os": "Linux"}
        mapper.add_node(GraphNode("n1", "target", "Host", props))
        assert mapper.nodes["n1"].properties == props

    def test_remove_node(self, mapper):
        """Removing a node decreases count and removes it."""
        mapper.add_node(GraphNode("n1", "target", "T"))
        mapper.remove_node("n1")
        assert mapper.node_count() == 0
        assert "n1" not in mapper.nodes

    def test_remove_node_removes_edges(self, mapper):
        """Removing a node also removes its incident edges."""
        mapper.add_node(GraphNode("a", "target", "A"))
        mapper.add_node(GraphNode("b", "service", "B"))
        mapper.add_edge(GraphEdge("a", "b", "hosts"))
        assert mapper.edge_count() == 1

        mapper.remove_node("b")
        assert mapper.edge_count() == 0

    def test_remove_nonexistent_node(self, mapper):
        """Removing a node that doesn't exist raises ValueError."""
        with pytest.raises(ValueError, match="not in graph"):
            mapper.remove_node("missing")

    def test_add_node_emits_signal(self, mapper, qtbot):
        """Adding a node emits graph_updated signal."""
        with qtbot.waitSignal(mapper.graph_updated, timeout=1000):
            mapper.add_node(GraphNode("n1", "target", "T"))

    def test_remove_node_emits_signal(self, mapper, qtbot):
        """Removing a node emits graph_updated signal."""
        mapper.add_node(GraphNode("n1", "target", "T"))
        with qtbot.waitSignal(mapper.graph_updated, timeout=1000):
            mapper.remove_node("n1")


# ---------------------------------------------------------------------------
# Edge operations
# ---------------------------------------------------------------------------


class TestEdgeOperations:
    """Tests for add_edge."""

    def test_add_edge_basic(self, mapper):
        """Adding a valid edge between existing nodes works."""
        mapper.add_node(GraphNode("a", "target", "A"))
        mapper.add_node(GraphNode("b", "service", "B"))
        mapper.add_edge(GraphEdge("a", "b", "hosts"))
        assert mapper.edge_count() == 1

    def test_add_edge_invalid_type(self, mapper):
        """Invalid edge_type raises ValueError."""
        mapper.add_node(GraphNode("a", "target", "A"))
        mapper.add_node(GraphNode("b", "service", "B"))
        with pytest.raises(ValueError, match="Invalid edge_type"):
            mapper.add_edge(GraphEdge("a", "b", "invalid_edge"))

    def test_add_edge_missing_source(self, mapper):
        """Adding edge with non-existent source raises ValueError."""
        mapper.add_node(GraphNode("b", "service", "B"))
        with pytest.raises(ValueError, match="Source node"):
            mapper.add_edge(GraphEdge("missing", "b", "hosts"))

    def test_add_edge_missing_target(self, mapper):
        """Adding edge with non-existent target raises ValueError."""
        mapper.add_node(GraphNode("a", "target", "A"))
        with pytest.raises(ValueError, match="Target node"):
            mapper.add_edge(GraphEdge("a", "missing", "hosts"))

    def test_add_edge_with_properties(self, mapper):
        """Edge properties are stored."""
        mapper.add_node(GraphNode("a", "target", "A"))
        mapper.add_node(GraphNode("b", "service", "B"))
        edge = GraphEdge("a", "b", "hosts", {"discovered": "2024-01-01"})
        mapper.add_edge(edge)
        assert mapper.edges[0].properties == {"discovered": "2024-01-01"}

    def test_add_edge_emits_signal(self, mapper, qtbot):
        """Adding an edge emits graph_updated signal."""
        mapper.add_node(GraphNode("a", "target", "A"))
        mapper.add_node(GraphNode("b", "service", "B"))
        with qtbot.waitSignal(mapper.graph_updated, timeout=1000):
            mapper.add_edge(GraphEdge("a", "b", "hosts"))


# ---------------------------------------------------------------------------
# Path finding
# ---------------------------------------------------------------------------


class TestPathFinding:
    """Tests for find_attack_paths."""

    def test_find_direct_path(self, mapper):
        """Direct path between two connected nodes is found."""
        mapper.add_node(GraphNode("a", "target", "A"))
        mapper.add_node(GraphNode("b", "service", "B"))
        mapper.add_edge(GraphEdge("a", "b", "hosts"))

        paths = mapper.find_attack_paths("a", "b")
        assert len(paths) == 1
        assert paths[0] == ["a", "b"]

    def test_find_multi_hop_path(self, mapper):
        """Multi-hop paths are found correctly."""
        mapper.add_node(GraphNode("a", "target", "A"))
        mapper.add_node(GraphNode("b", "service", "B"))
        mapper.add_node(GraphNode("c", "vulnerability", "C"))
        mapper.add_edge(GraphEdge("a", "b", "hosts"))
        mapper.add_edge(GraphEdge("b", "c", "has_vulnerability"))

        paths = mapper.find_attack_paths("a", "c")
        assert len(paths) == 1
        assert paths[0] == ["a", "b", "c"]

    def test_find_multiple_paths(self, mapper):
        """Multiple distinct paths are all discovered."""
        mapper.add_node(GraphNode("a", "target", "A"))
        mapper.add_node(GraphNode("b", "service", "B"))
        mapper.add_node(GraphNode("c", "service", "C"))
        mapper.add_node(GraphNode("d", "vulnerability", "D"))
        mapper.add_edge(GraphEdge("a", "b", "hosts"))
        mapper.add_edge(GraphEdge("a", "c", "hosts"))
        mapper.add_edge(GraphEdge("b", "d", "has_vulnerability"))
        mapper.add_edge(GraphEdge("c", "d", "has_vulnerability"))

        paths = mapper.find_attack_paths("a", "d")
        assert len(paths) == 2

    def test_no_path_exists(self, mapper):
        """Returns empty list when no path exists."""
        mapper.add_node(GraphNode("a", "target", "A"))
        mapper.add_node(GraphNode("b", "target", "B"))
        # No edge between them

        paths = mapper.find_attack_paths("a", "b")
        assert paths == []

    def test_path_respects_max_depth(self, mapper):
        """Paths longer than max_depth are not returned."""
        # Build chain: a -> b -> c -> d
        mapper.add_node(GraphNode("a", "target", "A"))
        mapper.add_node(GraphNode("b", "service", "B"))
        mapper.add_node(GraphNode("c", "service", "C"))
        mapper.add_node(GraphNode("d", "vulnerability", "D"))
        mapper.add_edge(GraphEdge("a", "b", "hosts"))
        mapper.add_edge(GraphEdge("b", "c", "lateral_movement"))
        mapper.add_edge(GraphEdge("c", "d", "has_vulnerability"))

        # max_depth=2 should NOT find the 3-hop path
        paths = mapper.find_attack_paths("a", "d", max_depth=2)
        assert len(paths) == 0

        # max_depth=3 should find it
        paths = mapper.find_attack_paths("a", "d", max_depth=3)
        assert len(paths) == 1

    def test_path_nonexistent_entry(self, mapper):
        """Non-existent entry node raises ValueError."""
        mapper.add_node(GraphNode("b", "target", "B"))
        with pytest.raises(ValueError, match="Entry node"):
            mapper.find_attack_paths("missing", "b")

    def test_path_nonexistent_target(self, mapper):
        """Non-existent target node raises ValueError."""
        mapper.add_node(GraphNode("a", "target", "A"))
        with pytest.raises(ValueError, match="Target node"):
            mapper.find_attack_paths("a", "missing")

    def test_path_discovered_signal(self, mapper, qtbot):
        """path_discovered signal is emitted for each path found."""
        mapper.add_node(GraphNode("a", "target", "A"))
        mapper.add_node(GraphNode("b", "service", "B"))
        mapper.add_edge(GraphEdge("a", "b", "hosts"))

        with qtbot.waitSignal(mapper.path_discovered, timeout=1000):
            mapper.find_attack_paths("a", "b")


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


class TestFiltering:
    """Tests for filter_graph."""

    def test_filter_by_subnet(self, populated_mapper):
        """Subnet filter returns only matching target/service nodes."""
        nodes, edges = populated_mapper.filter_graph(subnet="192.168.1.1")
        node_ids = {n.node_id for n in nodes}
        assert "t1" in node_ids

    def test_filter_by_service_type(self, populated_mapper):
        """Service type filter includes matching service nodes."""
        nodes, edges = populated_mapper.filter_graph(service_type="ssh")
        node_ids = {n.node_id for n in nodes}
        assert "s1" in node_ids

    def test_filter_by_severity(self, populated_mapper):
        """Severity filter includes matching vulnerability nodes."""
        nodes, edges = populated_mapper.filter_graph(severity="high")
        node_ids = {n.node_id for n in nodes}
        assert "v1" in node_ids

    def test_filter_no_match_returns_empty(self, mapper):
        """Filter with no matches returns empty lists."""
        mapper.add_node(GraphNode("t1", "target", "10.0.0.1", {"ip": "10.0.0.1"}))
        nodes, edges = mapper.filter_graph(subnet="192.168")
        assert len(nodes) == 0

    def test_filter_edges_require_both_nodes(self, populated_mapper):
        """Edges are only included if both endpoints pass the filter."""
        # Only severity=high matches v1, but its connecting edges need the
        # service/target nodes too. Since those don't match severity,
        # edges should be empty.
        nodes, edges = populated_mapper.filter_graph(severity="high")
        # v1 matches, target/service nodes pass (they're not vulnerability type)
        # The edge between s2 and v1 should be included since s2 passes
        # (service_type filter not applied, severity only checks vuln nodes)
        for edge in edges:
            node_ids = {n.node_id for n in nodes}
            assert edge.source_id in node_ids
            assert edge.target_id in node_ids

    def test_filter_by_date_range(self, mapper):
        """Date range filter works on nodes with discovered_at."""
        mapper.add_node(GraphNode(
            "v1", "vulnerability", "Old Bug",
            {"severity": "high", "discovered_at": "2024-01-15"}
        ))
        mapper.add_node(GraphNode(
            "v2", "vulnerability", "New Bug",
            {"severity": "high", "discovered_at": "2024-06-15"}
        ))

        nodes, _ = mapper.filter_graph(date_start="2024-03-01")
        node_ids = {n.node_id for n in nodes}
        assert "v2" in node_ids
        assert "v1" not in node_ids


# ---------------------------------------------------------------------------
# Database rebuild
# ---------------------------------------------------------------------------


class TestRebuildFromDatabase:
    """Tests for rebuild_from_database."""

    def test_rebuild_empty_database(self, mapper_with_db):
        """Rebuilding from an empty database produces an empty graph."""
        mapper_with_db.rebuild_from_database()
        assert mapper_with_db.node_count() == 0
        assert mapper_with_db.edge_count() == 0

    def test_rebuild_with_findings(self, mapper_with_db, engagement_db):
        """Rebuilding creates nodes/edges from findings data."""
        # Insert some test findings
        engagement_db.execute_write(
            """INSERT INTO findings (title, severity, target_id, service_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("SQLi", "high", 1, 10, "2024-01-01T00:00:00", "2024-01-01T00:00:00"),
        )
        engagement_db.execute_write(
            """INSERT INTO findings (title, severity, target_id, service_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("XSS", "medium", 1, 10, "2024-01-02T00:00:00", "2024-01-02T00:00:00"),
        )

        mapper_with_db.rebuild_from_database()

        # Should have: 1 target node, 1 service node, 2 vulnerability nodes
        assert mapper_with_db.node_count() == 4
        assert "target_1" in mapper_with_db.nodes
        assert "service_10" in mapper_with_db.nodes
        assert "vuln_1" in mapper_with_db.nodes
        assert "vuln_2" in mapper_with_db.nodes

    def test_rebuild_creates_edges(self, mapper_with_db, engagement_db):
        """Rebuilding creates proper host and vulnerability edges."""
        engagement_db.execute_write(
            """INSERT INTO findings (title, severity, target_id, service_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("SQLi", "high", 1, 10, "2024-01-01T00:00:00", "2024-01-01T00:00:00"),
        )

        mapper_with_db.rebuild_from_database()

        # Should have: target_1 -> service_10 (hosts) and service_10 -> vuln_1 (has_vulnerability)
        assert mapper_with_db.edge_count() == 2
        edge_types = {e.edge_type for e in mapper_with_db.edges}
        assert "hosts" in edge_types
        assert "has_vulnerability" in edge_types

    def test_rebuild_finding_without_service(self, mapper_with_db, engagement_db):
        """Finding without service_id links directly to target."""
        engagement_db.execute_write(
            """INSERT INTO findings (title, severity, target_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?)""",
            ("MisConfig", "low", 2, "2024-01-01T00:00:00", "2024-01-01T00:00:00"),
        )

        mapper_with_db.rebuild_from_database()

        # target_2 and vuln_1, with direct has_vulnerability edge
        assert "target_2" in mapper_with_db.nodes
        assert "vuln_1" in mapper_with_db.nodes
        edge_types = [e.edge_type for e in mapper_with_db.edges]
        assert "has_vulnerability" in edge_types

    def test_rebuild_clears_existing(self, mapper_with_db, engagement_db):
        """Rebuilding clears the existing graph before populating."""
        # Add a node manually
        mapper_with_db.add_node(GraphNode("manual", "target", "Manual"))
        assert mapper_with_db.node_count() == 1

        # Rebuild from empty DB should clear
        mapper_with_db.rebuild_from_database()
        assert mapper_with_db.node_count() == 0

    def test_rebuild_without_database_raises(self, mapper):
        """Rebuild without a database set raises RuntimeError."""
        with pytest.raises(RuntimeError, match="No database set"):
            mapper.rebuild_from_database()


# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------


class TestSignalHandlers:
    """Tests for on_result_added and on_target_added."""

    def test_on_result_added_creates_target(self, mapper):
        """on_result_added creates a target node."""
        mapper.on_result_added("port_scan", {"target": "10.0.0.1", "port": 22, "service": "ssh"})
        assert "target_10.0.0.1" in mapper.nodes
        assert mapper.nodes["target_10.0.0.1"].node_type == "target"

    def test_on_result_added_creates_service(self, mapper):
        """on_result_added creates a service node and edge."""
        mapper.on_result_added("port_scan", {"target": "10.0.0.1", "port": 443, "service": "https"})
        assert "service_10.0.0.1:443" in mapper.nodes
        assert mapper.edge_count() == 1

    def test_on_result_added_no_duplicate(self, mapper):
        """Calling on_result_added twice with same data doesn't duplicate."""
        mapper.on_result_added("scan", {"target": "10.0.0.1", "port": 80})
        mapper.on_result_added("scan", {"target": "10.0.0.1", "port": 80})
        assert mapper.node_count() == 2  # target + service
        assert mapper.edge_count() == 1

    def test_on_result_added_empty_target(self, mapper):
        """on_result_added with no target does nothing."""
        mapper.on_result_added("scan", {"port": 80})
        assert mapper.node_count() == 0

    def test_on_target_added(self, mapper):
        """on_target_added creates a target node."""
        mapper.on_target_added({"ip": "192.168.1.100", "hostname": "web-server"})
        assert "target_192.168.1.100" in mapper.nodes
        assert mapper.nodes["target_192.168.1.100"].label == "web-server"

    def test_on_target_added_no_ip(self, mapper):
        """on_target_added with no IP does nothing."""
        mapper.on_target_added({"hostname": "test"})
        assert mapper.node_count() == 0


# ---------------------------------------------------------------------------
# Export (basic validation, no pixel comparison)
# ---------------------------------------------------------------------------


class TestExport:
    """Tests for export_svg and export_png."""

    def test_export_svg_returns_string(self, populated_mapper):
        """export_svg returns a non-empty SVG string."""
        svg = populated_mapper.export_svg()
        assert isinstance(svg, str)
        assert "<svg" in svg.lower()
        assert len(svg) > 100

    def test_export_png_returns_bytes(self, populated_mapper):
        """export_png returns PNG bytes with proper header."""
        png = populated_mapper.export_png()
        assert isinstance(png, bytes)
        # PNG magic bytes
        assert png[:8] == b"\x89PNG\r\n\x1a\n"

    def test_export_empty_graph(self, mapper):
        """Export of empty graph still produces valid output."""
        svg = mapper.export_svg()
        assert isinstance(svg, str)
        assert "<svg" in svg.lower()

        png = mapper.export_png()
        assert isinstance(png, bytes)
        assert png[:8] == b"\x89PNG\r\n\x1a\n"


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


class TestUtility:
    """Tests for clear and count methods."""

    def test_clear(self, populated_mapper):
        """clear() removes all nodes and edges."""
        assert populated_mapper.node_count() > 0
        populated_mapper.clear()
        assert populated_mapper.node_count() == 0
        assert populated_mapper.edge_count() == 0

    def test_node_count(self, mapper):
        """node_count reflects current state."""
        assert mapper.node_count() == 0
        mapper.add_node(GraphNode("a", "target", "A"))
        assert mapper.node_count() == 1

    def test_edge_count(self, mapper):
        """edge_count reflects current state."""
        assert mapper.edge_count() == 0
        mapper.add_node(GraphNode("a", "target", "A"))
        mapper.add_node(GraphNode("b", "service", "B"))
        mapper.add_edge(GraphEdge("a", "b", "hosts"))
        assert mapper.edge_count() == 1
