"""Tests for the ContainerAssessmentEngine module.

Tests use mocked Docker API and K8s API responses to validate:
- Docker daemon misconfiguration detection
- Kubernetes cluster enumeration
- RBAC misconfiguration detection
- Container image vulnerability scanning
- Escape technique guidance
"""

import pytest
from unittest.mock import patch, MagicMock

from app.core.container_assessment_engine import (
    ContainerAssessmentEngine,
    CIS_DOCKER_CHECKS,
    CIS_K8S_CHECKS,
    ESCAPE_TECHNIQUES,
    RBAC_MISCONFIG_PATTERNS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(qtbot):
    """Create a ContainerAssessmentEngine instance for testing."""
    eng = ContainerAssessmentEngine()
    eng.configure_docker(daemon_url="http://testhost:2375")
    eng.configure_kubernetes(api_server="https://k8s-test:6443", token="test-token")
    return eng


# ---------------------------------------------------------------------------
# Mock Data - Docker API
# ---------------------------------------------------------------------------

MOCK_DOCKER_INFO = {
    "ServerVersion": "24.0.7",
    "Containers": 5,
    "ContainersRunning": 3,
    "OperatingSystem": "Ubuntu 22.04",
}

MOCK_CONTAINERS_LIST = [
    {
        "Id": "abc123def456789",
        "Names": ["/privileged-app"],
        "Image": "nginx:latest",
        "State": "running",
    },
    {
        "Id": "def456ghi789012",
        "Names": ["/socket-mounter"],
        "Image": "alpine:3.18",
        "State": "running",
    },
    {
        "Id": "ghi789jkl012345",
        "Names": ["/host-network-pod"],
        "Image": "busybox:latest",
        "State": "running",
    },
]

MOCK_CONTAINER_INSPECT_PRIVILEGED = {
    "Id": "abc123def456789",
    "HostConfig": {
        "Privileged": True,
        "NetworkMode": "bridge",
        "PidMode": "",
    },
    "Mounts": [
        {"Source": "/etc", "Destination": "/host-etc", "Type": "bind"},
    ],
}

MOCK_CONTAINER_INSPECT_SOCKET = {
    "Id": "def456ghi789012",
    "HostConfig": {
        "Privileged": False,
        "NetworkMode": "bridge",
        "PidMode": "",
    },
    "Mounts": [
        {"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "Type": "bind"},
    ],
}

MOCK_CONTAINER_INSPECT_HOST_NET = {
    "Id": "ghi789jkl012345",
    "HostConfig": {
        "Privileged": False,
        "NetworkMode": "host",
        "PidMode": "host",
    },
    "Mounts": [],
}


# ---------------------------------------------------------------------------
# Mock Data - Kubernetes API
# ---------------------------------------------------------------------------

MOCK_K8S_NAMESPACES = {
    "items": [
        {"metadata": {"name": "default", "labels": {}}, "status": {"phase": "Active"}},
        {"metadata": {"name": "kube-system", "labels": {"kubernetes.io/metadata.name": "kube-system"}}, "status": {"phase": "Active"}},
        {"metadata": {"name": "production", "labels": {"env": "prod"}}, "status": {"phase": "Active"}},
    ]
}

MOCK_K8S_PODS = {
    "items": [
        {
            "metadata": {"name": "privileged-pod", "namespace": "default"},
            "spec": {
                "nodeName": "node-1",
                "hostNetwork": True,
                "hostPID": True,
                "serviceAccountName": "default",
                "securityContext": {},
                "containers": [
                    {
                        "name": "main",
                        "securityContext": {"privileged": True},
                    }
                ],
            },
            "status": {"phase": "Running"},
        },
        {
            "metadata": {"name": "safe-pod", "namespace": "production"},
            "spec": {
                "nodeName": "node-2",
                "hostNetwork": False,
                "hostPID": False,
                "serviceAccountName": "app-sa",
                "securityContext": {"runAsNonRoot": True},
                "containers": [
                    {
                        "name": "app",
                        "securityContext": {"privileged": False},
                    }
                ],
            },
            "status": {"phase": "Running"},
        },
    ]
}

MOCK_K8S_SERVICES = {
    "items": [
        {
            "metadata": {"name": "kubernetes-dashboard", "namespace": "kubernetes-dashboard"},
            "spec": {"type": "NodePort", "ports": [{"port": 443, "nodePort": 30443}], "selector": {"app": "dashboard"}},
        },
        {
            "metadata": {"name": "my-service", "namespace": "default"},
            "spec": {"type": "ClusterIP", "ports": [{"port": 80}], "selector": {"app": "web"}},
        },
    ]
}

MOCK_K8S_ROLES = {
    "items": [
        {
            "metadata": {"name": "wildcard-role", "namespace": "default"},
            "rules": [
                {"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]},
            ],
        },
        {
            "metadata": {"name": "limited-role", "namespace": "production"},
            "rules": [
                {"verbs": ["get", "list"], "resources": ["pods"], "apiGroups": [""]},
            ],
        },
    ]
}

MOCK_K8S_ROLE_BINDINGS = {
    "items": [
        {
            "metadata": {"name": "wildcard-binding", "namespace": "default"},
            "roleRef": {"kind": "Role", "name": "wildcard-role"},
            "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "default"}],
        },
    ]
}

MOCK_K8S_CLUSTER_ROLES = {
    "items": [
        {
            "metadata": {"name": "cluster-admin"},
            "rules": [
                {"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]},
            ],
        },
        {
            "metadata": {"name": "view"},
            "rules": [
                {"verbs": ["get", "list", "watch"], "resources": ["pods", "services"], "apiGroups": [""]},
            ],
        },
    ]
}

MOCK_K8S_CLUSTER_ROLE_BINDINGS = {
    "items": [
        {
            "metadata": {"name": "admin-default-sa"},
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [
                {"kind": "ServiceAccount", "name": "default", "namespace": "kube-system"},
            ],
        },
    ]
}


# ---------------------------------------------------------------------------
# Mock Data - Image Scanning
# ---------------------------------------------------------------------------

MOCK_IMAGE_INSPECT = {
    "Id": "sha256:abc123",
    "Config": {
        "User": "",
        "ExposedPorts": {"80/tcp": {}, "443/tcp": {}},
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "DB_PASSWORD=supersecret123",
            "API_KEY=sk-test-12345",
        ],
        "Healthcheck": None,
    },
    "RootFS": {"Layers": ["sha256:layer1", "sha256:layer2", "sha256:layer3"]},
    "Size": 150000000,
}

MOCK_IMAGE_HISTORY = [
    {"CreatedBy": "/bin/sh -c #(nop) ADD file:abc123 in /", "Size": 80000000},
    {"CreatedBy": "/bin/sh -c apt-get install -y nginx", "Size": 40000000},
    {"CreatedBy": "/bin/sh -c COPY .ssh /root/.ssh", "Size": 1000},
    {"CreatedBy": "/bin/sh -c #(nop) CMD [\"nginx\", \"-g\", \"daemon off;\"]", "Size": 0},
]


# ===========================================================================
# Docker Daemon Assessment Tests
# ===========================================================================


class TestCheckDockerDaemon:
    """Tests for check_docker_daemon()."""

    def test_detects_exposed_api(self, engine):
        """Exposed Docker API without TLS produces a critical finding."""
        with patch.object(engine, "_docker_api_get") as mock_get:
            mock_get.side_effect = lambda path: {
                "/info": (200, MOCK_DOCKER_INFO),
                "/containers/json?all=true": (200, []),
            }.get(path, (404, None))

            findings = engine.check_docker_daemon()

        assert len(findings) >= 1
        api_finding = findings[0]
        assert api_finding["severity"] == "critical"
        assert "CIS-DK-0001" == api_finding["cis_reference"]
        assert "exposed" in api_finding["title"].lower() or "exposed" in api_finding["description"].lower()

    def test_detects_privileged_container(self, engine):
        """Privileged containers produce a critical finding."""
        with patch.object(engine, "_docker_api_get") as mock_get:
            def side_effect(path):
                if path == "/info":
                    return (200, MOCK_DOCKER_INFO)
                elif path == "/containers/json?all=true":
                    return (200, [MOCK_CONTAINERS_LIST[0]])
                elif "/containers/abc123def456/json" in path:
                    return (200, MOCK_CONTAINER_INSPECT_PRIVILEGED)
                return (404, None)

            mock_get.side_effect = side_effect
            findings = engine.check_docker_daemon()

        privileged_findings = [f for f in findings if "privileged" in f["title"].lower()]
        assert len(privileged_findings) >= 1
        assert privileged_findings[0]["severity"] == "critical"
        assert privileged_findings[0]["cis_reference"] == "CIS-DK-0002"

    def test_detects_host_mount(self, engine):
        """Sensitive host directory mounts produce findings."""
        with patch.object(engine, "_docker_api_get") as mock_get:
            def side_effect(path):
                if path == "/info":
                    return (200, MOCK_DOCKER_INFO)
                elif path == "/containers/json?all=true":
                    return (200, [MOCK_CONTAINERS_LIST[0]])
                elif "/containers/abc123def456/json" in path:
                    return (200, MOCK_CONTAINER_INSPECT_PRIVILEGED)
                return (404, None)

            mock_get.side_effect = side_effect
            findings = engine.check_docker_daemon()

        mount_findings = [f for f in findings if "mount" in f["title"].lower() or "mount" in f.get("description", "").lower()]
        assert len(mount_findings) >= 1
        assert any(f["cis_reference"] == "CIS-DK-0003" for f in mount_findings)

    def test_detects_docker_socket_mount(self, engine):
        """Docker socket mount produces a critical finding."""
        with patch.object(engine, "_docker_api_get") as mock_get:
            def side_effect(path):
                if path == "/info":
                    return (200, MOCK_DOCKER_INFO)
                elif path == "/containers/json?all=true":
                    return (200, [MOCK_CONTAINERS_LIST[1]])
                elif "/containers/def456ghi789/json" in path:
                    return (200, MOCK_CONTAINER_INSPECT_SOCKET)
                return (404, None)

            mock_get.side_effect = side_effect
            findings = engine.check_docker_daemon()

        socket_findings = [f for f in findings if f["cis_reference"] == "CIS-DK-0004"]
        assert len(socket_findings) >= 1
        assert socket_findings[0]["severity"] == "critical"
        assert "docker socket" in socket_findings[0]["title"].lower() or "docker socket" in socket_findings[0]["description"].lower()

    def test_detects_host_network_mode(self, engine):
        """Host network mode produces a high finding."""
        with patch.object(engine, "_docker_api_get") as mock_get:
            def side_effect(path):
                if path == "/info":
                    return (200, MOCK_DOCKER_INFO)
                elif path == "/containers/json?all=true":
                    return (200, [MOCK_CONTAINERS_LIST[2]])
                elif "/containers/ghi789jkl012/json" in path:
                    return (200, MOCK_CONTAINER_INSPECT_HOST_NET)
                return (404, None)

            mock_get.side_effect = side_effect
            findings = engine.check_docker_daemon()

        net_findings = [f for f in findings if "network" in f["title"].lower()]
        assert len(net_findings) >= 1
        assert net_findings[0]["severity"] == "high"
        assert net_findings[0]["cis_reference"] == "CIS-DK-0005"

    def test_detects_host_pid_mode(self, engine):
        """Host PID mode produces a high finding."""
        with patch.object(engine, "_docker_api_get") as mock_get:
            def side_effect(path):
                if path == "/info":
                    return (200, MOCK_DOCKER_INFO)
                elif path == "/containers/json?all=true":
                    return (200, [MOCK_CONTAINERS_LIST[2]])
                elif "/containers/ghi789jkl012/json" in path:
                    return (200, MOCK_CONTAINER_INSPECT_HOST_NET)
                return (404, None)

            mock_get.side_effect = side_effect
            findings = engine.check_docker_daemon()

        pid_findings = [f for f in findings if "pid" in f["title"].lower()]
        assert len(pid_findings) >= 1
        assert pid_findings[0]["severity"] == "high"
        assert pid_findings[0]["cis_reference"] == "CIS-DK-0006"

    def test_unreachable_daemon_returns_empty(self, engine):
        """Unreachable Docker daemon returns empty findings."""
        with patch.object(engine, "_docker_api_get") as mock_get:
            mock_get.return_value = (0, None)
            findings = engine.check_docker_daemon()

        assert findings == []

    def test_emits_signals(self, engine, qtbot):
        """Assessment events are emitted during check."""
        with patch.object(engine, "_docker_api_get") as mock_get:
            mock_get.side_effect = lambda path: {
                "/info": (200, MOCK_DOCKER_INFO),
                "/containers/json?all=true": (200, []),
            }.get(path, (404, None))

            events = []
            engine.assessment_event.connect(lambda t, m: events.append((t, m)))
            engine.check_docker_daemon()

        assert any(e[0] == "docker_check_start" for e in events)
        assert any(e[0] == "docker_check_complete" for e in events)


# ===========================================================================
# Kubernetes Enumeration Tests
# ===========================================================================


class TestEnumerateKubernetes:
    """Tests for enumerate_kubernetes()."""

    def _mock_k8s_responses(self, engine, path):
        """Return mock K8s API responses."""
        responses = {
            "/api/v1/namespaces": (200, MOCK_K8S_NAMESPACES),
            "/api/v1/pods": (200, MOCK_K8S_PODS),
            "/api/v1/services": (200, MOCK_K8S_SERVICES),
            "/apis/rbac.authorization.k8s.io/v1/roles": (200, MOCK_K8S_ROLES),
            "/apis/rbac.authorization.k8s.io/v1/rolebindings": (200, MOCK_K8S_ROLE_BINDINGS),
            "/apis/rbac.authorization.k8s.io/v1/clusterroles": (200, MOCK_K8S_CLUSTER_ROLES),
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": (200, MOCK_K8S_CLUSTER_ROLE_BINDINGS),
        }
        return responses.get(path, (404, None))

    def test_enumerates_namespaces(self, engine):
        """Enumerates namespaces from K8s API."""
        with patch.object(engine, "_k8s_api_get") as mock_get:
            mock_get.side_effect = lambda path: self._mock_k8s_responses(engine, path)
            result = engine.enumerate_kubernetes()

        assert len(result["namespaces"]) == 3
        ns_names = [ns["name"] for ns in result["namespaces"]]
        assert "default" in ns_names
        assert "kube-system" in ns_names
        assert "production" in ns_names

    def test_enumerates_pods(self, engine):
        """Enumerates pods with security context details."""
        with patch.object(engine, "_k8s_api_get") as mock_get:
            mock_get.side_effect = lambda path: self._mock_k8s_responses(engine, path)
            result = engine.enumerate_kubernetes()

        assert len(result["pods"]) == 2
        priv_pod = next(p for p in result["pods"] if p["name"] == "privileged-pod")
        assert priv_pod["host_network"] is True
        assert priv_pod["host_pid"] is True
        assert priv_pod["namespace"] == "default"

    def test_enumerates_services(self, engine):
        """Enumerates services including type information."""
        with patch.object(engine, "_k8s_api_get") as mock_get:
            mock_get.side_effect = lambda path: self._mock_k8s_responses(engine, path)
            result = engine.enumerate_kubernetes()

        assert len(result["services"]) == 2
        dashboard = next(s for s in result["services"] if "dashboard" in s["name"])
        assert dashboard["type"] == "NodePort"

    def test_enumerates_roles_and_bindings(self, engine):
        """Enumerates roles, role bindings, cluster roles, and cluster role bindings."""
        with patch.object(engine, "_k8s_api_get") as mock_get:
            mock_get.side_effect = lambda path: self._mock_k8s_responses(engine, path)
            result = engine.enumerate_kubernetes()

        assert len(result["roles"]) == 2
        assert len(result["role_bindings"]) == 1
        assert len(result["cluster_roles"]) == 2
        assert len(result["cluster_role_bindings"]) == 1

    def test_handles_api_failure_gracefully(self, engine):
        """Returns empty collections when K8s API is unreachable."""
        with patch.object(engine, "_k8s_api_get") as mock_get:
            mock_get.return_value = (0, None)
            result = engine.enumerate_kubernetes()

        assert result["namespaces"] == []
        assert result["pods"] == []
        assert result["services"] == []
        assert result["roles"] == []

    def test_emits_enum_signals(self, engine, qtbot):
        """Enumeration emits start and complete signals."""
        with patch.object(engine, "_k8s_api_get") as mock_get:
            mock_get.side_effect = lambda path: self._mock_k8s_responses(engine, path)

            events = []
            engine.assessment_event.connect(lambda t, m: events.append((t, m)))
            engine.enumerate_kubernetes()

        assert any(e[0] == "k8s_enum_start" for e in events)
        assert any(e[0] == "k8s_enum_complete" for e in events)


# ===========================================================================
# RBAC Misconfiguration Tests
# ===========================================================================


class TestCheckRBACMisconfigs:
    """Tests for check_rbac_misconfigs()."""

    def _build_k8s_resources(self, **overrides):
        """Build a k8s_resources dict with optional overrides."""
        base = {
            "namespaces": [{"name": "default", "status": "Active", "labels": {}}],
            "pods": [],
            "services": [],
            "roles": [],
            "role_bindings": [],
            "cluster_roles": [],
            "cluster_role_bindings": [],
        }
        base.update(overrides)
        return base

    def test_detects_cluster_admin_default_sa(self, engine):
        """Detects cluster-admin bound to default service account."""
        resources = self._build_k8s_resources(
            cluster_role_bindings=[
                {
                    "name": "admin-default-sa",
                    "role_ref": {"kind": "ClusterRole", "name": "cluster-admin"},
                    "subjects": [
                        {"kind": "ServiceAccount", "name": "default", "namespace": "kube-system"},
                    ],
                }
            ]
        )

        findings = engine.check_rbac_misconfigs(resources)

        admin_findings = [f for f in findings if "cluster-admin" in f["title"]]
        assert len(admin_findings) == 1
        assert admin_findings[0]["severity"] == "critical"
        assert admin_findings[0]["cis_reference"] == "CIS-K8S-5.1.1"

    def test_detects_wildcard_verbs_all_resources(self, engine):
        """Detects wildcard verbs on all resources."""
        resources = self._build_k8s_resources(
            cluster_roles=[
                {
                    "name": "overpermissive-role",
                    "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}],
                }
            ]
        )

        findings = engine.check_rbac_misconfigs(resources)

        wildcard_findings = [f for f in findings if "wildcard" in f["title"].lower()]
        assert len(wildcard_findings) == 1
        assert wildcard_findings[0]["severity"] == "high"
        assert wildcard_findings[0]["cis_reference"] == "CIS-K8S-5.1.3"

    def test_detects_privileged_pods(self, engine):
        """Detects pods running in privileged mode."""
        resources = self._build_k8s_resources(
            pods=[
                {
                    "name": "priv-pod",
                    "namespace": "default",
                    "host_network": False,
                    "host_pid": False,
                    "container_specs": [
                        {"name": "main", "securityContext": {"privileged": True}},
                    ],
                }
            ]
        )

        findings = engine.check_rbac_misconfigs(resources)

        priv_findings = [f for f in findings if "privileged" in f["title"].lower()]
        assert len(priv_findings) == 1
        assert priv_findings[0]["severity"] == "critical"
        assert priv_findings[0]["cis_reference"] == "CIS-K8S-5.2.1"

    def test_detects_host_network(self, engine):
        """Detects pods with hostNetwork: true."""
        resources = self._build_k8s_resources(
            pods=[
                {
                    "name": "net-pod",
                    "namespace": "default",
                    "host_network": True,
                    "host_pid": False,
                    "container_specs": [
                        {"name": "main", "securityContext": {}},
                    ],
                }
            ]
        )

        findings = engine.check_rbac_misconfigs(resources)

        net_findings = [f for f in findings if "network" in f["title"].lower()]
        assert len(net_findings) == 1
        assert net_findings[0]["severity"] == "high"
        assert net_findings[0]["cis_reference"] == "CIS-K8S-5.2.3"

    def test_detects_host_pid(self, engine):
        """Detects pods with hostPID: true."""
        resources = self._build_k8s_resources(
            pods=[
                {
                    "name": "pid-pod",
                    "namespace": "default",
                    "host_network": False,
                    "host_pid": True,
                    "container_specs": [
                        {"name": "main", "securityContext": {}},
                    ],
                }
            ]
        )

        findings = engine.check_rbac_misconfigs(resources)

        pid_findings = [f for f in findings if "pid" in f["title"].lower()]
        assert len(pid_findings) == 1
        assert pid_findings[0]["severity"] == "high"
        assert pid_findings[0]["cis_reference"] == "CIS-K8S-5.2.2"

    def test_detects_exposed_dashboard(self, engine):
        """Detects Kubernetes Dashboard exposed via NodePort/LoadBalancer."""
        resources = self._build_k8s_resources(
            services=[
                {
                    "name": "kubernetes-dashboard",
                    "namespace": "kubernetes-dashboard",
                    "type": "NodePort",
                    "ports": [{"port": 443, "nodePort": 30443}],
                    "selector": {"app": "dashboard"},
                }
            ]
        )

        findings = engine.check_rbac_misconfigs(resources)

        dash_findings = [f for f in findings if "dashboard" in f["title"].lower()]
        assert len(dash_findings) == 1
        assert dash_findings[0]["severity"] == "critical"
        assert dash_findings[0]["cis_reference"] == "CIS-K8S-DASH-001"

    def test_no_findings_for_secure_config(self, engine):
        """Secure configuration produces no findings."""
        resources = self._build_k8s_resources(
            cluster_roles=[
                {
                    "name": "viewer",
                    "rules": [{"verbs": ["get", "list"], "resources": ["pods"], "apiGroups": [""]}],
                }
            ],
            pods=[
                {
                    "name": "safe-pod",
                    "namespace": "prod",
                    "host_network": False,
                    "host_pid": False,
                    "container_specs": [
                        {"name": "app", "securityContext": {"privileged": False}},
                    ],
                }
            ],
            services=[
                {
                    "name": "web-service",
                    "namespace": "prod",
                    "type": "ClusterIP",
                    "ports": [{"port": 80}],
                    "selector": {"app": "web"},
                }
            ],
        )

        findings = engine.check_rbac_misconfigs(resources)
        assert findings == []

    def test_all_findings_have_cis_references(self, engine):
        """All RBAC findings include a valid CIS reference."""
        resources = self._build_k8s_resources(
            cluster_role_bindings=[
                {
                    "name": "bad-binding",
                    "role_ref": {"kind": "ClusterRole", "name": "cluster-admin"},
                    "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "default"}],
                }
            ],
            roles=[
                {
                    "name": "wildcard-role",
                    "namespace": "default",
                    "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}],
                }
            ],
            pods=[
                {
                    "name": "priv-pod",
                    "namespace": "default",
                    "host_network": True,
                    "host_pid": True,
                    "container_specs": [{"name": "c", "securityContext": {"privileged": True}}],
                }
            ],
        )

        findings = engine.check_rbac_misconfigs(resources)
        assert len(findings) >= 4

        all_cis_refs = set(CIS_DOCKER_CHECKS.keys()) | set(CIS_K8S_CHECKS.keys())
        for f in findings:
            assert f["cis_reference"] in all_cis_refs

    def test_emits_finding_discovered_signal(self, engine, qtbot):
        """Each finding emits finding_discovered signal."""
        resources = self._build_k8s_resources(
            cluster_role_bindings=[
                {
                    "name": "bad-binding",
                    "role_ref": {"kind": "ClusterRole", "name": "cluster-admin"},
                    "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "default"}],
                }
            ]
        )

        discovered = []
        engine.finding_discovered.connect(lambda f: discovered.append(f))
        engine.check_rbac_misconfigs(resources)

        assert len(discovered) >= 1
        assert discovered[0]["cis_reference"] == "CIS-K8S-5.1.1"


# ===========================================================================
# Container Image Scanning Tests
# ===========================================================================


class TestScanContainerImage:
    """Tests for scan_container_image()."""

    def test_detects_root_user(self, engine):
        """Detects images configured to run as root."""
        with patch.object(engine, "_docker_api_get") as mock_get:
            def side_effect(path):
                if "/images/" in path and "/json" in path:
                    return (200, MOCK_IMAGE_INSPECT)
                elif "/images/" in path and "/history" in path:
                    return (200, [])
                return (404, None)

            mock_get.side_effect = side_effect
            findings = engine.scan_container_image("nginx:latest")

        root_findings = [f for f in findings if "root" in f["title"].lower()]
        assert len(root_findings) == 1
        assert root_findings[0]["severity"] == "medium"

    def test_detects_secrets_in_env(self, engine):
        """Detects potential secrets in environment variables."""
        with patch.object(engine, "_docker_api_get") as mock_get:
            def side_effect(path):
                if "/images/" in path and "/json" in path:
                    return (200, MOCK_IMAGE_INSPECT)
                elif "/images/" in path and "/history" in path:
                    return (200, [])
                return (404, None)

            mock_get.side_effect = side_effect
            findings = engine.scan_container_image("nginx:latest")

        secret_findings = [f for f in findings if "secret" in f["title"].lower() or "environment" in f["title"].lower()]
        # Should find DB_PASSWORD and API_KEY
        assert len(secret_findings) >= 2

    def test_detects_sensitive_files_in_layers(self, engine):
        """Detects sensitive files copied in image layers."""
        with patch.object(engine, "_docker_api_get") as mock_get:
            def side_effect(path):
                if "/images/" in path and "/json" in path:
                    return (200, MOCK_IMAGE_INSPECT)
                elif "/images/" in path and "/history" in path:
                    return (200, MOCK_IMAGE_HISTORY)
                return (404, None)

            mock_get.side_effect = side_effect
            findings = engine.scan_container_image("nginx:latest")

        layer_findings = [f for f in findings if "layer" in f["title"].lower() or "sensitive file" in f["title"].lower()]
        assert len(layer_findings) >= 1
        assert any("ssh" in f["description"].lower() for f in layer_findings)

    def test_returns_empty_for_unreachable_image(self, engine):
        """Returns empty findings when image cannot be inspected."""
        with patch.object(engine, "_docker_api_get") as mock_get:
            mock_get.return_value = (404, None)
            findings = engine.scan_container_image("nonexistent:latest")

        assert findings == []

    def test_emits_scan_signals(self, engine, qtbot):
        """Image scan emits start and complete signals."""
        with patch.object(engine, "_docker_api_get") as mock_get:
            def side_effect(path):
                if "/images/" in path and "/json" in path:
                    return (200, MOCK_IMAGE_INSPECT)
                elif "/images/" in path and "/history" in path:
                    return (200, [])
                return (404, None)

            mock_get.side_effect = side_effect

            events = []
            engine.assessment_event.connect(lambda t, m: events.append((t, m)))
            engine.scan_container_image("nginx:latest")

        assert any(e[0] == "image_scan_start" for e in events)
        assert any(e[0] == "image_scan_complete" for e in events)


# ===========================================================================
# Escape Guidance Tests
# ===========================================================================


class TestGetEscapeGuidance:
    """Tests for get_escape_guidance()."""

    def test_privileged_escape_guidance(self, engine):
        """Privileged containers get host filesystem mount escape guidance."""
        context = {
            "privileged": True,
            "docker_socket_mounted": False,
            "host_pid": False,
            "host_network": False,
            "capabilities": [],
            "mounts": [],
        }

        guidance = engine.get_escape_guidance(context)

        assert len(guidance) >= 1
        priv_technique = next(g for g in guidance if g["applicable_because"] == "privileged")
        assert "mount" in priv_technique["description"].lower() or "host" in priv_technique["description"].lower()
        assert len(priv_technique["commands"]) > 0

    def test_docker_socket_escape_guidance(self, engine):
        """Docker socket mounted gets socket escape guidance."""
        context = {
            "privileged": False,
            "docker_socket_mounted": True,
            "host_pid": False,
            "host_network": False,
            "capabilities": [],
            "mounts": ["/var/run/docker.sock"],
        }

        guidance = engine.get_escape_guidance(context)

        assert len(guidance) >= 1
        socket_technique = next(g for g in guidance if g["applicable_because"] == "docker_socket_mounted")
        assert "docker" in socket_technique["description"].lower()

    def test_host_pid_escape_guidance(self, engine):
        """Host PID namespace gets nsenter escape guidance."""
        context = {
            "privileged": False,
            "docker_socket_mounted": False,
            "host_pid": True,
            "host_network": False,
            "capabilities": [],
            "mounts": [],
        }

        guidance = engine.get_escape_guidance(context)

        assert len(guidance) >= 1
        pid_technique = next(g for g in guidance if g["applicable_because"] == "host_pid")
        assert "nsenter" in " ".join(pid_technique["commands"]).lower()

    def test_cap_sys_admin_escape_guidance(self, engine):
        """CAP_SYS_ADMIN gets cgroup escape guidance."""
        context = {
            "privileged": False,
            "docker_socket_mounted": False,
            "host_pid": False,
            "host_network": False,
            "capabilities": ["CAP_SYS_ADMIN"],
            "mounts": [],
        }

        guidance = engine.get_escape_guidance(context)

        assert len(guidance) >= 1
        cap_technique = next(g for g in guidance if g["applicable_because"] == "cap_sys_admin")
        assert "cgroup" in cap_technique["description"].lower() or "cgrp" in " ".join(cap_technique["commands"]).lower()

    def test_host_network_guidance(self, engine):
        """Host network namespace gets network exploitation guidance."""
        context = {
            "privileged": False,
            "docker_socket_mounted": False,
            "host_pid": False,
            "host_network": True,
            "capabilities": [],
            "mounts": [],
        }

        guidance = engine.get_escape_guidance(context)

        assert len(guidance) >= 1
        net_technique = next(g for g in guidance if g["applicable_because"] == "host_network")
        assert "network" in net_technique["description"].lower()

    def test_multiple_conditions_return_multiple_techniques(self, engine):
        """Multiple conditions produce multiple applicable techniques."""
        context = {
            "privileged": True,
            "docker_socket_mounted": True,
            "host_pid": True,
            "host_network": True,
            "capabilities": ["CAP_SYS_ADMIN"],
            "mounts": ["/var/run/docker.sock"],
        }

        guidance = engine.get_escape_guidance(context)

        # Should have at least one technique per condition
        assert len(guidance) >= 4
        conditions_found = {g["applicable_because"] for g in guidance}
        assert "privileged" in conditions_found
        assert "docker_socket_mounted" in conditions_found
        assert "host_pid" in conditions_found
        assert "host_network" in conditions_found
        assert "cap_sys_admin" in conditions_found

    def test_no_conditions_return_empty(self, engine):
        """Secure container context returns no escape guidance."""
        context = {
            "privileged": False,
            "docker_socket_mounted": False,
            "host_pid": False,
            "host_network": False,
            "capabilities": [],
            "mounts": [],
        }

        guidance = engine.get_escape_guidance(context)
        assert guidance == []

    def test_guidance_includes_mitre_reference(self, engine):
        """All guidance includes MITRE ATT&CK technique reference."""
        context = {"privileged": True, "docker_socket_mounted": False, "host_pid": False, "host_network": False, "capabilities": [], "mounts": []}

        guidance = engine.get_escape_guidance(context)

        for g in guidance:
            assert "mitre_technique" in g
            assert g["mitre_technique"].startswith("T")


# ===========================================================================
# Configuration Tests
# ===========================================================================


class TestConfiguration:
    """Tests for engine configuration methods."""

    def test_configure_docker_default(self, engine):
        """Default Docker configuration."""
        engine.configure_docker()
        assert engine._docker_base_url == "http://localhost:2375"
        assert engine._docker_tls_config is None

    def test_configure_docker_tls(self, engine):
        """Docker TLS configuration is stored."""
        engine.configure_docker(
            daemon_url="https://docker-host:2376",
            tls_cert="/path/cert.pem",
            tls_key="/path/key.pem",
            tls_ca="/path/ca.pem",
        )
        assert engine._docker_base_url == "https://docker-host:2376"
        assert engine._docker_tls_config is not None
        assert engine._docker_tls_config["cert"] == "/path/cert.pem"

    def test_configure_kubernetes(self, engine):
        """Kubernetes configuration is stored."""
        engine.configure_kubernetes(
            api_server="https://k8s.example.com:6443",
            token="my-token",
            ca_cert="/path/ca.crt",
        )
        assert engine._k8s_api_server == "https://k8s.example.com:6443"
        assert engine._k8s_token == "my-token"
        assert engine._k8s_ca_cert == "/path/ca.crt"

    def test_trailing_slash_stripped(self, engine):
        """Trailing slashes are stripped from URLs."""
        engine.configure_docker(daemon_url="http://host:2375/")
        assert engine._docker_base_url == "http://host:2375"

        engine.configure_kubernetes(api_server="https://k8s:6443/")
        assert engine._k8s_api_server == "https://k8s:6443"


# ===========================================================================
# CIS Benchmark Data Tests
# ===========================================================================


class TestCISBenchmarkData:
    """Tests for CIS Benchmark reference data."""

    def test_docker_checks_not_empty(self):
        """CIS Docker checks dict is populated."""
        assert len(CIS_DOCKER_CHECKS) > 0

    def test_k8s_checks_not_empty(self):
        """CIS K8s checks dict is populated."""
        assert len(CIS_K8S_CHECKS) > 0

    def test_all_findings_reference_valid_cis(self, engine):
        """All pattern CIS refs exist in the checks dicts."""
        all_refs = set(CIS_DOCKER_CHECKS.keys()) | set(CIS_K8S_CHECKS.keys())
        for pattern in RBAC_MISCONFIG_PATTERNS:
            assert pattern["cis_ref"] in all_refs

    def test_escape_techniques_have_required_fields(self):
        """All escape techniques have required fields."""
        for technique in ESCAPE_TECHNIQUES:
            assert "id" in technique
            assert "name" in technique
            assert "condition" in technique
            assert "description" in technique
            assert "commands" in technique
            assert "mitre_technique" in technique
            assert len(technique["commands"]) > 0
