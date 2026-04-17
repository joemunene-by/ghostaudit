"""Pod security checks based on CIS Kubernetes Benchmark."""

from __future__ import annotations

from typing import Any

from ghostaudit.checks.base import BaseCheck, CheckInfo
from ghostaudit.client import KubeResources
from ghostaudit.models import Finding, Severity

DANGEROUS_CAPABILITIES = frozenset({
    "SYS_ADMIN", "NET_RAW", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
    "DAC_OVERRIDE", "SETUID", "SETGID", "ALL",
})

SYSTEM_NAMESPACES = frozenset({
    "kube-system", "kube-public", "kube-node-lease",
})


class PodSecurityCheck(BaseCheck):
    category = "pods"

    @classmethod
    def list_checks(cls) -> list[CheckInfo]:
        return [
            CheckInfo(
                "POD-001", "Privileged container",
                "Container running in privileged mode", "pods",
            ),
            CheckInfo(
                "POD-002", "Container running as root",
                "runAsNonRoot not set to true", "pods",
            ),
            CheckInfo(
                "POD-003", "Missing security context",
                "Container has no securityContext defined", "pods",
            ),
            CheckInfo(
                "POD-004", "Host networking enabled",
                "Pod using hostNetwork, hostPID, or hostIPC", "pods",
            ),
            CheckInfo(
                "POD-005", "Writable root filesystem",
                "readOnlyRootFilesystem not set to true", "pods",
            ),
            CheckInfo(
                "POD-006", "Privilege escalation allowed",
                "allowPrivilegeEscalation not set to false", "pods",
            ),
            CheckInfo(
                "POD-007", "Dangerous capabilities",
                "Container has dangerous Linux capabilities", "pods",
            ),
        ]

    def check(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        for pod in resources.pods:
            ns = self._resource_namespace(pod)
            if ns in SYSTEM_NAMESPACES:
                continue
            pod_name = self._resource_name(pod)
            spec = pod.get("spec") or {}

            # Host namespace checks (POD-004) - pod level
            findings.extend(self._check_host_namespaces(spec, pod_name, ns))

            # Container-level checks
            containers = (spec.get("containers") or []) + (spec.get("init_containers") or [])
            for container in containers:
                cname = container.get("name", "<unnamed>")
                full_name = f"{pod_name}/{cname}"
                sc = container.get("security_context") or {}

                findings.extend(self._check_privileged(sc, full_name, ns))
                findings.extend(self._check_run_as_root(sc, spec, full_name, ns))
                findings.extend(self._check_missing_security_context(container, full_name, ns))
                findings.extend(self._check_readonly_rootfs(sc, full_name, ns))
                findings.extend(self._check_privilege_escalation(sc, full_name, ns))
                findings.extend(self._check_capabilities(sc, full_name, ns))

        return findings

    def _check_privileged(
        self, sc: dict[str, Any], name: str, ns: str
    ) -> list[Finding]:
        if sc.get("privileged") is True:
            return [Finding(
                check_id="POD-001",
                title="Privileged container",
                description=(
                    f"Container '{name}' in namespace '{ns}' is running in "
                    "privileged mode. This gives the container full access to "
                    "the host's devices, kernel modules, and bypasses most "
                    "security mechanisms."
                ),
                severity=Severity.CRITICAL,
                resource_kind="Pod",
                resource_name=name,
                namespace=ns,
                remediation=(
                    "Set spec.containers[].securityContext.privileged: false. "
                    "If the container needs specific host access, use capabilities "
                    "instead of full privileged mode."
                ),
            )]
        return []

    def _check_run_as_root(
        self, sc: dict[str, Any], pod_spec: dict[str, Any], name: str, ns: str
    ) -> list[Finding]:
        # Check container-level first, then pod-level security context
        container_run_as = sc.get("run_as_non_root")
        pod_sc = pod_spec.get("security_context") or {}
        pod_run_as = pod_sc.get("run_as_non_root")

        if container_run_as is True or pod_run_as is True:
            return []

        # Also accept explicit run_as_user != 0
        container_uid = sc.get("run_as_user")
        pod_uid = pod_sc.get("run_as_user")
        if (container_uid is not None and container_uid != 0) or \
           (pod_uid is not None and pod_uid != 0):
            return []

        return [Finding(
            check_id="POD-002",
            title="Container may run as root",
            description=(
                f"Container '{name}' in namespace '{ns}' does not have "
                "runAsNonRoot set to true. The container process may execute "
                "as UID 0 (root), increasing the blast radius of a compromise."
            ),
            severity=Severity.HIGH,
            resource_kind="Pod",
            resource_name=name,
            namespace=ns,
            remediation=(
                "Set spec.containers[].securityContext.runAsNonRoot: true and "
                "spec.containers[].securityContext.runAsUser to a non-zero UID. "
                "Ensure the container image supports running as non-root."
            ),
        )]

    def _check_missing_security_context(
        self, container: dict[str, Any], name: str, ns: str
    ) -> list[Finding]:
        sc = container.get("security_context")
        if sc is None or sc == {}:
            return [Finding(
                check_id="POD-003",
                title="Missing security context",
                description=(
                    f"Container '{name}' in namespace '{ns}' has no "
                    "securityContext defined. Without a security context, "
                    "containers run with default (often permissive) settings."
                ),
                severity=Severity.MEDIUM,
                resource_kind="Pod",
                resource_name=name,
                namespace=ns,
                remediation=(
                    "Add a securityContext to the container with at minimum: "
                    "runAsNonRoot: true, readOnlyRootFilesystem: true, "
                    "allowPrivilegeEscalation: false, and drop ALL capabilities."
                ),
            )]
        return []

    def _check_host_namespaces(
        self, pod_spec: dict[str, Any], name: str, ns: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        host_settings = []
        if pod_spec.get("host_network") is True:
            host_settings.append("hostNetwork")
        if pod_spec.get("host_pid") is True:
            host_settings.append("hostPID")
        if pod_spec.get("host_ipc") is True:
            host_settings.append("hostIPC")

        if host_settings:
            findings.append(Finding(
                check_id="POD-004",
                title="Host namespace sharing enabled",
                description=(
                    f"Pod '{name}' in namespace '{ns}' has "
                    f"{', '.join(host_settings)} enabled. This allows the pod "
                    "to access host-level resources, which can be exploited "
                    "for container escape or lateral movement."
                ),
                severity=Severity.HIGH,
                resource_kind="Pod",
                resource_name=name,
                namespace=ns,
                remediation=(
                    "Set spec.hostNetwork: false, spec.hostPID: false, and "
                    "spec.hostIPC: false unless absolutely required. Use "
                    "NetworkPolicies for network isolation instead."
                ),
            ))
        return findings

    def _check_readonly_rootfs(
        self, sc: dict[str, Any], name: str, ns: str
    ) -> list[Finding]:
        if sc.get("read_only_root_filesystem") is not True:
            return [Finding(
                check_id="POD-005",
                title="Writable root filesystem",
                description=(
                    f"Container '{name}' in namespace '{ns}' does not have "
                    "readOnlyRootFilesystem set to true. A writable filesystem "
                    "allows attackers to install tools or modify binaries "
                    "inside the container."
                ),
                severity=Severity.MEDIUM,
                resource_kind="Pod",
                resource_name=name,
                namespace=ns,
                remediation=(
                    "Set spec.containers[].securityContext.readOnlyRootFilesystem: true. "
                    "Use emptyDir volumes for paths that need to be writable "
                    "(e.g., /tmp, /var/run)."
                ),
            )]
        return []

    def _check_privilege_escalation(
        self, sc: dict[str, Any], name: str, ns: str
    ) -> list[Finding]:
        if sc.get("allow_privilege_escalation") is not False:
            return [Finding(
                check_id="POD-006",
                title="Privilege escalation allowed",
                description=(
                    f"Container '{name}' in namespace '{ns}' does not have "
                    "allowPrivilegeEscalation set to false. A child process "
                    "could gain more privileges than its parent via setuid "
                    "binaries or capabilities."
                ),
                severity=Severity.MEDIUM,
                resource_kind="Pod",
                resource_name=name,
                namespace=ns,
                remediation=(
                    "Set spec.containers[].securityContext.allowPrivilegeEscalation: false. "
                    "This prevents child processes from gaining additional privileges."
                ),
            )]
        return []

    def _check_capabilities(
        self, sc: dict[str, Any], name: str, ns: str
    ) -> list[Finding]:
        caps = sc.get("capabilities") or {}
        add = caps.get("add") or []
        dangerous = [c for c in add if c.upper() in DANGEROUS_CAPABILITIES]

        if dangerous:
            return [Finding(
                check_id="POD-007",
                title="Dangerous capabilities added",
                description=(
                    f"Container '{name}' in namespace '{ns}' adds dangerous "
                    f"Linux capabilities: {', '.join(dangerous)}. These "
                    "capabilities can be used for privilege escalation or "
                    "container escape."
                ),
                severity=Severity.HIGH,
                resource_kind="Pod",
                resource_name=name,
                namespace=ns,
                remediation=(
                    "Remove dangerous capabilities from "
                    "securityContext.capabilities.add. "
                    "Drop ALL capabilities and only add back the minimum "
                    "required:\n"
                    "securityContext:\n  capabilities:\n"
                    "    drop: [\"ALL\"]\n    add: [<only-what-is-needed>]"
                ),
            )]
        return []
