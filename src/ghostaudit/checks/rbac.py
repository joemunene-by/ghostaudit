"""RBAC security checks."""

from __future__ import annotations

from ghostaudit.checks.base import BaseCheck, CheckInfo
from ghostaudit.client import KubeResources
from ghostaudit.models import Finding, Severity

# System accounts/namespaces that are expected to have cluster-admin
SYSTEM_PREFIXES = (
    "system:",
    "kube-system",
    "eks:",
    "gke-",
    "aks-",
)

SYSTEM_NAMESPACES = frozenset({
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "gatekeeper-system",
    "istio-system",
    "cert-manager",
})


class RBACCheck(BaseCheck):
    category = "rbac"

    @classmethod
    def list_checks(cls) -> list[CheckInfo]:
        return [
            CheckInfo(
                "RBAC-001",
                "Cluster-admin bound to non-system account",
                "ClusterRoleBindings that grant cluster-admin to non-system subjects",
                "rbac",
            ),
            CheckInfo(
                "RBAC-002",
                "Overly permissive role (wildcards)",
                "Roles or ClusterRoles with wildcard apiGroups, resources, or verbs",
                "rbac",
            ),
            CheckInfo(
                "RBAC-003",
                "ServiceAccount auto-mounts token",
                "ServiceAccounts with automountServiceAccountToken: true (or default)",
                "rbac",
            ),
            CheckInfo(
                "RBAC-004",
                "Workload in default namespace",
                "Pods running in the default namespace",
                "rbac",
            ),
        ]

    def check(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_cluster_admin_bindings(resources))
        findings.extend(self._check_wildcard_roles(resources))
        findings.extend(self._check_automount_token(resources))
        findings.extend(self._check_default_namespace(resources))
        return findings

    def _check_cluster_admin_bindings(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        for crb in resources.cluster_role_bindings:
            role_ref = crb.get("role_ref") or {}
            if role_ref.get("name") != "cluster-admin":
                continue

            subjects = crb.get("subjects") or []
            for subject in subjects:
                name = subject.get("name", "")
                ns = subject.get("namespace", "")
                kind = subject.get("kind", "")

                # Skip system accounts
                if any(name.startswith(p) for p in SYSTEM_PREFIXES):
                    continue
                if ns in SYSTEM_NAMESPACES:
                    continue

                binding_name = self._resource_name(crb)
                findings.append(Finding(
                    check_id="RBAC-001",
                    title="Cluster-admin bound to non-system account",
                    description=(
                        f"ClusterRoleBinding '{binding_name}' grants cluster-admin "
                        f"to {kind} '{name}'"
                        + (f" in namespace '{ns}'" if ns else "")
                        + ". This gives full control over the entire cluster."
                    ),
                    severity=Severity.CRITICAL,
                    resource_kind="ClusterRoleBinding",
                    resource_name=binding_name,
                    namespace="<cluster>",
                    remediation=(
                        "Remove the ClusterRoleBinding or replace cluster-admin with "
                        "a scoped Role/ClusterRole following the principle of least privilege. "
                        "Run: kubectl delete clusterrolebinding " + binding_name
                    ),
                ))
        return findings

    def _check_wildcard_roles(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []

        all_roles = [
            (r, "ClusterRole", "<cluster>") for r in resources.cluster_roles
        ] + [
            (r, "Role", self._resource_namespace(r)) for r in resources.roles
        ]

        for role, kind, ns in all_roles:
            name = self._resource_name(role)
            # Skip system roles
            if any(name.startswith(p) for p in SYSTEM_PREFIXES):
                continue

            rules = role.get("rules") or []
            for rule in rules:
                api_groups = rule.get("api_groups") or []
                resources_list = rule.get("resources") or []
                verbs = rule.get("verbs") or []

                wildcards = []
                if "*" in api_groups:
                    wildcards.append("apiGroups")
                if "*" in resources_list:
                    wildcards.append("resources")
                if "*" in verbs:
                    wildcards.append("verbs")

                if wildcards:
                    findings.append(Finding(
                        check_id="RBAC-002",
                        title="Overly permissive role (wildcards)",
                        description=(
                            f"{kind} '{name}' uses wildcards in: "
                            f"{', '.join(wildcards)}. "
                            "This grants broader permissions than typically needed."
                        ),
                        severity=Severity.HIGH,
                        resource_kind=kind,
                        resource_name=name,
                        namespace=ns,
                        remediation=(
                            "Replace wildcard ('*') with explicit apiGroups, resources, "
                            "and verbs. List only the specific permissions required. "
                            f"Run: kubectl edit {kind.lower()} {name}"
                            + (f" -n {ns}" if ns != "<cluster>" else "")
                        ),
                    ))
                    break  # One finding per role is enough

        return findings

    def _check_automount_token(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        for sa in resources.service_accounts:
            name = self._resource_name(sa)
            ns = self._resource_namespace(sa)

            # Skip system namespaces
            if ns in SYSTEM_NAMESPACES:
                continue

            automount = sa.get("automount_service_account_token")
            # Default is true if not explicitly set
            if automount is not False:
                findings.append(Finding(
                    check_id="RBAC-003",
                    title="ServiceAccount auto-mounts API token",
                    description=(
                        f"ServiceAccount '{name}' in namespace '{ns}' has "
                        "automountServiceAccountToken enabled (or default true). "
                        "Pods using this SA will have a token mounted that can "
                        "authenticate to the Kubernetes API."
                    ),
                    severity=Severity.MEDIUM,
                    resource_kind="ServiceAccount",
                    resource_name=name,
                    namespace=ns,
                    remediation=(
                        "Set automountServiceAccountToken: false on the ServiceAccount "
                        "unless the pod genuinely needs API access. "
                        f"Run: kubectl patch sa {name} -n {ns} "
                        "-p '{\"automountServiceAccountToken\": false}'"
                    ),
                ))
        return findings

    def _check_default_namespace(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        for pod in resources.pods:
            ns = self._resource_namespace(pod)
            if ns != "default":
                continue
            name = self._resource_name(pod)
            findings.append(Finding(
                check_id="RBAC-004",
                title="Workload running in default namespace",
                description=(
                    f"Pod '{name}' is running in the 'default' namespace. "
                    "The default namespace lacks RBAC restrictions and network "
                    "policies, making it a security risk for production workloads."
                ),
                severity=Severity.MEDIUM,
                resource_kind="Pod",
                resource_name=name,
                namespace="default",
                remediation=(
                    "Move workloads to a dedicated namespace with appropriate RBAC "
                    "and NetworkPolicy. Create a namespace and redeploy: "
                    "kubectl create namespace <app-name> && "
                    "kubectl apply -f deployment.yaml -n <app-name>"
                ),
            ))
        return findings
