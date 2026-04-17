"""Network security checks."""

from __future__ import annotations

from ghostaudit.checks.base import BaseCheck, CheckInfo
from ghostaudit.client import KubeResources
from ghostaudit.models import Finding, Severity

SYSTEM_NAMESPACES = frozenset({
    "kube-system", "kube-public", "kube-node-lease",
})


class NetworkCheck(BaseCheck):
    category = "network"

    @classmethod
    def list_checks(cls) -> list[CheckInfo]:
        return [
            CheckInfo(
                "NET-001",
                "Namespace without NetworkPolicy",
                "Namespaces that have no NetworkPolicy defined, allowing unrestricted traffic",
                "network",
            ),
            CheckInfo(
                "NET-002",
                "Service exposed via LoadBalancer or NodePort",
                "Services using type LoadBalancer or NodePort that are externally reachable",
                "network",
            ),
            CheckInfo(
                "NET-003",
                "External service without annotation",
                "LoadBalancer/NodePort services missing documentation annotations",
                "network",
            ),
        ]

    def check(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_missing_network_policies(resources))
        findings.extend(self._check_exposed_services(resources))
        findings.extend(self._check_unannotated_external_services(resources))
        return findings

    def _check_missing_network_policies(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []

        # Build set of namespaces that have at least one NetworkPolicy
        ns_with_policies: set[str] = set()
        for np in resources.network_policies:
            ns = self._resource_namespace(np)
            ns_with_policies.add(ns)

        for ns_obj in resources.namespaces:
            ns_name = self._resource_name(ns_obj)
            if ns_name in SYSTEM_NAMESPACES:
                continue
            if ns_name not in ns_with_policies:
                findings.append(Finding(
                    check_id="NET-001",
                    title="Namespace without NetworkPolicy",
                    description=(
                        f"Namespace '{ns_name}' has no NetworkPolicy defined. "
                        "Without network policies, all pods in this namespace "
                        "can communicate with any other pod in the cluster, "
                        "violating the principle of least privilege for network access."
                    ),
                    severity=Severity.HIGH,
                    resource_kind="Namespace",
                    resource_name=ns_name,
                    namespace=ns_name,
                    remediation=(
                        "Create a default-deny NetworkPolicy for the namespace, "
                        "then add specific allow rules:\n"
                        "apiVersion: networking.k8s.io/v1\n"
                        "kind: NetworkPolicy\n"
                        "metadata:\n"
                        f"  name: default-deny\n  namespace: {ns_name}\n"
                        "spec:\n  podSelector: {}\n  policyTypes:\n"
                        "  - Ingress\n  - Egress"
                    ),
                ))
        return findings

    def _check_exposed_services(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        for svc in resources.services:
            ns = self._resource_namespace(svc)
            if ns in SYSTEM_NAMESPACES:
                continue
            name = self._resource_name(svc)
            spec = svc.get("spec") or {}
            svc_type = spec.get("type", "ClusterIP")

            if svc_type in ("LoadBalancer", "NodePort"):
                ports = spec.get("ports") or []
                port_info = ", ".join(
                    f"{p.get('port', '?')}"
                    + (f":{p.get('node_port', '?')}" if svc_type == "NodePort" else "")
                    for p in ports
                )
                findings.append(Finding(
                    check_id="NET-002",
                    title=f"Service exposed via {svc_type}",
                    description=(
                        f"Service '{name}' in namespace '{ns}' is of type "
                        f"{svc_type} (ports: {port_info}). This makes the "
                        "service reachable from outside the cluster, increasing "
                        "the attack surface."
                    ),
                    severity=Severity.MEDIUM,
                    resource_kind="Service",
                    resource_name=name,
                    namespace=ns,
                    remediation=(
                        "Consider using ClusterIP with an Ingress controller instead of "
                        f"{svc_type}. If external access is required, ensure the service "
                        "is protected by network-level firewall rules and has proper "
                        "authentication. Add annotation 'ghostaudit.io/external-approved: true' "
                        "to acknowledge this exposure."
                    ),
                ))
        return findings

    def _check_unannotated_external_services(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        for svc in resources.services:
            ns = self._resource_namespace(svc)
            if ns in SYSTEM_NAMESPACES:
                continue
            name = self._resource_name(svc)
            spec = svc.get("spec") or {}
            svc_type = spec.get("type", "ClusterIP")

            if svc_type not in ("LoadBalancer", "NodePort"):
                continue

            meta = svc.get("metadata") or {}
            annotations = meta.get("annotations") or {}

            # Check for common approval/documentation annotations
            has_approval = any(
                key in annotations
                for key in [
                    "ghostaudit.io/external-approved",
                    "external-dns.alpha.kubernetes.io/hostname",
                    "service.beta.kubernetes.io/aws-load-balancer-internal",
                ]
            )

            if not has_approval:
                findings.append(Finding(
                    check_id="NET-003",
                    title="External service without documentation annotation",
                    description=(
                        f"Service '{name}' in namespace '{ns}' is externally "
                        f"exposed ({svc_type}) but lacks documentation annotations "
                        "explaining why external access is needed."
                    ),
                    severity=Severity.LOW,
                    resource_kind="Service",
                    resource_name=name,
                    namespace=ns,
                    remediation=(
                        "Add an annotation to document the external exposure: "
                        f"kubectl annotate svc {name} -n {ns} "
                        "ghostaudit.io/external-approved=true "
                        "ghostaudit.io/external-reason='<reason>'"
                    ),
                ))
        return findings
