"""Resource management checks."""

from __future__ import annotations

from ghostaudit.checks.base import BaseCheck, CheckInfo
from ghostaudit.client import KubeResources
from ghostaudit.models import Finding, Severity

SYSTEM_NAMESPACES = frozenset({
    "kube-system", "kube-public", "kube-node-lease",
})


class ResourceManagementCheck(BaseCheck):
    category = "resources"

    @classmethod
    def list_checks(cls) -> list[CheckInfo]:
        return [
            CheckInfo(
                "RES-001",
                "Container without resource limits",
                "Containers missing CPU or memory limits",
                "resources",
            ),
            CheckInfo(
                "RES-002",
                "Container without resource requests",
                "Containers missing CPU or memory requests",
                "resources",
            ),
            CheckInfo(
                "RES-003",
                "No PodDisruptionBudget for scaled deployment",
                "Deployments with >1 replica but no PodDisruptionBudget",
                "resources",
            ),
        ]

    def check(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_missing_limits(resources))
        findings.extend(self._check_missing_requests(resources))
        findings.extend(self._check_missing_pdb(resources))
        return findings

    def _check_missing_limits(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        for pod in resources.pods:
            ns = self._resource_namespace(pod)
            if ns in SYSTEM_NAMESPACES:
                continue
            pod_name = self._resource_name(pod)
            spec = pod.get("spec") or {}
            containers = spec.get("containers") or []

            for container in containers:
                cname = container.get("name", "<unnamed>")
                res = container.get("resources") or {}
                limits = res.get("limits") or {}
                missing = []
                if "cpu" not in limits:
                    missing.append("cpu")
                if "memory" not in limits:
                    missing.append("memory")

                if missing:
                    full_name = f"{pod_name}/{cname}"
                    findings.append(Finding(
                        check_id="RES-001",
                        title="Container without resource limits",
                        description=(
                            f"Container '{full_name}' in namespace '{ns}' is "
                            f"missing resource limits for: {', '.join(missing)}. "
                            "Without limits, a container can consume unbounded "
                            "resources, potentially starving other workloads or "
                            "causing node instability."
                        ),
                        severity=Severity.MEDIUM,
                        resource_kind="Pod",
                        resource_name=full_name,
                        namespace=ns,
                        remediation=(
                            "Set spec.containers[].resources.limits with appropriate "
                            "CPU and memory values:\n"
                            "resources:\n  limits:\n    cpu: \"500m\"\n    memory: \"256Mi\""
                        ),
                    ))
        return findings

    def _check_missing_requests(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        for pod in resources.pods:
            ns = self._resource_namespace(pod)
            if ns in SYSTEM_NAMESPACES:
                continue
            pod_name = self._resource_name(pod)
            spec = pod.get("spec") or {}
            containers = spec.get("containers") or []

            for container in containers:
                cname = container.get("name", "<unnamed>")
                res = container.get("resources") or {}
                requests = res.get("requests") or {}
                missing = []
                if "cpu" not in requests:
                    missing.append("cpu")
                if "memory" not in requests:
                    missing.append("memory")

                if missing:
                    full_name = f"{pod_name}/{cname}"
                    findings.append(Finding(
                        check_id="RES-002",
                        title="Container without resource requests",
                        description=(
                            f"Container '{full_name}' in namespace '{ns}' is "
                            f"missing resource requests for: {', '.join(missing)}. "
                            "Without requests, the Kubernetes scheduler cannot "
                            "make informed placement decisions, which can lead "
                            "to resource contention."
                        ),
                        severity=Severity.LOW,
                        resource_kind="Pod",
                        resource_name=full_name,
                        namespace=ns,
                        remediation=(
                            "Set spec.containers[].resources.requests with appropriate "
                            "CPU and memory values:\n"
                            "resources:\n  requests:\n    cpu: \"100m\"\n    memory: \"128Mi\""
                        ),
                    ))
        return findings

    def _check_missing_pdb(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []

        # Build a set of (namespace, label-selector) tuples covered by PDBs
        pdb_selectors: set[tuple[str, str]] = set()
        for pdb in resources.pod_disruption_budgets:
            ns = self._resource_namespace(pdb)
            spec = pdb.get("spec") or {}
            selector = spec.get("selector") or {}
            match_labels = selector.get("match_labels") or {}
            # Store as a frozenset string for comparison
            label_key = str(sorted(match_labels.items()))
            pdb_selectors.add((ns, label_key))

        for deploy in resources.deployments:
            ns = self._resource_namespace(deploy)
            if ns in SYSTEM_NAMESPACES:
                continue
            name = self._resource_name(deploy)
            spec = deploy.get("spec") or {}
            replicas = spec.get("replicas", 1)

            if replicas is not None and replicas > 1:
                # Check if there is a matching PDB
                selector = spec.get("selector") or {}
                match_labels = selector.get("match_labels") or {}
                label_key = str(sorted(match_labels.items()))

                if (ns, label_key) not in pdb_selectors:
                    findings.append(Finding(
                        check_id="RES-003",
                        title="No PodDisruptionBudget for scaled deployment",
                        description=(
                            f"Deployment '{name}' in namespace '{ns}' has "
                            f"{replicas} replicas but no matching PodDisruptionBudget. "
                            "Without a PDB, all pods can be evicted simultaneously "
                            "during node maintenance or cluster autoscaling."
                        ),
                        severity=Severity.LOW,
                        resource_kind="Deployment",
                        resource_name=name,
                        namespace=ns,
                        remediation=(
                            "Create a PodDisruptionBudget:\n"
                            "apiVersion: policy/v1\nkind: PodDisruptionBudget\n"
                            f"metadata:\n  name: {name}-pdb\n  namespace: {ns}\n"
                            "spec:\n  minAvailable: 1\n  selector:\n    matchLabels:\n"
                            f"      app: {name}"
                        ),
                    ))
        return findings
