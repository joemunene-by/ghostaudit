"""Secrets and ConfigMap security checks."""

from __future__ import annotations

import re

from ghostaudit.checks.base import BaseCheck, CheckInfo
from ghostaudit.client import KubeResources
from ghostaudit.models import Finding, Severity

SENSITIVE_KEY_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)"),
    re.compile(r"(?i)(secret|token|api[_-]?key)"),
    re.compile(r"(?i)(private[_-]?key|credentials?)"),
    re.compile(r"(?i)(connection[_-]?string|database[_-]?url)"),
]

SYSTEM_NAMESPACES = frozenset({
    "kube-system", "kube-public", "kube-node-lease",
})


class SecretsConfigCheck(BaseCheck):
    category = "secrets"

    @classmethod
    def list_checks(cls) -> list[CheckInfo]:
        return [
            CheckInfo(
                "SEC-001",
                "Secret exposed as environment variable",
                "Secrets mounted as env vars instead of volume mounts",
                "secrets",
            ),
            CheckInfo(
                "SEC-002",
                "ConfigMap contains sensitive-looking keys",
                "ConfigMaps with keys matching sensitive patterns (password, token, etc.)",
                "secrets",
            ),
            CheckInfo(
                "SEC-003",
                "Secret in default namespace",
                "Secrets stored in the default namespace",
                "secrets",
            ),
        ]

    def check(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_secret_env_vars(resources))
        findings.extend(self._check_configmap_sensitive_keys(resources))
        findings.extend(self._check_default_namespace_secrets(resources))
        return findings

    def _check_secret_env_vars(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        for pod in resources.pods:
            ns = self._resource_namespace(pod)
            if ns in SYSTEM_NAMESPACES:
                continue
            pod_name = self._resource_name(pod)
            spec = pod.get("spec") or {}
            containers = (spec.get("containers") or []) + (spec.get("init_containers") or [])

            for container in containers:
                cname = container.get("name", "<unnamed>")
                env_list = container.get("env") or []
                secret_refs = []

                for env_var in env_list:
                    value_from = env_var.get("value_from") or {}
                    secret_ref = value_from.get("secret_key_ref")
                    if secret_ref:
                        secret_name = secret_ref.get("name", "<unknown>")
                        key = secret_ref.get("key", "<unknown>")
                        secret_refs.append(f"{secret_name}.{key}")

                # Also check envFrom
                env_from = container.get("env_from") or []
                for ef in env_from:
                    secret_ref = ef.get("secret_ref")
                    if secret_ref:
                        secret_refs.append(secret_ref.get("name", "<unknown>"))

                if secret_refs:
                    full_name = f"{pod_name}/{cname}"
                    findings.append(Finding(
                        check_id="SEC-001",
                        title="Secret exposed as environment variable",
                        description=(
                            f"Container '{full_name}' in namespace '{ns}' mounts "
                            f"secrets as environment variables: {', '.join(secret_refs)}. "
                            "Environment variables can be leaked via process listings, "
                            "logs, error reports, and child processes."
                        ),
                        severity=Severity.MEDIUM,
                        resource_kind="Pod",
                        resource_name=full_name,
                        namespace=ns,
                        remediation=(
                            "Mount secrets as volumes instead of environment variables. "
                            "Use spec.volumes[].secret.secretName and "
                            "spec.containers[].volumeMounts[] to mount the secret as a file."
                        ),
                    ))
        return findings

    def _check_configmap_sensitive_keys(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        for cm in resources.config_maps:
            ns = self._resource_namespace(cm)
            if ns in SYSTEM_NAMESPACES:
                continue
            name = self._resource_name(cm)
            data = cm.get("data") or {}
            sensitive_keys = []

            for key in data:
                for pattern in SENSITIVE_KEY_PATTERNS:
                    if pattern.search(key):
                        sensitive_keys.append(key)
                        break

            if sensitive_keys:
                findings.append(Finding(
                    check_id="SEC-002",
                    title="ConfigMap contains sensitive-looking keys",
                    description=(
                        f"ConfigMap '{name}' in namespace '{ns}' contains keys "
                        f"that appear sensitive: {', '.join(sensitive_keys)}. "
                        "ConfigMaps are not encrypted and are visible to anyone "
                        "with read access to the namespace."
                    ),
                    severity=Severity.HIGH,
                    resource_kind="ConfigMap",
                    resource_name=name,
                    namespace=ns,
                    remediation=(
                        "Move sensitive values to Kubernetes Secrets (or an external "
                        "secrets manager like Vault, AWS Secrets Manager, etc.). "
                        "ConfigMaps should only contain non-sensitive configuration."
                    ),
                ))
        return findings

    def _check_default_namespace_secrets(self, resources: KubeResources) -> list[Finding]:
        findings: list[Finding] = []
        for secret in resources.secrets:
            ns = self._resource_namespace(secret)
            if ns != "default":
                continue
            name = self._resource_name(secret)
            secret_type = secret.get("type", "")
            # Skip the default SA token
            if secret_type == "kubernetes.io/service-account-token":
                continue
            findings.append(Finding(
                check_id="SEC-003",
                title="Secret in default namespace",
                description=(
                    f"Secret '{name}' (type: {secret_type}) exists in the "
                    "'default' namespace. The default namespace often has "
                    "broader access and less restrictive RBAC policies."
                ),
                severity=Severity.LOW,
                resource_kind="Secret",
                resource_name=name,
                namespace="default",
                remediation=(
                    "Move secrets to a dedicated namespace with appropriate RBAC. "
                    "Recreate the secret in the target namespace: "
                    f"kubectl get secret {name} -o yaml | "
                    "sed 's/namespace: default/namespace: <target>/' | kubectl apply -f -"
                ),
            ))
        return findings
