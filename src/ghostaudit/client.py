"""Kubernetes API client wrapper."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kubernetes import client, config


@dataclass
class KubeResources:
    """Pre-loaded Kubernetes resources for scanning.

    Each field holds a list of resource dicts (the .to_dict() representation
    from the kubernetes client, or raw dicts for testing).
    """

    pods: list[dict[str, Any]] = field(default_factory=list)
    deployments: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    namespaces: list[dict[str, Any]] = field(default_factory=list)
    cluster_role_bindings: list[dict[str, Any]] = field(default_factory=list)
    cluster_roles: list[dict[str, Any]] = field(default_factory=list)
    role_bindings: list[dict[str, Any]] = field(default_factory=list)
    roles: list[dict[str, Any]] = field(default_factory=list)
    service_accounts: list[dict[str, Any]] = field(default_factory=list)
    secrets: list[dict[str, Any]] = field(default_factory=list)
    config_maps: list[dict[str, Any]] = field(default_factory=list)
    network_policies: list[dict[str, Any]] = field(default_factory=list)
    pod_disruption_budgets: list[dict[str, Any]] = field(default_factory=list)


def _to_dict_list(items: Any) -> list[dict]:
    """Convert a kubernetes client list response to a list of dicts."""
    if items is None or items.items is None:
        return []
    result = []
    for item in items.items:
        if hasattr(item, "to_dict"):
            result.append(item.to_dict())
        else:
            result.append(item)
    return result


class KubeClient:
    """Wrapper around the kubernetes python client for fetching resources."""

    def __init__(self, kubeconfig: str | None = None) -> None:
        if kubeconfig:
            config.load_kube_config(config_file=kubeconfig)
        else:
            try:
                config.load_incluster_config()
            except config.ConfigException:
                config.load_kube_config()

        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()
        self.networking_v1 = client.NetworkingV1Api()
        self.policy_v1 = client.PolicyV1Api()

        # Determine cluster name
        _, active_context = config.list_kube_config_contexts()
        self.cluster_name = active_context.get("context", {}).get(
            "cluster", active_context.get("name", "unknown")
        )

    def fetch_resources(self, namespace: str | None = None) -> KubeResources:
        """Fetch all resources needed for scanning."""
        resources = KubeResources()

        if namespace:
            resources.pods = _to_dict_list(
                self.core_v1.list_namespaced_pod(namespace)
            )
            resources.deployments = _to_dict_list(
                self.apps_v1.list_namespaced_deployment(namespace)
            )
            resources.services = _to_dict_list(
                self.core_v1.list_namespaced_service(namespace)
            )
            resources.service_accounts = _to_dict_list(
                self.core_v1.list_namespaced_service_account(namespace)
            )
            resources.secrets = _to_dict_list(
                self.core_v1.list_namespaced_secret(namespace)
            )
            resources.config_maps = _to_dict_list(
                self.core_v1.list_namespaced_config_map(namespace)
            )
            resources.network_policies = _to_dict_list(
                self.networking_v1.list_namespaced_network_policy(namespace)
            )
            resources.role_bindings = _to_dict_list(
                self.rbac_v1.list_namespaced_role_binding(namespace)
            )
            resources.roles = _to_dict_list(
                self.rbac_v1.list_namespaced_role(namespace)
            )
            resources.pod_disruption_budgets = _to_dict_list(
                self.policy_v1.list_namespaced_pod_disruption_budget(namespace)
            )
            resources.namespaces = [
                self.core_v1.read_namespace(namespace).to_dict()
            ]
        else:
            resources.pods = _to_dict_list(
                self.core_v1.list_pod_for_all_namespaces()
            )
            resources.deployments = _to_dict_list(
                self.apps_v1.list_deployment_for_all_namespaces()
            )
            resources.services = _to_dict_list(
                self.core_v1.list_service_for_all_namespaces()
            )
            resources.service_accounts = _to_dict_list(
                self.core_v1.list_service_account_for_all_namespaces()
            )
            resources.secrets = _to_dict_list(
                self.core_v1.list_secret_for_all_namespaces()
            )
            resources.config_maps = _to_dict_list(
                self.core_v1.list_config_map_for_all_namespaces()
            )
            resources.network_policies = _to_dict_list(
                self.networking_v1.list_network_policy_for_all_namespaces()
            )
            resources.namespaces = _to_dict_list(
                self.core_v1.list_namespace()
            )
            resources.role_bindings = _to_dict_list(
                self.rbac_v1.list_role_binding_for_all_namespaces()
            )
            resources.roles = _to_dict_list(
                self.rbac_v1.list_role_for_all_namespaces()
            )
            resources.pod_disruption_budgets = _to_dict_list(
                self.policy_v1.list_pod_disruption_budget_for_all_namespaces()
            )

        # Cluster-scoped resources (always fetched)
        resources.cluster_role_bindings = _to_dict_list(
            self.rbac_v1.list_cluster_role_binding()
        )
        resources.cluster_roles = _to_dict_list(
            self.rbac_v1.list_cluster_role()
        )

        return resources

    def get_namespaces(self, namespace: str | None = None) -> list[str]:
        """Return list of namespace names being scanned."""
        if namespace:
            return [namespace]
        ns_list = self.core_v1.list_namespace()
        return [ns.metadata.name for ns in ns_list.items]
