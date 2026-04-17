"""Shared fixtures providing sample Kubernetes resource dicts for testing."""

from __future__ import annotations

import pytest

from ghostaudit.client import KubeResources

# ---------------------------------------------------------------------------
# Pod fixtures
# ---------------------------------------------------------------------------

def make_pod(
    name: str = "test-pod",
    namespace: str = "default",
    containers: list[dict] | None = None,
    init_containers: list[dict] | None = None,
    host_network: bool = False,
    host_pid: bool = False,
    host_ipc: bool = False,
    pod_security_context: dict | None = None,
) -> dict:
    """Helper to build a pod resource dict."""
    if containers is None:
        containers = [make_container()]
    spec: dict = {
        "containers": containers,
        "host_network": host_network,
        "host_pid": host_pid,
        "host_ipc": host_ipc,
    }
    if init_containers:
        spec["init_containers"] = init_containers
    if pod_security_context:
        spec["security_context"] = pod_security_context
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


def make_container(
    name: str = "app",
    image: str = "nginx:1.25.3",
    security_context: dict | None = None,
    resources: dict | None = None,
    env: list[dict] | None = None,
    env_from: list[dict] | None = None,
    image_pull_policy: str = "IfNotPresent",
) -> dict:
    c: dict = {"name": name, "image": image, "image_pull_policy": image_pull_policy}
    if security_context is not None:
        c["security_context"] = security_context
    if resources is not None:
        c["resources"] = resources
    if env is not None:
        c["env"] = env
    if env_from is not None:
        c["env_from"] = env_from
    return c


# ---------------------------------------------------------------------------
# RBAC fixtures
# ---------------------------------------------------------------------------

def make_cluster_role_binding(
    name: str = "test-crb",
    role_name: str = "cluster-admin",
    subjects: list[dict] | None = None,
) -> dict:
    if subjects is None:
        subjects = [{"kind": "User", "name": "admin-user", "namespace": ""}]
    return {
        "metadata": {"name": name},
        "role_ref": {
            "api_group": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": role_name,
        },
        "subjects": subjects,
    }


def make_cluster_role(
    name: str = "test-role",
    rules: list[dict] | None = None,
) -> dict:
    if rules is None:
        rules = [{"api_groups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]
    return {
        "metadata": {"name": name},
        "rules": rules,
    }


def make_role(
    name: str = "test-role",
    namespace: str = "default",
    rules: list[dict] | None = None,
) -> dict:
    if rules is None:
        rules = [{"api_groups": [""], "resources": ["pods"], "verbs": ["get"]}]
    return {
        "metadata": {"name": name, "namespace": namespace},
        "rules": rules,
    }


def make_service_account(
    name: str = "default",
    namespace: str = "default",
    automount: bool | None = None,
) -> dict:
    sa: dict = {"metadata": {"name": name, "namespace": namespace}}
    if automount is not None:
        sa["automount_service_account_token"] = automount
    return sa


# ---------------------------------------------------------------------------
# Network fixtures
# ---------------------------------------------------------------------------

def make_namespace(name: str = "default") -> dict:
    return {"metadata": {"name": name}}


def make_service(
    name: str = "test-svc",
    namespace: str = "default",
    svc_type: str = "ClusterIP",
    ports: list[dict] | None = None,
    annotations: dict | None = None,
) -> dict:
    if ports is None:
        ports = [{"port": 80, "target_port": 8080}]
    meta: dict = {"name": name, "namespace": namespace}
    if annotations:
        meta["annotations"] = annotations
    return {
        "metadata": meta,
        "spec": {"type": svc_type, "ports": ports},
    }


def make_network_policy(
    name: str = "default-deny",
    namespace: str = "default",
) -> dict:
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"pod_selector": {}, "policy_types": ["Ingress", "Egress"]},
    }


# ---------------------------------------------------------------------------
# Secrets & ConfigMaps
# ---------------------------------------------------------------------------

def make_secret(
    name: str = "test-secret",
    namespace: str = "default",
    secret_type: str = "Opaque",
) -> dict:
    return {
        "metadata": {"name": name, "namespace": namespace},
        "type": secret_type,
        "data": {},
    }


def make_config_map(
    name: str = "test-cm",
    namespace: str = "default",
    data: dict | None = None,
) -> dict:
    return {
        "metadata": {"name": name, "namespace": namespace},
        "data": data or {},
    }


# ---------------------------------------------------------------------------
# Deployment fixtures
# ---------------------------------------------------------------------------

def make_deployment(
    name: str = "test-deploy",
    namespace: str = "default",
    replicas: int = 1,
    match_labels: dict | None = None,
) -> dict:
    if match_labels is None:
        match_labels = {"app": name}
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "replicas": replicas,
            "selector": {"match_labels": match_labels},
        },
    }


def make_pdb(
    name: str = "test-pdb",
    namespace: str = "default",
    match_labels: dict | None = None,
) -> dict:
    if match_labels is None:
        match_labels = {"app": "test-deploy"}
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "min_available": 1,
            "selector": {"match_labels": match_labels},
        },
    }


# ---------------------------------------------------------------------------
# Composite resource fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def empty_resources() -> KubeResources:
    """A KubeResources with no items at all."""
    return KubeResources()


@pytest.fixture
def basic_resources() -> KubeResources:
    """A KubeResources with a mix of well-configured and misconfigured resources."""
    return KubeResources(
        pods=[
            # Well-configured pod
            make_pod(
                name="good-pod",
                namespace="production",
                containers=[make_container(
                    name="app",
                    image="myregistry.com/app@sha256:abc123",
                    security_context={
                        "run_as_non_root": True,
                        "read_only_root_filesystem": True,
                        "allow_privilege_escalation": False,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    resources={
                        "limits": {"cpu": "500m", "memory": "256Mi"},
                        "requests": {"cpu": "100m", "memory": "128Mi"},
                    },
                    image_pull_policy="Always",
                )],
            ),
            # Badly configured pod
            make_pod(
                name="bad-pod",
                namespace="default",
                containers=[make_container(
                    name="app",
                    image="nginx:latest",
                    security_context={"privileged": True},
                )],
                host_network=True,
            ),
        ],
        namespaces=[
            make_namespace("default"),
            make_namespace("production"),
        ],
        cluster_role_bindings=[
            make_cluster_role_binding(
                name="admin-binding",
                role_name="cluster-admin",
                subjects=[{"kind": "User", "name": "dev-user", "namespace": ""}],
            ),
        ],
        cluster_roles=[
            make_cluster_role(name="wildcard-role", rules=[
                {"api_groups": ["*"], "resources": ["*"], "verbs": ["*"]},
            ]),
        ],
        roles=[],
        role_bindings=[],
        service_accounts=[
            make_service_account("default", "default"),
        ],
        services=[
            make_service("web", "default", svc_type="LoadBalancer"),
        ],
        secrets=[
            make_secret("app-secret", "default"),
        ],
        config_maps=[
            make_config_map("app-config", "default", data={"DATABASE_PASSWORD": "hunter2"}),
        ],
        network_policies=[],
        deployments=[
            make_deployment("web-app", "default", replicas=3),
        ],
        pod_disruption_budgets=[],
    )
