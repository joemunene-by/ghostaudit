"""Tests for RBAC security checks."""

from __future__ import annotations

import pytest

from ghostaudit.checks.rbac import RBACCheck
from ghostaudit.client import KubeResources
from ghostaudit.models import Severity
from tests.conftest import (
    make_cluster_role,
    make_cluster_role_binding,
    make_container,
    make_pod,
    make_role,
    make_service_account,
)


@pytest.fixture
def checker() -> RBACCheck:
    return RBACCheck()


class TestClusterAdminBindings:
    def test_non_system_cluster_admin_detected(self, checker: RBACCheck) -> None:
        resources = KubeResources(cluster_role_bindings=[
            make_cluster_role_binding(
                name="dev-admin",
                role_name="cluster-admin",
                subjects=[{"kind": "User", "name": "dev-user", "namespace": ""}],
            ),
        ])
        findings = checker.check(resources)
        admin = [f for f in findings if f.check_id == "RBAC-001"]
        assert len(admin) == 1
        assert admin[0].severity == Severity.CRITICAL
        assert "dev-user" in admin[0].description

    def test_system_account_skipped(self, checker: RBACCheck) -> None:
        resources = KubeResources(cluster_role_bindings=[
            make_cluster_role_binding(
                name="system-binding",
                role_name="cluster-admin",
                subjects=[{
                    "kind": "User",
                    "name": "system:kube-controller-manager",
                    "namespace": "",
                }],
            ),
        ])
        findings = checker.check(resources)
        admin = [f for f in findings if f.check_id == "RBAC-001"]
        assert len(admin) == 0

    def test_kube_system_namespace_skipped(self, checker: RBACCheck) -> None:
        resources = KubeResources(cluster_role_bindings=[
            make_cluster_role_binding(
                name="sys-binding",
                role_name="cluster-admin",
                subjects=[{
                    "kind": "ServiceAccount",
                    "name": "some-sa",
                    "namespace": "kube-system",
                }],
            ),
        ])
        findings = checker.check(resources)
        admin = [f for f in findings if f.check_id == "RBAC-001"]
        assert len(admin) == 0

    def test_non_admin_role_ignored(self, checker: RBACCheck) -> None:
        resources = KubeResources(cluster_role_bindings=[
            make_cluster_role_binding(
                name="readonly-binding",
                role_name="view",
                subjects=[{"kind": "User", "name": "dev-user", "namespace": ""}],
            ),
        ])
        findings = checker.check(resources)
        admin = [f for f in findings if f.check_id == "RBAC-001"]
        assert len(admin) == 0


class TestWildcardRoles:
    def test_wildcard_cluster_role_detected(self, checker: RBACCheck) -> None:
        resources = KubeResources(cluster_roles=[
            make_cluster_role(
                name="super-role",
                rules=[{"api_groups": ["*"], "resources": ["*"], "verbs": ["*"]}],
            ),
        ])
        findings = checker.check(resources)
        wild = [f for f in findings if f.check_id == "RBAC-002"]
        assert len(wild) == 1
        assert wild[0].severity == Severity.HIGH
        assert "apiGroups" in wild[0].description

    def test_specific_permissions_pass(self, checker: RBACCheck) -> None:
        resources = KubeResources(cluster_roles=[
            make_cluster_role(
                name="reader-role",
                rules=[{"api_groups": [""], "resources": ["pods"], "verbs": ["get", "list"]}],
            ),
        ])
        findings = checker.check(resources)
        wild = [f for f in findings if f.check_id == "RBAC-002"]
        assert len(wild) == 0

    def test_wildcard_in_namespaced_role(self, checker: RBACCheck) -> None:
        resources = KubeResources(roles=[
            make_role(
                name="wide-role",
                namespace="default",
                rules=[{"api_groups": [""], "resources": ["*"], "verbs": ["get"]}],
            ),
        ])
        findings = checker.check(resources)
        wild = [f for f in findings if f.check_id == "RBAC-002"]
        assert len(wild) == 1
        assert wild[0].resource_kind == "Role"


class TestAutoMountToken:
    def test_automount_default_detected(self, checker: RBACCheck) -> None:
        resources = KubeResources(service_accounts=[
            make_service_account("default", "production"),
        ])
        findings = checker.check(resources)
        auto = [f for f in findings if f.check_id == "RBAC-003"]
        assert len(auto) == 1
        assert auto[0].severity == Severity.MEDIUM

    def test_automount_false_passes(self, checker: RBACCheck) -> None:
        resources = KubeResources(service_accounts=[
            make_service_account("default", "production", automount=False),
        ])
        findings = checker.check(resources)
        auto = [f for f in findings if f.check_id == "RBAC-003"]
        assert len(auto) == 0


class TestDefaultNamespace:
    def test_pod_in_default_namespace(self, checker: RBACCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(name="my-app", namespace="default",
                     containers=[make_container(security_context={"run_as_non_root": True})]),
        ])
        findings = checker.check(resources)
        default = [f for f in findings if f.check_id == "RBAC-004"]
        assert len(default) == 1

    def test_pod_in_other_namespace_passes(self, checker: RBACCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(name="my-app", namespace="production",
                     containers=[make_container(security_context={"run_as_non_root": True})]),
        ])
        findings = checker.check(resources)
        default = [f for f in findings if f.check_id == "RBAC-004"]
        assert len(default) == 0
