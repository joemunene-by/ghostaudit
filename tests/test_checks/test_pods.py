"""Tests for pod security checks."""

from __future__ import annotations

import pytest

from ghostaudit.checks.pods import PodSecurityCheck
from ghostaudit.client import KubeResources
from ghostaudit.models import Severity
from tests.conftest import make_container, make_pod


@pytest.fixture
def checker() -> PodSecurityCheck:
    return PodSecurityCheck()


class TestPrivilegedContainer:
    def test_privileged_container_detected(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(containers=[make_container(
                security_context={"privileged": True},
            )]),
        ])
        findings = checker.check(resources)
        priv = [f for f in findings if f.check_id == "POD-001"]
        assert len(priv) == 1
        assert priv[0].severity == Severity.CRITICAL

    def test_non_privileged_container_passes(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(containers=[make_container(
                security_context={"privileged": False, "run_as_non_root": True,
                                   "read_only_root_filesystem": True,
                                   "allow_privilege_escalation": False},
            )]),
        ])
        findings = checker.check(resources)
        priv = [f for f in findings if f.check_id == "POD-001"]
        assert len(priv) == 0


class TestRunAsRoot:
    def test_missing_run_as_non_root(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(containers=[make_container(
                security_context={"read_only_root_filesystem": True,
                                   "allow_privilege_escalation": False},
            )]),
        ])
        findings = checker.check(resources)
        root = [f for f in findings if f.check_id == "POD-002"]
        assert len(root) == 1
        assert root[0].severity == Severity.HIGH

    def test_run_as_non_root_set(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(containers=[make_container(
                security_context={"run_as_non_root": True,
                                   "read_only_root_filesystem": True,
                                   "allow_privilege_escalation": False},
            )]),
        ])
        findings = checker.check(resources)
        root = [f for f in findings if f.check_id == "POD-002"]
        assert len(root) == 0

    def test_run_as_user_nonzero_passes(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(containers=[make_container(
                security_context={"run_as_user": 1000,
                                   "read_only_root_filesystem": True,
                                   "allow_privilege_escalation": False},
            )]),
        ])
        findings = checker.check(resources)
        root = [f for f in findings if f.check_id == "POD-002"]
        assert len(root) == 0

    def test_pod_level_run_as_non_root(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(
                containers=[make_container(
                    security_context={"read_only_root_filesystem": True,
                                       "allow_privilege_escalation": False},
                )],
                pod_security_context={"run_as_non_root": True},
            ),
        ])
        findings = checker.check(resources)
        root = [f for f in findings if f.check_id == "POD-002"]
        assert len(root) == 0


class TestMissingSecurityContext:
    def test_no_security_context(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(containers=[make_container(security_context=None)]),
        ])
        findings = checker.check(resources)
        missing = [f for f in findings if f.check_id == "POD-003"]
        assert len(missing) == 1
        assert missing[0].severity == Severity.MEDIUM

    def test_empty_security_context(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(containers=[make_container(security_context={})]),
        ])
        findings = checker.check(resources)
        missing = [f for f in findings if f.check_id == "POD-003"]
        assert len(missing) == 1


class TestHostNamespaces:
    def test_host_network_detected(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(
                host_network=True,
                containers=[make_container(
                    security_context={"run_as_non_root": True,
                                       "read_only_root_filesystem": True,
                                       "allow_privilege_escalation": False},
                )],
            ),
        ])
        findings = checker.check(resources)
        host = [f for f in findings if f.check_id == "POD-004"]
        assert len(host) == 1
        assert "hostNetwork" in host[0].description

    def test_all_host_namespaces(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(
                host_network=True, host_pid=True, host_ipc=True,
                containers=[make_container(
                    security_context={"run_as_non_root": True,
                                       "read_only_root_filesystem": True,
                                       "allow_privilege_escalation": False},
                )],
            ),
        ])
        findings = checker.check(resources)
        host = [f for f in findings if f.check_id == "POD-004"]
        assert len(host) == 1
        assert "hostPID" in host[0].description
        assert "hostIPC" in host[0].description


class TestReadOnlyRootFS:
    def test_writable_root_fs_detected(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(containers=[make_container(
                security_context={"run_as_non_root": True,
                                   "allow_privilege_escalation": False},
            )]),
        ])
        findings = checker.check(resources)
        ro = [f for f in findings if f.check_id == "POD-005"]
        assert len(ro) == 1
        assert ro[0].severity == Severity.MEDIUM


class TestPrivilegeEscalation:
    def test_escalation_not_disabled(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(containers=[make_container(
                security_context={"run_as_non_root": True,
                                   "read_only_root_filesystem": True},
            )]),
        ])
        findings = checker.check(resources)
        esc = [f for f in findings if f.check_id == "POD-006"]
        assert len(esc) == 1


class TestCapabilities:
    def test_dangerous_capability_detected(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(containers=[make_container(
                security_context={
                    "run_as_non_root": True,
                    "read_only_root_filesystem": True,
                    "allow_privilege_escalation": False,
                    "capabilities": {"add": ["SYS_ADMIN", "NET_RAW"]},
                },
            )]),
        ])
        findings = checker.check(resources)
        caps = [f for f in findings if f.check_id == "POD-007"]
        assert len(caps) == 1
        assert caps[0].severity == Severity.HIGH
        assert "SYS_ADMIN" in caps[0].description

    def test_safe_capability_passes(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(containers=[make_container(
                security_context={
                    "run_as_non_root": True,
                    "read_only_root_filesystem": True,
                    "allow_privilege_escalation": False,
                    "capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]},
                },
            )]),
        ])
        findings = checker.check(resources)
        caps = [f for f in findings if f.check_id == "POD-007"]
        assert len(caps) == 0


class TestSystemNamespaceSkipped:
    def test_kube_system_pods_skipped(self, checker: PodSecurityCheck) -> None:
        resources = KubeResources(pods=[
            make_pod(
                name="kube-proxy",
                namespace="kube-system",
                containers=[make_container(security_context={"privileged": True})],
            ),
        ])
        findings = checker.check(resources)
        assert len(findings) == 0
