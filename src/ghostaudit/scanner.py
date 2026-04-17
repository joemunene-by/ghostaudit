"""Main scan orchestrator."""

from __future__ import annotations

from datetime import datetime, timezone

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ghostaudit.checks import ALL_CHECKS
from ghostaudit.client import KubeClient, KubeResources
from ghostaudit.config import ScanConfig
from ghostaudit.models import ScanReport

console = Console(stderr=True)


def run_scan(config: ScanConfig) -> ScanReport:
    """Run a full security scan against a Kubernetes cluster.

    Connects to the cluster, fetches resources, runs all configured
    checks, and returns a ScanReport.
    """
    report = ScanReport(
        cluster_name="unknown",
        scan_time=datetime.now(timezone.utc),
    )

    # Connect and fetch resources
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Connecting to cluster...", total=None)
            kube_client = KubeClient(kubeconfig=config.kubeconfig)
            report.cluster_name = kube_client.cluster_name

            progress.update(task, description="Fetching resources...")
            resources = kube_client.fetch_resources(namespace=config.namespace)
            report.namespaces_scanned = kube_client.get_namespaces(config.namespace)
    except Exception as e:
        console.print(f"[bold red]Error connecting to cluster:[/] {e}")
        report.errors.append(f"Connection error: {e}")
        return report

    return run_checks(config, resources, report)


def run_checks(
    config: ScanConfig,
    resources: KubeResources,
    report: ScanReport | None = None,
) -> ScanReport:
    """Run checks against pre-loaded resources.

    This is the testable entry point - pass in KubeResources directly
    without needing a live cluster.
    """
    if report is None:
        report = ScanReport(
            cluster_name="test-cluster",
            scan_time=datetime.now(timezone.utc),
        )

    for category in config.checks:
        check_cls = ALL_CHECKS.get(category)
        if check_cls is None:
            report.errors.append(f"Unknown check category: {category}")
            continue

        report.checks_run.append(category)
        checker = check_cls()
        try:
            findings = checker.check(resources)
            report.findings.extend(findings)
        except Exception as e:
            report.errors.append(f"Error in {category} checks: {e}")

    # Sort findings by severity (critical first)
    report.findings.sort(key=lambda f: f.severity.weight, reverse=True)
    return report
