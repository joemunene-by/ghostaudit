"""Image security checks."""

from __future__ import annotations

import re

from ghostaudit.checks.base import BaseCheck, CheckInfo
from ghostaudit.client import KubeResources
from ghostaudit.models import Finding, Severity

SYSTEM_NAMESPACES = frozenset({
    "kube-system", "kube-public", "kube-node-lease",
})

# Well-known public registries
PUBLIC_REGISTRIES = [
    re.compile(r"^docker\.io/"),
    re.compile(r"^registry\.hub\.docker\.com/"),
    re.compile(r"^ghcr\.io/"),
    re.compile(r"^quay\.io/"),
    re.compile(r"^gcr\.io/"),
    re.compile(r"^registry\.k8s\.io/"),
    # Images without a registry prefix are docker.io
    re.compile(r"^[a-z0-9-]+(/[a-z0-9._-]+)?:[a-z0-9._-]+$"),
    re.compile(r"^[a-z0-9-]+(/[a-z0-9._-]+)?$"),
]


class ImageSecurityCheck(BaseCheck):
    category = "images"

    @classmethod
    def list_checks(cls) -> list[CheckInfo]:
        return [
            CheckInfo(
                "IMG-001",
                "Container using :latest tag",
                "Containers with images tagged :latest or no tag specified",
                "images",
            ),
            CheckInfo(
                "IMG-002",
                "Public registry without digest",
                "Images pulled from public registries without a pinned digest",
                "images",
            ),
            CheckInfo(
                "IMG-003",
                "Missing imagePullPolicy for mutable tag",
                "Containers using mutable tags without imagePullPolicy: Always",
                "images",
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
            containers = (spec.get("containers") or []) + (spec.get("init_containers") or [])

            for container in containers:
                cname = container.get("name", "<unnamed>")
                image = container.get("image", "")
                pull_policy = container.get("image_pull_policy", "")
                full_name = f"{pod_name}/{cname}"

                findings.extend(self._check_latest_tag(image, full_name, ns))
                findings.extend(self._check_public_registry_no_digest(image, full_name, ns))
                findings.extend(self._check_pull_policy(image, pull_policy, full_name, ns))

        return findings

    def _check_latest_tag(
        self, image: str, name: str, ns: str
    ) -> list[Finding]:
        tag = self._extract_tag(image)
        if tag == "latest" or tag is None:
            return [Finding(
                check_id="IMG-001",
                title="Container using :latest tag",
                description=(
                    f"Container '{name}' in namespace '{ns}' uses image "
                    f"'{image}' which "
                    + (
                        "has the :latest tag"
                        if tag == "latest"
                        else "has no tag specified (defaults to :latest)"
                    )
                    + ". The :latest tag is mutable and can change unexpectedly, "
                    "making deployments non-reproducible and potentially introducing "
                    "vulnerabilities."
                ),
                severity=Severity.MEDIUM,
                resource_kind="Pod",
                resource_name=name,
                namespace=ns,
                remediation=(
                    "Pin the image to a specific version tag or digest: "
                    f"image: {image.split(':')[0]}:<specific-version> or "
                    f"image: {image.split(':')[0]}@sha256:<digest>"
                ),
            )]
        return []

    def _check_public_registry_no_digest(
        self, image: str, name: str, ns: str
    ) -> list[Finding]:
        # Skip if image already uses a digest
        if "@sha256:" in image:
            return []

        is_public = self._is_public_registry(image)
        if is_public:
            return [Finding(
                check_id="IMG-002",
                title="Public registry image without digest",
                description=(
                    f"Container '{name}' in namespace '{ns}' uses image "
                    f"'{image}' from a public registry without a pinned digest. "
                    "Tags on public registries can be overwritten, allowing "
                    "supply-chain attacks."
                ),
                severity=Severity.MEDIUM,
                resource_kind="Pod",
                resource_name=name,
                namespace=ns,
                remediation=(
                    "Pin the image using a digest: "
                    f"image: {image.split('@')[0]}@sha256:<digest>. "
                    "Get the digest with: docker inspect --format='{{.RepoDigests}}' " + image
                ),
            )]
        return []

    def _check_pull_policy(
        self, image: str, pull_policy: str, name: str, ns: str
    ) -> list[Finding]:
        # If using a digest, pull policy doesn't matter as much
        if "@sha256:" in image:
            return []

        tag = self._extract_tag(image)
        # Mutable tags: latest, no tag, or non-semver tags
        is_mutable = tag is None or tag == "latest" or not re.match(r"^v?\d+\.\d+", tag)

        if is_mutable and pull_policy != "Always":
            return [Finding(
                check_id="IMG-003",
                title="Missing imagePullPolicy: Always for mutable tag",
                description=(
                    f"Container '{name}' in namespace '{ns}' uses image "
                    f"'{image}' with a mutable tag but imagePullPolicy is "
                    f"'{pull_policy or 'IfNotPresent (default)'}'. "
                    "Without Always, Kubernetes may use a cached (potentially "
                    "outdated or compromised) image."
                ),
                severity=Severity.LOW,
                resource_kind="Pod",
                resource_name=name,
                namespace=ns,
                remediation=(
                    "Set spec.containers[].imagePullPolicy: Always, or better yet, "
                    "pin the image to an immutable tag or digest."
                ),
            )]
        return []

    @staticmethod
    def _extract_tag(image: str) -> str | None:
        """Extract the tag from an image reference. Returns None if no tag."""
        # Handle digest references
        if "@sha256:" in image:
            pre_digest = image.split("@")[0]
            if ":" in pre_digest:
                return pre_digest.rsplit(":", 1)[-1]
            return None

        if ":" in image:
            # Could be a port (e.g., registry:5000/image)
            parts = image.rsplit(":", 1)
            tag = parts[-1]
            # If the tag contains a slash, it's actually a registry port
            if "/" in tag:
                return None
            return tag
        return None

    @staticmethod
    def _is_public_registry(image: str) -> bool:
        """Check if image is from a public registry."""
        # Images without a dot in the first segment are docker.io
        first_segment = image.split("/")[0]
        if "." not in first_segment and ":" not in first_segment:
            return True

        for pattern in PUBLIC_REGISTRIES:
            if pattern.match(image):
                return True
        return False
