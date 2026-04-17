"""Base class for all security checks."""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any

from ghostaudit.client import KubeResources
from ghostaudit.models import Finding


@dataclass
class CheckInfo:
    """Metadata about a check."""

    check_id: str
    title: str
    description: str
    category: str


class BaseCheck(abc.ABC):
    """Abstract base class for security checks.

    Subclasses implement check() which receives pre-loaded K8s resources
    and returns a list of Findings. This design allows testing with
    fixture data without needing a live cluster connection.
    """

    category: str = ""

    @abc.abstractmethod
    def check(self, resources: KubeResources) -> list[Finding]:
        """Run the check against pre-loaded resources and return findings."""
        ...

    @classmethod
    @abc.abstractmethod
    def list_checks(cls) -> list[CheckInfo]:
        """Return metadata for all checks in this module."""
        ...

    @staticmethod
    def _get_nested(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
        """Safely traverse nested dict keys."""
        current = data
        for key in keys:
            if not isinstance(current, dict):
                return default
            current = current.get(key, default)
            if current is None:
                return default
        return current

    @staticmethod
    def _resource_name(resource: dict[str, Any]) -> str:
        """Extract resource name from metadata."""
        meta = resource.get("metadata", {}) or {}
        return meta.get("name", "<unknown>")

    @staticmethod
    def _resource_namespace(resource: dict[str, Any]) -> str:
        """Extract resource namespace from metadata."""
        meta = resource.get("metadata", {}) or {}
        return meta.get("namespace", "<cluster>")
