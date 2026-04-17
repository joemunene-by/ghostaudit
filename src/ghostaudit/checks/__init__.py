"""Security check modules for GhostAudit."""

from ghostaudit.checks.base import BaseCheck
from ghostaudit.checks.images import ImageSecurityCheck
from ghostaudit.checks.network import NetworkCheck
from ghostaudit.checks.pods import PodSecurityCheck
from ghostaudit.checks.rbac import RBACCheck
from ghostaudit.checks.resources import ResourceManagementCheck
from ghostaudit.checks.secrets import SecretsConfigCheck

ALL_CHECKS: dict[str, type[BaseCheck]] = {
    "rbac": RBACCheck,
    "pods": PodSecurityCheck,
    "secrets": SecretsConfigCheck,
    "network": NetworkCheck,
    "resources": ResourceManagementCheck,
    "images": ImageSecurityCheck,
}

__all__ = [
    "ALL_CHECKS",
    "BaseCheck",
    "RBACCheck",
    "PodSecurityCheck",
    "SecretsConfigCheck",
    "NetworkCheck",
    "ResourceManagementCheck",
    "ImageSecurityCheck",
]
