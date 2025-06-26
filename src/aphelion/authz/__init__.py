# src/aphelion/authz/__init__.py

"""
Authorization sub-package for Aphelion.
Handles Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC)
using PyCasbin.
"""

from .casbin_enforcer import (
    init_enforcer,
    get_enforcer,
    enforce,
    PolicyError,
    AuthorizationError,
    DEFAULT_MODEL_PATH,
    DEFAULT_POLICY_PATH
)

__all__ = [
    "init_enforcer",
    "get_enforcer",
    "enforce",
    "PolicyError",
    "AuthorizationError",
    "DEFAULT_MODEL_PATH",
    "DEFAULT_POLICY_PATH"
]
