"""Database drivers (P1), as far as UC-1 needs them.

:mod:`sopuli.driver.protocol` is the interface every command touching a database
goes through. No command contains vendor SQL, and Oracle -- the first and for now
the only product -- gets no privileged position in the shape of it.

Nothing here imports a database client. A driver is an install extra on the same
rule as a store (D9, ADR-006): ``python-oracledb`` arrives with
``sopuli-dba[oracle]``, is imported inside its own module on first use, and a
target declaring a driver this machine has not installed is a diagnosable
condition rather than a traceback. The registry that does the importing is #170;
until it lands, this package is the interface and its types alone.
"""

from sopuli.driver.protocol import (
    ACCOUNT_LOCK_STATE,
    ACCOUNT_UNLOCK,
    ATTRIBUTE_KINDS,
    ATTRIBUTE_SET,
    CAPABILITIES,
    COMMON_USERS,
    EXPIRE_PASSWORD,
    OFFLINE_VERIFY,
    PASSWORD_REUSE_POLICY,
    PASSWORD_ROLLOVER,
    PROFILE_MANAGEMENT,
    SCOPE_TYPES,
    UNKNOWN,
    VERIFY_METHODS,
    VERIFY_RESULTS,
    AccountAttributes,
    AttributeChange,
    AuthenticationError,
    ChangeResult,
    Credential,
    Driver,
    DriverError,
    Scope,
    Session,
    UnsupportedCapabilityError,
    UserState,
    VerifyResult,
    require_capability,
)

__all__ = [
    "ACCOUNT_LOCK_STATE",
    "ACCOUNT_UNLOCK",
    "ATTRIBUTE_KINDS",
    "ATTRIBUTE_SET",
    "CAPABILITIES",
    "COMMON_USERS",
    "EXPIRE_PASSWORD",
    "OFFLINE_VERIFY",
    "PASSWORD_REUSE_POLICY",
    "PASSWORD_ROLLOVER",
    "PROFILE_MANAGEMENT",
    "SCOPE_TYPES",
    "UNKNOWN",
    "VERIFY_METHODS",
    "VERIFY_RESULTS",
    "AccountAttributes",
    "AttributeChange",
    "AuthenticationError",
    "ChangeResult",
    "Credential",
    "Driver",
    "DriverError",
    "Scope",
    "Session",
    "UnsupportedCapabilityError",
    "UserState",
    "VerifyResult",
    "require_capability",
]
