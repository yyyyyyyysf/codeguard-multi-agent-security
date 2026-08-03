"""UUID v4 ID generator.

All business IDs in CodeGuard use UUID v4 for:
- No enumeration risk (vs auto-increment).
- Natural fit for distributed systems.
- Consistent format across task_id, scan_id, rule_id, finding_id.
"""

from __future__ import annotations

import uuid


def generate_id() -> str:
    """Generate a UUID v4 string.

    Returns:
        36-character UUID string (e.g., "550e8400-e29b-41d4-a716-446655440000").
    """
    return str(uuid.uuid4())


def generate_task_id() -> str:
    """Shortcut for task_id generation."""
    return generate_id()


def generate_scan_id() -> str:
    """Shortcut for scan_id generation."""
    return generate_id()


def is_valid_uuid(value: str) -> bool:
    """Check if a string is a valid UUID."""
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError):
        return False
