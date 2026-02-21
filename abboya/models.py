from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Role(str, Enum):
    OWNER = "owner"
    STAFF = "staff"
    CUSTOMER = "customer"


class ReservationStatus(str, Enum):
    CONFIRMED = "confirmed"
    CANCELLED = "cancelled"
    RESCHEDULED = "rescheduled"
    COMPLETED = "completed"


@dataclass(slots=True)
class User:
    id: str
    business_id: Optional[str]
    role: Role
    display_name: str
    phone_hash: str
    phone_last4: str
    password_hash: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class Business:
    id: str
    name: str
    timezone: str
    booking_slug: str
    whatsapp_number: str
    google_maps_url: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class Service:
    id: str
    business_id: str
    title: str
    duration_minutes: int
    price_cents: int
    deposit_required: bool = False


@dataclass(slots=True)
class Reservation:
    id: str
    business_id: str
    service_id: str
    customer_id: str
    starts_at: datetime
    ends_at: datetime
    status: ReservationStatus = ReservationStatus.CONFIRMED
    payment_reference: Optional[str] = None
    reminder_sent_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class AuditEntry:
    id: str
    actor_user_id: str
    action: str
    resource: str
    created_at: datetime
    prev_hash: str
    payload_hash: str
    chain_hash: str
