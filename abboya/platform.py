from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from .audit import AuditLog
from .models import Business, Reservation, ReservationStatus, Role, Service, User
from .security import PasswordHasher, TokenSigner, hash_phone


class AuthorizationError(PermissionError):
    pass


class BusinessRuleError(ValueError):
    pass


class AbboyaPlatform:
    """Core domain service for booking + appointment management."""

    def __init__(self, token_secret: str, phone_pepper: str):
        self.token_signer = TokenSigner(token_secret)
        self.phone_pepper = phone_pepper
        self.audit = AuditLog()

        self.users: dict[str, User] = {}
        self.businesses: dict[str, Business] = {}
        self.services: dict[str, Service] = {}
        self.reservations: dict[str, Reservation] = {}
        self.reservations_by_business: dict[str, list[str]] = defaultdict(list)

    def create_business(self, *, name: str, timezone: str, booking_slug: str, whatsapp_number: str, google_maps_url: str) -> Business:
        business = Business(
            id=str(uuid.uuid4()),
            name=name,
            timezone=timezone,
            booking_slug=booking_slug,
            whatsapp_number=whatsapp_number,
            google_maps_url=google_maps_url,
        )
        self.businesses[business.id] = business
        return business

    def register_user(self, *, display_name: str, phone: str, password: str, role: Role, business_id: str | None = None) -> User:
        if role in {Role.OWNER, Role.STAFF} and not business_id:
            raise BusinessRuleError("staff or owner must belong to a business")
        phone_hash, phone_last4 = hash_phone(phone, self.phone_pepper)
        user = User(
            id=str(uuid.uuid4()),
            business_id=business_id,
            role=role,
            display_name=display_name,
            phone_hash=phone_hash,
            phone_last4=phone_last4,
            password_hash=PasswordHasher.hash_password(password),
        )
        self.users[user.id] = user
        return user

    def authenticate(self, *, phone: str, password: str) -> str:
        phone_hash, _ = hash_phone(phone, self.phone_pepper)
        for user in self.users.values():
            if user.phone_hash == phone_hash and PasswordHasher.verify(password, user.password_hash):
                return self.token_signer.issue(user.id, user.role.value, user.business_id)
        raise AuthorizationError("invalid credentials")

    def create_service(self, *, actor_user_id: str, business_id: str, title: str, duration_minutes: int, price_cents: int, deposit_required: bool = False) -> Service:
        actor = self._require_staff(actor_user_id, business_id)
        service = Service(
            id=str(uuid.uuid4()),
            business_id=business_id,
            title=title,
            duration_minutes=duration_minutes,
            price_cents=price_cents,
            deposit_required=deposit_required,
        )
        self.services[service.id] = service
        self.audit.append(actor.id, "service.create", f"service:{service.id}", asdict(service))
        return service

    def book_appointment(self, *, customer_user_id: str, service_id: str, starts_at: datetime, payment_reference: str | None = None) -> Reservation:
        customer = self.users[customer_user_id]
        if customer.role is not Role.CUSTOMER:
            raise AuthorizationError("only customers can book")
        service = self.services[service_id]
        ends_at = starts_at + timedelta(minutes=service.duration_minutes)
        self._assert_slot_available(service.business_id, starts_at, ends_at)

        reservation = Reservation(
            id=str(uuid.uuid4()),
            business_id=service.business_id,
            service_id=service_id,
            customer_id=customer_user_id,
            starts_at=starts_at,
            ends_at=ends_at,
            payment_reference=payment_reference,
        )
        self.reservations[reservation.id] = reservation
        self.reservations_by_business[reservation.business_id].append(reservation.id)
        self.audit.append(customer.id, "reservation.book", f"reservation:{reservation.id}", {"service_id": service_id, "starts_at": starts_at.isoformat()})
        return reservation

    def cancel_appointment(self, *, actor_user_id: str, reservation_id: str) -> Reservation:
        reservation = self.reservations[reservation_id]
        actor = self.users[actor_user_id]
        if actor.role is Role.CUSTOMER and reservation.customer_id != actor.id:
            raise AuthorizationError("customer can only cancel own reservations")
        if actor.role in {Role.OWNER, Role.STAFF} and actor.business_id != reservation.business_id:
            raise AuthorizationError("staff can only cancel reservation from own business")
        reservation.status = ReservationStatus.CANCELLED
        self.audit.append(actor.id, "reservation.cancel", f"reservation:{reservation.id}", {"status": reservation.status.value})
        return reservation

    def reschedule_appointment(self, *, actor_user_id: str, reservation_id: str, new_start: datetime) -> Reservation:
        reservation = self.reservations[reservation_id]
        actor = self.users[actor_user_id]
        if actor.role not in {Role.OWNER, Role.STAFF}:
            raise AuthorizationError("only business staff can reschedule")
        if actor.business_id != reservation.business_id:
            raise AuthorizationError("cross-business operation denied")
        duration = reservation.ends_at - reservation.starts_at
        new_end = new_start + duration
        self._assert_slot_available(reservation.business_id, new_start, new_end, excluded_reservation_id=reservation.id)
        reservation.starts_at = new_start
        reservation.ends_at = new_end
        reservation.status = ReservationStatus.RESCHEDULED
        self.audit.append(actor.id, "reservation.reschedule", f"reservation:{reservation.id}", {"new_start": new_start.isoformat(), "new_end": new_end.isoformat()})
        return reservation

    def reminder_candidates(self, *, business_id: str, now: datetime, horizon_hours: int = 24) -> list[Reservation]:
        deadline = now + timedelta(hours=horizon_hours)
        candidates = []
        for res_id in self.reservations_by_business[business_id]:
            reservation = self.reservations[res_id]
            if reservation.status != ReservationStatus.CONFIRMED:
                continue
            if reservation.reminder_sent_at is not None:
                continue
            if now <= reservation.starts_at <= deadline:
                candidates.append(reservation)
        return candidates

    def mark_reminder_sent(self, *, actor_user_id: str, reservation_id: str, sent_at: datetime) -> None:
        actor = self.users[actor_user_id]
        reservation = self.reservations[reservation_id]
        if actor.role not in {Role.OWNER, Role.STAFF} or actor.business_id != reservation.business_id:
            raise AuthorizationError("not allowed to dispatch reminder")
        reservation.reminder_sent_at = sent_at
        self.audit.append(actor.id, "reservation.reminder", f"reservation:{reservation.id}", {"sent_at": sent_at.isoformat()})

    def business_stats(self, *, actor_user_id: str, business_id: str) -> dict[str, int]:
        self._require_staff(actor_user_id, business_id)
        stats = defaultdict(int)
        for res_id in self.reservations_by_business[business_id]:
            stats[self.reservations[res_id].status.value] += 1
        stats["total"] = sum(stats.values())
        return dict(stats)

    def _require_staff(self, actor_user_id: str, business_id: str) -> User:
        actor = self.users[actor_user_id]
        if actor.role not in {Role.OWNER, Role.STAFF}:
            raise AuthorizationError("only owner or staff allowed")
        if actor.business_id != business_id:
            raise AuthorizationError("staff cannot access another business")
        return actor

    def _assert_slot_available(self, business_id: str, starts_at: datetime, ends_at: datetime, excluded_reservation_id: str | None = None) -> None:
        for res_id in self.reservations_by_business[business_id]:
            if excluded_reservation_id and res_id == excluded_reservation_id:
                continue
            reservation = self.reservations[res_id]
            if reservation.status == ReservationStatus.CANCELLED:
                continue
            overlap = starts_at < reservation.ends_at and ends_at > reservation.starts_at
            if overlap:
                raise BusinessRuleError("slot is already taken")
