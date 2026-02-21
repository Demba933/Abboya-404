from datetime import datetime, timedelta, timezone

from abboya.models import Role
from abboya.platform import AbboyaPlatform


if __name__ == "__main__":
    platform = AbboyaPlatform(token_secret="change-me", phone_pepper="pepper")

    business = platform.create_business(
        name="Salon Dakar",
        timezone="Africa/Dakar",
        booking_slug="salon-dakar",
        whatsapp_number="+221700000000",
        google_maps_url="https://maps.google.com/?q=salon+dakar",
    )
    owner = platform.register_user(
        display_name="Awa",
        phone="+221771112233",
        password="Passw0rd!",
        role=Role.OWNER,
        business_id=business.id,
    )
    customer = platform.register_user(
        display_name="Moussa",
        phone="+221779998877",
        password="ClientPass!",
        role=Role.CUSTOMER,
    )
    service = platform.create_service(
        actor_user_id=owner.id,
        business_id=business.id,
        title="Coupe + barbe",
        duration_minutes=45,
        price_cents=5000,
        deposit_required=True,
    )
    reservation = platform.book_appointment(
        customer_user_id=customer.id,
        service_id=service.id,
        starts_at=datetime.now(timezone.utc) + timedelta(days=1),
    )

    print(f"Reservation created: {reservation.id}")
    print(f"Audit chain valid: {platform.audit.validate_integrity()}")
