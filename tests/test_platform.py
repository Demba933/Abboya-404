from datetime import datetime, timedelta, timezone
import unittest

from abboya.models import Role
from abboya.platform import AbboyaPlatform, AuthorizationError, BusinessRuleError


class PlatformTests(unittest.TestCase):
    def setUp(self) -> None:
        self.platform = AbboyaPlatform(token_secret="secret", phone_pepper="pepper")
        self.business = self.platform.create_business(
            name="Gym Bamako",
            timezone="Africa/Bamako",
            booking_slug="gym-bko",
            whatsapp_number="+223700000000",
            google_maps_url="https://maps.google.com/?q=gym+bamako",
        )
        self.owner = self.platform.register_user(
            display_name="Owner",
            phone="+22311112222",
            password="Owner123!",
            role=Role.OWNER,
            business_id=self.business.id,
        )
        self.customer = self.platform.register_user(
            display_name="Customer",
            phone="+22333334444",
            password="Cust0mer!",
            role=Role.CUSTOMER,
        )
        self.service = self.platform.create_service(
            actor_user_id=self.owner.id,
            business_id=self.business.id,
            title="Coaching",
            duration_minutes=60,
            price_cents=10000,
        )

    def test_prevent_double_booking(self):
        start = datetime.now(timezone.utc) + timedelta(days=1)
        self.platform.book_appointment(
            customer_user_id=self.customer.id,
            service_id=self.service.id,
            starts_at=start,
        )
        with self.assertRaises(BusinessRuleError):
            self.platform.book_appointment(
                customer_user_id=self.customer.id,
                service_id=self.service.id,
                starts_at=start + timedelta(minutes=30),
            )

    def test_customer_cannot_create_service(self):
        with self.assertRaises(AuthorizationError):
            self.platform.create_service(
                actor_user_id=self.customer.id,
                business_id=self.business.id,
                title="Not allowed",
                duration_minutes=10,
                price_cents=100,
            )

    def test_token_flow_and_audit_integrity(self):
        token = self.platform.authenticate(phone="+22311112222", password="Owner123!")
        claims = self.platform.token_signer.verify(token)
        self.assertEqual(claims.sub, self.owner.id)
        self.assertTrue(self.platform.audit.validate_integrity())


if __name__ == "__main__":
    unittest.main()
