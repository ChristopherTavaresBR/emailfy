import unittest
from ..emailfy import EmailNotValidError, validate_email, validate_single_email, ValidatedEmail


class TestEmailValidation(unittest.TestCase):

    def test_single_valid_email(self):
        valid_email = "test@example.com"
        result = validate_single_email(valid_email)
        self.assertIsInstance(result, ValidatedEmail)
        self.assertEqual(result.normalized, valid_email)

    def test_single_invalid_email(self):
        invalid_email = "invalid-email"
        with self.assertRaises(EmailNotValidError):
            validate_single_email(invalid_email)

    def test_single_email_with_name(self):
        email_with_name = "John Doe <john.doe@example.com>"
        result = validate_single_email(email_with_name)
        self.assertIsInstance(result, ValidatedEmail)
        self.assertEqual(result.normalized, "john.doe@example.com")

    def test_multiple_valid_emails(self):
        valid_emails = ["test1@example.com", "test2@example.com", "test3@example.com"]
        result = validate_email(valid_emails)
        self.assertIsInstance(result, dict)
        for email, validated_email in result.items():
            self.assertIsInstance(validated_email, ValidatedEmail)
            self.assertEqual(validated_email.normalized, email)

    def test_multiple_mixed_emails(self):
        mixed_emails = ["valid@example.com", "invalid-email", "another_valid@example.com"]
        result = validate_email(mixed_emails)
        self.assertIsInstance(result, dict)
        for email, validation_result in result.items():
            if isinstance(validation_result, ValidatedEmail):
                self.assertEqual(validation_result.normalized, email)
            else:
                self.assertIsInstance(validation_result, str)  # Error message for invalid emails

    def test_realistic_emails(self):
        realistic_emails = [
            "alice.smith@example.com",
            "bob.jones123@example.net",
            "charlie.brown@company.org",
            "david.wilson-jr@example.co.uk"
        ]
        result = validate_email(realistic_emails)
        self.assertIsInstance(result, dict)
        for email, validated_email in result.items():
            self.assertIsInstance(validated_email, ValidatedEmail)
            self.assertEqual(validated_email.normalized, email)

    # Add more test cases as needed


if __name__ == "__main__":
    unittest.main()
