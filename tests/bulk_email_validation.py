from emailfy import validate_email, EmailNotValidError

emails_to_validate = ["user@exemplo.com", "exe@exemplocom"]

try:
    validated_emails = validate_email(emails_to_validate)
    print(validated_emails)

except EmailNotValidError as e:
    print(f"Error details: {e.details}")
    print(f"Full exception: {str(e)}")
