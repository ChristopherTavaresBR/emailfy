from emailfy import validate_email, EmailNotValidError, ValidatedEmail

emails_to_validate = ["aratava82@gmail.com", "exe@exemplocom"]

try:
    validated_emails = validate_email(emails_to_validate)

    print(validated_emails)
    #for original_email, result in validated_emails.items():
    #    if isinstance(result, str):
    #        print(f"Original Email: {original_email}")
    #        print(f"Validation Error: {result}")
    #        print("Email is not valid")
    #        print("=" * 30)
    #    elif isinstance(result, ValidatedEmail):
    #        print(f"Original Email: {original_email}")
    #        print(f"Normalized Email: {result.normalized}")
    #        print("Email is valid")
    #        print("=" * 30)
    #    else:
    #        print(f"Unexpected result for {original_email}: {result}")

except EmailNotValidError as e:
    print(f"Error details: {e.details}")
    print(f"Full exception: {str(e)}")
