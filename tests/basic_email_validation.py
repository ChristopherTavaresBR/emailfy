from emailfy import validate_single_email, EmailNotValidError

try:
    validated_email = validate_single_email("aratava82@gmail.com")
    print("Email is valid:", validated_email.normalized)

except EmailNotValidError as e:
    print("Email is not valid:", str(e))