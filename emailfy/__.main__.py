import json
import os
import sys
from emailfy.validate_email import validate_email
from emailfy.deliverability import caching_resolver
from emailfy.exceptions_types import EmailNotValidError


def set_options_from_env():
    """
    Set options from environment variables.
    """
    options = {}

    for varname in ('ALLOW_SMTPUTF8', 'ALLOW_QUOTED_LOCAL', 'ALLOW_DOMAIN_LITERAL',
                    'GLOBALLY_DELIVERABLE', 'CHECK_DELIVERABILITY', 'TEST_ENVIRONMENT'):
        if varname in os.environ:
            options[varname.lower()] = bool(os.environ[varname])

    for varname in ('DEFAULT_TIMEOUT',):
        if varname in os.environ:
            options[varname.lower()] = float(os.environ[varname])

    return options


def validate_email_address(email, dns_resolver=None, **options):
    """
    Validate an email address and print the result.

    Args:
        email (str): The email address to be validated.
        dns_resolver (object): The DNS resolver object for tests.
        **options: Additional options for email validation.

    Returns:
        ValidatedEmail: An object containing information about the validated email.
    """
    try:
        result = validate_email(email, dns_resolver=dns_resolver, **options)
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True, ensure_ascii=False))
        return result
    except EmailNotValidError as e:
        print(e)
        return None


def validate_email_addresses_from_stdin(dns_resolver=None, **options):
    """
    Validate email addresses from STDIN and print the results.

    Args:
        dns_resolver (object): The DNS resolver object for tests.
        **options: Additional options for email validation.
    """
    dns_resolver = dns_resolver or caching_resolver()

    for line in sys.stdin:
        email = line.strip()
        validate_email_address(email, dns_resolver=dns_resolver, **options)


def main():
    """
    Main function for email validation.
    """
    options = set_options_from_env()

    if len(sys.argv) == 1:
        # Validate the email addresses passed line-by-line on STDIN.
        validate_email_addresses_from_stdin(**options)
    else:
        # Validate the email address passed on the command line.
        email = sys.argv[1]
        validate_email_address(email, **options)


if __name__ == "__main__":
    main()
