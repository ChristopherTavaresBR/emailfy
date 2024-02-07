from typing import Union, Optional, Dict, List, Any
from emailfy.exceptions_types import EmailNotValidError, EmailSyntaxError, ValidatedEmail
from emailfy.syntax import split_email, validate_email_local_part, validate_email_domain_name, validate_email_domain_literal, validate_email_length
from emailfy.rfc_constants import CASE_INSENSITIVE_MAILBOX_NAMES

def validate_email(
    email_input: Union[str, bytes, List[Union[str, bytes]], Dict[str, Any]],
    /,  # prior arguments are positional-only
    *,  # subsequent arguments are keyword-only
    allow_smtputf8: Optional[bool] = None,
    allow_empty_local: bool = False,
    allow_quoted_local: Optional[bool] = None,
    allow_domain_literal: Optional[bool] = None,
    check_deliverability: Optional[bool] = None,
    test_environment: Optional[bool] = None,
    globally_deliverable: Optional[bool] = None,
    timeout: Optional[int] = None,
    dns_resolver: Optional[object] = None
) -> Union[Dict[str, Union[ValidatedEmail, str]], ValidatedEmail]:
    """
    Given an email address, a list of email addresses, or a dictionary of email addresses,
    and some options, returns a dictionary with email addresses as keys and ValidatedEmail instances
    or error messages as values, depending on the validation results.
    """
    results = {}

    # Determine the type of input and process accordingly
    if isinstance(email_input, (str, bytes)):
        email_list = [email_input]
    elif isinstance(email_input, list):
        email_list = email_input
    elif isinstance(email_input, dict):
        email_list = email_input.keys()
    else:
        raise ValueError("Invalid input type. Expected str, bytes, list, or dict.")

    # Iterate through the email addresses
    for email in email_list:
        try:
            # Validate a single email address
            validated_email = validate_single_email(
                email,
                allow_smtputf8=allow_smtputf8,
                allow_empty_local=allow_empty_local,
                allow_quoted_local=allow_quoted_local,
                allow_domain_literal=allow_domain_literal,
                check_deliverability=check_deliverability,
                test_environment=test_environment,
                globally_deliverable=globally_deliverable,
                timeout=timeout,
                dns_resolver=dns_resolver
            )

            # Store the result in the dictionary
            results[email] = validated_email if isinstance(email_input, dict) else validated_email.normalized

        except EmailNotValidError as e:
            # Handle validation errors and store error messages in the dictionary
            results[email] = str(e)

    return results


def validate_single_email(
    email: Union[str, bytes],
    allow_smtputf8: Optional[bool] = None,
    allow_empty_local: bool = False,
    allow_quoted_local: Optional[bool] = None,
    allow_domain_literal: Optional[bool] = None,
    check_deliverability: Optional[bool] = None,
    test_environment: Optional[bool] = None,
    globally_deliverable: Optional[bool] = None,
    timeout: Optional[int] = None,
    dns_resolver: Optional[object] = None
) -> ValidatedEmail:
    """
    Validate a single email address and return a ValidatedEmail instance.
    """
    # Set default values for validation options
    from . import ALLOW_SMTPUTF8, ALLOW_QUOTED_LOCAL, ALLOW_DOMAIN_LITERAL, \
        GLOBALLY_DELIVERABLE, CHECK_DELIVERABILITY, TEST_ENVIRONMENT, DEFAULT_TIMEOUT
    if allow_smtputf8 is None:
        allow_smtputf8 = ALLOW_SMTPUTF8
    if allow_quoted_local is None:
        allow_quoted_local = ALLOW_QUOTED_LOCAL
    if allow_domain_literal is None:
        allow_domain_literal = ALLOW_DOMAIN_LITERAL
    if check_deliverability is None:
        check_deliverability = CHECK_DELIVERABILITY
    if test_environment is None:
        test_environment = TEST_ENVIRONMENT
    if globally_deliverable is None:
        globally_deliverable = GLOBALLY_DELIVERABLE
    if timeout is None and dns_resolver is None:
        timeout = DEFAULT_TIMEOUT

    # Validate email type and convert to ASCII if it's bytes
    if not isinstance(email, str):
        try:
            email = email.decode("ascii")
        except ValueError:
            raise EmailSyntaxError("The email address is not valid ASCII.")

    # Split the email into local and domain parts
    local_part, domain_part, is_quoted_local_part = split_email(email)

    # Initialize the ValidatedEmail object
    ret = ValidatedEmail()
    ret.original = email

    # Validate the local part of the email
    local_part_info = validate_email_local_part(local_part,
                                                allow_smtputf8=allow_smtputf8,
                                                allow_empty_local=allow_empty_local,
                                                quoted_local_part=is_quoted_local_part)
    ret.local_part = local_part_info["local_part"]
    ret.ascii_local_part = local_part_info["ascii_local_part"]
    ret.smtputf8 = local_part_info["smtputf8"]

    # Check for quoting rules violation
    if is_quoted_local_part and not allow_quoted_local:
        raise EmailSyntaxError("Quoting the part before the @-sign is not allowed here.")

    # Normalize case-insensitive mailbox names
    if ret.ascii_local_part is not None \
       and ret.ascii_local_part.lower() in CASE_INSENSITIVE_MAILBOX_NAMES \
       and ret.local_part is not None:
        ret.ascii_local_part = ret.ascii_local_part.lower()
        ret.local_part = ret.local_part.lower()

    # Check for domain literal or regular domain part
    is_domain_literal = False
    if len(domain_part) == 0:
        raise EmailSyntaxError("There must be something after the @-sign.")

    elif domain_part.startswith("[") and domain_part.endswith("]"):
        # Validate domain literal
        domain_part_info = validate_email_domain_literal(domain_part[1:-1])
        if not allow_domain_literal:
            raise EmailSyntaxError("A bracketed IP address after the @-sign is not allowed here.")
        ret.domain = domain_part_info["domain"]
        ret.ascii_domain = domain_part_info["domain"]  # Domain literals are always ASCII.
        ret.domain_address = domain_part_info["domain_address"]
        is_domain_literal = True  # Prevent deliverability checks.

    else:
        # Validate regular domain part
        domain_part_info = validate_email_domain_name(domain_part, test_environment=test_environment, globally_deliverable=globally_deliverable)
        ret.domain = domain_part_info["domain"]
        ret.ascii_domain = domain_part_info["ascii_domain"]

    # Construct the normalized email address
    ret.normalized = ret.local_part + "@" + ret.domain

    # If the email address has an ASCII form, add it.
    if not ret.smtputf8:
        if not ret.ascii_domain:
            raise Exception("Missing ASCII domain.")
        ret.ascii_email = (ret.ascii_local_part or "") + "@" + ret.ascii_domain
    else:
        ret.ascii_email = None

    # Check the length of the address
    validate_email_length(ret)

    # Check deliverability if required
    if check_deliverability and not test_environment:
        if is_domain_literal:
            return ret

        from .deliverability import validate_email_deliverability
        deliverability_info = validate_email_deliverability(
            ret.ascii_domain, ret.domain, timeout, dns_resolver
        )
        for key, value in deliverability_info.items():
            setattr(ret, key, value)

    return ret