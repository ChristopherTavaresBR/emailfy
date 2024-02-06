from typing import Optional, Tuple
import re
import unicodedata
import idna
import ipaddress
from exceptions_types import EmailSyntaxError
from rfc_constants import EMAIL_MAX_LENGTH, LOCAL_PART_MAX_LENGTH, DOMAIN_MAX_LENGTH, \
    DOT_ATOM_TEXT, DOT_ATOM_TEXT_INTL, ATEXT_RE, ATEXT_INTL_RE, ATEXT_HOSTNAME_INTL, QTEXT_INTL, \
    DNS_LABEL_LENGTH_LIMIT, DOT_ATOM_TEXT_HOSTNAME, DOMAIN_NAME_REGEX, DOMAIN_LITERAL_CHARS, \
    QUOTED_LOCAL_PART_ADDR


def split_email(email: str) -> Tuple[str, str, bool]:
    """
    Split the email address into local part, domain part, and check if the local part was quoted.

    Args:
        email (str): The email address.

    Returns:
        Tuple[str, str, bool]: A tuple containing local part, domain part, and a flag indicating if the local part was quoted.
    """
    match_quoted = QUOTED_LOCAL_PART_ADDR.match(email)
    if match_quoted:
        local_part, domain_part = match_quoted.groups()
        local_part = re.sub(r"\\(.)", "\\1", local_part)
        return local_part, domain_part, True
    else:
        parts = email.split('@')
        if len(parts) != 2:
            raise EmailSyntaxError("The email address is not valid. It must contain exactly one @.")
        local_part, domain_part = parts
        return local_part, domain_part, False


def get_length_reason(addr: str, utf8: bool = False, limit: int = 320) -> str:
    """
    Return an error message related to invalid length.

    Args:
        addr (str): The address.
        utf8 (bool, optional): Whether the address is UTF-8 encoded. Defaults to False.
        limit (int, optional): The length limit. Defaults to 320.

    Returns:
        str: An error message related to the length.
    """
    diff = len(addr) - limit
    prefix = "at least " if utf8 else ""
    suffix = "s" if diff > 1 else ""
    return f"({prefix}{diff} character{suffix} too many)"


def safe_character_display(c: str) -> str:
    """
    Return a safely displayable representation of the character.

    Args:
        c (str): The character.

    Returns:
        str: A safely displayable representation of the character.
    """
    if c == '\\':
        return f"\"{c}\""
    if unicodedata.category(c)[0] in ("L", "N", "P", "S"):
        return repr(c)
    if ord(c) < 0xFFFF:
        h = f"U+{ord(c):04x}".upper()
    else:
        h = f"U+{ord(c):08x}".upper()
    return unicodedata.name(c, h)


def validate_email_local_part(local: str, allow_smtputf8: bool = True, allow_empty_local: bool = False,
                              quoted_local_part: bool = False) -> dict:
    if len(local) == 0:
        if not allow_empty_local:
            raise EmailSyntaxError("There must be something before the @-sign.")
        else:
            return {
                "local_part": local,
                "ascii_local_part": local,
                "smtputf8": False,
            }
    if len(local) > LOCAL_PART_MAX_LENGTH:
        reason = get_length_reason(local, limit=LOCAL_PART_MAX_LENGTH)
        raise EmailSyntaxError(f"The email address is too long before the @-sign {reason}.")
    if DOT_ATOM_TEXT.match(local):
        return {
            "local_part": local,
            "ascii_local_part": local,
            "smtputf8": False,
        }
    valid: Optional[str] = None
    requires_smtputf8 = False
    if DOT_ATOM_TEXT_INTL.match(local):
        if not allow_smtputf8:
            bad_chars = {
                safe_character_display(c)
                for c in local
                if not ATEXT_RE.match(c)
            }
            if bad_chars:
                raise EmailSyntaxError("Internationalized characters before the @-sign are not supported: " + ", ".join(sorted(bad_chars)) + ".")
            raise EmailSyntaxError("Internationalized characters before the @-sign are not supported.")
        valid = "dot-atom"
        requires_smtputf8 = True
    elif quoted_local_part:
        bad_chars = {
            safe_character_display(c)
            for c in local
            if not QTEXT_INTL.match(c)
        }
        if bad_chars:
            raise EmailSyntaxError("The email address contains invalid characters in quotes before the @-sign: " + ", ".join(sorted(bad_chars)) + ".")
        bad_chars = {
            safe_character_display(c)
            for c in local
            if not (32 <= ord(c) <= 126)
        }
        if bad_chars:
            requires_smtputf8 = True
            if not allow_smtputf8:
                raise EmailSyntaxError("Internationalized characters before the @-sign are not supported: " + ", ".join(sorted(bad_chars)) + ".")
        valid = "quoted"
    if valid:
        local = unicodedata.normalize("NFC", local)
        check_unsafe_chars(local, allow_space=(valid == "quoted"))
        try:
            local.encode("utf8")
        except ValueError:
            raise EmailSyntaxError("The email address contains an invalid character.")
        if valid == "quoted":
            local = '"' + re.sub(r'(["\\])', r'\\\1', local) + '"'
        return {
            "local_part": local,
            "ascii_local_part": local if not requires_smtputf8 else None,
            "smtputf8": requires_smtputf8,
        }
    bad_chars = {
        safe_character_display(c)
        for c in local
        if not ATEXT_INTL_RE.match(c)
    }
    if bad_chars:
        raise EmailSyntaxError("The email address contains invalid characters before the @-sign: " + ", ".join(sorted(bad_chars)) + ".")
    check_dot_atom(local, 'An email address cannot start with a {}.', 'An email address cannot have a {} immediately before the @-sign.', is_hostname=False)
    raise EmailSyntaxError("The email address contains invalid characters before the @-sign.")


def check_unsafe_chars(s, allow_space=False):
    """
    Check for unsafe characters or characters that would make the string
    invalid or non-sensible Unicode.

    Args:
        s (str): The input string to be checked.
        allow_space (bool, optional): Whether to allow spaces. Defaults to False.

    Raises:
        EmailSyntaxError: If the input string contains unsafe characters.
    """
    bad_chars = set()
    for i, c in enumerate(s):
        category = unicodedata.category(c)
        if category[0] in ("L", "N", "P", "S"):
            pass
        elif category[0] == "M":
            if i == 0:
                bad_chars.add(c)
        elif category == "Zs":
            if not allow_space:
                bad_chars.add(c)
        elif category[0] == "Z":
            bad_chars.add(c)
        elif category[0] == "C":
            bad_chars.add(c)
        else:
            bad_chars.add(c)
    if bad_chars:
        raise EmailSyntaxError("The email address contains unsafe characters: "
                               + ", ".join(safe_character_display(c) for c in sorted(bad_chars)) + ".")


def check_dot_atom(label, start_descr, end_descr, is_hostname):
    """
    Check for the validity of the dot-atom label in an email address.

    Args:
        label (str): The dot-atom label to be checked.
        start_descr (str): Description for the error when the label starts with an invalid character.
        end_descr (str): Description for the error when the label ends with an invalid character.
        is_hostname (bool): Indicates whether the label is part of a hostname.

    Raises:
        EmailSyntaxError: If the dot-atom label is invalid based on the email address syntax rules.
    """
    if label.endswith("."):
        raise EmailSyntaxError(end_descr.format("period"))
    if label.startswith("."):
        raise EmailSyntaxError(start_descr.format("period"))
    if ".." in label:
        raise EmailSyntaxError("An email address cannot have two periods in a row.")

    if is_hostname:
        if label.endswith("-"):
            raise EmailSyntaxError(end_descr.format("hyphen"))
        if label.startswith("-"):
            raise EmailSyntaxError(start_descr.format("hyphen"))
        if ".-" in label or "-." in label:
            raise EmailSyntaxError("An email address cannot have a period and a hyphen next to each other.")


def validate_email_domain_name(domain: str, test_environment: bool = False, globally_deliverable: bool = True) -> dict:
    """
    Validates the syntax of the domain part of an email address.

    Args:
        domain (str): The domain part of the email address.
        test_environment (bool, optional): Indicates whether the validation is for a test environment. Defaults to False.
        globally_deliverable (bool, optional): Indicates whether the email address should be globally deliverable. Defaults to True.

    Returns:
        dict: A dictionary containing the ASCII-encoded domain and the canonical Unicode form of the domain.

    Raises:
        EmailSyntaxError: If the domain part is invalid based on the email address syntax rules.
    """
    bad_chars = {
        safe_character_display(c)
        for c in domain
        if not ATEXT_HOSTNAME_INTL.match(c)
    }
    if bad_chars:
        raise EmailSyntaxError("The part after the @-sign contains invalid characters: " + ", ".join(sorted(bad_chars)) + ".")

    check_unsafe_chars(domain)

    try:
        domain = idna.uts46_remap(domain, std3_rules=False, transitional=False)
    except idna.IDNAError as e:
        raise EmailSyntaxError(f"The part after the @-sign contains invalid characters ({e}).")

    check_dot_atom(domain, 'An email address cannot have a {} immediately after the @-sign.', 'An email address cannot end with a {}.', is_hostname=True)

    for label in domain.split("."):
        if re.match(r"(?!xn)..--", label, re.I):
            raise EmailSyntaxError("An email address cannot have two letters followed by two dashes immediately after the @-sign or after a period, except Punycode.")

    if DOT_ATOM_TEXT_HOSTNAME.match(domain):
        ascii_domain = domain
    else:
        try:
            ascii_domain = idna.encode(domain, uts46=False).decode("ascii")
        except idna.IDNAError as e:
            if "Domain too long" in str(e):
                raise EmailSyntaxError("The email address is too long after the @-sign.")

            raise EmailSyntaxError(f"The part after the @-sign contains invalid characters ({e}).")

        if not DOT_ATOM_TEXT_HOSTNAME.match(ascii_domain):
            raise EmailSyntaxError("The email address contains invalid characters after the @-sign after IDNA encoding.")

    if len(ascii_domain) > DOMAIN_MAX_LENGTH:
        reason = get_length_reason(ascii_domain, limit=DOMAIN_MAX_LENGTH)
        raise EmailSyntaxError(f"The email address is too long after the @-sign {reason}.")

    for label in ascii_domain.split("."):
        if len(label) > DNS_LABEL_LENGTH_LIMIT:
            reason = get_length_reason(label, limit=DNS_LABEL_LENGTH_LIMIT)
            raise EmailSyntaxError(f"After the @-sign, periods cannot be separated by so many characters {reason}.")

    if globally_deliverable:
        if "." not in ascii_domain and not (ascii_domain == "test" and test_environment):
            raise EmailSyntaxError("The part after the @-sign is not valid. It should have a period.")

        if not DOMAIN_NAME_REGEX.search(ascii_domain):
            raise EmailSyntaxError("The part after the @-sign is not valid. It is not within a valid top-level domain.")

    from . import SPECIAL_USE_DOMAIN_NAMES
    for d in SPECIAL_USE_DOMAIN_NAMES:
        if d == "test" and test_environment:
            continue

        if ascii_domain == d or ascii_domain.endswith("." + d):
            raise EmailSyntaxError("The part after the @-sign is a special-use or reserved name that cannot be used with email.")

    try:
        domain_i18n = idna.decode(ascii_domain.encode('ascii'))
    except idna.IDNAError as e:
        raise EmailSyntaxError(f"The part after the @-sign is not valid IDNA ({e}).")

    bad_chars = {
        safe_character_display(c)
        for c in domain
        if not ATEXT_HOSTNAME_INTL.match(c)
    }
    if bad_chars:
        raise EmailSyntaxError("The part after the @-sign contains invalid characters: " + ", ".join(sorted(bad_chars)) + ".")
    check_unsafe_chars(domain)

    return {
        "ascii_domain": ascii_domain,
        "domain": domain_i18n,
    }


def validate_email_length(addrinfo) -> None:
    """
    Validates the length of an email address.

    Args:
        addrinfo: Information about the email address.

    Raises:
        EmailSyntaxError: If the email address length exceeds the allowed maximum.
    """
    if addrinfo.ascii_email and len(addrinfo.ascii_email) > EMAIL_MAX_LENGTH:
        if addrinfo.ascii_email == addrinfo.normalized:
            reason = get_length_reason(addrinfo.ascii_email)
        elif len(addrinfo.normalized) > EMAIL_MAX_LENGTH:
            reason = get_length_reason(addrinfo.normalized, utf8=True)
        else:
            reason = "(when converted to IDNA ASCII)"
        raise EmailSyntaxError(f"The email address is too long {reason}.")

    if len(addrinfo.normalized.encode("utf8")) > EMAIL_MAX_LENGTH:
        if len(addrinfo.normalized) > EMAIL_MAX_LENGTH:
            reason = get_length_reason(addrinfo.normalized, utf8=True)
        else:
            reason = "(when encoded in bytes)"
        raise EmailSyntaxError(f"The email address is too long {reason}.")

def validate_email_domain_literal(domain_literal: str) -> dict:
    """
    Validates the syntax of the domain literal part of an email address.

    Args:
        domain_literal (str): The domain literal part of the email address.

    Returns:
        dict: A dictionary containing the address object and the normalized domain literal.

    Raises:
        EmailSyntaxError: If the domain literal part is invalid based on the email address syntax rules.
    """
    if re.match(r"^[0-9\.]+$", domain_literal):
        try:
            addr = ipaddress.IPv4Address(domain_literal)
        except ValueError as e:
            raise EmailSyntaxError(f"The address in brackets after the @-sign is not valid: It is not an IPv4 address ({e}) or is missing an address literal tag.")

        return {
            "domain_address": addr,
            "domain": f"[{addr}]",
        }

    if domain_literal.startswith("IPv6:"):
        try:
            addr = ipaddress.IPv6Address(domain_literal[5:])
        except ValueError as e:
            raise EmailSyntaxError(f"The IPv6 address in brackets after the @-sign is not valid ({e}).")

        return {
            "domain_address": addr,
            "domain": f"[IPv6:{addr.compressed}]",
        }

    if ":" not in domain_literal:
        raise EmailSyntaxError("The part after the @-sign in brackets is not an IPv4 address and has no address literal tag.")

    bad_chars = {
        safe_character_display(c)
        for c in domain_literal
        if not DOMAIN_LITERAL_CHARS.match(c)
    }
    if bad_chars:
        raise EmailSyntaxError("The part after the @-sign contains invalid characters in brackets: " + ", ".join(sorted(bad_chars)) + ".")

    raise EmailSyntaxError("The part after the @-sign contains an invalid address literal tag in brackets.")
