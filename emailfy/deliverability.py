from typing import Optional, Any, Dict
from exceptions_types import EmailUndeliverableError
import dns.resolver
import dns.exception


def caching_resolver(*, timeout: Optional[int] = None, cache=None):
    """
    Creates and configures a DNS resolver with optional caching.

    Args:
        timeout (int, optional): The timeout for DNS queries in seconds. Defaults to None.
        cache (object, optional): An optional DNS cache. Defaults to None.

    Returns:
        dns.resolver.Resolver: A configured DNS resolver.
    """
    if timeout is None:
        from . import DEFAULT_TIMEOUT
        timeout = DEFAULT_TIMEOUT
    resolver = dns.resolver.Resolver()
    resolver.cache = cache or dns.resolver.LRUCache()  # type: ignore
    resolver.lifetime = timeout  # type: ignore # timeout, in seconds
    return resolver


def validate_email_deliverability(domain: str, domain_i18n: str, timeout: Optional[int] = None, dns_resolver=None):
    """
    Validates the deliverability of the email address domain.

    Args:
        domain (str): The ASCII-encoded domain name.
        domain_i18n (str): The canonical Unicode form of the domain.
        timeout (int, optional): The timeout for DNS queries in seconds. Defaults to None.
        dns_resolver (dns.resolver.Resolver, optional): An optional DNS resolver. Defaults to None.

    Returns:
        dict: A dictionary containing deliverability information.

    Raises:
        EmailUndeliverableError: If the domain is determined to be undeliverable.
    """
    # If no custom DNS resolver is provided, use the default resolver with the specified timeout
    if dns_resolver is None:
        from . import DEFAULT_TIMEOUT
        if timeout is None:
            timeout = DEFAULT_TIMEOUT
        dns_resolver = dns.resolver.get_default_resolver()
        dns_resolver.lifetime = timeout
    elif timeout is not None:
        raise ValueError("It's not valid to pass both timeout and dns_resolver.")

    deliverability_info: Dict[str, Any] = {}

    try:
        try:
            # Try resolving for MX records (RFC 5321 Section 5).
            response = dns_resolver.resolve(domain, "MX")

            # For reporting, put them in priority order and remove the trailing dot in the qnames.
            mtas = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in response])

            # RFC 7505: Null MX (0, ".") records signify the domain does not accept email.
            # Remove null MX records from the mtas list
            mtas = [(preference, exchange) for preference, exchange in mtas if exchange != ""]
            if len(mtas) == 0:
                raise EmailUndeliverableError(f"The domain name {domain_i18n} does not accept email.")

            deliverability_info["mx"] = mtas
            deliverability_info["mx_fallback_type"] = None

        except dns.resolver.NoAnswer:
            # If there was no MX record, fall back to an A record. (RFC 5321 Section 5)
            try:
                response = dns_resolver.resolve(domain, "A")
                deliverability_info["mx"] = [(0, str(r)) for r in response]
                deliverability_info["mx_fallback_type"] = "A"

            except dns.resolver.NoAnswer:
                # If there was no A record, fall back to an AAAA record.
                try:
                    response = dns_resolver.resolve(domain, "AAAA")
                    deliverability_info["mx"] = [(0, str(r)) for r in response]
                    deliverability_info["mx_fallback_type"] = "AAAA"

                except dns.resolver.NoAnswer:
                    # If there was no MX, A, or AAAA record, then mail to this domain is not deliverable
                    raise EmailUndeliverableError(f"The domain name {domain_i18n} does not accept email.")

            # Check for a SPF (RFC 7208) reject-all record ("v=spf1 -all") which indicates
            # no emails are sent from this domain
            try:
                response = dns_resolver.resolve(domain, "TXT")
                for rec in response:
                    value = b"".join(rec.strings)
                    if value.startswith(b"v=spf1 "):
                        deliverability_info["spf"] = value.decode("ascii", errors='replace')
                        if value == b"v=spf1 -all":
                            raise EmailUndeliverableError(f"The domain name {domain_i18n} does not send email.")
            except dns.resolver.NoAnswer:
                # No TXT records means there is no SPF policy
                pass

    except dns.resolver.NXDOMAIN:
        # The domain name does not exist
        raise EmailUndeliverableError(f"The domain name {domain_i18n} does not exist.")

    except dns.resolver.NoNameservers:
        # All nameservers failed to answer the query. This might be a problem with local nameservers.
        return {
            "unknown-deliverability": "no_nameservers",
        }

    except dns.exception.Timeout:
        # A timeout could occur for various reasons, so don't treat it as a failure.
        return {
            "unknown-deliverability": "timeout",
        }

    except EmailUndeliverableError:
        # Don't let these get clobbered by the wider except block below.
        raise

    except Exception as e:
        # Unhandled conditions should not propagate.
        raise EmailUndeliverableError(
            "There was an error while checking if the domain name in the email address is deliverable: " + str(e)
        )

    return deliverability_info
