
# Emailfy: Validation and Deliverability Checker

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)


Emailfy is a Python package designed for comprehensive email address validation and checking the deliverability of email addresses. It goes beyond basic syntax checks, providing advanced validation features and deliverability checks to ensure that email addresses are not only correctly formatted but also deliverable in a real-world environment.

## Features

**Key Features:**

- **Email Validation:** Verify if an email address is syntactically correct and adheres to established RFC standards.
- **Internationalization Support:** Support for internationalized email addresses, including UTF-8 and IDNA encoding.
- **Deliverability Checks:** Ensure the deliverability of email addresses by validating MX records, SPF policies, and domain existence.
- **Customizable Options:** Fine-tune validation with customizable settings, including allowing SMTPUTF8, quoted local parts, domain literals, and more.
- **Test Environment Support:** Accommodate testing environments where special-use domain names are allowed.

**Use Cases:**

- **Web Forms:** Enhance the user experience by ensuring that entered email addresses are both valid and deliverable.
- **Email Verification Services:** Build robust email verification services by seamlessly integrating `emailfy` for thorough validation.
- **API Endpoints:** Secure your applications by validating email addresses before processing user inputs.

**Additional Features:**

- **Custom Resolver:** Configure custom DNS resolvers with adjustable timeouts for deliverability checks.
- **Special Use Domain Handling:** Optionally exclude special-use domains from deliverability checks.

Ensure your application's email handling is reliable and secure with `emailfy` — the ultimate solution for email validation, deliverability checks, and customizable options.

## Installation

You can install Emailfy using `pip`:

```bash
pip install emailfy
```

## Usage
- **Basic Email Validation:**

```bash
from emailfy import validate_email, EmailNotValidError

try:
    validated_email = validate_email("user@example.com")
    print("Email is valid:", validated_email.normalized)

except EmailNotValidError as e:
    print("Email is not valid:", str(e))
```

- **Custom Resolver Configuration:**

```bash
from emailfy import caching_resolver, validate_email, EmailNotValidError

# Configure a custom resolver with a longer timeout
custom_resolver = caching_resolver(timeout=20)

try:
    validated_email = validate_email("user@example.com", dns_resolver=custom_resolver)
    print("Email is valid:", validated_email.normalized)

except EmailNotValidError as e:
    print("Email is not valid:", str(e))
```

- **Using Special Use Domain Names:**

```bash
from emailfy import SPECIAL_USE_DOMAIN_NAMES, validate_email, EmailNotValidError

try:
    validated_email = validate_email("user@example.com", globally_deliverable=False)
    print("Email is valid:", validated_email.normalized)

except EmailNotValidError as e:
    print("Email is not valid:", str(e))

```
## Configuration
Emailfy provides global attributes that you can adjust:

**`ALLOW_SMTPUTF8`**
**`ALLOW_QUOTED_LOCAL`**
**`ALLOW_DOMAIN_LITERAL`**
**`GLOBALLY_DELIVERABLE`**
**`CHECK_DELIVERABILITY`**
**`TEST_ENVIRONMENT`**
**`DEFAULT_TIMEOUT`**

Refer to the documentation for detailed information on each configuration attribute.


## Contributing

If you find a bug, have questions, or want to contribute, please check our contribution guidelines.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
