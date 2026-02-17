[![DOI](https://img.shields.io/github/v/release/zsjstart/LOV)](https://github.com/zsjstart/LOV/releases/tag/v1.0.0)
# LOV
We develop, Learning Origin Validation (LOV), a new mechanism specifically crafted to whitelist benign conflicts on the Internet-wide scale. The generated whitelist is offered to the ASes that employ ROV to validate RPKI-invalid routes. This involves matching the RPKI-invalid routes against the whitelist. If a match is found, the routes are considered benign, and border routers refrain from blocking them.
