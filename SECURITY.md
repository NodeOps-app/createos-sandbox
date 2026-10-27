# Security Policy

This policy covers the code in this repository and the hosted CreateOS Sandbox
service at <https://createos.sh>.

## Reporting a vulnerability

**Do not report security problems in public.** That means no GitHub issues,
discussions, pull requests, or social media posts. Public security reports are
removed as soon as we see them, so the details can't help an attacker while a
fix is in progress.

Report privately through GitHub instead:

1. Open the **Security** tab of this repository.
2. Choose **Report a vulnerability**
   (or go straight to
   <https://github.com/NodeOps-app/createos-sandbox/security/advisories/new>).
3. Fill in the form. Only you and the maintainers can see it.

Please include:

- what the problem is and what an attacker could do with it,
- the commit or release you tested, or the date if you tested the hosted
  service,
- exact steps or a small proof of concept that shows the problem,
- any logs, requests, or screenshots that help.

## What happens next

| Step | Target |
| --- | --- |
| We confirm we received your report | within 3 business days |
| We tell you whether we accept it and how serious we think it is | within 10 business days |
| We fix it and publish an advisory | within 90 days, sooner for critical issues |

We'll keep you updated along the way and agree on a disclosure date with you.
If you'd like, we'll credit you by name in the advisory.

We don't run a paid bug bounty program.

## Supported versions

Only the latest commit on `main` and the most recent tagged release get
security fixes. If you run an older copy yourself, upgrade before you report.

## Testing rules (safe harbor)

If you follow these rules in good faith, we won't take legal action against you
for your research, and we'll treat your work as authorized:

- Only test against sandboxes, accounts, and data that belong to you.
- Never access, change, or delete other users' data. If you reach someone
  else's data by accident, stop, don't keep a copy, and tell us.
- Don't run denial-of-service, load, or spam tests against the hosted service.
- Don't use social engineering or physical attacks against our staff or
  offices.
- Give us a reasonable time to fix the problem before you talk about it in
  public.

## Out of scope

- Denial of service and rate-limit findings with no further impact
- Reports from automated scanners with no proof that the issue can be exploited
- Missing security headers or best-practice settings with no concrete attack
- Bugs in third-party dependencies that are already public. Report those
  upstream; tell us if our code makes them exploitable.
- Problems that come only from how a self-hosted operator set up their own
  deployment
- Feature or customization requests for the hosted platform. See
  [CONTRIBUTING.md](CONTRIBUTING.md#enterprise-and-customization).
