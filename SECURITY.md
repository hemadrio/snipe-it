# Security Policy

We take security issues very seriously, and will always attempt to address any vulnerabilities as quickly as possible.

## Supported Versions

We try to make a reasonable effort to support older versions of Snipe-IT, however there are times when library
dependencies and/or PHP/MySQL dependencies make it impossible to backport security fixes on older versions.

| Version | Supported          |
|---------|--------------------|
| 8.x     | :white_check_mark: |
| 7.x     | :x:                |
| 6.x     | :x:                |
| 5.1.x   | :x:                |
| 5.0.x   | :x:                |
| 4.0.x   | :x:                |
| < 4.0   | :x:                |

## Reporting a Vulnerability

__Security vulnerabilities should be reported [via a new GHSA](https://github.com/grokability/snipe-it/security) or via
email security@snipeitapp.com.__

If we find that your security report is valid but has been reported in a previous GHSA that is currently still in draft
mode (therefore currently invisible to you), we will add your Github username to the original GHSA so that you can be
credited for your discovery.

When creating a GHSA, please leave the "package" field blank. Snipe-IT is not a package, so we will just have to blank
that field out when reviewing your GHSA.

You can typically expect a response within five business days, and we typically have fixes out in under a week from the
initial disclosure.

This obviously varies based on the severity of the security issue and the difficulty in remediation, but those have
historically been the timelines we work around.

__We do ask that you do not disclose the vulnerability publicly until we have had a chance to address it and tag a
release__ so that we can protect our users, and we will work with you to coordinate a public disclosure once we have a
fix out.

If you alert us to the security issue via security@snipeitapp.com, please provide a GitHub username or other
information if you would like to be credited, or please let us know if you would like to remain anonymous.

For responsible disclosure, we ask that you give us at least __90 days__ to address the issue before disclosing it
publicly, but we will work with you if you need to disclose it sooner than that.

For a full breakdown of our security policies, please see https://snipeitapp.com/security.

## PHP2Shell Emergency Response Guidance

### CVE-2026-109618 and CVE-2026-109619

These vulnerabilities affect PHP runtimes below the approved patched floors:

| Branch | Minimum Patched Version | PHP_VERSION_ID |
|--------|------------------------|----------------|
| 8.2    | 8.2.35                 | 80235          |
| 8.3    | 8.3.36                 | 80336          |
| 8.4    | 8.4.27                 | 80427          |
| 8.5    | 8.5.12                 | 80512          |

### Restart and Isolation Fallback

If you cannot immediately upgrade to a patched PHP version:

1. **Apply runtime mitigations** — The Docker startup scripts automatically write
   `session.upload_progress.enabled=0` and `fatal_error_backtraces=0` (PHP 8.5 only)
   to a mitigation ini file. For non-Docker deployments, add these settings manually:

   ```ini
   ; /etc/php/8.x/apache2/conf.d/99-php2shell-mitigation.ini
   session.upload_progress.enabled=0
   ; PHP 8.5 only:
   fatal_error_backtraces=0
   ```

2. **Restart PHP workers** — After applying ini overrides, restart Apache/PHP-FPM
   to ensure the settings take effect:

   ```shell
   # Apache
   systemctl restart apache2

   # PHP-FPM
   systemctl restart php8.3-fpm

   # Docker
   docker restart <container>
   ```

3. **Verify effective configuration** — Confirm mitigations are active:

   ```shell
   php -i | grep session.upload_progress.enabled
   # Expected: session.upload_progress.enabled => Off => Off
   ```

4. **Network isolation** — If patching and mitigations are not possible, restrict
   network access to the Snipe-IT instance to trusted networks only. Place the
   application behind a WAF or reverse proxy that blocks requests with
   `PHP_SESSION_UPLOAD_PROGRESS` in the request body.

5. **Monitoring** — Monitor application logs for unusual session upload activity.
   The PHP2Shell report page (`/reports/php2shell`) provides real-time inventory
   of runtime exposure status.

### Temporary Exception Governance

If an operator must run a below-floor PHP runtime temporarily:

1. **Document the exception** — Record the host, PHP version, justification,
   owner, and planned remediation date.
2. **Apply all available mitigations** — See "Restart and Isolation Fallback" above.
3. **Set a time limit** — Exceptions should not exceed 7 calendar days without
   re-approval from the security team.
4. **Review weekly** — Check the PHP2Shell report page and CSV export for any
   hosts still showing "exposed" or "mitigated" status.
5. **Close the exception** — Once patched, verify via `php -v` and the PHP2Shell
   report page, then remove the exception record.

### PHP Worker Restart Verification

After applying mitigations, verify PHP workers have restarted:

- **Apache mod_php** — `systemctl status apache2` shows recent restart; `php -i` via
  web request confirms `session.upload_progress.enabled => Off`
- **PHP-FPM** — `systemctl status php8.x-fpm` shows recent restart; check FPM pool
  effective config via `php-fpm -tt` or web-served `phpinfo()`
- **Docker** — `docker inspect --format='{{.State.StartedAt}}' <container>` confirms
  restart after mitigation; `docker exec <container> php -i | grep session.upload_progress`

PHP2Shell mitigations are **temporary** and do not replace upgrading to
PHP 8.5.12, 8.4.27, 8.3.36, or 8.2.35. Systems without patching or adequate
mitigation that are internet-exposed must be isolated or taken offline. A WAF
blocking `PHP_SESSION_UPLOAD_PROGRESS` in request bodies provides partial
protection but is not equivalent to upgrading PHP.

### Release Block-Off Emergency Approval Checklist

Use this checklist when deploying the PHP2Shell remediation during a release
freeze or change block-off window (CVE-2026-109618, CVE-2026-109619):

- [ ] **Production-impacting incident** — Confirm this is a security incident
      requiring emergency remediation outside normal release windows
- [ ] **Director-level or on-call CAB approval** — Obtain approval from a
      director-level stakeholder or on-call Change Advisory Board member
- [ ] **Verbal approval logged within 24 hours** — If verbal approval was given,
      log it in the incident record within 24 hours
- [ ] **Second set of eyes** — A second engineer reviews the deployment changes
      before execution
- [ ] **Blast radius** — Document affected hosts, containers, and environments
- [ ] **Runtime verification evidence** — Capture `php -v` output and PHP2Shell
      report page screenshot or CSV export for each affected host
- [ ] **WAF / isolation status** — Document whether WAF rules or network isolation
      are active as compensating controls
- [ ] **Rollback constraints** — Rollback must not return production to a vulnerable
      PHP runtime without compensating isolation or mitigation
- [ ] **Owner / approver identity** — Record the deployer name and approver name
      (no secrets, tokens, or PHI)
- [ ] **Post-change retro** — Schedule a retro within 5 business days to record
      what broke, what changed, and why the remediation could not wait

### PHP2Shell Closure Evidence Package

The following artifacts are required to close the PHP2Shell remediation for
CVE-2026-109618 and CVE-2026-109619 (October 21, 2026 PHP security releases).

**Required Artifacts:**

1. **Vulnerability scan result** — Scanner output confirming CVE-2026-109618 and
   CVE-2026-109619 are no longer reported for the target runtime
2. **Runtime verification** — `php -v` output from each host/container showing
   PHP 8.5.12, 8.4.27, 8.3.36, or 8.2.35 (or higher). PHP 8.1 and older
   require upgrade, isolation, offline status, or trusted vendor backport
   exception evidence
3. **PHP2Shell inventory report/export** — CSV export from `/reports/php2shell/export`
   showing all tracked runtimes at "patched" status
4. **Regression test evidence** — PHPUnit output from the smoke checklist in
   TESTING.md (see "PHP2Shell Patched-Runtime Smoke Validation")
5. **Emergency approval record** — Completed release block-off checklist (above)
   with approver identification
6. **Rollback / mitigation notes** — Documentation of any active mitigations,
   isolation controls, or vendor backport exceptions still in effect

**Evidence Handling:**

- All PHP2Shell evidence is **Confidential**
- Evidence must **exclude** secrets, bearer tokens, connection strings, private
  keys, database credentials, and PHI
- Evidence must be retained for at least **1 year** to support SOC 2 and GDPR
  audit requirements
- Use placeholder identifiers (e.g., `host-prod-01`) rather than real production
  hostnames in shared documentation
