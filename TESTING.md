# Running the Test Suite

This document is targeted at developers looking to make modifications to this application's code base and want to run the existing test suite.

Before starting, follow the [instructions](README.md#installation) for installing the application locally and ensure you can load it in a browser properly.

## Unit and Feature Tests

Before attempting to run the test suite copy the example environment file for tests and update the values to match your environment:

`cp .env.testing.example .env.testing`

The following should work for running tests in memory with sqlite:
```
# --------------------------------------------
# REQUIRED: BASIC APP SETTINGS
# --------------------------------------------
APP_ENV=testing
APP_DEBUG=true
APP_KEY=base64:glJpcM7BYwWiBggp3SQ/+NlRkqsBQMaGEOjemXqJzOU=
APP_URL=http://localhost:8000
APP_TIMEZONE='UTC'
APP_LOCALE=en-US

# --------------------------------------------
# REQUIRED: DATABASE SETTINGS
# --------------------------------------------
DB_CONNECTION=sqlite_testing
#DB_HOST=127.0.0.1
#DB_PORT=3306
#DB_DATABASE=null
#DB_USERNAME=null
#DB_PASSWORD=null
```

To use MySQL you should update the `DB_` variables to match your local test database:
```
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE={}
DB_USERNAME={}
DB_PASSWORD={}
```

Now you are ready to run the entire test suite from your terminal:

```shell
php artisan test
````

To run individual test files, you can pass the path to the test that you want to run:

```shell
php artisan test tests/Unit/AccessoryTest.php
```

Some tests, like ones concerning LDAP, are marked with the `@group` annotation. Those groups can be run, or excluded, using the `--group` or `--exclude-group` flags:

```shell
php artisan test --group=ldap

php artisan test --exclude-group=ldap
```
This can be helpful if a set of tests are failing because you don't have an extension, like LDAP, installed.

## PHP2Shell Patched-Runtime Smoke Validation

This section documents the smoke verification steps for the PHP2Shell security remediation
(CVE-2026-109618, CVE-2026-109619). Use this checklist after upgrading PHP to a patched
release or after deploying a remediated container image.

### Approved Patched PHP Versions

| Branch | Minimum Patched Version |
|--------|------------------------|
| 8.2    | 8.2.35                 |
| 8.3    | 8.3.36                 |
| 8.4    | 8.4.27                 |
| 8.5    | 8.5.12                 |

### 1. PHP Runtime Verification

```shell
php -v
# Confirm the version matches or exceeds the approved floor for the branch.

php -r 'echo "PHP_VERSION_ID: " . PHP_VERSION_ID . "\n";'
# Approved floor IDs: 80235, 80336, 80427, 80512
```

### 2. Composer Validation

```shell
composer validate --strict
composer check-platform-reqs
```

### 3. Laravel Boot Checks

```shell
php artisan --version
php artisan config:clear
php artisan route:clear
php artisan optimize:clear
```

### 4. PHPUnit Test Filters

```shell
# Asset checkout/checkin
php artisan test --filter=AssetCheckoutTest

# Import workflows
php artisan test --filter=ImportAssetsTest

# PHP2Shell policy classification
php artisan test --filter=PhpRuntimePolicy

# PHP2Shell report and CSV export
php artisan test tests/Feature/Reports/
```

### 5. Manual Smoke Checks

- [ ] **Login** — Authenticate as a superuser via the web UI
- [ ] **Reports** — Navigate to `app/Http/Controllers/ReportsController.php` report pages (Accessories, Depreciation, Activity)
- [ ] **PHP2Shell Report** — Load `/reports/php2shell` and verify inventory rows render
- [ ] **CSV Export** — Download `/reports/php2shell/export` and verify CSV opens without formula injection
- [ ] **Asset Checkout** — Check out an asset to a user and confirm success redirect
- [ ] **Import** — Upload a small CSV via the import page and verify processing
- [ ] **API** — Confirm `routes/api.php` endpoints respond (e.g., `GET /api/v1/hardware`)

### 6. Rollback Warning

> **CRITICAL:** Rollback must not reintroduce an exposed PHP runtime without isolation
> or temporary mitigations (session.upload_progress.enabled=0, fatal_error_backtraces=0).
> If rollback is required, apply runtime mitigations before resuming service.
