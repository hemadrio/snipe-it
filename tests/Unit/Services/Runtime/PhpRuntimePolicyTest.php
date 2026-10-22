<?php

namespace Tests\Unit\Services\Runtime;

use App\Services\Runtime\PhpRuntimePolicy;
use Tests\TestCase;

/**
 * Unit tests for PhpRuntimePolicy::classify().
 *
 * Uses the committed fixture file as a data provider so every representative
 * case (patched, exposed, unsupported, unknown, CLI, vendor backport) is
 * tested from a single source of truth.
 */
class PhpRuntimePolicyTest extends TestCase
{
    private PhpRuntimePolicy $policy;

    protected function setUp(): void
    {
        parent::setUp();
        $this->policy = new PhpRuntimePolicy;
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('fixtureProvider')]
    public function test_classify_matches_fixture_expectations(
        string $version,
        ?string $sapi,
        bool $vendor_backport_claimed,
        ?string $vendor_backport_reason,
        array $expected,
    ): void {
        $result = $this->policy->classify($version, $sapi, $vendor_backport_claimed, $vendor_backport_reason);

        foreach ($expected as $key => $value) {
            $this->assertArrayHasKey($key, $result, "Result must contain key '{$key}'");
            $this->assertSame($value, $result[$key], "Key '{$key}' mismatch for version '{$version}'");
        }
    }

    public static function fixtureProvider(): array
    {
        return require __DIR__.'/../../../Fixtures/Runtime/php_runtime_policy_cases.php';
    }

    public function test_patched_8_3_36_apache_has_status_patched(): void
    {
        $result = $this->policy->classify('8.3.36', 'apache2handler');

        $this->assertSame('patched', $result['status']);
        $this->assertSame('8.3', $result['branch']);
        $this->assertSame('8.3.36', $result['patched_floor']);
        $this->assertTrue($result['sapi_exposed']);
    }

    public function test_exposed_8_3_35_apache_has_status_exposed(): void
    {
        $result = $this->policy->classify('8.3.35', 'apache2handler');

        $this->assertSame('exposed', $result['status']);
        $this->assertSame('8.3', $result['branch']);
        $this->assertSame('8.3.36', $result['patched_floor']);
        $this->assertTrue($result['sapi_exposed']);
    }

    public function test_unsupported_8_1_99_includes_both_cves(): void
    {
        $result = $this->policy->classify('8.1.99', 'apache2handler');

        $this->assertSame('unsupported', $result['status']);
        $this->assertContains('CVE-2026-109618', $result['cves']);
        $this->assertContains('CVE-2026-109619', $result['cves']);
    }

    public function test_classify_reads_config_patched_floors(): void
    {
        $result = $this->policy->classify('8.4.27', 'fpm-fcgi');

        $this->assertSame('patched', $result['status']);
        $this->assertSame('8.4.27', $result['patched_floor']);
    }

    public function test_cli_sapi_is_not_web_exposed(): void
    {
        $result = $this->policy->classify('8.3.35', 'cli');

        $this->assertSame('exposed', $result['status']);
        $this->assertFalse($result['sapi_exposed']);
    }

    public function test_malformed_version_returns_unknown_without_exception(): void
    {
        $result = $this->policy->classify('latest');

        $this->assertSame('unknown', $result['status']);
        $this->assertNull($result['branch']);
    }

    public function test_empty_version_returns_unknown(): void
    {
        $result = $this->policy->classify('');

        $this->assertSame('unknown', $result['status']);
    }

    public function test_version_without_patch_returns_unknown(): void
    {
        $result = $this->policy->classify('8.3', 'apache2handler');

        $this->assertSame('unknown', $result['status']);
        $this->assertSame('8.3', $result['branch']);
    }

    public function test_result_contains_all_expected_keys(): void
    {
        $result = $this->policy->classify('8.3.36', 'apache2handler');

        $expectedKeys = [
            'version', 'branch', 'major', 'minor', 'patch',
            'patched_floor', 'status', 'reason', 'sapi',
            'sapi_exposed', 'cves', 'next_action',
        ];

        foreach ($expectedKeys as $key) {
            $this->assertArrayHasKey($key, $result, "Result must contain key '{$key}'");
        }
    }

    public function test_vendor_backport_produces_distinct_status(): void
    {
        $result = $this->policy->classify('8.1.28', 'apache2handler', true, 'Ubuntu LTS backport');

        $this->assertSame('vendor_backport_exception', $result['status']);
        $this->assertStringContainsString('Ubuntu LTS backport', $result['reason']);
    }
}
