<?php

namespace Tests\Feature\Reports;

use App\Services\Runtime\PhpRuntimePolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class PhpRuntimePolicyTest extends TestCase
{
    private PhpRuntimePolicy $policy;

    protected function setUp(): void
    {
        parent::setUp();
        $this->policy = $this->app->make(PhpRuntimePolicy::class);
    }

    #[DataProvider('patchedVersionsProvider')]
    public function test_patched_versions_are_accepted(string $version): void
    {
        $result = $this->policy->classify($version);
        $this->assertSame('patched', $result['status'], "Expected {$version} to be classified as patched, got {$result['status']}: {$result['reason']}");
    }

    /**
     * @return array<string, array{string}>
     */
    public static function patchedVersionsProvider(): array
    {
        return [
            'PHP 8.2.35 (exact floor)' => ['8.2.35'],
            'PHP 8.3.36 (exact floor)' => ['8.3.36'],
            'PHP 8.4.27 (exact floor)' => ['8.4.27'],
            'PHP 8.5.12 (exact floor)' => ['8.5.12'],
            'PHP 8.3.37 (above floor)' => ['8.3.37'],
            'PHP 8.4.30 (above floor)' => ['8.4.30'],
            'PHP 8.5.20 (above floor)' => ['8.5.20'],
            'PHP 8.2.40 (above floor)' => ['8.2.40'],
        ];
    }

    #[DataProvider('exposedVersionsProvider')]
    public function test_exposed_versions_are_rejected(string $version): void
    {
        $result = $this->policy->classify($version);
        $this->assertSame('exposed', $result['status'], "Expected {$version} to be classified as exposed, got {$result['status']}: {$result['reason']}");
    }

    /**
     * @return array<string, array{string}>
     */
    public static function exposedVersionsProvider(): array
    {
        return [
            'PHP 8.2.34 (one below floor)' => ['8.2.34'],
            'PHP 8.3.35 (one below floor)' => ['8.3.35'],
            'PHP 8.4.26 (one below floor)' => ['8.4.26'],
            'PHP 8.5.11 (one below floor)' => ['8.5.11'],
            'PHP 8.3.20 (well below floor)' => ['8.3.20'],
            'PHP 8.2.0 (earliest in branch)' => ['8.2.0'],
        ];
    }

    #[DataProvider('unsupportedVersionsProvider')]
    public function test_unsupported_versions_are_rejected(string $version): void
    {
        $result = $this->policy->classify($version);
        $this->assertSame('unsupported', $result['status'], "Expected {$version} to be classified as unsupported, got {$result['status']}: {$result['reason']}");
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unsupportedVersionsProvider(): array
    {
        return [
            'PHP 8.1.99' => ['8.1.99'],
            'PHP 8.0.30' => ['8.0.30'],
            'PHP 7.4.33' => ['7.4.33'],
            'PHP 7.3.0' => ['7.3.0'],
            'PHP 5.6.40' => ['5.6.40'],
        ];
    }

    #[DataProvider('workerModelProvider')]
    public function test_worker_models_produce_explicit_sapi_values(string $sapi): void
    {
        $result = $this->policy->classify('8.3.36', $sapi);
        $this->assertSame($sapi, $result['sapi'], "Worker model {$sapi} should be preserved in the result.");
        $this->assertArrayHasKey('sapi_exposed', $result);
        $this->assertIsBool($result['sapi_exposed']);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function workerModelProvider(): array
    {
        return [
            'Apache/mod_php' => ['apache2handler'],
            'PHP-FPM' => ['fpm-fcgi'],
            'php-cgi' => ['cgi-fcgi'],
            'LiteSpeed' => ['litespeed'],
            'unknown' => ['unknown'],
            'CLI' => ['cli'],
        ];
    }

    public function test_distro_suffixed_version_is_accepted(): void
    {
        $result = $this->policy->classify('8.3.36-ubuntu1');
        $this->assertContains(
            $result['status'],
            ['patched', 'unknown'],
            'Distro-suffixed version should be classified as patched or unknown (if suffix parsing fails).'
        );
    }

    public function test_vendor_backport_exception_for_unsupported_branch(): void
    {
        $result = $this->policy->classify('8.1.30', null, true, 'Debian security team backport');
        $this->assertSame('vendor_backport_exception', $result['status']);
        $this->assertStringContainsString('backport', $result['reason']);
    }

    public function test_missing_patch_level_returns_unknown(): void
    {
        $result = $this->policy->classify('8.3');
        $this->assertSame('unknown', $result['status']);
        $this->assertStringContainsString('patch component', $result['reason']);
    }

    public function test_malformed_version_returns_unknown(): void
    {
        $result = $this->policy->classify('not-a-version');
        $this->assertSame('unknown', $result['status']);
    }

    public function test_exposed_result_includes_cves(): void
    {
        $result = $this->policy->classify('8.3.20');
        $this->assertSame('exposed', $result['status']);
        $this->assertNotEmpty($result['cves']);
        $this->assertContains('CVE-2026-109618', $result['cves']);
        $this->assertContains('CVE-2026-109619', $result['cves']);
    }
}
