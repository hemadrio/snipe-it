<?php

namespace Tests\Unit\Runtime;

use Tests\TestCase;

/**
 * Asserts that config/php_runtime_security.php loads through the Laravel
 * config repository and contains the approved PHP2Shell policy values
 * matching the October 21, 2026 security releases.
 */
class PhpRuntimeSecurityConfigTest extends TestCase
{
    public function test_patched_floors_contain_exact_branch_versions(): void
    {
        $floors = config('php_runtime_security.patched_floors');

        $this->assertIsArray($floors);
        $this->assertSame('8.5.12', $floors['8']['5']);
        $this->assertSame('8.4.27', $floors['8']['4']);
        $this->assertSame('8.3.36', $floors['8']['3']);
        $this->assertSame('8.2.35', $floors['8']['2']);
    }

    public function test_patched_floor_accessible_via_dot_notation(): void
    {
        $this->assertSame('8.3.36', config('php_runtime_security.patched_floors.8.3'));
    }

    public function test_affected_cves_contain_both_identifiers(): void
    {
        $cves = config('php_runtime_security.affected_cves');

        $this->assertIsArray($cves);
        $this->assertContains('CVE-2026-109618', $cves);
        $this->assertContains('CVE-2026-109619', $cves);
        $this->assertCount(2, $cves);
    }

    public function test_patch_released_on_is_correct_date(): void
    {
        $this->assertSame('2026-10-21', config('php_runtime_security.patch_released_on'));
    }

    public function test_unsupported_branches_include_eol_versions(): void
    {
        $unsupported = config('php_runtime_security.unsupported_branches');

        $this->assertIsArray($unsupported);
        $this->assertContains('5.4', $unsupported);
        $this->assertContains('7.4', $unsupported);
        $this->assertContains('8.0', $unsupported);
        $this->assertContains('8.1', $unsupported);
    }

    public function test_unsupported_branches_do_not_include_supported_versions(): void
    {
        $unsupported = config('php_runtime_security.unsupported_branches');

        $this->assertNotContains('8.2', $unsupported);
        $this->assertNotContains('8.3', $unsupported);
        $this->assertNotContains('8.4', $unsupported);
        $this->assertNotContains('8.5', $unsupported);
    }

    public function test_exposed_sapis_lists_incident_scope_entries(): void
    {
        $sapis = config('php_runtime_security.exposed_sapis');

        $this->assertIsArray($sapis);
        $this->assertContains('apache2handler', $sapis);
        $this->assertContains('fpm-fcgi', $sapis);
        $this->assertContains('cgi-fcgi', $sapis);
        $this->assertContains('litespeed', $sapis);
        $this->assertContains('php-fpm', $sapis);
        $this->assertContains('php-cgi', $sapis);
    }

    public function test_statuses_contain_all_classification_labels(): void
    {
        $statuses = config('php_runtime_security.statuses');

        $this->assertIsArray($statuses);
        $this->assertContains('patched', $statuses);
        $this->assertContains('exposed', $statuses);
        $this->assertContains('unsupported', $statuses);
        $this->assertContains('mitigated', $statuses);
        $this->assertContains('vendor_backport_exception', $statuses);
        $this->assertContains('unknown', $statuses);
        $this->assertContains('collection_failed', $statuses);
    }

    public function test_temporary_mitigations_is_a_non_empty_array(): void
    {
        $mitigations = config('php_runtime_security.temporary_mitigations');

        $this->assertIsArray($mitigations);
        $this->assertNotEmpty($mitigations);
    }

    public function test_patched_floors_dot_notation_resolves_all_branches(): void
    {
        $expected = [
            '8.5' => '8.5.12',
            '8.4' => '8.4.27',
            '8.3' => '8.3.36',
            '8.2' => '8.2.35',
        ];

        foreach ($expected as $branch => $version) {
            $this->assertSame(
                $version,
                config("php_runtime_security.patched_floors.{$branch}"),
                "Dot-notation access for branch {$branch} must return {$version}"
            );
        }
    }
}
