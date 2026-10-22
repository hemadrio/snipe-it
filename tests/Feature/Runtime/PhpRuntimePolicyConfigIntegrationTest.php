<?php

namespace Tests\Feature\Runtime;

use App\Services\Runtime\PhpRuntimePolicy;
use Tests\TestCase;

/**
 * Verifies that PhpRuntimePolicy resolves from the Laravel container and
 * reads config/php_runtime_security.php rather than duplicating patched floors.
 */
class PhpRuntimePolicyConfigIntegrationTest extends TestCase
{
    public function test_service_resolves_from_container(): void
    {
        $policy = app()->make(PhpRuntimePolicy::class);

        $this->assertInstanceOf(PhpRuntimePolicy::class, $policy);
    }

    public function test_classify_patched_8_4_27_fpm_reads_config(): void
    {
        /** @var PhpRuntimePolicy $policy */
        $policy = app()->make(PhpRuntimePolicy::class);

        $result = $policy->classify('8.4.27', 'fpm-fcgi');

        $this->assertSame('patched', $result['status']);
        $this->assertSame('8.4', $result['branch']);
        $this->assertSame('8.4.27', $result['patched_floor']);
        $this->assertTrue($result['sapi_exposed']);
        $this->assertContains('CVE-2026-109618', $result['cves']);
        $this->assertContains('CVE-2026-109619', $result['cves']);

        $configFloor = config('php_runtime_security.patched_floors.8.4');
        $this->assertSame($configFloor, $result['patched_floor'], 'Service must read floors from config, not hard-code them.');
    }

    public function test_config_change_is_reflected_in_classification(): void
    {
        config(['php_runtime_security.patched_floors.8.4' => '8.4.99']);

        /** @var PhpRuntimePolicy $policy */
        $policy = app()->make(PhpRuntimePolicy::class);

        $result = $policy->classify('8.4.27', 'fpm-fcgi');

        $this->assertSame('exposed', $result['status'], 'Changing the config floor must change the classification.');
        $this->assertSame('8.4.99', $result['patched_floor']);
    }
}
