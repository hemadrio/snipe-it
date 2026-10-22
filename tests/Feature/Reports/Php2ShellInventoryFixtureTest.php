<?php

namespace Tests\Feature\Reports;

use Tests\TestCase;

class Php2ShellInventoryFixtureTest extends TestCase
{
    /** @var array<int, array<string, mixed>> */
    private array $fixtureRows;

    protected function setUp(): void
    {
        parent::setUp();
        $this->fixtureRows = require base_path('tests/Feature/Reports/fixtures/php2shell_inventory_rows.php');
    }

    public function test_fixture_has_required_source_types(): void
    {
        $sources = array_column($this->fixtureRows, 'source');
        $requiredSources = ['docker', 'compose', 'ci', 'ansible', 'installer', 'staging', 'production'];

        foreach ($requiredSources as $source) {
            $this->assertContains($source, $sources, "Fixture must include a row with source '{$source}'.");
        }
    }

    public function test_fixture_rows_have_required_fields(): void
    {
        $requiredFields = ['php_version', 'sapi', 'source', 'exposure_status', 'mitigation_status', 'owner', 'last_verified_at'];

        foreach ($this->fixtureRows as $i => $row) {
            foreach ($requiredFields as $field) {
                $this->assertArrayHasKey($field, $row, "Fixture row {$i} (source: {$row['source']}) is missing required field '{$field}'.");
            }
        }
    }

    public function test_fixture_covers_all_exposure_statuses(): void
    {
        $statuses = array_unique(array_column($this->fixtureRows, 'exposure_status'));
        $expectedStatuses = ['patched', 'exposed', 'unsupported', 'unknown', 'mitigated', 'collection_failed'];

        foreach ($expectedStatuses as $status) {
            $this->assertContains($status, $statuses, "Fixture must include a row with exposure_status '{$status}'.");
        }
    }

    public function test_fixture_rows_do_not_contain_secrets(): void
    {
        $secretPatterns = ['/password/i', '/secret/i', '/bearer/i', '/token=[A-Za-z0-9]/i', '/DB_PASSWORD/i'];

        foreach ($this->fixtureRows as $i => $row) {
            $serialized = json_encode($row);
            foreach ($secretPatterns as $pattern) {
                $this->assertDoesNotMatchRegularExpression(
                    $pattern,
                    $serialized,
                    "Fixture row {$i} may contain a secret value (matched {$pattern})."
                );
            }
        }
    }

    public function test_fixture_has_null_sapi_for_collection_failed(): void
    {
        foreach ($this->fixtureRows as $row) {
            if ($row['exposure_status'] === 'collection_failed') {
                $this->assertNull($row['sapi'], 'Collection-failed rows should have null sapi.');
            }
        }
    }
}
