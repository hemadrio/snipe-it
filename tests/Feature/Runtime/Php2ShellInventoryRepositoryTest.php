<?php

namespace Tests\Feature\Runtime;

use App\Services\Runtime\Php2ShellInventory;
use Tests\TestCase;

/**
 * Integration test that collects PHP runtime inventory from the real
 * repository root and verifies all expected source files are represented.
 */
class Php2ShellInventoryRepositoryTest extends TestCase
{
    public function test_collect_from_repository_returns_expected_source_files(): void
    {
        $inventory = app()->make(Php2ShellInventory::class);

        $rows = $inventory->collect();

        $sourceFiles = array_unique(array_map(fn ($r) => $r['source_file'], $rows));

        $this->assertContains('Dockerfile', $sourceFiles);
        $this->assertContains('docker-compose.yml', $sourceFiles);
        $this->assertContains('snipeit.sh', $sourceFiles);
        $this->assertContains('.github/workflows/tests-mysql.yml', $sourceFiles);
        $this->assertContains('ansible/ubuntu/vagrant_playbook.yml', $sourceFiles);
    }

    public function test_collect_from_repository_has_no_uncaught_exceptions(): void
    {
        $inventory = app()->make(Php2ShellInventory::class);

        $rows = $inventory->collect();

        $this->assertNotEmpty($rows, 'Collect should return at least one row');

        foreach ($rows as $row) {
            $this->assertArrayHasKey('status', $row);
            $this->assertArrayHasKey('parse_status', $row);
            $this->assertNotSame('collection_failed', $row['parse_status'], "File {$row['source_file']} failed collection: {$row['reason']}");
        }
    }

    public function test_collect_resolves_service_from_container(): void
    {
        $inventory = app()->make(Php2ShellInventory::class);

        $this->assertInstanceOf(Php2ShellInventory::class, $inventory);
    }
}
