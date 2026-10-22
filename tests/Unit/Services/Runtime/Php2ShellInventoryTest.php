<?php

namespace Tests\Unit\Services\Runtime;

use App\Services\Runtime\Php2ShellInventory;
use App\Services\Runtime\PhpRuntimePolicy;
use Tests\TestCase;

/**
 * Unit tests for Php2ShellInventory using committed fixture files.
 *
 * Tests verify fixture parsing, classification delegation, multi-runtime
 * matrix handling, and missing-file collection_failed rows.
 */
class Php2ShellInventoryTest extends TestCase
{
    private Php2ShellInventory $inventory;

    private string $fixtureBasePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->inventory = new Php2ShellInventory(new PhpRuntimePolicy);
        $this->fixtureBasePath = __DIR__.'/../../../Fixtures/Runtime/php2shell_inventory';
    }

    public function test_dockerfile_fixture_detects_php_8_3_and_apache(): void
    {
        $rows = $this->inventory->collect($this->fixtureBasePath);

        $dockerfileRows = array_values(array_filter($rows, fn ($r) => $r['source_file'] === 'Dockerfile'));

        $this->assertNotEmpty($dockerfileRows, 'Should detect PHP from Dockerfile fixture');

        $php83Row = null;
        foreach ($dockerfileRows as $row) {
            if ($row['php_version'] === '8.3') {
                $php83Row = $row;
                break;
            }
        }

        $this->assertNotNull($php83Row, 'Should detect PHP 8.3 from Dockerfile fixture');
        $this->assertSame('apache2handler', $php83Row['sapi']);
        $this->assertSame('container', $php83Row['environment_type']);
        $this->assertSame('parsed', $php83Row['parse_status']);
    }

    public function test_dockerfile_fixture_classifies_php_8_3_as_exposed(): void
    {
        $rows = $this->inventory->collect($this->fixtureBasePath);

        $dockerfileRows = array_filter($rows, fn ($r) => $r['source_file'] === 'Dockerfile' && $r['php_version'] === '8.3');
        $php83Row = array_values($dockerfileRows)[0] ?? null;

        $this->assertNotNull($php83Row);

        $classification = (new PhpRuntimePolicy)->classify('8.3', 'apache2handler');
        $this->assertSame($classification['status'], $php83Row['status']);
    }

    public function test_github_actions_fixture_detects_php_matrix_versions(): void
    {
        $rows = $this->inventory->collect($this->fixtureBasePath);

        $ciRows = array_values(array_filter($rows, fn ($r) => $r['source_file'] === '.github/workflows/tests-mysql.yml'));

        $this->assertCount(4, $ciRows, 'Should detect all 4 PHP versions from CI matrix');

        $versions = array_map(fn ($r) => $r['php_version'], $ciRows);
        $this->assertContains('8.2', $versions);
        $this->assertContains('8.3', $versions);
        $this->assertContains('8.4', $versions);
        $this->assertContains('8.5', $versions);

        foreach ($ciRows as $row) {
            $this->assertSame('cli', $row['sapi']);
            $this->assertSame('ci', $row['environment_type']);
            $this->assertSame('parsed', $row['parse_status']);
        }
    }

    public function test_installer_script_fixture_detects_multiple_php_branches(): void
    {
        $rows = $this->inventory->collect($this->fixtureBasePath);

        $installerRows = array_values(array_filter($rows, fn ($r) => $r['source_file'] === 'snipeit.sh'));

        $this->assertNotEmpty($installerRows, 'Should detect PHP versions from installer script');

        $versions = array_unique(array_map(fn ($r) => $r['php_version'], $installerRows));
        $this->assertContains('8.4', $versions);
        $this->assertContains('8.2', $versions);
        $this->assertContains('8.3', $versions);
    }

    public function test_ansible_fixture_detects_unversioned_libapache2_mod_php(): void
    {
        $rows = $this->inventory->collect($this->fixtureBasePath);

        $ansibleRows = array_values(array_filter($rows, fn ($r) => $r['source_file'] === 'ansible/ubuntu/vagrant_playbook.yml'));

        $this->assertNotEmpty($ansibleRows, 'Should detect PHP from Ansible playbook');

        $unversionedRows = array_filter($ansibleRows, fn ($r) => $r['parse_status'] === 'runtime_resolved');
        $this->assertNotEmpty($unversionedRows, 'Should detect unversioned libapache2-mod-php');
    }

    public function test_docker_compose_fixture_detects_image_reference(): void
    {
        $rows = $this->inventory->collect($this->fixtureBasePath);

        $composeRows = array_values(array_filter($rows, fn ($r) => $r['source_file'] === 'docker-compose.yml'));

        $this->assertNotEmpty($composeRows, 'Should detect image from docker-compose.yml');
        $this->assertSame('container', $composeRows[0]['environment_type']);
    }

    public function test_missing_file_produces_collection_failed_row(): void
    {
        $nonExistentBase = __DIR__.'/../../../Fixtures/Runtime/php2shell_inventory_nonexistent';

        $rows = $this->inventory->collect($nonExistentBase);

        $this->assertNotEmpty($rows, 'Should produce rows even when files are missing');

        foreach ($rows as $row) {
            $this->assertSame('collection_failed', $row['status']);
            $this->assertSame('collection_failed', $row['parse_status']);
            $this->assertStringContainsString('not found', $row['reason']);
        }
    }

    public function test_missing_single_file_has_correct_source_file(): void
    {
        $tempDir = sys_get_temp_dir().'/php2shell_test_'.uniqid();
        mkdir($tempDir, 0755, true);

        try {
            $rows = $this->inventory->collect($tempDir);

            $dockerfileRow = null;
            foreach ($rows as $row) {
                if ($row['source_file'] === 'Dockerfile') {
                    $dockerfileRow = $row;
                    break;
                }
            }

            $this->assertNotNull($dockerfileRow, 'Should have a row for Dockerfile');
            $this->assertSame('collection_failed', $dockerfileRow['status']);
            $this->assertSame('Dockerfile', $dockerfileRow['source_file']);
        } finally {
            rmdir($tempDir);
        }
    }

    public function test_all_rows_have_required_fields(): void
    {
        $rows = $this->inventory->collect($this->fixtureBasePath);

        $requiredKeys = [
            'source_file', 'source_label', 'environment_type',
            'php_version', 'php_branch', 'sapi', 'worker_model',
            'status', 'reason', 'cves', 'mitigation_status',
            'owner', 'last_verified_at', 'parse_status',
        ];

        foreach ($rows as $i => $row) {
            foreach ($requiredKeys as $key) {
                $this->assertArrayHasKey($key, $row, "Row {$i} ({$row['source_file']}) missing key: {$key}");
            }
        }
    }

    public function test_all_fixture_source_files_represented(): void
    {
        $rows = $this->inventory->collect($this->fixtureBasePath);

        $sourceFiles = array_unique(array_map(fn ($r) => $r['source_file'], $rows));

        $this->assertContains('Dockerfile', $sourceFiles);
        $this->assertContains('docker-compose.yml', $sourceFiles);
        $this->assertContains('snipeit.sh', $sourceFiles);
        $this->assertContains('.github/workflows/tests-mysql.yml', $sourceFiles);
        $this->assertContains('ansible/ubuntu/vagrant_playbook.yml', $sourceFiles);
    }

    public function test_classification_is_delegated_to_policy(): void
    {
        $rows = $this->inventory->collect($this->fixtureBasePath);

        $policy = new PhpRuntimePolicy;

        $parsedRows = array_filter($rows, fn ($r) => $r['parse_status'] === 'parsed' && $r['php_version'] !== null);

        foreach ($parsedRows as $row) {
            $expected = $policy->classify($row['php_version'], $row['sapi']);
            $this->assertSame(
                $expected['status'],
                $row['status'],
                "Classification mismatch for {$row['source_file']} PHP {$row['php_version']}: expected {$expected['status']}, got {$row['status']}"
            );
        }
    }
}
