<?php

namespace Tests\Feature\Reports;

use App\Models\User;
use App\Services\Runtime\Php2ShellInventory;
use Tests\TestCase;

class Php2ShellCsvExportTest extends TestCase
{
    private function bindFakeInventory(array $rows): void
    {
        $fake = new class($rows) extends Php2ShellInventory
        {
            /** @var array<int, array<string, mixed>> */
            private array $fakeRows;

            /**
             * @param  array<int, array<string, mixed>>  $rows
             */
            public function __construct(array $rows)
            {
                $this->fakeRows = $rows;
            }

            public function collect(?string $basePath = null): array
            {
                return $this->fakeRows;
            }
        };

        $this->app->instance(Php2ShellInventory::class, $fake);
    }

    public function test_unauthorized_user_cannot_export(): void
    {
        $this->actingAs(User::factory()->create())
            ->get(route('reports/php2shell/export'))
            ->assertForbidden();
    }

    public function test_authorized_user_receives_csv(): void
    {
        $rows = require base_path('tests/Fixtures/Runtime/php2shell_csv_rows.php');
        $this->bindFakeInventory($rows);

        $response = $this->actingAs(User::factory()->canViewReports()->create())
            ->get(route('reports/php2shell/export'));

        $response->assertOk()
            ->assertHeader('content-type', 'text/csv; charset=utf-8');

        $disposition = $response->headers->get('content-disposition');
        $this->assertStringContainsString('php2shell', $disposition);
        $this->assertStringContainsString('attachment', $disposition);
    }

    public function test_csv_contains_header_row(): void
    {
        $rows = require base_path('tests/Fixtures/Runtime/php2shell_csv_rows.php');
        $this->bindFakeInventory($rows);

        $response = $this->actingAs(User::factory()->canViewReports()->create())
            ->get(route('reports/php2shell/export'));

        $content = $response->streamedContent();
        $this->assertStringContainsString('Source File', $content);
        $this->assertStringContainsString('PHP Version', $content);
        $this->assertStringContainsString('Status', $content);
    }

    public function test_csv_contains_data_rows(): void
    {
        $rows = require base_path('tests/Fixtures/Runtime/php2shell_csv_rows.php');
        $this->bindFakeInventory($rows);

        $content = $this->actingAs(User::factory()->canViewReports()->create())
            ->get(route('reports/php2shell/export'))
            ->streamedContent();

        $this->assertStringContainsString('Dockerfile', $content);
        $this->assertStringContainsString('8.3.36', $content);
        $this->assertStringContainsString('patched', $content);
    }

    public function test_formula_values_are_escaped_in_csv(): void
    {
        $rows = require base_path('tests/Fixtures/Runtime/php2shell_csv_rows.php');
        $this->bindFakeInventory($rows);

        $content = $this->actingAs(User::factory()->canViewReports()->create())
            ->get(route('reports/php2shell/export'))
            ->streamedContent();

        $this->assertStringNotContainsString('"=CMD', $content, 'Formula starting with = should be escaped.');
        $this->assertStringContainsString('`=CMD', $content, 'Formula should be prefixed with backtick.');
    }
}
