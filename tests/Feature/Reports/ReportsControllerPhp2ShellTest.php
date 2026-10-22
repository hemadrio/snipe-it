<?php

namespace Tests\Feature\Reports;

use App\Models\User;
use App\Services\Runtime\Php2ShellInventory;
use Tests\TestCase;

class ReportsControllerPhp2ShellTest extends TestCase
{
    private function bindFakeInventory(array $rows): void
    {
        $fake = new class($rows) extends Php2ShellInventory
        {
            private array $fakeRows;

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

    public function test_unauthenticated_report_request_redirects(): void
    {
        $this->get(route('reports/php2shell'))
            ->assertRedirect();
    }

    public function test_unauthenticated_export_request_redirects(): void
    {
        $this->get(route('reports/php2shell/export'))
            ->assertRedirect();
    }

    public function test_unauthorized_user_gets_403_on_report(): void
    {
        $this->actingAs(User::factory()->create())
            ->get(route('reports/php2shell'))
            ->assertForbidden();
    }

    public function test_unauthorized_user_gets_403_on_export(): void
    {
        $this->actingAs(User::factory()->create())
            ->get(route('reports/php2shell/export'))
            ->assertForbidden();
    }

    public function test_authorized_user_gets_200_on_report(): void
    {
        $this->bindFakeInventory([]);

        $this->actingAs(User::factory()->canViewReports()->create())
            ->get(route('reports/php2shell'))
            ->assertOk();
    }

    public function test_authorized_user_gets_csv_export(): void
    {
        $rows = require base_path('tests/Fixtures/Runtime/php2shell_csv_rows.php');
        $this->bindFakeInventory($rows);

        $response = $this->actingAs(User::factory()->canViewReports()->create())
            ->get(route('reports/php2shell/export'));

        $response->assertOk()
            ->assertHeader('content-type', 'text/csv; charset=utf-8');

        $disposition = $response->headers->get('content-disposition');
        $this->assertStringContainsString('.csv', $disposition);
    }

    public function test_csv_headers_are_not_formula_escaped(): void
    {
        $rows = require base_path('tests/Fixtures/Runtime/php2shell_csv_rows.php');
        $this->bindFakeInventory($rows);

        $content = $this->actingAs(User::factory()->canViewReports()->create())
            ->get(route('reports/php2shell/export'))
            ->streamedContent();

        $lines = explode("\n", trim($content));
        $headerLine = $lines[0];

        $this->assertStringNotContainsString('`Source', $headerLine, 'Header should not be formula-escaped.');
        $this->assertStringContainsString('Source File', $headerLine);
    }

    public function test_csv_formula_values_are_escaped(): void
    {
        $rows = [
            [
                'source_file' => '=CMD("evil")',
                'environment_type' => '+SUM(1,1)',
                'php_version' => '8.3.20',
                'php_branch' => '8.3',
                'sapi' => '-10',
                'status' => 'exposed',
                'reason' => '@host',
                'mitigation_status' => '	tab-prefixed',
                'owner' => "\rCR-prefixed",
                'last_verified' => '2026-10-22',
            ],
        ];
        $this->bindFakeInventory($rows);

        $content = $this->actingAs(User::factory()->canViewReports()->create())
            ->get(route('reports/php2shell/export'))
            ->streamedContent();

        $this->assertStringContainsString('`=CMD', $content, 'Equals formula should be escaped.');
        $this->assertStringContainsString('`+SUM', $content, 'Plus formula should be escaped.');
        $this->assertStringContainsString('`-10', $content, 'Minus formula should be escaped.');
        $this->assertStringContainsString('`@host', $content, 'At-sign formula should be escaped.');
    }

    public function test_empty_inventory_returns_csv_with_headers_only(): void
    {
        $this->bindFakeInventory([]);

        $content = $this->actingAs(User::factory()->canViewReports()->create())
            ->get(route('reports/php2shell/export'))
            ->streamedContent();

        $this->assertStringContainsString('Source File', $content);
        $lines = array_filter(explode("\n", trim($content)));
        $this->assertCount(1, $lines, 'Empty inventory should produce header row only.');
    }
}
