<?php

namespace Tests\Feature\Reports;

use App\Models\User;
use App\Services\Runtime\Php2ShellInventory;
use Tests\TestCase;

class Php2ShellReportTest extends TestCase
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

    public function test_unauthorized_user_cannot_access_php2shell_report(): void
    {
        $this->actingAs(User::factory()->create())
            ->get(route('reports/php2shell'))
            ->assertForbidden();
    }

    public function test_unauthenticated_user_is_redirected(): void
    {
        $this->get(route('reports/php2shell'))
            ->assertRedirect();
    }

    public function test_authorized_user_can_view_php2shell_report(): void
    {
        $rows = require base_path('tests/Fixtures/Runtime/php2shell_report_rows.php');
        $this->bindFakeInventory($rows);

        $this->actingAs(User::factory()->canViewReports()->create())
            ->get(route('reports/php2shell'))
            ->assertOk()
            ->assertSee('Dockerfile')
            ->assertSee('CVE-2026-109618');
    }

    public function test_report_shows_all_status_labels(): void
    {
        $rows = require base_path('tests/Fixtures/Runtime/php2shell_report_rows.php');
        $this->bindFakeInventory($rows);

        $response = $this->actingAs(User::factory()->canViewReports()->create())
            ->get(route('reports/php2shell'));

        $response->assertOk()
            ->assertSee('Patched')
            ->assertSee('Exposed')
            ->assertSee('Unsupported')
            ->assertSee('Unknown')
            ->assertSee('Mitigated')
            ->assertSee('Collection Failed');
    }

    public function test_report_shows_empty_state_when_no_rows(): void
    {
        $this->bindFakeInventory([]);

        $this->actingAs(User::factory()->canViewReports()->create())
            ->get(route('reports/php2shell'))
            ->assertOk()
            ->assertSee('No PHP runtime evidence was collected');
    }

    public function test_report_handles_collector_exception_gracefully(): void
    {
        $fake = new class extends Php2ShellInventory
        {
            public function __construct() {}

            public function collect(?string $basePath = null): array
            {
                throw new \RuntimeException('Simulated failure');
            }
        };

        $this->app->instance(Php2ShellInventory::class, $fake);

        $this->actingAs(User::factory()->canViewReports()->create())
            ->get(route('reports/php2shell'))
            ->assertOk()
            ->assertSee('Collection Failed')
            ->assertSee('Inventory collection encountered an error');
    }
}
