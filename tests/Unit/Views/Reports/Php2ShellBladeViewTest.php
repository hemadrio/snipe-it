<?php

namespace Tests\Unit\Views\Reports;

use Illuminate\Support\MessageBag;
use Tests\TestCase;

class Php2ShellBladeViewTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        view()->share('debug_in_production', false);
        view()->share('errors', new MessageBag);
    }

    public function test_view_renders_patched_status(): void
    {
        $rows = [['source_file' => 'Dockerfile', 'environment_type' => 'docker', 'php_version' => '8.3.36', 'php_branch' => '8.3', 'sapi' => 'apache2handler', 'status' => 'patched', 'reason' => 'Meets floor.', 'mitigation_status' => 'not_required', 'owner' => 'infra', 'last_verified' => '2026-10-22']];

        $view = $this->view('reports.php2shell', compact('rows'));

        $view->assertSee('Patched');
        $view->assertSee('Dockerfile');
    }

    public function test_view_renders_exposed_status(): void
    {
        $rows = [['source_file' => 'Dockerfile', 'environment_type' => 'docker', 'php_version' => '8.3.20', 'php_branch' => '8.3', 'sapi' => 'apache2handler', 'status' => 'exposed', 'reason' => 'Below floor.', 'mitigation_status' => 'none', 'owner' => 'infra', 'last_verified' => '2026-10-22']];

        $view = $this->view('reports.php2shell', compact('rows'));

        $view->assertSee('Exposed');
    }

    public function test_view_renders_unsupported_status(): void
    {
        $rows = [['source_file' => 'docker-compose.yml', 'environment_type' => 'compose', 'php_version' => '8.1.0', 'php_branch' => '8.1', 'sapi' => 'unknown', 'status' => 'unsupported', 'reason' => 'No floor.', 'mitigation_status' => 'none', 'owner' => 'infra', 'last_verified' => '2026-10-22']];

        $view = $this->view('reports.php2shell', compact('rows'));

        $view->assertSee('Unsupported');
    }

    public function test_view_renders_unknown_status(): void
    {
        $rows = [['source_file' => 'ci.yml', 'environment_type' => 'ci', 'php_version' => '8.4', 'php_branch' => '8.4', 'sapi' => 'cli', 'status' => 'unknown', 'reason' => 'Cannot determine.', 'mitigation_status' => 'none', 'owner' => 'ci', 'last_verified' => '2026-10-22']];

        $view = $this->view('reports.php2shell', compact('rows'));

        $view->assertSee('Unknown');
    }

    public function test_view_renders_collection_failed_status(): void
    {
        $rows = [['source_file' => 'playbook.yml', 'environment_type' => 'ansible', 'php_version' => null, 'php_branch' => null, 'sapi' => null, 'status' => 'collection_failed', 'reason' => 'Parse error.', 'mitigation_status' => 'N/A', 'owner' => 'infra', 'last_verified' => '2026-10-22']];

        $view = $this->view('reports.php2shell', compact('rows'));

        $view->assertSee('Collection Failed');
        $view->assertSee('Parse error.');
    }

    public function test_view_renders_empty_state(): void
    {
        $rows = [];

        $view = $this->view('reports.php2shell', compact('rows'));

        $view->assertSee('No PHP runtime evidence was collected');
    }

    public function test_view_escapes_html_in_row_values(): void
    {
        $rows = [['source_file' => '<script>alert("xss")</script>', 'environment_type' => 'docker', 'php_version' => '8.3.36', 'php_branch' => '8.3', 'sapi' => 'cli', 'status' => 'patched', 'reason' => 'OK', 'mitigation_status' => 'none', 'owner' => 'test', 'last_verified' => '2026-10-22']];

        $view = $this->view('reports.php2shell', compact('rows'));

        $view->assertDontSee('<script>alert("xss")</script>', false);
        $view->assertSee('&lt;script&gt;', false);
    }
}
