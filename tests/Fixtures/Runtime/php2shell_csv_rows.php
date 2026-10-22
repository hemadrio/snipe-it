<?php

/**
 * PHP2Shell CSV export fixture rows.
 * Includes formula-triggering values for EscapeFormula validation.
 */
return [
    [
        'source_file' => 'Dockerfile',
        'environment_type' => 'docker',
        'php_version' => '8.3.36',
        'php_branch' => '8.3',
        'sapi' => 'apache2handler',
        'status' => 'patched',
        'reason' => 'PHP 8.3.36 meets or exceeds the patched floor for branch 8.3 (8.3.36).',
        'mitigation_status' => 'not_required',
        'owner' => 'infrastructure',
        'last_verified' => '2026-10-22',
    ],
    [
        'source_file' => '=CMD("malicious")',
        'environment_type' => 'docker',
        'php_version' => '8.3.20',
        'php_branch' => '8.3',
        'sapi' => 'apache2handler',
        'status' => 'exposed',
        'reason' => '+HYPERLINK("evil")',
        'mitigation_status' => 'none',
        'owner' => '-@SUM(A1)',
        'last_verified' => '2026-10-22',
    ],
    [
        'source_file' => 'docker-compose.yml',
        'environment_type' => 'compose',
        'php_version' => '8.1.0',
        'php_branch' => '8.1',
        'sapi' => 'unknown',
        'status' => 'unsupported',
        'reason' => 'PHP branch 8.1 has no tracked patched floor.',
        'mitigation_status' => 'none',
        'owner' => 'infrastructure',
        'last_verified' => '2026-10-22',
    ],
    [
        'source_file' => '.github/workflows/tests-mysql.yml',
        'environment_type' => 'ci',
        'php_version' => '8.4',
        'php_branch' => '8.4',
        'sapi' => 'cli',
        'status' => 'unknown',
        'reason' => 'Patch level could not be determined.',
        'mitigation_status' => 'none',
        'owner' => 'ci',
        'last_verified' => '2026-10-22',
    ],
    [
        'source_file' => 'ansible/ubuntu/vagrant_playbook.yml',
        'environment_type' => 'ansible',
        'php_version' => null,
        'php_branch' => null,
        'sapi' => null,
        'status' => 'collection_failed',
        'reason' => 'Unable to parse PHP version.',
        'mitigation_status' => 'N/A',
        'owner' => 'infrastructure',
        'last_verified' => '2026-10-22',
    ],
];
