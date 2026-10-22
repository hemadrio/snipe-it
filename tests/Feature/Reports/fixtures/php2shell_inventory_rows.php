<?php

/**
 * PHP2Shell inventory fixture rows for feature tests.
 *
 * Covers all required source types (docker, compose, ci, ansible, installer,
 * staging, production) and all exposure statuses (patched, exposed, unsupported,
 * unknown, mitigated, collection_failed).
 */
return [
    [
        'php_version' => '8.3.36',
        'sapi' => 'apache2handler',
        'source' => 'docker',
        'exposure_status' => 'patched',
        'mitigation_status' => 'not_required',
        'owner' => 'infrastructure',
        'last_verified_at' => '2026-10-22T18:00:00Z',
    ],
    [
        'php_version' => '8.3.20',
        'sapi' => 'fpm-fcgi',
        'source' => 'compose',
        'exposure_status' => 'exposed',
        'mitigation_status' => 'none',
        'owner' => 'infrastructure',
        'last_verified_at' => '2026-10-22T18:00:00Z',
    ],
    [
        'php_version' => '8.4',
        'sapi' => 'cli',
        'source' => 'ci',
        'exposure_status' => 'unknown',
        'mitigation_status' => 'none',
        'owner' => 'ci-team',
        'last_verified_at' => '2026-10-22T18:00:00Z',
    ],
    [
        'php_version' => '8.1.30',
        'sapi' => 'apache2handler',
        'source' => 'ansible',
        'exposure_status' => 'unsupported',
        'mitigation_status' => 'none',
        'owner' => 'infrastructure',
        'last_verified_at' => '2026-10-22T18:00:00Z',
    ],
    [
        'php_version' => '8.2.30',
        'sapi' => 'apache2handler',
        'source' => 'installer',
        'exposure_status' => 'mitigated',
        'mitigation_status' => 'session.upload_progress.enabled=0',
        'owner' => 'operations',
        'last_verified_at' => '2026-10-22T18:00:00Z',
    ],
    [
        'php_version' => null,
        'sapi' => null,
        'source' => 'staging',
        'exposure_status' => 'collection_failed',
        'mitigation_status' => 'N/A',
        'owner' => 'infrastructure',
        'last_verified_at' => '2026-10-22T18:00:00Z',
    ],
    [
        'php_version' => '8.4.27',
        'sapi' => 'fpm-fcgi',
        'source' => 'production',
        'exposure_status' => 'patched',
        'mitigation_status' => 'not_required',
        'owner' => 'platform-team',
        'last_verified_at' => '2026-10-22T18:00:00Z',
    ],
];
