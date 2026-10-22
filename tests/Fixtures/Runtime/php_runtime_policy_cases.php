<?php

/**
 * Representative test cases for PhpRuntimePolicy::classify().
 *
 * Each entry contains the input parameters and expected output fields.
 * Used as a data provider by PhpRuntimePolicyTest.
 *
 * Format: [label, version, sapi, vendorBackportClaimed, vendorBackportReason, expected]
 */
return [

    // ── Patched versions ────────────────────────────────────────────────

    'patched 8.5.12 apache' => [
        'version' => '8.5.12',
        'sapi' => 'apache2handler',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'patched',
            'branch' => '8.5',
            'patched_floor' => '8.5.12',
            'sapi_exposed' => true,
        ],
    ],

    'patched 8.4.27 fpm' => [
        'version' => '8.4.27',
        'sapi' => 'fpm-fcgi',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'patched',
            'branch' => '8.4',
            'patched_floor' => '8.4.27',
            'sapi_exposed' => true,
        ],
    ],

    'patched 8.3.36 apache' => [
        'version' => '8.3.36',
        'sapi' => 'apache2handler',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'patched',
            'branch' => '8.3',
            'patched_floor' => '8.3.36',
            'sapi_exposed' => true,
        ],
    ],

    'patched 8.2.35 litespeed' => [
        'version' => '8.2.35',
        'sapi' => 'litespeed',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'patched',
            'branch' => '8.2',
            'patched_floor' => '8.2.35',
            'sapi_exposed' => true,
        ],
    ],

    'patched above floor 8.3.40' => [
        'version' => '8.3.40',
        'sapi' => 'apache2handler',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'patched',
            'branch' => '8.3',
            'patched_floor' => '8.3.36',
            'sapi_exposed' => true,
        ],
    ],

    // ── Exposed versions ────────────────────────────────────────────────

    'exposed 8.3.35 apache' => [
        'version' => '8.3.35',
        'sapi' => 'apache2handler',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'exposed',
            'branch' => '8.3',
            'patched_floor' => '8.3.36',
            'sapi_exposed' => true,
        ],
    ],

    'exposed 8.4.26 fpm' => [
        'version' => '8.4.26',
        'sapi' => 'fpm-fcgi',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'exposed',
            'branch' => '8.4',
            'patched_floor' => '8.4.27',
            'sapi_exposed' => true,
        ],
    ],

    'exposed 8.2.0 cgi' => [
        'version' => '8.2.0',
        'sapi' => 'cgi-fcgi',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'exposed',
            'branch' => '8.2',
            'patched_floor' => '8.2.35',
            'sapi_exposed' => true,
        ],
    ],

    // ── Unsupported branches ────────────────────────────────────────────

    'unsupported 8.1.99' => [
        'version' => '8.1.99',
        'sapi' => 'apache2handler',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'unsupported',
            'branch' => '8.1',
            'sapi_exposed' => true,
        ],
    ],

    'unsupported 8.0.30' => [
        'version' => '8.0.30',
        'sapi' => 'fpm-fcgi',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'unsupported',
            'branch' => '8.0',
            'sapi_exposed' => true,
        ],
    ],

    'unsupported 7.4.33' => [
        'version' => '7.4.33',
        'sapi' => 'apache2handler',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'unsupported',
            'branch' => '7.4',
            'sapi_exposed' => true,
        ],
    ],

    'unsupported 5.4.45' => [
        'version' => '5.4.45',
        'sapi' => 'mod_php',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'unsupported',
            'branch' => '5.4',
            'sapi_exposed' => true,
        ],
    ],

    // ── CLI / non-web SAPI ──────────────────────────────────────────────

    'cli exposed version not web-exposed' => [
        'version' => '8.3.35',
        'sapi' => 'cli',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'exposed',
            'branch' => '8.3',
            'sapi_exposed' => false,
        ],
    ],

    'cli patched version' => [
        'version' => '8.3.36',
        'sapi' => 'cli',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'patched',
            'branch' => '8.3',
            'sapi_exposed' => false,
        ],
    ],

    'null sapi patched' => [
        'version' => '8.3.36',
        'sapi' => null,
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'patched',
            'branch' => '8.3',
            'sapi_exposed' => false,
        ],
    ],

    // ── Unknown / malformed ─────────────────────────────────────────────

    'malformed latest' => [
        'version' => 'latest',
        'sapi' => null,
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'unknown',
            'branch' => null,
        ],
    ],

    'malformed php:8.3' => [
        'version' => 'php:8.3',
        'sapi' => null,
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'unknown',
            'branch' => '8.3',
        ],
    ],

    'malformed empty string' => [
        'version' => '',
        'sapi' => null,
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'unknown',
            'branch' => null,
        ],
    ],

    'version without patch 8.3' => [
        'version' => '8.3',
        'sapi' => 'apache2handler',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'unknown',
            'branch' => '8.3',
            'sapi_exposed' => true,
        ],
    ],

    'prefixed PHP 8.3.36' => [
        'version' => 'PHP 8.3.36',
        'sapi' => 'apache2handler',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'patched',
            'branch' => '8.3',
            'sapi_exposed' => true,
        ],
    ],

    'unknown future branch 9.0.1' => [
        'version' => '9.0.1',
        'sapi' => 'apache2handler',
        'vendor_backport_claimed' => false,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'unknown',
            'branch' => '9.0',
            'sapi_exposed' => true,
        ],
    ],

    // ── Vendor backport exception ───────────────────────────────────────

    'vendor backport 8.1 with reason' => [
        'version' => '8.1.28',
        'sapi' => 'apache2handler',
        'vendor_backport_claimed' => true,
        'vendor_backport_reason' => 'Ubuntu 22.04 LTS vendor backport verified by security team.',
        'expected' => [
            'status' => 'vendor_backport_exception',
            'branch' => '8.1',
            'sapi_exposed' => true,
        ],
    ],

    'vendor backport 7.4 without reason' => [
        'version' => '7.4.33',
        'sapi' => 'fpm-fcgi',
        'vendor_backport_claimed' => true,
        'vendor_backport_reason' => null,
        'expected' => [
            'status' => 'vendor_backport_exception',
            'branch' => '7.4',
            'sapi_exposed' => true,
        ],
    ],
];
