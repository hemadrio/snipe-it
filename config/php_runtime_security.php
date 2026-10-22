<?php

/*
|--------------------------------------------------------------------------
| PHP2Shell Runtime Security Policy
|--------------------------------------------------------------------------
|
| Patched PHP version floors and exposure metadata for CVE-2026-109618
| and CVE-2026-109619. This file is the single auditable source of truth
| used by runtime inventory features to classify whether a PHP installation
| is patched, exposed, or unsupported.
|
| Do not read environment variables, secrets, or deployment files here.
| Every value must be a deterministic static constant so that cached
| configuration produces identical results during incident response.
|
*/

return [

    /*
    |--------------------------------------------------------------------------
    | Affected CVEs
    |--------------------------------------------------------------------------
    |
    | The CVE identifiers addressed by the patched PHP releases below.
    |
    */

    'affected_cves' => [
        'CVE-2026-109618',
        'CVE-2026-109619',
    ],

    /*
    |--------------------------------------------------------------------------
    | Patch Release Date
    |--------------------------------------------------------------------------
    |
    | The date the patched PHP versions were released by the PHP project.
    |
    */

    'patch_released_on' => '2026-10-21',

    /*
    |--------------------------------------------------------------------------
    | Patched Version Floors
    |--------------------------------------------------------------------------
    |
    | The minimum PHP version per supported branch that contains fixes for
    | both CVEs. Any installation running a version below its branch floor
    | is considered exposed. Keys are strings to prevent numeric coercion
    | of branch identifiers like "8.10" in future PHP releases.
    |
    */

    'patched_floors' => [
        '8' => [
            '5' => '8.5.12',
            '4' => '8.4.27',
            '3' => '8.3.36',
            '2' => '8.2.35',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Unsupported Branches
    |--------------------------------------------------------------------------
    |
    | PHP branches that have reached end-of-life and will not receive an
    | upstream security patch for these CVEs. Installations on these branches
    | are classified as unsupported unless a trusted vendor backport exception
    | is explicitly represented by later code.
    |
    */

    'unsupported_branches' => [
        '5.4',
        '5.5',
        '5.6',
        '7.0',
        '7.1',
        '7.2',
        '7.3',
        '7.4',
        '8.0',
        '8.1',
    ],

    /*
    |--------------------------------------------------------------------------
    | Exposed SAPIs and Worker Models
    |--------------------------------------------------------------------------
    |
    | Server API interfaces and worker models named in the incident scope.
    | Later classifier code uses this list to determine whether a runtime's
    | SAPI is within the blast radius of the vulnerability.
    |
    */

    'exposed_sapis' => [
        'apache2handler',
        'fpm-fcgi',
        'cgi-fcgi',
        'litespeed',
        'mod_php',
        'php-fpm',
        'php-cgi',
    ],

    /*
    |--------------------------------------------------------------------------
    | Temporary Mitigations
    |--------------------------------------------------------------------------
    |
    | WAF rules or runtime workarounds that reduce exposure before a full
    | upgrade. Each entry describes one mitigation by identifier.
    |
    */

    'temporary_mitigations' => [
        'waf_block_php2shell_payloads',
        'disable_cgi_handler',
    ],

    /*
    |--------------------------------------------------------------------------
    | Report Status Constants
    |--------------------------------------------------------------------------
    |
    | Status labels that later code maps to report badges and evidence rows.
    | This list defines the vocabulary; classification logic lives in the
    | runtime inventory service, not in this configuration file.
    |
    */

    'statuses' => [
        'patched',
        'exposed',
        'unsupported',
        'mitigated',
        'vendor_backport_exception',
        'unknown',
        'collection_failed',
    ],

];
