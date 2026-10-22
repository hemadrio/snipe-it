<?php

namespace App\Services\Runtime;

/**
 * Classifies a PHP runtime against the PHP2Shell patched version floors.
 *
 * Accepts plain scalar inputs (version string, SAPI name) and returns a
 * deterministic associative array describing branch, status, SAPI exposure,
 * CVE list, and required next action. No database, HTTP, or shell access.
 *
 * @see config/php_runtime_security.php
 */
class PhpRuntimePolicy
{
    /**
     * Classify a PHP runtime against the PHP2Shell security policy.
     *
     * @param  string  $version  Raw PHP version string (e.g. "8.3.36", "8.3", "PHP 8.3.36")
     * @param  string|null  $sapi  SAPI or worker model (e.g. "apache2handler", "cli")
     * @param  bool  $vendorBackportClaimed  Whether the caller asserts a trusted vendor backport
     * @param  string|null  $vendorBackportReason  Reason for the vendor backport exception
     * @return array{
     *     version: string,
     *     branch: string|null,
     *     major: int|null,
     *     minor: int|null,
     *     patch: int|null,
     *     patched_floor: string|null,
     *     status: string,
     *     reason: string,
     *     sapi: string|null,
     *     sapi_exposed: bool,
     *     cves: list<string>,
     *     next_action: string
     * }
     */
    public function classify(
        string $version,
        ?string $sapi = null,
        bool $vendorBackportClaimed = false,
        ?string $vendorBackportReason = null,
    ): array {
        $normalized = $this->normalizeVersion($version);

        if ($normalized === null) {
            return $this->buildResult(
                version: $version,
                status: 'unknown',
                reason: 'Malformed or unrecognizable version string.',
                sapi: $sapi,
                next_action: 'Collect a valid PHP version from the runtime.',
            );
        }

        [$major, $minor, $patch] = $normalized;
        $branch = "{$major}.{$minor}";

        $unsupportedBranches = (array) config('php_runtime_security.unsupported_branches', []);
        $exposedSapis = (array) config('php_runtime_security.exposed_sapis', []);
        $cves = (array) config('php_runtime_security.affected_cves', []);

        $sapiExposed = $sapi !== null && in_array(strtolower($sapi), $exposedSapis, true);

        if (in_array($branch, $unsupportedBranches, true)) {
            if ($vendorBackportClaimed) {
                return $this->buildResult(
                    version: $version,
                    branch: $branch,
                    major: $major,
                    minor: $minor,
                    patch: $patch,
                    status: 'vendor_backport_exception',
                    reason: $vendorBackportReason ?? 'Vendor backport exception claimed without a reason.',
                    sapi: $sapi,
                    sapiExposed: $sapiExposed,
                    cves: $cves,
                    next_action: 'Verify the vendor backport covers both CVEs and re-assess at next review cycle.',
                );
            }

            return $this->buildResult(
                version: $version,
                branch: $branch,
                major: $major,
                minor: $minor,
                patch: $patch,
                status: 'unsupported',
                reason: "PHP {$branch} is end-of-life and will not receive an upstream security patch.",
                sapi: $sapi,
                sapiExposed: $sapiExposed,
                cves: $cves,
                next_action: 'Upgrade to a supported PHP branch (8.2+) at or above the patched floor.',
            );
        }

        $patchedFloor = config("php_runtime_security.patched_floors.{$branch}");

        if ($patchedFloor === null) {
            return $this->buildResult(
                version: $version,
                branch: $branch,
                major: $major,
                minor: $minor,
                patch: $patch,
                status: 'unknown',
                reason: "PHP {$branch} is not tracked in the PHP2Shell security policy.",
                sapi: $sapi,
                sapiExposed: $sapiExposed,
                cves: $cves,
                next_action: 'Verify whether this PHP branch is affected and update the policy configuration.',
            );
        }

        if ($patch === null) {
            return $this->buildResult(
                version: $version,
                branch: $branch,
                major: $major,
                minor: $minor,
                patchedFloor: $patchedFloor,
                status: 'unknown',
                reason: "Version '{$version}' lacks a patch component; cannot determine if patched.",
                sapi: $sapi,
                sapiExposed: $sapiExposed,
                cves: $cves,
                next_action: 'Collect the full three-part PHP version from the runtime.',
            );
        }

        $fullVersion = "{$major}.{$minor}.{$patch}";

        if (version_compare($fullVersion, $patchedFloor, '>=')) {
            return $this->buildResult(
                version: $version,
                branch: $branch,
                major: $major,
                minor: $minor,
                patch: $patch,
                patchedFloor: $patchedFloor,
                status: 'patched',
                reason: "PHP {$fullVersion} meets or exceeds the patched floor {$patchedFloor}.",
                sapi: $sapi,
                sapiExposed: $sapiExposed,
                cves: $cves,
                next_action: 'None — runtime is patched.',
            );
        }

        return $this->buildResult(
            version: $version,
            branch: $branch,
            major: $major,
            minor: $minor,
            patch: $patch,
            patchedFloor: $patchedFloor,
            status: 'exposed',
            reason: "PHP {$fullVersion} is below the patched floor {$patchedFloor}.",
            sapi: $sapi,
            sapiExposed: $sapiExposed,
            cves: $cves,
            next_action: "Upgrade PHP {$branch} to at least {$patchedFloor}.",
        );
    }

    /**
     * Normalize a raw version string into [major, minor, patch] or null.
     *
     * Handles formats like "8.3.36", "8.3", "PHP 8.3.36", "php:8.3-fpm".
     * Returns null for empty, "latest", or otherwise unrecognizable values.
     *
     * @return array{0: int, 1: int, 2: int|null}|null
     */
    private function normalizeVersion(string $version): ?array
    {
        $version = trim($version);

        if ($version === '') {
            return null;
        }

        $cleaned = preg_replace('/^(?:php[:\s]*)/i', '', $version);

        $cleaned = preg_replace('/[-+].*$/', '', $cleaned);

        if (! preg_match('/^(\d+)\.(\d+)(?:\.(\d+))?$/', $cleaned, $matches)) {
            return null;
        }

        $major = (int) $matches[1];
        $minor = (int) $matches[2];
        $patch = isset($matches[3]) ? (int) $matches[3] : null;

        return [$major, $minor, $patch];
    }

    /**
     * Build a standardized classification result array.
     *
     * @param  list<string>  $cves
     * @return array{
     *     version: string,
     *     branch: string|null,
     *     major: int|null,
     *     minor: int|null,
     *     patch: int|null,
     *     patched_floor: string|null,
     *     status: string,
     *     reason: string,
     *     sapi: string|null,
     *     sapi_exposed: bool,
     *     cves: list<string>,
     *     next_action: string
     * }
     */
    private function buildResult(
        string $version,
        string $status,
        string $reason,
        string $next_action,
        ?string $branch = null,
        ?int $major = null,
        ?int $minor = null,
        ?int $patch = null,
        ?string $patchedFloor = null,
        ?string $sapi = null,
        bool $sapiExposed = false,
        array $cves = [],
    ): array {
        return [
            'version' => $version,
            'branch' => $branch,
            'major' => $major,
            'minor' => $minor,
            'patch' => $patch,
            'patched_floor' => $patchedFloor,
            'status' => $status,
            'reason' => $reason,
            'sapi' => $sapi,
            'sapi_exposed' => $sapiExposed,
            'cves' => $cves,
            'next_action' => $next_action,
        ];
    }
}
