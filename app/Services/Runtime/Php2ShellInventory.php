<?php

namespace App\Services\Runtime;

/**
 * Collects PHP runtime evidence from known repository deployment files
 * and classifies each discovered runtime against the PHP2Shell security policy.
 *
 * Read-only: does not modify any deployment file, shell out to Docker/PHP/Ansible,
 * or access live hosts. Missing or unreadable files produce explicit
 * collection_failed rows rather than silently reducing the inventory.
 *
 * @see config/php_runtime_security.php
 */
class Php2ShellInventory
{
    /**
     * Source file definitions with their parse handlers, labels, and environment types.
     *
     * @var array<string, array{label: string, environment_type: string, method: string}>
     */
    private const FILE_SOURCES = [
        'Dockerfile' => [
            'label' => 'Docker Ubuntu Image',
            'environment_type' => 'container',
            'method' => 'parseDockerfile',
        ],
        'Dockerfile.alpine' => [
            'label' => 'Docker Alpine Image',
            'environment_type' => 'container',
            'method' => 'parseDockerfile',
        ],
        'Dockerfile.fpm-alpine' => [
            'label' => 'Docker FPM Alpine Image',
            'environment_type' => 'container',
            'method' => 'parseDockerfileFpmAlpine',
        ],
        'docker-compose.yml' => [
            'label' => 'Docker Compose',
            'environment_type' => 'container',
            'method' => 'parseDockerCompose',
        ],
        'snipeit.sh' => [
            'label' => 'Installer Script',
            'environment_type' => 'bare_metal',
            'method' => 'parseInstallerScript',
        ],
        '.github/workflows/tests-mysql.yml' => [
            'label' => 'GitHub Actions CI',
            'environment_type' => 'ci',
            'method' => 'parseGithubActionsWorkflow',
        ],
        'ansible/ubuntu/vagrant_playbook.yml' => [
            'label' => 'Ansible Playbook',
            'environment_type' => 'bare_metal',
            'method' => 'parseAnsiblePlaybook',
        ],
    ];

    public function __construct(
        private PhpRuntimePolicy $policy,
    ) {}

    /**
     * Collect PHP runtime evidence rows from all known deployment sources.
     *
     * @param  string|null  $basePath  Repository root path (defaults to Laravel base_path())
     * @return list<array{
     *     source_file: string,
     *     source_label: string,
     *     environment_type: string,
     *     php_version: string|null,
     *     php_branch: string|null,
     *     sapi: string|null,
     *     worker_model: string|null,
     *     status: string,
     *     reason: string,
     *     cves: list<string>,
     *     mitigation_status: string|null,
     *     owner: string|null,
     *     last_verified_at: string|null,
     *     parse_status: string
     * }>
     */
    public function collect(?string $basePath = null): array
    {
        $basePath = $basePath ?? base_path();
        $rows = [];

        foreach (self::FILE_SOURCES as $relativePath => $source) {
            $fullPath = rtrim($basePath, '/').'/'.$relativePath;

            if (! file_exists($fullPath) || ! is_readable($fullPath)) {
                $rows[] = $this->buildFailedRow(
                    $relativePath,
                    $source['label'],
                    $source['environment_type'],
                    "File not found or not readable: {$relativePath}",
                );

                continue;
            }

            $content = file_get_contents($fullPath);

            if ($content === false) {
                $rows[] = $this->buildFailedRow(
                    $relativePath,
                    $source['label'],
                    $source['environment_type'],
                    "Failed to read file: {$relativePath}",
                );

                continue;
            }

            $parsed = $this->{$source['method']}($content, $relativePath, $source);

            if (empty($parsed)) {
                $rows[] = $this->buildRow(
                    $relativePath,
                    $source['label'],
                    $source['environment_type'],
                    status: 'unknown',
                    reason: "No PHP runtime evidence detected in {$relativePath}.",
                    parseStatus: 'no_evidence',
                );

                continue;
            }

            foreach ($parsed as $row) {
                $rows[] = $row;
            }
        }

        return $rows;
    }

    /**
     * Parse a standard Dockerfile (Ubuntu or Alpine) for PHP package references.
     *
     * Detects patterns like: php8.3, libapache2-mod-php8.3, php84 (Alpine apk).
     *
     * @return list<array>
     */
    private function parseDockerfile(string $content, string $relativePath, array $source): array
    {
        $rows = [];
        $versions = [];

        if (preg_match_all('/libapache2-mod-php(\d+\.\d+)/i', $content, $matches)) {
            foreach ($matches[1] as $version) {
                $versions[$version] = 'apache2handler';
            }
        }

        if (preg_match_all('/\bphp(\d+)[-_](?:apache2|common|curl|mysql|gd|ldap|zip|mbstring|xml|bcmath|dev|redis|cli)\b/i', $content, $matches)) {
            foreach ($matches[1] as $majorMinorDigits) {
                if (strlen($majorMinorDigits) >= 2) {
                    $major = substr($majorMinorDigits, 0, -1);
                    $minor = substr($majorMinorDigits, -1);
                    $version = "{$major}.{$minor}";
                    if (! isset($versions[$version])) {
                        $versions[$version] = $this->detectWorkerModelFromContent($content);
                    }
                }
            }
        }

        if (preg_match_all('/\bphp(\d+\.\d+)\b/', $content, $matches)) {
            foreach ($matches[1] as $version) {
                if (! isset($versions[$version])) {
                    $versions[$version] = $this->detectWorkerModelFromContent($content);
                }
            }
        }

        foreach ($versions as $phpVersion => $workerModel) {
            $classification = $this->policy->classify($phpVersion, $workerModel);
            $rows[] = $this->buildRow(
                $relativePath,
                $source['label'],
                $source['environment_type'],
                phpVersion: $phpVersion,
                phpBranch: $classification['branch'],
                sapi: $workerModel,
                workerModel: $workerModel,
                status: $classification['status'],
                reason: $classification['reason'],
                cves: $classification['cves'],
                parseStatus: 'parsed',
            );
        }

        return $rows;
    }

    /**
     * Parse the FPM Alpine Dockerfile which uses ARG PHP_VERSION.
     *
     * @return list<array>
     */
    private function parseDockerfileFpmAlpine(string $content, string $relativePath, array $source): array
    {
        $rows = [];

        if (preg_match('/ARG\s+PHP_VERSION\s*=\s*(\S+)/i', $content, $match)) {
            $phpVersion = $match[1];
            $workerModel = 'fpm-fcgi';

            if (preg_match('/php-fpm/i', $content)) {
                $workerModel = 'fpm-fcgi';
            }

            $classification = $this->policy->classify($phpVersion, $workerModel);
            $rows[] = $this->buildRow(
                $relativePath,
                $source['label'],
                $source['environment_type'],
                phpVersion: $phpVersion,
                phpBranch: $classification['branch'],
                sapi: $workerModel,
                workerModel: $workerModel,
                status: $classification['status'],
                reason: $classification['reason'],
                cves: $classification['cves'],
                parseStatus: 'parsed',
            );
        }

        return $rows;
    }

    /**
     * Parse docker-compose.yml for Snipe-IT image references.
     *
     * @return list<array>
     */
    private function parseDockerCompose(string $content, string $relativePath, array $source): array
    {
        $rows = [];

        if (preg_match('/image:\s*snipe\/snipe-it:(\S+)/i', $content, $match)) {
            $tag = $match[1];
            $phpVersion = null;
            $workerModel = null;

            if (preg_match('/php(\d+\.\d+(?:\.\d+)?)/i', $tag, $vMatch)) {
                $phpVersion = $vMatch[1];
            }

            $rows[] = $this->buildRow(
                $relativePath,
                $source['label'],
                $source['environment_type'],
                phpVersion: $phpVersion,
                sapi: $workerModel,
                workerModel: $workerModel,
                status: $phpVersion ? $this->policy->classify($phpVersion, $workerModel)['status'] : 'unknown',
                reason: $phpVersion
                    ? $this->policy->classify($phpVersion, $workerModel)['reason']
                    : "Docker Compose uses image tag '{$tag}' — PHP version is determined by the image at runtime.",
                cves: $phpVersion ? $this->policy->classify($phpVersion, $workerModel)['cves'] : [],
                parseStatus: $phpVersion ? 'parsed' : 'runtime_resolved',
            );
        }

        return $rows;
    }

    /**
     * Parse the snipeit.sh installer for PHP package references per distro branch.
     *
     * @return list<array>
     */
    private function parseInstallerScript(string $content, string $relativePath, array $source): array
    {
        $rows = [];
        $seen = [];

        if (preg_match_all('/libapache2-mod-php(\d+\.\d+)/i', $content, $matches)) {
            foreach ($matches[1] as $version) {
                $key = "{$version}:apache2handler";
                if (! isset($seen[$key])) {
                    $seen[$key] = true;
                    $classification = $this->policy->classify($version, 'apache2handler');
                    $rows[] = $this->buildRow(
                        $relativePath,
                        $source['label'],
                        $source['environment_type'],
                        phpVersion: $version,
                        phpBranch: $classification['branch'],
                        sapi: 'apache2handler',
                        workerModel: 'apache2handler',
                        status: $classification['status'],
                        reason: $classification['reason'],
                        cves: $classification['cves'],
                        parseStatus: 'parsed',
                    );
                }
            }
        }

        if (preg_match_all('/\bphp(\d+\.\d+)\b/', $content, $matches)) {
            foreach ($matches[1] as $version) {
                $key = "{$version}:unknown";
                if (! isset($seen[$key]) && ! isset($seen["{$version}:apache2handler"])) {
                    $seen[$key] = true;
                    $workerModel = $this->detectWorkerModelFromContent($content);
                    $classification = $this->policy->classify($version, $workerModel);
                    $rows[] = $this->buildRow(
                        $relativePath,
                        $source['label'],
                        $source['environment_type'],
                        phpVersion: $version,
                        phpBranch: $classification['branch'],
                        sapi: $workerModel,
                        workerModel: $workerModel,
                        status: $classification['status'],
                        reason: $classification['reason'],
                        cves: $classification['cves'],
                        parseStatus: 'parsed',
                    );
                }
            }
        }

        if (preg_match_all('/amazon-linux-extras\s+install\s+-y\s+php(\d+\.\d+)/i', $content, $matches)) {
            foreach ($matches[1] as $version) {
                $key = "{$version}:httpd";
                if (! isset($seen[$key]) && ! isset($seen["{$version}:apache2handler"]) && ! isset($seen["{$version}:unknown"])) {
                    $seen[$key] = true;
                    $classification = $this->policy->classify($version, 'apache2handler');
                    $rows[] = $this->buildRow(
                        $relativePath,
                        $source['label'],
                        $source['environment_type'],
                        phpVersion: $version,
                        phpBranch: $classification['branch'],
                        sapi: 'apache2handler',
                        workerModel: 'apache2handler',
                        status: $classification['status'],
                        reason: $classification['reason'],
                        cves: $classification['cves'],
                        parseStatus: 'parsed',
                    );
                }
            }
        }

        return $rows;
    }

    /**
     * Parse a GitHub Actions workflow YAML for PHP version matrix entries.
     *
     * @return list<array>
     */
    private function parseGithubActionsWorkflow(string $content, string $relativePath, array $source): array
    {
        $rows = [];

        if (preg_match('/php-version:\s*\n((?:[ \t]+-[ \t]*"[^"]+"[^\n]*\n?)+)/i', $content, $matrixMatch)) {
            $matrixBlock = $matrixMatch[1];
            if (preg_match_all('/-\s*"(\d+\.\d+(?:\.\d+)?)"/i', $matrixBlock, $versions)) {
                foreach ($versions[1] as $version) {
                    $classification = $this->policy->classify($version, 'cli');
                    $rows[] = $this->buildRow(
                        $relativePath,
                        $source['label'],
                        $source['environment_type'],
                        phpVersion: $version,
                        phpBranch: $classification['branch'],
                        sapi: 'cli',
                        workerModel: 'cli',
                        status: $classification['status'],
                        reason: $classification['reason'],
                        cves: $classification['cves'],
                        parseStatus: 'parsed',
                    );
                }
            }
        }

        return $rows;
    }

    /**
     * Parse an Ansible playbook for PHP package references.
     *
     * @return list<array>
     */
    private function parseAnsiblePlaybook(string $content, string $relativePath, array $source): array
    {
        $rows = [];
        $seen = [];

        if (preg_match_all('/libapache2-mod-php(\d+\.\d+)?/i', $content, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $version = $match[1] ?? '';
                if ($version === '') {
                    $rows[] = $this->buildRow(
                        $relativePath,
                        $source['label'],
                        $source['environment_type'],
                        sapi: 'apache2handler',
                        workerModel: 'apache2handler',
                        status: 'unknown',
                        reason: 'Ansible installs libapache2-mod-php without a version pin — PHP version is determined by the OS default.',
                        parseStatus: 'runtime_resolved',
                    );

                    continue;
                }

                $key = "{$version}:apache2handler";
                if (! isset($seen[$key])) {
                    $seen[$key] = true;
                    $classification = $this->policy->classify($version, 'apache2handler');
                    $rows[] = $this->buildRow(
                        $relativePath,
                        $source['label'],
                        $source['environment_type'],
                        phpVersion: $version,
                        phpBranch: $classification['branch'],
                        sapi: 'apache2handler',
                        workerModel: 'apache2handler',
                        status: $classification['status'],
                        reason: $classification['reason'],
                        cves: $classification['cves'],
                        parseStatus: 'parsed',
                    );
                }
            }
        }

        if (preg_match_all('/\bphp(\d+\.\d+)\b/', $content, $matches)) {
            foreach ($matches[1] as $version) {
                $key = "{$version}:unknown";
                if (! isset($seen[$key]) && ! isset($seen["{$version}:apache2handler"])) {
                    $seen[$key] = true;
                    $classification = $this->policy->classify($version, null);
                    $rows[] = $this->buildRow(
                        $relativePath,
                        $source['label'],
                        $source['environment_type'],
                        phpVersion: $version,
                        phpBranch: $classification['branch'],
                        sapi: null,
                        workerModel: null,
                        status: $classification['status'],
                        reason: $classification['reason'],
                        cves: $classification['cves'],
                        parseStatus: 'parsed',
                    );
                }
            }
        }

        return $rows;
    }

    /**
     * Detect the worker model from file content heuristics.
     */
    private function detectWorkerModelFromContent(string $content): ?string
    {
        if (preg_match('/libapache2-mod-php|apache2handler|mod_php/i', $content)) {
            return 'apache2handler';
        }

        if (preg_match('/php-fpm|fpm-fcgi/i', $content)) {
            return 'fpm-fcgi';
        }

        return null;
    }

    /**
     * Build a normalized evidence row.
     *
     * @param  list<string>  $cves
     * @return array{
     *     source_file: string,
     *     source_label: string,
     *     environment_type: string,
     *     php_version: string|null,
     *     php_branch: string|null,
     *     sapi: string|null,
     *     worker_model: string|null,
     *     status: string,
     *     reason: string,
     *     cves: list<string>,
     *     mitigation_status: string|null,
     *     owner: string|null,
     *     last_verified_at: string|null,
     *     parse_status: string
     * }
     */
    private function buildRow(
        string $sourceFile,
        string $sourceLabel,
        string $environmentType,
        string $status,
        string $reason,
        string $parseStatus,
        ?string $phpVersion = null,
        ?string $phpBranch = null,
        ?string $sapi = null,
        ?string $workerModel = null,
        array $cves = [],
        ?string $mitigationStatus = null,
        ?string $owner = null,
        ?string $lastVerifiedAt = null,
    ): array {
        return [
            'source_file' => $sourceFile,
            'source_label' => $sourceLabel,
            'environment_type' => $environmentType,
            'php_version' => $phpVersion,
            'php_branch' => $phpBranch,
            'sapi' => $sapi,
            'worker_model' => $workerModel,
            'status' => $status,
            'reason' => $reason,
            'cves' => $cves,
            'mitigation_status' => $mitigationStatus,
            'owner' => $owner,
            'last_verified_at' => $lastVerifiedAt,
            'parse_status' => $parseStatus,
        ];
    }

    /**
     * Build a collection_failed evidence row for missing or unreadable files.
     */
    private function buildFailedRow(
        string $sourceFile,
        string $sourceLabel,
        string $environmentType,
        string $reason,
    ): array {
        return $this->buildRow(
            $sourceFile,
            $sourceLabel,
            $environmentType,
            status: 'collection_failed',
            reason: $reason,
            parseStatus: 'collection_failed',
        );
    }
}
