<?php

declare(strict_types=1);

namespace Ase\Feed;

use Ase\Config;
use Ase\Http\CurlClient;
use Ase\Model\AffectedPackage;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;
use Ase\Model\VulnerabilityBatch;
use Psr\Log\LoggerInterface;

final readonly class OsvFeed implements FeedInterface
{
    private const string QUERY_URL = 'https://api.osv.dev/v1/query';
    private const string VULNS_URL = 'https://api.osv.dev/v1/vulns';
    private const array ECOSYSTEM_MAP = [
        'composer' => 'Packagist',
        'npm' => 'npm',
        'pip' => 'PyPI',
    ];
    private const array SEVERITY_SCORES = [
        'CRITICAL' => 9.5,
        'HIGH' => 7.5,
        'MEDIUM' => 5.0,
        'LOW' => 2.5,
    ];

    public function __construct(
        private CurlClient $http,
        private Config $config,
        private LoggerInterface $logger,
    ) {}

    #[\Override]
    public function getName(): string
    {
        return 'osv';
    }

    #[\Override]
    public function poll(string $lastPollTimestamp): VulnerabilityBatch
    {
        $allVulnerabilities = [];

        foreach ($this->config->ecosystems() as $ecosystem) {
            $mapped = self::ECOSYSTEM_MAP[$ecosystem] ?? null;
            if ($mapped === null) {
                continue;
            }

            $response = $this->http->post(self::QUERY_URL, [
                'ecosystem' => $mapped,
            ]);

            if (!$response->isOk()) {
                $this->logger->error('OSV: HTTP error', [
                    'ecosystem' => $ecosystem,
                    'status' => $response->statusCode,
                ]);
                continue;
            }

            $data = $response->json();
            $vulns = $data['vulns'] ?? [];

            foreach ($vulns as $entry) {
                $vuln = $this->parseVuln($entry);
                if ($vuln !== null) {
                    $allVulnerabilities[] = $vuln;
                }
            }
        }

        $this->logger->info('OSV: poll complete', ['count' => count($allVulnerabilities)]);

        return new VulnerabilityBatch('osv', $allVulnerabilities);
    }

    /** @param array<string, mixed> $data */
    #[\Override]
    public function validateResponse(array $data): bool
    {
        return isset($data['id'], $data['aliases']) && is_array($data['aliases']);
    }

    /** @return string[]|null */
    public function resolveAlias(string $id): ?array
    {
        $response = $this->http->get(self::VULNS_URL . '/' . urlencode($id));

        if (!$response->isOk()) {
            return null;
        }

        $data = $response->json();
        return $data['aliases'] ?? null;
    }

    /** @param array<string, mixed> $entry */
    private function parseVuln(array $entry): ?Vulnerability
    {
        $id = $entry['id'] ?? null;
        if ($id === null) {
            return null;
        }

        $aliases = $entry['aliases'] ?? [];
        $cveId = null;
        foreach ($aliases as $alias) {
            if (str_starts_with($alias, 'CVE-')) {
                $cveId = $alias;
                break;
            }
        }

        $canonicalId = $cveId ?? $id;
        $now = date('c');

        $cvssScore = null;
        $dbSeverity = strtoupper($entry['database_specific']['severity'] ?? '');
        if (isset(self::SEVERITY_SCORES[$dbSeverity])) {
            $cvssScore = self::SEVERITY_SCORES[$dbSeverity];
        }

        $affectedPackages = [];
        foreach ($entry['affected'] ?? [] as $affected) {
            $pkgName = $affected['package']['name'] ?? null;
            $pkgEcosystem = strtolower($affected['package']['ecosystem'] ?? '');

            if ($pkgName === null) {
                continue;
            }

            $range = $this->buildVersionRange($affected['ranges'] ?? []);

            $affectedPackages[] = new AffectedPackage(
                ecosystem: $pkgEcosystem === 'packagist' ? 'composer' : $pkgEcosystem,
                name: $pkgName,
                vulnerableRange: $range,
            );
        }

        return new Vulnerability(
            canonicalId: $canonicalId,
            aliases: $aliases,
            description: $entry['summary'] ?? '',
            cvssScore: $cvssScore,
            cvssVector: null,
            epssScore: null,
            epssPercentile: null,
            inKev: false,
            knownRansomware: false,
            affectedPackages: $affectedPackages,
            cwes: $entry['database_specific']['cwe_ids'] ?? [],
            references: array_map(
                static fn(array $ref): string => $ref['url'] ?? '',
                $entry['references'] ?? [],
            ),
            sources: ['osv'],
            firstSeen: $now,
            lastUpdated: $entry['modified'] ?? $now,
            kevDateAdded: null,
            kevDueDate: null,
            kevRequiredAction: null,
            affectsInstalledVersion: false,
            priority: Priority::P4,
            notifiedAtPriority: null,
        );
    }

    /** @param array<int, array<string, mixed>> $ranges */
    private function buildVersionRange(array $ranges): string
    {
        foreach ($ranges as $range) {
            $events = $range['events'] ?? [];
            $introduced = null;
            $fixed = null;

            foreach ($events as $event) {
                if (isset($event['introduced'])) {
                    $introduced = $event['introduced'];
                }
                if (isset($event['fixed'])) {
                    $fixed = $event['fixed'];
                }
            }

            if ($introduced !== null && $fixed !== null) {
                return ">={$introduced},<{$fixed}";
            }
            if ($introduced !== null) {
                return ">={$introduced}";
            }
        }

        return '*';
    }
}
