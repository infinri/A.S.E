<?php

declare(strict_types=1);

namespace Ase\Feed;

use Ase\Filter\ComposerLockAnalyzer;
use Ase\Http\CurlClient;
use Ase\Model\AffectedPackage;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;
use Ase\Model\VulnerabilityBatch;
use Psr\Log\LoggerInterface;

final readonly class OsvFeed implements FeedInterface
{
    private const string QUERYBATCH_URL = 'https://api.osv.dev/v1/querybatch';
    private const string VULNS_URL = 'https://api.osv.dev/v1/vulns';
    private const array SEVERITY_SCORES = [
        'CRITICAL' => 9.5,
        'HIGH' => 7.5,
        'MEDIUM' => 5.0,
        'LOW' => 2.5,
    ];

    public function __construct(
        private CurlClient $http,
        private LoggerInterface $logger,
        private ComposerLockAnalyzer $composerLockAnalyzer,
    ) {}

    #[\Override]
    public function getName(): string
    {
        return 'osv';
    }

    #[\Override]
    public function poll(string $lastPollTimestamp): VulnerabilityBatch
    {
        $packages = $this->composerLockAnalyzer->getInstalledPackages();
        if ($packages === []) {
            $this->logger->info('OSV: no installed packages to query');
            return new VulnerabilityBatch('osv', []);
        }

        $queries = [];
        foreach ($packages as $name => $version) {
            $queries[] = [
                'package' => ['name' => $name, 'ecosystem' => 'Packagist'],
                'version' => $version,
            ];
        }

        $response = $this->http->post(self::QUERYBATCH_URL, ['queries' => $queries]);
        if (!$response->isOk()) {
            $this->logger->error('OSV: HTTP error', ['status' => $response->statusCode]);
            return new VulnerabilityBatch('osv', []);
        }

        /** @var array<string, mixed> $data */
        $data = $response->json();
        /** @var list<array<string, mixed>> $batchResults */
        $batchResults = $data['results'] ?? [];

        $vulns = $this->hydrateAndParse($batchResults);

        $this->logger->info('OSV: poll complete', [
            'count' => count($vulns),
            'packages' => count($packages),
        ]);

        return new VulnerabilityBatch('osv', $vulns);
    }

    /** @param array<string, mixed> $data */
    #[\Override]
    public function validateResponse(array $data): bool
    {
        return isset($data['id'], $data['aliases']) && is_array($data['aliases']);
    }

    /** @return string[]|null
     * @throws \JsonException
     */
    public function resolveAlias(string $id): ?array
    {
        $response = $this->http->get(self::VULNS_URL . '/' . urlencode($id));

        if (!$response->isOk()) {
            return null;
        }

        /** @var array<string, mixed> $data */
        $data = $response->json();
        /** @var string[]|null $aliases */
        $aliases = $data['aliases'] ?? null;
        return $aliases;
    }

    /**
     * @param list<array<string, mixed>> $batchResults
     * @return list<Vulnerability>
     */
    private function hydrateAndParse(array $batchResults): array
    {
        $out = [];
        foreach ($batchResults as $result) {
            /** @var list<array<string, mixed>> $stubs */
            $stubs = $result['vulns'] ?? [];
            foreach ($stubs as $stub) {
                $id = $stub['id'] ?? null;
                if (!is_string($id) || $id === '') {
                    continue;
                }
                $full = $this->fetchVuln($id);
                if ($full === null) {
                    continue;
                }
                $vuln = $this->parseVuln($full);
                if ($vuln !== null) {
                    $out[] = $vuln;
                }
            }
        }
        return $out;
    }

    /** @return array<string, mixed>|null */
    private function fetchVuln(string $id): ?array
    {
        $response = $this->http->get(self::VULNS_URL . '/' . urlencode($id));
        if (!$response->isOk()) {
            $this->logger->warning('OSV: failed to hydrate vuln', [
                'id' => $id,
                'status' => $response->statusCode,
            ]);
            return null;
        }
        /** @var array<string, mixed> $data */
        $data = $response->json();
        return $data;
    }

    /** @param array<string, mixed> $entry */
    private function parseVuln(array $entry): ?Vulnerability
    {
        $id = $entry['id'] ?? null;
        if (!is_string($id) || $id === '') {
            return null;
        }

        /** @var list<string> $aliases */
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
        /** @var array<string, mixed> $dbSpecific */
        $dbSpecific = $entry['database_specific'] ?? [];
        $dbSeverity = strtoupper((string) ($dbSpecific['severity'] ?? ''));
        if (isset(self::SEVERITY_SCORES[$dbSeverity])) {
            $cvssScore = self::SEVERITY_SCORES[$dbSeverity];
        }

        $affectedPackages = [];
        /** @var list<array<string, mixed>> $affectedList */
        $affectedList = $entry['affected'] ?? [];
        foreach ($affectedList as $affected) {
            /** @var array<string, mixed> $pkg */
            $pkg = $affected['package'] ?? [];
            $pkgName = $pkg['name'] ?? null;
            $pkgEcosystem = strtolower((string) ($pkg['ecosystem'] ?? ''));

            if (!is_string($pkgName) || $pkgName === '') {
                continue;
            }

            /** @var list<array<string, mixed>> $ranges */
            $ranges = $affected['ranges'] ?? [];
            $range = $this->buildVersionRange($ranges);

            $affectedPackages[] = new AffectedPackage(
                ecosystem: $pkgEcosystem === 'packagist' ? 'composer' : $pkgEcosystem,
                name: $pkgName,
                vulnerableRange: $range,
            );
        }

        /** @var list<string> $cwes */
        $cwes = $dbSpecific['cwe_ids'] ?? [];

        /** @var list<array<string, mixed>> $references */
        $references = $entry['references'] ?? [];
        $refUrls = array_values(array_filter(array_map(
            static fn(array $ref): string => (string) ($ref['url'] ?? ''),
            $references,
        )));

        return new Vulnerability(
            canonicalId: $canonicalId,
            aliases: $aliases,
            description: (string) ($entry['summary'] ?? ''),
            cvssScore: $cvssScore,
            cvssVector: null,
            epssScore: null,
            epssPercentile: null,
            inKev: false,
            knownRansomware: false,
            affectedPackages: $affectedPackages,
            cwes: $cwes,
            references: $refUrls,
            sources: ['osv'],
            firstSeen: $now,
            lastUpdated: (string) ($entry['modified'] ?? $now),
            kevDateAdded: null,
            kevDueDate: null,
            kevRequiredAction: null,
            affectsInstalledVersion: false,
            priority: Priority::P1,
            notifiedAtPriority: null,
        );
    }

    /** @param list<array<string, mixed>> $ranges */
    private function buildVersionRange(array $ranges): string
    {
        foreach ($ranges as $range) {
            /** @var list<array<string, mixed>> $events */
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
