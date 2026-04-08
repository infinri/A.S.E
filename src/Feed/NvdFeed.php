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

final readonly class NvdFeed implements FeedInterface
{
    private const string BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
    private const int PAGE_SIZE = 2000;

    public function __construct(
        private CurlClient $http,
        private Config $config,
        private LoggerInterface $logger,
    ) {}

    #[\Override]
    public function getName(): string
    {
        return 'nvd';
    }

    #[\Override]
    public function poll(string $lastPollTimestamp): VulnerabilityBatch
    {
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));

        if ($lastPollTimestamp === '' || $lastPollTimestamp === 'first_run') {
            $sinceDate = $this->config->sinceDate();
            $startDate = $sinceDate !== null
                ? new \DateTimeImmutable($sinceDate, new \DateTimeZone('UTC'))
                : $now->modify('-' . $this->config->backfillDays() . ' days');
        } else {
            $startDate = new \DateTimeImmutable($lastPollTimestamp, new \DateTimeZone('UTC'));
        }

        $params = [
            'lastModStartDate' => $startDate->format('Y-m-d\TH:i:s.000+00:00'),
            'lastModEndDate' => $now->format('Y-m-d\TH:i:s.000+00:00'),
        ];

        $cpePrefix = $this->config->nvdCpePrefix();
        if ($cpePrefix !== null) {
            $params['cpeName'] = $cpePrefix;
        }

        $headers = [];
        $apiKey = $this->config->nvdApiKey();
        if ($apiKey !== null) {
            $headers[] = "apiKey: {$apiKey}";
        }

        $allVulnerabilities = [];
        $startIndex = 0;

        do {
            $params['startIndex'] = $startIndex;
            $params['resultsPerPage'] = self::PAGE_SIZE;

            $url = self::BASE_URL . '?' . http_build_query($params);
            $this->logger->info('NVD: fetching page', ['startIndex' => $startIndex]);

            $response = $this->http->get($url, $headers);

            if (!$response->isOk()) {
                if ($response->statusCode === 404 && $apiKey !== null) {
                    $this->logger->error('NVD: HTTP 404 -- this usually means the API key is invalid or expired. Verify NVD_API_KEY in your .env file.');
                } else {
                    $this->logger->error('NVD: HTTP error', ['status' => $response->statusCode]);
                }
                break;
            }

            $data = $response->json();

            if (!$this->validateResponse($data)) {
                break;
            }

            $totalResults = (int) $data['totalResults'];
            $resultsPerPage = (int) ($data['resultsPerPage'] ?? self::PAGE_SIZE);

            foreach ($data['vulnerabilities'] as $wrapper) {
                $cve = $wrapper['cve'] ?? [];
                $vuln = $this->parseCve($cve);
                if ($vuln !== null) {
                    $allVulnerabilities[] = $vuln;
                }
            }

            $startIndex += $resultsPerPage;

            if ($startIndex < $totalResults) {
                sleep(1);
            }
        } while ($startIndex < $totalResults);

        $this->logger->info('NVD: poll complete', ['count' => count($allVulnerabilities)]);

        return new VulnerabilityBatch('nvd', $allVulnerabilities);
    }

    /** @param array<string, mixed> $data */
    #[\Override]
    public function validateResponse(array $data): bool
    {
        return isset($data['totalResults'])
            && is_int($data['totalResults'])
            && isset($data['vulnerabilities'])
            && is_array($data['vulnerabilities']);
    }

    /** @param array<string, mixed> $cve */
    private function parseCve(array $cve): ?Vulnerability
    {
        $id = $cve['id'] ?? null;
        if ($id === null) {
            return null;
        }

        $now = date('c');

        return new Vulnerability(
            canonicalId: $id,
            aliases: [],
            description: $this->extractDescription($cve),
            cvssScore: $this->extractCvssScore($cve),
            cvssVector: $this->extractCvssVector($cve),
            epssScore: null,
            epssPercentile: null,
            inKev: isset($cve['cisaExploitAdd']),
            knownRansomware: false,
            affectedPackages: $this->extractAffectedPackages($cve),
            cwes: $this->extractCwes($cve),
            references: $this->extractReferences($cve),
            sources: ['nvd'],
            firstSeen: $now,
            lastUpdated: $cve['lastModified'] ?? $now,
            kevDateAdded: $cve['cisaExploitAdd'] ?? null,
            kevDueDate: $cve['cisaActionDue'] ?? null,
            kevRequiredAction: $cve['cisaRequiredAction'] ?? null,
            affectsInstalledVersion: false,
            priority: Priority::P4,
            notifiedAtPriority: null,
        );
    }

    /** @param array<string, mixed> $cve */
    private function extractDescription(array $cve): string
    {
        foreach ($cve['descriptions'] ?? [] as $desc) {
            if (($desc['lang'] ?? '') === 'en') {
                return $desc['value'] ?? '';
            }
        }
        return '';
    }

    /** @param array<string, mixed> $cve */
    private function extractCvssScore(array $cve): ?float
    {
        $metrics = $cve['metrics'] ?? [];
        foreach (['cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30'] as $key) {
            $score = $this->getCvssField($metrics, $key, 'baseScore');
            if ($score !== null) {
                return (float) $score;
            }
        }
        return null;
    }

    /** @param array<string, mixed> $cve */
    private function extractCvssVector(array $cve): ?string
    {
        $metrics = $cve['metrics'] ?? [];
        foreach (['cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30'] as $key) {
            $vector = $this->getCvssField($metrics, $key, 'vectorString');
            if ($vector !== null) {
                return (string) $vector;
            }
        }
        return null;
    }

    /** @param array<string, mixed> $metrics */
    private function getCvssField(array $metrics, string $metricKey, string $field): string|float|null
    {
        $entries = $metrics[$metricKey] ?? [];
        if ($entries === []) {
            return null;
        }

        // Prefer Primary source
        foreach ($entries as $entry) {
            if (($entry['type'] ?? '') === 'Primary') {
                return $entry['cvssData'][$field] ?? null;
            }
        }

        // Fall back to first entry
        return $entries[0]['cvssData'][$field] ?? null;
    }

    /**
     * @param array<string, mixed> $cve
     * @return string[]
     */
    private function extractCwes(array $cve): array
    {
        $cwes = [];
        foreach ($cve['weaknesses'] ?? [] as $weakness) {
            foreach ($weakness['description'] ?? [] as $desc) {
                $value = $desc['value'] ?? '';
                if (str_starts_with($value, 'CWE-')) {
                    $cwes[] = $value;
                }
            }
        }
        return array_values(array_unique($cwes));
    }

    /**
     * @param array<string, mixed> $cve
     * @return string[]
     */
    private function extractReferences(array $cve): array
    {
        return array_filter(
            array_map(
                static fn(array $ref): ?string => $ref['url'] ?? null,
                $cve['references'] ?? [],
            ),
        );
    }

    /**
     * @param array<string, mixed> $cve
     * @return AffectedPackage[]
     */
    private function extractAffectedPackages(array $cve): array
    {
        $packages = [];
        foreach ($cve['configurations'] ?? [] as $config) {
            foreach ($config['nodes'] ?? [] as $node) {
                foreach ($node['cpeMatch'] ?? [] as $match) {
                    if (!($match['vulnerable'] ?? false)) {
                        continue;
                    }
                    $packages[] = new AffectedPackage(
                        ecosystem: 'cpe',
                        name: $match['criteria'] ?? '',
                        vulnerableRange: $this->buildVersionRange($match),
                    );
                }
            }
        }
        return $packages;
    }

    /** @param array<string, mixed> $match */
    private function buildVersionRange(array $match): string
    {
        if (isset($match['versionEndExcluding'])) {
            return '< ' . $match['versionEndExcluding'];
        }
        if (isset($match['versionEndIncluding'])) {
            return '<= ' . $match['versionEndIncluding'];
        }
        return '*';
    }
}
