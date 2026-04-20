<?php

declare(strict_types=1);

namespace Ase\Feed;

use Ase\Config;
use Ase\Filter\ComposerLockAnalyzer;
use Ase\Http\CurlClient;
use Ase\Model\AffectedPackage;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;
use Ase\Model\VulnerabilityBatch;
use Psr\Log\LoggerInterface;

final readonly class KevFeed implements FeedInterface
{
    private const string CATALOG_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

    public function __construct(
        private CurlClient $http,
        private Config $config,
        private LoggerInterface $logger,
        private ComposerLockAnalyzer $composerLockAnalyzer,
    ) {}

    #[\Override]
    public function getName(): string
    {
        return 'kev';
    }

    #[\Override]
    public function poll(string $lastPollTimestamp): VulnerabilityBatch
    {
        $this->logger->info('KEV: fetching catalog', ['since' => $lastPollTimestamp]);

        $response = $this->http->get(self::CATALOG_URL);

        if (!$response->isOk()) {
            $this->logger->error('KEV: HTTP error', ['status' => $response->statusCode]);
            return new VulnerabilityBatch('kev', []);
        }

        $data = $response->json();

        if (!$this->validateResponse($data)) {
            return new VulnerabilityBatch('kev', []);
        }

        $now = date('c');
        $vendorFilter = array_values(array_unique(array_map(
            'strtolower',
            array_merge($this->config->vendorFilter(), $this->composerLockAnalyzer->detectVendors()),
        )));
        $vulnerabilities = [];

        foreach ($data['vulnerabilities'] as $entry) {
            $dateAdded = $entry['dateAdded'] ?? '';

            if ($lastPollTimestamp !== 'first_run' && $lastPollTimestamp !== '' && $dateAdded <= substr($lastPollTimestamp, 0, 10)) {
                continue;
            }

            $affectedPackages = [];
            $vendor = strtolower($entry['vendorProject'] ?? '');
            if ($vendorFilter === [] || in_array($vendor, $vendorFilter, true)) {
                $affectedPackages[] = new AffectedPackage(
                    ecosystem: 'vendor',
                    name: ($entry['vendorProject'] ?? '') . '/' . ($entry['product'] ?? ''),
                    vulnerableRange: '*',
                );
            }

            $vulnerabilities[] = new Vulnerability(
                canonicalId: $entry['cveID'],
                aliases: [],
                description: $entry['shortDescription'] ?? '',
                cvssScore: null,
                cvssVector: null,
                epssScore: null,
                epssPercentile: null,
                inKev: true,
                knownRansomware: ($entry['knownRansomwareCampaignUse'] ?? 'Unknown') === 'Known',
                affectedPackages: $affectedPackages,
                cwes: $entry['cwes'] ?? [],
                references: [],
                sources: ['kev'],
                firstSeen: $now,
                lastUpdated: $now,
                kevDateAdded: $dateAdded,
                kevDueDate: $entry['dueDate'] ?? null,
                kevRequiredAction: $entry['requiredAction'] ?? null,
                affectsInstalledVersion: false,
                priority: Priority::P0,
                notifiedAtPriority: null,
            );
        }

        $this->logger->info('KEV: parsed entries', ['count' => count($vulnerabilities)]);

        return new VulnerabilityBatch('kev', $vulnerabilities);
    }

    /** @param array<string, mixed> $data */
    #[\Override]
    public function validateResponse(array $data): bool
    {
        if (!isset($data['vulnerabilities']) || !is_array($data['vulnerabilities']) || $data['vulnerabilities'] === []) {
            $this->logger->warning('KEV: missing or empty vulnerabilities array');
            return false;
        }

        if (!isset($data['catalogVersion'])) {
            $this->logger->warning('KEV: missing catalogVersion');
            return false;
        }

        return true;
    }
}
