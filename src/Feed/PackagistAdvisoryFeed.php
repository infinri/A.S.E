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

final readonly class PackagistAdvisoryFeed implements FeedInterface
{
    private const string BASE_URL = 'https://packagist.org/api/security-advisories/';
    private const array SEVERITY_SCORES = [
        'critical' => 9.5,
        'high' => 7.5,
        'medium' => 5.0,
        'low' => 2.5,
    ];

    public function __construct(
        private CurlClient $http,
        private Config $config,
        private LoggerInterface $logger,
    ) {}

    #[\Override]
    public function getName(): string
    {
        return 'packagist';
    }

    #[\Override]
    public function poll(string $lastPollTimestamp): VulnerabilityBatch
    {
        if ($lastPollTimestamp === '' || $lastPollTimestamp === 'first_run') {
            $since = time() - ($this->config->backfillDays() * 86400);
        } else {
            $since = strtotime($lastPollTimestamp) ?: time() - 86400;
        }

        $url = self::BASE_URL . '?' . http_build_query(['updatedSince' => $since]);
        $this->logger->info('Packagist: fetching advisories', ['since' => $since]);

        $response = $this->http->get($url);

        if (!$response->isOk()) {
            $this->logger->error('Packagist: HTTP error', ['status' => $response->statusCode]);
            return new VulnerabilityBatch('packagist', []);
        }

        $data = $response->json();

        if (!$this->validateResponse($data)) {
            return new VulnerabilityBatch('packagist', []);
        }

        $vulnerabilities = [];
        $now = date('c');

        foreach ($data['advisories'] as $packageName => $advisories) {
            foreach ($advisories as $advisory) {
                $cve = $advisory['cve'] ?? null;
                $ghsaId = $advisory['remoteId'] ?? null;
                $canonicalId = $cve ?? $ghsaId;

                if ($canonicalId === null) {
                    continue;
                }

                $aliases = array_values(array_filter([$cve, $ghsaId]));
                $severity = strtolower($advisory['severity'] ?? '');

                $vulnerabilities[] = new Vulnerability(
                    canonicalId: $canonicalId,
                    aliases: $aliases,
                    description: $advisory['title'] ?? '',
                    cvssScore: self::SEVERITY_SCORES[$severity] ?? null,
                    cvssVector: null,
                    epssScore: null,
                    epssPercentile: null,
                    inKev: false,
                    knownRansomware: false,
                    affectedPackages: [
                        new AffectedPackage(
                            ecosystem: 'composer',
                            name: $advisory['packageName'] ?? $packageName,
                            vulnerableRange: $advisory['affectedVersions'] ?? '*',
                        ),
                    ],
                    cwes: [],
                    references: array_filter([$advisory['link'] ?? null]),
                    sources: ['packagist'],
                    firstSeen: $now,
                    lastUpdated: $advisory['reportedAt'] ?? $now,
                    kevDateAdded: null,
                    kevDueDate: null,
                    kevRequiredAction: null,
                    affectsInstalledVersion: false,
                    priority: Priority::P1,
                    notifiedAtPriority: null,
                );
            }
        }

        $this->logger->info('Packagist: parsed advisories', ['count' => count($vulnerabilities)]);

        return new VulnerabilityBatch('packagist', $vulnerabilities);
    }

    /** @param array<string, mixed> $data */
    #[\Override]
    public function validateResponse(array $data): bool
    {
        if (!isset($data['advisories'])) {
            $this->logger->warning('Packagist: missing advisories key');
            return false;
        }
        return true;
    }
}
