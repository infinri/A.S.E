<?php

declare(strict_types=1);

namespace Ase\Feed;

use Ase\Http\CurlClient;
use Psr\Log\LoggerInterface;

class KevCatalog
{
    private const string CATALOG_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

    /** @var array<string, bool>|null cveId => knownRansomware */
    private ?array $entries = null;

    public function __construct(
        private readonly CurlClient $http,
        private readonly LoggerInterface $logger,
    ) {}

    public function inKev(string $vulnId): bool
    {
        return array_key_exists($vulnId, $this->load());
    }

    public function isRansomware(string $vulnId): bool
    {
        return $this->load()[$vulnId] ?? false;
    }

    /** @return array<string, bool> */
    private function load(): array
    {
        if ($this->entries !== null) {
            return $this->entries;
        }

        $response = $this->http->get(self::CATALOG_URL);
        if (!$response->isOk()) {
            throw new \RuntimeException(
                'Failed fetching CISA KEV catalog from ' . self::CATALOG_URL
                . ": HTTP {$response->statusCode}"
            );
        }

        $entries = [];
        foreach ($response->json()['vulnerabilities'] ?? [] as $entry) {
            $cveId = $entry['cveID'] ?? null;
            if (!is_string($cveId) || $cveId === '') {
                continue;
            }
            $entries[$cveId] = ($entry['knownRansomwareCampaignUse'] ?? '') === 'Known';
        }

        $this->logger->info('KEV catalog loaded', ['entries' => count($entries)]);
        return $this->entries = $entries;
    }
}
