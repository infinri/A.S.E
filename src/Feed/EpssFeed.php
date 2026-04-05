<?php

declare(strict_types=1);

namespace Ase\Feed;

use Ase\Http\CurlClient;
use Ase\Model\Vulnerability;
use Psr\Log\LoggerInterface;

final class EpssFeed
{
    private const string BASE_URL = 'https://api.first.org/data/v1/epss';
    private const int BATCH_SIZE = 100;

    public function __construct(
        private readonly CurlClient $http,
        private readonly LoggerInterface $logger,
    ) {}

    /**
     * @param string[] $cveIds
     * @return array<string, array{score: float, percentile: float}>
     */
    public function enrichBatch(array $cveIds): array
    {
        $results = [];

        foreach (array_chunk($cveIds, self::BATCH_SIZE) as $chunk) {
            $url = self::BASE_URL . '?cve=' . implode(',', $chunk);
            $response = $this->http->get($url);

            if (!$response->isOk()) {
                $this->logger->error('EPSS: HTTP error', ['status' => $response->statusCode]);
                continue;
            }

            $data = $response->json();

            if (($data['status'] ?? '') !== 'OK') {
                $this->logger->warning('EPSS: unexpected status', ['status' => $data['status'] ?? 'unknown']);
                continue;
            }

            foreach ($data['data'] ?? [] as $entry) {
                $cve = $entry['cve'] ?? null;
                if ($cve === null) {
                    continue;
                }

                $results[$cve] = [
                    'score' => (float) ($entry['epss'] ?? 0),
                    'percentile' => (float) ($entry['percentile'] ?? 0),
                ];
            }
        }

        $this->logger->info('EPSS: enriched CVEs', ['count' => count($results)]);

        return $results;
    }

    /**
     * @param Vulnerability[] $vulnerabilities
     * @return Vulnerability[]
     */
    public function enrichVulnerabilities(array $vulnerabilities): array
    {
        $cveIds = [];
        foreach ($vulnerabilities as $vuln) {
            if (str_starts_with($vuln->canonicalId, 'CVE-')) {
                $cveIds[] = $vuln->canonicalId;
            }
        }

        if ($cveIds === []) {
            return $vulnerabilities;
        }

        $scores = $this->enrichBatch($cveIds);

        return array_map(
            static function (Vulnerability $vuln) use ($scores): Vulnerability {
                $epss = $scores[$vuln->canonicalId] ?? null;
                if ($epss === null) {
                    return $vuln;
                }
                return $vuln->withEpss($epss['score'], $epss['percentile']);
            },
            $vulnerabilities,
        );
    }
}
