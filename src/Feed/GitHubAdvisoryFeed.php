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

final readonly class GitHubAdvisoryFeed implements FeedInterface
{
    private const string BASE_URL = 'https://api.github.com/advisories';
    private const int PER_PAGE = 100;
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
        private ComposerLockAnalyzer $composerLockAnalyzer,
    ) {}

    #[\Override]
    public function getName(): string
    {
        return 'ghsa';
    }

    #[\Override]
    public function poll(string $lastPollTimestamp): VulnerabilityBatch
    {
        $allVulnerabilities = [];
        $ecosystems = array_unique(array_merge(
            $this->config->ecosystems(),
            $this->composerLockAnalyzer->detectEcosystems(),
        ));

        foreach ($ecosystems as $ecosystem) {
            $vulns = $this->pollEcosystem($ecosystem, $lastPollTimestamp);
            array_push($allVulnerabilities, ...$vulns);
        }

        $this->logger->info('GHSA: poll complete', ['count' => count($allVulnerabilities)]);

        return new VulnerabilityBatch('ghsa', $allVulnerabilities);
    }

    /** @param array<string, mixed> $data */
    #[\Override]
    public function validateResponse(array $data): bool
    {
        foreach ($data as $entry) {
            if (!isset($entry['ghsa_id'], $entry['vulnerabilities'])) {
                return false;
            }
        }
        return true;
    }

    /** @return Vulnerability[] */
    private function pollEcosystem(string $ecosystem, string $lastPollTimestamp): array
    {
        $headers = ['Accept: application/vnd.github+json'];
        $token = $this->config->githubToken();
        if ($token !== null) {
            $headers[] = "Authorization: token {$token}";
        }

        $params = [
            'ecosystem' => $ecosystem,
            'sort' => 'updated',
            'direction' => 'desc',
            'per_page' => self::PER_PAGE,
        ];

        if ($lastPollTimestamp !== '' && $lastPollTimestamp !== 'first_run') {
            $params['updated'] = $lastPollTimestamp;
        }

        $vulnerabilities = [];
        $url = self::BASE_URL . '?' . http_build_query($params);

        while ($url !== null) {
            $this->logger->debug('GHSA: fetching', ['url' => $url]);
            $response = $this->http->get($url, $headers);

            if (!$response->isOk()) {
                $this->logger->error('GHSA: HTTP error', [
                    'status' => $response->statusCode,
                    'ecosystem' => $ecosystem,
                ]);
                break;
            }

            $data = $response->json();

            foreach ($data as $advisory) {
                if (($advisory['withdrawn_at'] ?? null) !== null) {
                    continue;
                }

                $vuln = $this->parseAdvisory($advisory);
                if ($vuln !== null) {
                    $vulnerabilities[] = $vuln;
                }
            }

            $url = $this->parseNextLink($response->header('link'));
        }

        return $vulnerabilities;
    }

    /** @param array<string, mixed> $advisory */
    private function parseAdvisory(array $advisory): ?Vulnerability
    {
        $ghsaId = $advisory['ghsa_id'] ?? null;
        if ($ghsaId === null) {
            return null;
        }

        $cveId = $advisory['cve_id'] ?? null;
        $canonicalId = $cveId ?? $ghsaId;

        $aliases = [];
        foreach ($advisory['identifiers'] ?? [] as $ident) {
            $aliases[] = $ident['value'] ?? '';
        }
        $aliases = array_values(array_filter(array_unique($aliases)));

        $cvssScore = $advisory['cvss_severities']['cvss_v3']['score'] ?? null;
        $cvssVector = $advisory['cvss_severities']['cvss_v3']['vector_string'] ?? null;

        // Fallback: map severity string to proxy score if no CVSS
        if ($cvssScore === null || $cvssScore === 0.0) {
            $severity = strtolower($advisory['severity'] ?? '');
            $cvssScore = self::SEVERITY_SCORES[$severity] ?? null;
        }

        $affectedPackages = [];
        foreach ($advisory['vulnerabilities'] ?? [] as $v) {
            $affectedPackages[] = new AffectedPackage(
                ecosystem: $v['package']['ecosystem'] ?? 'unknown',
                name: $v['package']['name'] ?? 'unknown',
                vulnerableRange: $v['vulnerable_version_range'] ?? '*',
                fixedVersion: $v['first_patched_version'] ?? null,
            );
        }

        $cwes = array_map(
            static fn(array $cwe): string => $cwe['cwe_id'] ?? '',
            $advisory['cwes'] ?? [],
        );

        $now = date('c');

        return new Vulnerability(
            canonicalId: $canonicalId,
            aliases: $aliases,
            description: $advisory['summary'] ?? '',
            cvssScore: $cvssScore !== null ? (float) $cvssScore : null,
            cvssVector: $cvssVector,
            epssScore: null,
            epssPercentile: null,
            inKev: false,
            knownRansomware: false,
            affectedPackages: $affectedPackages,
            cwes: array_values(array_filter($cwes)),
            references: $advisory['references'] ?? [],
            sources: ['ghsa'],
            firstSeen: $now,
            lastUpdated: $advisory['updated_at'] ?? $now,
            kevDateAdded: null,
            kevDueDate: null,
            kevRequiredAction: null,
            affectsInstalledVersion: false,
            priority: Priority::P1,
            notifiedAtPriority: null,
        );
    }

    private function parseNextLink(?string $linkHeader): ?string
    {
        if ($linkHeader === null) {
            return null;
        }

        if (preg_match('/<([^>]+)>;\s*rel="next"/', $linkHeader, $matches)) {
            return $matches[1];
        }

        return null;
    }
}
