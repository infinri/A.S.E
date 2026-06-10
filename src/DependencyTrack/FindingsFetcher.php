<?php

declare(strict_types=1);

namespace Ase\DependencyTrack;

use Ase\Http\CurlClient;
use Psr\Log\LoggerInterface;

final readonly class FindingsFetcher
{
    private const int PAGE_SIZE = 100;

    public function __construct(
        private CurlClient $client,
        private string $baseUrl,
        #[\SensitiveParameter] private string $apiKey,
        private LoggerInterface $logger,
    ) {}

    /** @return array<int, array{uuid: string, name: string, tags: string[]}> */
    public function projects(): array
    {
        $projects = [];
        $page = 1;
        do {
            $url = rtrim($this->baseUrl, '/') . '/api/v1/project?pageSize=' . self::PAGE_SIZE . "&pageNumber={$page}";
            $response = $this->client->get($url, ['X-Api-Key: ' . $this->apiKey]);
            if (!$response->isOk()) {
                throw new \RuntimeException(
                    "Failed listing Dependency-Track projects (page {$page}): HTTP {$response->statusCode}"
                );
            }
            $batch = $response->json();
            foreach ($batch as $project) {
                $projects[] = [
                    'uuid' => (string) $project['uuid'],
                    'name' => (string) $project['name'],
                    'tags' => array_values(array_map(
                        static fn (array $tag): string => (string) $tag['name'],
                        $project['tags'] ?? [],
                    )),
                ];
            }
            $total = (int) ($response->header('x-total-count') ?? count($projects));
            $page++;
        } while (count($projects) < $total && $batch !== []);

        $this->logger->info('Dependency-Track projects fetched', ['count' => count($projects)]);
        return $projects;
    }

    /** @return array<int, array<string, mixed>> */
    public function findingsForProject(string $projectUuid): array
    {
        $url = rtrim($this->baseUrl, '/') . "/api/v1/finding/project/{$projectUuid}";
        $response = $this->client->get($url, ['X-Api-Key: ' . $this->apiKey]);
        if (!$response->isOk()) {
            throw new \RuntimeException(
                "Failed fetching findings for project {$projectUuid}: HTTP {$response->statusCode}"
            );
        }

        $findings = [];
        foreach ($response->json() as $finding) {
            if (is_array($finding)) {
                $findings[] = $finding;
            }
        }
        return $findings;
    }
}
