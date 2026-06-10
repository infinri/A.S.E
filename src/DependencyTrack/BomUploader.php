<?php

declare(strict_types=1);

namespace Ase\DependencyTrack;

use Ase\Http\CurlClient;
use Psr\Log\LoggerInterface;

final class BomUploader
{
    public function __construct(
        private readonly CurlClient $client,
        private readonly string $baseUrl,
        #[\SensitiveParameter] private readonly string $apiKey,
        private readonly LoggerInterface $logger,
    ) {}

    /** @param array<string, mixed> $bom */
    public function upload(string $projectName, string $projectVersion, array $bom): void
    {
        $response = $this->client->put(
            rtrim($this->baseUrl, '/') . '/api/v1/bom',
            [
                'projectName' => $projectName,
                'projectVersion' => $projectVersion,
                'autoCreate' => true,
                'bom' => base64_encode(json_encode($bom, JSON_THROW_ON_ERROR)),
            ],
            ['X-Api-Key: ' . $this->apiKey],
        );

        if (!$response->isOk()) {
            throw new \RuntimeException(
                "BOM upload for project {$projectName} rejected by Dependency-Track: "
                . "HTTP {$response->statusCode} {$response->body}"
            );
        }

        $this->logger->info('BOM uploaded', [
            'project' => $projectName,
            'components' => count($bom['components'] ?? []),
        ]);
    }
}
