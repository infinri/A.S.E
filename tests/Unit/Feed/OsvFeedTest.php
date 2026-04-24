<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Feed;

use Ase\Feed\OsvFeed;
use Ase\Filter\ComposerLockAnalyzer;
use Ase\Http\CurlClient;
use Ase\Http\HttpResponse;
use Ase\Tests\Unit\ConfigTestHelper;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\NullLogger;
use Stringable;

final class OsvFeedTest extends TestCase
{
    private string $tmpDir;
    private string $originalCwd;

    protected function setUp(): void
    {
        $this->originalCwd = getcwd() ?: sys_get_temp_dir();
        $this->tmpDir = sys_get_temp_dir() . '/ase_osv_test_' . uniqid();
        mkdir($this->tmpDir, 0755, true);
        $cwdScratch = $this->tmpDir . '/cwd';
        mkdir($cwdScratch, 0755, true);
        chdir($cwdScratch);
    }

    protected function tearDown(): void
    {
        chdir($this->originalCwd);
        $cwdScratch = $this->tmpDir . '/cwd';
        @rmdir($cwdScratch);
        $files = glob($this->tmpDir . '/*');
        if ($files !== false) {
            foreach ($files as $f) {
                if (is_file($f)) {
                    unlink($f);
                }
            }
        }
        @rmdir($this->tmpDir);
    }

    #[Test]
    public function feedNameIsOsv(): void
    {
        $feed = $this->makeFeed(new RecordingOsvClient(), []);
        self::assertSame('osv', $feed->getName());
    }

    #[Test]
    public function pollReturnsEmptyBatchWhenNoPackagesInstalled(): void
    {
        $client = new RecordingOsvClient();
        $feed = $this->makeFeed($client, []);

        $batch = $feed->poll('first_run');

        self::assertSame('osv', $batch->getSource());
        self::assertSame([], $batch->getVulnerabilities());
        self::assertSame([], $client->postCalls, 'no HTTP POST should fire when composer.lock is empty');
    }

    #[Test]
    public function pollLogsWhenNoPackagesInstalled(): void
    {
        $logger = new CollectingLogger();
        $client = new RecordingOsvClient();
        $feed = $this->makeFeed($client, [], $logger);

        $feed->poll('first_run');

        $messages = array_map(static fn(array $r): string => (string) $r['message'], $logger->records);
        self::assertContains('OSV: no installed packages to query', $messages);
    }

    #[Test]
    public function pollPostsQueryBatchToCorrectUrl(): void
    {
        $client = new RecordingOsvClient();
        $client->enqueuePost(new HttpResponse(200, json_encode(['results' => []]) ?: '{}', []));

        $feed = $this->makeFeed($client, ['magento/framework' => '2.4.6']);
        $feed->poll('first_run');

        self::assertCount(1, $client->postCalls, 'exactly one querybatch POST expected');
        self::assertSame('https://api.osv.dev/v1/querybatch', $client->postCalls[0]['url']);
    }

    #[Test]
    public function pollIncludesAllInstalledPackagesInQueryBatch(): void
    {
        $client = new RecordingOsvClient();
        $client->enqueuePost(new HttpResponse(200, json_encode(['results' => []]) ?: '{}', []));

        $feed = $this->makeFeed($client, [
            'magento/framework' => '2.4.6',
            'symfony/console' => '6.4.0',
            'monolog/monolog' => '3.5.0',
        ]);
        $feed->poll('first_run');

        $body = $client->postCalls[0]['payload'];
        self::assertArrayHasKey('queries', $body);
        self::assertCount(3, $body['queries']);

        $byName = [];
        foreach ($body['queries'] as $q) {
            $byName[$q['package']['name']] = $q;
        }
        self::assertSame('2.4.6', $byName['magento/framework']['version']);
        self::assertSame('6.4.0', $byName['symfony/console']['version']);
        self::assertSame('3.5.0', $byName['monolog/monolog']['version']);
    }

    #[Test]
    public function pollUsesPackagistEcosystemForEachQuery(): void
    {
        $client = new RecordingOsvClient();
        $client->enqueuePost(new HttpResponse(200, json_encode(['results' => []]) ?: '{}', []));

        $feed = $this->makeFeed($client, ['magento/framework' => '2.4.6']);
        $feed->poll('first_run');

        $body = $client->postCalls[0]['payload'];
        self::assertSame('Packagist', $body['queries'][0]['package']['ecosystem']);
    }

    #[Test]
    public function pollReturnsEmptyBatchOnHttpError(): void
    {
        $client = new RecordingOsvClient();
        $client->enqueuePost(new HttpResponse(500, 'server error', []));

        $feed = $this->makeFeed($client, ['magento/framework' => '2.4.6']);
        $batch = $feed->poll('first_run');

        self::assertSame([], $batch->getVulnerabilities());
    }

    #[Test]
    public function pollLogsHttpErrorWithStatusCode(): void
    {
        $logger = new CollectingLogger();
        $client = new RecordingOsvClient();
        $client->enqueuePost(new HttpResponse(500, 'server error', []));

        $feed = $this->makeFeed($client, ['magento/framework' => '2.4.6'], $logger);
        $feed->poll('first_run');

        $errorRecords = array_values(array_filter(
            $logger->records,
            static fn(array $r): bool => str_contains((string) $r['message'], 'OSV: HTTP error'),
        ));
        self::assertCount(1, $errorRecords);
        self::assertSame(500, $errorRecords[0]['context']['status'] ?? null);
    }

    #[Test]
    public function pollHydratesStubsViaVulnsEndpoint(): void
    {
        $client = new RecordingOsvClient();
        $client->enqueuePost(new HttpResponse(200, json_encode([
            'results' => [
                ['vulns' => [['id' => 'GHSA-aaaa-bbbb-cccc']]],
            ],
        ]) ?: '{}', []));
        $client->enqueueGet('https://api.osv.dev/v1/vulns/GHSA-aaaa-bbbb-cccc', new HttpResponse(
            200,
            json_encode($this->makeOsvVulnPayload('GHSA-aaaa-bbbb-cccc', 'CVE-2024-00001')) ?: '{}',
            [],
        ));

        $feed = $this->makeFeed($client, ['magento/framework' => '2.4.6']);
        $feed->poll('first_run');

        self::assertCount(1, $client->getCalls);
        self::assertSame('https://api.osv.dev/v1/vulns/GHSA-aaaa-bbbb-cccc', $client->getCalls[0]);
    }

    #[Test]
    public function pollParsesHydratedVulnsIntoVulnerabilityModels(): void
    {
        $client = new RecordingOsvClient();
        $client->enqueuePost(new HttpResponse(200, json_encode([
            'results' => [
                ['vulns' => [['id' => 'GHSA-aaaa-bbbb-cccc']]],
            ],
        ]) ?: '{}', []));
        $client->enqueueGet('https://api.osv.dev/v1/vulns/GHSA-aaaa-bbbb-cccc', new HttpResponse(
            200,
            json_encode($this->makeOsvVulnPayload('GHSA-aaaa-bbbb-cccc', 'CVE-2024-00001')) ?: '{}',
            [],
        ));

        $feed = $this->makeFeed($client, ['magento/framework' => '2.4.6']);
        $batch = $feed->poll('first_run');

        self::assertCount(1, $batch->getVulnerabilities());
        self::assertSame('CVE-2024-00001', $batch->getVulnerabilities()[0]->canonicalId);
    }

    #[Test]
    public function pollReturnsEmptyBatchWhenAllResultsHaveNoVulns(): void
    {
        $client = new RecordingOsvClient();
        $client->enqueuePost(new HttpResponse(200, json_encode([
            'results' => [[], [], []],
        ]) ?: '{}', []));

        $feed = $this->makeFeed($client, [
            'magento/framework' => '2.4.6',
            'symfony/console' => '6.4.0',
            'monolog/monolog' => '3.5.0',
        ]);
        $batch = $feed->poll('first_run');

        self::assertSame([], $batch->getVulnerabilities());
        self::assertSame([], $client->getCalls, 'no vuln hydration should fire when all results are empty');
    }

    /**
     * @param array<string, string> $installed package name => version
     */
    private function makeFeed(
        RecordingOsvClient $client,
        array $installed,
        ?CollectingLogger $logger = null,
    ): OsvFeed {
        $logger ??= new CollectingLogger();
        $env = ['SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test'];
        if ($installed !== []) {
            $env['COMPOSER_LOCK_PATH'] = $this->writeLockFile($installed);
        }
        $config = ConfigTestHelper::create($env);
        $analyzer = new ComposerLockAnalyzer($config, $logger);
        return new OsvFeed($client, $logger, $analyzer);
    }

    /**
     * @param array<string, string> $installed package name => version
     */
    private function writeLockFile(array $installed): string
    {
        $packages = [];
        foreach ($installed as $name => $version) {
            $packages[] = ['name' => $name, 'version' => $version];
        }
        $path = $this->tmpDir . '/composer.lock';
        file_put_contents($path, json_encode([
            'packages' => $packages,
            'packages-dev' => [],
        ], JSON_THROW_ON_ERROR));
        return $path;
    }

    /**
     * @return array<string, mixed>
     */
    private function makeOsvVulnPayload(string $id, string $cveAlias): array
    {
        return [
            'id' => $id,
            'aliases' => [$cveAlias],
            'summary' => 'Example vulnerability',
            'modified' => '2024-01-01T00:00:00Z',
            'affected' => [
                [
                    'package' => ['name' => 'magento/framework', 'ecosystem' => 'Packagist'],
                    'ranges' => [[
                        'events' => [
                            ['introduced' => '0'],
                            ['fixed' => '2.4.7-p1'],
                        ],
                    ]],
                ],
            ],
            'references' => [],
            'database_specific' => [],
        ];
    }
}

/**
 * Test double for CurlClient that records calls and returns pre-enqueued responses.
 * Bypasses parent constructor so no logger / real HTTP is involved.
 */
final class RecordingOsvClient extends CurlClient
{
    /** @var list<array{url: string, payload: array<string, mixed>}> */
    public array $postCalls = [];

    /** @var list<string> */
    public array $getCalls = [];

    /** @var list<HttpResponse> */
    private array $postQueue = [];

    /** @var array<string, HttpResponse> */
    private array $getMap = [];

    public function __construct()
    {
        // Bypass parent: no HTTP, no logger.
    }

    public function enqueuePost(HttpResponse $response): void
    {
        $this->postQueue[] = $response;
    }

    public function enqueueGet(string $url, HttpResponse $response): void
    {
        $this->getMap[$url] = $response;
    }

    /**
     * @param array<string, mixed>|string $body
     * @param array<int, string> $headers
     */
    public function post(string $url, array|string $body, array $headers = []): HttpResponse
    {
        $this->postCalls[] = [
            'url' => $url,
            'payload' => is_array($body) ? $body : [],
        ];
        return array_shift($this->postQueue) ?? new HttpResponse(200, '{}', []);
    }

    /** @param array<int, string> $headers */
    public function get(string $url, array $headers = []): HttpResponse
    {
        $this->getCalls[] = $url;
        return $this->getMap[$url] ?? new HttpResponse(404, '', []);
    }
}

final class CollectingLogger extends AbstractLogger
{
    /** @var list<array{level: mixed, message: string|Stringable, context: array<string, mixed>}> */
    public array $records = [];

    /** @param array<string, mixed> $context */
    public function log(mixed $level, string|Stringable $message, array $context = []): void
    {
        $this->records[] = ['level' => $level, 'message' => $message, 'context' => $context];
    }
}
