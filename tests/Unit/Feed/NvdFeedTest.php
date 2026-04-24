<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Feed;

use Ase\Feed\NvdFeed;
use Ase\Http\CurlClient;
use Ase\Http\HttpResponse;
use Ase\Tests\Unit\ConfigTestHelper;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\NullLogger;
use Stringable;

final class NvdFeedTest extends TestCase
{
    #[Test]
    public function feedNameIsNvd(): void
    {
        $http = new CurlClient(new NullLogger());
        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
        ]);

        $logger = new NullLogger();
        $analyzer = new \Ase\Filter\ComposerLockAnalyzer($config, $logger);
        $feed = new NvdFeed($http, $config, $logger, $analyzer);

        self::assertSame('nvd', $feed->getName());
    }

    #[Test]
    public function pollUsesVirtualMatchStringNotCpeNameForPrefixFiltering(): void
    {
        $http = new RecordingNvdClient();
        $http->enqueueGet(new HttpResponse(200, json_encode([
            'totalResults' => 0,
            'resultsPerPage' => 2000,
            'vulnerabilities' => [],
        ]) ?: '{}', []));

        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
            'NVD_CPE_PREFIX' => 'cpe:2.3:a:adobe:commerce',
        ]);
        $logger = new NullLogger();
        $analyzer = new \Ase\Filter\ComposerLockAnalyzer($config, $logger);
        $feed = new NvdFeed($http, $config, $logger, $analyzer);

        $feed->poll('first_run');

        self::assertCount(1, $http->getCalls);
        self::assertStringContainsString('virtualMatchString=', $http->getCalls[0]);
        self::assertStringNotContainsString('cpeName=', $http->getCalls[0]);
    }

    #[Test]
    public function pollOmitsCpeParamWhenNoPrefixDetected(): void
    {
        // Clear any stale NVD_CPE_PREFIX leaked from a prior Config load in the PHPUnit process.
        unset($_ENV['NVD_CPE_PREFIX'], $_SERVER['NVD_CPE_PREFIX']);
        putenv('NVD_CPE_PREFIX');

        $http = new RecordingNvdClient();
        $http->enqueueGet(new HttpResponse(200, json_encode([
            'totalResults' => 0,
            'resultsPerPage' => 2000,
            'vulnerabilities' => [],
        ]) ?: '{}', []));

        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
        ]);
        $logger = new NullLogger();
        $analyzer = new \Ase\Filter\ComposerLockAnalyzer($config, $logger);
        $feed = new NvdFeed($http, $config, $logger, $analyzer);

        $feed->poll('first_run');

        self::assertCount(1, $http->getCalls);
        self::assertStringNotContainsString('virtualMatchString=', $http->getCalls[0]);
        self::assertStringNotContainsString('cpeName=', $http->getCalls[0]);
    }

    #[Test]
    public function http404ErrorMessageMentionsBothApiKeyAndCpeCauses(): void
    {
        $http = new RecordingNvdClient();
        $http->enqueueGet(new HttpResponse(404, '', []));

        $logger = new NvdCollectingLogger();
        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
            'NVD_API_KEY' => 'some-key',
            'NVD_CPE_PREFIX' => 'cpe:2.3:a:adobe:commerce',
        ]);
        $analyzer = new \Ase\Filter\ComposerLockAnalyzer($config, $logger);
        $feed = new NvdFeed($http, $config, $logger, $analyzer);

        $feed->poll('first_run');

        $errorRecords = array_values(array_filter(
            $logger->records,
            static fn(array $r): bool => str_contains((string) $r['message'], 'HTTP 404'),
        ));
        self::assertCount(1, $errorRecords);
        $msg = (string) $errorRecords[0]['message'];
        self::assertStringContainsString('NVD_API_KEY', $msg);
        self::assertStringContainsString('CPE', $msg);
    }
}

final class RecordingNvdClient extends CurlClient
{
    /** @var list<string> */
    public array $getCalls = [];

    /** @var list<HttpResponse> */
    private array $getQueue = [];

    public function __construct()
    {
        // Bypass parent constructor.
    }

    public function enqueueGet(HttpResponse $response): void
    {
        $this->getQueue[] = $response;
    }

    /** @param array<int, string> $headers */
    public function get(string $url, array $headers = []): HttpResponse
    {
        $this->getCalls[] = $url;
        return array_shift($this->getQueue) ?? new HttpResponse(200, '{}', []);
    }
}

final class NvdCollectingLogger extends AbstractLogger
{
    /** @var list<array{level: mixed, message: string|Stringable, context: array<string, mixed>}> */
    public array $records = [];

    /** @param array<string, mixed> $context */
    public function log(mixed $level, string|Stringable $message, array $context = []): void
    {
        $this->records[] = ['level' => $level, 'message' => $message, 'context' => $context];
    }
}
