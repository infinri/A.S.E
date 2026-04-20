<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Notify;

use Ase\Http\CurlClient;
use Ase\Http\HttpResponse;
use Ase\Model\AffectedPackage;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;
use Ase\Notify\SlackNotifier;
use Ase\Tests\Unit\ConfigTestHelper;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;
use Stringable;

final class SlackNotifierTest extends TestCase
{
    protected function setUp(): void
    {
        // Previous tests may have populated these via dotenv; clear so each test
        // starts from a clean webhook-config slate.
        foreach (['SLACK_WEBHOOK_URL', 'SLACK_WEBHOOK_P1'] as $key) {
            unset($_ENV[$key], $_SERVER[$key]);
            putenv($key);
        }
    }

    #[Test]
    public function testSendAlertsPostsP0ToPrimaryWebhook(): void
    {
        $client = new RecordingCurlClient();
        $notifier = new SlackNotifier(
            $client,
            ConfigTestHelper::create([
                'SLACK_WEBHOOK_URL' => 'https://hooks.example/p0-placeholder',
                'SLACK_WEBHOOK_P1' => 'https://hooks.example/p1-placeholder',
            ]),
            new CollectingLogger(),
        );

        $notifier->sendAlerts([$this->makeVuln(Priority::P0)]);

        self::assertCount(1, $client->calls);
        self::assertSame('https://hooks.example/p0-placeholder', $client->calls[0]['url']);
    }

    #[Test]
    public function testSendAlertsPostsP1ToSecondaryWebhook(): void
    {
        $client = new RecordingCurlClient();
        $notifier = new SlackNotifier(
            $client,
            ConfigTestHelper::create([
                'SLACK_WEBHOOK_URL' => 'https://hooks.example/p0-placeholder',
                'SLACK_WEBHOOK_P1' => 'https://hooks.example/p1-placeholder',
            ]),
            new CollectingLogger(),
        );

        $notifier->sendAlerts([$this->makeVuln(Priority::P1)]);

        self::assertCount(1, $client->calls);
        self::assertSame('https://hooks.example/p1-placeholder', $client->calls[0]['url']);
    }

    #[Test]
    public function testSendAlertsSkipsP1WhenP1WebhookMissing(): void
    {
        $client = new RecordingCurlClient();
        $logger = new CollectingLogger();
        $notifier = new SlackNotifier(
            $client,
            ConfigTestHelper::create([
                'SLACK_WEBHOOK_URL' => 'https://hooks.example/p0-placeholder',
            ]),
            $logger,
        );

        $notifier->sendAlerts([$this->makeVuln(Priority::P1)]);

        self::assertCount(0, $client->calls);
        $warning = $logger->firstMessageContaining('P1 findings present');
        self::assertNotNull($warning);
    }

    #[Test]
    public function testSendAlertsLogsP1SkipOnceOnly(): void
    {
        $logger = new CollectingLogger();
        $notifier = new SlackNotifier(
            new RecordingCurlClient(),
            ConfigTestHelper::create([
                'SLACK_WEBHOOK_URL' => 'https://hooks.example/p0-placeholder',
            ]),
            $logger,
        );

        $notifier->sendAlerts([$this->makeVuln(Priority::P1)]);
        $notifier->sendAlerts([$this->makeVuln(Priority::P1)]);

        $warnings = array_filter(
            $logger->records,
            static fn (array $r): bool => str_contains((string) $r['message'], 'SLACK_WEBHOOK_P1'),
        );
        self::assertCount(1, $warnings);
    }

    private function makeVuln(Priority $priority): Vulnerability
    {
        static $seq = 0;
        $seq++;

        return new Vulnerability(
            canonicalId: "CVE-2025-{$seq}",
            aliases: [],
            description: 'Test vulnerability',
            cvssScore: $priority === Priority::P0 ? 9.8 : 7.5,
            cvssVector: null,
            epssScore: 0.5,
            epssPercentile: 0.9,
            inKev: $priority === Priority::P0,
            knownRansomware: false,
            affectedPackages: [new AffectedPackage('composer', 'vendor/pkg', '<1.0.0', '1.0.0')],
            cwes: [],
            references: [],
            sources: ['test'],
            firstSeen: '2025-01-01T00:00:00+00:00',
            lastUpdated: '2025-01-01T00:00:00+00:00',
            kevDateAdded: null,
            kevDueDate: null,
            kevRequiredAction: null,
            affectsInstalledVersion: false,
            priority: $priority,
            notifiedAtPriority: null,
        );
    }
}

final class RecordingCurlClient extends CurlClient
{
    /** @var array<int, array{url: string, payload: array<string, mixed>}> */
    public array $calls = [];

    public function __construct()
    {
        // Bypass parent constructor; no logger or real HTTP needed.
    }

    /**
     * @param array<string, mixed>|string $body
     * @param array<int, string> $headers
     */
    public function post(string $url, array|string $body, array $headers = []): HttpResponse
    {
        $payload = is_array($body) ? $body : [];
        $this->calls[] = ['url' => $url, 'payload' => $payload];
        return new HttpResponse(200, 'ok', []);
    }
}

final class CollectingLogger extends AbstractLogger
{
    /** @var array<int, array{level: mixed, message: string|Stringable, context: array<string, mixed>}> */
    public array $records = [];

    /**
     * @param array<string, mixed> $context
     */
    public function log(mixed $level, string|Stringable $message, array $context = []): void
    {
        $this->records[] = ['level' => $level, 'message' => $message, 'context' => $context];
    }

    public function firstMessageContaining(string $needle): ?string
    {
        foreach ($this->records as $r) {
            $msg = (string) $r['message'];
            if (str_contains($msg, $needle)) {
                return $msg;
            }
        }
        return null;
    }
}
