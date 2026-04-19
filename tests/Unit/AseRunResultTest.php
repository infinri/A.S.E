<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use Ase\Ase;
use Ase\Dedup\Deduplicator;
use Ase\Feed\EpssFeed;
use Ase\Feed\FeedInterface;
use Ase\Filter\ComposerLockAnalyzer;
use Ase\Health\DigestReporter;
use Ase\Health\FeedHealthTracker;
use Ase\Http\CurlClient;
use Ase\Logging\CorrelationIdProcessor;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;
use Ase\Model\VulnerabilityBatch;
use Ase\Notify\SlackNotifier;
use Ase\Run\RunResult;
use Ase\Scoring\PriorityCalculator;
use Ase\State\StateManager;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class AseRunResultTest extends TestCase
{
    private string $tmpDir;
    private string $stateFile;
    private string $heartbeatFile;
    private string $lockFile;
    private string $originalCwd;
    private string $cwdScratch;

    protected function setUp(): void
    {
        $this->originalCwd = getcwd() ?: sys_get_temp_dir();
        $this->tmpDir = sys_get_temp_dir() . '/ase_run_test_' . uniqid();
        mkdir($this->tmpDir, 0755, true);
        $this->stateFile = $this->tmpDir . '/state.json';
        $this->heartbeatFile = $this->tmpDir . '/heartbeat.txt';
        $this->lockFile = $this->tmpDir . '/composer.lock';

        // Isolate cwd so Config::composerLockPath() walk-up does not pick up
        // the ase project's own composer.lock.
        $this->cwdScratch = $this->tmpDir . '/cwd';
        mkdir($this->cwdScratch, 0755, true);
        chdir($this->cwdScratch);
    }

    protected function tearDown(): void
    {
        chdir($this->originalCwd);
        @rmdir($this->cwdScratch);
        $files = glob($this->tmpDir . '/*');
        if ($files !== false) {
            array_map('unlink', $files);
        }
        @rmdir($this->tmpDir);
    }

    #[Test]
    public function testRunReturnsRunResultWithExitCode0WhenNoAlerts(): void
    {
        $feed = new StubFeed('test', []);
        $spy = new SpySlackNotifier();

        $ase = $this->buildAse($feed, $spy);
        $result = $ase->run(dryRun: false);

        self::assertInstanceOf(RunResult::class, $result);
        self::assertSame(0, $result->exitCode);
        self::assertFalse($result->dryRun);
    }

    #[Test]
    public function testRunReturnsRunResultWithExitCode2WhenP0Alert(): void
    {
        $feed = new StubFeed('test', [$this->makeVuln(Priority::P0)]);
        $spy = new SpySlackNotifier();

        // Seed state so isFirstRun() is false -- otherwise silent import mode swallows alerts.
        $this->seedState();

        $ase = $this->buildAse($feed, $spy);
        $result = $ase->run(dryRun: false);

        self::assertSame(2, $result->exitCode);
    }

    #[Test]
    public function testRunWithDryRunTrueDoesNotCallSlack(): void
    {
        $feed = new StubFeed('test', [$this->makeVuln(Priority::P0)]);
        $spy = new SpySlackNotifier();

        $this->seedState();

        $ase = $this->buildAse($feed, $spy);
        $result = $ase->run(dryRun: true);

        self::assertTrue($result->dryRun);
        self::assertSame(0, $spy->sendAlertsCalls);
    }

    #[Test]
    public function testRunWithDryRunTrueDoesNotSaveState(): void
    {
        $feed = new StubFeed('test', [$this->makeVuln(Priority::P2)]);
        $spy = new SpySlackNotifier();

        $ase = $this->buildAse($feed, $spy);
        $ase->run(dryRun: true);

        self::assertFileDoesNotExist($this->stateFile);
    }

    #[Test]
    public function testRunWithDryRunTrueDoesNotWriteHeartbeat(): void
    {
        $feed = new StubFeed('test', []);
        $spy = new SpySlackNotifier();

        $ase = $this->buildAse($feed, $spy);
        $ase->run(dryRun: true);

        self::assertFileDoesNotExist($this->heartbeatFile);
    }

    #[Test]
    public function testRunReturnsDetectedMagentoEditionInResult(): void
    {
        file_put_contents(
            $this->lockFile,
            json_encode([
                'packages' => [
                    ['name' => 'magento/product-community-edition', 'version' => '2.4.7'],
                ],
                'packages-dev' => [],
            ], JSON_THROW_ON_ERROR),
        );

        $feed = new StubFeed('test', []);
        $spy = new SpySlackNotifier();

        $ase = $this->buildAse($feed, $spy, $this->lockFile);
        $result = $ase->run(dryRun: true);

        self::assertNotNull($result->magento);
        self::assertSame('magento-community', $result->magento->edition);
        self::assertSame('2.4.7', $result->magento->version);
    }

    #[Test]
    public function testRunResultMagentoIsNullWhenEditionNotDetected(): void
    {
        file_put_contents(
            $this->lockFile,
            json_encode([
                'packages' => [
                    ['name' => 'monolog/monolog', 'version' => '3.0.0'],
                ],
                'packages-dev' => [],
            ], JSON_THROW_ON_ERROR),
        );

        $feed = new StubFeed('test', []);
        $spy = new SpySlackNotifier();

        $ase = $this->buildAse($feed, $spy, $this->lockFile);
        $result = $ase->run(dryRun: true);

        self::assertNull($result->magento);
    }

    #[Test]
    public function testRunWithNormalModeCallsSlackAndSavesState(): void
    {
        $feed = new StubFeed('test', [$this->makeVuln(Priority::P0)]);
        $spy = new SpySlackNotifier();

        $this->seedState();

        $ase = $this->buildAse($feed, $spy);
        $ase->run(dryRun: false);

        self::assertSame(1, $spy->sendAlertsCalls);
        self::assertFileExists($this->stateFile);
    }

    /**
     * Seed the state file with a non-null last_run so subsequent Ase::run() calls
     * are not treated as first-run silent-import.
     */
    private function seedState(): void
    {
        $seed = [
            'version' => 1,
            'last_run' => date('c'),
            'feed_cursors' => [],
            'feed_health' => [],
            'vulnerabilities' => [],
            'stats' => [
                'total_tracked' => 0,
                'total_notified' => 0,
                'total_escalations' => 0,
                'last_digest' => null,
            ],
        ];
        file_put_contents($this->stateFile, json_encode($seed, JSON_THROW_ON_ERROR));
    }

    private function makeVuln(Priority $priority): Vulnerability
    {
        static $seq = 0;
        $seq++;

        return new Vulnerability(
            canonicalId: "CVE-2025-{$seq}",
            aliases: [],
            description: 'Test vulnerability',
            cvssScore: $priority === Priority::P0 ? 9.8 : 5.0,
            cvssVector: null,
            epssScore: $priority === Priority::P0 ? 0.95 : 0.01,
            epssPercentile: null,
            inKev: $priority === Priority::P0,
            knownRansomware: false,
            affectedPackages: [],
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

    private function makeBatch(array $vulns): VulnerabilityBatch
    {
        return new VulnerabilityBatch('test', $vulns);
    }

    private function buildAse(
        FeedInterface $feed,
        SpySlackNotifier $spy,
        string $lockPath = '',
    ): Ase {
        $config = ConfigTestHelper::create(array_filter([
            'STATE_FILE' => $this->stateFile,
            'HEARTBEAT_FILE' => $this->heartbeatFile,
            'COMPOSER_LOCK_PATH' => $lockPath !== '' ? $lockPath : null,
            'ENABLED_FEEDS' => 'test',
            'POLL_INTERVAL_TEST' => '0',
        ]));

        $logger = new NullLogger();
        $stateManager = new StateManager($this->stateFile, $logger);
        $epss = new class(new CurlClient($logger), $logger) extends EpssFeed {
            public function enrichVulnerabilities(array $vulnerabilities): array
            {
                return $vulnerabilities;
            }
        };
        $deduplicator = new Deduplicator($logger);
        $priorityCalculator = new PriorityCalculator($config);
        $composerLockAnalyzer = new ComposerLockAnalyzer($config, $logger);
        $healthTracker = new FeedHealthTracker($logger);
        $digestReporter = new DigestReporter(new CurlClient($logger), $config, $logger);

        return new Ase(
            config: $config,
            stateManager: $stateManager,
            feeds: [$feed],
            epss: $epss,
            deduplicator: $deduplicator,
            priorityCalculator: $priorityCalculator,
            composerLockAnalyzer: $composerLockAnalyzer,
            slackNotifier: $spy,
            healthTracker: $healthTracker,
            digestReporter: $digestReporter,
            logger: $logger,
            correlationIdProcessor: new CorrelationIdProcessor(),
        );
    }

    #[Test]
    public function testRunResultContainsGeneratedRunId(): void
    {
        $feed = new StubFeed('test', [$this->makeVuln(Priority::P2)]);
        $ase = $this->buildAse($feed, new SpySlackNotifier());

        $result = $ase->run(dryRun: true);

        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $result->runId,
        );
    }

    #[Test]
    public function testTwoRunsProduceDistinctRunIds(): void
    {
        $feed = new StubFeed('test', [$this->makeVuln(Priority::P2)]);
        $ase = $this->buildAse($feed, new SpySlackNotifier());

        $first = $ase->run(dryRun: true);
        $second = $ase->run(dryRun: true);

        self::assertNotSame($first->runId, $second->runId);
    }
}

/**
 * Test double for SlackNotifier that records calls without hitting the network.
 */
final class SpySlackNotifier extends SlackNotifier
{
    public int $sendAlertsCalls = 0;

    public function __construct()
    {
        // Do not call parent::__construct() -- no real HTTP client needed in tests.
    }

    public function sendAlerts(array $newAlerts, array $escalations = []): int
    {
        $this->sendAlertsCalls++;
        return count($newAlerts) + count($escalations);
    }
}

/**
 * In-memory FeedInterface implementation that returns a pre-built batch on poll().
 */
final class StubFeed implements FeedInterface
{
    /** @param Vulnerability[] $vulns */
    public function __construct(
        private readonly string $name,
        private readonly array $vulns,
    ) {}

    public function getName(): string
    {
        return $this->name;
    }

    public function poll(string $lastPollTimestamp): VulnerabilityBatch
    {
        $keyed = [];
        foreach ($this->vulns as $v) {
            $keyed[$v->canonicalId] = $v;
        }
        return new VulnerabilityBatch($this->name, $keyed);
    }

    /** @param array<string, mixed> $data */
    public function validateResponse(array $data): bool
    {
        return true;
    }
}
