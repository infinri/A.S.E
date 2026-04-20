<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\State;

use Ase\State\StateManager;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class StateManagerTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/ase_test_' . uniqid();
        mkdir($this->tmpDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $files = glob($this->tmpDir . '/*');
        if ($files !== false) {
            array_map('unlink', $files);
        }
        @rmdir($this->tmpDir);
    }

    #[Test]
    public function loadReturnsDefaultsWhenFileDoesNotExist(): void
    {
        $mgr = new StateManager($this->tmpDir . '/missing.json', new NullLogger());
        $state = $mgr->load();

        self::assertSame(1, $state['version']);
        self::assertNull($state['last_run']);
        self::assertSame([], $state['feed_cursors']);
        self::assertSame([], $state['vulnerabilities']);
    }

    #[Test]
    public function isFirstRunReturnsTrueForNewState(): void
    {
        $mgr = new StateManager($this->tmpDir . '/missing.json', new NullLogger());

        self::assertTrue($mgr->isFirstRun());
    }

    #[Test]
    public function saveAndLoadRoundTrip(): void
    {
        $path = $this->tmpDir . '/state.json';
        $mgr = new StateManager($path, new NullLogger());

        $state = $mgr->load();
        $state['vulnerabilities'] = ['CVE-2025-0001' => ['canonical_id' => 'CVE-2025-0001']];
        $mgr->save($state);

        // Create new instance to force reload from disk
        $mgr2 = new StateManager($path, new NullLogger());
        $loaded = $mgr2->load();

        self::assertNotNull($loaded['last_run']);
        self::assertArrayHasKey('CVE-2025-0001', $loaded['vulnerabilities']);
        self::assertSame(1, $loaded['stats']['total_tracked']);
    }

    #[Test]
    public function isFirstRunReturnsFalseAfterSave(): void
    {
        $path = $this->tmpDir . '/state.json';
        $mgr = new StateManager($path, new NullLogger());

        $mgr->save($mgr->load());

        $mgr2 = new StateManager($path, new NullLogger());

        self::assertFalse($mgr2->isFirstRun());
    }

    #[Test]
    public function getVulnerabilityReturnsNullWhenMissing(): void
    {
        $mgr = new StateManager($this->tmpDir . '/missing.json', new NullLogger());

        self::assertNull($mgr->getVulnerability('CVE-9999-0000'));
    }

    #[Test]
    public function getVulnerabilityReturnsStoredData(): void
    {
        $path = $this->tmpDir . '/state.json';
        $mgr = new StateManager($path, new NullLogger());

        $state = $mgr->load();
        $state['vulnerabilities']['CVE-2025-0001'] = ['canonical_id' => 'CVE-2025-0001', 'cvss' => 9.8];
        $mgr->save($state);

        $mgr2 = new StateManager($path, new NullLogger());

        self::assertNotNull($mgr2->getVulnerability('CVE-2025-0001'));
        self::assertSame(9.8, $mgr2->getVulnerability('CVE-2025-0001')['cvss']);
    }

    #[Test]
    public function getFeedCursorReturnsNullForUnknownFeed(): void
    {
        $mgr = new StateManager($this->tmpDir . '/missing.json', new NullLogger());

        self::assertNull($mgr->getFeedCursor('nvd'));
    }

    #[Test]
    public function getFeedHealthReturnsDefaults(): void
    {
        $mgr = new StateManager($this->tmpDir . '/missing.json', new NullLogger());
        $health = $mgr->getFeedHealth('nvd');

        self::assertNull($health['last_success']);
        self::assertNull($health['last_failure']);
        self::assertSame(0, $health['consecutive_failures']);
    }

    #[Test]
    public function loadHandlesCorruptedJsonGracefully(): void
    {
        $path = $this->tmpDir . '/corrupt.json';
        file_put_contents($path, '{invalid json!!!');

        $mgr = new StateManager($path, new NullLogger());
        $state = $mgr->load();

        self::assertSame(1, $state['version']);
        self::assertNull($state['last_run']);
    }

    #[Test]
    public function loadHandlesEmptyFile(): void
    {
        $path = $this->tmpDir . '/empty.json';
        file_put_contents($path, '');

        $mgr = new StateManager($path, new NullLogger());
        $state = $mgr->load();

        self::assertSame(1, $state['version']);
    }

    #[Test]
    public function saveSetsLastRunAndTotalTracked(): void
    {
        $path = $this->tmpDir . '/state.json';
        $mgr = new StateManager($path, new NullLogger());

        $state = $mgr->load();
        $state['vulnerabilities'] = [
            'CVE-1' => ['id' => '1'],
            'CVE-2' => ['id' => '2'],
        ];
        $mgr->save($state);

        $mgr2 = new StateManager($path, new NullLogger());
        $loaded = $mgr2->load();

        self::assertNotNull($loaded['last_run']);
        self::assertSame(2, $loaded['stats']['total_tracked']);
    }

    #[Test]
    public function testLoadPrunesLegacyP2PriorityEntries(): void
    {
        $path = $this->tmpDir . '/state-with-legacy.json';
        file_put_contents($path, json_encode([
            'vulnerabilities' => [
                'CVE-A' => ['canonical_id' => 'CVE-A', 'priority' => 'P0'],
                'CVE-B' => ['canonical_id' => 'CVE-B', 'priority' => 'P1'],
                'CVE-C' => ['canonical_id' => 'CVE-C', 'priority' => 'P2'],
                'CVE-D' => ['canonical_id' => 'CVE-D', 'priority' => 'P3'],
                'CVE-E' => ['canonical_id' => 'CVE-E', 'priority' => 'P4'],
            ],
        ], JSON_THROW_ON_ERROR));

        $mgr = new StateManager($path, new NullLogger());
        $state = $mgr->load();

        self::assertArrayHasKey('CVE-A', $state['vulnerabilities']);
        self::assertArrayHasKey('CVE-B', $state['vulnerabilities']);
        self::assertArrayNotHasKey('CVE-C', $state['vulnerabilities']);
        self::assertArrayNotHasKey('CVE-D', $state['vulnerabilities']);
        self::assertArrayNotHasKey('CVE-E', $state['vulnerabilities']);
    }

    #[Test]
    public function testLoadLogsPruneCountWhenAboveZero(): void
    {
        $path = $this->tmpDir . '/state-legacy.json';
        file_put_contents($path, json_encode([
            'vulnerabilities' => [
                'CVE-A' => ['canonical_id' => 'CVE-A', 'priority' => 'P2'],
                'CVE-B' => ['canonical_id' => 'CVE-B', 'priority' => 'P3'],
                'CVE-C' => ['canonical_id' => 'CVE-C', 'priority' => 'P4'],
            ],
        ], JSON_THROW_ON_ERROR));

        $logger = new \Ase\Tests\Unit\State\TestCollectingLogger();
        $mgr = new StateManager($path, $logger);
        $mgr->load();

        $match = $logger->firstRecordMatching('Pruned legacy priority entries');
        self::assertNotNull($match);
        self::assertSame(3, $match['context']['count']);
    }

    #[Test]
    public function testLoadLogsNothingWhenNoLegacyEntries(): void
    {
        $path = $this->tmpDir . '/state-clean.json';
        file_put_contents($path, json_encode([
            'vulnerabilities' => [
                'CVE-A' => ['canonical_id' => 'CVE-A', 'priority' => 'P0'],
                'CVE-B' => ['canonical_id' => 'CVE-B', 'priority' => 'P1'],
            ],
        ], JSON_THROW_ON_ERROR));

        $logger = new \Ase\Tests\Unit\State\TestCollectingLogger();
        $mgr = new StateManager($path, $logger);
        $mgr->load();

        self::assertNull($logger->firstRecordMatching('Pruned legacy priority entries'));
    }
}

final class TestCollectingLogger extends \Psr\Log\AbstractLogger
{
    /** @var array<int, array{level: mixed, message: string, context: array<string, mixed>}> */
    public array $records = [];

    /**
     * @param array<string, mixed> $context
     */
    public function log(mixed $level, string|\Stringable $message, array $context = []): void
    {
        $this->records[] = ['level' => $level, 'message' => (string) $message, 'context' => $context];
    }

    /**
     * @return array{level: mixed, message: string, context: array<string, mixed>}|null
     */
    public function firstRecordMatching(string $needle): ?array
    {
        foreach ($this->records as $r) {
            if (str_contains($r['message'], $needle)) {
                return $r;
            }
        }
        return null;
    }
}