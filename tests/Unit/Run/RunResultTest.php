<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Run;

use Ase\Model\AffectedPackage;
use Ase\Model\MagentoEdition;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;
use Ase\Run\RunResult;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class RunResultTest extends TestCase
{
    #[Test]
    public function testFromClassificationExitCode0WhenNoAlerts(): void
    {
        $result = RunResult::fromClassification([], [], null, false);
        self::assertSame(0, $result->exitCode);
    }

    #[Test]
    public function testFromClassificationExitCode1WhenP1Present(): void
    {
        $result = RunResult::fromClassification(
            [$this->makeVuln(Priority::P1), $this->makeVuln(Priority::P2)],
            [],
            null,
            false,
        );
        self::assertSame(1, $result->exitCode);
    }

    #[Test]
    public function testFromClassificationExitCode2WhenP0Present(): void
    {
        $result = RunResult::fromClassification(
            [$this->makeVuln(Priority::P0)],
            [],
            null,
            false,
        );
        self::assertSame(2, $result->exitCode);
    }

    #[Test]
    public function testFromClassificationExitCode2WinsOverP1(): void
    {
        $result = RunResult::fromClassification(
            [$this->makeVuln(Priority::P1), $this->makeVuln(Priority::P0)],
            [],
            null,
            false,
        );
        self::assertSame(2, $result->exitCode);
    }

    #[Test]
    public function testFromClassificationCountsEscalations(): void
    {
        // P0 appears only in escalations -> should still promote exit code to 2.
        $result = RunResult::fromClassification(
            [$this->makeVuln(Priority::P2)],
            [$this->makeVuln(Priority::P0)],
            null,
            false,
        );
        self::assertSame(2, $result->exitCode);
        self::assertCount(1, $result->newAlerts);
        self::assertCount(1, $result->escalations);
    }

    #[Test]
    public function testFromClassificationExitCodeIgnoresP2P3P4(): void
    {
        $result = RunResult::fromClassification(
            [
                $this->makeVuln(Priority::P2),
                $this->makeVuln(Priority::P3),
                $this->makeVuln(Priority::P4),
            ],
            [],
            null,
            false,
        );
        self::assertSame(0, $result->exitCode);
    }

    #[Test]
    public function testToJsonArrayShape(): void
    {
        $result = RunResult::fromClassification([], [], null, false);
        $json = $result->toJsonArray();

        self::assertArrayHasKey('run_id', $json);
        self::assertArrayHasKey('magento', $json);
        self::assertArrayHasKey('findings', $json);
        self::assertArrayHasKey('summary', $json);
        self::assertArrayHasKey('exit_code', $json);
        self::assertNull($json['run_id']);
        self::assertNull($json['magento']);
        self::assertSame([], $json['findings']);
        self::assertSame(
            ['P0' => 0, 'P1' => 0, 'P2' => 0, 'P3' => 0, 'P4' => 0],
            $json['summary'],
        );
        self::assertSame(0, $json['exit_code']);
    }

    #[Test]
    public function testToJsonArraySerializesMagento(): void
    {
        $magento = new MagentoEdition('magento-community', '2.4.7', 'magento/product-community-edition');
        $result = RunResult::fromClassification([], [], $magento, false);
        $json = $result->toJsonArray();

        self::assertSame(
            [
                'edition' => 'magento-community',
                'version' => '2.4.7',
                'package' => 'magento/product-community-edition',
            ],
            $json['magento'],
        );
    }

    #[Test]
    public function testToJsonArraySerializesFindings(): void
    {
        $newAlerts = [$this->makeVuln(Priority::P0), $this->makeVuln(Priority::P2)];
        $escalations = [$this->makeVuln(Priority::P1)];

        $result = RunResult::fromClassification($newAlerts, $escalations, null, false);
        $json = $result->toJsonArray();

        self::assertCount(3, $json['findings']);
        self::assertSame(1, $json['summary']['P0']);
        self::assertSame(1, $json['summary']['P1']);
        self::assertSame(1, $json['summary']['P2']);
        self::assertSame(0, $json['summary']['P3']);
        self::assertSame(0, $json['summary']['P4']);
    }

    #[Test]
    public function testToJsonArrayIncludesExitCode(): void
    {
        $result = RunResult::fromClassification(
            [$this->makeVuln(Priority::P0)],
            [],
            null,
            false,
        );
        self::assertSame(2, $result->toJsonArray()['exit_code']);
    }

    #[Test]
    public function testDryRunFlagPropagated(): void
    {
        $dry = RunResult::fromClassification([], [], null, true);
        self::assertTrue($dry->dryRun);

        $live = RunResult::fromClassification([], [], null, false);
        self::assertFalse($live->dryRun);
    }

    private function makeVuln(Priority $priority): Vulnerability
    {
        static $seq = 0;
        $seq++;

        return new Vulnerability(
            canonicalId: "CVE-2025-{$seq}",
            aliases: [],
            description: 'Test vulnerability',
            cvssScore: null,
            cvssVector: null,
            epssScore: null,
            epssPercentile: null,
            inKev: false,
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
            affectsInstalledVersion: true,
            priority: $priority,
            notifiedAtPriority: null,
        );
    }
}
