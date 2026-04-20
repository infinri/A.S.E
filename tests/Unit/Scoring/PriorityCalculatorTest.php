<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Scoring;

use Ase\Model\Priority;
use Ase\Model\Vulnerability;
use Ase\Scoring\PriorityCalculator;
use Ase\Tests\Unit\ConfigTestHelper;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class PriorityCalculatorTest extends TestCase
{
    private PriorityCalculator $calculator;

    protected function setUp(): void
    {
        $this->calculator = new PriorityCalculator(ConfigTestHelper::withDefaults());
    }

    #[Test]
    public function inKevIsP0(): void
    {
        $vuln = $this->makeVuln(cvssScore: 5.0, epssScore: 0.01, inKev: true);
        self::assertSame(Priority::P0, $this->calculator->classify($vuln));
    }

    #[Test]
    public function criticalCvssWithHighEpssIsP0(): void
    {
        $vuln = $this->makeVuln(cvssScore: 9.5, epssScore: 0.25);
        self::assertSame(Priority::P0, $this->calculator->classify($vuln));
    }

    #[Test]
    public function knownRansomwareIsP1(): void
    {
        $vuln = $this->makeVuln(cvssScore: 5.0, epssScore: 0.01, knownRansomware: true);
        self::assertSame(Priority::P1, $this->calculator->classify($vuln));
    }

    #[Test]
    public function highCvssWithHighEpssIsP1(): void
    {
        $vuln = $this->makeVuln(cvssScore: 7.5, epssScore: 0.15);
        self::assertSame(Priority::P1, $this->calculator->classify($vuln));
    }

    #[Test]
    public function affectsInstalledWithHighCvssIsP1(): void
    {
        $vuln = $this->makeVuln(cvssScore: 7.5, epssScore: 0.01, affectsInstalled: true);
        self::assertSame(Priority::P1, $this->calculator->classify($vuln));
    }

    #[Test]
    public function highCvssAloneReturnsNull(): void
    {
        $vuln = $this->makeVuln(cvssScore: 7.5, epssScore: 0.01);
        self::assertNull($this->calculator->classify($vuln));
    }

    #[Test]
    public function mediumScoresReturnNull(): void
    {
        $vuln = $this->makeVuln(cvssScore: 5.0, epssScore: 0.06);
        self::assertNull($this->calculator->classify($vuln));
    }

    #[Test]
    public function lowScoresWithoutKevReturnNull(): void
    {
        $vuln = $this->makeVuln(cvssScore: 3.0, epssScore: 0.001);
        self::assertNull($this->calculator->classify($vuln));
    }

    #[Test]
    public function nullScoresReturnNull(): void
    {
        $vuln = $this->makeVuln(cvssScore: null, epssScore: null);
        self::assertNull($this->calculator->classify($vuln));
    }

    #[Test]
    public function fallbackCvssFromCvss3VectorNetworkLowUsedForP0(): void
    {
        $vuln = $this->makeVuln(
            cvssScore: null,
            epssScore: 0.25,
            cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        );
        self::assertSame(Priority::P0, $this->calculator->classify($vuln));
    }

    #[Test]
    public function fallbackCvssFromCvss3VectorNetworkOnlyUsedForP1(): void
    {
        $vuln = $this->makeVuln(
            cvssScore: null,
            epssScore: 0.25,
            cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
        );
        self::assertSame(Priority::P1, $this->calculator->classify($vuln));
    }

    #[Test]
    public function fallbackCvssFromCvss3VectorLocalReturnsNull(): void
    {
        $vuln = $this->makeVuln(
            cvssScore: null,
            epssScore: 0.25,
            cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        );
        self::assertNull($this->calculator->classify($vuln));
    }

    #[Test]
    public function fallbackIgnoresNonCvss3Vectors(): void
    {
        $vuln = $this->makeVuln(
            cvssScore: null,
            epssScore: 0.25,
            cvssVector: 'AV:N/AC:L',
        );
        self::assertNull($this->calculator->classify($vuln));
    }

    #[Test]
    public function classifyAllFiltersOutNonAlertable(): void
    {
        $vulns = [
            'CVE-1' => $this->makeVuln(cvssScore: 9.5, epssScore: 0.25, id: 'CVE-1'),
            'CVE-2' => $this->makeVuln(cvssScore: 2.0, epssScore: 0.001, id: 'CVE-2'),
            'CVE-3' => $this->makeVuln(cvssScore: 7.5, epssScore: 0.15, id: 'CVE-3'),
        ];

        $result = $this->calculator->classifyAll($vulns);

        self::assertCount(2, $result);
        self::assertArrayHasKey('CVE-1', $result);
        self::assertArrayHasKey('CVE-3', $result);
        self::assertArrayNotHasKey('CVE-2', $result);
        self::assertSame(Priority::P0, $result['CVE-1']->priority);
        self::assertSame(Priority::P1, $result['CVE-3']->priority);
    }

    private function makeVuln(
        ?float $cvssScore = null,
        ?float $epssScore = null,
        ?string $cvssVector = null,
        bool $inKev = false,
        bool $knownRansomware = false,
        bool $affectsInstalled = false,
        string $id = 'CVE-2025-0001',
    ): Vulnerability {
        return new Vulnerability(
            canonicalId: $id,
            aliases: [],
            description: 'Test',
            cvssScore: $cvssScore,
            cvssVector: $cvssVector,
            epssScore: $epssScore,
            epssPercentile: null,
            inKev: $inKev,
            knownRansomware: $knownRansomware,
            affectedPackages: [],
            cwes: [],
            references: [],
            sources: ['test'],
            firstSeen: '2025-01-01T00:00:00+00:00',
            lastUpdated: '2025-01-01T00:00:00+00:00',
            kevDateAdded: null,
            kevDueDate: null,
            kevRequiredAction: null,
            affectsInstalledVersion: $affectsInstalled,
            priority: Priority::P1,
            notifiedAtPriority: null,
        );
    }
}
