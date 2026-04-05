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
    public function kevAlwaysClassifiesAsP0(): void
    {
        $vuln = $this->makeVuln(inKev: true, cvssScore: 2.0, epssScore: 0.001);

        self::assertSame(Priority::P0, $this->calculator->classify($vuln));
    }

    #[Test]
    public function criticalCvssWithHighEpssIsP0(): void
    {
        $vuln = $this->makeVuln(cvssScore: 9.8, epssScore: 0.15);

        self::assertSame(Priority::P0, $this->calculator->classify($vuln));
    }

    #[Test]
    public function criticalCvssWithoutEpssIsNotP0(): void
    {
        $vuln = $this->makeVuln(cvssScore: 9.8, epssScore: null);

        // Falls through to P2 (CVSS >= 7.0)
        self::assertSame(Priority::P2, $this->calculator->classify($vuln));
    }

    #[Test]
    public function ransomwareClassifiesAsP1(): void
    {
        $vuln = $this->makeVuln(knownRansomware: true, cvssScore: 3.0);

        self::assertSame(Priority::P1, $this->calculator->classify($vuln));
    }

    #[Test]
    public function highCvssWithHighEpssIsP1(): void
    {
        $vuln = $this->makeVuln(cvssScore: 7.5, epssScore: 0.12);

        self::assertSame(Priority::P1, $this->calculator->classify($vuln));
    }

    #[Test]
    public function affectsInstalledWithHighCvssIsP1(): void
    {
        $vuln = $this->makeVuln(cvssScore: 8.0, affectsInstalled: true);

        self::assertSame(Priority::P1, $this->calculator->classify($vuln));
    }

    #[Test]
    public function highCvssAloneIsP2(): void
    {
        $vuln = $this->makeVuln(cvssScore: 7.5, epssScore: 0.02);

        self::assertSame(Priority::P2, $this->calculator->classify($vuln));
    }

    #[Test]
    public function mediumEpssAloneIsP2(): void
    {
        $vuln = $this->makeVuln(cvssScore: 3.0, epssScore: 0.06);

        self::assertSame(Priority::P2, $this->calculator->classify($vuln));
    }

    #[Test]
    public function mediumCvssWithLowEpssIsP3(): void
    {
        $vuln = $this->makeVuln(cvssScore: 5.0, epssScore: 0.01);

        self::assertSame(Priority::P3, $this->calculator->classify($vuln));
    }

    #[Test]
    public function lowCvssLowEpssIsP4(): void
    {
        $vuln = $this->makeVuln(cvssScore: 2.0, epssScore: 0.001);

        self::assertSame(Priority::P4, $this->calculator->classify($vuln));
    }

    #[Test]
    public function nullScoresDefaultToP4(): void
    {
        $vuln = $this->makeVuln(cvssScore: null, epssScore: null);

        self::assertSame(Priority::P4, $this->calculator->classify($vuln));
    }

    #[Test]
    public function fallbackCvssFromCvss3VectorNetworkLow(): void
    {
        // No cvssScore, but has a vector -- should estimate 9.0 for AV:N/AC:L
        $vuln = $this->makeVuln(
            cvssScore: null,
            cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        );

        // Estimated 9.0, no EPSS -> P2 (CVSS >= 7.0)
        self::assertSame(Priority::P2, $this->calculator->classify($vuln));
    }

    #[Test]
    public function fallbackCvssFromCvss3VectorNetworkOnly(): void
    {
        // AV:N without AC:L estimates 7.5
        $vuln = $this->makeVuln(
            cvssScore: null,
            cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
        );

        self::assertSame(Priority::P2, $this->calculator->classify($vuln));
    }

    #[Test]
    public function fallbackCvssFromCvss3VectorAdjacent(): void
    {
        $vuln = $this->makeVuln(
            cvssScore: null,
            cvssVector: 'CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        );

        // Estimated 5.5 -> P3 (>= 4.0)
        self::assertSame(Priority::P3, $this->calculator->classify($vuln));
    }

    #[Test]
    public function fallbackCvssFromCvss3VectorLocal(): void
    {
        $vuln = $this->makeVuln(
            cvssScore: null,
            cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        );

        // Estimated 4.0 -> P3
        self::assertSame(Priority::P3, $this->calculator->classify($vuln));
    }

    #[Test]
    public function fallbackIgnoresNonCvss3Vectors(): void
    {
        $vuln = $this->makeVuln(
            cvssScore: null,
            cvssVector: 'CVSS:4.0/AV:N/AC:L',
        );

        self::assertSame(Priority::P4, $this->calculator->classify($vuln));
    }

    #[Test]
    public function classifyAllAppliesPriorityToEachVuln(): void
    {
        $vulns = [
            'CVE-1' => $this->makeVuln(cvssScore: 9.8, epssScore: 0.15, id: 'CVE-1'),
            'CVE-2' => $this->makeVuln(cvssScore: 2.0, epssScore: 0.001, id: 'CVE-2'),
        ];

        $result = $this->calculator->classifyAll($vulns);

        self::assertSame(Priority::P0, $result['CVE-1']->priority);
        self::assertSame(Priority::P4, $result['CVE-2']->priority);
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
            priority: Priority::P4,
            notifiedAtPriority: null,
        );
    }
}
