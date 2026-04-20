<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Dedup;

use Ase\Dedup\Deduplicator;
use Ase\Model\AffectedPackage;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;
use Ase\Model\VulnerabilityBatch;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class DeduplicatorTest extends TestCase
{
    private Deduplicator $dedup;

    protected function setUp(): void
    {
        $this->dedup = new Deduplicator(new NullLogger());
    }

    #[Test]
    public function mergeWithEmptyBatchesReturnsExisting(): void
    {
        $existing = [
            'CVE-2025-0001' => $this->makeVulnArray('CVE-2025-0001'),
        ];

        $result = $this->dedup->merge($existing);

        self::assertCount(1, $result->allVulnerabilities);
        self::assertCount(0, $result->newVulnerabilities);
        self::assertCount(0, $result->updatedVulnerabilities);
    }

    #[Test]
    public function mergeAddsNewVulnerability(): void
    {
        $batch = new VulnerabilityBatch('nvd', [$this->makeVuln('CVE-2025-0002')]);

        $result = $this->dedup->merge([], $batch);

        self::assertCount(1, $result->newVulnerabilities);
        self::assertCount(0, $result->updatedVulnerabilities);
        self::assertArrayHasKey('CVE-2025-0002', $result->allVulnerabilities);
    }

    #[Test]
    public function mergeUpdatesExistingVulnerabilityByCanonicalId(): void
    {
        $existing = [
            'CVE-2025-0001' => $this->makeVulnArray('CVE-2025-0001', cvssScore: 5.0),
        ];

        $incoming = $this->makeVuln('CVE-2025-0001', cvssScore: 9.0, sources: ['kev']);
        $batch = new VulnerabilityBatch('kev', [$incoming]);

        $result = $this->dedup->merge($existing, $batch);

        self::assertCount(0, $result->newVulnerabilities);
        self::assertCount(1, $result->updatedVulnerabilities);
        // Keeps highest CVSS
        self::assertSame(9.0, $result->allVulnerabilities['CVE-2025-0001']->cvssScore);
    }

    #[Test]
    public function mergeResolvesViaAliasIndex(): void
    {
        $existing = [
            'CVE-2025-0001' => $this->makeVulnArray(
                'CVE-2025-0001',
                aliases: ['GHSA-xxxx-yyyy-zzzz'],
            ),
        ];

        // Incoming uses the alias as its canonical ID
        $incoming = $this->makeVuln('GHSA-xxxx-yyyy-zzzz', cvssScore: 8.0);
        $batch = new VulnerabilityBatch('ghsa', [$incoming]);

        $result = $this->dedup->merge($existing, $batch);

        self::assertCount(0, $result->newVulnerabilities);
        self::assertCount(1, $result->updatedVulnerabilities);
        self::assertArrayHasKey('CVE-2025-0001', $result->allVulnerabilities);
    }

    #[Test]
    public function mergeResolvesViaIncomingAliases(): void
    {
        $existing = [
            'CVE-2025-0001' => $this->makeVulnArray('CVE-2025-0001'),
        ];

        // Incoming has a different canonical ID but lists CVE-2025-0001 as alias
        $incoming = $this->makeVuln(
            'GHSA-new-advisory',
            aliases: ['CVE-2025-0001'],
            cvssScore: 7.5,
        );
        $batch = new VulnerabilityBatch('ghsa', [$incoming]);

        $result = $this->dedup->merge($existing, $batch);

        self::assertCount(0, $result->newVulnerabilities);
        self::assertCount(1, $result->updatedVulnerabilities);
        self::assertArrayHasKey('CVE-2025-0001', $result->allVulnerabilities);
    }

    #[Test]
    public function mergeUnionsSources(): void
    {
        $existing = [
            'CVE-2025-0001' => $this->makeVulnArray('CVE-2025-0001', sources: ['nvd']),
        ];

        $incoming = $this->makeVuln('CVE-2025-0001', sources: ['kev']);
        $batch = new VulnerabilityBatch('kev', [$incoming]);

        $result = $this->dedup->merge($existing, $batch);
        $sources = $result->allVulnerabilities['CVE-2025-0001']->sources;

        self::assertContains('nvd', $sources);
        self::assertContains('kev', $sources);
    }

    #[Test]
    public function mergeOrsKevAndRansomwareFlags(): void
    {
        $existing = [
            'CVE-2025-0001' => $this->makeVulnArray('CVE-2025-0001', inKev: false),
        ];

        $incoming = $this->makeVuln('CVE-2025-0001', inKev: true, knownRansomware: true);
        $batch = new VulnerabilityBatch('kev', [$incoming]);

        $result = $this->dedup->merge($existing, $batch);
        $merged = $result->allVulnerabilities['CVE-2025-0001'];

        self::assertTrue($merged->inKev);
        self::assertTrue($merged->knownRansomware);
    }

    #[Test]
    public function mergeKeepsHighestCvss(): void
    {
        $existing = [
            'CVE-2025-0001' => $this->makeVulnArray('CVE-2025-0001', cvssScore: 7.0),
        ];

        // Lower CVSS should not replace
        $incoming = $this->makeVuln('CVE-2025-0001', cvssScore: 5.0);
        $batch = new VulnerabilityBatch('ghsa', [$incoming]);

        $result = $this->dedup->merge($existing, $batch);

        self::assertSame(7.0, $result->allVulnerabilities['CVE-2025-0001']->cvssScore);
    }

    #[Test]
    public function mergeDeduplicatesAffectedPackages(): void
    {
        $pkg1 = new AffectedPackage('composer', 'vendor/lib', '>=1.0 <2.0');
        $pkg2 = new AffectedPackage('composer', 'vendor/lib', '>=3.0 <4.0');
        $pkg3 = new AffectedPackage('npm', 'some-pkg', '*');

        $existing = [
            'CVE-2025-0001' => $this->makeVulnArray(
                'CVE-2025-0001',
                affectedPackages: [$pkg1],
            ),
        ];

        $incoming = $this->makeVuln(
            'CVE-2025-0001',
            affectedPackages: [$pkg2, $pkg3],
        );
        $batch = new VulnerabilityBatch('nvd', [$incoming]);

        $result = $this->dedup->merge($existing, $batch);
        $packages = $result->allVulnerabilities['CVE-2025-0001']->affectedPackages;

        // composer:vendor/lib is deduped (first wins), npm:some-pkg is added
        self::assertCount(2, $packages);
    }

    #[Test]
    public function mergePreservesNvdDescription(): void
    {
        $existing = [
            'CVE-2025-0001' => $this->makeVulnArray(
                'CVE-2025-0001',
                description: 'Old description',
                sources: ['ghsa'],
            ),
        ];

        $incoming = $this->makeVuln(
            'CVE-2025-0001',
            description: 'NVD description',
            sources: ['nvd'],
        );
        $batch = new VulnerabilityBatch('nvd', [$incoming]);

        $result = $this->dedup->merge($existing, $batch);

        self::assertSame('NVD description', $result->allVulnerabilities['CVE-2025-0001']->description);
    }

    #[Test]
    public function mergeMultipleBatches(): void
    {
        $batch1 = new VulnerabilityBatch('nvd', [$this->makeVuln('CVE-2025-0001')]);
        $batch2 = new VulnerabilityBatch('kev', [$this->makeVuln('CVE-2025-0002')]);

        $result = $this->dedup->merge([], $batch1, $batch2);

        self::assertCount(2, $result->newVulnerabilities);
        self::assertCount(2, $result->allVulnerabilities);
    }

    private function makeVuln(
        string $id = 'CVE-2025-0001',
        ?float $cvssScore = null,
        bool $inKev = false,
        bool $knownRansomware = false,
        array $aliases = [],
        array $sources = ['test'],
        string $description = 'Test',
        array $affectedPackages = [],
    ): Vulnerability {
        return new Vulnerability(
            canonicalId: $id,
            aliases: $aliases,
            description: $description,
            cvssScore: $cvssScore,
            cvssVector: null,
            epssScore: null,
            epssPercentile: null,
            inKev: $inKev,
            knownRansomware: $knownRansomware,
            affectedPackages: $affectedPackages,
            cwes: [],
            references: [],
            sources: $sources,
            firstSeen: '2025-01-01T00:00:00+00:00',
            lastUpdated: '2025-01-01T00:00:00+00:00',
            kevDateAdded: null,
            kevDueDate: null,
            kevRequiredAction: null,
            affectsInstalledVersion: false,
            priority: Priority::P1,
            notifiedAtPriority: null,
        );
    }

    /** @return array<string, mixed> */
    private function makeVulnArray(
        string $id = 'CVE-2025-0001',
        ?float $cvssScore = null,
        bool $inKev = false,
        array $aliases = [],
        array $sources = ['test'],
        string $description = 'Test',
        array $affectedPackages = [],
    ): array {
        $vuln = $this->makeVuln(
            id: $id,
            cvssScore: $cvssScore,
            inKev: $inKev,
            aliases: $aliases,
            sources: $sources,
            description: $description,
            affectedPackages: $affectedPackages,
        );
        return $vuln->toArray();
    }
}
