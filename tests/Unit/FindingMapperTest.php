<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use Ase\Alert\FindingMapper;
use Ase\Feed\KevCatalog;
use PHPUnit\Framework\TestCase;

final class FindingMapperTest extends TestCase
{
    /**
     * @param array<string, mixed> $vulnOverrides
     * @return array<string, mixed>
     */
    private function finding(array $vulnOverrides = []): array
    {
        return [
            'component' => [
                'purl' => 'pkg:composer/guzzlehttp/guzzle@7.4.0',
                'name' => 'guzzle',
                'version' => '7.4.0',
            ],
            'vulnerability' => array_merge([
                'vulnId' => 'CVE-2022-31090',
                'severity' => 'HIGH',
                'cvssV3BaseScore' => 7.7,
                'epssScore' => 0.018,
                'description' => 'CURLOPT_HTTPAUTH option not cleared on change of origin',
            ], $vulnOverrides),
            'attribution' => ['attributedOn' => 1781200000000],
        ];
    }

    public function testMapsFindingToVulnerability(): void
    {
        $kev = $this->createStub(KevCatalog::class);
        $kev->method('inKev')->willReturn(false);
        $kev->method('isRansomware')->willReturn(false);

        $vuln = new FindingMapper($kev)->map($this->finding());

        self::assertSame('CVE-2022-31090', $vuln->canonicalId);
        self::assertSame(7.7, $vuln->cvssScore);
        self::assertSame(0.018, $vuln->epssScore);
        self::assertFalse($vuln->inKev);
        self::assertTrue($vuln->affectsInstalledVersion);
        self::assertStringContainsString('guzzle', implode(',', array_map(
            static fn ($package) => $package->name,
            $vuln->affectedPackages,
        )));
    }

    public function testKevMembershipFlagsVulnerability(): void
    {
        $kev = $this->createStub(KevCatalog::class);
        $kev->method('inKev')->willReturn(true);
        $kev->method('isRansomware')->willReturn(true);

        $vuln = new FindingMapper($kev)->map($this->finding());

        self::assertTrue($vuln->inKev);
        self::assertTrue($vuln->knownRansomware);
    }

    public function testThrowsOnFindingWithoutVulnId(): void
    {
        $kev = $this->createStub(KevCatalog::class);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('vulnId');
        new FindingMapper($kev)->map(['vulnerability' => []]);
    }
}
