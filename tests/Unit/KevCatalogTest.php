<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use Ase\Feed\KevCatalog;
use Ase\Http\CurlClient;
use Ase\Http\HttpResponse;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class KevCatalogTest extends TestCase
{
    private const string CATALOG_JSON = '{"vulnerabilities":[
        {"cveID":"CVE-2021-44228","knownRansomwareCampaignUse":"Known"},
        {"cveID":"CVE-2024-1234","knownRansomwareCampaignUse":"Unknown"}
    ]}';

    public function testMembershipAndRansomware(): void
    {
        $client = $this->createMock(CurlClient::class);
        $client->expects(self::once())->method('get')
            ->willReturn(new HttpResponse(200, self::CATALOG_JSON));

        $catalog = new KevCatalog($client, new NullLogger());

        self::assertTrue($catalog->inKev('CVE-2021-44228'));
        self::assertTrue($catalog->isRansomware('CVE-2021-44228'));
        self::assertTrue($catalog->inKev('CVE-2024-1234'));
        self::assertFalse($catalog->isRansomware('CVE-2024-1234'));
        self::assertFalse($catalog->inKev('CVE-2020-0000'));
        // second lookup must not refetch (expects once above)
        self::assertFalse($catalog->inKev('GHSA-not-a-cve'));
    }

    public function testThrowsOnHttpFailure(): void
    {
        $client = $this->createStub(CurlClient::class);
        $client->method('get')->willReturn(new HttpResponse(503, 'unavailable'));

        $catalog = new KevCatalog($client, new NullLogger());

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('KEV catalog');
        $catalog->inKev('CVE-2021-44228');
    }
}
