<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use Ase\DependencyTrack\FindingsFetcher;
use Ase\Http\CurlClient;
use Ase\Http\HttpResponse;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class FindingsFetcherTest extends TestCase
{
    public function testFetchesProjectsWithTags(): void
    {
        $client = $this->createMock(CurlClient::class);
        $client->expects(self::once())->method('get')
            ->with(
                'http://dt.local/api/v1/project?pageSize=100&pageNumber=1',
                ['X-Api-Key: k'],
            )
            ->willReturn(new HttpResponse(200, (string) json_encode([
                ['uuid' => 'u1', 'name' => 'magento', 'tags' => [['name' => 'team:ecommerce']]],
            ]), ['x-total-count' => '1']));

        $projects = new FindingsFetcher($client, 'http://dt.local', 'k', new NullLogger())->projects();

        self::assertSame([['uuid' => 'u1', 'name' => 'magento', 'tags' => ['team:ecommerce']]], $projects);
    }

    public function testFetchesFindingsForProject(): void
    {
        $client = $this->createMock(CurlClient::class);
        $client->expects(self::once())->method('get')
            ->with('http://dt.local/api/v1/finding/project/u1', ['X-Api-Key: k'])
            ->willReturn(new HttpResponse(200, '[{"vulnerability":{"vulnId":"CVE-1"}}]'));

        $findings = new FindingsFetcher($client, 'http://dt.local', 'k', new NullLogger())->findingsForProject('u1');

        self::assertCount(1, $findings);
        self::assertSame('CVE-1', $findings[0]['vulnerability']['vulnId']);
    }

    public function testThrowsOnApiError(): void
    {
        $client = $this->createStub(CurlClient::class);
        $client->method('get')->willReturn(new HttpResponse(403, 'forbidden'));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('u1');
        new FindingsFetcher($client, 'http://dt.local', 'k', new NullLogger())->findingsForProject('u1');
    }
}
