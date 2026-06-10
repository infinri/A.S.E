<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use Ase\DependencyTrack\BomUploader;
use Ase\Http\CurlClient;
use Ase\Http\HttpResponse;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class BomUploaderTest extends TestCase
{
    /** @var array<string, mixed> */
    private const array BOM = [
        'bomFormat' => 'CycloneDX',
        'specVersion' => '1.5',
        'version' => 1,
        'components' => [],
    ];

    public function testUploadsBase64BomWithApiKey(): void
    {
        $client = $this->createMock(CurlClient::class);
        $client->expects(self::once())
            ->method('put')
            ->with(
                'http://dtrack.local:8080/api/v1/bom',
                self::callback(function (array $body): bool {
                    self::assertSame('magento', $body['projectName']);
                    self::assertSame('main', $body['projectVersion']);
                    self::assertTrue($body['autoCreate']);
                    self::assertSame(
                        self::BOM,
                        json_decode(base64_decode($body['bom'], true) ?: '', true),
                    );
                    return true;
                }),
                ['X-Api-Key: test-key'],
            )
            ->willReturn(new HttpResponse(200, '{"token":"abc"}'));

        $uploader = new BomUploader($client, 'http://dtrack.local:8080', 'test-key', new NullLogger());
        $uploader->upload('magento', 'main', self::BOM);
    }

    public function testThrowsOnRejectedUpload(): void
    {
        $client = $this->createStub(CurlClient::class);
        $client->method('put')->willReturn(new HttpResponse(401, 'unauthorized'));

        $uploader = new BomUploader($client, 'http://dtrack.local:8080', 'bad-key', new NullLogger());

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('magento');
        $uploader->upload('magento', 'main', self::BOM);
    }
}
