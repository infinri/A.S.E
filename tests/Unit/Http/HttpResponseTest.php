<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Http;

use Ase\Http\HttpResponse;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class HttpResponseTest extends TestCase
{
    #[Test]
    public function isOkForSuccessStatusCodes(): void
    {
        self::assertTrue((new HttpResponse(200, ''))->isOk());
        self::assertTrue((new HttpResponse(201, ''))->isOk());
        self::assertTrue((new HttpResponse(299, ''))->isOk());
        self::assertFalse((new HttpResponse(199, ''))->isOk());
        self::assertFalse((new HttpResponse(300, ''))->isOk());
        self::assertFalse((new HttpResponse(404, ''))->isOk());
        self::assertFalse((new HttpResponse(500, ''))->isOk());
    }

    #[Test]
    public function jsonDecodesBody(): void
    {
        $response = new HttpResponse(200, '{"key":"value","count":42}');

        self::assertSame(['key' => 'value', 'count' => 42], $response->json());
    }

    #[Test]
    public function jsonThrowsOnInvalidJson(): void
    {
        $response = new HttpResponse(200, 'not json');

        $this->expectException(\JsonException::class);
        $response->json();
    }

    #[Test]
    public function jsonThrowsOnScalarValue(): void
    {
        $response = new HttpResponse(200, '"just a string"');

        $this->expectException(\JsonException::class);
        $response->json();
    }

    #[Test]
    public function headerLookupIsCaseInsensitive(): void
    {
        $response = new HttpResponse(200, '', ['content-type' => 'application/json']);

        self::assertSame('application/json', $response->header('Content-Type'));
        self::assertSame('application/json', $response->header('content-type'));
        self::assertSame('application/json', $response->header('CONTENT-TYPE'));
    }

    #[Test]
    public function headerReturnsNullWhenMissing(): void
    {
        $response = new HttpResponse(200, '', []);

        self::assertNull($response->header('x-missing'));
    }
}
