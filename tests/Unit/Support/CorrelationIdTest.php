<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Support;

use Ase\Support\CorrelationId;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class CorrelationIdTest extends TestCase
{
    #[Test]
    public function testGenerateReturnsUuidV4Format(): void
    {
        $id = CorrelationId::generate();

        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $id,
            'Generated id must be a valid UUIDv4',
        );
    }

    #[Test]
    public function testGenerateProducesUniqueValues(): void
    {
        $ids = [];
        for ($i = 0; $i < 1000; $i++) {
            $ids[] = CorrelationId::generate();
        }

        self::assertCount(1000, array_unique($ids), '1000 generated ids must be unique');
    }
}
