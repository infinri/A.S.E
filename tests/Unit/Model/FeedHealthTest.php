<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Model;

use Ase\Model\FeedHealth;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class FeedHealthTest extends TestCase
{
    #[Test]
    public function defaultsToHealthyState(): void
    {
        $health = new FeedHealth();

        self::assertNull($health->lastSuccess);
        self::assertNull($health->lastFailure);
        self::assertSame(0, $health->consecutiveFailures);
        self::assertFalse($health->shouldEscalate());
    }

    #[Test]
    public function withSuccessResetsConsecutiveFailures(): void
    {
        $health = new FeedHealth(consecutiveFailures: 5);
        $updated = $health->withSuccess('2025-01-01T00:00:00+00:00');

        self::assertSame('2025-01-01T00:00:00+00:00', $updated->lastSuccess);
        self::assertSame(0, $updated->consecutiveFailures);
        self::assertFalse($updated->shouldEscalate());
    }

    #[Test]
    public function withFailureIncrementsCounter(): void
    {
        $health = new FeedHealth();
        $h1 = $health->withFailure('2025-01-01T00:00:00+00:00');
        $h2 = $h1->withFailure('2025-01-01T01:00:00+00:00');
        $h3 = $h2->withFailure('2025-01-01T02:00:00+00:00');

        self::assertSame(1, $h1->consecutiveFailures);
        self::assertSame(2, $h2->consecutiveFailures);
        self::assertSame(3, $h3->consecutiveFailures);

        self::assertFalse($h2->shouldEscalate());
        self::assertTrue($h3->shouldEscalate());
    }

    #[Test]
    public function withFailurePreservesLastSuccess(): void
    {
        $health = (new FeedHealth())->withSuccess('2025-01-01T00:00:00+00:00');
        $failed = $health->withFailure('2025-01-01T01:00:00+00:00');

        self::assertSame('2025-01-01T00:00:00+00:00', $failed->lastSuccess);
        self::assertSame('2025-01-01T01:00:00+00:00', $failed->lastFailure);
    }

    #[Test]
    public function shouldEscalateAtThreshold(): void
    {
        self::assertFalse((new FeedHealth(consecutiveFailures: 2))->shouldEscalate());
        self::assertTrue((new FeedHealth(consecutiveFailures: 3))->shouldEscalate());
        self::assertTrue((new FeedHealth(consecutiveFailures: 10))->shouldEscalate());
    }

    #[Test]
    public function toArrayAndFromArrayRoundTrip(): void
    {
        $health = new FeedHealth(
            lastSuccess: '2025-01-01T00:00:00+00:00',
            lastFailure: '2025-01-02T00:00:00+00:00',
            consecutiveFailures: 2,
        );

        $restored = FeedHealth::fromArray($health->toArray());

        self::assertSame($health->lastSuccess, $restored->lastSuccess);
        self::assertSame($health->lastFailure, $restored->lastFailure);
        self::assertSame($health->consecutiveFailures, $restored->consecutiveFailures);
    }

    #[Test]
    public function fromArrayWithEmptyDataUsesDefaults(): void
    {
        $health = FeedHealth::fromArray([]);

        self::assertNull($health->lastSuccess);
        self::assertNull($health->lastFailure);
        self::assertSame(0, $health->consecutiveFailures);
    }
}