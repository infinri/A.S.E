<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Health;

use Ase\Health\FeedHealthTracker;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class FeedHealthTrackerTest extends TestCase
{
    private FeedHealthTracker $tracker;

    protected function setUp(): void
    {
        $this->tracker = new FeedHealthTracker(new NullLogger());
    }

    #[Test]
    public function recordSuccessUpdatesState(): void
    {
        $state = ['feed_health' => []];

        $this->tracker->recordSuccess('nvd', $state);

        self::assertNotNull($state['feed_health']['nvd']['last_success']);
        self::assertSame(0, $state['feed_health']['nvd']['consecutive_failures']);
    }

    #[Test]
    public function recordSuccessResetsConsecutiveFailures(): void
    {
        $state = ['feed_health' => [
            'nvd' => [
                'last_success' => null,
                'last_failure' => '2025-01-01T00:00:00+00:00',
                'consecutive_failures' => 5,
            ],
        ]];

        $this->tracker->recordSuccess('nvd', $state);

        self::assertSame(0, $state['feed_health']['nvd']['consecutive_failures']);
    }

    #[Test]
    public function recordFailureIncrementsCounter(): void
    {
        $state = ['feed_health' => []];

        $this->tracker->recordFailure('nvd', 'timeout', $state);

        self::assertSame(1, $state['feed_health']['nvd']['consecutive_failures']);
        self::assertNotNull($state['feed_health']['nvd']['last_failure']);
    }

    #[Test]
    public function recordFailureAccumulatesConsecutiveFailures(): void
    {
        $state = ['feed_health' => []];

        $this->tracker->recordFailure('nvd', 'timeout', $state);
        $this->tracker->recordFailure('nvd', 'timeout', $state);
        $this->tracker->recordFailure('nvd', 'timeout', $state);

        self::assertSame(3, $state['feed_health']['nvd']['consecutive_failures']);
    }

    #[Test]
    public function getHealthReturnsDefaultsForUnknownFeed(): void
    {
        $state = ['feed_health' => []];

        $health = $this->tracker->getHealth('unknown', $state);

        self::assertNull($health->lastSuccess);
        self::assertNull($health->lastFailure);
        self::assertSame(0, $health->consecutiveFailures);
    }

    #[Test]
    public function getHealthReturnsTrackedState(): void
    {
        $state = ['feed_health' => [
            'nvd' => [
                'last_success' => '2025-01-01T00:00:00+00:00',
                'last_failure' => null,
                'consecutive_failures' => 0,
            ],
        ]];

        $health = $this->tracker->getHealth('nvd', $state);

        self::assertSame('2025-01-01T00:00:00+00:00', $health->lastSuccess);
        self::assertSame(0, $health->consecutiveFailures);
    }
}
