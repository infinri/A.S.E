<?php

declare(strict_types=1);

namespace Ase\Health;

use Ase\Model\FeedHealth;
use Psr\Log\LoggerInterface;

final class FeedHealthTracker
{
    public function __construct(
        private readonly LoggerInterface $logger,
    ) {}

    /** @param array<string, mixed> $state */
    public function recordSuccess(string $feed, array &$state): void
    {
        $health = FeedHealth::fromArray($state['feed_health'][$feed] ?? []);
        $updated = $health->withSuccess(date('c'));
        $state['feed_health'][$feed] = $updated->toArray();
    }

    /** @param array<string, mixed> $state */
    public function recordFailure(string $feed, string $reason, array &$state): void
    {
        $health = FeedHealth::fromArray($state['feed_health'][$feed] ?? []);
        $updated = $health->withFailure(date('c'));
        $state['feed_health'][$feed] = $updated->toArray();

        $this->logger->warning('Feed poll failed', [
            'feed' => $feed,
            'reason' => $reason,
            'consecutive_failures' => $updated->consecutiveFailures,
        ]);

        if ($updated->shouldEscalate()) {
            $this->logger->error('Feed has 3+ consecutive failures', [
                'feed' => $feed,
                'consecutive_failures' => $updated->consecutiveFailures,
            ]);
        }
    }

    /** @param array<string, mixed> $state */
    public function getHealth(string $feed, array $state): FeedHealth
    {
        return FeedHealth::fromArray($state['feed_health'][$feed] ?? []);
    }
}
