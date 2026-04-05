<?php

declare(strict_types=1);

namespace Ase\Feed;

use Ase\Model\VulnerabilityBatch;

interface FeedInterface
{
    public function getName(): string;

    public function poll(string $lastPollTimestamp): VulnerabilityBatch;

    /** @param array<string, mixed> $data */
    public function validateResponse(array $data): bool;
}
