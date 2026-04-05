<?php

declare(strict_types=1);

namespace Ase\Dedup;

use Ase\Model\Vulnerability;

final readonly class DeduplicatorResult
{
    /**
     * @param Vulnerability[] $newVulnerabilities
     * @param Vulnerability[] $updatedVulnerabilities
     * @param Vulnerability[] $allVulnerabilities
     */
    public function __construct(
        public array $newVulnerabilities,
        public array $updatedVulnerabilities,
        public array $allVulnerabilities,
    ) {}
}
