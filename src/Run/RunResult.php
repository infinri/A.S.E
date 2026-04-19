<?php

declare(strict_types=1);

namespace Ase\Run;

use Ase\Model\MagentoEdition;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;

final readonly class RunResult
{
    /**
     * @param Vulnerability[] $newAlerts
     * @param Vulnerability[] $escalations
     */
    public function __construct(
        public int $exitCode,
        public array $newAlerts,
        public array $escalations,
        public ?MagentoEdition $magento,
        public bool $dryRun,
        public string $runId,
    ) {}

    /**
     * @param Vulnerability[] $newAlerts
     * @param Vulnerability[] $escalations
     */
    public static function fromClassification(
        array $newAlerts,
        array $escalations,
        ?MagentoEdition $magento,
        bool $dryRun,
        string $runId,
    ): self {
        $exitCode = 0;

        foreach ([...$newAlerts, ...$escalations] as $vuln) {
            if ($vuln->priority === Priority::P0) {
                $exitCode = 2;
                break;
            }
            if ($vuln->priority === Priority::P1) {
                $exitCode = 1;
            }
        }

        return new self(
            exitCode: $exitCode,
            newAlerts: $newAlerts,
            escalations: $escalations,
            magento: $magento,
            dryRun: $dryRun,
            runId: $runId,
        );
    }

    /** @return array<string, mixed> */
    public function toJsonArray(): array
    {
        $summary = [
            'P0' => 0,
            'P1' => 0,
            'P2' => 0,
            'P3' => 0,
            'P4' => 0,
        ];

        $findings = [];
        foreach ([...$this->newAlerts, ...$this->escalations] as $vuln) {
            $findings[] = $vuln->toArray();
            $summary[$vuln->priority->name]++;
        }

        return [
            'run_id' => $this->runId,
            'magento' => $this->magento?->toArray(),
            'findings' => $findings,
            'summary' => $summary,
            'exit_code' => $this->exitCode,
        ];
    }
}
