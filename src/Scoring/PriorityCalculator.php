<?php

declare(strict_types=1);

namespace Ase\Scoring;

use Ase\Config;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;

final class PriorityCalculator
{
    public function __construct(
        private readonly Config $config,
    ) {}

    public function classify(Vulnerability $vuln): Priority
    {
        $cvss = $vuln->cvssScore ?? $this->fallbackCvssFromSeverity($vuln);
        $epss = $vuln->epssScore;
        $epssHigh = $this->config->epssHighThreshold();
        $epssMedium = $this->config->epssMediumThreshold();
        $cvssCritical = $this->config->cvssCriticalThreshold();
        $cvssHigh = $this->config->cvssHighThreshold();
        $cvssMedium = $this->config->cvssMediumThreshold();

        // P0: In KEV, or CVSS >= 9.0 AND EPSS >= 10%
        if ($vuln->inKev) {
            return Priority::P0;
        }
        if ($cvss !== null && $cvss >= $cvssCritical && $epss !== null && $epss >= $epssHigh) {
            return Priority::P0;
        }

        // P1: CVSS >= 7.0 AND EPSS >= 10%, or ransomware, or affects installed AND CVSS >= 7.0
        if ($vuln->knownRansomware) {
            return Priority::P1;
        }
        if ($cvss !== null && $cvss >= $cvssHigh && $epss !== null && $epss >= $epssHigh) {
            return Priority::P1;
        }
        if ($vuln->affectsInstalledVersion && $cvss !== null && $cvss >= $cvssHigh) {
            return Priority::P1;
        }

        // P2: CVSS >= 7.0 OR EPSS >= 5%
        if ($cvss !== null && $cvss >= $cvssHigh) {
            return Priority::P2;
        }
        if ($epss !== null && $epss >= $epssMedium) {
            return Priority::P2;
        }

        // P3: CVSS >= 4.0 AND EPSS < 5%
        if ($cvss !== null && $cvss >= $cvssMedium) {
            return Priority::P3;
        }

        return Priority::P4;
    }

    /**
     * @param array<string, Vulnerability> $vulnerabilities
     * @return array<string, Vulnerability>
     */
    public function classifyAll(array $vulnerabilities): array
    {
        return array_map(
            fn(Vulnerability $v): Vulnerability => $v->withPriority($this->classify($v)),
            $vulnerabilities,
        );
    }

    private function fallbackCvssFromSeverity(Vulnerability $vuln): ?float
    {
        if ($vuln->cvssVector === null) {
            return null;
        }

        return $this->estimateBaseScoreFromVector($vuln->cvssVector);
    }

    private function estimateBaseScoreFromVector(string $vector): ?float
    {
        if (!str_starts_with($vector, 'CVSS:3')) {
            return null;
        }

        $metrics = [];
        foreach (explode('/', $vector) as $part) {
            $kv = explode(':', $part);
            if (count($kv) === 2) {
                $metrics[$kv[0]] = $kv[1];
            }
        }

        $av = $metrics['AV'] ?? null;
        $ac = $metrics['AC'] ?? null;

        if ($av === 'N' && $ac === 'L') {
            return 9.0;
        }
        if ($av === 'N') {
            return 7.5;
        }
        if ($av === 'A') {
            return 5.5;
        }
        if ($av === 'L' || $av === 'P') {
            return 4.0;
        }

        return null;
    }
}
