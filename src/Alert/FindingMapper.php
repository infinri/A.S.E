<?php

declare(strict_types=1);

namespace Ase\Alert;

use Ase\Feed\KevCatalog;
use Ase\Model\AffectedPackage;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;

final readonly class FindingMapper
{
    public function __construct(
        private KevCatalog $kevCatalog,
    ) {}

    /** @param array<string, mixed> $finding raw Dependency-Track finding */
    public function map(array $finding): Vulnerability
    {
        $vuln = $finding['vulnerability'] ?? [];
        $vulnId = $vuln['vulnId'] ?? null;
        if (!is_string($vulnId) || $vulnId === '') {
            throw new \RuntimeException(
                'Cannot map Dependency-Track finding: vulnerability.vulnId is missing. Raw keys: '
                . implode(',', array_keys($finding))
            );
        }

        $component = $finding['component'] ?? [];
        $affectedPackages = [];
        $purl = $component['purl'] ?? null;
        if (is_string($purl) && $purl !== '') {
            $affectedPackages[] = new AffectedPackage(
                ecosystem: 'composer',
                name: (string) ($component['name'] ?? $purl),
                vulnerableRange: (string) ($component['version'] ?? '*'),
            );
        }

        $now = date('c');

        return new Vulnerability(
            canonicalId: $vulnId,
            aliases: [],
            description: (string) ($vuln['description'] ?? ''),
            cvssScore: isset($vuln['cvssV3BaseScore']) ? (float) $vuln['cvssV3BaseScore']
                : (isset($vuln['cvssV2BaseScore']) ? (float) $vuln['cvssV2BaseScore'] : null),
            cvssVector: null,
            epssScore: isset($vuln['epssScore']) ? (float) $vuln['epssScore'] : null,
            epssPercentile: isset($vuln['epssPercentile']) ? (float) $vuln['epssPercentile'] : null,
            inKev: $this->kevCatalog->inKev($vulnId),
            knownRansomware: $this->kevCatalog->isRansomware($vulnId),
            affectedPackages: $affectedPackages,
            cwes: [],
            references: [],
            sources: ['dependency-track'],
            firstSeen: $now,
            lastUpdated: $now,
            kevDateAdded: null,
            kevDueDate: null,
            kevRequiredAction: null,
            affectsInstalledVersion: true,
            priority: Priority::P1,
            notifiedAtPriority: null,
        );
    }
}
