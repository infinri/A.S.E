<?php

declare(strict_types=1);

namespace Ase\Dedup;

use Ase\Model\AffectedPackage;
use Ase\Model\Vulnerability;
use Ase\Model\VulnerabilityBatch;
use Psr\Log\LoggerInterface;

final class Deduplicator
{
    public function __construct(
        private readonly LoggerInterface $logger,
    ) {}

    /**
     * @param array<string, array<string, mixed>> $existingVulns State data keyed by canonical ID
     */
    public function merge(array $existingVulns, VulnerabilityBatch ...$batches): DeduplicatorResult
    {
        /** @var array<string, Vulnerability> $all */
        $all = [];
        /** @var array<string, string> $aliasIndex alias -> canonical ID */
        $aliasIndex = [];

        foreach ($existingVulns as $id => $data) {
            $vuln = Vulnerability::fromArray($data);
            $all[$id] = $vuln;
            foreach ($vuln->aliases as $alias) {
                $aliasIndex[$alias] = $id;
            }
        }

        /** @var array<string, Vulnerability> $new */
        $new = [];
        /** @var array<string, Vulnerability> $updated */
        $updated = [];

        foreach ($batches as $batch) {
            foreach ($batch->getVulnerabilities() as $vuln) {
                $id = $this->resolveCanonicalId($vuln, $all, $aliasIndex);

                if (isset($all[$id])) {
                    $merged = $this->mergeVulnerability($all[$id], $vuln);
                    $all[$id] = $merged;
                    $updated[$id] = $merged;
                    $this->updateAliasIndex($aliasIndex, $merged);
                } else {
                    $all[$id] = $vuln;
                    $new[$id] = $vuln;
                    $this->updateAliasIndex($aliasIndex, $vuln);
                }
            }
        }

        $this->logger->info('Dedup complete', [
            'new' => count($new),
            'updated' => count($updated),
            'total' => count($all),
        ]);

        return new DeduplicatorResult(
            newVulnerabilities: $new,
            updatedVulnerabilities: $updated,
            allVulnerabilities: $all,
        );
    }

    /**
     * @param array<string, Vulnerability> $all
     * @param array<string, string> $aliasIndex
     */
    private function resolveCanonicalId(Vulnerability $vuln, array $all, array $aliasIndex): string
    {
        $id = $vuln->canonicalId;

        // Direct match
        if (isset($all[$id])) {
            return $id;
        }

        // Check if the incoming canonical ID is an alias of an existing entry
        if (isset($aliasIndex[$id])) {
            return $aliasIndex[$id];
        }

        // Check if any of the incoming aliases match an existing canonical ID or alias
        foreach ($vuln->aliases as $alias) {
            if (isset($all[$alias])) {
                return $alias;
            }
            if (isset($aliasIndex[$alias])) {
                return $aliasIndex[$alias];
            }
        }

        return $id;
    }

    /** @param array<string, string> $aliasIndex */
    private function updateAliasIndex(array &$aliasIndex, Vulnerability $vuln): void
    {
        foreach ($vuln->aliases as $alias) {
            $aliasIndex[$alias] = $vuln->canonicalId;
        }
        $aliasIndex[$vuln->canonicalId] = $vuln->canonicalId;
    }

    private function mergeVulnerability(Vulnerability $existing, Vulnerability $incoming): Vulnerability
    {
        // Keep highest CVSS
        $cvssScore = $existing->cvssScore;
        $cvssVector = $existing->cvssVector;
        if ($incoming->cvssScore !== null && ($cvssScore === null || $incoming->cvssScore > $cvssScore)) {
            $cvssScore = $incoming->cvssScore;
            $cvssVector = $incoming->cvssVector;
        }

        // OR KEV status
        $inKev = $existing->inKev || $incoming->inKev;
        $knownRansomware = $existing->knownRansomware || $incoming->knownRansomware;

        // Union sources
        $sources = array_values(array_unique([...$existing->sources, ...$incoming->sources]));

        // Union aliases
        $aliases = array_values(array_unique([...$existing->aliases, ...$incoming->aliases]));

        // Union references
        $references = array_values(array_unique([...$existing->references, ...$incoming->references]));

        // Union CWEs
        $cwes = array_values(array_unique([...$existing->cwes, ...$incoming->cwes]));

        // Union affected packages (dedup by ecosystem+name)
        $affectedPackages = $this->mergeAffectedPackages($existing->affectedPackages, $incoming->affectedPackages);

        // Prefer NVD description (more concise), fall back to existing
        $description = $existing->description;
        if (in_array('nvd', $incoming->sources, true) && $incoming->description !== '') {
            $description = $incoming->description;
        }

        // KEV fields: prefer non-null
        $kevDateAdded = $existing->kevDateAdded ?? $incoming->kevDateAdded;
        $kevDueDate = $existing->kevDueDate ?? $incoming->kevDueDate;
        $kevRequiredAction = $existing->kevRequiredAction ?? $incoming->kevRequiredAction;

        // Latest update
        $lastUpdated = max($existing->lastUpdated, $incoming->lastUpdated);

        return new Vulnerability(
            canonicalId: $existing->canonicalId,
            aliases: $aliases,
            description: $description,
            cvssScore: $cvssScore,
            cvssVector: $cvssVector,
            epssScore: $existing->epssScore,
            epssPercentile: $existing->epssPercentile,
            inKev: $inKev,
            knownRansomware: $knownRansomware,
            affectedPackages: $affectedPackages,
            cwes: $cwes,
            references: $references,
            sources: $sources,
            firstSeen: $existing->firstSeen,
            lastUpdated: $lastUpdated,
            kevDateAdded: $kevDateAdded,
            kevDueDate: $kevDueDate,
            kevRequiredAction: $kevRequiredAction,
            affectsInstalledVersion: $existing->affectsInstalledVersion || $incoming->affectsInstalledVersion,
            priority: $existing->priority,
            notifiedAtPriority: $existing->notifiedAtPriority,
        );
    }

    /**
     * @param AffectedPackage[] $existing
     * @param AffectedPackage[] $incoming
     * @return AffectedPackage[]
     */
    private function mergeAffectedPackages(array $existing, array $incoming): array
    {
        $seen = [];
        $result = [];

        foreach ([...$existing, ...$incoming] as $pkg) {
            $key = strtolower($pkg->ecosystem . ':' . $pkg->name);
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $result[] = $pkg;
            }
        }

        return $result;
    }
}
