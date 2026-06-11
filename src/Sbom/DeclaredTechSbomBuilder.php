<?php

declare(strict_types=1);

namespace Ase\Sbom;

use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

final class DeclaredTechSbomBuilder
{
    /**
     * Convert a declared-tech YAML inventory into per-owner CycloneDX 1.5 BOMs.
     *
     * @return array<string, array<string, mixed>> owner => BOM
     */
    public function buildPerOwner(string $inventoryPath): array
    {
        if (!is_file($inventoryPath) || !is_readable($inventoryPath)) {
            throw new \RuntimeException(
                "Cannot build declared-tech SBOM: inventory {$inventoryPath} does not exist or is not readable."
            );
        }

        try {
            $entries = Yaml::parseFile($inventoryPath);
        } catch (ParseException $e) {
            throw new \RuntimeException(
                "Cannot build declared-tech SBOM: {$inventoryPath} is not valid YAML: {$e->getMessage()}",
                previous: $e,
            );
        }

        if ($entries === null) {
            return [];
        }
        if (!is_array($entries)) {
            throw new \RuntimeException(
                "Cannot build declared-tech SBOM: {$inventoryPath} must contain a list of entries."
            );
        }

        $componentsByOwner = [];
        foreach ($entries as $index => $entry) {
            if (!is_array($entry)) {
                throw new \RuntimeException(
                    "Declared-tech entry #{$index} in {$inventoryPath} is not a mapping."
                );
            }

            $name = (string) ($entry['name'] ?? '');
            $version = (string) ($entry['version'] ?? '');
            $owner = (string) ($entry['owner'] ?? '');
            if ($name === '' || $version === '') {
                throw new \RuntimeException(
                    "Declared-tech entry #{$index} in {$inventoryPath} needs both name and version."
                );
            }
            if ($owner === '') {
                throw new \RuntimeException(
                    "Declared-tech entry \"{$name}\" in {$inventoryPath} has no owner; every entry needs an owning team."
                );
            }

            $component = ['type' => (string) ($entry['type'] ?? 'application')];
            if (isset($entry['vendor']) && $entry['vendor'] !== '') {
                $component['group'] = (string) $entry['vendor'];
            }
            $component['name'] = $name;
            $component['version'] = $version;
            if (isset($entry['cpe']) && $entry['cpe'] !== '') {
                $component['cpe'] = (string) $entry['cpe'];
            }

            $componentsByOwner[$owner][] = $component;
        }

        $boms = [];
        foreach ($componentsByOwner as $owner => $components) {
            $boms[$owner] = [
                'bomFormat' => 'CycloneDX',
                'specVersion' => '1.5',
                'version' => 1,
                'components' => $components,
            ];
        }
        return $boms;
    }
}
