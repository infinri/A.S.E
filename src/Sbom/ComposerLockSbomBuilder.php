<?php

declare(strict_types=1);

namespace Ase\Sbom;

final class ComposerLockSbomBuilder
{
    /**
     * Convert a composer.lock into a CycloneDX 1.5 BOM array.
     *
     * @return array<string, mixed>
     */
    public function build(string $lockfilePath): array
    {
        if (!is_file($lockfilePath) || !is_readable($lockfilePath)) {
            throw new \RuntimeException(
                "Cannot build SBOM: lockfile {$lockfilePath} does not exist or is not readable."
            );
        }

        $raw = file_get_contents($lockfilePath);
        if ($raw === false) {
            throw new \RuntimeException("Cannot build SBOM: failed reading {$lockfilePath}.");
        }

        try {
            /** @var array<string, mixed> $lock */
            $lock = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \RuntimeException(
                "Cannot build SBOM: {$lockfilePath} is not valid JSON: {$e->getMessage()}",
                previous: $e,
            );
        }

        $components = [];
        /** @var array<int, array<string, mixed>> $packages */
        $packages = array_merge($lock['packages'] ?? [], $lock['packages-dev'] ?? []);
        foreach ($packages as $package) {
            $name = (string) ($package['name'] ?? '');
            $version = ltrim((string) ($package['version'] ?? ''), 'v');
            if ($name === '' || $version === '') {
                continue;
            }
            [$group, $shortName] = str_contains($name, '/')
                ? explode('/', $name, 2)
                : [null, $name];

            $component = ['type' => 'library'];
            if ($group !== null) {
                $component['group'] = $group;
            }
            $component['name'] = $shortName;
            $component['version'] = $version;
            $component['purl'] = "pkg:composer/{$name}@{$version}";
            $components[] = $component;
        }

        return [
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.5',
            'version' => 1,
            'components' => $components,
        ];
    }
}
