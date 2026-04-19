<?php

declare(strict_types=1);

namespace Ase\Filter;

use Ase\Config;
use Ase\Model\MagentoEdition;
use Ase\Model\Vulnerability;
use Composer\Semver\Semver;
use Psr\Log\LoggerInterface;

final class ComposerLockAnalyzer
{
    /** @var array<string, string>|null Package name -> installed version */
    private ?array $installedPackages = null;

    public function __construct(
        private readonly Config $config,
        private readonly LoggerInterface $logger,
    ) {}

    public function detectMagentoEdition(): ?MagentoEdition
    {
        $lockPath = $this->config->composerLockPath();
        if ($lockPath === null || $lockPath === '') {
            return null;
        }

        $installed = $this->loadInstalledPackages($lockPath);
        if ($installed === []) {
            return null;
        }

        $candidates = [
            'magento-enterprise' => 'magento/product-enterprise-edition',
            'magento-community' => 'magento/product-community-edition',
            'mage-os-community' => 'mage-os/product-community-edition',
        ];

        foreach ($candidates as $edition => $packageName) {
            $version = $installed[$packageName] ?? null;
            if ($version !== null) {
                return new MagentoEdition(
                    edition: $edition,
                    version: $version,
                    packageName: $packageName,
                );
            }
        }

        return null;
    }

    /**
     * @param array<string, Vulnerability> $vulnerabilities
     * @return array<string, Vulnerability>
     */
    public function checkInstalledVersions(array $vulnerabilities): array
    {
        $lockPath = $this->config->composerLockPath();

        if ($lockPath === null || $lockPath === '') {
            return $vulnerabilities;
        }

        $installed = $this->loadInstalledPackages($lockPath);

        if ($installed === []) {
            return $vulnerabilities;
        }

        return array_map(
            function (Vulnerability $vuln) use ($installed): Vulnerability {
                $affected = $this->isAffected($vuln, $installed);
                return $vuln->withInstalledVersionFlag($affected);
            },
            $vulnerabilities,
        );
    }

    /** @return array<string, string> */
    private function loadInstalledPackages(string $lockPath): array
    {
        if ($this->installedPackages !== null) {
            return $this->installedPackages;
        }

        if (!file_exists($lockPath)) {
            $this->logger->warning('composer.lock not found', ['path' => $lockPath]);
            $this->installedPackages = [];
            return [];
        }

        $contents = file_get_contents($lockPath);
        if ($contents === false) {
            $this->logger->error('Cannot read composer.lock', ['path' => $lockPath]);
            $this->installedPackages = [];
            return [];
        }

        $lock = json_decode($contents, true);
        if (!is_array($lock)) {
            $this->logger->error('Invalid composer.lock JSON', ['path' => $lockPath]);
            $this->installedPackages = [];
            return [];
        }

        $packages = [];

        foreach ($lock['packages'] ?? [] as $pkg) {
            if (isset($pkg['name'], $pkg['version'])) {
                $packages[strtolower($pkg['name'])] = ltrim($pkg['version'], 'v');
            }
        }

        foreach ($lock['packages-dev'] ?? [] as $pkg) {
            if (isset($pkg['name'], $pkg['version'])) {
                $packages[strtolower($pkg['name'])] = ltrim($pkg['version'], 'v');
            }
        }

        $this->installedPackages = $packages;

        $this->logger->info('Loaded composer.lock', [
            'path' => $lockPath,
            'packages' => count($packages),
        ]);

        return $packages;
    }

    /** @param array<string, string> $installed */
    private function isAffected(Vulnerability $vuln, array $installed): bool
    {
        foreach ($vuln->affectedPackages as $pkg) {
            if (strtolower($pkg->ecosystem) !== 'composer') {
                continue;
            }

            $pkgName = strtolower($pkg->name);
            $installedVersion = $installed[$pkgName] ?? null;

            if ($installedVersion === null) {
                continue;
            }

            try {
                if (Semver::satisfies($installedVersion, $pkg->vulnerableRange)) {
                    $this->logger->notice('Installed package matches vulnerable range', [
                        'package' => $pkg->name,
                        'installed' => $installedVersion,
                        'vulnerable_range' => $pkg->vulnerableRange,
                        'cve' => $vuln->canonicalId,
                    ]);
                    return true;
                }
            } catch (\Throwable $e) {
                $this->logger->debug('Semver constraint parse failed', [
                    'package' => $pkg->name,
                    'constraint' => $pkg->vulnerableRange,
                    'error' => $e->getMessage(),
                ]);
            }
        }

        return false;
    }
}
