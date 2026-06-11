<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class ConfigDependencyTrackTest extends TestCase
{
    public function testParsesProjects(): void
    {
        $config = ConfigTestHelper::create([
            'ASE_PROJECTS' => '"magento:/var/www/magento/composer.lock, tools:/opt/tools/composer.lock"',
        ]);

        self::assertSame([
            'magento' => '/var/www/magento/composer.lock',
            'tools' => '/opt/tools/composer.lock',
        ], $config->projects());
    }

    public function testThrowsOnMalformedProjectEntry(): void
    {
        $config = ConfigTestHelper::create(['ASE_PROJECTS' => 'magento']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('magento');
        $config->projects();
    }

    public function testThrowsWhenDtrackUrlMissing(): void
    {
        $config = ConfigTestHelper::create(['ASE_PROJECTS' => 'magento:/var/www/magento/composer.lock']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('DTRACK_URL');
        $config->dtrackUrl();
    }

    public function testParsesAlertRoutes(): void
    {
        $config = ConfigTestHelper::create([
            'ASE_ALERT_ROUTES' => '"team:eco=https://hooks.example/a, team:infra=https://hooks.example/b"',
        ]);

        self::assertSame([
            'team:eco' => 'https://hooks.example/a',
            'team:infra' => 'https://hooks.example/b',
        ], $config->alertRoutes());
    }

    public function testAlertRoutesEmptyWhenUnset(): void
    {
        self::assertSame([], ConfigTestHelper::create(['ASE_ALERT_ROUTES' => ''])->alertRoutes());
    }

    public function testThrowsOnMalformedAlertRoute(): void
    {
        $config = ConfigTestHelper::create(['ASE_ALERT_ROUTES' => 'team-without-url']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('team-without-url');
        $config->alertRoutes();
    }

    public function testInventoryPathExplicitOverride(): void
    {
        $config = ConfigTestHelper::create(['ASE_INVENTORY_PATH' => '/tmp/custom-inventory.yaml']);

        self::assertSame('/tmp/custom-inventory.yaml', $config->inventoryPath());
    }

    public function testInventoryPathDefaultsToRepoFileWhenPresent(): void
    {
        $config = ConfigTestHelper::create(['ASE_INVENTORY_PATH' => '']);

        $path = $config->inventoryPath();
        if ($path !== null) {
            self::assertStringEndsWith('inventory/declared-tech.yaml', $path);
            self::assertFileExists($path);
        } else {
            self::assertNull($path);
        }
    }

    public function testNormalizesDtrackUrlTrailingSlash(): void
    {
        $config = ConfigTestHelper::create([
            'DTRACK_URL' => 'http://dtrack.local:8080/',
            'DTRACK_API_KEY' => 'k',
        ]);

        self::assertSame('http://dtrack.local:8080', $config->dtrackUrl());
        self::assertSame('k', $config->dtrackApiKey());
    }
}
