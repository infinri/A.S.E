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
