<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use Ase\Sbom\ComposerLockSbomBuilder;
use PHPUnit\Framework\TestCase;

final class ComposerLockSbomBuilderTest extends TestCase
{
    private string $lockPath;

    protected function setUp(): void
    {
        $this->lockPath = tempnam(sys_get_temp_dir(), 'ase-lock-');
        file_put_contents($this->lockPath, json_encode([
            'packages' => [
                ['name' => 'monolog/monolog', 'version' => '3.5.0'],
            ],
            'packages-dev' => [
                ['name' => 'phpunit/phpunit', 'version' => 'v11.0.1'],
            ],
        ], JSON_THROW_ON_ERROR));
    }

    protected function tearDown(): void
    {
        @unlink($this->lockPath);
    }

    public function testBuildsCycloneDxDocumentFromLockfile(): void
    {
        $bom = new ComposerLockSbomBuilder()->build($this->lockPath);

        self::assertSame('CycloneDX', $bom['bomFormat']);
        self::assertSame('1.5', $bom['specVersion']);
        self::assertCount(2, $bom['components']);
        self::assertSame([
            'type' => 'library',
            'group' => 'monolog',
            'name' => 'monolog',
            'version' => '3.5.0',
            'purl' => 'pkg:composer/monolog/monolog@3.5.0',
        ], $bom['components'][0]);
        self::assertSame('pkg:composer/phpunit/phpunit@11.0.1', $bom['components'][1]['purl']);
    }

    public function testThrowsOnMissingLockfile(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('/nonexistent/composer.lock');
        new ComposerLockSbomBuilder()->build('/nonexistent/composer.lock');
    }

    public function testThrowsOnInvalidJson(): void
    {
        file_put_contents($this->lockPath, 'not json');
        $this->expectException(\RuntimeException::class);
        new ComposerLockSbomBuilder()->build($this->lockPath);
    }
}
