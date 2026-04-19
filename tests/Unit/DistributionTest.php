<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class DistributionTest extends TestCase
{
    private string $repoRoot;

    protected function setUp(): void
    {
        $this->repoRoot = dirname(__DIR__, 2);
    }

    #[Test]
    public function testComposerJsonHasRequiredPackagistFields(): void
    {
        $composer = $this->loadComposerJson();

        self::assertArrayHasKey('name', $composer);
        self::assertSame('infinri/ase', $composer['name']);

        self::assertArrayHasKey('description', $composer);
        self::assertNotEmpty($composer['description']);

        self::assertArrayHasKey('type', $composer);
        self::assertSame('library', $composer['type']);

        self::assertArrayHasKey('license', $composer);

        self::assertArrayHasKey('keywords', $composer);
        self::assertIsArray($composer['keywords']);
        self::assertNotEmpty($composer['keywords']);

        self::assertArrayHasKey('authors', $composer);
        self::assertIsArray($composer['authors']);
        self::assertNotEmpty($composer['authors']);

        self::assertArrayHasKey('support', $composer);

        self::assertArrayHasKey('bin', $composer);
        self::assertIsArray($composer['bin']);
        self::assertContains('bin/ase', $composer['bin']);
    }

    #[Test]
    public function testComposerJsonLicenseIsMit(): void
    {
        $composer = $this->loadComposerJson();
        self::assertSame('MIT', $composer['license']);
    }

    #[Test]
    public function testLicenseFileExists(): void
    {
        $path = $this->repoRoot . '/LICENSE';
        self::assertFileExists($path);

        $contents = (string) file_get_contents($path);
        self::assertStringContainsString('MIT License', $contents);
        self::assertStringContainsString('Lucio Saldivar', $contents);
    }

    #[Test]
    public function testChangelogExists(): void
    {
        $path = $this->repoRoot . '/CHANGELOG.md';
        self::assertFileExists($path);

        $contents = (string) file_get_contents($path);
        self::assertStringContainsString('Keep a Changelog', $contents);
        self::assertStringContainsString('## [1.0.0]', $contents);
    }

    #[Test]
    public function testSecurityMdExists(): void
    {
        $path = $this->repoRoot . '/SECURITY.md';
        self::assertFileExists($path);

        $contents = (string) file_get_contents($path);
        self::assertStringContainsString('Reporting a Vulnerability', $contents);
        self::assertStringContainsString('lucio.saldivar@infinri.com', $contents);
    }

    #[Test]
    public function testBinFileExistsAndIsRunnable(): void
    {
        $path = $this->repoRoot . '/bin/ase';
        self::assertFileExists($path);

        $handle = fopen($path, 'r');
        self::assertNotFalse($handle);
        $firstLine = (string) fgets($handle);
        fclose($handle);
        self::assertStringStartsWith('#!/usr/bin/env php', $firstLine);
    }

    #[Test]
    public function testBinPhpLegacyPathRemoved(): void
    {
        self::assertFileDoesNotExist($this->repoRoot . '/bin/ase.php');
    }

    #[Test]
    public function testReadmeLeadsWithProblemStatement(): void
    {
        $readme = (string) file_get_contents($this->repoRoot . '/README.md');
        self::assertNotEmpty($readme);
        self::assertStringContainsString('composer global require infinri/ase', $readme);
        self::assertStringContainsString('--dry-run', $readme);
        self::assertStringContainsString('--format', $readme);
    }

    /**
     * @return array<string, mixed>
     */
    private function loadComposerJson(): array
    {
        $path = $this->repoRoot . '/composer.json';
        self::assertFileExists($path);
        $decoded = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($decoded);
        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
