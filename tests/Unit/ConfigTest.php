<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    private ?string $originalCwd = null;

    protected function tearDown(): void
    {
        // Clean up env vars that may leak between tests
        foreach (['NVD_API_KEY', 'GITHUB_TOKEN', 'SLACK_WEBHOOK_URL', 'COMPOSER_LOCK_PATH'] as $key) {
            unset($_ENV[$key], $_SERVER[$key]);
            putenv($key);
        }

        if ($this->originalCwd !== null) {
            chdir($this->originalCwd);
            $this->originalCwd = null;
        }
    }

    #[Test]
    public function trimsWhitespaceFromOptionalValues(): void
    {
        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
            'NVD_API_KEY' => '  abc-123  ',
        ]);

        self::assertSame('abc-123', $config->nvdApiKey());
    }

    #[Test]
    public function trimsCarriageReturnFromOptionalValues(): void
    {
        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
            'GITHUB_TOKEN' => "ghp_token123\r",
        ]);

        self::assertSame('ghp_token123', $config->githubToken());
    }

    #[Test]
    public function returnsNullForEmptyOptionalValues(): void
    {
        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
        ]);

        self::assertNull($config->nvdApiKey());
        self::assertNull($config->githubToken());
    }

    #[Test]
    public function testSlackWebhookUrlReturnsNullWhenUnset(): void
    {
        $config = ConfigTestHelper::withoutWebhook();
        self::assertNull($config->slackWebhookUrl());
    }

    #[Test]
    public function testSlackWebhookUrlReturnsStringWhenSet(): void
    {
        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
        ]);
        self::assertSame('https://hooks.slack.com/test', $config->slackWebhookUrl());
    }

    #[Test]
    public function logFileLevelDefaultsToInfo(): void
    {
        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
        ]);
        self::assertSame(\Monolog\Level::Info->value, $config->logFileLevel());
    }

    #[Test]
    public function logFileLevelMapsDebugString(): void
    {
        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
            'LOG_FILE_LEVEL' => 'debug',
        ]);
        self::assertSame(\Monolog\Level::Debug->value, $config->logFileLevel());
    }

    #[Test]
    public function logFileLevelRejectsUnknownValue(): void
    {
        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
            'LOG_FILE_LEVEL' => 'verbose',
        ]);
        $this->expectException(\InvalidArgumentException::class);
        $config->logFileLevel();
    }

    #[Test]
    public function composerLockPathReturnsEnvValueWhenSet(): void
    {
        $path = sys_get_temp_dir() . '/ase_cfg_envlock_' . uniqid() . '.lock';
        file_put_contents($path, '{"packages":[]}');

        $config = ConfigTestHelper::create([
            'COMPOSER_LOCK_PATH' => $path,
        ]);

        self::assertSame($path, $config->composerLockPath());

        unlink($path);
    }

    #[Test]
    public function composerLockPathReturnsNullWhenEnvUnset(): void
    {
        $config = ConfigTestHelper::withoutWebhook();
        self::assertNull($config->composerLockPath());
    }

    #[Test]
    public function composerLockPathIgnoresLocalComposerLockInCwd(): void
    {
        // Walk-up discovery has been removed. A composer.lock in CWD must NOT
        // be picked up when COMPOSER_LOCK_PATH is unset.
        $projectDir = sys_get_temp_dir() . '/ase_cfg_no_walkup_' . uniqid();
        mkdir($projectDir, 0755, true);
        $localLock = $projectDir . '/composer.lock';
        file_put_contents($localLock, '{"packages":[]}');

        $this->originalCwd = getcwd() ?: sys_get_temp_dir();
        chdir($projectDir);

        $config = ConfigTestHelper::withoutWebhook();
        self::assertNull($config->composerLockPath());

        chdir($this->originalCwd);
        $this->originalCwd = null;
        unlink($localLock);
        @rmdir($projectDir);
    }
}
