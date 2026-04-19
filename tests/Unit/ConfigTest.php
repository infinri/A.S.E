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
    public function testComposerLockPathWalksUpFromCwd(): void
    {
        $projectDir = sys_get_temp_dir() . '/ase_cfg_walkup_' . uniqid();
        $subDir = $projectDir . '/sub/nested';
        mkdir($subDir, 0755, true);

        $lockPath = $projectDir . '/composer.lock';
        file_put_contents($lockPath, '{"packages":[]}');

        $this->originalCwd = getcwd() ?: sys_get_temp_dir();
        chdir($subDir);

        $config = ConfigTestHelper::withoutWebhook();

        $resolved = $config->composerLockPath();

        self::assertNotNull($resolved);
        self::assertSame(realpath($lockPath), realpath($resolved));

        chdir($this->originalCwd);
        $this->originalCwd = null;
        unlink($lockPath);
        @rmdir($subDir);
        @rmdir($projectDir . '/sub');
        @rmdir($projectDir);
    }

    #[Test]
    public function testComposerLockPathUsesEnvFallbackWhenWalkUpFails(): void
    {
        $scratch = sys_get_temp_dir() . '/ase_cfg_nolock_' . uniqid();
        mkdir($scratch, 0755, true);
        $this->originalCwd = getcwd() ?: sys_get_temp_dir();
        chdir($scratch);

        $fallbackLock = sys_get_temp_dir() . '/ase_cfg_fallback_' . uniqid() . '.lock';
        file_put_contents($fallbackLock, '{"packages":[]}');

        $config = ConfigTestHelper::create([
            'COMPOSER_LOCK_PATH' => $fallbackLock,
        ]);

        self::assertSame($fallbackLock, $config->composerLockPath());

        chdir($this->originalCwd);
        $this->originalCwd = null;
        unlink($fallbackLock);
        @rmdir($scratch);
    }

    #[Test]
    public function testComposerLockPathWalkUpWinsOverEnv(): void
    {
        $projectDir = sys_get_temp_dir() . '/ase_cfg_winover_' . uniqid();
        mkdir($projectDir, 0755, true);
        $walkUpLock = $projectDir . '/composer.lock';
        file_put_contents($walkUpLock, '{"packages":[]}');

        $envLock = sys_get_temp_dir() . '/ase_cfg_env_' . uniqid() . '.lock';
        file_put_contents($envLock, '{"packages":[]}');

        $this->originalCwd = getcwd() ?: sys_get_temp_dir();
        chdir($projectDir);

        $config = ConfigTestHelper::create([
            'COMPOSER_LOCK_PATH' => $envLock,
        ]);

        $resolved = $config->composerLockPath();
        self::assertNotNull($resolved);
        self::assertSame(realpath($walkUpLock), realpath($resolved));

        chdir($this->originalCwd);
        $this->originalCwd = null;
        unlink($walkUpLock);
        unlink($envLock);
        @rmdir($projectDir);
    }

    #[Test]
    public function testComposerLockPathReturnsNullWhenNeitherAvailable(): void
    {
        $scratch = sys_get_temp_dir() . '/ase_cfg_none_' . uniqid();
        mkdir($scratch, 0755, true);
        $this->originalCwd = getcwd() ?: sys_get_temp_dir();
        chdir($scratch);

        // Nothing in walk-up from this sibling scratch dir, no COMPOSER_LOCK_PATH.
        // But walk-up from /tmp/ase_cfg_none_X will hit /, where there's no composer.lock.
        // However, if sys_get_temp_dir parents have a composer.lock we'd find it.
        // We chdir into a dedicated scratch dir, so walk-up only passes through /tmp and /.
        $config = ConfigTestHelper::withoutWebhook();
        self::assertNull($config->composerLockPath());

        chdir($this->originalCwd);
        $this->originalCwd = null;
        @rmdir($scratch);
    }
}
