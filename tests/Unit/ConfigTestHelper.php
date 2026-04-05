<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use Ase\Config;

final class ConfigTestHelper
{
    /**
     * Creates a Config instance backed by a temporary .env file.
     *
     * @param array<string, string> $env Key-value pairs to write to .env
     */
    public static function create(array $env = []): Config
    {
        // Clear any previously set env vars to avoid immutable dotenv conflicts
        foreach ($env as $key => $value) {
            unset($_ENV[$key], $_SERVER[$key]);
            putenv($key);
        }

        $tmpDir = sys_get_temp_dir() . '/ase_config_' . uniqid();
        mkdir($tmpDir, 0755, true);

        $lines = [];
        foreach ($env as $key => $value) {
            $lines[] = "{$key}={$value}";
        }
        file_put_contents($tmpDir . '/.env', implode("\n", $lines));

        $config = new Config($tmpDir);

        // Clean up temp files
        unlink($tmpDir . '/.env');
        rmdir($tmpDir);

        return $config;
    }

    /**
     * Creates a Config with default thresholds suitable for testing PriorityCalculator.
     */
    public static function withDefaults(): Config
    {
        return self::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
            'EPSS_HIGH_THRESHOLD' => '0.10',
            'EPSS_MEDIUM_THRESHOLD' => '0.05',
            'CVSS_CRITICAL_THRESHOLD' => '9.0',
            'CVSS_HIGH_THRESHOLD' => '7.0',
            'CVSS_MEDIUM_THRESHOLD' => '4.0',
        ]);
    }
}
