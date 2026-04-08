<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    protected function tearDown(): void
    {
        // Clean up env vars that may leak between tests
        foreach (['NVD_API_KEY', 'GITHUB_TOKEN', 'SLACK_WEBHOOK_URL'] as $key) {
            unset($_ENV[$key], $_SERVER[$key]);
            putenv($key);
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
}
