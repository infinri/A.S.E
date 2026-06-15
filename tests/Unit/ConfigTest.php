<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    protected function tearDown(): void
    {
        $key = 'ASE_ALERT_DEFAULT_WEBHOOK';
        unset($_ENV[$key], $_SERVER[$key]);
        putenv($key);
    }

    #[Test]
    public function trimsWhitespaceFromOptionalValues(): void
    {
        $config = ConfigTestHelper::create([
            'ASE_ALERT_DEFAULT_WEBHOOK' => '  https://hooks.slack.com/services/x  ',
        ]);

        self::assertSame('https://hooks.slack.com/services/x', $config->alertDefaultWebhook());
    }

    #[Test]
    public function trimsCarriageReturnFromOptionalValues(): void
    {
        $config = ConfigTestHelper::create([
            'ASE_ALERT_DEFAULT_WEBHOOK' => "https://hooks.slack.com/services/x\r",
        ]);

        self::assertSame('https://hooks.slack.com/services/x', $config->alertDefaultWebhook());
    }

    #[Test]
    public function returnsNullForEmptyOptionalValues(): void
    {
        $config = ConfigTestHelper::create([]);

        self::assertNull($config->alertDefaultWebhook());
    }
}
