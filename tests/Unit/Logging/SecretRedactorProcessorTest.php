<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Logging;

use Ase\Logging\SecretRedactor;
use Ase\Logging\SecretRedactorProcessor;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class SecretRedactorProcessorTest extends TestCase
{
    #[Test]
    public function testScrubsMessageField(): void
    {
        $processor = new SecretRedactorProcessor(new SecretRedactor());
        $secret = 'abcdefghij' . 'klmnopqrstuvwx';
        $record = $this->makeRecord(
            'Posting to https://hooks.slack.com/services/T' . '1/B' . '1/' . $secret,
        );

        $out = $processor($record);

        self::assertStringContainsString('[REDACTED:slack-webhook]', $out->message);
        self::assertStringNotContainsString($secret, $out->message);
    }

    #[Test]
    public function testScrubsStringContextValues(): void
    {
        $processor = new SecretRedactorProcessor(new SecretRedactor());
        $record = $this->makeRecord('normal message', [
            'url' => 'https://admin:topsecret@example.com',
            'status' => 500,
        ]);

        $out = $processor($record);

        self::assertStringContainsString('[REDACTED:basic-auth]', (string) $out->context['url']);
        self::assertSame(500, $out->context['status']);
    }

    #[Test]
    public function testScrubsNestedArrayValuesRecursively(): void
    {
        $processor = new SecretRedactorProcessor(new SecretRedactor());
        $record = $this->makeRecord('outer', [
            'nested' => [
                'auth' => 'Bearer abcdef_xyz-longer-than-eight',
                'safe' => 'harmless',
            ],
        ]);

        $out = $processor($record);

        self::assertIsArray($out->context['nested']);
        self::assertStringContainsString('[REDACTED:bearer]', (string) $out->context['nested']['auth']);
        self::assertSame('harmless', $out->context['nested']['safe']);
    }

    #[Test]
    public function testLeavesNonStringLeavesUntouched(): void
    {
        $processor = new SecretRedactorProcessor(new SecretRedactor());
        $record = $this->makeRecord('msg', [
            'flag' => true,
            'count' => 42,
            'ratio' => 0.5,
            'absent' => null,
        ]);

        $out = $processor($record);

        self::assertTrue($out->context['flag']);
        self::assertSame(42, $out->context['count']);
        self::assertSame(0.5, $out->context['ratio']);
        self::assertNull($out->context['absent']);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function makeRecord(string $message, array $context = []): LogRecord
    {
        return new LogRecord(
            datetime: new \DateTimeImmutable(),
            channel: 'test',
            level: Level::Info,
            message: $message,
            context: $context,
            extra: [],
        );
    }
}
