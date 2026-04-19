<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Logging;

use Ase\Logging\SecretRedactor;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class SecretRedactorTest extends TestCase
{
    #[Test]
    public function testMasksSlackWebhookUrl(): void
    {
        $r = new SecretRedactor();
        // URL built via concatenation so raw source does not resemble a real
        // Slack webhook (avoids GitHub secret-scanning false positive).
        $secret = 'xYzAbCd' . 'EfGhIj' . 'KlMnOpQrStUv';
        $input = 'Posting to https://hooks.slack.com/services/T012' . 'ABCD34/B056' . 'EFGH78/' . $secret . ' now';

        $out = $r->redact($input);

        self::assertStringNotContainsString($secret, $out);
        self::assertStringContainsString('[REDACTED:slack-webhook]', $out);
    }

    #[Test]
    public function testMasksGithubClassicToken(): void
    {
        $r = new SecretRedactor();
        $input = 'token=ghp_abcdefghijklmnopqrstuvwxyzABCDEF0123 failed';

        $out = $r->redact($input);

        self::assertStringNotContainsString('ghp_abcdefghijklmnopqrstuvwxyzABCDEF0123', $out);
        self::assertStringContainsString('[REDACTED:github-token]', $out);
    }

    #[Test]
    public function testMasksGithubFineGrainedToken(): void
    {
        $r = new SecretRedactor();
        $prefix = 'github_pat_';
        $body = str_repeat('A', 82);
        $input = "auth {$prefix}{$body}";

        $out = $r->redact($input);

        self::assertStringNotContainsString($body, $out);
        self::assertStringContainsString('[REDACTED:github-token]', $out);
    }

    #[Test]
    public function testMasksEveryGithubTokenPrefix(): void
    {
        $r = new SecretRedactor();
        foreach (['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_'] as $prefix) {
            $token = $prefix . str_repeat('X', 40);
            $out = $r->redact("value={$token};");

            self::assertStringNotContainsString($token, $out, "{$prefix} token must be masked");
            self::assertStringContainsString('[REDACTED:github-token]', $out);
        }
    }

    #[Test]
    public function testMasksBearerToken(): void
    {
        $r = new SecretRedactor();
        $out = $r->redact('Authorization: Bearer abc123_XYZ-def456.ghi789');

        self::assertStringNotContainsString('abc123_XYZ-def456.ghi789', $out);
        self::assertStringContainsString('[REDACTED:bearer]', $out);
    }

    #[Test]
    public function testMasksUrlBasicAuth(): void
    {
        $r = new SecretRedactor();
        $out = $r->redact('Connecting to https://admin:supersecret@example.com/path');

        self::assertStringNotContainsString('supersecret', $out);
        self::assertStringContainsString('[REDACTED:basic-auth]', $out);
    }

    #[Test]
    public function testRegisteredExactMatchSecretIsMasked(): void
    {
        $r = new SecretRedactor();
        $r->registerSecret('a1b2c3d4-e5f6-4789-8abc-def012345678', 'nvd-key');

        $out = $r->redact('Calling NVD with key a1b2c3d4-e5f6-4789-8abc-def012345678');

        self::assertStringNotContainsString('a1b2c3d4-e5f6-4789-8abc-def012345678', $out);
        self::assertStringContainsString('[REDACTED:nvd-key]', $out);
    }

    #[Test]
    public function testRegisterSecretRejectsEmptyValue(): void
    {
        $r = new SecretRedactor();
        $r->registerSecret('', 'whatever');
        $out = $r->redact('nothing to mask here');

        self::assertSame('nothing to mask here', $out);
    }

    #[Test]
    public function testRegisterSecretRejectsTooShortValue(): void
    {
        $r = new SecretRedactor();
        $r->registerSecret('abc', 'too-short');
        $out = $r->redact('abc is not a secret worth scrubbing');

        self::assertSame('abc is not a secret worth scrubbing', $out);
    }

    #[Test]
    public function testNoopWhenInputHasNoSecrets(): void
    {
        $r = new SecretRedactor();
        $input = 'A normal log line about CVE-2024-12345 and composer.lock';

        self::assertSame($input, $r->redact($input));
    }

    #[Test]
    public function testExceptionMessageWithWebhookStaysMasked(): void
    {
        $r = new SecretRedactor();
        $secret = 'MNOPQRSTUVWX' . 'YZabcdefghij';
        $webhook = 'https://hooks.slack.com/services/T0ABC' . 'DEF1/B0GHI' . 'JKL2/' . $secret;
        $e = new \RuntimeException("Failed POST to {$webhook}: HTTP 500");

        $out = $r->redact((string) $e);

        self::assertStringNotContainsString($secret, $out);
        self::assertStringContainsString('[REDACTED:slack-webhook]', $out);
    }
}
