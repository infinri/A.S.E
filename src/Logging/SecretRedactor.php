<?php

declare(strict_types=1);

namespace Ase\Logging;

final class SecretRedactor
{
    private const MIN_EXACT_LENGTH = 8;

    /** @var array<int, array{pattern: string, replacement: string}> */
    private array $patterns;

    /** @var array<int, array{secret: string, label: string}> */
    private array $exact = [];

    public function __construct()
    {
        $this->patterns = [
            [
                'pattern' => '#hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+#',
                'replacement' => 'hooks.slack.com/services/[REDACTED:slack-webhook]',
            ],
            [
                'pattern' => '#github_pat_[A-Za-z0-9_]{80,}#',
                'replacement' => '[REDACTED:github-token]',
            ],
            [
                'pattern' => '#gh[pousr]_[A-Za-z0-9]{36,}#',
                'replacement' => '[REDACTED:github-token]',
            ],
            [
                'pattern' => '#(?i)Bearer\s+[A-Za-z0-9._~+/=\-]{8,}#',
                'replacement' => 'Bearer [REDACTED:bearer]',
            ],
            [
                'pattern' => '#(https?://)([^:@/\s]+):[^@/\s]+@#',
                'replacement' => '$1$2:[REDACTED:basic-auth]@',
            ],
        ];
    }

    public function registerSecret(string $secret, string $label): void
    {
        if (strlen($secret) < self::MIN_EXACT_LENGTH) {
            return;
        }
        $this->exact[] = ['secret' => $secret, 'label' => $label];
    }

    public function redact(string $input): string
    {
        $out = $input;

        foreach ($this->exact as $entry) {
            $out = str_replace($entry['secret'], '[REDACTED:' . $entry['label'] . ']', $out);
        }

        foreach ($this->patterns as $rule) {
            $result = preg_replace($rule['pattern'], $rule['replacement'], $out);
            if (is_string($result)) {
                $out = $result;
            }
        }

        return $out;
    }
}
