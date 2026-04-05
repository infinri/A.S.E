<?php

declare(strict_types=1);

namespace Ase\Model;

final readonly class FeedHealth
{
    private const int ESCALATION_THRESHOLD = 3;

    public function __construct(
        public ?string $lastSuccess = null,
        public ?string $lastFailure = null,
        public int $consecutiveFailures = 0,
    ) {}

    public function shouldEscalate(): bool
    {
        return $this->consecutiveFailures >= self::ESCALATION_THRESHOLD;
    }

    public function withSuccess(string $timestamp): self
    {
        return new self(
            lastSuccess: $timestamp,
            lastFailure: $this->lastFailure,
            consecutiveFailures: 0,
        );
    }

    public function withFailure(string $timestamp): self
    {
        return new self(
            lastSuccess: $this->lastSuccess,
            lastFailure: $timestamp,
            consecutiveFailures: $this->consecutiveFailures + 1,
        );
    }

    /** @return array<string, string|int|null> */
    public function toArray(): array
    {
        return [
            'last_success' => $this->lastSuccess,
            'last_failure' => $this->lastFailure,
            'consecutive_failures' => $this->consecutiveFailures,
        ];
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        return new self(
            lastSuccess: $data['last_success'] ?? null,
            lastFailure: $data['last_failure'] ?? null,
            consecutiveFailures: $data['consecutive_failures'] ?? 0,
        );
    }
}
