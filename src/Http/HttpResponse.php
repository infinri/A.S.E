<?php

declare(strict_types=1);

namespace Ase\Http;

final readonly class HttpResponse
{
    /** @param array<string, string> $headers */
    public function __construct(
        public int $statusCode,
        public string $body,
        public array $headers = [],
    ) {}

    /**
     * @param positive-int $depth
     * @return array<string, mixed>
     */
    public function json(int $depth = 64): array
    {
        $decoded = json_decode($this->body, true, $depth, JSON_THROW_ON_ERROR);

        if (!is_array($decoded)) {
            throw new \JsonException('Expected JSON array or object, got ' . gettype($decoded));
        }

        return $decoded;
    }

    public function isOk(): bool
    {
        return $this->statusCode >= 200 && $this->statusCode < 300;
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }
}
