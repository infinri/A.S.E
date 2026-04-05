<?php

declare(strict_types=1);

namespace Ase\Model;

final readonly class AffectedPackage
{
    public function __construct(
        public string $ecosystem,
        public string $name,
        public string $vulnerableRange,
        public ?string $fixedVersion = null,
    ) {}

    /** @return array<string, string|null> */
    public function toArray(): array
    {
        return [
            'ecosystem' => $this->ecosystem,
            'name' => $this->name,
            'vulnerable_range' => $this->vulnerableRange,
            'fixed_version' => $this->fixedVersion,
        ];
    }

    /** @param array<string, string|null> $data */
    public static function fromArray(array $data): self
    {
        return new self(
            ecosystem: (string) ($data['ecosystem'] ?? ''),
            name: (string) ($data['name'] ?? ''),
            vulnerableRange: (string) ($data['vulnerable_range'] ?? '*'),
            fixedVersion: $data['fixed_version'] ?? null,
        );
    }
}
