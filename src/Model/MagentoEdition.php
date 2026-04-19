<?php

declare(strict_types=1);

namespace Ase\Model;

final readonly class MagentoEdition
{
    public function __construct(
        public string $edition,
        public string $version,
        public string $packageName,
    ) {}

    /** @return array<string, string> */
    public function toArray(): array
    {
        return [
            'edition' => $this->edition,
            'version' => $this->version,
            'package' => $this->packageName,
        ];
    }
}
