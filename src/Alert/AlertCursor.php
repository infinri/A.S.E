<?php

declare(strict_types=1);

namespace Ase\Alert;

final readonly class AlertCursor
{
    public function __construct(
        private string $path,
    ) {}

    public function get(): int
    {
        if (!is_file($this->path)) {
            return 0;
        }
        $raw = file_get_contents($this->path);
        if ($raw === false) {
            throw new \RuntimeException("Cannot read alert cursor file {$this->path}.");
        }
        $data = json_decode($raw, true);
        return is_array($data) && is_int($data['attributedOn'] ?? null) ? $data['attributedOn'] : 0;
    }

    public function set(int $attributedOn): void
    {
        $dir = dirname($this->path);
        if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) {
            throw new \RuntimeException("Cannot create alert cursor directory {$dir}.");
        }
        $tmp = $this->path . '.tmp';
        if (file_put_contents($tmp, json_encode(['attributedOn' => $attributedOn], JSON_THROW_ON_ERROR)) === false
            || !rename($tmp, $this->path)) {
            throw new \RuntimeException("Cannot write alert cursor file {$this->path}.");
        }
    }
}
