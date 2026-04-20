<?php

declare(strict_types=1);

namespace Ase\Model;

enum Priority: int
{
    case P0 = 0;
    case P1 = 1;

    public function isMoreUrgentThan(self $other): bool
    {
        return $this->value < $other->value;
    }

    public function label(): string
    {
        return match ($this) {
            self::P0 => 'Immediate',
            self::P1 => 'Urgent',
        };
    }

    public function slackColor(): string
    {
        return match ($this) {
            self::P0 => '#FF0000',
            self::P1 => '#FF6600',
        };
    }

    public function shouldNotify(): bool
    {
        return true;
    }

    public static function fromName(string $name): self
    {
        return match ($name) {
            'P0' => self::P0,
            'P1' => self::P1,
            default => throw new \ValueError("Invalid priority name: {$name}"),
        };
    }
}
