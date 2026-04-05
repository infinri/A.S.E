<?php

declare(strict_types=1);

namespace Ase\Model;

enum Priority: int
{
    case P0 = 0;
    case P1 = 1;
    case P2 = 2;
    case P3 = 3;
    case P4 = 4;

    public function isMoreUrgentThan(self $other): bool
    {
        return $this->value < $other->value;
    }

    public function label(): string
    {
        return match ($this) {
            self::P0 => 'Immediate',
            self::P1 => 'Urgent',
            self::P2 => 'Soon',
            self::P3 => 'Monitor',
            self::P4 => 'Track',
        };
    }

    public function slackColor(): string
    {
        return match ($this) {
            self::P0 => '#FF0000',
            self::P1 => '#FF6600',
            self::P2 => '#FFCC00',
            self::P3 => '#999999',
            self::P4 => '#CCCCCC',
        };
    }

    public function shouldNotify(): bool
    {
        return match ($this) {
            self::P0, self::P1, self::P2 => true,
            self::P3, self::P4 => false,
        };
    }

    public static function fromName(string $name): self
    {
        return match ($name) {
            'P0' => self::P0,
            'P1' => self::P1,
            'P2' => self::P2,
            'P3' => self::P3,
            'P4' => self::P4,
            default => throw new \ValueError("Invalid priority name: {$name}"),
        };
    }
}
