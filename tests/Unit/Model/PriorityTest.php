<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Model;

use Ase\Model\Priority;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class PriorityTest extends TestCase
{
    #[Test]
    public function isMoreUrgentThan(): void
    {
        self::assertTrue(Priority::P0->isMoreUrgentThan(Priority::P1));
        self::assertTrue(Priority::P0->isMoreUrgentThan(Priority::P4));
        self::assertTrue(Priority::P2->isMoreUrgentThan(Priority::P3));
        self::assertFalse(Priority::P4->isMoreUrgentThan(Priority::P0));
        self::assertFalse(Priority::P2->isMoreUrgentThan(Priority::P2));
    }

    #[Test]
    #[DataProvider('labelProvider')]
    public function label(Priority $priority, string $expected): void
    {
        self::assertSame($expected, $priority->label());
    }

    public static function labelProvider(): iterable
    {
        yield 'P0' => [Priority::P0, 'Immediate'];
        yield 'P1' => [Priority::P1, 'Urgent'];
        yield 'P2' => [Priority::P2, 'Soon'];
        yield 'P3' => [Priority::P3, 'Monitor'];
        yield 'P4' => [Priority::P4, 'Track'];
    }

    #[Test]
    public function slackColorReturnsHexString(): void
    {
        foreach (Priority::cases() as $p) {
            self::assertMatchesRegularExpression('/^#[0-9A-F]{6}$/', $p->slackColor());
        }
    }

    #[Test]
    public function shouldNotifyTrueForP0ThroughP2(): void
    {
        self::assertTrue(Priority::P0->shouldNotify());
        self::assertTrue(Priority::P1->shouldNotify());
        self::assertTrue(Priority::P2->shouldNotify());
        self::assertFalse(Priority::P3->shouldNotify());
        self::assertFalse(Priority::P4->shouldNotify());
    }

    #[Test]
    #[DataProvider('fromNameProvider')]
    public function fromName(string $name, Priority $expected): void
    {
        self::assertSame($expected, Priority::fromName($name));
    }

    public static function fromNameProvider(): iterable
    {
        yield ['P0', Priority::P0];
        yield ['P1', Priority::P1];
        yield ['P2', Priority::P2];
        yield ['P3', Priority::P3];
        yield ['P4', Priority::P4];
    }

    #[Test]
    public function fromNameThrowsOnInvalid(): void
    {
        $this->expectException(\ValueError::class);
        Priority::fromName('P99');
    }
}