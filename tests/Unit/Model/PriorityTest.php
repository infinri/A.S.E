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
    public function casesAreExactlyP0AndP1(): void
    {
        self::assertSame([Priority::P0, Priority::P1], Priority::cases());
    }

    #[Test]
    public function isMoreUrgentThan(): void
    {
        self::assertTrue(Priority::P0->isMoreUrgentThan(Priority::P1));
        self::assertFalse(Priority::P1->isMoreUrgentThan(Priority::P0));
        self::assertFalse(Priority::P0->isMoreUrgentThan(Priority::P0));
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
    }

    #[Test]
    public function slackColorReturnsHexString(): void
    {
        foreach (Priority::cases() as $p) {
            self::assertMatchesRegularExpression('/^#[0-9A-F]{6}$/', $p->slackColor());
        }
    }

    #[Test]
    public function shouldNotifyTrueForAllCases(): void
    {
        self::assertTrue(Priority::P0->shouldNotify());
        self::assertTrue(Priority::P1->shouldNotify());
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
    }

    #[Test]
    public function fromNameThrowsOnInvalid(): void
    {
        $this->expectException(\ValueError::class);
        Priority::fromName('P2');
    }
}
