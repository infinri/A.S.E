<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use Ase\Alert\AlertCursor;
use PHPUnit\Framework\TestCase;

final class AlertCursorTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/ase-cursor-' . uniqid() . '/cursor.json';
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
        @rmdir(dirname($this->path));
    }

    public function testReturnsZeroWhenMissing(): void
    {
        self::assertSame(0, new AlertCursor($this->path)->get());
    }

    public function testRoundTrips(): void
    {
        $cursor = new AlertCursor($this->path);
        $cursor->set(1781200000000);

        self::assertSame(1781200000000, new AlertCursor($this->path)->get());
    }
}
