<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Model;

use Ase\Model\AffectedPackage;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AffectedPackageTest extends TestCase
{
    #[Test]
    public function toArraySerializesAllFields(): void
    {
        $pkg = new AffectedPackage('composer', 'vendor/lib', '>=1.0 <2.0', '2.0.0');

        self::assertSame([
            'ecosystem' => 'composer',
            'name' => 'vendor/lib',
            'vulnerable_range' => '>=1.0 <2.0',
            'fixed_version' => '2.0.0',
        ], $pkg->toArray());
    }

    #[Test]
    public function fromArrayRoundTrips(): void
    {
        $data = [
            'ecosystem' => 'npm',
            'name' => 'lodash',
            'vulnerable_range' => '<4.17.21',
            'fixed_version' => '4.17.21',
        ];

        $pkg = AffectedPackage::fromArray($data);

        self::assertSame('npm', $pkg->ecosystem);
        self::assertSame('lodash', $pkg->name);
        self::assertSame('<4.17.21', $pkg->vulnerableRange);
        self::assertSame('4.17.21', $pkg->fixedVersion);
        self::assertSame($data, $pkg->toArray());
    }

    #[Test]
    public function fromArrayHandlesMissingFields(): void
    {
        $pkg = AffectedPackage::fromArray([]);

        self::assertSame('', $pkg->ecosystem);
        self::assertSame('', $pkg->name);
        self::assertSame('*', $pkg->vulnerableRange);
        self::assertNull($pkg->fixedVersion);
    }

    #[Test]
    public function fixedVersionDefaultsToNull(): void
    {
        $pkg = new AffectedPackage('composer', 'vendor/lib', '>=1.0');

        self::assertNull($pkg->fixedVersion);
    }
}
