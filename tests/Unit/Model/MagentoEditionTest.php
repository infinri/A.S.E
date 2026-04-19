<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Model;

use Ase\Model\MagentoEdition;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class MagentoEditionTest extends TestCase
{
    #[Test]
    public function testToArrayReturnsExpectedShape(): void
    {
        $edition = new MagentoEdition(
            edition: 'magento-community',
            version: '2.4.7',
            packageName: 'magento/product-community-edition',
        );

        self::assertSame(
            [
                'edition' => 'magento-community',
                'version' => '2.4.7',
                'package' => 'magento/product-community-edition',
            ],
            $edition->toArray(),
        );
    }

    #[Test]
    public function testReadonlyPropertiesAreAccessible(): void
    {
        $edition = new MagentoEdition(
            edition: 'magento-enterprise',
            version: '2.4.8',
            packageName: 'magento/product-enterprise-edition',
        );

        self::assertSame('magento-enterprise', $edition->edition);
        self::assertSame('2.4.8', $edition->version);
        self::assertSame('magento/product-enterprise-edition', $edition->packageName);
    }
}
