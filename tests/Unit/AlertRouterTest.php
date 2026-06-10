<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use Ase\Alert\AlertRouter;
use PHPUnit\Framework\TestCase;

final class AlertRouterTest extends TestCase
{
    public function testRoutesByMatchingTag(): void
    {
        $router = new AlertRouter(
            ['team:ecommerce' => 'https://hooks.example/eco', 'team:infra' => 'https://hooks.example/infra'],
            null,
        );

        self::assertSame(['https://hooks.example/eco'], $router->webhooksForTags(['team:ecommerce', 'prod']));
    }

    public function testMultipleMatchingTagsDeduplicated(): void
    {
        $router = new AlertRouter(
            ['team:a' => 'https://hooks.example/same', 'team:b' => 'https://hooks.example/same'],
            null,
        );

        self::assertSame(['https://hooks.example/same'], $router->webhooksForTags(['team:a', 'team:b']));
    }

    public function testFallsBackToDefault(): void
    {
        $router = new AlertRouter(['team:a' => 'https://hooks.example/a'], 'https://hooks.example/default');

        self::assertSame(['https://hooks.example/default'], $router->webhooksForTags(['unmapped']));
    }

    public function testNoMatchNoDefaultReturnsEmpty(): void
    {
        $router = new AlertRouter(['team:a' => 'https://hooks.example/a'], null);

        self::assertSame([], $router->webhooksForTags([]));
    }
}
