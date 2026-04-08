<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Feed;

use Ase\Feed\NvdFeed;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class NvdFeedTest extends TestCase
{
    #[Test]
    public function feedNameIsNvd(): void
    {
        $http = new \Ase\Http\CurlClient(new \Psr\Log\NullLogger());
        $config = \Ase\Tests\Unit\ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
        ]);

        $feed = new NvdFeed($http, $config, new \Psr\Log\NullLogger());

        self::assertSame('nvd', $feed->getName());
    }
}
