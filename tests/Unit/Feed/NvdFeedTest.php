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

        $logger = new \Psr\Log\NullLogger();
        $analyzer = new \Ase\Filter\ComposerLockAnalyzer($config, $logger);
        $feed = new NvdFeed($http, $config, $logger, $analyzer);

        self::assertSame('nvd', $feed->getName());
    }
}
