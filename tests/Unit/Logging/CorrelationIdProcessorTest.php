<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Logging;

use Ase\Logging\CorrelationIdProcessor;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class CorrelationIdProcessorTest extends TestCase
{
    #[Test]
    public function testRecordUnchangedWhenRunIdIsNull(): void
    {
        $processor = new CorrelationIdProcessor();
        $record = $this->makeRecord();

        $out = $processor($record);

        self::assertArrayNotHasKey('run_id', $out->extra);
    }

    #[Test]
    public function testRecordExtraGetsRunIdWhenSet(): void
    {
        $processor = new CorrelationIdProcessor();
        $processor->setRunId('abc-123');

        $out = $processor($this->makeRecord());

        self::assertSame('abc-123', $out->extra['run_id']);
    }

    #[Test]
    public function testSetRunIdNullClearsInjection(): void
    {
        $processor = new CorrelationIdProcessor();
        $processor->setRunId('abc-123');
        $processor->setRunId(null);

        $out = $processor($this->makeRecord());

        self::assertArrayNotHasKey('run_id', $out->extra);
    }

    #[Test]
    public function testChangingRunIdReflectedInSubsequentRecords(): void
    {
        $processor = new CorrelationIdProcessor();

        $processor->setRunId('first');
        $a = $processor($this->makeRecord());

        $processor->setRunId('second');
        $b = $processor($this->makeRecord());

        self::assertSame('first', $a->extra['run_id']);
        self::assertSame('second', $b->extra['run_id']);
    }

    private function makeRecord(): LogRecord
    {
        return new LogRecord(
            datetime: new \DateTimeImmutable(),
            channel: 'test',
            level: Level::Info,
            message: 'msg',
            context: [],
            extra: [],
        );
    }
}
