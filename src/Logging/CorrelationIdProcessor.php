<?php

declare(strict_types=1);

namespace Ase\Logging;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

final class CorrelationIdProcessor implements ProcessorInterface
{
    private ?string $runId = null;

    public function setRunId(?string $runId): void
    {
        $this->runId = $runId;
    }

    public function __invoke(LogRecord $record): LogRecord
    {
        if ($this->runId === null) {
            return $record;
        }

        $extra = $record->extra;
        $extra['run_id'] = $this->runId;

        return $record->with(extra: $extra);
    }
}
