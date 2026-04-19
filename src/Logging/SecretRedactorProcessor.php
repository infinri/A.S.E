<?php

declare(strict_types=1);

namespace Ase\Logging;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

final class SecretRedactorProcessor implements ProcessorInterface
{
    public function __construct(private readonly SecretRedactor $redactor) {}

    public function __invoke(LogRecord $record): LogRecord
    {
        $message = $this->redactor->redact($record->message);
        $context = $this->scrubArray($record->context);
        $extra = $this->scrubArray($record->extra);

        return $record->with(message: $message, context: $context, extra: $extra);
    }

    /**
     * @param array<array-key, mixed> $values
     * @return array<array-key, mixed>
     */
    private function scrubArray(array $values): array
    {
        $out = [];
        foreach ($values as $key => $value) {
            $out[$key] = match (true) {
                is_string($value) => $this->redactor->redact($value),
                is_array($value) => $this->scrubArray($value),
                default => $value,
            };
        }
        return $out;
    }
}
