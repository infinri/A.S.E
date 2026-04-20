<?php

declare(strict_types=1);

namespace Ase\State;

use Psr\Log\LoggerInterface;

final class StateManager
{
    /** @var array<string, mixed>|null */
    private ?array $state = null;

    /** @var array<string, mixed> */
    private const array DEFAULT_STATE = [
        'version' => 1,
        'last_run' => null,
        'feed_cursors' => [],
        'feed_health' => [],
        'vulnerabilities' => [],
        'stats' => [
            'total_tracked' => 0,
            'total_notified' => 0,
            'total_escalations' => 0,
        ],
    ];

    public function __construct(
        private readonly string $filePath,
        private readonly LoggerInterface $logger,
    ) {}

    /** @return array<string, mixed> */
    public function load(): array
    {
        if ($this->state !== null) {
            return $this->state;
        }

        if (!file_exists($this->filePath)) {
            $this->logger->info('State file not found, using defaults', ['path' => $this->filePath]);
            $this->state = self::DEFAULT_STATE;
            return $this->state;
        }

        $handle = fopen($this->filePath, 'r');
        if ($handle === false) {
            $this->logger->critical('Cannot open state file', ['path' => $this->filePath]);
            $this->state = self::DEFAULT_STATE;
            return $this->state;
        }

        flock($handle, LOCK_SH);
        $contents = stream_get_contents($handle);
        flock($handle, LOCK_UN);
        fclose($handle);

        if ($contents === false || $contents === '') {
            $this->logger->warning('State file is empty', ['path' => $this->filePath]);
            $this->state = self::DEFAULT_STATE;
            return $this->state;
        }

        $decoded = json_decode($contents, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->logger->critical('State file is corrupted, resetting to defaults', [
                'path' => $this->filePath,
                'error' => json_last_error_msg(),
            ]);
            $this->state = self::DEFAULT_STATE;
            return $this->state;
        }

        $merged = array_merge(self::DEFAULT_STATE, $decoded);
        $this->state = $this->prunePreP4LegacyPriorities($merged);
        return $this->state;
    }

    /**
     * @param array<string, mixed> $state
     * @return array<string, mixed>
     */
    private function prunePreP4LegacyPriorities(array $state): array
    {
        /** @var array<string, array<string, mixed>> $vulns */
        $vulns = $state['vulnerabilities'] ?? [];
        $allowed = ['P0', 'P1'];
        $pruned = 0;

        foreach ($vulns as $id => $data) {
            $priority = $data['priority'] ?? null;
            $notifiedAt = $data['notified_at_priority'] ?? null;

            $priorityLegacy = is_string($priority) && !in_array($priority, $allowed, true);
            $notifiedLegacy = is_string($notifiedAt) && !in_array($notifiedAt, $allowed, true);

            if ($priorityLegacy || $notifiedLegacy) {
                unset($vulns[$id]);
                $pruned++;
            }
        }

        if ($pruned > 0) {
            $this->logger->info('Pruned legacy priority entries', ['count' => $pruned]);
            $state['vulnerabilities'] = $vulns;
        }

        return $state;
    }

    /** @param array<string, mixed> $state */
    public function save(array $state): void
    {
        $state['last_run'] = date('c');
        $state['stats']['total_tracked'] = count($state['vulnerabilities'] ?? []);

        $dir = dirname($this->filePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        $tmpPath = $this->filePath . '.tmp.' . getmypid();
        $json = json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        $written = file_put_contents($tmpPath, $json, LOCK_EX);

        if ($written === false) {
            $this->logger->critical('Failed to write temp state file', ['path' => $tmpPath]);
            return;
        }

        if (!rename($tmpPath, $this->filePath)) {
            $this->logger->critical('Failed to atomically replace state file', [
                'tmp' => $tmpPath,
                'target' => $this->filePath,
            ]);
            @unlink($tmpPath);
            return;
        }

        $this->state = $state;

        $this->logger->info('State saved', [
            'path' => $this->filePath,
            'size_kb' => round(strlen($json) / 1024, 1),
            'vulnerabilities' => $state['stats']['total_tracked'],
        ]);
    }

    public function isFirstRun(): bool
    {
        $state = $this->load();
        return $state['last_run'] === null;
    }

    /** @return array<string, mixed>|null */
    public function getVulnerability(string $id): ?array
    {
        $state = $this->load();
        return $state['vulnerabilities'][$id] ?? null;
    }

    /** @return array<string, mixed>|null */
    public function getFeedCursor(string $feed): ?array
    {
        $state = $this->load();
        return $state['feed_cursors'][$feed] ?? null;
    }

    /** @return array<string, mixed> */
    public function getFeedHealth(string $feed): array
    {
        $state = $this->load();
        return $state['feed_health'][$feed] ?? [
            'last_success' => null,
            'last_failure' => null,
            'consecutive_failures' => 0,
        ];
    }
}
