<?php

declare(strict_types=1);

namespace Ase;

use Ase\Dedup\Deduplicator;
use Ase\Feed\EpssFeed;
use Ase\Feed\FeedInterface;
use Ase\Filter\ComposerLockAnalyzer;
use Ase\Health\DigestReporter;
use Ase\Health\FeedHealthTracker;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;
use Ase\Model\VulnerabilityBatch;
use Ase\Notify\SlackNotifier;
use Ase\Scoring\PriorityCalculator;
use Ase\State\StateManager;
use Psr\Log\LoggerInterface;

final class Ase
{
    /** @param FeedInterface[] $feeds */
    public function __construct(
        private readonly Config $config,
        private readonly StateManager $stateManager,
        private readonly array $feeds,
        private readonly EpssFeed $epss,
        private readonly Deduplicator $deduplicator,
        private readonly PriorityCalculator $priorityCalculator,
        private readonly ComposerLockAnalyzer $composerLockAnalyzer,
        private readonly SlackNotifier $slackNotifier,
        private readonly FeedHealthTracker $healthTracker,
        private readonly DigestReporter $digestReporter,
        private readonly LoggerInterface $logger,
    ) {}

    public function run(): void
    {
        $this->logger->info('A.S.E. run started');

        $state = $this->stateManager->load();
        $isFirstRun = $this->stateManager->isFirstRun();

        if ($isFirstRun) {
            $this->logger->info('First run detected: silent import mode');
        }

        // Poll enabled feeds
        $batches = $this->pollFeeds($state);

        if ($this->allBatchesEmpty($batches)) {
            $this->logger->info('No new vulnerabilities from any feed');
            $this->finalize($state, $isFirstRun);
            return;
        }

        // Merge new data into existing state
        /** @var array<string, array<string, mixed>> $existingVulns */
        $existingVulns = $state['vulnerabilities'] ?? [];
        $result = $this->deduplicator->merge($existingVulns, ...$batches);

        // EPSS enrichment for new CVEs
        $allVulns = $this->enrichWithEpss($result->allVulnerabilities, $state);

        // Composer.lock cross-reference
        $allVulns = $this->composerLockAnalyzer->checkInstalledVersions($allVulns);

        // Classify priorities
        $allVulns = $this->priorityCalculator->classifyAll($allVulns);

        // Determine what to notify
        $newAlerts = [];
        $escalations = [];

        foreach ($allVulns as $vuln) {
            if ($isFirstRun) {
                // Silent import: mark as notified at current priority, send nothing
                $allVulns[$vuln->canonicalId] = $vuln->withNotifiedAtPriority($vuln->priority);
                continue;
            }

            if ($vuln->notifiedAtPriority === null && $vuln->priority->shouldNotify()) {
                // New vulnerability, never notified
                $newAlerts[] = $vuln;
            } elseif ($vuln->shouldEscalate() && $vuln->priority->shouldNotify()) {
                // Existing vulnerability escalated to more urgent tier
                $escalations[] = $vuln;
            }
        }

        // Send notifications
        if ($newAlerts !== [] || $escalations !== []) {
            $sent = $this->slackNotifier->sendAlerts($newAlerts, $escalations);

            // Mark notified
            foreach ([...$newAlerts, ...$escalations] as $vuln) {
                $allVulns[$vuln->canonicalId] = $vuln->withNotifiedAtPriority($vuln->priority);
            }

            $state['stats']['total_notified'] = ($state['stats']['total_notified'] ?? 0) + count($newAlerts);
            $state['stats']['total_escalations'] = ($state['stats']['total_escalations'] ?? 0) + count($escalations);

            $this->logger->info('Notifications sent', [
                'new' => count($newAlerts),
                'escalations' => count($escalations),
                'slack_messages' => $sent,
            ]);
        }

        // Serialize vulnerabilities back to state
        $state['vulnerabilities'] = [];
        foreach ($allVulns as $vuln) {
            $state['vulnerabilities'][$vuln->canonicalId] = $vuln->toArray();
        }

        $this->finalize($state, $isFirstRun);
    }

    /**
     * @param array<string, mixed> $state
     * @return VulnerabilityBatch[]
     */
    private function pollFeeds(array &$state): array
    {
        $batches = [];

        foreach ($this->feeds as $feed) {
            $feedName = $feed->getName();

            if (!$this->config->isFeedEnabled($feedName)) {
                continue;
            }

            // Check poll interval
            $cursor = $state['feed_cursors'][$feedName] ?? [];
            $lastPoll = $cursor['last_poll'] ?? null;

            if ($lastPoll !== null) {
                $elapsed = time() - strtotime($lastPoll);
                $interval = $this->config->pollInterval($feedName);

                if ($elapsed < $interval) {
                    $this->logger->debug('Skipping feed (interval not reached)', [
                        'feed' => $feedName,
                        'elapsed' => $elapsed,
                        'interval' => $interval,
                    ]);
                    continue;
                }
            }

            $lastPollTimestamp = $lastPoll ?? 'first_run';

            try {
                $this->logger->info('Polling feed', ['feed' => $feedName]);
                $batch = $feed->poll($lastPollTimestamp);
                $this->healthTracker->recordSuccess($feedName, $state);

                $state['feed_cursors'][$feedName] = [
                    'last_poll' => date('c'),
                ];

                $this->logger->info('Feed poll complete', [
                    'feed' => $feedName,
                    'new_vulns' => count($batch),
                ]);

                $batches[] = $batch;
            } catch (\Throwable $e) {
                $this->healthTracker->recordFailure($feedName, $e->getMessage(), $state);
                $this->logger->error('Feed poll failed', [
                    'feed' => $feedName,
                    'error' => $e->getMessage(),
                ]);
            }
        }

        return $batches;
    }

    /**
     * @param array<string, Vulnerability> $vulns
     * @param array<string, mixed> $state
     * @return array<string, Vulnerability>
     */
    private function enrichWithEpss(array $vulns, array &$state): array
    {
        $cveIds = [];
        foreach ($vulns as $vuln) {
            if (str_starts_with($vuln->canonicalId, 'CVE-')) {
                $cveIds[] = $vuln->canonicalId;
            }
        }

        if ($cveIds === []) {
            return $vulns;
        }

        try {
            $enriched = $this->epss->enrichVulnerabilities($vulns);
            $this->healthTracker->recordSuccess('epss', $state);
            return $enriched;
        } catch (\Throwable $e) {
            $this->healthTracker->recordFailure('epss', $e->getMessage(), $state);
            $this->logger->error('EPSS enrichment failed', ['error' => $e->getMessage()]);
            return $vulns;
        }
    }

    /** @param VulnerabilityBatch[] $batches */
    private function allBatchesEmpty(array $batches): bool
    {
        foreach ($batches as $batch) {
            if (!$batch->isEmpty()) {
                return false;
            }
        }
        return true;
    }

    /** @param array<string, mixed> $state */
    private function finalize(array $state, bool $isFirstRun): void
    {
        // Weekly digest
        $lastDigest = $state['stats']['last_digest'] ?? null;
        if (!$isFirstRun && $this->digestReporter->shouldPostDigest($lastDigest)) {
            if ($this->digestReporter->postDigest($state)) {
                $state['stats']['last_digest'] = date('c');
            }
        }

        // Prune old records
        $state = $this->pruneOldRecords($state);

        // Save state
        $this->stateManager->save($state);

        // Write heartbeat
        $heartbeatPath = $this->config->heartbeatFilePath();
        $heartbeatDir = dirname($heartbeatPath);
        if (!is_dir($heartbeatDir)) {
            @mkdir($heartbeatDir, 0755, true);
        }
        file_put_contents($heartbeatPath, date('c'));

        $this->logger->info('A.S.E. run complete', [
            'tracked' => count($state['vulnerabilities'] ?? []),
        ]);
    }

    /**
     * @param array<string, mixed> $state
     * @return array<string, mixed>
     */
    private function pruneOldRecords(array $state): array
    {
        $cutoff = strtotime('-365 days');
        $pruned = 0;

        foreach ($state['vulnerabilities'] ?? [] as $id => $data) {
            $firstSeen = strtotime($data['first_seen'] ?? 'now');
            $notified = $data['notified_at_priority'] !== null;
            $inKev = $data['in_kev'] ?? false;
            $hasFixed = false;

            foreach ($data['affected_packages'] ?? [] as $pkg) {
                if (($pkg['fixed_version'] ?? null) !== null) {
                    $hasFixed = true;
                    break;
                }
            }

            if ($firstSeen < $cutoff && $notified && !$inKev && $hasFixed) {
                unset($state['vulnerabilities'][$id]);
                $pruned++;
            }
        }

        if ($pruned > 0) {
            $this->logger->info('Pruned old records', ['count' => $pruned]);
        }

        return $state;
    }
}
