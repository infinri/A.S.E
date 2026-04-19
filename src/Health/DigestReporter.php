<?php

declare(strict_types=1);

namespace Ase\Health;

use Ase\Http\CurlClient;
use Ase\Config;
use Ase\Notify\SlackMessage;
use Psr\Log\LoggerInterface;

final class DigestReporter
{
    private const string DIGEST_DAY = 'Sunday';

    private bool $warnedNoWebhook = false;

    public function __construct(
        private readonly CurlClient $client,
        private readonly Config $config,
        private readonly LoggerInterface $logger,
    ) {}

    public function shouldPostDigest(?string $lastDigestDate): bool
    {
        if (date('l') !== self::DIGEST_DAY) {
            return false;
        }

        if ($lastDigestDate === null) {
            return true;
        }

        $lastDigest = strtotime($lastDigestDate);
        $daysSince = (time() - $lastDigest) / 86400;

        return $daysSince >= 6;
    }

    /** @param array<string, mixed> $state */
    public function postDigest(array $state): bool
    {
        $webhookUrl = $this->config->slackWebhookUrl();
        if ($webhookUrl === null) {
            if (!$this->warnedNoWebhook) {
                $this->logger->warning('Slack webhook not configured; skipping digest');
                $this->warnedNoWebhook = true;
            }
            return false;
        }

        $stats = $state['stats'] ?? [];
        $feedHealth = $state['feed_health'] ?? [];
        $vulnCount = count($state['vulnerabilities'] ?? []);

        $stateSize = strlen(json_encode($state, JSON_THROW_ON_ERROR));
        $stateSizeKb = round($stateSize / 1024, 1);

        $lines = [
            "*A.S.E. Weekly Digest*",
            "",
            "*Tracked vulnerabilities:* {$vulnCount}",
            "*Total notified:* " . ($stats['total_notified'] ?? 0),
            "*Total escalations:* " . ($stats['total_escalations'] ?? 0),
            "*State file size:* {$stateSizeKb} KB",
            "",
            "*Feed Health:*",
        ];

        foreach ($feedHealth as $feed => $health) {
            $status = ($health['consecutive_failures'] ?? 0) > 0
                ? "FAILING ({$health['consecutive_failures']} consecutive)"
                : "OK";
            $lastSuccess = $health['last_success'] ?? 'never';
            $lines[] = "  {$feed}: {$status} (last success: {$lastSuccess})";
        }

        $payload = [
            'channel' => $this->config->slackChannelAlerts(),
            'blocks' => [
                [
                    'type' => 'section',
                    'text' => ['type' => 'mrkdwn', 'text' => implode("\n", $lines)],
                ],
            ],
        ];

        $response = $this->client->post($webhookUrl, $payload);

        if (!$response->isOk()) {
            $this->logger->error('Failed to post weekly digest', [
                'status' => $response->statusCode,
            ]);
            return false;
        }

        $this->logger->info('Weekly digest posted');
        return true;
    }
}
