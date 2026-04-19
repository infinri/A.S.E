<?php

declare(strict_types=1);

namespace Ase\Notify;

use Ase\Config;
use Ase\Http\CurlClient;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;
use Psr\Log\LoggerInterface;

class SlackNotifier
{
    private const float THROTTLE_SECONDS = 1.5;

    private bool $warnedNoWebhook = false;

    public function __construct(
        private readonly CurlClient $client,
        private readonly Config $config,
        private readonly LoggerInterface $logger,
    ) {}

    /**
     * @param Vulnerability[] $newAlerts
     * @param Vulnerability[] $escalations
     */
    public function sendAlerts(array $newAlerts, array $escalations = []): int
    {
        $sent = 0;

        // P0 and P1: individual messages to critical channel (skipped if channel not configured)
        $criticalChannel = $this->config->slackChannelCritical();
        if ($criticalChannel !== null) {
            foreach ($this->filterByPriority($newAlerts, Priority::P0, Priority::P1) as $vuln) {
                if ($this->sendMessage(
                    SlackMessage::forVulnerability($vuln),
                    $criticalChannel,
                )) {
                    $sent++;
                }
                usleep((int) (self::THROTTLE_SECONDS * 1_000_000));
            }

            // Escalations: individual messages to critical channel
            foreach ($escalations as $vuln) {
                if ($this->sendMessage(
                    SlackMessage::forVulnerability($vuln, isEscalation: true),
                    $criticalChannel,
                )) {
                    $sent++;
                }
                usleep((int) (self::THROTTLE_SECONDS * 1_000_000));
            }
        }

        // P2: batched digest to alerts channel (skipped if channel not configured)
        $alertsChannel = $this->config->slackChannelAlerts();
        if ($alertsChannel !== null) {
            $p2Alerts = $this->filterByPriority($newAlerts, Priority::P2);
            if ($p2Alerts !== []) {
                if ($this->sendMessage(
                    SlackMessage::digest($p2Alerts),
                    $alertsChannel,
                )) {
                    $sent++;
                }
            }
        }

        return $sent;
    }

    /** @param array<string, mixed> $stats */
    public function sendWeeklyDigest(array $stats): bool
    {
        $msg = new SlackMessage();
        // Build a simple stats message - the DigestReporter handles the content
        return $this->sendMessage($msg, $this->config->slackChannelAlerts());
    }

    private function sendMessage(SlackMessage $message, ?string $channel): bool
    {
        $webhookUrl = $this->config->slackWebhookUrl();
        if ($webhookUrl === null) {
            if (!$this->warnedNoWebhook) {
                $this->logger->warning('Slack webhook not configured; skipping message');
                $this->warnedNoWebhook = true;
            }
            return false;
        }

        $payload = $message->toPayload($channel);
        $response = $this->client->post($webhookUrl, $payload);

        if (!$response->isOk() || $response->body !== 'ok') {
            $this->logger->error('Slack notification failed', [
                'status' => $response->statusCode,
                'body' => mb_substr($response->body, 0, 200),
                'channel' => $channel,
            ]);
            return false;
        }

        $this->logger->info('Slack notification sent', ['channel' => $channel]);
        return true;
    }

    /**
     * @param Vulnerability[] $vulns
     * @return Vulnerability[]
     */
    private function filterByPriority(array $vulns, Priority ...$priorities): array
    {
        return array_values(array_filter(
            $vulns,
            static fn(Vulnerability $v): bool => in_array($v->priority, $priorities, true),
        ));
    }
}
