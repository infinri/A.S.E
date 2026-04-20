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
    private bool $warnedNoP1Webhook = false;

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

        $p0New = $this->filterByPriority($newAlerts, Priority::P0);
        $p1New = $this->filterByPriority($newAlerts, Priority::P1);
        $p0Escalations = $this->filterByPriority($escalations, Priority::P0);
        $p1Escalations = $this->filterByPriority($escalations, Priority::P1);

        $p0Webhook = $this->config->slackWebhookUrl();
        foreach ($p0New as $vuln) {
            if ($this->postToWebhook($p0Webhook, SlackMessage::forVulnerability($vuln), 'P0')) {
                $sent++;
            }
            usleep((int) (self::THROTTLE_SECONDS * 1_000_000));
        }
        foreach ($p0Escalations as $vuln) {
            if ($this->postToWebhook($p0Webhook, SlackMessage::forVulnerability($vuln, isEscalation: true), 'P0')) {
                $sent++;
            }
            usleep((int) (self::THROTTLE_SECONDS * 1_000_000));
        }

        $p1Webhook = $this->config->slackWebhookP1();
        $p1Count = count($p1New) + count($p1Escalations);
        if ($p1Webhook === null) {
            if ($p1Count > 0 && !$this->warnedNoP1Webhook) {
                $this->logger->warning('P1 findings present but SLACK_WEBHOOK_P1 not configured; skipping alerts', [
                    'skipped' => $p1Count,
                ]);
                $this->warnedNoP1Webhook = true;
            }
            return $sent;
        }

        foreach ($p1New as $vuln) {
            if ($this->postToWebhook($p1Webhook, SlackMessage::forVulnerability($vuln), 'P1')) {
                $sent++;
            }
            usleep((int) (self::THROTTLE_SECONDS * 1_000_000));
        }
        foreach ($p1Escalations as $vuln) {
            if ($this->postToWebhook($p1Webhook, SlackMessage::forVulnerability($vuln, isEscalation: true), 'P1')) {
                $sent++;
            }
            usleep((int) (self::THROTTLE_SECONDS * 1_000_000));
        }

        return $sent;
    }

    private function postToWebhook(?string $webhookUrl, SlackMessage $message, string $tier): bool
    {
        if ($webhookUrl === null) {
            if (!$this->warnedNoWebhook) {
                $this->logger->warning('Slack webhook not configured; skipping message');
                $this->warnedNoWebhook = true;
            }
            return false;
        }

        $payload = $message->toPayload();
        $response = $this->client->post($webhookUrl, $payload);

        if (!$response->isOk() || $response->body !== 'ok') {
            $this->logger->error('Slack notification failed', [
                'status' => $response->statusCode,
                'body' => mb_substr($response->body, 0, 200),
                'tier' => $tier,
            ]);
            return false;
        }

        $this->logger->info('Slack notification sent', ['tier' => $tier]);
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
            static fn (Vulnerability $v): bool => in_array($v->priority, $priorities, true),
        ));
    }
}
