<?php

declare(strict_types=1);

namespace Ase;

use Dotenv\Dotenv;

final class Config
{
    /** @var array<string, string> */
    private readonly array $env;

    public function __construct(?string $envPath = null, private readonly ?string $sinceDate = null)
    {
        $path = $envPath ?? dirname(__DIR__);

        if (file_exists($path . '/.env')) {
            $dotenv = Dotenv::createImmutable($path);
            $dotenv->load();
        }

        $this->env = $_ENV;
    }

    /** @return string[] */
    public function enabledFeeds(): array
    {
        $feeds = $this->get('ENABLED_FEEDS', 'kev,nvd,ghsa,osv,packagist');
        return array_map('trim', explode(',', $feeds));
    }

    public function isFeedEnabled(string $feed): bool
    {
        return in_array($feed, $this->enabledFeeds(), true);
    }

    public function nvdApiKey(): ?string
    {
        return $this->getOptional('NVD_API_KEY');
    }

    public function githubToken(): ?string
    {
        return $this->getOptional('GITHUB_TOKEN');
    }

    public function slackWebhookUrl(): string
    {
        return $this->get('SLACK_WEBHOOK_URL');
    }

    public function slackChannelCritical(): string
    {
        return $this->get('SLACK_CHANNEL_CRITICAL', '#security-critical');
    }

    public function slackChannelAlerts(): string
    {
        return $this->get('SLACK_CHANNEL_ALERTS', '#security-alerts');
    }

    public function pollInterval(string $feed): int
    {
        $key = 'POLL_INTERVAL_' . strtoupper($feed);
        return (int) $this->get($key, '7200');
    }

    /** @return string[] */
    public function ecosystems(): array
    {
        $value = $this->get('ECOSYSTEMS', 'composer,npm');
        return array_map('trim', explode(',', $value));
    }

    /** @return string[] */
    public function vendorFilter(): array
    {
        $value = $this->get('VENDOR_FILTER', 'adobe,magento');
        return array_map('trim', explode(',', $value));
    }

    public function nvdCpePrefix(): ?string
    {
        return $this->getOptional('NVD_CPE_PREFIX');
    }

    public function stateFilePath(): string
    {
        return $this->get('STATE_FILE', '/var/lib/ase/state.json');
    }

    public function logFilePath(): string
    {
        return $this->get('LOG_FILE', '/var/log/ase/ase.log');
    }

    public function heartbeatFilePath(): string
    {
        return $this->get('HEARTBEAT_FILE', '/var/run/ase/last_success.txt');
    }

    public function composerLockPath(): ?string
    {
        return $this->getOptional('COMPOSER_LOCK_PATH');
    }

    public function epssHighThreshold(): float
    {
        return (float) $this->get('EPSS_HIGH_THRESHOLD', '0.10');
    }

    public function epssMediumThreshold(): float
    {
        return (float) $this->get('EPSS_MEDIUM_THRESHOLD', '0.05');
    }

    public function cvssCriticalThreshold(): float
    {
        return (float) $this->get('CVSS_CRITICAL_THRESHOLD', '9.0');
    }

    public function cvssHighThreshold(): float
    {
        return (float) $this->get('CVSS_HIGH_THRESHOLD', '7.0');
    }

    public function cvssMediumThreshold(): float
    {
        return (float) $this->get('CVSS_MEDIUM_THRESHOLD', '4.0');
    }

    public function sinceDate(): ?string
    {
        return $this->sinceDate;
    }

    public function backfillDays(): int
    {
        return (int) $this->get('BACKFILL_DAYS', '30');
    }

    private function get(string $key, string $default = ''): string
    {
        return $this->env[$key] ?? $_ENV[$key] ?? $default;
    }

    private function getOptional(string $key): ?string
    {
        $value = $this->env[$key] ?? $_ENV[$key] ?? null;
        return ($value !== null && $value !== '') ? $value : null;
    }
}
