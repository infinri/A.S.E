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

        $skipDotenv = getenv('ASE_SKIP_DOTENV');
        if ($skipDotenv === false || $skipDotenv === '' || $skipDotenv === '0') {
            if (file_exists($path . '/.env')) {
                $dotenv = Dotenv::createImmutable($path);
                $dotenv->load();
            }
        }

        $this->env = $_ENV;
    }

    /** @return string[] */
    public function enabledFeeds(): array
    {
        $feeds = $this->get('ENABLED_FEEDS', 'kev,nvd,ghsa,packagist');
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

    public function slackWebhookUrl(): ?string
    {
        return $this->getOptional('SLACK_WEBHOOK_URL');
    }

    public function slackWebhookP1(): ?string
    {
        return $this->getOptional('SLACK_WEBHOOK_P1');
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

    public function logFileLevel(): int
    {
        $raw = strtoupper($this->get('LOG_FILE_LEVEL', 'INFO'));
        return match ($raw) {
            'DEBUG' => \Monolog\Level::Debug->value,
            'INFO' => \Monolog\Level::Info->value,
            'NOTICE' => \Monolog\Level::Notice->value,
            'WARNING' => \Monolog\Level::Warning->value,
            'ERROR' => \Monolog\Level::Error->value,
            'CRITICAL' => \Monolog\Level::Critical->value,
            'ALERT' => \Monolog\Level::Alert->value,
            'EMERGENCY' => \Monolog\Level::Emergency->value,
            default => throw new \InvalidArgumentException("Unknown LOG_FILE_LEVEL: {$raw}"),
        };
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

    public function dtrackUrl(): string
    {
        $url = $this->getOptional('DTRACK_URL');
        if ($url === null) {
            throw new \RuntimeException('DTRACK_URL is required for Dependency-Track sync but is not set.');
        }
        return rtrim($url, '/');
    }

    public function dtrackApiKey(): string
    {
        $key = $this->getOptional('DTRACK_API_KEY');
        if ($key === null) {
            throw new \RuntimeException('DTRACK_API_KEY is required for Dependency-Track sync but is not set.');
        }
        return $key;
    }

    /** @return array<string, string> project name => lockfile path */
    public function projects(): array
    {
        $spec = $this->getOptional('ASE_PROJECTS');
        if ($spec === null) {
            throw new \RuntimeException('ASE_PROJECTS is required: comma-separated name:path entries.');
        }

        $projects = [];
        foreach (explode(',', $spec) as $entry) {
            $entry = trim($entry);
            if (!str_contains($entry, ':')) {
                throw new \RuntimeException(
                    "ASE_PROJECTS entry \"{$entry}\" is malformed: expected name:/absolute/path/to/lockfile."
                );
            }
            [$name, $path] = explode(':', $entry, 2);
            $projects[trim($name)] = trim($path);
        }
        return $projects;
    }

    /** @return array<string, string> project tag => Slack webhook URL */
    public function alertRoutes(): array
    {
        $spec = $this->getOptional('ASE_ALERT_ROUTES');
        if ($spec === null) {
            return [];
        }

        $routes = [];
        foreach (explode(',', $spec) as $entry) {
            $entry = trim($entry);
            if (!str_contains($entry, '=')) {
                throw new \RuntimeException(
                    "ASE_ALERT_ROUTES entry \"{$entry}\" is malformed: expected tag=webhook-url."
                );
            }
            [$tag, $url] = explode('=', $entry, 2);
            $routes[trim($tag)] = trim($url);
        }
        return $routes;
    }

    public function alertDefaultWebhook(): ?string
    {
        return $this->getOptional('ASE_ALERT_DEFAULT_WEBHOOK');
    }

    public function alertCursorPath(): string
    {
        return $this->get('ASE_ALERT_CURSOR_PATH', dirname(__DIR__) . '/var/state/alert-cursor.json');
    }

    public function epssHighThreshold(): float
    {
        return (float) $this->get('EPSS_HIGH_THRESHOLD', '0.10');
    }

    public function cvssCriticalThreshold(): float
    {
        return (float) $this->get('CVSS_CRITICAL_THRESHOLD', '9.0');
    }

    public function cvssHighThreshold(): float
    {
        return (float) $this->get('CVSS_HIGH_THRESHOLD', '7.0');
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
        if (isset($this->env[$key])) {
            return $this->env[$key];
        }
        if (isset($_ENV[$key])) {
            return $_ENV[$key];
        }
        $envValue = getenv($key);
        if ($envValue !== false) {
            return $envValue;
        }
        return $default;
    }

    private function getOptional(string $key): ?string
    {
        $value = $this->env[$key] ?? $_ENV[$key] ?? null;
        if ($value === null) {
            $envValue = getenv($key);
            $value = $envValue === false ? null : $envValue;
        }
        if ($value === null || $value === '') {
            return null;
        }

        return trim($value);
    }
}
