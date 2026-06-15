<?php

declare(strict_types=1);

namespace Ase;

use Dotenv\Dotenv;

final class Config
{
    /** @var array<string, string> */
    private readonly array $env;

    public function __construct(?string $envPath = null)
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

    public function inventoryPath(): ?string
    {
        $explicit = $this->getOptional('ASE_INVENTORY_PATH');
        if ($explicit !== null) {
            return $explicit;
        }
        $default = dirname(__DIR__) . '/inventory/declared-tech.yaml';
        return is_file($default) ? $default : null;
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
