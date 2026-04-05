<?php

declare(strict_types=1);

namespace Ase\Health;

use Psr\Log\LoggerInterface;

final class SchemaValidator
{
    public function __construct(
        private readonly LoggerInterface $logger,
    ) {}

    /** @param array<string, mixed> $data */
    public function validate(string $feed, array $data): bool
    {
        return match ($feed) {
            'kev' => $this->validateKev($data),
            'nvd' => $this->validateNvd($data),
            'ghsa' => $this->validateGhsa($data),
            'osv' => $this->validateOsv($data),
            'epss' => $this->validateEpss($data),
            'packagist' => $this->validatePackagist($data),
            default => true,
        };
    }

    /** @param array<string, mixed> $data */
    private function validateKev(array $data): bool
    {
        if (!isset($data['vulnerabilities']) || !is_array($data['vulnerabilities'])) {
            $this->logMissing('kev', 'vulnerabilities');
            return false;
        }

        if ($data['vulnerabilities'] === []) {
            $this->logMissing('kev', 'vulnerabilities (empty)');
            return false;
        }

        if (!isset($data['catalogVersion'])) {
            $this->logMissing('kev', 'catalogVersion');
            return false;
        }

        return true;
    }

    /** @param array<string, mixed> $data */
    private function validateNvd(array $data): bool
    {
        if (!isset($data['totalResults']) || !is_int($data['totalResults'])) {
            $this->logMissing('nvd', 'totalResults');
            return false;
        }

        if (!isset($data['vulnerabilities']) || !is_array($data['vulnerabilities'])) {
            $this->logMissing('nvd', 'vulnerabilities');
            return false;
        }

        return true;
    }

    /** @param array<string, mixed> $data */
    private function validateGhsa(array $data): bool
    {
        foreach ($data as $i => $entry) {
            if (!isset($entry['ghsa_id'])) {
                $this->logMissing('ghsa', "entry[{$i}].ghsa_id");
                return false;
            }
            if (!isset($entry['vulnerabilities']) || !is_array($entry['vulnerabilities'])) {
                $this->logMissing('ghsa', "entry[{$i}].vulnerabilities");
                return false;
            }
        }

        return true;
    }

    /** @param array<string, mixed> $data */
    private function validateOsv(array $data): bool
    {
        if (!isset($data['id'])) {
            $this->logMissing('osv', 'id');
            return false;
        }

        if (!isset($data['aliases']) || !is_array($data['aliases'])) {
            $this->logMissing('osv', 'aliases');
            return false;
        }

        return true;
    }

    /** @param array<string, mixed> $data */
    private function validateEpss(array $data): bool
    {
        if (($data['status'] ?? '') !== 'OK') {
            $this->logMissing('epss', 'status (expected OK)');
            return false;
        }

        if (!isset($data['data']) || !is_array($data['data'])) {
            $this->logMissing('epss', 'data');
            return false;
        }

        return true;
    }

    /** @param array<string, mixed> $data */
    private function validatePackagist(array $data): bool
    {
        if (!isset($data['advisories'])) {
            $this->logMissing('packagist', 'advisories');
            return false;
        }

        return true;
    }

    private function logMissing(string $feed, string $field): void
    {
        $this->logger->warning('Schema validation failed: missing or invalid field', [
            'feed' => $feed,
            'field' => $field,
        ]);
    }
}
