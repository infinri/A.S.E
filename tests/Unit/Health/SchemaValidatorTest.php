<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Health;

use Ase\Health\SchemaValidator;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class SchemaValidatorTest extends TestCase
{
    private SchemaValidator $validator;

    protected function setUp(): void
    {
        $this->validator = new SchemaValidator(new NullLogger());
    }

    // --- KEV ---

    #[Test]
    public function kevValidWithRequiredFields(): void
    {
        self::assertTrue($this->validator->validate('kev', [
            'vulnerabilities' => [['cveID' => 'CVE-2025-0001']],
            'catalogVersion' => '2025.01.01',
        ]));
    }

    #[Test]
    public function kevInvalidWithoutVulnerabilities(): void
    {
        self::assertFalse($this->validator->validate('kev', ['catalogVersion' => '1']));
    }

    #[Test]
    public function kevInvalidWithEmptyVulnerabilities(): void
    {
        self::assertFalse($this->validator->validate('kev', [
            'vulnerabilities' => [],
            'catalogVersion' => '1',
        ]));
    }

    #[Test]
    public function kevInvalidWithoutCatalogVersion(): void
    {
        self::assertFalse($this->validator->validate('kev', [
            'vulnerabilities' => [['cveID' => 'CVE-2025-0001']],
        ]));
    }

    // --- NVD ---

    #[Test]
    public function nvdValidWithRequiredFields(): void
    {
        self::assertTrue($this->validator->validate('nvd', [
            'totalResults' => 1,
            'vulnerabilities' => [['cve' => []]],
        ]));
    }

    #[Test]
    public function nvdInvalidWithoutTotalResults(): void
    {
        self::assertFalse($this->validator->validate('nvd', [
            'vulnerabilities' => [],
        ]));
    }

    #[Test]
    public function nvdInvalidWithStringTotalResults(): void
    {
        self::assertFalse($this->validator->validate('nvd', [
            'totalResults' => '1',
            'vulnerabilities' => [],
        ]));
    }

    // --- GHSA ---

    #[Test]
    public function ghsaValidWithProperEntries(): void
    {
        self::assertTrue($this->validator->validate('ghsa', [
            ['ghsa_id' => 'GHSA-xxxx', 'vulnerabilities' => []],
        ]));
    }

    #[Test]
    public function ghsaValidWhenEmpty(): void
    {
        self::assertTrue($this->validator->validate('ghsa', []));
    }

    #[Test]
    public function ghsaInvalidWithoutGhsaId(): void
    {
        self::assertFalse($this->validator->validate('ghsa', [
            ['vulnerabilities' => []],
        ]));
    }

    #[Test]
    public function ghsaInvalidWithoutVulnerabilities(): void
    {
        self::assertFalse($this->validator->validate('ghsa', [
            ['ghsa_id' => 'GHSA-xxxx'],
        ]));
    }

    // --- OSV ---

    #[Test]
    public function osvValidWithRequiredFields(): void
    {
        self::assertTrue($this->validator->validate('osv', [
            'id' => 'PYSEC-2025-001',
            'aliases' => ['CVE-2025-0001'],
        ]));
    }

    #[Test]
    public function osvInvalidWithoutId(): void
    {
        self::assertFalse($this->validator->validate('osv', [
            'aliases' => [],
        ]));
    }

    // --- EPSS ---

    #[Test]
    public function epssValidWithOkStatus(): void
    {
        self::assertTrue($this->validator->validate('epss', [
            'status' => 'OK',
            'data' => [['cve' => 'CVE-2025-0001']],
        ]));
    }

    #[Test]
    public function epssInvalidWithWrongStatus(): void
    {
        self::assertFalse($this->validator->validate('epss', [
            'status' => 'ERROR',
            'data' => [],
        ]));
    }

    // --- Packagist ---

    #[Test]
    public function packagistValidWithAdvisories(): void
    {
        self::assertTrue($this->validator->validate('packagist', [
            'advisories' => [],
        ]));
    }

    #[Test]
    public function packagistInvalidWithoutAdvisories(): void
    {
        self::assertFalse($this->validator->validate('packagist', []));
    }

    // --- Unknown feed ---

    #[Test]
    public function unknownFeedPassesValidation(): void
    {
        self::assertTrue($this->validator->validate('unknown_feed', ['anything' => true]));
    }
}