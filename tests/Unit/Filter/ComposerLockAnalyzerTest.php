<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Filter;

use Ase\Filter\ComposerLockAnalyzer;
use Ase\Model\AffectedPackage;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;
use Ase\Tests\Unit\ConfigTestHelper;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class ComposerLockAnalyzerTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/ase_lock_test_' . uniqid();
        mkdir($this->tmpDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $files = glob($this->tmpDir . '/*');
        if ($files !== false) {
            array_map('unlink', $files);
        }
        @rmdir($this->tmpDir);
    }

    #[Test]
    public function returnsUnchangedWhenNoLockPathConfigured(): void
    {
        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
        ]);

        $analyzer = new ComposerLockAnalyzer($config, new NullLogger());
        $vulns = ['CVE-1' => $this->makeVuln('CVE-1')];

        $result = $analyzer->checkInstalledVersions($vulns);

        self::assertFalse($result['CVE-1']->affectsInstalledVersion);
    }

    #[Test]
    public function flagsVulnerableInstalledPackage(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'monolog/monolog', 'version' => '2.9.0'],
        ]);

        $analyzer = $this->makeAnalyzer($lockPath);

        $vuln = $this->makeVuln('CVE-1', [
            new AffectedPackage('composer', 'monolog/monolog', '>=2.0 <2.10.0', '2.10.0'),
        ]);

        $result = $analyzer->checkInstalledVersions(['CVE-1' => $vuln]);

        self::assertTrue($result['CVE-1']->affectsInstalledVersion);
    }

    #[Test]
    public function doesNotFlagNonVulnerableVersion(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'monolog/monolog', 'version' => '3.0.0'],
        ]);

        $analyzer = $this->makeAnalyzer($lockPath);

        $vuln = $this->makeVuln('CVE-1', [
            new AffectedPackage('composer', 'monolog/monolog', '>=2.0 <2.10.0', '2.10.0'),
        ]);

        $result = $analyzer->checkInstalledVersions(['CVE-1' => $vuln]);

        self::assertFalse($result['CVE-1']->affectsInstalledVersion);
    }

    #[Test]
    public function ignoresNonComposerEcosystems(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'lodash', 'version' => '4.17.0'],
        ]);

        $analyzer = $this->makeAnalyzer($lockPath);

        $vuln = $this->makeVuln('CVE-1', [
            new AffectedPackage('npm', 'lodash', '<4.17.21'),
        ]);

        $result = $analyzer->checkInstalledVersions(['CVE-1' => $vuln]);

        self::assertFalse($result['CVE-1']->affectsInstalledVersion);
    }

    #[Test]
    public function ignoresPackagesNotInstalled(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'other/package', 'version' => '1.0.0'],
        ]);

        $analyzer = $this->makeAnalyzer($lockPath);

        $vuln = $this->makeVuln('CVE-1', [
            new AffectedPackage('composer', 'monolog/monolog', '>=2.0 <2.10.0'),
        ]);

        $result = $analyzer->checkInstalledVersions(['CVE-1' => $vuln]);

        self::assertFalse($result['CVE-1']->affectsInstalledVersion);
    }

    #[Test]
    public function handlesDevPackages(): void
    {
        $lockPath = $this->writeLockFile([], [
            ['name' => 'phpunit/phpunit', 'version' => 'v10.0.0'],
        ]);

        $analyzer = $this->makeAnalyzer($lockPath);

        $vuln = $this->makeVuln('CVE-1', [
            new AffectedPackage('composer', 'phpunit/phpunit', '>=10.0 <10.5.0', '10.5.0'),
        ]);

        $result = $analyzer->checkInstalledVersions(['CVE-1' => $vuln]);

        self::assertTrue($result['CVE-1']->affectsInstalledVersion);
    }

    #[Test]
    public function handlesMissingLockFile(): void
    {
        $analyzer = $this->makeAnalyzer('/nonexistent/composer.lock');
        $vuln = $this->makeVuln('CVE-1');

        $result = $analyzer->checkInstalledVersions(['CVE-1' => $vuln]);

        self::assertFalse($result['CVE-1']->affectsInstalledVersion);
    }

    #[Test]
    public function stripsVPrefixFromVersion(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'vendor/lib', 'version' => 'v1.5.0'],
        ]);

        $analyzer = $this->makeAnalyzer($lockPath);

        $vuln = $this->makeVuln('CVE-1', [
            new AffectedPackage('composer', 'vendor/lib', '>=1.0 <2.0'),
        ]);

        $result = $analyzer->checkInstalledVersions(['CVE-1' => $vuln]);

        self::assertTrue($result['CVE-1']->affectsInstalledVersion);
    }

    private function makeAnalyzer(string $lockPath): ComposerLockAnalyzer
    {
        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
            'COMPOSER_LOCK_PATH' => $lockPath,
        ]);

        return new ComposerLockAnalyzer($config, new NullLogger());
    }

    private function writeLockFile(array $packages = [], array $packagesDev = []): string
    {
        $path = $this->tmpDir . '/composer.lock';
        $lock = [
            'packages' => $packages,
            'packages-dev' => $packagesDev,
        ];
        file_put_contents($path, json_encode($lock, JSON_THROW_ON_ERROR));
        return $path;
    }

    private function makeVuln(string $id, array $affectedPackages = []): Vulnerability
    {
        return new Vulnerability(
            canonicalId: $id,
            aliases: [],
            description: 'Test',
            cvssScore: null,
            cvssVector: null,
            epssScore: null,
            epssPercentile: null,
            inKev: false,
            knownRansomware: false,
            affectedPackages: $affectedPackages,
            cwes: [],
            references: [],
            sources: ['test'],
            firstSeen: '2025-01-01T00:00:00+00:00',
            lastUpdated: '2025-01-01T00:00:00+00:00',
            kevDateAdded: null,
            kevDueDate: null,
            kevRequiredAction: null,
            affectsInstalledVersion: false,
            priority: Priority::P4,
            notifiedAtPriority: null,
        );
    }
}
