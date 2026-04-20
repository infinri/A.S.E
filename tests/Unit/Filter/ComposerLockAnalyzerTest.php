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
    private string $originalCwd;

    protected function setUp(): void
    {
        $this->originalCwd = getcwd() ?: sys_get_temp_dir();
        $this->tmpDir = sys_get_temp_dir() . '/ase_lock_test_' . uniqid();
        mkdir($this->tmpDir, 0755, true);
        // chdir into an empty sub-dir so Config::composerLockPath() walk-up
        // does not discover the ase project's own composer.lock.
        $cwdScratch = $this->tmpDir . '/cwd';
        mkdir($cwdScratch, 0755, true);
        chdir($cwdScratch);
    }

    protected function tearDown(): void
    {
        chdir($this->originalCwd);
        $cwdScratch = $this->tmpDir . '/cwd';
        @rmdir($cwdScratch);
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

    #[Test]
    public function testDetectMagentoEditionDetectsCommunity(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'magento/product-community-edition', 'version' => '2.4.7'],
        ]);

        $edition = $this->makeAnalyzer($lockPath)->detectMagentoEdition();

        self::assertNotNull($edition);
        self::assertSame('magento-community', $edition->edition);
        self::assertSame('2.4.7', $edition->version);
        self::assertSame('magento/product-community-edition', $edition->packageName);
    }

    #[Test]
    public function testDetectMagentoEditionDetectsEnterprise(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'magento/product-enterprise-edition', 'version' => '2.4.8'],
        ]);

        $edition = $this->makeAnalyzer($lockPath)->detectMagentoEdition();

        self::assertNotNull($edition);
        self::assertSame('magento-enterprise', $edition->edition);
        self::assertSame('2.4.8', $edition->version);
        self::assertSame('magento/product-enterprise-edition', $edition->packageName);
    }

    #[Test]
    public function testDetectMagentoEditionDetectsMageOs(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'mage-os/product-community-edition', 'version' => '1.0.0'],
        ]);

        $edition = $this->makeAnalyzer($lockPath)->detectMagentoEdition();

        self::assertNotNull($edition);
        self::assertSame('mage-os-community', $edition->edition);
        self::assertSame('1.0.0', $edition->version);
        self::assertSame('mage-os/product-community-edition', $edition->packageName);
    }

    #[Test]
    public function testDetectMagentoEditionPrefersEnterpriseWhenBothPresent(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'magento/product-community-edition', 'version' => '2.4.7'],
            ['name' => 'magento/product-enterprise-edition', 'version' => '2.4.8'],
        ]);

        $edition = $this->makeAnalyzer($lockPath)->detectMagentoEdition();

        self::assertNotNull($edition);
        self::assertSame('magento-enterprise', $edition->edition);
        self::assertSame('2.4.8', $edition->version);
    }

    #[Test]
    public function testDetectMagentoEditionReturnsNullWhenNotFound(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'monolog/monolog', 'version' => '3.0.0'],
        ]);

        self::assertNull($this->makeAnalyzer($lockPath)->detectMagentoEdition());
    }

    #[Test]
    public function testDetectMagentoEditionReturnsNullWhenNoLockPathConfigured(): void
    {
        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
        ]);

        $analyzer = new ComposerLockAnalyzer($config, new NullLogger());

        self::assertNull($analyzer->detectMagentoEdition());
    }

    #[Test]
    public function testDetectMagentoEditionStripsVPrefixFromVersion(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'magento/product-community-edition', 'version' => 'v2.4.7'],
        ]);

        $edition = $this->makeAnalyzer($lockPath)->detectMagentoEdition();

        self::assertNotNull($edition);
        self::assertSame('2.4.7', $edition->version);
    }

    #[Test]
    public function testDetectEcosystemsReturnsComposerWhenLockPresent(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'magento/framework', 'version' => '103.0.0'],
        ]);

        self::assertSame(['composer'], $this->makeAnalyzer($lockPath)->detectEcosystems());
    }

    #[Test]
    public function testDetectEcosystemsReturnsEmptyWhenNoLock(): void
    {
        $config = ConfigTestHelper::create([
            'SLACK_WEBHOOK_URL' => 'https://hooks.slack.com/test',
        ]);

        self::assertSame([], (new ComposerLockAnalyzer($config, new NullLogger()))->detectEcosystems());
    }

    #[Test]
    public function testDetectVendorsReturnsUniqueVendorPrefixes(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'magento/framework', 'version' => '103.0.0'],
            ['name' => 'magento/module-catalog', 'version' => '104.0.0'],
            ['name' => 'amasty/shipping', 'version' => '1.2.3'],
        ]);

        $vendors = $this->makeAnalyzer($lockPath)->detectVendors();
        sort($vendors);

        self::assertSame(['amasty', 'magento'], $vendors);
    }

    #[Test]
    public function testDetectVendorsSkipsPackagesWithoutSlash(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'weirdname', 'version' => '1.0.0'],
            ['name' => 'magento/framework', 'version' => '103.0.0'],
        ]);

        self::assertSame(['magento'], $this->makeAnalyzer($lockPath)->detectVendors());
    }

    #[Test]
    public function testDetectCpePrefixMapsCommunityToMagento(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'magento/product-community-edition', 'version' => '2.4.7'],
        ]);

        self::assertSame(
            'cpe:2.3:a:magento:magento',
            $this->makeAnalyzer($lockPath)->detectCpePrefix(),
        );
    }

    #[Test]
    public function testDetectCpePrefixMapsEnterpriseToAdobe(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'magento/product-enterprise-edition', 'version' => '2.4.7'],
        ]);

        self::assertSame(
            'cpe:2.3:a:adobe:commerce',
            $this->makeAnalyzer($lockPath)->detectCpePrefix(),
        );
    }

    #[Test]
    public function testDetectCpePrefixReturnsNullForMageOs(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'mage-os/product-community-edition', 'version' => '1.0.0'],
        ]);

        self::assertNull($this->makeAnalyzer($lockPath)->detectCpePrefix());
    }

    #[Test]
    public function testDetectCpePrefixReturnsNullWhenNoMagentoEdition(): void
    {
        $lockPath = $this->writeLockFile([
            ['name' => 'monolog/monolog', 'version' => '3.0.0'],
        ]);

        self::assertNull($this->makeAnalyzer($lockPath)->detectCpePrefix());
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
            priority: Priority::P1,
            notifiedAtPriority: null,
        );
    }
}
