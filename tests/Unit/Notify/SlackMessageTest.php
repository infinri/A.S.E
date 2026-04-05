<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Notify;

use Ase\Model\AffectedPackage;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;
use Ase\Notify\SlackMessage;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class SlackMessageTest extends TestCase
{
    #[Test]
    public function kevVulnHeadlineLeadsWithActivelyExploited(): void
    {
        $vuln = $this->makeVuln(inKev: true, priority: Priority::P0);

        $payload = SlackMessage::forVulnerability($vuln)->toPayload();
        $header = $payload['attachments'][0]['blocks'][0]['text']['text'];

        self::assertStringContainsString('Actively Exploited', $header);
    }

    #[Test]
    public function ransomwareVulnHeadlineLeadsWithRansomwareThreat(): void
    {
        $vuln = $this->makeVuln(knownRansomware: true, priority: Priority::P1);

        $payload = SlackMessage::forVulnerability($vuln)->toPayload();
        $header = $payload['attachments'][0]['blocks'][0]['text']['text'];

        self::assertStringContainsString('Ransomware Threat', $header);
    }

    #[Test]
    public function installedVersionVulnHeadlineLeadsWithYouAreVulnerable(): void
    {
        $vuln = $this->makeVuln(affectsInstalled: true, priority: Priority::P1);

        $payload = SlackMessage::forVulnerability($vuln)->toPayload();
        $header = $payload['attachments'][0]['blocks'][0]['text']['text'];

        self::assertStringContainsString('You Are Vulnerable', $header);
    }

    #[Test]
    public function escalationHeadlineShowsEscalated(): void
    {
        $vuln = $this->makeVuln(priority: Priority::P0)
            ->withNotifiedAtPriority(Priority::P2);

        $payload = SlackMessage::forVulnerability($vuln, isEscalation: true)->toPayload();
        $header = $payload['attachments'][0]['blocks'][0]['text']['text'];

        self::assertStringContainsString('ESCALATED', $header);
    }

    #[Test]
    public function genericVulnUsesUrgencyLabel(): void
    {
        $vuln = $this->makeVuln(priority: Priority::P2);

        $payload = SlackMessage::forVulnerability($vuln)->toPayload();
        $header = $payload['attachments'][0]['blocks'][0]['text']['text'];

        self::assertStringContainsString('Action Needed', $header);
    }

    #[Test]
    public function impactSectionShowsActiveExploitationWarning(): void
    {
        $vuln = $this->makeVuln(inKev: true);
        $allText = $this->extractAllText($vuln);

        self::assertStringContainsString('actively exploited in the wild', $allText);
    }

    #[Test]
    public function impactAlertsAppearBeforeDescription(): void
    {
        $vuln = $this->makeVuln(inKev: true);

        $payload = SlackMessage::forVulnerability($vuln)->toPayload();
        $blocks = $payload['attachments'][0]['blocks'];

        // Find the impact block (second block, after header)
        $impactText = $blocks[1]['text']['text'];

        // "actively exploited" should come before the CVE description text
        $exploitedPos = strpos($impactText, 'actively exploited');
        $descPos = strpos($impactText, 'A test vulnerability');
        self::assertNotFalse($exploitedPos);
        self::assertNotFalse($descPos);
        self::assertLessThan($descPos, $exploitedPos);
    }

    #[Test]
    public function impactSectionShowsInstalledVersionWarning(): void
    {
        $vuln = $this->makeVuln(affectsInstalled: true, affectedPackages: [
            new AffectedPackage('composer', 'vendor/lib', '>=1.0 <2.0', '2.0.0'),
        ]);
        $allText = $this->extractAllText($vuln);

        self::assertStringContainsString('Your installed version is vulnerable', $allText);
    }

    #[Test]
    public function deadlineBlockShowsConcreteUpgradeOverCisaBoilerplate(): void
    {
        $vuln = $this->makeVuln(
            kevRequiredAction: 'Apply mitigations per vendor instructions',
            kevDueDate: '2025-02-01',
            affectedPackages: [
                new AffectedPackage('composer', 'vendor/lib', '>=1.0 <2.0', '2.0.0'),
            ],
        );
        $allText = $this->extractAllText($vuln);

        // Concrete upgrade wins over CISA boilerplate
        self::assertStringContainsString('composer update vendor/lib', $allText);
        self::assertStringContainsString('2.0.0', $allText);
        // Deadline still shows
        self::assertStringContainsString('2025-02-01', $allText);
        self::assertStringContainsString('CISA mandate', $allText);
    }

    #[Test]
    public function deadlineBlockFallsToCisaWhenNoFixVersion(): void
    {
        $vuln = $this->makeVuln(
            kevRequiredAction: 'Apply mitigations per vendor instructions',
            kevDueDate: '2025-02-01',
        );
        $allText = $this->extractAllText($vuln);

        self::assertStringContainsString('Apply mitigations', $allText);
    }

    #[Test]
    public function deadlineBlockShowsConcreteUpgradeWhenNoKevAction(): void
    {
        $vuln = $this->makeVuln(affectedPackages: [
            new AffectedPackage('composer', 'vendor/lib', '>=1.0 <2.0', '2.0.0'),
        ]);
        $allText = $this->extractAllText($vuln);

        self::assertStringContainsString('composer update vendor/lib', $allText);
        self::assertStringContainsString('2.0.0', $allText);
    }

    #[Test]
    public function hasDividerBetweenTiers(): void
    {
        $vuln = $this->makeVuln(affectedPackages: [
            new AffectedPackage('composer', 'vendor/lib', '>=1.0 <2.0'),
        ]);

        $payload = SlackMessage::forVulnerability($vuln)->toPayload();
        $blocks = $payload['attachments'][0]['blocks'];

        $hasDivider = false;
        foreach ($blocks as $block) {
            if ($block['type'] === 'divider') {
                $hasDivider = true;
                break;
            }
        }
        self::assertTrue($hasDivider);
    }

    #[Test]
    public function engineeringTierShowsPackageDetails(): void
    {
        $vuln = $this->makeVuln(affectedPackages: [
            new AffectedPackage('composer', 'vendor/lib', '>=1.0 <2.0', '2.0.0'),
        ]);
        $allText = $this->extractAllText($vuln);

        self::assertStringContainsString('vendor/lib', $allText);
        self::assertStringContainsString('composer', $allText);
        self::assertStringContainsString('2.0.0', $allText);
    }

    #[Test]
    public function scoreContextShowsRawNumbers(): void
    {
        $vuln = $this->makeVuln(cvssScore: 9.8, epssScore: 0.941, inKev: true);

        $payload = SlackMessage::forVulnerability($vuln)->toPayload();
        $blocks = $payload['attachments'][0]['blocks'];

        $contextTexts = '';
        foreach ($blocks as $block) {
            if ($block['type'] === 'context') {
                foreach ($block['elements'] as $el) {
                    $contextTexts .= ' ' . $el['text'];
                }
            }
        }

        self::assertStringContainsString('CVSS 9.8/10', $contextTexts);
        self::assertStringContainsString('EPSS 94.1%', $contextTexts);
        self::assertStringContainsString('CISA KEV', $contextTexts);
    }

    #[Test]
    public function buttonsShowDomainNames(): void
    {
        $vuln = $this->makeVuln(references: [
            'https://github.com/advisories/GHSA-xxxx',
            'https://helpx.adobe.com/security/products/magento.html',
        ]);

        $payload = SlackMessage::forVulnerability($vuln)->toPayload();
        $blocks = $payload['attachments'][0]['blocks'];

        $buttonLabels = [];
        foreach ($blocks as $block) {
            if ($block['type'] === 'actions') {
                foreach ($block['elements'] as $btn) {
                    $buttonLabels[] = $btn['text']['text'];
                }
            }
        }

        self::assertContains('NVD', $buttonLabels);
        self::assertContains('GitHub', $buttonLabels);
        self::assertContains('Adobe', $buttonLabels);
    }

    #[Test]
    public function footerShowsSourcesAndBrand(): void
    {
        $vuln = $this->makeVuln(sources: ['nvd', 'kev']);

        $payload = SlackMessage::forVulnerability($vuln)->toPayload();
        $blocks = $payload['attachments'][0]['blocks'];

        $lastBlock = end($blocks);
        self::assertSame('context', $lastBlock['type']);
        self::assertStringContainsString('A.S.E.', $lastBlock['elements'][0]['text']);
        self::assertStringContainsString('nvd, kev', $lastBlock['elements'][0]['text']);
    }

    #[Test]
    public function digestCreatesListOfVulnerabilities(): void
    {
        $vulns = [
            $this->makeVuln(id: 'CVE-2025-0001', cvssScore: 9.8),
            $this->makeVuln(id: 'CVE-2025-0002', cvssScore: 7.0),
        ];

        $payload = SlackMessage::digest($vulns)->toPayload();
        $blocks = $payload['attachments'][0]['blocks'];

        self::assertStringContainsString('2 vulnerabilities', $blocks[0]['text']['text']);
        self::assertStringContainsString('CVE-2025-0001', $blocks[1]['text']['text']);
    }

    #[Test]
    public function digestTruncatesAt20(): void
    {
        $vulns = [];
        for ($i = 1; $i <= 25; $i++) {
            $vulns[] = $this->makeVuln(id: sprintf('CVE-2025-%04d', $i));
        }

        $payload = SlackMessage::digest($vulns)->toPayload();
        self::assertStringContainsString('and 5 more', $payload['attachments'][0]['blocks'][1]['text']['text']);
    }

    #[Test]
    public function toPayloadWithoutChannelOmitsChannelKey(): void
    {
        $payload = SlackMessage::forVulnerability($this->makeVuln())->toPayload();

        self::assertArrayNotHasKey('channel', $payload);
    }

    #[Test]
    public function toPayloadWithChannelIncludesIt(): void
    {
        $payload = SlackMessage::forVulnerability($this->makeVuln())->toPayload('#sec');

        self::assertSame('#sec', $payload['channel']);
    }

    private function extractAllText(Vulnerability $vuln): string
    {
        $payload = SlackMessage::forVulnerability($vuln)->toPayload();
        $blocks = $payload['attachments'][0]['blocks'];

        $text = '';
        foreach ($blocks as $block) {
            if (isset($block['text']['text'])) {
                $text .= ' ' . $block['text']['text'];
            }
            foreach ($block['elements'] ?? [] as $el) {
                if (isset($el['text'])) {
                    $text .= ' ' . (is_array($el['text']) ? $el['text']['text'] : $el['text']);
                }
            }
        }
        return $text;
    }

    private function makeVuln(
        string $id = 'CVE-2025-0001',
        ?float $cvssScore = null,
        ?float $epssScore = null,
        ?float $epssPercentile = null,
        bool $inKev = false,
        bool $knownRansomware = false,
        Priority $priority = Priority::P2,
        bool $affectsInstalled = false,
        array $sources = ['test'],
        array $affectedPackages = [],
        array $references = [],
        ?string $kevRequiredAction = null,
        ?string $kevDueDate = null,
    ): Vulnerability {
        return new Vulnerability(
            canonicalId: $id,
            aliases: [],
            description: 'A test vulnerability that allows remote code execution.',
            cvssScore: $cvssScore,
            cvssVector: null,
            epssScore: $epssScore,
            epssPercentile: $epssPercentile,
            inKev: $inKev,
            knownRansomware: $knownRansomware,
            affectedPackages: $affectedPackages,
            cwes: ['CWE-611'],
            references: $references,
            sources: $sources,
            firstSeen: '2025-01-01T00:00:00+00:00',
            lastUpdated: '2025-01-01T00:00:00+00:00',
            kevDateAdded: null,
            kevDueDate: $kevDueDate,
            kevRequiredAction: $kevRequiredAction,
            affectsInstalledVersion: $affectsInstalled,
            priority: $priority,
            notifiedAtPriority: null,
        );
    }
}
