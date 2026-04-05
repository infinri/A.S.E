<?php

declare(strict_types=1);

namespace Ase\Notify;

use Ase\Model\Priority;
use Ase\Model\Vulnerability;

final class SlackMessage
{
    /** @var array<int, array<string, mixed>> */
    private array $blocks = [];
    private ?string $color = null;

    public static function forVulnerability(Vulnerability $vuln, bool $isEscalation = false): self
    {
        $msg = new self();
        $msg->color = $vuln->priority->slackColor();

        // ── TOP TIER: everyone reads this in 5 seconds ──

        // Headline: the scariest fact first
        $headline = self::buildHeadline($vuln, $isEscalation);
        $msg->blocks[] = [
            'type' => 'header',
            'text' => [
                'type' => 'plain_text',
                'text' => mb_substr($headline, 0, 150),
            ],
        ];

        // Impact statement: plain English, what can an attacker do
        $impact = self::buildImpactSummary($vuln);
        if ($impact !== '') {
            $msg->blocks[] = [
                'type' => 'section',
                'text' => ['type' => 'mrkdwn', 'text' => $impact],
            ];
        }

        // Deadline and status
        $deadlineText = self::buildDeadlineBlock($vuln);
        if ($deadlineText !== '') {
            $msg->blocks[] = [
                'type' => 'section',
                'text' => ['type' => 'mrkdwn', 'text' => $deadlineText],
            ];
        }

        // Divider between leadership tier and engineering tier
        $msg->blocks[] = ['type' => 'divider'];

        // ── BOTTOM TIER: engineering details ──

        // Affected packages with upgrade path
        $pkgText = self::buildPackageBlock($vuln);
        if ($pkgText !== '') {
            $msg->blocks[] = [
                'type' => 'section',
                'text' => ['type' => 'mrkdwn', 'text' => $pkgText],
            ];
        }

        // Scores for engineers who want the raw numbers
        $scoreText = self::buildScoreBlock($vuln);
        if ($scoreText !== '') {
            $msg->blocks[] = [
                'type' => 'context',
                'elements' => [['type' => 'mrkdwn', 'text' => $scoreText]],
            ];
        }

        // Buttons
        $buttons = self::buildButtons($vuln);
        if ($buttons !== []) {
            $msg->blocks[] = ['type' => 'actions', 'elements' => array_slice($buttons, 0, 5)];
        }

        // Footer
        $msg->blocks[] = [
            'type' => 'context',
            'elements' => [
                ['type' => 'mrkdwn', 'text' => self::buildFooter($vuln)],
            ],
        ];

        return $msg;
    }

    /** @param Vulnerability[] $vulns */
    public static function digest(array $vulns): self
    {
        $msg = new self();
        $msg->color = Priority::P2->slackColor();

        $msg->blocks[] = [
            'type' => 'header',
            'text' => ['type' => 'plain_text', 'text' => sprintf('Security Digest: %d vulnerabilities need attention', count($vulns))],
        ];

        $lines = [];
        foreach (array_slice($vulns, 0, 20) as $v) {
            $cvss = $v->cvssScore !== null ? sprintf('%.1f', $v->cvssScore) : '?';
            $pkg = $v->affectedPackages !== [] ? $v->affectedPackages[0]->name : 'unknown';
            $lines[] = "`{$v->canonicalId}` | Severity {$cvss}/10 | {$pkg}";
        }

        if (count($vulns) > 20) {
            $lines[] = sprintf('_...and %d more_', count($vulns) - 20);
        }

        $msg->blocks[] = [
            'type' => 'section',
            'text' => ['type' => 'mrkdwn', 'text' => implode("\n", $lines)],
        ];

        return $msg;
    }

    /** @return array<string, mixed> */
    public function toPayload(?string $channel = null): array
    {
        $payload = [];

        if ($channel !== null) {
            $payload['channel'] = $channel;
        }

        if ($this->color !== null) {
            $payload['attachments'] = [
                ['color' => $this->color, 'blocks' => $this->blocks],
            ];
        } else {
            $payload['blocks'] = $this->blocks;
        }

        return $payload;
    }

    private static function buildHeadline(Vulnerability $vuln, bool $isEscalation): string
    {
        // Lead with the scariest fact, not the CVE number
        if ($isEscalation) {
            return "ESCALATED: {$vuln->canonicalId}";
        }

        if ($vuln->inKev) {
            return "Actively Exploited: {$vuln->canonicalId}";
        }

        if ($vuln->knownRansomware) {
            return "Ransomware Threat: {$vuln->canonicalId}";
        }

        if ($vuln->affectsInstalledVersion) {
            return "You Are Vulnerable: {$vuln->canonicalId}";
        }

        $urgency = match ($vuln->priority) {
            Priority::P0 => 'CRITICAL',
            Priority::P1 => 'URGENT',
            Priority::P2 => 'Action Needed',
            Priority::P3 => 'Monitor',
            Priority::P4 => 'Low Risk',
        };

        return "{$urgency}: {$vuln->canonicalId}";
    }

    private static function buildImpactSummary(Vulnerability $vuln): string
    {
        $lines = [];

        // Lead with the scariest facts -- this is what leadership reads
        if ($vuln->inKev) {
            $lines[] = "This vulnerability is being *actively exploited in the wild* right now.";
        }

        if ($vuln->knownRansomware) {
            $lines[] = "This vulnerability is *used in known ransomware campaigns*.";
        }

        if ($vuln->affectsInstalledVersion) {
            $lines[] = "*Your installed version is vulnerable.* Immediate action required.";
        }

        // Technical description below the alerts
        if ($vuln->description !== '') {
            if ($lines !== []) {
                $lines[] = '';
            }
            $lines[] = $vuln->description;
        }

        return implode("\n", $lines);
    }

    private static function buildDeadlineBlock(Vulnerability $vuln): string
    {
        $parts = [];

        // Prefer concrete upgrade path over generic CISA boilerplate
        $hasFixVersion = $vuln->affectedPackages !== [] && $vuln->affectedPackages[0]->fixedVersion !== null;

        if ($hasFixVersion) {
            $pkg = $vuln->affectedPackages[0];
            $parts[] = "*What to do:* `composer update {$pkg->name}` to *{$pkg->fixedVersion}* or later";
        } elseif ($vuln->kevRequiredAction !== null) {
            $parts[] = "*What to do:* {$vuln->kevRequiredAction}";
        }

        if ($vuln->kevDueDate !== null) {
            $parts[] = "*Deadline:* {$vuln->kevDueDate} (CISA mandate)";
        }

        return implode("\n", $parts);
    }

    private static function buildPackageBlock(Vulnerability $vuln): string
    {
        if ($vuln->affectedPackages === []) {
            return '';
        }

        $lines = ["*Affected packages:*"];
        foreach (array_slice($vuln->affectedPackages, 0, 3) as $pkg) {
            $line = "`{$pkg->name}` ({$pkg->ecosystem}) -- vulnerable: {$pkg->vulnerableRange}";
            if ($pkg->fixedVersion !== null) {
                $line .= " -- fix: *{$pkg->fixedVersion}*";
            }
            $lines[] = $line;
        }

        return implode("\n", $lines);
    }

    private static function buildScoreBlock(Vulnerability $vuln): string
    {
        $parts = [];

        if ($vuln->cvssScore !== null) {
            $parts[] = "CVSS {$vuln->cvssScore}/10";
        }

        if ($vuln->epssScore !== null) {
            $pct = sprintf('%.1f%%', $vuln->epssScore * 100);
            $parts[] = "EPSS {$pct}";
            if ($vuln->epssPercentile !== null) {
                $parts[count($parts) - 1] .= sprintf(' (%d%%ile)', (int) ($vuln->epssPercentile * 100));
            }
        }

        if ($vuln->inKev) {
            $parts[] = 'In CISA KEV';
        }

        if ($vuln->cwes !== []) {
            $parts[] = implode(', ', array_slice($vuln->cwes, 0, 3));
        }

        return implode(' | ', $parts);
    }

    /** @return array<int, array<string, mixed>> */
    private static function buildButtons(Vulnerability $vuln): array
    {
        $buttons = [];

        if (str_starts_with($vuln->canonicalId, 'CVE-')) {
            $nvdUrl = "https://nvd.nist.gov/vuln/detail/{$vuln->canonicalId}";
            $buttons[] = ['type' => 'button', 'text' => ['type' => 'plain_text', 'text' => 'NVD'], 'url' => $nvdUrl];
        }

        foreach (array_slice($vuln->references, 0, 2) as $ref) {
            $parsed = parse_url($ref, PHP_URL_HOST);
            $host = is_string($parsed) ? $parsed : '';
            $label = match (true) {
                str_contains($host, 'github.com') => 'GitHub',
                str_contains($host, 'adobe.com') => 'Adobe',
                str_contains($host, 'magento.com') => 'Magento',
                str_contains($host, 'sansec.io') => 'Sansec',
                str_contains($host, 'cisa.gov') => 'CISA',
                $host !== '' => ucfirst(str_replace('www.', '', $host)),
                default => 'Reference',
            };
            $buttons[] = ['type' => 'button', 'text' => ['type' => 'plain_text', 'text' => $label], 'url' => $ref];
        }

        return $buttons;
    }

    private static function buildFooter(Vulnerability $vuln): string
    {
        $parts = [$vuln->canonicalId];

        if ($vuln->sources !== []) {
            $parts[] = 'via ' . implode(', ', $vuln->sources);
        }

        $parts[] = 'A.S.E.';

        return implode(' | ', $parts);
    }
}
