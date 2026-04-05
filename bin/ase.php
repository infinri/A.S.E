#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Ase\Ase;
use Ase\Config;
use Ase\Model\AffectedPackage;
use Ase\Model\Priority;
use Ase\Model\Vulnerability;
use Ase\Notify\SlackMessage;
use Ase\Dedup\Deduplicator;
use Ase\Feed\EpssFeed;
use Ase\Feed\GitHubAdvisoryFeed;
use Ase\Feed\KevFeed;
use Ase\Feed\NvdFeed;
use Ase\Feed\OsvFeed;
use Ase\Feed\PackagistAdvisoryFeed;
use Ase\Filter\ComposerLockAnalyzer;
use Ase\Health\DigestReporter;
use Ase\Health\FeedHealthTracker;
use Ase\Http\CurlClient;
use Ase\Notify\SlackNotifier;
use Ase\Scoring\PriorityCalculator;
use Ase\State\StateManager;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;

// Parse CLI arguments
$sinceDate = null;
$testSlack = false;
$testAlert = false;
foreach ($argv as $i => $arg) {
    if ($arg === '--since' && isset($argv[$i + 1])) {
        $sinceDate = $argv[$i + 1];
    }
    if ($arg === '--test-slack') {
        $testSlack = true;
    }
    if ($arg === '--test-alert') {
        $testAlert = true;
    }
}

// Bootstrap
$config = new Config(sinceDate: $sinceDate);

// Logger: rotating file + stderr
$logger = new Logger('ase');
$logPath = $config->logFilePath();
$logDir = dirname($logPath);
if (!is_dir($logDir)) {
    @mkdir($logDir, 0755, true);
}
$logger->pushHandler(new RotatingFileHandler($logPath, 7, Logger::DEBUG));
$logger->pushHandler(new StreamHandler('php://stderr', Logger::INFO));

// HTTP client
$http = new CurlClient($logger);

// State
$stateManager = new StateManager($config->stateFilePath(), $logger);

// Feeds
$feeds = [
    new KevFeed($http, $config, $logger),
    new NvdFeed($http, $config, $logger),
    new GitHubAdvisoryFeed($http, $config, $logger),
    new OsvFeed($http, $config, $logger),
    new PackagistAdvisoryFeed($http, $config, $logger),
];

// Services
$epss = new EpssFeed($http, $logger);
$deduplicator = new Deduplicator($logger);
$priorityCalculator = new PriorityCalculator($config);
$composerLockAnalyzer = new ComposerLockAnalyzer($config, $logger);
$slackNotifier = new SlackNotifier($http, $config, $logger);
$healthTracker = new FeedHealthTracker($logger);
$digestReporter = new DigestReporter($http, $config, $logger);

// Run
$ase = new Ase(
    config: $config,
    stateManager: $stateManager,
    feeds: $feeds,
    epss: $epss,
    deduplicator: $deduplicator,
    priorityCalculator: $priorityCalculator,
    composerLockAnalyzer: $composerLockAnalyzer,
    slackNotifier: $slackNotifier,
    healthTracker: $healthTracker,
    digestReporter: $digestReporter,
    logger: $logger,
);

// --test-slack: send a test message and exit
if ($testSlack) {
    $payload = [
        'channel' => $config->slackChannelCritical(),
        'blocks' => [
            [
                'type' => 'header',
                'text' => ['type' => 'plain_text', 'text' => 'A.S.E. Test Alert'],
            ],
            [
                'type' => 'section',
                'text' => [
                    'type' => 'mrkdwn',
                    'text' => "Slack integration is working.\nThis is a test message from A.S.E. (Automated Security Evaluator).",
                ],
            ],
        ],
    ];

    $response = $http->post($config->slackWebhookUrl(), $payload);

    if ($response->isOk() && $response->body === 'ok') {
        fwrite(STDOUT, "OK -- test message sent to {$config->slackChannelCritical()}\n");
        exit(0);
    }

    fwrite(STDERR, "FAILED -- Slack returned HTTP {$response->statusCode}: {$response->body}\n");
    exit(1);
}

// --test-alert: fetch CVE-2024-34102 (CosmicSting) from NVD + EPSS, build a real alert, post to Slack
if ($testAlert) {
    $cveId = 'CVE-2024-34102';
    fwrite(STDOUT, "Fetching {$cveId} from NVD...\n");

    $nvdUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={$cveId}";
    $nvdHeaders = [];
    $apiKey = $config->nvdApiKey();
    if ($apiKey !== null) {
        $nvdHeaders[] = "apiKey: {$apiKey}";
    }

    $nvdResponse = $http->get($nvdUrl, $nvdHeaders);
    if (!$nvdResponse->isOk()) {
        fwrite(STDERR, "FAILED -- NVD returned HTTP {$nvdResponse->statusCode}\n");
        exit(1);
    }

    $nvdData = $nvdResponse->json();
    $cve = $nvdData['vulnerabilities'][0]['cve'] ?? null;
    if ($cve === null) {
        fwrite(STDERR, "FAILED -- CVE not found in NVD response\n");
        exit(1);
    }

    $testDescription = '';
    foreach ($cve['descriptions'] ?? [] as $desc) {
        if ($desc['lang'] === 'en') {
            $testDescription = $desc['value'];
            break;
        }
    }

    $testCvssScore = null;
    $testCvssVector = null;
    foreach (['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV40'] as $metricKey) {
        foreach ($cve['metrics'][$metricKey] ?? [] as $metric) {
            if (($metric['type'] ?? '') === 'Primary') {
                $testCvssScore = (float) $metric['cvssData']['baseScore'];
                $testCvssVector = (string) $metric['cvssData']['vectorString'];
                break 2;
            }
        }
    }

    $testCwes = [];
    foreach ($cve['weaknesses'] ?? [] as $w) {
        foreach ($w['description'] ?? [] as $d) {
            if (($d['value'] ?? '') !== 'NVD-CWE-Other') {
                $testCwes[] = $d['value'];
            }
        }
    }

    $testReferences = [];
    foreach (array_slice($cve['references'] ?? [], 0, 5) as $ref) {
        $testReferences[] = $ref['url'];
    }

    $testInKev = isset($cve['cisaExploitAdd']);
    $testKevDateAdded = $cve['cisaExploitAdd'] ?? null;
    $testKevDueDate = $cve['cisaActionDue'] ?? null;
    $testKevAction = $cve['cisaRequiredAction'] ?? null;

    fwrite(STDOUT, "  CVSS: {$testCvssScore}, KEV: " . ($testInKev ? 'yes' : 'no') . "\n");

    fwrite(STDOUT, "Fetching EPSS score...\n");
    $epssResults = $epss->enrichBatch([$cveId]);
    $testEpssScore = isset($epssResults[$cveId]) ? $epssResults[$cveId]['score'] : null;
    $testEpssPercentile = isset($epssResults[$cveId]) ? $epssResults[$cveId]['percentile'] : null;
    fwrite(STDOUT, "  EPSS: {$testEpssScore} (percentile: {$testEpssPercentile})\n");

    $vuln = new Vulnerability(
        canonicalId: $cveId,
        aliases: [],
        description: $testDescription,
        cvssScore: $testCvssScore,
        cvssVector: $testCvssVector,
        epssScore: $testEpssScore,
        epssPercentile: $testEpssPercentile,
        inKev: $testInKev,
        knownRansomware: false,
        affectedPackages: [
            new AffectedPackage('composer', 'magento/framework', '<2.4.7-p1', '2.4.7-p1'),
        ],
        cwes: $testCwes,
        references: $testReferences,
        sources: ['nvd', 'epss'],
        firstSeen: date('c'),
        lastUpdated: date('c'),
        kevDateAdded: $testKevDateAdded,
        kevDueDate: $testKevDueDate,
        kevRequiredAction: $testKevAction,
        affectsInstalledVersion: false,
        priority: Priority::P4,
        notifiedAtPriority: null,
    );

    $testPriority = $priorityCalculator->classify($vuln);
    $vuln = $vuln->withPriority($testPriority);
    fwrite(STDOUT, "  Priority: {$testPriority->name} ({$testPriority->label()})\n");

    fwrite(STDOUT, "Posting alert to Slack...\n");
    $testMessage = SlackMessage::forVulnerability($vuln);
    $slackResponse = $http->post(
        $config->slackWebhookUrl(),
        $testMessage->toPayload($config->slackChannelCritical()),
    );

    if ($slackResponse->isOk() && $slackResponse->body === 'ok') {
        fwrite(STDOUT, "OK -- {$cveId} ({$testPriority->name}) posted to {$config->slackChannelCritical()}\n");
        fwrite(STDOUT, "Check Slack to review the alert format.\n");
        exit(0);
    }

    fwrite(STDERR, "FAILED -- Slack returned HTTP {$slackResponse->statusCode}: {$slackResponse->body}\n");
    exit(1);
}

try {
    $ase->run();
    exit(0);
} catch (Throwable $e) {
    $logger->critical('Unhandled exception', [
        'message' => $e->getMessage(),
        'file' => $e->getFile(),
        'line' => $e->getLine(),
    ]);
    fwrite(STDERR, "FATAL: {$e->getMessage()}\n");
    exit(1);
}
