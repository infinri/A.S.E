<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class CliIntegrationTest extends TestCase
{
    private string $tmpDir;
    private string $binPath;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/ase_cli_test_' . uniqid();
        mkdir($this->tmpDir, 0755, true);
        $this->binPath = dirname(__DIR__, 2) . '/bin/ase';
    }

    protected function tearDown(): void
    {
        $files = glob($this->tmpDir . '/*') ?: [];
        array_map('unlink', $files);
        @rmdir($this->tmpDir);
    }

    #[Test]
    public function testExitCode2FromP0DryRun(): void
    {
        $this->markTestSkipped('requires fixture feeds -- implementation will wire fixtures');
    }

    #[Test]
    public function testDryRunExitsWithoutSlackWebhookConfigured(): void
    {
        $result = $this->runCli(['--dry-run'], env: []);

        self::assertNotSame(
            2,
            $result['exit'],
            'Exit code 2 reserved for fatal config errors; dry-run should not require webhook',
        );
        self::assertStringNotContainsString(
            'SLACK_WEBHOOK_URL is required',
            $result['stderr'],
            'dry-run must not demand SLACK_WEBHOOK_URL',
        );
    }

    #[Test]
    public function testJsonFormatExitsWithoutSlackWebhook(): void
    {
        $result = $this->runCli(['--format=json', '--dry-run'], env: []);

        self::assertNotSame(
            2,
            $result['exit'],
            'Exit code 2 reserved for fatal config errors; --format=json should not require webhook',
        );
        self::assertStringNotContainsString(
            'SLACK_WEBHOOK_URL is required',
            $result['stderr'],
            '--format=json must not demand SLACK_WEBHOOK_URL',
        );
    }

    #[Test]
    public function testNormalRunExitsIfSlackWebhookMissing(): void
    {
        $result = $this->runCli([], env: []);

        self::assertSame(2, $result['exit']);
        self::assertStringContainsString('SLACK_WEBHOOK_URL is required', $result['stderr']);
    }

    #[Test]
    public function testUnknownFormatValueExits2(): void
    {
        $result = $this->runCli(['--format=yaml', '--dry-run'], env: []);

        self::assertSame(2, $result['exit']);
        self::assertMatchesRegularExpression('/format/i', $result['stderr']);
    }

    #[Test]
    public function testJsonFormatOutputsParseableJsonToStdout(): void
    {
        $this->markTestSkipped('requires fixture feeds -- implementation will wire fixtures');
    }

    #[Test]
    public function testJsonFormatKeepsLogsOnStderrNotStdout(): void
    {
        $this->markTestSkipped('requires fixture feeds -- implementation will wire fixtures');
    }

    /**
     * Run bin/ase in a subprocess and capture stdout, stderr, and exit code.
     *
     * @param string[] $args
     * @param array<string, string> $env  Extra env vars to pass. Empty array means no SLACK_WEBHOOK_URL.
     * @return array{stdout: string, stderr: string, exit: int}
     */
    private function runCli(array $args, array $env = []): array
    {
        $baseEnv = [
            'PATH' => getenv('PATH') ?: '/usr/bin:/bin',
            'STATE_FILE' => $this->tmpDir . '/state.json',
            'HEARTBEAT_FILE' => $this->tmpDir . '/heartbeat.txt',
            'LOG_FILE' => $this->tmpDir . '/ase.log',
            'ENABLED_FEEDS' => '',
            'ASE_SKIP_DOTENV' => '1',
        ];

        $fullEnv = array_merge($baseEnv, $env);

        $cmd = 'php ' . escapeshellarg($this->binPath);
        foreach ($args as $arg) {
            $cmd .= ' ' . escapeshellarg($arg);
        }

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = proc_open($cmd, $descriptors, $pipes, $this->tmpDir, $fullEnv);

        self::assertIsResource($process, 'proc_open failed to start subprocess');

        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);

        return [
            'stdout' => (string) $stdout,
            'stderr' => (string) $stderr,
            'exit' => $exitCode,
        ];
    }
}
