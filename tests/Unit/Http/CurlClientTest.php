<?php

declare(strict_types=1);

namespace Ase\Tests\Unit\Http;

use Ase\Http\CurlClient;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class CurlClientTest extends TestCase
{
    private const string HOST = '127.0.0.1';
    private const int PORT = 18943;

    /** @var resource|null */
    private static $serverProcess = null;
    private static string $routerPath = '';

    public static function setUpBeforeClass(): void
    {
        self::$routerPath = tempnam(sys_get_temp_dir(), 'ase-router-') . '.php';
        file_put_contents(self::$routerPath, <<<'PHP'
            <?php
            header('Content-Type: application/json');
            echo json_encode([
                'method' => $_SERVER['REQUEST_METHOD'],
                'body' => file_get_contents('php://input'),
                'contentType' => $_SERVER['HTTP_CONTENT_TYPE'] ?? ($_SERVER['CONTENT_TYPE'] ?? ''),
            ]);
            PHP);

        $process = proc_open(
            [PHP_BINARY, '-S', self::HOST . ':' . self::PORT, self::$routerPath],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
        );
        if ($process === false) {
            self::fail('Could not start PHP built-in server for CurlClient tests.');
        }
        self::$serverProcess = $process;

        $deadline = microtime(true) + 5.0;
        while (microtime(true) < $deadline) {
            $socket = @fsockopen(self::HOST, self::PORT);
            if (is_resource($socket)) {
                fclose($socket);
                return;
            }
            usleep(50_000);
        }
        self::fail('PHP built-in server did not become ready within 5 seconds.');
    }

    public static function tearDownAfterClass(): void
    {
        if (is_resource(self::$serverProcess)) {
            proc_terminate(self::$serverProcess);
            proc_close(self::$serverProcess);
        }
        @unlink(self::$routerPath);
    }

    private function url(): string
    {
        return 'http://' . self::HOST . ':' . self::PORT . '/';
    }

    public function testGetSendsGetMethod(): void
    {
        $response = new CurlClient(new NullLogger())->get($this->url());

        self::assertSame(200, $response->statusCode);
        self::assertSame('GET', $response->json()['method']);
    }

    public function testPostSendsBodyAsJson(): void
    {
        $response = new CurlClient(new NullLogger())->post($this->url(), ['a' => 1]);

        $echo = $response->json();
        self::assertSame('POST', $echo['method']);
        self::assertSame('{"a":1}', $echo['body']);
        self::assertSame('application/json', $echo['contentType']);
    }

    public function testPutSendsPutMethodWithJsonBody(): void
    {
        $response = new CurlClient(new NullLogger())->put($this->url(), ['bom' => 'abc']);

        $echo = $response->json();
        self::assertSame('PUT', $echo['method']);
        self::assertSame('{"bom":"abc"}', $echo['body']);
        self::assertSame('application/json', $echo['contentType']);
    }
}
