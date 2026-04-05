<?php

declare(strict_types=1);

namespace Ase\Http;

use Psr\Log\LoggerInterface;

final class CurlClient
{
    private const string USER_AGENT = 'A.S.E./1.0 (vulnerability-monitor)';
    private const int CONNECT_TIMEOUT = 10;
    private const int TIMEOUT = 30;
    private const int MAX_FILE_SIZE = 10_485_760; // 10MB
    private const int MAX_RETRIES = 3;
    private const array BACKOFF_SECONDS = [2, 8, 32];

    public function __construct(
        private readonly LoggerInterface $logger,
    ) {}

    /** @param string[] $headers */
    public function get(string $url, array $headers = []): HttpResponse
    {
        return $this->request('GET', $url, headers: $headers);
    }

    /**
     * @param array<string, mixed>|string $body
     * @param string[] $headers
     */
    public function post(string $url, array|string $body, array $headers = []): HttpResponse
    {
        $postBody = is_array($body) ? json_encode($body, JSON_THROW_ON_ERROR) : $body;

        if (is_array($body)) {
            $headers[] = 'Content-Type: application/json';
        }

        return $this->request('POST', $url, $postBody, $headers);
    }

    /** @param string[] $headers */
    private function request(
        string $method,
        string $url,
        ?string $body = null,
        array $headers = [],
    ): HttpResponse {
        for ($attempt = 0; $attempt <= self::MAX_RETRIES; $attempt++) {
            $response = $this->execute($method, $url, $body, $headers);

            if ($response->statusCode !== 429 || $attempt === self::MAX_RETRIES) {
                return $response;
            }

            $retryAfter = $response->header('retry-after');
            $waitSeconds = $retryAfter !== null
                ? (int) $retryAfter
                : self::BACKOFF_SECONDS[$attempt];

            $this->logger->warning('Rate limited (429), retrying', [
                'url' => $url,
                'attempt' => $attempt + 1,
                'wait_seconds' => $waitSeconds,
            ]);

            sleep($waitSeconds);
        }

        // Unreachable, but satisfies static analysis
        return $response;
    }

    /** @param string[] $headers */
    private function execute(
        string $method,
        string $url,
        ?string $body,
        array $headers,
    ): HttpResponse {
        $this->logger->debug('HTTP request', ['method' => $method, 'url' => $url]);

        $ch = curl_init();

        /** @var array<string, string> $responseHeaders */
        $responseHeaders = [];

        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT,
            CURLOPT_TIMEOUT => self::TIMEOUT,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT => self::USER_AGENT,
            CURLOPT_MAXFILESIZE => self::MAX_FILE_SIZE,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_HEADERFUNCTION => static function ($ch, string $header) use (&$responseHeaders): int {
                $parts = explode(':', $header, 2);
                if (count($parts) === 2) {
                    $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                }
                return strlen($header);
            },
        ]);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            if ($body !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            }
        }

        $rawResponse = curl_exec($ch);
        $statusCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        $responseBody = is_string($rawResponse) ? $rawResponse : false;

        if ($responseBody === false) {
            $this->logger->error('HTTP request failed', [
                'url' => $url,
                'error' => $error,
            ]);

            return new HttpResponse(
                statusCode: 0,
                body: '',
                headers: $responseHeaders,
            );
        }

        $this->logger->debug('HTTP response', [
            'url' => $url,
            'status' => $statusCode,
            'size' => strlen($responseBody),
        ]);

        return new HttpResponse(
            statusCode: $statusCode,
            body: $responseBody,
            headers: $responseHeaders,
        );
    }
}
