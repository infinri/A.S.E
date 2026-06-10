<?php

declare(strict_types=1);

namespace Ase\Alert;

final readonly class AlertRouter
{
    /** @param array<string, string> $routes tag => webhook URL */
    public function __construct(
        private array $routes,
        private ?string $defaultWebhook,
    ) {}

    /**
     * @param string[] $tags
     * @return string[] deduplicated webhook URLs; empty when unroutable
     */
    public function webhooksForTags(array $tags): array
    {
        $webhooks = [];
        foreach ($tags as $tag) {
            if (isset($this->routes[$tag])) {
                $webhooks[] = $this->routes[$tag];
            }
        }
        if ($webhooks === [] && $this->defaultWebhook !== null) {
            $webhooks[] = $this->defaultWebhook;
        }
        return array_values(array_unique($webhooks));
    }
}
