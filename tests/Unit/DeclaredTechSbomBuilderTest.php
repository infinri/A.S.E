<?php

declare(strict_types=1);

namespace Ase\Tests\Unit;

use Ase\Sbom\DeclaredTechSbomBuilder;
use PHPUnit\Framework\TestCase;

final class DeclaredTechSbomBuilderTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = tempnam(sys_get_temp_dir(), 'ase-inventory-') . '.yaml';
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
    }

    public function testGroupsEntriesByOwnerWithCpeComponents(): void
    {
        file_put_contents($this->path, <<<'YAML'
            - name: FortiGate 100F
              vendor: fortinet
              product: fortios
              version: 7.2.8
              cpe: "cpe:2.3:o:fortinet:fortios:7.2.8:*:*:*:*:*:*:*"
              owner: infra
              type: device
            - name: MySQL (prod)
              vendor: oracle
              product: mysql
              version: 8.0.36
              cpe: "cpe:2.3:a:oracle:mysql:8.0.36:*:*:*:*:*:*:*"
              owner: infra
            - name: Celigo connector
              vendor: celigo
              version: latest-saas
              owner: erp
            YAML);

        $boms = new DeclaredTechSbomBuilder()->buildPerOwner($this->path);

        self::assertSame(['infra', 'erp'], array_keys($boms));
        self::assertCount(2, $boms['infra']['components']);
        self::assertSame('CycloneDX', $boms['infra']['bomFormat']);

        $fortigate = $boms['infra']['components'][0];
        self::assertSame('device', $fortigate['type']);
        self::assertSame('FortiGate 100F', $fortigate['name']);
        self::assertSame('7.2.8', $fortigate['version']);
        self::assertSame('cpe:2.3:o:fortinet:fortios:7.2.8:*:*:*:*:*:*:*', $fortigate['cpe']);

        $mysql = $boms['infra']['components'][1];
        self::assertSame('application', $mysql['type']);

        $celigo = $boms['erp']['components'][0];
        self::assertArrayNotHasKey('cpe', $celigo);
    }

    public function testEmptyOrCommentOnlyFileBuildsNothing(): void
    {
        file_put_contents($this->path, "# template only, no entries yet\n");

        self::assertSame([], new DeclaredTechSbomBuilder()->buildPerOwner($this->path));
    }

    public function testThrowsWhenOwnerMissing(): void
    {
        file_put_contents($this->path, "- name: Thing\n  version: '1.0'\n");

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Thing');
        new DeclaredTechSbomBuilder()->buildPerOwner($this->path);
    }

    public function testThrowsOnMissingFile(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('/nonexistent/inventory.yaml');
        new DeclaredTechSbomBuilder()->buildPerOwner('/nonexistent/inventory.yaml');
    }

    public function testThrowsOnInvalidYaml(): void
    {
        file_put_contents($this->path, "::: not yaml {{{");

        $this->expectException(\RuntimeException::class);
        new DeclaredTechSbomBuilder()->buildPerOwner($this->path);
    }
}
