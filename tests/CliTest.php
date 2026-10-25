<?php

declare(strict_types=1);

namespace ComposerGuard\Tests;

use ComposerGuard\Cli;
use ComposerGuard\Project;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CliTest extends TestCase
{
    /**
     * @param list<string> $args
     * @return array{int, string, string}
     */
    private static function cli(array $args): array
    {
        $out = '';
        $err = '';
        $code = Cli::run(
            $args,
            static function (string $s) use (&$out): void {
                $out .= $s;
            },
            static function (string $s) use (&$err): void {
                $err .= $s;
            },
            dirname(__DIR__),
            new \DateTimeImmutable('2026-10-25T00:00:00+00:00'),
        );

        return [$code, $out, $err];
    }

    public function testScansEveryProjectUnderADirectory(): void
    {
        [$code, $out] = self::cli(['tests/fixtures']);
        self::assertSame(1, $code);
        self::assertStringContainsString('tests/fixtures/risky/composer.lock:6  HIGH   CG007', $out);
        self::assertStringContainsString('3 project(s), 10 finding(s): 7 high, 3 medium, 0 low', $out);
    }

    public function testDirectoryWalkSkipsFixturesUnlessNamed(): void
    {
        [$code, $out] = self::cli(['.']);
        self::assertSame(0, $code);
        self::assertStringContainsString('1 project(s), 0 finding(s)', $out);
        self::assertStringNotContainsString('./', self::cli(['--fail-on', 'none', './tests/fixtures/risky'])[1]);
    }

    public function testCleanProjectPasses(): void
    {
        [$code, $out] = self::cli(['tests/fixtures/clean', '--fail-on', 'low']);
        self::assertSame(0, $code);
        self::assertStringContainsString('No problems found.', $out);
    }

    public function testAcceptsAComposerFileAndAbsolutePaths(): void
    {
        [, $out] = self::cli(['--fail-on', 'none', dirname(__DIR__) . '/tests/fixtures/nolock/composer.json']);
        self::assertStringContainsString('1 project(s), 1 finding(s)', $out);
        [$code, , $err] = self::cli(['phpunit.xml.dist']);
        self::assertSame(2, $code);
        self::assertStringContainsString('no composer.json found', $err);
    }

    public function testFormats(): void
    {
        [, $json] = self::cli(['--format', 'json', '--fail-on', 'none', 'tests/fixtures']);
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($data);
        self::assertSame(['high' => 7, 'medium' => 3, 'low' => 0], $data['summary']);

        [, $md] = self::cli(['--format', 'markdown', '--fail-on', 'none', 'tests/fixtures/risky']);
        self::assertStringContainsString('### 🛑 composer-guard', $md);
        self::assertStringContainsString('| Severity | Check | Target | Problem | What to do |', $md);
        [, $mdClean] = self::cli(['--format', 'markdown', 'tests/fixtures/clean']);
        self::assertStringContainsString('### ✅ composer-guard', $mdClean);

        [, $sarif] = self::cli(['--format', 'sarif', '--fail-on', 'none', 'tests/fixtures/risky']);
        $s = json_decode($sarif, true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($s);
        $run = Project::get($s, ['runs', 0]);
        self::assertIsArray($run);
        self::assertSame('composer-guard', Project::get($run, ['tool', 'driver', 'name']));
        $rules = Project::get($run, ['tool', 'driver', 'rules']);
        self::assertIsArray($rules);
        self::assertCount(8, $rules);
        self::assertSame(['uri' => 'tests/fixtures/risky/composer.json'], Project::get($run, ['results', 0, 'locations', 0, 'physicalLocation', 'artifactLocation']));
    }

    public function testFailOnLevels(): void
    {
        self::assertSame(0, self::cli(['--fail-on', 'none', 'tests/fixtures/risky'])[0]);
        self::assertSame(1, self::cli(['--fail-on', 'high', 'tests/fixtures/risky'])[0]);
    }

    public function testHelpVersionAndChecks(): void
    {
        self::assertStringContainsString('usage: composer-guard', self::cli(['-h'])[1]);
        self::assertSame("composer-guard 0.1.0\n", self::cli(['--version'])[1]);
        self::assertCount(8, explode("\n", trim(self::cli(['--list-checks'])[1])));
        self::assertSame(0, self::cli(['--min-age', '0', 'tests/fixtures/clean'])[0]);
    }

    /** @return iterable<string, array{list<string>, string}> */
    public static function badArgs(): iterable
    {
        yield 'unknown option' => [['--bogus'], 'unknown option --bogus'];
        yield 'missing value' => [['--format'], '--format needs a value'];
        yield 'bad format' => [['--format', 'xml'], 'unknown format "xml"'];
        yield 'bad fail-on' => [['--fail-on', 'critical'], '--fail-on must be'];
        yield 'bad min-age' => [['--min-age', '-1'], '--min-age must be'];
        yield 'missing path' => [['/does/not/exist'], 'no such file or directory'];
        yield 'bad json' => [['tests/fixtures/broken'], 'invalid JSON'];
    }

    /** @param list<string> $args */
    #[DataProvider('badArgs')]
    public function testRejectsBadInput(array $args, string $message): void
    {
        $dir = dirname(__DIR__) . '/tests/fixtures/broken';
        if (in_array('tests/fixtures/broken', $args, true)) {
            @mkdir($dir);
            file_put_contents($dir . '/composer.json', '{ nope');
        }
        try {
            [$code, , $err] = self::cli($args);
            self::assertSame(2, $code);
            self::assertStringContainsString($message, $err);
        } finally {
            @unlink($dir . '/composer.json');
            @rmdir($dir);
        }
    }
}
