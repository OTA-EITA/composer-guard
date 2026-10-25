<?php

declare(strict_types=1);

namespace ComposerGuard;

final class Cli
{
    public const VERSION = '0.1.0';

    private const USAGE = <<<'TXT'
        usage: composer-guard [options] [path ...]

        Checks composer.json and composer.lock for supply-chain risks. Paths default
        to the current directory; directories are searched for composer.json.

        options:
          --min-age <days>       report versions released fewer than this many days ago (default: 7)
          --format <format>      text, json, markdown or sarif (default: text)
          --fail-on <severity>   exit 1 on findings at least this severe: high, medium, low or none (default: medium)
          --list-checks          print the checks and exit
          --version              print the version and exit
          -h, --help             show this help

        TXT;

    /**
     * @param list<string> $argv arguments without the program name
     * @param callable(string): void $out
     * @param callable(string): void $err
     */
    public static function run(array $argv, callable $out, callable $err, string $cwd, ?\DateTimeImmutable $now = null): int
    {
        $minAge = 7;
        $format = 'text';
        $failOn = 'medium';
        $paths = [];
        for ($i = 0; $i < count($argv); $i++) {
            $arg = $argv[$i];
            $value = static function (string $name) use ($argv, &$i): string {
                $v = $argv[$i + 1] ?? null;
                if ($v === null) {
                    throw new \InvalidArgumentException("{$name} needs a value");
                }
                $i++;

                return $v;
            };
            try {
                switch ($arg) {
                    case '-h':
                    case '--help':
                        $out(self::USAGE);

                        return 0;
                    case '--version':
                        $out('composer-guard ' . self::VERSION . "\n");

                        return 0;
                    case '--list-checks':
                        foreach (Checks::ALL as $id => [$severity, $title, $description]) {
                            $out(sprintf("%s  %-6s  %s: %s\n", $id, $severity->value, $title, $description));
                        }

                        return 0;
                    case '--min-age':
                        $v = $value($arg);
                        if (!ctype_digit($v)) {
                            throw new \InvalidArgumentException('--min-age must be a whole number of days');
                        }
                        $minAge = (int) $v;
                        break;
                    case '--format':
                        $format = $value($arg);
                        if (!in_array($format, Report::FORMATS, true)) {
                            throw new \InvalidArgumentException("unknown format \"{$format}\" (want " . implode(', ', Report::FORMATS) . ')');
                        }
                        break;
                    case '--fail-on':
                        $failOn = $value($arg);
                        if ($failOn !== 'none' && Severity::tryFrom($failOn) === null) {
                            throw new \InvalidArgumentException("--fail-on must be high, medium, low or none, got \"{$failOn}\"");
                        }
                        break;
                    default:
                        if (str_starts_with($arg, '-')) {
                            throw new \InvalidArgumentException("unknown option {$arg}");
                        }
                        $paths[] = $arg;
                }
            } catch (\InvalidArgumentException $e) {
                $err("error: {$e->getMessage()}\n\n" . self::USAGE);

                return 2;
            }
        }

        $checks = new Checks($minAge, $now ?? new \DateTimeImmutable());
        $findings = [];
        $files = 0;
        try {
            foreach ($paths === [] ? ['.'] : $paths as $path) {
                $abs = str_starts_with($path, '/') ? $path : $cwd . '/' . $path;
                foreach (self::projects($abs) as $dir) {
                    $rel = ltrim(substr($dir, strlen(rtrim($cwd, '/'))), '/');
                    $findings = [...$findings, ...$checks->run(Project::load($dir, str_starts_with($dir, $cwd) ? $rel : $dir))];
                    $files++;
                }
            }
        } catch (\RuntimeException $e) {
            $err("error: {$e->getMessage()}\n");

            return 2;
        }
        if ($files === 0) {
            $err("error: no composer.json found\n");

            return 2;
        }

        $out(Report::render($findings, $format, $files, self::VERSION));
        if ($failOn === 'none') {
            return 0;
        }
        $threshold = Severity::from($failOn)->rank();
        foreach ($findings as $f) {
            if ($f->severity->rank() >= $threshold) {
                return 1;
            }
        }

        return 0;
    }

    /**
     * Directories that contain a composer.json, skipping vendor and VCS folders.
     *
     * @return list<string>
     */
    public static function projects(string $path): array
    {
        if (is_file($path)) {
            return basename($path) === 'composer.json' || basename($path) === 'composer.lock' ? [dirname($path)] : [];
        }
        if (!is_dir($path)) {
            throw new \RuntimeException("{$path}: no such file or directory");
        }
        $out = is_file($path . '/composer.json') ? [rtrim($path, '/')] : [];
        $entries = scandir($path) ?: [];
        foreach ($entries as $e) {
            if (in_array($e, ['.', '..', 'vendor', 'node_modules', '.git'], true) || !is_dir("{$path}/{$e}")) {
                continue;
            }
            $out = [...$out, ...self::projects("{$path}/{$e}")];
        }

        return $out;
    }
}
