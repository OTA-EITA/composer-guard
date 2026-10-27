<?php

declare(strict_types=1);

namespace ComposerGuard;

final class Checks
{
    /** @var array<string, array{Severity, string, string}> id => [severity, title, description] */
    public const ALL = [
        'CG001' => [Severity::High, 'All plugins allowed', 'config.allow-plugins is true, so any Composer plugin that ends up in the dependency tree runs code during install.'],
        'CG002' => [Severity::Medium, 'Plugins allowed by wildcard', 'A wildcard in config.allow-plugins lets any package of that vendor run code during install, including ones added later.'],
        'CG003' => [Severity::High, 'HTTP downloads allowed', 'config.secure-http is false, so packages may be downloaded without TLS and swapped in transit.'],
        'CG004' => [Severity::High, 'TLS disabled', 'config.disable-tls is true: every HTTPS URL is fetched over plain HTTP.'],
        'CG005' => [Severity::High, 'Plain HTTP source', 'A repository or a locked package is fetched over http://.'],
        'CG006' => [Severity::Medium, 'Unpinned branch', 'A package is locked to a VCS branch (dev-*), so its contents change with every push to that branch.'],
        'CG007' => [Severity::Medium, 'Freshly released', 'The locked version was released less than the cooldown period ago; high when the package is a Composer plugin.'],
        'CG008' => [Severity::High, 'Remote script in a Composer script', 'A composer.json script downloads a script and pipes it into a shell.'],
        'CG009' => [Severity::Medium, 'Unstable versions preferred', 'minimum-stability allows dev, alpha, beta or RC versions and prefer-stable is not true, so Composer picks the newest pre-release or branch over a stable release.'],
        'CG010' => [Severity::Medium, 'Non-canonical repository', 'A repository has "canonical": false, so a higher version of the same package name on Packagist or a later repository can replace it (dependency confusion).'],
    ];

    public function __construct(
        private readonly int $minAgeDays,
        private readonly \DateTimeImmutable $now,
    ) {
    }

    /** @return list<Finding> */
    public function run(Project $p): array
    {
        $out = [];
        $add = function (string $id, string $target, string $file, int $line, string $message, string $help = '', ?Severity $severity = null) use (&$out): void {
            $out[] = new Finding($id, $severity ?? self::ALL[$id][0], $target, $file, $line, $message, $help);
        };

        // Plugins
        $allow = Project::get($p->json, ['config', 'allow-plugins']);
        if ($allow === true) {
            $add('CG001', 'config.allow-plugins', $p->jsonFile, $p->jsonLine('"allow-plugins"'), 'config.allow-plugins is true: every plugin in the dependency tree may run code during install', 'List the plugins you trust by name, e.g. {"composer/installers": true}.');
        } elseif (is_array($allow)) {
            foreach ($allow as $pattern => $allowed) {
                if ($allowed !== true || !str_contains((string) $pattern, '*')) {
                    continue;
                }
                $id = $pattern === '*' ? 'CG001' : 'CG002';
                $add($id, "config.allow-plugins.{$pattern}", $p->jsonFile, $p->jsonLine('"' . $pattern . '"'), "config.allow-plugins allows \"{$pattern}\" to run code during install", 'Name each plugin instead of using a wildcard.');
            }
        }

        // Transport
        if (Project::get($p->json, ['config', 'secure-http']) === false) {
            $add('CG003', 'config.secure-http', $p->jsonFile, $p->jsonLine('"secure-http"'), 'config.secure-http is false: Composer may download packages over plain HTTP', 'Remove it and serve the repository over HTTPS.');
        }
        if (Project::get($p->json, ['config', 'disable-tls']) === true) {
            $add('CG004', 'config.disable-tls', $p->jsonFile, $p->jsonLine('"disable-tls"'), 'config.disable-tls is true: Composer fetches every HTTPS URL over plain HTTP', 'Remove it and enable the openssl extension instead.');
        }
        $repos = Project::get($p->json, ['repositories']);
        foreach (is_array($repos) ? $repos : [] as $key => $repo) {
            $url = is_array($repo) ? Project::string($repo, ['url']) : null;
            if ($url !== null && str_starts_with(strtolower($url), 'http://')) {
                $add('CG005', $url, $p->jsonFile, $p->jsonLine($url), "repository {$url} is fetched over plain HTTP", 'Use https://.');
            }
            if (is_array($repo) && ($repo['canonical'] ?? null) === false) {
                $name = $url ?? Project::string($repo, ['type']) ?? 'repository';
                $add('CG010', $name, $p->jsonFile, $p->jsonKeyLine(['repositories', $key, 'canonical']), "repository {$name} is not canonical: a higher version of one of its packages published on Packagist or a later repository can be installed instead", 'Remove "canonical": false. If only some packages should come from this repository, list them with "only" instead.');
            }
        }

        // Stability
        $stability = Project::get($p->json, ['minimum-stability']);
        if (is_string($stability) && strtolower($stability) !== 'stable' && Project::get($p->json, ['prefer-stable']) !== true) {
            $add('CG009', 'minimum-stability', $p->jsonFile, $p->jsonLine('"minimum-stability"'), "minimum-stability is \"{$stability}\" without \"prefer-stable\": true: Composer installs the newest {$stability} version or branch even when a stable release matches", 'Add "prefer-stable": true, or keep minimum-stability at stable and allow single packages with a flag such as "vendor/pkg": "^2.0@beta".');
        }

        // Scripts
        $scripts = Project::get($p->json, ['scripts']);
        foreach (is_array($scripts) ? $scripts : [] as $event => $commands) {
            foreach (is_array($commands) ? $commands : [$commands] as $cmd) {
                if (is_string($cmd) && preg_match('/\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/', $cmd) === 1) {
                    $add('CG008', "scripts.{$event}", $p->jsonFile, $p->jsonLine($cmd), "script \"{$event}\" pipes a downloaded script into a shell", 'Vendor the script into the repository, or pin it by checksum.');
                }
            }
        }

        // Locked packages
        $cutoff = $this->now->modify("-{$this->minAgeDays} days");
        foreach ($p->packages() as ['package' => $pkg, 'dev' => $dev]) {
            $name = (string) Project::string($pkg, ['name']);
            $version = (string) Project::string($pkg, ['version']);
            $isPlugin = Project::string($pkg, ['type']) === 'composer-plugin';
            $line = $p->lockLine($name);
            $file = (string) $p->lockFile;
            $id = "{$name}@{$version}";

            foreach (['source', 'dist'] as $kind) {
                $url = Project::string($pkg, [$kind, 'url']);
                if ($url !== null && str_starts_with(strtolower($url), 'http://')) {
                    $add('CG005', $id, $file, $line, "{$id} is downloaded over plain HTTP ({$kind}: {$url})", 'Use an HTTPS repository so the archive cannot be swapped in transit.');
                    break;
                }
            }

            // roave/security-advisories is meant to be required as dev-master: it only holds conflict rules, no code.
            if (str_starts_with($version, 'dev-') && $name !== 'roave/security-advisories') {
                $add('CG006', $id, $file, $line, "{$id} is locked to a branch" . ($dev ? ' (dev dependency)' : ''), 'Require a tagged release; a branch can change under you between installs on different machines.');
            }

            $time = Project::string($pkg, ['time']);
            if ($time !== null && !str_starts_with($version, 'dev-')) {
                try {
                    $released = new \DateTimeImmutable($time);
                } catch (\Exception) {
                    continue;
                }
                if ($released > $cutoff) {
                    $days = intdiv($this->now->getTimestamp() - $released->getTimestamp(), 86400);
                    $age = $days < 1 ? 'less than a day' : "{$days} day(s)";
                    $add(
                        'CG007',
                        $id,
                        $file,
                        $line,
                        "{$id} was released {$age} ago" . ($isPlugin ? ' and is a Composer plugin, which runs code during install' : ''),
                        "Most hijacked releases are found and pulled within days. Hold it back until it is {$this->minAgeDays} days old: composer update --with \"{$name}:<{$version}\".",
                        $isPlugin ? Severity::High : null,
                    );
                }
            }
        }

        usort($out, static fn (Finding $a, Finding $b): int => [$b->severity->rank(), $a->file, $a->line, $a->checkId] <=> [$a->severity->rank(), $b->file, $b->line, $b->checkId]);

        return $out;
    }
}
