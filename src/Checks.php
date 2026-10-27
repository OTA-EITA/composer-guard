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
        'CG011' => [Severity::High, 'Security blocking disabled', 'config.policy (or the deprecated config.audit.block-insecure) turns off blocking of versions with security advisories or flagged as malware; medium when malware blocking is limited to some commands.'],
        'CG012' => [Severity::Medium, 'Advisories ignored', 'config.policy or config.audit makes composer audit pass despite advisories or malware, ignores whole severity levels or malware reports; low for single advisories ignored without a reason.'],
        'CG013' => [Severity::Medium, 'Lock file out of date', 'The content-hash in composer.lock does not match composer.json, so composer install keeps installing the old locked set and ignores changed requirements, repositories and constraints.'],
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

        $this->blocking($p, $add);
        $this->suppressed($p, $add);

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

        // Lock file freshness, the way `composer validate` and `composer install` judge it
        $hash = Project::string($p->lock, ['content-hash']);
        if ($p->lockFile !== null && $hash !== null && $hash !== '' && $hash !== $p->contentHash()) {
            $add('CG013', 'content-hash', $p->lockFile, $p->lockTextLine('"content-hash"'), 'composer.lock is out of date with composer.json: composer install ignores the changes and installs the old locked versions', 'Run composer update for the packages you changed (composer update --dry-run shows what would change) and commit composer.lock.');
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

    /**
     * config.policy (Composer 2.10+) and the deprecated config.audit keys it replaces:
     * blocking of insecure and malicious versions during update, require, remove and install.
     *
     * @param callable(string, string, string, int, string, string=, ?Severity=): void $add
     */
    private function blocking(Project $p, callable $add): void
    {
        $policy = Project::get($p->json, ['config', 'policy']);
        if ($policy === false) {
            $add('CG011', 'config.policy', $p->jsonFile, $p->jsonKeyLine(['config', 'policy']), 'config.policy is false: Composer no longer blocks versions with known security advisories or versions flagged as malware', 'Remove it. To skip a single advisory, list its ID in config.policy.advisories.ignore-id with a reason.');

            return;
        }
        $advisories = Project::get($p->json, ['config', 'policy', 'advisories']);
        if ($advisories === false || Project::get($p->json, ['config', 'policy', 'advisories', 'block']) === false) {
            $key = $advisories === false ? 'config.policy.advisories' : 'config.policy.advisories.block';
            $add('CG011', $key, $p->jsonFile, $p->jsonKeyLine($advisories === false ? ['config', 'policy', 'advisories'] : ['config', 'policy', 'advisories', 'block']), "{$key} is false: composer update no longer blocks versions with known security advisories", 'Remove it. To skip a single advisory, list its ID in config.policy.advisories.ignore-id with a reason.');
        }
        if (Project::get($p->json, ['config', 'audit', 'block-insecure']) === false) {
            $add('CG011', 'config.audit.block-insecure', $p->jsonFile, $p->jsonKeyLine(['config', 'audit', 'block-insecure']), 'config.audit.block-insecure is false: composer update no longer blocks versions with known security advisories', 'Remove it. To skip a single advisory, list its ID in config.audit.ignore with a reason.');
        }
        $malware = Project::get($p->json, ['config', 'policy', 'malware']);
        if ($malware === false || Project::get($p->json, ['config', 'policy', 'malware', 'block']) === false) {
            $key = $malware === false ? 'config.policy.malware' : 'config.policy.malware.block';
            $add('CG011', $key, $p->jsonFile, $p->jsonKeyLine($malware === false ? ['config', 'policy', 'malware'] : ['config', 'policy', 'malware', 'block']), "{$key} is false: Composer no longer blocks versions flagged as malware", 'Remove it.');
        }
        $scope = Project::get($p->json, ['config', 'policy', 'malware', 'block-scope']);
        if (is_string($scope) && $scope !== 'all') {
            $skipped = $scope === 'update' ? 'composer install does' : 'composer update, require and remove do';
            $add('CG011', 'config.policy.malware.block-scope', $p->jsonFile, $p->jsonKeyLine(['config', 'policy', 'malware', 'block-scope']), "config.policy.malware.block-scope is \"{$scope}\": {$skipped} not block versions flagged as malware", 'Remove it so that every command blocks malware (the default, "all").', Severity::Medium);
        }
    }

    /**
     * Settings that keep composer audit quiet, or let ignored advisories and malware through blocking.
     *
     * @param callable(string, string, string, int, string, string=, ?Severity=): void $add
     */
    private function suppressed(Project $p, callable $add): void
    {
        if (Project::get($p->json, ['config', 'policy']) === false) {
            return; // reported by CG011
        }
        foreach (['advisories' => 'security advisories', 'malware' => 'versions flagged as malware'] as $list => $what) {
            $path = ['config', 'policy', $list, 'audit'];
            $mode = Project::get($p->json, $path);
            if ($mode === 'ignore' || $mode === 'report') {
                $effect = $mode === 'ignore' ? "does not report {$what}" : "reports {$what} but still passes";
                $add('CG012', implode('.', $path), $p->jsonFile, $p->jsonKeyLine($path), 'config.policy.' . $list . ".audit is \"{$mode}\": composer audit {$effect}", 'Remove it so that composer audit fails (the default); ignore single advisories by ID instead.');
            }
        }

        foreach ([['config', 'policy', 'advisories', 'ignore-severity'], ['config', 'audit', 'ignore-severity']] as $path) {
            $levels = self::entries(Project::get($p->json, $path));
            if ($levels !== []) {
                $names = implode(', ', array_keys($levels));
                $add('CG012', implode('.', $path), $p->jsonFile, $p->jsonKeyLine($path), implode('.', $path) . " ignores every advisory of severity {$names}", 'Ignore single advisories by ID, with a reason, instead of whole severity levels.');
            }
        }

        foreach (['ignore' => 'is not blocked or reported as malware', 'ignore-source' => 'is not checked for malware'] as $key => $effect) {
            $path = ['config', 'policy', 'malware', $key];
            foreach (array_keys(self::entries(Project::get($p->json, $path))) as $name) {
                $add('CG012', implode('.', $path) . ".{$name}", $p->jsonFile, $p->jsonKeyLine($path), "{$name} {$effect} (" . implode('.', $path) . ')', 'Remove the entry unless the malware report is a confirmed false positive, and record why.');
            }
        }

        foreach ([['config', 'policy', 'advisories', 'ignore-id'], ['config', 'policy', 'advisories', 'ignore'], ['config', 'audit', 'ignore']] as $path) {
            foreach (self::entries(Project::get($p->json, $path)) as $name => $reason) {
                if (!$reason) {
                    $line = $p->jsonKeyLine([...$path, $name]);
                    $add('CG012', implode('.', $path) . ".{$name}", $p->jsonFile, $line === 1 ? $p->jsonKeyLine($path) : $line, ($path[2] === 'advisories' && $path[3] === 'ignore' ? "advisories of {$name} are" : "advisory {$name} is") . ' ignored without a reason (' . implode('.', $path) . ')', 'Give the reason, e.g. {"' . $name . '": "not reachable: we do not use the affected feature"}, so the ignore can be reviewed and removed later.', Severity::Low);
                }
            }
        }
    }

    /**
     * Entries of an ignore list in any of its forms (a list of names, or a map of names to
     * a reason, null, a rule object or a list of rule objects), with whether each gives a reason.
     *
     * @return array<string, bool>
     */
    private static function entries(mixed $list): array
    {
        if (!is_array($list)) {
            return [];
        }
        $out = [];
        foreach ($list as $key => $value) {
            if (array_is_list($list)) {
                if (is_string($value)) {
                    $out[$value] = false;
                }
                continue;
            }
            $rules = is_array($value) && array_is_list($value) && $value !== [] ? $value : [$value];
            $explained = true;
            foreach ($rules as $rule) {
                $reason = is_array($rule) ? ($rule['reason'] ?? null) : $rule;
                $explained = $explained && is_string($reason) && trim($reason) !== '';
            }
            $out[(string) $key] = $explained;
        }

        return $out;
    }
}
