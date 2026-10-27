<?php

declare(strict_types=1);

namespace ComposerGuard;

/**
 * composer.json and composer.lock of one project, decoded, with helpers to
 * read typed values and to find the line a value appears on.
 */
final class Project
{
    /** @var array<string, mixed> */
    public readonly array $json;
    /** @var array<string, mixed> */
    public readonly array $lock;

    public function __construct(
        public readonly string $jsonFile,
        private readonly string $jsonText,
        public readonly ?string $lockFile = null,
        private readonly string $lockText = '',
    ) {
        $this->json = self::decode($jsonFile, $jsonText);
        $this->lock = $lockFile === null ? [] : self::decode($lockFile, $lockText);
    }

    /** Loads composer.json (and composer.lock next to it, if present) from a directory. */
    public static function load(string $dir, string $displayDir): self
    {
        $json = $dir . '/composer.json';
        $text = @file_get_contents($json);
        if ($text === false) {
            throw new \RuntimeException("cannot read {$json}");
        }
        $lock = $dir . '/composer.lock';
        $lockText = is_file($lock) ? (string) file_get_contents($lock) : null;
        $prefix = $displayDir === '' || $displayDir === '.' ? '' : rtrim($displayDir, '/') . '/';

        return new self($prefix . 'composer.json', $text, $lockText === null ? null : $prefix . 'composer.lock', $lockText ?? '');
    }

    /** @return array<string, mixed> */
    private static function decode(string $file, string $text): array
    {
        try {
            $data = json_decode($text, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \RuntimeException("{$file}: invalid JSON: {$e->getMessage()}", 0, $e);
        }
        if (!is_array($data) || array_is_list($data) && $data !== []) {
            throw new \RuntimeException("{$file}: not a JSON object");
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    /**
     * Value at a path such as ['config', 'secure-http'].
     *
     * @param array<mixed> $data
     * @param list<string|int> $path
     */
    public static function get(array $data, array $path): mixed
    {
        $cur = $data;
        foreach ($path as $key) {
            if (!is_array($cur) || !array_key_exists($key, $cur)) {
                return null;
            }
            $cur = $cur[$key];
        }

        return $cur;
    }

    /**
     * @param array<mixed> $data
     * @param list<string|int> $path
     */
    public static function string(array $data, array $path): ?string
    {
        $v = self::get($data, $path);

        return is_string($v) ? $v : null;
    }

    /**
     * Locked packages, production and dev.
     *
     * @return list<array{package: array<mixed>, dev: bool}>
     */
    public function packages(): array
    {
        $out = [];
        foreach (['packages' => false, 'packages-dev' => true] as $key => $dev) {
            $list = $this->lock[$key] ?? [];
            if (!is_array($list)) {
                continue;
            }
            foreach ($list as $p) {
                if (is_array($p) && is_string($p['name'] ?? null)) {
                    $out[] = ['package' => $p, 'dev' => $dev];
                }
            }
        }

        return $out;
    }

    /** 1-based line of the first occurrence of a quoted string, or 1. */
    public function jsonLine(string $needle): int
    {
        return self::lineOf($this->jsonText, $needle);
    }

    /** 1-based line of the first occurrence of a string in composer.lock, or 1. */
    public function lockTextLine(string $needle): int
    {
        return self::lineOf($this->lockText, $needle);
    }

    /**
     * The hash Composer stores as "content-hash" in composer.lock, computed the
     * way Composer's Locker::getContentHash() does: the keys of composer.json
     * that affect dependency resolution, sorted, JSON-encoded without escaping flags.
     */
    public function contentHash(): string
    {
        $keys = ['name', 'version', 'require', 'require-dev', 'conflict', 'replace', 'provide', 'minimum-stability', 'prefer-stable', 'repositories', 'extra'];
        $relevant = array_intersect_key($this->json, array_flip($keys));
        $platform = self::get($this->json, ['config', 'platform']);
        if ($platform !== null) {
            $relevant['config'] = ['platform' => $platform];
        }
        ksort($relevant);

        // JSON_THROW_ON_ERROR does not change the output; Composer passes no other flags.
        return md5(json_encode($relevant, JSON_THROW_ON_ERROR));
    }

    /** Line of a package's entry in composer.lock. */
    public function lockLine(string $package): int
    {
        return self::lineOf($this->lockText, '"name": ' . json_encode($package, JSON_UNESCAPED_SLASHES));
    }

    private static function lineOf(string $text, string $needle): int
    {
        $pos = strpos($text, $needle);

        return $pos === false ? 1 : substr_count($text, "\n", 0, $pos) + 1;
    }
}
