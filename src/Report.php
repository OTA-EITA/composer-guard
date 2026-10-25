<?php

declare(strict_types=1);

namespace ComposerGuard;

final class Report
{
    public const FORMATS = ['text', 'json', 'markdown', 'sarif'];

    /** @param list<Finding> $findings */
    public static function render(array $findings, string $format, int $files, string $version): string
    {
        return match ($format) {
            'json' => json_encode(['findings' => array_map(self::toArray(...), $findings), 'summary' => self::counts($findings)], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n",
            'markdown' => self::markdown($findings, $files),
            'sarif' => json_encode(self::sarif($findings, $version), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n",
            default => self::text($findings, $files),
        };
    }

    /** @param list<Finding> $findings @return array{high: int, medium: int, low: int} */
    private static function counts(array $findings): array
    {
        $c = ['high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($findings as $f) {
            $c[$f->severity->value]++;
        }

        return $c;
    }

    /** @param list<Finding> $findings */
    private static function summary(array $findings, int $files): string
    {
        $c = self::counts($findings);

        return sprintf('%d project(s), %d finding(s): %d high, %d medium, %d low', $files, count($findings), $c['high'], $c['medium'], $c['low']);
    }

    /** @return array<string, string|int> */
    private static function toArray(Finding $f): array
    {
        return ['check' => $f->checkId, 'severity' => $f->severity->value, 'target' => $f->target, 'file' => $f->file, 'line' => $f->line, 'message' => $f->message, 'help' => $f->help];
    }

    /** @param list<Finding> $findings */
    private static function text(array $findings, int $files): string
    {
        $lines = array_map(static fn (Finding $f): string => sprintf('%s:%d  %-6s %s  %s', $f->file, $f->line, strtoupper($f->severity->value), $f->checkId, $f->message), $findings);

        return implode("\n", [...$lines, $lines === [] ? 'No problems found.' : '', self::summary($findings, $files), '']);
    }

    /** @param list<Finding> $findings */
    private static function markdown(array $findings, int $files): string
    {
        $high = array_filter($findings, static fn (Finding $f): bool => $f->severity === Severity::High);
        $icon = $high !== [] ? '🛑' : ($findings !== [] ? '⚠️' : '✅');
        $out = ["### {$icon} composer-guard", '', self::summary($findings, $files), ''];
        if ($findings !== []) {
            $out[] = '| Severity | Check | Target | Problem | What to do |';
            $out[] = '|---|---|---|---|---|';
            $esc = static fn (string $s): string => str_replace('|', '\|', $s);
            foreach ($findings as $f) {
                $out[] = "| {$f->severity->value} | {$f->checkId} | `{$esc($f->target)}` | {$esc($f->message)} | {$esc($f->help)} |";
            }
        }

        return implode("\n", $out) . "\n";
    }

    /**
     * @param list<Finding> $findings
     * @return array<string, mixed>
     */
    private static function sarif(array $findings, string $version): array
    {
        $level = static fn (Severity $s): string => match ($s) {
            Severity::High => 'error',
            Severity::Medium => 'warning',
            Severity::Low => 'note',
        };
        $score = static fn (Severity $s): string => match ($s) {
            Severity::High => '8.0',
            Severity::Medium => '5.0',
            Severity::Low => '2.0',
        };
        $rules = [];
        foreach (Checks::ALL as $id => [$severity, $title, $description]) {
            $rules[] = [
                'id' => $id,
                'name' => $title,
                'shortDescription' => ['text' => $title],
                'fullDescription' => ['text' => $description],
                'defaultConfiguration' => ['level' => $level($severity)],
                'properties' => ['tags' => ['security', 'composer', 'supply-chain'], 'security-severity' => $score($severity)],
            ];
        }

        return [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [[
                'tool' => ['driver' => ['name' => 'composer-guard', 'version' => $version, 'informationUri' => 'https://github.com/OTA-EITA/composer-guard', 'rules' => $rules]],
                'results' => array_map(static fn (Finding $f): array => [
                    'ruleId' => $f->checkId,
                    'level' => $level($f->severity),
                    'message' => ['text' => $f->help === '' ? $f->message : "{$f->message}. {$f->help}"],
                    'locations' => [['physicalLocation' => ['artifactLocation' => ['uri' => $f->file], 'region' => ['startLine' => $f->line]]]],
                ], $findings),
            ]],
        ];
    }
}
