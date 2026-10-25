<?php

declare(strict_types=1);

namespace ComposerGuard;

final readonly class Finding
{
    public function __construct(
        public string $checkId,
        public Severity $severity,
        /** Package name, or the config key the finding is about. */
        public string $target,
        public string $file,
        public int $line,
        public string $message,
        public string $help = '',
    ) {
    }
}
