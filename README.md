# composer-guard

[![ci](https://github.com/OTA-EITA/composer-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/OTA-EITA/composer-guard/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/OTA-EITA/composer-guard/badge)](https://securityscorecards.dev/viewer/?uri=github.com/OTA-EITA/composer-guard)

**Supply-chain checks for PHP projects that `composer audit` doesn't do.**

`composer audit` knows about published advisories, malware and abandoned packages. composer-guard looks at the things that let a _not-yet-known_ attack in: versions released a few days ago, Composer plugins allowed to run code during install, packages fetched without TLS, dependencies locked to a moving branch, repositories open to dependency confusion — and at settings that switch off the protection Composer already has, such as advisory and malware blocking. It reads `composer.json` and `composer.lock` only — no network, no dependencies, plain PHP.

```text
$ bin/composer-guard tests/fixtures/risky
tests/fixtures/risky/composer.json:10  HIGH   CG005  repository http://packages.acme.internal is fetched over plain HTTP
tests/fixtures/risky/composer.json:18  HIGH   CG003  config.secure-http is false: Composer may download packages over plain HTTP
tests/fixtures/risky/composer.json:19  HIGH   CG004  config.disable-tls is true: Composer fetches every HTTPS URL over plain HTTP
tests/fixtures/risky/composer.json:22  HIGH   CG008  script "post-install-cmd" pipes a downloaded script into a shell
tests/fixtures/risky/composer.lock:6  HIGH   CG007  acme/installer-plugin@1.4.0 was released less than a day ago and is a Composer plugin, which runs code during install
tests/fixtures/risky/composer.lock:13  HIGH   CG005  acme/legacy-sdk@2.1.0 is downloaded over plain HTTP (dist: http://packages.acme.internal/dist/legacy-sdk-2.1.0.zip)
tests/fixtures/risky/composer.json:15  MEDIUM CG002  config.allow-plugins allows "acme/*" to run code during install
tests/fixtures/risky/composer.lock:3  MEDIUM CG013  composer.lock is out of date with composer.json: composer install ignores the changes and installs the old locked versions
tests/fixtures/risky/composer.lock:20  MEDIUM CG006  acme/payments@dev-main is locked to a branch
tests/fixtures/risky/composer.lock:27  MEDIUM CG007  monolog/monolog@3.9.0 was released 3 day(s) ago

1 project(s), 10 finding(s): 6 high, 4 medium, 0 low
```

## Why a cooldown matters for Composer

npm, pnpm and Yarn can all refuse versions younger than N days. Composer has no built-in setting for that: its `policy` options block versions flagged by advisories, as malware or as abandoned, or listed by a custom policy service you run yourself. Yet most hijacked releases are found and pulled within days, and `composer.lock` already records when each locked version was released (`"time"`). composer-guard reads that field, so the check needs no network and works on any lock file.

When something is too fresh, hold it back without a permanent constraint:

```sh
composer update --with "vendor/package:<1.2.3"
```

## Checks

| ID    | Severity | What it finds                                                                                                                                            |
| ----- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CG001 | high     | `config.allow-plugins: true` or `"*": true` — every plugin in the dependency tree may run code during install (Composer's docs: _"NOT recommended"_)     |
| CG002 | medium   | Vendor wildcards such as `"acme/*": true`                                                                                                                |
| CG003 | high     | `config.secure-http: false`                                                                                                                              |
| CG004 | high     | `config.disable-tls: true`                                                                                                                               |
| CG005 | high     | Repositories or locked packages fetched over `http://`                                                                                                   |
| CG006 | medium   | Packages locked to a branch (`dev-main`), whose contents change with every push (`roave/security-advisories` is exempt: it is meant to be used that way) |
| CG007 | medium   | Versions released less than `--min-age` days ago (default 7); **high** for Composer plugins, which run code at install time                              |
| CG008 | high     | Composer scripts that pipe a downloaded script into a shell                                                                                              |
| CG009 | medium   | `minimum-stability` below `stable` without `"prefer-stable": true`: Composer then installs the newest pre-release or branch even when a stable release matches ([docs](https://getcomposer.org/doc/04-schema.md#prefer-stable))     |
| CG010 | medium   | Repositories with `"canonical": false`: a higher version of the same package name on Packagist can replace yours — dependency confusion ([docs](https://getcomposer.org/doc/articles/repository-priorities.md#canonical-repositories)) |
| CG011 | high     | `config.policy: false`, advisory or malware blocking turned off (`policy.advisories.block`, `policy.malware.block`, deprecated `audit.block-insecure`); **medium** for `policy.malware.block-scope` other than `all` ([docs](https://getcomposer.org/doc/06-config.md#policy)) |
| CG012 | medium   | `composer audit` made to pass (`policy.advisories.audit` / `policy.malware.audit` set to `report` or `ignore`), whole severity levels ignored, malware reports ignored; **low** for an advisory ignored without a reason ([docs](https://getcomposer.org/doc/06-config.md#ignore-id)) |
| CG013 | medium   | `composer.lock` out of date: its `content-hash` does not match `composer.json`, computed offline the way Composer does, so `composer install` keeps the old locked set ([docs](https://getcomposer.org/doc/01-basic-usage.md#installing-from-composer-lock)) |

## Tested on real projects

| Project                                                             | Locked packages | Findings                                                                |
| ------------------------------------------------------------------- | --------------- | ----------------------------------------------------------------------- |
| [symfony/demo](https://github.com/symfony/demo) (8d2e2ef)           | 153             | none                                                                    |
| [monicahq/monica](https://github.com/monicahq/monica) (6e6ec21)     | 241             | none                                                                    |
| [matomo-org/matomo](https://github.com/matomo-org/matomo) (272da0b) | 87              | 2 versions released 4–6 days earlier, 4 packages locked to `dev-master` |

Checked on 2026-10-27 with v0.2.0. None of the three trips CG009–CG013: all keep `minimum-stability` at `stable` (or leave it unset), use only canonical repositories, leave `config.policy` and `config.audit` at their defaults, and commit a lock file whose `content-hash` matches `composer.json`. The `content-hash` computation was also compared with Composer 2.10's own `Locker::getContentHash()` on 32 real `composer.json` files, with no mismatch.

## Usage

```sh
git clone https://github.com/OTA-EITA/composer-guard
composer-guard/bin/composer-guard path/to/project     # one project
composer-guard/bin/composer-guard packages/           # every composer.json below a directory (monorepos)
```

It has no dependencies, so the script runs straight from the checkout. In CI, use the GitHub Action below.

| Option          | Default  |                                                                           |
| --------------- | -------- | ------------------------------------------------------------------------- |
| `--min-age`     | `7`      | Report versions released fewer than this many days ago                    |
| `--format`      | `text`   | `text`, `json`, `markdown` or `sarif`                                     |
| `--fail-on`     | `medium` | Exit 1 on findings at least this severe (`high`, `medium`, `low`, `none`) |
| `--list-checks` |          | Print the checks                                                          |

PHP 8.2 or later; no extensions beyond `json`.

### GitHub Actions

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v5
    with:
      persist-credentials: false
  - uses: OTA-EITA/composer-guard@v0.2.0 # pin to a commit SHA in real use
    id: guard
    with:
      fail-on: high
  - uses: github/codeql-action/upload-sarif@v4
    if: always()
    with:
      sarif_file: ${{ steps.guard.outputs.sarif-file }}
      category: composer-guard
```

The action runs on the PHP that GitHub's Ubuntu runners already have, with nothing to install. Run it before `composer install`, together with `composer audit`.

## Development

```sh
composer install --no-plugins --no-scripts
vendor/bin/phpunit
vendor/bin/phpstan analyse   # level max
```

The dev dependencies are locked to versions released at least 7 days ago — checked by composer-guard itself in CI.

## Related

- [lockfile-guard](https://github.com/OTA-EITA/lockfile-guard): the same idea for `package-lock.json`

## License

MIT
