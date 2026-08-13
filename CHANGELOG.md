# Changelog

## [0.18.0](https://github.com/futville/sopuli-dba/compare/v0.17.0...v0.18.0) (2026-08-13)


### ⚠ BREAKING CHANGES

* **cli:** split usage from configuration errors, and state J7's rule ([#77](https://github.com/futville/sopuli-dba/issues/77))

### Features

* **cli:** emit a run document for every exit but 2 ([#79](https://github.com/futville/sopuli-dba/issues/79)) ([c36a723](https://github.com/futville/sopuli-dba/commit/c36a72335942afb51048b22704ce6174eda227cc))
* **cli:** split usage from configuration errors, and state J7's rule ([#77](https://github.com/futville/sopuli-dba/issues/77)) ([38bd55f](https://github.com/futville/sopuli-dba/commit/38bd55fb319610c576dfe5b79909cfe73828936e))

## [0.17.0](https://github.com/futville/sopuli-dba/compare/v0.16.0...v0.17.0) (2026-08-13)


### Features

* **cli:** resolve every global option through one precedence chain ([#75](https://github.com/futville/sopuli-dba/issues/75)) ([02531aa](https://github.com/futville/sopuli-dba/commit/02531aa791158a09da06228f57d3fe25274120dc))
* **settings:** resolve a setting across P3's layers, with a safety ratchet ([#73](https://github.com/futville/sopuli-dba/issues/73)) ([75d4513](https://github.com/futville/sopuli-dba/commit/75d4513ac43a761412ab04d6d12b7adbe2edf83a))

## [0.16.0](https://github.com/futville/sopuli-dba/compare/v0.15.0...v0.16.0) (2026-08-12)


### Features

* show what a password policy produces, with policy sample ([#69](https://github.com/futville/sopuli-dba/issues/69)) ([3e79280](https://github.com/futville/sopuli-dba/commit/3e792803cc1da441ff9968dbc893f211960f504d)), closes [#68](https://github.com/futville/sopuli-dba/issues/68)


### Bug Fixes

* **config:** say what to write in a missing auth key, not which one ([#71](https://github.com/futville/sopuli-dba/issues/71)) ([4f4a228](https://github.com/futville/sopuli-dba/commit/4f4a2286191c112313b61d8153a083bc4a9a9973)), closes [#70](https://github.com/futville/sopuli-dba/issues/70)

## [0.15.0](https://github.com/futville/sopuli-dba/compare/v0.14.0...v0.15.0) (2026-08-12)


### Features

* **config:** adopt the run document's scope vocabulary, as an assertion ([#65](https://github.com/futville/sopuli-dba/issues/65)) ([96f75f3](https://github.com/futville/sopuli-dba/commit/96f75f3027e234d4eaab17ee72acc8e2b285cac9)), closes [#27](https://github.com/futville/sopuli-dba/issues/27)
* **config:** name the database admin credential, in the vault grammar ([#64](https://github.com/futville/sopuli-dba/issues/64)) ([a7edd5b](https://github.com/futville/sopuli-dba/commit/a7edd5be9518366f57edc77e049582ff18cbbf1f)), closes [#27](https://github.com/futville/sopuli-dba/issues/27)
* **config:** point at vault auth material with a MaterialRef ([#63](https://github.com/futville/sopuli-dba/issues/63)) ([7d0d287](https://github.com/futville/sopuli-dba/commit/7d0d287d43f4711355099d6f42df46aa4b2922fd)), closes [#27](https://github.com/futville/sopuli-dba/issues/27)
* generate passwords from a policy, as tier 0 logic ([#67](https://github.com/futville/sopuli-dba/issues/67)) ([2008a5f](https://github.com/futville/sopuli-dba/commit/2008a5faa40b604c5f24bc54d03322b018bf8340)), closes [#58](https://github.com/futville/sopuli-dba/issues/58)

## [0.14.0](https://github.com/futville/sopuli-dba/compare/v0.13.0...v0.14.0) (2026-08-12)


### Features

* add target list, the estate as its own command ([#61](https://github.com/futville/sopuli-dba/issues/61)) ([52f17f5](https://github.com/futville/sopuli-dba/commit/52f17f583ecde962012759820ec2ba5705bf5ec2))

## [0.13.0](https://github.com/futville/sopuli-dba/compare/v0.12.1...v0.13.0) (2026-08-12)


### Features

* filter the expanded estate with --select over target labels ([#59](https://github.com/futville/sopuli-dba/issues/59)) ([90e133d](https://github.com/futville/sopuli-dba/commit/90e133db03591d8c71b160b61fdb9c3de36b60fa))

## [0.12.1](https://github.com/futville/sopuli-dba/compare/v0.12.0...v0.12.1) (2026-08-12)


### Bug Fixes

* report config warnings as diagnostics from config show ([#54](https://github.com/futville/sopuli-dba/issues/54)) ([93f67a8](https://github.com/futville/sopuli-dba/commit/93f67a83f7562cc989b5a3dc7e6993489ddf8686))

## [0.12.0](https://github.com/futville/sopuli-dba/compare/v0.11.0...v0.12.0) (2026-08-11)


### Features

* **config:** publish the config JSON Schema, generated from the model ([#49](https://github.com/futville/sopuli-dba/issues/49)) ([68df689](https://github.com/futville/sopuli-dba/commit/68df689d00b3d4cce43855dcd54667c0d1732de4))

## [0.11.0](https://github.com/futville/sopuli-dba/compare/v0.10.0...v0.11.0) (2026-08-11)


### Features

* colour the text output, semantically ([#47](https://github.com/futville/sopuli-dba/issues/47)) ([b2b08bd](https://github.com/futville/sopuli-dba/commit/b2b08bdde2cead98f6656d5f59151dadc5f92c19))

## [0.10.0](https://github.com/futville/sopuli-dba/compare/v0.9.0...v0.10.0) (2026-08-11)


### Features

* bind accounts to targets, and resolve every secret ref ([#43](https://github.com/futville/sopuli-dba/issues/43)) ([7642fe2](https://github.com/futville/sopuli-dba/commit/7642fe2437fafc4f7e63271fefd52fc4cc538e3b))
* render config show, as loaded and as resolved ([#45](https://github.com/futville/sopuli-dba/issues/45)) ([0407c7e](https://github.com/futville/sopuli-dba/commit/0407c7e946f1d7d9d27c7d6eac2256eadee1f4dd))

## [0.9.0](https://github.com/futville/sopuli-dba/compare/v0.8.0...v0.9.0) (2026-08-11)


### Features

* parse SecretRefs, and check every ref in the file ([#39](https://github.com/futville/sopuli-dba/issues/39)) ([d24d1c5](https://github.com/futville/sopuli-dba/commit/d24d1c59997a551a616fee392a25992aa5af00b1))

## [0.8.0](https://github.com/futville/sopuli-dba/compare/v0.7.0...v0.8.0) (2026-08-11)


### Features

* find and layer config files, and load them in config show ([#37](https://github.com/futville/sopuli-dba/issues/37)) ([0aae6fb](https://github.com/futville/sopuli-dba/commit/0aae6fbf2d882e7cf655e4d2bfc354e8184f737c))

## [0.7.0](https://github.com/futville/sopuli-dba/compare/v0.6.0...v0.7.0) (2026-08-11)


### Features

* expand target sets into targets, with labels and overrides ([#35](https://github.com/futville/sopuli-dba/issues/35)) ([dfbab9b](https://github.com/futville/sopuli-dba/commit/dfbab9bef1531ff4eaef7cf70c4802da228615b3))

## [0.6.0](https://github.com/futville/sopuli-dba/compare/v0.5.0...v0.6.0) (2026-08-10)


### Features

* model policies, profiles, defaults and runtime, and resolve every name ([#32](https://github.com/futville/sopuli-dba/issues/32)) ([d55ab8b](https://github.com/futville/sopuli-dba/commit/d55ab8b3b8ca3dcfe736f6e38f15c7cf5ce046b0))

## [0.5.0](https://github.com/futville/sopuli-dba/compare/v0.4.0...v0.5.0) (2026-08-10)


### Features

* model and validate the estate sections ([#28](https://github.com/futville/sopuli-dba/issues/28)) ([9c9be8a](https://github.com/futville/sopuli-dba/commit/9c9be8a8e581b8f1f38c2d6ce749fcb35c88aeff))

## [0.4.0](https://github.com/futville/sopuli-dba/compare/v0.3.0...v0.4.0) (2026-08-10)


### Features

* model and validate the application binding ([#25](https://github.com/futville/sopuli-dba/issues/25)) ([34f6064](https://github.com/futville/sopuli-dba/commit/34f60644614dbcc5ab0edd41b120ccfc30b38c09))

## [0.3.0](https://github.com/futville/sopuli-dba/compare/v0.2.0...v0.3.0) (2026-08-09)


### Features

* load and validate the config file layer ([#22](https://github.com/futville/sopuli-dba/issues/22)) ([4dbae7e](https://github.com/futville/sopuli-dba/commit/4dbae7eedee1990dc8592682d81bc9781a273273))

## [0.2.0](https://github.com/futville/sopuli-dba/compare/v0.1.1...v0.2.0) (2026-08-09)


### Features

* add --color, NO_COLOR and TTY detection to text output ([#17](https://github.com/futville/sopuli-dba/issues/17)) ([65e685d](https://github.com/futville/sopuli-dba/commit/65e685d51953858cc84b312239d2430fe1dee73c))

## [0.1.1](https://github.com/futville/sopuli-dba/compare/v0.1.0...v0.1.1) (2026-08-09)


### Bug Fixes

* write UTF-8 to stdin, stdout and stderr regardless of redirection ([#14](https://github.com/futville/sopuli-dba/issues/14)) ([9e41cda](https://github.com/futville/sopuli-dba/commit/9e41cda86e0e57e3d2c56811fb32cab0a06c35c2))

## 0.1.0 (2026-08-09)


### Features

* bootstrap sopuli CLI skeleton ([#7](https://github.com/futville/sopuli-dba/issues/7)) ([db47cc2](https://github.com/futville/sopuli-dba/commit/db47cc283243d552b7aa07ed72d36116f2ae8d09))
