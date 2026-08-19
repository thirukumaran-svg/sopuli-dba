# Changelog

## [0.25.0](https://github.com/futville/sopuli-dba/compare/v0.24.0...v0.25.0) (2026-08-18)


### Features

* **config:** a vault's transport settings — namespace, timeout_s and tls: ([#141](https://github.com/futville/sopuli-dba/issues/141)) ([1fd4547](https://github.com/futville/sopuli-dba/commit/1fd454716e450f196f3bd5a89d83ab2372d09186))
* **packaging:** extras in pyproject, and a store registry that imports lazily ([#139](https://github.com/futville/sopuli-dba/issues/139)) ([f02247e](https://github.com/futville/sopuli-dba/commit/f02247ec2c917c83f0e1501b0c4caeba8c1dbf57))
* **vault:** HashiCorp auth methods — token, AppRole, Kubernetes, userpass ([#146](https://github.com/futville/sopuli-dba/issues/146)) ([1d3b128](https://github.com/futville/sopuli-dba/commit/1d3b128ec03ff8ed13ccb92e3003db0267df65b4))
* **vault:** HashiCorp KV v2 store adapter, conformance-tested against the fake ([#142](https://github.com/futville/sopuli-dba/issues/142)) ([216d57b](https://github.com/futville/sopuli-dba/commit/216d57b2bc379e1d5c6a2b2815da7f0bf365c3e7))
* **vault:** resolve a MaterialRef to a Secret — env, file, and the token chain ([#144](https://github.com/futville/sopuli-dba/issues/144)) ([766257d](https://github.com/futville/sopuli-dba/commit/766257db620dd0e04ea4c486a0e4a39736570f10))


### Bug Fixes

* **test:** race the lock on a handshake, not on a guess about startup time ([#148](https://github.com/futville/sopuli-dba/issues/148)) ([cf25879](https://github.com/futville/sopuli-dba/commit/cf258796f36c61043197e997277f21a54cdec84c))

## [0.24.0](https://github.com/futville/sopuli-dba/compare/v0.23.0...v0.24.0) (2026-08-18)


### Features

* **config:** decide C15 — refuse a binding with no store only when vaults: is empty ([#126](https://github.com/futville/sopuli-dba/issues/126)) ([a1322e5](https://github.com/futville/sopuli-dba/commit/a1322e5ade3218ed7d3a2f884cb7534834e36132))

## [0.23.0](https://github.com/futville/sopuli-dba/compare/v0.22.0...v0.23.0) (2026-08-17)


### Features

* **config:** detect shared secrets, and show them in `config show --resolved` ([#110](https://github.com/futville/sopuli-dba/issues/110)) ([#117](https://github.com/futville/sopuli-dba/issues/117)) ([0849a3a](https://github.com/futville/sopuli-dba/commit/0849a3acfcab25d27685b4391ea34e07bb550e0b))
* **config:** refuse an unstageable secret ref while the file is read ([#111](https://github.com/futville/sopuli-dba/issues/111)) ([#113](https://github.com/futville/sopuli-dba/issues/113)) ([ef55726](https://github.com/futville/sopuli-dba/commit/ef55726ce1ace4f1114da5da81707eadc173643a))

## [0.22.0](https://github.com/futville/sopuli-dba/compare/v0.21.0...v0.22.0) (2026-08-17)


### Features

* **payload:** one secret per application by default, one rule for both layouts ([#85](https://github.com/futville/sopuli-dba/issues/85)) ([#109](https://github.com/futville/sopuli-dba/issues/109)) ([02a5871](https://github.com/futville/sopuli-dba/commit/02a5871ae9af74b0e1b5cc399f960686e7e0c1b4))

## [0.21.0](https://github.com/futville/sopuli-dba/compare/v0.20.0...v0.21.0) (2026-08-16)


### Features

* **config:** `vaults.*.locking` and `locking.break_expired` ([#83](https://github.com/futville/sopuli-dba/issues/83)) ([#108](https://github.com/futville/sopuli-dba/issues/108)) ([7aef5c5](https://github.com/futville/sopuli-dba/commit/7aef5c533c1afe442ceab71dd22d42d4efc5eb36))
* **lock:** a LockManager over a narrow store protocol ([#83](https://github.com/futville/sopuli-dba/issues/83)) ([#101](https://github.com/futville/sopuli-dba/issues/101)) ([8384e57](https://github.com/futville/sopuli-dba/commit/8384e57e23df4757a95e3788e205230ac48a1f48))
* **lock:** the lock record and its state machine, as tier-0 logic ([#83](https://github.com/futville/sopuli-dba/issues/83)) ([#100](https://github.com/futville/sopuli-dba/issues/100)) ([09320f5](https://github.com/futville/sopuli-dba/commit/09320f5b308ecfb4ca1b7c93098cde4cfcf31eac))
* **output:** emit the lock section, exit 7, and the first warning codes ([#83](https://github.com/futville/sopuli-dba/issues/83)) ([#102](https://github.com/futville/sopuli-dba/issues/102)) ([cb2cc68](https://github.com/futville/sopuli-dba/commit/cb2cc68bd62986191f4d2f351a775efe358c176b))
* **output:** record the Q2 advisory-lock decision, run schema 1.5 ([#98](https://github.com/futville/sopuli-dba/issues/98)) ([8d6f28b](https://github.com/futville/sopuli-dba/commit/8d6f28b5e17bc414ae1cdcdb93a76100c0c1e498))

## [0.20.0](https://github.com/futville/sopuli-dba/compare/v0.19.0...v0.20.0) (2026-08-16)


### ⚠ BREAKING CHANGES

* **config:** decide the SecretRef qualifier vocabularies (C14) ([#92](https://github.com/futville/sopuli-dba/issues/92))

### Features

* **config:** decide the SecretRef qualifier vocabularies (C14) ([#92](https://github.com/futville/sopuli-dba/issues/92)) ([59ab70b](https://github.com/futville/sopuli-dba/commit/59ab70b3e07e094c8a0404459da121ae2941a79c))

## [0.19.0](https://github.com/futville/sopuli-dba/compare/v0.18.0...v0.19.0) (2026-08-13)


### Features

* **config:** show where every effective setting came from, with --explain ([#81](https://github.com/futville/sopuli-dba/issues/81)) ([750654b](https://github.com/futville/sopuli-dba/commit/750654bb76ef015d55d3bdf5c789110644cee4b9))

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
