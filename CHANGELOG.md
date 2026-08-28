# Changelog

## [0.42.0](https://github.com/villebase/sopuli-dba/compare/v0.41.0...v0.42.0) (2026-08-28)


### Features

* **doctor:** the install-shape section, present on every run ([#214](https://github.com/villebase/sopuli-dba/issues/214)) ([#237](https://github.com/villebase/sopuli-dba/issues/237)) ([c374fd4](https://github.com/villebase/sopuli-dba/commit/c374fd47bc509706cdf94badc53359840483877d))
* **doctor:** wallet readability under `auth: external` ([#215](https://github.com/villebase/sopuli-dba/issues/215)) ([#241](https://github.com/villebase/sopuli-dba/issues/241)) ([f4706b6](https://github.com/villebase/sopuli-dba/commit/f4706b600802773b106defa75a26665b5b7475bd))

## [0.41.0](https://github.com/villebase/sopuli-dba/compare/v0.40.0...v0.41.0) (2026-08-26)


### Features

* **doctor:** the positive side of --check-privileges, and schema 1.12 ([#225](https://github.com/villebase/sopuli-dba/issues/225)) ([#227](https://github.com/villebase/sopuli-dba/issues/227)) ([b9bcab4](https://github.com/villebase/sopuli-dba/commit/b9bcab431f4816d52c8e291e4c99ccd65e093184))
* **sql:** pass the operator scripts their parameters ([#229](https://github.com/villebase/sopuli-dba/issues/229)) ([#234](https://github.com/villebase/sopuli-dba/issues/234)) ([65fcea1](https://github.com/villebase/sopuli-dba/commit/65fcea1704380c99107d1c914db6995a59f27a8d))


### Bug Fixes

* **sql:** four bugs in the operator scripts, found by executing them ([#232](https://github.com/villebase/sopuli-dba/issues/232)) ([c3153f7](https://github.com/villebase/sopuli-dba/commit/c3153f74b079e4c9e34d19821996aa9837c16dcb))

## [0.40.0](https://github.com/villebase/sopuli-dba/compare/v0.39.0...v0.40.0) (2026-08-26)


### Features

* **doctor:** --check-privileges — report what the account should not hold ([#213](https://github.com/villebase/sopuli-dba/issues/213)) ([#224](https://github.com/villebase/sopuli-dba/issues/224)) ([33c5853](https://github.com/villebase/sopuli-dba/commit/33c58534b0eb970daceff53cd923f2dcaf5cf64a))
* **store:** read a credential — resolve a SecretRef against a stored document ([#183](https://github.com/villebase/sopuli-dba/issues/183)) ([#221](https://github.com/villebase/sopuli-dba/issues/221)) ([59b32f0](https://github.com/villebase/sopuli-dba/commit/59b32f0150995914c0fbda87e684998b76f759b4))
* **store:** write a credential — a merge patch that leaves siblings alone ([#183](https://github.com/villebase/sopuli-dba/issues/183)) ([#223](https://github.com/villebase/sopuli-dba/issues/223)) ([9bd9153](https://github.com/villebase/sopuli-dba/commit/9bd91537dc7cecbdcb5d6583ef9eb1ce2213e37c))

## [0.39.0](https://github.com/futville/sopuli-dba/compare/v0.38.0...v0.39.0) (2026-08-22)


### Features

* **cli:** sopuli doctor — connect to every target and mutate nothing ([#182](https://github.com/futville/sopuli-dba/issues/182)) ([#212](https://github.com/futville/sopuli-dba/issues/212)) ([8652117](https://github.com/futville/sopuli-dba/commit/86521174ac2f9d1d1f580aaa3ae39a79fc97820c))
* **driver:** gradual password rollover — the check, the window, the finish ([#181](https://github.com/futville/sopuli-dba/issues/181)) ([#210](https://github.com/futville/sopuli-dba/issues/210)) ([1c41882](https://github.com/futville/sopuli-dba/commit/1c4188270d3b39c472920e9b030c137a3c1e9083))

## [0.38.0](https://github.com/futville/sopuli-dba/compare/v0.37.0...v0.38.0) (2026-08-22)


### Features

* **driver:** check the scope a target asserts against the one it reached ([#177](https://github.com/futville/sopuli-dba/issues/177)) ([#206](https://github.com/futville/sopuli-dba/issues/206)) ([ca4bbdb](https://github.com/futville/sopuli-dba/commit/ca4bbdbb2ff4dc7ac011649e703a159c172c3fc0))
* **driver:** issue the ALTER USER, and let a rejection be a rejection ([#179](https://github.com/futville/sopuli-dba/issues/179)) ([#208](https://github.com/futville/sopuli-dba/issues/208)) ([febc475](https://github.com/futville/sopuli-dba/commit/febc475b6b5f929c80ffde7610857f678afe92de))
* **driver:** probe capabilities and resolve scope on connect ([#177](https://github.com/futville/sopuli-dba/issues/177)) ([#203](https://github.com/futville/sopuli-dba/issues/203)) ([002f946](https://github.com/futville/sopuli-dba/commit/002f94676a350f737bc3ead464107c267722f0ec))
* **driver:** read an account's state from DBA_USERS and DBA_PROFILES ([#178](https://github.com/futville/sopuli-dba/issues/178)) ([#207](https://github.com/futville/sopuli-dba/issues/207)) ([4b21ac5](https://github.com/futville/sopuli-dba/commit/4b21ac53fe51c3ef2102ce55f301f8b7ca0c2d81))

## [0.37.0](https://github.com/futville/sopuli-dba/compare/v0.36.0...v0.37.0) (2026-08-21)


### Features

* **driver:** connect in thick mode, with the run's id on the session ([#201](https://github.com/futville/sopuli-dba/issues/201)) ([0b4a77a](https://github.com/futville/sopuli-dba/commit/0b4a77ada439b463f29c98e59f0a70a66a6bbff2))

## [0.36.0](https://github.com/futville/sopuli-dba/compare/v0.35.0...v0.36.0) (2026-08-21)


### Features

* **admin:** resolve the admin credential from P2's four sources ([#196](https://github.com/futville/sopuli-dba/issues/196)) ([1c38ea2](https://github.com/futville/sopuli-dba/commit/1c38ea2572b2aab0a9502ac09a04545cbc09452b))

## [0.35.0](https://github.com/futville/sopuli-dba/compare/v0.34.0...v0.35.0) (2026-08-21)


### Features

* **testing:** capability probing, skip markers and the matrix report ([#192](https://github.com/futville/sopuli-dba/issues/192)) ([60ba98c](https://github.com/futville/sopuli-dba/commit/60ba98ccc2f262b8322431cc451b8cbb63057bf8))

## [0.34.0](https://github.com/futville/sopuli-dba/compare/v0.33.0...v0.34.0) (2026-08-20)


### Features

* **driver:** a driver registry, and the mechanism it shares with stores ([#190](https://github.com/futville/sopuli-dba/issues/190)) ([3855543](https://github.com/futville/sopuli-dba/commit/3855543197b735203c7da61fb303961d90baf4f7))

## [0.33.0](https://github.com/futville/sopuli-dba/compare/v0.32.0...v0.33.0) (2026-08-20)


### Features

* **driver:** the client-side account guardrails, and what `--force` overrides ([#189](https://github.com/futville/sopuli-dba/issues/189)) ([45b4aae](https://github.com/futville/sopuli-dba/commit/45b4aae11a8b43171aff04312bb1a99158cdd25d))
* **driver:** the P1 driver interface, as types and vocabulary ([#185](https://github.com/futville/sopuli-dba/issues/185)) ([13743a1](https://github.com/futville/sopuli-dba/commit/13743a1f9fe1cd8df622a83cb2ce8fe0ef989d07))
* **oracle:** build ALTER USER directly, and refuse rather than escape ([#187](https://github.com/futville/sopuli-dba/issues/187)) ([60cfc52](https://github.com/futville/sopuli-dba/commit/60cfc528d66555ca6fc55cd7521a8773f249995d))
* **oracle:** map ORA- codes to a category, an exit code and a hint ([#188](https://github.com/futville/sopuli-dba/issues/188)) ([0e7b1ec](https://github.com/futville/sopuli-dba/commit/0e7b1ecf1f61f48ff6fde34d89d1778fce2215cf))

## [0.32.0](https://github.com/futville/sopuli-dba/compare/v0.31.0...v0.32.0) (2026-08-20)


### Features

* **lock:** `sopuli lock break` — take a lock from its holder, and fence them ([#167](https://github.com/futville/sopuli-dba/issues/167)) ([0e698a7](https://github.com/futville/sopuli-dba/commit/0e698a74c0566bcb980013f4053c02f970912770))

## [0.31.0](https://github.com/futville/sopuli-dba/compare/v0.30.0...v0.31.0) (2026-08-20)


### Features

* **config:** `SOPULI_VAULT__<NAME>__*` and the layer-3 vault variables ([#165](https://github.com/futville/sopuli-dba/issues/165)) ([d159d98](https://github.com/futville/sopuli-dba/commit/d159d98e40091fe46e0d4be794306a82b1f4062f))

## [0.30.0](https://github.com/futville/sopuli-dba/compare/v0.29.0...v0.30.0) (2026-08-19)


### Features

* **config:** activate a profile, so precedence layer 3 is reachable ([#163](https://github.com/futville/sopuli-dba/issues/163)) ([654f187](https://github.com/futville/sopuli-dba/commit/654f18756227d91a07495714918972f69f39d9b5)), closes [#153](https://github.com/futville/sopuli-dba/issues/153)

## [0.29.0](https://github.com/futville/sopuli-dba/compare/v0.28.0...v0.29.0) (2026-08-19)


### Features

* **lock:** `lock status` reports records the config does not declare ([#161](https://github.com/futville/sopuli-dba/issues/161)) ([65ed0a4](https://github.com/futville/sopuli-dba/commit/65ed0a49b290165caa60b52d5a52948017fb1118))
* **store:** `list(prefix)` on the store protocol, and both KV mounts ([#159](https://github.com/futville/sopuli-dba/issues/159)) ([070d4bc](https://github.com/futville/sopuli-dba/commit/070d4bc4cddf6d66c42067d7159239ad02e26714))

## [0.28.0](https://github.com/futville/sopuli-dba/compare/v0.27.0...v0.28.0) (2026-08-19)


### Features

* **vault:** `--vault-token-file` takes a path; `--vault-token` is refused ([#157](https://github.com/futville/sopuli-dba/issues/157)) ([2a97b1d](https://github.com/futville/sopuli-dba/commit/2a97b1d4260b44e5316fddbb89ae851fbf1e6dcc))

## [0.27.0](https://github.com/futville/sopuli-dba/compare/v0.26.0...v0.27.0) (2026-08-19)


### Features

* **config:** partial `vaults:` blocks, and the file's layers of the merge ([#155](https://github.com/futville/sopuli-dba/issues/155)) ([5ff9051](https://github.com/futville/sopuli-dba/commit/5ff90519f370285c542562cb544084cda15ba754))

## [0.26.0](https://github.com/futville/sopuli-dba/compare/v0.25.0...v0.26.0) (2026-08-19)


### Features

* **lock:** `sopuli lock status` — what is held, by whom, and since when ([#151](https://github.com/futville/sopuli-dba/issues/151)) ([57b4bcf](https://github.com/futville/sopuli-dba/commit/57b4bcffa216df8e47c60ba220c8b25040a35fee))

## [0.25.0](https://github.com/futville/sopuli-dba/compare/v0.24.0...v0.25.0) (2026-08-18)


### Features

* **config:** a vault's transport settings — namespace, timeout_s and tls: ([#141](https://github.com/futville/sopuli-dba/issues/141)) ([10e683b](https://github.com/futville/sopuli-dba/commit/10e683b018c0a306231f631d50339f9143904822))
* **packaging:** extras in pyproject, and a store registry that imports lazily ([#139](https://github.com/futville/sopuli-dba/issues/139)) ([7a8a14e](https://github.com/futville/sopuli-dba/commit/7a8a14efcbc42572232ff63c70b50df9bb6ff7ca))
* **vault:** HashiCorp auth methods — token, AppRole, Kubernetes, userpass ([#146](https://github.com/futville/sopuli-dba/issues/146)) ([e16a79e](https://github.com/futville/sopuli-dba/commit/e16a79eab441bf7148e530b07e9b945013991a8f))
* **vault:** HashiCorp KV v2 store adapter, conformance-tested against the fake ([#142](https://github.com/futville/sopuli-dba/issues/142)) ([8f3700d](https://github.com/futville/sopuli-dba/commit/8f3700d05c1f449e1ecb1ec77b33966e9f4b6330))
* **vault:** resolve a MaterialRef to a Secret — env, file, and the token chain ([#144](https://github.com/futville/sopuli-dba/issues/144)) ([49d2b6d](https://github.com/futville/sopuli-dba/commit/49d2b6d1189f0f78105c182fb1d2c7ec89ac43ae))


### Bug Fixes

* **test:** race the lock on a handshake, not on a guess about startup time ([#148](https://github.com/futville/sopuli-dba/issues/148)) ([04b9b84](https://github.com/futville/sopuli-dba/commit/04b9b841d6158bbe5c9f04b87f6887ebc1fa5bf9))

## [0.24.0](https://github.com/futville/sopuli-dba/compare/v0.23.0...v0.24.0) (2026-08-18)


### Features

* **config:** decide C15 — refuse a binding with no store only when vaults: is empty ([#126](https://github.com/futville/sopuli-dba/issues/126)) ([d2faa81](https://github.com/futville/sopuli-dba/commit/d2faa8156f590ab3b73f77eb9df603588dac266f))

## [0.23.0](https://github.com/futville/sopuli-dba/compare/v0.22.0...v0.23.0) (2026-08-17)


### Features

* **config:** detect shared secrets, and show them in `config show --resolved` ([#110](https://github.com/futville/sopuli-dba/issues/110)) ([#117](https://github.com/futville/sopuli-dba/issues/117)) ([994ce81](https://github.com/futville/sopuli-dba/commit/994ce81a770664ea4c457d863a3a16b614bb1cbe))
* **config:** refuse an unstageable secret ref while the file is read ([#111](https://github.com/futville/sopuli-dba/issues/111)) ([#113](https://github.com/futville/sopuli-dba/issues/113)) ([355bfa4](https://github.com/futville/sopuli-dba/commit/355bfa4eb0f5508455255403f3bc95d43de81e51))

## [0.22.0](https://github.com/futville/sopuli-dba/compare/v0.21.0...v0.22.0) (2026-08-17)


### Features

* **payload:** one secret per application by default, one rule for both layouts ([#85](https://github.com/futville/sopuli-dba/issues/85)) ([#109](https://github.com/futville/sopuli-dba/issues/109)) ([5cd9b74](https://github.com/futville/sopuli-dba/commit/5cd9b74c4507f3bc13c98f5b27e99eb25e5e70a1))

## [0.21.0](https://github.com/futville/sopuli-dba/compare/v0.20.0...v0.21.0) (2026-08-16)


### Features

* **config:** `vaults.*.locking` and `locking.break_expired` ([#83](https://github.com/futville/sopuli-dba/issues/83)) ([#108](https://github.com/futville/sopuli-dba/issues/108)) ([4a220d3](https://github.com/futville/sopuli-dba/commit/4a220d335e51b9e3e90937b0bfcd62676307bd8e))
* **lock:** a LockManager over a narrow store protocol ([#83](https://github.com/futville/sopuli-dba/issues/83)) ([#101](https://github.com/futville/sopuli-dba/issues/101)) ([4358348](https://github.com/futville/sopuli-dba/commit/435834869c25b8f67f3d1824af98f10559604b9c))
* **lock:** the lock record and its state machine, as tier-0 logic ([#83](https://github.com/futville/sopuli-dba/issues/83)) ([#100](https://github.com/futville/sopuli-dba/issues/100)) ([476ffc4](https://github.com/futville/sopuli-dba/commit/476ffc490e923279ffdf20f65e7efbe60e9ab51e))
* **output:** emit the lock section, exit 7, and the first warning codes ([#83](https://github.com/futville/sopuli-dba/issues/83)) ([#102](https://github.com/futville/sopuli-dba/issues/102)) ([d0f3872](https://github.com/futville/sopuli-dba/commit/d0f38725ac918a119536374244c998ab5878c95a))
* **output:** record the Q2 advisory-lock decision, run schema 1.5 ([#98](https://github.com/futville/sopuli-dba/issues/98)) ([2056398](https://github.com/futville/sopuli-dba/commit/2056398209a8df4f0a27555f9b40b9dcd3369ed5))

## [0.20.0](https://github.com/futville/sopuli-dba/compare/v0.19.0...v0.20.0) (2026-08-16)


### ⚠ BREAKING CHANGES

* **config:** decide the SecretRef qualifier vocabularies (C14) ([#92](https://github.com/futville/sopuli-dba/issues/92))

### Features

* **config:** decide the SecretRef qualifier vocabularies (C14) ([#92](https://github.com/futville/sopuli-dba/issues/92)) ([5290d6f](https://github.com/futville/sopuli-dba/commit/5290d6ff85d9b4281db98a9165172bd43c8f9912))

## [0.19.0](https://github.com/futville/sopuli-dba/compare/v0.18.0...v0.19.0) (2026-08-13)


### Features

* **config:** show where every effective setting came from, with --explain ([#81](https://github.com/futville/sopuli-dba/issues/81)) ([5ea2318](https://github.com/futville/sopuli-dba/commit/5ea2318a90ebede6f1e61e1dde186232e816f85b))

## [0.18.0](https://github.com/futville/sopuli-dba/compare/v0.17.0...v0.18.0) (2026-08-13)


### ⚠ BREAKING CHANGES

* **cli:** split usage from configuration errors, and state J7's rule ([#77](https://github.com/futville/sopuli-dba/issues/77))

### Features

* **cli:** emit a run document for every exit but 2 ([#79](https://github.com/futville/sopuli-dba/issues/79)) ([c778eae](https://github.com/futville/sopuli-dba/commit/c778eaef99df2f575a332b1f89d7eaa9641145e2))
* **cli:** split usage from configuration errors, and state J7's rule ([#77](https://github.com/futville/sopuli-dba/issues/77)) ([90ccf94](https://github.com/futville/sopuli-dba/commit/90ccf94e022d5b86586c8917db4cf68423a54e68))

## [0.17.0](https://github.com/futville/sopuli-dba/compare/v0.16.0...v0.17.0) (2026-08-13)


### Features

* **cli:** resolve every global option through one precedence chain ([#75](https://github.com/futville/sopuli-dba/issues/75)) ([d91742b](https://github.com/futville/sopuli-dba/commit/d91742bc34a10f46c18888c94c01565f76f2a233))
* **settings:** resolve a setting across P3's layers, with a safety ratchet ([#73](https://github.com/futville/sopuli-dba/issues/73)) ([33a64f4](https://github.com/futville/sopuli-dba/commit/33a64f4f36d18d70a4f9c4a4f5d918257d0c3fa6))

## [0.16.0](https://github.com/futville/sopuli-dba/compare/v0.15.0...v0.16.0) (2026-08-12)


### Features

* show what a password policy produces, with policy sample ([#69](https://github.com/futville/sopuli-dba/issues/69)) ([e23c5e7](https://github.com/futville/sopuli-dba/commit/e23c5e7d4fd7014912adb0e0b4c89c3562183acc)), closes [#68](https://github.com/futville/sopuli-dba/issues/68)


### Bug Fixes

* **config:** say what to write in a missing auth key, not which one ([#71](https://github.com/futville/sopuli-dba/issues/71)) ([082cfe1](https://github.com/futville/sopuli-dba/commit/082cfe10c474c0e07efa615748ac9e9491248b5e)), closes [#70](https://github.com/futville/sopuli-dba/issues/70)

## [0.15.0](https://github.com/futville/sopuli-dba/compare/v0.14.0...v0.15.0) (2026-08-12)


### Features

* **config:** adopt the run document's scope vocabulary, as an assertion ([#65](https://github.com/futville/sopuli-dba/issues/65)) ([ef6c5b0](https://github.com/futville/sopuli-dba/commit/ef6c5b05d0325f2e1fa5616c0ed4a2049c5e9b9a)), closes [#27](https://github.com/futville/sopuli-dba/issues/27)
* **config:** name the database admin credential, in the vault grammar ([#64](https://github.com/futville/sopuli-dba/issues/64)) ([e881c4c](https://github.com/futville/sopuli-dba/commit/e881c4ca9ac4ad476cf917efbe9c8dc0d57a791a)), closes [#27](https://github.com/futville/sopuli-dba/issues/27)
* **config:** point at vault auth material with a MaterialRef ([#63](https://github.com/futville/sopuli-dba/issues/63)) ([274c730](https://github.com/futville/sopuli-dba/commit/274c73083b2816abc5b0f5236983cc12e08e1d55)), closes [#27](https://github.com/futville/sopuli-dba/issues/27)
* generate passwords from a policy, as tier 0 logic ([#67](https://github.com/futville/sopuli-dba/issues/67)) ([c385483](https://github.com/futville/sopuli-dba/commit/c38548365f50d2e414e3975e05b1a75ed301bf6d)), closes [#58](https://github.com/futville/sopuli-dba/issues/58)

## [0.14.0](https://github.com/futville/sopuli-dba/compare/v0.13.0...v0.14.0) (2026-08-12)


### Features

* add target list, the estate as its own command ([#61](https://github.com/futville/sopuli-dba/issues/61)) ([d925977](https://github.com/futville/sopuli-dba/commit/d925977476eee614b931a3c0b430ea17b959c6a7))

## [0.13.0](https://github.com/futville/sopuli-dba/compare/v0.12.1...v0.13.0) (2026-08-12)


### Features

* filter the expanded estate with --select over target labels ([#59](https://github.com/futville/sopuli-dba/issues/59)) ([ee3bdf8](https://github.com/futville/sopuli-dba/commit/ee3bdf82bf7303fb349fa64f245dfd9806faf08f))

## [0.12.1](https://github.com/futville/sopuli-dba/compare/v0.12.0...v0.12.1) (2026-08-12)


### Bug Fixes

* report config warnings as diagnostics from config show ([#54](https://github.com/futville/sopuli-dba/issues/54)) ([9d0dc7e](https://github.com/futville/sopuli-dba/commit/9d0dc7e0841b2c462cfcf6c830b4f7faf5c1cbbe))

## [0.12.0](https://github.com/futville/sopuli-dba/compare/v0.11.0...v0.12.0) (2026-08-11)


### Features

* **config:** publish the config JSON Schema, generated from the model ([#49](https://github.com/futville/sopuli-dba/issues/49)) ([a3ee3f9](https://github.com/futville/sopuli-dba/commit/a3ee3f90f8fd70f1566415b5a5b820afbd74f3e5))

## [0.11.0](https://github.com/futville/sopuli-dba/compare/v0.10.0...v0.11.0) (2026-08-11)


### Features

* colour the text output, semantically ([#47](https://github.com/futville/sopuli-dba/issues/47)) ([b38e13a](https://github.com/futville/sopuli-dba/commit/b38e13ac11ccf7157fdf4ef88dc612e3ea52a878))

## [0.10.0](https://github.com/futville/sopuli-dba/compare/v0.9.0...v0.10.0) (2026-08-11)


### Features

* bind accounts to targets, and resolve every secret ref ([#43](https://github.com/futville/sopuli-dba/issues/43)) ([7848b54](https://github.com/futville/sopuli-dba/commit/7848b54455462c5aaf530c3fdf046ed751642177))
* render config show, as loaded and as resolved ([#45](https://github.com/futville/sopuli-dba/issues/45)) ([83108a7](https://github.com/futville/sopuli-dba/commit/83108a779336546464de960fa194edfb8f6dac88))

## [0.9.0](https://github.com/futville/sopuli-dba/compare/v0.8.0...v0.9.0) (2026-08-11)


### Features

* parse SecretRefs, and check every ref in the file ([#39](https://github.com/futville/sopuli-dba/issues/39)) ([3ee6591](https://github.com/futville/sopuli-dba/commit/3ee659179fe42603d27ab9d8db0a8abdaf672d0d))

## [0.8.0](https://github.com/futville/sopuli-dba/compare/v0.7.0...v0.8.0) (2026-08-11)


### Features

* find and layer config files, and load them in config show ([#37](https://github.com/futville/sopuli-dba/issues/37)) ([ce02d23](https://github.com/futville/sopuli-dba/commit/ce02d23400c3c0a3279684a5792ffc1cd9146572))

## [0.7.0](https://github.com/futville/sopuli-dba/compare/v0.6.0...v0.7.0) (2026-08-11)


### Features

* expand target sets into targets, with labels and overrides ([#35](https://github.com/futville/sopuli-dba/issues/35)) ([ed80879](https://github.com/futville/sopuli-dba/commit/ed808799378faf1646bb6e594d91b31b5613d75f))

## [0.6.0](https://github.com/futville/sopuli-dba/compare/v0.5.0...v0.6.0) (2026-08-10)


### Features

* model policies, profiles, defaults and runtime, and resolve every name ([#32](https://github.com/futville/sopuli-dba/issues/32)) ([449cd88](https://github.com/futville/sopuli-dba/commit/449cd886000892972fa44f82e9132d078ed87f73))

## [0.5.0](https://github.com/futville/sopuli-dba/compare/v0.4.0...v0.5.0) (2026-08-10)


### Features

* model and validate the estate sections ([#28](https://github.com/futville/sopuli-dba/issues/28)) ([75844fa](https://github.com/futville/sopuli-dba/commit/75844fa71dddaa4d0abd44e63ed2c5191ac94dce))

## [0.4.0](https://github.com/futville/sopuli-dba/compare/v0.3.0...v0.4.0) (2026-08-10)


### Features

* model and validate the application binding ([#25](https://github.com/futville/sopuli-dba/issues/25)) ([63f551c](https://github.com/futville/sopuli-dba/commit/63f551c66bda2fe736dd29bb1675fd257116b1d6))

## [0.3.0](https://github.com/futville/sopuli-dba/compare/v0.2.0...v0.3.0) (2026-08-09)


### Features

* load and validate the config file layer ([#22](https://github.com/futville/sopuli-dba/issues/22)) ([fc776e6](https://github.com/futville/sopuli-dba/commit/fc776e6af3dea217d1e25ca8b583dee29bab3b78))

## [0.2.0](https://github.com/futville/sopuli-dba/compare/v0.1.1...v0.2.0) (2026-08-09)


### Features

* add --color, NO_COLOR and TTY detection to text output ([#17](https://github.com/futville/sopuli-dba/issues/17)) ([f3a637f](https://github.com/futville/sopuli-dba/commit/f3a637f32fc972750737075df96677729fee544e))

## [0.1.1](https://github.com/futville/sopuli-dba/compare/v0.1.0...v0.1.1) (2026-08-09)


### Bug Fixes

* write UTF-8 to stdin, stdout and stderr regardless of redirection ([#14](https://github.com/futville/sopuli-dba/issues/14)) ([de29d2b](https://github.com/futville/sopuli-dba/commit/de29d2b60a5b2953ec9450ed947c5fa6382e9807))

## 0.1.0 (2026-08-09)


### Features

* bootstrap sopuli CLI skeleton ([#7](https://github.com/futville/sopuli-dba/issues/7)) ([11374ff](https://github.com/futville/sopuli-dba/commit/11374ff548f1d8603e025c34d995257221a4e7bb))
