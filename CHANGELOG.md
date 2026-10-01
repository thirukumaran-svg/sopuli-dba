# Changelog

## [0.67.3](https://github.com/villebase/sopuli-dba/compare/v0.67.2...v0.67.3) (2026-10-01)


### Bug Fixes

* **apply:** say why a rollback meets a reuse-restricted profile ([#568](https://github.com/villebase/sopuli-dba/issues/568)) ([#579](https://github.com/villebase/sopuli-dba/issues/579)) ([753420c](https://github.com/villebase/sopuli-dba/commit/753420ced17f725691c4fd41191fd2b1834ca9dd))
* **apply:** withhold a promotion the run was narrowed past ([#406](https://github.com/villebase/sopuli-dba/issues/406)) ([#578](https://github.com/villebase/sopuli-dba/issues/578)) ([32baed6](https://github.com/villebase/sopuli-dba/commit/32baed6d479c1411beabaa43f969218117de7cb0))
* **oracle:** give thick mode its three reasons and stop saying OCI requires NNE ([#574](https://github.com/villebase/sopuli-dba/issues/574)) ([#576](https://github.com/villebase/sopuli-dba/issues/576)) ([2f000f1](https://github.com/villebase/sopuli-dba/commit/2f000f118b01502b5c5310dba3a75d2c99a158de))

## [0.67.2](https://github.com/villebase/sopuli-dba/compare/v0.67.1...v0.67.2) (2026-09-27)


### Bug Fixes

* **check:** keep "the lockout guard is unavailable" on a login that passes ([#558](https://github.com/villebase/sopuli-dba/issues/558)) ([#559](https://github.com/villebase/sopuli-dba/issues/559)) ([090d71b](https://github.com/villebase/sopuli-dba/commit/090d71b689186d7b151f52a4d7b153a12470ff25))

## [0.67.1](https://github.com/villebase/sopuli-dba/compare/v0.67.0...v0.67.1) (2026-09-26)


### Bug Fixes

* **output:** on Windows, count a stream as a terminal only if it is a console ([#549](https://github.com/villebase/sopuli-dba/issues/549)) ([#550](https://github.com/villebase/sopuli-dba/issues/550)) ([e558743](https://github.com/villebase/sopuli-dba/commit/e5587430b90ea5a26c4bd83b7e0811d36df41779))

## [0.67.0](https://github.com/villebase/sopuli-dba/compare/v0.66.0...v0.67.0) (2026-09-26)


### Features

* **output:** `--output jsonl`, streamed by `creds check` ([#9](https://github.com/villebase/sopuli-dba/issues/9)) ([#534](https://github.com/villebase/sopuli-dba/issues/534)) ([d98fd17](https://github.com/villebase/sopuli-dba/commit/d98fd17cdf1c181a9660d8aa9dd479497862bcfa))
* **output:** stream `account reset-password` under `--output jsonl` ([#535](https://github.com/villebase/sopuli-dba/issues/535)) ([#546](https://github.com/villebase/sopuli-dba/issues/546)) ([a660276](https://github.com/villebase/sopuli-dba/commit/a660276ba969455c4400107765984e63d99ddb82))
* **output:** stream `creds apply` under `--output jsonl` ([#535](https://github.com/villebase/sopuli-dba/issues/535)) ([#542](https://github.com/villebase/sopuli-dba/issues/542)) ([95c868b](https://github.com/villebase/sopuli-dba/commit/95c868b678c89e8623484aea7628f9951d1335c2))
* **output:** stream `creds generate` under `--output jsonl` ([#535](https://github.com/villebase/sopuli-dba/issues/535)) ([#544](https://github.com/villebase/sopuli-dba/issues/544)) ([4a9e7a5](https://github.com/villebase/sopuli-dba/commit/4a9e7a51c69fa2a33e895d563b3fa3c766e0e0d6))
* **output:** stream `creds rotate` under `--output jsonl` ([#535](https://github.com/villebase/sopuli-dba/issues/535)) ([#543](https://github.com/villebase/sopuli-dba/issues/543)) ([68509a0](https://github.com/villebase/sopuli-dba/commit/68509a05bfc13a8d0c7fd6178451a4ff34e8e350))


### Bug Fixes

* **expire:** don't count a close-only partial row as expired in the closing line ([#537](https://github.com/villebase/sopuli-dba/issues/537)) ([#539](https://github.com/villebase/sopuli-dba/issues/539)) ([92d2123](https://github.com/villebase/sopuli-dba/commit/92d21235142b02d0f29598f1f73e50b27bdae910))
* **oracle:** grant DBA_ROLES and gate role predicates on role_lookup ([#531](https://github.com/villebase/sopuli-dba/issues/531)) ([#533](https://github.com/villebase/sopuli-dba/issues/533)) ([addeb6d](https://github.com/villebase/sopuli-dba/commit/addeb6d07b23475a3f56ea2e76973f63d60b432c))
* **oracle:** surface dictionary read failures and refuse a read-only rollover finish ([#521](https://github.com/villebase/sopuli-dba/issues/521)) ([#530](https://github.com/villebase/sopuli-dba/issues/530)) ([804f02f](https://github.com/villebase/sopuli-dba/commit/804f02f0f3ae5de0035002165ad05c135c1e4db2))
* **reset:** report a partly-applied reset as changed, and hand over a live password ([#528](https://github.com/villebase/sopuli-dba/issues/528)) ([#536](https://github.com/villebase/sopuli-dba/issues/536)) ([b38cce7](https://github.com/villebase/sopuli-dba/commit/b38cce7944b9fb3c04e9661e54e1adef4e5a763c))

## [0.66.0](https://github.com/villebase/sopuli-dba/compare/v0.65.0...v0.66.0) (2026-09-25)


### Features

* `sopuli account expire-password`, forcing a change without setting a password ([#525](https://github.com/villebase/sopuli-dba/issues/525)) ([#527](https://github.com/villebase/sopuli-dba/issues/527)) ([a05ef27](https://github.com/villebase/sopuli-dba/commit/a05ef276f53f89dbc2534ad42078ba735d2d79f3))
* **driver:** expire a password without setting one, closing an open window first ([#525](https://github.com/villebase/sopuli-dba/issues/525)) ([#526](https://github.com/villebase/sopuli-dba/issues/526)) ([24dbb8a](https://github.com/villebase/sopuli-dba/commit/24dbb8a3138ba772ea8c9257295ac02b43783f52))
* **notify:** `notify.method: webhook`, UC-2's shared notify channel ([#442](https://github.com/villebase/sopuli-dba/issues/442)) ([#520](https://github.com/villebase/sopuli-dba/issues/520)) ([6925161](https://github.com/villebase/sopuli-dba/commit/69251615cfd0833de8a601c31d034ebf49761ab7))

## [0.65.0](https://github.com/villebase/sopuli-dba/compare/v0.64.0...v0.65.0) (2026-09-22)


### Features

* `sopuli account reset-password`, UC-2's seen path under five guards ([#441](https://github.com/villebase/sopuli-dba/issues/441)) ([#507](https://github.com/villebase/sopuli-dba/issues/507)) ([981d009](https://github.com/villebase/sopuli-dba/commit/981d00959abb113b1a3d1d8b8373d99bd5a64164))
* **delivery:** `vault_wrapped`, UC-2's unseen path ([#444](https://github.com/villebase/sopuli-dba/issues/444), part 1 of 2) ([#518](https://github.com/villebase/sopuli-dba/issues/518)) ([d41693c](https://github.com/villebase/sopuli-dba/commit/d41693cdfaa3457db71027f5d0e9e7ec04d2eb3e))
* **delivery:** the hand-over receipt ([#444](https://github.com/villebase/sopuli-dba/issues/444), part 2 of 2) ([#519](https://github.com/villebase/sopuli-dba/issues/519)) ([c1acce1](https://github.com/villebase/sopuli-dba/commit/c1acce1092338ae3639bf497bdbad2a93aa6b2e5))
* **driver:** reset a personal account's password, UC-2 §4.1's three statements ([#441](https://github.com/villebase/sopuli-dba/issues/441)) ([#504](https://github.com/villebase/sopuli-dba/issues/504)) ([1c4aa09](https://github.com/villebase/sopuli-dba/commit/1c4aa09b82ccf3be87789c71b6a68ddb4772cd41))
* **reset:** take UC-2's advisory lock on the reset record's path ([#512](https://github.com/villebase/sopuli-dba/issues/512)) ([#515](https://github.com/villebase/sopuli-dba/issues/515)) ([3871cc6](https://github.com/villebase/sopuli-dba/commit/3871cc67f28ccb641969428e4a87e119cfed8fb6))
* **reset:** write UC-2's reset record, and say so when there is none ([#511](https://github.com/villebase/sopuli-dba/issues/511)) ([#513](https://github.com/villebase/sopuli-dba/issues/513)) ([1872d86](https://github.com/villebase/sopuli-dba/commit/1872d8602c8b9e63f160f33742176ac0df28e065))
* **settings:** `safety.delivery.allowed_methods`, the fourth ratchet shape ([#498](https://github.com/villebase/sopuli-dba/issues/498)) ([#500](https://github.com/villebase/sopuli-dba/issues/500)) ([d4f48ba](https://github.com/villebase/sopuli-dba/commit/d4f48ba0b64817e6ccb59ef4540295577ee6233a))


### Bug Fixes

* **config:** refuse a null `safety:` block and a null `confirm_environments` ([#501](https://github.com/villebase/sopuli-dba/issues/501)) ([#508](https://github.com/villebase/sopuli-dba/issues/508)) ([4ec02da](https://github.com/villebase/sopuli-dba/commit/4ec02da5ddf53072d18b2b7e13f8ff5c19a6b371))
* **lock:** survey UC-2's reset locks by listing the declared prefix ([#514](https://github.com/villebase/sopuli-dba/issues/514)) ([#517](https://github.com/villebase/sopuli-dba/issues/517)) ([cfa1b2c](https://github.com/villebase/sopuli-dba/commit/cfa1b2c7e11b00fb479e39e52134a6363ca9808f))

## [0.64.0](https://github.com/villebase/sopuli-dba/compare/v0.63.0...v0.64.0) (2026-09-18)


### Features

* `sopuli account list`, the verb H1 owed ([#490](https://github.com/villebase/sopuli-dba/issues/490)) ([#493](https://github.com/villebase/sopuli-dba/issues/493)) ([ba78c82](https://github.com/villebase/sopuli-dba/commit/ba78c82c6559b9d10cc0218acd4c7d3b0b35306e))
* **config:** the `delivery:` block, UC-2's handover ([#440](https://github.com/villebase/sopuli-dba/issues/440)) ([#499](https://github.com/villebase/sopuli-dba/issues/499)) ([2f0ee29](https://github.com/villebase/sopuli-dba/commit/2f0ee2990e56defebc08d1cb819f387b4d7d7cc1))
* **config:** the `reset_records:` block, and the record a reset writes ([#468](https://github.com/villebase/sopuli-dba/issues/468)) ([#491](https://github.com/villebase/sopuli-dba/issues/491)) ([5852894](https://github.com/villebase/sopuli-dba/commit/5852894ece73d0ae6ae75982c79502135c346e10))

## [0.63.0](https://github.com/villebase/sopuli-dba/compare/v0.62.0...v0.63.0) (2026-09-18)


### Features

* `sopuli account suspend`, UC-2's offboarding verb ([#463](https://github.com/villebase/sopuli-dba/issues/463)) ([#480](https://github.com/villebase/sopuli-dba/issues/480)) ([68e5264](https://github.com/villebase/sopuli-dba/commit/68e52648dc2b329a41bce1871371dc492005b10f))
* **config:** the `personal_accounts:` block, by name or by predicate ([#467](https://github.com/villebase/sopuli-dba/issues/467)) ([#473](https://github.com/villebase/sopuli-dba/issues/473)) ([52baa5d](https://github.com/villebase/sopuli-dba/commit/52baa5dd449bd9f85d03ee2d59c3715fd8c66f9d))
* **driver:** ALTER USER ACCOUNT LOCK, and who a personal account is declared by ([#463](https://github.com/villebase/sopuli-dba/issues/463)) ([#475](https://github.com/villebase/sopuli-dba/issues/475)) ([e6de5ee](https://github.com/villebase/sopuli-dba/commit/e6de5ee0e4a02fb893aa0b7a23b42718f3681700))
* **output:** flag the low-assurance admin source, SOPULI-W022 ([#477](https://github.com/villebase/sopuli-dba/issues/477)) ([#487](https://github.com/villebase/sopuli-dba/issues/487)) ([a3c97f6](https://github.com/villebase/sopuli-dba/commit/a3c97f642df8c42b601842aab92a9497f1a8ace7))


### Bug Fixes

* **cli:** build a prompter, so `auth: prompt` can prompt ([#476](https://github.com/villebase/sopuli-dba/issues/476)) ([#482](https://github.com/villebase/sopuli-dba/issues/482)) ([c555e22](https://github.com/villebase/sopuli-dba/commit/c555e22e7af9ced6cf1d884bc891f97f4bc0789c))
* **cli:** supply the store, so `auth: { method: vault }` resolves ([#483](https://github.com/villebase/sopuli-dba/issues/483)) ([#488](https://github.com/villebase/sopuli-dba/issues/488)) ([84effb2](https://github.com/villebase/sopuli-dba/commit/84effb2cef63d8008edcb06f4a77d94e876de28d))

## [0.62.0](https://github.com/villebase/sopuli-dba/compare/v0.61.0...v0.62.0) (2026-09-15)


### Features

* add `--vault-addr`, layer 1 of `vaults.*.addr` ([#427](https://github.com/villebase/sopuli-dba/issues/427)) ([2224787](https://github.com/villebase/sopuli-dba/commit/22247872473a4aa4ded51bf086eac24525b6dcdb))
* add `sopuli about`, the one command that is not a run ([#413](https://github.com/villebase/sopuli-dba/issues/413)) ([#414](https://github.com/villebase/sopuli-dba/issues/414)) ([9979a6c](https://github.com/villebase/sopuli-dba/commit/9979a6c59a5f76ac478912ca805406bde5cfe93d))
* add a stderr spinner, on the one call that actually waits ([#419](https://github.com/villebase/sopuli-dba/issues/419)) ([#420](https://github.com/villebase/sopuli-dba/issues/420)) ([20be635](https://github.com/villebase/sopuli-dba/commit/20be6354821d1bb17749e70b2c66039937e7d073))
* enforce a `safety:` block written on a target, a group or a target set ([#425](https://github.com/villebase/sopuli-dba/issues/425)) ([fc85d89](https://github.com/villebase/sopuli-dba/commit/fc85d89d336be46a42aa5bd15ec91185504d43a5))
* read the password change date from SYS.USER$.PTIME where DBA_USERS lacks it, and say why when it is absent ([#386](https://github.com/villebase/sopuli-dba/issues/386)) ([#421](https://github.com/villebase/sopuli-dba/issues/421)) ([9887d7d](https://github.com/villebase/sopuli-dba/commit/9887d7d7a8a2eb2896fc97b1f5e50c06dcd2bf82))
* report every `safety:` block in `config show`, and per target in JSON ([#429](https://github.com/villebase/sopuli-dba/issues/429)) ([8692bb0](https://github.com/villebase/sopuli-dba/commit/8692bb0a061d2b277135750c9af28f960653b516))
* report which layer supplied each of a store's settings ([#428](https://github.com/villebase/sopuli-dba/issues/428)) ([#430](https://github.com/villebase/sopuli-dba/issues/430)) ([85f67bf](https://github.com/villebase/sopuli-dba/commit/85f67bffea406914a932d6ad7761d0bb26cd72ff))

## [0.61.0](https://github.com/villebase/sopuli-dba/compare/v0.60.0...v0.61.0) (2026-09-11)


### Features

* creds apply --repair FILE, acting only on a run's unconfirmed set ([#405](https://github.com/villebase/sopuli-dba/issues/405)) ([4b0f922](https://github.com/villebase/sopuli-dba/commit/4b0f9225396dda2e0b032e993f02490e7d39db7c))
* emit invocation.config_files, and add an (account, target) filter ([#403](https://github.com/villebase/sopuli-dba/issues/403)) ([55b602d](https://github.com/villebase/sopuli-dba/commit/55b602ddf601f4a421ccc86424a461de050172bd))
* remove `creds.promote` from the run schema, and strike the flags that never existed ([#392](https://github.com/villebase/sopuli-dba/issues/392)) ([#408](https://github.com/villebase/sopuli-dba/issues/408)) ([56ab566](https://github.com/villebase/sopuli-dba/commit/56ab56692d8dc52b2ba3dc33db7c5d59aad215d3))

## [0.60.0](https://github.com/villebase/sopuli-dba/compare/v0.59.0...v0.60.0) (2026-09-10)


### Features

* paint the five views that had no colour at all ([#398](https://github.com/villebase/sopuli-dba/issues/398)) ([13bef22](https://github.com/villebase/sopuli-dba/commit/13bef22df8e9d326ef60ad4dc4db34a91bf9fe9a))

## [0.59.0](https://github.com/villebase/sopuli-dba/compare/v0.58.0...v0.59.0) (2026-09-09)


### Features

* one palette for result states, and one function that decides it ([#396](https://github.com/villebase/sopuli-dba/issues/396)) ([e1f7beb](https://github.com/villebase/sopuli-dba/commit/e1f7beb77acf607bdf40c2622d4eed03a56417c5))


### Bug Fixes

* arrange the compare-and-set guarantee on a lock path, do not just read it ([#393](https://github.com/villebase/sopuli-dba/issues/393)) ([760e584](https://github.com/villebase/sopuli-dba/commit/760e58475b02a81d3377cb997850abbdf6e2344e))

## [0.58.0](https://github.com/villebase/sopuli-dba/compare/v0.57.3...v0.58.0) (2026-09-06)


### Features

* **oracle:** audit SYSDBA and SYSOPER where V$PWFILE_USERS is readable ([#366](https://github.com/villebase/sopuli-dba/issues/366)) ([6b25da0](https://github.com/villebase/sopuli-dba/commit/6b25da0bd4179ab00b0e7f604ef9a2c0a8e3dbda))

## [0.57.3](https://github.com/villebase/sopuli-dba/compare/v0.57.2...v0.57.3) (2026-09-06)


### Bug Fixes

* **config:** import the package's re-exports on demand ([#363](https://github.com/villebase/sopuli-dba/issues/363)) ([#365](https://github.com/villebase/sopuli-dba/issues/365)) ([d68d526](https://github.com/villebase/sopuli-dba/commit/d68d526590d16a0bc77a4788d1d640a07c98568d))
* **config:** move `normalise_path` to the ref grammar that owns it ([#357](https://github.com/villebase/sopuli-dba/issues/357)) ([#364](https://github.com/villebase/sopuli-dba/issues/364)) ([777758a](https://github.com/villebase/sopuli-dba/commit/777758a3d4ad16077b64fadc46b0e32762c9f0c9))
* **config:** wire both `db` budgets to the driver ([#360](https://github.com/villebase/sopuli-dba/issues/360)) ([#361](https://github.com/villebase/sopuli-dba/issues/361)) ([b820c0a](https://github.com/villebase/sopuli-dba/commit/b820c0abaedd488c580fd8c5963f7d59115ff2e9))

## [0.57.2](https://github.com/villebase/sopuli-dba/compare/v0.57.1...v0.57.2) (2026-09-06)


### Bug Fixes

* **apply:** fence the attribute pass and the rollover close ([#347](https://github.com/villebase/sopuli-dba/issues/347)) ([#353](https://github.com/villebase/sopuli-dba/issues/353)) ([5b20400](https://github.com/villebase/sopuli-dba/commit/5b20400a2b7ddbad1e68d35b3c198c8c49808791))
* **lock:** give back the locks already taken when acquisition fails ([#345](https://github.com/villebase/sopuli-dba/issues/345)) ([#350](https://github.com/villebase/sopuli-dba/issues/350)) ([7a09372](https://github.com/villebase/sopuli-dba/commit/7a093723596369342eba452e2182ab9b33696711))
* **lock:** let `lock status` survey a slice past a binding with no store ([#349](https://github.com/villebase/sopuli-dba/issues/349)) ([#355](https://github.com/villebase/sopuli-dba/issues/355)) ([768d4a5](https://github.com/villebase/sopuli-dba/commit/768d4a5800637d22ab30a12c8bb05f848a3f5f40))
* **lock:** refuse `.` and `..` in a secret path ([#344](https://github.com/villebase/sopuli-dba/issues/344)) ([#351](https://github.com/villebase/sopuli-dba/issues/351)) ([bd4bcce](https://github.com/villebase/sopuli-dba/commit/bd4bccec214232d75d66af32c919b0624c897cde))
* **lock:** report a renewal takeover as one, and a capability refusal as one ([#346](https://github.com/villebase/sopuli-dba/issues/346)) ([#354](https://github.com/villebase/sopuli-dba/issues/354)) ([ea64baa](https://github.com/villebase/sopuli-dba/commit/ea64baa36572110357bb4b2f68985b2b98275ad1))
* **lock:** wire `locking.break_expired` through to the LockManager ([#348](https://github.com/villebase/sopuli-dba/issues/348)) ([#356](https://github.com/villebase/sopuli-dba/issues/356)) ([fe0cf5f](https://github.com/villebase/sopuli-dba/commit/fe0cf5fce7952bc59878f5eeda2e358b3c6e3c54))

## [0.57.1](https://github.com/villebase/sopuli-dba/compare/v0.57.0...v0.57.1) (2026-09-05)


### Bug Fixes

* **guardrails:** read `V$PWFILE_USERS`, and report check 3 when it cannot ([#296](https://github.com/villebase/sopuli-dba/issues/296)) ([#340](https://github.com/villebase/sopuli-dba/issues/340)) ([abc3f62](https://github.com/villebase/sopuli-dba/commit/abc3f6279a97d1a1814802e73025dcc11d0e785e))

## [0.57.0](https://github.com/villebase/sopuli-dba/compare/v0.56.0...v0.57.0) (2026-09-05)


### Features

* **generate:** `--promote` writes `current`, behind `--overwrite-current` ([#257](https://github.com/villebase/sopuli-dba/issues/257)) ([#339](https://github.com/villebase/sopuli-dba/issues/339)) ([e4e5331](https://github.com/villebase/sopuli-dba/commit/e4e5331caf5dc4871082825b307c4002c7a35cab))
* **generate:** report the constraints a draw cannot be bound by ([#317](https://github.com/villebase/sopuli-dba/issues/317)) ([#336](https://github.com/villebase/sopuli-dba/issues/336)) ([6d7159c](https://github.com/villebase/sopuli-dba/commit/6d7159c4eff8bd18a9d4b5a30b1b0110b2d8ba93))

## [0.56.0](https://github.com/villebase/sopuli-dba/compare/v0.55.0...v0.56.0) (2026-09-03)


### Features

* **generate:** read the target's byte limit before drawing ([#317](https://github.com/villebase/sopuli-dba/issues/317)) ([#335](https://github.com/villebase/sopuli-dba/issues/335)) ([d0f2c67](https://github.com/villebase/sopuli-dba/commit/d0f2c67a32f9d4d82f0115107b2cfd902268a92b))
* **oracle:** detect application containers and split the refusal ([#204](https://github.com/villebase/sopuli-dba/issues/204)) ([#333](https://github.com/villebase/sopuli-dba/issues/333)) ([b30b0ff](https://github.com/villebase/sopuli-dba/commit/b30b0ff391842ae513bb8fd799a757d85aaf0332))

## [0.55.0](https://github.com/villebase/sopuli-dba/compare/v0.54.0...v0.55.0) (2026-09-02)


### Features

* **check:** carry a diagnostic the server attached to a successful login ([#328](https://github.com/villebase/sopuli-dba/issues/328)) ([4bd4041](https://github.com/villebase/sopuli-dba/commit/4bd404161401483fc88bdc9a8aece83022133a02))


### Bug Fixes

* **check:** read a grace period apart from a hard expiry ([#324](https://github.com/villebase/sopuli-dba/issues/324)) ([b50d54d](https://github.com/villebase/sopuli-dba/commit/b50d54d74846746beaf7a95b4b52b6848a0b51a7))

## [0.54.0](https://github.com/villebase/sopuli-dba/compare/v0.53.0...v0.54.0) (2026-09-02)


### ⚠ BREAKING CHANGES

* **config:** widen `config validate` to every backend it cannot serve ([#321](https://github.com/villebase/sopuli-dba/issues/321))

### Bug Fixes

* **config:** stop sending `config validate` to `pip` for an unwritten backend ([#319](https://github.com/villebase/sopuli-dba/issues/319)) ([11dc2d1](https://github.com/villebase/sopuli-dba/commit/11dc2d16cac922f7a4af1d96027aba38d96d4df7))
* **config:** widen `config validate` to every backend it cannot serve ([#321](https://github.com/villebase/sopuli-dba/issues/321)) ([0475794](https://github.com/villebase/sopuli-dba/commit/04757946e2814cfd20b5fc9f9134c4d446505cdb))

## [0.53.0](https://github.com/villebase/sopuli-dba/compare/v0.52.0...v0.53.0) (2026-09-01)


### Features

* **apply:** decide when a refused password may be redrawn ([#315](https://github.com/villebase/sopuli-dba/issues/315)) ([cf3f7c9](https://github.com/villebase/sopuli-dba/commit/cf3f7c92d780ac888e694913a2634aedb015a6ac))
* **apply:** draw again when the server refuses the password ([#316](https://github.com/villebase/sopuli-dba/issues/316)) ([aebc69e](https://github.com/villebase/sopuli-dba/commit/aebc69e357840c2d81641a2c18f4d5b29dbbcc0c))
* **vault:** record where a staged password came from ([#313](https://github.com/villebase/sopuli-dba/issues/313)) ([edc9549](https://github.com/villebase/sopuli-dba/commit/edc954949eecef617b8d6a49e88c5ba280408765))

## [0.52.0](https://github.com/villebase/sopuli-dba/compare/v0.51.0...v0.52.0) (2026-09-01)


### Features

* **apply:** profile assignment, the second of UC-1 §5's attributes ([#306](https://github.com/villebase/sopuli-dba/issues/306)) ([dbc52b9](https://github.com/villebase/sopuli-dba/commit/dbc52b97bbe83b797c0db66297a37e6977bb36b5))

## [0.51.0](https://github.com/villebase/sopuli-dba/compare/v0.50.0...v0.51.0) (2026-09-01)


### Features

* **apply:** account unlock, the first of UC-1 §5's attributes ([#304](https://github.com/villebase/sopuli-dba/issues/304)) ([70c05b7](https://github.com/villebase/sopuli-dba/commit/70c05b72349d34d067ea8acd8ac00099b65ab4f4))

## [0.50.0](https://github.com/villebase/sopuli-dba/compare/v0.49.0...v0.50.0) (2026-08-31)


### Features

* **cli:** --target, --account, --group and --application ([#299](https://github.com/villebase/sopuli-dba/issues/299)) ([ee95f07](https://github.com/villebase/sopuli-dba/commit/ee95f0757501b02a041362819098d2caf9d3580d))
* **cli:** creds rotate, the sequence under one lock ([#293](https://github.com/villebase/sopuli-dba/issues/293)) ([f564554](https://github.com/villebase/sopuli-dba/commit/f5645548be7d2bccac83bcf326969368f9b41018))
* **safety:** call the section 4 account guardrails ([#298](https://github.com/villebase/sopuli-dba/issues/298)) ([5cebebb](https://github.com/villebase/sopuli-dba/commit/5cebebb54d271615f9ce5ccd3f8bd97c742a3f5c))
* **safety:** enforce `safety.confirm_environments` ([#295](https://github.com/villebase/sopuli-dba/issues/295)) ([da38969](https://github.com/villebase/sopuli-dba/commit/da38969cad01cb25c79be9515ee11918ffb80b3f))

## [0.49.0](https://github.com/villebase/sopuli-dba/compare/v0.48.0...v0.49.0) (2026-08-31)


### Features

* **cli:** creds apply --preflight, and the estate it asks before writing ([#289](https://github.com/villebase/sopuli-dba/issues/289)) ([43589c2](https://github.com/villebase/sopuli-dba/commit/43589c2f048dea0c2adf550b0d07b01faba1eb0b))
* **cli:** exit 4 names the repair, and where --repair's list will come from ([#280](https://github.com/villebase/sopuli-dba/issues/280)) ([a27dc90](https://github.com/villebase/sopuli-dba/commit/a27dc9093c40f7662fc8405a31c882767a20067f))
* **lock:** re-read the fence before every mutation, and stop when it fails ([#285](https://github.com/villebase/sopuli-dba/issues/285)) ([5f031f2](https://github.com/villebase/sopuli-dba/commit/5f031f271352bd58a65ee6332a629a95d56aac1c))


### Bug Fixes

* **output:** driver errors carry their own category, exit code and capability ([#288](https://github.com/villebase/sopuli-dba/issues/288)) ([1073096](https://github.com/villebase/sopuli-dba/commit/1073096f9a2fb9bfcea55d75ee1f5f910a515067))

## [0.48.0](https://github.com/villebase/sopuli-dba/compare/v0.47.0...v0.48.0) (2026-08-29)


### Features

* **cli:** sopuli creds status, the inventory that spends no logins ([#278](https://github.com/villebase/sopuli-dba/issues/278)) ([dbfdba2](https://github.com/villebase/sopuli-dba/commit/dbfdba243e153e20f82cb433fcb0ef1291f6fbde))

## [0.47.0](https://github.com/villebase/sopuli-dba/compare/v0.46.0...v0.47.0) (2026-08-29)


### Features

* **cli:** creds apply --source, and the rollback it exists for ([#273](https://github.com/villebase/sopuli-dba/issues/273)) ([231cf89](https://github.com/villebase/sopuli-dba/commit/231cf89520a9ba96b5d279cf5707d73cdcaaa6e3))
* **cli:** sopuli creds finish-rollover, and the windows it refuses to close ([#271](https://github.com/villebase/sopuli-dba/issues/271)) ([fd0a135](https://github.com/villebase/sopuli-dba/commit/fd0a1357a846d053370f6e216f8ee35af7813943))

## [0.46.0](https://github.com/villebase/sopuli-dba/compare/v0.45.0...v0.46.0) (2026-08-29)


### Features

* **cli:** creds apply --strategy, and the regime that cannot be honoured ([#269](https://github.com/villebase/sopuli-dba/issues/269)) ([a775939](https://github.com/villebase/sopuli-dba/commit/a775939b398b7175cdd515edbbd4eb16bfdca437))

## [0.45.0](https://github.com/villebase/sopuli-dba/compare/v0.44.0...v0.45.0) (2026-08-29)


### Features

* **cli:** sopuli creds apply, vault to database and the promote after it ([#261](https://github.com/villebase/sopuli-dba/issues/261)) ([00bf92e](https://github.com/villebase/sopuli-dba/commit/00bf92e2a03674269544719d91ece8b3fa5ccb87))
* **cli:** sopuli creds generate, the first credential mutation ([#256](https://github.com/villebase/sopuli-dba/issues/256)) ([50966dd](https://github.com/villebase/sopuli-dba/commit/50966dd31c82339af53e963c9a84bcf16ce30628))
* **config:** refuse two accounts staging into one place at load ([#260](https://github.com/villebase/sopuli-dba/issues/260)) ([ebfeaba](https://github.com/villebase/sopuli-dba/commit/ebfeaba163c8d3937c1182919f3cbeb8c4c41203))

## [0.44.0](https://github.com/villebase/sopuli-dba/compare/v0.43.0...v0.44.0) (2026-08-28)


### Features

* **cli:** sopuli creds check, the first creds verb ([#253](https://github.com/villebase/sopuli-dba/issues/253)) ([887b061](https://github.com/villebase/sopuli-dba/commit/887b0611e5159d265fa4dad3da2a94dab61b2260))
* **config:** complete a binding's store once the run is known ([#252](https://github.com/villebase/sopuli-dba/issues/252)) ([a196797](https://github.com/villebase/sopuli-dba/commit/a19679757deab12352e463c5409f8a7d02a4e2ab))
* **plan:** the plan section, and the max_targets refusal that reads it ([#249](https://github.com/villebase/sopuli-dba/issues/249)) ([a710882](https://github.com/villebase/sopuli-dba/commit/a7108829b344f294169372569f4a939d2f3005c6))

## [0.43.0](https://github.com/villebase/sopuli-dba/compare/v0.42.0...v0.43.0) (2026-08-28)


### Features

* **doctor:** vault reachability and clock skew ([#216](https://github.com/villebase/sopuli-dba/issues/216)) ([#246](https://github.com/villebase/sopuli-dba/issues/246)) ([50750af](https://github.com/villebase/sopuli-dba/commit/50750afc52ff1cfb95e5aedbe471d2149a88637e))
* **store:** health(), and the server clock it reports ([#216](https://github.com/villebase/sopuli-dba/issues/216)) ([#244](https://github.com/villebase/sopuli-dba/issues/244)) ([903f403](https://github.com/villebase/sopuli-dba/commit/903f403d4881053d149df5de2c1bd576cbfe00ea))

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
