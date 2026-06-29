# simrun-stratus-adapter

A [SimRun](https://github.com/IBM/simrun) pack that exposes the **entire**
[Stratus Red Team](https://github.com/DataDog/stratus-red-team) attack-technique
registry — no per-technique work. Install it and every Stratus cloud attack
becomes a SimRun simulation, MITRE ATT&CK tactics intact.

## How it works

Instead of re-implementing techniques, the adapter translates each one at startup:

```go
for _, technique := range stratus.GetRegistry().ListAttackTechniques() {
    pack.Register(adapter.AdaptTechnique(technique))
}
```

`AdaptTechnique` maps a Stratus `AttackTechnique` onto a SimRun `Simulation`:
its prerequisites Terraform becomes the warm-up, `Detonate`/`Revert` become the
detonation and cleanup, the platform becomes the scope, and MITRE tactics are
carried across. Pin the Stratus version in `go.mod` to control which techniques
ship.

## Install

Install from the SimRun **Packs** page (`/packs`) by pointing it at this repo's
release, then reference simulations as `<scope>.<name>` where `<name>` is the last segment of the Stratus technique ID:

```yaml
detonate:
  simrunDetonator:
    pack: stratus-adapter
    simulation: aws.iam-backdoor-role   # from aws.persistence.iam-backdoor-role
```

> These are real cloud attack techniques. They create and (where supported)
> revert live infrastructure, so run them only against accounts you control.

## Related

- [simrun-pack](https://github.com/confluentinc/simrun-pack) — the first-party pack and authoring reference.
- [SimRun ecosystem guide](https://github.com/IBM/simrun/blob/main/docs/ecosystem.md).

## Contributing & License

Part of the Confluent organization on GitHub; public and open to contributions.
See LICENSE for terms and CHANGELOG.md for recent updates.