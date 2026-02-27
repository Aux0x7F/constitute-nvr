# Contributing

## Objectives
Contributions should prioritize:
- contract clarity
- security invariants
- operability
- ecosystem convergence

## Workflow
1. Open a scoped issue.
2. Branch from issue scope.
3. Add tests with behavior changes.
4. Update docs with contract or operator changes.

## Commit Style
Use Conventional Commit subject lines with multi-line detail:
- `feat:` behavior additions
- `fix:` correctness/security corrections
- `docs:` documentation-only updates
- `test:` test-only changes
- `chore:` process/repo updates

## Quality Bar
Before PR:
- [ ] build/test passes
- [ ] docs updated where needed
- [ ] no secrets or environment-specific artifacts
- [ ] ecosystem impact noted (`constitute` / `constitute-gateway`)
