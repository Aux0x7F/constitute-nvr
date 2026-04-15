# Issue Draft: NVR History Is Not Complete

## Summary
The NVR live path is in usable shape, but history/archive is still incomplete and should be tracked explicitly as follow-up work rather than implied by the current UI.

## Current State
- The NVR UI still renders a placeholder history surface with `No History Yet`.
- Roadmap item `recorded retrieval preserved alongside live preview` is still open.
- Recorded segments exist at the service/storage layer, but the managed NVR experience does not yet provide a finished browser history/archive flow.

## Evidence
- `constitute-nvr-ui/src/shell.ts`
  - History view copy is still placeholder-only.
- `constitute-nvr/docs/ROADMAP.md`
  - recorded retrieval remains unchecked.

## Problem
We cannot call the NVR mission complete while history is only partially represented. Live preview is working, but operators still need a coherent way to:
- browse recent recordings
- retrieve recorded segments
- understand empty/error/loading states
- use history from the same managed app surface without dropping into ad hoc tooling

## Acceptance Criteria
- History tab shows real recording data instead of placeholder copy.
- The UI can list recordings/segments for at least one mounted camera.
- The UI can request and retrieve a selected recording/segment through the intended managed path.
- Empty, loading, and error states are explicit and user-readable.
- The flow is documented in NVR operator docs and reflected in roadmap status.

## Non-Goals
- Do not block the runtime refactor on a perfect archive product.
- Do not reopen PTZ as part of this issue.
- Do not introduce git-tracked build artifacts to support history UI work.

## Notes
- This should remain an issue even if we merge the current convergence branches.
- Recommended label framing when turned into a real tracker issue:
  - `nvr`
  - `history`
  - `mission-followup`
