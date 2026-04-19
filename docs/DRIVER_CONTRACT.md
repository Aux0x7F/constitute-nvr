# Camera Device Driver Contract

This document defines the minimum managed-driver surface for `constitute-nvr`.

Model-specific notes belong primarily in:
- `src/camera_device/drivers/<driver>/driver.rs`
- `src/camera_device/drivers/<driver>/identification.rs`

This file defines the shared contract only.

## Surface Levels
- `IdentifyOnly`
- `Mountable`
- `Managed`

Current first-class drivers should converge on `Managed`.

## Required Managed Driver Surface
- identification
- mount synthesis
- probe
- observed-state readback
- capability truth
- stream catalog
- media capabilities
- requested-field verification

## Capability-Gated Optional Features
- PTZ
- password rotation
- hardening
- overlay text/timestamp
- time sync

Unsupported capability must be explicit in the driver capability set. Drivers must not expose implied support through UI fallback or shared default behavior.

## Required Driver Outputs
- canonical driver id
- candidate match result with confidence/reason
- mounted device config/defaults
- observed state
- verification result for requested fields
- stream catalog
- media capability facts

## Media Boundary
Drivers stop at device truth.

Drivers must not:
- build ffmpeg command lines
- decide copy/transcode/drop execution directly
- own recorder runtime lifecycle

Drivers must provide enough truth for `media` to decide preview and recording plans.

## Required Driver Documentation
Each supported driver should document:
- validated models/firmware
- supported management planes
- minimum supported feature surface
- unsupported features
- known quirks
- date of live proof
