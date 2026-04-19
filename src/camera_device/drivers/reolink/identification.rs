#![allow(dead_code)]

//! Reolink candidate signature lane.
//!
//! Reolink-specific match policy is centralized in `camera_device::mod` for the current
//! sweep, with this file existing as the durable driver-local identification home.

pub const DRIVER_ID: &str = "reolink";
