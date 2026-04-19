#![allow(dead_code, unused_imports)]

use serde::{Deserialize, Serialize};

pub use super::{
    ApplyMountedCameraRequest as ApplyMountedCameraDeviceRequest,
    CameraCapabilitySet as CameraDeviceCapabilitySet,
    CameraCredentialSafety as CameraDeviceCredentialSafety,
    CameraDriver as CameraDeviceDriver,
    CameraInventory as CameraDeviceInventory,
    CameraNetworkSummary,
    CameraPose,
    CameraPtzControlResult as CameraDeviceControlResult,
    CameraReconcileResult as CameraDeviceVerification,
    CameraSignatureSet,
    CameraTransportFacts,
    DiscoveredCameraCandidate as CameraDeviceCandidate,
    DriverMatch,
    MountedCamera as MountedCameraDevice,
    MountCameraRequest as MountCameraDeviceRequest,
    ObservedCameraState as ObservedCameraDeviceState,
    ProbeCameraRequest as ProbeCameraDeviceRequest,
};
pub use crate::media::types::{
    DeviceMediaCapabilities, DeviceStreamDescriptor, PreviewPipelinePlan, RecordingPipelinePlan,
    StreamCatalog,
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverSurfaceLevel {
    IdentifyOnly,
    Mountable,
    #[default]
    Managed,
}
