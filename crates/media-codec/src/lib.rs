//! Native media primitives. Run synchronous codec work on a dedicated media
//! worker; these types neither grant permissions nor validate session epochs.
mod opus;
mod vp8;
pub use opus::{OpusConfig, OpusDecoder, OpusEncoder};
pub use vp8::{EncodedVideo, VideoConfig, Vp8Decoder, Vp8Encoder};
