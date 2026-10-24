//! Controller-only compressed sink routing. IPC identity remains outside core.
use super::*;
pub use nestlink_media_session::ExternalVideoCleanup;
pub use nestlink_media_session::external::{
    ExternalAccessUnit, VideoSinkContext, VideoSinkFeedback,
};

impl CoreHandle {
    pub fn native_compressed_cleanup(
        &self,
        context: &VideoSinkContext,
    ) -> Result<ExternalVideoCleanup, NativeVideoError> {
        self.native_video_presentation()?
            .presentation
            .external_cleanup(context)
            .map_err(|_| NativeVideoError::Invalid)
    }
    pub fn native_compressed_authority_remaining(&self) -> Result<Duration, NativeVideoError> {
        self.native_video_presentation()?
            .presentation
            .authority_remaining()
            .map_err(|_| NativeVideoError::Unauthorized)
    }
    pub fn open_native_compressed(
        &self,
        binding: &NativeSessionBinding,
        source: u32,
    ) -> Result<(VideoSinkContext, u32, u32), NativeVideoError> {
        let view = self
            .native_displays(binding)
            .map_err(|_| NativeVideoError::Unauthorized)?;
        let selected = view
            .selected
            .filter(|s| s.source == source)
            .ok_or(NativeVideoError::Unauthorized)?;
        if view.is_host || !view.catalog_acknowledged {
            return Err(NativeVideoError::Unauthorized);
        }
        let route = self.native_video_presentation()?;
        if route.request_id != binding.request_id
            || route.connection_generation != binding.connection_generation
        {
            return Err(NativeVideoError::Unauthorized);
        }
        let context = VideoSinkContext {
            connection_generation: binding.connection_generation,
            source,
            stream_id: nestlink_auth::random_bytes(),
            stream_epoch: 1,
            catalog_revision: selected.catalog.revision,
            selection_sequence: selected.sequence,
            layout_epoch: selected.layout_epoch,
            decode_epoch: 1,
            configuration_id: 1,
        };
        route
            .presentation
            .open_external(context.clone())
            .map_err(|_| NativeVideoError::Invalid)?;
        let (_, width, height) = route
            .presentation
            .external_context()
            .map_err(|_| NativeVideoError::Transport)?
            .ok_or(NativeVideoError::Invalid)?;
        Ok((context, width, height))
    }
    pub fn native_compressed_context(
        &self,
        binding: &NativeSessionBinding,
    ) -> Result<Option<(VideoSinkContext, u32, u32)>, NativeVideoError> {
        let route = self.native_video_presentation()?;
        if route.request_id != binding.request_id
            || route.connection_generation != binding.connection_generation
        {
            return Err(NativeVideoError::Unauthorized);
        }
        let context = route
            .presentation
            .external_context()
            .map_err(|_| NativeVideoError::Transport)?;
        if let Some((c, _, _)) = &context {
            let state = self
                .native_displays(binding)
                .map_err(|_| NativeVideoError::Unauthorized)?;
            if !state.selected.as_ref().is_some_and(|s| {
                s.source == c.source
                    && s.layout_epoch == c.layout_epoch
                    && s.sequence == c.selection_sequence
                    && s.catalog.revision == c.catalog_revision
            }) {
                return Err(NativeVideoError::Unauthorized);
            }
        }
        Ok(context)
    }
    pub fn poll_native_compressed(
        &self,
        binding: &NativeSessionBinding,
        context: &VideoSinkContext,
    ) -> Result<Option<ExternalAccessUnit>, NativeVideoError> {
        if self
            .native_compressed_context(binding)?
            .as_ref()
            .map(|v| &v.0)
            != Some(context)
        {
            return Err(NativeVideoError::Unauthorized);
        }
        let route = self.native_video_presentation()?;
        let unit = route
            .presentation
            .poll_external()
            .map_err(|_| NativeVideoError::Transport)?;
        if self
            .native_compressed_context(binding)?
            .as_ref()
            .map(|v| &v.0)
            != Some(context)
        {
            return Err(NativeVideoError::Unauthorized);
        }
        Ok(unit)
    }
    pub fn native_compressed_feedback(
        &self,
        binding: &NativeSessionBinding,
        context: &VideoSinkContext,
        feedback: VideoSinkFeedback,
    ) -> Result<(), NativeVideoError> {
        let route = self.native_video_presentation()?;
        if route.request_id != binding.request_id
            || route.connection_generation != binding.connection_generation
        {
            return Err(NativeVideoError::Unauthorized);
        }
        let stopped = matches!(&feedback, VideoSinkFeedback::Stopped { joined: true });
        route
            .presentation
            .external_feedback(context, feedback)
            .map_err(|_| NativeVideoError::Invalid)?;
        if stopped {
            route.presentation.close_external(context).map_err(|_| {
                NativeVideoError::Cleanup(io::Error::other("external close failed"))
            })?;
        }
        Ok(())
    }
}
