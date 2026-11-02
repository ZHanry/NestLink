//! A single consumer of the original HEVC decoder. No decoder is opened here.
use super::*;
use nestlink_media_codec::{HevcExecutionOutput, HevcExecutionReceipt, SharedRingDescriptor};
use nestlink_media_codec::VerifiedProcessExportTarget;
use nestlink_protocol::native_media_format::FormatSelection;
use std::sync::atomic::Ordering;

pub struct SharedVideoConsumer {
    presentation: VideoPresentation,
    execution: HevcExecutionReceipt,
    context: crate::external::VideoSinkContext,
    selection: FormatSelection,
    revision: u64,
    ring: Option<SharedRingDescriptor>,
}
impl VideoPresentation {
    pub async fn open_shared_original(
        &self,
        selection: FormatSelection,
        execution: HevcExecutionReceipt,
        peer: VerifiedProcessExportTarget,
    ) -> io::Result<SharedVideoConsumer> {
        let mut consumer = self.reserve_shared_original(selection, execution)?;
        let mut ticket = consumer.execution.enable_shared_output(peer)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            consumer.check_current()?;
            if let Some(output) = ticket.try_poll()? {
                let HevcExecutionOutput::SharedOutput(ring) = output else { return Err(io::Error::other("original shared setup returned another operation")); };
                consumer.ring = Some(ring);
                consumer.check_current()?;
                return Ok(consumer);
            }
            if tokio::time::Instant::now() >= deadline { return Err(io::Error::new(io::ErrorKind::TimedOut,"original shared setup expired")); }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    fn reserve_shared_original(&self, selection: FormatSelection, execution: HevcExecutionReceipt) -> io::Result<SharedVideoConsumer> {
        self.lease.check_media_binding(Channel::Video, self.connection_generation).map_err(io::Error::other)?;
        crate::hevc_execution_receipt_matches(&execution, selection.format)?;
        let identity = execution.identity()?;
        let external = self.output.external.lock().map_err(|_| io::Error::other("external sink poisoned"))?;
        let mut state = self.output.state.lock().map_err(|_| io::Error::other("media output poisoned"))?;
        if external.is_some() || state.closed || state.format.as_ref() != Some(&selection)
            || state.catalog.as_ref().map(|(key, _)| key) != Some(&selection.display.catalog)
            || state.selected.is_none_or(|layout| layout.source != selection.display.source || layout.epoch.layout != selection.display.layout_epoch)
            || state.execution.as_ref().map(|value| value.identity()).transpose()? != Some(crate::LiveExecutionIdentity::Hevc(identity))
        { return Err(io::Error::other("original shared consumer context differs")); }
        let hardware = self.decoder_hardware_target()?;
        let mut claim=self.output.shared_claim.lock().map_err(|_| io::Error::other("shared consumer poisoned"))?;
        if claim.as_ref().is_some_and(|previous| !previous.retired_joined()) {return Err(io::Error::other("previous original shared consumer has not retired and joined"));}
        self.output.advance_consumer()?;
        *claim=Some(execution.clone());
        state.scheduled.clear(); state.videos.clear(); state.ready.clear();
        let revision = self.output.consumer_revision.load(Ordering::Acquire);
        let context = crate::external::VideoSinkContext {
            connection_generation: self.connection_generation,
            source: selection.display.source,
            stream_id: identity.resource_id(), stream_epoch: identity.generation(),
            catalog_revision: selection.display.catalog.revision,
            catalog_sha256: selection.display.catalog.sha256,
            format_epoch: selection.format_epoch, format_sha256: selection.format_sha256,
            format: Some(selection.format), decoder_hardware: Some(hardware),
            selection_sequence: selection.display.sequence,
            layout_epoch: selection.display.layout_epoch,
            decode_epoch: identity.generation(), configuration_id: selection.format_epoch,
        };
        drop(claim); drop(state); drop(external);
        Ok(SharedVideoConsumer {presentation:self.clone(), execution, context, selection, revision, ring:None})
    }
}
impl SharedVideoConsumer {
    pub fn context(&self) -> &crate::external::VideoSinkContext { &self.context }
    pub fn ring(&self) -> io::Result<SharedRingDescriptor> {
        self.check_current()?;
        self.ring.ok_or_else(|| io::Error::other("original shared ring not ready"))
    }
    pub fn check_current(&self) -> io::Result<()> {
        self.presentation.authority_remaining()?;
        self.execution.check_current()?;
        if self.presentation.output.consumer_revision.load(Ordering::Acquire) != self.revision {return Err(io::Error::other("original shared consumer revision retired"));}
        let state = self.presentation.output.state.lock().map_err(|_| io::Error::other("media output poisoned"))?;
        if state.closed || state.format.as_ref() != Some(&self.selection)
            || state.catalog.as_ref().map(|(key,_)| key) != Some(&self.selection.display.catalog)
            || state.selected.is_none_or(|layout| layout.source != self.context.source || layout.epoch.layout != self.context.layout_epoch)
            || state.execution.as_ref().map(|value| value.identity()).transpose()? != Some(crate::LiveExecutionIdentity::Hevc(self.execution.identity()?))
        {return Err(io::Error::other("original shared selection or execution retired"));}
        Ok(())
    }
    pub fn authority_remaining(&self) -> io::Result<Duration> {
        self.check_current()?;
        self.presentation.authority_remaining()
    }
    pub fn poll(&self) -> io::Result<Option<DecodedVideo>> {
        self.check_current()?;
        let Some(frame) = self.presentation.poll_video_inner(true)? else {return Ok(None);};
        self.check_current()?;
        if frame.source != self.context.source || frame.epoch.layout != self.context.layout_epoch
            || frame.epoch.connection != self.context.connection_generation
            || (frame.width,frame.height) != (self.selection.format.width,self.selection.format.height)
        {return Err(io::Error::other("original shared output context differs"));}
        // A pre-enable decoder output can still be buffered by MF. It has no
        // surface and must be dropped without inventing a shared receipt.
        let Some(surface) = frame.shared_surface()? else {return Ok(None);};
        if surface.ring() != self.ring()? {return Err(io::Error::other("original shared ring changed"));}
        Ok(Some(frame))
    }
}
impl Drop for SharedVideoConsumer {
    fn drop(&mut self) {
        // There is no reconnect on a partially exported native ring. The
        // original worker retires and joins before a new session may own it.
        self.execution.fence();
        self.presentation.output.wake();
    }
}
