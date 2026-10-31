//! One bounded observation window and one authenticated report history per
//! original session. Neither state can authorize media or renew its lifetime.
use nestlink_protocol::native_qos::{ReceiverContext, ReceiverReport};
use nestlink_media_codec::ReceiverCondition;
use std::{collections::BTreeMap, io, time::{Duration, Instant}};

#[derive(Default)]
pub struct ReceiverReportTracker {
    sequence: u64,
    last_accepted: Option<ReceiverReport>,
    last: BTreeMap<u32,(ReceiverReport,Instant)>,
    prepared:Option<(ReceiverContext,u64)>,
}
impl ReceiverReportTracker {
    pub fn prepared(&mut self, context:ReceiverContext, highest_sequence:u64){self.prepared=Some((context,highest_sequence));}
    pub fn accept_current(&mut self,report:ReceiverReport,now:Instant)->io::Result<()> {
        let (context,highest)=self.prepared.clone().ok_or_else(||io::Error::other("receiver report preceded original sender"))?;
        self.accept(report,&context,highest,now)
    }
    pub fn current_condition(&self,source:u32,layout:u64,fps:u32,now:Instant)->ReceiverCondition {
        let Some((context,highest))=&self.prepared else {return ReceiverCondition::Unknown;};
        if context.source!=source || context.layout_epoch!=layout {return ReceiverCondition::Unknown;}
        self.condition(context,*highest,fps,now)
    }
    pub fn accept(&mut self, report:ReceiverReport, current:&ReceiverContext, highest_sequence:u64, now:Instant)->io::Result<()> {
        report.validate().map_err(io::Error::other)?;
        if report.report_sequence==self.sequence && self.last_accepted.as_ref()==Some(&report){return Ok(());}
        if self.sequence.checked_add(1)!=Some(report.report_sequence) || report.context.connection_generation!=current.connection_generation {
            return Err(io::Error::other("receiver report replay or connection mismatch"));
        }
        // A retired layout/format can still be in the independent reliable
        // feedback stream. Consume its sequence without refreshing current data.
        if report.context.layout_epoch<current.layout_epoch || (report.context.layout_epoch==current.layout_epoch && report.context.format_epoch<current.format_epoch) {
            self.sequence=report.report_sequence;
            self.last_accepted=Some(report);
            return Ok(());
        }
        if &report.context!=current || report.last_sequence>highest_sequence {
            return Err(io::Error::other("receiver report context or unsent acknowledgement"));
        }
        if let Some((previous,_))=self.last.get(&current.source)
            && previous.context==report.context && report.last_sequence<previous.last_sequence {
            return Err(io::Error::other("receiver acknowledgement moved backwards"));
        }
        self.last.retain(|_,(value,_)|value.context.connection_generation==current.connection_generation && value.context.layout_epoch==current.layout_epoch);
        if !self.last.contains_key(&current.source) && self.last.len()>=64 {return Err(io::Error::other("receiver source bound exceeded"));}
        self.sequence=report.report_sequence;
        self.last_accepted=Some(report.clone());
        self.last.insert(current.source,(report,now));
        Ok(())
    }
    pub fn condition(&self, current:&ReceiverContext, highest_sequence:u64, fps:u32, now:Instant)->ReceiverCondition {
        let Some((report,at))=self.last.get(&current.source) else{return ReceiverCondition::Unknown;};
        let Some(age)=now.checked_duration_since(*at) else {return ReceiverCondition::Unknown;};
        if &report.context!=current || age>Duration::from_secs(2) {
            return ReceiverCondition::Unknown;
        }
        // Frames produced since this report arrived are expected. Account for
        // the report cadence locally; never interpret it as measured loss.
        let normal_lag=(u64::from(fps)*u64::try_from(age.as_millis().saturating_add(200)).unwrap_or(u64::MAX)/1000).max(3);
        let congested=highest_sequence.saturating_sub(report.last_sequence)>normal_lag
            || report.decoded_frames.is_some_and(|decoded|decoded.saturating_mul(2)<report.received_frames)
            || report.maximum_decode_us.is_some_and(|us|us>1_250_000/u64::from(fps.max(1)));
        if congested {ReceiverCondition::Congested} else {ReceiverCondition::Healthy}
    }
}

pub(crate) struct ReportWindow {
    sequence:u64,
    sources:BTreeMap<u32,SourceWindow>,
}
struct SourceWindow {
    context:Option<ReceiverContext>,
    start:Instant,
    last:Instant,
    payload_bytes:u64,
    frames:u32,
    decoded:Option<u32>,
    decode_us:Option<u64>,
}
impl ReportWindow {
    pub(crate) fn new(_now:Instant)->Self {
        Self{sequence:0,sources:BTreeMap::new()}
    }
    pub(crate) fn observe(&mut self, context:ReceiverContext, last_sequence:u64, bytes:usize, decoded:Option<bool>, decode_time:Duration, now:Instant)->io::Result<Option<ReceiverReport>> {
        self.sources.retain(|_,value|value.context.as_ref().is_some_and(|old|old.connection_generation==context.connection_generation && old.layout_epoch==context.layout_epoch));
        if !self.sources.contains_key(&context.source) && self.sources.len()>=64 {return Err(io::Error::other("receiver source window bound exceeded"));}
        let sample=self.sources.entry(context.source).or_insert_with(||SourceWindow{context:None,start:now,last:now,payload_bytes:0,frames:0,decoded:Some(0),decode_us:Some(0)});
        if sample.context.as_ref()!=Some(&context) || now.saturating_duration_since(sample.last)>Duration::from_secs(2) || now.saturating_duration_since(sample.start)>Duration::from_secs(2) {
            sample.context=Some(context.clone());sample.start=now;sample.payload_bytes=0;sample.frames=0;sample.decoded=Some(0);sample.decode_us=Some(0);
        }
        sample.last=now;
        sample.payload_bytes=sample.payload_bytes.checked_add(u64::try_from(bytes).map_err(io::Error::other)?).ok_or_else(||io::Error::other("receiver report byte overflow"))?;
        sample.frames=sample.frames.checked_add(1).ok_or_else(||io::Error::other("receiver report frame overflow"))?;
        if let Some(decoded)=decoded {
            sample.decoded=sample.decoded.map(|n|n.saturating_add(u32::from(decoded)));
            sample.decode_us=sample.decode_us.map(|us|us.max(u64::try_from(decode_time.as_micros()).unwrap_or(u64::MAX)));
        }else{sample.decoded=None;sample.decode_us=None;}
        let window=now.saturating_duration_since(sample.start);
        if window<Duration::from_millis(500) {return Ok(None);}
        let report=ReceiverReport{context,report_sequence:self.sequence.checked_add(1).ok_or_else(||io::Error::other("receiver report sequence overflow"))?,last_sequence,window_ms:u32::try_from(window.as_millis()).map_err(io::Error::other)?,received_payload_bytes:sample.payload_bytes,received_frames:sample.frames,decoded_frames:sample.decoded,maximum_decode_us:sample.decode_us};
        report.validate().map_err(io::Error::other)?;
        Ok(Some(report))
    }
    pub(crate) fn inserted(&mut self, report:&ReceiverReport, now:Instant){
        self.sequence=report.report_sequence;
        if let Some(sample)=self.sources.get_mut(&report.context.source){
            sample.start=now;sample.payload_bytes=0;sample.frames=0;sample.decoded=Some(0);sample.decode_us=Some(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context()->ReceiverContext{ReceiverContext{connection_generation:2,layout_epoch:1,source:0,format_epoch:0,format_sha256:Vec::new()}}
    #[test]
    fn actual_window_reports_only_observed_data_and_queued_sequence_is_not_reused()->io::Result<()> {
        let now=Instant::now();let mut window=ReportWindow::new(now);
        assert!(window.observe(context(),1,100,None,Duration::ZERO,now)?.is_none());
        let first=window.observe(context(),2,200,None,Duration::ZERO,now+Duration::from_millis(500))?.ok_or_else(||io::Error::other("missing report"))?;
        assert_eq!((first.received_payload_bytes,first.received_frames,first.decoded_frames,first.maximum_decode_us),(300,2,None,None));
        window.inserted(&first,now+Duration::from_millis(500));
        let next=window.observe(context(),3,400,Some(true),Duration::from_millis(4),now+Duration::from_secs(1))?.ok_or_else(||io::Error::other("missing next report"))?;
        assert_eq!((next.report_sequence,next.received_payload_bytes,next.decoded_frames),(2,400,Some(1)));
        Ok(())
    }
    #[test]
    fn replay_unsent_cross_context_and_old_reports_cannot_refresh_current_health()->io::Result<()> {
        let now=Instant::now();let current=context();let mut tracker=ReceiverReportTracker::default();
        let report=ReceiverReport{context:current.clone(),report_sequence:1,last_sequence:5,window_ms:500,received_payload_bytes:500,received_frames:5,decoded_frames:Some(5),maximum_decode_us:Some(4000)};
        let mut bad=report.clone();bad.last_sequence=6;assert!(tracker.accept(bad,&current,5,now).is_err());
        tracker.accept(report.clone(),&current,5,now)?;
        assert_eq!(tracker.condition(&current,5,30,now),ReceiverCondition::Healthy);
        tracker.accept(report.clone(),&current,5,now+Duration::from_secs(3))?;
        assert_eq!(tracker.condition(&current,5,30,now+Duration::from_secs(3)),ReceiverCondition::Unknown);
        assert_eq!(tracker.condition(&current,50,30,now),ReceiverCondition::Congested);
        let mut changed=current.clone();changed.layout_epoch=2;
        let mut old=report;old.report_sequence=2;tracker.accept(old,&changed,5,now+Duration::from_secs(3))?;
        assert_eq!(tracker.condition(&changed,5,30,now+Duration::from_secs(3)),ReceiverCondition::Unknown);
        Ok(())
    }
    #[test]
    fn report_cadence_and_multiple_approved_sources_do_not_create_false_congestion()->io::Result<()> {
        let now=Instant::now();let mut window=ReportWindow::new(now);let first=context();let mut second=first.clone();second.source=42;
        assert!(window.observe(first.clone(),1,100,Some(true),Duration::from_millis(1),now)?.is_none());
        assert!(window.observe(second.clone(),1,100,None,Duration::ZERO,now)?.is_none());
        let a=window.observe(first.clone(),2,100,Some(true),Duration::from_millis(1),now+Duration::from_millis(500))?.ok_or_else(||io::Error::other("source A missing"))?;
        window.inserted(&a,now+Duration::from_millis(500));
        let b=window.observe(second.clone(),2,100,None,Duration::ZERO,now+Duration::from_millis(500))?.ok_or_else(||io::Error::other("source B missing"))?;
        assert_eq!((a.report_sequence,b.report_sequence),(1,2));
        let mut tracker=ReceiverReportTracker::default();tracker.accept(a,&first,2,now)?;tracker.accept(b,&second,2,now)?;
        for source in [&first,&second] {
            assert_eq!(tracker.condition(source,29,60,now+Duration::from_millis(450)),ReceiverCondition::Healthy);
            assert_eq!(tracker.condition(source,90,60,now+Duration::from_millis(450)),ReceiverCondition::Congested);
            assert_eq!(tracker.condition(source,29,60,now+Duration::from_millis(2001)),ReceiverCondition::Unknown);
        }
        Ok(())
    }
}
