use super::*;

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn real_vp8_receiver_reports_cross_original_tls_and_quic_then_stop_with_original_lease()->Result {
    for quic in [false,true] {
        let mut pair=pair_with_features(quic,None,false,true).await?;
        let frames=Arc::new(Mutex::new(VecDeque::new()));
        let stopped=Arc::new(AtomicBool::new(false));
        let display=Display{source:42,left:0,top:0,width:64,height:48,logical_width:64,logical_height:48};
        let mut sender=VideoSender::attach(&mut pair.host,Capture{frames:frames.clone(),stopped:stopped.clone()},EPOCH,vec![display],vec![selected(42)])?;
        let mut receiver=VideoReceiver::attach(pair.controller,EPOCH,vec![selected(42)])?;
        let deadline=Instant::now()+Duration::from_secs(2);
        let mut decoded=0;
        while sender.stats().receiver_reports==0 && Instant::now()<deadline {
            push(&frames,42,[0,255,0,255])?;
            tokio::time::sleep(Duration::from_millis(20)).await;
            if receiver.poll_video()?.is_some(){decoded+=1;}
        }
        assert!(decoded>2,"actual decoder must progress before receiver health is reported");
        assert!(sender.stats().receiver_reports>0,"original authenticated feedback did not reach producer (quic={quic})");
        pair.revoke.send_replace(Some(StopReason::Revoked));
        pair.controller_revoke.send_replace(Some(StopReason::Revoked));
        wait_until(||Ok(sender.monitor().status().finished && receiver.monitor().status().finished)).await?;
        assert!(receiver.poll_video().is_err());
        assert_eq!(sender.shutdown(StopReason::Revoked)?,ShutdownReport::Joined);
        assert_eq!(receiver.shutdown(StopReason::Revoked)?,ShutdownReport::Joined);
        pair.host.shutdown(StopReason::Revoked).await?;
    }
    Ok(())
}
