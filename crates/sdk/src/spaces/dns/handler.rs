use super::{REQUEST_TIMEOUT, authority::Authority};
use hickory_server::{
    net::runtime::Time,
    proto::{op::{Header, HeaderCounts, Metadata, OpCode, ResponseCode}, rr::{DNSClass, RData, Record, RecordType, rdata::{A, AAAA}}},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
};
use std::sync::Arc;
use tokio::sync::{Semaphore, watch};

pub(super) struct Handler {
    authority: Arc<Authority>,
    stop: watch::Sender<bool>,
    capacity: Semaphore,
}

impl Handler {
    pub(super) fn new(authority: Arc<Authority>, stop: watch::Sender<bool>) -> Self {
        Self { authority, stop, capacity: Semaphore::new(8) }
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(&self, request: &Request, mut response: R) -> ResponseInfo {
        let fallback = || {
            let mut metadata = Metadata::response_from_request(&request.metadata);
            metadata.response_code = ResponseCode::ServFail;
            ResponseInfo::from(Header { metadata, counts: HeaderCounts::default() })
        };
        let future = async {
            let mut metadata = Metadata::response_from_request(&request.metadata);
            metadata.recursion_available = false;
            let mut answers = Vec::new();
            let mut observation = None;
            let mut permit = None;
            metadata.response_code = ResponseCode::Refused;
            if let Ok(info) = request.request_info() {
                let query = info.query;
                let name = query.name().to_string();
                let managed = name.strip_suffix('.').unwrap_or(&name);
                let tail = format!(".{}", self.authority.suffix);
                let label = managed.strip_suffix(&tail);
                let in_scope = label.is_some_and(|s| !s.is_empty() && !s.contains('.'));
                if in_scope && request.metadata.op_code == OpCode::Query
                    && query.query_class() == DNSClass::IN
                    && matches!(query.query_type(), RecordType::A | RecordType::AAAA)
                    && !*self.stop.borrow()
                {
                    if let Ok(slot) = self.capacity.try_acquire() {
                        permit = Some(slot);
                        match self.authority.observe().await {
                            Ok(current) => {
                                metadata.authoritative = true;
                                metadata.response_code = ResponseCode::NXDomain;
                                if let Some(row) = current.directory.addresses.iter().find(|row| {
                                    row.active && !row.revoked && row.account_id == current.account && row.fqdn == managed
                                }) {
                                    let data = match query.query_type() {
                                        RecordType::A => row.ipv4.parse().ok().map(|ip| RData::A(A(ip))),
                                        RecordType::AAAA => row.ipv6.parse().ok().map(|ip| RData::AAAA(AAAA(ip))),
                                        _ => None,
                                    };
                                    if let Some(data) = data {
                                        answers.push(Record::from_rdata(query.original().name().clone(), 0, data));
                                        metadata.response_code = ResponseCode::NoError;
                                    }
                                }
                                observation = Some(current);
                            }
                            Err(_) => {
                                metadata.response_code = ResponseCode::ServFail;
                                let _ = self.stop.send(true);
                            }
                        }
                    } else { metadata.response_code = ResponseCode::ServFail; }
                }
            } else { metadata.response_code = ResponseCode::FormErr; }
            if *self.stop.borrow() {
                answers.clear(); metadata.response_code = ResponseCode::ServFail;
            }
            let message = MessageResponseBuilder::from_message_request(request)
                .build(metadata, answers.iter(), std::iter::empty(), std::iter::empty(), std::iter::empty());
            let deadline = observation.as_ref().map(|current| current.deadline)
                .unwrap_or_else(|| tokio::time::Instant::now() + REQUEST_TIMEOUT);
            let result = tokio::time::timeout_at(deadline, response.send_response(message)).await
                .ok().and_then(Result::ok).unwrap_or_else(fallback);
            // Retain both the current-session guard and the query budget until
            // the mature transport has accepted the response.
            drop(observation);
            drop(permit);
            result
        };
        tokio::time::timeout(REQUEST_TIMEOUT, future).await.unwrap_or_else(|_| fallback())
    }
}
