//! Shared aggregate capacity and one-second-burst token bucket, independent of transport.
use nestlink_protocol::{ContractError, ErrorCode};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub opened_connections: u64,
    pub closed_connections: u64,
    pub admitted_bytes: u64,
}
#[derive(Clone, Default)]
pub(crate) struct Meter {
    counters: Counters,
    bucket: Option<(u64, u128, u64)>, // last monotonic sample, milli-byte tokens, rate
}
impl Meter {
    pub fn counters(&self) -> Counters {
        self.counters
    }
    pub fn reserve(&mut self, maximum: u32) -> Result<(), ContractError> {
        if self.counters.opened_connections - self.counters.closed_connections >= u64::from(maximum)
            || self.counters.opened_connections >= i64::MAX as u64
        {
            return Err(capacity());
        }
        self.counters.opened_connections += 1;
        Ok(())
    }
    pub fn close(&mut self) {
        // A non-cloneable reservation calls this once. There is no allocation-ID map to leak.
        if self.counters.closed_connections < self.counters.opened_connections {
            self.counters.closed_connections += 1;
        }
    }
    pub fn restore(&mut self, counters: Counters) -> Result<(), ContractError> {
        if counters.closed_connections > counters.opened_connections
            || counters.admitted_bytes > i64::MAX as u64
            || counters.opened_connections > i64::MAX as u64
            || counters.closed_connections > i64::MAX as u64
        {
            return Err(capacity_error());
        }
        self.counters = counters;
        Ok(())
    }

    /// Durable service admission commits its highwater before the caller may
    /// enqueue or forward bytes. A later enqueue failure remains charged.
    pub fn admit_durable(
        &mut self,
        bytes: u64,
        rate: u64,
        now: u64,
        persist: impl FnOnce(Counters) -> Result<(), ContractError>,
    ) -> Result<(), ContractError> {
        let capacity = u128::from(rate) * 1000;
        let (last, tokens, old_rate) = self.bucket.unwrap_or((now, capacity, rate));
        if now < last || old_rate != rate {
            return Err(ContractError::new(
                ErrorCode::PolicyRevoked,
                "service meter clock or quota changed",
            ));
        }
        let available = (tokens + u128::from(now - last) * u128::from(rate)).min(capacity);
        let cost = u128::from(bytes) * 1000;
        let admitted_bytes = self
            .counters
            .admitted_bytes
            .checked_add(bytes)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or_else(capacity_error)?;
        if bytes == 0 || cost > available {
            return Err(capacity_error());
        }
        let counters = Counters {
            admitted_bytes,
            ..self.counters
        };
        persist(counters)?;
        self.bucket = Some((now, available - cost, rate));
        self.counters = counters;
        Ok(())
    }
    pub fn admit<T>(
        &mut self,
        bytes: u64,
        rate: u64,
        now: u64,
        enqueue: impl FnOnce() -> Result<T, ContractError>,
    ) -> Result<T, ContractError> {
        let capacity = u128::from(rate) * 1000;
        let (last, tokens, old_rate) = self.bucket.unwrap_or((now, capacity, rate));
        if now < last || old_rate != rate {
            return Err(ContractError::new(
                ErrorCode::PolicyRevoked,
                "node meter clock or quota changed",
            ));
        }
        let available = (tokens + u128::from(now - last) * u128::from(rate)).min(capacity);
        let cost = u128::from(bytes) * 1000;
        let total = self
            .counters
            .admitted_bytes
            .checked_add(bytes)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or_else(capacity_error)?;
        if bytes == 0 || cost > available {
            return Err(capacity_error());
        }
        let result = enqueue()?;
        self.bucket = Some((now, available - cost, rate));
        self.counters.admitted_bytes = total;
        Ok(result)
    }
}
fn capacity() -> ContractError {
    capacity_error()
}
fn capacity_error() -> ContractError {
    ContractError::new(
        ErrorCode::CapacityExceeded,
        "node aggregate capacity exceeded",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_capacity_rate_refill_and_failed_enqueue_count_once() -> Result<(), ContractError> {
        let mut m = Meter::default();
        m.reserve(2)?;
        m.reserve(2)?;
        assert!(m.reserve(2).is_err());
        m.admit(600, 1000, 0, || Ok(()))?;
        assert!(m.admit(401, 1000, 0, || Ok(())).is_err());
        assert!(m.admit(400, 1000, 0, || Err::<(), _>(capacity())).is_err());
        assert_eq!(m.counters.admitted_bytes, 600);
        m.admit(400, 1000, 0, || Ok(()))?;
        assert!(m.admit(1, 1000, 0, || Ok(())).is_err());
        m.admit(500, 1000, 500, || Ok(()))?;
        assert!(m.admit(1, 1000, 499, || Ok(())).is_err());
        assert!(m.admit(1, 999, 501, || Ok(())).is_err());
        m.close();
        m.reserve(2)?;
        m.close();
        m.close();
        assert_eq!(
            m.counters(),
            Counters {
                opened_connections: 3,
                closed_connections: 3,
                admitted_bytes: 1500
            }
        );
        Ok(())
    }
}
