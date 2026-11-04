//! Parsing and archival code report facts through this interface. The default
//! observer keeps synchronous callers compatible and never fabricates progress.
use crate::analyzers::Finding;

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogCounts {
    pub bytes: u64,
    pub lines: u64,
    pub parsed: u64,
    pub invalid: u64,
    pub oversized: u64,
    pub hits: u64,
}
pub trait Observer: Sync {
    fn check(&self) -> Result<(), String> {
        Ok(())
    }
    fn phase(&self, _phase: &str, _total: u64) -> Result<(), String> {
        self.check()
    }
    fn copied(&self, _bytes: u64) -> Result<(), String> {
        self.check()
    }
    fn scanned(&self, _counts: LogCounts, _findings: &[Finding]) -> Result<(), String> {
        self.check()
    }
    fn findings(&self, _findings: &[Finding]) -> Result<(), String> {
        self.check()
    }
    fn begin_commit(&self, _evidence_id: &str) -> Result<(), String> {
        self.check()
    }
}
pub struct Silent;
impl Observer for Silent {}
