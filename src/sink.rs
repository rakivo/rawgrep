use std::sync::Arc;
use crossbeam_channel::Sender;

pub trait MatchSink: Send + Sync + Clone {
    const STDOUT_NOP: bool;

    fn push(&self, path: &[u8], line_num: u32, text: &[u8], ranges: &[(u32, u32)]);
}

#[derive(Copy, Clone)]
pub struct NoSink;

impl MatchSink for NoSink {
    const STDOUT_NOP: bool = false;

    #[inline(always)]
    fn push(&self, _: &[u8], _: u32, _: &[u8], _: &[(u32, u32)]) {}
}

#[derive(Debug)]
pub struct RawMatch {
    pub path:     Box<[u8]>,          // Full file path
    pub line_num: u32,                // 1-indexed line number
    pub text:     Box<[u8]>,          // The matched line content
    pub ranges:   Box<[(u32, u32)]>,  // Byte ranges of match spans within text
}

#[derive(Clone)]
pub struct ChannelSink(pub Sender<RawMatch>);

impl MatchSink for ChannelSink {
    const STDOUT_NOP: bool = true;

    #[inline(always)]
    fn push(&self, path: &[u8], line_num: u32, text: &[u8], ranges: &[(u32, u32)]) {
        self.0.send(RawMatch {
            path:     path.into(),
            line_num,
            text:     text.into(),
            ranges:   ranges.into(),
        }).ok();
    }
}

pub struct CallbackSink<F>(pub Arc<F>);

impl<F> Clone for CallbackSink<F>
where
    F: Fn(&[u8], u32, &[u8], &[(u32, u32)]) + Send + Sync
{
    #[inline]
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<F> MatchSink for CallbackSink<F>
where
    F: Fn(&[u8], u32, &[u8], &[(u32, u32)]) + Send + Sync
{
    const STDOUT_NOP: bool = true;

    #[inline(always)]
    fn push(&self, path: &[u8], line_num: u32, text: &[u8], ranges: &[(u32, u32)]) {
        (self.0)(path, line_num, text, ranges);
    }
}
