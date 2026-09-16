//! The digest cache with the `digest-cache` feature OFF: the same
//! crate-internal surface as `digest_cache.rs`, every member of it inert,
//! so the create and verify paths compile one way and never branch on the
//! feature. There is no store here to publish, so nothing public.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

/// Uninhabited: no store exists without the feature.
pub enum DigestCache {}

pub(crate) const FLAG_CREATE: u32 = 1;
pub(crate) const FLAG_VERIFY: u32 = 2;

pub(crate) fn active() -> Option<Arc<DigestCache>> {
    None
}

pub(crate) fn has_record(_cache: Option<&Arc<DigestCache>>, _path: &Path, _length: u64) -> bool {
    false
}

pub(crate) struct MemberDigest;

impl MemberDigest {
    pub(crate) fn begin(
        _cache: Option<&Arc<DigestCache>>,
        _file: &File,
        _path: &Path,
        _length: u64,
        _flags: u32,
    ) -> MemberDigest {
        MemberDigest
    }

    #[inline]
    pub(crate) fn chain_abandoned(&self) -> bool {
        false
    }

    pub(crate) fn validated_md5(&mut self) -> Option<[u8; 16]> {
        None
    }

    pub(crate) fn unresolved(&mut self, _why: &str) -> Option<&'static str> {
        None
    }

    pub(crate) fn resolve(
        self,
        chain: Option<[u8; 16]>,
    ) -> Result<([u8; 16], Option<Pending>), String> {
        chain
            .map(|md5| (md5, None))
            .ok_or_else(|| "a whole-file chain stopped with no digest record behind it".into())
    }
}

pub(crate) struct Pending;

impl Pending {
    pub(crate) fn commit(self) {}
}
