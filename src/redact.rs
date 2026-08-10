//! Redaction helpers that keep shielded values out of `Debug` and trace output.
//!
//! Seismic stores confidential state in the same trie as public state, distinguished only by
//! the leaf's `is_private` flag. Nothing stops a `Debug` impl from rendering a private leaf's
//! value, and once it reaches a `trace!` call the plaintext lands in the node's log sink.
//!
//! [`MaybeRedacted`] renders public values exactly as before (hex-encoded) and replaces private
//! ones with a fixed marker. The marker deliberately carries no length: the byte length of an
//! RLP-encoded storage value correlates with the magnitude of the secret it holds.

use alloy_primitives::hex;
use core::fmt;

/// The placeholder substituted for the value of a private leaf.
pub(crate) const REDACTED: &str = "<redacted>";

/// A stand-in rendered in place of a value that must not reach the log sink.
///
/// Used where the value is not a plain byte slice (for example
/// [`HashBuilderValue`](crate::hash_builder::HashBuilderValue)) and wrapping it in
/// [`MaybeRedacted`] would be awkward.
pub(crate) struct RedactedValue;

impl fmt::Debug for RedactedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// Wraps a trie value so that it only renders when the value is public.
pub(crate) struct MaybeRedacted<'a> {
    /// The raw node value.
    pub(crate) value: &'a [u8],
    /// Whether the value belongs to a private slot.
    pub(crate) is_private: bool,
}

impl fmt::Debug for MaybeRedacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_private {
            f.write_str(REDACTED)
        } else {
            fmt::Debug::fmt(&hex::encode(self.value), f)
        }
    }
}
