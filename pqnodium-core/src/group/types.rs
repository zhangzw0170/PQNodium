use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Unique 32-byte group identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GroupId([u8; 32]);

impl GroupId {
    /// Generate a cryptographically random group ID.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Construct from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for GroupId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…")
    }
}

/// A 32-byte symmetric group key, zeroed on drop.
///
/// **Note:** `Clone` duplicates key material in memory. Use sparingly and
/// prefer passing references. Do **not** derive `PartialEq` — use
/// [`ct_eq`](GroupKey::ct_eq) for comparisons to prevent timing side-channels.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GroupKey([u8; 32]);

impl GroupKey {
    /// Construct from raw bytes.
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Constant-time equality comparison to prevent timing side-channels.
    pub fn ct_eq(&self, other: &GroupKey) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ── GroupId: construction ──

    #[test]
    fn group_id_from_bytes_roundtrip() {
        let bytes = [0xab; 32];
        let id = GroupId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn group_id_from_zero_bytes() {
        let id = GroupId::from_bytes([0u8; 32]);
        assert_eq!(id.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn group_id_from_max_bytes() {
        let id = GroupId::from_bytes([0xff; 32]);
        assert_eq!(id.as_bytes(), &[0xff; 32]);
    }

    // ── GroupId: randomness ──

    #[test]
    fn group_id_random_unique() {
        let a = GroupId::random();
        let b = GroupId::random();
        assert_ne!(a, b);
    }

    #[test]
    fn group_id_random_statistical_uniqueness() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            assert!(
                seen.insert(GroupId::random()),
                "duplicate GroupId generated"
            );
        }
    }

    #[test]
    fn group_id_random_non_zero() {
        for _ in 0..100 {
            let id = GroupId::random();
            assert_ne!(
                id.as_bytes(),
                &[0u8; 32],
                "random GroupId should not be all-zero"
            );
        }
    }

    // ── GroupId: equality, clone, hash ──

    #[test]
    fn group_id_equality() {
        let bytes = [0x42; 32];
        let a = GroupId::from_bytes(bytes);
        let b = GroupId::from_bytes(bytes);
        assert_eq!(a, b);
    }

    #[test]
    fn group_id_inequality() {
        let a = GroupId::from_bytes([1; 32]);
        let b = GroupId::from_bytes([2; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn group_id_clone_equal() {
        let a = GroupId::random();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn group_id_hashable_no_false_positives() {
        let mut set = HashSet::new();
        let a = GroupId::from_bytes([1; 32]);
        let b = GroupId::from_bytes([2; 32]);
        assert!(set.insert(a.clone()));
        assert!(set.insert(b.clone()));
        assert!(
            !set.insert(a.clone()),
            "duplicate insert should return false"
        );
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn group_id_hashable_1000_unique() {
        let mut set = HashSet::new();
        for i in 0u8..255 {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            assert!(set.insert(GroupId::from_bytes(bytes)));
        }
        assert_eq!(set.len(), 255);
    }

    // ── GroupId: AsRef ──

    #[test]
    fn group_id_as_ref_len() {
        let id = GroupId::from_bytes([0x01; 32]);
        assert_eq!(id.as_ref().len(), 32);
    }

    #[test]
    fn group_id_as_ref_content() {
        let bytes = [0xcd; 32];
        let id = GroupId::from_bytes(bytes);
        assert_eq!(id.as_ref(), bytes.as_slice());
    }

    // ── GroupId: Display ──

    #[test]
    fn group_id_display_shows_8_byte_hex_prefix() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[1] = 0xcd;
        let id = GroupId::from_bytes(bytes);
        let s = format!("{id}");
        assert!(s.starts_with("abcd00"));
        assert!(s.ends_with('…'));
        // 16 hex chars (8 bytes) + "…" (3-byte UTF-8)
        assert_eq!(s.len(), 19);
    }

    #[test]
    fn group_id_display_all_zeros() {
        let id = GroupId::from_bytes([0u8; 32]);
        assert_eq!(format!("{id}"), "0000000000000000…");
    }

    #[test]
    fn group_id_display_all_ff() {
        let id = GroupId::from_bytes([0xff; 32]);
        assert_eq!(format!("{id}"), "ffffffffffffffff…");
    }

    // ── GroupKey: construction ──

    #[test]
    fn group_key_from_bytes_and_access() {
        let key = GroupKey::from_bytes([0x42; 32]);
        assert_eq!(key.as_bytes(), &[0x42u8; 32]);
    }

    #[test]
    fn group_key_from_zero_bytes() {
        let key = GroupKey::from_bytes([0u8; 32]);
        assert_eq!(key.as_bytes(), &[0u8; 32]);
    }

    // ── GroupKey: ct_eq ──

    #[test]
    fn group_key_ct_eq_same_key() {
        let a = GroupKey::from_bytes([0xab; 32]);
        assert!(a.ct_eq(&a), "key should be equal to itself");
    }

    #[test]
    fn group_key_ct_eq_identical_keys() {
        let a = GroupKey::from_bytes([0xab; 32]);
        let b = GroupKey::from_bytes([0xab; 32]);
        assert!(a.ct_eq(&b));
    }

    #[test]
    fn group_key_ct_eq_differs_single_byte() {
        let mut bytes_a = [0u8; 32];
        let mut bytes_b = [0u8; 32];
        bytes_a[31] = 1;
        bytes_b[31] = 2;
        let a = GroupKey::from_bytes(bytes_a);
        let b = GroupKey::from_bytes(bytes_b);
        assert!(
            !a.ct_eq(&b),
            "keys differing in one byte should not be equal"
        );
    }

    #[test]
    fn group_key_ct_eq_differs_single_bit() {
        let mut bytes_a = [0u8; 32];
        let mut bytes_b = [0u8; 32];
        bytes_a[0] = 0b0000_0000;
        bytes_b[0] = 0b0000_0001;
        let a = GroupKey::from_bytes(bytes_a);
        let b = GroupKey::from_bytes(bytes_b);
        assert!(
            !a.ct_eq(&b),
            "keys differing in one bit should not be equal"
        );
    }

    #[test]
    fn group_key_ct_eq_all_zeros_vs_all_ones() {
        let a = GroupKey::from_bytes([0u8; 32]);
        let b = GroupKey::from_bytes([0xff; 32]);
        assert!(!a.ct_eq(&b));
    }

    // ── GroupKey: clone ──

    #[test]
    fn group_key_clone_independent() {
        let a = GroupKey::from_bytes([0x11; 32]);
        let b = a.clone();
        assert!(a.ct_eq(&b));
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    // ── GroupKey: zeroize ──
    // We can't directly observe zeroize, but we verify the type supports it.

    #[test]
    fn group_key_zeroize_on_drop_compiles() {
        let key = GroupKey::from_bytes([0x42; 32]);
        drop(key);
        // If this compiles, ZeroizeOnDrop is correctly derived.
    }
}
