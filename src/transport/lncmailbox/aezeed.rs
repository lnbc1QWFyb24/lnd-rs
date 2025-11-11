#![cfg(feature = "transport-mailbox")]
//! AEZEED pairing phrase helpers compatible with LNC Go implementation.
//! - Uses the 2048-word English list (same as lnd/aezeed `DefaultWordList`).
//! - Packs 11 bits/word across 10 words to produce 14 bytes of entropy.

use std::collections::HashMap;
use std::sync::LazyLock;

const WORDS: &str = include_str!("../../../resources/aezeed_words_english.txt");

static WORD_MAP: LazyLock<HashMap<&'static str, u16>> = LazyLock::new(|| {
    let mut map = HashMap::with_capacity(2048);
    for (i, w) in WORDS.lines().enumerate() {
        let idx = u16::try_from(i).expect("word list fits in u16");
        map.insert(w.trim(), idx);
    }
    map
});

/// Convert a 10-word AEZEED phrase into its 14-byte entropy form.
///
/// # Errors
/// Returns an error when the phrase length is not 10 words or any word is not part of the
/// expected AEZEED dictionary.
///
/// # Panics
/// Panics if the bundled word list contains more than `u16::MAX` entries, which cannot happen with
/// the canonical 2048-word list.
pub fn mnemonic_to_entropy(words: &[String]) -> Result<[u8; 14], String> {
    if words.len() != 10 {
        return Err("pairing phrase must be 10 words".into());
    }
    // Pack 10×11 bits MSB-first into 14 bytes, leaving the last 2 bits zeroed.
    let mut out = [0u8; 14];
    let mut bit_index = 0usize; // counts from MSB of out[0]
    for w in words {
        let idx = *WORD_MAP
            .get(w.as_str())
            .ok_or_else(|| format!("unknown word: {w}"))?;
        for i in (0..11).rev() {
            let bit = ((idx >> i) & 1) as u8;
            let byte_index = bit_index / 8;
            let bit_in_byte = 7 - (bit_index % 8);
            out[byte_index] |= bit << bit_in_byte;
            bit_index += 1;
        }
    }
    debug_assert_eq!(bit_index, 110);
    // Remaining 2 bits are left as 0 by design.
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_matches_reference_entropy() {
        let words = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse",
        ];
        let input: Vec<String> = words.iter().copied().map(str::to_string).collect();
        let entropy = mnemonic_to_entropy(&input).expect("entropy");
        assert_eq!(hex::encode(entropy), "0000040100300801403007010024");
    }
}
