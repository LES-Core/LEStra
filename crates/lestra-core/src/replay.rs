use crate::MAX_PACKET_NUMBER_EXCLUSIVE;

const WINDOW_SIZE: u64 = 1024;
const WORD_COUNT: usize = 16;
const WORD_BITS: usize = 64;

/// Fixed-size receive replay window.
///
/// This type does not authenticate packets. The caller must
/// authenticate a packet before committing its packet number.
///
/// Each receiving direction must own a separate window.
#[derive(Default)]
pub struct ReplayWindow {
    highest: Option<u64>,
    seen: [u64; WORD_COUNT],
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Highest authenticated packet number, if any.
    pub fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Check whether a packet may be authenticated.
    ///
    /// Does not modify the replay window.
    pub fn is_candidate(&self, packet_number: u64) -> bool {
        if packet_number >= MAX_PACKET_NUMBER_EXCLUSIVE {
            return false;
        }

        let Some(highest) = self.highest else {
            return true;
        };

        if packet_number > highest {
            return true;
        }

        let distance = highest - packet_number;

        if distance >= WINDOW_SIZE {
            return false;
        }

        !self.is_seen(distance as usize)
    }

    /// Commit a successfully authenticated packet number.
    ///
    /// Rechecks the replay predicate before modifying state.
    /// Returns false for duplicate, expired or invalid numbers.
    ///
    /// Must only be called after successful authentication.
    pub fn commit_authenticated(&mut self, packet_number: u64) -> bool {
        if !self.is_candidate(packet_number) {
            return false;
        }

        match self.highest {
            None => {
                self.highest = Some(packet_number);
                self.mark_seen(0);
            }

            Some(highest) if packet_number > highest => {
                self.shift(packet_number - highest);
                self.highest = Some(packet_number);
                self.mark_seen(0);
            }

            Some(highest) => {
                let distance = highest - packet_number;
                self.mark_seen(distance as usize);
            }
        }

        true
    }

    fn is_seen(&self, distance: usize) -> bool {
        let word = distance / WORD_BITS;
        let bit = distance % WORD_BITS;

        self.seen[word] & (1_u64 << bit) != 0
    }

    fn mark_seen(&mut self, distance: usize) {
        let word = distance / WORD_BITS;
        let bit = distance % WORD_BITS;

        self.seen[word] |= 1_u64 << bit;
    }

    fn shift(&mut self, distance: u64) {
        if distance >= WINDOW_SIZE {
            self.seen.fill(0);
            return;
        }

        let distance = distance as usize;
        let word_shift = distance / WORD_BITS;
        let bit_shift = distance % WORD_BITS;

        let previous = self.seen;

        for (index, word) in self.seen.iter_mut().enumerate() {
            let Some(source) = index.checked_sub(word_shift) else {
                *word = 0;
                continue;
            };

            let mut value = previous[source] << bit_shift;

            if bit_shift != 0 && source > 0 {
                value |= previous[source - 1] >> (WORD_BITS - bit_shift);
            }

            *word = value;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_window_accepts_first_packet() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.highest(), None);
        assert!(window.is_candidate(0));
        assert!(window.commit_authenticated(0));
        assert_eq!(window.highest(), Some(0));
    }

    #[test]
    fn rejects_duplicates() {
        let mut window = ReplayWindow::new();

        assert!(window.commit_authenticated(10));
        assert!(!window.is_candidate(10));
        assert!(!window.commit_authenticated(10));
    }

    #[test]
    fn accepts_out_of_order_packets() {
        let mut window = ReplayWindow::new();

        assert!(window.commit_authenticated(100));
        assert!(window.commit_authenticated(98));
        assert!(window.commit_authenticated(99));

        assert_eq!(window.highest(), Some(100));

        assert!(!window.commit_authenticated(98));
        assert!(!window.commit_authenticated(99));
        assert!(!window.commit_authenticated(100));
    }

    #[test]
    fn enforces_window_boundaries() {
        let mut window = ReplayWindow::new();

        assert!(window.commit_authenticated(1024));

        // Distance 1023: inside the window.
        assert!(window.commit_authenticated(1));

        // Distance 1024: outside the window.
        assert!(!window.commit_authenticated(0));

        assert!(window.commit_authenticated(1025));

        assert!(!window.is_candidate(1));
    }

    #[test]
    fn preserves_seen_bits_across_word_boundaries() {
        for shift in [1, 63, 64, 65, 127, 128, 1023] {
            let mut window = ReplayWindow::new();

            assert!(window.commit_authenticated(100));
            assert!(window.commit_authenticated(100 + shift));

            assert!(!window.is_candidate(100));
            assert!(!window.commit_authenticated(100));

            assert_eq!(window.highest(), Some(100 + shift));
        }
    }

    #[test]
    fn large_jump_clears_previous_bitmap() {
        let mut window = ReplayWindow::new();

        assert!(window.commit_authenticated(0));
        assert!(window.commit_authenticated(5000));

        assert_eq!(window.highest(), Some(5000));

        assert_eq!(window.seen[0], 1);
        assert!(window.seen[1..].iter().all(|word| *word == 0));

        assert!(window.commit_authenticated(4999));
        assert!(!window.commit_authenticated(0));
    }

    #[test]
    fn precheck_does_not_modify_state() {
        let mut window = ReplayWindow::new();

        assert!(window.commit_authenticated(10));

        let previous = window.seen;

        assert!(window.is_candidate(MAX_PACKET_NUMBER_EXCLUSIVE - 1));

        assert_eq!(window.highest(), Some(10));
        assert_eq!(window.seen, previous);

        assert!(window.commit_authenticated(11));
    }

    #[test]
    fn rejects_packet_numbers_outside_protocol_limit() {
        let mut window = ReplayWindow::new();

        assert!(!window.is_candidate(MAX_PACKET_NUMBER_EXCLUSIVE));
        assert!(!window.commit_authenticated(u64::MAX));

        assert_eq!(window.highest(), None);

        assert!(window.commit_authenticated(MAX_PACKET_NUMBER_EXCLUSIVE - 1));
    }

    #[test]
    fn independent_windows_do_not_share_state() {
        let mut client = ReplayWindow::new();
        let mut server = ReplayWindow::new();

        assert!(client.commit_authenticated(0));
        assert!(server.is_candidate(0));
        assert!(server.commit_authenticated(0));

        assert!(client.commit_authenticated(100));

        assert_eq!(client.highest(), Some(100));
        assert_eq!(server.highest(), Some(0));
    }

    #[test]
    fn commit_rechecks_duplicate_after_precheck() {
        let mut window = ReplayWindow::new();

        assert!(window.is_candidate(42));
        assert!(window.is_candidate(42));

        assert!(window.commit_authenticated(42));
        assert!(!window.commit_authenticated(42));
    }
}
