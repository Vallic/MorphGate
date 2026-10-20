//! Sliding-window replay protection for packet ids (UDP may reorder; it must not repeat).

const WINDOW: u32 = 128;

#[derive(Default)]
pub struct ReplayWindow {
    highest: u32,
    /// Bit `i` = id `highest - i` seen.
    seen: u128,
}

impl ReplayWindow {
    /// `true` for a fresh id (and remembers it); `false` for a repeat or one too old to judge.
    pub fn check_and_set(&mut self, id: u32) -> bool {
        if id == 0 {
            return false;
        }
        if id > self.highest {
            let shift = id - self.highest;
            self.seen = if shift >= WINDOW {
                0
            } else {
                self.seen << shift
            };
            self.seen |= 1;
            self.highest = id;
            return true;
        }
        let age = self.highest - id;
        if age >= WINDOW {
            return false;
        }
        let bit = 1u128 << age;
        if self.seen & bit != 0 {
            return false;
        }
        self.seen |= bit;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_reordering_rejects_repeats() {
        let mut w = ReplayWindow::default();
        assert!(w.check_and_set(1));
        assert!(w.check_and_set(3));
        assert!(w.check_and_set(2));
        assert!(!w.check_and_set(2));
        assert!(!w.check_and_set(0));
        assert!(w.check_and_set(500));
        assert!(!w.check_and_set(3), "too old");
        assert!(w.check_and_set(499));
        assert!(!w.check_and_set(500));
    }
}
