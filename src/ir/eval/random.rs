//! The default glibc additive random number generator.

#[derive(Clone)]
pub(super) struct Random {
    words: [u32; 31],
    position: usize,
}

impl Default for Random {
    fn default() -> Self {
        Self::seeded(1)
    }
}

impl Random {
    pub(super) fn seeded(seed: u32) -> Self {
        let seed = if seed == 0 { 1 } else { seed };
        let mut words = [0; 31];
        words[0] = seed;
        let mut value = i64::from(seed as i32);
        for word in &mut words[1..] {
            value = 16807 * (value % 127773) - 2836 * (value / 127773);
            if value < 0 {
                value += 2147483647;
            }
            *word = value as u32;
        }
        let mut random = Self { words, position: 0 };
        for _ in 0..310 {
            random.next();
        }
        random
    }

    pub(super) fn next(&mut self) -> u32 {
        let front = (self.position + 3) % 31;
        let value = self.words[front].wrapping_add(self.words[self.position]);
        self.words[front] = value;
        self.position = (self.position + 1) % 31;
        value >> 1
    }
}
