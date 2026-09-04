//! The reporting sink, and the verbosity ladder it enforces.
//!
//! par2cmdline's `-v` and `-q` are counters, not flags: `-q -q` is
//! silence and `-v -v` adds the per-packet detail. Every line this
//! program prints declares the level it belongs to, so the ladder lives
//! HERE and not at a few hundred call sites - which is the only way the
//! `create-silent` row (`-q -q`, empty stdout) stays true as lines are
//! added.

/// How loud a line is, and the whole reason the ladder lives in one
/// place.
///
/// The three levels are the reference's, read off the captured tables
/// rather than off its source: `verify-intact` passes `-q` and prints
/// Loading/Target/verdict, `verify-intact-verbose` passes nothing and
/// adds the packet counts and the set summary, and `repair-verbose`
/// passes `-v` and adds the per-kernel trace. So the DEFAULT is already
/// the middle rung - a sink that treated level 0 as terse would empty
/// twenty-three sweep rows at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Printed unless `-q -q`. The result lines a script parses:
    /// `Loading`, `Target`, the verdict sentences, create's `Opening`
    /// and `Done`.
    Terse,
    /// Printed at the default level and above, silenced by `-q`. The
    /// per-file packet counts, the set summary, create's header block.
    Normal,
    /// Printed at `-v` and above. The per-kernel trace and the damage
    /// census.
    Verbose,
}

/// Where the lines go. `stdio` is the program; the buffering
/// constructor is what the unit tests read back.
pub struct Sink {
    level: i32,
    buf: Option<(String, String)>,
}

impl Sink {
    /// The real one: straight to stdout and stderr.
    pub fn stdio() -> Sink {
        Sink {
            level: 0,
            buf: None,
        }
    }

    /// A capturing sink. `(stdout, stderr)` come back from
    /// [`Sink::take`].
    pub fn buffered() -> Sink {
        Sink {
            level: 0,
            buf: Some((String::new(), String::new())),
        }
    }

    /// Set the run's loudness: `verbose - quiet`, exactly as the two
    /// counters were seen on the command line.
    pub fn set_level(&mut self, level: i32) {
        self.level = level;
    }

    /// The current loudness, for a caller that must decide whether to
    /// do WORK rather than whether to print (the verbose repair prints
    /// a per-target open line, and finding the targets is not free).
    pub fn level(&self) -> i32 {
        self.level
    }

    /// Is this level going to print? Same predicate the sink applies,
    /// exposed so an expensive line is not formatted to be dropped.
    pub fn shows(&self, level: Level) -> bool {
        match level {
            // -q -q is silence, which is one step quieter than -q.
            Level::Terse => self.level > -2,
            Level::Normal => self.level >= 0,
            Level::Verbose => self.level >= 1,
        }
    }

    /// A line at [`Level::Terse`], which is everything a caller
    /// outside the three commands prints (help, the version lines).
    pub fn out(&mut self, line: &str) {
        self.line(Level::Terse, line);
    }

    /// A line at an explicit level.
    pub fn line(&mut self, level: Level, line: &str) {
        if !self.shows(level) {
            return;
        }
        match &mut self.buf {
            Some((o, _)) => {
                o.push_str(line);
                o.push('\n');
            }
            None => println!("{line}"),
        }
    }

    /// A diagnosis. NEVER filtered by the verbosity ladder: `-q -q` is
    /// silence about progress, not about failure, and the captured
    /// table pins a stderr line under `-q` on three separate shapes.
    pub fn err(&mut self, line: &str) {
        match &mut self.buf {
            Some((_, e)) => {
                e.push_str(line);
                e.push('\n');
            }
            None => eprintln!("{line}"),
        }
    }

    /// What a buffered sink collected. Panics on a stdio sink, which is
    /// a test-only mistake.
    pub fn take(&mut self) -> (String, String) {
        self.buf
            .take()
            .expect("take() on a stdio sink - only a buffered sink collects")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_twice_is_silence_and_the_third_q_does_not_unsilence() {
        for level in [-2, -3, -4] {
            let mut s = Sink::buffered();
            s.set_level(level);
            s.out("Done");
            let (o, _) = s.take();
            assert_eq!(o, "", "level {level} must print no normal line");
        }
    }

    #[test]
    fn one_quiet_still_prints_the_result_lines() {
        // The `create-default` row passes -q and the reference still
        // prints Opening/Done, so -q is NOT silence and a sink that
        // treated it as one would empty seventeen rows at once.
        let mut s = Sink::buffered();
        s.set_level(-1);
        s.out("Done");
        assert_eq!(s.take().0, "Done\n");
    }

    #[test]
    fn the_default_level_prints_normal_but_not_verbose() {
        // The captured `verify-intact-verbose` row is a bare `v` and it
        // carries the packet counts, so level 0 must show Normal; the
        // same row carries no `Data hash method:` line, so it must not
        // show Verbose.
        let mut s = Sink::buffered();
        s.set_level(0);
        s.line(Level::Normal, "Loaded 6 new packets");
        s.line(Level::Verbose, "Data hash method: x");
        assert_eq!(s.take().0, "Loaded 6 new packets\n");
    }

    #[test]
    fn one_quiet_drops_normal_and_keeps_terse() {
        let mut s = Sink::buffered();
        s.set_level(-1);
        s.line(Level::Normal, "Loaded 6 new packets");
        s.line(Level::Terse, "Loading \"set.par2\".");
        assert_eq!(s.take().0, "Loading \"set.par2\".\n");
    }

    #[test]
    fn stderr_survives_silence() {
        let mut s = Sink::buffered();
        s.set_level(-2);
        s.err("Not enough command line arguments.");
        let (o, e) = s.take();
        assert_eq!(o, "");
        assert_eq!(e, "Not enough command line arguments.\n");
    }
}
