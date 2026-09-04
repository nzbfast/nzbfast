//! `[source] split`, plane 7.K: one payload file posted as several raw
//! wire files and landed joined.
//!
//! The no-container split recipe. A poster who wants volumes but not an
//! archive cuts the file into contiguous parts and posts each one: no
//! rar bytes, no unpack pass, and a client that harvests blocks can put
//! it back together with no recovery spend at all, because every block
//! of the joined file exists in the post at its own offset.
//! `bench/capability-corpus` legs n18, n19 and n33 are the family.
//!
//! **Two directions, and the difference is which side of the cut a
//! recovery set describes.** `split_names = "join"` puts the whole file
//! in the set and leaves the parts to the naming plane - the MultiPar
//! join shape, where a client has to notice that several wire files are
//! ranges of one described member. `split_names = "parts"` puts the
//! PARTS in the set, as `name.001`, `name.002` and so on, and the
//! client joins what it has just named. The end state is the same file
//! either way, which is why one plane carries both.
//!
//! **A split profile carries exactly one `[source]` file**, refused by
//! the schema with the reason. With a split the wire files and the
//! source files are not one to one, so the positional walk every other
//! stage makes over the payload stops lining up, and the end state of a
//! MIXED post - one member joined out of parts, another named by the
//! wire - has no derivation this generator can state. Each of the three
//! legs is one logical file, which is what the shape is in the field.
//!
//! **This stage draws nothing.** The parts are slices of bytes that
//! were already drawn, so adding a split to a profile moves no payload
//! byte; it moves the wire names and message-ids, because there are
//! more files, which is correct - it is a different post.

use crate::assemble::SourceFile;
use crate::profile::{Profile, SplitNames};

/// What the split plane decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Split {
    /// The files that go on the WIRE: contiguous slices of the source,
    /// in order, named `<source>.001`, `<source>.002`, ...
    pub posted: Vec<SourceFile>,
    /// The files a recovery set DESCRIBES: the one whole source under
    /// `join`, and the parts under `parts`.
    pub described: Vec<SourceFile>,
}

/// Apply the split plane, or `None` when no source splits.
///
/// The part naming is `<name>.NNN`, 1-based and three digits, which is
/// the spelling every splitter in the field produces and the one a
/// client's own numeric-suffix ordering expects. It is used for the
/// wire file's `rel` in both directions: under `join` the naming plane
/// usually turns it into a token anyway, and under a descriptive wire
/// it is exactly what a real split post carries.
pub fn apply(profile: &Profile, sources: &[SourceFile]) -> Option<Split> {
    let spec = profile.source.files.first().filter(|f| f.split > 0)?;
    // The schema has refused every shape but this one: exactly one
    // source, at least two parts, and at least a byte in each.
    let whole = sources.first().expect("one source file");
    let n = spec.split as usize;
    let each = whole.bytes.len() / n;
    let mut posted = Vec::with_capacity(n);
    for i in 0..n {
        let start = i * each;
        // The LAST part takes the remainder, so a length that does not
        // divide evenly is carried rather than refused: a splitter cuts
        // at a fixed size and the tail is whatever is left, which is
        // what makes the last part the short one in the field too.
        let end = if i + 1 == n {
            whole.bytes.len()
        } else {
            start + each
        };
        let name = format!("{}.{:03}", whole.rel, i + 1);
        posted.push(SourceFile {
            base: name.clone(),
            rel: name,
            bytes: whole.bytes[start..end].to_vec(),
        });
    }
    let described = match spec.split_names {
        SplitNames::Join => vec![whole.clone()],
        SplitNames::Parts => posted.clone(),
    };
    Some(Split { posted, described })
}

#[cfg(test)]
mod tests {
    use crate::Profile;
    use crate::rng::Rng;

    fn split(extra: &str) -> super::Split {
        let p = Profile::parse(&format!(
            "[layout]\nname = \"t\"\nseed = 2\n\n[source]\n\
             files = [{{ name = \"Feature.mkv\", bytes = 1000{extra} }}]\n"
        ))
        .expect("profile parses");
        let sources = crate::assemble::sources(&p, &mut Rng::for_profile(&p)).expect("sources");
        super::apply(&p, &sources).expect("the profile splits")
    }

    /// The parts are contiguous slices of the source and nothing else:
    /// concatenated they ARE the file, which is the only reason a client
    /// can join them.
    #[test]
    fn the_parts_concatenate_back_to_the_source() {
        let p = Profile::parse(
            "[layout]\nname = \"t\"\nseed = 2\n\n[source]\n\
             files = [{ name = \"Feature.mkv\", bytes = 1000, split = 4 }]\n",
        )
        .expect("profile parses");
        let sources = crate::assemble::sources(&p, &mut Rng::for_profile(&p)).expect("sources");
        let s = super::apply(&p, &sources).expect("the profile splits");
        let joined: Vec<u8> = s.posted.iter().flat_map(|f| f.bytes.clone()).collect();
        assert_eq!(joined, sources[0].bytes);
        assert_eq!(s.posted.len(), 4);
    }

    /// A length that does not divide evenly puts the remainder in the
    /// LAST part, which is where a splitter cutting at a fixed size
    /// leaves it.
    #[test]
    fn an_uneven_length_makes_the_last_part_the_long_one() {
        let s = split(", split = 3");
        assert_eq!(s.posted[0].bytes.len(), 333);
        assert_eq!(s.posted[1].bytes.len(), 333);
        assert_eq!(s.posted[2].bytes.len(), 334);
    }

    /// The parts are named `.001`, `.002`, ... which is the spelling
    /// every splitter in the field produces.
    #[test]
    fn the_parts_are_numbered_from_one_in_three_digits() {
        let s = split(", split = 2");
        assert_eq!(s.posted[0].rel, "Feature.mkv.001");
        assert_eq!(s.posted[1].rel, "Feature.mkv.002");
    }

    /// The two directions differ in exactly one thing: which side of
    /// the cut the recovery set is handed.
    #[test]
    fn join_describes_the_whole_file_and_parts_describes_the_parts() {
        let join = split(", split = 2");
        assert_eq!(join.described.len(), 1);
        assert_eq!(join.described[0].rel, "Feature.mkv");

        let parts = split(", split = 2, split_names = \"parts\"");
        assert_eq!(parts.described.len(), 2);
        assert_eq!(parts.described[0].rel, "Feature.mkv.001");
        assert_eq!(
            parts.posted, parts.described,
            "under `parts` the set describes exactly what is on the wire"
        );
    }
}
