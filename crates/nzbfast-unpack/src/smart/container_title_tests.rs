//! `smart::main_video` composed with `identity::container_title` - the
//! pair `serve::naming` writes, pinned as a pair.
//!
//! IT LIVES HERE AND NOT IN `identity` because of the crate-split step 2
//! cut: `identity` is `nzbfast-core` now and `main_video` is `smart`,
//! which is a layer above it, so a core-side test can no longer reach
//! half of what it is about. It moved rather than being dropped -
//! `container_title` takes the VIDEO since the crate-split prep, and the
//! property under test ("read from the FEATURE only") is a fact about
//! the composition and not about either half. With both halves taking a
//! `&Path`, passing the directory straight to `container_title` still
//! COMPILES and quietly tests nothing, which is why the composition is
//! spelled once below rather than at each assertion.

use nzbfast_core::identity::container_title;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-ctitle-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn container_title_of_dir(dir: &std::path::Path) -> Option<String> {
    super::main_video(dir).and_then(|v| container_title(&v))
}

#[test]
fn the_container_title_is_read_from_the_feature_only() {
    let d = tmpdir("mkv");
    assert_eq!(container_title_of_dir(&d), None);
    // A non-Matroska feature has no Title to read.
    std::fs::write(d.join("movie.mp4"), vec![0u8; 4096]).unwrap();
    assert_eq!(container_title_of_dir(&d), None);
    let _ = std::fs::remove_dir_all(&d);

    // The real thing, repacker credit and all.
    let d = tmpdir("mkv2");
    let mux = nzbkit::mkv::test_mux_titled(
        Some(5400.0),
        Some((1920, 1080)),
        Some("Example.Movie.2019.1080p.BluRay.x264-GRP, RMZ.cr"),
    );
    // Padded with a Void element the way a real mux is, so the
    // feature is the biggest file here and still parses.
    let mut feature = mux.clone();
    feature.extend(nzbkit::mkv::el(&[0xEC], &vec![0u8; 8000]));
    std::fs::write(d.join("movie.mkv"), &feature).unwrap();
    assert_eq!(
        container_title_of_dir(&d).as_deref(),
        Some("Example.Movie.2019.1080p.BluRay.x264-GRP")
    );
    // The SAMPLE is not the feature: its Title is the sample's, and
    // reading it would name the release after a teaser.
    let sample = nzbkit::mkv::test_mux_titled(None, None, Some("Wrong.Sample.Name-XXX"));
    std::fs::write(d.join("movie-sample.mkv"), &sample).unwrap();
    assert_eq!(
        container_title_of_dir(&d).as_deref(),
        Some("Example.Movie.2019.1080p.BluRay.x264-GRP")
    );
    let _ = std::fs::remove_dir_all(&d);
}
