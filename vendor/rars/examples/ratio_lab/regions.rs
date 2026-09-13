//! Sample-guided regional filters. Probes are heuristics; the caller retains
//! a complete baseline archive because dictionary interactions are not additive.
use rars::codec::rar50::{
    EncodeOptions, Rar50FilterKind as Kind, Rar50FilterSpec as Spec, Unpack50Encoder,
};

pub fn select(data: &[u8], options: EncodeOptions, span: usize, merge: bool) -> Vec<Spec> {
    let kinds = [
        None,
        Some(Kind::Delta { channels: 1 }),
        Some(Kind::Delta { channels: 2 }),
        Some(Kind::Delta { channels: 3 }),
        Some(Kind::Delta { channels: 4 }),
        Some(Kind::Delta { channels: 8 }),
        Some(Kind::Delta { channels: 16 }),
        Some(Kind::Delta { channels: 24 }),
        Some(Kind::Delta { channels: 32 }),
        Some(Kind::E8E9),
        Some(Kind::Arm),
    ];
    let mut specs: Vec<Spec> = Vec::new();
    for start in (0..data.len()).step_by(span) {
        let end = (start + span).min(data.len());
        let region = &data[start..end];
        let sample_len = region.len().min(16 * 1024);
        let mut starts = vec![
            0,
            (region.len() - sample_len) / 2,
            region.len() - sample_len,
        ];
        starts.sort_unstable();
        starts.dedup();
        let mut best = usize::MAX;
        let mut winner = None;
        for kind in kinds {
            let mut cost = 0;
            for &offset in &starts {
                let sample = &region[offset..offset + sample_len];
                let mut encoder = Unpack50Encoder::with_options(options);
                let packed = if let Some(kind) = kind {
                    encoder.encode_member_with_filter(sample, 0, Spec::new(kind))
                } else {
                    encoder.encode_member(sample, 0)
                }
                .expect("region probe");
                cost += packed.len();
            }
            if cost < best {
                best = cost;
                winner = kind;
            }
        }
        if let Some(kind) = winner {
            if merge {
                if let Some(last) = specs.last_mut() {
                    if last.kind == kind && last.range.as_ref().unwrap().end == start {
                        last.range.as_mut().unwrap().end = end;
                        continue;
                    }
                }
            }
            specs.push(Spec::range(kind, start..end));
        }
    }
    eprintln!("regional span={span} merge={merge} filters={}", specs.len());
    specs
}
