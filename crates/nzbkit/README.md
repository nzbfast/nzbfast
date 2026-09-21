# nzbkit

The nzbfast engine: a one-pass NZB download pipeline.

NNTP `BODY` commands are pipelined per connection so latency never
idles a socket, articles are yEnc-decoded in place as they come off the
wire and written at their final file offsets, and PAR2 verification,
repair decisions and archive extraction happen while the download runs
instead of after it. Multi-provider fleets share one queue with union
availability accounting, so a post missing on one server completes from
another.

This crate is a facade over [`nzbkit-base`](https://github.com/nzbfast/nzbfast/tree/main/crates/nzbkit-base), which
carries the wire, the disk, the codecs and the containers; what lives
here is extraction, the connection pool, media probing and the indexer.
The downloader built on it is
[nzbfast](https://github.com/nzbfast/nzbfast).

## Status

**This crate is not on crates.io yet.** It depends on a vendored fork
of `rars` by path, and `nzbkit-base` has to be published first. See
TODO paragraph 84 in the nzbfast repository for the current state.

## Licence

GPL-3.0-or-later.
