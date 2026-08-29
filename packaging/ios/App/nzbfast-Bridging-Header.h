/* Objective-C bridging header: the engine's C ABI, made visible to
 * Swift.
 *
 * It includes the REAL header out of crates/nzbfast-ffi rather than
 * restating the three prototypes, and that is the whole point of having
 * one. The A3 spike harness binds the same symbols with
 * `@_silgen_name`, which is fine for a throwaway and wrong here: that
 * attribute asserts a signature instead of checking one, so a
 * parameter added on the Rust side (as `out_dir` was, for TODO 281 IO1)
 * would be a silently corrupted call frame at run time. Through this
 * header the same drift is a compile error.
 */
#ifndef NZBFAST_BRIDGING_HEADER_H
#define NZBFAST_BRIDGING_HEADER_H

#include "nzbfast.h"

#endif /* NZBFAST_BRIDGING_HEADER_H */
