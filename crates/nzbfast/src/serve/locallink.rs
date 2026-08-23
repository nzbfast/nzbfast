//! The local link: which network interface carries this daemon's
//! traffic to the news servers, what it is (wired, Wi-Fi, a tunnel),
//! and what it can carry.
//!
//! Why this exists: a tester on a 710 Mbit line over Wi-Fi 6 hit
//! 560 Mbit and nothing in the product could tell him that was his
//! access point, not the client and not the ISP. The tuner scored his
//! providers against the typed line speed, which his LAN could never
//! reach, and the system benchmark's network row could not say WHICH
//! network is short. This module answers that one question, and three
//! surfaces read it: the tune hint names the link when it is the
//! ceiling ([`LocalLink::verdict`]), the System benchmark's network row
//! names it when the measurement ran into it
//! ([`LocalLink::measured_note`]), and the "why is this slow?" panel
//! draws its 100% mark at the LAN when the LAN is lower than the typed
//! line (`whyslow::link_capped`).
//!
//! Everything here is read-only and sends no packets: a route lookup,
//! the interface's media line or sysfs entries, and the Wi-Fi
//! association details the OS already holds. It shells out to the
//! platform's own tools and parses their text, with every parser a
//! pure function over captured output so it is unit-tested on every
//! platform regardless of where the tests run.
//!
//! What it refuses to judge: a tunnel (VPN, Tailscale, WireGuard) or
//! a container's bridge - the interface the daemon sees says nothing
//! about the physical link, and a guess there is worse than silence.

use nzbkit::sync::MutexExt;
use serde::Serialize;
use std::process::Command;

/// What kind of interface carries the traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum LinkKind {
    Wired,
    Wireless,
    Tunnel,
    /// Only the Windows arm produces this (an adapter whose media type
    /// names neither 802.3 nor 802.11).
    // Not #[expect]: dead off Windows in a PLAIN build only. `locallink_tests`
    // drives `win::adapter`, which is the one place that builds this variant,
    // so under --all-targets - the shape CI's clippy gate runs - the lint does
    // not fire and the expectation goes unfulfilled. Measured 23 Aug 2026:
    // unfulfilled on macOS, Linux and slim Linux --all-targets; fulfilled in
    // every plain build.
    #[cfg_attr(not(windows), allow(dead_code))]
    Unknown,
}

/// One observation of the local link.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct LocalLink {
    /// OS interface name (en0, wlp3s0, "Wi-Fi").
    pub iface: String,
    pub kind: LinkKind,
    /// The negotiated (wired) or current transmit (Wi-Fi) rate in
    /// megabits. 0 when the OS would not say.
    pub link_mbps: u64,
    /// Wi-Fi PHY mode ("802.11ax") or wired media ("1000baseT"); empty
    /// when unknown.
    pub phy: String,
    /// Wi-Fi signal in dBm (negative), when reported.
    pub signal_dbm: Option<i32>,
    /// Wi-Fi channel description ("165 (6GHz, 160MHz)"), when reported.
    pub channel: String,
    /// The newest 802.11 generation the ADAPTER supports ("802.11be"),
    /// as distinct from `phy`, which is what this association
    /// negotiated. When the adapter's is newer, the access point side
    /// is the older one. Empty when unknown.
    pub adapter_phy: String,
}

/// Wi-Fi delivers about this fraction of its link rate as TCP payload
/// in practice: the rate is the PHY rate of one frame, and contention,
/// ACKs, preambles and retries take the rest. Measured across Wi-Fi 5
/// and 6 gear the band is 50-65%; the midpoint is used and the copy
/// only ever says "about half".
const WIFI_EFFICIENCY: f64 = 0.55;
/// Wired Ethernet delivers nearly its negotiated rate; framing and TCP
/// headers cost about 5%.
const WIRED_EFFICIENCY: f64 = 0.95;

/// A measurement at or above this fraction of the estimated ceiling IS
/// the ceiling, for [`LocalLink::measured_note`].
///
/// The estimate carries its own error - the Wi-Fi band is 50-65% of the
/// link rate and 55% is the midpoint, so the true ceiling can sit ~18%
/// above what `ceiling_bps` returns - and a measurement inside that
/// error has run into the link however the estimate is read. Well below
/// it the link is plainly not what the download hit, and saying so
/// would send the reader to the wrong place.
const AT_CEILING: f64 = 0.85;

impl LocalLink {
    /// The most this link can carry, in bytes per second - or None when
    /// the link kind gives no basis for a ceiling.
    pub(crate) fn ceiling_bps(&self) -> Option<u64> {
        if self.link_mbps == 0 {
            return None;
        }
        let eff = match self.kind {
            LinkKind::Wired => WIRED_EFFICIENCY,
            LinkKind::Wireless => WIFI_EFFICIENCY,
            LinkKind::Tunnel | LinkKind::Unknown => return None,
        };
        Some((self.link_mbps as f64 * 1e6 / 8.0 * eff) as u64)
    }

    /// The verdict when this link sits well under the line the user
    /// typed: names the link and its rate as a fact about THIS machine,
    /// never a product to buy (the 20 Aug 2026 rule in
    /// `nzbkit::sysbench` - "a faster link" was bad advice twice over).
    /// Empty when the link is not the ceiling or cannot be judged.
    pub(crate) fn verdict(&self, line_bps: u64) -> String {
        let Some(ceiling) = self.ceiling_bps() else {
            return String::new();
        };
        // Speak whenever the link's ceiling sits under the line at all
        // (5% absorbs the estimate's own slack) - not at the provider
        // hint's 80% bar. The case this exists for was a 1200 Mbps
        // Wi-Fi link (~660 deliverable) under a 710 Mbit line: 93%,
        // and the whole of the user's shortfall.
        if line_bps == 0 || ceiling as f64 >= line_bps as f64 * 0.95 {
            return String::new();
        }
        let line_mbps = line_bps as f64 * 8.0 / 1e6;
        let ceil_mbps = ceiling as f64 * 8.0 / 1e6;
        match self.kind {
            LinkKind::Wireless => {
                let phy = if self.phy.is_empty() {
                    String::new()
                } else {
                    format!("{}, ", self.phy)
                };
                let chan = if self.channel.is_empty() {
                    String::new()
                } else {
                    format!(", channel {}", self.channel)
                };
                let mut v = format!(
                    "this machine reaches the internet over Wi-Fi ({phy}link {} Mbps on {}{chan}). \
                     Wi-Fi usually delivers about half its link rate, so ~{ceil_mbps:.0} Mbps \
                     is the most it can carry - under the ~{line_mbps:.0} Mbps Line speed. \
                     The access point, not the line or the client, is the ceiling; a wired \
                     connection would show whether the line has more",
                    self.link_mbps, self.iface
                );
                // The adapter can do better than this association: the
                // access point (or the band it offered) is the older
                // side. A fact about which end is limiting, not a
                // shopping list.
                if wifi_gen_rank(&self.adapter_phy) > wifi_gen_rank(&self.phy)
                    && !self.phy.is_empty()
                {
                    v.push_str(&format!(
                        ". The Wi-Fi adapter supports {} but this connection is {}, so the \
                         access point side is the older one",
                        self.adapter_phy, self.phy
                    ));
                }
                v
            }
            LinkKind::Wired => {
                let why = if self.link_mbps <= 100 {
                    " - a port negotiating 100 Mbps under a faster line is usually a cable \
                     or a switch port, and is worth checking"
                } else {
                    " - the port, not the line or the client, is the ceiling"
                };
                format!(
                    "this machine's network port ({}) negotiated {} Mbps, under the \
                     ~{line_mbps:.0} Mbps Line speed{why}",
                    self.iface, self.link_mbps
                )
            }
            LinkKind::Tunnel | LinkKind::Unknown => String::new(),
        }
    }

    /// The same fact as [`LocalLink::verdict`], but for a MEASURED
    /// figure rather than a typed line speed: the System benchmark's
    /// network row (TODO 210 item (b)).
    ///
    /// That row is a real Usenet download over N connections, and when
    /// it is the shortest of the three the card tells the reader that
    /// more connections or another provider may raise it. On a machine
    /// whose own link is what the download ran into, that advice is
    /// wrong and there is nothing the reader can do with it - the row
    /// has never been able to say WHICH network is short, which is the
    /// gap this module exists to close.
    ///
    /// Speaks only when the measurement has actually reached this
    /// link's ceiling. Empty otherwise, and empty for a link that
    /// gives no basis for a ceiling at all.
    pub(crate) fn measured_note(&self, measured_bps: u64) -> String {
        let Some(ceiling) = self.ceiling_bps() else {
            return String::new();
        };
        if measured_bps == 0 || (measured_bps as f64) < ceiling as f64 * AT_CEILING {
            return String::new();
        }
        let ceil_mbps = ceiling as f64 * 8.0 / 1e6;
        match self.kind {
            LinkKind::Wireless => {
                let phy = if self.phy.is_empty() {
                    String::new()
                } else {
                    format!("{}, ", self.phy)
                };
                format!(
                    "this machine reaches the internet over Wi-Fi ({phy}link {} Mbps on {}). \
                     Wi-Fi usually delivers about half its link rate, so ~{ceil_mbps:.0} Mbps \
                     is the most it can carry, and the figure above is at that ceiling. More \
                     connections will not raise it; a wired connection would show whether the \
                     line has more",
                    self.link_mbps, self.iface
                )
            }
            LinkKind::Wired => {
                let why = if self.link_mbps <= 100 {
                    " - a port negotiating 100 Mbps is usually a cable or a switch port, and \
                     is worth checking"
                } else {
                    ""
                };
                format!(
                    "this figure is at what this machine's network port ({}) negotiated, \
                     {} Mbps, so more connections will not raise it{why}",
                    self.iface, self.link_mbps
                )
            }
            LinkKind::Tunnel | LinkKind::Unknown => String::new(),
        }
    }
}

/// How many recent Wi-Fi transmit rates the published figure is the
/// median of. Three: enough to drop a single outlier, short enough
/// that a link that really changed is followed within two probes.
const TX_SAMPLES: usize = 3;

/// The recent Wi-Fi transmit rates for one interface, so what the rest
/// of the daemon reads is a median rather than one instantaneous
/// sample (TODO 210 item (a)).
///
/// Why: `Transmit Rate` / `tx bitrate` / `Transmit rate (Mbps)` is the
/// rate the radio last sent a frame at, and 802.11 rate-adapts per
/// frame. An idle machine reports whatever the last small exchange
/// negotiated, so two probes five minutes apart can differ several-fold
/// with the association, the band and the distance all unchanged. The
/// ceiling this feeds is a claim about what the link can carry, and it
/// should not swing on one frame's luck.
#[derive(Default)]
pub(crate) struct TxMedian {
    /// The interface the samples belong to; a different one starts over.
    iface: String,
    samples: std::collections::VecDeque<u64>,
}

impl TxMedian {
    /// Fold this probe's Wi-Fi rate in and replace it with the median
    /// of the last [`TX_SAMPLES`].
    ///
    /// Only Wi-Fi: a wired port reports a NEGOTIATED rate, which does
    /// not wander, and a tunnel has no rate to steady.
    ///
    /// The history belongs to one association. A different interface (a
    /// laptop docking, or roaming to Ethernet and back) or a rate the OS
    /// would not give at all (0, which reads as "no basis for a
    /// ceiling") starts it over, because a median across two different
    /// links describes neither of them.
    pub(crate) fn steady(&mut self, link: &mut LocalLink) {
        if link.kind != LinkKind::Wireless || link.link_mbps == 0 {
            self.samples.clear();
            self.iface.clear();
            return;
        }
        if self.iface != link.iface {
            self.samples.clear();
            self.iface = link.iface.clone();
        }
        self.samples.push_back(link.link_mbps);
        while self.samples.len() > TX_SAMPLES {
            self.samples.pop_front();
        }
        let mut v: Vec<u64> = self.samples.iter().copied().collect();
        v.sort_unstable();
        // With an even count this takes the UPPER of the two middles,
        // deliberately: overstating the link's ceiling only means this
        // module says nothing, and rule 1 of §210 is that silence beats
        // a guess.
        link.link_mbps = v[v.len() / 2];
    }
}

/// Probe the link that carries traffic to `target` (an IP literal).
/// Blocking: shells out, so call it from `spawn_blocking`. None when
/// the platform has no probe, a tool is missing, or the route could
/// not be read.
pub(crate) fn probe(target: &str) -> Option<LocalLink> {
    if std::path::Path::new("/.dockerenv").exists() {
        // A container's eth0 is a veth on a bridge: nothing about it
        // describes the host's link.
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        return mac::probe(target);
    }
    #[cfg(target_os = "linux")]
    {
        return linux::probe(target);
    }
    #[cfg(windows)]
    {
        return win::probe(target);
    }
    // Not #[expect]: this None is unreachable only where one of the arms
    // above matched. On a target with none of them (the iOS staticlib) it
    // is reachable and the expectation goes unfulfilled.
    #[allow(unreachable_code)]
    None
}

#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux", windows)),
    expect(dead_code)
)]
fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Interface names that are tunnels on every platform.
fn is_tunnel_name(iface: &str) -> bool {
    [
        "utun",
        "tun",
        "tap",
        "wg",
        "tailscale",
        "ppp",
        "ipsec",
        "zt",
        "nebula",
    ]
    .iter()
    .any(|p| iface.starts_with(p))
}

/// "1000baseT", "10Gbase-T", "2500Base-T" -> megabits.
fn media_mbps(s: &str) -> u64 {
    let lower = s.to_ascii_lowercase();
    let Some(pos) = lower.find("base") else {
        return 0;
    };
    let head = &lower[..pos];
    let digits: String = head
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit() || *c == 'g')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let (num, giga) = match digits.strip_suffix('g') {
        Some(n) => (n, true),
        None => (digits.as_str(), false),
    };
    let n: u64 = num.parse().unwrap_or(0);
    if giga { n * 1000 } else { n }
}

/// Rank of an 802.11 generation for "newer than" comparisons. Takes
/// the newest suffix in a list like "802.11 a/b/g/n/ac/ax/be" or a
/// single "802.11ax"; 0 when unrecognised.
fn wifi_gen_rank(phy: &str) -> u8 {
    phy.split(['/', ' ', ','])
        .map(
            |g| match g.trim().strip_prefix("802.11").unwrap_or(g).trim() {
                "b" => 1,
                "a" | "g" => 2,
                "n" => 3,
                "ac" => 4,
                "ax" => 5,
                "be" => 6,
                _ => 0,
            },
        )
        .max()
        .unwrap_or(0)
}

/// The newest generation named in a supported-modes list, as
/// "802.11xx"; empty when none recognised.
fn best_wifi_gen(list: &str) -> String {
    match wifi_gen_rank(list) {
        6 => "802.11be",
        5 => "802.11ax",
        4 => "802.11ac",
        3 => "802.11n",
        2 => "802.11g",
        1 => "802.11b",
        _ => "",
    }
    .to_string()
}

/// Value after the first ':' on the first line whose trimmed start is
/// `key`.
fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|l| {
        let t = l.trim();
        t.strip_prefix(key)
            .and_then(|rest| rest.trim_start().strip_prefix(':'))
            .map(str::trim)
    })
}

fn leading_int(s: &str) -> Option<i64> {
    let s = s.trim();
    let end = s
        .char_indices()
        .find(|(i, c)| !(c.is_ascii_digit() || (*i == 0 && *c == '-')))
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    s[..end].parse().ok()
}

// Every platform arm compiles everywhere so its parsers are tested
// everywhere; only its `probe` runs on its own OS.
// Not #[expect] for that reason: the parsers are exactly what
// `locallink_tests` exercises, so under --all-targets the module is live on
// every host and the expectation goes unfulfilled. Measured 23 Aug 2026:
// unfulfilled on Windows, Linux and slim Windows/Linux --all-targets;
// fulfilled in a plain build off macOS.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod mac {
    use super::*;

    #[cfg(target_os = "macos")]
    pub(super) fn probe(target: &str) -> Option<LocalLink> {
        let route = run("route", &["-n", "get", target])?;
        let iface = route_iface(&route)?;
        if is_tunnel_name(&iface) {
            return Some(tunnel(&iface));
        }
        let ports = run("networksetup", &["-listallhardwareports"]).unwrap_or_default();
        let port = hardware_port(&ports, &iface);
        if port
            .as_deref()
            .is_some_and(|p| p == "Wi-Fi" || p == "AirPort")
        {
            let sp = run(
                "system_profiler",
                &["SPAirPortDataType", "-detailLevel", "basic"],
            )
            .unwrap_or_default();
            return Some(wifi(&iface, &sp));
        }
        let ifc = run("ifconfig", &[&iface]).unwrap_or_default();
        Some(wired(&iface, &ifc))
    }

    pub(super) fn route_iface(route: &str) -> Option<String> {
        field(route, "interface").map(str::to_string)
    }

    /// The "Hardware Port:" name whose "Device:" line is `iface`.
    pub(super) fn hardware_port(ports: &str, iface: &str) -> Option<String> {
        let mut cur: Option<&str> = None;
        for l in ports.lines() {
            let t = l.trim();
            if let Some(p) = t.strip_prefix("Hardware Port:") {
                cur = Some(p.trim());
            } else if let Some(d) = t.strip_prefix("Device:")
                && d.trim() == iface
            {
                return cur.map(str::to_string);
            }
        }
        None
    }

    pub(super) fn wired(iface: &str, ifconfig: &str) -> LocalLink {
        let media = field(ifconfig, "media").unwrap_or("");
        let inner = media
            .split_once('(')
            .map(|(_, r)| r.split([' ', ')', '<']).next().unwrap_or(""))
            .unwrap_or("");
        LocalLink {
            iface: iface.to_string(),
            kind: LinkKind::Wired,
            link_mbps: media_mbps(inner),
            phy: inner.to_string(),
            signal_dbm: None,
            channel: String::new(),
            adapter_phy: String::new(),
        }
    }

    /// The "Current Network Information:" block of the connected
    /// interface - the first such block, which is the active one.
    pub(super) fn wifi(iface: &str, profile: &str) -> LocalLink {
        let cur = profile
            .split_once("Current Network Information:")
            .map(|(_, r)| r)
            .unwrap_or("");
        let cur = cur
            .split_once("Other Local Wi-Fi Networks:")
            .map(|(l, _)| l)
            .unwrap_or(cur);
        let signal = field(cur, "Signal / Noise")
            .and_then(|s| s.split('/').next())
            .and_then(leading_int)
            .map(|v| v as i32);
        LocalLink {
            adapter_phy: best_wifi_gen(field(profile, "Supported PHY Modes").unwrap_or("")),
            iface: iface.to_string(),
            kind: LinkKind::Wireless,
            link_mbps: field(cur, "Transmit Rate")
                .and_then(leading_int)
                .unwrap_or(0)
                .max(0) as u64,
            phy: field(cur, "PHY Mode").unwrap_or("").to_string(),
            signal_dbm: signal,
            channel: field(cur, "Channel").unwrap_or("").to_string(),
        }
    }
}

// Not #[expect]: same as `mod mac` above - `locallink_tests` drives these
// parsers everywhere, so the module is live under --all-targets and the
// expectation goes unfulfilled. Measured 23 Aug 2026: unfulfilled on macOS,
// Windows and slim Windows --all-targets; fulfilled in a plain build off
// Linux.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod linux {
    use super::*;

    #[cfg(target_os = "linux")]
    pub(super) fn probe(target: &str) -> Option<LocalLink> {
        let route = run("ip", &["route", "get", target])?;
        let iface = route_iface(&route)?;
        let sys = std::path::Path::new("/sys/class/net").join(&iface);
        if is_tunnel_name(&iface) || sys.join("tun_flags").exists() {
            return Some(tunnel(&iface));
        }
        if sys.join("wireless").exists() {
            let iw = run("iw", &["dev", &iface, "link"]).unwrap_or_default();
            let phy = run("iw", &["phy"]).unwrap_or_default();
            return Some(wifi(&iface, &iw, &phy));
        }
        let speed = std::fs::read_to_string(sys.join("speed")).unwrap_or_default();
        Some(wired(&iface, &speed))
    }

    pub(super) fn route_iface(route: &str) -> Option<String> {
        let mut it = route.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "dev" {
                return it.next().map(str::to_string);
            }
        }
        None
    }

    pub(super) fn wired(iface: &str, sysfs_speed: &str) -> LocalLink {
        let mbps = leading_int(sysfs_speed).unwrap_or(0).max(0) as u64;
        LocalLink {
            iface: iface.to_string(),
            kind: LinkKind::Wired,
            link_mbps: mbps,
            phy: if mbps > 0 {
                format!("{mbps}baseT")
            } else {
                String::new()
            },
            signal_dbm: None,
            channel: String::new(),
            adapter_phy: String::new(),
        }
    }

    /// `iw_phy` is `iw phy` (or `iw list`): its capability sections
    /// name the adapter's newest generation.
    pub(super) fn wifi(iface: &str, iw_link: &str, iw_phy: &str) -> LocalLink {
        let adapter_phy = if iw_phy.contains("EHT") {
            "802.11be"
        } else if iw_phy.contains("HE ") || iw_phy.contains("HE Iftypes") {
            "802.11ax"
        } else if iw_phy.contains("VHT") {
            "802.11ac"
        } else if iw_phy.contains("HT Capabilities") {
            "802.11n"
        } else {
            ""
        };
        let tx = field(iw_link, "tx bitrate").unwrap_or("");
        let mbps = tx
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0) as u64;
        // "VHT-MCS 9 80MHz" / "HE-MCS 11 160MHz" / "EHT-MCS" name the
        // generation; map to the 802.11 letter people know.
        let phy = if tx.contains("EHT") {
            "802.11be"
        } else if tx.contains("HE-") {
            "802.11ax"
        } else if tx.contains("VHT") {
            "802.11ac"
        } else if tx.contains("MCS") {
            "802.11n"
        } else {
            ""
        };
        LocalLink {
            iface: iface.to_string(),
            kind: LinkKind::Wireless,
            link_mbps: mbps,
            phy: phy.to_string(),
            signal_dbm: field(iw_link, "signal")
                .and_then(leading_int)
                .map(|v| v as i32),
            channel: field(iw_link, "freq")
                .map(|f| format!("{f} MHz"))
                .unwrap_or_default(),
            adapter_phy: adapter_phy.to_string(),
        }
    }
}

// Not #[expect]: same as `mod mac` above - `locallink_tests` drives these
// parsers everywhere, so the module is live under --all-targets and the
// expectation goes unfulfilled. Measured 23 Aug 2026: unfulfilled on macOS,
// Linux and slim Linux --all-targets; fulfilled in a plain build off Windows.
#[cfg_attr(not(windows), allow(dead_code))]
mod win {
    use super::*;

    #[cfg(windows)]
    pub(super) fn probe(target: &str) -> Option<LocalLink> {
        let script = format!(
            "$r=(Find-NetRoute -RemoteIPAddress '{target}' -ErrorAction Stop)[0]; \
             Get-NetAdapter -InterfaceIndex $r.InterfaceIndex | \
             Select-Object Name,LinkSpeed,PhysicalMediaType,InterfaceDescription | \
             ConvertTo-Json -Compress"
        );
        let out = run(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
        )?;
        let mut link = adapter(&out)?;
        if link.kind == LinkKind::Wireless {
            let netsh = run("netsh", &["wlan", "show", "interfaces"]).unwrap_or_default();
            wlan_details(&mut link, &netsh);
            let drivers = run("netsh", &["wlan", "show", "drivers"]).unwrap_or_default();
            link.adapter_phy =
                best_wifi_gen(field(&drivers, "Radio types supported").unwrap_or(""));
        }
        Some(link)
    }

    pub(super) fn adapter(json: &str) -> Option<LocalLink> {
        let v: serde_json::Value = serde_json::from_str(json.trim()).ok()?;
        let v = v.as_array().and_then(|a| a.first()).unwrap_or(&v);
        let name = v.get("Name")?.as_str()?.to_string();
        let media = v
            .get("PhysicalMediaType")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        let desc = v
            .get("InterfaceDescription")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        let kind = if media.contains("802.11") {
            LinkKind::Wireless
        } else if is_tunnel_name(&name.to_ascii_lowercase())
            || desc.contains("TAP")
            || desc.contains("WireGuard")
            || desc.contains("Tailscale")
            || desc.contains("VPN")
        {
            LinkKind::Tunnel
        } else if media.contains("802.3") {
            LinkKind::Wired
        } else {
            LinkKind::Unknown
        };
        let speed = v.get("LinkSpeed").and_then(|m| m.as_str()).unwrap_or("");
        Some(LocalLink {
            iface: name,
            kind,
            link_mbps: link_speed_mbps(speed),
            phy: String::new(),
            signal_dbm: None,
            channel: String::new(),
            adapter_phy: String::new(),
        })
    }

    /// "1 Gbps", "1.2 Gbps", "100 Mbps", "2.5 Gbps".
    pub(super) fn link_speed_mbps(s: &str) -> u64 {
        let mut it = s.split_whitespace();
        let n: f64 = it.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
        match it.next().map(|u| u.to_ascii_lowercase()).as_deref() {
            Some("gbps") => (n * 1000.0) as u64,
            Some("mbps") => n as u64,
            Some("kbps") => (n / 1000.0) as u64,
            _ => 0,
        }
    }

    pub(super) fn wlan_details(link: &mut LocalLink, netsh: &str) {
        if let Some(r) = field(netsh, "Radio type") {
            link.phy = r.to_string();
        }
        if let Some(rate) = field(netsh, "Transmit rate (Mbps)").and_then(leading_int)
            && rate > 0
        {
            link.link_mbps = rate as u64;
        }
        if let Some(ch) = field(netsh, "Channel") {
            link.channel = ch.to_string();
        }
        // netsh reports a percentage, not dBm; the usual mapping is
        // quality = 2 * (dBm + 100), clamped.
        if let Some(pct) =
            field(netsh, "Signal").and_then(|s| s.trim_end_matches('%').parse::<i32>().ok())
        {
            link.signal_dbm = Some(pct / 2 - 100);
        }
    }
}

/// Only the mac and linux probes build one (Windows classifies in
/// `win::adapter`); the tests use it everywhere.
// Not #[expect]: "the tests use it everywhere" is precisely why - under
// --all-targets it is live on Windows too and the expectation goes
// unfulfilled. Measured 23 Aug 2026: unfulfilled on Windows and slim Windows
// --all-targets; fulfilled in a plain Windows build.
#[cfg_attr(windows, allow(dead_code))]
fn tunnel(iface: &str) -> LocalLink {
    LocalLink {
        iface: iface.to_string(),
        kind: LinkKind::Tunnel,
        link_mbps: 0,
        phy: String::new(),
        signal_dbm: None,
        channel: String::new(),
        adapter_phy: String::new(),
    }
}

/// The `NZBFAST_LOCAL_LINK=0` kill switch, honoured by every entry
/// point into this module rather than by the daemon's probe loop
/// alone: a user who turned the link probe off did not mean "except in
/// the CLI".
fn disabled() -> bool {
    std::env::var("NZBFAST_LOCAL_LINK").is_ok_and(|v| v == "0")
}

/// One-shot probe for a caller with no daemon behind it: resolve
/// `host`:`port` the way [`spawn`]'s loop does, then read the link that
/// carries traffic there. `nzbfast sysbench` is the caller (TODO 210
/// item (b) on the CLI side); the daemon reads `Daemon::local_link`,
/// which this deliberately does not touch.
///
/// Blocking, like [`probe`] itself, and on a macOS Wi-Fi machine
/// `system_profiler` inside it can take ~10 s - so a one-shot caller
/// should start it beside whatever else it is measuring rather than in
/// front of it.
///
/// No [`TxMedian`] here, deliberately: the median of §210 item (a)
/// needs a series of probes five minutes apart and a one-shot has
/// exactly one sample. What that costs is bounded the right way: a
/// Wi-Fi rate caught high overstates the ceiling, and under rule 1 an
/// overstated ceiling only ever means this module says nothing.
pub(crate) fn probe_local_link(host: &str, port: u16) -> Option<LocalLink> {
    if disabled() {
        return None;
    }
    probe(&target_ip(host, port)?)
}

#[cfg(test)]
#[path = "locallink_tests.rs"]
mod tests;

/// Probe at startup and every five minutes (laptops roam between Wi-Fi
/// and a dock), against the first enabled server's address, and
/// re-judge the tune hint when the link changes. `NZBFAST_LOCAL_LINK=0`
/// disables it. The probe itself runs on the blocking pool: it shells
/// out, and `system_profiler` can take a second or two.
pub(in crate::serve) fn spawn(
    daemon: &std::sync::Arc<super::daemon::Daemon>,
    config: &std::path::Path,
) {
    if disabled() {
        return;
    }
    let d = daemon.clone();
    let cfg_path = config.to_path_buf();
    tokio::spawn(async move {
        // §210 (a): the Wi-Fi rate published is the median of the last
        // three probes, not the one frame this probe happened to catch.
        let mut tx = TxMedian::default();
        loop {
            let path = cfg_path.clone();
            let probed = tokio::task::spawn_blocking(move || {
                let cfg = nzbkit::config::Config::load(&path).ok()?;
                let srv = cfg.servers.iter().find(|s| s.enabled)?;
                let ip = target_ip(&srv.host, srv.port)?;
                Some((probe(&ip), cfg))
            })
            .await
            .ok()
            .flatten();
            if let Some((mut link, cfg)) = probed {
                match link.as_mut() {
                    Some(l) => tx.steady(l),
                    // Nothing judgeable here now; what it was before
                    // says nothing about what it will be next.
                    None => tx = TxMedian::default(),
                }
                let changed = {
                    let mut cur = d.local_link.lock_ok();
                    let changed = *cur != link;
                    if changed {
                        match &link {
                            Some(l) => tracing::info!(target: "tune",
                                "local link: {} {:?} {} Mbps {} {}",
                                l.iface, l.kind, l.link_mbps, l.phy, l.channel),
                            None => {
                                tracing::debug!(target: "tune", "local link: not judgeable here")
                            }
                        }
                    }
                    *cur = link;
                    changed
                };
                if changed {
                    super::tasks::update_tune_hint(
                        &d,
                        &cfg.servers,
                        &crate::conntune::load(&cfg_path),
                    );
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        }
    });
}

/// Resolve the server to one IP literal for the route lookup. Any
/// address will do: the question is which interface the default route
/// leaves by, and every provider answers that the same way.
fn target_ip(host: &str, port: u16) -> Option<String> {
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()
        .ok()?
        .next()
        .map(|a| a.ip().to_string())
}
