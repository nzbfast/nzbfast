//! Parsers over captured tool output, so every platform's arm is
//! tested wherever the tests run. The macOS fixtures are verbatim
//! from an M3 Ultra on Wi-Fi 7 (21 Aug 2026); the Linux and Windows
//! ones are the documented shapes of `iw`, sysfs, Get-NetAdapter and
//! netsh.

use super::*;

const MAC_ROUTE: &str = "   route to: 8.8.8.8
destination: 8.8.8.8
    gateway: 192.168.12.1
  interface: en0
      flags: <UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE,IFREF,GLOBAL>
";

const MAC_PORTS: &str = "
Hardware Port: Ethernet Adapter (en3)
Device: en3
Ethernet Address: 76:d6:8d:37:52:c3

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 36:3f:f0:de:9f:c0

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: fc:b2:14:c9:38:e6
";

const MAC_AIRPORT: &str = "Wi-Fi:

      Interfaces:
        en0:
          Supported PHY Modes: 802.11 a/b/g/n/ac/ax/be
          Status: Connected
          Current Network Information:
            Sanami:
              PHY Mode: 802.11be
              Channel: 165 (6GHz, 160MHz)
              Country Code: US
              Network Type: Infrastructure
              Signal / Noise: -25 dBm / -95 dBm
              Transmit Rate: 1200
              MCS Index: 11
          Other Local Wi-Fi Networks:
            AHT-98:
              PHY Mode: 802.11b/g/n/ax
              Channel: 6 (2GHz, 20MHz)
              Signal / Noise: -70 dBm / -95 dBm
";

#[test]
fn mac_route_names_the_interface() {
    assert_eq!(mac::route_iface(MAC_ROUTE).as_deref(), Some("en0"));
    assert_eq!(mac::route_iface("no such host"), None);
}

#[test]
fn mac_hardware_port_maps_device_to_port_name() {
    assert_eq!(
        mac::hardware_port(MAC_PORTS, "en0").as_deref(),
        Some("Wi-Fi")
    );
    assert_eq!(
        mac::hardware_port(MAC_PORTS, "en3").as_deref(),
        Some("Ethernet Adapter (en3)")
    );
    assert_eq!(mac::hardware_port(MAC_PORTS, "en9"), None);
}

#[test]
fn mac_wifi_reads_the_current_network_not_the_neighbours() {
    let l = mac::wifi("en0", MAC_AIRPORT);
    assert_eq!(l.kind, LinkKind::Wireless);
    assert_eq!(l.link_mbps, 1200);
    assert_eq!(l.phy, "802.11be");
    assert_eq!(l.signal_dbm, Some(-25));
    assert_eq!(l.channel, "165 (6GHz, 160MHz)");
    assert_eq!(l.adapter_phy, "802.11be");
}

#[test]
fn mac_wired_reads_the_negotiated_media() {
    let l = mac::wired(
        "en3",
        "\tmedia: autoselect (1000baseT <full-duplex,flow-control>)\n\tstatus: active\n",
    );
    assert_eq!(l.kind, LinkKind::Wired);
    assert_eq!(l.link_mbps, 1000);
    assert_eq!(l.phy, "1000baseT");
    let l = mac::wired("en5", "\tmedia: autoselect (10Gbase-T <full-duplex>)\n");
    assert_eq!(l.link_mbps, 10_000);
    let l = mac::wired("en6", "\tmedia: autoselect (2500Base-T <full-duplex>)\n");
    assert_eq!(l.link_mbps, 2500);
    // A bare "media: autoselect" (no link) yields no rate and no verdict.
    let l = mac::wired("en3", "\tmedia: autoselect\n\tstatus: inactive\n");
    assert_eq!(l.link_mbps, 0);
    assert_eq!(l.ceiling_bps(), None);
}

#[test]
fn linux_route_and_sysfs_and_iw() {
    assert_eq!(
        linux::route_iface(
            "1.1.1.1 via 192.168.1.1 dev wlp3s0 src 192.168.1.5 uid 1000\n    cache\n"
        )
        .as_deref(),
        Some("wlp3s0")
    );
    let l = linux::wired("enp5s0", "1000\n");
    assert_eq!((l.kind, l.link_mbps), (LinkKind::Wired, 1000));
    // sysfs reports -1 for "unknown" (USB adapters, VMs): no rate.
    assert_eq!(linux::wired("eth0", "-1\n").link_mbps, 0);
    let iw = "Connected to aa:bb:cc:dd:ee:ff (on wlp3s0)
\tSSID: home
\tfreq: 5180
\tsignal: -50 dBm
\trx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2
\ttx bitrate: 1201.0 MBit/s HE-MCS 11 80MHz HE-NSS 2
";
    let l = linux::wifi(
        "wlp3s0",
        iw,
        "Wiphy phy0\n\tBand 2:\n\t\tHT Capabilities (0x1ff)\n\t\tVHT Capabilities (0x339071b2)\n\t\tHE Iftypes: managed\n\t\tEHT Iftypes: managed\n",
    );
    assert_eq!(l.kind, LinkKind::Wireless);
    assert_eq!(l.link_mbps, 1201);
    assert_eq!(l.phy, "802.11ax");
    assert_eq!(l.signal_dbm, Some(-50));
    assert_eq!(l.adapter_phy, "802.11be");
}

#[test]
fn windows_adapter_json_and_netsh() {
    let j = r#"{"Name":"Wi-Fi","LinkSpeed":"1.2 Gbps","PhysicalMediaType":"Native 802.11","InterfaceDescription":"Intel(R) Wi-Fi 6 AX201"}"#;
    let mut l = win::adapter(j).unwrap();
    assert_eq!((l.kind, l.link_mbps), (LinkKind::Wireless, 1200));
    win::wlan_details(
        &mut l,
        "    Name                   : Wi-Fi
    Radio type             : 802.11ax
    Channel                : 36
    Signal                 : 90%
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 1201
",
    );
    assert_eq!(l.phy, "802.11ax");
    assert_eq!(l.link_mbps, 1201);
    assert_eq!(l.signal_dbm, Some(-55));
    let j = r#"[{"Name":"Ethernet","LinkSpeed":"100 Mbps","PhysicalMediaType":"802.3","InterfaceDescription":"Realtek PCIe GbE"}]"#;
    let l = win::adapter(j).unwrap();
    assert_eq!((l.kind, l.link_mbps), (LinkKind::Wired, 100));
    let j = r#"{"Name":"Tailscale","LinkSpeed":"100 Gbps","PhysicalMediaType":"Unspecified","InterfaceDescription":"Tailscale Tunnel"}"#;
    assert_eq!(win::adapter(j).unwrap().kind, LinkKind::Tunnel);
    assert_eq!(win::link_speed_mbps("2.5 Gbps"), 2500);
}

#[test]
fn tunnels_are_recognised_by_name() {
    for n in ["utun3", "tun0", "wg0", "tailscale0", "ppp0"] {
        assert!(is_tunnel_name(n), "{n}");
    }
    assert!(!is_tunnel_name("en0"));
    assert!(!is_tunnel_name("eth0"));
}

fn wifi(mbps: u64) -> LocalLink {
    LocalLink {
        iface: "en0".into(),
        kind: LinkKind::Wireless,
        link_mbps: mbps,
        phy: "802.11ax".into(),
        signal_dbm: Some(-55),
        channel: String::new(),
        adapter_phy: String::new(),
    }
}

fn wired(mbps: u64) -> LocalLink {
    LocalLink {
        iface: "en3".into(),
        kind: LinkKind::Wired,
        link_mbps: mbps,
        phy: String::new(),
        signal_dbm: None,
        channel: String::new(),
        adapter_phy: String::new(),
    }
}

const MBIT: u64 = 125_000;

#[test]
fn wifi_ceiling_is_about_half_the_link_rate() {
    // Gary's case: 710 Mbit line, Wi-Fi 6 at a 1200 Mbps link; he
    // measured 560 Mbit. The ceiling lands at 660, under 80% of the
    // line, so the verdict names the access point.
    let l = wifi(1200);
    assert_eq!(l.ceiling_bps(), Some(82_500_000));
    let v = l.verdict(710 * MBIT);
    assert!(
        v.contains("over Wi-Fi (802.11ax, link 1200 Mbps on en0)"),
        "{v}"
    );
    assert!(v.contains("~660 Mbps"), "{v}");
    assert!(v.contains("~710 Mbps Line speed"), "{v}");
    // Never a product to buy, never a standard to upgrade to.
    for banned in ["6E", "Wi-Fi 7", "2.5", "10 GbE", "buy", "upgrade"] {
        assert!(!v.contains(banned), "{banned}: {v}");
    }
}

#[test]
fn an_adapter_newer_than_its_association_names_the_access_point_side() {
    // Gary's machine supports 802.11be; the AP offers 802.11ax on
    // 5 GHz at 80 MHz. The link is the ceiling, so the mismatch is
    // worth saying - as which side is older, not what to buy.
    let mut l = wifi(1200);
    l.adapter_phy = "802.11be".into();
    l.channel = "44 (5GHz, 80MHz)".into();
    let v = l.verdict(710 * MBIT);
    assert!(v.contains("channel 44 (5GHz, 80MHz)"), "{v}");
    assert!(
        v.contains("adapter supports 802.11be but this connection is 802.11ax, so the access point side is the older one"),
        "{v}"
    );
    // Same generation both sides: no mismatch sentence.
    l.adapter_phy = "802.11ax".into();
    assert!(!l.verdict(710 * MBIT).contains("adapter supports"));
    // Unknown adapter capability: no claim.
    l.adapter_phy = String::new();
    assert!(!l.verdict(710 * MBIT).contains("adapter supports"));
    // And no mismatch is mentioned when the link is NOT the ceiling.
    l.adapter_phy = "802.11be".into();
    assert_eq!(l.verdict(300 * MBIT), "");
}

#[test]
fn wifi_generations_rank() {
    assert_eq!(wifi_gen_rank("802.11 a/b/g/n/ac/ax/be"), 6);
    assert_eq!(wifi_gen_rank("802.11ax"), 5);
    assert_eq!(wifi_gen_rank("802.11b/g/n/ax"), 5);
    assert_eq!(wifi_gen_rank(""), 0);
    assert_eq!(best_wifi_gen("802.11n 802.11ac 802.11ax"), "802.11ax");
}

#[test]
fn wifi_that_covers_the_line_says_nothing() {
    // A 2400 Mbps link delivers ~1300: above a 1 Gbit line.
    assert_eq!(wifi(2400).verdict(1000 * MBIT), "");
    // And no line speed means no yardstick.
    assert_eq!(wifi(1200).verdict(0), "");
    // A link the OS would not rate is no basis either.
    assert_eq!(wifi(0).verdict(710 * MBIT), "");
}

#[test]
fn a_port_at_100_under_a_faster_line_is_named_as_a_fault() {
    let v = wired(100).verdict(500 * MBIT);
    assert!(v.contains("negotiated 100 Mbps"), "{v}");
    assert!(v.contains("cable or a switch port"), "{v}");
    // Gigabit under a 2 Gbit line: the port is the ceiling, no fault.
    let v = wired(1000).verdict(2000 * MBIT);
    assert!(v.contains("negotiated 1000 Mbps"), "{v}");
    assert!(!v.contains("cable"), "{v}");
    // Gigabit under a gigabit line (950 deliverable = 95%): nothing to say.
    assert_eq!(wired(1000).verdict(1000 * MBIT), "");
    // And under a 940 Mbit line either - the line is reachable.
    assert_eq!(wired(1000).verdict(940 * MBIT), "");
}

#[test]
fn tunnels_refuse_to_judge() {
    let t = tunnel("utun3");
    assert_eq!(t.ceiling_bps(), None);
    assert_eq!(t.verdict(1000 * MBIT), "");
}

#[test]
fn media_rates_parse() {
    assert_eq!(media_mbps("1000baseT"), 1000);
    assert_eq!(media_mbps("10Gbase-T"), 10_000);
    assert_eq!(media_mbps("100baseTX"), 100);
    assert_eq!(media_mbps("autoselect"), 0);
}

#[test]
fn the_wifi_rate_published_is_the_median_of_the_last_three() {
    // 802.11 rate-adapts per frame, so a probe catches whatever the
    // radio last sent at. One dip must not move the ceiling.
    let mut m = TxMedian::default();
    let mut l = wifi(1200);
    m.steady(&mut l);
    assert_eq!(l.link_mbps, 1200, "one sample is its own median");

    let mut l = wifi(1200);
    m.steady(&mut l);
    assert_eq!(l.link_mbps, 1200);

    // The dip: 1200, 1200, 120 -> 1200.
    let mut l = wifi(120);
    m.steady(&mut l);
    assert_eq!(l.link_mbps, 1200, "one low sample cannot pull the median");

    // ...and a link that REALLY dropped is followed, within two probes:
    // a second low sample makes 120 the middle of the window
    // (1200, 120, 120). A median steadies the figure; it does not
    // outvote the link.
    let mut l = wifi(120);
    m.steady(&mut l);
    assert_eq!(l.link_mbps, 120, "two probes in, the new rate rules");
}

#[test]
fn an_even_window_takes_the_upper_middle() {
    // Two samples only: the higher one, so the error is silence rather
    // than a wrong verdict (§210 rule 1).
    let mut m = TxMedian::default();
    let mut l = wifi(600);
    m.steady(&mut l);
    let mut l = wifi(1200);
    m.steady(&mut l);
    assert_eq!(l.link_mbps, 1200);
}

#[test]
fn the_median_window_belongs_to_one_association() {
    let mut m = TxMedian::default();
    for _ in 0..3 {
        let mut l = wifi(1200);
        m.steady(&mut l);
    }
    // Docked: a wired port reports a negotiated rate and is never
    // smoothed, and it clears the Wi-Fi history behind it.
    let mut w = wired(1000);
    m.steady(&mut w);
    assert_eq!(w.link_mbps, 1000);
    let mut l = wifi(300);
    m.steady(&mut l);
    assert_eq!(
        l.link_mbps, 300,
        "the dock's samples do not describe this link"
    );

    // Roaming to another interface starts over too.
    let mut m = TxMedian::default();
    for _ in 0..3 {
        let mut l = wifi(1200);
        m.steady(&mut l);
    }
    let mut other = wifi(300);
    other.iface = "en1".into();
    m.steady(&mut other);
    assert_eq!(other.link_mbps, 300);

    // A rate the OS would not give stays 0 (no basis for a ceiling)
    // and clears what came before it.
    let mut m = TxMedian::default();
    for _ in 0..3 {
        let mut l = wifi(1200);
        m.steady(&mut l);
    }
    let mut dark = wifi(0);
    m.steady(&mut dark);
    assert_eq!(dark.link_mbps, 0);
    assert_eq!(dark.ceiling_bps(), None);
    let mut back = wifi(300);
    m.steady(&mut back);
    assert_eq!(back.link_mbps, 300);
}

#[test]
fn a_tunnel_is_never_smoothed() {
    let mut m = TxMedian::default();
    let mut t = tunnel("utun3");
    m.steady(&mut t);
    assert_eq!(t.link_mbps, 0);
    assert_eq!(t.ceiling_bps(), None);
}

#[test]
fn the_bench_network_row_names_the_link_it_ran_into() {
    // Gary's shape as the System benchmark sees it: a 1200 Mbps Wi-Fi
    // link carries ~660 Mbps, and the probe measured 640.
    let l = wifi(1200);
    let v = l.measured_note(640 * MBIT);
    assert!(
        v.contains("over Wi-Fi (802.11ax, link 1200 Mbps on en0)"),
        "{v}"
    );
    assert!(v.contains("~660 Mbps"), "{v}");
    assert!(v.contains("More connections will not raise it"), "{v}");
    // Same rule as the tune hint: a mechanism, never a product.
    for banned in ["6E", "Wi-Fi 7", "2.5", "10 GbE", "buy", "upgrade"] {
        assert!(!v.contains(banned), "{banned}: {v}");
    }
}

#[test]
fn a_measurement_well_under_the_link_says_nothing() {
    // 200 of a possible 660: the link is plainly not what this hit,
    // and naming it would send the reader to the wrong place.
    assert_eq!(wifi(1200).measured_note(200 * MBIT), "");
    // Nothing measured at all is no evidence either.
    assert_eq!(wifi(1200).measured_note(0), "");
    // No rate, no ceiling, no claim.
    assert_eq!(wifi(0).measured_note(640 * MBIT), "");
    assert_eq!(tunnel("utun3").measured_note(640 * MBIT), "");
}

#[test]
fn a_wired_port_at_its_negotiated_rate_is_named_too() {
    // A gigabit port delivering ~950: that is the port, not the fleet.
    let v = wired(1000).measured_note(930 * MBIT);
    assert!(
        v.contains("network port (en3) negotiated, 1000 Mbps"),
        "{v}"
    );
    assert!(v.contains("more connections will not raise it"), "{v}");
    assert!(!v.contains("cable"), "{v}");
    // ...and 100 Mbps is a fault worth checking, as in the tune hint.
    let v = wired(100).measured_note(90 * MBIT);
    assert!(v.contains("cable or a switch port"), "{v}");
    // Half of what the port can do: the port is not the answer.
    assert_eq!(wired(1000).measured_note(400 * MBIT), "");
}
