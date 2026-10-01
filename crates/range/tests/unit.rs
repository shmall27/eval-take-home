//! Offline unit/integration tests: parsing, segment resolution, VMID
//! allocation, validation, and plan generation. No network required.

use range::error::RangeError;
use range::planner::{self, Op, Stage, CLEAN_SNAPSHOT};
use range::schema::{Range, Role};
use range::segments::{Segment, SegmentMap};

fn seg(name: &str, bridge: &str) -> Segment {
    Segment {
        name: name.to_string(),
        bridge: bridge.to_string(),
        cidr: None,
        gateway_ip: None,
        dhcp_start: None,
        dhcp_end: None,
        domain: None,
    }
}

fn test_segments() -> SegmentMap {
    SegmentMap::from_segments(vec![
        seg("server", "vmbr4"),
        seg("dmz", "vmbr2"),
        seg("user", "vmbr3"),
    ])
}

// --- parsing -----------------------------------------------------------------

#[test]
fn parses_full_host() {
    let toml = r#"
        name = "r"
        [[hosts]]
        name = "dc01"
        template = 9000
        segment = "server"
        ip = "10.78.30.10"
        cores = 4
        memory = 4096
        role = "windows"
    "#;
    let r = Range::from_toml_str(toml).unwrap();
    assert_eq!(r.name, "r");
    assert_eq!(r.hosts.len(), 1);
    let h = &r.hosts[0];
    assert_eq!(h.template, 9000);
    assert_eq!(h.role, Role::Windows);
    assert_eq!(h.ip.as_deref(), Some("10.78.30.10"));
}

#[test]
fn applies_defaults_and_dhcp() {
    let toml = r#"
        name = "r"
        [[hosts]]
        name = "u"
        template = 9000
        segment = "user"
        role = "linux"
    "#;
    let r = Range::from_toml_str(toml).unwrap();
    let h = &r.hosts[0];
    assert_eq!(h.cores, 2); // default
    assert_eq!(h.memory, 2048); // default
    assert!(h.ip.is_none()); // dhcp
}

#[test]
fn rejects_unknown_field() {
    let toml = r#"
        name = "r"
        bogus = true
    "#;
    assert!(matches!(
        Range::from_toml_str(toml),
        Err(RangeError::Parse(_))
    ));
}

#[test]
fn bundled_example_parses_and_compiles() {
    let text = include_str!("../examples/example-range.toml");
    let r = Range::from_toml_str(text).unwrap();
    let c = planner::compile(&r, &test_segments()).unwrap();
    assert_eq!(c.hosts.len(), 3);
}

// --- segment resolution ------------------------------------------------------

#[test]
fn fallback_when_absent() {
    let m = SegmentMap::load_or_fallback("/no/such/segments.json").unwrap();
    assert!(m.is_fallback());
    assert_eq!(m.get("iso").unwrap().bridge, "vmbr1");
}

#[test]
fn parses_segments_json_contract_schema() {
    let json = r#"[
        {"name":"dmz","bridge":"vmbr2","cidr":"10.78.10.0/24","gateway_ip":"10.78.10.1",
         "dhcp_start":"10.78.10.100","dhcp_end":"10.78.10.200","domain":"dmz.range.lab"}
    ]"#;
    let m = SegmentMap::from_json_str(json).unwrap();
    assert!(!m.is_fallback());
    let s = m.get("dmz").unwrap();
    assert_eq!(s.bridge, "vmbr2");
    assert_eq!(s.gateway_ip.as_deref(), Some("10.78.10.1"));
}

#[test]
fn unknown_segment_errors() {
    let toml = r#"
        name = "r"
        [[hosts]]
        name = "x"
        template = 9000
        segment = "nope"
        role = "linux"
    "#;
    let r = Range::from_toml_str(toml).unwrap();
    let err = planner::compile(&r, &test_segments()).unwrap_err();
    match err {
        RangeError::UnknownSegment { host, segment, .. } => {
            assert_eq!(host, "x");
            assert_eq!(segment, "nope");
        }
        other => panic!("expected UnknownSegment, got {other:?}"),
    }
}

// --- VMID allocation + validation --------------------------------------------

#[test]
fn allocates_base_plus_index() {
    let toml = r#"
        name = "r"
        [[hosts]]
        name = "a"
        template = 9000
        segment = "server"
        role = "linux"
        [[hosts]]
        name = "b"
        template = 9000
        segment = "dmz"
        role = "linux"
    "#;
    let r = Range::from_toml_str(toml).unwrap();
    let c = planner::compile(&r, &test_segments()).unwrap();
    assert_eq!(c.hosts[0].vmid, 10000);
    assert_eq!(c.hosts[1].vmid, 10001);
}

#[test]
fn honors_base_vmid_override_and_explicit_vmid() {
    let toml = r#"
        name = "r"
        base_vmid = 10500
        [[hosts]]
        name = "a"
        template = 9000
        segment = "server"
        role = "linux"
        [[hosts]]
        name = "b"
        template = 9000
        segment = "dmz"
        role = "linux"
        vmid = 10900
    "#;
    let r = Range::from_toml_str(toml).unwrap();
    let c = planner::compile(&r, &test_segments()).unwrap();
    assert_eq!(c.hosts[0].vmid, 10500); // base + 0
    assert_eq!(c.hosts[1].vmid, 10900); // explicit
}

#[test]
fn rejects_vmid_out_of_band() {
    let toml = r#"
        name = "r"
        base_vmid = 9000
        [[hosts]]
        name = "a"
        template = 9000
        segment = "server"
        role = "linux"
    "#;
    let r = Range::from_toml_str(toml).unwrap();
    match planner::compile(&r, &test_segments()).unwrap_err() {
        RangeError::VmidOutOfRange { vmid, .. } => assert_eq!(vmid, 9000),
        other => panic!("expected VmidOutOfRange, got {other:?}"),
    }
}

#[test]
fn rejects_duplicate_host_name() {
    let toml = r#"
        name = "r"
        [[hosts]]
        name = "dup"
        template = 9000
        segment = "server"
        role = "linux"
        [[hosts]]
        name = "dup"
        template = 9000
        segment = "dmz"
        role = "linux"
    "#;
    let r = Range::from_toml_str(toml).unwrap();
    assert!(matches!(
        planner::compile(&r, &test_segments()).unwrap_err(),
        RangeError::DuplicateHostName(n) if n == "dup"
    ));
}

#[test]
fn rejects_duplicate_vmid() {
    let toml = r#"
        name = "r"
        [[hosts]]
        name = "a"
        template = 9000
        segment = "server"
        role = "linux"
        vmid = 10005
        [[hosts]]
        name = "b"
        template = 9000
        segment = "dmz"
        role = "linux"
        vmid = 10005
    "#;
    let r = Range::from_toml_str(toml).unwrap();
    match planner::compile(&r, &test_segments()).unwrap_err() {
        RangeError::DuplicateVmid { vmid, .. } => assert_eq!(vmid, 10005),
        other => panic!("expected DuplicateVmid, got {other:?}"),
    }
}

// --- plan generation ---------------------------------------------------------

#[test]
fn apply_plan_is_ordered_and_complete() {
    let toml = r#"
        name = "r"
        [[hosts]]
        name = "dc01"
        template = 9000
        segment = "server"
        ip = "10.78.30.10"
        role = "windows"
    "#;
    let r = Range::from_toml_str(toml).unwrap();
    let c = planner::compile(&r, &test_segments()).unwrap();
    let ops = c.operations(Stage::Apply);
    assert_eq!(
        ops,
        vec![
            Op::Clone {
                template: 9000,
                vmid: 10000,
                name: "dc01".into()
            },
            Op::SetNet {
                vmid: 10000,
                bridge: "vmbr4".into()
            },
            Op::Start { vmid: 10000 },
            Op::SetIp {
                vmid: 10000,
                ip: "10.78.30.10".into(),
                role: Role::Windows
            },
            Op::Snapshot {
                vmid: 10000,
                name: CLEAN_SNAPSHOT.into(),
                vmstate: true
            },
        ]
    );
}

#[test]
fn apply_plan_skips_setip_for_dhcp() {
    let toml = r#"
        name = "r"
        [[hosts]]
        name = "u"
        template = 9000
        segment = "user"
        role = "linux"
    "#;
    let r = Range::from_toml_str(toml).unwrap();
    let c = planner::compile(&r, &test_segments()).unwrap();
    let ops = c.operations(Stage::Apply);
    assert!(!ops.iter().any(|o| matches!(o, Op::SetIp { .. })));
    assert_eq!(ops.len(), 4); // clone, set-net, start, snapshot
}

#[test]
fn reset_and_destroy_plans() {
    let toml = r#"
        name = "r"
        [[hosts]]
        name = "a"
        template = 9000
        segment = "server"
        role = "linux"
        [[hosts]]
        name = "b"
        template = 9000
        segment = "dmz"
        role = "linux"
    "#;
    let r = Range::from_toml_str(toml).unwrap();
    let c = planner::compile(&r, &test_segments()).unwrap();

    let reset = c.operations(Stage::Reset);
    assert_eq!(
        reset,
        vec![
            Op::Rollback {
                vmid: 10000,
                name: CLEAN_SNAPSHOT.into()
            },
            Op::Rollback {
                vmid: 10001,
                name: CLEAN_SNAPSHOT.into()
            },
        ]
    );

    let destroy = c.operations(Stage::Destroy);
    assert_eq!(
        destroy,
        vec![
            Op::Stop { vmid: 10000 },
            Op::Delete { vmid: 10000 },
            Op::Stop { vmid: 10001 },
            Op::Delete { vmid: 10001 },
        ]
    );
}

#[test]
fn guest_setip_argv_by_role() {
    let win = range::guest::set_ip_argv(Role::Windows, "10.0.0.5");
    assert_eq!(win[0], "powershell.exe");
    assert!(win.last().unwrap().contains("10.0.0.5"));

    let lin = range::guest::set_ip_argv(Role::Linux, "10.0.0.5");
    assert_eq!(lin[0], "/bin/sh");
    assert!(lin.last().unwrap().contains("10.0.0.5"));
}
