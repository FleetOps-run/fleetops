use fleetops_core::Error;
use fleetops_ee::siem::{
    db,
    model::{SinkKind, SinkSecrets, SinkSettings, SyslogTransport},
    validate,
};
use fleetops_store::Store;

async fn store() -> Store {
    let s = Store::in_memory().await.unwrap();
    fleetops_ee::db::migrate(s.pool()).await.unwrap();
    s
}

fn hec() -> (SinkSettings, SinkSecrets) {
    (
        SinkSettings::default(),
        SinkSecrets {
            url: Some("https://splunk.example:8088/services/collector/event".into()),
            token: Some("t0ken".into()),
            headers: vec![],
        },
    )
}

#[tokio::test]
async fn create_get_round_trips_and_seals() {
    let s = store().await;
    let (set, sec) = hec();
    let id = db::create(&s, "splunk", SinkKind::SplunkHec, true, &set, &sec, 7, 1)
        .await
        .unwrap();
    let (sink, got) = db::get(&s, id).await.unwrap();
    assert_eq!(sink.name, "splunk");
    assert_eq!(sink.kind, SinkKind::SplunkHec);
    assert_eq!(sink.cursor, 7);
    assert_eq!(sink.settings, set);
    assert_eq!(got.url, sec.url);
    assert_eq!(got.token.as_deref(), Some("t0ken"));
    let raw: String = sqlx::query_scalar("SELECT secrets FROM ee_audit_sinks WHERE id = ?")
        .bind(id)
        .fetch_one(s.pool())
        .await
        .unwrap();
    assert!(!raw.contains("t0ken"));
    assert_eq!(db::list(&s).await.unwrap().len(), 1);
    assert_eq!(db::count(&s).await.unwrap(), 1);
}

#[tokio::test]
async fn update_without_secrets_keeps_them() {
    let s = store().await;
    let (set, sec) = hec();
    let id = db::create(&s, "splunk", SinkKind::SplunkHec, true, &set, &sec, 0, 1)
        .await
        .unwrap();
    db::update(&s, id, "renamed", false, &set, None, 2)
        .await
        .unwrap();
    let (sink, got) = db::get(&s, id).await.unwrap();
    assert_eq!((sink.name.as_str(), sink.enabled), ("renamed", false));
    assert_eq!(got.token.as_deref(), Some("t0ken"));
}

#[tokio::test]
async fn update_with_secrets_replaces_them() {
    let s = store().await;
    let (set, sec) = hec();
    let id = db::create(&s, "splunk", SinkKind::SplunkHec, true, &set, &sec, 0, 1)
        .await
        .unwrap();
    let new = SinkSecrets {
        url: sec.url.clone(),
        token: Some("n3w".into()),
        headers: vec![],
    };
    db::update(&s, id, "splunk", true, &set, Some(&new), 2)
        .await
        .unwrap();
    assert_eq!(
        db::get(&s, id).await.unwrap().1.token.as_deref(),
        Some("n3w")
    );
}

#[tokio::test]
async fn advance_clears_error() {
    let s = store().await;
    let (set, sec) = hec();
    let id = db::create(&s, "splunk", SinkKind::SplunkHec, true, &set, &sec, 0, 1)
        .await
        .unwrap();
    db::fail(&s, id, "x", 5).await.unwrap();
    let sink = db::get(&s, id).await.unwrap().0;
    assert_eq!(
        (sink.last_error.as_deref(), sink.last_error_at),
        (Some("x"), Some(5))
    );
    db::advance(&s, id, 42, 3, 9).await.unwrap();
    let sink = db::get(&s, id).await.unwrap().0;
    assert_eq!(sink.cursor, 42);
    assert_eq!(sink.gap_rows, 3);
    assert_eq!(sink.last_sent_at, Some(9));
    assert_eq!(sink.last_error, None);
}

#[tokio::test]
async fn duplicate_name_is_conflict() {
    let s = store().await;
    let (set, sec) = hec();
    db::create(&s, "splunk", SinkKind::SplunkHec, true, &set, &sec, 0, 1)
        .await
        .unwrap();
    let e = db::create(&s, "splunk", SinkKind::SplunkHec, true, &set, &sec, 0, 1)
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Conflict(_)), "{e:?}");
}

#[test]
fn validate_rules() {
    let none = SinkSecrets::default();
    let syslog = |host: Option<&str>, port: Option<u16>, t: SyslogTransport, ca: Option<&str>| {
        validate(
            SinkKind::Syslog,
            &SinkSettings {
                host: host.map(Into::into),
                port,
                transport: Some(t),
                ca_pem: ca.map(Into::into),
                ..Default::default()
            },
            &none,
        )
    };
    assert!(syslog(Some("siem.lan"), Some(6514), SyslogTransport::Tls, None).is_ok());
    assert!(syslog(None, Some(514), SyslogTransport::Udp, None).is_err());
    assert!(syslog(Some("siem.lan"), None, SyslogTransport::Udp, None).is_err());
    assert!(syslog(
        Some("siem.lan"),
        Some(6514),
        SyslogTransport::Tls,
        Some("not pem")
    )
    .is_err());

    let (set, sec) = hec();
    assert!(validate(SinkKind::SplunkHec, &set, &sec).is_ok());
    assert!(
        validate(SinkKind::SplunkHec, &set, &none).is_err(),
        "HEC needs a token"
    );

    let http = |url: &str, headers: Vec<(String, String)>| {
        let names = headers.iter().map(|h| h.0.clone()).collect();
        validate(
            SinkKind::Http,
            &SinkSettings {
                header_names: names,
                ..Default::default()
            },
            &SinkSecrets {
                url: Some(url.into()),
                token: None,
                headers,
            },
        )
    };
    assert!(http("https://logs.example/in", vec![]).is_ok());
    assert!(
        http("http://example.com/in", vec![]).is_err(),
        "plain http off loopback"
    );
    assert!(http("http://127.0.0.1:9/x", vec![]).is_ok());
    assert!(http(
        "https://logs.example/in",
        vec![("DD-API-KEY".into(), "k".into())]
    )
    .is_ok());
    assert!(http(
        "https://logs.example/in",
        vec![("Bad Name".into(), "k".into())]
    )
    .is_err());
}
