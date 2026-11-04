//! 显式运行的累计数据验收。时间戳和分析摘要均为合成夹具，不能视为
//! 数月连续运行、日志检出率或客户现场结果；从不读取凭据或访问网络。
use crate::{dashboard, maintenance, monitoring, store::Store};
use chrono::{TimeZone, Utc};
use rusqlite::params;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, time::Instant};

fn measure(mut action: impl FnMut() -> Value) -> (Value, f64) {
    let mut times = Vec::new();
    let mut result = Value::Null;
    for _ in 0..5 {
        let start = Instant::now();
        result = action();
        times.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    times.sort_by(f64::total_cmp);
    (result, times[2])
}

fn sample(store: &Store) -> (Value, Value) {
    let (assets, asset_ms) = measure(|| json!(monitoring::assets(store, Some("c000")).unwrap()));
    let (snapshots, snapshot_ms) =
        measure(|| json!(monitoring::snapshots(store, "a000-0").unwrap()));
    let (observations, observation_ms) =
        measure(|| json!(monitoring::observations(store, "c000").unwrap()));
    let (queue, queue_ms) = measure(|| monitoring::queue_stats(store, "c000").unwrap());
    let (workspace, workspace_ms) = measure(|| {
        let w = store.workspace().unwrap();
        json!({"cases":w.cases.len(),"evidence":w.evidence.len(),"nodes":w.nodes.len(),"caseId":w.active_case})
    });
    let now = Utc.with_ymd_and_hms(2026, 10, 29, 0, 0, 0).unwrap();
    let (overview, overview_ms) =
        measure(|| dashboard::snapshot(store, "c000", "case", 30, now, false).unwrap());
    (
        json!({"assets":assets,"snapshots":snapshots,"observations":observations,"queue":queue,"workspace":workspace,"overview":overview}),
        json!({"assetsMs":asset_ms,"snapshotsMs":snapshot_ms,"observationsMs":observation_ms,"queueMs":queue_ms,"workspaceMs":workspace_ms,"dashboardMs":overview_ms}),
    )
}

#[test]
#[ignore = "explicit synthetic accumulated-data and backup benchmark; no cloud or malware"]
fn accumulated_storage_and_restore() {
    let root = std::env::var_os("GAGA_STORAGE_AUDIT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir()
                .join(format!("gaga-storage-{}", uuid::Uuid::new_v4()))
                .join("workspace")
        });
    assert!(!root.exists(), "需要全新的合成压力测试目录");
    let store = Store::open(root.clone()).unwrap();
    let source = b"Synthetic storage fixture only. No real attack or analyzed log.\n";
    let sha = format!("{:x}", Sha256::digest(source));
    let report = json!({"kind":"http","engine":"synthetic-storage/1","title":"合成存储夹具","summary":"人工构造元数据，不是实际分析结果。","metrics":[],"findings":[],"indicators":[],"details":[],"warnings":["合成压力夹具"]}).to_string();
    let started = Instant::now();
    {
        let mut db = store.db.lock().unwrap();
        let tx = db.transaction().unwrap();
        tx.execute("DELETE FROM cases", []).unwrap();
        tx.execute(
            "UPDATE settings SET value='c000' WHERE key='active_case'",
            [],
        )
        .unwrap();
        let mut add_case = tx.prepare("INSERT INTO cases VALUES(?1,?2,?3)").unwrap();
        let mut add_evidence = tx
            .prepare("INSERT INTO evidence VALUES(?1,?2,?3,'http',?4,?5,?6,?7)")
            .unwrap();
        let mut add_node = tx
            .prepare("INSERT INTO nodes VALUES(?1,?2,?3,NULL,?4,?4,?5,'合成记录','J4team test',1)")
            .unwrap();
        let mut add_asset = tx
            .prepare("INSERT INTO monitor_assets VALUES(?1,?2,0,?3,0,?4)")
            .unwrap();
        let mut add_snapshot = tx
            .prepare("INSERT INTO monitor_snapshots VALUES(?1,?2,?3,?4,?5)")
            .unwrap();
        let mut add_observation = tx
            .prepare("INSERT INTO monitor_observations VALUES(?1,?2,'web',?3,?4,?5,NULL,?6)")
            .unwrap();
        for c in 0..100 {
            let case = format!("c{c:03}");
            let at = "2026-01-01T00:00:00+00:00";
            add_case
                .execute(params![case, format!("[合成存储压力] {c}"), at])
                .unwrap();
            for e in 0..20 {
                let id = format!("{c:08x}-0000-4000-8000-{e:012x}");
                fs::write(root.join("evidence").join(&id), source).unwrap();
                add_evidence
                    .execute(params![
                        id,
                        case,
                        format!("synthetic-{c}-{e}.txt"),
                        sha,
                        source.len(),
                        at,
                        report
                    ])
                    .unwrap();
                if e < 10 {
                    add_node
                        .execute(params![
                            format!("n{c:03}-{e}"),
                            case,
                            id,
                            at,
                            format!("[合成] 节点 {e}")
                        ])
                        .unwrap();
                }
            }
            for a in 0..10 {
                let asset = format!("a{c:03}-{a}");
                let record = json!({"id":asset,"caseId":case,"name":"synthetic disabled asset","url":"http://127.0.0.1:9/synthetic","intervalSecs":60,"enabled":false,"baselineId":null,"lastSnapshotId":null,"lastStatus":"never","lastChecked":null});
                add_asset
                    .execute(params![asset, case, at, record.to_string()])
                    .unwrap();
                for s in 0..100 {
                    let seq = c * 1000 + a * 100 + s;
                    let time = Utc.timestamp_opt(1767225600 + seq, 0).unwrap().to_rfc3339();
                    let id = format!("s{seq}");
                    let evidence = format!("{c:08x}-0000-4000-8000-{:012x}", a % 20);
                    let snap = json!({"id":id,"assetId":asset,"createdAt":time,"evidenceId":evidence,"status":200,"title":"synthetic","sha256":sha,"scripts":[],"externalLinks":[],"hiddenLinks":[],"changes":[],"error":null,"elapsedMs":1});
                    add_snapshot
                        .execute(params![id, asset, time, evidence, snap.to_string()])
                        .unwrap();
                    let state = if s % 10 == 0 { "completed" } else { "pending" };
                    let observation = json!({"id":id,"caseId":case,"kind":"web","subject":"synthetic observation","summary":"合成摘要，不代表真实抓取或分析。","createdAt":time,"evidenceId":evidence,"aiState":state,"reviewId":null,"error":null,"detail":{}});
                    add_observation
                        .execute(params![
                            id,
                            case,
                            time,
                            evidence,
                            state,
                            observation.to_string()
                        ])
                        .unwrap();
                }
            }
        }
        drop((
            add_case,
            add_evidence,
            add_node,
            add_asset,
            add_snapshot,
            add_observation,
        ));
        tx.commit().unwrap();
        // 只在本测试的新建空间移除本轮索引，比较同数据、同 Rust 业务查询。
        db.execute_batch("DROP INDEX monitor_assets_case; DROP INDEX monitor_assets_due; DROP INDEX monitor_snapshots_asset_time; DROP INDEX monitor_observations_case_time; DROP INDEX monitor_observations_state_case; DROP INDEX monitor_observations_evidence_kind; DROP INDEX monitor_ai_calls_time;").unwrap();
    }
    let seed_ms = started.elapsed().as_secs_f64() * 1000.0;
    let (before, before_ms) = sample(&store);
    let index_started = Instant::now();
    monitoring::init(&store).unwrap();
    let index_ms = index_started.elapsed().as_secs_f64() * 1000.0;
    let (after, after_ms) = sample(&store);
    assert_eq!(before, after, "索引升级不能改变返回记录、计数或事件归属");
    assert_eq!(after["assets"].as_array().unwrap().len(), 10);
    assert_eq!(after["snapshots"].as_array().unwrap().len(), 30);
    assert_eq!(after["observations"].as_array().unwrap().len(), 200);
    assert_eq!(after["queue"]["pending"], 900);
    assert_eq!(after["queue"]["globalPending"], 90000);
    assert_eq!(after["queue"]["eligible"], 0);
    assert_eq!(after["workspace"]["evidence"], 20);
    assert_eq!(after["workspace"]["nodes"], 10);
    let backup_parent = root.parent().unwrap().join("backups");
    let restore_parent = root.parent().unwrap().join("restores");
    fs::create_dir_all(&backup_parent).unwrap();
    fs::create_dir_all(&restore_parent).unwrap();
    let start = Instant::now();
    let backup = maintenance::backup(&store, &backup_parent).unwrap();
    let backup_ms = start.elapsed().as_secs_f64() * 1000.0;
    let start = Instant::now();
    let restored = maintenance::restore(
        std::path::Path::new(backup["path"].as_str().unwrap()),
        &restore_parent,
    )
    .unwrap();
    let restore_ms = start.elapsed().as_secs_f64() * 1000.0;
    let copy = Store::open(PathBuf::from(restored["path"].as_str().unwrap())).unwrap();
    assert_eq!(sample(&copy).0, after);
    for current in [&store, &copy] {
        let db = current.db.lock().unwrap();
        assert_eq!(
            db.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        assert!(!db
            .prepare("PRAGMA foreign_key_check")
            .unwrap()
            .exists([])
            .unwrap());
        assert_eq!(
            db.query_row("SELECT count(*) FROM monitor_snapshots", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            100000
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM monitor_observations", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            100000
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM monitor_assets WHERE enabled=1",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            0
        );
    }
    drop(copy);
    drop(store);
    let start = Instant::now();
    let reopened = Store::open(root.clone()).unwrap();
    let reopen_ms = start.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(sample(&reopened).0, after);
    let info = maintenance::information(&reopened).unwrap();
    let result = json!({"version":env!("CARGO_PKG_VERSION"),"syntheticStorageFixture":true,"realElapsedMonths":0,"workspace":root,"cases":100,"archives":2000,"nodes":1000,"assets":1000,"snapshots":100000,"observations":100000,"seedMs":seed_ms,"indexBuildMs":index_ms,"queryMedianOf5Before":before_ms,"queryMedianOf5After":after_ms,"backupMs":backup_ms,"restoreMs":restore_ms,"reopenMs":reopen_ms,"storage":info,"checks":["same business results before/after indexes","case-local query bounds and counts","AI remains disabled","backup/restore preserves all records and query results","original and restored integrity/FK checks","2000 physical archives checked during backup/restore","reopen preserves results"],"errors":[],"networkRequests":0,"credentialsRead":false});
    fs::write(
        root.join("storage-fixture.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!("GAGA_STORAGE_AUDIT: {result}");
}
