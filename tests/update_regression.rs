use custos::update::{ReleaseUpdater, UpdateStatus, binary_asset_name, release_target};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

fn file_digest(path: &Path) -> String {
    let mut file = std::fs::File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let n = file.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    format!("{:x}", hash.finalize())
}

struct Fixture {
    root: String,
    downloads: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    task: Option<std::thread::JoinHandle<()>>,
}
impl Fixture {
    fn start(metadata: serde_json::Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let root = format!("http://{}/", listener.local_addr().unwrap());
        let downloads = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (requests, done) = (downloads.clone(), stop.clone());
        let bytes = serde_json::to_vec(&metadata).unwrap();
        let task = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let Ok((mut socket, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(30)))
                    .unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let asset = line.starts_with("GET /download/");
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                if asset {
                    requests.fetch_add(1, Ordering::Relaxed);
                    let mut file = std::fs::File::open(env!("CARGO_BIN_EXE_custos")).unwrap();
                    let size = file.metadata().unwrap().len();
                    if write!(
                        socket,
                        "HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n"
                    )
                    .is_ok()
                    {
                        let mut sent = 0;
                        let mut buffer = [0; 65536];
                        loop {
                            let n = file.read(&mut buffer).unwrap();
                            if n == 0 {
                                break;
                            }
                            if let Err(error) = socket.write_all(&buffer[..n]) {
                                eprintln!("fixture stopped after {sent}/{size}: {error}");
                                break;
                            }
                            sent += n as u64;
                        }
                        assert_eq!(sent, size, "fixture transfer was incomplete");
                    }
                } else {
                    let _ = write!(
                        socket,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        bytes.len()
                    );
                    let _ = socket.write_all(&bytes);
                }
            }
        });
        Self {
            root,
            downloads,
            stop,
            task: Some(task),
        }
    }
    fn client(&self) -> ReleaseUpdater {
        ReleaseUpdater::from_source(
            &format!("{}releases/", self.root),
            &format!("{}download/", self.root),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.task.take().unwrap().join();
    }
}

fn metadata(version: &str) -> serde_json::Value {
    let binary = Path::new(env!("CARGO_BIN_EXE_custos"));
    serde_json::json!({"tag_name":format!("v{version}"), "draft":false, "prerelease":false,
        "assets":[{"name":binary_asset_name(release_target().unwrap()), "size":binary.metadata().unwrap().len(),
            "state":"uploaded", "digest":format!("sha256:{}", file_digest(binary)),
            "browser_download_url":"http://untrusted.invalid/ignored"}]})
}

#[tokio::test]
async fn checking_is_read_only_and_versions_compare_numerically() {
    let fixture = Fixture::start(metadata("0.10.0"));
    let UpdateStatus::Available(plan) = fixture.client().check("0.9.0", None).await.unwrap() else {
        panic!("expected update");
    };
    assert_eq!(plan.version().to_string(), "0.10.0");
    assert!(matches!(
        fixture.client().check("0.10.0", None).await.unwrap(),
        UpdateStatus::Current { .. }
    ));
    assert!(
        fixture
            .client()
            .check("0.10.0", Some("v0.9.0"))
            .await
            .is_err()
    );
    assert_eq!(fixture.downloads.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn missing_digests_oversized_and_unpublished_releases_are_refused() {
    for case in [
        "missing_digest",
        "oversize",
        "prerelease",
        "draft",
        "missing_target",
        "mismatched_tag",
    ] {
        let mut value = metadata("0.6.0");
        match case {
            "missing_digest" => value["assets"][0]["digest"] = serde_json::Value::Null,
            "oversize" => {
                value["assets"][0]["size"] = (custos::update::MAX_BINARY_BYTES + 1).into()
            }
            "prerelease" => value["prerelease"] = true.into(),
            "draft" => value["draft"] = true.into(),
            "missing_target" => value["assets"] = serde_json::json!([]),
            _ => {}
        }
        let fixture = Fixture::start(value);
        let requested = if case == "mismatched_tag" {
            Some("v0.7.0")
        } else {
            None
        };
        assert!(
            fixture.client().check("0.5.0", requested).await.is_err(),
            "{case}"
        );
        assert_eq!(fixture.downloads.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn a_verified_update_replaces_only_the_executable() {
    exercise_install("ok");
}
#[test]
fn corrupted_download_leaves_the_original_executable_untouched() {
    exercise_install("checksum");
}
#[test]
fn wrong_candidate_version_leaves_the_original_executable_untouched() {
    exercise_install("version");
}

fn exercise_install(case: &str) {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join(if cfg!(windows) {
        "fixture.exe"
    } else {
        "fixture"
    });
    std::fs::copy(std::env::current_exe().unwrap(), &target).unwrap();
    let original = file_digest(&target);
    let journal = directory.path().join("ledger");
    std::fs::write(&journal, b"preserve active bans and pending cleanup\n").unwrap();
    let mut value = metadata(env!("CARGO_PKG_VERSION"));
    if case == "checksum" {
        value["assets"][0]["digest"] = format!("sha256:{}", "0".repeat(64)).into();
    }
    if case == "version" {
        value["tag_name"] = "v9.9.9".into();
    }
    let fixture = Fixture::start(value);
    let output = Command::new(&target)
        .args(["--exact", "update_worker", "--ignored", "--nocapture"])
        .env("CUSTOS_TEST_UPDATE_SOURCE", &fixture.root)
        .env("CUSTOS_TEST_UPDATE_CASE", case)
        .env("NO_PROXY", "*")
        .env("no_proxy", "*")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if case == "ok" {
        assert_eq!(
            file_digest(&target),
            file_digest(Path::new(env!("CARGO_BIN_EXE_custos")))
        );
        let version = Command::new(&target).arg("-v").output().unwrap();
        assert!(version.status.success());
        assert_eq!(
            String::from_utf8(version.stdout).unwrap().trim(),
            concat!("custos ", env!("CARGO_PKG_VERSION"))
        );
    } else {
        assert_eq!(file_digest(&target), original);
    }
    assert_eq!(
        std::fs::read(&journal).unwrap(),
        b"preserve active bans and pending cleanup\n"
    );
    assert_eq!(fixture.downloads.load(Ordering::Relaxed), 1);
}

#[test]
#[ignore = "runs only in a disposable executable copy"]
fn update_worker() {
    let source = std::env::var("CUSTOS_TEST_UPDATE_SOURCE").unwrap();
    let case = std::env::var("CUSTOS_TEST_UPDATE_CASE").unwrap();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let client = ReleaseUpdater::from_source(
            &format!("{source}releases/"),
            &format!("{source}download/"),
        )
        .unwrap();
        let UpdateStatus::Available(plan) = client.check("0.4.1", None).await.unwrap() else {
            panic!("expected update");
        };
        let result = client.install(plan).await;
        assert_eq!(result.is_ok(), case == "ok", "{result:?}");
        if let Err(error) = result {
            assert!(
                error.to_string().contains(if case == "checksum" {
                    "checksum"
                } else {
                    "Candidate validation"
                }),
                "{error:#}"
            );
        }
    });
}
