//! Proxmox VE API client.
//!
//! A faithful Rust port of `infra/range-host/pve.py`: token auth via the
//! `Authorization: PVEAPIToken=<id>=<secret>` header, the GET/DELETE-take-query-
//! params quirk (Proxmox rejects a body on those methods), blocking task-status
//! polling, the guest-agent exec/exec-status flow, and the post-rollback lock
//! retry wrapper.
//!
//! Configuration (base URL, node, token) comes from the environment or a config
//! struct — never hardcoded. The client accepts the node's self-signed cert.
//!
//! This module is intentionally kept free of any range/planner concepts; it is a
//! thin transport over the Proxmox API that the executor drives.

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;

/// How the token is presented in the `Authorization` header.
#[derive(Debug, Clone)]
pub struct Token {
    /// e.g. `root@pam!automation`
    pub id: String,
    /// the secret UUID value
    pub secret: String,
}

impl Token {
    fn header(&self) -> String {
        format!("PVEAPIToken={}={}", self.id, self.secret)
    }

    /// Load a token from the JSON file shape used on vanilla:
    /// `{"full-tokenid": "...", "value": "..."}`.
    pub fn from_json_file(path: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct TokenFile {
            #[serde(rename = "full-tokenid")]
            full_tokenid: String,
            value: String,
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading token file {path}"))?;
        let tf: TokenFile = serde_json::from_str(&text)
            .with_context(|| format!("parsing token file {path}"))?;
        Ok(Token {
            id: tf.full_tokenid,
            secret: tf.value,
        })
    }
}

/// Connection configuration for the client.
#[derive(Debug, Clone)]
pub struct Config {
    /// e.g. `https://localhost:8006/api2/json`
    pub base: String,
    /// e.g. `cathedral-pve`
    pub node: String,
    pub token: Token,
}

impl Config {
    /// Build config from environment variables:
    /// - `PVE_BASE_URL` (default `https://localhost:8006/api2/json`)
    /// - `PVE_NODE` (default `cathedral-pve`)
    /// - token: either `PVE_TOKEN_ID` + `PVE_TOKEN_SECRET`, or `PVE_TOKEN_FILE`
    ///   pointing at the JSON file shape used on vanilla.
    pub fn from_env() -> Result<Self> {
        let base = std::env::var("PVE_BASE_URL")
            .unwrap_or_else(|_| "https://localhost:8006/api2/json".to_string());
        let node = std::env::var("PVE_NODE").unwrap_or_else(|_| "cathedral-pve".to_string());

        let token = if let (Ok(id), Ok(secret)) =
            (std::env::var("PVE_TOKEN_ID"), std::env::var("PVE_TOKEN_SECRET"))
        {
            Token { id, secret }
        } else if let Ok(path) = std::env::var("PVE_TOKEN_FILE") {
            Token::from_json_file(&path)?
        } else {
            bail!(
                "no Proxmox token configured: set PVE_TOKEN_ID + PVE_TOKEN_SECRET, \
                 or PVE_TOKEN_FILE pointing at the token JSON"
            );
        };

        Ok(Config { base, node, token })
    }
}

/// The result of a guest-agent command.
#[derive(Debug, Clone)]
pub struct GuestExecResult {
    pub exitcode: i64,
    pub stdout: String,
    pub stderr: String,
}

/// Blocking Proxmox API client.
pub struct Pve {
    cfg: Config,
    http: reqwest::blocking::Client,
}

impl Pve {
    /// Build a client that accepts the node's self-signed certificate.
    pub fn new(cfg: Config) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(60))
            .build()
            .context("building HTTP client")?;
        Ok(Self { cfg, http })
    }

    fn vm_path(&self, vmid: u32) -> String {
        format!("/nodes/{}/qemu/{}", self.cfg.node, vmid)
    }

    /// Core request. Mirrors `pve.py`: GET/DELETE carry params as query string
    /// (Proxmox rejects a body on those), everything else as form-encoded body.
    /// Returns the `data` member of the response.
    fn call(&self, method: reqwest::Method, path: &str, params: &[(&str, String)]) -> Result<Value> {
        let url = format!("{}{}", self.cfg.base, path);
        let auth = self.cfg.token.header();

        let is_query = matches!(method, reqwest::Method::GET | reqwest::Method::DELETE);
        let mut req = self
            .http
            .request(method.clone(), &url)
            .header(reqwest::header::AUTHORIZATION, auth);

        if !params.is_empty() {
            if is_query {
                req = req.query(params);
            } else {
                req = req.form(params);
            }
        }

        let resp = req
            .send()
            .with_context(|| format!("{method} {url}"))?;
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow!("{method} {path} -> HTTP {status}: {body}"));
        }
        let json: Value = serde_json::from_str(&body)
            .with_context(|| format!("decoding response from {path}: {body}"))?;
        Ok(json.get("data").cloned().unwrap_or(Value::Null))
    }

    // --- convenience wrappers over HTTP verbs --------------------------------

    fn get(&self, path: &str, params: &[(&str, String)]) -> Result<Value> {
        self.call(reqwest::Method::GET, path, params)
    }
    fn post(&self, path: &str, params: &[(&str, String)]) -> Result<Value> {
        self.call(reqwest::Method::POST, path, params)
    }
    fn delete(&self, path: &str, params: &[(&str, String)]) -> Result<Value> {
        self.call(reqwest::Method::DELETE, path, params)
    }

    // --- read ----------------------------------------------------------------

    /// API version string (useful as a connectivity check).
    pub fn version(&self) -> Result<String> {
        let v = self.get("/version", &[])?;
        Ok(v.get("version")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string())
    }

    /// List VMIDs on the configured node.
    pub fn list_vms(&self) -> Result<Vec<u32>> {
        let data = self.get(&format!("/nodes/{}/qemu", self.cfg.node), &[])?;
        let arr = data.as_array().cloned().unwrap_or_default();
        Ok(arr
            .iter()
            .filter_map(|v| v.get("vmid").and_then(Value::as_u64).map(|n| n as u32))
            .collect())
    }

    /// Current status of a VM (e.g. `running` / `stopped`).
    pub fn status(&self, vmid: u32) -> Result<String> {
        let data = self.get(&format!("{}/status/current", self.vm_path(vmid)), &[])?;
        Ok(data
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string())
    }

    // --- lifecycle -----------------------------------------------------------

    /// Linked-clone `template` into `newid`, named `name`. Returns the task UPID.
    pub fn clone_linked(&self, template: u32, newid: u32, name: &str) -> Result<String> {
        let path = format!("{}/clone", self.vm_path(template));
        let upid = self.post(
            &path,
            &[
                ("newid", newid.to_string()),
                ("name", name.to_string()),
                ("full", "0".to_string()),
            ],
        )?;
        upid_str(&upid)
    }

    /// Set net0 to `virtio,bridge=<bridge>`. Config changes return no task.
    pub fn set_net0_bridge(&self, vmid: u32, bridge: &str) -> Result<()> {
        let path = format!("{}/config", self.vm_path(vmid));
        self.post(&path, &[("net0", format!("virtio,bridge={bridge}"))])?;
        Ok(())
    }

    /// Start a VM. Returns the task UPID.
    pub fn start(&self, vmid: u32) -> Result<String> {
        upid_str(&self.post(&format!("{}/status/start", self.vm_path(vmid)), &[])?)
    }

    /// Stop a VM. Returns the task UPID.
    pub fn stop(&self, vmid: u32) -> Result<String> {
        upid_str(&self.post(&format!("{}/status/stop", self.vm_path(vmid)), &[])?)
    }

    /// Snapshot a VM, optionally including RAM state. Returns the task UPID.
    pub fn snapshot(&self, vmid: u32, snapname: &str, vmstate: bool) -> Result<String> {
        let path = format!("{}/snapshot", self.vm_path(vmid));
        upid_str(&self.post(
            &path,
            &[
                ("snapname", snapname.to_string()),
                ("vmstate", if vmstate { "1" } else { "0" }.to_string()),
            ],
        )?)
    }

    /// Roll back to a snapshot. Returns the task UPID.
    pub fn rollback(&self, vmid: u32, snapname: &str) -> Result<String> {
        let path = format!("{}/snapshot/{}/rollback", self.vm_path(vmid), snapname);
        upid_str(&self.post(&path, &[])?)
    }

    /// Delete + purge a VM. Returns the task UPID.
    pub fn delete_purge(&self, vmid: u32) -> Result<String> {
        upid_str(&self.delete(&self.vm_path(vmid), &[("purge", "1".to_string())])?)
    }

    // --- task polling --------------------------------------------------------

    /// Block until a task finishes; error on non-OK exit. Mirrors `pve.wait`.
    pub fn wait(&self, upid: &str, timeout: Duration) -> Result<Duration> {
        let enc = urlencoding::encode(upid);
        let path = format!("/nodes/{}/tasks/{}/status", self.cfg.node, enc);
        let t0 = Instant::now();
        loop {
            let st = self.get(&path, &[])?;
            let status = st.get("status").and_then(Value::as_str).unwrap_or("");
            if status == "stopped" {
                let exit = st.get("exitstatus").and_then(Value::as_str).unwrap_or("");
                if exit != "OK" {
                    bail!("task {upid} failed: {exit}");
                }
                return Ok(t0.elapsed());
            }
            if t0.elapsed() > timeout {
                bail!("task {upid} did not finish within {:?}", timeout);
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    /// Run `f`, retrying while it fails with a lock error. After a live
    /// rollback, Proxmox holds the VM file lock for ~30 s and state-changing
    /// calls fail with a lock timeout. Mirrors `pve.retry_locked`.
    pub fn retry_locked<T, F>(&self, attempts: usize, delay: Duration, mut f: F) -> Result<T>
    where
        F: FnMut() -> Result<T>,
    {
        let mut last: Option<anyhow::Error> = None;
        for i in 0..attempts {
            match f() {
                Ok(v) => return Ok(v),
                Err(e) => {
                    let is_lock = e.to_string().contains("lock");
                    if !is_lock || i == attempts - 1 {
                        return Err(e);
                    }
                    last = Some(e);
                    std::thread::sleep(delay);
                }
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("retry_locked: exhausted with no error recorded")))
    }

    // --- guest agent ---------------------------------------------------------

    /// True if the guest agent answers a ping.
    pub fn agent_up(&self, vmid: u32) -> bool {
        self.post(&format!("{}/agent/ping", self.vm_path(vmid)), &[])
            .is_ok()
    }

    /// Block until the guest agent responds, or time out.
    pub fn wait_agent(&self, vmid: u32, timeout: Duration) -> Result<Duration> {
        let t0 = Instant::now();
        while !self.agent_up(vmid) {
            if t0.elapsed() > timeout {
                bail!("guest agent on VMID {vmid} did not come up within {timeout:?}");
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        Ok(t0.elapsed())
    }

    /// Run a command inside the guest via the QEMU guest agent, retrying the
    /// start on the agent's short-timeout 500s, then poll exec-status. Mirrors
    /// `pve.guest_exec`. Keep guest commands idempotent (start may run twice).
    pub fn guest_exec(&self, vmid: u32, argv: &[&str], timeout: Duration) -> Result<GuestExecResult> {
        // POST /agent/exec with `command` as a repeated form field (doseq).
        let path = format!("{}/agent/exec", self.vm_path(vmid));
        let params: Vec<(&str, String)> =
            argv.iter().map(|a| ("command", a.to_string())).collect();

        let pid = self.agent_retry(5, Duration::from_secs(2), || {
            let data = self.post(&path, &params)?;
            data.get("pid")
                .and_then(Value::as_i64)
                .ok_or_else(|| anyhow!("agent/exec returned no pid: {data}"))
        })?;

        let status_path = format!("{}/agent/exec-status", self.vm_path(vmid));
        let t0 = Instant::now();
        loop {
            let st = self.agent_retry(30, Duration::from_secs(2), || {
                self.get(&status_path, &[("pid", pid.to_string())])
            })?;
            if st.get("exited").and_then(Value::as_bool).unwrap_or(false)
                || st.get("exited").and_then(Value::as_i64).unwrap_or(0) == 1
            {
                return Ok(GuestExecResult {
                    exitcode: st.get("exitcode").and_then(Value::as_i64).unwrap_or(-1),
                    stdout: st
                        .get("out-data")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    stderr: st
                        .get("err-data")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                });
            }
            if t0.elapsed() > timeout {
                bail!("guest command on VMID {vmid} timed out after {timeout:?}");
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Retry a closure on transient agent HTTP 500s. Mirrors `pve._agent_call`.
    fn agent_retry<T, F>(&self, tries: usize, delay: Duration, mut f: F) -> Result<T>
    where
        F: FnMut() -> Result<T>,
    {
        let mut last: Option<anyhow::Error> = None;
        for i in 0..tries {
            match f() {
                Ok(v) => return Ok(v),
                Err(e) => {
                    let transient = e.to_string().contains("HTTP 500");
                    if !transient || i == tries - 1 {
                        return Err(e);
                    }
                    last = Some(e);
                    std::thread::sleep(delay);
                }
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("agent_retry: exhausted")))
    }
}

/// Coerce a task response (expected to be the UPID string) into a String.
fn upid_str(v: &Value) -> Result<String> {
    v.as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("expected a task UPID string, got {v}"))
}
