//! 容器内部的一次性只读 Worker。原始字节仅写入 noexec tmpfs，绝不执行样本。
mod analyzers {
    include!("types.rs");
}
mod sample_static;
mod tools;
mod webshell;
mod webshell_schema;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

fn run() -> Result<Value, String> {
    let args: Vec<String> = std::env::args().collect();
    let kind = args.get(1).ok_or("missing kind")?.as_str();
    if !["webshell", "binary"].contains(&kind) {
        return Err("unsupported sample kind".into());
    }
    let operation = args.get(2).map(String::as_str).unwrap_or("metadata");
    let params: Value = serde_json::from_str(args.get(3).map(String::as_str).unwrap_or("{}"))
        .map_err(|e| e.to_string())?;
    // Worker 与宿主机各自验证参数，不能将 SDK 的类型约束当成信任边界。
    tools::validate(operation, &params)?;
    let mut bytes = vec![];
    std::io::stdin()
        .take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 128 * 1024 * 1024 {
        return Err("sample exceeds 128 MiB".into());
    }
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let path = std::path::Path::new("/tmp/sample");
    let mut file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())?;
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
            .map_err(|e| e.to_string())?;
    }
    let mut result = match operation {
        "metadata" => {
            let report = if kind == "webshell" {
                sample_static::analyze_webshell(path)
            } else {
                sample_static::analyze_binary(path)
            }?;
            json!({"report":report})
        }
        "read_source" => {
            if kind != "webshell" {
                return Err("read_source is only available for scripts".into());
            }
            tools::source(
                &bytes,
                params["startLine"].as_u64().unwrap() as usize,
                params["count"].as_u64().unwrap() as usize,
            )
        }
        "search_strings" => tools::strings(&bytes, params["query"].as_str().unwrap()),
        "disassemble" => {
            let (bitness, entry_offset, entry_va, region_end) = tools::entry(&bytes)?;
            let delta = params["entryOffset"].as_u64().unwrap();
            let count = params["count"].as_u64().unwrap();
            let start = entry_offset.checked_add(delta).ok_or("offset overflow")?;
            let address = entry_va
                .checked_add(delta)
                .ok_or("virtual address overflow")?;
            if start >= region_end {
                return Err("offset outside executable file region".into());
            }
            let length = (region_end - start).min(4096);
            // 命令和路径固定，样本字节从不作为命令参数。WASM 仍受外层容器资源/时间限制。
            let output = std::process::Command::new("node")
                .args([
                    "/opt/gaga/disassemble.mjs",
                    &bitness.to_string(),
                    &start.to_string(),
                    &address.to_string(),
                    &count.to_string(),
                    &length.to_string(),
                ])
                .output()
                .map_err(|e| e.to_string())?;
            if !output.status.success() {
                return Err("isolated disassembler failed".into());
            }
            let rows: Value = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
            json!({"bitness":bitness,"instructions":rows,"scope":"入口附近可执行文件区间的线性解码；不是函数恢复或反编译，不能证明指令被执行。"})
        }
        _ => return Err("tool operation denied".into()),
    };
    result["sha256"] = json!(hash);
    result["protocol"] = json!("gaga-static/2");
    Ok(result)
}
fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            // 只允许已知输入/范围拒绝被上游恢复；解析器崩溃和工具执行异常不能被忽略。
            let recoverable = [
                "本版仅支持",
                "entry outside executable",
                "offset outside executable",
                "unsupported disassembly format",
                "read_source is only available",
                "tool argument outside bounds",
                "tool parameters must be an object",
                "unknown tool argument",
                "tool operation denied",
            ]
            .iter()
            .any(|prefix| error.starts_with(prefix));
            eprintln!("{}", json!({"error":error,"recoverable":recoverable}));
            std::process::exit(1);
        }
    }
}
