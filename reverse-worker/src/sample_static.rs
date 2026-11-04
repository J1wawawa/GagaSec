use crate::analyzers::{cut, detail, finding, metric, report, AnalysisReport};
use std::path::Path;
pub fn analyze_webshell(path: &Path) -> Result<AnalysisReport, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let mut out = crate::webshell::analyze(&bytes);
    append_anti_analysis(&mut out, &bytes);
    Ok(out)
}

pub fn analyze_binary(path: &Path) -> Result<AnalysisReport, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let mut out = report("binary", "样本基础静态分析");
    let mut counts = [0usize; 256];
    for b in &bytes {
        counts[*b as usize] += 1;
    }
    let entropy: f64 = counts
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = n as f64 / bytes.len().max(1) as f64;
            -p * p.log2()
        })
        .sum();
    let mut format = "未知 / 非可执行文件".to_string();
    match goblin::Object::parse(&bytes) {
        Ok(goblin::Object::PE(pe)) => {
            format = "PE".into();
            out.details.push(detail(
                "架构",
                format!(
                    "0x{:04x} / {} 位",
                    pe.header.coff_header.machine,
                    if pe.is_64 { 64 } else { 32 }
                ),
            ));
            out.details
                .push(detail("入口点 RVA", format!("0x{:x}", pe.entry)));
            out.details.push(detail(
                "节区",
                pe.sections
                    .iter()
                    .map(|s| format!("{} ({})", s.name().unwrap_or("?"), s.size_of_raw_data))
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
            out.details.push(detail(
                "导入函数",
                pe.imports
                    .iter()
                    .take(120)
                    .map(|i| format!("{}!{}", i.dll, i.name))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ));
            for import in pe
                .imports
                .iter()
                .filter(|i| {
                    [
                        "VirtualAlloc",
                        "WriteProcessMemory",
                        "CreateRemoteThread",
                        "WinExec",
                        "URLDownloadToFile",
                    ]
                    .iter()
                    .any(|s| i.name.contains(s))
                })
                .take(50)
            {
                out.findings.push(finding(
                    "medium",
                    "需复核的导入函数",
                    "该 API 也被正常软件使用；导入表本身不能证明恶意行为。",
                    format!("{}!{}", import.dll, import.name),
                    None,
                    &import.name,
                    "结合调用路径、签名、来源与动态沙箱结果判断。",
                ));
            }
        }
        Ok(goblin::Object::Elf(elf)) => {
            format = "ELF".into();
            out.details.push(detail(
                "架构",
                format!(
                    "machine={} / {} 位",
                    elf.header.e_machine,
                    if elf.is_64 { 64 } else { 32 }
                ),
            ));
            out.details
                .push(detail("入口点", format!("0x{:x}", elf.entry)));
            out.details.push(detail("依赖库", elf.libraries.join("\n")));
            out.details
                .push(detail("节区数量", elf.section_headers.len()));
        }
        Ok(goblin::Object::Mach(_)) => {
            format = "Mach-O".into();
            out.details
                .push(detail("解析范围", "已识别 Mach-O，本版不展开其结构。"));
        }
        Err(e) => out.warnings.push(format!(
            "可执行结构未识别或格式损坏：{}",
            cut(&e.to_string(), 200)
        )),
        _ => {}
    }
    let mut strings = Vec::new();
    let mut run = Vec::new();
    for b in bytes.iter().chain(std::iter::once(&0)) {
        if b.is_ascii_graphic() || *b == b' ' {
            if run.len() < 300 {
                run.push(*b);
            }
        } else {
            if run.len() >= 6 && strings.len() < 160 {
                strings.push(String::from_utf8_lossy(&run).to_string());
            }
            run.clear();
        }
    }
    out.metrics = vec![
        metric("文件类型", &format),
        metric("文件字节", bytes.len()),
        metric("字节熵", format!("{entropy:.3}")),
        metric("字符串展示", strings.len()),
    ];
    out.details
        .push(detail("ASCII 字符串（前 160 条）", strings.join("\n")));
    out.summary = format!("识别 {format}，提取基础结构、字符串和可用导入信息；未执行样本。 ");
    out.warnings.push("此页只做基础静态检查；动态观察请到动态行为分析页。本版未接入 Ghidra、反编译、签名链验证或 YARA / capa。高熵及敏感导入均不等于恶意。".into());
    append_anti_analysis(&mut out, &bytes);
    Ok(out)
}

// Candidate strings only: never infer that an evasion branch executed.
fn append_anti_analysis(out: &mut AnalysisReport, bytes: &[u8]) {
    let groups = [
        (
            "调试检测",
            vec![
                "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess",
                "NtSetInformationThread",
                "TracerPid",
                "ptrace",
            ],
        ),
        (
            "虚拟化环境标记",
            vec!["VMware", "VBoxService", "VirtualBox", "QEMU", "Hypervisor"],
        ),
        (
            "计时与活跃度检查",
            vec![
                "SleepEx",
                "nanosleep",
                "clock_gettime",
                "QueryPerformanceCounter",
                "GetLastInputInfo",
            ],
        ),
    ];
    let pattern = format!(
        r"(?i)\b(?:{})\b",
        groups
            .iter()
            .flat_map(|(_, names)| names.iter())
            .map(|s| regex::escape(s))
            .collect::<Vec<_>>()
            .join("|")
    );
    let re = regex::bytes::Regex::new(&pattern).expect("constant anti-analysis strings");
    let mut hits = Vec::new();
    let mut omitted = 0usize;
    for m in re.find_iter(bytes) {
        if hits.len() >= 64 {
            omitted += 1;
            continue;
        }
        let marker = String::from_utf8_lossy(m.as_bytes()).into_owned();
        let category = groups
            .iter()
            .find(|(_, names)| names.iter().any(|n| n.eq_ignore_ascii_case(&marker)))
            .map(|(name, _)| *name)
            .unwrap_or("未知");
        let line = if out.kind == "webshell" {
            Some(bytes[..m.start()].iter().filter(|b| **b == b'\n').count() + 1)
        } else {
            None
        };
        hits.push(serde_json::json!({"category":category,"marker":marker,"fileOffset":format!("0x{:x}",m.start()),"line":line,"interpretation":"仅已知字符串线索；可能位于正常调用、注释或不可达代码，未验证调用或逃逸行为。"}));
    }
    let categories:Vec<_>=groups.iter().map(|(name,_)|serde_json::json!({"category":name,"status":if hits.iter().any(|v|v["category"]==*name){"存在字符串线索，待复核"}else{"本规则未见字符串；能力未知"}})).collect();
    out.details.push(detail("反分析覆盖与线索",serde_json::json!({"method":"固定 ASCII 字符串规则，不是行为或可达性检测","categories":categories,"evidence":hits,"omitted":omitted,"dynamicEvasion":"未验证","gaps":["未覆盖 API 哈希、动态解析、混淆或加密字符串、UTF-16、时钟指令、内核级与硬件检测。","未做多环境执行、延长观察、内存取证或真实主机行为对照。","无行为、未命中或正常退出均不能判定样本安全。"]}).to_string()));
    out.warnings.push("反调试 / 反沙箱检查仅覆盖列举的 ASCII 字符串；字符串命中不证明实际启用，未命中也不排除反分析。动态行为可能受触发条件、等待时间或环境影响。".into());
}

#[cfg(test)]
mod anti_tests {
    use super::*;
    #[test]
    fn markers_in_comments_keep_exact_offsets_and_never_claim_execution() {
        let bytes = b"<?php\n// IsDebuggerPresent VMware SleepEx\necho 'benign';";
        let mut r = report("webshell", "fixture");
        append_anti_analysis(&mut r, bytes);
        let value: serde_json::Value = serde_json::from_str(&r.details[0].value).unwrap();
        assert_eq!(value["dynamicEvasion"], "未验证");
        assert_eq!(value["evidence"][0]["fileOffset"], "0x9");
        assert_eq!(value["evidence"][0]["line"], 2);
        assert!(r.findings.is_empty());
        let mut r = report("binary", "fixture");
        append_anti_analysis(&mut r, b"GAGA_BENIGN_FIXTURE");
        let value: serde_json::Value = serde_json::from_str(&r.details[0].value).unwrap();
        assert!(value["categories"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["status"] == "本规则未见字符串；能力未知"));
    }
}
