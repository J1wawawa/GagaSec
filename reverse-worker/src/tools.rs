//! 纯工具逻辑：只读取传入字节，不能执行样本或解析任意文件路径。
use goblin::Object;
use serde_json::{json, Value};

pub fn validate(operation: &str, params: &Value) -> Result<(), String> {
    let keys: &[&str] = match operation {
        "metadata" => &[],
        "read_source" => &["startLine", "count"],
        "search_strings" => &["query"],
        "disassemble" => &["entryOffset", "count"],
        _ => return Err("tool operation denied".into()),
    };
    let object = params
        .as_object()
        .ok_or("tool parameters must be an object")?;
    if object.keys().any(|k| !keys.contains(&k.as_str())) {
        return Err("unknown tool argument".into());
    }
    let valid = match operation {
        "metadata" => true,
        "read_source" => {
            params["startLine"]
                .as_u64()
                .is_some_and(|v| (1..=1_000_000).contains(&v))
                && params["count"]
                    .as_u64()
                    .is_some_and(|v| (1..=120).contains(&v))
        }
        "search_strings" => params["query"].as_str().is_some_and(|v| v.len() <= 128),
        "disassemble" => {
            params["entryOffset"].as_u64().is_some_and(|v| v <= 16384)
                && params["count"]
                    .as_u64()
                    .is_some_and(|v| (1..=160).contains(&v))
        }
        _ => false,
    };
    if !valid {
        return Err("tool argument outside bounds".into());
    }
    Ok(())
}

pub fn source(bytes: &[u8], start: usize, count: usize) -> Value {
    let text = String::from_utf8_lossy(bytes);
    let total = text.lines().count();
    let mut rows = vec![];
    let mut size = 0;
    let mut truncated = false;
    for (i, line) in text.lines().enumerate().skip(start - 1).take(count) {
        let clipped: String = line.chars().take(1200).collect();
        size += clipped.len();
        if size > 18000 {
            truncated = true;
            break;
        }
        let mut row = json!({"line":i+1,"text":clipped});
        if clipped.len() < line.len() {
            row["truncated"] = json!(true);
            truncated = true;
        }
        rows.push(row);
    }
    json!({"totalLines":total,"startLine":start,"lines":rows,"truncated":truncated,
        "scope":"仅此行范围；最多 120 行 / 18000 字节，单行最多 1200 字符；不执行脚本，非 UTF-8 显示替代字符。"})
}

pub fn strings(bytes: &[u8], query: &str) -> Value {
    let mut rows = vec![];
    let mut start = 0;
    let mut matched = 0;
    let mut runs = 0;
    for (i, b) in bytes.iter().chain(std::iter::once(&0)).enumerate() {
        if b.is_ascii_graphic() || *b == b' ' {
            continue;
        }
        if i - start >= 6 {
            runs += 1;
            let run = &bytes[start..i];
            // 必须先搜索完整字符串，再截取展示上下文；否则长字符串尾部的 IOC 会漏掉。
            let hit = if query.is_empty() {
                Some(0)
            } else {
                run.windows(query.len())
                    .position(|part| part.eq_ignore_ascii_case(query.as_bytes()))
            };
            if let Some(hit) = hit {
                matched += 1;
                if rows.len() < 100 {
                    let context = hit.saturating_sub(80);
                    let end = (context + 300).min(run.len());
                    rows.push(json!({"fileOffset":format!("0x{:x}",start+context),
                        "matchOffset":format!("0x{:x}",start+hit),"stringOffset":format!("0x{start:x}"),
                        "text":String::from_utf8_lossy(&run[context..end]),"truncated":context>0 || end<run.len()}));
                }
            }
        }
        start = i + 1;
    }
    json!({"strings":rows,"matchedRuns":matched,"scannedRuns":runs,"omittedMatches":matched-rows.len(),
        "scope":"全文件 ASCII 可打印连续串，最短 6 字节；大小写不敏感，每串展示首个命中上下文，最多 100 串 / 每串 300 字节。未覆盖 UTF-16、解密或解压后内容。"})
}

/// 映射入口至文件支持的可执行区间。使用差值判断，避免恶意头部的地址加法溢出。
pub fn entry(bytes: &[u8]) -> Result<(u32, u64, u64, u64), String> {
    let mapping = match Object::parse(bytes).map_err(|e| e.to_string())? {
        Object::PE(pe) => {
            if ![0x14c, 0x8664].contains(&pe.header.coff_header.machine) {
                return Err("本版仅支持 x86/x64 反汇编；此架构保留未知。".into());
            }
            let entry = pe.entry as u64;
            let s = pe
                .sections
                .iter()
                .find(|s| {
                    entry
                        .checked_sub(s.virtual_address as u64)
                        .is_some_and(|d| d < s.size_of_raw_data as u64)
                        && s.characteristics & 0x2000_0000 != 0
                })
                .ok_or("entry outside executable raw sections")?;
            let offset = (entry - s.virtual_address as u64)
                .checked_add(s.pointer_to_raw_data as u64)
                .ok_or("file offset overflow")?;
            let end = (s.pointer_to_raw_data as u64)
                .checked_add(s.size_of_raw_data as u64)
                .ok_or("section overflow")?;
            (
                if pe.is_64 { 64 } else { 32 },
                offset,
                entry
                    .checked_add(pe.image_base as u64)
                    .ok_or("virtual address overflow")?,
                end,
            )
        }
        Object::Elf(elf) => {
            if ![3, 62].contains(&elf.header.e_machine) || !elf.little_endian {
                return Err("本版仅支持 little-endian x86/x64 反汇编；此架构保留未知。".into());
            }
            let h = elf
                .program_headers
                .iter()
                .find(|h| {
                    h.p_type == goblin::elf::program_header::PT_LOAD
                        && h.is_executable()
                        && elf
                            .entry
                            .checked_sub(h.p_vaddr)
                            .is_some_and(|d| d < h.p_filesz)
                })
                .ok_or("entry outside executable file segments")?;
            (
                if elf.is_64 { 64 } else { 32 },
                (elf.entry - h.p_vaddr)
                    .checked_add(h.p_offset)
                    .ok_or("file offset overflow")?,
                elf.entry,
                h.p_offset
                    .checked_add(h.p_filesz)
                    .ok_or("segment overflow")?,
            )
        }
        _ => return Err("unsupported disassembly format".into()),
    };
    if mapping.1 >= mapping.3 || mapping.3 > bytes.len() as u64 {
        return Err("entry mapping outside sample bytes".into());
    }
    Ok(mapping)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn elf() -> Vec<u8> {
        let mut b = vec![0; 512];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        b[16..18].copy_from_slice(&2u16.to_le_bytes());
        b[18..20].copy_from_slice(&62u16.to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&0x400100u64.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&1u16.to_le_bytes());
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        b[68..72].copy_from_slice(&5u32.to_le_bytes());
        b[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
        b[96..104].copy_from_slice(&512u64.to_le_bytes());
        b[104..112].copy_from_slice(&512u64.to_le_bytes());
        b
    }
    #[test]
    fn long_ascii_tail_matches_before_clipping_with_real_file_offset() {
        let mut bytes = vec![0; 3];
        bytes.extend_from_slice(&vec![b'A'; 900]);
        bytes.extend_from_slice(b"Needle.IOC");
        bytes.extend_from_slice(&vec![b'Z'; 400]);
        let value = strings(&bytes, "needle.ioc");
        assert_eq!(value["matchedRuns"], 1);
        assert_eq!(value["strings"][0]["matchOffset"], "0x387");
        assert_eq!(value["strings"][0]["fileOffset"], "0x337");
        assert!(value["strings"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Needle.IOC"));
        assert_eq!(value["strings"][0]["truncated"], true);
        let repeated = b"Needle\0".repeat(101);
        let value = strings(&repeated, "needle");
        assert_eq!(value["strings"].as_array().unwrap().len(), 100);
        assert_eq!(value["omittedMatches"], 1);
    }
    #[test]
    fn malformed_or_non_executable_segments_fail_without_overflow() {
        let original = elf();
        assert_eq!(entry(&original).unwrap(), (64, 256, 0x400100, 512));
        for (position, bytes) in [
            (68, 4u32.to_le_bytes().to_vec()),
            (64, 2u32.to_le_bytes().to_vec()),
            (96, u64::MAX.to_le_bytes().to_vec()),
            (72, u64::MAX.to_le_bytes().to_vec()),
        ] {
            let mut b = original.clone();
            b[position..position + bytes.len()].copy_from_slice(&bytes);
            assert!(entry(&b).is_err(), "offset {position}");
        }
        let mut b = original;
        b[24..32].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
        b[80..88].copy_from_slice(&(u64::MAX - 10).to_le_bytes());
        assert_eq!(entry(&b).unwrap().1, 9); // 没有用虚拟地址上界加法，不会溢出。
    }
    #[test]
    fn arguments_and_source_clipping_expose_coverage() {
        assert!(validate("read_source", &json!({"startLine":"1","count":1})).is_err());
        assert!(validate("metadata", &json!({"path":"/etc/passwd"})).is_err());
        assert!(validate("search_strings", &json!({"query":""})).is_ok());
        assert!(validate("disassemble", &json!({"entryOffset":0,"count":1})).is_ok());
        let value = source(format!("{}\nlast", "汉".repeat(1300)).as_bytes(), 1, 2);
        assert_eq!(value["lines"][0]["truncated"], true);
        assert_eq!(value["lines"][1]["line"], 2);
        assert_eq!(value["lines"][1]["text"], "last");
    }
}
