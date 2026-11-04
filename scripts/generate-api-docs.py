#!/usr/bin/env python3
"""Document the registered Rust IPC surface and fail CI on documentation drift.

This is a source inventory, not a JSON Schema compiler. Unsupported signatures
fail rather than silently omit an interface. Examples and lifecycle contracts
are maintained in docs/IPC-API.md.
"""
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "docs/IPC-API.generated.md"


def pieces(text):
    depth = 0
    start = 0
    result = []
    for i, char in enumerate(text):
        if char in "<([": depth += 1
        elif char in ">)]": depth -= 1
        elif char == "," and depth == 0:
            result.append(text[start:i].strip()); start = i + 1
    if text[start:].strip(): result.append(text[start:].strip())
    return result


def generate():
    source = ROOT / "src-tauri/src"
    main = (source / "main.rs").read_text()
    registered = re.search(r"tauri::generate_handler!\[(.*?)\];", main, re.S)
    if not registered: raise RuntimeError("IPC registry not found")
    names = [name.strip() for name in registered[1].split(",") if name.strip()]
    if len(set(names)) != len(names): raise RuntimeError("Duplicate IPC registration")
    commands = {}
    for path in sorted(source.rglob("*.rs")):
        text = path.read_text()
        for match in re.finditer(r"#\[tauri::command\]\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*\((.*?)\)\s*(?:->\s*([^\{]+))?\{", text, re.S):
            module = path.relative_to(source).with_suffix("").as_posix().replace("/mod", "").replace("/", "::")
            name = (module + "::" if module != "main" else "") + match[1]
            args = []
            for arg in pieces(match[2]):
                key, typ = arg.split(":", 1); typ = " ".join(typ.split())
                if re.search(r"\b(?:State|AppHandle|WebviewWindow)\b", typ): continue
                key = re.sub(r"_([a-z])", lambda m: m[1].upper(), key.strip().removeprefix("mut "))
                args.append(f"{key}: {typ}")
            commands[name] = (args, " ".join((match[3] or "()").split()), path.relative_to(ROOT).as_posix(), text[:match.start()].count("\n") + 1)
    missing = set(names) - commands.keys()
    extra = commands.keys() - set(names)
    if missing or extra: raise RuntimeError(f"Unmatched signatures: missing={missing}; unregistered={extra}")
    version = json.loads((ROOT / "package.json").read_text())["version"]
    rows = [f"# IPC 注册目录 · {version}", "", "由 `scripts/generate-api-docs.py` 生成。更改接口后重新生成；CI 检查漂移。Rust 类型为源码类型，JSON 字段按 camelCase；`Option<T>` 可传 `null`。`State`、窗口和 AppHandle 由框架注入，不是调用参数。", "", "生命周期、权限、错误和调用示例见 [接口契约](IPC-API.md)。本表不承诺第三方插件或所有 `Value` 数据结构的独立版本兼容。", "", f"共 {len(names)} 个已注册命令。验收命令在正式工作区拒绝。", "", "| 命令 | JSON 参数（Rust 类型） | 成功值 | 定义 |", "| --- | --- | --- | --- |"]
    for name in names:
        args, result, file, line = commands[name]
        public = name.split("::")[-1]
        rows.append(f"| `{public}` | `{' ; '.join(args) or '无'}` | `{result}` | [{file}](../{file}#L{line}) |")
    platform = (source / "platform.rs").read_text()
    actions = sorted(set(re.findall(r'"([A-Za-z][A-Za-z0-9]+)"\s*=>', platform)) | {"assetCheck"})
    rows += ["", "## platform_action 操作目录", "", "参数为 `{ action, args }`，args 的字段由各操作校验。返回值按操作不同；未知操作拒绝。完整字段见上表 platform_action 定义；新增操作需同步契约与功能验收。", "", ", ".join(f"`{a}`" for a in actions), ""]
    return "\n".join(rows)


if __name__ == "__main__":
    content = generate()
    if "--check" in sys.argv:
        if not TARGET.exists() or TARGET.read_text() != content:
            raise SystemExit("IPC documentation is stale; run python3 scripts/generate-api-docs.py")
        print("Registered IPC documentation matches source")
    else:
        TARGET.write_text(content)
        print(str(TARGET.relative_to(ROOT)))
