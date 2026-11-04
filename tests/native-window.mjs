// Capture only the acceptance client's window, never the user's full desktop.
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
export async function nativeWindowCapture(root) {
  assert.equal(process.platform, 'darwin');
  const helper = path.join(root, 'capture-own-window');
  await fs.writeFile(
    helper + '.swift',
    `import CoreGraphics
import Foundation
let pid = Int(CommandLine.arguments[1])!
let rows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as! [[String: Any]]
if let r = rows.first(where: { ($0[kCGWindowOwnerPID as String] as? Int) == pid && ($0[kCGWindowLayer as String] as? Int) == 0 }) { print(r[kCGWindowNumber as String]!) }
`,
  );
  execFileSync('swiftc', [helper + '.swift', '-o', helper]);
  return (pid, file) => {
    const id = execFileSync(helper, [String(pid)], { encoding: 'utf8' }).trim();
    assert(/^\d+$/.test(id), 'Acceptance window was not found');
    execFileSync('/usr/sbin/screencapture', ['-x', '-o', '-l', id, file]);
  };
}
