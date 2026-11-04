import { readFileSync } from 'node:fs';
import { Decoder, DecoderOptions, Formatter, FormatterSyntax } from 'iced-x86';
const [bits, offset, va, limit, windowLength] = process.argv.slice(2);
const bitness = Number(bits),
  start = Number(offset),
  count = Number(limit);
if (
  ![32, 64].includes(bitness) ||
  !Number.isSafeInteger(start) ||
  start < 0 ||
  !Number.isSafeInteger(count) ||
  count < 1 ||
  count > 160
)
  throw Error('invalid disassembly range');
const length = Number(windowLength);
if (!Number.isSafeInteger(length) || length < 1 || length > 4096)
  throw Error('invalid byte window');
const bytes = readFileSync('/tmp/sample');
if (start >= bytes.length) throw Error('offset outside sample');
const decoder = new Decoder(
  bitness,
  bytes.subarray(start, start + length),
  DecoderOptions.None,
);
const formatter = new Formatter(FormatterSyntax.Nasm);
const initial = BigInt(va);
decoder.ip = initial;
const rows = [];
try {
  for (const instruction of decoder.decodeInstructions(count)) {
    try {
      rows.push({
        address: '0x' + instruction.ip.toString(16),
        fileOffset:
          '0x' + (BigInt(start) + instruction.ip - initial).toString(16),
        text: formatter.format(instruction),
        length: instruction.length,
      });
    } finally {
      instruction.free();
    }
  }
  process.stdout.write(JSON.stringify(rows));
} finally {
  formatter.free();
  decoder.free();
}
