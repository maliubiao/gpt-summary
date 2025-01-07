Response:
The user wants a summary of the provided C++ code snippet from `v8/src/codegen/arm/assembler-arm.cc`. Specifically, they are asking for:

1. **Functionality:** A general description of what the code does.
2. **Torque Check:** Whether the file could be a Torque source file based on its extension.
3. **JavaScript Relationship:** If the code relates to JavaScript functionality, provide a JavaScript example.
4. **Code Logic Inference:** If there's any conditional logic or computation that can be illustrated with input/output examples, provide those.
5. **Common Programming Errors:**  Highlight any potential user programming errors related to the functions in the snippet.
6. **Summary:** A concise overview of the code's purpose.

Let's break down the code:

- It defines various `Assembler` class methods for generating ARM instructions.
- These instructions deal with bitfield manipulation (`ubfx`, `sbfx`, `bfc`, `bfi`), packing/unpacking (`pkhbt`, `pkhtb`), and byte/half-word extraction/insertion with optional rotation and sign/zero extension (`sxtb`, `sxtab`, `sxth`, `sxtah`, `uxtb`, `uxtab`, `uxtb16`, `uxth`, `uxtah`).
- It also includes instructions for bit reversal (`rbit`) and byte/half-word reversal (`rev`).

Based on this, I can formulate the answer by addressing each of the user's requests.
这是 `v8/src/codegen/arm/assembler-arm.cc` 源代码的第三部分，它主要定义了 `Assembler` 类中用于生成 ARM 指令的成员函数。这些函数封装了生成特定 ARM 指令的逻辑，方便在 V8 编译器的代码生成阶段使用。

**功能归纳:**

这部分代码主要定义了以下功能的汇编指令生成函数：

1. **位域操作指令:**
   - `ubfx`:  无符号位域提取 (Unsigned Bit Field Extract)。从源寄存器提取指定宽度和位置的位，并写入目标寄存器的低位。
   - `sbfx`:  有符号位域提取 (Signed Bit Field Extract)。与 `ubfx` 类似，但提取的值会进行符号扩展。
   - `bfc`:  位域清零 (Bit Field Clear)。将目标寄存器中指定宽度和位置的位设置为零。
   - `bfi`:  位域插入 (Bit Field Insert)。将源寄存器低位的指定宽度位插入到目标寄存器的指定位置。

2. **打包和解包指令:**
   - `pkhbt`:  打包高半字和低字节 (Pack Halfword and Byte Top)。将一个寄存器的低16位与另一个寄存器的经过移位的低8位打包到目标寄存器。
   - `pkhtb`:  打包低半字和高字节 (Pack Halfword and Byte Bottom)。将一个寄存器的低16位与另一个寄存器的经过移位的低8位打包到目标寄存器。

3. **符号和零扩展指令:**
   - `sxtb`:  带符号扩展的字节 (Signed Extend Byte)。将源寄存器的低8位带符号扩展到目标寄存器。
   - `sxtab`: 带符号扩展的字节并加法 (Signed Extend Byte and Add)。将源寄存器的低8位带符号扩展后加到目标寄存器。
   - `sxth`:  带符号扩展的半字 (Signed Extend Halfword)。将源寄存器的低16位带符号扩展到目标寄存器。
   - `sxtah`: 带符号扩展的半字并加法 (Signed Extend Halfword and Add)。将源寄存器的低16位带符号扩展后加到目标寄存器。
   - `uxtb`:  无符号扩展的字节 (Unsigned Extend Byte)。将源寄存器的低8位无符号扩展到目标寄存器。
   - `uxtab`: 无符号扩展的字节并加法 (Unsigned Extend Byte and Add)。将源寄存器的低8位无符号扩展后加到目标寄存器。
   - `uxtb16`: 无符号扩展的字节到 16 位 (Unsigned Extend Byte to 16 bits)。将源寄存器的低8位无符号扩展到目标寄存器的低 16 位。
   - `uxth`:  无符号扩展的半字 (Unsigned Extend Halfword)。将源寄存器的低16位无符号扩展到目标寄存器。
   - `uxtah`: 无符号扩展的半字并加法 (Unsigned Extend Halfword and Add)。将源寄存器的低16位无符号扩展后加到目标寄存器。

4. **位反转和字节/半字反转指令:**
   - `rbit`:  位反转 (Reverse Bits)。反转寄存器中的所有位。
   - `rev`:  反转字节顺序 (Reverse Bytes)。反转寄存器中字节的顺序。

**关于文件类型:**

如果 `v8/src/codegen/arm/assembler-arm.cc` 以 `.tq` 结尾，那么它确实是一个 v8 Torque 源代码文件。然而，根据您提供的文件名 `.cc`，它是一个 C++ 源代码文件。 Torque 文件通常用于定义内置函数的类型签名和一些辅助函数。

**与 JavaScript 的关系 (示例):**

这些底层的汇编指令是 JavaScript 引擎执行 JavaScript 代码的基础。例如，当 JavaScript 执行位操作或需要进行类型转换时，V8 可能会生成这些 ARM 指令。

```javascript
// JavaScript 示例

// 位运算
let a = 0b10110011;
let b = a >> 2; // 右移操作，可能在底层用到位域提取或移位指令

// 类型转换
let num = 255;
let byte = num & 0xFF; // 提取低 8 位，可能用到 ubfx 或类似指令

// 数组操作 (涉及到内存读取和写入，间接用到这些指令)
let arr = [1, 2, 3];
let first = arr[0];
```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

- `dst` 寄存器：初始值为 0
- `src` 寄存器：值为 0b11110000111100001111000010101010 (十进制: -1431655766)
- `lsb`：4
- `width`：8

**指令:** `Assembler::ubfx(dst, src, lsb, width);`

**逻辑推理:**

`ubfx` 指令会从 `src` 寄存器的第 4 位开始（从 0 开始计数），提取 8 位。

`src` 的二进制表示： `11110000 11110000 11110000 **10101010**`
提取的 8 位： `10101010` (十进制: 170)

**输出:**

- `dst` 寄存器：值为 0b00000000000000000000000010101010 (十进制: 170)

**用户常见的编程错误:**

1. **`ubfx` 和 `sbfx` 的 `lsb` 和 `width` 参数错误:**  如果 `lsb + width` 大于 32，会导致提取超出寄存器边界，产生不可预测的结果或程序崩溃。

   ```c++
   // 错误示例
   Assembler a;
   Register dst = r0;
   Register src = r1;
   a.ubfx(dst, src, 30, 5); // 错误：30 + 5 > 32
   ```

2. **位域操作影响到不期望的位:** 使用 `bfc` 或 `bfi` 时，如果对 `lsb` 和 `width` 的计算错误，可能会意外地修改了寄存器中其他重要的位。

   ```c++
   // 错误示例
   Assembler a;
   Register dst = r0;
   // 假设 r0 的某些高位存储了重要信息
   a.bfc(dst, 0, 10); // 可能会意外清零不该清零的位
   ```

3. **混淆有符号和无符号扩展指令:**  错误地使用了 `sxtb` 代替 `uxtb`，或者反过来，会导致类型转换错误，尤其是在处理有符号和无符号整数时。

   ```c++
   // 错误示例
   Assembler a;
   Register dst = r0;
   Register src = r1;
   // 假设 r1 低 8 位表示一个有符号数 -1 (0xFF)
   a.uxtb(dst, src); // dst 的值会是 255，而不是 -1
   ```

**第 3 部分功能总结:**

这部分 `assembler-arm.cc` 代码专注于实现 ARM 架构中与**位操作、数据打包解包以及字节/半字扩展**相关的汇编指令生成。这些指令是构建更复杂操作的基础，并且在 V8 引擎进行 JavaScript 代码优化和执行时被广泛使用。 开发者通过调用这些 `Assembler` 的成员函数，能够精确地控制生成的底层机器码，从而实现高效的代码执行。

Prompt: 
```
这是目录为v8/src/codegen/arm/assembler-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm/assembler-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
 src.shift_imm_ * B7 | sh * B6 | 0x1 * B4 | src.rm_.code());
}

// Bitfield manipulation instructions.

// Unsigned bit field extract.
// Extracts #width adjacent bits from position #lsb in a register, and
// writes them to the low bits of a destination register.
//   ubfx dst, src, #lsb, #width
void Assembler::ubfx(Register dst, Register src, int lsb, int width,
                     Condition cond) {
  DCHECK(IsEnabled(ARMv7));
  DCHECK(dst != pc && src != pc);
  DCHECK((lsb >= 0) && (lsb <= 31));
  DCHECK((width >= 1) && (width <= (32 - lsb)));
  emit(cond | 0xF * B23 | B22 | B21 | (width - 1) * B16 | dst.code() * B12 |
       lsb * B7 | B6 | B4 | src.code());
}

// Signed bit field extract.
// Extracts #width adjacent bits from position #lsb in a register, and
// writes them to the low bits of a destination register. The extracted
// value is sign extended to fill the destination register.
//   sbfx dst, src, #lsb, #width
void Assembler::sbfx(Register dst, Register src, int lsb, int width,
                     Condition cond) {
  DCHECK(IsEnabled(ARMv7));
  DCHECK(dst != pc && src != pc);
  DCHECK((lsb >= 0) && (lsb <= 31));
  DCHECK((width >= 1) && (width <= (32 - lsb)));
  emit(cond | 0xF * B23 | B21 | (width - 1) * B16 | dst.code() * B12 |
       lsb * B7 | B6 | B4 | src.code());
}

// Bit field clear.
// Sets #width adjacent bits at position #lsb in the destination register
// to zero, preserving the value of the other bits.
//   bfc dst, #lsb, #width
void Assembler::bfc(Register dst, int lsb, int width, Condition cond) {
  DCHECK(IsEnabled(ARMv7));
  DCHECK(dst != pc);
  DCHECK((lsb >= 0) && (lsb <= 31));
  DCHECK((width >= 1) && (width <= (32 - lsb)));
  int msb = lsb + width - 1;
  emit(cond | 0x1F * B22 | msb * B16 | dst.code() * B12 | lsb * B7 | B4 | 0xF);
}

// Bit field insert.
// Inserts #width adjacent bits from the low bits of the source register
// into position #lsb of the destination register.
//   bfi dst, src, #lsb, #width
void Assembler::bfi(Register dst, Register src, int lsb, int width,
                    Condition cond) {
  DCHECK(IsEnabled(ARMv7));
  DCHECK(dst != pc && src != pc);
  DCHECK((lsb >= 0) && (lsb <= 31));
  DCHECK((width >= 1) && (width <= (32 - lsb)));
  int msb = lsb + width - 1;
  emit(cond | 0x1F * B22 | msb * B16 | dst.code() * B12 | lsb * B7 | B4 |
       src.code());
}

void Assembler::pkhbt(Register dst, Register src1, const Operand& src2,
                      Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.125.
  // cond(31-28) | 01101000(27-20) | Rn(19-16) |
  // Rd(15-12) | imm5(11-7) | 0(6) | 01(5-4) | Rm(3-0)
  DCHECK(dst != pc);
  DCHECK(src1 != pc);
  DCHECK(src2.IsImmediateShiftedRegister());
  DCHECK(src2.rm() != pc);
  DCHECK((src2.shift_imm_ >= 0) && (src2.shift_imm_ <= 31));
  DCHECK(src2.shift_op() == LSL);
  emit(cond | 0x68 * B20 | src1.code() * B16 | dst.code() * B12 |
       src2.shift_imm_ * B7 | B4 | src2.rm().code());
}

void Assembler::pkhtb(Register dst, Register src1, const Operand& src2,
                      Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.125.
  // cond(31-28) | 01101000(27-20) | Rn(19-16) |
  // Rd(15-12) | imm5(11-7) | 1(6) | 01(5-4) | Rm(3-0)
  DCHECK(dst != pc);
  DCHECK(src1 != pc);
  DCHECK(src2.IsImmediateShiftedRegister());
  DCHECK(src2.rm() != pc);
  DCHECK((src2.shift_imm_ >= 1) && (src2.shift_imm_ <= 32));
  DCHECK(src2.shift_op() == ASR);
  int asr = (src2.shift_imm_ == 32) ? 0 : src2.shift_imm_;
  emit(cond | 0x68 * B20 | src1.code() * B16 | dst.code() * B12 | asr * B7 |
       B6 | B4 | src2.rm().code());
}

void Assembler::sxtb(Register dst, Register src, int rotate, Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.233.
  // cond(31-28) | 01101010(27-20) | 1111(19-16) |
  // Rd(15-12) | rotate(11-10) | 00(9-8)| 0111(7-4) | Rm(3-0)
  DCHECK(dst != pc);
  DCHECK(src != pc);
  DCHECK(rotate == 0 || rotate == 8 || rotate == 16 || rotate == 24);
  emit(cond | 0x6A * B20 | 0xF * B16 | dst.code() * B12 |
       ((rotate >> 1) & 0xC) * B8 | 7 * B4 | src.code());
}

void Assembler::sxtab(Register dst, Register src1, Register src2, int rotate,
                      Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.233.
  // cond(31-28) | 01101010(27-20) | Rn(19-16) |
  // Rd(15-12) | rotate(11-10) | 00(9-8)| 0111(7-4) | Rm(3-0)
  DCHECK(dst != pc);
  DCHECK(src1 != pc);
  DCHECK(src2 != pc);
  DCHECK(rotate == 0 || rotate == 8 || rotate == 16 || rotate == 24);
  emit(cond | 0x6A * B20 | src1.code() * B16 | dst.code() * B12 |
       ((rotate >> 1) & 0xC) * B8 | 7 * B4 | src2.code());
}

void Assembler::sxth(Register dst, Register src, int rotate, Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.235.
  // cond(31-28) | 01101011(27-20) | 1111(19-16) |
  // Rd(15-12) | rotate(11-10) | 00(9-8)| 0111(7-4) | Rm(3-0)
  DCHECK(dst != pc);
  DCHECK(src != pc);
  DCHECK(rotate == 0 || rotate == 8 || rotate == 16 || rotate == 24);
  emit(cond | 0x6B * B20 | 0xF * B16 | dst.code() * B12 |
       ((rotate >> 1) & 0xC) * B8 | 7 * B4 | src.code());
}

void Assembler::sxtah(Register dst, Register src1, Register src2, int rotate,
                      Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.235.
  // cond(31-28) | 01101011(27-20) | Rn(19-16) |
  // Rd(15-12) | rotate(11-10) | 00(9-8)| 0111(7-4) | Rm(3-0)
  DCHECK(dst != pc);
  DCHECK(src1 != pc);
  DCHECK(src2 != pc);
  DCHECK(rotate == 0 || rotate == 8 || rotate == 16 || rotate == 24);
  emit(cond | 0x6B * B20 | src1.code() * B16 | dst.code() * B12 |
       ((rotate >> 1) & 0xC) * B8 | 7 * B4 | src2.code());
}

void Assembler::uxtb(Register dst, Register src, int rotate, Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.274.
  // cond(31-28) | 01101110(27-20) | 1111(19-16) |
  // Rd(15-12) | rotate(11-10) | 00(9-8)| 0111(7-4) | Rm(3-0)
  DCHECK(dst != pc);
  DCHECK(src != pc);
  DCHECK(rotate == 0 || rotate == 8 || rotate == 16 || rotate == 24);
  emit(cond | 0x6E * B20 | 0xF * B16 | dst.code() * B12 |
       ((rotate >> 1) & 0xC) * B8 | 7 * B4 | src.code());
}

void Assembler::uxtab(Register dst, Register src1, Register src2, int rotate,
                      Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.271.
  // cond(31-28) | 01101110(27-20) | Rn(19-16) |
  // Rd(15-12) | rotate(11-10) | 00(9-8)| 0111(7-4) | Rm(3-0)
  DCHECK(dst != pc);
  DCHECK(src1 != pc);
  DCHECK(src2 != pc);
  DCHECK(rotate == 0 || rotate == 8 || rotate == 16 || rotate == 24);
  emit(cond | 0x6E * B20 | src1.code() * B16 | dst.code() * B12 |
       ((rotate >> 1) & 0xC) * B8 | 7 * B4 | src2.code());
}

void Assembler::uxtb16(Register dst, Register src, int rotate, Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.275.
  // cond(31-28) | 01101100(27-20) | 1111(19-16) |
  // Rd(15-12) | rotate(11-10) | 00(9-8)| 0111(7-4) | Rm(3-0)
  DCHECK(dst != pc);
  DCHECK(src != pc);
  DCHECK(rotate == 0 || rotate == 8 || rotate == 16 || rotate == 24);
  emit(cond | 0x6C * B20 | 0xF * B16 | dst.code() * B12 |
       ((rotate >> 1) & 0xC) * B8 | 7 * B4 | src.code());
}

void Assembler::uxth(Register dst, Register src, int rotate, Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.276.
  // cond(31-28) | 01101111(27-20) | 1111(19-16) |
  // Rd(15-12) | rotate(11-10) | 00(9-8)| 0111(7-4) | Rm(3-0)
  DCHECK(dst != pc);
  DCHECK(src != pc);
  DCHECK(rotate == 0 || rotate == 8 || rotate == 16 || rotate == 24);
  emit(cond | 0x6F * B20 | 0xF * B16 | dst.code() * B12 |
       ((rotate >> 1) & 0xC) * B8 | 7 * B4 | src.code());
}

void Assembler::uxtah(Register dst, Register src1, Register src2, int rotate,
                      Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.273.
  // cond(31-28) | 01101111(27-20) | Rn(19-16) |
  // Rd(15-12) | rotate(11-10) | 00(9-8)| 0111(7-4) | Rm(3-0)
  DCHECK(dst != pc);
  DCHECK(src1 != pc);
  DCHECK(src2 != pc);
  DCHECK(rotate == 0 || rotate == 8 || rotate == 16 || rotate == 24);
  emit(cond | 0x6F * B20 | src1.code() * B16 | dst.code() * B12 |
       ((rotate >> 1) & 0xC) * B8 | 7 * B4 | src2.code());
}

void Assembler::rbit(Register dst, Register src, Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.144.
  // cond(31-28) | 011011111111(27-16) | Rd(15-12) | 11110011(11-4) | Rm(3-0)
  DCHECK(IsEnabled(ARMv7));
  DCHECK(dst != pc);
  DCHECK(src != pc);
  emit(cond | 0x6FF * B16 | dst.code() * B12 | 0xF3 * B4 | src.code());
}

void Assembler::rev(Register dst, Register src, Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.144.
  // cond(31-28) | 011010111111(27-16) | Rd(15-12) | 11110011(11-4) | Rm(3-0)
  DCHECK(dst != pc);
  DCHECK(src != pc);
  emit(cond | 0x6BF * B16 | dst.code() * B12 | 0xF3 * B4 | src.code());
}

// Status register access instructions.
void Assembler::mrs(Register dst, SRegister s, Condition cond) {
  DCHECK(dst != pc);
  emit(cond | B24 | s | 15 * B16 | dst.code() * B12);
}

void Assembler::msr(SRegisterFieldMask fields, const Operand& src,
                    Condition cond) {
  DCHECK_NE(fields & 0x000F0000, 0);  // At least one field must be set.
  DCHECK(((fields & 0xFFF0FFFF) == CPSR) || ((fields & 0xFFF0FFFF) == SPSR));
  Instr instr;
  if (src.IsImmediate()) {
    // Immediate.
    uint32_t rotate_imm;
    uint32_t immed_8;
    if (src.MustOutputRelocInfo(this) ||
        !FitsShifter(src.immediate(), &rotate_imm, &immed_8, nullptr)) {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      // Immediate operand cannot be encoded, load it first to a scratch
      // register.
      Move32BitImmediate(scratch, src);
      msr(fields, Operand(scratch), cond);
      return;
    }
    instr = I | rotate_imm * B8 | immed_8;
  } else {
    DCHECK(src.IsRegister());  // Only rm is allowed.
    instr = src.rm_.code();
  }
  emit(cond | instr | B24 | B21 | fields | 15 * B12);
}

// Load/Store instructions.
void Assembler::ldr(Register dst, const MemOperand& src, Condition cond) {
  AddrMode2(cond | B26 | L, dst, src);
}

void Assembler::str(Register src, const MemOperand& dst, Condition cond) {
  AddrMode2(cond | B26, src, dst);
}

void Assembler::ldrb(Register dst, const MemOperand& src, Condition cond) {
  AddrMode2(cond | B26 | B | L, dst, src);
}

void Assembler::strb(Register src, const MemOperand& dst, Condition cond) {
  AddrMode2(cond | B26 | B, src, dst);
}

void Assembler::ldrh(Register dst, const MemOperand& src, Condition cond) {
  AddrMode3(cond | L | B7 | H | B4, dst, src);
}

void Assembler::strh(Register src, const MemOperand& dst, Condition cond) {
  AddrMode3(cond | B7 | H | B4, src, dst);
}

void Assembler::ldrsb(Register dst, const MemOperand& src, Condition cond) {
  AddrMode3(cond | L | B7 | S6 | B4, dst, src);
}

void Assembler::ldrsh(Register dst, const MemOperand& src, Condition cond) {
  AddrMode3(cond | L | B7 | S6 | H | B4, dst, src);
}

void Assembler::ldrd(Register dst1, Register dst2, const MemOperand& src,
                     Condition cond) {
  DCHECK(src.rm() == no_reg);
  DCHECK(dst1 != lr);  // r14.
  DCHECK_EQ(0, dst1.code() % 2);
  DCHECK_EQ(dst1.code() + 1, dst2.code());
  AddrMode3(cond | B7 | B6 | B4, dst1, src);
}

void Assembler::strd(Register src1, Register src2, const MemOperand& dst,
                     Condition cond) {
  DCHECK(dst.rm() == no_reg);
  DCHECK(src1 != lr);  // r14.
  DCHECK_EQ(0, src1.code() % 2);
  DCHECK_EQ(src1.code() + 1, src2.code());
  AddrMode3(cond | B7 | B6 | B5 | B4, src1, dst);
}

void Assembler::ldr_pcrel(Register dst, int imm12, Condition cond) {
  AddrMode am = Offset;
  if (imm12 < 0) {
    imm12 = -imm12;
    am = NegOffset;
  }
  DCHECK(is_uint12(imm12));
  emit(cond | B26 | am | L | pc.code() * B16 | dst.code() * B12 | imm12);
}

// Load/Store exclusive instructions.
void Assembler::ldrex(Register dst, Register src, Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.75.
  // cond(31-28) | 00011001(27-20) | Rn(19-16) | Rt(15-12) | 111110011111(11-0)
  DCHECK(dst != pc);
  DCHECK(src != pc);
  emit(cond | B24 | B23 | B20 | src.code() * B16 | dst.code() * B12 | 0xF9F);
}

void Assembler::strex(Register src1, Register src2, Register dst,
                      Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.212.
  // cond(31-28) | 00011000(27-20) | Rn(19-16) | Rd(15-12) | 11111001(11-4) |
  // Rt(3-0)
  DCHECK(dst != pc);
  DCHECK(src1 != pc);
  DCHECK(src2 != pc);
  DCHECK(src1 != dst);
  DCHECK(src1 != src2);
  emit(cond | B24 | B23 | dst.code() * B16 | src1.code() * B12 | 0xF9 * B4 |
       src2.code());
}

void Assembler::ldrexb(Register dst, Register src, Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.76.
  // cond(31-28) | 00011101(27-20) | Rn(19-16) | Rt(15-12) | 111110011111(11-0)
  DCHECK(dst != pc);
  DCHECK(src != pc);
  emit(cond | B24 | B23 | B22 | B20 | src.code() * B16 | dst.code() * B12 |
       0xF9F);
}

void Assembler::strexb(Register src1, Register src2, Register dst,
                       Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.213.
  // cond(31-28) | 00011100(27-20) | Rn(19-16) | Rd(15-12) | 11111001(11-4) |
  // Rt(3-0)
  DCHECK(dst != pc);
  DCHECK(src1 != pc);
  DCHECK(src2 != pc);
  DCHECK(src1 != dst);
  DCHECK(src1 != src2);
  emit(cond | B24 | B23 | B22 | dst.code() * B16 | src1.code() * B12 |
       0xF9 * B4 | src2.code());
}

void Assembler::ldrexh(Register dst, Register src, Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.78.
  // cond(31-28) | 00011111(27-20) | Rn(19-16) | Rt(15-12) | 111110011111(11-0)
  DCHECK(dst != pc);
  DCHECK(src != pc);
  emit(cond | B24 | B23 | B22 | B21 | B20 | src.code() * B16 |
       dst.code() * B12 | 0xF9F);
}

void Assembler::strexh(Register src1, Register src2, Register dst,
                       Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.215.
  // cond(31-28) | 00011110(27-20) | Rn(19-16) | Rd(15-12) | 11111001(11-4) |
  // Rt(3-0)
  DCHECK(dst != pc);
  DCHECK(src1 != pc);
  DCHECK(src2 != pc);
  DCHECK(src1 != dst);
  DCHECK(src1 != src2);
  emit(cond | B24 | B23 | B22 | B21 | dst.code() * B16 | src1.code() * B12 |
       0xF9 * B4 | src2.code());
}

void Assembler::ldrexd(Register dst1, Register dst2, Register src,
                       Condition cond) {
  // cond(31-28) | 00011011(27-20) | Rn(19-16) | Rt(15-12) | 111110011111(11-0)
  DCHECK(dst1 != lr);  // r14.
  // The pair of destination registers is restricted to being an even-numbered
  // register and the odd-numbered register that immediately follows it.
  DCHECK_EQ(0, dst1.code() % 2);
  DCHECK_EQ(dst1.code() + 1, dst2.code());
  emit(cond | B24 | B23 | B21 | B20 | src.code() * B16 | dst1.code() * B12 |
       0xF9F);
}

void Assembler::strexd(Register res, Register src1, Register src2, Register dst,
                       Condition cond) {
  // cond(31-28) | 00011010(27-20) | Rn(19-16) | Rt(15-12) | 111110011111(11-0)
  DCHECK(src1 != lr);  // r14.
  // The pair of source registers is restricted to being an even-numbered
  // register and the odd-numbered register that immediately follows it.
  DCHECK_EQ(0, src1.code() % 2);
  DCHECK_EQ(src1.code() + 1, src2.code());
  emit(cond | B24 | B23 | B21 | dst.code() * B16 | res.code() * B12 |
       0xF9 * B4 | src1.code());
}

// Preload instructions.
void Assembler::pld(const MemOperand& address) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.128.
  // 1111(31-28) | 0111(27-24) | U(23) | R(22) | 01(21-20) | Rn(19-16) |
  // 1111(15-12) | imm5(11-07) | type(6-5) | 0(4)| Rm(3-0) |
  DCHECK(address.rm() == no_reg);
  DCHECK(address.am() == Offset);
  int U = B23;
  int offset = address.offset();
  if (offset < 0) {
    offset = -offset;
    U = 0;
  }
  DCHECK_LT(offset, 4096);
  emit(kSpecialCondition | B26 | B24 | U | B22 | B20 |
       address.rn().code() * B16 | 0xF * B12 | offset);
}

// Load/Store multiple instructions.
void Assembler::ldm(BlockAddrMode am, Register base, RegList dst,
                    Condition cond) {
  // ABI stack constraint: ldmxx base, {..sp..}  base != sp  is not restartable.
  DCHECK(base == sp || !dst.has(sp));

  AddrMode4(cond | B27 | am | L, base, dst);

  // Emit the constant pool after a function return implemented by ldm ..{..pc}.
  if (cond == al && dst.has(pc)) {
    // There is a slight chance that the ldm instruction was actually a call,
    // in which case it would be wrong to return into the constant pool; we
    // recognize this case by checking if the emission of the pool was blocked
    // at the pc of the ldm instruction by a mov lr, pc instruction; if this is
    // the case, we emit a jump over the pool.
    CheckConstPool(true, no_const_pool_before_ == pc_offset() - kInstrSize);
  }
}

void Assembler::stm(BlockAddrMode am, Register base, RegList src,
                    Condition cond) {
  AddrMode4(cond | B27 | am, base, src);
}

// Exception-generating instructions and debugging support.
// Stops with a non-negative code less than kNumOfWatchedStops support
// enabling/disabling and a counter feature. See simulator-arm.h .
void Assembler::stop(Condition cond, int32_t code) {
#ifndef __arm__
  DCHECK_GE(code, kDefaultStopCode);
  {
    BlockConstPoolScope block_const_pool(this);
    if (code >= 0) {
      svc(kStopCode + code, cond);
    } else {
      svc(kStopCode + kMaxStopCode, cond);
    }
  }
#else   // def __arm__
  if (cond != al) {
    Label skip;
    b(&skip, NegateCondition(cond));
    bkpt(0);
    bind(&skip);
  } else {
    bkpt(0);
  }
#endif  // def __arm__
}

void Assembler::bkpt(uint32_t imm16) {
  DCHECK(is_uint16(imm16));
  emit(al | B24 | B21 | (imm16 >> 4) * B8 | BKPT | (imm16 & 0xF));
}

void Assembler::svc(uint32_t imm24, Condition cond) {
  CHECK(is_uint24(imm24));
  emit(cond | 15 * B24 | imm24);
}

void Assembler::dmb(BarrierOption option) {
  if (CpuFeatures::IsSupported(ARMv7)) {
    // Details available in ARM DDI 0406C.b, A8-378.
    emit(kSpecialCondition | 0x57FF * B12 | 5 * B4 | option);
  } else {
    // Details available in ARM DDI 0406C.b, B3-1750.
    // CP15DMB: CRn=c7, opc1=0, CRm=c10, opc2=5, Rt is ignored.
    mcr(p15, 0, r0, cr7, cr10, 5);
  }
}

void Assembler::dsb(BarrierOption option) {
  if (CpuFeatures::IsSupported(ARMv7)) {
    // Details available in ARM DDI 0406C.b, A8-380.
    emit(kSpecialCondition | 0x57FF * B12 | 4 * B4 | option);
  } else {
    // Details available in ARM DDI 0406C.b, B3-1750.
    // CP15DSB: CRn=c7, opc1=0, CRm=c10, opc2=4, Rt is ignored.
    mcr(p15, 0, r0, cr7, cr10, 4);
  }
}

void Assembler::isb(BarrierOption option) {
  if (CpuFeatures::IsSupported(ARMv7)) {
    // Details available in ARM DDI 0406C.b, A8-389.
    emit(kSpecialCondition | 0x57FF * B12 | 6 * B4 | option);
  } else {
    // Details available in ARM DDI 0406C.b, B3-1750.
    // CP15ISB: CRn=c7, opc1=0, CRm=c5, opc2=4, Rt is ignored.
    mcr(p15, 0, r0, cr7, cr5, 4);
  }
}

void Assembler::csdb() {
  // Details available in Arm Cache Speculation Side-channels white paper,
  // version 1.1, page 4.
  emit(0xE320F014);
}

// Coprocessor instructions.
void Assembler::cdp(Coprocessor coproc, int opcode_1, CRegister crd,
                    CRegister crn, CRegister crm, int opcode_2,
                    Condition cond) {
  DCHECK(is_uint4(opcode_1) && is_uint3(opcode_2));
  emit(cond | B27 | B26 | B25 | (opcode_1 & 15) * B20 | crn.code() * B16 |
       crd.code() * B12 | coproc * B8 | (opcode_2 & 7) * B5 | crm.code());
}

void Assembler::cdp2(Coprocessor coproc, int opcode_1, CRegister crd,
                     CRegister crn, CRegister crm, int opcode_2) {
  cdp(coproc, opcode_1, crd, crn, crm, opcode_2, kSpecialCondition);
}

void Assembler::mcr(Coprocessor coproc, int opcode_1, Register rd,
                    CRegister crn, CRegister crm, int opcode_2,
                    Condition cond) {
  DCHECK(is_uint3(opcode_1) && is_uint3(opcode_2));
  emit(cond | B27 | B26 | B25 | (opcode_1 & 7) * B21 | crn.code() * B16 |
       rd.code() * B12 | coproc * B8 | (opcode_2 & 7) * B5 | B4 | crm.code());
}

void Assembler::mcr2(Coprocessor coproc, int opcode_1, Register rd,
                     CRegister crn, CRegister crm, int opcode_2) {
  mcr(coproc, opcode_1, rd, crn, crm, opcode_2, kSpecialCondition);
}

void Assembler::mrc(Coprocessor coproc, int opcode_1, Register rd,
                    CRegister crn, CRegister crm, int opcode_2,
                    Condition cond) {
  DCHECK(is_uint3(opcode_1) && is_uint3(opcode_2));
  emit(cond | B27 | B26 | B25 | (opcode_1 & 7) * B21 | L | crn.code() * B16 |
       rd.code() * B12 | coproc * B8 | (opcode_2 & 7) * B5 | B4 | crm.code());
}

void Assembler::mrc2(Coprocessor coproc, int opcode_1, Register rd,
                     CRegister crn, CRegister crm, int opcode_2) {
  mrc(coproc, opcode_1, rd, crn, crm, opcode_2, kSpecialCondition);
}

void Assembler::ldc(Coprocessor coproc, CRegister crd, const MemOperand& src,
                    LFlag l, Condition cond) {
  AddrMode5(cond | B27 | B26 | l | L | coproc * B8, crd, src);
}

void Assembler::ldc(Coprocessor coproc, CRegister crd, Register rn, int option,
                    LFlag l, Condition cond) {
  // Unindexed addressing.
  DCHECK(is_uint8(option));
  emit(cond | B27 | B26 | U | l | L | rn.code() * B16 | crd.code() * B12 |
       coproc * B8 | (option & 255));
}

void Assembler::ldc2(Coprocessor coproc, CRegister crd, const MemOperand& src,
                     LFlag l) {
  ldc(coproc, crd, src, l, kSpecialCondition);
}

void Assembler::ldc2(Coprocessor coproc, CRegister crd, Register rn, int option,
                     LFlag l) {
  ldc(coproc, crd, rn, option, l, kSpecialCondition);
}

// Support for VFP.

void Assembler::vldr(const DwVfpRegister dst, const Register base, int offset,
                     const Condition cond) {
  // Ddst = MEM(Rbase + offset).
  // Instruction details available in ARM DDI 0406C.b, A8-924.
  // cond(31-28) | 1101(27-24)| U(23) | D(22) | 01(21-20) | Rbase(19-16) |
  // Vd(15-12) | 1011(11-8) | offset
  DCHECK(VfpRegisterIsAvailable(dst));
  int u = 1;
  if (offset < 0) {
    CHECK_NE(offset, kMinInt);
    offset = -offset;
    u = 0;
  }
  int vd, d;
  dst.split_code(&vd, &d);

  DCHECK_GE(offset, 0);
  if ((offset % 4) == 0 && (offset / 4) < 256) {
    emit(cond | 0xD * B24 | u * B23 | d * B22 | B20 | base.code() * B16 |
         vd * B12 | 0xB * B8 | ((offset / 4) & 255));
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    // Larger offsets must be handled by computing the correct address in a
    // scratch register.
    DCHECK(base != scratch);
    if (u == 1) {
      add(scratch, base, Operand(offset));
    } else {
      sub(scratch, base, Operand(offset));
    }
    emit(cond | 0xD * B24 | d * B22 | B20 | scratch.code() * B16 | vd * B12 |
         0xB * B8);
  }
}

void Assembler::vldr(const DwVfpRegister dst, const MemOperand& operand,
                     const Condition cond) {
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(operand.am_ == Offset);
  if (operand.rm().is_valid()) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    add(scratch, operand.rn(),
        Operand(operand.rm(), operand.shift_op_, operand.shift_imm_));
    vldr(dst, scratch, 0, cond);
  } else {
    vldr(dst, operand.rn(), operand.offset(), cond);
  }
}

void Assembler::vldr(const SwVfpRegister dst, const Register base, int offset,
                     const Condition cond) {
  // Sdst = MEM(Rbase + offset).
  // Instruction details available in ARM DDI 0406A, A8-628.
  // cond(31-28) | 1101(27-24)| U001(23-20) | Rbase(19-16) |
  // Vdst(15-12) | 1010(11-8) | offset
  int u = 1;
  if (offset < 0) {
    offset = -offset;
    u = 0;
  }
  int sd, d;
  dst.split_code(&sd, &d);
  DCHECK_GE(offset, 0);

  if ((offset % 4) == 0 && (offset / 4) < 256) {
    emit(cond | u * B23 | d * B22 | 0xD1 * B20 | base.code() * B16 | sd * B12 |
         0xA * B8 | ((offset / 4) & 255));
  } else {
    // Larger offsets must be handled by computing the correct address in a
    // scratch register.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(base != scratch);
    if (u == 1) {
      add(scratch, base, Operand(offset));
    } else {
      sub(scratch, base, Operand(offset));
    }
    emit(cond | d * B22 | 0xD1 * B20 | scratch.code() * B16 | sd * B12 |
         0xA * B8);
  }
}

void Assembler::vldr(const SwVfpRegister dst, const MemOperand& operand,
                     const Condition cond) {
  DCHECK(operand.am_ == Offset);
  if (operand.rm().is_valid()) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    add(scratch, operand.rn(),
        Operand(operand.rm(), operand.shift_op_, operand.shift_imm_));
    vldr(dst, scratch, 0, cond);
  } else {
    vldr(dst, operand.rn(), operand.offset(), cond);
  }
}

void Assembler::vstr(const DwVfpRegister src, const Register base, int offset,
                     const Condition cond) {
  // MEM(Rbase + offset) = Dsrc.
  // Instruction details available in ARM DDI 0406C.b, A8-1082.
  // cond(31-28) | 1101(27-24)| U(23) | D(22) | 00(21-20) | Rbase(19-16) |
  // Vd(15-12) | 1011(11-8) | (offset/4)
  DCHECK(VfpRegisterIsAvailable(src));
  int u = 1;
  if (offset < 0) {
    CHECK_NE(offset, kMinInt);
    offset = -offset;
    u = 0;
  }
  DCHECK_GE(offset, 0);
  int vd, d;
  src.split_code(&vd, &d);

  if ((offset % 4) == 0 && (offset / 4) < 256) {
    emit(cond | 0xD * B24 | u * B23 | d * B22 | base.code() * B16 | vd * B12 |
         0xB * B8 | ((offset / 4) & 255));
  } else {
    // Larger offsets must be handled by computing the correct address in the a
    // scratch register.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(base != scratch);
    if (u == 1) {
      add(scratch, base, Operand(offset));
    } else {
      sub(scratch, base, Operand(offset));
    }
    emit(cond | 0xD * B24 | d * B22 | scratch.code() * B16 | vd * B12 |
         0xB * B8);
  }
}

void Assembler::vstr(const DwVfpRegister src, const MemOperand& operand,
                     const Condition cond) {
  DCHECK(VfpRegisterIsAvailable(src));
  DCHECK(operand.am_ == Offset);
  if (operand.rm().is_valid()) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    add(scratch, operand.rn(),
        Operand(operand.rm(), operand.shift_op_, operand.shift_imm_));
    vstr(src, scratch, 0, cond);
  } else {
    vstr(src, operand.rn(), operand.offset(), cond);
  }
}

void Assembler::vstr(const SwVfpRegister src, const Register base, int offset,
                     const Condition cond) {
  // MEM(Rbase + offset) = SSrc.
  // Instruction details available in ARM DDI 0406A, A8-786.
  // cond(31-28) | 1101(27-24)| U000(23-20) | Rbase(19-16) |
  // Vdst(15-12) | 1010(11-8) | (offset/4)
  int u = 1;
  if (offset < 0) {
    CHECK_NE(offset, kMinInt);
    offset = -offset;
    u = 0;
  }
  int sd, d;
  src.split_code(&sd, &d);
  DCHECK_GE(offset, 0);
  if ((offset % 4) == 0 && (offset / 4) < 256) {
    emit(cond | u * B23 | d * B22 | 0xD0 * B20 | base.code() * B16 | sd * B12 |
         0xA * B8 | ((offset / 4) & 255));
  } else {
    // Larger offsets must be handled by computing the correct address in a
    // scratch register.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    DCHECK(base != scratch);
    if (u == 1) {
      add(scratch, base, Operand(offset));
    } else {
      sub(scratch, base, Operand(offset));
    }
    emit(cond | d * B22 | 0xD0 * B20 | scratch.code() * B16 | sd * B12 |
         0xA * B8);
  }
}

void Assembler::vstr(const SwVfpRegister src, const MemOperand& operand,
                     const Condition cond) {
  DCHECK(operand.am_ == Offset);
  if (operand.rm().is_valid()) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    add(scratch, operand.rn(),
        Operand(operand.rm(), operand.shift_op_, operand.shift_imm_));
    vstr(src, scratch, 0, cond);
  } else {
    vstr(src, operand.rn(), operand.offset(), cond);
  }
}

void Assembler::vldm(BlockAddrMode am, Register base, DwVfpRegister first,
                     DwVfpRegister last, Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-922.
  // cond(31-28) | 110(27-25)| PUDW1(24-20) | Rbase(19-16) |
  // first(15-12) | 1011(11-8) | (count * 2)
  DCHECK_LE(first.code(), last.code());
  DCHECK(VfpRegisterIsAvailable(last));
  DCHECK(am == ia || am == ia_w || am == db_w);
  DCHECK(base != pc);

  int sd, d;
  first.split_code(&sd, &d);
  int count = last.code() - first.code() + 1;
  DCHECK_LE(count, 16);
  emit(cond | B27 | B26 | am | d * B22 | B20 | base.code() * B16 | sd * B12 |
       0xB * B8 | count * 2);
}

void Assembler::vstm(BlockAddrMode am, Register base, DwVfpRegister first,
                     DwVfpRegister last, Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-1080.
  // cond(31-28) | 110(27-25)| PUDW0(24-20) | Rbase(19-16) |
  // first(15-12) | 1011(11-8) | (count * 2)
  DCHECK_LE(first.code(), last.code());
  DCHECK(VfpRegisterIsAvailable(last));
  DCHECK(am == ia || am == ia_w || am == db_w);
  DCHECK(base != pc);

  int sd, d;
  first.split_code(&sd, &d);
  int count = last.code() - first.code() + 1;
  DCHECK_LE(count, 16);
  emit(cond | B27 | B26 | am | d * B22 | base.code() * B16 | sd * B12 |
       0xB * B8 | count * 2);
}

void Assembler::vldm(BlockAddrMode am, Register base, SwVfpRegister first,
                     SwVfpRegister last, Condition cond) {
  // Instruction details available in ARM DDI 0406A, A8-626.
  // cond(31-28) | 110(27-25)| PUDW1(24-20) | Rbase(19-16) |
  // first(15-12) | 1010(11-8) | (count/2)
  DCHECK_LE(first.code(), last.code());
  DCHECK(am == ia || am == ia_w || am == db_w);
  DCHECK(base != pc);

  int sd, d;
  first.split_code(&sd, &d);
  int count = last.code() - first.code() + 1;
  emit(cond | B27 | B26 | am | d * B22 | B20 | base.code() * B16 | sd * B12 |
       0xA * B8 | count);
}

void Assembler::vstm(BlockAddrMode am, Register base, SwVfpRegister first,
                     SwVfpRegister last, Condition cond) {
  // Instruction details available in ARM DDI 0406A, A8-784.
  // cond(31-28) | 110(27-25)| PUDW0(24-20) | Rbase(19-16) |
  // first(15-12) | 1011(11-8) | (count/2)
  DCHECK_LE(first.code(), last.code());
  DCHECK(am == ia || am == ia_w || am == db_w);
  DCHECK(base != pc);

  int sd, d;
  first.split_code(&sd, &d);
  int count = last.code() - first.code() + 1;
  emit(cond | B27 | B26 | am | d * B22 | base.code() * B16 | sd * B12 |
       0xA * B8 | count);
}

static void DoubleAsTwoUInt32(base::Double d, uint32_t* lo, uint32_t* hi) {
  uint64_t i = d.AsUint64();

  *lo = i & 0xFFFFFFFF;
  *hi = i >> 32;
}

static void WriteVmovIntImmEncoding(uint8_t imm, uint32_t* encoding) {
  // Integer promotion from uint8_t to int makes these all okay.
  *encoding = ((imm & 0x80) << (24 - 7));   // a
  *encoding |= ((imm & 0x70) << (16 - 4));  // bcd
  *encoding |= (imm & 0x0f);                //  efgh
}

// This checks if imm can be encoded into an immediate for vmov.
// See Table A7-15 in ARM DDI 0406C.d.
// Currently only supports the first row and op=0 && cmode=1110.
static bool FitsVmovIntImm(uint64_t imm, uint32_t* encoding, uint8_t* cmode) {
  uint32_t lo = imm & 0xFFFFFFFF;
  uint32_t hi = imm >> 32;
  if ((lo == hi && ((lo & 0xffffff00) == 0))) {
    WriteVmovIntImmEncoding(imm & 0xff, encoding);
    *cmode = 0;
    return true;
  } else if ((lo == hi) && ((lo & 0xffff) == (lo >> 16)) &&
             ((lo & 0xff) == (lo >> 24))) {
    // Check that all bytes in imm are the same.
    WriteVmovIntImmEncoding(imm & 0xff, encoding);
    *cmode = 0xe;
    return true;
  }

  return false;
}

void Assembler::vmov(const DwVfpRegister dst, uint64_t imm) {
  uint32_t enc;
  uint8_t cmode;
  uint8_t op = 0;
  if (CpuFeatures::IsSupported(NEON) && FitsVmovIntImm(imm, &enc, &cmode)) {
    CpuFeatureScope scope(this, NEON);
    // Instruction details available in ARM DDI 0406C.b, A8-937.
    // 001i1(27-23) | D(22) | 000(21-19) | imm3(18-16) | Vd(15-12) | cmode(11-8)
    // | 0(7) | 0(6) | op(5) | 4(1) | imm4(3-0)
    int vd, d;
    dst.split_code(&vd, &d);
    emit(kSpecialCondition | 0x05 * B23 | d * B22 | vd * B12 | cmode * B8 |
         op * B5 | 0x1 * B4 | enc);
  } els
"""


```