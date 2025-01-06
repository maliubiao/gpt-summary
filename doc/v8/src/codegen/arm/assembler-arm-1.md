Response: The user wants to understand the functionality of the provided C++ code snippet from `v8/src/codegen/arm/assembler-arm.cc`. This is the second part of a three-part file. The goal is to summarize its purpose and illustrate its connection to JavaScript using examples, if any.

**Thinking Process:**

1. **Identify the Core Task:** The code consists of a class named `Assembler` and several methods within it. These methods seem to correspond to ARM assembly instructions. The primary function of this code is to *generate* ARM machine code.

2. **Analyze Method Signatures and Functionality:**  Each method has a name that closely resembles an ARM assembly instruction (e.g., `ubfx`, `sbfx`, `bfc`, `bfi`, `pkhbt`, `pkhtb`, `sxtb`, `sxtab`, `sxth`, `sxtah`, `uxtb`, `uxtab`, `uxtb16`, `uxth`, `uxtah`, `rbit`, `rev`, `mrs`, `msr`, `ldr`, `str`, etc.). The parameters usually involve registers, immediate values, and conditions, which are common components of assembly instructions. The `emit()` function is likely used to output the generated instruction bytes.

3. **Group Instructions by Functionality:**
    * **Bitfield Manipulation:** Instructions like `ubfx`, `sbfx`, `bfc`, `bfi`.
    * **Packing/Unpacking:** Instructions like `pkhbt`, `pkhtb`.
    * **Sign/Zero Extension:** Instructions like `sxtb`, `sxtab`, `sxth`, `sxtah`, `uxtb`, `uxtab`, `uxtb16`, `uxth`, `uxtah`.
    * **Bit Reversal:** Instructions like `rbit`, `rev`.
    * **Status Register Access:** Instructions like `mrs`, `msr`.
    * **Load/Store:** Instructions like `ldr`, `str`, `ldrb`, `strb`, `ldrh`, `strh`, `ldrsb`, `ldrsh`, `ldrd`, `strd`, `ldr_pcrel`, `ldrex`, `strex`, etc.
    * **Load/Store Multiple:** Instructions like `ldm`, `stm`.
    * **Exception Handling/Debugging:** Instructions like `stop`, `bkpt`, `svc`.
    * **Memory Barriers:** Instructions like `dmb`, `dsb`, `isb`, `csdb`.
    * **Coprocessor Instructions:** Instructions like `cdp`, `mcr`, `mrc`, `ldc`.
    * **VFP (Vector Floating Point) Instructions:** A significant portion of the code deals with VFP instructions for loading, storing, moving, converting, and performing arithmetic operations on floating-point values.

4. **Identify Connections to JavaScript:** V8 is a JavaScript engine. The `Assembler` class is part of the code generation process. When V8 compiles JavaScript code, it translates it into machine code for the target architecture (in this case, ARM). The methods in this `Assembler` class directly correspond to the ARM instructions needed to execute JavaScript operations.

5. **Construct JavaScript Examples:** For each group of instructions, think about what kind of JavaScript operation would necessitate their use.
    * **Bitfield:**  Low-level bit manipulation, potentially for encoding/decoding data or interacting with hardware. Less common in typical JS.
    * **Packing/Unpacking:**  Working with data structures where multiple small values are packed into a single word. Could be related to typed arrays or optimization.
    * **Sign/Zero Extension:**  JavaScript numbers are typically double-precision floats, but sometimes integer operations or conversions are needed. These instructions handle the conversion of smaller integer types to larger ones.
    * **Status Register:**  Less directly related to standard JS, but might be used for internal engine operations or debugging.
    * **Load/Store:**  Accessing variables, object properties, and array elements in JavaScript requires loading data from memory into registers and storing data back.
    * **Load/Store Multiple:**  Optimized ways to load or store multiple values at once, potentially for function calls or stack management.
    * **Exception/Debugging:**  JavaScript exceptions map to underlying machine code traps or breakpoints. The `stop` and `bkpt` instructions can be used for debugging the engine or generated code.
    * **Memory Barriers:**  Important for multi-threaded JavaScript (e.g., Web Workers, SharedArrayBuffer) to ensure memory consistency.
    * **Floating-Point:**  JavaScript's number type is based on IEEE 754 double-precision floats. The VFP instructions are crucial for performing arithmetic, comparisons, and conversions on these numbers.

6. **Refine the Summary:**  Organize the findings into a clear and concise summary of the file's functionality. Emphasize its role in the V8 code generation pipeline.

7. **Provide Illustrative JavaScript Examples:**  Craft simple JavaScript snippets that would likely lead to the generation of the specific ARM instructions described in the code. Focus on demonstrating the *intent* and not necessarily the exact machine code output, which can be complex.
这是目录为v8/src/codegen/arm/assembler-arm.cc的c++源代码文件的第2部分，主要包含 `Assembler` 类的成员函数实现，这些函数对应于 ARMv7 及更高版本架构的一些指令集，特别是涉及到以下几个方面：

**功能归纳:**

1. **位域操作指令:**
   - `ubfx`: 无符号位域提取
   - `sbfx`: 有符号位域提取
   - `bfc`: 位域清零
   - `bfi`: 位域插入

2. **数据打包和解包指令:**
   - `pkhbt`: 将一个寄存器的低半字和另一个寄存器的经过移位的上半字打包到目标寄存器。
   - `pkhtb`: 将一个寄存器的上半字和另一个寄存器的经过移位的低半字打包到目标寄存器。

3. **符号和零扩展指令:**
   - `sxtb`: 符号扩展字节
   - `sxtab`: 符号扩展字节并加法
   - `sxth`: 符号扩展半字
   - `sxtah`: 符号扩展半字并加法
   - `uxtb`: 零扩展字节
   - `uxtab`: 零扩展字节并加法
   - `uxtb16`: 零扩展两个字节
   - `uxth`: 零扩展半字
   - `uxtah`: 零扩展半字并加法

4. **位反转指令:**
   - `rbit`: 位反转

5. **字节序反转指令:**
   - `rev`: 字节序反转

6. **状态寄存器访问指令:**
   - `mrs`: 将状态寄存器的内容移动到通用寄存器
   - `msr`: 将通用寄存器的内容移动到状态寄存器

7. **加载和存储指令 (Load/Store):**
   - `ldr`: 加载字
   - `str`: 存储字
   - `ldrb`: 加载字节
   - `strb`: 存储字节
   - `ldrh`: 加载半字
   - `strh`: 存储半字
   - `ldrsb`: 加载符号扩展字节
   - `ldrsh`: 加载符号扩展半字
   - `ldrd`: 加载双字
   - `strd`: 存储双字
   - `ldr_pcrel`: PC 相对地址加载
   - `ldrex`: 独占加载字
   - `strex`: 独占存储字
   - `ldrexb`: 独占加载字节
   - `strexb`: 独占存储字节
   - `ldrexh`: 独占加载半字
   - `strexh`: 独占存储半字
   - `ldrexd`: 独占加载双字
   - `strexd`: 独占存储双字

8. **预加载指令 (Preload):**
   - `pld`: 预加载数据

9. **多重加载和存储指令 (Load/Store Multiple):**
   - `ldm`: 加载多个寄存器
   - `stm`: 存储多个寄存器

10. **异常生成和调试支持指令:**
    - `stop`: 停止执行
    - `bkpt`: 断点
    - `svc`: 软件中断

11. **内存屏障指令:**
    - `dmb`: 数据内存屏障
    - `dsb`: 数据同步屏障
    - `isb`: 指令同步屏障
    - `csdb`: 推测性数据屏障

12. **协处理器指令:**
    - `cdp`: 协处理器数据操作
    - `mcr`: 通用寄存器到协处理器寄存器的数据传输
    - `mrc`: 协处理器寄存器到通用寄存器的数据传输
    - `ldc`: 加载协处理器寄存器

13. **VFP (Vector Floating Point) 指令:**  这部分代码涵盖了大量的 VFP 指令，用于处理单精度和双精度浮点数，包括：
    - 加载和存储 (`vldr`, `vstr`, `vldm`, `vstm`)
    - 移动 (`vmov`)，包括立即数移动
    - 类型转换 (`vcvt`)
    - 算术运算 (`vneg`, `vabs`, `vadd`, `vsub`, `vmul`, `vmla`, `vmls`, `vdiv`, `vsqrt`)
    - 比较 (`vcmp`)
    - 最大最小值 (`vmaxnm`, `vminnm`)
    - 选择 (`vsel`)
    - 状态寄存器操作 (`vmsr`)

**与 Javascript 的关系 (举例说明):**

这些指令是 V8 JavaScript 引擎在 ARM 架构上执行 JavaScript 代码的基础。当 V8 编译 JavaScript 代码时，它会将高级的 JavaScript 操作转换为底层的 ARM 汇编指令。

以下是一些 JavaScript 功能与这里列出的 ARM 指令可能的关系示例：

**1. 位操作:**

```javascript
let a = 10; // 0b1010
let b = a >> 1; // 右移一位，相当于 ubfx 或 sbfx

let c = 0xF0;
let d = c & 0x0F; //  位与操作可能涉及 bfc 和 bfi 来提取或修改特定位
```

V8 在执行这些 JavaScript 位操作时，可能会使用 `ubfx` 或 `sbfx` 来提取特定位，或者使用 `bfc` 和 `bfi` 来清零或插入位。

**2. 类型转换和大小端:**

```javascript
let num = 255;
let smallInt = new Int8Array([num])[0]; // 将 number 截断为有符号 8 位整数，可能用到 sxtb
let unsignedSmallInt = new Uint8Array([num])[0]; // 截断为无符号 8 位整数，可能用到 uxtb

let bigEndian = new Uint32Array(1);
bigEndian[0] = 0x12345678;
let littleEndianView = new Uint8Array(bigEndian.buffer);
// 访问 littleEndianView 可能会涉及到 rev 指令来处理字节序问题
```

在处理不同大小的整数类型或者需要考虑字节序时，V8 可能会使用 `sxtb`, `uxtb`, `rev` 等指令。

**3. 数字运算:**

```javascript
let x = 3.14;
let y = 2.71;
let sum = x + y; // 浮点数加法，会使用 vadd 指令
let product = x * y; // 浮点数乘法，会使用 vmul 指令
let absX = Math.abs(x); // 绝对值，会使用 vabs 指令
```

JavaScript 中的数字运算主要基于浮点数。V8 在执行这些运算时，会使用 VFP 指令，如 `vadd`, `vsub`, `vmul`, `vdiv`, `vabs` 等。

**4. 数组和对象访问:**

```javascript
let arr = [1, 2, 3];
let first = arr[0]; // 数组元素访问，会使用 ldr 指令加载内存中的值

let obj = { a: 10 };
let prop = obj.a; // 对象属性访问，也会涉及到 ldr 指令
```

访问数组元素或对象属性需要从内存中加载数据到寄存器，这会使用到 `ldr` 等加载指令。

**5. 原子操作 (SharedArrayBuffer 等):**

```javascript
const sab = new SharedArrayBuffer(4);
const view = new Int32Array(sab);
Atomics.add(view, 0, 5); // 原子加法，可能会用到 ldrex 和 strex 指令来实现原子性
```

当涉及到共享内存和原子操作时，V8 可能会使用 `ldrex` 和 `strex` 等独占加载/存储指令来确保操作的原子性。

**总结:**

这个代码文件的第二部分是 V8 JavaScript 引擎在 ARM 架构上生成机器码的关键组成部分。它定义了大量与 ARMv7 及更高版本架构相关的指令，涵盖了位操作、数据处理、内存访问、异常处理、以及浮点数运算等多个方面。这些指令使得 V8 能够高效地将 JavaScript 代码转化为可以在 ARM 处理器上执行的本地代码。

Prompt: 
```
这是目录为v8/src/codegen/arm/assembler-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

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
  } else {
    UNIMPLEMENTED();
  }
}

void Assembler::vmov(const QwNeonRegister dst, uint64_t imm) {
  uint32_t enc;
  uint8_t cmode;
  uint8_t op = 0;
  if (CpuFeatures::IsSupported(NEON) && FitsVmovIntImm(imm, &enc, &cmode)) {
    CpuFeatureScope scope(this, NEON);
    // Instruction details available in ARM DDI 0406C.b, A8-937.
    // 001i1(27-23) | D(22) | 000(21-19) | imm3(18-16) | Vd(15-12) | cmode(11-8)
    // | 0(7) | Q(6) | op(5) | 4(1) | imm4(3-0)
    int vd, d;
    dst.split_code(&vd, &d);
    emit(kSpecialCondition | 0x05 * B23 | d * B22 | vd * B12 | cmode * B8 |
         0x1 * B6 | op * B5 | 0x1 * B4 | enc);
  } else {
    UNIMPLEMENTED();
  }
}

// Only works for little endian floating point formats.
// We don't support VFP on the mixed endian floating point platform.
static bool FitsVmovFPImmediate(base::Double d, uint32_t* encoding) {
  // VMOV can accept an immediate of the form:
  //
  //  +/- m * 2^(-n) where 16 <= m <= 31 and 0 <= n <= 7
  //
  // The immediate is encoded using an 8-bit quantity, comprised of two
  // 4-bit fields. For an 8-bit immediate of the form:
  //
  //  [abcdefgh]
  //
  // where a is the MSB and h is the LSB, an immediate 64-bit double can be
  // created of the form:
  //
  //  [aBbbbbbb,bbcdefgh,00000000,00000000,
  //      00000000,00000000,00000000,00000000]
  //
  // where B = ~b.
  //

  uint32_t lo, hi;
  DoubleAsTwoUInt32(d, &lo, &hi);

  // The most obvious constraint is the long block of zeroes.
  if ((lo != 0) || ((hi & 0xFFFF) != 0)) {
    return false;
  }

  // Bits 61:54 must be all clear or all set.
  if (((hi & 0x3FC00000) != 0) && ((hi & 0x3FC00000) != 0x3FC00000)) {
    return false;
  }

  // Bit 62 must be NOT bit 61.
  if (((hi ^ (hi << 1)) & (0x40000000)) == 0) {
    return false;
  }

  // Create the encoded immediate in the form:
  //  [00000000,0000abcd,00000000,0000efgh]
  *encoding = (hi >> 16) & 0xF;       // Low nybble.
  *encoding |= (hi >> 4) & 0x70000;   // Low three bits of the high nybble.
  *encoding |= (hi >> 12) & 0x80000;  // Top bit of the high nybble.

  return true;
}

void Assembler::vmov(const SwVfpRegister dst, Float32 imm) {
  uint32_t enc;
  if (CpuFeatures::IsSupported(VFPv3) &&
      FitsVmovFPImmediate(base::Double(imm.get_scalar()), &enc)) {
    CpuFeatureScope scope(this, VFPv3);
    // The float can be encoded in the instruction.
    //
    // Sd = immediate
    // Instruction details available in ARM DDI 0406C.b, A8-936.
    // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | imm4H(19-16) |
    // Vd(15-12) | 101(11-9) | sz=0(8) | imm4L(3-0)
    int vd, d;
    dst.split_code(&vd, &d);
    emit(al | 0x1D * B23 | d * B22 | 0x3 * B20 | vd * B12 | 0x5 * B9 | enc);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    mov(scratch, Operand(imm.get_bits()));
    vmov(dst, scratch);
  }
}

void Assembler::vmov(const DwVfpRegister dst, base::Double imm,
                     const Register extra_scratch) {
  DCHECK(VfpRegisterIsAvailable(dst));
  uint32_t enc;
  if (CpuFeatures::IsSupported(VFPv3) && FitsVmovFPImmediate(imm, &enc)) {
    CpuFeatureScope scope(this, VFPv3);
    // The double can be encoded in the instruction.
    //
    // Dd = immediate
    // Instruction details available in ARM DDI 0406C.b, A8-936.
    // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | imm4H(19-16) |
    // Vd(15-12) | 101(11-9) | sz=1(8) | imm4L(3-0)
    int vd, d;
    dst.split_code(&vd, &d);
    emit(al | 0x1D * B23 | d * B22 | 0x3 * B20 | vd * B12 | 0x5 * B9 | B8 |
         enc);
  } else {
    // Synthesise the double from ARM immediates.
    uint32_t lo, hi;
    DoubleAsTwoUInt32(imm, &lo, &hi);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();

    if (lo == hi) {
      // Move the low and high parts of the double to a D register in one
      // instruction.
      mov(scratch, Operand(lo));
      vmov(dst, scratch, scratch);
    } else if (extra_scratch == no_reg) {
      // We only have one spare scratch register.
      mov(scratch, Operand(lo));
      vmov(NeonS32, dst, 0, scratch);
      if (((lo & 0xFFFF) == (hi & 0xFFFF)) && CpuFeatures::IsSupported(ARMv7)) {
        CpuFeatureScope scope(this, ARMv7);
        movt(scratch, hi >> 16);
      } else {
        mov(scratch, Operand(hi));
      }
      vmov(NeonS32, dst, 1, scratch);
    } else {
      // Move the low and high parts of the double to a D register in one
      // instruction.
      mov(scratch, Operand(lo));
      mov(extra_scratch, Operand(hi));
      vmov(dst, scratch, extra_scratch);
    }
  }
}

void Assembler::vmov(const SwVfpRegister dst, const SwVfpRegister src,
                     const Condition cond) {
  // Sd = Sm
  // Instruction details available in ARM DDI 0406B, A8-642.
  int sd, d, sm, m;
  dst.split_code(&sd, &d);
  src.split_code(&sm, &m);
  emit(cond | 0xE * B24 | d * B22 | 0xB * B20 | sd * B12 | 0xA * B8 | B6 |
       m * B5 | sm);
}

void Assembler::vmov(const DwVfpRegister dst, const DwVfpRegister src,
                     const Condition cond) {
  // Dd = Dm
  // Instruction details available in ARM DDI 0406C.b, A8-938.
  // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | 0000(19-16) | Vd(15-12) |
  // 101(11-9) | sz=1(8) | 0(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | vd * B12 | 0x5 * B9 | B8 | B6 |
       m * B5 | vm);
}

void Assembler::vmov(const DwVfpRegister dst, const Register src1,
                     const Register src2, const Condition cond) {
  // Dm = <Rt,Rt2>.
  // Instruction details available in ARM DDI 0406C.b, A8-948.
  // cond(31-28) | 1100(27-24)| 010(23-21) | op=0(20) | Rt2(19-16) |
  // Rt(15-12) | 1011(11-8) | 00(7-6) | M(5) | 1(4) | Vm
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(src1 != pc && src2 != pc);
  int vm, m;
  dst.split_code(&vm, &m);
  emit(cond | 0xC * B24 | B22 | src2.code() * B16 | src1.code() * B12 |
       0xB * B8 | m * B5 | B4 | vm);
}

void Assembler::vmov(const Register dst1, const Register dst2,
                     const DwVfpRegister src, const Condition cond) {
  // <Rt,Rt2> = Dm.
  // Instruction details available in ARM DDI 0406C.b, A8-948.
  // cond(31-28) | 1100(27-24)| 010(23-21) | op=1(20) | Rt2(19-16) |
  // Rt(15-12) | 1011(11-8) | 00(7-6) | M(5) | 1(4) | Vm
  DCHECK(VfpRegisterIsAvailable(src));
  DCHECK(dst1 != pc && dst2 != pc);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0xC * B24 | B22 | B20 | dst2.code() * B16 | dst1.code() * B12 |
       0xB * B8 | m * B5 | B4 | vm);
}

void Assembler::vmov(const SwVfpRegister dst, const Register src,
                     const Condition cond) {
  // Sn = Rt.
  // Instruction details available in ARM DDI 0406A, A8-642.
  // cond(31-28) | 1110(27-24)| 000(23-21) | op=0(20) | Vn(19-16) |
  // Rt(15-12) | 1010(11-8) | N(7)=0 | 00(6-5) | 1(4) | 0000(3-0)
  DCHECK(src != pc);
  int sn, n;
  dst.split_code(&sn, &n);
  emit(cond | 0xE * B24 | sn * B16 | src.code() * B12 | 0xA * B8 | n * B7 | B4);
}

void Assembler::vmov(const Register dst, const SwVfpRegister src,
                     const Condition cond) {
  // Rt = Sn.
  // Instruction details available in ARM DDI 0406A, A8-642.
  // cond(31-28) | 1110(27-24)| 000(23-21) | op=1(20) | Vn(19-16) |
  // Rt(15-12) | 1010(11-8) | N(7)=0 | 00(6-5) | 1(4) | 0000(3-0)
  DCHECK(dst != pc);
  int sn, n;
  src.split_code(&sn, &n);
  emit(cond | 0xE * B24 | B20 | sn * B16 | dst.code() * B12 | 0xA * B8 |
       n * B7 | B4);
}

// Type of data to read from or write to VFP register.
// Used as specifier in generic vcvt instruction.
enum VFPType { S32, U32, F32, F64 };

static bool IsSignedVFPType(VFPType type) {
  switch (type) {
    case S32:
      return true;
    case U32:
      return false;
    default:
      UNREACHABLE();
  }
}

static bool IsIntegerVFPType(VFPType type) {
  switch (type) {
    case S32:
    case U32:
      return true;
    case F32:
    case F64:
      return false;
    default:
      UNREACHABLE();
  }
}

static bool IsDoubleVFPType(VFPType type) {
  switch (type) {
    case F32:
      return false;
    case F64:
      return true;
    default:
      UNREACHABLE();
  }
}

// Split five bit reg_code based on size of reg_type.
//  32-bit register codes are Vm:M
//  64-bit register codes are M:Vm
// where Vm is four bits, and M is a single bit.
static void SplitRegCode(VFPType reg_type, int reg_code, int* vm, int* m) {
  DCHECK((reg_code >= 0) && (reg_code <= 31));
  if (IsIntegerVFPType(reg_type) || !IsDoubleVFPType(reg_type)) {
    SwVfpRegister::split_code(reg_code, vm, m);
  } else {
    DwVfpRegister::split_code(reg_code, vm, m);
  }
}

// Encode vcvt.src_type.dst_type instruction.
static Instr EncodeVCVT(const VFPType dst_type, const int dst_code,
                        const VFPType src_type, const int src_code,
                        VFPConversionMode mode, const Condition cond) {
  DCHECK(src_type != dst_type);
  int D, Vd, M, Vm;
  SplitRegCode(src_type, src_code, &Vm, &M);
  SplitRegCode(dst_type, dst_code, &Vd, &D);

  if (IsIntegerVFPType(dst_type) || IsIntegerVFPType(src_type)) {
    // Conversion between IEEE floating point and 32-bit integer.
    // Instruction details available in ARM DDI 0406B, A8.6.295.
    // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 1(19) | opc2(18-16) |
    // Vd(15-12) | 101(11-9) | sz(8) | op(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
    DCHECK(!IsIntegerVFPType(dst_type) || !IsIntegerVFPType(src_type));

    int sz, opc2, op;

    if (IsIntegerVFPType(dst_type)) {
      opc2 = IsSignedVFPType(dst_type) ? 0x5 : 0x4;
      sz = IsDoubleVFPType(src_type) ? 0x1 : 0x0;
      op = mode;
    } else {
      DCHECK(IsIntegerVFPType(src_type));
      opc2 = 0x0;
      sz = IsDoubleVFPType(dst_type) ? 0x1 : 0x0;
      op = IsSignedVFPType(src_type) ? 0x1 : 0x0;
    }

    return (cond | 0xE * B24 | B23 | D * B22 | 0x3 * B20 | B19 | opc2 * B16 |
            Vd * B12 | 0x5 * B9 | sz * B8 | op * B7 | B6 | M * B5 | Vm);
  } else {
    // Conversion between IEEE double and single precision.
    // Instruction details available in ARM DDI 0406B, A8.6.298.
    // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 0111(19-16) |
    // Vd(15-12) | 101(11-9) | sz(8) | 1(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
    int sz = IsDoubleVFPType(src_type) ? 0x1 : 0x0;
    return (cond | 0xE * B24 | B23 | D * B22 | 0x3 * B20 | 0x7 * B16 |
            Vd * B12 | 0x5 * B9 | sz * B8 | B7 | B6 | M * B5 | Vm);
  }
}

void Assembler::vcvt_f64_s32(const DwVfpRegister dst, const SwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  DCHECK(VfpRegisterIsAvailable(dst));
  emit(EncodeVCVT(F64, dst.code(), S32, src.code(), mode, cond));
}

void Assembler::vcvt_f32_s32(const SwVfpRegister dst, const SwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  emit(EncodeVCVT(F32, dst.code(), S32, src.code(), mode, cond));
}

void Assembler::vcvt_f64_u32(const DwVfpRegister dst, const SwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  DCHECK(VfpRegisterIsAvailable(dst));
  emit(EncodeVCVT(F64, dst.code(), U32, src.code(), mode, cond));
}

void Assembler::vcvt_f32_u32(const SwVfpRegister dst, const SwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  emit(EncodeVCVT(F32, dst.code(), U32, src.code(), mode, cond));
}

void Assembler::vcvt_s32_f32(const SwVfpRegister dst, const SwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  emit(EncodeVCVT(S32, dst.code(), F32, src.code(), mode, cond));
}

void Assembler::vcvt_u32_f32(const SwVfpRegister dst, const SwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  emit(EncodeVCVT(U32, dst.code(), F32, src.code(), mode, cond));
}

void Assembler::vcvt_s32_f64(const SwVfpRegister dst, const DwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  DCHECK(VfpRegisterIsAvailable(src));
  emit(EncodeVCVT(S32, dst.code(), F64, src.code(), mode, cond));
}

void Assembler::vcvt_u32_f64(const SwVfpRegister dst, const DwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  DCHECK(VfpRegisterIsAvailable(src));
  emit(EncodeVCVT(U32, dst.code(), F64, src.code(), mode, cond));
}

void Assembler::vcvt_f64_f32(const DwVfpRegister dst, const SwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  DCHECK(VfpRegisterIsAvailable(dst));
  emit(EncodeVCVT(F64, dst.code(), F32, src.code(), mode, cond));
}

void Assembler::vcvt_f32_f64(const SwVfpRegister dst, const DwVfpRegister src,
                             VFPConversionMode mode, const Condition cond) {
  DCHECK(VfpRegisterIsAvailable(src));
  emit(EncodeVCVT(F32, dst.code(), F64, src.code(), mode, cond));
}

void Assembler::vcvt_f64_s32(const DwVfpRegister dst, int fraction_bits,
                             const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-874.
  // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | 1010(19-16) | Vd(15-12) |
  // 101(11-9) | sf=1(8) | sx=1(7) | 1(6) | i(5) | 0(4) | imm4(3-0)
  DCHECK(IsEnabled(VFPv3));
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(fraction_bits > 0 && fraction_bits <= 32);
  int vd, d;
  dst.split_code(&vd, &d);
  int imm5 = 32 - fraction_bits;
  int i = imm5 & 1;
  int imm4 = (imm5 >> 1) & 0xF;
  emit(cond | 0xE * B24 | B23 | d * B22 | 0x3 * B20 | B19 | 0x2 * B16 |
       vd * B12 | 0x5 * B9 | B8 | B7 | B6 | i * B5 | imm4);
}

void Assembler::vneg(const DwVfpRegister dst, const DwVfpRegister src,
                     const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-968.
  // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | 0001(19-16) | Vd(15-12) |
  // 101(11-9) | sz=1(8) | 0(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);

  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | B16 | vd * B12 | 0x5 * B9 |
       B8 | B6 | m * B5 | vm);
}

void Assembler::vneg(const SwVfpRegister dst, const SwVfpRegister src,
                     const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-968.
  // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | 0001(19-16) | Vd(15-12) |
  // 101(11-9) | sz=0(8) | 0(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);

  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | B16 | vd * B12 | 0x5 * B9 |
       B6 | m * B5 | vm);
}

void Assembler::vabs(const DwVfpRegister dst, const DwVfpRegister src,
                     const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-524.
  // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | 0000(19-16) | Vd(15-12) |
  // 101(11-9) | sz=1(8) | 1(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | vd * B12 | 0x5 * B9 | B8 | B7 |
       B6 | m * B5 | vm);
}

void Assembler::vabs(const SwVfpRegister dst, const SwVfpRegister src,
                     const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-524.
  // cond(31-28) | 11101(27-23) | D(22) | 11(21-20) | 0000(19-16) | Vd(15-12) |
  // 101(11-9) | sz=0(8) | 1(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | vd * B12 | 0x5 * B9 | B7 | B6 |
       m * B5 | vm);
}

void Assembler::vadd(const DwVfpRegister dst, const DwVfpRegister src1,
                     const DwVfpRegister src2, const Condition cond) {
  // Dd = vadd(Dn, Dm) double precision floating point addition.
  // Dd = D:Vd; Dm=M:Vm; Dn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-830.
  // cond(31-28) | 11100(27-23)| D(22) | 11(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK(VfpRegisterIsAvailable(src2));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | 0x3 * B20 | vn * B16 | vd * B12 |
       0x5 * B9 | B8 | n * B7 | m * B5 | vm);
}

void Assembler::vadd(const SwVfpRegister dst, const SwVfpRegister src1,
                     const SwVfpRegister src2, const Condition cond) {
  // Sd = vadd(Sn, Sm) single precision floating point addition.
  // Sd = D:Vd; Sm=M:Vm; Sn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-830.
  // cond(31-28) | 11100(27-23)| D(22) | 11(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | 0x3 * B20 | vn * B16 | vd * B12 |
       0x5 * B9 | n * B7 | m * B5 | vm);
}

void Assembler::vsub(const DwVfpRegister dst, const DwVfpRegister src1,
                     const DwVfpRegister src2, const Condition cond) {
  // Dd = vsub(Dn, Dm) double precision floating point subtraction.
  // Dd = D:Vd; Dm=M:Vm; Dn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-1086.
  // cond(31-28) | 11100(27-23)| D(22) | 11(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK(VfpRegisterIsAvailable(src2));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | 0x3 * B20 | vn * B16 | vd * B12 |
       0x5 * B9 | B8 | n * B7 | B6 | m * B5 | vm);
}

void Assembler::vsub(const SwVfpRegister dst, const SwVfpRegister src1,
                     const SwVfpRegister src2, const Condition cond) {
  // Sd = vsub(Sn, Sm) single precision floating point subtraction.
  // Sd = D:Vd; Sm=M:Vm; Sn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-1086.
  // cond(31-28) | 11100(27-23)| D(22) | 11(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | 0x3 * B20 | vn * B16 | vd * B12 |
       0x5 * B9 | n * B7 | B6 | m * B5 | vm);
}

void Assembler::vmul(const DwVfpRegister dst, const DwVfpRegister src1,
                     const DwVfpRegister src2, const Condition cond) {
  // Dd = vmul(Dn, Dm) double precision floating point multiplication.
  // Dd = D:Vd; Dm=M:Vm; Dn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-960.
  // cond(31-28) | 11100(27-23)| D(22) | 10(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK(VfpRegisterIsAvailable(src2));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | 0x2 * B20 | vn * B16 | vd * B12 |
       0x5 * B9 | B8 | n * B7 | m * B5 | vm);
}

void Assembler::vmul(const SwVfpRegister dst, const SwVfpRegister src1,
                     const SwVfpRegister src2, const Condition cond) {
  // Sd = vmul(Sn, Sm) single precision floating point multiplication.
  // Sd = D:Vd; Sm=M:Vm; Sn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-960.
  // cond(31-28) | 11100(27-23)| D(22) | 10(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | 0x2 * B20 | vn * B16 | vd * B12 |
       0x5 * B9 | n * B7 | m * B5 | vm);
}

void Assembler::vmla(const DwVfpRegister dst, const DwVfpRegister src1,
                     const DwVfpRegister src2, const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-932.
  // cond(31-28) | 11100(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | op=0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK(VfpRegisterIsAvailable(src2));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | vn * B16 | vd * B12 | 0x5 * B9 | B8 |
       n * B7 | m * B5 | vm);
}

void Assembler::vmla(const SwVfpRegister dst, const SwVfpRegister src1,
                     const SwVfpRegister src2, const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-932.
  // cond(31-28) | 11100(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | op=0(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | vn * B16 | vd * B12 | 0x5 * B9 | n * B7 |
       m * B5 | vm);
}

void Assembler::vmls(const DwVfpRegister dst, const DwVfpRegister src1,
                     const DwVfpRegister src2, const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-932.
  // cond(31-28) | 11100(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | op=1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK(VfpRegisterIsAvailable(src2));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | vn * B16 | vd * B12 | 0x5 * B9 | B8 |
       n * B7 | B6 | m * B5 | vm);
}

void Assembler::vmls(const SwVfpRegister dst, const SwVfpRegister src1,
                     const SwVfpRegister src2, const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-932.
  // cond(31-28) | 11100(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | op=1(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1C * B23 | d * B22 | vn * B16 | vd * B12 | 0x5 * B9 | n * B7 |
       B6 | m * B5 | vm);
}

void Assembler::vdiv(const DwVfpRegister dst, const DwVfpRegister src1,
                     const DwVfpRegister src2, const Condition cond) {
  // Dd = vdiv(Dn, Dm) double precision floating point division.
  // Dd = D:Vd; Dm=M:Vm; Dn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-882.
  // cond(31-28) | 11101(27-23)| D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK(VfpRegisterIsAvailable(src2));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | vn * B16 | vd * B12 | 0x5 * B9 | B8 |
       n * B7 | m * B5 | vm);
}

void Assembler::vdiv(const SwVfpRegister dst, const SwVfpRegister src1,
                     const SwVfpRegister src2, const Condition cond) {
  // Sd = vdiv(Sn, Sm) single precision floating point division.
  // Sd = D:Vd; Sm=M:Vm; Sn=N:Vm.
  // Instruction details available in ARM DDI 0406C.b, A8-882.
  // cond(31-28) | 11101(27-23)| D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | vn * B16 | vd * B12 | 0x5 * B9 | n * B7 |
       m * B5 | vm);
}

void Assembler::vcmp(const DwVfpRegister src1, const DwVfpRegister src2,
                     const Condition cond) {
  // vcmp(Dd, Dm) double precision floating point comparison.
  // Instruction details available in ARM DDI 0406C.b, A8-864.
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 0100(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | E=0(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK(VfpRegisterIsAvailable(src2));
  int vd, d;
  src1.split_code(&vd, &d);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | 0x4 * B16 | vd * B12 |
       0x5 * B9 | B8 | B6 | m * B5 | vm);
}

void Assembler::vcmp(const SwVfpRegister src1, const SwVfpRegister src2,
                     const Condition cond) {
  // vcmp(Sd, Sm) single precision floating point comparison.
  // Instruction details available in ARM DDI 0406C.b, A8-864.
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 0100(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | E=0(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  src1.split_code(&vd, &d);
  int vm, m;
  src2.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | 0x4 * B16 | vd * B12 |
       0x5 * B9 | B6 | m * B5 | vm);
}

void Assembler::vcmp(const DwVfpRegister src1, const double src2,
                     const Condition cond) {
  // vcmp(Dd, #0.0) double precision floating point comparison.
  // Instruction details available in ARM DDI 0406C.b, A8-864.
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 0101(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | E=0(7) | 1(6) | 0(5) | 0(4) | 0000(3-0)
  DCHECK(VfpRegisterIsAvailable(src1));
  DCHECK_EQ(src2, 0.0);
  int vd, d;
  src1.split_code(&vd, &d);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | 0x5 * B16 | vd * B12 |
       0x5 * B9 | B8 | B6);
}

void Assembler::vcmp(const SwVfpRegister src1, const float src2,
                     const Condition cond) {
  // vcmp(Sd, #0.0) single precision floating point comparison.
  // Instruction details available in ARM DDI 0406C.b, A8-864.
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 0101(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | E=0(7) | 1(6) | 0(5) | 0(4) | 0000(3-0)
  DCHECK_EQ(src2, 0.0);
  int vd, d;
  src1.split_code(&vd, &d);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | 0x5 * B16 | vd * B12 |
       0x5 * B9 | B6);
}

void Assembler::vmaxnm(const DwVfpRegister dst, const DwVfpRegister src1,
                       const DwVfpRegister src2) {
  // kSpecialCondition(31-28) | 11101(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);

  emit(kSpecialCondition | 0x1D * B23 | d * B22 | vn * B16 | vd * B12 |
       0x5 * B9 | B8 | n * B7 | m * B5 | vm);
}

void Assembler::vmaxnm(const SwVfpRegister dst, const SwVfpRegister src1,
                       const SwVfpRegister src2) {
  // kSpecialCondition(31-28) | 11101(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | 0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);

  emit(kSpecialCondition | 0x1D * B23 | d * B22 | vn * B16 | vd * B12 |
       0x5 * B9 | n * B7 | m * B5 | vm);
}

void Assembler::vminnm(const DwVfpRegister dst, const DwVfpRegister src1,
                       const DwVfpRegister src2) {
  // kSpecialCondition(31-28) | 11101(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | N(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);

  emit(kSpecialCondition | 0x1D * B23 | d * B22 | vn * B16 | vd * B12 |
       0x5 * B9 | B8 | n * B7 | B6 | m * B5 | vm);
}

void Assembler::vminnm(const SwVfpRegister dst, const SwVfpRegister src1,
                       const SwVfpRegister src2) {
  // kSpecialCondition(31-28) | 11101(27-23) | D(22) | 00(21-20) | Vn(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | N(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);

  emit(kSpecialCondition | 0x1D * B23 | d * B22 | vn * B16 | vd * B12 |
       0x5 * B9 | n * B7 | B6 | m * B5 | vm);
}

void Assembler::vsel(Condition cond, const DwVfpRegister dst,
                     const DwVfpRegister src1, const DwVfpRegister src2) {
  // cond=kSpecialCondition(31-28) | 11100(27-23) | D(22) |
  // vsel_cond=XX(21-20) | Vn(19-16) | Vd(15-12) | 101(11-9) | sz=1(8) | N(7) |
  // 0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  int sz = 1;

  // VSEL has a special (restricted) condition encoding.
  //   eq(0b0000)... -> 0b00
  //   ge(0b1010)... -> 0b10
  //   gt(0b1100)... -> 0b11
  //   vs(0b0110)... -> 0b01
  // No other conditions are supported.
  int vsel_cond = (cond >> 30) & 0x3;
  if ((cond != eq) && (cond != ge) && (cond != gt) && (cond != vs)) {
    // We can implement some other conditions by swapping the inputs.
    DCHECK((cond == ne) | (cond == lt) | (cond == le) | (cond == vc));
    std::swap(vn, vm);
    std::swap(n, m);
  }

  emit(kSpecialCondition | 0x1C * B23 | d * B22 | vsel_cond * B20 | vn * B16 |
       vd * B12 | 0x5 * B9 | sz * B8 | n * B7 | m * B5 | vm);
}

void Assembler::vsel(Condition cond, const SwVfpRegister dst,
                     const SwVfpRegister src1, const SwVfpRegister src2) {
  // cond=kSpecialCondition(31-28) | 11100(27-23) | D(22) |
  // vsel_cond=XX(21-20) | Vn(19-16) | Vd(15-12) | 101(11-9) | sz=0(8) | N(7) |
  // 0(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  int sz = 0;

  // VSEL has a special (restricted) condition encoding.
  //   eq(0b0000)... -> 0b00
  //   ge(0b1010)... -> 0b10
  //   gt(0b1100)... -> 0b11
  //   vs(0b0110)... -> 0b01
  // No other conditions are supported.
  int vsel_cond = (cond >> 30) & 0x3;
  if ((cond != eq) && (cond != ge) && (cond != gt) && (cond != vs)) {
    // We can implement some other conditions by swapping the inputs.
    DCHECK((cond == ne) | (cond == lt) | (cond == le) | (cond == vc));
    std::swap(vn, vm);
    std::swap(n, m);
  }

  emit(kSpecialCondition | 0x1C * B23 | d * B22 | vsel_cond * B20 | vn * B16 |
       vd * B12 | 0x5 * B9 | sz * B8 | n * B7 | m * B5 | vm);
}

void Assembler::vsqrt(const DwVfpRegister dst, const DwVfpRegister src,
                      const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-1058.
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 0001(19-16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | 11(7-6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | B16 | vd * B12 | 0x5 * B9 |
       B8 | 0x3 * B6 | m * B5 | vm);
}

void Assembler::vsqrt(const SwVfpRegister dst, const SwVfpRegister src,
                      const Condition cond) {
  // Instruction details available in ARM DDI 0406C.b, A8-1058.
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 0001(19-16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | 11(7-6) | M(5) | 0(4) | Vm(3-0)
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | B16 | vd * B12 | 0x5 * B9 |
       0x3 * B6 | m * B5 | vm);
}

void Assembler::vmsr(Register dst, Condition cond) {
  // Instruction details available in ARM DDI 0406A, A8-652.
  // cond(31-28) | 1110 (27-24) | 1110(23-20)| 0001 (19-16) |
  // Rt(15-12) | 1010 (11-8) | 0(7) | 00 (6-5) | 1(4) | 0000(3-0)
  emit(cond | 0xE * B24 | 0xE * B20 | B16 
"""


```