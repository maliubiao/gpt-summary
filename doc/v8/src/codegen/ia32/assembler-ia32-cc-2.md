Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The code resides in `v8/src/codegen/ia32/assembler-ia32.cc`. The `assembler` part is a strong clue. Assemblers are responsible for translating assembly language instructions into machine code. The `ia32` part indicates this code is specific to the IA-32 (x86) architecture.

2. **Analyze the Functions:**  The code is a collection of member functions within the `Assembler` class. Most function names directly correspond to IA-32 assembly instructions (e.g., `pshufd`, `pblendw`, `addss`, `vmovlps`). This confirms the assembler's role. The functions take operands as arguments, often registers (`XMMRegister`, `Register`) and memory locations (`Operand`).

3. **Group Functionality:** The instructions can be broadly categorized:
    * **SSE/AVX Instructions:** Many functions have names like `pshufd`, `pblendw`, `addss`, `vmovlps`, `vpsllw`, etc. These are Streaming SIMD Extensions (SSE) and Advanced Vector Extensions (AVX) instructions, used for vectorized operations on floating-point and integer data.
    * **General Purpose Instructions (Implicit):**  While not explicitly defined in this snippet, the `emit_*` functions suggest the assembler also handles general-purpose instructions. The presence of `emit_operand` is key here.
    * **Buffer Management:** Functions like `EnsureSpace` and `GrowBuffer` indicate the assembler manages an internal buffer to store the generated machine code.
    * **Relocation Information:**  `RecordRelocInfo` and the mention of `RelocInfo` suggest the assembler handles relocation, necessary for code that might be loaded at different memory addresses.

4. **Address Specific Questions:**
    * **.tq extension:** The prompt asks about `.tq`. The answer should state that this extension signifies Torque code, a higher-level language used within V8, and that `.cc` indicates C++.
    * **Relationship to JavaScript:**  Since V8 is a JavaScript engine, the generated assembly code directly executes JavaScript. Examples of JavaScript operations that might leverage these instructions (like array manipulation or number processing) are needed.
    * **Code Logic & Assumptions:**  The functions are essentially wrappers around emitting byte sequences. The "logic" involves correctly encoding the instruction and operands. The input is the desired operation and its arguments; the output is the corresponding machine code bytes.
    * **Common Programming Errors:**  Focus on errors related to using these specific instructions, such as incorrect operand types or not checking for CPU feature support.
    * **Final Summary:**  Condense the findings into a concise summary of the code's purpose.

5. **Construct the Answer:**  Organize the information logically, addressing each part of the prompt. Use clear language and provide illustrative examples. Ensure the answer distinguishes between the C++ code and its relation to JavaScript execution.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus heavily on explaining each individual instruction.
* **Correction:** Realized a higher-level overview of the *categories* of instructions is more useful for understanding the file's purpose. Detailed explanations of each instruction aren't necessary for a functional summary.
* **Initial thought:**  Just list the JavaScript features that *could* use these instructions.
* **Correction:** Provide a concrete JavaScript example that clearly maps to the type of operations these instructions perform (e.g., array addition for vector operations).
* **Initial thought:** Focus only on the SSE/AVX instructions.
* **Correction:** Recognize the `emit_*` functions imply a broader assembler functionality beyond just SIMD instructions.

By following these steps, the comprehensive and accurate answer can be generated.
这是对目录为 `v8/src/codegen/ia32/assembler-ia32.cc` 的 V8 源代码的第三部分的功能归纳。结合前两部分，我们可以更全面地理解其作用。

**综合前三部分，`v8/src/codegen/ia32/assembler-ia32.cc` 文件的主要功能是实现了一个 IA-32 (x86) 架构的汇编器。**

具体来说，它提供了以下功能：

1. **生成 IA-32 架构的机器码:**  该文件包含 `Assembler` 类的实现，该类允许开发者通过 C++ 代码来构建 IA-32 汇编指令序列。每个以汇编指令命名的函数（例如 `mov`, `add`, `push`, `jmp`, `call`, 以及本部分看到的 `pshufd`, `pblendw`, `addss` 等）都负责将相应的汇编指令及其操作数编码成机器码字节。

2. **支持多种 IA-32 指令:** 代码覆盖了基本的通用指令（在前面的部分），以及本部分重点介绍的 **SSE (Streaming SIMD Extensions)** 和 **AVX (Advanced Vector Extensions)** 指令。这些指令用于执行 SIMD（Single Instruction, Multiple Data）操作，可以同时处理多个数据，常用于加速浮点数和整数运算。

3. **管理代码缓冲区:** `Assembler` 类内部维护一个缓冲区 (`buffer_`) 用于存储生成的机器码。`EnsureSpace` 函数确保在写入新指令之前有足够的空间，而 `GrowBuffer` 函数在缓冲区满时动态地扩展其大小。

4. **处理操作数:**  `emit_operand` 函数负责将汇编指令的操作数（寄存器、内存地址、立即数）编码到机器码中。它还处理与重定位相关的信息。

5. **支持标签和跳转:**  通过 `Label` 类和相关的 `bind`、`emit_label` 等方法，汇编器可以创建代码标签，并生成跳转指令（在前面的部分）以实现代码的控制流。

6. **处理重定位信息:** `RecordRelocInfo` 函数用于记录需要在代码加载时进行调整的信息，例如外部函数地址或全局变量地址。这对于生成可重定位的代码非常重要。

7. **提供 VEX 前缀支持 (AVX):**  `emit_vex_prefix` 函数用于生成 AVX 指令所需的可变长度编码（VEX）前缀。

**与 JavaScript 的关系：**

`v8/src/codegen/ia32/assembler-ia32.cc` 中生成的机器码最终会执行 JavaScript 代码。当 V8 编译 JavaScript 代码时，它会将高级的 JavaScript 代码转换为底层的机器码，而这个文件中的 `Assembler` 类就是用来生成这些机器码的工具。

例如，JavaScript 中的数组操作、数学运算、以及一些内置函数的实现，在底层可能会用到 SSE 或 AVX 指令来提升性能。

```javascript
// JavaScript 示例：对数组进行向量加法
function vectorAdd(a, b) {
  const result = [];
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] + b[i];
  }
  return result;
}

const arr1 = [1.0, 2.0, 3.0, 4.0];
const arr2 = [5.0, 6.0, 7.0, 8.0];
const sum = vectorAdd(arr1, arr2); // [6, 8, 10, 12]
```

在 V8 的底层实现中，对于 `vectorAdd` 这样的函数，如果条件允许（例如 CPU 支持 SSE/AVX），编译器可能会生成使用 `addps` (add packed single-precision floating-point values) 或 `vaddps` (AVX 版本) 等指令的机器码来并行地执行加法操作，从而提高效率。  本文件中定义的 `addss`， `ps`， `vps` 等函数就是用来生成这些指令的。

**代码逻辑推理和假设输入/输出：**

以 `Assembler::pshufd(XMMRegister dst, Operand src, uint8_t shuffle)` 为例：

* **假设输入:**
    * `dst`: 一个 `XMMRegister` 对象，例如 `xmm0`，表示目标 XMM 寄存器。
    * `src`: 一个 `Operand` 对象，可以是一个 XMM 寄存器（例如 `xmm1`）或一个内存地址。
    * `shuffle`: 一个 `uint8_t` 值，例如 `0b00011011`，用于指定 shuffle 模式。

* **代码逻辑:**
    1. `EnsureSpace` 确保有足够的空间写入指令。
    2. `EMIT(0x66); EMIT(0x0F); EMIT(0x70);`  写入 `pshufd` 指令的操作码前缀和操作码。
    3. `emit_sse_operand(dst, src);`  将目标寄存器 `dst` 和源操作数 `src` 编码到 ModR/M 字节中。
    4. `EMIT(shuffle);` 写入 shuffle 模式字节。

* **假设输出 (如果 src 是 xmm1):** 生成的机器码字节序列可能类似于：`0x66 0x0F 0x70 0xC1 0x1B` (最后的 `0x1B` 是 `shuffle` 值的例子)。

**用户常见的编程错误：**

1. **没有检查 CPU 特性支持:**  有些指令（例如 SSE4.1, AVX）只能在支持这些特性的 CPU 上运行。直接使用这些指令而不先检查 CPU 功能会导致程序崩溃或产生未定义行为。
   ```c++
   // 错误示例：直接使用 SSE4.1 指令，没有检查 CPU 特性
   void foo(Assembler& assm, XMMRegister dst, Operand src, uint8_t mask) {
     assm.pblendw(dst, src, mask); // 如果 CPU 不支持 SSE4.1，则会出错
   }
   ```
   **正确做法:** 在使用需要特定 CPU 特性的指令前，使用 V8 提供的特性检测机制 (`CpuFeatures::IsSupported()`).

2. **操作数类型不匹配:**  汇编指令对操作数的类型和大小有严格的要求。例如，某些指令可能只接受寄存器作为操作数，或者要求操作数是特定的数据类型。
   ```c++
   // 错误示例：尝试将立即数作为某些 SSE 指令的目标操作数
   // (通常 SSE 指令的目标操作数是寄存器)
   // assm.movsd(Immediate(10), xmm0); // 假设 movsd 不允许立即数作为目标
   ```
   需要仔细查阅指令的文档，确保操作数类型正确。

3. **shuffle 掩码使用错误:** 对于像 `pshufd` 这样的 shuffle 指令，`shuffle` 字节的每一部分都有特定的含义，指定了源操作数的哪个元素移动到目标操作数的哪个位置。使用错误的掩码会导致数据错乱。

4. **忘记 `EnsureSpace`:** 虽然 `EMIT` 宏内部通常会调用 `EnsureSpace`，但在直接操作缓冲区时，忘记检查空间会导致缓冲区溢出。

**总结 `v8/src/codegen/ia32/assembler-ia32.cc` (第 3 部分):**

本部分代码主要集中在实现 **SSE 和 AVX 指令** 的汇编功能。它提供了生成各种 SIMD 指令的方法，用于在 IA-32 架构上进行高效的向量化计算。这些指令对于 V8 优化 JavaScript 的数字运算和数组处理等操作至关重要。结合前两部分，这个文件构成了一个完整的 IA-32 汇编器，是 V8 代码生成器的核心组件之一。

**关于 `.tq` 结尾的文件:**

如果 `v8/src/codegen/ia32/assembler-ia32.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。Torque 是 V8 开发的一种领域特定语言 (DSL)，用于更安全、更易于维护的方式来编写 V8 的内置函数和运行时代码。  `.cc` 后缀表明它是 C++ 源代码。因此，`v8/src/codegen/ia32/assembler-ia32.cc` 是一个 **C++** 文件，而不是 Torque 文件。

Prompt: 
```
这是目录为v8/src/codegen/ia32/assembler-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ia32/assembler-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
d src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  EMIT(0xF2);
  EMIT(0x0F);
  EMIT(0x70);
  emit_sse_operand(dst, src);
  EMIT(shuffle);
}

void Assembler::pshufd(XMMRegister dst, Operand src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x70);
  emit_sse_operand(dst, src);
  EMIT(shuffle);
}

void Assembler::pblendw(XMMRegister dst, Operand src, uint8_t mask) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x3A);
  EMIT(0x0E);
  emit_sse_operand(dst, src);
  EMIT(mask);
}

void Assembler::palignr(XMMRegister dst, Operand src, uint8_t mask) {
  DCHECK(IsEnabled(SSSE3));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x3A);
  EMIT(0x0F);
  emit_sse_operand(dst, src);
  EMIT(mask);
}

void Assembler::pextrb(Operand dst, XMMRegister src, uint8_t offset) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x3A);
  EMIT(0x14);
  emit_sse_operand(src, dst);
  EMIT(offset);
}

void Assembler::pextrw(Operand dst, XMMRegister src, uint8_t offset) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x3A);
  EMIT(0x15);
  emit_sse_operand(src, dst);
  EMIT(offset);
}

void Assembler::pextrd(Operand dst, XMMRegister src, uint8_t offset) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x3A);
  EMIT(0x16);
  emit_sse_operand(src, dst);
  EMIT(offset);
}

void Assembler::insertps(XMMRegister dst, Operand src, uint8_t offset) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x3A);
  EMIT(0x21);
  emit_sse_operand(dst, src);
  EMIT(offset);
}

void Assembler::pinsrb(XMMRegister dst, Operand src, uint8_t offset) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x3A);
  EMIT(0x20);
  emit_sse_operand(dst, src);
  EMIT(offset);
}

void Assembler::pinsrw(XMMRegister dst, Operand src, uint8_t offset) {
  DCHECK(is_uint8(offset));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0xC4);
  emit_sse_operand(dst, src);
  EMIT(offset);
}

void Assembler::pinsrd(XMMRegister dst, Operand src, uint8_t offset) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(0x3A);
  EMIT(0x22);
  emit_sse_operand(dst, src);
  EMIT(offset);
}

void Assembler::addss(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x58);
  emit_sse_operand(dst, src);
}

void Assembler::subss(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x5C);
  emit_sse_operand(dst, src);
}

void Assembler::mulss(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x59);
  emit_sse_operand(dst, src);
}

void Assembler::divss(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x5E);
  emit_sse_operand(dst, src);
}

void Assembler::sqrtss(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x51);
  emit_sse_operand(dst, src);
}

void Assembler::ucomiss(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(0x2E);
  emit_sse_operand(dst, src);
}

void Assembler::maxss(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x5F);
  emit_sse_operand(dst, src);
}

void Assembler::minss(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0x5D);
  emit_sse_operand(dst, src);
}

// Packed single-precision floating-point SSE instructions.
void Assembler::ps(uint8_t opcode, XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0x0F);
  EMIT(opcode);
  emit_sse_operand(dst, src);
}

// Packed double-precision floating-point SSE instructions.
void Assembler::pd(uint8_t opcode, XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  EMIT(0x66);
  EMIT(0x0F);
  EMIT(opcode);
  emit_sse_operand(dst, src);
}

// AVX instructions

void Assembler::vss(uint8_t op, XMMRegister dst, XMMRegister src1,
                    Operand src2) {
  vinstr(op, dst, src1, src2, kF3, k0F, kWIG);
}

void Assembler::vps(uint8_t op, XMMRegister dst, XMMRegister src1,
                    Operand src2) {
  vinstr(op, dst, src1, src2, kNoPrefix, k0F, kWIG);
}

void Assembler::vpd(uint8_t op, XMMRegister dst, XMMRegister src1,
                    Operand src2) {
  vinstr(op, dst, src1, src2, k66, k0F, kWIG);
}

void Assembler::vshufpd(XMMRegister dst, XMMRegister src1, Operand src2,
                        uint8_t imm8) {
  DCHECK(is_uint8(imm8));
  vpd(0xC6, dst, src1, src2);
  EMIT(imm8);
}

void Assembler::vmovhlps(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
  vinstr(0x12, dst, src1, src2, kNoPrefix, k0F, kWIG);
}

void Assembler::vmovlhps(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
  vinstr(0x16, dst, src1, src2, kNoPrefix, k0F, kWIG);
}

void Assembler::vmovlps(XMMRegister dst, XMMRegister src1, Operand src2) {
  vinstr(0x12, dst, src1, src2, kNoPrefix, k0F, kWIG);
}

void Assembler::vmovlps(Operand dst, XMMRegister src) {
  vinstr(0x13, src, xmm0, dst, kNoPrefix, k0F, kWIG);
}

void Assembler::vmovhps(XMMRegister dst, XMMRegister src1, Operand src2) {
  vinstr(0x16, dst, src1, src2, kNoPrefix, k0F, kWIG);
}

void Assembler::vmovhps(Operand dst, XMMRegister src) {
  vinstr(0x17, src, xmm0, dst, kNoPrefix, k0F, kWIG);
}

void Assembler::vcmpps(XMMRegister dst, XMMRegister src1, Operand src2,
                       uint8_t cmp) {
  vps(0xC2, dst, src1, src2);
  EMIT(cmp);
}

void Assembler::vcmppd(XMMRegister dst, XMMRegister src1, Operand src2,
                       uint8_t cmp) {
  vpd(0xC2, dst, src1, src2);
  EMIT(cmp);
}

void Assembler::vshufps(XMMRegister dst, XMMRegister src1, Operand src2,
                        uint8_t imm8) {
  DCHECK(is_uint8(imm8));
  vps(0xC6, dst, src1, src2);
  EMIT(imm8);
}

void Assembler::vpsllw(XMMRegister dst, XMMRegister src, uint8_t imm8) {
  XMMRegister iop = XMMRegister::from_code(6);
  vinstr(0x71, iop, dst, Operand(src), k66, k0F, kWIG);
  EMIT(imm8);
}

void Assembler::vpslld(XMMRegister dst, XMMRegister src, uint8_t imm8) {
  XMMRegister iop = XMMRegister::from_code(6);
  vinstr(0x72, iop, dst, Operand(src), k66, k0F, kWIG);
  EMIT(imm8);
}

void Assembler::vpsllq(XMMRegister dst, XMMRegister src, uint8_t imm8) {
  XMMRegister iop = XMMRegister::from_code(6);
  vinstr(0x73, iop, dst, Operand(src), k66, k0F, kWIG);
  EMIT(imm8);
}

void Assembler::vpsrlw(XMMRegister dst, XMMRegister src, uint8_t imm8) {
  XMMRegister iop = XMMRegister::from_code(2);
  vinstr(0x71, iop, dst, Operand(src), k66, k0F, kWIG);
  EMIT(imm8);
}

void Assembler::vpsrld(XMMRegister dst, XMMRegister src, uint8_t imm8) {
  XMMRegister iop = XMMRegister::from_code(2);
  vinstr(0x72, iop, dst, Operand(src), k66, k0F, kWIG);
  EMIT(imm8);
}

void Assembler::vpsrlq(XMMRegister dst, XMMRegister src, uint8_t imm8) {
  XMMRegister iop = XMMRegister::from_code(2);
  vinstr(0x73, iop, dst, Operand(src), k66, k0F, kWIG);
  EMIT(imm8);
}

void Assembler::vpsraw(XMMRegister dst, XMMRegister src, uint8_t imm8) {
  XMMRegister iop = XMMRegister::from_code(4);
  vinstr(0x71, iop, dst, Operand(src), k66, k0F, kWIG);
  EMIT(imm8);
}

void Assembler::vpsrad(XMMRegister dst, XMMRegister src, uint8_t imm8) {
  XMMRegister iop = XMMRegister::from_code(4);
  vinstr(0x72, iop, dst, Operand(src), k66, k0F, kWIG);
  EMIT(imm8);
}

void Assembler::vpshufhw(XMMRegister dst, Operand src, uint8_t shuffle) {
  vinstr(0x70, dst, xmm0, src, kF3, k0F, kWIG);
  EMIT(shuffle);
}

void Assembler::vpshuflw(XMMRegister dst, Operand src, uint8_t shuffle) {
  vinstr(0x70, dst, xmm0, src, kF2, k0F, kWIG);
  EMIT(shuffle);
}

void Assembler::vpshufd(XMMRegister dst, Operand src, uint8_t shuffle) {
  vinstr(0x70, dst, xmm0, src, k66, k0F, kWIG);
  EMIT(shuffle);
}

void Assembler::vblendvps(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                          XMMRegister mask) {
  vinstr(0x4A, dst, src1, src2, k66, k0F3A, kW0);
  EMIT(mask.code() << 4);
}

void Assembler::vblendvpd(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                          XMMRegister mask) {
  vinstr(0x4B, dst, src1, src2, k66, k0F3A, kW0);
  EMIT(mask.code() << 4);
}

void Assembler::vpblendvb(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                          XMMRegister mask) {
  vinstr(0x4C, dst, src1, src2, k66, k0F3A, kW0);
  EMIT(mask.code() << 4);
}

void Assembler::vpblendw(XMMRegister dst, XMMRegister src1, Operand src2,
                         uint8_t mask) {
  vinstr(0x0E, dst, src1, src2, k66, k0F3A, kWIG);
  EMIT(mask);
}

void Assembler::vpalignr(XMMRegister dst, XMMRegister src1, Operand src2,
                         uint8_t mask) {
  vinstr(0x0F, dst, src1, src2, k66, k0F3A, kWIG);
  EMIT(mask);
}

void Assembler::vpextrb(Operand dst, XMMRegister src, uint8_t offset) {
  vinstr(0x14, src, xmm0, dst, k66, k0F3A, kWIG);
  EMIT(offset);
}

void Assembler::vpextrw(Operand dst, XMMRegister src, uint8_t offset) {
  vinstr(0x15, src, xmm0, dst, k66, k0F3A, kWIG);
  EMIT(offset);
}

void Assembler::vpextrd(Operand dst, XMMRegister src, uint8_t offset) {
  vinstr(0x16, src, xmm0, dst, k66, k0F3A, kWIG);
  EMIT(offset);
}

void Assembler::vinsertps(XMMRegister dst, XMMRegister src1, Operand src2,
                          uint8_t offset) {
  vinstr(0x21, dst, src1, src2, k66, k0F3A, kWIG);
  EMIT(offset);
}

void Assembler::vpinsrb(XMMRegister dst, XMMRegister src1, Operand src2,
                        uint8_t offset) {
  vinstr(0x20, dst, src1, src2, k66, k0F3A, kWIG);
  EMIT(offset);
}

void Assembler::vpinsrw(XMMRegister dst, XMMRegister src1, Operand src2,
                        uint8_t offset) {
  vinstr(0xC4, dst, src1, src2, k66, k0F, kWIG);
  EMIT(offset);
}

void Assembler::vpinsrd(XMMRegister dst, XMMRegister src1, Operand src2,
                        uint8_t offset) {
  vinstr(0x22, dst, src1, src2, k66, k0F3A, kWIG);
  EMIT(offset);
}

void Assembler::vroundsd(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                         RoundingMode mode) {
  vinstr(0x0b, dst, src1, src2, k66, k0F3A, kWIG);
  EMIT(static_cast<uint8_t>(mode) | 0x8);  // Mask precision exception.
}
void Assembler::vroundss(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                         RoundingMode mode) {
  vinstr(0x0a, dst, src1, src2, k66, k0F3A, kWIG);
  EMIT(static_cast<uint8_t>(mode) | 0x8);  // Mask precision exception.
}
void Assembler::vroundps(XMMRegister dst, XMMRegister src, RoundingMode mode) {
  vinstr(0x08, dst, xmm0, Operand(src), k66, k0F3A, kWIG);
  EMIT(static_cast<uint8_t>(mode) | 0x8);  // Mask precision exception.
}
void Assembler::vroundpd(XMMRegister dst, XMMRegister src, RoundingMode mode) {
  vinstr(0x09, dst, xmm0, Operand(src), k66, k0F3A, kWIG);
  EMIT(static_cast<uint8_t>(mode) | 0x8);  // Mask precision exception.
}

void Assembler::vmovmskpd(Register dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(xmm0, kL128, k66, k0F, kWIG);
  EMIT(0x50);
  emit_sse_operand(dst, src);
}

void Assembler::vmovmskps(Register dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(xmm0, kL128, kNoPrefix, k0F, kWIG);
  EMIT(0x50);
  emit_sse_operand(dst, src);
}

void Assembler::vpmovmskb(Register dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(xmm0, kL128, k66, k0F, kWIG);
  EMIT(0xD7);
  emit_sse_operand(dst, src);
}

void Assembler::vextractps(Operand dst, XMMRegister src, uint8_t imm8) {
  vinstr(0x17, src, xmm0, dst, k66, k0F3A, VexW::kWIG);
  EMIT(imm8);
}

void Assembler::vpcmpgtq(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
  vinstr(0x37, dst, src1, src2, k66, k0F38, VexW::kWIG);
}

void Assembler::bmi1(uint8_t op, Register reg, Register vreg, Operand rm) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(vreg, kLZ, kNoPrefix, k0F38, kW0);
  EMIT(op);
  emit_operand(reg, rm);
}

void Assembler::tzcnt(Register dst, Operand src) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0xBC);
  emit_operand(dst, src);
}

void Assembler::lzcnt(Register dst, Operand src) {
  DCHECK(IsEnabled(LZCNT));
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0xBD);
  emit_operand(dst, src);
}

void Assembler::popcnt(Register dst, Operand src) {
  DCHECK(IsEnabled(POPCNT));
  EnsureSpace ensure_space(this);
  EMIT(0xF3);
  EMIT(0x0F);
  EMIT(0xB8);
  emit_operand(dst, src);
}

void Assembler::bmi2(SIMDPrefix pp, uint8_t op, Register reg, Register vreg,
                     Operand rm) {
  DCHECK(IsEnabled(BMI2));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(vreg, kLZ, pp, k0F38, kW0);
  EMIT(op);
  emit_operand(reg, rm);
}

void Assembler::rorx(Register dst, Operand src, uint8_t imm8) {
  DCHECK(IsEnabled(BMI2));
  DCHECK(is_uint8(imm8));
  Register vreg = Register::from_code(0);  // VEX.vvvv unused
  EnsureSpace ensure_space(this);
  emit_vex_prefix(vreg, kLZ, kF2, k0F3A, kW0);
  EMIT(0xF0);
  emit_operand(dst, src);
  EMIT(imm8);
}

void Assembler::sse_instr(XMMRegister dst, Operand src, uint8_t escape,
                          uint8_t opcode) {
  EnsureSpace ensure_space(this);
  EMIT(escape);
  EMIT(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse2_instr(XMMRegister dst, Operand src, uint8_t prefix,
                           uint8_t escape, uint8_t opcode) {
  EnsureSpace ensure_space(this);
  EMIT(prefix);
  EMIT(escape);
  EMIT(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::ssse3_instr(XMMRegister dst, Operand src, uint8_t prefix,
                            uint8_t escape1, uint8_t escape2, uint8_t opcode) {
  DCHECK(IsEnabled(SSSE3));
  EnsureSpace ensure_space(this);
  EMIT(prefix);
  EMIT(escape1);
  EMIT(escape2);
  EMIT(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse4_instr(XMMRegister dst, Operand src, uint8_t prefix,
                           uint8_t escape1, uint8_t escape2, uint8_t opcode) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  EMIT(prefix);
  EMIT(escape1);
  EMIT(escape2);
  EMIT(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::vinstr(uint8_t op, XMMRegister dst, XMMRegister src1,
                       XMMRegister src2, SIMDPrefix pp, LeadingOpcode m, VexW w,
                       CpuFeature feature) {
  vinstr(op, dst, src1, src2, kL128, pp, m, w, feature);
}

void Assembler::vinstr(uint8_t op, XMMRegister dst, XMMRegister src1,
                       Operand src2, SIMDPrefix pp, LeadingOpcode m, VexW w,
                       CpuFeature feature) {
  vinstr(op, dst, src1, src2, kL128, pp, m, w, feature);
}

void Assembler::vinstr(uint8_t op, XMMRegister dst, XMMRegister src1,
                       XMMRegister src2, VectorLength l, SIMDPrefix pp,
                       LeadingOpcode m, VexW w, CpuFeature feature) {
  DCHECK(IsEnabled(feature));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src1, l, pp, m, w);
  EMIT(op);
  emit_sse_operand(dst, src2);
}

void Assembler::vinstr(uint8_t op, XMMRegister dst, XMMRegister src1,
                       Operand src2, VectorLength l, SIMDPrefix pp,
                       LeadingOpcode m, VexW w, CpuFeature feature) {
  DCHECK(IsEnabled(feature));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src1, l, pp, m, w);
  EMIT(op);
  emit_sse_operand(dst, src2);
}

void Assembler::emit_sse_operand(XMMRegister reg, Operand adr) {
  Register ireg = Register::from_code(reg.code());
  emit_operand(ireg, adr);
}

void Assembler::emit_sse_operand(XMMRegister dst, XMMRegister src) {
  EMIT(0xC0 | dst.code() << 3 | src.code());
}

void Assembler::emit_sse_operand(Register dst, XMMRegister src) {
  EMIT(0xC0 | dst.code() << 3 | src.code());
}

void Assembler::emit_sse_operand(XMMRegister dst, Register src) {
  EMIT(0xC0 | (dst.code() << 3) | src.code());
}

void Assembler::emit_vex_prefix(XMMRegister vreg, VectorLength l, SIMDPrefix pp,
                                LeadingOpcode mm, VexW w) {
  if (mm != k0F || w != kW0) {
    EMIT(0xC4);
    // Change RXB from "110" to "111" to align with gdb disassembler.
    EMIT(0xE0 | mm);
    EMIT(w | ((~vreg.code() & 0xF) << 3) | l | pp);
  } else {
    EMIT(0xC5);
    EMIT(((~vreg.code()) << 3) | l | pp);
  }
}

void Assembler::emit_vex_prefix(Register vreg, VectorLength l, SIMDPrefix pp,
                                LeadingOpcode mm, VexW w) {
  XMMRegister ivreg = XMMRegister::from_code(vreg.code());
  emit_vex_prefix(ivreg, l, pp, mm, w);
}

void Assembler::GrowBuffer() {
  DCHECK(buffer_overflow());
  DCHECK_EQ(buffer_start_, buffer_->start());

  // Compute new buffer size.
  int old_size = buffer_->size();
  int new_size = 2 * old_size;

  // Some internal data structures overflow for very large buffers,
  // they must ensure that kMaximalBufferSize is not too large.
  if (new_size > kMaximalBufferSize) {
    V8::FatalProcessOutOfMemory(nullptr, "Assembler::GrowBuffer");
  }

  // Set up new buffer.
  std::unique_ptr<AssemblerBuffer> new_buffer = buffer_->Grow(new_size);
  DCHECK_EQ(new_size, new_buffer->size());
  uint8_t* new_start = new_buffer->start();

  // Copy the data.
  intptr_t pc_delta = new_start - buffer_start_;
  intptr_t rc_delta = (new_start + new_size) - (buffer_start_ + old_size);
  size_t reloc_size = (buffer_start_ + old_size) - reloc_info_writer.pos();
  MemMove(new_start, buffer_start_, pc_offset());
  MemMove(rc_delta + reloc_info_writer.pos(), reloc_info_writer.pos(),
          reloc_size);

  // Switch buffers.
  buffer_ = std::move(new_buffer);
  buffer_start_ = new_start;
  pc_ += pc_delta;
  reloc_info_writer.Reposition(reloc_info_writer.pos() + rc_delta,
                               reloc_info_writer.last_pc() + pc_delta);

  // Relocate internal references.
  for (auto pos : internal_reference_positions_) {
    Address p = reinterpret_cast<Address>(buffer_start_ + pos);
    WriteUnalignedValue(p, ReadUnalignedValue<int>(p) + pc_delta);
  }

  // Relocate pc-relative references.
  int mode_mask = RelocInfo::ModeMask(RelocInfo::OFF_HEAP_TARGET);
  DCHECK_EQ(mode_mask, RelocInfo::kApplyMask & mode_mask);
  base::Vector<uint8_t> instructions{buffer_start_,
                                     static_cast<size_t>(pc_offset())};
  base::Vector<const uint8_t> reloc_info{reloc_info_writer.pos(), reloc_size};
  WritableJitAllocation jit_allocation =
      WritableJitAllocation::ForNonExecutableMemory(
          reinterpret_cast<Address>(instructions.begin()), instructions.size(),
          ThreadIsolation::JitAllocationType::kInstructionStream);
  for (WritableRelocIterator it(jit_allocation, instructions, reloc_info, 0,
                                mode_mask);
       !it.done(); it.next()) {
    it.rinfo()->apply(pc_delta);
  }

  DCHECK(!buffer_overflow());
}

void Assembler::emit_arith_b(int op1, int op2, Register dst, int imm8) {
  DCHECK(is_uint8(op1) && is_uint8(op2));  // wrong opcode
  DCHECK(is_uint8(imm8));
  DCHECK_EQ(op1 & 0x01, 0);  // should be 8bit operation
  EMIT(op1);
  EMIT(op2 | dst.code());
  EMIT(imm8);
}

void Assembler::emit_arith(int sel, Operand dst, const Immediate& x) {
  DCHECK((0 <= sel) && (sel <= 7));
  Register ireg = Register::from_code(sel);
  if (x.is_int8()) {
    EMIT(0x83);  // using a sign-extended 8-bit immediate.
    emit_operand(ireg, dst);
    EMIT(x.immediate() & 0xFF);
  } else if (dst.is_reg(eax)) {
    EMIT((sel << 3) | 0x05);  // short form if the destination is eax.
    emit(x);
  } else {
    EMIT(0x81);  // using a literal 32-bit immediate.
    emit_operand(ireg, dst);
    emit(x);
  }
}

void Assembler::emit_operand(Register reg, Operand adr) {
  emit_operand(reg.code(), adr);
}

void Assembler::emit_operand(XMMRegister reg, Operand adr) {
  Register ireg = Register::from_code(reg.code());
  emit_operand(ireg, adr);
}

void Assembler::emit_operand(int code, Operand adr) {
  // Isolate-independent code may not embed relocatable addresses.
  DCHECK_IMPLIES(options().isolate_independent_code,
                 adr.rmode() != RelocInfo::CODE_TARGET);
  DCHECK_IMPLIES(options().isolate_independent_code,
                 adr.rmode() != RelocInfo::FULL_EMBEDDED_OBJECT);
  DCHECK_IMPLIES(options().isolate_independent_code,
                 adr.rmode() != RelocInfo::EXTERNAL_REFERENCE);

  const unsigned length = adr.encoded_bytes().length();
  DCHECK_GT(length, 0);

  // Emit updated ModRM byte containing the given register.
  EMIT((adr.encoded_bytes()[0] & ~0x38) | (code << 3));

  // Emit the rest of the encoded operand.
  for (unsigned i = 1; i < length; i++) EMIT(adr.encoded_bytes()[i]);

  // Emit relocation information if necessary.
  if (length >= sizeof(int32_t) && !RelocInfo::IsNoInfo(adr.rmode())) {
    pc_ -= sizeof(int32_t);  // pc_ must be *at* disp32
    RecordRelocInfo(adr.rmode());
    if (adr.rmode() == RelocInfo::INTERNAL_REFERENCE) {  // Fixup for labels
      emit_label(ReadUnalignedValue<Label*>(reinterpret_cast<Address>(pc_)));
    } else {
      pc_ += sizeof(int32_t);
    }
  }
}

void Assembler::emit_label(Label* label) {
  if (label->is_bound()) {
    internal_reference_positions_.push_back(pc_offset());
    emit(reinterpret_cast<uint32_t>(buffer_start_ + label->pos()));
  } else {
    emit_disp(label, Displacement::CODE_ABSOLUTE);
  }
}

void Assembler::emit_farith(int b1, int b2, int i) {
  DCHECK(is_uint8(b1) && is_uint8(b2));  // wrong opcode
  DCHECK(0 <= i && i < 8);               // illegal stack offset
  EMIT(b1);
  EMIT(b2 + i);
}

void Assembler::db(uint8_t data) {
  EnsureSpace ensure_space(this);
  EMIT(data);
}

void Assembler::dd(uint32_t data) {
  EnsureSpace ensure_space(this);
  emit(data);
}

void Assembler::dq(uint64_t data) {
  EnsureSpace ensure_space(this);
  emit_q(data);
}

void Assembler::dd(Label* label) {
  EnsureSpace ensure_space(this);
  RecordRelocInfo(RelocInfo::INTERNAL_REFERENCE);
  emit_label(label);
}

void Assembler::RecordRelocInfo(RelocInfo::Mode rmode, intptr_t data) {
  if (!ShouldRecordRelocInfo(rmode)) return;
  RelocInfo rinfo(reinterpret_cast<Address>(pc_), rmode, data);
  reloc_info_writer.Write(&rinfo);
}

#undef EMIT

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_IA32

"""


```