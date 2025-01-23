Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Initial Scan and Keywords:**  The first step is a quick scan for recognizable patterns and keywords. We see things like `Assembler`, `emit`, `vbroadcast`, `vinserti128`, `vmovd`, `vmovq`, `fma_instr`, `sse_instr`, register names (XMM, YMM), opcodes (like `0x18`, `0x19`), and `DCHECK`. These strongly suggest this code is related to generating machine code, specifically for the x64 architecture, and involves Single Instruction Multiple Data (SIMD) operations.

2. **Identify the Core Class:** The repeated use of `Assembler::` clearly points to the `Assembler` class as the central entity. The filename `assembler-x64.cc` reinforces this. The code is defining *methods* of this class.

3. **Focus on Function Definitions:** The majority of the snippet consists of function definitions. Each function seems to correspond to a specific x64 instruction or a family of instructions. The names of the functions (e.g., `vbroadcastss`, `vinserti128`, `vmovd`) strongly hint at the x86/x64 assembly instructions they are implementing.

4. **Analyze the Structure of a Typical Function:** Let's pick a representative function, like `Assembler::vbroadcastss(XMMRegister dst, XMMRegister src)`. We see:
    * `DCHECK(IsEnabled(AVX2));`: This suggests a runtime check that the required processor feature (AVX2 in this case) is enabled. This is crucial for instruction set extensions.
    * `EnsureSpace ensure_space(this);`: This likely handles memory management for the generated code, ensuring enough space is available to write the instruction.
    * `emit_vex_prefix(...)`:  This is a key function. "VEX prefix" is a characteristic of modern x86 instruction encoding, especially for AVX instructions. It provides information about register operands, vector lengths, and opcodes.
    * `emit(0x18);`: This emits the actual opcode byte for the instruction.
    * `emit_sse_operand(dst, src);`: This emits the ModR/M byte and potentially SIB byte, which specify the operands of the instruction.

5. **Recognize Macros:** The `BROADCAST` macro is used to generate multiple similar function definitions. This is a code generation technique to reduce redundancy. Understanding the macro expansion is helpful.

6. **Group Similar Functions:** Observe the patterns in function names. Functions starting with `v` often indicate AVX instructions. The suffixes like `ss`, `sd`, `ps`, `pd` likely refer to the data types being operated on (single-precision scalar, double-precision scalar, single-precision packed, double-precision packed).

7. **Infer Functionality from Names and Structure:**  Based on the function names and their internal structure, we can deduce their purpose:
    * `vbroadcast`: Broadcasting a value from a smaller register to a larger vector register.
    * `vinserti128`, `vextractf128`, `vperm2f128`:  Manipulating parts of YMM registers (256-bit).
    * `vmovd`, `vmovq`: Moving data between general-purpose registers and XMM registers.
    * `vmovdqa`, `vmovdqu`: Moving aligned and unaligned packed integer data.
    * `vmovlps`, `vmovhps`: Moving lower and higher parts of XMM registers to/from memory.
    * `fma_instr`: Implementing Fused Multiply-Add instructions.
    * `sse_instr`, `sse2_instr`, `ssse3_instr`, `sse4_instr`, `sse4_2_instr`:  Implementing various SSE instruction set extensions.
    * `bmi1q`, `bmi2q`, `tzcntq`, `lzcntq`, `popcntq`, `rorxq`: Implementing Bit Manipulation Instructions (BMI).

8. **Relate to JavaScript (if applicable):**  Since the code is part of V8, the JavaScript engine, it's reasonable to consider how these low-level instructions might relate to JavaScript. JavaScript doesn't directly expose these instructions. However, V8's JIT compiler uses them to optimize JavaScript code execution, especially for number-intensive tasks or when dealing with typed arrays. Think of scenarios where JavaScript performs vector operations or bitwise manipulations.

9. **Consider Error Scenarios:**  The `DCHECK` statements are crucial. They point to potential programming errors, such as using instructions that require specific CPU features when those features are not available. Incorrect operand types or sizes could also be a problem.

10. **Synthesize a Summary:** Combine the observations into a concise description of the code's functionality. Highlight the key aspects: generating x64 machine code, supporting SIMD and other instruction set extensions, and its role in V8's code generation process.

11. **Address Specific Instructions:**  If prompted for examples, choose representative instructions and illustrate their use. For instance, `vmovd` for moving integer data, or `vaddps` (though not explicitly in the snippet, similar patterns exist) for vector addition.

12. **Final Review:** Read through the analysis to ensure clarity, accuracy, and completeness in addressing all aspects of the prompt. Make sure the explanation flows logically and is easy to understand.
好的，让我们来分析一下这段 `v8/src/codegen/x64/assembler-x64.cc` 的代码片段。

**功能列举:**

这段代码是 V8 JavaScript 引擎中 x64 架构的汇编器（Assembler）的一部分。它的主要功能是提供了一系列方法，用于生成 x64 架构的机器码指令。更具体地说，这段代码集中于支持以下方面的指令生成：

1. **AVX 和 AVX2 指令集:**  大量的函数以 `v` 开头，例如 `vbroadcastss`, `vinserti128`, `vperm2f128`, `vextractf128`, `vmovd`, `vmovq`, `vmovdqa`, `vmovdqu` 等。这些都属于高级向量扩展（Advanced Vector Extensions）指令集，允许对 128 位 (XMM) 或 256 位 (YMM) 寄存器中的多个数据同时进行操作。

2. **FMA (Fused Multiply-Add) 指令:** `fma_instr` 模板函数用于生成 FMA 指令，这是一种将乘法和加法运算融合在一起的指令，可以提高浮点运算的性能。

3. **SSE (Streaming SIMD Extensions) 指令:**  虽然 AVX 是重点，但代码中也包含了对 SSE 指令的支持，例如 `movups`, `sse_instr`, `sse2_instr`, `ssse3_instr`, `sse4_instr`, `sse4_2_instr`, `lddqu`, `movddup`, `movshdup`, `psrldq`, `pshufhw`, `pshuflw`, `pshufd` 等。SSE 是 AVX 的前身，也用于 SIMD 操作。

4. **BMI (Bit Manipulation Instructions) 指令:**  `bmi1q`, `bmi1l`, `tzcntq`, `tzcntl`, `lzcntq`, `lzcntl`, `popcntq`, `popcntl`, `bmi2q`, `bmi2l`, `rorxq`, `rorxl` 等函数用于生成 BMI 指令，用于高效地进行位操作。

5. **F16C (半精度浮点转换) 指令:** `vcvtph2ps` 和 `vcvtps2ph` 用于半精度（16 位）浮点数和单精度（32 位）浮点数之间的转换。

6. **VEX 前缀编码:** 代码中大量使用了 `emit_vex_prefix` 函数，这表明这段代码生成的指令主要采用 VEX 编码，这是 AVX 和更高版本指令使用的前缀编码方式。

7. **内存操作:**  可以看到一些 `vmov` 指令可以将数据从内存加载到寄存器，或者将寄存器中的数据存储到内存中。

8. **控制流指令:**  `pause` 指令用于优化自旋等待循环。

9. **辅助函数:**  例如 `emit_sse_operand` 用于生成 SSE 指令的操作数部分，`emit`, `emitl`, `emitq` 用于将字节、双字和四字数据写入到代码缓冲区。

**关于 .tq 结尾:**

如果 `v8/src/codegen/x64/assembler-x64.cc` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码**。Torque 是一种用于 V8 内部实现的领域特定语言，用于生成高效的 C++ 代码，包括汇编代码。然而，当前给出的代码片段是 `.cc` 结尾，表明它是直接编写的 C++ 代码。

**与 JavaScript 的关系和示例:**

这段汇编器代码是 V8 引擎将 JavaScript 代码编译成机器码的关键部分。当 V8 的即时编译器 (JIT) 需要生成执行 JavaScript 代码的机器指令时，它会使用像 `Assembler` 这样的类来完成。

**示例 (假设的 JavaScript 代码和可能的编译结果):**

假设有以下 JavaScript 代码：

```javascript
function addArrays(a, b) {
  const result = [];
  for (let i = 0; i < a.length; i++) {
    result.push(a[i] + b[i]);
  }
  return result;
}

const arr1 = [1.0, 2.0, 3.0, 4.0];
const arr2 = [5.0, 6.0, 7.0, 8.0];
const sum = addArrays(arr1, arr2);
console.log(sum); // 输出 [6, 8, 10, 12]
```

当 V8 编译 `addArrays` 函数时，它可能会使用这段汇编器中的指令来优化数组元素的加法操作。例如，对于处理 `arr1` 和 `arr2` 这样的浮点数数组，V8 可能会生成类似于以下的 x64 汇编指令（这只是一个简化的例子，实际情况更复杂）：

```assembly
  // 假设 a 的数据指针在寄存器 rdi，b 的数据指针在寄存器 rsi，结果数组指针在 rdx
  movups xmm0, [rdi]  // 将 a 的前 4 个单精度浮点数加载到 xmm0
  movups xmm1, [rsi]  // 将 b 的前 4 个单精度浮点数加载到 xmm1
  addps xmm0, xmm1   // 将 xmm0 和 xmm1 中的浮点数相加，结果存回 xmm0
  movups [rdx], xmm0  // 将 xmm0 中的结果存储到结果数组
  // ... 处理剩余的数组元素
```

在这个例子中，`movups` 和 `addps` 指令就可能由 `Assembler` 类中的相应方法生成。`movups` (Move Unaligned Packed Single-Precision Floating-Point Values) 对应 `Assembler::movups`，`addps` (Add Packed Single-Precision Floating-Point Values) 对应 `Assembler::vps` 的某种用法（或者 SSE 版本）。

**代码逻辑推理（假设输入与输出）:**

以 `Assembler::vbroadcastss(XMMRegister dst, XMMRegister src)` 为例：

**假设输入:**
* `dst`:  一个 `XMMRegister` 对象，例如 `xmm0`。
* `src`:  一个 `XMMRegister` 对象，例如 `xmm1`。

**可能的输出（生成的机器码片段）:**

假设 AVX2 指令的编码规则，生成的机器码可能类似于：

```
VEX.NDS.128.66.0F38.W0 18 /r
```

这会被编码成具体的字节序列，例如 `C4 E1 79 18 C1` (这只是一个例子，实际编码可能因寄存器而异)。这个字节序列表示将 `src` 寄存器（例如 `xmm1`）中的单精度浮点数广播到 `dst` 寄存器（例如 `xmm0`）的所有 4 个单精度浮点数槽位。

**用户常见的编程错误举例:**

在与这类底层代码交互时，用户通常不会直接编写或看到这些汇编指令。但是，如果 V8 的 JIT 编译器在生成代码时出现错误，可能会导致程序崩溃或产生意想不到的结果。

一个与 SIMD 指令相关的常见概念性错误是 **数据对齐问题**。例如，一些 SIMD 指令要求操作的内存地址是对齐到特定边界的（例如 16 字节对齐）。如果 JavaScript 代码操作的数据在内存中没有正确对齐，JIT 编译器生成的指令可能会导致错误（尽管 V8 通常会处理这些情况，但在某些极端情况下仍然可能出现问题）。

另一个错误是 **错误地假设 CPU 特性支持**。例如，如果 JavaScript 代码的执行路径导致 JIT 编译器生成了 AVX2 指令，但运行代码的 CPU 实际上不支持 AVX2，那么程序将会崩溃。V8 会尽量避免这种情况，但开发者需要了解目标运行环境的 CPU 能力。

**第 4 部分功能归纳:**

这段代码是 `v8/src/codegen/x64/assembler-x64.cc` 文件的 **一部分**，专注于实现 x64 架构汇编器的向量 (AVX, SSE) 指令、位操作 (BMI) 指令以及一些其他相关的指令生成功能。它提供了 C++ 接口，供 V8 的代码生成器使用，以将高级语言（如 JavaScript）编译成高效的本地机器码。这段代码的核心职责是将抽象的指令操作转化为具体的字节序列，这些字节序列可以被 x64 处理器执行。

总结来说，这段代码是 V8 引擎中一个关键的低级组件，负责将 JavaScript 代码高效地翻译成 x64 机器码，尤其侧重于利用现代 CPU 的 SIMD 和位操作能力来提升性能。

### 提示词
```
这是目录为v8/src/codegen/x64/assembler-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/x64/assembler-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
\
    emit_vex_prefix(dst, xmm0, src, k##length, k66, k0F38, kW0);          \
    emit(0x##opcode);                                                     \
    emit_sse_operand(dst, src);                                           \
  }                                                                       \
  void Assembler::vbroadcast##suffix(SIMDRegister dst, XMMRegister src) { \
    DCHECK(IsEnabled(AVX2));                                              \
    EnsureSpace ensure_space(this);                                       \
    emit_vex_prefix(dst, xmm0, src, k##length, k66, k0F38, kW0);          \
    emit(0x##opcode);                                                     \
    emit_sse_operand(dst, src);                                           \
  }
BROADCAST(ss, XMMRegister, L128, 18)
BROADCAST(ss, YMMRegister, L256, 18)
BROADCAST(sd, YMMRegister, L256, 19)
#undef BROADCAST

void Assembler::vinserti128(YMMRegister dst, YMMRegister src1, XMMRegister src2,
                            uint8_t imm8) {
  DCHECK(IsEnabled(AVX2));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL256, k66, k0F3A, kW0);
  emit(0x38);
  emit_sse_operand(dst, src2);
  emit(imm8);
}

void Assembler::vperm2f128(YMMRegister dst, YMMRegister src1, YMMRegister src2,
                           uint8_t imm8) {
  DCHECK(IsEnabled(AVX));
  DCHECK(is_uint8(imm8));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL256, k66, k0F3A, kW0);
  emit(0x06);
  emit_sse_operand(dst, src2);
  emit(imm8);
}

void Assembler::vextractf128(XMMRegister dst, YMMRegister src, uint8_t imm8) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src, xmm0, dst, kL256, k66, k0F3A, kW0);
  emit(0x19);
  emit_sse_operand(src, dst);
  emit(imm8);
}

template <typename Reg1, typename Reg2, typename Op>
void Assembler::fma_instr(uint8_t op, Reg1 dst, Reg2 src1, Op src2,
                          VectorLength l, SIMDPrefix pp, LeadingOpcode m,
                          VexW w) {
  DCHECK(IsEnabled(FMA3));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, l, pp, m, w);
  emit(op);
  emit_sse_operand(dst, src2);
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::fma_instr(
    uint8_t op, XMMRegister dst, XMMRegister src1, XMMRegister src2,
    VectorLength l, SIMDPrefix pp, LeadingOpcode m, VexW w);

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::fma_instr(
    uint8_t op, YMMRegister dst, YMMRegister src1, YMMRegister src2,
    VectorLength l, SIMDPrefix pp, LeadingOpcode m, VexW w);

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::fma_instr(
    uint8_t op, XMMRegister dst, XMMRegister src1, Operand src2, VectorLength l,
    SIMDPrefix pp, LeadingOpcode m, VexW w);

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::fma_instr(
    uint8_t op, YMMRegister dst, YMMRegister src1, Operand src2, VectorLength l,
    SIMDPrefix pp, LeadingOpcode m, VexW w);

void Assembler::vmovd(XMMRegister dst, Register src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  XMMRegister isrc = XMMRegister::from_code(src.code());
  emit_vex_prefix(dst, xmm0, isrc, kL128, k66, k0F, kW0);
  emit(0x6E);
  emit_sse_operand(dst, src);
}

void Assembler::vmovd(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, xmm0, src, kL128, k66, k0F, kW0);
  emit(0x6E);
  emit_sse_operand(dst, src);
}

void Assembler::vmovd(Register dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  XMMRegister idst = XMMRegister::from_code(dst.code());
  emit_vex_prefix(src, xmm0, idst, kL128, k66, k0F, kW0);
  emit(0x7E);
  emit_sse_operand(src, dst);
}

void Assembler::vmovq(XMMRegister dst, Register src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  XMMRegister isrc = XMMRegister::from_code(src.code());
  emit_vex_prefix(dst, xmm0, isrc, kL128, k66, k0F, kW1);
  emit(0x6E);
  emit_sse_operand(dst, src);
}

void Assembler::vmovq(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, xmm0, src, kL128, k66, k0F, kW1);
  emit(0x6E);
  emit_sse_operand(dst, src);
}

void Assembler::vmovq(Register dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  XMMRegister idst = XMMRegister::from_code(dst.code());
  emit_vex_prefix(src, xmm0, idst, kL128, k66, k0F, kW1);
  emit(0x7E);
  emit_sse_operand(src, dst);
}

void Assembler::vmovdqa(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, xmm0, src, kL128, k66, k0F, kWIG);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::vmovdqa(XMMRegister dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, xmm0, src, kL128, k66, k0F, kWIG);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::vmovdqa(YMMRegister dst, Operand src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, ymm0, src, kL256, k66, k0F, kWIG);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::vmovdqa(YMMRegister dst, YMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, ymm0, src, kL256, k66, k0F, kWIG);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::vmovdqu(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, xmm0, src, kL128, kF3, k0F, kWIG);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::vmovdqu(Operand dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src, xmm0, dst, kL128, kF3, k0F, kWIG);
  emit(0x7F);
  emit_sse_operand(src, dst);
}

void Assembler::vmovdqu(XMMRegister dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src, xmm0, dst, kL128, kF3, k0F, kWIG);
  emit(0x7F);
  emit_sse_operand(src, dst);
}

void Assembler::vmovdqu(YMMRegister dst, Operand src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, ymm0, src, kL256, kF3, k0F, kWIG);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::vmovdqu(Operand dst, YMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src, ymm0, dst, kL256, kF3, k0F, kWIG);
  emit(0x7F);
  emit_sse_operand(src, dst);
}

void Assembler::vmovdqu(YMMRegister dst, YMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src, ymm0, dst, kL256, kF3, k0F, kWIG);
  emit(0x7F);
  emit_sse_operand(src, dst);
}

void Assembler::vmovlps(XMMRegister dst, XMMRegister src1, Operand src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL128, kNoPrefix, k0F, kWIG);
  emit(0x12);
  emit_sse_operand(dst, src2);
}

void Assembler::vmovlps(Operand dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src, xmm0, dst, kL128, kNoPrefix, k0F, kWIG);
  emit(0x13);
  emit_sse_operand(src, dst);
}

void Assembler::vmovhps(XMMRegister dst, XMMRegister src1, Operand src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL128, kNoPrefix, k0F, kWIG);
  emit(0x16);
  emit_sse_operand(dst, src2);
}

void Assembler::vmovhps(Operand dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src, xmm0, dst, kL128, kNoPrefix, k0F, kWIG);
  emit(0x17);
  emit_sse_operand(src, dst);
}

void Assembler::vinstr(uint8_t op, XMMRegister dst, XMMRegister src1,
                       XMMRegister src2, SIMDPrefix pp, LeadingOpcode m, VexW w,
                       CpuFeature feature) {
  DCHECK(IsEnabled(feature));
  DCHECK(feature == AVX || feature == AVX2 || feature == AVX_VNNI ||
         feature == AVX_VNNI_INT8);
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kLIG, pp, m, w);
  emit(op);
  emit_sse_operand(dst, src2);
}

void Assembler::vinstr(uint8_t op, XMMRegister dst, XMMRegister src1,
                       Operand src2, SIMDPrefix pp, LeadingOpcode m, VexW w,
                       CpuFeature feature) {
  DCHECK(IsEnabled(feature));
  DCHECK(feature == AVX || feature == AVX2);
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kLIG, pp, m, w);
  emit(op);
  emit_sse_operand(dst, src2);
}

template <typename Reg1, typename Reg2, typename Op>
void Assembler::vinstr(uint8_t op, Reg1 dst, Reg2 src1, Op src2, SIMDPrefix pp,
                       LeadingOpcode m, VexW w, CpuFeature feature) {
  DCHECK(IsEnabled(feature));
  DCHECK(feature == AVX || feature == AVX2 || feature == AVX_VNNI ||
         feature == AVX_VNNI_INT8);
  DCHECK(
      (std::is_same_v<Reg1, YMMRegister> || std::is_same_v<Reg2, YMMRegister>));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL256, pp, m, w);
  emit(op);
  emit_sse_operand(dst, src2);
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::vinstr(
    uint8_t op, YMMRegister dst, YMMRegister src1, YMMRegister src2,
    SIMDPrefix pp, LeadingOpcode m, VexW w, CpuFeature feature);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::vinstr(
    uint8_t op, YMMRegister dst, XMMRegister src1, XMMRegister src2,
    SIMDPrefix pp, LeadingOpcode m, VexW w, CpuFeature feature);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::vinstr(
    uint8_t op, YMMRegister dst, YMMRegister src1, Operand src2, SIMDPrefix pp,
    LeadingOpcode m, VexW w, CpuFeature feature);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::vinstr(
    uint8_t op, YMMRegister dst, YMMRegister src1, XMMRegister src2,
    SIMDPrefix pp, LeadingOpcode m, VexW w, CpuFeature feature);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::vinstr(
    uint8_t op, YMMRegister dst, XMMRegister src1, Operand src2, SIMDPrefix pp,
    LeadingOpcode m, VexW w, CpuFeature feature);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::vinstr(
    uint8_t op, YMMRegister dst, XMMRegister src1, YMMRegister src2,
    SIMDPrefix pp, LeadingOpcode m, VexW w, CpuFeature feature);

void Assembler::vps(uint8_t op, XMMRegister dst, XMMRegister src1,
                    XMMRegister src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL128, kNoPrefix, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
}

void Assembler::vps(uint8_t op, YMMRegister dst, YMMRegister src1,
                    YMMRegister src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL256, kNoPrefix, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
}

void Assembler::vps(uint8_t op, XMMRegister dst, XMMRegister src1,
                    Operand src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL128, kNoPrefix, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
}

void Assembler::vps(uint8_t op, YMMRegister dst, YMMRegister src1,
                    Operand src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL256, kNoPrefix, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
}

void Assembler::vps(uint8_t op, XMMRegister dst, XMMRegister src1,
                    XMMRegister src2, uint8_t imm8) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL128, kNoPrefix, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
  emit(imm8);
}

void Assembler::vps(uint8_t op, YMMRegister dst, YMMRegister src1,
                    YMMRegister src2, uint8_t imm8) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL256, kNoPrefix, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
  emit(imm8);
}

#define VPD(DSTRegister, SRCRegister, length)                        \
  void Assembler::vpd(uint8_t op, DSTRegister dst, SRCRegister src1, \
                      SRCRegister src2) {                            \
    DCHECK(IsEnabled(AVX));                                          \
    EnsureSpace ensure_space(this);                                  \
    emit_vex_prefix(dst, src1, src2, k##length, k66, k0F, kWIG);     \
    emit(op);                                                        \
    emit_sse_operand(dst, src2);                                     \
  }                                                                  \
                                                                     \
  void Assembler::vpd(uint8_t op, DSTRegister dst, SRCRegister src1, \
                      Operand src2) {                                \
    DCHECK(IsEnabled(AVX));                                          \
    EnsureSpace ensure_space(this);                                  \
    emit_vex_prefix(dst, src1, src2, k##length, k66, k0F, kWIG);     \
    emit(op);                                                        \
    emit_sse_operand(dst, src2);                                     \
  }
VPD(XMMRegister, XMMRegister, L128)
VPD(XMMRegister, YMMRegister, L256)
VPD(YMMRegister, YMMRegister, L256)
#undef VPD

#define F16C(Dst, Src, Pref, Op, PP, Tmp)             \
  DCHECK(IsEnabled(F16C));                            \
  EnsureSpace ensure_space(this);                     \
  emit_vex_prefix(Dst, Tmp, Src, PP, k66, Pref, kW0); \
  emit(Op);                                           \
  emit_sse_operand(Dst, Src);

void Assembler::vcvtph2ps(XMMRegister dst, XMMRegister src) {
  F16C(dst, src, k0F38, 0x13, kLIG, xmm0);
}

void Assembler::vcvtph2ps(YMMRegister dst, XMMRegister src) {
  F16C(dst, src, k0F38, 0x13, kL256, ymm0);
}

void Assembler::vcvtps2ph(XMMRegister dst, YMMRegister src, uint8_t imm8) {
  F16C(src, dst, k0F3A, 0x1D, kL256, xmm0);
  emit(imm8);
}

void Assembler::vcvtps2ph(XMMRegister dst, XMMRegister src, uint8_t imm8) {
  F16C(src, dst, k0F3A, 0x1D, kLIG, ymm0);
  emit(imm8);
}

#undef F16C

void Assembler::vucomiss(XMMRegister dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, xmm0, src, kLIG, kNoPrefix, k0F, kWIG);
  emit(0x2E);
  emit_sse_operand(dst, src);
}

void Assembler::vucomiss(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, xmm0, src, kLIG, kNoPrefix, k0F, kWIG);
  emit(0x2E);
  emit_sse_operand(dst, src);
}

void Assembler::vpmovmskb(Register dst, XMMRegister src) {
  XMMRegister idst = XMMRegister::from_code(dst.code());
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(idst, xmm0, src, kL128, k66, k0F, kWIG);
  emit(0xD7);
  emit_sse_operand(idst, src);
}

void Assembler::vss(uint8_t op, XMMRegister dst, XMMRegister src1,
                    XMMRegister src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kLIG, kF3, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
}

void Assembler::vss(uint8_t op, XMMRegister dst, XMMRegister src1,
                    Operand src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kLIG, kF3, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
}

void Assembler::bmi1q(uint8_t op, Register reg, Register vreg, Register rm) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, kNoPrefix, k0F38, kW1);
  emit(op);
  emit_modrm(reg, rm);
}

void Assembler::bmi1q(uint8_t op, Register reg, Register vreg, Operand rm) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, kNoPrefix, k0F38, kW1);
  emit(op);
  emit_operand(reg, rm);
}

void Assembler::bmi1l(uint8_t op, Register reg, Register vreg, Register rm) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, kNoPrefix, k0F38, kW0);
  emit(op);
  emit_modrm(reg, rm);
}

void Assembler::bmi1l(uint8_t op, Register reg, Register vreg, Operand rm) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, kNoPrefix, k0F38, kW0);
  emit(op);
  emit_operand(reg, rm);
}

void Assembler::tzcntq(Register dst, Register src) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBC);
  emit_modrm(dst, src);
}

void Assembler::tzcntq(Register dst, Operand src) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBC);
  emit_operand(dst, src);
}

void Assembler::tzcntl(Register dst, Register src) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBC);
  emit_modrm(dst, src);
}

void Assembler::tzcntl(Register dst, Operand src) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBC);
  emit_operand(dst, src);
}

void Assembler::lzcntq(Register dst, Register src) {
  DCHECK(IsEnabled(LZCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBD);
  emit_modrm(dst, src);
}

void Assembler::lzcntq(Register dst, Operand src) {
  DCHECK(IsEnabled(LZCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBD);
  emit_operand(dst, src);
}

void Assembler::lzcntl(Register dst, Register src) {
  DCHECK(IsEnabled(LZCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBD);
  emit_modrm(dst, src);
}

void Assembler::lzcntl(Register dst, Operand src) {
  DCHECK(IsEnabled(LZCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBD);
  emit_operand(dst, src);
}

void Assembler::popcntq(Register dst, Register src) {
  DCHECK(IsEnabled(POPCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xB8);
  emit_modrm(dst, src);
}

void Assembler::popcntq(Register dst, Operand src) {
  DCHECK(IsEnabled(POPCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xB8);
  emit_operand(dst, src);
}

void Assembler::popcntl(Register dst, Register src) {
  DCHECK(IsEnabled(POPCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xB8);
  emit_modrm(dst, src);
}

void Assembler::popcntl(Register dst, Operand src) {
  DCHECK(IsEnabled(POPCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xB8);
  emit_operand(dst, src);
}

void Assembler::bmi2q(SIMDPrefix pp, uint8_t op, Register reg, Register vreg,
                      Register rm) {
  DCHECK(IsEnabled(BMI2));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, pp, k0F38, kW1);
  emit(op);
  emit_modrm(reg, rm);
}

void Assembler::bmi2q(SIMDPrefix pp, uint8_t op, Register reg, Register vreg,
                      Operand rm) {
  DCHECK(IsEnabled(BMI2));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, pp, k0F38, kW1);
  emit(op);
  emit_operand(reg, rm);
}

void Assembler::bmi2l(SIMDPrefix pp, uint8_t op, Register reg, Register vreg,
                      Register rm) {
  DCHECK(IsEnabled(BMI2));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, pp, k0F38, kW0);
  emit(op);
  emit_modrm(reg, rm);
}

void Assembler::bmi2l(SIMDPrefix pp, uint8_t op, Register reg, Register vreg,
                      Operand rm) {
  DCHECK(IsEnabled(BMI2));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, pp, k0F38, kW0);
  emit(op);
  emit_operand(reg, rm);
}

void Assembler::rorxq(Register dst, Register src, uint8_t imm8) {
  DCHECK(IsEnabled(BMI2));
  DCHECK(is_uint8(imm8));
  Register vreg = Register::from_code(0);  // VEX.vvvv unused
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, vreg, src, kLZ, kF2, k0F3A, kW1);
  emit(0xF0);
  emit_modrm(dst, src);
  emit(imm8);
}

void Assembler::rorxq(Register dst, Operand src, uint8_t imm8) {
  DCHECK(IsEnabled(BMI2));
  DCHECK(is_uint8(imm8));
  Register vreg = Register::from_code(0);  // VEX.vvvv unused
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, vreg, src, kLZ, kF2, k0F3A, kW1);
  emit(0xF0);
  emit_operand(dst, src);
  emit(imm8);
}

void Assembler::rorxl(Register dst, Register src, uint8_t imm8) {
  DCHECK(IsEnabled(BMI2));
  DCHECK(is_uint8(imm8));
  Register vreg = Register::from_code(0);  // VEX.vvvv unused
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, vreg, src, kLZ, kF2, k0F3A, kW0);
  emit(0xF0);
  emit_modrm(dst, src);
  emit(imm8);
}

void Assembler::rorxl(Register dst, Operand src, uint8_t imm8) {
  DCHECK(IsEnabled(BMI2));
  DCHECK(is_uint8(imm8));
  Register vreg = Register::from_code(0);  // VEX.vvvv unused
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, vreg, src, kLZ, kF2, k0F3A, kW0);
  emit(0xF0);
  emit_operand(dst, src);
  emit(imm8);
}

void Assembler::pause() {
  emit(0xF3);
  emit(0x90);
}

void Assembler::movups(XMMRegister dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  if (src.low_bits() == 4) {
    // Try to avoid an unnecessary SIB byte.
    emit_optional_rex_32(src, dst);
    emit(0x0F);
    emit(0x11);
    emit_sse_operand(src, dst);
  } else {
    emit_optional_rex_32(dst, src);
    emit(0x0F);
    emit(0x10);
    emit_sse_operand(dst, src);
  }
}

void Assembler::movups(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x10);
  emit_sse_operand(dst, src);
}

void Assembler::movups(Operand dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(src, dst);
  emit(0x0F);
  emit(0x11);
  emit_sse_operand(src, dst);
}

void Assembler::sse_instr(XMMRegister dst, XMMRegister src, uint8_t escape,
                          uint8_t opcode) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(escape);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse_instr(XMMRegister dst, Operand src, uint8_t escape,
                          uint8_t opcode) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(escape);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse2_instr(XMMRegister dst, XMMRegister src, uint8_t prefix,
                           uint8_t escape, uint8_t opcode) {
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse2_instr(XMMRegister dst, Operand src, uint8_t prefix,
                           uint8_t escape, uint8_t opcode) {
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::ssse3_instr(XMMRegister dst, XMMRegister src, uint8_t prefix,
                            uint8_t escape1, uint8_t escape2, uint8_t opcode) {
  DCHECK(IsEnabled(SSSE3));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::ssse3_instr(XMMRegister dst, Operand src, uint8_t prefix,
                            uint8_t escape1, uint8_t escape2, uint8_t opcode) {
  DCHECK(IsEnabled(SSSE3));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse4_instr(XMMRegister dst, Register src, uint8_t prefix,
                           uint8_t escape1, uint8_t escape2, uint8_t opcode,
                           int8_t imm8) {
  DCHECK(is_uint8(imm8));
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(dst, src);
  emit(imm8);
}

void Assembler::sse4_instr(XMMRegister dst, XMMRegister src, uint8_t prefix,
                           uint8_t escape1, uint8_t escape2, uint8_t opcode) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse4_instr(XMMRegister dst, Operand src, uint8_t prefix,
                           uint8_t escape1, uint8_t escape2, uint8_t opcode) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse4_instr(Register dst, XMMRegister src, uint8_t prefix,
                           uint8_t escape1, uint8_t escape2, uint8_t opcode,
                           int8_t imm8) {
  DCHECK(is_uint8(imm8));
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(src, dst);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(src, dst);
  emit(imm8);
}

void Assembler::sse4_instr(Operand dst, XMMRegister src, uint8_t prefix,
                           uint8_t escape1, uint8_t escape2, uint8_t opcode,
                           int8_t imm8) {
  DCHECK(is_uint8(imm8));
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(src, dst);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(src, dst);
  emit(imm8);
}

void Assembler::sse4_2_instr(XMMRegister dst, XMMRegister src, uint8_t prefix,
                             uint8_t escape1, uint8_t escape2, uint8_t opcode) {
  DCHECK(IsEnabled(SSE4_2));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse4_2_instr(XMMRegister dst, Operand src, uint8_t prefix,
                             uint8_t escape1, uint8_t escape2, uint8_t opcode) {
  DCHECK(IsEnabled(SSE4_2));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::lddqu(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xF0);
  emit_sse_operand(dst, src);
}

void Assembler::movddup(XMMRegister dst, XMMRegister src) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x12);
  emit_sse_operand(dst, src);
}

void Assembler::movddup(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x12);
  emit_sse_operand(dst, src);
}

void Assembler::movshdup(XMMRegister dst, XMMRegister src) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x16);
  emit_sse_operand(dst, src);
}

void Assembler::psrldq(XMMRegister dst, uint8_t shift) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst);
  emit(0x0F);
  emit(0x73);
  emit_sse_operand(dst);
  emit(shift);
}

void Assembler::pshufhw(XMMRegister dst, XMMRegister src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x70);
  emit_sse_operand(dst, src);
  emit(shuffle);
}

void Assembler::pshufhw(XMMRegister dst, Operand src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x70);
  emit_sse_operand(dst, src);
  emit(shuffle);
}

void Assembler::pshuflw(XMMRegister dst, XMMRegister src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x70);
  emit_sse_operand(dst, src);
  emit(shuffle);
}

void Assembler::pshuflw(XMMRegister dst, Operand src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x70);
  emit_sse_operand(dst, src);
  emit(shuffle);
}

void Assembler::pshufd(XMMRegister dst, XMMRegister src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x70);
  emit_sse_operand(dst, src);
  emit(shuffle);
}

void Assembler::pshufd(XMMRegister dst, Operand src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x70);
  emit_sse_operand(dst, src);
  emit(shuffle);
}

void Assembler::emit_sse_operand(XMMRegister reg, Operand adr) {
  Register ireg = Register::from_code(reg.code());
  emit_operand(ireg, adr);
}

void Assembler::emit_sse_operand(Register reg, Operand adr) {
  emit_operand(reg, adr);
}

void Assembler::emit_sse_operand(XMMRegister dst, XMMRegister src) {
  emit(0xC0 | (dst.low_bits() << 3) | src.low_bits());
}

void Assembler::emit_sse_operand(XMMRegister dst, Register src) {
  emit(0xC0 | (dst.low_bits() << 3) | src.low_bits());
}

void Assembler::emit_sse_operand(Register dst, XMMRegister src) {
  emit(0xC0 | (dst.low_bits() << 3) | src.low_bits());
}

void Assembler::emit_sse_operand(XMMRegister dst) {
  emit(0xD8 | dst.low_bits());
}

void Assembler::db(uint8_t data) {
  EnsureSpace ensure_space(this);
  emit(data);
}

void Assembler::dd(uint32_t data) {
  EnsureSpace ensure_space(this);
  emitl(data);
}

void Assembler::dq(uint64_t data) {
  EnsureSpace ensure_space(this);
  emitq(data);
}

void Assembler::dq(Label* label) {
  EnsureSpace ensure_space(this);
  if (label->is_bound()) {
    internal_reference_positions_.push_back(pc_offset());
    emit(Immediate64(reinterpret_cast<Address>(buffer_start_) + label->pos(),
                     RelocInfo::INTERNAL_REFERENCE));
  } else {
    RecordRelocInfo(RelocInfo::INTERNAL_REFERENCE);
    emitl(0);  // Zero for the first 32bit marks it as 64bit absolute address.
    if (label->is_linked()) {
      emitl(label->pos());
      label->link_to(pc_offset() - sizeof(int32_t));
    } else {
      DCHECK(label->is_unused());
      int32_t current = pc_offset();
      emitl(current);
      label->link_to(current);
    }
  }
}

void Assembler::WriteBuiltinJumpTableEntry(Label* label, int table_pos) {
  EnsureSpace ensure_space(this);
  CHECK(label->is_bound());
  int32_t value = label->pos() - table_pos;
  if constexpr (V8_BUILTIN_JUMP_TABLE_INFO_BOOL) {
    builtin_jump_table_info_writer_.Add(pc_offset(), label->pos());
  }
  emitl(value);
}

int Assembler::WriteBuiltinJumpTableInfos() {
  if (builtin_jump_table_info_writer_.entry_count() == 0) return 0;
  CHECK(V8_BUILTIN_JUMP_TABLE_INFO_BOOL);
  int offset = pc_offset();
  builtin_jump_table_info_writer_.Emit(this);
  int size = pc_offset() - offset;
  DCHECK_EQ(size, builtin_jump_table_info_writer_.size_in_bytes());
  return size;
}

// Relocation information implementations.

void Assembler::RecordRelocInfo(RelocInfo::Mode rmode, intptr_t data) {
  if (!ShouldRecordRelocInfo(rmode)) return;
  RelocInfo rinfo(reinterpret_cast<Address>(pc_), rmode, data);
  reloc_info_writer.Write(&rinfo);
}

const int RelocInfo::kApplyMask =
    RelocInfo::ModeMask(RelocInfo::CODE_TARGET) |
    RelocInfo::ModeMask(RelocInfo::NEAR_BUILTIN_ENTRY) |
    RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE) |
    RelocInfo::ModeMask(RelocInfo::WASM_CALL) |
    RelocInfo::ModeMask(RelocInfo::WASM_STUB_CALL);

bool RelocInfo::IsCodedSpecially() {
  // The deserializer needs to know whether a pointer is specially coded.  Being
  // specially coded on x64 means that it is a relative 32 bit address, as used
  // by branch instructions.
  return (1 << rmode_) & kApplyMask;
}

bool RelocInfo::IsInConstantPool() { return false; }

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_X64
```