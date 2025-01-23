Response: The user has provided the second part of a C++ source code file for the IA32 architecture's assembler within the V8 JavaScript engine. They are asking for a summary of its functionality and how it relates to JavaScript, including a JavaScript example if applicable.

**Part 1: Understanding the Code**

The code consists primarily of methods within the `Assembler` class. These methods correspond to specific IA32 assembly instructions, especially those related to SSE (Streaming SIMD Extensions) and AVX (Advanced Vector Extensions). Each method typically:

1. **`EnsureSpace`**: Checks if there's enough space in the internal buffer to emit the instruction. If not, it grows the buffer.
2. **`EMIT`**: Writes the raw byte representation of the opcode and operands into the buffer.
3. **`emit_sse_operand` / `emit_operand`**: Handles the encoding of operands (registers, memory addresses, immediate values).
4. **`emit_vex_prefix`**: Handles the encoding of VEX prefixes for AVX instructions.
5. **Relocation Handling**:  Includes mechanisms for recording relocation information needed when the generated code is moved in memory.

**Part 2: Connecting to JavaScript**

V8 uses this `Assembler` class to generate native machine code from the JavaScript code it compiles. When the JavaScript engine encounters operations that can be optimized using SIMD instructions (like vector or array operations), it uses these methods to emit the corresponding IA32 assembly code.

**Part 3: Crafting the Summary**

The summary should highlight that this part of the file focuses on SIMD and AVX instructions, explaining their purpose in optimizing numerical and data-parallel operations. The JavaScript example should illustrate a common scenario where these instructions would be utilized.

**Part 4: JavaScript Example (Mental Simulation)**

Consider JavaScript code that performs an element-wise addition of two large arrays. V8's optimizing compiler might recognize this pattern and use SSE/AVX instructions to perform multiple additions in parallel.

```javascript
const a = [1.0, 2.0, 3.0, 4.0];
const b = [5.0, 6.0, 7.0, 8.0];
const c = [];
for (let i = 0; i < a.length; i++) {
  c.push(a[i] + b[i]);
}
```

In the C++ code, a function like `Assembler::addps` (add packed single-precision floats) or its AVX counterpart `Assembler::vps` would be used to generate the actual machine code for this addition.

**Part 5: Refining the Summary and Example**

The summary should clearly state the connection between the C++ code and the generated machine code for JavaScript. The JavaScript example should be simple and illustrative.
这是 `v8/src/codegen/ia32/assembler-ia32.cc` 文件第二部分的代码，延续了第一部分的功能，主要负责 **定义 IA32 架构的汇编指令生成方法，特别是针对 SSE (Streaming SIMD Extensions) 和 AVX (Advanced Vector Extensions) 指令集的操作**。

具体来说，这部分代码实现了 `Assembler` 类中与以下操作相关的成员函数：

* **数据重排和混洗指令 (Shuffle and Blend):**  例如 `pshufd`, `pblendw`, `palignr`, `vshufps`, `vshufpd`, `vblendvps`, `vpblendw` 等，这些指令允许对 SIMD 寄存器中的数据元素进行重新排列、混合和选择。
* **数据提取和插入指令 (Extract and Insert):** 例如 `pextrb`, `pextrw`, `pextrd`, `insertps`, `pinsrb`, `pinsrw`, `pinsrd`, `vpextrb`, `vpinsrw` 等，这些指令允许从 SIMD 寄存器中提取单个数据元素到通用寄存器或内存，以及将数据从通用寄存器或内存插入到 SIMD 寄存器的特定位置。
* **单精度浮点运算指令 (Single-Precision Floating-Point):** 例如 `addss`, `subss`, `mulss`, `divss`, `sqrtss`, `ucomiss`, `maxss`, `minss` 等，这些指令对 SIMD 寄存器中的单个单精度浮点数进行算术和比较操作。
* **打包单精度和双精度浮点运算指令 (Packed Single/Double-Precision Floating-Point):** 例如 `ps`, `pd`, `vps`, `vpd`, `vcmpps`, `vcmppd` 等，这些指令可以同时对 SIMD 寄存器中的多个单精度或双精度浮点数进行操作。
* **AVX 指令 (Advanced Vector Extensions):** 以 `v` 开头的指令，例如 `vaddps`, `vmovaps`, `vpsllw` 等，是 AVX 指令集的实现，提供了更宽的寄存器和更灵活的操作。
* **位操作指令 (Bit Manipulation Instructions):** 例如 `tzcnt`, `lzcnt`, `popcnt`, `rorx` 等，这些指令用于执行位计数和旋转等操作。
* **掩码操作指令 (Mask Operations):** 例如 `vmovmskpd`, `vpmovmskb` 等，用于创建或使用掩码来控制 SIMD 操作。
* **舍入指令 (Rounding Instructions):** 例如 `vroundsd`, `vroundps` 等，用于控制浮点运算的舍入方式。

**与 JavaScript 的关系及示例**

这部分代码直接关系到 V8 JavaScript 引擎执行 JavaScript 代码的性能优化。当 JavaScript 代码中涉及到大量数值计算、数组操作或者需要并行处理的数据时，V8 的编译器会尝试将这些操作映射到高效的 SIMD 或 AVX 指令上。

例如，考虑以下 JavaScript 代码，它对两个数组进行元素级别的加法：

```javascript
const a = [1.0, 2.0, 3.0, 4.0];
const b = [5.0, 6.0, 7.0, 8.0];
const c = [];

for (let i = 0; i < a.length; i++) {
  c.push(a[i] + b[i]);
}

console.log(c); // 输出 [6, 8, 10, 12]
```

在 V8 引擎的底层，当这段代码被编译执行时，优化编译器可能会使用类似 `vaddps` (AVX packed single-precision add) 的指令来一次性处理多个元素的加法。  `Assembler::vps(0x58, ...)` 这个函数（其中 0x58 是 `vaddps` 的操作码）会被调用，生成对应的机器码。

再例如，考虑一个需要对数组元素进行混洗的操作，这可能在图形处理或其他数据转换场景中出现：

```javascript
const data = [1, 2, 3, 4];
// 假设我们想重新排列数组，例如 [3, 4, 1, 2]
// 这需要底层的 shuffle 操作
```

在 V8 内部，如果编译器识别到这种模式，可能会使用类似 `vpshufd` 指令及其对应的 `Assembler::vpshufd` 函数来生成高效的汇编代码，完成数据的重排。

**总结**

这部分 `assembler-ia32.cc` 代码是 V8 引擎将高级 JavaScript 代码转换为底层高效机器码的关键组成部分。 它专注于实现 SIMD 和 AVX 指令的生成，使得 JavaScript 引擎能够利用现代处理器提供的并行计算能力，显著提升数值计算和数据密集型 JavaScript 应用的性能。 这些指令对于优化诸如数组操作、图形处理、音视频处理等场景至关重要。

### 提示词
```
这是目录为v8/src/codegen/ia32/assembler-ia32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
```