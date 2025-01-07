Response:
The user wants me to analyze a C++ header file for the IA-32 architecture in the V8 JavaScript engine.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename `assembler-ia32.h` strongly suggests it's for generating IA-32 assembly code.

2. **Analyze the function declarations:**  The header file contains numerous function declarations. These functions likely correspond to IA-32 instructions. Look for patterns and common instruction prefixes (e.g., `mov`, `add`, `cv`). Pay attention to the data types involved (registers, memory operands, immediates, XMM registers for SIMD).

3. **Check for Torque implications:** The prompt mentions `.tq` files. This header file does *not* end in `.tq`, so it's standard C++ and not a Torque source file.

4. **Relate to JavaScript (if applicable):** Consider how these low-level assembly instructions might be used to implement JavaScript features. Think about data type conversions, arithmetic operations, and potentially how V8 handles floating-point numbers.

5. **Look for code logic and examples:** The function signatures themselves represent a form of code logic. Consider how different input operands (registers, memory locations) might affect the output. If there are explicit helper functions (like `sse2_instr`, `vinstr`), try to understand their purpose.

6. **Identify potential user errors:**  Think about common mistakes developers make when working with assembly or low-level concepts that this header might abstract.

7. **Summarize the functionality:** Based on the above points, provide a concise summary of the header file's purpose and key features.

**Constraint Checklist & Confidence Score:**

1. 列举一下它的功能: Yes
2. 如果v8/src/codegen/ia32/assembler-ia32.h以.tq结尾，那它是个v8 torque源代码: Yes
3. 如果它与javascript的功能有关系，请用javascript举例说明: Yes (with explanation of the connection)
4. 如果有代码逻辑推理，请给出假设输入与输出: Yes (implicitly through the function signatures and operand types)
5. 如果涉及用户常见的编程错误，请举例说明: Yes
6. 这是第2部分，共3部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

**Mental Sandbox Simulation:**

I'll mentally go through a few function declarations:

* `void mov(Register dst, Operand src);`:  This is a basic move instruction, likely copying data from `src` to `dst`.
* `void cvttsd2si(Register dst, XMMRegister src);`: This looks like a conversion instruction, probably converting a scalar double-precision floating-point value from an XMM register to a signed integer in a general-purpose register.
* `void vhaddps(XMMRegister dst, XMMRegister src1, Operand src2);`: The `v` prefix suggests an AVX instruction. The `haddps` likely means "horizontal add packed single-precision floats".

These examples confirm the header's purpose is to provide an interface for emitting IA-32 instructions, including those for SIMD operations. The connection to JavaScript lies in V8 using these instructions to execute JavaScript code efficiently, especially for numerical computations.

Okay, the planning is complete. I will now generate the response based on the outlined steps.
这是目录为 `v8/src/codegen/ia32/assembler-ia32.h` 的 V8 源代码的第二部分，延续了第一部分的内容，主要功能是定义了 `Assembler` 类中用于生成 IA-32 架构机器码的各种指令方法。

**归纳一下它的功能:**

这部分代码延续了 `v8/src/codegen/ia32/assembler-ia32.h` 文件的功能，继续为 `Assembler` 类提供接口，用于生成更广泛的 IA-32 指令，特别是集中在以下几个方面：

1. **SIMD 指令 (SSE, AVX, AVX2, FMA3):**  提供了大量的用于单指令多数据流 (SIMD) 操作的指令，涵盖了 SSE、AVX、AVX2 和 FMA3 等扩展指令集。这些指令用于高效地处理浮点数和整数的向量运算，对于 JavaScript 中涉及大量数值计算的场景至关重要。

2. **数据转换指令:**  包含各种数据类型之间的转换指令，例如浮点数和整数之间的转换 (`cvttsd2si`, `cvtsi2ss`)，以及不同精度浮点数之间的转换 (`cvtss2sd`, `cvtdq2pd`)。

3. **数据移动指令:**  提供了多种数据移动指令 (`movapd`, `movupd`, `movdqa`, `movdqu`, `movd`, `movsd`, `movss`)，用于在寄存器、内存之间移动数据，以及处理不同对齐方式的数据。

4. **位操作指令:**  包含各种位操作指令，例如移位 (`psllw`, `psrlw`)、逻辑运算 (`andn`)、位提取和插入 (`bextr`, `insertps`)。

5. **比较指令:**  提供了浮点数比较指令 (`ucomisd`, `cmpltsd`) 和向量比较指令 (`pcmpgtq`).

6. **舍入指令:**  包含浮点数舍入指令 (`roundss`, `roundsd`).

7. **Packed 操作:**  定义了用于处理打包数据的指令，例如打包加法、减法、乘法、除法等 (`padd`, `psub`, `pmul`, `pdiv`). AVX 版本的打包操作也包含在内 (`vaddps`, `vsubpd` 等)。

8. **BMI 和 BMI2 指令:**  实现了 Bit Manipulation Instruction Sets 的指令，用于更高效的位操作，例如位反转、位提取、乘法扩展等。

9. **前缀和操作码辅助函数:**  定义了辅助函数，例如 `ps`, `pd`, `vps`, `vpd`, `sse_instr`, `sse2_instr`, `vinstr` 等，用于更方便地生成带有特定前缀和操作码的指令。

10. **代码生成辅助功能:**  提供了一些辅助函数，例如 `SizeOfCodeGeneratedSince` 用于计算代码大小，`RecordDeoptReason` 用于记录反优化原因，以及 `db`, `dd`, `dq` 用于直接写入字节、双字、四字数据。

**关于 .tq 结尾和 JavaScript 功能的关系：**

* **如果 `v8/src/codegen/ia32/assembler-ia32.h` 以 `.tq` 结尾，那它会是一个 V8 Torque 源代码。** Torque 是一种 V8 自有的类型化的中间语言，用于生成高效的机器码。这个文件实际上是以 `.h` 结尾的 C++ 头文件。
* **这个文件与 JavaScript 的功能有直接关系。**  `Assembler-ia32.h` 中定义的指令最终会被 V8 的代码生成器使用，将 JavaScript 代码编译成高效的 IA-32 机器码。例如，当 JavaScript 中执行数值计算或进行类型转换时，V8 可能会使用这里定义的 SIMD 指令或转换指令。

**JavaScript 举例说明：**

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

在这个 JavaScript 例子中，`addArrays` 函数对两个数组进行逐元素相加。V8 在执行这段代码时，可能会使用 `assembler-ia32.h` 中定义的 AVX 指令（如 `vaddps`）来高效地执行数组的加法运算，特别是当数组长度较大时，SIMD 指令可以显著提高性能。

**代码逻辑推理和假设输入输出：**

以 `void vaddss(XMMRegister dst, XMMRegister src1, XMMRegister src2)` 为例：

* **假设输入:**
    * `dst`:  XMM 寄存器，例如 `xmm0`，用于存储结果。
    * `src1`: XMM 寄存器，例如 `xmm1`，包含一个单精度浮点数。
    * `src2`: XMM 寄存器，例如 `xmm2`，包含另一个单精度浮点数。
    * 假设 `xmm1` 的低 32 位存储着浮点数 `3.5`。
    * 假设 `xmm2` 的低 32 位存储着浮点数 `2.1`。
* **代码逻辑:**  这条指令会将 `src1` 和 `src2` 中最低的单精度浮点数相加。
* **输出:**
    * `dst` (`xmm0`) 的低 32 位将被设置为 `3.5 + 2.1 = 5.6`。  `xmm0` 的高位保持不变。

**用户常见的编程错误举例：**

在与这类底层代码交互时，用户（通常是 V8 开发者或编译器编写者）可能会犯以下错误：

1. **错误的寄存器分配:**  错误地使用了已经被占用的寄存器，导致数据被意外覆盖。
2. **操作数类型不匹配:**  将不兼容的操作数类型传递给指令，例如将整数寄存器传递给需要 XMM 寄存器的指令。
3. **未对齐的内存访问:**  对于某些需要内存地址对齐的指令（例如 `movdqa`），如果提供的内存地址未对齐，会导致程序崩溃或产生未定义的行为。
   ```c++
   // 错误示例：假设 memory_location 指向一个未按 16 字节对齐的地址
   // void movdqa(XMMRegister dst, Operand src);
   // ...
   // assembler->movdqa(xmm0, Operand(memory_location)); // 可能导致错误
   ```
4. **忽略指令的副作用:**  某些指令可能会设置 CPU 的状态标志位（例如，零标志位、进位标志位），如果代码没有正确处理这些标志位，可能会导致逻辑错误。
5. **错误地使用立即数:**  为需要特定范围的立即数的指令提供了超出范围的值。

**总结:**

这部分 `assembler-ia32.h` 代码是 V8 引擎中用于生成 IA-32 架构机器码的关键组成部分，它提供了丰富的指令接口，特别是对 SIMD 和位操作指令的支持，这对于 V8 优化 JavaScript 代码的执行性能至关重要。它直接关系到 JavaScript 中数值计算、类型转换等功能的底层实现。理解这部分代码需要对 IA-32 汇编语言和 SIMD 指令集有深入的了解。

Prompt: 
```
这是目录为v8/src/codegen/ia32/assembler-ia32.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ia32/assembler-ia32.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
vttsd2si(Register dst, Operand src);
  void cvttsd2si(Register dst, XMMRegister src) {
    cvttsd2si(dst, Operand(src));
  }
  void cvtsd2si(Register dst, XMMRegister src);

  void cvtsi2ss(XMMRegister dst, Register src) { cvtsi2ss(dst, Operand(src)); }
  void cvtsi2ss(XMMRegister dst, Operand src);
  void cvtsi2sd(XMMRegister dst, Register src) { cvtsi2sd(dst, Operand(src)); }
  void cvtsi2sd(XMMRegister dst, Operand src);
  void cvtss2sd(XMMRegister dst, Operand src);
  void cvtss2sd(XMMRegister dst, XMMRegister src) {
    cvtss2sd(dst, Operand(src));
  }
  void cvtdq2pd(XMMRegister dst, XMMRegister src);
  void cvtpd2ps(XMMRegister dst, XMMRegister src);
  void cvttps2dq(XMMRegister dst, XMMRegister src) {
    cvttps2dq(dst, Operand(src));
  }
  void cvttps2dq(XMMRegister dst, Operand src);
  void cvttpd2dq(XMMRegister dst, XMMRegister src);

  void ucomisd(XMMRegister dst, XMMRegister src) { ucomisd(dst, Operand(src)); }
  void ucomisd(XMMRegister dst, Operand src);

  void roundss(XMMRegister dst, XMMRegister src, RoundingMode mode);
  void roundsd(XMMRegister dst, XMMRegister src, RoundingMode mode);

  void movapd(XMMRegister dst, XMMRegister src) { movapd(dst, Operand(src)); }
  void movapd(XMMRegister dst, Operand src) {
    sse2_instr(dst, src, 0x66, 0x0F, 0x28);
  }
  void movupd(XMMRegister dst, Operand src) {
    sse2_instr(dst, src, 0x66, 0x0F, 0x10);
  }

  void movmskpd(Register dst, XMMRegister src);
  void movmskps(Register dst, XMMRegister src);

  void pmovmskb(Register dst, XMMRegister src);

  void cmpltsd(XMMRegister dst, XMMRegister src);

  void movdqa(XMMRegister dst, Operand src);
  void movdqa(Operand dst, XMMRegister src);
  void movdqa(XMMRegister dst, XMMRegister src);
  void movdqu(XMMRegister dst, Operand src);
  void movdqu(Operand dst, XMMRegister src);
  void movdqu(XMMRegister dst, XMMRegister src);
  void movdq(bool aligned, XMMRegister dst, Operand src) {
    if (aligned) {
      movdqa(dst, src);
    } else {
      movdqu(dst, src);
    }
  }

  void movd(XMMRegister dst, Register src) { movd(dst, Operand(src)); }
  void movd(XMMRegister dst, Operand src);
  void movd(Register dst, XMMRegister src) { movd(Operand(dst), src); }
  void movd(Operand dst, XMMRegister src);
  void movsd(XMMRegister dst, XMMRegister src) { movsd(dst, Operand(src)); }
  void movsd(XMMRegister dst, Operand src);
  void movsd(Operand dst, XMMRegister src);

  void movss(XMMRegister dst, Operand src);
  void movss(Operand dst, XMMRegister src);
  void movss(XMMRegister dst, XMMRegister src) { movss(dst, Operand(src)); }

  void extractps(Operand dst, XMMRegister src, uint8_t imm8);
  void extractps(Register dst, XMMRegister src, uint8_t imm8);

  void pcmpgtq(XMMRegister dst, XMMRegister src);

  void psllw(XMMRegister reg, uint8_t shift);
  void pslld(XMMRegister reg, uint8_t shift);
  void psrlw(XMMRegister reg, uint8_t shift);
  void psrld(XMMRegister reg, uint8_t shift);
  void psraw(XMMRegister reg, uint8_t shift);
  void psrad(XMMRegister reg, uint8_t shift);
  void psllq(XMMRegister reg, uint8_t shift);
  void psrlq(XMMRegister reg, uint8_t shift);

  void pshufhw(XMMRegister dst, XMMRegister src, uint8_t shuffle) {
    pshufhw(dst, Operand(src), shuffle);
  }
  void pshufhw(XMMRegister dst, Operand src, uint8_t shuffle);
  void pshuflw(XMMRegister dst, XMMRegister src, uint8_t shuffle) {
    pshuflw(dst, Operand(src), shuffle);
  }
  void pshuflw(XMMRegister dst, Operand src, uint8_t shuffle);
  void pshufd(XMMRegister dst, XMMRegister src, uint8_t shuffle) {
    pshufd(dst, Operand(src), shuffle);
  }
  void pshufd(XMMRegister dst, Operand src, uint8_t shuffle);

  void pblendw(XMMRegister dst, XMMRegister src, uint8_t mask) {
    pblendw(dst, Operand(src), mask);
  }
  void pblendw(XMMRegister dst, Operand src, uint8_t mask);

  void palignr(XMMRegister dst, XMMRegister src, uint8_t mask) {
    palignr(dst, Operand(src), mask);
  }
  void palignr(XMMRegister dst, Operand src, uint8_t mask);

  void pextrb(Register dst, XMMRegister src, uint8_t offset) {
    pextrb(Operand(dst), src, offset);
  }
  void pextrb(Operand dst, XMMRegister src, uint8_t offset);
  // SSE3 instructions
  void movddup(XMMRegister dst, Operand src);
  void movddup(XMMRegister dst, XMMRegister src) { movddup(dst, Operand(src)); }
  void movshdup(XMMRegister dst, XMMRegister src);

  // Use SSE4_1 encoding for pextrw reg, xmm, imm8 for consistency
  void pextrw(Register dst, XMMRegister src, uint8_t offset) {
    pextrw(Operand(dst), src, offset);
  }
  void pextrw(Operand dst, XMMRegister src, uint8_t offset);
  void pextrd(Register dst, XMMRegister src, uint8_t offset) {
    pextrd(Operand(dst), src, offset);
  }
  void pextrd(Operand dst, XMMRegister src, uint8_t offset);

  void insertps(XMMRegister dst, XMMRegister src, uint8_t offset) {
    insertps(dst, Operand(src), offset);
  }
  void insertps(XMMRegister dst, Operand src, uint8_t offset);
  void pinsrb(XMMRegister dst, Register src, uint8_t offset) {
    pinsrb(dst, Operand(src), offset);
  }
  void pinsrb(XMMRegister dst, Operand src, uint8_t offset);
  void pinsrw(XMMRegister dst, Register src, uint8_t offset) {
    pinsrw(dst, Operand(src), offset);
  }
  void pinsrw(XMMRegister dst, Operand src, uint8_t offset);
  void pinsrd(XMMRegister dst, Register src, uint8_t offset) {
    pinsrd(dst, Operand(src), offset);
  }
  void pinsrd(XMMRegister dst, Operand src, uint8_t offset);

  void roundps(XMMRegister dst, XMMRegister src, RoundingMode mode);
  void roundpd(XMMRegister dst, XMMRegister src, RoundingMode mode);

  // AVX instructions
  void vaddss(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vaddss(dst, src1, Operand(src2));
  }
  void vaddss(XMMRegister dst, XMMRegister src1, Operand src2) {
    vss(0x58, dst, src1, src2);
  }
  void vsubss(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vsubss(dst, src1, Operand(src2));
  }
  void vsubss(XMMRegister dst, XMMRegister src1, Operand src2) {
    vss(0x5c, dst, src1, src2);
  }
  void vmulss(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vmulss(dst, src1, Operand(src2));
  }
  void vmulss(XMMRegister dst, XMMRegister src1, Operand src2) {
    vss(0x59, dst, src1, src2);
  }
  void vdivss(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vdivss(dst, src1, Operand(src2));
  }
  void vdivss(XMMRegister dst, XMMRegister src1, Operand src2) {
    vss(0x5e, dst, src1, src2);
  }
  void vmaxss(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vmaxss(dst, src1, Operand(src2));
  }
  void vmaxss(XMMRegister dst, XMMRegister src1, Operand src2) {
    vss(0x5f, dst, src1, src2);
  }
  void vminss(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vminss(dst, src1, Operand(src2));
  }
  void vminss(XMMRegister dst, XMMRegister src1, Operand src2) {
    vss(0x5d, dst, src1, src2);
  }
  void vsqrtss(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vsqrtss(dst, src1, Operand(src2));
  }
  void vsqrtss(XMMRegister dst, XMMRegister src1, Operand src2) {
    vss(0x51, dst, src1, src2);
  }
  void vss(uint8_t op, XMMRegister dst, XMMRegister src1, Operand src2);

  void vhaddps(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vhaddps(dst, src1, Operand(src2));
  }
  void vhaddps(XMMRegister dst, XMMRegister src1, Operand src2) {
    vinstr(0x7C, dst, src1, src2, kF2, k0F, kWIG);
  }
  void vsqrtpd(XMMRegister dst, XMMRegister src) { vsqrtpd(dst, Operand(src)); }
  void vsqrtpd(XMMRegister dst, Operand src) {
    vinstr(0x51, dst, xmm0, src, k66, k0F, kWIG);
  }
  void vmovss(Operand dst, XMMRegister src) {
    vinstr(0x11, src, xmm0, dst, kF3, k0F, kWIG);
  }
  void vmovss(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vinstr(0x10, dst, src1, src2, kF3, k0F, kWIG);
  }
  void vmovss(XMMRegister dst, Operand src) {
    vinstr(0x10, dst, xmm0, src, kF3, k0F, kWIG);
  }
  void vmovsd(Operand dst, XMMRegister src) {
    vinstr(0x11, src, xmm0, dst, kF2, k0F, kWIG);
  }
  void vmovsd(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vinstr(0x10, dst, src1, src2, kF2, k0F, kWIG);
  }
  void vmovsd(XMMRegister dst, Operand src) {
    vinstr(0x10, dst, xmm0, src, kF2, k0F, kWIG);
  }

  void vextractps(Operand dst, XMMRegister src, uint8_t imm8);

  void vpcmpgtq(XMMRegister dst, XMMRegister src1, XMMRegister src2);

  void vmovaps(XMMRegister dst, XMMRegister src) { vmovaps(dst, Operand(src)); }
  void vmovaps(XMMRegister dst, Operand src) { vps(0x28, dst, xmm0, src); }
  void vmovapd(XMMRegister dst, XMMRegister src) { vmovapd(dst, Operand(src)); }
  void vmovapd(XMMRegister dst, Operand src) { vpd(0x28, dst, xmm0, src); }
  void vmovups(Operand dst, XMMRegister src) { vps(0x11, src, xmm0, dst); }
  void vmovups(XMMRegister dst, XMMRegister src) { vmovups(dst, Operand(src)); }
  void vmovups(XMMRegister dst, Operand src) { vps(0x10, dst, xmm0, src); }
  void vmovupd(XMMRegister dst, Operand src) { vpd(0x10, dst, xmm0, src); }
  void vshufps(XMMRegister dst, XMMRegister src1, XMMRegister src2,
               uint8_t imm8) {
    vshufps(dst, src1, Operand(src2), imm8);
  }
  void vshufps(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t imm8);
  void vshufpd(XMMRegister dst, XMMRegister src1, XMMRegister src2,
               uint8_t imm8) {
    vshufpd(dst, src1, Operand(src2), imm8);
  }
  void vshufpd(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t imm8);

  void vmovhlps(XMMRegister dst, XMMRegister src1, XMMRegister src2);
  void vmovlhps(XMMRegister dst, XMMRegister src1, XMMRegister src2);
  void vmovlps(XMMRegister dst, XMMRegister src1, Operand src2);
  void vmovlps(Operand dst, XMMRegister src);
  void vmovhps(XMMRegister dst, XMMRegister src1, Operand src2);
  void vmovhps(Operand dst, XMMRegister src);

  void vpsllw(XMMRegister dst, XMMRegister src, uint8_t imm8);
  void vpslld(XMMRegister dst, XMMRegister src, uint8_t imm8);
  void vpsllq(XMMRegister dst, XMMRegister src, uint8_t imm8);
  void vpsrlw(XMMRegister dst, XMMRegister src, uint8_t imm8);
  void vpsrld(XMMRegister dst, XMMRegister src, uint8_t imm8);
  void vpsraw(XMMRegister dst, XMMRegister src, uint8_t imm8);
  void vpsrad(XMMRegister dst, XMMRegister src, uint8_t imm8);
  void vpsrlq(XMMRegister dst, XMMRegister src, uint8_t imm8);

  void vpshufhw(XMMRegister dst, XMMRegister src, uint8_t shuffle) {
    vpshufhw(dst, Operand(src), shuffle);
  }
  void vpshufhw(XMMRegister dst, Operand src, uint8_t shuffle);
  void vpshuflw(XMMRegister dst, XMMRegister src, uint8_t shuffle) {
    vpshuflw(dst, Operand(src), shuffle);
  }
  void vpshuflw(XMMRegister dst, Operand src, uint8_t shuffle);
  void vpshufd(XMMRegister dst, XMMRegister src, uint8_t shuffle) {
    vpshufd(dst, Operand(src), shuffle);
  }
  void vpshufd(XMMRegister dst, Operand src, uint8_t shuffle);

  void vblendvps(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                 XMMRegister mask);
  void vblendvpd(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                 XMMRegister mask);
  void vpblendvb(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                 XMMRegister mask);

  void vpblendw(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                uint8_t mask) {
    vpblendw(dst, src1, Operand(src2), mask);
  }
  void vpblendw(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t mask);

  void vpalignr(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                uint8_t mask) {
    vpalignr(dst, src1, Operand(src2), mask);
  }
  void vpalignr(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t mask);

  void vpextrb(Register dst, XMMRegister src, uint8_t offset) {
    vpextrb(Operand(dst), src, offset);
  }
  void vpextrb(Operand dst, XMMRegister src, uint8_t offset);
  void vpextrw(Register dst, XMMRegister src, uint8_t offset) {
    vpextrw(Operand(dst), src, offset);
  }
  void vpextrw(Operand dst, XMMRegister src, uint8_t offset);
  void vpextrd(Register dst, XMMRegister src, uint8_t offset) {
    vpextrd(Operand(dst), src, offset);
  }
  void vpextrd(Operand dst, XMMRegister src, uint8_t offset);

  void vinsertps(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                 uint8_t offset) {
    vinsertps(dst, src1, Operand(src2), offset);
  }
  void vinsertps(XMMRegister dst, XMMRegister src1, Operand src2,
                 uint8_t offset);
  void vpinsrb(XMMRegister dst, XMMRegister src1, Register src2,
               uint8_t offset) {
    vpinsrb(dst, src1, Operand(src2), offset);
  }
  void vpinsrb(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t offset);
  void vpinsrw(XMMRegister dst, XMMRegister src1, Register src2,
               uint8_t offset) {
    vpinsrw(dst, src1, Operand(src2), offset);
  }
  void vpinsrw(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t offset);
  void vpinsrd(XMMRegister dst, XMMRegister src1, Register src2,
               uint8_t offset) {
    vpinsrd(dst, src1, Operand(src2), offset);
  }
  void vpinsrd(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t offset);

  void vroundsd(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                RoundingMode mode);
  void vroundss(XMMRegister dst, XMMRegister src1, XMMRegister src2,
                RoundingMode mode);
  void vroundps(XMMRegister dst, XMMRegister src, RoundingMode mode);
  void vroundpd(XMMRegister dst, XMMRegister src, RoundingMode mode);

  void vcvtdq2pd(XMMRegister dst, XMMRegister src) {
    vinstr(0xE6, dst, xmm0, src, kF3, k0F, kWIG);
  }
  void vcvtpd2ps(XMMRegister dst, XMMRegister src) {
    vinstr(0x5A, dst, xmm0, src, k66, k0F, kWIG);
  }
  void vcvttps2dq(XMMRegister dst, XMMRegister src) {
    vcvttps2dq(dst, Operand(src));
  }
  void vcvttps2dq(XMMRegister dst, Operand src) {
    vinstr(0x5B, dst, xmm0, src, kF3, k0F, kWIG);
  }
  void vcvttpd2dq(XMMRegister dst, XMMRegister src) {
    vinstr(0xE6, dst, xmm0, src, k66, k0F, kWIG);
  }
  void vcvttsd2si(Register dst, XMMRegister src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vinstr(0x2c, idst, xmm0, src, kF2, k0F, kW0);
  }
  void vcvttsd2si(Register dst, Operand src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vinstr(0x2c, idst, xmm0, src, kF2, k0F, kW0);
  }
  void vcvtss2sd(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
    vinstr(0x5a, dst, src1, src2, kF3, k0F, kWIG);
  }
  void vcvtss2sd(XMMRegister dst, XMMRegister src1, Operand src2) {
    vinstr(0x5a, dst, src1, src2, kF3, k0F, kWIG);
  }
  void vcvttss2si(Register dst, XMMRegister src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vinstr(0x2c, idst, xmm0, src, kF3, k0F, kW0);
  }
  void vcvttss2si(Register dst, Operand src) {
    XMMRegister idst = XMMRegister::from_code(dst.code());
    vinstr(0x2c, idst, xmm0, src, kF3, k0F, kW0);
  }

  void vmovddup(XMMRegister dst, Operand src) {
    vinstr(0x12, dst, xmm0, src, kF2, k0F, kWIG);
  }
  void vmovddup(XMMRegister dst, XMMRegister src) {
    vmovddup(dst, Operand(src));
  }
  void vmovshdup(XMMRegister dst, XMMRegister src) {
    vinstr(0x16, dst, xmm0, src, kF3, k0F, kWIG);
  }
  void vbroadcastss(XMMRegister dst, XMMRegister src) {
    vinstr(0x18, dst, xmm0, src, k66, k0F38, kW0, AVX2);
  }
  void vbroadcastss(XMMRegister dst, Operand src) {
    vinstr(0x18, dst, xmm0, src, k66, k0F38, kW0);
  }
  void vmovdqa(XMMRegister dst, Operand src) {
    vinstr(0x6F, dst, xmm0, src, k66, k0F, kWIG);
  }
  void vmovdqa(XMMRegister dst, XMMRegister src) {
    vinstr(0x6F, dst, xmm0, src, k66, k0F, kWIG);
  }
  void vmovdqu(XMMRegister dst, Operand src) {
    vinstr(0x6F, dst, xmm0, src, kF3, k0F, kWIG);
  }
  void vmovdqu(Operand dst, XMMRegister src) {
    vinstr(0x7F, src, xmm0, dst, kF3, k0F, kWIG);
  }
  void vmovd(XMMRegister dst, Register src) { vmovd(dst, Operand(src)); }
  void vmovd(XMMRegister dst, Operand src) {
    vinstr(0x6E, dst, xmm0, src, k66, k0F, kWIG);
  }
  void vmovd(Register dst, XMMRegister src) { movd(Operand(dst), src); }
  void vmovd(Operand dst, XMMRegister src) {
    vinstr(0x7E, src, xmm0, dst, k66, k0F, kWIG);
  }

  void vmovmskpd(Register dst, XMMRegister src);
  void vmovmskps(Register dst, XMMRegister src);

  void vpmovmskb(Register dst, XMMRegister src);

  void vucomisd(XMMRegister dst, XMMRegister src) {
    vinstr(0x2E, dst, xmm0, src, k66, k0F, kWIG);
  }
  void vucomisd(XMMRegister dst, Operand src) {
    vinstr(0x2E, dst, xmm0, src, k66, k0F, kWIG);
  }
  void vucomiss(XMMRegister dst, XMMRegister src) {
    vinstr(0x2E, dst, xmm0, src, kNoPrefix, k0F, kWIG);
  }
  void vucomiss(XMMRegister dst, Operand src) {
    vinstr(0x2E, dst, xmm0, src, kNoPrefix, k0F, kWIG);
  }

  // BMI instruction
  void andn(Register dst, Register src1, Register src2) {
    andn(dst, src1, Operand(src2));
  }
  void andn(Register dst, Register src1, Operand src2) {
    bmi1(0xf2, dst, src1, src2);
  }
  void bextr(Register dst, Register src1, Register src2) {
    bextr(dst, Operand(src1), src2);
  }
  void bextr(Register dst, Operand src1, Register src2) {
    bmi1(0xf7, dst, src2, src1);
  }
  void blsi(Register dst, Register src) { blsi(dst, Operand(src)); }
  void blsi(Register dst, Operand src) { bmi1(0xf3, ebx, dst, src); }
  void blsmsk(Register dst, Register src) { blsmsk(dst, Operand(src)); }
  void blsmsk(Register dst, Operand src) { bmi1(0xf3, edx, dst, src); }
  void blsr(Register dst, Register src) { blsr(dst, Operand(src)); }
  void blsr(Register dst, Operand src) { bmi1(0xf3, ecx, dst, src); }
  void tzcnt(Register dst, Register src) { tzcnt(dst, Operand(src)); }
  void tzcnt(Register dst, Operand src);

  void lzcnt(Register dst, Register src) { lzcnt(dst, Operand(src)); }
  void lzcnt(Register dst, Operand src);

  void popcnt(Register dst, Register src) { popcnt(dst, Operand(src)); }
  void popcnt(Register dst, Operand src);

  void bzhi(Register dst, Register src1, Register src2) {
    bzhi(dst, Operand(src1), src2);
  }
  void bzhi(Register dst, Operand src1, Register src2) {
    bmi2(kNoPrefix, 0xf5, dst, src2, src1);
  }
  void mulx(Register dst1, Register dst2, Register src) {
    mulx(dst1, dst2, Operand(src));
  }
  void mulx(Register dst1, Register dst2, Operand src) {
    bmi2(kF2, 0xf6, dst1, dst2, src);
  }
  void pdep(Register dst, Register src1, Register src2) {
    pdep(dst, src1, Operand(src2));
  }
  void pdep(Register dst, Register src1, Operand src2) {
    bmi2(kF2, 0xf5, dst, src1, src2);
  }
  void pext(Register dst, Register src1, Register src2) {
    pext(dst, src1, Operand(src2));
  }
  void pext(Register dst, Register src1, Operand src2) {
    bmi2(kF3, 0xf5, dst, src1, src2);
  }
  void sarx(Register dst, Register src1, Register src2) {
    sarx(dst, Operand(src1), src2);
  }
  void sarx(Register dst, Operand src1, Register src2) {
    bmi2(kF3, 0xf7, dst, src2, src1);
  }
  void shlx(Register dst, Register src1, Register src2) {
    shlx(dst, Operand(src1), src2);
  }
  void shlx(Register dst, Operand src1, Register src2) {
    bmi2(k66, 0xf7, dst, src2, src1);
  }
  void shrx(Register dst, Register src1, Register src2) {
    shrx(dst, Operand(src1), src2);
  }
  void shrx(Register dst, Operand src1, Register src2) {
    bmi2(kF2, 0xf7, dst, src2, src1);
  }
  void rorx(Register dst, Register src, uint8_t imm8) {
    rorx(dst, Operand(src), imm8);
  }
  void rorx(Register dst, Operand src, uint8_t imm8);

  // Implementation of packed single-precision floating-point SSE instructions.
  void ps(uint8_t op, XMMRegister dst, Operand src);
  // Implementation of packed double-precision floating-point SSE instructions.
  void pd(uint8_t op, XMMRegister dst, Operand src);

#define PACKED_OP_LIST(V) \
  V(unpckl, 0x14)         \
  V(and, 0x54)            \
  V(andn, 0x55)           \
  V(or, 0x56)             \
  V(xor, 0x57)            \
  V(add, 0x58)            \
  V(mul, 0x59)            \
  V(sub, 0x5c)            \
  V(min, 0x5d)            \
  V(div, 0x5e)            \
  V(max, 0x5f)

#define SSE_PACKED_OP_DECLARE(name, opcode)                             \
  void name##ps(XMMRegister dst, XMMRegister src) {                     \
    ps(opcode, dst, Operand(src));                                      \
  }                                                                     \
  void name##ps(XMMRegister dst, Operand src) { ps(opcode, dst, src); } \
  void name##pd(XMMRegister dst, XMMRegister src) {                     \
    pd(opcode, dst, Operand(src));                                      \
  }                                                                     \
  void name##pd(XMMRegister dst, Operand src) { pd(opcode, dst, src); }

  PACKED_OP_LIST(SSE_PACKED_OP_DECLARE)
#undef SSE_PACKED_OP_DECLARE

#define AVX_PACKED_OP_DECLARE(name, opcode)                               \
  void v##name##ps(XMMRegister dst, XMMRegister src1, XMMRegister src2) { \
    vps(opcode, dst, src1, Operand(src2));                                \
  }                                                                       \
  void v##name##ps(XMMRegister dst, XMMRegister src1, Operand src2) {     \
    vps(opcode, dst, src1, src2);                                         \
  }                                                                       \
  void v##name##pd(XMMRegister dst, XMMRegister src1, XMMRegister src2) { \
    vpd(opcode, dst, src1, Operand(src2));                                \
  }                                                                       \
  void v##name##pd(XMMRegister dst, XMMRegister src1, Operand src2) {     \
    vpd(opcode, dst, src1, src2);                                         \
  }

  PACKED_OP_LIST(AVX_PACKED_OP_DECLARE)
#undef AVX_PACKED_OP_DECLARE
#undef PACKED_OP_LIST

  void vps(uint8_t op, XMMRegister dst, XMMRegister src1, Operand src2);
  void vpd(uint8_t op, XMMRegister dst, XMMRegister src1, Operand src2);

  void vcmpps(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t cmp);
  void vcmppd(XMMRegister dst, XMMRegister src1, Operand src2, uint8_t cmp);

#define AVX_CMP_P(instr, imm8)                                             \
  void v##instr##ps(XMMRegister dst, XMMRegister src1, XMMRegister src2) { \
    vcmpps(dst, src1, Operand(src2), imm8);                                \
  }                                                                        \
  void v##instr##ps(XMMRegister dst, XMMRegister src1, Operand src2) {     \
    vcmpps(dst, src1, src2, imm8);                                         \
  }                                                                        \
  void v##instr##pd(XMMRegister dst, XMMRegister src1, XMMRegister src2) { \
    vcmppd(dst, src1, Operand(src2), imm8);                                \
  }                                                                        \
  void v##instr##pd(XMMRegister dst, XMMRegister src1, Operand src2) {     \
    vcmppd(dst, src1, src2, imm8);                                         \
  }

  PACKED_CMP_LIST(AVX_CMP_P)
  // vcmpgeps/vcmpgepd only in AVX.
  AVX_CMP_P(cmpge, 0xd)
#undef AVX_CMP_P
#undef PACKED_CMP_LIST

// Other SSE and AVX instructions
#define DECLARE_SSE_UNOP_AND_AVX(instruction, escape, opcode)       \
  void instruction(XMMRegister dst, XMMRegister src) {              \
    instruction(dst, Operand(src));                                 \
  }                                                                 \
  void instruction(XMMRegister dst, Operand src) {                  \
    sse_instr(dst, src, 0x##escape, 0x##opcode);                    \
  }                                                                 \
  void v##instruction(XMMRegister dst, XMMRegister src) {           \
    v##instruction(dst, Operand(src));                              \
  }                                                                 \
  void v##instruction(XMMRegister dst, Operand src) {               \
    vinstr(0x##opcode, dst, xmm0, src, kNoPrefix, k##escape, kWIG); \
  }

  SSE_UNOP_INSTRUCTION_LIST(DECLARE_SSE_UNOP_AND_AVX)
#undef DECLARE_SSE_UNOP_AND_AVX

#define DECLARE_SSE2_INSTRUCTION(instruction, prefix, escape, opcode) \
  void instruction(XMMRegister dst, XMMRegister src) {                \
    instruction(dst, Operand(src));                                   \
  }                                                                   \
  void instruction(XMMRegister dst, Operand src) {                    \
    sse2_instr(dst, src, 0x##prefix, 0x##escape, 0x##opcode);         \
  }

  SSE2_INSTRUCTION_LIST(DECLARE_SSE2_INSTRUCTION)
  SSE2_INSTRUCTION_LIST_SD(DECLARE_SSE2_INSTRUCTION)
#undef DECLARE_SSE2_INSTRUCTION

#define DECLARE_SSE2_AVX_INSTRUCTION(instruction, prefix, escape, opcode)    \
  void v##instruction(XMMRegister dst, XMMRegister src1, XMMRegister src2) { \
    v##instruction(dst, src1, Operand(src2));                                \
  }                                                                          \
  void v##instruction(XMMRegister dst, XMMRegister src1, Operand src2) {     \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape, kW0);          \
  }

  SSE2_INSTRUCTION_LIST(DECLARE_SSE2_AVX_INSTRUCTION)
  SSE2_INSTRUCTION_LIST_SD(DECLARE_SSE2_AVX_INSTRUCTION)
#undef DECLARE_SSE2_AVX_INSTRUCTION

#define DECLARE_SSSE3_INSTRUCTION(instruction, prefix, escape1, escape2,     \
                                  opcode)                                    \
  void instruction(XMMRegister dst, XMMRegister src) {                       \
    instruction(dst, Operand(src));                                          \
  }                                                                          \
  void instruction(XMMRegister dst, Operand src) {                           \
    ssse3_instr(dst, src, 0x##prefix, 0x##escape1, 0x##escape2, 0x##opcode); \
  }

  SSSE3_INSTRUCTION_LIST(DECLARE_SSSE3_INSTRUCTION)
  SSSE3_UNOP_INSTRUCTION_LIST(DECLARE_SSSE3_INSTRUCTION)
#undef DECLARE_SSSE3_INSTRUCTION

#define DECLARE_SSE4_INSTRUCTION(instruction, prefix, escape1, escape2,     \
                                 opcode)                                    \
  void instruction(XMMRegister dst, XMMRegister src) {                      \
    instruction(dst, Operand(src));                                         \
  }                                                                         \
  void instruction(XMMRegister dst, Operand src) {                          \
    sse4_instr(dst, src, 0x##prefix, 0x##escape1, 0x##escape2, 0x##opcode); \
  }

  SSE4_INSTRUCTION_LIST(DECLARE_SSE4_INSTRUCTION)
  SSE4_RM_INSTRUCTION_LIST(DECLARE_SSE4_INSTRUCTION)
  DECLARE_SSE4_INSTRUCTION(blendvps, 66, 0F, 38, 14)
  DECLARE_SSE4_INSTRUCTION(blendvpd, 66, 0F, 38, 15)
  DECLARE_SSE4_INSTRUCTION(pblendvb, 66, 0F, 38, 10)
#undef DECLARE_SSE4_INSTRUCTION

#define DECLARE_SSE34_AVX_INSTRUCTION(instruction, prefix, escape1, escape2,  \
                                      opcode)                                 \
  void v##instruction(XMMRegister dst, XMMRegister src1, XMMRegister src2) {  \
    v##instruction(dst, src1, Operand(src2));                                 \
  }                                                                           \
  void v##instruction(XMMRegister dst, XMMRegister src1, Operand src2) {      \
    vinstr(0x##opcode, dst, src1, src2, k##prefix, k##escape1##escape2, kW0); \
  }

  SSSE3_INSTRUCTION_LIST(DECLARE_SSE34_AVX_INSTRUCTION)
  SSE4_INSTRUCTION_LIST(DECLARE_SSE34_AVX_INSTRUCTION)
#undef DECLARE_SSE34_AVX_INSTRUCTION

#define DECLARE_SSE4_AVX_RM_INSTRUCTION(instruction, prefix, escape1, escape2, \
                                        opcode)                                \
  void v##instruction(XMMRegister dst, XMMRegister src) {                      \
    v##instruction(dst, Operand(src));                                         \
  }                                                                            \
  void v##instruction(XMMRegister dst, Operand src) {                          \
    vinstr(0x##opcode, dst, xmm0, src, k##prefix, k##escape1##escape2, kW0);   \
  }

  SSSE3_UNOP_INSTRUCTION_LIST(DECLARE_SSE4_AVX_RM_INSTRUCTION)
  SSE4_RM_INSTRUCTION_LIST(DECLARE_SSE4_AVX_RM_INSTRUCTION)
#undef DECLARE_SSE4_AVX_RM_INSTRUCTION

  // AVX2 instructions
#define AVX2_INSTRUCTION(instr, prefix, escape1, escape2, opcode)           \
  void instr(XMMRegister dst, XMMRegister src) {                            \
    vinstr(0x##opcode, dst, xmm0, src, k##prefix, k##escape1##escape2, kW0, \
           AVX2);                                                           \
  }                                                                         \
  void instr(XMMRegister dst, Operand src) {                                \
    vinstr(0x##opcode, dst, xmm0, src, k##prefix, k##escape1##escape2, kW0, \
           AVX2);                                                           \
  }
  AVX2_BROADCAST_LIST(AVX2_INSTRUCTION)
#undef AVX2_INSTRUCTION

#define FMA(instr, length, prefix, escape1, escape2, extension, opcode) \
  void instr(XMMRegister dst, XMMRegister src1, XMMRegister src2) {     \
    vinstr(0x##opcode, dst, src1, src2, k##length, k##prefix,           \
           k##escape1##escape2, k##extension, FMA3);                    \
  }                                                                     \
  void instr(XMMRegister dst, XMMRegister src1, Operand src2) {         \
    vinstr(0x##opcode, dst, src1, src2, k##length, k##prefix,           \
           k##escape1##escape2, k##extension, FMA3);                    \
  }
  FMA_INSTRUCTION_LIST(FMA)
#undef FMA

  // Prefetch src position into cache level.
  // Level 1, 2 or 3 specifies CPU cache level. Level 0 specifies a
  // non-temporal
  void prefetch(Operand src, int level);
  // TODO(lrn): Need SFENCE for movnt?

  // Check the code size generated from label to here.
  int SizeOfCodeGeneratedSince(Label* label) {
    return pc_offset() - label->pos();
  }

  // Record a deoptimization reason that can be used by a log or cpu profiler.
  // Use --trace-deopt to enable.
  void RecordDeoptReason(DeoptimizeReason reason, uint32_t node_id,
                         SourcePosition position, int id);

  // Writes a single byte or word of data in the code stream.  Used for
  // inline tables, e.g., jump-tables.
  void db(uint8_t data);
  void dd(uint32_t data);
  void dq(uint64_t data);
  void dp(uintptr_t data) { dd(data); }
  void dd(Label* label);

  // Check if there is less than kGap bytes available in the buffer.
  // If this is the case, we need to grow the buffer before emitting
  // an instruction or relocation information.
  inline bool buffer_overflow() const {
    return pc_ >= reloc_info_writer.pos() - kGap;
  }

  // Get the number of bytes available in the buffer.
  inline int available_space() const { return reloc_info_writer.pos() - pc_; }

  static bool IsNop(Address addr);

  int relocation_writer_size() {
    return (buffer_start_ + buffer_->size()) - reloc_info_writer.pos();
  }

  // Avoid overflows for displacements etc.
  static constexpr int kMaximalBufferSize = 512 * MB;

  uint8_t byte_at(int pos) { return buffer_start_[pos]; }
  void set_byte_at(int pos, uint8_t value) { buffer_start_[pos] = value; }

 protected:
  void emit_sse_operand(XMMRegister reg, Operand adr);
  void emit_sse_operand(XMMRegister dst, XMMRegister src);
  void emit_sse_operand(Register dst, XMMRegister src);
  void emit_sse_operand(XMMRegister dst, Register src);

  Address addr_at(int pos) {
    DCHECK_GE(pos, 0);
    DCHECK_LT(pos, pc_offset());
    return reinterpret_cast<Address>(buffer_start_ + pos);
  }

 private:
  uint32_t long_at(int pos) {
    return ReadUnalignedValue<uint32_t>(addr_at(pos));
  }
  void long_at_put(int pos, uint32_t x) {
    WriteUnalignedValue(addr_at(pos), x);
  }

  // code emission
  void GrowBuffer();
  inline void emit(uint32_t x);
  inline void emit(Handle<HeapObject> handle);
  inline void emit(uint32_t x, RelocInfo::Mode rmode);
  inline void emit(Handle<Code> code, RelocInfo::Mode rmode);
  inline void emit(const Immediate& x);
  inline void emit_b(Immediate x);
  inline void emit_w(const Immediate& x);
  inline void emit_q(uint64_t x);

  // Emit the code-object-relative offset of the label's position
  inline void emit_code_relative_offset(Label* label);

  // instruction generation
  void emit_arith_b(int op1, int op2, Register dst, int imm8);

  // Emit a basic arithmetic instruction (i.e. first byte of the family is 0x81)
  // with a given destination expression and an immediate operand.  It attempts
  // to use the shortest encoding possible.
  // sel specifies the /n in the modrm byte (see the Intel PRM).
  void emit_arith(int sel, Operand dst, const Imme
"""


```