Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine's ARM code generator.

Here's a breakdown of the thought process:

1. **Identify the Language and Context:** The code is C++, and the comment at the beginning explicitly states it's from `v8/src/codegen/arm/assembler-arm.cc`. This immediately tells me it's related to generating ARM assembly code within the V8 engine.

2. **Recognize the Core Class:** The code heavily uses the `Assembler` class. This class is central to the code generation process, providing methods to emit ARM instructions.

3. **Analyze the Function Names and Structures:**  The functions have names like `vmrs`, `vrinta`, `vld1`, `vst1`, `vmovl`, `vqmovn`, `vmov`, `vdup`, `vcvt_f32_s32`, `vmvn`, `vswp`, `vabs`, `vneg`, `vand`, `vbic`, `vbsl`, `veor`, `vorr`, `vorn`, `vadd`, `vsub`, `vmul`, `vmin`, `vmax`. Many of these names are prefixed with 'v', which strongly suggests they are related to Vector/SIMD (Single Instruction, Multiple Data) operations, specifically for ARM's NEON instruction set. The suffixes often indicate data types (e.g., `_f32_s32` for float to integer conversion) or operations (e.g., `l` for long, `n` for narrow).

4. **Look for Clues in the Comments:** The comments within each function are crucial. They often provide:
    * The specific ARM instruction being implemented (e.g., "Instruction details available in ARM DDI...").
    * The ARM instruction encoding in binary format.
    * Explanations of the instruction's purpose.

5. **Categorize the Functionality:** Based on the function names and comments, the code can be broadly categorized into:
    * **VFP (Vector Floating Point) Instructions:** Functions like `vmrs` and the `vrint` series deal with transferring data between VFP registers and the ARM core, and rounding operations on floating-point numbers.
    * **NEON Instructions:**  The majority of the functions (prefixed with 'v' and dealing with `NeonSize`, `NeonListOperand`, `NeonMemOperand`, `QwNeonRegister`, `DwVfpRegister`) are related to NEON, ARM's Advanced SIMD extension. These cover:
        * **Data Loading and Storing:** `vld1`, `vst1`, `vld1s`, `vld1r`.
        * **Data Movement and Duplication:** `vmovl`, `vqmovn`, `vmov`, `vdup`.
        * **Data Type Conversion:** `vcvt_f32_s32`, `vcvt_s32_f32`, etc.
        * **Unary Operations:** `vmvn`, `vswp`, `vabs`, `vneg`.
        * **Binary Bitwise Operations:** `vand`, `vbic`, `vbsl`, `veor`, `vorr`, `vorn`.
        * **Binary Floating-Point Operations:** `vadd`, `vsub`, `vmul`, `vmin`, `vmax`.
        * **Binary Integer Operations:** `vadd`, `vqadd`, `vsub`, `vqsub`, `vmul`, `vmin`, `vmax`.
        * **Shift Operations:** (Although the snippet ends before showcasing many shift operations, the naming convention and structure suggest their presence in the full file).

6. **Address Specific User Queries:**
    * **`.tq` Extension:** The code is `.cc`, so it's C++ source, not Torque.
    * **Relationship to JavaScript:**  NEON instructions are often used to optimize performance-critical parts of JavaScript execution, particularly those dealing with numerical computations, array processing, or graphics.
    * **JavaScript Examples:**  Think about common JavaScript operations that could benefit from SIMD:  array manipulations (mapping, filtering), image processing (pixel manipulation), mathematical calculations on large datasets.
    * **Code Logic and Assumptions:**  The code often makes assertions (`DCHECK`) about the validity of input parameters (e.g., register types, sizes, enabling of specific ARM features). The output is the emission of the corresponding ARM instruction's binary encoding.
    * **Common Programming Errors:**  Incorrect register usage, providing wrong data types, using instructions not supported by the target architecture, or misinterpreting the bit encoding of instructions are potential errors.

7. **Synthesize the Summary:** Combine the identified functionalities into a concise summary, emphasizing the core purpose of generating ARM assembly code, particularly for VFP and NEON instructions, to optimize JavaScript execution.

8. **Self-Correction/Refinement:** Initially, I might have focused too much on individual instruction encodings. The key is to abstract that detail and focus on the *types* of operations the code enables. Recognizing the pattern of VFP and NEON instructions is essential for a good summary. Also, remembering the context of V8 and JavaScript performance is important for connecting the code to its higher-level purpose.
这是目录为 `v8/src/codegen/arm/assembler-arm.cc` 的一个 V8 源代码片段，它是一个 **C++** 文件，而不是 Torque (`.tq`) 文件。

**功能归纳:**

这个代码片段定义了 `Assembler` 类中用于生成 ARM 汇编指令的方法。具体来说，它涵盖了以下几个主要功能：

1. **VFP (Vector Floating Point) 指令生成:**  包含生成 VFP 指令的方法，例如 `vmrs`（将 VFP 状态寄存器移动到 ARM 核心寄存器）和各种 `vrint` 开头的指令，这些指令用于浮点数的舍入操作 (如 `vrinta`, `vrintn`, `vrintp`, `vrintm`, `vrintz`)，支持单精度 (`SwVfpRegister`) 和双精度 (`DwVfpRegister`) 浮点寄存器。

2. **NEON (Advanced SIMD) 指令生成:**  包含生成 NEON SIMD 指令的方法，这些指令用于并行处理向量数据，显著提升性能。  这些指令可以进一步细分为：
    * **加载和存储指令:** `vld1`（加载数据到 NEON 寄存器）， `vst1`（存储 NEON 寄存器数据）。包括加载单个元素到所有通道 (`vld1r`) 或特定通道 (`vld1s`).
    * **数据移动和转换指令:** `vmovl` (窄数据移动到宽数据)，`vqmovn` (带饱和的窄化移动)， `vmov` (在 NEON 寄存器和 ARM 核心寄存器之间移动数据)。
    * **数据复制指令:** `vdup` (将标量值复制到 NEON 向量的所有通道，支持从 ARM 寄存器或另一个 NEON 寄存器的指定元素复制)。
    * **数据类型转换指令:** `vcvt_f32_s32`, `vcvt_f32_u32`, `vcvt_s32_f32`, `vcvt_u32_f32` (浮点数和整数之间的转换)。
    * **一元运算指令:** `vmvn` (按位取反)， `vswp` (交换寄存器内容)， `vabs` (绝对值)， `vneg` (取负)。
    * **二元按位运算指令:** `vand` (按位与)， `vbic` (按位清除)， `vbsl` (按位选择)， `veor` (按位异或)， `vorr` (按位或)， `vorn` (按位或非)。
    * **二元浮点运算指令:** `vadd` (加法)， `vsub` (减法)， `vmul` (乘法)， `vmin` (最小值)， `vmax` (最大值)。
    * **二元整数运算指令:**  `vadd`, `vqadd` (饱和加法)， `vsub`, `vqsub` (饱和减法)， `vmul`, `vmin`, `vmax`, `vtst` (位测试)， `vceq` (相等比较)， `vcge` (大于等于比较)， `vcgt` (大于比较)， `vrhadd` (舍入加法)， `vqdmulh` (饱和倍增高半部分)。
    * **移位操作指令:** (代码片段末尾开始涉及移位操作，但未完整展示)。

3. **指令编码细节:** 代码中直接操作二进制位来构建 ARM 指令，这反映了汇编器的工作原理。每一条指令的生成都对应着特定的二进制编码格式，注释中也详细列出了这些编码。

**与 JavaScript 的关系及示例:**

`v8/src/codegen/arm/assembler-arm.cc` 中生成的汇编代码是 V8 引擎执行 JavaScript 代码的基础。当 V8 的编译器（如 Crankshaft 或 TurboFan）需要将 JavaScript 代码编译成本地 ARM 机器码时，就会使用 `Assembler` 类来生成这些指令。

**JavaScript 示例:**

例如，以下 JavaScript 代码中的数值计算可以被 V8 编译成使用 NEON 指令进行优化的 ARM 汇编代码：

```javascript
function addArrays(a, b) {
  const result = [];
  for (let i = 0; i < a.length; i++) {
    result.push(a[i] + b[i]);
  }
  return result;
}

const array1 = [1.0, 2.0, 3.0, 4.0];
const array2 = [5.0, 6.0, 7.0, 8.0];
const sum = addArrays(array1, array2);
console.log(sum); // 输出 [6, 8, 10, 12]
```

在 ARM 架构上，V8 可能会将 `addArrays` 函数中的循环编译成使用 NEON 的 `vadd` 指令，一次性处理多个数组元素的加法，从而显著提升性能。

**代码逻辑推理与假设输入输出:**

以 `Assembler::vadd(QwNeonRegister dst, QwNeonRegister src1, QwNeonRegister src2)` 函数为例：

**假设输入:**
* `dst`:  一个 `QwNeonRegister` 对象，例如 `q0` (代表 NEON 寄存器 Q0)。
* `src1`: 一个 `QwNeonRegister` 对象，例如 `q1`。
* `src2`: 一个 `QwNeonRegister` 对象，例如 `q2`。

**代码逻辑:**
该函数会根据 `VADDF` 操作的指令编码格式，将 `q1` 和 `q2` 中的浮点数向量相加，并将结果存储到 `q0`。函数内部会提取寄存器编号，并按照 ARM 指令的二进制格式进行组装。

**输出:**
该函数会向 `Assembler` 的内部缓冲区（用于存储生成的机器码）中写入表示 `vadd q0, q1, q2` 指令的 32 位二进制编码。这个编码是根据 `EncodeNeonBinOp(VADDF, dst, src1, src2)` 函数计算出来的。

**用户常见的编程错误示例:**

在手动编写 ARM 汇编代码时，常见的错误包括：

1. **寄存器类型不匹配:** 例如，尝试将单精度浮点数加载到双精度寄存器，或者在需要 NEON 寄存器的地方使用了通用寄存器。
2. **指令参数顺序错误:** ARM 指令的参数顺序是固定的，弄错顺序会导致指令无法正确执行或被识别。
3. **条件码使用错误:**  某些指令可以带条件码执行，如果条件码设置不当，指令可能不会执行。
4. **立即数范围超出:**  某些指令的立即数有范围限制，超出范围会导致编译错误或运行时错误。
5. **内存访问错误:**  例如，访问未对齐的内存地址，或者访问了没有访问权限的内存区域。

在 V8 的上下文中，开发者通常不会直接编写这些汇编代码。但是，理解这些底层的指令对于理解 V8 的性能优化机制非常重要。V8 的开发者需要确保生成的汇编代码是正确且高效的。

**作为第 5 部分，共 6 部分的归纳:**

在这个系列的源代码中，`v8/src/codegen/arm/assembler-arm.cc` 文件作为 ARM 架构代码生成的核心组件，负责将高级的中间表示或者操作翻译成实际的 ARM 机器指令。  这部分代码专注于实现浮点运算 (VFP) 和 SIMD 运算 (NEON) 的指令生成，是 V8 在 ARM 平台上实现高性能 JavaScript 执行的关键组成部分。之前的部分可能涉及了更基础的 ARM 指令生成，而接下来的部分可能涉及更高级的代码生成策略、优化或者特定的平台功能支持。  总而言之，`assembler-arm.cc` 的核心功能是提供了一组 C++ 接口，用于方便地生成各种 ARM 汇编指令，特别是那些能够显著提升 JavaScript 性能的浮点和向量运算指令。

### 提示词
```
这是目录为v8/src/codegen/arm/assembler-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm/assembler-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
| dst.code() * B12 | 0xA * B8 | B4);
}

void Assembler::vmrs(Register dst, Condition cond) {
  // Instruction details available in ARM DDI 0406A, A8-652.
  // cond(31-28) | 1110 (27-24) | 1111(23-20)| 0001 (19-16) |
  // Rt(15-12) | 1010 (11-8) | 0(7) | 00 (6-5) | 1(4) | 0000(3-0)
  emit(cond | 0xE * B24 | 0xF * B20 | B16 | dst.code() * B12 | 0xA * B8 | B4);
}

void Assembler::vrinta(const SwVfpRegister dst, const SwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=00(17-16) |  Vd(15-12) | 101(11-9) | sz=0(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | vd * B12 |
       0x5 * B9 | B6 | m * B5 | vm);
}

void Assembler::vrinta(const DwVfpRegister dst, const DwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=00(17-16) |  Vd(15-12) | 101(11-9) | sz=1(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | vd * B12 |
       0x5 * B9 | B8 | B6 | m * B5 | vm);
}

void Assembler::vrintn(const SwVfpRegister dst, const SwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=01(17-16) |  Vd(15-12) | 101(11-9) | sz=0(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | 0x1 * B16 |
       vd * B12 | 0x5 * B9 | B6 | m * B5 | vm);
}

void Assembler::vrintn(const DwVfpRegister dst, const DwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=01(17-16) |  Vd(15-12) | 101(11-9) | sz=1(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | 0x1 * B16 |
       vd * B12 | 0x5 * B9 | B8 | B6 | m * B5 | vm);
}

void Assembler::vrintp(const SwVfpRegister dst, const SwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=10(17-16) |  Vd(15-12) | 101(11-9) | sz=0(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | 0x2 * B16 |
       vd * B12 | 0x5 * B9 | B6 | m * B5 | vm);
}

void Assembler::vrintp(const DwVfpRegister dst, const DwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=10(17-16) |  Vd(15-12) | 101(11-9) | sz=1(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | 0x2 * B16 |
       vd * B12 | 0x5 * B9 | B8 | B6 | m * B5 | vm);
}

void Assembler::vrintm(const SwVfpRegister dst, const SwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=11(17-16) |  Vd(15-12) | 101(11-9) | sz=0(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | 0x3 * B16 |
       vd * B12 | 0x5 * B9 | B6 | m * B5 | vm);
}

void Assembler::vrintm(const DwVfpRegister dst, const DwVfpRegister src) {
  // cond=kSpecialCondition(31-28) | 11101(27-23)| D(22) | 11(21-20) |
  // 10(19-18) | RM=11(17-16) |  Vd(15-12) | 101(11-9) | sz=1(8) | 01(7-6) |
  // M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(kSpecialCondition | 0x1D * B23 | d * B22 | 0x3 * B20 | B19 | 0x3 * B16 |
       vd * B12 | 0x5 * B9 | B8 | B6 | m * B5 | vm);
}

void Assembler::vrintz(const SwVfpRegister dst, const SwVfpRegister src,
                       const Condition cond) {
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 011(19-17) | 0(16) |
  // Vd(15-12) | 101(11-9) | sz=0(8) | op=1(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | 0x3 * B17 | vd * B12 |
       0x5 * B9 | B7 | B6 | m * B5 | vm);
}

void Assembler::vrintz(const DwVfpRegister dst, const DwVfpRegister src,
                       const Condition cond) {
  // cond(31-28) | 11101(27-23)| D(22) | 11(21-20) | 011(19-17) | 0(16) |
  // Vd(15-12) | 101(11-9) | sz=1(8) | op=1(7) | 1(6) | M(5) | 0(4) | Vm(3-0)
  DCHECK(IsEnabled(ARMv8));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  emit(cond | 0x1D * B23 | d * B22 | 0x3 * B20 | 0x3 * B17 | vd * B12 |
       0x5 * B9 | B8 | B7 | B6 | m * B5 | vm);
}

// Support for NEON.

void Assembler::vld1(NeonSize size, const NeonListOperand& dst,
                     const NeonMemOperand& src) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.320.
  // 1111(31-28) | 01000(27-23) | D(22) | 10(21-20) | Rn(19-16) |
  // Vd(15-12) | type(11-8) | size(7-6) | align(5-4) | Rm(3-0)
  DCHECK(IsEnabled(NEON));
  int vd, d;
  dst.base().split_code(&vd, &d);
  emit(0xFU * B28 | 4 * B24 | d * B22 | 2 * B20 | src.rn().code() * B16 |
       vd * B12 | dst.type() * B8 | size * B6 | src.align() * B4 |
       src.rm().code());
}

// vld1s(ingle element to one lane).
void Assembler::vld1s(NeonSize size, const NeonListOperand& dst, uint8_t index,
                      const NeonMemOperand& src) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.322.
  // 1111(31-28) | 01001(27-23) | D(22) | 10(21-20) | Rn(19-16) |
  // Vd(15-12) | size(11-10) | index_align(7-4) | Rm(3-0)
  // See vld1 (single element to all lanes) if size == 0x3, implemented as
  // vld1r(eplicate).
  DCHECK_NE(size, 0x3);
  // Check for valid lane indices.
  DCHECK_GT(1 << (3 - size), index);
  // Specifying alignment not supported, use standard alignment.
  uint8_t index_align = index << (size + 1);

  DCHECK(IsEnabled(NEON));
  int vd, d;
  dst.base().split_code(&vd, &d);
  emit(0xFU * B28 | 4 * B24 | 1 * B23 | d * B22 | 2 * B20 |
       src.rn().code() * B16 | vd * B12 | size * B10 | index_align * B4 |
       src.rm().code());
}

// vld1r(eplicate)
void Assembler::vld1r(NeonSize size, const NeonListOperand& dst,
                      const NeonMemOperand& src) {
  DCHECK(IsEnabled(NEON));
  int vd, d;
  dst.base().split_code(&vd, &d);
  emit(0xFU * B28 | 4 * B24 | 1 * B23 | d * B22 | 2 * B20 |
       src.rn().code() * B16 | vd * B12 | 0xC * B8 | size * B6 |
       dst.length() * B5 | src.rm().code());
}

void Assembler::vst1(NeonSize size, const NeonListOperand& src,
                     const NeonMemOperand& dst) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.404.
  // 1111(31-28) | 01000(27-23) | D(22) | 00(21-20) | Rn(19-16) |
  // Vd(15-12) | type(11-8) | size(7-6) | align(5-4) | Rm(3-0)
  DCHECK(IsEnabled(NEON));
  int vd, d;
  src.base().split_code(&vd, &d);
  emit(0xFU * B28 | 4 * B24 | d * B22 | dst.rn().code() * B16 | vd * B12 |
       src.type() * B8 | size * B6 | dst.align() * B4 | dst.rm().code());
}

void Assembler::vst1s(NeonSize size, const NeonListOperand& src, uint8_t index,
                      const NeonMemOperand& dst) {
  // Instruction details available in ARM DDI 0487F.b F6.1.236.
  // 1111(31-28) | 01001(27-23) | D(22) | 00(21-20) | Rn(19-16) |
  // Vd(15-12) | size(11-10) | 00(9-8) | index_align(7-4) | Rm(3-0)
  DCHECK(IsEnabled(NEON));
  DCHECK_NE(size, 0x3);
  DCHECK_GT(1 << (3 - size), index);
  // Specifying alignment not supported, use standard alignment.
  uint8_t index_align = index << (size + 1);
  int vd, d;
  src.base().split_code(&vd, &d);
  emit(0xFU * B28 | 9 * B23 | d * B22 | dst.rn().code() * B16 | vd * B12 |
       size * B10 | index_align * B4 | dst.rm().code());
}

void Assembler::vmovl(NeonDataType dt, QwNeonRegister dst, DwVfpRegister src) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.346.
  // 1111(31-28) | 001(27-25) | U(24) | 1(23) | D(22) | imm3(21-19) |
  // 000(18-16) | Vd(15-12) | 101000(11-6) | M(5) | 1(4) | Vm(3-0)
  DCHECK(IsEnabled(NEON));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  int U = NeonU(dt);
  int imm3 = 1 << NeonSz(dt);
  emit(0xFU * B28 | B25 | U * B24 | B23 | d * B22 | imm3 * B19 | vd * B12 |
       0xA * B8 | m * B5 | B4 | vm);
}

void Assembler::vqmovn(NeonDataType dst_dt, NeonDataType src_dt,
                       DwVfpRegister dst, QwNeonRegister src) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.1004.
  // vqmovn.<type><size> Dd, Qm. ARM vector narrowing move with saturation.
  // vqmovun.<type><size> Dd, Qm. Same as above, but produces unsigned results.
  DCHECK(IsEnabled(NEON));
  DCHECK_IMPLIES(NeonU(src_dt), NeonU(dst_dt));
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);
  int size = NeonSz(dst_dt);
  DCHECK_NE(3, size);
  int op = NeonU(src_dt) ? 0b11 : NeonU(dst_dt) ? 0b01 : 0b10;
  emit(0x1E7U * B23 | d * B22 | 0x3 * B20 | size * B18 | 0x2 * B16 | vd * B12 |
       0x2 * B8 | op * B6 | m * B5 | vm);
}

static int EncodeScalar(NeonDataType dt, int index) {
  int opc1_opc2 = 0;
  DCHECK_LE(0, index);
  switch (dt) {
    case NeonS8:
    case NeonU8:
      DCHECK_GT(8, index);
      opc1_opc2 = 0x8 | index;
      break;
    case NeonS16:
    case NeonU16:
      DCHECK_GT(4, index);
      opc1_opc2 = 0x1 | (index << 1);
      break;
    case NeonS32:
    case NeonU32:
      DCHECK_GT(2, index);
      opc1_opc2 = index << 2;
      break;
    default:
      UNREACHABLE();
  }
  return (opc1_opc2 >> 2) * B21 | (opc1_opc2 & 0x3) * B5;
}

void Assembler::vmov(NeonDataType dt, DwVfpRegister dst, int index,
                     Register src) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.940.
  // vmov ARM core register to scalar.
  DCHECK(dt == NeonS32 || dt == NeonU32 || IsEnabled(NEON));
  int vd, d;
  dst.split_code(&vd, &d);
  int opc1_opc2 = EncodeScalar(dt, index);
  emit(0xEEu * B24 | vd * B16 | src.code() * B12 | 0xB * B8 | d * B7 | B4 |
       opc1_opc2);
}

void Assembler::vmov(NeonDataType dt, Register dst, DwVfpRegister src,
                     int index) {
  // Instruction details available in ARM DDI 0406C.b, A8.8.942.
  // vmov Arm scalar to core register.
  DCHECK(dt == NeonS32 || dt == NeonU32 || IsEnabled(NEON));
  int vn, n;
  src.split_code(&vn, &n);
  int opc1_opc2 = EncodeScalar(dt, index);
  // NeonS32 and NeonU32 both encoded as u = 0.
  int u = NeonDataTypeToSize(dt) == Neon32 ? 0 : NeonU(dt);
  emit(0xEEu * B24 | u * B23 | B20 | vn * B16 | dst.code() * B12 | 0xB * B8 |
       n * B7 | B4 | opc1_opc2);
}

void Assembler::vmov(QwNeonRegister dst, QwNeonRegister src) {
  // Instruction details available in ARM DDI 0406C.b, A8-938.
  // vmov is encoded as vorr.
  vorr(dst, src, src);
}

void Assembler::vdup(NeonSize size, QwNeonRegister dst, Register src) {
  DCHECK(IsEnabled(NEON));
  // Instruction details available in ARM DDI 0406C.b, A8-886.
  int B = 0, E = 0;
  switch (size) {
    case Neon8:
      B = 1;
      break;
    case Neon16:
      E = 1;
      break;
    case Neon32:
      break;
    default:
      UNREACHABLE();
  }
  int vd, d;
  dst.split_code(&vd, &d);

  emit(al | 0x1D * B23 | B * B22 | B21 | vd * B16 | src.code() * B12 |
       0xB * B8 | d * B7 | E * B5 | B4);
}

enum NeonRegType { NEON_D, NEON_Q };

void NeonSplitCode(NeonRegType type, int code, int* vm, int* m, int* encoding) {
  if (type == NEON_D) {
    DwVfpRegister::split_code(code, vm, m);
  } else {
    DCHECK_EQ(type, NEON_Q);
    QwNeonRegister::split_code(code, vm, m);
    *encoding |= B6;
  }
}

static Instr EncodeNeonDupOp(NeonSize size, NeonRegType reg_type, int dst_code,
                             DwVfpRegister src, int index) {
  DCHECK_NE(Neon64, size);
  int sz = static_cast<int>(size);
  DCHECK_LE(0, index);
  DCHECK_GT(kSimd128Size / (1 << sz), index);
  int imm4 = (1 << sz) | ((index << (sz + 1)) & 0xF);
  int qbit = 0;
  int vd, d;
  NeonSplitCode(reg_type, dst_code, &vd, &d, &qbit);
  int vm, m;
  src.split_code(&vm, &m);

  return 0x1E7U * B23 | d * B22 | 0x3 * B20 | imm4 * B16 | vd * B12 |
         0x18 * B7 | qbit | m * B5 | vm;
}

void Assembler::vdup(NeonSize size, DwVfpRegister dst, DwVfpRegister src,
                     int index) {
  DCHECK(IsEnabled(NEON));
  // Instruction details available in ARM DDI 0406C.b, A8-884.
  emit(EncodeNeonDupOp(size, NEON_D, dst.code(), src, index));
}

void Assembler::vdup(NeonSize size, QwNeonRegister dst, DwVfpRegister src,
                     int index) {
  // Instruction details available in ARM DDI 0406C.b, A8-884.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonDupOp(size, NEON_Q, dst.code(), src, index));
}

// Encode NEON vcvt.src_type.dst_type instruction.
static Instr EncodeNeonVCVT(VFPType dst_type, QwNeonRegister dst,
                            VFPType src_type, QwNeonRegister src) {
  DCHECK(src_type != dst_type);
  DCHECK(src_type == F32 || dst_type == F32);
  // Instruction details available in ARM DDI 0406C.b, A8.8.868.
  int vd, d;
  dst.split_code(&vd, &d);
  int vm, m;
  src.split_code(&vm, &m);

  int op = 0;
  if (src_type == F32) {
    DCHECK(dst_type == S32 || dst_type == U32);
    op = dst_type == U32 ? 3 : 2;
  } else {
    DCHECK(src_type == S32 || src_type == U32);
    op = src_type == U32 ? 1 : 0;
  }

  return 0x1E7U * B23 | d * B22 | 0x3B * B16 | vd * B12 | 0x3 * B9 | op * B7 |
         B6 | m * B5 | vm;
}

void Assembler::vcvt_f32_s32(QwNeonRegister dst, QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  emit(EncodeNeonVCVT(F32, dst, S32, src));
}

void Assembler::vcvt_f32_u32(QwNeonRegister dst, QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  emit(EncodeNeonVCVT(F32, dst, U32, src));
}

void Assembler::vcvt_s32_f32(QwNeonRegister dst, QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  emit(EncodeNeonVCVT(S32, dst, F32, src));
}

void Assembler::vcvt_u32_f32(QwNeonRegister dst, QwNeonRegister src) {
  DCHECK(IsEnabled(NEON));
  DCHECK(VfpRegisterIsAvailable(dst));
  DCHECK(VfpRegisterIsAvailable(src));
  emit(EncodeNeonVCVT(U32, dst, F32, src));
}

enum UnaryOp {
  VMVN,
  VSWP,
  VABS,
  VABSF,
  VNEG,
  VNEGF,
  VRINTM,
  VRINTN,
  VRINTP,
  VRINTZ,
  VZIP,
  VUZP,
  VREV16,
  VREV32,
  VREV64,
  VTRN,
  VRECPE,
  VRSQRTE,
  VPADAL_S,
  VPADAL_U,
  VPADDL_S,
  VPADDL_U,
  VCEQ0,
  VCLT0,
  VCNT
};

// Encoding helper for "Advanced SIMD two registers misc" decode group. See ARM
// DDI 0487F.b, F4-4228.
static Instr EncodeNeonUnaryOp(UnaryOp op, NeonRegType reg_type, NeonSize size,
                               int dst_code, int src_code) {
  int op_encoding = 0;
  switch (op) {
    case VMVN:
      DCHECK_EQ(Neon8, size);  // size == 0 for vmvn
      op_encoding = B10 | 0x3 * B7;
      break;
    case VSWP:
      DCHECK_EQ(Neon8, size);  // size == 0 for vswp
      op_encoding = B17;
      break;
    case VABS:
      op_encoding = B16 | 0x6 * B7;
      break;
    case VABSF:
      DCHECK_EQ(Neon32, size);
      op_encoding = B16 | B10 | 0x6 * B7;
      break;
    case VNEG:
      op_encoding = B16 | 0x7 * B7;
      break;
    case VNEGF:
      DCHECK_EQ(Neon32, size);
      op_encoding = B16 | B10 | 0x7 * B7;
      break;
    case VRINTM:
      op_encoding = B17 | 0xD * B7;
      break;
    case VRINTN:
      op_encoding = B17 | 0x8 * B7;
      break;
    case VRINTP:
      op_encoding = B17 | 0xF * B7;
      break;
    case VRINTZ:
      op_encoding = B17 | 0xB * B7;
      break;
    case VZIP:
      op_encoding = 0x2 * B16 | 0x3 * B7;
      break;
    case VUZP:
      op_encoding = 0x2 * B16 | 0x2 * B7;
      break;
    case VREV16:
      op_encoding = 0x2 * B7;
      break;
    case VREV32:
      op_encoding = 0x1 * B7;
      break;
    case VREV64:
      // op_encoding is 0;
      break;
    case VTRN:
      op_encoding = 0x2 * B16 | B7;
      break;
    case VRECPE:
      // Only support floating point.
      op_encoding = 0x3 * B16 | 0xA * B7;
      break;
    case VRSQRTE:
      // Only support floating point.
      op_encoding = 0x3 * B16 | 0xB * B7;
      break;
    case VPADAL_S:
      op_encoding = 0xC * B7;
      break;
    case VPADAL_U:
      op_encoding = 0xD * B7;
      break;
    case VPADDL_S:
      op_encoding = 0x4 * B7;
      break;
    case VPADDL_U:
      op_encoding = 0x5 * B7;
      break;
    case VCEQ0:
      // Only support integers.
      op_encoding = 0x1 * B16 | 0x2 * B7;
      break;
    case VCLT0:
      // Only support signed integers.
      op_encoding = 0x1 * B16 | 0x4 * B7;
      break;
    case VCNT:
      op_encoding = 0xA * B7;
      break;
  }
  int vd, d;
  NeonSplitCode(reg_type, dst_code, &vd, &d, &op_encoding);
  int vm, m;
  NeonSplitCode(reg_type, src_code, &vm, &m, &op_encoding);

  return 0x1E7U * B23 | d * B22 | 0x3 * B20 | size * B18 | vd * B12 | m * B5 |
         vm | op_encoding;
}

void Assembler::vmvn(QwNeonRegister dst, QwNeonRegister src) {
  // Qd = vmvn(Qn, Qm) SIMD bitwise negate.
  // Instruction details available in ARM DDI 0406C.b, A8-966.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VMVN, NEON_Q, Neon8, dst.code(), src.code()));
}

void Assembler::vswp(DwVfpRegister dst, DwVfpRegister src) {
  DCHECK(IsEnabled(NEON));
  // Dd = vswp(Dn, Dm) SIMD d-register swap.
  // Instruction details available in ARM DDI 0406C.b, A8.8.418.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VSWP, NEON_D, Neon8, dst.code(), src.code()));
}

void Assembler::vswp(QwNeonRegister dst, QwNeonRegister src) {
  // Qd = vswp(Qn, Qm) SIMD q-register swap.
  // Instruction details available in ARM DDI 0406C.b, A8.8.418.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VSWP, NEON_Q, Neon8, dst.code(), src.code()));
}

void Assembler::vabs(QwNeonRegister dst, QwNeonRegister src) {
  // Qd = vabs.f<size>(Qn, Qm) SIMD floating point absolute value.
  // Instruction details available in ARM DDI 0406C.b, A8.8.824.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VABSF, NEON_Q, Neon32, dst.code(), src.code()));
}

void Assembler::vabs(NeonSize size, QwNeonRegister dst, QwNeonRegister src) {
  // Qd = vabs.s<size>(Qn, Qm) SIMD integer absolute value.
  // Instruction details available in ARM DDI 0406C.b, A8.8.824.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VABS, NEON_Q, size, dst.code(), src.code()));
}

void Assembler::vneg(QwNeonRegister dst, QwNeonRegister src) {
  // Qd = vabs.f<size>(Qn, Qm) SIMD floating point negate.
  // Instruction details available in ARM DDI 0406C.b, A8.8.968.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VNEGF, NEON_Q, Neon32, dst.code(), src.code()));
}

void Assembler::vneg(NeonSize size, QwNeonRegister dst, QwNeonRegister src) {
  // Qd = vabs.s<size>(Qn, Qm) SIMD integer negate.
  // Instruction details available in ARM DDI 0406C.b, A8.8.968.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonUnaryOp(VNEG, NEON_Q, size, dst.code(), src.code()));
}

enum BinaryBitwiseOp { VAND, VBIC, VBIF, VBIT, VBSL, VEOR, VORR, VORN };

static Instr EncodeNeonBinaryBitwiseOp(BinaryBitwiseOp op, NeonRegType reg_type,
                                       int dst_code, int src_code1,
                                       int src_code2) {
  int op_encoding = 0;
  switch (op) {
    case VBIC:
      op_encoding = 0x1 * B20;
      break;
    case VBIF:
      op_encoding = B24 | 0x3 * B20;
      break;
    case VBIT:
      op_encoding = B24 | 0x2 * B20;
      break;
    case VBSL:
      op_encoding = B24 | 0x1 * B20;
      break;
    case VEOR:
      op_encoding = B24;
      break;
    case VORR:
      op_encoding = 0x2 * B20;
      break;
    case VORN:
      op_encoding = 0x3 * B20;
      break;
    case VAND:
      // op_encoding is 0.
      break;
    default:
      UNREACHABLE();
  }
  int vd, d;
  NeonSplitCode(reg_type, dst_code, &vd, &d, &op_encoding);
  int vn, n;
  NeonSplitCode(reg_type, src_code1, &vn, &n, &op_encoding);
  int vm, m;
  NeonSplitCode(reg_type, src_code2, &vm, &m, &op_encoding);

  return 0x1E4U * B23 | op_encoding | d * B22 | vn * B16 | vd * B12 | B8 |
         n * B7 | m * B5 | B4 | vm;
}

void Assembler::vand(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  // Qd = vand(Qn, Qm) SIMD AND.
  // Instruction details available in ARM DDI 0406C.b, A8.8.836.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonBinaryBitwiseOp(VAND, NEON_Q, dst.code(), src1.code(),
                                 src2.code()));
}

void Assembler::vbic(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  // Qd = vbic(Qn, Qm) SIMD AND.
  // Instruction details available in ARM DDI 0406C.b, A8-840.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonBinaryBitwiseOp(VBIC, NEON_Q, dst.code(), src1.code(),
                                 src2.code()));
}

void Assembler::vbsl(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  // Qd = vbsl(Qn, Qm) SIMD bitwise select.
  // Instruction details available in ARM DDI 0406C.b, A8-844.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonBinaryBitwiseOp(VBSL, NEON_Q, dst.code(), src1.code(),
                                 src2.code()));
}

void Assembler::veor(DwVfpRegister dst, DwVfpRegister src1,
                     DwVfpRegister src2) {
  // Dd = veor(Dn, Dm) SIMD exclusive OR.
  // Instruction details available in ARM DDI 0406C.b, A8.8.888.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonBinaryBitwiseOp(VEOR, NEON_D, dst.code(), src1.code(),
                                 src2.code()));
}

void Assembler::veor(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  // Qd = veor(Qn, Qm) SIMD exclusive OR.
  // Instruction details available in ARM DDI 0406C.b, A8.8.888.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonBinaryBitwiseOp(VEOR, NEON_Q, dst.code(), src1.code(),
                                 src2.code()));
}

void Assembler::vorr(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  // Qd = vorr(Qn, Qm) SIMD OR.
  // Instruction details available in ARM DDI 0406C.b, A8.8.976.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonBinaryBitwiseOp(VORR, NEON_Q, dst.code(), src1.code(),
                                 src2.code()));
}

void Assembler::vorn(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  // Qd = vorn(Qn, Qm) SIMD OR NOT.
  // Instruction details available in ARM DDI 0406C.d, A8.8.359.
  DCHECK(IsEnabled(NEON));
  emit(EncodeNeonBinaryBitwiseOp(VORN, NEON_Q, dst.code(), src1.code(),
                                 src2.code()));
}

enum FPBinOp {
  VADDF,
  VSUBF,
  VMULF,
  VMINF,
  VMAXF,
  VRECPS,
  VRSQRTS,
  VCEQF,
  VCGEF,
  VCGTF
};

static Instr EncodeNeonBinOp(FPBinOp op, QwNeonRegister dst,
                             QwNeonRegister src1, QwNeonRegister src2) {
  int op_encoding = 0;
  switch (op) {
    case VADDF:
      op_encoding = 0xD * B8;
      break;
    case VSUBF:
      op_encoding = B21 | 0xD * B8;
      break;
    case VMULF:
      op_encoding = B24 | 0xD * B8 | B4;
      break;
    case VMINF:
      op_encoding = B21 | 0xF * B8;
      break;
    case VMAXF:
      op_encoding = 0xF * B8;
      break;
    case VRECPS:
      op_encoding = 0xF * B8 | B4;
      break;
    case VRSQRTS:
      op_encoding = B21 | 0xF * B8 | B4;
      break;
    case VCEQF:
      op_encoding = 0xE * B8;
      break;
    case VCGEF:
      op_encoding = B24 | 0xE * B8;
      break;
    case VCGTF:
      op_encoding = B24 | B21 | 0xE * B8;
      break;
    default:
      UNREACHABLE();
  }
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  return 0x1E4U * B23 | d * B22 | vn * B16 | vd * B12 | n * B7 | B6 | m * B5 |
         vm | op_encoding;
}

enum IntegerBinOp {
  VADD,
  VQADD,
  VSUB,
  VQSUB,
  VMUL,
  VMIN,
  VMAX,
  VTST,
  VCEQ,
  VCGE,
  VCGT,
  VRHADD,
  VQRDMULH
};

static Instr EncodeNeonDataTypeBinOp(IntegerBinOp op, NeonDataType dt,
                                     QwNeonRegister dst, QwNeonRegister src1,
                                     QwNeonRegister src2) {
  int op_encoding = 0;
  switch (op) {
    case VADD:
      op_encoding = 0x8 * B8;
      break;
    case VQADD:
      op_encoding = B4;
      break;
    case VSUB:
      op_encoding = B24 | 0x8 * B8;
      break;
    case VQSUB:
      op_encoding = 0x2 * B8 | B4;
      break;
    case VMUL:
      op_encoding = 0x9 * B8 | B4;
      break;
    case VMIN:
      op_encoding = 0x6 * B8 | B4;
      break;
    case VMAX:
      op_encoding = 0x6 * B8;
      break;
    case VTST:
      op_encoding = 0x8 * B8 | B4;
      break;
    case VCEQ:
      op_encoding = B24 | 0x8 * B8 | B4;
      break;
    case VCGE:
      op_encoding = 0x3 * B8 | B4;
      break;
    case VCGT:
      op_encoding = 0x3 * B8;
      break;
    case VRHADD:
      op_encoding = B8;
      break;
    case VQRDMULH:
      op_encoding = B24 | 0xB * B8;
      break;
    default:
      UNREACHABLE();
  }
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  int size = NeonSz(dt);
  int u = NeonU(dt);
  return 0x1E4U * B23 | u * B24 | d * B22 | size * B20 | vn * B16 | vd * B12 |
         n * B7 | B6 | m * B5 | vm | op_encoding;
}

static Instr EncodeNeonSizeBinOp(IntegerBinOp op, NeonSize size,
                                 QwNeonRegister dst, QwNeonRegister src1,
                                 QwNeonRegister src2) {
  // Map NeonSize values to the signed values in NeonDataType, so the U bit
  // will be 0.
  return EncodeNeonDataTypeBinOp(op, static_cast<NeonDataType>(size), dst, src1,
                                 src2);
}

void Assembler::vadd(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vadd(Qn, Qm) SIMD floating point addition.
  // Instruction details available in ARM DDI 0406C.b, A8-830.
  emit(EncodeNeonBinOp(VADDF, dst, src1, src2));
}

void Assembler::vadd(NeonSize size, QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vadd(Qn, Qm) SIMD integer addition.
  // Instruction details available in ARM DDI 0406C.b, A8-828.
  emit(EncodeNeonSizeBinOp(VADD, size, dst, src1, src2));
}

void Assembler::vqadd(NeonDataType dt, QwNeonRegister dst, QwNeonRegister src1,
                      QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vqadd(Qn, Qm) SIMD integer saturating addition.
  // Instruction details available in ARM DDI 0406C.b, A8-996.
  emit(EncodeNeonDataTypeBinOp(VQADD, dt, dst, src1, src2));
}

void Assembler::vsub(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vsub(Qn, Qm) SIMD floating point subtraction.
  // Instruction details available in ARM DDI 0406C.b, A8-1086.
  emit(EncodeNeonBinOp(VSUBF, dst, src1, src2));
}

void Assembler::vsub(NeonSize size, QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vsub(Qn, Qm) SIMD integer subtraction.
  // Instruction details available in ARM DDI 0406C.b, A8-1084.
  emit(EncodeNeonSizeBinOp(VSUB, size, dst, src1, src2));
}

void Assembler::vqsub(NeonDataType dt, QwNeonRegister dst, QwNeonRegister src1,
                      QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vqsub(Qn, Qm) SIMD integer saturating subtraction.
  // Instruction details available in ARM DDI 0406C.b, A8-1020.
  emit(EncodeNeonDataTypeBinOp(VQSUB, dt, dst, src1, src2));
}

void Assembler::vmlal(NeonDataType dt, QwNeonRegister dst, DwVfpRegister src1,
                      DwVfpRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vmlal(Dn, Dm) Vector Multiply Accumulate Long (integer)
  // Instruction details available in ARM DDI 0406C.b, A8-931.
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  int size = NeonSz(dt);
  int u = NeonU(dt);
  if (!u) UNIMPLEMENTED();
  DCHECK_NE(size, 3);  // SEE "Related encodings"
  emit(0xFU * B28 | B25 | u * B24 | B23 | d * B22 | size * B20 | vn * B16 |
       vd * B12 | 0x8 * B8 | n * B7 | m * B5 | vm);
}

void Assembler::vmul(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vadd(Qn, Qm) SIMD floating point multiply.
  // Instruction details available in ARM DDI 0406C.b, A8-958.
  emit(EncodeNeonBinOp(VMULF, dst, src1, src2));
}

void Assembler::vmul(NeonSize size, QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vadd(Qn, Qm) SIMD integer multiply.
  // Instruction details available in ARM DDI 0406C.b, A8-960.
  emit(EncodeNeonSizeBinOp(VMUL, size, dst, src1, src2));
}

void Assembler::vmull(NeonDataType dt, QwNeonRegister dst, DwVfpRegister src1,
                      DwVfpRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vmull(Dn, Dm) Vector Multiply Long (integer).
  // Instruction details available in ARM DDI 0406C.b, A8-960.
  int vd, d;
  dst.split_code(&vd, &d);
  int vn, n;
  src1.split_code(&vn, &n);
  int vm, m;
  src2.split_code(&vm, &m);
  int size = NeonSz(dt);
  int u = NeonU(dt);
  emit(0xFU * B28 | B25 | u * B24 | B23 | d * B22 | size * B20 | vn * B16 |
       vd * B12 | 0xC * B8 | n * B7 | m * B5 | vm);
}

void Assembler::vmin(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vmin(Qn, Qm) SIMD floating point MIN.
  // Instruction details available in ARM DDI 0406C.b, A8-928.
  emit(EncodeNeonBinOp(VMINF, dst, src1, src2));
}

void Assembler::vmin(NeonDataType dt, QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vmin(Qn, Qm) SIMD integer MIN.
  // Instruction details available in ARM DDI 0406C.b, A8-926.
  emit(EncodeNeonDataTypeBinOp(VMIN, dt, dst, src1, src2));
}

void Assembler::vmax(QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vmax(Qn, Qm) SIMD floating point MAX.
  // Instruction details available in ARM DDI 0406C.b, A8-928.
  emit(EncodeNeonBinOp(VMAXF, dst, src1, src2));
}

void Assembler::vmax(NeonDataType dt, QwNeonRegister dst, QwNeonRegister src1,
                     QwNeonRegister src2) {
  DCHECK(IsEnabled(NEON));
  // Qd = vmax(Qn, Qm) SIMD integer MAX.
  // Instruction details available in ARM DDI 0406C.b, A8-926.
  emit(EncodeNeonDataTypeBinOp(VMAX, dt, dst, src1, src2));
}

enum NeonShiftOp { VSHL, VSHR, VSLI, VSRI, VSRA };

static Instr EncodeNeonShiftRegisterOp(NeonShiftOp op, NeonDataType dt,
                                       NeonRegType reg_type, int dst_code,
                                       int src_code, int shift_code) {
  DCHECK_EQ(op, VSHL);
  int op_encoding = 0;
  int vd, d;
  NeonSplitCode(reg_type, dst_code, &vd, &d, &op_encoding);
  int vm, m;
  NeonSplitCode(reg_type, src_code, &vm, &m, &op_encoding);
  int vn, n;
  NeonSplitCode(reg_type, shift_code, &vn, &n, &op_encoding);
  int size = NeonSz(dt);
  int u = NeonU(dt);

  return 0x1E4U * B23 | u * B24 | d * B22 | size * B20 | vn * B16 | vd * B12 |
         0x4 * B8 | n * B7 | m * B5 | vm | op_encoding;
}

static Instr EncodeNeonShiftOp(NeonShiftOp op, NeonSize size, bool is_unsigned,
                               NeonRegType reg_type, int dst_code, int src_code,
                               int shift) {
  int size_in_bits = kBitsPerByte << static_cast<int>(size);
  int op_encoding = 0, imm6 = 0, L = 0;
  switch (op) {
    case VSHL: {
      DCHECK(shift >= 0 && size_in_bits > shift);
      imm6 = size_in_bits + shift;
      op_encoding = 0x5 * B8;
      break;
    }
    case VSHR: {
      DCHECK(shift > 0 && size_in_b
```