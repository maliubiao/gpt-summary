Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Scan and High-Level Understanding:**

* **Keywords:** The code is filled with `constexpr`, `uint32_t`, `using`, and names like `FPDataProcessing`, `FPIntegerConvert`, `NEON`. This immediately suggests it's about defining constants, likely related to hardware instructions or low-level operations.
* **Naming Conventions:** The names are very descriptive (e.g., `FMADD_s`, `FCVTNS_xs`, `NEON_ADD`). This hints at instruction mnemonics or categories. The suffixes like `_s`, `_d`, `_ws`, `_xs` likely refer to data types or sizes (single, double, word, extended size). `NEON` strongly suggests ARM's SIMD (Single Instruction, Multiple Data) extensions.
* **Structure:**  The code is organized into logical groups based on instruction types (FP data processing, integer conversion, fixed-point conversion, various NEON instruction categories). This organization is crucial for understanding.
* **Absence of Logic:**  There are no `if`, `else`, `for` loops, or function definitions. It's purely declarations of constants.

**2. Deeper Dive into the Groups:**

* **FPDataProcessing:**  The names `FMADD`, `FMSUB`, `FNMADD`, `FNMSUB` are recognizable as floating-point fused multiply-add/subtract operations. The `_s` and `_d` clearly indicate single and double precision. The bitwise ORing with `FPDataProcessingFixed` suggests combining base opcodes with specific modifiers.
* **FPIntegerConvert:**  The `FCVT` prefix strongly indicates floating-point to integer conversion, and vice-versa. The suffixes like `NS` (nearest with same sign), `NU` (nearest with unsigned), `TZS` (truncate towards zero with signed), `TZU` (truncate towards zero with unsigned) are common rounding modes in floating-point conversions. The combinations with `_ws`, `_xs`, `_wd`, `_xd` reinforce the idea of different data sizes. `SCVTF` and `UCVTF` are signed and unsigned integer to floating-point conversions.
* **FPFixedPointConvert:** Similar to `FPIntegerConvert`, but the `fixed` suffix suggests conversions involving fixed-point numbers.
* **NEON Instructions:** This is the largest section, and the names are clearly ARM NEON instruction mnemonics. The groups (two-register misc, three same-type operands, three different-type operands, across lanes, by indexed element, modified immediate, extract, load/store) reflect the different categories of NEON instructions. The suffixes like `L`, `W`, `HN`, `2` likely relate to operand sizes (long, wide, half-narrow, second half of registers). The presence of `UBit` (unsigned bit) is important. The `_byelement` suffix indicates operations involving a single element from a vector. `_post` refers to post-increment addressing modes.

**3. Connecting to Concepts and Potential Usage:**

* **Instruction Encoding:** The bitwise operations (`|`, `&`) and the `Fixed`, `Mask`, and `FMask` constants strongly suggest this file is used to define the binary encoding of ARM64 instructions. The `Mask` would be used to isolate specific bits, `FMask` to check against a full mask, and the constants themselves represent the bit patterns for different instruction variations.
* **Compiler/Assembler Role:**  This header file would be crucial for components of the V8 engine that generate ARM64 machine code. The compiler (Torque in this case) or assembler needs to know the exact bit patterns to emit the correct instructions.
* **Optimization:**  Knowing the specific instructions available allows the compiler to perform optimizations by choosing the most efficient instruction sequence for a given task.

**4. Addressing the Specific Questions:**

* **Functionality:** Based on the analysis, the primary function is to define constants representing ARM64 instruction encodings, particularly for floating-point and NEON operations.
* **.tq Extension:** Yes, if the file ended in `.tq`, it would be a Torque source file, which is V8's internal language for code generation.
* **JavaScript Relationship:** While this file doesn't directly contain JavaScript code, it's *fundamental* to how JavaScript code is executed on ARM64. JavaScript's numerical operations (especially with typed arrays and SIMD.js, if used) rely on these underlying instructions. The example provided in the initial prompt for `Math.fround` is a good illustration.
* **Code Logic Inference:** The bitwise operations are the core "logic." The assumption is that by combining the `Fixed` part with specific option bits (e.g., `SixtyFourBits`, `FP64`), you construct the complete instruction opcode.
* **Common Programming Errors:** The most relevant error in this context isn't directly about *using* these constants in user code (as they are internal). Instead, it relates to **misunderstanding floating-point behavior** in JavaScript, which is *implemented* using these instructions. The example of precision loss is perfect.
* **Part 3 Summary:** This section focuses heavily on defining constants for floating-point conversions (to/from integers and fixed-point) and a wide range of NEON (SIMD) instructions, crucial for optimizing numerical and data-parallel tasks in JavaScript.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Could these constants be used for something other than instruction encoding?  *Correction:* While they *could* theoretically represent other things, the naming and structure strongly point to instruction opcodes.
* **Initial thought:** Is the JavaScript connection direct? *Refinement:* It's indirect. Users don't manipulate these constants directly, but JavaScript engines use them behind the scenes. The examples should illustrate the *effects* of these instructions in JavaScript.
* **Focusing too much on individual constants:** *Refinement:*  Step back and look at the *groups* of constants and the overall purpose of the file. The organization is key.

By following these steps, combining pattern recognition with knowledge of computer architecture and V8's internal workings, one can effectively analyze this type of header file and understand its significance.
这是目录为 `v8/src/codegen/arm64/constants-arm64.h` 的一个 V8 源代码片段。根据其内容，我们可以推断出它的主要功能是：**定义用于表示 ARM64 架构指令的常量**。

**功能归纳：**

这个头文件定义了大量的 `constexpr` 常量，这些常量用于表示 ARM64 架构中各种指令的不同操作码和标志位。这些常量被组织成不同的组，对应于不同的指令类型，例如：

* **浮点数据处理指令 (FPDataProcessing):**  定义了浮点数的加、减、乘、除等操作，包括融合乘加/减 (FMADD, FMSUB) 及其否定形式。
* **浮点与整数之间的转换指令 (FPIntegerConvert):** 定义了浮点数与不同大小和符号的整数之间相互转换的指令，以及一些浮点数移动指令。 这些指令涵盖了不同的舍入模式 (例如，向最近偶数舍入 FCVTNS, 向零舍入 FCVTZS)。
* **浮点与定点之间的转换指令 (FPFixedPointConvert):** 定义了浮点数与定点数之间相互转换的指令。
* **NEON 指令:** 这是最主要的部分，定义了大量的 NEON (Advanced SIMD) 扩展指令，用于并行处理向量数据。这些指令涵盖了：
    * **双操作数指令 (NEON2RegMiscOp):** 包括反转、加法、绝对值、比较、类型转换等。
    * **三操作数同类型指令 (NEON3SameOp):** 包括加法、减法、乘法、比较、最大值、最小值等。
    * **三操作数不同类型指令 (NEON3DifferentOp):**  包括不同大小数据类型的加法、乘法等。
    * **跨通道操作指令 (NEONAcrossLanesOp):**  对向量的不同通道进行操作，例如求和、求最大值/最小值。
    * **带索引元素操作指令 (NEONByIndexedElementOp):**  使用向量中的一个特定元素进行操作。
    * **带立即数操作指令 (NEONModifiedImmediateOp):** 使用修改后的立即数进行操作。
    * **提取指令 (NEONExtractOp):**  从两个向量中提取数据。
    * **加载/存储多结构体指令 (NEONLoadStoreMultiStructOp, NEONLoadStoreMultiStructPostIndexOp):**  批量加载和存储多个向量到内存。

**关于文件扩展名和 Torque：**

如果 `v8/src/codegen/arm64/constants-arm64.h` 以 `.tq` 结尾，那么它的确是一个 V8 Torque 源代码文件。 Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的汇编代码。虽然这个例子中的文件是 `.h` 头文件，但 Torque 可以用来生成类似的常量定义。

**与 JavaScript 功能的关系：**

`constants-arm64.h` 中定义的常量直接影响 V8 如何将 JavaScript 代码编译成 ARM64 机器码。特别是对于涉及数值计算、数组操作以及使用 SIMD API 的 JavaScript 代码，这些常量决定了最终执行的底层指令。

**JavaScript 示例：**

以下 JavaScript 示例展示了与 `constants-arm64.h` 中定义的某些指令相关的概念：

```javascript
// 浮点数操作
let a = 1.5;
let b = 2.7;
let c = a * b + 3.0; // 这可能会用到 FMADD 指令

// 浮点数与整数转换
let floatNum = 3.14;
let intNum = Math.floor(floatNum); // 向下取整，可能与 FCVTZS 相关

// 使用 Typed Arrays 和 SIMD (如果支持)
let array1 = new Float32Array([1.0, 2.0, 3.0, 4.0]);
let array2 = new Float32Array([5.0, 6.0, 7.0, 8.0]);

// 如果 JavaScript 引擎使用 NEON，下面的向量化操作可能会用到 NEON 指令
for (let i = 0; i < array1.length; i++) {
  array1[i] += array2[i]; // 例如，可能用到 NEON_ADD
}
```

**代码逻辑推理 (假设输入与输出)：**

这些常量本身不包含动态的代码逻辑，它们是静态的定义。但是，在 V8 的代码生成过程中，这些常量会被用来构建指令。

**假设输入：**  V8 编译器需要生成 ARM64 指令来执行 `a * b + c` 这个 JavaScript 表达式，其中 `a`, `b`, `c` 是浮点数。

**输出：** 编译器可能会查找 `FMADD_s` (如果使用单精度浮点数) 或 `FMADD_d` (如果使用双精度浮点数) 常量的值，并将其嵌入到生成的机器码中，以表示融合乘加指令。  输出的机器码会包含与这些常量对应的位模式。

**用户常见的编程错误 (间接相关)：**

虽然用户不会直接操作这些常量，但对浮点数和 SIMD 的误解可能会导致错误，这些错误最终会由使用了这些指令的代码执行。

**示例：**

```javascript
// 浮点数精度问题
let result = 0.1 + 0.2;
console.log(result === 0.3); // 输出 false，因为浮点数精度有限

// 误用 SIMD (如果直接操作 SIMD API)
// 假设错误地对不同长度的向量进行操作，可能导致未定义的行为或错误结果，
// 底层的 NEON 指令执行也会因此产生预期外的结果。
```

**总结第 3 部分的功能：**

这部分主要定义了用于浮点数处理（包括基本运算和与整数、定点数的转换）以及大量 NEON (SIMD) 指令的常量。 这些常量是 V8 将 JavaScript 代码编译成高效 ARM64 机器码的关键，特别是对于数值密集型和并行计算相关的代码。 这部分内容展示了 ARM64 架构在浮点数和向量化计算方面的丰富指令集。

### 提示词
```
这是目录为v8/src/codegen/arm64/constants-arm64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/constants-arm64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
0;
constexpr FPDataProcessing3SourceOp FPDataProcessing3SourceFMask = 0x5F000000;
constexpr FPDataProcessing3SourceOp FPDataProcessing3SourceMask = 0xFFE08000;
constexpr FPDataProcessing3SourceOp FMADD_s =
    FPDataProcessing3SourceFixed | 0x00000000;
constexpr FPDataProcessing3SourceOp FMSUB_s =
    FPDataProcessing3SourceFixed | 0x00008000;
constexpr FPDataProcessing3SourceOp FNMADD_s =
    FPDataProcessing3SourceFixed | 0x00200000;
constexpr FPDataProcessing3SourceOp FNMSUB_s =
    FPDataProcessing3SourceFixed | 0x00208000;
constexpr FPDataProcessing3SourceOp FMADD_d =
    FPDataProcessing3SourceFixed | 0x00400000;
constexpr FPDataProcessing3SourceOp FMSUB_d =
    FPDataProcessing3SourceFixed | 0x00408000;
constexpr FPDataProcessing3SourceOp FNMADD_d =
    FPDataProcessing3SourceFixed | 0x00600000;
constexpr FPDataProcessing3SourceOp FNMSUB_d =
    FPDataProcessing3SourceFixed | 0x00608000;

// Conversion between floating point and integer.
using FPIntegerConvertOp = uint32_t;
constexpr FPIntegerConvertOp FPIntegerConvertFixed = 0x1E200000;
constexpr FPIntegerConvertOp FPIntegerConvertFMask = 0x5F20FC00;
constexpr FPIntegerConvertOp FPIntegerConvertMask = 0xFFFFFC00;
constexpr FPIntegerConvertOp FCVTNS = FPIntegerConvertFixed | 0x00000000;
constexpr FPIntegerConvertOp FCVTNS_ws = FCVTNS;
constexpr FPIntegerConvertOp FCVTNS_xs = FCVTNS | SixtyFourBits;
constexpr FPIntegerConvertOp FCVTNS_wd = FCVTNS | FP64;
constexpr FPIntegerConvertOp FCVTNS_xd = FCVTNS | SixtyFourBits | FP64;
constexpr FPIntegerConvertOp FCVTNU = FPIntegerConvertFixed | 0x00010000;
constexpr FPIntegerConvertOp FCVTNU_ws = FCVTNU;
constexpr FPIntegerConvertOp FCVTNU_xs = FCVTNU | SixtyFourBits;
constexpr FPIntegerConvertOp FCVTNU_wd = FCVTNU | FP64;
constexpr FPIntegerConvertOp FCVTNU_xd = FCVTNU | SixtyFourBits | FP64;
constexpr FPIntegerConvertOp FCVTPS = FPIntegerConvertFixed | 0x00080000;
constexpr FPIntegerConvertOp FCVTPS_ws = FCVTPS;
constexpr FPIntegerConvertOp FCVTPS_xs = FCVTPS | SixtyFourBits;
constexpr FPIntegerConvertOp FCVTPS_wd = FCVTPS | FP64;
constexpr FPIntegerConvertOp FCVTPS_xd = FCVTPS | SixtyFourBits | FP64;
constexpr FPIntegerConvertOp FCVTPU = FPIntegerConvertFixed | 0x00090000;
constexpr FPIntegerConvertOp FCVTPU_ws = FCVTPU;
constexpr FPIntegerConvertOp FCVTPU_xs = FCVTPU | SixtyFourBits;
constexpr FPIntegerConvertOp FCVTPU_wd = FCVTPU | FP64;
constexpr FPIntegerConvertOp FCVTPU_xd = FCVTPU | SixtyFourBits | FP64;
constexpr FPIntegerConvertOp FCVTMS = FPIntegerConvertFixed | 0x00100000;
constexpr FPIntegerConvertOp FCVTMS_ws = FCVTMS;
constexpr FPIntegerConvertOp FCVTMS_xs = FCVTMS | SixtyFourBits;
constexpr FPIntegerConvertOp FCVTMS_wd = FCVTMS | FP64;
constexpr FPIntegerConvertOp FCVTMS_xd = FCVTMS | SixtyFourBits | FP64;
constexpr FPIntegerConvertOp FCVTMU = FPIntegerConvertFixed | 0x00110000;
constexpr FPIntegerConvertOp FCVTMU_ws = FCVTMU;
constexpr FPIntegerConvertOp FCVTMU_xs = FCVTMU | SixtyFourBits;
constexpr FPIntegerConvertOp FCVTMU_wd = FCVTMU | FP64;
constexpr FPIntegerConvertOp FCVTMU_xd = FCVTMU | SixtyFourBits | FP64;
constexpr FPIntegerConvertOp FCVTZS = FPIntegerConvertFixed | 0x00180000;
constexpr FPIntegerConvertOp FCVTZS_ws = FCVTZS;
constexpr FPIntegerConvertOp FCVTZS_xs = FCVTZS | SixtyFourBits;
constexpr FPIntegerConvertOp FCVTZS_wd = FCVTZS | FP64;
constexpr FPIntegerConvertOp FCVTZS_xd = FCVTZS | SixtyFourBits | FP64;
constexpr FPIntegerConvertOp FCVTZU = FPIntegerConvertFixed | 0x00190000;
constexpr FPIntegerConvertOp FCVTZU_ws = FCVTZU;
constexpr FPIntegerConvertOp FCVTZU_xs = FCVTZU | SixtyFourBits;
constexpr FPIntegerConvertOp FCVTZU_wd = FCVTZU | FP64;
constexpr FPIntegerConvertOp FCVTZU_xd = FCVTZU | SixtyFourBits | FP64;
constexpr FPIntegerConvertOp SCVTF = FPIntegerConvertFixed | 0x00020000;
constexpr FPIntegerConvertOp SCVTF_sw = SCVTF;
constexpr FPIntegerConvertOp SCVTF_sx = SCVTF | SixtyFourBits;
constexpr FPIntegerConvertOp SCVTF_dw = SCVTF | FP64;
constexpr FPIntegerConvertOp SCVTF_dx = SCVTF | SixtyFourBits | FP64;
constexpr FPIntegerConvertOp UCVTF = FPIntegerConvertFixed | 0x00030000;
constexpr FPIntegerConvertOp UCVTF_sw = UCVTF;
constexpr FPIntegerConvertOp UCVTF_sx = UCVTF | SixtyFourBits;
constexpr FPIntegerConvertOp UCVTF_dw = UCVTF | FP64;
constexpr FPIntegerConvertOp UCVTF_dx = UCVTF | SixtyFourBits | FP64;
constexpr FPIntegerConvertOp FCVTAS = FPIntegerConvertFixed | 0x00040000;
constexpr FPIntegerConvertOp FCVTAS_ws = FCVTAS;
constexpr FPIntegerConvertOp FCVTAS_xs = FCVTAS | SixtyFourBits;
constexpr FPIntegerConvertOp FCVTAS_wd = FCVTAS | FP64;
constexpr FPIntegerConvertOp FCVTAS_xd = FCVTAS | SixtyFourBits | FP64;
constexpr FPIntegerConvertOp FCVTAU = FPIntegerConvertFixed | 0x00050000;
constexpr FPIntegerConvertOp FCVTAU_ws = FCVTAU;
constexpr FPIntegerConvertOp FCVTAU_xs = FCVTAU | SixtyFourBits;
constexpr FPIntegerConvertOp FCVTAU_wd = FCVTAU | FP64;
constexpr FPIntegerConvertOp FCVTAU_xd = FCVTAU | SixtyFourBits | FP64;
constexpr FPIntegerConvertOp FMOV_ws = FPIntegerConvertFixed | 0x00060000;
constexpr FPIntegerConvertOp FMOV_sw = FPIntegerConvertFixed | 0x00070000;
constexpr FPIntegerConvertOp FMOV_xd = FMOV_ws | SixtyFourBits | FP64;
constexpr FPIntegerConvertOp FMOV_dx = FMOV_sw | SixtyFourBits | FP64;
constexpr FPIntegerConvertOp FMOV_d1_x =
    FPIntegerConvertFixed | SixtyFourBits | 0x008F0000;
constexpr FPIntegerConvertOp FMOV_x_d1 =
    FPIntegerConvertFixed | SixtyFourBits | 0x008E0000;
constexpr FPIntegerConvertOp FJCVTZS =
    FPIntegerConvertFixed | FP64 | 0x001E0000;

// Conversion between fixed point and floating point.
using FPFixedPointConvertOp = uint32_t;
constexpr FPFixedPointConvertOp FPFixedPointConvertFixed = 0x1E000000;
constexpr FPFixedPointConvertOp FPFixedPointConvertFMask = 0x5F200000;
constexpr FPFixedPointConvertOp FPFixedPointConvertMask = 0xFFFF0000;
constexpr FPFixedPointConvertOp FCVTZS_fixed =
    FPFixedPointConvertFixed | 0x00180000;
constexpr FPFixedPointConvertOp FCVTZS_ws_fixed = FCVTZS_fixed;
constexpr FPFixedPointConvertOp FCVTZS_xs_fixed = FCVTZS_fixed | SixtyFourBits;
constexpr FPFixedPointConvertOp FCVTZS_wd_fixed = FCVTZS_fixed | FP64;
constexpr FPFixedPointConvertOp FCVTZS_xd_fixed =
    FCVTZS_fixed | SixtyFourBits | FP64;
constexpr FPFixedPointConvertOp FCVTZU_fixed =
    FPFixedPointConvertFixed | 0x00190000;
constexpr FPFixedPointConvertOp FCVTZU_ws_fixed = FCVTZU_fixed;
constexpr FPFixedPointConvertOp FCVTZU_xs_fixed = FCVTZU_fixed | SixtyFourBits;
constexpr FPFixedPointConvertOp FCVTZU_wd_fixed = FCVTZU_fixed | FP64;
constexpr FPFixedPointConvertOp FCVTZU_xd_fixed =
    FCVTZU_fixed | SixtyFourBits | FP64;
constexpr FPFixedPointConvertOp SCVTF_fixed =
    FPFixedPointConvertFixed | 0x00020000;
constexpr FPFixedPointConvertOp SCVTF_sw_fixed = SCVTF_fixed;
constexpr FPFixedPointConvertOp SCVTF_sx_fixed = SCVTF_fixed | SixtyFourBits;
constexpr FPFixedPointConvertOp SCVTF_dw_fixed = SCVTF_fixed | FP64;
constexpr FPFixedPointConvertOp SCVTF_dx_fixed =
    SCVTF_fixed | SixtyFourBits | FP64;
constexpr FPFixedPointConvertOp UCVTF_fixed =
    FPFixedPointConvertFixed | 0x00030000;
constexpr FPFixedPointConvertOp UCVTF_sw_fixed = UCVTF_fixed;
constexpr FPFixedPointConvertOp UCVTF_sx_fixed = UCVTF_fixed | SixtyFourBits;
constexpr FPFixedPointConvertOp UCVTF_dw_fixed = UCVTF_fixed | FP64;
constexpr FPFixedPointConvertOp UCVTF_dx_fixed =
    UCVTF_fixed | SixtyFourBits | FP64;

// NEON instructions with two register operands.
using NEON2RegMiscOp = uint32_t;
constexpr NEON2RegMiscOp NEON2RegMiscFixed = 0x0E200800;
constexpr NEON2RegMiscOp NEON2RegMiscFMask = 0x9F260C00;
constexpr NEON2RegMiscOp NEON2RegMiscHPFixed = 0x00180000;
constexpr NEON2RegMiscOp NEON2RegMiscMask = 0xBF3FFC00;
constexpr NEON2RegMiscOp NEON2RegMiscUBit = 0x20000000;
constexpr NEON2RegMiscOp NEON_REV64 = NEON2RegMiscFixed | 0x00000000;
constexpr NEON2RegMiscOp NEON_REV32 = NEON2RegMiscFixed | 0x20000000;
constexpr NEON2RegMiscOp NEON_REV16 = NEON2RegMiscFixed | 0x00001000;
constexpr NEON2RegMiscOp NEON_SADDLP = NEON2RegMiscFixed | 0x00002000;
constexpr NEON2RegMiscOp NEON_UADDLP = NEON_SADDLP | NEON2RegMiscUBit;
constexpr NEON2RegMiscOp NEON_SUQADD = NEON2RegMiscFixed | 0x00003000;
constexpr NEON2RegMiscOp NEON_USQADD = NEON_SUQADD | NEON2RegMiscUBit;
constexpr NEON2RegMiscOp NEON_CLS = NEON2RegMiscFixed | 0x00004000;
constexpr NEON2RegMiscOp NEON_CLZ = NEON2RegMiscFixed | 0x20004000;
constexpr NEON2RegMiscOp NEON_CNT = NEON2RegMiscFixed | 0x00005000;
constexpr NEON2RegMiscOp NEON_RBIT_NOT = NEON2RegMiscFixed | 0x20005000;
constexpr NEON2RegMiscOp NEON_SADALP = NEON2RegMiscFixed | 0x00006000;
constexpr NEON2RegMiscOp NEON_UADALP = NEON_SADALP | NEON2RegMiscUBit;
constexpr NEON2RegMiscOp NEON_SQABS = NEON2RegMiscFixed | 0x00007000;
constexpr NEON2RegMiscOp NEON_SQNEG = NEON2RegMiscFixed | 0x20007000;
constexpr NEON2RegMiscOp NEON_CMGT_zero = NEON2RegMiscFixed | 0x00008000;
constexpr NEON2RegMiscOp NEON_CMGE_zero = NEON2RegMiscFixed | 0x20008000;
constexpr NEON2RegMiscOp NEON_CMEQ_zero = NEON2RegMiscFixed | 0x00009000;
constexpr NEON2RegMiscOp NEON_CMLE_zero = NEON2RegMiscFixed | 0x20009000;
constexpr NEON2RegMiscOp NEON_CMLT_zero = NEON2RegMiscFixed | 0x0000A000;
constexpr NEON2RegMiscOp NEON_ABS = NEON2RegMiscFixed | 0x0000B000;
constexpr NEON2RegMiscOp NEON_NEG = NEON2RegMiscFixed | 0x2000B000;
constexpr NEON2RegMiscOp NEON_XTN = NEON2RegMiscFixed | 0x00012000;
constexpr NEON2RegMiscOp NEON_SQXTUN = NEON2RegMiscFixed | 0x20012000;
constexpr NEON2RegMiscOp NEON_SHLL = NEON2RegMiscFixed | 0x20013000;
constexpr NEON2RegMiscOp NEON_SQXTN = NEON2RegMiscFixed | 0x00014000;
constexpr NEON2RegMiscOp NEON_UQXTN = NEON_SQXTN | NEON2RegMiscUBit;

constexpr NEON2RegMiscOp NEON2RegMiscOpcode = 0x0001F000;
constexpr NEON2RegMiscOp NEON_RBIT_NOT_opcode =
    NEON_RBIT_NOT & NEON2RegMiscOpcode;
constexpr NEON2RegMiscOp NEON_NEG_opcode = NEON_NEG & NEON2RegMiscOpcode;
constexpr NEON2RegMiscOp NEON_XTN_opcode = NEON_XTN & NEON2RegMiscOpcode;
constexpr NEON2RegMiscOp NEON_UQXTN_opcode = NEON_UQXTN & NEON2RegMiscOpcode;

// These instructions use only one bit of the size field. The other bit is
// used to distinguish between instructions.
constexpr NEON2RegMiscOp NEON2RegMiscFPMask = NEON2RegMiscMask | 0x00800000;
constexpr NEON2RegMiscOp NEON_FABS = NEON2RegMiscFixed | 0x0080F000;
constexpr NEON2RegMiscOp NEON_FNEG = NEON2RegMiscFixed | 0x2080F000;
constexpr NEON2RegMiscOp NEON_FCVTN = NEON2RegMiscFixed | 0x00016000;
constexpr NEON2RegMiscOp NEON_FCVTXN = NEON2RegMiscFixed | 0x20016000;
constexpr NEON2RegMiscOp NEON_FCVTL = NEON2RegMiscFixed | 0x00017000;
constexpr NEON2RegMiscOp NEON_FRINTN = NEON2RegMiscFixed | 0x00018000;
constexpr NEON2RegMiscOp NEON_FRINTA = NEON2RegMiscFixed | 0x20018000;
constexpr NEON2RegMiscOp NEON_FRINTP = NEON2RegMiscFixed | 0x00818000;
constexpr NEON2RegMiscOp NEON_FRINTM = NEON2RegMiscFixed | 0x00019000;
constexpr NEON2RegMiscOp NEON_FRINTX = NEON2RegMiscFixed | 0x20019000;
constexpr NEON2RegMiscOp NEON_FRINTZ = NEON2RegMiscFixed | 0x00819000;
constexpr NEON2RegMiscOp NEON_FRINTI = NEON2RegMiscFixed | 0x20819000;
constexpr NEON2RegMiscOp NEON_FCVTNS = NEON2RegMiscFixed | 0x0001A000;
constexpr NEON2RegMiscOp NEON_FCVTNU = NEON_FCVTNS | NEON2RegMiscUBit;
constexpr NEON2RegMiscOp NEON_FCVTPS = NEON2RegMiscFixed | 0x0081A000;
constexpr NEON2RegMiscOp NEON_FCVTPU = NEON_FCVTPS | NEON2RegMiscUBit;
constexpr NEON2RegMiscOp NEON_FCVTMS = NEON2RegMiscFixed | 0x0001B000;
constexpr NEON2RegMiscOp NEON_FCVTMU = NEON_FCVTMS | NEON2RegMiscUBit;
constexpr NEON2RegMiscOp NEON_FCVTZS = NEON2RegMiscFixed | 0x0081B000;
constexpr NEON2RegMiscOp NEON_FCVTZU = NEON_FCVTZS | NEON2RegMiscUBit;
constexpr NEON2RegMiscOp NEON_FCVTAS = NEON2RegMiscFixed | 0x0001C000;
constexpr NEON2RegMiscOp NEON_FCVTAU = NEON_FCVTAS | NEON2RegMiscUBit;
constexpr NEON2RegMiscOp NEON_FSQRT = NEON2RegMiscFixed | 0x2081F000;
constexpr NEON2RegMiscOp NEON_SCVTF = NEON2RegMiscFixed | 0x0001D000;
constexpr NEON2RegMiscOp NEON_UCVTF = NEON_SCVTF | NEON2RegMiscUBit;
constexpr NEON2RegMiscOp NEON_URSQRTE = NEON2RegMiscFixed | 0x2081C000;
constexpr NEON2RegMiscOp NEON_URECPE = NEON2RegMiscFixed | 0x0081C000;
constexpr NEON2RegMiscOp NEON_FRSQRTE = NEON2RegMiscFixed | 0x2081D000;
constexpr NEON2RegMiscOp NEON_FRECPE = NEON2RegMiscFixed | 0x0081D000;
constexpr NEON2RegMiscOp NEON_FCMGT_zero = NEON2RegMiscFixed | 0x0080C000;
constexpr NEON2RegMiscOp NEON_FCMGE_zero = NEON2RegMiscFixed | 0x2080C000;
constexpr NEON2RegMiscOp NEON_FCMEQ_zero = NEON2RegMiscFixed | 0x0080D000;
constexpr NEON2RegMiscOp NEON_FCMLE_zero = NEON2RegMiscFixed | 0x2080D000;
constexpr NEON2RegMiscOp NEON_FCMLT_zero = NEON2RegMiscFixed | 0x0080E000;

constexpr NEON2RegMiscOp NEON_FCVTL_opcode = NEON_FCVTL & NEON2RegMiscOpcode;
constexpr NEON2RegMiscOp NEON_FCVTN_opcode = NEON_FCVTN & NEON2RegMiscOpcode;

// NEON instructions with three same-type operands.
using NEON3SameOp = uint32_t;
constexpr NEON3SameOp NEON3SameFixed = 0x0E200400;
constexpr NEON3SameOp NEON3SameFMask = 0x9F200400;
constexpr NEON3SameOp NEON3SameMask = 0xBF20FC00;
constexpr NEON3SameOp NEON3SameUBit = 0x20000000;
constexpr NEON3SameOp NEON_ADD = NEON3SameFixed | 0x00008000;
constexpr NEON3SameOp NEON_ADDP = NEON3SameFixed | 0x0000B800;
constexpr NEON3SameOp NEON_SHADD = NEON3SameFixed | 0x00000000;
constexpr NEON3SameOp NEON_SHSUB = NEON3SameFixed | 0x00002000;
constexpr NEON3SameOp NEON_SRHADD = NEON3SameFixed | 0x00001000;
constexpr NEON3SameOp NEON_CMEQ = NEON3SameFixed | NEON3SameUBit | 0x00008800;
constexpr NEON3SameOp NEON_CMGE = NEON3SameFixed | 0x00003800;
constexpr NEON3SameOp NEON_CMGT = NEON3SameFixed | 0x00003000;
constexpr NEON3SameOp NEON_CMHI = NEON3SameFixed | NEON3SameUBit | NEON_CMGT;
constexpr NEON3SameOp NEON_CMHS = NEON3SameFixed | NEON3SameUBit | NEON_CMGE;
constexpr NEON3SameOp NEON_CMTST = NEON3SameFixed | 0x00008800;
constexpr NEON3SameOp NEON_MLA = NEON3SameFixed | 0x00009000;
constexpr NEON3SameOp NEON_MLS = NEON3SameFixed | 0x20009000;
constexpr NEON3SameOp NEON_MUL = NEON3SameFixed | 0x00009800;
constexpr NEON3SameOp NEON_PMUL = NEON3SameFixed | 0x20009800;
constexpr NEON3SameOp NEON_SRSHL = NEON3SameFixed | 0x00005000;
constexpr NEON3SameOp NEON_SQSHL = NEON3SameFixed | 0x00004800;
constexpr NEON3SameOp NEON_SQRSHL = NEON3SameFixed | 0x00005800;
constexpr NEON3SameOp NEON_SSHL = NEON3SameFixed | 0x00004000;
constexpr NEON3SameOp NEON_SMAX = NEON3SameFixed | 0x00006000;
constexpr NEON3SameOp NEON_SMAXP = NEON3SameFixed | 0x0000A000;
constexpr NEON3SameOp NEON_SMIN = NEON3SameFixed | 0x00006800;
constexpr NEON3SameOp NEON_SMINP = NEON3SameFixed | 0x0000A800;
constexpr NEON3SameOp NEON_SABD = NEON3SameFixed | 0x00007000;
constexpr NEON3SameOp NEON_SABA = NEON3SameFixed | 0x00007800;
constexpr NEON3SameOp NEON_UABD = NEON3SameFixed | NEON3SameUBit | NEON_SABD;
constexpr NEON3SameOp NEON_UABA = NEON3SameFixed | NEON3SameUBit | NEON_SABA;
constexpr NEON3SameOp NEON_SQADD = NEON3SameFixed | 0x00000800;
constexpr NEON3SameOp NEON_SQSUB = NEON3SameFixed | 0x00002800;
constexpr NEON3SameOp NEON_SUB = NEON3SameFixed | NEON3SameUBit | 0x00008000;
constexpr NEON3SameOp NEON_UHADD = NEON3SameFixed | NEON3SameUBit | NEON_SHADD;
constexpr NEON3SameOp NEON_UHSUB = NEON3SameFixed | NEON3SameUBit | NEON_SHSUB;
constexpr NEON3SameOp NEON_URHADD =
    NEON3SameFixed | NEON3SameUBit | NEON_SRHADD;
constexpr NEON3SameOp NEON_UMAX = NEON3SameFixed | NEON3SameUBit | NEON_SMAX;
constexpr NEON3SameOp NEON_UMAXP = NEON3SameFixed | NEON3SameUBit | NEON_SMAXP;
constexpr NEON3SameOp NEON_UMIN = NEON3SameFixed | NEON3SameUBit | NEON_SMIN;
constexpr NEON3SameOp NEON_UMINP = NEON3SameFixed | NEON3SameUBit | NEON_SMINP;
constexpr NEON3SameOp NEON_URSHL = NEON3SameFixed | NEON3SameUBit | NEON_SRSHL;
constexpr NEON3SameOp NEON_UQADD = NEON3SameFixed | NEON3SameUBit | NEON_SQADD;
constexpr NEON3SameOp NEON_UQRSHL =
    NEON3SameFixed | NEON3SameUBit | NEON_SQRSHL;
constexpr NEON3SameOp NEON_UQSHL = NEON3SameFixed | NEON3SameUBit | NEON_SQSHL;
constexpr NEON3SameOp NEON_UQSUB = NEON3SameFixed | NEON3SameUBit | NEON_SQSUB;
constexpr NEON3SameOp NEON_USHL = NEON3SameFixed | NEON3SameUBit | NEON_SSHL;
constexpr NEON3SameOp NEON_SQDMULH = NEON3SameFixed | 0x0000B000;
constexpr NEON3SameOp NEON_SQRDMULH = NEON3SameFixed | 0x2000B000;

// NEON floating point instructions with three same-type operands.
constexpr NEON3SameOp NEON3SameFPFixed = NEON3SameFixed | 0x0000C000;
constexpr NEON3SameOp NEON3SameFPFMask = NEON3SameFMask | 0x0000C000;
constexpr NEON3SameOp NEON3SameFPMask = NEON3SameMask | 0x00800000;
constexpr NEON3SameOp NEON_FADD = NEON3SameFixed | 0x0000D000;
constexpr NEON3SameOp NEON_FSUB = NEON3SameFixed | 0x0080D000;
constexpr NEON3SameOp NEON_FMUL = NEON3SameFixed | 0x2000D800;
constexpr NEON3SameOp NEON_FDIV = NEON3SameFixed | 0x2000F800;
constexpr NEON3SameOp NEON_FMAX = NEON3SameFixed | 0x0000F000;
constexpr NEON3SameOp NEON_FMAXNM = NEON3SameFixed | 0x0000C000;
constexpr NEON3SameOp NEON_FMAXP = NEON3SameFixed | 0x2000F000;
constexpr NEON3SameOp NEON_FMAXNMP = NEON3SameFixed | 0x2000C000;
constexpr NEON3SameOp NEON_FMIN = NEON3SameFixed | 0x0080F000;
constexpr NEON3SameOp NEON_FMINNM = NEON3SameFixed | 0x0080C000;
constexpr NEON3SameOp NEON_FMINP = NEON3SameFixed | 0x2080F000;
constexpr NEON3SameOp NEON_FMINNMP = NEON3SameFixed | 0x2080C000;
constexpr NEON3SameOp NEON_FMLA = NEON3SameFixed | 0x0000C800;
constexpr NEON3SameOp NEON_FMLS = NEON3SameFixed | 0x0080C800;
constexpr NEON3SameOp NEON_FMULX = NEON3SameFixed | 0x0000D800;
constexpr NEON3SameOp NEON_FRECPS = NEON3SameFixed | 0x0000F800;
constexpr NEON3SameOp NEON_FRSQRTS = NEON3SameFixed | 0x0080F800;
constexpr NEON3SameOp NEON_FABD = NEON3SameFixed | 0x2080D000;
constexpr NEON3SameOp NEON_FADDP = NEON3SameFixed | 0x2000D000;
constexpr NEON3SameOp NEON_FCMEQ = NEON3SameFixed | 0x0000E000;
constexpr NEON3SameOp NEON_FCMGE = NEON3SameFixed | 0x2000E000;
constexpr NEON3SameOp NEON_FCMGT = NEON3SameFixed | 0x2080E000;
constexpr NEON3SameOp NEON_FACGE = NEON3SameFixed | 0x2000E800;
constexpr NEON3SameOp NEON_FACGT = NEON3SameFixed | 0x2080E800;

constexpr NEON3SameOp NEON3SameHPMask = 0x0020C000;
constexpr NEON3SameOp NEON3SameHPFixed = 0x0E400400;
constexpr NEON3SameOp NEON3SameHPFMask = 0x9F400400;

// NEON logical instructions with three same-type operands.
constexpr NEON3SameOp NEON3SameLogicalFixed = NEON3SameFixed | 0x00001800;
constexpr NEON3SameOp NEON3SameLogicalFMask = NEON3SameFMask | 0x0000F800;
constexpr NEON3SameOp NEON3SameLogicalMask = 0xBFE0FC00;
constexpr NEON3SameOp NEON3SameLogicalFormatMask = NEON_Q;
constexpr NEON3SameOp NEON_AND = NEON3SameLogicalFixed | 0x00000000;
constexpr NEON3SameOp NEON_ORR = NEON3SameLogicalFixed | 0x00A00000;
constexpr NEON3SameOp NEON_ORN = NEON3SameLogicalFixed | 0x00C00000;
constexpr NEON3SameOp NEON_EOR = NEON3SameLogicalFixed | 0x20000000;
constexpr NEON3SameOp NEON_BIC = NEON3SameLogicalFixed | 0x00400000;
constexpr NEON3SameOp NEON_BIF = NEON3SameLogicalFixed | 0x20C00000;
constexpr NEON3SameOp NEON_BIT = NEON3SameLogicalFixed | 0x20800000;
constexpr NEON3SameOp NEON_BSL = NEON3SameLogicalFixed | 0x20400000;

// NEON instructions with three different-type operands.
using NEON3DifferentOp = uint32_t;
constexpr NEON3DifferentOp NEON3DifferentFixed = 0x0E200000;
constexpr NEON3DifferentOp NEON3DifferentDot = 0x0E800000;
constexpr NEON3DifferentOp NEON3DifferentFMask = 0x9F200C00;
constexpr NEON3DifferentOp NEON3DifferentMask = 0xFF20FC00;
constexpr NEON3DifferentOp NEON_ADDHN = NEON3DifferentFixed | 0x00004000;
constexpr NEON3DifferentOp NEON_ADDHN2 = NEON_ADDHN | NEON_Q;
constexpr NEON3DifferentOp NEON_PMULL = NEON3DifferentFixed | 0x0000E000;
constexpr NEON3DifferentOp NEON_PMULL2 = NEON_PMULL | NEON_Q;
constexpr NEON3DifferentOp NEON_RADDHN = NEON3DifferentFixed | 0x20004000;
constexpr NEON3DifferentOp NEON_RADDHN2 = NEON_RADDHN | NEON_Q;
constexpr NEON3DifferentOp NEON_RSUBHN = NEON3DifferentFixed | 0x20006000;
constexpr NEON3DifferentOp NEON_RSUBHN2 = NEON_RSUBHN | NEON_Q;
constexpr NEON3DifferentOp NEON_SABAL = NEON3DifferentFixed | 0x00005000;
constexpr NEON3DifferentOp NEON_SABAL2 = NEON_SABAL | NEON_Q;
constexpr NEON3DifferentOp NEON_SABDL = NEON3DifferentFixed | 0x00007000;
constexpr NEON3DifferentOp NEON_SABDL2 = NEON_SABDL | NEON_Q;
constexpr NEON3DifferentOp NEON_SADDL = NEON3DifferentFixed | 0x00000000;
constexpr NEON3DifferentOp NEON_SADDL2 = NEON_SADDL | NEON_Q;
constexpr NEON3DifferentOp NEON_SADDW = NEON3DifferentFixed | 0x00001000;
constexpr NEON3DifferentOp NEON_SADDW2 = NEON_SADDW | NEON_Q;
constexpr NEON3DifferentOp NEON_SMLAL = NEON3DifferentFixed | 0x00008000;
constexpr NEON3DifferentOp NEON_SMLAL2 = NEON_SMLAL | NEON_Q;
constexpr NEON3DifferentOp NEON_SMLSL = NEON3DifferentFixed | 0x0000A000;
constexpr NEON3DifferentOp NEON_SMLSL2 = NEON_SMLSL | NEON_Q;
constexpr NEON3DifferentOp NEON_SMULL = NEON3DifferentFixed | 0x0000C000;
constexpr NEON3DifferentOp NEON_SMULL2 = NEON_SMULL | NEON_Q;
constexpr NEON3DifferentOp NEON_SSUBL = NEON3DifferentFixed | 0x00002000;
constexpr NEON3DifferentOp NEON_SSUBL2 = NEON_SSUBL | NEON_Q;
constexpr NEON3DifferentOp NEON_SSUBW = NEON3DifferentFixed | 0x00003000;
constexpr NEON3DifferentOp NEON_SSUBW2 = NEON_SSUBW | NEON_Q;
constexpr NEON3DifferentOp NEON_SQDMLAL = NEON3DifferentFixed | 0x00009000;
constexpr NEON3DifferentOp NEON_SQDMLAL2 = NEON_SQDMLAL | NEON_Q;
constexpr NEON3DifferentOp NEON_SQDMLSL = NEON3DifferentFixed | 0x0000B000;
constexpr NEON3DifferentOp NEON_SQDMLSL2 = NEON_SQDMLSL | NEON_Q;
constexpr NEON3DifferentOp NEON_SQDMULL = NEON3DifferentFixed | 0x0000D000;
constexpr NEON3DifferentOp NEON_SQDMULL2 = NEON_SQDMULL | NEON_Q;
constexpr NEON3DifferentOp NEON_SUBHN = NEON3DifferentFixed | 0x00006000;
constexpr NEON3DifferentOp NEON_SUBHN2 = NEON_SUBHN | NEON_Q;
constexpr NEON3DifferentOp NEON_UABAL = NEON_SABAL | NEON3SameUBit;
constexpr NEON3DifferentOp NEON_UABAL2 = NEON_UABAL | NEON_Q;
constexpr NEON3DifferentOp NEON_UABDL = NEON_SABDL | NEON3SameUBit;
constexpr NEON3DifferentOp NEON_UABDL2 = NEON_UABDL | NEON_Q;
constexpr NEON3DifferentOp NEON_UADDL = NEON_SADDL | NEON3SameUBit;
constexpr NEON3DifferentOp NEON_UADDL2 = NEON_UADDL | NEON_Q;
constexpr NEON3DifferentOp NEON_UADDW = NEON_SADDW | NEON3SameUBit;
constexpr NEON3DifferentOp NEON_UADDW2 = NEON_UADDW | NEON_Q;
constexpr NEON3DifferentOp NEON_UMLAL = NEON_SMLAL | NEON3SameUBit;
constexpr NEON3DifferentOp NEON_UMLAL2 = NEON_UMLAL | NEON_Q;
constexpr NEON3DifferentOp NEON_UMLSL = NEON_SMLSL | NEON3SameUBit;
constexpr NEON3DifferentOp NEON_UMLSL2 = NEON_UMLSL | NEON_Q;
constexpr NEON3DifferentOp NEON_UMULL = NEON_SMULL | NEON3SameUBit;
constexpr NEON3DifferentOp NEON_UMULL2 = NEON_UMULL | NEON_Q;
constexpr NEON3DifferentOp NEON_USUBL = NEON_SSUBL | NEON3SameUBit;
constexpr NEON3DifferentOp NEON_USUBL2 = NEON_USUBL | NEON_Q;
constexpr NEON3DifferentOp NEON_USUBW = NEON_SSUBW | NEON3SameUBit;
constexpr NEON3DifferentOp NEON_USUBW2 = NEON_USUBW | NEON_Q;

// NEON instructions with three operands and extension.
using NEON3ExtensionOp = uint32_t;
constexpr NEON3ExtensionOp NEON3ExtensionFixed = 0x0E008400;
constexpr NEON3ExtensionOp NEON3ExtensionFMask = 0x9F208400;
constexpr NEON3ExtensionOp NEON3ExtensionMask = 0xBF20FC00;
constexpr NEON3ExtensionOp NEON_SDOT = NEON3ExtensionFixed | 0x00001000;

// NEON instructions operating across vectors.
using NEONAcrossLanesOp = uint32_t;
constexpr NEONAcrossLanesOp NEONAcrossLanesFixed = 0x0E300800;
constexpr NEONAcrossLanesOp NEONAcrossLanesFMask = 0x9F3E0C00;
constexpr NEONAcrossLanesOp NEONAcrossLanesMask = 0xBF3FFC00;
constexpr NEONAcrossLanesOp NEON_ADDV = NEONAcrossLanesFixed | 0x0001B000;
constexpr NEONAcrossLanesOp NEON_SADDLV = NEONAcrossLanesFixed | 0x00003000;
constexpr NEONAcrossLanesOp NEON_UADDLV = NEONAcrossLanesFixed | 0x20003000;
constexpr NEONAcrossLanesOp NEON_SMAXV = NEONAcrossLanesFixed | 0x0000A000;
constexpr NEONAcrossLanesOp NEON_SMINV = NEONAcrossLanesFixed | 0x0001A000;
constexpr NEONAcrossLanesOp NEON_UMAXV = NEONAcrossLanesFixed | 0x2000A000;
constexpr NEONAcrossLanesOp NEON_UMINV = NEONAcrossLanesFixed | 0x2001A000;

// NEON floating point across instructions.
constexpr NEONAcrossLanesOp NEONAcrossLanesFPFixed =
    NEONAcrossLanesFixed | 0x0000C000;
constexpr NEONAcrossLanesOp NEONAcrossLanesFPFMask =
    NEONAcrossLanesFMask | 0x0000C000;
constexpr NEONAcrossLanesOp NEONAcrossLanesFPMask =
    NEONAcrossLanesMask | 0x00800000;

constexpr NEONAcrossLanesOp NEON_FMAXV = NEONAcrossLanesFPFixed | 0x2000F000;
constexpr NEONAcrossLanesOp NEON_FMINV = NEONAcrossLanesFPFixed | 0x2080F000;
constexpr NEONAcrossLanesOp NEON_FMAXNMV = NEONAcrossLanesFPFixed | 0x2000C000;
constexpr NEONAcrossLanesOp NEON_FMINNMV = NEONAcrossLanesFPFixed | 0x2080C000;

// NEON instructions with indexed element operand.
using NEONByIndexedElementOp = uint32_t;
constexpr NEONByIndexedElementOp NEONByIndexedElementFixed = 0x0F000000;
constexpr NEONByIndexedElementOp NEONByIndexedElementFMask = 0x9F000400;
constexpr NEONByIndexedElementOp NEONByIndexedElementMask = 0xBF00F400;
constexpr NEONByIndexedElementOp NEON_MUL_byelement =
    NEONByIndexedElementFixed | 0x00008000;
constexpr NEONByIndexedElementOp NEON_MLA_byelement =
    NEONByIndexedElementFixed | 0x20000000;
constexpr NEONByIndexedElementOp NEON_MLS_byelement =
    NEONByIndexedElementFixed | 0x20004000;
constexpr NEONByIndexedElementOp NEON_SMULL_byelement =
    NEONByIndexedElementFixed | 0x0000A000;
constexpr NEONByIndexedElementOp NEON_SMLAL_byelement =
    NEONByIndexedElementFixed | 0x00002000;
constexpr NEONByIndexedElementOp NEON_SMLSL_byelement =
    NEONByIndexedElementFixed | 0x00006000;
constexpr NEONByIndexedElementOp NEON_UMULL_byelement =
    NEONByIndexedElementFixed | 0x2000A000;
constexpr NEONByIndexedElementOp NEON_UMLAL_byelement =
    NEONByIndexedElementFixed | 0x20002000;
constexpr NEONByIndexedElementOp NEON_UMLSL_byelement =
    NEONByIndexedElementFixed | 0x20006000;
constexpr NEONByIndexedElementOp NEON_SQDMULL_byelement =
    NEONByIndexedElementFixed | 0x0000B000;
constexpr NEONByIndexedElementOp NEON_SQDMLAL_byelement =
    NEONByIndexedElementFixed | 0x00003000;
constexpr NEONByIndexedElementOp NEON_SQDMLSL_byelement =
    NEONByIndexedElementFixed | 0x00007000;
constexpr NEONByIndexedElementOp NEON_SQDMULH_byelement =
    NEONByIndexedElementFixed | 0x0000C000;
constexpr NEONByIndexedElementOp NEON_SQRDMULH_byelement =
    NEONByIndexedElementFixed | 0x0000D000;

// Floating point instructions.
constexpr NEONByIndexedElementOp NEONByIndexedElementFPFixed =
    NEONByIndexedElementFixed | 0x00800000;
constexpr NEONByIndexedElementOp NEONByIndexedElementFPMask =
    NEONByIndexedElementMask | 0x00800000;
constexpr NEONByIndexedElementOp NEON_FMLA_byelement =
    NEONByIndexedElementFPFixed | 0x00001000;
constexpr NEONByIndexedElementOp NEON_FMLS_byelement =
    NEONByIndexedElementFPFixed | 0x00005000;
constexpr NEONByIndexedElementOp NEON_FMUL_byelement =
    NEONByIndexedElementFPFixed | 0x00009000;
constexpr NEONByIndexedElementOp NEON_FMULX_byelement =
    NEONByIndexedElementFPFixed | 0x20009000;

// NEON modified immediate.
using NEONModifiedImmediateOp = uint32_t;
constexpr NEONModifiedImmediateOp NEONModifiedImmediateFixed = 0x0F000400;
constexpr NEONModifiedImmediateOp NEONModifiedImmediateFMask = 0x9FF80400;
constexpr NEONModifiedImmediateOp NEONModifiedImmediateOpBit = 0x20000000;
constexpr NEONModifiedImmediateOp NEONModifiedImmediate_MOVI =
    NEONModifiedImmediateFixed | 0x00000000;
constexpr NEONModifiedImmediateOp NEONModifiedImmediate_MVNI =
    NEONModifiedImmediateFixed | 0x20000000;
constexpr NEONModifiedImmediateOp NEONModifiedImmediate_ORR =
    NEONModifiedImmediateFixed | 0x00001000;
constexpr NEONModifiedImmediateOp NEONModifiedImmediate_BIC =
    NEONModifiedImmediateFixed | 0x20001000;

// NEON extract.
using NEONExtractOp = uint32_t;
constexpr NEONExtractOp NEONExtractFixed = 0x2E000000;
constexpr NEONExtractOp NEONExtractFMask = 0xBF208400;
constexpr NEONExtractOp NEONExtractMask = 0xBFE08400;
constexpr NEONExtractOp NEON_EXT = NEONExtractFixed | 0x00000000;

using NEONLoadStoreMultiOp = uint32_t;
constexpr NEONLoadStoreMultiOp NEONLoadStoreMultiL = 0x00400000;
constexpr NEONLoadStoreMultiOp NEONLoadStoreMulti1_1v = 0x00007000;
constexpr NEONLoadStoreMultiOp NEONLoadStoreMulti1_2v = 0x0000A000;
constexpr NEONLoadStoreMultiOp NEONLoadStoreMulti1_3v = 0x00006000;
constexpr NEONLoadStoreMultiOp NEONLoadStoreMulti1_4v = 0x00002000;
constexpr NEONLoadStoreMultiOp NEONLoadStoreMulti2 = 0x00008000;
constexpr NEONLoadStoreMultiOp NEONLoadStoreMulti3 = 0x00004000;
constexpr NEONLoadStoreMultiOp NEONLoadStoreMulti4 = 0x00000000;

// NEON load/store multiple structures.
using NEONLoadStoreMultiStructOp = uint32_t;
constexpr NEONLoadStoreMultiStructOp NEONLoadStoreMultiStructFixed = 0x0C000000;
constexpr NEONLoadStoreMultiStructOp NEONLoadStoreMultiStructFMask = 0xBFBF0000;
constexpr NEONLoadStoreMultiStructOp NEONLoadStoreMultiStructMask = 0xBFFFF000;
constexpr NEONLoadStoreMultiStructOp NEONLoadStoreMultiStructStore =
    NEONLoadStoreMultiStructFixed;
constexpr NEONLoadStoreMultiStructOp NEONLoadStoreMultiStructLoad =
    NEONLoadStoreMultiStructFixed | NEONLoadStoreMultiL;
constexpr NEONLoadStoreMultiStructOp NEON_LD1_1v =
    NEONLoadStoreMultiStructLoad | NEONLoadStoreMulti1_1v;
constexpr NEONLoadStoreMultiStructOp NEON_LD1_2v =
    NEONLoadStoreMultiStructLoad | NEONLoadStoreMulti1_2v;
constexpr NEONLoadStoreMultiStructOp NEON_LD1_3v =
    NEONLoadStoreMultiStructLoad | NEONLoadStoreMulti1_3v;
constexpr NEONLoadStoreMultiStructOp NEON_LD1_4v =
    NEONLoadStoreMultiStructLoad | NEONLoadStoreMulti1_4v;
constexpr NEONLoadStoreMultiStructOp NEON_LD2 =
    NEONLoadStoreMultiStructLoad | NEONLoadStoreMulti2;
constexpr NEONLoadStoreMultiStructOp NEON_LD3 =
    NEONLoadStoreMultiStructLoad | NEONLoadStoreMulti3;
constexpr NEONLoadStoreMultiStructOp NEON_LD4 =
    NEONLoadStoreMultiStructLoad | NEONLoadStoreMulti4;
constexpr NEONLoadStoreMultiStructOp NEON_ST1_1v =
    NEONLoadStoreMultiStructStore | NEONLoadStoreMulti1_1v;
constexpr NEONLoadStoreMultiStructOp NEON_ST1_2v =
    NEONLoadStoreMultiStructStore | NEONLoadStoreMulti1_2v;
constexpr NEONLoadStoreMultiStructOp NEON_ST1_3v =
    NEONLoadStoreMultiStructStore | NEONLoadStoreMulti1_3v;
constexpr NEONLoadStoreMultiStructOp NEON_ST1_4v =
    NEONLoadStoreMultiStructStore | NEONLoadStoreMulti1_4v;
constexpr NEONLoadStoreMultiStructOp NEON_ST2 =
    NEONLoadStoreMultiStructStore | NEONLoadStoreMulti2;
constexpr NEONLoadStoreMultiStructOp NEON_ST3 =
    NEONLoadStoreMultiStructStore | NEONLoadStoreMulti3;
constexpr NEONLoadStoreMultiStructOp NEON_ST4 =
    NEONLoadStoreMultiStructStore | NEONLoadStoreMulti4;

// NEON load/store multiple structures with post-index addressing.
using NEONLoadStoreMultiStructPostIndexOp = uint32_t;
constexpr NEONLoadStoreMultiStructPostIndexOp
    NEONLoadStoreMultiStructPostIndexFixed = 0x0C800000;
constexpr NEONLoadStoreMultiStructPostIndexOp
    NEONLoadStoreMultiStructPostIndexFMask = 0xBFA00000;
constexpr NEONLoadStoreMultiStructPostIndexOp
    NEONLoadStoreMultiStructPostIndexMask = 0xBFE0F000;
constexpr NEONLoadStoreMultiStructPostIndexOp
    NEONLoadStoreMultiStructPostIndex = 0x00800000;
constexpr NEONLoadStoreMultiStructPostIndexOp NEON_LD1_1v_post =
    NEON_LD1_1v | NEONLoadStoreMultiStructPostIndex;
constexpr NEONLoadStoreMultiStructPostIndexOp NEON_LD1_2v_post =
    NEON_LD1_2v | NEONLoadStoreMultiStructPostIndex;
constexpr NEONLoadStoreMultiStructPostIndexOp NEON_LD1_3v_post =
    NEON_LD1_3v | NEONLoadStoreMultiStructPostIndex;
constexpr NEONLoadStoreMultiStructPostIndexOp NEON_LD1_4v_post =
    NEON_LD1_4v | NEONLoadStoreMultiStructPostIndex;
constexpr NEONLoadStoreMultiStructPostIndexOp NEON_LD2_post =
    NEON_LD2 | NEONLoadStoreMultiStructPostIndex;
constexpr NEONLoadStoreMultiStructPostIndexOp NEON_LD3_post =
    NEON_LD3 | NEONLoadStoreMultiStructPostIndex;
constexpr NEONLoadStoreMultiStructPostIndexOp NEON_LD4_post =
    NEON_LD4 | NEONLoadStoreMultiStructPostIndex;
constexpr NEONLoadStoreMultiStructPostIndexOp NEON_ST1_1v_post =
    NEON_ST1_1v | NEONLoadStoreMultiStructPostIndex;
constexpr NEONLoadStoreMultiStructPostIndexOp NEON_ST1_2v_post =
    NEON_ST1_2v | NEONLoadStoreMultiStructPostIndex;
constexpr NEONLoadStoreMultiStructPostIndexOp NEON_ST1_3v_post =
    NEON_ST1_3v | NEONLoadStoreMultiStructPostIndex;
constexpr NEONLoadStoreMultiStructPostIndexOp NEON_ST1_4v_post =
    NEON_ST1_4v | NEONLoadStoreMultiStructPostIndex;
constexpr NEONLoadStoreMultiStructPostIndexOp NEON_ST2_post =
    NEON_ST2 | NEONLoadStoreMultiStructPostIndex;
constexpr NEONLoadStoreMultiStructPostIndexOp NEON_ST3_post =
    N
```