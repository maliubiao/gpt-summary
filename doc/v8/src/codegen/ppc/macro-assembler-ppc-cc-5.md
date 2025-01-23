Response:
The user wants a summary of the provided C++ code snippet from `v8/src/codegen/ppc/macro-assembler-ppc.cc`. The summary should cover:

1. **Functionality:** What does this code do?
2. **Torque Source:**  Is it a Torque file (based on the `.tq` extension)?
3. **JavaScript Relation:** If it relates to JavaScript functionality, provide a JavaScript example.
4. **Code Logic/Inference:** If there are logical operations, provide example inputs and outputs.
5. **Common Programming Errors:**  Are there examples of common errors?
6. **Overall Functionality (Part 6 of 7):**  Summarize the functionality of this specific part within the larger file.

Let's break down the code and address each point.

**Code Analysis:**

The code consists of various methods within the `MacroAssembler` class for the PPC architecture in V8. These methods primarily deal with:

* **SIMD (Vector) Operations:**  Many functions operate on `Simd128Register` types, performing operations like conversion, bit manipulation, dot products, shuffling, swizzling, and extending.
* **Memory Access with Lanes:**  Functions like `LoadLaneXXLE` and `StoreLaneXXLE` deal with loading and storing specific lanes (parts) of SIMD registers from/to memory. The `LE` suffix suggests little-endian handling.
* **Register/Memory Swapping:**  Functions like `SwapP`, `SwapFloat32`, `SwapDouble`, and `SwapSimd128` are for exchanging the values in registers and memory locations.
* **Bit Manipulation:** Functions for byte reversing (`ByteReverseUXX`), counting leading/trailing zeros, and reversing bits.
* **Builtin Calls:** Functions for calling pre-defined V8 functions (`CallBuiltinByIndex`, `LoadEntryFromBuiltin`).
* **Code Object Handling:** Functions for loading and calling code objects (`LoadCodeInstructionStart`, `CallCodeObject`, `JumpCodeObject`).
* **JS Function Calls:** Functions for calling JavaScript functions (`CallJSFunction`, `JumpJSFunction`).
* **Deoptimization Handling:**  Functions related to bailing out if code is deoptimized (`BailoutIfDeoptimized`, `CallForDeoptimization`).
* **Zero Extension:** Functions to zero-extend values to larger sizes.

**Addressing the User's Points:**

1. **Functionality:** This code defines a set of low-level operations (macros) for the PPC architecture within the V8 JavaScript engine. These macros are used to generate machine code for various JavaScript functionalities and internal V8 operations, especially those involving SIMD and memory manipulation.

2. **Torque Source:** The prompt explicitly states how to identify Torque files. Since the filename ends in `.cc`, it is **not** a Torque source file.

3. **JavaScript Relation:**  The SIMD operations have a direct relationship to the JavaScript SIMD API (e.g., `Float32x4`, `Int32x4`). The builtin and JS function call functions are fundamental to how JavaScript code execution is managed.

4. **Code Logic/Inference:** Let's take `I32x4ExtAddPairwiseI16x8S` as an example:

   * **Assumption:** `src` contains eight 16-bit signed integers.
   * **Input `src` (example):**  `[1, 2, 3, 4, 5, 6, 7, 8]` (representing the 16-bit values)
   * **Logic:**
     * `vspltish(scratch1, Operand(1))`:  Creates a SIMD register `scratch1` with the value `1` in each of its 16-bit lanes.
     * `vmulesh(scratch2, src, scratch1)`: Multiplies the even-indexed 16-bit elements of `src` by the corresponding element of `scratch1` (which is always 1). So `scratch2` will contain `[1*1, _, 3*1, _, 5*1, _, 7*1, _]`.
     * `vmulosh(scratch1, src, scratch1)`: Multiplies the odd-indexed 16-bit elements of `src` by the corresponding element of `scratch1`. So `scratch1` will contain `[_, 2*1, _, 4*1, _, 6*1, _, 8*1]`.
     * `vadduwm(dst, scratch2, scratch1)`: Adds the corresponding 32-bit elements of `scratch2` and `scratch1`.
   * **Output `dst`:** `[1+2, 3+4, 5+6, 7+8]`  => `[3, 7, 11, 15]` (as 32-bit integers).

5. **Common Programming Errors:**

   * **Incorrect Register Usage:**  Many functions take scratch registers as arguments. A common error would be to pass a register that's already in use, leading to data corruption. For example, in `I16x8UConvertI8x16Low`, if `scratch1` or `scratch2` held important values, those values would be overwritten.
   * **Incorrect Lane Indexing:**  In the `LoadLane` and `StoreLane` functions, providing an out-of-bounds lane index would lead to unexpected memory access or program crashes. For instance, `LoadLane64LE(dst, mem, 2, ...)` would be invalid as there are only two 64-bit lanes in a 128-bit register (indices 0 and 1).
   * **Endianness Issues:** The `LE` suffix signifies little-endian. Assuming big-endian memory layout when using these functions would result in incorrect data interpretation.
   * **Forgetting Scratch Registers:**  Some operations require temporary registers. Not providing enough scratch registers can cause issues.

   **JavaScript Example (illustrating potential errors with SIMD):**

   ```javascript
   const a = Float32x4(1, 2, 3, 4);
   const b = Float32x4(5, 6, 7, 8);

   // Potential error: Incorrectly assuming the result will be stored in 'a'
   // without assigning it back.
   a.add(b);
   console.log(a); // Output: Float32x4 { 1, 2, 3, 4 } - 'a' is unchanged.

   // Correct usage:
   const c = a.add(b);
   console.log(c); // Output: Float32x4 { 6, 8, 10, 12 }

   // Potential error: Accessing an invalid lane (index out of bounds)
   // This would likely throw an error in JavaScript but highlights the
   // underlying complexity the C++ code handles.
   // a.getLane(4); // Error!
   ```

6. **Overall Functionality (Part 6 of 7):** This section of the `macro-assembler-ppc.cc` file focuses heavily on implementing **SIMD (Single Instruction, Multiple Data) operations** for the PPC architecture. It provides a collection of low-level functions that enable efficient manipulation of 128-bit vectors of data. It also includes functions for memory access with lane specificity, register and memory swapping, bit manipulation utilities, and some foundational elements for interacting with built-in functions and managing code execution (though less prominently than SIMD in this specific part). The presence of `LE` functions indicates a focus on little-endian byte order.

这是 `v8/src/codegen/ppc/macro-assembler-ppc.cc` 文件的一部分，它为 V8 JavaScript 引擎在 PowerPC (PPC) 架构上生成机器码提供了一组宏汇编指令。

**功能归纳:**

这部分代码主要集中在实现 **SIMD (Single Instruction, Multiple Data)** 相关的操作，以及一些辅助的内存操作、寄存器操作和位操作。具体功能包括：

* **SIMD 数据类型转换:**  提供了各种 SIMD 数据类型之间的转换操作，例如从 8 位整数转换为 16 位整数，并可以选择进行符号扩展或零扩展。例如 `I16x8SConvertI8x16Low` 将一个 128 位寄存器中低 8 位的 8 位有符号整数转换为 16 位有符号整数并存储到目标寄存器中。
* **SIMD 位掩码生成:** `I8x16BitMask` 用于生成一个基于 SIMD 寄存器中每个字节的最高位的位掩码。
* **SIMD 点积运算:** 提供了不同数据类型的 SIMD 点积运算，例如 `I32x4DotI16x8S` 计算两个 SIMD 寄存器中 16 位整数的带符号点积，结果为 32 位整数。
* **SIMD 乘法和加法运算:**  实现了 SIMD 数据的乘法和加法运算，例如 `I16x8DotI8x16S` 计算两个 SIMD 寄存器中 8 位整数的乘积，并将结果累加。
* **SIMD 饱和乘法:** `I16x8Q15MulRSatS` 执行带饱和的 Q15 格式的 SIMD 乘法。
* **SIMD 数据重排和混洗:**  提供了 SIMD 数据的重排和混洗操作，允许根据索引重新排列 SIMD 寄存器中的元素。`I8x16Swizzle` 和 `I8x16Shuffle` 提供了不同的混洗方式。
* **SIMD 成对扩展和加法:**  提供了将 SIMD 寄存器中的元素成对扩展并相加的操作，例如 `I32x4ExtAddPairwiseI16x8S` 将 8 个 16 位整数成对扩展为 32 位整数并相加。
* **SIMD 单通道操作:** 提供了访问和操作 SIMD 寄存器中特定通道（lane）的功能，例如 `F64x2PromoteLowF32x4` 将一个 `Float32x4` 寄存器低 64 位提升为 `Float64x2` 寄存器。
* **SIMD 寄存器与内存之间的数据交换:** 提供了将 SIMD 寄存器中的数据加载和存储到内存特定通道的功能，并考虑了字节序 (Little-Endian)。例如 `LoadLane64LE` 从内存中加载 64 位数据并将其放入 SIMD 寄存器的指定通道。
* **SIMD 寄存器值的复制和扩展加载:** 提供了从内存加载数据并复制到 SIMD 寄存器的所有通道，以及加载并扩展数据到更大的 SIMD 数据类型的功能。
* **SIMD 寄存器的零值加载:**  `LoadV64ZeroLE` 和 `LoadV32ZeroLE` 从内存加载部分数据，并将 SIMD 寄存器的剩余部分置零。
* **SIMD 逻辑运算:** 提供了 SIMD 寄存器的逻辑运算，例如 `V128AnyTrue` 判断 SIMD 寄存器中是否有任何非零元素， `S128Not` 对 SIMD 寄存器进行按位取反，`S128Select` 根据掩码选择两个 SIMD 寄存器的元素。
* **寄存器和内存值的交换:** 提供了各种数据类型（通用寄存器、浮点寄存器、SIMD 寄存器）在寄存器之间以及寄存器与内存之间进行值交换的功能。 例如 `SwapP` 用于交换两个通用寄存器的值。
* **字节序反转:** 提供了字节序反转的指令，例如 `ByteReverseU16` 用于反转 16 位无符号整数的字节序。
* **条件跳转:** `JumpIfEqual` 和 `JumpIfLessThan` 提供基于通用寄存器值与立即数比较结果的条件跳转指令。
* **内置函数调用:**  提供了加载内置函数入口地址并调用的功能，例如 `LoadEntryFromBuiltinIndex` 和 `CallBuiltinByIndex`。
* **代码对象和 JS 函数调用:**  提供了加载代码对象入口点并调用，以及调用 JavaScript 函数的功能，例如 `CallCodeObject` 和 `CallJSFunction`。
* **处理反优化:** `BailoutIfDeoptimized` 检查代码对象是否被标记为反优化，如果是则跳转到反优化处理的内置函数。
* **零扩展:**  提供了将寄存器中的低位部分零扩展到高位的功能，例如 `ZeroExtByte` 将寄存器中的 8 位值零扩展到 64 位。
* **调试和错误处理:** `Trap` 和 `DebugBreak` 用于插入断点或触发陷阱。
* **位操作:** 提供了位计数、前导零计数、尾随零计数等位操作指令。
* **字节清除和位反转:**  提供了清除寄存器中特定字节以及反转寄存器中位的功能。

**关于 .tq 结尾:**

正如代码注释中所述，如果 `v8/src/codegen/ppc/macro-assembler-ppc.cc` 以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。由于当前文件以 `.cc` 结尾，因此它是一个 **C++** 源代码文件。

**与 JavaScript 功能的关系及示例:**

这部分代码中的 SIMD 操作与 JavaScript 中的 [SIMD API](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Global_Objects/SIMD) 有着直接的联系。 JavaScript SIMD API 允许开发者在 JavaScript 中使用 SIMD 指令来执行并行计算，提高性能。

**JavaScript 示例:**

```javascript
// 假设 JavaScript 引擎使用了上述 C++ 代码中的 I32x4ExtAddPairwiseI16x8S

const a = new Int16Array([1, 2, 3, 4, 5, 6, 7, 8]);
const b = SIMD.Int16x8(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);

// 模拟 I32x4ExtAddPairwiseI16x8S 的功能
const result = SIMD.Int32x4(
  b.extractLane(0) + b.extractLane(1),
  b.extractLane(2) + b.extractLane(3),
  b.extractLane(4) + b.extractLane(5),
  b.extractLane(6) + b.extractLane(7)
);

console.log(result); // 输出: Int32x4 { 3, 7, 11, 15 }
```

在这个例子中，`SIMD.Int16x8` 和 `SIMD.Int32x4` 对应了 C++ 代码中操作的 SIMD 寄存器类型。`I32x4ExtAddPairwiseI16x8S` 的功能是将 `Int16x8` 中相邻的两个 16 位整数扩展为 32 位并相加，得到一个 `Int32x4` 的结果。

**代码逻辑推理 (示例):**

**假设输入:**

* `dst` (Simd128Register):  初始状态不重要，将被覆盖。
* `src` (Simd128Register): 包含 16 个 8 位有符号整数，例如 `[1, 2, 3, 4, 5, 6, 7, 8, -1, -2, -3, -4, -5, -6, -7, -8]`。
* `scratch1` (Register):  作为临时寄存器使用。
* `scratch2` (Simd128Register): 作为临时寄存器使用。

**针对 `I16x8SConvertI8x16Low` 函数:**

1. `vupklsb(dst, src)`: 将 `src` 寄存器中低 8 个字节的 8 位有符号整数解包并符号扩展为 16 位整数，结果存储在 `dst` 中。此时 `dst` 可能包含 `[1, 2, 3, 4, 5, 6, 7, 8, ...] ` (高位部分可能未定义或为之前的值)。
2. `li(scratch1, Operand(0xFF))`: 将立即数 `0xFF` (二进制 `11111111`) 加载到通用寄存器 `scratch1` 中。
3. `mtvsrd(scratch2, scratch1)`: 将 `scratch1` 中的值 (0xFF) 复制到 SIMD 寄存器 `scratch2` 的所有 64 位通道中。
4. `vsplth(scratch2, scratch2, Operand(3))`: 将 `scratch2` 中索引为 3 的 16 位通道的值复制到所有其他 16 位通道。由于初始 `scratch2` 的低 64 位是 `0x00000000000000ff`，索引为 3 的 16 位通道的值是 `0x00ff`。因此 `scratch2` 现在包含 `[0x00ff, 0x00ff, 0x00ff, 0x00ff, 0x00ff, 0x00ff, 0x00ff, 0x00ff]`。
5. `vand(dst, scratch2, dst)`: 对 `dst` 和 `scratch2` 进行按位与运算。 由于 `scratch2` 的每个 16 位通道都是 `0x00ff`，这相当于对 `dst` 中的每个 16 位整数与 `0x00ff` 进行按位与，**实现了低 8 位的保留，高 8 位的清零 (零扩展)**。

**输出 `dst`:** `[0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008]` (作为 16 位有符号整数)。

**用户常见的编程错误 (示例):**

* **错误的寄存器使用:** 在需要临时寄存器 (`scratch1`, `scratch2` 等) 的函数中，如果使用了错误的寄存器，可能会覆盖掉需要保留的值。例如，在 `I16x8UConvertI8x16Low` 中，如果 `scratch1` 或 `scratch2` 被错误地指定为输入参数使用的寄存器，会导致计算错误。
* **错误的 Lane 索引:**  在使用 `LoadLane` 或 `StoreLane` 系列函数时，如果指定的 `lane` 索引超出范围，会导致读取或写入错误的内存位置。
* **未考虑字节序:**  在处理内存中的数据时，如果没有正确考虑目标平台的字节序 (例如，PowerPC 是大端序，但这些函数名中的 `LE` 指示小端序处理)，会导致数据解析错误。
* **忘记处理饱和:** 在使用饱和运算的函数时，如果没有意识到结果会被限制在一定范围内，可能会导致逻辑错误。例如，在 `I16x8Q15MulRSatS` 中，乘法结果超出 16 位有符号整数范围时会被饱和到最大或最小值。

**这是第 6 部分，共 7 部分，请归纳一下它的功能:**

作为总共 7 个部分中的第 6 部分，这部分代码继续扩展了 `MacroAssembler` 类的功能，**着重于为 PowerPC 架构提供 SIMD 指令的支持**。它实现了各种 SIMD 数据类型的转换、运算、重排以及与内存之间的数据交换。此外，它还包含了一些通用的寄存器和内存操作，以及处理程序控制流（例如条件跳转和函数调用）的功能。 可以推断，前后的部分可能分别负责更基础的指令、浮点运算、更高级的控制流或与 V8 引擎其他部分的交互。 这部分的功能是构建高性能 JavaScript 执行引擎的关键组成部分，特别是对于需要并行处理数据的场景（例如图形处理、音视频编解码等）。

### 提示词
```
这是目录为v8/src/codegen/ppc/macro-assembler-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ppc/macro-assembler-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
egister scratch1,
                                            Simd128Register scratch2) {
  vupkhsh(dst, src);
  // Zero extend.
  mov(scratch1, Operand(0xFFFF));
  mtvsrd(scratch2, scratch1);
  vspltw(scratch2, scratch2, Operand(1));
  vand(dst, scratch2, dst);
}

void MacroAssembler::I16x8UConvertI8x16Low(Simd128Register dst,
                                           Simd128Register src,
                                           Register scratch1,
                                           Simd128Register scratch2) {
  vupklsb(dst, src);
  // Zero extend.
  li(scratch1, Operand(0xFF));
  mtvsrd(scratch2, scratch1);
  vsplth(scratch2, scratch2, Operand(3));
  vand(dst, scratch2, dst);
}

void MacroAssembler::I16x8UConvertI8x16High(Simd128Register dst,
                                            Simd128Register src,
                                            Register scratch1,
                                            Simd128Register scratch2) {
  vupkhsb(dst, src);
  // Zero extend.
  li(scratch1, Operand(0xFF));
  mtvsrd(scratch2, scratch1);
  vsplth(scratch2, scratch2, Operand(3));
  vand(dst, scratch2, dst);
}

void MacroAssembler::I8x16BitMask(Register dst, Simd128Register src,
                                  Register scratch1, Register scratch2,
                                  Simd128Register scratch3) {
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    vextractbm(dst, src);
  } else {
    mov(scratch1, Operand(0x8101820283038));
    mov(scratch2, Operand(0x4048505860687078));
    mtvsrdd(scratch3, scratch1, scratch2);
    vbpermq(scratch3, src, scratch3);
    mfvsrd(dst, scratch3);
  }
}

void MacroAssembler::I32x4DotI16x8S(Simd128Register dst, Simd128Register src1,
                                    Simd128Register src2) {
  vxor(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
  vmsumshm(dst, src1, src2, kSimd128RegZero);
}

void MacroAssembler::I32x4DotI8x16AddS(Simd128Register dst,
                                       Simd128Register src1,
                                       Simd128Register src2,
                                       Simd128Register src3) {
  vmsummbm(dst, src1, src2, src3);
}

void MacroAssembler::I16x8DotI8x16S(Simd128Register dst, Simd128Register src1,
                                    Simd128Register src2,
                                    Simd128Register scratch) {
  vmulesb(scratch, src1, src2);
  vmulosb(dst, src1, src2);
  vadduhm(dst, scratch, dst);
}

void MacroAssembler::I16x8Q15MulRSatS(Simd128Register dst, Simd128Register src1,
                                      Simd128Register src2) {
  vxor(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
  vmhraddshs(dst, src1, src2, kSimd128RegZero);
}

void MacroAssembler::I8x16Swizzle(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch) {
  // Saturate the indices to 5 bits. Input indices more than 31 should
  // return 0.
  xxspltib(scratch, Operand(31));
  vminub(scratch, src2, scratch);
  // Input needs to be reversed.
  xxbrq(dst, src1);
  vxor(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
  vperm(dst, dst, kSimd128RegZero, scratch);
}

void MacroAssembler::I8x16Shuffle(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2, uint64_t high,
                                  uint64_t low, Register scratch1,
                                  Register scratch2, Simd128Register scratch3) {
  mov(scratch1, Operand(low));
  mov(scratch2, Operand(high));
  mtvsrdd(scratch3, scratch2, scratch1);
  vperm(dst, src1, src2, scratch3);
}

#define EXT_ADD_PAIRWISE(splat, mul_even, mul_odd, add) \
  splat(scratch1, Operand(1));                          \
  mul_even(scratch2, src, scratch1);                    \
  mul_odd(scratch1, src, scratch1);                     \
  add(dst, scratch2, scratch1);
void MacroAssembler::I32x4ExtAddPairwiseI16x8S(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register scratch1,
                                               Simd128Register scratch2) {
  EXT_ADD_PAIRWISE(vspltish, vmulesh, vmulosh, vadduwm)
}
void MacroAssembler::I32x4ExtAddPairwiseI16x8U(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register scratch1,
                                               Simd128Register scratch2) {
  EXT_ADD_PAIRWISE(vspltish, vmuleuh, vmulouh, vadduwm)
}
void MacroAssembler::I16x8ExtAddPairwiseI8x16S(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register scratch1,
                                               Simd128Register scratch2) {
  EXT_ADD_PAIRWISE(xxspltib, vmulesb, vmulosb, vadduhm)
}
void MacroAssembler::I16x8ExtAddPairwiseI8x16U(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register scratch1,
                                               Simd128Register scratch2) {
  EXT_ADD_PAIRWISE(xxspltib, vmuleub, vmuloub, vadduhm)
}
#undef EXT_ADD_PAIRWISE

void MacroAssembler::F64x2PromoteLowF32x4(Simd128Register dst,
                                          Simd128Register src) {
  constexpr int lane_number = 8;
  vextractd(dst, src, Operand(lane_number));
  vinsertw(dst, dst, Operand(lane_number));
  xvcvspdp(dst, dst);
}

void MacroAssembler::F32x4DemoteF64x2Zero(Simd128Register dst,
                                          Simd128Register src,
                                          Simd128Register scratch) {
  constexpr int lane_number = 8;
  xvcvdpsp(scratch, src);
  vextractuw(dst, scratch, Operand(lane_number));
  vinsertw(scratch, dst, Operand(4));
  vxor(dst, dst, dst);
  vinsertd(dst, scratch, Operand(lane_number));
}

void MacroAssembler::I32x4TruncSatF64x2SZero(Simd128Register dst,
                                             Simd128Register src,
                                             Simd128Register scratch) {
  constexpr int lane_number = 8;
  // NaN to 0.
  xvcmpeqdp(scratch, src, src);
  vand(scratch, src, scratch);
  xvcvdpsxws(scratch, scratch);
  vextractuw(dst, scratch, Operand(lane_number));
  vinsertw(scratch, dst, Operand(4));
  vxor(dst, dst, dst);
  vinsertd(dst, scratch, Operand(lane_number));
}

void MacroAssembler::I32x4TruncSatF64x2UZero(Simd128Register dst,
                                             Simd128Register src,
                                             Simd128Register scratch) {
  constexpr int lane_number = 8;
  xvcvdpuxws(scratch, src);
  vextractuw(dst, scratch, Operand(lane_number));
  vinsertw(scratch, dst, Operand(4));
  vxor(dst, dst, dst);
  vinsertd(dst, scratch, Operand(lane_number));
}

#if V8_TARGET_BIG_ENDIAN
#define MAYBE_REVERSE_BYTES(reg, instr) instr(reg, reg);
#else
#define MAYBE_REVERSE_BYTES(reg, instr)
#endif
void MacroAssembler::LoadLane64LE(Simd128Register dst, const MemOperand& mem,
                                  int lane, Register scratch1,
                                  Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 8;
  LoadSimd128Uint64(scratch2, mem, scratch1);
  MAYBE_REVERSE_BYTES(scratch2, xxbrd)
  vinsertd(dst, scratch2, Operand((1 - lane) * lane_width_in_bytes));
}

void MacroAssembler::LoadLane32LE(Simd128Register dst, const MemOperand& mem,
                                  int lane, Register scratch1,
                                  Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 4;
  LoadSimd128Uint32(scratch2, mem, scratch1);
  MAYBE_REVERSE_BYTES(scratch2, xxbrw)
  vinsertw(dst, scratch2, Operand((3 - lane) * lane_width_in_bytes));
}

void MacroAssembler::LoadLane16LE(Simd128Register dst, const MemOperand& mem,
                                  int lane, Register scratch1,
                                  Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 2;
  LoadSimd128Uint16(scratch2, mem, scratch1);
  MAYBE_REVERSE_BYTES(scratch2, xxbrh)
  vinserth(dst, scratch2, Operand((7 - lane) * lane_width_in_bytes));
}

void MacroAssembler::LoadLane8LE(Simd128Register dst, const MemOperand& mem,
                                 int lane, Register scratch1,
                                 Simd128Register scratch2) {
  LoadSimd128Uint8(scratch2, mem, scratch1);
  vinsertb(dst, scratch2, Operand((15 - lane)));
}

void MacroAssembler::StoreLane64LE(Simd128Register src, const MemOperand& mem,
                                   int lane, Register scratch1,
                                   Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 8;
  vextractd(scratch2, src, Operand((1 - lane) * lane_width_in_bytes));
  MAYBE_REVERSE_BYTES(scratch2, xxbrd)
  StoreSimd128Uint64(scratch2, mem, scratch1);
}

void MacroAssembler::StoreLane32LE(Simd128Register src, const MemOperand& mem,
                                   int lane, Register scratch1,
                                   Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 4;
  vextractuw(scratch2, src, Operand((3 - lane) * lane_width_in_bytes));
  MAYBE_REVERSE_BYTES(scratch2, xxbrw)
  StoreSimd128Uint32(scratch2, mem, scratch1);
}

void MacroAssembler::StoreLane16LE(Simd128Register src, const MemOperand& mem,
                                   int lane, Register scratch1,
                                   Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 2;
  vextractuh(scratch2, src, Operand((7 - lane) * lane_width_in_bytes));
  MAYBE_REVERSE_BYTES(scratch2, xxbrh)
  StoreSimd128Uint16(scratch2, mem, scratch1);
}

void MacroAssembler::StoreLane8LE(Simd128Register src, const MemOperand& mem,
                                  int lane, Register scratch1,
                                  Simd128Register scratch2) {
  vextractub(scratch2, src, Operand(15 - lane));
  StoreSimd128Uint8(scratch2, mem, scratch1);
}

void MacroAssembler::LoadAndSplat64x2LE(Simd128Register dst,
                                        const MemOperand& mem,
                                        Register scratch) {
  constexpr int lane_width_in_bytes = 8;
  LoadSimd128Uint64(dst, mem, scratch);
  MAYBE_REVERSE_BYTES(dst, xxbrd)
  vinsertd(dst, dst, Operand(1 * lane_width_in_bytes));
}

void MacroAssembler::LoadAndSplat32x4LE(Simd128Register dst,
                                        const MemOperand& mem,
                                        Register scratch) {
  LoadSimd128Uint32(dst, mem, scratch);
  MAYBE_REVERSE_BYTES(dst, xxbrw)
  vspltw(dst, dst, Operand(1));
}

void MacroAssembler::LoadAndSplat16x8LE(Simd128Register dst,
                                        const MemOperand& mem,
                                        Register scratch) {
  LoadSimd128Uint16(dst, mem, scratch);
  MAYBE_REVERSE_BYTES(dst, xxbrh)
  vsplth(dst, dst, Operand(3));
}

void MacroAssembler::LoadAndSplat8x16LE(Simd128Register dst,
                                        const MemOperand& mem,
                                        Register scratch) {
  LoadSimd128Uint8(dst, mem, scratch);
  vspltb(dst, dst, Operand(7));
}

void MacroAssembler::LoadAndExtend32x2SLE(Simd128Register dst,
                                          const MemOperand& mem,
                                          Register scratch) {
  LoadSimd128Uint64(dst, mem, scratch);
  MAYBE_REVERSE_BYTES(dst, xxbrd)
  vupkhsw(dst, dst);
}

void MacroAssembler::LoadAndExtend32x2ULE(Simd128Register dst,
                                          const MemOperand& mem,
                                          Register scratch1,
                                          Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 8;
  LoadAndExtend32x2SLE(dst, mem, scratch1);
  // Zero extend.
  mov(scratch1, Operand(0xFFFFFFFF));
  mtvsrd(scratch2, scratch1);
  vinsertd(scratch2, scratch2, Operand(1 * lane_width_in_bytes));
  vand(dst, scratch2, dst);
}

void MacroAssembler::LoadAndExtend16x4SLE(Simd128Register dst,
                                          const MemOperand& mem,
                                          Register scratch) {
  LoadSimd128Uint64(dst, mem, scratch);
  MAYBE_REVERSE_BYTES(dst, xxbrd)
  vupkhsh(dst, dst);
}

void MacroAssembler::LoadAndExtend16x4ULE(Simd128Register dst,
                                          const MemOperand& mem,
                                          Register scratch1,
                                          Simd128Register scratch2) {
  LoadAndExtend16x4SLE(dst, mem, scratch1);
  // Zero extend.
  mov(scratch1, Operand(0xFFFF));
  mtvsrd(scratch2, scratch1);
  vspltw(scratch2, scratch2, Operand(1));
  vand(dst, scratch2, dst);
}

void MacroAssembler::LoadAndExtend8x8SLE(Simd128Register dst,
                                         const MemOperand& mem,
                                         Register scratch) {
  LoadSimd128Uint64(dst, mem, scratch);
  MAYBE_REVERSE_BYTES(dst, xxbrd)
  vupkhsb(dst, dst);
}

void MacroAssembler::LoadAndExtend8x8ULE(Simd128Register dst,
                                         const MemOperand& mem,
                                         Register scratch1,
                                         Simd128Register scratch2) {
  LoadAndExtend8x8SLE(dst, mem, scratch1);
  // Zero extend.
  li(scratch1, Operand(0xFF));
  mtvsrd(scratch2, scratch1);
  vsplth(scratch2, scratch2, Operand(3));
  vand(dst, scratch2, dst);
}

void MacroAssembler::LoadV64ZeroLE(Simd128Register dst, const MemOperand& mem,
                                   Register scratch1,
                                   Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 8;
  LoadSimd128Uint64(scratch2, mem, scratch1);
  MAYBE_REVERSE_BYTES(scratch2, xxbrd)
  vxor(dst, dst, dst);
  vinsertd(dst, scratch2, Operand(1 * lane_width_in_bytes));
}

void MacroAssembler::LoadV32ZeroLE(Simd128Register dst, const MemOperand& mem,
                                   Register scratch1,
                                   Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 4;
  LoadSimd128Uint32(scratch2, mem, scratch1);
  MAYBE_REVERSE_BYTES(scratch2, xxbrw)
  vxor(dst, dst, dst);
  vinsertw(dst, scratch2, Operand(3 * lane_width_in_bytes));
}
#undef MAYBE_REVERSE_BYTES

void MacroAssembler::V128AnyTrue(Register dst, Simd128Register src,
                                 Register scratch1, Register scratch2,
                                 Simd128Register scratch3) {
  constexpr uint8_t fxm = 0x2;  // field mask.
  constexpr int bit_number = 24;
  li(scratch1, Operand(0));
  li(scratch2, Operand(1));
  // Check if both lanes are 0, if so then return false.
  vxor(scratch3, scratch3, scratch3);
  mtcrf(scratch1, fxm);  // Clear cr6.
  vcmpequd(scratch3, src, scratch3, SetRC);
  isel(dst, scratch1, scratch2, bit_number);
}

void MacroAssembler::S128Not(Simd128Register dst, Simd128Register src) {
  vnor(dst, src, src);
}

void MacroAssembler::S128Const(Simd128Register dst, uint64_t high, uint64_t low,
                               Register scratch1, Register scratch2) {
  mov(scratch1, Operand(low));
  mov(scratch2, Operand(high));
  mtvsrdd(dst, scratch2, scratch1);
}

void MacroAssembler::S128Select(Simd128Register dst, Simd128Register src1,
                                Simd128Register src2, Simd128Register mask) {
  vsel(dst, src2, src1, mask);
}

Register GetRegisterThatIsNotOneOf(Register reg1, Register reg2, Register reg3,
                                   Register reg4, Register reg5,
                                   Register reg6) {
  RegList regs = {reg1, reg2, reg3, reg4, reg5, reg6};

  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_general_registers(); ++i) {
    int code = config->GetAllocatableGeneralCode(i);
    Register candidate = Register::from_code(code);
    if (regs.has(candidate)) continue;
    return candidate;
  }
  UNREACHABLE();
}

void MacroAssembler::SwapP(Register src, Register dst, Register scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  mr(scratch, src);
  mr(src, dst);
  mr(dst, scratch);
}

void MacroAssembler::SwapP(Register src, MemOperand dst, Register scratch) {
  if (dst.ra() != r0 && dst.ra().is_valid())
    DCHECK(!AreAliased(src, dst.ra(), scratch));
  if (dst.rb() != r0 && dst.rb().is_valid())
    DCHECK(!AreAliased(src, dst.rb(), scratch));
  DCHECK(!AreAliased(src, scratch));
  mr(scratch, src);
  LoadU64(src, dst, r0);
  StoreU64(scratch, dst, r0);
}

void MacroAssembler::SwapP(MemOperand src, MemOperand dst, Register scratch_0,
                           Register scratch_1) {
  if (src.ra() != r0 && src.ra().is_valid())
    DCHECK(!AreAliased(src.ra(), scratch_0, scratch_1));
  if (src.rb() != r0 && src.rb().is_valid())
    DCHECK(!AreAliased(src.rb(), scratch_0, scratch_1));
  if (dst.ra() != r0 && dst.ra().is_valid())
    DCHECK(!AreAliased(dst.ra(), scratch_0, scratch_1));
  if (dst.rb() != r0 && dst.rb().is_valid())
    DCHECK(!AreAliased(dst.rb(), scratch_0, scratch_1));
  DCHECK(!AreAliased(scratch_0, scratch_1));
  if (is_int16(src.offset()) || is_int16(dst.offset())) {
    if (!is_int16(src.offset())) {
      // swap operand
      MemOperand temp = src;
      src = dst;
      dst = temp;
    }
    LoadU64(scratch_1, dst, scratch_0);
    LoadU64(scratch_0, src);
    StoreU64(scratch_1, src);
    StoreU64(scratch_0, dst, scratch_1);
  } else {
    LoadU64(scratch_1, dst, scratch_0);
    push(scratch_1);
    LoadU64(scratch_0, src, scratch_1);
    StoreU64(scratch_0, dst, scratch_1);
    pop(scratch_1);
    StoreU64(scratch_1, src, scratch_0);
  }
}

void MacroAssembler::SwapFloat32(DoubleRegister src, DoubleRegister dst,
                                 DoubleRegister scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  fmr(scratch, src);
  fmr(src, dst);
  fmr(dst, scratch);
}

void MacroAssembler::SwapFloat32(DoubleRegister src, MemOperand dst,
                                 DoubleRegister scratch) {
  DCHECK(!AreAliased(src, scratch));
  fmr(scratch, src);
  LoadF32(src, dst, r0);
  StoreF32(scratch, dst, r0);
}

void MacroAssembler::SwapFloat32(MemOperand src, MemOperand dst,
                                 DoubleRegister scratch_0,
                                 DoubleRegister scratch_1) {
  DCHECK(!AreAliased(scratch_0, scratch_1));
  LoadF32(scratch_0, src, r0);
  LoadF32(scratch_1, dst, r0);
  StoreF32(scratch_0, dst, r0);
  StoreF32(scratch_1, src, r0);
}

void MacroAssembler::SwapDouble(DoubleRegister src, DoubleRegister dst,
                                DoubleRegister scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  fmr(scratch, src);
  fmr(src, dst);
  fmr(dst, scratch);
}

void MacroAssembler::SwapDouble(DoubleRegister src, MemOperand dst,
                                DoubleRegister scratch) {
  DCHECK(!AreAliased(src, scratch));
  fmr(scratch, src);
  LoadF64(src, dst, r0);
  StoreF64(scratch, dst, r0);
}

void MacroAssembler::SwapDouble(MemOperand src, MemOperand dst,
                                DoubleRegister scratch_0,
                                DoubleRegister scratch_1) {
  DCHECK(!AreAliased(scratch_0, scratch_1));
  LoadF64(scratch_0, src, r0);
  LoadF64(scratch_1, dst, r0);
  StoreF64(scratch_0, dst, r0);
  StoreF64(scratch_1, src, r0);
}

void MacroAssembler::SwapSimd128(Simd128Register src, Simd128Register dst,
                                 Simd128Register scratch) {
  if (src == dst) return;
  vor(scratch, src, src);
  vor(src, dst, dst);
  vor(dst, scratch, scratch);
}

void MacroAssembler::SwapSimd128(Simd128Register src, MemOperand dst,
                                 Simd128Register scratch1, Register scratch2) {
  DCHECK(src != scratch1);
  LoadSimd128(scratch1, dst, scratch2);
  StoreSimd128(src, dst, scratch2);
  vor(src, scratch1, scratch1);
}

void MacroAssembler::SwapSimd128(MemOperand src, MemOperand dst,
                                 Simd128Register scratch1,
                                 Simd128Register scratch2, Register scratch3) {
  LoadSimd128(scratch1, src, scratch3);
  LoadSimd128(scratch2, dst, scratch3);

  StoreSimd128(scratch1, dst, scratch3);
  StoreSimd128(scratch2, src, scratch3);
}

void MacroAssembler::ByteReverseU16(Register dst, Register val,
                                    Register scratch) {
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    brh(dst, val);
    ZeroExtHalfWord(dst, dst);
    return;
  }
  rlwinm(scratch, val, 8, 16, 23);
  rlwinm(dst, val, 24, 24, 31);
  orx(dst, scratch, dst);
  ZeroExtHalfWord(dst, dst);
}

void MacroAssembler::ByteReverseU32(Register dst, Register val,
                                    Register scratch) {
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    brw(dst, val);
    ZeroExtWord32(dst, dst);
    return;
  }
  rotlwi(scratch, val, 8);
  rlwimi(scratch, val, 24, 0, 7);
  rlwimi(scratch, val, 24, 16, 23);
  ZeroExtWord32(dst, scratch);
}

void MacroAssembler::ByteReverseU64(Register dst, Register val, Register) {
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    brd(dst, val);
    return;
  }
  subi(sp, sp, Operand(kSystemPointerSize));
  std(val, MemOperand(sp));
  ldbrx(dst, MemOperand(r0, sp));
  addi(sp, sp, Operand(kSystemPointerSize));
}

void MacroAssembler::JumpIfEqual(Register x, int32_t y, Label* dest) {
  CmpS32(x, Operand(y), r0);
  beq(dest);
}

void MacroAssembler::JumpIfLessThan(Register x, int32_t y, Label* dest) {
  CmpS32(x, Operand(y), r0);
  blt(dest);
}

void MacroAssembler::LoadEntryFromBuiltinIndex(Register builtin_index,
                                               Register target) {
  static_assert(kSystemPointerSize == 8);
  static_assert(kSmiTagSize == 1);
  static_assert(kSmiTag == 0);

  // The builtin_index register contains the builtin index as a Smi.
  if (SmiValuesAre32Bits()) {
    ShiftRightS64(target, builtin_index,
                  Operand(kSmiShift - kSystemPointerSizeLog2));
  } else {
    DCHECK(SmiValuesAre31Bits());
    ShiftLeftU64(target, builtin_index,
                 Operand(kSystemPointerSizeLog2 - kSmiShift));
  }
  AddS64(target, target, Operand(IsolateData::builtin_entry_table_offset()));
  LoadU64(target, MemOperand(kRootRegister, target));
}

void MacroAssembler::CallBuiltinByIndex(Register builtin_index,
                                        Register target) {
  LoadEntryFromBuiltinIndex(builtin_index, target);
  Call(target);
}

void MacroAssembler::LoadEntryFromBuiltin(Builtin builtin,
                                          Register destination) {
  ASM_CODE_COMMENT(this);
  LoadU64(destination, EntryFromBuiltinAsOperand(builtin));
}

MemOperand MacroAssembler::EntryFromBuiltinAsOperand(Builtin builtin) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  return MemOperand(kRootRegister,
                    IsolateData::BuiltinEntrySlotOffset(builtin));
}

void MacroAssembler::LoadCodeInstructionStart(Register destination,
                                              Register code_object,
                                              CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  LoadCodeEntrypointViaCodePointer(
      destination,
      FieldMemOperand(code_object, Code::kSelfIndirectPointerOffset), r0);
#else
  LoadU64(destination,
          FieldMemOperand(code_object, Code::kInstructionStartOffset), r0);
#endif
}

void MacroAssembler::CallCodeObject(Register code_object) {
  ASM_CODE_COMMENT(this);
  LoadCodeInstructionStart(code_object, code_object);
  Call(code_object);
}

void MacroAssembler::JumpCodeObject(Register code_object, JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(JumpMode::kJump, jump_mode);
  LoadCodeInstructionStart(code_object, code_object);
  Jump(code_object);
}

void MacroAssembler::CallJSFunction(Register function_object,
                                    uint16_t argument_count, Register scratch) {
  DCHECK_WITH_MSG(!V8_ENABLE_LEAPTIERING_BOOL,
                  "argument_count is only used with Leaptiering");
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset), scratch);
  Call(code);
#else
  LoadTaggedField(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset), scratch);
  CallCodeObject(code);
#endif
}

void MacroAssembler::JumpJSFunction(Register function_object, Register scratch,
                                    JumpMode jump_mode) {
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset), scratch);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  DCHECK_EQ(code, r5);
  Jump(code);
#else
  LoadTaggedField(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset), scratch);
  JumpCodeObject(code, jump_mode);
#endif
}

void MacroAssembler::StoreReturnAddressAndCall(Register target) {
  // This generates the final instruction sequence for calls to C functions
  // once an exit frame has been constructed.
  //
  // Note that this assumes the caller code (i.e. the InstructionStream object
  // currently being generated) is immovable or that the callee function cannot
  // trigger GC, since the callee function will return to it.

  static constexpr int after_call_offset = 5 * kInstrSize;
  Label start_call;
  Register dest = target;

  if (ABI_USES_FUNCTION_DESCRIPTORS) {
    // AIX/PPC64BE Linux uses a function descriptor. When calling C code be
    // aware of this descriptor and pick up values from it
    LoadU64(ToRegister(ABI_TOC_REGISTER),
            MemOperand(target, kSystemPointerSize));
    LoadU64(ip, MemOperand(target, 0));
    dest = ip;
  } else if (ABI_CALL_VIA_IP && dest != ip) {
    Move(ip, target);
    dest = ip;
  }

  LoadPC(r7);
  bind(&start_call);
  addi(r7, r7, Operand(after_call_offset));
  StoreU64(r7, MemOperand(sp, kStackFrameExtraParamSlot * kSystemPointerSize));
  Call(dest);

  DCHECK_EQ(after_call_offset - kInstrSize,
            SizeOfCodeGeneratedSince(&start_call));
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void MacroAssembler::BailoutIfDeoptimized() {
  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  LoadTaggedField(r11, MemOperand(kJavaScriptCallCodeStartRegister, offset),
                     r0);
  LoadU32(r11, FieldMemOperand(r11, Code::kFlagsOffset), r0);
  TestBit(r11, Code::kMarkedForDeoptimizationBit);
  TailCallBuiltin(Builtin::kCompileLazyDeoptimizedCode, ne, cr0);
}

void MacroAssembler::CallForDeoptimization(Builtin target, int, Label* exit,
                                           DeoptimizeKind kind, Label* ret,
                                           Label*) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  CHECK_LE(target, Builtins::kLastTier0);
  LoadU64(ip, MemOperand(kRootRegister,
                         IsolateData::BuiltinEntrySlotOffset(target)));
  Call(ip);
  DCHECK_EQ(SizeOfCodeGeneratedSince(exit),
            (kind == DeoptimizeKind::kLazy) ? Deoptimizer::kLazyDeoptExitSize
                                            : Deoptimizer::kEagerDeoptExitSize);
}

void MacroAssembler::ZeroExtByte(Register dst, Register src) {
  clrldi(dst, src, Operand(56));
}

void MacroAssembler::ZeroExtHalfWord(Register dst, Register src) {
  clrldi(dst, src, Operand(48));
}

void MacroAssembler::ZeroExtWord32(Register dst, Register src) {
  clrldi(dst, src, Operand(32));
}

void MacroAssembler::Trap() { stop(); }
void MacroAssembler::DebugBreak() { stop(); }

void MacroAssembler::Popcnt32(Register dst, Register src) { popcntw(dst, src); }

void MacroAssembler::Popcnt64(Register dst, Register src) { popcntd(dst, src); }

void MacroAssembler::CountLeadingZerosU32(Register dst, Register src, RCBit r) {
  cntlzw(dst, src, r);
}

void MacroAssembler::CountLeadingZerosU64(Register dst, Register src, RCBit r) {
  cntlzd(dst, src, r);
}

#define COUNT_TRAILING_ZEROES_SLOW(max_count, scratch1, scratch2) \
  Label loop, done;                                               \
  li(scratch1, Operand(max_count));                               \
  mtctr(scratch1);                                                \
  mr(scratch1, src);                                              \
  li(dst, Operand::Zero());                                       \
  bind(&loop); /* while ((src & 1) == 0) */                       \
  andi(scratch2, scratch1, Operand(1));                           \
  bne(&done, cr0);                                                \
  srdi(scratch1, scratch1, Operand(1)); /* src >>= 1;*/           \
  addi(dst, dst, Operand(1));           /* dst++ */               \
  bdnz(&loop);                                                    \
  bind(&done);
void MacroAssembler::CountTrailingZerosU32(Register dst, Register src,
                                           Register scratch1, Register scratch2,
                                           RCBit r) {
  if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
    cnttzw(dst, src, r);
  } else {
    COUNT_TRAILING_ZEROES_SLOW(32, scratch1, scratch2);
  }
}

void MacroAssembler::CountTrailingZerosU64(Register dst, Register src,
                                           Register scratch1, Register scratch2,
                                           RCBit r) {
  if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
    cnttzd(dst, src, r);
  } else {
    COUNT_TRAILING_ZEROES_SLOW(64, scratch1, scratch2);
  }
}
#undef COUNT_TRAILING_ZEROES_SLOW

void MacroAssembler::ClearByteU64(Register dst, int byte_idx) {
  CHECK(0 <= byte_idx && byte_idx <= 7);
  int shift = byte_idx*8;
  rldicl(dst, dst, shift, 8);
  rldicl(dst, dst, 64-shift, 0);
}

void MacroAssembler::ReverseBitsU64(Register dst, Register src,
                                    Register scratch1, Register scratch2) {
  ByteReverseU64(dst, src);
  for (int i = 0; i < 8; i++) {
    ReverseBitsInSingleByteU64(dst, dst, scratch1, scratch2, i);
  }
}

void MacroAssembler::ReverseBitsU32(Register dst, Register src,
                                    Register scratch1, Register scratch2) {
  ByteReverseU32(dst, src, scratch1);
  for (int i = 4; i < 8; i++) {
    ReverseBitsInSingleByteU64(dst, dst, scratch1, scratch2, i);
  }
}

// byte_idx=7 refers to least significant byte
void MacroAssembler::ReverseBitsInSingleByteU64(Register dst, Register src,
                                                Register scratch1,
                                                Register scratch2,
                                                int byte_idx) {
  CHECK(0 <= byte_idx && byte_idx <= 7);
  int j = byte_idx;
  // zero all bits of scratch1
  li(scratch2, Operand(0));
  for (int i = 0; i <= 7; i++) {
    // zero all bits of scratch1
    li(scratch1, Operand(0));
    // move bit (j+1)*8-i-1 of src to bit j*8+i of scratch1, erase bits
    // (j*8+i+1):end of scratch1
    int shift = 7 - (2*i);
    if (shift < 0) shift += 64;
    rldicr(scratch1, src, shift, j*8+i);
    // erase bits start:(j*8-1+i) of scratch1 (inclusive)
    rldicl(scratch1, scratch1, 0, j*8+i);
    // scratch2 = scratch2|scratch1
    orx(scratch2, scratch2, scratch1);
  }
  // clear jth byte of dst and insert jth byte of scratch2
  ClearByteU64(dst, j);
  orx(dst, dst, scratch2);
}

// Calls an API function. Allocates HandleScope, extracts returned value
// from handle and propagates exceptions. Clobbers C argument registers
// and C caller-saved registers. Restores context. On return removes
//   (*argc_operand + slots_to_drop_on_return) * kSystemPointerSize
// (GCed, includes the call JS arguments space and the additional space
// allocated for t
```