Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Understanding:** The file name `constants-arm64.h` and the namespace `v8::internal` immediately suggest that this file defines constants related to the ARM64 architecture within the V8 JavaScript engine. The `.h` extension confirms it's a C++ header file.

2. **Scanning for Patterns:**  A quick scroll reveals a consistent pattern: `constexpr` followed by a type (often `uint32_t`), a constant name (usually in all caps with underscores), and a hexadecimal value. There are also `using` statements that define type aliases.

3. **Identifying Key Concepts:** The constant names frequently contain terms like `NEON`, `LoadStore`, `MultiStruct`, `Single`, `PostIndex`, `Scalar`, `ShiftImmediate`, `Table`, `Perm`, etc. These are strong indicators of ARM's NEON instruction set and common memory access patterns. The presence of `Fixed`, `FMask`, and `Mask` also stands out as a recurring pattern.

4. **Inferring Functionality:** Based on the constant names, we can start inferring the purpose of this file:
    * **Instruction Encoding:** The hexadecimal values likely represent bit patterns for encoding ARM64 instructions, particularly those related to NEON (Advanced SIMD).
    * **Categorization:** The `using` statements like `NEONLoadStoreMultiStructOp` and the consistent naming conventions suggest a systematic way of categorizing and representing different types of NEON instructions.
    * **Bit Manipulation:** The `|` (bitwise OR) operations in the constant definitions suggest combining different parts of the instruction encoding. The `Mask` constants likely define which bits are relevant for specific parts of an instruction.

5. **Addressing Specific Questions:**

    * **Functionality:**  Synthesize the observations into a concise summary. Focus on the core purpose: defining constants for encoding ARM64 NEON instructions. Mention the categories observed (load/store, scalar, etc.) and the role of masks and fixed values.

    * **`.tq` Extension:**  The file *does not* end in `.tq`. State this fact clearly. Explain that `.tq` indicates Torque, a different V8-specific language for compiler intrinsics.

    * **Relationship to JavaScript:**  This requires connecting the low-level instruction constants to the high-level JavaScript world. NEON instructions are used for SIMD operations, which are often leveraged to optimize JavaScript array manipulations, image processing, or other data-intensive tasks. Provide a simple JavaScript example that benefits from such optimizations (e.g., adding two arrays). Explain *how* the constants are used (by the compiler to generate machine code).

    * **Code Logic/Reasoning:** Select a clear example of how the constants are combined. `NEON_LD1_b` is a good choice. Break down its definition into its components (`NEONLoadStoreSingleStructLoad1` and `NEONLoadStoreSingle_b`) and explain what each component signifies (load single structure, byte size). Create a hypothetical scenario of using this constant during code generation. Explain the input (high-level operation) and the output (the encoded instruction).

    * **Common Programming Errors:**  Think about what could go wrong when *using* or *interpreting* these constants (though developers rarely directly interact with these). Misinterpreting the bit patterns or using the wrong constant for an instruction are potential errors. Illustrate with a conceptual example of incorrect usage.

    * **Overall Summary (Part 4):** Reiterate the main function of the header file, emphasizing its role in the architecture-specific code generation process within V8. Highlight that it provides the building blocks for generating efficient ARM64 machine code.

6. **Refinement and Clarity:** Review the generated text for clarity and accuracy. Ensure the explanations are understandable to someone with some programming background but not necessarily deep knowledge of V8 internals or ARM assembly. Use precise language and avoid jargon where possible.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe these constants are directly used in the interpreter. **Correction:**  Realized they are more likely used during the *compilation* phase to generate optimized machine code for NEON instructions.
* **Struggling with the JavaScript example:** Initially considered a complex example. **Correction:**  Simplified to a basic array addition to clearly illustrate the concept of SIMD optimization.
* **Overly technical explanation:**  The first draft of the code logic explanation was too focused on bit manipulation details. **Correction:**  Shifted the focus to the higher-level meaning of the combined constants and their role in instruction selection.

By following this structured approach, focusing on pattern recognition, inference, and addressing each part of the prompt systematically, we can arrive at a comprehensive and accurate analysis of the provided C++ header file.
好的，这是对 `v8/src/codegen/arm64/constants-arm64.h` 文件功能的详细分析：

**功能总览**

`v8/src/codegen/arm64/constants-arm64.h` 文件是一个 C++ 头文件，它定义了用于在 ARM64 架构上生成机器码时使用的各种常量。这些常量主要与 ARM64 的 NEON (Advanced SIMD) 指令集相关。该文件为 V8 引擎在 ARM64 平台上进行代码生成提供了基础的构建块。

**具体功能分解**

1. **定义 NEON 指令操作码常量:** 文件中定义了大量的 `constexpr` 常量，它们实际上是 ARM64 NEON 指令的操作码的各个组成部分或完整的操作码。这些常量以十六进制形式表示，对应于指令的二进制编码。

   * **指令类别:** 常量名中包含了指令的类别，例如 `NEONLoadStoreMultiStructPostIndexOp`、`NEONLoadStoreSingleStructOp`、`NEONCopyOp`、`NEONShiftImmediateOp` 等，清晰地表明了指令所属的类型（加载/存储、复制、移位等）。
   * **具体指令:**  更细化的常量名，如 `NEON_ST3_post`、`NEON_LD1_b`、`NEON_INS_ELEMENT`、`NEON_SHL` 等，指明了具体的 NEON 指令。
   * **操作数类型和大小:**  常量名中还包含了操作数类型和大小的信息，例如 `_b` (byte)、`_h` (half-word)、`_s` (single-word)、`_d` (double-word)。
   * **修饰符:**  一些常量名带有修饰符，如 `_post` (post-index)、`_scalar` (标量操作)。
   * **掩码 (Mask) 和固定位 (Fixed):**  像 `NEONLoadStoreMultiStructMask` 和 `NEONLoadStoreMultiStructFixed` 这样的常量用于构建完整的操作码。`Fixed` 定义了指令中不变的位，而 `Mask` 用于提取或比较指令中特定部分的位。

2. **组织指令类别:**  使用 `using` 关键字定义了类型别名，例如 `using NEONLoadStoreMultiStructOp = uint32_t;`，将相关的常量组织在一起，提高了代码的可读性和可维护性。

3. **支持不同的 NEON 指令变体:**  文件中定义了各种 NEON 指令的变体，例如加载/存储单个结构体的不同数量的寄存器 (LD1, LD2, LD3, LD4) 以及它们的标量版本。

4. **提供构建完整指令的片段:**  通过位或运算 (`|`) 将不同的常量组合起来，可以构建出完整的 NEON 指令操作码。例如，`constexpr NEONLoadStoreSingleStructOp NEON_LD1_b = NEONLoadStoreSingleStructLoad1 | NEONLoadStoreSingle_b;` 将加载单个结构体指令的基本部分和字节大小操作数部分组合起来。

**关于文件扩展名和 Torque**

正如你提供的文本所示，`v8/src/codegen/arm64/constants-arm64.h` 的扩展名是 `.h`，这表明它是一个标准的 C++ 头文件。因此，它**不是**一个以 `.tq` 结尾的 V8 Torque 源代码文件。

**与 JavaScript 的关系**

`constants-arm64.h` 文件本身不包含任何 JavaScript 代码，但它与 JavaScript 的功能有着密切的关系。V8 引擎负责执行 JavaScript 代码。为了在 ARM64 架构上高效地执行 JavaScript，V8 的代码生成器 (codegen) 需要将 JavaScript 代码翻译成对应的 ARM64 机器码。

这个头文件中定义的常量就用于指导代码生成器如何生成针对 ARM64 架构优化的 NEON 指令。NEON 指令集允许并行处理多个数据，从而显著提高某些 JavaScript 操作的性能，尤其是在处理数组、图像、音频等数据时。

**JavaScript 示例**

假设一段 JavaScript 代码涉及到对数组进行并行处理，V8 引擎在 ARM64 平台上可能会生成使用 NEON 指令的机器码：

```javascript
function addArrays(a, b) {
  const result = [];
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] + b[i];
  }
  return result;
}

const array1 = [1, 2, 3, 4];
const array2 = [5, 6, 7, 8];
const sum = addArrays(array1, array2);
console.log(sum); // 输出: [6, 8, 10, 12]
```

在 V8 的代码生成过程中，当编译 `addArrays` 函数时，如果检测到可以利用 NEON 指令进行优化，那么 `constants-arm64.h` 中定义的常量（例如，与向量加法相关的指令操作码）会被用来构造实际的 ARM64 机器码指令。例如，可能会使用 `NEON_ADD` 或类似的常量来生成执行向量加法的 NEON 指令。

**代码逻辑推理**

让我们以 `constexpr NEONLoadStoreSingleStructOp NEON_LD1_b = NEONLoadStoreSingleStructLoad1 | NEONLoadStoreSingle_b;` 为例进行推理：

**假设输入：**  V8 代码生成器需要生成一个 NEON 指令，用于从内存中加载一个字节到一个 NEON 寄存器中（作为单个结构体的一部分）。

**常量值：**
* `NEONLoadStoreSingleStructLoad1` 的值为 `0x0D000000` (假设值，实际值请参考完整的头文件)
* `NEONLoadStoreSingle_b` 的值为 `0x00000000` (假设值)

**代码逻辑：**  通过位或运算 (`|`) 将这两个常量组合起来：

`0x0D000000 | 0x00000000 = 0x0D000000`

**输出：**  最终得到的 `NEON_LD1_b` 常量的值为 `0x0D000000`。这个值会被 V8 代码生成器用作加载单个字节的 NEON 指令操作码的一部分。在实际的指令编码中，还需要填充其他字段，例如寄存器信息和内存地址。

**用户常见的编程错误**

虽然开发者通常不会直接操作这些底层的指令常量，但理解它们有助于理解 V8 的性能特性。与 NEON 指令相关的常见编程错误（在编写需要手动使用 SIMD 指令的代码时）包括：

1. **数据对齐问题:** NEON 指令通常对数据对齐有要求。如果加载或存储的数据没有正确对齐到内存地址，可能会导致程序崩溃或性能下降。

   ```c++
   // 错误示例 (假设在 C++ 中手动使用 NEON)
   uint8_t buffer[5]; // 未对齐的缓冲区
   uint8x16_t data;
   // 尝试加载未对齐的数据到 NEON 寄存器，可能导致错误
   // data = vld1q_u8(buffer);
   ```

2. **访问越界:**  在使用 NEON 指令处理数组时，如果计算不当，可能会导致访问数组越界。

   ```c++
   // 错误示例
   float array[10];
   float32x4_t vec;
   // 假设循环次数不正确，可能尝试访问 array[10] 或更高索引
   // for (int i = 0; i < 3; ++i) {
   //   vec = vld1q_f32(&array[i * 4]);
   // }
   ```

3. **错误的指令选择:**  选择了不适合当前数据类型或操作的 NEON 指令，导致结果错误或性能下降。

4. **忽略 NEON 指令的副作用:** 某些 NEON 指令可能会有特殊的副作用，例如修改状态寄存器。不了解这些副作用可能会导致意想不到的结果。

**归纳一下它的功能 (第4部分)**

作为第 4 部分，我们再次强调 `v8/src/codegen/arm64/constants-arm64.h` 文件的核心功能：

* **为 V8 引擎的 ARM64 代码生成器提供预定义的常量，这些常量代表了 ARM64 架构中 NEON 指令集的各种操作码和操作数修饰符。**
* **通过组合这些常量，代码生成器能够构建出正确的 ARM64 机器码指令，用于高效地执行 JavaScript 代码，特别是涉及并行数据处理的操作。**
* **该文件是 V8 在 ARM64 平台上实现高性能的关键组成部分，它抽象了底层的指令编码细节，使得代码生成过程更加结构化和易于维护。**

总而言之，`constants-arm64.h` 是 V8 引擎在 ARM64 平台上进行代码生成的基石，它定义了用于操作 NEON 指令的关键常量，从而实现了 JavaScript 代码在该架构上的高效执行。

Prompt: 
```
这是目录为v8/src/codegen/arm64/constants-arm64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/constants-arm64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
EON_ST3 | NEONLoadStoreMultiStructPostIndex;
constexpr NEONLoadStoreMultiStructPostIndexOp NEON_ST4_post =
    NEON_ST4 | NEONLoadStoreMultiStructPostIndex;

using NEONLoadStoreSingleOp = uint32_t;
constexpr NEONLoadStoreSingleOp NEONLoadStoreSingle1 = 0x00000000;
constexpr NEONLoadStoreSingleOp NEONLoadStoreSingle2 = 0x00200000;
constexpr NEONLoadStoreSingleOp NEONLoadStoreSingle3 = 0x00002000;
constexpr NEONLoadStoreSingleOp NEONLoadStoreSingle4 = 0x00202000;
constexpr NEONLoadStoreSingleOp NEONLoadStoreSingleL = 0x00400000;
constexpr NEONLoadStoreSingleOp NEONLoadStoreSingle_b = 0x00000000;
constexpr NEONLoadStoreSingleOp NEONLoadStoreSingle_h = 0x00004000;
constexpr NEONLoadStoreSingleOp NEONLoadStoreSingle_s = 0x00008000;
constexpr NEONLoadStoreSingleOp NEONLoadStoreSingle_d = 0x00008400;
constexpr NEONLoadStoreSingleOp NEONLoadStoreSingleAllLanes = 0x0000C000;
constexpr NEONLoadStoreSingleOp NEONLoadStoreSingleLenMask = 0x00202000;

// NEON load/store single structure.
using NEONLoadStoreSingleStructOp = uint32_t;
constexpr NEONLoadStoreSingleStructOp NEONLoadStoreSingleStructFixed =
    0x0D000000;
constexpr NEONLoadStoreSingleStructOp NEONLoadStoreSingleStructFMask =
    0xBF9F0000;
constexpr NEONLoadStoreSingleStructOp NEONLoadStoreSingleStructMask =
    0xBFFFE000;
constexpr NEONLoadStoreSingleStructOp NEONLoadStoreSingleStructStore =
    NEONLoadStoreSingleStructFixed;
constexpr NEONLoadStoreSingleStructOp NEONLoadStoreSingleStructLoad =
    NEONLoadStoreSingleStructFixed | NEONLoadStoreSingleL;
constexpr NEONLoadStoreSingleStructOp NEONLoadStoreSingleStructLoad1 =
    NEONLoadStoreSingle1 | NEONLoadStoreSingleStructLoad;
constexpr NEONLoadStoreSingleStructOp NEONLoadStoreSingleStructLoad2 =
    NEONLoadStoreSingle2 | NEONLoadStoreSingleStructLoad;
constexpr NEONLoadStoreSingleStructOp NEONLoadStoreSingleStructLoad3 =
    NEONLoadStoreSingle3 | NEONLoadStoreSingleStructLoad;
constexpr NEONLoadStoreSingleStructOp NEONLoadStoreSingleStructLoad4 =
    NEONLoadStoreSingle4 | NEONLoadStoreSingleStructLoad;
constexpr NEONLoadStoreSingleStructOp NEONLoadStoreSingleStructStore1 =
    NEONLoadStoreSingle1 | NEONLoadStoreSingleStructFixed;
constexpr NEONLoadStoreSingleStructOp NEONLoadStoreSingleStructStore2 =
    NEONLoadStoreSingle2 | NEONLoadStoreSingleStructFixed;
constexpr NEONLoadStoreSingleStructOp NEONLoadStoreSingleStructStore3 =
    NEONLoadStoreSingle3 | NEONLoadStoreSingleStructFixed;
constexpr NEONLoadStoreSingleStructOp NEONLoadStoreSingleStructStore4 =
    NEONLoadStoreSingle4 | NEONLoadStoreSingleStructFixed;
constexpr NEONLoadStoreSingleStructOp NEON_LD1_b =
    NEONLoadStoreSingleStructLoad1 | NEONLoadStoreSingle_b;
constexpr NEONLoadStoreSingleStructOp NEON_LD1_h =
    NEONLoadStoreSingleStructLoad1 | NEONLoadStoreSingle_h;
constexpr NEONLoadStoreSingleStructOp NEON_LD1_s =
    NEONLoadStoreSingleStructLoad1 | NEONLoadStoreSingle_s;
constexpr NEONLoadStoreSingleStructOp NEON_LD1_d =
    NEONLoadStoreSingleStructLoad1 | NEONLoadStoreSingle_d;
constexpr NEONLoadStoreSingleStructOp NEON_LD1R =
    NEONLoadStoreSingleStructLoad1 | NEONLoadStoreSingleAllLanes;
constexpr NEONLoadStoreSingleStructOp NEON_ST1_b =
    NEONLoadStoreSingleStructStore1 | NEONLoadStoreSingle_b;
constexpr NEONLoadStoreSingleStructOp NEON_ST1_h =
    NEONLoadStoreSingleStructStore1 | NEONLoadStoreSingle_h;
constexpr NEONLoadStoreSingleStructOp NEON_ST1_s =
    NEONLoadStoreSingleStructStore1 | NEONLoadStoreSingle_s;
constexpr NEONLoadStoreSingleStructOp NEON_ST1_d =
    NEONLoadStoreSingleStructStore1 | NEONLoadStoreSingle_d;

constexpr NEONLoadStoreSingleStructOp NEON_LD2_b =
    NEONLoadStoreSingleStructLoad2 | NEONLoadStoreSingle_b;
constexpr NEONLoadStoreSingleStructOp NEON_LD2_h =
    NEONLoadStoreSingleStructLoad2 | NEONLoadStoreSingle_h;
constexpr NEONLoadStoreSingleStructOp NEON_LD2_s =
    NEONLoadStoreSingleStructLoad2 | NEONLoadStoreSingle_s;
constexpr NEONLoadStoreSingleStructOp NEON_LD2_d =
    NEONLoadStoreSingleStructLoad2 | NEONLoadStoreSingle_d;
constexpr NEONLoadStoreSingleStructOp NEON_LD2R =
    NEONLoadStoreSingleStructLoad2 | NEONLoadStoreSingleAllLanes;
constexpr NEONLoadStoreSingleStructOp NEON_ST2_b =
    NEONLoadStoreSingleStructStore2 | NEONLoadStoreSingle_b;
constexpr NEONLoadStoreSingleStructOp NEON_ST2_h =
    NEONLoadStoreSingleStructStore2 | NEONLoadStoreSingle_h;
constexpr NEONLoadStoreSingleStructOp NEON_ST2_s =
    NEONLoadStoreSingleStructStore2 | NEONLoadStoreSingle_s;
constexpr NEONLoadStoreSingleStructOp NEON_ST2_d =
    NEONLoadStoreSingleStructStore2 | NEONLoadStoreSingle_d;

constexpr NEONLoadStoreSingleStructOp NEON_LD3_b =
    NEONLoadStoreSingleStructLoad3 | NEONLoadStoreSingle_b;
constexpr NEONLoadStoreSingleStructOp NEON_LD3_h =
    NEONLoadStoreSingleStructLoad3 | NEONLoadStoreSingle_h;
constexpr NEONLoadStoreSingleStructOp NEON_LD3_s =
    NEONLoadStoreSingleStructLoad3 | NEONLoadStoreSingle_s;
constexpr NEONLoadStoreSingleStructOp NEON_LD3_d =
    NEONLoadStoreSingleStructLoad3 | NEONLoadStoreSingle_d;
constexpr NEONLoadStoreSingleStructOp NEON_LD3R =
    NEONLoadStoreSingleStructLoad3 | NEONLoadStoreSingleAllLanes;
constexpr NEONLoadStoreSingleStructOp NEON_ST3_b =
    NEONLoadStoreSingleStructStore3 | NEONLoadStoreSingle_b;
constexpr NEONLoadStoreSingleStructOp NEON_ST3_h =
    NEONLoadStoreSingleStructStore3 | NEONLoadStoreSingle_h;
constexpr NEONLoadStoreSingleStructOp NEON_ST3_s =
    NEONLoadStoreSingleStructStore3 | NEONLoadStoreSingle_s;
constexpr NEONLoadStoreSingleStructOp NEON_ST3_d =
    NEONLoadStoreSingleStructStore3 | NEONLoadStoreSingle_d;

constexpr NEONLoadStoreSingleStructOp NEON_LD4_b =
    NEONLoadStoreSingleStructLoad4 | NEONLoadStoreSingle_b;
constexpr NEONLoadStoreSingleStructOp NEON_LD4_h =
    NEONLoadStoreSingleStructLoad4 | NEONLoadStoreSingle_h;
constexpr NEONLoadStoreSingleStructOp NEON_LD4_s =
    NEONLoadStoreSingleStructLoad4 | NEONLoadStoreSingle_s;
constexpr NEONLoadStoreSingleStructOp NEON_LD4_d =
    NEONLoadStoreSingleStructLoad4 | NEONLoadStoreSingle_d;
constexpr NEONLoadStoreSingleStructOp NEON_LD4R =
    NEONLoadStoreSingleStructLoad4 | NEONLoadStoreSingleAllLanes;
constexpr NEONLoadStoreSingleStructOp NEON_ST4_b =
    NEONLoadStoreSingleStructStore4 | NEONLoadStoreSingle_b;
constexpr NEONLoadStoreSingleStructOp NEON_ST4_h =
    NEONLoadStoreSingleStructStore4 | NEONLoadStoreSingle_h;
constexpr NEONLoadStoreSingleStructOp NEON_ST4_s =
    NEONLoadStoreSingleStructStore4 | NEONLoadStoreSingle_s;
constexpr NEONLoadStoreSingleStructOp NEON_ST4_d =
    NEONLoadStoreSingleStructStore4 | NEONLoadStoreSingle_d;

// NEON load/store single structure with post-index addressing.
using NEONLoadStoreSingleStructPostIndexOp = uint32_t;
constexpr NEONLoadStoreSingleStructPostIndexOp
    NEONLoadStoreSingleStructPostIndexFixed = 0x0D800000;
constexpr NEONLoadStoreSingleStructPostIndexOp
    NEONLoadStoreSingleStructPostIndexFMask = 0xBF800000;
constexpr NEONLoadStoreSingleStructPostIndexOp
    NEONLoadStoreSingleStructPostIndexMask = 0xBFE0E000;
constexpr NEONLoadStoreSingleStructPostIndexOp
    NEONLoadStoreSingleStructPostIndex = 0x00800000;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD1_b_post =
    NEON_LD1_b | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD1_h_post =
    NEON_LD1_h | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD1_s_post =
    NEON_LD1_s | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD1_d_post =
    NEON_LD1_d | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD1R_post =
    NEON_LD1R | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST1_b_post =
    NEON_ST1_b | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST1_h_post =
    NEON_ST1_h | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST1_s_post =
    NEON_ST1_s | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST1_d_post =
    NEON_ST1_d | NEONLoadStoreSingleStructPostIndex;

constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD2_b_post =
    NEON_LD2_b | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD2_h_post =
    NEON_LD2_h | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD2_s_post =
    NEON_LD2_s | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD2_d_post =
    NEON_LD2_d | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD2R_post =
    NEON_LD2R | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST2_b_post =
    NEON_ST2_b | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST2_h_post =
    NEON_ST2_h | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST2_s_post =
    NEON_ST2_s | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST2_d_post =
    NEON_ST2_d | NEONLoadStoreSingleStructPostIndex;

constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD3_b_post =
    NEON_LD3_b | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD3_h_post =
    NEON_LD3_h | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD3_s_post =
    NEON_LD3_s | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD3_d_post =
    NEON_LD3_d | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD3R_post =
    NEON_LD3R | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST3_b_post =
    NEON_ST3_b | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST3_h_post =
    NEON_ST3_h | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST3_s_post =
    NEON_ST3_s | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST3_d_post =
    NEON_ST3_d | NEONLoadStoreSingleStructPostIndex;

constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD4_b_post =
    NEON_LD4_b | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD4_h_post =
    NEON_LD4_h | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD4_s_post =
    NEON_LD4_s | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD4_d_post =
    NEON_LD4_d | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_LD4R_post =
    NEON_LD4R | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST4_b_post =
    NEON_ST4_b | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST4_h_post =
    NEON_ST4_h | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST4_s_post =
    NEON_ST4_s | NEONLoadStoreSingleStructPostIndex;
constexpr NEONLoadStoreSingleStructPostIndexOp NEON_ST4_d_post =
    NEON_ST4_d | NEONLoadStoreSingleStructPostIndex;

// NEON register copy.
using NEONCopyOp = uint32_t;
constexpr NEONCopyOp NEONCopyFixed = 0x0E000400;
constexpr NEONCopyOp NEONCopyFMask = 0x9FE08400;
constexpr NEONCopyOp NEONCopyMask = 0x3FE08400;
constexpr NEONCopyOp NEONCopyInsElementMask = NEONCopyMask | 0x40000000;
constexpr NEONCopyOp NEONCopyInsGeneralMask = NEONCopyMask | 0x40007800;
constexpr NEONCopyOp NEONCopyDupElementMask = NEONCopyMask | 0x20007800;
constexpr NEONCopyOp NEONCopyDupGeneralMask = NEONCopyDupElementMask;
constexpr NEONCopyOp NEONCopyUmovMask = NEONCopyMask | 0x20007800;
constexpr NEONCopyOp NEONCopySmovMask = NEONCopyMask | 0x20007800;
constexpr NEONCopyOp NEON_INS_ELEMENT = NEONCopyFixed | 0x60000000;
constexpr NEONCopyOp NEON_INS_GENERAL = NEONCopyFixed | 0x40001800;
constexpr NEONCopyOp NEON_DUP_ELEMENT = NEONCopyFixed | 0x00000000;
constexpr NEONCopyOp NEON_DUP_GENERAL = NEONCopyFixed | 0x00000800;
constexpr NEONCopyOp NEON_SMOV = NEONCopyFixed | 0x00002800;
constexpr NEONCopyOp NEON_UMOV = NEONCopyFixed | 0x00003800;

// NEON scalar instructions with indexed element operand.
using NEONScalarByIndexedElementOp = uint32_t;
constexpr NEONScalarByIndexedElementOp NEONScalarByIndexedElementFixed =
    0x5F000000;
constexpr NEONScalarByIndexedElementOp NEONScalarByIndexedElementFMask =
    0xDF000400;
constexpr NEONScalarByIndexedElementOp NEONScalarByIndexedElementMask =
    0xFF00F400;
constexpr NEONScalarByIndexedElementOp NEON_SQDMLAL_byelement_scalar =
    NEON_Q | NEONScalar | NEON_SQDMLAL_byelement;
constexpr NEONScalarByIndexedElementOp NEON_SQDMLSL_byelement_scalar =
    NEON_Q | NEONScalar | NEON_SQDMLSL_byelement;
constexpr NEONScalarByIndexedElementOp NEON_SQDMULL_byelement_scalar =
    NEON_Q | NEONScalar | NEON_SQDMULL_byelement;
constexpr NEONScalarByIndexedElementOp NEON_SQDMULH_byelement_scalar =
    NEON_Q | NEONScalar | NEON_SQDMULH_byelement;
constexpr NEONScalarByIndexedElementOp NEON_SQRDMULH_byelement_scalar =
    NEON_Q | NEONScalar | NEON_SQRDMULH_byelement;

// Floating point instructions.
constexpr NEONScalarByIndexedElementOp NEONScalarByIndexedElementFPFixed =
    NEONScalarByIndexedElementFixed | 0x00800000;
constexpr NEONScalarByIndexedElementOp NEONScalarByIndexedElementFPMask =
    NEONScalarByIndexedElementMask | 0x00800000;
constexpr NEONScalarByIndexedElementOp NEON_FMLA_byelement_scalar =
    NEON_Q | NEONScalar | NEON_FMLA_byelement;
constexpr NEONScalarByIndexedElementOp NEON_FMLS_byelement_scalar =
    NEON_Q | NEONScalar | NEON_FMLS_byelement;
constexpr NEONScalarByIndexedElementOp NEON_FMUL_byelement_scalar =
    NEON_Q | NEONScalar | NEON_FMUL_byelement;
constexpr NEONScalarByIndexedElementOp NEON_FMULX_byelement_scalar =
    NEON_Q | NEONScalar | NEON_FMULX_byelement;

// NEON shift immediate.
using NEONShiftImmediateOp = uint32_t;
constexpr NEONShiftImmediateOp NEONShiftImmediateFixed = 0x0F000400;
constexpr NEONShiftImmediateOp NEONShiftImmediateFMask = 0x9F800400;
constexpr NEONShiftImmediateOp NEONShiftImmediateMask = 0xBF80FC00;
constexpr NEONShiftImmediateOp NEONShiftImmediateUBit = 0x20000000;
constexpr NEONShiftImmediateOp NEON_SHL = NEONShiftImmediateFixed | 0x00005000;
constexpr NEONShiftImmediateOp NEON_SSHLL =
    NEONShiftImmediateFixed | 0x0000A000;
constexpr NEONShiftImmediateOp NEON_USHLL =
    NEONShiftImmediateFixed | 0x2000A000;
constexpr NEONShiftImmediateOp NEON_SLI = NEONShiftImmediateFixed | 0x20005000;
constexpr NEONShiftImmediateOp NEON_SRI = NEONShiftImmediateFixed | 0x20004000;
constexpr NEONShiftImmediateOp NEON_SHRN = NEONShiftImmediateFixed | 0x00008000;
constexpr NEONShiftImmediateOp NEON_RSHRN =
    NEONShiftImmediateFixed | 0x00008800;
constexpr NEONShiftImmediateOp NEON_UQSHRN =
    NEONShiftImmediateFixed | 0x20009000;
constexpr NEONShiftImmediateOp NEON_UQRSHRN =
    NEONShiftImmediateFixed | 0x20009800;
constexpr NEONShiftImmediateOp NEON_SQSHRN =
    NEONShiftImmediateFixed | 0x00009000;
constexpr NEONShiftImmediateOp NEON_SQRSHRN =
    NEONShiftImmediateFixed | 0x00009800;
constexpr NEONShiftImmediateOp NEON_SQSHRUN =
    NEONShiftImmediateFixed | 0x20008000;
constexpr NEONShiftImmediateOp NEON_SQRSHRUN =
    NEONShiftImmediateFixed | 0x20008800;
constexpr NEONShiftImmediateOp NEON_SSHR = NEONShiftImmediateFixed | 0x00000000;
constexpr NEONShiftImmediateOp NEON_SRSHR =
    NEONShiftImmediateFixed | 0x00002000;
constexpr NEONShiftImmediateOp NEON_USHR = NEONShiftImmediateFixed | 0x20000000;
constexpr NEONShiftImmediateOp NEON_URSHR =
    NEONShiftImmediateFixed | 0x20002000;
constexpr NEONShiftImmediateOp NEON_SSRA = NEONShiftImmediateFixed | 0x00001000;
constexpr NEONShiftImmediateOp NEON_SRSRA =
    NEONShiftImmediateFixed | 0x00003000;
constexpr NEONShiftImmediateOp NEON_USRA = NEONShiftImmediateFixed | 0x20001000;
constexpr NEONShiftImmediateOp NEON_URSRA =
    NEONShiftImmediateFixed | 0x20003000;
constexpr NEONShiftImmediateOp NEON_SQSHLU =
    NEONShiftImmediateFixed | 0x20006000;
constexpr NEONShiftImmediateOp NEON_SCVTF_imm =
    NEONShiftImmediateFixed | 0x0000E000;
constexpr NEONShiftImmediateOp NEON_UCVTF_imm =
    NEONShiftImmediateFixed | 0x2000E000;
constexpr NEONShiftImmediateOp NEON_FCVTZS_imm =
    NEONShiftImmediateFixed | 0x0000F800;
constexpr NEONShiftImmediateOp NEON_FCVTZU_imm =
    NEONShiftImmediateFixed | 0x2000F800;
constexpr NEONShiftImmediateOp NEON_SQSHL_imm =
    NEONShiftImmediateFixed | 0x00007000;
constexpr NEONShiftImmediateOp NEON_UQSHL_imm =
    NEONShiftImmediateFixed | 0x20007000;

// NEON scalar register copy.
using NEONScalarCopyOp = uint32_t;
constexpr NEONScalarCopyOp NEONScalarCopyFixed = 0x5E000400;
constexpr NEONScalarCopyOp NEONScalarCopyFMask = 0xDFE08400;
constexpr NEONScalarCopyOp NEONScalarCopyMask = 0xFFE0FC00;
constexpr NEONScalarCopyOp NEON_DUP_ELEMENT_scalar =
    NEON_Q | NEONScalar | NEON_DUP_ELEMENT;

// NEON scalar pairwise instructions.
using NEONScalarPairwiseOp = uint32_t;
constexpr NEONScalarPairwiseOp NEONScalarPairwiseFixed = 0x5E300800;
constexpr NEONScalarPairwiseOp NEONScalarPairwiseFMask = 0xDF3E0C00;
constexpr NEONScalarPairwiseOp NEONScalarPairwiseMask = 0xFFB1F800;
constexpr NEONScalarPairwiseOp NEON_ADDP_scalar =
    NEONScalarPairwiseFixed | 0x0081B000;
constexpr NEONScalarPairwiseOp NEON_FMAXNMP_scalar =
    NEONScalarPairwiseFixed | 0x2000C000;
constexpr NEONScalarPairwiseOp NEON_FMINNMP_scalar =
    NEONScalarPairwiseFixed | 0x2080C000;
constexpr NEONScalarPairwiseOp NEON_FADDP_scalar =
    NEONScalarPairwiseFixed | 0x2000D000;
constexpr NEONScalarPairwiseOp NEON_FMAXP_scalar =
    NEONScalarPairwiseFixed | 0x2000F000;
constexpr NEONScalarPairwiseOp NEON_FMINP_scalar =
    NEONScalarPairwiseFixed | 0x2080F000;

// NEON scalar shift immediate.
using NEONScalarShiftImmediateOp = uint32_t;
constexpr NEONScalarShiftImmediateOp NEONScalarShiftImmediateFixed = 0x5F000400;
constexpr NEONScalarShiftImmediateOp NEONScalarShiftImmediateFMask = 0xDF800400;
constexpr NEONScalarShiftImmediateOp NEONScalarShiftImmediateMask = 0xFF80FC00;
constexpr NEONScalarShiftImmediateOp NEON_SHL_scalar =
    NEON_Q | NEONScalar | NEON_SHL;
constexpr NEONScalarShiftImmediateOp NEON_SLI_scalar =
    NEON_Q | NEONScalar | NEON_SLI;
constexpr NEONScalarShiftImmediateOp NEON_SRI_scalar =
    NEON_Q | NEONScalar | NEON_SRI;
constexpr NEONScalarShiftImmediateOp NEON_SSHR_scalar =
    NEON_Q | NEONScalar | NEON_SSHR;
constexpr NEONScalarShiftImmediateOp NEON_USHR_scalar =
    NEON_Q | NEONScalar | NEON_USHR;
constexpr NEONScalarShiftImmediateOp NEON_SRSHR_scalar =
    NEON_Q | NEONScalar | NEON_SRSHR;
constexpr NEONScalarShiftImmediateOp NEON_URSHR_scalar =
    NEON_Q | NEONScalar | NEON_URSHR;
constexpr NEONScalarShiftImmediateOp NEON_SSRA_scalar =
    NEON_Q | NEONScalar | NEON_SSRA;
constexpr NEONScalarShiftImmediateOp NEON_USRA_scalar =
    NEON_Q | NEONScalar | NEON_USRA;
constexpr NEONScalarShiftImmediateOp NEON_SRSRA_scalar =
    NEON_Q | NEONScalar | NEON_SRSRA;
constexpr NEONScalarShiftImmediateOp NEON_URSRA_scalar =
    NEON_Q | NEONScalar | NEON_URSRA;
constexpr NEONScalarShiftImmediateOp NEON_UQSHRN_scalar =
    NEON_Q | NEONScalar | NEON_UQSHRN;
constexpr NEONScalarShiftImmediateOp NEON_UQRSHRN_scalar =
    NEON_Q | NEONScalar | NEON_UQRSHRN;
constexpr NEONScalarShiftImmediateOp NEON_SQSHRN_scalar =
    NEON_Q | NEONScalar | NEON_SQSHRN;
constexpr NEONScalarShiftImmediateOp NEON_SQRSHRN_scalar =
    NEON_Q | NEONScalar | NEON_SQRSHRN;
constexpr NEONScalarShiftImmediateOp NEON_SQSHRUN_scalar =
    NEON_Q | NEONScalar | NEON_SQSHRUN;
constexpr NEONScalarShiftImmediateOp NEON_SQRSHRUN_scalar =
    NEON_Q | NEONScalar | NEON_SQRSHRUN;
constexpr NEONScalarShiftImmediateOp NEON_SQSHLU_scalar =
    NEON_Q | NEONScalar | NEON_SQSHLU;
constexpr NEONScalarShiftImmediateOp NEON_SQSHL_imm_scalar =
    NEON_Q | NEONScalar | NEON_SQSHL_imm;
constexpr NEONScalarShiftImmediateOp NEON_UQSHL_imm_scalar =
    NEON_Q | NEONScalar | NEON_UQSHL_imm;
constexpr NEONScalarShiftImmediateOp NEON_SCVTF_imm_scalar =
    NEON_Q | NEONScalar | NEON_SCVTF_imm;
constexpr NEONScalarShiftImmediateOp NEON_UCVTF_imm_scalar =
    NEON_Q | NEONScalar | NEON_UCVTF_imm;
constexpr NEONScalarShiftImmediateOp NEON_FCVTZS_imm_scalar =
    NEON_Q | NEONScalar | NEON_FCVTZS_imm;
constexpr NEONScalarShiftImmediateOp NEON_FCVTZU_imm_scalar =
    NEON_Q | NEONScalar | NEON_FCVTZU_imm;

// NEON table.
using NEONTableOp = uint32_t;
constexpr NEONTableOp NEONTableFixed = 0x0E000000;
constexpr NEONTableOp NEONTableFMask = 0xBF208C00;
constexpr NEONTableOp NEONTableExt = 0x00001000;
constexpr NEONTableOp NEONTableMask = 0xBF20FC00;
constexpr NEONTableOp NEON_TBL_1v = NEONTableFixed | 0x00000000;
constexpr NEONTableOp NEON_TBL_2v = NEONTableFixed | 0x00002000;
constexpr NEONTableOp NEON_TBL_3v = NEONTableFixed | 0x00004000;
constexpr NEONTableOp NEON_TBL_4v = NEONTableFixed | 0x00006000;
constexpr NEONTableOp NEON_TBX_1v = NEON_TBL_1v | NEONTableExt;
constexpr NEONTableOp NEON_TBX_2v = NEON_TBL_2v | NEONTableExt;
constexpr NEONTableOp NEON_TBX_3v = NEON_TBL_3v | NEONTableExt;
constexpr NEONTableOp NEON_TBX_4v = NEON_TBL_4v | NEONTableExt;

// NEON perm.
using NEONPermOp = uint32_t;
constexpr NEONPermOp NEONPermFixed = 0x0E000800;
constexpr NEONPermOp NEONPermFMask = 0xBF208C00;
constexpr NEONPermOp NEONPermMask = 0x3F20FC00;
constexpr NEONPermOp NEON_UZP1 = NEONPermFixed | 0x00001000;
constexpr NEONPermOp NEON_TRN1 = NEONPermFixed | 0x00002000;
constexpr NEONPermOp NEON_ZIP1 = NEONPermFixed | 0x00003000;
constexpr NEONPermOp NEON_UZP2 = NEONPermFixed | 0x00005000;
constexpr NEONPermOp NEON_TRN2 = NEONPermFixed | 0x00006000;
constexpr NEONPermOp NEON_ZIP2 = NEONPermFixed | 0x00007000;

// NEON scalar instructions with two register operands.
using NEONScalar2RegMiscOp = uint32_t;
constexpr NEONScalar2RegMiscOp NEONScalar2RegMiscFixed = 0x5E200800;
constexpr NEONScalar2RegMiscOp NEONScalar2RegMiscFMask = 0xDF3E0C00;
constexpr NEONScalar2RegMiscOp NEONScalar2RegMiscMask =
    NEON_Q | NEONScalar | NEON2RegMiscMask;
constexpr NEONScalar2RegMiscOp NEON_CMGT_zero_scalar =
    NEON_Q | NEONScalar | NEON_CMGT_zero;
constexpr NEONScalar2RegMiscOp NEON_CMEQ_zero_scalar =
    NEON_Q | NEONScalar | NEON_CMEQ_zero;
constexpr NEONScalar2RegMiscOp NEON_CMLT_zero_scalar =
    NEON_Q | NEONScalar | NEON_CMLT_zero;
constexpr NEONScalar2RegMiscOp NEON_CMGE_zero_scalar =
    NEON_Q | NEONScalar | NEON_CMGE_zero;
constexpr NEONScalar2RegMiscOp NEON_CMLE_zero_scalar =
    NEON_Q | NEONScalar | NEON_CMLE_zero;
constexpr NEONScalar2RegMiscOp NEON_ABS_scalar = NEON_Q | NEONScalar | NEON_ABS;
constexpr NEONScalar2RegMiscOp NEON_SQABS_scalar =
    NEON_Q | NEONScalar | NEON_SQABS;
constexpr NEONScalar2RegMiscOp NEON_NEG_scalar = NEON_Q | NEONScalar | NEON_NEG;
constexpr NEONScalar2RegMiscOp NEON_SQNEG_scalar =
    NEON_Q | NEONScalar | NEON_SQNEG;
constexpr NEONScalar2RegMiscOp NEON_SQXTN_scalar =
    NEON_Q | NEONScalar | NEON_SQXTN;
constexpr NEONScalar2RegMiscOp NEON_UQXTN_scalar =
    NEON_Q | NEONScalar | NEON_UQXTN;
constexpr NEONScalar2RegMiscOp NEON_SQXTUN_scalar =
    NEON_Q | NEONScalar | NEON_SQXTUN;
constexpr NEONScalar2RegMiscOp NEON_SUQADD_scalar =
    NEON_Q | NEONScalar | NEON_SUQADD;
constexpr NEONScalar2RegMiscOp NEON_USQADD_scalar =
    NEON_Q | NEONScalar | NEON_USQADD;

constexpr NEONScalar2RegMiscOp NEONScalar2RegMiscOpcode = NEON2RegMiscOpcode;
constexpr NEONScalar2RegMiscOp NEON_NEG_scalar_opcode =
    NEON_NEG_scalar & NEONScalar2RegMiscOpcode;

constexpr NEONScalar2RegMiscOp NEONScalar2RegMiscFPMask =
    NEONScalar2RegMiscMask | 0x00800000;
constexpr NEONScalar2RegMiscOp NEON_FRSQRTE_scalar =
    NEON_Q | NEONScalar | NEON_FRSQRTE;
constexpr NEONScalar2RegMiscOp NEON_FRECPE_scalar =
    NEON_Q | NEONScalar | NEON_FRECPE;
constexpr NEONScalar2RegMiscOp NEON_SCVTF_scalar =
    NEON_Q | NEONScalar | NEON_SCVTF;
constexpr NEONScalar2RegMiscOp NEON_UCVTF_scalar =
    NEON_Q | NEONScalar | NEON_UCVTF;
constexpr NEONScalar2RegMiscOp NEON_FCMGT_zero_scalar =
    NEON_Q | NEONScalar | NEON_FCMGT_zero;
constexpr NEONScalar2RegMiscOp NEON_FCMEQ_zero_scalar =
    NEON_Q | NEONScalar | NEON_FCMEQ_zero;
constexpr NEONScalar2RegMiscOp NEON_FCMLT_zero_scalar =
    NEON_Q | NEONScalar | NEON_FCMLT_zero;
constexpr NEONScalar2RegMiscOp NEON_FCMGE_zero_scalar =
    NEON_Q | NEONScalar | NEON_FCMGE_zero;
constexpr NEONScalar2RegMiscOp NEON_FCMLE_zero_scalar =
    NEON_Q | NEONScalar | NEON_FCMLE_zero;
constexpr NEONScalar2RegMiscOp NEON_FRECPX_scalar =
    NEONScalar2RegMiscFixed | 0x0081F000;
constexpr NEONScalar2RegMiscOp NEON_FCVTNS_scalar =
    NEON_Q | NEONScalar | NEON_FCVTNS;
constexpr NEONScalar2RegMiscOp NEON_FCVTNU_scalar =
    NEON_Q | NEONScalar | NEON_FCVTNU;
constexpr NEONScalar2RegMiscOp NEON_FCVTPS_scalar =
    NEON_Q | NEONScalar | NEON_FCVTPS;
constexpr NEONScalar2RegMiscOp NEON_FCVTPU_scalar =
    NEON_Q | NEONScalar | NEON_FCVTPU;
constexpr NEONScalar2RegMiscOp NEON_FCVTMS_scalar =
    NEON_Q | NEONScalar | NEON_FCVTMS;
constexpr NEONScalar2RegMiscOp NEON_FCVTMU_scalar =
    NEON_Q | NEONScalar | NEON_FCVTMU;
constexpr NEONScalar2RegMiscOp NEON_FCVTZS_scalar =
    NEON_Q | NEONScalar | NEON_FCVTZS;
constexpr NEONScalar2RegMiscOp NEON_FCVTZU_scalar =
    NEON_Q | NEONScalar | NEON_FCVTZU;
constexpr NEONScalar2RegMiscOp NEON_FCVTAS_scalar =
    NEON_Q | NEONScalar | NEON_FCVTAS;
constexpr NEONScalar2RegMiscOp NEON_FCVTAU_scalar =
    NEON_Q | NEONScalar | NEON_FCVTAU;
constexpr NEONScalar2RegMiscOp NEON_FCVTXN_scalar =
    NEON_Q | NEONScalar | NEON_FCVTXN;

// NEON scalar instructions with three same-type operands.
using NEONScalar3SameOp = uint32_t;
constexpr NEONScalar3SameOp NEONScalar3SameFixed = 0x5E200400;
constexpr NEONScalar3SameOp NEONScalar3SameFMask = 0xDF200400;
constexpr NEONScalar3SameOp NEONScalar3SameMask = 0xFF20FC00;
constexpr NEONScalar3SameOp NEON_ADD_scalar = NEON_Q | NEONScalar | NEON_ADD;
constexpr NEONScalar3SameOp NEON_CMEQ_scalar = NEON_Q | NEONScalar | NEON_CMEQ;
constexpr NEONScalar3SameOp NEON_CMGE_scalar = NEON_Q | NEONScalar | NEON_CMGE;
constexpr NEONScalar3SameOp NEON_CMGT_scalar = NEON_Q | NEONScalar | NEON_CMGT;
constexpr NEONScalar3SameOp NEON_CMHI_scalar = NEON_Q | NEONScalar | NEON_CMHI;
constexpr NEONScalar3SameOp NEON_CMHS_scalar = NEON_Q | NEONScalar | NEON_CMHS;
constexpr NEONScalar3SameOp NEON_CMTST_scalar =
    NEON_Q | NEONScalar | NEON_CMTST;
constexpr NEONScalar3SameOp NEON_SUB_scalar = NEON_Q | NEONScalar | NEON_SUB;
constexpr NEONScalar3SameOp NEON_UQADD_scalar =
    NEON_Q | NEONScalar | NEON_UQADD;
constexpr NEONScalar3SameOp NEON_SQADD_scalar =
    NEON_Q | NEONScalar | NEON_SQADD;
constexpr NEONScalar3SameOp NEON_UQSUB_scalar =
    NEON_Q | NEONScalar | NEON_UQSUB;
constexpr NEONScalar3SameOp NEON_SQSUB_scalar =
    NEON_Q | NEONScalar | NEON_SQSUB;
constexpr NEONScalar3SameOp NEON_USHL_scalar = NEON_Q | NEONScalar | NEON_USHL;
constexpr NEONScalar3SameOp NEON_SSHL_scalar = NEON_Q | NEONScalar | NEON_SSHL;
constexpr NEONScalar3SameOp NEON_UQSHL_scalar =
    NEON_Q | NEONScalar | NEON_UQSHL;
constexpr NEONScalar3SameOp NEON_SQSHL_scalar =
    NEON_Q | NEONScalar | NEON_SQSHL;
constexpr NEONScalar3SameOp NEON_URSHL_scalar =
    NEON_Q | NEONScalar | NEON_URSHL;
constexpr NEONScalar3SameOp NEON_SRSHL_scalar =
    NEON_Q | NEONScalar | NEON_SRSHL;
constexpr NEONScalar3SameOp NEON_UQRSHL_scalar =
    NEON_Q | NEONScalar | NEON_UQRSHL;
constexpr NEONScalar3SameOp NEON_SQRSHL_scalar =
    NEON_Q | NEONScalar | NEON_SQRSHL;
constexpr NEONScalar3SameOp NEON_SQDMULH_scalar =
    NEON_Q | NEONScalar | NEON_SQDMULH;
constexpr NEONScalar3SameOp NEON_SQRDMULH_scalar =
    NEON_Q | NEONScalar | NEON_SQRDMULH;

// NEON floating point scalar instructions with three same-type operands.
constexpr NEONScalar3SameOp NEONScalar3SameFPFixed =
    NEONScalar3SameFixed | 0x0000C000;
constexpr NEONScalar3SameOp NEONScalar3SameFPFMask =
    NEONScalar3SameFMask | 0x0000C000;
constexpr NEONScalar3SameOp NEONScalar3SameFPMask =
    NEONScalar3SameMask | 0x00800000;
constexpr NEONScalar3SameOp NEON_FACGE_scalar =
    NEON_Q | NEONScalar | NEON_FACGE;
constexpr NEONScalar3SameOp NEON_FACGT_scalar =
    NEON_Q | NEONScalar | NEON_FACGT;
constexpr NEONScalar3SameOp NEON_FCMEQ_scalar =
    NEON_Q | NEONScalar | NEON_FCMEQ;
constexpr NEONScalar3SameOp NEON_FCMGE_scalar =
    NEON_Q | NEONScalar | NEON_FCMGE;
constexpr NEONScalar3SameOp NEON_FCMGT_scalar =
    NEON_Q | NEONScalar | NEON_FCMGT;
constexpr NEONScalar3SameOp NEON_FMULX_scalar =
    NEON_Q | NEONScalar | NEON_FMULX;
constexpr NEONScalar3SameOp NEON_FRECPS_scalar =
    NEON_Q | NEONScalar | NEON_FRECPS;
constexpr NEONScalar3SameOp NEON_FRSQRTS_scalar =
    NEON_Q | NEONScalar | NEON_FRSQRTS;
constexpr NEONScalar3SameOp NEON_FABD_scalar = NEON_Q | NEONScalar | NEON_FABD;

// NEON scalar instructions with three different-type operands.
using NEONScalar3DiffOp = uint32_t;
constexpr NEONScalar3DiffOp NEONScalar3DiffFixed = 0x5E200000;
constexpr NEONScalar3DiffOp NEONScalar3DiffFMask = 0xDF200C00;
constexpr NEONScalar3DiffOp NEONScalar3DiffMask =
    NEON_Q | NEONScalar | NEON3DifferentMask;
constexpr NEONScalar3DiffOp NEON_SQDMLAL_scalar =
    NEON_Q | NEONScalar | NEON_SQDMLAL;
constexpr NEONScalar3DiffOp NEON_SQDMLSL_scalar =
    NEON_Q | NEONScalar | NEON_SQDMLSL;
constexpr NEONScalar3DiffOp NEON_SQDMULL_scalar =
    NEON_Q | NEONScalar | NEON_SQDMULL;

// Unimplemented and unallocated instructions. These are defined to make fixed
// bit assertion easier.
using UnimplementedOp = uint32_t;
constexpr UnimplementedOp UnimplementedFixed = 0x00000000;
constexpr UnimplementedOp UnimplementedFMask = 0x00000000;

using UnallocatedOp = uint32_t;
constexpr UnallocatedOp UnallocatedFixed = 0x00000000;
constexpr UnallocatedOp UnallocatedFMask = 0x00000000;

}  // namespace internal
}  // namespace v8

#endif  // V8_CODEGEN_ARM64_CONSTANTS_ARM64_H_

"""


```