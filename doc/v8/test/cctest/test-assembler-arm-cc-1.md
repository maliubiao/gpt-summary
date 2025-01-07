Response:
The user wants to understand the functionality of a C++ source code file `v8/test/cctest/test-assembler-arm.cc`. This is the second part of a five-part code snippet.

Here's a breakdown of the thought process to analyze the provided code:

1. **Identify the core purpose:** The file name and the presence of `Assembler` suggest that this code tests the ARM assembler functionality within the V8 JavaScript engine. The numerous `TEST` macros confirm this is a unit test file. The focus on NEON instructions is evident by the `CpuFeatures::IsSupported(NEON)` check and the abundance of Neon-specific assembly instructions.

2. **Examine the `TEST` block:** The provided snippet contains one large `TEST(15)` block. This indicates that this test focuses on a specific set of ARM NEON instructions.

3. **Analyze the `struct T`:** The `struct T` defines a layout in memory. Its members are likely used as input and output buffers for the assembly code being tested. The names of the fields (`src0`, `dst0`, `vmov`, `vaddf`, etc.) strongly suggest they correspond to specific ARM/NEON instructions.

4. **Understand the macros:** The code defines several helper macros (`CHECK_EQ`, `CHECK_EQ_32X2`, etc.). These are used to verify the results of the assembly code by comparing the actual output in `struct T` with expected values.

5. **Trace the assembly instructions:** Inside the `TEST` block, an `Assembler` object is created. The code within the `if (CpuFeatures::IsSupported(NEON))` block executes only if the processor supports NEON instructions. The assembly instructions use V8's `__` prefixed mnemonics. The instructions primarily involve:
    * **Data loading and storing:** `vld1`, `vst1`, `vstr`. These move data between memory and NEON registers.
    * **Data manipulation:** `vmov`, `vmvn`, `vcvt`, `vdup`, `vabs`, `vneg`, `veor`, `vand`, `vorr`, `vmin`, `vmax`, `vadd`, `vpadd`, `vsub`, `vmul`, `vrecpe`, `vrecps`, `vrsqrte`, `vrsqrts`, `vceq`, `vcge`, `vcgt`, `vshl`, `vshr`, `vsli`, `vsri`, `vsra`, `vtst`, `vbsl`, `vext`, `vzip`, `vuzp`, `vrev`, `vtrn`. These represent a wide range of NEON operations on different data types.
    * **Register manipulation:**  Moving data between core ARM registers and NEON registers (`vmov` with core registers).

6. **Infer the testing strategy:** The test seems to be setting up input data in the `struct T`, executing a sequence of NEON assembly instructions that operate on this data, and then storing the results back into `struct T`. The subsequent parts of the test (not included in this snippet) will likely use the `CHECK_*` macros to verify the correctness of these operations.

7. **Address the specific questions:**

    * **Functionality:**  The code tests various ARM NEON assembler instructions.
    * **`.tq` extension:**  The code is C++, not Torque.
    * **JavaScript relation:** NEON instructions are low-level and generally not directly exposed in JavaScript. However, V8 uses them internally to optimize certain operations, particularly those involving SIMD (Single Instruction, Multiple Data) processing.
    * **Code logic and I/O:**  The input is the initial state of `struct T`. The assembly instructions transform this data. The output is the modified state of `struct T`. Since the exact initial values and verification logic are in other parts of the file, providing a precise input/output example is difficult.
    * **Common programming errors:**  While this specific code is for testing, common errors when *using* NEON assembly include incorrect data types, misaligned memory accesses, and incorrect register usage.

8. **Synthesize the summary:** Combine the findings from the analysis to create a concise summary of the code's functionality. Emphasize the focus on testing NEON instructions, the use of `struct T` for data, and the lack of direct JavaScript interaction in the test itself. Acknowledge that this is part 2 of a larger test file.
这是V8源代码文件 `v8/test/cctest/test-assembler-arm.cc` 的第二部分，它主要的功能是**测试ARM架构的汇编器 (Assembler) 中关于NEON（Advanced SIMD）指令的生成和执行是否正确**。

以下是对代码片段功能的归纳：

1. **定义辅助宏:**  代码开头定义了一些宏 (`CHECK_EQ`, `CHECK_EQ_32X2`, `CHECK_EQ_32X4`, `CHECK_ESTIMATE`, `CHECK_ESTIMATE_SPLAT`)，用于在测试中比较预期值和实际值，方便断言测试结果是否符合预期。

2. **定义测试用数据结构 `T`:**  定义了一个结构体 `T`，包含了多种类型的成员变量，例如 `uint32_t`, `uint64_t`, `float` 以及数组。这些成员变量被设计用来作为NEON指令的源操作数和目标操作数，用于测试各种NEON指令的功能。

3. **测试用例 `TEST(15)`:**  包含了一个名为 `15` 的测试用例。这个测试用例专门用于测试各种不同的NEON指令。

4. **NEON 指令测试:** 在 `TEST(15)` 中，如果系统支持 NEON 指令集 (`CpuFeatures::IsSupported(NEON)`), 则会执行以下操作：
    * **加载和存储数据:** 使用 `vld1` 和 `vst1` 指令在内存和NEON寄存器之间移动数据。
    * **数据扩展和窄化:** 使用 `vmovl` 指令将较小的数据类型扩展到较大的数据类型，使用 `vqmovn` 指令将较大的数据类型窄化到较小的数据类型。
    * **标量和向量之间的移动:** 使用 `vmov` 指令在ARM核心寄存器和NEON标量寄存器之间移动数据。
    * **向量操作:** 测试了大量的NEON向量操作指令，包括：
        * **算术运算:** `vadd`, `vsub`, `vmul`, `vabs`, `vneg`, `vpadd`, `vqadd`, `vqsub`
        * **位运算:** `veor`, `vand`, `vorr`
        * **比较运算:** `vceq`, `vcge`, `vcgt`, `vclt`
        * **移位操作:** `vshl`, `vshr`, `vsli`, `vsri`, `vsra`
        * **浮点运算:** `vaddf`, `vsubf`, `vmulf`, `vabsf`, `vnegf`, `vpaddf`, `vminf`, `vmaxf`, `vrecpe`, `vrecps`, `vrsqrte`, `vrsqrts`
        * **数据复制:** `vdup`
        * **数据重排:** `vext`, `vzip`, `vuzp`, `vrev`, `vtrn`, `vtbl`, `vtbx`
        * **条件选择:** `vbsl`
        * **按位测试:** `vtst`
    * **将结果存储回内存:** 使用 `vstr` 和 `vst1` 指令将NEON寄存器中的结果存储回结构体 `T` 的成员变量中。

**如果 `v8/test/cctest/test-assembler-arm.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码:**

这个说法是**错误**的。当前的文件名是 `v8/test/cctest/test-assembler-arm.cc`，以 `.cc` 结尾，表明这是一个 **C++** 源代码文件。 Torque 源代码文件通常以 `.tq` 结尾。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

虽然这个 C++ 代码是测试 V8 引擎的底层汇编器，但它间接地与 JavaScript 的性能有关。V8 引擎在执行 JavaScript 代码时，会将其编译成机器码，其中就可能涉及到这些 ARM NEON 指令的运用。NEON 指令可以加速诸如图像处理、音频处理、数学计算等需要并行处理的 JavaScript 操作。

虽然 JavaScript 本身不能直接调用这些 NEON 指令，但 V8 引擎在底层会利用它们来优化某些 JavaScript 操作。例如，当你在 JavaScript 中进行大量数值计算或者操作 Typed Arrays 时，V8 可能会使用 NEON 指令来提高效率。

**JavaScript 例子 (体现 NEON 指令可能在底层优化的场景):**

```javascript
// 假设我们有一个很大的 Float32Array
const array1 = new Float32Array(1024);
const array2 = new Float32Array(1024);
const result = new Float32Array(1024);

// 初始化数组 (省略)

// 执行向量加法 (V8 可能会在底层使用 NEON 指令优化)
for (let i = 0; i < array1.length; i++) {
  result[i] = array1[i] + array2[i];
}

// 或者使用更高级的 WebAssembly SIMD API (更直接地体现 SIMD 概念)
// (需要 WebAssembly 支持)
// const wasmModule = new WebAssembly.Module( ... );
// const wasmInstance = new WebAssembly.Instance(wasmModule);
// wasmInstance.exports.vectorAdd(array1, array2, result);
```

在这个 JavaScript 例子中，循环进行浮点数加法操作。V8 引擎在运行时可能会检测到这种模式，并尝试使用底层的 NEON 指令并行地执行多个加法操作，从而提高性能。

**如果有代码逻辑推理，请给出假设输入与输出:**

由于这段代码是汇编测试，具体的输入和输出是结构体 `T` 中各个成员变量的值。我们以其中一个测试的 NEON 指令为例：

**假设输入:**

在执行 `vadd(Neon8, q1, q1, q0);` 之前，结构体 `T` 的状态是（假设）：

* `t.lane_test` 数组被加载到 NEON 寄存器 `q0`，假设 `q0` 的值为 `[1, 2, 3, 4, 5, 6, 7, 8]` (每个元素是8位整数)。
* NEON 寄存器 `q1` 被用相同的值初始化，即 `q1` 的值为 `[1, 2, 3, 4, 5, 6, 7, 8]`。

**代码逻辑:**

执行 `vadd(Neon8, q1, q1, q0);`  这条指令会将 `q1` 和 `q0` 中对应位置的 8 位整数相加，结果存储回 `q1`。

**预期输出:**

执行 `vadd` 后，NEON 寄存器 `q1` 的值变为 `[1+1, 2+2, 3+3, 4+4, 5+5, 6+6, 7+7, 8+8]`，即 `[2, 4, 6, 8, 10, 12, 14, 16]`。

然后，代码会将 `q1` 的值存储到 `t.vadd8` 数组中。因此，`t.vadd8` 的值预计为 `[2, 4, 6, 8]`. (注意 `vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));` 会根据寄存器大小和存储类型写入相应数量的数据)

**如果涉及用户常见的编程错误，请举例说明:**

虽然这段代码是 V8 内部的测试代码，用户不会直接编写这样的代码，但理解它测试的指令有助于避免在使用支持 SIMD 的 API (例如 WebAssembly SIMD) 时犯类似的错误。

**常见的与 SIMD 相关的编程错误 (在更贴近用户编程的层面):**

1. **数据类型不匹配:**  例如，尝试将 `int32` 类型的向量与 `float32` 类型的向量进行加法运算，而没有进行显式的类型转换。这会导致未定义的行为或编译错误。

2. **向量长度不匹配:**  某些 SIMD 指令要求操作的向量长度相同。如果向量长度不一致，可能会导致错误。

3. **内存对齐问题:**  SIMD 指令通常对内存对齐有要求。如果加载或存储的数据地址没有正确对齐（例如，没有按照 16 字节或 32 字节对齐），会导致性能下降甚至程序崩溃。

4. **错误地理解指令语义:**  不同的 SIMD 指令有不同的行为。例如，饱和加法 (`vqadd`) 和普通加法 (`vadd`) 在溢出时的处理方式不同。错误地理解指令的语义会导致计算结果错误。

5. **过度依赖编译器优化:**  虽然编译器可以自动向量化某些循环，但并非所有循环都能被有效优化。开发者需要了解哪些操作可以被向量化，并在必要时使用显式的 SIMD 指令或库。

**这是第2部分，共5部分，请归纳一下它的功能:**

总而言之，这部分代码（第2部分）的功能是：

* **定义了测试 NEON 指令所需的数据结构 `T`。**
* **包含了一个主要的测试用例 `TEST(15)`，用于测试各种 ARM NEON 指令的功能。**
* **通过执行一系列 NEON 汇编指令，并将其结果存储回内存，为后续的断言测试做准备。**
* **间接测试了 V8 引擎在处理可能使用 NEON 优化的场景下的正确性。**

后续的部分很可能会包含：

* **设置 `struct T` 的初始值。**
* **使用 `CHECK_*` 宏来验证执行 NEON 指令后的 `struct T` 的成员变量值是否符合预期。**
* **可能包含其他针对不同 NEON 指令或特性的测试用例。**

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
, t.field[3]);

#define CHECK_EQ_32X2(field, ex0, ex1) \
  CHECK_EQ(ex0, t.field[0]);           \
  CHECK_EQ(ex1, t.field[1]);

#define CHECK_EQ_32X4(field, ex0, ex1, ex2, ex3) \
  CHECK_EQ(ex0, t.field[0]);                     \
  CHECK_EQ(ex1, t.field[1]);                     \
  CHECK_EQ(ex2, t.field[2]);                     \
  CHECK_EQ(ex3, t.field[3]);

#define CHECK_ESTIMATE(expected, tolerance, value) \
  CHECK_LT((expected) - (tolerance), value);       \
  CHECK_GT((expected) + (tolerance), value);

#define CHECK_ESTIMATE_SPLAT(field, ex, tol) \
  CHECK_ESTIMATE(ex, tol, t.field[0]);       \
  CHECK_ESTIMATE(ex, tol, t.field[1]);       \
  CHECK_ESTIMATE(ex, tol, t.field[2]);       \
  CHECK_ESTIMATE(ex, tol, t.field[3]);

#define INT32_TO_FLOAT(val) \
  std::round(static_cast<float>(base::bit_cast<int32_t>(val)))
#define UINT32_TO_FLOAT(val) \
  std::round(static_cast<float>(base::bit_cast<uint32_t>(val)))

TEST(15) {
  // Test the Neon instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint32_t src0;
    uint32_t src1;
    uint32_t src2;
    uint32_t src3;
    uint32_t src4;
    uint32_t src5;
    uint32_t src6;
    uint32_t src7;
    uint32_t dst0;
    uint32_t dst1;
    uint32_t dst2;
    uint32_t dst3;
    uint32_t dst4;
    uint32_t dst5;
    uint32_t dst6;
    uint32_t dst7;
    uint32_t srcA0;
    uint32_t srcA1;
    uint32_t dstA0;
    uint32_t dstA1;
    uint32_t dstA2;
    uint32_t dstA3;
    uint32_t lane_test[4];
    uint64_t vmov_to_scalar1, vmov_to_scalar2;
    uint32_t vmov_from_scalar_s8, vmov_from_scalar_u8;
    uint32_t vmov_from_scalar_s16, vmov_from_scalar_u16;
    uint32_t vmov_from_scalar_32;
    uint32_t vmov[4], vmvn[4];
    uint32_t vmovl_s8[4], vmovl_u16[4], vmovl_s32[4];
    uint32_t vqmovn_s8[2], vqmovn_u16[2], vqmovn_s32[2];
    int32_t vcvt_s32_f32[4];
    uint32_t vcvt_u32_f32[4];
    float vcvt_f32_s32[4], vcvt_f32_u32[4];
    uint32_t vdup8[4], vdup16[4], vdup32[4];
    float vabsf[4], vnegf[4];
    uint32_t vclt0_s8[4], vclt0_s16[4], vclt0_s32[4];
    uint32_t vabs_s8[4], vabs_s16[4], vabs_s32[4];
    uint32_t vneg_s8[4], vneg_s16[4], vneg_s32[4];
    uint32_t veor[4], vand[4], vorr[4];
    float vdupf[4], vaddf[4], vpaddf[2], vsubf[4], vmulf[4];
    uint32_t vdupf_16[2], vdupf_8[4];
    uint32_t vmin_s8[4], vmin_u16[4], vmin_s32[4];
    uint32_t vmax_s8[4], vmax_u16[4], vmax_s32[4];
    uint32_t vpadd_i8[2], vpadd_i16[2], vpadd_i32[2];
    uint32_t vpadal_s8[4], vpadal_s16[4], vpadal_s32[4];
    uint32_t vpadal_u8[4], vpadal_u16[4], vpadal_u32[4];
    uint32_t vpaddl_s8[4], vpaddl_s16[4], vpaddl_s32[4];
    uint32_t vpaddl_u8[4], vpaddl_u16[4], vpaddl_u32[4];
    uint32_t vpmin_s8[2], vpmin_u16[2], vpmin_s32[2];
    uint32_t vpmax_s8[2], vpmax_u16[2], vpmax_s32[2];
    uint32_t vadd8[4], vadd16[4], vadd32[4];
    uint32_t vqadd_s8[4], vqadd_u16[4], vqadd_s32[4];
    uint32_t vsub8[4], vsub16[4], vsub32[4];
    uint32_t vqsub_u8[4], vqsub_s16[4], vqsub_u32[4];
    uint32_t vmul8[4], vmul16[4], vmul32[4];
    uint32_t vshl8[4], vshl16[4], vshl32[4];
    uint32_t vshr_s8[4], vshr_u16[4], vshr_s32[4];
    uint32_t vshr_s8_d[2], vshr_u16_d[2], vshr_s32_d[2];
    uint32_t vsli_64[2], vsri_64[2], vsli_32[2], vsri_32[2];
    uint32_t vsra_64[2], vsra_32[2], vsra_16[2];
    uint32_t vceq[4], vceqf[4], vcgef[4], vcgtf[4];
    uint32_t vcge_s8[4], vcge_u16[4], vcge_s32[4];
    uint32_t vcgt_s8[4], vcgt_u16[4], vcgt_s32[4];
    float vrecpe[4], vrecps[4], vrsqrte[4], vrsqrts[4];
    float vminf[4], vmaxf[4];
    uint32_t vtst[4], vbsl[4];
    uint32_t vext[4];
    uint32_t vzip8a[4], vzip8b[4], vzip16a[4], vzip16b[4], vzip32a[4],
        vzip32b[4];
    uint32_t vzipd8a[2], vzipd8b[2], vzipd16a[2], vzipd16b[2];
    uint32_t vuzp8a[4], vuzp8b[4], vuzp16a[4], vuzp16b[4], vuzp32a[4],
        vuzp32b[4];
    uint32_t vuzpd8a[2], vuzpd8b[2], vuzpd16a[2], vuzpd16b[2];
    uint32_t vrev64_32[4], vrev64_16[4], vrev64_8[4];
    uint32_t vrev32_16[4], vrev32_8[4], vrev16_8[4];
    uint32_t vtrn8a[4], vtrn8b[4], vtrn16a[4], vtrn16b[4], vtrn32a[4],
        vtrn32b[4];
    uint32_t vtrnd8a[2], vtrnd8b[2], vtrnd16a[2], vtrnd16b[2], vtrnd32a[2],
        vtrnd32b[2];
    uint32_t vtbl[2], vtbx[2];
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles, floats, and SIMD values.
  Assembler assm(AssemblerOptions{});

  if (CpuFeatures::IsSupported(NEON)) {
    CpuFeatureScope scope(&assm, NEON);

    __ stm(db_w, sp, {r4, r5, lr});
    // Move 32 bytes with neon.
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, src0))));
    __ vld1(Neon8, NeonListOperand(d0, 4), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, dst0))));
    __ vst1(Neon8, NeonListOperand(d0, 4), NeonMemOperand(r4));

    // Expand 8 bytes into 8 words(16 bits).
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, srcA0))));
    __ vld1(Neon8, NeonListOperand(d0), NeonMemOperand(r4));
    __ vmovl(NeonU8, q0, d0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, dstA0))));
    __ vst1(Neon8, NeonListOperand(d0, 2), NeonMemOperand(r4));

    // The same expansion, but with different source and destination registers.
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, srcA0))));
    __ vld1(Neon8, NeonListOperand(d1), NeonMemOperand(r4));
    __ vmovl(NeonS8, q1, d1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmovl_s8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vmovl(NeonU16, q2, d3);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmovl_u16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vmovl(NeonS32, q3, d4);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmovl_s32))));
    __ vst1(Neon8, NeonListOperand(q3), NeonMemOperand(r4));
    // Narrow what we widened.
    __ vqmovn(NeonU16, NeonU16, d0, q2);
    __ vstr(d0, r0, offsetof(T, vqmovn_u16));
    __ vmov(d1, d0);
    __ vqmovn(NeonS8, NeonS8, d2, q0);
    __ vstr(d2, r0, offsetof(T, vqmovn_s8));
    __ vqmovn(NeonS32, NeonS32, d4, q3);
    __ vstr(d4, r0, offsetof(T, vqmovn_s32));

    // ARM core register to scalar.
    __ mov(r4, Operand(0xFFFFFFF8));
    __ vmov(d0, base::Double(0.0));
    __ vmov(NeonS8, d0, 1, r4);
    __ vmov(NeonS16, d0, 1, r4);
    __ vmov(NeonS32, d0, 1, r4);
    __ vstr(d0, r0, offsetof(T, vmov_to_scalar1));
    __ vmov(d0, base::Double(0.0));
    __ vmov(NeonS8, d0, 3, r4);
    __ vmov(NeonS16, d0, 3, r4);
    __ vstr(d0, r0, offsetof(T, vmov_to_scalar2));

    // Scalar to ARM core register.
    __ mov(r4, Operand(0xFFFFFF00));
    __ mov(r5, Operand(0xFFFFFFFF));
    __ vmov(d0, r4, r5);
    __ vmov(NeonS8, r4, d0, 1);
    __ str(r4, MemOperand(r0, offsetof(T, vmov_from_scalar_s8)));
    __ vmov(NeonU8, r4, d0, 1);
    __ str(r4, MemOperand(r0, offsetof(T, vmov_from_scalar_u8)));
    __ vmov(NeonS16, r4, d0, 1);
    __ str(r4, MemOperand(r0, offsetof(T, vmov_from_scalar_s16)));
    __ vmov(NeonU16, r4, d0, 1);
    __ str(r4, MemOperand(r0, offsetof(T, vmov_from_scalar_u16)));
    __ vmov(NeonS32, r4, d0, 1);
    __ str(r4, MemOperand(r0, offsetof(T, vmov_from_scalar_32)));

    // vmov for q-registers.
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmov))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vmvn.
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmvn(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmvn))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vcvt for q-registers.
    __ vmov(s0, Float32(-1.5f));
    __ vmov(s1, Float32(-1.0f));
    __ vmov(s2, Float32(1.0f));
    __ vmov(s3, Float32(1.5f));
    __ vcvt_s32_f32(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcvt_s32_f32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vcvt_u32_f32(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcvt_u32_f32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(kMinInt));
    __ mov(r5, Operand(kMaxInt));
    __ vmov(d0, r4, r5);
    __ mov(r4, Operand(kMaxUInt32));
    __ mov(r5, Operand(kMinInt + 1));
    __ vmov(d1, r4, r5);  // q0 = [kMinInt, kMaxInt, kMaxUInt32, kMinInt + 1]
    __ vcvt_f32_s32(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcvt_f32_s32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vcvt_f32_u32(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcvt_f32_u32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vdup (from register).
    __ mov(r4, Operand(0xA));
    __ vdup(Neon8, q0, r4);
    __ vdup(Neon16, q1, r4);
    __ vdup(Neon32, q2, r4);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vdup8))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vdup16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vdup32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vdup (from scalar).
    __ vmov(s0, Float32(-1.0f));
    __ vdup(Neon32, q1, d0, 0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vdupf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vdup(Neon16, d2, d0, 1);
    __ vstr(d2, r0, offsetof(T, vdupf_16));
    __ vdup(Neon8, q1, d0, 3);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vdupf_8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vabs (float).
    __ vmov(s0, Float32(-1.0f));
    __ vmov(s1, Float32(-0.0f));
    __ vmov(s2, Float32(0.0f));
    __ vmov(s3, Float32(1.0f));
    __ vabs(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vabsf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vneg (float).
    __ vneg(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vnegf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vabs (integer).
    __ mov(r4, Operand(0x7F7F7F7F));
    __ mov(r5, Operand(0x01010101));
    __ vmov(d0, r4, r5);
    __ mov(r4, Operand(0xFFFFFFFF));
    __ mov(r5, Operand(0x80808080));
    __ vmov(d1, r4, r5);
    __ vabs(Neon8, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vabs_s8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vabs(Neon16, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vabs_s16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vabs(Neon32, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vabs_s32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vneg (integer).
    __ vneg(Neon8, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vneg_s8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vneg(Neon16, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vneg_s16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vneg(Neon32, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vneg_s32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // veor.
    __ mov(r4, Operand(0xAA));
    __ vdup(Neon16, q0, r4);
    __ mov(r4, Operand(0x55));
    __ vdup(Neon16, q1, r4);
    __ veor(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, veor))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vand.
    __ mov(r4, Operand(0xFF));
    __ vdup(Neon16, q0, r4);
    __ mov(r4, Operand(0xFE));
    __ vdup(Neon16, q1, r4);
    __ vand(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vand))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vorr.
    __ mov(r4, Operand(0xAA));
    __ vdup(Neon16, q0, r4);
    __ mov(r4, Operand(0x55));
    __ vdup(Neon16, q1, r4);
    __ vorr(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vorr))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vmin (float).
    __ vmov(s4, Float32(2.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vmov(s4, Float32(1.0f));
    __ vdup(Neon32, q1, d2, 0);
    __ vmin(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vminf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vmax (float).
    __ vmov(s4, Float32(2.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vmov(s4, Float32(1.0f));
    __ vdup(Neon32, q1, d2, 0);
    __ vmax(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmaxf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vadd (float).
    __ vmov(s4, Float32(1.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vdup(Neon32, q1, d2, 0);
    __ vadd(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vaddf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vpadd (float).
    __ vmov(s0, Float32(1.0f));
    __ vmov(s1, Float32(2.0f));
    __ vmov(s2, Float32(3.0f));
    __ vmov(s3, Float32(4.0f));
    __ vpadd(d2, d0, d1);
    __ vstr(d2, r0, offsetof(T, vpaddf));
    // vsub (float).
    __ vmov(s4, Float32(2.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vmov(s4, Float32(1.0f));
    __ vdup(Neon32, q1, d2, 0);
    __ vsub(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vsubf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vmul (float).
    __ vmov(s4, Float32(2.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vdup(Neon32, q1, d2, 0);
    __ vmul(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmulf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vrecpe.
    __ vmov(s4, Float32(2.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vrecpe(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrecpe))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vrecps.
    __ vmov(s4, Float32(2.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vmov(s4, Float32(1.5f));
    __ vdup(Neon32, q1, d2, 0);
    __ vrecps(q1, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrecps))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vrsqrte.
    __ vmov(s4, Float32(4.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vrsqrte(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrsqrte))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vrsqrts.
    __ vmov(s4, Float32(2.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vmov(s4, Float32(2.5f));
    __ vdup(Neon32, q1, d2, 0);
    __ vrsqrts(q1, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrsqrts))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vceq (float).
    __ vmov(s4, Float32(1.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vdup(Neon32, q1, d2, 0);
    __ vceq(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vceqf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vcge (float).
    __ vmov(s0, Float32(1.0f));
    __ vmov(s1, Float32(-1.0f));
    __ vmov(s2, Float32(-0.0f));
    __ vmov(s3, Float32(0.0f));
    __ vdup(Neon32, q1, d1, 1);
    __ vcge(q2, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcgef))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vcgt(q2, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcgtf))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vmin/vmax integer.
    __ mov(r4, Operand(0x03));
    __ vdup(Neon16, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vmin(NeonS8, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmin_s8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vmax(NeonS8, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmax_s8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ mov(r4, Operand(0xFF));
    __ vdup(Neon16, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vmin(NeonU16, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmin_u16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vmax(NeonU16, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmax_u16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ mov(r4, Operand(0xFF));
    __ vdup(Neon32, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vmin(NeonS32, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmin_s32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vmax(NeonS32, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmax_s32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vpadd integer.
    __ mov(r4, Operand(0x03));
    __ vdup(Neon16, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vpadd(Neon8, d0, d0, d2);
    __ vstr(d0, r0, offsetof(T, vpadd_i8));
    __ vpadd(Neon16, d0, d0, d2);
    __ vstr(d0, r0, offsetof(T, vpadd_i16));
    __ vpadd(Neon32, d0, d0, d2);
    __ vstr(d0, r0, offsetof(T, vpadd_i32));

    // vpadal signed.
    __ mov(r4, Operand(0x81));
    __ vdup(Neon8, q0, r4);

    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q2, r4);
    __ vpadal(NeonS8, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpadal_s8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q2, r4);
    __ vpadal(NeonS16, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpadal_s16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q2, r4);
    __ vpadal(NeonS32, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpadal_s32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vpadal unsigned.
    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q2, r4);
    __ vpadal(NeonU8, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpadal_u8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q2, r4);
    __ vpadal(NeonU16, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpadal_u16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q2, r4);
    __ vpadal(NeonU32, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpadal_u32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vpaddl signed.
    __ mov(r4, Operand(0x81));
    __ vdup(Neon8, q0, r4);

    __ vpaddl(NeonS8, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpaddl_s8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ vpaddl(NeonS16, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpaddl_s16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ vpaddl(NeonS32, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpaddl_s32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vpaddl unsigned.
    __ vpaddl(NeonU8, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpaddl_u8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ vpaddl(NeonU16, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpaddl_u16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ vpaddl(NeonU32, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpaddl_u32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vpmin/vpmax integer.
    __ mov(r4, Operand(0x03));
    __ vdup(Neon16, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vpmin(NeonS8, d4, d0, d2);
    __ vstr(d4, r0, offsetof(T, vpmin_s8));
    __ vpmax(NeonS8, d4, d0, d2);
    __ vstr(d4, r0, offsetof(T, vpmax_s8));
    __ mov(r4, Operand(0xFFFF));
    __ vdup(Neon32, q0, r4);
    __ vdup(Neon16, q1, r4);
    __ vpmin(NeonU16, d4, d0, d2);
    __ vstr(d4, r0, offsetof(T, vpmin_u16));
    __ vpmax(NeonU16, d4, d0, d2);
    __ vstr(d4, r0, offsetof(T, vpmax_u16));
    __ mov(r4, Operand(0xFF));
    __ veor(q0, q0, q0);
    __ vmov(s0, r4);
    __ vdup(Neon8, q1, r4);
    __ vpmin(NeonS32, d4, d0, d2);
    __ vstr(d4, r0, offsetof(T, vpmin_s32));
    __ vpmax(NeonS32, d4, d0, d2);
    __ vstr(d4, r0, offsetof(T, vpmax_s32));

    // vadd (integer).
    __ mov(r4, Operand(0x81));
    __ vdup(Neon8, q0, r4);
    __ mov(r4, Operand(0x82));
    __ vdup(Neon8, q1, r4);
    __ vadd(Neon8, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vadd8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x8001));
    __ vdup(Neon16, q0, r4);
    __ mov(r4, Operand(0x8002));
    __ vdup(Neon16, q1, r4);
    __ vadd(Neon16, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vadd16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x80000001));
    __ vdup(Neon32, q0, r4);
    __ mov(r4, Operand(0x80000002));
    __ vdup(Neon32, q1, r4);
    __ vadd(Neon32, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vadd32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vqadd.
    __ mov(r4, Operand(0x81));
    __ vdup(Neon8, q0, r4);
    __ mov(r4, Operand(0x82));
    __ vdup(Neon8, q1, r4);
    __ vqadd(NeonS8, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vqadd_s8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x8000));
    __ vdup(Neon16, q0, r4);
    __ vdup(Neon16, q1, r4);
    __ vqadd(NeonU16, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vqadd_u16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x80000001));
    __ vdup(Neon32, q0, r4);
    __ mov(r4, Operand(0x80000002));
    __ vdup(Neon32, q1, r4);
    __ vqadd(NeonS32, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vqadd_s32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vsub (integer).
    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q0, r4);
    __ mov(r4, Operand(0x03));
    __ vdup(Neon8, q1, r4);
    __ vsub(Neon8, q1, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vsub8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x0001));
    __ vdup(Neon16, q0, r4);
    __ mov(r4, Operand(0x0003));
    __ vdup(Neon16, q1, r4);
    __ vsub(Neon16, q1, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vsub16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x00000001));
    __ vdup(Neon32, q0, r4);
    __ mov(r4, Operand(0x00000003));
    __ vdup(Neon32, q1, r4);
    __ vsub(Neon32, q1, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vsub32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vqsub.
    __ mov(r4, Operand(0x7F));
    __ vdup(Neon8, q0, r4);
    __ mov(r4, Operand(0x3F));
    __ vdup(Neon8, q1, r4);
    __ vqsub(NeonU8, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vqsub_u8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x8000));
    __ vdup(Neon16, q0, r4);
    __ mov(r4, Operand(0x7FFF));
    __ vdup(Neon16, q1, r4);
    __ vqsub(NeonS16, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vqsub_s16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x80000001));
    __ vdup(Neon32, q0, r4);
    __ mov(r4, Operand(0x80000000));
    __ vdup(Neon32, q1, r4);
    __ vqsub(NeonU32, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vqsub_u32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vmul (integer).
    __ mov(r4, Operand(0x02));
    __ vdup(Neon8, q0, r4);
    __ vmul(Neon8, q1, q0, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmul8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x0002));
    __ vdup(Neon16, q0, r4);
    __ vmul(Neon16, q1, q0, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmul16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x00000002));
    __ vdup(Neon32, q0, r4);
    __ vmul(Neon32, q1, q0, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmul32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vshl.
    __ mov(r4, Operand(0x55));
    __ vdup(Neon8, q0, r4);
    __ vshl(NeonS8, q1, q0, 1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshl8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vshl(NeonU16, q1, q0, 9);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshl16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vshl(NeonS32, q1, q0, 17);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshl32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vshr.s, vshr.u.
    __ mov(r4, Operand(0x80));
    __ vdup(Neon8, q0, r4);
    __ vshr(NeonS8, q1, q0, 1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshr_s8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vshr(NeonU16, q1, q0, 9);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshr_u16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vshr(NeonS32, q1, q0, 17);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshr_s32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vshr.s, vshr.u with d registers.
    __ mov(r4, Operand(0x80));
    __ vdup(Neon8, q0, r4);
    __ vshr(NeonS8, d1, d0, 1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshr_s8_d))));
    __ vst1(Neon8, NeonListOperand(d1), NeonMemOperand(r4));
    __ vshr(NeonU16, d2, d0, 9);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshr_u16_d))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vshr(NeonS32, d2, d0, 17);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshr_s32_d))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vsli, vsri.
    __ mov(r4, Operand(0xFFFFFFFF));
    __ mov(r5, Operand(0x1));
    __ vmov(d0, r4, r5);
    __ vmov(d1, r5, r5);
    __ vsli(Neon64, d1, d0, 32);
    __ vstr(d1, r0, offsetof(T, vsli_64));
    __ vmov(d0, r5, r4);
    __ vmov(d1, r5, r5);
    __ vsri(Neon64, d1, d0, 32);
    __ vstr(d1, r0, offsetof(T, vsri_64));
    __ vmov(d0, r4, r5);
    __ vmov(d1, r5, r5);
    __ vsli(Neon32, d1, d0, 16);
    __ vstr(d1, r0, offsetof(T, vsli_32));
    __ vmov(d0, r5, r4);
    __ vmov(d1, r5, r5);
    __ vsri(Neon32, d1, d0, 16);
    __ vstr(d1, r0, offsetof(T, vsri_32));

    // vsra.
    __ vmov(d0, r4, r5);
    // Check same dst and src registers.
    __ vsra(NeonU64, d0, d0, 1);
    __ vstr(d0, r0, offsetof(T, vsra_64));
    __ vmov(d0, r4, r5);
    __ vmov(d1, r5, r4);
    __ vsra(NeonS32, d1, d0, 16);
    __ vstr(d1, r0, offsetof(T, vsra_32));
    __ vmov(d0, r4, r5);
    __ vmov(d1, r5, r4);
    __ vsra(NeonU16, d1, d0, 2);
    __ vstr(d1, r0, offsetof(T, vsra_16));

    // vceq.
    __ mov(r4, Operand(0x03));
    __ vdup(Neon8, q0, r4);
    __ vdup(Neon16, q1, r4);
    __ vceq(Neon8, q1, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vceq))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vcge/vcgt (integer).
    __ mov(r4, Operand(0x03));
    __ vdup(Neon16, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vcge(NeonS8, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcge_s8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vcgt(NeonS8, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcgt_s8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ mov(r4, Operand(0xFF));
    __ vdup(Neon16, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vcge(NeonU16, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcge_u16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vcgt(NeonU16, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcgt_u16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ mov(r4, Operand(0xFF));
    __ vdup(Neon32, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vcge(NeonS32, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcge_s32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vcgt(NeonS32, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcgt_s32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vclt #0 (signed integer).
    __ mov(r4, Operand(0x7F80807F));
    __ mov(r5, Operand(0xFF01FF01));
    __ vmov(d0, r4, r5);
    __ mov(r4, Operand(0xFF0000FF));
    __ mov(r5, Operand(0x00800080));
    __ vmov(d1, r4, r5);

    __ vclt(Neon8, q1, q0, 0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vclt0_s8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    __ vclt(Neon16, q1, q0, 0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vclt0_s16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    __ vclt(Neon32, q1, q0, 0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vclt0_s32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vtst.
    __ mov(r4, Operand(0x03));
    __ vdup(Neon8, q0, r4);
    __ mov(r4, Operand(0x02));
    __ vdup(Neon16, q1, r4);
    __ vtst(Neon8, q1, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vtst))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vbsl.
    __ mov(r4, Operand(0x00FF));
    __ vdup(Neon16, q0, r4);
    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q1, r4);
    __ mov(r4, Operand(0x02));
    __ vdup(Neon8, q2, r4);
    __ vbsl(q0, q1, q2);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vbsl))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));

    // vext.
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vext(q2, q0, q1, 3);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vext))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vzip (q-register).
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vzip(Neon8, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vzip8a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vzip8b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vzip(Neon16, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vzip16a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vzip16b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vzip(Neon32, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vzip32a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vzip32b))));
    __ vst1(Neon8,
"""


```