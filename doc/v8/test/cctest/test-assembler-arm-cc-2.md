Response:
The user wants a summary of the functionality of the provided C++ code snippet from a V8 source file.

Here's a breakdown of the thought process to address the request:

1. **Identify the Core Functionality:** The code snippet primarily uses ARM assembly instructions, particularly those related to the Advanced SIMD (NEON) instruction set. It seems to be testing various NEON instructions.

2. **Recognize the Test Context:** The code is within a `TEST` macro, strongly indicating this is part of V8's testing framework. The `CcTest::InitializeVM()` call confirms this. The use of `CHECK_EQ` and similar macros further reinforces this.

3. **Analyze the NEON Instructions:** Go through the assembly instructions and group them by the operation they perform. Keywords like `vzip`, `vuzp`, `vtrn`, `vrev`, `vtbl`, `vtbx`, `vmovl`, `vqmovn`, `vmov`, `vmvn`, `vdup`, `vcvt`, `vclt0`, `vabsf`, `vnegf`, `vabs`, `vneg`, `veor`, `vand`, `vorr`, `vaddf`, `vpaddf`, `vminf`, `vmaxf`, `vsubf`, `vmulf`, `vrecpe`, `vrecps`, `vrsqrte`, `vrsqrts`, `vceqf`, `vcgef`, `vcgtf`, `vmin`, `vmax`, `vpadd`, `vpadal`, `vpaddl`, `vpmin`, `vpmax`, `vadd`, `vqadd`, `vqsub`, `vsub`, `vmul`, `vshl`, `vshr`, `vsli`, `vsri`, `vsra`, `vceq`, `vcge`, `vcgt`, `vtst`, `vbsl`, `vext` are strong indicators of specific NEON operations.

4. **Relate to Data Manipulation:**  Note that these NEON instructions operate on vectors (multiple data elements simultaneously). The code loads data into NEON registers, performs operations, and stores the results back into memory. The `offsetof` calls suggest interaction with a struct `T` to hold input and output values.

5. **Infer Testing Strategy:** The code sets up input values in the `T` struct, calls the generated assembly code, and then uses `CHECK_EQ` to compare the output values in `T` with expected values. This is a common pattern for unit testing.

6. **Consider Javascript Relevance:** NEON instructions are used for optimizing performance-critical operations. In JavaScript, this often translates to operations on typed arrays or when the JavaScript engine performs optimizations behind the scenes (e.g., in certain array methods or WebAssembly).

7. **Example Javascript Scenario:**  Think of a common JavaScript operation that benefits from SIMD: vector addition. Demonstrate this with typed arrays.

8. **Code Logic Inference:** Focus on a smaller, self-contained section of the code. The `vzip` instruction is a good example. Explain how it interleaves elements from two registers. Create a simple input scenario and trace the expected output.

9. **Common Programming Errors:**  Think about how a programmer might misuse NEON instructions. Incorrect lane selection, data type mismatches, and alignment issues are typical pitfalls.

10. **Address the File Extension Check:** Explicitly state that `.cc` is not `.tq`, so it's not Torque.

11. **Structure the Response:** Organize the findings into the requested categories: functionality, Torque check, JavaScript relevance, code logic, common errors, and summary.

12. **Refine and Elaborate:** Provide clear and concise explanations for each point. Use specific instruction names and data sizes when possible. Ensure the JavaScript example is understandable.

13. **Handle Part 3/5:** Acknowledge that this is part 3 and provide a concise summary that reflects the focus on NEON instructions within this specific part of the test file.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** Maybe this tests *all* ARM assembler instructions. **Correction:** The heavy use of `v` prefixed instructions points specifically to NEON.
* **Initial thought:**  Focus heavily on the register names. **Correction:** While register names are present, the *operations* are more important for understanding the *functionality*. Focus on what the instructions *do*.
* **Initial thought:** Try to explain every single instruction in detail. **Correction:** This would be too verbose. Group similar instructions and explain the general purpose of those groups (e.g., data arrangement, arithmetic, logical operations).
* **Initial thought:**  Make the JavaScript example very complex. **Correction:** Keep the JavaScript example simple and focused on illustrating the *benefit* of SIMD-like operations, even if the underlying implementation is hidden.
这是目录为 `v8/test/cctest/test-assembler-arm.cc` 的一个 V8 源代码文件的部分内容。根据提供的信息，我们可以归纳出以下功能：

**功能归纳 (针对提供的代码片段):**

这段代码片段主要功能是 **测试 ARM 架构下 V8 汇编器对 NEON (Advanced SIMD) 指令的支持**。它通过生成汇编代码来执行各种 NEON 指令，并将结果与预期值进行比较，以验证汇编器的正确性。

具体来说，这段代码测试了以下 NEON 指令及其不同的变体（例如，针对 8 位、16 位、32 位数据）：

* **数据重排指令:**
    * `vzip`:  将两个寄存器的元素交错合并。
    * `vuzp`:  将一个寄存器的交错元素分离到两个寄存器。
    * `vtrn`:  将两个寄存器的元素进行转置。
    * `vrev64`, `vrev32`, `vrev16`: 反转寄存器中特定大小元素的字节顺序。
    * `vtbl`, `vtbx`:  查表操作。
    * `vext`: 提取寄存器的部分内容。

* **数据加载和存储指令:**
    * `vld1`: 加载数据到 NEON 寄存器。
    * `vstr`: 存储 NEON 寄存器中的数据。
    * `vldr`: 加载单个值到 NEON 寄存器。

* **数据移动指令:**
    * `vmov`: 在 NEON 寄存器之间移动数据。

**关于文件类型:**

`v8/test/cctest/test-assembler-arm.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 源代码文件以 `.tq` 结尾）。

**与 Javascript 的关系及示例:**

虽然这段代码本身是 C++ 汇编测试代码，但 NEON 指令的正确实现对于 V8 优化 Javascript 代码至关重要。V8 引擎在执行某些 Javascript 操作时，特别是涉及到数组、图像处理、音频处理等密集型计算时，会利用 SIMD (Single Instruction, Multiple Data) 技术来提高性能。NEON 是 ARM 架构下的 SIMD 扩展。

例如，当 Javascript 代码执行对数组元素进行批量操作时，V8 可能会将这些操作编译成 NEON 指令。

**Javascript 示例:**

```javascript
// 假设我们有一个 Typed Array (Uint8Array)
const arr1 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
const arr2 = new Uint8Array([9, 10, 11, 12, 13, 14, 15, 16]);
const result = new Uint8Array(8);

// 模拟 NEON 的 vzip 指令效果 (交错合并)
for (let i = 0; i < 4; i++) {
  result[i * 2] = arr1[i];
  result[i * 2 + 1] = arr2[i];
}

console.log(result); // 输出: Uint8Array [1, 9, 2, 10, 3, 11, 4, 12]
```

在这个例子中，Javascript 代码执行了一个类似于 NEON `vzip` 指令的操作，将两个数组的元素交错合并。V8 引擎在底层可能会使用 NEON 指令来加速类似的操作。

**代码逻辑推理及假设输入输出:**

让我们以 `vzip` 指令为例进行代码逻辑推理：

**假设输入:**

* NEON 寄存器 `d0` 的值为 `[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]` (假设是 8 位元素)
* NEON 寄存器 `d1` 的值为 `[0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]`

**执行指令:**

```assembly
__ vzip(Neon8, d0, d1);
```

**预期输出:**

* `d0` 的值变为 `[0x01, 0x09, 0x02, 0x0A, 0x03, 0x0B, 0x04, 0x0C]` (取 `d0` 和 `d1` 的前半部分交错)
* `d1` 的值变为 `[0x05, 0x0D, 0x06, 0x0E, 0x07, 0x0F, 0x08, 0x10]` (取 `d0` 和 `d1` 的后半部分交错)

代码中的 `vstr` 指令会将这些结果存储到内存中 `T` 结构体的相应字段，例如 `t.vzipd8a` 和 `t.vzipd8b`。测试代码会比较这些存储的值是否与预期值一致。

**用户常见的编程错误示例:**

如果用户在编写使用 NEON 指令的代码时出现错误，可能会导致以下问题：

1. **数据类型不匹配:** 例如，尝试将 16 位数据加载到声明为 8 位元素的 NEON 寄存器中。这可能导致数据截断或读取错误。

   ```c++
   // 错误示例：假设 q0 是 uint8x16_t 类型，而 lane_test 是 uint16_t 数组
   // __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4)); // 可能导致类型不匹配
   ```

2. **访问越界:**  当使用查表指令 (`vtbl`, `vtbx`) 时，如果索引超出表的范围，则可能导致未定义的行为或程序崩溃。

   ```c++
   // 错误示例：如果 d2 的某些字节值大于等于表的大小
   // __ vtbl(d0, NeonListOperand(d2, 1), d2);
   ```

3. **对齐问题:**  某些 NEON 指令可能要求操作数在内存中进行特定的对齐。如果数据未对齐，可能会导致性能下降或在某些平台上引发错误。

4. **误解指令的功能:**  错误地理解 NEON 指令的功能，例如 `vzip` 和 `vuzp` 的作用，可能导致逻辑错误。

**第 3 部分功能归纳:**

总而言之，这部分代码（第 3 部分）专注于测试 V8 引擎在 ARM 架构下对 **NEON 数据重排指令** 的汇编代码生成和执行的正确性。它涵盖了 `vzip`、`vuzp`、`vtrn`、`vrev` 以及查表指令 `vtbl` 和 `vtbx`。 这些指令对于优化涉及数据重新排列和查找的算法至关重要。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
 NeonListOperand(q1), NeonMemOperand(r4));

    // vzip (d-register).
    __ vldr(d2, r0, offsetof(T, lane_test));
    __ vmov(d0, d2);
    __ vmov(d1, d2);
    __ vzip(Neon8, d0, d1);
    __ vstr(d0, r0, offsetof(T, vzipd8a));
    __ vstr(d1, r0, offsetof(T, vzipd8b));
    __ vmov(d0, d2);
    __ vmov(d1, d2);
    __ vzip(Neon16, d0, d1);
    __ vstr(d0, r0, offsetof(T, vzipd16a));
    __ vstr(d1, r0, offsetof(T, vzipd16b));

    // vuzp (q-register).
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vuzp(Neon8, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vuzp8a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vuzp8b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vuzp(Neon16, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vuzp16a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vuzp16b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vuzp(Neon32, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vuzp32a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vuzp32b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vuzp (d-register).
    __ vldr(d2, r0, offsetof(T, lane_test));
    __ vmov(d0, d2);
    __ vmov(d1, d2);
    __ vuzp(Neon8, d0, d1);
    __ vstr(d0, r0, offsetof(T, vuzpd8a));
    __ vstr(d1, r0, offsetof(T, vuzpd8b));
    __ vmov(d0, d2);
    __ vmov(d1, d2);
    __ vuzp(Neon16, d0, d1);
    __ vstr(d0, r0, offsetof(T, vuzpd16a));
    __ vstr(d1, r0, offsetof(T, vuzpd16b));

    // vtrn (q-register).
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vtrn(Neon8, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vtrn8a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vtrn8b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vtrn(Neon16, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vtrn16a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vtrn16b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vtrn(Neon32, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vtrn32a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vtrn32b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vtrn (d-register).
    __ vldr(d2, r0, offsetof(T, lane_test));
    __ vmov(d0, d2);
    __ vmov(d1, d2);
    __ vtrn(Neon8, d0, d1);
    __ vstr(d0, r0, offsetof(T, vtrnd8a));
    __ vstr(d1, r0, offsetof(T, vtrnd8b));
    __ vmov(d0, d2);
    __ vmov(d1, d2);
    __ vtrn(Neon16, d0, d1);
    __ vstr(d0, r0, offsetof(T, vtrnd16a));
    __ vstr(d1, r0, offsetof(T, vtrnd16b));
    __ vmov(d0, d2);
    __ vmov(d1, d2);
    __ vtrn(Neon32, d0, d1);
    __ vstr(d0, r0, offsetof(T, vtrnd32a));
    __ vstr(d1, r0, offsetof(T, vtrnd32b));

    // vrev64/32/16
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vrev64(Neon32, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrev64_32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vrev64(Neon16, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrev64_16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vrev64(Neon8, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrev64_8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vrev32(Neon16, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrev32_16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vrev32(Neon8, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrev32_8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vrev16(Neon8, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrev16_8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vtb[l/x].
    __ mov(r4, Operand(0x06040200));
    __ mov(r5, Operand(0xFF050301));
    __ vmov(d2, r4, r5);  // d2 = ff05030106040200
    __ vtbl(d0, NeonListOperand(d2, 1), d2);
    __ vstr(d0, r0, offsetof(T, vtbl));
    __ vtbx(d2, NeonListOperand(d2, 1), d2);
    __ vstr(d2, r0, offsetof(T, vtbx));

    // Restore and return.
    __ ldm(ia_w, sp, {r4, r5, pc});

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
    t.src0 = 0x01020304;
    t.src1 = 0x11121314;
    t.src2 = 0x21222324;
    t.src3 = 0x31323334;
    t.src4 = 0x41424344;
    t.src5 = 0x51525354;
    t.src6 = 0x61626364;
    t.src7 = 0x71727374;
    t.dst0 = 0;
    t.dst1 = 0;
    t.dst2 = 0;
    t.dst3 = 0;
    t.dst4 = 0;
    t.dst5 = 0;
    t.dst6 = 0;
    t.dst7 = 0;
    t.srcA0 = 0x41424344;
    t.srcA1 = 0x81828384;
    t.dstA0 = 0;
    t.dstA1 = 0;
    t.dstA2 = 0;
    t.dstA3 = 0;
    t.lane_test[0] = 0x03020100;
    t.lane_test[1] = 0x07060504;
    t.lane_test[2] = 0x0B0A0908;
    t.lane_test[3] = 0x0F0E0D0C;
    f.Call(&t, 0, 0, 0, 0);

    CHECK_EQ(0x01020304u, t.dst0);
    CHECK_EQ(0x11121314u, t.dst1);
    CHECK_EQ(0x21222324u, t.dst2);
    CHECK_EQ(0x31323334u, t.dst3);
    CHECK_EQ(0x41424344u, t.dst4);
    CHECK_EQ(0x51525354u, t.dst5);
    CHECK_EQ(0x61626364u, t.dst6);
    CHECK_EQ(0x71727374u, t.dst7);
    CHECK_EQ(0x00430044u, t.dstA0);
    CHECK_EQ(0x00410042u, t.dstA1);
    CHECK_EQ(0x00830084u, t.dstA2);
    CHECK_EQ(0x00810082u, t.dstA3);

    CHECK_EQ_32X4(vmovl_s8, 0x00430044u, 0x00410042u, 0xFF83FF84u, 0xFF81FF82u);
    CHECK_EQ_32X4(vmovl_u16, 0xFF84u, 0xFF83u, 0xFF82u, 0xFF81u);
    CHECK_EQ_32X4(vmovl_s32, 0xFF84u, 0x0u, 0xFF83u, 0x0u);
    CHECK_EQ_32X2(vqmovn_u16, 0xFF83FF84u, 0xFF81FF82u);
    CHECK_EQ_32X2(vqmovn_s8, 0x81828384u, 0x81828384u);
    CHECK_EQ_32X2(vqmovn_s32, 0xFF84u, 0xFF83u);

    CHECK_EQ(0xFFFFFFF8FFF8F800u, t.vmov_to_scalar1);
    CHECK_EQ(0xFFF80000F8000000u, t.vmov_to_scalar2);
    CHECK_EQ(0xFFFFFFFFu, t.vmov_from_scalar_s8);
    CHECK_EQ(0xFFu, t.vmov_from_scalar_u8);
    CHECK_EQ(0xFFFFFFFFu, t.vmov_from_scalar_s16);
    CHECK_EQ(0xFFFFu, t.vmov_from_scalar_u16);
    CHECK_EQ(0xFFFFFFFFu, t.vmov_from_scalar_32);

    CHECK_EQ_32X4(vmov, 0x03020100u, 0x07060504u, 0x0B0A0908u, 0x0F0E0D0Cu);
    CHECK_EQ_32X4(vmvn, 0xFCFDFEFFu, 0xF8F9FAFBu, 0xF4F5F6F7u, 0xF0F1F2F3u);

    CHECK_EQ_SPLAT(vdup8, 0x0A0A0A0Au);
    CHECK_EQ_SPLAT(vdup16, 0x000A000Au);
    CHECK_EQ_SPLAT(vdup32, 0x0000000Au);
    CHECK_EQ_SPLAT(vdupf, -1.0);  // bit pattern is 0xBF800000.
    CHECK_EQ_32X2(vdupf_16, 0xBF80BF80u, 0xBF80BF80u);
    CHECK_EQ_SPLAT(vdupf_8, 0xBFBFBFBFu);

    // src: [-1, -1, 1, 1]
    CHECK_EQ_32X4(vcvt_s32_f32, -1, -1, 1, 1);
    CHECK_EQ_32X4(vcvt_u32_f32, 0u, 0u, 1u, 1u);
    // src: [kMinInt, kMaxInt, kMaxUInt32, kMinInt + 1]
    CHECK_EQ_32X4(vcvt_f32_s32, INT32_TO_FLOAT(kMinInt),
                  INT32_TO_FLOAT(kMaxInt), INT32_TO_FLOAT(kMaxUInt32),
                  INT32_TO_FLOAT(kMinInt + 1));
    CHECK_EQ_32X4(vcvt_f32_u32, UINT32_TO_FLOAT(kMinInt),
                  UINT32_TO_FLOAT(kMaxInt), UINT32_TO_FLOAT(kMaxUInt32),
                  UINT32_TO_FLOAT(kMinInt + 1));

    CHECK_EQ_32X4(vclt0_s8, 0x00FFFF00u, 0xFF00FF00u, 0xFF0000FFu, 0x00FF00FFu);
    CHECK_EQ_32X4(vclt0_s16, 0x0000FFFF, 0xFFFFFFFFu, 0xFFFF0000u, 0x00000000u);
    CHECK_EQ_32X4(vclt0_s32, 0x00000000u, 0xFFFFFFFFu, 0xFFFFFFFFu,
                  0x00000000u);

    CHECK_EQ_32X4(vabsf, 1.0, 0.0, 0.0, 1.0);
    CHECK_EQ_32X4(vnegf, 1.0, 0.0, -0.0, -1.0);
    // src: [0x7F7F7F7F, 0x01010101, 0xFFFFFFFF, 0x80808080]
    CHECK_EQ_32X4(vabs_s8, 0x7F7F7F7Fu, 0x01010101u, 0x01010101u, 0x80808080u);
    CHECK_EQ_32X4(vabs_s16, 0x7F7F7F7Fu, 0x01010101u, 0x00010001u, 0x7F807F80u);
    CHECK_EQ_32X4(vabs_s32, 0x7F7F7F7Fu, 0x01010101u, 0x00000001u, 0x7F7F7F80u);
    CHECK_EQ_32X4(vneg_s8, 0x81818181u, 0xFFFFFFFFu, 0x01010101u, 0x80808080u);
    CHECK_EQ_32X4(vneg_s16, 0x80818081u, 0xFEFFFEFFu, 0x00010001u, 0x7F807F80u);
    CHECK_EQ_32X4(vneg_s32, 0x80808081u, 0xFEFEFEFFu, 0x00000001u, 0x7F7F7F80u);

    CHECK_EQ_SPLAT(veor, 0x00FF00FFu);
    CHECK_EQ_SPLAT(vand, 0x00FE00FEu);
    CHECK_EQ_SPLAT(vorr, 0x00FF00FFu);
    CHECK_EQ_SPLAT(vaddf, 2.0);
    CHECK_EQ_32X2(vpaddf, 3.0, 7.0);
    CHECK_EQ_SPLAT(vminf, 1.0);
    CHECK_EQ_SPLAT(vmaxf, 2.0);
    CHECK_EQ_SPLAT(vsubf, -1.0);
    CHECK_EQ_SPLAT(vmulf, 4.0);
    CHECK_ESTIMATE_SPLAT(vrecpe, 0.5f, 0.1f);  // 1 / 2
    CHECK_EQ_SPLAT(vrecps, -1.0f);   // 2 - (2 * 1.5)
    CHECK_ESTIMATE_SPLAT(vrsqrte, 0.5f, 0.1f);  // 1 / sqrt(4)
    CHECK_EQ_SPLAT(vrsqrts, -1.0f);  // (3 - (2 * 2.5)) / 2
    CHECK_EQ_SPLAT(vceqf, 0xFFFFFFFFu);
    // [0] >= [-1, 1, -0, 0]
    CHECK_EQ_32X4(vcgef, 0u, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu);
    CHECK_EQ_32X4(vcgtf, 0u, 0xFFFFFFFFu, 0u, 0u);
    // [0, 3, 0, 3, ...] and [3, 3, 3, 3, ...]
    CHECK_EQ_SPLAT(vmin_s8, 0x00030003u);
    CHECK_EQ_SPLAT(vmax_s8, 0x03030303u);
    // [0x00FF, 0x00FF, ...] and [0xFFFF, 0xFFFF, ...]
    CHECK_EQ_SPLAT(vmin_u16, 0x00FF00FFu);
    CHECK_EQ_SPLAT(vmax_u16, 0xFFFFFFFFu);
    // [0x000000FF, 0x000000FF, ...] and [0xFFFFFFFF, 0xFFFFFFFF, ...]
    CHECK_EQ_SPLAT(vmin_s32, 0xFFFFFFFFu);
    CHECK_EQ_SPLAT(vmax_s32, 0xFFu);
    // [0, 3, 0, 3, ...] and [3, 3, 3, 3, ...]
    CHECK_EQ_32X2(vpadd_i8, 0x03030303u, 0x06060606u);
    CHECK_EQ_32X2(vpadd_i16, 0x0C0C0606u, 0x06060606u);
    CHECK_EQ_32X2(vpadd_i32, 0x12120C0Cu, 0x06060606u);

    CHECK_EQ_32X4(vpadal_s8, 0x30003, 0x30003, 0x30003, 0x30003);
    CHECK_EQ_32X4(vpadal_s16, 0x1000403, 0x1000403, 0x1000403, 0x1000403);
    CHECK_EQ_32X4(vpadal_s32, 0x4040403, 0x1010100, 0x4040403, 0x1010100);

    CHECK_EQ_32X4(vpadal_u8, 0x2030203, 0x2030203, 0x2030203, 0x2030203);
    CHECK_EQ_32X4(vpadal_u16, 0x1020403, 0x1020403, 0x1020403, 0x1020403);
    CHECK_EQ_32X4(vpadal_u32, 0x4040403, 0x1010102, 0x4040403, 0x1010102);

    CHECK_EQ_32X4(vpaddl_s8, 0xFF02FF02, 0xFF02FF02, 0xFF02FF02, 0xFF02FF02);
    CHECK_EQ_32X4(vpaddl_s16, 0xFFFF0302, 0xFFFF0302, 0xFFFF0302, 0xFFFF0302);
    CHECK_EQ_32X4(vpaddl_s32, 0x03030302, 0xFFFFFFFF, 0x03030302, 0xFFFFFFFF);

    CHECK_EQ_32X4(vpaddl_u8, 0x01020102, 0x01020102, 0x01020102, 0x01020102);
    CHECK_EQ_32X4(vpaddl_u16, 0x00010302, 0x00010302, 0x00010302, 0x00010302);
    CHECK_EQ_32X4(vpaddl_u32, 0x03030302, 0x00000001, 0x03030302, 0x00000001);

    CHECK_EQ_32X2(vpmin_s8, 0x00000000u, 0x03030303u);
    CHECK_EQ_32X2(vpmax_s8, 0x03030303u, 0x03030303u);
    // [0, ffff, 0, ffff] and [ffff, ffff]
    CHECK_EQ_32X2(vpmin_u16, 0x00000000u, 0xFFFFFFFFu);
    CHECK_EQ_32X2(vpmax_u16, 0xFFFFFFFFu, 0xFFFFFFFFu);
    // [0x000000FF, 0x00000000u] and [0xFFFFFFFF, 0xFFFFFFFF, ...]
    CHECK_EQ_32X2(vpmin_s32, 0x00u, 0xFFFFFFFFu);
    CHECK_EQ_32X2(vpmax_s32, 0xFFu, 0xFFFFFFFFu);
    CHECK_EQ_SPLAT(vadd8, 0x03030303u);
    CHECK_EQ_SPLAT(vadd16, 0x00030003u);
    CHECK_EQ_SPLAT(vadd32, 0x00000003u);
    CHECK_EQ_SPLAT(vqadd_s8, 0x80808080u);
    CHECK_EQ_SPLAT(vqadd_u16, 0xFFFFFFFFu);
    CHECK_EQ_SPLAT(vqadd_s32, 0x80000000u);
    CHECK_EQ_SPLAT(vqsub_u8, 0x00000000u);
    CHECK_EQ_SPLAT(vqsub_s16, 0x7FFF7FFFu);
    CHECK_EQ_SPLAT(vqsub_u32, 0x00000000u);
    CHECK_EQ_SPLAT(vsub8, 0xFEFEFEFEu);
    CHECK_EQ_SPLAT(vsub16, 0xFFFEFFFEu);
    CHECK_EQ_SPLAT(vsub32, 0xFFFFFFFEu);
    CHECK_EQ_SPLAT(vmul8, 0x04040404u);
    CHECK_EQ_SPLAT(vmul16, 0x00040004u);
    CHECK_EQ_SPLAT(vmul32, 0x00000004u);
    CHECK_EQ_SPLAT(vshl8, 0xAAAAAAAAu);
    CHECK_EQ_SPLAT(vshl16, 0xAA00AA00u);
    CHECK_EQ_SPLAT(vshl32, 0xAAAA0000u);
    CHECK_EQ_SPLAT(vshr_s8, 0xC0C0C0C0u);
    CHECK_EQ_SPLAT(vshr_u16, 0x00400040u);
    CHECK_EQ_SPLAT(vshr_s32, 0xFFFFC040u);
    CHECK_EQ_32X2(vshr_s8_d, 0xC0C0C0C0u, 0xC0C0C0C0u);
    CHECK_EQ_32X2(vshr_u16_d, 0x00400040u, 0x00400040u);
    CHECK_EQ_32X2(vshr_s32_d, 0xFFFFC040u, 0xFFFFC040u);
    CHECK_EQ_32X2(vsli_64, 0x01u, 0xFFFFFFFFu);
    CHECK_EQ_32X2(vsri_64, 0xFFFFFFFFu, 0x01u);
    CHECK_EQ_32X2(vsli_32, 0xFFFF0001u, 0x00010001u);
    CHECK_EQ_32X2(vsri_32, 0x00000000u, 0x0000FFFFu);
    CHECK_EQ_32X2(vsra_64, 0xFFFFFFFEu, 0x2);
    CHECK_EQ_32X2(vsra_32, 0x0, 0xFFFFFFFFu);
    CHECK_EQ_32X2(vsra_16, 0x3FFF4000, 0xFFFFFFFFu);
    CHECK_EQ_SPLAT(vceq, 0x00FF00FFu);
    // [0, 3, 0, 3, ...] >= [3, 3, 3, 3, ...]
    CHECK_EQ_SPLAT(vcge_s8, 0x00FF00FFu);
    CHECK_EQ_SPLAT(vcgt_s8, 0u);
    // [0x00FF, 0x00FF, ...] >= [0xFFFF, 0xFFFF, ...]
    CHECK_EQ_SPLAT(vcge_u16, 0u);
    CHECK_EQ_SPLAT(vcgt_u16, 0u);
    // [0x000000FF, 0x000000FF, ...] >= [0xFFFFFFFF, 0xFFFFFFFF, ...]
    CHECK_EQ_SPLAT(vcge_s32, 0xFFFFFFFFu);
    CHECK_EQ_SPLAT(vcgt_s32, 0xFFFFFFFFu);
    CHECK_EQ_SPLAT(vtst, 0x00FF00FFu);
    CHECK_EQ_SPLAT(vbsl, 0x02010201u);

    CHECK_EQ_32X4(vext, 0x06050403u, 0x0A090807u, 0x0E0D0C0Bu, 0x0201000Fu);

    CHECK_EQ_32X4(vzip8a, 0x01010000u, 0x03030202u, 0x05050404u, 0x07070606u);
    CHECK_EQ_32X4(vzip8b, 0x09090808u, 0x0B0B0A0Au, 0x0D0D0C0Cu, 0x0F0F0E0Eu);
    CHECK_EQ_32X4(vzip16a, 0x01000100u, 0x03020302u, 0x05040504u, 0x07060706u);
    CHECK_EQ_32X4(vzip16b, 0x09080908u, 0x0B0A0B0Au, 0x0D0C0D0Cu, 0x0F0E0F0Eu);
    CHECK_EQ_32X4(vzip32a, 0x03020100u, 0x03020100u, 0x07060504u, 0x07060504u);
    CHECK_EQ_32X4(vzip32b, 0x0B0A0908u, 0x0B0A0908u, 0x0F0E0D0Cu, 0x0F0E0D0Cu);

    CHECK_EQ_32X2(vzipd8a, 0x01010000u, 0x03030202u);
    CHECK_EQ_32X2(vzipd8b, 0x05050404u, 0x07070606u);
    CHECK_EQ_32X2(vzipd16a, 0x01000100u, 0x03020302u);
    CHECK_EQ_32X2(vzipd16b, 0x05040504u, 0x07060706u);

    CHECK_EQ_32X4(vuzp8a, 0x06040200u, 0x0E0C0A08u, 0x06040200u, 0x0E0C0A08u);
    CHECK_EQ_32X4(vuzp8b, 0x07050301u, 0x0F0D0B09u, 0x07050301u, 0x0F0D0B09u);
    CHECK_EQ_32X4(vuzp16a, 0x05040100u, 0x0D0C0908u, 0x05040100u, 0x0D0C0908u);
    CHECK_EQ_32X4(vuzp16b, 0x07060302u, 0x0F0E0B0Au, 0x07060302u, 0x0F0E0B0Au);
    CHECK_EQ_32X4(vuzp32a, 0x03020100u, 0x0B0A0908u, 0x03020100u, 0x0B0A0908u);
    CHECK_EQ_32X4(vuzp32b, 0x07060504u, 0x0F0E0D0Cu, 0x07060504u, 0x0F0E0D0Cu);

    CHECK_EQ_32X2(vuzpd8a, 0x06040200u, 0x06040200u);
    CHECK_EQ_32X2(vuzpd8b, 0x07050301u, 0x07050301u);
    CHECK_EQ_32X2(vuzpd16a, 0x05040100u, 0x05040100u);
    CHECK_EQ_32X2(vuzpd16b, 0x07060302u, 0x07060302u);

    CHECK_EQ_32X4(vtrn8a, 0x02020000u, 0x06060404u, 0x0A0A0808u, 0x0E0E0C0Cu);
    CHECK_EQ_32X4(vtrn8b, 0x03030101u, 0x07070505u, 0x0B0B0909u, 0x0F0F0D0Du);
    CHECK_EQ_32X4(vtrn16a, 0x01000100u, 0x05040504u, 0x09080908u, 0x0D0C0D0Cu);
    CHECK_EQ_32X4(vtrn16b, 0x03020302u, 0x07060706u, 0x0B0A0B0Au, 0x0F0E0F0Eu);
    CHECK_EQ_32X4(vtrn32a, 0x03020100u, 0x03020100u, 0x0B0A0908u, 0x0B0A0908u);
    CHECK_EQ_32X4(vtrn32b, 0x07060504u, 0x07060504u, 0x0F0E0D0Cu, 0x0F0E0D0Cu);

    CHECK_EQ_32X2(vtrnd8a, 0x02020000u, 0x06060404u);
    CHECK_EQ_32X2(vtrnd8b, 0x03030101u, 0x07070505u);
    CHECK_EQ_32X2(vtrnd16a, 0x01000100u, 0x05040504u);
    CHECK_EQ_32X2(vtrnd16b, 0x03020302u, 0x07060706u);
    CHECK_EQ_32X2(vtrnd32a, 0x03020100u, 0x03020100u);
    CHECK_EQ_32X2(vtrnd32b, 0x07060504u, 0x07060504u);

    // src: 0 1 2 3  4 5 6 7  8 9 a b  c d e f (little endian)
    CHECK_EQ_32X4(vrev64_32, 0x07060504u, 0x03020100u, 0x0F0E0D0Cu,
                  0x0B0A0908u);
    CHECK_EQ_32X4(vrev64_16, 0x05040706u, 0x01000302u, 0x0D0C0F0Eu,
                  0x09080B0Au);
    CHECK_EQ_32X4(vrev64_8, 0x04050607u, 0x00010203u, 0x0C0D0E0Fu, 0x08090A0Bu);
    CHECK_EQ_32X4(vrev32_16, 0x01000302u, 0x05040706u, 0x09080B0Au,
                  0x0D0C0F0Eu);
    CHECK_EQ_32X4(vrev32_8, 0x00010203u, 0x04050607u, 0x08090A0Bu, 0x0C0D0E0Fu);
    CHECK_EQ_32X4(vrev16_8, 0x02030001u, 0x06070405u, 0x0A0B0809u, 0x0E0F0C0Du);

    CHECK_EQ(0x05010400u, t.vtbl[0]);
    CHECK_EQ(0x00030602u, t.vtbl[1]);
    CHECK_EQ(0x05010400u, t.vtbx[0]);
    CHECK_EQ(0xFF030602u, t.vtbx[1]);
  }
}

TEST(16) {
  // Test the pkh, uxtb, uxtab and uxtb16 instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint32_t src0;
    uint32_t src1;
    uint32_t src2;
    uint32_t dst0;
    uint32_t dst1;
    uint32_t dst2;
    uint32_t dst3;
    uint32_t dst4;
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles and floats.
  Assembler assm(AssemblerOptions{});

  __ stm(db_w, sp, {r4, lr});

  __ mov(r4, Operand(r0));
  __ ldr(r0, MemOperand(r4, offsetof(T, src0)));
  __ ldr(r1, MemOperand(r4, offsetof(T, src1)));

  __ pkhbt(r2, r0, Operand(r1, LSL, 8));
  __ str(r2, MemOperand(r4, offsetof(T, dst0)));

  __ pkhtb(r2, r0, Operand(r1, ASR, 8));
  __ str(r2, MemOperand(r4, offsetof(T, dst1)));

  __ uxtb16(r2, r0, 8);
  __ str(r2, MemOperand(r4, offsetof(T, dst2)));

  __ uxtb(r2, r0, 8);
  __ str(r2, MemOperand(r4, offsetof(T, dst3)));

  __ ldr(r0, MemOperand(r4, offsetof(T, src2)));
  __ uxtab(r2, r0, r1, 8);
  __ str(r2, MemOperand(r4, offsetof(T, dst4)));

  __ ldm(ia_w, sp, {r4, pc});

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  t.src0 = 0x01020304;
  t.src1 = 0x11121314;
  t.src2 = 0x11121300;
  t.dst0 = 0;
  t.dst1 = 0;
  t.dst2 = 0;
  t.dst3 = 0;
  t.dst4 = 0;
  f.Call(&t, 0, 0, 0, 0);
  CHECK_EQ(0x12130304u, t.dst0);
  CHECK_EQ(0x01021213u, t.dst1);
  CHECK_EQ(0x00010003u, t.dst2);
  CHECK_EQ(0x00000003u, t.dst3);
  CHECK_EQ(0x11121313u, t.dst4);
}


TEST(17) {
  // Test generating labels at high addresses.
  // Should not assert.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  // Generate a code segment that will be longer than 2^24 bytes.
  Assembler assm(AssemblerOptions{});
  for (size_t i = 0; i < 1 << 23 ; ++i) {  // 2^23
    __ nop();
  }

  Label target;
  __ b(eq, &target);
  __ bind(&target);
  __ nop();
}

#define TEST_SDIV(expected_, dividend_, divisor_) \
  t.dividend = dividend_;                         \
  t.divisor = divisor_;                           \
  t.result = 0;                                   \
  f.Call(&t, 0, 0, 0, 0);                         \
  CHECK_EQ(expected_, t.result);

TEST(sdiv) {
  // Test the sdiv.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Assembler assm(AssemblerOptions{});

  struct T {
    int32_t dividend;
    int32_t divisor;
    int32_t result;
  } t;

  if (CpuFeatures::IsSupported(SUDIV)) {
    CpuFeatureScope scope(&assm, SUDIV);

    __ mov(r3, Operand(r0));

    __ ldr(r0, MemOperand(r3, offsetof(T, dividend)));
    __ ldr(r1, MemOperand(r3, offsetof(T, divisor)));

    __ sdiv(r2, r0, r1);
    __ str(r2, MemOperand(r3, offsetof(T, result)));

  __ bx(lr);

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
    TEST_SDIV(0, kMinInt, 0);
    TEST_SDIV(0, 1024, 0);
    TEST_SDIV(1073741824, kMinInt, -2);
    TEST_SDIV(kMinInt, kMinInt, -1);
    TEST_SDIV(5, 10, 2);
    TEST_SDIV(3, 10, 3);
    TEST_SDIV(-5, 10, -2);
    TEST_SDIV(-3, 10, -3);
    TEST_SDIV(-5, -10, 2);
    TEST_SDIV(-3, -10, 3);
    TEST_SDIV(5, -10, -2);
    TEST_SDIV(3, -10, -3);
  }
}


#undef TEST_SDIV

#define TEST_UDIV(expected_, dividend_, divisor_) \
  t.dividend = dividend_;                         \
  t.divisor = divisor_;                           \
  t.result = 0;                                   \
  f.Call(&t, 0, 0, 0, 0);                         \
  CHECK_EQ(expected_, t.result);

TEST(udiv) {
  // Test the udiv.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Assembler assm(AssemblerOptions{});

  struct T {
    uint32_t dividend;
    uint32_t divisor;
    uint32_t result;
  } t;

  if (CpuFeatures::IsSupported(SUDIV)) {
    CpuFeatureScope scope(&assm, SUDIV);

    __ mov(r3, Operand(r0));

    __ ldr(r0, MemOperand(r3, offsetof(T, dividend)));
    __ ldr(r1, MemOperand(r3, offsetof(T, divisor)));

    __ sdiv(r2, r0, r1);
    __ str(r2, MemOperand(r3, offsetof(T, result)));

    __ bx(lr);

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
    TEST_UDIV(0u, 0, 0);
    TEST_UDIV(0u, 1024, 0);
    TEST_UDIV(5u, 10, 2);
    TEST_UDIV(3u, 10, 3);
  }
}


#undef TEST_UDIV


TEST(smmla) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ smmla(r1, r1, r2, r3);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt(), y = rng->NextInt(), z = rng->NextInt();
    f.Call(&r, x, y, z, 0);
    CHECK_EQ(base::bits::SignedMulHighAndAdd32(x, y, z), r);
  }
}


TEST(smmul) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ smmul(r1, r1, r2);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt(), y = rng->NextInt();
    f.Call(&r, x, y, 0, 0);
    CHECK_EQ(base::bits::SignedMulHigh32(x, y), r);
  }
}


TEST(sxtb) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ sxtb(r1, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt();
    f.Call(&r, x, 0, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<int8_t>(x)), r);
  }
}


TEST(sxtab) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ sxtab(r1, r2, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt(), y = rng->NextInt();
    f.Call(&r, x, y, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<int8_t>(x)) + y, r);
  }
}


TEST(sxth) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ sxth(r1, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt();
    f.Call(&r, x, 0, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<int16_t>(x)), r);
  }
}


TEST(sxtah) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ sxtah(r1, r2, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt(), y = rng->NextInt();
    f.Call(&r, x, y, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<int16_t>(x)) + y, r);
  }
}


TEST(uxtb) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ uxtb(r1, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt();
    f.Call(&r, x, 0, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<uint8_t>(x)), r);
  }
}


TEST(uxtab) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ uxtab(r1, r2, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt(), y = rng->NextInt();
    f.Call(&r, x, y, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<uint8_t>(x)) + y, r);
  }
}


TEST(uxth) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ uxth(r1, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt();
    f.Call(&r, x, 0, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<uint16_t>(x)), r);
  }
}


TEST(uxtah) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  RandomNumberGenerator* const rng = isolate->random_number_generator();
  Assembler assm(AssemblerOptions{});
  __ uxtah(r1, r2, r1);
  __ str(r1, MemOperand(r0));
  __ bx(lr);
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  for (size_t i = 0; i < 128; ++i) {
    int32_t r, x = rng->NextInt(), y = rng->NextInt();
    f.Call(&r, x, y, 0, 0);
    CHECK_EQ(static_cast<int32_t>(static_cast<uint16_t>(x)) + y, r);
  }
}

#define TEST_RBIT(expected_, input_) \
  t.input = input_;                  \
  t.result = 0;                      \
  f.Call(&t, 0, 0, 0, 0);            \
  CHECK_EQ(static_cast<uint32_t>(expected_), t.result);

TEST(rbit) {
  CcTest::InitializeVM();
  Isolate* const isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Assembler assm(AssemblerOptions{});

  if (CpuFeatures::IsSupported(ARMv7)) {
    CpuFeatureScope scope(&assm, ARMv7);

    struct T {
      uint32_t input;
      uint32_t result;
    };
    T t;

    __ ldr(r1, MemOperand(r0, offsetof(T, input)));
    __ rbit(r1, r1);
    __ str(r1, MemOperand(r0, offsetof(T, result)));
    __ bx(lr);

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

#ifdef OBJECT_PRINT
    Print(*code, std::cout);
#endif

    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
    TEST_RBIT(0xFFFFFFFF, 0xFFFFFFFF);
    TEST_RBIT(0x00000000, 0x00000000);
    TEST_RBIT(0xFFFF0000, 0x0000FFFF);
    TEST_RBIT(0xFF00FF00, 0x00FF00FF);
    TEST_RBIT(0xF0F0F0F0, 0x0F0F0F0F);
    TEST_RBIT(0x1E6A2C48, 0x12345678);
  }
}


TEST(code_relative_offset) {
  // Test extracting the offset of a label from the beginning of the code
  // in a register.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  // Initialize a code object that will contain the code.
  Handle<HeapObject> code_object(ReadOnlyRoots(isolate).self_reference_marker(),
                                 isolate);

  Assembler assm(AssemblerOptions{});

  Label start, target_away, target_faraway;

  __ stm(db_w, sp, {r4, r5, lr});

  // r3 is used as the address zero, the test will crash when we load it.
  __ mov(r3, Operand::Zero());

  // r5 will be a pointer to the start of the code.
  __ mov(r5, Operand(code_object));
  __ mov_label_offset(r4, &start);

  __ mov_label_offset(r1, &target_faraway);
  __ str(r1, MemOperand(sp, kPointerSize, NegPreIndex));

  __ mov_label_offset(r1, &target_away);

  // Jump straight to 'target_away' the first time and use the relative
  // position the second time. This covers the case when extracting the
  // position of a label which is linked.
  __ mov(r2, Operand::Zero());
  __ bind(&start);
  __ cmp(r2, Operand::Zero());
  __ b(eq, &target_away);
  __ add(pc, r5, r1);
  // Emit invalid instructions to push the label between 2^8 and 2^16
  // instructions away. The test will crash if they are reached.
  for (int i = 0; i < (1 << 10); i++) {
    __ ldr(r3, MemOperand(r3));
  }
  __ bind(&target_away);
  // This will be hit twice: r0 = r0 + 5 + 5.
  __ add(r0, r0, Operand(5));

  __ ldr(r1, MemOperand(sp, kPointerSize, PostIndex), ne);
  __ add(pc, r5, r4, LeaveCC, ne);

  __ mov(r2, Operand(1));
  __ b(&start);
  // Emit invalid instructions to push the label between 2^16 and 2^24
  // instructions away. The test will crash if they are reached.
  for (int i = 0; i < (1 << 21); i++) {
    __ ldr(r3, MemOperand(r3));
  }
  __ bind(&target_faraway);
  // r0 = r0 + 5 + 5 + 11
  __ add(r0, r0, Operand(11));

  __ ldm
"""


```