Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/interpreter/wasm-interpreter.cc`.

Here's a breakdown of the thought process to arrive at the answer:

1. **Identify the Core Functionality:** The code consists of a series of C++ functions defined using macros like `INSTRUCTION_HANDLER_FUNC`, `SHIFT_CASE`, `CONVERT_CASE`, etc. The names of these functions (e.g., `s2s_SimdI64x2Shl`, `s2s_SimdF32x4SConvertI32x4`, `s2s_Throw`, `s2s_BranchOnNull`) strongly suggest they are implementations of specific WebAssembly instructions within the interpreter. The `s2s_` prefix likely stands for "stack to stack," indicating operations that primarily manipulate the interpreter's stack.

2. **Group Functionality by Instruction Type:** The code naturally falls into several categories based on the instruction types it handles:
    * **SIMD Operations:**  A large portion of the code deals with `Simd128` values and operations like shifts, extended multiplication, conversions, packing, selection, dot products, swizzling, shuffling, reductions (any/all true), and fused multiply-add/subtract (QFM). This is a prominent feature.
    * **Memory Access (SIMD):**  Instructions for loading and storing SIMD values to/from memory (`s2s_SimdS128Load`, `s2s_SimdS128Store`) are present, including splatting (loading a single value to all lanes), extending (loading and widening), and lane-specific operations.
    * **Exception Handling:**  The `s2s_Throw` and `s2s_Rethrow` functions clearly implement WebAssembly's exception handling mechanisms.
    * **Reference Type Operations (GC):**  Functions starting with `s2s_BranchOnNull`, `s2s_BranchOnNonNull`, and `s2s_BranchOnCast` deal with operations on reference types, which are related to WebAssembly's garbage collection features. These functions check for null values and perform type casting.

3. **Check for Torque:** The filename ends with `.cc`, not `.tq`. Therefore, it's C++ source code, not Torque.

4. **Relate to JavaScript (if applicable):**  SIMD operations in WebAssembly have a direct counterpart in JavaScript through the `SIMD` API. It's important to illustrate this connection with an example. The SIMD API allows performing parallel operations on fixed-width data vectors, mirroring the functionality seen in the C++ code.

5. **Provide Code Logic Reasoning (with assumptions):** For a specific instruction, demonstrate the input, the operation performed, and the output. The `s2s_SimdI64x2Shl` (shift left) is a good example for this. Clearly state the assumptions about the initial stack state.

6. **Illustrate Common Programming Errors:**  The memory access operations are prone to "out-of-bounds" errors. Provide a simple JavaScript example that attempts to access memory outside the allocated bounds, leading to a similar error.

7. **Address the "Part X of Y" Instruction:** This is the 7th part of a 15-part file. It's reasonable to infer that the entire file implements the WebAssembly interpreter, and this section focuses on a subset of its functionality, specifically SIMD and GC-related instructions.

8. **Structure the Answer:** Organize the information logically with clear headings for each aspect requested by the user (functionality, Torque, JavaScript relation, code logic, common errors, and overall function).

9. **Refine and Clarify:** Review the answer for clarity and accuracy. Use precise language and avoid jargon where possible. Ensure the JavaScript examples are concise and directly related to the C++ code's functionality. Double-check the assumptions and calculations in the code logic reasoning.
这是V8源代码 `v8/src/wasm/interpreter/wasm-interpreter.cc` 的第 7 部分，主要负责实现 **WebAssembly 解释器**中与 **SIMD (Single Instruction, Multiple Data)** 操作以及部分 **垃圾回收 (GC) 相关** 的指令。

以下是其功能的详细列举：

**1. SIMD 操作指令处理:**

* **内存加载和存储 SIMD 值:**
    * `s2s_SimdS128Store`: 将 SIMD 值存储到内存中指定地址。会进行越界检查。
    * `s2s_SimdS128Load8Splat`, `s2s_SimdS128Load16Splat`, `s2s_SimdS128Load32Splat`, `s2s_SimdS128Load64Splat`: 从内存中加载单个值并复制到 SIMD 向量的所有通道 (splat)。
    * `s2s_SimdS128Load8x8S/U`, `s2s_SimdS128Load16x4S/U`, `s2s_SimdS128Load32x2S/U`: 从内存中加载并扩展低位数据到 SIMD 向量。
    * `s2s_SimdS128Load32Zero`, `s2s_SimdS128Load64Zero`: 从内存加载 32 位或 64 位值到 SIMD 向量的第一个通道，其余通道置零。
    * `s2s_SimdS128Load8Lane`, `s2s_SimdS128Load16Lane`, `s2s_SimdS128Load32Lane`, `s2s_SimdS128Load64Lane`: 从内存加载单个值并设置到 SIMD 向量的指定通道。
    * `s2s_SimdS128Store8Lane`, `s2s_SimdS128Store16Lane`, `s2s_SimdS128Store32Lane`, `s2s_SimdS128Store64Lane`: 将 SIMD 向量的指定通道存储到内存。

* **SIMD 算术和位运算:**
    * `s2s_SimdI64x2Shl`, `s2s_SimdI64x2ShrS`, `s2s_SimdI64x2ShrU`, `s2s_SimdI32x4Shl`, `s2s_SimdI32x4ShrS`, `s2s_SimdI32x4ShrU`, `s2s_SimdI16x8Shl`, `s2s_SimdI16x8ShrS`, `s2s_SimdI16x8ShrU`, `s2s_SimdI8x16Shl`, `s2s_SimdI8x16ShrS`, `s2s_SimdI8x16ShrU`:  SIMD 向量的移位操作。
    * `s2s_SimdI16x8ExtMulLowI8x16S/U`, `s2s_SimdI16x8ExtMulHighI8x16S/U`, `s2s_SimdI32x4ExtMulLowI16x8S/U`, `s2s_SimdI32x4ExtMulHighI16x8S/U`, `s2s_SimdI64x2ExtMulLowI32x4S/U`, `s2s_SimdI64x2ExtMulHighI32x4S/U`: SIMD 向量的扩展乘法。

* **SIMD 类型转换:**
    * `s2s_SimdF32x4SConvertI32x4`, `s2s_SimdF32x4UConvertI32x4`, `s2s_SimdI32x4SConvertF32x4`, `s2s_SimdI32x4UConvertF32x4`, `s2s_SimdI32x4RelaxedTruncF32x4S/U`, `s2s_SimdI64x2SConvertI32x4Low/High`, `s2s_SimdI64x2UConvertI32x4Low/High`, `s2s_SimdI32x4SConvertI16x8High/Low`, `s2s_SimdI32x4UConvertI16x8High/Low`, `s2s_SimdI16x8SConvertI8x16High/Low`, `s2s_SimdI16x8UConvertI8x16High/Low`, `s2s_SimdF64x2ConvertLowI32x4S/U`, `s2s_SimdI32x4TruncSatF64x2SZero/U`, `s2s_SimdI32x4RelaxedTruncF64x2SZero/U`, `s2s_SimdF32x4DemoteF64x2Zero`, `s2s_SimdF64x2PromoteLowF32x4`: SIMD 向量元素之间的类型转换。

* **SIMD 数据打包:**
    * `s2s_SimdI16x8SConvertI32x4`, `s2s_SimdI16x8UConvertI32x4`, `s2s_SimdI8x16SConvertI16x8`, `s2s_SimdI8x16UConvertI16x8`: 将较大元素类型的 SIMD 向量打包成较小元素类型的 SIMD 向量。

* **SIMD 选择 (Select):**
    * `s2s_DoSimdSelect`, `s2s_SimdI8x16RelaxedLaneSelect`, `s2s_SimdI16x8RelaxedLaneSelect`, `s2s_SimdI32x4RelaxedLaneSelect`, `s2s_SimdI64x2RelaxedLaneSelect`, `s2s_SimdS128Select`: 根据布尔掩码从两个 SIMD 向量中选择元素。

* **SIMD 点积 (Dot Product):**
    * `s2s_SimdI32x4DotI16x8S`, `s2s_SimdI16x8DotI8x16I7x16S`, `s2s_SimdI32x4DotI8x16I7x16AddS`: 计算 SIMD 向量的点积。

* **SIMD 混洗和置换:**
    * `s2s_SimdI8x16Swizzle`, `s2s_SimdI8x16RelaxedSwizzle`: 根据第二个 SIMD 向量的值作为索引来置换第一个 SIMD 向量的元素。
    * `s2s_SimdI8x16Shuffle`: 根据第三个 SIMD 向量的值作为索引，从前两个 SIMD 向量中选择元素组成新的 SIMD 向量。

* **SIMD 规约:**
    * `s2s_SimdV128AnyTrue`: 检查 SIMD 向量中是否有任何元素为 true。
    * `s2s_SimdI64x2AllTrue`, `s2s_SimdI32x4AllTrue`, `s2s_SimdI16x8AllTrue`, `s2s_SimdI8x16AllTrue`: 检查 SIMD 向量中的所有元素是否都为 true。

* **SIMD 融合乘加/减 (Fused Multiply-Add/Subtract):**
    * `s2s_SimdF32x4Qfma`, `s2s_SimdF32x4Qfms`, `s2s_SimdF64x2Qfma`, `s2s_SimdF64x2Qfms`: 执行 SIMD 向量的融合乘法和加法或减法运算。

* **SIMD 成对扩展加法:**
    * `s2s_SimdI32x4ExtAddPairwiseI16x8S/U`, `s2s_SimdI16x8ExtAddPairwiseI8x16S/U`: 将 SIMD 向量中相邻的元素对相加，并将结果扩展到更大的数据类型。

**2. 异常处理指令处理:**

* `s2s_Throw`: 抛出一个 WebAssembly 异常。
* `s2s_Rethrow`: 重新抛出一个 WebAssembly 异常。

**3. 垃圾回收 (GC) 相关指令处理:**

* **空值检查分支:**
    * `s2s_BranchOnNull`: 如果引用是 null，则跳转到指定偏移量。
    * `s2s_BranchOnNullWithParams`: 如果引用不是 null，则跳转到指定偏移量。
    * `s2s_BranchOnNonNull`: 如果引用不是 null，则跳转到指定偏移量。
    * `s2s_BranchOnNonNullWithParams`: 如果引用是 null，则跳转到指定偏移量。
* **类型转换分支:**
    * `s2s_BranchOnCast`: 尝试将引用转换为指定类型，如果转换失败则跳转到指定偏移量。

**如果 v8/src/wasm/interpreter/wasm-interpreter.cc 以 .tq 结尾:**

那它将是一个 **V8 Torque 源代码**。Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的 C++ 代码，特别是用于实现 JavaScript 内置函数和 WebAssembly 指令。

**与 Javascript 的功能关系及举例:**

这里列出的 SIMD 操作指令在 JavaScript 中可以通过 **WebAssembly 的 SIMD proposal (现在是 WebAssembly 标准的一部分)** 来使用。开发者可以使用 JavaScript 的 `WebAssembly.Module` 和 `WebAssembly.Instance` API 来加载和执行包含 SIMD 指令的 WebAssembly 模块。

**JavaScript 示例:**

```javascript
// 假设有一个包含 SIMD 加法指令的 WebAssembly 模块
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // wasm header
  0x01, 0x07, 0x01, 0x00, 0x01, 0x60, 0x00, 0x00, // function signature
  0x03, 0x02, 0x01, 0x00,                         // function import section (empty)
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x00, 0xfd, 0x0b, 0x0b // code section (i32x4.add)
]);

WebAssembly.instantiate(wasmCode)
  .then(obj => {
    const instance = obj.instance;
    // 假设 WebAssembly 函数接受两个 i32x4 类型的参数
    // 并返回它们的和

    // 在 JavaScript 中没有直接的 i32x4 类型，
    // 但可以通过传递两个 i32 数组来模拟
    // (具体的模拟方式取决于 WebAssembly 模块的接口)
    // 这里只是概念性的例子

    // 实际操作会涉及 WebAssembly 的 Memory 和 TypedArray
    console.log("SIMD 加法结果 (概念性): 需要更具体的 WebAssembly 模块和接口定义");
  });
```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

* **指令:** `s2s_SimdI64x2Shl` (64位整数向量左移)
* **栈顶数据 (pop 顺序):**
    * `shift`:  3 (移位量)
    * `simd_value`:  `{ val: [5, 10] }`  (一个包含两个 64 位整数的 SIMD 向量)

**输出:**

* **操作:** 将 `simd_value` 中的每个 64 位整数左移 `shift` 位。
* **压入栈顶的数据:** `{ val: [5 << 3, 10 << 3] }`，即 `{ val: [40, 80] }`

**用户常见的编程错误举例:**

在使用 SIMD 操作时，一个常见的编程错误是 **内存越界访问**。

**C++ 代码片段中的例子：**

```c++
if (V8_UNLIKELY(effective_index < index ||
                !base::IsInBounds<uint64_t>(effective_index, sizeof(Simd128),
                                            wasm_runtime->GetMemorySize()))) {
  TRAP(TrapReason::kTrapMemOutOfBounds)
}
```

这段代码在尝试存储 SIMD 值之前，会检查计算出的有效内存地址 (`effective_index`) 是否越界。如果越界，就会触发 `TRAP(TrapReason::kTrapMemOutOfBounds)`，导致程序终止。

**JavaScript 例子:**

```javascript
const memory = new WebAssembly.Memory({ initial: 1 }); // 1 页内存 (64KB)
const buffer = new Uint8Array(memory.buffer);

// 尝试写入超出内存范围的数据
const offset = 65530; // 接近或超过 64KB 的末尾
const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]); // 16 字节

try {
  buffer.set(data, offset);
  console.log("写入成功 (不应该发生)");
} catch (e) {
  console.error("内存越界错误:", e); // 这应该会被捕获
}
```

在这个 JavaScript 例子中，尝试将 16 字节的数据写入接近内存末尾的位置，很可能会导致越界错误，这与 C++ 代码中检查的错误类型相似。

**归纳一下它的功能 (第 7 部分):**

这个代码片段是 WebAssembly 解释器中实现 **SIMD 操作** 和部分 **GC 相关操作** 的核心部分。它定义了各种指令的处理函数，负责执行 SIMD 向量的加载、存储、算术运算、位运算、类型转换、数据打包、选择、点积、混洗和规约等操作。此外，它还处理了 WebAssembly 的异常抛出和重新抛出机制，以及与引用类型相关的空值检查和类型转换分支指令。  这部分是解释器实现 WebAssembly 强大并行计算能力和安全内存管理的关键组成部分。

Prompt: 
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共15部分，请归纳一下它的功能

"""
effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(Simd128),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;
  base::WriteUnalignedValue<Simd128>(reinterpret_cast<Address>(address), val);

  NextOp();
}

#define SHIFT_CASE(op, name, stype, count, expr)                              \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##op(const uint8_t* code, uint32_t* sp,    \
                                        WasmInterpreterRuntime* wasm_runtime, \
                                        int64_t r0, double fp0) {             \
    uint32_t shift = pop<uint32_t>(sp, code, wasm_runtime);                   \
    stype s = pop<Simd128>(sp, code, wasm_runtime).to_##name();               \
    stype res;                                                                \
    for (size_t i = 0; i < count; ++i) {                                      \
      auto a = s.val[LANE(i, s)];                                             \
      res.val[LANE(i, res)] = expr;                                           \
    }                                                                         \
    push<Simd128>(sp, code, wasm_runtime, Simd128(res));                      \
    NextOp();                                                                 \
  }
SHIFT_CASE(I64x2Shl, i64x2, int64x2, 2,
           static_cast<uint64_t>(a) << (shift % 64))
SHIFT_CASE(I64x2ShrS, i64x2, int64x2, 2, a >> (shift % 64))
SHIFT_CASE(I64x2ShrU, i64x2, int64x2, 2,
           static_cast<uint64_t>(a) >> (shift % 64))
SHIFT_CASE(I32x4Shl, i32x4, int32x4, 4,
           static_cast<uint32_t>(a) << (shift % 32))
SHIFT_CASE(I32x4ShrS, i32x4, int32x4, 4, a >> (shift % 32))
SHIFT_CASE(I32x4ShrU, i32x4, int32x4, 4,
           static_cast<uint32_t>(a) >> (shift % 32))
SHIFT_CASE(I16x8Shl, i16x8, int16x8, 8,
           static_cast<uint16_t>(a) << (shift % 16))
SHIFT_CASE(I16x8ShrS, i16x8, int16x8, 8, a >> (shift % 16))
SHIFT_CASE(I16x8ShrU, i16x8, int16x8, 8,
           static_cast<uint16_t>(a) >> (shift % 16))
SHIFT_CASE(I8x16Shl, i8x16, int8x16, 16, static_cast<uint8_t>(a) << (shift % 8))
SHIFT_CASE(I8x16ShrS, i8x16, int8x16, 16, a >> (shift % 8))
SHIFT_CASE(I8x16ShrU, i8x16, int8x16, 16,
           static_cast<uint8_t>(a) >> (shift % 8))
#undef SHIFT_CASE

template <typename s_type, typename d_type, typename narrow, typename wide,
          uint32_t start>
INSTRUCTION_HANDLER_FUNC s2s_DoSimdExtMul(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  s_type s2 = pop<Simd128>(sp, code, wasm_runtime).to<s_type>();
  s_type s1 = pop<Simd128>(sp, code, wasm_runtime).to<s_type>();
  auto end = start + (kSimd128Size / sizeof(wide));
  d_type res;
  uint32_t i = start;
  for (size_t dst = 0; i < end; ++i, ++dst) {
    // Need static_cast for unsigned narrow types.
    res.val[LANE(dst, res)] =
        MultiplyLong<wide>(static_cast<narrow>(s1.val[LANE(start, s1)]),
                           static_cast<narrow>(s2.val[LANE(start, s2)]));
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));
  NextOp();
}
static auto s2s_SimdI16x8ExtMulLowI8x16S =
    s2s_DoSimdExtMul<int8x16, int16x8, int8_t, int16_t, 0>;
static auto s2s_SimdI16x8ExtMulHighI8x16S =
    s2s_DoSimdExtMul<int8x16, int16x8, int8_t, int16_t, 8>;
static auto s2s_SimdI16x8ExtMulLowI8x16U =
    s2s_DoSimdExtMul<int8x16, int16x8, uint8_t, uint16_t, 0>;
static auto s2s_SimdI16x8ExtMulHighI8x16U =
    s2s_DoSimdExtMul<int8x16, int16x8, uint8_t, uint16_t, 8>;
static auto s2s_SimdI32x4ExtMulLowI16x8S =
    s2s_DoSimdExtMul<int16x8, int32x4, int16_t, int32_t, 0>;
static auto s2s_SimdI32x4ExtMulHighI16x8S =
    s2s_DoSimdExtMul<int16x8, int32x4, int16_t, int32_t, 4>;
static auto s2s_SimdI32x4ExtMulLowI16x8U =
    s2s_DoSimdExtMul<int16x8, int32x4, uint16_t, uint32_t, 0>;
static auto s2s_SimdI32x4ExtMulHighI16x8U =
    s2s_DoSimdExtMul<int16x8, int32x4, uint16_t, uint32_t, 4>;
static auto s2s_SimdI64x2ExtMulLowI32x4S =
    s2s_DoSimdExtMul<int32x4, int64x2, int32_t, int64_t, 0>;
static auto s2s_SimdI64x2ExtMulHighI32x4S =
    s2s_DoSimdExtMul<int32x4, int64x2, int32_t, int64_t, 2>;
static auto s2s_SimdI64x2ExtMulLowI32x4U =
    s2s_DoSimdExtMul<int32x4, int64x2, uint32_t, uint64_t, 0>;
static auto s2s_SimdI64x2ExtMulHighI32x4U =
    s2s_DoSimdExtMul<int32x4, int64x2, uint32_t, uint64_t, 2>;
#undef EXT_MUL_CASE

#define CONVERT_CASE(op, src_type, name, dst_type, count, start_index, ctype, \
                     expr)                                                    \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##op(const uint8_t* code, uint32_t* sp,    \
                                        WasmInterpreterRuntime* wasm_runtime, \
                                        int64_t r0, double fp0) {             \
    src_type s = pop<Simd128>(sp, code, wasm_runtime).to_##name();            \
    dst_type res = {0};                                                       \
    for (size_t i = 0; i < count; ++i) {                                      \
      ctype a = s.val[LANE(start_index + i, s)];                              \
      res.val[LANE(i, res)] = expr;                                           \
    }                                                                         \
    push<Simd128>(sp, code, wasm_runtime, Simd128(res));                      \
    NextOp();                                                                 \
  }
CONVERT_CASE(F32x4SConvertI32x4, int32x4, i32x4, float32x4, 4, 0, int32_t,
             static_cast<float>(a))
CONVERT_CASE(F32x4UConvertI32x4, int32x4, i32x4, float32x4, 4, 0, uint32_t,
             static_cast<float>(a))
CONVERT_CASE(I32x4SConvertF32x4, float32x4, f32x4, int32x4, 4, 0, float,
             base::saturated_cast<int32_t>(a))
CONVERT_CASE(I32x4UConvertF32x4, float32x4, f32x4, int32x4, 4, 0, float,
             base::saturated_cast<uint32_t>(a))
CONVERT_CASE(I32x4RelaxedTruncF32x4S, float32x4, f32x4, int32x4, 4, 0, float,
             base::saturated_cast<int32_t>(a))
CONVERT_CASE(I32x4RelaxedTruncF32x4U, float32x4, f32x4, int32x4, 4, 0, float,
             base::saturated_cast<uint32_t>(a))
CONVERT_CASE(I64x2SConvertI32x4Low, int32x4, i32x4, int64x2, 2, 0, int32_t, a)
CONVERT_CASE(I64x2SConvertI32x4High, int32x4, i32x4, int64x2, 2, 2, int32_t, a)
CONVERT_CASE(I64x2UConvertI32x4Low, int32x4, i32x4, int64x2, 2, 0, uint32_t, a)
CONVERT_CASE(I64x2UConvertI32x4High, int32x4, i32x4, int64x2, 2, 2, uint32_t, a)
CONVERT_CASE(I32x4SConvertI16x8High, int16x8, i16x8, int32x4, 4, 4, int16_t, a)
CONVERT_CASE(I32x4UConvertI16x8High, int16x8, i16x8, int32x4, 4, 4, uint16_t, a)
CONVERT_CASE(I32x4SConvertI16x8Low, int16x8, i16x8, int32x4, 4, 0, int16_t, a)
CONVERT_CASE(I32x4UConvertI16x8Low, int16x8, i16x8, int32x4, 4, 0, uint16_t, a)
CONVERT_CASE(I16x8SConvertI8x16High, int8x16, i8x16, int16x8, 8, 8, int8_t, a)
CONVERT_CASE(I16x8UConvertI8x16High, int8x16, i8x16, int16x8, 8, 8, uint8_t, a)
CONVERT_CASE(I16x8SConvertI8x16Low, int8x16, i8x16, int16x8, 8, 0, int8_t, a)
CONVERT_CASE(I16x8UConvertI8x16Low, int8x16, i8x16, int16x8, 8, 0, uint8_t, a)
CONVERT_CASE(F64x2ConvertLowI32x4S, int32x4, i32x4, float64x2, 2, 0, int32_t,
             static_cast<double>(a))
CONVERT_CASE(F64x2ConvertLowI32x4U, int32x4, i32x4, float64x2, 2, 0, uint32_t,
             static_cast<double>(a))
CONVERT_CASE(I32x4TruncSatF64x2SZero, float64x2, f64x2, int32x4, 2, 0, double,
             base::saturated_cast<int32_t>(a))
CONVERT_CASE(I32x4TruncSatF64x2UZero, float64x2, f64x2, int32x4, 2, 0, double,
             base::saturated_cast<uint32_t>(a))
CONVERT_CASE(I32x4RelaxedTruncF64x2SZero, float64x2, f64x2, int32x4, 2, 0,
             double, base::saturated_cast<int32_t>(a))
CONVERT_CASE(I32x4RelaxedTruncF64x2UZero, float64x2, f64x2, int32x4, 2, 0,
             double, base::saturated_cast<uint32_t>(a))
CONVERT_CASE(F32x4DemoteF64x2Zero, float64x2, f64x2, float32x4, 2, 0, float,
             DoubleToFloat32(a))
CONVERT_CASE(F64x2PromoteLowF32x4, float32x4, f32x4, float64x2, 2, 0, float,
             static_cast<double>(a))
#undef CONVERT_CASE

#define PACK_CASE(op, src_type, name, dst_type, count, dst_ctype)             \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##op(const uint8_t* code, uint32_t* sp,    \
                                        WasmInterpreterRuntime* wasm_runtime, \
                                        int64_t r0, double fp0) {             \
    src_type s2 = pop<Simd128>(sp, code, wasm_runtime).to_##name();           \
    src_type s1 = pop<Simd128>(sp, code, wasm_runtime).to_##name();           \
    dst_type res;                                                             \
    for (size_t i = 0; i < count; ++i) {                                      \
      int64_t v = i < count / 2 ? s1.val[LANE(i, s1)]                         \
                                : s2.val[LANE(i - count / 2, s2)];            \
      res.val[LANE(i, res)] = base::saturated_cast<dst_ctype>(v);             \
    }                                                                         \
    push<Simd128>(sp, code, wasm_runtime, Simd128(res));                      \
    NextOp();                                                                 \
  }
PACK_CASE(I16x8SConvertI32x4, int32x4, i32x4, int16x8, 8, int16_t)
PACK_CASE(I16x8UConvertI32x4, int32x4, i32x4, int16x8, 8, uint16_t)
PACK_CASE(I8x16SConvertI16x8, int16x8, i16x8, int8x16, 16, int8_t)
PACK_CASE(I8x16UConvertI16x8, int16x8, i16x8, int8x16, 16, uint8_t)
#undef PACK_CASE

INSTRUCTION_HANDLER_FUNC s2s_DoSimdSelect(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  int32x4 bool_val = pop<Simd128>(sp, code, wasm_runtime).to_i32x4();
  int32x4 v2 = pop<Simd128>(sp, code, wasm_runtime).to_i32x4();
  int32x4 v1 = pop<Simd128>(sp, code, wasm_runtime).to_i32x4();
  int32x4 res;
  for (size_t i = 0; i < 4; ++i) {
    res.val[LANE(i, res)] =
        v2.val[LANE(i, v2)] ^ ((v1.val[LANE(i, v1)] ^ v2.val[LANE(i, v2)]) &
                               bool_val.val[LANE(i, bool_val)]);
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));
  NextOp();
}
// Do these 5 instructions really have the same implementation?
static auto s2s_SimdI8x16RelaxedLaneSelect = s2s_DoSimdSelect;
static auto s2s_SimdI16x8RelaxedLaneSelect = s2s_DoSimdSelect;
static auto s2s_SimdI32x4RelaxedLaneSelect = s2s_DoSimdSelect;
static auto s2s_SimdI64x2RelaxedLaneSelect = s2s_DoSimdSelect;
static auto s2s_SimdS128Select = s2s_DoSimdSelect;

INSTRUCTION_HANDLER_FUNC s2s_SimdI32x4DotI16x8S(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  int16x8 v2 = pop<Simd128>(sp, code, wasm_runtime).to_i16x8();
  int16x8 v1 = pop<Simd128>(sp, code, wasm_runtime).to_i16x8();
  int32x4 res;
  for (size_t i = 0; i < 4; i++) {
    int32_t lo = (v1.val[LANE(i * 2, v1)] * v2.val[LANE(i * 2, v2)]);
    int32_t hi = (v1.val[LANE(i * 2 + 1, v1)] * v2.val[LANE(i * 2 + 1, v2)]);
    res.val[LANE(i, res)] = base::AddWithWraparound(lo, hi);
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_SimdI16x8DotI8x16I7x16S(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  int8x16 v2 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int8x16 v1 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int16x8 res;
  for (size_t i = 0; i < 8; i++) {
    int16_t lo = (v1.val[LANE(i * 2, v1)] * v2.val[LANE(i * 2, v2)]);
    int16_t hi = (v1.val[LANE(i * 2 + 1, v1)] * v2.val[LANE(i * 2 + 1, v2)]);
    res.val[LANE(i, res)] = base::AddWithWraparound(lo, hi);
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_SimdI32x4DotI8x16I7x16AddS(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  int32x4 v3 = pop<Simd128>(sp, code, wasm_runtime).to_i32x4();
  int8x16 v2 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int8x16 v1 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int32x4 res;
  for (size_t i = 0; i < 4; i++) {
    int32_t a = (v1.val[LANE(i * 4, v1)] * v2.val[LANE(i * 4, v2)]);
    int32_t b = (v1.val[LANE(i * 4 + 1, v1)] * v2.val[LANE(i * 4 + 1, v2)]);
    int32_t c = (v1.val[LANE(i * 4 + 2, v1)] * v2.val[LANE(i * 4 + 2, v2)]);
    int32_t d = (v1.val[LANE(i * 4 + 3, v1)] * v2.val[LANE(i * 4 + 3, v2)]);
    int32_t acc = v3.val[LANE(i, v3)];
    // a + b + c + d should not wrap
    res.val[LANE(i, res)] = base::AddWithWraparound(a + b + c + d, acc);
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_SimdI8x16Swizzle(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  int8x16 v2 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int8x16 v1 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int8x16 res;
  for (size_t i = 0; i < kSimd128Size; ++i) {
    int lane = v2.val[LANE(i, v2)];
    res.val[LANE(i, res)] =
        lane < kSimd128Size && lane >= 0 ? v1.val[LANE(lane, v1)] : 0;
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));
  NextOp();
}
static auto s2s_SimdI8x16RelaxedSwizzle = s2s_SimdI8x16Swizzle;

INSTRUCTION_HANDLER_FUNC s2s_SimdI8x16Shuffle(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  int8x16 value = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int8x16 v2 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int8x16 v1 = pop<Simd128>(sp, code, wasm_runtime).to_i8x16();
  int8x16 res;
  for (size_t i = 0; i < kSimd128Size; ++i) {
    int lane = value.val[i];
    res.val[LANE(i, res)] = lane < kSimd128Size
                                ? v1.val[LANE(lane, v1)]
                                : v2.val[LANE(lane - kSimd128Size, v2)];
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_SimdV128AnyTrue(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  int32x4 s = pop<Simd128>(sp, code, wasm_runtime).to_i32x4();
  bool res = s.val[LANE(0, s)] | s.val[LANE(1, s)] | s.val[LANE(2, s)] |
             s.val[LANE(3, s)];
  push<int32_t>(sp, code, wasm_runtime, res);
  NextOp();
}

#define REDUCTION_CASE(op, name, stype, count)                                \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##op(const uint8_t* code, uint32_t* sp,    \
                                        WasmInterpreterRuntime* wasm_runtime, \
                                        int64_t r0, double fp0) {             \
    stype s = pop<Simd128>(sp, code, wasm_runtime).to_##name();               \
    bool res = true;                                                          \
    for (size_t i = 0; i < count; ++i) {                                      \
      res = res & static_cast<bool>(s.val[LANE(i, s)]);                       \
    }                                                                         \
    push<int32_t>(sp, code, wasm_runtime, res);                               \
    NextOp();                                                                 \
  }
REDUCTION_CASE(I64x2AllTrue, i64x2, int64x2, 2)
REDUCTION_CASE(I32x4AllTrue, i32x4, int32x4, 4)
REDUCTION_CASE(I16x8AllTrue, i16x8, int16x8, 8)
REDUCTION_CASE(I8x16AllTrue, i8x16, int8x16, 16)
#undef REDUCTION_CASE

#define QFM_CASE(op, name, stype, count, operation)                           \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##op(const uint8_t* code, uint32_t* sp,    \
                                        WasmInterpreterRuntime* wasm_runtime, \
                                        int64_t r0, double fp0) {             \
    stype c = pop<Simd128>(sp, code, wasm_runtime).to_##name();               \
    stype b = pop<Simd128>(sp, code, wasm_runtime).to_##name();               \
    stype a = pop<Simd128>(sp, code, wasm_runtime).to_##name();               \
    stype res;                                                                \
    for (size_t i = 0; i < count; i++) {                                      \
      res.val[LANE(i, res)] =                                                 \
          operation(a.val[LANE(i, a)] * b.val[LANE(i, b)]) +                  \
          c.val[LANE(i, c)];                                                  \
    }                                                                         \
    push<Simd128>(sp, code, wasm_runtime, Simd128(res));                      \
    NextOp();                                                                 \
  }
QFM_CASE(F32x4Qfma, f32x4, float32x4, 4, +)
QFM_CASE(F32x4Qfms, f32x4, float32x4, 4, -)
QFM_CASE(F64x2Qfma, f64x2, float64x2, 2, +)
QFM_CASE(F64x2Qfms, f64x2, float64x2, 2, -)
#undef QFM_CASE

template <typename s_type, typename load_type>
INSTRUCTION_HANDLER_FUNC s2s_DoSimdLoadSplat(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);

  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index,
                                              sizeof(load_type),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;
  load_type v =
      base::ReadUnalignedValue<load_type>(reinterpret_cast<Address>(address));
  s_type s;
  for (size_t i = 0; i < arraysize(s.val); i++) {
    s.val[LANE(i, s)] = v;
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(s));

  NextOp();
}
static auto s2s_SimdS128Load8Splat = s2s_DoSimdLoadSplat<int8x16, int8_t>;
static auto s2s_SimdS128Load16Splat = s2s_DoSimdLoadSplat<int16x8, int16_t>;
static auto s2s_SimdS128Load32Splat = s2s_DoSimdLoadSplat<int32x4, int32_t>;
static auto s2s_SimdS128Load64Splat = s2s_DoSimdLoadSplat<int64x2, int64_t>;

template <typename s_type, typename wide_type, typename narrow_type>
INSTRUCTION_HANDLER_FUNC s2s_DoSimdLoadExtend(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  static_assert(sizeof(wide_type) == sizeof(narrow_type) * 2,
                "size mismatch for wide and narrow types");
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);

  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(uint64_t),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;
  uint64_t v =
      base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(address));
  constexpr int lanes = kSimd128Size / sizeof(wide_type);
  s_type s;
  for (int i = 0; i < lanes; i++) {
    uint8_t shift = i * (sizeof(narrow_type) * 8);
    narrow_type el = static_cast<narrow_type>(v >> shift);
    s.val[LANE(i, s)] = static_cast<wide_type>(el);
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(s));

  NextOp();
}
static auto s2s_SimdS128Load8x8S =
    s2s_DoSimdLoadExtend<int16x8, int16_t, int8_t>;
static auto s2s_SimdS128Load8x8U =
    s2s_DoSimdLoadExtend<int16x8, uint16_t, uint8_t>;
static auto s2s_SimdS128Load16x4S =
    s2s_DoSimdLoadExtend<int32x4, int32_t, int16_t>;
static auto s2s_SimdS128Load16x4U =
    s2s_DoSimdLoadExtend<int32x4, uint32_t, uint16_t>;
static auto s2s_SimdS128Load32x2S =
    s2s_DoSimdLoadExtend<int64x2, int64_t, int32_t>;
static auto s2s_SimdS128Load32x2U =
    s2s_DoSimdLoadExtend<int64x2, uint64_t, uint32_t>;

template <typename s_type, typename load_type>
INSTRUCTION_HANDLER_FUNC s2s_DoSimdLoadZeroExtend(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);

  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index,
                                              sizeof(load_type),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;
  load_type v =
      base::ReadUnalignedValue<load_type>(reinterpret_cast<Address>(address));
  s_type s;
  // All lanes are 0.
  for (size_t i = 0; i < arraysize(s.val); i++) {
    s.val[LANE(i, s)] = 0;
  }
  // Lane 0 is set to the loaded value.
  s.val[LANE(0, s)] = v;
  push<Simd128>(sp, code, wasm_runtime, Simd128(s));

  NextOp();
}
static auto s2s_SimdS128Load32Zero =
    s2s_DoSimdLoadZeroExtend<int32x4, uint32_t>;
static auto s2s_SimdS128Load64Zero =
    s2s_DoSimdLoadZeroExtend<int64x2, uint64_t>;

template <typename s_type, typename result_type, typename load_type>
INSTRUCTION_HANDLER_FUNC s2s_DoSimdLoadLane(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  s_type value = pop<Simd128>(sp, code, wasm_runtime).to<s_type>();

  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);

  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index,
                                              sizeof(load_type),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;
  result_type loaded =
      base::ReadUnalignedValue<load_type>(reinterpret_cast<Address>(address));
  uint16_t lane = Read<uint16_t>(code);
  value.val[LANE(lane, value)] = loaded;
  push<Simd128>(sp, code, wasm_runtime, Simd128(value));

  NextOp();
}
static auto s2s_SimdS128Load8Lane =
    s2s_DoSimdLoadLane<int8x16, int32_t, int8_t>;
static auto s2s_SimdS128Load16Lane =
    s2s_DoSimdLoadLane<int16x8, int32_t, int16_t>;
static auto s2s_SimdS128Load32Lane =
    s2s_DoSimdLoadLane<int32x4, int32_t, int32_t>;
static auto s2s_SimdS128Load64Lane =
    s2s_DoSimdLoadLane<int64x2, int64_t, int64_t>;

template <typename s_type, typename result_type, typename load_type>
INSTRUCTION_HANDLER_FUNC s2s_DoSimdStoreLane(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  // Extract a single lane, push it onto the stack, then store the lane.
  s_type value = pop<Simd128>(sp, code, wasm_runtime).to<s_type>();

  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);

  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index,
                                              sizeof(load_type),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }
  uint8_t* address = memory_start + effective_index;

  uint16_t lane = Read<uint16_t>(code);
  result_type res = value.val[LANE(lane, value)];
  base::WriteUnalignedValue<result_type>(reinterpret_cast<Address>(address),
                                         res);

  NextOp();
}
static auto s2s_SimdS128Store8Lane =
    s2s_DoSimdStoreLane<int8x16, int32_t, int8_t>;
static auto s2s_SimdS128Store16Lane =
    s2s_DoSimdStoreLane<int16x8, int32_t, int16_t>;
static auto s2s_SimdS128Store32Lane =
    s2s_DoSimdStoreLane<int32x4, int32_t, int32_t>;
static auto s2s_SimdS128Store64Lane =
    s2s_DoSimdStoreLane<int64x2, int64_t, int64_t>;

template <typename DstSimdType, typename SrcSimdType, typename Wide,
          typename Narrow>
INSTRUCTION_HANDLER_FUNC s2s_DoSimdExtAddPairwise(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  constexpr int lanes = kSimd128Size / sizeof(DstSimdType::val[0]);
  auto v = pop<Simd128>(sp, code, wasm_runtime).to<SrcSimdType>();
  DstSimdType res;
  for (int i = 0; i < lanes; ++i) {
    res.val[LANE(i, res)] =
        AddLong<Wide>(static_cast<Narrow>(v.val[LANE(i * 2, v)]),
                      static_cast<Narrow>(v.val[LANE(i * 2 + 1, v)]));
  }
  push<Simd128>(sp, code, wasm_runtime, Simd128(res));

  NextOp();
}
static auto s2s_SimdI32x4ExtAddPairwiseI16x8S =
    s2s_DoSimdExtAddPairwise<int32x4, int16x8, int32_t, int16_t>;
static auto s2s_SimdI32x4ExtAddPairwiseI16x8U =
    s2s_DoSimdExtAddPairwise<int32x4, int16x8, uint32_t, uint16_t>;
static auto s2s_SimdI16x8ExtAddPairwiseI8x16S =
    s2s_DoSimdExtAddPairwise<int16x8, int8x16, int16_t, int8_t>;
static auto s2s_SimdI16x8ExtAddPairwiseI8x16U =
    s2s_DoSimdExtAddPairwise<int16x8, int8x16, uint16_t, uint8_t>;

////////////////////////////////////////////////////////////////////////////////

INSTRUCTION_HANDLER_FUNC s2s_Throw(const uint8_t* code, uint32_t* sp,
                                   WasmInterpreterRuntime* wasm_runtime,
                                   int64_t r0, double fp0) {
  uint32_t tag_index = ReadI32(code);

  // This will advance the code pointer.
  wasm_runtime->ThrowException(code, sp, tag_index);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_Rethrow(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  uint32_t catch_block_index = ReadI32(code);
  wasm_runtime->RethrowException(code, sp, catch_block_index);

  NextOp();
}

////////////////////////////////////////////////////////////////////////////////
// GC instruction handlers.

int StructFieldOffset(const StructType* struct_type, int field_index) {
  return wasm::ObjectAccess::ToTagged(WasmStruct::kHeaderSize +
                                      struct_type->field_offset(field_index));
}

INSTRUCTION_HANDLER_FUNC s2s_BranchOnNull(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  // TODO(paolosev@microsoft.com): Implement peek<T>?
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);

  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);

  push<WasmRef>(sp, code, wasm_runtime, ref);

  int32_t if_null_offset = ReadI32(code);
  if (wasm_runtime->IsNullTypecheck(ref, ref_type)) {
    // If condition is true (ref is null), jump to the target branch.
    code += (if_null_offset - kCodeOffsetSize);
  }

  NextOp();
}

/*
 * Notice that in s2s_BranchOnNullWithParams the branch happens when the
 * condition is false, not true, as follows:
 *
 *   > s2s_BranchOnNullWithParams
 *       pop - ref
 *       i32: ref value_tye
 *       push - ref
 *       branch_offset (if NOT NULL)  ----+
 *   > s2s_CopySlot                       |
 *       ....                             |
 *   > s2s_Branch (gets here if NULL)     |
 *       branch_offset                    |
 *   > (next instruction) <---------------+
 */
INSTRUCTION_HANDLER_FUNC s2s_BranchOnNullWithParams(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  // TO(paolosev@microsoft.com): Implement peek<T>?
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);

  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);

  push<WasmRef>(sp, code, wasm_runtime, ref);

  int32_t if_null_offset = ReadI32(code);
  if (!wasm_runtime->IsNullTypecheck(ref, ref_type)) {
    // If condition is false (ref is not null), jump to the false branch.
    code += (if_null_offset - kCodeOffsetSize);
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_BranchOnNonNull(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  // TO(paolosev@microsoft.com): Implement peek<T>?
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);

  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);

  push<WasmRef>(sp, code, wasm_runtime, ref);

  int32_t if_non_null_offset = ReadI32(code);
  if (!wasm_runtime->IsNullTypecheck(ref, ref_type)) {
    // If condition is true (ref is not null), jump to the target branch.
    code += (if_non_null_offset - kCodeOffsetSize);
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_BranchOnNonNullWithParams(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  // TO(paolosev@microsoft.com): Implement peek<T>?
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);

  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);

  push<WasmRef>(sp, code, wasm_runtime, ref);

  int32_t if_non_null_offset = ReadI32(code);
  if (wasm_runtime->IsNullTypecheck(ref, ref_type)) {
    // If condition is false (ref is null), jump to the false branch.
    code += (if_non_null_offset - kCodeOffsetSize);
  }

  NextOp();
}

bool DoRefCast(WasmRef ref, ValueType ref_type, HeapType target_type,
               bool null_succeeds, WasmInterpreterRuntime* wasm_runtime) {
  if (target_type.is_index()) {
    Handle<Map> rtt = wasm_runtime->RttCanon(target_type.ref_index());
    return wasm_runtime->SubtypeCheck(ref, ref_type, rtt,
                                      ValueType::Rtt(target_type.ref_index()),
                                      null_succeeds);
  } else {
    switch (target_type.representation()) {
      case HeapType::kEq:
        return wasm_runtime->RefIsEq(ref, ref_type, null_succeeds);
      case HeapType::kI31:
        return wasm_runtime->RefIsI31(ref, ref_type, null_succeeds);
      case HeapType::kStruct:
        return wasm_runtime->RefIsStruct(ref, ref_type, null_succeeds);
      case HeapType::kArray:
        return wasm_runtime->RefIsArray(ref, ref_type, null_succeeds);
      case HeapType::kString:
        return wasm_runtime->RefIsString(ref, ref_type, null_succeeds);
      case HeapType::kNone:
      case HeapType::kNoExtern:
      case HeapType::kNoFunc:
        DCHECK(null_succeeds);
        return wasm_runtime->IsNullTypecheck(ref, ref_type);
      case HeapType::kAny:
        // Any may never need a cast as it is either implicitly convertible or
        // never convertible for any given type.
      default:
        UNREACHABLE();
    }
  }
}

/*
 * Notice that in s2s_BranchOnCast the branch happens when the condition is
 * false, not true, as follows:
 *
 *   > s2s_BranchOnCast
 *       i32: null_succeeds
 *       i32: target_type HeapType representation
 *       pop - ref
 *       i32: ref value_tye
 *       push - ref
 *       branch_offset (if CAST FAILS) --------+
 *   > s2s_CopySlot                            |
 *       ....                                  |
 *   > s2s_Branch (gets here if CAST SUCCEEDS) |
 *       branch_offset                         |
 *   > (next instruction) <--------------------+
 */
INSTRUCTION_HANDLER_FUNC s2s_BranchOnCast(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  bool null_succeeds = ReadI32(code);
  HeapType target_type(ReadI32(code));

  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);
  push<WasmRef>(sp, code, wasm_runtime, ref);
  int32_t no_branch_offset = ReadI32(code);

  if (!DoRefCast(ref, ref_type, target_type, null_succeeds, wasm_runtime)) {
    // If condition is not true, jump to the 'false' branch.
    code += (no_branch_offset - kCodeOffsetSize)
"""


```