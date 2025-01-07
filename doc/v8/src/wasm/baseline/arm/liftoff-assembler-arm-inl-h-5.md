Response:
Let's break down the thought process for analyzing this V8 Liftoff Assembler code.

1. **Understand the Goal:** The request asks for the *functionality* of the provided C++ header file. This means identifying what operations it enables and how it interacts with the larger V8 system.

2. **Initial Scan for Keywords:** Quickly scan the code for recognizable keywords and patterns:
    * `emit_`:  This strongly suggests functions that generate assembly instructions. The names following `emit_` (e.g., `emit_i64x2_ge_s`, `emit_f32x4_eq`) are likely the names of WebAssembly instructions or related operations.
    * `LiftoffAssembler`: This is the central class, and its methods are the primary focus.
    * `LiftoffRegister`:  This likely represents a register used in the Liftoff compiler.
    * `Simd128Register`, `DoubleRegister`, `FloatRegister`, `Register`:  These indicate different types of registers, probably corresponding to different data types (SIMD, floating-point, general-purpose).
    * `v...`:  Prefixes like `vceq`, `vmvn`, `vand`, etc., are strongly indicative of ARM Neon (SIMD) instructions.
    * `I64x2GeS`, `F64x2Compare`, `S128NarrowOp`, `I64x2Abs`: These appear to be helper functions or macros within the Liftoff framework for more complex operations.
    * `memcpy`:  Standard C library function for memory copying.
    * `UseScratchRegisterScope`: A RAII (Resource Acquisition Is Initialization) pattern for managing temporary registers.
    * `Label`:  Used for branching within the generated code.
    * `StackCheck`, `PushRegisters`, `PopRegisters`:  Functions related to stack management.
    * `CallC`, `CallNativeWasmCode`, `CallIndirect`, `CallBuiltin`: Functions related to calling other code (C functions, WebAssembly functions, built-in functions).
    * `AllocateStackSlot`, `DeallocateStackSlot`: Functions for managing stack memory.
    * `LiftoffStackSlots`: A separate class likely for managing stack slot allocation during code generation.

3. **Categorize Functionality:** Based on the keywords and patterns, start grouping the functions into logical categories:
    * **SIMD Operations:**  The majority of the functions fall into this category, dealing with `i8x16`, `i16x8`, `i32x4`, `i64x2`, `f32x4`, `f64x2`, and potentially `f16x8` (though many `f16x8` functions return `false`, suggesting incomplete implementation or lack of support). These functions perform arithmetic, comparison, bitwise, and conversion operations on SIMD vectors.
    * **Stack Management:** Functions like `StackCheck`, `PushRegisters`, `PopRegisters`, `AllocateStackSlot`, `DeallocateStackSlot`, and the `LiftoffStackSlots` class clearly handle managing the execution stack.
    * **Function Calls:**  The `CallC`, `CallNativeWasmCode`, `TailCallNativeWasmCode`, `CallIndirect`, and `CallBuiltin` functions are responsible for invoking other code, either within the WebAssembly module or external C/C++ functions or built-in V8 functions.
    * **Conversions:**  Functions with `convert` in their name (e.g., `emit_i32x4_sconvert_f32x4`) handle converting data between different types (integers to floats, narrower to wider integers, etc.).
    * **Bitwise Operations:**  Functions like `emit_s128_not`, `emit_s128_and`, `emit_s128_or`, `emit_s128_xor`, and `emit_s128_and_not` perform bitwise logical operations on SIMD vectors.
    * **Comparisons:** Functions like `emit_i32x4_eq`, `emit_f32x4_lt`, etc., perform comparisons between SIMD vectors.
    * **Constants:** The `emit_s128_const` function deals with loading constant values into SIMD registers.
    * **Miscellaneous:**  Functions like `AssertUnreachable`, `RecordSpillsInSafepoint`, `DropStackSlotsAndRet`, `MaybeOSR`, and the `emit_set_if_nan` functions don't fit neatly into the other categories but are still part of the assembler's functionality.

4. **Detail within Categories:**  For each category, elaborate on the specific operations performed by the functions. For example, within "SIMD Operations," mention the different data types and the types of operations (arithmetic, logical, comparison, etc.). Note any patterns, like the use of ARM Neon instructions.

5. **Address Specific Questions:** Go through the specific questions in the prompt:
    * **Functionality:** This is covered by the categorization and detailed descriptions.
    * **Torque Source:** Check the file extension (`.h` vs. `.tq`). In this case, it's `.h`, so it's not Torque.
    * **JavaScript Relation:** Think about which WebAssembly features these operations map to in JavaScript. SIMD is the obvious connection. Provide a JavaScript example using `SIMD`.
    * **Code Logic and I/O:** Choose a simple function and illustrate its operation with an example input and output. Focus on the data manipulation within the function.
    * **Common Programming Errors:**  Relate the operations to potential errors a programmer might make when working with SIMD or similar concepts (e.g., type mismatches, incorrect lane access).
    * **Final Summary:**  Provide a concise overview of the file's purpose.

6. **Refine and Organize:** Review the generated analysis for clarity, accuracy, and completeness. Organize the information logically with headings and bullet points. Ensure that the language is precise and avoids jargon where possible, or explains it when necessary. For instance, explaining what SIMD is helps provide context.

7. **Self-Correction/Double-Checking:**  Read through the analysis as if you were someone unfamiliar with the code. Does it make sense? Are there any ambiguities?  Are the examples clear and accurate? For the `f16x8` functions, explicitly stating that they seem unsupported based on their return value is important.

By following these steps, you can systematically analyze the provided V8 source code and generate a comprehensive and informative response that addresses all aspects of the request. The key is to start with a broad overview and progressively drill down into the details, focusing on the core functionality and its relationship to the larger system and user-level programming concepts.
好的，这是V8源代码文件 `v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h` 的功能分析。

**文件功能总览**

`v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h` 是 V8 JavaScript 引擎中 Liftoff 编译器的 ARM 架构后端的一部分。它定义了 `LiftoffAssembler` 类的一些内联函数，这些函数负责生成 ARM 汇编代码，用于实现 WebAssembly (Wasm) 的各种操作。  这个文件主要关注 SIMD (Single Instruction, Multiple Data) 相关的操作，以及一些其他的底层操作，例如栈管理和函数调用。

**具体功能分解**

1. **SIMD 指令生成 (大部分函数):**
   - 这个文件中的大部分函数都以 `emit_` 开头，并且对应着 Wasm 的 SIMD 指令。它们负责将 Wasm 的 SIMD 操作（例如，加法、减法、比较、位运算、类型转换等）转换为相应的 ARM Neon 指令。
   - 这些函数操作 `LiftoffRegister`，它代表 Liftoff 编译器中的寄存器。它们通常会调用底层的汇编器接口（例如 `vceq`, `vmvn`, `vand` 等）来生成具体的 ARM 指令。
   - 支持的 SIMD 操作类型包括：
     - **整数 SIMD (i8x16, i16x8, i32x4, i64x2):**  比较（ge_s）、位运算（not, and, or, xor, and_not）、绝对值（abs）、窄化转换（narrowing conversion）、符号/无符号扩展转换。
     - **浮点数 SIMD (f32x4, f64x2):**  比较（eq, ne, lt, le）、融合乘加/减（qfma, qfms）、类型转换。
     - **通用 SIMD (s128):** 常量加载、按位逻辑运算（not, and, or, xor, select, and_not）。
   - 注意，文件中也包含了一些 `f16x8` 相关的 `emit_` 函数，但它们都返回 `false`，这可能意味着当前版本的 Liftoff 编译器对 `f16x8` 的支持尚未完全实现或者在 ARM 架构上不可用。

2. **栈管理:**
   - `StackCheck(Label* ool_code)`:  生成检查栈溢出的代码。如果栈指针超出限制，则跳转到 out-of-line (OOL) 代码处理。
   - `PushRegisters(LiftoffRegList regs)`: 生成将指定的寄存器列表推入栈的代码。
   - `PopRegisters(LiftoffRegList regs)`: 生成从栈中弹出指定寄存器列表的代码。
   - `RecordSpillsInSafepoint(...)`: 记录在安全点需要保存到栈上的寄存器信息。
   - `DropStackSlotsAndRet(uint32_t num_stack_slots)`: 生成弹出指定数量的栈槽并返回的代码。
   - `AllocateStackSlot(Register addr, uint32_t size)`: 生成分配指定大小栈空间并将栈顶地址写入寄存器的代码。
   - `DeallocateStackSlot(uint32_t size)`: 生成释放指定大小栈空间的代码。
   - `LiftoffStackSlots::Construct(int param_slots)`:  用于在函数入口构建栈帧，将参数从寄存器或之前的栈帧移动到当前函数的栈帧中。

3. **函数调用:**
   - `CallCWithStackBuffer(...)`:  生成调用 C 函数的代码，参数通过栈传递。
   - `CallC(const std::initializer_list<VarState>& args, ExternalReference ext_ref)`: 生成调用 C 函数的代码，参数通过寄存器和栈传递。
   - `CallNativeWasmCode(Address addr)`: 生成直接调用本地 WebAssembly 代码的代码。
   - `TailCallNativeWasmCode(Address addr)`: 生成尾调用本地 WebAssembly 代码的代码。
   - `CallIndirect(...)`: 生成间接调用的代码。
   - `TailCallIndirect(Register target)`: 生成尾调用的代码。
   - `CallBuiltin(Builtin builtin)`: 生成调用内置函数的代码。

4. **常量加载:**
   - `emit_s128_const(LiftoffRegister dst, const uint8_t imms[16])`:  生成将 128 位常量加载到 SIMD 寄存器的代码。

5. **条件设置:**
   - `emit_set_if_nan(Register dst, DoubleRegister src, ValueKind kind)`: 如果源浮点数是 NaN，则设置目标寄存器为非零值。
   - `emit_s128_set_if_nan(...)`:  如果 SIMD 向量中的任何元素是 NaN，则设置目标寄存器为非零值。

6. **其他操作:**
   - `AssertUnreachable(AbortReason reason)`: 生成断言不可达的代码。
   - `MaybeOSR()`:  可能是与 On-Stack Replacement (OSR) 相关的占位符或空操作。

**关于 .tq 结尾**

根据描述，如果 `v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h` 以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。由于当前文件以 `.h` 结尾，所以它是一个 C++ 头文件，包含了 C++ 代码。

**与 JavaScript 的关系 (SIMD 部分)**

这个文件中的 SIMD 指令生成功能直接对应于 JavaScript 中的 [WebAssembly SIMD API](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/WebAssembly/SIMD)。当 JavaScript 代码调用 Wasm 的 SIMD 功能时，V8 的 Liftoff 编译器会使用这里定义的函数来生成底层的 ARM Neon 指令。

**JavaScript 示例**

```javascript
// 假设有一个编译好的 WebAssembly 模块实例，其中包含 SIMD 指令

const wasmBytes = new Uint8Array([
  // ... WebAssembly 字节码，包含 SIMD 指令 ...
]);

WebAssembly.instantiate(wasmBytes)
  .then(result => {
    const wasmInstance = result.instance;

    // 假设 Wasm 模块导出了一个接受两个 i32x4 参数并返回 i32x4 的函数
    const addI32x4 = wasmInstance.exports.add_i32x4;

    // 创建 SIMD.i32x4 类型的值
    const a = SIMD.i32x4(1, 2, 3, 4);
    const b = SIMD.i32x4(5, 6, 7, 8);

    // 调用 Wasm 函数
    const result = addI32x4(a, b);

    console.log(result); // 输出类似 SIMD.i32x4(6, 8, 10, 12)
  });
```

在这个例子中，当 `addI32x4(a, b)` 被执行时，如果 Liftoff 编译器负责编译该 Wasm 函数，那么 `v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h` 中类似 `emit_i32x4_add` 的函数会被调用，生成 ARM Neon 指令来执行向量加法。

**代码逻辑推理 (以 `emit_i32x4_eq` 为例)**

```c++
void LiftoffAssembler::emit_i32x4_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  vceq(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
       liftoff::GetSimd128Register(rhs));
}
```

**假设输入:**
- `dst`: LiftoffRegister，假设代表 VFP 寄存器 `q0`
- `lhs`: LiftoffRegister，假设代表 VFP 寄存器 `q1`，其值为 `[1, 2, 3, 4]` (作为 i32x4)
- `rhs`: LiftoffRegister，假设代表 VFP 寄存器 `q2`，其值为 `[1, 5, 3, 7]` (作为 i32x4)

**代码逻辑:**
1. `liftoff::GetSimd128Register(dst)` 获取 `dst` 对应的 ARM Neon 寄存器 (例如 `q0`)。
2. `liftoff::GetSimd128Register(lhs)` 获取 `lhs` 对应的 ARM Neon 寄存器 (例如 `q1`)。
3. `liftoff::GetSimd128Register(rhs)` 获取 `rhs` 对应的 ARM Neon 寄存器 (例如 `q2`)。
4. `vceq(q0, q1, q2)` 生成 ARM Neon 的 `vceq` 指令。`vceq` (Vector Compare Equal)  比较 `q1` 和 `q2` 中对应的 32 位整数元素，如果相等，则在 `q0` 中对应的位置写入全 1，否则写入全 0。

**输出 (生成的 ARM 指令效果):**
- 执行 `vceq q0, q1, q2` 后，`q0` 的值将是 `[0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0x00000000]`。  (`0xFFFFFFFF` 代表真，`0x00000000` 代表假)

**用户常见的编程错误 (与 SIMD 相关)**

1. **类型不匹配:**  尝试对不兼容的 SIMD 类型进行操作。例如，将 `f32x4` 向量与 `i32x4` 向量直接相加，如果没有进行正确的类型转换。

   ```javascript
   // 错误的示例 (假设 Wasm 导出了这些函数)
   const floats = SIMD.float32x4(1.0, 2.0, 3.0, 4.0);
   const ints = SIMD.int32x4(1, 2, 3, 4);

   // 假设 Wasm 中有一个期望两个 i32x4 的函数
   // wasmInstance.exports.process_ints(floats, ints); // 这将导致类型错误
   ```

2. **错误的 Lane 访问:**  在访问或替换 SIMD 向量中的特定元素（lane）时，使用了超出范围的索引。

   ```javascript
   const vec = SIMD.int32x4(1, 2, 3, 4);
   // vec.extractLane(4); // 错误：索引 4 超出范围 (0-3)
   ```

3. **未对齐的数据访问 (在某些架构上):** 虽然 ARM Neon 通常对未对齐访问有较好的支持，但在某些情况下，尤其是在手动编写汇编代码或进行底层操作时，未对齐的数据访问可能会导致性能下降或错误。

4. **对 NaN 的处理不当:**  在浮点 SIMD 运算中，NaN (Not a Number) 的传播和比较需要特别注意。例如，与 NaN 比较的结果通常为 false。

   ```javascript
   const nanVec = SIMD.float32x4(NaN, 2.0, 3.0, 4.0);
   const otherVec = SIMD.float32x4(1.0, 2.0, 3.0, 4.0);

   // SIMD.float32x4.equal(nanVec, otherVec); // 结果将是包含 false 的向量
   ```

**第 6 部分归纳总结**

作为第 6 部分（共 6 部分），这个代码片段主要集中在 `LiftoffAssembler` 类的 SIMD 操作实现，特别是针对 ARM 架构。它定义了如何将 WebAssembly 的 SIMD 指令转换为底层的 ARM Neon 指令。此外，它还涵盖了一些其他的底层操作，例如栈管理和特定的条件设置。结合之前的几个部分，这个文件为 Liftoff 编译器在 ARM 架构上生成高效的 WebAssembly 代码提供了关键的基础设施。  整个 `liftoff-assembler-arm-inl.h` 文件是 Liftoff 编译器在 ARM 架构上实现 WebAssembly 功能的核心组成部分之一。

Prompt: 
```
这是目录为v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能

"""
r::emit_i64x2_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  I64x2GeS(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
           liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_f32x4_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  vceq(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
       liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_f32x4_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  vceq(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
       liftoff::GetSimd128Register(rhs));
  vmvn(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(dst));
}

void LiftoffAssembler::emit_f32x4_lt(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  vcgt(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(rhs),
       liftoff::GetSimd128Register(lhs));
}

void LiftoffAssembler::emit_f32x4_le(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  vcge(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(rhs),
       liftoff::GetSimd128Register(lhs));
}

void LiftoffAssembler::emit_f64x2_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::F64x2Compare(this, dst, lhs, rhs, eq);
}

void LiftoffAssembler::emit_f64x2_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::F64x2Compare(this, dst, lhs, rhs, ne);
}

void LiftoffAssembler::emit_f64x2_lt(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::F64x2Compare(this, dst, lhs, rhs, lt);
}

void LiftoffAssembler::emit_f64x2_le(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::F64x2Compare(this, dst, lhs, rhs, le);
}

void LiftoffAssembler::emit_s128_const(LiftoffRegister dst,
                                       const uint8_t imms[16]) {
  uint64_t vals[2];
  memcpy(vals, imms, sizeof(vals));
  vmov(dst.low_fp(), base::Double(vals[0]));
  vmov(dst.high_fp(), base::Double(vals[1]));
}

void LiftoffAssembler::emit_s128_not(LiftoffRegister dst, LiftoffRegister src) {
  vmvn(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_s128_and(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  vand(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
       liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_s128_or(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  vorr(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
       liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_s128_xor(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  veor(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
       liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_s128_select(LiftoffRegister dst,
                                        LiftoffRegister src1,
                                        LiftoffRegister src2,
                                        LiftoffRegister mask) {
  if (dst != mask) {
    vmov(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(mask));
  }
  vbsl(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(src1),
       liftoff::GetSimd128Register(src2));
}

void LiftoffAssembler::emit_i32x4_sconvert_f32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  vcvt_s32_f32(liftoff::GetSimd128Register(dst),
               liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_i32x4_uconvert_f32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  vcvt_u32_f32(liftoff::GetSimd128Register(dst),
               liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_f32x4_sconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  vcvt_f32_s32(liftoff::GetSimd128Register(dst),
               liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_f32x4_uconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  vcvt_f32_u32(liftoff::GetSimd128Register(dst),
               liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_f32x4_demote_f64x2_zero(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  LowDwVfpRegister dst_d = LowDwVfpRegister::from_code(dst.low_fp().code());
  vcvt_f32_f64(dst_d.low(), src.low_fp());
  vcvt_f32_f64(dst_d.high(), src.high_fp());
  vmov(dst.high_fp(), 0);
}

void LiftoffAssembler::emit_i8x16_sconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  liftoff::S128NarrowOp(this, NeonS8, NeonS8, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i8x16_uconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  liftoff::S128NarrowOp(this, NeonU8, NeonS8, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_sconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  liftoff::S128NarrowOp(this, NeonS16, NeonS16, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_uconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  liftoff::S128NarrowOp(this, NeonU16, NeonS16, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_sconvert_i8x16_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  vmovl(NeonS8, liftoff::GetSimd128Register(dst), src.low_fp());
}

void LiftoffAssembler::emit_i16x8_sconvert_i8x16_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  vmovl(NeonS8, liftoff::GetSimd128Register(dst), src.high_fp());
}

void LiftoffAssembler::emit_i16x8_uconvert_i8x16_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  vmovl(NeonU8, liftoff::GetSimd128Register(dst), src.low_fp());
}

void LiftoffAssembler::emit_i16x8_uconvert_i8x16_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  vmovl(NeonU8, liftoff::GetSimd128Register(dst), src.high_fp());
}

void LiftoffAssembler::emit_i32x4_sconvert_i16x8_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  vmovl(NeonS16, liftoff::GetSimd128Register(dst), src.low_fp());
}

void LiftoffAssembler::emit_i32x4_sconvert_i16x8_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  vmovl(NeonS16, liftoff::GetSimd128Register(dst), src.high_fp());
}

void LiftoffAssembler::emit_i32x4_uconvert_i16x8_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  vmovl(NeonU16, liftoff::GetSimd128Register(dst), src.low_fp());
}

void LiftoffAssembler::emit_i32x4_uconvert_i16x8_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  vmovl(NeonU16, liftoff::GetSimd128Register(dst), src.high_fp());
}

void LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_s_zero(LiftoffRegister dst,
                                                         LiftoffRegister src) {
  LowDwVfpRegister dst_d = LowDwVfpRegister::from_code(dst.low_fp().code());
  vcvt_s32_f64(dst_d.low(), src.low_fp());
  vcvt_s32_f64(dst_d.high(), src.high_fp());
  vmov(dst.high_fp(), 0);
}

void LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_u_zero(LiftoffRegister dst,
                                                         LiftoffRegister src) {
  LowDwVfpRegister dst_d = LowDwVfpRegister::from_code(dst.low_fp().code());
  vcvt_u32_f64(dst_d.low(), src.low_fp());
  vcvt_u32_f64(dst_d.high(), src.high_fp());
  vmov(dst.high_fp(), 0);
}

void LiftoffAssembler::emit_s128_and_not(LiftoffRegister dst,
                                         LiftoffRegister lhs,
                                         LiftoffRegister rhs) {
  vbic(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
       liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_i8x16_rounding_average_u(LiftoffRegister dst,
                                                     LiftoffRegister lhs,
                                                     LiftoffRegister rhs) {
  vrhadd(NeonU8, liftoff::GetSimd128Register(dst),
         liftoff::GetSimd128Register(lhs), liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_i16x8_rounding_average_u(LiftoffRegister dst,
                                                     LiftoffRegister lhs,
                                                     LiftoffRegister rhs) {
  vrhadd(NeonU16, liftoff::GetSimd128Register(dst),
         liftoff::GetSimd128Register(lhs), liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_i8x16_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  vabs(Neon8, liftoff::GetSimd128Register(dst),
       liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_i16x8_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  vabs(Neon16, liftoff::GetSimd128Register(dst),
       liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_i32x4_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  vabs(Neon32, liftoff::GetSimd128Register(dst),
       liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_i64x2_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  I64x2Abs(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_f32x4_qfma(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  UseScratchRegisterScope temps(this);
  Simd128Register scratch =
      dst == src3 ? temps.AcquireQ() : liftoff::GetSimd128Register(dst);
  vmul(scratch, liftoff::GetSimd128Register(src1),
       liftoff::GetSimd128Register(src2));
  vadd(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(src3),
       scratch);
}

void LiftoffAssembler::emit_f32x4_qfms(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  UseScratchRegisterScope temps(this);
  Simd128Register scratch =
      dst == src3 ? temps.AcquireQ() : liftoff::GetSimd128Register(dst);
  vmul(scratch, liftoff::GetSimd128Register(src1),
       liftoff::GetSimd128Register(src2));
  vsub(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(src3),
       scratch);
}

void LiftoffAssembler::emit_f64x2_qfma(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  UseScratchRegisterScope temps(this);
  Simd128Register scratch =
      dst == src3 ? temps.AcquireQ() : liftoff::GetSimd128Register(dst);
  vmul(scratch.low(), src1.low_fp(), src2.low_fp());
  vmul(scratch.high(), src1.high_fp(), src2.high_fp());
  vadd(dst.low_fp(), src3.low_fp(), scratch.low());
  vadd(dst.high_fp(), src3.high_fp(), scratch.high());
}

void LiftoffAssembler::emit_f64x2_qfms(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  UseScratchRegisterScope temps(this);
  Simd128Register scratch =
      dst == src3 ? temps.AcquireQ() : liftoff::GetSimd128Register(dst);
  vmul(scratch.low(), src1.low_fp(), src2.low_fp());
  vmul(scratch.high(), src1.high_fp(), src2.high_fp());
  vsub(dst.low_fp(), src3.low_fp(), scratch.low());
  vsub(dst.high_fp(), src3.high_fp(), scratch.high());
}

bool LiftoffAssembler::emit_f16x8_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_sqrt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_ceil(LiftoffRegister dst,
                                       LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_floor(LiftoffRegister dst,
                                        LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_trunc(LiftoffRegister dst,
                                        LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_nearest_int(LiftoffRegister dst,
                                              LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_lt(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_le(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_div(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_min(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_max(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_pmin(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_pmax(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_i16x8_sconvert_f16x8(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_i16x8_uconvert_f16x8(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_sconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_uconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_demote_f32x4_zero(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f32x4_promote_low_f16x8(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_demote_f64x2_zero(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_qfma(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_qfms(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  return false;
}

bool LiftoffAssembler::supports_f16_mem_access() { return false; }

void LiftoffAssembler::StackCheck(Label* ool_code) {
  UseScratchRegisterScope temps(this);
  Register limit_address = temps.Acquire();
  LoadStackLimit(limit_address, StackLimitKind::kInterruptStackLimit);
  cmp(sp, limit_address);
  b(ool_code, ls);
}

void LiftoffAssembler::AssertUnreachable(AbortReason reason) {
  // Asserts unreachable within the wasm code.
  MacroAssembler::AssertUnreachable(reason);
}

void LiftoffAssembler::PushRegisters(LiftoffRegList regs) {
  RegList core_regs = regs.GetGpList();
  if (!core_regs.is_empty()) {
    stm(db_w, sp, core_regs);
  }
  LiftoffRegList fp_regs = regs & kFpCacheRegList;
  while (!fp_regs.is_empty()) {
    LiftoffRegister reg = fp_regs.GetFirstRegSet();
    DoubleRegister first = reg.fp();
    DoubleRegister last = first;
    fp_regs.clear(reg);
    while (!fp_regs.is_empty()) {
      LiftoffRegister reg = fp_regs.GetFirstRegSet();
      int code = reg.fp().code();
      // vstm can not push more than 16 registers. We have to make sure the
      // condition is met.
      if ((code != last.code() + 1) || ((code - first.code() + 1) > 16)) break;
      last = reg.fp();
      fp_regs.clear(reg);
    }
    vstm(db_w, sp, first, last);
  }
}

void LiftoffAssembler::PopRegisters(LiftoffRegList regs) {
  LiftoffRegList fp_regs = regs & kFpCacheRegList;
  while (!fp_regs.is_empty()) {
    LiftoffRegister reg = fp_regs.GetLastRegSet();
    DoubleRegister last = reg.fp();
    DoubleRegister first = last;
    fp_regs.clear(reg);
    while (!fp_regs.is_empty()) {
      LiftoffRegister reg = fp_regs.GetLastRegSet();
      int code = reg.fp().code();
      if ((code != first.code() - 1) || ((last.code() - code + 1) > 16)) break;
      first = reg.fp();
      fp_regs.clear(reg);
    }
    vldm(ia_w, sp, first, last);
  }
  RegList core_regs = regs.GetGpList();
  if (!core_regs.is_empty()) {
    ldm(ia_w, sp, core_regs);
  }
}

void LiftoffAssembler::RecordSpillsInSafepoint(
    SafepointTableBuilder::Safepoint& safepoint, LiftoffRegList all_spills,
    LiftoffRegList ref_spills, int spill_offset) {
  LiftoffRegList fp_spills = all_spills & kFpCacheRegList;
  int spill_space_size = fp_spills.GetNumRegsSet() * kSimd128Size;
  LiftoffRegList gp_spills = all_spills & kGpCacheRegList;
  while (!gp_spills.is_empty()) {
    LiftoffRegister reg = gp_spills.GetLastRegSet();
    if (ref_spills.has(reg)) {
      safepoint.DefineTaggedStackSlot(spill_offset);
    }
    gp_spills.clear(reg);
    ++spill_offset;
    spill_space_size += kSystemPointerSize;
  }
  // Record the number of additional spill slots.
  RecordOolSpillSpaceSize(spill_space_size);
}

void LiftoffAssembler::DropStackSlotsAndRet(uint32_t num_stack_slots) {
  Drop(num_stack_slots);
  Ret();
}

void LiftoffAssembler::CallCWithStackBuffer(
    const std::initializer_list<VarState> args, const LiftoffRegister* rets,
    ValueKind return_kind, ValueKind out_argument_kind, int stack_bytes,
    ExternalReference ext_ref) {
  // Arguments are passed by pushing them all to the stack and then passing
  // a pointer to them.
  DCHECK(IsAligned(stack_bytes, kSystemPointerSize));
  // Reserve space in the stack.
  AllocateStackSpace(stack_bytes);

  int arg_offset = 0;
  for (const VarState& arg : args) {
    MemOperand dst{sp, arg_offset};
    if (arg.is_reg()) {
      liftoff::Store(this, arg.reg(), dst, arg.kind());
    } else if (arg.is_const()) {
      DCHECK_EQ(kI32, arg.kind());
      UseScratchRegisterScope temps(this);
      Register src = temps.Acquire();
      mov(src, Operand(arg.i32_const()));
      str(src, dst);
    } else {
      // Stack to stack move.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      MemOperand src = liftoff::GetStackSlot(arg.offset());
      int words = SlotSizeForType(arg.kind()) / kSystemPointerSize;
      do {
        ldr(scratch, src);
        str(scratch, dst);
        src.set_offset(src.offset() + kSystemPointerSize);
        dst.set_offset(dst.offset() + kSystemPointerSize);
      } while (--words > 0);
    }
    arg_offset += value_kind_size(arg.kind());
  }
  DCHECK_LE(arg_offset, stack_bytes);

  // Pass a pointer to the buffer with the arguments to the C function.
  mov(r0, sp);

  // Now call the C function.
  constexpr int kNumCCallArgs = 1;
  PrepareCallCFunction(kNumCCallArgs);
  CallCFunction(ext_ref, kNumCCallArgs);

  // Move return value to the right register.
  const LiftoffRegister* result_reg = rets;
  if (return_kind != kVoid) {
    constexpr Register kReturnReg = r0;
    if (kReturnReg != rets->gp()) {
      Move(*rets, LiftoffRegister(kReturnReg), return_kind);
    }
    result_reg++;
  }

  // Load potential output value from the buffer on the stack.
  if (out_argument_kind != kVoid) {
    liftoff::Load(this, *result_reg, MemOperand{sp}, out_argument_kind);
  }
  add(sp, sp, Operand(stack_bytes));
}

void LiftoffAssembler::CallC(const std::initializer_list<VarState> args,
                             ExternalReference ext_ref) {
  // First, prepare the stack for the C call.
  int num_args = static_cast<int>(args.size());
  PrepareCallCFunction(num_args);

  // Then execute the parallel register move and also move values to parameter
  // stack slots.
  int reg_args = 0;
  int stack_args = 0;
  ParallelMove parallel_move{this};
  for (const VarState& arg : args) {
    if (needs_gp_reg_pair(arg.kind())) {
      // All i64 arguments (currently) fully fit in the register parameters.
      DCHECK_LE(reg_args + 2, arraysize(kCArgRegs));
      parallel_move.LoadIntoRegister(
          LiftoffRegister::ForPair(kCArgRegs[reg_args],
                                   kCArgRegs[reg_args + 1]),
          arg);
      reg_args += 2;
      continue;
    }
    if (reg_args < int{arraysize(kCArgRegs)}) {
      parallel_move.LoadIntoRegister(LiftoffRegister{kCArgRegs[reg_args]}, arg);
      ++reg_args;
      continue;
    }
    MemOperand dst{sp, stack_args * kSystemPointerSize};
    ++stack_args;
    if (arg.is_reg()) {
      liftoff::Store(this, arg.reg(), dst, arg.kind());
      continue;
    }
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    if (arg.is_const()) {
      DCHECK_EQ(kI32, arg.kind());
      mov(scratch, Operand(arg.i32_const()));
      str(scratch, dst);
    } else {
      // Stack to stack move.
      MemOperand src = liftoff::GetStackSlot(arg.offset());
      ldr(scratch, src);
      str(scratch, dst);
    }
  }
  parallel_move.Execute();

  // Now call the C function.
  CallCFunction(ext_ref, num_args);
}

void LiftoffAssembler::CallNativeWasmCode(Address addr) {
  Call(addr, RelocInfo::WASM_CALL);
}

void LiftoffAssembler::TailCallNativeWasmCode(Address addr) {
  Jump(addr, RelocInfo::WASM_CALL);
}

void LiftoffAssembler::CallIndirect(const ValueKindSig* sig,
                                    compiler::CallDescriptor* call_descriptor,
                                    Register target) {
  DCHECK(target != no_reg);
  CallWasmCodePointer(target);
}

void LiftoffAssembler::TailCallIndirect(Register target) {
  DCHECK(target != no_reg);
  CallWasmCodePointer(target, CallJumpMode::kTailCall);
}

void LiftoffAssembler::CallBuiltin(Builtin builtin) {
  // A direct call to a builtin. Just encode the builtin index. This will be
  // patched at relocation.
  Call(static_cast<Address>(builtin), RelocInfo::WASM_STUB_CALL);
}

void LiftoffAssembler::AllocateStackSlot(Register addr, uint32_t size) {
  AllocateStackSpace(size);
  mov(addr, sp);
}

void LiftoffAssembler::DeallocateStackSlot(uint32_t size) {
  add(sp, sp, Operand(size));
}

void LiftoffAssembler::MaybeOSR() {}

void LiftoffAssembler::emit_set_if_nan(Register dst, DoubleRegister src,
                                       ValueKind kind) {
  if (kind == kF32) {
    FloatRegister src_f = liftoff::GetFloatRegister(src);
    VFPCompareAndSetFlags(src_f, src_f);
  } else {
    DCHECK_EQ(kind, kF64);
    VFPCompareAndSetFlags(src, src);
  }

  // Store a non-zero value if src is NaN.
  str(dst, MemOperand(dst), ne);  // x != x iff isnan(x)
}

void LiftoffAssembler::emit_s128_set_if_nan(Register dst, LiftoffRegister src,
                                            Register tmp_gp,
                                            LiftoffRegister tmp_s128,
                                            ValueKind lane_kind) {
  QwNeonRegister src_q = liftoff::GetSimd128Register(src);
  QwNeonRegister tmp_q = liftoff::GetSimd128Register(tmp_s128);
  if (lane_kind == kF32) {
    vpadd(tmp_q.low(), src_q.low(), src_q.high());
    LowDwVfpRegister tmp_d =
        LowDwVfpRegister::from_code(tmp_s128.low_fp().code());
    vadd(tmp_d.low(), tmp_d.low(), tmp_d.high());
  } else {
    DCHECK_EQ(lane_kind, kF64);
    vadd(tmp_q.low(), src_q.low(), src_q.high());
  }
  emit_set_if_nan(dst, tmp_q.low(), lane_kind);
}

void LiftoffStackSlots::Construct(int param_slots) {
  DCHECK_LT(0, slots_.size());
  SortInPushOrder();
  int last_stack_slot = param_slots;
  for (auto& slot : slots_) {
    const int stack_slot = slot.dst_slot_;
    int stack_decrement = (last_stack_slot - stack_slot) * kSystemPointerSize;
    DCHECK_LT(0, stack_decrement);
    last_stack_slot = stack_slot;
    const LiftoffAssembler::VarState& src = slot.src_;
    switch (src.loc()) {
      case LiftoffAssembler::VarState::kStack: {
        switch (src.kind()) {
          // i32 and i64 can be treated as similar cases, i64 being previously
          // split into two i32 registers
          case kI32:
          case kI64:
          case kF32:
          case kRef:
          case kRefNull: {
            asm_->AllocateStackSpace(stack_decrement - kSystemPointerSize);
            UseScratchRegisterScope temps(asm_);
            Register scratch = temps.Acquire();
            asm_->ldr(scratch,
                      liftoff::GetHalfStackSlot(slot.src_offset_, slot.half_));
            asm_->Push(scratch);
          } break;
          case kF64: {
            asm_->AllocateStackSpace(stack_decrement - kDoubleSize);
            UseScratchRegisterScope temps(asm_);
            DwVfpRegister scratch = temps.AcquireD();
            asm_->vldr(scratch, liftoff::GetStackSlot(slot.src_offset_));
            asm_->vpush(scratch);
          } break;
          case kS128: {
            asm_->AllocateStackSpace(stack_decrement - kSimd128Size);
            MemOperand mem_op = liftoff::GetStackSlot(slot.src_offset_);
            UseScratchRegisterScope temps(asm_);
            Register addr = liftoff::CalculateActualAddress(
                asm_, &temps, mem_op.rn(), no_reg, mem_op.offset());
            QwNeonRegister scratch = temps.AcquireQ();
            asm_->vld1(Neon8, NeonListOperand(scratch), NeonMemOperand(addr));
            asm_->vpush(scratch);
            break;
          }
          default:
            UNREACHABLE();
        }
        break;
      }
      case LiftoffAssembler::VarState::kRegister: {
        int pushed_bytes = SlotSizeInBytes(slot);
        asm_->AllocateStackSpace(stack_decrement - pushed_bytes);
        switch (src.kind()) {
          case kI64: {
            LiftoffRegister reg =
                slot.half_ == kLowWord ? src.reg().low() : src.reg().high();
            asm_->push(reg.gp());
            break;
          }
          case kI32:
          case kRef:
          case kRefNull:
          case kRtt:
            asm_->push(src.reg().gp());
            break;
          case kF32:
            asm_->vpush(liftoff::GetFloatRegister(src.reg().fp()));
            break;
          case kF64:
            asm_->vpush(src.reg().fp());
            break;
          case kS128:
            asm_->vpush(liftoff::GetSimd128Register(src.reg()));
            break;
          default:
            UNREACHABLE();
        }
        break;
      }
      case LiftoffAssembler::VarState::kIntConst: {
        asm_->AllocateStackSpace(stack_decrement - kSystemPointerSize);
        DCHECK(src.kind() == kI32 || src.kind() == kI64);
        UseScratchRegisterScope temps(asm_);
        Register scratch = temps.Acquire();
        // The high word is the sign extension of the low word.
        asm_->mov(scratch,
                  Operand(slot.half_ == kLowWord ? src.i32_const()
                                                 : src.i32_const() >> 31));
        asm_->push(scratch);
        break;
      }
    }
  }
}

}  // namespace v8::internal::wasm

#endif  // V8_WASM_BASELINE_ARM_LIFTOFF_ASSEMBLER_ARM_INL_H_

"""


```