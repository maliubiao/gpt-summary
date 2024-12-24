Response: The user wants a summary of the C++ code in `v8/src/wasm/baseline/liftoff-compiler.cc`.
This is part 4 of a 7-part file. The code snippet seems to be handling WebAssembly SIMD and atomic instructions.

Here's a breakdown of the thought process:

1. **Identify the core functionality:** The code heavily features `case wasm::kExpr...` statements, which strongly suggests it's processing different WebAssembly opcodes. The names of the opcodes and the associated `LiftoffAssembler` methods (e.g., `emit_i16x8_add`, `emit_f32x4_abs`) clearly point to SIMD (Single Instruction, Multiple Data) operations. The later part of the snippet deals with atomic operations.

2. **Recognize the pattern:** The code uses templates (`EmitUnOp`, `EmitBinOp`, `EmitSimdShiftOp`, etc.) to generate assembly code for different kinds of operations with varying input and output types. This is a common pattern in compilers to reduce code duplication.

3. **SIMD instruction handling:**  Focus on the SIMD-related opcodes. Note the different data types (i8x16, i16x8, i32x4, f32x4, f64x2, f16x8) and the variety of operations (arithmetic, logical, shifts, comparisons, conversions). The presence of `EmitSimdFloatRoundingOpWithCFallback` and `EmitSimdFloatBinOpWithCFallback` indicates that some operations might require a C++ fallback implementation if the hardware doesn't directly support them.

4. **Atomic instruction handling:** Identify the `AtomicStoreMem`, `AtomicLoadMem`, `AtomicBinop`, `AtomicCompareExchange`, `AtomicWait`, and `AtomicNotify` functions. These strongly suggest support for WebAssembly's atomic memory access features for multithreading.

5. **Connection to JavaScript:**  WebAssembly runs within a JavaScript environment. The SIMD instructions provided here are directly accessible and usable from JavaScript through the WebAssembly API. The atomic operations enable shared memory concurrency, which is also relevant in JavaScript environments with shared array buffers and atomics.

6. **Construct the summary:** Combine the identified functionalities into a concise description. Emphasize the role of the code in translating WebAssembly SIMD and atomic operations into machine code.

7. **Provide JavaScript examples:**  Illustrate how the SIMD and atomic operations handled in the C++ code are used in JavaScript. For SIMD, show basic arithmetic operations on SIMD types. For atomics, demonstrate a simple atomic increment using `Atomics.add`.

8. **Address the "part 4 of 7" instruction:** Acknowledge the context and infer that the other parts likely handle other aspects of the Liftoff compiler.

9. **Review and refine:** Ensure the summary is clear, accurate, and addresses all parts of the prompt. Check for any technical jargon that needs clarification. For example, briefly explain what SIMD is.
这个C++源代码文件是V8 JavaScript引擎中Liftoff编译器的**一部分**，专门负责为WebAssembly的**SIMD (Single Instruction, Multiple Data) 向量指令**和**原子指令**生成机器码。

**具体功能归纳:**

* **SIMD 指令编译:**  该部分代码定义了如何将各种WebAssembly的SIMD操作码 (例如 `i8x16.add`, `f32x4.mul`, `f64x2.sqrt` 等) 转换成底层的机器指令。它针对不同的SIMD类型 (例如 `i8x16`, `i16x8`, `i32x4`, `f32x4`, `f64x2`, `f16x8`) 和不同的操作 (加法、减法、乘法、除法、取反、绝对值、位运算、移位、类型转换等) 提供了相应的编译逻辑。
* **原子指令编译:**  该部分代码也处理WebAssembly的原子操作指令 (例如 `atomic.load`, `atomic.store`, `atomic.add`, `atomic.compare_exchange`, `atomic.wait`, `atomic.notify`)。这些指令用于在共享内存的多线程环境中进行安全的并发操作。
* **指令发射:**  它使用 `LiftoffAssembler` 类来实际生成目标架构的机器码指令。例如，`&LiftoffAssembler::emit_i16x8_add` 就指向了 `LiftoffAssembler` 类中用于发射 `i16x8` 加法指令的方法。
* **C++ Fallback:** 对于某些SIMD浮点运算 (例如 `f16x8` 的一些操作)，如果当前硬件架构没有直接支持的指令，它会提供C++的后备 (fallback) 实现。
* **与 JavaScript 的桥梁:**  该文件是V8引擎的一部分，负责将WebAssembly代码编译成可以在JavaScript环境中执行的机器码。SIMD和原子指令是WebAssembly提供的高级功能，可以直接被JavaScript调用。

**与 JavaScript 的关系及举例说明:**

WebAssembly 的 SIMD 和原子指令可以直接在 JavaScript 中使用。该文件编译生成的机器码使得这些操作在V8引擎中能够高效执行。

**SIMD 的 JavaScript 示例:**

```javascript
const buffer = new ArrayBuffer(16);
const i8x16 = new Int8x16Array(buffer);
i8x16[0] = 10;
i8x16[1] = 20;
// ...

const simdValue1 = SIMD.int8x16(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
const simdValue2 = SIMD.int8x16(10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160);
const sum = SIMD.int8x16.add(simdValue1, simdValue2);

console.log(SIMD.int8x16.extractLane(sum, 0)); // 输出 11
console.log(SIMD.int8x16.extractLane(sum, 1)); // 输出 22
// ...
```

在这个例子中，`SIMD.int8x16.add` 操作对应了 `liftoff-compiler.cc` 中处理 `wasm::kExprI8x16Add` 的逻辑，该文件会生成相应的机器码来执行这个加法操作。

**原子操作的 JavaScript 示例:**

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const ia = new Int32Array(sab);

Atomics.add(ia, 0, 5);
console.log(ia[0]); // 输出 5

Atomics.compareExchange(ia, 0, 5, 10);
console.log(ia[0]); // 输出 10 (如果当前值为 5，则更新为 10)
```

`Atomics.add` 和 `Atomics.compareExchange` 等操作对应了 `liftoff-compiler.cc` 中处理诸如 `wasm::kExprI32AtomicAdd` 和 `wasm::kExprI32AtomicCompareExchange` 等指令的逻辑。

**总结:**

作为第4部分，这个文件专注于 WebAssembly 中与性能密切相关的 SIMD 向量指令和原子指令的编译，使得 JavaScript 能够利用这些底层硬件加速功能，提高 WebAssembly 代码的执行效率，尤其是在处理多媒体、图形计算和并发任务时。

Prompt: 
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共7部分，请归纳一下它的功能

"""
inOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_extmul_high_i8x16_s);
      case wasm::kExprI16x8ExtMulHighI8x16U:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_extmul_high_i8x16_u);
      case wasm::kExprI16x8Q15MulRSatS:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_q15mulr_sat_s);
      case wasm::kExprI32x4Neg:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_neg);
      case wasm::kExprI32x4AllTrue:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i32x4_alltrue);
      case wasm::kExprI32x4BitMask:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i32x4_bitmask);
      case wasm::kExprI32x4Shl:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i32x4_shl,
                               &LiftoffAssembler::emit_i32x4_shli);
      case wasm::kExprI32x4ShrS:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i32x4_shr_s,
                               &LiftoffAssembler::emit_i32x4_shri_s);
      case wasm::kExprI32x4ShrU:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i32x4_shr_u,
                               &LiftoffAssembler::emit_i32x4_shri_u);
      case wasm::kExprI32x4Add:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_add);
      case wasm::kExprI32x4Sub:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_sub);
      case wasm::kExprI32x4Mul:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_mul);
      case wasm::kExprI32x4MinS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_min_s);
      case wasm::kExprI32x4MinU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_min_u);
      case wasm::kExprI32x4MaxS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_max_s);
      case wasm::kExprI32x4MaxU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_max_u);
      case wasm::kExprI32x4DotI16x8S:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_dot_i16x8_s);
      case wasm::kExprI32x4ExtAddPairwiseI16x8S:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_extadd_pairwise_i16x8_s);
      case wasm::kExprI32x4ExtAddPairwiseI16x8U:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_extadd_pairwise_i16x8_u);
      case wasm::kExprI32x4ExtMulLowI16x8S:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_extmul_low_i16x8_s);
      case wasm::kExprI32x4ExtMulLowI16x8U:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_extmul_low_i16x8_u);
      case wasm::kExprI32x4ExtMulHighI16x8S:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_extmul_high_i16x8_s);
      case wasm::kExprI32x4ExtMulHighI16x8U:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_extmul_high_i16x8_u);
      case wasm::kExprI64x2Neg:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_neg);
      case wasm::kExprI64x2AllTrue:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i64x2_alltrue);
      case wasm::kExprI64x2Shl:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i64x2_shl,
                               &LiftoffAssembler::emit_i64x2_shli);
      case wasm::kExprI64x2ShrS:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i64x2_shr_s,
                               &LiftoffAssembler::emit_i64x2_shri_s);
      case wasm::kExprI64x2ShrU:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i64x2_shr_u,
                               &LiftoffAssembler::emit_i64x2_shri_u);
      case wasm::kExprI64x2Add:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_add);
      case wasm::kExprI64x2Sub:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_sub);
      case wasm::kExprI64x2Mul:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_mul);
      case wasm::kExprI64x2ExtMulLowI32x4S:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_extmul_low_i32x4_s);
      case wasm::kExprI64x2ExtMulLowI32x4U:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_extmul_low_i32x4_u);
      case wasm::kExprI64x2ExtMulHighI32x4S:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_extmul_high_i32x4_s);
      case wasm::kExprI64x2ExtMulHighI32x4U:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_extmul_high_i32x4_u);
      case wasm::kExprI64x2BitMask:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i64x2_bitmask);
      case wasm::kExprI64x2SConvertI32x4Low:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_sconvert_i32x4_low);
      case wasm::kExprI64x2SConvertI32x4High:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_sconvert_i32x4_high);
      case wasm::kExprI64x2UConvertI32x4Low:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_uconvert_i32x4_low);
      case wasm::kExprI64x2UConvertI32x4High:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_uconvert_i32x4_high);
      case wasm::kExprF16x8Abs:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_abs,
            &ExternalReference::wasm_f16x8_abs);
      case wasm::kExprF16x8Neg:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_neg,
            &ExternalReference::wasm_f16x8_neg);
      case wasm::kExprF16x8Sqrt:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_sqrt,
            &ExternalReference::wasm_f16x8_sqrt);
      case wasm::kExprF16x8Ceil:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_ceil,
            &ExternalReference::wasm_f16x8_ceil);
      case wasm::kExprF16x8Floor:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_floor,
            ExternalReference::wasm_f16x8_floor);
      case wasm::kExprF16x8Trunc:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_trunc,
            ExternalReference::wasm_f16x8_trunc);
      case wasm::kExprF16x8NearestInt:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_nearest_int,
            ExternalReference::wasm_f16x8_nearest_int);
      case wasm::kExprF16x8Add:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_add,
            ExternalReference::wasm_f16x8_add);
      case wasm::kExprF16x8Sub:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_sub,
            ExternalReference::wasm_f16x8_sub);
      case wasm::kExprF16x8Mul:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_mul,
            ExternalReference::wasm_f16x8_mul);
      case wasm::kExprF16x8Div:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_div,
            ExternalReference::wasm_f16x8_div);
      case wasm::kExprF16x8Min:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_min,
            ExternalReference::wasm_f16x8_min);
      case wasm::kExprF16x8Max:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_max,
            ExternalReference::wasm_f16x8_max);
      case wasm::kExprF16x8Pmin:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_pmin,
            ExternalReference::wasm_f16x8_pmin);
      case wasm::kExprF16x8Pmax:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_pmax,
            ExternalReference::wasm_f16x8_pmax);
      case wasm::kExprF32x4Abs:
        return EmitUnOp<kS128, kS128, kF32>(&LiftoffAssembler::emit_f32x4_abs);
      case wasm::kExprF32x4Neg:
        return EmitUnOp<kS128, kS128, kF32>(&LiftoffAssembler::emit_f32x4_neg);
      case wasm::kExprF32x4Sqrt:
        return EmitUnOp<kS128, kS128, kF32>(&LiftoffAssembler::emit_f32x4_sqrt);
      case wasm::kExprF32x4Ceil:
        return EmitSimdFloatRoundingOpWithCFallback<kF32>(
            &LiftoffAssembler::emit_f32x4_ceil,
            &ExternalReference::wasm_f32x4_ceil);
      case wasm::kExprF32x4Floor:
        return EmitSimdFloatRoundingOpWithCFallback<kF32>(
            &LiftoffAssembler::emit_f32x4_floor,
            ExternalReference::wasm_f32x4_floor);
      case wasm::kExprF32x4Trunc:
        return EmitSimdFloatRoundingOpWithCFallback<kF32>(
            &LiftoffAssembler::emit_f32x4_trunc,
            ExternalReference::wasm_f32x4_trunc);
      case wasm::kExprF32x4NearestInt:
        return EmitSimdFloatRoundingOpWithCFallback<kF32>(
            &LiftoffAssembler::emit_f32x4_nearest_int,
            ExternalReference::wasm_f32x4_nearest_int);
      case wasm::kExprF32x4Add:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_add);
      case wasm::kExprF32x4Sub:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_sub);
      case wasm::kExprF32x4Mul:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_mul);
      case wasm::kExprF32x4Div:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_div);
      case wasm::kExprF32x4Min:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_min);
      case wasm::kExprF32x4Max:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_max);
      case wasm::kExprF32x4Pmin:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_pmin);
      case wasm::kExprF32x4Pmax:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_pmax);
      case wasm::kExprF64x2Abs:
        return EmitUnOp<kS128, kS128, kF64>(&LiftoffAssembler::emit_f64x2_abs);
      case wasm::kExprF64x2Neg:
        return EmitUnOp<kS128, kS128, kF64>(&LiftoffAssembler::emit_f64x2_neg);
      case wasm::kExprF64x2Sqrt:
        return EmitUnOp<kS128, kS128, kF64>(&LiftoffAssembler::emit_f64x2_sqrt);
      case wasm::kExprF64x2Ceil:
        return EmitSimdFloatRoundingOpWithCFallback<kF64>(
            &LiftoffAssembler::emit_f64x2_ceil,
            &ExternalReference::wasm_f64x2_ceil);
      case wasm::kExprF64x2Floor:
        return EmitSimdFloatRoundingOpWithCFallback<kF64>(
            &LiftoffAssembler::emit_f64x2_floor,
            ExternalReference::wasm_f64x2_floor);
      case wasm::kExprF64x2Trunc:
        return EmitSimdFloatRoundingOpWithCFallback<kF64>(
            &LiftoffAssembler::emit_f64x2_trunc,
            ExternalReference::wasm_f64x2_trunc);
      case wasm::kExprF64x2NearestInt:
        return EmitSimdFloatRoundingOpWithCFallback<kF64>(
            &LiftoffAssembler::emit_f64x2_nearest_int,
            ExternalReference::wasm_f64x2_nearest_int);
      case wasm::kExprF64x2Add:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_add);
      case wasm::kExprF64x2Sub:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_sub);
      case wasm::kExprF64x2Mul:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_mul);
      case wasm::kExprF64x2Div:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_div);
      case wasm::kExprF64x2Min:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_min);
      case wasm::kExprF64x2Max:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_max);
      case wasm::kExprF64x2Pmin:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_pmin);
      case wasm::kExprF64x2Pmax:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_pmax);
      case wasm::kExprI32x4SConvertF32x4:
        return EmitUnOp<kS128, kS128, kF32>(
            &LiftoffAssembler::emit_i32x4_sconvert_f32x4);
      case wasm::kExprI32x4UConvertF32x4:
        return EmitUnOp<kS128, kS128, kF32>(
            &LiftoffAssembler::emit_i32x4_uconvert_f32x4);
      case wasm::kExprF32x4SConvertI32x4:
        return EmitUnOp<kS128, kS128, kF32>(
            &LiftoffAssembler::emit_f32x4_sconvert_i32x4);
      case wasm::kExprF32x4UConvertI32x4:
        return EmitUnOp<kS128, kS128, kF32>(
            &LiftoffAssembler::emit_f32x4_uconvert_i32x4);
      case wasm::kExprF32x4PromoteLowF16x8:
        return EmitSimdFloatRoundingOpWithCFallback<kF32>(
            &LiftoffAssembler::emit_f32x4_promote_low_f16x8,
            &ExternalReference::wasm_f32x4_promote_low_f16x8);
      case wasm::kExprF16x8DemoteF32x4Zero:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_demote_f32x4_zero,
            &ExternalReference::wasm_f16x8_demote_f32x4_zero);
      case wasm::kExprF16x8DemoteF64x2Zero:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_demote_f64x2_zero,
            &ExternalReference::wasm_f16x8_demote_f64x2_zero);
      case wasm::kExprI16x8SConvertF16x8:
        return EmitSimdFloatRoundingOpWithCFallback<kI16>(
            &LiftoffAssembler::emit_i16x8_sconvert_f16x8,
            &ExternalReference::wasm_i16x8_sconvert_f16x8);
      case wasm::kExprI16x8UConvertF16x8:
        return EmitSimdFloatRoundingOpWithCFallback<kI16>(
            &LiftoffAssembler::emit_i16x8_uconvert_f16x8,
            &ExternalReference::wasm_i16x8_uconvert_f16x8);
      case wasm::kExprF16x8SConvertI16x8:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_sconvert_i16x8,
            &ExternalReference::wasm_f16x8_sconvert_i16x8);
      case wasm::kExprF16x8UConvertI16x8:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_uconvert_i16x8,
            &ExternalReference::wasm_f16x8_uconvert_i16x8);
      case wasm::kExprI8x16SConvertI16x8:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i8x16_sconvert_i16x8);
      case wasm::kExprI8x16UConvertI16x8:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i8x16_uconvert_i16x8);
      case wasm::kExprI16x8SConvertI32x4:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_sconvert_i32x4);
      case wasm::kExprI16x8UConvertI32x4:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_uconvert_i32x4);
      case wasm::kExprI16x8SConvertI8x16Low:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_sconvert_i8x16_low);
      case wasm::kExprI16x8SConvertI8x16High:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_sconvert_i8x16_high);
      case wasm::kExprI16x8UConvertI8x16Low:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_uconvert_i8x16_low);
      case wasm::kExprI16x8UConvertI8x16High:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_uconvert_i8x16_high);
      case wasm::kExprI32x4SConvertI16x8Low:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_sconvert_i16x8_low);
      case wasm::kExprI32x4SConvertI16x8High:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_sconvert_i16x8_high);
      case wasm::kExprI32x4UConvertI16x8Low:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_uconvert_i16x8_low);
      case wasm::kExprI32x4UConvertI16x8High:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_uconvert_i16x8_high);
      case wasm::kExprS128AndNot:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_s128_and_not);
      case wasm::kExprI8x16RoundingAverageU:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i8x16_rounding_average_u);
      case wasm::kExprI16x8RoundingAverageU:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_rounding_average_u);
      case wasm::kExprI8x16Abs:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_abs);
      case wasm::kExprI16x8Abs:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_abs);
      case wasm::kExprI32x4Abs:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_abs);
      case wasm::kExprI64x2Abs:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_abs);
      case wasm::kExprF64x2ConvertLowI32x4S:
        return EmitUnOp<kS128, kS128, kF64>(
            &LiftoffAssembler::emit_f64x2_convert_low_i32x4_s);
      case wasm::kExprF64x2ConvertLowI32x4U:
        return EmitUnOp<kS128, kS128, kF64>(
            &LiftoffAssembler::emit_f64x2_convert_low_i32x4_u);
      case wasm::kExprF64x2PromoteLowF32x4:
        return EmitUnOp<kS128, kS128, kF64>(
            &LiftoffAssembler::emit_f64x2_promote_low_f32x4);
      case wasm::kExprF32x4DemoteF64x2Zero:
        return EmitUnOp<kS128, kS128, kF32>(
            &LiftoffAssembler::emit_f32x4_demote_f64x2_zero);
      case wasm::kExprI32x4TruncSatF64x2SZero:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_s_zero);
      case wasm::kExprI32x4TruncSatF64x2UZero:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_u_zero);
      case wasm::kExprF16x8Qfma:
        return EmitSimdFmaOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_qfma,
            &ExternalReference::wasm_f16x8_qfma);
      case wasm::kExprF16x8Qfms:
        return EmitSimdFmaOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_qfms,
            &ExternalReference::wasm_f16x8_qfms);
      case wasm::kExprF32x4Qfma:
        return EmitSimdFmaOp<kF32>(&LiftoffAssembler::emit_f32x4_qfma);
      case wasm::kExprF32x4Qfms:
        return EmitSimdFmaOp<kF32>(&LiftoffAssembler::emit_f32x4_qfms);
      case wasm::kExprF64x2Qfma:
        return EmitSimdFmaOp<kF64>(&LiftoffAssembler::emit_f64x2_qfma);
      case wasm::kExprF64x2Qfms:
        return EmitSimdFmaOp<kF64>(&LiftoffAssembler::emit_f64x2_qfms);
      case wasm::kExprI16x8RelaxedLaneSelect:
      case wasm::kExprI8x16RelaxedLaneSelect:
        // There is no special hardware instruction for 16-bit wide lanes on
        // any of our platforms, so fall back to bytewise selection for i16x8.
        return EmitRelaxedLaneSelect(8);
      case wasm::kExprI32x4RelaxedLaneSelect:
        return EmitRelaxedLaneSelect(32);
      case wasm::kExprI64x2RelaxedLaneSelect:
        return EmitRelaxedLaneSelect(64);
      case wasm::kExprF32x4RelaxedMin:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_relaxed_min);
      case wasm::kExprF32x4RelaxedMax:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_relaxed_max);
      case wasm::kExprF64x2RelaxedMin:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_relaxed_min);
      case wasm::kExprF64x2RelaxedMax:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_relaxed_max);
      case wasm::kExprI16x8RelaxedQ15MulRS:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_relaxed_q15mulr_s);
      case wasm::kExprI32x4RelaxedTruncF32x4S:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_s);
      case wasm::kExprI32x4RelaxedTruncF32x4U:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_u);
      case wasm::kExprI32x4RelaxedTruncF64x2SZero:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_s_zero);
      case wasm::kExprI32x4RelaxedTruncF64x2UZero:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_u_zero);
      case wasm::kExprI16x8DotI8x16I7x16S:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_dot_i8x16_i7x16_s);
      case wasm::kExprI32x4DotI8x16I7x16AddS: {
        // There is no helper for an instruction with 3 SIMD operands
        // and we do not expect to add any more, so inlining it here.
        static constexpr RegClass res_rc = reg_class_for(kS128);
        LiftoffRegList pinned;
        LiftoffRegister acc = pinned.set(__ PopToRegister(pinned));
        LiftoffRegister rhs = pinned.set(__ PopToRegister(pinned));
        LiftoffRegister lhs = pinned.set(__ PopToRegister(pinned));
#if V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_IA32
        // x86 platforms save a move when dst == acc, so prefer that.
        LiftoffRegister dst =
            __ GetUnusedRegister(res_rc, {acc}, LiftoffRegList{lhs, rhs});
#else
        // On other platforms, for simplicity, we ensure that none of the
        // registers alias. (If we cared, it would probably be feasible to
        // allow {dst} to alias with {lhs} or {rhs}, but that'd be brittle.)
        LiftoffRegister dst = __ GetUnusedRegister(res_rc, pinned);
#endif

        __ emit_i32x4_dot_i8x16_i7x16_add_s(dst, lhs, rhs, acc);
        __ PushRegister(kS128, dst);
        return;
      }
      default:
        UNREACHABLE();
    }
  }

  template <ValueKind src_kind, ValueKind result_kind, typename EmitFn>
  void EmitSimdExtractLaneOp(EmitFn fn, const SimdLaneImmediate& imm) {
    static constexpr RegClass src_rc = reg_class_for(src_kind);
    static constexpr RegClass result_rc = reg_class_for(result_kind);
    LiftoffRegister lhs = __ PopToRegister();
    LiftoffRegister dst = src_rc == result_rc
                              ? __ GetUnusedRegister(result_rc, {lhs}, {})
                              : __ GetUnusedRegister(result_rc, {});
    fn(dst, lhs, imm.lane);
    __ PushRegister(result_kind, dst);
  }

  template <ValueKind src2_kind, typename EmitFn>
  void EmitSimdReplaceLaneOp(EmitFn fn, const SimdLaneImmediate& imm) {
    static constexpr RegClass src1_rc = reg_class_for(kS128);
    static constexpr RegClass src2_rc = reg_class_for(src2_kind);
    static constexpr RegClass result_rc = reg_class_for(kS128);
    // On backends which need fp pair, src1_rc and result_rc end up being
    // kFpRegPair, which is != kFpReg, but we still want to pin src2 when it is
    // kFpReg, since it can overlap with those pairs.
    static constexpr bool pin_src2 = kNeedS128RegPair && src2_rc == kFpReg;

    // Does not work for arm
    LiftoffRegister src2 = __ PopToRegister();
    LiftoffRegister src1 = (src1_rc == src2_rc || pin_src2)
                               ? __ PopToRegister(LiftoffRegList{src2})
                               : __
                                 PopToRegister();
    LiftoffRegister dst =
        (src2_rc == result_rc || pin_src2)
            ? __ GetUnusedRegister(result_rc, {src1}, LiftoffRegList{src2})
            : __ GetUnusedRegister(result_rc, {src1}, {});
    fn(dst, src1, src2, imm.lane);
    __ PushRegister(kS128, dst);
  }

  void SimdLaneOp(FullDecoder* decoder, WasmOpcode opcode,
                  const SimdLaneImmediate& imm,
                  base::Vector<const Value> inputs, Value* result) {
    CHECK(CpuFeatures::SupportsWasmSimd128());
    switch (opcode) {
#define CASE_SIMD_EXTRACT_LANE_OP(opcode, kind, fn)      \
  case wasm::kExpr##opcode:                              \
    EmitSimdExtractLaneOp<kS128, k##kind>(               \
        [this](LiftoffRegister dst, LiftoffRegister lhs, \
               uint8_t imm_lane_idx) {                   \
          __ emit_##fn(dst, lhs, imm_lane_idx);          \
        },                                               \
        imm);                                            \
    break;
      CASE_SIMD_EXTRACT_LANE_OP(I8x16ExtractLaneS, I32, i8x16_extract_lane_s)
      CASE_SIMD_EXTRACT_LANE_OP(I8x16ExtractLaneU, I32, i8x16_extract_lane_u)
      CASE_SIMD_EXTRACT_LANE_OP(I16x8ExtractLaneS, I32, i16x8_extract_lane_s)
      CASE_SIMD_EXTRACT_LANE_OP(I16x8ExtractLaneU, I32, i16x8_extract_lane_u)
      CASE_SIMD_EXTRACT_LANE_OP(I32x4ExtractLane, I32, i32x4_extract_lane)
      CASE_SIMD_EXTRACT_LANE_OP(I64x2ExtractLane, I64, i64x2_extract_lane)
      CASE_SIMD_EXTRACT_LANE_OP(F32x4ExtractLane, F32, f32x4_extract_lane)
      CASE_SIMD_EXTRACT_LANE_OP(F64x2ExtractLane, F64, f64x2_extract_lane)
#undef CASE_SIMD_EXTRACT_LANE_OP
      case wasm::kExprF16x8ExtractLane:
        EmitSimdExtractLaneOp<kS128, kF32>(
            [this](LiftoffRegister dst, LiftoffRegister lhs,
                   uint8_t imm_lane_idx) {
              if (asm_.emit_f16x8_extract_lane(dst, lhs, imm_lane_idx)) return;
              LiftoffRegister value = __ GetUnusedRegister(kGpReg, {});
              __ emit_i16x8_extract_lane_u(value, lhs, imm_lane_idx);
              auto conv_ref = ExternalReference::wasm_float16_to_float32();
              GenerateCCallWithStackBuffer(
                  &dst, kVoid, kF32, {VarState{kI16, value, 0}}, conv_ref);
            },
            imm);
        break;
#define CASE_SIMD_REPLACE_LANE_OP(opcode, kind, fn)          \
  case wasm::kExpr##opcode:                                  \
    EmitSimdReplaceLaneOp<k##kind>(                          \
        [this](LiftoffRegister dst, LiftoffRegister src1,    \
               LiftoffRegister src2, uint8_t imm_lane_idx) { \
          __ emit_##fn(dst, src1, src2, imm_lane_idx);       \
        },                                                   \
        imm);                                                \
    break;
      CASE_SIMD_REPLACE_LANE_OP(I8x16ReplaceLane, I32, i8x16_replace_lane)
      CASE_SIMD_REPLACE_LANE_OP(I16x8ReplaceLane, I32, i16x8_replace_lane)
      CASE_SIMD_REPLACE_LANE_OP(I32x4ReplaceLane, I32, i32x4_replace_lane)
      CASE_SIMD_REPLACE_LANE_OP(I64x2ReplaceLane, I64, i64x2_replace_lane)
      CASE_SIMD_REPLACE_LANE_OP(F32x4ReplaceLane, F32, f32x4_replace_lane)
      CASE_SIMD_REPLACE_LANE_OP(F64x2ReplaceLane, F64, f64x2_replace_lane)
#undef CASE_SIMD_REPLACE_LANE_OP
      case wasm::kExprF16x8ReplaceLane: {
        EmitSimdReplaceLaneOp<kI32>(
            [this](LiftoffRegister dst, LiftoffRegister src1,
                   LiftoffRegister src2, uint8_t imm_lane_idx) {
              if (asm_.emit_f16x8_replace_lane(dst, src1, src2, imm_lane_idx)) {
                return;
              }
              __ PushRegister(kS128, src1);
              LiftoffRegister value = __ GetUnusedRegister(kGpReg, {});
              auto conv_ref = ExternalReference::wasm_float32_to_float16();
              GenerateCCallWithStackBuffer(&value, kVoid, kI16,
                                           {VarState{kF32, src2, 0}}, conv_ref);
              __ PopToFixedRegister(src1);
              __ emit_i16x8_replace_lane(dst, src1, value, imm_lane_idx);
            },
            imm);
        break;
      }
      default:
        UNREACHABLE();
    }
  }

  void S128Const(FullDecoder* decoder, const Simd128Immediate& imm,
                 Value* result) {
    CHECK(CpuFeatures::SupportsWasmSimd128());
    constexpr RegClass result_rc = reg_class_for(kS128);
    LiftoffRegister dst = __ GetUnusedRegister(result_rc, {});
    bool all_zeroes = std::all_of(std::begin(imm.value), std::end(imm.value),
                                  [](uint8_t v) { return v == 0; });
    bool all_ones = std::all_of(std::begin(imm.value), std::end(imm.value),
                                [](uint8_t v) { return v == 0xff; });
    if (all_zeroes) {
      __ LiftoffAssembler::emit_s128_xor(dst, dst, dst);
    } else if (all_ones) {
      // Any SIMD eq will work, i32x4 is efficient on all archs.
      __ LiftoffAssembler::emit_i32x4_eq(dst, dst, dst);
    } else {
      __ LiftoffAssembler::emit_s128_const(dst, imm.value);
    }
    __ PushRegister(kS128, dst);
  }

  void Simd8x16ShuffleOp(FullDecoder* decoder, const Simd128Immediate& imm,
                         const Value& input0, const Value& input1,
                         Value* result) {
    CHECK(CpuFeatures::SupportsWasmSimd128());
    static constexpr RegClass result_rc = reg_class_for(kS128);
    LiftoffRegList pinned;
    LiftoffRegister rhs = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister lhs = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister dst = __ GetUnusedRegister(result_rc, {lhs, rhs}, {});

    uint8_t shuffle[kSimd128Size];
    memcpy(shuffle, imm.value, sizeof(shuffle));
    bool is_swizzle;
    bool needs_swap;
    wasm::SimdShuffle::CanonicalizeShuffle(lhs == rhs, shuffle, &needs_swap,
                                           &is_swizzle);
    if (needs_swap) {
      std::swap(lhs, rhs);
    }
    __ LiftoffAssembler::emit_i8x16_shuffle(dst, lhs, rhs, shuffle, is_swizzle);
    __ PushRegister(kS128, dst);
  }

  void ToSmi(Register reg) {
    if (COMPRESS_POINTERS_BOOL || kSystemPointerSize == 4) {
      __ emit_i32_shli(reg, reg, kSmiShiftSize + kSmiTagSize);
    } else {
      __ emit_i64_shli(LiftoffRegister{reg}, LiftoffRegister{reg},
                       kSmiShiftSize + kSmiTagSize);
    }
  }

  void Store32BitExceptionValue(Register values_array, int* index_in_array,
                                Register value, LiftoffRegList pinned) {
    Register tmp_reg = __ GetUnusedRegister(kGpReg, pinned).gp();
    // Get the lower half word into tmp_reg and extend to a Smi.
    --*index_in_array;
    __ emit_i32_andi(tmp_reg, value, 0xffff);
    ToSmi(tmp_reg);
    __ StoreTaggedPointer(
        values_array, no_reg,
        wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(*index_in_array),
        tmp_reg, pinned, nullptr, LiftoffAssembler::kSkipWriteBarrier);

    // Get the upper half word into tmp_reg and extend to a Smi.
    --*index_in_array;
    __ emit_i32_shri(tmp_reg, value, 16);
    ToSmi(tmp_reg);
    __ StoreTaggedPointer(
        values_array, no_reg,
        wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(*index_in_array),
        tmp_reg, pinned, nullptr, LiftoffAssembler::kSkipWriteBarrier);
  }

  void Store64BitExceptionValue(Register values_array, int* index_in_array,
                                LiftoffRegister value, LiftoffRegList pinned) {
    if (kNeedI64RegPair) {
      Store32BitExceptionValue(values_array, index_in_array, value.low_gp(),
                               pinned);
      Store32BitExceptionValue(values_array, index_in_array, value.high_gp(),
                               pinned);
    } else {
      Store32BitExceptionValue(values_array, index_in_array, value.gp(),
                               pinned);
      __ emit_i64_shri(value, value, 32);
      Store32BitExceptionValue(values_array, index_in_array, value.gp(),
                               pinned);
    }
  }

  void Load16BitExceptionValue(LiftoffRegister dst,
                               LiftoffRegister values_array, uint32_t* index,
                               LiftoffRegList pinned) {
    __ LoadSmiAsInt32(
        dst, values_array.gp(),
        wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(*index));
    (*index)++;
  }

  void Load32BitExceptionValue(Register dst, LiftoffRegister values_array,
                               uint32_t* index, LiftoffRegList pinned) {
    LiftoffRegister upper = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    Load16BitExceptionValue(upper, values_array, index, pinned);
    __ emit_i32_shli(upper.gp(), upper.gp(), 16);
    Load16BitExceptionValue(LiftoffRegister(dst), values_array, index, pinned);
    __ emit_i32_or(dst, upper.gp(), dst);
  }

  void Load64BitExceptionValue(LiftoffRegister dst,
                               LiftoffRegister values_array, uint32_t* index,
                               LiftoffRegList pinned) {
    if (kNeedI64RegPair) {
      Load32BitExceptionValue(dst.high_gp(), values_array, index, pinned);
      Load32BitExceptionValue(dst.low_gp(), values_array, index, pinned);
    } else {
      Load16BitExceptionValue(dst, values_array, index, pinned);
      __ emit_i64_shli(dst, dst, 48);
      LiftoffRegister tmp_reg =
          pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      Load16BitExceptionValue(tmp_reg, values_array, index, pinned);
      __ emit_i64_shli(tmp_reg, tmp_reg, 32);
      __ emit_i64_or(dst, tmp_reg, dst);
      Load16BitExceptionValue(tmp_reg, values_array, index, pinned);
      __ emit_i64_shli(tmp_reg, tmp_reg, 16);
      __ emit_i64_or(dst, tmp_reg, dst);
      Load16BitExceptionValue(tmp_reg, values_array, index, pinned);
      __ emit_i64_or(dst, tmp_reg, dst);
    }
  }

  void StoreExceptionValue(ValueType type, Register values_array,
                           int* index_in_array, LiftoffRegList pinned) {
    LiftoffRegister value = pinned.set(__ PopToRegister(pinned));
    switch (type.kind()) {
      case kI32:
        Store32BitExceptionValue(values_array, index_in_array, value.gp(),
                                 pinned);
        break;
      case kF32: {
        LiftoffRegister gp_reg =
            pinned.set(__ GetUnusedRegister(kGpReg, pinned));
        __ emit_type_conversion(kExprI32ReinterpretF32, gp_reg, value, nullptr);
        Store32BitExceptionValue(values_array, index_in_array, gp_reg.gp(),
                                 pinned);
        break;
      }
      case kI64:
        Store64BitExceptionValue(values_array, index_in_array, value, pinned);
        break;
      case kF64: {
        LiftoffRegister tmp_reg =
            pinned.set(__ GetUnusedRegister(reg_class_for(kI64), pinned));
        __ emit_type_conversion(kExprI64ReinterpretF64, tmp_reg, value,
                                nullptr);
        Store64BitExceptionValue(values_array, index_in_array, tmp_reg, pinned);
        break;
      }
      case kS128: {
        LiftoffRegister tmp_reg =
            pinned.set(__ GetUnusedRegister(kGpReg, pinned));
        for (int i : {3, 2, 1, 0}) {
          __ emit_i32x4_extract_lane(tmp_reg, value, i);
          Store32BitExceptionValue(values_array, index_in_array, tmp_reg.gp(),
                                   pinned);
        }
        break;
      }
      case wasm::kRef:
      case wasm::kRefNull:
      case wasm::kRtt: {
        --(*index_in_array);
        __ StoreTaggedPointer(
            values_array, no_reg,
            wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(
                *index_in_array),
            value.gp(), pinned);
        break;
      }
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kVoid:
      case wasm::kTop:
      case wasm::kBottom:
        UNREACHABLE();
    }
  }

  void LoadExceptionValue(ValueKind kind, LiftoffRegister values_array,
                          uint32_t* index, LiftoffRegList pinned) {
    RegClass rc = reg_class_for(kind);
    LiftoffRegister value = pinned.set(__ GetUnusedRegister(rc, pinned));
    switch (kind) {
      case kI32:
        Load32BitExceptionValue(value.gp(), values_array, index, pinned);
        break;
      case kF32: {
        LiftoffRegister tmp_reg =
            pinned.set(__ GetUnusedRegister(kGpReg, pinned));
        Load32BitExceptionValue(tmp_reg.gp(), values_array, index, pinned);
        __ emit_type_conversion(kExprF32ReinterpretI32, value, tmp_reg,
                                nullptr);
        break;
      }
      case kI64:
        Load64BitExceptionValue(value, values_array, index, pinned);
        break;
      case kF64: {
        RegClass rc_i64 = reg_class_for(kI64);
        LiftoffRegister tmp_reg =
            pinned.set(__ GetUnusedRegister(rc_i64, pinned));
        Load64BitExceptionValue(tmp_reg, values_array, index, pinned);
        __ emit_type_conversion(kExprF64ReinterpretI64, value, tmp_reg,
                                nullptr);
        break;
      }
      case kS128: {
        LiftoffRegister tmp_reg =
            pinned.set(__ GetUnusedRegister(kGpReg, pinned));
        Load32BitExceptionValue(tmp_reg.gp(), values_array, index, pinned);
        __ emit_i32x4_splat(value, tmp_reg);
        for (int lane : {1, 2, 3}) {
          Load32BitExceptionValue(tmp_reg.gp(), values_array, index, pinned);
          __ emit_i32x4_replace_lane(value, value, tmp_reg, lane);
        }
        break;
      }
      case wasm::kRef:
      case wasm::kRefNull:
      case wasm::kRtt: {
        __ LoadTaggedPointer(
            value.gp(), values_array.gp(), no_reg,
            wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(*index));
        (*index)++;
        break;
      }
      case wasm::kI8:
      case wasm::kI16:
      case wasm::kF16:
      case wasm::kVoid:
      case wasm::kTop:
      case wasm::kBottom:
        UNREACHABLE();
    }
    __ PushRegister(kind, value);
  }

  void GetExceptionValues(FullDecoder* decoder, const VarState& exception_var,
                          const WasmTag* tag) {
    LiftoffRegList pinned;
    CODE_COMMENT("get exception values");
    LiftoffRegister values_array = GetExceptionProperty(
        exception_var, RootIndex::kwasm_exception_values_symbol);
    pinned.set(values_array);
    uint32_t index = 0;
    const WasmTagSig* sig = tag->sig;
    for (ValueType param : sig->parameters()) {
      LoadExceptionValue(param.kind(), values_array, &index, pinned);
    }
    DCHECK_EQ(index, WasmExceptionPackage::GetEncodedSize(tag));
  }

  void EmitLandingPad(FullDecoder* decoder, int handler_offset) {
    if (decoder->current_catch() == -1) return;
    MovableLabel handler{zone_};

    // If we return from the throwing code normally, just skip over the handler.
    Label skip_handler;
    __ emit_jump(&skip_handler);

    // Handler: merge into the catch state, and jump to the catch body.
    CODE_COMMENT("-- landing pad --");
    __ bind(handler.get());
    __ ExceptionHandler();
    __ PushException();
    handlers_.push_back({std::move(handler), handler_offset});
    Control* current_try =
        decoder->control_at(decoder->control_depth_of_current_catch());
    DCHECK_NOT_NULL(current_try->try_info);
    if (current_try->try_info->catch_reached) {
      __ MergeStackWith(current_try->try_info->catch_state, 1,
                        LiftoffAssembler::kForwardJump);
    } else {
      current_try->try_info->catch_state = __ MergeIntoNewState(
          __ num_locals(), 1,
          current_try->stack_depth + current_try->num_exceptions);
      current_try->try_info->catch_reached = true;
    }
    __ emit_jump(&current_try->try_info->catch_label);

    __ bind(&skip_handler);
    // Drop the exception.
    __ DropValues(1);
  }

  void Throw(FullDecoder* decoder, const TagIndexImmediate& imm,
             const Value* /* args */) {
    LiftoffRegList pinned;

    // Load the encoded size in a register for the builtin call.
    int encoded_size = WasmExceptionPackage::GetEncodedSize(imm.tag);
    LiftoffRegister encoded_size_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    __ LoadConstant(encoded_size_reg, WasmValue::ForUintPtr(encoded_size));

    // Call the WasmAllocateFixedArray builtin to create the values array.
    CallBuiltin(Builtin::kWasmAllocateFixedArray,
                MakeSig::Returns(kIntPtrKind).Params(kIntPtrKind),
                {VarState{kIntPtrKind, LiftoffRegister{encoded_size_reg}, 0}},
                decoder->position());
    MaybeOSR();

    // The FixedArray for the exception values is now in the first gp return
    // register.
    LiftoffRegister values_array{kReturnRegister0};
    pinned.set(values_array);

    // Now store the exception values in the FixedArray. Do this from last to
    // first value, such that we can just pop them from the value stack.
    CODE_COMMENT("fill values array");
    int index = encoded_size;
    auto* sig = imm.tag->sig;
    for (size_t param_idx = sig->parameter_count(); param_idx > 0;
         --param_idx) {
      ValueType type = sig->GetParam(param_idx - 1);
      StoreExceptionValue(type, values_array.gp(), &index, pinned);
    }
    DCHECK_EQ(0, index);

    // Load the exception tag.
    CODE_COMMENT("load exception tag");
    LiftoffRegister exception_tag =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LOAD_TAGGED_PTR_INSTANCE_FIELD(exception_tag.gp(), TagsTable, pinned);
    __ LoadTaggedPointer(
        exception_tag.gp(), exception_tag.gp(), no_reg,
        wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(imm.index));

    // Finally, call WasmThrow.
    CallBuiltin(Builtin::kWasmThrow, MakeSig::Params(kIntPtrKind, kIntPtrKind),
                {VarState{kIntPtrKind, exception_tag, 0},
                 VarState{kIntPtrKind, values_array, 0}},
                decoder->position());

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    int pc_offset = __ pc_offset();
    MaybeOSR();
    EmitLandingPad(decoder, pc_offset);
  }

  void AtomicStoreMem(FullDecoder* decoder, StoreType type,
                      const MemoryAccessImmediate& imm) {
    LiftoffRegList pinned;
    LiftoffRegister value = pinned.set(__ PopToRegister());
    bool i64_offset = imm.memory->is_memory64();
    auto& index_slot = __ cache_state() -> stack_state.back();
    DCHECK_EQ(i64_offset ? kI64 : kI32, index_slot.kind());
    uintptr_t offset = imm.offset;
    LiftoffRegList outer_pinned;
    Register index = no_reg;

    if (IndexStaticallyInBoundsAndAligned(imm.memory, index_slot, type.size(),
                                          &offset)) {
      __ cache_state() -> stack_state.pop_back();  // Pop index.
      CODE_COMMENT("atomic store (constant offset)");
    } else {
      LiftoffRegister full_index = __ PopToRegister(pinned);
      index =
          BoundsCheckMem(decoder, imm.memory, type.size(), imm.offset,
                         full_index, pinned, kDoForceCheck, kCheckAlignment);
      pinned.set(index);
      CODE_COMMENT("atomic store");
    }
    Register addr = pinned.set(GetMemoryStart(imm.mem_index, pinned));
    if (V8_UNLIKELY(v8_flags.trace_wasm_memory) && index != no_reg) {
      outer_pinned.set(index);
    }
    __ AtomicStore(addr, index, offset, value, type, outer_pinned, i64_offset);
    if (V8_UNLIKELY(v8_flags.trace_wasm_memory)) {
      // TODO(14259): Implement memory tracing for multiple memories.
      CHECK_EQ(0, imm.memory->index);
      TraceMemoryOperation(true, type.mem_rep(), index, offset,
                           decoder->position());
    }
  }

  void AtomicLoadMem(FullDecoder* decoder, LoadType type,
                     const MemoryAccessImmediate& imm) {
    ValueKind kind = type.value_type().kind();
    bool i64_offset = imm.memory->is_memory64();
    auto& index_slot = __ cache_state() -> stack_state.back();
    DCHECK_EQ(i64_offset ? kI64 : kI32, index_slot.kind());
    uintptr_t offset = imm.offset;
    Register index = no_reg;
    LiftoffRegList pinned;

    if (IndexStaticallyInBoundsAndAligned(imm.memory, index_slot, type.size(),
                                          &offset)) {
      __ cache_state() -> stack_state.pop_back();  // Pop index.
      CODE_COMMENT("atomic load (constant offset)");
    } else {
      LiftoffRegister full_index = __ PopToRegister();
      index = BoundsCheckMem(decoder, imm.memory, type.size(), imm.offset,
                             full_index, {}, kDoForceCheck, kCheckAlignment);
      pinned.set(index);
      CODE_COMMENT("atomic load");
    }

    Register addr = pinned.set(GetMemoryStart(imm.mem_index, pinned));
    RegClass rc = reg_class_for(kind);
    LiftoffRegister value = pinned.set(__ GetUnusedRegister(rc, pinned));
    __ AtomicLoad(value, addr, index, offset, type, pinned, i64_offset);
    __ PushRegister(kind, value);

    if (V8_UNLIKELY(v8_flags.trace_wasm_memory)) {
      // TODO(14259): Implement memory tracing for multiple memories.
      CHECK_EQ(0, imm.memory->index);
      TraceMemoryOperation(false, type.mem_type().representation(), index,
                           offset, decoder->position());
    }
  }

  void AtomicBinop(FullDecoder* decoder, StoreType type,
                   const MemoryAccessImmediate& imm,
                   void (LiftoffAssembler::*emit_fn)(Register, Register,
                                                     uintptr_t, LiftoffRegister,
                                                     LiftoffRegister, StoreType,
                                                     bool)) {
    ValueKind result_kind = type.value_type().kind();
    LiftoffRegList pinned;
    LiftoffRegister value = pinned.set(__ PopToRegister());
#ifdef V8_TARGET_ARCH_IA32
    // We have to reuse the value register as the result register so that we
    // don't run out of registers on ia32. For this we use the value register as
    // the result register if it has no other uses. Otherwise we allocate a new
    // register and let go of the value register to get spilled.
    LiftoffRegister result = value;
    if (__ cache_state()->is_used(value)) {
      result = pinned.set(__ GetUnusedRegister(value.reg_class(), pinned));
      __ Move(result, value, result_kind);
      pinned.clear(value);
      value = result;
    }
#else
    LiftoffRegister result =
        pinned.set(__ GetUnusedRegister(value.reg_class(), pinned));
#endif
    auto& index_slot = __ cache_state() -> stack_state.back();
    uintptr_t offset = imm.offset;
    bool i64_offset = imm.memory->is_memory64();
    DCHECK_EQ(i64_offset ? kI64 : kI32, index_slot.kind());
    Register index = no_reg;

    if (IndexStaticallyInBoundsAndAligned(imm.memory, index_slot, type.size(),
                                          &offset)) {
      __ cache_state() -> stack_state.pop_back();  // Pop index.
      CODE_COMMENT("atomic binop (constant offset)");
    } else {
      LiftoffRegister full_index = __ PopToRegister(pinned);
      index =
          BoundsCheckMem(decoder, imm.memory, type.size(), imm.offset,
                         full_index, pinned, kDoForceCheck, kCheckAlignment);

      pinned.set(index);
      CODE_COMMENT("atomic binop");
    }

    Register addr = pinned.set(GetMemoryStart(imm.mem_index, pinned));
    (asm_.*emit_fn)(addr, index, offset, value, result, type, i64_offset);
    __ PushRegister(result_kind, result);
  }

  void AtomicCompareExchange(FullDecoder* decoder, StoreType type,
                             const MemoryAccessImmediate& imm) {
#ifdef V8_TARGET_ARCH_IA32
    // On ia32 we don't have enough registers to first pop all the values off
    // the stack and then start with the code generation. Instead we do the
    // complete address calculation first, so that the address only needs a
    // single register. Afterwards we load all remaining values into the
    // other registers.
    LiftoffRegister full_index = __ PeekToRegister(2, {});

    Register index =
        BoundsCheckMem(decoder, imm.memory, type.size(), imm.offset, full_index,
                       {}, kDoForceCheck, kCheckAlignment);
    LiftoffRegList pinned{index};

    uintptr_t offset = imm.offset;
    Register addr = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    if (imm.memory->index == 0) {
      LOAD_INSTANCE_FIELD(addr, Memory0Start, kSystemPointerSize, pinned);
    } else {
      LOAD_PROTECTED_PTR_INSTANCE_FIELD(addr, MemoryBasesAndSizes, pinned);
      int buffer_offset =
          wasm::ObjectAccess::ToTagged(OFFSET_OF_DATA_START(ByteArray)) +
          kSystemPointerSize * imm.memory->index * 2;
      __ LoadFullPointer(addr, addr, buffer_offset);
    }
    __ emit_i32_add(addr, addr, index);
    pinned.clear(LiftoffRegister(index));
    LiftoffRegister new_value = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister expected = pinned.set(__ PopToRegister(pinned));

    // Pop the index from the stack.
    bool i64_offset = imm.memory->is_memory64();
    DCHECK_EQ(i64_offset ? kI64 : kI32,
              __ cache_state()->stack_state.back().kind());
    __ DropValues(1);

    LiftoffRegister result = expected;
    if (__ cache_state()->is_used(result)) __ SpillRegister(result);

    // We already added the index to addr, so we can just pass no_reg to the
    // assembler now.
    __ AtomicCompareExchange(addr, no_reg, offset, expected, new_value, result,
                             type, i64_offset);
    __ PushRegister(type.value_type().kind(), result);
    return;
#else
    ValueKind result_kind = type.value_type().kind();
    LiftoffRegList pinned;
    LiftoffRegister new_value = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister expected = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister result =
        pinned.set(__ GetUnusedRegister(reg_class_for(result_kind), pinned));

    auto& index_slot = __ cache_state() -> stack_state.back();
    uintptr_t offset = imm.offset;
    bool i64_offset = imm.memory->is_memory64();
    DCHECK_EQ(i64_offset ? kI64 : kI32, index_slot.kind());
    Register index = no_reg;

    if (IndexStaticallyInBoundsAndAligned(imm.memory, index_slot, type.size(),
                                          &offset)) {
      __ cache_state() -> stack_state.pop_back();  // Pop index.
      CODE_COMMENT("atomic cmpxchg (constant offset)");
    } else {
      LiftoffRegister full_index = __ PopToRegister(pinned);
      index =
          BoundsCheckMem(decoder, imm.memory, type.size(), imm.offset,
                         full_index, pinned, kDoForceCheck, kCheckAlignment);
      pinned.set(index);
      CODE_COMMENT("atomic cmpxchg");
    }

    Register addr = pinned.set(GetMemoryStart(imm.mem_index, pinned));
    __ AtomicCompareExchange(addr, index, offset, expected, new_value, result,
                             type, i64_offset);
    __ PushRegister(result_kind, result);
#endif
  }

  void CallBuiltin(Builtin builtin, const ValueKindSig& sig,
                   std::initializer_list<VarState> params, int position) {
    SCOPED_CODE_COMMENT(
        (std::string{"Call builtin: "} + Builtins::name(builtin)));
    auto interface_descriptor = Builtins::CallInterfaceDescriptorFor(builtin);
    auto* call_descriptor = compiler::Linkage::GetStubCallDescriptor(
        zone_,                                          // zone
        interface_descriptor,                           // descriptor
        interface_descriptor.GetStackParameterCount(),  // stack parameter count
        compiler::CallDescriptor::kNoFlags,             // flags
        compiler::Operator::kNoProperties,              // properties
        StubCallMode::kCallWasmRuntimeStub);            // stub call mode

    __ PrepareBuiltinCall(&sig, call_descriptor, params);
    if (position != kNoSourcePosition) {
      source_position_table_builder_.AddPosition(
          __ pc_offset(), SourcePosition(position), true);
    }
    __ CallBuiltin(builtin);
    DefineSafepoint();
  }

  void AtomicWait(FullDecoder* decoder, ValueKind kind,
                  const MemoryAccessImmediate& imm) {
    FUZZER_HEAVY_INSTRUCTION;
    ValueKind index_kind;
    {
      LiftoffRegList pinned;
      LiftoffRegister full_index = __ PeekToRegister(2, pinned);

      Register index_reg =
          BoundsCheckMem(decoder, imm.memory, value_kind_size(kind), imm.offset,
                         full_index, pinned, kDoForceCheck, kCheckAlignment);
      pinned.set(index_reg);

      uintptr_t offset = imm.offset;
      Register index_plus_offset = index_reg;

      if (__ cache_state()->is_used(LiftoffRegister(index_reg))) {
        index_plus_offset =
            pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
        __ Move(index_plus_offset, index_reg, kIntPtrKind);
      }
      if (offset) {
        __ emit_ptrsize_addi(index_plus_offset, index_plus_offset, offset);
      }

      VarState& index = __ cache_state()->stack_state.end()[-3];

      // We replace the index on the value stack with the `index_plus_offset`
      // calculated above. Thereby the BigInt allocation below does not
      // overwrite the calculated value by accident.
      // The kind of `index_plus_offset has to be the same or smaller than the
      // original kind of `index`. The kind of index is kI32 for memory32, and
      // kI64 for memory64. On 64-bit platforms we can use in both cases the
      // kind of `index` also for `index_plus_offset`. Note that
      // `index_plus_offset` fits into a kI32 because we do a bounds check
      // first.
      // On 32-bit platforms, we have to use an kI32 also for memory64, because
      // `index_plus_offset` does not exist in a register pair.
      __ cache_state()->inc_used(LiftoffRegister(index_plus_offset));
      if (index.is_reg()) __ cache_state()->dec_used(index.reg());
      index_kind = index.kind() == kI32 ? kI32 : kIntPtrKind;

      index = VarState{index_kind, LiftoffRegister{index_plus_offset},
                       index.offset()};
    }
    {
      // Convert the top value of the stack (the timeout) from I64 to a BigInt,
      // which we can then pass to the atomic.wait builtin.
      VarState i64_timeout = __ cache_state()->stack_state.back();
      CallBuiltin(
          kNeedI64RegPair ? Builtin::kI32PairToBigInt : Builtin::kI64ToBigInt,
          MakeSig::Returns(kRef).Params(kI64), {i64_timeout},
          decoder->position());
      __ DropValues(1);
      // We put the result on the value stack so that it gets preserved across
      // a potential GC that may get triggered by the BigInt allocation below.
      __ PushRegister(kRef, LiftoffRegister(kReturnRegister0));
    }

    Register expected = no_reg;
    if (kind == kI32) {
      expected = __ PeekToRegister(1, {}).gp();
    } else {
      VarState i64_expected = __ cache_state()->stack_state.end()[-2];
      CallBuiltin(
          kNeedI64RegPair ? Builtin::kI32PairToBigInt : Builtin::kI64ToBigInt,
          MakeSig::Returns(kRef).Params(kI64), {i64_expected},
          decoder->position());
      expected = kReturnRegister0;
    }
    ValueKind expected_kind = kind == kI32 ? kI32 : kRef;

    VarState timeout = __ cache_state()->stack_state.end()[-1];
    VarState index = __ cache_state()->stack_state.end()[-3];

    auto target = kind == kI32 ? Builtin::kWasmI32AtomicWait
                               : Builtin::kWasmI64AtomicWait;

    // The type of {index} can either by i32 or intptr, depending on whether
    // memory32 or memory64 is used. This is okay because both values get passed
    // by register.
    CallBuiltin(target, MakeSig::Params(kI32, index_kind, expected_kind, kRef),
                {{kI32, static_cast<int32_t>(imm.memory->index), 0},
                 index,
                 {expected_kind, LiftoffRegister{expected}, 0},
                 timeout},
                decoder->position());
    // Pop parameters from the value stack.
    __ DropValues(3);

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    __ PushRegister(kI32, LiftoffRegister(kReturnRegister0));
  }

  void AtomicNotify(FullDecoder* decoder, const MemoryAccessImmediate& imm) {
    LiftoffRegList pinned;
    LiftoffRegister num_waiters_to_wake = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister full_index = __ PopToRegister(pinned);
    Register index_reg =
        BoundsCheckMem(decoder, imm.memory, kInt32Size, imm.offset, full_index,
                       pinned, kDoForceCheck, kCheckAlignment);
    pinned.set(index_reg);

    uintptr_t offset = imm.offset;
    Register addr = index_reg;
    if (__ cache_state()->is_used(LiftoffRegister(index_reg))) {
      addr = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
      __ Move(addr, index_reg, kIntPtrKind);
    }
    if (offset) {
      __ emit_ptrsize_addi(addr, addr, offset);
    }

    Register mem_start = GetMemoryStart(imm.memory->index, pinned);
    __ emit_ptrsize_add(addr, addr, mem_start);

    LiftoffRegister result =
        GenerateCCall(kI32,
                      {{kIntPtrKind, LiftoffRegister{addr}, 0},
                       {kI32, num_waiters_to_wake, 0}},
                      ExternalReference::wasm_atomic_notify());

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    __ PushRegister(kI32, result);
  }

#define ATOMIC_STORE_LIST(V)        \
  V(I32AtomicStore, kI32Store)      \
  V(I64AtomicStore, kI64Store)      \
  V(I32AtomicStore8U, kI32Store8)   \
  V(I32AtomicStore16U, kI32Store16) \
  V(I64AtomicStore8U, kI64Store8)   \
  V(I64AtomicStore16U, kI64Store16) \
  V(I64AtomicStore32U, kI64Store32)

#define ATOMIC_LOAD_LIST(V)        \
  V(I32AtomicLoad, kI32Load)       \
  V(I64AtomicLoad, kI64Load)       \
  V(I32AtomicLoad8U, kI32Load8U)   \
  V(I32AtomicLoad16U, kI32Load16U) \
  V(I64AtomicLoad8U, kI64Load8U)   \
  V(I64AtomicLoad16U, kI64Load16U) \
  V(I64AtomicLoad32U, kI64Load32U)

#define ATOMIC_BINOP_INSTRUCTION_LIST(V)         \
  V(Add, I32AtomicAdd, kI32Store)                \
  V(Add, I64AtomicAdd, kI64Store)                \
  V(Add, I32AtomicAdd8U, kI32Store8)             \
  V(Add, I32AtomicAdd16U, kI32Store16)           \
  V(Add, I64AtomicAdd8U, kI64Store8)             \
  V(Add, I64AtomicAdd16U, kI64Store16)           \
  V(Add, I64AtomicAdd32U, kI64Store32)           \
  V(Sub, I32AtomicSub, kI32Store)                \
  V(Sub, I64AtomicSub, kI64Store)                \
  V(Sub, I32AtomicSub8U, kI32Store8)             \
  V(Sub, I32AtomicSub16U, kI32Store16)           \
  V(Sub, I64AtomicSub8U, kI64Store8)             \
  V(Sub, I64AtomicSub16U, kI64Store16)           \
  V(Sub, I64AtomicSub32U, kI64Store32)           \
  V(And, I32AtomicAnd, kI32Store)                \
  V(And, I64AtomicAnd, kI64Store)                \
  V(And, I32AtomicAnd8U, kI32Store8)             \
  V(And, I32AtomicAnd16U, kI32Store16)           \
  V(And, I64AtomicAnd8U, kI64Store8)             \
  V(And, I64AtomicAnd16U, kI64Store16)           \
  V(And, I64AtomicAnd32U, kI64Store32)           \
  V(Or, I32AtomicOr, kI32Store)                  \
  V(Or, I64AtomicOr, kI64Store)                  \
  V(Or, I32AtomicOr8U, kI32Store8)               \
  V(Or, I32AtomicOr16U, kI32Store16)             \
  V(Or, I64AtomicOr8U, kI64Store8)               \
  V(Or, I64AtomicOr16U, kI64Store16)             \
  V(Or, I64AtomicOr32U, kI64Store32)             \
  V(Xor, I32AtomicXor, kI32Store)                \
  V(Xor, I64AtomicXor, kI64Store)                \
  V(Xor, I32AtomicXor8U, kI32Store8)             \
  V(Xor, I32AtomicXor16U, kI32Store16)           \
  V(Xor, I64AtomicXor8U, kI64Store8)             \
  V(Xor, I64AtomicXor16U, kI64Store16)           \
  V(Xor, I64AtomicXor32U, kI64Store32)           \
  V(Exchange, I32AtomicExchange, kI32Store)      \
  V(Exchange, I64AtomicExchange, kI64Store)      \
  V(Exchange, I32AtomicExchange8U, kI32Store8)   \
  V(Exchange, I32AtomicExchange16U, kI32Store16) \
  V(Exchange, I64AtomicExchange8U, kI64Store8)   \
  V(Exchange, I64AtomicExchange16U, kI64Store16) \
  V(Exchange, I64AtomicExchange32U, kI64Store32)

#define ATOMIC_COMPARE_EXCHANGE_LIST(V)       \
  V(I32AtomicCompareExchange, kI32Store)      \
  V(I64AtomicCompareExchange, kI64Store)      \
  V(I32AtomicCompareExchange8U, kI32Store8)   \
  V(I32AtomicCompareExchange16U, kI32Store16) \
  V(I64AtomicCompareExchange8U, kI64Store8)   \
  V(I64AtomicCompareExchange16U, kI64Store16) \
  V(I64AtomicCompareExchange32U, kI64Store32)

  void AtomicOp(FullDecoder* decoder, WasmOpcode opcode, const Value args[],
                const size_t argc, const MemoryAccessImmediate& imm,
                Value* result) {
    switch (opcode) {
#define ATOMIC_STORE_OP(name, type)                \
  case wasm::kExpr##name:                          \
    AtomicStoreMem(decoder, StoreType::type, imm); \
    break;

      ATOMIC_STORE_LIST(ATOMIC_STORE_OP)
#undef ATOMIC_STORE_OP

#define ATOMIC_LOAD_OP(name, type)               \
  case wasm::kExpr##name:                        \
    AtomicLoadMem(decoder, LoadType::type, imm); \
    break;

      ATOMIC_LOAD_LIST(ATOMIC_LOAD_OP)
#undef ATOMIC_LOAD_OP

#define ATOMIC_BINOP_OP(op, name, type)                                        \
  case wasm::kExpr##name:                                                      \
    AtomicBinop(decoder, StoreType::type, imm, &LiftoffAssembler::Atomic##op); \
    break;

      ATOMIC_BINOP_INSTRUCTION_LIST(ATOMIC_BINOP_OP)
#undef ATOMIC_BINOP_OP

#define ATOMIC_COMPARE_EXCHANGE_OP(name, type)            \
  case wasm::kExpr##name:                                 \
    AtomicCompareExchange(decoder, StoreType::type, imm); \
    break;

      ATOMIC_COMPARE_EXCHANGE_LIST(ATOMIC_COMPARE_EXCHANGE_OP)
#undef ATOMIC_COMPARE_EXCHANGE_OP

      case kExprI32AtomicWait:
        AtomicWait(decoder, kI32, imm);
        break;
      case kExprI64AtomicWait:
        AtomicWait(decoder, kI64, imm);
        break;
      case kExprAtomicNotify:
        AtomicNotify(decoder, imm);
        break;
      default:
        UNREACHABLE();
    }
  }

#undef ATOMIC_STORE_LIST
#undef ATOMIC_LOAD_LIST
#undef ATOMIC_BINOP_INSTRUCTION_LIST
#undef ATOMIC_COMPARE_EXCHANGE_LIST

  void AtomicFence(FullDecoder* decoder) { __ AtomicFence(); }

  // Pop a VarState and if needed transform it to an intptr.
  // When truncating from u64 to u32, the {*high_word} is updated to contain
  // the ORed combination of all high words.
  VarState PopIndexToVarState(Register* high_word, LiftoffRegList* pinned) {
    VarState slot = __ PopVarState();
    const bool is_64bit_value = slot.kind() == kI64;
    // For memory32 on a 32-bit system or memory64 on a 64-bit system, there is
    // nothing to do.
    if (Is64() == is_64bit_value) {
      if (slot.is_reg()) pinned->set(slot.reg());
      return slot;
    }

    // {kI64} constants will be stored as 32-bit integers in the {VarState} and
    // will be sign-extended later. Hence we can return constants if they are
    // positive (such that sign-extension and zero-extension are identical).
    if (slot.is_const() && (kIntPtrKind == kI32 || slot.i32_const() >= 0)) {
      return {kIntPtrKind, slot.i32_const(), 0};
    }

    // For memory32 on 64-bit hosts, zero-extend.
    if constexpr (Is64()) {
      DCHECK(!is_64bit_value);  // Handled above.
      LiftoffRegister reg = __ LoadToModifiableRegister(slot, *pinned);
      __ emit_u32_to_uintptr(reg.gp(), reg.gp());
      pinned->set(reg);
      return {kIntPtrKind, reg, 0};
    }

    // For memory64 on 32-bit systems, combine all high words for a zero-check
    // and only use the low words afterwards. This keeps the register pressure
    // managable.
    DCHECK(is_64bit_value && !Is64());  // Other cases are handled above.
    LiftoffRegister reg = __ LoadToRegister(slot, *pinned);
    pinned->set(reg.low());
    if (*high_word == no_reg) {
      // Choose a register to hold the (combination of) high word(s). It cannot
      // be one of the pinned registers, and it cannot be used in the value
      // stack.
      *high_word =
          !pinned->has(reg.high()) && __ cache_state()->is_free(reg.high())
              ? reg.high().gp()
              : __ GetUnusedRegister(kGpReg, *pinned).gp();
      pinned->set(*high_word);
      if (*high_word != reg.high_gp()) {
        __ Move(*high_word, reg.high_gp(), kI32);
      }
    } else if (*high_word != reg.high_gp()) {
      // Combine the new high word into existing high words.
      __ emit_i32_or(*high_word, *high_word, reg.high_gp());
    }
    return {kIntPtrKind, reg.low(), 0};
  }

  // This is a helper function that traps with TableOOB if any bit is set in
  // `high_word`. It is meant to be used after `PopIndexToVarState()` to check
  // if the conversion was valid.
  // Note that this is suboptimal as we add an OOL code for this special
  // condition, and there's also another conditional trap in the caller builtin.
  // However, it only applies for the rare case of 32-bit platforms with
  // table64.
  void CheckHighWordEmptyForTableType(FullDecoder* decoder,
                                      const Register high_word,
                                      LiftoffRegList* pinned) {
    if constexpr (Is64()) {
      DCHECK_EQ(no_reg, high_word);
      return;
    }
    if (high_word == no_reg) return;

    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapTableOutOfBounds);
    FREEZE_STATE(trapping);
    __ emit_cond_jump(kNotZero, trap_label, kI32, high_word, no_reg, trapping);
    // Clearing `high_word` is safe because this never aliases with another
    // in-use register, see `PopIndexToVarState()`.
    pinned->clear(high_word);
  }

  // Same as {PopIndexToVarState}, but can take a VarState in the middle of the
  // stack without popping it.
  // For 64-bit values on 32-bit systems, the resulting VarState will contain a
  // single register whose value will be 
"""


```