Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is from `v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h`.
The file name does not end with `.tq`, so it's not a Torque file.
The code seems to implement various operations related to WebAssembly SIMD (Single Instruction, Multiple Data) instructions on the ARM architecture, using NEON intrinsics.

Here's a plan to summarize the functionality:
1. Identify the main purpose of the code.
2. List the categories of operations implemented.
3. Provide examples of specific operations and their corresponding ARM NEON instructions.
4. Check if there are any connections to JavaScript functionality and provide examples if any.
5. Look for any implicit logic or assumptions that could be represented with input/output examples.
6. Identify potential common programming errors related to the operations.
```
这是目录为v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h 的一个v8源代码， 请列举一下它的功能,
如果v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

这个代码片段是V8 JavaScript 引擎中 Liftoff 编译器的 ARM 后端实现的一部分，专注于 **SIMD (Single Instruction, Multiple Data) 向量操作** 的汇编代码生成。

**主要功能归纳:**

这个代码片段主要负责为 WebAssembly 的 SIMD 指令生成 ARM NEON 汇编代码。它定义了 `LiftoffAssembler` 类的一些方法，用于执行各种 SIMD 操作，包括：

* **加载和存储 SIMD 数据:**
    * 从内存加载 SIMD 向量数据 (`Load`, `LoadLane`)，支持不同的数据类型和加载方式（如零扩展、广播）。
    * 将 SIMD 向量数据存储到内存 (`StoreLane`).
* **SIMD 通道 (Lane) 操作:**
    * 提取 SIMD 向量中的特定通道 (`emit_f64x2_extract_lane`, `emit_f32x4_extract_lane`, `emit_i64x2_extract_lane`, `emit_i32x4_extract_lane`).
    * 替换 SIMD 向量中的特定通道 (`emit_f64x2_replace_lane`, `emit_f32x4_replace_lane`, `emit_i64x2_replace_lane`, `emit_i32x4_replace_lane`).
* **SIMD 向量的创建:**
    * 创建所有通道值相同的 SIMD 向量 (`emit_f64x2_splat`, `emit_f32x4_splat`, `emit_i64x2_splat`, `emit_i32x4_splat`).
* **SIMD 向量的算术运算:**
    * 加法 (`emit_f64x2_add`, `emit_f32x4_add`, `emit_i64x2_add`, `emit_i32x4_add`).
    * 减法 (`emit_f64x2_sub`, `emit_f32x4_sub`, `emit_i64x2_sub`, `emit_i32x4_sub`).
    * 乘法 (`emit_f64x2_mul`, `emit_f32x4_mul`, `emit_i64x2_mul`, `emit_i64x2_extmul_low_i32x4_s`, `emit_i64x2_extmul_high_i32x4_u`).
    * 除法 (`emit_f64x2_div`, `emit_f32x4_div`).
    * 取反 (`emit_f64x2_neg`, `emit_f32x4_neg`, `emit_i64x2_neg`, `emit_i32x4_neg`).
    * 绝对值 (`emit_f64x2_abs`, `emit_f32x4_abs`).
    * 平方根 (`emit_f64x2_sqrt`, `emit_f32x4_sqrt`).
    * 最小值和最大值 (`emit_f64x2_min`, `emit_f64x2_max`, `emit_f32x4_min`, `emit_f32x4_max`, `emit_f64x2_pmin`, `emit_f64x2_pmax`, `emit_f32x4_pmin`, `emit_f32x4_pmax`).
* **SIMD 向量的类型转换:**
    * 浮点数转换为整数 (`emit_i32x4_relaxed_trunc_f32x4_s`, `emit_i32x4_relaxed_trunc_f32x4_u`, `emit_f64x2_convert_low_i32x4_s`, `emit_f64x2_convert_low_i32x4_u`).
    * 整数转换为浮点数 (`emit_f64x2_promote_low_f32x4`).
* **SIMD 向量的位运算:**
    * 左移 (`emit_i64x2_shl`, `emit_i32x4_shl`, `emit_i64x2_shli`, `emit_i32x4_shli`).
    * 右移 (有符号和无符号) (`emit_i64x2_shr_s`, `emit_i64x2_shr_u`, `emit_i32x4_shr_s`, `emit_i32x4_shr_u`, `emit_i64x2_shri_s`, `emit_i64x2_shri_u`, `emit_i32x4_shri_s`, `emit_i32x4_shri_u`).
* **其他 SIMD 操作:**
    * Swizzle (通道重排) (`emit_i8x16_swizzle`, `emit_i8x16_relaxed_swizzle`).
    * Lane 选择 (`emit_s128_relaxed_laneselect`).
    * 近似到整数 (`emit_f64x2_ceil`, `emit_f64x2_floor`, `emit_f64x2_trunc`, `emit_f64x2_nearest_int`, `emit_f32x4_ceil`, `emit_f32x4_floor`, `emit_f32x4_trunc`, `emit_f32x4_nearest_int`).
    * 检查所有通道是否为真 (`emit_i64x2_alltrue`, `emit_i32x4_alltrue`).
    * 生成位掩码 (`emit_i64x2_bitmask`, `emit_i32x4_bitmask`).

**与 JavaScript 的关系 (通过 WebAssembly):**

这段代码直接服务于 WebAssembly 的 SIMD 功能。JavaScript 可以通过调用 WebAssembly 模块来间接使用这些功能。

**JavaScript 示例:**

```javascript
const buffer = new Uint8Array([0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3]);
const wasmMemory = new WebAssembly.Memory({ initial: 1 });
new Uint8Array(wasmMemory.buffer).set(buffer);

const wasmCode = `
  (module
    (memory (export "memory") 1)
    (func (export "load_splat_i32") (result v128)
      i32.const 0
      v128.load32_splat align=1
    )
    (func (export "add_i32x4") (param v128 v128) (result v128)
      local.get 0
      local.get 1
      i32x4.add
    )
  )
`;
const wasmModule = new WebAssembly.Module(WebAssembly.compile(wasmCode));
const wasmInstance = new WebAssembly.Instance(wasmModule, { memory: wasmMemory });

// 调用 WebAssembly 函数，这些函数可能会使用到上面代码生成的汇编指令
const splat_result = wasmInstance.exports.load_splat_i32();
console.log(splat_result); // 输出一个 i32x4 向量，所有元素都为 0

const a = new Uint32Array([1, 2, 3, 4]);
const b = new Uint32Array([5, 6, 7, 8]);
const a_v128 = new Uint8Array(a.buffer); // 将 ArrayBuffer 视为 v128
const b_v128 = new Uint8Array(b.buffer);
const add_result = wasmInstance.exports.add_i32x4(a_v128, b_v128);
console.log(add_result); // 输出 i32x4 向量，元素分别为 6, 8, 10, 12
```

在这个例子中，`v128.load32_splat` 和 `i32x4.add` 这两个 WebAssembly 指令的执行，在 ARM 架构上很可能会由 `LiftoffAssembler` 生成的代码来实现，就像这个代码片段展示的那样。

**代码逻辑推理 (假设输入与输出):**

假设 `emit_i32x4_add` 函数被调用，并且：

* `dst` 代表目标 SIMD 寄存器，假设为 `q0`。
* `lhs` 代表左操作数 SIMD 寄存器，假设为 `q1`，其值为 `{1, 2, 3, 4}`。
* `rhs` 代表右操作数 SIMD 寄存器，假设为 `q2`，其值为 `{5, 6, 7, 8}`。

调用 `emit_i32x4_add(q0, q1, q2)` 后，生成的 ARM NEON 指令 `vadd.i32 q0, q1, q2` 会执行，`q0` 的值将变为 `{1+5, 2+6, 3+7, 4+8}`，即 `{6, 8, 10, 12}`。

**用户常见的编程错误 (与 SIMD 操作相关):**

1. **类型不匹配:**  尝试对不同类型的 SIMD 向量进行操作，例如将 `f32x4` 向量与 `i32x4` 向量相加。WebAssembly 的类型系统会阻止这种情况，但理解底层操作可以帮助调试。

   ```javascript
   // WebAssembly (示例)
   (func $add_mismatch (param $a f32x4) (param $b i32x4) (result f32x4)
     local.get $a
     local.get $b ;; 错误：类型不匹配
     f32x4.add
   )
   ```

2. **访问越界内存:** 在加载或存储 SIMD 数据时，提供的内存地址可能超出分配的内存范围。这会导致程序崩溃或未定义的行为.

   ```javascript
   // JavaScript (示例 - 模拟越界访问)
   const buffer = new Uint8Array(15); // 只能访问到索引 0-14
   const v128_offset = 10; // 尝试从索引 10 开始加载 16 字节，会越界
   // ... (WebAssembly 代码尝试从偏移量 v128_offset 加载 v128)
   ```

3. **通道索引错误:** 在提取或替换 SIMD 向量的通道时，使用了超出有效范围的索引。例如，对于 `i32x4` 向量，有效的通道索引是 0, 1, 2, 3。

   ```javascript
   // WebAssembly (示例)
   (func $extract_oob (param $v i32x4) (result i32)
     local.get $v
     i32x4.extract_lane 4 ;; 错误：索引 4 超出范围
   )
   ```

4. **未对齐的内存访问:** 某些 SIMD 加载和存储操作可能要求内存地址是对齐的（例如，16 字节对齐）。未对齐的访问可能会导致性能下降或在某些平台上崩溃。

**总结第4部分的功能:**

作为 6 部分中的第 4 部分，这个代码片段主要集中在 **为 WebAssembly 的 SIMD 操作生成 ARM NEON 汇编代码**。它涵盖了各种 SIMD 向量的创建、加载/存储、通道操作、算术运算、类型转换和位运算等功能。这是 Liftoff 编译器将 WebAssembly 的 SIMD 指令翻译成底层机器码的关键组成部分。

Prompt: 
```
这是目录为v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
    NeonMemOperand(actual_src_addr));
      vmovl(NeonU32, liftoff::GetSimd128Register(dst), dst.low_fp());
    }
  } else if (transform == LoadTransformationKind::kZeroExtend) {
    Simd128Register dest = liftoff::GetSimd128Register(dst);
    if (memtype == MachineType::Int32()) {
      vmov(dest, 0);
      vld1s(Neon32, NeonListOperand(dst.low_fp()), 0,
            NeonMemOperand(actual_src_addr));
    } else {
      DCHECK_EQ(MachineType::Int64(), memtype);
      vmov(dest.high(), 0);
      vld1(Neon64, NeonListOperand(dest.low()),
           NeonMemOperand(actual_src_addr));
    }
  } else {
    DCHECK_EQ(LoadTransformationKind::kSplat, transform);
    if (memtype == MachineType::Int8()) {
      vld1r(Neon8, NeonListOperand(liftoff::GetSimd128Register(dst)),
            NeonMemOperand(actual_src_addr));
    } else if (memtype == MachineType::Int16()) {
      vld1r(Neon16, NeonListOperand(liftoff::GetSimd128Register(dst)),
            NeonMemOperand(actual_src_addr));
    } else if (memtype == MachineType::Int32()) {
      vld1r(Neon32, NeonListOperand(liftoff::GetSimd128Register(dst)),
            NeonMemOperand(actual_src_addr));
    } else if (memtype == MachineType::Int64()) {
      vld1(Neon32, NeonListOperand(dst.low_fp()),
           NeonMemOperand(actual_src_addr));
      MacroAssembler::Move(dst.high_fp(), dst.low_fp());
    }
  }
}

void LiftoffAssembler::LoadLane(LiftoffRegister dst, LiftoffRegister src,
                                Register addr, Register offset_reg,
                                uintptr_t offset_imm, LoadType type,
                                uint8_t laneidx, uint32_t* protected_load_pc,
                                bool /* i64_offset */) {
  UseScratchRegisterScope temps(this);
  Register actual_src_addr = liftoff::CalculateActualAddress(
      this, &temps, addr, offset_reg, offset_imm);
  MacroAssembler::Move(liftoff::GetSimd128Register(dst),
                       liftoff::GetSimd128Register(src));
  *protected_load_pc = pc_offset();
  LoadStoreLaneParams load_params(type.mem_type().representation(), laneidx);
  NeonListOperand dst_op =
      NeonListOperand(load_params.low_op ? dst.low_fp() : dst.high_fp());
  MacroAssembler::LoadLane(load_params.sz, dst_op, load_params.laneidx,
                           NeonMemOperand(actual_src_addr));
}

void LiftoffAssembler::StoreLane(Register dst, Register offset,
                                 uintptr_t offset_imm, LiftoffRegister src,
                                 StoreType type, uint8_t laneidx,
                                 uint32_t* protected_store_pc,
                                 bool /* i64_offset */) {
  UseScratchRegisterScope temps(this);
  Register actual_dst_addr =
      liftoff::CalculateActualAddress(this, &temps, dst, offset, offset_imm);
  *protected_store_pc = pc_offset();

  LoadStoreLaneParams store_params(type.mem_rep(), laneidx);
  NeonListOperand src_op =
      NeonListOperand(store_params.low_op ? src.low_fp() : src.high_fp());
  MacroAssembler::StoreLane(store_params.sz, src_op, store_params.laneidx,
                            NeonMemOperand(actual_dst_addr));
}

void LiftoffAssembler::emit_i8x16_swizzle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs) {
  UseScratchRegisterScope temps(this);

  NeonListOperand table(liftoff::GetSimd128Register(lhs));
  if (dst == lhs) {
    // dst will be overwritten, so keep the table somewhere else.
    QwNeonRegister tbl = temps.AcquireQ();
    MacroAssembler::Move(tbl, liftoff::GetSimd128Register(lhs));
    table = NeonListOperand(tbl);
  }

  vtbl(dst.low_fp(), table, rhs.low_fp());
  vtbl(dst.high_fp(), table, rhs.high_fp());
}

void LiftoffAssembler::emit_i8x16_relaxed_swizzle(LiftoffRegister dst,
                                                  LiftoffRegister lhs,
                                                  LiftoffRegister rhs) {
  emit_i8x16_swizzle(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_s(LiftoffRegister dst,
                                                        LiftoffRegister src) {
  vcvt_s32_f32(liftoff::GetSimd128Register(dst),
               liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_u(LiftoffRegister dst,
                                                        LiftoffRegister src) {
  vcvt_u32_f32(liftoff::GetSimd128Register(dst),
               liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_s_zero(
    LiftoffRegister dst, LiftoffRegister src) {
  emit_i32x4_trunc_sat_f64x2_s_zero(dst, src);
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_u_zero(
    LiftoffRegister dst, LiftoffRegister src) {
  emit_i32x4_trunc_sat_f64x2_u_zero(dst, src);
}

void LiftoffAssembler::emit_s128_relaxed_laneselect(LiftoffRegister dst,
                                                    LiftoffRegister src1,
                                                    LiftoffRegister src2,
                                                    LiftoffRegister mask,
                                                    int lane_width) {
  // ARM uses bytewise selection for all lane widths.
  emit_s128_select(dst, src1, src2, mask);
}

void LiftoffAssembler::emit_f64x2_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  MacroAssembler::Move(dst.low_fp(), src.fp());
  MacroAssembler::Move(dst.high_fp(), src.fp());
}

void LiftoffAssembler::emit_f64x2_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  ExtractLane(dst.fp(), liftoff::GetSimd128Register(lhs), imm_lane_idx);
}

void LiftoffAssembler::emit_f64x2_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  ReplaceLane(liftoff::GetSimd128Register(dst),
              liftoff::GetSimd128Register(src1), src2.fp(), imm_lane_idx);
}

void LiftoffAssembler::emit_f64x2_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  vabs(dst.low_fp(), src.low_fp());
  vabs(dst.high_fp(), src.high_fp());
}

void LiftoffAssembler::emit_f64x2_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  vneg(dst.low_fp(), src.low_fp());
  vneg(dst.high_fp(), src.high_fp());
}

void LiftoffAssembler::emit_f64x2_sqrt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  vsqrt(dst.low_fp(), src.low_fp());
  vsqrt(dst.high_fp(), src.high_fp());
}

bool LiftoffAssembler::emit_f64x2_ceil(LiftoffRegister dst,
                                       LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(ARMv8)) {
    return false;
  }

  CpuFeatureScope scope(this, ARMv8);
  vrintp(dst.low_fp(), src.low_fp());
  vrintp(dst.high_fp(), src.high_fp());
  return true;
}

bool LiftoffAssembler::emit_f64x2_floor(LiftoffRegister dst,
                                        LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(ARMv8)) {
    return false;
  }

  CpuFeatureScope scope(this, ARMv8);
  vrintm(dst.low_fp(), src.low_fp());
  vrintm(dst.high_fp(), src.high_fp());
  return true;
}

bool LiftoffAssembler::emit_f64x2_trunc(LiftoffRegister dst,
                                        LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(ARMv8)) {
    return false;
  }

  CpuFeatureScope scope(this, ARMv8);
  vrintz(dst.low_fp(), src.low_fp());
  vrintz(dst.high_fp(), src.high_fp());
  return true;
}

bool LiftoffAssembler::emit_f64x2_nearest_int(LiftoffRegister dst,
                                              LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(ARMv8)) {
    return false;
  }

  CpuFeatureScope scope(this, ARMv8);
  vrintn(dst.low_fp(), src.low_fp());
  vrintn(dst.high_fp(), src.high_fp());
  return true;
}

void LiftoffAssembler::emit_f64x2_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  vadd(dst.low_fp(), lhs.low_fp(), rhs.low_fp());
  vadd(dst.high_fp(), lhs.high_fp(), rhs.high_fp());
}

void LiftoffAssembler::emit_f64x2_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  vsub(dst.low_fp(), lhs.low_fp(), rhs.low_fp());
  vsub(dst.high_fp(), lhs.high_fp(), rhs.high_fp());
}

void LiftoffAssembler::emit_f64x2_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  vmul(dst.low_fp(), lhs.low_fp(), rhs.low_fp());
  vmul(dst.high_fp(), lhs.high_fp(), rhs.high_fp());
}

void LiftoffAssembler::emit_f64x2_div(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  vdiv(dst.low_fp(), lhs.low_fp(), rhs.low_fp());
  vdiv(dst.high_fp(), lhs.high_fp(), rhs.high_fp());
}

void LiftoffAssembler::emit_f64x2_min(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Simd128Register dest = liftoff::GetSimd128Register(dst);
  Simd128Register left = liftoff::GetSimd128Register(lhs);
  Simd128Register right = liftoff::GetSimd128Register(rhs);

  liftoff::EmitFloatMinOrMax(this, dest.low(), left.low(), right.low(),
                             liftoff::MinOrMax::kMin);
  liftoff::EmitFloatMinOrMax(this, dest.high(), left.high(), right.high(),
                             liftoff::MinOrMax::kMin);
}

void LiftoffAssembler::emit_f64x2_max(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  Simd128Register dest = liftoff::GetSimd128Register(dst);
  Simd128Register left = liftoff::GetSimd128Register(lhs);
  Simd128Register right = liftoff::GetSimd128Register(rhs);

  liftoff::EmitFloatMinOrMax(this, dest.low(), left.low(), right.low(),
                             liftoff::MinOrMax::kMax);
  liftoff::EmitFloatMinOrMax(this, dest.high(), left.high(), right.high(),
                             liftoff::MinOrMax::kMax);
}

void LiftoffAssembler::emit_f64x2_pmin(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  QwNeonRegister dest = liftoff::GetSimd128Register(dst);
  QwNeonRegister left = liftoff::GetSimd128Register(lhs);
  QwNeonRegister right = liftoff::GetSimd128Register(rhs);

  VFPCompareAndSetFlags(right.low(), left.low());
  if (dst != rhs) vmov(dest.low(), right.low(), mi);
  if (dst != lhs) vmov(dest.low(), left.low(), NegateCondition(mi));
  VFPCompareAndSetFlags(right.high(), left.high());
  if (dst != rhs) vmov(dest.high(), right.high(), mi);
  if (dst != lhs) vmov(dest.high(), left.high(), NegateCondition(mi));
}

void LiftoffAssembler::emit_f64x2_pmax(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  QwNeonRegister dest = liftoff::GetSimd128Register(dst);
  QwNeonRegister left = liftoff::GetSimd128Register(lhs);
  QwNeonRegister right = liftoff::GetSimd128Register(rhs);

  VFPCompareAndSetFlags(right.low(), left.low());
  if (dst != rhs) vmov(dest.low(), right.low(), gt);
  if (dst != lhs) vmov(dest.low(), left.low(), NegateCondition(gt));
  VFPCompareAndSetFlags(right.high(), left.high());
  if (dst != rhs) vmov(dest.high(), right.high(), gt);
  if (dst != lhs) vmov(dest.high(), left.high(), NegateCondition(gt));
}

void LiftoffAssembler::emit_f64x2_relaxed_min(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  emit_f64x2_pmin(dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_relaxed_max(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  emit_f64x2_pmax(dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_convert_low_i32x4_s(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  F64x2ConvertLowI32x4S(liftoff::GetSimd128Register(dst),
                        liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_f64x2_convert_low_i32x4_u(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  F64x2ConvertLowI32x4U(liftoff::GetSimd128Register(dst),
                        liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_f64x2_promote_low_f32x4(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  F64x2PromoteLowF32x4(liftoff::GetSimd128Register(dst),
                       liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_f32x4_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  vdup(Neon32, liftoff::GetSimd128Register(dst), src.fp(), 0);
}

void LiftoffAssembler::emit_f32x4_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  ExtractLane(liftoff::GetFloatRegister(dst.fp()),
              liftoff::GetSimd128Register(lhs), imm_lane_idx);
}

void LiftoffAssembler::emit_f32x4_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  ReplaceLane(liftoff::GetSimd128Register(dst),
              liftoff::GetSimd128Register(src1),
              liftoff::GetFloatRegister(src2.fp()), imm_lane_idx);
}

void LiftoffAssembler::emit_f32x4_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  vabs(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_f32x4_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  vneg(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_f32x4_sqrt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  // The list of d registers available to us is from d0 to d15, which always
  // maps to 2 s registers.
  LowDwVfpRegister dst_low = LowDwVfpRegister::from_code(dst.low_fp().code());
  LowDwVfpRegister src_low = LowDwVfpRegister::from_code(src.low_fp().code());

  LowDwVfpRegister dst_high = LowDwVfpRegister::from_code(dst.high_fp().code());
  LowDwVfpRegister src_high = LowDwVfpRegister::from_code(src.high_fp().code());

  vsqrt(dst_low.low(), src_low.low());
  vsqrt(dst_low.high(), src_low.high());
  vsqrt(dst_high.low(), src_high.low());
  vsqrt(dst_high.high(), src_high.high());
}

bool LiftoffAssembler::emit_f32x4_ceil(LiftoffRegister dst,
                                       LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(ARMv8)) {
    return false;
  }

  CpuFeatureScope scope(this, ARMv8);
  vrintp(NeonS32, liftoff::GetSimd128Register(dst),
         liftoff::GetSimd128Register(src));
  return true;
}

bool LiftoffAssembler::emit_f32x4_floor(LiftoffRegister dst,
                                        LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(ARMv8)) {
    return false;
  }

  CpuFeatureScope scope(this, ARMv8);
  vrintm(NeonS32, liftoff::GetSimd128Register(dst),
         liftoff::GetSimd128Register(src));
  return true;
}

bool LiftoffAssembler::emit_f32x4_trunc(LiftoffRegister dst,
                                        LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(ARMv8)) {
    return false;
  }

  CpuFeatureScope scope(this, ARMv8);
  vrintz(NeonS32, liftoff::GetSimd128Register(dst),
         liftoff::GetSimd128Register(src));
  return true;
}

bool LiftoffAssembler::emit_f32x4_nearest_int(LiftoffRegister dst,
                                              LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(ARMv8)) {
    return false;
  }

  CpuFeatureScope scope(this, ARMv8);
  vrintn(NeonS32, liftoff::GetSimd128Register(dst),
         liftoff::GetSimd128Register(src));
  return true;
}

void LiftoffAssembler::emit_f32x4_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  vadd(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
       liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_f32x4_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  vsub(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
       liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_f32x4_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  vmul(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
       liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_f32x4_div(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  // The list of d registers available to us is from d0 to d15, which always
  // maps to 2 s registers.
  LowDwVfpRegister dst_low = LowDwVfpRegister::from_code(dst.low_fp().code());
  LowDwVfpRegister lhs_low = LowDwVfpRegister::from_code(lhs.low_fp().code());
  LowDwVfpRegister rhs_low = LowDwVfpRegister::from_code(rhs.low_fp().code());

  LowDwVfpRegister dst_high = LowDwVfpRegister::from_code(dst.high_fp().code());
  LowDwVfpRegister lhs_high = LowDwVfpRegister::from_code(lhs.high_fp().code());
  LowDwVfpRegister rhs_high = LowDwVfpRegister::from_code(rhs.high_fp().code());

  vdiv(dst_low.low(), lhs_low.low(), rhs_low.low());
  vdiv(dst_low.high(), lhs_low.high(), rhs_low.high());
  vdiv(dst_high.low(), lhs_high.low(), rhs_high.low());
  vdiv(dst_high.high(), lhs_high.high(), rhs_high.high());
}

void LiftoffAssembler::emit_f32x4_min(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  vmin(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
       liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_f32x4_max(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  vmax(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
       liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_f32x4_relaxed_min(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  vmin(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
       liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_f32x4_relaxed_max(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  vmax(liftoff::GetSimd128Register(dst), liftoff::GetSimd128Register(lhs),
       liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_f32x4_pmin(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  UseScratchRegisterScope temps(this);

  QwNeonRegister tmp = liftoff::GetSimd128Register(dst);
  if (dst == lhs || dst == rhs) {
    tmp = temps.AcquireQ();
  }

  QwNeonRegister left = liftoff::GetSimd128Register(lhs);
  QwNeonRegister right = liftoff::GetSimd128Register(rhs);
  vcgt(tmp, left, right);
  vbsl(tmp, right, left);

  if (dst == lhs || dst == rhs) {
    vmov(liftoff::GetSimd128Register(dst), tmp);
  }
}

void LiftoffAssembler::emit_f32x4_pmax(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  UseScratchRegisterScope temps(this);

  QwNeonRegister tmp = liftoff::GetSimd128Register(dst);
  if (dst == lhs || dst == rhs) {
    tmp = temps.AcquireQ();
  }

  QwNeonRegister left = liftoff::GetSimd128Register(lhs);
  QwNeonRegister right = liftoff::GetSimd128Register(rhs);
  vcgt(tmp, right, left);
  vbsl(tmp, right, left);

  if (dst == lhs || dst == rhs) {
    vmov(liftoff::GetSimd128Register(dst), tmp);
  }
}

void LiftoffAssembler::emit_i64x2_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Simd128Register dst_simd = liftoff::GetSimd128Register(dst);
  vdup(Neon32, dst_simd, src.low_gp());
  ReplaceLane(dst_simd, dst_simd, src.high_gp(), NeonS32, 1);
  ReplaceLane(dst_simd, dst_simd, src.high_gp(), NeonS32, 3);
}

void LiftoffAssembler::emit_i64x2_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  ExtractLane(dst.low_gp(), liftoff::GetSimd128Register(lhs), NeonS32,
              imm_lane_idx * 2);
  ExtractLane(dst.high_gp(), liftoff::GetSimd128Register(lhs), NeonS32,
              imm_lane_idx * 2 + 1);
}

void LiftoffAssembler::emit_i64x2_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  Simd128Register dst_simd = liftoff::GetSimd128Register(dst);
  Simd128Register src1_simd = liftoff::GetSimd128Register(src1);
  ReplaceLane(dst_simd, src1_simd, src2.low_gp(), NeonS32, imm_lane_idx * 2);
  ReplaceLane(dst_simd, dst_simd, src2.high_gp(), NeonS32,
              imm_lane_idx * 2 + 1);
}

void LiftoffAssembler::emit_i64x2_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  UseScratchRegisterScope temps(this);
  QwNeonRegister zero =
      dst == src ? temps.AcquireQ() : liftoff::GetSimd128Register(dst);
  vmov(zero, uint64_t{0});
  vsub(Neon64, liftoff::GetSimd128Register(dst), zero,
       liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_i64x2_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  I64x2AllTrue(dst.gp(), liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_i64x2_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::kLeft, NeonS64, Neon32>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  vshl(NeonS64, liftoff::GetSimd128Register(dst),
       liftoff::GetSimd128Register(lhs), rhs & 63);
}

void LiftoffAssembler::emit_i64x2_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::kRight, NeonS64, Neon32>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftImmediate<liftoff::kRight, NeonS64>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_i64x2_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::kRight, NeonU64, Neon32>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftImmediate<liftoff::kRight, NeonU64>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_i64x2_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  vadd(Neon64, liftoff::GetSimd128Register(dst),
       liftoff::GetSimd128Register(lhs), liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_i64x2_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  vsub(Neon64, liftoff::GetSimd128Register(dst),
       liftoff::GetSimd128Register(lhs), liftoff::GetSimd128Register(rhs));
}

void LiftoffAssembler::emit_i64x2_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  UseScratchRegisterScope temps(this);

  QwNeonRegister dst_neon = liftoff::GetSimd128Register(dst);
  QwNeonRegister left = liftoff::GetSimd128Register(lhs);
  QwNeonRegister right = liftoff::GetSimd128Register(rhs);

  // These temporary registers will be modified. We can directly modify lhs and
  // rhs if they are not uesd, saving on temporaries.
  QwNeonRegister tmp1 = left;
  QwNeonRegister tmp2 = right;

  LiftoffRegList used_plus_dst =
      cache_state()->used_registers | LiftoffRegList{dst};

  if (used_plus_dst.has(lhs) && used_plus_dst.has(rhs)) {
    tmp1 = temps.AcquireQ();
    // We only have 1 scratch Q register, so acquire another ourselves.
    LiftoffRegList pinned{dst};
    LiftoffRegister unused_pair = GetUnusedRegister(kFpRegPair, pinned);
    tmp2 = liftoff::GetSimd128Register(unused_pair);
  } else if (used_plus_dst.has(lhs)) {
    tmp1 = temps.AcquireQ();
  } else if (used_plus_dst.has(rhs)) {
    tmp2 = temps.AcquireQ();
  }

  // Algorithm from code-generator-arm.cc, refer to comments there for details.
  if (tmp1 != left) {
    vmov(tmp1, left);
  }
  if (tmp2 != right) {
    vmov(tmp2, right);
  }

  vtrn(Neon32, tmp1.low(), tmp1.high());
  vtrn(Neon32, tmp2.low(), tmp2.high());

  vmull(NeonU32, dst_neon, tmp1.low(), tmp2.high());
  vmlal(NeonU32, dst_neon, tmp1.high(), tmp2.low());
  vshl(NeonU64, dst_neon, dst_neon, 32);

  vmlal(NeonU32, dst_neon, tmp1.low(), tmp2.low());
}

void LiftoffAssembler::emit_i64x2_extmul_low_i32x4_s(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  vmull(NeonS32, liftoff::GetSimd128Register(dst), src1.low_fp(),
        src2.low_fp());
}

void LiftoffAssembler::emit_i64x2_extmul_low_i32x4_u(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  vmull(NeonU32, liftoff::GetSimd128Register(dst), src1.low_fp(),
        src2.low_fp());
}

void LiftoffAssembler::emit_i64x2_extmul_high_i32x4_s(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  vmull(NeonS32, liftoff::GetSimd128Register(dst), src1.high_fp(),
        src2.high_fp());
}

void LiftoffAssembler::emit_i64x2_extmul_high_i32x4_u(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  vmull(NeonU32, liftoff::GetSimd128Register(dst), src1.high_fp(),
        src2.high_fp());
}

void LiftoffAssembler::emit_i64x2_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  I64x2BitMask(dst.gp(), liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_i64x2_sconvert_i32x4_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  vmovl(NeonS32, liftoff::GetSimd128Register(dst), src.low_fp());
}

void LiftoffAssembler::emit_i64x2_sconvert_i32x4_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  vmovl(NeonS32, liftoff::GetSimd128Register(dst), src.high_fp());
}

void LiftoffAssembler::emit_i64x2_uconvert_i32x4_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  vmovl(NeonU32, liftoff::GetSimd128Register(dst), src.low_fp());
}

void LiftoffAssembler::emit_i64x2_uconvert_i32x4_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  vmovl(NeonU32, liftoff::GetSimd128Register(dst), src.high_fp());
}

void LiftoffAssembler::emit_i32x4_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  vdup(Neon32, liftoff::GetSimd128Register(dst), src.gp());
}

void LiftoffAssembler::emit_i32x4_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  ExtractLane(dst.gp(), liftoff::GetSimd128Register(lhs), NeonS32,
              imm_lane_idx);
}

void LiftoffAssembler::emit_i32x4_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  ReplaceLane(liftoff::GetSimd128Register(dst),
              liftoff::GetSimd128Register(src1), src2.gp(), NeonS32,
              imm_lane_idx);
}

void LiftoffAssembler::emit_i32x4_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  vneg(Neon32, liftoff::GetSimd128Register(dst),
       liftoff::GetSimd128Register(src));
}

void LiftoffAssembler::emit_i32x4_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  UseScratchRegisterScope temps(this);
  DwVfpRegister scratch = temps.AcquireD();
  vpmin(NeonU32, scratch, src.low_fp(), src.high_fp());
  vpmin(NeonU32, scratch, scratch, scratch);
  ExtractLane(dst.gp(), scratch, NeonS32, 0);
  cmp(dst.gp(), Operand(0));
  mov(dst.gp(), Operand(1), LeaveCC, ne);
}

void LiftoffAssembler::emit_i32x4_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  UseScratchRegisterScope temps(this);
  Simd128Register tmp = liftoff::GetSimd128Register(src);
  Simd128Register mask = temps.AcquireQ();

  if (cache_state()->is_used(src)) {
    // We only have 1 scratch Q register, so try and reuse src.
    LiftoffRegList pinned{src};
    LiftoffRegister unused_pair = GetUnusedRegister(kFpRegPair, pinned);
    mask = liftoff::GetSimd128Register(unused_pair);
  }

  vshr(NeonS32, tmp, liftoff::GetSimd128Register(src), 31);
  // Set i-th bit of each lane i. When AND with tmp, the lanes that
  // are signed will have i-th bit set, unsigned will be 0.
  vmov(mask.low(), base::Double((uint64_t)0x0000'0002'0000'0001));
  vmov(mask.high(), base::Double((uint64_t)0x0000'0008'0000'0004));
  vand(tmp, mask, tmp);
  vpadd(Neon32, tmp.low(), tmp.low(), tmp.high());
  vpadd(Neon32, tmp.low(), tmp.low(), kDoubleRegZero);
  VmovLow(dst.gp(), tmp.low());
}

void LiftoffAssembler::emit_i32x4_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::kLeft, NeonS32, Neon32>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  vshl(NeonS32, liftoff::GetSimd128Register(dst),
       liftoff::GetSimd128Register(lhs), rhs & 31);
}

void LiftoffAssembler::emit_i32x4_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::kRight, NeonS32, Neon32>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftImmediate<liftoff::kRight, NeonS32>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_i32x4_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShift<liftoff::kRight, NeonU32, Neon32>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftImmediate<liftoff::kRight, NeonU32>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_i32x4_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  vadd(Neon32, liftoff::GetSimd128Register(dst),
       liftoff::GetSimd128Register(lhs), liftoff::GetSimd12
"""


```