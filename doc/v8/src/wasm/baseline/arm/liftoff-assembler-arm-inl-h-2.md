Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the provided C++ code snippet from a V8 header file. It also includes specific constraints about mentioning its purpose, handling `.tq` files, relating to JavaScript, providing examples, discussing errors, and acknowledging the "part X of 6" structure.

2. **Initial Code Scan (Keywords and Structure):** I quickly scan the code for recognizable patterns and keywords. I see:
    * Class methods (like `emit_i32_sar`, `emit_f32_add`, etc.) within a `LiftoffAssembler` class.
    * ARM assembly instructions (like `and_`, `asr`, `lsr`, `vadd`, `vsub`, `cmp`, `b`, `mov`, `ldr`, `str`, etc.).
    * Data types like `Register`, `DoubleRegister`, `LiftoffRegister`.
    * Conditional compilation (`V8_LIKELY`).
    * Calls to other functions (like `liftoff::GetFloatRegister`, `liftoff::I64Binop`, `liftoff::GeneratePopCnt`).
    * Use of `Label` for branching.
    * Specific WASM opcodes (like `kExprI32ConvertI64`).
    * Features flags checks (`CpuFeatures::IsSupported`).
    * Scopes (`UseScratchRegisterScope`, `CpuFeatureScope`).

3. **Identify Core Functionality:**  The naming convention of the methods (`emit_...`) strongly suggests that this code is responsible for *emitting* (generating) assembly instructions. The prefixes like `i32_`, `f32_`, `f64_`, `i64_` indicate these instructions are related to different data types (integers and floating-point numbers of varying sizes). The suffixes like `_add`, `_sub`, `_mul`, `_div`, `_shl`, `_sar`, etc., clearly point to specific arithmetic, logical, and bitwise operations.

4. **Determine the Context (File Path):** The file path `v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h` provides crucial context:
    * `v8`:  This is part of the V8 JavaScript engine.
    * `wasm`: This relates to WebAssembly.
    * `baseline`: This suggests it's part of the baseline compiler in V8 (a fast but less optimized compiler).
    * `arm`: This targets the ARM architecture.
    * `liftoff-assembler`:  The "assembler" part confirms the instruction emission role, and "liftoff" is the specific name of V8's baseline WASM compiler.
    * `-inl.h`: This indicates an inline header file, likely containing the implementations of the `LiftoffAssembler` methods.

5. **Address Specific Constraints:**

    * **Functionality:**  Based on the analysis, the primary function is to provide a set of methods for generating ARM assembly instructions for the Liftoff WebAssembly compiler. These instructions implement basic arithmetic, logical, bitwise, and type conversion operations for WASM.

    * **`.tq` Files:** The code does *not* end with `.tq`. Therefore, it is not a Torque source file.

    * **JavaScript Relationship:**  This code is *indirectly* related to JavaScript. V8 executes JavaScript. When JavaScript code uses WebAssembly, V8 compiles that WASM code. The Liftoff compiler (and this header file) is part of that compilation process. The generated ARM assembly instructions are what the processor ultimately executes when running the WASM. I can provide a JavaScript example that *would* trigger the use of this code during WASM execution.

    * **Code Logic/Input/Output:**  For specific functions, I can provide examples. For instance, `emit_i32_add(r1, r2, r3)` takes register names as input and would *emit* the ARM instruction `add r1, r2, r3`. The actual *execution* behavior depends on the values in the registers at runtime. I can give hypothetical input register values and the resulting output register value.

    * **Common Programming Errors:** Since this code generates low-level assembly, typical user-level JavaScript errors aren't directly applicable. However, *if the Liftoff compiler itself had bugs* in generating these instructions, it could lead to incorrect WASM behavior. I can also point out potential WASM-level errors that *might* lead to these specific assembly instructions being executed in ways that cause issues (e.g., integer overflow, division by zero).

    * **Part 3 of 6:** This is just a meta-information point to acknowledge.

6. **Structure the Answer:**  I will organize the answer according to the points raised in the prompt, providing clear explanations and examples where requested. I'll start with the main functionality and then address each constraint systematically.

7. **Refine and Elaborate:** After the initial draft, I'll review and refine the answer, ensuring accuracy, clarity, and completeness. For example, when discussing JavaScript, I'll make the connection to WASM explicit. When providing code examples, I'll use clear variable names and explain what the code is doing.

By following these steps, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request.
这是对 V8 源代码文件 `v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h` 的第三部分代码的功能归纳。

**功能归纳 (基于提供的代码片段):**

这部分代码主要定义了 `LiftoffAssembler` 类中用于生成 ARM 汇编指令的方法，这些指令对应于 WebAssembly (Wasm) 的各种算术、逻辑、位运算和类型转换操作。 具体来说，这部分代码实现了以下功能：

**1. 整数运算 (32 位和 64 位):**

* **移位操作:**
    * `emit_i32_sar`, `emit_i32_sari`: 算术右移 32 位整数。
    * `emit_i32_shr`, `emit_i32_shri`: 逻辑右移 32 位整数。
    * `emit_i64_shl`, `emit_i64_shli`: 左移 64 位整数。
    * `emit_i64_sar`, `emit_i64_sari`: 算术右移 64 位整数。
    * `emit_i64_shr`, `emit_i64_shri`: 逻辑右移 64 位整数。
* **位计数操作:**
    * `emit_i32_clz`: 计算前导零的个数 (Count Leading Zeros)。
    * `emit_i32_ctz`: 计算尾部零的个数 (Count Trailing Zeros)。
    * `emit_i32_popcnt`: 计算 population count (设置了多少位)。
    * `emit_i64_clz`, `emit_i64_ctz`, `emit_i64_popcnt`: 64 位版本的位计数操作。
* **除法和求余操作:**
    * `emit_i32_divs`, `emit_i32_divu`: 有符号和无符号 32 位整数除法，带有除零陷阱处理。
    * `emit_i32_rems`, `emit_i32_remu`: 有符号和无符号 32 位整数求余，带有除零陷阱处理。
    * `emit_i64_add`, `emit_i64_addi`, `emit_i64_sub`, `emit_i64_mul`: 64 位整数的加法、带立即数的加法、减法和乘法。
    * `emit_i64_divs`, `emit_i64_divu`, `emit_i64_rems`, `emit_i64_remu`:  这些方法目前返回 `false`，表示 64 位整数的除法和求余操作尚未在此处实现 (可能通过调用 C++ fallback 或其他机制处理)。

**2. 浮点数运算 (32 位和 64 位):**

* **基本算术运算:**
    * `emit_f32_add`, `emit_f32_sub`, `emit_f32_mul`, `emit_f32_div`: 32 位浮点数的加、减、乘、除。
    * `emit_f64_add`, `emit_f64_sub`, `emit_f64_mul`, `emit_f64_div`: 64 位浮点数的加、减、乘、除。
* **其他运算:**
    * `emit_f32_abs`, `emit_f32_neg`, `emit_f32_sqrt`: 32 位浮点数的绝对值、取反、平方根。
    * `emit_f64_abs`, `emit_f64_neg`, `emit_f64_sqrt`: 64 位浮点数的绝对值、取反、平方根。
    * `emit_f32_ceil`, `emit_f32_floor`, `emit_f32_trunc`, `emit_f32_nearest_int`: 32 位浮点数的 ceiling、floor、截断和四舍五入到最接近的整数 (需要 ARMv8 支持)。
    * `emit_f64_ceil`, `emit_f64_floor`, `emit_f64_trunc`, `emit_f64_nearest_int`: 64 位浮点数的 ceiling、floor、截断和四舍五入到最接近的整数 (需要 ARMv8 支持)。
    * `emit_f32_min`, `emit_f32_max`: 32 位浮点数的最小值和最大值。
    * `emit_f64_min`, `emit_f64_max`: 64 位浮点数的最小值和最大值。
    * `emit_f32_copysign`, `emit_f64_copysign`: 复制符号位。

**3. 类型转换:**

* `emit_type_conversion`: 处理各种 Wasm 操作码指示的类型转换，例如：
    * 整数类型之间的转换 (`i32` 到 `i64`，反之亦然)。
    * 浮点数到整数的转换 (有符号和无符号，可能带有饱和转换)。
    * 整数到浮点数的转换 (单精度和双精度)。
    * 浮点数类型之间的转换 (单精度到双精度，反之亦然)。
    * 整数和浮点数之间的按位重新解释。
    * 某些 64 位相关的转换可能尚未在此处直接实现。

**4. 扩展操作:**

* `emit_i32_signextend_i8`, `emit_i32_signextend_i16`: 将 8 位或 16 位有符号整数扩展为 32 位。
* `emit_i64_signextend_i8`, `emit_i64_signextend_i16`, `emit_i64_signextend_i32`: 将 8 位、16 位或 32 位有符号整数扩展为 64 位。

**5. 控制流:**

* `emit_jump`: 生成无条件跳转指令。
* `emit_jump(Register target)`: 生成跳转到寄存器指定地址的指令。
* `emit_cond_jump`: 生成条件跳转指令。
* `emit_i32_cond_jumpi`: 生成与立即数比较的条件跳转指令。

**6. 比较和条件设置:**

* `emit_i32_eqz`: 检查 32 位整数是否为零。
* `emit_i32_set_cond`: 根据条件设置 32 位寄存器的值为 0 或 1。
* `emit_i64_eqz`: 检查 64 位整数是否为零。
* `emit_i64_set_cond`: 根据条件设置 32 位寄存器的值为 0 或 1 (针对 64 位比较)。
* `emit_f32_set_cond`, `emit_f64_set_cond`: 根据浮点数比较结果设置 32 位寄存器的值为 0 或 1。

**7. 选择操作:**

* `emit_select`: 根据条件选择两个值中的一个 (当前返回 `false`，可能尚未在此处实现)。

**8. 其他实用功能:**

* `IncrementSmi`: 递增一个 Smi (Small Integer)。
* `emit_smi_check`: 检查一个值是否是 Smi。
* `LoadTransform`: 从内存加载并进行转换 (例如，符号扩展)。

**关于代码的特点:**

* **目标架构:** 明确针对 ARM 架构。
* **Liftoff 编译器:**  属于 V8 中名为 "Liftoff" 的 baseline Wasm 编译器的组成部分。Liftoff 旨在快速生成代码，牺牲了一些优化。
* **内联头文件:**  `.inl.h` 后缀表明这是一个内联头文件，包含了函数的实现。
* **使用汇编指令宏:** 代码中使用了 V8 提供的汇编指令宏 (例如 `and_`, `asr`, `vadd` 等)，这些宏是对底层 ARM 汇编指令的封装。
* **寄存器分配和使用:** 代码中涉及到寄存器的分配和使用，例如 `Register`, `DoubleRegister`, `LiftoffRegister` 等类型。
* **条件编译:** 使用 `V8_LIKELY` 等宏进行性能优化。
* **CPU 特性检测:** 使用 `CpuFeatures::IsSupported` 来检查目标 CPU 是否支持某些指令 (例如 ARMv8 的浮点数指令)。
* **陷阱处理:**  对可能导致错误的运算 (例如除零) 生成跳转到陷阱标签的代码。

**关于 .tq 结尾：**

你提供的代码片段 `v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h` 的确没有以 `.tq` 结尾。因此，它不是 V8 Torque 源代码。Torque 是 V8 用于定义运行时内置函数和某些编译器组件的领域特定语言。

**与 JavaScript 的关系：**

这段代码是 V8 JavaScript 引擎的一部分，负责将 WebAssembly 代码编译成目标机器 (ARM) 的汇编指令。当 JavaScript 代码中调用 WebAssembly 模块时，V8 会使用 Liftoff 编译器（以及这段代码）将 Wasm 指令转换为 ARM 机器码，从而使浏览器能够执行 WebAssembly 代码。

**JavaScript 示例：**

```javascript
// 假设你有一个名为 'wasmCode' 的 ArrayBuffer 包含了 WebAssembly 字节码
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);

// 假设你的 Wasm 模块导出一个名为 'add' 的函数，它接收两个整数参数并返回它们的和
const result = wasmInstance.exports.add(5, 10);
console.log(result); // 输出 15
```

在这个例子中，当 `wasmInstance.exports.add(5, 10)` 被调用时，V8 引擎会执行以下操作：

1. 查找 `add` 函数对应的 WebAssembly 指令。
2. Liftoff 编译器 (包含 `liftoff-assembler-arm-inl.h` 中的代码) 会将 `add` 指令转换成相应的 ARM 汇编指令 (可能涉及到 `emit_i32_add` 或类似的函数)。
3. 生成的 ARM 汇编指令会在 CPU 上执行，计算 5 + 10 的结果。
4. 结果返回给 JavaScript 代码。

**代码逻辑推理与假设输入/输出：**

以 `emit_i32_sari(Register dst, Register src, int32_t amount)` 为例：

**假设输入：**

* `dst`:  代表目标寄存器的对象，假设对应 ARM 寄存器 `r0`。
* `src`:  代表源寄存器的对象，假设对应 ARM 寄存器 `r1`，其值为二进制 `0b11110000` (十进制 240)。
* `amount`: 整数值 `2`。

**代码逻辑：**

1. `if (V8_LIKELY((amount & 31) != 0))`：`2 & 31` 的结果是 2，不为 0，所以条件成立。
2. `asr(dst, src, Operand(amount & 31))`: 生成 ARM 汇编指令 `asr r0, r1, #2`。

**输出：**

生成的 ARM 汇编指令 `asr r0, r1, #2` 会将 `r1` 的值算术右移 2 位，结果存储在 `r0` 中。算术右移会保留符号位。

`r1` 的二进制值是 `0b11110000`。右移 2 位后，变成 `0b11111100` (十进制 -4)。

因此，假设执行该指令后，寄存器 `r0` 的值将为 -4。

**用户常见的编程错误举例：**

虽然这段代码是底层的汇编生成代码，用户通常不会直接编写或修改它。但是，如果 WebAssembly 代码中存在某些错误，可能会导致 Liftoff 编译器生成不期望的汇编指令，从而导致运行时错误。

例如，一个常见的错误是 **整数溢出**。假设 WebAssembly 代码尝试执行一个加法运算，其结果超出了整数类型的表示范围。虽然 Liftoff 会生成相应的加法指令，但结果可能会回绕，导致程序行为不正确。

**示例 (WebAssembly 代码层面)：**

```wasm
(module
  (func $add (param $p i32) (param $q i32) (result i32)
    local.get $p
    local.get $q
    i32.add
  )
  (export "add" (func $add))
)
```

如果 JavaScript 调用 `add` 函数时传入的值很大，例如 `wasmInstance.exports.add(2147483647, 1)` (接近 `i32` 的最大值)，`i32.add` 指令会导致溢出。Liftoff 会生成 ARM 的 `add` 指令，但结果会回绕到负数。

另一个常见的错误是 **除零错误**。在 WebAssembly 中，整数除以零是未定义的行为，会导致陷阱。Liftoff 会生成带有除零检查的除法指令，并在检测到除零时跳转到陷阱处理代码。

**总结：**

这段代码是 V8 JavaScript 引擎中 Liftoff WebAssembly 编译器的核心组成部分，负责将 WebAssembly 指令翻译成高效的 ARM 汇编代码，涵盖了各种算术、逻辑、位运算、类型转换和控制流操作。它确保了在 ARM 架构的设备上能够正确执行 WebAssembly 代码。虽然用户不会直接接触这段代码，但其正确性对于 WebAssembly 应用的稳定运行至关重要。

### 提示词
```
这是目录为v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/arm/liftoff-assembler-arm-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
sterScope temps(this);
  Register scratch = temps.Acquire();
  and_(scratch, amount, Operand(0x1f));
  asr(dst, src, Operand(scratch));
}
void LiftoffAssembler::emit_i32_sari(Register dst, Register src,
                                     int32_t amount) {
  if (V8_LIKELY((amount & 31) != 0)) {
    asr(dst, src, Operand(amount & 31));
  } else if (dst != src) {
    mov(dst, src);
  }
}

void LiftoffAssembler::emit_i32_shr(Register dst, Register src,
                                    Register amount) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  and_(scratch, amount, Operand(0x1f));
  lsr(dst, src, Operand(scratch));
}
void LiftoffAssembler::emit_i32_shri(Register dst, Register src,
                                     int32_t amount) {
  if (V8_LIKELY((amount & 31) != 0)) {
    lsr(dst, src, Operand(amount & 31));
  } else if (dst != src) {
    mov(dst, src);
  }
}

void LiftoffAssembler::emit_f32_add(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  vadd(liftoff::GetFloatRegister(dst), liftoff::GetFloatRegister(lhs),
       liftoff::GetFloatRegister(rhs));
}

void LiftoffAssembler::emit_f32_sub(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  vsub(liftoff::GetFloatRegister(dst), liftoff::GetFloatRegister(lhs),
       liftoff::GetFloatRegister(rhs));
}

void LiftoffAssembler::emit_f32_mul(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  vmul(liftoff::GetFloatRegister(dst), liftoff::GetFloatRegister(lhs),
       liftoff::GetFloatRegister(rhs));
}

void LiftoffAssembler::emit_f32_div(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  vdiv(liftoff::GetFloatRegister(dst), liftoff::GetFloatRegister(lhs),
       liftoff::GetFloatRegister(rhs));
}

void LiftoffAssembler::emit_f32_abs(DoubleRegister dst, DoubleRegister src) {
  vabs(liftoff::GetFloatRegister(dst), liftoff::GetFloatRegister(src));
}

void LiftoffAssembler::emit_f32_neg(DoubleRegister dst, DoubleRegister src) {
  vneg(liftoff::GetFloatRegister(dst), liftoff::GetFloatRegister(src));
}

void LiftoffAssembler::emit_f32_sqrt(DoubleRegister dst, DoubleRegister src) {
  vsqrt(liftoff::GetFloatRegister(dst), liftoff::GetFloatRegister(src));
}

void LiftoffAssembler::emit_f64_add(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  vadd(dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64_sub(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  vsub(dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64_mul(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  vmul(dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64_div(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  vdiv(dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64_abs(DoubleRegister dst, DoubleRegister src) {
  vabs(dst, src);
}

void LiftoffAssembler::emit_f64_neg(DoubleRegister dst, DoubleRegister src) {
  vneg(dst, src);
}

void LiftoffAssembler::emit_f64_sqrt(DoubleRegister dst, DoubleRegister src) {
  vsqrt(dst, src);
}

void LiftoffAssembler::emit_i32_clz(Register dst, Register src) {
  clz(dst, src);
}

void LiftoffAssembler::emit_i32_ctz(Register dst, Register src) {
  rbit(dst, src);
  clz(dst, dst);
}

namespace liftoff {
inline void GeneratePopCnt(Assembler* assm, Register dst, Register src,
                           Register scratch1, Register scratch2) {
  DCHECK(!AreAliased(dst, scratch1, scratch2));
  if (src == scratch1) std::swap(scratch1, scratch2);
  // x = x - ((x & (0x55555555 << 1)) >> 1)
  assm->and_(scratch1, src, Operand(0xaaaaaaaa));
  assm->sub(dst, src, Operand(scratch1, LSR, 1));
  // x = (x & 0x33333333) + ((x & (0x33333333 << 2)) >> 2)
  assm->mov(scratch1, Operand(0x33333333));
  assm->and_(scratch2, dst, Operand(scratch1, LSL, 2));
  assm->and_(scratch1, dst, scratch1);
  assm->add(dst, scratch1, Operand(scratch2, LSR, 2));
  // x = (x + (x >> 4)) & 0x0F0F0F0F
  assm->add(dst, dst, Operand(dst, LSR, 4));
  assm->and_(dst, dst, Operand(0x0f0f0f0f));
  // x = x + (x >> 8)
  assm->add(dst, dst, Operand(dst, LSR, 8));
  // x = x + (x >> 16)
  assm->add(dst, dst, Operand(dst, LSR, 16));
  // x = x & 0x3F
  assm->and_(dst, dst, Operand(0x3f));
}
}  // namespace liftoff

bool LiftoffAssembler::emit_i32_popcnt(Register dst, Register src) {
  LiftoffRegList pinned{dst};
  Register scratch1 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register scratch2 = GetUnusedRegister(kGpReg, pinned).gp();
  liftoff::GeneratePopCnt(this, dst, src, scratch1, scratch2);
  return true;
}

void LiftoffAssembler::emit_i32_divs(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  if (!CpuFeatures::IsSupported(SUDIV)) {
    bailout(kMissingCPUFeature, "i32_divs");
    return;
  }
  CpuFeatureScope scope(this, SUDIV);
  // Issue division early so we can perform the trapping checks whilst it
  // completes.
  bool speculative_sdiv = dst != lhs && dst != rhs;
  if (speculative_sdiv) {
    sdiv(dst, lhs, rhs);
  }
  Label noTrap;
  // Check for division by zero.
  cmp(rhs, Operand(0));
  b(trap_div_by_zero, eq);
  // Check for kMinInt / -1. This is unrepresentable.
  cmp(rhs, Operand(-1));
  b(&noTrap, ne);
  cmp(lhs, Operand(kMinInt));
  b(trap_div_unrepresentable, eq);
  bind(&noTrap);
  if (!speculative_sdiv) {
    sdiv(dst, lhs, rhs);
  }
}

void LiftoffAssembler::emit_i32_divu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  if (!CpuFeatures::IsSupported(SUDIV)) {
    bailout(kMissingCPUFeature, "i32_divu");
    return;
  }
  CpuFeatureScope scope(this, SUDIV);
  // Check for division by zero.
  cmp(rhs, Operand(0));
  b(trap_div_by_zero, eq);
  udiv(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_rems(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  if (!CpuFeatures::IsSupported(SUDIV)) {
    // When this case is handled, a check for ARMv7 is required to use mls.
    // Mls support is implied with SUDIV support.
    bailout(kMissingCPUFeature, "i32_rems");
    return;
  }
  CpuFeatureScope scope(this, SUDIV);
  // No need to check kMinInt / -1 because the result is kMinInt and then
  // kMinInt * -1 -> kMinInt. In this case, the Msub result is therefore 0.
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  sdiv(scratch, lhs, rhs);
  // Check for division by zero.
  cmp(rhs, Operand(0));
  b(trap_div_by_zero, eq);
  // Compute remainder.
  mls(dst, scratch, rhs, lhs);
}

void LiftoffAssembler::emit_i32_remu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  if (!CpuFeatures::IsSupported(SUDIV)) {
    // When this case is handled, a check for ARMv7 is required to use mls.
    // Mls support is implied with SUDIV support.
    bailout(kMissingCPUFeature, "i32_remu");
    return;
  }
  CpuFeatureScope scope(this, SUDIV);
  // No need to check kMinInt / -1 because the result is kMinInt and then
  // kMinInt * -1 -> kMinInt. In this case, the Msub result is therefore 0.
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  udiv(scratch, lhs, rhs);
  // Check for division by zero.
  cmp(rhs, Operand(0));
  b(trap_div_by_zero, eq);
  // Compute remainder.
  mls(dst, scratch, rhs, lhs);
}

void LiftoffAssembler::emit_i64_add(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  liftoff::I64Binop<&Assembler::add, &Assembler::adc>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64_addi(LiftoffRegister dst, LiftoffRegister lhs,
                                     int64_t imm) {
  liftoff::I64BinopI<&Assembler::add, &Assembler::adc>(this, dst, lhs, imm);
}

void LiftoffAssembler::emit_i64_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  liftoff::I64Binop<&Assembler::sub, &Assembler::sbc>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  // Idea:
  //        [           lhs_hi  |           lhs_lo  ] * [  rhs_hi  |  rhs_lo  ]
  //    =   [  lhs_hi * rhs_lo  |                   ]  (32 bit mul, shift 32)
  //      + [  lhs_lo * rhs_hi  |                   ]  (32 bit mul, shift 32)
  //      + [             lhs_lo * rhs_lo           ]  (32x32->64 mul, shift 0)
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  // scratch = lhs_hi * rhs_lo
  mul(scratch, lhs.high_gp(), rhs.low_gp());
  // scratch += lhs_lo * rhs_hi
  mla(scratch, lhs.low_gp(), rhs.high_gp(), scratch);
  // TODO(arm): use umlal once implemented correctly in the simulator.
  // [dst_hi|dst_lo] = lhs_lo * rhs_lo
  umull(dst.low_gp(), dst.high_gp(), lhs.low_gp(), rhs.low_gp());
  // dst_hi += scratch
  add(dst.high_gp(), dst.high_gp(), scratch);
}

bool LiftoffAssembler::emit_i64_divs(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  return false;
}

bool LiftoffAssembler::emit_i64_divu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  return false;
}

bool LiftoffAssembler::emit_i64_rems(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  return false;
}

bool LiftoffAssembler::emit_i64_remu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  return false;
}

void LiftoffAssembler::emit_i64_shl(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  liftoff::I64Shiftop<&MacroAssembler::LslPair, true>(this, dst, src, amount);
}

void LiftoffAssembler::emit_i64_shli(LiftoffRegister dst, LiftoffRegister src,
                                     int32_t amount) {
  UseScratchRegisterScope temps(this);
  // {src.low_gp()} will still be needed after writing {dst.high_gp()}.
  Register src_low =
      liftoff::EnsureNoAlias(this, src.low_gp(), dst.high_gp(), &temps);

  LslPair(dst.low_gp(), dst.high_gp(), src_low, src.high_gp(), amount & 63);
}

void LiftoffAssembler::emit_i64_sar(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  liftoff::I64Shiftop<&MacroAssembler::AsrPair, false>(this, dst, src, amount);
}

void LiftoffAssembler::emit_i64_sari(LiftoffRegister dst, LiftoffRegister src,
                                     int32_t amount) {
  UseScratchRegisterScope temps(this);
  // {src.high_gp()} will still be needed after writing {dst.low_gp()}.
  Register src_high =
      liftoff::EnsureNoAlias(this, src.high_gp(), dst.low_gp(), &temps);

  AsrPair(dst.low_gp(), dst.high_gp(), src.low_gp(), src_high, amount & 63);
}

void LiftoffAssembler::emit_i64_shr(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  liftoff::I64Shiftop<&MacroAssembler::LsrPair, false>(this, dst, src, amount);
}

void LiftoffAssembler::emit_i64_shri(LiftoffRegister dst, LiftoffRegister src,
                                     int32_t amount) {
  UseScratchRegisterScope temps(this);
  // {src.high_gp()} will still be needed after writing {dst.low_gp()}.
  Register src_high =
      liftoff::EnsureNoAlias(this, src.high_gp(), dst.low_gp(), &temps);

  LsrPair(dst.low_gp(), dst.high_gp(), src.low_gp(), src_high, amount & 63);
}

void LiftoffAssembler::emit_i64_clz(LiftoffRegister dst, LiftoffRegister src) {
  // return high == 0 ? 32 + CLZ32(low) : CLZ32(high);
  Label done;
  Label high_is_zero;
  cmp(src.high_gp(), Operand(0));
  b(&high_is_zero, eq);

  clz(dst.low_gp(), src.high_gp());
  jmp(&done);

  bind(&high_is_zero);
  clz(dst.low_gp(), src.low_gp());
  add(dst.low_gp(), dst.low_gp(), Operand(32));

  bind(&done);
  mov(dst.high_gp(), Operand(0));  // High word of result is always 0.
}

void LiftoffAssembler::emit_i64_ctz(LiftoffRegister dst, LiftoffRegister src) {
  // return low == 0 ? 32 + CTZ32(high) : CTZ32(low);
  // CTZ32(x) = CLZ(RBIT(x))
  Label done;
  Label low_is_zero;
  cmp(src.low_gp(), Operand(0));
  b(&low_is_zero, eq);

  rbit(dst.low_gp(), src.low_gp());
  clz(dst.low_gp(), dst.low_gp());
  jmp(&done);

  bind(&low_is_zero);
  rbit(dst.low_gp(), src.high_gp());
  clz(dst.low_gp(), dst.low_gp());
  add(dst.low_gp(), dst.low_gp(), Operand(32));

  bind(&done);
  mov(dst.high_gp(), Operand(0));  // High word of result is always 0.
}

bool LiftoffAssembler::emit_i64_popcnt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  // Produce partial popcnts in the two dst registers, making sure not to
  // overwrite the second src register before using it.
  Register src1 = src.high_gp() == dst.low_gp() ? src.high_gp() : src.low_gp();
  Register src2 = src.high_gp() == dst.low_gp() ? src.low_gp() : src.high_gp();
  LiftoffRegList pinned{dst, src2};
  Register scratch1 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register scratch2 = GetUnusedRegister(kGpReg, pinned).gp();
  liftoff::GeneratePopCnt(this, dst.low_gp(), src1, scratch1, scratch2);
  liftoff::GeneratePopCnt(this, dst.high_gp(), src2, scratch1, scratch2);
  // Now add the two into the lower dst reg and clear the higher dst reg.
  add(dst.low_gp(), dst.low_gp(), dst.high_gp());
  mov(dst.high_gp(), Operand(0));
  return true;
}

void LiftoffAssembler::IncrementSmi(LiftoffRegister dst, int offset) {
  if (!is_int12(offset)) {
    // For large offsets, ldr/str will need a scratch register, but we need
    // the single available scratch register here. So fold the offset into the
    // base address.
    // Note: if we ever want to use this function for callers that don't want
    // {dst} to get clobbered, we could spill it to the stack and restore it
    // later.
    add(dst.gp(), dst.gp(), Operand(offset));
    offset = 0;
  }
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  ldr(scratch, MemOperand(dst.gp(), offset));
  add(scratch, scratch, Operand(Smi::FromInt(1)));
  str(scratch, MemOperand(dst.gp(), offset));
}

bool LiftoffAssembler::emit_f32_ceil(DoubleRegister dst, DoubleRegister src) {
  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(this, ARMv8);
    vrintp(liftoff::GetFloatRegister(dst), liftoff::GetFloatRegister(src));
    return true;
  }
  return false;
}

bool LiftoffAssembler::emit_f32_floor(DoubleRegister dst, DoubleRegister src) {
  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(this, ARMv8);
    vrintm(liftoff::GetFloatRegister(dst), liftoff::GetFloatRegister(src));
    return true;
  }
  return false;
}

bool LiftoffAssembler::emit_f32_trunc(DoubleRegister dst, DoubleRegister src) {
  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(this, ARMv8);
    vrintz(liftoff::GetFloatRegister(dst), liftoff::GetFloatRegister(src));
    return true;
  }
  return false;
}

bool LiftoffAssembler::emit_f32_nearest_int(DoubleRegister dst,
                                            DoubleRegister src) {
  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(this, ARMv8);
    vrintn(liftoff::GetFloatRegister(dst), liftoff::GetFloatRegister(src));
    return true;
  }
  return false;
}

void LiftoffAssembler::emit_f32_min(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  liftoff::EmitFloatMinOrMax(
      this, liftoff::GetFloatRegister(dst), liftoff::GetFloatRegister(lhs),
      liftoff::GetFloatRegister(rhs), liftoff::MinOrMax::kMin);
}

void LiftoffAssembler::emit_f32_max(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  liftoff::EmitFloatMinOrMax(
      this, liftoff::GetFloatRegister(dst), liftoff::GetFloatRegister(lhs),
      liftoff::GetFloatRegister(rhs), liftoff::MinOrMax::kMax);
}

bool LiftoffAssembler::emit_f64_ceil(DoubleRegister dst, DoubleRegister src) {
  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(this, ARMv8);
    vrintp(dst, src);
    return true;
  }
  return false;
}

bool LiftoffAssembler::emit_f64_floor(DoubleRegister dst, DoubleRegister src) {
  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(this, ARMv8);
    vrintm(dst, src);
    return true;
  }
  return false;
}

bool LiftoffAssembler::emit_f64_trunc(DoubleRegister dst, DoubleRegister src) {
  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(this, ARMv8);
    vrintz(dst, src);
    return true;
  }
  return false;
}

bool LiftoffAssembler::emit_f64_nearest_int(DoubleRegister dst,
                                            DoubleRegister src) {
  if (CpuFeatures::IsSupported(ARMv8)) {
    CpuFeatureScope scope(this, ARMv8);
    vrintn(dst, src);
    return true;
  }
  return false;
}

void LiftoffAssembler::emit_f64_min(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  liftoff::EmitFloatMinOrMax(this, dst, lhs, rhs, liftoff::MinOrMax::kMin);
}

void LiftoffAssembler::emit_f64_max(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  liftoff::EmitFloatMinOrMax(this, dst, lhs, rhs, liftoff::MinOrMax::kMax);
}

void LiftoffAssembler::emit_f32_copysign(DoubleRegister dst, DoubleRegister lhs,
                                         DoubleRegister rhs) {
  constexpr uint32_t kF32SignBit = uint32_t{1} << 31;
  UseScratchRegisterScope temps(this);
  Register scratch = GetUnusedRegister(kGpReg, {}).gp();
  Register scratch2 = temps.Acquire();
  VmovLow(scratch, lhs);
  // Clear sign bit in {scratch}.
  bic(scratch, scratch, Operand(kF32SignBit));
  VmovLow(scratch2, rhs);
  // Isolate sign bit in {scratch2}.
  and_(scratch2, scratch2, Operand(kF32SignBit));
  // Combine {scratch2} into {scratch}.
  orr(scratch, scratch, scratch2);
  VmovLow(dst, scratch);
}

void LiftoffAssembler::emit_f64_copysign(DoubleRegister dst, DoubleRegister lhs,
                                         DoubleRegister rhs) {
  constexpr uint32_t kF64SignBitHighWord = uint32_t{1} << 31;
  // On arm, we cannot hold the whole f64 value in a gp register, so we just
  // operate on the upper half (UH).
  UseScratchRegisterScope temps(this);
  Register scratch = GetUnusedRegister(kGpReg, {}).gp();
  Register scratch2 = temps.Acquire();
  VmovHigh(scratch, lhs);
  // Clear sign bit in {scratch}.
  bic(scratch, scratch, Operand(kF64SignBitHighWord));
  VmovHigh(scratch2, rhs);
  // Isolate sign bit in {scratch2}.
  and_(scratch2, scratch2, Operand(kF64SignBitHighWord));
  // Combine {scratch2} into {scratch}.
  orr(scratch, scratch, scratch2);
  vmov(dst, lhs);
  VmovHigh(dst, scratch);
}

bool LiftoffAssembler::emit_type_conversion(WasmOpcode opcode,
                                            LiftoffRegister dst,
                                            LiftoffRegister src, Label* trap) {
  switch (opcode) {
    case kExprI32ConvertI64:
      MacroAssembler::Move(dst.gp(), src.low_gp());
      return true;
    case kExprI32SConvertF32: {
      UseScratchRegisterScope temps(this);
      SwVfpRegister scratch_f = temps.AcquireS();
      vcvt_s32_f32(
          scratch_f,
          liftoff::GetFloatRegister(src.fp()));  // f32 -> i32 round to zero.
      vmov(dst.gp(), scratch_f);
      // Check underflow and NaN.
      vmov(scratch_f, Float32(static_cast<float>(INT32_MIN)));
      VFPCompareAndSetFlags(liftoff::GetFloatRegister(src.fp()), scratch_f);
      b(trap, lt);
      // Check overflow.
      cmp(dst.gp(), Operand(-1));
      b(trap, vs);
      return true;
    }
    case kExprI32UConvertF32: {
      UseScratchRegisterScope temps(this);
      SwVfpRegister scratch_f = temps.AcquireS();
      vcvt_u32_f32(
          scratch_f,
          liftoff::GetFloatRegister(src.fp()));  // f32 -> i32 round to zero.
      vmov(dst.gp(), scratch_f);
      // Check underflow and NaN.
      vmov(scratch_f, Float32(-1.0f));
      VFPCompareAndSetFlags(liftoff::GetFloatRegister(src.fp()), scratch_f);
      b(trap, le);
      // Check overflow.
      cmp(dst.gp(), Operand(-1));
      b(trap, eq);
      return true;
    }
    case kExprI32SConvertF64: {
      UseScratchRegisterScope temps(this);
      SwVfpRegister scratch_f = temps.AcquireS();
      vcvt_s32_f64(scratch_f, src.fp());  // f64 -> i32 round to zero.
      vmov(dst.gp(), scratch_f);
      // Check underflow and NaN.
      DwVfpRegister scratch_d = temps.AcquireD();
      vmov(scratch_d, base::Double(static_cast<double>(INT32_MIN - 1.0)));
      VFPCompareAndSetFlags(src.fp(), scratch_d);
      b(trap, le);
      // Check overflow.
      vmov(scratch_d, base::Double(static_cast<double>(INT32_MAX + 1.0)));
      VFPCompareAndSetFlags(src.fp(), scratch_d);
      b(trap, ge);
      return true;
    }
    case kExprI32UConvertF64: {
      UseScratchRegisterScope temps(this);
      SwVfpRegister scratch_f = temps.AcquireS();
      vcvt_u32_f64(scratch_f, src.fp());  // f64 -> i32 round to zero.
      vmov(dst.gp(), scratch_f);
      // Check underflow and NaN.
      DwVfpRegister scratch_d = temps.AcquireD();
      vmov(scratch_d, base::Double(static_cast<double>(-1.0)));
      VFPCompareAndSetFlags(src.fp(), scratch_d);
      b(trap, le);
      // Check overflow.
      vmov(scratch_d, base::Double(static_cast<double>(UINT32_MAX + 1.0)));
      VFPCompareAndSetFlags(src.fp(), scratch_d);
      b(trap, ge);
      return true;
    }
    case kExprI32SConvertSatF32: {
      UseScratchRegisterScope temps(this);
      SwVfpRegister scratch_f = temps.AcquireS();
      vcvt_s32_f32(
          scratch_f,
          liftoff::GetFloatRegister(src.fp()));  // f32 -> i32 round to zero.
      vmov(dst.gp(), scratch_f);
      return true;
    }
    case kExprI32UConvertSatF32: {
      UseScratchRegisterScope temps(this);
      SwVfpRegister scratch_f = temps.AcquireS();
      vcvt_u32_f32(
          scratch_f,
          liftoff::GetFloatRegister(src.fp()));  // f32 -> u32 round to zero.
      vmov(dst.gp(), scratch_f);
      return true;
    }
    case kExprI32SConvertSatF64: {
      UseScratchRegisterScope temps(this);
      SwVfpRegister scratch_f = temps.AcquireS();
      vcvt_s32_f64(scratch_f, src.fp());  // f64 -> i32 round to zero.
      vmov(dst.gp(), scratch_f);
      return true;
    }
    case kExprI32UConvertSatF64: {
      UseScratchRegisterScope temps(this);
      SwVfpRegister scratch_f = temps.AcquireS();
      vcvt_u32_f64(scratch_f, src.fp());  // f64 -> u32 round to zero.
      vmov(dst.gp(), scratch_f);
      return true;
    }
    case kExprI32ReinterpretF32:
      vmov(dst.gp(), liftoff::GetFloatRegister(src.fp()));
      return true;
    case kExprI64SConvertI32:
      if (dst.low_gp() != src.gp()) mov(dst.low_gp(), src.gp());
      mov(dst.high_gp(), Operand(src.gp(), ASR, 31));
      return true;
    case kExprI64UConvertI32:
      if (dst.low_gp() != src.gp()) mov(dst.low_gp(), src.gp());
      mov(dst.high_gp(), Operand(0));
      return true;
    case kExprI64ReinterpretF64:
      vmov(dst.low_gp(), dst.high_gp(), src.fp());
      return true;
    case kExprF32SConvertI32: {
      SwVfpRegister dst_float = liftoff::GetFloatRegister(dst.fp());
      vmov(dst_float, src.gp());
      vcvt_f32_s32(dst_float, dst_float);
      return true;
    }
    case kExprF32UConvertI32: {
      SwVfpRegister dst_float = liftoff::GetFloatRegister(dst.fp());
      vmov(dst_float, src.gp());
      vcvt_f32_u32(dst_float, dst_float);
      return true;
    }
    case kExprF32ConvertF64:
      vcvt_f32_f64(liftoff::GetFloatRegister(dst.fp()), src.fp());
      return true;
    case kExprF32ReinterpretI32:
      vmov(liftoff::GetFloatRegister(dst.fp()), src.gp());
      return true;
    case kExprF64SConvertI32: {
      vmov(liftoff::GetFloatRegister(dst.fp()), src.gp());
      vcvt_f64_s32(dst.fp(), liftoff::GetFloatRegister(dst.fp()));
      return true;
    }
    case kExprF64UConvertI32: {
      vmov(liftoff::GetFloatRegister(dst.fp()), src.gp());
      vcvt_f64_u32(dst.fp(), liftoff::GetFloatRegister(dst.fp()));
      return true;
    }
    case kExprF64ConvertF32:
      vcvt_f64_f32(dst.fp(), liftoff::GetFloatRegister(src.fp()));
      return true;
    case kExprF64ReinterpretI64:
      vmov(dst.fp(), src.low_gp(), src.high_gp());
      return true;
    case kExprF64SConvertI64:
    case kExprF64UConvertI64:
    case kExprI64SConvertF32:
    case kExprI64UConvertF32:
    case kExprI64SConvertSatF32:
    case kExprI64UConvertSatF32:
    case kExprF32SConvertI64:
    case kExprF32UConvertI64:
    case kExprI64SConvertF64:
    case kExprI64UConvertF64:
    case kExprI64SConvertSatF64:
    case kExprI64UConvertSatF64:
      // These cases can be handled by the C fallback function.
      return false;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::emit_i32_signextend_i8(Register dst, Register src) {
  sxtb(dst, src);
}

void LiftoffAssembler::emit_i32_signextend_i16(Register dst, Register src) {
  sxth(dst, src);
}

void LiftoffAssembler::emit_i64_signextend_i8(LiftoffRegister dst,
                                              LiftoffRegister src) {
  emit_i32_signextend_i8(dst.low_gp(), src.low_gp());
  mov(dst.high_gp(), Operand(dst.low_gp(), ASR, 31));
}

void LiftoffAssembler::emit_i64_signextend_i16(LiftoffRegister dst,
                                               LiftoffRegister src) {
  emit_i32_signextend_i16(dst.low_gp(), src.low_gp());
  mov(dst.high_gp(), Operand(dst.low_gp(), ASR, 31));
}

void LiftoffAssembler::emit_i64_signextend_i32(LiftoffRegister dst,
                                               LiftoffRegister src) {
  MacroAssembler::Move(dst.low_gp(), src.low_gp());
  mov(dst.high_gp(), Operand(src.low_gp(), ASR, 31));
}

void LiftoffAssembler::emit_jump(Label* label) { b(label); }

void LiftoffAssembler::emit_jump(Register target) { bx(target); }

void LiftoffAssembler::emit_cond_jump(Condition cond, Label* label,
                                      ValueKind kind, Register lhs,
                                      Register rhs,
                                      const FreezeCacheState& frozen) {
  if (rhs == no_reg) {
    DCHECK_EQ(kind, kI32);
    cmp(lhs, Operand(0));
  } else {
    DCHECK(kind == kI32 ||
           (is_reference(kind) && (cond == kEqual || cond == kNotEqual)));
    cmp(lhs, rhs);
  }
  b(label, cond);
}

void LiftoffAssembler::emit_i32_cond_jumpi(Condition cond, Label* label,
                                           Register lhs, int32_t imm,
                                           const FreezeCacheState& frozen) {
  cmp(lhs, Operand(imm));
  b(label, cond);
}

void LiftoffAssembler::emit_i32_eqz(Register dst, Register src) {
  clz(dst, src);
  mov(dst, Operand(dst, LSR, kRegSizeInBitsLog2));
}

void LiftoffAssembler::emit_i32_set_cond(Condition cond, Register dst,
                                         Register lhs, Register rhs) {
  cmp(lhs, rhs);
  mov(dst, Operand(0), LeaveCC);
  mov(dst, Operand(1), LeaveCC, cond);
}

void LiftoffAssembler::emit_i64_eqz(Register dst, LiftoffRegister src) {
  orr(dst, src.low_gp(), src.high_gp());
  clz(dst, dst);
  mov(dst, Operand(dst, LSR, 5));
}

void LiftoffAssembler::emit_i64_set_cond(Condition cond, Register dst,
                                         LiftoffRegister lhs,
                                         LiftoffRegister rhs) {
  // For signed i64 comparisons, we still need to use unsigned comparison for
  // the low word (the only bit carrying signedness information is the MSB in
  // the high word).
  Condition unsigned_cond = liftoff::MakeUnsigned(cond);
  Label set_cond;
  Label cont;
  LiftoffRegister dest = LiftoffRegister(dst);
  bool speculative_move = !dest.overlaps(lhs) && !dest.overlaps(rhs);
  if (speculative_move) {
    mov(dst, Operand(0));
  }
  // Compare high word first. If it differs, use it for the set_cond. If it's
  // equal, compare the low word and use that for set_cond.
  cmp(lhs.high_gp(), rhs.high_gp());
  if (unsigned_cond == cond) {
    cmp(lhs.low_gp(), rhs.low_gp(), eq);
    if (!speculative_move) {
      mov(dst, Operand(0));
    }
    mov(dst, Operand(1), LeaveCC, cond);
  } else {
    // If the condition predicate for the low differs from that for the high
    // word, the conditional move instructions must be separated.
    b(ne, &set_cond);
    cmp(lhs.low_gp(), rhs.low_gp());
    if (!speculative_move) {
      mov(dst, Operand(0));
    }
    mov(dst, Operand(1), LeaveCC, unsigned_cond);
    b(&cont);
    bind(&set_cond);
    if (!speculative_move) {
      mov(dst, Operand(0));
    }
    mov(dst, Operand(1), LeaveCC, cond);
    bind(&cont);
  }
}

void LiftoffAssembler::emit_f32_set_cond(Condition cond, Register dst,
                                         DoubleRegister lhs,
                                         DoubleRegister rhs) {
  VFPCompareAndSetFlags(liftoff::GetFloatRegister(lhs),
                        liftoff::GetFloatRegister(rhs));
  mov(dst, Operand(0), LeaveCC);
  mov(dst, Operand(1), LeaveCC, cond);
  if (cond != ne) {
    // If V flag set, at least one of the arguments was a Nan -> false.
    mov(dst, Operand(0), LeaveCC, vs);
  }
}

void LiftoffAssembler::emit_f64_set_cond(Condition cond, Register dst,
                                         DoubleRegister lhs,
                                         DoubleRegister rhs) {
  VFPCompareAndSetFlags(lhs, rhs);
  mov(dst, Operand(0), LeaveCC);
  mov(dst, Operand(1), LeaveCC, cond);
  if (cond != ne) {
    // If V flag set, at least one of the arguments was a Nan -> false.
    mov(dst, Operand(0), LeaveCC, vs);
  }
}

bool LiftoffAssembler::emit_select(LiftoffRegister dst, Register condition,
                                   LiftoffRegister true_value,
                                   LiftoffRegister false_value,
                                   ValueKind kind) {
  return false;
}

void LiftoffAssembler::emit_smi_check(Register obj, Label* target,
                                      SmiCheckMode mode,
                                      const FreezeCacheState& frozen) {
  tst(obj, Operand(kSmiTagMask));
  Condition condition = mode == kJumpOnSmi ? eq : ne;
  b(condition, target);
}

void LiftoffAssembler::LoadTransform(LiftoffRegister dst, Register src_addr,
                                     Register offset_reg, uintptr_t offset_imm,
                                     LoadType type,
                                     LoadTransformationKind transform,
                                     uint32_t* protected_load_pc) {
  UseScratchRegisterScope temps(this);
  Register actual_src_addr = liftoff::CalculateActualAddress(
      this, &temps, src_addr, offset_reg, offset_imm);
  *protected_load_pc = pc_offset();
  MachineType memtype = type.mem_type();

  if (transform == LoadTransformationKind::kExtend) {
    if (memtype == MachineType::Int8()) {
      vld1(Neon8, NeonListOperand(dst.low_fp()),
           NeonMemOperand(actual_src_addr));
      vmovl(NeonS8, liftoff::GetSimd128Register(dst), dst.low_fp());
    } else if (memtype == MachineType::Uint8()) {
      vld1(Neon8, NeonListOperand(dst.low_fp()),
           NeonMemOperand(actual_src_addr));
      vmovl(NeonU8, liftoff::GetSimd128Register(dst), dst.low_fp());
    } else if (memtype == MachineType::Int16()) {
      vld1(Neon16, NeonListOperand(dst.low_fp()),
           NeonMemOperand(actual_src_addr));
      vmovl(NeonS16, liftoff::GetSimd128Register(dst), dst.low_fp());
    } else if (memtype == MachineType::Uint16()) {
      vld1(Neon16, NeonListOperand(dst.low_fp()),
           NeonMemOperand(actual_src_addr));
      vmovl(NeonU16, liftoff::GetSimd128Register(dst), dst.low_fp());
    } else if (memtype == MachineType::Int32()) {
      vld1(Neon32, NeonListOperand(dst.low_fp()),
           NeonMemOperand(actual_src_addr));
      vmovl(NeonS32, liftoff::GetSimd128Register(dst), dst.low_fp());
    } else if (memtype == MachineType::Uint32()) {
      vld1(Neon32, NeonListOperand(dst.low_fp()),
```