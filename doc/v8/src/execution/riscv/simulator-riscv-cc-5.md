Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/execution/riscv/simulator-riscv.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The filename `simulator-riscv.cc` strongly suggests this code simulates the execution of RISC-V instructions. The content confirms this, showing code that interprets different RISC-V instruction formats and their corresponding operations.

2. **Categorize the functionality:**  The code is organized around decoding and executing different types of RISC-V instructions. The major categories that emerge are:
    * Integer operations (implicit through register setting and memory access, though not explicitly detailed in this snippet).
    * Floating-point operations (explicitly handled by functions like `CanonicalizeFPUOp2`, `RoundF2IHelper`, and comparisons).
    * Atomic operations (identified by the `DecodeRVRAType` function and operations like `LR.W`, `SC.W`, `AMOSWAP.W`, etc.).
    * Vector operations (present under `#ifdef CAN_USE_RVV_INSTRUCTIONS`).

3. **Analyze specific code blocks:**
    * **Floating-point conversion:** The `RoundF2IHelper` function is crucial for converting floating-point numbers to integers, handling overflow and underflow.
    * **Floating-point classification:** `FclassHelper` determines the type of a floating-point number (infinity, NaN, normal, subnormal, zero).
    * **Floating-point comparison:** `CompareFHelper` implements floating-point comparisons, considering NaN and signaling NaNs.
    * **Invalid floating-point operations:**  `is_invalid_fmul`, `is_invalid_fadd`, etc., detect cases that result in NaN.
    * **Atomic operations:** The `DecodeRVRAType` function handles load-reserved/store-conditional (`LR.W`, `SC.W`) and various atomic memory operations (`AMOSWAP.W`, `AMOADD.W`, etc.). It uses mutexes for synchronization.
    * **Vector operations:** The `DecodeRvvVL` and `DecodeRvvVS` functions (under the `#ifdef`) indicate support for RISC-V vector instructions.

4. **Address specific user requests:**
    * **`.tq` extension:** The code is C++, so it's not a Torque file.
    * **Relationship to JavaScript:**  As a simulator for the RISC-V architecture, it directly enables V8 to run JavaScript code on RISC-V processors. The simulated instructions are the low-level operations that execute the higher-level JavaScript code. A simple example is variable assignment in JavaScript, which would likely translate to register moves or memory writes in the simulated RISC-V code.
    * **Code logic推理 (reasoning):**  Focus on `RoundF2IHelper`. Identify the input (a floating-point number, the target integer type), the core logic (rounding and clamping to the integer limits), and potential output (the rounded integer or the maximum/minimum integer value).
    * **Common programming errors:**  Highlight floating-point to integer conversion issues (truncation, overflow, NaN handling) as a common source of errors.
    * **Function summarization:** Consolidate the identified functionalities into a concise summary.

5. **Structure the response:** Organize the information logically with clear headings for each point requested by the user. Use bullet points for lists of functionalities. Provide a concrete JavaScript example and a clear explanation of the code logic inference.

6. **Refine and review:** Ensure the language is clear, accurate, and addresses all parts of the user's request. For example, initially, I might just say "handles floating-point operations."  Refining this to include details about conversions, comparisons, and NaN handling makes the answer more comprehensive.

By following these steps, we can generate a detailed and informative answer that effectively addresses the user's request about the functionality of the provided C++ code.
```
功能列举:

- **浮点数转换为整数:**
    - `RoundF2IHelper`:  将浮点数（单精度或双精度）转换为有符号或无符号的整数 (32位或64位)。
    - 它处理舍入模式，并检查上溢和下溢，设置相应的浮点异常标志。

- **浮点数分类:**
    - `FclassHelper`:  确定浮点数的类别，例如正无穷、负无穷、NaN（Signaling NaN 或 Quiet NaN）、正/负普通数、正/负次正规数、正/负零。

- **浮点数比较:**
    - `CompareFHelper`:  比较两个浮点数（单精度或双精度），并根据比较结果（小于、小于等于、等于、不等于）返回布尔值。
    - 对于 signaling NaN 的比较，它会设置无效操作的浮点异常标志。

- **检测无效的浮点运算:**
    - `is_invalid_fmul`, `is_invalid_fadd`, `is_invalid_fsub`, `is_invalid_fdiv`, `is_invalid_fsqrt`:  这些内联函数用于检测会导致产生 NaN 结果的特定浮点运算（例如，无穷乘以零，无穷加减符号相反的无穷，零除以零，无穷除以无穷，负数的平方根）。

- **RISC-V 原子操作指令的解码和模拟:**
    - `DecodeRVRAType`:  解码并模拟 RISC-V 原子操作指令 (A 扩展指令)。
    - 包括 `LR.W` (Load Reserved Word), `SC.W` (Store Conditional Word), 以及各种原子内存操作 (AMO)，如 `AMOSWAP.W`, `AMOADD.W`, `AMOXOR.W` 等，以及它们的双字版本 (在 RISC-V 64位架构下)。
    - 使用互斥锁 (`base::MutexGuard`) 来模拟原子操作的互斥性。
    - 涉及本地监视器 (`local_monitor_`) 和全局监视器 (`GlobalMonitor::Get()`) 来跟踪 load-reserved 和 store-conditional 操作。

- **RISC-V 浮点运算指令的解码和模拟:**
    - `DecodeRVRFPType`:  解码并模拟 RISC-V 浮点运算指令 (F 和 D 扩展指令)。
    - 包括加法 (`FADD.S`, `FADD.D`), 减法 (`FSUB.S`, `FSUB.D`), 乘法 (`FMUL.S`, `FMUL.D`), 除法 (`FDIV.S`, `FDIV.D`), 平方根 (`FSQRT.S`, `FSQRT.D`)。
    - 包括符号注入 (`FSGNJ.S`, `FSGNJN.S`, `FSGNJX.S`, 以及双精度版本)。
    - 包括最小值/最大值 (`FMIN.S`, `FMAX.S`, 以及双精度版本)。
    - 包括浮点数到整数的转换 (`FCVT.W.S`, `FCVT.WU.S`, `FCVT.L.S`, `FCVT.LU.S`, 以及双精度版本)。
    - 包括整数到浮点数的转换 (`FCVT.S.W`, `FCVT.S.WU`, `FCVT.S.L`, `FCVT.S.LU`, 以及双精度版本)。
    - 包括浮点数的移动 (`FMV.X.W`, `FMV.W.X`, 以及双精度版本)。
    - 包括浮点数的分类 (`FCLASS.S`, `FCLASS.D`)。
    - 包括浮点数比较 (`FLE.S`, `FEQ.S`, `FLT.S`, 以及双精度版本)。

- **RISC-V 四操作数浮点运算指令的解码和模拟:**
    - `DecodeRVR4Type`: 解码并模拟 RISC-V 四操作数的融合乘加/减指令 (F 和 D 扩展指令)。
    - 包括融合乘加 (`FMADD.S`, `FMADD.D`), 融合乘减 (`FMSUB.S`, `FMSUB.D`), 负融合乘减 (`FNMSUB.S`, `FNMSUB.D`), 负融合乘加 (`FNMADD.S`, `FNMADD.D`)。

- **RISC-V 向量指令的解码和模拟 (如果启用):**
    - `DecodeRvvVL`, `DecodeRvvVS`:  在定义了 `CAN_USE_RVV_INSTRUCTIONS` 宏的情况下，解码和模拟 RISC-V 向量加载和存储指令。目前的代码中这些函数大部分是 `UNIMPLEMENTED_RISCV()`，意味着这些功能尚未完全实现。

- **辅助函数:**
    - `CanonicalizeFPUOp1`, `CanonicalizeFPUOp2`, `CanonicalizeFPUOp3`: 用于规范化浮点运算的结果，处理 NaN 的表示。
    - `FMaxMinHelper`:  实现浮点数的最大值和最小值操作，处理 NaN 的情况。

- **查找内置函数:**
    - `LookUp`:  根据给定的程序计数器 (PC) 地址，查找对应的 V8 内置函数。

- **通用 RISC-V 指令的解码和模拟:**
    - `DecodeRVIType`:  解码并模拟基本的 RISC-V I 型指令，例如 `JALR` (跳转并链接寄存器)。

**如果 `v8/src/execution/riscv/simulator-riscv.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码:**

这个说法是**错误**的。当前提供的代码片段是 C++ 代码。Torque 文件通常以 `.tq` 结尾，并且其语法与 C++ 有显著不同。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

`v8/src/execution/riscv/simulator-riscv.cc` 是 V8 JavaScript 引擎的一部分，它的主要作用是**模拟** RISC-V 架构的 CPU 指令。当 JavaScript 代码在 RISC-V 架构上运行时，V8 引擎会将 JavaScript 代码编译成 RISC-V 汇编指令。这个 `simulator-riscv.cc` 文件提供的功能就是为了在没有实际 RISC-V 硬件的情况下，**模拟执行**这些指令，方便 V8 的开发、测试和调试。

例如，在 JavaScript 中执行一个简单的加法操作：

```javascript
let a = 1.5;
let b = 2.5;
let sum = a + b;
console.log(sum); // 输出 4
```

在 V8 内部，这个 JavaScript 加法操作会被转换成 RISC-V 的浮点加法指令，例如 `fadd.s` (单精度浮点数加法) 或 `fadd.d` (双精度浮点数加法)，具体使用哪个指令取决于变量 `a` 和 `b` 的类型。 `simulator-riscv.cc` 中的 `DecodeRVRFPType` 函数及其相关的 `RO_FADD_S` 或 `RO_FADD_D` 的处理逻辑，就是负责模拟这些 RISC-V 加法指令的行为，包括读取寄存器中的操作数，执行加法运算，并将结果写回寄存器。

**如果有代码逻辑推理，请给出假设输入与输出:**

以 `RoundF2IHelper` 函数为例进行推理：

**假设输入:**

- `original_val` (浮点数): `3.7`
- `round_mode`:  假设使用**Round to Nearest Even** 模式 (RISC-V 的 `kRoundToNearestEven`)
- `I_TYPE`: `int32_t` (32位有符号整数)

**代码逻辑推理:**

1. `rounded = std::nearbyintf(original_val)`:  `std::nearbyintf(3.7)` 会将 `3.7` 四舍五入到最接近的偶数整数，结果为 `4.0`。
2. `max_i = std::numeric_limits<I_TYPE>::max()`:  `int32_t` 的最大值为 `2147483647`。
3. `min_i = std::numeric_limits<I_TYPE>::min()`:  `int32_t` 的最小值为 `-2147483648`。
4. `max_i_plus_1`: 计算略过，因为 `rounded` 不会超过最大值。
5. `if (rounded >= max_i_plus_1)`:  `4.0` 不大于 `int32_t::max + 1`。
6. `if (rounded <= min_i)`: `4.0` 不小于 `-2147483648`。
7. `F_TYPE underflow_fval`: 下溢检查略过，因为 `rounded` 的值较大。
8. `return static_cast<I_TYPE>(rounded)`:  将 `4.0` 转换为 `int32_t`，结果为 `4`。

**预期输出:** `4` (作为 `int32_t`)

**假设输入 (溢出情况):**

- `original_val` (浮点数): `2147483648.0`
- `round_mode`: 假设使用 `kRoundToNearestEven`
- `I_TYPE`: `int32_t`

**代码逻辑推理:**

1. `rounded = std::nearbyintf(original_val)`: `std::nearbyintf(2147483648.0)` 结果为 `2147483648.0`。
2. `max_i = std::numeric_limits<I_TYPE>::max()`: `2147483647`。
3. `max_i_plus_1`: 大约是 `2147483648.0` 的浮点表示。
4. `if (rounded >= max_i_plus_1)`: `2147483648.0` 大于或等于 `max_i_plus_1`。
5. `set_fflags(kFPUOverflow | kInvalidOperation)`: 设置溢出和无效操作标志。
6. `return max_i`: 返回 `int32_t` 的最大值 `2147483647`。

**预期输出:** `2147483647` (作为 `int32_t`)，并设置了浮点溢出和无效操作标志。

**如果涉及用户常见的编程错误，请举例说明:**

一个常见的编程错误是在 JavaScript 中进行浮点数到整数的转换，而没有考虑到精度损失和溢出的情况。 例如：

```javascript
let largeFloat = 9007199254740992; // 大于 2^53 的整数，不能被精确表示为 Number
let integerValue = parseInt(largeFloat);
console.log(integerValue); // 可能输出 9007199254740992 或者一个近似值，取决于具体环境

let veryLargeFloat = 1e30;
let intValue = parseInt(veryLargeFloat);
console.log(intValue); // 输出 NaN (非数字)
```

在上述例子中，`parseInt()` 函数尝试将浮点数转换为整数。当浮点数非常大时，可能会导致精度丢失或超出整数范围，从而产生不期望的结果。

`simulator-riscv.cc` 中的 `RoundF2IHelper` 函数模拟了这种转换过程，并明确处理了溢出的情况，这反映了在底层实现中需要考虑的这些问题。用户在 JavaScript 中进行类似操作时，如果没有正确处理，就会遇到这些精度和溢出相关的错误。

**归纳一下它的功能 (第 6 部分，共 10 部分):**

这部分代码（第 6 部分）主要集中在 RISC-V 架构的**浮点运算和原子操作的模拟**。 它提供了：

- **精确的浮点数到整数的转换**, 包括舍入、溢出和下溢的处理。
- **浮点数的分类和比较**，以及对无效浮点运算的检测。
- **RISC-V 原子内存操作指令的模拟**，确保了在模拟环境下的互斥性。
- **各种 RISC-V 浮点运算指令的模拟**，涵盖了基本的算术运算、符号注入、比较、类型转换等。
- **对融合乘加/减指令的模拟**。
- **初步的向量指令模拟 (但大部分尚未实现)**。

总而言之，这部分代码是 RISC-V 模拟器的核心组成部分，负责模拟 RISC-V 处理器在执行浮点运算和进行多线程同步时涉及的关键指令行为。它确保了 V8 引擎能够在非 RISC-V 硬件上正确地执行针对 RISC-V 架构编译的 JavaScript 代码。
```
### 提示词
```
这是目录为v8/src/execution/riscv/simulator-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/riscv/simulator-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
}

  // Since integer max values are either all 1s (for unsigned) or all 1s
  // except for sign-bit (for signed), they cannot be represented precisely in
  // floating point, in order to precisely tell whether the rounded floating
  // point is within the max range, we compare against (max_i+1) which would
  // have a single 1 w/ many trailing zeros
  float max_i_plus_1 =
      std::is_same<uint64_t, I_TYPE>::value
          ? 0x1p64f  // uint64_t::max + 1 cannot be represented in integers,
                     // so use its float representation directly
          : static_cast<float>(static_cast<uint64_t>(max_i) + 1);
  if (rounded >= max_i_plus_1) {
    set_fflags(kFPUOverflow | kInvalidOperation);
    return max_i;
  }

  // Since min_i (either 0 for unsigned, or for signed) is represented
  // precisely in floating-point,  comparing rounded directly against min_i
  if (rounded <= min_i) {
    if (rounded < min_i) set_fflags(kFPUOverflow | kInvalidOperation);
    return min_i;
  }

  F_TYPE underflow_fval =
      std::is_same<F_TYPE, float>::value ? FLT_MIN : DBL_MIN;
  if (rounded < underflow_fval && rounded > -underflow_fval && rounded != 0) {
    set_fflags(kUnderflow);
  }

  return static_cast<I_TYPE>(rounded);
}

template <typename T>
static int64_t FclassHelper(T value) {
  switch (std::fpclassify(value)) {
    case FP_INFINITE:
      return (std::signbit(value) ? kNegativeInfinity : kPositiveInfinity);
    case FP_NAN:
      return (isSnan(value) ? kSignalingNaN : kQuietNaN);
    case FP_NORMAL:
      return (std::signbit(value) ? kNegativeNormalNumber
                                  : kPositiveNormalNumber);
    case FP_SUBNORMAL:
      return (std::signbit(value) ? kNegativeSubnormalNumber
                                  : kPositiveSubnormalNumber);
    case FP_ZERO:
      return (std::signbit(value) ? kNegativeZero : kPositiveZero);
    default:
      UNREACHABLE();
  }
}

template <typename T>
bool Simulator::CompareFHelper(T input1, T input2, FPUCondition cc) {
  DCHECK(std::is_floating_point<T>::value);
  bool result = false;
  switch (cc) {
    case LT:
    case LE:
      // FLT, FLE are signaling compares
      if (std::isnan(input1) || std::isnan(input2)) {
        set_fflags(kInvalidOperation);
        result = false;
      } else {
        result = (cc == LT) ? (input1 < input2) : (input1 <= input2);
      }
      break;

    case EQ:
      if (std::numeric_limits<T>::signaling_NaN() == input1 ||
          std::numeric_limits<T>::signaling_NaN() == input2) {
        set_fflags(kInvalidOperation);
      }
      if (std::isnan(input1) || std::isnan(input2)) {
        result = false;
      } else {
        result = (input1 == input2);
      }
      break;
    case NE:
      if (std::numeric_limits<T>::signaling_NaN() == input1 ||
          std::numeric_limits<T>::signaling_NaN() == input2) {
        set_fflags(kInvalidOperation);
      }
      if (std::isnan(input1) || std::isnan(input2)) {
        result = true;
      } else {
        result = (input1 != input2);
      }
      break;
    default:
      UNREACHABLE();
  }
  return result;
}

template <typename T>
static inline bool is_invalid_fmul(T src1, T src2) {
  return (isinf(src1) && src2 == static_cast<T>(0.0)) ||
         (src1 == static_cast<T>(0.0) && isinf(src2));
}

template <typename T>
static inline bool is_invalid_fadd(T src1, T src2) {
  return (isinf(src1) && isinf(src2) &&
          std::signbit(src1) != std::signbit(src2));
}

template <typename T>
static inline bool is_invalid_fsub(T src1, T src2) {
  return (isinf(src1) && isinf(src2) &&
          std::signbit(src1) == std::signbit(src2));
}

template <typename T>
static inline bool is_invalid_fdiv(T src1, T src2) {
  return ((src1 == 0 && src2 == 0) || (isinf(src1) && isinf(src2)));
}

template <typename T>
static inline bool is_invalid_fsqrt(T src1) {
  return (src1 < 0);
}

void Simulator::DecodeRVRAType() {
  // TODO(riscv): Add macro for RISCV A extension
  // Special handling for A extension instructions because it uses func5
  // For all A extension instruction, V8 simulator is pure sequential. No
  // Memory address lock or other synchronizaiton behaviors.
  switch (instr_.InstructionBits() & kRATypeMask) {
    case RO_LR_W: {
      sreg_t addr = rs1();
      if (!ProbeMemory(addr, sizeof(int32_t))) return;
      {
        base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
        if ((addr & 0x3) != 0) {
          DieOrDebug();
        }
        auto val = ReadMem<int32_t>(addr, instr_.instr());
        set_rd(sext32(val), false);
        TraceMemRd(addr, val, get_register(rd_reg()));
        local_monitor_.NotifyLoadLinked(addr, TransactionSize::Word);
        GlobalMonitor::Get()->NotifyLoadLinked_Locked(addr,
                                                      &global_monitor_thread_);
      }
      break;
    }
    case RO_SC_W: {
      sreg_t addr = rs1();
      if (!ProbeMemory(addr, sizeof(int32_t))) return;
      if ((addr & 0x3) != 0) {
        DieOrDebug();
      }
      base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
      if (local_monitor_.NotifyStoreConditional(addr, TransactionSize::Word) &&
          GlobalMonitor::Get()->NotifyStoreConditional_Locked(
              addr, &global_monitor_thread_)) {
        local_monitor_.NotifyStore();
        GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
        WriteMem<int32_t>(rs1(), (int32_t)rs2(), instr_.instr());
        set_rd(0, false);
      } else {
        set_rd(1, false);
      }
      break;
    }
    case RO_AMOSWAP_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<uint32_t>(
          rs1(), [&](uint32_t lhs) { return (uint32_t)rs2(); }, instr_.instr(),
          WORD)));
      break;
    }
    case RO_AMOADD_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<uint32_t>(
          rs1(), [&](uint32_t lhs) { return lhs + (uint32_t)rs2(); },
          instr_.instr(), WORD)));
      break;
    }
    case RO_AMOXOR_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<uint32_t>(
          rs1(), [&](uint32_t lhs) { return lhs ^ (uint32_t)rs2(); },
          instr_.instr(), WORD)));
      break;
    }
    case RO_AMOAND_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<uint32_t>(
          rs1(), [&](uint32_t lhs) { return lhs & (uint32_t)rs2(); },
          instr_.instr(), WORD)));
      break;
    }
    case RO_AMOOR_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<uint32_t>(
          rs1(), [&](uint32_t lhs) { return lhs | (uint32_t)rs2(); },
          instr_.instr(), WORD)));
      break;
    }
    case RO_AMOMIN_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<int32_t>(
          rs1(), [&](int32_t lhs) { return std::min(lhs, (int32_t)rs2()); },
          instr_.instr(), WORD)));
      break;
    }
    case RO_AMOMAX_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<int32_t>(
          rs1(), [&](int32_t lhs) { return std::max(lhs, (int32_t)rs2()); },
          instr_.instr(), WORD)));
      break;
    }
    case RO_AMOMINU_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<uint32_t>(
          rs1(), [&](uint32_t lhs) { return std::min(lhs, (uint32_t)rs2()); },
          instr_.instr(), WORD)));
      break;
    }
    case RO_AMOMAXU_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<uint32_t>(
          rs1(), [&](uint32_t lhs) { return std::max(lhs, (uint32_t)rs2()); },
          instr_.instr(), WORD)));
      break;
    }
#ifdef V8_TARGET_ARCH_RISCV64
    case RO_LR_D: {
      int64_t addr = rs1();
      if (!ProbeMemory(addr, sizeof(int64_t))) return;
      {
        base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
        auto val = ReadMem<int64_t>(addr, instr_.instr());
        set_rd(val, false);
        TraceMemRd(addr, val, get_register(rd_reg()));
        local_monitor_.NotifyLoadLinked(addr, TransactionSize::DoubleWord);
        GlobalMonitor::Get()->NotifyLoadLinked_Locked(addr,
                                                      &global_monitor_thread_);
        break;
      }
    }
    case RO_SC_D: {
      int64_t addr = rs1();
      if (!ProbeMemory(addr, sizeof(int64_t))) return;
      base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
      if (local_monitor_.NotifyStoreConditional(addr,
                                                TransactionSize::DoubleWord) &&
          (GlobalMonitor::Get()->NotifyStoreConditional_Locked(
              addr, &global_monitor_thread_))) {
        GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
        WriteMem<int64_t>(rs1(), rs2(), instr_.instr());
        set_rd(0, false);
      } else {
        set_rd(1, false);
      }
      break;
    }
    case RO_AMOSWAP_D: {
      set_rd(amo<int64_t>(
          rs1(), [&](int64_t lhs) { return rs2(); }, instr_.instr(), DWORD));
      break;
    }
    case RO_AMOADD_D: {
      set_rd(amo<int64_t>(
          rs1(), [&](int64_t lhs) { return lhs + rs2(); }, instr_.instr(),
          DWORD));
      break;
    }
    case RO_AMOXOR_D: {
      set_rd(amo<int64_t>(
          rs1(), [&](int64_t lhs) { return lhs ^ rs2(); }, instr_.instr(),
          DWORD));
      break;
    }
    case RO_AMOAND_D: {
      set_rd(amo<int64_t>(
          rs1(), [&](int64_t lhs) { return lhs & rs2(); }, instr_.instr(),
          DWORD));
      break;
    }
    case RO_AMOOR_D: {
      set_rd(amo<int64_t>(
          rs1(), [&](int64_t lhs) { return lhs | rs2(); }, instr_.instr(),
          DWORD));
      break;
    }
    case RO_AMOMIN_D: {
      set_rd(amo<int64_t>(
          rs1(), [&](int64_t lhs) { return std::min(lhs, rs2()); },
          instr_.instr(), DWORD));
      break;
    }
    case RO_AMOMAX_D: {
      set_rd(amo<int64_t>(
          rs1(), [&](int64_t lhs) { return std::max(lhs, rs2()); },
          instr_.instr(), DWORD));
      break;
    }
    case RO_AMOMINU_D: {
      set_rd(amo<uint64_t>(
          rs1(), [&](uint64_t lhs) { return std::min(lhs, (uint64_t)rs2()); },
          instr_.instr(), DWORD));
      break;
    }
    case RO_AMOMAXU_D: {
      set_rd(amo<uint64_t>(
          rs1(), [&](uint64_t lhs) { return std::max(lhs, (uint64_t)rs2()); },
          instr_.instr(), DWORD));
      break;
    }
#endif /*V8_TARGET_ARCH_RISCV64*/
    // TODO(riscv): End Add macro for RISCV A extension
    default: {
      UNSUPPORTED();
    }
  }
}

void Simulator::DecodeRVRFPType() {
  // OP_FP instructions (F/D) uses func7 first. Some further uses func3 and
  // rs2()

  // kRATypeMask is only for func7
  switch (instr_.InstructionBits() & kRFPTypeMask) {
    // TODO(riscv): Add macro for RISCV F extension
    case RO_FADD_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2) {
        if (is_invalid_fadd(frs1, frs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else {
          return frs1 + frs2;
        }
      };
      set_frd(CanonicalizeFPUOp2<float>(fn));
      break;
    }
    case RO_FSUB_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2) {
        if (is_invalid_fsub(frs1, frs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else {
          return frs1 - frs2;
        }
      };
      set_frd(CanonicalizeFPUOp2<float>(fn));
      break;
    }
    case RO_FMUL_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2) {
        if (is_invalid_fmul(frs1, frs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else {
          return frs1 * frs2;
        }
      };
      set_frd(CanonicalizeFPUOp2<float>(fn));
      break;
    }
    case RO_FDIV_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2) {
        if (is_invalid_fdiv(frs1, frs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else if (frs2 == 0.0f) {
          this->set_fflags(kDivideByZero);
          return (std::signbit(frs1) == std::signbit(frs2)
                      ? std::numeric_limits<float>::infinity()
                      : -std::numeric_limits<float>::infinity());
        } else {
          return frs1 / frs2;
        }
      };
      set_frd(CanonicalizeFPUOp2<float>(fn));
      break;
    }
    case RO_FSQRT_S: {
      if (instr_.Rs2Value() == 0b00000) {
        // TODO(riscv): use rm value (round mode)
        auto fn = [this](float frs) {
          if (is_invalid_fsqrt(frs)) {
            this->set_fflags(kInvalidOperation);
            return std::numeric_limits<float>::quiet_NaN();
          } else {
            return std::sqrt(frs);
          }
        };
        set_frd(CanonicalizeFPUOp1<float>(fn));
      } else {
        UNSUPPORTED();
      }
      break;
    }
    case RO_FSGNJ_S: {  // RO_FSGNJN_S  RO_FSQNJX_S
      switch (instr_.Funct3Value()) {
        case 0b000: {  // RO_FSGNJ_S
          set_frd(fsgnj32(frs1_boxed(), frs2_boxed(), false, false));
          break;
        }
        case 0b001: {  // RO_FSGNJN_S
          set_frd(fsgnj32(frs1_boxed(), frs2_boxed(), true, false));
          break;
        }
        case 0b010: {  // RO_FSQNJX_S
          set_frd(fsgnj32(frs1_boxed(), frs2_boxed(), false, true));
          break;
        }
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FMIN_S: {  // RO_FMAX_S
      switch (instr_.Funct3Value()) {
        case 0b000: {  // RO_FMIN_S
          set_frd(FMaxMinHelper(frs1(), frs2(), MaxMinKind::kMin));
          break;
        }
        case 0b001: {  // RO_FMAX_S
          set_frd(FMaxMinHelper(frs1(), frs2(), MaxMinKind::kMax));
          break;
        }
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FCVT_W_S: {  // RO_FCVT_WU_S , 64F RO_FCVT_L_S RO_FCVT_LU_S
      float original_val = frs1();
      switch (instr_.Rs2Value()) {
        case 0b00000: {  // RO_FCVT_W_S
          set_rd(RoundF2IHelper<int32_t>(original_val, instr_.RoundMode()));
          break;
        }
        case 0b00001: {  // RO_FCVT_WU_S
          set_rd(sext32(
              RoundF2IHelper<uint32_t>(original_val, instr_.RoundMode())));
          break;
        }
#ifdef V8_TARGET_ARCH_RISCV64
        case 0b00010: {  // RO_FCVT_L_S
          set_rd(RoundF2IHelper<int64_t>(original_val, instr_.RoundMode()));
          break;
        }
        case 0b00011: {  // RO_FCVT_LU_S
          set_rd(RoundF2IHelper<uint64_t>(original_val, instr_.RoundMode()));
          break;
        }
#endif /* V8_TARGET_ARCH_RISCV64 */
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FMV: {  // RO_FCLASS_S
      switch (instr_.Funct3Value()) {
        case 0b000: {
          if (instr_.Rs2Value() == 0b00000) {
            // RO_FMV_X_W
            set_rd(sext32(get_fpu_register_word(rs1_reg())));
          } else {
            UNSUPPORTED();
          }
          break;
        }
        case 0b001: {  // RO_FCLASS_S
          set_rd(FclassHelper(frs1()));
          break;
        }
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FLE_S: {  // RO_FEQ_S RO_FLT_S RO_FLE_S
      switch (instr_.Funct3Value()) {
        case 0b010: {  // RO_FEQ_S
          set_rd(CompareFHelper(frs1(), frs2(), EQ));
          break;
        }
        case 0b001: {  // RO_FLT_S
          set_rd(CompareFHelper(frs1(), frs2(), LT));
          break;
        }
        case 0b000: {  // RO_FLE_S
          set_rd(CompareFHelper(frs1(), frs2(), LE));
          break;
        }
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FCVT_S_W: {  // RO_FCVT_S_WU , 64F RO_FCVT_S_L RO_FCVT_S_LU
      switch (instr_.Rs2Value()) {
        case 0b00000: {  // RO_FCVT_S_W
          set_frd(static_cast<float>((int32_t)rs1()));
          break;
        }
        case 0b00001: {  // RO_FCVT_S_WU
          set_frd(static_cast<float>((uint32_t)rs1()));
          break;
        }
#ifdef V8_TARGET_ARCH_RISCV64
        case 0b00010: {  // RO_FCVT_S_L
          set_frd(static_cast<float>((int64_t)rs1()));
          break;
        }
        case 0b00011: {  // RO_FCVT_S_LU
          set_frd(static_cast<float>((uint64_t)rs1()));
          break;
        }
#endif /* V8_TARGET_ARCH_RISCV64 */
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FMV_W_X: {
      if (instr_.Funct3Value() == 0b000) {
        // since FMV preserves source bit-pattern, no need to canonize
        Float32 result = Float32::FromBits((uint32_t)rs1());
        set_frd(result);
      } else {
        UNSUPPORTED();
      }
      break;
    }
      // TODO(riscv): Add macro for RISCV D extension
    case RO_FADD_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2) {
        if (is_invalid_fadd(drs1, drs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else {
          return drs1 + drs2;
        }
      };
      set_drd(CanonicalizeFPUOp2<double>(fn));
      break;
    }
    case RO_FSUB_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2) {
        if (is_invalid_fsub(drs1, drs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else {
          return drs1 - drs2;
        }
      };
      set_drd(CanonicalizeFPUOp2<double>(fn));
      break;
    }
    case RO_FMUL_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2) {
        if (is_invalid_fmul(drs1, drs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else {
          return drs1 * drs2;
        }
      };
      set_drd(CanonicalizeFPUOp2<double>(fn));
      break;
    }
    case RO_FDIV_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2) {
        if (is_invalid_fdiv(drs1, drs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else if (drs2 == 0.0) {
          this->set_fflags(kDivideByZero);
          return (std::signbit(drs1) == std::signbit(drs2)
                      ? std::numeric_limits<double>::infinity()
                      : -std::numeric_limits<double>::infinity());
        } else {
          return drs1 / drs2;
        }
      };
      set_drd(CanonicalizeFPUOp2<double>(fn));
      break;
    }
    case RO_FSQRT_D: {
      if (instr_.Rs2Value() == 0b00000) {
        // TODO(riscv): use rm value (round mode)
        auto fn = [this](double drs) {
          if (is_invalid_fsqrt(drs)) {
            this->set_fflags(kInvalidOperation);
            return std::numeric_limits<double>::quiet_NaN();
          } else {
            return std::sqrt(drs);
          }
        };
        set_drd(CanonicalizeFPUOp1<double>(fn));
      } else {
        UNSUPPORTED();
      }
      break;
    }
    case RO_FSGNJ_D: {  // RO_FSGNJN_D RO_FSQNJX_D
      switch (instr_.Funct3Value()) {
        case 0b000: {  // RO_FSGNJ_D
          set_drd(fsgnj64(drs1_boxed(), drs2_boxed(), false, false));
          break;
        }
        case 0b001: {  // RO_FSGNJN_D
          set_drd(fsgnj64(drs1_boxed(), drs2_boxed(), true, false));
          break;
        }
        case 0b010: {  // RO_FSQNJX_D
          set_drd(fsgnj64(drs1_boxed(), drs2_boxed(), false, true));
          break;
        }
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FMIN_D: {  // RO_FMAX_D
      switch (instr_.Funct3Value()) {
        case 0b000: {  // RO_FMIN_D
          set_drd(FMaxMinHelper(drs1(), drs2(), MaxMinKind::kMin));
          break;
        }
        case 0b001: {  // RO_FMAX_D
          set_drd(FMaxMinHelper(drs1(), drs2(), MaxMinKind::kMax));
          break;
        }
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case (RO_FCVT_S_D & kRFPTypeMask): {
      if (instr_.Rs2Value() == 0b00001) {
        auto fn = [](double drs) { return static_cast<float>(drs); };
        set_frd(CanonicalizeDoubleToFloatOperation(fn));
      } else {
        UNSUPPORTED();
      }
      break;
    }
    case RO_FCVT_D_S: {
      if (instr_.Rs2Value() == 0b00000) {
        auto fn = [](float frs) { return static_cast<double>(frs); };
        set_drd(CanonicalizeFloatToDoubleOperation(fn));
      } else {
        UNSUPPORTED();
      }
      break;
    }
    case RO_FLE_D: {  // RO_FEQ_D RO_FLT_D RO_FLE_D
      switch (instr_.Funct3Value()) {
        case 0b010: {  // RO_FEQ_S
          set_rd(CompareFHelper(drs1(), drs2(), EQ));
          break;
        }
        case 0b001: {  // RO_FLT_D
          set_rd(CompareFHelper(drs1(), drs2(), LT));
          break;
        }
        case 0b000: {  // RO_FLE_D
          set_rd(CompareFHelper(drs1(), drs2(), LE));
          break;
        }
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case (RO_FCLASS_D & kRFPTypeMask): {  // RO_FCLASS_D , 64D RO_FMV_X_D
      if (instr_.Rs2Value() != 0b00000) {
        UNSUPPORTED();
      }
      switch (instr_.Funct3Value()) {
        case 0b001: {  // RO_FCLASS_D
          set_rd(FclassHelper(drs1()));
          break;
        }
#ifdef V8_TARGET_ARCH_RISCV64
        case 0b000: {  // RO_FMV_X_D
          set_rd(base::bit_cast<int64_t>(drs1()));
          break;
        }
#endif /* V8_TARGET_ARCH_RISCV64 */
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FCVT_W_D: {  // RO_FCVT_WU_D , 64F RO_FCVT_L_D RO_FCVT_LU_D
      double original_val = drs1();
      switch (instr_.Rs2Value()) {
        case 0b00000: {  // RO_FCVT_W_D
          set_rd(RoundF2IHelper<int32_t>(original_val, instr_.RoundMode()));
          break;
        }
        case 0b00001: {  // RO_FCVT_WU_D
          set_rd(sext32(
              RoundF2IHelper<uint32_t>(original_val, instr_.RoundMode())));
          break;
        }
#ifdef V8_TARGET_ARCH_RISCV64
        case 0b00010: {  // RO_FCVT_L_D
          set_rd(RoundF2IHelper<int64_t>(original_val, instr_.RoundMode()));
          break;
        }
        case 0b00011: {  // RO_FCVT_LU_D
          set_rd(RoundF2IHelper<uint64_t>(original_val, instr_.RoundMode()));
          break;
        }
#endif /* V8_TARGET_ARCH_RISCV64 */
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FCVT_D_W: {  // RO_FCVT_D_WU , 64F RO_FCVT_D_L RO_FCVT_D_LU
      switch (instr_.Rs2Value()) {
        case 0b00000: {  // RO_FCVT_D_W
          set_drd((int32_t)rs1());
          break;
        }
        case 0b00001: {  // RO_FCVT_D_WU
          set_drd((uint32_t)rs1());
          break;
        }
#ifdef V8_TARGET_ARCH_RISCV64
        case 0b00010: {  // RO_FCVT_D_L
          set_drd((int64_t)rs1());
          break;
        }
        case 0b00011: {  // RO_FCVT_D_LU
          set_drd((uint64_t)rs1());
          break;
        }
#endif /* V8_TARGET_ARCH_RISCV64 */
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
#ifdef V8_TARGET_ARCH_RISCV64
    case RO_FMV_D_X: {
      if (instr_.Funct3Value() == 0b000 && instr_.Rs2Value() == 0b00000) {
        // Since FMV preserves source bit-pattern, no need to canonize
        set_drd(base::bit_cast<double>(rs1()));
      } else {
        UNSUPPORTED();
      }
      break;
    }
#endif /* V8_TARGET_ARCH_RISCV64 */
    default: {
      UNSUPPORTED();
    }
  }
}

void Simulator::DecodeRVR4Type() {
  switch (instr_.InstructionBits() & kR4TypeMask) {
    // TODO(riscv): use F Extension macro block
    case RO_FMADD_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2, float frs3) {
        if (is_invalid_fmul(frs1, frs2) || is_invalid_fadd(frs1 * frs2, frs3)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else {
          return std::fma(frs1, frs2, frs3);
        }
      };
      set_frd(CanonicalizeFPUOp3<float>(fn));
      break;
    }
    case RO_FMSUB_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2, float frs3) {
        if (is_invalid_fmul(frs1, frs2) || is_invalid_fsub(frs1 * frs2, frs3)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else {
          return std::fma(frs1, frs2, -frs3);
        }
      };
      set_frd(CanonicalizeFPUOp3<float>(fn));
      break;
    }
    case RO_FNMSUB_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2, float frs3) {
        if (is_invalid_fmul(frs1, frs2) || is_invalid_fsub(frs3, frs1 * frs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else {
          return -std::fma(frs1, frs2, -frs3);
        }
      };
      set_frd(CanonicalizeFPUOp3<float>(fn));
      break;
    }
    case RO_FNMADD_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2, float frs3) {
        if (is_invalid_fmul(frs1, frs2) || is_invalid_fadd(frs1 * frs2, frs3)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else {
          return -std::fma(frs1, frs2, frs3);
        }
      };
      set_frd(CanonicalizeFPUOp3<float>(fn));
      break;
    }
    // TODO(riscv): use F Extension macro block
    case RO_FMADD_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2, double drs3) {
        if (is_invalid_fmul(drs1, drs2) || is_invalid_fadd(drs1 * drs2, drs3)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else {
          return std::fma(drs1, drs2, drs3);
        }
      };
      set_drd(CanonicalizeFPUOp3<double>(fn));
      break;
    }
    case RO_FMSUB_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2, double drs3) {
        if (is_invalid_fmul(drs1, drs2) || is_invalid_fsub(drs1 * drs2, drs3)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else {
          return std::fma(drs1, drs2, -drs3);
        }
      };
      set_drd(CanonicalizeFPUOp3<double>(fn));
      break;
    }
    case RO_FNMSUB_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2, double drs3) {
        if (is_invalid_fmul(drs1, drs2) || is_invalid_fsub(drs3, drs1 * drs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else {
          return -std::fma(drs1, drs2, -drs3);
        }
      };
      set_drd(CanonicalizeFPUOp3<double>(fn));
      break;
    }
    case RO_FNMADD_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2, double drs3) {
        if (is_invalid_fmul(drs1, drs2) || is_invalid_fadd(drs1 * drs2, drs3)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else {
          return -std::fma(drs1, drs2, drs3);
        }
      };
      set_drd(CanonicalizeFPUOp3<double>(fn));
      break;
    }
    default:
      UNSUPPORTED();
  }
}

#ifdef CAN_USE_RVV_INSTRUCTIONS
bool Simulator::DecodeRvvVL() {
  uint32_t instr_temp =
      instr_.InstructionBits() & (kRvvMopMask | kRvvNfMask | kBaseOpcodeMask);
  if (RO_V_VL == instr_temp) {
    if (!(instr_.InstructionBits() & (kRvvRs2Mask))) {
      switch (instr_.vl_vs_width()) {
        case 8: {
          RVV_VI_LD(0, (i * nf + fn), int8, false);
          break;
        }
        case 16: {
          RVV_VI_LD(0, (i * nf + fn), int16, false);
          break;
        }
        case 32: {
          RVV_VI_LD(0, (i * nf + fn), int32, false);
          break;
        }
        case 64: {
          RVV_VI_LD(0, (i * nf + fn), int64, false);
          break;
        }
        default:
          UNIMPLEMENTED_RISCV();
          break;
      }
      return true;
    } else {
      UNIMPLEMENTED_RISCV();
      return true;
    }
  } else if (RO_V_VLS == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VLX == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VLSEG2 == instr_temp || RO_V_VLSEG3 == instr_temp ||
             RO_V_VLSEG4 == instr_temp || RO_V_VLSEG5 == instr_temp ||
             RO_V_VLSEG6 == instr_temp || RO_V_VLSEG7 == instr_temp ||
             RO_V_VLSEG8 == instr_temp) {
    if (!(instr_.InstructionBits() & (kRvvRs2Mask))) {
      UNIMPLEMENTED_RISCV();
      return true;
    } else {
      UNIMPLEMENTED_RISCV();
      return true;
    }
  } else if (RO_V_VLSSEG2 == instr_temp || RO_V_VLSSEG3 == instr_temp ||
             RO_V_VLSSEG4 == instr_temp || RO_V_VLSSEG5 == instr_temp ||
             RO_V_VLSSEG6 == instr_temp || RO_V_VLSSEG7 == instr_temp ||
             RO_V_VLSSEG8 == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VLXSEG2 == instr_temp || RO_V_VLXSEG3 == instr_temp ||
             RO_V_VLXSEG4 == instr_temp || RO_V_VLXSEG5 == instr_temp ||
             RO_V_VLXSEG6 == instr_temp || RO_V_VLXSEG7 == instr_temp ||
             RO_V_VLXSEG8 == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else {
    return false;
  }
}

bool Simulator::DecodeRvvVS() {
  uint32_t instr_temp =
      instr_.InstructionBits() & (kRvvMopMask | kRvvNfMask | kBaseOpcodeMask);
  if (RO_V_VS == instr_temp) {
    if (!(instr_.InstructionBits() & (kRvvRs2Mask))) {
      switch (instr_.vl_vs_width()) {
        case 8: {
          RVV_VI_ST(0, (i * nf + fn), uint8, false);
          break;
        }
        case 16: {
          RVV_VI_ST(0, (i * nf + fn), uint16, false);
          break;
        }
        case 32: {
          RVV_VI_ST(0, (i * nf + fn), uint32, false);
          break;
        }
        case 64: {
          RVV_VI_ST(0, (i * nf + fn), uint64, false);
          break;
        }
        default:
          UNIMPLEMENTED_RISCV();
          break;
      }
    } else {
      UNIMPLEMENTED_RISCV();
    }
    return true;
  } else if (RO_V_VSS == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VSX == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VSU == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VSSEG2 == instr_temp || RO_V_VSSEG3 == instr_temp ||
             RO_V_VSSEG4 == instr_temp || RO_V_VSSEG5 == instr_temp ||
             RO_V_VSSEG6 == instr_temp || RO_V_VSSEG7 == instr_temp ||
             RO_V_VSSEG8 == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VSSSEG2 == instr_temp || RO_V_VSSSEG3 == instr_temp ||
             RO_V_VSSSEG4 == instr_temp || RO_V_VSSSEG5 == instr_temp ||
             RO_V_VSSSEG6 == instr_temp || RO_V_VSSSEG7 == instr_temp ||
             RO_V_VSSSEG8 == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VSXSEG2 == instr_temp || RO_V_VSXSEG3 == instr_temp ||
             RO_V_VSXSEG4 == instr_temp || RO_V_VSXSEG5 == instr_temp ||
             RO_V_VSXSEG6 == instr_temp || RO_V_VSXSEG7 == instr_temp ||
             RO_V_VSXSEG8 == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else {
    return false;
  }
}
#endif

Builtin Simulator::LookUp(Address pc) {
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    if (builtins_.code(builtin)->contains(isolate_, pc)) return builtin;
  }
  return Builtin::kNoBuiltinId;
}

void Simulator::DecodeRVIType() {
  switch (instr_.InstructionBits() & kITypeMask) {
    case RO_JALR: {
      set_rd(get_pc() + kInstrSize);
      // Note: No need to shift 2 for JALR's imm12, but set lowest bit to 0.
      sreg_t next_pc = (rs1() + imm12())
```