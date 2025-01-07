Response:
My thought process for summarizing the provided C++ code snippet goes like this:

1. **Initial Scan for Keywords and Patterns:** I quickly scanned the code looking for recurring terms, data types, and function names. "Simulator", "register", "FPU", "FCSR", "set_", "get_", "read_", "write_", "Trace", and data types like `int64_t`, `int32_t`, `double`, `float`, `bool` immediately stood out. This suggests the code is dealing with simulating a processor's state.

2. **Identify Core Components:**  The presence of `registers_`, `FPUregisters_`, `CFregisters_`, and `FCSR_` strongly indicates the code is managing the state of a simulated CPU, including general-purpose registers, floating-point registers, condition flags, and a floating-point control and status register.

3. **Categorize Functionality by Prefix:**  The naming convention of the functions (e.g., `set_register`, `get_register`, `set_fpu_register`, `get_fpu_register`) provides a clear categorization of actions:
    * `set_*`:  Functions to modify the simulated processor's state.
    * `get_*`: Functions to retrieve the simulated processor's state.
    * `Read*`, `Write*`: Functions to simulate memory access.
    * `Trace*`: Functions related to logging or debugging.

4. **Analyze Function Signatures and Bodies (High-Level):**  I examined the function signatures to understand what data they operate on (e.g., register indices, values, memory addresses). I glanced at the function bodies to confirm my initial understanding. For example, the `set_fpu_register_*` functions clearly handle setting values of different sizes (word, hi-word, float, double) in the FPU registers. The `get_fpu_register_*` functions do the opposite.

5. **Focus on Key Areas:**  I identified the major functional areas:
    * **Register Management:** Setting and getting values of various register types (general-purpose, floating-point, condition flags).
    * **Memory Access:** Simulating reading and writing to memory, including handling alignment and conditional operations.
    * **Floating-Point Specifics:** Managing the FCSR, handling rounding modes, and dealing with floating-point values (float and double).
    * **Tracing/Debugging:**  Logging register and memory accesses for debugging purposes.

6. **Look for Conditional Logic and Error Handling:** I noticed checks for valid register indices (`DCHECK`) and error conditions related to floating-point operations (e.g., `set_fcsr_round_error`). The `DieOrDebug()` function indicates a mechanism for handling critical errors during simulation.

7. **Synthesize the Functionality Description:** Based on the above analysis, I started formulating a concise description of the code's purpose, highlighting the core functionalities. I used the identified keywords and categories to structure the summary.

8. **Address Specific Instructions in the Prompt:** I then specifically addressed the prompt's requirements:
    * **List of functionalities:** I enumerated the key actions the code performs.
    * **Torque source:**  I checked the file extension (.cc vs .tq) and confirmed it wasn't a Torque file.
    * **Relationship to JavaScript:** I recognized the connection to V8's execution and mentioned that this code simulates the underlying hardware behavior upon which JavaScript runs. I provided a conceptual JavaScript example to illustrate how the simulator's actions relate to high-level JavaScript operations.
    * **Code logic inference:** I crafted a simple example with hypothetical inputs and outputs for a register setting and getting operation.
    * **Common programming errors:** I identified potential errors like incorrect register indexing or misunderstanding floating-point behavior.
    * **归纳功能 (Summarize functionality):**  This was the final step, consolidating the identified functionalities into a high-level summary.

9. **Refine and Organize:** I reviewed the summary for clarity, accuracy, and conciseness, ensuring it flowed logically and covered the essential aspects of the provided code. I also made sure to present it in a structured manner, using bullet points and clear headings.

By following these steps, I could effectively analyze the C++ code snippet and generate a comprehensive summary that addresses the specific points raised in the prompt. The key is to break down the code into smaller, manageable parts and then synthesize the information into a coherent overview.
好的，这是对提供的v8源代码 `v8/src/execution/loong64/simulator-loong64.cc` 第二部分的归纳总结。

**功能归纳 (第二部分):**

这部分代码主要负责 **模拟 LoongArch64 架构 CPU 的寄存器操作、浮点运算相关的状态管理和一些调试辅助功能**。  具体来说，它实现了以下功能：

1. **寄存器读写操作:**
   - 提供了用于设置和获取通用寄存器 (integer registers) 和浮点寄存器 (FPU registers) 的值的函数。
   - 针对浮点寄存器，还提供了设置和获取 32 位字 (word)、高 32 位字 (hi-word)、单精度浮点数 (float) 和双精度浮点数 (double) 的函数。
   - 提供了设置和获取条件标志寄存器 (CF registers) 的值的函数。
   - 特殊处理了程序计数器 (PC) 寄存器的访问。

2. **浮点运算状态管理 (FCSR):**
   - 提供了访问和修改浮点控制和状态寄存器 (FCSR) 中各个位的函数，包括设置特定的标志位和舍入模式。
   - 提供了基于浮点运算结果设置 FCSR 中舍入错误代码的函数，能够区分单精度和双精度浮点数，以及 64 位整数转换的情况。
   - 提供了根据 FCSR 中设置的舍入模式对浮点数进行舍入的函数，包括舍入到最接近、向零舍入、向上舍入和向下舍入。这些函数能够处理单精度和双精度浮点数，并返回舍入后的整数值。

3. **辅助函数:**
   - `GetFpArgs`:  用于从寄存器中获取浮点运算的参数。
   - `SetFpResult`: 用于将浮点运算的结果设置到寄存器中。
   - `DieOrDebug`: 在遇到错误时触发调试器或终止程序。
   - `TraceRegWr`, `TraceMemRd`, `TraceMemWr`:  用于在模拟过程中跟踪寄存器写入和内存读写操作，方便调试。

4. **内存访问模拟:**
   - 提供了模拟内存读取 (ReadW, ReadWU, Read2W, ReadD, ReadHU, ReadH) 和写入 (WriteW, WriteConditionalW, Write2W, WriteConditional2W, WriteD) 的函数。
   - 包含了对内存访问地址有效性的基本检查，并在访问无效地址时触发调试或终止。
   - 实现了条件内存写入操作 (WriteConditionalW, WriteConditional2W)，模拟原子操作。
   - 包含了 `ProbeMemory` 函数，可能用于内存访问探测，特别是与 WebAssembly 的陷阱处理相关。

**与 JavaScript 的关系:**

这段代码是 V8 JavaScript 引擎的一部分，负责在 LoongArch64 架构上模拟 CPU 的行为。 当 JavaScript 代码执行涉及到需要底层硬件操作时（例如，算术运算、内存访问等），V8 引擎会利用这个模拟器来模拟这些操作。

例如，JavaScript 中的浮点数运算：

```javascript
let a = 1.5;
let b = 2.7;
let sum = a + b;
```

在 LoongArch64 架构上运行时，V8 可能会使用模拟器的浮点寄存器和相关的 FCSR 管理功能来执行这个加法操作。模拟器会设置浮点寄存器 `f0` 和 `f1` 为 `1.5` 和 `2.7` 的表示，然后模拟加法指令，并将结果存回浮点寄存器 `f0`。  FCSR 可能会被用来记录运算过程中的状态（例如，是否发生溢出或下溢）。

**代码逻辑推理示例:**

**假设输入:**

- `fpureg = 5`
- `value = 3.14159` (double)

**执行的函数:** `Simulator::set_fpu_register_double(5, 3.14159)`

**输出:**

- 浮点寄存器 `FPUregisters_[5]` 的内存表示会被修改为 `3.14159` 的双精度浮点数表示。后续调用 `Simulator::get_fpu_register_double(5)` 将返回 `3.14159`。

**用户常见的编程错误示例:**

1. **错误的寄存器索引:**  用户可能会传递超出有效范围的寄存器索引给 `set_register` 或 `get_register` 函数，例如 `set_register(100, value)`，但如果只有 32 个通用寄存器，这将导致断言失败或未定义的行为。

2. **浮点数精度理解错误:** 用户可能期望浮点运算的结果是精确的，但由于浮点数的二进制表示的限制，可能会出现精度损失。模拟器的 FCSR 管理功能可以帮助开发者理解这些精度问题，例如通过检查 `kFCSRInexactCauseBit` 标志。

3. **内存访问越界:** 在模拟器外部，JavaScript 代码可能会尝试访问无效的内存地址。模拟器的内存访问函数会检查地址范围，并在检测到越界访问时触发 `DieOrDebug()`。

**总结:**

这部分 `simulator-loong64.cc` 代码是 V8 引擎在 LoongArch64 平台上模拟 CPU 核心功能的重要组成部分。它允许 V8 引擎在没有真实硬件的情况下运行和测试 JavaScript 代码，并提供了对寄存器、浮点运算状态和内存访问的细粒度控制和模拟，同时包含了一些用于调试和错误检测的机制。

Prompt: 
```
这是目录为v8/src/execution/loong64/simulator-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/loong64/simulator-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能

"""
sters));
  FPUregisters_[fpureg] = value;
}

void Simulator::set_fpu_register_word(int fpureg, int32_t value) {
  // Set ONLY lower 32-bits, leaving upper bits untouched.
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  int32_t* pword;
  pword = reinterpret_cast<int32_t*>(&FPUregisters_[fpureg]);

  *pword = value;
}

void Simulator::set_fpu_register_hi_word(int fpureg, int32_t value) {
  // Set ONLY upper 32-bits, leaving lower bits untouched.
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  int32_t* phiword;
  phiword = (reinterpret_cast<int32_t*>(&FPUregisters_[fpureg])) + 1;

  *phiword = value;
}

void Simulator::set_fpu_register_float(int fpureg, float value) {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  memcpy(&FPUregisters_[fpureg], &value, sizeof(value));
}

void Simulator::set_fpu_register_double(int fpureg, double value) {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  memcpy(&FPUregisters_[fpureg], &value, sizeof(value));
}

void Simulator::set_cf_register(int cfreg, bool value) {
  DCHECK((cfreg >= 0) && (cfreg < kNumCFRegisters));
  CFregisters_[cfreg] = value;
}

// Get the register from the architecture state. This function does handle
// the special case of accessing the PC register.
int64_t Simulator::get_register(int reg) const {
  DCHECK((reg >= 0) && (reg < kNumSimuRegisters));
  if (reg == 0)
    return 0;
  else
    return registers_[reg];
}

double Simulator::get_double_from_register_pair(int reg) {
  // TODO(plind): bad ABI stuff, refactor or remove.
  DCHECK((reg >= 0) && (reg < kNumSimuRegisters));

  double dm_val = 0.0;
  // Read the bits from the unsigned integer register_[] array
  // into the double precision floating point value and return it.
  char buffer[sizeof(registers_[0])];
  memcpy(buffer, &registers_[reg], sizeof(registers_[0]));
  memcpy(&dm_val, buffer, sizeof(registers_[0]));
  return (dm_val);
}

int64_t Simulator::get_fpu_register(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return FPUregisters_[fpureg];
}

int32_t Simulator::get_fpu_register_word(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return static_cast<int32_t>(FPUregisters_[fpureg] & 0xFFFFFFFF);
}

int32_t Simulator::get_fpu_register_signed_word(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return static_cast<int32_t>(FPUregisters_[fpureg] & 0xFFFFFFFF);
}

int32_t Simulator::get_fpu_register_hi_word(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return static_cast<int32_t>((FPUregisters_[fpureg] >> 32) & 0xFFFFFFFF);
}

float Simulator::get_fpu_register_float(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return base::bit_cast<float>(get_fpu_register_word(fpureg));
}

double Simulator::get_fpu_register_double(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return base::bit_cast<double>(FPUregisters_[fpureg]);
}

bool Simulator::get_cf_register(int cfreg) const {
  DCHECK((cfreg >= 0) && (cfreg < kNumCFRegisters));
  return CFregisters_[cfreg];
}

// Runtime FP routines take up to two double arguments and zero
// or one integer arguments. All are constructed here,
// from a0-a3 or fa0 and fa1 (n64).
void Simulator::GetFpArgs(double* x, double* y, int32_t* z) {
  const int fparg2 = f1;
  *x = get_fpu_register_double(f0);
  *y = get_fpu_register_double(fparg2);
  *z = static_cast<int32_t>(get_register(a2));
}

// The return value is either in v0/v1 or f0.
void Simulator::SetFpResult(const double& result) {
  set_fpu_register_double(0, result);
}

// Helper functions for setting and testing the FCSR register's bits.
void Simulator::set_fcsr_bit(uint32_t cc, bool value) {
  if (value) {
    FCSR_ |= (1 << cc);
  } else {
    FCSR_ &= ~(1 << cc);
  }
}

bool Simulator::test_fcsr_bit(uint32_t cc) { return FCSR_ & (1 << cc); }

void Simulator::set_fcsr_rounding_mode(FPURoundingMode mode) {
  FCSR_ |= mode & kFPURoundingModeMask;
}

unsigned int Simulator::get_fcsr_rounding_mode() {
  return FCSR_ & kFPURoundingModeMask;
}

// Sets the rounding error codes in FCSR based on the result of the rounding.
// Returns true if the operation was invalid.
bool Simulator::set_fcsr_round_error(double original, double rounded) {
  bool ret = false;
  double max_int32 = std::numeric_limits<int32_t>::max();
  double min_int32 = std::numeric_limits<int32_t>::min();
  set_fcsr_bit(kFCSRInvalidOpCauseBit, false);
  set_fcsr_bit(kFCSRUnderflowCauseBit, false);
  set_fcsr_bit(kFCSROverflowCauseBit, false);
  set_fcsr_bit(kFCSRInexactCauseBit, false);

  if (!std::isfinite(original) || !std::isfinite(rounded)) {
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  if (original != rounded) {
    set_fcsr_bit(kFCSRInexactCauseBit, true);
  }

  if (rounded < DBL_MIN && rounded > -DBL_MIN && rounded != 0) {
    set_fcsr_bit(kFCSRUnderflowCauseBit, true);
    ret = true;
  }

  if (rounded > max_int32 || rounded < min_int32) {
    set_fcsr_bit(kFCSROverflowCauseBit, true);
    // The reference is not really clear but it seems this is required:
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  return ret;
}

// Sets the rounding error codes in FCSR based on the result of the rounding.
// Returns true if the operation was invalid.
bool Simulator::set_fcsr_round64_error(double original, double rounded) {
  bool ret = false;
  // The value of INT64_MAX (2^63-1) can't be represented as double exactly,
  // loading the most accurate representation into max_int64, which is 2^63.
  double max_int64 = static_cast<double>(std::numeric_limits<int64_t>::max());
  double min_int64 = std::numeric_limits<int64_t>::min();
  set_fcsr_bit(kFCSRInvalidOpCauseBit, false);
  set_fcsr_bit(kFCSRUnderflowCauseBit, false);
  set_fcsr_bit(kFCSROverflowCauseBit, false);
  set_fcsr_bit(kFCSRInexactCauseBit, false);

  if (!std::isfinite(original) || !std::isfinite(rounded)) {
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  if (original != rounded) {
    set_fcsr_bit(kFCSRInexactCauseBit, true);
  }

  if (rounded < DBL_MIN && rounded > -DBL_MIN && rounded != 0) {
    set_fcsr_bit(kFCSRUnderflowCauseBit, true);
    ret = true;
  }

  if (rounded >= max_int64 || rounded < min_int64) {
    set_fcsr_bit(kFCSROverflowCauseBit, true);
    // The reference is not really clear but it seems this is required:
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  return ret;
}

// Sets the rounding error codes in FCSR based on the result of the rounding.
// Returns true if the operation was invalid.
bool Simulator::set_fcsr_round_error(float original, float rounded) {
  bool ret = false;
  double max_int32 = std::numeric_limits<int32_t>::max();
  double min_int32 = std::numeric_limits<int32_t>::min();
  set_fcsr_bit(kFCSRInvalidOpCauseBit, false);
  set_fcsr_bit(kFCSRUnderflowCauseBit, false);
  set_fcsr_bit(kFCSROverflowCauseBit, false);
  set_fcsr_bit(kFCSRInexactCauseBit, false);

  if (!std::isfinite(original) || !std::isfinite(rounded)) {
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  if (original != rounded) {
    set_fcsr_bit(kFCSRInexactCauseBit, true);
  }

  if (rounded < FLT_MIN && rounded > -FLT_MIN && rounded != 0) {
    set_fcsr_bit(kFCSRUnderflowCauseBit, true);
    ret = true;
  }

  if (rounded > max_int32 || rounded < min_int32) {
    set_fcsr_bit(kFCSROverflowCauseBit, true);
    // The reference is not really clear but it seems this is required:
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  return ret;
}

void Simulator::set_fpu_register_word_invalid_result(float original,
                                                     float rounded) {
  double max_int32 = std::numeric_limits<int32_t>::max();
  double min_int32 = std::numeric_limits<int32_t>::min();
  if (std::isnan(original)) {
    set_fpu_register_word(fd_reg(), 0);
  } else if (rounded > max_int32) {
    set_fpu_register_word(fd_reg(), kFPUInvalidResult);
  } else if (rounded < min_int32) {
    set_fpu_register_word(fd_reg(), kFPUInvalidResultNegative);
  } else {
    UNREACHABLE();
  }
}

void Simulator::set_fpu_register_invalid_result(float original, float rounded) {
  double max_int32 = std::numeric_limits<int32_t>::max();
  double min_int32 = std::numeric_limits<int32_t>::min();
  if (std::isnan(original)) {
    set_fpu_register(fd_reg(), 0);
  } else if (rounded > max_int32) {
    set_fpu_register(fd_reg(), kFPUInvalidResult);
  } else if (rounded < min_int32) {
    set_fpu_register(fd_reg(), kFPUInvalidResultNegative);
  } else {
    UNREACHABLE();
  }
}

void Simulator::set_fpu_register_invalid_result64(float original,
                                                  float rounded) {
  // The value of INT64_MAX (2^63-1) can't be represented as double exactly,
  // loading the most accurate representation into max_int64, which is 2^63.
  double max_int64 = static_cast<double>(std::numeric_limits<int64_t>::max());
  double min_int64 = std::numeric_limits<int64_t>::min();
  if (std::isnan(original)) {
    set_fpu_register(fd_reg(), 0);
  } else if (rounded >= max_int64) {
    set_fpu_register(fd_reg(), kFPU64InvalidResult);
  } else if (rounded < min_int64) {
    set_fpu_register(fd_reg(), kFPU64InvalidResultNegative);
  } else {
    UNREACHABLE();
  }
}

void Simulator::set_fpu_register_word_invalid_result(double original,
                                                     double rounded) {
  double max_int32 = std::numeric_limits<int32_t>::max();
  double min_int32 = std::numeric_limits<int32_t>::min();
  if (std::isnan(original)) {
    set_fpu_register_word(fd_reg(), 0);
  } else if (rounded > max_int32) {
    set_fpu_register_word(fd_reg(), kFPUInvalidResult);
  } else if (rounded < min_int32) {
    set_fpu_register_word(fd_reg(), kFPUInvalidResultNegative);
  } else {
    UNREACHABLE();
  }
}

void Simulator::set_fpu_register_invalid_result(double original,
                                                double rounded) {
  double max_int32 = std::numeric_limits<int32_t>::max();
  double min_int32 = std::numeric_limits<int32_t>::min();
  if (std::isnan(original)) {
    set_fpu_register(fd_reg(), 0);
  } else if (rounded > max_int32) {
    set_fpu_register(fd_reg(), kFPUInvalidResult);
  } else if (rounded < min_int32) {
    set_fpu_register(fd_reg(), kFPUInvalidResultNegative);
  } else {
    UNREACHABLE();
  }
}

void Simulator::set_fpu_register_invalid_result64(double original,
                                                  double rounded) {
  // The value of INT64_MAX (2^63-1) can't be represented as double exactly,
  // loading the most accurate representation into max_int64, which is 2^63.
  double max_int64 = static_cast<double>(std::numeric_limits<int64_t>::max());
  double min_int64 = std::numeric_limits<int64_t>::min();
  if (std::isnan(original)) {
    set_fpu_register(fd_reg(), 0);
  } else if (rounded >= max_int64) {
    set_fpu_register(fd_reg(), kFPU64InvalidResult);
  } else if (rounded < min_int64) {
    set_fpu_register(fd_reg(), kFPU64InvalidResultNegative);
  } else {
    UNREACHABLE();
  }
}

// Sets the rounding error codes in FCSR based on the result of the rounding.
// Returns true if the operation was invalid.
bool Simulator::set_fcsr_round64_error(float original, float rounded) {
  bool ret = false;
  // The value of INT64_MAX (2^63-1) can't be represented as double exactly,
  // loading the most accurate representation into max_int64, which is 2^63.
  double max_int64 = static_cast<double>(std::numeric_limits<int64_t>::max());
  double min_int64 = std::numeric_limits<int64_t>::min();
  set_fcsr_bit(kFCSRInvalidOpCauseBit, false);
  set_fcsr_bit(kFCSRUnderflowCauseBit, false);
  set_fcsr_bit(kFCSROverflowCauseBit, false);
  set_fcsr_bit(kFCSRInexactCauseBit, false);

  if (!std::isfinite(original) || !std::isfinite(rounded)) {
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  if (original != rounded) {
    set_fcsr_bit(kFCSRInexactCauseBit, true);
  }

  if (rounded < FLT_MIN && rounded > -FLT_MIN && rounded != 0) {
    set_fcsr_bit(kFCSRUnderflowCauseBit, true);
    ret = true;
  }

  if (rounded >= max_int64 || rounded < min_int64) {
    set_fcsr_bit(kFCSROverflowCauseBit, true);
    // The reference is not really clear but it seems this is required:
    set_fcsr_bit(kFCSRInvalidOpCauseBit, true);
    ret = true;
  }

  return ret;
}

// For ftint instructions only
void Simulator::round_according_to_fcsr(double toRound, double* rounded,
                                        int32_t* rounded_int) {
  // 0 RN (round to nearest): Round a result to the nearest
  // representable value; if the result is exactly halfway between
  // two representable values, round to zero.

  // 1 RZ (round toward zero): Round a result to the closest
  // representable value whose absolute value is less than or
  // equal to the infinitely accurate result.

  // 2 RP (round up, or toward +infinity): Round a result to the
  // next representable value up.

  // 3 RN (round down, or toward −infinity): Round a result to
  // the next representable value down.
  // switch ((FCSR_ >> 8) & 3) {
  switch (FCSR_ & kFPURoundingModeMask) {
    case kRoundToNearest:
      *rounded = floor(toRound + 0.5);
      *rounded_int = static_cast<int32_t>(*rounded);
      if ((*rounded_int & 1) != 0 && *rounded_int - toRound == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        *rounded_int -= 1;
        *rounded -= 1.;
      }
      break;
    case kRoundToZero:
      *rounded = trunc(toRound);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
    case kRoundToPlusInf:
      *rounded = ceil(toRound);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
    case kRoundToMinusInf:
      *rounded = floor(toRound);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
  }
}

void Simulator::round64_according_to_fcsr(double toRound, double* rounded,
                                          int64_t* rounded_int) {
  // 0 RN (round to nearest): Round a result to the nearest
  // representable value; if the result is exactly halfway between
  // two representable values, round to zero.

  // 1 RZ (round toward zero): Round a result to the closest
  // representable value whose absolute value is less than or.
  // equal to the infinitely accurate result.

  // 2 RP (round up, or toward +infinity): Round a result to the
  // next representable value up.

  // 3 RN (round down, or toward −infinity): Round a result to
  // the next representable value down.
  switch (FCSR_ & kFPURoundingModeMask) {
    case kRoundToNearest:
      *rounded = floor(toRound + 0.5);
      *rounded_int = static_cast<int64_t>(*rounded);
      if ((*rounded_int & 1) != 0 && *rounded_int - toRound == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        *rounded_int -= 1;
        *rounded -= 1.;
      }
      break;
    case kRoundToZero:
      *rounded = trunc(toRound);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
    case kRoundToPlusInf:
      *rounded = ceil(toRound);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
    case kRoundToMinusInf:
      *rounded = floor(toRound);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
  }
}

void Simulator::round_according_to_fcsr(float toRound, float* rounded,
                                        int32_t* rounded_int) {
  // 0 RN (round to nearest): Round a result to the nearest
  // representable value; if the result is exactly halfway between
  // two representable values, round to zero.

  // 1 RZ (round toward zero): Round a result to the closest
  // representable value whose absolute value is less than or
  // equal to the infinitely accurate result.

  // 2 RP (round up, or toward +infinity): Round a result to the
  // next representable value up.

  // 3 RN (round down, or toward −infinity): Round a result to
  // the next representable value down.
  switch (FCSR_ & kFPURoundingModeMask) {
    case kRoundToNearest:
      *rounded = floor(toRound + 0.5);
      *rounded_int = static_cast<int32_t>(*rounded);
      if ((*rounded_int & 1) != 0 && *rounded_int - toRound == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        *rounded_int -= 1;
        *rounded -= 1.f;
      }
      break;
    case kRoundToZero:
      *rounded = trunc(toRound);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
    case kRoundToPlusInf:
      *rounded = ceil(toRound);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
    case kRoundToMinusInf:
      *rounded = floor(toRound);
      *rounded_int = static_cast<int32_t>(*rounded);
      break;
  }
}

void Simulator::round64_according_to_fcsr(float toRound, float* rounded,
                                          int64_t* rounded_int) {
  // 0 RN (round to nearest): Round a result to the nearest
  // representable value; if the result is exactly halfway between
  // two representable values, round to zero.

  // 1 RZ (round toward zero): Round a result to the closest
  // representable value whose absolute value is less than or.
  // equal to the infinitely accurate result.

  // 2 RP (round up, or toward +infinity): Round a result to the
  // next representable value up.

  // 3 RN (round down, or toward −infinity): Round a result to
  // the next representable value down.
  switch (FCSR_ & kFPURoundingModeMask) {
    case kRoundToNearest:
      *rounded = floor(toRound + 0.5);
      *rounded_int = static_cast<int64_t>(*rounded);
      if ((*rounded_int & 1) != 0 && *rounded_int - toRound == 0.5) {
        // If the number is halfway between two integers,
        // round to the even one.
        *rounded_int -= 1;
        *rounded -= 1.f;
      }
      break;
    case kRoundToZero:
      *rounded = trunc(toRound);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
    case kRoundToPlusInf:
      *rounded = ceil(toRound);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
    case kRoundToMinusInf:
      *rounded = floor(toRound);
      *rounded_int = static_cast<int64_t>(*rounded);
      break;
  }
}

// Raw access to the PC register.
void Simulator::set_pc(int64_t value) {
  pc_modified_ = true;
  registers_[pc] = value;
}

bool Simulator::has_bad_pc() const {
  return ((registers_[pc] == bad_ra) || (registers_[pc] == end_sim_pc));
}

// Raw access to the PC register without the special adjustment when reading.
int64_t Simulator::get_pc() const { return registers_[pc]; }

// TODO(plind): refactor this messy debug code when we do unaligned access.
void Simulator::DieOrDebug() {
  if ((1)) {  // Flag for this was removed.
    Loong64Debugger dbg(this);
    dbg.Debug();
  } else {
    base::OS::Abort();
  }
}

void Simulator::TraceRegWr(int64_t value, TraceType t) {
  if (v8_flags.trace_sim) {
    union {
      int64_t fmt_int64;
      int32_t fmt_int32[2];
      float fmt_float[2];
      double fmt_double;
    } v;
    v.fmt_int64 = value;

    switch (t) {
      case WORD:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "    (%" PRId64 ")    int32:%" PRId32
                       " uint32:%" PRIu32,
                       v.fmt_int64, icount_, v.fmt_int32[0], v.fmt_int32[0]);
        break;
      case DWORD:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "    (%" PRId64 ")    int64:%" PRId64
                       " uint64:%" PRIu64,
                       value, icount_, value, value);
        break;
      case FLOAT:
        base::SNPrintF(trace_buf_, "%016" PRIx64 "    (%" PRId64 ")    flt:%e",
                       v.fmt_int64, icount_, v.fmt_float[0]);
        break;
      case DOUBLE:
        base::SNPrintF(trace_buf_, "%016" PRIx64 "    (%" PRId64 ")    dbl:%e",
                       v.fmt_int64, icount_, v.fmt_double);
        break;
      case FLOAT_DOUBLE:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "    (%" PRId64 ")    flt:%e dbl:%e",
                       v.fmt_int64, icount_, v.fmt_float[0], v.fmt_double);
        break;
      case WORD_DWORD:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "    (%" PRId64 ")    int32:%" PRId32
                       " uint32:%" PRIu32 " int64:%" PRId64 " uint64:%" PRIu64,
                       v.fmt_int64, icount_, v.fmt_int32[0], v.fmt_int32[0],
                       v.fmt_int64, v.fmt_int64);
        break;
      default:
        UNREACHABLE();
    }
  }
}

// TODO(plind): consider making icount_ printing a flag option.
void Simulator::TraceMemRd(int64_t addr, int64_t value, TraceType t) {
  if (v8_flags.trace_sim) {
    union {
      int64_t fmt_int64;
      int32_t fmt_int32[2];
      float fmt_float[2];
      double fmt_double;
    } v;
    v.fmt_int64 = value;

    switch (t) {
      case WORD:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "  <-- [%016" PRIx64 "]    (%" PRId64
                       ")    int32:%" PRId32 " uint32:%" PRIu32,
                       v.fmt_int64, addr, icount_, v.fmt_int32[0],
                       v.fmt_int32[0]);
        break;
      case DWORD:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "  <-- [%016" PRIx64 "]    (%" PRId64
                       ")    int64:%" PRId64 " uint64:%" PRIu64,
                       value, addr, icount_, value, value);
        break;
      case FLOAT:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "  <-- [%016" PRIx64 "]    (%" PRId64
                       ")    flt:%e",
                       v.fmt_int64, addr, icount_, v.fmt_float[0]);
        break;
      case DOUBLE:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "  <-- [%016" PRIx64 "]    (%" PRId64
                       ")    dbl:%e",
                       v.fmt_int64, addr, icount_, v.fmt_double);
        break;
      case FLOAT_DOUBLE:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "  <-- [%016" PRIx64 "]    (%" PRId64
                       ")    flt:%e dbl:%e",
                       v.fmt_int64, addr, icount_, v.fmt_float[0],
                       v.fmt_double);
        break;
      default:
        UNREACHABLE();
    }
  }
}

void Simulator::TraceMemWr(int64_t addr, int64_t value, TraceType t) {
  if (v8_flags.trace_sim) {
    switch (t) {
      case BYTE:
        base::SNPrintF(trace_buf_,
                       "               %02" PRIx8 " --> [%016" PRIx64
                       "]    (%" PRId64 ")",
                       static_cast<uint8_t>(value), addr, icount_);
        break;
      case HALF:
        base::SNPrintF(trace_buf_,
                       "            %04" PRIx16 " --> [%016" PRIx64
                       "]    (%" PRId64 ")",
                       static_cast<uint16_t>(value), addr, icount_);
        break;
      case WORD:
        base::SNPrintF(trace_buf_,
                       "        %08" PRIx32 " --> [%016" PRIx64 "]    (%" PRId64
                       ")",
                       static_cast<uint32_t>(value), addr, icount_);
        break;
      case DWORD:
        base::SNPrintF(trace_buf_,
                       "%016" PRIx64 "  --> [%016" PRIx64 "]    (%" PRId64 " )",
                       value, addr, icount_);
        break;
      default:
        UNREACHABLE();
    }
  }
}

template <typename T>
void Simulator::TraceMemRd(int64_t addr, T value) {
  if (v8_flags.trace_sim) {
    switch (sizeof(T)) {
      case 1:
        base::SNPrintF(trace_buf_,
                       "%08" PRIx8 " <-- [%08" PRIx64 "]    (%" PRIu64
                       ")    int8:%" PRId8 " uint8:%" PRIu8,
                       static_cast<uint8_t>(value), addr, icount_,
                       static_cast<int8_t>(value), static_cast<uint8_t>(value));
        break;
      case 2:
        base::SNPrintF(trace_buf_,
                       "%08" PRIx16 " <-- [%08" PRIx64 "]    (%" PRIu64
                       ")    int16:%" PRId16 " uint16:%" PRIu16,
                       static_cast<uint16_t>(value), addr, icount_,
                       static_cast<int16_t>(value),
                       static_cast<uint16_t>(value));
        break;
      case 4:
        base::SNPrintF(trace_buf_,
                       "%08" PRIx32 " <-- [%08" PRIx64 "]    (%" PRIu64
                       ")    int32:%" PRId32 " uint32:%" PRIu32,
                       static_cast<uint32_t>(value), addr, icount_,
                       static_cast<int32_t>(value),
                       static_cast<uint32_t>(value));
        break;
      case 8:
        base::SNPrintF(trace_buf_,
                       "%08" PRIx64 " <-- [%08" PRIx64 "]    (%" PRIu64
                       ")    int64:%" PRId64 " uint64:%" PRIu64,
                       static_cast<uint64_t>(value), addr, icount_,
                       static_cast<int64_t>(value),
                       static_cast<uint64_t>(value));
        break;
      default:
        UNREACHABLE();
    }
  }
}

template <typename T>
void Simulator::TraceMemWr(int64_t addr, T value) {
  if (v8_flags.trace_sim) {
    switch (sizeof(T)) {
      case 1:
        base::SNPrintF(trace_buf_,
                       "      %02" PRIx8 " --> [%08" PRIx64 "]    (%" PRIu64
                       ")",
                       static_cast<uint8_t>(value), addr, icount_);
        break;
      case 2:
        base::SNPrintF(trace_buf_,
                       "    %04" PRIx16 " --> [%08" PRIx64 "]    (%" PRIu64 ")",
                       static_cast<uint16_t>(value), addr, icount_);
        break;
      case 4:
        base::SNPrintF(trace_buf_,
                       "%08" PRIx32 " --> [%08" PRIx64 "]    (%" PRIu64 ")",
                       static_cast<uint32_t>(value), addr, icount_);
        break;
      case 8:
        base::SNPrintF(trace_buf_,
                       "%16" PRIx64 " --> [%08" PRIx64 "]    (%" PRIu64 ")",
                       static_cast<uint64_t>(value), addr, icount_);
        break;
      default:
        UNREACHABLE();
    }
  }
}

bool Simulator::ProbeMemory(uintptr_t address, uintptr_t access_size) {
#if V8_ENABLE_WEBASSEMBLY && V8_TRAP_HANDLER_SUPPORTED
  uintptr_t last_accessed_byte = address + access_size - 1;
  uintptr_t current_pc = registers_[pc];
  uintptr_t landing_pad =
      trap_handler::ProbeMemory(last_accessed_byte, current_pc);
  if (!landing_pad) return true;
  set_pc(landing_pad);
  set_register(kWasmTrapHandlerFaultAddressRegister.code(), current_pc);
  return false;
#else
  return true;
#endif
}

int32_t Simulator::ReadW(int64_t addr, Instruction* instr, TraceType t) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory read from bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }

  {
    local_monitor_.NotifyLoad();
    int32_t* ptr = reinterpret_cast<int32_t*>(addr);
    TraceMemRd(addr, static_cast<int64_t>(*ptr), t);
    return *ptr;
  }
}

uint32_t Simulator::ReadWU(int64_t addr, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory read from bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }

  {
    local_monitor_.NotifyLoad();
    uint32_t* ptr = reinterpret_cast<uint32_t*>(addr);
    TraceMemRd(addr, static_cast<int64_t>(*ptr), WORD);
    return *ptr;
  }
}

void Simulator::WriteW(int64_t addr, int32_t value, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }

  {
    local_monitor_.NotifyStore();
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
    TraceMemWr(addr, value, WORD);
    int* ptr = reinterpret_cast<int*>(addr);
    *ptr = value;
    return;
  }
}

void Simulator::WriteConditionalW(int64_t addr, int32_t value,
                                  Instruction* instr, int32_t* done) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }

  if ((addr & 0x3) == 0) {
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    if (local_monitor_.NotifyStoreConditional(addr, TransactionSize::Word) &&
        GlobalMonitor::Get()->NotifyStoreConditional_Locked(
            addr, &global_monitor_thread_)) {
      local_monitor_.NotifyStore();
      GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
      TraceMemWr(addr, value, WORD);
      int* ptr = reinterpret_cast<int*>(addr);
      *ptr = value;
      *done = 1;
    } else {
      *done = 0;
    }
    return;
  }
  PrintF("Unaligned write at 0x%08" PRIx64 " , pc=0x%08" V8PRIxPTR "\n", addr,
         reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
}

int64_t Simulator::Read2W(int64_t addr, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory read from bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }

  {
    local_monitor_.NotifyLoad();
    int64_t* ptr = reinterpret_cast<int64_t*>(addr);
    TraceMemRd(addr, *ptr);
    return *ptr;
  }
}

void Simulator::Write2W(int64_t addr, int64_t value, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           "\n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }

  {
    local_monitor_.NotifyStore();
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
    TraceMemWr(addr, value, DWORD);
    int64_t* ptr = reinterpret_cast<int64_t*>(addr);
    *ptr = value;
    return;
  }
}

void Simulator::WriteConditional2W(int64_t addr, int64_t value,
                                   Instruction* instr, int32_t* done) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" PRIx64 " , pc=0x%08" PRIxPTR
           "\n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }

  if ((addr & kPointerAlignmentMask) == 0) {
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    if (local_monitor_.NotifyStoreConditional(addr,
                                              TransactionSize::DoubleWord) &&
        GlobalMonitor::Get()->NotifyStoreConditional_Locked(
            addr, &global_monitor_thread_)) {
      local_monitor_.NotifyStore();
      GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
      TraceMemWr(addr, value, DWORD);
      int64_t* ptr = reinterpret_cast<int64_t*>(addr);
      *ptr = value;
      *done = 1;
    } else {
      *done = 0;
    }
    return;
  }
  PrintF("Unaligned write at 0x%08" PRIx64 " , pc=0x%08" V8PRIxPTR "\n", addr,
         reinterpret_cast<intptr_t>(instr));
  DieOrDebug();
}

double Simulator::ReadD(int64_t addr, Instruction* instr) {
  local_monitor_.NotifyLoad();
  double* ptr = reinterpret_cast<double*>(addr);
  return *ptr;
}

void Simulator::WriteD(int64_t addr, double value, Instruction* instr) {
  local_monitor_.NotifyStore();
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
  double* ptr = reinterpret_cast<double*>(addr);
  *ptr = value;
  return;
}

uint16_t Simulator::ReadHU(int64_t addr, Instruction* instr) {
  local_monitor_.NotifyLoad();
  uint16_t* ptr = reinterpret_cast<uint16_t*>(addr);
  TraceMemRd(addr, static_cast<int64_t>(*ptr));
  return *ptr;
}

int16_t Simulator::ReadH(int64_t addr, Instruction* instr) {
  local_monitor_.NotifyLoad();
  int16_t* ptr = reinterpret_cast<int16_t*>(addr);
  TraceMemRd(addr, static_cast<int64_t>(*ptr));
  return *p
"""


```