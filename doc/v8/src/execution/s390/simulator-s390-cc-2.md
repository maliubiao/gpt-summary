Response:
The user wants me to analyze a C++ source code file for the V8 JavaScript engine, specifically the `simulator-s390.cc` file. I need to extract its functionalities based on the provided code snippet, which primarily contains an initialization table for instruction evaluation.

Here's a breakdown of the request and my plan:

1. **Identify the core function:** The provided code snippet shows the initialization of `EvalTable`. This suggests the main functionality of `simulator-s390.cc` is to *simulate* the execution of S390 architecture instructions.

2. **List the functionalities:**  I will enumerate the different instructions that the simulator can evaluate, based on the keys in `EvalTable`.

3. **Check for Torque:** The prompt explicitly asks if the file ends with `.tq`. Since it ends with `.cc`, it's a C++ file, not a Torque file.

4. **Relate to JavaScript (if applicable):**  The simulator's purpose is to run JavaScript code on an S390 architecture when a native S390 environment isn't available (e.g., during development or testing on a different platform). I need to give a simple JavaScript example that would be executed using this simulator.

5. **Code logic reasoning (example):** I need to pick one of the instructions and provide a simple hypothetical input and output, showing how the simulator might evaluate it.

6. **Common programming errors:** Simulators are often used to catch architecture-specific issues or errors in generated code. I need to think of a common programming error that the simulator might help uncover.

7. **Summarize the functionality:** Finally, I need to condense the findings into a concise summary.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果v8/src/execution/s390/simulator-s390.cc以.tq结尾: Yes
* 如果它与javascript的功能有关系: Yes
* 请用javascript举例说明: Yes
* 如果有代码逻辑推理: Yes
* 请给出假设输入与输出: Yes
* 如果涉及用户常见的编程错误: Yes
* 请举例说明: Yes
* 这是第3部分，共10部分: Acknowledged, but doesn't affect the analysis of this code snippet.
* 请归纳一下它的功能: Yes

Confidence Score: 5/5

**Mental Sandbox:**

I'll pick `MVCLU` (Move Characters Long Under Mask) as the example instruction for the code logic reasoning. I'll imagine it moving a string in memory with a specific mask.

For the common programming error, I'll consider memory access errors, which are often caught by simulators.

Okay, the planning is complete. I'm ready to generate the response.
基于您提供的代码片段，`v8/src/execution/s390/simulator-s390.cc` 的主要功能是 **模拟 S390 架构的指令执行**。

以下是更详细的分析：

1. **模拟指令集:**  代码中的 `lTable` 和 `EvalTable` 数组将特定的 S390 指令（例如 `MVCLU`, `CLCLU`, `STMY` 等）与 `Simulator` 类中相应的评估函数（例如 `Evaluate_MVCLU`, `Evaluate_CLCLU`, `Evaluate_STMY` 等）关联起来。这表明 `simulator-s390.cc` 实现了对这些 S390 指令的软件模拟。

2. **指令评估:**  每个 `Evaluate_XXX` 函数（尽管其具体实现未在提供的代码中）负责模拟对应 S390 指令的行为，包括修改模拟的寄存器、内存和条件码。

**关于文件扩展名：**

`v8/src/execution/s390/simulator-s390.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**。如果它以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。

**与 JavaScript 的关系：**

`v8/src/execution/s390/simulator-s390.cc` 与 JavaScript 的功能密切相关。当 V8 JavaScript 引擎需要在非 S390 架构的平台上运行 S390 架构的代码（例如，在开发或测试阶段），或者在某些嵌入式环境中时，就需要使用这个模拟器。

**JavaScript 示例：**

虽然 `simulator-s390.cc` 本身不是 JavaScript 代码，但它可以执行为了 S390 架构编译的 JavaScript 代码。例如，以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
console.log(result);
```

当这段 JavaScript 代码被 V8 引擎执行时，它会被编译成 S390 架构的机器码。如果 V8 引擎运行在一个非 S390 平台上，`simulator-s390.cc` 就会负责解释和执行这些 S390 指令，从而模拟出在 S390 架构上的运行效果。

**代码逻辑推理示例：**

假设我们关注 `MVCLU` 指令（Move Characters Long Under Mask），它用于在内存中移动一段数据，并受一个掩码控制。

**假设输入：**

* **寄存器:**
    * `R1`: 源地址（假设为内存地址 `0x1000`）
    * `R2`: 目标地址（假设为内存地址 `0x2000`）
    * `R3`: 长度（假设为 `10` 字节）
    * `R4`: 掩码（假设为 `0xFF`，表示不屏蔽任何字节）
* **内存 (源地址):**
    * `0x1000`: `A`
    * `0x1001`: `B`
    * `0x1002`: `C`
    * ...
    * `0x1009`: `J`
* **内存 (目标地址):**  初始状态可以是任意值。

**预期输出：**

当模拟器执行 `MVCLU R1, R2, R3, R4` 时，预期结果是：

* **内存 (目标地址):**
    * `0x2000`: `A`
    * `0x2001`: `B`
    * `0x2002`: `C`
    * ...
    * `0x2009`: `J`
* **寄存器:** `R1`, `R2`, `R3`, `R4` 的值可能根据 `MVCLU` 指令的具体实现而改变（例如，指向下一个未处理的字节）。

**用户常见的编程错误示例：**

在使用 JavaScript 并且涉及到与底层交互或者当 JavaScript 引擎尝试优化代码时，模拟器可以帮助发现一些常见的编程错误，例如：

* **内存越界访问:**  如果编译后的 JavaScript 代码生成了访问超出分配内存范围的 S390 指令，模拟器在执行这些指令时可能会检测到并报错。

   **例子 (虽然是 JavaScript 层面的，但模拟器可以帮助发现底层问题):**

   ```javascript
   let arr = new Array(5);
   arr[10] = 1; // 这是一个越界访问
   ```

   虽然这段代码在 JavaScript 层面可能不会立即崩溃，但当 V8 将其编译成机器码并在模拟器上运行时，模拟器可能会捕获到对应的内存访问错误。

* **类型混淆导致的错误:**  在某些情况下，JavaScript 的动态类型可能会导致一些在编译后的机器码层面才显现出来的问题。例如，如果一段代码错误地将一个整数的地址当作指针使用，模拟器可能会在执行相关指令时报错。

**功能归纳 (基于提供的代码片段):**

这段代码片段展示了 `v8/src/execution/s390/simulator-s390.cc` 的核心功能之一：**指令分发和初步的模拟框架**。它定义了如何将 S390 指令映射到相应的 C++ 函数进行模拟执行。  更广泛地说，`simulator-s390.cc` 的完整功能是为 V8 引擎提供一个在非 S390 平台上运行 S390 架构代码的能力，这对于跨平台开发、测试以及某些特定的嵌入式场景至关重要。

Prompt: 
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/s390/simulator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共10部分，请归纳一下它的功能

"""
lTable[MVCLU] = &Simulator::Evaluate_MVCLU;
  EvalTable[CLCLU] = &Simulator::Evaluate_CLCLU;
  EvalTable[STMY] = &Simulator::Evaluate_STMY;
  EvalTable[LMH] = &Simulator::Evaluate_LMH;
  EvalTable[LMY] = &Simulator::Evaluate_LMY;
  EvalTable[TP] = &Simulator::Evaluate_TP;
  EvalTable[SRAK] = &Simulator::Evaluate_SRAK;
  EvalTable[SLAK] = &Simulator::Evaluate_SLAK;
  EvalTable[SRLK] = &Simulator::Evaluate_SRLK;
  EvalTable[SLLK] = &Simulator::Evaluate_SLLK;
  EvalTable[LOCG] = &Simulator::Evaluate_LOCG;
  EvalTable[STOCG] = &Simulator::Evaluate_STOCG;
  EvalTable[LANG] = &Simulator::Evaluate_LANG;
  EvalTable[LAOG] = &Simulator::Evaluate_LAOG;
  EvalTable[LAXG] = &Simulator::Evaluate_LAXG;
  EvalTable[LAAG] = &Simulator::Evaluate_LAAG;
  EvalTable[LAALG] = &Simulator::Evaluate_LAALG;
  EvalTable[LOC] = &Simulator::Evaluate_LOC;
  EvalTable[STOC] = &Simulator::Evaluate_STOC;
  EvalTable[LAN] = &Simulator::Evaluate_LAN;
  EvalTable[LAO] = &Simulator::Evaluate_LAO;
  EvalTable[LAX] = &Simulator::Evaluate_LAX;
  EvalTable[LAA] = &Simulator::Evaluate_LAA;
  EvalTable[LAAL] = &Simulator::Evaluate_LAAL;
  EvalTable[BRXHG] = &Simulator::Evaluate_BRXHG;
  EvalTable[BRXLG] = &Simulator::Evaluate_BRXLG;
  EvalTable[RISBLG] = &Simulator::Evaluate_RISBLG;
  EvalTable[RNSBG] = &Simulator::Evaluate_RNSBG;
  EvalTable[RISBG] = &Simulator::Evaluate_RISBG;
  EvalTable[ROSBG] = &Simulator::Evaluate_ROSBG;
  EvalTable[RXSBG] = &Simulator::Evaluate_RXSBG;
  EvalTable[RISBGN] = &Simulator::Evaluate_RISBGN;
  EvalTable[RISBHG] = &Simulator::Evaluate_RISBHG;
  EvalTable[CGRJ] = &Simulator::Evaluate_CGRJ;
  EvalTable[CGIT] = &Simulator::Evaluate_CGIT;
  EvalTable[CIT] = &Simulator::Evaluate_CIT;
  EvalTable[CLFIT] = &Simulator::Evaluate_CLFIT;
  EvalTable[CGIJ] = &Simulator::Evaluate_CGIJ;
  EvalTable[CIJ] = &Simulator::Evaluate_CIJ;
  EvalTable[AHIK] = &Simulator::Evaluate_AHIK;
  EvalTable[AGHIK] = &Simulator::Evaluate_AGHIK;
  EvalTable[ALHSIK] = &Simulator::Evaluate_ALHSIK;
  EvalTable[ALGHSIK] = &Simulator::Evaluate_ALGHSIK;
  EvalTable[CGRB] = &Simulator::Evaluate_CGRB;
  EvalTable[CGIB] = &Simulator::Evaluate_CGIB;
  EvalTable[CIB] = &Simulator::Evaluate_CIB;
  EvalTable[LDEB] = &Simulator::Evaluate_LDEB;
  EvalTable[LXDB] = &Simulator::Evaluate_LXDB;
  EvalTable[LXEB] = &Simulator::Evaluate_LXEB;
  EvalTable[MXDB] = &Simulator::Evaluate_MXDB;
  EvalTable[KEB] = &Simulator::Evaluate_KEB;
  EvalTable[CEB] = &Simulator::Evaluate_CEB;
  EvalTable[AEB] = &Simulator::Evaluate_AEB;
  EvalTable[SEB] = &Simulator::Evaluate_SEB;
  EvalTable[MDEB] = &Simulator::Evaluate_MDEB;
  EvalTable[DEB] = &Simulator::Evaluate_DEB;
  EvalTable[MAEB] = &Simulator::Evaluate_MAEB;
  EvalTable[MSEB] = &Simulator::Evaluate_MSEB;
  EvalTable[TCEB] = &Simulator::Evaluate_TCEB;
  EvalTable[TCDB] = &Simulator::Evaluate_TCDB;
  EvalTable[TCXB] = &Simulator::Evaluate_TCXB;
  EvalTable[SQEB] = &Simulator::Evaluate_SQEB;
  EvalTable[SQDB] = &Simulator::Evaluate_SQDB;
  EvalTable[MEEB] = &Simulator::Evaluate_MEEB;
  EvalTable[KDB] = &Simulator::Evaluate_KDB;
  EvalTable[CDB] = &Simulator::Evaluate_CDB;
  EvalTable[ADB] = &Simulator::Evaluate_ADB;
  EvalTable[SDB] = &Simulator::Evaluate_SDB;
  EvalTable[MDB] = &Simulator::Evaluate_MDB;
  EvalTable[DDB] = &Simulator::Evaluate_DDB;
  EvalTable[MADB] = &Simulator::Evaluate_MADB;
  EvalTable[MSDB] = &Simulator::Evaluate_MSDB;
  EvalTable[SLDT] = &Simulator::Evaluate_SLDT;
  EvalTable[SRDT] = &Simulator::Evaluate_SRDT;
  EvalTable[SLXT] = &Simulator::Evaluate_SLXT;
  EvalTable[SRXT] = &Simulator::Evaluate_SRXT;
  EvalTable[TDCET] = &Simulator::Evaluate_TDCET;
  EvalTable[TDGET] = &Simulator::Evaluate_TDGET;
  EvalTable[TDCDT] = &Simulator::Evaluate_TDCDT;
  EvalTable[TDGDT] = &Simulator::Evaluate_TDGDT;
  EvalTable[TDCXT] = &Simulator::Evaluate_TDCXT;
  EvalTable[TDGXT] = &Simulator::Evaluate_TDGXT;
  EvalTable[LEY] = &Simulator::Evaluate_LEY;
  EvalTable[LDY] = &Simulator::Evaluate_LDY;
  EvalTable[STEY] = &Simulator::Evaluate_STEY;
  EvalTable[STDY] = &Simulator::Evaluate_STDY;
  EvalTable[CZDT] = &Simulator::Evaluate_CZDT;
  EvalTable[CZXT] = &Simulator::Evaluate_CZXT;
  EvalTable[CDZT] = &Simulator::Evaluate_CDZT;
  EvalTable[CXZT] = &Simulator::Evaluate_CXZT;
}

Simulator::Simulator(Isolate* isolate) : isolate_(isolate) {
  static base::OnceType once = V8_ONCE_INIT;
  base::CallOnce(&once, &Simulator::EvalTableInit);
// Set up simulator support first. Some of this information is needed to
// setup the architecture state.
  stack_ = reinterpret_cast<uint8_t*>(base::Malloc(AllocatedStackSize()));
  pc_modified_ = false;
  icount_ = 0;
  break_pc_ = nullptr;
  break_instr_ = 0;

// make sure our register type can hold exactly 4/8 bytes
  DCHECK_EQ(sizeof(intptr_t), 8);
  // Set up architecture state.
  // All registers are initialized to zero to start with.
  for (int i = 0; i < kNumGPRs; i++) {
    registers_[i] = 0;
  }
  condition_reg_ = 0;
  special_reg_pc_ = 0;

  // Initializing FP registers.
  for (int i = 0; i < kNumFPRs; i++) {
    set_simd_register_by_lane<double>(i, 0, 0.0);
    set_simd_register_by_lane<double>(i, 1, 0.0);
  }

  // The sp is initialized to point to the bottom (high address) of the
  // allocated stack area. To be safe in potential stack underflows we leave
  // some buffer below.
  registers_[sp] = reinterpret_cast<intptr_t>(stack_) + UsableStackSize();

  last_debugger_input_ = nullptr;
}

Simulator::~Simulator() { base::Free(stack_); }

// Get the active Simulator for the current thread.
Simulator* Simulator::current(Isolate* isolate) {
  v8::internal::Isolate::PerIsolateThreadData* isolate_data =
      isolate->FindOrAllocatePerThreadDataForThisThread();
  DCHECK_NOT_NULL(isolate_data);

  Simulator* sim = isolate_data->simulator();
  if (sim == nullptr) {
    // TODO(146): delete the simulator object when a thread/isolate goes away.
    sim = new Simulator(isolate);
    isolate_data->set_simulator(sim);
  }
  return sim;
}

// Sets the register in the architecture state.
void Simulator::set_register(int reg, uint64_t value) {
  DCHECK((reg >= 0) && (reg < kNumGPRs));
  registers_[reg] = value;
}

// Get the register from the architecture state.
const uint64_t& Simulator::get_register(int reg) const {
  DCHECK((reg >= 0) && (reg < kNumGPRs));
  return registers_[reg];
}

uint64_t& Simulator::get_register(int reg) {
  DCHECK((reg >= 0) && (reg < kNumGPRs));
  return registers_[reg];
}

template <typename T>
T Simulator::get_low_register(int reg) const {
  DCHECK((reg >= 0) && (reg < kNumGPRs));
  // Stupid code added to avoid bug in GCC.
  // See: http://gcc.gnu.org/bugzilla/show_bug.cgi?id=43949
  if (reg >= kNumGPRs) return 0;
  // End stupid code.
  return static_cast<T>(registers_[reg] & 0xFFFFFFFF);
}

template <typename T>
T Simulator::get_high_register(int reg) const {
  DCHECK((reg >= 0) && (reg < kNumGPRs));
  // Stupid code added to avoid bug in GCC.
  // See: http://gcc.gnu.org/bugzilla/show_bug.cgi?id=43949
  if (reg >= kNumGPRs) return 0;
  // End stupid code.
  return static_cast<T>(registers_[reg] >> 32);
}

template <class T, class R>
static R ComputeSignedRoundingResult(T a, T n) {
  constexpr T NINF = -std::numeric_limits<T>::infinity();
  constexpr T PINF = std::numeric_limits<T>::infinity();
  constexpr long double MN =
      static_cast<long double>(std::numeric_limits<R>::min());
  constexpr long double MP =
      static_cast<long double>(std::numeric_limits<R>::max());

  if (NINF <= a && a < MN && n < MN) {
    return std::numeric_limits<R>::min();
  } else if (NINF < a && a < MN && n == MN) {
    return std::numeric_limits<R>::min();
  } else if (MN <= a && a < 0.0) {
    return static_cast<R>(n);
  } else if (a == 0.0) {
    return 0;
  } else if (0.0 < a && a <= MP) {
    return static_cast<R>(n);
  } else if (MP < a && a <= PINF && n == MP) {
    return std::numeric_limits<R>::max();
  } else if (MP < a && a <= PINF && n > MP) {
    return std::numeric_limits<R>::max();
  } else if (std::isnan(a)) {
    return std::numeric_limits<R>::min();
  }
  UNIMPLEMENTED();
  return 0;
}

template <class T, class R>
static R ComputeLogicalRoundingResult(T a, T n) {
  constexpr T NINF = -std::numeric_limits<T>::infinity();
  constexpr T PINF = std::numeric_limits<T>::infinity();
  constexpr long double MP =
      static_cast<long double>(std::numeric_limits<R>::max());

  if (NINF <= a && a <= 0.0) {
    return 0;
  } else if (0.0 < a && a <= MP) {
    return static_cast<R>(n);
  } else if (MP < a && a <= PINF) {
    return std::numeric_limits<R>::max();
  } else if (std::isnan(a)) {
    return 0;
  }
  UNIMPLEMENTED();
  return 0;
}

void Simulator::set_low_register(int reg, uint32_t value) {
  uint64_t shifted_val = static_cast<uint64_t>(value);
  uint64_t orig_val = static_cast<uint64_t>(registers_[reg]);
  uint64_t result = (orig_val >> 32 << 32) | shifted_val;
  registers_[reg] = result;
}

void Simulator::set_high_register(int reg, uint32_t value) {
  uint64_t shifted_val = static_cast<uint64_t>(value) << 32;
  uint64_t orig_val = static_cast<uint64_t>(registers_[reg]);
  uint64_t result = (orig_val & 0xFFFFFFFF) | shifted_val;
  registers_[reg] = result;
}

double Simulator::get_double_from_register_pair(int reg) {
  DCHECK((reg >= 0) && (reg < kNumGPRs) && ((reg % 2) == 0));
  double dm_val = 0.0;
  return (dm_val);
}

// Raw access to the PC register.
void Simulator::set_pc(intptr_t value) {
  pc_modified_ = true;
  special_reg_pc_ = value;
}

bool Simulator::has_bad_pc() const {
  return ((special_reg_pc_ == bad_lr) || (special_reg_pc_ == end_sim_pc));
}

// Raw access to the PC register without the special adjustment when reading.
intptr_t Simulator::get_pc() const { return special_reg_pc_; }

// Runtime FP routines take:
// - two double arguments
// - one double argument and zero or one integer arguments.
// All are consructed here from d1, d2 and r2.
void Simulator::GetFpArgs(double* x, double* y, intptr_t* z) {
  *x = get_fpr<double>(0);
  *y = get_fpr<double>(2);
  *z = get_register(2);
}

// The return value is in d0.
void Simulator::SetFpResult(const double& result) { set_fpr(0, result); }

void Simulator::TrashCallerSaveRegisters() {
// We don't trash the registers with the return value.
#if 0  // A good idea to trash volatile registers, needs to be done
  registers_[2] = 0x50BAD4U;
  registers_[3] = 0x50BAD4U;
  registers_[12] = 0x50BAD4U;
#endif
}

uint32_t Simulator::ReadWU(intptr_t addr) {
  uint32_t* ptr = reinterpret_cast<uint32_t*>(addr);
  return *ptr;
}

int64_t Simulator::ReadW64(intptr_t addr) {
  int64_t* ptr = reinterpret_cast<int64_t*>(addr);
  return *ptr;
}

int32_t Simulator::ReadW(intptr_t addr) {
  int32_t* ptr = reinterpret_cast<int32_t*>(addr);
  return *ptr;
}

void Simulator::WriteW(intptr_t addr, uint32_t value) {
  uint32_t* ptr = reinterpret_cast<uint32_t*>(addr);
  *ptr = value;
  return;
}

void Simulator::WriteW(intptr_t addr, int32_t value) {
  int32_t* ptr = reinterpret_cast<int32_t*>(addr);
  *ptr = value;
  return;
}

uint16_t Simulator::ReadHU(intptr_t addr) {
  uint16_t* ptr = reinterpret_cast<uint16_t*>(addr);
  return *ptr;
}

int16_t Simulator::ReadH(intptr_t addr) {
  int16_t* ptr = reinterpret_cast<int16_t*>(addr);
  return *ptr;
}

void Simulator::WriteH(intptr_t addr, uint16_t value) {
  uint16_t* ptr = reinterpret_cast<uint16_t*>(addr);
  *ptr = value;
  return;
}

void Simulator::WriteH(intptr_t addr, int16_t value) {
  int16_t* ptr = reinterpret_cast<int16_t*>(addr);
  *ptr = value;
  return;
}

uint8_t Simulator::ReadBU(intptr_t addr) {
  uint8_t* ptr = reinterpret_cast<uint8_t*>(addr);
  return *ptr;
}

int8_t Simulator::ReadB(intptr_t addr) {
  int8_t* ptr = reinterpret_cast<int8_t*>(addr);
  return *ptr;
}

void Simulator::WriteB(intptr_t addr, uint8_t value) {
  uint8_t* ptr = reinterpret_cast<uint8_t*>(addr);
  *ptr = value;
}

void Simulator::WriteB(intptr_t addr, int8_t value) {
  int8_t* ptr = reinterpret_cast<int8_t*>(addr);
  *ptr = value;
}

int64_t Simulator::ReadDW(intptr_t addr) {
  int64_t* ptr = reinterpret_cast<int64_t*>(addr);
  return *ptr;
}

void Simulator::WriteDW(intptr_t addr, int64_t value) {
  int64_t* ptr = reinterpret_cast<int64_t*>(addr);
  *ptr = value;
  return;
}

/**
 * Reads a double value from memory at given address.
 */
double Simulator::ReadDouble(intptr_t addr) {
  double* ptr = reinterpret_cast<double*>(addr);
  return *ptr;
}

float Simulator::ReadFloat(intptr_t addr) {
  float* ptr = reinterpret_cast<float*>(addr);
  return *ptr;
}

// Returns the limit of the stack area to enable checking for stack overflows.
uintptr_t Simulator::StackLimit(uintptr_t c_limit) const {
  // The simulator uses a separate JS stack. If we have exhausted the C stack,
  // we also drop down the JS limit to reflect the exhaustion on the JS stack.
  if (base::Stack::GetCurrentStackPosition() < c_limit) {
    return reinterpret_cast<uintptr_t>(get_sp());
  }

  // Otherwise the limit is the JS stack. Leave a safety margin to prevent
  // overrunning the stack when pushing values.
  return reinterpret_cast<uintptr_t>(stack_) + kStackProtectionSize;
}

base::Vector<uint8_t> Simulator::GetCentralStackView() const {
  // We do not add an additional safety margin as above in
  // Simulator::StackLimit, as this is currently only used in wasm::StackMemory,
  // which adds its own margin.
  return base::VectorOf(stack_, UsableStackSize());
}

// Unsupported instructions use Format to print an error and stop execution.
void Simulator::Format(Instruction* instr, const char* format) {
  PrintF("Simulator found unsupported instruction:\n 0x%08" V8PRIxPTR ": %s\n",
         reinterpret_cast<intptr_t>(instr), format);
  UNIMPLEMENTED();
}

// Calculate C flag value for additions.
bool Simulator::CarryFrom(int32_t left, int32_t right, int32_t carry) {
  uint32_t uleft = static_cast<uint32_t>(left);
  uint32_t uright = static_cast<uint32_t>(right);
  uint32_t urest = 0xFFFFFFFFU - uleft;

  return (uright > urest) ||
         (carry && (((uright + 1) > urest) || (uright > (urest - 1))));
}

// Calculate C flag value for subtractions.
bool Simulator::BorrowFrom(int32_t left, int32_t right) {
  uint32_t uleft = static_cast<uint32_t>(left);
  uint32_t uright = static_cast<uint32_t>(right);

  return (uright > uleft);
}

// Calculate V flag value for additions and subtractions.
template <typename T1>
bool Simulator::OverflowFromSigned(T1 alu_out, T1 left, T1 right,
                                   bool addition) {
  bool overflow;
  if (addition) {
    // operands have the same sign
    overflow = ((left >= 0 && right >= 0) || (left < 0 && right < 0))
               // and operands and result have different sign
               && ((left < 0 && alu_out >= 0) || (left >= 0 && alu_out < 0));
  } else {
    // operands have different signs
    overflow = ((left < 0 && right >= 0) || (left >= 0 && right < 0))
               // and first operand and result have different signs
               && ((left < 0 && alu_out >= 0) || (left >= 0 && alu_out < 0));
  }
  return overflow;
}

static void decodeObjectPair(ObjectPair* pair, intptr_t* x, intptr_t* y) {
  *x = static_cast<intptr_t>(pair->x);
  *y = static_cast<intptr_t>(pair->y);
}

// Calls into the V8 runtime.
using SimulatorRuntimeCall = intptr_t (*)(
    intptr_t arg0, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4,
    intptr_t arg5, intptr_t arg6, intptr_t arg7, intptr_t arg8, intptr_t arg9,
    intptr_t arg10, intptr_t arg11, intptr_t arg12, intptr_t arg13,
    intptr_t arg14, intptr_t arg15, intptr_t arg16, intptr_t arg17,
    intptr_t arg18, intptr_t arg19);
using SimulatorRuntimePairCall = ObjectPair (*)(
    intptr_t arg0, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4,
    intptr_t arg5, intptr_t arg6, intptr_t arg7, intptr_t arg8, intptr_t arg9,
    intptr_t arg10, intptr_t arg11, intptr_t arg12, intptr_t arg13,
    intptr_t arg14, intptr_t arg15, intptr_t arg16, intptr_t arg17,
    intptr_t arg18, intptr_t arg19);

// These prototypes handle the four types of FP calls.
using SimulatorRuntimeCompareCall = int (*)(double darg0, double darg1);
using SimulatorRuntimeFPFPCall = double (*)(double darg0, double darg1);
using SimulatorRuntimeFPCall = double (*)(double darg0);
using SimulatorRuntimeFPIntCall = double (*)(double darg0, intptr_t arg0);
// Define four args for future flexibility; at the time of this writing only
// one is ever used.
using SimulatorRuntimeFPTaggedCall = double (*)(int32_t arg0, int32_t arg1,
                                                int32_t arg2, int32_t arg3);

// This signature supports direct call in to API function native callback
// (refer to InvocationCallback in v8.h).
using SimulatorRuntimeDirectApiCall = void (*)(intptr_t arg0);
// This signature supports direct call to accessor getter callback.
using SimulatorRuntimeDirectGetterCall = void (*)(intptr_t arg0, intptr_t arg1);

// Software interrupt instructions are used by the simulator to call into the
// C-based V8 runtime.
void Simulator::SoftwareInterrupt(Instruction* instr) {
  int svc = instr->SvcValue();
  switch (svc) {
    case kCallRtRedirected: {
      // Check if stack is aligned. Error if not aligned is reported below to
      // include information on the function called.
      bool stack_aligned =
          (get_register(sp) & (v8_flags.sim_stack_alignment - 1)) == 0;
      Redirection* redirection = Redirection::FromInstruction(instr);
      const int kArgCount = 20;
      const int kRegisterArgCount = 5;
      int arg0_regnum = 2;
      intptr_t result_buffer = 0;
      bool uses_result_buffer =
          redirection->type() == ExternalReference::BUILTIN_CALL_PAIR &&
          !ABI_RETURNS_OBJECTPAIR_IN_REGS;
      if (uses_result_buffer) {
        result_buffer = get_register(r2);
        arg0_regnum++;
      }
      intptr_t arg[kArgCount];
      // First 5 arguments in registers r2-r6.
      for (int i = 0; i < kRegisterArgCount; i++) {
        arg[i] = get_register(arg0_regnum + i);
      }
      // Remaining arguments on stack
      intptr_t* stack_pointer = reinterpret_cast<intptr_t*>(get_register(sp));
      for (int i = kRegisterArgCount; i < kArgCount; i++) {
        arg[i] =
            stack_pointer[(kCalleeRegisterSaveAreaSize / kSystemPointerSize) +
                          (i - kRegisterArgCount)];
      }
      static_assert(kArgCount == kRegisterArgCount + 15);
      static_assert(kMaxCParameters == kArgCount);
      bool fp_call =
          (redirection->type() == ExternalReference::BUILTIN_FP_FP_CALL) ||
          (redirection->type() == ExternalReference::BUILTIN_COMPARE_CALL) ||
          (redirection->type() == ExternalReference::BUILTIN_FP_CALL) ||
          (redirection->type() == ExternalReference::BUILTIN_FP_INT_CALL);

      // Place the return address on the stack, making the call GC safe.
      *reinterpret_cast<intptr_t*>(get_register(sp) +
                                   kStackFrameRASlot * kSystemPointerSize) =
          get_register(r14);

      intptr_t external =
          reinterpret_cast<intptr_t>(redirection->external_function());
      if (fp_call) {
        double dval0, dval1;  // one or two double parameters
        intptr_t ival;        // zero or one integer parameters
        int iresult = 0;      // integer return value
        double dresult = 0;   // double return value
        GetFpArgs(&dval0, &dval1, &ival);
        if (v8_flags.trace_sim || !stack_aligned) {
          SimulatorRuntimeCall generic_target =
              reinterpret_cast<SimulatorRuntimeCall>(external);
          switch (redirection->type()) {
            case ExternalReference::BUILTIN_FP_FP_CALL:
            case ExternalReference::BUILTIN_COMPARE_CALL:
              PrintF("Call to host function at %p with args %f, %f",
                     reinterpret_cast<void*>(FUNCTION_ADDR(generic_target)),
                     dval0, dval1);
              break;
            case ExternalReference::BUILTIN_FP_CALL:
              PrintF("Call to host function at %p with arg %f",
                     reinterpret_cast<void*>(FUNCTION_ADDR(generic_target)),
                     dval0);
              break;
            case ExternalReference::BUILTIN_FP_INT_CALL:
              PrintF("Call to host function at %p with args %f, %" V8PRIdPTR,
                     reinterpret_cast<void*>(FUNCTION_ADDR(generic_target)),
                     dval0, ival);
              break;
            default:
              UNREACHABLE();
          }
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08" V8PRIxPTR "\n",
                   static_cast<intptr_t>(get_register(sp)));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        switch (redirection->type()) {
          case ExternalReference::BUILTIN_COMPARE_CALL: {
            SimulatorRuntimeCompareCall target =
                reinterpret_cast<SimulatorRuntimeCompareCall>(external);
            iresult = target(dval0, dval1);
            set_register(r2, iresult);
            break;
          }
          case ExternalReference::BUILTIN_FP_FP_CALL: {
            SimulatorRuntimeFPFPCall target =
                reinterpret_cast<SimulatorRuntimeFPFPCall>(external);
            dresult = target(dval0, dval1);
            SetFpResult(dresult);
            break;
          }
          case ExternalReference::BUILTIN_FP_CALL: {
            SimulatorRuntimeFPCall target =
                reinterpret_cast<SimulatorRuntimeFPCall>(external);
            dresult = target(dval0);
            SetFpResult(dresult);
            break;
          }
          case ExternalReference::BUILTIN_FP_INT_CALL: {
            SimulatorRuntimeFPIntCall target =
                reinterpret_cast<SimulatorRuntimeFPIntCall>(external);
            dresult = target(dval0, ival);
            SetFpResult(dresult);
            break;
          }
          default:
            UNREACHABLE();
        }
        if (v8_flags.trace_sim) {
          switch (redirection->type()) {
            case ExternalReference::BUILTIN_COMPARE_CALL:
              PrintF("Returned %08x\n", iresult);
              break;
            case ExternalReference::BUILTIN_FP_FP_CALL:
            case ExternalReference::BUILTIN_FP_CALL:
            case ExternalReference::BUILTIN_FP_INT_CALL:
              PrintF("Returned %f\n", dresult);
              break;
            default:
              UNREACHABLE();
          }
        }
      } else if (redirection->type() ==
                 ExternalReference::BUILTIN_FP_POINTER_CALL) {
        if (v8_flags.trace_sim || !stack_aligned) {
          PrintF("Call to host function at %p args %08" V8PRIxPTR,
                 reinterpret_cast<void*>(external), arg[0]);
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08" V8PRIxPTR "\n",
                   get_register(sp));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        SimulatorRuntimeFPTaggedCall target =
            reinterpret_cast<SimulatorRuntimeFPTaggedCall>(external);
        double dresult = target(arg[0], arg[1], arg[2], arg[3]);
#ifdef DEBUG
        TrashCallerSaveRegisters();
#endif
        SetFpResult(dresult);
        if (v8_flags.trace_sim) {
          PrintF("Returned %f\n", dresult);
        }
      } else if (redirection->type() == ExternalReference::DIRECT_API_CALL) {
        // See callers of MacroAssembler::CallApiFunctionAndReturn for
        // explanation of register usage.
        // void f(v8::FunctionCallbackInfo&)
        if (v8_flags.trace_sim || !stack_aligned) {
          PrintF("Call to host function at %p args %08" V8PRIxPTR,
                 reinterpret_cast<void*>(external), arg[0]);
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08" V8PRIxPTR "\n",
                   static_cast<intptr_t>(get_register(sp)));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        SimulatorRuntimeDirectApiCall target =
            reinterpret_cast<SimulatorRuntimeDirectApiCall>(external);
        target(arg[0]);
      } else if (redirection->type() == ExternalReference::DIRECT_GETTER_CALL) {
        // See callers of MacroAssembler::CallApiFunctionAndReturn for
        // explanation of register usage.
        // void f(v8::Local<String> property, v8::PropertyCallbackInfo& info)
        if (v8_flags.trace_sim || !stack_aligned) {
          PrintF("Call to host function at %p args %08" V8PRIxPTR
                 " %08" V8PRIxPTR,
                 reinterpret_cast<void*>(external), arg[0], arg[1]);
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08" V8PRIxPTR "\n",
                   static_cast<intptr_t>(get_register(sp)));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        SimulatorRuntimeDirectGetterCall target =
            reinterpret_cast<SimulatorRuntimeDirectGetterCall>(external);
        if (!ABI_PASSES_HANDLES_IN_REGS) {
          arg[0] = base::bit_cast<intptr_t>(arg[0]);
        }
        target(arg[0], arg[1]);
      } else {
        // builtin call.
        if (v8_flags.trace_sim || !stack_aligned) {
          SimulatorRuntimeCall target =
              reinterpret_cast<SimulatorRuntimeCall>(external);
          PrintF(
              "Call to host function at %p,\n"
              "\t\t\t\targs %08" V8PRIxPTR ", %08" V8PRIxPTR ", %08" V8PRIxPTR
              ", %08" V8PRIxPTR ", %08" V8PRIxPTR ", %08" V8PRIxPTR
              ", %08" V8PRIxPTR ", %08" V8PRIxPTR ", %08" V8PRIxPTR
              ", %08" V8PRIxPTR ", %08" V8PRIxPTR ", %08" V8PRIxPTR
              ", %08" V8PRIxPTR ", %08" V8PRIxPTR ", %08" V8PRIxPTR
              ", %08" V8PRIxPTR ", %08" V8PRIxPTR ", %08" V8PRIxPTR
              ", %08" V8PRIxPTR ", %08" V8PRIxPTR,
              reinterpret_cast<void*>(FUNCTION_ADDR(target)), arg[0], arg[1],
              arg[2], arg[3], arg[4], arg[5], arg[6], arg[7], arg[8], arg[9],
              arg[10], arg[11], arg[12], arg[13], arg[14], arg[15], arg[16],
              arg[17], arg[18], arg[19]);
          if (!stack_aligned) {
            PrintF(" with unaligned stack %08" V8PRIxPTR "\n",
                   static_cast<intptr_t>(get_register(sp)));
          }
          PrintF("\n");
        }
        CHECK(stack_aligned);
        if (redirection->type() == ExternalReference::BUILTIN_CALL_PAIR) {
          SimulatorRuntimePairCall target =
              reinterpret_cast<SimulatorRuntimePairCall>(external);
          ObjectPair result =
              target(arg[0], arg[1], arg[2], arg[3], arg[4], arg[5], arg[6],
                     arg[7], arg[8], arg[9], arg[10], arg[11], arg[12], arg[13],
                     arg[14], arg[15], arg[16], arg[17], arg[18], arg[19]);
          intptr_t x;
          intptr_t y;
          decodeObjectPair(&result, &x, &y);
          if (v8_flags.trace_sim) {
            PrintF("Returned {%08" V8PRIxPTR ", %08" V8PRIxPTR "}\n", x, y);
          }
          if (ABI_RETURNS_OBJECTPAIR_IN_REGS) {
            set_register(r2, x);
            set_register(r3, y);
          } else {
            memcpy(reinterpret_cast<void*>(result_buffer), &result,
                   sizeof(ObjectPair));
            set_register(r2, result_buffer);
          }
        } else {
          // FAST_C_CALL is temporarily handled here as well, because we lack
          // proper support for direct C calls with FP params in the simulator.
          // The generic BUILTIN_CALL path assumes all parameters are passed in
          // the GP registers, thus supporting calling the slow callback without
          // crashing. The reason for that is that in the mjsunit tests we check
          // the `fast_c_api.supports_fp_params` (which is false on
          // non-simulator builds for arm/arm64), thus we expect that the slow
          // path will be called. And since the slow path passes the arguments
          // as a `const FunctionCallbackInfo<Value>&` (which is a GP argument),
          // the call is made correctly.
          DCHECK(redirection->type() == ExternalReference::BUILTIN_CALL ||
                 redirection->type() == ExternalReference::FAST_C_CALL);
          SimulatorRuntimeCall target =
              reinterpret_cast<SimulatorRuntimeCall>(external);
          intptr_t result =
              target(arg[0], arg[1], arg[2], arg[3], arg[4], arg[5], arg[6],
                     arg[7], arg[8], arg[9], arg[10], arg[11], arg[12], arg[13],
                     arg[14], arg[15], arg[16], arg[17], arg[18], arg[19]);
          if (v8_flags.trace_sim) {
            PrintF("Returned %08" V8PRIxPTR "\n", result);
          }
          set_register(r2, result);
        }
        //         if (redirection->type() == ExternalReference::BUILTIN_CALL) {
        //           SimulatorRuntimeCall target =
        //             reinterpret_cast<SimulatorRuntimeCall>(external);
        //           intptr_t result = target(arg[0], arg[1], arg[2], arg[3],
        //           arg[4],
        //               arg[5]);
        //           if (v8_flags.trace_sim) {
        //             PrintF("Returned %08" V8PRIxPTR "\n", result);
        //           }
        //           set_register(r2, result);
        //         } else {
        //           DCHECK(redirection->type() ==
        //               ExternalReference::BUILTIN_CALL_PAIR);
        //           SimulatorRuntimePairCall target =
        //             reinterpret_cast<SimulatorRuntimePairCall>(external);
        //           ObjectPair result = target(arg[0], arg[1], arg[2], arg[3],
        //               arg[4], arg[5]);
        //           if (v8_flags.trace_sim) {
        //             PrintF("Returned %08" V8PRIxPTR ", %08" V8PRIxPTR "\n",
        //                 result.x, result.y);
        //           }
        // #if ABI_RETURNS_OBJECTPAIR_IN_REGS
        //           set_register(r2, result.x);
        //           set_register(r3, result.y);
        // #else
        //            memcpy(reinterpret_cast<void *>(result_buffer), &result,
        //                sizeof(ObjectPair));
        // #endif
        //         }
      }
      int64_t saved_lr = *reinterpret_cast<intptr_t*>(
          get_register(sp) + kStackFrameRASlot * kSystemPointerSize);
      set_pc(saved_lr);
      break;
    }
    case kBreakpoint:
      S390Debugger(this).Debug();
      break;
    // stop uses all codes greater than 1 << 23.
    default:
      if (svc >= (1 << 23)) {
        uint32_t code = svc & kStopCodeMask;
        if (isWatchedStop(code)) {
          IncreaseStopCounter(code);
        }
        // Stop if it is enabled, otherwise go on jumping over the stop
        // and the message address.
        if (isEnabledStop(code)) {
          if (code != kMaxStopCode) {
            PrintF("Simulator hit stop %u. ", code);
          } else {
            PrintF("Simulator hit stop. ");
          }
          DebugAtNextPC();
        } else {
          set_pc(get_pc() + sizeof(FourByteInstr) + kSystemPointerSize);
        }
      } else {
        // This is not a valid svc code.
        UNREACHABLE();
      }
  }
}

// Stop helper functions.
bool Simulator::isStopInstruction(Instruction* instr) {
  return (instr->Bits(27, 24) == 0xF) && (instr->SvcValue() >= kStopCode);
}

bool Simulator::isWatchedStop(uint32_t code) {
  DCHECK_LE(code, kMaxStopCode);
  return code < kNumOfWatchedStops;
}

bool Simulator::isEnabledStop(uint32_t code) {
  DCHECK_LE(code, kMaxStopCode);
  // Unwatched stops are always enabled.
  return !isWatchedStop(code) ||
         !(watched_stops_[code].count & kStopDisabledBit);
}

void Simulator::EnableStop(uint32_t code) {
  DCHECK(isWatchedStop(code));
  if (!isEnabledStop(code)) {
    watched_stops_[code].count &= ~kStopDisabledBit;
  }
}

void Simulator::DisableStop(uint32_t code) {
  DCHECK(isWatchedStop(code));
  if (isEnabledStop(code)) {
    watched_stops_[code].count |= kStopDisabledBit;
  }
}

void Simulator::IncreaseStopCounter(uint32_t code) {
  DCHECK_LE(code, kMaxStopCode);
  DCHECK(isWatchedStop(code));
  if ((watched_stops_[code].count & ~(1 << 31)) == 0x7FFFFFFF) {
    PrintF(
        "Stop counter for code %i has overflowed.\n"
        "Enabling this code and reseting the counter to 0.\n",
        code);
    watched_stops_[code].count = 0;
    EnableStop(code);
  } else {
    watched_stops_[code].count++;
  }
}

// Print a stop status.
void Simulator::PrintStopInfo(uint32_t code) {
  DCHECK_LE(code, kMaxStopCode);
  if (!isWatchedStop(code)) {
    PrintF("Stop not watched.");
  } else {
    const char* state = isEnabledStop(code) ? "Enabled" : "Disabled";
    int32_t count = watched_stops_[code].count & ~kStopDisabledBit;
    // Don
"""


```