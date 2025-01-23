Response: The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of a five-part series, so I should focus on the code within this specific section. The code primarily consists of a large table initialization `EvalTable` which maps opcodes to `Simulator::Evaluate_...` methods. This strongly suggests that this part of the code is responsible for defining the execution logic of different S390 instructions within the simulator.

To illustrate the connection to JavaScript, I need to think about how a JavaScript engine utilizes such a simulator. The V8 engine, where this code originates, compiles JavaScript into machine code. When running on an architecture that isn't natively supported (like running on an x86 machine while simulating S390), the simulator steps in to execute the generated S390 machine code instruction by instruction.

Therefore, the functionality is about implementing the behavior of S390 instructions within the simulator.

For the JavaScript example, I need a simple JavaScript operation and how it might be represented in simulated S390 instructions. A basic arithmetic operation like adding two numbers in JavaScript would eventually translate into an S390 addition instruction.
这是目录为v8/src/execution/s390/simulator-s390.cc 的 C++ 源代码文件的第 2 部分。

根据提供的代码片段，这部分代码的主要功能是**初始化一个指令评估表 `EvalTable`，该表将 S390 架构的各种指令操作码映射到 `Simulator` 类的相应评估函数。**

换句话说，这段代码定义了模拟器如何解释和执行不同的 S390 指令。  每个 `EvalTable[指令操作码] = &Simulator::Evaluate_指令名称;`  这样的语句，都表示当模拟器遇到特定的 `指令操作码` 时，会调用 `Simulator` 类的 `Evaluate_指令名称` 函数来模拟该指令的行为。

**与 JavaScript 的关系以及 JavaScript 示例：**

V8 JavaScript 引擎在某些情况下会使用模拟器。 例如，当 JavaScript 代码需要在与底层硬件架构不同的架构上运行时（例如，在 x86 机器上模拟运行为 S390 架构编译的代码），就需要使用模拟器。

当 V8 引擎需要执行一段为 S390 架构编译的 JavaScript 代码时，它会逐条取出 S390 指令，并根据 `EvalTable` 中的映射，调用相应的 `Simulator::Evaluate_...` 函数来模拟该指令的执行。

**JavaScript 示例：**

假设我们有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
```

在 V8 引擎中，`add(5, 3)` 这个加法操作会被编译成一系列 S390 汇编指令。 其中可能包含一个加法指令，例如 `AGR` (Add Logical Register, 假设存在这样一个指令)。

当 V8 模拟器执行到这个 `AGR` 指令时，它会查找 `EvalTable[AGR]`，找到对应的 `Simulator::Evaluate_AGR` 函数，并调用该函数。  `Simulator::Evaluate_AGR` 函数会模拟 S390 架构下 `AGR` 指令的行为，例如从寄存器中取出操作数，执行加法运算，并将结果存回寄存器。

虽然代码中没有直接名为 `AGR` 的指令，但例如 `LAAG` (Load Address Absolute Long) 可以看作一种加载并进行简单加法操作的指令。  当 JavaScript 执行类似 `let x = a + 100;` 的操作时，如果 `a` 已经在寄存器中，编译器可能会生成 `LAAG` 指令，模拟器会调用 `Simulator::Evaluate_LAAG` 来执行这个模拟的加载和加法操作。

总而言之，这段 C++ 代码是 V8 引擎中 S390 模拟器的核心组成部分，它定义了模拟器如何理解和执行 S390 指令，从而使得 V8 能够在非 S390 架构上运行为 S390 编译的 JavaScript 代码。

### 提示词
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```
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
    // Don't print the state of unused breakpoints.
    if (count != 0) {
      if (watched_stops_[code].desc) {
        PrintF("stop %i - 0x%x: \t%s, \tcounter = %i, \t%s\n", code, code,
               state, count, watched_stops_[code].desc);
      } else {
        PrintF("stop %i - 0x%x: \t%s, \tcounter = %i\n", code, code, state,
               count);
      }
    }
  }
}

// Method for checking overflow on signed addition:
//   Test src1 and src2 have opposite sign,
//   (1) No overflow if they have opposite sign
//   (2) Test the result and one of the operands have opposite sign
//      (a) No overflow if they don't have opposite sign
//      (b) Overflow if opposite
#define CheckOverflowForIntAdd(src1, src2, type) \
  OverflowFromSigned<type>(src1 + src2, src1, src2, true);

#define CheckOverflowForIntSub(src1, src2, type) \
  OverflowFromSigned<type>(src1 - src2, src1, src2, false);

// Method for checking overflow on unsigned addition
#define CheckOverflowForUIntAdd(src1, src2) \
  ((src1) + (src2) < (src1) || (src1) + (src2) < (src2))

// Method for checking overflow on unsigned subtraction
#define CheckOverflowForUIntSub(src1, src2) ((src1) - (src2) > (src1))

// Method for checking overflow on multiplication
#define CheckOverflowForMul(src1, src2) (((src1) * (src2)) / (src2) != (src1))

// Method for checking overflow on shift right
#define CheckOverflowForShiftRight(src1, src2) \
  (((src1) >> (src2)) << (src2) != (src1))

// Method for checking overflow on shift left
#define CheckOverflowForShiftLeft(src1, src2) \
  (((src1) << (src2)) >> (src2) != (src1))

int Simulator::DecodeInstruction(Instruction* instr) {
  Opcode op = instr->S390OpcodeValue();
  DCHECK_NOT_NULL(EvalTable[op]);
  return (this->*EvalTable[op])(instr);
}

// Executes the current instruction.
void Simulator::ExecuteInstruction(Instruction* instr, bool auto_incr_pc) {
  icount_++;

  if (v8_flags.check_icache) {
    CheckICache(i_cache(), instr);
  }

  pc_modified_ = false;

  if (v8_flags.trace_sim) {
    disasm::NameConverter converter;
    disasm::Disassembler dasm(converter);
    // use a reasonably large buffer
    v8::base::EmbeddedVector<char, 256> buffer;
    dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(instr));
    PrintF("%05" PRId64 "  %08" V8PRIxPTR "  %s\n", icount_,
           reinterpret_cast<intptr_t>(instr), buffer.begin());

    // Flush stdout to prevent incomplete file output during abnormal exits
    // This is caused by the output being buffered before being written to file
    fflush(stdout);
  }

  // Try to simulate as S390 Instruction first.
  int length = DecodeInstruction(instr);

  if (!pc_modified_ && auto_incr_pc) {
    DCHECK(length == instr->InstructionLength());
    set_pc(reinterpret_cast<intptr_t>(instr) + length);
  }
  return;
}

void Simulator::DebugStart() {
  S390Debugger dbg(this);
  dbg.Debug();
}

void Simulator::Execute() {
  // Get the PC to simulate. Cannot use the accessor here as we need the
  // raw PC value and not the one used as input to arithmetic instructions.
  intptr_t program_counter = get_pc();

  if (v8_flags.stop_sim_at == 0) {
    // Fast version of the dispatch loop without checking whether the simulator
    // should be stopping at a particular executed instruction.
    while (program_counter != end_sim_pc) {
      Instruction* instr = reinterpret_cast<Instruction*>(program_counter);
      ExecuteInstruction(instr);
      program_counter = get_pc();
    }
  } else {
    // v8_flags.stop_sim_at is at the non-default value. Stop in the debugger
    // when we reach the particular instruction count.
    while (program_counter != end_sim_pc) {
      Instruction* instr = reinterpret_cast<Instruction*>(program_counter);
      if (icount_ == v8_flags.stop_sim_at) {
        S390Debugger dbg(this);
        dbg.Debug();
      } else {
        ExecuteInstruction(instr);
      }
      program_counter = get_pc();
    }
  }
}

void Simulator::CallInternal(Address entry, int reg_arg_count) {
  // Adjust JS-based stack limit to C-based stack limit.
  isolate_->stack_guard()->AdjustStackLimitForSimulator();

  // Prepare to execute the code at entry
  if (ABI_USES_FUNCTION_DESCRIPTORS) {
    // entry is the function descriptor
    set_pc(*(reinterpret_cast<intptr_t*>(entry)));
  } else {
    // entry is the instruction address
    set_pc(static_cast<intptr_t>(entry));
  }
  // Remember the values of non-volatile registers.
  int64_t r6_val = get_register(r6);
  int64_t r7_val = get_register(r7);
  int64_t r8_val = get_register(r8);
  int64_t r9_val = get_register(r9);
  int64_t r10_val = get_register(r10);
  int64_t r11_val = get_register(r11);
  int64_t r12_val = get_register(r12);
  int64_t r13_val = get_register(r13);

  if (ABI_CALL_VIA_IP) {
    // Put target address in ip (for JS prologue).
    set_register(ip, get_pc());
  }

  // Put down marker for end of simulation. The simulator will stop simulation
  // when the PC reaches this value. By saving the "end simulation" value into
  // the LR the simulation stops when returning to this call point.
  registers_[14] = end_sim_pc;

  // Set up the non-volatile registers with a known value. To be able to check
  // that they are preserved properly across JS execution.
  uintptr_t callee_saved_value = icount_;
  if (reg_arg_count < 5) {
    set_register(r6, callee_saved_value + 6);
  }
  set_register(r7, callee_saved_value + 7);
  set_register(r8, callee_saved_value + 8);
  set_register(r9, callee_saved_value + 9);
  set_register(r10, callee_saved_value + 10);
  set_register(r11, callee_saved_value + 11);
  set_register(r12, callee_saved_value + 12);
  set_register(r13, callee_saved_value + 13);

  // Start the simulation
  Execute();

// Check that the non-volatile registers have been preserved.
  if (reg_arg_count < 5) {
    DCHECK_EQ(callee_saved_value + 6, get_register(r6));
  }
  DCHECK_EQ(callee_saved_value + 7, get_register(r7));
  DCHECK_EQ(callee_saved_value + 8, get_register(r8));
  DCHECK_EQ(callee_saved_value + 9, get_register(r9));
  DCHECK_EQ(callee_saved_value + 10, get_register(r10));
  DCHECK_EQ(callee_saved_value + 11, get_register(r11));
  DCHECK_EQ(callee_saved_value + 12, get_register(r12));
  DCHECK_EQ(callee_saved_value + 13, get_register(r13));

  // Restore non-volatile registers with the original value.
  set_register(r6, r6_val);
  set_register(r7, r7_val);
  set_register(r8, r8_val);
  set_register(r9, r9_val);
  set_register(r10, r10_val);
  set_register(r11, r11_val);
  set_register(r12, r12_val);
  set_register(r13, r13_val);
}

intptr_t Simulator::CallImpl(Address entry, int argument_count,
                             const intptr_t* arguments) {
  // Adjust JS-based stack limit to C-based stack limit.
  isolate_->stack_guard()->AdjustStackLimitForSimulator();

  // Remember the values of non-volatile registers.
  int64_t r6_val = get_register(r6);
  int64_t r7_val = get_register(r7);
  int64_t r8_val = get_register(r8);
  int64_t r9_val = get_register(r9);
  int64_t r10_val = get_register(r10);
  int64_t r11_val = get_register(r11);
  int64_t r12_val = get_register(r12);
  int64_t r13_val = get_register(r13);

  // Set up arguments

  // First 5 arguments passed in registers r2-r6.
  int reg_arg_count = std::min(5, argument_count);
  int stack_arg_count = argument_count - reg_arg_count;
  for (int i = 0; i < reg_arg_count; i++) {
    set_register(i + 2, arguments[i]);
  }

  // Remaining arguments passed on stack.
  int64_t original_stack = get_register(sp);
  // Compute position of stack on entry to generated code.
  uintptr_t entry_stack =
      (original_stack -
       (kCalleeRegisterSaveAreaSize + stack_arg_count * sizeof(intptr_t)));
  if (base::OS::ActivationFrameAlignment() != 0) {
    entry_stack &= -base::OS::ActivationFrameAlignment();
  }

  // Store remaining arguments on stack, from low to high memory.
  intptr_t* stack_argument =
      reinterpret_cast<intptr_t*>(entry_stack + kCalleeRegisterSaveAreaSize);
  memcpy(stack_argument, arguments + reg_arg_count,
         stack_arg_count * sizeof(*arguments));
  set_register(sp, entry_stack);

// Prepare to execute the code at entry
#if ABI_USES_FUNCTION_DESCRIPTORS
  // entry is the function descriptor
  set_pc(*(reinterpret_cast<intptr_t*>(entry)));
#else
  // entry is the instruction address
  set_pc(static_cast<intptr_t>(entry));
#endif

  // Put target address in ip (for JS prologue).
  set_register(r12, get_pc());

  // Put down marker for end of simulation. The simulator will stop simulation
  // when the PC reaches this value. By saving the "end simulation" value into
  // the LR the simulation stops when returning to this call point.
  registers_[14] = end_sim_pc;

  // Set up the non-volatile registers with a known value. To be able to check
  // that they are preserved properly across JS execution.
  uintptr_t callee_saved_value = icount_;
  if (reg_arg_count < 5) {
    set_register(r6, callee_saved_value + 6);
  }
  set_register(r7, callee_saved_value + 7);
  set_register(r8, callee_saved_value + 8);
  set_register(r9, callee_saved_value + 9);
  set_register(r10, callee_saved_value + 10);
  set_register(r11, callee_saved_value + 11);
  set_register(r12, callee_saved_value + 12);
  set_register(r13, callee_saved_value + 13);

  // Start the simulation
  Execute();

// Check that the non-volatile registers have been preserved.
  if (reg_arg_count < 5) {
    DCHECK_EQ(callee_saved_value + 6, get_register(r6));
  }
  DCHECK_EQ(callee_saved_value + 7, get_register(r7));
  DCHECK_EQ(callee_saved_value + 8, get_register(r8));
  DCHECK_EQ(callee_saved_value + 9, get_register(r9));
  DCHECK_EQ(callee_saved_value + 10, get_register(r10));
  DCHECK_EQ(callee_saved_value + 11, get_register(r11));
  DCHECK_EQ(callee_saved_value + 12, get_register(r12));
  DCHECK_EQ(callee_saved_value + 13, get_register(r13));

  // Restore non-volatile registers with the original value.
  set_register(r6, r6_val);
  set_register(r7, r7_val);
  set_register(r8, r8_val);
  set_register(r9, r9_val);
  set_register(r10, r10_val);
  set_register(r11, r11_val);
  set_register(r12, r12_val);
  set_register(r13, r13_val);
  // Pop stack passed arguments.

  DCHECK_EQ(entry_stack, get_register(sp));
  set_register(sp, original_stack);

  // Return value register
  return get_register(r2);
}

void Simulator::CallFP(Address entry, double d0, double d1) {
  set_fpr(0, d0);
  set_fpr(1, d1);
  CallInternal(entry);
}

int32_t Simulator::CallFPReturnsInt(Address entry, double d0, double d1) {
  CallFP(entry, d0, d1);
  int32_t result = get_register(r2);
  return result;
}

double Simulator::CallFPReturnsDouble(Address entry, double d0, double d1) {
  CallFP(entry, d0, d1);
  return get_fpr<double>(0);
}

uintptr_t Simulator::PushAddress(uintptr_t address) {
  uintptr_t new_sp = get_register(sp) - sizeof(uintptr_t);
  uintptr_t* stack_slot = reinterpret_cast<uintptr_t*>(new_sp);
  *stack_slot = address;
  set_register(sp, new_sp);
  return new_sp;
}

uintptr_t Simulator::PopAddress() {
  uintptr_t current_sp = get_register(sp);
  uintptr_t* stack_slot = reinterpret_cast<uintptr_t*>(current_sp);
  uintptr_t address = *stack_slot;
  set_register(sp, current_sp + sizeof(uintptr_t));
  return address;
}

#define EVALUATE(name) int Simulator::Evaluate_##name(Instruction* instr)

#define DCHECK_OPCODE(op) DCHECK(instr->S390OpcodeValue() == op)

#define AS(type) reinterpret_cast<type*>(instr)

#define DECODE_RIL_A_INSTRUCTION(r1, i2)               \
  int r1 = AS(RILInstruction)->R1Value();              \
  uint32_t i2 = AS(RILInstruction)->I2UnsignedValue(); \
  int length = 6;

#define DECODE_RIL_B_INSTRUCTION(r1, i2)      \
  int r1 = AS(RILInstruction)->R1Value();     \
  int32_t i2 = AS(RILInstruction)->I2Value(); \
  int length = 6;

#define DECODE_RIL_C_INSTRUCTION(m1, ri2)                               \
  Condition m1 = static_cast<Condition>(AS(RILInstruction)->R1Value()); \
  uint64_t ri2 = AS(RILInstruction)->I2Value();                         \
  int length = 6;

#define DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2) \
  int r1 = AS(RXYInstruction)->R1Value();        \
  int x2 = AS(RXYInstruction)->X2Value();        \
  int b2 = AS(RXYInstruction)->B2Value();        \
  int d2 = AS(RXYInstruction)->D2Value();        \
  int length = 6;

#define DECODE_RX_A_INSTRUCTION(x2, b2, r1, d2_val) \
  int x2 = AS(RXInstruction)->X2Value();            \
  int b2 = AS(RXInstruction)->B2Value();            \
  int r1 = AS(RXInstruction)->R1Value();            \
  intptr_t d2_val = AS(RXInstruction)->D2Value();   \
  int length = 4;

#define DECODE_RS_A_INSTRUCTION(r1, r3, b2, d2) \
  int r3 = AS(RSInstruction)->R3Value();        \
  int b2 = AS(RSInstruction)->B2Value();        \
  int r1 = AS(RSInstruction)->R1Value();        \
  intptr_t d2 = AS(RSInstruction)->D2Value();   \
  int length = 4;

#define DECODE_RS_A_INSTRUCTION_NO_R3(r1, b2, d2) \
  int b2 = AS(RSInstruction)->B2Value();          \
  int r1 = AS(RSInstruction)->R1Value();          \
  int d2 = AS(RSInstruction)->D2Value();          \
  int length = 4;

#define DECODE_RSI_INSTRUCTION(r1, r3, i2)    \
  int r1 = AS(RSIInstruction)->R1Value();     \
  int r3 = AS(RSIInstruction)->R3Value();     \
  int32_t i2 = AS(RSIInstruction)->I2Value(); \
  int length = 4;

#define DECODE_SI_INSTRUCTION_I_UINT8(b1, d1_val, imm_val) \
  int b1 = AS(SIInstruction)->B1Value();                   \
  intptr_t d1_val = AS(SIInstruction)->D1Value();          \
  uint8_t imm_val = AS(SIInstruction)->I2Value();          \
  int length = 4;

#define DECODE_SIL_INSTRUCTION(b1, d1, i2)     \
  int b1 = AS(SILInstruction)->B1Value();      \
  intptr_t d1 = AS(SILInstruction)->D1Value(); \
  int16_t i2 = AS(SILInstruction)->I2Value();  \
  int length = 6;

#define DECODE_SIY_INSTRUCTION(b1, d1, i2)     \
  int b1 = AS(SIYInstruction)->B1Value();      \
  intptr_t d1 = AS(SIYInstruction)->D1Value(); \
  uint8_t i2 = AS(SIYInstruction)->I2Value();  \
  int length = 6;

#define DECODE_RRE_INSTRUCTION(r1, r2)    \
  int r1 = AS(RREInstruction)->R1Value(); \
  int r2 = AS(RREInstruction)->R2Value(); \
  int length = 4;

#define DECODE_RRE_INSTRUCTION_M3(r1, r2, m3) \
  int r1 = AS(RREInstruction)->R1Value();     \
  int r2 = AS(RREInstruction)->R2Value();     \
  int m3 = AS(RREInstruction)->M3Value();     \
  int length = 4;

#define DECODE_RRE_INSTRUCTION_NO_R2(r1)  \
  int r1 = AS(RREInstruction)->R1Value(); \
  int length = 4;

#define DECODE_RRD_INSTRUCTION(r1, r2, r3) \
  int r1 = AS(RRDInstruction)->R1Value();  \
  int r2 = AS(RRDInstruction)->R2Value();  \
  int r3 = AS(RRDInstruction)->R3Value();  \
  int length = 4;

#define DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4) \
  int r1 = AS(RRFInstruction)->R1Value();        \
  int r2 = AS(RRFInstruction)->R2Value();        \
  int m3 = AS(RRFInstruction)->M3Value();        \
  int m4 = AS(RRFInstruction)->M4Value();        \
  int length = 4;

#define DECODE_RRF_A_INSTRUCTION(r1, r2, r3) \
  int r1 = AS(RRFInstruction)->R1Value();    \
  int r2 = AS(RRFInstruction)->R2Value();    \
  int r3 = AS(RRFInstruction)->R3Value();    \
  int length = 4;

#define DECODE_RRF_C_INSTRUCTION(r1, r2, m3)                            \
  int r1 = AS(RRFInstruction)->R1Value();                               \
  int r2 = AS(RRFInstruction)->R2Value();                               \
  Condition m3 = static_cast<Condition>(AS(RRFInstruction)->M3Value()); \
  int length = 4;

#define DECODE_RR_INSTRUCTION(r1, r2)    \
  int r1 = AS(RRInstruction)->R1Value(); \
  int r2 = AS(RRInstruction)->R2Value(); \
  int length = 2;

#define DECODE_RIE_D_INSTRUCTION(r1, r2, i2)  \
  int r1 = AS(RIEInstruction)->R1Value();     \
  int r2 = AS(RIEInstruction)->R2Value();     \
  int32_t i2 = AS(RIEInstruction)->I6Value(); \
  int length = 6;

#define DECODE_RIE_E_INSTRUCTION(r1, r2, i2)  \
  int r1 = AS(RIEInstruction)->R1Value();     \
  int r2 = AS(RIEInstruction)->R2Value();     \
  int32_t i2 = AS(RIEInstruction)->I6Value(); \
  int length = 6;

#define DECODE_RIE_F_INSTRUCTION(r1, r2, i3, i4, i5) \
  int r1 = AS(RIEInstruction)->R1Value();            \
  int r2 = AS(RIEInstruction)->R2Value();            \
  uint32_t i3 = AS(RIEInstruction)->I3Value();       \
  uint32_t i4 = AS(RIEInstruction)->I4Value();       \
  uint32_t i5 = AS(RIEInstruction)->I5Value();       \
  int length = 6;

#define DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2) \
  int r1 = AS(RSYInstruction)->R1Value();        \
  int r3 = AS(RSYInstruction)->R3Value();        \
  int b2 = AS(RSYInstruction)->B2Value();        \
  intptr_t d2 = AS(RSYInstruction)->D2Value();   \
  int length = 6;

#define DECODE_RI_A_INSTRUCTION(instr, r1, i2) \
  int32_t r1 = AS(RIInstruction)->R1Value();   \
  int16_t i2 = AS(RIInstruction)->I2Value();   \
  int length = 4;

#define DECODE_RI_B_INSTRUCTION(instr, r1, i2) \
  int32_t r1 = AS(RILInstruction)->R1Value();  \
  int16_t i2 = AS(RILInstruction)->I2Value();  \
  int length = 4;

#define DECODE_RI_C_INSTRUCTION(instr, m1, i2)                         \
  Condition m1 = static_cast<Condition>(AS(RIInstruction)->R1Value()); \
  int16_t i2 = AS(RIInstruction)->I2Value();                           \
  int length = 4;

#define DECODE_RXE_INSTRUCTION(r1, b2, x2, d2) \
  int r1 = AS(RXEInstruction)->R1Value();      \
  int b2 = AS(RXEInstruction)->B2Value();      \
  int x2 = AS(RXEInstruction)->X2Value();      \
  int d2 = AS(RXEInstruction)->D2Value();      \
  int length = 6;

#define DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3) \
  int r1 = AS(VRR_A_Instruction)->R1Value();         \
  int r2 = AS(VRR_A_Instruction)->R2Value();         \
  int m5 = AS(VRR_A_Instruction)->M5Value();         \
  int m4 = AS(VRR_A_Instruction)->M4Value();         \
  int m3 = AS(VRR_A_Instruction)->M3Value();         \
  int length = 6;

#define DECODE_VRR_B_INSTRUCTION(r1, r2, r3, m5, m4) \
  int r1 = AS(VRR_B_Instruction)->R1Value();         \
  int r2 = AS(VRR_B_Instruction)->R2Value();         \
  int r3 = AS(VRR_B_Instruction)->R3Value();         \
  int m5 = AS(VRR_B_Instruction)->M5Value();         \
  int m4 = AS(VRR_B_Instruction)->M4Value();         \
  int length = 6;

#define DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4) \
  int r1 = AS(VRR_C_Instruction)->R1Value();             \
  int r2 = AS(VRR_C_Instruction)->R2Value();             \
  int r3 = AS(VRR_C_Instruction)->R3Value();             \
  int m6 = AS(VRR_C_Instruction)->M6Value();             \
  int m5 = AS(VRR_C_Instruction)->M5Value();             \
  int m4 = AS(VRR_C_Instruction)->M4Value();             \
  int length = 6;

#define DECODE_VRR_E_INSTRUCTION(r1, r2, r3, r4, m6, m5) \
  int r1 = AS(VRR_E_Instruction)->R1Value();             \
  int r2 = AS(VRR_E_Instruction)->R2Value();             \
  int r3 = AS(VRR_E_Instruction)->R3Value();             \
  int r4 = AS(VRR_E_Instruction)->R4Value();             \
  int m6 = AS(VRR_E_Instruction)->M6Value();             \
  int m5 = AS(VRR_E_Instruction)->M5Value();             \
  int length = 6;

#define DECODE_VRR_F_INSTRUCTION(r1, r2, r3) \
  int r1 = AS(VRR_F_Instruction)->R1Value(); \
  int r2 = AS(VRR_F_Instruction)->R2Value(); \
  int r3 = AS(VRR_F_Instruction)->R3Value(); \
  int length = 6;

#define DECODE_VRX_INSTRUCTION(r1, x2, b2, d2, m3) \
  int r1 = AS(VRX_Instruction)->R1Value();         \
  int x2 = AS(VRX_Instruction)->X2Value();         \
  int b2 = AS(VRX_Instruction)->B2Value();         \
  int d2 = AS(VRX_Instruction)->D2Value();         \
  int m3 = AS(VRX_Instruction)->M3Value();         \
  int length = 6;

#define DECODE_VRS_INSTRUCTION(r1, r3, b2, d2, m4) \
  int r1 = AS(VRS_Instruction)->R1Value();         \
  int r3 = AS(VRS_Instruction)->R3Value();         \
  int b2 = AS(VRS_Instruction)->B2Value();         \
  int d2 = AS(VRS_Instruction)->D2Value();         \
  int m4 = AS(VRS_Instruction)->M4Value();         \
  int length = 6;

#define DECODE_VRI_A_INSTRUCTION(r1, i2, m3)     \
  int r1 = AS(VRI_A_Instruction)->R1Value();     \
  int16_t i2 = AS(VRI_A_Instruction)->I2Value(); \
  int m3 = AS(VRI_A_Instruction)->M3Value();     \
  int length = 6;

#define DECODE_VRI_C_INSTRUCTION(r1, r3, i2, m4)  \
  int r1 = AS(VRI_C_Instruction)->R1Value();      \
  int r3 = AS(VRI_C_Instruction)->R3Value();      \
  uint16_t i2 = AS(VRI_C_Instruction)->I2Value(); \
  int m4 = AS(VRI_C_Instruction)->M4Value();      \
  int length = 6;

#define GET_ADDRESS(index_reg, base_reg, offset)       \
  (((index_reg) == 0) ? 0 : get_register(index_reg)) + \
      (((base_reg) == 0) ? 0 : get_register(base_reg)) + offset

int Simulator::Evaluate_Unknown(Instruction* instr) { UNREACHABLE(); }

EVALUATE(VST) {
  DCHECK_OPCODE(VST);
  DECODE_VRX_INSTRUCTION(r1, x2, b2, d2, m3);
  USE(m3);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  fpr_t* ptr = reinterpret_cast<fpr_t*>(addr);
  *ptr = get_simd_register(r1);
  return length;
}

EVALUATE(VL) {
  DCHECK_OPCODE(VL);
  DECODE_VRX_INSTRUCTION(r1, x2, b2, d2, m3);
  USE(m3);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  fpr_t* ptr = reinterpret_cast<fpr_t*>(addr);
  DCHECK(m3 != 3 || (0x7 & addr) == 0);
  DCHECK(m3 != 4 || (0xf & addr) == 0);
  set_simd_register(r1, *ptr);
  return length;
}

#define VECTOR_LOAD_POSITIVE(r1, r2, type)                              \
  for (size_t i = 0, j = 0; j < kSimd128Size; i++, j += sizeof(type)) { \
    set_simd_register_by_lane<type>(                                    \
        r1, i, abs(get_simd_register_by_lane<type>(r2, i)));            \
  }
EVALUATE(VLP) {
  DCHECK_OPCODE(VLP);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  USE(m5);
  USE(m4);
  switch (m3) {
    case 0: {
      VECTOR_LOAD_POSITIVE(r1, r2, int8_t)
      break;
    }
    case 1: {
      VECTOR_LOAD_POSITIVE(r1, r2, int16_t)
      break;
    }
    case 2: {
      VECTOR_LOAD_POSITIVE(r1, r2, int32_t)
      break;
    }
    case 3: {
      VECTOR_LOAD_POSITIVE(r1, r2, int64_t)
      break;
    }
    default:
      UNREACHABLE();
  }

  return length;
}
#undef VECTOR_LOAD_POSITIVE

#define VECTOR_AVERAGE_U(r1, r2, r3, type)                                    \
  for (size_t i = 0, j = 0; j < kSimd128Size; i++, j += sizeof(type)) {       \
    type src0 = get_simd_register_by_lane<type>(r2, i);                       \
    type src1 = get_simd_register_by_lane<type>(r3, i);                       \
    set_simd_register_by_lane<type>(                                          \
        r1, i, (static_cast<type>(src0) + static_cast<type>(src1) + 1) >> 1); \
  }
EVALUATE(VAVGL) {
  DCHECK_OPCODE(VAVGL);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m6);
  USE(m5);
  switch (m4) {
    case 0: {
      VECTOR_AVERAGE_U(r1, r2, r3, uint8_t)
      break;
    }
    case 1: {
      VECTOR_AVERAGE_U(r1, r2, r3, uint16_t)
      break;
    }
    case 2: {
      VECTOR_AVERAGE_U(r1, r2, r3, uint32_t)
      break;
    }
    case 3: {
      VECTOR_AVERAGE_U(r1, r2, r3, uint64_t)
      break;
    }
    default:
      UNREACHABLE();
  }

  return length;
}
#undef VECTOR_AVERAGE_U

EVALUATE(VLGV) {
  DCHECK_OPCODE(VLGV);
  DECODE_VRS_INSTRUCTION(r1, r3, b2, d2, m4);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t index = b2_val + d2;
#define CASE(i, type)                                             \
  case i:                                                         \
    set_register(r1, get_simd_register_by_lane<type>(r3, index)); \
    break;
  switch (m4) {
    CASE(0, uint8_t);
    CASE(1, uint16_t);
    CASE(2, uint32_t);
    CASE(3, uint64_t);
    default:
      UNREACHABLE();
  }
#undef CASE
  return length;
}

EVALUATE(VLVG) {
  DCHECK_OPCODE(VLVG);
  DECODE_VRS_INSTRUCTION(r1, r3, b2, d2, m4);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t index = b2_val + d2;
#define CASE(i, type)                                                     \
  case i:                                                                 \
    set_simd_register_by_lane<type>(r1, index,                            \
                                    static_cast<type>(get_register(r3))); \
    break;
  switch (m4) {
    CASE(0, uint8_t);
    CASE(1, uint16_t);
    CASE(2, uint32_t);
    CASE(3, uint64_t);
    default:
      UNREACHABLE();
  }
#undef CASE
  return length;
}

EVALUATE(VLVGP) {
  DCHECK_OPCODE(VLVGP);
  DECODE_VRR_F_INSTRUCTION(r1, r2, r3);
  set_simd_register_by_lane<int64_t>(r1, 0, get_register(r2));
  set_simd_register_by_lane<int64_t>(r1, 1, get_register(r3));
  return length;
}

#define FOR_EACH_LANE(i, type) \
  for (uint32_t i = 0; i < kSimd128Size / sizeof(type); i++)

EVALUATE(VREP) {
  DCHECK_OPCODE(VREP);
  DECODE_VRI_C_INSTRUCTION(r1, r3, i2, m4);
#define CASE(i, type)                                      \
  case i: {                                                \
    FOR_EACH_LANE(j, type) {                               \
      set_simd_register_by_lane<type>(                     \
          r1, j, get_simd_register_by_lane<type>(r3, i2)); \
    }                                                      \
    break;                                                 \
  }
  switch (m4) {
    CASE(0, uint8_t);
    CASE(1, uint16_t);
    CASE(2, uint32_t);
    CASE(3, uint64_t);
    default:
      UNREACHABLE();
  }
#undef CASE
  return length;
}

EVALUATE(VLREP) {
  DCHECK_OPCODE(VLREP);
  DECODE_VRX_INSTRUCTION(r1, x2, b2, d2, m3);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
#define CASE(i, type)                                                         \
  case i: {                                                                   \
    FOR_EACH_LANE(j, type) {                                                  \
      set_simd_register_by_lane<type>(r1, j, *reinterpret_cast<type*>(addr)); \
    }                                                                         \
    break;                                                                    \
  }
  switch (m3) {
    CASE(0, uint8_t);
    CASE(1, uint16_t);
    CASE(2, uint32_t);
    CASE(3, uint64_t);
    default:
      UNREACHABLE();
  }
#undef CASE
  return length;
}

EVALUATE(VREPI) {
  DCHECK_OPCODE(VREPI);
  DECODE_VRI_A_INSTRUCTION(r1, i2, m3);
#define CASE(i, type)                                                \
  case i: {                                                          \
    FOR_EACH_LANE(j, type) {                                         \
      set_simd_register_by_lane<type>(r1, j, static_cast<type>(i2)); \
    }                                                                \
    break;                                                           \
  }
  switch (m3) {
    CASE(0, int8_t);
    CASE(1, int16_t);
    CASE(2, int32_t);
    CASE(3, int64_t);
    default:
      UNREACHABLE();
  }
#undef CASE
  return length;
}

EVALUATE(VLR) {
  DCHECK_OPCODE(VLR);
  DECODE_VRR_A_INSTRUCTION(r1, r2, m5, m4, m3);
  USE(m5);
  USE(m4);
  USE(m3);
  set_simd_register(r1, get_simd_register(r2));
  return length;
}

EVALUATE(VSTEB) {
  DCHECK_OPCODE(VSTEB);
  DECODE_VRX_INSTRUCTION(r1, x2, b2, d2, m3);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  int8_t value = get_simd_register_by_lane<int8_t>(r1, m3);
  WriteB(addr, value);
  return length;
}

EVALUATE(VSTEH) {
  DCHECK_OPCODE(VSTEH);
  DECODE_VRX_INSTRUCTION(r1, x2, b2, d2, m3);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  int16_t value = get_simd_register_by_lane<int16_t>(r1, m3);
  WriteH(addr, value);
  return length;
}

EVALUATE(VSTEF) {
  DCHECK_OPCODE(VSTEF);
  DECODE_VRX_INSTRUCTION(r1, x2, b2, d2, m3);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  int32_t value = get_simd_register_by_lane<int32_t>(r1, m3);
  WriteW(addr, value);
  return length;
}

EVALUATE(VSTEG) {
  DCHECK_OPCODE(VSTEG);
  DECODE_VRX_INSTRUCTION(r1, x2, b2, d2, m3);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  int64_t value = get_simd_register_by_lane<int64_t>(r1, m3);
  WriteDW(addr, value);
  return length;
}

EVALUATE(VLEB) {
  DCHECK_OPCODE(VLEB);
  DECODE_VRX_INSTRUCTION(r1, x2, b2, d2, m3);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  int8_t value = ReadB(addr);
  set_simd_register_by_lane<int8_t>(r1, m3, value);
  return length;
}

EVALUATE(VLEH) {
  DCHECK_OPCODE(VLEH);
  DECODE_VRX_INSTRUCTION(r1, x2, b2, d2, m3);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  int16_t value = ReadH(addr);
  set_simd_register_by_lane<int16_t>(r1, m3, value);
  return length;
}

EVALUATE(VLEF) {
  DCHECK_OPCODE(VLEF);
  DECODE_VRX_INSTRUCTION(r1, x2, b2, d2, m3);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  int32_t value = ReadW(addr);
  set_simd_register_by_lane<int32_t>(r1, m3, value);
  return length;
}

EVALUATE(VLEG) {
  DCHECK_OPCODE(VLEG);
  DECODE_VRX_INSTRUCTION(r1, x2, b2, d2, m3);
  intptr_t addr = GET_ADDRESS(x2, b2, d2);
  uint64_t value = ReadDW(addr);
  set_simd_register_by_lane<uint64_t>(r1, m3, value);
  return length;
}

// TODO(john): unify most fp binary operations
template <class T, class Operation>
inline static void VectorBinaryOp(Simulator* sim, int dst, int src1, int src2,
                                  Operation op) {
  FOR_EACH_LANE(i, T) {
    T src1_val = sim->get_simd_register_by_lane<T>(src1, i);
    T src2_val = sim->get_simd_register_by_lane<T>(src2, i);
    T dst_val = op(src1_val, src2_val);
    sim->set_simd_register_by_lane<T>(dst, i, dst_val);
  }
}

#define VECTOR_BINARY_OP_FOR_TYPE(type, op) \
  VectorBinaryOp<type>(this, r1, r2, r3, [](type a, type b) { return a op b; });

#define VECTOR_BINARY_OP(op)                 \
  switch (m4) {                              \
    case 0:                                  \
      VECTOR_BINARY_OP_FOR_TYPE(int8_t, op)  \
      break;                                 \
    case 1:                                  \
      VECTOR_BINARY_OP_FOR_TYPE(int16_t, op) \
      break;                                 \
    case 2:                                  \
      VECTOR_BINARY_OP_FOR_TYPE(int32_t, op) \
      break;                                 \
    case 3:                                  \
      VECTOR_BINARY_OP_FOR_TYPE(int64_t, op) \
      break;                                 \
    default:                                 \
      UNREACHABLE();                         \
      break;                                 \
  }

EVALUATE(VA) {
  DCHECK_OPCODE(VA);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m5);
  USE(m6);
  VECTOR_BINARY_OP(+)
  return length;
}

EVALUATE(VS) {
  DCHECK_OPCODE(VS);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m5);
  USE(m6);
  VECTOR_BINARY_OP(-)
  return length;
}

EVALUATE(VML) {
  DCHECK_OPCODE(VML);
  DECODE_VRR_C_INSTRUCTION(r1, r2, r3, m6, m5, m4);
  USE(m5);
  USE(m6);
  VECTOR_BINARY_OP(*)
  return length;
}

#define VECTOR_MULTIPLY_EVEN_ODD_TYPE(r1, r2, r3, input_type, result_type, \
                                      is_odd)                              \
  size_t i = 0, j = 0, k = 0;                                              \
  size_t lane_size = sizeof(input_type);                                   \
  if (is_odd) {                                                            \
    i = 1;                                                                 \
    j = lane_size;                                                         \
  }                                                                        \
  for (; j < kSimd128Size; i += 2, j += lane_size * 2, k++) {              \
    result_type src0 = static_cast<result_type>(                           \
        get_simd_register_by_lane<input_type>(r2, i));                     \
    result_type src1 = static_cast<result_type>(                           \
        get_simd_register_by_lane<input_type>(r3, i));                     \
    set_simd_register_by_lane<result_type>(r1, k, src0 * src1);            \
  }
#define VECTOR_MULTIPLY_EVEN_ODD(r1, r2, r3, is_odd, sign)                    \
  switch (m4) {                                                               \
    case 0: {                                                                 \
      VECTOR_MULTIPLY_EVEN_ODD_TYPE(r1, r2, r3, sign##int8_t, sign##int16_t,  \
                                    is_odd)                                   \
      break;                                                                  \
    }                                                                         \
    case 1: {                                                                 \
      VECTOR_MULTIPLY_EVEN_ODD_TYPE(r1, r2, r3, sign##int16_t, sign##int32_t, \
                                    is_odd)                                   \
      break;                                                                  \
    }                                                                         \
    case 2: {
```