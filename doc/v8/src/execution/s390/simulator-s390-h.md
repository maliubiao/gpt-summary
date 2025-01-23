Response:
Let's break down the thought process for analyzing the provided C++ header file for the S390 simulator in V8.

**1. Initial Skim and Keyword Identification:**

First, I'd quickly skim the code looking for obvious keywords and patterns. This helps get a general sense of the file's purpose. Keywords that jump out are:

* `Simulator`:  Appears in the filename and comments, strongly suggesting the core functionality.
* `S390`: Indicates the target architecture being simulated.
* `execution`: Hints at the simulator's role in running code.
* `USE_SIMULATOR`: Suggests conditional compilation, likely enabling the simulator build.
* `Register`, `FPR`, `GPR`:  Points to the management of simulated processor registers.
* `Execute`, `Call`: Indicates how the simulator runs code.
* `ICache`, `FlushICache`:  Related to instruction caching, important for performance and correctness.
* `ConditionCode`:  Flags used in conditional branching.
* `ReadBU`, `WriteW`, etc.:  Memory access functions.
* `Debug`, `BKPT`:  Debugging features.
* `Evaluate_...`: A large number of functions prefixed this way strongly suggests instruction decoding and execution logic.

**2. Understanding the Core Purpose (From Comments and Class Structure):**

The initial comments clearly state the simulator's purpose: to run and debug S390 code on non-S390 machines. The `Simulator` class is central. The presence of `SimulatorBase` suggests inheritance and a common base class for simulators across different architectures in V8.

**3. Analyzing Key Components:**

* **Conditional Compilation (`#if defined(USE_SIMULATOR)`):** This is a crucial starting point. The entire file's content is only relevant when `USE_SIMULATOR` is defined. This immediately tells me the simulator is an optional component.

* **`CachePage`:**  This nested class is clearly related to instruction caching. The `validity_map_` strongly suggests a mechanism for tracking the validity of cached lines.

* **`ComputeRounding`:** A template function indicating support for different rounding modes, probably for floating-point operations.

* **`Simulator::Register` (enum):** This enumeration defines symbolic names for S390 registers. The aliases like `fp`, `sp`, `ra` are common in assembly programming.

* **Register Accessors (`set_register`, `get_register`, `get_fpr`, `set_fpr`):** These methods provide controlled access to the simulated register state. The template versions likely handle different data types.

* **Execution Control (`Execute`, `Call`, `CallFP`):** These methods define how to start and manage the execution of simulated code. The `Call` variants suggest calling functions with different argument types.

* **Memory Access (`ReadBU`, `WriteW`, etc.):** The naming convention clearly indicates the type and size of memory reads and writes (Byte Unsigned, Word, etc.).

* **Condition Codes (`SetS390ConditionCode`, `TestConditionCode`):** These functions implement the logic for setting and checking the S390 condition code register.

* **Instruction Decoding and Execution (`Evaluate_...` functions, `DecodeInstruction`, `EvalTable`):** This is a massive part of the simulator. The numerous `Evaluate_` functions, along with `EvalTable`, strongly suggest a dispatch mechanism for handling individual S390 instructions. The macros `EVALUATE` and the opcode lists (`S390_VRR_A_OPCODE_LIST`, etc.) confirm this.

* **Debugging Features (`DebugStart`, `BKPT`, `watched_stops_`):** The presence of these elements shows the simulator supports breakpoints and other debugging capabilities.

* **Internal State (`registers_`, `fp_registers_`, `condition_reg_`, `special_reg_pc_`, `stack_`):** These member variables represent the core internal state of the simulated S390 processor.

**4. Inferring Functionality and Relationships:**

By examining the members and methods, I could infer the following:

* The simulator maintains its own memory space (`stack_`).
* It has a program counter (`special_reg_pc_`).
* It simulates both general-purpose and floating-point registers.
* The `ICache` is used to speed up instruction fetching in the simulator.
* The simulator can handle various S390 instructions, judging by the large number of `Evaluate_` functions.
* Error handling is likely done through the `Format` function for unimplemented or unsupported instructions.

**5. Considering the ".tq" Check:**

The prompt specifically asked about the `.tq` extension. Knowing that Torque is a language used for defining V8's built-in functions, I recognized this check as a way to distinguish between manually written C++ and generated Torque code.

**6. Thinking About JavaScript Relevance:**

The simulator's purpose is to *run* the generated S390 code. This generated code is often the result of compiling JavaScript. Therefore, the simulator directly relates to JavaScript execution, even though the header file itself is C++.

**7. Constructing Examples and Identifying Potential Errors:**

To illustrate the JavaScript connection and common errors, I considered scenarios where the simulator would be used:

* **JavaScript Example:**  A simple JavaScript function would be compiled to S390 machine code, and the simulator would execute that code.
* **Code Logic Inference:**  A conditional branch instruction's behavior depends on the condition codes. I could create a simple example to show how setting registers affects the condition codes and the branch taken.
* **Common Programming Errors:** Stack overflows are a classic issue, and the simulator's stack management makes it relevant. Incorrect register usage is also a common assembly-level mistake.

**8. Structuring the Output:**

Finally, I organized the information logically, starting with the main purpose, then detailing specific functionalities, and addressing the prompt's specific questions (Torque, JavaScript relevance, examples, errors). Using bullet points and clear headings improves readability.

This step-by-step thought process, combining code analysis, domain knowledge (about simulators, assembly, and V8), and consideration of the prompt's specific points, allowed me to generate a comprehensive and accurate description of the header file's functionality.
This C++ header file, `v8/src/execution/s390/simulator-s390.h`, defines a **simulator for the S390 architecture** within the V8 JavaScript engine. Its primary function is to allow developers to **run and debug S390 machine code on non-S390 hardware**.

Here's a breakdown of its key functionalities:

**1. Simulating S390 Instructions:**

* The core purpose is to mimic the behavior of S390 instructions. It contains logic to decode and execute a wide range of S390 opcodes.
* The `Evaluate_...` functions (like `Evaluate_AR`, `Evaluate_BC`, etc.) are the individual handlers for specific S390 instructions. Each of these functions simulates the effect of that instruction on the simulated processor state (registers, memory, condition codes).
* The `EvalTable` acts as a lookup table to dispatch execution to the correct `Evaluate_` function based on the decoded opcode.
* It manages simulated general-purpose registers (GPRs) and floating-point registers (FPRs) using `registers_` and `fp_registers_`.

**2. Managing Simulated Processor State:**

* It maintains the simulated state of the S390 processor, including:
    * **Registers:**  Provides accessors (`set_register`, `get_register`, `get_fpr`, `set_fpr`) to manipulate the simulated registers.
    * **Program Counter (PC):**  Tracks the current instruction being executed (`special_reg_pc_`).
    * **Condition Code Register:**  Simulates the S390 condition code register, which is set by various instructions and used for conditional branching (`condition_reg_`).
    * **Memory:**  Provides functions to read and write data to the simulated memory (`ReadBU`, `WriteW`, etc.).
    * **Stack:**  Manages a simulated stack for function calls and local variables (`stack_`).

**3. Enabling Debugging:**

* It includes support for breakpoints (`BKPT`, `watched_stops_`). Developers can set breakpoints in the simulated code to inspect the state of the simulator at specific points.
* The `DebugStart()` function likely initiates the debugging environment.
* It provides a mechanism for setting and getting the last debugger input.

**4. Supporting Function Calls:**

* The `Call` and `CallFP` methods allow calling simulated S390 functions from the host environment. This is crucial for integrating with V8's code generation and execution pipeline.
* It handles the passing of arguments and return values between the simulator and the host environment.

**5. Instruction Cache Simulation:**

* The `CachePage` class and related functions (`ICacheMatch`, `FlushICache`) simulate the behavior of an instruction cache. This can be important for accurately modeling the performance characteristics of S390 code.

**6. Handling Unsupported Instructions:**

* The `Format` function is likely used to signal when the simulator encounters an instruction it doesn't yet support.

**7. Integration with V8:**

* The header includes `<src/common/globals.h>`, indicating its integration with the broader V8 codebase.
* The use of `v8::internal::Isolate*` suggests it's tied to V8's isolate concept (an isolated instance of the V8 engine).

**Regarding the `.tq` extension:**

The comment states: "If `v8/src/execution/s390/simulator-s390.h` ends with `.tq`, that it is a v8 torque source code."

**Since the file ends with `.h`, it is NOT a V8 Torque source code.** It's a standard C++ header file. Torque files are used to define V8's built-in JavaScript functions and often generate C++ code.

**Relationship to JavaScript Functionality:**

This simulator is indirectly related to JavaScript functionality. Here's how:

1. **V8's Code Generation:** When V8 compiles JavaScript code on an S390 architecture (or when targeting S390 for cross-compilation and testing on other platforms), it generates S390 machine code.
2. **Simulating Execution:** This simulator allows that generated S390 code to be executed on development machines that are not actually S390-based. This is invaluable for development, testing, and debugging.
3. **Testing and Verification:**  The simulator helps ensure the correctness of V8's S390 code generation. Developers can run JavaScript code, observe the simulated execution of the generated S390 code, and verify that it behaves as expected.

**JavaScript Example (Illustrative - the simulator doesn't directly interact with JS in this file):**

Imagine a simple JavaScript function:

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result); // Output: 15
```

When V8 compiles this code for S390, it will generate S390 machine instructions. The `simulator-s390.h` defines the logic to *execute* those generated S390 instructions. For instance, the `add` function might translate to S390 instructions that:

1. Load the values of `a` and `b` into registers.
2. Perform an addition operation on those registers (which would be simulated by the `Evaluate_AR` function if it's an "Add Register" instruction).
3. Store the result back into a register.
4. Return the result.

The simulator would step through these simulated S390 instructions, updating the simulated registers and memory, eventually producing the correct result (15).

**Code Logic Inference Example:**

Let's consider a simplified scenario with a conditional branch instruction.

**Assumption:** The `Evaluate_BC` function simulates the "Branch on Condition" instruction.

**Hypothesis:**  The S390 condition code register determines whether a branch is taken.

**Input:**

1. **Simulated Registers:** `r1` contains the value 10, `r2` contains the value 10.
2. **S390 Instruction:** A "Compare Register" instruction (`CR r1, r2`) followed by a "Branch if Equal" instruction (`BC 8, target_address`). (Note: 8 is the mask for the "equal" condition in S390).
3. **Initial PC:** Points to the `CR` instruction.

**Execution Flow:**

1. **`Evaluate_CR(instr)`:**  This function simulates the comparison. Since `r1` and `r2` are equal, it will set the appropriate bit in the `condition_reg_` to indicate equality.
2. **`Evaluate_BC(instr)`:** This function checks the `condition_reg_`. The instruction `BC 8, target_address` means "branch to `target_address` if the equal bit is set". Since the equal bit was set by the `CR` instruction, the simulator will update the `special_reg_pc_` to `target_address`.

**Output:**

* The `special_reg_pc_` will be updated to `target_address`. The branch is taken.

**User-Visible Programming Errors:**

While this header file defines the *simulator*, it doesn't directly *cause* user programming errors. However, it helps in understanding and debugging errors that might arise from incorrect code generation or assumptions about S390 behavior. Here are some examples of errors the simulator can help uncover:

1. **Incorrect Register Usage:** If the generated S390 code uses the wrong register for an operation, the simulator will reflect this incorrect behavior, potentially leading to wrong results or crashes.

   **Example (Conceptual JavaScript leading to faulty S390):**

   ```javascript
   function multiplyByTwo(x) {
     // Intentionally incorrect: tries to use a register as memory address
     memory[x] = x * 2;
     return memory[x];
   }
   ```

   If the generated S390 code incorrectly interprets the value of `x` as a memory address, the simulator will attempt to write to that address, likely causing an error (if the address is invalid) or producing unexpected results.

2. **Stack Overflow:** If the generated code pushes too much data onto the stack, exceeding the simulated stack limit, the simulator can detect this.

   **Example (Conceptual JavaScript leading to stack overflow):**

   ```javascript
   function recursiveFunction() {
     recursiveFunction(); // Infinite recursion
   }
   recursiveFunction();
   ```

   The generated S390 code for this will involve repeatedly pushing return addresses and potentially local variables onto the stack. The simulator's stack management (`stack_`, `StackLimit`) can help identify when the stack overflows.

3. **Incorrect Conditional Branching Logic:** If the generated code sets the condition codes incorrectly or uses the wrong branch condition, the simulator will follow the incorrect execution path.

   **Example (Conceptual JavaScript leading to faulty branching):**

   ```javascript
   function isPositive(num) {
     if (num > 0) {
       return "Positive";
     } else {
       return "Not Positive";
     }
   }
   ```

   If the S390 code generated for the `if` statement incorrectly sets the condition codes after the comparison, the simulator might take the wrong branch, leading to an incorrect return value.

In summary, `v8/src/execution/s390/simulator-s390.h` is a crucial component for enabling V8 development and testing on the S390 architecture, even when the development environment doesn't have native S390 hardware. It simulates the execution of S390 machine code, allowing developers to understand and debug the generated code, ultimately contributing to the correctness and performance of V8 on that platform.

### 提示词
```
这是目录为v8/src/execution/s390/simulator-s390.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/s390/simulator-s390.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Declares a Simulator for S390 instructions if we are not generating a native
// S390 binary. This Simulator allows us to run and debug S390 code generation
// on regular desktop machines.
// V8 calls into generated code via the GeneratedCode wrapper,
// which will start execution in the Simulator or forwards to the real entry
// on a S390 hardware platform.

#ifndef V8_EXECUTION_S390_SIMULATOR_S390_H_
#define V8_EXECUTION_S390_SIMULATOR_S390_H_

// globals.h defines USE_SIMULATOR.
#include "src/common/globals.h"

#if defined(USE_SIMULATOR)
// Running with a simulator.

#include "src/base/hashmap.h"
#include "src/codegen/assembler.h"
#include "src/codegen/s390/constants-s390.h"
#include "src/execution/simulator-base.h"
#include "src/utils/allocation.h"

namespace v8 {
namespace internal {

class CachePage {
 public:
  static const int LINE_VALID = 0;
  static const int LINE_INVALID = 1;

  static const int kPageShift = 12;
  static const int kPageSize = 1 << kPageShift;
  static const int kPageMask = kPageSize - 1;
  static const int kLineShift = 2;  // The cache line is only 4 bytes right now.
  static const int kLineLength = 1 << kLineShift;
  static const int kLineMask = kLineLength - 1;

  CachePage() { memset(&validity_map_, LINE_INVALID, sizeof(validity_map_)); }

  char* ValidityByte(int offset) {
    return &validity_map_[offset >> kLineShift];
  }

  char* CachedData(int offset) { return &data_[offset]; }

 private:
  char data_[kPageSize];  // The cached data.
  static const int kValidityMapSize = kPageSize >> kLineShift;
  char validity_map_[kValidityMapSize];  // One byte per line.
};

template <class T>
static T ComputeRounding(T a, int mode) {
  switch (mode) {
    case ROUND_TO_NEAREST_AWAY_FROM_0:
      return std::round(a);
    case ROUND_TO_NEAREST_TO_EVEN:
      return std::nearbyint(a);
    case ROUND_TOWARD_0:
      return std::trunc(a);
    case ROUND_TOWARD_POS_INF:
      return std::ceil(a);
    case ROUND_TOWARD_NEG_INF:
      return std::floor(a);
    default:
      UNIMPLEMENTED();
  }
  return 0;
}

class Simulator : public SimulatorBase {
 public:
  friend class S390Debugger;
  enum Register {
    no_reg = -1,
    r0 = 0,
    r1 = 1,
    r2 = 2,
    r3 = 3,
    r4 = 4,
    r5 = 5,
    r6 = 6,
    r7 = 7,
    r8 = 8,
    r9 = 9,
    r10 = 10,
    r11 = 11,
    r12 = 12,
    r13 = 13,
    r14 = 14,
    r15 = 15,
    fp = r11,
    ip = r12,
    cp = r13,
    ra = r14,
    sp = r15,  // name aliases
    kNumGPRs = 16,
    d0 = 0,
    d1,
    d2,
    d3,
    d4,
    d5,
    d6,
    d7,
    d8,
    d9,
    d10,
    d11,
    d12,
    d13,
    d14,
    d15,
    kNumFPRs = 16
  };

  explicit Simulator(Isolate* isolate);
  ~Simulator();

  // The currently executing Simulator instance. Potentially there can be one
  // for each native thread.
  static Simulator* current(v8::internal::Isolate* isolate);

  // Accessors for register state.
  void set_register(int reg, uint64_t value);
  const uint64_t& get_register(int reg) const;
  uint64_t& get_register(int reg);
  template <typename T>
  T get_low_register(int reg) const;
  template <typename T>
  T get_high_register(int reg) const;
  void set_low_register(int reg, uint32_t value);
  void set_high_register(int reg, uint32_t value);

  double get_double_from_register_pair(int reg);

  // Unlike Integer values, Floating Point values are located on the left most
  // side of a native 64 bit register. As FP registers are a subset of vector
  // registers, 64 and 32 bit FP values need to be located on first lane (lane
  // number 0) of a vector register.
  template <class T>
  T get_fpr(int dreg) {
    DCHECK(dreg >= 0 && dreg < kNumFPRs);
    return get_simd_register_by_lane<T>(dreg, 0);
  }

  template <class T>
  void set_fpr(int dreg, const T val) {
    DCHECK(dreg >= 0 && dreg < kNumFPRs);
    set_simd_register_by_lane<T>(dreg, 0, val);
  }

  // Special case of set_register and get_register to access the raw PC value.
  void set_pc(intptr_t value);
  intptr_t get_pc() const;

  Address get_sp() const { return static_cast<Address>(get_register(sp)); }

  // Accessor to the internal simulator stack area. Adds a safety
  // margin to prevent overflows.
  uintptr_t StackLimit(uintptr_t c_limit) const;
  // Return central stack view, without additional safety margins.
  // Users, for example wasm::StackMemory, can add their own.
  base::Vector<uint8_t> GetCentralStackView() const;

  // Executes S390 instructions until the PC reaches end_sim_pc.
  void Execute();

  template <typename Return, typename... Args>
  Return Call(Address entry, Args... args) {
    return VariadicCall<Return>(this, &Simulator::CallImpl, entry, args...);
  }

  // Alternative: call a 2-argument double function.
  void CallFP(Address entry, double d0, double d1);
  int32_t CallFPReturnsInt(Address entry, double d0, double d1);
  double CallFPReturnsDouble(Address entry, double d0, double d1);

  // Push an address onto the JS stack.
  V8_EXPORT_PRIVATE uintptr_t PushAddress(uintptr_t address);

  // Pop an address from the JS stack.
  V8_EXPORT_PRIVATE uintptr_t PopAddress();

  // Debugger input.
  void set_last_debugger_input(char* input);
  char* last_debugger_input() { return last_debugger_input_; }

  // Redirection support.
  static void SetRedirectInstruction(Instruction* instruction);

  // ICache checking.
  static bool ICacheMatch(void* one, void* two);
  static void FlushICache(base::CustomMatcherHashMap* i_cache, void* start,
                          size_t size);

  // Returns true if pc register contains one of the 'special_values' defined
  // below (bad_lr, end_sim_pc).
  bool has_bad_pc() const;

  enum special_values {
    // Known bad pc value to ensure that the simulator does not execute
    // without being properly setup.
    bad_lr = -1,
    // A pc value used to signal the simulator to stop execution.  Generally
    // the lr is set to this value on transition from native C code to
    // simulated execution, so that the simulator can "return" to the native
    // C code.
    end_sim_pc = -2
  };

  intptr_t CallImpl(Address entry, int argument_count,
                    const intptr_t* arguments);

  // Unsupported instructions use Format to print an error and stop execution.
  void Format(Instruction* instr, const char* format);

  // Helper functions to set the conditional flags in the architecture state.
  bool CarryFrom(int32_t left, int32_t right, int32_t carry = 0);
  bool BorrowFrom(int32_t left, int32_t right);
  template <typename T1>
  inline bool OverflowFromSigned(T1 alu_out, T1 left, T1 right, bool addition);

  // Helper functions to decode common "addressing" modes
  int32_t GetShiftRm(Instruction* instr, bool* carry_out);
  int32_t GetImm(Instruction* instr, bool* carry_out);
  void ProcessPUW(Instruction* instr, int num_regs, int operand_size,
                  intptr_t* start_address, intptr_t* end_address);
  void HandleRList(Instruction* instr, bool load);
  void HandleVList(Instruction* inst);
  void SoftwareInterrupt(Instruction* instr);
  void DebugAtNextPC();

  // Stop helper functions.
  inline bool isStopInstruction(Instruction* instr);
  inline bool isWatchedStop(uint32_t bkpt_code);
  inline bool isEnabledStop(uint32_t bkpt_code);
  inline void EnableStop(uint32_t bkpt_code);
  inline void DisableStop(uint32_t bkpt_code);
  inline void IncreaseStopCounter(uint32_t bkpt_code);
  void PrintStopInfo(uint32_t code);

  // Read and write memory.
  inline uint8_t ReadBU(intptr_t addr);
  inline int8_t ReadB(intptr_t addr);
  inline void WriteB(intptr_t addr, uint8_t value);
  inline void WriteB(intptr_t addr, int8_t value);

  inline uint16_t ReadHU(intptr_t addr);
  inline int16_t ReadH(intptr_t addr);
  // Note: Overloaded on the sign of the value.
  inline void WriteH(intptr_t addr, uint16_t value);
  inline void WriteH(intptr_t addr, int16_t value);

  inline uint32_t ReadWU(intptr_t addr);
  inline int32_t ReadW(intptr_t addr);
  inline int64_t ReadW64(intptr_t addr);
  inline void WriteW(intptr_t addr, uint32_t value);
  inline void WriteW(intptr_t addr, int32_t value);

  inline int64_t ReadDW(intptr_t addr);
  inline double ReadDouble(intptr_t addr);
  inline float ReadFloat(intptr_t addr);
  inline void WriteDW(intptr_t addr, int64_t value);

  // S390
  void Trace(Instruction* instr);

  template <typename T>
  void SetS390ConditionCode(T lhs, T rhs) {
    condition_reg_ = 0;
    if (lhs == rhs) {
      condition_reg_ |= CC_EQ;
    } else if (lhs < rhs) {
      condition_reg_ |= CC_LT;
    } else if (lhs > rhs) {
      condition_reg_ |= CC_GT;
    }

    // We get down here only for floating point
    // comparisons and the values are unordered
    // i.e. NaN
    if (condition_reg_ == 0) condition_reg_ = unordered;
  }

  // Used by arithmetic operations that use carry.
  template <typename T>
  void SetS390ConditionCodeCarry(T result, bool overflow) {
    condition_reg_ = 0;
    bool zero_result = (result == static_cast<T>(0));
    if (zero_result && !overflow) {
      condition_reg_ |= 8;
    } else if (!zero_result && !overflow) {
      condition_reg_ |= 4;
    } else if (zero_result && overflow) {
      condition_reg_ |= 2;
    } else if (!zero_result && overflow) {
      condition_reg_ |= 1;
    }
    if (condition_reg_ == 0) UNREACHABLE();
  }

  bool isNaN(double value) { return (value != value); }

  // Set the condition code for bitwise operations
  // CC0 is set if value == 0.
  // CC1 is set if value != 0.
  // CC2/CC3 are not set.
  template <typename T>
  void SetS390BitWiseConditionCode(T value) {
    condition_reg_ = 0;

    if (value == 0)
      condition_reg_ |= CC_EQ;
    else
      condition_reg_ |= CC_LT;
  }

  void SetS390OverflowCode(bool isOF) {
    if (isOF) condition_reg_ = CC_OF;
  }

  bool TestConditionCode(Condition mask) {
    // Check for unconditional branch
    if (mask == 0xf) return true;

    return (condition_reg_ & mask) != 0;
  }

  // Executes one instruction.
  void ExecuteInstruction(Instruction* instr, bool auto_incr_pc = true);

  // ICache.
  static void CheckICache(base::CustomMatcherHashMap* i_cache,
                          Instruction* instr);
  static void FlushOnePage(base::CustomMatcherHashMap* i_cache, intptr_t start,
                           int size);
  static CachePage* GetCachePage(base::CustomMatcherHashMap* i_cache,
                                 void* page);

  // Handle arguments and return value for runtime FP functions.
  void GetFpArgs(double* x, double* y, intptr_t* z);
  void SetFpResult(const double& result);
  void TrashCallerSaveRegisters();

  void CallInternal(Address entry, int reg_arg_count = 3);

  // Architecture state.
  // On z9 and higher and supported Linux on z Systems platforms, all registers
  // are 64-bit, even in 31-bit mode.
  uint64_t registers_[kNumGPRs];
  union fpr_t {
    int8_t int8[16];
    uint8_t uint8[16];
    int16_t int16[8];
    uint16_t uint16[8];
    int32_t int32[4];
    uint32_t uint32[4];
    int64_t int64[2];
    uint64_t uint64[2];
    float f32[4];
    double f64[2];
  };
  fpr_t fp_registers_[kNumFPRs];

  static constexpr fpr_t fp_zero = {{0}};

  fpr_t get_simd_register(int reg) { return fp_registers_[reg]; }

  void set_simd_register(int reg, const fpr_t& value) {
    fp_registers_[reg] = value;
  }

  // Vector register lane numbers on IBM machines are reversed compared to
  // x64. For example, doing an I32x4 extract_lane with lane number 0 on x64
  // will be equal to lane number 3 on IBM machines. Vector registers are only
  // used for compiling Wasm code at the moment. Wasm is also little endian
  // enforced. On s390 native, we manually do a reverse byte whenever values are
  // loaded/stored from memory to a Simd register. On the simulator however, we
  // do not reverse the bytes and data is just copied as is from one memory
  // location to another location which represents a register. To keep the Wasm
  // simulation accurate, we need to make sure accessing a lane is correctly
  // simulated and as such we reverse the lane number on the getters and setters
  // below. We need to be careful when getting/setting values on the Low or High
  // side of a simulated register. In the simulation, "Low" is equal to the MSB
  // and "High" is equal to the LSB on memory. "force_ibm_lane_numbering" could
  // be used to disabled automatic lane number reversal and help with accessing
  // the Low or High side of a simulated register.
  template <class T>
  T get_simd_register_by_lane(int reg, int lane,
                              bool force_ibm_lane_numbering = true) {
    if (force_ibm_lane_numbering) {
      lane = (kSimd128Size / sizeof(T)) - 1 - lane;
    }
    CHECK_LE(lane, kSimd128Size / sizeof(T));
    CHECK_LT(reg, kNumFPRs);
    CHECK_GE(lane, 0);
    CHECK_GE(reg, 0);
    return (reinterpret_cast<T*>(&fp_registers_[reg]))[lane];
  }

  template <class T>
  void set_simd_register_by_lane(int reg, int lane, const T& value,
                                 bool force_ibm_lane_numbering = true) {
    if (force_ibm_lane_numbering) {
      lane = (kSimd128Size / sizeof(T)) - 1 - lane;
    }
    CHECK_LE(lane, kSimd128Size / sizeof(T));
    CHECK_LT(reg, kNumFPRs);
    CHECK_GE(lane, 0);
    CHECK_GE(reg, 0);
    (reinterpret_cast<T*>(&fp_registers_[reg]))[lane] = value;
  }

  // Condition Code register. In S390, the last 4 bits are used.
  int32_t condition_reg_;
  // Special register to track PC.
  intptr_t special_reg_pc_;

  // Simulator support.
  uint8_t* stack_;
  static const size_t kStackProtectionSize = 256 * kSystemPointerSize;
  // This includes a protection margin at each end of the stack area.
  static size_t AllocatedStackSize() {
    size_t stack_size = v8_flags.sim_stack_size * KB;
    return stack_size + (2 * kStackProtectionSize);
  }
  static size_t UsableStackSize() {
    return AllocatedStackSize() - kStackProtectionSize;
  }
  bool pc_modified_;
  int64_t icount_;

  // Debugger input.
  char* last_debugger_input_;

  // Registered breakpoints.
  Instruction* break_pc_;
  Instr break_instr_;

  v8::internal::Isolate* isolate_;

  // A stop is watched if its code is less than kNumOfWatchedStops.
  // Only watched stops support enabling/disabling and the counter feature.
  static const uint32_t kNumOfWatchedStops = 256;

  // Breakpoint is disabled if bit 31 is set.
  static const uint32_t kStopDisabledBit = 1 << 31;

  // A stop is enabled, meaning the simulator will stop when meeting the
  // instruction, if bit 31 of watched_stops_[code].count is unset.
  // The value watched_stops_[code].count & ~(1 << 31) indicates how many times
  // the breakpoint was hit or gone through.
  struct StopCountAndDesc {
    uint32_t count;
    char* desc;
  };
  StopCountAndDesc watched_stops_[kNumOfWatchedStops];
  void DebugStart();

  int DecodeInstructionOriginal(Instruction* instr);
  int DecodeInstruction(Instruction* instr);
  int Evaluate_Unknown(Instruction* instr);
#define MAX_NUM_OPCODES (1 << 16)
  using EvaluateFuncType = int (Simulator::*)(Instruction*);

  static EvaluateFuncType EvalTable[MAX_NUM_OPCODES];
  static void EvalTableInit();

#define EVALUATE(name) int Evaluate_##name(Instruction* instr)
#define EVALUATE_VR_INSTRUCTIONS(name, op_name, op_value) EVALUATE(op_name);
  S390_VRR_A_OPCODE_LIST(EVALUATE_VR_INSTRUCTIONS)
  S390_VRR_C_OPCODE_LIST(EVALUATE_VR_INSTRUCTIONS)
  S390_VRR_E_OPCODE_LIST(EVALUATE_VR_INSTRUCTIONS)
  S390_VRR_F_OPCODE_LIST(EVALUATE_VR_INSTRUCTIONS)
  S390_VRX_OPCODE_LIST(EVALUATE_VR_INSTRUCTIONS)
  S390_VRS_A_OPCODE_LIST(EVALUATE_VR_INSTRUCTIONS)
  S390_VRS_B_OPCODE_LIST(EVALUATE_VR_INSTRUCTIONS)
  S390_VRS_C_OPCODE_LIST(EVALUATE_VR_INSTRUCTIONS)
  S390_VRR_B_OPCODE_LIST(EVALUATE_VR_INSTRUCTIONS)
  S390_VRI_A_OPCODE_LIST(EVALUATE_VR_INSTRUCTIONS)
  S390_VRI_C_OPCODE_LIST(EVALUATE_VR_INSTRUCTIONS)
#undef EVALUATE_VR_INSTRUCTIONS

  EVALUATE(DUMY);
  EVALUATE(BKPT);
  EVALUATE(SPM);
  EVALUATE(BALR);
  EVALUATE(BCTR);
  EVALUATE(BCR);
  EVALUATE(SVC);
  EVALUATE(BSM);
  EVALUATE(BASSM);
  EVALUATE(BASR);
  EVALUATE(MVCL);
  EVALUATE(CLCL);
  EVALUATE(LPR);
  EVALUATE(LNR);
  EVALUATE(LTR);
  EVALUATE(LCR);
  EVALUATE(NR);
  EVALUATE(CLR);
  EVALUATE(OR);
  EVALUATE(XR);
  EVALUATE(LR);
  EVALUATE(CR);
  EVALUATE(AR);
  EVALUATE(SR);
  EVALUATE(MR);
  EVALUATE(DR);
  EVALUATE(ALR);
  EVALUATE(SLR);
  EVALUATE(LDR);
  EVALUATE(CDR);
  EVALUATE(LER);
  EVALUATE(STH);
  EVALUATE(LA);
  EVALUATE(STC);
  EVALUATE(IC_z);
  EVALUATE(EX);
  EVALUATE(BAL);
  EVALUATE(BCT);
  EVALUATE(BC);
  EVALUATE(LH);
  EVALUATE(CH);
  EVALUATE(AH);
  EVALUATE(SH);
  EVALUATE(MH);
  EVALUATE(BAS);
  EVALUATE(CVD);
  EVALUATE(CVB);
  EVALUATE(ST);
  EVALUATE(LAE);
  EVALUATE(N);
  EVALUATE(CL);
  EVALUATE(O);
  EVALUATE(X);
  EVALUATE(L);
  EVALUATE(C);
  EVALUATE(A);
  EVALUATE(S);
  EVALUATE(M);
  EVALUATE(D);
  EVALUATE(AL);
  EVALUATE(SL);
  EVALUATE(STD);
  EVALUATE(LD);
  EVALUATE(CD);
  EVALUATE(STE);
  EVALUATE(MS);
  EVALUATE(LE);
  EVALUATE(BRXH);
  EVALUATE(BRXLE);
  EVALUATE(BXH);
  EVALUATE(BXLE);
  EVALUATE(SRL);
  EVALUATE(SLL);
  EVALUATE(SRA);
  EVALUATE(SLA);
  EVALUATE(SRDL);
  EVALUATE(SLDL);
  EVALUATE(SRDA);
  EVALUATE(SLDA);
  EVALUATE(STM);
  EVALUATE(TM);
  EVALUATE(MVI);
  EVALUATE(TS);
  EVALUATE(NI);
  EVALUATE(CLI);
  EVALUATE(OI);
  EVALUATE(XI);
  EVALUATE(LM);
  EVALUATE(CS);
  EVALUATE(MVCLE);
  EVALUATE(CLCLE);
  EVALUATE(MC);
  EVALUATE(CDS);
  EVALUATE(STCM);
  EVALUATE(ICM);
  EVALUATE(BPRP);
  EVALUATE(BPP);
  EVALUATE(TRTR);
  EVALUATE(MVN);
  EVALUATE(MVC);
  EVALUATE(MVZ);
  EVALUATE(NC);
  EVALUATE(CLC);
  EVALUATE(OC);
  EVALUATE(XC);
  EVALUATE(MVCP);
  EVALUATE(TR);
  EVALUATE(TRT);
  EVALUATE(ED);
  EVALUATE(EDMK);
  EVALUATE(PKU);
  EVALUATE(UNPKU);
  EVALUATE(MVCIN);
  EVALUATE(PKA);
  EVALUATE(UNPKA);
  EVALUATE(PLO);
  EVALUATE(LMD);
  EVALUATE(SRP);
  EVALUATE(MVO);
  EVALUATE(PACK);
  EVALUATE(UNPK);
  EVALUATE(ZAP);
  EVALUATE(AP);
  EVALUATE(SP);
  EVALUATE(MP);
  EVALUATE(DP);
  EVALUATE(UPT);
  EVALUATE(PFPO);
  EVALUATE(IIHH);
  EVALUATE(IIHL);
  EVALUATE(IILH);
  EVALUATE(IILL);
  EVALUATE(NIHH);
  EVALUATE(NIHL);
  EVALUATE(NILH);
  EVALUATE(NILL);
  EVALUATE(OIHH);
  EVALUATE(OIHL);
  EVALUATE(OILH);
  EVALUATE(OILL);
  EVALUATE(LLIHH);
  EVALUATE(LLIHL);
  EVALUATE(LLILH);
  EVALUATE(LLILL);
  EVALUATE(TMLH);
  EVALUATE(TMLL);
  EVALUATE(TMHH);
  EVALUATE(TMHL);
  EVALUATE(BRC);
  EVALUATE(BRAS);
  EVALUATE(BRCT);
  EVALUATE(BRCTG);
  EVALUATE(LHI);
  EVALUATE(LGHI);
  EVALUATE(AHI);
  EVALUATE(AGHI);
  EVALUATE(MHI);
  EVALUATE(MGHI);
  EVALUATE(CHI);
  EVALUATE(CGHI);
  EVALUATE(LARL);
  EVALUATE(LGFI);
  EVALUATE(BRCL);
  EVALUATE(BRASL);
  EVALUATE(XIHF);
  EVALUATE(XILF);
  EVALUATE(IIHF);
  EVALUATE(IILF);
  EVALUATE(NIHF);
  EVALUATE(NILF);
  EVALUATE(OIHF);
  EVALUATE(OILF);
  EVALUATE(LLIHF);
  EVALUATE(LLILF);
  EVALUATE(MSGFI);
  EVALUATE(MSFI);
  EVALUATE(SLGFI);
  EVALUATE(SLFI);
  EVALUATE(AGFI);
  EVALUATE(AFI);
  EVALUATE(ALGFI);
  EVALUATE(ALFI);
  EVALUATE(CGFI);
  EVALUATE(CFI);
  EVALUATE(CLGFI);
  EVALUATE(CLFI);
  EVALUATE(LLHRL);
  EVALUATE(LGHRL);
  EVALUATE(LHRL);
  EVALUATE(LLGHRL);
  EVALUATE(STHRL);
  EVALUATE(LGRL);
  EVALUATE(STGRL);
  EVALUATE(LGFRL);
  EVALUATE(LRL);
  EVALUATE(LLGFRL);
  EVALUATE(STRL);
  EVALUATE(EXRL);
  EVALUATE(PFDRL);
  EVALUATE(CGHRL);
  EVALUATE(CHRL);
  EVALUATE(CGRL);
  EVALUATE(CGFRL);
  EVALUATE(ECTG);
  EVALUATE(CSST);
  EVALUATE(LPD);
  EVALUATE(LPDG);
  EVALUATE(BRCTH);
  EVALUATE(AIH);
  EVALUATE(ALSIH);
  EVALUATE(ALSIHN);
  EVALUATE(CIH);
  EVALUATE(CLIH);
  EVALUATE(STCK);
  EVALUATE(CFC);
  EVALUATE(IPM);
  EVALUATE(HSCH);
  EVALUATE(MSCH);
  EVALUATE(SSCH);
  EVALUATE(STSCH);
  EVALUATE(TSCH);
  EVALUATE(TPI);
  EVALUATE(SAL);
  EVALUATE(RSCH);
  EVALUATE(STCRW);
  EVALUATE(STCPS);
  EVALUATE(RCHP);
  EVALUATE(SCHM);
  EVALUATE(CKSM);
  EVALUATE(SAR);
  EVALUATE(EAR);
  EVALUATE(MSR);
  EVALUATE(MSRKC);
  EVALUATE(MVST);
  EVALUATE(CUSE);
  EVALUATE(SRST);
  EVALUATE(XSCH);
  EVALUATE(STCKE);
  EVALUATE(STCKF);
  EVALUATE(SRNM);
  EVALUATE(STFPC);
  EVALUATE(LFPC);
  EVALUATE(TRE);
  EVALUATE(CUUTF);
  EVALUATE(CUTFU);
  EVALUATE(STFLE);
  EVALUATE(SRNMB);
  EVALUATE(SRNMT);
  EVALUATE(LFAS);
  EVALUATE(PPA);
  EVALUATE(ETND);
  EVALUATE(TEND);
  EVALUATE(NIAI);
  EVALUATE(TABORT);
  EVALUATE(TRAP4);
  EVALUATE(LPEBR);
  EVALUATE(LNEBR);
  EVALUATE(LTEBR);
  EVALUATE(LCEBR);
  EVALUATE(LDEBR);
  EVALUATE(LXDBR);
  EVALUATE(LXEBR);
  EVALUATE(MXDBR);
  EVALUATE(KEBR);
  EVALUATE(CEBR);
  EVALUATE(AEBR);
  EVALUATE(SEBR);
  EVALUATE(MDEBR);
  EVALUATE(DEBR);
  EVALUATE(MAEBR);
  EVALUATE(MSEBR);
  EVALUATE(LPDBR);
  EVALUATE(LNDBR);
  EVALUATE(LTDBR);
  EVALUATE(LCDBR);
  EVALUATE(SQEBR);
  EVALUATE(SQDBR);
  EVALUATE(SQXBR);
  EVALUATE(MEEBR);
  EVALUATE(KDBR);
  EVALUATE(CDBR);
  EVALUATE(ADBR);
  EVALUATE(SDBR);
  EVALUATE(MDBR);
  EVALUATE(DDBR);
  EVALUATE(MADBR);
  EVALUATE(MSDBR);
  EVALUATE(LPXBR);
  EVALUATE(LNXBR);
  EVALUATE(LTXBR);
  EVALUATE(LCXBR);
  EVALUATE(LEDBRA);
  EVALUATE(LDXBRA);
  EVALUATE(LEXBRA);
  EVALUATE(FIXBRA);
  EVALUATE(KXBR);
  EVALUATE(CXBR);
  EVALUATE(AXBR);
  EVALUATE(SXBR);
  EVALUATE(MXBR);
  EVALUATE(DXBR);
  EVALUATE(TBEDR);
  EVALUATE(TBDR);
  EVALUATE(DIEBR);
  EVALUATE(FIEBRA);
  EVALUATE(THDER);
  EVALUATE(THDR);
  EVALUATE(DIDBR);
  EVALUATE(FIDBRA);
  EVALUATE(LXR);
  EVALUATE(LPDFR);
  EVALUATE(LNDFR);
  EVALUATE(LCDFR);
  EVALUATE(LZER);
  EVALUATE(LZDR);
  EVALUATE(LZXR);
  EVALUATE(SFPC);
  EVALUATE(SFASR);
  EVALUATE(EFPC);
  EVALUATE(CELFBR);
  EVALUATE(CDLFBR);
  EVALUATE(CXLFBR);
  EVALUATE(CEFBRA);
  EVALUATE(CDFBRA);
  EVALUATE(CXFBRA);
  EVALUATE(CFEBRA);
  EVALUATE(CFDBRA);
  EVALUATE(CFXBRA);
  EVALUATE(CLFEBR);
  EVALUATE(CLFDBR);
  EVALUATE(CLFXBR);
  EVALUATE(CELGBR);
  EVALUATE(CDLGBR);
  EVALUATE(CXLGBR);
  EVALUATE(CEGBRA);
  EVALUATE(CDGBRA);
  EVALUATE(CXGBRA);
  EVALUATE(CGEBRA);
  EVALUATE(CGDBRA);
  EVALUATE(CGXBRA);
  EVALUATE(CLGEBR);
  EVALUATE(CLGDBR);
  EVALUATE(CFER);
  EVALUATE(CFDR);
  EVALUATE(CFXR);
  EVALUATE(LDGR);
  EVALUATE(CGER);
  EVALUATE(CGDR);
  EVALUATE(CGXR);
  EVALUATE(LGDR);
  EVALUATE(MDTR);
  EVALUATE(MDTRA);
  EVALUATE(DDTRA);
  EVALUATE(ADTRA);
  EVALUATE(SDTRA);
  EVALUATE(LDETR);
  EVALUATE(LEDTR);
  EVALUATE(LTDTR);
  EVALUATE(FIDTR);
  EVALUATE(MXTRA);
  EVALUATE(DXTRA);
  EVALUATE(AXTRA);
  EVALUATE(SXTRA);
  EVALUATE(LXDTR);
  EVALUATE(LDXTR);
  EVALUATE(LTXTR);
  EVALUATE(FIXTR);
  EVALUATE(KDTR);
  EVALUATE(CGDTRA);
  EVALUATE(CUDTR);
  EVALUATE(CDTR);
  EVALUATE(EEDTR);
  EVALUATE(ESDTR);
  EVALUATE(KXTR);
  EVALUATE(CGXTRA);
  EVALUATE(CUXTR);
  EVALUATE(CSXTR);
  EVALUATE(CXTR);
  EVALUATE(EEXTR);
  EVALUATE(ESXTR);
  EVALUATE(CDGTRA);
  EVALUATE(CDUTR);
  EVALUATE(CDSTR);
  EVALUATE(CEDTR);
  EVALUATE(QADTR);
  EVALUATE(IEDTR);
  EVALUATE(RRDTR);
  EVALUATE(CXGTRA);
  EVALUATE(CXUTR);
  EVALUATE(CXSTR);
  EVALUATE(CEXTR);
  EVALUATE(QAXTR);
  EVALUATE(IEXTR);
  EVALUATE(RRXTR);
  EVALUATE(LPGR);
  EVALUATE(LNGR);
  EVALUATE(LTGR);
  EVALUATE(LCGR);
  EVALUATE(LGR);
  EVALUATE(LGBR);
  EVALUATE(LGHR);
  EVALUATE(AGR);
  EVALUATE(SGR);
  EVALUATE(ALGR);
  EVALUATE(SLGR);
  EVALUATE(MSGR);
  EVALUATE(MSGRKC);
  EVALUATE(DSGR);
  EVALUATE(LRVGR);
  EVALUATE(LPGFR);
  EVALUATE(LNGFR);
  EVALUATE(LTGFR);
  EVALUATE(LCGFR);
  EVALUATE(LGFR);
  EVALUATE(LLGFR);
  EVALUATE(LLGTR);
  EVALUATE(AGFR);
  EVALUATE(SGFR);
  EVALUATE(ALGFR);
  EVALUATE(SLGFR);
  EVALUATE(MSGFR);
  EVALUATE(DSGFR);
  EVALUATE(KMAC);
  EVALUATE(LRVR);
  EVALUATE(CGR);
  EVALUATE(CLGR);
  EVALUATE(LBR);
  EVALUATE(LHR);
  EVALUATE(KMF);
  EVALUATE(KMO);
  EVALUATE(PCC);
  EVALUATE(KMCTR);
  EVALUATE(KM);
  EVALUATE(KMC);
  EVALUATE(CGFR);
  EVALUATE(KIMD);
  EVALUATE(KLMD);
  EVALUATE(CFDTR);
  EVALUATE(CLGDTR);
  EVALUATE(CLFDTR);
  EVALUATE(BCTGR);
  EVALUATE(CFXTR);
  EVALUATE(CLFXTR);
  EVALUATE(CDFTR);
  EVALUATE(CDLGTR);
  EVALUATE(CDLFTR);
  EVALUATE(CXFTR);
  EVALUATE(CXLGTR);
  EVALUATE(CXLFTR);
  EVALUATE(CGRT);
  EVALUATE(NGR);
  EVALUATE(OGR);
  EVALUATE(XGR);
  EVALUATE(FLOGR);
  EVALUATE(LLGCR);
  EVALUATE(LLGHR);
  EVALUATE(MLGR);
  EVALUATE(DLGR);
  EVALUATE(ALCGR);
  EVALUATE(SLBGR);
  EVALUATE(EPSW);
  EVALUATE(TRTT);
  EVALUATE(TRTO);
  EVALUATE(TROT);
  EVALUATE(TROO);
  EVALUATE(LLCR);
  EVALUATE(LLHR);
  EVALUATE(MLR);
  EVALUATE(DLR);
  EVALUATE(ALCR);
  EVALUATE(SLBR);
  EVALUATE(CU14);
  EVALUATE(CU24);
  EVALUATE(CU41);
  EVALUATE(CU42);
  EVALUATE(TRTRE);
  EVALUATE(SRSTU);
  EVALUATE(TRTE);
  EVALUATE(AHHHR);
  EVALUATE(SHHHR);
  EVALUATE(ALHHHR);
  EVALUATE(SLHHHR);
  EVALUATE(CHHR);
  EVALUATE(AHHLR);
  EVALUATE(SHHLR);
  EVALUATE(ALHHLR);
  EVALUATE(SLHHLR);
  EVALUATE(CHLR);
  EVALUATE(POPCNT_Z);
  EVALUATE(LOCGR);
  EVALUATE(NGRK);
  EVALUATE(OGRK);
  EVALUATE(XGRK);
  EVALUATE(AGRK);
  EVALUATE(SGRK);
  EVALUATE(ALGRK);
  EVALUATE(SLGRK);
  EVALUATE(LOCR);
  EVALUATE(NRK);
  EVALUATE(ORK);
  EVALUATE(XRK);
  EVALUATE(ARK);
  EVALUATE(SRK);
  EVALUATE(ALRK);
  EVALUATE(SLRK);
  EVALUATE(LTG);
  EVALUATE(LG);
  EVALUATE(CVBY);
  EVALUATE(AG);
  EVALUATE(SG);
  EVALUATE(ALG);
  EVALUATE(SLG);
  EVALUATE(MSG);
  EVALUATE(DSG);
  EVALUATE(CVBG);
  EVALUATE(LRVG);
  EVALUATE(LT);
  EVALUATE(LGF);
  EVALUATE(LGH);
  EVALUATE(LLGF);
  EVALUATE(LLGT);
  EVALUATE(AGF);
  EVALUATE(SGF);
  EVALUATE(ALGF);
  EVALUATE(SLGF);
  EVALUATE(MSGF);
  EVALUATE(DSGF);
  EVALUATE(LRV);
  EVALUATE(LRVH);
  EVALUATE(CG);
  EVALUATE(CLG);
  EVALUATE(STG);
  EVALUATE(NTSTG);
  EVALUATE(CVDY);
  EVALUATE(CVDG);
  EVALUATE(STRVG);
  EVALUATE(CGF);
  EVALUATE(CLGF);
  EVALUATE(LTGF);
  EVALUATE(CGH);
  EVALUATE(PFD);
  EVALUATE(STRV);
  EVALUATE(STRVH);
  EVALUATE(BCTG);
  EVALUATE(STY);
  EVALUATE(MSY);
  EVALUATE(MSC);
  EVALUATE(NY);
  EVALUATE(CLY);
  EVALUATE(OY);
  EVALUATE(XY);
  EVALUATE(LY);
  EVALUATE(CY);
  EVALUATE(AY);
  EVALUATE(SY);
  EVALUATE(MFY);
  EVALUATE(ALY);
  EVALUATE(SLY);
  EVALUATE(STHY);
  EVALUATE(LAY);
  EVALUATE(STCY);
  EVALUATE(ICY);
  EVALUATE(LAEY);
  EVALUATE(LB);
  EVALUATE(LGB);
  EVALUATE(LHY);
  EVALUATE(CHY);
  EVALUATE(AHY);
  EVALUATE(SHY);
  EVALUATE(MHY);
  EVALUATE(NG);
  EVALUATE(OG);
  EVALUATE(XG);
  EVALUATE(LGAT);
  EVALUATE(MLG);
  EVALUATE(DLG);
  EVALUATE(ALCG);
  EVALUATE(SLBG);
  EVALUATE(STPQ);
  EVALUATE(LPQ);
  EVALUATE(LLGC);
  EVALUATE(LLGH);
  EVALUATE(LLC);
  EVALUATE(LLH);
  EVALUATE(ML);
  EVALUATE(DL);
  EVALUATE(ALC);
  EVALUATE(SLB);
  EVALUATE(LLGTAT);
  EVALUATE(LLGFAT);
  EVALUATE(LAT);
  EVALUATE(LBH);
  EVALUATE(LLCH);
  EVALUATE(STCH);
  EVALUATE(LHH);
  EVALUATE(LLHH);
  EVALUATE(STHH);
  EVALUATE(LFHAT);
  EVALUATE(LFH);
  EVALUATE(STFH);
  EVALUATE(CHF);
  EVALUATE(MVCDK);
  EVALUATE(MVHHI);
  EVALUATE(MVGHI);
  EVALUATE(MVHI);
  EVALUATE(CHHSI);
  EVALUATE(CGHSI);
  EVALUATE(CHSI);
  EVALUATE(CLFHSI);
  EVALUATE(TBEGIN);
  EVALUATE(TBEGINC);
  EVALUATE(LMG);
  EVALUATE(SRAG);
  EVALUATE(SLAG);
  EVALUATE(SRLG);
  EVALUATE(SLLG);
  EVALUATE(CSY);
  EVALUATE(CSG);
  EVALUATE(RLLG);
  EVALUATE(RLL);
  EVALUATE(STMG);
  EVALUATE(STMH);
  EVALUATE(STCMH);
  EVALUATE(STCMY);
  EVALUATE(CDSY);
  EVALUATE(CDSG);
  EVALUATE(BXHG);
  EVALUATE(BXLEG);
  EVALUATE(ECAG);
  EVALUATE(TMY);
  EVALUATE(MVIY);
  EVALUATE(NIY);
  EVALUATE(CLIY);
  EVALUATE(OIY);
  EVALUATE(XIY);
  EVALUATE(ASI);
  EVALUATE(ALSI);
  EVALUATE(AGSI);
  EVALUATE(ALGSI);
  EVALUATE(ICMH);
  EVALUATE(ICMY);
  EVALUATE(MVCLU);
  EVALUATE(CLCLU);
  EVALUATE(STMY);
  EVALUATE(LMH);
  EVALUATE(LMY);
  EVALUATE(TP);
  EVALUATE(SRAK);
  EVALUATE(SLAK);
  EVALUATE(SRLK);
  EVALUATE(SLLK);
  EVALUATE(LOCG);
  EVALUATE(STOCG);
  EVALUATE(LANG);
  EVALUATE(LAOG);
  EVALUATE(LAXG);
  EVALUATE(LAAG);
  EVALUATE(LAALG);
  EVALUATE(LOC);
  EVALUATE(STOC);
  EVALUATE(LAN);
  EVALUATE(LAO);
  EVALUATE(LAX);
  EVALUATE(LAA);
  EVALUATE(LAAL);
  EVALUATE(BRXHG);
  EVALUATE(BRXLG);
  EVALUATE(RISBLG);
  EVALUATE(RNSBG);
  EVALUATE(RISBG);
  EVALUATE(ROSBG);
  EVALUATE(RXSBG);
  EVALUATE(RISBGN);
  EVALUATE(RISBHG);
  EVALUATE(CGRJ);
  EVALUATE(CGIT);
  EVALUATE(CIT);
  EVALUATE(CLFIT);
  EVALUATE(CGIJ);
  EVALUATE(CIJ);
  EVALUATE(AHIK);
  EVALUATE(AGHIK);
  EVALUATE(ALHSIK);
  EVALUATE(ALGHSIK);
  EVALUATE(CGRB);
  EVALUATE(CGIB);
  EVALUATE(CIB);
  EVALUATE(LDEB);
  EVALUATE(LXDB);
  EVALUATE(LXEB);
  EVALUATE(MXDB);
  EVALUATE(KEB);
  EVALUATE(CEB);
  EVALUATE(AEB);
  EVALUATE(SEB);
  EVALUATE(MDEB);
  EVALUATE(DEB);
  EVALUATE(MAEB);
  EVALUATE(MSEB);
  EVALUATE(TCEB);
  EVALUATE(TCDB);
  EVALUATE(TCXB);
  EVALUATE(SQEB);
  EVALUATE(SQDB);
  EVALUATE(MEEB);
  EVALUATE(KDB);
  EVALUATE(CDB);
  EVALUATE(ADB);
  EVALUATE(SDB);
  EVALUATE(MDB);
  EVALUATE(DDB);
  EVALUATE(MADB);
  EVALUATE(MSDB);
  EVALUATE(SLDT);
  EVALUATE(SRDT);
  EVALUATE(SLXT);
  EVALUATE(SRXT);
  EVALUATE(TDCET);
  EVALUATE(TDGET);
  EVALUATE(TDCDT);
  EVALUATE(TDGDT);
  EVALUATE(TDCXT);
  EVALUATE(TDGXT);
  EVALUATE(LEY);
  EVALUATE(LDY);
  EVALUATE(STEY);
  EVALUATE(STDY);
  EVALUATE(CZDT);
  EVALUATE(CZXT);
  EVALUATE(CDZT);
  EVALUATE(CXZT);
  EVALUATE(MG);
  EVALUATE(MGRK);

#undef EVALUATE
};

}  // namespace internal
}  // namespace v8

#endif  // defined(USE_SIMULATOR)
#endif  // V8_EXECUTION_S390_SIMULATOR_S390_H_
```