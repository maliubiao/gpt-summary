Response: The user wants me to summarize the functionality of the provided C++ code snippet, which is a part of the `simulator-riscv.cc` file in the V8 JavaScript engine. I need to identify the main purposes of the code and, if relevant, illustrate the connection to JavaScript with examples.

The code snippet appears to define macros and functions related to simulating RISC-V vector instructions (RVV). It includes:

1. **Macros for generating loops for vector operations:** These macros handle scaling, checking alignment, and applying operations based on the vector element width (SEW).
2. **A function for calculating rounding values:** `get_round` implements different rounding modes for vector operations.
3. **Template functions for signed and unsigned saturation:** `signed_saturation` and `unsigned_saturation` handle clipping values to a specific range.
4. **Macros for implementing vector narrow instructions with clipping:** `RVV_VN_CLIPU_VI_LOOP` and `RVV_VN_CLIP_VI_LOOP` perform vector narrowing operations with unsigned and signed saturation, respectively.
5. **Macros for implementing vector-scalar widening instructions:** `RVV_VI_VIE_8_LOOP`, `RVV_VI_VIE_4_LOOP`, and `RVV_VI_VIE_2_LOOP` handle widening operations where a scalar value is expanded into a vector.
6. **A debugger class:** `RiscvDebugger` provides functionality for inspecting the state of the simulated RISC-V processor, including registers, memory, and disassembling code. It also allows for stepping through instructions and setting breakpoints.
7. **Functions within the debugger class:** These functions handle printing register values, disassembling instructions, examining memory, and managing breakpoints.
8. **Simulator class methods related to debugging:** `SetBreakpoint`, `ListBreakpoints`, `CheckBreakpoints`, and methods for interacting with the instruction cache.
9. **Simulator class methods for register and memory access:** `set_register`, `get_register`, `set_fpu_register`, `get_fpu_register`, `ReadMem`, `WriteMem`.
10. **Simulator class methods for handling floating-point CSR:** `read_csr_value`, `write_csr_value`, `set_csr_bits`, `clear_csr_bits`.
11. **Tracing functionality:** Methods for tracing register writes and memory reads/writes.
12. **Stack management methods:** `StackLimit`, `GetCentralStackView`.

The code is heavily involved in the low-level simulation of RISC-V instructions, particularly those related to vector processing. The debugger class provides essential tools for understanding the execution flow and state of the simulated processor.

The connection to JavaScript lies in how V8 executes JavaScript code. When JavaScript code needs to perform operations that can be optimized using SIMD (Single Instruction, Multiple Data) techniques, V8 can potentially translate these operations into RISC-V vector instructions. The simulator then executes these instructions, effectively mimicking the behavior of a real RISC-V processor.

**JavaScript Example:**

Consider a JavaScript array of numbers where we want to perform an element-wise addition with another number and then clip the result to a specific range.

```javascript
const arr = [10, 20, 30, 40];
const scalar = 5;
const upperBound = 35;

const result = arr.map(x => Math.min(x + scalar, upperBound));
console.log(result); // Output: [15, 25, 35, 35]
```

Internally, if the JavaScript engine (V8 in this case) detects an opportunity for optimization, it might translate this operation into a sequence of RISC-V vector instructions. The `RVV_VN_CLIPU_VI_LOOP` macro (or similar) could be used in the simulator to execute the clipping operation efficiently on multiple array elements in parallel, simulating how a real RISC-V processor with vector extensions would handle it. The `get_round` function might be relevant if the addition involved floating-point numbers and specific rounding rules were required. The saturation functions would be used to enforce the `upperBound`. The debugger class would be used by V8 developers to test and verify the correct execution of these simulated vector instructions.

This code snippet from `v8/src/execution/riscv/simulator-riscv.cc` is a crucial part of the RISC-V simulator within the V8 JavaScript engine. It primarily focuses on **simulating the execution of RISC-V Vector (RVV) instructions and providing debugging capabilities for the simulator.**

Here's a breakdown of its functionalities:

**1. Vector Instruction Simulation Macros and Functions:**

*   **Loop Generation Macros (`_VI_VFP_LOOP`, `RVV_VN_CLIPU_VI_LOOP`, `RVV_VN_CLIP_VI_LOOP`, `RVV_VI_VIE_8_LOOP`, etc.):** These macros are designed to generate the core loop structure for simulating various RVV instructions. They handle details like:
    *   **Scaling:** Adjusting the loop based on the Vector Length Multiplier (VLMUL).
    *   **Element Width (SEW):**  Switching execution paths based on the size of the vector elements (8, 16, 32 bits).
    *   **Masking:**  Skipping elements based on the current vector mask.
    *   **Alignment Checks:** Ensuring memory accesses are aligned according to RVV requirements.
    *   **Applying the core operation (BODY):**  A placeholder where the specific logic of the vector instruction is implemented.
    *   **Rounding:** Potentially calling functions to handle rounding modes.
    *   **Saturation:**  Using functions like `signed_saturation` and `unsigned_saturation` to clamp values to specific ranges.
    *   **Tracing:** Calling `rvv_trace_vd()` to log the result of the vector operation (for debugging).
*   **`get_round()`:** This function calculates the rounding value based on the current rounding mode (`vxrm`) and the bits being shifted out during a shift operation. This is essential for accurately simulating different rounding behaviors in floating-point and integer RVV instructions.
*   **`signed_saturation()` and `unsigned_saturation()`:** These template functions implement signed and unsigned saturation, respectively. They are used in instructions that clip values to a specific bit width, preventing overflow or underflow.

**2. RISC-V Debugger (`RiscvDebugger`):**

*   This class provides an interactive debugger for inspecting the state of the simulated RISC-V processor. It allows developers to:
    *   **Step through instructions (`si`, `stepi`).**
    *   **Continue execution (`c`, `cont`).**
    *   **Print register values (`p`, `print`):**  For general-purpose registers, FPU registers, and potentially vector registers.
    *   **Print object information (`po`, `printobject`):**  If the register holds a pointer to a V8 object.
    *   **Examine memory (`stack`, `mem`, `memhex`):**  To view the contents of memory locations.
    *   **Set watchpoints (`watch`):** To monitor memory locations for changes.
    *   **Disassemble code (`disasm`, `dpc`, `di`):** To view the assembly instructions around a given address.
    *   **Drop into GDB (`gdb`):**  To use a more powerful external debugger.
    *   **Toggle tracing (`trace`):** To enable detailed logging of instruction execution.
    *   **Set breakpoints (`break`, `b`, `tbreak`):** To pause execution at specific instructions.
    *   **Manage "stops" (`stop`):** Debug instructions inserted by the assembler.
    *   **View simulator statistics (`stat`, `st`):** Print registers and disassemble nearby code.
    *   **Get help (`h`, `help`).**

**3. Simulator Class Methods for Debugging and State Management:**

*   **`SetBreakpoint()`:**  Allows setting breakpoints at specific instruction addresses.
*   **`ListBreakpoints()`:** Displays the currently set breakpoints.
*   **`CheckBreakpoints()`:**  Checks if the current program counter matches any enabled breakpoints and, if so, enters the debugger.
*   **`ICacheMatch()`, `ICacheHash()`, `FlushICache()`, `GetCachePage()`, `FlushOnePage()`, `CheckICache()`:** These methods handle the simulation of the instruction cache (I-cache), ensuring that the simulator fetches the correct instructions from memory and manages cache coherency.
*   **`set_last_debugger_input()`:** Stores the last debugger command entered by the user.
*   **`SetRedirectInstruction()`:** Modifies an instruction to redirect execution, potentially used for implementing function calls or other control flow mechanisms within the simulator.
*   **`set_register()`, `get_register()`:**  Methods for setting and getting the values of general-purpose registers.
*   **`set_fpu_register()`, `get_fpu_register()` (and variants for different FPU data types):** Methods for setting and getting the values of floating-point registers.
*   **`read_csr_value()`, `write_csr_value()`, `set_csr_bits()`, `clear_csr_bits()`:** Methods for interacting with Control and Status Registers (CSRs), particularly those related to floating-point operations (FCSR).
*   **`FMaxMinHelper()`:** A helper function for simulating the `fmax` and `fmin` instructions, handling NaN and signed zero cases according to the IEEE 754 standard.
*   **`set_pc()`, `get_pc()`, `has_bad_pc()`:** Methods for managing the program counter.
*   **`DieOrDebug()`:**  A function to trigger the debugger or abort execution when an error occurs.
*   **`TraceRegWr()`, `TraceMemRd()`, `TraceMemWr()`:** Methods for tracing register writes and memory accesses, used for debugging and understanding the simulator's execution flow.
*   **`ReadMem()`, `WriteMem()`:** Template methods for reading and writing data to simulated memory, handling alignment checks (depending on configuration).
*   **`StackLimit()`, `GetCentralStackView()`:** Methods related to managing the simulated stack.
*   **`Format()`:** A function to handle unsupported instructions by printing an error message.

**Relationship to JavaScript:**

This code is directly responsible for **how V8 executes JavaScript code when that code leverages features that can be optimized using RISC-V vector instructions.**

**Example:**

Imagine the following JavaScript code:

```javascript
const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);
const c = new Float32Array(4);

for (let i = 0; i < a.length; i++) {
  c[i] = Math.max(a[i], b[i]);
}
console.log(c); // Output: Float32Array [ 5, 6, 7, 8 ]
```

When V8's optimizing compiler (like TurboFan) encounters this loop, it might recognize that the `Math.max` operation can be vectorized on a RISC-V processor with vector extensions. It might generate RISC-V vector instructions to perform the `max` operation on multiple elements of `a` and `b` simultaneously.

The provided C++ code in the simulator would then be responsible for executing these generated vector instructions. Specifically:

*   A macro like `_VI_VFP_LOOP` (or a similar one for floating-point max) would be used to structure the simulation loop.
*   The `BODY` part of the macro would contain the logic to compare corresponding elements from the simulated vector registers holding chunks of `a` and `b`, and store the maximums into the simulated vector register representing `c`.
*   The `get_round` function might be relevant if the operations involved different rounding modes.
*   The debugger class would allow V8 developers to step through the execution of these simulated vector instructions, inspect the values in the vector registers, and verify that the simulation is behaving correctly.

In essence, this code allows V8 to **test and verify the correctness of its code generation for RISC-V vector instructions** on platforms where a real RISC-V processor with vector extensions might not be available. It also provides a powerful tool for understanding the low-level details of how these instructions operate.

Prompt: 
```
这是目录为v8/src/execution/riscv/simulator-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
_check);                                                           \
  switch (rvv_vsew()) {                                                       \
    case E8: {                                                                \
      CHECK8                                                                  \
      VI_VFP_LOOP_SCALE_BASE                                                  \
      BODY8 /*set_fp_exceptions*/;                                            \
      RVV_VI_VFP_LOOP_END                                                     \
    } break;                                                                  \
    case E16: {                                                               \
      CHECK16                                                                 \
      VI_VFP_LOOP_SCALE_BASE                                                  \
      BODY16 /*set_fp_exceptions*/;                                           \
      RVV_VI_VFP_LOOP_END                                                     \
    } break;                                                                  \
    case E32: {                                                               \
      CHECK32                                                                 \
      VI_VFP_LOOP_SCALE_BASE                                                  \
      BODY32 /*set_fp_exceptions*/;                                           \
      RVV_VI_VFP_LOOP_END                                                     \
    } break;                                                                  \
    default:                                                                  \
      require(0);                                                             \
      break;                                                                  \
  }                                                                           \
  rvv_trace_vd();

// calculate the value of r used in rounding
static inline uint8_t get_round(int vxrm, uint64_t v, uint8_t shift) {
  uint8_t d = v8::internal::unsigned_bitextract_64(shift, shift, v);
  uint8_t d1;
  uint64_t D1, D2;

  if (shift == 0 || shift > 64) {
    return 0;
  }

  d1 = v8::internal::unsigned_bitextract_64(shift - 1, shift - 1, v);
  D1 = v8::internal::unsigned_bitextract_64(shift - 1, 0, v);
  if (vxrm == 0) { /* round-to-nearest-up (add +0.5 LSB) */
    return d1;
  } else if (vxrm == 1) { /* round-to-nearest-even */
    if (shift > 1) {
      D2 = v8::internal::unsigned_bitextract_64(shift - 2, 0, v);
      return d1 & ((D2 != 0) | d);
    } else {
      return d1 & d;
    }
  } else if (vxrm == 3) { /* round-to-odd (OR bits into LSB, aka "jam") */
    return !d & (D1 != 0);
  }
  return 0; /* round-down (truncate) */
}

template <typename Src, typename Dst>
inline Dst signed_saturation(Src v, uint n) {
  Dst smax = (Dst)(INTPTR_MAX >> (sizeof(intptr_t) * 8 - n));
  Dst smin = (Dst)(INTPTR_MIN >> (sizeof(intptr_t) * 8 - n));
  return (v > smax) ? smax : ((v < smin) ? smin : (Dst)v);
}

template <typename Src, typename Dst>
inline Dst unsigned_saturation(Src v, uint n) {
  Dst umax = (Dst)(UINTPTR_MAX >> (sizeof(uintptr_t) * 8 - n));
  return (v > umax) ? umax : ((v < 0) ? 0 : (Dst)v);
}

#define RVV_VN_CLIPU_VI_LOOP()                                   \
  RVV_VI_GENERAL_LOOP_BASE                                       \
  RVV_VI_LOOP_MASK_SKIP()                                        \
  if (rvv_vsew() == E8) {                                        \
    VN_UPARAMS(16);                                              \
    vd = unsigned_saturation<uint16_t, uint8_t>(                 \
        (static_cast<uint16_t>(vs2) >> uimm5) +                  \
            get_round(static_cast<int>(rvv_vxrm()), vs2, uimm5), \
        8);                                                      \
  } else if (rvv_vsew() == E16) {                                \
    VN_UPARAMS(32);                                              \
    vd = unsigned_saturation<uint32_t, uint16_t>(                \
        (static_cast<uint32_t>(vs2) >> uimm5) +                  \
            get_round(static_cast<int>(rvv_vxrm()), vs2, uimm5), \
        16);                                                     \
  } else if (rvv_vsew() == E32) {                                \
    VN_UPARAMS(64);                                              \
    vd = unsigned_saturation<uint64_t, uint32_t>(                \
        (static_cast<uint64_t>(vs2) >> uimm5) +                  \
            get_round(static_cast<int>(rvv_vxrm()), vs2, uimm5), \
        32);                                                     \
  } else if (rvv_vsew() == E64) {                                \
    UNREACHABLE();                                               \
  } else {                                                       \
    UNREACHABLE();                                               \
  }                                                              \
  RVV_VI_LOOP_END                                                \
  rvv_trace_vd();

#define RVV_VN_CLIP_VI_LOOP()                                                 \
  RVV_VI_GENERAL_LOOP_BASE                                                    \
  RVV_VI_LOOP_MASK_SKIP()                                                     \
  if (rvv_vsew() == E8) {                                                     \
    VN_PARAMS(16);                                                            \
    vd = signed_saturation<int16_t, int8_t>(                                  \
        (vs2 >> uimm5) + get_round(static_cast<int>(rvv_vxrm()), vs2, uimm5), \
        8);                                                                   \
  } else if (rvv_vsew() == E16) {                                             \
    VN_PARAMS(32);                                                            \
    vd = signed_saturation<int32_t, int16_t>(                                 \
        (vs2 >> uimm5) + get_round(static_cast<int>(rvv_vxrm()), vs2, uimm5), \
        16);                                                                  \
  } else if (rvv_vsew() == E32) {                                             \
    VN_PARAMS(64);                                                            \
    vd = signed_saturation<int64_t, int32_t>(                                 \
        (vs2 >> uimm5) + get_round(static_cast<int>(rvv_vxrm()), vs2, uimm5), \
        32);                                                                  \
  } else if (rvv_vsew() == E64) {                                             \
    UNREACHABLE();                                                            \
  } else {                                                                    \
    UNREACHABLE();                                                            \
  }                                                                           \
  RVV_VI_LOOP_END                                                             \
  rvv_trace_vd();

#define CHECK_EXT(div)                                              \
  CHECK_NE(rvv_vd_reg(), rvv_vs2_reg());                            \
  reg_t from = rvv_vsew() / div;                                    \
  CHECK(from >= E8 && from <= E64);                                 \
  CHECK_GE((float)rvv_vflmul() / div, 0.125);                       \
  CHECK_LE((float)rvv_vflmul() / div, 8);                           \
  require_align(rvv_vd_reg(), rvv_vflmul());                        \
  require_align(rvv_vs2_reg(), rvv_vflmul() / div);                 \
  if ((rvv_vflmul() / div) < 1) {                                   \
    require_noover(rvv_vd_reg(), rvv_vflmul(), rvv_vs2_reg(),       \
                   rvv_vflmul() / div);                             \
  } else {                                                          \
    require_noover_widen(rvv_vd_reg(), rvv_vflmul(), rvv_vs2_reg(), \
                         rvv_vflmul() / div);                       \
  }

#define RVV_VI_VIE_8_LOOP(signed)      \
  CHECK_EXT(8)                         \
  RVV_VI_GENERAL_LOOP_BASE             \
  RVV_VI_LOOP_MASK_SKIP()              \
  if (rvv_vsew() == E64) {             \
    if (signed) {                      \
      VI_VIE_PARAMS(64, 8);            \
      vd = static_cast<int64_t>(vs2);  \
    } else {                           \
      VI_VIE_UPARAMS(64, 8);           \
      vd = static_cast<uint64_t>(vs2); \
    }                                  \
  } else {                             \
    UNREACHABLE();                     \
  }                                    \
  RVV_VI_LOOP_END                      \
  rvv_trace_vd();

#define RVV_VI_VIE_4_LOOP(signed)      \
  CHECK_EXT(4)                         \
  RVV_VI_GENERAL_LOOP_BASE             \
  RVV_VI_LOOP_MASK_SKIP()              \
  if (rvv_vsew() == E32) {             \
    if (signed) {                      \
      VI_VIE_PARAMS(32, 4);            \
      vd = static_cast<int32_t>(vs2);  \
    } else {                           \
      VI_VIE_UPARAMS(32, 4);           \
      vd = static_cast<uint32_t>(vs2); \
    }                                  \
  } else if (rvv_vsew() == E64) {      \
    if (signed) {                      \
      VI_VIE_PARAMS(64, 4);            \
      vd = static_cast<int64_t>(vs2);  \
    } else {                           \
      VI_VIE_UPARAMS(64, 4);           \
      vd = static_cast<uint64_t>(vs2); \
    }                                  \
  } else {                             \
    UNREACHABLE();                     \
  }                                    \
  RVV_VI_LOOP_END                      \
  rvv_trace_vd();

#define RVV_VI_VIE_2_LOOP(signed)      \
  CHECK_EXT(2)                         \
  RVV_VI_GENERAL_LOOP_BASE             \
  RVV_VI_LOOP_MASK_SKIP()              \
  if (rvv_vsew() == E16) {             \
    if (signed) {                      \
      VI_VIE_PARAMS(16, 2);            \
      vd = static_cast<int16_t>(vs2);  \
    } else {                           \
      VI_VIE_UPARAMS(16, 2);           \
      vd = static_cast<uint16_t>(vs2); \
    }                                  \
  } else if (rvv_vsew() == E32) {      \
    if (signed) {                      \
      VI_VIE_PARAMS(32, 2);            \
      vd = static_cast<int32_t>(vs2);  \
    } else {                           \
      VI_VIE_UPARAMS(32, 2);           \
      vd = static_cast<uint32_t>(vs2); \
    }                                  \
  } else if (rvv_vsew() == E64) {      \
    if (signed) {                      \
      VI_VIE_PARAMS(64, 2);            \
      vd = static_cast<int64_t>(vs2);  \
    } else {                           \
      VI_VIE_UPARAMS(64, 2);           \
      vd = static_cast<uint64_t>(vs2); \
    }                                  \
  } else {                             \
    UNREACHABLE();                     \
  }                                    \
  RVV_VI_LOOP_END                      \
  rvv_trace_vd();
#endif

namespace v8 {
namespace internal {

DEFINE_LAZY_LEAKY_OBJECT_GETTER(Simulator::GlobalMonitor,
                                Simulator::GlobalMonitor::Get)

// Util functions.
inline bool HaveSameSign(int64_t a, int64_t b) { return ((a ^ b) >= 0); }

uint32_t get_fcsr_condition_bit(uint32_t cc) {
  if (cc == 0) {
    return 23;
  } else {
    return 24 + cc;
  }
}

// Generated by Assembler::break_()/stop(), ebreak code is passed as immediate
// field of a subsequent LUI instruction; otherwise returns -1
static inline int32_t get_ebreak_code(Instruction* instr) {
  DCHECK(instr->InstructionBits() == kBreakInstr);
  uint8_t* cur = reinterpret_cast<uint8_t*>(instr);
  Instruction* next_instr = reinterpret_cast<Instruction*>(cur + kInstrSize);
  if (next_instr->BaseOpcodeFieldRaw() == LUI)
    return (next_instr->Imm20UValue());
  else
    return -1;
}

// This macro provides a platform independent use of sscanf. The reason for
// SScanF not being implemented in a platform independent was through
// ::v8::internal::OS in the same way as SNPrintF is that the Windows C Run-Time
// Library does not provide vsscanf.
#define SScanF sscanf

// The RiscvDebugger class is used by the simulator while debugging simulated
// code.
class RiscvDebugger {
 public:
  explicit RiscvDebugger(Simulator* sim) : sim_(sim) {}

  void Debug();
  // Print all registers with a nice formatting.
  void PrintRegs(char name_prefix, int start_index, int end_index);
  void PrintAllRegs();
  void PrintAllRegsIncludingFPU();

  static const Instr kNopInstr = 0x0;

 private:
  Simulator* sim_;

  sreg_t GetRegisterValue(int regnum);
  int64_t GetFPURegisterValue(int regnum);
  float GetFPURegisterValueFloat(int regnum);
  double GetFPURegisterValueDouble(int regnum);
#ifdef CAN_USE_RVV_INSTRUCTIONS
  __int128_t GetVRegisterValue(int regnum);
#endif
  bool GetValue(const char* desc, sreg_t* value);
};

#define UNSUPPORTED()                                                  \
  v8::base::EmbeddedVector<char, 256> buffer;                          \
  disasm::NameConverter converter;                                     \
  disasm::Disassembler dasm(converter);                                \
  dasm.InstructionDecode(buffer, reinterpret_cast<uint8_t*>(&instr_)); \
  printf("Sim: Unsupported inst. Func:%s Line:%d PC:0x%" REGIx_FORMAT, \
         __FUNCTION__, __LINE__, get_pc());                            \
  PrintF(" %-44s\n", buffer.begin());                                  \
  base::OS::Abort();

sreg_t RiscvDebugger::GetRegisterValue(int regnum) {
  if (regnum == kNumSimuRegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_register(regnum);
  }
}

int64_t RiscvDebugger::GetFPURegisterValue(int regnum) {
  if (regnum == kNumFPURegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_fpu_register(regnum);
  }
}

float RiscvDebugger::GetFPURegisterValueFloat(int regnum) {
  if (regnum == kNumFPURegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_fpu_register_float(regnum);
  }
}

double RiscvDebugger::GetFPURegisterValueDouble(int regnum) {
  if (regnum == kNumFPURegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_fpu_register_double(regnum);
  }
}

#ifdef CAN_USE_RVV_INSTRUCTIONS
__int128_t RiscvDebugger::GetVRegisterValue(int regnum) {
  if (regnum == kNumVRegisters) {
    return sim_->get_pc();
  } else {
    return sim_->get_vregister(regnum);
  }
}
#endif

bool RiscvDebugger::GetValue(const char* desc, sreg_t* value) {
  int regnum = Registers::Number(desc);
  int fpuregnum = FPURegisters::Number(desc);

  if (regnum != kInvalidRegister) {
    *value = GetRegisterValue(regnum);
    return true;
  } else if (fpuregnum != kInvalidFPURegister) {
    *value = GetFPURegisterValue(fpuregnum);
    return true;
  } else if (strncmp(desc, "0x", 2) == 0) {
#if V8_TARGET_ARCH_RISCV64
    return SScanF(desc + 2, "%" SCNx64, reinterpret_cast<reg_t*>(value)) == 1;
#elif V8_TARGET_ARCH_RISCV32
    return SScanF(desc + 2, "%" SCNx32, reinterpret_cast<reg_t*>(value)) == 1;
#endif
  } else {
#if V8_TARGET_ARCH_RISCV64
    return SScanF(desc, "%" SCNu64, reinterpret_cast<reg_t*>(value)) == 1;
#elif V8_TARGET_ARCH_RISCV32
    return SScanF(desc, "%" SCNu32, reinterpret_cast<reg_t*>(value)) == 1;
#endif
  }
}

#define REG_INFO(name)                             \
  name, GetRegisterValue(Registers::Number(name)), \
      GetRegisterValue(Registers::Number(name))

void RiscvDebugger::PrintRegs(char name_prefix, int start_index,
                              int end_index) {
  base::EmbeddedVector<char, 10> name1, name2;
  DCHECK(name_prefix == 'a' || name_prefix == 't' || name_prefix == 's');
  DCHECK(start_index >= 0 && end_index <= 99);
  int num_registers = (end_index - start_index) + 1;
  for (int i = 0; i < num_registers / 2; i++) {
    SNPrintF(name1, "%c%d", name_prefix, start_index + 2 * i);
    SNPrintF(name2, "%c%d", name_prefix, start_index + 2 * i + 1);
    PrintF("%3s: 0x%016" REGIx_FORMAT "  %14" REGId_FORMAT
           " \t%3s: 0x%016" REGIx_FORMAT "  %14" REGId_FORMAT " \n",
           REG_INFO(name1.begin()), REG_INFO(name2.begin()));
  }
  if (num_registers % 2 == 1) {
    SNPrintF(name1, "%c%d", name_prefix, end_index);
    PrintF("%3s: 0x%016" REGIx_FORMAT "  %14" REGId_FORMAT " \n",
           REG_INFO(name1.begin()));
  }
}

void RiscvDebugger::PrintAllRegs() {
  PrintF("\n");
  // ra, sp, gp
  PrintF("%3s: 0x%016" REGIx_FORMAT " %14" REGId_FORMAT
         "\t%3s: 0x%016" REGIx_FORMAT " %14" REGId_FORMAT
         "\t%3s: 0x%016" REGIx_FORMAT " %14" REGId_FORMAT "\n",
         REG_INFO("ra"), REG_INFO("sp"), REG_INFO("gp"));

  // tp, fp, pc
  PrintF("%3s: 0x%016" REGIx_FORMAT " %14" REGId_FORMAT
         "\t%3s: 0x%016" REGIx_FORMAT " %14" REGId_FORMAT
         "\t%3s: 0x%016" REGIx_FORMAT " %14" REGId_FORMAT "\n",
         REG_INFO("tp"), REG_INFO("fp"), REG_INFO("pc"));

  // print register a0, .., a7
  PrintRegs('a', 0, 7);
  // print registers s1, ..., s11
  PrintRegs('s', 1, 11);
  // print registers t0, ..., t6
  PrintRegs('t', 0, 6);
}

#undef REG_INFO

void RiscvDebugger::PrintAllRegsIncludingFPU() {
#define FPU_REG_INFO(n) \
  FPURegisters::Name(n), GetFPURegisterValue(n), GetFPURegisterValueDouble(n)

  PrintAllRegs();

  PrintF("\n\n");
  // f0, f1, f2, ... f31.
  DCHECK_EQ(kNumFPURegisters % 2, 0);
  for (int i = 0; i < kNumFPURegisters; i += 2)
    PrintF("%3s: 0x%016" PRIx64 "  %16.4e \t%3s: 0x%016" PRIx64 "  %16.4e\n",
           FPU_REG_INFO(i), FPU_REG_INFO(i + 1));
#undef FPU_REG_INFO
}

void RiscvDebugger::Debug() {
  intptr_t last_pc = -1;
  bool done = false;

#define COMMAND_SIZE 63
#define ARG_SIZE 255

#define STR(a) #a
#define XSTR(a) STR(a)

  char cmd[COMMAND_SIZE + 1];
  char arg1[ARG_SIZE + 1];
  char arg2[ARG_SIZE + 1];
  char* argv[3] = {cmd, arg1, arg2};

  // Make sure to have a proper terminating character if reaching the limit.
  cmd[COMMAND_SIZE] = 0;
  arg1[ARG_SIZE] = 0;
  arg2[ARG_SIZE] = 0;

  while (!done && (sim_->get_pc() != Simulator::end_sim_pc)) {
    if (last_pc != sim_->get_pc()) {
      disasm::NameConverter converter;
      disasm::Disassembler dasm(converter);
      // Use a reasonably large buffer.
      v8::base::EmbeddedVector<char, 256> buffer;
      const char* name = sim_->builtins_.Lookup((Address)sim_->get_pc());
      if (name != nullptr) {
        PrintF("Call builtin:  %s\n", name);
      }
      dasm.InstructionDecode(buffer,
                             reinterpret_cast<uint8_t*>(sim_->get_pc()));
      PrintF("  0x%016" REGIx_FORMAT "   %s\n", sim_->get_pc(), buffer.begin());
      last_pc = sim_->get_pc();
    }
    char* line = ReadLine("sim> ");
    if (line == nullptr) {
      break;
    } else {
      char* last_input = sim_->last_debugger_input();
      if (strcmp(line, "\n") == 0 && last_input != nullptr) {
        line = last_input;
      } else {
        // Ownership is transferred to sim_;
        sim_->set_last_debugger_input(line);
      }
      // Use sscanf to parse the individual parts of the command line. At the
      // moment no command expects more than two parameters.
      int argc = SScanF(
            line,
            "%" XSTR(COMMAND_SIZE) "s "
            "%" XSTR(ARG_SIZE) "s "
            "%" XSTR(ARG_SIZE) "s",
            cmd, arg1, arg2);
      if ((strcmp(cmd, "si") == 0) || (strcmp(cmd, "stepi") == 0)) {
        Instruction* instr = reinterpret_cast<Instruction*>(sim_->get_pc());
        if (!(instr->IsTrap()) ||
            instr->InstructionBits() == rtCallRedirInstr) {
          sim_->icount_++;
          sim_->InstructionDecode(
              reinterpret_cast<Instruction*>(sim_->get_pc()));
        } else {
          // Allow si to jump over generated breakpoints.
          PrintF("/!\\ Jumping over generated breakpoint.\n");
          sim_->set_pc(sim_->get_pc() + kInstrSize);
        }
      } else if ((strcmp(cmd, "c") == 0) || (strcmp(cmd, "cont") == 0)) {
        // Execute the one instruction we broke at with breakpoints disabled.
        sim_->InstructionDecode(reinterpret_cast<Instruction*>(sim_->get_pc()));
        // Leave the debugger shell.
        done = true;
      } else if ((strcmp(cmd, "p") == 0) || (strcmp(cmd, "print") == 0)) {
        if (argc == 2) {
          sreg_t value;
          int64_t fvalue;
          double dvalue;
          if (strcmp(arg1, "all") == 0) {
            PrintAllRegs();
          } else if (strcmp(arg1, "allf") == 0) {
            PrintAllRegsIncludingFPU();
          } else {
            int regnum = Registers::Number(arg1);
            int fpuregnum = FPURegisters::Number(arg1);
#ifdef CAN_USE_RVV_INSTRUCTIONS
            int vregnum = VRegisters::Number(arg1);
#endif
            if (regnum != kInvalidRegister) {
              value = GetRegisterValue(regnum);
              PrintF("%s: 0x%08" REGIx_FORMAT "  %" REGId_FORMAT "  \n", arg1,
                     value, value);
            } else if (fpuregnum != kInvalidFPURegister) {
              fvalue = GetFPURegisterValue(fpuregnum);
              dvalue = GetFPURegisterValueDouble(fpuregnum);
              PrintF("%3s: 0x%016" PRIx64 "  %16.4e\n",
                     FPURegisters::Name(fpuregnum), fvalue, dvalue);
#ifdef CAN_USE_RVV_INSTRUCTIONS
            } else if (vregnum != kInvalidVRegister) {
              __int128_t v = GetVRegisterValue(vregnum);
              PrintF("\t%s:0x%016" PRIx64 "%016" PRIx64 "\n",
                     VRegisters::Name(vregnum), (uint64_t)(v >> 64),
                     (uint64_t)v);
#endif
            } else {
              PrintF("%s unrecognized\n", arg1);
            }
          }
        } else {
          if (argc == 3) {
            if (strcmp(arg2, "single") == 0) {
              int64_t value;
              float fvalue;
              int fpuregnum = FPURegisters::Number(arg1);

              if (fpuregnum != kInvalidFPURegister) {
                value = GetFPURegisterValue(fpuregnum);
                value &= 0xFFFFFFFFUL;
                fvalue = GetFPURegisterValueFloat(fpuregnum);
                PrintF("%s: 0x%08" PRIx64 "  %11.4e\n", arg1, value, fvalue);
              } else {
                PrintF("%s unrecognized\n", arg1);
              }
            } else {
              PrintF("print <fpu register> single\n");
            }
          } else {
            PrintF("print <register> or print <fpu register> single\n");
          }
        }
      } else if ((strcmp(cmd, "po") == 0) ||
                 (strcmp(cmd, "printobject") == 0)) {
        if (argc == 2) {
          sreg_t value;
          StdoutStream os;
          if (GetValue(arg1, &value)) {
            Tagged<Object> obj(value);
            os << arg1 << ": \n";
#ifdef DEBUG
            Print(obj, os);
            os << "\n";
#else
            os << Brief(obj) << "\n";
#endif
          } else {
            os << arg1 << " unrecognized\n";
          }
        } else {
          PrintF("printobject <value>\n");
        }
      } else if (strcmp(cmd, "stack") == 0 || strcmp(cmd, "mem") == 0) {
        sreg_t* cur = nullptr;
        sreg_t* end = nullptr;
        int next_arg = 1;

        if (strcmp(cmd, "stack") == 0) {
          cur = reinterpret_cast<sreg_t*>(sim_->get_register(Simulator::sp));
        } else {  // Command "mem".
          if (argc < 2) {
            PrintF("Need to specify <address> to mem command\n");
            continue;
          }
          sreg_t value;
          if (!GetValue(arg1, &value)) {
            PrintF("%s unrecognized\n", arg1);
            continue;
          }
          cur = reinterpret_cast<sreg_t*>(value);
          next_arg++;
        }

        sreg_t words;
        if (argc == next_arg) {
          words = 10;
        } else {
          if (!GetValue(argv[next_arg], &words)) {
            words = 10;
          }
        }
        end = cur + words;

        while (cur < end) {
          PrintF("  0x%012" PRIxPTR " :  0x%016" REGIx_FORMAT
                 "  %14" REGId_FORMAT " ",
                 reinterpret_cast<intptr_t>(cur), *cur, *cur);
          // Tagged<Object> obj(*cur);
          // Heap* current_heap = sim_->isolate_->heap();
          // if (IsSmi(obj) ||
          //     IsValidHeapObject(current_heap, Cast<HeapObject>(obj))) {
          //   PrintF(" (");
          //   if (IsSmi(obj)) {
          //     PrintF("smi %d", Smi::ToInt(obj));
          //   }
          //   PrintF(")");
          // }
          PrintF("\n");
          cur++;
        }
      } else if (strcmp(cmd, "memhex") == 0) {
        sreg_t* cur = nullptr;
        sreg_t* end = nullptr;
        int next_arg = 1;
        if (argc < 2) {
          PrintF("Need to specify <address> to memhex command\n");
          continue;
        }
        sreg_t value;
        if (!GetValue(arg1, &value)) {
          PrintF("%s unrecognized\n", arg1);
          continue;
        }
        cur = reinterpret_cast<sreg_t*>(value);
        next_arg++;

        sreg_t words;
        if (argc == next_arg) {
          words = 10;
        } else {
          if (!GetValue(argv[next_arg], &words)) {
            words = 10;
          }
        }
        end = cur + words;

        while (cur < end) {
          PrintF("  0x%012" PRIxPTR " :  0x%016" REGIx_FORMAT
                 "  %14" REGId_FORMAT " ",
                 reinterpret_cast<intptr_t>(cur), *cur, *cur);
          PrintF("\n");
          cur++;
        }
      } else if ((strcmp(cmd, "watch") == 0)) {
        if (argc < 2) {
          PrintF("Need to specify <address> to mem command\n");
          continue;
        }
        sreg_t value;
        if (!GetValue(arg1, &value)) {
          PrintF("%s unrecognized\n", arg1);
          continue;
        }
        sim_->watch_address_ = reinterpret_cast<sreg_t*>(value);
        sim_->watch_value_ = *(sim_->watch_address_);
      } else if ((strcmp(cmd, "disasm") == 0) || (strcmp(cmd, "dpc") == 0) ||
                 (strcmp(cmd, "di") == 0)) {
        disasm::NameConverter converter;
        disasm::Disassembler dasm(converter);
        // Use a reasonably large buffer.
        v8::base::EmbeddedVector<char, 256> buffer;

        uint8_t* cur = nullptr;
        uint8_t* end = nullptr;

        if (argc == 1) {
          cur = reinterpret_cast<uint8_t*>(sim_->get_pc());
          end = cur + (10 * kInstrSize);
        } else if (argc == 2) {
          int regnum = Registers::Number(arg1);
          if (regnum != kInvalidRegister || strncmp(arg1, "0x", 2) == 0) {
            // The argument is an address or a register name.
            sreg_t value;
            if (GetValue(arg1, &value)) {
              cur = reinterpret_cast<uint8_t*>(value);
              // Disassemble 10 instructions at <arg1>.
              end = cur + (10 * kInstrSize);
            }
          } else {
            // The argument is the number of instructions.
            sreg_t value;
            if (GetValue(arg1, &value)) {
              cur = reinterpret_cast<uint8_t*>(sim_->get_pc());
              // Disassemble <arg1> instructions.
              end = cur + (value * kInstrSize);
            }
          }
        } else {
          sreg_t value1;
          sreg_t value2;
          if (GetValue(arg1, &value1) && GetValue(arg2, &value2)) {
            cur = reinterpret_cast<uint8_t*>(value1);
            end = cur + (value2 * kInstrSize);
          }
        }

        while (cur < end) {
          dasm.InstructionDecode(buffer, cur);
          PrintF("  0x%08" PRIxPTR "   %s\n", reinterpret_cast<intptr_t>(cur),
                 buffer.begin());
          cur += kInstrSize;
        }
      } else if (strcmp(cmd, "gdb") == 0) {
        PrintF("relinquishing control to gdb\n");
        v8::base::OS::DebugBreak();
        PrintF("regaining control from gdb\n");
      } else if (strcmp(cmd, "trace") == 0) {
        PrintF("enable trace sim\n");
        v8_flags.trace_sim = true;
      } else if (strcmp(cmd, "break") == 0 || strcmp(cmd, "b") == 0 ||
                 strcmp(cmd, "tbreak") == 0) {
        bool is_tbreak = strcmp(cmd, "tbreak") == 0;
        if (argc == 2) {
          sreg_t value;
          if (GetValue(arg1, &value)) {
            sim_->SetBreakpoint(reinterpret_cast<Instruction*>(value),
                                is_tbreak);
          } else {
            PrintF("%s unrecognized\n", arg1);
          }
        } else {
          sim_->ListBreakpoints();
          PrintF("Use `break <address>` to set or disable a breakpoint\n");
          PrintF(
              "Use `tbreak <address>` to set or disable a temporary "
              "breakpoint\n");
        }
      } else if (strcmp(cmd, "flags") == 0) {
        PrintF("No flags on RISC-V !\n");
      } else if (strcmp(cmd, "stop") == 0) {
        sreg_t value;
        if (argc == 3) {
          // Print information about all/the specified breakpoint(s).
          if (strcmp(arg1, "info") == 0) {
            if (strcmp(arg2, "all") == 0) {
              PrintF("Stop information:\n");
              for (uint32_t i = kMaxWatchpointCode + 1; i <= kMaxStopCode;
                   i++) {
                sim_->PrintStopInfo(i);
              }
            } else if (GetValue(arg2, &value)) {
              sim_->PrintStopInfo(value);
            } else {
              PrintF("Unrecognized argument.\n");
            }
          } else if (strcmp(arg1, "enable") == 0) {
            // Enable all/the specified breakpoint(s).
            if (strcmp(arg2, "all") == 0) {
              for (uint32_t i = kMaxWatchpointCode + 1; i <= kMaxStopCode;
                   i++) {
                sim_->EnableStop(i);
              }
            } else if (GetValue(arg2, &value)) {
              sim_->EnableStop(value);
            } else {
              PrintF("Unrecognized argument.\n");
            }
          } else if (strcmp(arg1, "disable") == 0) {
            // Disable all/the specified breakpoint(s).
            if (strcmp(arg2, "all") == 0) {
              for (uint32_t i = kMaxWatchpointCode + 1; i <= kMaxStopCode;
                   i++) {
                sim_->DisableStop(i);
              }
            } else if (GetValue(arg2, &value)) {
              sim_->DisableStop(value);
            } else {
              PrintF("Unrecognized argument.\n");
            }
          }
        } else {
          PrintF("Wrong usage. Use help command for more information.\n");
        }
      } else if ((strcmp(cmd, "stat") == 0) || (strcmp(cmd, "st") == 0)) {
        // Print registers and disassemble.
        PrintAllRegs();
        PrintF("\n");

        disasm::NameConverter converter;
        disasm::Disassembler dasm(converter);
        // Use a reasonably large buffer.
        v8::base::EmbeddedVector<char, 256> buffer;

        uint8_t* cur = nullptr;
        uint8_t* end = nullptr;

        if (argc == 1) {
          cur = reinterpret_cast<uint8_t*>(sim_->get_pc());
          end = cur + (10 * kInstrSize);
        } else if (argc == 2) {
          sreg_t value;
          if (GetValue(arg1, &value)) {
            cur = reinterpret_cast<uint8_t*>(value);
            // no length parameter passed, assume 10 instructions
            end = cur + (10 * kInstrSize);
          }
        } else {
          sreg_t value1;
          sreg_t value2;
          if (GetValue(arg1, &value1) && GetValue(arg2, &value2)) {
            cur = reinterpret_cast<uint8_t*>(value1);
            end = cur + (value2 * kInstrSize);
          }
        }

        while (cur < end) {
          dasm.InstructionDecode(buffer, cur);
          PrintF("  0x%08" PRIxPTR "   %s\n", reinterpret_cast<intptr_t>(cur),
                 buffer.begin());
          cur += kInstrSize;
        }
      } else if ((strcmp(cmd, "h") == 0) || (strcmp(cmd, "help") == 0)) {
        PrintF("cont (alias 'c')\n");
        PrintF("  Continue execution\n");
        PrintF("stepi (alias 'si')\n");
        PrintF("  Step one instruction\n");
        PrintF("print (alias 'p')\n");
        PrintF("  print <register>\n");
        PrintF("  Print register content\n");
        PrintF("  Use register name 'all' to print all GPRs\n");
        PrintF("  Use register name 'allf' to print all GPRs and FPRs\n");
        PrintF("printobject (alias 'po')\n");
        PrintF("  printobject <register>\n");
        PrintF("  Print an object from a register\n");
        PrintF("stack\n");
        PrintF("  stack [<words>]\n");
        PrintF("  Dump stack content, default dump 10 words)\n");
        PrintF("mem\n");
        PrintF("  mem <address> [<words>]\n");
        PrintF("  Dump memory content, default dump 10 words)\n");
        PrintF("watch\n");
        PrintF("  watch <address> \n");
        PrintF("  watch memory content.)\n");
        PrintF("flags\n");
        PrintF("  print flags\n");
        PrintF("disasm (alias 'di')\n");
        PrintF("  disasm [<instructions>]\n");
        PrintF("  disasm [<address/register>] (e.g., disasm pc) \n");
        PrintF("  disasm [[<address/register>] <instructions>]\n");
        PrintF("  Disassemble code, default is 10 instructions\n");
        PrintF("  from pc\n");
        PrintF("gdb \n");
        PrintF("  Return to gdb if the simulator was started with gdb\n");
        PrintF("break (alias 'b')\n");
        PrintF("  break : list all breakpoints\n");
        PrintF("  break <address> : set / enable / disable a breakpoint.\n");
        PrintF("tbreak\n");
        PrintF("  tbreak : list all breakpoints\n");
        PrintF(
            "  tbreak <address> : set / enable / disable a temporary "
            "breakpoint.\n");
        PrintF("  Set a breakpoint enabled only for one stop. \n");
        PrintF("stop feature:\n");
        PrintF("  Description:\n");
        PrintF("    Stops are debug instructions inserted by\n");
        PrintF("    the Assembler::stop() function.\n");
        PrintF("    When hitting a stop, the Simulator will\n");
        PrintF("    stop and give control to the Debugger.\n");
        PrintF("    All stop codes are watched:\n");
        PrintF("    - They can be enabled / disabled: the Simulator\n");
        PrintF("       will / won't stop when hitting them.\n");
        PrintF("    - The Simulator keeps track of how many times they \n");
        PrintF("      are met. (See the info command.) Going over a\n");
        PrintF("      disabled stop still increases its counter. \n");
        PrintF("  Commands:\n");
        PrintF("    stop info all/<code> : print infos about number <code>\n");
        PrintF("      or all stop(s).\n");
        PrintF("    stop enable/disable all/<code> : enables / disables\n");
        PrintF("      all or number <code> stop(s)\n");
      } else {
        PrintF("Unknown command: %s\n", cmd);
      }
    }
  }

#undef COMMAND_SIZE
#undef ARG_SIZE

#undef STR
#undef XSTR
}

void Simulator::SetBreakpoint(Instruction* location, bool is_tbreak) {
  for (unsigned i = 0; i < breakpoints_.size(); i++) {
    if (breakpoints_.at(i).location == location) {
      if (breakpoints_.at(i).is_tbreak != is_tbreak) {
        PrintF("Change breakpoint at %p to %s breakpoint\n",
               reinterpret_cast<void*>(location),
               is_tbreak ? "temporary" : "regular");
        breakpoints_.at(i).is_tbreak = is_tbreak;
        return;
      }
      PrintF("Existing breakpoint at %p was %s\n",
             reinterpret_cast<void*>(location),
             breakpoints_.at(i).enabled ? "disabled" : "enabled");
      breakpoints_.at(i).enabled = !breakpoints_.at(i).enabled;
      return;
    }
  }
  Breakpoint new_breakpoint = {location, true, is_tbreak};
  breakpoints_.push_back(new_breakpoint);
  PrintF("Set a %sbreakpoint at %p\n", is_tbreak ? "temporary " : "",
         reinterpret_cast<void*>(location));
}

void Simulator::ListBreakpoints() {
  PrintF("Breakpoints:\n");
  for (unsigned i = 0; i < breakpoints_.size(); i++) {
    PrintF("%p  : %s %s\n",
           reinterpret_cast<void*>(breakpoints_.at(i).location),
           breakpoints_.at(i).enabled ? "enabled" : "disabled",
           breakpoints_.at(i).is_tbreak ? ": temporary" : "");
  }
}

void Simulator::CheckBreakpoints() {
  bool hit_a_breakpoint = false;
  bool is_tbreak = false;
  Instruction* pc_ = reinterpret_cast<Instruction*>(get_pc());
  for (unsigned i = 0; i < breakpoints_.size(); i++) {
    if ((breakpoints_.at(i).location == pc_) && breakpoints_.at(i).enabled) {
      hit_a_breakpoint = true;
      if (breakpoints_.at(i).is_tbreak) {
        // Disable a temporary breakpoint.
        is_tbreak = true;
        breakpoints_.at(i).enabled = false;
      }
      break;
    }
  }
  if (hit_a_breakpoint) {
    PrintF("Hit %sa breakpoint at %p.\n", is_tbreak ? "and disabled " : "",
           reinterpret_cast<void*>(pc_));
    RiscvDebugger dbg(this);
    dbg.Debug();
  }
}

bool Simulator::ICacheMatch(void* one, void* two) {
  DCHECK_EQ(reinterpret_cast<intptr_t>(one) & CachePage::kPageMask, 0);
  DCHECK_EQ(reinterpret_cast<intptr_t>(two) & CachePage::kPageMask, 0);
  return one == two;
}

static uint32_t ICacheHash(void* key) {
  return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(key)) >> 2;
}

static bool AllOnOnePage(uintptr_t start, size_t size) {
  intptr_t start_page = (start & ~CachePage::kPageMask);
  intptr_t end_page = ((start + size) & ~CachePage::kPageMask);
  return start_page == end_page;
}

void Simulator::set_last_debugger_input(char* input) {
  DeleteArray(last_debugger_input_);
  last_debugger_input_ = input;
}

void Simulator::SetRedirectInstruction(Instruction* instruction) {
  instruction->SetInstructionBits(rtCallRedirInstr);
}

void Simulator::FlushICache(base::CustomMatcherHashMap* i_cache,
                            void* start_addr, size_t size) {
  int64_t start = reinterpret_cast<int64_t>(start_addr);
  int64_t intra_line = (start & CachePage::kLineMask);
  start -= intra_line;
  size += intra_line;
  size = ((size - 1) | CachePage::kLineMask) + 1;
  int offset = (start & CachePage::kPageMask);
  while (!AllOnOnePage(start, size - 1)) {
    int bytes_to_flush = CachePage::kPageSize - offset;
    FlushOnePage(i_cache, start, bytes_to_flush);
    start += bytes_to_flush;
    size -= bytes_to_flush;
    DCHECK_EQ((int64_t)0, start & CachePage::kPageMask);
    offset = 0;
  }
  if (size != 0) {
    FlushOnePage(i_cache, start, size);
  }
}

CachePage* Simulator::GetCachePage(base::CustomMatcherHashMap* i_cache,
                                   void* page) {
  base::HashMap::Entry* entry = i_cache->LookupOrInsert(page, ICacheHash(page));
  if (entry->value == nullptr) {
    CachePage* new_page = new CachePage();
    entry->value = new_page;
  }
  return reinterpret_cast<CachePage*>(entry->value);
}

// Flush from start up to and not including start + size.
void Simulator::FlushOnePage(base::CustomMatcherHashMap* i_cache,
                             intptr_t start, size_t size) {
  DCHECK_LE(size, CachePage::kPageSize);
  DCHECK(AllOnOnePage(start, size - 1));
  DCHECK_EQ(start & CachePage::kLineMask, 0);
  DCHECK_EQ(size & CachePage::kLineMask, 0);
  void* page = reinterpret_cast<void*>(start & (~CachePage::kPageMask));
  int offset = (start & CachePage::kPageMask);
  CachePage* cache_page = GetCachePage(i_cache, page);
  char* valid_bytemap = cache_page->ValidityByte(offset);
  memset(valid_bytemap, CachePage::LINE_INVALID, size >> CachePage::kLineShift);
}

void Simulator::CheckICache(base::CustomMatcherHashMap* i_cache,
                            Instruction* instr) {
  sreg_t address = reinterpret_cast<sreg_t>(instr);
  void* page = reinterpret_cast<void*>(address & (~CachePage::kPageMask));
  void* line = reinterpret_cast<void*>(address & (~CachePage::kLineMask));
  int offset = (address & CachePage::kPageMask);
  CachePage* cache_page = GetCachePage(i_cache, page);
  char* cache_valid_byte = cache_page->ValidityByte(offset);
  bool cache_hit = (*cache_valid_byte == CachePage::LINE_VALID);
  char* cached_line = cache_page->CachedData(offset & ~CachePage::kLineMask);
  if (cache_hit) {
    // Check that the data in memory matches the contents of the I-cache.
    CHECK_EQ(0, memcmp(reinterpret_cast<void*>(instr),
                       cache_page->CachedData(offset), kInstrSize));
  } else {
    // Cache miss.  Load memory into the cache.
    memcpy(cached_line, line, CachePage::kLineLength);
    *cache_valid_byte = CachePage::LINE_VALID;
  }
}

Simulator::Simulator(Isolate* isolate) : isolate_(isolate), builtins_(isolate) {
  // Set up simulator support first. Some of this information is needed to
  // setup the architecture state.
  // Allocate and setup the simulator stack.
  size_t stack_size = AllocatedStackSize();

  stack_ = reinterpret_cast<uintptr_t>(new uint8_t[stack_size]());
  stack_limit_ = stack_ + kStackProtectionSize;
  pc_modified_ = false;
  icount_ = 0;
  break_count_ = 0;
  // Reset debug helpers.
  breakpoints_.clear();
  // TODO(riscv): 'next' command
  // break_on_next_ = false;

  // Set up architecture state.
  // All registers are initialized to zero to start with.
  for (int i = 0; i < kNumSimuRegisters; i++) {
    registers_[i] = 0;
  }

  for (int i = 0; i < kNumFPURegisters; i++) {
    FPUregisters_[i] = 0;
  }

  FCSR_ = 0;

  // The sp is initialized to point to the bottom (high address) of the
  // allocated stack area. To be safe in potential stack underflows we leave
  // some buffer below.
  registers_[sp] = stack_ + stack_size - kStackProtectionSize;
  // The ra and pc are initialized to a known bad value that will cause an
  // access violation if the simulator ever tries to execute it.
  registers_[pc] = bad_ra;
  registers_[ra] = bad_ra;

  last_debugger_input_ = nullptr;
#ifdef CAN_USE_RVV_INSTRUCTIONS
  for (int i = 0; i < kNumVRegisters; ++i) {
    Vregister_[i] = 0;
  }
  vxrm_ = 0;
  vstart_ = 0;
  vxsat_ = 0;
  vxrm_ = 0;
  vcsr_ = 0;
  vtype_ = 0;
  vl_ = 0;
  vlenb_ = 0;
#endif
}

Simulator::~Simulator() {
  GlobalMonitor::Get()->RemoveLinkedAddress(&global_monitor_thread_);
  delete[] reinterpret_cast<uint8_t*>(stack_);
}

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

// Sets the register in the architecture state. It will also deal with
// updating Simulator internal state for special registers such as PC.
void Simulator::set_register(int reg, sreg_t value) {
  DCHECK((reg >= 0) && (reg < kNumSimuRegisters));
  if (reg == pc) {
    pc_modified_ = true;
  }

  // Zero register always holds 0.
  registers_[reg] = (reg == 0) ? 0 : value;
}

void Simulator::set_fpu_register(int fpureg, int64_t value) {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  FPUregisters_[fpureg] = value;
}

void Simulator::set_fpu_register_word(int fpureg, int32_t value) {
  // Set ONLY lower 32-bits, leaving upper bits untouched.
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  int32_t* pword;
  if (kArchEndian == kLittle) {
    pword = reinterpret_cast<int32_t*>(&FPUregisters_[fpureg]);
  } else {
    pword = reinterpret_cast<int32_t*>(&FPUregisters_[fpureg]) + 1;
  }
  *pword = value;
}

void Simulator::set_fpu_register_hi_word(int fpureg, int32_t value) {
  // Set ONLY upper 32-bits, leaving lower bits untouched.
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  int32_t* phiword;
  if (kArchEndian == kLittle) {
    phiword = (reinterpret_cast<int32_t*>(&FPUregisters_[fpureg])) + 1;
  } else {
    phiword = reinterpret_cast<int32_t*>(&FPUregisters_[fpureg]);
  }
  *phiword = value;
}

void Simulator::set_fpu_register_float(int fpureg, float value) {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  FPUregisters_[fpureg] = box_float(value);
}

void Simulator::set_fpu_register_float(int fpureg, Float32 value) {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  Float64 t = Float64::FromBits(box_float(value.get_bits()));
  memcpy(&FPUregisters_[fpureg], &t, 8);
}

void Simulator::set_fpu_register_double(int fpureg, double value) {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  FPUregisters_[fpureg] = base::bit_cast<int64_t>(value);
}

void Simulator::set_fpu_register_double(int fpureg, Float64 value) {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  memcpy(&FPUregisters_[fpureg], &value, 8);
}
// Get the register from the architecture state. This function does handle
// the special case of accessing the PC register.
sreg_t Simulator::get_register(int reg) const {
  DCHECK((reg >= 0) && (reg < kNumSimuRegisters));
  if (reg == 0)
    return 0;
  else
    return registers_[reg] + ((reg == pc) ? Instruction::kPCReadOffset : 0);
}

double Simulator::get_double_from_register_pair(int reg) {
  // TODO(plind): bad ABI stuff, refactor or remove.
  DCHECK((reg >= 0) && (reg < kNumSimuRegisters) && ((reg % 2) == 0));

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
  if (!is_boxed_float(FPUregisters_[fpureg])) {
    return std::numeric_limits<float>::quiet_NaN();
  }
  return Float32::FromBits(FPUregisters_[fpureg] & 0xFFFF'FFFF).get_scalar();
}

// Fix NaN boxing error according to
// https://github.com/riscv/riscv-isa-manual/blob/main/src/d-st-ext.adoc#nan-boxing-of-narrower-values"
Float32 Simulator::get_fpu_register_Float32(int fpureg,
                                            bool check_nanbox) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  if (check_nanbox && !is_boxed_float(FPUregisters_[fpureg])) {
    std::cout << std::hex << FPUregisters_[fpureg] << std::endl;
    return Float32::FromBits(0x7fc00000);
  }
  return Float32::FromBits(FPUregisters_[fpureg] & 0xFFFF'FFFF);
}

double Simulator::get_fpu_register_double(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return base::bit_cast<double>(FPUregisters_[fpureg]);
}

Float64 Simulator::get_fpu_register_Float64(int fpureg) const {
  DCHECK((fpureg >= 0) && (fpureg < kNumFPURegisters));
  return Float64::FromBits(FPUregisters_[fpureg]);
}

#ifdef CAN_USE_RVV_INSTRUCTIONS
__int128_t Simulator::get_vregister(int vreg) const {
  DCHECK((vreg >= 0) && (vreg < kNumVRegisters));
  return Vregister_[vreg];
}
#endif

// Runtime FP routines take up to two double arguments and zero
// or one integer arguments. All are constructed here,
// from fa0, fa1, and a0.
void Simulator::GetFpArgs(double* x, double* y, int32_t* z) {
  *x = get_fpu_register_double(fa0);
  *y = get_fpu_register_double(fa1);
  *z = static_cast<int32_t>(get_register(a0));
}

// The return value is in fa0.
void Simulator::SetFpResult(const double& result) {
  set_fpu_register_double(fa0, result);
}

// helper functions to read/write/set/clear CRC values/bits
uint32_t Simulator::read_csr_value(uint32_t csr) {
  switch (csr) {
    case csr_fflags:  // Floating-Point Accrued Exceptions (RW)
      return (FCSR_ & kFcsrFlagsMask);
    case csr_frm:  // Floating-Point Dynamic Rounding Mode (RW)
      return (FCSR_ & kFcsrFrmMask) >> kFcsrFrmShift;
    case csr_fcsr:  // Floating-Point Control and Status Register (RW)
      return (FCSR_ & kFcsrMask);
    default:
      UNIMPLEMENTED();
  }
}

uint32_t Simulator::get_dynamic_rounding_mode() {
  return read_csr_value(csr_frm);
}

void Simulator::write_csr_value(uint32_t csr, reg_t val) {
  uint32_t value = (uint32_t)val;
  switch (csr) {
    case csr_fflags:  // Floating-Point Accrued Exceptions (RW)
      DCHECK(value <= ((1 << kFcsrFlagsBits) - 1));
      FCSR_ = (FCSR_ & (~kFcsrFlagsMask)) | value;
      break;
    case csr_frm:  // Floating-Point Dynamic Rounding Mode (RW)
      DCHECK(value <= ((1 << kFcsrFrmBits) - 1));
      FCSR_ = (FCSR_ & (~kFcsrFrmMask)) | (value << kFcsrFrmShift);
      break;
    case csr_fcsr:  // Floating-Point Control and Status Register (RW)
      DCHECK(value <= ((1 << kFcsrBits) - 1));
      FCSR_ = (FCSR_ & (~kFcsrMask)) | value;
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::set_csr_bits(uint32_t csr, reg_t val) {
  uint32_t value = (uint32_t)val;
  switch (csr) {
    case csr_fflags:  // Floating-Point Accrued Exceptions (RW)
      DCHECK(value <= ((1 << kFcsrFlagsBits) - 1));
      FCSR_ = FCSR_ | value;
      break;
    case csr_frm:  // Floating-Point Dynamic Rounding Mode (RW)
      DCHECK(value <= ((1 << kFcsrFrmBits) - 1));
      FCSR_ = FCSR_ | (value << kFcsrFrmShift);
      break;
    case csr_fcsr:  // Floating-Point Control and Status Register (RW)
      DCHECK(value <= ((1 << kFcsrBits) - 1));
      FCSR_ = FCSR_ | value;
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::clear_csr_bits(uint32_t csr, reg_t val) {
  uint32_t value = (uint32_t)val;
  switch (csr) {
    case csr_fflags:  // Floating-Point Accrued Exceptions (RW)
      DCHECK(value <= ((1 << kFcsrFlagsBits) - 1));
      FCSR_ = FCSR_ & (~value);
      break;
    case csr_frm:  // Floating-Point Dynamic Rounding Mode (RW)
      DCHECK(value <= ((1 << kFcsrFrmBits) - 1));
      FCSR_ = FCSR_ & (~(value << kFcsrFrmShift));
      break;
    case csr_fcsr:  // Floating-Point Control and Status Register (RW)
      DCHECK(value <= ((1 << kFcsrBits) - 1));
      FCSR_ = FCSR_ & (~value);
      break;
    default:
      UNIMPLEMENTED();
  }
}

bool Simulator::test_fflags_bits(uint32_t mask) {
  return (FCSR_ & kFcsrFlagsMask & mask) != 0;
}

template <typename T>
T Simulator::FMaxMinHelper(T a, T b, MaxMinKind kind) {
  // set invalid bit for signaling nan
  if ((a == std::numeric_limits<T>::signaling_NaN()) ||
      (b == std::numeric_limits<T>::signaling_NaN())) {
    set_csr_bits(csr_fflags, kInvalidOperation);
  }

  T result = 0;
  if (std::isnan(a) && std::isnan(b)) {
    result = std::numeric_limits<float>::quiet_NaN();
  } else if (std::isnan(a)) {
    result = b;
  } else if (std::isnan(b)) {
    result = a;
  } else if (b == a) {  // Handle -0.0 == 0.0 case.
    if (kind == MaxMinKind::kMax) {
      result = std::signbit(b) ? a : b;
    } else {
      result = std::signbit(b) ? b : a;
    }
  } else {
    result = (kind == MaxMinKind::kMax) ? fmax(a, b) : fmin(a, b);
  }

  return result;
}

// Raw access to the PC register.
void Simulator::set_pc(sreg_t value) {
  pc_modified_ = true;
  registers_[pc] = value;
  DCHECK(has_bad_pc() || ((value % kInstrSize) == 0) ||
         ((value % kShortInstrSize) == 0));
}

bool Simulator::has_bad_pc() const {
  return ((registers_[pc] == bad_ra) || (registers_[pc] == end_sim_pc));
}

// Raw access to the PC register without the special adjustment when reading.
sreg_t Simulator::get_pc() const { return registers_[pc]; }

// The RISC-V spec leaves it open to the implementation on how to handle
// unaligned reads and writes. For now, we simply disallow unaligned reads but
// at some point, we may want to implement some other behavior.

// TODO(plind): refactor this messy debug code when we do unaligned access.
void Simulator::DieOrDebug() {
  if (v8_flags.riscv_trap_to_simulator_debugger) {
    RiscvDebugger dbg(this);
    dbg.Debug();
  } else {
    base::OS::Abort();
  }
}

#if V8_TARGET_ARCH_RISCV64
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
        SNPrintF(trace_buf_,
                 "%016" REGIx_FORMAT "    (%" PRId64 ")    int32:%" PRId32
                 " uint32:%" PRIu32,
                 v.fmt_int64, icount_, v.fmt_int32[0], v.fmt_int32[0]);
        break;
      case DWORD:
        SNPrintF(trace_buf_,
                 "%016" REGIx_FORMAT "    (%" PRId64 ")    int64:%" REGId_FORMAT
                 " uint64:%" PRIu64,
                 value, icount_, value, value);
        break;
      case FLOAT:
        SNPrintF(trace_buf_, "%016" REGIx_FORMAT "    (%" PRId64 ")    flt:%e",
                 v.fmt_int64, icount_, v.fmt_float[0]);
        break;
      case DOUBLE:
        SNPrintF(trace_buf_, "%016" REGIx_FORMAT "    (%" PRId64 ")    dbl:%e",
                 v.fmt_int64, icount_, v.fmt_double);
        break;
      default:
        UNREACHABLE();
    }
  }
}

#elif V8_TARGET_ARCH_RISCV32
template <typename T>
void Simulator::TraceRegWr(T value, TraceType t) {
  if (v8_flags.trace_sim) {
    union {
      int32_t fmt_int32;
      float fmt_float;
      double fmt_double;
    } v;
    if (t != DOUBLE) {
      v.fmt_int32 = value;
    } else {
      DCHECK_EQ(sizeof(T), 8);
      v.fmt_double = value;
    }
    switch (t) {
      case WORD:
        SNPrintF(trace_buf_,
                 "%016" REGIx_FORMAT "    (%" PRId64 ")    int32:%" REGId_FORMAT
                 " uint32:%" PRIu32,
                 v.fmt_int32, icount_, v.fmt_int32, v.fmt_int32);
        break;
      case FLOAT:
        SNPrintF(trace_buf_, "%016" REGIx_FORMAT "    (%" PRId64 ")    flt:%e",
                 v.fmt_int32, icount_, v.fmt_float);
        break;
      case DOUBLE:
        SNPrintF(trace_buf_, "%016" PRIx64 "    (%" PRId64 ")    dbl:%e",
                 static_cast<int64_t>(v.fmt_double), icount_, v.fmt_double);
        break;
      default:
        UNREACHABLE();
    }
  }
}
#endif

// TODO(plind): consider making icount_ printing a flag option.
template <typename T>
void Simulator::TraceMemRd(sreg_t addr, T value, sreg_t reg_value) {
  if (v8_flags.trace_sim) {
    if (std::is_integral<T>::value) {
      switch (sizeof(T)) {
        case 1:
          SNPrintF(trace_buf_,
                   "%016" REGIx_FORMAT "    (%" PRId64 ")    int8:%" PRId8
                   " uint8:%" PRIu8 " <-- [addr: %" REGIx_FORMAT "]",
                   reg_value, icount_, static_cast<int8_t>(value),
                   static_cast<uint8_t>(value), addr);
          break;
        case 2:
          SNPrintF(trace_buf_,
                   "%016" REGIx_FORMAT "    (%" PRId64 ")    int16:%" PRId16
                   " uint16:%" PRIu16 " <-- [addr: %" REGIx_FORMAT "]",
                   reg_value, icount_, static_cast<int16_t>(value),
                   static_cast<uint16_t>(value), addr);
          break;
        case 4:
          SNPrintF(trace_buf_,
                   "%016" REGIx_FORMAT "    (%" PRId64 ")    int32:%" PRId32
                   " uint32:%" PRIu32 " <-- [addr: %" REGIx_FORMAT "]",
                   reg_value, icount_, static_cast<int32_t>(value),
                   static_cast<uint32_t>(value), addr);
          break;
        case 8:
          SNPrintF(trace_buf_,
                   "%016" REGIx_FORMAT "    (%" PRId64 ")    int64:%" PRId64
                   " uint64:%" PRIu64 " <-- [addr: %" REGIx_FORMAT "]",
                   reg_value, icount_, static_cast<int64_t>(value),
                   static_cast<uint64_t>(value), addr);
          break;
        default:
          UNREACHABLE();
      }
    } else if (std::is_same<float, T>::value) {
      SNPrintF(trace_buf_,
               "%016" REGIx_FORMAT "    (%" PRId64
               ")    flt:%e <-- [addr: %" REGIx_FORMAT "]",
               reg_value, icount_, static_cast<float>(value), addr);
    } else if (std::is_same<double, T>::value) {
      SNPrintF(trace_buf_,
               "%016" REGIx_FORMAT "    (%" PRId64
               ")    dbl:%e <-- [addr: %" REGIx_FORMAT "]",
               reg_value, icount_, static_cast<double>(value), addr);
    } else {
      UNREACHABLE();
    }
  }
}

void Simulator::TraceMemRdFloat(sreg_t addr, Float32 value, int64_t reg_value) {
  if (v8_flags.trace_sim) {
    SNPrintF(trace_buf_,
             "%016" PRIx64 "    (%" PRId64
             ")    flt:%e <-- [addr: %" REGIx_FORMAT "]",
             reg_value, icount_, static_cast<float>(value.get_scalar()), addr);
  }
}

void Simulator::TraceMemRdDouble(sreg_t addr, double value, int64_t reg_value) {
  if (v8_flags.trace_sim) {
    SNPrintF(trace_buf_,
             "%016" PRIx64 "    (%" PRId64
             ")    dbl:%e <-- [addr: %" REGIx_FORMAT "]",
             reg_value, icount_, static_cast<double>(value), addr);
  }
}

void Simulator::TraceMemRdDouble(sreg_t addr, Float64 value,
                                 int64_t reg_value) {
  if (v8_flags.trace_sim) {
    SNPrintF(trace_buf_,
             "%016" PRIx64 "    (%" PRId64
             ")    dbl:%e <-- [addr: %" REGIx_FORMAT "]",
             reg_value, icount_, static_cast<double>(value.get_scalar()), addr);
  }
}

template <typename T>
void Simulator::TraceMemWr(sreg_t addr, T value) {
  if (v8_flags.trace_sim) {
    switch (sizeof(T)) {
      case 1:
        SNPrintF(trace_buf_,
                 "                    (%" PRIu64 ")    int8:%" PRId8
                 " uint8:%" PRIu8 " --> [addr: %" REGIx_FORMAT "]",
                 icount_, static_cast<int8_t>(value),
                 static_cast<uint8_t>(value), addr);
        break;
      case 2:
        SNPrintF(trace_buf_,
                 "                    (%" PRIu64 ")    int16:%" PRId16
                 " uint16:%" PRIu16 " --> [addr: %" REGIx_FORMAT "]",
                 icount_, static_cast<int16_t>(value),
                 static_cast<uint16_t>(value), addr);
        break;
      case 4:
        if (std::is_integral<T>::value) {
          SNPrintF(trace_buf_,
                   "                    (%" PRIu64 ")    int32:%" PRId32
                   " uint32:%" PRIu32 " --> [addr: %" REGIx_FORMAT "]",
                   icount_, static_cast<int32_t>(value),
                   static_cast<uint32_t>(value), addr);
        } else {
          SNPrintF(trace_buf_,
                   "                    (%" PRIu64
                   ")    flt:%e bit:%x --> [addr: %" REGIx_FORMAT "]",
                   icount_, static_cast<float>(value),
                   base::bit_cast<int32_t, float>(value), addr);
        }
        break;
      case 8:
        if (std::is_integral<T>::value) {
          SNPrintF(trace_buf_,
                   "                    (%" PRIu64 ")    int64:%" PRId64
                   " uint64:%" PRIu64 " --> [addr: %" REGIx_FORMAT "]",
                   icount_, static_cast<int64_t>(value),
                   static_cast<uint64_t>(value), addr);
        } else {
          SNPrintF(trace_buf_,
                   "                    (%" PRIu64 ")    dbl:%e bit:%" PRIx64
                   " --> [addr: %" REGIx_FORMAT "]",
                   icount_, static_cast<double>(value),
                   base::bit_cast<int64_t, double>(value), addr);
        }
        break;
      default:
        UNREACHABLE();
    }
  }
}

void Simulator::TraceMemWrDouble(sreg_t addr, double value) {
  if (v8_flags.trace_sim) {
    SNPrintF(trace_buf_,
             "                    (%" PRIu64 ")    dbl:%e bit:%" PRIx64
             "--> [addr: %" REGIx_FORMAT "]",
             icount_, value, base::bit_cast<int64_t, double>(value), addr);
  }
}
// RISCV Memory Read/Write functions

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

// TODO(RISCV): check whether the specific board supports unaligned load/store
// (determined by EEI). For now, we assume the board does not support unaligned
// load/store (e.g., trapping)
template <typename T>
T Simulator::ReadMem(sreg_t addr, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory read from bad address: 0x%08" REGIx_FORMAT
           " , pc=0x%08" PRIxPTR " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
#if !defined(V8_COMPRESS_POINTERS) && defined(RISCV_HAS_NO_UNALIGNED)
  // check for natural alignment
  if (!v8_flags.riscv_c_extension && ((addr & (sizeof(T) - 1)) != 0)) {
    PrintF("Unaligned read at 0x%08" REGIx_FORMAT " , pc=0x%08" V8PRIxPTR "\n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
#endif
  T* ptr = reinterpret_cast<T*>(addr);
  T value = *ptr;
  return value;
}

template <typename T>
void Simulator::WriteMem(sreg_t addr, T value, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" REGIx_FORMAT
           " , pc=0x%08" PRIxPTR " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
#if !defined(V8_COMPRESS_POINTERS) && defined(RISCV_HAS_NO_UNALIGNED)
  // check for natural alignment
  if (!v8_flags.riscv_c_extension && ((addr & (sizeof(T) - 1)) != 0)) {
    PrintF("Unaligned write at 0x%08" REGIx_FORMAT " , pc=0x%08" V8PRIxPTR "\n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
#endif
  T* ptr = reinterpret_cast<T*>(addr);
  if (!std::is_same<double, T>::value) {
    TraceMemWr(addr, value);
  } else {
    TraceMemWrDouble(addr, value);
  }
  *ptr = value;
}

template <>
void Simulator::WriteMem(sreg_t addr, Float32 value, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" REGIx_FORMAT
           " , pc=0x%08" PRIxPTR " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
#if !defined(V8_COMPRESS_POINTERS) && defined(RISCV_HAS_NO_UNALIGNED)
  // check for natural alignment
  if (!v8_flags.riscv_c_extension && ((addr & (sizeof(T) - 1)) != 0)) {
    PrintF("Unaligned write at 0x%08" REGIx_FORMAT " , pc=0x%08" V8PRIxPTR "\n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
#endif
  float* ptr = reinterpret_cast<float*>(addr);
  TraceMemWr(addr, value.get_scalar());
  memcpy(ptr, &value, 4);
}

template <>
void Simulator::WriteMem(sreg_t addr, Float64 value, Instruction* instr) {
  if (addr >= 0 && addr < 0x400) {
    // This has to be a nullptr-dereference, drop into debugger.
    PrintF("Memory write to bad address: 0x%08" REGIx_FORMAT
           " , pc=0x%08" PRIxPTR " \n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
#if !defined(V8_COMPRESS_POINTERS) && defined(RISCV_HAS_NO_UNALIGNED)
  // check for natural alignment
  if (!v8_flags.riscv_c_extension && ((addr & (sizeof(T) - 1)) != 0)) {
    PrintF("Unaligned write at 0x%08" REGIx_FORMAT " , pc=0x%08" V8PRIxPTR "\n",
           addr, reinterpret_cast<intptr_t>(instr));
    DieOrDebug();
  }
#endif
  double* ptr = reinterpret_cast<double*>(addr);
  TraceMemWrDouble(addr, value.get_scalar());
  memcpy(ptr, &value, 8);
}

// Returns the limit of the stack area to enable checking for stack overflows.
uintptr_t Simulator::StackLimit(uintptr_t c_limit) const {
  // The simulator uses a separate JS stack. If we have exhausted the C stack,
  // we also drop down the JS limit to reflect the exhaustion on the JS stack.
  if (GetCurrentStackPosition() < c_limit) {
    return reinterpret_cast<uintptr_t>(get_sp());
  }

  // Otherwise the limit is the JS stack. Leave a safety margin to prevent
  // overrunning the stack when pushing values.
  return stack_limit_ + kAdditionalStackMargin;
}

base::Vector<uint8_t> Simulator::GetCentralStackView() const {
  // We do not add an additional safety margin as above in
  // Simulator::StackLimit, as users of this method are expected to add their
  // own margin.
  return base::VectorOf(
      reinterpret_cast<uint8_t*>(stack_ + kStackProtectionSize),
      UsableStackSize());
}

// Unsupported instructions use Format to print an error and stop execution.
void Simulator::Format(Instruction* instr, const char* format) {
  PrintF("Simulator found unsupported instruction:\n 0x%08" PRIxPTR " : %s\n",
         reinterpret_cast<intptr_t>(instr), format);
  UNIMPLEMENTED_RISCV();
}

// Calls 
"""


```