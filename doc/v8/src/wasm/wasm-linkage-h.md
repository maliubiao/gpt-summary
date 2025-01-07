Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Understand the Goal:** The request asks for the functionality of `v8/src/wasm/wasm-linkage.h`, whether it's related to JavaScript, examples, logic, and potential errors.

2. **Initial Scan and Keyword Spotting:** Quickly read through the code, looking for keywords and patterns. I notice:
    * `#ifndef`, `#define`, `#include`:  Standard C/C++ header file guards.
    * `namespace v8`, `namespace internal`, `namespace wasm`:  Indicates V8's internal structure and the specific Wasm module.
    * `constexpr`:  Suggests compile-time constants.
    * `Register`, `DoubleRegister`: Likely related to CPU registers.
    * `kGpParamRegisters`, `kFpParamRegisters`, `kGpReturnRegisters`, `kFpReturnRegisters`:  Arrays of registers, probably for function parameters and return values. The prefixes "Gp" and "Fp" hint at general-purpose and floating-point registers.
    * Architecture-specific `#elif V8_TARGET_ARCH_...`: The file defines register sets for different CPU architectures (IA32, X64, ARM, etc.).
    * `LinkageAllocator`, `LinkageLocationAllocator`:  Class names that strongly suggest memory/register management for linking functions.
    * `MachineRepresentation`, `MachineType`:  Enums or classes representing data types.
    * `DCHECK`, `UNREACHABLE`:  Debugging/assertion macros.

3. **Identify Core Functionality:** Based on the keyword spotting, the primary purpose of this header seems to be defining how WebAssembly functions are linked and called on different architectures. This includes:
    * **Register Allocation:**  Specifying which registers are used for passing parameters and returning values. This is architecture-dependent.
    * **Stack Allocation:**  Providing mechanisms for allocating space on the stack for function arguments and local variables when registers are insufficient.
    * **Data Representation:**  Dealing with different data types (integers, floats, SIMD).

4. **Analyze Key Classes:**

    * **`LinkageAllocator`:** This class is responsible for managing the allocation of general-purpose registers, floating-point registers, and stack slots. It tracks which registers are available and assigns them. The ARM-specific logic for even/odd D-register pairs for floats is interesting.
    * **`LinkageLocationAllocator`:** This class uses a `LinkageAllocator` and decides whether to allocate a register or a stack slot for a given `MachineRepresentation`. It abstracts the allocation process and returns a `LinkageLocation` object, which seems to encapsulate the location (register or stack) and type of a value.

5. **Consider JavaScript Relevance:**  WebAssembly is designed to work closely with JavaScript. This header, being part of the Wasm implementation in V8, is *fundamentally* related to JavaScript. It defines the low-level mechanisms for calling Wasm functions from JavaScript and vice versa.

6. **Develop JavaScript Examples (Conceptual):** Since this is a C++ header, a direct JavaScript equivalent isn't possible. However, we can illustrate the *effects* of this linkage:

    * **Parameter Passing:** When calling a Wasm function from JS, V8 uses the defined register conventions to pass arguments.
    * **Return Values:**  Similarly, return values are placed in designated registers.
    * **Stack Overflow (as a potential error):** If a Wasm function has many local variables or deep recursion, it could exhaust the stack, a common programming error. While this header doesn't directly *cause* it, it's involved in how stack space is managed during Wasm execution.

7. **Infer Code Logic (Hypothetical):** Imagine a simple Wasm function that adds two integers.

    * **Input:** Two integer values.
    * **Process (using the header's info):** The `LinkageAllocator` (or `LinkageLocationAllocator`) would assign the input integers to the designated parameter registers (e.g., `rsi` and `rax` on x64).
    * **Output:** The sum, placed in the designated return register (e.g., `rax` on x64).

8. **Identify Potential User Errors:** Users don't directly interact with this header file. However, their *Wasm code* can lead to issues that this header helps manage:

    * **Incorrect Function Signatures:** If the Wasm function signature doesn't match how JavaScript calls it, the register and stack usage might be wrong, leading to crashes or incorrect results.
    * **Stack Overflow (again):**  As mentioned before, this is a common error in any programming language, and Wasm is no exception.

9. **Address `.tq` Check:** The request specifically asks about `.tq` files. The response correctly identifies that this header is `.h`, not `.tq`, and therefore not a Torque file.

10. **Structure the Response:**  Organize the findings into clear sections (Functionality, JavaScript Relationship, Code Logic, User Errors, etc.) as requested. Use clear and concise language.

11. **Review and Refine:**  Read through the generated response to ensure accuracy, clarity, and completeness. Check if all parts of the original request have been addressed. For instance, initially, I might have focused too much on register allocation and less on the stack. Reviewing helps balance the explanation. Also, ensure the JavaScript examples are illustrative and don't require deep V8 knowledge to understand the concept.The provided code snippet is a C++ header file (`wasm-linkage.h`) from the V8 JavaScript engine, specifically for the WebAssembly (Wasm) implementation. Let's break down its functionality:

**Functionality of `v8/src/wasm/wasm-linkage.h`:**

This header file defines **calling conventions and data layout conventions** for WebAssembly functions within the V8 engine. It essentially specifies how arguments are passed to and results are returned from Wasm functions, bridging the gap between the Wasm bytecode and the underlying machine code. Here's a more detailed breakdown:

1. **Architecture-Specific Register Allocation:**
   - The core of the file defines `constexpr` arrays of registers (`kGpParamRegisters`, `kFpParamRegisters`, `kGpReturnRegisters`, `kFpReturnRegisters`) for various target architectures (IA32, X64, ARM, ARM64, MIPS64, LOONG64, PPC64, S390X, RISCV32/64).
   - These arrays specify which **general-purpose registers (GP)** and **floating-point registers (FP)** are used for passing function parameters and returning results on each architecture.
   - This is crucial for generating correct machine code that adheres to the platform's Application Binary Interface (ABI) or a custom calling convention.

2. **`LinkageAllocator` Class:**
   - This class is responsible for allocating registers and stack slots for function arguments and return values.
   - It keeps track of which registers have been used (`gp_offset_`, `fp_offset_`) and provides methods like `NextGpReg()` and `NextFpReg()` to get the next available register.
   - It also handles stack slot allocation using `AlignedSlotAllocator`.
   - The ARM architecture has special logic within `CanAllocateFP` and `NextFpReg` to handle the pairing requirements of D-registers for floating-point values.

3. **`LinkageLocationAllocator` Class:**
   - This class uses a `LinkageAllocator` to determine the location (either a register or a stack slot) for a given value with a specific `MachineRepresentation`.
   - It tries to allocate registers first and falls back to stack slots if no more registers are available.
   - The `slot_offset_` is used to manage stack offsets for parameters and return values, which might reside in different stack frames.

4. **Constants and Flags:**
   - `kWasmInstanceDataParameterIndex`:  Defines the index of the parameter where the Wasm instance data is passed. This is essential for the Wasm runtime to access instance-specific information.
   - `kIsFpAlwaysDouble`, `kIsBigEndian`, `kIsBigEndianOnSim`: These `constexpr bool` values specify platform-specific characteristics related to floating-point representation and endianness.

**Is `v8/src/wasm/wasm-linkage.h` a Torque source file?**

No, `v8/src/wasm/wasm-linkage.h` ends with `.h`, indicating it's a standard C++ header file. Torque source files have the `.tq` extension.

**Relationship with JavaScript and Examples:**

This header file is fundamental to the interaction between JavaScript and WebAssembly. When you call a WebAssembly function from JavaScript, V8 uses the calling conventions defined in this header to:

1. **Prepare Arguments:** Place JavaScript values (after appropriate type conversion) into the registers or stack locations specified for the target architecture.
2. **Call the Wasm Function:** Execute the compiled Wasm code.
3. **Retrieve Results:**  Read the return value(s) from the designated return registers or stack locations and convert them back to JavaScript values.

**JavaScript Example (Conceptual):**

```javascript
// Assume you have a WebAssembly module loaded as 'wasmModule'
const addFunction = wasmModule.instance.exports.add;

// Calling the 'add' function from JavaScript
const result = addFunction(5, 10);
console.log(result); // Output: 15
```

**Behind the scenes (using the information from `wasm-linkage.h`):**

If the target architecture is x64, when `addFunction(5, 10)` is called:

- V8 would likely move the value `5` into the `rsi` register (the first general-purpose parameter register).
- V8 would likely move the value `10` into the `rax` register (the second general-purpose parameter register).
- The Wasm code for `add` would execute, taking its input from `rsi` and `rax`.
- The Wasm code would place the result (15) into the `rax` register (the first general-purpose return register).
- V8 would then read the value from `rax` and return it to the JavaScript code.

**Code Logic Reasoning (Hypothetical):**

Let's consider the `LinkageAllocator` and a hypothetical function call on x64 with two integer parameters:

**Assumptions:**

- Target architecture: x64
- Function signature: `i32 func(i32 a, i32 b)` (takes two 32-bit integers)
- We are allocating registers for the parameters.

**Input:**

- `LinkageAllocator` instance initialized for x64.

**Process:**

1. **Allocate first parameter:** `allocator.NextGpReg()` is called.
   - `gp_offset_` is initially 0.
   - `kGpParamRegisters[0]` is `rsi`.
   - `NextGpReg()` returns the code for `rsi`.
   - `gp_offset_` is incremented to 1.

2. **Allocate second parameter:** `allocator.NextGpReg()` is called again.
   - `gp_offset_` is now 1.
   - `kGpParamRegisters[1]` is `rax`.
   - `NextGpReg()` returns the code for `rax`.
   - `gp_offset_` is incremented to 2.

**Output:**

- The first parameter would be placed in the `rsi` register.
- The second parameter would be placed in the `rax` register.

**If the function also had a floating-point parameter:**

1. **Allocate floating-point parameter:** `allocator.NextFpReg(MachineRepresentation::kFloat64)` would be called.
   - `fp_offset_` is initially 0.
   - `kFpParamRegisters[0]` is `xmm1`.
   - `NextFpReg()` returns the code for `xmm1`.
   - `fp_offset_` is incremented to 1.

**Potential User Programming Errors (Indirectly Related):**

While users don't directly interact with `wasm-linkage.h`, errors in their Wasm code or when interfacing with JavaScript can manifest due to mismatches in expected calling conventions or data types. Here are some examples:

1. **Incorrect Function Signatures in JavaScript:**

   ```javascript
   // Wasm function expects two i32 parameters
   const wasmAdd = wasmModule.instance.exports.add;

   // User mistakenly passes a string
   wasmAdd("hello", 5); // Potential type mismatch, V8 might attempt to convert
                         // or the Wasm code might misinterpret the data.
   ```

   V8 will try its best to marshal the data, but if the Wasm function expects specific integer types and receives something else, the behavior can be unpredictable, potentially leading to crashes or incorrect results.

2. **Mismatched Return Types:**

   ```javascript
   // Wasm function returns an i32
   const wasmGetCounter = wasmModule.instance.exports.getCounter;

   // User assumes it returns a float and performs float operations
   const counter = wasmGetCounter();
   const result = counter + 0.5; // Might lead to unexpected results due to type mismatch.
   ```

   If the JavaScript code expects a different return type than what the Wasm function actually returns, the interpretation of the value in the return register will be incorrect.

3. **Stack Overflow in Wasm (Indirectly):**

   While `wasm-linkage.h` helps manage stack allocation, a deeply recursive Wasm function or a function with very large local variables can still lead to a stack overflow. This isn't directly caused by errors in this header but is a consequence of how stack space is managed during function calls, which this header helps define.

   ```c++ // Hypothetical Wasm code causing stack overflow
   int recursiveFunction(int n) {
       int localArray[10000]; // Large local array
       if (n <= 0) return 0;
       return n + recursiveFunction(n - 1);
   }
   ```

In summary, `v8/src/wasm/wasm-linkage.h` is a crucial low-level header file that defines the rules for how WebAssembly functions are called and how data is passed between JavaScript and WebAssembly within the V8 engine. It handles architecture-specific details and is essential for the correct and efficient execution of WebAssembly code.

Prompt: 
```
这是目录为v8/src/wasm/wasm-linkage.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-linkage.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_WASM_LINKAGE_H_
#define V8_WASM_WASM_LINKAGE_H_

#include "src/codegen/aligned-slot-allocator.h"
#include "src/codegen/assembler-arch.h"
#include "src/codegen/linkage-location.h"
#include "src/codegen/machine-type.h"

namespace v8 {
namespace internal {
namespace wasm {

// TODO(wasm): optimize calling conventions to be both closer to C++ (to
// reduce adapter costs for fast Wasm <-> C++ calls) and to be more efficient
// in general.

#if V8_TARGET_ARCH_IA32
// ===========================================================================
// == ia32 ===================================================================
// ===========================================================================
constexpr Register kGpParamRegisters[] = {esi, eax, edx, ecx};
constexpr Register kGpReturnRegisters[] = {eax, edx};
constexpr DoubleRegister kFpParamRegisters[] = {xmm1, xmm2, xmm3,
                                                xmm4, xmm5, xmm6};
constexpr DoubleRegister kFpReturnRegisters[] = {xmm1, xmm2};

#elif V8_TARGET_ARCH_X64
// ===========================================================================
// == x64 ====================================================================
// ===========================================================================
constexpr Register kGpParamRegisters[] = {rsi, rax, rdx, rcx, rbx, r9};
constexpr Register kGpReturnRegisters[] = {rax, rdx};
constexpr DoubleRegister kFpParamRegisters[] = {xmm1, xmm2, xmm3,
                                                xmm4, xmm5, xmm6};
constexpr DoubleRegister kFpReturnRegisters[] = {xmm1, xmm2};

#elif V8_TARGET_ARCH_ARM
// ===========================================================================
// == arm ====================================================================
// ===========================================================================
constexpr Register kGpParamRegisters[] = {r3, r0, r2, r6};
constexpr Register kGpReturnRegisters[] = {r0, r1};
// ARM d-registers must be in even/odd D-register pairs for correct allocation.
constexpr DoubleRegister kFpParamRegisters[] = {d0, d1, d2, d3, d4, d5, d6, d7};
constexpr DoubleRegister kFpReturnRegisters[] = {d0, d1};

#elif V8_TARGET_ARCH_ARM64
// ===========================================================================
// == arm64 ====================================================================
// ===========================================================================
constexpr Register kGpParamRegisters[] = {x7, x0, x2, x3, x4, x5, x6};
constexpr Register kGpReturnRegisters[] = {x0, x1};
constexpr DoubleRegister kFpParamRegisters[] = {d0, d1, d2, d3, d4, d5, d6, d7};
constexpr DoubleRegister kFpReturnRegisters[] = {d0, d1};

#elif V8_TARGET_ARCH_MIPS64
// ===========================================================================
// == mips64 =================================================================
// ===========================================================================
constexpr Register kGpParamRegisters[] = {a0, a2, a3, a4, a5, a6, a7};
constexpr Register kGpReturnRegisters[] = {v0, v1};
constexpr DoubleRegister kFpParamRegisters[] = {f2, f4, f6, f8, f10, f12, f14};
constexpr DoubleRegister kFpReturnRegisters[] = {f2, f4};

#elif V8_TARGET_ARCH_LOONG64
// ===========================================================================
// == LOONG64 ================================================================
// ===========================================================================
constexpr Register kGpParamRegisters[] = {a7, a0, a2, a3, a4, a5, a6};
constexpr Register kGpReturnRegisters[] = {a0, a1};
constexpr DoubleRegister kFpParamRegisters[] = {f0, f1, f2, f3, f4, f5, f6, f7};
constexpr DoubleRegister kFpReturnRegisters[] = {f0, f1};

#elif V8_TARGET_ARCH_PPC64
// ===========================================================================
// == ppc64 ==================================================================
// ===========================================================================
constexpr Register kGpParamRegisters[] = {r10, r3, r5, r6, r7, r8, r9};
constexpr Register kGpReturnRegisters[] = {r3, r4};
constexpr DoubleRegister kFpParamRegisters[] = {d1, d2, d3, d4, d5, d6, d7, d8};
constexpr DoubleRegister kFpReturnRegisters[] = {d1, d2};

#elif V8_TARGET_ARCH_S390X
// ===========================================================================
// == s390x ==================================================================
// ===========================================================================
constexpr Register kGpParamRegisters[] = {r6, r2, r4, r5};
constexpr Register kGpReturnRegisters[] = {r2, r3};
constexpr DoubleRegister kFpParamRegisters[] = {d0, d2, d4, d6};
constexpr DoubleRegister kFpReturnRegisters[] = {d0, d2};

#elif V8_TARGET_ARCH_RISCV32 || V8_TARGET_ARCH_RISCV64
// ===========================================================================
// == riscv64 =================================================================
// ===========================================================================
// Note that kGpParamRegisters and kFpParamRegisters are used in
// Builtins::Generate_WasmCompileLazy (builtins-riscv.cc)
constexpr Register kGpParamRegisters[] = {a7, a0, a2, a3, a4, a5, a6};
constexpr Register kGpReturnRegisters[] = {a0, a1};
constexpr DoubleRegister kFpParamRegisters[] = {fa0, fa1, fa2, fa3,
                                                fa4, fa5, fa6, fa7};
constexpr DoubleRegister kFpReturnRegisters[] = {fa0, fa1};

#else
// ===========================================================================
// == unknown ================================================================
// ===========================================================================
// Do not use any registers, we will just always use the stack.
constexpr Register kGpParamRegisters[] = {};
constexpr Register kGpReturnRegisters[] = {};
constexpr DoubleRegister kFpParamRegisters[] = {};
constexpr DoubleRegister kFpReturnRegisters[] = {};

#endif

#if V8_TARGET_ARCH_PPC64
// Platforms where a Floating Point value is represented in Double Precision
// format in a FP register.
constexpr bool kIsFpAlwaysDouble = true;
#else
constexpr bool kIsFpAlwaysDouble = false;
#endif
#if V8_TARGET_BIG_ENDIAN
constexpr bool kIsBigEndian = true;
#else
constexpr bool kIsBigEndian = false;
#endif
#if V8_TARGET_ARCH_S390X_LE_SIM
constexpr bool kIsBigEndianOnSim = true;
#else
constexpr bool kIsBigEndianOnSim = false;
#endif

// The parameter index where the trusted instance data should be placed in wasm
// call descriptors. This is used by the Int64Lowering::LowerNode method.
constexpr int kWasmInstanceDataParameterIndex = 0;
static_assert(kWasmImplicitArgRegister ==
              kGpParamRegisters[kWasmInstanceDataParameterIndex]);

class LinkageAllocator {
 public:
  template <size_t kNumGpRegs, size_t kNumFpRegs>
  constexpr LinkageAllocator(const Register (&gp)[kNumGpRegs],
                             const DoubleRegister (&fp)[kNumFpRegs])
      : LinkageAllocator(gp, kNumGpRegs, fp, kNumFpRegs) {}

  constexpr LinkageAllocator(const Register* gp, int gpc,
                             const DoubleRegister* fp, int fpc)
      : gp_count_(gpc), gp_regs_(gp), fp_count_(fpc), fp_regs_(fp) {}

  bool CanAllocateGP() const { return gp_offset_ < gp_count_; }
  bool CanAllocateFP(MachineRepresentation rep) const {
#if V8_TARGET_ARCH_ARM
    switch (rep) {
      case MachineRepresentation::kFloat32: {
        // Get the next D-register (Liftoff only uses the even S-registers).
        int next = fp_allocator_.NextSlot(2) / 2;
        // Only the lower 16 D-registers alias S-registers.
        return next < fp_count_ && fp_regs_[next].code() < 16;
      }
      case MachineRepresentation::kFloat64: {
        int next = fp_allocator_.NextSlot(2) / 2;
        return next < fp_count_;
      }
      case MachineRepresentation::kSimd128: {
        int next = fp_allocator_.NextSlot(4) / 2;
        return next < fp_count_ - 1;  // 2 D-registers are required.
      }
      default:
        UNREACHABLE();
        return false;
    }
#else
    return fp_offset_ < fp_count_;
#endif
  }

  int NextGpReg() {
    DCHECK_LT(gp_offset_, gp_count_);
    return gp_regs_[gp_offset_++].code();
  }

  int NextFpReg(MachineRepresentation rep) {
    DCHECK(CanAllocateFP(rep));
#if V8_TARGET_ARCH_ARM
    switch (rep) {
      case MachineRepresentation::kFloat32: {
        // Liftoff uses only even-numbered S-registers, and encodes them using
        // the code of the corresponding D-register. This limits the calling
        // interface to only using the even-numbered S-registers.
        int d_reg_code = NextFpReg(MachineRepresentation::kFloat64);
        DCHECK_GT(16, d_reg_code);  // D16 - D31 don't alias S-registers.
        return d_reg_code * 2;
      }
      case MachineRepresentation::kFloat64: {
        int next = fp_allocator_.Allocate(2) / 2;
        return fp_regs_[next].code();
      }
      case MachineRepresentation::kSimd128: {
        int next = fp_allocator_.Allocate(4) / 2;
        int d_reg_code = fp_regs_[next].code();
        // Check that result and the next D-register pair.
        DCHECK_EQ(0, d_reg_code % 2);
        DCHECK_EQ(d_reg_code + 1, fp_regs_[next + 1].code());
        return d_reg_code / 2;
      }
      default:
        UNREACHABLE();
    }
#else
    return fp_regs_[fp_offset_++].code();
#endif
  }

  // Stackslots are counted upwards starting from 0 (or the offset set by
  // {SetStackOffset}. If {type} needs more than one stack slot, the lowest
  // used stack slot is returned.
  int NextStackSlot(MachineRepresentation type) {
    int num_slots =
        AlignedSlotAllocator::NumSlotsForWidth(ElementSizeInBytes(type));
    int slot = slot_allocator_.Allocate(num_slots);
    return slot;
  }

  // Set an offset for the stack slots returned by {NextStackSlot} and
  // {NumStackSlots}. Can only be called before any call to {NextStackSlot}.
  void SetStackOffset(int offset) {
    DCHECK_LE(0, offset);
    DCHECK_EQ(0, slot_allocator_.Size());
    slot_allocator_.AllocateUnaligned(offset);
  }

  int NumStackSlots() const { return slot_allocator_.Size(); }

  void EndSlotArea() { slot_allocator_.AllocateUnaligned(0); }

 private:
  const int gp_count_;
  int gp_offset_ = 0;
  const Register* const gp_regs_;

  const int fp_count_;
#if V8_TARGET_ARCH_ARM
  // Use an aligned slot allocator to model ARM FP register aliasing. The slots
  // are 32 bits, so 2 slots are required for a D-register, 4 for a Q-register.
  AlignedSlotAllocator fp_allocator_;
#else
  int fp_offset_ = 0;
#endif
  const DoubleRegister* const fp_regs_;

  AlignedSlotAllocator slot_allocator_;
};

// Helper for allocating either an GP or FP reg, or the next stack slot.
class LinkageLocationAllocator {
 public:
  template <size_t kNumGpRegs, size_t kNumFpRegs>
  constexpr LinkageLocationAllocator(const Register (&gp)[kNumGpRegs],
                                     const DoubleRegister (&fp)[kNumFpRegs],
                                     int slot_offset)
      : allocator_(LinkageAllocator(gp, fp)), slot_offset_(slot_offset) {}

  LinkageLocation Next(MachineRepresentation rep) {
    MachineType type = MachineType::TypeForRepresentation(rep);
    if (IsFloatingPoint(rep)) {
      if (allocator_.CanAllocateFP(rep)) {
        int reg_code = allocator_.NextFpReg(rep);
        return LinkageLocation::ForRegister(reg_code, type);
      }
    } else if (allocator_.CanAllocateGP()) {
      int reg_code = allocator_.NextGpReg();
      return LinkageLocation::ForRegister(reg_code, type);
    }
    // Cannot use register; use stack slot.
    int index = -1 - (slot_offset_ + allocator_.NextStackSlot(rep));
    return LinkageLocation::ForCallerFrameSlot(index, type);
  }

  int NumStackSlots() const { return allocator_.NumStackSlots(); }
  void EndSlotArea() { allocator_.EndSlotArea(); }

 private:
  LinkageAllocator allocator_;
  // Since params and returns are in different stack frames, we must allocate
  // them separately. Parameter slots don't need an offset, but return slots
  // must be offset to just before the param slots, using this |slot_offset_|.
  int slot_offset_;
};
}  // namespace wasm
}  // namespace internal
}  // namespace v8

#endif  // V8_WASM_WASM_LINKAGE_H_

"""

```