Response:
The user wants a summary of the functionality of the provided C++ header file `liftoff-assembler.h`.

Here's a breakdown of the file's purpose and key components:

1. **Filename and Path:** `v8/src/wasm/baseline/liftoff-assembler.h` indicates this file is part of the V8 JavaScript engine, specifically related to the WebAssembly (Wasm) baseline compiler, "Liftoff". The `.h` extension signifies a C++ header file.

2. **Copyright and License:**  Standard V8 copyright and BSD-style license information.

3. **Includes:**  Includes necessary header files for:
    - Standard C++ functionalities (`iosfwd`, `memory`).
    - V8 base utilities (`bits.h`).
    - V8 code generation (`macro-assembler.h`).
    - Liftoff-specific components (`liftoff-assembler-defs.h`, `liftoff-compiler.h`, `liftoff-register.h`, `liftoff-varstate.h`).
    - Wasm infrastructure (`function-body-decoder.h`, `wasm-module.h`, `wasm-opcodes.h`, `wasm-value.h`).

4. **Forward Declarations:** Declares `CallDescriptor` to avoid circular dependencies.

5. **`Negate` and `Flip` Functions:**  These inline functions manipulate `Condition` enums, likely used for conditional branching in the generated assembly code. `Negate` inverts the condition (e.g., `kEqual` becomes `kNotEqual`), and `Flip` swaps operands implicitly (e.g., `kLessThan` becomes `kGreaterThan`).

6. **`FreezeCacheState` Class:** A helper class, likely used for debugging or temporarily freezing the assembler's internal state. It seems to primarily be active in debug builds.

7. **`LiftoffAssembler` Class:** This is the core class of the header file. It inherits from `MacroAssembler`, providing the basic assembly code generation functionality. The class appears to manage the state of registers and the Wasm stack during code generation for the Liftoff compiler.

8. **Constants:** Defines constants like `kStackSlotSize`, `kIntPtrKind`, and `kSmiKind`, related to memory layout and data types.

9. **`ValueKindSig`:** A type alias for a signature of `ValueKind`, likely representing the types of function parameters and return values.

10. **`VarState`:** A type alias for `LiftoffVarState`, representing the state of a Wasm variable (e.g., stored in a register or on the stack).

11. **`CacheState` Struct:** A crucial part, managing the register allocation and stack state. It tracks:
    - `stack_state`:  The Wasm value stack.
    - `used_registers`: Registers currently holding values.
    - `register_use_count`: How many times each register is used.
    - `last_spilled_regs`:  Registers recently spilled to avoid immediately spilling them again.
    - Cached values (instance data, memory start) in registers.
    - Methods for managing register usage (allocating, freeing, spilling).
    - Methods for merging cache states during control flow merges.

12. **`LiftoffAssembler` Public Interface:**  Provides methods for:
    - Loading and storing values between registers and the stack.
    - Managing the Wasm value stack (`PushVarState`, `PopVarState`, `PeekToRegister`, `DropValues`).
    - Register allocation (`GetUnusedRegister`).
    - Control flow merging (`MergeIntoNewState`, `MergeFullStackWith`, `MergeStackWith`).
    - Spilling registers to memory.
    - Preparing for function calls (`PrepareBuiltinCall`, `PrepareCall`, `FinishCall`).
    - Moving data between registers (`Move`, `ParallelRegisterMove`).
    - Handling return values (`MoveToReturnLocations`).
    - Platform-specific assembly code emission (e.g., `PrepareStackFrame`, `CallFrameSetupStub`, `Load`, `Store`, arithmetic operations).

**Plan for the response:**

- State that this is a C++ header file for the Liftoff assembler.
- Explain its main responsibility: managing register allocation and generating machine code for the Wasm baseline compiler.
- List key components: `Negate`/`Flip`, `FreezeCacheState`, `LiftoffAssembler`, `CacheState`.
- Summarize the functionality of `CacheState` (register/stack management).
- Summarize the functionality of `LiftoffAssembler` (stack operations, register allocation, call preparation, code emission).
- Note that it is C++ and not Torque, so the Torque check is negative.
- Indicate that it's deeply related to Wasm functionality, which in turn is related to JavaScript's ability to run Wasm code, but direct JavaScript examples are not applicable for this *header file*.
- Mention code logic (conditional branches based on `Condition`).
- Point out the register allocation/spilling logic as a place where programming errors could occur in the *implementation* of the assembler (not user code).
这是v8 JavaScript引擎中用于WebAssembly (Wasm) 基线编译器 Liftoff 的汇编器头文件。 它定义了 `LiftoffAssembler` 类，该类负责生成特定架构的机器码来执行 WebAssembly 代码。

**主要功能:**

1. **机器码生成:** `LiftoffAssembler` 类继承自 `MacroAssembler`，提供了生成各种机器指令的能力，用于实现 WebAssembly 的操作。

2. **寄存器和栈管理:**  `LiftoffAssembler` 维护了 Wasm 执行期间的寄存器和栈的状态。这包括：
    - **`CacheState`:**  跟踪哪些值存储在寄存器中，哪些在栈上，以及寄存器的使用情况（例如，使用计数）。它负责寄存器的分配和释放，以及在需要时将寄存器中的值溢出到栈上。
    - **Wasm 值栈模拟:** 通过 `stack_state` 成员模拟 Wasm 的值栈。
    - **栈帧管理:** 提供用于准备和管理函数调用栈帧的方法。

3. **WebAssembly 操作实现:**  `LiftoffAssembler` 提供了许多方法来生成执行特定 WebAssembly 操作（例如，加法、减法、加载、存储、函数调用）所需的机器码。

4. **控制流管理:**  支持生成条件分支、循环和其他控制流结构的机器码。它还处理控制流合并的情况，即在不同的执行路径汇合时，如何合并寄存器和栈的状态。

5. **函数调用支持:**  提供用于准备和执行函数调用的方法，包括加载参数到正确的寄存器或栈位置，以及处理返回值。

6. **内存访问:**  支持生成用于访问 WebAssembly 线性内存的机器码，包括有界和无界的内存访问。

7. **原子操作:** 支持生成用于执行原子内存操作的机器码。

8. **异常处理:**  支持处理 WebAssembly 执行期间发生的异常。

**关于文件类型和 JavaScript 关系:**

* **文件类型:**  `v8/src/wasm/baseline/liftoff-assembler.h` 以 `.h` 结尾，这是一个标准的 C++ 头文件，用于声明类、函数和其他类型。 它 **不是**以 `.tq` 结尾，因此它 **不是**一个 V8 Torque 源代码文件。

* **JavaScript 关系:** 虽然 `liftoff-assembler.h` 本身不是 JavaScript 代码，但它与 JavaScript 的功能密切相关。  JavaScript 引擎 V8 使用 Liftoff 编译器来快速编译 WebAssembly 代码，以便在浏览器或其他 JavaScript 运行时环境中执行。 当 JavaScript 代码加载并执行 WebAssembly 模块时，V8 会调用 Liftoff 编译器，而 `LiftoffAssembler` 就负责生成实际运行 Wasm 代码的机器指令。

**JavaScript 示例 (概念性):**

虽然无法直接用 JavaScript 展示 `liftoff-assembler.h` 的内容，但可以说明其在 JavaScript 执行 WebAssembly 时的作用：

```javascript
// 假设这段 JavaScript 代码加载了一个简单的 WebAssembly 模块
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60,
  0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x0a, 0x09, 0x01,
  0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b
]); // 简单的 Wasm 代码，将两个 i32 相加

WebAssembly.instantiate(wasmCode).then(instance => {
  const add = instance.exports.add;
  const result = add(5, 10); // 调用 Wasm 模块中的 add 函数
  console.log(result); // 输出 15
});
```

在这个例子中，当 `WebAssembly.instantiate` 被调用时，V8 的 Liftoff 编译器（其中使用了 `LiftoffAssembler`）会将 `wasmCode` 中的 Wasm 指令转换为机器码。 当调用 `add(5, 10)` 时，实际上执行的是 `LiftoffAssembler` 生成的机器指令。

**代码逻辑推理:**

让我们看一个 `Negate` 函数的例子：

**假设输入:** `cond = kLessThan`

**代码逻辑:**  `Negate(kLessThan)` 进入 `switch` 语句的 `case kLessThan:` 分支，并返回 `kGreaterThanEqual`。

**输出:** `kGreaterThanEqual`

**用户常见的编程错误 (与 Liftoff 编译器实现相关，而非用户直接编写 WebAssembly):**

对于直接使用 `liftoff-assembler.h` 的开发者（通常是 V8 引擎的开发者），常见的编程错误可能包括：

* **寄存器分配错误:**  在需要使用寄存器时，没有正确地分配或释放寄存器，导致寄存器冲突或值被意外覆盖。
* **栈管理错误:**  错误地推送或弹出栈上的值，导致栈不平衡或访问到错误的数据。
* **指令生成错误:**  生成了不正确的机器指令序列，无法正确实现 WebAssembly 的语义。
* **内存访问错误:**  生成了越界或非法的内存访问指令。
* **类型错误:**  没有正确处理不同 WebAssembly 数据类型（如 i32, i64, f32, f64）的差异，导致指令操作了错误类型的数据。

**第1部分功能归纳:**

`v8/src/wasm/baseline/liftoff-assembler.h` 定义了 V8 JavaScript 引擎中 Liftoff WebAssembly 基线编译器的核心组件：`LiftoffAssembler` 类。 该类负责生成目标架构的机器码来执行 WebAssembly 代码，并管理执行期间的寄存器和栈状态。 它提供了用于实现各种 WebAssembly 操作、控制流、函数调用和内存访问的方法。 虽然不是 Torque 代码，但它是 V8 执行 WebAssembly 功能的关键部分，与 JavaScript 通过 `WebAssembly` API 执行 Wasm 代码的能力息息相关。

Prompt: 
```
这是目录为v8/src/wasm/baseline/liftoff-assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/liftoff-assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_WASM_BASELINE_LIFTOFF_ASSEMBLER_H_
#define V8_WASM_BASELINE_LIFTOFF_ASSEMBLER_H_

#include <iosfwd>
#include <memory>

#include "src/base/bits.h"
#include "src/codegen/macro-assembler.h"
#include "src/wasm/baseline/liftoff-assembler-defs.h"
#include "src/wasm/baseline/liftoff-compiler.h"
#include "src/wasm/baseline/liftoff-register.h"
#include "src/wasm/baseline/liftoff-varstate.h"
#include "src/wasm/function-body-decoder.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-opcodes.h"
#include "src/wasm/wasm-value.h"

// Forward declarations.
namespace v8::internal::compiler {
class CallDescriptor;
}  // namespace v8::internal::compiler

namespace v8::internal::wasm {

inline constexpr Condition Negate(Condition cond) {
  switch (cond) {
    case kEqual:
      return kNotEqual;
    case kNotEqual:
      return kEqual;
    case kLessThan:
      return kGreaterThanEqual;
    case kLessThanEqual:
      return kGreaterThan;
    case kGreaterThanEqual:
      return kLessThan;
    case kGreaterThan:
      return kLessThanEqual;
    case kUnsignedLessThan:
      return kUnsignedGreaterThanEqual;
    case kUnsignedLessThanEqual:
      return kUnsignedGreaterThan;
    case kUnsignedGreaterThanEqual:
      return kUnsignedLessThan;
    case kUnsignedGreaterThan:
      return kUnsignedLessThanEqual;
    default:
      UNREACHABLE();
  }
}

inline constexpr Condition Flip(Condition cond) {
  switch (cond) {
    case kEqual:
      return kEqual;
    case kNotEqual:
      return kNotEqual;
    case kLessThan:
      return kGreaterThan;
    case kLessThanEqual:
      return kGreaterThanEqual;
    case kGreaterThanEqual:
      return kLessThanEqual;
    case kGreaterThan:
      return kLessThan;
    case kUnsignedLessThan:
      return kUnsignedGreaterThan;
    case kUnsignedLessThanEqual:
      return kUnsignedGreaterThanEqual;
    case kUnsignedGreaterThanEqual:
      return kUnsignedLessThanEqual;
    case kUnsignedGreaterThan:
      return kUnsignedLessThan;
    default:
      UNREACHABLE();
  }
}

class LiftoffAssembler;
class FreezeCacheState {
 public:
#if DEBUG
  explicit FreezeCacheState(LiftoffAssembler& assm);
  ~FreezeCacheState();

 private:
  LiftoffAssembler& assm_;
#else
  explicit FreezeCacheState(LiftoffAssembler& assm) {}
#endif
};

class LiftoffAssembler : public MacroAssembler {
 public:
  // Each slot in our stack frame currently has exactly 8 bytes.
  static constexpr int kStackSlotSize = 8;

  static constexpr ValueKind kIntPtrKind =
      kSystemPointerSize == kInt32Size ? kI32 : kI64;
  // A tagged value known to be a Smi can be treated like a ptr-sized int.
  static constexpr ValueKind kSmiKind = kTaggedSize == kInt32Size ? kI32 : kI64;

  using ValueKindSig = Signature<ValueKind>;

  using VarState = LiftoffVarState;

  struct CacheState {
    explicit CacheState(Zone* zone) : stack_state(zone) {}

    // Allow move construction and move assignment.
    CacheState(CacheState&&) V8_NOEXCEPT = default;
    CacheState& operator=(CacheState&&) V8_NOEXCEPT = default;
    // Disallow copy construction.
    CacheState(const CacheState&) = delete;

    enum class SpillLocation { kTopOfStack, kStackSlots };
    // Generates two lists of locations that contain references. {slots}
    // contains the indices of slots on the value stack that contain references.
    // {spills} contains all registers that contain references. The
    // {spill_location} defines where register values will be spilled for a
    // function call within the out-of-line code. {kStackSlots} means that the
    // values in the registers will be written back to their stack slots.
    // {kTopOfStack} means that the registers will be spilled on the stack with
    // a {push} instruction.
    void GetTaggedSlotsForOOLCode(/*out*/ ZoneVector<int>* slots,
                                  /*out*/ LiftoffRegList* spills,
                                  SpillLocation spill_location);

    void DefineSafepoint(SafepointTableBuilder::Safepoint& safepoint);

    void DefineSafepointWithCalleeSavedRegisters(
        SafepointTableBuilder::Safepoint& safepoint);

    // TODO(jkummerow): Wrap all accesses to {stack_state} in accessors that
    // check {frozen}.
    SmallZoneVector<VarState, 16> stack_state;
    LiftoffRegList used_registers;
    uint32_t register_use_count[kAfterMaxLiftoffRegCode] = {0};
    LiftoffRegList last_spilled_regs;
    Register cached_instance_data = no_reg;
    static constexpr int kNoCachedMemIndex = -1;
    // The index of the cached memory start, or {kNoCachedMemIndex} if none is
    // cached ({cached_mem_start} will be {no_reg} in that case).
    int cached_mem_index = kNoCachedMemIndex;
    Register cached_mem_start = no_reg;
#if DEBUG
    uint32_t frozen = 0;
#endif

    bool has_unused_register(RegClass rc, LiftoffRegList pinned = {}) const {
      if (kNeedI64RegPair && rc == kGpRegPair) {
        LiftoffRegList available_regs =
            kGpCacheRegList.MaskOut(used_registers).MaskOut(pinned);
        return available_regs.GetNumRegsSet() >= 2;
      } else if (kNeedS128RegPair && rc == kFpRegPair) {
        LiftoffRegList available_regs =
            kFpCacheRegList.MaskOut(used_registers).MaskOut(pinned);
        return available_regs.HasAdjacentFpRegsSet();
      }
      LiftoffRegList candidates = GetCacheRegList(rc);
      return has_unused_register(candidates.MaskOut(pinned));
    }

    bool has_unused_register(LiftoffRegList candidates) const {
      LiftoffRegList available_regs = candidates.MaskOut(used_registers);
      return !available_regs.is_empty();
    }

    LiftoffRegister unused_register(RegClass rc,
                                    LiftoffRegList pinned = {}) const {
      if (kNeedI64RegPair && rc == kGpRegPair) {
        Register low = pinned.set(unused_register(kGpReg, pinned)).gp();
        Register high = unused_register(kGpReg, pinned).gp();
        return LiftoffRegister::ForPair(low, high);
      } else if (kNeedS128RegPair && rc == kFpRegPair) {
        LiftoffRegList available_regs =
            kFpCacheRegList.MaskOut(used_registers).MaskOut(pinned);
        DoubleRegister low =
            available_regs.GetAdjacentFpRegsSet().GetFirstRegSet().fp();
        DCHECK(is_free(LiftoffRegister::ForFpPair(low)));
        return LiftoffRegister::ForFpPair(low);
      }
      LiftoffRegList candidates = GetCacheRegList(rc);
      return unused_register(candidates, pinned);
    }

    LiftoffRegister unused_register(LiftoffRegList candidates,
                                    LiftoffRegList pinned = {}) const {
      LiftoffRegList available_regs =
          candidates.MaskOut(used_registers).MaskOut(pinned);
      return available_regs.GetFirstRegSet();
    }

    // Volatile registers are registers which are used for caching values that
    // can easily be reloaded. Those are returned first if we run out of free
    // registers.
    bool has_volatile_register(LiftoffRegList candidates) {
      return (cached_instance_data != no_reg &&
              candidates.has(cached_instance_data)) ||
             (cached_mem_start != no_reg && candidates.has(cached_mem_start));
    }

    LiftoffRegister take_volatile_register(LiftoffRegList candidates) {
      DCHECK(!frozen);
      DCHECK(has_volatile_register(candidates));
      Register reg = no_reg;
      if (cached_instance_data != no_reg &&
          candidates.has(cached_instance_data)) {
        reg = cached_instance_data;
        cached_instance_data = no_reg;
      } else {
        DCHECK(candidates.has(cached_mem_start));
        reg = cached_mem_start;
        cached_mem_start = no_reg;
        cached_mem_index = kNoCachedMemIndex;
      }

      LiftoffRegister ret{reg};
      DCHECK_EQ(1, register_use_count[ret.liftoff_code()]);
      register_use_count[ret.liftoff_code()] = 0;
      used_registers.clear(ret);
      return ret;
    }

    void SetCacheRegister(Register* cache, Register reg) {
      DCHECK(!frozen);
      DCHECK_EQ(no_reg, *cache);
      *cache = reg;
      int liftoff_code = LiftoffRegister{reg}.liftoff_code();
      DCHECK_EQ(0, register_use_count[liftoff_code]);
      register_use_count[liftoff_code] = 1;
      used_registers.set(reg);
    }

    void SetInstanceCacheRegister(Register reg) {
      SetCacheRegister(&cached_instance_data, reg);
    }

    void SetMemStartCacheRegister(Register reg, int memory_index) {
      SetCacheRegister(&cached_mem_start, reg);
      DCHECK_EQ(kNoCachedMemIndex, cached_mem_index);
      cached_mem_index = memory_index;
    }

    Register TrySetCachedInstanceRegister(LiftoffRegList pinned) {
      DCHECK_EQ(no_reg, cached_instance_data);
      LiftoffRegList available_regs =
          kGpCacheRegList.MaskOut(pinned).MaskOut(used_registers);
      if (available_regs.is_empty()) return no_reg;
      // Prefer the {kWasmImplicitArgRegister}, because that's where the
      // instance data initially is, and where it needs to be for calls.
      Register new_cache_reg = available_regs.has(kWasmImplicitArgRegister)
                                   ? kWasmImplicitArgRegister
                                   : available_regs.GetFirstRegSet().gp();
      SetInstanceCacheRegister(new_cache_reg);
      DCHECK_EQ(new_cache_reg, cached_instance_data);
      return new_cache_reg;
    }

    V8_INLINE void ClearCacheRegister(Register* cache) {
      DCHECK(!frozen);
      V8_ASSUME(cache == &cached_instance_data || cache == &cached_mem_start);
      if (*cache == no_reg) return;
      int liftoff_code = LiftoffRegister{*cache}.liftoff_code();
      DCHECK_EQ(1, register_use_count[liftoff_code]);
      register_use_count[liftoff_code] = 0;
      used_registers.clear(*cache);
      *cache = no_reg;
    }

    void ClearCachedInstanceRegister() {
      ClearCacheRegister(&cached_instance_data);
    }

    void ClearCachedMemStartRegister() {
      V8_ASSUME(cached_mem_index == kNoCachedMemIndex || cached_mem_index >= 0);
      if (cached_mem_index == kNoCachedMemIndex) return;
      cached_mem_index = kNoCachedMemIndex;
      DCHECK_NE(no_reg, cached_mem_start);
      ClearCacheRegister(&cached_mem_start);
    }

    void ClearAllCacheRegisters() {
      ClearCachedInstanceRegister();
      ClearCachedMemStartRegister();
    }

    void inc_used(LiftoffRegister reg) {
      DCHECK(!frozen);
      if (reg.is_pair()) {
        inc_used(reg.low());
        inc_used(reg.high());
        return;
      }
      used_registers.set(reg);
      DCHECK_GT(kMaxInt, register_use_count[reg.liftoff_code()]);
      ++register_use_count[reg.liftoff_code()];
    }

    // Returns whether this was the last use.
    void dec_used(LiftoffRegister reg) {
      DCHECK(!frozen);
      DCHECK(is_used(reg));
      if (reg.is_pair()) {
        dec_used(reg.low());
        dec_used(reg.high());
        return;
      }
      int code = reg.liftoff_code();
      DCHECK_LT(0, register_use_count[code]);
      if (--register_use_count[code] == 0) used_registers.clear(reg);
    }

    bool is_used(LiftoffRegister reg) const {
      if (reg.is_pair()) return is_used(reg.low()) || is_used(reg.high());
      bool used = used_registers.has(reg);
      DCHECK_EQ(used, register_use_count[reg.liftoff_code()] != 0);
      return used;
    }

    uint32_t get_use_count(LiftoffRegister reg) const {
      if (reg.is_pair()) {
        DCHECK_EQ(register_use_count[reg.low().liftoff_code()],
                  register_use_count[reg.high().liftoff_code()]);
        reg = reg.low();
      }
      DCHECK_GT(arraysize(register_use_count), reg.liftoff_code());
      return register_use_count[reg.liftoff_code()];
    }

    void clear_used(LiftoffRegister reg) {
      DCHECK(!frozen);
      if (reg.is_pair()) {
        clear_used(reg.low());
        clear_used(reg.high());
        return;
      }
      register_use_count[reg.liftoff_code()] = 0;
      used_registers.clear(reg);
    }

    bool is_free(LiftoffRegister reg) const { return !is_used(reg); }

    void reset_used_registers() {
      DCHECK(!frozen);
      used_registers = {};
      memset(register_use_count, 0, sizeof(register_use_count));
    }

    LiftoffRegister GetNextSpillReg(LiftoffRegList candidates) {
      DCHECK(!frozen);
      DCHECK(!candidates.is_empty());
      // This method should only be called if none of the candidates is free.
      DCHECK(candidates.MaskOut(used_registers).is_empty());
      LiftoffRegList unspilled = candidates.MaskOut(last_spilled_regs);
      if (unspilled.is_empty()) {
        unspilled = candidates;
        last_spilled_regs = {};
      }
      LiftoffRegister reg = unspilled.GetFirstRegSet();
      return reg;
    }

    void Steal(CacheState& source);

    void Split(const CacheState& source);

    uint32_t stack_height() const {
      return static_cast<uint32_t>(stack_state.size());
    }

   private:
    // Make the copy assignment operator private (to be used from {Split()}).
    CacheState& operator=(const CacheState&) V8_NOEXCEPT = default;
  };

  explicit LiftoffAssembler(Zone*, std::unique_ptr<AssemblerBuffer>);
  ~LiftoffAssembler() override;

  Zone* zone() const { return cache_state_.stack_state.get_allocator().zone(); }

  // Load a cache slot to a free register.
  V8_INLINE LiftoffRegister LoadToRegister(VarState slot,
                                           LiftoffRegList pinned) {
    if (V8_LIKELY(slot.is_reg())) return slot.reg();
    return LoadToRegister_Slow(slot, pinned);
  }

  // Slow path called for the method above.
  V8_NOINLINE V8_PRESERVE_MOST LiftoffRegister
  LoadToRegister_Slow(VarState slot, LiftoffRegList pinned);

  // Load a non-register cache slot to a given (fixed) register.
  inline void LoadToFixedRegister(VarState slot, LiftoffRegister reg);

  // Load a cache slot to a register that has no other uses, so it can be
  // modified.
  LiftoffRegister LoadToModifiableRegister(VarState slot,
                                           LiftoffRegList pinned) {
    LiftoffRegister reg = LoadToRegister(slot, pinned);
    // TODO(jkummerow): The following line is overly optimistic, as long as
    // we don't pop the VarState, the register will never be considered free.
    if (cache_state()->is_free(reg) && !pinned.has(reg)) return reg;

    LiftoffRegister new_reg = GetUnusedRegister(reg.reg_class(), pinned);
    // {new_reg} could be equal to {reg}, but it's unused by the stack now.
    // Also, {reg} still holds the previous value, even if it was spilled.
    if (new_reg != reg) Move(new_reg, reg, slot.kind());
    return new_reg;
  }

  // Pop a VarState from the stack, updating the register use count accordingly.
  V8_INLINE VarState PopVarState() {
    DCHECK(!cache_state_.stack_state.empty());
    VarState slot = cache_state_.stack_state.back();
    cache_state_.stack_state.pop_back();
    if (V8_LIKELY(slot.is_reg())) cache_state_.dec_used(slot.reg());
    return slot;
  }

  V8_INLINE LiftoffRegister PopToRegister(LiftoffRegList pinned = {}) {
    VarState slot = PopVarState();
    return LoadToRegister(slot, pinned);
  }

  inline void PopToFixedRegister(LiftoffRegister reg);

  // Use this to pop a value into a register that has no other uses, so it
  // can be modified.
  LiftoffRegister PopToModifiableRegister(LiftoffRegList pinned = {}) {
    ValueKind kind = cache_state_.stack_state.back().kind();
    LiftoffRegister reg = PopToRegister(pinned);
    if (cache_state()->is_free(reg) && !pinned.has(reg)) return reg;

    LiftoffRegister new_reg = GetUnusedRegister(reg.reg_class(), pinned);
    // {new_reg} could be equal to {reg}, but it's unused by the stack now.
    // Also, {reg} still holds the previous value, even if it was spilled.
    if (new_reg != reg) Move(new_reg, reg, kind);
    return new_reg;
  }

  // Returns the register which holds the value of stack slot {index}. If the
  // value is not stored in a register yet, a register is allocated for it. The
  // register is then assigned to the stack slot. The value stack height is not
  // modified. The top of the stack is index 0, i.e. {PopToRegister()} and
  // {PeekToRegister(0)} should result in the same register.
  // When the value is finally popped, the use counter of its register has to be
  // decremented. This can be done by popping the value with {DropValues}.
  LiftoffRegister PeekToRegister(int index, LiftoffRegList pinned) {
    DCHECK_LT(index, cache_state_.stack_state.size());
    VarState& slot = cache_state_.stack_state.end()[-1 - index];
    if (V8_LIKELY(slot.is_reg())) return slot.reg();
    LiftoffRegister reg = LoadToRegister(slot, pinned);
    cache_state_.inc_used(reg);
    slot.MakeRegister(reg);
    return reg;
  }

  void DropValues(int count) {
    DCHECK_GE(cache_state_.stack_state.size(), count);
    for (VarState& slot :
         base::VectorOf(cache_state_.stack_state.end() - count, count)) {
      if (slot.is_reg()) {
        cache_state_.dec_used(slot.reg());
      }
    }
    cache_state_.stack_state.pop_back(count);
  }

  // Drop a specific value from the stack; this is an expensive operation which
  // is currently only used for exceptions.
  // Careful: this indexes "from the other end", i.e. offset=0 is the value at
  // the bottom of the stack.
  void DropExceptionValueAtOffset(int offset);

  // Spill all loop inputs to the stack to free registers and to ensure that we
  // can merge different values on the back-edge.
  void SpillLoopArgs(int num);

  V8_INLINE static int NextSpillOffset(ValueKind kind, int top_spill_offset);
  V8_INLINE int NextSpillOffset(ValueKind kind);
  inline int TopSpillOffset() const;

  inline void PushRegister(ValueKind kind, LiftoffRegister reg);

  // Assumes that the exception is in {kReturnRegister0}. This is where the
  // exception is stored by the unwinder after a throwing call.
  inline void PushException();

  inline void PushConstant(ValueKind kind, int32_t i32_const);

  inline void PushStack(ValueKind kind);

  V8_NOINLINE V8_PRESERVE_MOST void SpillRegister(LiftoffRegister);

  uint32_t GetNumUses(LiftoffRegister reg) const {
    return cache_state_.get_use_count(reg);
  }

  // Get an unused register for class {rc}, reusing one of {try_first} if
  // possible.
  LiftoffRegister GetUnusedRegister(
      RegClass rc, std::initializer_list<LiftoffRegister> try_first,
      LiftoffRegList pinned) {
    DCHECK(!cache_state_.frozen);
    for (LiftoffRegister reg : try_first) {
      DCHECK_EQ(reg.reg_class(), rc);
      if (cache_state_.is_free(reg)) return reg;
    }
    return GetUnusedRegister(rc, pinned);
  }

  // Get an unused register for class {rc}, excluding registers from {pinned},
  // potentially spilling to free one.
  LiftoffRegister GetUnusedRegister(RegClass rc, LiftoffRegList pinned) {
    DCHECK(!cache_state_.frozen);
    if (kNeedI64RegPair && rc == kGpRegPair) {
      LiftoffRegList candidates = kGpCacheRegList.MaskOut(pinned);
      Register low = candidates.clear(GetUnusedRegister(candidates)).gp();
      Register high = GetUnusedRegister(candidates).gp();
      return LiftoffRegister::ForPair(low, high);
    } else if (kNeedS128RegPair && rc == kFpRegPair) {
      // kFpRegPair specific logic here because we need adjacent registers, not
      // just any two registers (like kGpRegPair).
      if (cache_state_.has_unused_register(rc, pinned)) {
        return cache_state_.unused_register(rc, pinned);
      }
      DoubleRegister low_fp = SpillAdjacentFpRegisters(pinned).fp();
      return LiftoffRegister::ForFpPair(low_fp);
    }
    LiftoffRegList candidates = GetCacheRegList(rc).MaskOut(pinned);
    return GetUnusedRegister(candidates);
  }

  // Get an unused register of {candidates}, potentially spilling to free one.
  LiftoffRegister GetUnusedRegister(LiftoffRegList candidates) {
    DCHECK(!cache_state_.frozen);
    DCHECK(!candidates.is_empty());
    if (V8_LIKELY(cache_state_.has_unused_register(candidates))) {
      return cache_state_.unused_register(candidates);
    }
    return SpillOneRegister(candidates);
  }

  // Performs operations on locals and the top {arity} value stack entries
  // that would (very likely) have to be done by branches. Doing this up front
  // avoids making each subsequent (conditional) branch repeat this work.
  void PrepareForBranch(uint32_t arity, LiftoffRegList pinned);

  // These methods handle control-flow merges. {MergeIntoNewState} is used to
  // generate a new {CacheState} for a merge point, and also emits code to
  // transfer values from the current state to the new merge state.
  // {MergeFullStackWith} and {MergeStackWith} then later generate the code for
  // more merges into an existing state.
  V8_NODISCARD CacheState MergeIntoNewState(uint32_t num_locals, uint32_t arity,
                                            uint32_t stack_depth);
  void MergeFullStackWith(CacheState& target);
  enum JumpDirection { kForwardJump, kBackwardJump };
  void MergeStackWith(CacheState& target, uint32_t arity, JumpDirection);

  void Spill(VarState* slot);
  void SpillLocals();
  void SpillAllRegisters();
  inline void LoadSpillAddress(Register dst, int offset, ValueKind kind);

  // Clear any uses of {reg} in both the cache and in {possible_uses}.
  // Any use in the stack is spilled. If any register in {possible_uses} matches
  // {reg}, then the content of {reg} is moved to a new temporary register, and
  // all matches in {possible_uses} are rewritten to that temporary register.
  void ClearRegister(Register reg,
                     std::initializer_list<Register*> possible_uses,
                     LiftoffRegList pinned);

  // Spills all passed registers.
  template <typename... Regs>
  void SpillRegisters(Regs... regs) {
    for (LiftoffRegister r : {LiftoffRegister(regs)...}) {
      if (cache_state_.is_free(r)) continue;
      if (r.is_gp() && cache_state_.cached_instance_data == r.gp()) {
        cache_state_.ClearCachedInstanceRegister();
      } else if (r.is_gp() && cache_state_.cached_mem_start == r.gp()) {
        V8_ASSUME(cache_state_.cached_mem_index >= 0);
        cache_state_.ClearCachedMemStartRegister();
      } else {
        SpillRegister(r);
      }
    }
  }

  // Call this method whenever spilling something, such that the number of used
  // spill slot can be tracked and the stack frame will be allocated big enough.
  void RecordUsedSpillOffset(int offset) {
    if (offset >= max_used_spill_offset_) max_used_spill_offset_ = offset;
  }

  void RecordOolSpillSpaceSize(int size) {
    if (size > ool_spill_space_size_) ool_spill_space_size_ = size;
  }

  // Load parameters into the right registers / stack slots for the call.
  void PrepareBuiltinCall(const ValueKindSig* sig,
                          compiler::CallDescriptor* call_descriptor,
                          std::initializer_list<VarState> params);

  // Load parameters into the right registers / stack slots for the call.
  // Move {*target} into another register if needed and update {*target} to that
  // register, or {no_reg} if target was spilled to the stack.
  void PrepareCall(const ValueKindSig*, compiler::CallDescriptor*,
                   Register* target = nullptr,
                   Register target_instance = no_reg);
  // Process return values of the call.
  void FinishCall(const ValueKindSig*, compiler::CallDescriptor*);

  // Move {src} into {dst}. {src} and {dst} must be different.
  void Move(LiftoffRegister dst, LiftoffRegister src, ValueKind);

  // Parallel register move: For a list of tuples <dst, src, kind>, move the
  // {src} register of kind {kind} into {dst}. If {src} equals {dst}, ignore
  // that tuple.
  struct ParallelRegisterMoveTuple {
    LiftoffRegister dst;
    LiftoffRegister src;
    ValueKind kind;
    template <typename Dst, typename Src>
    ParallelRegisterMoveTuple(Dst dst, Src src, ValueKind kind)
        : dst(dst), src(src), kind(kind) {}
  };

  void ParallelRegisterMove(base::Vector<const ParallelRegisterMoveTuple>);

  void ParallelRegisterMove(
      std::initializer_list<ParallelRegisterMoveTuple> moves) {
    ParallelRegisterMove(base::VectorOf(moves));
  }

  // Move the top stack values into the expected return locations specified by
  // the given call descriptor.
  void MoveToReturnLocations(const FunctionSig*, compiler::CallDescriptor*);
  // Slow path for multi-return, called from {MoveToReturnLocations}.
  V8_NOINLINE V8_PRESERVE_MOST void MoveToReturnLocationsMultiReturn(
      const FunctionSig*, compiler::CallDescriptor*);
#if DEBUG
  void SetCacheStateFrozen() { cache_state_.frozen++; }
  void UnfreezeCacheState() {
    DCHECK_GT(cache_state_.frozen, 0);
    cache_state_.frozen--;
  }
#endif
#ifdef ENABLE_SLOW_DCHECKS
  // Validate that the register use counts reflect the state of the cache.
  bool ValidateCacheState() const;
#endif

  inline void LoadFixedArrayLengthAsInt32(LiftoffRegister dst, Register array,
                                          LiftoffRegList pinned);

  inline void LoadSmiAsInt32(LiftoffRegister dst, Register src_addr,
                             int32_t offset);

  ////////////////////////////////////
  // Platform-specific part.        //
  ////////////////////////////////////

  // This function emits machine code to prepare the stack frame, before the
  // size of the stack frame is known. It returns an offset in the machine code
  // which can later be patched (via {PatchPrepareStackFrame)} when the size of
  // the frame is known.
  inline int PrepareStackFrame();
  inline void CallFrameSetupStub(int declared_function_index);
  inline void PrepareTailCall(int num_callee_stack_params,
                              int stack_param_delta);
  inline void AlignFrameSize();
  inline void PatchPrepareStackFrame(int offset, SafepointTableBuilder*,
                                     bool feedback_vector_slot,
                                     size_t stack_param_slots);
  inline void FinishCode();
  inline void AbortCompilation();
  inline static constexpr int StaticStackFrameSize();
  inline static int SlotSizeForType(ValueKind kind);
  inline static bool NeedsAlignment(ValueKind kind);

  inline void CheckTierUp(int declared_func_index, int budget_used,
                          Label* ool_label, const FreezeCacheState& frozen);
  inline Register LoadOldFramePointer();
  inline void CheckStackShrink();
  inline void LoadConstant(LiftoffRegister, WasmValue);
  inline void LoadInstanceDataFromFrame(Register dst);
  inline void LoadTrustedPointer(Register dst, Register src_addr, int offset,
                                 IndirectPointerTag tag);
  inline void LoadFromInstance(Register dst, Register instance, int offset,
                               int size);
  inline void LoadTaggedPointerFromInstance(Register dst, Register instance,
                                            int offset);
  inline void SpillInstanceData(Register instance);
  inline void ResetOSRTarget();
  inline void LoadTaggedPointer(Register dst, Register src_addr,
                                Register offset_reg, int32_t offset_imm,
                                uint32_t* protected_load_pc = nullptr,
                                bool offset_reg_needs_shift = false);
  inline void LoadProtectedPointer(Register dst, Register src_addr,
                                   int32_t offset);
  inline void LoadFullPointer(Register dst, Register src_addr,
                              int32_t offset_imm);
  inline void LoadCodePointer(Register dst, Register src_addr, int32_t offset);
#ifdef V8_ENABLE_SANDBOX
  inline void LoadCodeEntrypointViaCodePointer(Register dsr, Register src_addr,
                                               int offset_imm);
#endif
  enum SkipWriteBarrier : bool {
    kSkipWriteBarrier = true,
    kNoSkipWriteBarrier = false
  };
  inline void StoreTaggedPointer(Register dst_addr, Register offset_reg,
                                 int32_t offset_imm, Register src,
                                 LiftoffRegList pinned,
                                 uint32_t* protected_store_pc = nullptr,
                                 SkipWriteBarrier = kNoSkipWriteBarrier);
  // Warning: may clobber {dst} on some architectures!
  inline void IncrementSmi(LiftoffRegister dst, int offset);
  inline void Load(LiftoffRegister dst, Register src_addr, Register offset_reg,
                   uintptr_t offset_imm, LoadType type,
                   uint32_t* protected_load_pc = nullptr,
                   bool is_load_mem = false, bool i64_offset = false,
                   bool needs_shift = false);
  inline void Store(Register dst_addr, Register offset_reg,
                    uintptr_t offset_imm, LiftoffRegister src, StoreType type,
                    LiftoffRegList pinned,
                    uint32_t* protected_store_pc = nullptr,
                    bool is_store_mem = false, bool i64_offset = false);
  inline void AtomicLoad(LiftoffRegister dst, Register src_addr,
                         Register offset_reg, uintptr_t offset_imm,
                         LoadType type, LiftoffRegList pinned, bool i64_offset);
  inline void AtomicStore(Register dst_addr, Register offset_reg,
                          uintptr_t offset_imm, LiftoffRegister src,
                          StoreType type, LiftoffRegList pinned,
                          bool i64_offset);

  inline void AtomicAdd(Register dst_addr, Register offset_reg,
                        uintptr_t offset_imm, LiftoffRegister value,
                        LiftoffRegister result, StoreType type,
                        bool i64_offset);

  inline void AtomicSub(Register dst_addr, Register offset_reg,
                        uintptr_t offset_imm, LiftoffRegister value,
                        LiftoffRegister result, StoreType type,
                        bool i64_offset);

  inline void AtomicAnd(Register dst_addr, Register offset_reg,
                        uintptr_t offset_imm, LiftoffRegister value,
                        LiftoffRegister result, StoreType type,
                        bool i64_offset);

  inline void AtomicOr(Register dst_addr, Register offset_reg,
                       uintptr_t offset_imm, LiftoffRegister value,
                       LiftoffRegister result, StoreType type, bool i64_offset);

  inline void AtomicXor(Register dst_addr, Register offset_reg,
                        uintptr_t offset_imm, LiftoffRegister value,
                        LiftoffRegister result, StoreType type,
                        bool i64_offset);

  inline void AtomicExchange(Register dst_addr, Register offset_reg,
                             uintptr_t offset_imm, LiftoffRegister value,
                             LiftoffRegister result, StoreType type,
                             bool i64_offset);

  inline void AtomicCompareExchange(Register dst_addr, Register offset_reg,
                                    uintptr_t offset_imm,
                                    LiftoffRegister expected,
                                    LiftoffRegister new_value,
                                    LiftoffRegister value, StoreType type,
                                    bool i64_offset);

  inline void AtomicFence();

  inline void LoadCallerFrameSlot(LiftoffRegister, uint32_t caller_slot_idx,
                                  ValueKind);
  inline void StoreCallerFrameSlot(LiftoffRegister, uint32_t caller_slot_idx,
                                   ValueKind, Register frame_pointer);
  inline void LoadReturnStackSlot(LiftoffRegister, int offset, ValueKind);
  inline void MoveStackValue(uint32_t dst_offset, uint32_t src_offset,
                             ValueKind);

  inline void Move(Register dst, Register src, ValueKind);
  inline void Move(DoubleRegister dst, DoubleRegister src, ValueKind);

  inline void Spill(int offset, LiftoffRegister, ValueKind);
  inline void Spill(int offset, WasmValue);
  inline void Fill(LiftoffRegister, int offset, ValueKind);
  // Only used on 32-bit systems: Fill a register from a "half stack slot", i.e.
  // 4 bytes on the stack holding half of a 64-bit value.
  inline void FillI64Half(Register, int offset, RegPairHalf);
  inline void FillStackSlotsWithZero(int start, int size);

  inline void emit_trace_instruction(uint32_t markid);

  // i32 binops.
  inline void emit_i32_add(Register dst, Register lhs, Register rhs);
  inline void emit_i32_addi(Register dst, Register lhs, int32_t imm);
  inline void emit_i32_sub(Register dst, Register lhs, Register rhs);
  inline void emit_i32_subi(Register dst, Register lhs, int32_t imm);
  inline void emit_i32_mul(Register dst, Register lhs,
"""


```