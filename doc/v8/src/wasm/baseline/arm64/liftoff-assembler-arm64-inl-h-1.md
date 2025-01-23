Response:
My thinking process to arrive at the summarized functionality goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided C++ code snippet. It also mentions the context of this being part 2 of a larger sequence, implying a need for a concise yet informative summary.

2. **Identify the Core Purpose:**  I scanned the code for recurring patterns and function names. The frequent use of `AtomicLoad`, `AtomicStore`, `AtomicAdd`, `AtomicSub`, etc., immediately signals that the primary focus is on **atomic operations**. The presence of `LiftoffAssembler` further clarifies this is related to code generation within the V8 JavaScript engine's liftoff compiler for the ARM64 architecture.

3. **Group Related Functionality:**  I started grouping the functions based on their prefixes and the operations they perform:
    * **Atomic Operations:**  Clearly a major section. I noted the different atomic operations like load, store, add, subtract, and, or, xor, exchange, and compare-exchange.
    * **Stack Management:** Functions like `LoadCallerFrameSlot`, `StoreCallerFrameSlot`, `LoadReturnStackSlot`, `MoveStackValue`, `Spill`, `Fill`, and `FillStackSlotsWithZero` are all related to managing data on the stack.
    * **Basic Arithmetic and Logic:**  The `emit_i32_...` and `emit_i64_...` functions perform basic integer arithmetic and logical operations (add, sub, mul, and, or, xor, shift, etc.).
    * **Floating-Point Operations:** The `emit_f32_...` and `emit_f64_...` functions perform floating-point arithmetic and other operations (add, sub, mul, div, min, max, abs, neg, ceil, floor, trunc, nearest int, sqrt).
    * **Bit Manipulation:** Functions like `emit_i32_clz`, `emit_i32_ctz`, `emit_i32_popcnt`, `emit_i64_clz`, `emit_i64_ctz`, and `emit_i64_popcnt` deal with counting leading zeros, trailing zeros, and set bits.
    * **Division and Remainder:**  The `emit_i32_divs`, `emit_i32_divu`, `emit_i32_rems`, `emit_i32_remu`, `emit_i64_divs`, and `emit_i64_remu` functions handle integer division and remainder operations, including checks for division by zero and unrepresentable results.
    * **Move Operations:** `Move` functions for registers and stack values.
    * **Addressing:** `LoadSpillAddress` for getting the address of a stack slot.
    * **Increment:** `IncrementSmi` for incrementing Small Integers.
    * **Fence:** `AtomicFence` for memory barrier.

4. **Identify Key Concepts:**  Within the grouped functionality, I identified some important concepts:
    * **Atomic Operations and Memory Ordering:** The atomic operations are crucial for concurrent programming, ensuring data consistency. The presence of `AtomicFence` reinforces this.
    * **Stack Frame Management:**  The functions for loading and storing caller frame slots and return stack slots are essential for function calls and returns.
    * **Register Allocation and Usage:**  The code uses `LiftoffRegister` and `UseScratchRegisterScope`, indicating a concern for efficient register usage during code generation.
    * **Data Types:** The code explicitly handles different data types (i32, i64, f32, f64), as seen in the function naming conventions.

5. **Synthesize the Summary:**  Based on the grouped functionality and key concepts, I formulated a concise summary. I aimed for clarity and avoided overly technical jargon while still conveying the essential purpose of the code. I structured the summary by category of operations: atomic operations, stack management, arithmetic/logical operations, and other utility functions. I also made sure to highlight the architectural context (ARM64) and the purpose within V8 (liftoff compiler).

6. **Refine and Review:** I reviewed the summary to ensure accuracy and completeness, considering the context of it being part 2 of a larger series. I wanted to make it informative without repeating too much detail that might be covered in other parts.

This systematic approach of identifying the core purpose, grouping related functionality, and synthesizing a concise summary allowed me to effectively capture the essence of the provided code snippet. The iterative refinement step ensured the summary was both accurate and easy to understand.
Based on the provided code snippet, here's a breakdown of its functionality within the context of `v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h`, which is part of V8's Liftoff compiler for WebAssembly on ARM64 architecture:

**Core Functionality:**

This code snippet implements various low-level assembly instructions for performing **atomic operations** and **basic arithmetic/logical operations** on the ARM64 architecture within the Liftoff compiler. It focuses on operations that interact directly with memory in an atomic (indivisible) manner and fundamental computations on integer and floating-point values.

**Specific Functionalities:**

* **Atomic Memory Operations:**
    * **Atomic Load:**  Loads a value from memory atomically. Different sizes (8-bit, 16-bit, 32-bit, 64-bit) and signed/unsigned variations are handled.
    * **Atomic Store:** Stores a value to memory atomically. Handles different sizes.
    * **Atomic Read-Modify-Write Operations:** Implements atomic operations like Add, Subtract, And, Or, Xor, and Exchange. These operations read a value from memory, perform an operation with a given value, and then write the result back to memory, all as a single atomic step. It uses both Load-Exclusive/Store-Exclusive (LDXR/STXR) loops for architectures without native atomic instructions for these operations and optimized instructions (like `ldaddal`, `ldsetal` etc.) when the Large System Extensions (LSE) are available.
    * **Atomic Compare and Exchange (CAS):** Atomically compares a value in memory with an expected value. If they match, it replaces the memory value with a new value. Again, it handles both LSE-optimized and fallback LDXR/STXR implementations.
    * **Atomic Fence:** Inserts a memory barrier (`Dmb`) to ensure proper memory ordering between threads or cores.

* **Stack Frame and Local Variable Management:**
    * **Load/Store Caller Frame Slot:** Accesses values in the stack frame of the calling function.
    * **Load Return Stack Slot:** Loads values from the return stack slot.
    * **Move Stack Value:** Copies a value from one stack location to another.
    * **Spill:** Stores the value of a register onto the stack.
    * **Fill:** Loads a value from the stack into a register.
    * **Fill Stack Slots With Zero:** Initializes a range of stack slots with zero.
    * **Load Spill Address:** Calculates the memory address of a stack slot.

* **Basic Arithmetic and Logical Operations:**
    * **Integer Operations (32-bit and 64-bit):** Implements common arithmetic operations (add, subtract, multiply) and bitwise logical operations (and, or, xor, shift left, shift right arithmetic, shift right logical). Includes immediate operands for some operations.
    * **Floating-Point Operations (32-bit and 64-bit):** Implements standard floating-point arithmetic operations (add, subtract, multiply, divide, min, max), absolute value, negation, and some mathematical functions (ceil, floor, truncate, nearest integer, square root).

* **Bit Manipulation Operations:**
    * **Count Leading Zeros (CLZ):** Counts the number of leading zero bits.
    * **Count Trailing Zeros (CTZ):** Counts the number of trailing zero bits.
    * **Population Count (Popcnt):** Counts the number of set bits.

* **Integer Division and Remainder (with overflow/zero checks):**
    * Implements signed and unsigned integer division and remainder operations, including checks for division by zero and handling of unrepresentable results (like the minimum integer divided by -1).

* **Smi (Small Integer) Handling:**
    * **IncrementSmi:**  Increments a Smi value stored in memory. This handles the tagging of small integers in V8.

* **Move Operations:** Copies the value between registers (integer and floating-point).

**Is it a Torque file?**

The filename ends in `.h`, not `.tq`. Therefore, it is **not** a V8 Torque source file. It's a standard C++ header file containing inline function definitions for the ARM64 Liftoff assembler.

**Relationship to JavaScript:**

While this code is low-level assembly, it's directly related to the execution of JavaScript code within V8. When JavaScript code involving atomic operations or basic arithmetic is compiled by the Liftoff compiler for ARM64, the functions defined in this header file are used to generate the corresponding machine code.

**Example (Atomic Increment):**

Imagine a JavaScript scenario involving shared memory and atomic operations:

```javascript
// SharedArrayBuffer 'sab' is a shared memory region
const atomicView = new Int32Array(sab);
const index = 0;

// Atomically increment the value at index 0
Atomics.add(atomicView, index, 1);

console.log(atomicView[index]);
```

The `Atomics.add` operation in this JavaScript code would eventually be translated by the Liftoff compiler into a sequence of ARM64 instructions, potentially using the `AtomicAdd` function defined in the provided C++ snippet.

**Code Logic Inference (Atomic Add):**

Let's consider the `AtomicAdd` function:

**Hypothetical Input:**

* `dst_addr`: Register holding the memory address to modify (e.g., `x10`).
* `offset_reg`:  No offset register is used in this example (could be `no_reg`).
* `offset_imm`: Immediate offset of 0.
* `value`: `LiftoffRegister` representing the value to add (e.g., a register holding the value `5`).
* `result`: `LiftoffRegister` where the original value at the memory location will be stored.
* `type`: `StoreType::kI32Store` (indicating a 32-bit integer atomic operation).

**Expected Output (Conceptual):**

1. The code will calculate the effective memory address (in this case, it's just the value in `dst_addr`).
2. Depending on whether LSE is supported:
   * **With LSE:**  It will use the `ldaddal` instruction to atomically add the value in the `value` register to the memory location pointed to by `dst_addr`, storing the original value at that location in the `result` register.
   * **Without LSE:** It will enter a loop:
      * Load the current value from the memory location atomically using `ldaxr`.
      * Add the `value` to the loaded value.
      * Attempt to store the new value back to the memory location atomically using `stlxr`.
      * If the store fails (another thread modified the memory in the meantime), the loop retries.
3. The `result` register will contain the original value that was at the memory location before the addition.

**User Programming Errors (Related to Atomic Operations):**

* **Incorrect Memory Ordering:**  Failing to use memory fences (`AtomicFence`) when necessary can lead to unexpected behavior in multi-threaded scenarios due to compiler and CPU optimizations reordering memory accesses. For example, one thread might observe changes made by another thread in a different order than they actually happened.
* **Data Races:**  Multiple threads accessing and modifying the same memory location without proper synchronization (like atomic operations) can lead to unpredictable and corrupted data. Using regular loads and stores instead of atomic operations on shared memory is a common source of data races.
* **ABA Problem (in CAS scenarios):** If a value is changed from A to B and then back to A between the load and store in a non-atomic compare-and-swap implementation, the CAS might incorrectly succeed, even though the underlying data has changed temporarily. The atomic CAS instructions provided here mitigate this risk.

**Summary of Functionality (for Part 2):**

This part of the `liftoff-assembler-arm64-inl.h` header file focuses on providing **low-level building blocks for atomic memory operations, basic arithmetic and logical computations, and stack management** within the V8 Liftoff compiler for the ARM64 architecture. It defines inline functions that emit specific ARM64 assembly instructions to perform these operations efficiently, handling both scenarios with and without hardware support for certain atomic instructions. These functions are crucial for the correct and performant execution of WebAssembly (and by extension, JavaScript using shared memory) on ARM64 platforms.

### 提示词
```
这是目录为v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/arm64/liftoff-assembler-arm64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
alb(temp, result.gp().W(), MemOperand(actual_addr));
            break;
          }
          case StoreType::kI64Store16:
          case StoreType::kI32Store16: {
            UseScratchRegisterScope temps(lasm);
            Register temp = temps.AcquireW();
            __ mvn(temp, value.gp().W());
            __ ldclralh(temp, result.gp().W(), MemOperand(actual_addr));
            break;
          }
          case StoreType::kI64Store32:
          case StoreType::kI32Store: {
            UseScratchRegisterScope temps(lasm);
            Register temp = temps.AcquireW();
            __ mvn(temp, value.gp().W());
            __ ldclral(temp, result.gp().W(), MemOperand(actual_addr));
            break;
          }
          case StoreType::kI64Store: {
            UseScratchRegisterScope temps(lasm);
            Register temp = temps.AcquireX();
            __ mvn(temp, value.gp());
            __ ldclral(temp, result.gp(), MemOperand(actual_addr));
            break;
          }
          default:
            UNREACHABLE();
        }
        break;
      case Binop::kSub:
        switch (type.value()) {
          case StoreType::kI64Store8:
          case StoreType::kI32Store8: {
            UseScratchRegisterScope temps(lasm);
            Register temp = temps.AcquireW();
            __ neg(temp, value.gp().W());
            __ ldaddalb(temp, result.gp().W(), MemOperand(actual_addr));
            break;
          }
          case StoreType::kI64Store16:
          case StoreType::kI32Store16: {
            UseScratchRegisterScope temps(lasm);
            Register temp = temps.AcquireW();
            __ neg(temp, value.gp().W());
            __ ldaddalh(temp, result.gp().W(), MemOperand(actual_addr));
            break;
          }
          case StoreType::kI64Store32:
          case StoreType::kI32Store: {
            UseScratchRegisterScope temps(lasm);
            Register temp = temps.AcquireW();
            __ neg(temp, value.gp().W());
            __ ldaddal(temp, result.gp().W(), MemOperand(actual_addr));
            break;
          }
          case StoreType::kI64Store: {
            UseScratchRegisterScope temps(lasm);
            Register temp = temps.AcquireX();
            __ neg(temp, value.gp());
            __ ldaddal(temp, result.gp(), MemOperand(actual_addr));
            break;
          }
          default:
            UNREACHABLE();
        }
        break;
#define ATOMIC_BINOP_CASE(op, instr)                                           \
  case Binop::op:                                                              \
    switch (type.value()) {                                                    \
      case StoreType::kI64Store8:                                              \
      case StoreType::kI32Store8:                                              \
        __ instr##b(value.gp().W(), result.gp().W(), MemOperand(actual_addr)); \
        break;                                                                 \
      case StoreType::kI64Store16:                                             \
      case StoreType::kI32Store16:                                             \
        __ instr##h(value.gp().W(), result.gp().W(), MemOperand(actual_addr)); \
        break;                                                                 \
      case StoreType::kI64Store32:                                             \
      case StoreType::kI32Store:                                               \
        __ instr(value.gp().W(), result.gp().W(), MemOperand(actual_addr));    \
        break;                                                                 \
      case StoreType::kI64Store:                                               \
        __ instr(value.gp(), result.gp(), MemOperand(actual_addr));            \
        break;                                                                 \
      default:                                                                 \
        UNREACHABLE();                                                         \
    }                                                                          \
    break;
        ATOMIC_BINOP_CASE(kAdd, ldaddal)
        ATOMIC_BINOP_CASE(kOr, ldsetal)
        ATOMIC_BINOP_CASE(kXor, ldeoral)
        ATOMIC_BINOP_CASE(kExchange, swpal)
#undef ATOMIC_BINOP_CASE
    }
  } else {
    // Allocate an additional {temp} register to hold the result that should be
    // stored to memory. Note that {temp} and {store_result} are not allowed to
    // be the same register.
    Register temp = temps.AcquireX();

    Label retry;
    __ Bind(&retry);
    switch (type.value()) {
      case StoreType::kI64Store8:
      case StoreType::kI32Store8:
        __ ldaxrb(result.gp().W(), actual_addr);
        break;
      case StoreType::kI64Store16:
      case StoreType::kI32Store16:
        __ ldaxrh(result.gp().W(), actual_addr);
        break;
      case StoreType::kI64Store32:
      case StoreType::kI32Store:
        __ ldaxr(result.gp().W(), actual_addr);
        break;
      case StoreType::kI64Store:
        __ ldaxr(result.gp().X(), actual_addr);
        break;
      default:
        UNREACHABLE();
    }

    switch (op) {
      case Binop::kAdd:
        __ add(temp, result.gp(), value.gp());
        break;
      case Binop::kSub:
        __ sub(temp, result.gp(), value.gp());
        break;
      case Binop::kAnd:
        __ and_(temp, result.gp(), value.gp());
        break;
      case Binop::kOr:
        __ orr(temp, result.gp(), value.gp());
        break;
      case Binop::kXor:
        __ eor(temp, result.gp(), value.gp());
        break;
      case Binop::kExchange:
        __ mov(temp, value.gp());
        break;
    }

    switch (type.value()) {
      case StoreType::kI64Store8:
      case StoreType::kI32Store8:
        __ stlxrb(store_result.W(), temp.W(), actual_addr);
        break;
      case StoreType::kI64Store16:
      case StoreType::kI32Store16:
        __ stlxrh(store_result.W(), temp.W(), actual_addr);
        break;
      case StoreType::kI64Store32:
      case StoreType::kI32Store:
        __ stlxr(store_result.W(), temp.W(), actual_addr);
        break;
      case StoreType::kI64Store:
        __ stlxr(store_result.W(), temp.X(), actual_addr);
        break;
      default:
        UNREACHABLE();
    }

    __ Cbnz(store_result.W(), &retry);
  }
}

#undef __
}  // namespace liftoff

void LiftoffAssembler::AtomicLoad(LiftoffRegister dst, Register src_addr,
                                  Register offset_reg, uintptr_t offset_imm,
                                  LoadType type, LiftoffRegList /* pinned */,
                                  bool /* i64_offset */) {
  UseScratchRegisterScope temps(this);
  Register src_reg = liftoff::CalculateActualAddress(this, temps, src_addr,
                                                     offset_reg, offset_imm);
  switch (type.value()) {
    case LoadType::kI32Load8U:
    case LoadType::kI64Load8U:
      Ldarb(dst.gp().W(), src_reg);
      return;
    case LoadType::kI32Load16U:
    case LoadType::kI64Load16U:
      Ldarh(dst.gp().W(), src_reg);
      return;
    case LoadType::kI32Load:
    case LoadType::kI64Load32U:
      Ldar(dst.gp().W(), src_reg);
      return;
    case LoadType::kI64Load:
      Ldar(dst.gp().X(), src_reg);
      return;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicStore(Register dst_addr, Register offset_reg,
                                   uintptr_t offset_imm, LiftoffRegister src,
                                   StoreType type, LiftoffRegList /* pinned */,
                                   bool /* i64_offset */) {
  UseScratchRegisterScope temps(this);
  Register dst_reg = liftoff::CalculateActualAddress(this, temps, dst_addr,
                                                     offset_reg, offset_imm);
  switch (type.value()) {
    case StoreType::kI64Store8:
    case StoreType::kI32Store8:
      Stlrb(src.gp().W(), dst_reg);
      return;
    case StoreType::kI64Store16:
    case StoreType::kI32Store16:
      Stlrh(src.gp().W(), dst_reg);
      return;
    case StoreType::kI64Store32:
    case StoreType::kI32Store:
      Stlr(src.gp().W(), dst_reg);
      return;
    case StoreType::kI64Store:
      Stlr(src.gp().X(), dst_reg);
      return;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicAdd(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool /* i64_offset */) {
  liftoff::AtomicBinop(this, dst_addr, offset_reg, offset_imm, value, result,
                       type, liftoff::Binop::kAdd);
}

void LiftoffAssembler::AtomicSub(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool /* i64_offset */) {
  liftoff::AtomicBinop(this, dst_addr, offset_reg, offset_imm, value, result,
                       type, liftoff::Binop::kSub);
}

void LiftoffAssembler::AtomicAnd(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool /* i64_offset */) {
  liftoff::AtomicBinop(this, dst_addr, offset_reg, offset_imm, value, result,
                       type, liftoff::Binop::kAnd);
}

void LiftoffAssembler::AtomicOr(Register dst_addr, Register offset_reg,
                                uintptr_t offset_imm, LiftoffRegister value,
                                LiftoffRegister result, StoreType type,
                                bool /* i64_offset */) {
  liftoff::AtomicBinop(this, dst_addr, offset_reg, offset_imm, value, result,
                       type, liftoff::Binop::kOr);
}

void LiftoffAssembler::AtomicXor(Register dst_addr, Register offset_reg,
                                 uintptr_t offset_imm, LiftoffRegister value,
                                 LiftoffRegister result, StoreType type,
                                 bool /* i64_offset */) {
  liftoff::AtomicBinop(this, dst_addr, offset_reg, offset_imm, value, result,
                       type, liftoff::Binop::kXor);
}

void LiftoffAssembler::AtomicExchange(Register dst_addr, Register offset_reg,
                                      uintptr_t offset_imm,
                                      LiftoffRegister value,
                                      LiftoffRegister result, StoreType type,
                                      bool /* i64_offset */) {
  liftoff::AtomicBinop(this, dst_addr, offset_reg, offset_imm, value, result,
                       type, liftoff::Binop::kExchange);
}

void LiftoffAssembler::AtomicCompareExchange(
    Register dst_addr, Register offset_reg, uintptr_t offset_imm,
    LiftoffRegister expected, LiftoffRegister new_value, LiftoffRegister result,
    StoreType type, bool /* i64_offset */) {
  LiftoffRegList pinned{dst_addr, expected, new_value};
  if (offset_reg != no_reg) pinned.set(offset_reg);

  Register result_reg = result.gp();
  if (pinned.has(result)) {
    result_reg = GetUnusedRegister(kGpReg, pinned).gp();
  }

  UseScratchRegisterScope temps(this);

  Register actual_addr = liftoff::CalculateActualAddress(
      this, temps, dst_addr, offset_reg, offset_imm);

  if (CpuFeatures::IsSupported(LSE)) {
    CpuFeatureScope scope(this, LSE);
    switch (type.value()) {
      case StoreType::kI64Store8:
      case StoreType::kI32Store8:
        if (result.gp() != expected.gp()) {
          mov(result.gp().W(), expected.gp().W());
        }
        casalb(result.gp().W(), new_value.gp().W(), MemOperand(actual_addr));
        break;
      case StoreType::kI64Store16:
      case StoreType::kI32Store16:
        if (result.gp() != expected.gp()) {
          mov(result.gp().W(), expected.gp().W());
        }
        casalh(result.gp().W(), new_value.gp().W(), MemOperand(actual_addr));
        break;
      case StoreType::kI64Store32:
      case StoreType::kI32Store:
        if (result.gp() != expected.gp()) {
          mov(result.gp().W(), expected.gp().W());
        }
        casal(result.gp().W(), new_value.gp().W(), MemOperand(actual_addr));
        break;
      case StoreType::kI64Store:
        if (result.gp() != expected.gp()) {
          mov(result.gp().X(), expected.gp().X());
        }
        casal(result.gp().X(), new_value.gp().X(), MemOperand(actual_addr));
        break;
      default:
        UNREACHABLE();
    }
  } else {
    Register store_result = temps.AcquireW();

    Label retry;
    Label done;
    Bind(&retry);
    switch (type.value()) {
      case StoreType::kI64Store8:
      case StoreType::kI32Store8:
        ldaxrb(result_reg.W(), actual_addr);
        Cmp(result.gp().W(), Operand(expected.gp().W(), UXTB));
        B(ne, &done);
        stlxrb(store_result.W(), new_value.gp().W(), actual_addr);
        break;
      case StoreType::kI64Store16:
      case StoreType::kI32Store16:
        ldaxrh(result_reg.W(), actual_addr);
        Cmp(result.gp().W(), Operand(expected.gp().W(), UXTH));
        B(ne, &done);
        stlxrh(store_result.W(), new_value.gp().W(), actual_addr);
        break;
      case StoreType::kI64Store32:
      case StoreType::kI32Store:
        ldaxr(result_reg.W(), actual_addr);
        Cmp(result.gp().W(), Operand(expected.gp().W(), UXTW));
        B(ne, &done);
        stlxr(store_result.W(), new_value.gp().W(), actual_addr);
        break;
      case StoreType::kI64Store:
        ldaxr(result_reg.X(), actual_addr);
        Cmp(result.gp().X(), Operand(expected.gp().X(), UXTX));
        B(ne, &done);
        stlxr(store_result.W(), new_value.gp().X(), actual_addr);
        break;
      default:
        UNREACHABLE();
    }

    Cbnz(store_result.W(), &retry);
    Bind(&done);
  }

  if (result_reg != result.gp()) {
    mov(result.gp(), result_reg);
  }
}

void LiftoffAssembler::AtomicFence() { Dmb(InnerShareable, BarrierAll); }

void LiftoffAssembler::LoadCallerFrameSlot(LiftoffRegister dst,
                                           uint32_t caller_slot_idx,
                                           ValueKind kind) {
  int32_t offset = (caller_slot_idx + 1) * LiftoffAssembler::kStackSlotSize;
  Ldr(liftoff::GetRegFromType(dst, kind), MemOperand(fp, offset));
}

void LiftoffAssembler::StoreCallerFrameSlot(LiftoffRegister src,
                                            uint32_t caller_slot_idx,
                                            ValueKind kind,
                                            Register frame_pointer) {
  int32_t offset = (caller_slot_idx + 1) * LiftoffAssembler::kStackSlotSize;
  Str(liftoff::GetRegFromType(src, kind), MemOperand(frame_pointer, offset));
}

void LiftoffAssembler::LoadReturnStackSlot(LiftoffRegister dst, int offset,
                                           ValueKind kind) {
  Ldr(liftoff::GetRegFromType(dst, kind), MemOperand(sp, offset));
}

void LiftoffAssembler::MoveStackValue(uint32_t dst_offset, uint32_t src_offset,
                                      ValueKind kind) {
  UseScratchRegisterScope temps(this);
  CPURegister scratch = liftoff::AcquireByType(&temps, kind);
  Ldr(scratch, liftoff::GetStackSlot(src_offset));
  Str(scratch, liftoff::GetStackSlot(dst_offset));
}

void LiftoffAssembler::Move(Register dst, Register src, ValueKind kind) {
  if (kind == kI32) {
    Mov(dst.W(), src.W());
  } else {
    DCHECK(kI64 == kind || is_reference(kind));
    Mov(dst.X(), src.X());
  }
}

void LiftoffAssembler::Move(DoubleRegister dst, DoubleRegister src,
                            ValueKind kind) {
  if (kind == kF32) {
    Fmov(dst.S(), src.S());
  } else if (kind == kF64) {
    Fmov(dst.D(), src.D());
  } else {
    DCHECK_EQ(kS128, kind);
    Mov(dst.Q(), src.Q());
  }
}

void LiftoffAssembler::Spill(int offset, LiftoffRegister reg, ValueKind kind) {
  RecordUsedSpillOffset(offset);
  MemOperand dst = liftoff::GetStackSlot(offset);
  Str(liftoff::GetRegFromType(reg, kind), dst);
}

void LiftoffAssembler::Spill(int offset, WasmValue value) {
  RecordUsedSpillOffset(offset);
  MemOperand dst = liftoff::GetStackSlot(offset);
  UseScratchRegisterScope temps(this);
  CPURegister src = CPURegister::no_reg();
  switch (value.type().kind()) {
    case kI32:
      if (value.to_i32() == 0) {
        src = wzr;
      } else {
        src = temps.AcquireW();
        Mov(src.W(), value.to_i32());
      }
      break;
    case kI64:
      if (value.to_i64() == 0) {
        src = xzr;
      } else {
        src = temps.AcquireX();
        Mov(src.X(), value.to_i64());
      }
      break;
    default:
      // We do not track f32 and f64 constants, hence they are unreachable.
      UNREACHABLE();
  }
  Str(src, dst);
}

void LiftoffAssembler::Fill(LiftoffRegister reg, int offset, ValueKind kind) {
  MemOperand src = liftoff::GetStackSlot(offset);
  Ldr(liftoff::GetRegFromType(reg, kind), src);
}

void LiftoffAssembler::FillI64Half(Register, int offset, RegPairHalf) {
  UNREACHABLE();
}

void LiftoffAssembler::FillStackSlotsWithZero(int start, int size) {
  // Zero 'size' bytes *below* start, byte at offset 'start' is untouched.
  DCHECK_LE(0, start);
  DCHECK_LT(0, size);
  DCHECK_EQ(0, size % 4);
  RecordUsedSpillOffset(start + size);

  int max_stp_offset = -start - size;
  // We check IsImmLSUnscaled(-start-12) because str only allows for unscaled
  // 9-bit immediate offset [-256,256]. If start is large enough, which can
  // happen when a function has many params (>=32 i64), str cannot be encoded
  // properly. We can use Str, which will generate more instructions, so
  // fallback to the general case below.
  if (size <= 12 * kStackSlotSize &&
      IsImmLSPair(max_stp_offset, kXRegSizeLog2) &&
      IsImmLSUnscaled(-start - 12)) {
    // Special straight-line code for up to 12 slots. Generates one
    // instruction per two slots (<= 7 instructions total).
    static_assert(kStackSlotSize == kSystemPointerSize);
    uint32_t remainder = size;
    for (; remainder >= 2 * kStackSlotSize; remainder -= 2 * kStackSlotSize) {
      stp(xzr, xzr, liftoff::GetStackSlot(start + remainder));
    }

    DCHECK_GE(12, remainder);
    switch (remainder) {
      case 12:
        str(xzr, liftoff::GetStackSlot(start + remainder));
        str(wzr, liftoff::GetStackSlot(start + remainder - 8));
        break;
      case 8:
        str(xzr, liftoff::GetStackSlot(start + remainder));
        break;
      case 4:
        str(wzr, liftoff::GetStackSlot(start + remainder));
        break;
      case 0:
        break;
      default:
        UNREACHABLE();
    }
  } else {
    // General case for bigger counts (5-8 instructions).
    UseScratchRegisterScope temps(this);
    Register address_reg = temps.AcquireX();
    // This {Sub} might use another temp register if the offset is too large.
    Sub(address_reg, fp, start + size);
    Register count_reg = temps.AcquireX();
    Mov(count_reg, size / 4);

    Label loop;
    bind(&loop);
    sub(count_reg, count_reg, 1);
    str(wzr, MemOperand(address_reg, kSystemPointerSize / 2, PostIndex));
    cbnz(count_reg, &loop);
  }
}

void LiftoffAssembler::LoadSpillAddress(Register dst, int offset,
                                        ValueKind /* kind */) {
  Sub(dst, fp, offset);
}

void LiftoffAssembler::emit_i32_add(Register dst, Register lhs, Register rhs) {
  Add(dst.W(), lhs.W(), rhs.W());
}
void LiftoffAssembler::emit_i32_addi(Register dst, Register lhs, int32_t imm) {
  Add(dst.W(), lhs.W(), Immediate(imm));
}

void LiftoffAssembler::emit_i32_sub(Register dst, Register lhs, Register rhs) {
  Sub(dst.W(), lhs.W(), rhs.W());
}
void LiftoffAssembler::emit_i32_subi(Register dst, Register lhs, int32_t imm) {
  Sub(dst.W(), lhs.W(), Immediate(imm));
}

void LiftoffAssembler::emit_i32_mul(Register dst, Register lhs, Register rhs) {
  Mul(dst.W(), lhs.W(), rhs.W());
}

void LiftoffAssembler::emit_i32_and(Register dst, Register lhs, Register rhs) {
  And(dst.W(), lhs.W(), rhs.W());
}
void LiftoffAssembler::emit_i32_andi(Register dst, Register lhs, int32_t imm) {
  And(dst.W(), lhs.W(), Immediate(imm));
}

void LiftoffAssembler::emit_i32_or(Register dst, Register lhs, Register rhs) {
  Orr(dst.W(), lhs.W(), rhs.W());
}
void LiftoffAssembler::emit_i32_ori(Register dst, Register lhs, int32_t imm) {
  Orr(dst.W(), lhs.W(), Immediate(imm));
}

void LiftoffAssembler::emit_i32_xor(Register dst, Register lhs, Register rhs) {
  Eor(dst.W(), lhs.W(), rhs.W());
}
void LiftoffAssembler::emit_i32_xori(Register dst, Register lhs, int32_t imm) {
  Eor(dst.W(), lhs.W(), Immediate(imm));
}

void LiftoffAssembler::emit_i32_shl(Register dst, Register src,
                                    Register amount) {
  Lsl(dst.W(), src.W(), amount.W());
}
void LiftoffAssembler::emit_i32_shli(Register dst, Register src,
                                     int32_t amount) {
  Lsl(dst.W(), src.W(), amount & 31);
}

void LiftoffAssembler::emit_i32_sar(Register dst, Register src,
                                    Register amount) {
  Asr(dst.W(), src.W(), amount.W());
}
void LiftoffAssembler::emit_i32_sari(Register dst, Register src,
                                     int32_t amount) {
  Asr(dst.W(), src.W(), amount & 31);
}

void LiftoffAssembler::emit_i32_shr(Register dst, Register src,
                                    Register amount) {
  Lsr(dst.W(), src.W(), amount.W());
}
void LiftoffAssembler::emit_i32_shri(Register dst, Register src,
                                     int32_t amount) {
  Lsr(dst.W(), src.W(), amount & 31);
}

void LiftoffAssembler::emit_i64_add(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  Add(dst.gp().X(), lhs.gp().X(), rhs.gp().X());
}

void LiftoffAssembler::emit_i64_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  Sub(dst.gp().X(), lhs.gp().X(), rhs.gp().X());
}

void LiftoffAssembler::emit_i64_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  Mul(dst.gp().X(), lhs.gp().X(), rhs.gp().X());
}
void LiftoffAssembler::emit_i64_muli(LiftoffRegister dst, LiftoffRegister lhs,
                                     int32_t imm) {
  if (base::bits::IsPowerOfTwo(imm)) {
    emit_i64_shli(dst, lhs, base::bits::WhichPowerOfTwo(imm));
    return;
  }
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireX();
  Mov(scratch, imm);
  Mul(dst.gp().X(), lhs.gp().X(), scratch);
}

void LiftoffAssembler::emit_i64_and(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  And(dst.gp().X(), lhs.gp().X(), rhs.gp().X());
}
void LiftoffAssembler::emit_i64_andi(LiftoffRegister dst, LiftoffRegister lhs,
                                     int32_t imm) {
  And(dst.gp().X(), lhs.gp().X(), imm);
}

void LiftoffAssembler::emit_i64_or(LiftoffRegister dst, LiftoffRegister lhs,
                                   LiftoffRegister rhs) {
  Orr(dst.gp().X(), lhs.gp().X(), rhs.gp().X());
}
void LiftoffAssembler::emit_i64_ori(LiftoffRegister dst, LiftoffRegister lhs,
                                    int32_t imm) {
  Orr(dst.gp().X(), lhs.gp().X(), imm);
}

void LiftoffAssembler::emit_i64_xor(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  Eor(dst.gp().X(), lhs.gp().X(), rhs.gp().X());
}
void LiftoffAssembler::emit_i64_xori(LiftoffRegister dst, LiftoffRegister lhs,
                                     int32_t imm) {
  Eor(dst.gp().X(), lhs.gp().X(), imm);
}

void LiftoffAssembler::emit_i64_shl(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  Lsl(dst.gp().X(), src.gp().X(), amount.X());
}
void LiftoffAssembler::emit_i64_shli(LiftoffRegister dst, LiftoffRegister src,
                                     int32_t amount) {
  Lsl(dst.gp().X(), src.gp().X(), amount & 63);
}

void LiftoffAssembler::emit_i64_sar(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  Asr(dst.gp().X(), src.gp().X(), amount.X());
}
void LiftoffAssembler::emit_i64_sari(LiftoffRegister dst, LiftoffRegister src,
                                     int32_t amount) {
  Asr(dst.gp().X(), src.gp().X(), amount & 63);
}

void LiftoffAssembler::emit_i64_shr(LiftoffRegister dst, LiftoffRegister src,
                                    Register amount) {
  Lsr(dst.gp().X(), src.gp().X(), amount.X());
}
void LiftoffAssembler::emit_i64_shri(LiftoffRegister dst, LiftoffRegister src,
                                     int32_t amount) {
  Lsr(dst.gp().X(), src.gp().X(), amount & 63);
}

void LiftoffAssembler::emit_f32_add(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Fadd(dst.S(), lhs.S(), rhs.S());
}

void LiftoffAssembler::emit_f32_sub(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Fsub(dst.S(), lhs.S(), rhs.S());
}

void LiftoffAssembler::emit_f32_mul(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Fmul(dst.S(), lhs.S(), rhs.S());
}

void LiftoffAssembler::emit_f32_div(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Fdiv(dst.S(), lhs.S(), rhs.S());
}

void LiftoffAssembler::emit_f32_min(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Fmin(dst.S(), lhs.S(), rhs.S());
}

void LiftoffAssembler::emit_f32_max(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Fmax(dst.S(), lhs.S(), rhs.S());
}

void LiftoffAssembler::emit_f32_abs(DoubleRegister dst, DoubleRegister src) {
  Fabs(dst.S(), src.S());
}

void LiftoffAssembler::emit_f32_neg(DoubleRegister dst, DoubleRegister src) {
  Fneg(dst.S(), src.S());
}

bool LiftoffAssembler::emit_f32_ceil(DoubleRegister dst, DoubleRegister src) {
  Frintp(dst.S(), src.S());
  return true;
}

bool LiftoffAssembler::emit_f32_floor(DoubleRegister dst, DoubleRegister src) {
  Frintm(dst.S(), src.S());
  return true;
}

bool LiftoffAssembler::emit_f32_trunc(DoubleRegister dst, DoubleRegister src) {
  Frintz(dst.S(), src.S());
  return true;
}

bool LiftoffAssembler::emit_f32_nearest_int(DoubleRegister dst,
                                            DoubleRegister src) {
  Frintn(dst.S(), src.S());
  return true;
}

void LiftoffAssembler::emit_f32_sqrt(DoubleRegister dst, DoubleRegister src) {
  Fsqrt(dst.S(), src.S());
}

void LiftoffAssembler::emit_f64_add(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Fadd(dst.D(), lhs.D(), rhs.D());
}

void LiftoffAssembler::emit_f64_sub(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Fsub(dst.D(), lhs.D(), rhs.D());
}

void LiftoffAssembler::emit_f64_mul(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Fmul(dst.D(), lhs.D(), rhs.D());
}

void LiftoffAssembler::emit_f64_div(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Fdiv(dst.D(), lhs.D(), rhs.D());
}

void LiftoffAssembler::emit_f64_min(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Fmin(dst.D(), lhs.D(), rhs.D());
}

void LiftoffAssembler::emit_f64_max(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Fmax(dst.D(), lhs.D(), rhs.D());
}

void LiftoffAssembler::emit_f64_abs(DoubleRegister dst, DoubleRegister src) {
  Fabs(dst.D(), src.D());
}

void LiftoffAssembler::emit_f64_neg(DoubleRegister dst, DoubleRegister src) {
  Fneg(dst.D(), src.D());
}

bool LiftoffAssembler::emit_f64_ceil(DoubleRegister dst, DoubleRegister src) {
  Frintp(dst.D(), src.D());
  return true;
}

bool LiftoffAssembler::emit_f64_floor(DoubleRegister dst, DoubleRegister src) {
  Frintm(dst.D(), src.D());
  return true;
}

bool LiftoffAssembler::emit_f64_trunc(DoubleRegister dst, DoubleRegister src) {
  Frintz(dst.D(), src.D());
  return true;
}

bool LiftoffAssembler::emit_f64_nearest_int(DoubleRegister dst,
                                            DoubleRegister src) {
  Frintn(dst.D(), src.D());
  return true;
}

void LiftoffAssembler::emit_f64_sqrt(DoubleRegister dst, DoubleRegister src) {
  Fsqrt(dst.D(), src.D());
}

void LiftoffAssembler::emit_i64_addi(LiftoffRegister dst, LiftoffRegister lhs,
                                     int64_t imm) {
  Add(dst.gp().X(), lhs.gp().X(), imm);
}

void LiftoffAssembler::emit_i32_clz(Register dst, Register src) {
  Clz(dst.W(), src.W());
}

void LiftoffAssembler::emit_i32_ctz(Register dst, Register src) {
  Rbit(dst.W(), src.W());
  Clz(dst.W(), dst.W());
}

bool LiftoffAssembler::emit_i32_popcnt(Register dst, Register src) {
  PopcntHelper(dst.W(), src.W());
  return true;
}

void LiftoffAssembler::emit_i64_clz(LiftoffRegister dst, LiftoffRegister src) {
  Clz(dst.gp().X(), src.gp().X());
}

void LiftoffAssembler::emit_i64_ctz(LiftoffRegister dst, LiftoffRegister src) {
  Rbit(dst.gp().X(), src.gp().X());
  Clz(dst.gp().X(), dst.gp().X());
}

bool LiftoffAssembler::emit_i64_popcnt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  PopcntHelper(dst.gp().X(), src.gp().X());
  return true;
}

void LiftoffAssembler::IncrementSmi(LiftoffRegister dst, int offset) {
  UseScratchRegisterScope temps(this);
  if (COMPRESS_POINTERS_BOOL) {
    DCHECK(SmiValuesAre31Bits());
    Register scratch = temps.AcquireW();
    Ldr(scratch, MemOperand(dst.gp(), offset));
    Add(scratch, scratch, Operand(Smi::FromInt(1)));
    Str(scratch, MemOperand(dst.gp(), offset));
  } else {
    Register scratch = temps.AcquireX();
    SmiUntag(scratch, MemOperand(dst.gp(), offset));
    Add(scratch, scratch, Operand(1));
    SmiTag(scratch);
    Str(scratch, MemOperand(dst.gp(), offset));
  }
}

void LiftoffAssembler::emit_i32_divs(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  Register dst_w = dst.W();
  Register lhs_w = lhs.W();
  Register rhs_w = rhs.W();
  bool can_use_dst = !dst_w.Aliases(lhs_w) && !dst_w.Aliases(rhs_w);
  if (can_use_dst) {
    // Do div early.
    Sdiv(dst_w, lhs_w, rhs_w);
  }
  // Check for division by zero.
  Cbz(rhs_w, trap_div_by_zero);
  // Check for kMinInt / -1. This is unrepresentable.
  Cmp(rhs_w, -1);
  Ccmp(lhs_w, 1, NoFlag, eq);
  B(trap_div_unrepresentable, vs);
  if (!can_use_dst) {
    // Do div.
    Sdiv(dst_w, lhs_w, rhs_w);
  }
}

void LiftoffAssembler::emit_i32_divu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  // Check for division by zero.
  Cbz(rhs.W(), trap_div_by_zero);
  // Do div.
  Udiv(dst.W(), lhs.W(), rhs.W());
}

void LiftoffAssembler::emit_i32_rems(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  Register dst_w = dst.W();
  Register lhs_w = lhs.W();
  Register rhs_w = rhs.W();
  // Do early div.
  // No need to check kMinInt / -1 because the result is kMinInt and then
  // kMinInt * -1 -> kMinInt. In this case, the Msub result is therefore 0.
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireW();
  Sdiv(scratch, lhs_w, rhs_w);
  // Check for division by zero.
  Cbz(rhs_w, trap_div_by_zero);
  // Compute remainder.
  Msub(dst_w, scratch, rhs_w, lhs_w);
}

void LiftoffAssembler::emit_i32_remu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  Register dst_w = dst.W();
  Register lhs_w = lhs.W();
  Register rhs_w = rhs.W();
  // Do early div.
  UseScratchRegisterScope temps(this);
  Register scratch = temps.AcquireW();
  Udiv(scratch, lhs_w, rhs_w);
  // Check for division by zero.
  Cbz(rhs_w, trap_div_by_zero);
  // Compute remainder.
  Msub(dst_w, scratch, rhs_w, lhs_w);
}

bool LiftoffAssembler::emit_i64_divs(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  Register dst_x = dst.gp().X();
  Register lhs_x = lhs.gp().X();
  Register rhs_x = rhs.gp().X();
  bool can_use_dst = !dst_x.Al
```