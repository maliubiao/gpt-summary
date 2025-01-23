Response:
My thinking process to analyze the provided IA32 assembly code snippet goes like this:

1. **Understand the Goal:** The request asks for an analysis of a V8 source file (`code-generator-ia32.cc`), focusing on its functionality, potential JavaScript relation, logic, and common programming errors. It specifically asks for a summary of the provided snippet.

2. **Identify the Language:**  The snippet uses IA32 assembly instructions (e.g., `mov`, `cmpxchg`, `add`, `jmp`, `push`, `pop`). This confirms it's part of the architecture-specific code generation within V8.

3. **High-Level Overview:** I skim the code to get a general sense of what it's doing. I see `case` statements, macros (`ASSEMBLE_ATOMIC_BINOP`, `ASSEMBLE_I64ATOMIC_BINOP`), and instruction mnemonics. This suggests it's handling different kinds of operations, likely related to atomic operations and potentially other low-level tasks.

4. **Focus on Key Sections:**

   * **Atomic Operations:** The initial part clearly deals with atomic operations. The `kAtomic##op##...` patterns indicate different atomic binary operations on various data sizes (Int8, Uint8, Int16, Uint16, Word32). The macros `ASSEMBLE_ATOMIC_BINOP` suggest a common assembly pattern for these. I recognize the `cmpxchg` instruction, which is central to implementing atomic operations (compare and swap).

   * **64-bit Atomic Operations:** The `kIA32Word32AtomicPair##op` section deals with 64-bit atomic operations, evident from the `ASSEMBLE_I64ATOMIC_BINOP` macro. It uses pairs of instructions (e.g., `add`, `adc` for addition with carry).

   * **Atomic Subtraction:** The `kIA32Word32AtomicPairSub` case is handled separately, showing a more involved sequence of instructions, likely because direct 64-bit atomic subtraction might not be a single instruction on IA32. It involves negation, addition with carry, and compare-and-exchange.

   * **Unreachable Cases:** The `kAtomicLoad...` and `kAtomicStore...` cases being `UNREACHABLE()` indicates that the instruction selector doesn't generate these specific atomic load/store instructions in this context.

   * **Flags and Branching:** The `FlagsConditionToCondition` function translates V8's internal `FlagsCondition` enum to IA32's condition codes for jump instructions. The `AssembleArchBranch` function uses these translated conditions to generate conditional jumps.

5. **Infer Functionality:** Based on the observed instructions and structures, I deduce the following functionalities:

   * **Atomic Binary Operations:** Implementing atomic addition, subtraction, bitwise AND, OR, and XOR operations on different integer sizes.
   * **64-bit Atomic Operations:** Handling 64-bit atomic operations by combining 32-bit instructions.
   * **Conditional Branching:**  Generating assembly code for conditional jumps based on the results of previous comparisons or operations.

6. **Relate to JavaScript (if applicable):** Atomic operations are directly related to JavaScript's `SharedArrayBuffer` and `Atomics` API. I can provide a simple JavaScript example demonstrating the use of `Atomics`.

7. **Code Logic Inference:**

   * **Atomic Operations:** The pattern suggests a loop or retry mechanism for the compare-and-swap operation. If the value at the memory location hasn't changed since the read, the swap succeeds. Otherwise, it retries.
   * **64-bit Subtraction:** The special handling of 64-bit subtraction indicates that it needs a sequence of 32-bit operations with carry handling to achieve atomicity.

8. **Hypothetical Input and Output (for logic):** I construct a simple scenario to illustrate the atomic addition:

   * **Input:** Memory location with value 5, thread A wants to add 3, thread B wants to add 7.
   * **Output (possible):** The final value in memory could be 15 (5 + 3 + 7), with the atomic operations ensuring that updates from both threads are applied without data races.

9. **Common Programming Errors:**  I consider common errors related to atomic operations:

   * **Forgetting Atomicity:**  Performing non-atomic operations on shared memory can lead to race conditions.
   * **Incorrect Ordering:** Even with atomic operations, the order of operations can be crucial for correctness in concurrent programming.
   * **ABA Problem:**  In some scenarios with compare-and-swap, a value might change from A to B and back to A, leading to a successful swap even though the underlying state has changed.

10. **Summarize the Snippet's Function:** I synthesize the observations into a concise summary, highlighting the key functionalities like atomic operations, branching, and the specific IA32 instructions used. I mention that it's a part of the code generation process.

11. **Address Specific Constraints:** I ensure I've addressed all parts of the prompt, such as the ".tq" extension check (which is negative in this case), the section number, and the request for a summary.

By following these steps, I can systematically analyze the assembly code snippet and provide a comprehensive answer that addresses all aspects of the request. The process involves understanding the assembly language, recognizing common patterns for specific operations (like atomics), inferring functionality, and connecting it back to higher-level concepts like JavaScript APIs and concurrent programming challenges.
这是提供的 v8/src/compiler/backend/ia32/code-generator-ia32.cc 源代码的第五部分，主要关注于**原子操作**和**控制流**的汇编代码生成。

**功能列举:**

1. **原子二元运算汇编生成:** 这部分代码定义了宏 `ATOMIC_BINOP_CASE` 和 `ASSEMBLE_ATOMIC_BINOP`，用于生成不同类型原子二元运算（Add, Sub, And, Or, Xor）的 IA32 汇编代码。它支持对 `int8_t`, `uint8_t`, `int16_t`, `uint16_t`, 和 `word32` 类型的原子操作。
2. **64位原子二元运算汇编生成:**  定义了宏 `ASSEMBLE_I64ATOMIC_BINOP` 和 `ATOMIC_BINOP_CASE` 用于生成 64 位（Word32 Pair）原子二元运算的汇编代码。它使用两个 32 位寄存器模拟 64 位操作，并使用 `lock` 指令确保原子性。支持 Add, And, Or, Xor 操作。
3. **特殊的 64 位原子减法:** `kIA32Word32AtomicPairSub` 单独处理，因为它需要更复杂的指令序列来实现原子减法，包括取反、带进位的加法以及 `cmpxchg8b` 指令。
4. **条件码到 IA32 条件跳转的转换:** `FlagsConditionToCondition` 函数将 V8 内部的条件码枚举类型 (`FlagsCondition`) 转换为 IA32 的条件跳转指令所需的条件码 (`Condition`)。
5. **生成架构相关的分支指令:** `AssembleArchBranch` 函数根据给定的条件生成 IA32 的条件跳转指令 (`jcc`) 或无条件跳转指令 (`jmp`)。它还处理了无序比较的情况 (`kUnorderedEqual`, `kUnorderedNotEqual`)，使用了奇偶校验位 (`parity_even`).
6. **生成架构相关的 Deopt 分支:** `AssembleArchDeoptBranch` 函数调用 `AssembleArchBranch`，表明 Deopt 分支也通过相同的机制生成。
7. **生成架构相关的无条件跳转:** `AssembleArchJumpRegardlessOfAssemblyOrder` 生成一个无条件跳转指令到指定的目标基本块。
8. **WebAssembly Trap 处理 (如果启用):** `AssembleArchTrap` 函数（在 `V8_ENABLE_WEBASSEMBLY` 宏定义下）生成 WebAssembly trap 的处理代码，包括调用 wasm runtime stub。
9. **生成架构相关的布尔值:** `AssembleArchBoolean` 函数根据条件码生成布尔值（0 或 1）并存储到指定的寄存器中。它处理了字节寄存器的特殊情况，使用了 `setcc` 和 `movzx_b` 指令。

**关于 .tq 结尾:**

如果 `v8/src/compiler/backend/ia32/code-generator-ia32.cc` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码**。Torque 是一种 V8 使用的类型化的中间语言，用于生成高效的 C++ 代码，通常用于实现内置函数或性能关键的代码。然而，根据你提供的文件名，它以 `.cc` 结尾，所以它是 **C++ 源代码**。

**与 JavaScript 的关系 (原子操作部分):**

原子操作在 JavaScript 中通过 `SharedArrayBuffer` 和 `Atomics` API 暴露出来，用于在多个共享内存的 worker 之间进行同步。

**JavaScript 示例:**

```javascript
// 创建一个共享的 Int32Array
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const sharedArray = new Int32Array(sab);

// 模拟两个 worker
function workerA() {
  Atomics.add(sharedArray, 0, 5); // 原子地将索引 0 的值加 5
  console.log("Worker A added 5, value:", Atomics.load(sharedArray, 0));
}

function workerB() {
  Atomics.sub(sharedArray, 0, 3); // 原子地将索引 0 的值减 3
  console.log("Worker B subtracted 3, value:", Atomics.load(sharedArray, 0));
}

// 初始值
console.log("Initial value:", Atomics.load(sharedArray, 0));

// 模拟并发执行
workerA();
workerB();
```

在这个例子中，`Atomics.add` 和 `Atomics.sub` 对应了代码中生成的原子加法和减法的汇编指令。`cmpxchg` 指令是实现这些原子操作的关键，它保证了在多线程环境下，对共享内存的修改是原子性的，避免了数据竞争。

**代码逻辑推理 (原子加法):**

假设输入：

* `inst` 代表一个原子加法指令，目标内存地址在寄存器 `address_reg` 中，要加的值在寄存器 `value_reg` 中。
* 初始时，内存地址 `address_reg` 指向的值为 `10`，寄存器 `value_reg` 的值为 `5`。

输出 (期望):

* 执行生成的汇编代码后，内存地址 `address_reg` 指向的值变为 `15`。

生成的汇编代码（基于宏展开的推测）可能如下：

```assembly
// 假设 address_reg 是 esi, value_reg 是 ebx
retry_atomic_add:
  mov eax, [esi]       // 将内存中的值加载到 eax (期望值)
  mov ecx, eax       // 将期望值复制到 ecx
  add ecx, ebx       // ecx = 期望值 + 要加的值
  lock cmpxchg [esi], ecx  // 原子地比较并交换 [esi] 和 ecx，如果 [esi] 等于 eax
  jne retry_atomic_add // 如果比较失败 (说明内存中的值被其他线程修改了)，则重试
```

**用户常见的编程错误 (与原子操作相关):**

1. **忘记使用原子操作:** 在多线程环境下修改共享数据时，如果忘记使用原子操作，会导致数据竞争和不可预测的结果。

   ```javascript
   // 错误示例：非原子操作
   let counter = 0;

   function increment() {
     counter++; // 非原子操作，可能导致多个线程同时修改 counter 导致数据丢失
   }
   ```

2. **错误地使用原子操作的返回值:** 一些原子操作（如 `Atomics.compareExchange`）会返回一个布尔值表示是否成功，程序员可能会忽略这个返回值，导致逻辑错误。

   ```javascript
   // 错误示例：忽略 compareExchange 的返回值
   const oldValue = Atomics.load(sharedArray, 0);
   const newValue = oldValue + 10;
   Atomics.compareExchange(sharedArray, 0, oldValue, newValue);
   // 如果 compareExchange 失败，sharedArray[0] 可能没有被更新，但代码没有处理这种情况
   ```

3. **ABA 问题:** 在某些使用 compare-and-swap 的场景中，一个值从 A 变成 B，然后再变回 A。CAS 操作会认为值没有改变，但实际上可能已经经历了中间状态，这可能会导致问题。

**第五部分的功能归纳:**

这部分代码主要负责为 IA32 架构生成执行原子二元运算和控制流（分支跳转）的汇编指令。它通过宏定义和辅助函数，针对不同数据类型和操作类型生成高效且正确的汇编代码。特别是对于原子操作，它使用了 `lock cmpxchg` 指令来保证多线程环境下的数据一致性。此外，它还处理了条件码到 IA32 条件跳转指令的转换，以及 WebAssembly trap 的特殊处理（如果启用）。这部分是代码生成器中至关重要的一部分，因为它直接影响了 JavaScript 代码在 IA32 架构上的并发性能和控制流程。

### 提示词
```
这是目录为v8/src/compiler/backend/ia32/code-generator-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/ia32/code-generator-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
\
  case kAtomic##op##Int8: {                        \
    ASSEMBLE_ATOMIC_BINOP(inst, mov_b, cmpxchg_b); \
    __ movsx_b(eax, eax);                          \
    break;                                         \
  }                                                \
  case kAtomic##op##Uint8: {                       \
    ASSEMBLE_ATOMIC_BINOP(inst, mov_b, cmpxchg_b); \
    __ movzx_b(eax, eax);                          \
    break;                                         \
  }                                                \
  case kAtomic##op##Int16: {                       \
    ASSEMBLE_ATOMIC_BINOP(inst, mov_w, cmpxchg_w); \
    __ movsx_w(eax, eax);                          \
    break;                                         \
  }                                                \
  case kAtomic##op##Uint16: {                      \
    ASSEMBLE_ATOMIC_BINOP(inst, mov_w, cmpxchg_w); \
    __ movzx_w(eax, eax);                          \
    break;                                         \
  }                                                \
  case kAtomic##op##Word32: {                      \
    ASSEMBLE_ATOMIC_BINOP(inst, mov, cmpxchg);     \
    break;                                         \
  }
      ATOMIC_BINOP_CASE(Add, add)
      ATOMIC_BINOP_CASE(Sub, sub)
      ATOMIC_BINOP_CASE(And, and_)
      ATOMIC_BINOP_CASE(Or, or_)
      ATOMIC_BINOP_CASE(Xor, xor_)
#undef ATOMIC_BINOP_CASE
#define ATOMIC_BINOP_CASE(op, instr1, instr2)         \
  case kIA32Word32AtomicPair##op: {                   \
    DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr)); \
    ASSEMBLE_I64ATOMIC_BINOP(instr1, instr2)          \
    break;                                            \
  }
      ATOMIC_BINOP_CASE(Add, add, adc)
      ATOMIC_BINOP_CASE(And, and_, and_)
      ATOMIC_BINOP_CASE(Or, or_, or_)
      ATOMIC_BINOP_CASE(Xor, xor_, xor_)
#undef ATOMIC_BINOP_CASE
    case kIA32Word32AtomicPairSub: {
      DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr));
      Label binop;
      __ bind(&binop);
      // Move memory operand into edx:eax
      __ mov(eax, i.MemoryOperand(2));
      __ mov(edx, i.NextMemoryOperand(2));
      // Save input registers temporarily on the stack.
      __ push(ebx);
      frame_access_state()->IncreaseSPDelta(1);
      i.MoveInstructionOperandToRegister(ebx, instr->InputAt(0));
      __ push(i.InputRegister(1));
      // Negate input in place
      __ neg(ebx);
      __ adc(i.InputRegister(1), 0);
      __ neg(i.InputRegister(1));
      // Add memory operand, negated input.
      __ add(ebx, eax);
      __ adc(i.InputRegister(1), edx);
      __ lock();
      __ cmpxchg8b(i.MemoryOperand(2));
      // Restore input registers
      __ pop(i.InputRegister(1));
      __ pop(ebx);
      frame_access_state()->IncreaseSPDelta(-1);
      __ j(not_equal, &binop);
      break;
    }
    case kAtomicLoadInt8:
    case kAtomicLoadUint8:
    case kAtomicLoadInt16:
    case kAtomicLoadUint16:
    case kAtomicLoadWord32:
    case kAtomicStoreWord8:
    case kAtomicStoreWord16:
    case kAtomicStoreWord32:
      UNREACHABLE();  // Won't be generated by instruction selector.
  }
  return kSuccess;
}

static Condition FlagsConditionToCondition(FlagsCondition condition) {
  switch (condition) {
    case kUnorderedEqual:
    case kEqual:
      return equal;
    case kUnorderedNotEqual:
    case kNotEqual:
      return not_equal;
    case kSignedLessThan:
      return less;
    case kSignedGreaterThanOrEqual:
      return greater_equal;
    case kSignedLessThanOrEqual:
      return less_equal;
    case kSignedGreaterThan:
      return greater;
    case kUnsignedLessThan:
      return below;
    case kUnsignedGreaterThanOrEqual:
      return above_equal;
    case kUnsignedLessThanOrEqual:
      return below_equal;
    case kUnsignedGreaterThan:
      return above;
    case kOverflow:
      return overflow;
    case kNotOverflow:
      return no_overflow;
    default:
      UNREACHABLE();
  }
}

// Assembles a branch after an instruction.
void CodeGenerator::AssembleArchBranch(Instruction* instr, BranchInfo* branch) {
  Label::Distance flabel_distance =
      branch->fallthru ? Label::kNear : Label::kFar;
  Label* tlabel = branch->true_label;
  Label* flabel = branch->false_label;
  if (branch->condition == kUnorderedEqual) {
    __ j(parity_even, flabel, flabel_distance);
  } else if (branch->condition == kUnorderedNotEqual) {
    __ j(parity_even, tlabel);
  }
  __ j(FlagsConditionToCondition(branch->condition), tlabel);

  // Add a jump if not falling through to the next block.
  if (!branch->fallthru) __ jmp(flabel);
}

void CodeGenerator::AssembleArchDeoptBranch(Instruction* instr,
                                            BranchInfo* branch) {
  AssembleArchBranch(instr, branch);
}

void CodeGenerator::AssembleArchJumpRegardlessOfAssemblyOrder(
    RpoNumber target) {
  __ jmp(GetLabel(target));
}

#if V8_ENABLE_WEBASSEMBLY
void CodeGenerator::AssembleArchTrap(Instruction* instr,
                                     FlagsCondition condition) {
  class OutOfLineTrap final : public OutOfLineCode {
   public:
    OutOfLineTrap(CodeGenerator* gen, Instruction* instr)
        : OutOfLineCode(gen), instr_(instr), gen_(gen) {}

    void Generate() final {
      IA32OperandConverter i(gen_, instr_);
      TrapId trap_id =
          static_cast<TrapId>(i.InputInt32(instr_->InputCount() - 1));
      GenerateCallToTrap(trap_id);
    }

   private:
    void GenerateCallToTrap(TrapId trap_id) {
      gen_->AssembleSourcePosition(instr_);
      // A direct call to a wasm runtime stub defined in this module.
      // Just encode the stub index. This will be patched when the code
      // is added to the native module and copied into wasm code space.
      __ wasm_call(static_cast<Address>(trap_id), RelocInfo::WASM_STUB_CALL);
      ReferenceMap* reference_map =
          gen_->zone()->New<ReferenceMap>(gen_->zone());
      gen_->RecordSafepoint(reference_map);
      __ AssertUnreachable(AbortReason::kUnexpectedReturnFromWasmTrap);
    }

    Instruction* instr_;
    CodeGenerator* gen_;
  };
  auto ool = zone()->New<OutOfLineTrap>(this, instr);
  Label* tlabel = ool->entry();
  Label end;
  if (condition == kUnorderedEqual) {
    __ j(parity_even, &end, Label::kNear);
  } else if (condition == kUnorderedNotEqual) {
    __ j(parity_even, tlabel);
  }
  __ j(FlagsConditionToCondition(condition), tlabel);
  __ bind(&end);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Assembles boolean materializations after an instruction.
void CodeGenerator::AssembleArchBoolean(Instruction* instr,
                                        FlagsCondition condition) {
  IA32OperandConverter i(this, instr);
  Label done;

  // Materialize a full 32-bit 1 or 0 value. The result register is always the
  // last output of the instruction.
  Label check;
  DCHECK_NE(0u, instr->OutputCount());
  Register reg = i.OutputRegister(instr->OutputCount() - 1);
  if (condition == kUnorderedEqual) {
    __ j(parity_odd, &check, Label::kNear);
    __ Move(reg, Immediate(0));
    __ jmp(&done, Label::kNear);
  } else if (condition == kUnorderedNotEqual) {
    __ j(parity_odd, &check, Label::kNear);
    __ mov(reg, Immediate(1));
    __ jmp(&done, Label::kNear);
  }
  Condition cc = FlagsConditionToCondition(condition);

  __ bind(&check);
  if (reg.is_byte_register()) {
    // setcc for byte registers (al, bl, cl, dl).
    __ setcc(cc, reg);
    __ movzx_b(reg, reg);
  } else {
    // Emit a branch to set a register to either 1 or 0.
    Label set;
    __ j(cc, &set, Label::kNear);
    __ Move(reg, Immediate(0));
    __ jmp(&done, Label::kNear);
    __ bind(&set);
    __ mov(reg, Immediate(1));
  }
  __ bind(&done);
}

void CodeGenerator::AssembleArchConditionalBoolean(Instruction* instr) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchConditionalBranch(Instruction* instr,
                                                  BranchInfo* branch) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchBinarySearchSwitch(Instruction* instr) {
  IA32OperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  std::vector<std::pair<int32_t, Label*>> cases;
  for (size_t index = 2; index < instr->InputCount(); index += 2) {
    cases.push_back({i.InputInt32(index + 0), GetLabel(i.InputRpo(index + 1))});
  }
  AssembleArchBinarySearchSwitchRange(input, i.InputRpo(1), cases.data(),
                                      cases.data() + cases.size());
}

void CodeGenerator::AssembleArchTableSwitch(Instruction* instr) {
  IA32OperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  size_t const case_count = instr->InputCount() - 2;
  base::Vector<Label*> cases = zone()->AllocateVector<Label*>(case_count);
  for (size_t index = 0; index < case_count; ++index) {
    cases[index] = GetLabel(i.InputRpo(index + 2));
  }
  Label* const table = AddJumpTable(cases);
  __ cmp(input, Immediate(case_count));
  __ j(above_equal, GetLabel(i.InputRpo(1)));
  __ jmp(Operand::JumpTable(input, times_system_pointer_size, table));
}

void CodeGenerator::AssembleArchSelect(Instruction* instr,
                                       FlagsCondition condition) {
  UNIMPLEMENTED();
}

// The calling convention for JSFunctions on IA32 passes arguments on the
// stack and the JSFunction and context in EDI and ESI, respectively, thus
// the steps of the call look as follows:

// --{ before the call instruction }--------------------------------------------
//                                                         |  caller frame |
//                                                         ^ esp           ^ ebp

// --{ push arguments and setup ESI, EDI }--------------------------------------
//                                       | args + receiver |  caller frame |
//                                       ^ esp                             ^ ebp
//                 [edi = JSFunction, esi = context]

// --{ call [edi + kCodeEntryOffset] }------------------------------------------
//                                 | RET | args + receiver |  caller frame |
//                                 ^ esp                                   ^ ebp

// =={ prologue of called function }============================================
// --{ push ebp }---------------------------------------------------------------
//                            | FP | RET | args + receiver |  caller frame |
//                            ^ esp                                        ^ ebp

// --{ mov ebp, esp }-----------------------------------------------------------
//                            | FP | RET | args + receiver |  caller frame |
//                            ^ ebp,esp

// --{ push esi }---------------------------------------------------------------
//                      | CTX | FP | RET | args + receiver |  caller frame |
//                      ^esp  ^ ebp

// --{ push edi }---------------------------------------------------------------
//                | FNC | CTX | FP | RET | args + receiver |  caller frame |
//                ^esp        ^ ebp

// --{ subi esp, #N }-----------------------------------------------------------
// | callee frame | FNC | CTX | FP | RET | args + receiver |  caller frame |
// ^esp                       ^ ebp

// =={ body of called function }================================================

// =={ epilogue of called function }============================================
// --{ mov esp, ebp }-----------------------------------------------------------
//                            | FP | RET | args + receiver |  caller frame |
//                            ^ esp,ebp

// --{ pop ebp }-----------------------------------------------------------
// |                               | RET | args + receiver |  caller frame |
//                                 ^ esp                                   ^ ebp

// --{ ret #A+1 }-----------------------------------------------------------
// |                                                       |  caller frame |
//                                                         ^ esp           ^ ebp

// Runtime function calls are accomplished by doing a stub call to the
// CEntry (a real code object). On IA32 passes arguments on the
// stack, the number of arguments in EAX, the address of the runtime function
// in EBX, and the context in ESI.

// --{ before the call instruction }--------------------------------------------
//                                                         |  caller frame |
//                                                         ^ esp           ^ ebp

// --{ push arguments and setup EAX, EBX, and ESI }-----------------------------
//                                       | args + receiver |  caller frame |
//                                       ^ esp                             ^ ebp
//              [eax = #args, ebx = runtime function, esi = context]

// --{ call #CEntry }-----------------------------------------------------------
//                                 | RET | args + receiver |  caller frame |
//                                 ^ esp                                   ^ ebp

// =={ body of runtime function }===============================================

// --{ runtime returns }--------------------------------------------------------
//                                                         |  caller frame |
//                                                         ^ esp           ^ ebp

// Other custom linkages (e.g. for calling directly into and out of C++) may
// need to save callee-saved registers on the stack, which is done in the
// function prologue of generated code.

// --{ before the call instruction }--------------------------------------------
//                                                         |  caller frame |
//                                                         ^ esp           ^ ebp

// --{ set up arguments in registers on stack }---------------------------------
//                                                  | args |  caller frame |
//                                                  ^ esp                  ^ ebp
//                  [r0 = arg0, r1 = arg1, ...]

// --{ call code }--------------------------------------------------------------
//                                            | RET | args |  caller frame |
//                                            ^ esp                        ^ ebp

// =={ prologue of called function }============================================
// --{ push ebp }---------------------------------------------------------------
//                                       | FP | RET | args |  caller frame |
//                                       ^ esp                             ^ ebp

// --{ mov ebp, esp }-----------------------------------------------------------
//                                       | FP | RET | args |  caller frame |
//                                       ^ ebp,esp

// --{ save registers }---------------------------------------------------------
//                                | regs | FP | RET | args |  caller frame |
//                                ^ esp  ^ ebp

// --{ subi esp, #N }-----------------------------------------------------------
//                 | callee frame | regs | FP | RET | args |  caller frame |
//                 ^esp                  ^ ebp

// =={ body of called function }================================================

// =={ epilogue of called function }============================================
// --{ restore registers }------------------------------------------------------
//                                | regs | FP | RET | args |  caller frame |
//                                ^ esp  ^ ebp

// --{ mov esp, ebp }-----------------------------------------------------------
//                                       | FP | RET | args |  caller frame |
//                                       ^ esp,ebp

// --{ pop ebp }----------------------------------------------------------------
//                                            | RET | args |  caller frame |
//                                            ^ esp                        ^ ebp

void CodeGenerator::FinishFrame(Frame* frame) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {  // Save callee-saved registers.
    DCHECK(!info()->is_osr());
    frame->AllocateSavedCalleeRegisterSlots(saves.Count());
  }
}

void CodeGenerator::AssembleConstructFrame() {
  auto call_descriptor = linkage()->GetIncomingDescriptor();
  if (frame_access_state()->has_frame()) {
    if (call_descriptor->IsCFunctionCall()) {
      __ push(ebp);
      __ mov(ebp, esp);
#if V8_ENABLE_WEBASSEMBLY
      if (info()->GetOutputStackFrameType() == StackFrame::C_WASM_ENTRY) {
        __ Push(Immediate(StackFrame::TypeToMarker(StackFrame::C_WASM_ENTRY)));
        // Reserve stack space for saving the c_entry_fp later.
        __ AllocateStackSpace(kSystemPointerSize);
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    } else if (call_descriptor->IsJSFunctionCall()) {
      __ Prologue();
    } else {
      __ StubPrologue(info()->GetOutputStackFrameType());
#if V8_ENABLE_WEBASSEMBLY
      if (call_descriptor->IsWasmFunctionCall() ||
          call_descriptor->IsWasmImportWrapper() ||
          call_descriptor->IsWasmCapiFunction()) {
        // For import wrappers and C-API functions, this stack slot is only used
        // for printing stack traces in V8. Also, it holds a WasmImportData
        // instead of the trusted instance data, which is taken care of in the
        // frames accessors.
        __ push(kWasmImplicitArgRegister);
      }
      if (call_descriptor->IsWasmCapiFunction()) {
        // Reserve space for saving the PC later.
        __ AllocateStackSpace(kSystemPointerSize);
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    }
  }

  int required_slots =
      frame()->GetTotalFrameSlotCount() - frame()->GetFixedSlotCount();

  if (info()->is_osr()) {
    // TurboFan OSR-compiled functions cannot be entered directly.
    __ Abort(AbortReason::kShouldNotDirectlyEnterOsrFunction);

    // Unoptimized code jumps directly to this entrypoint while the unoptimized
    // frame is still on the stack. Optimized code uses OSR values directly from
    // the unoptimized frame. Thus, all that needs to be done is to allocate the
    // remaining stack slots.
    __ RecordComment("-- OSR entrypoint --");
    osr_pc_offset_ = __ pc_offset();
    required_slots -= osr_helper()->UnoptimizedFrameSlots();
  }

  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (required_slots > 0) {
    DCHECK(frame_access_state()->has_frame());
#if V8_ENABLE_WEBASSEMBLY
    if (info()->IsWasm() && required_slots * kSystemPointerSize > 4 * KB) {
      // For WebAssembly functions with big frames we have to do the stack
      // overflow check before we construct the frame. Otherwise we may not
      // have enough space on the stack to call the runtime for the stack
      // overflow.
      Label done;

      // If the frame is bigger than the stack, we throw the stack overflow
      // exception unconditionally. Thereby we can avoid the integer overflow
      // check in the condition code.
      if (required_slots * kSystemPointerSize < v8_flags.stack_size * KB) {
        Register scratch = esi;
        __ push(scratch);
        __ mov(scratch, esp);
        __ sub(scratch, Immediate(required_slots * kSystemPointerSize));
        __ CompareStackLimit(scratch, StackLimitKind::kRealStackLimit);
        __ pop(scratch);
        __ j(above_equal, &done, Label::kNear);
      }

      if (v8_flags.experimental_wasm_growable_stacks) {
        RegList regs_to_save;
        regs_to_save.set(WasmHandleStackOverflowDescriptor::GapRegister());
        regs_to_save.set(
            WasmHandleStackOverflowDescriptor::FrameBaseRegister());
        for (auto reg : wasm::kGpParamRegisters) regs_to_save.set(reg);
        for (Register reg : base::Reversed(regs_to_save)) {
          __ push(reg);
        }
        __ mov(WasmHandleStackOverflowDescriptor::GapRegister(),
               Immediate(required_slots * kSystemPointerSize));
        __ mov(WasmHandleStackOverflowDescriptor::FrameBaseRegister(), ebp);
        __ add(WasmHandleStackOverflowDescriptor::FrameBaseRegister(),
               Immediate(static_cast<int32_t>(
                   call_descriptor->ParameterSlotCount() * kSystemPointerSize +
                   CommonFrameConstants::kFixedFrameSizeAboveFp)));
        __ CallBuiltin(Builtin::kWasmHandleStackOverflow);
        for (Register reg : regs_to_save) {
          __ pop(reg);
        }
      } else {
        __ wasm_call(static_cast<Address>(Builtin::kWasmStackOverflow),
                     RelocInfo::WASM_STUB_CALL);
        // The call does not return, hence we can ignore any references and just
        // define an empty safepoint.
        ReferenceMap* reference_map = zone()->New<ReferenceMap>(zone());
        RecordSafepoint(reference_map);
        __ AssertUnreachable(AbortReason::kUnexpectedReturnFromWasmTrap);
      }
      __ bind(&done);
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    // Skip callee-saved and return slots, which are created below.
    required_slots -= saves.Count();
    required_slots -= frame()->GetReturnSlotCount();
    if (required_slots > 0) {
      __ AllocateStackSpace(required_slots * kSystemPointerSize);
    }
  }

  if (!saves.is_empty()) {  // Save callee-saved registers.
    DCHECK(!info()->is_osr());
    for (Register reg : base::Reversed(saves)) {
      __ push(reg);
    }
  }

  // Allocate return slots (located after callee-saved).
  if (frame()->GetReturnSlotCount() > 0) {
    __ AllocateStackSpace(frame()->GetReturnSlotCount() * kSystemPointerSize);
  }

  for (int spill_slot : frame()->tagged_slots()) {
    FrameOffset offset = frame_access_state()->GetFrameOffset(spill_slot);
    DCHECK(offset.from_frame_pointer());
    __ mov(Operand(ebp, offset.offset()), Immediate(0));
  }
}

void CodeGenerator::AssembleReturn(InstructionOperand* additional_pop_count) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const RegList saves = call_descriptor->CalleeSavedRegisters();
  // Restore registers.
  if (!saves.is_empty()) {
    const int returns = frame()->GetReturnSlotCount();
    if (returns != 0) {
      __ add(esp, Immediate(returns * kSystemPointerSize));
    }
    for (Register reg : saves) {
      __ pop(reg);
    }
  }

  IA32OperandConverter g(this, nullptr);
  int parameter_slots = static_cast<int>(call_descriptor->ParameterSlotCount());

  // {aditional_pop_count} is only greater than zero if {parameter_slots = 0}.
  // Check RawMachineAssembler::PopAndReturn.
  if (parameter_slots != 0) {
    if (additional_pop_count->IsImmediate()) {
      DCHECK_EQ(g.ToConstant(additional_pop_count).ToInt32(), 0);
    } else if (v8_flags.debug_code) {
      __ cmp(g.ToRegister(additional_pop_count), Immediate(0));
      __ Assert(equal, AbortReason::kUnexpectedAdditionalPopValue);
    }
  }

#if V8_ENABLE_WEBASSEMBLY
  if (call_descriptor->IsWasmFunctionCall() &&
      v8_flags.experimental_wasm_growable_stacks) {
    Register tmp = ecx;
    __ mov(tmp, MemOperand(ebp, TypedFrameConstants::kFrameTypeOffset));
    __ cmp(tmp,
           Immediate(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
    Label done;
    __ j(not_equal, &done);
    for (Register reg : base::Reversed(wasm::kGpReturnRegisters)) {
      __ push(reg);
    }
    __ PrepareCallCFunction(1, kReturnRegister0);
    __ Move(Operand(esp, 0 * kSystemPointerSize),
            Immediate(ExternalReference::isolate_address()));
    __ CallCFunction(ExternalReference::wasm_shrink_stack(), 1);
    // Restore old ebp. We don't need to restore old esp explicitly, because
    // it will be restored from ebp in LeaveFrame before return.
    __ mov(ebp, kReturnRegister0);
    for (Register reg : wasm::kGpReturnRegisters) {
      __ pop(reg);
    }
    __ bind(&done);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  Register argc_reg = ecx;
  // Functions with JS linkage have at least one parameter (the receiver).
  // If {parameter_slots} == 0, it means it is a builtin with
  // kDontAdaptArgumentsSentinel, which takes care of JS arguments popping
  // itself.

  const bool drop_jsargs = parameter_slots != 0 &&
                           frame_access_state()->has_frame() &&
                           call_descriptor->IsJSFunctionCall();
  if (call_descriptor->IsCFunctionCall()) {
    AssembleDeconstructFrame();
  } else if (frame_access_state()->has_frame()) {
    // Canonicalize JSFunction return sites for now if they always have the same
    // number of return args.
    if (additional_pop_count->IsImmediate() &&
        g.ToConstant(additional_pop_count).ToInt32() == 0) {
      if (return_label_.is_bound()) {
        __ jmp(&return_label_);
        return;
      } else {
        __ bind(&return_label_);
      }
    }
    if (drop_jsargs) {
      // Get the actual argument count.
      __ mov(argc_reg, Operand(ebp, StandardFrameConstants::kArgCOffset));
      DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
    }
    AssembleDeconstructFrame();
  }

  if (drop_jsargs) {
    // We must pop all arguments from the stack (including the receiver).
    // The number of arguments without the receiver is
    // max(argc_reg, parameter_slots-1), and the receiver is added in
    // DropArguments().
    Label mismatch_return;
    Register scratch_reg = edx;
    DCHECK_NE(argc_reg, scratch_reg);
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(scratch_reg));
    __ cmp(argc_reg, Immediate(parameter_slots));
    __ j(greater, &mismatch_return, Label::kNear);
    __ Ret(parameter_slots * kSystemPointerSize, scratch_reg);
    __ bind(&mismatch_return);
    __ DropArguments(argc_reg, scratch_reg);
    // We use a return instead of a jump for better return address prediction.
    __ Ret();
  } else if (additional_pop_count->IsImmediate()) {
    int additional_count = g.ToConstant(additional_pop_count).ToInt32();
    size_t pop_size = (parameter_slots + additional_count) * kSystemPointerSize;
    if (is_uint16(pop_size)) {
      // Avoid the additional scratch register, it might clobber the
      // CalleeSavedRegisters.
      __ ret(static_cast<int>(pop_size));
    } else {
      Register scratch_reg = ecx;
      DCHECK(!call_descriptor->CalleeSavedRegisters().has(scratch_reg));
      CHECK_LE(pop_size, static_cast<size_t>(std::numeric_limits<int>::max()));
      __ Ret(static_cast<int>(pop_size), scratch_reg);
    }
  } else {
    Register pop_reg = g.ToRegister(additional_pop_count);
    Register scratch_reg = pop_reg == ecx ? edi : ecx;
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(scratch_reg));
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(pop_reg));
    int pop_size = static_cast<int>(parameter_slots * kSystemPointerSize);
    __ PopReturnAddressTo(scratch_reg);
    __ lea(esp, Operand(esp, pop_reg, times_system_pointer_size,
                        static_cast<int>(pop_size)));
    __ PushReturnAddressFrom(scratch_reg);
    __ Ret();
  }
}

void CodeGenerator::FinishCode() {}

void CodeGenerator::PrepareForDeoptimizationExits(
    ZoneDeque<DeoptimizationExit*>* exits) {}

AllocatedOperand CodeGenerator::Push(InstructionOperand* source) {
  auto rep = LocationOperand::cast(source)->representation();
  int new_slots = ElementSizeInPointers(rep);
  IA32OperandConverter g(this, nullptr);
  int last_frame_slot_id =
      frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
  int sp_delta = frame_access_state_->sp_delta();
  int slot_id = last_frame_slot_id + sp_delta + new_slots;
  AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
  if (source->IsRegister()) {
    __ push(g.ToRegister(source));
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else if (source->IsStackSlot() || source->IsFloatStackSlot()) {
    __ push(g.ToOperand(source));
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else {
    // No push instruction for this operand type. Bump the stack pointer and
    // assemble the move.
    __ sub(esp, Immediate(new_slots * kSystemPointerSize));
    frame_access_state()->IncreaseSPDelta(new_slots);
    AssembleMove(source, &stack_slot);
  }
  temp_slots_ += new_slots;
  return stack_slot;
}

void CodeGenerator::Pop(InstructionOperand* dest, MachineRepresentation rep) {
  IA32OperandConverter g(this, nullptr);
  int dropped_slots = ElementSizeInPointers(rep);
  if (dest->IsRegister()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ pop(g.ToRegister(dest));
  } else if (dest->IsStackSlot() || dest->IsFloatStackSlot()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ pop(g.ToOperand(dest));
  } else {
    int last_frame_slot_id =
        frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
    int sp_delta = frame_access_state_->sp_delta();
    int slot_id = last_frame_slot_id + sp_delta;
    AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
    AssembleMove(&stack_slot, dest);
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ add(esp, Immediate(dropped_slots * kSystemPointerSize));
  }
  temp_slots_ -= dropped_slots;
}

void CodeGenerator::PopTempStackSlots() {
  if (temp_slots_ > 0) {
    frame_access_state()->IncreaseSPDelta(-temp_slots_);
    __ add(esp, Immediate(temp_slots_ * kSystemPointerSize));
    temp_slots_ = 0;
  }
}

void CodeGenerator::MoveToTempLocation(InstructionOperand* source,
                                       MachineRepresentation rep) {
  // Must be kept in sync with {MoveTempLocationTo}.
  DCHECK(!source->IsImmediate());
  if ((IsFloatingPoint(rep) &&
       !move_cycle_.pending_double_scratch_register_use)) {
    // The scratch double register is available.
    AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                             kScratchDoubleReg.code());
    AssembleMove(source, &scratch);
  } else {
    // The scratch register blocked by pending moves. Use the stack instead.
    Push(source);
  }
}

void CodeGenerator::MoveTempLocationTo(InstructionOperand* dest,
                                       MachineRepresentation rep) {
  if (IsFloatingPoint(rep) &&
      !move_cycle_.pending_double_scratch_register_use) {
    AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                             kScratchDoubleReg.code());
    AssembleMove(&scratch, dest);
  } else {
    Pop(dest, rep);
  }
  move_cycle_ = MoveCycleState();
}

void CodeGenerator::SetPendingMove(MoveOperands* move) {
  InstructionOperand* source = &move->source();
  InstructionOperand* destination = &move->destination();
  MoveType::Type move_type = MoveType::InferMove(source, destination);
  if (move_type == MoveType::kStackToStack) {
    if (!source->IsStackSlot()) {
      move_cycle_.pending_double_scratch_register_use = true;
    }
    return;
  }
}

void CodeGenerator::AssembleMove(InstructionOperand* source,
                                 InstructionOperand* destination) {
  IA32OperandConverter g(this, nullptr);
  // Dispatch on the source and destination operand kinds.
  switch (MoveType::InferMove(source, destination)) {
    case MoveType::kRegisterToRegister:
      if (source->IsRegister()) {
        __ mov(g.ToRegister(destination), g.ToRegister(source));
      } else {
        DCHECK(source->IsFPRegister());
        __ Movaps(g.ToDoubleRegister(destination), g.ToDoubleRegister(source));
      }
      return;
    case MoveType::kRegisterToStack: {
      Operand dst = g.ToOperand(destination);
      if (source->IsRegister()) {
        __ mov(dst, g.ToRegister(source));
      } else {
        DCHECK(source->IsFPRegister());
        XMMRegister src = g.ToDoubleRegister(source);
        MachineRepresentation rep =
            LocationOperand::cast(source)->representation();
        if (rep == MachineRepresentation::kFloat32) {
          __ Movss(dst, src);
        } else if (rep == MachineRepresentation::kFloat64) {
          __ Movsd(dst, src);
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, rep);
          __ Movups(dst, src);
        }
      }
      return;
    }
    case MoveType::kStackToRegister: {
      Operand src = g.ToOperand(source);
      if (source->IsStackSlot()) {
        __ mov(g.ToRegister(destination), src);
      } else {
        DCHECK(source->IsFPStackSlot());
        XMMRegister dst = g.ToDoubleRegister(destination);
        MachineRepresentation rep =
            LocationOperand
```