Response:
The user wants a summary of the provided C++ code snippet from `v8/src/compiler/backend/arm/code-generator-arm.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the file's purpose:** The filename `code-generator-arm.cc` strongly suggests this file is responsible for generating ARM assembly code from a higher-level representation (likely the intermediate representation used by V8's TurboFan compiler). The directory `v8/src/compiler/backend/arm` confirms it's part of the ARM backend.

2. **Analyze the code blocks:**  The provided snippet is a large `switch` statement within a function (likely `AssembleInstruction`). The `case` labels (`kAtomicCompareExchangeUint16`, `kAtomicAddInt8`, `kArmWord32AtomicPairLoad`, etc.) clearly indicate that this code handles the generation of assembly instructions for various atomic operations on different data sizes.

3. **Categorize the operations:**  The `case` names reveal several categories:
    * **Atomic Compare and Exchange:**  Operations like `kAtomicCompareExchangeWord32` suggest atomic updates based on a comparison.
    * **Atomic Binary Operations:** The `ATOMIC_BINOP_CASE` macro hints at common binary operations (Add, Sub, And, Or, Xor) performed atomically. The `ldrexb/strexb`, `ldrexh/strexh`, `ldrex/strex` instructions are key ARM atomic load/store primitives.
    * **Atomic Pair Operations:** Cases like `kArmWord32AtomicPairLoad`, `kArmWord32AtomicPairStore`, and the `ATOMIC_ARITH_BINOP_CASE`/`ATOMIC_LOGIC_BINOP_CASE` macros point to atomic operations on pairs of 32-bit words (64-bit values).
    * **Atomic Exchange:** `kArmWord32AtomicPairExchange` suggests atomically swapping a pair of words.

4. **Infer the overall function's role:**  Based on the `switch` statement and the types of operations, the primary function of this part of the code is to translate high-level atomic operation instructions into their corresponding ARM assembly code sequences. This involves:
    * Loading values atomically (`ldrex`, `ldrexb`, `ldrexh`, `ldrexd`).
    * Performing the operation (add, sub, and_, orr, eor).
    * Storing the result atomically (`strex`, `strexb`, `strexh`, `strexd`).
    * Handling potential failures in atomic operations (e.g., using labels and conditional branches to retry on contention).
    * Ensuring memory ordering (`dmb` - Data Memory Barrier).

5. **Address the specific questions:**
    * **Functionality:** List the identified categories of atomic operations and their purpose.
    * **Torque:**  The code doesn't end with `.tq`, so it's not a Torque file.
    * **JavaScript relation:** Atomic operations are related to concurrency in JavaScript. Provide an example using `SharedArrayBuffer` and `Atomics` to demonstrate how these low-level operations manifest in JS.
    * **Code Logic Inference:** Select a simple atomic operation (like `kAtomicAddInt8`) and explain the input (memory address, value to add) and output (the original value at the address).
    * **Common Programming Errors:** Concurrency is prone to errors. Give an example of a race condition that atomic operations help prevent.
    * **Part 5 Summary:**  Synthesize the findings into a concise summary for this particular code section.

6. **Refine and organize:** Structure the answer logically with clear headings and bullet points. Use precise terminology (e.g., "load-exclusive," "store-exclusive"). Ensure the JavaScript example is relevant and easy to understand.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Maybe it's just about basic arithmetic.
* **Correction:** The presence of `ldrex`/`strex` and the "Atomic" prefixes clearly indicate atomic operations, which are more complex than simple arithmetic.
* **Initial thought:** Focus on individual instructions.
* **Correction:** Grouping the cases into categories (compare-exchange, binary ops, pair ops) provides a better high-level understanding.
* **Initial thought:**  The JavaScript example might be too technical.
* **Correction:**  Simplify the example to focus on the core concept of concurrent modification and how atomics help.

By following these steps, the comprehensive and accurate answer can be generated.
好的，让我们来分析一下这段V8源代码 `v8/src/compiler/backend/arm/code-generator-arm.cc` 的功能。

**功能归纳：**

这段代码是V8 JavaScript引擎中用于ARM架构的代码生成器的一部分，专门负责将中间表示（IR）中的原子操作指令转换为ARM汇编代码。它涵盖了各种原子操作，包括：

* **原子比较并交换 (Atomic Compare and Exchange):**  允许原子地比较内存中的值和一个预期值，如果相等则将内存中的值更新为新的值。支持不同大小的数据类型（Uint16, Word32）。
* **原子二元运算 (Atomic Binary Operations):**  提供原子地执行加、减、与、或、异或等二元运算的能力。同样支持不同大小的数据类型（Int8, Uint8, Int16, Uint16, Word32）。
* **原子加载和存储对 (Atomic Pair Load and Store):**  用于原子地加载或存储一对32位的字（相当于64位）。
* **原子算术和逻辑运算对 (Atomic Arithmetic and Logic Operations on Pairs):** 提供原子地对一对32位字执行加、减、与、或、异或等操作。
* **原子交换对 (Atomic Exchange Pair):** 原子地将内存中的一对32位字与一对新的32位字进行交换。
* **原子比较并交换对 (Atomic Compare and Exchange Pair):** 原子地比较内存中的一对32位字与预期值，如果相等则更新为新的值对。

**关于文件类型：**

根据您提供的描述，`v8/src/compiler/backend/arm/code-generator-arm.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。

**与 JavaScript 功能的关系 (示例):**

这段代码中实现的原子操作与 JavaScript 中的 `Atomics` 对象息息相关。`Atomics` 对象提供了一组静态方法来执行原子操作，这些操作对于实现多线程或共享内存的并发编程至关重要。

例如，`kAtomicCompareExchangeWord32` 这个 case 对应于 JavaScript 中 `Atomics.compareExchange()` 方法对 32 位整数的操作。

**JavaScript 示例：**

```javascript
// 创建一个共享的 ArrayBuffer
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const view = new Int32Array(sab);

// 初始值
view[0] = 10;

// 模拟两个线程并发地尝试比较并交换值
function workerThread(expectedValue, newValue) {
  const current = Atomics.compareExchange(view, 0, expectedValue, newValue);
  console.log(`线程执行：期望 ${expectedValue}, 更新为 ${newValue}, 实际 ${current}`);
}

// 启动两个线程
const thread1 = () => workerThread(10, 20);
const thread2 = () => workerThread(10, 30);

thread1();
thread2();

console.log("最终值:", view[0]);
```

**代码逻辑推理 (假设输入与输出):**

以 `kAtomicAddInt8` 这个 case 为例，假设：

* **输入:**
    * `i.InputRegister(0)`: 内存地址的寄存器 (例如，R0)
    * `i.InputRegister(1)`: 偏移量的寄存器 (例如，R1)
    * `i.OutputRegister(0)`: 用于存放结果的寄存器 (例如，R2)，同时也是要加上的值的寄存器。

* **假设执行前的内存状态:**  假设内存地址 `R0 + R1` 处的值为 `5`，并且 `R2` 的值为 `3`。

* **代码逻辑:**
    1. `ASSEMBLE_ATOMIC_BINOP(ldrexb, strexb, add)`:  这会生成原子地将内存中的字节加载到临时寄存器，然后将 `R2` 的值加到临时寄存器，最后将结果原子地存储回内存的指令序列。
    2. `__ sxtb(i.OutputRegister(0), i.OutputRegister(0));`: 这会将结果寄存器 `R2` 中的值进行符号扩展为 32 位。

* **输出:**
    * **寄存器 R2 的值:** `8` (因为内存中的原始值 5 加上了 R2 的值 3)。
    * **内存地址 `R0 + R1` 处的值:** `8` (原子加操作已完成)。

**用户常见的编程错误 (与原子操作相关):**

使用原子操作时，一个常见的错误是 **不恰当地使用或过度依赖原子操作**。

**示例：**

```javascript
// 错误的示例：使用原子操作进行非原子级别的计数

let counter = 0;

function increment() {
  // 这不是一个原子操作，即使单独的操作是原子的
  const oldValue = Atomics.load(view, 0);
  const newValue = oldValue + 1;
  Atomics.store(view, 0, newValue);
  counter++; // 这个自增操作不是原子的，在多线程环境下可能导致数据竞争
}

// 正确的示例：使用原子加
function atomicIncrement() {
  Atomics.add(view, 0, 1);
}
```

在错误的示例中，即使 `Atomics.load` 和 `Atomics.store` 是原子操作，但读取值、加 1、再存储的整个过程不是原子的。在多线程环境下，两个线程可能同时读取到相同的 `oldValue`，然后各自加 1 并存储，导致计数丢失。

**第 5 部分功能归纳:**

作为第 5 部分，这段代码主要关注于 **生成 ARM 汇编代码以实现 JavaScript 中 `Atomics` 对象提供的原子操作功能**。它针对不同的原子操作类型和数据大小提供了相应的代码生成逻辑，确保在多线程环境下对共享内存的访问是安全和一致的。这段代码是 V8 编译器后端的重要组成部分，使得 JavaScript 能够利用底层的硬件原子指令来实现高性能的并发编程。

Prompt: 
```
这是目录为v8/src/compiler/backend/arm/code-generator-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm/code-generator-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
changeUint16:
      __ add(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1));
      __ uxth(i.TempRegister(2), i.InputRegister(2));
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(ldrexh, strexh,
                                               i.TempRegister(2));
      break;
    case kAtomicCompareExchangeWord32:
      __ add(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1));
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(ldrex, strex,
                                               i.InputRegister(2));
      break;
#define ATOMIC_BINOP_CASE(op, inst)                    \
  case kAtomic##op##Int8:                              \
    ASSEMBLE_ATOMIC_BINOP(ldrexb, strexb, inst);       \
    __ sxtb(i.OutputRegister(0), i.OutputRegister(0)); \
    break;                                             \
  case kAtomic##op##Uint8:                             \
    ASSEMBLE_ATOMIC_BINOP(ldrexb, strexb, inst);       \
    break;                                             \
  case kAtomic##op##Int16:                             \
    ASSEMBLE_ATOMIC_BINOP(ldrexh, strexh, inst);       \
    __ sxth(i.OutputRegister(0), i.OutputRegister(0)); \
    break;                                             \
  case kAtomic##op##Uint16:                            \
    ASSEMBLE_ATOMIC_BINOP(ldrexh, strexh, inst);       \
    break;                                             \
  case kAtomic##op##Word32:                            \
    ASSEMBLE_ATOMIC_BINOP(ldrex, strex, inst);         \
    break;
      ATOMIC_BINOP_CASE(Add, add)
      ATOMIC_BINOP_CASE(Sub, sub)
      ATOMIC_BINOP_CASE(And, and_)
      ATOMIC_BINOP_CASE(Or, orr)
      ATOMIC_BINOP_CASE(Xor, eor)
#undef ATOMIC_BINOP_CASE
    case kArmWord32AtomicPairLoad: {
      if (instr->OutputCount() == 2) {
        DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr, r0, r1));
        __ add(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
        __ ldrexd(r0, r1, i.TempRegister(0));
        __ dmb(ISH);
      } else {
        // A special case of this instruction: even though this is a pair load,
        // we only need one of the two words. We emit a normal atomic load.
        DCHECK_EQ(instr->OutputCount(), 1);
        Register base = i.InputRegister(0);
        Register offset = i.InputRegister(1);
        DCHECK(instr->InputAt(2)->IsImmediate());
        int32_t offset_imm = i.InputInt32(2);
        if (offset_imm != 0) {
          Register temp = i.TempRegister(0);
          __ add(temp, offset, Operand(offset_imm));
          offset = temp;
        }
        __ ldr(i.OutputRegister(), MemOperand(base, offset));
        __ dmb(ISH);
      }
      break;
    }
    case kArmWord32AtomicPairStore: {
      Label store;
      Register base = i.InputRegister(0);
      Register offset = i.InputRegister(1);
      Register value_low = i.InputRegister(2);
      Register value_high = i.InputRegister(3);
      Register actual_addr = i.TempRegister(0);
      // The {ldrexd} instruction needs two temp registers. We do not need the
      // result of {ldrexd}, but {strexd} likely fails without the {ldrexd}.
      Register tmp1 = i.TempRegister(1);
      Register tmp2 = i.TempRegister(2);
      // Reuse one of the temp registers for the result of {strexd}.
      Register store_result = tmp1;
      __ add(actual_addr, base, offset);
      __ dmb(ISH);
      __ bind(&store);
      // Add this {ldrexd} instruction here so that {strexd} below can succeed.
      // We don't need the result of {ldrexd} itself.
      __ ldrexd(tmp1, tmp2, actual_addr);
      __ strexd(store_result, value_low, value_high, actual_addr);
      __ cmp(store_result, Operand(0));
      __ b(ne, &store);
      __ dmb(ISH);
      break;
    }
#define ATOMIC_ARITH_BINOP_CASE(op, instr1, instr2)           \
  case kArmWord32AtomicPair##op: {                            \
    DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr, r2, r3)); \
    ASSEMBLE_ATOMIC64_ARITH_BINOP(instr1, instr2);            \
    break;                                                    \
  }
      ATOMIC_ARITH_BINOP_CASE(Add, add, adc)
      ATOMIC_ARITH_BINOP_CASE(Sub, sub, sbc)
#undef ATOMIC_ARITH_BINOP_CASE
#define ATOMIC_LOGIC_BINOP_CASE(op, instr1)                   \
  case kArmWord32AtomicPair##op: {                            \
    DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr, r2, r3)); \
    ASSEMBLE_ATOMIC64_LOGIC_BINOP(instr1);                    \
    break;                                                    \
  }
      ATOMIC_LOGIC_BINOP_CASE(And, and_)
      ATOMIC_LOGIC_BINOP_CASE(Or, orr)
      ATOMIC_LOGIC_BINOP_CASE(Xor, eor)
#undef ATOMIC_LOGIC_BINOP_CASE
    case kArmWord32AtomicPairExchange: {
      DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr, r6, r7));
      Label exchange;
      __ add(i.TempRegister(0), i.InputRegister(2), i.InputRegister(3));
      __ dmb(ISH);
      __ bind(&exchange);
      __ ldrexd(r6, r7, i.TempRegister(0));
      __ strexd(i.TempRegister(1), i.InputRegister(0), i.InputRegister(1),
                i.TempRegister(0));
      __ teq(i.TempRegister(1), Operand(0));
      __ b(ne, &exchange);
      __ dmb(ISH);
      break;
    }
    case kArmWord32AtomicPairCompareExchange: {
      DCHECK(VerifyOutputOfAtomicPairInstr(&i, instr, r2, r3));
      __ add(i.TempRegister(0), i.InputRegister(4), i.InputRegister(5));
      Label compareExchange;
      Label exit;
      __ dmb(ISH);
      __ bind(&compareExchange);
      __ ldrexd(r2, r3, i.TempRegister(0));
      __ teq(i.InputRegister(0), Operand(r2));
      __ b(ne, &exit);
      __ teq(i.InputRegister(1), Operand(r3));
      __ b(ne, &exit);
      __ strexd(i.TempRegister(1), i.InputRegister(2), i.InputRegister(3),
                i.TempRegister(0));
      __ teq(i.TempRegister(1), Operand(0));
      __ b(ne, &compareExchange);
      __ bind(&exit);
      __ dmb(ISH);
      break;
    }
#undef ASSEMBLE_ATOMIC_LOAD_INTEGER
#undef ASSEMBLE_ATOMIC_STORE_INTEGER
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_BINOP
#undef ASSEMBLE_ATOMIC64_ARITH_BINOP
#undef ASSEMBLE_ATOMIC64_LOGIC_BINOP
#undef ASSEMBLE_IEEE754_BINOP
#undef ASSEMBLE_IEEE754_UNOP
#undef ASSEMBLE_NEON_NARROWING_OP
#undef ASSEMBLE_SIMD_SHIFT_LEFT
#undef ASSEMBLE_SIMD_SHIFT_RIGHT
  }
  return kSuccess;
}

// Assembles branches after an instruction.
void CodeGenerator::AssembleArchBranch(Instruction* instr, BranchInfo* branch) {
  ArmOperandConverter i(this, instr);
  Label* tlabel = branch->true_label;
  Label* flabel = branch->false_label;
  Condition cc = FlagsConditionToCondition(branch->condition);
  __ b(cc, tlabel);
  if (!branch->fallthru) __ b(flabel);  // no fallthru to flabel.
}

void CodeGenerator::AssembleArchDeoptBranch(Instruction* instr,
                                            BranchInfo* branch) {
  AssembleArchBranch(instr, branch);
}

void CodeGenerator::AssembleArchJumpRegardlessOfAssemblyOrder(
    RpoNumber target) {
  __ b(GetLabel(target));
}

#if V8_ENABLE_WEBASSEMBLY
void CodeGenerator::AssembleArchTrap(Instruction* instr,
                                     FlagsCondition condition) {
  class OutOfLineTrap final : public OutOfLineCode {
   public:
    OutOfLineTrap(CodeGenerator* gen, Instruction* instr)
        : OutOfLineCode(gen), instr_(instr), gen_(gen) {}

    void Generate() final {
      ArmOperandConverter i(gen_, instr_);
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
      __ Call(static_cast<Address>(trap_id), RelocInfo::WASM_STUB_CALL);
      ReferenceMap* reference_map =
          gen_->zone()->New<ReferenceMap>(gen_->zone());
      gen_->RecordSafepoint(reference_map);
      if (v8_flags.debug_code) {
        __ stop();
      }
    }

    Instruction* instr_;
    CodeGenerator* gen_;
  };
  auto ool = zone()->New<OutOfLineTrap>(this, instr);
  Label* tlabel = ool->entry();
  Condition cc = FlagsConditionToCondition(condition);
  __ b(cc, tlabel);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Assembles boolean materializations after an instruction.
void CodeGenerator::AssembleArchBoolean(Instruction* instr,
                                        FlagsCondition condition) {
  ArmOperandConverter i(this, instr);

  // Materialize a full 32-bit 1 or 0 value. The result register is always the
  // last output of the instruction.
  DCHECK_NE(0u, instr->OutputCount());
  Register reg = i.OutputRegister(instr->OutputCount() - 1);
  Condition cc = FlagsConditionToCondition(condition);
  __ mov(reg, Operand(0));
  __ mov(reg, Operand(1), LeaveCC, cc);
}

void CodeGenerator::AssembleArchConditionalBoolean(Instruction* instr) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchConditionalBranch(Instruction* instr,
                                                  BranchInfo* branch) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchBinarySearchSwitch(Instruction* instr) {
  ArmOperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  std::vector<std::pair<int32_t, Label*>> cases;
  for (size_t index = 2; index < instr->InputCount(); index += 2) {
    cases.push_back({i.InputInt32(index + 0), GetLabel(i.InputRpo(index + 1))});
  }
  AssembleArchBinarySearchSwitchRange(input, i.InputRpo(1), cases.data(),
                                      cases.data() + cases.size());
}

void CodeGenerator::AssembleArchTableSwitch(Instruction* instr) {
  ArmOperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  size_t const case_count = instr->InputCount() - 2;
  // This {cmp} might still emit a constant pool entry.
  __ cmp(input, Operand(case_count));
  // Ensure to emit the constant pool first if necessary.
  __ CheckConstPool(true, true);
  __ BlockConstPoolFor(case_count + 2);
  __ add(pc, pc, Operand(input, LSL, 2), LeaveCC, lo);
  __ b(GetLabel(i.InputRpo(1)));
  for (size_t index = 0; index < case_count; ++index) {
    __ b(GetLabel(i.InputRpo(index + 2)));
  }
}

void CodeGenerator::AssembleArchSelect(Instruction* instr,
                                       FlagsCondition condition) {
  UNIMPLEMENTED();
}

void CodeGenerator::FinishFrame(Frame* frame) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const DoubleRegList saves_fp = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fp.is_empty()) {
    frame->AlignSavedCalleeRegisterSlots();
  }

  if (!saves_fp.is_empty()) {
    // Save callee-saved FP registers.
    static_assert(DwVfpRegister::kNumRegisters == 32);
    uint32_t last = base::bits::CountLeadingZeros32(saves_fp.bits()) - 1;
    uint32_t first = base::bits::CountTrailingZeros32(saves_fp.bits());
    DCHECK_EQ((last - first + 1), saves_fp.Count());
    frame->AllocateSavedCalleeRegisterSlots((last - first + 1) *
                                            (kDoubleSize / kSystemPointerSize));
  }
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    // Save callee-saved registers.
    frame->AllocateSavedCalleeRegisterSlots(saves.Count());
  }
}

void CodeGenerator::AssembleConstructFrame() {
  auto call_descriptor = linkage()->GetIncomingDescriptor();
  if (frame_access_state()->has_frame()) {
    if (call_descriptor->IsCFunctionCall()) {
#if V8_ENABLE_WEBASSEMBLY
      if (info()->GetOutputStackFrameType() == StackFrame::C_WASM_ENTRY) {
        __ StubPrologue(StackFrame::C_WASM_ENTRY);
        // Reserve stack space for saving the c_entry_fp later.
        __ AllocateStackSpace(kSystemPointerSize);
#else
      // For balance.
      if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
      } else {
        __ Push(lr, fp);
        __ mov(fp, sp);
      }
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
        __ Push(kWasmImplicitArgRegister);
      }
      if (call_descriptor->IsWasmCapiFunction()) {
        // Reserve space for saving the PC later.
        __ AllocateStackSpace(kSystemPointerSize);
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    }

    unwinding_info_writer_.MarkFrameConstructed(__ pc_offset());
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
  const DoubleRegList saves_fp = call_descriptor->CalleeSavedFPRegisters();

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
        UseScratchRegisterScope temps(masm());
        Register stack_limit = temps.Acquire();
        __ LoadStackLimit(stack_limit, StackLimitKind::kRealStackLimit);
        __ add(stack_limit, stack_limit,
               Operand(required_slots * kSystemPointerSize));
        __ cmp(sp, stack_limit);
        __ b(cs, &done);
      }

      if (v8_flags.experimental_wasm_growable_stacks) {
        RegList regs_to_save;
        regs_to_save.set(WasmHandleStackOverflowDescriptor::GapRegister());
        regs_to_save.set(
            WasmHandleStackOverflowDescriptor::FrameBaseRegister());
        for (auto reg : wasm::kGpParamRegisters) regs_to_save.set(reg);
        __ stm(db_w, sp, regs_to_save);
        __ mov(WasmHandleStackOverflowDescriptor::GapRegister(),
               Operand(required_slots * kSystemPointerSize));
        __ add(
            WasmHandleStackOverflowDescriptor::FrameBaseRegister(), fp,
            Operand(call_descriptor->ParameterSlotCount() * kSystemPointerSize +
                    CommonFrameConstants::kFixedFrameSizeAboveFp));
        __ CallBuiltin(Builtin::kWasmHandleStackOverflow);
        __ ldm(ia_w, sp, regs_to_save);
      } else {
        __ Call(static_cast<intptr_t>(Builtin::kWasmStackOverflow),
                RelocInfo::WASM_STUB_CALL);
        // The call does not return, hence we can ignore any references and just
        // define an empty safepoint.
        ReferenceMap* reference_map = zone()->New<ReferenceMap>(zone());
        RecordSafepoint(reference_map);
        if (v8_flags.debug_code) __ stop();
      }

      __ bind(&done);
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    // Skip callee-saved and return slots, which are pushed below.
    required_slots -= saves.Count();
    required_slots -= frame()->GetReturnSlotCount();
    required_slots -= 2 * saves_fp.Count();
    if (required_slots > 0) {
      __ AllocateStackSpace(required_slots * kSystemPointerSize);
    }
  }

  if (!saves_fp.is_empty()) {
    // Save callee-saved FP registers.
    static_assert(DwVfpRegister::kNumRegisters == 32);
    __ vstm(db_w, sp, saves_fp.first(), saves_fp.last());
  }

  if (!saves.is_empty()) {
    // Save callee-saved registers.
    __ stm(db_w, sp, saves);
  }

  const int returns = frame()->GetReturnSlotCount();
  // Create space for returns.
  __ AllocateStackSpace(returns * kSystemPointerSize);

  if (!frame()->tagged_slots().IsEmpty()) {
    UseScratchRegisterScope temps(masm());
    Register zero = temps.Acquire();
    __ mov(zero, Operand(0));
    for (int spill_slot : frame()->tagged_slots()) {
      FrameOffset offset = frame_access_state()->GetFrameOffset(spill_slot);
      DCHECK(offset.from_frame_pointer());
      __ str(zero, MemOperand(fp, offset.offset()));
    }
  }
}

void CodeGenerator::AssembleReturn(InstructionOperand* additional_pop_count) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const int returns = frame()->GetReturnSlotCount();
  if (returns != 0) {
    // Free space of returns.
    __ add(sp, sp, Operand(returns * kSystemPointerSize));
  }

  // Restore registers.
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    __ ldm(ia_w, sp, saves);
  }

  // Restore FP registers.
  const DoubleRegList saves_fp = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fp.is_empty()) {
    static_assert(DwVfpRegister::kNumRegisters == 32);
    __ vldm(ia_w, sp, saves_fp.first(), saves_fp.last());
  }

  unwinding_info_writer_.MarkBlockWillExit();

  ArmOperandConverter g(this, nullptr);
  const int parameter_slots =
      static_cast<int>(call_descriptor->ParameterSlotCount());

  // {additional_pop_count} is only greater than zero if {parameter_slots = 0}.
  // Check RawMachineAssembler::PopAndReturn.
  if (parameter_slots != 0) {
    if (additional_pop_count->IsImmediate()) {
      DCHECK_EQ(g.ToConstant(additional_pop_count).ToInt32(), 0);
    } else if (v8_flags.debug_code) {
      __ cmp(g.ToRegister(additional_pop_count), Operand(0));
      __ Assert(eq, AbortReason::kUnexpectedAdditionalPopValue);
    }
  }

#if V8_ENABLE_WEBASSEMBLY
  if (call_descriptor->IsWasmFunctionCall() &&
      v8_flags.experimental_wasm_growable_stacks) {
    {
      UseScratchRegisterScope temps{masm()};
      Register scratch = temps.Acquire();
      __ ldr(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
      __ cmp(scratch,
             Operand(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
    }
    Label done;
    __ b(&done, ne);
    RegList regs_to_save;
    for (auto reg : wasm::kGpReturnRegisters) regs_to_save.set(reg);
    __ stm(db_w, sp, regs_to_save);
    __ Move(kCArgRegs[0], ExternalReference::isolate_address());
    __ PrepareCallCFunction(1);
    __ CallCFunction(ExternalReference::wasm_shrink_stack(), 1);
    // Restore old FP. We don't need to restore old SP explicitly, because
    // it will be restored from FP in LeaveFrame before return.
    __ mov(fp, kReturnRegister0);
    __ ldm(ia_w, sp, regs_to_save);
    __ bind(&done);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  Register argc_reg = r3;
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
    // Canonicalize JSFunction return sites for now unless they have an variable
    // number of stack slot pops.
    if (additional_pop_count->IsImmediate() &&
        g.ToConstant(additional_pop_count).ToInt32() == 0) {
      if (return_label_.is_bound()) {
        __ b(&return_label_);
        return;
      } else {
        __ bind(&return_label_);
      }
    }
    if (drop_jsargs) {
      // Get the actual argument count.
      __ ldr(argc_reg, MemOperand(fp, StandardFrameConstants::kArgCOffset));
      DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
    }
    AssembleDeconstructFrame();
  }

  if (drop_jsargs) {
    // We must pop all arguments from the stack (including the receiver).
    // The number of arguments without the receiver is
    // max(argc_reg, parameter_slots-1), and the receiver is added in
    // DropArguments().
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
    if (parameter_slots > 1) {
      __ cmp(argc_reg, Operand(parameter_slots));
      __ mov(argc_reg, Operand(parameter_slots), LeaveCC, lt);
    }
    __ DropArguments(argc_reg);
  } else if (additional_pop_count->IsImmediate()) {
    DCHECK_EQ(Constant::kInt32, g.ToConstant(additional_pop_count).type());
    int additional_count = g.ToConstant(additional_pop_count).ToInt32();
    __ Drop(parameter_slots + additional_count);
  } else if (parameter_slots == 0) {
    __ Drop(g.ToRegister(additional_pop_count));
  } else {
    // {additional_pop_count} is guaranteed to be zero if {parameter_slots !=
    // 0}. Check RawMachineAssembler::PopAndReturn.
    __ Drop(parameter_slots);
  }
  __ Ret();
}

void CodeGenerator::FinishCode() { __ CheckConstPool(true, false); }

void CodeGenerator::PrepareForDeoptimizationExits(
    ZoneDeque<DeoptimizationExit*>* exits) {
  __ CheckConstPool(true, false);
}

void CodeGenerator::AssembleMove(InstructionOperand* source,
                                 InstructionOperand* destination) {
  ArmOperandConverter g(this, nullptr);
  // Helper function to write the given constant to the dst register.
  auto MoveConstantToRegister = [&](Register dst, Constant src) {
    if (src.type() == Constant::kHeapObject) {
      Handle<HeapObject> src_object = src.ToHeapObject();
      RootIndex index;
      if (IsMaterializableFromRoot(src_object, &index)) {
        __ LoadRoot(dst, index);
      } else {
        __ Move(dst, src_object);
      }
    } else if (src.type() == Constant::kExternalReference) {
      __ Move(dst, src.ToExternalReference());
    } else {
      __ mov(dst, g.ToImmediate(source));
    }
  };
  switch (MoveType::InferMove(source, destination)) {
    case MoveType::kRegisterToRegister:
      if (source->IsRegister()) {
        __ mov(g.ToRegister(destination), g.ToRegister(source));
      } else if (source->IsFloatRegister()) {
        DCHECK(destination->IsFloatRegister());
        // GapResolver may give us reg codes that don't map to actual
        // s-registers. Generate code to work around those cases.
        int src_code = LocationOperand::cast(source)->register_code();
        int dst_code = LocationOperand::cast(destination)->register_code();
        __ VmovExtended(dst_code, src_code);
      } else if (source->IsDoubleRegister()) {
        __ Move(g.ToDoubleRegister(destination), g.ToDoubleRegister(source));
      } else {
        __ Move(g.ToSimd128Register(destination), g.ToSimd128Register(source));
      }
      return;
    case MoveType::kRegisterToStack: {
      MemOperand dst = g.ToMemOperand(destination);
      if (source->IsRegister()) {
        __ str(g.ToRegister(source), dst);
      } else if (source->IsFloatRegister()) {
        // GapResolver may give us reg codes that don't map to actual
        // s-registers. Generate code to work around those cases.
        int src_code = LocationOperand::cast(source)->register_code();
        __ VmovExtended(dst, src_code);
      } else if (source->IsDoubleRegister()) {
        __ vstr(g.ToDoubleRegister(source), dst);
      } else {
        UseScratchRegisterScope temps(masm());
        Register temp = temps.Acquire();
        QwNeonRegister src = g.ToSimd128Register(source);
        __ add(temp, dst.rn(), Operand(dst.offset()));
        __ vst1(Neon8, NeonListOperand(src.low(), 2), NeonMemOperand(temp));
      }
      return;
    }
    case MoveType::kStackToRegister: {
      MemOperand src = g.ToMemOperand(source);
      if (source->IsStackSlot()) {
        __ ldr(g.ToRegister(destination), src);
      } else if (source->IsFloatStackSlot()) {
        DCHECK(destination->IsFloatRegister());
        // GapResolver may give us reg codes that don't map to actual
        // s-registers. Generate code to work around those cases.
        int dst_code = LocationOperand::cast(destination)->register_code();
        __ VmovExtended(dst_code, src);
      } else if (source->IsDoubleStackSlot()) {
        __ vldr(g.ToDoubleRegister(destination), src);
      } else {
        UseScratchRegisterScope temps(masm());
        Register temp = temps.Acquire();
        QwNeonRegister dst = g.ToSimd128Register(destination);
        __ add(temp, src.rn(), Operand(src.offset()));
        __ vld1(Neon8, NeonListOperand(dst.low(), 2), NeonMemOperand(temp));
      }
      return;
    }
    case MoveType::kStackToStack: {
      MemOperand src = g.ToMemOperand(source);
      MemOperand dst = g.ToMemOperand(destination);
      UseScratchRegisterScope temps(masm());
      if (source->IsStackSlot() || source->IsFloatStackSlot()) {
        SwVfpRegister temp = temps.AcquireS();
        __ vldr(temp, src);
        __ vstr(temp, dst);
      } else if (source->IsDoubleStackSlot()) {
        DwVfpRegister temp = temps.AcquireD();
        __ vldr(temp, src);
        __ vstr(temp, dst);
      } else {
        DCHECK(source->IsSimd128StackSlot());
        Register temp = temps.Acquire();
        QwNeonRegister temp_q = temps.AcquireQ();
        __ add(temp, src.rn(), Operand(src.offset()));
        __ vld1(Neon8, NeonListOperand(temp_q.low(), 2), NeonMemOperand(temp));
        __ add(temp, dst.rn(), Operand(dst.offset()));
        __ vst1(Neon8, NeonListOperand(temp_q.low(), 2), NeonMemOperand(temp));
      }
      return;
    }
    case MoveType::kConstantToRegister: {
      Constant src = g.ToConstant(source);
      if (destination->IsRegister()) {
        MoveConstantToRegister(g.ToRegister(destination), src);
      } else if (destination->IsFloatRegister()) {
        __ vmov(g.ToFloatRegister(destination),
                Float32::FromBits(src.ToFloat32AsInt()));
      } else {
        // TODO(arm): Look into optimizing this further if possible. Supporting
        // the NEON version of VMOV may help.
        __ vmov(g.ToDoubleRegister(destination), src.ToFloat64());
      }
      return;
    }
    case MoveType::kConstantToStack: {
      Constant src = g.ToConstant(source);
      MemOperand dst = g.ToMemOperand(destination);
      if (destination->IsStackSlot()) {
        UseScratchRegisterScope temps(masm());
        // Acquire a S register instead of a general purpose register in case
        // `vstr` needs one to compute the address of `dst`.
        SwVfpRegister s_temp = temps.AcquireS();
        {
          // TODO(arm): This sequence could be optimized further if necessary by
          // writing the constant directly into `s_temp`.
          UseScratchRegisterScope temps(masm());
          Register temp = temps.Acquire();
          MoveConstantToRegister(temp, src);
          __ vmov(s_temp, temp);
        }
        __ vstr(s_temp, dst);
      } else if (destination->IsFloatStackSlot()) {
        UseScratchRegisterScope temps(masm());
        SwVfpRegister temp = temps.AcquireS();
        __ vmov(temp, Float32::FromBits(src.ToFloat32AsInt()));
        __ vstr(temp, dst);
      } else {
        DCHECK(destination->IsDoubleStackSlot());
        UseScratchRegisterScope temps(masm());
        DwVfpRegister temp = temps.AcquireD();
        // TODO(arm): Look into optimizing this further if possible. Supporting
        // the NEON version of VMOV may help.
        __ vmov(temp, src.ToFloat64());
        __ vstr(temp, g.ToMemOperand(destination));
      }
      return;
    }
  }
  UNREACHABLE();
}

AllocatedOperand CodeGenerator::Push(InstructionOperand* source) {
  auto rep = LocationOperand::cast(source)->representation();
  int new_slots = ElementSizeInPointers(rep);
  ArmOperandConverter g(this, nullptr);
  int last_frame_slot_id =
      frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
  int sp_delta = frame_access_state_->sp_delta();
  int slot_id = last_frame_slot_id + sp_delta + new_slots;
  AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
  if (source->IsRegister()) {
    __ push(g.ToRegister(source));
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else if (source->IsStackSlot()) {
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    __ ldr(scratch, g.ToMemOperand(source));
    __ push(scratch);
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else {
    // No push instruction for this operand type. Bump the stack pointer and
    // assemble the move.
    __ sub(sp, sp, Operand(new_slots * kSystemPointerSize));
    frame_access_state()->IncreaseSPDelta(new_slots);
    AssembleMove(source, &stack_slot);
  }
  temp_slots_ += new_slots;
  return stack_slot;
}

void CodeGenerator::Pop(InstructionOperand* dest, MachineRepresentation rep) {
  int dropped_slots = ElementSizeInPointers(rep);
  ArmOperandConverter g(this, nullptr);
  if (dest->IsRegister()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ pop(g.ToRegister(dest));
  } else if (dest->IsStackSlot()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    __ pop(scratch);
    __ str(scratch, g.ToMemOperand(dest));
  } else {
    int last_frame_slot_id =
        frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
    int sp_delta = frame_access_state_->sp_delta();
    int slot_id = last_frame_slot_id + sp_delta;
    AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
    AssembleMove(&stack_slot, dest);
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ add(sp, sp, Operand(dropped_slots * kSystemPointerSize));
  }
  temp_slots_ -= dropped_slots;
}

void CodeGenerator::PopTempStackSlots() {
  if (temp_slots_ > 0) {
    frame_access_state()->IncreaseSPDelta(-temp_slots_);
    __ add(sp, sp, Operand(temp_slots_ * kSystemPointerSize));
    temp_slots_ = 0;
  }
}

void CodeGenerator::MoveToTempLocation(InstructionOperand* source,
                                       MachineRepresentation rep) {
  // Must be kept in sync with {MoveTempLocationTo}.
  move_cycle_.temps.emplace(masm());
  auto& temps = *move_cycle_.temps;
  // Temporarily exclude the reserved scratch registers while we pick a
  // location to resolve the cycle. Re-include them immediately afterwards so
  // that they are available to assemble the move.
  temps.Exclude(move_cycle_.scratch_v_reglist);
  int reg_code = -1;
  if ((!IsFloatingPoint(rep) || rep == MachineRepresentation::kFloat32) &&
      temps.CanAcquireS()) {
    reg_code = temps.AcquireS().code();
  } else if (rep == MachineRepresentation::kFloat64 && temps.CanAcquireD()) {
    reg_code = temps.AcquireD().code();
  } else if (rep == MachineRepresentation::kSimd128 && temps.CanAcquireQ()) {
    reg_code = temps.AcquireQ().code();
  }
  temps.Include(move_cycle_.scratch_v_reglist);
  if (reg_code != -1) {
    // A scratch register is available for this rep.
    move_cycle_.scratch_reg_code = reg_code;
    if (IsFloatingPoint(rep)) {
      AllocatedOperand scratch(LocationOperand::REGISTER, rep, reg_code);
      AssembleMove(source, &scratch);
    } else {
      AllocatedOperand scratch(LocationOperand::REGISTER,
                               MachineRepresentation::kFloat32, reg_code);
      ArmOperandConverter g(this, nullptr);
      if (source->IsStackSlot()) {
        __ vldr(g.ToFloatRegister(&scratch), g.ToMemOperand(source));
      } else {
        DCHECK(source->IsRegister());
        __ vmov(g.ToFloatRegister(&scratch), g.ToRegister(source));
      }
    }
  } else {
    // The scratch registers are blocked by pending moves. Use the stack
    // instead.
    Push(source);
  }
}

void CodeGenerator::MoveTempLocationTo(InstructionOperand* dest,
                                       MachineRepresentation rep) {
  int scratch_reg_code = move_cycle_.scratch_reg_code;
  DCHECK(move_cycle_.temps.h
"""


```