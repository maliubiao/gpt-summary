Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/execution/arm64/simulator-arm64.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The filename `simulator-arm64.cc` strongly suggests this code simulates the behavior of ARM64 instructions. The code contains functions named `Visit...` which correspond to different ARM64 instructions. This confirms the simulation purpose.

2. **Categorize Functionality by Instruction Type:** The code is organized around handling different instruction categories. Look for patterns in the `Visit...` function names and the operations within them. Common categories emerge:
    * **Arithmetic/Logical:**  `VisitAddSub...`, `VisitLogical...`
    * **Conditional Comparison:** `VisitConditionalCompare...`
    * **Load/Store:** `VisitLoadStore...`, `VisitLoadLiteral`, `VisitLoadStorePair...`
    * **Atomic Operations:** `VisitLoadStoreAcquireRelease`, `VisitAtomicMemory`
    * **Move:** `VisitMoveWideImmediate`

3. **Analyze Individual Instruction Handlers:** For each category, examine the specific `Visit...` functions to understand their detailed actions. Look for:
    * **Operand Extraction:** How the code retrieves the source registers, immediate values, and memory addresses from the instruction.
    * **Operation Execution:** The core logic that performs the simulated instruction (e.g., addition, bitwise operations, memory access).
    * **Flag Updates:** How the code updates the status registers (NZCV) for arithmetic and logical operations.
    * **Memory Access:** How load and store instructions interact with the simulated memory. Pay attention to different addressing modes (offset, pre/post-index).
    * **Logging:**  The presence of `Log...` functions indicates the simulator tracks and potentially displays the execution flow and register/memory changes.

4. **Address Specific User Questions:**
    * **`.tq` Check:** The code doesn't end in `.tq`, so it's not a Torque file.
    * **JavaScript Relationship:**  Since this is a simulator, it directly relates to how JavaScript code is *executed* on an ARM64 architecture. Provide a simple JavaScript example and explain how these simulated instructions are the low-level steps in that execution. A simple arithmetic operation is a good starting point.
    * **Code Logic and Assumptions:**  For a concrete example, choose a simple arithmetic instruction (like `ADD`). Define input register values and predict the output register value and flag settings based on the code.
    * **Common Programming Errors:** Focus on errors related to memory access, as this is a common area for bugs and heavily featured in the code (e.g., accessing uninitialized memory, stack overflow/underflow).

5. **Synthesize the Summary:** Combine the categorized functionalities into a concise overview. Highlight the core role of the simulator and the types of operations it handles.

6. **Review and Refine:**  Read through the generated response to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. Make sure the JavaScript example and the code logic example are clear and illustrative.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on individual instructions. **Correction:** Group instructions by category to provide a higher-level understanding.
* **Overlook logging:**  Initially, I might miss the significance of the `Log...` functions. **Correction:** Recognize that logging is a key part of a simulator for debugging and understanding execution.
* **JavaScript example too complex:** Trying to link a very complex JavaScript feature directly to the simulator code might be confusing. **Correction:** Choose a very simple JavaScript operation to illustrate the connection.
* **Code logic example too trivial:** A very simple addition might not demonstrate the flag updates. **Correction:** Choose an addition that results in a carry or zero flag to show the flag setting logic.
* **Common errors too abstract:** Mentioning "memory errors" is vague. **Correction:** Provide specific examples like accessing uninitialized memory or stack overflow.

By following these steps and engaging in self-correction, I can arrive at a comprehensive and accurate summary of the provided code snippet.
这是一个V8 JavaScript引擎的源代码文件，具体来说，它位于 `v8/src/execution/arm64` 目录下，并且名为 `simulator-arm64.cc`。从命名上看，它与 **ARM64架构的模拟器** 有关。

**功能归纳:**

这段代码是 V8 引擎中用于模拟 ARM64 架构处理器执行指令的核心部分。它的主要功能是：

1. **指令解码与分发:**  虽然这段代码没有直接展示指令的解码过程，但它包含了一系列的 `Visit...` 函数，每个函数对应一种或一类 ARM64 指令。V8 的模拟器会先解码 ARM64 指令，然后根据指令类型调用相应的 `Visit...` 函数进行模拟执行。

2. **模拟执行算术和逻辑运算指令:**
   - `VisitAddSub...`: 模拟加法和减法指令，包括带进位的加减法。
   - `VisitLogicalShifted`, `VisitLogicalImmediate`: 模拟逻辑运算指令（AND, ORR, EOR），支持移位操作和立即数。
   - `LogicalHelper`:  辅助函数，执行具体的逻辑运算并更新标志位。

3. **模拟条件比较指令:**
   - `VisitConditionalCompareRegister`, `VisitConditionalCompareImmediate`: 模拟条件比较指令，根据条件码和操作数更新状态标志。
   - `ConditionalCompareHelper`: 辅助函数，执行比较并设置标志位。

4. **模拟加载和存储指令:**
   - `VisitLoadStoreUnsignedOffset`, `VisitLoadStoreUnscaledOffset`, `VisitLoadStorePreIndex`, `VisitLoadStorePostIndex`, `VisitLoadStoreRegisterOffset`: 模拟不同寻址模式的加载和存储单个寄存器指令。
   - `VisitLoadStorePairOffset`, `VisitLoadStorePairPreIndex`, `VisitLoadStorePairPostIndex`: 模拟加载和存储寄存器对指令。
   - `VisitLoadLiteral`: 模拟从文字池加载数据的指令。
   - `LoadStoreHelper`: 核心辅助函数，处理加载和存储操作，包括地址计算、内存访问、写回等。
   - `LoadStoreAddress`: 计算加载/存储指令的内存地址。
   - `LoadStoreWriteBack`: 处理加载/存储指令的地址写回操作。

5. **模拟原子操作指令:**
   - `VisitLoadStoreAcquireRelease`: 模拟带有 acquire 和 release 语义的加载和存储指令，用于多线程同步。
   - `VisitAtomicMemory`: 模拟各种原子内存操作，如原子加、原子清除、原子异或、原子设置、原子最大/最小值、原子交换等。
   - `CompareAndSwapHelper`, `CompareAndSwapPairHelper`: 辅助函数，模拟比较并交换操作。
   - `AtomicMemorySimpleHelper`, `AtomicMemorySwapHelper`: 辅助函数，模拟简单的原子内存操作和原子交换操作。

6. **模拟移动指令:**
   - `VisitMoveWideImmediate`: 模拟将立即数移动到寄存器的指令。

7. **内存访问和管理:**
   - 代码中使用了 `MemoryRead` 和 `MemoryWrite` 等函数（未在此段代码中定义），这些函数负责模拟内存的读写操作。
   - `ProbeMemory`: 用于检查内存地址是否可访问。
   - `CheckMemoryAccess`: 用于检测对栈的非法访问（低于栈指针）。

8. **状态和标志位管理:**
   - 代码中涉及到 `nzcv()` 函数，用于访问和修改 ARM64 的 NZCV (负数、零、进位、溢出) 标志位。

9. **调试和日志:**
   - 代码中包含大量的 `Log...` 函数调用，用于在模拟执行过程中记录寄存器和内存的变化，方便调试。

**关于代码特性：**

* **不是 Torque 代码:**  代码以 `.cc` 结尾，表明它是 C++ 源代码，而不是以 `.tq` 结尾的 V8 Torque 源代码。

**与 JavaScript 的关系（示例）：**

V8 引擎负责执行 JavaScript 代码。当 V8 在 ARM64 架构上运行时，它会将 JavaScript 代码编译成 ARM64 的机器码。然而，在某些开发或测试场景下，可能需要在非 ARM64 的机器上模拟 ARM64 的执行。这时，`simulator-arm64.cc` 中的代码就派上了用场。

例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当 V8 执行 `add(5, 10)` 时，它会被编译成一系列 ARM64 指令，其中可能包含一个加法指令。  `simulator-arm64.cc` 中的 `VisitAdd...` 函数就负责模拟这个加法指令的行为。

**代码逻辑推理（假设输入与输出）：**

假设我们执行以下 ARM64 加法指令：

```assembly
ADD x0, x1, x2  // 将寄存器 x1 和 x2 的值相加，结果存入 x0
```

在 `simulator-arm64.cc` 中，这个指令会被 `VisitAdd...` 函数处理。假设在执行该指令前：

* **假设输入:**
    * `x1` 寄存器的值为 `5` (0x5)
    * `x2` 寄存器的值为 `10` (0xA)

* **代码逻辑推理:**
   `VisitAdd...` 函数会读取 `x1` 和 `x2` 的值，执行加法运算 `5 + 10 = 15`。然后，将结果 `15` (0xF) 写入 `x0` 寄存器。 由于结果为正数且没有溢出或进位，NZCV 标志位会被相应地设置 (例如，Z=0, N=0, C=0, V=0)。

* **预期输出:**
    * `x0` 寄存器的值为 `15` (0xF)
    * NZCV 标志位会被设置为 Z=0, N=0, C=0, V=0 (具体取决于是否影响到这些标志)。

**用户常见的编程错误示例:**

这段代码涉及到内存操作，因此与内存相关的编程错误很常见。例如：

1. **访问未初始化的内存:**  如果 JavaScript 代码尝试读取一个对象属性，而该属性对应的内存尚未初始化，那么模拟器在执行加载指令时可能会读取到垃圾数据。虽然模拟器本身不会直接导致程序崩溃（除非模拟了硬件异常），但这种行为会导致程序逻辑错误。

   ```javascript
   let obj = {};
   console.log(obj.someProperty); // 访问未定义的属性，可能对应未初始化的内存
   ```

2. **栈溢出或栈下溢:**  如果 JavaScript 代码导致函数调用过深（栈溢出）或者操作栈指针不当（栈下溢），模拟器中的加载和存储指令可能会访问到超出栈范围的内存，`CheckMemoryAccess` 函数可能会检测到这种错误并报错。

   ```javascript
   function recursiveFunction() {
     recursiveFunction(); // 导致栈溢出
   }
   recursiveFunction();
   ```

3. **错误的类型转换导致内存访问错误:** 虽然 JavaScript 是动态类型语言，但在底层执行时，V8 仍然需要进行类型处理。错误的类型转换可能导致加载或存储指令访问到错误的内存地址或大小。

   ```javascript
   let arr = [1, 2, 3];
   // 错误地将数组作为指针进行操作（在 C++ 层面可能发生）
   // 模拟器可能会尝试从不正确的地址读取数据
   ```

总而言之，`v8/src/execution/arm64/simulator-arm64.cc` 是 V8 引擎中用于在非 ARM64 架构上模拟执行 ARM64 指令的关键组件，它实现了对各种 ARM64 指令的模拟，包括算术运算、逻辑运算、内存访问、原子操作等，对于 V8 的开发、测试和在不同平台上的移植具有重要意义。

### 提示词
```
这是目录为v8/src/execution/arm64/simulator-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm64/simulator-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
tyFourBits()) {
    uint64_t op2 = ExtendValue(xreg(instr->Rm()), ext, left_shift);
    AddSubHelper(instr, op2);
  } else {
    uint32_t op2 = ExtendValue(wreg(instr->Rm()), ext, left_shift);
    AddSubHelper(instr, op2);
  }
}

void Simulator::VisitAddSubWithCarry(Instruction* instr) {
  if (instr->SixtyFourBits()) {
    AddSubWithCarry<uint64_t>(instr);
  } else {
    AddSubWithCarry<uint32_t>(instr);
  }
}

void Simulator::VisitLogicalShifted(Instruction* instr) {
  Shift shift_type = static_cast<Shift>(instr->ShiftDP());
  unsigned shift_amount = instr->ImmDPShift();

  if (instr->SixtyFourBits()) {
    uint64_t op2 = ShiftOperand(xreg(instr->Rm()), shift_type, shift_amount);
    op2 = (instr->Mask(NOT) == NOT) ? ~op2 : op2;
    LogicalHelper(instr, op2);
  } else {
    uint32_t op2 = ShiftOperand(wreg(instr->Rm()), shift_type, shift_amount);
    op2 = (instr->Mask(NOT) == NOT) ? ~op2 : op2;
    LogicalHelper(instr, op2);
  }
}

void Simulator::VisitLogicalImmediate(Instruction* instr) {
  if (instr->SixtyFourBits()) {
    LogicalHelper(instr, static_cast<uint64_t>(instr->ImmLogical()));
  } else {
    LogicalHelper(instr, static_cast<uint32_t>(instr->ImmLogical()));
  }
}

template <typename T>
void Simulator::LogicalHelper(Instruction* instr, T op2) {
  T op1 = reg<T>(instr->Rn());
  T result = 0;
  bool update_flags = false;

  // Switch on the logical operation, stripping out the NOT bit, as it has a
  // different meaning for logical immediate instructions.
  switch (instr->Mask(LogicalOpMask & ~NOT)) {
    case ANDS:
      update_flags = true;
      [[fallthrough]];
    case AND:
      result = op1 & op2;
      break;
    case ORR:
      result = op1 | op2;
      break;
    case EOR:
      result = op1 ^ op2;
      break;
    default:
      UNIMPLEMENTED();
  }

  if (update_flags) {
    nzcv().SetN(CalcNFlag(result));
    nzcv().SetZ(CalcZFlag(result));
    nzcv().SetC(0);
    nzcv().SetV(0);
    LogSystemRegister(NZCV);
  }

  set_reg<T>(instr->Rd(), result, instr->RdMode());
}

void Simulator::VisitConditionalCompareRegister(Instruction* instr) {
  if (instr->SixtyFourBits()) {
    ConditionalCompareHelper(instr, static_cast<uint64_t>(xreg(instr->Rm())));
  } else {
    ConditionalCompareHelper(instr, static_cast<uint32_t>(wreg(instr->Rm())));
  }
}

void Simulator::VisitConditionalCompareImmediate(Instruction* instr) {
  if (instr->SixtyFourBits()) {
    ConditionalCompareHelper(instr, static_cast<uint64_t>(instr->ImmCondCmp()));
  } else {
    ConditionalCompareHelper(instr, static_cast<uint32_t>(instr->ImmCondCmp()));
  }
}

template <typename T>
void Simulator::ConditionalCompareHelper(Instruction* instr, T op2) {
  // Use unsigned types to avoid implementation-defined overflow behaviour.
  static_assert(std::is_unsigned<T>::value, "operands must be unsigned");

  T op1 = reg<T>(instr->Rn());

  if (ConditionPassed(static_cast<Condition>(instr->Condition()))) {
    // If the condition passes, set the status flags to the result of comparing
    // the operands.
    if (instr->Mask(ConditionalCompareMask) == CCMP) {
      AddWithCarry<T>(true, op1, ~op2, 1);
    } else {
      DCHECK(instr->Mask(ConditionalCompareMask) == CCMN);
      AddWithCarry<T>(true, op1, op2, 0);
    }
  } else {
    // If the condition fails, set the status flags to the nzcv immediate.
    nzcv().SetFlags(instr->Nzcv());
    LogSystemRegister(NZCV);
  }
}

void Simulator::VisitLoadStoreUnsignedOffset(Instruction* instr) {
  int offset = instr->ImmLSUnsigned() << instr->SizeLS();
  LoadStoreHelper(instr, offset, Offset);
}

void Simulator::VisitLoadStoreUnscaledOffset(Instruction* instr) {
  LoadStoreHelper(instr, instr->ImmLS(), Offset);
}

void Simulator::VisitLoadStorePreIndex(Instruction* instr) {
  LoadStoreHelper(instr, instr->ImmLS(), PreIndex);
}

void Simulator::VisitLoadStorePostIndex(Instruction* instr) {
  LoadStoreHelper(instr, instr->ImmLS(), PostIndex);
}

void Simulator::VisitLoadStoreRegisterOffset(Instruction* instr) {
  Extend ext = static_cast<Extend>(instr->ExtendMode());
  DCHECK((ext == UXTW) || (ext == UXTX) || (ext == SXTW) || (ext == SXTX));
  unsigned shift_amount = instr->ImmShiftLS() * instr->SizeLS();

  int64_t offset = ExtendValue(xreg(instr->Rm()), ext, shift_amount);
  LoadStoreHelper(instr, offset, Offset);
}

void Simulator::LoadStoreHelper(Instruction* instr, int64_t offset,
                                AddrMode addrmode) {
  unsigned srcdst = instr->Rt();
  unsigned addr_reg = instr->Rn();
  uintptr_t address = LoadStoreAddress(addr_reg, offset, addrmode);
  uintptr_t stack = 0;

  unsigned access_size = 1 << instr->SizeLS();
  // First, check whether the memory is accessible (for wasm trap handling).
  if (!ProbeMemory(address, access_size)) return;

  {
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    if (instr->IsLoad()) {
      local_monitor_.NotifyLoad();
    } else {
      local_monitor_.NotifyStore();
      GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_processor_);
    }
  }

  // Handle the writeback for stores before the store. On a CPU the writeback
  // and the store are atomic, but when running on the simulator it is possible
  // to be interrupted in between. The simulator is not thread safe and V8 does
  // not require it to be to run JavaScript therefore the profiler may sample
  // the "simulated" CPU in the middle of load/store with writeback. The code
  // below ensures that push operations are safe even when interrupted: the
  // stack pointer will be decremented before adding an element to the stack.
  if (instr->IsStore()) {
    LoadStoreWriteBack(addr_reg, offset, addrmode);

    // For store the address post writeback is used to check access below the
    // stack.
    stack = sp();
  }

  LoadStoreOp op = static_cast<LoadStoreOp>(instr->Mask(LoadStoreMask));
  switch (op) {
    // Use _no_log variants to suppress the register trace (LOG_REGS,
    // LOG_VREGS). We will print a more detailed log.
    case LDRB_w:
      set_wreg_no_log(srcdst, MemoryRead<uint8_t>(address));
      break;
    case LDRH_w:
      set_wreg_no_log(srcdst, MemoryRead<uint16_t>(address));
      break;
    case LDR_w:
      set_wreg_no_log(srcdst, MemoryRead<uint32_t>(address));
      break;
    case LDR_x:
      set_xreg_no_log(srcdst, MemoryRead<uint64_t>(address));
      break;
    case LDRSB_w:
      set_wreg_no_log(srcdst, MemoryRead<int8_t>(address));
      break;
    case LDRSH_w:
      set_wreg_no_log(srcdst, MemoryRead<int16_t>(address));
      break;
    case LDRSB_x:
      set_xreg_no_log(srcdst, MemoryRead<int8_t>(address));
      break;
    case LDRSH_x:
      set_xreg_no_log(srcdst, MemoryRead<int16_t>(address));
      break;
    case LDRSW_x:
      set_xreg_no_log(srcdst, MemoryRead<int32_t>(address));
      break;
    case LDR_b:
      set_breg_no_log(srcdst, MemoryRead<uint8_t>(address));
      break;
    case LDR_h:
      set_hreg_no_log(srcdst, MemoryRead<uint16_t>(address));
      break;
    case LDR_s:
      set_sreg_no_log(srcdst, MemoryRead<float>(address));
      break;
    case LDR_d:
      set_dreg_no_log(srcdst, MemoryRead<double>(address));
      break;
    case LDR_q:
      set_qreg_no_log(srcdst, MemoryRead<qreg_t>(address));
      break;

    case STRB_w:
      MemoryWrite<uint8_t>(address, wreg(srcdst));
      break;
    case STRH_w:
      MemoryWrite<uint16_t>(address, wreg(srcdst));
      break;
    case STR_w:
      MemoryWrite<uint32_t>(address, wreg(srcdst));
      break;
    case STR_x:
      MemoryWrite<uint64_t>(address, xreg(srcdst));
      break;
    case STR_b:
      MemoryWrite<uint8_t>(address, breg(srcdst));
      break;
    case STR_h:
      MemoryWrite<uint16_t>(address, hreg(srcdst));
      break;
    case STR_s:
      MemoryWrite<float>(address, sreg(srcdst));
      break;
    case STR_d:
      MemoryWrite<double>(address, dreg(srcdst));
      break;
    case STR_q:
      MemoryWrite<qreg_t>(address, qreg(srcdst));
      break;

    default:
      UNIMPLEMENTED();
  }

  // Print a detailed trace (including the memory address) instead of the basic
  // register:value trace generated by set_*reg().
  if (instr->IsLoad()) {
    if ((op == LDR_s) || (op == LDR_d)) {
      LogVRead(address, srcdst, GetPrintRegisterFormatForSizeFP(access_size));
    } else if ((op == LDR_b) || (op == LDR_h) || (op == LDR_q)) {
      LogVRead(address, srcdst, GetPrintRegisterFormatForSize(access_size));
    } else {
      LogRead(address, srcdst, GetPrintRegisterFormatForSize(access_size));
    }
  } else {
    if ((op == STR_s) || (op == STR_d)) {
      LogVWrite(address, srcdst, GetPrintRegisterFormatForSizeFP(access_size));
    } else if ((op == STR_b) || (op == STR_h) || (op == STR_q)) {
      LogVWrite(address, srcdst, GetPrintRegisterFormatForSize(access_size));
    } else {
      LogWrite(address, srcdst, GetPrintRegisterFormatForSize(access_size));
    }
  }

  // Handle the writeback for loads after the load to ensure safe pop
  // operation even when interrupted in the middle of it. The stack pointer
  // is only updated after the load so pop(fp) will never break the invariant
  // sp <= fp expected while walking the stack in the sampler.
  if (instr->IsLoad()) {
    // For loads the address pre writeback is used to check access below the
    // stack.
    stack = sp();

    LoadStoreWriteBack(addr_reg, offset, addrmode);
  }

  // Accesses below the stack pointer (but above the platform stack limit) are
  // not allowed in the ABI.
  CheckMemoryAccess(address, stack);
}

void Simulator::VisitLoadStorePairOffset(Instruction* instr) {
  LoadStorePairHelper(instr, Offset);
}

void Simulator::VisitLoadStorePairPreIndex(Instruction* instr) {
  LoadStorePairHelper(instr, PreIndex);
}

void Simulator::VisitLoadStorePairPostIndex(Instruction* instr) {
  LoadStorePairHelper(instr, PostIndex);
}

void Simulator::LoadStorePairHelper(Instruction* instr, AddrMode addrmode) {
  unsigned rt = instr->Rt();
  unsigned rt2 = instr->Rt2();
  unsigned addr_reg = instr->Rn();
  size_t access_size = 1ULL << instr->SizeLSPair();
  int64_t offset = instr->ImmLSPair() * access_size;
  uintptr_t address = LoadStoreAddress(addr_reg, offset, addrmode);
  uintptr_t address2 = address + access_size;
  uintptr_t stack = 0;

  {
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    if (instr->IsLoad()) {
      local_monitor_.NotifyLoad();
    } else {
      local_monitor_.NotifyStore();
      GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_processor_);
    }
  }

  // Handle the writeback for stores before the store. On a CPU the writeback
  // and the store are atomic, but when running on the simulator it is possible
  // to be interrupted in between. The simulator is not thread safe and V8 does
  // not require it to be to run JavaScript therefore the profiler may sample
  // the "simulated" CPU in the middle of load/store with writeback. The code
  // below ensures that push operations are safe even when interrupted: the
  // stack pointer will be decremented before adding an element to the stack.
  if (instr->IsStore()) {
    LoadStoreWriteBack(addr_reg, offset, addrmode);

    // For store the address post writeback is used to check access below the
    // stack.
    stack = sp();
  }

  LoadStorePairOp op =
      static_cast<LoadStorePairOp>(instr->Mask(LoadStorePairMask));

  // 'rt' and 'rt2' can only be aliased for stores.
  DCHECK(((op & LoadStorePairLBit) == 0) || (rt != rt2));

  switch (op) {
    // Use _no_log variants to suppress the register trace (LOG_REGS,
    // LOG_VREGS). We will print a more detailed log.
    case LDP_w: {
      DCHECK_EQ(access_size, static_cast<unsigned>(kWRegSize));
      set_wreg_no_log(rt, MemoryRead<uint32_t>(address));
      set_wreg_no_log(rt2, MemoryRead<uint32_t>(address2));
      break;
    }
    case LDP_s: {
      DCHECK_EQ(access_size, static_cast<unsigned>(kSRegSize));
      set_sreg_no_log(rt, MemoryRead<float>(address));
      set_sreg_no_log(rt2, MemoryRead<float>(address2));
      break;
    }
    case LDP_x: {
      DCHECK_EQ(access_size, static_cast<unsigned>(kXRegSize));
      set_xreg_no_log(rt, MemoryRead<uint64_t>(address));
      set_xreg_no_log(rt2, MemoryRead<uint64_t>(address2));
      break;
    }
    case LDP_d: {
      DCHECK_EQ(access_size, static_cast<unsigned>(kDRegSize));
      set_dreg_no_log(rt, MemoryRead<double>(address));
      set_dreg_no_log(rt2, MemoryRead<double>(address2));
      break;
    }
    case LDP_q: {
      DCHECK_EQ(access_size, static_cast<unsigned>(kQRegSize));
      set_qreg(rt, MemoryRead<qreg_t>(address), NoRegLog);
      set_qreg(rt2, MemoryRead<qreg_t>(address2), NoRegLog);
      break;
    }
    case LDPSW_x: {
      DCHECK_EQ(access_size, static_cast<unsigned>(kWRegSize));
      set_xreg_no_log(rt, MemoryRead<int32_t>(address));
      set_xreg_no_log(rt2, MemoryRead<int32_t>(address2));
      break;
    }
    case STP_w: {
      DCHECK_EQ(access_size, static_cast<unsigned>(kWRegSize));
      MemoryWrite<uint32_t>(address, wreg(rt));
      MemoryWrite<uint32_t>(address2, wreg(rt2));
      break;
    }
    case STP_s: {
      DCHECK_EQ(access_size, static_cast<unsigned>(kSRegSize));
      MemoryWrite<float>(address, sreg(rt));
      MemoryWrite<float>(address2, sreg(rt2));
      break;
    }
    case STP_x: {
      DCHECK_EQ(access_size, static_cast<unsigned>(kXRegSize));
      MemoryWrite<uint64_t>(address, xreg(rt));
      MemoryWrite<uint64_t>(address2, xreg(rt2));
      break;
    }
    case STP_d: {
      DCHECK_EQ(access_size, static_cast<unsigned>(kDRegSize));
      MemoryWrite<double>(address, dreg(rt));
      MemoryWrite<double>(address2, dreg(rt2));
      break;
    }
    case STP_q: {
      DCHECK_EQ(access_size, static_cast<unsigned>(kQRegSize));
      MemoryWrite<qreg_t>(address, qreg(rt));
      MemoryWrite<qreg_t>(address2, qreg(rt2));
      break;
    }
    default:
      UNREACHABLE();
  }

  // Print a detailed trace (including the memory address) instead of the basic
  // register:value trace generated by set_*reg().
  if (instr->IsLoad()) {
    if ((op == LDP_s) || (op == LDP_d)) {
      LogVRead(address, rt, GetPrintRegisterFormatForSizeFP(access_size));
      LogVRead(address2, rt2, GetPrintRegisterFormatForSizeFP(access_size));
    } else if (op == LDP_q) {
      LogVRead(address, rt, GetPrintRegisterFormatForSize(access_size));
      LogVRead(address2, rt2, GetPrintRegisterFormatForSize(access_size));
    } else {
      LogRead(address, rt, GetPrintRegisterFormatForSize(access_size));
      LogRead(address2, rt2, GetPrintRegisterFormatForSize(access_size));
    }
  } else {
    if ((op == STP_s) || (op == STP_d)) {
      LogVWrite(address, rt, GetPrintRegisterFormatForSizeFP(access_size));
      LogVWrite(address2, rt2, GetPrintRegisterFormatForSizeFP(access_size));
    } else if (op == STP_q) {
      LogVWrite(address, rt, GetPrintRegisterFormatForSize(access_size));
      LogVWrite(address2, rt2, GetPrintRegisterFormatForSize(access_size));
    } else {
      LogWrite(address, rt, GetPrintRegisterFormatForSize(access_size));
      LogWrite(address2, rt2, GetPrintRegisterFormatForSize(access_size));
    }
  }

  // Handle the writeback for loads after the load to ensure safe pop
  // operation even when interrupted in the middle of it. The stack pointer
  // is only updated after the load so pop(fp) will never break the invariant
  // sp <= fp expected while walking the stack in the sampler.
  if (instr->IsLoad()) {
    // For loads the address pre writeback is used to check access below the
    // stack.
    stack = sp();

    LoadStoreWriteBack(addr_reg, offset, addrmode);
  }

  // Accesses below the stack pointer (but above the platform stack limit) are
  // not allowed in the ABI.
  CheckMemoryAccess(address, stack);
}

void Simulator::VisitLoadLiteral(Instruction* instr) {
  uintptr_t address = instr->LiteralAddress();
  unsigned rt = instr->Rt();

  {
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    local_monitor_.NotifyLoad();
  }

  switch (instr->Mask(LoadLiteralMask)) {
    // Use _no_log variants to suppress the register trace (LOG_REGS,
    // LOG_VREGS), then print a more detailed log.
    case LDR_w_lit:
      set_wreg_no_log(rt, MemoryRead<uint32_t>(address));
      LogRead(address, rt, kPrintWReg);
      break;
    case LDR_x_lit:
      set_xreg_no_log(rt, MemoryRead<uint64_t>(address));
      LogRead(address, rt, kPrintXReg);
      break;
    case LDR_s_lit:
      set_sreg_no_log(rt, MemoryRead<float>(address));
      LogVRead(address, rt, kPrintSReg);
      break;
    case LDR_d_lit:
      set_dreg_no_log(rt, MemoryRead<double>(address));
      LogVRead(address, rt, kPrintDReg);
      break;
    default:
      UNREACHABLE();
  }
}

uintptr_t Simulator::LoadStoreAddress(unsigned addr_reg, int64_t offset,
                                      AddrMode addrmode) {
  const unsigned kSPRegCode = kSPRegInternalCode & kRegCodeMask;
  uint64_t address = xreg(addr_reg, Reg31IsStackPointer);
  if ((addr_reg == kSPRegCode) && ((address % 16) != 0)) {
    // When the base register is SP the stack pointer is required to be
    // quadword aligned prior to the address calculation and write-backs.
    // Misalignment will cause a stack alignment fault.
    FATAL("ALIGNMENT EXCEPTION");
  }

  if ((addrmode == Offset) || (addrmode == PreIndex)) {
    address += offset;
  }

  return address;
}

void Simulator::LoadStoreWriteBack(unsigned addr_reg, int64_t offset,
                                   AddrMode addrmode) {
  if ((addrmode == PreIndex) || (addrmode == PostIndex)) {
    DCHECK_NE(offset, 0);
    uint64_t address = xreg(addr_reg, Reg31IsStackPointer);
    set_reg(addr_reg, address + offset, Reg31IsStackPointer);
  }
}

Simulator::TransactionSize Simulator::get_transaction_size(unsigned size) {
  switch (size) {
    case 0:
      return TransactionSize::None;
    case 1:
      return TransactionSize::Byte;
    case 2:
      return TransactionSize::HalfWord;
    case 4:
      return TransactionSize::Word;
    case 8:
      return TransactionSize::DoubleWord;
    default:
      UNREACHABLE();
  }
}

void Simulator::VisitLoadStoreAcquireRelease(Instruction* instr) {
  unsigned rt = instr->Rt();
  unsigned rn = instr->Rn();
  LoadStoreAcquireReleaseOp op = static_cast<LoadStoreAcquireReleaseOp>(
      instr->Mask(LoadStoreAcquireReleaseMask));

  switch (op) {
    case CAS_w:
    case CASA_w:
    case CASL_w:
    case CASAL_w:
      CompareAndSwapHelper<uint32_t>(instr);
      return;
    case CAS_x:
    case CASA_x:
    case CASL_x:
    case CASAL_x:
      CompareAndSwapHelper<uint64_t>(instr);
      return;
    case CASB:
    case CASAB:
    case CASLB:
    case CASALB:
      CompareAndSwapHelper<uint8_t>(instr);
      return;
    case CASH:
    case CASAH:
    case CASLH:
    case CASALH:
      CompareAndSwapHelper<uint16_t>(instr);
      return;
    case CASP_w:
    case CASPA_w:
    case CASPL_w:
    case CASPAL_w:
      CompareAndSwapPairHelper<uint32_t>(instr);
      return;
    case CASP_x:
    case CASPA_x:
    case CASPL_x:
    case CASPAL_x:
      CompareAndSwapPairHelper<uint64_t>(instr);
      return;
    default:
      break;
  }

  int32_t is_acquire_release = instr->LoadStoreXAcquireRelease();
  int32_t is_exclusive = (instr->LoadStoreXNotExclusive() == 0);
  int32_t is_load = instr->LoadStoreXLoad();
  int32_t is_pair = instr->LoadStoreXPair();
  USE(is_acquire_release);
  USE(is_pair);
  DCHECK_NE(is_acquire_release, 0);  // Non-acquire/release unimplemented.
  DCHECK_EQ(is_pair, 0);             // Pair unimplemented.
  unsigned access_size = 1 << instr->LoadStoreXSizeLog2();
  uintptr_t address = LoadStoreAddress(rn, 0, AddrMode::Offset);
  DCHECK_EQ(address % access_size, 0);
  // First, check whether the memory is accessible (for wasm trap handling).
  if (!ProbeMemory(address, access_size)) return;
  base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
  if (is_load != 0) {
    if (is_exclusive) {
      local_monitor_.NotifyLoadExcl(address, get_transaction_size(access_size));
      GlobalMonitor::Get()->NotifyLoadExcl_Locked(address,
                                                  &global_monitor_processor_);
    } else {
      local_monitor_.NotifyLoad();
    }
    switch (op) {
      case LDAR_b:
      case LDAXR_b:
        set_wreg_no_log(rt, MemoryRead<uint8_t>(address));
        break;
      case LDAR_h:
      case LDAXR_h:
        set_wreg_no_log(rt, MemoryRead<uint16_t>(address));
        break;
      case LDAR_w:
      case LDAXR_w:
        set_wreg_no_log(rt, MemoryRead<uint32_t>(address));
        break;
      case LDAR_x:
      case LDAXR_x:
        set_xreg_no_log(rt, MemoryRead<uint64_t>(address));
        break;
      default:
        UNIMPLEMENTED();
    }
    LogRead(address, rt, GetPrintRegisterFormatForSize(access_size));
  } else {
    if (is_exclusive) {
      unsigned rs = instr->Rs();
      DCHECK_NE(rs, rt);
      DCHECK_NE(rs, rn);
      if (local_monitor_.NotifyStoreExcl(address,
                                         get_transaction_size(access_size)) &&
          GlobalMonitor::Get()->NotifyStoreExcl_Locked(
              address, &global_monitor_processor_)) {
        switch (op) {
          case STLXR_b:
            MemoryWrite<uint8_t>(address, wreg(rt));
            break;
          case STLXR_h:
            MemoryWrite<uint16_t>(address, wreg(rt));
            break;
          case STLXR_w:
            MemoryWrite<uint32_t>(address, wreg(rt));
            break;
          case STLXR_x:
            MemoryWrite<uint64_t>(address, xreg(rt));
            break;
          default:
            UNIMPLEMENTED();
        }
        LogWrite(address, rt, GetPrintRegisterFormatForSize(access_size));
        set_wreg(rs, 0);
      } else {
        set_wreg(rs, 1);
      }
    } else {
      local_monitor_.NotifyStore();
      GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_processor_);
      switch (op) {
        case STLR_b:
          MemoryWrite<uint8_t>(address, wreg(rt));
          break;
        case STLR_h:
          MemoryWrite<uint16_t>(address, wreg(rt));
          break;
        case STLR_w:
          MemoryWrite<uint32_t>(address, wreg(rt));
          break;
        case STLR_x:
          MemoryWrite<uint64_t>(address, xreg(rt));
          break;
        default:
          UNIMPLEMENTED();
      }
    }
  }
}

template <typename T>
void Simulator::CompareAndSwapHelper(const Instruction* instr) {
  unsigned rs = instr->Rs();
  unsigned rt = instr->Rt();
  unsigned rn = instr->Rn();

  unsigned element_size = sizeof(T);
  uint64_t address = reg<uint64_t>(rn, Reg31IsStackPointer);

  // First, check whether the memory is accessible (for wasm trap handling).
  if (!ProbeMemory(address, element_size)) return;

  bool is_acquire = instr->Bit(22) == 1;
  bool is_release = instr->Bit(15) == 1;

  T comparevalue = reg<T>(rs);
  T newvalue = reg<T>(rt);

  // The architecture permits that the data read clears any exclusive monitors
  // associated with that location, even if the compare subsequently fails.
  local_monitor_.NotifyLoad();

  T data = MemoryRead<T>(address);
  if (is_acquire) {
    // Approximate load-acquire by issuing a full barrier after the load.
    std::atomic_thread_fence(std::memory_order_seq_cst);
  }

  if (data == comparevalue) {
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);

    if (is_release) {
      local_monitor_.NotifyStore();
      GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_processor_);
      // Approximate store-release by issuing a full barrier before the store.
      std::atomic_thread_fence(std::memory_order_seq_cst);
    }

    MemoryWrite<T>(address, newvalue);
    LogWrite(address, rt, GetPrintRegisterFormatForSize(element_size));
  }

  set_reg<T>(rs, data);
  LogRead(address, rs, GetPrintRegisterFormatForSize(element_size));
}

template <typename T>
void Simulator::CompareAndSwapPairHelper(const Instruction* instr) {
  DCHECK((sizeof(T) == 4) || (sizeof(T) == 8));
  unsigned rs = instr->Rs();
  unsigned rt = instr->Rt();
  unsigned rn = instr->Rn();

  DCHECK((rs % 2 == 0) && (rt % 2 == 0));

  unsigned element_size = sizeof(T);
  uint64_t address = reg<uint64_t>(rn, Reg31IsStackPointer);

  uint64_t address2 = address + element_size;

  // First, check whether the memory is accessible (for wasm trap handling).
  if (!ProbeMemory(address, element_size)) return;
  if (!ProbeMemory(address2, element_size)) return;

  bool is_acquire = instr->Bit(22) == 1;
  bool is_release = instr->Bit(15) == 1;

  T comparevalue_high = reg<T>(rs + 1);
  T comparevalue_low = reg<T>(rs);
  T newvalue_high = reg<T>(rt + 1);
  T newvalue_low = reg<T>(rt);

  // The architecture permits that the data read clears any exclusive monitors
  // associated with that location, even if the compare subsequently fails.
  local_monitor_.NotifyLoad();

  T data_low = MemoryRead<T>(address);
  T data_high = MemoryRead<T>(address2);

  if (is_acquire) {
    // Approximate load-acquire by issuing a full barrier after the load.
    std::atomic_thread_fence(std::memory_order_seq_cst);
  }

  bool same =
      (data_high == comparevalue_high) && (data_low == comparevalue_low);
  if (same) {
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);

    if (is_release) {
      local_monitor_.NotifyStore();
      GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_processor_);
      // Approximate store-release by issuing a full barrier before the store.
      std::atomic_thread_fence(std::memory_order_seq_cst);
    }

    MemoryWrite<T>(address, newvalue_low);
    MemoryWrite<T>(address2, newvalue_high);
  }

  set_reg<T>(rs + 1, data_high);
  set_reg<T>(rs, data_low);

  PrintRegisterFormat format = GetPrintRegisterFormatForSize(element_size);
  LogRead(address, rs, format);
  LogRead(address2, rs + 1, format);

  if (same) {
    LogWrite(address, rt, format);
    LogWrite(address2, rt + 1, format);
  }
}

template <typename T>
void Simulator::AtomicMemorySimpleHelper(const Instruction* instr) {
  unsigned rs = instr->Rs();
  unsigned rt = instr->Rt();
  unsigned rn = instr->Rn();

  bool is_acquire = (instr->Bit(23) == 1) && (rt != kZeroRegCode);
  bool is_release = instr->Bit(22) == 1;

  unsigned element_size = sizeof(T);
  uint64_t address = xreg(rn, Reg31IsStackPointer);
  DCHECK_EQ(address % element_size, 0);

  // First, check whether the memory is accessible (for wasm trap handling).
  if (!ProbeMemory(address, element_size)) return;

  local_monitor_.NotifyLoad();

  T value = reg<T>(rs);

  T data = MemoryRead<T>(address);

  if (is_acquire) {
    // Approximate load-acquire by issuing a full barrier after the load.
    std::atomic_thread_fence(std::memory_order_seq_cst);
  }

  T result = 0;
  switch (instr->Mask(AtomicMemorySimpleOpMask)) {
    case LDADDOp:
      result = data + value;
      break;
    case LDCLROp:
      DCHECK(!std::numeric_limits<T>::is_signed);
      result = data & ~value;
      break;
    case LDEOROp:
      DCHECK(!std::numeric_limits<T>::is_signed);
      result = data ^ value;
      break;
    case LDSETOp:
      DCHECK(!std::numeric_limits<T>::is_signed);
      result = data | value;
      break;

    // Signed/Unsigned difference is done via the templated type T.
    case LDSMAXOp:
    case LDUMAXOp:
      result = (data > value) ? data : value;
      break;
    case LDSMINOp:
    case LDUMINOp:
      result = (data > value) ? value : data;
      break;
  }

  if (is_release) {
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    local_monitor_.NotifyStore();
    GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_processor_);
    // Approximate store-release by issuing a full barrier before the store.
    std::atomic_thread_fence(std::memory_order_seq_cst);
  }

  MemoryWrite<T>(address, result);
  set_reg<T>(rt, data);

  PrintRegisterFormat format = GetPrintRegisterFormatForSize(element_size);
  LogRead(address, rt, format);
  LogWrite(address, rs, format);
}

template <typename T>
void Simulator::AtomicMemorySwapHelper(const Instruction* instr) {
  unsigned rs = instr->Rs();
  unsigned rt = instr->Rt();
  unsigned rn = instr->Rn();

  bool is_acquire = (instr->Bit(23) == 1) && (rt != kZeroRegCode);
  bool is_release = instr->Bit(22) == 1;

  unsigned element_size = sizeof(T);
  uint64_t address = xreg(rn, Reg31IsStackPointer);

  // First, check whether the memory is accessible (for wasm trap handling).
  if (!ProbeMemory(address, element_size)) return;

  local_monitor_.NotifyLoad();

  T data = MemoryRead<T>(address);
  if (is_acquire) {
    // Approximate load-acquire by issuing a full barrier after the load.
    std::atomic_thread_fence(std::memory_order_seq_cst);
  }

  if (is_release) {
    base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
    local_monitor_.NotifyStore();
    GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_processor_);
    // Approximate store-release by issuing a full barrier before the store.
    std::atomic_thread_fence(std::memory_order_seq_cst);
  }
  MemoryWrite<T>(address, reg<T>(rs));

  set_reg<T>(rt, data);

  PrintRegisterFormat format = GetPrintRegisterFormatForSize(element_size);
  LogRead(address, rt, format);
  LogWrite(address, rs, format);
}

#define ATOMIC_MEMORY_SIMPLE_UINT_LIST(V) \
  V(LDADD)                                \
  V(LDCLR)                                \
  V(LDEOR)                                \
  V(LDSET)                                \
  V(LDUMAX)                               \
  V(LDUMIN)

#define ATOMIC_MEMORY_SIMPLE_INT_LIST(V) \
  V(LDSMAX)                              \
  V(LDSMIN)

void Simulator::VisitAtomicMemory(Instruction* instr) {
  switch (instr->Mask(AtomicMemoryMask)) {
// clang-format off
#define SIM_FUNC_B(A) \
    case A##B:        \
    case A##AB:       \
    case A##LB:       \
    case A##ALB:
#define SIM_FUNC_H(A) \
    case A##H:        \
    case A##AH:       \
    case A##LH:       \
    case A##ALH:
#define SIM_FUNC_w(A) \
    case A##_w:       \
    case A##A_w:      \
    case A##L_w:      \
    case A##AL_w:
#define SIM_FUNC_x(A) \
    case A##_x:       \
    case A##A_x:      \
    case A##L_x:      \
    case A##AL_x:

    ATOMIC_MEMORY_SIMPLE_UINT_LIST(SIM_FUNC_B)
      AtomicMemorySimpleHelper<uint8_t>(instr);
      break;
    ATOMIC_MEMORY_SIMPLE_INT_LIST(SIM_FUNC_B)
      AtomicMemorySimpleHelper<int8_t>(instr);
      break;
    ATOMIC_MEMORY_SIMPLE_UINT_LIST(SIM_FUNC_H)
      AtomicMemorySimpleHelper<uint16_t>(instr);
      break;
    ATOMIC_MEMORY_SIMPLE_INT_LIST(SIM_FUNC_H)
      AtomicMemorySimpleHelper<int16_t>(instr);
      break;
    ATOMIC_MEMORY_SIMPLE_UINT_LIST(SIM_FUNC_w)
      AtomicMemorySimpleHelper<uint32_t>(instr);
      break;
    ATOMIC_MEMORY_SIMPLE_INT_LIST(SIM_FUNC_w)
      AtomicMemorySimpleHelper<int32_t>(instr);
      break;
    ATOMIC_MEMORY_SIMPLE_UINT_LIST(SIM_FUNC_x)
      AtomicMemorySimpleHelper<uint64_t>(instr);
      break;
    ATOMIC_MEMORY_SIMPLE_INT_LIST(SIM_FUNC_x)
      AtomicMemorySimpleHelper<int64_t>(instr);
      break;
      // clang-format on

    case SWPB:
    case SWPAB:
    case SWPLB:
    case SWPALB:
      AtomicMemorySwapHelper<uint8_t>(instr);
      break;
    case SWPH:
    case SWPAH:
    case SWPLH:
    case SWPALH:
      AtomicMemorySwapHelper<uint16_t>(instr);
      break;
    case SWP_w:
    case SWPA_w:
    case SWPL_w:
    case SWPAL_w:
      AtomicMemorySwapHelper<uint32_t>(instr);
      break;
    case SWP_x:
    case SWPA_x:
    case SWPL_x:
    case SWPAL_x:
      AtomicMemorySwapHelper<uint64_t>(instr);
      break;
  }
}

void Simulator::CheckMemoryAccess(uintptr_t address, uintptr_t stack) {
  if ((address >= stack_limit_) && (address < stack)) {
    fprintf(stream_, "ACCESS BELOW STACK POINTER:\n");
    fprintf(stream_, "  sp is here:          0x%016" PRIx64 "\n",
            static_cast<uint64_t>(stack));
    fprintf(stream_, "  access was here:     0x%016" PRIx64 "\n",
            static_cast<uint64_t>(address));
    fprintf(stream_, "  stack limit is here: 0x%016" PRIx64 "\n",
            static_cast<uint64_t>(stack_limit_));
    fprintf(stream_, "\n");
    FATAL("ACCESS BELOW STACK POINTER");
  }
}

void Simulator::VisitMoveWideImmediate(Instruction* instr) {
  MoveWideImmediateOp mov_op =
      static_cast<MoveWideImmediateOp>(instr->Mask(MoveWideImmediateMask));
  int64_t new_xn_val = 0;

  bool is_64_bits = instr->SixtyFourBits() == 1;
  // Shift is limited for W operations.
  DCHECK(is_64_bits || (instr->ShiftMoveWide() < 2));

  // Get the shifted immediate.
  int64_t shift = instr->ShiftMoveWide() * 16;
  int64_t shifted_imm16 = static_cast<int
```