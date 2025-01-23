Response: The user wants to understand the functionality of the provided C++ code snippet, which is a part of an ARM64 simulator within the V8 JavaScript engine.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the Context:** The code is within the `Simulator` class, specifically for ARM64 architecture (`simulator-arm64.cc`). This immediately suggests it's about emulating ARM64 instructions.

2. **Scan Function Names:** Look for the `Visit...` methods. These strongly indicate the simulation of specific ARM64 instructions. Each `Visit` method likely handles a group or a single ARM64 instruction.

3. **Group by Functionality:** Observe the operations performed within the `Visit` methods. Notice patterns:
    * Arithmetic and Logical operations (`VisitAddSubImmediate`, `VisitAddSubShifted`, `VisitAddSubWithCarry`, `VisitLogicalShifted`, `VisitLogicalImmediate`).
    * Conditional comparisons (`VisitConditionalCompareRegister`, `VisitConditionalCompareImmediate`).
    * Load and Store operations (`VisitLoadStoreUnsignedOffset`, `VisitLoadStoreUnscaledOffset`, `VisitLoadStorePreIndex`, `VisitLoadStorePostIndex`, `VisitLoadStoreRegisterOffset`, `VisitLoadStorePairOffset`, `VisitLoadStorePairPreIndex`, `VisitLoadStorePairPostIndex`, `VisitLoadLiteral`, `VisitLoadStoreAcquireRelease`).
    * Atomic memory operations (`VisitAtomicMemory`).
    * Bit manipulation (`VisitMoveWideImmediate`, `VisitConditionalSelect`, `VisitDataProcessing1Source`, `VisitDataProcessing2Source`, `VisitDataProcessing3Source`, `VisitBitfield`, `VisitExtract`).
    * Floating-point operations (`VisitFPImmediate`, `VisitFPIntegerConvert`, `VisitFPFixedPointConvert`, `VisitFPCompare`, `VisitFPConditionalCompare`, `VisitFPConditionalSelect`, `VisitFPDataProcessing1Source`, `VisitFPDataProcessing2Source`, `VisitFPDataProcessing3Source`).
    * System instructions (`VisitSystem`).
    * Debugging related functionality (`Debug`, `ExecDebugCommand`, `GetValue`, `PrintValue`).

4. **Summarize Each Group:** Concisely describe the purpose of each identified group of functions. For example, the `VisitLoadStore...` functions are clearly about simulating memory access.

5. **Connect to JavaScript:**  The key is to understand *why* a JavaScript engine needs to simulate CPU instructions. The core reason is to execute JavaScript code on platforms where a native ARM64 execution environment isn't directly available or for debugging and testing purposes. Think about how JavaScript uses these basic CPU operations:
    * **Arithmetic/Logical:** Directly correspond to JavaScript operators (`+`, `-`, `*`, `/`, `&`, `|`, `^`, etc.).
    * **Load/Store:** Accessing variables, object properties, and array elements in JavaScript involves reading and writing memory.
    * **Conditionals:** `if`, `else`, and conditional operators in JavaScript rely on comparisons.
    * **Bit Manipulation:** Less common in typical JavaScript but used in lower-level operations or specific algorithms.
    * **Floating-Point:**  JavaScript's `Number` type uses floating-point representation.
    * **System Instructions:**  Interact with the underlying system (though often abstracted away in JavaScript).

6. **Create JavaScript Examples:** For the most prominent groups (arithmetic/logical, load/store, conditionals), create simple JavaScript code snippets that illustrate the corresponding underlying ARM64 operations being simulated. Keep the examples straightforward and focused.

7. **Structure the Summary:** Organize the information logically:
    * Start with a general statement of the file's purpose.
    * Detail the categories of simulated instructions.
    * Provide JavaScript examples for key functionalities.
    * Conclude with a summary of the file's role in the V8 engine.

8. **Refine and Clarify:** Review the summary for clarity, accuracy, and conciseness. Ensure the connection between the C++ code and JavaScript is well-explained. Use clear and simple language. For example, explicitly state that the simulator enables V8 to run on different architectures.这是 `v8/src/execution/arm64/simulator-arm64.cc` 文件的第二部分，延续了第一部分的功能，继续实现了 ARM64 指令的模拟执行。

**主要功能归纳：**

这部分代码主要负责模拟执行以下类型的 ARM64 指令：

* **算术和逻辑运算指令 (续):**
    * 带进位的加减法 (`VisitAddSubWithCarry`)
    * 逻辑移位运算 (`VisitLogicalShifted`)
    * 立即数逻辑运算 (`VisitLogicalImmediate`)
    * 条件比较 (`VisitConditionalCompareRegister`, `VisitConditionalCompareImmediate`)
* **加载和存储指令:**
    * 基于无符号偏移的加载/存储 (`VisitLoadStoreUnsignedOffset`)
    * 基于无比例偏移的加载/存储 (`VisitLoadStoreUnscaledOffset`)
    * 预索引加载/存储 (`VisitLoadStorePreIndex`)
    * 后索引加载/存储 (`VisitLoadStorePostIndex`)
    * 基于寄存器偏移的加载/存储 (`VisitLoadStoreRegisterOffset`)
    * 加载字面量 (`VisitLoadLiteral`)
    * 加载/存储对 (`VisitLoadStorePairOffset`, `VisitLoadStorePairPreIndex`, `VisitLoadStorePairPostIndex`)
    * 原子加载/存储 (`VisitLoadStoreAcquireRelease`)
* **原子内存操作指令:** (`VisitAtomicMemory`)
* **位域操作指令:** (`VisitMoveWideImmediate`, `VisitConditionalSelect`, `VisitDataProcessing1Source`, `VisitDataProcessing2Source`, `VisitDataProcessing3Source`, `VisitBitfield`, `VisitExtract`)
* **浮点指令:** (`VisitFPImmediate`, `VisitFPIntegerConvert`, `VisitFPFixedPointConvert`, `VisitFPCompare`, `VisitFPConditionalCompare`, `VisitFPConditionalSelect`, `VisitFPDataProcessing1Source`, `VisitFPDataProcessing2Source`, `VisitFPDataProcessing3Source`)
* **系统指令:** (`VisitSystem`)

**与 JavaScript 的关系及 JavaScript 示例：**

这部分代码是 V8 引擎的一部分，V8 引擎负责执行 JavaScript 代码。当 V8 运行在非 ARM64 架构的平台上，或者在某些调试和测试场景下，就需要使用模拟器来执行为 ARM64 架构编译的代码。

这部分代码模拟的 ARM64 指令，对应了 JavaScript 代码在底层执行时所需要的各种操作。

**JavaScript 示例：**

1. **算术和逻辑运算：**

   ```javascript
   let a = 10;
   let b = 5;
   let sum = a + b; // 对应 ARM64 的加法指令 (如 ADD)
   let andResult = a & b; // 对应 ARM64 的按位与指令 (如 AND)
   if (a > b) { // 对应 ARM64 的比较指令 (如 CMP) 和条件分支指令
       console.log("a is greater than b");
   }
   ```
   `VisitAddSubImmediate`, `VisitLogicalShifted` 等函数就负责模拟这些指令的执行。

2. **加载和存储：**

   ```javascript
   let obj = { x: 1 };
   let value = obj.x; // 对应 ARM64 的加载指令 (如 LDR) 将 obj.x 的值从内存加载到寄存器
   obj.x = 2;        // 对应 ARM64 的存储指令 (如 STR) 将值 2 存储到 obj.x 所在的内存地址
   let arr = [1, 2, 3];
   let firstElement = arr[0]; // 对应数组元素的加载
   ```
   `VisitLoadStoreUnsignedOffset`, `VisitLoadLiteral` 等函数模拟了这些内存访问操作。

3. **位域操作：** (虽然在常见的 JavaScript 代码中不常见，但在一些底层操作或优化中可能涉及)

   ```javascript
   // 假设我们想提取一个 32 位整数的特定位段
   let num = 0b11001010000111101010110001110001;
   // 可以使用位运算符来模拟位域提取，这在底层可能对应 ARM64 的位域操作指令
   let bitfield = (num >> 5) & 0x3F; // 提取第 5 到 10 位
   ```
   `VisitBitfield` 等函数负责模拟这些指令。

4. **浮点运算：**

   ```javascript
   let float1 = 3.14;
   let float2 = 2.71;
   let product = float1 * float2; // 对应 ARM64 的浮点乘法指令 (如 FMUL)
   let sqrtValue = Math.sqrt(float1); // 对应 ARM64 的浮点平方根指令 (如 FSQRT)
   ```
   `VisitFPDataProcessing2Source` 等函数模拟了浮点运算指令。

**总结：**

这部分 `simulator-arm64.cc` 代码是 V8 引擎在 ARM64 架构模拟执行方面的重要组成部分。它通过解释执行的方式，逐条模拟 ARM64 指令的行为，使得 V8 能够在非 ARM64 平台上运行为 ARM64 平台编译的 JavaScript 代码，或者为调试和测试提供支持。它涵盖了多种指令类型，包括算术、逻辑、内存访问、位操作和浮点运算等，这些指令是 JavaScript 代码在底层执行的基础。

### 提示词
```
这是目录为v8/src/execution/arm64/simulator-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
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
  int64_t shifted_imm16 = static_cast<int64_t>(instr->ImmMoveWide()) << shift;

  // Compute the new value.
  switch (mov_op) {
    case MOVN_w:
    case MOVN_x: {
      new_xn_val = ~shifted_imm16;
      if (!is_64_bits) new_xn_val &= kWRegMask;
      break;
    }
    case MOVK_w:
    case MOVK_x: {
      unsigned reg_code = instr->Rd();
      int64_t prev_xn_val = is_64_bits ? xreg(reg_code) : wreg(reg_code);
      new_xn_val = (prev_xn_val & ~(INT64_C(0xFFFF) << shift)) | shifted_imm16;
      break;
    }
    case MOVZ_w:
    case MOVZ_x: {
      new_xn_val = shifted_imm16;
      break;
    }
    default:
      UNREACHABLE();
  }

  // Update the destination register.
  set_xreg(instr->Rd(), new_xn_val);
}

void Simulator::VisitConditionalSelect(Instruction* instr) {
  uint64_t new_val = xreg(instr->Rn());
  if (ConditionFailed(static_cast<Condition>(instr->Condition()))) {
    new_val = xreg(instr->Rm());
    switch (instr->Mask(ConditionalSelectMask)) {
      case CSEL_w:
      case CSEL_x:
        break;
      case CSINC_w:
      case CSINC_x:
        new_val++;
        break;
      case CSINV_w:
      case CSINV_x:
        new_val = ~new_val;
        break;
      case CSNEG_w:
      case CSNEG_x:
        // Simulate two's complement (instead of casting to signed and negating)
        // to avoid undefined behavior on signed overflow.
        new_val = (~new_val) + 1;
        break;
      default:
        UNIMPLEMENTED();
    }
  }
  if (instr->SixtyFourBits()) {
    set_xreg(instr->Rd(), new_val);
  } else {
    set_wreg(instr->Rd(), static_cast<uint32_t>(new_val));
  }
}

void Simulator::VisitDataProcessing1Source(Instruction* instr) {
  unsigned dst = instr->Rd();
  unsigned src = instr->Rn();

  switch (instr->Mask(DataProcessing1SourceMask)) {
    case RBIT_w:
      set_wreg(dst, base::bits::ReverseBits(wreg(src)));
      break;
    case RBIT_x:
      set_xreg(dst, base::bits::ReverseBits(xreg(src)));
      break;
    case REV16_w:
      set_wreg(dst, ReverseBytes(wreg(src), 1));
      break;
    case REV16_x:
      set_xreg(dst, ReverseBytes(xreg(src), 1));
      break;
    case REV_w:
      set_wreg(dst, ReverseBytes(wreg(src), 2));
      break;
    case REV32_x:
      set_xreg(dst, ReverseBytes(xreg(src), 2));
      break;
    case REV_x:
      set_xreg(dst, ReverseBytes(xreg(src), 3));
      break;
    case CLZ_w:
      set_wreg(dst, CountLeadingZeros(wreg(src), kWRegSizeInBits));
      break;
    case CLZ_x:
      set_xreg(dst, CountLeadingZeros(xreg(src), kXRegSizeInBits));
      break;
    case CLS_w: {
      set_wreg(dst, CountLeadingSignBits(wreg(src), kWRegSizeInBits));
      break;
    }
    case CLS_x: {
      set_xreg(dst, CountLeadingSignBits(xreg(src), kXRegSizeInBits));
      break;
    }
    default:
      UNIMPLEMENTED();
  }
}

template <typename T>
void Simulator::DataProcessing2Source(Instruction* instr) {
  Shift shift_op = NO_SHIFT;
  T result = 0;
  switch (instr->Mask(DataProcessing2SourceMask)) {
    case SDIV_w:
    case SDIV_x: {
      T rn = reg<T>(instr->Rn());
      T rm = reg<T>(instr->Rm());
      if ((rn == std::numeric_limits<T>::min()) && (rm == -1)) {
        result = std::numeric_limits<T>::min();
      } else if (rm == 0) {
        // Division by zero can be trapped, but not on A-class processors.
        result = 0;
      } else {
        result = rn / rm;
      }
      break;
    }
    case UDIV_w:
    case UDIV_x: {
      using unsignedT = typename std::make_unsigned<T>::type;
      unsignedT rn = static_cast<unsignedT>(reg<T>(instr->Rn()));
      unsignedT rm = static_cast<unsignedT>(reg<T>(instr->Rm()));
      if (rm == 0) {
        // Division by zero can be trapped, but not on A-class processors.
        result = 0;
      } else {
        result = rn / rm;
      }
      break;
    }
    case LSLV_w:
    case LSLV_x:
      shift_op = LSL;
      break;
    case LSRV_w:
    case LSRV_x:
      shift_op = LSR;
      break;
    case ASRV_w:
    case ASRV_x:
      shift_op = ASR;
      break;
    case RORV_w:
    case RORV_x:
      shift_op = ROR;
      break;
    default:
      UNIMPLEMENTED();
  }

  if (shift_op != NO_SHIFT) {
    // Shift distance encoded in the least-significant five/six bits of the
    // register.
    unsigned shift = wreg(instr->Rm());
    if (sizeof(T) == kWRegSize) {
      shift &= kShiftAmountWRegMask;
    } else {
      shift &= kShiftAmountXRegMask;
    }
    result = ShiftOperand(reg<T>(instr->Rn()), shift_op, shift);
  }
  set_reg<T>(instr->Rd(), result);
}

void Simulator::VisitDataProcessing2Source(Instruction* instr) {
  if (instr->SixtyFourBits()) {
    DataProcessing2Source<int64_t>(instr);
  } else {
    DataProcessing2Source<int32_t>(instr);
  }
}

void Simulator::VisitDataProcessing3Source(Instruction* instr) {
  int64_t result = 0;
  // Extract and sign- or zero-extend 32-bit arguments for widening operations.
  uint64_t rn_u32 = reg<uint32_t>(instr->Rn());
  uint64_t rm_u32 = reg<uint32_t>(instr->Rm());
  int64_t rn_s32 = reg<int32_t>(instr->Rn());
  int64_t rm_s32 = reg<int32_t>(instr->Rm());
  switch (instr->Mask(DataProcessing3SourceMask)) {
    case MADD_w:
    case MADD_x:
      result = base::AddWithWraparound(
          xreg(instr->Ra()),
          base::MulWithWraparound(xreg(instr->Rn()), xreg(instr->Rm())));
      break;
    case MSUB_w:
    case MSUB_x:
      result = base::SubWithWraparound(
          xreg(instr->Ra()),
          base::MulWithWraparound(xreg(instr->Rn()), xreg(instr->Rm())));
      break;
    case SMADDL_x:
      result = base::AddWithWraparound(xreg(instr->Ra()), (rn_s32 * rm_s32));
      break;
    case SMSUBL_x:
      result = base::SubWithWraparound(xreg(instr->Ra()), (rn_s32 * rm_s32));
      break;
    case UMADDL_x:
      result = static_cast<uint64_t>(xreg(instr->Ra())) + (rn_u32 * rm_u32);
      break;
    case UMSUBL_x:
      result = static_cast<uint64_t>(xreg(instr->Ra())) - (rn_u32 * rm_u32);
      break;
    case SMULH_x:
      DCHECK_EQ(instr->Ra(), kZeroRegCode);
      result =
          base::bits::SignedMulHigh64(xreg(instr->Rn()), xreg(instr->Rm()));
      break;
    case UMULH_x:
      DCHECK_EQ(instr->Ra(), kZeroRegCode);
      result =
          base::bits::UnsignedMulHigh64(xreg(instr->Rn()), xreg(instr->Rm()));
      break;
    default:
      UNIMPLEMENTED();
  }

  if (instr->SixtyFourBits()) {
    set_xreg(instr->Rd(), result);
  } else {
    set_wreg(instr->Rd(), static_cast<int32_t>(result));
  }
}

template <typename T>
void Simulator::BitfieldHelper(Instruction* instr) {
  using unsignedT = typename std::make_unsigned<T>::type;
  T reg_size = sizeof(T) * 8;
  T R = instr->ImmR();
  T S = instr->ImmS();
  T diff = S - R;
  T mask;
  if (diff >= 0) {
    mask = diff < reg_size - 1 ? (static_cast<unsignedT>(1) << (diff + 1)) - 1
                               : static_cast<T>(-1);
  } else {
    uint64_t umask = ((1ULL << (S + 1)) - 1);
    umask = (umask >> R) | (umask << (reg_size - R));
    mask = static_cast<T>(umask);
    diff += reg_size;
  }

  // inzero indicates if the extracted bitfield is inserted into the
  // destination register value or in zero.
  // If extend is true, extend the sign of the extracted bitfield.
  bool inzero = false;
  bool extend = false;
  switch (instr->Mask(BitfieldMask)) {
    case BFM_x:
    case BFM_w:
      break;
    case SBFM_x:
    case SBFM_w:
      inzero = true;
      extend = true;
      break;
    case UBFM_x:
    case UBFM_w:
      inzero = true;
      break;
    default:
      UNIMPLEMENTED();
  }

  T dst = inzero ? 0 : reg<T>(instr->Rd());
  T src = reg<T>(instr->Rn());
  // Rotate source bitfield into place.
  T result = R == 0 ? src
                    : (static_cast<unsignedT>(src) >> R) |
                          (static_cast<unsignedT>(src) << (reg_size - R));
  // Determine the sign extension.
  T topbits_preshift = (static_cast<unsignedT>(1) << (reg_size - diff - 1)) - 1;
  T signbits =
      diff >= reg_size - 1
          ? 0
          : ((extend && ((src >> S) & 1) ? topbits_preshift : 0) << (diff + 1));

  // Merge sign extension, dest/zero and bitfield.
  result = signbits | (result & mask) | (dst & ~mask);

  set_reg<T>(instr->Rd(), result);
}

void Simulator::VisitBitfield(Instruction* instr) {
  if (instr->SixtyFourBits()) {
    BitfieldHelper<int64_t>(instr);
  } else {
    BitfieldHelper<int32_t>(instr);
  }
}

void Simulator::VisitExtract(Instruction* instr) {
  if (instr->SixtyFourBits()) {
    Extract<uint64_t>(instr);
  } else {
    Extract<uint32_t>(instr);
  }
}

void Simulator::VisitFPImmediate(Instruction* instr) {
  AssertSupportedFPCR();

  unsigned dest = instr->Rd();
  switch (instr->Mask(FPImmediateMask)) {
    case FMOV_s_imm:
      set_sreg(dest, instr->ImmFP32());
      break;
    case FMOV_d_imm:
      set_dreg(dest, instr->ImmFP64());
      break;
    default:
      UNREACHABLE();
  }
}

void Simulator::VisitFPIntegerConvert(Instruction* instr) {
  AssertSupportedFPCR();

  unsigned dst = instr->Rd();
  unsigned src = instr->Rn();

  FPRounding round = fpcr().RMode();

  switch (instr->Mask(FPIntegerConvertMask)) {
    case FCVTAS_ws:
      set_wreg(dst, FPToInt32(sreg(src), FPTieAway));
      break;
    case FCVTAS_xs:
      set_xreg(dst, FPToInt64(sreg(src), FPTieAway));
      break;
    case FCVTAS_wd:
      set_wreg(dst, FPToInt32(dreg(src), FPTieAway));
      break;
    case FCVTAS_xd:
      set_xreg(dst, FPToInt64(dreg(src), FPTieAway));
      break;
    case FCVTAU_ws:
      set_wreg(dst, FPToUInt32(sreg(src), FPTieAway));
      break;
    case FCVTAU_xs:
      set_xreg(dst, FPToUInt64(sreg(src), FPTieAway));
      break;
    case FCVTAU_wd:
      set_wreg(dst, FPToUInt32(dreg(src), FPTieAway));
      break;
    case FCVTAU_xd:
      set_xreg(dst, FPToUInt64(dreg(src), FPTieAway));
      break;
    case FCVTMS_ws:
      set_wreg(dst, FPToInt32(sreg(src), FPNegativeInfinity));
      break;
    case FCVTMS_xs:
      set_xreg(dst, FPToInt64(sreg(src), FPNegativeInfinity));
      break;
    case FCVTMS_wd:
      set_wreg(dst, FPToInt32(dreg(src), FPNegativeInfinity));
      break;
    case FCVTMS_xd:
      set_xreg(dst, FPToInt64(dreg(src), FPNegativeInfinity));
      break;
    case FCVTMU_ws:
      set_wreg(dst, FPToUInt32(sreg(src), FPNegativeInfinity));
      break;
    case FCVTMU_xs:
      set_xreg(dst, FPToUInt64(sreg(src), FPNegativeInfinity));
      break;
    case FCVTMU_wd:
      set_wreg(dst, FPToUInt32(dreg(src), FPNegativeInfinity));
      break;
    case FCVTMU_xd:
      set_xreg(dst, FPToUInt64(dreg(src), FPNegativeInfinity));
      break;
    case FCVTNS_ws:
      set_wreg(dst, FPToInt32(sreg(src), FPTieEven));
      break;
    case FCVTNS_xs:
      set_xreg(dst, FPToInt64(sreg(src), FPTieEven));
      break;
    case FCVTNS_wd:
      set_wreg(dst, FPToInt32(dreg(src), FPTieEven));
      break;
    case FCVTNS_xd:
      set_xreg(dst, FPToInt64(dreg(src), FPTieEven));
      break;
    case FCVTNU_ws:
      set_wreg(dst, FPToUInt32(sreg(src), FPTieEven));
      break;
    case FCVTNU_xs:
      set_xreg(dst, FPToUInt64(sreg(src), FPTieEven));
      break;
    case FCVTNU_wd:
      set_wreg(dst, FPToUInt32(dreg(src), FPTieEven));
      break;
    case FCVTNU_xd:
      set_xreg(dst, FPToUInt64(dreg(src), FPTieEven));
      break;
    case FCVTZS_ws:
      set_wreg(dst, FPToInt32(sreg(src), FPZero));
      break;
    case FCVTZS_xs:
      set_xreg(dst, FPToInt64(sreg(src), FPZero));
      break;
    case FCVTZS_wd:
      set_wreg(dst, FPToInt32(dreg(src), FPZero));
      break;
    case FCVTZS_xd:
      set_xreg(dst, FPToInt64(dreg(src), FPZero));
      break;
    case FCVTZU_ws:
      set_wreg(dst, FPToUInt32(sreg(src), FPZero));
      break;
    case FCVTZU_xs:
      set_xreg(dst, FPToUInt64(sreg(src), FPZero));
      break;
    case FCVTZU_wd:
      set_wreg(dst, FPToUInt32(dreg(src), FPZero));
      break;
    case FCVTZU_xd:
      set_xreg(dst, FPToUInt64(dreg(src), FPZero));
      break;
    case FJCVTZS:
      set_wreg(dst, FPToFixedJS(dreg(src)));
      break;
    case FMOV_ws:
      set_wreg(dst, sreg_bits(src));
      break;
    case FMOV_xd:
      set_xreg(dst, dreg_bits(src));
      break;
    case FMOV_sw:
      set_sreg_bits(dst, wreg(src));
      break;
    case FMOV_dx:
      set_dreg_bits(dst, xreg(src));
      break;

    // A 32-bit input can be handled in the same way as a 64-bit input, since
    // the sign- or zero-extension will not affect the conversion.
    case SCVTF_dx:
      set_dreg(dst, FixedToDouble(xreg(src), 0, round));
      break;
    case SCVTF_dw:
      set_dreg(dst, FixedToDouble(wreg(src), 0, round));
      break;
    case UCVTF_dx:
      set_dreg(dst, UFixedToDouble(xreg(src), 0, round));
      break;
    case UCVTF_dw: {
      set_dreg(dst, UFixedToDouble(reg<uint32_t>(src), 0, round));
      break;
    }
    case SCVTF_sx:
      set_sreg(dst, FixedToFloat(xreg(src), 0, round));
      break;
    case SCVTF_sw:
      set_sreg(dst, FixedToFloat(wreg(src), 0, round));
      break;
    case UCVTF_sx:
      set_sreg(dst, UFixedToFloat(xreg(src), 0, round));
      break;
    case UCVTF_sw: {
      set_sreg(dst, UFixedToFloat(reg<uint32_t>(src), 0, round));
      break;
    }

    default:
      UNREACHABLE();
  }
}

void Simulator::VisitFPFixedPointConvert(Instruction* instr) {
  AssertSupportedFPCR();

  unsigned dst = instr->Rd();
  unsigned src = instr->Rn();
  int fbits = 64 - instr->FPScale();

  FPRounding round = fpcr().RMode();

  switch (instr->Mask(FPFixedPointConvertMask)) {
    // A 32-bit input can be handled in the same way as a 64-bit input, since
    // the sign- or zero-extension will not affect the conversion.
    case SCVTF_dx_fixed:
      set_dreg(dst, FixedToDouble(xreg(src), fbits, round));
      break;
    case SCVTF_dw_fixed:
      set_dreg(dst, FixedToDouble(wreg(src), fbits, round));
      break;
    case UCVTF_dx_fixed:
      set_dreg(dst, UFixedToDouble(xreg(src), fbits, round));
      break;
    case UCVTF_dw_fixed: {
      set_dreg(dst, UFixedToDouble(reg<uint32_t>(src), fbits, round));
      break;
    }
    case SCVTF_sx_fixed:
      set_sreg(dst, FixedToFloat(xreg(src), fbits, round));
      break;
    case SCVTF_sw_fixed:
      set_sreg(dst, FixedToFloat(wreg(src), fbits, round));
      break;
    case UCVTF_sx_fixed:
      set_sreg(dst, UFixedToFloat(xreg(src), fbits, round));
      break;
    case UCVTF_sw_fixed: {
      set_sreg(dst, UFixedToFloat(reg<uint32_t>(src), fbits, round));
      break;
    }
    default:
      UNREACHABLE();
  }
}

void Simulator::VisitFPCompare(Instruction* instr) {
  AssertSupportedFPCR();

  switch (instr->Mask(FPCompareMask)) {
    case FCMP_s:
      FPCompare(sreg(instr->Rn()), sreg(instr->Rm()));
      break;
    case FCMP_d:
      FPCompare(dreg(instr->Rn()), dreg(instr->Rm()));
      break;
    case FCMP_s_zero:
      FPCompare(sreg(instr->Rn()), 0.0f);
      break;
    case FCMP_d_zero:
      FPCompare(dreg(instr->Rn()), 0.0);
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitFPConditionalCompare(Instruction* instr) {
  AssertSupportedFPCR();

  switch (instr->Mask(FPConditionalCompareMask)) {
    case FCCMP_s:
      if (ConditionPassed(static_cast<Condition>(instr->Condition()))) {
        FPCompare(sreg(instr->Rn()), sreg(instr->Rm()));
      } else {
        nzcv().SetFlags(instr->Nzcv());
        LogSystemRegister(NZCV);
      }
      break;
    case FCCMP_d: {
      if (ConditionPassed(static_cast<Condition>(instr->Condition()))) {
        FPCompare(dreg(instr->Rn()), dreg(instr->Rm()));
      } else {
        // If the condition fails, set the status flags to the nzcv immediate.
        nzcv().SetFlags(instr->Nzcv());
        LogSystemRegister(NZCV);
      }
      break;
    }
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitFPConditionalSelect(Instruction* instr) {
  AssertSupportedFPCR();

  Instr selected;
  if (ConditionPassed(static_cast<Condition>(instr->Condition()))) {
    selected = instr->Rn();
  } else {
    selected = instr->Rm();
  }

  switch (instr->Mask(FPConditionalSelectMask)) {
    case FCSEL_s:
      set_sreg(instr->Rd(), sreg(selected));
      break;
    case FCSEL_d:
      set_dreg(instr->Rd(), dreg(selected));
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitFPDataProcessing1Source(Instruction* instr) {
  AssertSupportedFPCR();

  FPRounding fpcr_rounding = static_cast<FPRounding>(fpcr().RMode());
  VectorFormat vform = (instr->Mask(FP64) == FP64) ? kFormatD : kFormatS;
  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  bool inexact_exception = false;

  unsigned fd = instr->Rd();
  unsigned fn = instr->Rn();

  switch (instr->Mask(FPDataProcessing1SourceMask)) {
    case FMOV_s:
      set_sreg(fd, sreg(fn));
      return;
    case FMOV_d:
      set_dreg(fd, dreg(fn));
      return;
    case FABS_s:
    case FABS_d:
      fabs_(vform, vreg(fd), vreg(fn));
      // Explicitly log the register update whilst we have type information.
      LogVRegister(fd, GetPrintRegisterFormatFP(vform));
      return;
    case FNEG_s:
    case FNEG_d:
      fneg(vform, vreg(fd), vreg(fn));
      // Explicitly log the register update whilst we have type information.
      LogVRegister(fd, GetPrintRegisterFormatFP(vform));
      return;
    case FCVT_ds:
      set_dreg(fd, FPToDouble(sreg(fn)));
      return;
    case FCVT_sd:
      set_sreg(fd, FPToFloat(dreg(fn), FPTieEven));
      return;
    case FCVT_hs:
      set_hreg(fd, FPToFloat16(sreg(fn), FPTieEven));
      return;
    case FCVT_sh:
      set_sreg(fd, FPToFloat(hreg(fn)));
      return;
    case FCVT_dh:
      set_dreg(fd, FPToDouble(FPToFloat(hreg(fn))));
      return;
    case FCVT_hd:
      set_hreg(fd, FPToFloat16(dreg(fn), FPTieEven));
      return;
    case FSQRT_s:
    case FSQRT_d:
      fsqrt(vform, rd, rn);
      // Explicitly log the register update whilst we have type information.
      LogVRegister(fd, GetPrintRegisterFormatFP(vform));
      return;
    case FRINTI_s:
    case FRINTI_d:
      break;  // Use FPCR rounding mode.
    case FRINTX_s:
    case FRINTX_d:
      inexact_exception = true;
      break;
    case FRINTA_s:
    case FRINTA_d:
      fpcr_rounding = FPTieAway;
      break;
    case FRINTM_s:
    case FRINTM_d:
      fpcr_rounding = FPNegativeInfinity;
      break;
    case FRINTN_s:
    case FRINTN_d:
      fpcr_rounding = FPTieEven;
      break;
    case FRINTP_s:
    case FRINTP_d:
      fpcr_rounding = FPPositiveInfinity;
      break;
    case FRINTZ_s:
    case FRINTZ_d:
      fpcr_rounding = FPZero;
      break;
    default:
      UNIMPLEMENTED();
  }

  // Only FRINT* instructions fall through the switch above.
  frint(vform, rd, rn, fpcr_rounding, inexact_exception);
  // Explicitly log the register update whilst we have type information
  LogVRegister(fd, GetPrintRegisterFormatFP(vform));
}

void Simulator::VisitFPDataProcessing2Source(Instruction* instr) {
  AssertSupportedFPCR();

  VectorFormat vform = (instr->Mask(FP64) == FP64) ? kFormatD : kFormatS;
  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  SimVRegister& rm = vreg(instr->Rm());

  switch (instr->Mask(FPDataProcessing2SourceMask)) {
    case FADD_s:
    case FADD_d:
      fadd(vform, rd, rn, rm);
      break;
    case FSUB_s:
    case FSUB_d:
      fsub(vform, rd, rn, rm);
      break;
    case FMUL_s:
    case FMUL_d:
      fmul(vform, rd, rn, rm);
      break;
    case FNMUL_s:
    case FNMUL_d:
      fnmul(vform, rd, rn, rm);
      break;
    case FDIV_s:
    case FDIV_d:
      fdiv(vform, rd, rn, rm);
      break;
    case FMAX_s:
    case FMAX_d:
      fmax(vform, rd, rn, rm);
      break;
    case FMIN_s:
    case FMIN_d:
      fmin(vform, rd, rn, rm);
      break;
    case FMAXNM_s:
    case FMAXNM_d:
      fmaxnm(vform, rd, rn, rm);
      break;
    case FMINNM_s:
    case FMINNM_d:
      fminnm(vform, rd, rn, rm);
      break;
    default:
      UNREACHABLE();
  }
  // Explicitly log the register update whilst we have type information.
  LogVRegister(instr->Rd(), GetPrintRegisterFormatFP(vform));
}

void Simulator::VisitFPDataProcessing3Source(Instruction* instr) {
  AssertSupportedFPCR();

  unsigned fd = instr->Rd();
  unsigned fn = instr->Rn();
  unsigned fm = instr->Rm();
  unsigned fa = instr->Ra();

  switch (instr->Mask(FPDataProcessing3SourceMask)) {
    // fd = fa +/- (fn * fm)
    case FMADD_s:
      set_sreg(fd, FPMulAdd(sreg(fa), sreg(fn), sreg(fm)));
      break;
    case FMSUB_s:
      set_sreg(fd, FPMulAdd(sreg(fa), -sreg(fn), sreg(fm)));
      break;
    case FMADD_d:
      set_dreg(fd, FPMulAdd(dreg(fa), dreg(fn), dreg(fm)));
      break;
    case FMSUB_d:
      set_dreg(fd, FPMulAdd(dreg(fa), -dreg(fn), dreg(fm)));
      break;
    // Negated variants of the above.
    case FNMADD_s:
      set_sreg(fd, FPMulAdd(-sreg(fa), -sreg(fn), sreg(fm)));
      break;
    case FNMSUB_s:
      set_sreg(fd, FPMulAdd(-sreg(fa), sreg(fn), sreg(fm)));
      break;
    case FNMADD_d:
      set_dreg(fd, FPMulAdd(-dreg(fa), -dreg(fn), dreg(fm)));
      break;
    case FNMSUB_d:
      set_dreg(fd, FPMulAdd(-dreg(fa), dreg(fn), dreg(fm)));
      break;
    default:
      UNIMPLEMENTED();
  }
}

bool Simulator::FPProcessNaNs(Instruction* instr) {
  unsigned fd = instr->Rd();
  unsigned fn = instr->Rn();
  unsigned fm = instr->Rm();
  bool done = false;

  if (instr->Mask(FP64) == FP64) {
    double result = FPProcessNaNs(dreg(fn), dreg(fm));
    if (std::isnan(result)) {
      set_dreg(fd, result);
      done = true;
    }
  } else {
    float result = FPProcessNaNs(sreg(fn), sreg(fm));
    if (std::isnan(result)) {
      set_sreg(fd, result);
      done = true;
    }
  }

  return done;
}

// clang-format off
#define PAUTH_SYSTEM_MODES(V)                            \
  V(B1716, 17, xreg(16),                      kPACKeyIB) \
  V(BSP,   30, xreg(31, Reg31IsStackPointer), kPACKeyIB)
// clang-format on

void Simulator::VisitSystem(Instruction* instr) {
  // Some system instructions hijack their Op and Cp fields to represent a
  // range of immediates instead of indicating a different instruction. This
  // makes the decoding tricky.
  if (instr->Mask(SystemPAuthFMask) == SystemPAuthFixed) {
    // The BType check for PACIBSP happens in CheckBType().
    switch (instr->Mask(SystemPAuthMask)) {
#define DEFINE_PAUTH_FUNCS(SUFFIX, DST, MOD, KEY)                     \
  case PACI##SUFFIX:                                                  \
    set_xreg(DST, AddPAC(xreg(DST), MOD, KEY, kInstructionPointer));  \
    break;                                                            \
  case AUTI##SUFFIX:                                                  \
    set_xreg(DST, AuthPAC(xreg(DST), MOD, KEY, kInstructionPointer)); \
    break;

      PAUTH_SYSTEM_MODES(DEFINE_PAUTH_FUNCS)
#undef DEFINE_PAUTH_FUNCS
#undef PAUTH_SYSTEM_MODES
    }
  } else if (instr->Mask(SystemSysRegFMask) == SystemSysRegFixed) {
    switch (instr->Mask(SystemSysRegMask)) {
      case MRS: {
        switch (instr->ImmSystemRegister()) {
          case NZCV:
            set_xreg(instr->Rt(), nzcv().RawValue());
            break;
          case FPCR:
            set_xreg(instr->Rt(), fpcr().RawValue());
            break;
          default:
            UNIMPLEMENTED();
        }
        break;
      }
      case MSR: {
        switch (instr->ImmSystemRegister()) {
          case NZCV:
            nzcv().SetRawValue(wreg(instr->Rt()));
            LogSystemRegister(NZCV);
            break;
          case FPCR:
            fpcr().SetRawValue(wreg(instr->Rt()));
            LogSystemRegister(FPCR);
            break;
          default:
            UNIMPLEMENTED();
        }
        break;
      }
    }
  } else if (instr->Mask(SystemHintFMask) == SystemHintFixed) {
    DCHECK(instr->Mask(SystemHintMask) == HINT);
    switch (instr->ImmHint()) {
      case NOP:
      case YIELD:
      case CSDB:
      case BTI_jc:
      case BTI:
      case BTI_c:
      case BTI_j:
        // The BType checks happen in CheckBType().
        break;
      default:
        UNIMPLEMENTED();
    }
  } else if (instr->Mask(MemBarrierFMask) == MemBarrierFixed) {
    std::atomic_thread_fence(std::memory_order_seq_cst);
  } else {
    UNIMPLEMENTED();
  }
}

bool Simulator::GetValue(const char* desc, int64_t* value) {
  int regnum = CodeFromName(desc);
  if (regnum >= 0) {
    unsigned code = regnum;
    if (code == kZeroRegCode) {
      // Catch the zero register and return 0.
      *value = 0;
      return true;
    } else if (code == kSPRegInternalCode) {
      // Translate the stack pointer code to 31, for Reg31IsStackPointer.
      code = 31;
    }
    if (desc[0] == 'w') {
      *value = wreg(code, Reg31IsStackPointer);
    } else {
      *value = xreg(code, Reg31IsStackPointer);
    }
    return true;
  } else if (strncmp(desc, "0x", 2) == 0) {
    return SScanF(desc + 2, "%" SCNx64, reinterpret_cast<uint64_t*>(value)) ==
           1;
  } else {
    return SScanF(desc, "%" SCNu64, reinterpret_cast<uint64_t*>(value)) == 1;
  }
}

bool Simulator::PrintValue(const char* desc) {
  if (strcmp(desc, "sp") == 0) {
    DCHECK(CodeFromName(desc) == static_cast<int>(kSPRegInternalCode));
    PrintF(stream_, "%s sp:%s 0x%016" PRIx64 "%s\n", clr_reg_name,
           clr_reg_value, xreg(31, Reg31IsStackPointer), clr_normal);
    return true;
  } else if (strcmp(desc, "wsp") == 0) {
    DCHECK(CodeFromName(desc) == static_cast<int>(kSPRegInternalCode));
    PrintF(stream_, "%s wsp:%s 0x%08" PRIx32 "%s\n", clr_reg_name,
           clr_reg_value, wreg(31, Reg31IsStackPointer), clr_normal);
    return true;
  }

  int i = CodeFromName(desc);
  static_assert(kNumberOfRegisters == kNumberOfVRegisters,
                "Must be same number of Registers as VRegisters.");
  if (i < 0 || static_cast<unsigned>(i) >= kNumberOfVRegisters) return false;

  if (desc[0] == 'v') {
    struct qreg_t reg = qreg(i);
    PrintF(stream_, "%s %s:%s (%s0x%02x%s", clr_vreg_name, VRegNameForCode(i),
           clr_normal, clr_vreg_value, reg.val[0], clr_normal);
    for (int b = 1; b < kQRegSize; b++) {
      PrintF(stream_, ", %s0x%02x%s", clr_vreg_value, reg.val[b], clr_normal);
    }
    PrintF(stream_, ")\n");
    return true;
  } else if (desc[0] == 'd') {
    PrintF(stream_, "%s %s:%s %g%s\n", clr_vreg_name, DRegNameForCode(i),
           clr_vreg_value, dreg(i), clr_normal);
    return true;
  } else if (desc[0] == 's') {
    PrintF(stream_, "%s %s:%s %g%s\n", clr_vreg_name, SRegNameForCode(i),
           clr_vreg_value, sreg(i), clr_normal);
    return true;
  } else if (desc[0] == 'w') {
    PrintF(stream_, "%s %s:%s 0x%08" PRIx32 "%s\n", clr_reg_name,
           WRegNameForCode(i), clr_reg_value, wreg(i), clr_normal);
    return true;
  } else {
    // X register names have a wide variety of starting characters, but anything
    // else will be an X register.
    PrintF(stream_, "%s %s:%s 0x%016" PRIx64 "%s\n", clr_reg_name,
           XRegNameForCode(i), clr_reg_value, xreg(i), clr_normal);
    return true;
  }
}

void Simulator::Debug() {
  if (v8_flags.correctness_fuzzer_suppressions) {
    PrintF("Debugger disabled for differential fuzzing.\n");
    return;
  }
  bool done = false;
  while (!done) {
    // Disassemble the next instruction to execute before doing anything else.
    PrintInstructionsAt(pc_, 1);
    // Read the command line.
    ArrayUniquePtr<char> line(ReadLine("sim> "));
    done = ExecDebugCommand(std::move(line));
  }
}

bool Simulator::ExecDebugCommand(ArrayUniquePtr<char> line_ptr) {
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

  bool cleared_log_disasm_bit = false;

  if (line_ptr == nullptr) return false;

  // Repeat last command by default.
  const char* line = line_ptr.get();
  const char* last_input = last_debugger_input();
  if (strcmp(line, "\n") == 0 && (last_input != nullptr)) {
    line_ptr.reset();
    line = last_input;
  } else {
    // Update the latest command ran
    set_last_debugger_input(std::move(line_ptr));
  }

  // Use sscanf to parse the individual parts of the command line. At the
  // moment no command expects more than two parameters.
  int argc = SScanF(line,
                      "%" XSTR(COMMAND_SIZE) "s "
                      "%" XSTR(ARG_SIZE) "s "
                      "%" XSTR(ARG_SIZE) "s",
                      cmd, arg1, arg2);

  // stepi / si ------------------------------------------------------------
  if ((strcmp(cmd, "si") == 0) || (strcmp(cmd, "stepi") == 0)) {
    // We are about to execute instructions, after which by default we
    // should increment the pc_. If it was set when reaching this debug
    // instruction, it has not been cleared because this instruction has not
    // completed yet. So clear it manually.
    pc_modified_ = false;

    if (argc == 1) {
      ExecuteInstruction();
    } else {
      int64_t number_of_instructions_to_execute = 1;
      GetValue(arg1, &number_of_instructions_to_execute);

      set_log_parameters(log_parameters() | LOG_DISASM);
      while (number_of_instructions_to_execute-- > 0) {
        ExecuteInstruction();
      }
      set_log_parameters(log_parameters() & ~LOG_DISASM);
      PrintF("\n");
    }

    // If it was necessary, the pc has already been updated or incremented
    // when executing the instruction. So we do not want it to be updated
    // again. It will be cleared when exiting.
    pc_modified_ = true;

    // next / n
    // --------------------------------------------------------------
  } else if ((strcmp(cmd, "next") == 0) || (strcmp(cmd, "n") == 0)) {
    // Tell the simulator to break after the next executed BL.
    break_on_next_ = true;
    // Continue.
    return true;

    // continue / cont / c
    // ---------------------------------------------------
  } else if ((strcmp(cmd, "continue") == 0) || (strcmp(cmd, "cont") == 0) ||
             (strcmp(cmd, "c") == 0)) {
    // Leave the debugger shell.
    return true;

    // disassemble / disasm / di
    // ---------------------------------------------
  } else if (strcmp(cmd, "disassemble") == 0 || strcmp(cmd, "disasm") == 0 ||
             strcmp(cmd, "di") == 0) {
    int64_t n_of_instrs_to_disasm = 10;                // default value.
    int64_t address = reinterpret_cast<int64_t>(pc_);  // default value.
    if (argc >= 2) {                                   // disasm <n of instrs>
      GetValue(arg1, &n_of_instrs_to_disasm);
    }
    if (argc >= 3) {  // disasm <n of instrs> <address>
      GetValue(arg2, &address);
    }

    // Disassemble.
    PrintInstructionsAt(reinterpret_cast<Instruction*>(address),
                        n_of_instrs_to_disasm);
    PrintF("\n");

    // print / p
    // -------------------------------------------------------------
  } else if ((strcmp(cmd, "print") == 0) || (strcmp(cmd, "p") == 0)) {
    if (argc == 2) {
      if (strcmp(arg1, "all") == 0) {
        PrintRegisters();
        PrintVRegisters();
      } else {
        if (!PrintValue(arg1)) {
          PrintF("%s unrecognized\n", arg1);
        }
      }
    } else {
      PrintF(
          "print <register>\n"
          "    Print the content of a register. (alias 'p')\n"
          "    'print all' will print all registers.\n"
          "    Use 'printobject' to get more details about the value.\n");
    }

    // printobject / po
    // ------------------------------------------------------
  } else if ((strcmp(cmd, "printobject") == 0) || (strcmp(cmd, "po") == 0)) {
    if (argc == 2) {
      int64_t value;
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
      PrintF(
          "printobject <value>\n"
          "printobject <register>\n"
          "    Print details about the value. (alias 'po')\n");
    }

    // stack / mem
    // ----------------------------------------------------------
  } else if (strcmp(cmd, "stack") == 0 || strcmp(cmd, "mem") == 0 ||
             strcmp(cmd, "dump") == 0) {
    int64_t* cur = nullptr;
    int64_t* end = nullptr;
    int next_arg = 1;

    if (strcmp(cmd, "stack") == 0) {
      cur = reinterpret_cast<int64_t*>(sp());

    } else {  // "mem"
      int64_t value;
      if (!GetValue(arg1, &value)) {
        Prin
```