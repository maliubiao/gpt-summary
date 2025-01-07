Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/execution/s390/simulator-s390.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename and the initial comments clearly indicate this file is about a simulator for the s390 architecture within the V8 JavaScript engine.

2. **Scan for key functionalities:**  Look for function names, macros, and comments that suggest major blocks of code. Keywords like `Simulator`, `ExecuteInstruction`, `DecodeInstruction`, `CallInternal`, `CallImpl`, and various instruction mnemonics (e.g., `VST`, `VL`, `VA`) are important.

3. **Group related functionalities:** Notice patterns in the code:
    * Breakpoint handling (`watched_stops_`, `PrintBreakpoints`)
    * Overflow checks (`CheckOverflowForIntAdd`, `CheckOverflowForUIntAdd`, etc.)
    * Instruction decoding and execution (`DecodeInstruction`, `ExecuteInstruction`, `EvalTable`)
    * Debugging support (`DebugStart`, `S390Debugger`)
    * Function calls (internal and external) (`CallInternal`, `CallImpl`, `CallFP`)
    * Stack manipulation (`PushAddress`, `PopAddress`)
    * Instruction-specific evaluation functions (all the `Evaluate_...` functions)

4. **Infer the purpose of each group:**
    * Breakpoints are for debugging.
    * Overflow checks ensure arithmetic operations behave correctly and detect potential errors.
    * Instruction decoding and execution are the heart of the simulator, interpreting s390 instructions.
    * Debugging support provides interactive control during simulation.
    * Function calls simulate calling conventions, including argument passing and register preservation.
    * Stack manipulation is necessary for function calls and local variable management.
    * Instruction evaluation functions implement the behavior of individual s390 instructions.

5. **Address specific questions from the prompt:**
    * **`.tq` extension:** The code is C++, so the answer is no.
    * **Relationship to JavaScript:** The simulator executes the low-level machine code that V8 generates from JavaScript. Provide a simple JavaScript example and explain how it relates to the simulated execution.
    * **Code logic reasoning:**  The overflow check macros provide a clear example of conditional logic. Pick one and illustrate with input/output examples.
    * **Common programming errors:** Overflow errors, which the simulator helps detect, are a classic example. Show a C++ example of integer overflow.

6. **Synthesize the information into a structured summary:**  Organize the findings into logical sections covering the core functionalities. Start with a high-level overview and then delve into more specific details.

7. **Address the "Part 4 of 10" aspect:**  Acknowledge this context and reiterate that this specific file focuses on the simulation logic itself.

8. **Refine the language and add clarity:** Use clear and concise language, explaining technical terms where necessary. Ensure the answer directly addresses all parts of the user's request. For example, explicitly state that the `Evaluate_` functions correspond to specific s390 instructions.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on individual instruction implementations.
* **Correction:** Shift focus to the broader functionalities and group related code blocks.
* **Initial thought:**  Only explain the direct execution of instructions.
* **Correction:**  Include the role of the simulator in the V8 pipeline, connecting it to JavaScript execution.
* **Initial thought:**  Provide only C++ examples.
* **Correction:**  Provide a JavaScript example to illustrate the connection to the higher-level language.
* **Initial thought:** The overflow check examples might be too complex.
* **Correction:** Choose simple examples with clear inputs and outputs to demonstrate the logic.

By following these steps, including the self-correction, the comprehensive answer that addresses all aspects of the user's prompt can be constructed.
好的，让我们来分析一下 `v8/src/execution/s390/simulator-s390.cc` 这个文件的功能。

**文件功能归纳：**

`v8/src/execution/s390/simulator-s390.cc` 文件是 V8 JavaScript 引擎中针对 s390 架构的**指令模拟器**的实现。它的主要功能是：

1. **模拟 s390 架构的 CPU 指令执行：**  它能够读取并解释 s390 机器码指令，并模拟这些指令在 CPU 寄存器和内存上的行为。这包括算术运算、逻辑运算、数据加载/存储、跳转等各种指令。
2. **提供调试支持：**  代码中包含了断点 (`watched_stops_`)、单步执行、指令跟踪 (`v8_flags.trace_sim`) 等调试功能，方便开发者分析和调试 V8 生成的 s390 代码。
3. **处理函数调用：**  实现了模拟器内部函数调用 (`CallInternal`) 和模拟调用外部函数 (`CallImpl`) 的机制，包括参数传递、栈帧管理以及寄存器保存和恢复。
4. **实现溢出检查：**  定义了用于检查有符号和无符号整数加减乘法以及移位操作是否发生溢出的宏 (`CheckOverflowForIntAdd` 等)。这有助于在模拟执行过程中发现潜在的算术错误。
5. **支持 SIMD 指令 (向量指令)：** 代码中包含以 `V` 开头的指令模拟函数 (例如 `Evaluate_VST`, `Evaluate_VL`)，这表明该模拟器也支持 s390 的向量扩展指令集，用于并行处理数据。
6. **与 V8 引擎集成：**  该模拟器是 V8 引擎的一部分，用于在没有真实 s390 硬件的情况下测试和运行为 s390 架构生成的代码。

**关于文件扩展名和 Torque：**

如果 `v8/src/execution/s390/simulator-s390.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是 V8 用于定义运行时内置函数和优化编译器优化的领域特定语言。但是，根据您提供的文件名，它以 `.cc` 结尾，所以它是一个 C++ 源代码文件。

**与 JavaScript 的关系和示例：**

V8 的主要任务是执行 JavaScript 代码。当 V8 需要在 s390 架构上运行 JavaScript 时，它会将 JavaScript 代码编译成 s390 机器码。`simulator-s390.cc` 中实现的模拟器允许 V8 在没有实际 s390 硬件的情况下执行这些机器码。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
console.log(result); // 输出 8
```

当 V8 执行这段 JavaScript 代码时，`add` 函数会被编译成一系列 s390 指令。如果启用了模拟器（例如在开发或测试环境中），`simulator-s390.cc` 中的代码将会模拟这些 s390 指令的执行，包括：

1. **加载 `a` 和 `b` 的值到寄存器。**
2. **执行加法指令，将两个寄存器中的值相加。**
3. **将结果存储回寄存器或内存。**
4. **返回结果。**

模拟器中的 `Evaluate_` 函数（例如，如果加法被编译成一个特定的 s390 加法指令，可能对应一个 `Evaluate_A` 或类似的函数）会负责模拟这些指令的运算过程。

**代码逻辑推理和示例：**

我们来看一个溢出检查的例子：

```c++
#define CheckOverflowForIntAdd(src1, src2, type) \
  OverflowFromSigned<type>(src1 + src2, src1, src2, true);
```

假设输入：

* `src1 = 2147483647` (int32_t 的最大值)
* `src2 = 1`
* `type = int32_t`

模拟器执行 `CheckOverflowForIntAdd(src1, src2, int32_t)` 时，`OverflowFromSigned` 宏会被展开，它会检查 `src1 + src2` 是否超出了 `int32_t` 的表示范围。

输出：

由于 `2147483647 + 1` 的结果 `2147483648` 超出了 `int32_t` 的最大值，`OverflowFromSigned` 函数会返回 `true`，表示发生了有符号整数溢出。

**用户常见的编程错误示例：**

模拟器中实现的溢出检查可以帮助发现用户在编写 C++ 或其他编译成机器码的语言时可能犯的错误，例如：

```c++
int main() {
  int max_int = 2147483647;
  int result = max_int + 1; // 有符号整数溢出
  printf("Result: %d\n", result); // 输出结果是未定义的，通常会回绕成一个负数
  return 0;
}
```

在模拟器中运行这段代码时，`CheckOverflowForIntAdd` 宏会检测到溢出，从而帮助开发者意识到这个问题。

**总结该部分的功能（第 4 部分）：**

结合提供的代码片段，这部分代码主要关注以下功能：

* **打印未使用断点的状态：** `PrintBreakpoints` 函数能够显示已设置但尚未被触发的断点信息，这对于调试来说很有用，可以帮助开发者了解哪些断点没有被执行到。
* **定义用于检查整数运算溢出的宏：**  `CheckOverflowForIntAdd`, `CheckOverflowForIntSub`, `CheckOverflowForUIntAdd`, `CheckOverflowForUIntSub`, `CheckOverflowForMul`, `CheckOverflowForShiftRight`, `CheckOverflowForShiftLeft` 这些宏为模拟器提供了便捷的方式来检测各种算术和位运算中可能发生的溢出情况。

因此，**第 4 部分的功能是提供打印未使用断点信息的能力，并定义了一系列用于在模拟执行过程中检测整数运算溢出的宏。** 这部分代码增强了模拟器的调试能力，并有助于发现潜在的程序错误。

Prompt: 
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/s390/simulator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共10部分，请归纳一下它的功能

"""
't print the state of unused breakpoints.
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
"""


```