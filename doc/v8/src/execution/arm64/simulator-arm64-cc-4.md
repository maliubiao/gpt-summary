Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a simulator for the ARM64 architecture within the V8 JavaScript engine.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The code clearly deals with simulating ARM64 instructions. Keywords like `Simulator`, `Instruction`, `Register`, `Memory`, and command names like `stepi`, `disassemble`, `print` strongly suggest a debugging/execution environment.

2. **Categorize Functionality:**  Group related actions together. Looking at the `else if` blocks reveals distinct command categories:
    * **Execution Control:** Stepping (`stepi`, `next`, `continue`), Breakpoints (`break`), Backtrace (`backtrace`).
    * **Inspection:** Register printing (`print`), Memory dumping (`stack`, `mem`, `dump`), Disassembly (`disassemble`).
    * **Debugging Aids:** Tracing (`trace`), GDB integration (`gdb`), System register printing (`sysregs`).
    * **Help:**  (`help`).
    * **Exception Handling:** The `VisitException` function deals with specific simulator instructions (`HLT`, `BRK`).
    * **NEON Instruction Handling:**  A large portion of the code (`VisitNEON2RegMisc`, `VisitNEON3Same`, etc.) is dedicated to simulating NEON (Advanced SIMD) instructions.

3. **Analyze Individual Commands:** For each command, understand its purpose and any variations (e.g., `print all`).

4. **Note Specific Code Features:**
    * **Debugger Integration:** The code interacts with a debugger (the `Debug()` call and the `BREAK` parameter).
    * **Tracing/Logging:** The `log_parameters()` and related settings suggest a mechanism for controlling the verbosity of the simulator's output.
    * **Memory Access:** The `mem` and `dump` commands explicitly read memory.
    * **Register Access:** The `print` command reads register values.
    * **Exception Handling:** The `VisitException` function handles different types of exceptions triggered by specific instructions.

5. **Check for JavaScript Relationship:** The code interacts with V8's internal structures (e.g., `Tagged<Object>`, `Heap`), indicating it's used for simulating JavaScript execution within V8. The `DoRuntimeCall` function points to the execution of JavaScript runtime functions.

6. **Address the ".tq" Question:** The prompt mentions ".tq" files and Torque. Since the file ends in ".cc", it's a C++ file, not a Torque file.

7. **Consider User Errors:**  Commands with incorrect arguments (`GetValue` failing) are handled, and error messages are printed. This suggests the simulator helps identify issues in generated code.

8. **Handle Input/Output and Logic:**
    * **Input:**  The simulator takes commands as input (strings). Commands can have arguments (register names, memory addresses, counts).
    * **Output:**  The simulator produces textual output (register values, memory contents, disassembled instructions, etc.).
    * **Logic:** The code implements the behavior of various ARM64 instructions, including arithmetic, logical, and memory operations, as well as NEON instructions. The debugger commands implement control flow and inspection.

9. **Structure the Summary:** Organize the findings into logical sections for clarity. Use headings and bullet points.

10. **Refine and Elaborate:**  Add details and explanations where needed. For example, explain what NEON is.

11. **Address All Prompt Requirements:** Ensure all parts of the prompt are addressed, including the ".tq" check, the JavaScript relationship, input/output/logic, and common errors.

12. **Review and Verify:** Read through the summary to ensure accuracy and completeness.

Self-Correction/Refinement during the process:

* Initially, I might focus too much on the low-level instruction simulation. Realizing the debugging commands are a significant part of the functionality leads to expanding that section.
* Recognizing the interaction with V8's `Heap` and `Tagged<Object>` is crucial for understanding the JavaScript connection.
*  The "common programming errors" aspect needs careful consideration. The simulator itself doesn't directly *cause* user programming errors in the typical sense, but it *helps diagnose* errors in the generated code or runtime environment. Focusing on incorrect command usage is a valid interpretation.

By following these steps, the comprehensive summary of the `simulator-arm64.cc` file can be constructed.
这是 `v8/src/execution/arm64/simulator-arm64.cc` 文件的第 5 部分，它是一个 V8 引擎中用于 ARM64 架构的 **指令模拟器** 的源代码。  这个模拟器的主要功能是 **解释执行** ARM64 汇编指令，而不是直接在硬件上运行。这对于在没有真实 ARM64 硬件的环境中测试和调试 V8 代码非常有用。

根据提供的代码片段，我们可以归纳出以下功能：

**核心功能：模拟器命令处理**

这部分代码主要实现了模拟器内部的各种命令，允许用户在模拟执行过程中进行交互和检查状态。  以下是各个命令的详细功能：

* **`dump / d`**:
    * **功能**:  转储指定内存地址的内容。
    * **参数**:  接受一个起始地址 (`arg1`) 和可选的要转储的字数 (`words`)。
    * **逻辑推理**:
        * **假设输入**: `dump x10 20`
        * **输出**:  从寄存器 `x10` 的值所指向的内存地址开始，打印 20 个 64 位字（double words）的内容，包括十六进制地址、十六进制值、十进制值，以及如果该值看起来像一个 V8 对象（Smi 或有效的堆对象），还会尝试打印对象的简短信息。
    * **默认行为**: 如果没有指定字数，默认转储 10 个字。
    * **`skip_obj_print`**: 如果命令是 "dump"，则不会尝试打印 JS 对象的信息，只打印原始内存值。这在查看非对象内存区域时很有用。

* **`trace / t`**:
    * **功能**:  切换指令反汇编、寄存器状态和内存写入跟踪的开关。
    * **逻辑推理**:  如果当前跟踪是关闭的，执行该命令会启用所有跟踪；如果当前跟踪是开启的，则会关闭所有跟踪。
    * **与 JavaScript 的关系**:  当模拟执行 JavaScript 代码生成的机器码时，启用跟踪可以帮助开发者理解每一条指令的执行情况以及寄存器和内存的变化，从而理解 JavaScript 代码是如何被执行的。

* **`break / b`**:
    * **功能**:  设置、启用或禁用断点。
    * **参数**:  可以不带参数列出所有已设置的断点，或者带一个地址参数 (`arg1`) 在该地址设置或取消断点。
    * **逻辑推理**:
        * **假设输入**: `break 0x1234567890abcdef`
        * **输出**:  如果在该地址没有断点，则设置一个断点；如果已存在断点，则移除该断点。
    * **用户常见的编程错误**:  尝试在无效的内存地址设置断点可能会导致模拟器行为异常或崩溃。

* **`backtrace / bt`**:
    * **功能**:  回溯堆栈帧，打印每个帧的程序计数器 (PC)、栈指针 (SP) 和帧指针 (FP)。
    * **逻辑推理**:  它会沿着帧指针链向上遍历堆栈，直到遇到一个特定的结束标记。
    * **与 JavaScript 的关系**:  当 JavaScript 代码调用函数时，会形成堆栈帧。回溯可以帮助理解 JavaScript 函数的调用关系。

* **`gdb`**:
    * **功能**:  将控制权移交给 GDB 调试器。
    * **逻辑推理**:  调用 `base::OS::DebugBreak()` 触发中断，允许 GDB 连接并接管模拟器进程。

* **`sysregs`**:
    * **功能**:  打印所有系统寄存器的值，包括条件码标志 (NZCV)。

* **`help / h`**:
    * **功能**:  打印模拟器支持的命令列表和简要说明。

* **其他未知命令**:  如果输入的命令无法识别，会打印错误信息并提示使用 `help` 命令。

**代码逻辑推理示例 (`dump` 命令):**

假设当前寄存器 `x10` 的值为 `0x0000012345678000`。执行命令 `dump x10` 会执行以下步骤：

1. `GetValue("x10", &value)` 会解析 "x10" 并将 `0x0000012345678000` 赋值给 `value`。
2. `cur` 被设置为 `reinterpret_cast<int64_t*>(value)`，即 `0x0000012345678000`。
3. 由于 `argc` 为 2，`next_arg` 为 2，所以 `words` 默认为 10。
4. 循环执行 10 次，每次打印 `cur` 指向的内存地址和值。
5. 在循环中，会尝试将内存值解释为 V8 对象，并打印其简短信息（如果可能）。

**用户常见的编程错误示例 (`break` 命令):**

一个常见的错误是尝试在非代码区域设置断点，例如在数据段或堆上。 这通常不会直接导致模拟器崩溃，但当程序执行到该地址时，可能会导致无法预测的行为，因为模拟器会尝试将该处的数据解释为指令。

**总结 (第 5 部分功能):**

这部分代码主要负责实现 `v8/src/execution/arm64/simulator-arm64.cc` 模拟器的 **用户交互界面和调试功能**。它允许用户在模拟执行 ARM64 代码时，通过各种命令来观察和控制执行流程，包括内存查看、寄存器检查、断点设置和回溯等，是进行底层代码分析和调试的重要工具。

**关于 `.tq` 结尾：**

你提供的代码片段是 `.cc` 结尾的，所以它是 **C++ 源代码**。如果文件以 `.tq` 结尾，那么它才是 **V8 Torque 源代码**。Torque 是一种 V8 自定义的语言，用于定义 V8 内部的内置函数和运行时函数的实现。

**与 JavaScript 的关系举例 (`trace` 命令):**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当 V8 执行这段 JavaScript 代码时，它会被编译成 ARM64 机器码。  在模拟器中运行这段代码，并在执行前输入 `trace` 命令，模拟器会打印出执行 `add` 函数时每条 ARM64 指令的反汇编、寄存器状态和内存变化。这能帮助理解 JavaScript 的加法操作是如何在底层实现的。例如，你可能会看到加载参数到寄存器、执行加法指令、将结果存储回内存等操作。

Prompt: 
```
这是目录为v8/src/execution/arm64/simulator-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm64/simulator-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能

"""
tF("%s unrecognized\n", arg1);
        return false;
      }
      cur = reinterpret_cast<int64_t*>(value);
      next_arg++;
    }

    int64_t words = 0;
    if (argc == next_arg) {
      words = 10;
    } else if (argc == next_arg + 1) {
      if (!GetValue(argv[next_arg], &words)) {
        PrintF("%s unrecognized\n", argv[next_arg]);
        PrintF("Printing 10 double words by default");
        words = 10;
      }
    } else {
      UNREACHABLE();
    }
    end = cur + words;

    bool skip_obj_print = (strcmp(cmd, "dump") == 0);
    while (cur < end) {
      PrintF("  0x%016" PRIx64 ":  0x%016" PRIx64 " %10" PRId64,
             reinterpret_cast<uint64_t>(cur), *cur, *cur);
      if (!skip_obj_print) {
        Tagged<Object> obj(*cur);
        Heap* current_heap = isolate_->heap();
        if (IsSmi(obj) ||
            IsValidHeapObject(current_heap, Cast<HeapObject>(obj))) {
          PrintF(" (");
          if (IsSmi(obj)) {
            PrintF("smi %" PRId32, Smi::ToInt(obj));
          } else {
            ShortPrint(obj);
          }
          PrintF(")");
        }
      }
      PrintF("\n");
      cur++;
    }

    // trace / t
    // -------------------------------------------------------------
  } else if (strcmp(cmd, "trace") == 0 || strcmp(cmd, "t") == 0) {
    if ((log_parameters() & LOG_ALL) != LOG_ALL) {
      PrintF("Enabling disassembly, registers and memory write tracing\n");
      set_log_parameters(log_parameters() | LOG_ALL);
    } else {
      PrintF("Disabling disassembly, registers and memory write tracing\n");
      set_log_parameters(log_parameters() & ~LOG_ALL);
    }

    // break / b
    // -------------------------------------------------------------
  } else if (strcmp(cmd, "break") == 0 || strcmp(cmd, "b") == 0) {
    if (argc == 2) {
      int64_t value;
      if (GetValue(arg1, &value)) {
        SetBreakpoint(reinterpret_cast<Instruction*>(value));
      } else {
        PrintF("%s unrecognized\n", arg1);
      }
    } else {
      ListBreakpoints();
      PrintF("Use `break <address>` to set or disable a breakpoint\n");
    }

    // backtrace / bt
    // ---------------------------------------------------------------
  } else if (strcmp(cmd, "backtrace") == 0 || strcmp(cmd, "bt") == 0) {
    Address pc = reinterpret_cast<Address>(pc_);
    Address lr = reinterpret_cast<Address>(this->lr());
    Address sp = static_cast<Address>(this->sp());
    Address fp = static_cast<Address>(this->fp());

    int i = 0;
    while (true) {
      PrintF("#%d: " V8PRIxPTR_FMT " (sp=" V8PRIxPTR_FMT ", fp=" V8PRIxPTR_FMT
             ")\n",
             i, pc, sp, fp);
      pc = lr;
      sp = fp;
      if (pc == reinterpret_cast<Address>(kEndOfSimAddress)) {
        break;
      }
      lr = *(reinterpret_cast<Address*>(fp) + 1);
      fp = *reinterpret_cast<Address*>(fp);
      i++;
      if (i > 100) {
        PrintF("Too many frames\n");
        break;
      }
    }

    // gdb
    // -------------------------------------------------------------------
  } else if (strcmp(cmd, "gdb") == 0) {
    PrintF("Relinquishing control to gdb.\n");
    base::OS::DebugBreak();
    PrintF("Regaining control from gdb.\n");

    // sysregs
    // ---------------------------------------------------------------
  } else if (strcmp(cmd, "sysregs") == 0) {
    PrintSystemRegisters();

    // help / h
    // --------------------------------------------------------------
  } else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "h") == 0) {
    PrintF(
        "stepi / si\n"
        "    stepi <n>\n"
        "    Step <n> instructions.\n"
        "next / n\n"
        "    Continue execution until a BL instruction is reached.\n"
        "    At this point a breakpoint is set just after this BL.\n"
        "    Then execution is resumed. It will probably later hit the\n"
        "    breakpoint just set.\n"
        "continue / cont / c\n"
        "    Continue execution from here.\n"
        "disassemble / disasm / di\n"
        "    disassemble <n> <address>\n"
        "    Disassemble <n> instructions from current <address>.\n"
        "    By default <n> is 20 and <address> is the current pc.\n"
        "print / p\n"
        "    print <register>\n"
        "    Print the content of a register.\n"
        "    'print all' will print all registers.\n"
        "    Use 'printobject' to get more details about the value.\n"
        "printobject / po\n"
        "    printobject <value>\n"
        "    printobject <register>\n"
        "    Print details about the value.\n"
        "stack\n"
        "    stack [<words>]\n"
        "    Dump stack content, default dump 10 words\n"
        "mem\n"
        "    mem <address> [<words>]\n"
        "    Dump memory content, default dump 10 words\n"
        "dump\n"
        "    dump <address> [<words>]\n"
        "    Dump memory content without pretty printing JS objects, "
        "default dump 10 words\n"
        "trace / t\n"
        "    Toggle disassembly and register tracing\n"
        "break / b\n"
        "    break : list all breakpoints\n"
        "    break <address> : set / enable / disable a breakpoint.\n"
        "backtrace / bt\n"
        "    Walk the frame pointers, dumping the pc/sp/fp for each frame.\n"
        "gdb\n"
        "    Enter gdb.\n"
        "sysregs\n"
        "    Print all system registers (including NZCV).\n");
  } else {
    PrintF("Unknown command: %s\n", cmd);
    PrintF("Use 'help' for more information.\n");
  }

  if (cleared_log_disasm_bit == true) {
    set_log_parameters(log_parameters_ | LOG_DISASM);
  }
  return false;
}

void Simulator::VisitException(Instruction* instr) {
  switch (instr->Mask(ExceptionMask)) {
    case HLT: {
      if (instr->ImmException() == kImmExceptionIsDebug) {
        // Read the arguments encoded inline in the instruction stream.
        uint32_t code;
        uint32_t parameters;

        memcpy(&code, pc_->InstructionAtOffset(kDebugCodeOffset), sizeof(code));
        memcpy(&parameters, pc_->InstructionAtOffset(kDebugParamsOffset),
               sizeof(parameters));
        char const* message = reinterpret_cast<char const*>(
            pc_->InstructionAtOffset(kDebugMessageOffset));

        // Always print something when we hit a debug point that breaks.
        // We are going to break, so printing something is not an issue in
        // terms of speed.
        if (v8_flags.trace_sim_messages || v8_flags.trace_sim ||
            (parameters & BREAK)) {
          if (message != nullptr) {
            PrintF(stream_, "# %sDebugger hit %d: %s%s%s\n", clr_debug_number,
                   code, clr_debug_message, message, clr_normal);
          } else {
            PrintF(stream_, "# %sDebugger hit %d.%s\n", clr_debug_number, code,
                   clr_normal);
          }
          Builtin maybe_builtin = OffHeapInstructionStream::TryLookupCode(
              Isolate::Current(), reinterpret_cast<Address>(pc_));
          if (Builtins::IsBuiltinId(maybe_builtin)) {
            char const* name = Builtins::name(maybe_builtin);
            PrintF(stream_, "# %s                %sLOCATION: %s%s\n",
                   clr_debug_number, clr_debug_message, name, clr_normal);
          }
        }

        // Other options.
        switch (parameters & kDebuggerTracingDirectivesMask) {
          case TRACE_ENABLE:
            set_log_parameters(log_parameters() | parameters);
            if (parameters & LOG_SYS_REGS) {
              PrintSystemRegisters();
            }
            if (parameters & LOG_REGS) {
              PrintRegisters();
            }
            if (parameters & LOG_VREGS) {
              PrintVRegisters();
            }
            break;
          case TRACE_DISABLE:
            set_log_parameters(log_parameters() & ~parameters);
            break;
          case TRACE_OVERRIDE:
            set_log_parameters(parameters);
            break;
          default:
            // We don't support a one-shot LOG_DISASM.
            DCHECK_EQ(parameters & LOG_DISASM, 0);
            // Don't print information that is already being traced.
            parameters &= ~log_parameters();
            // Print the requested information.
            if (parameters & LOG_SYS_REGS) PrintSystemRegisters();
            if (parameters & LOG_REGS) PrintRegisters();
            if (parameters & LOG_VREGS) PrintVRegisters();
        }

        // The stop parameters are inlined in the code. Skip them:
        //  - Skip to the end of the message string.
        size_t size = kDebugMessageOffset + strlen(message) + 1;
        pc_ = pc_->InstructionAtOffset(RoundUp(size, kInstrSize));
        //  - Verify that the unreachable marker is present.
        DCHECK(pc_->Mask(ExceptionMask) == HLT);
        DCHECK_EQ(pc_->ImmException(), kImmExceptionIsUnreachable);
        //  - Skip past the unreachable marker.
        set_pc(pc_->following());

        // Check if the debugger should break.
        if (parameters & BREAK) Debug();

      } else if (instr->ImmException() == kImmExceptionIsRedirectedCall) {
        DoRuntimeCall(instr);
      } else if (instr->ImmException() == kImmExceptionIsPrintf) {
        DoPrintf(instr);
      } else if (instr->ImmException() == kImmExceptionIsSwitchStackLimit) {
        DoSwitchStackLimit(instr);
      } else if (instr->ImmException() == kImmExceptionIsUnreachable) {
        fprintf(stream_, "Hit UNREACHABLE marker at PC=%p.\n",
                reinterpret_cast<void*>(pc_));
        abort();

      } else {
        base::OS::DebugBreak();
      }
      break;
    }
    case BRK:
      base::OS::DebugBreak();
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitNEON2RegMisc(Instruction* instr) {
  NEONFormatDecoder nfd(instr);
  VectorFormat vf = nfd.GetVectorFormat();

  // Format mapping for "long pair" instructions, [su]addlp, [su]adalp.
  static const NEONFormatMap map_lp = {
      {23, 22, 30}, {NF_4H, NF_8H, NF_2S, NF_4S, NF_1D, NF_2D}};
  VectorFormat vf_lp = nfd.GetVectorFormat(&map_lp);

  static const NEONFormatMap map_fcvtl = {{22}, {NF_4S, NF_2D}};
  VectorFormat vf_fcvtl = nfd.GetVectorFormat(&map_fcvtl);

  static const NEONFormatMap map_fcvtn = {{22, 30},
                                          {NF_4H, NF_8H, NF_2S, NF_4S}};
  VectorFormat vf_fcvtn = nfd.GetVectorFormat(&map_fcvtn);

  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());

  if (instr->Mask(NEON2RegMiscOpcode) <= NEON_NEG_opcode) {
    // These instructions all use a two bit size field, except NOT and RBIT,
    // which use the field to encode the operation.
    switch (instr->Mask(NEON2RegMiscMask)) {
      case NEON_REV64:
        rev64(vf, rd, rn);
        break;
      case NEON_REV32:
        rev32(vf, rd, rn);
        break;
      case NEON_REV16:
        rev16(vf, rd, rn);
        break;
      case NEON_SUQADD:
        suqadd(vf, rd, rn);
        break;
      case NEON_USQADD:
        usqadd(vf, rd, rn);
        break;
      case NEON_CLS:
        cls(vf, rd, rn);
        break;
      case NEON_CLZ:
        clz(vf, rd, rn);
        break;
      case NEON_CNT:
        cnt(vf, rd, rn);
        break;
      case NEON_SQABS:
        abs(vf, rd, rn).SignedSaturate(vf);
        break;
      case NEON_SQNEG:
        neg(vf, rd, rn).SignedSaturate(vf);
        break;
      case NEON_CMGT_zero:
        cmp(vf, rd, rn, 0, gt);
        break;
      case NEON_CMGE_zero:
        cmp(vf, rd, rn, 0, ge);
        break;
      case NEON_CMEQ_zero:
        cmp(vf, rd, rn, 0, eq);
        break;
      case NEON_CMLE_zero:
        cmp(vf, rd, rn, 0, le);
        break;
      case NEON_CMLT_zero:
        cmp(vf, rd, rn, 0, lt);
        break;
      case NEON_ABS:
        abs(vf, rd, rn);
        break;
      case NEON_NEG:
        neg(vf, rd, rn);
        break;
      case NEON_SADDLP:
        saddlp(vf_lp, rd, rn);
        break;
      case NEON_UADDLP:
        uaddlp(vf_lp, rd, rn);
        break;
      case NEON_SADALP:
        sadalp(vf_lp, rd, rn);
        break;
      case NEON_UADALP:
        uadalp(vf_lp, rd, rn);
        break;
      case NEON_RBIT_NOT:
        vf = nfd.GetVectorFormat(nfd.LogicalFormatMap());
        switch (instr->FPType()) {
          case 0:
            not_(vf, rd, rn);
            break;
          case 1:
            rbit(vf, rd, rn);
            break;
          default:
            UNIMPLEMENTED();
        }
        break;
    }
  } else {
    VectorFormat fpf = nfd.GetVectorFormat(instr->Mask(NEON2RegMiscHPFixed) ==
                                                   NEON2RegMiscHPFixed
                                               ? nfd.FPHPFormatMap()
                                               : nfd.FPFormatMap());
    FPRounding fpcr_rounding = static_cast<FPRounding>(fpcr().RMode());
    bool inexact_exception = false;

    // These instructions all use a one bit size field, except XTN, SQXTUN,
    // SHLL, SQXTN and UQXTN, which use a two bit size field.
    switch (instr->Mask(NEON2RegMiscFPMask ^ NEON2RegMiscHPFixed)) {
      case NEON_FABS:
        fabs_(fpf, rd, rn);
        return;
      case NEON_FNEG:
        fneg(fpf, rd, rn);
        return;
      case NEON_FSQRT:
        fsqrt(fpf, rd, rn);
        return;
      case NEON_FCVTL:
        if (instr->Mask(NEON_Q)) {
          fcvtl2(vf_fcvtl, rd, rn);
        } else {
          fcvtl(vf_fcvtl, rd, rn);
        }
        return;
      case NEON_FCVTN:
        if (instr->Mask(NEON_Q)) {
          fcvtn2(vf_fcvtn, rd, rn);
        } else {
          fcvtn(vf_fcvtn, rd, rn);
        }
        return;
      case NEON_FCVTXN:
        if (instr->Mask(NEON_Q)) {
          fcvtxn2(vf_fcvtn, rd, rn);
        } else {
          fcvtxn(vf_fcvtn, rd, rn);
        }
        return;

      // The following instructions break from the switch statement, rather
      // than return.
      case NEON_FRINTI:
        break;  // Use FPCR rounding mode.
      case NEON_FRINTX:
        inexact_exception = true;
        break;
      case NEON_FRINTA:
        fpcr_rounding = FPTieAway;
        break;
      case NEON_FRINTM:
        fpcr_rounding = FPNegativeInfinity;
        break;
      case NEON_FRINTN:
        fpcr_rounding = FPTieEven;
        break;
      case NEON_FRINTP:
        fpcr_rounding = FPPositiveInfinity;
        break;
      case NEON_FRINTZ:
        fpcr_rounding = FPZero;
        break;

      // The remaining cases return to the caller.
      case NEON_FCVTNS:
        fcvts(fpf, rd, rn, FPTieEven);
        return;
      case NEON_FCVTNU:
        fcvtu(fpf, rd, rn, FPTieEven);
        return;
      case NEON_FCVTPS:
        fcvts(fpf, rd, rn, FPPositiveInfinity);
        return;
      case NEON_FCVTPU:
        fcvtu(fpf, rd, rn, FPPositiveInfinity);
        return;
      case NEON_FCVTMS:
        fcvts(fpf, rd, rn, FPNegativeInfinity);
        return;
      case NEON_FCVTMU:
        fcvtu(fpf, rd, rn, FPNegativeInfinity);
        return;
      case NEON_FCVTZS:
        fcvts(fpf, rd, rn, FPZero);
        return;
      case NEON_FCVTZU:
        fcvtu(fpf, rd, rn, FPZero);
        return;
      case NEON_FCVTAS:
        fcvts(fpf, rd, rn, FPTieAway);
        return;
      case NEON_FCVTAU:
        fcvtu(fpf, rd, rn, FPTieAway);
        return;
      case NEON_SCVTF:
        scvtf(fpf, rd, rn, 0, fpcr_rounding);
        return;
      case NEON_UCVTF:
        ucvtf(fpf, rd, rn, 0, fpcr_rounding);
        return;
      case NEON_URSQRTE:
        ursqrte(fpf, rd, rn);
        return;
      case NEON_URECPE:
        urecpe(fpf, rd, rn);
        return;
      case NEON_FRSQRTE:
        frsqrte(fpf, rd, rn);
        return;
      case NEON_FRECPE:
        frecpe(fpf, rd, rn, fpcr_rounding);
        return;
      case NEON_FCMGT_zero:
        fcmp_zero(fpf, rd, rn, gt);
        return;
      case NEON_FCMGE_zero:
        fcmp_zero(fpf, rd, rn, ge);
        return;
      case NEON_FCMEQ_zero:
        fcmp_zero(fpf, rd, rn, eq);
        return;
      case NEON_FCMLE_zero:
        fcmp_zero(fpf, rd, rn, le);
        return;
      case NEON_FCMLT_zero:
        fcmp_zero(fpf, rd, rn, lt);
        return;
      default:
        if ((NEON_XTN_opcode <= instr->Mask(NEON2RegMiscOpcode)) &&
            (instr->Mask(NEON2RegMiscOpcode) <= NEON_UQXTN_opcode)) {
          switch (instr->Mask(NEON2RegMiscMask)) {
            case NEON_XTN:
              xtn(vf, rd, rn);
              return;
            case NEON_SQXTN:
              sqxtn(vf, rd, rn);
              return;
            case NEON_UQXTN:
              uqxtn(vf, rd, rn);
              return;
            case NEON_SQXTUN:
              sqxtun(vf, rd, rn);
              return;
            case NEON_SHLL:
              vf = nfd.GetVectorFormat(nfd.LongIntegerFormatMap());
              if (instr->Mask(NEON_Q)) {
                shll2(vf, rd, rn);
              } else {
                shll(vf, rd, rn);
              }
              return;
            default:
              UNIMPLEMENTED();
          }
        } else {
          UNIMPLEMENTED();
        }
    }

    // Only FRINT* instructions fall through the switch above.
    frint(fpf, rd, rn, fpcr_rounding, inexact_exception);
  }
}

void Simulator::VisitNEON3SameFP(NEON3SameOp op, VectorFormat vf,
                                 SimVRegister& rd, SimVRegister& rn,
                                 SimVRegister& rm) {
  switch (op) {
    case NEON_FADD:
      fadd(vf, rd, rn, rm);
      break;
    case NEON_FSUB:
      fsub(vf, rd, rn, rm);
      break;
    case NEON_FMUL:
      fmul(vf, rd, rn, rm);
      break;
    case NEON_FDIV:
      fdiv(vf, rd, rn, rm);
      break;
    case NEON_FMAX:
      fmax(vf, rd, rn, rm);
      break;
    case NEON_FMIN:
      fmin(vf, rd, rn, rm);
      break;
    case NEON_FMAXNM:
      fmaxnm(vf, rd, rn, rm);
      break;
    case NEON_FMINNM:
      fminnm(vf, rd, rn, rm);
      break;
    case NEON_FMLA:
      fmla(vf, rd, rn, rm);
      break;
    case NEON_FMLS:
      fmls(vf, rd, rn, rm);
      break;
    case NEON_FMULX:
      fmulx(vf, rd, rn, rm);
      break;
    case NEON_FACGE:
      fabscmp(vf, rd, rn, rm, ge);
      break;
    case NEON_FACGT:
      fabscmp(vf, rd, rn, rm, gt);
      break;
    case NEON_FCMEQ:
      fcmp(vf, rd, rn, rm, eq);
      break;
    case NEON_FCMGE:
      fcmp(vf, rd, rn, rm, ge);
      break;
    case NEON_FCMGT:
      fcmp(vf, rd, rn, rm, gt);
      break;
    case NEON_FRECPS:
      frecps(vf, rd, rn, rm);
      break;
    case NEON_FRSQRTS:
      frsqrts(vf, rd, rn, rm);
      break;
    case NEON_FABD:
      fabd(vf, rd, rn, rm);
      break;
    case NEON_FADDP:
      faddp(vf, rd, rn, rm);
      break;
    case NEON_FMAXP:
      fmaxp(vf, rd, rn, rm);
      break;
    case NEON_FMAXNMP:
      fmaxnmp(vf, rd, rn, rm);
      break;
    case NEON_FMINP:
      fminp(vf, rd, rn, rm);
      break;
    case NEON_FMINNMP:
      fminnmp(vf, rd, rn, rm);
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitNEON3Same(Instruction* instr) {
  NEONFormatDecoder nfd(instr);
  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  SimVRegister& rm = vreg(instr->Rm());

  if (instr->Mask(NEON3SameLogicalFMask) == NEON3SameLogicalFixed) {
    VectorFormat vf = nfd.GetVectorFormat(nfd.LogicalFormatMap());
    switch (instr->Mask(NEON3SameLogicalMask)) {
      case NEON_AND:
        and_(vf, rd, rn, rm);
        break;
      case NEON_ORR:
        orr(vf, rd, rn, rm);
        break;
      case NEON_ORN:
        orn(vf, rd, rn, rm);
        break;
      case NEON_EOR:
        eor(vf, rd, rn, rm);
        break;
      case NEON_BIC:
        bic(vf, rd, rn, rm);
        break;
      case NEON_BIF:
        bif(vf, rd, rn, rm);
        break;
      case NEON_BIT:
        bit(vf, rd, rn, rm);
        break;
      case NEON_BSL:
        bsl(vf, rd, rn, rm);
        break;
      default:
        UNIMPLEMENTED();
    }
  } else if (instr->Mask(NEON3SameFPFMask) == NEON3SameFPFixed) {
    VectorFormat vf = nfd.GetVectorFormat(nfd.FPFormatMap());
    VisitNEON3SameFP(instr->Mask(NEON3SameFPMask), vf, rd, rn, rm);
  } else {
    VectorFormat vf = nfd.GetVectorFormat();
    switch (instr->Mask(NEON3SameMask)) {
      case NEON_ADD:
        add(vf, rd, rn, rm);
        break;
      case NEON_ADDP:
        addp(vf, rd, rn, rm);
        break;
      case NEON_CMEQ:
        cmp(vf, rd, rn, rm, eq);
        break;
      case NEON_CMGE:
        cmp(vf, rd, rn, rm, ge);
        break;
      case NEON_CMGT:
        cmp(vf, rd, rn, rm, gt);
        break;
      case NEON_CMHI:
        cmp(vf, rd, rn, rm, hi);
        break;
      case NEON_CMHS:
        cmp(vf, rd, rn, rm, hs);
        break;
      case NEON_CMTST:
        cmptst(vf, rd, rn, rm);
        break;
      case NEON_MLS:
        mls(vf, rd, rn, rm);
        break;
      case NEON_MLA:
        mla(vf, rd, rn, rm);
        break;
      case NEON_MUL:
        mul(vf, rd, rn, rm);
        break;
      case NEON_PMUL:
        pmul(vf, rd, rn, rm);
        break;
      case NEON_SMAX:
        smax(vf, rd, rn, rm);
        break;
      case NEON_SMAXP:
        smaxp(vf, rd, rn, rm);
        break;
      case NEON_SMIN:
        smin(vf, rd, rn, rm);
        break;
      case NEON_SMINP:
        sminp(vf, rd, rn, rm);
        break;
      case NEON_SUB:
        sub(vf, rd, rn, rm);
        break;
      case NEON_UMAX:
        umax(vf, rd, rn, rm);
        break;
      case NEON_UMAXP:
        umaxp(vf, rd, rn, rm);
        break;
      case NEON_UMIN:
        umin(vf, rd, rn, rm);
        break;
      case NEON_UMINP:
        uminp(vf, rd, rn, rm);
        break;
      case NEON_SSHL:
        sshl(vf, rd, rn, rm);
        break;
      case NEON_USHL:
        ushl(vf, rd, rn, rm);
        break;
      case NEON_SABD:
        AbsDiff(vf, rd, rn, rm, true);
        break;
      case NEON_UABD:
        AbsDiff(vf, rd, rn, rm, false);
        break;
      case NEON_SABA:
        saba(vf, rd, rn, rm);
        break;
      case NEON_UABA:
        uaba(vf, rd, rn, rm);
        break;
      case NEON_UQADD:
        add(vf, rd, rn, rm).UnsignedSaturate(vf);
        break;
      case NEON_SQADD:
        add(vf, rd, rn, rm).SignedSaturate(vf);
        break;
      case NEON_UQSUB:
        sub(vf, rd, rn, rm).UnsignedSaturate(vf);
        break;
      case NEON_SQSUB:
        sub(vf, rd, rn, rm).SignedSaturate(vf);
        break;
      case NEON_SQDMULH:
        sqdmulh(vf, rd, rn, rm);
        break;
      case NEON_SQRDMULH:
        sqrdmulh(vf, rd, rn, rm);
        break;
      case NEON_UQSHL:
        ushl(vf, rd, rn, rm).UnsignedSaturate(vf);
        break;
      case NEON_SQSHL:
        sshl(vf, rd, rn, rm).SignedSaturate(vf);
        break;
      case NEON_URSHL:
        ushl(vf, rd, rn, rm).Round(vf);
        break;
      case NEON_SRSHL:
        sshl(vf, rd, rn, rm).Round(vf);
        break;
      case NEON_UQRSHL:
        ushl(vf, rd, rn, rm).Round(vf).UnsignedSaturate(vf);
        break;
      case NEON_SQRSHL:
        sshl(vf, rd, rn, rm).Round(vf).SignedSaturate(vf);
        break;
      case NEON_UHADD:
        add(vf, rd, rn, rm).Uhalve(vf);
        break;
      case NEON_URHADD:
        add(vf, rd, rn, rm).Uhalve(vf).Round(vf);
        break;
      case NEON_SHADD:
        add(vf, rd, rn, rm).Halve(vf);
        break;
      case NEON_SRHADD:
        add(vf, rd, rn, rm).Halve(vf).Round(vf);
        break;
      case NEON_UHSUB:
        sub(vf, rd, rn, rm).Uhalve(vf);
        break;
      case NEON_SHSUB:
        sub(vf, rd, rn, rm).Halve(vf);
        break;
      default:
        UNIMPLEMENTED();
    }
  }
}

void Simulator::VisitNEON3SameHP(Instruction* instr) {
  NEONFormatDecoder nfd(instr);
  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  SimVRegister& rm = vreg(instr->Rm());
  VectorFormat vf = nfd.GetVectorFormat(nfd.FPHPFormatMap());
  VisitNEON3SameFP(instr->Mask(NEON3SameFPMask) | NEON3SameHPMask, vf, rd, rn,
                   rm);
}

void Simulator::VisitNEON3Different(Instruction* instr) {
  NEONFormatDecoder nfd(instr);
  VectorFormat vf = nfd.GetVectorFormat();
  VectorFormat vf_l = nfd.GetVectorFormat(nfd.LongIntegerFormatMap());

  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  SimVRegister& rm = vreg(instr->Rm());
  int size = instr->NEONSize();

  switch (instr->Mask(NEON3DifferentMask)) {
    case NEON_PMULL:
      if ((size == 1) || (size == 2)) {  // S/D reserved.
        VisitUnallocated(instr);
      } else {
        if (size == 3) vf_l = kFormat1Q;
        pmull(vf_l, rd, rn, rm);
      }
      break;
    case NEON_PMULL2:
      if ((size == 1) || (size == 2)) {  // S/D reserved.
        VisitUnallocated(instr);
      } else {
        if (size == 3) vf_l = kFormat1Q;
        pmull2(vf_l, rd, rn, rm);
      }
      break;
    case NEON_UADDL:
      uaddl(vf_l, rd, rn, rm);
      break;
    case NEON_UADDL2:
      uaddl2(vf_l, rd, rn, rm);
      break;
    case NEON_SADDL:
      saddl(vf_l, rd, rn, rm);
      break;
    case NEON_SADDL2:
      saddl2(vf_l, rd, rn, rm);
      break;
    case NEON_USUBL:
      usubl(vf_l, rd, rn, rm);
      break;
    case NEON_USUBL2:
      usubl2(vf_l, rd, rn, rm);
      break;
    case NEON_SSUBL:
      ssubl(vf_l, rd, rn, rm);
      break;
    case NEON_SSUBL2:
      ssubl2(vf_l, rd, rn, rm);
      break;
    case NEON_SABAL:
      sabal(vf_l, rd, rn, rm);
      break;
    case NEON_SABAL2:
      sabal2(vf_l, rd, rn, rm);
      break;
    case NEON_UABAL:
      uabal(vf_l, rd, rn, rm);
      break;
    case NEON_UABAL2:
      uabal2(vf_l, rd, rn, rm);
      break;
    case NEON_SABDL:
      sabdl(vf_l, rd, rn, rm);
      break;
    case NEON_SABDL2:
      sabdl2(vf_l, rd, rn, rm);
      break;
    case NEON_UABDL:
      uabdl(vf_l, rd, rn, rm);
      break;
    case NEON_UABDL2:
      uabdl2(vf_l, rd, rn, rm);
      break;
    case NEON_SMLAL:
      smlal(vf_l, rd, rn, rm);
      break;
    case NEON_SMLAL2:
      smlal2(vf_l, rd, rn, rm);
      break;
    case NEON_UMLAL:
      umlal(vf_l, rd, rn, rm);
      break;
    case NEON_UMLAL2:
      umlal2(vf_l, rd, rn, rm);
      break;
    case NEON_SMLSL:
      smlsl(vf_l, rd, rn, rm);
      break;
    case NEON_SMLSL2:
      smlsl2(vf_l, rd, rn, rm);
      break;
    case NEON_UMLSL:
      umlsl(vf_l, rd, rn, rm);
      break;
    case NEON_UMLSL2:
      umlsl2(vf_l, rd, rn, rm);
      break;
    case NEON_SMULL:
      smull(vf_l, rd, rn, rm);
      break;
    case NEON_SMULL2:
      smull2(vf_l, rd, rn, rm);
      break;
    case NEON_UMULL:
      umull(vf_l, rd, rn, rm);
      break;
    case NEON_UMULL2:
      umull2(vf_l, rd, rn, rm);
      break;
    case NEON_SQDMLAL:
      sqdmlal(vf_l, rd, rn, rm);
      break;
    case NEON_SQDMLAL2:
      sqdmlal2(vf_l, rd, rn, rm);
      break;
    case NEON_SQDMLSL:
      sqdmlsl(vf_l, rd, rn, rm);
      break;
    case NEON_SQDMLSL2:
      sqdmlsl2(vf_l, rd, rn, rm);
      break;
    case NEON_SQDMULL:
      sqdmull(vf_l, rd, rn, rm);
      break;
    case NEON_SQDMULL2:
      sqdmull2(vf_l, rd, rn, rm);
      break;
    case NEON_UADDW:
      uaddw(vf_l, rd, rn, rm);
      break;
    case NEON_UADDW2:
      uaddw2(vf_l, rd, rn, rm);
      break;
    case NEON_SADDW:
      saddw(vf_l, rd, rn, rm);
      break;
    case NEON_SADDW2:
      saddw2(vf_l, rd, rn, rm);
      break;
    case NEON_USUBW:
      usubw(vf_l, rd, rn, rm);
      break;
    case NEON_USUBW2:
      usubw2(vf_l, rd, rn, rm);
      break;
    case NEON_SSUBW:
      ssubw(vf_l, rd, rn, rm);
      break;
    case NEON_SSUBW2:
      ssubw2(vf_l, rd, rn, rm);
      break;
    case NEON_ADDHN:
      addhn(vf, rd, rn, rm);
      break;
    case NEON_ADDHN2:
      addhn2(vf, rd, rn, rm);
      break;
    case NEON_RADDHN:
      raddhn(vf, rd, rn, rm);
      break;
    case NEON_RADDHN2:
      raddhn2(vf, rd, rn, rm);
      break;
    case NEON_SUBHN:
      subhn(vf, rd, rn, rm);
      break;
    case NEON_SUBHN2:
      subhn2(vf, rd, rn, rm);
      break;
    case NEON_RSUBHN:
      rsubhn(vf, rd, rn, rm);
      break;
    case NEON_RSUBHN2:
      rsubhn2(vf, rd, rn, rm);
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitNEON3Extension(Instruction* instr) {
  NEONFormatDecoder nfd(instr);
  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rm = vreg(instr->Rm());
  SimVRegister& rn = vreg(instr->Rn());
  VectorFormat vf = nfd.GetVectorFormat();

  switch (instr->Mask(NEON3ExtensionMask)) {
    case NEON_SDOT:
      if (vf == kFormat4S || vf == kFormat2S) {
        sdot(vf, rd, rn, rm);
      } else {
        VisitUnallocated(instr);
      }

      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitNEONAcrossLanes(Instruction* instr) {
  NEONFormatDecoder nfd(instr);

  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());

  // The input operand's VectorFormat is passed for these instructions.
  if (instr->Mask(NEONAcrossLanesFPFMask) == NEONAcrossLanesFPFixed) {
    VectorFormat vf = nfd.GetVectorFormat(nfd.FPFormatMap());

    switch (instr->Mask(NEONAcrossLanesFPMask)) {
      case NEON_FMAXV:
        fmaxv(vf, rd, rn);
        break;
      case NEON_FMINV:
        fminv(vf, rd, rn);
        break;
      case NEON_FMAXNMV:
        fmaxnmv(vf, rd, rn);
        break;
      case NEON_FMINNMV:
        fminnmv(vf, rd, rn);
        break;
      default:
        UNIMPLEMENTED();
    }
  } else {
    VectorFormat vf = nfd.GetVectorFormat();

    switch (instr->Mask(NEONAcrossLanesMask)) {
      case NEON_ADDV:
        addv(vf, rd, rn);
        break;
      case NEON_SMAXV:
        smaxv(vf, rd, rn);
        break;
      case NEON_SMINV:
        sminv(vf, rd, rn);
        break;
      case NEON_UMAXV:
        umaxv(vf, rd, rn);
        break;
      case NEON_UMINV:
        uminv(vf, rd, rn);
        break;
      case NEON_SADDLV:
        saddlv(vf, rd, rn);
        break;
      case NEON_UADDLV:
        uaddlv(vf, rd, rn);
        break;
      default:
        UNIMPLEMENTED();
    }
  }
}

void Simulator::VisitNEONByIndexedElement(Instruction* instr) {
  NEONFormatDecoder nfd(instr);
  VectorFormat vf_r = nfd.GetVectorFormat();
  VectorFormat vf = nfd.GetVectorFormat(nfd.LongIntegerFormatMap());

  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());

  ByElementOp Op = nullptr;

  int rm_reg = instr->Rm();
  int index = (instr->NEONH() << 1) | instr->NEONL();
  if (instr->NEONSize() == 1) {
    rm_reg &= 0xF;
    index = (index << 1) | instr->NEONM();
  }

  switch (instr->Mask(NEONByIndexedElementMask)) {
    case NEON_MUL_byelement:
      Op = &Simulator::mul;
      vf = vf_r;
      break;
    case NEON_MLA_byelement:
      Op = &Simulator::mla;
      vf = vf_r;
      break;
    case NEON_MLS_byelement:
      Op = &Simulator::mls;
      vf = vf_r;
      break;
    case NEON_SQDMULH_byelement:
      Op = &Simulator::sqdmulh;
      vf = vf_r;
      break;
    case NEON_SQRDMULH_byelement:
      Op = &Simulator::sqrdmulh;
      vf = vf_r;
      break;
    case NEON_SMULL_byelement:
      if (instr->Mask(NEON_Q)) {
        Op = &Simulator::smull2;
      } else {
        Op = &Simulator::smull;
      }
      break;
    case NEON_UMULL_byelement:
      if (instr->Mask(NEON_Q)) {
        Op = &Simulator::umull2;
      } else {
        Op = &Simulator::umull;
      }
      break;
    case NEON_SMLAL_byelement:
      if (instr->Mask(NEON_Q)) {
        Op = &Simulator::smlal2;
      } else {
        Op = &Simulator::smlal;
      }
      break;
    case NEON_UMLAL_byelement:
      if (instr->Mask(NEON_Q)) {
        Op = &Simulator::umlal2;
      } else {
        Op = &Simulator::umlal;
      }
      break;
    case NEON_SMLSL_byelement:
      if (instr->Mask(NEON_Q)) {
        Op = &Simulator::smlsl2;
      } else {
        Op = &Simulator::smlsl;
      }
      break;
    case NEON_UMLSL_byelement:
      if (instr->Mask(NEON_Q)) {
        Op = &Simulator::umlsl2;
      } else {
        Op = &Simulator::umlsl;
      }
      break;
    case NEON_SQDMULL_byelement:
      if (instr->Mask(NEON_Q)) {
        Op = &Simulator::sqdmull2;
      } else {
        Op = &Simulator::sqdmull;
      }
      break;
    case NEON_SQDMLAL_byelement:
      if (instr->Mask(NEON_Q)) {
        Op = &Simulator::sqdmlal2;
      } else {
        Op = &Simulator::sqdmlal;
      }
      break;
    case NEON_SQDMLSL_byelement:
      if (instr->Mask(NEON_Q)) {
        Op = &Simulator::sqdmlsl2;
      } else {
        Op = &Simulator::sqdmlsl;
      }
      break;
    default:
      index = instr->NEONH();
      if ((instr->FPType() & 1) == 0) {
        index = (index << 1) | instr->NEONL();
      }

      vf = nfd.Ge
"""


```