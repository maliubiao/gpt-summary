Response:
Let's break down the thought process to analyze the provided C++ code snippet.

**1. Initial Understanding of the Request:**

The request asks for an analysis of a specific V8 source file (`code-generator-riscv.cc`). It wants to know its functionality, how it relates to JavaScript, and information about potential programming errors or logic. Crucially, it also specifies that this is *part 6 of 6*, implying a need for a summary/conclusion.

**2. High-Level Identification - Code Generation:**

The file name `code-generator-riscv.cc` immediately suggests that this code is responsible for generating machine code for the RISC-V architecture within the V8 JavaScript engine. The `compiler/backend` path reinforces this, indicating it's part of the compilation process that translates high-level code into low-level instructions.

**3. Examining Key Functions:**

I'll scan the code for important function names and patterns.

* **`AssembleArch...` functions:**  Functions like `AssembleArchBranch`, `AssembleArchConditionalBoolean`, `AssembleArchConditionalBranch`, `AssembleArchBinarySearchSwitch`, and `AssembleArchTableSwitch` strongly suggest the core purpose: assembling RISC-V instructions for different control flow constructs (branches, switches). The "Arch" prefix likely indicates architecture-specific code generation.
* **`AssembleMove` and `AssembleSwap`:** These are fundamental for moving data between registers, memory, and constants.
* **`AssembleConstructFrame` and `AssembleDeconstructFrame` / `AssembleReturn`:** These deal with setting up and tearing down the execution stack frame when a function is called and returns.
* **`Push` and `Pop`:**  Basic stack manipulation operations.
* **`CodeGenerator::FinishFrame` and `CodeGenerator::FinishCode`:**  Lifecycle-related functions for code generation.
* **Conditional Compilation (`#ifdef V8_TARGET_ARCH_RISCV64`):**  This indicates that the code handles different instruction sets or behaviors depending on whether it's compiling for 32-bit or 64-bit RISC-V. This is an important distinction.

**4. Focusing on the `AssembleArchBranch` Function:**

This function is quite detailed and provides insights into how comparisons and conditional jumps are handled on RISC-V.

* **Comparison with Zero:** The code handles comparisons against zero (`kRiscvCmpZero`, `kRiscvCmpZero32`). This suggests a common optimization.
* **Floating-Point Comparisons (`kRiscvCmpD`, `kRiscvCmpS`):**  Special handling for comparing floating-point numbers.
* **Stack Pointer Check (`kArchStackPointerGreaterThan`):**  Indicates checks for stack overflow or underflow.
* **Use of RISC-V Instructions:** Instructions like `Sltu`, `Slt`, `Xor`, `Sgtu`, `fmv.x.w`, `fmv.w.x` are RISC-V specific. Understanding these (or recognizing their function from the context) is key.

**5. Identifying Connections to JavaScript:**

The fact that this is V8 means it *must* be related to JavaScript. The code generates the low-level instructions that execute JavaScript. Specific examples can be inferred:

* **Conditional Statements (`if`, `else if`, `else`):** The `AssembleArchConditionalBranch` and related functions are directly responsible for implementing these.
* **Comparison Operators (`==`, `!=`, `<`, `>`, `<=`, `>=`):** The `AssembleArchBranch` logic for various conditions directly implements these operators.
* **Function Calls:** `AssembleConstructFrame` and `AssembleReturn` are essential for calling JavaScript functions.
* **Data Types (Numbers, Floats):**  The handling of floating-point comparisons and the use of `kRiscvCmpD` and `kRiscvCmpS` indicate support for JavaScript's number type.

**6. Considering Potential Programming Errors:**

Based on the code, potential errors can be identified:

* **Incorrect Handling of Floating-Point Comparisons:**  The comments about the `kScratchReg` and toggling it suggest a delicate implementation that could be error-prone if not done correctly. Specifically, failing to handle NaN or different floating-point comparison semantics could lead to bugs.
* **Stack Overflow Issues:** The `kArchStackPointerGreaterThan` check and the frame setup/teardown logic are areas where errors in calculating stack frame size or improperly managing the stack pointer could cause crashes.
* **Register Allocation Problems:**  While not directly visible in this snippet, the use of scratch registers and temporary registers within the assembly functions suggests potential for errors if registers are not managed carefully, leading to data corruption.

**7. Simulating a Code Logic Scenario:**

Choose a simple scenario, like comparing two integers:

* **Input:**  JavaScript code `if (a > b) { ... }` where `a` and `b` are integer variables.
* **Code Generation (Hypothetical):** The `AssembleArchBranch` function (specifically the `gt` case within the integer comparison) would be invoked. It would likely generate RISC-V `slt` (set less than) instruction, potentially followed by inverting the result depending on the specific condition. The output would be RISC-V assembly instructions that set a flag based on the comparison.

**8. Considering the `.tq` Extension:**

The request asks about the `.tq` extension. Based on common V8 practices, `.tq` files are typically related to Torque, V8's internal language for defining built-in functions. If this file *were* a `.tq` file, it would contain a higher-level description that Torque would then compile into C++ code (potentially something very similar to the provided snippet).

**9. Synthesizing the Summary (Part 6 of 6):**

Recognize the "part 6 of 6" instruction. The summary should emphasize that this file is a *key component* of V8's RISC-V backend, responsible for the final stage of compilation where abstract instructions are translated into concrete machine code. It's the bridge between V8's internal representation and the actual hardware.

**Self-Correction/Refinement:**

* **Initial thought:**  Focus heavily on individual RISC-V instructions.
* **Correction:**  Shift focus to the *purpose* of the code – code generation for control flow, data manipulation, and function calls. While RISC-V knowledge is helpful, explaining the higher-level function is more important for a general understanding.
* **Initial thought:**  Provide extremely detailed RISC-V instruction explanations.
* **Correction:**  Keep explanations concise and focus on the *effect* of the instructions rather than deep technical details, unless absolutely necessary. Assume the user has some familiarity with assembly concepts.
* **Initial thought:**  Treat the `.tq` question as a hypothetical.
* **Correction:**  Explicitly state that the provided code is C++ (`.cc`) and explain the potential meaning of `.tq` in the V8 context.

By following this thought process, I can systematically analyze the code snippet, address all parts of the request, and provide a comprehensive explanation.
这是一个V8 JavaScript引擎中用于RISC-V架构的代码生成器的C++源代码文件。根据你提供的信息，我们来详细分析它的功能：

**1. 核心功能：RISC-V 架构的代码生成**

`v8/src/compiler/backend/riscv/code-generator-riscv.cc` 的主要职责是将 V8 编译器生成的中间表示（IR，通常是 Machine Instructions）转换为可以在 RISC-V 处理器上执行的实际机器码。它负责选择合适的 RISC-V 指令，管理寄存器分配，处理内存访问，以及生成函数调用和返回的指令序列。

**2. 具体功能分解 (基于代码片段分析):**

从提供的代码片段中，我们可以推断出以下具体功能：

* **条件分支指令生成 (`AssembleArchBranch`)：**
    * 该函数负责根据不同的条件码（例如相等、不等、小于、大于等）生成相应的 RISC-V 分支指令。
    * 它处理了整数（包括 32 位和 64 位）以及浮点数的比较。
    * 对于比较操作，它使用了 RISC-V 的 `sltu` (set less than unsigned), `slt` (set less than), `xor` (异或) 等指令来实现不同的比较逻辑。
    * 它还处理了与零的特殊比较 (`kRiscvCmpZero`, `kRiscvCmpZero32`)，这是一种常见的优化。
    * 针对浮点数比较 (`kRiscvCmpD`, `kRiscvCmpS`)，它使用了 FPU 寄存器，并根据条件码设置结果寄存器 (`result`)。
    * 实现了对栈指针的比较 (`kArchStackPointerGreaterThan`)，这通常用于栈溢出检查。

* **条件布尔值生成 (`AssembleArchConditionalBoolean`)：** 虽然代码中是 `UNREACHABLE()`，但从函数名可以推断，它本应负责根据条件生成布尔值结果，可能在某些优化场景下使用。

* **条件分支 (`AssembleArchConditionalBranch`)：** 同样是 `UNREACHABLE()`，表明该架构可能没有单独的条件分支指令，而是通过 `AssembleArchBranch` 实现。

* **二分查找 Switch 语句生成 (`AssembleArchBinarySearchSwitch`)：**  该函数实现了使用二分查找方式生成 Switch 语句的机器码。它会生成一系列比较和跳转指令，以便在多个 case 中高效地定位目标。

* **跳转表 Switch 语句生成 (`AssembleArchTableSwitch`)：**  该函数实现了使用跳转表的方式生成 Switch 语句的机器码。它会生成一个地址表，通过索引直接跳转到对应的 case。

* **帧的构造和析构 (`FinishFrame`, `AssembleConstructFrame`, `AssembleDeconstructFrame`, `AssembleReturn`)：**
    * `FinishFrame`：在代码生成结束后执行，可能进行一些清理工作。
    * `AssembleConstructFrame`：生成函数调用的序言代码，包括保存返回地址和帧指针，分配栈空间，保存被调用者保存的寄存器等。它还处理了 WebAssembly 函数的大帧情况下的栈溢出检查。
    * `AssembleReturn`：生成函数调用的尾声代码，包括恢复寄存器，调整栈指针，并返回。它还处理了 JavaScript 函数调用时参数的弹出。

* **代码完成 (`FinishCode`)：**  执行代码生成后的最终步骤，例如强制常量池的生成。

* **为反优化出口做准备 (`PrepareForDeoptimizationExits`)：**  预留空间和设置标记，以便在需要进行反优化时跳转到相应的出口。

* **数据移动 (`AssembleMove`, `AssembleSwap`)：**
    * `AssembleMove`：生成将数据从一个位置移动到另一个位置的指令，包括寄存器到寄存器、寄存器到内存、内存到寄存器、常量到寄存器/内存等多种情况。它还处理了浮点数和 SIMD 数据的移动。
    * `AssembleSwap`：生成交换两个位置数据的指令。

* **栈操作 (`Push`, `Pop`, `PopTempStackSlots`)：**
    * `Push`：生成将数据压入栈的指令。
    * `Pop`：生成从栈中弹出数据的指令。
    * `PopTempStackSlots`：弹出临时使用的栈空间。

* **跳转表生成 (`AssembleJumpTable`)：** 在 RISC-V 64 位架构上，跳转表是内联生成的。

**3. 与 JavaScript 功能的关系：**

`code-generator-riscv.cc` 是 V8 将 JavaScript 代码转换为机器码的关键环节。它直接影响了 JavaScript 代码在 RISC-V 架构上的执行效率。例如：

* **`if` 语句和比较运算符：** `AssembleArchBranch` 函数生成的代码直接对应 JavaScript 中的 `if`、`else if`、`else` 语句以及比较运算符（`==`, `!=`, `<`, `>`, `<=`, `>=`）。
* **`switch` 语句：** `AssembleArchBinarySearchSwitch` 和 `AssembleArchTableSwitch` 函数生成的代码对应 JavaScript 中的 `switch` 语句。
* **函数调用：** `AssembleConstructFrame` 和 `AssembleReturn` 生成的代码负责 JavaScript 函数的调用和返回机制。
* **变量和数据操作：** `AssembleMove` 和 `AssembleSwap` 生成的代码负责 JavaScript 变量的赋值、读取以及各种数据操作。

**JavaScript 示例：**

```javascript
function compare(a, b) {
  if (a > b) {
    return "a is greater than b";
  } else if (a < b) {
    return "a is less than b";
  } else {
    return "a is equal to b";
  }
}

let x = 10;
let y = 5;
let result = compare(x, y);
console.log(result);

switch (x) {
  case 5:
    console.log("x is 5");
    break;
  case 10:
    console.log("x is 10");
    break;
  default:
    console.log("x is something else");
}
```

当 V8 编译这段 JavaScript 代码时，`code-generator-riscv.cc` 中的函数会被调用来生成相应的 RISC-V 机器码，例如：

* 对于 `if (a > b)`，`AssembleArchBranch` 会生成比较 `a` 和 `b` 的 RISC-V 指令，并根据比较结果跳转到不同的代码块。
* 对于 `switch (x)`，`AssembleArchTableSwitch` 或 `AssembleArchBinarySearchSwitch` 会生成跳转表或二分查找代码来高效地确定要执行的 `case`。
* 对于函数 `compare` 的调用，`AssembleConstructFrame` 会生成设置栈帧的代码，`AssembleReturn` 会生成返回指令。
* 对于变量 `x` 和 `y` 的赋值和比较，`AssembleMove` 会生成在寄存器或内存之间移动数据的指令。

**4. 代码逻辑推理示例 (假设输入与输出):**

假设 `AssembleArchBranch` 的输入是一个表示 "a > b" 的比较指令，并且 `a` 和 `b` 的值分别存储在寄存器 `r10` 和 `r11` 中。输出的 RISC-V 指令可能如下（简化）：

```assembly
  slt t0, r11, r10  // 如果 r11 < r10 (即 b < a)，则设置 t0 为 1，否则为 0
  beqz t0, .else_label // 如果 t0 为 0 (即 a <= b)，则跳转到 .else_label
  // ... "a is greater than b" 的代码 ...
  j .end_if

.else_label:
  // ... 其他 else if 或 else 的代码 ...

.end_if:
```

这里 `slt` 指令执行了小于比较，而 `beqz` 指令实现了条件跳转。

**5. 用户常见的编程错误示例：**

* **浮点数比较错误：**  直接使用 `==` 或 `!=` 比较浮点数可能由于精度问题导致意外结果。`code-generator-riscv.cc` 中对浮点数比较的处理需要确保符合 IEEE 754 标准，但如果 JavaScript 代码中直接使用 `==` 比较浮点数，可能会产生与预期不符的行为。

   ```javascript
   let num1 = 0.1 + 0.2;
   let num2 = 0.3;
   if (num1 == num2) { // 结果可能为 false，即使理论上应该相等
     console.log("Equal");
   } else {
     console.log("Not equal"); // 可能会输出这个
   }
   ```

* **Switch 语句缺少 `break`：**  在 `switch` 语句中忘记添加 `break` 会导致 case 穿透，执行到后续的 case 代码，这可能是非预期的行为。代码生成器会按照逻辑生成指令，但逻辑错误来源于 JavaScript 代码。

   ```javascript
   let value = 1;
   switch (value) {
     case 1:
       console.log("Case 1"); // 会执行
     case 2:
       console.log("Case 2"); // 会执行，因为缺少 break
       break;
     default:
       console.log("Default");
   }
   ```

* **栈溢出：**  虽然 `code-generator-riscv.cc` 中有栈溢出检查的代码，但如果 JavaScript 代码中存在大量的递归调用或者创建非常大的局部变量，仍然可能导致栈溢出错误。

**6. 归纳总结其功能 (作为第 6 部分):**

`v8/src/compiler/backend/riscv/code-generator-riscv.cc` 是 V8 JavaScript 引擎针对 RISC-V 架构的代码生成器的核心组件。它负责将编译器生成的中间表示转换为实际的 RISC-V 机器码，是连接高级 JavaScript 代码和底层硬件执行的关键桥梁。 该文件实现了生成各种指令的功能，包括条件分支、数据移动、栈操作以及函数调用的序言和尾声代码。其正确性和效率直接影响 JavaScript 代码在 RISC-V 平台上的性能。 理解这个文件的功能对于深入了解 V8 的编译流程和 RISC-V 架构至关重要。

**关于 `.tq` 结尾：**

如果 `v8/src/compiler/backend/riscv/code-generator-riscv.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是 V8 内部使用的一种领域特定语言，用于定义内置函数和运行时函数的实现。 Torque 代码会被编译成 C++ 代码。  然而，你提供的文件是 `.cc` 结尾，所以它是一个直接用 C++ 编写的源代码文件。

### 提示词
```
这是目录为v8/src/compiler/backend/riscv/code-generator-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/riscv/code-generator-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
_equal: {
        Register left = zero_reg;
        Operand right = i.InputOperand(0);
        __ Sltu(result, left, right);
        if (cc == Uless_equal) {
          __ Xor(result, result, 1);
        }
      } break;
      default:
        UNREACHABLE();
    }
    return;
#ifdef V8_TARGET_ARCH_RISCV64
  } else if (instr->arch_opcode() == kRiscvCmpZero32) {
    auto trim_reg = [&](Register in) -> Register {
        Register temp = i.TempRegister(0);
        __ slliw(temp, in, 0);
        return temp;
    };
    auto trim_op = [&](Operand in) -> Register {
        Register temp = i.TempRegister(0);
        if (in.is_reg()) {
          __ slliw(temp, in.rm(), 0);
        } else {
          __ Li(temp, in.immediate());
          __ slliw(temp, temp, 0);
        }
        return temp;
    };
    Condition cc = FlagsConditionToConditionCmp(condition);
    switch (cc) {
      case eq: {
        auto left = trim_reg(i.InputOrZeroRegister(0));
        __ Sltu(result, left, 1);
        break;
      }
      case ne: {
        auto left = trim_reg(i.InputOrZeroRegister(0));
        __ Sltu(result, zero_reg, left);
        break;
      }
      case lt:
      case ge: {
        auto left = trim_reg(i.InputOrZeroRegister(0));
        __ Slt(result, left, zero_reg);
        if (cc == ge) {
          __ Xor(result, result, 1);
        }
      } break;
      case gt:
      case le: {
        auto left = trim_op(i.InputOperand(0));
        __ Slt(result, zero_reg, left);
        if (cc == le) {
          __ Xor(result, result, 1);
        }
      } break;
      case Uless:
      case Ugreater_equal: {
        auto left = trim_reg(i.InputOrZeroRegister(0));
        __ Sltu(result, left, zero_reg);
        if (cc == Ugreater_equal) {
          __ Xor(result, result, 1);
        }
      } break;
      case Ugreater:
      case Uless_equal: {
        auto right = trim_op(i.InputOperand(0));
        __ Sltu(result, zero_reg, right);
        if (cc == Uless_equal) {
          __ Xor(result, result, 1);
        }
      } break;
      default:
        UNREACHABLE();
    }
    return;
#endif
  } else if (instr->arch_opcode() == kArchStackPointerGreaterThan) {
    Register lhs_register = sp;
    uint32_t offset;
    if (ShouldApplyOffsetToStackCheck(instr, &offset)) {
      lhs_register = i.TempRegister(0);
      __ SubWord(lhs_register, sp, offset);
    }
    __ Sgtu(result, lhs_register, Operand(i.InputRegister(0)));
    return;
  } else if (instr->arch_opcode() == kRiscvCmpD ||
             instr->arch_opcode() == kRiscvCmpS) {
    if (instr->arch_opcode() == kRiscvCmpD) {
      FPURegister left = i.InputOrZeroDoubleRegister(0);
      FPURegister right = i.InputOrZeroDoubleRegister(1);
      if ((left == kDoubleRegZero || right == kDoubleRegZero) &&
          !__ IsDoubleZeroRegSet()) {
        __ LoadFPRImmediate(kDoubleRegZero, 0.0);
      }
    } else {
      FPURegister left = i.InputOrZeroSingleRegister(0);
      FPURegister right = i.InputOrZeroSingleRegister(1);
      if ((left == kSingleRegZero || right == kSingleRegZero) &&
          !__ IsSingleZeroRegSet()) {
        __ LoadFPRImmediate(kSingleRegZero, 0.0f);
      }
    }
    bool predicate;
    FlagsConditionToConditionCmpFPU(&predicate, condition);
    // RISCV compare returns 0 or 1, do nothing when predicate; otherwise
    // toggle kScratchReg (i.e., 0 -> 1, 1 -> 0)
    if (predicate) {
      __ Move(result, kScratchReg);
    } else {
      __ Xor(result, kScratchReg, 1);
    }
    return;
  } else {
    PrintF("AssembleArchBranch Unimplemented arch_opcode is : %d\n",
           instr->arch_opcode());
    TRACE("UNIMPLEMENTED code_generator_riscv64: %s at line %d\n", __FUNCTION__,
          __LINE__);
    UNIMPLEMENTED();
  }
}

void CodeGenerator::AssembleArchConditionalBoolean(Instruction* instr) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchConditionalBranch(Instruction* instr,
                                                  BranchInfo* branch) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchBinarySearchSwitch(Instruction* instr) {
  RiscvOperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  std::vector<std::pair<int32_t, Label*>> cases;
  for (size_t index = 2; index < instr->InputCount(); index += 2) {
    cases.push_back({i.InputInt32(index + 0), GetLabel(i.InputRpo(index + 1))});
  }
  AssembleArchBinarySearchSwitchRange(input, i.InputRpo(1), cases.data(),
                                      cases.data() + cases.size());
}

void CodeGenerator::AssembleArchTableSwitch(Instruction* instr) {
  RiscvOperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  size_t const case_count = instr->InputCount() - 2;

  __ Branch(GetLabel(i.InputRpo(1)), Ugreater_equal, input,
            Operand(case_count));
  __ GenerateSwitchTable(input, case_count, [&i, this](size_t index) {
    return GetLabel(i.InputRpo(index + 2));
  });
}

void CodeGenerator::FinishFrame(Frame* frame) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const DoubleRegList saves_fpu = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fpu.is_empty()) {
    int count = saves_fpu.Count();
    DCHECK_EQ(kNumCalleeSavedFPU, count);
    frame->AllocateSavedCalleeRegisterSlots(count *
                                            (kDoubleSize / kSystemPointerSize));
  }

  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    int count = saves.Count();
    frame->AllocateSavedCalleeRegisterSlots(count);
  }
}

void CodeGenerator::AssembleConstructFrame() {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  if (frame_access_state()->has_frame()) {
    if (call_descriptor->IsCFunctionCall()) {
      if (info()->GetOutputStackFrameType() == StackFrame::C_WASM_ENTRY) {
        __ StubPrologue(StackFrame::C_WASM_ENTRY);
        // Reserve stack space for saving the c_entry_fp later.
        __ SubWord(sp, sp, Operand(kSystemPointerSize));
      } else {
        __ Push(ra, fp);
        __ Move(fp, sp);
      }
    } else if (call_descriptor->IsJSFunctionCall()) {
      __ Prologue();
    } else {
      __ StubPrologue(info()->GetOutputStackFrameType());
      if (call_descriptor->IsWasmFunctionCall() ||
          call_descriptor->IsWasmImportWrapper() ||
          call_descriptor->IsWasmCapiFunction()) {
        __ Push(kWasmImplicitArgRegister);
      }
      if (call_descriptor->IsWasmCapiFunction()) {
        // Reserve space for saving the PC later.
        __ SubWord(sp, sp, Operand(kSystemPointerSize));
      }
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
  const DoubleRegList saves_fpu = call_descriptor->CalleeSavedFPRegisters();

  if (required_slots > 0) {
    DCHECK(frame_access_state()->has_frame());
    if (info()->IsWasm() && required_slots > 128) {
      // For WebAssembly functions with big frames we have to do the stack
      // overflow check before we construct the frame. Otherwise we may not
      // have enough space on the stack to call the runtime for the stack
      // overflow.
      Label done;

      // If the frame is bigger than the stack, we throw the stack overflow
      // exception unconditionally. Thereby we can avoid the integer overflow
      // check in the condition code.
      if ((required_slots * kSystemPointerSize) <
          (v8_flags.stack_size * KB)) {
        UseScratchRegisterScope temps(masm());
        Register stack_limit = temps.Acquire();
        __ LoadStackLimit(stack_limit, StackLimitKind::kRealStackLimit);
        __ AddWord(stack_limit, stack_limit,
                 Operand(required_slots * kSystemPointerSize));
        __ Branch(&done, uge, sp, Operand(stack_limit));
      }

      __ Call(static_cast<intptr_t>(Builtin::kWasmStackOverflow),
              RelocInfo::WASM_STUB_CALL);
      // We come from WebAssembly, there are no references for the GC.
      ReferenceMap* reference_map = zone()->New<ReferenceMap>(zone());
      RecordSafepoint(reference_map);
      if (v8_flags.debug_code) {
        __ stop();
      }

      __ bind(&done);
    }
  }

  const int returns = frame()->GetReturnSlotCount();

  // Skip callee-saved and return slots, which are pushed below.
  required_slots -= saves.Count();
  required_slots -= saves_fpu.Count() * (kDoubleSize / kSystemPointerSize);
  required_slots -= returns;
  if (required_slots > 0) {
    __ SubWord(sp, sp, Operand(required_slots * kSystemPointerSize));
  }

  if (!saves_fpu.is_empty()) {
    // Save callee-saved FPU registers.
    __ MultiPushFPU(saves_fpu);
    DCHECK_EQ(kNumCalleeSavedFPU, saves_fpu.Count());
  }

  if (!saves.is_empty()) {
    // Save callee-saved registers.
    __ MultiPush(saves);
  }

  if (returns != 0) {
    // Create space for returns.
    __ SubWord(sp, sp, Operand(returns * kSystemPointerSize));
  }

  for (int spill_slot : frame()->tagged_slots()) {
    FrameOffset offset = frame_access_state()->GetFrameOffset(spill_slot);
    DCHECK(offset.from_frame_pointer());
    __ StoreWord(zero_reg, MemOperand(fp, offset.offset()));
  }
}

void CodeGenerator::AssembleReturn(InstructionOperand* additional_pop_count) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const int returns = frame()->GetReturnSlotCount();
  if (returns != 0) {
    __ AddWord(sp, sp, Operand(returns * kSystemPointerSize));
  }

  // Restore GP registers.
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    __ MultiPop(saves);
  }

  // Restore FPU registers.
  const DoubleRegList saves_fpu = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fpu.is_empty()) {
    __ MultiPopFPU(saves_fpu);
  }

  RiscvOperandConverter g(this, nullptr);

  const int parameter_slots =
      static_cast<int>(call_descriptor->ParameterSlotCount());

  // {aditional_pop_count} is only greater than zero if {parameter_slots = 0}.
  // Check RawMachineAssembler::PopAndReturn.
  if (parameter_slots != 0) {
    if (additional_pop_count->IsImmediate()) {
      DCHECK_EQ(g.ToConstant(additional_pop_count).ToInt32(), 0);
    } else if (v8_flags.debug_code) {
      __ Assert(eq, AbortReason::kUnexpectedAdditionalPopValue,
                g.ToRegister(additional_pop_count),
                Operand(static_cast<intptr_t>(0)));
    }
  }

  // Functions with JS linkage have at least one parameter (the receiver).
  // If {parameter_slots} == 0, it means it is a builtin with
  // kDontAdaptArgumentsSentinel, which takes care of JS arguments popping
  // itself.
  const bool drop_jsargs = frame_access_state()->has_frame() &&
                           call_descriptor->IsJSFunctionCall() &&
                           parameter_slots != 0;

  if (call_descriptor->IsCFunctionCall()) {
    AssembleDeconstructFrame();
  } else if (frame_access_state()->has_frame()) {
    // Canonicalize JSFunction return sites for now unless they have an variable
    // number of stack slot pops.
    if (additional_pop_count->IsImmediate() &&
        g.ToConstant(additional_pop_count).ToInt32() == 0) {
      if (return_label_.is_bound()) {
        __ Branch(&return_label_);
        return;
      } else {
        __ bind(&return_label_);
      }
    }
    if (drop_jsargs) {
      // Get the actual argument count
      __ LoadWord(t0, MemOperand(fp, StandardFrameConstants::kArgCOffset));
    }
    AssembleDeconstructFrame();
  }
  if (drop_jsargs) {
    // We must pop all arguments from the stack (including the receiver). This
    // number of arguments is given by max(1 + argc_reg, parameter_slots).
    if (parameter_slots > 1) {
      Label done;
      __ li(kScratchReg, parameter_slots);
      __ BranchShort(&done, ge, t0, Operand(kScratchReg));
      __ Move(t0, kScratchReg);
      __ bind(&done);
    }
    __ SllWord(t0, t0, kSystemPointerSizeLog2);
    __ AddWord(sp, sp, t0);
  } else if (additional_pop_count->IsImmediate()) {
    // it should be a kInt32 or a kInt64
    DCHECK_LE(g.ToConstant(additional_pop_count).type(), Constant::kInt64);
    int additional_count = g.ToConstant(additional_pop_count).ToInt32();
    __ Drop(parameter_slots + additional_count);
  } else {
    Register pop_reg = g.ToRegister(additional_pop_count);
    __ Drop(parameter_slots);
    __ SllWord(pop_reg, pop_reg, kSystemPointerSizeLog2);
    __ AddWord(sp, sp, pop_reg);
  }
  __ Ret();
}

void CodeGenerator::FinishCode() { __ ForceConstantPoolEmissionWithoutJump(); }

void CodeGenerator::PrepareForDeoptimizationExits(
    ZoneDeque<DeoptimizationExit*>* exits) {
  __ ForceConstantPoolEmissionWithoutJump();
  int total_size = 0;
  for (DeoptimizationExit* exit : deoptimization_exits_) {
    total_size += (exit->kind() == DeoptimizeKind::kLazy)
                      ? Deoptimizer::kLazyDeoptExitSize
                      : Deoptimizer::kEagerDeoptExitSize;
  }

  __ CheckTrampolinePoolQuick(total_size);
}

void CodeGenerator::MoveToTempLocation(InstructionOperand* source,
                                       MachineRepresentation rep) {
  // Must be kept in sync with {MoveTempLocationTo}.
  DCHECK(!source->IsImmediate());
  move_cycle_.temps.emplace(masm());
  auto& temps = *move_cycle_.temps;
  // Temporarily exclude the reserved scratch registers while we pick one to
  // resolve the move cycle. Re-include them immediately afterwards as they
  // might be needed for the move to the temp location.
  temps.Exclude(move_cycle_.scratch_regs);
  if (!IsFloatingPoint(rep)) {
    if (temps.CanAcquire()) {
      Register scratch = move_cycle_.temps->Acquire();
      move_cycle_.scratch_reg.emplace(scratch);
    }
  }

  temps.Include(move_cycle_.scratch_regs);

  if (move_cycle_.scratch_reg.has_value()) {
    // A scratch register is available for this rep.
    // auto& scratch_reg = *move_cycle_.scratch_reg;
    AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                             move_cycle_.scratch_reg->code());
    AssembleMove(source, &scratch);
  } else {
    // The scratch registers are blocked by pending moves. Use the stack
    // instead.
    Push(source);
  }
}

void CodeGenerator::MoveTempLocationTo(InstructionOperand* dest,
                                       MachineRepresentation rep) {
  if (move_cycle_.scratch_reg.has_value()) {
    // auto& scratch_reg = *move_cycle_.scratch_reg;
    AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                             move_cycle_.scratch_reg->code());
    AssembleMove(&scratch, dest);
  } else {
    Pop(dest, rep);
  }
  // Restore the default state to release the {UseScratchRegisterScope} and to
  // prepare for the next cycle.
  move_cycle_ = MoveCycleState();
}

void CodeGenerator::SetPendingMove(MoveOperands* move) {
  InstructionOperand* src = &move->source();
  InstructionOperand* dst = &move->destination();
  UseScratchRegisterScope temps(masm());
  if (src->IsConstant() && dst->IsFPLocationOperand()) {
    Register temp = temps.Acquire();
    move_cycle_.scratch_regs.set(temp);
  } else if (src->IsAnyStackSlot() || dst->IsAnyStackSlot()) {
    RiscvOperandConverter g(this, nullptr);
    bool src_need_scratch = false;
    bool dst_need_scratch = false;
    if (src->IsAnyStackSlot()) {
      MemOperand src_mem = g.ToMemOperand(src);
      src_need_scratch =
          (!is_int16(src_mem.offset())) || (((src_mem.offset() & 0b111) != 0) &&
                                            !is_int16(src_mem.offset() + 4));
    }
    if (dst->IsAnyStackSlot()) {
      MemOperand dst_mem = g.ToMemOperand(dst);
      dst_need_scratch =
          (!is_int16(dst_mem.offset())) || (((dst_mem.offset() & 0b111) != 0) &&
                                            !is_int16(dst_mem.offset() + 4));
    }
    if (src_need_scratch || dst_need_scratch) {
      Register temp = temps.Acquire();
      move_cycle_.scratch_regs.set(temp);
    }
  }
}

void CodeGenerator::AssembleMove(InstructionOperand* source,
                                 InstructionOperand* destination) {
  RiscvOperandConverter g(this, nullptr);
  // Dispatch on the source and destination operand kinds.  Not all
  // combinations are possible.
  if (source->IsRegister()) {
    DCHECK(destination->IsRegister() || destination->IsStackSlot());
    Register src = g.ToRegister(source);
    if (destination->IsRegister()) {
      __ Move(g.ToRegister(destination), src);
    } else {
      __ StoreWord(src, g.ToMemOperand(destination));
    }
  } else if (source->IsStackSlot()) {
    DCHECK(destination->IsRegister() || destination->IsStackSlot());
    MemOperand src = g.ToMemOperand(source);
    if (destination->IsRegister()) {
      __ LoadWord(g.ToRegister(destination), src);
    } else {
      Register temp = kScratchReg;
      __ LoadWord(temp, src);
      __ StoreWord(temp, g.ToMemOperand(destination));
    }
  } else if (source->IsConstant()) {
    Constant src = g.ToConstant(source);
    if (destination->IsRegister() || destination->IsStackSlot()) {
      Register dst =
          destination->IsRegister() ? g.ToRegister(destination) : kScratchReg;
      switch (src.type()) {
        case Constant::kInt32:
          if (src.ToInt32() == 0 && destination->IsStackSlot() &&
              RelocInfo::IsNoInfo(src.rmode())) {
            dst = zero_reg;
          } else {
            __ li(dst, Operand(src.ToInt32(), src.rmode()));
          }
          break;
        case Constant::kFloat32:
          __ li(dst, Operand::EmbeddedNumber(src.ToFloat32()));
          break;
        case Constant::kInt64:
          if (src.ToInt64() == 0 && destination->IsStackSlot() &&
              RelocInfo::IsNoInfo(src.rmode())) {
            dst = zero_reg;
          } else {
            __ li(dst, Operand(src.ToInt64(), src.rmode()));
          }
          break;
        case Constant::kFloat64:
          __ li(dst, Operand::EmbeddedNumber(src.ToFloat64().value()));
          break;
        case Constant::kExternalReference:
          __ li(dst, src.ToExternalReference());
          break;
        case Constant::kHeapObject: {
          Handle<HeapObject> src_object = src.ToHeapObject();
          RootIndex index;
          if (IsMaterializableFromRoot(src_object, &index)) {
            __ LoadRoot(dst, index);
          } else {
            __ li(dst, src_object);
          }
          break;
        }
        case Constant::kCompressedHeapObject: {
          Handle<HeapObject> src_object = src.ToHeapObject();
          RootIndex index;
          if (IsMaterializableFromRoot(src_object, &index)) {
            __ LoadCompressedTaggedRoot(dst, index);
          } else {
            __ li(dst, src_object, RelocInfo::COMPRESSED_EMBEDDED_OBJECT);
          }
          break;
        }
        case Constant::kRpoNumber:
          UNREACHABLE();  // TODO(titzer): loading RPO numbers
      }
      if (destination->IsStackSlot()) {
        __ StoreWord(dst, g.ToMemOperand(destination));
      }
    } else if (src.type() == Constant::kFloat32) {
      if (destination->IsFPStackSlot()) {
        MemOperand dst = g.ToMemOperand(destination);
        if (base::bit_cast<int32_t>(src.ToFloat32()) == 0) {
          __ Sw(zero_reg, dst);
        } else {
          __ li(kScratchReg, Operand(base::bit_cast<int32_t>(src.ToFloat32())));
          __ Sw(kScratchReg, dst);
        }
      } else {
        DCHECK(destination->IsFPRegister());
        FloatRegister dst = g.ToSingleRegister(destination);
        __ LoadFPRImmediate(dst, src.ToFloat32());
      }
    } else {
      DCHECK_EQ(Constant::kFloat64, src.type());
      DoubleRegister dst = destination->IsFPRegister()
                               ? g.ToDoubleRegister(destination)
                               : kScratchDoubleReg;
      __ LoadFPRImmediate(dst, src.ToFloat64().value());
      if (destination->IsFPStackSlot()) {
        __ StoreDouble(dst, g.ToMemOperand(destination));
      }
    }
  } else if (source->IsFPRegister()) {
    MachineRepresentation rep = LocationOperand::cast(source)->representation();
    if (rep == MachineRepresentation::kSimd128) {
      VRegister src = g.ToSimd128Register(source);
      if (destination->IsSimd128Register()) {
        VRegister dst = g.ToSimd128Register(destination);
        __ VU.set(kScratchReg, E8, m1);
        __ vmv_vv(dst, src);
      } else {
        DCHECK(destination->IsSimd128StackSlot());
        __ VU.set(kScratchReg, E8, m1);
        MemOperand dst = g.ToMemOperand(destination);
        Register dst_r = dst.rm();
        if (dst.offset() != 0) {
          dst_r = kScratchReg;
          __ AddWord(dst_r, dst.rm(), dst.offset());
        }
        __ vs(src, dst_r, 0, E8);
      }
    } else {
      FPURegister src = g.ToDoubleRegister(source);
      if (destination->IsFPRegister()) {
        FPURegister dst = g.ToDoubleRegister(destination);
        if (rep == MachineRepresentation::kFloat32) {
          // In src/builtins/wasm-to-js.tq:193
          //*toRef =
          //Convert<intptr>(Bitcast<uint32>(WasmTaggedToFloat32(retVal))); so
          // high 32 of src is 0. fmv.s can't NaNBox src.
          __ fmv_x_w(kScratchReg, src);
          __ fmv_w_x(dst, kScratchReg);
        } else {
          __ MoveDouble(dst, src);
        }
      } else {
        DCHECK(destination->IsFPStackSlot());
        if (rep == MachineRepresentation::kFloat32) {
          __ StoreFloat(src, g.ToMemOperand(destination));
        } else {
          DCHECK_EQ(rep, MachineRepresentation::kFloat64);
          __ StoreDouble(src, g.ToMemOperand(destination));
        }
      }
    }
  } else if (source->IsFPStackSlot()) {
    DCHECK(destination->IsFPRegister() || destination->IsFPStackSlot());
    MemOperand src = g.ToMemOperand(source);
    MachineRepresentation rep = LocationOperand::cast(source)->representation();
    if (rep == MachineRepresentation::kSimd128) {
      __ VU.set(kScratchReg, E8, m1);
      Register src_r = src.rm();
      if (src.offset() != 0) {
        src_r = kScratchReg;
        __ AddWord(src_r, src.rm(), src.offset());
      }
      if (destination->IsSimd128Register()) {
        __ vl(g.ToSimd128Register(destination), src_r, 0, E8);
      } else {
        DCHECK(destination->IsSimd128StackSlot());
        VRegister temp = kSimd128ScratchReg;
        MemOperand dst = g.ToMemOperand(destination);
        Register dst_r = dst.rm();
        if (dst.offset() != 0) {
          dst_r = kScratchReg2;
          __ AddWord(dst_r, dst.rm(), dst.offset());
        }
        __ vl(temp, src_r, 0, E8);
        __ vs(temp, dst_r, 0, E8);
      }
    } else {
      if (destination->IsFPRegister()) {
        if (rep == MachineRepresentation::kFloat32) {
          __ LoadFloat(g.ToDoubleRegister(destination), src);
        } else {
          DCHECK_EQ(rep, MachineRepresentation::kFloat64);
          __ LoadDouble(g.ToDoubleRegister(destination), src);
        }
      } else {
        DCHECK(destination->IsFPStackSlot());
        FPURegister temp = kScratchDoubleReg;
        if (rep == MachineRepresentation::kFloat32) {
          __ LoadFloat(temp, src);
          __ StoreFloat(temp, g.ToMemOperand(destination));
        } else {
          DCHECK_EQ(rep, MachineRepresentation::kFloat64);
          __ LoadDouble(temp, src);
          __ StoreDouble(temp, g.ToMemOperand(destination));
        }
      }
    }
  } else {
    UNREACHABLE();
  }
}

void CodeGenerator::AssembleSwap(InstructionOperand* source,
                                 InstructionOperand* destination) {
  RiscvOperandConverter g(this, nullptr);
  switch (MoveType::InferSwap(source, destination)) {
    case MoveType::kRegisterToRegister:
      if (source->IsRegister()) {
        Register temp = kScratchReg;
        Register src = g.ToRegister(source);
        Register dst = g.ToRegister(destination);
        __ Move(temp, src);
        __ Move(src, dst);
        __ Move(dst, temp);
      } else {
        if (source->IsFloatRegister() || source->IsDoubleRegister()) {
          FPURegister temp = kScratchDoubleReg;
          FPURegister src = g.ToDoubleRegister(source);
          FPURegister dst = g.ToDoubleRegister(destination);
          __ Move(temp, src);
          __ Move(src, dst);
          __ Move(dst, temp);
        } else {
          DCHECK(source->IsSimd128Register());
          VRegister src = g.ToDoubleRegister(source).toV();
          VRegister dst = g.ToDoubleRegister(destination).toV();
          VRegister temp = kSimd128ScratchReg;
          __ VU.set(kScratchReg, E8, m1);
          __ vmv_vv(temp, src);
          __ vmv_vv(src, dst);
          __ vmv_vv(dst, temp);
        }
      }
      break;
    case MoveType::kRegisterToStack: {
      MemOperand dst = g.ToMemOperand(destination);
      if (source->IsRegister()) {
        Register temp = kScratchReg;
        Register src = g.ToRegister(source);
        __ mv(temp, src);
        __ LoadWord(src, dst);
        __ StoreWord(temp, dst);
      } else {
        MemOperand dst = g.ToMemOperand(destination);
        if (source->IsFloatRegister()) {
          DoubleRegister src = g.ToDoubleRegister(source);
          DoubleRegister temp = kScratchDoubleReg;
          __ fmv_s(temp, src);
          __ LoadFloat(src, dst);
          __ StoreFloat(temp, dst);
        } else if (source->IsDoubleRegister()) {
          DoubleRegister src = g.ToDoubleRegister(source);
          DoubleRegister temp = kScratchDoubleReg;
          __ fmv_d(temp, src);
          __ LoadDouble(src, dst);
          __ StoreDouble(temp, dst);
        } else {
          DCHECK(source->IsSimd128Register());
          VRegister src = g.ToDoubleRegister(source).toV();
          VRegister temp = kSimd128ScratchReg;
          __ VU.set(kScratchReg, E8, m1);
          __ vmv_vv(temp, src);
          Register dst_v = dst.rm();
          if (dst.offset() != 0) {
            dst_v = kScratchReg2;
            __ AddWord(dst_v, dst.rm(), Operand(dst.offset()));
          }
          __ vl(src, dst_v, 0, E8);
          __ vs(temp, dst_v, 0, E8);
        }
      }
    } break;
    case MoveType::kStackToStack: {
      MemOperand src = g.ToMemOperand(source);
      MemOperand dst = g.ToMemOperand(destination);
      if (source->IsSimd128StackSlot()) {
        __ VU.set(kScratchReg, E8, m1);
        Register src_v = src.rm();
        Register dst_v = dst.rm();
        if (src.offset() != 0) {
          src_v = kScratchReg;
          __ AddWord(src_v, src.rm(), Operand(src.offset()));
        }
        if (dst.offset() != 0) {
          dst_v = kScratchReg2;
          __ AddWord(dst_v, dst.rm(), Operand(dst.offset()));
        }
        __ vl(kSimd128ScratchReg, src_v, 0, E8);
        __ vl(kSimd128ScratchReg2, dst_v, 0, E8);
        __ vs(kSimd128ScratchReg, dst_v, 0, E8);
        __ vs(kSimd128ScratchReg2, src_v, 0, E8);
      } else {
#if V8_TARGET_ARCH_RISCV32
        if (source->IsFPStackSlot()) {
          DCHECK(destination->IsFPStackSlot());
          MachineRepresentation rep =
              LocationOperand::cast(source)->representation();
          if (rep == MachineRepresentation::kFloat64) {
            FPURegister temp_double = kScratchDoubleReg;
            Register temp_word32 = kScratchReg;
            MemOperand src_hi(src.rm(), src.offset() + kSystemPointerSize);
            MemOperand dst_hi(dst.rm(), dst.offset() + kSystemPointerSize);
            __ LoadDouble(temp_double, src);
            __ Lw(temp_word32, dst);
            __ Sw(temp_word32, src);
            __ Lw(temp_word32, dst_hi);
            __ Sw(temp_word32, src_hi);
            __ StoreDouble(temp_double, dst);
            break;
          }
        }
#endif
        UseScratchRegisterScope scope(masm());
        Register temp_0 = kScratchReg;
        Register temp_1 = kScratchReg2;
        __ LoadWord(temp_0, src);
        __ LoadWord(temp_1, dst);
        __ StoreWord(temp_0, dst);
        __ StoreWord(temp_1, src);
      }
    } break;
    default:
      UNREACHABLE();
  }
}

AllocatedOperand CodeGenerator::Push(InstructionOperand* source) {
  auto rep = LocationOperand::cast(source)->representation();
  int new_slots = ElementSizeInPointers(rep);
  RiscvOperandConverter g(this, nullptr);
  int last_frame_slot_id =
      frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
  int sp_delta = frame_access_state_->sp_delta();
  int slot_id = last_frame_slot_id + sp_delta + new_slots;
  AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
  if (source->IsRegister()) {
    __ Push(g.ToRegister(source));
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else if (source->IsStackSlot()) {
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    __ LoadWord(scratch, g.ToMemOperand(source));
    __ Push(scratch);
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else {
    // No push instruction for this operand type. Bump the stack pointer and
    // assemble the move.
    __ SubWord(sp, sp, Operand(new_slots * kSystemPointerSize));
    frame_access_state()->IncreaseSPDelta(new_slots);
    AssembleMove(source, &stack_slot);
  }
  temp_slots_ += new_slots;
  return stack_slot;
}

void CodeGenerator::Pop(InstructionOperand* dest, MachineRepresentation rep) {
  int dropped_slots = ElementSizeInPointers(rep);
  RiscvOperandConverter g(this, nullptr);
  if (dest->IsRegister()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ Pop(g.ToRegister(dest));
  } else if (dest->IsStackSlot()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    __ Pop(scratch);
    __ StoreWord(scratch, g.ToMemOperand(dest));
  } else {
    int last_frame_slot_id =
        frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
    int sp_delta = frame_access_state_->sp_delta();
    int slot_id = last_frame_slot_id + sp_delta;
    AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
    AssembleMove(&stack_slot, dest);
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ AddWord(sp, sp, Operand(dropped_slots * kSystemPointerSize));
  }
  temp_slots_ -= dropped_slots;
}

void CodeGenerator::PopTempStackSlots() {
  if (temp_slots_ > 0) {
    frame_access_state()->IncreaseSPDelta(-temp_slots_);
    __ AddWord(sp, sp, Operand(temp_slots_ * kSystemPointerSize));
    temp_slots_ = 0;
  }
}

void CodeGenerator::AssembleJumpTable(base::Vector<Label*> targets) {
  // On 64-bit RISC-V we emit the jump tables inline.
  UNREACHABLE();
}

#undef ASSEMBLE_ATOMIC_LOAD_INTEGER
#undef ASSEMBLE_ATOMIC_STORE_INTEGER
#undef ASSEMBLE_ATOMIC_BINOP
#undef ASSEMBLE_ATOMIC_BINOP_EXT
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT
#undef ASSEMBLE_IEEE754_BINOP
#undef ASSEMBLE_IEEE754_UNOP

#undef TRACE
#undef __

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```