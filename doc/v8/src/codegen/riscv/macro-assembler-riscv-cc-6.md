Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/riscv/macro-assembler-riscv.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The filename suggests it's part of the RISC-V backend for V8's macro assembler. Macro assemblers provide an abstraction layer over raw assembly instructions.

2. **Analyze Included Functions:** Examine the functions defined in the snippet. Look for patterns and common themes. Keywords like `Wasm`, `Load`, `Store`, `Overflow`, `Runtime`, `Call`, `Debug`, `Assert`, `Compare`, `Map`, `Frame`, `Smi` are strong indicators of the functionalities being implemented.

3. **Group Functionalities:** Categorize the functions based on their apparent purpose. For example, functions related to WebAssembly can be grouped, as can those handling arithmetic operations with overflow checks, runtime calls, debugging aids, and stack frame manipulation.

4. **Check for `.tq` Relevance:**  The prompt asks if the file could be a Torque file if it ended in `.tq`. This is not the case here.

5. **JavaScript Relationship:** Determine if any of the functionalities directly relate to JavaScript concepts. Runtime calls, object property access (implied by `LoadMap`), and type checking are all used in the execution of JavaScript code.

6. **Provide JavaScript Examples:**  If a connection to JavaScript exists, create simple examples demonstrating the underlying concept.

7. **Infer Code Logic and Provide Examples:**  For functions with clear logic (like overflow checks), create hypothetical inputs and outputs to illustrate their behavior.

8. **Identify Common Programming Errors:** Based on the functionalities, point out potential user programming errors that these functions might help to catch or handle.

9. **Consider the "Part 7 of 9" Context:**  This suggests that this file handles a specific subset of the macro assembler's functionality. The summary should reflect this specialization.

10. **Structure the Output:** Organize the findings into a clear and readable format, addressing each point in the prompt.

**Pre-computation/Analysis of the Code Snippet:**

* **WebAssembly Support:** Functions like `WasmRvvS128const`, `LoadLane`, and `StoreLane` clearly deal with WebAssembly vector operations.
* **Overflow Handling:** `AddOverflow`, `SubOverflow`, `MulOverflow` functions implement arithmetic operations with overflow detection. These exist for both 32-bit and 64-bit architectures.
* **Runtime Calls:** `CallRuntime` and `TailCallRuntime` are used to invoke V8's runtime functions.
* **External References:** `JumpToExternalReference` allows jumping to externally defined functions.
* **Weak References:** `LoadWeakValue` handles loading values from weak references.
* **Counters:** `EmitIncrementCounter` and `EmitDecrementCounter` update performance counters.
* **Debugging and Assertions:** `Trap`, `DebugBreak`, `Assert`, `Check` are debugging aids.
* **Object Type Handling:** `CompareObjectTypeAndJump`, `LoadMap`, `LoadCompressedMap` deal with inspecting object types.
* **Optimized Code Loading:** `TryLoadOptimizedOsrCode` attempts to load and execute optimized code.
* **Stack Frame Management:** Functions like `StubPrologue`, `Prologue`, `EnterFrame`, `LeaveFrame`, `EnterExitFrame`, `LeaveExitFrame` manage stack frames.
* **Smi Handling:** `SmiUntag`, `SmiToInt32`, `JumpIfSmi`, `JumpIfNotSmi` deal with Small Integers (Smis).

By following these steps, a comprehensive summary addressing all the points in the prompt can be generated.
这是 `v8/src/codegen/riscv/macro-assembler-riscv.cc` 源代码的第七部分，它主要负责实现 RISC-V 架构下的宏汇编器功能。宏汇编器提供了一层抽象，允许开发者使用更高级的指令和模式，而无需直接编写原始的汇编代码。这一部分的功能集中在以下几个方面：

**功能归纳:**

1. **WebAssembly (Wasm) 支持 (RVV 部分):**  提供加载和存储 WebAssembly SIMD (Single Instruction, Multiple Data) 向量常量的功能，特别使用了 RISC-V Vector Extension (RVV) 指令。例如，`WasmRvvS128const` 可以将 128 位常量加载到向量寄存器中。

2. **向量通道 (Lane) 操作:**  实现了从内存加载单个向量通道 (`LoadLane`) 和将单个向量通道存储到内存 (`StoreLane`) 的功能。这允许对向量中的特定元素进行读写。

3. **带溢出检查的算术运算:** 提供了 `AddOverflow`, `SubOverflow`, `MulOverflow` 等函数，用于执行加法、减法和乘法运算，并检测是否发生溢出。这些函数会设置一个单独的寄存器来指示溢出状态。

4. **运行时调用:**  包含 `CallRuntime` 和 `TailCallRuntime` 函数，用于调用 V8 的运行时函数。这些函数通常用于执行一些需要 V8 虚拟机支持的操作，例如对象分配或类型转换。

5. **跳转到外部引用:**  `JumpToExternalReference` 函数允许代码跳转到外部定义的函数或数据地址。

6. **弱引用处理:**  `LoadWeakValue` 函数用于加载弱引用的值。如果弱引用已被清除，则会跳转到指定的目标标签。

7. **性能计数器操作:** `EmitIncrementCounter` 和 `EmitDecrementCounter` 函数用于增加或减少性能计数器的值。

8. **调试和断言:** 提供了 `Trap`, `DebugBreak`, `Assert`, `Check` 等函数，用于在开发和调试过程中插入断点和断言检查。

9. **对象类型比较和跳转:**  `CompareObjectTypeAndJump` 函数用于比较对象的类型，并根据比较结果跳转到不同的代码段。

10. **加载 Map:** `LoadMap` 和 `LoadCompressedMap` 用于加载对象的 Map (元数据)，它描述了对象的结构和类型。

11. **加载 Native Context Slot:** `LoadNativeContextSlot` 用于加载 Native Context 中的特定槽位。

12. **尝试加载优化后的代码:** `TryLoadOptimizedOsrCode` 函数用于尝试加载和执行优化后的代码，这通常发生在 On-Stack Replacement (OSR) 过程中。

13. **栈帧管理:**  提供了 `StubPrologue`, `Prologue`, `EnterFrame`, `LeaveFrame`, `EnterExitFrame`, `LeaveExitFrame` 等函数，用于管理函数调用时的栈帧结构。

14. **Smi (Small Integer) 处理:** 包含 `SmiUntag`, `SmiToInt32`, `JumpIfSmi`, `JumpIfNotSmi` 等函数，用于处理 V8 中的小整数类型。

**关于 .tq 结尾：**

你说的对，如果 `v8/src/codegen/riscv/macro-assembler-riscv.cc` 以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码**。Torque 是一种用于 V8 的类型化中间表示和代码生成器，它允许以更安全和可维护的方式定义内置函数和运行时代码。然而，当前的 `.cc` 结尾表明它是一个标准的 C++ 源代码文件。

**与 JavaScript 的关系和示例:**

这一部分的代码与 JavaScript 的执行密切相关。宏汇编器生成的代码最终会执行 JavaScript 代码。以下是一些功能的 JavaScript 示例：

1. **带溢出检查的算术运算:**  虽然 JavaScript 本身不直接暴露溢出标志，但在执行诸如大整数运算时，V8 内部可能会使用这些带溢出检查的指令。
   ```javascript
   // 内部执行可能会涉及到溢出检查
   let a = 2147483647;
   let b = 1;
   let sum = a + b; // JavaScript 会得到 -2147483648 (溢出回绕)
   ```

2. **运行时调用:** 当 JavaScript 代码执行需要 V8 虚拟机支持的操作时，会调用运行时函数。
   ```javascript
   let obj = {}; // 对象分配，内部会调用 V8 的对象分配运行时函数
   console.log("Hello"); // 控制台输出，内部会调用 V8 的打印运行时函数
   ```

3. **对象类型比较:** JavaScript 中经常进行类型检查。
   ```javascript
   function isNumber(x) {
     return typeof x === 'number';
   }
   isNumber(10); // 内部会进行对象类型比较
   ```

4. **Smi 处理:**  V8 内部会将小的整数表示为 Smis，以提高性能。
   ```javascript
   let smallInt = 5; // 内部可能表示为 Smi
   ```

**代码逻辑推理和示例:**

**假设输入与输出 (以 `AddOverflow64` 为例):**

* **假设输入:**
    * `dst`: 目标寄存器 (例如 `a0`)
    * `left`: 左操作数寄存器 (例如 `a1`)，值为 0xFFFFFFFFFFFFFFFF (最大的 64 位无符号整数)
    * `right`: 右操作数，可以是寄存器或立即数，假设是寄存器 `a2`，值为 1
    * `overflow`: 溢出标志寄存器 (例如 `a3`)

* **代码逻辑 (简化):**
    1. 将 `left` 和 `right` 的值相加，结果放入一个临时寄存器。
    2. 比较临时结果与 `left` 或 `right`，通过异或和与操作来判断是否发生溢出。
    3. 将最终结果移动到 `dst` 寄存器。
    4. 将溢出标志设置到 `overflow` 寄存器 (非零表示溢出)。

* **输出:**
    * `dst` 寄存器 (`a0`) 的值将会是 0x0000000000000000 (由于溢出回绕)。
    * `overflow` 寄存器 (`a3`) 的值将会是非零，表示发生了溢出。

**用户常见的编程错误:**

1. **整数溢出:**  在 C++ 或其他语言中进行算术运算时，如果结果超出了数据类型的表示范围，就会发生溢出。V8 的 `AddOverflow` 等函数可以帮助检测这类错误。
   ```c++
   int maxInt = 2147483647;
   int result = maxInt + 1; // 溢出，result 的值将是负数
   ```

2. **类型假设错误:**  在 JavaScript 中，开发者可能错误地假设变量的类型，导致在 V8 内部进行对象类型比较时出现意外行为。
   ```javascript
   function process(input) {
     if (typeof input === 'number') {
       // ... 假设 input 一定是 Number 类型
     }
   }
   process(new Number(5)); // 这里的 input 是 Object 类型，而不是原始 number
   ```

**总结:**

`v8/src/codegen/riscv/macro-assembler-riscv.cc` 的第七部分是 RISC-V 宏汇编器的核心组成部分，它提供了用于 WebAssembly 支持、向量操作、带溢出检查的算术运算、运行时调用、调试、对象类型处理和栈帧管理等关键功能。这些功能是 V8 引擎在 RISC-V 架构上执行 JavaScript 和 WebAssembly 代码的基础。虽然 JavaScript 开发者通常不直接接触这些底层代码，但理解其功能有助于理解 JavaScript 引擎的内部工作原理以及可能出现的性能瓶颈和错误类型。

### 提示词
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/macro-assembler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
eg, 1);
  li(kScratchReg, vals[0]);
  vmv_sx(dst, kScratchReg);
}
#elif V8_TARGET_ARCH_RISCV32
void MacroAssembler::WasmRvvS128const(VRegister dst, const uint8_t imms[16]) {
  uint32_t vals[4];
  memcpy(vals, imms, sizeof(vals));
  VU.set(kScratchReg, VSew::E32, Vlmul::m1);
  li(kScratchReg, vals[3]);
  vmv_vx(kSimd128ScratchReg, kScratchReg);
  li(kScratchReg, vals[2]);
  vmv_sx(kSimd128ScratchReg, kScratchReg);
  li(kScratchReg, vals[1]);
  vmv_vx(dst, kScratchReg);
  li(kScratchReg, vals[0]);
  vmv_sx(dst, kScratchReg);
  vslideup_vi(dst, kSimd128ScratchReg, 2);
}
#endif

void MacroAssembler::LoadLane(int ts, VRegister dst, uint8_t laneidx,
                              MemOperand src, Trapper&& trapper) {
  DCHECK_NE(kScratchReg, src.rm());
  if (ts == 8) {
    Lbu(kScratchReg2, src, std::forward<Trapper>(trapper));
    VU.set(kScratchReg, E32, m1);
    li(kScratchReg, 0x1 << laneidx);
    vmv_sx(v0, kScratchReg);
    VU.set(kScratchReg, E8, m1);
    vmerge_vx(dst, kScratchReg2, dst);
  } else if (ts == 16) {
    Lhu(kScratchReg2, src, std::forward<Trapper>(trapper));
    VU.set(kScratchReg, E16, m1);
    li(kScratchReg, 0x1 << laneidx);
    vmv_sx(v0, kScratchReg);
    vmerge_vx(dst, kScratchReg2, dst);
  } else if (ts == 32) {
    Load32U(kScratchReg2, src, std::forward<Trapper>(trapper));
    VU.set(kScratchReg, E32, m1);
    li(kScratchReg, 0x1 << laneidx);
    vmv_sx(v0, kScratchReg);
    vmerge_vx(dst, kScratchReg2, dst);
  } else if (ts == 64) {
#if V8_TARGET_ARCH_RISCV64
    LoadWord(kScratchReg2, src, std::forward<Trapper>(trapper));
    VU.set(kScratchReg, E64, m1);
    li(kScratchReg, 0x1 << laneidx);
    vmv_sx(v0, kScratchReg);
    vmerge_vx(dst, kScratchReg2, dst);
#elif V8_TARGET_ARCH_RISCV32
    LoadDouble(kScratchDoubleReg, src, std::forward<Trapper>(trapper));
    VU.set(kScratchReg, E64, m1);
    li(kScratchReg, 0x1 << laneidx);
    vmv_sx(v0, kScratchReg);
    vfmerge_vf(dst, kScratchDoubleReg, dst);
#endif
  } else {
    UNREACHABLE();
  }
}

void MacroAssembler::StoreLane(int sz, VRegister src, uint8_t laneidx,
                               MemOperand dst, Trapper&& trapper) {
  DCHECK_NE(kScratchReg, dst.rm());
  if (sz == 8) {
    VU.set(kScratchReg, E8, m1);
    vslidedown_vi(kSimd128ScratchReg, src, laneidx);
    vmv_xs(kScratchReg, kSimd128ScratchReg);
    Sb(kScratchReg, dst, std::forward<Trapper>(trapper));
  } else if (sz == 16) {
    VU.set(kScratchReg, E16, m1);
    vslidedown_vi(kSimd128ScratchReg, src, laneidx);
    vmv_xs(kScratchReg, kSimd128ScratchReg);
    Sh(kScratchReg, dst, std::forward<Trapper>(trapper));
  } else if (sz == 32) {
    VU.set(kScratchReg, E32, m1);
    vslidedown_vi(kSimd128ScratchReg, src, laneidx);
    vmv_xs(kScratchReg, kSimd128ScratchReg);
    Sw(kScratchReg, dst, std::forward<Trapper>(trapper));
  } else {
    DCHECK_EQ(sz, 64);
    VU.set(kScratchReg, E64, m1);
    vslidedown_vi(kSimd128ScratchReg, src, laneidx);
#if V8_TARGET_ARCH_RISCV64
    vmv_xs(kScratchReg, kSimd128ScratchReg);
    StoreWord(kScratchReg, dst, std::forward<Trapper>(trapper));
#elif V8_TARGET_ARCH_RISCV32
    vfmv_fs(kScratchDoubleReg, kSimd128ScratchReg);
    StoreDouble(kScratchDoubleReg, dst, std::forward<Trapper>(trapper));
#endif
  }
}
// -----------------------------------------------------------------------------
// Runtime calls.
#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::AddOverflow64(Register dst, Register left,
                                   const Operand& right, Register overflow) {
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }
  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);
  if (dst == left || dst == right_reg) {
    add(scratch2, left, right_reg);
    xor_(overflow, scratch2, left);
    xor_(scratch, scratch2, right_reg);
    and_(overflow, overflow, scratch);
    Mv(dst, scratch2);
  } else {
    add(dst, left, right_reg);
    xor_(overflow, dst, left);
    xor_(scratch, dst, right_reg);
    and_(overflow, overflow, scratch);
  }
}

void MacroAssembler::SubOverflow64(Register dst, Register left,
                                   const Operand& right, Register overflow) {
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    sub(scratch2, left, right_reg);
    xor_(overflow, left, scratch2);
    xor_(scratch, left, right_reg);
    and_(overflow, overflow, scratch);
    Mv(dst, scratch2);
  } else {
    sub(dst, left, right_reg);
    xor_(overflow, left, dst);
    xor_(scratch, left, right_reg);
    and_(overflow, overflow, scratch);
  }
}

void MacroAssembler::MulOverflow32(Register dst, Register left,
                                   const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);
  sext_w(overflow, left);
  sext_w(scratch2, right_reg);

  mul(overflow, overflow, scratch2);
  sext_w(dst, overflow);
  xor_(overflow, overflow, dst);
}

void MacroAssembler::MulOverflow64(Register dst, Register left,
                                   const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);
  // use this sequence of "mulh/mul" according to recommendation of ISA Spec 7.1
  // upper part
  mulh(scratch2, left, right_reg);
  // lower part
  mul(dst, left, right_reg);
  // expand the sign of the lower part to 64bit
  srai(overflow, dst, 63);
  // if the upper part is not eqaul to the expanded sign bit of the lower part,
  // overflow happens
  xor_(overflow, overflow, scratch2);
}

#elif V8_TARGET_ARCH_RISCV32
void MacroAssembler::AddOverflow(Register dst, Register left,
                                 const Operand& right, Register overflow) {
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }
  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);
  if (dst == left || dst == right_reg) {
    add(scratch2, left, right_reg);
    xor_(overflow, scratch2, left);
    xor_(scratch, scratch2, right_reg);
    and_(overflow, overflow, scratch);
    Mv(dst, scratch2);
  } else {
    add(dst, left, right_reg);
    xor_(overflow, dst, left);
    xor_(scratch, dst, right_reg);
    and_(overflow, overflow, scratch);
  }
}

void MacroAssembler::SubOverflow(Register dst, Register left,
                                 const Operand& right, Register overflow) {
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);

  if (dst == left || dst == right_reg) {
    sub(scratch2, left, right_reg);
    xor_(overflow, left, scratch2);
    xor_(scratch, left, right_reg);
    and_(overflow, overflow, scratch);
    Mv(dst, scratch2);
  } else {
    sub(dst, left, right_reg);
    xor_(overflow, left, dst);
    xor_(scratch, left, right_reg);
    and_(overflow, overflow, scratch);
  }
}

void MacroAssembler::MulOverflow32(Register dst, Register left,
                                   const Operand& right, Register overflow) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register right_reg = no_reg;
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  if (!right.is_reg()) {
    li(scratch, Operand(right));
    right_reg = scratch;
  } else {
    right_reg = right.rm();
  }

  DCHECK(left != scratch2 && right_reg != scratch2 && dst != scratch2 &&
         overflow != scratch2);
  DCHECK(overflow != left && overflow != right_reg);
  mulh(overflow, left, right_reg);
  mul(dst, left, right_reg);
  srai(scratch2, dst, 31);
  xor_(overflow, overflow, scratch2);
}
#endif

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  ASM_CODE_COMMENT(this);
  // All parameters are on the stack. a0 has the return value after call.

  // If the expected number of arguments of the runtime function is
  // constant, we check that the actual number of arguments match the
  // expectation.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // TODO(1236192): Most runtime routines don't need the number of
  // arguments passed in because it is constant. At some point we
  // should remove this need and make the runtime routine entry code
  // smarter.
  PrepareCEntryArgs(num_arguments);
  PrepareCEntryFunction(ExternalReference::Create(f));
#if V8_TARGET_ARCH_RISCV64
  bool switch_to_central = options().is_wasm;
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size, switch_to_central));
#else
  CallBuiltin(Builtins::RuntimeCEntry(1));
#endif
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  ASM_CODE_COMMENT(this);
  const Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    PrepareCEntryArgs(function->nargs);
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& builtin,
                                             bool builtin_exit_frame) {
  ASM_CODE_COMMENT(this);
  PrepareCEntryFunction(builtin);
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

void MacroAssembler::LoadWeakValue(Register out, Register in,
                                   Label* target_if_cleared) {
  ASM_CODE_COMMENT(this);
  CompareTaggedAndBranch(target_if_cleared, eq, in,
                         Operand(kClearedWeakHeapObjectLower32));
  And(out, in, Operand(~kWeakHeapObjectMask));
}

void MacroAssembler::EmitIncrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t
    // dummy_stats_counter_ field.
    li(scratch2, ExternalReference::Create(counter));
    Lw(scratch1, MemOperand(scratch2));
    Add32(scratch1, scratch1, Operand(value));
    Sw(scratch1, MemOperand(scratch2));
  }
}

void MacroAssembler::EmitDecrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    ASM_CODE_COMMENT(this);
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t
    // dummy_stats_counter_ field.
    li(scratch2, ExternalReference::Create(counter));
    Lw(scratch1, MemOperand(scratch2));
    Sub32(scratch1, scratch1, Operand(value));
    Sw(scratch1, MemOperand(scratch2));
  }
}

// -----------------------------------------------------------------------------
// Debugging.

void MacroAssembler::Trap() { stop(); }
void MacroAssembler::DebugBreak() { stop(); }

void MacroAssembler::Assert(Condition cc, AbortReason reason, Register rs,
                            Operand rt) {
  if (v8_flags.debug_code) Check(cc, reason, rs, rt);
}

void MacroAssembler::AssertJSAny(Register object, Register map_tmp,
                                 Register tmp, AbortReason abort_reason) {
  if (!v8_flags.debug_code) return;

  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, map_tmp, tmp));
  Label ok;

  JumpIfSmi(object, &ok);

  GetObjectType(object, map_tmp, tmp);

  Branch(&ok, kUnsignedLessThanEqual, tmp, Operand(LAST_NAME_TYPE));

  Branch(&ok, kUnsignedGreaterThanEqual, tmp, Operand(FIRST_JS_RECEIVER_TYPE));

  Branch(&ok, kEqual, map_tmp, RootIndex::kHeapNumberMap);

  Branch(&ok, kEqual, map_tmp, RootIndex::kBigIntMap);

  Branch(&ok, kEqual, object, RootIndex::kUndefinedValue);

  Branch(&ok, kEqual, object, RootIndex::kTrueValue);

  Branch(&ok, kEqual, object, RootIndex::kFalseValue);

  Branch(&ok, kEqual, object, RootIndex::kNullValue);

  Abort(abort_reason);
  bind(&ok);
}

#ifdef V8_ENABLE_DEBUG_CODE

void MacroAssembler::AssertZeroExtended(Register int32_register) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Assert(Condition::ule, AbortReason::k32BitValueInRegisterIsNotZeroExtended,
         int32_register, Operand(kMaxUInt32));
}

#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::Check(Condition cc, AbortReason reason, Register rs,
                           Operand rt) {
  Label L;
  BranchShort(&L, cc, rs, rt);
  Abort(reason);
  // Will not return here.
  bind(&L);
}

void MacroAssembler::Abort(AbortReason reason) {
  Label abort_start;
  bind(&abort_start);
  if (v8_flags.code_comments) {
    const char* msg = GetAbortReason(reason);
    RecordComment("Abort message: ");
    RecordComment(msg);
  }

  // Avoid emitting call to builtin if requested.
  if (trap_on_abort()) {
    ebreak();
    return;
  }

  if (should_abort_hard()) {
    // We don't care if we constructed a frame. Just pretend we did.
    FrameScope assume_frame(this, StackFrame::NO_FRAME_TYPE);
    PrepareCallCFunction(1, a0);
    li(a0, Operand(static_cast<int>(reason)));
    li(a1, ExternalReference::abort_with_reason());
    // Use Call directly to avoid any unneeded overhead. The function won't
    // return anyway.
    Call(a1);
    return;
  }

  Move(a0, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      LoadEntryFromBuiltin(Builtin::kAbort, t6);
      Call(t6);
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }
  // Will not return here.
  if (is_trampoline_pool_blocked()) {
    // If the calling code cares about the exact number of
    // instructions generated, we insert padding here to keep the size
    // of the Abort macro constant.
    // Currently in debug mode with debug_code enabled the number of
    // generated instructions is 10, so we use this as a maximum value.
    static const int kExpectedAbortInstructions = 10;
    int abort_instructions = InstructionsGeneratedSince(&abort_start);
    DCHECK_LE(abort_instructions, kExpectedAbortInstructions);
    while (abort_instructions++ < kExpectedAbortInstructions) {
      nop();
    }
  }
}

// Sets condition flags based on comparison, and returns type in type_reg.
void MacroAssembler::CompareObjectTypeAndJump(Register object, Register map,
                                              Register type_reg,
                                              InstanceType type, Condition cond,
                                              Label* target,
                                              Label::Distance distance) {
  ASM_CODE_COMMENT(this);
  LoadMap(map, object);
  // Borrowed from BaselineAssembler
  if (v8_flags.debug_code) {
    AssertNotSmi(map);
    Register temp_type_reg = type_reg;
    UseScratchRegisterScope temps(this);
    if (map == temp_type_reg) {
      // GetObjectType clobbers 2nd and 3rd args, can't be same registers as
      // first one
      temp_type_reg = temps.Acquire();
    }
    GetObjectType(map, temp_type_reg, temp_type_reg);
    Assert(eq, AbortReason::kUnexpectedValue, temp_type_reg, Operand(MAP_TYPE));
  }
  Lhu(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  Branch(target, cond, type_reg, Operand(type), distance);
}

void MacroAssembler::LoadMap(Register destination, Register object) {
  ASM_CODE_COMMENT(this);
  LoadTaggedField(destination, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadCompressedMap(Register dst, Register object) {
  ASM_CODE_COMMENT(this);
  Lw(dst, FieldMemOperand(object, HeapObject::kMapOffset));
}

void MacroAssembler::LoadNativeContextSlot(Register dst, int index) {
  ASM_CODE_COMMENT(this);
  LoadMap(dst, cp);
  LoadTaggedField(
      dst, FieldMemOperand(
               dst, Map::kConstructorOrBackPointerOrNativeContextOffset));
  LoadTaggedField(dst, MemOperand(dst, Context::SlotOffset(index)));
}

void MacroAssembler::TryLoadOptimizedOsrCode(Register scratch_and_result,
                                             CodeKind min_opt_level,
                                             Register feedback_vector,
                                             FeedbackSlot slot,
                                             Label* on_result,
                                             Label::Distance distance) {
  ASM_CODE_COMMENT(this);
  Label fallthrough, clear_slot;
  LoadTaggedField(
      scratch_and_result,
      FieldMemOperand(feedback_vector,
                      FeedbackVector::OffsetOfElementAt(slot.ToInt())));
  LoadWeakValue(scratch_and_result, scratch_and_result, &fallthrough);

  // Is it marked_for_deoptimization? If yes, clear the slot.
  {
    // The entry references a CodeWrapper object. Unwrap it now.
    LoadCodePointerField(
        scratch_and_result,
        FieldMemOperand(scratch_and_result, CodeWrapper::kCodeOffset));

    // marked for deoptimization?
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Load32U(scratch, FieldMemOperand(scratch_and_result, Code::kFlagsOffset));
    And(scratch, scratch, Operand(1 << Code::kMarkedForDeoptimizationBit));

    if (min_opt_level == CodeKind::TURBOFAN_JS) {
      Branch(&clear_slot, not_equal, scratch, Operand(zero_reg),
             Label::Distance::kNear);

      // is code "turbofanned"?
      Load32U(scratch, FieldMemOperand(scratch_and_result, Code::kFlagsOffset));
      And(scratch, scratch, Operand(1 << Code::kIsTurbofannedBit));
      Branch(on_result, not_equal, scratch, Operand(zero_reg), distance);

      Branch(&fallthrough);
    } else {
      DCHECK_EQ(min_opt_level, CodeKind::MAGLEV);
      Branch(on_result, equal, scratch, Operand(zero_reg), distance);
    }

    bind(&clear_slot);
    li(scratch_and_result, ClearedValue());
    StoreTaggedField(
        scratch_and_result,
        FieldMemOperand(feedback_vector,
                        FeedbackVector::OffsetOfElementAt(slot.ToInt())));
  }

  bind(&fallthrough);
  Move(scratch_and_result, zero_reg);
}

void MacroAssembler::StubPrologue(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(StackFrame::TypeToMarker(type)));
  PushCommonFrame(scratch);
}

void MacroAssembler::Prologue() { PushStandardFrame(a1); }

void MacroAssembler::EnterFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Push(ra, fp);
  Move(fp, sp);
  if (!StackFrame::IsJavaScript(type)) {
    li(scratch, Operand(StackFrame::TypeToMarker(type)));
    Push(scratch);
  }
#if V8_ENABLE_WEBASSEMBLY
  if (type == StackFrame::WASM || type == StackFrame::WASM_LIFTOFF_SETUP) {
    Push(kWasmImplicitArgRegister);
  }
#endif  // V8_ENABLE_WEBASSEMBLY
}

void MacroAssembler::LeaveFrame(StackFrame::Type type) {
  ASM_CODE_COMMENT(this);
  addi(sp, fp, 2 * kSystemPointerSize);
  LoadWord(ra, MemOperand(fp, 1 * kSystemPointerSize));
  LoadWord(fp, MemOperand(fp, 0 * kSystemPointerSize));
}

void MacroAssembler::EnterExitFrame(Register scratch, int stack_space,
                                    StackFrame::Type frame_type) {
  ASM_CODE_COMMENT(this);
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  // Set up the frame structure on the stack.
  static_assert(2 * kSystemPointerSize ==
                ExitFrameConstants::kCallerSPDisplacement);
  static_assert(1 * kSystemPointerSize == ExitFrameConstants::kCallerPCOffset);
  static_assert(0 * kSystemPointerSize == ExitFrameConstants::kCallerFPOffset);

  // This is how the stack will look:
  // fp + 2 (==kCallerSPDisplacement) - old stack's end
  // [fp + 1 (==kCallerPCOffset)] - saved old ra
  // [fp + 0 (==kCallerFPOffset)] - saved old fp
  // [fp - 1 StackFrame::EXIT Smi
  // [fp - 2 (==kSPOffset)] - sp of the called function
  // fp - (2 + stack_space + alignment) == sp == [fp - kSPOffset] - top of the
  //   new stack (will contain saved ra)

  using ER = ExternalReference;

  // Save registers and reserve room for saved entry sp.
  addi(sp, sp,
       -2 * kSystemPointerSize - ExitFrameConstants::kFixedFrameSizeFromFp);
  StoreWord(ra, MemOperand(sp, 3 * kSystemPointerSize));
  StoreWord(fp, MemOperand(sp, 2 * kSystemPointerSize));

  li(scratch, Operand(StackFrame::TypeToMarker(frame_type)));
  StoreWord(scratch, MemOperand(sp, 1 * kSystemPointerSize));
  // Set up new frame pointer.
  addi(fp, sp, ExitFrameConstants::kFixedFrameSizeFromFp);

  if (v8_flags.debug_code) {
    StoreWord(zero_reg, MemOperand(fp, ExitFrameConstants::kSPOffset));
  }

  // Save the frame pointer and the context in top.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  StoreWord(fp, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));
  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  StoreWord(cp, ExternalReferenceAsOperand(context_address, no_reg));

  const int frame_alignment = MacroAssembler::ActivationFrameAlignment();

  // Reserve place for the return address, stack space and an optional slot
  // (used by DirectCEntry to hold the return value if a struct is
  // returned) and align the frame preparing for calling the runtime function.
  DCHECK_GE(stack_space, 0);
  SubWord(sp, sp, Operand((stack_space + 1) * kSystemPointerSize));
  if (frame_alignment > 0) {
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    And(sp, sp, Operand(-frame_alignment));  // Align stack.
  }

  // Set the exit frame sp value to point just before the return address
  // location.
  addi(scratch, sp, kSystemPointerSize);
  StoreWord(scratch, MemOperand(fp, ExitFrameConstants::kSPOffset));
}

void MacroAssembler::LeaveExitFrame(Register scratch) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  using ER = ExternalReference;
  // Clear top frame.
  // Restore current context from top and clear it in debug mode.
  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  LoadWord(cp, ExternalReferenceAsOperand(context_address, no_reg));

  if (v8_flags.debug_code) {
    li(scratch, Operand(Context::kInvalidContext));
    StoreWord(scratch, ExternalReferenceAsOperand(context_address, no_reg));
  }

  // Clear the top frame.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  StoreWord(zero_reg, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Pop the arguments, restore registers, and return.
  Mv(sp, fp);  // Respect ABI stack constraint.
  LoadWord(fp, MemOperand(sp, ExitFrameConstants::kCallerFPOffset));
  LoadWord(ra, MemOperand(sp, ExitFrameConstants::kCallerPCOffset));

  addi(sp, sp, 2 * kSystemPointerSize);
}

int MacroAssembler::ActivationFrameAlignment() {
#if V8_HOST_ARCH_RISCV32 || V8_HOST_ARCH_RISCV64
  // Running on the real platform. Use the alignment as mandated by the local
  // environment.
  // Note: This will break if we ever start generating snapshots on one RISC-V
  // platform for another RISC-V platform with a different alignment.
  return base::OS::ActivationFrameAlignment();
#else   // V8_HOST_ARCH_RISCV64
  // If we are using the simulator then we should always align to the expected
  // alignment. As the simulator is used to generate snapshots we do not know
  // if the target platform will need alignment, so this is controlled from a
  // flag.
  return v8_flags.sim_stack_alignment;
#endif  // V8_HOST_ARCH_RISCV64
}

void MacroAssembler::AssertStackIsAligned() {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    const int frame_alignment = ActivationFrameAlignment();
    const int frame_alignment_mask = frame_alignment - 1;

    if (frame_alignment > kSystemPointerSize) {
      Label alignment_as_expected;
      DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
      {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.Acquire();
        andi(scratch, sp, frame_alignment_mask);
        BranchShort(&alignment_as_expected, eq, scratch, Operand(zero_reg));
      }
      // Don't use Check here, as it will call Runtime_Abort re-entering here.
      ebreak();
      bind(&alignment_as_expected);
    }
  }
}

void MacroAssembler::SmiUntag(Register dst, const MemOperand& src) {
  ASM_CODE_COMMENT(this);
  if (SmiValuesAre32Bits()) {
    Lw(dst, MemOperand(src.rm(), SmiWordOffset(src.offset())));
  } else {
    DCHECK(SmiValuesAre31Bits());
    if (COMPRESS_POINTERS_BOOL) {
      Lw(dst, src);
    } else {
      LoadWord(dst, src);
    }
    SmiUntag(dst);
  }
}

void MacroAssembler::SmiToInt32(Register smi) {
  ASM_CODE_COMMENT(this);
  if (v8_flags.enable_slow_asserts) {
    AssertSmi(smi);
  }
  DCHECK(SmiValuesAre32Bits() || SmiValuesAre31Bits());
  SmiUntag(smi);
}

void MacroAssembler::SmiToInt32(Register dst, Register src) {
  if (dst != src) {
    Move(dst, src);
  }
  SmiToInt32(dst);
}

void MacroAssembler::JumpIfSmi(Register value, Label* smi_label,
                               Label::Distance distance) {
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(0, kSmiTag);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  andi(scratch, value, kSmiTagMask);
  Branch(smi_label, eq, scratch, Operand(zero_reg), distance);
}

void MacroAssembler::JumpIfCodeIsMarkedForDeoptimization(
    Register code, Register scratch, Label* if_marked_for_deoptimization) {
  Load32U(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  And(scratch, scratch, Operand(1 << Code::kMarkedForDeoptimizationBit));
  Branch(if_marked_for_deoptimization, ne, scratch, Operand(zero_reg));
}

Operand MacroAssembler::ClearedValue() const {
  return Operand(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

void MacroAssembler::JumpIfNotSmi(Register value, Label* not_smi_label,
                                  Label::Distance distance) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  DCHECK_EQ(0, kSmiTag);
  andi(scratch, value, kSmiTagMask);
  Branch(not_smi_label, ne, scratch, Operand(zero_reg), distance);
}

void MacroAssembler::JumpIfObjectType(Label* target, Condition cc,
                                      Register object,
                                      InstanceType instance_type,
                                      Register scratch) {
  DCHECK(cc == eq || cc == ne);
  UseScratchRegisterScope temps(this);
  if (scratch == no_reg) {
    scratch = temps.Acquire();
  }
  if (V8_STATIC_ROOTS_BOOL) {
    if (std::optional<RootIndex> expected =
            InstanceTypeChecker::UniqueMapOfInstanceType(instance_type)) {
      Tagged_t ptr = ReadOnlyRootPtr(*expected);
      LoadCompressedMap(scratch, object);
      Branch(target, cc, scratch, Operand(ptr));
      return;
    }
  }
  GetObjectType(object, scratch, scratch);
  Branch(target, cc, scratch, Operand(instance_type));
}

void MacroAssembler::JumpIfJSAnyIsNotPrimitive(Register heap_object,
                                               Register scratch, Label* target,
                                               Label::Distance distance,
                                               Condition cc) {
  CHECK(cc == Condition::kUnsignedLessThan ||
        cc == Condition::kUnsignedGreaterThanEqual);
  if (V8_STATIC_ROOTS_BOOL) {
#ifdef DEBUG
    Label ok;
    LoadMap(scratch, heap_object);
    GetInstanceTypeRange(scratch, scratch, FIRST_JS_RECEIVER_TYPE, scratch);
    Branch(&ok, Condition::kUnsignedLessThanEqual, scratch,
           Operand(LAST_JS_RECEIVER_TYPE - FIRST_JS_RECEIVER_TYPE));

    LoadMap(scratch, heap_object);
    GetInstanceTypeRange(scratch, scratch, FIRST_PRIMITIVE_HEAP_OBJECT_TYPE,
                         scratch);
    Branch(&ok, Condition::kUnsignedLessThanEqual, scratch,
           Operand(LAST_PRIMITIVE_HEAP_OBJECT_TYPE -
                   FIRST_PRIMITIVE_HEAP_OBJECT_TYPE));

    Abort(AbortReason::kInvalidReceiver);
    bind(&ok);
#endif  // DEBUG

    // All primitive object's maps are allocated at the start of the read only
    // heap. Thus JS_RECEIVER's must have maps with larger (compressed)
    // addresses.
    LoadCompressedMap(scratch, heap_object);
    Branch(target, cc, scratch,
           Operand(InstanceTypeChecker::kNonJsReceiverMapLimit));
  } else {
    static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
    GetObjectType(heap_object, scratch, scratch);
    Branch(target, cc, scratch, Operand(FIRST_JS_RECEIVER_TYPE));
  }
}

void MacroAssembler::AssertNotSmi(Register object, AbortReason reason) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    static_assert(kSmiTag == 0);
    andi(scratch, object, kSmiTagMask);
    Check(ne, reason, scratch, Operand(zero_reg));
  }
}

void MacroAssembler::AssertSmi(Register object, AbortReason reason) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    static_assert(kSmiTag == 0);
    andi(scratch, object, kSmiTagMask);
    Check(eq, reason, scratch, Operand(zero_reg));
  }
}

void MacroAssembler::AssertConstructor(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, scratch);
    Check(ne, AbortReason::kOperandIsASmiAndNotAConstructor, scratch,
          Operand(zero_reg));

    LoadMap(sc
```