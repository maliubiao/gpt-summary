Response: The user wants to understand the functionality of a C++ source code file, specifically the fourth part of a five-part series. The file seems to be related to the V8 JavaScript engine and RISC-V architecture.

Here's a breakdown of the thought process to summarize the code:

1. **Identify the core class:** The code is part of the `MacroAssembler` class for the RISC-V architecture in V8. This class is responsible for generating machine code instructions.

2. **Scan for major sections:** Look for comments or clear separations in the code. The provided snippet has sections for:
    * Loading and storing SIMD (vector) lane values.
    * Implementing arithmetic operations with overflow checks.
    * Calling runtime functions.
    * Debugging utilities (assertions, traps, aborts).
    * Stack frame management (prologue, epilogue, entering/leaving frames).
    * Handling tagged values (Smi, HeapObject).
    * Object type checking and casting.
    * Optimized code loading.
    * Stub and standard prologues.
    * Entering and leaving frames, including exit frames.
    * Stack alignment assertions.
    * Smi manipulation.
    * Conditional jumps based on Smi or object types.
    * Assertions for various object types.
    * Floating-point min/max operations.
    * Preparing and calling C functions.
    * Checking page flags.
    * Computing code start address.
    * Handling deoptimization.
    * Calling and jumping to code objects and JS functions.
    * Helper functions for tagged field loading and storing (with pointer compression considerations).
    * Dropping arguments from the stack.
    * Calling API functions.

3. **Group related functionalities:**  The sections can be grouped into higher-level functionalities:
    * **SIMD operations:** Instructions for manipulating individual lanes of vector registers.
    * **Arithmetic with overflow:**  Implementing addition, subtraction, and multiplication with mechanisms to detect overflow.
    * **Runtime calls:**  Interfacing with V8's runtime system.
    * **Debugging and assertions:**  Tools for verifying assumptions and detecting errors during development.
    * **Stack frame management:**  Routines for setting up and tearing down stack frames for function calls.
    * **Tagged value manipulation:**  Working with V8's representation of JavaScript values (Smis and HeapObjects).
    * **Object type handling:** Checking the type of JavaScript objects.
    * **Code optimization:** Trying to load and execute optimized code.
    * **C function calls:** Interfacing with native C/C++ functions.
    * **Deoptimization:** Handling scenarios where optimized code needs to be abandoned.
    * **Function calls:**  Calling JavaScript functions.
    * **Memory access:** Loading and storing tagged fields, considering pointer compression.
    * **Argument handling:** Manipulating arguments on the stack.
    * **API calls:** Calling V8's C++ API functions.

4. **Identify connections to JavaScript:** Many of these functions directly support the execution of JavaScript code:
    * **SIMD operations:** Implementations for JavaScript's SIMD API.
    * **Arithmetic with overflow:** Necessary for implementing JavaScript's arithmetic operations, which have specific overflow semantics.
    * **Runtime calls:** Many core JavaScript functionalities are implemented in the runtime.
    * **Object type handling:** JavaScript's dynamic nature requires frequent type checking.
    * **Stack frame management:** Essential for function calls in JavaScript.
    * **Tagged value manipulation:** JavaScript values are represented as tagged pointers.
    * **C function calls:** Used for calling built-in JavaScript functions or when interacting with native modules.
    * **Deoptimization:** A mechanism to fall back from optimized code when assumptions are violated.
    * **Function calls:** The fundamental operation of executing JavaScript code.
    * **API calls:**  Allow embedding applications to interact with the V8 engine.

5. **Provide JavaScript examples:**  For each relevant functionality, provide a simple JavaScript code snippet that would trigger the underlying C++ code. For example:
    * `WasmRvvS128const`:  Illustrate with WebAssembly SIMD constant initialization.
    * `AddOverflow64`:  Show how JavaScript's `+` operator might trigger this.
    * `CallRuntime`:  Demonstrate with a built-in function like `parseInt`.
    * Assertions: Explain they are for internal checks but not directly triggered by user code.
    * `CallJSFunction`:  Show a simple function call.

6. **Structure the summary:** Organize the findings into clear sections: "Functionality Summary" and "Relationship to JavaScript". Within each section, use bullet points for readability.

7. **Refine and clarify:** Review the summary for clarity, accuracy, and completeness. Ensure the JavaScript examples are relevant and easy to understand. Emphasize that this is part 4 of 5 and therefore focuses on a subset of the overall functionality.
这是 `v8/src/codegen/riscv/macro-assembler-riscv.cc` 文件的第四部分，主要包含以下功能：

**功能归纳:**

* **SIMD (向量) 指令支持 (RVV extension):**  提供了用于加载和存储 SIMD 寄存器常量的函数 (`WasmRvvS128const`)，以及用于加载和存储 SIMD 寄存器中特定通道 (lane) 的值的函数 (`LoadLane`, `StoreLane`). 这些函数针对 WebAssembly 的 SIMD 操作进行了优化。

* **溢出检测的算术运算:**  实现了一些带有溢出检测的算术运算函数，例如 `AddOverflow64`, `SubOverflow64`, `MulOverflow32`, `MulOverflow64`。这些函数不仅计算结果，还会将溢出状态写入指定的寄存器。这对于实现 JavaScript 中具有特定溢出行为的算术运算至关重要。

* **运行时函数调用:**  提供了调用 V8 运行时函数的机制 (`CallRuntime`, `TailCallRuntime`)。运行时函数是用 C++ 实现的，用于处理一些 JavaScript 语言的核心功能，例如对象创建、类型转换等。

* **跳转到外部引用:**  允许直接跳转到外部 C++ 函数 (`JumpToExternalReference`)，这常用于调用内置函数。

* **弱引用的加载:**  实现了加载弱引用的值，并在弱引用被清除时跳转到指定标签的功能 (`LoadWeakValue`). 弱引用用于实现垃圾回收，允许对象在不再被强引用时被回收。

* **性能计数器操作:**  提供了增加和减少性能计数器的功能 (`EmitIncrementCounter`, `EmitDecrementCounter`)，用于性能分析和监控。

* **调试和断言:**  包含用于触发断点 (`Trap`, `DebugBreak`) 和进行条件断言 (`Assert`, `Check`) 的功能。这些功能在开发和调试过程中非常有用，用于验证代码的正确性。

* **类型检查和跳转:**  提供了基于对象类型进行比较和跳转的功能 (`CompareObjectTypeAndJump`, `JumpIfObjectType`)。这在 JavaScript 虚拟机中非常常见，因为需要根据对象的实际类型来执行不同的操作。

* **加载 Map 和 NativeContext:**  提供了加载对象的 Map (`LoadMap`, `LoadCompressedMap`) 和 NativeContext 插槽 (`LoadNativeContextSlot`) 的功能。Map 描述了对象的结构和类型，NativeContext 包含了全局对象和内置函数。

* **尝试加载优化的代码:**  实现了尝试加载并跳转到优化的机器码的逻辑 (`TryLoadOptimizedOsrCode`)。这对于提升 JavaScript 代码的执行性能至关重要。

* **函数调用序言和尾声:**  提供了生成函数调用序言 (`StubPrologue`, `Prologue`, `EnterFrame`) 和尾声 (`LeaveFrame`) 的代码，用于设置和清理函数调用的栈帧。

* **进入和离开 ExitFrame:**  提供了用于进入和离开 ExitFrame 的函数 (`EnterExitFrame`, `LeaveExitFrame`)。ExitFrame 用于在 JavaScript 代码调用 C++ 代码或反之的情况下进行栈帧管理。

* **栈对齐断言:**  提供了在调试模式下检查栈是否对齐的功能 (`AssertStackIsAligned`)，这对于保证程序的正确性至关重要。

* **Smi (小整数) 处理:**  提供了将 Smi 解压缩为整数 (`SmiUntag`, `SmiToInt32`)、检查是否为 Smi (`JumpIfSmi`, `JumpIfNotSmi`) 以及断言是否为 Smi (`AssertSmi`, `AssertNotSmi`) 的功能。Smi 是 V8 中用于高效表示小整数的一种特殊类型。

* **对象类型断言:**  提供了一系列用于断言对象是否为特定类型的函数，例如构造函数 (`AssertConstructor`)、函数 (`AssertFunction`, `AssertCallableFunction`, `AssertBoundFunction`)、Generator 对象 (`AssertGeneratorObject`) 等。

* **浮点数 Min/Max 操作:**  提供了用于计算单精度和双精度浮点数的最小值和最大值的函数 (`Float32Max`, `Float32Min`, `Float64Max`, `Float64Min`)，并考虑了 NaN 的处理。

* **调用 C 函数:**  提供了一系列用于准备和调用 C 函数的函数 (`PrepareCallCFunction`, `CallCFunction`)。

* **页标志检查:**  提供了检查内存页标志的功能 (`CheckPageFlag`)，用于内存管理。

* **获取非指定寄存器:** 提供了一个辅助函数 `GetRegisterThatIsNotOneOf` 用于获取一个不与其他指定寄存器冲突的寄存器。

* **计算代码起始地址:** 提供了计算当前代码起始地址的功能 (`ComputeCodeStartAddress`)。

* **检查是否需要反优化:** 提供了检查代码对象是否被标记为需要反优化，并跳转到反优化代码的功能 (`BailoutIfDeoptimized`, `CallForDeoptimization`).

* **加载代码指令起始地址:** 提供了加载代码对象的指令起始地址的功能 (`LoadCodeInstructionStart`).

* **加载受保护的指针字段:** 提供了加载受保护的指针字段的功能 (`LoadProtectedPointerField`)，这与 V8 的安全沙箱有关。

* **调用和跳转到 Code 对象和 JSFunction:** 提供了调用 (`CallCodeObject`, `CallJSFunction`) 和跳转 (`JumpCodeObject`, `JumpJSFunction`) 到 Code 对象和 JavaScript 函数的功能。

* **JSDispatchTable 相关 (可能与 Leaptiering 有关):**  提供了一些与 `JSDispatchTable` 相关的函数 (`LoadEntrypointFromJSDispatchTable`, `LoadParameterCountFromJSDispatchTable`, `LoadEntrypointAndParameterCountFromJSDispatchTable`)，这可能与 V8 的 Leaptiering 优化技术有关。

* **带符号和不带符号的 Tagged 字段加载和存储 (考虑指针压缩):**  提供了一系列用于加载和存储 Tagged 字段的函数 (`LoadTaggedField`, `LoadTaggedFieldWithoutDecompressing`, `LoadTaggedSignedField`, `StoreTaggedField`, `AtomicStoreTaggedField`, `DecompressTaggedSigned`, `DecompressTagged`, `DecompressProtected`, `AtomicDecompressTaggedSigned`, `AtomicDecompressTagged`)，这些函数会根据是否启用指针压缩来选择不同的指令。Tagged 指针是 V8 中用于表示 JavaScript 对象的常用方式。

* **丢弃栈上的参数:** 提供了从栈上丢弃指定数量参数的功能 (`DropArguments`, `DropArgumentsAndPushNewReceiver`).

* **调用 API 函数并返回:** 提供了一个复杂的函数 `CallApiFunctionAndReturn`，用于调用 V8 的 C++ API 函数，并处理 HandleScope 的管理、异常传播和返回值处理。

**与 JavaScript 功能的关系 (示例):**

这个文件中的很多功能都直接关系到 JavaScript 的执行：

1. **SIMD 指令:**  当 JavaScript 代码中使用 SIMD API 时，例如创建和操作 `Float32x4` 或 `Int32x4` 等类型的对象时，底层的 `WasmRvvS128const`, `LoadLane`, `StoreLane` 等函数会被调用。

   ```javascript
   const arr = new Float32Array([1.0, 2.0, 3.0, 4.0]);
   const vec = Float32x4.fromArray(arr, 0);
   const x = vec.x; // 底层可能用到 LoadLane
   ```

2. **溢出检测的算术运算:** JavaScript 的算术运算符 (例如 `+`, `-`, `*`) 在某些情况下需要检测溢出。 例如，当进行 32 位整数运算时，`AddOverflow32` 等函数可能会被用于检测是否超出 32 位范围。

   ```javascript
   let a = 2147483647; // 最大的 32 位有符号整数
   let b = 1;
   let c = a + b; // 这里可能会触发溢出检测，虽然 JavaScript 不会抛出异常，但 V8 内部会处理。
   ```

3. **运行时函数调用:**  许多内置的 JavaScript 函数，如 `parseInt`, `Object.create`, `Array.prototype.push` 等，其核心逻辑是通过 `CallRuntime` 调用 V8 的运行时函数实现的。

   ```javascript
   let num = parseInt("10"); // parseInt 的实现会调用底层的运行时函数
   let obj = {}; // Object.create(null) 也会调用运行时函数
   ```

4. **类型检查:**  JavaScript 的动态类型特性需要在运行时进行类型检查。 例如，当执行 `instanceof` 运算符或进行函数调用时，`CompareObjectTypeAndJump` 或 `JumpIfObjectType` 等函数会被用来判断对象的类型。

   ```javascript
   function foo(obj) {
       if (obj instanceof Array) { // 底层会进行类型检查
           console.log("It's an array!");
       }
   }
   foo([1, 2, 3]);
   ```

5. **函数调用:**  当 JavaScript 代码调用一个函数时，`CallJSFunction` 函数会被用来执行实际的调用过程，包括设置栈帧、传递参数和跳转到函数代码。

   ```javascript
   function add(a, b) {
       return a + b;
   }
   let sum = add(5, 3); // 调用 add 函数会使用 CallJSFunction
   ```

总而言之，这个代码文件的第四部分包含了 V8 引擎在 RISC-V 架构上执行 JavaScript 代码的关键底层实现，涵盖了 SIMD 指令、算术运算、运行时调用、类型检查、函数调用等核心功能。它将高级的 JavaScript 语义转换为底层的机器指令，使得 JavaScript 代码能够在 RISC-V 处理器上高效运行。

Prompt: 
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
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

    LoadMap(scratch, object);
    Lbu(scratch, FieldMemOperand(scratch, Map::kBitFieldOffset));
    And(scratch, scratch, Operand(Map::Bits1::IsConstructorBit::kMask));
    Check(ne, AbortReason::kOperandIsNotAConstructor, scratch,
          Operand(zero_reg));
  }
}

void MacroAssembler::AssertFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    static_assert(kSmiTag == 0);
    SmiTst(object, scratch);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, scratch,
          Operand(zero_reg));
    push(object);
    LoadMap(object, object);
    Register range = scratch;
    GetInstanceTypeRange(object, object, FIRST_JS_FUNCTION_TYPE, range);
    Check(Uless_equal, AbortReason::kOperandIsNotAFunction, range,
          Operand(LAST_JS_FUNCTION_TYPE - FIRST_JS_FUNCTION_TYPE));
    pop(object);
  }
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  AssertNotSmi(object, AbortReason::kOperandIsASmiAndNotAFunction);
  push(object);
  LoadMap(object, object);
  UseScratchRegisterScope temps(this);
  Register range = temps.Acquire();
  GetInstanceTypeRange(object, object, FIRST_CALLABLE_JS_FUNCTION_TYPE, range);
  Check(Uless_equal, AbortReason::kOperandIsNotACallableFunction, range,
        Operand(LAST_CALLABLE_JS_FUNCTION_TYPE -
                FIRST_CALLABLE_JS_FUNCTION_TYPE));
  pop(object);
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    static_assert(kSmiTag == 0);
    SmiTst(object, scratch);
    Check(ne, AbortReason::kOperandIsASmiAndNotABoundFunction, scratch,
          Operand(zero_reg));
    GetObjectType(object, scratch, scratch);
    Check(eq, AbortReason::kOperandIsNotABoundFunction, scratch,
          Operand(JS_BOUND_FUNCTION_TYPE));
  }
}

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertSmiOrHeapObjectInMainCompressionCage(
    Register object) {
#if V8_TARGET_ARCH_RISCV64
  if (!PointerCompressionIsEnabled()) return;
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  // We may not have any scratch registers so we preserve our input register.
  Push(object, zero_reg);
  Label ok;
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  SmiTst(object, scratch);
  BranchShort(&ok, kEqual, scratch, Operand(zero_reg));
  // Clear the lower 32 bits.
  Srl64(object, object, Operand(32));
  Sll64(object, object, Operand(32));
  // Either the value is now equal to the right-shifted pointer compression
  // cage base or it's zero if we got a compressed pointer register as input.
  BranchShort(&ok, kEqual, object, Operand(zero_reg));
  Check(kEqual, AbortReason::kObjectNotTagged, object,
        Operand(kPtrComprCageBaseRegister));
  bind(&ok);
  Pop(object, zero_reg);
#endif
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  static_assert(kSmiTag == 0);
  SmiTst(object, scratch);
  Check(ne, AbortReason::kOperandIsASmiAndNotAGeneratorObject, scratch,
        Operand(zero_reg));

  LoadMap(scratch, object);
  GetInstanceTypeRange(scratch, scratch, FIRST_JS_GENERATOR_OBJECT_TYPE,
                       scratch);
  Check(
      Uless_equal, AbortReason::kOperandIsNotAGeneratorObject, scratch,
      Operand(LAST_JS_GENERATOR_OBJECT_TYPE - FIRST_JS_GENERATOR_OBJECT_TYPE));
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object,
                                                     Register scratch) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    Label done_checking;
    AssertNotSmi(object);
    LoadRoot(scratch, RootIndex::kUndefinedValue);
    BranchShort(&done_checking, eq, object, Operand(scratch));
    GetObjectType(object, scratch, scratch);
    Assert(eq, AbortReason::kExpectedUndefinedOrCell, scratch,
           Operand(ALLOCATION_SITE_TYPE));
    bind(&done_checking);
  }
}

template <typename F_TYPE>
void MacroAssembler::FloatMinMaxHelper(FPURegister dst, FPURegister src1,
                                       FPURegister src2, MaxMinKind kind) {
  DCHECK((std::is_same<F_TYPE, float>::value) ||
         (std::is_same<F_TYPE, double>::value));

  if (src1 == src2 && dst != src1) {
    if (std::is_same<float, F_TYPE>::value) {
      fmv_s(dst, src1);
    } else {
      fmv_d(dst, src1);
    }
    return;
  }

  Label done, nan;

  // For RISCV, fmin_s returns the other non-NaN operand as result if only one
  // operand is NaN; but for JS, if any operand is NaN, result is Nan. The
  // following handles the discrepency between handling of NaN between ISA and
  // JS semantics
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  if (std::is_same<float, F_TYPE>::value) {
    CompareIsNotNanF32(scratch, src1, src2);
  } else {
    CompareIsNotNanF64(scratch, src1, src2);
  }
  BranchFalseF(scratch, &nan);

  if (kind == MaxMinKind::kMax) {
    if (std::is_same<float, F_TYPE>::value) {
      fmax_s(dst, src1, src2);
    } else {
      fmax_d(dst, src1, src2);
    }
  } else {
    if (std::is_same<float, F_TYPE>::value) {
      fmin_s(dst, src1, src2);
    } else {
      fmin_d(dst, src1, src2);
    }
  }
  j(&done);

  bind(&nan);
  // if any operand is NaN, return NaN (fadd returns NaN if any operand is NaN)
  if (std::is_same<float, F_TYPE>::value) {
    fadd_s(dst, src1, src2);
  } else {
    fadd_d(dst, src1, src2);
  }

  bind(&done);
}

void MacroAssembler::Float32Max(FPURegister dst, FPURegister src1,
                                FPURegister src2) {
  ASM_CODE_COMMENT(this);
  FloatMinMaxHelper<float>(dst, src1, src2, MaxMinKind::kMax);
}

void MacroAssembler::Float32Min(FPURegister dst, FPURegister src1,
                                FPURegister src2) {
  ASM_CODE_COMMENT(this);
  FloatMinMaxHelper<float>(dst, src1, src2, MaxMinKind::kMin);
}

void MacroAssembler::Float64Max(FPURegister dst, FPURegister src1,
                                FPURegister src2) {
  ASM_CODE_COMMENT(this);
  FloatMinMaxHelper<double>(dst, src1, src2, MaxMinKind::kMax);
}

void MacroAssembler::Float64Min(FPURegister dst, FPURegister src1,
                                FPURegister src2) {
  ASM_CODE_COMMENT(this);
  FloatMinMaxHelper<double>(dst, src1, src2, MaxMinKind::kMin);
}

int MacroAssembler::CalculateStackPassedDWords(int num_gp_arguments,
                                               int num_fp_arguments) {
  int stack_passed_dwords = 0;

  // Up to eight integer arguments are passed in registers a0..a7 and
  // up to eight floating point arguments are passed in registers fa0..fa7
  if (num_gp_arguments > kRegisterPassedArguments) {
    stack_passed_dwords += num_gp_arguments - kRegisterPassedArguments;
  }
  if (num_fp_arguments > kRegisterPassedArguments) {
    stack_passed_dwords += num_fp_arguments - kRegisterPassedArguments;
  }
  stack_passed_dwords += kCArgSlotCount;
  return stack_passed_dwords;
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          int num_double_arguments,
                                          Register scratch) {
  ASM_CODE_COMMENT(this);
  int frame_alignment = ActivationFrameAlignment();

  // Up to eight simple arguments in a0..a7, fa0..fa7.
  // Remaining arguments are pushed on the stack (arg slot calculation handled
  // by CalculateStackPassedDWords()).
  int stack_passed_arguments =
      CalculateStackPassedDWords(num_reg_arguments, num_double_arguments);
  if (frame_alignment > kSystemPointerSize) {
    // Make stack end at alignment and make room for stack arguments and the
    // original value of sp.
    Mv(scratch, sp);
    SubWord(sp, sp, Operand((stack_passed_arguments + 1) * kSystemPointerSize));
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    And(sp, sp, Operand(-frame_alignment));
    StoreWord(scratch,
              MemOperand(sp, stack_passed_arguments * kSystemPointerSize));
  } else {
    SubWord(sp, sp, Operand(stack_passed_arguments * kSystemPointerSize));
  }
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          Register scratch) {
  PrepareCallCFunction(num_reg_arguments, 0, scratch);
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  li(t6, function);
  return CallCFunctionHelper(t6, num_reg_arguments, num_double_arguments,
                             set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunctionHelper(function, num_reg_arguments, num_double_arguments,
                             set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(ExternalReference function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       return_location);
}

int MacroAssembler::CallCFunctionHelper(
    Register function, int num_reg_arguments, int num_double_arguments,
    SetIsolateDataSlots set_isolate_data_slots, Label* return_location) {
  DCHECK_LE(num_reg_arguments + num_double_arguments, kMaxCParameters);
  DCHECK(has_frame());
  ASM_CODE_COMMENT(this);
  // Make sure that the stack is aligned before calling a C function unless
  // running in the simulator. The simulator has its own alignment check which
  // provides more information.
  // The argument stots are presumed to have been set up by
  // PrepareCallCFunction.

#if V8_HOST_ARCH_RISCV32 || V8_HOST_ARCH_RISCV64
  if (v8_flags.debug_code) {
    int frame_alignment = base::OS::ActivationFrameAlignment();
    int frame_alignment_mask = frame_alignment - 1;
    if (frame_alignment > kSystemPointerSize) {
      DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
      Label alignment_as_expected;
      {
        UseScratchRegisterScope temps(this);
        Register scratch = temps.Acquire();
        And(scratch, sp, Operand(frame_alignment_mask));
        BranchShort(&alignment_as_expected, eq, scratch, Operand(zero_reg));
      }
      // Don't use Check here, as it will call Runtime_Abort possibly
      // re-entering here.
      ebreak();
      bind(&alignment_as_expected);
    }
  }
#endif  // V8_HOST_ARCH_RISCV32 || V8_HOST_ARCH_RISCV64

  // Just call directly. The function called cannot cause a GC, or
  // allow preemption, so the return address in the link register
  // stays correct.
  Label get_pc;
  {
    if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
      if (function != t6) {
        Mv(t6, function);
        function = t6;
      }

      // Save the frame pointer and PC so that the stack layout remains
      // iterable, even without an ExitFrame which normally exists between JS
      // and C frames.
      // 't' registers are caller-saved so this is safe as a scratch register.
      Register pc_scratch = t1;

      LoadAddress(pc_scratch, &get_pc);
      // See x64 code for reasoning about how to address the isolate data
      // fields.
      CHECK(root_array_available());
      StoreWord(pc_scratch,
                ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC));
      StoreWord(fp,
                ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
    }
  }

  Call(function);
  int call_pc_offset = pc_offset();
  bind(&get_pc);
  if (return_location) bind(return_location);

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // We don't unset the PC; the FP is the source of truth.
    StoreWord(zero_reg,
              ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
  }

  // Remove frame bought in PrepareCallCFunction
  int stack_passed_arguments =
      CalculateStackPassedDWords(num_reg_arguments, num_double_arguments);
  if (base::OS::ActivationFrameAlignment() > kSystemPointerSize) {
    LoadWord(sp, MemOperand(sp, stack_passed_arguments * kSystemPointerSize));
  } else {
    AddWord(sp, sp, Operand(stack_passed_arguments * kSystemPointerSize));
  }

  return call_pc_offset;
}

#undef BRANCH_ARGS_CHECK

void MacroAssembler::CheckPageFlag(Register object, int mask, Condition cc,
                                   Label* condition_met) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  temps.Include(t6);
  Register scratch = temps.Acquire();
  And(scratch, object, Operand(~MemoryChunk::GetAlignmentMaskForAssembler()));
  LoadWord(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()));
  And(scratch, scratch, Operand(mask));
  Branch(condition_met, cc, scratch, Operand(zero_reg));
}

Register GetRegisterThatIsNotOneOf(Register reg1, Register reg2, Register reg3,
                                   Register reg4, Register reg5,
                                   Register reg6) {
  RegList regs = {reg1, reg2, reg3, reg4, reg5, reg6};

  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_general_registers(); ++i) {
    int code = config->GetAllocatableGeneralCode(i);
    Register candidate = Register::from_code(code);
    if (regs.has(candidate)) continue;
    return candidate;
  }
  UNREACHABLE();
}

void MacroAssembler::ComputeCodeStartAddress(Register dst) {
  ASM_CODE_COMMENT(this);
  auto pc = -pc_offset();
  auipc(dst, 0);
  if (pc != 0) {
    SubWord(dst, dst, pc);
  }
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void MacroAssembler::BailoutIfDeoptimized() {
  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  LoadProtectedPointerField(
      kScratchReg, MemOperand(kJavaScriptCallCodeStartRegister, offset));
  Lw(kScratchReg, FieldMemOperand(kScratchReg, Code::kFlagsOffset));
  And(kScratchReg, kScratchReg,
      Operand(1 << Code::kMarkedForDeoptimizationBit));
  TailCallBuiltin(Builtin::kCompileLazyDeoptimizedCode, ne, kScratchReg,
                  Operand(zero_reg));
}

void MacroAssembler::CallForDeoptimization(Builtin target, int, Label* exit,
                                           DeoptimizeKind kind, Label* ret,
                                           Label*) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  LoadWord(t6, MemOperand(kRootRegister,
                          IsolateData::BuiltinEntrySlotOffset(target)));
  Call(t6);
  DCHECK_EQ(SizeOfCodeGeneratedSince(exit),
            (kind == DeoptimizeKind::kLazy) ? Deoptimizer::kLazyDeoptExitSize
                                            : Deoptimizer::kEagerDeoptExitSize);
}

void MacroAssembler::LoadCodeInstructionStart(Register destination,
                                              Register code_object,
                                              CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  LoadCodeEntrypointViaCodePointer(
      destination,
      FieldMemOperand(code_object, Code::kSelfIndirectPointerOffset), tag);
#else
  LoadWord(destination,
           FieldMemOperand(code_object, Code::kInstructionStartOffset));
#endif
}

void MacroAssembler::LoadProtectedPointerField(Register destination,
                                               MemOperand field_operand) {
  DCHECK(root_array_available());
#ifdef V8_ENABLE_SANDBOX
  DecompressProtected(destination, field_operand);
#else
  LoadTaggedField(destination, field_operand);
#endif
}

void MacroAssembler::CallCodeObject(Register code_object,
                                    CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
  LoadCodeInstructionStart(code_object, code_object, tag);
  Call(code_object);
}

void MacroAssembler::JumpCodeObject(Register code_object, CodeEntrypointTag tag,
                                    JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(JumpMode::kJump, jump_mode);
  LoadCodeInstructionStart(code_object, code_object, tag);
  Jump(code_object);
}

void MacroAssembler::CallJSFunction(Register function_object,
                                    uint16_t argument_count) {
  DCHECK_WITH_MSG(!V8_ENABLE_LEAPTIERING_BOOL,
                  "argument_count is only used with Leaptiering");
  ASM_CODE_COMMENT(this);
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_LEAPTIERING
  UseScratchRegisterScope temps(this);
  Register dispatch_handle = t0;
  Register parameter_count = t1;
  Register scratch = temps.Acquire();
  Lw(dispatch_handle,
     FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointAndParameterCountFromJSDispatchTable(code, parameter_count,
                                                     dispatch_handle, scratch);
  Label match;
  Branch(&match, le, parameter_count, Immediate(argument_count));
  // If the parameter count doesn't match, we force a safe crash by setting the
  // code entrypoint to zero, causing a nullptr dereference during the call.
  mv(code, zero_reg);
  bind(&match);
  Call(code);
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  Call(code);
#else
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  CallCodeObject(code, kJSEntrypointTag);
#endif
}

void MacroAssembler::JumpJSFunction(Register function_object,
                                    JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_LEAPTIERING
  LoadCodeEntrypointFromJSDispatchTable(
      code,
      FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  DCHECK_NE(code, t6);
  mv(t6, code);
  Jump(t6);
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  // We jump through x17 here because for Branch Identification (BTI) we use
  // "Call" (`bti c`) rather than "Jump" (`bti j`) landing pads for tail-called
  // code. See TailCallBuiltin for more information.
  DCHECK_NE(code, t6);
  mv(t6, code);
  Jump(t6);
#else
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  JumpCodeObject(code, kJSEntrypointTag, jump_mode);
#endif
}

#ifdef V8_ENABLE_LEAPTIERING
void MacroAssembler::LoadEntrypointFromJSDispatchTable(Register destination,
                                                       Register dispatch_handle,
                                                       Register scratch) {
  DCHECK(!AreAliased(destination, scratch));
  ASM_CODE_COMMENT(this);
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli(index, dispatch_handle, kJSDispatchHandleShift);
  slli(index, index, kJSDispatchTableEntrySizeLog2);
  AddWord(scratch, scratch, index);
  Ld(destination, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
}

void MacroAssembler::LoadParameterCountFromJSDispatchTable(
    Register destination, Register dispatch_handle, Register scratch) {
  DCHECK(!AreAliased(destination, scratch));
  ASM_CODE_COMMENT(this);
  Register index = destination;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli(index, dispatch_handle, kJSDispatchHandleShift);
  slli(index, index, kJSDispatchTableEntrySizeLog2);
  AddWord(scratch, scratch, index);
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Lh(destination, MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}

void MacroAssembler::LoadEntrypointAndParameterCountFromJSDispatchTable(
    Register entrypoint, Register parameter_count, Register dispatch_handle,
    Register scratch) {
  DCHECK(!AreAliased(entrypoint, parameter_count, scratch));
  ASM_CODE_COMMENT(this);
  Register index = parameter_count;
  li(scratch, ExternalReference::js_dispatch_table_address());
  srli(index, dispatch_handle, kJSDispatchHandleShift);
  slli(index, index, kJSDispatchTableEntrySizeLog2);
  AddWord(scratch, scratch, index);

  Ld(entrypoint, MemOperand(scratch, JSDispatchEntry::kEntrypointOffset));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  Lh(parameter_count, MemOperand(scratch, JSDispatchEntry::kCodeObjectOffset));
}
#endif

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::LoadTaggedField(const Register& destination,
                                     const MemOperand& field_operand,
                                     Trapper&& trapper) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTagged(destination, field_operand,
                     std::forward<Trapper>(trapper));
  } else {
    Ld(destination, field_operand, std::forward<Trapper>(trapper));
  }
}

void MacroAssembler::LoadTaggedFieldWithoutDecompressing(
    const Register& destination, const MemOperand& field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    Lw(destination, field_operand);
  } else {
    Ld(destination, field_operand);
  }
}

void MacroAssembler::LoadTaggedSignedField(const Register& destination,
                                           const MemOperand& field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTaggedSigned(destination, field_operand);
  } else {
    Ld(destination, field_operand);
  }
}

void MacroAssembler::SmiUntagField(Register dst, const MemOperand& src) {
  SmiUntag(dst, src);
}

void MacroAssembler::StoreTaggedField(const Register& value,
                                      const MemOperand& dst_field_operand,
                                      Trapper&& trapper) {
  if (COMPRESS_POINTERS_BOOL) {
    Sw(value, dst_field_operand, std::forward<Trapper>(trapper));
  } else {
    Sd(value, dst_field_operand, std::forward<Trapper>(trapper));
  }
}

void MacroAssembler::AtomicStoreTaggedField(Register src,
                                            const MemOperand& dst) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  AddWord(scratch, dst.rm(), dst.offset());
  if (COMPRESS_POINTERS_BOOL) {
    amoswap_w(true, true, zero_reg, src, scratch);
  } else {
    amoswap_d(true, true, zero_reg, src, scratch);
  }
}

void MacroAssembler::DecompressTaggedSigned(const Register& destination,
                                            const MemOperand& field_operand) {
  ASM_CODE_COMMENT(this);
  Lwu(destination, field_operand);
  if (v8_flags.debug_code) {
    // Corrupt the top 32 bits. Made up of 16 fixed bits and 16 pc offset bits.
    AddWord(destination, destination,
            Operand(((kDebugZapValue << 16) | (pc_offset() & 0xffff)) << 32));
  }
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      const MemOperand& field_operand,
                                      Trapper&& trapper) {
  ASM_CODE_COMMENT(this);
  Lwu(destination, field_operand, std::forward<Trapper>(trapper));
  AddWord(destination, kPtrComprCageBaseRegister, destination);
}

void MacroAssembler::DecompressTagged(const Register& destination,
                                      const Register& source) {
  ASM_CODE_COMMENT(this);
  And(destination, source, Operand(0xFFFFFFFF));
  AddWord(destination, kPtrComprCageBaseRegister, Operand(destination));
}

void MacroAssembler::DecompressTagged(Register dst, Tagged_t immediate) {
  ASM_CODE_COMMENT(this);
  AddWord(dst, kPtrComprCageBaseRegister, static_cast<int32_t>(immediate));
}

void MacroAssembler::DecompressProtected(const Register& destination,
                                         const MemOperand& field_operand,
                                         Trapper&& trapper) {
#ifdef V8_ENABLE_SANDBOX
  CHECK(V8_ENABLE_SANDBOX_BOOL);
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Lw(destination, field_operand, std::forward<Trapper>(trapper));
  LoadWord(scratch,
           MemOperand(kRootRegister, IsolateData::trusted_cage_base_offset()));
  Or(destination, destination, scratch);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::AtomicDecompressTaggedSigned(Register dst,
                                                  const MemOperand& src) {
  ASM_CODE_COMMENT(this);
  Lwu(dst, src);
  sync();
  if (v8_flags.debug_code) {
    // Corrupt the top 32 bits. Made up of 16 fixed bits and 16 pc offset bits.
    AddWord(dst, dst,
            Operand(((kDebugZapValue << 16) | (pc_offset() & 0xffff)) << 32));
  }
}

void MacroAssembler::AtomicDecompressTagged(Register dst,
                                            const MemOperand& src) {
  ASM_CODE_COMMENT(this);
  Lwu(dst, src);
  sync();
  AddWord(dst, kPtrComprCageBaseRegister, dst);
}

#endif
void MacroAssembler::DropArguments(Register count) {
  CalcScaledAddress(sp, sp, count, kSystemPointerSizeLog2);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver) {
  DCHECK(!AreAliased(argc, receiver));
  DropArguments(argc);
  push(receiver);
}

// Calls an API function. Allocates HandleScope, extracts returned value
// from handle and propagates exceptions. Clobbers C argument registers
// and C caller-saved registers. Restores context. On return removes
//   (*argc_operand + slots_to_drop_on_return) * kSystemPointerSize
// (GCed, includes the call JS arguments space and the additional space
// allocated for the fast call).
void CallApiFunctionAndReturn(MacroAssembler* masm, bool with_profiling,
                              Register function_address,
                              ExternalReference thunk_ref, Register thunk_arg,
                              int slots_to_drop_on_return,
                              MemOperand* argc_operand,
                              MemOperand return_value_operand) {
  ASM_CODE_COMMENT(masm);
  using ER = ExternalReference;

  Isolate* isolate = masm->isolate();
  MemOperand next_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_next_address(isolate), no_reg);
  MemOperand limit_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_limit_address(isolate), no_reg);
  MemOperand level_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_level_address(isolate), no_reg);

  Register return_value = a0;
  Register scratch = a4;
  Register scratch2 = a5;

  // Allocate HandleScope in callee-saved registers.
  // We will need to restore the HandleScope after the call to the API function,
  // by allocating it in callee-saved registers it'll be preserved by C code.
  Register prev_next_address_reg = kScratchReg;
  Register prev_limit_reg = s1;
  Register prev_level_reg = s2;

  // C arguments (kCArgRegs[0/1]) are expected to be initialized outside, so
  // this function must not corrupt them (return_value overlaps with
  // kCArgRegs[0] but that's ok because we start using it only after the C
  // call).
  DCHECK(!AreAliased(kCArgRegs[0], kCArgRegs[1],  // C args
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  // function_address and thunk_arg might overlap but this function must not
  // corrupted them until the call is made (i.e. overlap with return_value is
  // fine).
  DCHECK(!AreAliased(function_address,  // incoming parameters
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  DCHECK(!AreAliased(thunk_arg,  // incoming parameters
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Allocate HandleScope in callee-save registers.");
    __ LoadWord(prev_next_address_reg, next_mem_op);
    __ LoadWord(prev_limit_reg, limit_mem_op);
    __ Lw(prev_level_reg, level_mem_op);
    __ Add32(scratch, prev_level_reg, Operand(1));
    __ Sw(scratch, level_mem_op);
  }

  Label profiler_or_side_effects_check_enabled, done_api_call;
  if (with_profiling) {
    __ RecordComment("Check if profiler or side effects check is enabled");
    __ Lb(scratch,
          __ ExternalReferenceAsOperand(IsolateFieldId::kExecutionMode));
    __ Branch(&profiler_or_side_effects_check_enabled, ne, scratch,
              Operand(zero_reg));
#ifdef V8_RUNTIME_CALL_STATS
    __ RecordComment("Check if RCS is enabled");
    __ li(scratch, ER::address_of_runtime_stats_flag());
    __ Lw(scratch, MemOperand(scratch, 0));
    __ Branch(&profiler_or_side_effects_check_enabled, ne, scratch,
              Operand(zero_reg));
#endif  // V8_RUNTIME_CALL_STATS
  }

  __ RecordComment("Call the api function directly.");
  __ StoreReturnAddressAndCall(function_address);
  __ bind(&done_api_call);

  Label propagate_exception;
  Label delete_allocated_handles;
  Label leave_exit_frame;

  __ RecordComment("Load the value from ReturnValue");
  __ LoadWord(return_value, return_value_operand);

  {
    ASM_CODE_COMMENT_STRING(
        masm,
        "No more valid handles (the result handle was the last one)."
        "Restore previous handle scope.");
    __ StoreWord(prev_next_address_reg, next_mem_op);
    if (v8_flags.debug_code) {
      __ Lw(scratch, level_mem_op);
      __ Sub32(scratch, scratch, Operand(1));
      __ Check(eq, AbortReason::kUnexpectedLevelAfterReturnFromApiCall, scratch,
               Operand(prev_level_reg));
    }
    __ Sw(prev_level_reg, level_mem_op);
    __ LoadWord(scratch, limit_mem_op);
    __ Branch(&delete_allocated_handles, ne, prev_limit_reg, Operand(scratch));
  }
  __ RecordComment("Leave the API exit frame.");
  __ bind(&leave_exit_frame);

  Register argc_reg = prev_limit_reg;
  if (argc_operand != nullptr) {
    // Load the number of stack slots to drop before LeaveExitFrame modifies sp.
    __ LoadWord(argc_reg, *argc_operand);
  }

  __ LeaveExitFrame(scratch);

  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Check if the function scheduled an exception.");
    __ LoadRoot(scratch, RootIndex::kTheHoleValue);
    __ LoadWord(scratch2, __ ExternalReferenceAsOperand(
                              ER::exception_address(isolate), no_reg));
    __ Branch(&propagate_exception, ne, scratch, Operand(scratch2));
  }

  __ AssertJSAny(return_value, scratch, scratch2,
                 AbortReason::kAPICallReturnedInvalidObject);

  if (argc_operand == nullptr) {
    DCHECK_NE(slots_to_drop_on_return, 0);
    __ AddWord(sp, sp, Operand(slots_to_drop_on_return * kSystemPointerSize));
  } else {
    // {argc_operand} was loaded into {argc_reg} above.
    if (slots_to_drop_on_return != 0) {
      __ AddWord(sp, sp, Operand(slots_t
"""


```