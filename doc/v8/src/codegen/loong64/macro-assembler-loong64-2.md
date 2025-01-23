Response: The user wants a summary of the C++ source code file `v8/src/codegen/loong64/macro-assembler-loong64.cc`. This is the third part of the file.

Based on the content of this part, it seems to focus on:

1. **Stack Frame Management:** Functions like `EnterExitFrame`, `LeaveExitFrame`, and `ActivationFrameAlignment` deal with setting up and tearing down stack frames for transitions between JavaScript and C++ code.
2. **Smi Handling:** Functions like `SmiUntag`, `JumpIfSmi`, and `JumpIfNotSmi` handle operations specific to Small Integers (Smis) in V8.
3. **Object Type Checking:** Functions like `JumpIfObjectType` and `JumpIfJSAnyIsNotPrimitive` are used to check the type of JavaScript objects.
4. **Assertions and Debugging:** Several `Assert` functions are used for runtime checks in debug builds.
5. **Floating-Point Operations:** Functions like `Float32Max`, `Float32Min`, `Float64Max`, and `Float64Min` implement maximum and minimum operations for floating-point numbers, handling NaN cases.
6. **C Function Calls:** Functions like `PrepareCallCFunction` and `CallCFunction` handle calling C++ functions from generated code.
7. **Code Object Handling:** Functions like `ComputeCodeStartAddress`, `CallCodeObject`, and `JumpCodeObject` deal with executing code objects in V8.
8. **JavaScript Function Calls:** Functions like `CallJSFunction` and `JumpJSFunction` handle calling JavaScript functions.
9. **Optimized Code Handling:** Functions related to tail calling optimized code and replacing closure code with optimized code.
10. **Tagged Field Access:** Functions like `LoadTaggedField` and `StoreTaggedField` are used to access fields of JavaScript objects, considering pointer compression.
11. **API Function Calls:** The `CallApiFunctionAndReturn` function handles calls to V8's C++ API from generated code.

The overall functionality seems to be providing low-level primitives for code generation on the LoongArch 64-bit architecture, specifically for interactions between JavaScript and the underlying C++ runtime.
这个C++源代码文件（`v8/src/codegen/loong64/macro-assembler-loong64.cc` 的第 3 部分）继续定义了 `MacroAssembler` 类的成员函数，这些函数提供了在 LoongArch64 架构上生成机器码的底层操作。以下是本部分功能点的归纳：

**核心功能延续：**

*   **栈帧管理 (Stack Frame Management):** 提供了进入和离开特定类型栈帧（如 ExitFrame）的函数 (`EnterExitFrame`, `LeaveExitFrame`)，用于在 JavaScript 代码和 C++ 代码之间切换时管理栈结构。
*   **Smi（小整数）处理 (Smi Handling):** 提供了对 Smi 进行解标签 (`SmiUntag`) 以及根据 Smi 类型进行跳转的函数 (`JumpIfSmi`, `JumpIfNotSmi`)。
*   **对象类型检查 (Object Type Checking):** 提供了根据对象类型进行条件跳转的函数 (`JumpIfObjectType`, `JumpIfJSAnyIsNotPrimitive`)，用于在运行时检查对象的类型。
*   **断言和调试 (Assertions and Debugging):**  定义了各种 `Assert` 函数，用于在调试模式下进行运行时检查，确保代码的预期行为。
*   **浮点数操作 (Floating-Point Operations):** 实现了浮点数的最大值和最小值运算 (`Float32Max`, `Float32Min`, `Float64Max`, `Float64Min`)，并处理了 NaN 的情况。
*   **C 函数调用 (C Function Calls):** 提供了准备调用 C 函数 (`PrepareCallCFunction`) 和实际调用 C 函数 (`CallCFunction`) 的功能，涉及到参数传递和栈对齐。

**新增或深入的功能点：**

*   **计算栈上传递的字数 (Calculate Stack Passed Words):**  `CalculateStackPassedWords` 函数用于计算调用 C 函数时需要通过栈传递的参数数量。
*   **调用 C 函数的辅助函数 (Call C Function Helper):** `CallCFunctionHelper` 是 `CallCFunction` 的底层实现，处理了调用 C 函数的细节，包括保存和恢复寄存器，以及处理可能的垃圾回收。
*   **检查页标志 (Check Page Flag):** `CheckPageFlag` 函数用于检查内存页的特定标志位，这通常与垃圾回收或内存管理相关。
*   **获取未使用的寄存器 (Get Register That Is Not One Of):** `GetRegisterThatIsNotOneOf` 函数用于获取一个当前未被使用的通用寄存器，避免寄存器冲突。
*   **计算代码起始地址 (Compute Code Start Address):** `ComputeCodeStartAddress` 函数用于计算当前代码块的起始地址。
*   **为反优化调用 (Call For Deoptimization):** `CallForDeoptimization` 函数用于在需要反优化时调用相应的内置函数。
*   **加载代码指令起始地址 (Load Code Instruction Start):** `LoadCodeInstructionStart` 函数用于加载 Code 对象的指令起始地址，这是执行代码的前提。
*   **调用和跳转到代码对象 (Call/Jump Code Object):** `CallCodeObject` 和 `JumpCodeObject` 函数用于调用或跳转到指定的 Code 对象执行。
*   **调用和跳转到 JavaScript 函数 (Call/Jump JS Function):** `CallJSFunction` 和 `JumpJSFunction` 函数用于调用或跳转到 JavaScript 函数，并考虑了 leaptiering (如果启用)。
*   **尾调用优化代码槽 (Tail Call Optimized Code Slot):**  定义了在优化代码可用时进行尾调用的逻辑 (`TailCallOptimizedCodeSlot`)，以及在优化代码失效时进行处理的逻辑。
*   **生成尾调用到返回的代码 (Generate Tail Call To Returned Code):** `GenerateTailCallToReturnedCode` 函数用于生成一个尾调用，通常用于调用运行时函数。
*   **加载反馈向量标志并根据需要跳转 (Load Feedback Vector Flags And Jump If Needs Processing):**  `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing` 函数用于检查反馈向量中的标志，判断是否需要进行进一步的处理，例如优化或日志记录。
*   **优化代码或尾调用优化代码槽 (Optimize Code Or Tail Call Optimized Code Slot):** `OptimizeCodeOrTailCallOptimizedCodeSlot` 函数根据反馈向量的标志决定是调用优化编译器还是直接尾调用已存在的优化代码。
*   **加载和存储带标签的字段 (Load/Store Tagged Field):** 提供了加载 (`LoadTaggedField`, `LoadTaggedSignedField`) 和存储 (`StoreTaggedField`, `AtomicStoreTaggedField`) JavaScript 对象字段的函数，考虑了指针压缩的情况。
*   **解压缩带标签的指针 (Decompress Tagged):** 提供了对压缩指针进行解压缩的函数 (`DecompressTagged`, `DecompressTaggedSigned`, `AtomicDecompressTagged`, `AtomicDecompressTaggedSigned`)。
*   **调用 API 函数并返回 (Call Api Function And Return):** `CallApiFunctionAndReturn` 函数处理从生成的代码中调用 V8 的 C++ API 函数，包括处理 HandleScope、返回值和异常。

**与 JavaScript 功能的关系：**

这个文件中的函数是 V8 引擎将 JavaScript 代码转换为机器码的关键部分。它提供了执行各种 JavaScript 操作所需的底层指令序列。以下是一些与 JavaScript 功能相关的示例：

*   **函数调用:** `CallJSFunction` 和 `JumpJSFunction` 直接支持 JavaScript 函数的调用和跳转。例如，当 JavaScript 代码中调用一个函数时，V8 会生成使用这些函数的机器码。

    ```javascript
    function myFunction(a, b) {
      return a + b;
    }

    myFunction(5, 10); // 这会触发 CallJSFunction 相关的机器码生成
    ```

*   **对象属性访问:**  虽然这部分代码没有直接展示属性访问的汇编生成，但 `LoadTaggedField` 和 `StoreTaggedField` 是实现对象属性读取和写入的基础。例如，访问 `object.property` 或 `object.property = value` 时，会生成使用这些函数的机器码。

    ```javascript
    const obj = { x: 10 };
    const value = obj.x; // 这会涉及到 LoadTaggedField 相关的机器码生成
    obj.y = 20;        // 这会涉及到 StoreTaggedField 相关的机器码生成
    ```

*   **类型检查:** `JumpIfObjectType` 和 `JumpIfJSAnyIsNotPrimitive` 用于实现 JavaScript 中的类型检查，例如 `typeof` 运算符或判断一个值是否为原始值。

    ```javascript
    function isNumber(value) {
      return typeof value === 'number'; // 这会触发 JumpIfObjectType 相关的机器码生成
    }

    isNumber(123);
    ```

*   **算术运算:** `Float32Max`, `Float32Min`, `Float64Max`, `Float64Min` 用于实现 JavaScript 中的 `Math.max()` 和 `Math.min()` 等函数。

    ```javascript
    const maxVal = Math.max(3.14, 2.71); // 这会触发 Float64Max 相关的机器码生成
    ```

*   **与 C++ 扩展交互:**  `CallApiFunctionAndReturn` 用于调用 V8 提供的 C++ API，这允许 JavaScript 代码与底层的 C++ 模块进行交互，例如使用 `node.js` 的原生模块。

    ```javascript
    // 假设有一个 C++ 扩展提供了名为 'myExtensionFunction' 的函数
    const result = nativeBinding.myExtensionFunction(arg1, arg2); // 这会触发 CallApiFunctionAndReturn 相关的机器码生成
    ```

总而言之，这个文件是 V8 引擎在 LoongArch64 架构上将 JavaScript 代码高效转换为可执行机器码的关键组成部分，它提供了构建更高级 JavaScript 功能所需的各种底层操作。

### 提示词
```
这是目录为v8/src/codegen/loong64/macro-assembler-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```
terSize));
  Ld_d(fp, MemOperand(fp, 0 * kSystemPointerSize));
}

void MacroAssembler::EnterExitFrame(Register scratch, int stack_space,
                                    StackFrame::Type frame_type) {
  ASM_CODE_COMMENT(this);
  DCHECK(frame_type == StackFrame::EXIT ||
         frame_type == StackFrame::BUILTIN_EXIT ||
         frame_type == StackFrame::API_ACCESSOR_EXIT ||
         frame_type == StackFrame::API_CALLBACK_EXIT);

  using ER = ExternalReference;

  // Set up the frame structure on the stack.
  static_assert(2 * kSystemPointerSize ==
                ExitFrameConstants::kCallerSPDisplacement);
  static_assert(1 * kSystemPointerSize == ExitFrameConstants::kCallerPCOffset);
  static_assert(0 * kSystemPointerSize == ExitFrameConstants::kCallerFPOffset);

  // This is how the stack will look:
  // fp + 2 (==kCallerSPDisplacement) - old stack's end
  // [fp + 1 (==kCallerPCOffset)] - saved old ra
  // [fp + 0 (==kCallerFPOffset)] - saved old fp
  // [fp - 1 frame_type Smi
  // [fp - 2 (==kSPOffset)] - sp of the called function
  // fp - (2 + stack_space + alignment) == sp == [fp - kSPOffset] - top of the
  //   new stack (will contain saved ra)

  // Save registers and reserve room for saved entry sp.
  addi_d(sp, sp,
         -2 * kSystemPointerSize - ExitFrameConstants::kFixedFrameSizeFromFp);
  St_d(ra, MemOperand(sp, 3 * kSystemPointerSize));
  St_d(fp, MemOperand(sp, 2 * kSystemPointerSize));
  li(scratch, Operand(StackFrame::TypeToMarker(frame_type)));
  St_d(scratch, MemOperand(sp, 1 * kSystemPointerSize));

  // Set up new frame pointer.
  addi_d(fp, sp, ExitFrameConstants::kFixedFrameSizeFromFp);

  if (v8_flags.debug_code) {
    St_d(zero_reg, MemOperand(fp, ExitFrameConstants::kSPOffset));
  }

  // Save the frame pointer and the context in top.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  St_d(fp, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  St_d(cp, ExternalReferenceAsOperand(context_address, no_reg));

  const int frame_alignment = MacroAssembler::ActivationFrameAlignment();

  // Reserve place for the return address, stack space and align the frame
  // preparing for calling the runtime function.
  DCHECK_GE(stack_space, 0);
  Sub_d(sp, sp, Operand((stack_space + 1) * kSystemPointerSize));
  if (frame_alignment > 0) {
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    And(sp, sp, Operand(-frame_alignment));  // Align stack.
  }

  // Set the exit frame sp value to point just before the return address
  // location.
  addi_d(scratch, sp, kSystemPointerSize);
  St_d(scratch, MemOperand(fp, ExitFrameConstants::kSPOffset));
}

void MacroAssembler::LeaveExitFrame(Register scratch) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);

  using ER = ExternalReference;

  // Restore current context from top and clear it in debug mode.
  ER context_address = ER::Create(IsolateAddressId::kContextAddress, isolate());
  Ld_d(cp, ExternalReferenceAsOperand(context_address, no_reg));

  if (v8_flags.debug_code) {
    li(scratch, Operand(Context::kInvalidContext));
    St_d(scratch, ExternalReferenceAsOperand(context_address, no_reg));
  }

  // Clear the top frame.
  ER c_entry_fp_address =
      ER::Create(IsolateAddressId::kCEntryFPAddress, isolate());
  St_d(zero_reg, ExternalReferenceAsOperand(c_entry_fp_address, no_reg));

  // Pop the arguments, restore registers, and return.
  mov(sp, fp);  // Respect ABI stack constraint.
  Ld_d(fp, MemOperand(sp, ExitFrameConstants::kCallerFPOffset));
  Ld_d(ra, MemOperand(sp, ExitFrameConstants::kCallerPCOffset));
  addi_d(sp, sp, 2 * kSystemPointerSize);
}

int MacroAssembler::ActivationFrameAlignment() {
#if V8_HOST_ARCH_LOONG64
  // Running on the real platform. Use the alignment as mandated by the local
  // environment.
  // Note: This will break if we ever start generating snapshots on one LOONG64
  // platform for another LOONG64 platform with a different alignment.
  return base::OS::ActivationFrameAlignment();
#else   // V8_HOST_ARCH_LOONG64
  // If we are using the simulator then we should always align to the expected
  // alignment. As the simulator is used to generate snapshots we do not know
  // if the target platform will need alignment, so this is controlled from a
  // flag.
  return v8_flags.sim_stack_alignment;
#endif  // V8_HOST_ARCH_LOONG64
}

void MacroAssembler::SmiUntag(Register dst, const MemOperand& src) {
  if (SmiValuesAre32Bits()) {
    Ld_w(dst, MemOperand(src.base(), SmiWordOffset(src.offset())));
  } else {
    DCHECK(SmiValuesAre31Bits());
    if (COMPRESS_POINTERS_BOOL) {
      Ld_w(dst, src);
    } else {
      Ld_d(dst, src);
    }
    SmiUntag(dst);
  }
}

void MacroAssembler::JumpIfSmi(Register value, Label* smi_label) {
  DCHECK_EQ(0, kSmiTag);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  andi(scratch, value, kSmiTagMask);
  Branch(smi_label, eq, scratch, Operand(zero_reg));
}

void MacroAssembler::JumpIfNotSmi(Register value, Label* not_smi_label) {
  DCHECK_EQ(0, kSmiTag);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  andi(scratch, value, kSmiTagMask);
  Branch(not_smi_label, ne, scratch, Operand(zero_reg));
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

#ifdef V8_ENABLE_DEBUG_CODE

void MacroAssembler::Assert(Condition cc, AbortReason reason, Register rs,
                            Operand rk) {
  if (v8_flags.debug_code) Check(cc, reason, rs, rk);
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

void MacroAssembler::AssertNotSmi(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    static_assert(kSmiTag == 0);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    andi(scratch, object, kSmiTagMask);
    Check(ne, AbortReason::kOperandIsASmi, scratch, Operand(zero_reg));
  }
}

void MacroAssembler::AssertSmi(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    static_assert(kSmiTag == 0);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    andi(scratch, object, kSmiTagMask);
    Check(eq, AbortReason::kOperandIsASmi, scratch, Operand(zero_reg));
  }
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
        Branch(&alignment_as_expected, eq, scratch, Operand(zero_reg));
      }
      // Don't use Check here, as it will call Runtime_Abort re-entering here.
      stop();
      bind(&alignment_as_expected);
    }
  }
}

void MacroAssembler::AssertConstructor(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotAConstructor, t8,
          Operand(zero_reg));

    LoadMap(t8, object);
    Ld_bu(t8, FieldMemOperand(t8, Map::kBitFieldOffset));
    And(t8, t8, Operand(Map::Bits1::IsConstructorBit::kMask));
    Check(ne, AbortReason::kOperandIsNotAConstructor, t8, Operand(zero_reg));
  }
}

void MacroAssembler::AssertFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, t8,
          Operand(zero_reg));
    Push(object);
    LoadMap(object, object);
    GetInstanceTypeRange(object, object, FIRST_JS_FUNCTION_TYPE, t8);
    Check(ls, AbortReason::kOperandIsNotAFunction, t8,
          Operand(LAST_JS_FUNCTION_TYPE - FIRST_JS_FUNCTION_TYPE));
    Pop(object);
  }
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, t8,
          Operand(zero_reg));
    Push(object);
    LoadMap(object, object);
    GetInstanceTypeRange(object, object, FIRST_CALLABLE_JS_FUNCTION_TYPE, t8);
    Check(ls, AbortReason::kOperandIsNotACallableFunction, t8,
          Operand(LAST_CALLABLE_JS_FUNCTION_TYPE -
                  FIRST_CALLABLE_JS_FUNCTION_TYPE));
    Pop(object);
  }
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    static_assert(kSmiTag == 0);
    SmiTst(object, t8);
    Check(ne, AbortReason::kOperandIsASmiAndNotABoundFunction, t8,
          Operand(zero_reg));
    GetObjectType(object, t8, t8);
    Check(eq, AbortReason::kOperandIsNotABoundFunction, t8,
          Operand(JS_BOUND_FUNCTION_TYPE));
  }
}

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  static_assert(kSmiTag == 0);
  SmiTst(object, t8);
  Check(ne, AbortReason::kOperandIsASmiAndNotAGeneratorObject, t8,
        Operand(zero_reg));
  GetObjectType(object, t8, t8);
  Sub_d(t8, t8, Operand(FIRST_JS_GENERATOR_OBJECT_TYPE));
  Check(
      ls, AbortReason::kOperandIsNotAGeneratorObject, t8,
      Operand(LAST_JS_GENERATOR_OBJECT_TYPE - FIRST_JS_GENERATOR_OBJECT_TYPE));
}

void MacroAssembler::AssertUnreachable(AbortReason reason) {
  if (v8_flags.debug_code) Abort(reason);
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object,
                                                     Register scratch) {
  if (v8_flags.debug_code) {
    ASM_CODE_COMMENT(this);
    Label done_checking;
    AssertNotSmi(object);
    LoadRoot(scratch, RootIndex::kUndefinedValue);
    Branch(&done_checking, eq, object, Operand(scratch));
    GetObjectType(object, scratch, scratch);
    Assert(eq, AbortReason::kExpectedUndefinedOrCell, scratch,
           Operand(ALLOCATION_SITE_TYPE));
    bind(&done_checking);
  }
}

#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::Float32Max(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_s(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF32(src1, src2);
  BranchTrueF(out_of_line);

  fmax_s(dst, src1, src2);
}

void MacroAssembler::Float32MaxOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  fadd_s(dst, src1, src2);
}

void MacroAssembler::Float32Min(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_s(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF32(src1, src2);
  BranchTrueF(out_of_line);

  fmin_s(dst, src1, src2);
}

void MacroAssembler::Float32MinOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  fadd_s(dst, src1, src2);
}

void MacroAssembler::Float64Max(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_d(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF64(src1, src2);
  BranchTrueF(out_of_line);

  fmax_d(dst, src1, src2);
}

void MacroAssembler::Float64MaxOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  fadd_d(dst, src1, src2);
}

void MacroAssembler::Float64Min(FPURegister dst, FPURegister src1,
                                FPURegister src2, Label* out_of_line) {
  ASM_CODE_COMMENT(this);
  if (src1 == src2) {
    Move_d(dst, src1);
    return;
  }

  // Check if one of operands is NaN.
  CompareIsNanF64(src1, src2);
  BranchTrueF(out_of_line);

  fmin_d(dst, src1, src2);
}

void MacroAssembler::Float64MinOutOfLine(FPURegister dst, FPURegister src1,
                                         FPURegister src2) {
  fadd_d(dst, src1, src2);
}

int MacroAssembler::CalculateStackPassedWords(int num_reg_arguments,
                                              int num_double_arguments) {
  int stack_passed_words = 0;

  // Up to eight simple arguments are passed in registers a0..a7.
  if (num_reg_arguments > kRegisterPassedArguments) {
    stack_passed_words += num_reg_arguments - kRegisterPassedArguments;
  }
  if (num_double_arguments > kFPRegisterPassedArguments) {
    int num_count = num_double_arguments - kFPRegisterPassedArguments;
    if (num_reg_arguments >= kRegisterPassedArguments) {
      stack_passed_words += num_count;
    } else if (num_count > kRegisterPassedArguments - num_reg_arguments) {
      stack_passed_words +=
          num_count - (kRegisterPassedArguments - num_reg_arguments);
    }
  }
  return stack_passed_words;
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          int num_double_arguments,
                                          Register scratch) {
  ASM_CODE_COMMENT(this);
  int frame_alignment = ActivationFrameAlignment();

  // Up to eight simple arguments in a0..a3, a4..a7, No argument slots.
  // Remaining arguments are pushed on the stack.
  int stack_passed_arguments =
      CalculateStackPassedWords(num_reg_arguments, num_double_arguments);
  if (frame_alignment > kSystemPointerSize) {
    // Make stack end at alignment and make room for num_arguments - 4 words
    // and the original value of sp.
    mov(scratch, sp);
    Sub_d(sp, sp, Operand((stack_passed_arguments + 1) * kSystemPointerSize));
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    bstrins_d(sp, zero_reg, std::log2(frame_alignment) - 1, 0);
    St_d(scratch, MemOperand(sp, stack_passed_arguments * kSystemPointerSize));
  } else {
    Sub_d(sp, sp, Operand(stack_passed_arguments * kSystemPointerSize));
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
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  li(t7, function);
  return CallCFunctionHelper(t7, num_reg_arguments, num_double_arguments,
                             set_isolate_data_slots, return_location);
}

int MacroAssembler::CallCFunction(Register function, int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  Label* return_location) {
  ASM_CODE_COMMENT(this);
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

  Label get_pc;

  // Make sure that the stack is aligned before calling a C function unless
  // running in the simulator. The simulator has its own alignment check which
  // provides more information.

#if V8_HOST_ARCH_LOONG64
  if (v8_flags.debug_code) {
    int frame_alignment = base::OS::ActivationFrameAlignment();
    int frame_alignment_mask = frame_alignment - 1;
    if (frame_alignment > kSystemPointerSize) {
      DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
      Label alignment_as_expected;
      {
        Register scratch = t8;
        And(scratch, sp, Operand(frame_alignment_mask));
        Branch(&alignment_as_expected, eq, scratch, Operand(zero_reg));
      }
      // Don't use Check here, as it will call Runtime_Abort possibly
      // re-entering here.
      stop();
      bind(&alignment_as_expected);
    }
  }
#endif  // V8_HOST_ARCH_LOONG64

  // Just call directly. The function called cannot cause a GC, or
  // allow preemption, so the return address in the link register
  // stays correct.
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
      if (function != t7) {
        mov(t7, function);
        function = t7;
      }

      // Save the frame pointer and PC so that the stack layout remains
      // iterable, even without an ExitFrame which normally exists between JS
      // and C frames. 't' registers are caller-saved so this is safe as a
      // scratch register.
      Register pc_scratch = t1;
      DCHECK(!AreAliased(pc_scratch, function));
      CHECK(root_array_available());

      LoadLabelRelative(pc_scratch, &get_pc);

      St_d(pc_scratch,
           ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC));
      St_d(fp, ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
    }

    Call(function);
    int call_pc_offset = pc_offset();
    bind(&get_pc);
    if (return_location) bind(return_location);

    if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
      // We don't unset the PC; the FP is the source of truth.
      St_d(zero_reg,
           ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
    }

    int stack_passed_arguments =
        CalculateStackPassedWords(num_reg_arguments, num_double_arguments);

    if (base::OS::ActivationFrameAlignment() > kSystemPointerSize) {
      Ld_d(sp, MemOperand(sp, stack_passed_arguments * kSystemPointerSize));
    } else {
      Add_d(sp, sp, Operand(stack_passed_arguments * kSystemPointerSize));
    }

    set_pc_for_safepoint();

    return call_pc_offset;
  }
}

#undef BRANCH_ARGS_CHECK

void MacroAssembler::CheckPageFlag(Register object, int mask, Condition cc,
                                   Label* condition_met) {
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  temps.Include(t8);
  Register scratch = temps.Acquire();
  And(scratch, object, Operand(~MemoryChunk::GetAlignmentMaskForAssembler()));
  Ld_d(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()));
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
  // TODO(LOONG_dev): range check, add Pcadd macro function?
  pcaddi(dst, -pc_offset() >> 2);
}

void MacroAssembler::CallForDeoptimization(Builtin target, int, Label* exit,
                                           DeoptimizeKind kind, Label* ret,
                                           Label*) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Ld_d(t7,
       MemOperand(kRootRegister, IsolateData::BuiltinEntrySlotOffset(target)));
  Call(t7);
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
  Ld_d(destination,
       FieldMemOperand(code_object, Code::kInstructionStartOffset));
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
  // TODO(saelo): can we avoid using this for JavaScript functions
  // (kJSEntrypointTag) and instead use a variant that ensures that the caller
  // and callee agree on the signature (i.e. parameter count)?
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(JumpMode::kJump, jump_mode);
  LoadCodeInstructionStart(code_object, code_object, tag);
  Jump(code_object);
}

void MacroAssembler::CallJSFunction(Register function_object,
                                    uint16_t argument_count) {
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_LEAPTIERING
  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  Register parameter_count = s1;
  Register scratch = s2;

  Ld_w(dispatch_handle,
       FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointAndParameterCountFromJSDispatchTable(code, parameter_count,
                                                     dispatch_handle, scratch);

  // Force a safe crash if the parameter count doesn't match.
  SbxCheck(le, AbortReason::kJSSignatureMismatch, parameter_count,
           Operand(argument_count));
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
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_LEAPTIERING
  Register dispatch_handle = kJavaScriptCallDispatchHandleRegister;
  Register scratch = s1;
  Ld_w(dispatch_handle,
       FieldMemOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointFromJSDispatchTable(code, dispatch_handle, scratch);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  Jump(code);
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  Jump(code);
#else
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  JumpCodeObject(code, kJSEntrypointTag, jump_mode);
#endif
}

namespace {

#ifndef V8_ENABLE_LEAPTIERING
// Only used when leaptiering is disabled.
void TailCallOptimizedCodeSlot(MacroAssembler* masm,
                               Register optimized_code_entry) {
  // ----------- S t a t e -------------
  //  -- a0 : actual argument count
  //  -- a3 : new target (preserved for callee if needed, and caller)
  //  -- a1 : target function (preserved for callee if needed, and caller)
  // -----------------------------------
  DCHECK(!AreAliased(optimized_code_entry, a1, a3));

  Label heal_optimized_code_slot;

  // If the optimized code is cleared, go to runtime to update the optimization
  // marker field.
  __ LoadWeakValue(optimized_code_entry, optimized_code_entry,
                   &heal_optimized_code_slot);

  // The entry references a CodeWrapper object. Unwrap it now.
  __ LoadCodePointerField(
      optimized_code_entry,
      FieldMemOperand(optimized_code_entry, CodeWrapper::kCodeOffset));

  // Check if the optimized code is marked for deopt. If it is, call the
  // runtime to clear it.
  __ TestCodeIsMarkedForDeoptimizationAndJump(optimized_code_entry, a6, ne,
                                              &heal_optimized_code_slot);

  // Optimized code is good, get it into the closure and link the closure into
  // the optimized functions list, then tail call the optimized code.
  // The feedback vector is no longer used, so re-use it as a scratch
  // register.
  __ ReplaceClosureCodeWithOptimizedCode(optimized_code_entry, a1);

  static_assert(kJavaScriptCallCodeStartRegister == a2, "ABI mismatch");
  __ LoadCodeInstructionStart(a2, optimized_code_entry, kJSEntrypointTag);
  __ Jump(a2);

  // Optimized code slot contains deoptimized code or code is cleared and
  // optimized code marker isn't updated. Evict the code, update the marker
  // and re-enter the closure's code.
  __ bind(&heal_optimized_code_slot);
  __ GenerateTailCallToReturnedCode(Runtime::kHealOptimizedCodeSlot);
}
#endif  // V8_ENABLE_LEAPTIERING

}  // namespace

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertFeedbackCell(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    GetObjectType(object, scratch, scratch);
    Assert(eq, AbortReason::kExpectedFeedbackCell, scratch,
           Operand(FEEDBACK_CELL_TYPE));
  }
}
void MacroAssembler::AssertFeedbackVector(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    GetObjectType(object, scratch, scratch);
    Assert(eq, AbortReason::kExpectedFeedbackVector, scratch,
           Operand(FEEDBACK_VECTOR_TYPE));
  }
}
#endif  // V8_ENABLE_DEBUG_CODE

void MacroAssembler::ReplaceClosureCodeWithOptimizedCode(
    Register optimized_code, Register closure) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(optimized_code, closure));

#ifdef V8_ENABLE_LEAPTIERING
  UNREACHABLE();
#else
  // Store code entry in the closure.
  StoreCodePointerField(optimized_code,
                        FieldMemOperand(closure, JSFunction::kCodeOffset));
  RecordWriteField(closure, JSFunction::kCodeOffset, optimized_code,
                   kRAHasNotBeenSaved, SaveFPRegsMode::kIgnore, SmiCheck::kOmit,
                   SlotDescriptor::ForCodePointerSlot());
#endif  // V8_ENABLE_LEAPTIERING
}

void MacroAssembler::GenerateTailCallToReturnedCode(
    Runtime::FunctionId function_id) {
  ASM_CODE_COMMENT(this);
  // ----------- S t a t e -------------
  //  -- a0 : actual argument count (preserved for callee)
  //  -- a1 : target function (preserved for callee)
  //  -- a3 : new target (preserved for callee)
  //  -- a4 : dispatch handle (preserved for callee)
  // -----------------------------------
  {
    FrameScope scope(this, StackFrame::INTERNAL);
    // Push a copy of the target function, the new target, the actual
    // argument count, and the dispatch handle.
    // Push function as parameter to the runtime call.
    SmiTag(kJavaScriptCallArgCountRegister);
    Push(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
         kJavaScriptCallArgCountRegister);
#ifdef V8_ENABLE_LEAPTIERING
    // No need to SmiTag since dispatch handles always look like Smis.
    static_assert(kJSDispatchHandleShift > 0);
    Push(kJavaScriptCallDispatchHandleRegister);
#endif
    // Function is also the parameter to the runtime call.
    Push(kJavaScriptCallTargetRegister);

    CallRuntime(function_id, 1);
    LoadCodeInstructionStart(a2, a0, kJSEntrypointTag);

    // Restore target function, new target, actual argument count and dispatch
    // handle.
#ifdef V8_ENABLE_LEAPTIERING
    Pop(kJavaScriptCallDispatchHandleRegister);
#endif
    Pop(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
        kJavaScriptCallArgCountRegister);
    SmiUntag(kJavaScriptCallArgCountRegister);
  }

  static_assert(kJavaScriptCallCodeStartRegister == a2, "ABI mismatch");
  Jump(a2);
}

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
void MacroAssembler::LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind,
    Label* flags_need_processing) {
  ASM_CODE_COMMENT(this);
  Register scratch = t2;
  DCHECK(!AreAliased(t2, flags, feedback_vector));
  DCHECK(CodeKindCanTierUp(current_code_kind));
  uint32_t flag_mask =
      FeedbackVector::FlagMaskForNeedsProcessingCheckFrom(current_code_kind);
  Ld_hu(flags, FieldMemOperand(feedback_vector, FeedbackVector::kFlagsOffset));
  And(scratch, flags, Operand(flag_mask));
  Branch(flags_need_processing, ne, scratch, Operand(zero_reg));
}

void MacroAssembler::OptimizeCodeOrTailCallOptimizedCodeSlot(
    Register flags, Register feedback_vector) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
#ifdef V8_ENABLE_LEAPTIERING
  // In the leaptiering case, we don't load optimized code from the feedback
  // vector so only need to call CompileOptimized or FunctionLogNextExecution
  // here. See also LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing above.
  Label needs_logging;
  {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    And(scratch, flags,
        Operand(FeedbackVector::kFlagsTieringStateIsAnyRequested));
    Branch(&needs_logging, eq, scratch, Operand(zero_reg));
  }

  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized);

  bind(&needs_logging);
  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution);
#else
  Label maybe_has_optimized_code, maybe_needs_logging;
  // Check if optimized code marker is available.
  {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    And(scratch, flags,
        Operand(FeedbackVector::kFlagsTieringStateIsAnyRequested));
    Branch(&maybe_needs_logging, eq, scratch, Operand(zero_reg));
  }

  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized);

  bind(&maybe_needs_logging);
  {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    And(scratch, flags, Operand(FeedbackVector::LogNextExecutionBit::kMask));
    Branch(&maybe_has_optimized_code, eq, scratch, Operand(zero_reg));
  }

  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution);

  bind(&maybe_has_optimized_code);
  Register optimized_code_entry = flags;
  LoadTaggedField(optimized_code_entry,
                  FieldMemOperand(feedback_vector,
                                  FeedbackVector::kMaybeOptimizedCodeOffset));

  TailCallOptimizedCodeSlot(this, optimized_code_entry);
#endif  // V8_ENABLE_LEAPTIERING
}

void MacroAssembler::LoadTaggedField(Register destination,
                                     const MemOperand& field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTagged(destination, field_operand);
  } else {
    Ld_d(destination, field_operand);
  }
}

void MacroAssembler::LoadTaggedSignedField(Register destination,
                                           const MemOperand& field_operand) {
  if (COMPRESS_POINTERS_BOOL) {
    DecompressTaggedSigned(destination, field_operand);
  } else {
    Ld_d(destination, field_operand);
  }
}

void MacroAssembler::SmiUntagField(Register dst, const MemOperand& src) {
  SmiUntag(dst, src);
}

void MacroAssembler::StoreTaggedField(Register src, const MemOperand& dst) {
  if (COMPRESS_POINTERS_BOOL) {
    St_w(src, dst);
  } else {
    St_d(src, dst);
  }
}

void MacroAssembler::AtomicStoreTaggedField(Register src,
                                            const MemOperand& dst) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Add_d(scratch, dst.base(), dst.offset());
  if (COMPRESS_POINTERS_BOOL) {
    amswap_db_w(zero_reg, src, scratch);
  } else {
    amswap_db_d(zero_reg, src, scratch);
  }
}

void MacroAssembler::DecompressTaggedSigned(Register dst,
                                            const MemOperand& src) {
  ASM_CODE_COMMENT(this);
  Ld_wu(dst, src);
  if (v8_flags.debug_code) {
    //  Corrupt the top 32 bits. Made up of 16 fixed bits and 16 pc offset bits.
    Add_d(dst, dst, ((kDebugZapValue << 16) | (pc_offset() & 0xffff)) << 32);
  }
}

void MacroAssembler::DecompressTagged(Register dst, const MemOperand& src) {
  ASM_CODE_COMMENT(this);
  Ld_wu(dst, src);
  Add_d(dst, kPtrComprCageBaseRegister, dst);
}

void MacroAssembler::DecompressTagged(Register dst, Register src) {
  ASM_CODE_COMMENT(this);
  Bstrpick_d(dst, src, 31, 0);
  Add_d(dst, kPtrComprCageBaseRegister, Operand(dst));
}

void MacroAssembler::DecompressTagged(Register dst, Tagged_t immediate) {
  ASM_CODE_COMMENT(this);
  Add_d(dst, kPtrComprCageBaseRegister, static_cast<int32_t>(immediate));
}

void MacroAssembler::DecompressProtected(const Register& destination,
                                         const MemOperand& field_operand) {
#if V8_ENABLE_SANDBOX
  ASM_CODE_COMMENT(this);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Ld_wu(destination, field_operand);
  Ld_d(scratch,
       MemOperand(kRootRegister, IsolateData::trusted_cage_base_offset()));
  Or(destination, destination, scratch);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

void MacroAssembler::AtomicDecompressTaggedSigned(Register dst,
                                                  const MemOperand& src) {
  ASM_CODE_COMMENT(this);
  Ld_wu(dst, src);
  dbar(0);
  if (v8_flags.debug_code) {
    // Corrupt the top 32 bits. Made up of 16 fixed bits and 16 pc offset bits.
    Add_d(dst, dst, ((kDebugZapValue << 16) | (pc_offset() & 0xffff)) << 32);
  }
}

void MacroAssembler::AtomicDecompressTagged(Register dst,
                                            const MemOperand& src) {
  ASM_CODE_COMMENT(this);
  Ld_wu(dst, src);
  dbar(0);
  Add_d(dst, kPtrComprCageBaseRegister, dst);
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
  Register prev_next_address_reg = s0;
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
    __ Ld_d(prev_next_address_reg, next_mem_op);
    __ Ld_d(prev_limit_reg, limit_mem_op);
    __ Ld_w(prev_level_reg, level_mem_op);
    __ Add_w(scratch, prev_level_reg, Operand(1));
    __ St_w(scratch, level_mem_op);
  }

  Label profiler_or_side_effects_check_enabled, done_api_call;
  if (with_profiling) {
    __ RecordComment("Check if profiler or side effects check is enabled");
    __ Ld_b(scratch,
            __ ExternalReferenceAsOperand(IsolateFieldId::kExecutionMode));
    __ Branch(&profiler_or_side_effects_check_enabled, ne, scratch,
              Operand(zero_reg));
#ifdef V8_RUNTIME_CALL_STATS
    __ RecordComment("Check if RCS is enabled");
    __ li(scratch, ER::address_of_runtime_stats_flag());
    __ Ld_w(scratch, MemOperand(scratch, 0));
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
  __ Ld_d(return_value, return_value_operand);

  {
    ASM_CODE_COMMENT_STRING(
        masm,
        "No more valid handles (the result handle was the last one)."
        "Restore previous handle scope.");
    __ St_d(prev_next_address_reg, next_mem_op);
    if (v8_flags.debug_code) {
      __ Ld_w(scratch, level_mem_op);
      __ Sub_w(scratch, scratch, Operand(1));
      __ Check(eq, AbortReason::kUnexpectedLevelAfterReturnFromApiCall, scratch,
               Operand(prev_level_reg));
    }
    __ St_w(prev_level_reg, level_mem_op);
    __ Ld_d(scratch, limit_mem_op);
    __ Branch(&delete_allocated_handles, ne, prev_limit_reg, Operand(scratch));
  }

  __ RecordComment("Leave the API exit frame.");
  __ bind(&leave_exit_frame);

  Register argc_reg = prev_limit_reg;
  if (argc_operand != nullptr) {
    // Load the number of stack slots to drop before LeaveExitFrame modifies sp.
    __ Ld_d(argc_reg, *argc_operand);
  }

  __ LeaveExitFrame(scratch);

  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Check if the function scheduled an exception.");
    __ LoadRoot(scratch, RootIndex::kTheHoleValue);
    __ Ld_d(scratch2, __ ExternalReferenceAsOperand(
                          ER::exception_address(isolate), no_reg));
    __ Branch(&propagate_exception, ne, scratch, Operand(scratch2));
  }

  __ AssertJSAny(return_value, scratch, scratch2,
                 AbortReason::kAPICallReturnedInvalidObject);

  if (argc_operand == nullptr) {
    DCHECK_NE(slots_to_drop_on_return, 0);
    __ Add_d(sp, sp, Operand(slots_to_drop_on_return * kSystemPointerSize));
  } else {
    // {argc_operand} was loaded into {argc_reg} above.
    if (slots_to_drop_on_return != 0) {
      __ Add_d(sp, sp, Operand(slots_to_drop_on_return * kSystemPointerSize));
    }
    __ Alsl_d(sp, argc_reg, sp, kSystemPointerSizeLog2);
  }

  __ Ret();

  if (with_profiling) {
    ASM_CODE_COMMENT_STRING(masm, "Call the api function via thunk wrapper.");
    __ bind(&profiler_or_side_effects_check_enabled);
    // Additional parameter is the address of the actual callback function.
    if (thunk_arg.is_valid()) {
      MemOperand thunk_arg_mem_op = __ ExternalReferenceAsOperand(
          IsolateFieldId::kApiCallbackThunkArgument);
      __ St_d(thunk_arg, thunk_arg_mem_op);
    }
    __ li(scratch, thunk_ref);
    __ StoreReturnAddressAndCall(scratch);
    __ Branch(&done_api_call);
  }

  __ RecordComment("An exception was thrown. Propagate it.");
  __ bind(&propagate_exception);
  __ TailCallRuntime(Runtime::kPropagateException);

  {
    ASM_CODE_COMMENT_STRING(
        masm, "HandleScope limit has changed. Delete allocated extensions.");
    __ bind(&delete_allocated_handles);
    __ St_d(prev_limit_reg, limit_mem_op);
    // Save the return value in a callee-save register.
    Register saved_result = prev_limit_reg;
    __ mov(saved_result, a0);
    __ PrepareCallCFunction(1, prev_level_reg);
    __ li(kCArgRegs[0], ER::isolate_address());
    __ CallCFunction(ER::delete_handle_scope_extensions(), 1);
    __ mov(kCArgRegs[0], saved_result);
    __ jmp(&leave_exit_frame);
  }
}

}  // namespace internal
}  // namespace v8

#undef __

#endif  // V8_TARGET_ARCH_LOONG64
```