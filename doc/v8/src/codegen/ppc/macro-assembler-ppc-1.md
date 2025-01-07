Response: The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `macro-assembler-ppc.cc` file in the V8 JavaScript engine. The user also wants to know how this code relates to JavaScript, with a JavaScript example if applicable.

**Plan:**

1. **Identify the core purpose:** The code defines a `MacroAssembler` class with methods for generating PPC assembly instructions.
2. **Group functionalities:** Categorize the methods based on their actions (e.g., comparisons, arithmetic operations, memory access, function calls, etc.).
3. **Explain the relationship to JavaScript:**  The `MacroAssembler` is used by the V8 engine to generate machine code from the compiled JavaScript. This involves translating high-level JavaScript constructs into low-level assembly instructions.
4. **Provide a JavaScript example:**  Illustrate how a seemingly simple JavaScript operation might involve some of the assembly instructions defined in the code.
这是 `v8/src/codegen/ppc/macro-assembler-ppc.cc` 文件的第二部分，主要包含以下功能的宏汇编器方法：

**核心功能：提供用于生成 PowerPC 汇编指令的接口。**  `MacroAssembler` 类封装了底层的汇编指令，为 V8 引擎的编译过程提供了一组更高级、更易用的方法来生成机器码。

**具体功能可以归纳为以下几类：**

1. **类型比较和检查:**
    *   `CompareObjectType`: 比较对象的类型。
    *   `CompareObjectTypeRange`: 比较对象类型是否在一个范围内。
    *   `CompareInstanceType`: 比较实例类型。
    *   `CompareInstanceTypeRange`: 比较实例类型是否在一个范围内。
    *   `CompareTaggedRoot`: 比较对象是否与特定的根对象（Tagged 指针）相等。
    *   `CompareRoot`: 比较对象是否与特定的根对象相等。
    *   `JumpIfIsInRange`: 如果值在指定范围内则跳转。

2. **算术运算并检查溢出:**
    *   `AddAndCheckForOverflow`: 加法运算并检查溢出。
    *   `SubAndCheckForOverflow`: 减法运算并检查溢出。

3. **浮点数运算:**
    *   `MinF64`: 计算两个双精度浮点数的最小值。
    *   `MaxF64`: 计算两个双精度浮点数的最大值。

4. **类型转换:**
    *   `TruncateDoubleToI`: 将双精度浮点数截断为整数。
    *   `TryInlineTruncateDoubleToI`: 尝试内联地将双精度浮点数截断为整数。

5. **尾调用优化相关:**
    *   `ReplaceClosureCodeWithOptimizedCode`: 用优化后的代码替换闭包的代码。
    *   `GenerateTailCallToReturnedCode`: 生成尾调用到返回代码的指令。
    *   `LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing`: 加载反馈向量的标志并根据需要跳转。
    *   `OptimizeCodeOrTailCallOptimizedCodeSlot`: 优化代码或尾调用到优化的代码槽。

6. **运行时调用:**
    *   `CallRuntime`: 调用运行时函数。
    *   `TailCallRuntime`: 尾调用运行时函数。
    *   `JumpToExternalReference`: 跳转到外部引用。

7. **弱引用处理:**
    *   `LoadWeakValue`: 加载弱引用对象的值，如果被清除则跳转。

8. **性能计数器操作:**
    *   `EmitIncrementCounter`: 增加性能计数器的值。
    *   `EmitDecrementCounter`: 减少性能计数器的值。

9. **断言和中止:**
    *   `Check`: 如果条件不成立则中止。
    *   `Abort`: 中止程序的执行。

10. **对象属性加载:**
    *   `LoadMap`: 加载对象的 Map 属性。
    *   `LoadFeedbackVector`: 加载闭包的反馈向量。
    *   `LoadCompressedMap`: 加载对象的压缩 Map 属性。
    *   `LoadNativeContextSlot`: 加载原生上下文的槽位。

11. **调试断言（`V8_ENABLE_DEBUG_CODE` 宏控制）:**  提供了一系列 `Assert` 函数，用于在调试模式下检查对象的类型和状态。

12. **C 函数调用准备和调用:**
    *   `PrepareCallCFunction`: 准备调用 C 函数的栈帧。
    *   `CallCFunction`: 调用 C 函数。
    *   `MovToFloatParameter`, `MovToFloatResult`, `MovToFloatParameters`: 用于传递浮点参数和接收浮点结果。

13. **页标志检查:**
    *   `CheckPageFlag`: 检查内存页的标志。

14. **浮点数舍入模式控制:**
    *   `SetRoundingMode`: 设置浮点数的舍入模式。
    *   `ResetRoundingMode`: 重置浮点数的舍入模式为默认值。

15. **加载字面量:**
    *   `LoadIntLiteral`: 加载整数字面量。
    *   `LoadSmiLiteral`: 加载 Smi 字面量。
    *   `LoadDoubleLiteral`: 加载双精度浮点数字面量。

16. **数据移动和转换:**
    *   `MovIntToDouble`: 将整数移动到双精度浮点寄存器。
    *   `MovUnsignedIntToDouble`: 将无符号整数移动到双精度浮点寄存器。
    *   `MovInt64ToDouble`: 将 64 位整数移动到双精度浮点寄存器。
    *   `MovInt64ComponentsToDouble`: 将 64 位整数的高低位移动到双精度浮点寄存器。
    *   `InsertDoubleLow`, `InsertDoubleHigh`:  插入双精度浮点数的低位或高位。
    *   `MovDoubleLowToInt`, `MovDoubleHighToInt`, `MovDoubleToInt64`: 从双精度浮点寄存器移动到整数寄存器。
    *   `MovIntToFloat`, `MovFloatToInt`: 整数和单精度浮点数之间的转换。

17. **算术和逻辑运算指令 (带有不同大小和符号的变体，以及与立即数运算):** `AddS64`, `SubS64`, `MulS64`, `DivS64`, `DivU64`, `ModS64`, `ModU64`, `AndU64`, `OrU64`, `XorU64`, `ShiftLeftU64`, `ShiftRightU64`, `ShiftRightS64` 等。

18. **比较指令 (带有不同大小和符号的变体以及与立即数比较):** `CmpS64`, `CmpU64`, `CmpS32`, `CmpU32`, `CmpSmiLiteral`, `CmplSmiLiteral`.

19. **浮点数运算指令:** `AddF64`, `SubF64`, `MulF64`, `DivF64`, `AddF32`, `SubF32`, `MulF32`, `DivF32`, `CopySignF64`.

20. **Smi 字面量操作:** `AddSmiLiteral`, `SubSmiLiteral`, `AndSmiLiteral`.

21. **内存操作指令 (多种变体，包括带更新的加载/存储，以及处理对齐的指令):** `LoadU64WithUpdate`, `StoreU64WithUpdate`, `LoadS32`, `LoadU64`, `StoreU64`, `LoadU32`, `LoadS16`, `LoadU16`, `LoadU8`, `StoreU32`, `StoreU16`, `StoreU8`, `LoadF64`, `LoadF32`, `StoreF64`, `StoreF32`, `LoadSimd128`, `StoreSimd128` 等。  还包括处理大小端问题的指令（以 `LE` 结尾）。

**与 JavaScript 的关系：**

`MacroAssembler` 是 V8 引擎将 JavaScript 代码编译成机器码的关键组件。当 V8 编译 JavaScript 代码时，它会将抽象语法树（AST）转换为中间表示（IR），然后使用 `MacroAssembler` 将 IR 指令翻译成特定架构（这里是 PowerPC）的机器码。

例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译这个函数时，它会生成 PowerPC 汇编指令来执行加法操作。`MacroAssembler` 提供的 `AddS64` 或类似的指令会被用来生成实际的加法机器码。

再比如，JavaScript 的类型检查也会用到这里的比较指令。例如：

```javascript
function isNumber(x) {
  return typeof x === 'number';
}
```

在编译 `isNumber` 函数时，V8 会使用 `CompareObjectType` 或 `CompareInstanceType` 等方法生成的汇编指令来检查 `x` 的类型。

**JavaScript 示例说明与 `CompareObjectType` 的关系：**

假设 V8 引擎在编译以下 JavaScript 代码：

```javascript
function foo(obj) {
  if (typeof obj === 'object' && obj !== null) {
    // ... 对对象进行操作
  }
}
```

当编译 `typeof obj === 'object'` 时，`MacroAssembler::CompareObjectType` 方法可能会被调用来生成类似以下的汇编指令（简化示例）：

```assembly
  // 加载 obj 的 Map 指针到寄存器 r8
  lwz r8, 0(r3)
  // 加载 Map 的 InstanceType 到寄存器 r9
  lhz r9, kInstanceTypeOffset(r8)
  // 将 'object' 类型的 InstanceType 值加载到寄存器 r10
  movi r10, kObjectType
  // 比较 r9 和 r10
  cmpw r9, r10
  // 如果相等则跳转到某个标签
  beq some_label
```

这段汇编代码的作用是检查 `obj` 的类型是否为 `object`。`MacroAssembler::CompareObjectType` 方法封装了这些底层的加载和比较操作，使得 V8 编译器可以更方便地生成类型检查的代码。

总而言之，`macro-assembler-ppc.cc` 的这部分代码是 V8 引擎将 JavaScript 代码转化为可以在 PowerPC 架构上执行的机器码的基石。它提供了一组用于生成各种 PowerPC 汇编指令的 C++ 接口，涵盖了类型检查、算术运算、内存访问、函数调用等核心功能。

Prompt: 
```
这是目录为v8/src/codegen/ppc/macro-assembler-ppc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
 InstanceType type) {
  ASM_CODE_COMMENT(this);

#if V8_STATIC_ROOTS_BOOL
  if (InstanceTypeChecker::UniqueMapOfInstanceType(type)) {
    DCHECK((scratch1 != scratch2) || (scratch1 != r0));
    LoadCompressedMap(scratch1, object, scratch1 != scratch2 ? scratch2 : r0);
    CompareInstanceTypeWithUniqueCompressedMap(
        scratch1, scratch1 != scratch2 ? scratch2 : r0, type);
    return;
  }
#endif  // V8_STATIC_ROOTS_BOOL

  CompareObjectType(object, scratch1, scratch2, type);
}

void MacroAssembler::CompareObjectType(Register object, Register map,
                                       Register type_reg, InstanceType type) {
  const Register temp = type_reg == no_reg ? r0 : type_reg;

  LoadMap(map, object);
  CompareInstanceType(map, temp, type);
}

void MacroAssembler::CompareObjectTypeRange(Register object, Register map,
                                            Register type_reg, Register scratch,
                                            InstanceType lower_limit,
                                            InstanceType upper_limit) {
  ASM_CODE_COMMENT(this);
  LoadMap(map, object);
  CompareInstanceTypeRange(map, type_reg, scratch, lower_limit, upper_limit);
}

void MacroAssembler::CompareInstanceType(Register map, Register type_reg,
                                         InstanceType type) {
  static_assert(Map::kInstanceTypeOffset < 4096);
  static_assert(LAST_TYPE <= 0xFFFF);
  lhz(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  cmpi(type_reg, Operand(type));
}

void MacroAssembler::CompareRange(Register value, Register scratch,
                                  unsigned lower_limit, unsigned higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  if (lower_limit != 0) {
    mov(scratch, Operand(lower_limit));
    sub(scratch, value, scratch);
    cmpli(scratch, Operand(higher_limit - lower_limit));
  } else {
    mov(scratch, Operand(higher_limit));
    CmpU64(value, scratch);
  }
}

void MacroAssembler::CompareInstanceTypeRange(Register map, Register type_reg,
                                              Register scratch,
                                              InstanceType lower_limit,
                                              InstanceType higher_limit) {
  DCHECK_LT(lower_limit, higher_limit);
  LoadU16(type_reg, FieldMemOperand(map, Map::kInstanceTypeOffset));
  CompareRange(type_reg, scratch, lower_limit, higher_limit);
}

void MacroAssembler::CompareTaggedRoot(const Register& obj, RootIndex index) {
  ASM_CODE_COMMENT(this);
  // Use r0 as a safe scratch register here, since temps.Acquire() tends
  // to spit back the register being passed as an argument in obj...
  Register temp = r0;
  DCHECK(!AreAliased(obj, temp));

  if (V8_STATIC_ROOTS_BOOL && RootsTable::IsReadOnly(index)) {
    mov(temp, Operand(ReadOnlyRootPtr(index)));
    CompareTagged(obj, temp);
    return;
  }
  // Some smi roots contain system pointer size values like stack limits.
  DCHECK(base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                         RootIndex::kLastStrongOrReadOnlyRoot));
  LoadRoot(temp, index);
  CompareTagged(obj, temp);
}

void MacroAssembler::CompareRoot(Register obj, RootIndex index) {
  ASM_CODE_COMMENT(this);
  // Use r0 as a safe scratch register here, since temps.Acquire() tends
  // to spit back the register being passed as an argument in obj...
  Register temp = r0;
  if (!base::IsInRange(index, RootIndex::kFirstStrongOrReadOnlyRoot,
                       RootIndex::kLastStrongOrReadOnlyRoot)) {
    // Some smi roots contain system pointer size values like stack limits.
    DCHECK(!AreAliased(obj, temp));
    LoadRoot(temp, index);
    CmpU64(obj, temp);
    return;
  }
  CompareTaggedRoot(obj, index);
}

void MacroAssembler::AddAndCheckForOverflow(Register dst, Register left,
                                            Register right,
                                            Register overflow_dst,
                                            Register scratch) {
  DCHECK(dst != overflow_dst);
  DCHECK(dst != scratch);
  DCHECK(overflow_dst != scratch);
  DCHECK(overflow_dst != left);
  DCHECK(overflow_dst != right);

  bool left_is_right = left == right;
  RCBit xorRC = left_is_right ? SetRC : LeaveRC;

  // C = A+B; C overflows if A/B have same sign and C has diff sign than A
  if (dst == left) {
    mr(scratch, left);                        // Preserve left.
    add(dst, left, right);                    // Left is overwritten.
    xor_(overflow_dst, dst, scratch, xorRC);  // Original left.
    if (!left_is_right) xor_(scratch, dst, right);
  } else if (dst == right) {
    mr(scratch, right);     // Preserve right.
    add(dst, left, right);  // Right is overwritten.
    xor_(overflow_dst, dst, left, xorRC);
    if (!left_is_right) xor_(scratch, dst, scratch);  // Original right.
  } else {
    add(dst, left, right);
    xor_(overflow_dst, dst, left, xorRC);
    if (!left_is_right) xor_(scratch, dst, right);
  }
  if (!left_is_right) and_(overflow_dst, scratch, overflow_dst, SetRC);
}

void MacroAssembler::AddAndCheckForOverflow(Register dst, Register left,
                                            intptr_t right,
                                            Register overflow_dst,
                                            Register scratch) {
  Register original_left = left;
  DCHECK(dst != overflow_dst);
  DCHECK(dst != scratch);
  DCHECK(overflow_dst != scratch);
  DCHECK(overflow_dst != left);

  // C = A+B; C overflows if A/B have same sign and C has diff sign than A
  if (dst == left) {
    // Preserve left.
    original_left = overflow_dst;
    mr(original_left, left);
  }
  AddS64(dst, left, Operand(right), scratch);
  xor_(overflow_dst, dst, original_left);
  if (right >= 0) {
    and_(overflow_dst, overflow_dst, dst, SetRC);
  } else {
    andc(overflow_dst, overflow_dst, dst, SetRC);
  }
}

void MacroAssembler::SubAndCheckForOverflow(Register dst, Register left,
                                            Register right,
                                            Register overflow_dst,
                                            Register scratch) {
  DCHECK(dst != overflow_dst);
  DCHECK(dst != scratch);
  DCHECK(overflow_dst != scratch);
  DCHECK(overflow_dst != left);
  DCHECK(overflow_dst != right);

  // C = A-B; C overflows if A/B have diff signs and C has diff sign than A
  if (dst == left) {
    mr(scratch, left);      // Preserve left.
    sub(dst, left, right);  // Left is overwritten.
    xor_(overflow_dst, dst, scratch);
    xor_(scratch, scratch, right);
    and_(overflow_dst, overflow_dst, scratch, SetRC);
  } else if (dst == right) {
    mr(scratch, right);     // Preserve right.
    sub(dst, left, right);  // Right is overwritten.
    xor_(overflow_dst, dst, left);
    xor_(scratch, left, scratch);
    and_(overflow_dst, overflow_dst, scratch, SetRC);
  } else {
    sub(dst, left, right);
    xor_(overflow_dst, dst, left);
    xor_(scratch, left, right);
    and_(overflow_dst, scratch, overflow_dst, SetRC);
  }
}

void MacroAssembler::MinF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, DoubleRegister scratch) {
  Label return_nan, done;
  fcmpu(lhs, rhs);
  bunordered(&return_nan);
  xsmindp(dst, lhs, rhs);
  b(&done);
  bind(&return_nan);
  /* If left or right are NaN, fadd propagates the appropriate one.*/
  fadd(dst, lhs, rhs);
  bind(&done);
}

void MacroAssembler::MaxF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, DoubleRegister scratch) {
  Label return_nan, done;
  fcmpu(lhs, rhs);
  bunordered(&return_nan);
  xsmaxdp(dst, lhs, rhs);
  b(&done);
  bind(&return_nan);
  /* If left or right are NaN, fadd propagates the appropriate one.*/
  fadd(dst, lhs, rhs);
  bind(&done);
}

void MacroAssembler::JumpIfIsInRange(Register value, Register scratch,
                                     unsigned lower_limit,
                                     unsigned higher_limit,
                                     Label* on_in_range) {
  CompareRange(value, scratch, lower_limit, higher_limit);
  ble(on_in_range);
}

void MacroAssembler::TruncateDoubleToI(Isolate* isolate, Zone* zone,
                                       Register result,
                                       DoubleRegister double_input,
                                       StubCallMode stub_mode) {
  Label done;

  TryInlineTruncateDoubleToI(result, double_input, &done);

  // If we fell through then inline version didn't succeed - call stub instead.
  mflr(r0);
  push(r0);
  // Put input on stack.
  stfdu(double_input, MemOperand(sp, -kDoubleSize));

#if V8_ENABLE_WEBASSEMBLY
  if (stub_mode == StubCallMode::kCallWasmRuntimeStub) {
    Call(static_cast<Address>(Builtin::kDoubleToI), RelocInfo::WASM_STUB_CALL);
#else
  // For balance.
  if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
  } else {
    CallBuiltin(Builtin::kDoubleToI);
  }

  LoadU64(result, MemOperand(sp));
  addi(sp, sp, Operand(kDoubleSize));
  pop(r0);
  mtlr(r0);

  bind(&done);
}

void MacroAssembler::TryInlineTruncateDoubleToI(Register result,
                                                DoubleRegister double_input,
                                                Label* done) {
  DoubleRegister double_scratch = kScratchDoubleReg;
  ConvertDoubleToInt64(double_input,
                       result, double_scratch);

// Test for overflow
  TestIfInt32(result, r0);
  beq(done);
}

namespace {

void TailCallOptimizedCodeSlot(MacroAssembler* masm,
                               Register optimized_code_entry,
                               Register scratch) {
  // ----------- S t a t e -------------
  //  -- r3 : actual argument count
  //  -- r6 : new target (preserved for callee if needed, and caller)
  //  -- r4 : target function (preserved for callee if needed, and caller)
  // -----------------------------------
  DCHECK(!AreAliased(r4, r6, optimized_code_entry, scratch));

  Register closure = r4;
  Label heal_optimized_code_slot;

  // If the optimized code is cleared, go to runtime to update the optimization
  // marker field.
  __ LoadWeakValue(optimized_code_entry, optimized_code_entry,
                   &heal_optimized_code_slot);

  // The entry references a CodeWrapper object. Unwrap it now.
  __ LoadCodePointerField(
      optimized_code_entry,
      FieldMemOperand(optimized_code_entry, CodeWrapper::kCodeOffset), scratch);

  // Check if the optimized code is marked for deopt. If it is, call the
  // runtime to clear it.
  {
    UseScratchRegisterScope temps(masm);
    __ TestCodeIsMarkedForDeoptimization(optimized_code_entry, temps.Acquire(),
                                         scratch);
    __ bne(&heal_optimized_code_slot, cr0);
  }

  // Optimized code is good, get it into the closure and link the closure
  // into the optimized functions list, then tail call the optimized code.
  __ ReplaceClosureCodeWithOptimizedCode(optimized_code_entry, closure, scratch,
                                         r8);
  static_assert(kJavaScriptCallCodeStartRegister == r5, "ABI mismatch");
  __ LoadCodeInstructionStart(r5, optimized_code_entry);
  __ Jump(r5);

  // Optimized code slot contains deoptimized code or code is cleared and
  // optimized code marker isn't updated. Evict the code, update the marker
  // and re-enter the closure's code.
  __ bind(&heal_optimized_code_slot);
  __ GenerateTailCallToReturnedCode(Runtime::kHealOptimizedCodeSlot);
}

}  // namespace

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertFeedbackCell(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    CompareObjectType(object, scratch, scratch, FEEDBACK_CELL_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackCell);
  }
}
void MacroAssembler::AssertFeedbackVector(Register object, Register scratch) {
  if (v8_flags.debug_code) {
    CompareObjectType(object, scratch, scratch, FEEDBACK_VECTOR_TYPE);
    Assert(eq, AbortReason::kExpectedFeedbackVector);
  }
}
#endif  // V8_ENABLE_DEBUG_CODE

// Optimized code is good, get it into the closure and link the closure
// into the optimized functions list, then tail call the optimized code.
void MacroAssembler::ReplaceClosureCodeWithOptimizedCode(
    Register optimized_code, Register closure, Register scratch1,
    Register slot_address) {
  DCHECK(!AreAliased(optimized_code, closure, scratch1, slot_address));
  DCHECK_EQ(closure, kJSFunctionRegister);
  DCHECK(!AreAliased(optimized_code, closure));
  // Store code entry in the closure.
  StoreCodePointerField(optimized_code,
                        FieldMemOperand(closure, JSFunction::kCodeOffset), r0);
  // Write barrier clobbers scratch1 below.
  Register value = scratch1;
  mr(value, optimized_code);

  RecordWriteField(closure, JSFunction::kCodeOffset, value, slot_address,
                   kLRHasNotBeenSaved, SaveFPRegsMode::kIgnore, SmiCheck::kOmit,
                   SlotDescriptor::ForCodePointerSlot());
}

void MacroAssembler::GenerateTailCallToReturnedCode(
    Runtime::FunctionId function_id) {
  // ----------- S t a t e -------------
  //  -- r3 : actual argument count
  //  -- r4 : target function (preserved for callee)
  //  -- r6 : new target (preserved for callee)
  // -----------------------------------
  {
    FrameAndConstantPoolScope scope(this, StackFrame::INTERNAL);
    // Push a copy of the target function, the new target and the actual
    // argument count.
    // Push function as parameter to the runtime call.
    SmiTag(kJavaScriptCallArgCountRegister);
    Push(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
         kJavaScriptCallArgCountRegister, kJavaScriptCallTargetRegister);

    CallRuntime(function_id, 1);
    mr(r5, r3);

    // Restore target function, new target and actual argument count.
    Pop(kJavaScriptCallTargetRegister, kJavaScriptCallNewTargetRegister,
        kJavaScriptCallArgCountRegister);
    SmiUntag(kJavaScriptCallArgCountRegister);
  }
  static_assert(kJavaScriptCallCodeStartRegister == r5, "ABI mismatch");
  JumpCodeObject(r5);
}

// Read off the flags in the feedback vector and check if there
// is optimized code or a tiering state that needs to be processed.
void MacroAssembler::LoadFeedbackVectorFlagsAndJumpIfNeedsProcessing(
    Register flags, Register feedback_vector, CodeKind current_code_kind,
    Label* flags_need_processing) {
  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(flags, feedback_vector));
  DCHECK(CodeKindCanTierUp(current_code_kind));
  LoadU16(flags,
          FieldMemOperand(feedback_vector, FeedbackVector::kFlagsOffset));
  uint32_t kFlagsMask = FeedbackVector::kFlagsTieringStateIsAnyRequested |
                        FeedbackVector::kFlagsMaybeHasTurbofanCode |
                        FeedbackVector::kFlagsLogNextExecution;
  if (current_code_kind != CodeKind::MAGLEV) {
    kFlagsMask |= FeedbackVector::kFlagsMaybeHasMaglevCode;
  }
  CHECK(is_uint16(kFlagsMask));
  mov(r0, Operand(kFlagsMask));
  AndU32(r0, flags, r0, SetRC);
  bne(flags_need_processing, cr0);
}

void MacroAssembler::OptimizeCodeOrTailCallOptimizedCodeSlot(
    Register flags, Register feedback_vector) {
  DCHECK(!AreAliased(flags, feedback_vector));
  Label maybe_has_optimized_code, maybe_needs_logging;
  // Check if optimized code is available
  TestBitMask(flags, FeedbackVector::kFlagsTieringStateIsAnyRequested, r0);
  beq(&maybe_needs_logging, cr0);

  GenerateTailCallToReturnedCode(Runtime::kCompileOptimized);

  bind(&maybe_needs_logging);
  TestBitMask(flags, FeedbackVector::LogNextExecutionBit::kMask, r0);
  beq(&maybe_has_optimized_code, cr0);
  GenerateTailCallToReturnedCode(Runtime::kFunctionLogNextExecution);

  bind(&maybe_has_optimized_code);
  Register optimized_code_entry = flags;
  LoadTaggedField(optimized_code_entry,
                  FieldMemOperand(feedback_vector,
                                  FeedbackVector::kMaybeOptimizedCodeOffset),
                  r0);
  TailCallOptimizedCodeSlot(this, optimized_code_entry, r9);
}

void MacroAssembler::CallRuntime(const Runtime::Function* f,
                                 int num_arguments) {
  // All parameters are on the stack.  r3 has the return value after call.

  // If the expected number of arguments of the runtime function is
  // constant, we check that the actual number of arguments match the
  // expectation.
  CHECK(f->nargs < 0 || f->nargs == num_arguments);

  // TODO(1236192): Most runtime routines don't need the number of
  // arguments passed in because it is constant. At some point we
  // should remove this need and make the runtime routine entry code
  // smarter.
  mov(r3, Operand(num_arguments));
  Move(r4, ExternalReference::Create(f));
  CallBuiltin(Builtins::RuntimeCEntry(f->result_size));
}

void MacroAssembler::TailCallRuntime(Runtime::FunctionId fid) {
  const Runtime::Function* function = Runtime::FunctionForId(fid);
  DCHECK_EQ(1, function->result_size);
  if (function->nargs >= 0) {
    mov(r3, Operand(function->nargs));
  }
  JumpToExternalReference(ExternalReference::Create(fid));
}

void MacroAssembler::JumpToExternalReference(const ExternalReference& builtin,
                                             bool builtin_exit_frame) {
  Move(r4, builtin);
  TailCallBuiltin(Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame));
}

void MacroAssembler::LoadWeakValue(Register out, Register in,
                                   Label* target_if_cleared) {
  CmpS32(in, Operand(kClearedWeakHeapObjectLower32), r0);
  beq(target_if_cleared);

  mov(r0, Operand(~kWeakHeapObjectMask));
  and_(out, in, r0);
}

void MacroAssembler::EmitIncrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    Move(scratch2, ExternalReference::Create(counter));
    lwz(scratch1, MemOperand(scratch2));
    addi(scratch1, scratch1, Operand(value));
    stw(scratch1, MemOperand(scratch2));
  }
}

void MacroAssembler::EmitDecrementCounter(StatsCounter* counter, int value,
                                          Register scratch1,
                                          Register scratch2) {
  DCHECK_GT(value, 0);
  if (v8_flags.native_code_counters && counter->Enabled()) {
    // This operation has to be exactly 32-bit wide in case the external
    // reference table redirects the counter to a uint32_t dummy_stats_counter_
    // field.
    Move(scratch2, ExternalReference::Create(counter));
    lwz(scratch1, MemOperand(scratch2));
    subi(scratch1, scratch1, Operand(value));
    stw(scratch1, MemOperand(scratch2));
  }
}

void MacroAssembler::Check(Condition cond, AbortReason reason, CRegister cr) {
  Label L;
  b(cond, &L, cr);
  Abort(reason);
  // will not return here
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
    stop();
    return;
  }

  if (should_abort_hard()) {
    // We don't care if we constructed a frame. Just pretend we did.
    FrameScope assume_frame(this, StackFrame::NO_FRAME_TYPE);
    mov(r3, Operand(static_cast<int>(reason)));
    PrepareCallCFunction(1, 0, r4);
    Register dst = ip;
    if (!ABI_CALL_VIA_IP) {
      dst = r4;
    }
    Move(dst, ExternalReference::abort_with_reason());
    // Use Call directly to avoid any unneeded overhead. The function won't
    // return anyway.
    Call(dst);
    return;
  }

  LoadSmiLiteral(r4, Smi::FromInt(static_cast<int>(reason)));

  {
    // We don't actually want to generate a pile of code for this, so just
    // claim there is a stack frame, without generating one.
    FrameScope scope(this, StackFrame::NO_FRAME_TYPE);
    if (root_array_available()) {
      // Generate an indirect call via builtins entry table here in order to
      // ensure that the interpreter_entry_return_pc_offset is the same for
      // InterpreterEntryTrampoline and InterpreterEntryTrampolineForProfiling
      // when v8_flags.debug_code is enabled.
      LoadEntryFromBuiltin(Builtin::kAbort, ip);
      Call(ip);
    } else {
      CallBuiltin(Builtin::kAbort);
    }
  }
  // will not return here
}

void MacroAssembler::LoadMap(Register destination, Register object) {
  LoadTaggedField(destination, FieldMemOperand(object, HeapObject::kMapOffset),
                  r0);
}

void MacroAssembler::LoadFeedbackVector(Register dst, Register closure,
                                        Register scratch, Label* fbv_undef) {
  Label done;

  // Load the feedback vector from the closure.
  LoadTaggedField(
      dst, FieldMemOperand(closure, JSFunction::kFeedbackCellOffset), r0);
  LoadTaggedField(dst, FieldMemOperand(dst, FeedbackCell::kValueOffset), r0);

  // Check if feedback vector is valid.
  LoadTaggedField(scratch, FieldMemOperand(dst, HeapObject::kMapOffset), r0);
  LoadU16(scratch, FieldMemOperand(scratch, Map::kInstanceTypeOffset));
  CmpS32(scratch, Operand(FEEDBACK_VECTOR_TYPE), r0);
  b(eq, &done);

  // Not valid, load undefined.
  LoadRoot(dst, RootIndex::kUndefinedValue);
  b(fbv_undef);

  bind(&done);
}

void MacroAssembler::LoadCompressedMap(Register dst, Register object,
                                       Register scratch) {
  ASM_CODE_COMMENT(this);
  LoadU32(dst, FieldMemOperand(object, HeapObject::kMapOffset), scratch);
}

void MacroAssembler::LoadNativeContextSlot(Register dst, int index) {
  LoadMap(dst, cp);
  LoadTaggedField(
      dst,
      FieldMemOperand(dst, Map::kConstructorOrBackPointerOrNativeContextOffset),
      r0);
  LoadTaggedField(dst, MemOperand(dst, Context::SlotOffset(index)), r0);
}

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::Assert(Condition cond, AbortReason reason, CRegister cr) {
  if (v8_flags.debug_code) Check(cond, reason, cr);
}

void MacroAssembler::AssertNotSmi(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object, r0);
    Check(ne, AbortReason::kOperandIsASmi, cr0);
  }
}

void MacroAssembler::AssertSmi(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object, r0);
    Check(eq, AbortReason::kOperandIsNotASmi, cr0);
  }
}

void MacroAssembler::AssertConstructor(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object, r0);
    Check(ne, AbortReason::kOperandIsASmiAndNotAConstructor, cr0);
    push(object);
    LoadMap(object, object);
    lbz(object, FieldMemOperand(object, Map::kBitFieldOffset));
    andi(object, object, Operand(Map::Bits1::IsConstructorBit::kMask));
    pop(object);
    Check(ne, AbortReason::kOperandIsNotAConstructor, cr0);
  }
}

void MacroAssembler::AssertFunction(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object, r0);
    Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, cr0);
    push(object);
    LoadMap(object, object);
    CompareInstanceTypeRange(object, object, r0, FIRST_JS_FUNCTION_TYPE,
                             LAST_JS_FUNCTION_TYPE);
    pop(object);
    Check(le, AbortReason::kOperandIsNotAFunction);
  }
}

void MacroAssembler::AssertCallableFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  TestIfSmi(object, r0);
  Check(ne, AbortReason::kOperandIsASmiAndNotAFunction, cr0);
  push(object);
  LoadMap(object, object);
  CompareInstanceTypeRange(object, object, r0, FIRST_CALLABLE_JS_FUNCTION_TYPE,
                           LAST_CALLABLE_JS_FUNCTION_TYPE);
  pop(object);
  Check(le, AbortReason::kOperandIsNotACallableFunction);
}

void MacroAssembler::AssertBoundFunction(Register object) {
  if (v8_flags.debug_code) {
    static_assert(kSmiTag == 0);
    TestIfSmi(object, r0);
    Check(ne, AbortReason::kOperandIsASmiAndNotABoundFunction, cr0);
    push(object);
    CompareObjectType(object, object, object, JS_BOUND_FUNCTION_TYPE);
    pop(object);
    Check(eq, AbortReason::kOperandIsNotABoundFunction);
  }
}

void MacroAssembler::AssertGeneratorObject(Register object) {
  if (!v8_flags.debug_code) return;
  TestIfSmi(object, r0);
  Check(ne, AbortReason::kOperandIsASmiAndNotAGeneratorObject, cr0);

  // Load map
  Register map = object;
  push(object);
  LoadMap(map, object);

  // Check if JSGeneratorObject
  Register instance_type = object;
  CompareInstanceTypeRange(map, instance_type, r0,
                           FIRST_JS_GENERATOR_OBJECT_TYPE,
                           LAST_JS_GENERATOR_OBJECT_TYPE);
  // Restore generator object to register and perform assertion
  pop(object);
  Check(le, AbortReason::kOperandIsNotAGeneratorObject);
}

void MacroAssembler::AssertUndefinedOrAllocationSite(Register object,
                                                     Register scratch) {
  if (v8_flags.debug_code) {
    Label done_checking;
    AssertNotSmi(object);
    CompareRoot(object, RootIndex::kUndefinedValue);
    beq(&done_checking);
    LoadMap(scratch, object);
    CompareInstanceType(scratch, scratch, ALLOCATION_SITE_TYPE);
    Assert(eq, AbortReason::kExpectedUndefinedOrCell);
    bind(&done_checking);
  }
}

void MacroAssembler::AssertJSAny(Register object, Register map_tmp,
                                 Register tmp, AbortReason abort_reason) {
  if (!v8_flags.debug_code) return;

  ASM_CODE_COMMENT(this);
  DCHECK(!AreAliased(object, map_tmp, tmp));
  Label ok;

  JumpIfSmi(object, &ok);

  LoadMap(map_tmp, object);
  CompareInstanceType(map_tmp, tmp, LAST_NAME_TYPE);
  ble(&ok);

  CompareInstanceType(map_tmp, tmp, FIRST_JS_RECEIVER_TYPE);
  bge(&ok);

  CompareRoot(map_tmp, RootIndex::kHeapNumberMap);
  beq(&ok);

  CompareRoot(map_tmp, RootIndex::kBigIntMap);
  beq(&ok);

  CompareRoot(object, RootIndex::kUndefinedValue);
  beq(&ok);

  CompareRoot(object, RootIndex::kTrueValue);
  beq(&ok);

  CompareRoot(object, RootIndex::kFalseValue);
  beq(&ok);

  CompareRoot(object, RootIndex::kNullValue);
  beq(&ok);

  Abort(abort_reason);

  bind(&ok);
}

#endif  // V8_ENABLE_DEBUG_CODE

int MacroAssembler::CalculateStackPassedWords(int num_reg_arguments,
                                              int num_double_arguments) {
  int stack_passed_words = 0;
  if (num_double_arguments > DoubleRegister::kNumRegisters) {
    stack_passed_words +=
        2 * (num_double_arguments - DoubleRegister::kNumRegisters);
  }
  // Up to 8 simple arguments are passed in registers r3..r10.
  if (num_reg_arguments > kRegisterPassedArguments) {
    stack_passed_words += num_reg_arguments - kRegisterPassedArguments;
  }
  return stack_passed_words;
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          int num_double_arguments,
                                          Register scratch) {
  int frame_alignment = ActivationFrameAlignment();
  int stack_passed_arguments =
      CalculateStackPassedWords(num_reg_arguments, num_double_arguments);
  int stack_space = kNumRequiredStackFrameSlots;

  if (frame_alignment > kSystemPointerSize) {
    // Make stack end at alignment and make room for stack arguments
    // -- preserving original value of sp.
    mr(scratch, sp);
    AddS64(sp, sp, Operand(-(stack_passed_arguments + 1) * kSystemPointerSize),
           scratch);
    DCHECK(base::bits::IsPowerOfTwo(frame_alignment));
    ClearRightImm(sp, sp,
                  Operand(base::bits::WhichPowerOfTwo(frame_alignment)));
    StoreU64(scratch,
             MemOperand(sp, stack_passed_arguments * kSystemPointerSize));
  } else {
    // Make room for stack arguments
    stack_space += stack_passed_arguments;
  }

  // Allocate frame with required slots to make ABI work.
  li(r0, Operand::Zero());
  StoreU64WithUpdate(r0, MemOperand(sp, -stack_space * kSystemPointerSize));
}

void MacroAssembler::PrepareCallCFunction(int num_reg_arguments,
                                          Register scratch) {
  PrepareCallCFunction(num_reg_arguments, 0, scratch);
}

void MacroAssembler::MovToFloatParameter(DoubleRegister src) { Move(d1, src); }

void MacroAssembler::MovToFloatResult(DoubleRegister src) { Move(d1, src); }

void MacroAssembler::MovToFloatParameters(DoubleRegister src1,
                                          DoubleRegister src2) {
  if (src2 == d1) {
    DCHECK(src1 != d2);
    Move(d2, src2);
    Move(d1, src1);
  } else {
    Move(d1, src1);
    Move(d2, src2);
  }
}

int MacroAssembler::CallCFunction(ExternalReference function,
                                  int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor) {
  Move(ip, function);
  return CallCFunction(ip, num_reg_arguments, num_double_arguments,
                       set_isolate_data_slots, has_function_descriptor);
}

int MacroAssembler::CallCFunction(Register function, int num_reg_arguments,
                                  int num_double_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor) {
  ASM_CODE_COMMENT(this);
  DCHECK_LE(num_reg_arguments + num_double_arguments, kMaxCParameters);
  DCHECK(has_frame());

  Label start_call;
  Register pc_scratch = r11;
  DCHECK(!AreAliased(pc_scratch, function));
  LoadPC(pc_scratch);
  bind(&start_call);
  int start_pc_offset = pc_offset();
  // We are going to patch this instruction after emitting
  // Call, using a zero offset here as placeholder for now.
  // patch_pc_address assumes `addi` is used here to
  // add the offset to pc.
  addi(pc_scratch, pc_scratch, Operand::Zero());

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // Save the frame pointer and PC so that the stack layout remains iterable,
    // even without an ExitFrame which normally exists between JS and C frames.
    Register scratch = r8;
    Push(scratch);
    mflr(scratch);
    CHECK(root_array_available());
    StoreU64(pc_scratch,
             ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerPC));
    StoreU64(fp,
             ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
    mtlr(scratch);
    Pop(scratch);
  }

  // Just call directly. The function called cannot cause a GC, or
  // allow preemption, so the return address in the link register
  // stays correct.
  Register dest = function;
  if (ABI_USES_FUNCTION_DESCRIPTORS && has_function_descriptor) {
    // AIX/PPC64BE Linux uses a function descriptor. When calling C code be
    // aware of this descriptor and pick up values from it
    LoadU64(ToRegister(ABI_TOC_REGISTER),
            MemOperand(function, kSystemPointerSize));
    LoadU64(ip, MemOperand(function, 0));
    dest = ip;
  } else if (ABI_CALL_VIA_IP) {
    // pLinux and Simualtor, not AIX
    Move(ip, function);
    dest = ip;
  }

  Call(dest);
  int call_pc_offset = pc_offset();
  int offset_since_start_call = SizeOfCodeGeneratedSince(&start_call);
  // Here we are going to patch the `addi` instruction above to use the
  // correct offset.
  // LoadPC emits two instructions and pc is the address of its second emitted
  // instruction. Add one more to the offset to point to after the Call.
  offset_since_start_call += kInstrSize;
  patch_pc_address(pc_scratch, start_pc_offset, offset_since_start_call);

  if (set_isolate_data_slots == SetIsolateDataSlots::kYes) {
    // We don't unset the PC; the FP is the source of truth.
    Register zero_scratch = r0;
    mov(zero_scratch, Operand::Zero());

    StoreU64(zero_scratch,
             ExternalReferenceAsOperand(IsolateFieldId::kFastCCallCallerFP));
  }

  // Remove frame bought in PrepareCallCFunction
  int stack_passed_arguments =
      CalculateStackPassedWords(num_reg_arguments, num_double_arguments);
  int stack_space = kNumRequiredStackFrameSlots + stack_passed_arguments;
  if (ActivationFrameAlignment() > kSystemPointerSize) {
    LoadU64(sp, MemOperand(sp, stack_space * kSystemPointerSize), r0);
  } else {
    AddS64(sp, sp, Operand(stack_space * kSystemPointerSize), r0);
  }

  return call_pc_offset;
}

int MacroAssembler::CallCFunction(ExternalReference function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       has_function_descriptor);
}

int MacroAssembler::CallCFunction(Register function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       has_function_descriptor);
}

void MacroAssembler::CheckPageFlag(
    Register object,
    Register scratch,  // scratch may be same register as object
    int mask, Condition cc, Label* condition_met) {
  DCHECK(cc == ne || cc == eq);
  DCHECK(scratch != r0);
  ClearRightImm(scratch, object, Operand(kPageSizeBits));
  LoadU64(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()), r0);

  mov(r0, Operand(mask));
  and_(r0, scratch, r0, SetRC);

  if (cc == ne) {
    bne(condition_met, cr0);
  }
  if (cc == eq) {
    beq(condition_met, cr0);
  }
}

void MacroAssembler::SetRoundingMode(FPRoundingMode RN) { mtfsfi(7, RN); }

void MacroAssembler::ResetRoundingMode() {
  mtfsfi(7, kRoundToNearest);  // reset (default is kRoundToNearest)
}

////////////////////////////////////////////////////////////////////////////////
//
// New MacroAssembler Interfaces added for PPC
//
////////////////////////////////////////////////////////////////////////////////
void MacroAssembler::LoadIntLiteral(Register dst, int value) {
  mov(dst, Operand(value));
}

void MacroAssembler::LoadSmiLiteral(Register dst, Tagged<Smi> smi) {
  mov(dst, Operand(smi));
}

void MacroAssembler::LoadDoubleLiteral(DoubleRegister result,
                                       base::Double value, Register scratch) {
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL && is_constant_pool_available() &&
      !(scratch == r0 && ConstantPoolAccessIsInOverflow())) {
    ConstantPoolEntry::Access access = ConstantPoolAddEntry(value);
    if (access == ConstantPoolEntry::OVERFLOWED) {
      addis(scratch, kConstantPoolRegister, Operand::Zero());
      lfd(result, MemOperand(scratch, 0));
    } else {
      lfd(result, MemOperand(kConstantPoolRegister, 0));
    }
    return;
  }

  // avoid gcc strict aliasing error using union cast
  union {
    uint64_t dval;
    intptr_t ival;
  } litVal;

  litVal.dval = value.AsUint64();

  mov(scratch, Operand(litVal.ival));
  mtfprd(result, scratch);
}

void MacroAssembler::MovIntToDouble(DoubleRegister dst, Register src,
                                    Register scratch) {
  // sign-extend src to 64-bit
  mtfprwa(dst, src);
}

void MacroAssembler::MovUnsignedIntToDouble(DoubleRegister dst, Register src,
                                            Register scratch) {
  // zero-extend src to 64-bit
  mtfprwz(dst, src);
}

void MacroAssembler::MovInt64ToDouble(DoubleRegister dst,
                                      Register src) {
  mtfprd(dst, src);
}

void MacroAssembler::MovInt64ComponentsToDouble(DoubleRegister dst,
                                                Register src_hi,
                                                Register src_lo,
                                                Register scratch) {
  ShiftLeftU64(scratch, src_hi, Operand(32));
  rldimi(scratch, src_lo, 0, 32);
  mtfprd(dst, scratch);
}

void MacroAssembler::InsertDoubleLow(DoubleRegister dst, Register src,
                                     Register scratch) {
  mffprd(scratch, dst);
  rldimi(scratch, src, 0, 32);
  mtfprd(dst, scratch);
}

void MacroAssembler::InsertDoubleHigh(DoubleRegister dst, Register src,
                                      Register scratch) {
  mffprd(scratch, dst);
  rldimi(scratch, src, 32, 0);
  mtfprd(dst, scratch);
}

void MacroAssembler::MovDoubleLowToInt(Register dst, DoubleRegister src) {
  mffprwz(dst, src);
}

void MacroAssembler::MovDoubleHighToInt(Register dst, DoubleRegister src) {
  mffprd(dst, src);
  srdi(dst, dst, Operand(32));
}

void MacroAssembler::MovDoubleToInt64(Register dst, DoubleRegister src) {
  mffprd(dst, src);
}

void MacroAssembler::MovIntToFloat(DoubleRegister dst, Register src,
                                   Register scratch) {
  ShiftLeftU64(scratch, src, Operand(32));
  mtfprd(dst, scratch);
  xscvspdpn(dst, dst);
}

void MacroAssembler::MovFloatToInt(Register dst, DoubleRegister src,
                                   DoubleRegister scratch) {
  xscvdpspn(scratch, src);
  mffprwz(dst, scratch);
}

void MacroAssembler::AddS64(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  add(dst, src, value, s, r);
}

void MacroAssembler::AddS64(Register dst, Register src, const Operand& value,
                            Register scratch, OEBit s, RCBit r) {
  if (is_int16(value.immediate()) && s == LeaveOE && r == LeaveRC) {
    addi(dst, src, value);
  } else {
    mov(scratch, value);
    add(dst, src, scratch, s, r);
  }
}

void MacroAssembler::SubS64(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  sub(dst, src, value, s, r);
}

void MacroAssembler::SubS64(Register dst, Register src, const Operand& value,
                            Register scratch, OEBit s, RCBit r) {
  if (is_int16(value.immediate()) && s == LeaveOE && r == LeaveRC) {
    subi(dst, src, value);
  } else {
    mov(scratch, value);
    sub(dst, src, scratch, s, r);
  }
}

void MacroAssembler::AddS32(Register dst, Register src, Register value,
                            RCBit r) {
  AddS64(dst, src, value, LeaveOE, r);
  extsw(dst, dst, r);
}

void MacroAssembler::AddS32(Register dst, Register src, const Operand& value,
                            Register scratch, RCBit r) {
  AddS64(dst, src, value, scratch, LeaveOE, r);
  extsw(dst, dst, r);
}

void MacroAssembler::SubS32(Register dst, Register src, Register value,
                            RCBit r) {
  SubS64(dst, src, value, LeaveOE, r);
  extsw(dst, dst, r);
}

void MacroAssembler::SubS32(Register dst, Register src, const Operand& value,
                            Register scratch, RCBit r) {
  SubS64(dst, src, value, scratch, LeaveOE, r);
  extsw(dst, dst, r);
}

void MacroAssembler::MulS64(Register dst, Register src, const Operand& value,
                            Register scratch, OEBit s, RCBit r) {
  if (is_int16(value.immediate()) && s == LeaveOE && r == LeaveRC) {
    mulli(dst, src, value);
  } else {
    mov(scratch, value);
    mulld(dst, src, scratch, s, r);
  }
}

void MacroAssembler::MulS64(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  mulld(dst, src, value, s, r);
}

void MacroAssembler::MulS32(Register dst, Register src, const Operand& value,
                            Register scratch, OEBit s, RCBit r) {
  MulS64(dst, src, value, scratch, s, r);
  extsw(dst, dst, r);
}

void MacroAssembler::MulS32(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  MulS64(dst, src, value, s, r);
  extsw(dst, dst, r);
}

void MacroAssembler::DivS64(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  divd(dst, src, value, s, r);
}

void MacroAssembler::DivU64(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  divdu(dst, src, value, s, r);
}

void MacroAssembler::DivS32(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  divw(dst, src, value, s, r);
  extsw(dst, dst);
}
void MacroAssembler::DivU32(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  divwu(dst, src, value, s, r);
  ZeroExtWord32(dst, dst);
}

void MacroAssembler::ModS64(Register dst, Register src, Register value) {
  if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
    modsd(dst, src, value);
  } else {
    Register scratch = GetRegisterThatIsNotOneOf(dst, src, value);
    Push(scratch);
    divd(scratch, src, value);
    mulld(scratch, scratch, value);
    sub(dst, src, scratch);
    Pop(scratch);
  }
}

void MacroAssembler::ModU64(Register dst, Register src, Register value) {
  if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
    modud(dst, src, value);
  } else {
    Register scratch = GetRegisterThatIsNotOneOf(dst, src, value);
    Push(scratch);
    divdu(scratch, src, value);
    mulld(scratch, scratch, value);
    sub(dst, src, scratch);
    Pop(scratch);
  }
}

void MacroAssembler::ModS32(Register dst, Register src, Register value) {
  if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
    modsw(dst, src, value);
  } else {
    Register scratch = GetRegisterThatIsNotOneOf(dst, src, value);
    Push(scratch);
    divw(scratch, src, value);
    mullw(scratch, scratch, value);
    sub(dst, src, scratch);
    Pop(scratch);
  }
  extsw(dst, dst);
}
void MacroAssembler::ModU32(Register dst, Register src, Register value) {
  if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
    moduw(dst, src, value);
  } else {
    Register scratch = GetRegisterThatIsNotOneOf(dst, src, value);
    Push(scratch);
    divwu(scratch, src, value);
    mullw(scratch, scratch, value);
    sub(dst, src, scratch);
    Pop(scratch);
  }
  ZeroExtWord32(dst, dst);
}

void MacroAssembler::AndU64(Register dst, Register src, const Operand& value,
                            Register scratch, RCBit r) {
  if (is_uint16(value.immediate()) && r == SetRC) {
    andi(dst, src, value);
  } else {
    mov(scratch, value);
    and_(dst, src, scratch, r);
  }
}

void MacroAssembler::AndU64(Register dst, Register src, Register value,
                            RCBit r) {
  and_(dst, src, value, r);
}

void MacroAssembler::OrU64(Register dst, Register src, const Operand& value,
                           Register scratch, RCBit r) {
  if (is_int16(value.immediate()) && r == LeaveRC) {
    ori(dst, src, value);
  } else {
    mov(scratch, value);
    orx(dst, src, scratch, r);
  }
}

void MacroAssembler::OrU64(Register dst, Register src, Register value,
                           RCBit r) {
  orx(dst, src, value, r);
}

void MacroAssembler::XorU64(Register dst, Register src, const Operand& value,
                            Register scratch, RCBit r) {
  if (is_int16(value.immediate()) && r == LeaveRC) {
    xori(dst, src, value);
  } else {
    mov(scratch, value);
    xor_(dst, src, scratch, r);
  }
}

void MacroAssembler::XorU64(Register dst, Register src, Register value,
                            RCBit r) {
  xor_(dst, src, value, r);
}

void MacroAssembler::AndU32(Register dst, Register src, const Operand& value,
                            Register scratch, RCBit r) {
  AndU64(dst, src, value, scratch, r);
  extsw(dst, dst, r);
}

void MacroAssembler::AndU32(Register dst, Register src, Register value,
                            RCBit r) {
  AndU64(dst, src, value, r);
  extsw(dst, dst, r);
}

void MacroAssembler::OrU32(Register dst, Register src, const Operand& value,
                           Register scratch, RCBit r) {
  OrU64(dst, src, value, scratch, r);
  extsw(dst, dst, r);
}

void MacroAssembler::OrU32(Register dst, Register src, Register value,
                           RCBit r) {
  OrU64(dst, src, value, r);
  extsw(dst, dst, r);
}

void MacroAssembler::XorU32(Register dst, Register src, const Operand& value,
                            Register scratch, RCBit r) {
  XorU64(dst, src, value, scratch, r);
  extsw(dst, dst, r);
}

void MacroAssembler::XorU32(Register dst, Register src, Register value,
                            RCBit r) {
  XorU64(dst, src, value, r);
  extsw(dst, dst, r);
}

void MacroAssembler::ShiftLeftU64(Register dst, Register src,
                                  const Operand& value, RCBit r) {
  sldi(dst, src, value, r);
}

void MacroAssembler::ShiftRightU64(Register dst, Register src,
                                   const Operand& value, RCBit r) {
  srdi(dst, src, value, r);
}

void MacroAssembler::ShiftRightS64(Register dst, Register src,
                                   const Operand& value, RCBit r) {
  sradi(dst, src, value.immediate(), r);
}

void MacroAssembler::ShiftLeftU32(Register dst, Register src,
                                  const Operand& value, RCBit r) {
  slwi(dst, src, value, r);
}

void MacroAssembler::ShiftRightU32(Register dst, Register src,
                                   const Operand& value, RCBit r) {
  srwi(dst, src, value, r);
}

void MacroAssembler::ShiftRightS32(Register dst, Register src,
                                   const Operand& value, RCBit r) {
  srawi(dst, src, value.immediate(), r);
}

void MacroAssembler::ShiftLeftU64(Register dst, Register src, Register value,
                                  RCBit r) {
  sld(dst, src, value, r);
}

void MacroAssembler::ShiftRightU64(Register dst, Register src, Register value,
                                   RCBit r) {
  srd(dst, src, value, r);
}

void MacroAssembler::ShiftRightS64(Register dst, Register src, Register value,
                                   RCBit r) {
  srad(dst, src, value, r);
}

void MacroAssembler::ShiftLeftU32(Register dst, Register src, Register value,
                                  RCBit r) {
  slw(dst, src, value, r);
}

void MacroAssembler::ShiftRightU32(Register dst, Register src, Register value,
                                   RCBit r) {
  srw(dst, src, value, r);
}

void MacroAssembler::ShiftRightS32(Register dst, Register src, Register value,
                                   RCBit r) {
  sraw(dst, src, value, r);
}

void MacroAssembler::CmpS64(Register src1, Register src2, CRegister cr) {
  cmp(src1, src2, cr);
}

void MacroAssembler::CmpS64(Register src1, const Operand& src2,
                            Register scratch, CRegister cr) {
  intptr_t value = src2.immediate();
  if (is_int16(value)) {
    cmpi(src1, src2, cr);
  } else {
    mov(scratch, src2);
    CmpS64(src1, scratch, cr);
  }
}

void MacroAssembler::CmpU64(Register src1, const Operand& src2,
                            Register scratch, CRegister cr) {
  intptr_t value = src2.immediate();
  if (is_uint16(value)) {
    cmpli(src1, src2, cr);
  } else {
    mov(scratch, src2);
    CmpU64(src1, scratch, cr);
  }
}

void MacroAssembler::CmpU64(Register src1, Register src2, CRegister cr) {
  cmpl(src1, src2, cr);
}

void MacroAssembler::CmpS32(Register src1, const Operand& src2,
                            Register scratch, CRegister cr) {
  intptr_t value = src2.immediate();
  if (is_int16(value)) {
    cmpwi(src1, src2, cr);
  } else {
    mov(scratch, src2);
    CmpS32(src1, scratch, cr);
  }
}

void MacroAssembler::CmpS32(Register src1, Register src2, CRegister cr) {
  cmpw(src1, src2, cr);
}

void MacroAssembler::CmpU32(Register src1, const Operand& src2,
                            Register scratch, CRegister cr) {
  intptr_t value = src2.immediate();
  if (is_uint16(value)) {
    cmplwi(src1, src2, cr);
  } else {
    mov(scratch, src2);
    cmplw(src1, scratch, cr);
  }
}

void MacroAssembler::CmpU32(Register src1, Register src2, CRegister cr) {
  cmplw(src1, src2, cr);
}

void MacroAssembler::AddF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fadd(dst, lhs, rhs, r);
}

void MacroAssembler::SubF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fsub(dst, lhs, rhs, r);
}

void MacroAssembler::MulF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fmul(dst, lhs, rhs, r);
}

void MacroAssembler::DivF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fdiv(dst, lhs, rhs, r);
}

void MacroAssembler::AddF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fadd(dst, lhs, rhs, r);
  frsp(dst, dst, r);
}

void MacroAssembler::SubF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fsub(dst, lhs, rhs, r);
  frsp(dst, dst, r);
}

void MacroAssembler::MulF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fmul(dst, lhs, rhs, r);
  frsp(dst, dst, r);
}

void MacroAssembler::DivF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fdiv(dst, lhs, rhs, r);
  frsp(dst, dst, r);
}

void MacroAssembler::CopySignF64(DoubleRegister dst, DoubleRegister lhs,
                                 DoubleRegister rhs, RCBit r) {
  fcpsgn(dst, rhs, lhs, r);
}

void MacroAssembler::CmpSmiLiteral(Register src1, Tagged<Smi> smi,
                                   Register scratch, CRegister cr) {
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  CmpS32(src1, Operand(smi), scratch, cr);
#else
  LoadSmiLiteral(scratch, smi);
  CmpS64(src1, scratch, cr);
#endif
}

void MacroAssembler::CmplSmiLiteral(Register src1, Tagged<Smi> smi,
                                    Register scratch, CRegister cr) {
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  CmpU64(src1, Operand(smi), scratch, cr);
#else
  LoadSmiLiteral(scratch, smi);
  CmpU64(src1, scratch, cr);
#endif
}

void MacroAssembler::AddSmiLiteral(Register dst, Register src, Tagged<Smi> smi,
                                   Register scratch) {
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  AddS64(dst, src, Operand(smi.ptr()), scratch);
#else
  LoadSmiLiteral(scratch, smi);
  add(dst, src, scratch);
#endif
}

void MacroAssembler::SubSmiLiteral(Register dst, Register src, Tagged<Smi> smi,
                                   Register scratch) {
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  AddS64(dst, src, Operand(-(static_cast<intptr_t>(smi.ptr()))), scratch);
#else
  LoadSmiLiteral(scratch, smi);
  sub(dst, src, scratch);
#endif
}

void MacroAssembler::AndSmiLiteral(Register dst, Register src, Tagged<Smi> smi,
                                   Register scratch, RCBit rc) {
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  AndU64(dst, src, Operand(smi), scratch, rc);
#else
  LoadSmiLiteral(scratch, smi);
  and_(dst, src, scratch, rc);
#endif
}

#define GenerateMemoryOperation(reg, mem, ri_op, rr_op) \
  {                                                     \
    int64_t offset = mem.offset();                      \
                                                        \
    if (mem.rb() == no_reg) {                           \
      if (!is_int16(offset)) {                          \
        /* cannot use d-form */                         \
        CHECK_NE(scratch, no_reg);                      \
        mov(scratch, Operand(offset));                  \
        rr_op(reg, MemOperand(mem.ra(), scratch));      \
      } else {                                          \
        ri_op(reg, mem);                                \
      }                                                 \
    } else {                                            \
      if (offset == 0) {                                \
        rr_op(reg, mem);                                \
      } else if (is_int16(offset)) {                    \
        CHECK_NE(scratch, no_reg);                      \
        addi(scratch, mem.rb(), Operand(offset));       \
        rr_op(reg, MemOperand(mem.ra(), scratch));      \
      } else {                                          \
        CHECK_NE(scratch, no_reg);                      \
        mov(scratch, Operand(offset));                  \
        add(scratch, scratch, mem.rb());                \
        rr_op(reg, MemOperand(mem.ra(), scratch));      \
      }                                                 \
    }                                                   \
  }

#define GenerateMemoryOperationRR(reg, mem, op)                \
  {                                                            \
    if (mem.offset() == 0) {                                   \
      if (mem.rb() != no_reg)                                  \
        op(reg, mem);                                          \
      else                                                     \
        op(reg, MemOperand(r0, mem.ra()));                     \
    } else if (is_int16(mem.offset())) {                       \
      if (mem.rb() != no_reg)                                  \
        addi(scratch, mem.rb(), Operand(mem.offset()));        \
      else                                                     \
        mov(scratch, Operand(mem.offset()));                   \
      op(reg, MemOperand(mem.ra(), scratch));                  \
    } else {                                                   \
      mov(scratch, Operand(mem.offset()));                     \
      if (mem.rb() != no_reg) add(scratch, scratch, mem.rb()); \
      op(reg, MemOperand(mem.ra(), scratch));                  \
    }                                                          \
  }

#define GenerateMemoryOperationPrefixed(reg, mem, ri_op, rip_op, rr_op)       \
  {                                                                           \
    int64_t offset = mem.offset();                                            \
                                                                              \
    if (mem.rb() == no_reg) {                                                 \
      if (is_int16(offset)) {                                                 \
        ri_op(reg, mem);                                                      \
      } else if (is_int34(offset) && CpuFeatures::IsSupported(PPC_10_PLUS)) { \
        rip_op(reg, mem);                                                     \
      } else {                                                                \
        /* cannot use d-form */                                               \
        CHECK_NE(scratch, no_reg);                                            \
        mov(scratch, Operand(offset));                                        \
        rr_op(reg, MemOperand(mem.ra(), scratch));                            \
      }                                                                       \
    } else {                                                                  \
      if (offset == 0) {                                                      \
        rr_op(reg, mem);                                                      \
      } else if (is_int16(offset)) {                                          \
        CHECK_NE(scratch, no_reg);                                            \
        addi(scratch, mem.rb(), Operand(offset));                             \
        rr_op(reg, MemOperand(mem.ra(), scratch));                            \
      } else {                                                                \
        CHECK_NE(scratch, no_reg);                                            \
        mov(scratch, Operand(offset));                                        \
        add(scratch, scratch, mem.rb());                                      \
        rr_op(reg, MemOperand(mem.ra(), scratch));                            \
      }                                                                       \
    }                                                                         \
  }

#define GenerateMemoryOperationWithAlign(reg, mem, ri_op, rr_op) \
  {                                                              \
    int64_t offset = mem.offset();                               \
    int misaligned = (offset & 3);                               \
                                                                 \
    if (mem.rb() == no_reg) {                                    \
      if (!is_int16(offset) || misaligned) {                     \
        /* cannot use d-form */                                  \
        CHECK_NE(scratch, no_reg);                               \
        mov(scratch, Operand(offset));                           \
        rr_op(reg, MemOperand(mem.ra(), scratch));               \
      } else {                                                   \
        ri_op(reg, mem);                                         \
      }                                                          \
    } else {                                                     \
      if (offset == 0) {                                         \
        rr_op(reg, mem);                                         \
      } else if (is_int16(offset)) {                             \
        CHECK_NE(scratch, no_reg);                               \
        addi(scratch, mem.rb(), Operand(offset));                \
        rr_op(reg, MemOperand(mem.ra(), scratch));               \
      } else {                                                   \
        CHECK_NE(scratch, no_reg);                               \
        mov(scratch, Operand(offset));                           \
        add(scratch, scratch, mem.rb());                         \
        rr_op(reg, MemOperand(mem.ra(), scratch));               \
      }                                                          \
    }                                                            \
  }

#define GenerateMemoryOperationWithAlignPrefixed(reg, mem, ri_op, rip_op,     \
                                                 rr_op)                       \
  {                                                                           \
    int64_t offset = mem.offset();                                            \
    int misaligned = (offset & 3);                                            \
                                                                              \
    if (mem.rb() == no_reg) {                                                 \
      if (is_int16(offset) && !misaligned) {                                  \
        ri_op(reg, mem);                                                      \
      } else if (is_int34(offset) && CpuFeatures::IsSupported(PPC_10_PLUS)) { \
        rip_op(reg, mem);                                                     \
      } else {                                                                \
        /* cannot use d-form */                                               \
        CHECK_NE(scratch, no_reg);                                            \
        mov(scratch, Operand(offset));                                        \
        rr_op(reg, MemOperand(mem.ra(), scratch));                            \
      }                                                                       \
    } else {                                                                  \
      if (offset == 0) {                                                      \
        rr_op(reg, mem);                                                      \
      } else if (is_int16(offset)) {                                          \
        CHECK_NE(scratch, no_reg);                                            \
        addi(scratch, mem.rb(), Operand(offset));                             \
        rr_op(reg, MemOperand(mem.ra(), scratch));                            \
      } else {                                                                \
        CHECK_NE(scratch, no_reg);                                            \
        mov(scratch, Operand(offset));                                        \
        add(scratch, scratch, mem.rb());                                      \
        rr_op(reg, MemOperand(mem.ra(), scratch));                            \
      }                                                                       \
    }                                                                         \
  }

#define MEM_OP_WITH_ALIGN_LIST(V) \
  V(LoadU64WithUpdate, ldu, ldux) \
  V(StoreU64WithUpdate, stdu, stdux)

#define MEM_OP_WITH_ALIGN_FUNCTION(name, ri_op, rr_op)           \
  void MacroAssembler::name(Register reg, const MemOperand& mem, \
                            Register scratch) {                  \
    GenerateMemoryOperationWithAlign(reg, mem, ri_op, rr_op);    \
  }
MEM_OP_WITH_ALIGN_LIST(MEM_OP_WITH_ALIGN_FUNCTION)
#undef MEM_OP_WITH_ALIGN_LIST
#undef MEM_OP_WITH_ALIGN_FUNCTION

#define MEM_OP_WITH_ALIGN_PREFIXED_LIST(V) \
  V(LoadS32, lwa, plwa, lwax)              \
  V(LoadU64, ld, pld, ldx)                 \
  V(StoreU64, std, pstd, stdx)

#define MEM_OP_WITH_ALIGN_PREFIXED_FUNCTION(name, ri_op, rip_op, rr_op)       \
  void MacroAssembler::name(Register reg, const MemOperand& mem,              \
                            Register scratch) {                               \
    GenerateMemoryOperationWithAlignPrefixed(reg, mem, ri_op, rip_op, rr_op); \
  }
MEM_OP_WITH_ALIGN_PREFIXED_LIST(MEM_OP_WITH_ALIGN_PREFIXED_FUNCTION)
#undef MEM_OP_WITH_ALIGN_PREFIXED_LIST
#undef MEM_OP_WITH_ALIGN_PREFIXED_FUNCTION

#define MEM_OP_LIST(V)                                 \
  V(LoadF64WithUpdate, DoubleRegister, lfdu, lfdux)    \
  V(LoadF32WithUpdate, DoubleRegister, lfsu, lfsux)    \
  V(StoreF64WithUpdate, DoubleRegister, stfdu, stfdux) \
  V(StoreF32WithUpdate, DoubleRegister, stfsu, stfsux)

#define MEM_OP_FUNCTION(name, result_t, ri_op, rr_op)            \
  void MacroAssembler::name(result_t reg, const MemOperand& mem, \
                            Register scratch) {                  \
    GenerateMemoryOperation(reg, mem, ri_op, rr_op);             \
  }
MEM_OP_LIST(MEM_OP_FUNCTION)
#undef MEM_OP_LIST
#undef MEM_OP_FUNCTION

#define MEM_OP_PREFIXED_LIST(V)                   \
  V(LoadU32, Register, lwz, plwz, lwzx)           \
  V(LoadS16, Register, lha, plha, lhax)           \
  V(LoadU16, Register, lhz, plhz, lhzx)           \
  V(LoadU8, Register, lbz, plbz, lbzx)            \
  V(StoreU32, Register, stw, pstw, stwx)          \
  V(StoreU16, Register, sth, psth, sthx)          \
  V(StoreU8, Register, stb, pstb, stbx)           \
  V(LoadF64, DoubleRegister, lfd, plfd, lfdx)     \
  V(LoadF32, DoubleRegister, lfs, plfs, lfsx)     \
  V(StoreF64, DoubleRegister, stfd, pstfd, stfdx) \
  V(StoreF32, DoubleRegister, stfs, pstfs, stfsx)

#define MEM_OP_PREFIXED_FUNCTION(name, result_t, ri_op, rip_op, rr_op) \
  void MacroAssembler::name(result_t reg, const MemOperand& mem,       \
                            Register scratch) {                        \
    GenerateMemoryOperationPrefixed(reg, mem, ri_op, rip_op, rr_op);   \
  }
MEM_OP_PREFIXED_LIST(MEM_OP_PREFIXED_FUNCTION)
#undef MEM_OP_PREFIXED_LIST
#undef MEM_OP_PREFIXED_FUNCTION

#define MEM_OP_SIMD_LIST(V)      \
  V(LoadSimd128, lxvx)           \
  V(StoreSimd128, stxvx)         \
  V(LoadSimd128Uint64, lxsdx)    \
  V(LoadSimd128Uint32, lxsiwzx)  \
  V(LoadSimd128Uint16, lxsihzx)  \
  V(LoadSimd128Uint8, lxsibzx)   \
  V(StoreSimd128Uint64, stxsdx)  \
  V(StoreSimd128Uint32, stxsiwx) \
  V(StoreSimd128Uint16, stxsihx) \
  V(StoreSimd128Uint8, stxsibx)

#define MEM_OP_SIMD_FUNCTION(name, rr_op)                               \
  void MacroAssembler::name(Simd128Register reg, const MemOperand& mem, \
                            Register scratch) {                         \
    GenerateMemoryOperationRR(reg, mem, rr_op);                         \
  }
MEM_OP_SIMD_LIST(MEM_OP_SIMD_FUNCTION)
#undef MEM_OP_SIMD_LIST
#undef MEM_OP_SIMD_FUNCTION

void MacroAssembler::LoadS8(Register dst, const MemOperand& mem,
                            Register scratch) {
  LoadU8(dst, mem, scratch);
  extsb(dst, dst);
}

#define MEM_LE_OP_LIST(V) \
  V(LoadU64, ldbrx)       \
  V(LoadU32, lwbrx)       \
  V(LoadU16, lhbrx)       \
  V(StoreU64, stdbrx)     \
  V(StoreU32, stwbrx)     \
  V(StoreU16, sthbrx)

#ifdef V8_TARGET_BIG_ENDIAN
#define MEM_LE_OP_FUNCTION(name, op)                                 \
  void MacroAssembler::name##LE(Register reg, const MemOperand& mem, \
                                Register scratch) {                  \
    GenerateMemoryOperationRR(reg, mem, op);                         \
  }
#else
#define MEM_LE_OP_FUNCTION(name, op)                                 \
  void MacroAssembler::name##LE(Register reg, const MemOperand& mem, \
                                Register scratch) {                  \
    name(reg, mem, scratch);                                         \
  }
#endif

MEM_LE_OP_LIST(MEM_LE_OP_FUNCTION)
#undef MEM_LE_OP_FUNCTION
#undef MEM_LE_OP_LIST

void MacroAssembler::LoadS32LE(Register dst, const MemOperand& mem,
                               Register scratch) {
#ifdef V8_TARGET_BIG_ENDIAN
  LoadU32LE(dst, mem, scratch);
  extsw(dst, dst);
#else
  LoadS32(dst, mem, scratch);
#endif
}

void MacroAssembler::LoadS16LE(Register dst, const MemOperand& mem,
             
"""


```