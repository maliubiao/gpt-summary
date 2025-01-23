Response: The user wants to understand the functionality of the C++ code in `v8/src/wasm/baseline/liftoff-compiler.cc`, specifically the part provided in the current section (part 6 of 7).

The code seems to be implementing handlers for various WebAssembly instructions within the Liftoff compiler. These handlers manage the stack, registers, and call built-in functions to perform the actual operations.

The current section focuses on handlers related to **string manipulation** in WebAssembly.

To illustrate the connection with JavaScript, I need to identify the corresponding JavaScript APIs or scenarios that would trigger these WebAssembly string operations.

**Plan:**
1. **Summarize the functionality of each C++ function in the provided snippet.**  Focus on the WebAssembly string operations they implement.
2. **Identify which JavaScript features or APIs interact with these WebAssembly string operations.**  This will involve thinking about when WebAssembly might need to manipulate strings coming from or going to JavaScript.
3. **Provide concrete JavaScript examples** to demonstrate the interaction.
这是 `v8/src/wasm/baseline/liftoff-compiler.cc` 文件的第六部分，主要负责实现 WebAssembly 中与 **字符串操作** 相关的指令的编译。Liftoff 编译器是 V8 引擎中用于快速编译 WebAssembly 代码的基线编译器。这部分代码定义了 Liftoff 编译器如何处理各种 WebAssembly 字符串操作，例如创建、测量长度、编码、连接、比较等等。

具体来说，这部分代码中的每个函数都对应一个特定的 WebAssembly 字符串操作指令，并负责生成相应的机器码来实现该指令的功能。这些函数通常会：

1. **从 WebAssembly 栈中弹出操作数。**
2. **执行必要的操作，可能通过调用 V8 引擎的内置函数 (built-in functions)。**
3. **将结果压入 WebAssembly 栈。**
4. **处理可能的空指针检查和类型转换。**
5. **记录调试信息。**

**与 JavaScript 的关系和示例：**

WebAssembly 的字符串功能是为了更好地与 JavaScript 互操作而设计的。当 JavaScript 代码和 WebAssembly 代码需要共享或操作字符串时，就会涉及到这里编译的指令。

以下是一些 JavaScript 场景，它们可能会触发这里定义的 WebAssembly 字符串操作：

1. **从 JavaScript 向 WebAssembly 传递字符串:** 当 JavaScript 代码调用 WebAssembly 导出的函数，并且该函数接收字符串作为参数时，V8 引擎需要将 JavaScript 字符串转换为 WebAssembly 可以理解的格式。这可能会涉及到 `StringMeasureWtf16`（测量长度）和 `StringEncodeWtf8` 或 `StringEncodeWtf16`（编码）等操作。

   ```javascript
   // 假设有一个 WebAssembly 模块实例 instance，其中导出了一个名为 processString 的函数
   const wasmModule = await WebAssembly.instantiateStreaming(fetch('my_module.wasm'));
   const instance = wasmModule.instance;

   const myString = "Hello from JavaScript!";
   instance.exports.processString(myString); // 传递 JavaScript 字符串到 WebAssembly
   ```

2. **从 WebAssembly 向 JavaScript 返回字符串:** 当 WebAssembly 函数需要将字符串返回给 JavaScript 调用者时，需要将 WebAssembly 的字符串格式转换回 JavaScript 字符串。这可能涉及到一些内部的转换操作，与这里定义的某些指令相关。

   ```javascript
   // 假设 WebAssembly 导出的函数 getString 返回一个字符串
   const wasmString = instance.exports.getString();
   console.log(wasmString); // 打印从 WebAssembly 返回的字符串
   ```

3. **在 WebAssembly 中操作字符串:** WebAssembly 代码本身也可以创建、操作字符串。这里定义的指令允许 WebAssembly 代码执行各种字符串操作，例如连接字符串 (`StringConcat`)，比较字符串 (`StringEq`， `StringCompare`)，获取字符串长度 (`StringMeasureWtf16`)，以及对字符串进行编码和解码 (`StringEncodeWtf8`, `StringEncodeWtf16`, `StringAsWtf8`, `StringAsWtf16`) 等。

   尽管 JavaScript 代码不会直接触发这些 WebAssembly 内部的字符串操作，但理解这些指令的功能有助于理解 WebAssembly 如何在内部处理字符串。

4. **使用 WebAssembly 的字符串视图 (String View) API:**  WebAssembly 提供了字符串视图 API，允许在 WebAssembly 的线性内存中直接操作字符串数据，而无需创建完整的字符串对象。这里定义的 `StringViewWtf8Advance`, `StringViewWtf8Encode`, `StringViewWtf8Slice`, `StringViewWtf16GetCodeUnit`, `StringViewWtf16Encode`, `StringViewWtf16Slice` 等函数就是为了支持这些字符串视图操作。JavaScript 可以通过 `WebAssembly.StringView` 等 API 与这些 WebAssembly 字符串视图进行交互。

   ```javascript
   // 假设 WebAssembly 模块导出了一个函数 createStringView，返回一个字符串视图
   const view = instance.exports.createStringView();

   // 假设 WebAssembly 模块还导出了一个函数 getStringViewLength
   const length = instance.exports.getStringViewLength(view);
   console.log("String View Length:", length);
   ```

**总结:**

这部分 `liftoff-compiler.cc` 代码是 WebAssembly 引擎中处理字符串操作的关键部分。它定义了如何将 WebAssembly 的字符串指令转换为底层的机器码，从而使得 WebAssembly 能够有效地创建、操作和与 JavaScript 共享字符串数据。这些功能对于构建更复杂、更强大的 WebAssembly 应用，特别是那些需要进行文本处理的应用至关重要。

### 提示词
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```
RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kI32, result_reg);
  }

  void StringMeasureWtf16(FullDecoder* decoder, const Value& str,
                          Value* result) {
    LiftoffRegList pinned;
    LiftoffRegister string_reg = pinned.set(__ PopToRegister(pinned));
    MaybeEmitNullCheck(decoder, string_reg.gp(), pinned, str.type);
    LiftoffRegister value = __ GetUnusedRegister(kGpReg, pinned);
    LoadObjectField(decoder, value, string_reg.gp(), no_reg,
                    wasm::ObjectAccess::ToTagged(
                        compiler::AccessBuilder::ForStringLength().offset),
                    ValueKind::kI32, false /* is_signed */,
                    false /* trapping */, pinned);
    __ PushRegister(kI32, value);
  }

  void StringEncodeWtf8(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                        const unibrow::Utf8Variant variant, const Value& str,
                        const Value& offset, Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    DCHECK(MatchingMemType(imm.memory, 0));
    VarState offset_var = IndexToVarStateSaturating(0, &pinned);

    LiftoffRegister string_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-2], pinned));
    MaybeEmitNullCheck(decoder, string_reg.gp(), pinned, str.type);
    VarState string_var(kRef, string_reg, 0);

    VarState memory_var{kI32, static_cast<int32_t>(imm.index), 0};
    VarState variant_var{kI32, static_cast<int32_t>(variant), 0};

    CallBuiltin(Builtin::kWasmStringEncodeWtf8,
                MakeSig::Returns(kI32).Params(kIntPtrKind, kI32, kI32, kRef),
                {offset_var, memory_var, variant_var, string_var},
                decoder->position());
    __ DropValues(2);
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kI32, result_reg);
  }

  void StringEncodeWtf8Array(FullDecoder* decoder,
                             const unibrow::Utf8Variant variant,
                             const Value& str, const Value& array,
                             const Value& start, Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    LiftoffRegister array_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-2], pinned));
    MaybeEmitNullCheck(decoder, array_reg.gp(), pinned, array.type);
    VarState array_var(kRef, array_reg, 0);

    LiftoffRegister string_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-3], pinned));
    MaybeEmitNullCheck(decoder, string_reg.gp(), pinned, str.type);
    VarState string_var(kRef, string_reg, 0);

    VarState& start_var = __ cache_state()->stack_state.end()[-1];

    LiftoffRegister variant_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadSmi(variant_reg, static_cast<int32_t>(variant));
    VarState variant_var(kSmiKind, variant_reg, 0);

    CallBuiltin(Builtin::kWasmStringEncodeWtf8Array,
                MakeSig::Returns(kI32).Params(kRef, kRef, kI32, kSmiKind),
                {
                    string_var,
                    array_var,
                    start_var,
                    variant_var,
                },
                decoder->position());
    __ DropValues(3);
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kI32, result_reg);
  }

  void StringEncodeWtf16(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                         const Value& str, const Value& offset, Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    DCHECK(MatchingMemType(imm.memory, 0));
    VarState offset_var = IndexToVarStateSaturating(0, &pinned);

    LiftoffRegister string_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-2], pinned));
    MaybeEmitNullCheck(decoder, string_reg.gp(), pinned, str.type);
    VarState string_var(kRef, string_reg, 0);

    VarState memory_var{kI32, static_cast<int32_t>(imm.index), 0};

    CallBuiltin(Builtin::kWasmStringEncodeWtf16,
                MakeSig::Returns(kI32).Params(kRef, kIntPtrKind, kI32),
                {string_var, offset_var, memory_var}, decoder->position());
    __ DropValues(2);
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kI32, result_reg);
  }

  void StringEncodeWtf16Array(FullDecoder* decoder, const Value& str,
                              const Value& array, const Value& start,
                              Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    LiftoffRegister array_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-2], pinned));
    MaybeEmitNullCheck(decoder, array_reg.gp(), pinned, array.type);
    VarState array_var(kRef, array_reg, 0);

    LiftoffRegister string_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-3], pinned));
    MaybeEmitNullCheck(decoder, string_reg.gp(), pinned, str.type);
    VarState string_var(kRef, string_reg, 0);

    VarState& start_var = __ cache_state()->stack_state.end()[-1];

    CallBuiltin(Builtin::kWasmStringEncodeWtf16Array,
                MakeSig::Returns(kI32).Params(kRef, kRef, kI32),
                {
                    string_var,
                    array_var,
                    start_var,
                },
                decoder->position());
    __ DropValues(3);
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kI32, result_reg);
  }

  void StringConcat(FullDecoder* decoder, const Value& head, const Value& tail,
                    Value* result) {
    FUZZER_HEAVY_INSTRUCTION;  // Fast, but may create very long strings.
    LiftoffRegList pinned;

    LiftoffRegister tail_reg = pinned.set(__ PopToRegister(pinned));
    MaybeEmitNullCheck(decoder, tail_reg.gp(), pinned, tail.type);
    VarState tail_var(kRef, tail_reg, 0);

    LiftoffRegister head_reg = pinned.set(__ PopToRegister(pinned));
    MaybeEmitNullCheck(decoder, head_reg.gp(), pinned, head.type);
    VarState head_var(kRef, head_reg, 0);

    CallBuiltin(Builtin::kWasmStringConcat,
                MakeSig::Returns(kRef).Params(kRef, kRef),
                {
                    head_var,
                    tail_var,
                },
                decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kRef, result_reg);
  }

  void StringEq(FullDecoder* decoder, const Value& a, const Value& b,
                Value* result) {
    FUZZER_HEAVY_INSTRUCTION;  // Slow path is linear in string length.
    LiftoffRegister result_reg(kReturnRegister0);
    LiftoffRegList pinned{result_reg};
    LiftoffRegister b_reg = pinned.set(__ PopToModifiableRegister(pinned));
    LiftoffRegister a_reg = pinned.set(__ PopToModifiableRegister(pinned));

    __ SpillAllRegisters();

    Label done;

    {
      LiftoffRegister null = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      bool check_for_null = a.type.is_nullable() || b.type.is_nullable();
      if (check_for_null) {
        LoadNullValueForCompare(null.gp(), pinned, kWasmStringRef);
      }

      FREEZE_STATE(frozen);

      // If values pointer-equal, result is 1.
      __ LoadConstant(result_reg, WasmValue(int32_t{1}));
      __ emit_cond_jump(kEqual, &done, kRefNull, a_reg.gp(), b_reg.gp(),
                        frozen);

      // Otherwise if either operand is null, result is 0.
      if (check_for_null) {
        __ LoadConstant(result_reg, WasmValue(int32_t{0}));
        if (a.type.is_nullable()) {
          __ emit_cond_jump(kEqual, &done, kRefNull, a_reg.gp(), null.gp(),
                            frozen);
        }
        if (b.type.is_nullable()) {
          __ emit_cond_jump(kEqual, &done, kRefNull, b_reg.gp(), null.gp(),
                            frozen);
        }
      }

      // Ending the frozen state here is fine, because we already spilled the
      // rest of the cache, and the subsequent runtime call will reset the cache
      // state anyway.
    }

    // Operands are pointer-distinct and neither is null; call out to the
    // runtime.
    VarState a_var(kRef, a_reg, 0);
    VarState b_var(kRef, b_reg, 0);
    CallBuiltin(Builtin::kWasmStringEqual,
                MakeSig::Returns(kI32).Params(kRef, kRef),
                {
                    a_var,
                    b_var,
                },
                decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    __ bind(&done);

    __ PushRegister(kI32, result_reg);
  }

  void StringIsUSVSequence(FullDecoder* decoder, const Value& str,
                           Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    LiftoffRegister str_reg = pinned.set(__ PopToRegister(pinned));
    MaybeEmitNullCheck(decoder, str_reg.gp(), pinned, str.type);
    VarState str_var(kRef, str_reg, 0);

    CallBuiltin(Builtin::kWasmStringIsUSVSequence,
                MakeSig::Returns(kI32).Params(kRef),
                {
                    str_var,
                },
                decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kI32, result_reg);
  }

  void StringAsWtf8(FullDecoder* decoder, const Value& str, Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    LiftoffRegister str_reg = pinned.set(__ PopToRegister(pinned));
    MaybeEmitNullCheck(decoder, str_reg.gp(), pinned, str.type);
    VarState str_var(kRef, str_reg, 0);

    CallBuiltin(Builtin::kWasmStringAsWtf8, MakeSig::Returns(kRef).Params(kRef),
                {
                    str_var,
                },
                decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kRef, result_reg);
  }

  void StringViewWtf8Advance(FullDecoder* decoder, const Value& view,
                             const Value& pos, const Value& bytes,
                             Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    VarState& bytes_var = __ cache_state()->stack_state.end()[-1];
    VarState& pos_var = __ cache_state()->stack_state.end()[-2];

    LiftoffRegister view_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-3], pinned));
    MaybeEmitNullCheck(decoder, view_reg.gp(), pinned, view.type);
    VarState view_var(kRef, view_reg, 0);

    CallBuiltin(Builtin::kWasmStringViewWtf8Advance,
                MakeSig::Returns(kI32).Params(kRef, kI32, kI32),
                {
                    view_var,
                    pos_var,
                    bytes_var,
                },
                decoder->position());
    __ DropValues(3);
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kI32, result_reg);
  }

  void StringViewWtf8Encode(FullDecoder* decoder,
                            const MemoryIndexImmediate& imm,
                            const unibrow::Utf8Variant variant,
                            const Value& view, const Value& addr,
                            const Value& pos, const Value& bytes,
                            Value* next_pos, Value* bytes_written) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    VarState& bytes_var = __ cache_state()->stack_state.end()[-1];
    VarState& pos_var = __ cache_state()->stack_state.end()[-2];

    DCHECK(MatchingMemType(imm.memory, 2));
    VarState addr_var = IndexToVarStateSaturating(2, &pinned);

    LiftoffRegister view_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-4], pinned));
    MaybeEmitNullCheck(decoder, view_reg.gp(), pinned, view.type);
    VarState view_var(kRef, view_reg, 0);

    // TODO(jkummerow): Support Smi offsets when constructing {VarState}s
    // directly; avoid requesting a register.
    LiftoffRegister memory_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadSmi(memory_reg, imm.index);
    VarState memory_var(kSmiKind, memory_reg, 0);

    LiftoffRegister variant_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadSmi(variant_reg, static_cast<int32_t>(variant));
    VarState variant_var(kSmiKind, variant_reg, 0);

    CallBuiltin(
        Builtin::kWasmStringViewWtf8Encode,
        MakeSig::Returns(kI32, kI32)
            .Params(kIntPtrKind, kI32, kI32, kRef, kSmiKind, kSmiKind),
        {addr_var, pos_var, bytes_var, view_var, memory_var, variant_var},
        decoder->position());
    __ DropValues(4);
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister next_pos_reg(kReturnRegister0);
    __ PushRegister(kI32, next_pos_reg);
    LiftoffRegister bytes_written_reg(kReturnRegister1);
    __ PushRegister(kI32, bytes_written_reg);
  }

  void StringViewWtf8Slice(FullDecoder* decoder, const Value& view,
                           const Value& start, const Value& end,
                           Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    VarState& end_var = __ cache_state()->stack_state.end()[-1];
    VarState& start_var = __ cache_state()->stack_state.end()[-2];

    LiftoffRegister view_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-3], pinned));
    MaybeEmitNullCheck(decoder, view_reg.gp(), pinned, view.type);
    VarState view_var(kRef, view_reg, 0);

    CallBuiltin(Builtin::kWasmStringViewWtf8Slice,
                MakeSig::Returns(kRef).Params(kRef, kI32, kI32),
                {
                    view_var,
                    start_var,
                    end_var,
                },
                decoder->position());
    __ DropValues(3);
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kRef, result_reg);
  }

  void StringAsWtf16(FullDecoder* decoder, const Value& str, Value* result) {
    LiftoffRegList pinned;

    LiftoffRegister str_reg = pinned.set(__ PopToRegister(pinned));
    MaybeEmitNullCheck(decoder, str_reg.gp(), pinned, str.type);
    VarState str_var(kRef, str_reg, 0);

    CallBuiltin(Builtin::kWasmStringAsWtf16,
                MakeSig::Returns(kRef).Params(kRef),
                {
                    str_var,
                },
                decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kRef, result_reg);
  }

  void StringViewWtf16GetCodeUnit(FullDecoder* decoder, const Value& view,
                                  const Value& pos, Value* result) {
    LiftoffRegList pinned;
    LiftoffRegister pos_reg = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister view_reg = pinned.set(__ PopToRegister(pinned));
    MaybeEmitNullCheck(decoder, view_reg.gp(), pinned, view.type);
    VarState view_var(kRef, view_reg, 0);
    VarState pos_var(kI32, pos_reg, 0);

    CallBuiltin(Builtin::kWasmStringViewWtf16GetCodeUnit,
                MakeSig::Returns(kI32).Params(kRef, kI32), {view_var, pos_var},
                decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kI32, result_reg);
  }

  void StringViewWtf16Encode(FullDecoder* decoder,
                             const MemoryIndexImmediate& imm, const Value& view,
                             const Value& offset, const Value& pos,
                             const Value& codeunits, Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    VarState& codeunits_var = __ cache_state()->stack_state.end()[-1];
    VarState& pos_var = __ cache_state()->stack_state.end()[-2];

    DCHECK(MatchingMemType(imm.memory, 2));
    VarState offset_var = IndexToVarStateSaturating(2, &pinned);

    LiftoffRegister view_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-4], pinned));
    MaybeEmitNullCheck(decoder, view_reg.gp(), pinned, view.type);
    VarState view_var(kRef, view_reg, 0);

    LiftoffRegister memory_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadSmi(memory_reg, imm.index);
    VarState memory_var(kSmiKind, memory_reg, 0);

    CallBuiltin(
        Builtin::kWasmStringViewWtf16Encode,
        MakeSig::Returns(kI32).Params(kIntPtrKind, kI32, kI32, kRef, kSmiKind),
        {offset_var, pos_var, codeunits_var, view_var, memory_var},
        decoder->position());
    __ DropValues(4);
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kI32, result_reg);
  }

  void StringViewWtf16Slice(FullDecoder* decoder, const Value& view,
                            const Value& start, const Value& end,
                            Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;
    LiftoffRegister end_reg = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister start_reg = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister view_reg = pinned.set(__ PopToRegister(pinned));
    MaybeEmitNullCheck(decoder, view_reg.gp(), pinned, view.type);
    VarState view_var(kRef, view_reg, 0);
    VarState start_var(kI32, start_reg, 0);
    VarState end_var(kI32, end_reg, 0);

    CallBuiltin(Builtin::kWasmStringViewWtf16Slice,
                MakeSig::Returns(kRef).Params(kRef, kI32, kI32),
                {
                    view_var,
                    start_var,
                    end_var,
                },
                decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kRef, result_reg);
  }

  void StringAsIter(FullDecoder* decoder, const Value& str, Value* result) {
    LiftoffRegList pinned;

    LiftoffRegister str_reg = pinned.set(__ PopToRegister(pinned));
    MaybeEmitNullCheck(decoder, str_reg.gp(), pinned, str.type);
    VarState str_var(kRef, str_reg, 0);

    CallBuiltin(Builtin::kWasmStringAsIter, MakeSig::Returns(kRef).Params(kRef),
                {
                    str_var,
                },
                decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kRef, result_reg);
  }

  void StringViewIterNext(FullDecoder* decoder, const Value& view,
                          Value* result) {
    LiftoffRegList pinned;

    LiftoffRegister view_reg = pinned.set(__ PopToRegister(pinned));
    MaybeEmitNullCheck(decoder, view_reg.gp(), pinned, view.type);
    VarState view_var(kRef, view_reg, 0);

    CallBuiltin(Builtin::kWasmStringViewIterNext,
                MakeSig::Returns(kI32).Params(kRef),
                {
                    view_var,
                },
                decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kI32, result_reg);
  }

  void StringViewIterAdvance(FullDecoder* decoder, const Value& view,
                             const Value& codepoints, Value* result) {
    LiftoffRegList pinned;

    VarState& codepoints_var = __ cache_state()->stack_state.end()[-1];

    LiftoffRegister view_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-2], pinned));
    MaybeEmitNullCheck(decoder, view_reg.gp(), pinned, view.type);
    VarState view_var(kRef, view_reg, 0);

    CallBuiltin(Builtin::kWasmStringViewIterAdvance,
                MakeSig::Returns(kI32).Params(kRef, kI32),
                {
                    view_var,
                    codepoints_var,
                },
                decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ DropValues(2);
    __ PushRegister(kI32, result_reg);
  }

  void StringViewIterRewind(FullDecoder* decoder, const Value& view,
                            const Value& codepoints, Value* result) {
    LiftoffRegList pinned;

    VarState& codepoints_var = __ cache_state()->stack_state.end()[-1];

    LiftoffRegister view_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-2], pinned));
    MaybeEmitNullCheck(decoder, view_reg.gp(), pinned, view.type);
    VarState view_var(kRef, view_reg, 0);

    CallBuiltin(Builtin::kWasmStringViewIterRewind,
                MakeSig::Returns(kI32).Params(kRef, kI32),
                {
                    view_var,
                    codepoints_var,
                },
                decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ DropValues(2);
    __ PushRegister(kI32, result_reg);
  }

  void StringViewIterSlice(FullDecoder* decoder, const Value& view,
                           const Value& codepoints, Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    VarState& codepoints_var = __ cache_state()->stack_state.end()[-1];

    LiftoffRegister view_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-2], pinned));
    MaybeEmitNullCheck(decoder, view_reg.gp(), pinned, view.type);
    VarState view_var(kRef, view_reg, 0);

    CallBuiltin(Builtin::kWasmStringViewIterSlice,
                MakeSig::Returns(kRef).Params(kRef, kI32),
                {
                    view_var,
                    codepoints_var,
                },
                decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ DropValues(2);
    __ PushRegister(kRef, result_reg);
  }

  void StringCompare(FullDecoder* decoder, const Value& lhs, const Value& rhs,
                     Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;
    LiftoffRegister rhs_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-1], pinned));
    MaybeEmitNullCheck(decoder, rhs_reg.gp(), pinned, rhs.type);
    VarState rhs_var(kRef, rhs_reg, 0);

    LiftoffRegister lhs_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-2], pinned));
    MaybeEmitNullCheck(decoder, lhs_reg.gp(), pinned, lhs.type);
    VarState lhs_var(kRef, lhs_reg, 0);

    CallBuiltin(Builtin::kStringCompare,
                MakeSig::Returns(kSmiKind).Params(kRef, kRef),
                {lhs_var, rhs_var}, decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ DropValues(2);
    __ SmiToInt32(kReturnRegister0);
    __ PushRegister(kI32, result_reg);
  }

  void StringFromCodePoint(FullDecoder* decoder, const Value& code_point,
                           Value* result) {
    VarState& codepoint_var = __ cache_state()->stack_state.end()[-1];

    CallBuiltin(Builtin::kWasmStringFromCodePoint,
                MakeSig::Returns(kRef).Params(kI32), {codepoint_var},
                decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ DropValues(1);
    __ PushRegister(kRef, result_reg);
  }

  void StringHash(FullDecoder* decoder, const Value& string, Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;
    LiftoffRegister string_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-1], pinned));
    MaybeEmitNullCheck(decoder, string_reg.gp(), pinned, string.type);
    VarState string_var(kRef, string_reg, 0);

    CallBuiltin(Builtin::kWasmStringHash, MakeSig::Returns(kI32).Params(kRef),
                {string_var}, decoder->position());

    LiftoffRegister result_reg(kReturnRegister0);
    __ DropValues(1);
    __ PushRegister(kI32, result_reg);
  }

  void Forward(FullDecoder* decoder, const Value& from, Value* to) {
    // Nothing to do here.
  }

 private:
  void CallDirect(FullDecoder* decoder, const CallFunctionImmediate& imm,
                  const Value args[], Value returns[],
                  CallJumpMode call_jump_mode) {
    MostlySmallValueKindSig sig(zone_, imm.sig);
    for (ValueKind ret : sig.returns()) {
      if (!CheckSupportedType(decoder, ret, "return")) return;
    }

    auto call_descriptor = compiler::GetWasmCallDescriptor(zone_, imm.sig);
    call_descriptor = GetLoweredCallDescriptor(zone_, call_descriptor);

    // One slot would be enough for call_direct, but would make index
    // computations much more complicated.
    size_t vector_slot = encountered_call_instructions_.size() * 2;
    if (v8_flags.wasm_inlining) {
      encountered_call_instructions_.push_back(imm.index);
    }

    if (imm.index < env_->module->num_imported_functions) {
      // A direct call to an imported function.
      FUZZER_HEAVY_INSTRUCTION;
      LiftoffRegList pinned;
      Register implicit_arg =
          pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
      Register target = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();

      {
        SCOPED_CODE_COMMENT("Load ref and target for imported function");
        Register dispatch_table = target;
        LOAD_PROTECTED_PTR_INSTANCE_FIELD(dispatch_table,
                                          DispatchTableForImports, pinned);
        __ LoadProtectedPointer(
            implicit_arg, dispatch_table,
            ObjectAccess::ToTagged(WasmDispatchTable::OffsetOf(imm.index) +
                                   WasmDispatchTable::kImplicitArgBias));

        __ LoadCodePointer(
            target, dispatch_table,
            ObjectAccess::ToTagged(WasmDispatchTable::OffsetOf(imm.index) +
                                   WasmDispatchTable::kTargetBias));
      }

      __ PrepareCall(&sig, call_descriptor, &target, implicit_arg);
      if (call_jump_mode == CallJumpMode::kTailCall) {
        __ PrepareTailCall(
            static_cast<int>(call_descriptor->ParameterSlotCount()),
            static_cast<int>(
                call_descriptor->GetStackParameterDelta(descriptor_)));
        __ TailCallIndirect(target);
      } else {
        source_position_table_builder_.AddPosition(
            __ pc_offset(), SourcePosition(decoder->position()), true);
        __ CallIndirect(&sig, call_descriptor, target);
        FinishCall(decoder, &sig, call_descriptor);
      }
    } else {
      // Update call counts for inlining.
      if (v8_flags.wasm_inlining) {
        LiftoffRegister vector = __ GetUnusedRegister(kGpReg, {});
        __ Fill(vector, WasmLiftoffFrameConstants::kFeedbackVectorOffset,
                kIntPtrKind);
        __ IncrementSmi(vector,
                        wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(
                            static_cast<int>(vector_slot)));
        // Warning: {vector} may be clobbered by {IncrementSmi}!
      }
      // A direct call within this module just gets the current instance.
      __ PrepareCall(&sig, call_descriptor);
      // Just encode the function index. This will be patched at instantiation.
      Address addr = static_cast<Address>(imm.index);
      if (call_jump_mode == CallJumpMode::kTailCall) {
        DCHECK(descriptor_->CanTailCall(call_descriptor));
        __ PrepareTailCall(
            static_cast<int>(call_descriptor->ParameterSlotCount()),
            static_cast<int>(
                call_descriptor->GetStackParameterDelta(descriptor_)));
        __ TailCallNativeWasmCode(addr);
      } else {
        source_position_table_builder_.AddPosition(
            __ pc_offset(), SourcePosition(decoder->position()), true);
        __ CallNativeWasmCode(addr);
        FinishCall(decoder, &sig, call_descriptor);
      }
    }
  }

  void CallIndirectImpl(FullDecoder* decoder, const CallIndirectImmediate& imm,
                        CallJumpMode call_jump_mode) {
    MostlySmallValueKindSig sig(zone_, imm.sig);
    for (ValueKind ret : sig.returns()) {
      if (!CheckSupportedType(decoder, ret, "return")) return;
    }
    const WasmTable* table = imm.table_imm.table;

    if (v8_flags.wasm_deopt &&
        env_->deopt_info_bytecode_offset == decoder->pc_offset() &&
        env_->deopt_location_kind == LocationKindForDeopt::kEagerDeopt) {
      EmitDeoptPoint(decoder);
    }

    LiftoffRegList pinned;
    VarState index_slot = IndexToVarStateSaturating(0, &pinned);

    const bool is_static_index = index_slot.is_const();
    Register index_reg =
        is_static_index
            ? no_reg
            : pinned.set(__ LoadToRegister(index_slot, pinned).gp());

    static_assert(kV8MaxWasmTableSize <= kMaxUInt32);
    const uint32_t max_table_size =
        table->has_maximum_size ? static_cast<uint32_t>(std::min<uint64_t>(
                                      table->maximum_size, kV8MaxWasmTableSize))
                                : uint32_t{kV8MaxWasmTableSize};
    const bool statically_oob =
        is_static_index &&
        static_cast<uint32_t>(index_slot.i32_const()) >= max_table_size;

    TempRegisterScope temps;
    pinned |= temps.AddTempRegisters(3, kGpReg, &asm_, pinned);

    ScopedTempRegister dispatch_table{temps, kGpReg};
    if (imm.table_imm.index == 0) {
      // Load the dispatch table directly.
      LOAD_PROTECTED_PTR_INSTANCE_FIELD(dispatch_table.gp_reg(), DispatchTable0,
                                        pinned);
    } else {
      // Load the dispatch table from the ProtectedFixedArray of all dispatch
      // tables.
      Register dispatch_tables = dispatch_table.gp_reg();
      LOAD_PROTECTED_PTR_INSTANCE_FIELD(dispatch_tables, DispatchTables,
                                        pinned);
      __ LoadProtectedPointer(dispatch_table.gp_reg(), dispatch_tables,
                              ObjectAccess::ElementOffsetInProtectedFixedArray(
                                  imm.table_imm.index));
    }

    {
      SCOPED_CODE_COMMENT("Check index is in-bounds");
      // Bounds check against the table size: Compare against the dispatch table
      // size, or a constant if the size is statically known.
      const bool needs_dynamic_size =
          !table->has_maximum_size ||
          table->maximum_size != table->initial_size;

      Label* out_of_bounds_label =
          AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapTableOutOfBounds);

      ScopedTempRegister table_size{temps, kGpReg};
      FREEZE_STATE(trapping);
      if (statically_oob) {
        __ emit_jump(out_of_bounds_label);
        // This case is unlikely to happen in production. Thus we just continue
        // generating code afterwards, to make sure that the stack is in a
        // consistent state for following instructions.
      } else if (needs_dynamic_size) {
        __ Load(table_size.reg(), dispatch_table.gp_reg(), no_reg,
                wasm::ObjectAccess::ToTagged(WasmDispatchTable::kLengthOffset),
                LoadType::kI32Load);

        if (is_static_index) {
          __ emit_i32_cond_jumpi(kUnsignedLessThanEqual, out_of_bounds_label,
                                 table_size.gp_reg(), index_slot.i32_const(),
                                 trapping);
        } else {
          ValueKind comparison_type = kI32;
          if (Is64() && table->is_table64()) {
            // {index_reg} is a uintptr, so do a ptrsize comparison.
            __ emit_u32_to_uintptr(table_size.gp_reg(), table_size.gp_reg());
            comparison_type = kIntPtrKind;
          }
          __ emit_cond_jump(kUnsignedLessThanEqual, out_of_bounds_label,
                            comparison_type, table_size.gp_reg(), index_reg,
                            trapping);
        }
      } else {
        DCHECK_EQ(max_table_size, table->initial_size);
        if (is_static_index) {
          DCHECK_LT(index_slot.i32_const(), max_table_size);
        } else if (Is64() && table->is_table64()) {
          // On 32-bit, this is the same as below, so include the `Is64()` test
          // to statically tell the compiler to skip this branch.
          // Note: {max_table_size} will be sign-extended, which is fine because
          // the MSB is known to be 0 (asserted by the static_assert below).
          static_assert(kV8MaxWasmTableSize <= kMaxInt);
          __ emit_ptrsize_cond_jumpi(kUnsignedGreaterThanEqual,
                                     out_of_bounds_label, index_reg,
                                     max_table_size, trapping);
        } else {
          __ emit_i32_cond_jumpi(kUnsignedGreaterThanEqual, out_of_bounds_label,
                                 index_reg, max_table_size, trapping);
        }
      }
    }

    // If the function index is dynamic, compute a pointer to the dispatch table
    // entry. Otherwise remember the static offset from the dispatch table to
    // add it to later loads from that table.
    ScopedTempRegister dispatch_table_base{std::move(dispatch_table)};
    int dispatch_table_offset = 0;
    if (is_static_index) {
      // Avoid potential integer overflow here by excluding too large
      // (statically OOB) indexes. This code is not reached for statically OOB
      // indexes anyway.
      dispatch_table_offset =
          statically_oob
              ? 0
              : wasm::ObjectAccess::ToTagged(
                    WasmDispatchTable::OffsetOf(index_slot.i32_const()));
    } else {
      // TODO(clemensb): Produce better code for this (via more specialized
      // platform-specific methods?).

      Register entry_offset = index_reg;
      // After this computation we don't need the index register any more. If
      // there is no other user we can overwrite it.
      bool index_reg_still_used =
          __ cache_state() -> get_use_count(LiftoffRegister{index_reg}) > 1;
      if (index_reg_still_used) entry_offset = temps.Acquire(kGpReg).gp();

      __ emit_u32_to_uintptr(entry_offset, index_reg);
      index_reg = no_reg;
      __ emit_ptrsize_muli(entry_offset, entry_offset,
                           WasmDispatchTable::kEntrySize);
      __ emit_ptrsize_add(dispatch_table_base.gp_reg(),
                          dispatch_table_base.gp_reg(), entry_offset);
      if (index_reg_still_used) temps.Return(std::move(entry_offset));
      dispatch_table_offset =
          wasm::ObjectAccess::ToTagged(WasmDispatchTable::kEntriesOffset);
    }

    bool needs_type_check = !EquivalentTypes(
        table->type.AsNonNull(), ValueType::Ref(imm.sig_imm.index),
        decoder->module_, decoder->module_);
    bool needs_null_check = table->type.is_nullable();

    // We do both the type check and the null check by checking the signature,
    // so this shares most code. For the null check we then only check if the
    // stored signature is != -1.
    if (needs_type_check || needs_null_check) {
      SCOPED_CODE_COMMENT(needs_type_check ? "Check signature"
                                           : "Check for null entry");
      ScopedTempRegister real_sig_id{temps, kGpReg};

      // Load the signature from the dispatch table.
      __ Load(real_sig_id.reg(), dispatch_table_base.gp_reg(), no_reg,
              dispatch_table_offset + WasmDispatchTable::kSigBias,
              LoadType::kI32Load);

      // Compare against expected signature.
      // Since Liftoff code is never serialized (hence not reused across
      // isolates / processes) the canonical signature ID is a static integer.
      CanonicalTypeIndex canonical_sig_id =
          decoder->module_->canonical_sig_id(imm.sig_imm.index);
      Label* sig_mismatch_label =
          AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapFuncSigMismatch);
      __ DropValues(1);

      if (!needs_type_check) {
        DCHECK(needs_null_check);
        // Only check for -1 (nulled table entry).
        FREEZE_STATE(frozen);
        __ emit_i32_cond_jumpi(kEqual, sig_mismatch_label, real_sig_id.gp_reg(),
                               -1, frozen);
      } else if (!decoder->module_->type(imm.sig_imm.index).is_final) {
        Label success_label;
        FREEZE_STATE(frozen);
        __ emit_i32_cond_jumpi(kEqual, &success_label, real_sig_id.gp_reg(),
                               canonical_sig_id.index, frozen);
        if (needs_null_check) {
          __ emit_i32_cond_jumpi(kEqual, sig_mismatch_label,
                                 real_sig_id.gp_reg(), -1, frozen);
        }
        ScopedTempRegister real_rtt{temps, kGpReg};
        __ LoadFullPointer(
            real_rtt.gp_reg(), kRootRegister,
            IsolateData::root_slot_offset(RootIndex::kWasmCanonicalRtts));
        __ LoadTaggedPointer(
            real_rtt.gp_reg(), real_rtt.gp_reg(), real_sig_id.gp_reg(),
            ObjectAccess::ToTagged(OFFSET_OF_DATA_START(WeakFixedArray)),
            nullptr, true);
        // real_sig_id is not used any more.
        real_sig_id.Reset();
        // Remove the weak reference tag.
        if constexpr (kSystemPointerSize == 4) {
          __ emit_i32_andi(real_rtt.gp_reg(), real_rtt.gp_reg(),
                           static_cast<int32_t>(~kWeakHeapObjectMask));
        } else {
          __ emit_i64_andi(real_rtt.reg(), real_rtt.reg(),
                           static_cast<int32_t>(~kWeakHeapObjectMask));
        }
        // Constant-time subtyping check: load exactly one candidate RTT from
        // the supertypes list.
        // Step 1: load the WasmTypeInfo.
        constexpr int kTypeInfoOffset = wasm::ObjectAccess::ToTagged(
            Map::kConstructorOrBackPointerOrNativeContextOffset);
        ScopedTempRegister type_info{std::move(real_rtt)};
        __ LoadTaggedPointer(type_info.gp_reg(), type_info.gp_reg(), no_reg,
                             kTypeInfoOffset);
        // Step 2: check the list's length if needed.
        uint32_t rtt_depth =
            GetSubtypingDepth(decoder->module_, imm.sig_imm.index);
        if (rtt_depth >= kMinimumSupertypeArraySize) {
          ScopedTempRegister list_length{temps, kGpReg};
          int offset =
              ObjectAccess::ToTagged(WasmTypeInfo::kSupertypesLengthOffset);
          __ LoadSmiAsInt32(list_length.reg(), type_info.gp_reg(), offset);
          __ emit_i32_cond_jumpi(kUnsignedLessThanEqual, sig_mismatch_label,
                                 list_length.gp_reg(), rtt_depth, frozen);
        }
        // Step 3: load the candidate list slot, and compare it.
        ScopedTempRegister maybe_match{std::move(type_info)};
        __ LoadTaggedPointer(
            maybe_match.gp_reg(), maybe_match.gp_reg(), no_reg,
            ObjectAccess::ToTagged(WasmTypeInfo::kSupertypesOffset +
                                   rtt_depth * kTaggedSize));
        ScopedTempRegister formal_rtt{temps, kGpReg};
        // Instead of {pinned}, we use {kGpCacheRegList} as the list of pinned
        // registers, to prevent any attempt to cache the instance, which would
        // be incompatible with the {FREEZE_STATE} that is in effect here.
        LOAD_TAGGED_PTR_INSTANCE_FIELD(formal_rtt.gp_reg(), ManagedObjectMaps,
                                       kGpCacheRegList);
        __ LoadTaggedPointer(
            formal_rtt.gp_reg(), formal_rtt.gp_reg(), no_reg,
            wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(
                imm.sig_imm.index.index));
        __ emit_cond_jump(kNotEqual, sig_mismatch_label, kRtt,
                          formal_rtt.gp_reg(), maybe_match.gp_reg(), frozen);

        __ bind(&success_label);
      } else {
        FREEZE_STATE(trapping);
        __ emit_i32_cond_jumpi(kNotEqual, sig_mismatch_label,
                               real_sig_id.gp_reg(), canonical_sig_id.index,
                               trapping);
      }
    } else {
      __ DropValues(1);
    }

    {
      SCOPED_CODE_COMMENT("Execute indirect call");

      // The first parameter will be either a WasmTrustedInstanceData or a
      // WasmImportData.
      Register implicit_arg = temps.Acquire(kGpReg).gp();
      Register target = temps.Acquire(kGpReg).gp();

      {
        SCOPED_CODE_COMMENT("Load implicit arg and target from dispatch table");
        __ LoadProtectedPointer(
            implicit_arg, dispatch_table_base.gp_reg(),
            dispatch_table_offset + WasmDispatchTable::kImplicitArgBias);
        __ LoadCodePointer(
            target, dispatch_table_base.gp_reg(),
            dispatch_table_offset + WasmDispatchTable::kTargetBias);
      }

      if (v8_flags.wasm_inlining_call_indirect) {
        SCOPED_CODE_COMMENT("Feedback collection for speculative inlining");

        ScopedTempRegister vector{std::move(dispatch_table_base)};
        __ Fill(vector.reg(), WasmLiftoffFrameConstants::kFeedbackVectorOffset,
                kRef);
        VarState vector_var{kRef, vector.reg(), 0};

        // A constant `uint32_t` is sufficient for the vector slot index.
        // The number of call instructions (and hence feedback vector slots) is
        // capped by the number of instructions, which is capped by the maximum
        // function body size.
        static_assert(kV8MaxWasmFunctionSize <
                      std::numeric_limits<uint32_t>::max() / 2);
        uint32_t vector_slot =
            static_cast<uint32_t>(encountered_call_instructions_.size()) * 2;
        encountered_call_instructions_.push_back(
            FunctionTypeFeedback::kCallIndirect);
        VarState index_var(kI32, vector_slot, 0);

        // Thread the target and ref through the builtin call (i.e., pass them
        // as parameters and return them unchanged) as `CallBuiltin` otherwise
        // clobbers them. (The spilling code in `SpillAllRegisters` is only
        // aware of registers used on Liftoff's abstract value stack, not the
        // ones manually allocated above.)
        // TODO(335082212): We could avoid this and reduce the code size for
        // each call_indirect by moving the target and ref lookup into the
        // builtin as well.
        // However, then we would either (a) need to replicate the optimizations
        // above for static indices etc., which increases code duplication and
        // maintenance cost, or (b) regress performance even more than the
        // builtin call itself already does.
        // All in all, let's keep it simple at first, i.e., share the maximum
        // amount of code when inlining is enabled vs. not.
        VarState target_var(kIntPtrKind, LiftoffRegister(target), 0);
        VarState implicit_arg_var(kRef, LiftoffRegister(implicit_arg), 0);

        // CallIndirectIC(vector: FixedArray, vectorIndex: int32,
        //                target: RawPtr,
        //                implicitArg: WasmTrustedInstanceData|WasmImportData)
        //               -> <target, implicit_arg>
        CallBuiltin(Builtin::kCallIndirectIC,
                    MakeSig::Returns(kIntPtrKind, kIntPtrKind)
                        .Params(kRef, kI32, kIntPtrKind, kRef),
                    {vector_var, index_var, target_var, implicit_arg_var},
                    decoder->position());
        target = kReturnRegister0;
        implicit_arg = kReturnRegister1;
      }

      auto call_descriptor = compiler::GetWasmCallDescriptor(zone_, imm.sig);
      call_descriptor = GetLoweredCallDescriptor(zone_, call_descriptor);

      __ PrepareCall(&sig, call_descriptor, &target, implicit_arg);
      if (call_jump_mode == CallJumpMode::kTailCall) {
        __ PrepareTailCall(
            static_cast<int>(call_descriptor->ParameterSlotCount()),
            static_cast<int>(
                call_descriptor->GetStackParameterDelta(descriptor_)));
        __ TailCallIndirect(target);
      } else {
        source_position_table_builder_.AddPosition(
            __ pc_offset(), SourcePosition(decoder->position()), true);
        __ CallIndirect(&sig, call_descriptor, target);
        FinishCall(decoder, &sig, call_descriptor);
      }
    }
  }

  void StoreFrameDescriptionForDeopt(
      FullDecoder* decoder, uint32_t adapt_shadow_stack_pc_offset = 0) {
    DCHECK(v8_flags.wasm_deopt);
    DCHECK(!frame_description_);

    frame_description_ = std::make_unique<LiftoffFrameDescriptionForDeopt>(
        LiftoffFrameDescriptionForDeopt{
            decoder->pc_offset(), static_cast<uint32_t>(__ pc_offset()),
#ifdef V8_ENABLE_CET_SHADOW_STACK
            adapt_shadow_stack_pc_offset,
#endif  // V8_ENABLE_CET_SHADOW_STACK
            std::vector<LiftoffVarState>(__ cache_state()->stack_state.begin(),
                                         __ cache_state()->stack_state.end()),
            __ cache_state()->cached_instance_data});
  }

  void EmitDeoptPoint(FullDecoder* decoder) {
#if defined(DEBUG) and !defined(V8_TARGET_ARCH_ARM)
    // Liftoff may only use "allocatable registers" as defined by the
    // RegisterConfiguration. (The deoptimizer will not handle non-allocatable
    // registers).
    // Note that this DCHECK is skipped for arm 32 bit as its deoptimizer
    // decides to handle all available double / simd registers.
    const RegisterConfiguration* config = RegisterConfiguration::Default();
    DCHECK_LE(kLiftoffAssemblerFpCacheRegs.Count(),
              config->num_allocatable_simd128_registers());
    for (DoubleRegister reg : kLiftoffAssemblerFpCacheRegs) {
      const int* end = config->allocatable_simd128_codes() +
                       config->num_allocatable_simd128_registers();
      DCHECK(std::find(config->allocatable_simd128_codes(), end, reg.code()) !=
             end);
    }
#endif

    LiftoffAssembler::CacheState initial_state(zone_);
    initial_state.Split(*__ cache_state());
    // TODO(mliedtke): The deopt point should be in out-of-line-code.
    Label deopt_point;
    Label callref;
    __ emit_jump(&callref);
    __ bind(&deopt_point);
    uint32_t adapt_shadow_stack_pc_offset = __ pc_offset();
#ifdef V8_ENABLE_CET_SHADOW_STACK
    if (v8_flags.cet_compatible) {
      __ CallBuiltin(Builtin::kAdaptShadowStackForDeopt);
    }
#endif  // V8_ENABLE_CET_SHADOW_STACK
    StoreFrameDescriptionForDeopt(decoder, adapt_shadow_stack_pc_offset);
    CallBuiltin(Builtin::kWasmLiftoffDeoptFinish, MakeSig(), {},
                kNoSourcePosition);
    __ MergeStackWith(initial_state, 0, LiftoffAssembler::kForwardJump);
    __ cache_state() -> Steal(initial_state);
    __ bind(&callref);
  }

  void CallRefImpl(FullDecoder* decoder, ValueType func_ref_type,
                   const FunctionSig* type_sig, CallJumpMode call_jump_mode) {
    MostlySmallValueKindSig sig(zone_, type_sig);
    for (ValueKind ret : sig.returns()) {
      if (!CheckSupportedType(decoder, ret, "return")) return;
    }
    compiler::CallDescriptor* call_descriptor =
        compiler::GetWasmCallDescriptor(zone_, type_sig);
    call_descriptor = GetLoweredCallDescriptor(zone_, call_descriptor);

    Register target_reg = no_reg;
    Register implicit_arg_reg = no_reg;

    if (v8_flags.wasm_inlining) {
      if (v8_flags.wasm_deopt &&
          env_->deopt_info_bytecode_offset == decoder->pc_offset() &&
          env_->deopt_location_kind == LocationKindForDeopt::kEagerDeopt) {
        EmitDeoptPoint(decoder);
      }
      LiftoffRegList pinned;
      LiftoffRegister func_ref = pinned.set(__ PopToRegister(pinned));
      LiftoffRegister vector = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      MaybeEmitNullCheck(decoder, func_ref.gp(), pinned, func_ref_type);
      VarState func_ref_var(kRef, func_ref, 0);

#if V8_ENABLE_SANDBOX
      LiftoffRegister sig_hash_reg =
          pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      __ LoadConstant(sig_hash_reg, WasmValue{SignatureHasher::Hash(type_sig)});
      VarState sig_hash_var{kIntPtrKind, sig_hash_reg, 0};
#else
      VarState sig_hash_var{kIntPtrKind, 0, 0};  // Unused by callee.
#endif

      __ Fill(vector, WasmLiftoffFrameConstants::kFeedbackVectorOffset, kRef);
      VarState vector_var{kRef, vector, 0};
      // A constant `uint32_t` is sufficient for the vector slot index.
      // The number of call instructions (and hence feedback vector slots) is
      // capped by the number of instructions, which is capped by the maximum
      // function body size.
      static_assert(kV8MaxWasmFunctionSize <
                    std::numeric_limits<uint32_t>::max() / 2);
      uint32_t vector_slot =
          static_cast<uint32_t>(encountered_call_instructions_.size()) * 2;
      encountered_call_instructions_.push_back(FunctionTypeFeedback::kCallRef);
      VarState index_var(kI32, vector_slot, 0);

      // CallRefIC(vector: FixedArray, vectorIndex: int32,
      //           signatureHash: uintptr,
      //           funcref: WasmFuncRef) -> <target, implicit_arg>
      CallBuiltin(Builtin::kCallRefIC,
                  MakeSig::Returns(kIntPtrKind, kIntPtrKind)
                      .Params(kRef, kI32, kIntPtrKind, kRef),
                  {vector_var, index_var, sig_hash_var, func_ref_var},
                  decoder->position());
      target_reg = LiftoffRegister(kReturnRegister0).gp();
      implicit_arg_reg = kReturnRegister1;
    } else {  // v8_flags.wasm_inlining
      // Non-feedback-collecting version.
      // Executing a write barrier needs temp registers; doing this on a
      // conditional branch confuses the LiftoffAssembler's register management.
      // Spill everything up front to work around that.
      __ SpillAllRegisters();

      LiftoffRegList pinned;
      Register func_ref = pinned.set(__ PopToModifiableRegister(pinned)).gp();
      MaybeEmitNullCheck(decoder, func_ref, pinned, func_ref_type);
      implicit_arg_reg = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
      target_reg = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();

      // Load the WasmInternalFunction from the WasmFuncRef.
      Register internal_function = func_ref;
      __ LoadTrustedPointer(
          internal_function, func_ref,
          ObjectAccess::ToTagged(WasmFuncRef::kTrustedInternalOffset),
          kWasmInternalFunctionIndirectPointerTag);

      // Load the implicit argument (WasmTrustedInstanceData or WasmImportData)
      // and target.
      __ LoadProtectedPointer(
          implicit_arg_reg, internal_function,
          wasm::ObjectAccess::ToTagged(
              WasmInternalFunction::kProtectedImplicitArgOffset));

      __ LoadFullPointer(target_reg, internal_function,
                         wasm::ObjectAccess::ToTagged(
                             WasmInternalFunction::kCallTargetOffset));

      // Now the call target is in {target_reg} and the first parameter
      // (WasmTrustedInstanceData or WasmImportData) is in
      // {implicit_arg_reg}.
    }  // v8_flags.wasm_inlining

    __ PrepareCall(&sig, call_descriptor, &target_reg, implicit_arg_reg);
    if (call_jump_mode == CallJumpMode::kTailCall) {
      __ PrepareTailCall(
          static_cast<int>(call_descriptor->ParameterSlotCount()),
          static_cast<int>(
              call_descriptor->GetStackParameterDelta(descriptor_)));
      __ TailCallIndirect(target_reg);
    } else {
      source_position_table_builder_.AddPosition(
          __ pc_offset(), SourcePosition(decoder->position()), true);
      __ CallIndirect(&sig, call_descriptor, target_reg);
      FinishCall(decoder, &sig, call_descriptor);
    }
  }

  void LoadNullValue(Register null, ValueType type) {
    __ LoadFullPointer(
        null, kRootRegister,
        type.use_wasm_null()
            ? IsolateData::root_slot_offset(RootIndex::kWasmNull)
            : IsolateData::root_slot_offset(RootIndex::kNullValue));
  }

  // Stores the null value representation in the passed register.
  // If pointer compression is active, only the compressed tagged pointer
  // will be stored. Any operations with this register therefore must
  // not compare this against 64 bits using quadword instructions.
  void LoadNullValueForCompare(Register null, LiftoffRegList pinned,
                               ValueType type) {
#if V8_STATIC_ROOTS_BOOL
    uint32_t value = type.use_wasm_null() ? StaticReadOnlyRoot::kWasmNull
                                          : StaticReadOnlyRoot::kNullValue;
    __ LoadConstant(LiftoffRegister(null),
                    WasmValue(static_cast<uint32_t>(value)));
#else
    LoadNullValue(null, type);
#endif
  }

  void LoadExceptionSymbol(Register dst, LiftoffRegList pinned,
                           RootIndex root_index) {
    __ LoadFullPointer(dst, kRootRegister,
                       IsolateData::root_slot_offset(root_index));
  }

  void MaybeEmitNullCheck(FullDecoder* decoder, Register object,
                          LiftoffRegList pinned, ValueType type) {
    if (v8_flags.experimental_wasm_skip_null_checks || !type.is_nullable()) {
      return;
    }
    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapNullDereference);
    LiftoffRegister null = __ GetUnusedRegister(kGpReg, pinned);
    LoadNullValueForCompare(null.gp(), pinned, type);
    FREEZE_STATE(trapping);
    __ emit_cond_jump(kEqual, trap_label, kRefNull, object, null.gp(),
                      trapping);
  }

  void BoundsCheckArray(FullDecoder* decoder, bool implicit_null_check,
                        LiftoffRegister array, LiftoffRegister index,
                        LiftoffRegList pinned) {
    if (V8_UNLIKELY(v8_flags.experimental_wasm_skip_bounds_checks)) return;
    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapArrayOutOfBounds);
    LiftoffRegister length = __ GetUnusedRegister(kGpReg, pinned);
    constexpr int kLengthOffset =
        wasm::ObjectAccess::ToTagged(WasmArray::kLengthOffset);
    uint32_t protected_instruction_pc = 0;
    __ Load(length, array.gp(), no_reg, kLengthOffset, LoadType::kI32Load,
            implicit_null_check ? &protected_instruction_pc : nullptr);
    if (implicit_null_check) {
      RegisterProtectedInstruction(decoder, protected_instruction_pc);
    }
    FREEZE_STATE(trapping);
    __ emit_cond_jump(kUnsignedGreaterThanEqual, trap_label, kI32, index.gp(),
                      length.gp(), trapping);
  }

  int StructFieldOffset(const StructType* struct_type, int field_index) {
    return wasm::ObjectAccess::ToTagged(WasmStruct::kHeaderSize +
                                        struct_type->field_offset(field_index));
  }

  std::pair<bool, bool> null_checks_for_struct_op(ValueType struct_type,
                                                  int field_index) {
    bool explicit_null_check =
        struct_type.is_nullable() &&
        (null_check_strategy_ == compiler::NullCheckStrategy::kExplicit ||
         field_index > wasm::kMaxStructFieldIndexForImplicitNullCheck);
    bool implicit_null_check =
        struct_type.is_nullable() && !explicit_null_check;
    return {explicit_null_check, implicit_null_check};
  }

  void LoadObjectField(FullDecoder* decoder, LiftoffRegister dst, Register src,
                       Register offset_reg, int offset, ValueKind kind,
                       bool is_signed, bool trapping, LiftoffRegList pinned) {
    uint32_t protected_load_pc = 0;
    if (is_reference(kind)) {
      __ LoadTaggedPointer(dst.gp(), src, offset_reg, offset,
                           trapping ? &protected_load_pc : nullptr);
    } else {
      // Primitive kind.
      LoadType load_type = LoadType::ForValueKind(kind, is_signed);
      __ Load(dst, src, offset_reg, offset, load_type,
              trapping ? &protected_load_pc : nullptr);
    }
    if (trapping) RegisterProtectedInstruction(decoder, protected_load_pc);
  }

  void StoreObjectField(FullDecoder* decoder, Register obj, Register offset_reg,
                        int offset, LiftoffRegister value, bool trapping,
                        LiftoffRegList pinned, ValueKind kind,
                        LiftoffAssembler::SkipWriteBarrier skip_write_barrier =
                            LiftoffAssembler::kNoSkipWriteBarrier) {
    uint32_t protected_load_pc = 0;
    if (is_reference(kind)) {
      __ StoreTaggedPointer(obj, offset_reg, offset, value.gp(), pinned,
                            trapping ? &protected_load_pc : nullptr,
                            skip_write_barrier);
    } else {
      // Primitive kind.
      StoreType store_type = StoreType::ForValueKind(kind);
      __ Store(obj, offset_reg, offset, value, store_type, pinned,
               trapping ? &protected_load_pc : nullptr);
    }
    if (trapping) RegisterProtectedInstruction(decoder, protected_load_pc);
  }

  void SetDefaultValue(LiftoffRegister reg, ValueType type) {
    DCHECK(is_defaultable(type.kind()));
    switch (type.kind()) {
      case kI8:
      case kI16:
      case kI32:
        return __ LoadConstant(reg, WasmValue(int32_t{0}));
      case kI64:
        return __ LoadConstant(reg, WasmValue(int64_t{0}));
      case kF16:
      case kF32:
        return __ LoadConstant(reg, WasmValue(float{0.0}));
      case kF64:
        return __ LoadConstant(reg, WasmValue(double{0.0}));
      case kS128:
        DCHECK(CpuFeatures::SupportsWasmSimd128());
        return __ emit_s128_xor(reg, reg, reg);
      case kRefNull:
        return LoadNullValue(reg.gp(), type);
      case kRtt:
      case kVoid:
      case kTop:
      case kBottom:
      case kRef:
        UNREACHABLE();
    }
  }

  void MaybeOSR() {
    if (V8_UNLIKELY(for_debugging_)) {
      __ MaybeOSR();
    }
  }

  void FinishCall(FullDecoder* decoder, ValueKindSig* sig,
                  compiler::CallDescriptor* call_descriptor) {
    DefineSafepoint();
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    if (v8_flags.wasm_deopt &&
        env_->deopt_info_bytecode_offset == decoder->pc_offset() &&
        env_->deopt_location_kind == LocationKindForDeopt::kInlinedCall) {
      uint32_t adapt_shadow_stack_pc_offset = 0;
#ifdef V8_ENABLE_CET_SHADOW_STACK
      if (v8_flags.cet_compatible) {
        // AdaptShadowStackForDeopt is be called to build shadow stack after
        // deoptimization. Deoptimizer will directly jump to
        // `call AdaptShadowStackForDeopt`. But, in any other case, it should be
        // ignored.
        Label deopt_point;
        __ emit_jump(&deopt_point);
        adapt_shadow_stack_pc_offset = __ pc_offset();
        __ CallBuiltin(Builtin::kAdaptShadowStackForDeopt);
        __ bind(&deopt_point);
      }
#endif  // V8_ENABLE_CET_SHADOW_STACK
      StoreFrameDescriptionForDeopt(decoder, adapt_shadow_stack_pc_offset);
    }

    int pc_offset = __ pc_offset();
    MaybeOSR();
    EmitLandingPad(decoder, pc_offset);
    __ FinishCall(sig, call_descriptor);
  }

  void CheckNan(LiftoffRegister src, LiftoffRegList pinned, ValueKind kind) {
    DCHECK(kind == ValueKind::kF32 || kind == ValueKind::kF64);
    auto nondeterminism_addr = __ GetUnusedRegister(kGpReg, pinned);
    __ LoadConstant(
        nondeterminism_addr,
        WasmValue::ForUintPtr(reinterpret_cast<uintptr_t>(nondeterminism_)));
    __ emit_set_if_nan(nondeterminism_addr.gp(), src.fp(), kind);
  }

  void CheckS128Nan(LiftoffRegister dst, LiftoffRegList pinned,
                    ValueKind lane_kind) {
    RegClass rc = reg_class_for(kS128);
    LiftoffRegister tmp_gp = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LiftoffRegister tmp_s128 = pinned.set(__ GetUnusedRegister(rc, pinned));
    LiftoffRegister nondeterminism_addr =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    __ LoadConstant(
        nondeterminism_addr,
        WasmValue::ForUintPtr(reinterpret_cast<uintptr_t>(nondeterminism_)));
    __ emit_s128_set_if_nan(nondeterminism_addr.gp(), dst, tmp_gp.gp(),
                            tmp_s128, lane_kind);
  }

  void ArrayFillImpl(FullDecoder* decoder, LiftoffRegList pinned,
                     LiftoffRegister obj, LiftoffRegister index,
                     LiftoffRegister value, LiftoffRegister length,
                     ValueKind elem_kind,
                     LiftoffAssembler::SkipWriteBarrier skip_write_barrier) {
    // initial_offset = WasmArray::kHeaderSize + index * elem_size.
    LiftoffRegister offset = index;
    if (value_kind_size_log2(elem_kind) != 0) {
      __ emit_i32_shli(offset.gp(), index.gp(),
                       value_kind_size_log2(elem_kind));
    }
    __ emit_i32_addi(offset.gp(), offset.gp(),
                     wasm::ObjectAccess::ToTagged(WasmArray::kHeaderSize));

    // end_offset = initial_offset + length * elem_size.
    LiftoffRegister end_offset = length;
    if (value_kind_size_log2(elem_kind) != 0) {
      __ emit_i32_shli(end_offset.gp(), length.gp(),
                       value_kind_size_log2(elem_kind));
    }
    __ emit_i32_add(end_offset.gp(), end_offset.gp(), offset.gp());

    FREEZE_STATE(frozen_for_conditional_jumps);
    Label loop, done;
    __ bind(&loop);
    __ emit_cond_jump(kUnsignedGreaterThanEqual, &done, kI32, offset.gp(),
                      end_offset.gp(), frozen_for_conditional_jumps);
    StoreObjectField(decoder, obj.gp(), offset.gp(), 0, value, false, pinned,
                     elem_kind, skip_write_barrier);
    __ emit_i32_addi(offset.gp(), offset.gp(), value_kind_size(elem_kind));
    __ emit_jump(&loop);

    __ bind(&done);
  }

  void RegisterProtectedInstruction(FullDecoder* decoder,
                                    uint32_t protected_instruction_pc) {
    protected_instructions_.emplace_back(
        trap_handler::ProtectedInstructionData{protected_instruction_pc});
    source_position_table_builder_.AddPosition(
        protected_instruction_pc, SourcePosition(decoder->position()), true);
    if (for_debugging_) {
      DefineSafepoint(protected_instruction_pc);
    }
  }

  bool has_outstanding_op() const {
    return outstanding_op_ != kNoOutstandingOp;
  }

  bool test_and_reset_outstanding_op(WasmOpcode opcode) {
    DCHECK_NE(kNoOutstandingOp, opcode);
    if (outstanding_op_ != opcode) return false;
    outstanding_op_ = kNoOutstandingOp;
    return true;
  }

  void TraceCacheState(FullDecoder* decoder) const {
    if (!v8_flags.trace_liftoff) return;
    StdoutStream os;
    for (int control_depth = decoder->control_depth() - 1; control_depth >= -1;
         --control_depth) {
      auto* cache_state =
          control_depth == -1 ? __ cache_state()
                              : &decoder->control_at(control_depth)
                                     ->label_state;
      os << PrintCollection(cache_state->stack_state);
      if (control_depth != -1) PrintF("; ");
    }
    os << "\n";
  }

  void DefineSafepoint(int pc_offset = 0) {
    if (pc_offset == 0) pc_offset = __ pc_offset_for_safepoint();
    if (pc_offset == last_safepoint_offset_) return;
    last_safepoint_offset_ = pc_offset;
    auto safepoint = safepoint_table_builder_.DefineSafepoint(&asm_, pc_offset);
    __ cache_state()->DefineSafepoint(safepoint);
  }

  void DefineSafepointWithCalleeSavedRegisters() {
    int pc_offset = __ pc_offset_for_safepoint();
    if (pc_offset == last_safepoint_offset_) return;
    last_safepoint_offset_ = pc_offset;
    auto safepoint = safepoint_table_builder_.DefineSafepoint(&asm_, pc_offset);
    __ cache_state()->DefineSafepointWithCalleeSavedRegisters(safepoint);
  }

  // Return a register holding the instance, populating the "cached instance"
  // register if possible. If no free register is available, the cache is not
  // set and we use {fallback} instead. This can be freely overwritten by the
  // caller then.
  V8_INLINE Register LoadInstanceIntoRegister(LiftoffRegList pinned,
                                              Register fallback) {
    Register instance = __ cache_state() -> cached_instance_data;
    if (V8_UNLIKELY(instance == no_reg)) {
      instance = LoadInstanceIntoRegister_Slow(pinned, fallback);
    }
    return instance;
  }

  V8_NOINLINE V8_PRESERVE_MOST Register
  LoadInstanceIntoRegister_Slow(LiftoffRegList pinned, Register fallback) {
    DCHECK_EQ(no_reg, __ cache_state()->cached_instance_data);
    SCOPED_CODE_COMMENT("load instance");
    Register instance = __ cache_state()->TrySetCachedInstanceRegister(
        pinned | LiftoffRegList{fallback});
    if (instance == no_reg) instance = fallback;
    __ LoadInstanceDataFromFrame(instance);
    return instance;
  }

  static constexpr WasmOpcode kNoOutstandingOp = kExprUnreachable;
  static constexpr base::EnumSet<ValueKind> kUnconditionallySupported{
      // MVP:
      kI32, kI64, kF32, kF64,
      // Extern ref:
      kRef, kRefNull, kRtt, kI8, kI16};

  LiftoffAssembler asm_;

  // Used for merging code generation of subsequent operations (via look-ahea
```