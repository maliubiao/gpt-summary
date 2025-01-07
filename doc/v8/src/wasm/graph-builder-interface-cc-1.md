Response:
The user wants me to analyze a C++ code snippet from V8's `graph-builder-interface.cc` file, specifically the second part of a larger section. I need to:

1. **Identify the functionalities** within the provided code.
2. **Confirm if it's Torque code:** Based on the filename ending (`.cc`), it's not Torque.
3. **Determine relationship to JavaScript and provide examples:** Analyze if the functions interact with JavaScript concepts and illustrate with JS code if applicable.
4. **Infer code logic with hypothetical input/output:**  For specific functions, describe what input would lead to what output.
5. **Point out common programming errors:** Identify potential mistakes a programmer might make when using similar functionalities.
6. **Summarize the functionality of this specific part.**

Let's break down the code snippet:

- It seems to be handling calls to "well-known imports" in WebAssembly.
- It focuses heavily on string manipulation (`StringFromCharCode`, `StringFromCodePoint`, `StringFromWtf16Array`, etc.).
- It also covers other data type conversions and operations like `DoubleToString`, `IntToString`, `ParseFloat`, and `StringIndexOf`.
- There's code related to exception handling (`Throw`, `Rethrow`, `CatchException`, `Delegate`, `CatchAll`, `TryTable`, `CatchCase`).
- It includes logic for handling function calls (direct, indirect, and through function references) with potential inlining based on type feedback.
- There are sections for SIMD operations, atomic operations, and memory/table operations.
- It seems to interact with V8's internal `builder_` to create nodes in a graph representation, likely for optimization.

**Plan:**

1. List the distinct functionalities based on the `case` statements.
2. Confirm it's not Torque based on the file extension.
3. For string-related functions, show how they relate to JavaScript's `String` object and its methods.
4. For other conversions and operations, link them to corresponding JavaScript features.
5. For code logic, select a simpler case (e.g., `StringLength`) and describe input/output.
6. For common errors, focus on incorrect argument types or usage of string manipulation functions.
7. Summarize the overall purpose of this code segment.
这是对 `v8/src/wasm/graph-builder-interface.cc` 文件的一部分代码的功能归纳。

**功能列举:**

这段代码主要负责处理 WebAssembly 模块中调用 "well-known imports" (预定义的导入函数) 的情况，并将其转换为 V8 的内部图表示形式。 具体来说，它涵盖了以下功能：

* **字符串操作:**
    * 从字符编码创建字符串 (`StringFromCharCode`, `StringFromCodePoint`).
    * 从 UTF-16 数组创建字符串 (`StringFromWtf16Array`).
    * 从 UTF-8 数组创建字符串 (`StringFromUtf8Array`).
    * 将字符串编码到 UTF-8 数组 (`StringIntoUtf8Array`, `StringToUtf8Array`).
    * 获取字符串的长度 (`StringLength`, `StringMeasureUtf8`).
    * 获取字符串的子串 (`StringSubstring`).
    * 将字符串编码到 UTF-16 数组 (`StringToWtf16Array`).
* **类型转换:**
    * 将双精度浮点数转换为字符串 (`DoubleToString`).
    * 将整数转换为字符串 (`IntToString`).
    * 解析浮点数 (`ParseFloat`).
* **字符串查找:**
    * 查找子字符串在字符串中的索引 (`StringIndexOf`).
* **字符串大小写转换 (部分):**
    * 将字符串转换为小写 (`StringToLowerCaseStringref`).
    * (已注释掉) 将字符串转换为本地化小写 (`StringToLocaleLowerCaseStringref`).
* **数据视图操作 (未实现):**
    * 各种 `DataViewGet...` 和 `DataViewSet...` 操作。
    * 获取 `DataView` 的字节长度 (`DataViewByteLength`).
* **快速 API 调用 (未实现):**
    * `FastAPICall`.
* **调用处理:**
    * 处理直接函数调用 (`CallDirect`).
    * 处理尾调用 (`ReturnCall`).
    * 处理间接函数调用 (`CallIndirect`).
    * 处理间接尾调用 (`ReturnCallIndirect`).
    * 处理通过函数引用调用 (`CallRef`).
    * 处理通过函数引用尾调用 (`ReturnCallRef`).
* **引用类型操作:**
    * 判断引用是否为空 (`BrOnNull`).
    * 判断引用是否非空 (`BrOnNonNull`).
* **SIMD 操作:**
    * 执行 SIMD 指令 (`SimdOp`).
    * 执行 SIMD Lane 操作 (`SimdLaneOp`).
    * 执行 SIMD 8x16 洗牌操作 (`Simd8x16ShuffleOp`).
* **异常处理:**
    * 抛出异常 (`Throw`).
    * 重新抛出异常 (`Rethrow`).
    * 捕获和解包 Wasm 异常 (`CatchAndUnpackWasmException`).
    * 捕获特定类型的异常 (`CatchException`).
    * 委托异常处理 (`Delegate`).
    * 捕获所有异常 (`CatchAll`).
    * 尝试执行代码块 (`TryTable`).
    * 处理 `try-table` 中的 `catch` 子句 (`CatchCase`).
    * 抛出引用类型的异常 (`ThrowRef`).
* **原子操作:**
    * 执行原子操作 (`AtomicOp`).
    * 原子栅栏 (`AtomicFence`).
* **内存操作:**
    * 初始化内存 (`MemoryInit`).
    * 丢弃数据段 (`DataDrop`).
    * 复制内存 (`MemoryCopy`).
    * 填充内存 (`MemoryFill`).
* **表操作:**
    * 初始化表 (`TableInit`).
    * 丢弃元素段 (`ElemDrop`).
    * 复制表 (`TableCopy`).
    * 增长表 (`TableGrow`).
    * 获取表的大小 (`TableSize`).
    * 填充表 (`TableFill`).
* **结构体操作:**
    * 创建新的结构体实例 (`StructNew`).
    * 创建新的结构体实例并使用默认值初始化字段 (`StructNewDefault`).
    * 获取结构体字段的值 (`StructGet`).

**关于源代码类型:**

`v8/src/wasm/graph-builder-interface.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码**，而不是 v8 Torque 源代码。

**与 JavaScript 的关系及示例:**

这段代码处理的很多 "well-known imports" 都直接对应 JavaScript 的内置功能。以下是一些示例：

* **`WKI::kStringFromCharCode`:** 对应 JavaScript 的 `String.fromCharCode()` 方法。
   ```javascript
   const charCode = 65;
   const str = String.fromCharCode(charCode); // str 将会是 "A"
   ```
* **`WKI::kStringLength`:** 对应 JavaScript 字符串的 `length` 属性。
   ```javascript
   const str = "hello";
   const length = str.length; // length 将会是 5
   ```
* **`WKI::kStringSubstring`:** 对应 JavaScript 字符串的 `substring()` 或 `slice()` 方法。
   ```javascript
   const str = "hello";
   const sub = str.substring(1, 4); // sub 将会是 "ell"
   ```
* **`WKI::kDoubleToString`:**  对应 JavaScript 中数字到字符串的隐式转换或 `toString()` 方法。
   ```javascript
   const num = 123.45;
   const str = String(num); // str 将会是 "123.45"
   const str2 = num.toString(); // str2 将会是 "123.45"
   ```
* **`WKI::kIntToString`:** 对应 JavaScript 中整数到字符串的转换。
   ```javascript
   const num = 123;
   const str = String(num); // str 将会是 "123"
   ```
* **`WKI::kParseFloat`:** 对应 JavaScript 的 `parseFloat()` 函数。
   ```javascript
   const str = "3.14";
   const num = parseFloat(str); // num 将会是 3.14
   ```
* **`WKI::kStringIndexOf`:** 对应 JavaScript 字符串的 `indexOf()` 方法。
   ```javascript
   const str = "hello world";
   const index = str.indexOf("world"); // index 将会是 6
   ```
* **异常处理 (`Throw`, `Catch`)**: 对应 JavaScript 的 `throw` 语句和 `try...catch` 结构。
   ```javascript
   function mightThrow() {
     throw new Error("Something went wrong");
   }

   try {
     mightThrow();
   } catch (e) {
     console.error("Caught an error:", e.message);
   }
   ```

**代码逻辑推理 (假设输入与输出):**

以 `WKI::kStringLength` 为例：

**假设输入:**

* `args[0].node`: 一个表示外部字符串引用的 V8 内部节点，假设该字符串在 JavaScript 中是 `"example"`.

**输出:**

* `result`: 一个表示整数的 V8 内部节点，其值为 7 (字符串 `"example"` 的长度)。

**用户常见的编程错误:**

* **字符串操作相关的错误:**
    * **索引越界:**  在使用 `StringFromCharCode` 时传入超出 Unicode 范围的编码值，可能导致非预期的字符。在使用 `StringSubstring` 时，起始或结束索引超出字符串长度会导致错误或返回空字符串。
    * **类型错误:**  在期望字符串参数的地方传入非字符串类型的值，例如在调用 `StringLength` 时传入一个数字。
    * **编码问题:**  在处理 UTF-8 或 UTF-16 数组时，如果数组内容不是有效的编码，可能会导致创建的字符串出现乱码。例如，在使用 `StringFromUtf8Array` 时，如果字节数组包含无效的 UTF-8 序列。
    * **假设字符串非空:** 在没有进行空值检查的情况下直接对从 WebAssembly 导入的字符串引用进行操作，如果该引用实际上为空，则可能导致错误。

* **类型转换相关的错误:**
    * **`ParseFloat` 无法解析的字符串:**  将无法转换为数字的字符串传递给 `ParseFloat`，会导致返回 `NaN`。
    * **假设数字格式:** 在将数字转换为字符串时，没有考虑到不同语言环境的格式差异，可能导致输出与预期不符。

* **异常处理相关的错误:**
    * **没有正确捕获异常:**  在 WebAssembly 中抛出的异常如果没有被 JavaScript 或 WebAssembly 代码中的 `try...catch` 结构捕获，会导致程序终止。
    * **错误地假设异常类型:** 在 `catch` 块中假设了错误的异常类型，导致无法处理特定的异常。

**功能归纳:**

这段代码的主要功能是 **将 WebAssembly 中对各种 "well-known" (通常与 JavaScript 内置功能对应的) 导入函数的调用，转换为 V8 内部的图表示形式，以便后续的优化和代码生成**。它涵盖了字符串操作、类型转换、字符串查找、部分字符串大小写转换、函数调用（包括直接调用、间接调用和尾调用）、引用类型操作、SIMD 操作、原子操作、内存和表操作以及异常处理等多个方面。 这段代码是 WebAssembly 和 JavaScript 互操作性的关键部分，因为它允许 WebAssembly 代码有效地利用 JavaScript 引擎提供的功能。

Prompt: 
```
这是目录为v8/src/wasm/graph-builder-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/graph-builder-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
WKI::kStringFromCharCode:
        result = builder_->StringFromCharCode(args[0].node);
        builder_->SetType(result, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      case WKI::kStringFromCodePoint:
        result = builder_->StringFromCodePoint(args[0].node);
        builder_->SetType(result, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      case WKI::kStringFromWtf16Array:
        result = builder_->StringNewWtf16Array(
            args[0].node, NullCheckFor(args[0].type), args[1].node,
            args[2].node, decoder->position());
        builder_->SetType(result, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      case WKI::kStringFromUtf8Array:
        result = builder_->StringNewWtf8Array(
            unibrow::Utf8Variant::kLossyUtf8, args[0].node,
            NullCheckFor(args[0].type), args[1].node, args[2].node,
            decoder->position());
        builder_->SetType(result, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      case WKI::kStringIntoUtf8Array: {
        TFNode* string = ExternRefToString(decoder, args[0]);
        result = builder_->StringEncodeWtf8Array(
            unibrow::Utf8Variant::kLossyUtf8, string,
            compiler::kWithoutNullCheck, args[1].node,
            NullCheckFor(args[1].type), args[2].node, decoder->position());
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringToUtf8Array: {
        TFNode* string = ExternRefToString(decoder, args[0]);
        result = builder_->StringToUtf8Array(
            string, compiler::kWithoutNullCheck, decoder->position());
        builder_->SetType(result, returns[0].type);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringLength: {
        TFNode* string = ExternRefToString(decoder, args[0]);
        result = builder_->StringMeasureWtf16(
            string, compiler::kWithoutNullCheck, decoder->position());
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringMeasureUtf8: {
        TFNode* string = ExternRefToString(decoder, args[0]);
        result = builder_->StringMeasureWtf8(string, compiler::kWithNullCheck,
                                             decoder->position());
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringSubstring: {
        TFNode* string = ExternRefToString(decoder, args[0]);
        TFNode* view = builder_->StringAsWtf16(
            string, compiler::kWithoutNullCheck, decoder->position());
        builder_->SetType(view, kWasmRefExternString);
        result = builder_->StringViewWtf16Slice(
            view, compiler::kWithoutNullCheck, args[1].node, args[2].node,
            decoder->position());
        builder_->SetType(result, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringToWtf16Array: {
        TFNode* string = ExternRefToString(decoder, args[0]);
        result = builder_->StringEncodeWtf16Array(
            string, compiler::kWithoutNullCheck, args[1].node,
            NullCheckFor(args[1].type), args[2].node, decoder->position());
        decoder->detected_->add_imported_strings();
        break;
      }

      // Other string-related imports.
      case WKI::kDoubleToString:
        result = builder_->WellKnown_DoubleToString(args[0].node);
        break;
      case WKI::kIntToString:
        result = builder_->WellKnown_IntToString(args[0].node, args[1].node);
        break;
      case WKI::kParseFloat:
        result = builder_->WellKnown_ParseFloat(args[0].node,
                                                NullCheckFor(args[0].type));
        decoder->detected_->add_stringref();
        break;
      case WKI::kStringIndexOf:
        result = builder_->WellKnown_StringIndexOf(
            args[0].node, args[1].node, args[2].node,
            NullCheckFor(args[0].type), NullCheckFor(args[1].type));
        decoder->detected_->add_stringref();
        break;
      case WKI::kStringToLocaleLowerCaseStringref:
        // Temporarily ignored because of bugs (v8:13977, v8:13985).
        // TODO(jkummerow): Fix and re-enable.
        return false;
        // result = builder_->WellKnown_StringToLocaleLowerCaseStringref(
        //     args[0].node, args[1].node, NullCheckFor(args[0].type));
        // decoder->detected_->add_stringref();
        // break;
      case WKI::kStringToLowerCaseStringref:
        result = builder_->WellKnown_StringToLowerCaseStringref(
            args[0].node, NullCheckFor(args[0].type));
        decoder->detected_->add_stringref();
        break;
        // Not implementing for Turbofan.
      case WKI::kStringIndexOfImported:
      case WKI::kStringToLowerCaseImported:
      case WKI::kDataViewGetBigInt64:
      case WKI::kDataViewGetBigUint64:
      case WKI::kDataViewGetFloat32:
      case WKI::kDataViewGetFloat64:
      case WKI::kDataViewGetInt8:
      case WKI::kDataViewGetInt16:
      case WKI::kDataViewGetInt32:
      case WKI::kDataViewGetUint8:
      case WKI::kDataViewGetUint16:
      case WKI::kDataViewGetUint32:
      case WKI::kDataViewSetBigInt64:
      case WKI::kDataViewSetBigUint64:
      case WKI::kDataViewSetFloat32:
      case WKI::kDataViewSetFloat64:
      case WKI::kDataViewSetInt8:
      case WKI::kDataViewSetInt16:
      case WKI::kDataViewSetInt32:
      case WKI::kDataViewSetUint8:
      case WKI::kDataViewSetUint16:
      case WKI::kDataViewSetUint32:
      case WKI::kDataViewByteLength:
      case WKI::kFastAPICall:
        return false;
    }
    if (v8_flags.trace_wasm_inlining) {
      PrintF("[function %d: call to %d is well-known %s]\n", func_index_, index,
             WellKnownImportName(import));
    }
    assumptions_->RecordAssumption(index, import);
    SetAndTypeNode(&returns[0], result);
    // The decoder assumes that any call might throw, so if we are in a try
    // block, it marks the associated catch block as reachable, and will
    // later ask the graph builder to build the catch block's graph.
    // However, we just replaced the call with a sequence that doesn't throw,
    // which might make the catch block unreachable as far as the graph builder
    // is concerned, which would violate assumptions when trying to build a
    // graph for it. So we insert a fake branch to the catch block to make it
    // reachable. Later phases will optimize this out.
    if (decoder->current_catch() != -1) {
      TryInfo* try_info = current_try_info(decoder);
      if (try_info->catch_env->state == SsaEnv::kUnreachable) {
        auto [true_cont, false_cont] =
            builder_->BranchExpectTrue(builder_->Int32Constant(1));
        SsaEnv* success_env = Steal(decoder->zone(), ssa_env_);
        success_env->control = true_cont;

        SsaEnv* exception_env = Split(decoder->zone(), success_env);
        exception_env->control = false_cont;

        ScopedSsaEnv scoped_env(this, exception_env, success_env);

        if (emit_loop_exits()) {
          ValueVector stack_values;
          uint32_t depth = decoder->control_depth_of_current_catch();
          BuildNestedLoopExits(decoder, depth, true, stack_values);
        }
        Goto(decoder, try_info->catch_env);
        try_info->exception = builder_->Int32Constant(1);
      }
    }
    return true;
  }

  void CallDirect(FullDecoder* decoder, const CallFunctionImmediate& imm,
                  const Value args[], Value returns[]) {
    int maybe_call_count = -1;
    if (v8_flags.wasm_inlining && !type_feedback_.empty()) {
      const CallSiteFeedback& feedback = next_call_feedback();
      DCHECK_EQ(feedback.num_cases(), 1);
      maybe_call_count = feedback.call_count(0);
    }
    // This must happen after the {next_call_feedback()} call.
    if (HandleWellKnownImport(decoder, imm.index, args, returns)) return;

    DoCall(decoder, CallInfo::CallDirect(imm.index, maybe_call_count), imm.sig,
           args, returns);
  }

  void ReturnCall(FullDecoder* decoder, const CallFunctionImmediate& imm,
                  const Value args[]) {
    int maybe_call_count = -1;
    if (v8_flags.wasm_inlining && !type_feedback_.empty()) {
      const CallSiteFeedback& feedback = next_call_feedback();
      DCHECK_EQ(feedback.num_cases(), 1);
      maybe_call_count = feedback.call_count(0);
    }
    DoReturnCall(decoder, CallInfo::CallDirect(imm.index, maybe_call_count),
                 imm.sig, args);
  }

  void CallIndirect(FullDecoder* decoder, const Value& index,
                    const CallIndirectImmediate& imm, const Value args[],
                    Value returns[]) {
    DoCall(
        decoder,
        CallInfo::CallIndirect(index, imm.table_imm.index, imm.sig_imm.index),
        imm.sig, args, returns);
  }

  void ReturnCallIndirect(FullDecoder* decoder, const Value& index,
                          const CallIndirectImmediate& imm,
                          const Value args[]) {
    DoReturnCall(
        decoder,
        CallInfo::CallIndirect(index, imm.table_imm.index, imm.sig_imm.index),
        imm.sig, args);
  }

  void CallRef(FullDecoder* decoder, const Value& func_ref,
               const FunctionSig* sig, const Value args[], Value returns[]) {
    const CallSiteFeedback* feedback = nullptr;
    if (v8_flags.wasm_inlining && !type_feedback_.empty()) {
      feedback = &next_call_feedback();
    }
    if (feedback == nullptr || feedback->num_cases() == 0) {
      DoCall(decoder, CallInfo::CallRef(func_ref, NullCheckFor(func_ref.type)),
             sig, args, returns);
      return;
    }

    // Check for equality against a function at a specific index, and if
    // successful, just emit a direct call.
    int num_cases = feedback->num_cases();
    std::vector<TFNode*> control_args;
    std::vector<TFNode*> effect_args;
    std::vector<Value*> returns_values;
    control_args.reserve(num_cases + 1);
    effect_args.reserve(num_cases + 2);
    returns_values.reserve(num_cases);
    for (int i = 0; i < num_cases; i++) {
      const uint32_t expected_function_index = feedback->function_index(i);

      if (v8_flags.trace_wasm_inlining) {
        PrintF("[function %d: call #%d: graph support for inlining #%d]\n",
               func_index_, feedback_instruction_index_ - 1,
               expected_function_index);
      }

      TFNode* success_control;
      TFNode* failure_control;
      builder_->CompareToFuncRefAtIndex(func_ref.node, expected_function_index,
                                        &success_control, &failure_control,
                                        i == num_cases - 1);
      TFNode* initial_effect = effect();

      builder_->SetControl(success_control);
      ssa_env_->control = success_control;
      Value* returns_direct =
          decoder->zone()->AllocateArray<Value>(sig->return_count());
      for (size_t i = 0; i < sig->return_count(); i++) {
        returns_direct[i].type = returns[i].type;
      }
      DoCall(decoder,
             CallInfo::CallDirect(expected_function_index,
                                  feedback->call_count(i)),
             sig, args, returns_direct);
      control_args.push_back(control());
      effect_args.push_back(effect());
      returns_values.push_back(returns_direct);

      builder_->SetEffectControl(initial_effect, failure_control);
      ssa_env_->effect = initial_effect;
      ssa_env_->control = failure_control;
    }
    Value* returns_ref =
        decoder->zone()->AllocateArray<Value>(sig->return_count());
    for (size_t i = 0; i < sig->return_count(); i++) {
      returns_ref[i].type = returns[i].type;
    }
    DoCall(decoder, CallInfo::CallRef(func_ref, NullCheckFor(func_ref.type)),
           sig, args, returns_ref);

    control_args.push_back(control());
    TFNode* control = builder_->Merge(num_cases + 1, control_args.data());

    effect_args.push_back(effect());
    effect_args.push_back(control);
    TFNode* effect = builder_->EffectPhi(num_cases + 1, effect_args.data());

    ssa_env_->control = control;
    ssa_env_->effect = effect;
    builder_->SetEffectControl(effect, control);

    // Each of the {DoCall} helpers above has created a reload of the instance
    // cache nodes. Rather than merging all of them into a Phi, just
    // let them get DCE'ed and perform a single reload after the merge.
    ReloadInstanceCacheIntoSsa(ssa_env_, decoder->module_);

    for (uint32_t i = 0; i < sig->return_count(); i++) {
      std::vector<TFNode*> phi_args;
      phi_args.reserve(num_cases + 2);
      for (int j = 0; j < num_cases; j++) {
        phi_args.push_back(returns_values[j][i].node);
      }
      phi_args.push_back(returns_ref[i].node);
      phi_args.push_back(control);
      SetAndTypeNode(
          &returns[i],
          builder_->Phi(sig->GetReturn(i), num_cases + 1, phi_args.data()));
    }
  }

  void ReturnCallRef(FullDecoder* decoder, const Value& func_ref,
                     const FunctionSig* sig, const Value args[]) {
    const CallSiteFeedback* feedback = nullptr;
    if (v8_flags.wasm_inlining && !type_feedback_.empty()) {
      feedback = &next_call_feedback();
    }
    if (feedback == nullptr || feedback->num_cases() == 0) {
      DoReturnCall(decoder,
                   CallInfo::CallRef(func_ref, NullCheckFor(func_ref.type)),
                   sig, args);
      return;
    }

    // Check for equality against a function at a specific index, and if
    // successful, just emit a direct call.
    int num_cases = feedback->num_cases();
    for (int i = 0; i < num_cases; i++) {
      const uint32_t expected_function_index = feedback->function_index(i);

      if (v8_flags.trace_wasm_inlining) {
        PrintF("[function %d: call #%d: graph support for inlining #%d]\n",
               func_index_, feedback_instruction_index_ - 1,
               expected_function_index);
      }

      TFNode* success_control;
      TFNode* failure_control;
      builder_->CompareToFuncRefAtIndex(func_ref.node, expected_function_index,
                                        &success_control, &failure_control,
                                        i == num_cases - 1);
      TFNode* initial_effect = effect();

      builder_->SetControl(success_control);
      ssa_env_->control = success_control;
      DoReturnCall(decoder,
                   CallInfo::CallDirect(expected_function_index,
                                        feedback->call_count(i)),
                   sig, args);

      builder_->SetEffectControl(initial_effect, failure_control);
      ssa_env_->effect = initial_effect;
      ssa_env_->control = failure_control;
    }

    DoReturnCall(decoder,
                 CallInfo::CallRef(func_ref, NullCheckFor(func_ref.type)), sig,
                 args);
  }

  void BrOnNull(FullDecoder* decoder, const Value& ref_object, uint32_t depth,
                bool pass_null_along_branch, Value* result_on_fallthrough) {
    SsaEnv* false_env = ssa_env_;
    SsaEnv* true_env = Split(decoder->zone(), false_env);
    false_env->SetNotMerged();
    std::tie(true_env->control, false_env->control) =
        builder_->BrOnNull(ref_object.node, ref_object.type);
    builder_->SetControl(false_env->control);
    {
      ScopedSsaEnv scoped_env(this, true_env);
      int drop_values = pass_null_along_branch ? 0 : 1;
      BrOrRet(decoder, depth, drop_values);
    }
    SetAndTypeNode(
        result_on_fallthrough,
        builder_->TypeGuard(ref_object.node, result_on_fallthrough->type));
  }

  void BrOnNonNull(FullDecoder* decoder, const Value& ref_object, Value* result,
                   uint32_t depth, bool /* drop_null_on_fallthrough */) {
    SsaEnv* false_env = ssa_env_;
    SsaEnv* true_env = Split(decoder->zone(), false_env);
    false_env->SetNotMerged();
    std::tie(false_env->control, true_env->control) =
        builder_->BrOnNull(ref_object.node, ref_object.type);
    builder_->SetControl(false_env->control);
    ScopedSsaEnv scoped_env(this, true_env);
    // Make sure the TypeGuard has the right Control dependency.
    SetAndTypeNode(result, builder_->TypeGuard(ref_object.node, result->type));
    BrOrRet(decoder, depth);
  }

  void SimdOp(FullDecoder* decoder, WasmOpcode opcode, const Value* args,
              Value* result) {
    size_t num_inputs = WasmOpcodes::Signature(opcode)->parameter_count();
    NodeVector inputs(num_inputs);
    GetNodes(inputs.begin(), args, num_inputs);
    TFNode* node = builder_->SimdOp(opcode, inputs.begin());
    if (result) SetAndTypeNode(result, node);
  }

  void SimdLaneOp(FullDecoder* decoder, WasmOpcode opcode,
                  const SimdLaneImmediate& imm,
                  base::Vector<const Value> inputs, Value* result) {
    NodeVector nodes(inputs.size());
    GetNodes(nodes.begin(), inputs);
    SetAndTypeNode(result,
                   builder_->SimdLaneOp(opcode, imm.lane, nodes.begin()));
  }

  void Simd8x16ShuffleOp(FullDecoder* decoder, const Simd128Immediate& imm,
                         const Value& input0, const Value& input1,
                         Value* result) {
    TFNode* input_nodes[] = {input0.node, input1.node};
    SetAndTypeNode(result, builder_->Simd8x16ShuffleOp(imm.value, input_nodes));
  }

  void Throw(FullDecoder* decoder, const TagIndexImmediate& imm,
             const Value arg_values[]) {
    int count = static_cast<int>(imm.tag->sig->parameter_count());
    NodeVector args(count);
    GetNodes(args.data(), base::VectorOf(arg_values, count));
    CheckForException(decoder,
                      builder_->Throw(imm.index, imm.tag, base::VectorOf(args),
                                      decoder->position()),
                      false);
    builder_->TerminateThrow(effect(), control());
  }

  void Rethrow(FullDecoder* decoder, Control* block) {
    DCHECK(block->is_try_catchall() || block->is_try_catch());
    TFNode* exception = block->try_info->exception;
    DCHECK_NOT_NULL(exception);
    CheckForException(decoder, builder_->Rethrow(exception), false);
    builder_->TerminateThrow(effect(), control());
  }

  void CatchAndUnpackWasmException(FullDecoder* decoder, Control* block,
                                   TFNode* exception, const WasmTag* tag,
                                   TFNode* caught_tag, TFNode* exception_tag,
                                   base::Vector<Value> values) {
    TFNode* compare = builder_->ExceptionTagEqual(caught_tag, exception_tag);
    auto [if_catch, if_no_catch] = builder_->BranchNoHint(compare);
    // If the tags don't match we continue with the next tag by setting the
    // false environment as the new {TryInfo::catch_env} here.
    block->try_info->catch_env = Split(decoder->zone(), ssa_env_);
    block->try_info->catch_env->control = if_no_catch;
    block->block_env = Steal(decoder->zone(), ssa_env_);
    block->block_env->control = if_catch;
    SetEnv(block->block_env);
    NodeVector caught_values(values.size());
    base::Vector<TFNode*> caught_vector = base::VectorOf(caught_values);
    builder_->GetExceptionValues(exception, tag, caught_vector);
    for (size_t i = 0, e = values.size(); i < e; ++i) {
      SetAndTypeNode(&values[i], caught_values[i]);
    }
  }

  void CatchException(FullDecoder* decoder, const TagIndexImmediate& imm,
                      Control* block, base::Vector<Value> values) {
    DCHECK(block->is_try_catch());
    TFNode* exception = block->try_info->exception;
    SetEnv(block->try_info->catch_env);

    TFNode* caught_tag = builder_->GetExceptionTag(exception);
    TFNode* expected_tag = builder_->LoadTagFromTable(imm.index);

    if (imm.tag->sig->parameter_count() == 1 &&
        imm.tag->sig->GetParam(0).is_reference_to(HeapType::kExtern)) {
      // Check for the special case where the tag is WebAssembly.JSTag and the
      // exception is not a WebAssembly.Exception. In this case the exception is
      // caught and pushed on the operand stack.
      // Only perform this check if the tag signature is the same as
      // the JSTag signature, i.e. a single externref or (ref extern), otherwise
      // we know statically that it cannot be the JSTag.

      TFNode* is_js_exn = builder_->IsExceptionTagUndefined(caught_tag);
      auto [exn_is_js, exn_is_wasm] = builder_->BranchExpectFalse(is_js_exn);
      SsaEnv* exn_is_js_env = Split(decoder->zone(), ssa_env_);
      exn_is_js_env->control = exn_is_js;
      SsaEnv* exn_is_wasm_env = Steal(decoder->zone(), ssa_env_);
      exn_is_wasm_env->control = exn_is_wasm;

      // Case 1: A wasm exception.
      SetEnv(exn_is_wasm_env);
      CatchAndUnpackWasmException(decoder, block, exception, imm.tag,
                                  caught_tag, expected_tag, values);

      // Case 2: A JS exception.
      SetEnv(exn_is_js_env);
      TFNode* js_tag = builder_->LoadJSTag();
      TFNode* compare = builder_->ExceptionTagEqual(expected_tag, js_tag);
      auto [if_catch, if_no_catch] = builder_->BranchNoHint(compare);
      // Merge the wasm no-catch and JS no-catch paths.
      SsaEnv* if_no_catch_env = Split(decoder->zone(), ssa_env_);
      if_no_catch_env->control = if_no_catch;
      SetEnv(if_no_catch_env);
      Goto(decoder, block->try_info->catch_env);
      // Merge the wasm catch and JS catch paths.
      SsaEnv* if_catch_env = Steal(decoder->zone(), ssa_env_);
      if_catch_env->control = if_catch;
      SetEnv(if_catch_env);
      Goto(decoder, block->block_env);

      // The final env is a merge of case 1 and 2. The unpacked value is a Phi
      // of the unpacked value (case 1) and the exception itself (case 2).
      SetEnv(block->block_env);
      TFNode* phi_inputs[] = {values[0].node, exception,
                              block->block_env->control};
      TFNode* ref = builder_->Phi(wasm::kWasmExternRef, 2, phi_inputs);
      SetAndTypeNode(&values[0], ref);
    } else {
      CatchAndUnpackWasmException(decoder, block, exception, imm.tag,
                                  caught_tag, expected_tag, values);
    }
  }

  void Delegate(FullDecoder* decoder, uint32_t depth, Control* block) {
    DCHECK_EQ(decoder->control_at(0), block);
    DCHECK(block->is_incomplete_try());

    if (block->try_info->exception) {
      // Merge the current env into the target handler's env.
      SetEnv(block->try_info->catch_env);
      if (depth == decoder->control_depth() - 1) {
        if (inlined_status_ == kInlinedHandledCall) {
          if (emit_loop_exits()) {
            ValueVector stack_values;
            BuildNestedLoopExits(decoder, depth, false, stack_values,
                                 &block->try_info->exception);
          }
          // We are inlining this function and the inlined Call has a handler.
          // Add the delegated exception to {dangling_exceptions_}.
          dangling_exceptions_.Add(block->try_info->exception, effect(),
                                   control());
          return;
        }
        // We just throw to the caller here, so no need to generate IfSuccess
        // and IfFailure nodes.
        builder_->Rethrow(block->try_info->exception);
        builder_->TerminateThrow(effect(), control());
        return;
      }
      DCHECK(decoder->control_at(depth)->is_try());
      TryInfo* target_try = decoder->control_at(depth)->try_info;
      if (emit_loop_exits()) {
        ValueVector stack_values;
        BuildNestedLoopExits(decoder, depth, true, stack_values,
                             &block->try_info->exception);
      }
      Goto(decoder, target_try->catch_env);

      // Create or merge the exception.
      if (target_try->catch_env->state == SsaEnv::kReached) {
        target_try->exception = block->try_info->exception;
      } else {
        DCHECK_EQ(target_try->catch_env->state, SsaEnv::kMerged);
        target_try->exception = builder_->CreateOrMergeIntoPhi(
            MachineRepresentation::kTagged, target_try->catch_env->control,
            target_try->exception, block->try_info->exception);
      }
    }
  }

  void CatchAll(FullDecoder* decoder, Control* block) {
    DCHECK(block->is_try_catchall() || block->is_try_catch());
    DCHECK_EQ(decoder->control_at(0), block);
    SetEnv(block->try_info->catch_env);
  }

  void TryTable(FullDecoder* decoder, Control* block) { Try(decoder, block); }

  void CatchCase(FullDecoder* decoder, Control* block,
                 const CatchCase& catch_case, base::Vector<Value> values) {
    DCHECK(block->is_try_table());
    TFNode* exception = block->try_info->exception;
    SetEnv(block->try_info->catch_env);

    if (catch_case.kind == kCatchAll || catch_case.kind == kCatchAllRef) {
      if (catch_case.kind == kCatchAllRef) {
        DCHECK_EQ(values[0].type, ValueType::Ref(HeapType::kExn));
        values[0].node = block->try_info->exception;
      }
      BrOrRet(decoder, catch_case.br_imm.depth);
      return;
    }

    TFNode* caught_tag = builder_->GetExceptionTag(exception);
    TFNode* expected_tag =
        builder_->LoadTagFromTable(catch_case.maybe_tag.tag_imm.index);

    base::Vector<Value> values_without_exnref =
        catch_case.kind == kCatch ? values
                                  : values.SubVector(0, values.size() - 1);

    if (catch_case.maybe_tag.tag_imm.tag->sig->parameter_count() == 1 &&
        catch_case.maybe_tag.tag_imm.tag->sig->GetParam(0) == kWasmExternRef) {
      // Check for the special case where the tag is WebAssembly.JSTag and the
      // exception is not a WebAssembly.Exception. In this case the exception is
      // caught and pushed on the operand stack.
      // Only perform this check if the tag signature is the same as
      // the JSTag signature, i.e. a single externref, otherwise
      // we know statically that it cannot be the JSTag.

      TFNode* is_js_exn = builder_->IsExceptionTagUndefined(caught_tag);
      auto [exn_is_js, exn_is_wasm] = builder_->BranchExpectFalse(is_js_exn);
      SsaEnv* exn_is_js_env = Split(decoder->zone(), ssa_env_);
      exn_is_js_env->control = exn_is_js;
      SsaEnv* exn_is_wasm_env = Steal(decoder->zone(), ssa_env_);
      exn_is_wasm_env->control = exn_is_wasm;

      // Case 1: A wasm exception.
      SetEnv(exn_is_wasm_env);
      CatchAndUnpackWasmException(decoder, block, exception,
                                  catch_case.maybe_tag.tag_imm.tag, caught_tag,
                                  expected_tag, values_without_exnref);

      // Case 2: A JS exception.
      SetEnv(exn_is_js_env);
      TFNode* js_tag = builder_->LoadJSTag();
      TFNode* compare = builder_->ExceptionTagEqual(expected_tag, js_tag);
      auto [if_catch, if_no_catch] = builder_->BranchNoHint(compare);
      // Merge the wasm no-catch and JS no-catch paths.
      SsaEnv* if_no_catch_env = Split(decoder->zone(), ssa_env_);
      if_no_catch_env->control = if_no_catch;
      SetEnv(if_no_catch_env);
      Goto(decoder, block->try_info->catch_env);
      // Merge the wasm catch and JS catch paths.
      SsaEnv* if_catch_env = Steal(decoder->zone(), ssa_env_);
      if_catch_env->control = if_catch;
      SetEnv(if_catch_env);
      Goto(decoder, block->block_env);

      // The final env is a merge of case 1 and 2. The unpacked value is a Phi
      // of the unpacked value (case 1) and the exception itself (case 2).
      SetEnv(block->block_env);
      TFNode* phi_inputs[] = {values[0].node, exception,
                              block->block_env->control};
      TFNode* ref = builder_->Phi(wasm::kWasmExternRef, 2, phi_inputs);
      SetAndTypeNode(&values[0], ref);
    } else {
      CatchAndUnpackWasmException(decoder, block, exception,
                                  catch_case.maybe_tag.tag_imm.tag, caught_tag,
                                  expected_tag, values_without_exnref);
    }

    if (catch_case.kind == kCatchRef) {
      DCHECK_EQ(values.last().type, ValueType::Ref(HeapType::kExn));
      values.last().node = block->try_info->exception;
    }
    BrOrRet(decoder, catch_case.br_imm.depth);
    bool is_last = &catch_case == &block->catch_cases.last();
    if (is_last && !decoder->HasCatchAll(block)) {
      SetEnv(block->try_info->catch_env);
      ThrowRef(decoder, block->try_info->exception);
    }
  }

  void ThrowRef(FullDecoder* decoder, Value* value) {
    ThrowRef(decoder, value->node);
  }

  void AtomicOp(FullDecoder* decoder, WasmOpcode opcode, const Value args[],
                const size_t argc, const MemoryAccessImmediate& imm,
                Value* result) {
    NodeVector inputs(argc);
    GetNodes(inputs.begin(), args, argc);
    TFNode* node =
        builder_->AtomicOp(imm.memory, opcode, inputs.begin(), imm.alignment,
                           imm.offset, decoder->position());
    if (result) SetAndTypeNode(result, node);
  }

  void AtomicFence(FullDecoder* decoder) { builder_->AtomicFence(); }

  void MemoryInit(FullDecoder* decoder, const MemoryInitImmediate& imm,
                  const Value& dst, const Value& src, const Value& size) {
    builder_->MemoryInit(imm.memory.memory, imm.data_segment.index, dst.node,
                         src.node, size.node, decoder->position());
  }

  void DataDrop(FullDecoder* decoder, const IndexImmediate& imm) {
    builder_->DataDrop(imm.index, decoder->position());
  }

  void MemoryCopy(FullDecoder* decoder, const MemoryCopyImmediate& imm,
                  const Value& dst, const Value& src, const Value& size) {
    builder_->MemoryCopy(imm.memory_dst.memory, imm.memory_src.memory, dst.node,
                         src.node, size.node, decoder->position());
  }

  void MemoryFill(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                  const Value& dst, const Value& value, const Value& size) {
    builder_->MemoryFill(imm.memory, dst.node, value.node, size.node,
                         decoder->position());
  }

  void TableInit(FullDecoder* decoder, const TableInitImmediate& imm,
                 const Value& dst, const Value& src, const Value& size) {
    builder_->TableInit(imm.table.index, imm.element_segment.index, dst.node,
                        src.node, size.node, decoder->position());
  }

  void ElemDrop(FullDecoder* decoder, const IndexImmediate& imm) {
    builder_->ElemDrop(imm.index, decoder->position());
  }

  void TableCopy(FullDecoder* decoder, const TableCopyImmediate& imm,
                 const Value& dst, const Value& src, const Value& size) {
    builder_->TableCopy(imm.table_dst.index, imm.table_src.index, dst.node,
                        src.node, size.node, decoder->position());
  }

  void TableGrow(FullDecoder* decoder, const TableIndexImmediate& imm,
                 const Value& value, const Value& delta, Value* result) {
    SetAndTypeNode(result,
                   builder_->TableGrow(imm.index, value.node, delta.node,
                                       decoder->position()));
  }

  void TableSize(FullDecoder* decoder, const TableIndexImmediate& imm,
                 Value* result) {
    SetAndTypeNode(result, builder_->TableSize(imm.index));
  }

  void TableFill(FullDecoder* decoder, const TableIndexImmediate& imm,
                 const Value& start, const Value& value, const Value& count) {
    builder_->TableFill(imm.index, start.node, value.node, count.node,
                        decoder->position());
  }

  void StructNew(FullDecoder* decoder, const StructIndexImmediate& imm,
                 const Value args[], Value* result) {
    TFNode* rtt = builder_->RttCanon(imm.index);
    uint32_t field_count = imm.struct_type->field_count();
    NodeVector arg_nodes(field_count);
    for (uint32_t i = 0; i < field_count; i++) {
      arg_nodes[i] = args[i].node;
    }
    SetAndTypeNode(result, builder_->StructNew(imm.index, imm.struct_type, rtt,
                                               base::VectorOf(arg_nodes)));
  }
  void StructNewDefault(FullDecoder* decoder, const StructIndexImmediate& imm,
                        Value* result) {
    TFNode* rtt = builder_->RttCanon(imm.index);
    uint32_t field_count = imm.struct_type->field_count();
    NodeVector arg_nodes(field_count);
    for (uint32_t i = 0; i < field_count; i++) {
      ValueType field_type = imm.struct_type->field(i);
      arg_nodes[i] = builder_->SetType(builder_->DefaultValue(field_type),
                                       field_type.Unpacked());
    }
    SetAndTypeNode(result, builder_->StructNew(imm.index, imm.struct_type, rtt,
                                               base::VectorOf(arg_nodes)));
  }

  void StructGet(FullDecoder* decoder, const Value& struct_object,
                 const FieldI
"""


```