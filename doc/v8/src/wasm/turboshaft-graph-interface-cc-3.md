Response:
My thinking process to answer the request about `v8/src/wasm/turboshaft-graph-interface.cc` goes like this:

1. **Understand the Goal:** The request asks for a summary of the file's functionality, considering various aspects like Torque, JavaScript interaction, logic, and common errors. It also specifies this is part 4 of 12.

2. **Identify Key Information from the File Name and Path:**
    * `v8`: This clearly indicates a part of the V8 JavaScript engine.
    * `src`:  Suggests this is a source code file, likely containing core implementation logic.
    * `wasm`:  Focuses on WebAssembly functionality.
    * `turboshaft`:  Names the optimizing compiler for WebAssembly in V8.
    * `graph-interface`: Implies this file bridges the Turboshaft compiler with some other component, likely the Wasm decoder or intermediate representation.
    * `.cc`:  Indicates a C++ source file. The request specifically mentions checking for `.tq`, but since it's `.cc`, it's not a Torque file.

3. **Analyze the Provided Code Snippet:**  I carefully read the code, looking for recurring patterns, function names, and data structures. Key observations:
    * **`FullDecoder* decoder`:** This pointer is a common argument, suggesting the file is involved in the decoding or processing of WebAssembly bytecode.
    * **`WellKnownImportName` and `HandleWellKnownImport`:** These strongly suggest the file deals with special handling of certain imported functions.
    * **`GetStringIndexOf`, `CallStringToLowercase`:**  These indicate string manipulation operations, implying interaction with JavaScript strings or string-related WebAssembly features.
    * **`DataViewGetter`, `DataViewSetter`:**  These are related to `DataView` objects in JavaScript, which provide typed access to raw binary data.
    * **`CallDirect`, `ReturnCall`, `CallIndirect`, `ReturnCallIndirect`, `CallRef`, `ReturnCallRef`:** These are different calling mechanisms for WebAssembly functions, including direct calls, tail calls, indirect calls through tables, and calls through function references.
    * **`should_inline` and extensive inlining logic:**  This points to the file's role in the inlining optimization process within Turboshaft. The code branches based on whether a function should be inlined and implements logic for both inlined and non-inlined cases.
    * **`DeoptIfNot`, `CreateFrameState`:** These are related to deoptimization, a mechanism to fall back to less optimized code when assumptions made during compilation are violated. This further confirms the file's role in optimization.
    * **`BrOnNull`, `BrOnNonNull`:**  These handle branching based on whether a reference is null or not, a feature of WebAssembly's reference types.
    * **`SimdOp`:**  Indicates support for WebAssembly's SIMD (Single Instruction, Multiple Data) instructions.
    * **`Value args[]`, `Value returns[]`:** These arrays suggest the file manages the flow of data (arguments and return values) between WebAssembly functions.
    * **`assumptions_->RecordAssumption`:**  This suggests tracking assumptions made during compilation, which is crucial for speculative optimization and deoptimization.

4. **Infer Functionality Based on Observations:** Combining the file path and code analysis, I can infer the following functionalities:
    * **Interface between Wasm Decoder and Turboshaft:**  It takes decoded Wasm instructions and translates them into Turboshaft graph nodes.
    * **Handling Well-Known Imports:** It has specific logic for optimizing or inlining certain frequently used imported JavaScript functions.
    * **String and DataView Operations:** It supports Wasm operations that interact with JavaScript strings and `DataView` objects.
    * **Function Call Handling:**  It implements different call mechanisms, including direct and indirect calls, and calls through function references.
    * **Inlining Optimization:** A significant portion of the code deals with inlining decisions and the generation of inlined code.
    * **Deoptimization Support:** It includes mechanisms for deoptimizing when inlining assumptions are wrong.
    * **Reference Type Handling:**  It supports Wasm's reference types, including null checks and branching.
    * **SIMD Instruction Support:** It handles WebAssembly SIMD instructions.

5. **Address Specific Requirements:**
    * **Torque:**  The file extension is `.cc`, not `.tq`, so it's not a Torque file.
    * **JavaScript Relationship:** The code directly interacts with JavaScript concepts like strings and `DataView`. I can provide JavaScript examples demonstrating the corresponding Wasm functionality (e.g., `indexOf`, `toLowerCase`, `DataView` usage).
    * **Logic and I/O:** I can create simple scenarios with hypothetical inputs and outputs to illustrate the logic of functions like `GetStringIndexOf`.
    * **Common Errors:** I can think of common mistakes Wasm developers might make related to the handled operations, such as incorrect type casting of imported values or out-of-bounds access with `DataView`.

6. **Synthesize the Summary:**  Based on all the above points, I can formulate a concise summary that captures the core responsibilities of `turboshaft-graph-interface.cc`. I emphasize its role as the bridge between the Wasm decoder and the Turboshaft compiler, highlighting its key functionalities like handling imports, string/`DataView` operations, function calls, inlining, and deoptimization. I also include the information about it being part 4 of 12.

7. **Refine and Organize:** I organize the summary into logical sections, addressing each aspect of the request clearly and concisely. I ensure the language is accurate and avoids jargon where possible.

By following this systematic process, I can accurately and comprehensively answer the request, extracting the essential information from the code snippet and relating it to the broader context of V8 and WebAssembly.
好的，让我们来分析一下 `v8/src/wasm/turboshaft-graph-interface.cc` 这个文件的功能。

**文件功能归纳：**

`v8/src/wasm/turboshaft-graph-interface.cc` 文件是 V8 引擎中 Turboshaft 编译器处理 WebAssembly 代码的关键组成部分。它的主要功能是：

1. **作为 WebAssembly 解码器和 Turboshaft 编译器的桥梁：**  它接收解码后的 WebAssembly 指令，并将这些指令转换为 Turboshaft 编译器可以理解的图结构（graph）。这个过程涉及到将 Wasm 的操作语义映射到 Turboshaft 的节点和边。

2. **处理 WebAssembly 的各种操作：** 从提供的代码片段来看，这个文件负责处理大量的 WebAssembly 操作，包括：
    * **字符串操作：** 例如 `string.indexOf`、`string.toLowerCase` 等， 包括对导入的字符串进行处理。
    * **DataView 操作：**  支持 `DataView` 对象的各种 `get` 和 `set` 方法，用于访问和修改内存中的二进制数据。
    * **函数调用：**  处理直接调用 (`CallDirect`)、尾调用 (`ReturnCall`)、间接调用 (`CallIndirect`, `ReturnCallIndirect`) 和通过函数引用调用 (`CallRef`, `ReturnCallRef`)。
    * **控制流：**  处理基于 null 值的分支 (`BrOnNull`, `BrOnNonNull`)。
    * **SIMD 操作：**  初步迹象表明支持 SIMD 指令 (`SimdOp`)。
    * **Fast API 调用：**  处理特定的快速 API 调用 (`FastAPICall`)。

3. **支持内联优化：**  代码中大量出现了 `should_inline` 函数以及相关的逻辑，这表明该文件负责决定是否将某个函数调用内联到当前函数中，并且实现了内联的逻辑。这对于提高性能至关重要。

4. **处理导入的函数（Imports）：**  代码中专门处理了 "well-known" 的导入函数，例如字符串操作和 `DataView` 操作的导入版本 (`WKI::kStringIndexOfImported`, `WKI::kStringToLowerCaseImported` 等)。这允许 V8 对特定的常用导入函数进行优化。

5. **支持 Deoptimization (去优化)：**  代码中出现了 `DeoptIfNot` 和 `CreateFrameState`，这些都与去优化机制相关。当 Turboshaft 编译器做出的某些假设在运行时不成立时，会触发去优化，回到解释执行或较低级别的编译代码。

**关于文件类型和 JavaScript 关系：**

* **文件类型：**  `v8/src/wasm/turboshaft-graph-interface.cc` 的后缀是 `.cc`，这表明它是一个 **C++** 源文件。因此，它不是一个 Torque 源文件。

* **JavaScript 关系：**  这个文件与 JavaScript 的功能有密切关系，因为它处理的很多 WebAssembly 操作都对应 JavaScript 中的功能：
    * **字符串操作：**  Wasm 中的字符串操作通常与 JavaScript 中的字符串操作对应。
    * **`DataView`：** Wasm 可以导入和操作 JavaScript 的 `DataView` 对象。
    * **函数调用：**  Wasm 可以调用 JavaScript 函数，反之亦然。

**JavaScript 示例：**

```javascript
// 假设 WebAssembly 模块中导入了 String.prototype.indexOf 和 String.prototype.toLowerCase

const wasmModule = new WebAssembly.Instance(compiledWasm, importObject);

const myString = "Hello, World!";
const searchString = "World";
const startIndex = 7;

// 对应 WKI::kStringIndexOf 和 WKI::kStringIndexOfImported
const index = wasmModule.exports.stringIndexOf(myString, searchString, startIndex);
console.log(index); // 输出 7

// 对应 WKI::kStringToLowerCaseStringref 和 WKI::kStringToLowerCaseImported
const lowerCaseString = wasmModule.exports.stringToLowerCase(myString);
console.log(lowerCaseString); // 输出 "hello, world!"

// 对应 DataView 的 get 和 set 操作
const buffer = new ArrayBuffer(16);
const dataView = new DataView(buffer);

// 对应 WKI::kDataViewSetInt32
wasmModule.exports.dataViewSetInt32(dataView, 4, 12345, true); // offset 4, value 12345, littleEndian true

// 对应 WKI::kDataViewGetInt32
const value = wasmModule.exports.dataViewGetInt32(dataView, 4, true);
console.log(value); // 输出 12345
```

**代码逻辑推理示例：**

**假设输入：**

* `decoder`: 一个指向 `FullDecoder` 对象的指针，包含了当前 WebAssembly 模块的解码信息。
* `string`: 一个表示 JavaScript 字符串 "example" 的 `Value` 对象。
* `search`: 一个表示 JavaScript 字符串 "amp" 的 `Value` 对象。
* `start`: 一个表示起始索引 2 的 `Value` 对象。
* 当前执行的代码块是 `WKI::kStringIndexOf` 分支。

**预期输出：**

* `result`: 一个 `Value` 对象，其内部表示整数 4 (因为 "amp" 在 "example" 中从索引 4 开始)。
* `decoder->detected_->add_stringref()` 会被调用，记录使用了字符串引用。

**代码逻辑：**  `GetStringIndexOf` 函数会被调用，它会执行类似于 JavaScript 中 `string.indexOf(search, start)` 的操作。

**用户常见的编程错误示例：**

1. **在需要字符串的地方传入了非字符串的值：**

   ```javascript
   // Wasm 代码期望导入的参数是字符串
   wasmModule.exports.stringIndexOf(123, "a", 0); // 错误：第一个参数不是字符串
   ```
   在 `turboshaft-graph-interface.cc` 中，对于导入的字符串操作，会检查是否进行了显式的字符串类型转换 (`IsExplicitStringCast`)，如果类型不匹配，可能会导致内联失败或者运行时错误。

2. **`DataView` 的偏移量或长度超出范围：**

   ```javascript
   const buffer = new ArrayBuffer(8);
   const dataView = new DataView(buffer);

   // 错误：偏移量 10 超出了 buffer 的大小
   wasmModule.exports.dataViewGetInt32(dataView, 10, true);
   ```
   `turboshaft-graph-interface.cc` 中的 `DataViewGetter` 和 `DataViewSetter` 会处理这些操作，但如果偏移量不正确，最终会导致运行时错误。

3. **在 `StringToLowerCase` 等操作中传入了 `null` 或 `undefined`：**

   ```javascript
   wasmModule.exports.stringToLowerCase(null); // 错误：在 null 上调用 toLowerCase
   ```
   代码中针对 `WKI::kStringToLowerCaseStringref` 进行了检查，如果输入是 `null`，会抛出一个特定的异常 (`ThrowToLowerCaseCalledOnNull`)。

**作为第 4 部分的功能归纳：**

作为 Turboshaft 编译器流程的第 4 部分，`v8/src/wasm/turboshaft-graph-interface.cc` 的主要职责是在解码器完成 WebAssembly 代码的初步解析后，将这些信息转换为 Turboshaft 编译器可以进一步优化的图结构。它负责：

* **指令到图的转换：**  将 Wasm 的操作和控制流转换为 Turboshaft 的图节点和边。
* **初步的类型处理：**  根据 Wasm 的类型信息，创建相应的 Turboshaft 类型。
* **内联决策和实现：**  根据启发式规则和反馈信息，决定是否进行函数内联，并生成相应的内联代码。
* **处理与 JavaScript 的交互：**  处理涉及到 JavaScript 对象（如字符串和 `DataView`）的操作。

总而言之，`v8/src/wasm/turboshaft-graph-interface.cc` 是 WebAssembly 代码从解码到被 Turboshaft 编译器优化的关键转换环节，它负责理解 WebAssembly 的语义，并将其转化为编译器可以操作的形式，同时还处理了与 JavaScript 环境的互操作。

### 提示词
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/turboshaft-graph-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
].type), search_done_label,
                      search);
          GOTO(search_done_label, LOAD_ROOT(null_string));
          BIND(search_done_label, search_value);
          search = search_value;
        }

        result = GetStringIndexOf(decoder, string, search, start);
        decoder->detected_->add_stringref();
        break;
      }
      case WKI::kStringIndexOfImported: {
        // As the `string` and `search` parameters are externrefs, we have to
        // make sure they are strings. To enforce this, we inline only if a
        // (successful) `"js-string":"cast"` was performed before.
        if (!(IsExplicitStringCast(args[0]) && IsExplicitStringCast(args[1]))) {
          return false;
        }
        V<String> string = args[0].op;
        V<String> search = args[1].op;
        V<Word32> start = args[2].op;

        result = GetStringIndexOf(decoder, string, search, start);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringToLocaleLowerCaseStringref:
        // TODO(14108): Implement.
        return false;
      case WKI::kStringToLowerCaseStringref: {
#if V8_INTL_SUPPORT
        V<String> string = args[0].op;
        if (args[0].type.is_nullable()) {
          IF (__ IsNull(string, args[0].type)) {
            CallBuiltinThroughJumptable<
                BuiltinCallDescriptor::ThrowToLowerCaseCalledOnNull>(decoder,
                                                                     {});
            __ Unreachable();
          }
        }
        V<String> result_value = CallStringToLowercase(decoder, string);
        result = __ AnnotateWasmType(result_value, kWasmRefString);
        decoder->detected_->add_stringref();
        break;
#else
        return false;
#endif
      }
      case WKI::kStringToLowerCaseImported: {
        // We have to make sure that the externref `string` parameter is a
        // string. To enforce this, we inline only if a (successful)
        // `"js-string":"cast"` was performed before.
#if V8_INTL_SUPPORT
        if (!IsExplicitStringCast(args[0])) {
          return false;
        }
        V<String> string = args[0].op;
        V<String> result_value = CallStringToLowercase(decoder, string);
        result = __ AnnotateWasmType(result_value, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
#else
        return false;
#endif
      }

      // DataView related imports.
      // Note that we don't support DataView imports for resizable ArrayBuffers.
      case WKI::kDataViewGetBigInt64: {
        result = DataViewGetter(decoder, args, DataViewOp::kGetBigInt64);
        break;
      }
      case WKI::kDataViewGetBigUint64:
        result = DataViewGetter(decoder, args, DataViewOp::kGetBigUint64);
        break;
      case WKI::kDataViewGetFloat32:
        result = DataViewGetter(decoder, args, DataViewOp::kGetFloat32);
        break;
      case WKI::kDataViewGetFloat64:
        result = DataViewGetter(decoder, args, DataViewOp::kGetFloat64);
        break;
      case WKI::kDataViewGetInt8:
        result = DataViewGetter(decoder, args, DataViewOp::kGetInt8);
        break;
      case WKI::kDataViewGetInt16:
        result = DataViewGetter(decoder, args, DataViewOp::kGetInt16);
        break;
      case WKI::kDataViewGetInt32:
        result = DataViewGetter(decoder, args, DataViewOp::kGetInt32);
        break;
      case WKI::kDataViewGetUint8:
        result = DataViewGetter(decoder, args, DataViewOp::kGetUint8);
        break;
      case WKI::kDataViewGetUint16:
        result = DataViewGetter(decoder, args, DataViewOp::kGetUint16);
        break;
      case WKI::kDataViewGetUint32:
        result = DataViewGetter(decoder, args, DataViewOp::kGetUint32);
        break;
      case WKI::kDataViewSetBigInt64:
        DataViewSetter(decoder, args, DataViewOp::kSetBigInt64);
        break;
      case WKI::kDataViewSetBigUint64:
        DataViewSetter(decoder, args, DataViewOp::kSetBigUint64);
        break;
      case WKI::kDataViewSetFloat32:
        DataViewSetter(decoder, args, DataViewOp::kSetFloat32);
        break;
      case WKI::kDataViewSetFloat64:
        DataViewSetter(decoder, args, DataViewOp::kSetFloat64);
        break;
      case WKI::kDataViewSetInt8:
        DataViewSetter(decoder, args, DataViewOp::kSetInt8);
        break;
      case WKI::kDataViewSetInt16:
        DataViewSetter(decoder, args, DataViewOp::kSetInt16);
        break;
      case WKI::kDataViewSetInt32:
        DataViewSetter(decoder, args, DataViewOp::kSetInt32);
        break;
      case WKI::kDataViewSetUint8:
        DataViewSetter(decoder, args, DataViewOp::kSetUint8);
        break;
      case WKI::kDataViewSetUint16:
        DataViewSetter(decoder, args, DataViewOp::kSetUint16);
        break;
      case WKI::kDataViewSetUint32:
        DataViewSetter(decoder, args, DataViewOp::kSetUint32);
        break;
      case WKI::kDataViewByteLength: {
        V<Object> dataview = args[0].op;

        V<WordPtr> view_byte_length =
            GetDataViewByteLength(decoder, dataview, DataViewOp::kByteLength);
        if constexpr (Is64()) {
          result =
              __ ChangeInt64ToFloat64(__ ChangeIntPtrToInt64(view_byte_length));
        } else {
          result = __ ChangeInt32ToFloat64(
              __ TruncateWordPtrToWord32(view_byte_length));
        }
        break;
      }
      case WKI::kFastAPICall: {
        WellKnown_FastApi(decoder, imm, args, returns);
        result = returns[0].op;
        break;
      }
    }
    if (v8_flags.trace_wasm_inlining) {
      PrintF("[function %d: call to %d is well-known %s]\n", func_index_, index,
             WellKnownImportName(imported_op));
    }
    assumptions_->RecordAssumption(index, imported_op);
    returns[0].op = result;
    return true;
  }

  void CallDirect(FullDecoder* decoder, const CallFunctionImmediate& imm,
                  const Value args[], Value returns[]) {
    feedback_slot_++;
    if (imm.index < decoder->module_->num_imported_functions) {
      if (HandleWellKnownImport(decoder, imm, args, returns)) {
        return;
      }
      auto [target, implicit_arg] =
          BuildImportedFunctionTargetAndImplicitArg(decoder, imm.index);
      BuildWasmCall(decoder, imm.sig, target, implicit_arg, args, returns);
    } else {
      // Locally defined function.
      if (should_inline(decoder, feedback_slot_,
                        decoder->module_->functions[imm.index].code.length())) {
        if (v8_flags.trace_wasm_inlining) {
          PrintF("[function %d%s: inlining direct call #%d to function %d]\n",
                 func_index_, mode_ == kRegular ? "" : " (inlined)",
                 feedback_slot_, imm.index);
        }
        InlineWasmCall(decoder, imm.index, imm.sig, 0, false, args, returns);
      } else {
        V<WordPtr> callee =
            __ RelocatableConstant(imm.index, RelocInfo::WASM_CALL);
        BuildWasmCall(decoder, imm.sig, callee,
                      trusted_instance_data(
                          decoder->module_->function_is_shared(imm.index)),
                      args, returns);
      }
    }
  }

  void ReturnCall(FullDecoder* decoder, const CallFunctionImmediate& imm,
                  const Value args[]) {
    feedback_slot_++;
    if (imm.index < decoder->module_->num_imported_functions) {
      auto [target, implicit_arg] =
          BuildImportedFunctionTargetAndImplicitArg(decoder, imm.index);
      BuildWasmMaybeReturnCall(decoder, imm.sig, target, implicit_arg, args);
    } else {
      // Locally defined function.
      if (should_inline(decoder, feedback_slot_,
                        decoder->module_->functions[imm.index].code.length())) {
        if (v8_flags.trace_wasm_inlining) {
          PrintF(
              "[function %d%s: inlining direct tail call #%d to function %d]\n",
              func_index_, mode_ == kRegular ? "" : " (inlined)",
              feedback_slot_, imm.index);
        }
        InlineWasmCall(decoder, imm.index, imm.sig, 0, true, args, nullptr);
      } else {
        BuildWasmMaybeReturnCall(
            decoder, imm.sig,
            __ RelocatableConstant(imm.index, RelocInfo::WASM_CALL),
            trusted_instance_data(
                decoder->module_->function_is_shared(imm.index)),
            args);
      }
    }
  }

  void CallIndirect(FullDecoder* decoder, const Value& index,
                    const CallIndirectImmediate& imm, const Value args[],
                    Value returns[]) {
    if (v8_flags.wasm_inlining_call_indirect) {
      CHECK(v8_flags.wasm_inlining);
      feedback_slot_++;
      // In case of being unreachable, skip it because it tries to access nodes
      // which might be non-existent (OpIndex::Invalid()) in unreachable code.
      if (__ generating_unreachable_operations()) return;

      if (should_inline(decoder, feedback_slot_,
                        std::numeric_limits<int>::max())) {
        V<WordPtr> index_wordptr = TableAddressToUintPtrOrOOBTrap(
            imm.table_imm.table->address_type, index.op);

        DCHECK(!shared_);
        constexpr bool kNotShared = false;
        // Load the instance here even though it's only used below, in the hope
        // that load elimination can use it when fetching the target next.
        V<WasmTrustedInstanceData> instance = trusted_instance_data(kNotShared);

        // We are only interested in the target here for comparison against
        // the inlined call target below.
        // In particular, we don't need a dynamic type or null check: If the
        // actual call target (at runtime) is equal to the inlined call target,
        // we know already from the static check on the inlinee (see below) that
        // the inlined code has the right signature.
        constexpr bool kNeedsTypeOrNullCheck = false;
        auto [target, implicit_arg] = BuildIndirectCallTargetAndImplicitArg(
            decoder, index_wordptr, imm, kNeedsTypeOrNullCheck);

        size_t return_count = imm.sig->return_count();
        base::Vector<InliningTree*> feedback_cases =
            inlining_decisions_->function_calls()[feedback_slot_];
        std::vector<base::SmallVector<OpIndex, 2>> case_returns(return_count);
        // The slow path is the non-inlined generic `call_indirect`,
        // or a deopt node if that is enabled.
        constexpr int kSlowpathCase = 1;
        base::SmallVector<TSBlock*, wasm::kMaxPolymorphism + kSlowpathCase>
            case_blocks;
        for (size_t i = 0; i < feedback_cases.size() + kSlowpathCase; i++) {
          case_blocks.push_back(__ NewBlock());
        }
        // Block for the slowpath, i.e., the not-inlined call or deopt.
        TSBlock* no_inline_block = case_blocks.back();
        // Block for merging results after the inlined code.
        TSBlock* merge = __ NewBlock();

        // Always create a frame state, but rely on DCE to remove it in case we
        // end up not using deopts. This allows us to share the frame state
        // between a deopt due to wrong instance and deopt due to wrong target.
        V<FrameState> frame_state =
            CreateFrameState(decoder, imm.sig, &index, args);
        bool use_deopt_slowpath = deopts_enabled_;
        DCHECK_IMPLIES(use_deopt_slowpath, frame_state.valid());
        if (use_deopt_slowpath &&
            inlining_decisions_->has_non_inlineable_targets()[feedback_slot_]) {
          if (v8_flags.trace_wasm_inlining) {
            PrintF(
                "[function %d%s: Not emitting deopt slow-path for "
                "call_indirect #%d as feedback contains non-inlineable "
                "targets]\n",
                func_index_, mode_ == kRegular ? "" : " (inlined)",
                feedback_slot_);
          }
          use_deopt_slowpath = false;
        }

        // Wasm functions are semantically closures over the instance, but
        // when we inline a target in the following, we implicitly assume the
        // inlinee instance is the same as the caller's instance.
        // Directly jump to the non-inlined slowpath if that's violated.
        // Note that for `call_ref` this isn't necessary, because the funcref
        // equality check already captures both code and instance equality.
        constexpr BranchHint kUnlikelyCrossInstanceCall = BranchHint::kTrue;
        // Note that the `implicit_arg` can never be a `WasmImportData`,
        // since we don't inline imported functions right now.
        __ Branch({__ TaggedEqual(implicit_arg, instance),
                   kUnlikelyCrossInstanceCall},
                  case_blocks[0], no_inline_block);

        for (size_t i = 0; i < feedback_cases.size(); i++) {
          __ Bind(case_blocks[i]);
          InliningTree* tree = feedback_cases[i];
          if (!tree || !tree->is_inlined()) {
            // Fall through to the next case.
            __ Goto(case_blocks[i + 1]);
            // Do not use the deopt slowpath if we decided to not inline (at
            // least) one call target.
            // Otherwise, this could lead to a deopt loop.
            use_deopt_slowpath = false;
            continue;
          }
          uint32_t inlined_index = tree->function_index();
          // Ensure that we only inline if the inlinee's signature is compatible
          // with the call_indirect. In other words, perform the type check that
          // would normally be done dynamically (see above
          // `BuildIndirectCallTargetAndImplicitArg`) statically on the inlined
          // target. This can fail, e.g., because the mapping of feedback back
          // to function indices may produce spurious targets, or because the
          // feedback in the JS heap has been corrupted by a vulnerability.
          if (!InlineTargetIsTypeCompatible(
                  decoder->module_, imm.sig,
                  decoder->module_->functions[inlined_index].sig)) {
            __ Goto(case_blocks[i + 1]);
            continue;
          }

          V<WasmCodePtr> inlined_target =
              __ RelocatableWasmIndirectCallTarget(inlined_index);

          bool is_last_feedback_case = (i == feedback_cases.size() - 1);
          if (use_deopt_slowpath && is_last_feedback_case) {
              DeoptIfNot(decoder, __ WasmCodePtrEqual(target, inlined_target),
                         frame_state);
            } else {
            TSBlock* inline_block = __ NewBlock();
            BranchHint hint =
                is_last_feedback_case ? BranchHint::kTrue : BranchHint::kNone;
            __ Branch({__ WasmCodePtrEqual(target, inlined_target), hint},
                      inline_block, case_blocks[i + 1]);
            __ Bind(inline_block);
          }

          SmallZoneVector<Value, 4> direct_returns(return_count,
                                                   decoder->zone_);
          if (v8_flags.trace_wasm_inlining) {
            PrintF(
                "[function %d%s: Speculatively inlining call_indirect #%d, "
                "case #%zu, to function %d]\n",
                func_index_, mode_ == kRegular ? "" : " (inlined)",
                feedback_slot_, i, inlined_index);
          }
          InlineWasmCall(decoder, inlined_index, imm.sig,
                         static_cast<uint32_t>(i), false, args,
                         direct_returns.data());

          if (__ current_block() != nullptr) {
            // Only add phi inputs and a Goto to {merge} if the current_block is
            // not nullptr. If the current_block is nullptr, it means that the
            // inlined body unconditionally exits early (likely an unconditional
            // trap or throw).
            for (size_t ret = 0; ret < direct_returns.size(); ret++) {
              case_returns[ret].push_back(direct_returns[ret].op);
            }
            __ Goto(merge);
          }
        }

        __ Bind(no_inline_block);
        if (use_deopt_slowpath) {
          // We need this unconditional deopt only for the "instance check",
          // as the last "target check" already uses a `DeoptIfNot` node.
          Deopt(decoder, frame_state);
        } else {
          auto [target, implicit_arg] = BuildIndirectCallTargetAndImplicitArg(
              decoder, index_wordptr, imm);
          SmallZoneVector<Value, 4> indirect_returns(return_count,
                                                     decoder->zone_);
          BuildWasmCall(decoder, imm.sig, target, implicit_arg, args,
                        indirect_returns.data());
          for (size_t ret = 0; ret < indirect_returns.size(); ret++) {
            case_returns[ret].push_back(indirect_returns[ret].op);
          }
          __ Goto(merge);
        }

        __ Bind(merge);
        for (size_t i = 0; i < case_returns.size(); i++) {
          returns[i].op = __ Phi(base::VectorOf(case_returns[i]),
                                 RepresentationFor(imm.sig->GetReturn(i)));
        }

        return;
      }  // should_inline
    }    // v8_flags.wasm_inlining_call_indirect

    // Didn't inline.
    V<WordPtr> index_wordptr = TableAddressToUintPtrOrOOBTrap(
        imm.table_imm.table->address_type, index.op);
    auto [target, implicit_arg] =
        BuildIndirectCallTargetAndImplicitArg(decoder, index_wordptr, imm);
    BuildWasmCall(decoder, imm.sig, target, implicit_arg, args, returns);
  }

  void ReturnCallIndirect(FullDecoder* decoder, const Value& index,
                          const CallIndirectImmediate& imm,
                          const Value args[]) {
    if (v8_flags.wasm_inlining_call_indirect) {
      CHECK(v8_flags.wasm_inlining);
      feedback_slot_++;

      if (should_inline(decoder, feedback_slot_,
                        std::numeric_limits<int>::max())) {
        V<WordPtr> index_wordptr = TableAddressToUintPtrOrOOBTrap(
            imm.table_imm.table->address_type, index.op);

        DCHECK(!shared_);
        constexpr bool kNotShared = false;
        // Load the instance here even though it's only used below, in the hope
        // that load elimination can use it when fetching the target next.
        V<WasmTrustedInstanceData> instance = trusted_instance_data(kNotShared);

        // We are only interested in the target here for comparison against
        // the inlined call target below.
        // In particular, we don't need a dynamic type or null check: If the
        // actual call target (at runtime) is equal to the inlined call target,
        // we know already from the static check on the inlinee (see below) that
        // the inlined code has the right signature.
        constexpr bool kNeedsTypeOrNullCheck = false;
        auto [target, implicit_arg] = BuildIndirectCallTargetAndImplicitArg(
            decoder, index_wordptr, imm, kNeedsTypeOrNullCheck);

        base::Vector<InliningTree*> feedback_cases =
            inlining_decisions_->function_calls()[feedback_slot_];
        constexpr int kSlowpathCase = 1;
        base::SmallVector<TSBlock*, wasm::kMaxPolymorphism + kSlowpathCase>
            case_blocks;
        for (size_t i = 0; i < feedback_cases.size() + kSlowpathCase; i++) {
          case_blocks.push_back(__ NewBlock());
        }
        // Block for the slowpath, i.e., the not-inlined call.
        TSBlock* no_inline_block = case_blocks.back();

        // Wasm functions are semantically closures over the instance, but
        // when we inline a target in the following, we implicitly assume the
        // inlinee instance is the same as the caller's instance.
        // Directly jump to the non-inlined slowpath if that's violated.
        // Note that for `call_ref` this isn't necessary, because the funcref
        // equality check already captures both code and instance equality.
        constexpr BranchHint kUnlikelyCrossInstanceCall = BranchHint::kTrue;
        // Note that the `implicit_arg` can never be a `WasmImportData`,
        // since we don't inline imported functions right now.
        __ Branch({__ TaggedEqual(implicit_arg, instance),
                   kUnlikelyCrossInstanceCall},
                  case_blocks[0], no_inline_block);

        for (size_t i = 0; i < feedback_cases.size(); i++) {
          __ Bind(case_blocks[i]);
          InliningTree* tree = feedback_cases[i];
          if (!tree || !tree->is_inlined()) {
            // Fall through to the next case.
            __ Goto(case_blocks[i + 1]);
            continue;
          }
          uint32_t inlined_index = tree->function_index();
          // Ensure that we only inline if the inlinee's signature is compatible
          // with the call_indirect. In other words, perform the type check that
          // would normally be done dynamically (see above
          // `BuildIndirectCallTargetAndImplicitArg`) statically on the inlined
          // target. This can fail, e.g., because the mapping of feedback back
          // to function indices may produce spurious targets, or because the
          // feedback in the JS heap has been corrupted by a vulnerability.
          if (!InlineTargetIsTypeCompatible(
                  decoder->module_, imm.sig,
                  decoder->module_->functions[inlined_index].sig)) {
            __ Goto(case_blocks[i + 1]);
            continue;
          }

          V<WasmCodePtr> inlined_target =
              __ RelocatableWasmIndirectCallTarget(inlined_index);

          TSBlock* inline_block = __ NewBlock();
          bool is_last_case = (i == feedback_cases.size() - 1);
          BranchHint hint =
              is_last_case ? BranchHint::kTrue : BranchHint::kNone;
          __ Branch({__ WasmCodePtrEqual(target, inlined_target), hint},
                    inline_block, case_blocks[i + 1]);
          __ Bind(inline_block);
          if (v8_flags.trace_wasm_inlining) {
            PrintF(
                "[function %d%s: Speculatively inlining return_call_indirect "
                "#%d, case #%zu, to function %d]\n",
                func_index_, mode_ == kRegular ? "" : " (inlined)",
                feedback_slot_, i, inlined_index);
          }
          InlineWasmCall(decoder, inlined_index, imm.sig,
                         static_cast<uint32_t>(i), true, args, nullptr);

          // An inlined tail call should still terminate execution.
          DCHECK_NULL(__ current_block());
        }

        __ Bind(no_inline_block);
      }  // should_inline
    }    // v8_flags.wasm_inlining_call_indirect

    // Didn't inline.
    V<WordPtr> index_wordptr = TableAddressToUintPtrOrOOBTrap(
        imm.table_imm.table->address_type, index.op);
    auto [target, implicit_arg] =
        BuildIndirectCallTargetAndImplicitArg(decoder, index_wordptr, imm);
    BuildWasmMaybeReturnCall(decoder, imm.sig, target, implicit_arg, args);
  }

  void CallRef(FullDecoder* decoder, const Value& func_ref,
               const FunctionSig* sig, const Value args[], Value returns[]) {
    // TODO(14108): As the slot needs to be aligned with Liftoff, ideally the
    // stack slot index would be provided by the decoder and passed to both
    // Liftoff and Turbofan.
    feedback_slot_++;
    // In case of being unreachable, skip it because it tries to access nodes
    // which might be non-existent (OpIndex::Invalid()) in unreachable code.
    if (__ generating_unreachable_operations()) return;

#if V8_ENABLE_SANDBOX
    uint64_t signature_hash = SignatureHasher::Hash(sig);
#else
    uint64_t signature_hash = 0;
#endif  // V8_ENABLE_SANDBOX

    if (should_inline(decoder, feedback_slot_,
                      std::numeric_limits<int>::max())) {
      DCHECK(!shared_);
      constexpr bool kNotShared = false;
      V<FixedArray> func_refs = LOAD_IMMUTABLE_INSTANCE_FIELD(
          trusted_instance_data(kNotShared), FuncRefs,
          MemoryRepresentation::TaggedPointer());

      size_t return_count = sig->return_count();
      base::Vector<InliningTree*> feedback_cases =
          inlining_decisions_->function_calls()[feedback_slot_];
      std::vector<base::SmallVector<OpIndex, 2>> case_returns(return_count);
      // The slow path is the non-inlined generic `call_ref`,
      // or a deopt node if that is enabled.
      constexpr int kSlowpathCase = 1;
      base::SmallVector<TSBlock*, wasm::kMaxPolymorphism + kSlowpathCase>
          case_blocks;
      for (size_t i = 0; i < feedback_cases.size() + kSlowpathCase; i++) {
        case_blocks.push_back(__ NewBlock());
      }
      TSBlock* merge = __ NewBlock();
      __ Goto(case_blocks[0]);

      bool use_deopt_slowpath = deopts_enabled_;
      for (size_t i = 0; i < feedback_cases.size(); i++) {
        __ Bind(case_blocks[i]);
        InliningTree* tree = feedback_cases[i];
        if (!tree || !tree->is_inlined()) {
          // Fall through to the next case.
          __ Goto(case_blocks[i + 1]);
          // Do not use the deopt slowpath if we decided to not inline (at
          // least) one call target. Otherwise, this could lead to a deopt loop.
          use_deopt_slowpath = false;
          continue;
        }
        uint32_t inlined_index = tree->function_index();
        DCHECK(!decoder->module_->function_is_shared(inlined_index));
        V<Object> inlined_func_ref =
            __ LoadFixedArrayElement(func_refs, inlined_index);

        bool is_last_feedback_case = (i == feedback_cases.size() - 1);
        if (use_deopt_slowpath && is_last_feedback_case) {
          if (inlining_decisions_
                  ->has_non_inlineable_targets()[feedback_slot_]) {
            if (v8_flags.trace_wasm_inlining) {
              PrintF(
                  "[function %d%s: Not emitting deopt slow-path for "
                  "call_ref #%d as feedback contains non-inlineable "
                  "targets]\n",
                  func_index_, mode_ == kRegular ? "" : " (inlined)",
                  feedback_slot_);
            }
            use_deopt_slowpath = false;
          }
        }
        bool emit_deopt = use_deopt_slowpath && is_last_feedback_case;
        if (emit_deopt) {
          V<FrameState> frame_state =
              CreateFrameState(decoder, sig, &func_ref, args);
          if (frame_state.valid()) {
            DeoptIfNot(decoder, __ TaggedEqual(func_ref.op, inlined_func_ref),
                       frame_state);
          } else {
            emit_deopt = false;
            use_deopt_slowpath = false;
          }
        }
        if (!emit_deopt) {
          TSBlock* inline_block = __ NewBlock();
          BranchHint hint =
              is_last_feedback_case ? BranchHint::kTrue : BranchHint::kNone;
          __ Branch({__ TaggedEqual(func_ref.op, inlined_func_ref), hint},
                    inline_block, case_blocks[i + 1]);
          __ Bind(inline_block);
        }

        SmallZoneVector<Value, 4> direct_returns(return_count, decoder->zone_);
        if (v8_flags.trace_wasm_inlining) {
          PrintF(
              "[function %d%s: Speculatively inlining call_ref #%d, case #%zu, "
              "to function %d]\n",
              func_index_, mode_ == kRegular ? "" : " (inlined)",
              feedback_slot_, i, inlined_index);
        }
        InlineWasmCall(decoder, inlined_index, sig, static_cast<uint32_t>(i),
                       false, args, direct_returns.data());

        if (__ current_block() != nullptr) {
          // Only add phi inputs and a Goto to {merge} if the current_block is
          // not nullptr. If the current_block is nullptr, it means that the
          // inlined body unconditionally exits early (likely an unconditional
          // trap or throw).
          for (size_t ret = 0; ret < direct_returns.size(); ret++) {
            case_returns[ret].push_back(direct_returns[ret].op);
          }
          __ Goto(merge);
        }
      }

      if (!use_deopt_slowpath) {
        TSBlock* no_inline_block = case_blocks.back();
        __ Bind(no_inline_block);
        auto [target, implicit_arg] =
            BuildFunctionReferenceTargetAndImplicitArg(
                func_ref.op, func_ref.type, signature_hash);
        SmallZoneVector<Value, 4> ref_returns(return_count, decoder->zone_);
        BuildWasmCall(decoder, sig, target, implicit_arg, args,
                      ref_returns.data());
        for (size_t ret = 0; ret < ref_returns.size(); ret++) {
          case_returns[ret].push_back(ref_returns[ret].op);
        }
        __ Goto(merge);
      }

      __ Bind(merge);
      for (size_t i = 0; i < case_returns.size(); i++) {
        returns[i].op = __ Phi(base::VectorOf(case_returns[i]),
                               RepresentationFor(sig->GetReturn(i)));
      }
    } else {
      auto [target, implicit_arg] = BuildFunctionReferenceTargetAndImplicitArg(
          func_ref.op, func_ref.type, signature_hash);
      BuildWasmCall(decoder, sig, target, implicit_arg, args, returns);
    }
  }

  void ReturnCallRef(FullDecoder* decoder, const Value& func_ref,
                     const FunctionSig* sig, const Value args[]) {
    feedback_slot_++;

#if V8_ENABLE_SANDBOX
    uint64_t signature_hash = SignatureHasher::Hash(sig);
#else
    uint64_t signature_hash = 0;
#endif  // V8_ENABLE_SANDBOX

    if (should_inline(decoder, feedback_slot_,
                      std::numeric_limits<int>::max())) {
      DCHECK(!shared_);
      constexpr bool kNotShared = false;
      V<FixedArray> func_refs = LOAD_IMMUTABLE_INSTANCE_FIELD(
          trusted_instance_data(kNotShared), FuncRefs,
          MemoryRepresentation::TaggedPointer());

      base::Vector<InliningTree*> feedback_cases =
          inlining_decisions_->function_calls()[feedback_slot_];
      constexpr int kSlowpathCase = 1;
      base::SmallVector<TSBlock*, wasm::kMaxPolymorphism + kSlowpathCase>
          case_blocks;

      for (size_t i = 0; i < feedback_cases.size() + kSlowpathCase; i++) {
        case_blocks.push_back(__ NewBlock());
      }
      __ Goto(case_blocks[0]);

      for (size_t i = 0; i < feedback_cases.size(); i++) {
        __ Bind(case_blocks[i]);
        InliningTree* tree = feedback_cases[i];
        if (!tree || !tree->is_inlined()) {
          // Fall through to the next case.
          __ Goto(case_blocks[i + 1]);
          continue;
        }
        uint32_t inlined_index = tree->function_index();
        DCHECK(!decoder->module_->function_is_shared(inlined_index));
        V<Object> inlined_func_ref =
            __ LoadFixedArrayElement(func_refs, inlined_index);

        TSBlock* inline_block = __ NewBlock();
        bool is_last_case = (i == feedback_cases.size() - 1);
        BranchHint hint = is_last_case ? BranchHint::kTrue : BranchHint::kNone;
        __ Branch({__ TaggedEqual(func_ref.op, inlined_func_ref), hint},
                  inline_block, case_blocks[i + 1]);
        __ Bind(inline_block);
        if (v8_flags.trace_wasm_inlining) {
          PrintF(
              "[function %d%s: Speculatively inlining return_call_ref #%d, "
              "case #%zu, to function %d]\n",
              func_index_, mode_ == kRegular ? "" : " (inlined)",
              feedback_slot_, i, inlined_index);
        }
        InlineWasmCall(decoder, inlined_index, sig, static_cast<uint32_t>(i),
                       true, args, nullptr);

        // An inlined tail call should still terminate execution.
        DCHECK_NULL(__ current_block());
      }

      TSBlock* no_inline_block = case_blocks.back();
      __ Bind(no_inline_block);
    }
    auto [target, implicit_arg] = BuildFunctionReferenceTargetAndImplicitArg(
        func_ref.op, func_ref.type, signature_hash);
    BuildWasmMaybeReturnCall(decoder, sig, target, implicit_arg, args);
  }

  void BrOnNull(FullDecoder* decoder, const Value& ref_object, uint32_t depth,
                bool pass_null_along_branch, Value* result_on_fallthrough) {
    result_on_fallthrough->op = ref_object.op;
    IF (UNLIKELY(__ IsNull(ref_object.op, ref_object.type))) {
      int drop_values = pass_null_along_branch ? 0 : 1;
      BrOrRet(decoder, depth, drop_values);
    }
  }

  void BrOnNonNull(FullDecoder* decoder, const Value& ref_object, Value* result,
                   uint32_t depth, bool /* drop_null_on_fallthrough */) {
    result->op = ref_object.op;
    IF_NOT (UNLIKELY(__ IsNull(ref_object.op, ref_object.type))) {
      BrOrRet(decoder, depth);
    }
  }

  void SimdOp(FullDecoder* decoder, WasmOpcode opcode, const Value* args,
              Value* result) {
    switch (opcode) {
#define HANDLE_BINARY_OPCODE(kind)                                            \
  case kExpr##kind:                                                           \
    result->op =                                                              \
        __ Simd128Binop(V<compiler::turboshaft::Simd128>::Cast(args[0].op
```