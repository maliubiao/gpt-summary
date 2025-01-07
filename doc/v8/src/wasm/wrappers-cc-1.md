Response:
The user wants a summary of the functionalities present in the provided C++ code snippet from `v8/src/wasm/wrappers.cc`.

Here's a breakdown of the code's functionalities:

1. **Handling Function Returns:** The `BuildReturn` function deals with returning values from WebAssembly functions, including handling cases with zero or multiple return values.

2. **Smi Conversion:** Several functions (`BuildSmiShiftBitsConstant`, `BuildSmiShiftBitsConstant32`, `BuildChangeSmiToInt32`) are involved in converting Smi (Small Integer) values to other integer representations.

3. **Heap Number Conversion:**  The `HeapNumberToFloat64` function extracts the floating-point value from a HeapNumber object.

4. **Fast Type Conversion from JavaScript:** The `FromJSFast` function attempts to perform fast conversions from JavaScript values to WebAssembly types. It handles integers and floating-point numbers efficiently, but throws an error for unsupported types.

5. **String Type Checking:** The `BuildCheckString` function ensures that a given input is a string, throwing a JavaScript TypeError if it's not.

6. **General Type Conversion from JavaScript:** The `FromJS` function handles the conversion of JavaScript values to WebAssembly types. It includes logic for different types like numbers, references, and BigInts, and calls runtime functions for more complex conversions.

7. **Tagged Value Conversion:** `BuildChangeTaggedToFloat64` and `BuildChangeTaggedToInt32` handle the conversion of tagged JavaScript values (which can be Smis or HeapObjects) to their respective WebAssembly types.

8. **BigInt Conversion:**  `BuildChangeBigIntToInt64` converts JavaScript BigInts to WebAssembly i64 values.

9. **Fast Transformation Qualification:** `QualifiesForFastTransform` checks if a function's signature allows for optimized (fast) conversions between JavaScript and WebAssembly.

10. **Map Handling:**  The code includes functions for loading and potentially unpacking the `Map` of a JavaScript object, which is crucial for type checking.

11. **Fast Type Check:** The `CanTransformFast` function checks if a JavaScript value can be quickly converted to a specific WebAssembly type.

12. **Argument Handling:** `AddArgumentNodes` converts WebAssembly parameters to JavaScript values before calling a JavaScript function.

13. **Function Information Loading:** `LoadSharedFunctionInfo` retrieves information about a JavaScript function.

14. **Receiver Determination:** `BuildReceiverNode` determines the `this` value for a function call, taking into account whether the function is strict or not.

15. **Context Management:** `LoadContextFromJSFunction` retrieves the context of a JavaScript function.

16. **Central Stack Switching:** Functions like `BuildSwitchToTheCentralStack`, `BuildSwitchToTheCentralStackIfNeeded`, and `BuildSwitchBackFromCentralStack` manage the switching of the stack pointer between the main thread and a central stack, often used in WebAssembly execution.

17. **Suspension Handling:** The `BuildSuspend` function deals with the suspension of WebAssembly execution when interacting with JavaScript Promises.

18. **Multi-Return Value Handling:** `BuildMultiReturnFixedArrayFromIterable` converts an iterable of return values into a FixedArray.

19. **Memory Access:** `SafeStore` and `SafeLoad` provide safe mechanisms for storing and loading data from memory, handling alignment and compressed pointers.

20. **Call Target Loading:** `BuildLoadCallTargetFromExportedFunctionData` retrieves the actual function pointer from exported WebAssembly functions.

21. **Wrapper Building:** The `BuildWasmWrapper` function orchestrates the creation of different types of wrappers (JS-to-Wasm, Wasm-to-JS, Wasm-to-CAPI) based on the provided information.

Based on these functionalities, the code appears to be responsible for generating code that bridges the gap between JavaScript and WebAssembly, handling data conversion, function calls, and stack management.

Considering the second part instruction, the primary function of this snippet is to **implement various utility functions and logic used in building wrappers that facilitate communication between JavaScript and WebAssembly code.** It focuses on tasks like type conversion, function call setup, and managing execution state transitions.
这是 v8 源代码文件 `v8/src/wasm/wrappers.cc` 的一部分，它主要负责构建 WebAssembly 和 JavaScript 之间互操作的桥梁代码，即所谓的 "wrappers"。  这些 wrappers 允许 JavaScript 调用 WebAssembly 函数，反之亦然。

以下是代码片段中列举的功能：

**1. WebAssembly 函数返回值处理:**

*   **`BuildReturn(base::Vector<OpIndex> values, int offset)`:** 此函数负责生成 WebAssembly 函数的返回代码。它会根据函数签名 (`sig_`) 处理不同数量的返回值。
    *   如果函数没有返回值 (`return_count == 0`)，则返回一个常数 0。
    *   如果函数有返回值，它会从 `values` 中加载每个返回值，并使用 `Return` 指令返回。

**2. Smi（小整数）相关操作:**

*   **`BuildSmiShiftBitsConstant()` 和 `BuildSmiShiftBitsConstant32()`:** 这两个函数生成表示 Smi 移位位数的常量。Smi 是 V8 中用于高效表示小整数的一种方式。
*   **`BuildChangeSmiToInt32(OpIndex value)`:** 此函数将一个 Smi 值转换为一个 32 位整数。它考虑了指针压缩的情况。

**3. HeapNumber（堆数字）到 Float64 的转换:**

*   **`HeapNumberToFloat64(V<HeapNumber> input)`:** 此函数从一个 `HeapNumber` 对象中加载并返回其 `Float64` 值。`HeapNumber` 是 V8 中用于表示非 Smi 数字的方式。

**4. 从 JavaScript 快速转换为 WebAssembly 类型:**

*   **`FromJSFast(OpIndex input, CanonicalValueType type)`:** 此函数尝试将一个 JavaScript 值快速转换为指定的 WebAssembly 类型。
    *   对于 `kI32` 类型，它直接将 Smi 转换为 Int32。
    *   对于 `kF32` 和 `kF64` 类型，如果输入是 Smi，则转换为相应的浮点数，否则假定输入是 `HeapNumber` 并进行转换。
    *   对于其他类型，会触发 `UNREACHABLE()`，表明此快速路径不支持这些类型。

**5. 加载实例类型:**

*   **`LoadInstanceType(V<Map> map)`:** 此函数从对象的 `Map` 中加载实例类型。`Map` 是 V8 中用于描述对象结构的关键信息。

**6. 字符串类型检查:**

*   **`BuildCheckString(OpIndex input, OpIndex js_context, CanonicalValueType type)`:** 此函数检查一个 JavaScript 输入是否为字符串。
    *   如果输入是 Smi，则抛出一个 JavaScript `TypeError`。
    *   如果类型是可空的，则允许 `null` 值。
    *   否则，它会加载输入的 `Map` 并检查其 `instance_type` 是否小于 `FIRST_NONSTRING_TYPE`。如果不是字符串，则抛出 `TypeError`。

**7. 将 Tagged 值转换为 Float64:**

*   **`BuildChangeTaggedToFloat64(OpIndex value, OpIndex context, compiler::turboshaft::OptionalOpIndex frame_state)`:**  此函数将一个可能是 Smi 或 HeapObject 的 JavaScript 值转换为 `Float64`。它会调用内置函数 `kWasmTaggedToFloat64` 来处理非 Smi 的情况。

**8. 将 Tagged 值转换为 Int32:**

*   **`BuildChangeTaggedToInt32(OpIndex value, OpIndex context, compiler::turboshaft::OptionalOpIndex frame_state)`:** 此函数将一个可能是 Smi 或 HeapObject 的 JavaScript 值转换为 `Int32`。
    *   如果输入是 Smi，则直接转换。
    *   否则，调用内置函数 `kWasmTaggedNonSmiToInt32`。

**9. 获取 BigInt 到 I64 的调用描述符:**

*   **`GetBigIntToI64CallDescriptor(bool needs_frame_state)`:**  此函数返回用于调用 BigInt 到 I64 转换的调用描述符。

**10. 将 BigInt 转换为 Int64:**

*   **`BuildChangeBigIntToInt64(OpIndex input, OpIndex context, compiler::turboshaft::OptionalOpIndex frame_state)`:** 此函数将 JavaScript 的 BigInt 对象转换为 WebAssembly 的 i64 类型。它会调用内置函数 `kBigIntToI64` (或在 32 位平台上调用 `kBigIntToI32Pair`)。

**11. 从 JavaScript 转换为 WebAssembly 类型:**

*   **`FromJS(OpIndex input, OpIndex context, CanonicalValueType type, OptionalOpIndex frame_state)`:**  这是一个更通用的函数，用于将 JavaScript 值转换为 WebAssembly 类型。
    *   对于 `kRef` 和 `kRefNull` 类型，它会根据底层堆表示进行不同的处理，例如检查 `Extern` 类型，检查字符串类型，或者调用运行时函数 `kWasmJSToWasmObject` 进行更通用的转换。
    *   对于 `kF32` 和 `kF64`，它调用 `BuildChangeTaggedToFloat64`。
    *   对于 `kI32`，它调用 `BuildChangeTaggedToInt32`。
    *   对于 `kI64`，它调用 `BuildChangeBigIntToInt64`。
    *   对于其他类型，会触发 `UNREACHABLE()`，表示不支持直接转换。

**12. 判断是否适合快速转换:**

*   **`QualifiesForFastTransform()`:** 此函数检查函数的参数类型是否都允许进行快速的 JavaScript 到 WebAssembly 的转换。如果参数包含引用、i64 或其他复杂类型，则不适合快速转换。

**13. Map 解包 (可选):**

*   **`UnpackMapWord(OpIndex map_word)`:**  在定义了 `V8_MAP_PACKING` 的情况下，此函数用于解包压缩的 `Map` 对象。

**14. 加载 Map:**

*   **`LoadMap(V<Object> object)`:** 此函数加载 JavaScript 对象的 `Map`。它会根据是否启用 Map 压缩来选择是否调用 `UnpackMapWord`。

**15. 快速转换检查:**

*   **`CanTransformFast(OpIndex input, CanonicalValueType type, TSBlock* slow_path)`:** 此函数检查一个 JavaScript 输入是否可以快速转换为指定的 WebAssembly 类型，如果不能则跳转到慢速路径 (`slow_path`)。
    *   对于 `kI32`，它检查是否为 Smi。
    *   对于 `kF32` 和 `kF64`，它检查是否为 Smi 或 HeapNumber。

**16. 添加参数节点:**

*   **`AddArgumentNodes(base::Vector<OpIndex> args, int pos, base::SmallVector<OpIndex, 16> wasm_params, const CanonicalSig* sig, V<Context> context)`:**  此函数将 WebAssembly 函数的参数转换为 JavaScript 值，以便传递给 JavaScript 函数。

**17. 加载 SharedFunctionInfo:**

*   **`LoadSharedFunctionInfo(V<Object> js_function)`:**  此函数从 JavaScript 函数对象中加载 `SharedFunctionInfo`。`SharedFunctionInfo` 包含关于函数的元数据。

**18. 构建接收者节点:**

*   **`BuildReceiverNode(OpIndex callable_node, OpIndex native_context, V<Undefined> undefined_node)`:** 此函数为函数调用构建接收者（`this`）对象。它会检查函数的 strict 模式标志，并根据情况选择使用全局接收者或 `undefined`。

**19. 从 JSFunction 加载 Context:**

*   **`LoadContextFromJSFunction(V<JSFunction> js_function)`:** 此函数从 JavaScript 函数对象中加载其关联的上下文。

**20. 切换到中心堆栈:**

*   **`BuildSwitchToTheCentralStack()`:** 此函数生成代码以切换到 V8 的中心堆栈。
*   **`BuildSwitchToTheCentralStackIfNeeded()`:**  此函数检查当前是否在中心堆栈上，如果不在则切换。
*   **`BuildSwitchBackFromCentralStack(OpIndex old_sp)`:** 此函数生成代码以从中心堆栈切换回来。

**21. 处理挂起 (Suspend):**

*   **`BuildSuspend(OpIndex value, V<Object> import_data, OpIndex* old_sp)`:** 此函数处理当 WebAssembly 函数返回一个 Promise 时的情况。它会挂起当前的执行，并在 Promise resolve 后恢复。

**22. 从可迭代对象构建多返回值 FixedArray:**

*   **`BuildMultiReturnFixedArrayFromIterable(OpIndex iterable, V<Context> context)`:**  此函数将一个可迭代对象（通常包含多个返回值）转换为一个 `FixedArray`。

**23. 安全存储:**

*   **`SafeStore(int offset, CanonicalValueType type, OpIndex base, OpIndex value)`:**  此函数提供了一种安全的内存存储操作，它会考虑对齐和指针压缩。

**24. 加载导出函数数据的调用目标:**

*   **`BuildLoadCallTargetFromExportedFunctionData(V<WasmFunctionData> function_data)`:** 此函数从导出的 WebAssembly 函数数据中加载实际的调用目标地址。

**25. 安全加载:**

*   **`SafeLoad(OpIndex base, int offset, CanonicalValueType type)`:**  此函数提供了一种安全的内存加载操作，它会考虑对齐和指针压缩。

**26. 构建 Wasm 包装器:**

*   **`BuildWasmWrapper(compiler::turboshaft::PipelineData* data, AccountingAllocator* allocator, compiler::turboshaft::Graph& graph, const CanonicalSig* sig, WrapperCompilationInfo wrapper_info)`:**  这是主要的入口点，用于根据不同的 `wrapper_info` 构建不同类型的 Wasm 包装器（例如，JS 到 Wasm，Wasm 到 JS，Wasm 到 C API）。

**如果 `v8/src/wasm/wrappers.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**  但根据你提供的代码内容，它更像是 C++ 代码，使用了 Turboshaft 图构建 API。Torque 是一种 V8 特有的领域特定语言，用于生成高效的 JavaScript 运行时代码。

**与 JavaScript 功能的关系和示例:**

这段代码的核心功能是连接 JavaScript 和 WebAssembly。以下是一些与 JavaScript 功能相关的示例：

*   **JavaScript 调用 WebAssembly 函数：**  当你在 JavaScript 中调用一个 WebAssembly 导出的函数时，`BuildJSToWasmWrapper`  负责创建将 JavaScript 参数转换为 WebAssembly 格式，调用 WebAssembly 函数，并将 WebAssembly 返回值转换回 JavaScript 的代码。
    ```javascript
    // 假设有一个导出的 WebAssembly 函数 add(a: i32, b: i32) => i32
    const instance = await WebAssembly.instantiateStreaming(fetch('module.wasm'));
    const result = instance.exports.add(5, 10); // JavaScript 调用 WebAssembly
    console.log(result); // 输出 15
    ```

*   **WebAssembly 调用 JavaScript 函数：** 当 WebAssembly 代码需要调用导入的 JavaScript 函数时，`BuildWasmToJSWrapper`  负责创建将 WebAssembly 参数转换为 JavaScript 格式，调用 JavaScript 函数，并将 JavaScript 返回值转换回 WebAssembly 格式的代码。
    ```javascript
    // JavaScript 定义一个供 WebAssembly 调用的函数
    function logMessage(message) {
      console.log("WebAssembly says:", message);
    }

    // 假设 WebAssembly 模块导入了 logMessage
    const importObject = {
      env: {
        logMessage: logMessage
      }
    };
    const instance = await WebAssembly.instantiateStreaming(fetch('module.wasm'), importObject);
    // ... 在 WebAssembly 代码中调用 logMessage ...
    ```

*   **处理 Promise (挂起):** 当 WebAssembly 调用返回一个 JavaScript Promise 时，`BuildSuspend`  中的逻辑会暂停 WebAssembly 的执行，等待 Promise resolve，然后再恢复执行。
    ```javascript
    async function asyncOperation() {
      return new Promise(resolve => setTimeout(() => resolve(42), 100));
    }

    // 假设 WebAssembly 导入了 asyncOperation 并调用它
    const importObject = {
      env: {
        asyncOperation: asyncOperation
      }
    };
    const instance = await WebAssembly.instantiateStreaming(fetch('module.wasm'), importObject);
    // ... WebAssembly 代码调用 asyncOperation ...
    ```

**代码逻辑推理示例 (假设输入与输出):**

假设有一个 WebAssembly 函数 `add(a: i32, b: i32) => i32`。当 JavaScript 调用 `instance.exports.add(5, 10)` 时，`BuildJSToWasmWrapper` 生成的代码会执行以下类似的操作：

**假设输入:**

*   JavaScript 调用 `instance.exports.add(5, 10)`
*   `wasm_params` (WebAssembly 参数):  `[5, 10]` (作为 OpIndex)
*   `sig_`:  表示 `(i32, i32) => i32` 的函数签名
*   `context`: 当前的 JavaScript 执行上下文

**输出 (简化的逻辑流程):**

1. `AddArgumentNodes` 将 JavaScript 参数 5 和 10 (可能是 Smi) 转换为 WebAssembly 的 i32 格式 (如果需要，会调用类似 `BuildChangeSmiToInt32` 的函数)。
2. 生成调用 WebAssembly 函数 `add` 的代码，并将转换后的参数传递给它。
3. WebAssembly 函数 `add` 执行，返回结果 15。
4. `BuildReturn` 被调用，将 WebAssembly 的 i32 结果 15 转换为 JavaScript 的 Number 类型 (可能是 Smi)。
5. JavaScript 得到返回值 15。

**用户常见的编程错误举例:**

*   **类型不匹配:**  如果在 JavaScript 中传递了错误类型的参数给 WebAssembly 函数，例如，传递了一个字符串给一个期望整数的参数，那么 `FromJS` 或 `FromJSFast` 中的类型检查可能会失败，导致抛出异常或类型错误。
    ```javascript
    // 假设 add 函数期望两个整数
    instance.exports.add("hello", 10); // 可能会导致类型错误
    ```

*   **WebAssembly 返回值类型与 JavaScript 期望的不符:** 如果 WebAssembly 函数返回的类型与 JavaScript 代码期望的类型不兼容，可能会导致意外的结果或错误。

*   **异步操作处理不当:** 如果 WebAssembly 调用了一个返回 Promise 的 JavaScript 函数，但 JavaScript 代码没有正确地处理这个 Promise，可能会导致程序挂起或出现未处理的 rejection。

**归纳一下它的功能 (第 2 部分):**

这段代码是 `v8/src/wasm/wrappers.cc` 的一部分，专注于实现构建 WebAssembly 和 JavaScript 之间互操作桥梁（wrappers）所需的各种底层操作和逻辑。它提供了用于类型转换、函数调用管理、堆栈切换、Promise 处理以及安全内存访问等关键功能。这些功能共同使得 JavaScript 代码能够无缝地调用 WebAssembly 代码，反之亦然，从而实现混合编程。这段代码是 V8 引擎中 WebAssembly 支持的关键组成部分。

Prompt: 
```
这是目录为v8/src/wasm/wrappers.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wrappers.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
eturn_count(), kV8MaxWasmFunctionReturns);
    size_t return_count = sig_->return_count();
    if (return_count == 0) {
      __ Return(__ Word32Constant(0));
    } else {
      base::SmallVector<OpIndex, 8> returns(return_count);
      offset = 0;
      for (size_t i = 0; i < return_count; ++i) {
        CanonicalValueType type = sig_->GetReturn(i);
        OpIndex val = SafeLoad(values, offset, type);
        returns[i] = val;
        offset += type.value_kind_size();
      }
      __ Return(__ Word32Constant(0), base::VectorOf(returns));
    }
  }

  V<Word32> BuildSmiShiftBitsConstant() {
    return __ Word32Constant(kSmiShiftSize + kSmiTagSize);
  }

  V<Word32> BuildSmiShiftBitsConstant32() {
    return __ Word32Constant(kSmiShiftSize + kSmiTagSize);
  }

  V<Word32> BuildChangeSmiToInt32(OpIndex value) {
    return COMPRESS_POINTERS_BOOL
               ? __ Word32ShiftRightArithmetic(value,
                                               BuildSmiShiftBitsConstant32())
               : __
                 TruncateWordPtrToWord32(__ WordPtrShiftRightArithmetic(
                     value, BuildSmiShiftBitsConstant()));
  }

  V<Float64> HeapNumberToFloat64(V<HeapNumber> input) {
    return __ template LoadField<Float64>(
        input, compiler::AccessBuilder::ForHeapNumberValue());
  }

  OpIndex FromJSFast(OpIndex input, CanonicalValueType type) {
    switch (type.kind()) {
      case kI32:
        return BuildChangeSmiToInt32(input);
      case kF32: {
        ScopedVar<Float32> result(this, OpIndex::Invalid());
        IF (__ IsSmi(input)) {
          result = __ ChangeInt32ToFloat32(__ UntagSmi(input));
        } ELSE {
          result = __ TruncateFloat64ToFloat32(HeapNumberToFloat64(input));
        }
        return result;
      }
      case kF64: {
        ScopedVar<Float64> result(this, OpIndex::Invalid());
        IF (__ IsSmi(input)) {
          result = __ ChangeInt32ToFloat64(__ UntagSmi(input));
        } ELSE{
          result = HeapNumberToFloat64(input);
        }
        return result;
      }
      case kRef:
      case kRefNull:
      case kI64:
      case kRtt:
      case kS128:
      case kI8:
      case kI16:
      case kF16:
      case kTop:
      case kBottom:
      case kVoid:
        UNREACHABLE();
    }
  }

  OpIndex LoadInstanceType(V<Map> map) {
    return __ Load(map, LoadOp::Kind::TaggedBase().Immutable(),
                   MemoryRepresentation::Uint16(), Map::kInstanceTypeOffset);
  }

  OpIndex BuildCheckString(OpIndex input, OpIndex js_context,
                           CanonicalValueType type) {
    auto done = __ NewBlock();
    auto type_error = __ NewBlock();
    ScopedVar<Object> result(this, LOAD_ROOT(WasmNull));
    __ GotoIf(__ IsSmi(input), type_error, BranchHint::kFalse);
    if (type.is_nullable()) {
      auto not_null = __ NewBlock();
      __ GotoIfNot(__ TaggedEqual(input, LOAD_ROOT(NullValue)), not_null);
      __ Goto(done);
      __ Bind(not_null);
    }
    V<Map> map = LoadMap(input);
    OpIndex instance_type = LoadInstanceType(map);
    OpIndex check = __ Uint32LessThan(instance_type,
                                      __ Word32Constant(FIRST_NONSTRING_TYPE));
    result = input;
    __ GotoIf(check, done, BranchHint::kTrue);
    __ Goto(type_error);
    __ Bind(type_error);
    CallRuntime(__ phase_zone(), Runtime::kWasmThrowJSTypeError, {},
                js_context);
    __ Unreachable();
    __ Bind(done);
    return result;
  }

  V<Float64> BuildChangeTaggedToFloat64(
      OpIndex value, OpIndex context,
      compiler::turboshaft::OptionalOpIndex frame_state) {
    OpIndex call = frame_state.valid()
                       ? CallBuiltin<WasmTaggedToFloat64Descriptor>(
                             Builtin::kWasmTaggedToFloat64, frame_state.value(),
                             Operator::kNoProperties, value, context)
                       : CallBuiltin<WasmTaggedToFloat64Descriptor>(
                             Builtin::kWasmTaggedToFloat64,
                             Operator::kNoProperties, value, context);
    // The source position here is needed for asm.js, see the comment on the
    // source position of the call to JavaScript in the wasm-to-js wrapper.
    __ output_graph().source_positions()[call] = SourcePosition(1);
    return call;
  }

  OpIndex BuildChangeTaggedToInt32(
      OpIndex value, OpIndex context,
      compiler::turboshaft::OptionalOpIndex frame_state) {
    // We expect most integers at runtime to be Smis, so it is important for
    // wrapper performance that Smi conversion be inlined.
    ScopedVar<Word32> result(this, OpIndex::Invalid());
    IF (__ IsSmi(value)) {
      result = BuildChangeSmiToInt32(value);
    } ELSE{
      OpIndex call =
          frame_state.valid()
              ? CallBuiltin<WasmTaggedNonSmiToInt32Descriptor>(
                    Builtin::kWasmTaggedNonSmiToInt32, frame_state.value(),
                    Operator::kNoProperties, value, context)
              : CallBuiltin<WasmTaggedNonSmiToInt32Descriptor>(
                    Builtin::kWasmTaggedNonSmiToInt32, Operator::kNoProperties,
                    value, context);
      result = call;
      // The source position here is needed for asm.js, see the comment on the
      // source position of the call to JavaScript in the wasm-to-js wrapper.
      __ output_graph().source_positions()[call] = SourcePosition(1);
    }
    return result;
  }

  CallDescriptor* GetBigIntToI64CallDescriptor(bool needs_frame_state) {
    return GetWasmEngine()->call_descriptors()->GetBigIntToI64Descriptor(
        needs_frame_state);
  }

  OpIndex BuildChangeBigIntToInt64(
      OpIndex input, OpIndex context,
      compiler::turboshaft::OptionalOpIndex frame_state) {
    OpIndex target;
    if (Is64()) {
      target = GetTargetForBuiltinCall(Builtin::kBigIntToI64);
    } else {
      // On 32-bit platforms we already set the target to the
      // BigIntToI32Pair builtin here, so that we don't have to replace the
      // target in the int64-lowering.
      target = GetTargetForBuiltinCall(Builtin::kBigIntToI32Pair);
    }

    CallDescriptor* call_descriptor =
        GetBigIntToI64CallDescriptor(frame_state.valid());
    const TSCallDescriptor* ts_call_descriptor = TSCallDescriptor::Create(
        call_descriptor, compiler::CanThrow::kNo,
        compiler::LazyDeoptOnThrow::kNo, __ graph_zone());
    return frame_state.valid()
               ? __ Call(target, frame_state.value(),
                         base::VectorOf({input, context}), ts_call_descriptor)
               : __ Call(target, {input, context}, ts_call_descriptor);
  }

  OpIndex FromJS(OpIndex input, OpIndex context, CanonicalValueType type,
                 OptionalOpIndex frame_state = {}) {
    switch (type.kind()) {
      case kRef:
      case kRefNull: {
        switch (type.heap_representation_non_shared()) {
          // TODO(14034): Add more fast paths?
          case HeapType::kExtern:
            if (type.kind() == kRef) {
              IF (UNLIKELY(__ TaggedEqual(input, LOAD_ROOT(NullValue)))) {
                CallRuntime(__ phase_zone(), Runtime::kWasmThrowJSTypeError, {},
                            context);
                __ Unreachable();
              }
            }
            return input;
          case HeapType::kString:
            return BuildCheckString(input, context, type);
          case HeapType::kExn:
          case HeapType::kNoExn: {
            UNREACHABLE();
          }
          case HeapType::kNoExtern:
          case HeapType::kNone:
          case HeapType::kNoFunc:
          case HeapType::kI31:
          case HeapType::kAny:
          case HeapType::kFunc:
          case HeapType::kStruct:
          case HeapType::kArray:
          case HeapType::kEq:
          default: {
            // Make sure ValueType fits in a Smi.
            static_assert(ValueType::kLastUsedBit + 1 <= kSmiValueSize);

            std::initializer_list<const OpIndex> inputs = {
                input, __ IntPtrConstant(
                           IntToSmi(static_cast<int>(type.raw_bit_field())))};
            return CallRuntime(__ phase_zone(), Runtime::kWasmJSToWasmObject,
                               inputs, context);
          }
        }
      }
      case kF32:
        return __ TruncateFloat64ToFloat32(
            BuildChangeTaggedToFloat64(input, context, frame_state));

      case kF64:
        return BuildChangeTaggedToFloat64(input, context, frame_state);

      case kI32:
        return BuildChangeTaggedToInt32(input, context, frame_state);

      case kI64:
        // i64 values can only come from BigInt.
        return BuildChangeBigIntToInt64(input, context, frame_state);

      case kRtt:
      case kS128:
      case kI8:
      case kI16:
      case kF16:
      case kTop:
      case kBottom:
      case kVoid:
        // If this is reached, then IsJSCompatibleSignature() is too permissive.
        UNREACHABLE();
    }
  }

  bool QualifiesForFastTransform() {
    const int wasm_count = static_cast<int>(sig_->parameter_count());
    for (int i = 0; i < wasm_count; ++i) {
      CanonicalValueType type = sig_->GetParam(i);
      switch (type.kind()) {
        case kRef:
        case kRefNull:
        case kI64:
        case kRtt:
        case kS128:
        case kI8:
        case kI16:
        case kF16:
        case kTop:
        case kBottom:
        case kVoid:
          return false;
        case kI32:
        case kF32:
        case kF64:
          break;
      }
    }
    return true;
  }

#ifdef V8_MAP_PACKING
  V<Map> UnpackMapWord(OpIndex map_word) {
    map_word = __ BitcastTaggedToWordPtrForTagAndSmiBits(map_word);
    // TODO(wenyuzhao): Clear header metadata.
    OpIndex map = __ WordBitwiseXor(
        map_word, __ IntPtrConstant(Internals::kMapWordXorMask),
        WordRepresentation::UintPtr());
    return V<Map>::Cast(__ BitcastWordPtrToTagged(map));
  }
#endif

  V<Map> LoadMap(V<Object> object) {
    // TODO(thibaudm): Handle map packing.
    OpIndex map_word = __ Load(object, LoadOp::Kind::TaggedBase(),
                               MemoryRepresentation::TaggedPointer(), 0);
#ifdef V8_MAP_PACKING
    return UnpackMapWord(map_word);
#else
    return map_word;
#endif
  }

  void CanTransformFast(OpIndex input, CanonicalValueType type,
                        TSBlock* slow_path) {
    switch (type.kind()) {
      case kI32: {
        __ GotoIfNot(LIKELY(__ IsSmi(input)), slow_path);
        return;
      }
      case kF32:
      case kF64: {
        TSBlock* done = __ NewBlock();
        __ GotoIf(__ IsSmi(input), done);
        V<Map> map = LoadMap(input);
        V<Map> heap_number_map = LOAD_ROOT(HeapNumberMap);
        // TODO(thibaudm): Handle map packing.
        V<Word32> is_heap_number = __ TaggedEqual(heap_number_map, map);
        __ GotoIf(LIKELY(is_heap_number), done);
        __ Goto(slow_path);
        __ Bind(done);
        return;
      }
      case kRef:
      case kRefNull:
      case kI64:
      case kRtt:
      case kS128:
      case kI8:
      case kI16:
      case kF16:
      case kTop:
      case kBottom:
      case kVoid:
        UNREACHABLE();
    }
  }

  // Must be called in the first block to emit the Parameter ops.
  int AddArgumentNodes(base::Vector<OpIndex> args, int pos,
                       base::SmallVector<OpIndex, 16> wasm_params,
                       const CanonicalSig* sig, V<Context> context) {
    // Convert wasm numbers to JS values.
    for (size_t i = 0; i < wasm_params.size(); ++i) {
      args[pos++] = ToJS(wasm_params[i], sig->GetParam(i), context);
    }
    return pos;
  }

  OpIndex LoadSharedFunctionInfo(V<Object> js_function) {
    return __ Load(js_function, LoadOp::Kind::TaggedBase(),
                   MemoryRepresentation::TaggedPointer(),
                   JSFunction::kSharedFunctionInfoOffset);
  }

  OpIndex BuildReceiverNode(OpIndex callable_node, OpIndex native_context,
                            V<Undefined> undefined_node) {
    // Check function strict bit.
    V<SharedFunctionInfo> shared_function_info =
        LoadSharedFunctionInfo(callable_node);
    OpIndex flags = __ Load(shared_function_info, LoadOp::Kind::TaggedBase(),
                            MemoryRepresentation::Int32(),
                            SharedFunctionInfo::kFlagsOffset);
    OpIndex strict_check = __ Word32BitwiseAnd(
        flags, __ Word32Constant(SharedFunctionInfo::IsNativeBit::kMask |
                                 SharedFunctionInfo::IsStrictBit::kMask));

    // Load global receiver if sloppy else use undefined.
    ScopedVar<Object> strict_d(this, OpIndex::Invalid());
    IF (strict_check) {
      strict_d = undefined_node;
    } ELSE {
      strict_d =
          __ LoadFixedArrayElement(native_context, Context::GLOBAL_PROXY_INDEX);
    }
    return strict_d;
  }

  V<Context> LoadContextFromJSFunction(V<JSFunction> js_function) {
    return __ Load(js_function, LoadOp::Kind::TaggedBase(),
                   MemoryRepresentation::TaggedPointer(),
                   JSFunction::kContextOffset);
  }

  OpIndex BuildSwitchToTheCentralStack() {
    MachineType reps[] = {MachineType::Pointer(), MachineType::Pointer(),
                          MachineType::Pointer()};
    MachineSignature sig(1, 2, reps);

    OpIndex central_stack_sp = CallC(
        &sig, ExternalReference::wasm_switch_to_the_central_stack_for_js(),
        {__ ExternalConstant(ExternalReference::isolate_address()),
         __ FramePointer()});
    OpIndex old_sp = __ LoadStackPointer();
    // Temporarily disallow sp-relative offsets.
    __ SetStackPointer(central_stack_sp);
    return old_sp;
  }

  OpIndex BuildSwitchToTheCentralStackIfNeeded() {
    OpIndex isolate_root = __ LoadRootRegister();
    OpIndex is_on_central_stack_flag = __ Load(
        isolate_root, LoadOp::Kind::RawAligned(), MemoryRepresentation::Uint8(),
        IsolateData::is_on_central_stack_flag_offset());
    ScopedVar<WordPtr> old_sp_var(this, __ IntPtrConstant(0));
    // The stack switch performs a C call which causes some spills that would
    // not be needed otherwise. Add a branch hint such that we don't spill if we
    // are already on the central stack.
    // TODO(thibaudm): Look into ways to optimize the switching case as well.
    // Can we avoid the C call? Can we avoid spilling callee-saved registers?
    IF_NOT (LIKELY(is_on_central_stack_flag)) {
      OpIndex old_sp = BuildSwitchToTheCentralStack();
      old_sp_var = old_sp;
    }
    return old_sp_var;
  }

  void BuildSwitchBackFromCentralStack(OpIndex old_sp) {
    MachineType reps[] = {MachineType::Pointer(), MachineType::Pointer()};
    MachineSignature sig(0, 1, reps);
    IF_NOT (LIKELY(__ WordPtrEqual(old_sp, __ IntPtrConstant(0)))) {
      CallC(&sig,
            ExternalReference::wasm_switch_from_the_central_stack_for_js(),
            {__ ExternalConstant(ExternalReference::isolate_address())});
      __ SetStackPointer(old_sp);
    }
  }

  OpIndex BuildSuspend(OpIndex value, V<Object> import_data, OpIndex* old_sp) {
    // If value is a promise, suspend to the js-to-wasm prompt, and resume later
    // with the promise's resolved value.
    ScopedVar<Object> result(this, value);
    ScopedVar<WordPtr> old_sp_var(this, *old_sp);
    IF_NOT (__ IsSmi(value)) {
      IF (__ HasInstanceType(value, JS_PROMISE_TYPE)) {
        OpIndex suspender = LOAD_ROOT(ActiveSuspender);
        V<Context> native_context =
            __ Load(import_data, LoadOp::Kind::TaggedBase(),
                    MemoryRepresentation::TaggedPointer(),
                    WasmImportData::kNativeContextOffset);
        IF (__ TaggedEqual(suspender, LOAD_ROOT(UndefinedValue))) {
          CallRuntime(__ phase_zone(), Runtime::kThrowBadSuspenderError, {},
                      native_context);
          __ Unreachable();
        }
        if (v8_flags.stress_wasm_stack_switching) {
          V<Word32> for_stress_testing = __ TaggedEqual(
              __ LoadTaggedField(suspender, WasmSuspenderObject::kResumeOffset),
              LOAD_ROOT(UndefinedValue));
          IF (for_stress_testing) {
            CallRuntime(__ phase_zone(), Runtime::kThrowBadSuspenderError, {},
                        native_context);
            __ Unreachable();
          }
        }
        // If {old_sp} is null, it must be that we were on the central stack
        // before entering the wasm-to-js wrapper, which means that there are JS
        // frames in the current suspender. JS frames cannot be suspended, so
        // trap.
        OpIndex has_js_frames = __ WordPtrEqual(__ IntPtrConstant(0), *old_sp);
        IF (has_js_frames) {
          // {ThrowWasmError} expects to be called from wasm code, so set the
          // thread-in-wasm flag now.
          // Usually we set this flag later so that it stays off while we
          // convert the return values. This is a special case, it is safe to
          // set it now because the error will unwind this frame.
          BuildModifyThreadInWasmFlag(__ phase_zone(), true);
          V<Smi> error = __ SmiConstant(Smi::FromInt(
              static_cast<int32_t>(MessageTemplate::kWasmTrapSuspendJSFrames)));
          CallRuntime(__ phase_zone(), Runtime::kThrowWasmError, {error},
                      native_context);
          __ Unreachable();
        }
        V<Object> on_fulfilled = __ Load(suspender, LoadOp::Kind::TaggedBase(),
                                         MemoryRepresentation::TaggedPointer(),
                                         WasmSuspenderObject::kResumeOffset);
        V<Object> on_rejected = __ Load(suspender, LoadOp::Kind::TaggedBase(),
                                        MemoryRepresentation::TaggedPointer(),
                                        WasmSuspenderObject::kRejectOffset);

        OpIndex promise_then =
            GetBuiltinPointerTarget(Builtin::kPerformPromiseThen);
        auto* then_call_desc = GetBuiltinCallDescriptor(
            Builtin::kPerformPromiseThen, __ graph_zone());
        base::SmallVector<OpIndex, 16> args{value, on_fulfilled, on_rejected,
                                            LOAD_ROOT(UndefinedValue),
                                            native_context};
        __ Call(promise_then, OpIndex::Invalid(), base::VectorOf(args),
                then_call_desc);

        OpIndex suspend = GetTargetForBuiltinCall(Builtin::kWasmSuspend);
        auto* suspend_call_descriptor =
            GetBuiltinCallDescriptor(Builtin::kWasmSuspend, __ graph_zone());
        BuildSwitchBackFromCentralStack(*old_sp);
        OpIndex resolved =
            __ Call(suspend, {suspender}, suspend_call_descriptor);
        old_sp_var = BuildSwitchToTheCentralStack();
        result = resolved;
      }
    }
    *old_sp = old_sp_var;
    return result;
  }

  V<FixedArray> BuildMultiReturnFixedArrayFromIterable(OpIndex iterable,
                                                       V<Context> context) {
    V<Smi> length = __ SmiConstant(Smi::FromIntptr(sig_->return_count()));
    return CallBuiltin<IterableToFixedArrayForWasmDescriptor>(
        Builtin::kIterableToFixedArrayForWasm, Operator::kEliminatable,
        iterable, length, context);
  }

  void SafeStore(int offset, CanonicalValueType type, OpIndex base,
                 OpIndex value) {
    int alignment = offset % type.value_kind_size();
    auto rep = MemoryRepresentation::FromMachineRepresentation(
        type.machine_representation());
    if (COMPRESS_POINTERS_BOOL && rep.IsCompressibleTagged()) {
      // We are storing tagged value to off-heap location, so we need to store
      // it as a full word otherwise we will not be able to decompress it.
      rep = MemoryRepresentation::UintPtr();
      value = __ BitcastTaggedToWordPtr(value);
    }
    StoreOp::Kind store_kind =
        alignment == 0 || compiler::turboshaft::SupportedOperations::
                              IsUnalignedStoreSupported(rep)
            ? StoreOp::Kind::RawAligned()
            : StoreOp::Kind::RawUnaligned();
    __ Store(base, value, store_kind, rep, compiler::kNoWriteBarrier, offset);
  }

  V<WordPtr> BuildLoadCallTargetFromExportedFunctionData(
      V<WasmFunctionData> function_data) {
    V<WasmInternalFunction> internal =
        V<WasmInternalFunction>::Cast(__ LoadProtectedPointerField(
            function_data, LoadOp::Kind::TaggedBase().Immutable(),
            WasmFunctionData::kProtectedInternalOffset));
    return __ Load(internal, LoadOp::Kind::TaggedBase(),
                   MemoryRepresentation::UintPtr(),
                   WasmInternalFunction::kCallTargetOffset);
  }

  const OpIndex SafeLoad(OpIndex base, int offset, CanonicalValueType type) {
    int alignment = offset % type.value_kind_size();
    auto rep = MemoryRepresentation::FromMachineRepresentation(
        type.machine_representation());
    if (COMPRESS_POINTERS_BOOL && rep.IsCompressibleTagged()) {
      // We are loading tagged value from off-heap location, so we need to load
      // it as a full word otherwise we will not be able to decompress it.
      rep = MemoryRepresentation::UintPtr();
    }
    LoadOp::Kind load_kind = alignment == 0 ||
                                     compiler::turboshaft::SupportedOperations::
                                         IsUnalignedLoadSupported(rep)
                                 ? LoadOp::Kind::RawAligned()
                                 : LoadOp::Kind::RawUnaligned();
    return __ Load(base, load_kind, rep, offset);
  }

 private:
  const CanonicalSig* const sig_;
};

void BuildWasmWrapper(compiler::turboshaft::PipelineData* data,
                      AccountingAllocator* allocator,
                      compiler::turboshaft::Graph& graph,
                      const CanonicalSig* sig,
                      WrapperCompilationInfo wrapper_info) {
  Zone zone(allocator, ZONE_NAME);
  WasmGraphBuilderBase::Assembler assembler(data, graph, graph, &zone);
  WasmWrapperTSGraphBuilder builder(&zone, assembler, sig);
  if (wrapper_info.code_kind == CodeKind::JS_TO_WASM_FUNCTION) {
    builder.BuildJSToWasmWrapper();
  } else if (wrapper_info.code_kind == CodeKind::WASM_TO_JS_FUNCTION) {
    builder.BuildWasmToJSWrapper(wrapper_info.import_kind,
                                 wrapper_info.expected_arity,
                                 wrapper_info.suspend);
  } else if (wrapper_info.code_kind == CodeKind::WASM_TO_CAPI_FUNCTION) {
    builder.BuildCapiCallWrapper();
  } else {
    // TODO(thibaudm): Port remaining wrappers.
    UNREACHABLE();
  }
}

}  // namespace v8::internal::wasm

"""


```