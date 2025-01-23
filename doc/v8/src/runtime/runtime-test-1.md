Response: The user wants a summary of the C++ code provided. This is the second part of the file `v8/src/runtime/runtime-test.cc`. I need to explain the functionality of the C++ code snippets and relate them to JavaScript concepts if applicable, providing JavaScript examples.

Let's break down each `RUNTIME_FUNCTION`:

- `Runtime_ObjectVerify`: Checks the validity of a V8 object. This is an internal V8 function, not directly exposed to JavaScript.
- `Runtime_ArrayBufferMaxByteLength`: Returns the maximum allowed byte length for an `ArrayBuffer`. This is related to JavaScript's `ArrayBuffer`.
- `Runtime_CompleteInobjectSlackTracking`:  Likely related to optimizing object layout, not directly exposed.
- `Runtime_TurbofanStaticAssert`, `Runtime_IsBeingInterpreted`: These seem to be related to V8's internal compilation pipeline (Turbofan) and are not directly exposed.
- `Runtime_EnableCodeLoggingForTesting`:  Enables code logging for testing purposes. This is related to V8's internal logging and not directly accessible in JavaScript.
- `Runtime_NewRegExpWithBacktrackLimit`: Creates a regular expression with a specified backtrack limit. This relates to JavaScript's `RegExp`.
- `Runtime_Is64Bit`: Checks if the underlying system is 64-bit. This is related to the environment but not directly a JavaScript feature.
- `Runtime_BigIntMaxLengthBits`: Returns the maximum length in bits for a `BigInt`. This relates to JavaScript's `BigInt`.
- `Runtime_IsSameHeapObject`: Checks if two objects reside at the same memory location. This is a low-level V8 concept.
- `Runtime_IsSharedString`: Checks if a string is a shared string. This is an internal V8 string optimization.
- `Runtime_ShareObject`:  Attempts to share an object, likely for memory efficiency. This is a V8 internal.
- `Runtime_IsInPlaceInternalizableString`, `Runtime_IsInternalizedString`: These are related to V8's string interning mechanism.
- `Runtime_StringToCString`, `Runtime_StringUtf8Value`:  Converts a V8 string to a C-style string or UTF-8 encoded bytes. While not direct JavaScript, it relates to how JavaScript strings are handled internally.
- `Runtime_SharedGC`:  Triggers a garbage collection in shared space, a V8 internal.
- `Runtime_AtomicsSynchronizationPrimitiveNumWaitersForTesting`, `Runtime_AtomicsSychronizationNumAsyncWaitersInIsolateForTesting`: These are for testing purposes related to Atomics and asynchronous operations.
- `Runtime_GetWeakCollectionSize`:  Returns the size of a weak collection (WeakMap, WeakSet). This relates to JavaScript's weak collections.
- `Runtime_SetPriorityBestEffort`, `Runtime_SetPriorityUserVisible`, `Runtime_SetPriorityUserBlocking`:  Sets the priority of the V8 isolate. This is more about the execution environment.
- `Runtime_IsEfficiencyModeEnabled`: Checks if efficiency mode is enabled in V8.
- `Runtime_SetBatterySaverMode`:  Enables or disables battery saver mode in V8.
- `Runtime_IsWasmTieringPredictable`: Checks if WebAssembly tiering is predictable for testing.
- `Runtime_GetFeedback`:  Retrieves feedback data about a function, used for optimization.

Now, I will structure the summary and provide JavaScript examples where applicable.
这个C++代码文件 `v8/src/runtime/runtime-test.cc` 的第二部分，延续了第一部分的功能，主要定义了一系列 V8 引擎的**运行时函数 (Runtime Functions)**，这些函数通常用于**测试**或提供一些**底层能力**，可以通过特定的 JavaScript 语法（例如 `%FunctionName()`）在 JavaScript 代码中调用（尽管通常不建议在生产环境中使用）。

**总而言之，这部分代码定义了用于测试 V8 引擎内部机制和提供一些底层能力的运行时函数。**

下面分别归纳每个函数的功能，并尝试用 JavaScript 举例说明其与 JavaScript 功能的关系：

**1. 对象验证 (Object Verification):**

*   **功能:** `Runtime_ObjectVerify` 函数用于验证一个 V8 对象的有效性。它会检查对象是否为合法对象，如果是堆对象还会检查其 Map 的有效性。
*   **与 JavaScript 的关系:** 虽然这个函数本身不能直接在 JavaScript 中调用，但它体现了 V8 引擎在底层对 JavaScript 对象进行管理和校验的机制。
*   **JavaScript 示例:**  在 JavaScript 中，我们不需要显式地验证对象的有效性，V8 引擎会自动处理。如果尝试访问一个无效对象，通常会抛出错误。

    ```javascript
    // V8 内部可能会进行类似这样的校验
    // let obj = ...;
    // if (V8Internal.isValidObject(obj)) {
    //   // ...操作对象
    // } else {
    //   throw new Error("Invalid object");
    // }
    ```

**2. ArrayBuffer 最大字节长度:**

*   **功能:** `Runtime_ArrayBufferMaxByteLength` 函数返回 `ArrayBuffer` 允许的最大字节长度。
*   **与 JavaScript 的关系:**  这个函数直接对应 JavaScript 中的 `ArrayBuffer` 对象的最大尺寸限制。
*   **JavaScript 示例:**

    ```javascript
    console.log(Number.MAX_SAFE_INTEGER); // JavaScript 中最大的安全整数，但 ArrayBuffer 的限制可能不同
    // 通过运行时函数获取 V8 引擎的限制
    // 注意：这通常是测试或调试时使用的方式
    // console.log(%ArrayBufferMaxByteLength());
    ```

**3. 完成对象内联空闲跟踪 (Complete Inobject Slack Tracking):**

*   **功能:** `Runtime_CompleteInobjectSlackTracking` 函数可能与优化对象内存布局有关，用于完成对对象内联空闲空间的跟踪。
*   **与 JavaScript 的关系:**  这个函数涉及到 V8 引擎内部的优化策略，对开发者来说是透明的。
*   **JavaScript 示例:**  JavaScript 开发者不需要关心这个底层的优化过程。

    ```javascript
    // V8 内部可能会在创建或修改对象时进行类似的操作
    // let obj = { a: 1 };
    // // V8 可能会调整 obj 的内存布局以提高效率
    ```

**4. Turbofan 静态断言和解释器状态:**

*   **功能:** `Runtime_TurbofanStaticAssert` 和 `Runtime_IsBeingInterpreted`  是 V8 的 Turbofan 编译器相关的运行时函数。`Runtime_TurbofanStaticAssert` 用于在编译时进行断言，而 `Runtime_IsBeingInterpreted`  在 Turbofan 编译的代码中总是返回 `false`。
*   **与 JavaScript 的关系:** 这些函数主要用于 V8 引擎的内部测试和调试，与 JavaScript 代码的执行方式有关。
*   **JavaScript 示例:**  JavaScript 开发者通常不需要直接接触这些概念。

    ```javascript
    function myFunction() {
      // 这段代码可能被解释执行或被 Turbofan 编译
      return 1 + 1;
    }
    ```

**5. 启用代码日志记录:**

*   **功能:** `Runtime_EnableCodeLoggingForTesting` 函数用于启用代码日志记录，方便测试 V8 引擎的代码生成和执行过程。它创建了一个 `NoopListener`，虽然名字叫 Noop，但它的 `is_listening_to_code_events()` 方法返回 `true`，表明正在监听代码事件。
*   **与 JavaScript 的关系:** 这个函数主要用于 V8 引擎的内部调试和测试。
*   **JavaScript 示例:**  JavaScript 开发者无法直接控制 V8 的代码日志记录。

**6. 创建带回溯限制的正则表达式:**

*   **功能:** `Runtime_NewRegExpWithBacktrackLimit` 函数允许创建一个带有指定回溯限制的正则表达式。这可以用于防止某些恶意的正则表达式导致性能问题。
*   **与 JavaScript 的关系:**  这个函数扩展了 JavaScript 中 `RegExp` 的创建能力，允许更细粒度的控制。
*   **JavaScript 示例:**

    ```javascript
    // 普通的正则表达式创建
    const regex = /abc/;

    // 通过运行时函数创建带回溯限制的正则表达式 (仅用于测试/调试)
    // const limitedRegex = %NewRegExpWithBacktrackLimit("abc", "", 100);
    ```

**7. 判断是否为 64 位系统:**

*   **功能:** `Runtime_Is64Bit` 函数返回一个布尔值，指示 V8 引擎运行在 64 位系统上。
*   **与 JavaScript 的关系:**  这反映了 JavaScript 运行的环境信息。
*   **JavaScript 示例:**  JavaScript 本身不直接提供获取系统位数的 API，但这会影响 V8 内部的内存管理等。

**8. BigInt 最大长度 (位):**

*   **功能:** `Runtime_BigIntMaxLengthBits` 函数返回 `BigInt` 类型允许的最大位数。
*   **与 JavaScript 的关系:**  这个函数直接对应 JavaScript 中 `BigInt` 的精度限制。
*   **JavaScript 示例:**

    ```javascript
    console.log(9007199254740991n); // JavaScript 中 Number 类型的安全整数限制
    // 通过运行时函数获取 BigInt 的限制 (仅用于测试/调试)
    // console.log(%BigIntMaxLengthBits());
    ```

**9. 判断是否为相同的堆对象:**

*   **功能:** `Runtime_IsSameHeapObject` 函数判断两个对象是否指向内存中的同一个位置。
*   **与 JavaScript 的关系:**  这涉及到 JavaScript 对象的引用和内存管理。
*   **JavaScript 示例:**

    ```javascript
    const obj1 = {};
    const obj2 = obj1;
    console.log(obj1 === obj2); // true，因为它们引用同一个对象

    const obj3 = {};
    console.log(obj1 === obj3); // false，它们是不同的对象

    // 通过运行时函数判断 (仅用于测试/调试)
    // console.log(%IsSameHeapObject(obj1, obj2));
    // console.log(%IsSameHeapObject(obj1, obj3));
    ```

**10. 判断是否为共享字符串:**

*   **功能:** `Runtime_IsSharedString` 函数判断一个字符串是否是共享字符串。共享字符串是一种 V8 内部的优化，用于节省内存。
*   **与 JavaScript 的关系:**  这涉及到 V8 引擎内部的字符串优化策略。
*   **JavaScript 示例:**  JavaScript 开发者不需要直接关心字符串是否共享。

    ```javascript
    const str1 = "hello";
    const str2 = "hello";
    console.log(str1 === str2); // true，字符串字面量通常会被内部化或共享

    // 通过运行时函数判断 (仅用于测试/调试)
    // console.log(%IsSharedString(str1));
    ```

**11. 共享对象:**

*   **功能:** `Runtime_ShareObject` 函数尝试将一个对象标记为共享。这可能是 V8 引擎内部用于优化内存的一种机制。
*   **与 JavaScript 的关系:**  这涉及到 V8 引擎内部的内存管理。
*   **JavaScript 示例:**  JavaScript 开发者无法直接控制对象的共享状态。

**12. 判断字符串是否可以就地内部化/是否已内部化:**

*   **功能:** `Runtime_IsInPlaceInternalizableString` 和 `Runtime_IsInternalizedString` 函数用于检查字符串是否可以就地内部化，以及是否已经被内部化。字符串内部化是 V8 引擎的一种优化，通过共享相同的字符串对象来节省内存。
*   **与 JavaScript 的关系:**  这涉及到 V8 引擎内部的字符串优化策略。
*   **JavaScript 示例:**

    ```javascript
    const str1 = "constant string";
    const str2 = "constant string";

    // 字符串字面量通常会被内部化
    // 通过运行时函数判断 (仅用于测试/调试)
    // console.log(%IsInternalizedString(str1));
    // console.log(%IsInPlaceInternalizableString("some potentially internalizable string"));
    ```

**13. 字符串转换为 C 风格字符串/UTF-8 值:**

*   **功能:** `Runtime_StringToCString` 和 `Runtime_StringUtf8Value` 函数分别将 V8 的字符串对象转换为 C 风格的字符串（以 null 结尾）和 UTF-8 编码的字节数组。
*   **与 JavaScript 的关系:**  这涉及到 JavaScript 字符串在 V8 引擎底层的表示和转换。
*   **JavaScript 示例:**  JavaScript 字符串在底层会被编码成不同的格式。

    ```javascript
    const str = "你好";
    // 通过运行时函数获取 C 风格字符串或 UTF-8 值 (仅用于测试/调试)
    // const cString = %StringToCString(str);
    // const utf8Bytes = %StringUtf8Value(str);
    ```

**14. 共享堆垃圾回收:**

*   **功能:** `Runtime_SharedGC` 函数触发共享堆的垃圾回收。共享堆是 V8 引擎用于存储一些跨 Isolate 共享的对象的地方。
*   **与 JavaScript 的关系:**  垃圾回收是 V8 引擎自动进行的内存管理机制，对 JavaScript 开发者来说通常是透明的。
*   **JavaScript 示例:**  JavaScript 开发者无法直接控制垃圾回收。

**15. Atomics 同步原语等待者数量:**

*   **功能:** `Runtime_AtomicsSynchronizationPrimitiveNumWaitersForTesting` 和 `Runtime_AtomicsSychronizationNumAsyncWaitersInIsolateForTesting` 函数用于测试目的，分别返回特定同步原语的等待者数量以及 Isolate 中异步等待者的数量。
*   **与 JavaScript 的关系:**  这涉及到 JavaScript 中的 `Atomics` API，用于实现多线程环境下的同步。
*   **JavaScript 示例:**

    ```javascript
    const sab = new SharedArrayBuffer(4);
    const i32a = new Int32Array(sab);
    // ... 在不同的线程中使用 Atomics.wait 等
    // 通过运行时函数获取等待者数量 (仅用于测试/调试)
    // console.log(%AtomicsSynchronizationPrimitiveNumWaitersForTesting(primitive));
    ```

**16. 获取 Weak Collection 的大小:**

*   **功能:** `Runtime_GetWeakCollectionSize` 函数返回 `WeakMap` 或 `WeakSet` 中元素的数量。
*   **与 JavaScript 的关系:**  直接对应 JavaScript 中 `WeakMap` 和 `WeakSet` 的使用。由于 Weak Collection 中的键是弱引用，所以其大小可能随时变化。
*   **JavaScript 示例:**

    ```javascript
    const wm = new WeakMap();
    const key = {};
    wm.set(key, "value");
    console.log(wm.size); // WeakMap 没有 size 属性

    // 通过运行时函数获取大小 (仅用于测试/调试)
    // console.log(%GetWeakCollectionSize(wm));
    ```

**17. 设置 Isolate 优先级:**

*   **功能:** `Runtime_SetPriorityBestEffort`, `Runtime_SetPriorityUserVisible`, `Runtime_SetPriorityUserBlocking` 函数用于设置 V8 Isolate 的执行优先级。
*   **与 JavaScript 的关系:**  这涉及到 V8 引擎的调度和资源分配。
*   **JavaScript 示例:**  JavaScript 开发者无法直接控制 V8 Isolate 的优先级。

**18. 判断是否启用效率模式:**

*   **功能:** `Runtime_IsEfficiencyModeEnabled` 函数返回一个布尔值，指示 V8 引擎是否启用了效率模式。
*   **与 JavaScript 的关系:**  效率模式是 V8 引擎的一种优化策略，可能会影响代码的执行效率和内存使用。

**19. 设置省电模式:**

*   **功能:** `Runtime_SetBatterySaverMode` 函数用于启用或禁用 V8 引擎的省电模式。
*   **与 JavaScript 的关系:**  省电模式可能会影响 JavaScript 代码的执行性能，以换取更低的功耗。

**20. 判断 WebAssembly 分层编译是否可预测:**

*   **功能:** `Runtime_IsWasmTieringPredictable` 函数用于判断 WebAssembly 的分层编译状态是否可以以可预测的方式断言。这主要用于测试。
*   **与 JavaScript 的关系:**  涉及到 WebAssembly 代码在 V8 引擎中的编译和优化。

**21. 获取函数反馈信息:**

*   **功能:** `Runtime_GetFeedback` 函数用于获取关于函数的反馈信息，这些信息被 V8 的优化编译器 (如 Turbofan) 用于进行代码优化。
*   **与 JavaScript 的关系:**  这涉及到 V8 引擎的性能优化机制。
*   **JavaScript 示例:**  JavaScript 开发者通常不需要直接访问这些反馈信息。

    ```javascript
    function add(a, b) {
      return a + b;
    }
    add(1, 2); // 调用几次后，V8 可能会收集反馈信息

    // 通过运行时函数获取反馈信息 (仅用于测试/调试)
    // console.log(%GetFeedback(add));
    ```

总的来说，这部分代码是 V8 引擎内部机制的“后门”，主要用于测试和提供一些底层的控制能力，与开发者日常编写的 JavaScript 代码有间接的关系，体现了 V8 引擎为了高效执行 JavaScript 代码所做的各种底层工作。

### 提示词
```
这是目录为v8/src/runtime/runtime-test.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
Y_HEAP
  Object::ObjectVerify(*object, isolate);
#else
  CHECK(IsObject(*object));
  if (IsHeapObject(*object)) {
    CHECK(IsMap(Cast<HeapObject>(*object)->map()));
  } else {
    CHECK(IsSmi(*object));
  }
#endif
  return isolate->heap()->ToBoolean(true);
}

RUNTIME_FUNCTION(Runtime_ArrayBufferMaxByteLength) {
  HandleScope shs(isolate);
  return *isolate->factory()->NewNumber(JSArrayBuffer::kMaxByteLength);
}

RUNTIME_FUNCTION(Runtime_CompleteInobjectSlackTracking) {
  // TODO(353928347): This function is not currently exposed to fuzzers.
  // Investigate if it should be.
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsJSObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }

  DirectHandle<JSObject> object = args.at<JSObject>(0);
  MapUpdater::CompleteInobjectSlackTracking(isolate, object->map());

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_TurbofanStaticAssert) {
  SealHandleScope shs(isolate);
  // Always lowered to StaticAssert node in Turbofan, so we never get here in
  // compiled code.
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_IsBeingInterpreted) {
  SealHandleScope shs(isolate);
  // Always lowered to false in Turbofan, so we never get here in compiled code.
  return ReadOnlyRoots(isolate).true_value();
}

RUNTIME_FUNCTION(Runtime_EnableCodeLoggingForTesting) {
  // The {NoopListener} currently does nothing on any callback, but reports
  // {true} on {is_listening_to_code_events()}. Feel free to add assertions to
  // any method to further test the code logging callbacks.
  class NoopListener final : public LogEventListener {
    void CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                         const char* name) final {}
    void CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                         Handle<Name> name) final {}
    void CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                         Handle<SharedFunctionInfo> shared,
                         Handle<Name> script_name) final {}
    void CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                         Handle<SharedFunctionInfo> shared,
                         Handle<Name> script_name, int line, int column) final {
    }
#if V8_ENABLE_WEBASSEMBLY
    void CodeCreateEvent(CodeTag tag, const wasm::WasmCode* code,
                         wasm::WasmName name, const char* source_url,
                         int code_offset, int script_id) final {}
#endif  // V8_ENABLE_WEBASSEMBLY

    void CallbackEvent(Handle<Name> name, Address entry_point) final {}
    void GetterCallbackEvent(Handle<Name> name, Address entry_point) final {}
    void SetterCallbackEvent(Handle<Name> name, Address entry_point) final {}
    void RegExpCodeCreateEvent(Handle<AbstractCode> code, Handle<String> source,
                               RegExpFlags flags) final {}
    void CodeMoveEvent(Tagged<InstructionStream> from,
                       Tagged<InstructionStream> to) final {}
    void BytecodeMoveEvent(Tagged<BytecodeArray> from,
                           Tagged<BytecodeArray> to) final {}
    void SharedFunctionInfoMoveEvent(Address from, Address to) final {}
    void NativeContextMoveEvent(Address from, Address to) final {}
    void CodeMovingGCEvent() final {}
    void CodeDisableOptEvent(Handle<AbstractCode> code,
                             Handle<SharedFunctionInfo> shared) final {}
    void CodeDeoptEvent(Handle<Code> code, DeoptimizeKind kind, Address pc,
                        int fp_to_sp_delta) final {}
    void CodeDependencyChangeEvent(Handle<Code> code,
                                   Handle<SharedFunctionInfo> shared,
                                   const char* reason) final {}
    void WeakCodeClearEvent() final {}

    bool is_listening_to_code_events() final { return true; }
  };
  static base::LeakyObject<NoopListener> noop_listener;
#if V8_ENABLE_WEBASSEMBLY
  wasm::GetWasmEngine()->EnableCodeLogging(isolate);
#endif  // V8_ENABLE_WEBASSEMBLY
  isolate->logger()->AddListener(noop_listener.get());
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_NewRegExpWithBacktrackLimit) {
  HandleScope scope(isolate);
  if (args.length() != 3 || !IsString(args[0]) || !IsString(args[1]) ||
      !IsSmi(args[2])) {
    return CrashUnlessFuzzing(isolate);
  }

  Handle<String> pattern = args.at<String>(0);
  Handle<String> flags_string = args.at<String>(1);
  int backtrack_limit = args.smi_value_at(2);
  if (backtrack_limit < 0) {
    return CrashUnlessFuzzing(isolate);
  }

  auto maybe_flags = JSRegExp::FlagsFromString(isolate, flags_string);
  if (!maybe_flags.has_value()) {
    return CrashUnlessFuzzing(isolate);
  }
  JSRegExp::Flags flags = maybe_flags.value();

  RETURN_RESULT_OR_FAILURE(
      isolate, JSRegExp::New(isolate, pattern, flags, backtrack_limit));
}

RUNTIME_FUNCTION(Runtime_Is64Bit) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(kSystemPointerSize == 8);
}

RUNTIME_FUNCTION(Runtime_BigIntMaxLengthBits) {
  HandleScope scope(isolate);
  return *isolate->factory()->NewNumber(BigInt::kMaxLengthBits);
}

RUNTIME_FUNCTION(Runtime_IsSameHeapObject) {
  HandleScope scope(isolate);
  if (args.length() != 2 || !IsHeapObject(args[0]) || !IsHeapObject(args[1])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<HeapObject> obj1 = args.at<HeapObject>(0);
  DirectHandle<HeapObject> obj2 = args.at<HeapObject>(1);
  return isolate->heap()->ToBoolean(obj1->address() == obj2->address());
}

RUNTIME_FUNCTION(Runtime_IsSharedString) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsHeapObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<HeapObject> obj = args.at<HeapObject>(0);
  return isolate->heap()->ToBoolean(IsString(*obj) &&
                                    Cast<String>(obj)->IsShared());
}

RUNTIME_FUNCTION(Runtime_ShareObject) {
  // TODO(354005312): This function is not currently exposed to fuzzers.
  // Investigate if it should be.
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsHeapObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<HeapObject> obj = args.at<HeapObject>(0);
  ShouldThrow should_throw = v8_flags.fuzzing ? kDontThrow : kThrowOnError;
  MaybeHandle<Object> maybe_shared = Object::Share(isolate, obj, should_throw);
  Handle<Object> shared;
  if (!maybe_shared.ToHandle(&shared)) {
    return CrashUnlessFuzzing(isolate);
  }
  return *shared;
}

RUNTIME_FUNCTION(Runtime_IsInPlaceInternalizableString) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsHeapObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<HeapObject> obj = args.at<HeapObject>(0);
  return isolate->heap()->ToBoolean(
      IsString(*obj) && String::IsInPlaceInternalizable(Cast<String>(*obj)));
}

RUNTIME_FUNCTION(Runtime_IsInternalizedString) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsHeapObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<HeapObject> obj = args.at<HeapObject>(0);
  return isolate->heap()->ToBoolean(IsInternalizedString(*obj));
}

RUNTIME_FUNCTION(Runtime_StringToCString) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsString(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<String> string = args.at<String>(0);

  size_t output_length;
  auto bytes = string->ToCString(&output_length);

  Handle<JSArrayBuffer> result =
      isolate->factory()
          ->NewJSArrayBufferAndBackingStore(output_length,
                                            InitializedFlag::kUninitialized)
          .ToHandleChecked();
  memcpy(result->backing_store(), bytes.get(), output_length);
  return *result;
}

RUNTIME_FUNCTION(Runtime_StringUtf8Value) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsString(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<String> string = args.at<String>(0);

  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  v8::String::Utf8Value value(v8_isolate, v8::Utils::ToLocal(string));

  Handle<JSArrayBuffer> result =
      isolate->factory()
          ->NewJSArrayBufferAndBackingStore(value.length(),
                                            InitializedFlag::kUninitialized)
          .ToHandleChecked();
  memcpy(result->backing_store(), *value, value.length());
  return *result;
}

RUNTIME_FUNCTION(Runtime_SharedGC) {
  SealHandleScope scope(isolate);
  if (!isolate->has_shared_space()) {
    return CrashUnlessFuzzing(isolate);
  }
  isolate->heap()->CollectGarbageShared(isolate->main_thread_local_heap(),
                                        GarbageCollectionReason::kTesting);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_AtomicsSynchronizationPrimitiveNumWaitersForTesting) {
  HandleScope scope(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<JSSynchronizationPrimitive> primitive =
      args.at<JSSynchronizationPrimitive>(0);
  return primitive->NumWaitersForTesting(isolate);
}

RUNTIME_FUNCTION(
    Runtime_AtomicsSychronizationNumAsyncWaitersInIsolateForTesting) {
  return Smi::FromInt(
      static_cast<uint32_t>(isolate->async_waiter_queue_nodes().size()));
}

RUNTIME_FUNCTION(Runtime_GetWeakCollectionSize) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsJSWeakCollection(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<JSWeakCollection> collection = args.at<JSWeakCollection>(0);

  return Smi::FromInt(
      Cast<EphemeronHashTable>(collection->table())->NumberOfElements());
}

RUNTIME_FUNCTION(Runtime_SetPriorityBestEffort) {
  isolate->SetPriority(v8::Isolate::Priority::kBestEffort);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_SetPriorityUserVisible) {
  isolate->SetPriority(v8::Isolate::Priority::kUserVisible);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_SetPriorityUserBlocking) {
  isolate->SetPriority(v8::Isolate::Priority::kUserBlocking);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_IsEfficiencyModeEnabled) {
  if (isolate->EfficiencyModeEnabled()) {
    return ReadOnlyRoots(isolate).true_value();
  }
  return ReadOnlyRoots(isolate).false_value();
}

RUNTIME_FUNCTION(Runtime_SetBatterySaverMode) {
  HandleScope scope(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  if (*args.at<Object>(0) == ReadOnlyRoots(isolate).true_value()) {
    isolate->set_battery_saver_mode_enabled(true);
  } else {
    isolate->set_battery_saver_mode_enabled(false);
  }
  // If the override flag is set changing the mode has no effect.
  if (v8_flags.battery_saver_mode.value().has_value()) {
    return ReadOnlyRoots(isolate).false_value();
  }
  return ReadOnlyRoots(isolate).true_value();
}

// Returns true if the tiering state (liftoff, turbofan) of wasm functions can
// be asserted in a predictable way.
RUNTIME_FUNCTION(Runtime_IsWasmTieringPredictable) {
  DCHECK_EQ(args.length(), 0);
  const bool single_isolate = g_num_isolates_for_testing == 1;
  const bool stress_deopt = v8_flags.deopt_every_n_times > 0;
  return ReadOnlyRoots(isolate).boolean_value(single_isolate && !stress_deopt);
}

RUNTIME_FUNCTION(Runtime_GetFeedback) {
  HandleScope scope(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<Object> function_object = args.at(0);
  if (!IsJSFunction(*function_object)) return CrashUnlessFuzzing(isolate);
  Handle<JSFunction> function = Cast<JSFunction>(function_object);

  if (!function->has_feedback_vector()) {
    return CrashUnlessFuzzing(isolate);
  }

#ifdef V8_JITLESS
  // No feedback is collected in jitless mode, so tests calling %GetFeedback
  // don't make sense.
  return ReadOnlyRoots(isolate).undefined_value();
#else
#ifdef OBJECT_PRINT
  Handle<FeedbackVector> feedback_vector =
      handle(function->feedback_vector(), isolate);

  Handle<FixedArray> result =
      isolate->factory()->NewFixedArray(feedback_vector->length());
  int result_ix = 0;

  FeedbackMetadataIterator iter(feedback_vector->metadata());
  while (iter.HasNext()) {
    FeedbackSlot slot = iter.Next();
    FeedbackSlotKind kind = iter.kind();

    Handle<FixedArray> sub_result = isolate->factory()->NewFixedArray(2);
    {
      std::ostringstream out;
      out << kind;
      Handle<String> kind_string =
          isolate->factory()->NewStringFromAsciiChecked(out.str().c_str());
      sub_result->set(0, *kind_string);
    }

    FeedbackNexus nexus(isolate, *feedback_vector, slot);
    {
      std::ostringstream out;
      nexus.Print(out);
      Handle<String> nexus_string =
          isolate->factory()->NewStringFromAsciiChecked(out.str().c_str());
      sub_result->set(1, *nexus_string);
    }

    Handle<JSArray> sub_result_array =
        isolate->factory()->NewJSArrayWithElements(sub_result);
    result->set(result_ix++, *sub_result_array);
  }

  return *isolate->factory()->NewJSArrayWithElements(result);
#else
  return ReadOnlyRoots(isolate).undefined_value();
#endif  // OBJECT_PRINT
#endif  // not V8_JITLESS
}

}  // namespace internal
}  // namespace v8
```