Response:
My thinking process to analyze the provided C++ code snippet and generate the summary follows these steps:

1. **Understand the Context:** The prompt explicitly states this is part 3 of a 3-part analysis of `v8/src/runtime/runtime-test.cc`. This tells me I need to consider it as a continuation of previous analyses and focus on the specific functionalities present in this snippet. The prompt also provides crucial information:
    * If it were a `.tq` file, it would be Torque (a V8-specific language). This tells me to look for C++ runtime functions.
    * Its connection to JavaScript means I need to identify functionalities that have direct counterparts or are used in the implementation of JavaScript features.
    * The request for examples, logic, and common errors guides the type of analysis I need to perform.

2. **Identify Key Components:**  I scan the code for the defining structure: `RUNTIME_FUNCTION(...)`. This macro clearly indicates the functions being defined are part of V8's runtime system, accessible (in some way) from JavaScript. Each `RUNTIME_FUNCTION` block represents a distinct functionality.

3. **Analyze Each `RUNTIME_FUNCTION` Individually:** For each function, I perform the following sub-steps:

    * **Function Name and Arguments:** Note the function name (e.g., `Runtime_IsObject`) and the arguments it expects (implicit via `args`).
    * **Core Logic:**  Understand the main purpose of the code within the function. What does it check? What does it return?  I look for core V8 API calls like `isolate->heap()->ToBoolean()`, `IsObject()`, `Cast<>`, factory methods (e.g., `isolate->factory()->NewNumber()`), etc.
    * **JavaScript Connection:**  Consider if this function has a direct or indirect connection to a JavaScript concept. For example, `Runtime_IsObject` clearly relates to the JavaScript `typeof` operator or checking object types. `Runtime_ArrayBufferMaxByteLength` relates to `ArrayBuffer.maxByteLength`.
    * **Logic and Input/Output:** If there's conditional logic, I try to infer possible inputs and the corresponding outputs. For example, `Runtime_IsObject` takes an object and returns a boolean.
    * **Potential Errors:** Think about how a user might misuse or encounter issues related to the functionality. For instance, providing the wrong type of argument to a runtime function would be a common error.
    * **Internal V8 Mechanisms:**  Note any internal V8 concepts like "inobject slack tracking," "Turbofan," "code logging," "shared space," "weak collections," "efficiency mode," etc. These are important for understanding the broader context.

4. **Categorize and Group Functionalities:**  As I analyze each function, I start to see patterns and can group them logically. For example, there are functions related to:
    * **Object inspection:** `Runtime_IsObject`, `Runtime_IsSameHeapObject`, `Runtime_IsSharedString`, `Runtime_IsInPlaceInternalizableString`, `Runtime_IsInternalizedString`.
    * **String manipulation:** `Runtime_StringToCString`, `Runtime_StringUtf8Value`.
    * **Internal V8 state:** `Runtime_TurbofanStaticAssert`, `Runtime_IsBeingInterpreted`, `Runtime_EnableCodeLoggingForTesting`, `Runtime_Is64Bit`.
    * **Memory management:** `Runtime_SharedGC`.
    * **Regular expressions:** `Runtime_NewRegExpWithBacktrackLimit`.
    * **Concurrency primitives:** `Runtime_AtomicsSynchronizationPrimitiveNumWaitersForTesting`, `Runtime_AtomicsSychronizationNumAsyncWaitersInIsolateForTesting`.
    * **Weak collections:** `Runtime_GetWeakCollectionSize`.
    * **Performance/Power Management:** `Runtime_SetPriorityBestEffort`, `Runtime_SetPriorityUserVisible`, `Runtime_SetPriorityUserBlocking`, `Runtime_IsEfficiencyModeEnabled`, `Runtime_SetBatterySaverMode`, `Runtime_IsWasmTieringPredictable`.
    * **Debugging/Testing:** `Runtime_GetFeedback`.

5. **Synthesize the Summary:**  Based on the individual analyses and the groupings, I formulate a concise summary that captures the main purposes of the code. I reiterate the key information from the prompt (C++, runtime tests) and then list the major categories of functionality.

6. **Provide Examples and Explanations:** For functions with JavaScript relevance, I craft simple JavaScript examples to illustrate their behavior or the JavaScript features they relate to. For code logic, I provide specific input/output examples. For common errors, I illustrate typical mistakes a programmer might make.

7. **Address the "Part 3" and Overall Functionality:**  Since this is part 3, I ensure the summary integrates with the understanding built in the previous parts (even though I don't have the actual content of parts 1 and 2). I aim to provide a high-level overview of the role of `runtime-test.cc`.

8. **Refine and Review:**  I reread my summary to ensure clarity, accuracy, and completeness, checking if I've addressed all aspects of the prompt. I make sure the language is precise and avoids unnecessary jargon.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and informative summary that addresses all the requirements of the prompt. The key is to break down the problem into smaller, manageable parts and then synthesize the results into a coherent overview.
这是`v8/src/runtime/runtime-test.cc`源代码的第三部分，主要包含了一系列V8运行时的测试函数。这些函数通常以`Runtime_`开头，用于在V8内部进行各种底层功能的测试和验证。由于这是测试代码，它的功能是为了确保V8引擎的各个部分按照预期工作。

**归纳一下它的功能:**

这部分代码定义了一系列V8运行时测试函数，涵盖了对象类型检查、内存管理、字符串处理、正则表达式、并发原语、弱集合、性能和电源管理等多个方面。这些函数不直接暴露给JavaScript开发者，而是V8内部测试框架使用的，用于验证V8引擎的底层实现细节和功能是否正确。

**详细功能列举:**

以下是每个`RUNTIME_FUNCTION`的具体功能解释：

* **`Runtime_IsObject(Object object)`:**
    * **功能:** 检查给定的对象是否是V8中的对象。
    * **代码逻辑推理:**
        * **假设输入:** 一个V8中的对象实例或一个原始值。
        * **输出:** 如果是对象则返回 `true` (转换为 JavaScript 的 `true`)，否则返回 `false` (转换为 JavaScript 的 `false`)。
    * **与 JavaScript 的关系:** 类似于 JavaScript 中的 `typeof obj === 'object'` 或 `obj instanceof Object`。
    * **JavaScript 示例:**
      ```javascript
      %IsObject({}); // true
      %IsObject(null); // false
      %IsObject(1); // false
      ```

* **`Runtime_ArrayBufferMaxByteLength()`:**
    * **功能:** 返回 `ArrayBuffer` 允许的最大字节长度。
    * **与 JavaScript 的关系:**  对应 JavaScript 中的 `ArrayBuffer.maxByteLength` 属性。
    * **JavaScript 示例:**
      ```javascript
      %ArrayBufferMaxByteLength(); // 返回一个数字，表示最大字节长度
      ```

* **`Runtime_CompleteInobjectSlackTracking(JSObject object)`:**
    * **功能:**  完成对给定对象的内联空闲空间跟踪。这通常用于优化对象内存布局。
    * **代码逻辑推理:**  该函数接收一个 `JSObject`，并调用 `MapUpdater::CompleteInobjectSlackTracking` 来更新其映射信息。
    * **与 JavaScript 的关系:**  这是一个内部优化机制，JavaScript 用户通常不会直接感知。

* **`Runtime_TurbofanStaticAssert()`:**
    * **功能:**  一个静态断言，在 Turbofan 优化编译过程中会被内联处理，正常执行时不会到达这里。
    * **与 JavaScript 的关系:**  用于 V8 内部的优化和断言机制。

* **`Runtime_IsBeingInterpreted()`:**
    * **功能:**  判断当前代码是否正在被解释器执行。在 Turbofan 优化编译后，通常返回 `false`。
    * **与 JavaScript 的关系:**  V8 内部的执行状态判断。

* **`Runtime_EnableCodeLoggingForTesting()`:**
    * **功能:**  启用代码日志记录，用于测试目的。它添加一个不做任何操作的监听器，但会报告正在监听代码事件。
    * **与 JavaScript 的关系:**  用于 V8 内部的调试和测试。

* **`Runtime_NewRegExpWithBacktrackLimit(String pattern, String flags_string, Smi backtrack_limit)`:**
    * **功能:**  创建一个带有指定回溯限制的正则表达式对象。
    * **与 JavaScript 的关系:**  类似于 JavaScript 中的 `new RegExp(pattern, flags)`，但增加了回溯限制的控制。
    * **JavaScript 示例:**
      ```javascript
      // 假设 %NewRegExpWithBacktrackLimit 是如何暴露的
      %NewRegExpWithBacktrackLimit("a+", "", 10); // 创建一个回溯限制为 10 的 /a+/ 正则表达式
      ```
    * **用户常见的编程错误:**  设置过小的回溯限制可能导致正则表达式匹配失败或提前停止。

* **`Runtime_Is64Bit()`:**
    * **功能:**  判断 V8 引擎是否在 64 位系统上运行。
    * **与 JavaScript 的关系:**  与 JavaScript 运行环境的体系结构相关。
    * **JavaScript 示例:**  虽然 JavaScript 本身没有直接获取这个信息的方法，但在一些宿主环境或通过特定的 API 可能可以间接判断。

* **`Runtime_BigIntMaxLengthBits()`:**
    * **功能:**  返回 `BigInt` 可以表示的最大位数。
    * **与 JavaScript 的关系:**  对应 JavaScript 中的 `BigInt` 类型的限制。
    * **JavaScript 示例:**
      ```javascript
      %BigIntMaxLengthBits(); // 返回一个数字，表示 BigInt 的最大位数
      ```

* **`Runtime_IsSameHeapObject(HeapObject obj1, HeapObject obj2)`:**
    * **功能:**  检查两个堆对象是否是同一个对象（在内存中的地址是否相同）。
    * **与 JavaScript 的关系:**  类似于 JavaScript 中的严格相等 `===` 对对象进行比较。
    * **JavaScript 示例:**
      ```javascript
      const obj1 = {};
      const obj2 = obj1;
      const obj3 = {};
      %IsSameHeapObject(obj1, obj2); // true
      %IsSameHeapObject(obj1, obj3); // false
      ```

* **`Runtime_IsSharedString(HeapObject obj)`:**
    * **功能:**  检查给定的堆对象是否是一个共享字符串。
    * **与 JavaScript 的关系:**  共享字符串是 V8 内部的一种优化机制。
    * **JavaScript 示例:**  JavaScript 没有直接的方法创建或判断共享字符串。

* **`Runtime_ShareObject(HeapObject obj)`:**
    * **功能:**  尝试将一个对象共享。这通常用于优化内存使用。
    * **与 JavaScript 的关系:**  V8 内部的内存管理机制。

* **`Runtime_IsInPlaceInternalizableString(HeapObject obj)`:**
    * **功能:**  检查给定的堆对象是否是一个可以原地内部化的字符串。内部化是一种字符串优化的方式。
    * **与 JavaScript 的关系:**  V8 内部的字符串优化机制。

* **`Runtime_IsInternalizedString(HeapObject obj)`:**
    * **功能:**  检查给定的堆对象是否是一个已经被内部化的字符串。
    * **与 JavaScript 的关系:**  V8 内部的字符串优化机制，类似于字符串池。

* **`Runtime_StringToCString(String string)`:**
    * **功能:**  将 V8 的字符串转换为 C 风格的字符串 (char*)。
    * **与 JavaScript 的关系:**  用于 V8 内部与 C++ 代码的交互。

* **`Runtime_StringUtf8Value(String string)`:**
    * **功能:**  将 V8 的字符串转换为 UTF-8 编码的字节数组。
    * **与 JavaScript 的关系:**  类似于获取 JavaScript 字符串的 UTF-8 表示。
    * **JavaScript 示例:**
      ```javascript
      const str = "你好";
      // 假设 %StringUtf8Value 是如何暴露的
      const utf8Bytes = %StringUtf8Value(str); // 返回一个 ArrayBuffer 或类似结构
      // 可以手动验证其 UTF-8 编码
      ```

* **`Runtime_SharedGC()`:**
    * **功能:**  触发共享堆的垃圾回收。
    * **与 JavaScript 的关系:**  V8 的垃圾回收机制，对 JavaScript 开发者是透明的。

* **`Runtime_AtomicsSynchronizationPrimitiveNumWaitersForTesting(JSSynchronizationPrimitive primitive)`:**
    * **功能:**  获取原子同步原语上等待的线程数量，用于测试。
    * **与 JavaScript 的关系:**  与 JavaScript 的原子操作和并发相关。

* **`Runtime_AtomicsSychronizationNumAsyncWaitersInIsolateForTesting()`:**
    * **功能:**  获取当前 Isolate 中异步等待的原子操作数量，用于测试。
    * **与 JavaScript 的关系:**  与 JavaScript 的异步原子操作相关。

* **`Runtime_GetWeakCollectionSize(JSWeakCollection collection)`:**
    * **功能:**  获取弱集合（如 `WeakMap`，`WeakSet`）中元素的数量。
    * **与 JavaScript 的关系:**  对应 JavaScript 中的 `WeakMap.size` 或 `WeakSet.size` (虽然 `WeakMap` 和 `WeakSet` 没有 `size` 属性，但这个运行时函数用于内部检查)。

* **`Runtime_SetPriorityBestEffort()`, `Runtime_SetPriorityUserVisible()`, `Runtime_SetPriorityUserBlocking()`:**
    * **功能:**  设置 V8 Isolate 的优先级，影响其资源分配。
    * **与 JavaScript 的关系:**  影响 JavaScript 代码的执行性能。

* **`Runtime_IsEfficiencyModeEnabled()`:**
    * **功能:**  检查是否启用了效率模式（可能降低性能以节省资源）。
    * **与 JavaScript 的关系:**  影响 JavaScript 代码的执行方式和性能。

* **`Runtime_SetBatterySaverMode(Object value)`:**
    * **功能:**  设置电池保护模式。
    * **与 JavaScript 的关系:**  可能影响 JavaScript 代码的执行方式和性能以节省电量。

* **`Runtime_IsWasmTieringPredictable()`:**
    * **功能:**  判断 WebAssembly 分层编译的状态是否可预测，用于测试。
    * **与 JavaScript 的关系:**  与 WebAssembly 模块的编译和优化相关。

* **`Runtime_GetFeedback(JSFunction function)`:**
    * **功能:**  获取函数的反馈信息，用于性能分析和优化。
    * **与 JavaScript 的关系:**  V8 内部的性能监控和优化机制。

**用户常见的编程错误示例:**

虽然这些运行时函数不直接暴露给用户，但了解它们背后的概念可以帮助理解一些 JavaScript 编程错误：

* **类型错误:**  例如，期望一个对象但传入了原始值，这可能导致 V8 内部的类型检查失败，就像 `Runtime_IsObject` 的测试那样。
* **正则表达式性能问题:**  不当的正则表达式可能导致回溯过多，影响性能甚至导致拒绝服务。`Runtime_NewRegExpWithBacktrackLimit` 的存在表明 V8 内部有控制这种行为的机制。
* **内存泄漏:** 理解共享对象和弱集合的概念有助于避免由于不正确的对象引用导致的内存泄漏。

总而言之，`v8/src/runtime/runtime-test.cc` 的这部分代码是 V8 引擎内部测试框架的重要组成部分，用于确保 V8 的各种底层功能和优化机制按预期工作。虽然开发者不能直接调用这些函数，但理解它们的功能有助于深入了解 V8 的内部运作机制。

### 提示词
```
这是目录为v8/src/runtime/runtime-test.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-test.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
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