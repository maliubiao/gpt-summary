Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/api/api.cc`. They also have specific instructions related to file extensions, JavaScript relationships, code logic, common programming errors, and the fact that this is part 14 of 15.

Here's a breakdown of the thought process to address each point:

1. **Overall Functionality:** Read through the code and identify the main classes and methods being defined. Notice the heavy use of `Isolate`, `CpuProfile`, `MicrotaskQueue`, and `String`. Recognize that this file seems to provide the C++ API for interacting with V8's core functionalities. Key areas appear to be memory management (code and embedded code ranges, code pages), JavaScript execution control (entry stubs, callbacks), error handling, WebAssembly integration, microtasks, string manipulation, exception handling, CPU profiling, and code event tracking.

2. **`.tq` Extension:**  The instruction is straightforward. Check if the file extension is `.tq`. Since it's `.cc`, the answer is that it's not a Torque source file.

3. **Relationship to JavaScript:** Look for methods and functionalities that directly relate to JavaScript concepts. `JSEntryStubs` clearly relates to entering JavaScript execution. Callbacks like `FatalErrorHandler`, `OOMErrorHandler`, and `ModifyCodeGenerationFromStringsCallback` are used when JavaScript execution encounters errors or requires customization. `InstallConditionalFeatures` hints at setting up features within a JavaScript context. Microtasks are a direct JavaScript feature. String conversion methods (`Utf8Value`, `Value`) are used to interact with JavaScript strings. Exception handling is fundamental to JavaScript. The CPU profiler can be used to analyze JavaScript performance.

4. **JavaScript Examples:** For the identified JavaScript relationships, provide concrete examples.
    * `GetCodeRange`:  While not directly used in JS, explain its relevance in understanding the JS engine's memory.
    * `GetJSEntryStubs`: Explain how this relates to calling JS functions from C++.
    * Callbacks: Show how to set error handlers in Node.js.
    * `InstallConditionalFeatures`: Mention that this is internal but affects available JS features.
    * Microtasks: Give a basic `queueMicrotask` example.
    * String conversion: Show how to convert JS values to strings in C++.
    * Exception handling: Demonstrate catching errors in JS.
    * CPU Profiling:  Provide a brief explanation of how to use Node.js's profiler.

5. **Code Logic Inference (Hypothetical Inputs/Outputs):** Select a method with clear input and output. `CopyCodePages` seems suitable. Create a hypothetical scenario with a specific `capacity` and demonstrate how the `code_pages_out` array would be populated, including the case where `capacity` is smaller than the number of code pages.

6. **Common Programming Errors:** Think about how developers might misuse the functionalities provided in this file.
    * Incorrectly sized buffer for `CopyCodePages`.
    * Forgetting to handle potential failures in string conversion (`ToString` returning `empty`).
    * Misunderstanding microtask execution order.

7. **归纳功能 (Summarize Functionality):**  Combine the points from step 1 into a concise summary. Emphasize that it's the C++ API for core V8 features.

8. **Part of a Series:** Acknowledge that this is part 14/15 and infer that the overall `api.cc` file likely covers the entire public API of the V8 engine. The specific section focuses on `Isolate` and related functionalities.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:**  Focus heavily on low-level memory details.
* **Correction:**  Balance the low-level details with higher-level concepts more directly relevant to JavaScript developers. The request specifically asks about the relationship to JavaScript.
* **Initial thought:** Provide very technical C++ examples for everything.
* **Correction:**  Use JavaScript examples where applicable to make the explanations more accessible. Keep C++ examples for purely C++-related functions.
* **Initial thought:**  Go into extreme detail about each method.
* **Correction:**  Provide a high-level overview of most methods and only delve into details for illustrative examples. Given that this is part of a larger file, a complete deep dive into every function would be excessive for a summary.
* **Initial thought:** Directly translate C++ code into JavaScript.
* **Correction:**  Explain the *purpose* of the C++ code in relation to JavaScript concepts, rather than attempting a direct translation, which isn't always possible or meaningful.

By following these steps and making adjustments along the way, the aim is to provide a comprehensive yet understandable summary that addresses all aspects of the user's request.
好的，根据你提供的代码片段，并结合这是一个15部分中的第14部分，我们可以归纳一下 `v8/src/api/api.cc` 中这段代码的功能：

**主要功能归纳:**

这段代码主要定义了 `v8::Isolate` 类的一些核心方法，用于管理 V8 虚拟机实例的内部状态和资源，并提供与嵌入器进行交互的接口。 核心功能点包括：

1. **代码内存管理:**
   - 提供获取代码段（code region）和嵌入代码段（embedded code range）内存地址和大小的方法 (`GetCodeRange`, `GetEmbeddedCodeRange`)。这允许嵌入器了解 V8 代码的内存布局。
   - 提供了复制代码页信息的方法 (`CopyCodePages`)，这在某些架构下用于内存管理和安全。

2. **JavaScript 执行入口:**
   -  `GetJSEntryStubs()` 方法返回 JavaScript 执行的入口点（例如，普通函数调用、构造函数调用、运行微任务）。这些入口点是 C++ 代码调用 JavaScript 代码的关键。

3. **回调函数设置:**
   -  定义了一系列的 `CALLBACK_SETTER` 宏，用于方便地设置各种回调函数。这些回调函数允许嵌入器在 V8 虚拟机内部发生特定事件时（例如，致命错误、内存不足、Wasm 模块加载等）接收通知或进行干预。
   -  涵盖了错误处理、代码生成修改、WebAssembly 相关回调等。

4. **条件特性安装:**
   -  `InstallConditionalFeatures()` 方法允许在指定的 JavaScript 上下文中安装一些有条件的特性，例如 WebAssembly 的支持。

5. **堆内存管理回调:**
   -  提供了添加和移除近堆限制回调的方法 (`AddNearHeapLimitCallback`, `RemoveNearHeapLimitCallback`)，允许嵌入器在堆内存接近限制时收到通知。
   -  `AutomaticallyRestoreInitialHeapLimit()` 方法允许 V8 自动恢复初始堆大小限制。

6. **Isolate 状态查询:**
   -  `IsDead()` 方法用于检查 Isolate 是否已经死亡（例如，由于致命错误）。
   -  `IsInUse()` 方法用于检查 Isolate 是否正在被使用。

7. **消息监听器:**
   -  提供了添加和移除消息监听器的方法 (`AddMessageListener`, `RemoveMessageListeners`)。消息监听器用于接收 V8 产生的消息，例如错误和警告。

8. **安全和调试支持:**
   -  `SetFailedAccessCheckCallbackFunction()` 用于设置访问检查失败时的回调。
   -  `SetCaptureStackTraceForUncaughtExceptions()` 用于控制是否捕获未捕获异常的堆栈跟踪。

9. **外部资源访问:**
   -  `VisitExternalResources()` 方法允许访问与 Isolate 关联的外部资源。

10. **Atomics 支持:**
    - `SetAllowAtomicsWait()` 方法控制是否允许使用 `Atomics.wait()`。

11. **国际化支持:**
    - 提供了日期和本地化配置变更通知 (`DateTimeConfigurationChangeNotification`, `LocaleConfigurationChangeNotification`)，以及获取默认本地化信息的方法 (`GetDefaultLocale()`)。

12. **ETW 支持 (Windows):**
    -  `SetFilterETWSessionByURLCallback()` 方法用于设置基于 URL 过滤 ETW 会话的回调（仅限 Windows）。

13. **对象类型判断:**
    - `Object::IsCodeLike()` 方法用于判断一个对象是否像代码对象。

14. **微任务队列管理:**
    - 提供了创建微任务队列的方法 (`MicrotaskQueue::New`) 以及管理微任务作用域的类 (`MicrotasksScope`)，允许嵌入器控制微任务的执行。

15. **字符串处理工具:**
    - 提供了 `String::Utf8Value` 和 `String::Value` 类，用于方便地将 V8 的字符串对象转换为 C++ 的 UTF-8 或 UTF-16 字符串。
    - `String::ValueView` 提供了对 V8 字符串的只读视图，避免不必要的拷贝。

16. **异常处理:**
    - 提供了创建各种标准 JavaScript 错误对象（例如 `RangeError`, `TypeError`）的便捷方法。
    - `Exception::CreateMessage()` 用于从异常对象创建错误消息。
    - `Exception::GetStackTrace()` 用于获取异常的堆栈跟踪信息。
    - `Exception::CaptureStackTrace()` 用于手动捕获堆栈跟踪到对象中。

17. **对象属性预览:**
    - `Object::PreviewEntries()` 方法用于获取类似 Map 或 Set 对象的条目预览。

18. **CPU Profiler 集成:**
    - 提供了与 CPU Profiler 相关的类和方法 (`CpuProfileNode`, `CpuProfile`, `CpuProfiler`)，允许嵌入器启动、停止和访问 CPU 性能分析数据。包括获取函数名、脚本信息、行号、列号、命中次数、子节点等。
    - 提供了设置采样间隔、使用精确采样、序列化 Profile 数据等功能。

19. **代码事件跟踪:**
    -  定义了 `CodeEvent` 类，用于表示代码执行事件，包含代码起始地址、大小、函数名、脚本信息等。

**关于其他指令的回答:**

* **如果 v8/src/api/api.cc 以 .tq 结尾，那它是个 v8 torque 源代码:**
  代码片段的文件名是 `api.cc`，因此它不是 Torque 源代码。Torque 源代码文件通常以 `.tq` 结尾。

* **如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

   ```javascript
   // 获取代码范围 (尽管 JS 中无法直接获取，但这是 V8 内部用于管理代码内存的概念)
   // console.log("V8 代码起始地址:", ...); // 无法直接获取

   // 获取 JavaScript 执行入口 (内部使用，JS 中无法直接访问)

   // 设置错误处理回调 (例如在 Node.js 中)
   process.on('uncaughtException', (err) => {
     console.error('捕获到未处理的异常:', err);
   });

   // 设置内存不足回调 (在某些嵌入环境或使用特定 API 时可能涉及)

   // 安装条件特性 (WebAssembly 是 V8 的一项特性)
   // (在 JS 中，可以直接使用 WebAssembly API)
   WebAssembly.instantiateStreaming(fetch('module.wasm'))
     .then(results => {
       // ...
     });

   // 堆内存管理回调 (JS 中通常通过 `performance.memory` 观察)
   // console.log(performance.memory);

   // Isolate 状态查询 (JS 中无法直接访问 Isolate 的状态)

   // 消息监听器 (可以使用 `process.on('warning', ...)` 监听警告)
   process.on('warning', (warning) => {
     console.warn('警告:', warning.name, warning.message);
   });

   // 安全和调试支持 (例如，设置访问拦截器)
   // const obj = {};
   // Object.defineProperty(obj, 'x', {
   //   get() {
   //     console.log('访问了 x 属性');
   //     return this._x;
   //   },
   //   set(value) {
   //     console.log('设置了 x 属性:', value);
   //     this._x = value;
   //   }
   // });

   // 外部资源访问 (JS 可以访问全局对象、DOM 等外部资源)

   // Atomics 支持
   // const sab = new SharedArrayBuffer(1024);
   // const int32Array = new Int32Array(sab);
   // Atomics.wait(int32Array, 0, 0);

   // 国际化支持
   const now = new Date();
   console.log(now.toLocaleDateString('zh-CN'));

   // CPU Profiler (可以使用 Node.js 的 profiler)
   // node --inspect profiler.js

   // 异常处理
   try {
     throw new Error('Something went wrong!');
   } catch (e) {
     console.error(e.stack);
   }

   // 微任务
   queueMicrotask(() => {
     console.log('这是一个微任务');
   });
   ```

* **如果有代码逻辑推理，请给出假设输入与输出:**

   **方法:** `size_t Isolate::CopyCodePages(size_t capacity, MemoryRange* code_pages_out)`

   **假设输入:**
   - `capacity`: 2
   - `code_pages` 内部向量大小为 5，包含以下 `MemoryRange` 对象（简化表示）：
     ```
     [{start: 0x1000, length_in_bytes: 4096},
      {start: 0x2000, length_in_bytes: 4096},
      {start: 0x3000, length_in_bytes: 4096},
      {start: 0x4000, length_in_bytes: 4096},
      {start: 0x5000, length_in_bytes: 4096}]
     ```
   - `code_pages_out` 是一个预先分配好的 `MemoryRange` 数组，大小至少为 `capacity`。

   **输出:**
   - 函数返回值为 `5` (原始 `code_pages` 的大小)。
   - `code_pages_out` 数组的内容为：
     ```
     [{start: 0x1000, length_in_bytes: 4096},
      {start: 0x2000, length_in_bytes: 4096}]
     ```
   - 只有前 `capacity` 个元素被复制到 `code_pages_out` 中。

* **如果涉及用户常见的编程错误，请举例说明:**

   1. **`CopyCodePages` 缓冲区溢出:** 用户可能分配的 `code_pages_out` 缓冲区大小 `capacity` 小于实际的代码页数量，导致缓冲区溢出。

      ```c++
      // 假设 Isolate 中有 5 个代码页
      size_t capacity = 3;
      MemoryRange code_pages_out[capacity];
      isolate->CopyCodePages(capacity, code_pages_out); // 潜在的缓冲区溢出
      ```

   2. **`String::Utf8Value` 使用不当:** 用户可能忘记检查 `Utf8Value` 是否成功创建（例如，当传入的对象无法转换为字符串时）。

      ```c++
      Local<Value> nonStringValue = Undefined(isolate);
      String::Utf8Value utf8(isolate, nonStringValue);
      if (utf8.length() > 0) { // 错误：length() 可能未初始化或指向无效内存
        // ...
      }
      ```

   3. **错误地假设微任务的执行顺序:**  用户可能错误地认为微任务会在当前宏任务的特定时间点立即执行，而忽略了微任务队列的特性。

      ```javascript
      console.log('开始');

      Promise.resolve().then(() => {
        console.log('Promise 微任务');
      });

      queueMicrotask(() => {
        console.log('queueMicrotask 微任务');
      });

      console.log('结束');
      // 输出顺序可能是： 开始 -> 结束 -> Promise 微任务 -> queueMicrotask 微任务
      // 而不是： 开始 -> Promise 微任务 -> queueMicrotask 微任务 -> 结束
      ```

**这是第14部分，共15部分，请归纳一下它的功能:**

考虑到这是 `v8/src/api/api.cc` 的倒数第二部分，可以推断出整个 `api.cc` 文件定义了 V8 引擎提供给外部嵌入器的核心 C++ API。 这第14部分主要关注于 `v8::Isolate` 实例的管理和与其相关的核心功能，涵盖了内存管理、JavaScript 执行控制、错误处理、WebAssembly 集成、微任务、字符串处理、异常处理、性能分析等方面。 结合上下文来看，`Isolate` 类是 V8 提供的最核心的抽象之一，它代表了一个独立的 JavaScript 虚拟机实例，这段代码展示了如何管理和配置这个实例的各种行为和资源。

Prompt: 
```
这是目录为v8/src/api/api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第14部分，共15部分，请归纳一下它的功能

"""
 = reinterpret_cast<i::Isolate*>(this);
  const base::AddressRegion& code_region = i_isolate->heap()->code_region();
  *start = reinterpret_cast<void*>(code_region.begin());
  *length_in_bytes = code_region.size();
}

void Isolate::GetEmbeddedCodeRange(const void** start,
                                   size_t* length_in_bytes) {
  // Note, we should return the embedded code rande from the .text section here.
  i::EmbeddedData d = i::EmbeddedData::FromBlob();
  *start = reinterpret_cast<const void*>(d.code());
  *length_in_bytes = d.code_size();
}

JSEntryStubs Isolate::GetJSEntryStubs() {
  JSEntryStubs entry_stubs;

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  std::array<std::pair<i::Builtin, JSEntryStub*>, 3> stubs = {
      {{i::Builtin::kJSEntry, &entry_stubs.js_entry_stub},
       {i::Builtin::kJSConstructEntry, &entry_stubs.js_construct_entry_stub},
       {i::Builtin::kJSRunMicrotasksEntry,
        &entry_stubs.js_run_microtasks_entry_stub}}};
  for (auto& pair : stubs) {
    i::Tagged<i::Code> js_entry = i_isolate->builtins()->code(pair.first);
    pair.second->code.start =
        reinterpret_cast<const void*>(js_entry->instruction_start());
    pair.second->code.length_in_bytes = js_entry->instruction_size();
  }

  return entry_stubs;
}

size_t Isolate::CopyCodePages(size_t capacity, MemoryRange* code_pages_out) {
#if !defined(V8_TARGET_ARCH_64_BIT) && !defined(V8_TARGET_ARCH_ARM)
  // Not implemented on other platforms.
  UNREACHABLE();
#else

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  std::vector<MemoryRange>* code_pages = i_isolate->GetCodePages();

  DCHECK_NOT_NULL(code_pages);

  // Copy as many elements into the output vector as we can. If the
  // caller-provided buffer is not big enough, we fill it, and the caller can
  // provide a bigger one next time. We do it this way because allocation is not
  // allowed in signal handlers.
  size_t limit = std::min(capacity, code_pages->size());
  for (size_t i = 0; i < limit; i++) {
    code_pages_out[i] = code_pages->at(i);
  }
  return code_pages->size();
#endif
}

#define CALLBACK_SETTER(ExternalName, Type, InternalName)        \
  void Isolate::Set##ExternalName(Type callback) {               \
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this); \
    i_isolate->set_##InternalName(callback);                     \
  }

CALLBACK_SETTER(FatalErrorHandler, FatalErrorCallback, exception_behavior)
CALLBACK_SETTER(OOMErrorHandler, OOMErrorCallback, oom_behavior)
CALLBACK_SETTER(ModifyCodeGenerationFromStringsCallback,
                ModifyCodeGenerationFromStringsCallback2,
                modify_code_gen_callback)
CALLBACK_SETTER(AllowWasmCodeGenerationCallback,
                AllowWasmCodeGenerationCallback, allow_wasm_code_gen_callback)

CALLBACK_SETTER(WasmModuleCallback, ExtensionCallback, wasm_module_callback)
CALLBACK_SETTER(WasmInstanceCallback, ExtensionCallback, wasm_instance_callback)

CALLBACK_SETTER(WasmStreamingCallback, WasmStreamingCallback,
                wasm_streaming_callback)

CALLBACK_SETTER(WasmAsyncResolvePromiseCallback,
                WasmAsyncResolvePromiseCallback,
                wasm_async_resolve_promise_callback)

CALLBACK_SETTER(WasmLoadSourceMapCallback, WasmLoadSourceMapCallback,
                wasm_load_source_map_callback)

CALLBACK_SETTER(WasmImportedStringsEnabledCallback,
                WasmImportedStringsEnabledCallback,
                wasm_imported_strings_enabled_callback)

CALLBACK_SETTER(WasmJSPIEnabledCallback, WasmJSPIEnabledCallback,
                wasm_jspi_enabled_callback)

CALLBACK_SETTER(SharedArrayBufferConstructorEnabledCallback,
                SharedArrayBufferConstructorEnabledCallback,
                sharedarraybuffer_constructor_enabled_callback)

// TODO(42203853): Remove this after the deprecated API is removed. Right now,
// the embedder can still set the callback, but it's never called.
CALLBACK_SETTER(JavaScriptCompileHintsMagicEnabledCallback,
                JavaScriptCompileHintsMagicEnabledCallback,
                compile_hints_magic_enabled_callback)

void Isolate::InstallConditionalFeatures(Local<Context> context) {
  v8::HandleScope handle_scope(this);
  v8::Context::Scope context_scope(context);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  if (i_isolate->is_execution_terminating()) return;
  i_isolate->InstallConditionalFeatures(Utils::OpenHandle(*context));
  if (i_isolate->has_exception()) return;
#if V8_ENABLE_WEBASSEMBLY
  i::WasmJs::InstallConditionalFeatures(i_isolate, Utils::OpenHandle(*context));
#endif  // V8_ENABLE_WEBASSEMBLY
}

void Isolate::AddNearHeapLimitCallback(v8::NearHeapLimitCallback callback,
                                       void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->AddNearHeapLimitCallback(callback, data);
}

void Isolate::RemoveNearHeapLimitCallback(v8::NearHeapLimitCallback callback,
                                          size_t heap_limit) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->RemoveNearHeapLimitCallback(callback, heap_limit);
}

void Isolate::AutomaticallyRestoreInitialHeapLimit(double threshold_percent) {
  DCHECK_GT(threshold_percent, 0.0);
  DCHECK_LT(threshold_percent, 1.0);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->AutomaticallyRestoreInitialHeapLimit(threshold_percent);
}

bool Isolate::IsDead() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->IsDead();
}

bool Isolate::AddMessageListener(MessageCallback that, Local<Value> data) {
  return AddMessageListenerWithErrorLevel(that, kMessageError, data);
}

bool Isolate::AddMessageListenerWithErrorLevel(MessageCallback that,
                                               int message_levels,
                                               Local<Value> data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  i::Handle<i::ArrayList> list = i_isolate->factory()->message_listeners();
  i::DirectHandle<i::FixedArray> listener =
      i_isolate->factory()->NewFixedArray(3);
  i::DirectHandle<i::Foreign> foreign =
      i_isolate->factory()->NewForeign<internal::kMessageListenerTag>(
          FUNCTION_ADDR(that));
  listener->set(0, *foreign);
  listener->set(1, data.IsEmpty()
                       ? i::ReadOnlyRoots(i_isolate).undefined_value()
                       : *Utils::OpenDirectHandle(*data));
  listener->set(2, i::Smi::FromInt(message_levels));
  list = i::ArrayList::Add(i_isolate, list, listener);
  i_isolate->heap()->SetMessageListeners(*list);
  return true;
}

void Isolate::RemoveMessageListeners(MessageCallback that) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::ArrayList> listeners = i_isolate->heap()->message_listeners();
  for (int i = 0; i < listeners->length(); i++) {
    if (i::IsUndefined(listeners->get(i), i_isolate)) {
      continue;  // skip deleted ones
    }
    i::Tagged<i::FixedArray> listener =
        i::Cast<i::FixedArray>(listeners->get(i));
    i::Tagged<i::Foreign> callback_obj = i::Cast<i::Foreign>(listener->get(0));
    if (callback_obj->foreign_address<internal::kMessageListenerTag>() ==
        FUNCTION_ADDR(that)) {
      listeners->set(i, i::ReadOnlyRoots(i_isolate).undefined_value());
    }
  }
}

void Isolate::SetFailedAccessCheckCallbackFunction(
    FailedAccessCheckCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetFailedAccessCheckCallback(callback);
}

void Isolate::SetCaptureStackTraceForUncaughtExceptions(
    bool capture, int frame_limit, StackTrace::StackTraceOptions options) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetCaptureStackTraceForUncaughtExceptions(capture, frame_limit,
                                                       options);
}

void Isolate::VisitExternalResources(ExternalResourceVisitor* visitor) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->VisitExternalResources(visitor);
}

bool Isolate::IsInUse() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->IsInUse();
}

void Isolate::SetAllowAtomicsWait(bool allow) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->set_allow_atomics_wait(allow);
}

void v8::Isolate::DateTimeConfigurationChangeNotification(
    TimeZoneDetection time_zone_detection) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  API_RCS_SCOPE(i_isolate, Isolate, DateTimeConfigurationChangeNotification);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i_isolate->date_cache()->ResetDateCache(
      static_cast<base::TimezoneCache::TimeZoneDetection>(time_zone_detection));
#ifdef V8_INTL_SUPPORT
  i_isolate->clear_cached_icu_object(
      i::Isolate::ICUObjectCacheType::kDefaultSimpleDateFormat);
  i_isolate->clear_cached_icu_object(
      i::Isolate::ICUObjectCacheType::kDefaultSimpleDateFormatForTime);
  i_isolate->clear_cached_icu_object(
      i::Isolate::ICUObjectCacheType::kDefaultSimpleDateFormatForDate);
#endif  // V8_INTL_SUPPORT
}

void v8::Isolate::LocaleConfigurationChangeNotification() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  API_RCS_SCOPE(i_isolate, Isolate, LocaleConfigurationChangeNotification);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

#ifdef V8_INTL_SUPPORT
  i_isolate->ResetDefaultLocale();
#endif  // V8_INTL_SUPPORT
}

std::string Isolate::GetDefaultLocale() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

#ifdef V8_INTL_SUPPORT
  return i_isolate->DefaultLocale();
#else
  return std::string();
#endif
}

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
void Isolate::SetFilterETWSessionByURLCallback(
    FilterETWSessionByURLCallback callback) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetFilterETWSessionByURLCallback(callback);
}
#endif  // V8_OS_WIN && V8_ENABLE_ETW_STACK_WALKING

bool v8::Object::IsCodeLike(v8::Isolate* v8_isolate) const {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, Object, IsCodeLike);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  return Utils::OpenDirectHandle(this)->IsCodeLike(i_isolate);
}

// static
std::unique_ptr<MicrotaskQueue> MicrotaskQueue::New(Isolate* v8_isolate,
                                                    MicrotasksPolicy policy) {
  auto microtask_queue =
      i::MicrotaskQueue::New(reinterpret_cast<i::Isolate*>(v8_isolate));
  microtask_queue->set_microtasks_policy(policy);
  std::unique_ptr<MicrotaskQueue> ret(std::move(microtask_queue));
  return ret;
}

MicrotasksScope::MicrotasksScope(Local<Context> v8_context,
                                 MicrotasksScope::Type type)
    : MicrotasksScope(v8_context->GetIsolate(), v8_context->GetMicrotaskQueue(),
                      type) {}

MicrotasksScope::MicrotasksScope(Isolate* v8_isolate,
                                 MicrotaskQueue* microtask_queue,
                                 MicrotasksScope::Type type)
    : i_isolate_(reinterpret_cast<i::Isolate*>(v8_isolate)),
      microtask_queue_(microtask_queue
                           ? static_cast<i::MicrotaskQueue*>(microtask_queue)
                           : i_isolate_->default_microtask_queue()),
      run_(type == MicrotasksScope::kRunMicrotasks) {
  if (run_) microtask_queue_->IncrementMicrotasksScopeDepth();
#ifdef DEBUG
  if (!run_) microtask_queue_->IncrementDebugMicrotasksScopeDepth();
#endif
}

MicrotasksScope::~MicrotasksScope() {
  if (run_) {
    microtask_queue_->DecrementMicrotasksScopeDepth();
    if (MicrotasksPolicy::kScoped == microtask_queue_->microtasks_policy() &&
        !i_isolate_->has_exception()) {
      microtask_queue_->PerformCheckpoint(
          reinterpret_cast<Isolate*>(i_isolate_));
      DCHECK_IMPLIES(i_isolate_->has_exception(),
                     i_isolate_->is_execution_terminating());
    }
  }
#ifdef DEBUG
  if (!run_) microtask_queue_->DecrementDebugMicrotasksScopeDepth();
#endif
}

// static
void MicrotasksScope::PerformCheckpoint(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto* microtask_queue = i_isolate->default_microtask_queue();
  microtask_queue->PerformCheckpoint(v8_isolate);
}

// static
int MicrotasksScope::GetCurrentDepth(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto* microtask_queue = i_isolate->default_microtask_queue();
  return microtask_queue->GetMicrotasksScopeDepth();
}

// static
bool MicrotasksScope::IsRunningMicrotasks(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto* microtask_queue = i_isolate->default_microtask_queue();
  return microtask_queue->IsRunningMicrotasks();
}

String::Utf8Value::Utf8Value(v8::Isolate* v8_isolate, v8::Local<v8::Value> obj,
                             WriteOptions options)
    : str_(nullptr), length_(0) {
  if (obj.IsEmpty()) return;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  Local<Context> context = v8_isolate->GetCurrentContext();
  ENTER_V8_BASIC(i_isolate);
  i::HandleScope scope(i_isolate);
  TryCatch try_catch(v8_isolate);
  Local<String> str;
  if (!obj->ToString(context).ToLocal(&str)) return;
  length_ = str->Utf8LengthV2(v8_isolate);
  str_ = i::NewArray<char>(length_ + 1);
  int flags = String::WriteFlags::kNullTerminate;
  if (options & REPLACE_INVALID_UTF8)
    flags |= String::WriteFlags::kReplaceInvalidUtf8;
  str->WriteUtf8V2(v8_isolate, str_, length_ + 1, flags);
}

String::Utf8Value::~Utf8Value() { i::DeleteArray(str_); }

String::Value::Value(v8::Isolate* v8_isolate, v8::Local<v8::Value> obj)
    : str_(nullptr), length_(0) {
  if (obj.IsEmpty()) return;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::HandleScope scope(i_isolate);
  Local<Context> context = v8_isolate->GetCurrentContext();
  ENTER_V8_BASIC(i_isolate);
  TryCatch try_catch(v8_isolate);
  Local<String> str;
  if (!obj->ToString(context).ToLocal(&str)) return;
  length_ = str->Length();
  str_ = i::NewArray<uint16_t>(length_ + 1);
  str->WriteV2(v8_isolate, 0, length_, str_,
               String::WriteFlags::kNullTerminate);
}

String::Value::~Value() { i::DeleteArray(str_); }

String::ValueView::ValueView(v8::Isolate* v8_isolate,
                             v8::Local<v8::String> str) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::HandleScope scope(i_isolate);
  i::Handle<i::String> i_str = Utils::OpenHandle(*str);
  i::Handle<i::String> i_flat_str = i::String::Flatten(i_isolate, i_str);

  flat_str_ = Utils::ToLocal(i_flat_str);

  i::DisallowGarbageCollectionInRelease* no_gc =
      new (no_gc_debug_scope_) i::DisallowGarbageCollectionInRelease();
  i::String::FlatContent flat_content = i_flat_str->GetFlatContent(*no_gc);
  DCHECK(flat_content.IsFlat());
  is_one_byte_ = flat_content.IsOneByte();
  length_ = flat_content.length();
  if (is_one_byte_) {
    data8_ = flat_content.ToOneByteVector().data();
  } else {
    data16_ = flat_content.ToUC16Vector().data();
  }
}

String::ValueView::~ValueView() {
  using i::DisallowGarbageCollectionInRelease;
  DisallowGarbageCollectionInRelease* no_gc =
      reinterpret_cast<DisallowGarbageCollectionInRelease*>(no_gc_debug_scope_);
  no_gc->~DisallowGarbageCollectionInRelease();
}

void String::ValueView::CheckOneByte(bool is_one_byte) const {
  if (is_one_byte) {
    Utils::ApiCheck(is_one_byte_, "v8::String::ValueView::data8",
                    "Called the one-byte accessor on a two-byte string view.");
  } else {
    Utils::ApiCheck(!is_one_byte_, "v8::String::ValueView::data16",
                    "Called the two-byte accessor on a one-byte string view.");
  }
}

#define DEFINE_ERROR(NAME, name)                                              \
  Local<Value> Exception::NAME(v8::Local<v8::String> raw_message,             \
                               v8::Local<v8::Value> raw_options) {            \
    i::Isolate* i_isolate = i::Isolate::Current();                            \
    API_RCS_SCOPE(i_isolate, NAME, New);                                      \
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);                               \
    i::Tagged<i::Object> error;                                               \
    {                                                                         \
      i::HandleScope scope(i_isolate);                                        \
      i::Handle<i::Object> options;                                           \
      if (!raw_options.IsEmpty()) {                                           \
        options = Utils::OpenHandle(*raw_options);                            \
      }                                                                       \
      auto message = Utils::OpenHandle(*raw_message);                         \
      i::Handle<i::JSFunction> constructor = i_isolate->name##_function();    \
      error = *i_isolate->factory()->NewError(constructor, message, options); \
    }                                                                         \
    return Utils::ToLocal(i::direct_handle(error, i_isolate));                \
  }

DEFINE_ERROR(RangeError, range_error)
DEFINE_ERROR(ReferenceError, reference_error)
DEFINE_ERROR(SyntaxError, syntax_error)
DEFINE_ERROR(TypeError, type_error)
DEFINE_ERROR(WasmCompileError, wasm_compile_error)
DEFINE_ERROR(WasmLinkError, wasm_link_error)
DEFINE_ERROR(WasmRuntimeError, wasm_runtime_error)
DEFINE_ERROR(Error, error)

#undef DEFINE_ERROR

Local<Message> Exception::CreateMessage(Isolate* v8_isolate,
                                        Local<Value> exception) {
  auto obj = Utils::OpenHandle(*exception);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  return Utils::MessageToLocal(
      scope.CloseAndEscape(i_isolate->CreateMessage(obj, nullptr)));
}

Local<StackTrace> Exception::GetStackTrace(Local<Value> exception) {
  auto obj = Utils::OpenHandle(*exception);
  if (!IsJSObject(*obj)) return {};
  auto js_obj = i::Cast<i::JSObject>(obj);
  i::Isolate* i_isolate = js_obj->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto stack_trace = i_isolate->GetDetailedStackTrace(js_obj);
  return Utils::StackTraceToLocal(stack_trace);
}

Maybe<bool> Exception::CaptureStackTrace(Local<Context> context,
                                         Local<Object> object) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8_NO_SCRIPT(i_isolate, context, Exception, CaptureStackTrace,
                     i::HandleScope);
  auto obj = Utils::OpenHandle(*object);
  if (!IsJSObject(*obj)) return Just(false);

  auto js_obj = i::Cast<i::JSObject>(obj);

  i::FrameSkipMode mode = i::FrameSkipMode::SKIP_FIRST;

  auto result = i::ErrorUtils::CaptureStackTrace(i_isolate, js_obj, mode,
                                                 i::Handle<i::Object>());

  i::Handle<i::Object> handle;
  has_exception = !result.ToHandle(&handle);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

v8::MaybeLocal<v8::Array> v8::Object::PreviewEntries(bool* is_key_value) {
  auto object = Utils::OpenHandle(this);
  i::Isolate* i_isolate = object->GetIsolate();
  if (i_isolate->is_execution_terminating()) return {};
  if (IsMap()) {
    *is_key_value = true;
    return Map::Cast(this)->AsArray();
  }
  if (IsSet()) {
    *is_key_value = false;
    return Set::Cast(this)->AsArray();
  }

  Isolate* v8_isolate = reinterpret_cast<Isolate*>(i_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (i::IsJSWeakCollection(*object)) {
    *is_key_value = IsJSWeakMap(*object);
    return Utils::ToLocal(i::JSWeakCollection::GetEntries(
        i::Cast<i::JSWeakCollection>(object), 0));
  }
  if (i::IsJSMapIterator(*object)) {
    auto it = i::Cast<i::JSMapIterator>(object);
    MapAsArrayKind const kind =
        static_cast<MapAsArrayKind>(it->map()->instance_type());
    *is_key_value = kind == MapAsArrayKind::kEntries;
    if (!it->HasMore()) return v8::Array::New(v8_isolate);
    return Utils::ToLocal(
        MapAsArray(i_isolate, it->table(), i::Smi::ToInt(it->index()), kind));
  }
  if (i::IsJSSetIterator(*object)) {
    auto it = i::Cast<i::JSSetIterator>(object);
    SetAsArrayKind const kind =
        static_cast<SetAsArrayKind>(it->map()->instance_type());
    *is_key_value = kind == SetAsArrayKind::kEntries;
    if (!it->HasMore()) return v8::Array::New(v8_isolate);
    return Utils::ToLocal(
        SetAsArray(i_isolate, it->table(), i::Smi::ToInt(it->index()), kind));
  }
  return v8::MaybeLocal<v8::Array>();
}

Local<String> CpuProfileNode::GetFunctionName() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  i::Isolate* i_isolate = node->isolate();
  const i::CodeEntry* entry = node->entry();
  i::DirectHandle<i::String> name =
      i_isolate->factory()->InternalizeUtf8String(entry->name());
  return ToApiHandle<String>(name);
}

const char* CpuProfileNode::GetFunctionNameStr() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  return node->entry()->name();
}

int CpuProfileNode::GetScriptId() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  const i::CodeEntry* entry = node->entry();
  return entry->script_id();
}

Local<String> CpuProfileNode::GetScriptResourceName() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  i::Isolate* i_isolate = node->isolate();
  return ToApiHandle<String>(i_isolate->factory()->InternalizeUtf8String(
      node->entry()->resource_name()));
}

const char* CpuProfileNode::GetScriptResourceNameStr() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  return node->entry()->resource_name();
}

bool CpuProfileNode::IsScriptSharedCrossOrigin() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  return node->entry()->is_shared_cross_origin();
}

int CpuProfileNode::GetLineNumber() const {
  return reinterpret_cast<const i::ProfileNode*>(this)->line_number();
}

int CpuProfileNode::GetColumnNumber() const {
  return reinterpret_cast<const i::ProfileNode*>(this)
      ->entry()
      ->column_number();
}

unsigned int CpuProfileNode::GetHitLineCount() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  return node->GetHitLineCount();
}

bool CpuProfileNode::GetLineTicks(LineTick* entries,
                                  unsigned int length) const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  return node->GetLineTicks(entries, length);
}

const char* CpuProfileNode::GetBailoutReason() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  return node->entry()->bailout_reason();
}

unsigned CpuProfileNode::GetHitCount() const {
  return reinterpret_cast<const i::ProfileNode*>(this)->self_ticks();
}

unsigned CpuProfileNode::GetNodeId() const {
  return reinterpret_cast<const i::ProfileNode*>(this)->id();
}

CpuProfileNode::SourceType CpuProfileNode::GetSourceType() const {
  return reinterpret_cast<const i::ProfileNode*>(this)->source_type();
}

int CpuProfileNode::GetChildrenCount() const {
  return static_cast<int>(
      reinterpret_cast<const i::ProfileNode*>(this)->children()->size());
}

const CpuProfileNode* CpuProfileNode::GetChild(int index) const {
  const i::ProfileNode* child =
      reinterpret_cast<const i::ProfileNode*>(this)->children()->at(index);
  return reinterpret_cast<const CpuProfileNode*>(child);
}

const CpuProfileNode* CpuProfileNode::GetParent() const {
  const i::ProfileNode* parent =
      reinterpret_cast<const i::ProfileNode*>(this)->parent();
  return reinterpret_cast<const CpuProfileNode*>(parent);
}

const std::vector<CpuProfileDeoptInfo>& CpuProfileNode::GetDeoptInfos() const {
  const i::ProfileNode* node = reinterpret_cast<const i::ProfileNode*>(this);
  return node->deopt_infos();
}

void CpuProfile::Delete() {
  i::CpuProfile* profile = reinterpret_cast<i::CpuProfile*>(this);
  i::CpuProfiler* profiler = profile->cpu_profiler();
  DCHECK_NOT_NULL(profiler);
  profiler->DeleteProfile(profile);
}

Local<String> CpuProfile::GetTitle() const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  i::Isolate* i_isolate = profile->top_down()->isolate();
  return ToApiHandle<String>(
      i_isolate->factory()->InternalizeUtf8String(profile->title()));
}

const CpuProfileNode* CpuProfile::GetTopDownRoot() const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  return reinterpret_cast<const CpuProfileNode*>(profile->top_down()->root());
}

const CpuProfileNode* CpuProfile::GetSample(int index) const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  return reinterpret_cast<const CpuProfileNode*>(profile->sample(index).node);
}

const int CpuProfileNode::kNoLineNumberInfo;
const int CpuProfileNode::kNoColumnNumberInfo;

int64_t CpuProfile::GetSampleTimestamp(int index) const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  return profile->sample(index).timestamp.since_origin().InMicroseconds();
}

StateTag CpuProfile::GetSampleState(int index) const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  return profile->sample(index).state_tag;
}

EmbedderStateTag CpuProfile::GetSampleEmbedderState(int index) const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  return profile->sample(index).embedder_state_tag;
}

int64_t CpuProfile::GetStartTime() const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  return profile->start_time().since_origin().InMicroseconds();
}

int64_t CpuProfile::GetEndTime() const {
  const i::CpuProfile* profile = reinterpret_cast<const i::CpuProfile*>(this);
  return profile->end_time().since_origin().InMicroseconds();
}

static i::CpuProfile* ToInternal(const CpuProfile* profile) {
  return const_cast<i::CpuProfile*>(
      reinterpret_cast<const i::CpuProfile*>(profile));
}

void CpuProfile::Serialize(OutputStream* stream,
                           CpuProfile::SerializationFormat format) const {
  Utils::ApiCheck(format == kJSON, "v8::CpuProfile::Serialize",
                  "Unknown serialization format");
  Utils::ApiCheck(stream->GetChunkSize() > 0, "v8::CpuProfile::Serialize",
                  "Invalid stream chunk size");
  i::CpuProfileJSONSerializer serializer(ToInternal(this));
  serializer.Serialize(stream);
}

int CpuProfile::GetSamplesCount() const {
  return reinterpret_cast<const i::CpuProfile*>(this)->samples_count();
}

CpuProfiler* CpuProfiler::New(Isolate* v8_isolate,
                              CpuProfilingNamingMode naming_mode,
                              CpuProfilingLoggingMode logging_mode) {
  return reinterpret_cast<CpuProfiler*>(new i::CpuProfiler(
      reinterpret_cast<i::Isolate*>(v8_isolate), naming_mode, logging_mode));
}

CpuProfilingOptions::CpuProfilingOptions(CpuProfilingMode mode,
                                         unsigned max_samples,
                                         int sampling_interval_us,
                                         MaybeLocal<Context> filter_context)
    : mode_(mode),
      max_samples_(max_samples),
      sampling_interval_us_(sampling_interval_us) {
  if (!filter_context.IsEmpty()) {
    Local<Context> local_filter_context = filter_context.ToLocalChecked();
    filter_context_.Reset(local_filter_context->GetIsolate(),
                          local_filter_context);
    filter_context_.SetWeak();
  }
}

void* CpuProfilingOptions::raw_filter_context() const {
  return reinterpret_cast<void*>(
      i::Cast<i::Context>(*Utils::OpenPersistent(filter_context_))
          ->native_context()
          .address());
}

void CpuProfiler::Dispose() { delete reinterpret_cast<i::CpuProfiler*>(this); }

// static
void CpuProfiler::CollectSample(Isolate* v8_isolate) {
  i::CpuProfiler::CollectSample(reinterpret_cast<i::Isolate*>(v8_isolate));
}

void CpuProfiler::SetSamplingInterval(int us) {
  DCHECK_GE(us, 0);
  return reinterpret_cast<i::CpuProfiler*>(this)->set_sampling_interval(
      base::TimeDelta::FromMicroseconds(us));
}

void CpuProfiler::SetUsePreciseSampling(bool use_precise_sampling) {
  reinterpret_cast<i::CpuProfiler*>(this)->set_use_precise_sampling(
      use_precise_sampling);
}

CpuProfilingResult CpuProfiler::Start(
    CpuProfilingOptions options,
    std::unique_ptr<DiscardedSamplesDelegate> delegate) {
  return reinterpret_cast<i::CpuProfiler*>(this)->StartProfiling(
      std::move(options), std::move(delegate));
}

CpuProfilingResult CpuProfiler::Start(
    Local<String> title, CpuProfilingOptions options,
    std::unique_ptr<DiscardedSamplesDelegate> delegate) {
  return reinterpret_cast<i::CpuProfiler*>(this)->StartProfiling(
      *Utils::OpenDirectHandle(*title), std::move(options),
      std::move(delegate));
}

CpuProfilingResult CpuProfiler::Start(Local<String> title,
                                      bool record_samples) {
  CpuProfilingOptions options(
      kLeafNodeLineNumbers,
      record_samples ? CpuProfilingOptions::kNoSampleLimit : 0);
  return reinterpret_cast<i::CpuProfiler*>(this)->StartProfiling(
      *Utils::OpenDirectHandle(*title), std::move(options));
}

CpuProfilingResult CpuProfiler::Start(Local<String> title,
                                      CpuProfilingMode mode,
                                      bool record_samples,
                                      unsigned max_samples) {
  CpuProfilingOptions options(mode, record_samples ? max_samples : 0);
  return reinterpret_cast<i::CpuProfiler*>(this)->StartProfiling(
      *Utils::OpenDirectHandle(*title), std::move(options));
}

CpuProfilingStatus CpuProfiler::StartProfiling(
    Local<String> title, CpuProfilingOptions options,
    std::unique_ptr<DiscardedSamplesDelegate> delegate) {
  return Start(title, std::move(options), std::move(delegate)).status;
}

CpuProfilingStatus CpuProfiler::StartProfiling(Local<String> title,
                                               bool record_samples) {
  return Start(title, record_samples).status;
}

CpuProfilingStatus CpuProfiler::StartProfiling(Local<String> title,
                                               CpuProfilingMode mode,
                                               bool record_samples,
                                               unsigned max_samples) {
  return Start(title, mode, record_samples, max_samples).status;
}

CpuProfile* CpuProfiler::StopProfiling(Local<String> title) {
  return reinterpret_cast<CpuProfile*>(
      reinterpret_cast<i::CpuProfiler*>(this)->StopProfiling(
          *Utils::OpenDirectHandle(*title)));
}

CpuProfile* CpuProfiler::Stop(ProfilerId id) {
  return reinterpret_cast<CpuProfile*>(
      reinterpret_cast<i::CpuProfiler*>(this)->StopProfiling(id));
}

void CpuProfiler::UseDetailedSourcePositionsForProfiling(Isolate* v8_isolate) {
  reinterpret_cast<i::Isolate*>(v8_isolate)
      ->SetDetailedSourcePositionsForProfiling(true);
}

uintptr_t CodeEvent::GetCodeStartAddress() {
  return reinterpret_cast<i::CodeEvent*>(this)->code_start_address;
}

size_t CodeEvent::GetCodeSize() {
  return reinterpret_cast<i::CodeEvent*>(this)->code_size;
}

Local<String> CodeEvent::GetFunctionName() {
  return ToApiHandle<String>(
      reinterpret_cast<i::CodeEvent*>(this)->function_name);
}

Local<String> CodeEvent::GetScriptName() {
  return ToApiHandle<String>(
      reinterpret_cast<i::CodeEvent*>(this)->script_name);
}

int CodeEvent::GetScriptLine() {
  return reinterpret_cast<i::CodeEvent*>(this)->script_line;
}

int CodeEvent::GetScriptColumn() {
  return reinterpret_cast<i::CodeEvent*>(this)->script_column;
}

CodeEventType CodeEvent::GetCodeType() {
  return reinterpret_cast<i::CodeEvent*>(this)->code_type;
}

const char* CodeEvent::GetComment() {
  return reinterpret_cast<i::CodeEvent*>(this)->comment;
}

uintptr_t CodeEvent::GetPreviousCodeStartAddress() {
  return 
"""


```