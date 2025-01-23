Response:
Let's break down the thought process for analyzing this code snippet.

1. **Initial Scan and Keyword Recognition:**  The first step is a quick scan for recognizable V8 API calls and common programming patterns. Keywords like `v8::FunctionCallbackInfo`, `Isolate`, `Context`, `Local`, `HandleScope`, `TryCatch`, `String`, `ArrayBuffer`, `Promise`, `Worker`, `SetTimeout`, `Serialize`, `Deserialize`, `Profiler`, `WriteFile`, `ReadFile`, and `Print` immediately jump out. These hint at the core functionalities being exposed by `d8`.

2. **Categorization by Function Callbacks:** The code is structured around a series of functions that are called as callbacks from JavaScript. Organizing the analysis around these callbacks makes sense. We can treat each `void Shell::FunctionName(...)` as a distinct feature.

3. **Inferring Functionality from Names:** The function names are generally descriptive. For example, `SetDebugDelegate`, `SetPromiseHooks`, `SerializerSerialize`, `SerializerDeserialize`, `ProfilerSetOnProfileEndListener`, `Print`, `WriteFile`, `ReadFile`, `ExecuteFile`, `SetTimeout`, `WorkerNew`, `WorkerPostMessage`, `WorkerGetMessage`, `WorkerOnMessageGetter/Setter`, `WorkerTerminate`, `Quit`, `Version`, and `ReportException` clearly suggest their purpose.

4. **Analyzing Individual Functions:** For each function, we look at the parameters and the V8 API calls used within.

    * **Simple Functions:** Some functions are straightforward. `SetDebugDelegate` likely disables a debug delegate. `Version` returns the V8 version. `Print`, `PrintErr`, and `WriteStdout` handle output.

    * **Functions with Logic:** Others have more complex logic. `SetPromiseHooks` manages promise lifecycle callbacks (though it's conditionally compiled). `SerializerSerialize` and `SerializerDeserialize` handle object serialization/deserialization using `ValueSerializer` and `ValueDeserializer`. `ProfilerSetOnProfileEndListener` sets up a callback for profiler completion.

    * **File I/O:** `WriteFile` has two modes: writing binary data from an `ArrayBuffer` or writing strings. `ReadFile` reads the content of a file.

    * **Execution and Timing:** `ExecuteFile` runs JavaScript code from a file. `SetTimeout` implements the `setTimeout` functionality using `v8::Task`.

    * **Workers:** The `Worker` related functions (`WorkerNew`, `WorkerPostMessage`, `WorkerGetMessage`, `WorkerOnMessageGetter/Setter`, `WorkerTerminate`, `WorkerTerminateAndWait`) expose the Web Workers API for creating and managing background threads. Pay attention to the serialization/deserialization involved in message passing.

    * **Error Handling:**  The use of `TryCatch` in `WriteToFile` and `TriggerOnProfileEndListener` indicates error handling for specific operations.

5. **Identifying JavaScript Relationships:**  Once the basic functionality of a C++ function is understood, think about how it relates to JavaScript. This often involves looking at what arguments are passed and what the return value is. For instance:

    * `Shell::Print` directly corresponds to the `print()` function in JavaScript.
    * `Shell::SetTimeout` implements the global `setTimeout()` function.
    * The `Worker` functions mirror the Web Workers API in JavaScript.
    * `SerializerSerialize` and `SerializerDeserialize` enable structured cloning.

6. **Considering Edge Cases and Errors:** Look for conditional checks, error handling, and potential failure points. The code explicitly checks for `IsFunction`, `IsString`, `IsArrayBuffer`, etc., suggesting potential type errors. The `WriteFile` function checks for file opening errors. The `correctness_fuzzer_suppressions` flag indicates features that might be problematic in certain testing scenarios.

7. **Code Logic Inference (with Examples):** For functions with more complex logic (like serialization or message passing), create simple examples to illustrate the input and output. For serialization, show how a JavaScript object is transformed into a binary representation and back. For workers, demonstrate sending a message and receiving it in the worker thread.

8. **Common Programming Errors:** Think about typical mistakes JavaScript developers make that these functions might be susceptible to. Incorrect argument types, file I/O errors, and issues with asynchronous operations (like `setTimeout` or workers) are common.

9. **Torque Check:**  The prompt specifically asks about Torque. The `.cc` extension immediately tells us it's *not* a Torque file.

10. **Summarization:** Finally, synthesize the individual function analyses into a high-level summary of the overall functionality provided by `d8.cc`. Emphasize the core purposes: running JavaScript, interacting with the environment (file system, console), debugging, profiling, and concurrency.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "Maybe `SetPromiseHooks` is always available."  **Correction:** Notice the `#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS` and the error message if the flag is not defined. This means it's a build-time option.
* **Initial thought:** "The `WriteFile` function always writes strings." **Correction:** Notice the special handling for `ArrayBuffer` and `ArrayBufferView` for binary writes.
* **When analyzing workers:**  Pay close attention to how messages are passed between the main thread and the worker thread using serialization. The `CheckMessageFromWorkerTask` is crucial for understanding the asynchronous nature of worker communication. The `CleanUpWorkerTask` highlights the importance of resource management.

By following these steps and being attentive to details, we can effectively analyze and understand the functionality of this C++ code snippet.
`v8/src/d8/d8.cc` 的这段代码是 V8 JavaScript 引擎的 `d8` 工具的一部分，它是一个命令行工具，可以用来执行 JavaScript 代码。这段代码主要集中在以下功能：

**1. 调试控制 (SetDebugDelegate):**

*   允许设置一个调试代理，但在这段代码中，它被用来移除已有的调试代理 (`nullptr`)。
*   **JavaScript 关联:** 这与 JavaScript 的调试功能相关，但这段代码是移除调试功能。

**2. Promise 钩子 (SetPromiseHooks):**

*   允许设置 Promise 的生命周期钩子函数，例如 Promise 创建时、状态改变时等。
*   出于某些优化或测试目的，这个功能可能被禁用。
*   **JavaScript 关联:** 这直接关联到 JavaScript 的 Promise API。
    ```javascript
    // 假设 d8 提供了访问这些钩子的方法
    d8.promise.setHooks(
      (resolve) => { console.log("Promise created"); }, // init
      (resolve) => { console.log("Promise resolved"); }, // resolve
      (reject) => { console.log("Promise rejected"); },  // reject
      (asyncContext) => { console.log("Async context created"); } // async
    );

    new Promise((resolve) => resolve());
    ```
*   **条件编译:** 请注意 `#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS`，这意味着这个功能可能需要在编译时启用。

**3. 序列化与反序列化 (SerializerSerialize, SerializerDeserialize):**

*   `SerializerSerialize`: 将 JavaScript 值序列化为二进制 ArrayBuffer。
*   `SerializerDeserialize`: 将二进制 ArrayBuffer 反序列化为 JavaScript 值。
*   这对于在不同的 V8 实例之间传递数据非常有用。
*   **JavaScript 关联:** 与 JavaScript 的结构化克隆 (Structured Cloning Algorithm) 的概念相关。
    ```javascript
    const obj = { a: 1, b: "hello" };
    const buffer = d8.serializer.serialize(obj);
    console.log(buffer instanceof ArrayBuffer); // 输出 true
    const deserializedObj = d8.serializer.deserialize(buffer);
    console.log(deserializedObj.a); // 输出 1
    ```
*   **代码逻辑推理:**
    *   **假设输入 (Serialize):** JavaScript 对象 `{x: 10, y: "test"}`
    *   **输出 (Serialize):** 一个表示该对象的二进制 `ArrayBuffer`。具体的二进制内容取决于 V8 的序列化格式。
    *   **假设输入 (Deserialize):** 上一步生成的 `ArrayBuffer`。
    *   **输出 (Deserialize):** JavaScript 对象 `{x: 10, y: "test"}`。

**4. 性能分析回调 (ProfilerSetOnProfileEndListener, TriggerOnProfileEndListener):**

*   `ProfilerSetOnProfileEndListener`: 允许设置一个在性能分析结束时调用的 JavaScript 函数。
*   `TriggerOnProfileEndListener`:  在 C++ 代码中触发这个回调，传递性能分析数据。
*   这允许在性能分析完成后，在 JavaScript 中处理分析结果。
*   **JavaScript 关联:** 与 V8 的性能分析器相关。
    ```javascript
    d8.profiler.setOnProfileEndListener(function(profileData) {
      console.log("Profile data received:", profileData);
    });

    // 启动性能分析 (通常通过 d8 的命令行参数或内部机制)
    // ...
    // 性能分析结束，d8 会调用上面设置的回调函数
    ```

**5. 文件和标准输出/错误流操作 (WriteToFile, WriteAndFlush, Print, PrintErr, WriteStdout, WriteFile, ReadFile):**

*   提供了一系列函数，用于向标准输出、标准错误流和文件中写入数据，以及从文件中读取数据。
*   `WriteFile` 尤其有趣，它支持写入字符串和二进制数据 (如果第二个参数是 `ArrayBuffer` 或 `ArrayBufferView`)。
*   `ReadFile` 用于读取文件内容。
*   **JavaScript 关联:**  模拟了 Node.js 中类似的文件系统操作和控制台输出。
    ```javascript
    d8.print("Hello, world!"); // 输出到标准输出
    d8.writeFile("output.txt", "Some text");
    const fileContent = d8.readFile("output.txt");
    console.log(fileContent); // 输出 "Some text"

    const binaryData = new Uint8Array([65, 66, 67]).buffer;
    d8.writeFile("binary.dat", binaryData);
    const readBinary = d8.readFile("binary.dat", "binary");
    console.log(readBinary instanceof ArrayBuffer); // 输出 true
    ```
*   **用户常见的编程错误:**
    *   在 `WriteFile` 中，忘记处理可能的文件打开错误。
    *   在 `ReadFile` 中，假设文件总是存在，而没有处理文件不存在的情况。
    *   `WriteFile` 二进制写入时，类型传递错误，例如将字符串当作 `ArrayBuffer` 传入。
    *   **示例 (WriteFile 错误):**
        ```javascript
        // 假设文件不存在或权限不足
        d8.writeFile("/non/existent/path.txt", "some data"); // 可能会抛出异常或 d8 崩溃
        ```
    *   **示例 (ReadFile 错误):**
        ```javascript
        const content = d8.readFile("non_existent_file.txt"); // 可能会返回 undefined 或抛出异常
        if (content === undefined) {
          console.error("Failed to read file.");
        }
        ```

**6. 执行文件 (ExecuteFile):**

*   允许执行指定的 JavaScript 文件。
*   **JavaScript 关联:** 这是 `d8` 工具的核心功能之一。
    ```bash
    # 假设有一个名为 script.js 的文件
    # 在 d8 中执行该文件
    d8.executeFile("script.js");
    ```

**7. 设置超时 (SetTimeout):**

*   提供了类似于 JavaScript `setTimeout` 的功能，用于在指定延迟后执行回调函数。
*   **JavaScript 关联:**  实现了标准的 JavaScript 定时器 API。
    ```javascript
    d8.setTimeout(function() {
      d8.print("Delayed message");
    }, 1000); // 1秒后输出
    ```

**8. Web Workers 支持 (WorkerNew, WorkerPostMessage, WorkerGetMessage, WorkerOnMessageGetter/Setter, WorkerTerminate, WorkerTerminateAndWait):**

*   提供创建、管理和与 Web Workers 通信的功能，允许在独立的线程中执行 JavaScript 代码。
*   `WorkerNew`: 创建一个新的 Worker。
*   `WorkerPostMessage`: 向 Worker 发送消息。
*   `WorkerGetMessage`: 从 Worker 接收消息。
*   `WorkerOnMessageGetter/Setter`: 设置 Worker 的 `onmessage` 事件处理函数。
*   `WorkerTerminate`: 终止 Worker。
*   `WorkerTerminateAndWait`: 终止 Worker 并等待其线程结束。
*   **JavaScript 关联:**  实现了 Web Workers API。
    ```javascript
    const worker = new Worker({ type: 'string' }, 'console.log("Hello from worker");');
    worker.onmessage = function(event) {
      console.log("Received message:", event.data);
    };
    worker.postMessage("Message to worker");
    worker.terminate();
    ```
*   **代码逻辑推理 (Worker Message Passing):**
    *   **假设输入 (主线程):**  `worker.postMessage({data: 123});`
    *   **输出 (Worker 线程):**  Worker 的 `onmessage` 事件被触发，`event.data` 的值为 `{data: 123}`。反之亦然。

**9. 退出 (QuitOnce, Terminate, Quit):**

*   提供了退出 `d8` 工具的功能。
*   `Quit`: 正常退出。
*   `Terminate`: 立即终止 JavaScript 执行。
*   `QuitOnce`: 确保 `Quit` 只被调用一次。
*   **JavaScript 关联:**  允许 JavaScript 代码控制 `d8` 的生命周期。
    ```javascript
    d8.quit(0); // 正常退出，返回码 0
    ```

**10. 版本信息 (Version):**

*   返回 V8 引擎的版本号。
*   **JavaScript 关联:**  提供 V8 引擎的信息。
    ```javascript
    console.log("V8 Version:", d8.version());
    ```

**11. 异常报告 (ReportException):**

*   当 JavaScript 代码抛出未捕获的异常时，`d8` 使用此函数来格式化并打印错误信息，包括文件名、行号、错误消息和堆栈跟踪。
*   **JavaScript 关联:**  这是 `d8` 如何向用户展示 JavaScript 运行时错误的方式。
*   **用户常见的编程错误:**  所有会导致 JavaScript 运行时异常的错误，例如 `TypeError`, `ReferenceError`, `SyntaxError` 等。

**归纳一下它的功能:**

作为 `d8` 工具的一部分，这段代码提供了一系列底层的 C++ 函数，这些函数被暴露给 JavaScript 环境，用于：

*   **控制 V8 引擎的行为:**  例如设置调试代理、Promise 钩子。
*   **提供与外部环境交互的能力:**  例如文件读写、标准输入输出。
*   **支持并发:** 通过 Web Workers 实现多线程。
*   **提供实用工具:**  例如序列化、性能分析。
*   **控制 `d8` 工具的生命周期:**  例如退出。
*   **报告错误:**  格式化并显示 JavaScript 运行时错误。

这段代码是 `d8` 工具连接 V8 引擎核心功能和 JavaScript 环境的关键桥梁，使得开发者可以使用 JavaScript 与操作系统进行一定程度的交互，进行调试、性能分析以及构建并发应用。

**关于 `.tq` 结尾:**

`v8/src/d8/d8.cc` 以 `.cc` 结尾，表明它是 C++ 源代码文件，而不是 Torque 源代码文件。Torque 文件通常以 `.tq` 结尾。

### 提示词
```
这是目录为v8/src/d8/d8.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/d8/d8.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
fo) {
  v8::debug::SetDebugDelegate(info.GetIsolate(), nullptr);
}

void Shell::SetPromiseHooks(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  if (i::v8_flags.correctness_fuzzer_suppressions) {
    // Setting promise hooks dynamically has unexpected timing side-effects
    // with certain promise optimizations. We might not get all callbacks for
    // previously scheduled Promises or optimized code-paths that skip Promise
    // creation.
    ThrowError(isolate,
               "d8.promise.setHooks is disabled with "
               "--correctness-fuzzer-suppressions");
    return;
  }
#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  Local<Context> context = isolate->GetCurrentContext();
  HandleScope handle_scope(isolate);

  context->SetPromiseHooks(
      info[0]->IsFunction() ? info[0].As<Function>() : Local<Function>(),
      info[1]->IsFunction() ? info[1].As<Function>() : Local<Function>(),
      info[2]->IsFunction() ? info[2].As<Function>() : Local<Function>(),
      info[3]->IsFunction() ? info[3].As<Function>() : Local<Function>());

  info.GetReturnValue().Set(v8::Undefined(isolate));
#else   // V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  ThrowError(isolate,
             "d8.promise.setHooks is disabled due to missing build flag "
             "v8_enabale_javascript_in_promise_hooks");
#endif  // V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
}

void Shell::SerializerSerialize(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  HandleScope handle_scope(isolate);
  Local<Context> context = isolate->GetCurrentContext();

  ValueSerializer serializer(isolate);
  serializer.WriteHeader();
  for (int i = 0; i < info.Length(); i++) {
    bool ok;
    if (!serializer.WriteValue(context, info[i]).To(&ok)) return;
  }
  Local<v8::ArrayBuffer> buffer;
  {
    std::pair<uint8_t*, size_t> pair = serializer.Release();
    buffer = ArrayBuffer::New(isolate, pair.second);
    memcpy(buffer->GetBackingStore()->Data(), pair.first, pair.second);
    free(pair.first);
  }
  info.GetReturnValue().Set(buffer);
}

void Shell::SerializerDeserialize(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  HandleScope handle_scope(isolate);
  Local<Context> context = isolate->GetCurrentContext();

  if (!info[0]->IsArrayBuffer()) {
    ThrowError(isolate, "Can only deserialize from an ArrayBuffer");
    return;
  }
  std::shared_ptr<BackingStore> backing_store =
      info[0].As<ArrayBuffer>()->GetBackingStore();
  ValueDeserializer deserializer(
      isolate, static_cast<const uint8_t*>(backing_store->Data()),
      backing_store->ByteLength());
  bool ok;
  if (!deserializer.ReadHeader(context).To(&ok)) return;
  Local<Value> result;
  if (!deserializer.ReadValue(context).ToLocal(&result)) return;
  info.GetReturnValue().Set(result);
}

void Shell::ProfilerSetOnProfileEndListener(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  HandleScope handle_scope(isolate);
  if (!info[0]->IsFunction()) {
    ThrowError(isolate, "The OnProfileEnd listener has to be a function");
    return;
  }
  base::MutexGuard lock_guard(&profiler_end_callback_lock_);
  profiler_end_callback_[isolate] =
      std::make_pair(Global<Function>(isolate, info[0].As<Function>()),
                     Global<Context>(isolate, isolate->GetCurrentContext()));
}

bool Shell::HasOnProfileEndListener(Isolate* isolate) {
  base::MutexGuard lock_guard(&profiler_end_callback_lock_);
  return profiler_end_callback_.find(isolate) != profiler_end_callback_.end();
}

void Shell::ResetOnProfileEndListener(Isolate* isolate) {
  // If the inspector is enabled, then the installed console is not the
  // D8Console.
  if (options.enable_inspector) return;
  {
    base::MutexGuard lock_guard(&profiler_end_callback_lock_);
    profiler_end_callback_.erase(isolate);
  }

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  D8Console* console =
      reinterpret_cast<D8Console*>(i_isolate->console_delegate());
  if (console) {
    console->DisposeProfiler();
  }
}

void Shell::ProfilerTriggerSample(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  Isolate* isolate = info.GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  D8Console* console =
      reinterpret_cast<D8Console*>(i_isolate->console_delegate());
  if (console && console->profiler()) {
    console->profiler()->CollectSample(isolate);
  }
}

void Shell::TriggerOnProfileEndListener(Isolate* isolate, std::string profile) {
  CHECK(HasOnProfileEndListener(isolate));
  Local<Function> callback;
  Local<Context> context;
  Local<Value> argv[1] = {
      String::NewFromUtf8(isolate, profile.c_str()).ToLocalChecked()};
  {
    base::MutexGuard lock_guard(&profiler_end_callback_lock_);
    auto& callback_pair = profiler_end_callback_[isolate];
    callback = callback_pair.first.Get(isolate);
    context = callback_pair.second.Get(isolate);
  }
  TryCatch try_catch(isolate);
  try_catch.SetVerbose(true);
  USE(callback->Call(context, Undefined(isolate), 1, argv));
}

void WriteToFile(FILE* file, const v8::FunctionCallbackInfo<v8::Value>& info,
                 int first_arg_index = 0) {
  for (int i = first_arg_index; i < info.Length(); i++) {
    HandleScope handle_scope(info.GetIsolate());
    if (i != first_arg_index) {
      fprintf(file, " ");
    }

    // Explicitly catch potential exceptions in toString().
    v8::TryCatch try_catch(info.GetIsolate());
    Local<Value> arg = info[i];
    Local<String> str_obj;

    if (arg->IsSymbol()) {
      arg = arg.As<Symbol>()->Description(info.GetIsolate());
    }
    if (!arg->ToString(info.GetIsolate()->GetCurrentContext())
             .ToLocal(&str_obj)) {
      try_catch.ReThrow();
      return;
    }

    v8::String::Utf8Value str(info.GetIsolate(), str_obj);
    size_t n = fwrite(*str, sizeof(**str), str.length(), file);
    if (n != str.length()) {
      printf("Error in fwrite\n");
      base::OS::ExitProcess(1);
    }
  }
}

void WriteAndFlush(FILE* file,
                   const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  WriteToFile(file, info);
  fprintf(file, "\n");
  fflush(file);
}

void Shell::Print(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WriteAndFlush(stdout, info);
}

void Shell::PrintErr(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WriteAndFlush(stderr, info);
}

void Shell::WriteStdout(const v8::FunctionCallbackInfo<v8::Value>& info) {
  WriteToFile(stdout, info);
}

// There are two overloads of writeFile().
//
// The first parameter is always the filename.
//
// If there are exactly 2 arguments, and the second argument is an ArrayBuffer
// or an ArrayBufferView, write the binary contents into the file.
//
// Otherwise, convert arguments to UTF-8 strings, and write them to the file,
// separated by space.
void Shell::WriteFile(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  String::Utf8Value file_name(info.GetIsolate(), info[0]);
  if (*file_name == nullptr) {
    ThrowError(info.GetIsolate(), "Error converting filename to string");
    return;
  }
  FILE* file;
  if (info.Length() == 2 &&
      (info[1]->IsArrayBuffer() || info[1]->IsArrayBufferView())) {
    file = base::Fopen(*file_name, "wb");
    if (file == nullptr) {
      ThrowError(info.GetIsolate(), "Error opening file");
      return;
    }

    void* data;
    size_t length;
    if (info[1]->IsArrayBuffer()) {
      Local<v8::ArrayBuffer> buffer = Local<v8::ArrayBuffer>::Cast(info[1]);
      length = buffer->ByteLength();
      data = buffer->Data();
    } else {
      Local<v8::ArrayBufferView> buffer_view =
          Local<v8::ArrayBufferView>::Cast(info[1]);
      length = buffer_view->ByteLength();
      data = static_cast<uint8_t*>(buffer_view->Buffer()->Data()) +
             buffer_view->ByteOffset();
    }
    fwrite(data, 1, length, file);
  } else {
    file = base::Fopen(*file_name, "w");
    if (file == nullptr) {
      ThrowError(info.GetIsolate(), "Error opening file");
      return;
    }
    WriteToFile(file, info, 1);
  }
  base::Fclose(file);
}

void Shell::ReadFile(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  String::Utf8Value file_name(info.GetIsolate(), info[0]);
  if (*file_name == nullptr) {
    ThrowError(info.GetIsolate(), "Error converting filename to string");
    return;
  }
  if (info.Length() == 2) {
    String::Utf8Value format(info.GetIsolate(), info[1]);
    if (*format && std::strcmp(*format, "binary") == 0) {
      ReadBuffer(info);
      return;
    }
  }
  Local<String> source;
  if (!ReadFile(info.GetIsolate(), *file_name).ToLocal(&source)) return;
  info.GetReturnValue().Set(source);
}

Local<String> Shell::ReadFromStdin(Isolate* isolate) {
  static const int kBufferSize = 256;
  char buffer[kBufferSize];
  Local<String> accumulator = String::NewFromUtf8Literal(isolate, "");
  int length;
  // Flush stdout before reading stdin, as stdout isn't guaranteed to be flushed
  // automatically.
  fflush(stdout);
  while (true) {
    // Continue reading if the line ends with an escape '\\' or the line has
    // not been fully read into the buffer yet (does not end with '\n').
    // If fgets gets an error, just give up.
    char* input = nullptr;
    input = fgets(buffer, kBufferSize, stdin);
    if (input == nullptr) return Local<String>();
    length = static_cast<int>(strlen(buffer));
    if (length == 0) {
      return accumulator;
    } else if (buffer[length - 1] != '\n') {
      accumulator = String::Concat(
          isolate, accumulator,
          String::NewFromUtf8(isolate, buffer, NewStringType::kNormal, length)
              .ToLocalChecked());
    } else if (length > 1 && buffer[length - 2] == '\\') {
      buffer[length - 2] = '\n';
      accumulator =
          String::Concat(isolate, accumulator,
                         String::NewFromUtf8(isolate, buffer,
                                             NewStringType::kNormal, length - 1)
                             .ToLocalChecked());
    } else {
      return String::Concat(
          isolate, accumulator,
          String::NewFromUtf8(isolate, buffer, NewStringType::kNormal,
                              length - 1)
              .ToLocalChecked());
    }
  }
}

void Shell::ExecuteFile(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  for (int i = 0; i < info.Length(); i++) {
    HandleScope handle_scope(isolate);
    String::Utf8Value file_name(isolate, info[i]);
    if (*file_name == nullptr) {
      std::ostringstream oss;
      oss << "Cannot convert file[" << i << "] name to string.";
      ThrowError(
          isolate,
          String::NewFromUtf8(isolate, oss.str().c_str()).ToLocalChecked());
      return;
    }
    Local<String> source;
    if (!ReadFile(isolate, *file_name).ToLocal(&source)) return;
    if (!ExecuteString(
            info.GetIsolate(), source,
            String::NewFromUtf8(isolate, *file_name).ToLocalChecked(),
            options.quiet_load ? kNoReportExceptions : kReportExceptions)) {
      std::ostringstream oss;
      oss << "Error executing file: \"" << *file_name << '"';
      ThrowError(
          isolate,
          String::NewFromUtf8(isolate, oss.str().c_str()).ToLocalChecked());
      return;
    }
  }
}

class SetTimeoutTask : public v8::Task {
 public:
  SetTimeoutTask(v8::Isolate* isolate, v8::Local<v8::Context> context,
                 v8::Local<v8::Function> callback)
      : isolate_(isolate),
        context_(isolate, context),
        callback_(isolate, callback) {}

  void Run() override {
    HandleScope scope(isolate_);
    Local<Context> context = context_.Get(isolate_);
    Local<Function> callback = callback_.Get(isolate_);
    Context::Scope context_scope(context);
    MaybeLocal<Value> result =
        callback->Call(context, Undefined(isolate_), 0, nullptr);
    USE(result);
  }

 private:
  v8::Isolate* isolate_;
  v8::Global<v8::Context> context_;
  v8::Global<v8::Function> callback_;
};

void Shell::SetTimeout(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  info.GetReturnValue().Set(v8::Number::New(isolate, 0));
  if (info.Length() == 0 || !info[0]->IsFunction()) return;
  Local<Function> callback = info[0].As<Function>();
  Local<Context> context = isolate->GetCurrentContext();
  g_platform->GetForegroundTaskRunner(isolate)->PostTask(
      std::make_unique<SetTimeoutTask>(isolate, context, callback));
}

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
void Shell::GetContinuationPreservedEmbedderData(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  info.GetReturnValue().Set(
      info.GetIsolate()->GetContinuationPreservedEmbedderData());
}
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

void Shell::GetExtrasBindingObject(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  Local<Context> context = info.GetIsolate()->GetCurrentContext();
  info.GetReturnValue().Set(context->GetExtrasBindingObject());
}

void Shell::ReadCodeTypeAndArguments(
    const v8::FunctionCallbackInfo<v8::Value>& info, int index,
    CodeType* code_type, Local<Value>* arguments) {
  Isolate* isolate = info.GetIsolate();
  if (info.Length() > index && info[index]->IsObject()) {
    Local<Object> object = info[index].As<Object>();
    Local<Context> context = isolate->GetCurrentContext();
    Local<Value> value;
    if (!TryGetValue(isolate, context, object, "type").ToLocal(&value)) {
      *code_type = CodeType::kNone;
      return;
    }
    if (!value->IsString()) {
      *code_type = CodeType::kInvalid;
      return;
    }
    Local<String> worker_type_string =
        value->ToString(context).ToLocalChecked();
    String::Utf8Value str(isolate, worker_type_string);
    if (strcmp("classic", *str) == 0) {
      *code_type = CodeType::kFileName;
    } else if (strcmp("string", *str) == 0) {
      *code_type = CodeType::kString;
    } else if (strcmp("function", *str) == 0) {
      *code_type = CodeType::kFunction;
    } else {
      *code_type = CodeType::kInvalid;
    }
    if (arguments != nullptr) {
      bool got_arguments =
          TryGetValue(isolate, context, object, "arguments").ToLocal(arguments);
      USE(got_arguments);
    }
  } else {
    *code_type = CodeType::kNone;
  }
}

bool Shell::FunctionAndArgumentsToString(Local<Function> function,
                                         Local<Value> arguments,
                                         Local<String>* source,
                                         Isolate* isolate) {
  Local<Context> context = isolate->GetCurrentContext();
  MaybeLocal<String> maybe_function_string =
      function->FunctionProtoToString(context);
  Local<String> function_string;
  if (!maybe_function_string.ToLocal(&function_string)) {
    ThrowError(isolate, "Failed to convert function to string");
    return false;
  }
  *source = String::NewFromUtf8Literal(isolate, "(");
  *source = String::Concat(isolate, *source, function_string);
  Local<String> middle = String::NewFromUtf8Literal(isolate, ")(");
  *source = String::Concat(isolate, *source, middle);
  if (!arguments.IsEmpty() && !arguments->IsUndefined()) {
    if (!arguments->IsArray()) {
      ThrowError(isolate, "'arguments' must be an array");
      return false;
    }
    Local<String> comma = String::NewFromUtf8Literal(isolate, ",");
    Local<Array> array = arguments.As<Array>();
    for (uint32_t i = 0; i < array->Length(); ++i) {
      if (i > 0) {
        *source = String::Concat(isolate, *source, comma);
      }
      MaybeLocal<Value> maybe_argument = array->Get(context, i);
      Local<Value> argument;
      if (!maybe_argument.ToLocal(&argument)) {
        ThrowError(isolate, "Failed to get argument");
        return false;
      }
      Local<String> argument_string;
      if (!JSON::Stringify(context, argument).ToLocal(&argument_string)) {
        ThrowError(isolate, "Failed to convert argument to string");
        return false;
      }
      *source = String::Concat(isolate, *source, argument_string);
    }
  }
  Local<String> suffix = String::NewFromUtf8Literal(isolate, ")");
  *source = String::Concat(isolate, *source, suffix);
  return true;
}

// ReadSource() supports reading source code through `info[index]` as specified
// by the `default_type` or an optional options bag provided in `info[index+1]`
// (e.g. `options={type: 'code_type', arguments:[...]}`).
MaybeLocal<String> Shell::ReadSource(
    const v8::FunctionCallbackInfo<v8::Value>& info, int index,
    CodeType default_type) {
  CodeType code_type;
  Local<Value> arguments;
  ReadCodeTypeAndArguments(info, index + 1, &code_type, &arguments);

  Isolate* isolate = info.GetIsolate();
  Local<String> source;
  if (code_type == CodeType::kNone) {
    code_type = default_type;
  }
  switch (code_type) {
    case CodeType::kFunction:
      if (!info[index]->IsFunction()) {
        return MaybeLocal<String>();
      }
      // Source: ( function_to_string )( params )
      if (!FunctionAndArgumentsToString(info[index].As<Function>(), arguments,
                                        &source, isolate)) {
        return MaybeLocal<String>();
      }
      break;
    case CodeType::kFileName: {
      if (!info[index]->IsString()) {
        return MaybeLocal<String>();
      }
      String::Utf8Value filename(isolate, info[index]);
      if (!Shell::ReadFile(isolate, *filename).ToLocal(&source)) {
        return MaybeLocal<String>();
      }
      break;
    }
    case CodeType::kString:
      if (!info[index]->IsString()) {
        return MaybeLocal<String>();
      }
      source = info[index].As<String>();
      break;
    case CodeType::kNone:
    case CodeType::kInvalid:
      return MaybeLocal<String>();
  }
  return source;
}

void Shell::WorkerNew(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  HandleScope handle_scope(isolate);
  if (info.Length() < 1 || (!info[0]->IsString() && !info[0]->IsFunction())) {
    ThrowError(isolate, "1st argument must be a string or a function");
    return;
  }

  Local<String> source;
  if (!ReadSource(info, 0, CodeType::kFileName).ToLocal(&source)) {
    ThrowError(isolate, "Invalid argument");
    return;
  }

  if (!info.IsConstructCall()) {
    ThrowError(isolate, "Worker must be constructed with new");
    return;
  }

  // Initialize the embedder field to 0; if we return early without
  // creating a new Worker (because the main thread is terminating) we can
  // early-out from the instance calls.
  info.This()->SetInternalField(0, v8::Integer::New(isolate, 0));

  {
    // Don't allow workers to create more workers if the main thread
    // is waiting for existing running workers to terminate.
    i::ParkedMutexGuard lock_guard(
        reinterpret_cast<i::Isolate*>(isolate)->main_thread_local_isolate(),
        workers_mutex_.Pointer());
    if (!allow_new_workers_) return;

    String::Utf8Value script(isolate, source);
    if (!*script) {
      ThrowError(isolate, "Can't get worker script");
      return;
    }

    // The C++ worker object's lifetime is shared between the Managed<Worker>
    // object on the heap, which the JavaScript object points to, and an
    // internal std::shared_ptr in the worker thread itself.
    auto worker = std::make_shared<Worker>(isolate, *script);
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
    const size_t kWorkerSizeEstimate = 4 * 1024 * 1024;  // stack + heap.
    i::Handle<i::Object> managed =
        i::Managed<Worker>::From(i_isolate, kWorkerSizeEstimate, worker);
    info.This()->SetInternalField(0, Utils::ToLocal(managed));
    base::Thread::Priority priority =
        options.apply_priority ? base::Thread::Priority::kUserBlocking
                               : base::Thread::Priority::kDefault;
    if (!Worker::StartWorkerThread(isolate, worker, priority)) {
      ThrowError(isolate, "Can't start thread");
      return;
    }
    PerIsolateData::Get(isolate)->RegisterWorker(worker);
  }
}

void Shell::WorkerPostMessage(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  HandleScope handle_scope(isolate);

  if (info.Length() < 1) {
    ThrowError(isolate, "Invalid argument");
    return;
  }

  std::shared_ptr<Worker> worker =
      GetWorkerFromInternalField(isolate, info.This());
  if (!worker.get()) {
    return;
  }

  Local<Value> message = info[0];
  Local<Value> transfer =
      info.Length() >= 2 ? info[1] : Undefined(isolate).As<Value>();
  std::unique_ptr<SerializationData> data =
      Shell::SerializeValue(isolate, message, transfer);
  if (data) {
    worker->PostMessage(std::move(data));
  }
}

void Shell::WorkerGetMessage(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  HandleScope handle_scope(isolate);
  std::shared_ptr<Worker> worker =
      GetWorkerFromInternalField(isolate, info.This());
  if (!worker.get()) {
    return;
  }

  std::unique_ptr<SerializationData> data = worker->GetMessage(isolate);
  if (data) {
    Local<Value> value;
    if (Shell::DeserializeValue(isolate, std::move(data)).ToLocal(&value)) {
      info.GetReturnValue().Set(value);
    }
  }
}

// Task processing one onmessage event received from a Worker.
class OnMessageFromWorkerTask : public v8::Task {
 public:
  OnMessageFromWorkerTask(v8::Isolate* isolate, v8::Local<v8::Context> context,
                          v8::Local<v8::Value> callback,
                          std::unique_ptr<SerializationData> data)
      : isolate_(isolate),
        context_(isolate, context),
        callback_(isolate, callback),
        data_(std::move(data)) {}

  void Run() override {
    HandleScope scope(isolate_);
    Local<Context> context = context_.Get(isolate_);
    Context::Scope context_scope(context);
    MicrotasksScope microtasks_scope(context,
                                     MicrotasksScope::kDoNotRunMicrotasks);

    Local<Object> global = context->Global();

    // Get the message handler.
    Local<Value> onmessage = callback_.Get(isolate_);
    if (!onmessage->IsFunction()) return;
    Local<Function> onmessage_fun = onmessage.As<Function>();

    v8::TryCatch try_catch(isolate_);
    try_catch.SetVerbose(true);
    Local<Value> value;
    if (Shell::DeserializeValue(isolate_, std::move(data_)).ToLocal(&value)) {
      DCHECK(!isolate_->IsExecutionTerminating());
      Local<Object> event = v8::Object::New(isolate_);
      event
          ->CreateDataProperty(
              context,
              String::NewFromUtf8Literal(isolate_, "data",
                                         NewStringType::kInternalized),
              value)
          .ToChecked();
      Local<Value> argv[] = {event};
      MaybeLocal<Value> result = onmessage_fun->Call(context, global, 1, argv);
      USE(result);
    }
  }

 private:
  v8::Isolate* isolate_;
  v8::Global<v8::Context> context_;
  v8::Global<v8::Value> callback_;
  std::unique_ptr<SerializationData> data_;
};

// Check, on the main thread, whether a worker has any enqueued any message
// events. Workers post this task when posting a message, instead of posting
// OnMessageFromWorkerTask directly, to avoid races between message posting
// and onmessage subscription.
class CheckMessageFromWorkerTask : public v8::Task {
 public:
  CheckMessageFromWorkerTask(v8::Isolate* isolate,
                             std::shared_ptr<Worker> worker)
      : isolate_(isolate), worker_(std::move(worker)) {}

  void Run() override {
    HandleScope scope(isolate_);

    // Get the callback for onmessage events from this worker. It's important to
    // do this here, and not in OnMessageFromWorkerTask, because we may get a
    // CleanUpWorkerTask scheduled before the posted OnMessageFromWorkerTask
    // executes, which will
    auto callback_pair =
        PerIsolateData::Get(isolate_)->GetWorkerOnMessage(worker_);
    // Bail out if there's no callback -- leave the message queue untouched so
    // that we don't lose the messages and can read them with GetMessage later.
    // This is slightly different to browser behaviour, where events can be
    // missed, but it's helpful for d8's GetMessage behaviour.
    if (callback_pair.second.IsEmpty()) return;

    std::unique_ptr<SerializationData> result;
    while ((result = worker_->TryGetMessage())) {
      // Each onmessage callback call is posted as a separate task.
      g_platform->GetForegroundTaskRunner(isolate_)->PostTask(
          std::make_unique<OnMessageFromWorkerTask>(
              isolate_, callback_pair.first, callback_pair.second,
              std::move(result)));
    }
  }

 private:
  v8::Isolate* isolate_;
  std::shared_ptr<Worker> worker_;
};

// Unregister the given isolate from message events from the given worker.
// This must be done before the isolate or worker are destroyed, so that the
// global handles for context and callback are cleaned up correctly -- thus the
// event loop blocks until all workers are unregistered.
class CleanUpWorkerTask : public v8::Task {
 public:
  CleanUpWorkerTask(v8::Isolate* isolate, std::shared_ptr<Worker> worker)
      : isolate_(isolate), worker_(std::move(worker)) {}

  void Run() override {
    PerIsolateData::Get(isolate_)->UnregisterWorker(std::move(worker_));
  }

 private:
  v8::Isolate* isolate_;
  std::shared_ptr<Worker> worker_;
};

void Shell::WorkerOnMessageGetter(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  HandleScope handle_scope(isolate);

  std::shared_ptr<Worker> worker =
      GetWorkerFromInternalField(isolate, info.This());
  if (!worker.get()) {
    return;
  }
  Local<Function> callback =
      PerIsolateData::Get(isolate)->GetWorkerOnMessage(worker).second;

  if (!callback.IsEmpty()) {
    info.GetReturnValue().Set(callback);
  }
}

void Shell::WorkerOnMessageSetter(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  HandleScope handle_scope(isolate);

  if (info.Length() < 1) {
    ThrowError(isolate, "Invalid argument");
    return;
  }

  std::shared_ptr<Worker> worker =
      GetWorkerFromInternalField(isolate, info.This());
  if (!worker.get()) {
    return;
  }

  Local<Value> callback = info[0];
  if (!callback->IsFunction()) return;

  PerIsolateData::Get(isolate)->SubscribeWorkerOnMessage(
      worker, isolate->GetCurrentContext(), Local<Function>::Cast(callback));
}

void Shell::WorkerTerminate(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  HandleScope handle_scope(isolate);
  std::shared_ptr<Worker> worker =
      GetWorkerFromInternalField(isolate, info.This());
  if (!worker.get()) return;
  worker->Terminate();
}

void Shell::WorkerTerminateAndWait(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  Isolate* isolate = info.GetIsolate();
  HandleScope handle_scope(isolate);
  std::shared_ptr<Worker> worker =
      GetWorkerFromInternalField(isolate, info.This());
  if (!worker.get()) {
    return;
  }

  reinterpret_cast<i::Isolate*>(isolate)
      ->main_thread_local_isolate()
      ->ExecuteMainThreadWhileParked([worker](const i::ParkedScope& parked) {
        worker->TerminateAndWaitForThread(parked);
      });
}

void Shell::QuitOnce(v8::FunctionCallbackInfo<v8::Value>* info) {
  int exit_code = (*info)[0]
                      ->Int32Value(info->GetIsolate()->GetCurrentContext())
                      .FromMaybe(0);
  Isolate* isolate = info->GetIsolate();
  ResetOnProfileEndListener(isolate);
  isolate->Exit();

  // As we exit the process anyway, we do not dispose the platform and other
  // global data and manually unlock to quell DCHECKs. Other isolates might
  // still be running, so disposing here can cause them to crash.
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  if (i_isolate->thread_manager()->IsLockedByCurrentThread()) {
    i_isolate->thread_manager()->Unlock();
  }

  // When disposing the shared space isolate, the workers (client isolates) need
  // to be terminated first.
  if (i_isolate->is_shared_space_isolate()) {
    i_isolate->main_thread_local_isolate()->ExecuteMainThreadWhileParked(
        [](const i::ParkedScope& parked) { WaitForRunningWorkers(parked); });
  }

  OnExit(isolate, false);
  base::OS::ExitProcess(exit_code);
}

void Shell::Terminate(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  // Triggering termination from JS can cause some non-determinism thus we
  // skip it for correctness fuzzing.
  // Termination also currently breaks Fuzzilli's REPRL mechanism as the
  // scheduled termination will prevent the next testcase sent by Fuzzilli from
  // being processed. This will in turn desynchronize the communication
  // between d8 and Fuzzilli, leading to a crash.
  if (!i::v8_flags.correctness_fuzzer_suppressions && !fuzzilli_reprl) {
    auto v8_isolate = info.GetIsolate();
    if (!v8_isolate->IsExecutionTerminating()) v8_isolate->TerminateExecution();
  }
}

void Shell::Quit(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  base::CallOnce(&quit_once_, &QuitOnce,
                 const_cast<v8::FunctionCallbackInfo<v8::Value>*>(&info));
}

void Shell::Version(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(
      String::NewFromUtf8(info.GetIsolate(), V8::GetVersion())
          .ToLocalChecked());
}

void Shell::ReportException(Isolate* isolate, Local<v8::Message> message,
                            Local<v8::Value> exception_obj) {
  HandleScope handle_scope(isolate);
  Local<Context> context = isolate->GetCurrentContext();
  bool enter_context = context.IsEmpty();
  if (enter_context) {
    context = Local<Context>::New(isolate, evaluation_context_);
    context->Enter();
  }
  // Converts a V8 value to a C string.
  auto ToCString = [](const v8::String::Utf8Value& value) {
    return *value ? *value : "<string conversion failed>";
  };

  v8::String::Utf8Value exception(isolate, exception_obj);
  const char* exception_string = ToCString(exception);
  if (message.IsEmpty()) {
    // V8 didn't provide any extra information about this error; just
    // print the exception.
    printf("%s\n", exception_string);
  } else if (message->GetScriptOrigin().Options().IsWasm()) {
    // Print wasm-function[(function index)]:(offset): (message).
    int function_index = message->GetWasmFunctionIndex();
    int offset = message->GetStartColumn(context).FromJust();
    printf("wasm-function[%d]:0x%x: %s\n", function_index, offset,
           exception_string);
  } else {
    // Print (filename):(line number): (message).
    v8::String::Utf8Value filename(isolate,
                                   message->GetScriptOrigin().ResourceName());
    const char* filename_string = ToCString(filename);
    int linenum = message->GetLineNumber(context).FromMaybe(-1);
    printf("%s:%i: %s\n", filename_string, linenum, exception_string);
    Local<String> sourceline;
    if (message->GetSourceLine(context).ToLocal(&sourceline)) {
      // Print line of source code.
      v8::String::Utf8Value sourcelinevalue(isolate, sourceline);
      const char* sourceline_string = ToCString(sourcelinevalue);
      printf("%s\n", sourceline_string);
      // Print wavy underline (GetUnderline is deprecated).
      int start = message->GetStartColumn(context).FromJust();
      for (int i = 0; i < start; i++) {
        printf(" ");
      }
      int end = message->GetEndColumn(context).FromJust();
      for (int i = start; i < end; i++) {
        printf("^");
      }
      printf("\n");
    }
  }
  Local<Value> stack_trace_string;
  if (v8::TryCatch::StackTrace(context, exception_obj)
          .ToLocal(&stack_trace_string) &&
      stack_trace_string->IsString()) {
    v8::String::Utf8Value stack_trace(isolate, stack_trace_string.As<String>());
    print
```