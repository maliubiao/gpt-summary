Response:
The user wants a summary of the C++ code provided, focusing on its functionalities. I need to go through the code and identify the main tasks it performs. The user also has specific questions about Torque, JavaScript interaction, code logic, and common programming errors. Finally, they want a summary of the functionalities of this specific part of the code.

Here's a breakdown of what the code does:

1. **System Memory Stats:**  The beginning part deals with dumping system memory usage.
2. **Fuzzer Monitor:**  It includes a `FuzzerMonitor` class that simulates different types of errors for testing purposes.
3. **File Reading:**  There are functions for reading files (`ReadChars`, `ReadLines`, `ReadFileData`, `ReadFile`).
4. **File Writing:** A function to write to files (`WriteChars`).
5. **Shell Interaction:**  The `Shell::RunShell` function seems to implement an interactive shell for executing JavaScript code.
6. **Inspector Integration:** There's code related to integrating with the V8 Inspector for debugging.
7. **Source Group Execution:** The `SourceGroup` class handles the execution of JavaScript code from files or command-line arguments, potentially in separate threads.
8. **Serialization and Workers:**  The code includes classes for `SerializationDataQueue` and `Worker`, suggesting support for multi-threading and message passing between workers.
9. **Worker Implementation Details:** The latter part of the code shows the implementation of the `Worker` class, including setting up the isolate, context, global functions (`postMessage`, `close`, `importScripts`), and message processing.

Considering this is part 6 of 8, I should focus on the functionalities introduced or significantly developed in this specific section. The introduction of the `Worker` class and its related functionalities appears to be the most significant part of this code snippet.
这是 `v8/src/d8/d8.cc` 源代码的第 6 部分，主要关注以下功能：

**1. 系统内存统计和计数器输出：**

*   代码块的开始部分负责输出收集到的性能计数器信息。它遍历 `counter_map_`，并以表格形式打印每个计数器的名称和值。
*   它还输出了系统峰值内存使用量（如果 `options.dump_system_memory_stats` 为 true）。
*   这段代码展示了 d8 如何收集和报告 V8 内部的性能指标。

**2. 模糊测试监控 (`FuzzerMonitor`):**

*   `FuzzerMonitor` 类及其方法 (`SimulateErrors`, `ControlFlowViolation`, `DCheck`, `Fatal`, `ObservableDifference`, `UndefinedBehavior`, `UseAfterFree`, `UseOfUninitializedValue`)  用于在 d8 工具中模拟各种错误情况，这对于模糊测试 V8 引擎非常有用。
*   这些方法会触发不同类型的错误，例如控制流违规、断言失败、致命错误、可观察差异、未定义行为、释放后使用和使用未初始化的值。
*   这部分代码与 JavaScript 功能没有直接关系，而是用于 V8 内部的测试和稳定性验证。

**3. 文件读取功能 (`Shell::ReadChars`, `Shell::ReadLines`, `Shell::ReadBuffer`, `Shell::ReadFileData`, `Shell::ReadFile`):**

*   这些函数提供了从不同来源（普通文件、TCP 端口）读取数据的功能，并将数据加载到不同的数据结构中，例如字符数组、字符串数组或 V8 字符串对象。
*   `ReadChars`：读取文件内容到字符数组。
*   `ReadLines`：读取文件内容，按行分割成字符串数组。
*   `ReadBuffer`：作为 JavaScript 回调函数暴露，读取文件内容到 `ArrayBuffer`。
*   `ReadFileData`：将文件内容映射到内存中。
*   `ReadFile`：读取文件内容到 V8 字符串对象。

**与 JavaScript 的关系和示例：**

`Shell::ReadBuffer` 和 `Shell::ReadLine` 这两个函数可以直接在 JavaScript 代码中调用（因为它们被设置为全局函数），用于读取文件内容或标准输入。

```javascript
// 调用 Shell::ReadBuffer 读取文件内容到 ArrayBuffer
function readFileToBuffer(filename) {
  return readbuffer(filename);
}

// 调用 Shell::ReadLine 读取一行标准输入
function readInputLine() {
  return readline();
}

// 示例用法
let buffer = readFileToBuffer("my_file.txt");
console.log(buffer);

let input = readInputLine();
console.log("你输入了:", input);
```

**代码逻辑推理 (假设输入与输出):**

假设 `counter_map_` 中有以下计数器：

```
{"FunctionCalls": Counter(123), "MemoryAllocations": Counter(4567)}
```

且 `options.dump_counters` 为 true。

**输出：**

```
+-----------------+----------+
| FunctionCalls   |      123 |
| MemoryAllocations |     4567 |
+-----------------+----------+
```

如果 `options.dump_system_memory_stats` 也为 true，则还会输出：

```
System peak memory usage (kb): XXXXX // XXXXX 是实际的峰值内存使用量
```

**用户常见的编程错误 (与文件读取相关):**

*   **文件不存在或无法访问：**

    ```javascript
    try {
      let buffer = readbuffer("non_existent_file.txt");
      console.log(buffer); // 这行代码不会被执行
    } catch (error) {
      console.error("读取文件出错:", error); // 输出错误信息
    }
    ```

*   **忘记处理 `readbuffer` 返回的 `ArrayBuffer`：**

    ```javascript
    readbuffer("data.bin"); // 读取了文件，但没有使用返回的 ArrayBuffer
    ```

*   **假设 `readline` 始终返回有效字符串，而没有处理输入结束的情况：**

    ```javascript
    let input = readline();
    console.log("你输入了:", input.toUpperCase()); // 如果输入结束，readline 可能返回 null 或 undefined，导致错误
    ```

**归纳本部分功能：**

本部分代码主要负责以下 d8 工具的功能：

*   **性能监控和报告：** 收集并输出 V8 内部的性能计数器信息以及系统内存使用情况。
*   **模糊测试支持：** 提供了一种模拟各种错误情况的机制，用于测试 V8 的健壮性。
*   **文件系统交互：** 提供了读取文件内容（以不同格式）到 V8 环境的能力，包括读取为字符数组、字符串数组、`ArrayBuffer` 和 V8 字符串对象。
*   **简单的用户交互：** 允许通过 `readline` 函数读取用户的标准输入。

总而言之，这部分代码增强了 d8 工具的诊断能力（性能监控）和测试能力（模糊测试），并提供了基本的与文件系统交互的功能，使得 d8 可以加载和执行 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/d8/d8.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/d8/d8.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共8部分，请归纳一下它的功能

"""
else {
          std::cout << "| " << std::setw(kNameBoxSize - 2) << std::left << key
                    << " | " << std::setw(kValueBoxSize - 2) << std::right
                    << counter->count() << " |\n";
        }
      }
      std::cout << "+" << std::string(kNameBoxSize, '-') << "+"
                << std::string(kValueBoxSize, '-') << "+\n";
    }
  }

  if (options.dump_system_memory_stats) {
    int peak_memory_usage = base::OS::GetPeakMemoryUsageKb();
    std::cout << "System peak memory usage (kb): " << peak_memory_usage
              << std::endl;
    // TODO(jdapena): call rusage platform independent call, and extract peak
    // memory usage to print it
  }

  // Only delete the counters if we are done executing; after calling `quit`,
  // other isolates might still be running and accessing that memory. This is a
  // memory leak, which is OK in this case.
  if (dispose) {
    delete counters_file_;
    delete counter_map_;
  }
}

void Dummy(char* arg) {}

V8_NOINLINE void FuzzerMonitor::SimulateErrors() {
  // Initialize a fresh RNG to not interfere with JS execution.
  std::unique_ptr<base::RandomNumberGenerator> rng;
  int64_t seed = i::v8_flags.random_seed;
  if (seed != 0) {
    rng = std::make_unique<base::RandomNumberGenerator>(seed);
  } else {
    rng = std::make_unique<base::RandomNumberGenerator>();
  }

  double p = rng->NextDouble();
  if (p < 0.1) {
    ControlFlowViolation();
  } else if (p < 0.2) {
    DCheck();
  } else if (p < 0.3) {
    Fatal();
  } else if (p < 0.4) {
    ObservableDifference();
  } else if (p < 0.5) {
    UndefinedBehavior();
  } else if (p < 0.6) {
    UseAfterFree();
  } else if (p < 0.7) {
    UseOfUninitializedValue();
  }
}

V8_NOINLINE void FuzzerMonitor::ControlFlowViolation() {
  // Control flow violation caught by CFI.
  void (*func)() = (void (*)()) & Dummy;
  func();
}

V8_NOINLINE void FuzzerMonitor::DCheck() {
  // Caught in debug builds.
  DCHECK(false);
}

V8_NOINLINE void FuzzerMonitor::Fatal() {
  // Caught in all build types.
  FATAL("Fake error.");
}

V8_NOINLINE void FuzzerMonitor::ObservableDifference() {
  // Observable difference caught by differential fuzzing.
  printf("___fake_difference___\n");
}

V8_NOINLINE void FuzzerMonitor::UndefinedBehavior() {
  // Caught by UBSAN.
  int32_t val = -1;
  USE(val << val);
}

V8_NOINLINE void FuzzerMonitor::UseAfterFree() {
  // Use-after-free caught by ASAN.
#if defined(__clang__)  // GCC-12 detects this at compile time!
  std::vector<bool>* storage = new std::vector<bool>(3);
  delete storage;
  USE(storage->at(1));
#endif
}

V8_NOINLINE void FuzzerMonitor::UseOfUninitializedValue() {
// Use-of-uninitialized-value caught by MSAN.
#if defined(__clang__)
  int uninitialized[1];
  if (uninitialized[0]) USE(uninitialized);
#endif
}

char* Shell::ReadChars(const char* name, int* size_out) {
  if (options.read_from_tcp_port >= 0) {
    return ReadCharsFromTcpPort(name, size_out);
  }

  FILE* file = base::OS::FOpen(name, "rb");
  if (file == nullptr) return nullptr;

  fseek(file, 0, SEEK_END);
  size_t size = ftell(file);
  rewind(file);

  char* chars = new char[size + 1];
  chars[size] = '\0';
  for (size_t i = 0; i < size;) {
    i += fread(&chars[i], 1, size - i, file);
    if (ferror(file)) {
      base::Fclose(file);
      delete[] chars;
      return nullptr;
    }
  }
  base::Fclose(file);
  *size_out = static_cast<int>(size);
  return chars;
}

MaybeLocal<PrimitiveArray> Shell::ReadLines(Isolate* isolate,
                                            const char* name) {
  int length;
  std::unique_ptr<char[]> data(ReadChars(name, &length));

  if (data.get() == nullptr) {
    return MaybeLocal<PrimitiveArray>();
  }
  std::stringstream stream(data.get());
  std::string line;
  std::vector<std::string> lines;
  while (std::getline(stream, line, '\n')) {
    lines.emplace_back(line);
  }
  // Create a Local<PrimitiveArray> off the read lines.
  int size = static_cast<int>(lines.size());
  Local<PrimitiveArray> exports = PrimitiveArray::New(isolate, size);
  for (int i = 0; i < size; ++i) {
    MaybeLocal<String> maybe_str = v8::String::NewFromUtf8(
        isolate, lines[i].c_str(), NewStringType::kNormal,
        static_cast<int>(lines[i].length()));
    Local<String> str;
    if (!maybe_str.ToLocal(&str)) {
      return MaybeLocal<PrimitiveArray>();
    }
    exports->Set(isolate, i, str);
  }
  return exports;
}

void Shell::ReadBuffer(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  static_assert(sizeof(char) == sizeof(uint8_t),
                "char and uint8_t should both have 1 byte");
  Isolate* isolate = info.GetIsolate();
  String::Utf8Value filename(isolate, info[0]);
  int length;
  if (*filename == nullptr) {
    ThrowError(isolate, "Error loading file");
    return;
  }

  uint8_t* data = reinterpret_cast<uint8_t*>(ReadChars(*filename, &length));
  if (data == nullptr) {
    ThrowError(isolate, "Error reading file");
    return;
  }
  Local<v8::ArrayBuffer> buffer = ArrayBuffer::New(isolate, length);
  memcpy(buffer->GetBackingStore()->Data(), data, length);
  delete[] data;

  info.GetReturnValue().Set(buffer);
}

void Shell::ReadLine(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(ReadFromStdin(info.GetIsolate()));
}

// Reads a file into a memory blob.
std::unique_ptr<base::OS::MemoryMappedFile> Shell::ReadFileData(
    Isolate* isolate, const char* name, bool should_throw) {
  std::unique_ptr<base::OS::MemoryMappedFile> file(
      base::OS::MemoryMappedFile::open(
          name, base::OS::MemoryMappedFile::FileMode::kReadOnly));
  if (!file) {
    if (should_throw) {
      std::ostringstream oss;
      oss << "Error loading file: " << name;
      ThrowError(isolate,
                 v8::String::NewFromUtf8(
                     isolate, oss.str().substr(0, String::kMaxLength).c_str())
                     .ToLocalChecked());
    }
    return nullptr;
  }
  return file;
}

// Reads a file into a v8 string.
MaybeLocal<String> Shell::ReadFile(Isolate* isolate, const char* name,
                                   bool should_throw) {
  auto file = ReadFileData(isolate, name, should_throw);
  if (!file) {
    return MaybeLocal<String>();
  }
  int size = static_cast<int>(file->size());
  char* chars = static_cast<char*>(file->memory());
  if (i::v8_flags.use_external_strings && i::String::IsAscii(chars, size)) {
    String::ExternalOneByteStringResource* resource =
        new ExternalOwningOneByteStringResource(std::move(file));
    return String::NewExternalOneByte(isolate, resource);
  }
  return String::NewFromUtf8(isolate, chars, NewStringType::kNormal, size);
}

void Shell::WriteChars(const char* name, uint8_t* buffer, size_t buffer_size) {
  FILE* file = base::Fopen(name, "w");
  if (file == nullptr) return;
  fwrite(buffer, 1, buffer_size, file);
  base::Fclose(file);
}

void Shell::RunShell(Isolate* isolate) {
  Global<Context> context;
  {
    HandleScope scope(isolate);
    context.Reset(isolate, Local<Context>::New(isolate, evaluation_context_));
  }
  PerIsolateData::RealmScope realm_scope(isolate, context);
  printf("V8 version %s\n", V8::GetVersion());
  while (true) {
    Global<Value> global_result;
    bool success;
    {
      HandleScope scope(isolate);
      Context::Scope context_scope(context.Get(isolate));
      printf("d8> ");
      Local<String> input = Shell::ReadFromStdin(isolate);
      if (input.IsEmpty()) break;
      Local<String> name = String::NewFromUtf8Literal(isolate, "(d8)");
      success = ExecuteString(isolate, input, name, kReportExceptions,
                              &global_result);
      CHECK_EQ(success, !global_result.IsEmpty());
    }
    if (!FinishExecuting(isolate, context)) success = false;
    if (success) {
      HandleScope scope(isolate);
      Context::Scope context_scope(context.Get(isolate));
      Local<Value> result = global_result.Get(isolate);
      if (options.test_shell) {
        if (!result->IsUndefined()) {
          // If all went well and the result wasn't undefined then print
          // the returned value.
          v8::String::Utf8Value str(isolate, result);
          fwrite(*str, sizeof(**str), str.length(), stdout);
          printf("\n");
        }
      } else {
        v8::String::Utf8Value str(isolate, Stringify(isolate, result));
        fwrite(*str, sizeof(**str), str.length(), stdout);
        printf("\n");
      }
    }
  }
  printf("\n");
}

class InspectorFrontend final : public v8_inspector::V8Inspector::Channel {
 public:
  explicit InspectorFrontend(Local<Context> context) {
    isolate_ = context->GetIsolate();
    context_.Reset(isolate_, context);
  }
  ~InspectorFrontend() override = default;

 private:
  void sendResponse(
      int callId,
      std::unique_ptr<v8_inspector::StringBuffer> message) override {
    Send(message->string());
  }
  void sendNotification(
      std::unique_ptr<v8_inspector::StringBuffer> message) override {
    Send(message->string());
  }
  void flushProtocolNotifications() override {}

  void Send(const v8_inspector::StringView& string) {
    v8::Isolate::AllowJavascriptExecutionScope allow_script(isolate_);
    v8::HandleScope handle_scope(isolate_);
    int length = static_cast<int>(string.length());
    DCHECK_LT(length, v8::String::kMaxLength);
    Local<String> message =
        (string.is8Bit()
             ? v8::String::NewFromOneByte(
                   isolate_,
                   reinterpret_cast<const uint8_t*>(string.characters8()),
                   v8::NewStringType::kNormal, length)
             : v8::String::NewFromTwoByte(
                   isolate_,
                   reinterpret_cast<const uint16_t*>(string.characters16()),
                   v8::NewStringType::kNormal, length))
            .ToLocalChecked();
    Local<String> callback_name = v8::String::NewFromUtf8Literal(
        isolate_, "receive", NewStringType::kInternalized);
    Local<Context> context = context_.Get(isolate_);
    Local<Value> callback =
        context->Global()->Get(context, callback_name).ToLocalChecked();
    if (callback->IsFunction()) {
      v8::TryCatch try_catch(isolate_);
      Local<Value> args[] = {message};
      USE(callback.As<Function>()->Call(context, Undefined(isolate_), 1, args));
#ifdef DEBUG
      if (try_catch.HasCaught()) {
        Local<Object> exception = try_catch.Exception().As<Object>();
        Local<String> key = v8::String::NewFromUtf8Literal(
            isolate_, "message", NewStringType::kInternalized);
        Local<String> expected = v8::String::NewFromUtf8Literal(
            isolate_, "Maximum call stack size exceeded");
        Local<Value> value = exception->Get(context, key).ToLocalChecked();
        DCHECK(value->StrictEquals(expected));
      }
#endif
    }
  }

  Isolate* isolate_;
  Global<Context> context_;
};

class InspectorClient : public v8_inspector::V8InspectorClient {
 public:
  InspectorClient(Isolate* isolate, const Global<Context>& global_context,
                  bool connect) {
    if (!connect) return;
    isolate_ = isolate;
    Local<Context> context = global_context.Get(isolate);
    channel_.reset(new InspectorFrontend(context));
    inspector_ = v8_inspector::V8Inspector::create(isolate_, this);
    session_ =
        inspector_->connect(1, channel_.get(), v8_inspector::StringView(),
                            v8_inspector::V8Inspector::kFullyTrusted,
                            v8_inspector::V8Inspector::kNotWaitingForDebugger);
    context->SetAlignedPointerInEmbedderData(kInspectorClientIndex, this);
    inspector_->contextCreated(v8_inspector::V8ContextInfo(
        context, kContextGroupId, v8_inspector::StringView()));

    Local<Value> function =
        FunctionTemplate::New(isolate_, SendInspectorMessage)
            ->GetFunction(context)
            .ToLocalChecked();
    Local<String> function_name = String::NewFromUtf8Literal(
        isolate_, "send", NewStringType::kInternalized);
    CHECK(context->Global()->Set(context, function_name, function).FromJust());

    context_.Reset(isolate_, global_context);
  }

  void runMessageLoopOnPause(int contextGroupId) override {
    v8::Isolate::AllowJavascriptExecutionScope allow_script(isolate_);
    v8::HandleScope handle_scope(isolate_);
    Local<String> callback_name = v8::String::NewFromUtf8Literal(
        isolate_, "handleInspectorMessage", NewStringType::kInternalized);
    Local<Context> context = context_.Get(isolate_);
    Local<Value> callback =
        context->Global()->Get(context, callback_name).ToLocalChecked();
    if (!callback->IsFunction()) return;

    // Running the message loop below may trigger the execution of a stackless
    // GC. We need to override the embedder stack state, to force scanning the
    // stack, if this happens.
    i::Heap* heap = reinterpret_cast<i::Isolate*>(isolate_)->heap();
    i::EmbedderStackStateScope stack_scanning_scope(
        heap, i::EmbedderStackStateOrigin::kExplicitInvocation,
        v8::StackState::kMayContainHeapPointers);

    v8::TryCatch try_catch(isolate_);
    try_catch.SetVerbose(true);
    is_paused = true;

    while (is_paused) {
      USE(callback.As<Function>()->Call(context, Undefined(isolate_), 0, {}));
      if (try_catch.HasCaught()) {
        is_paused = false;
      }
    }
  }

  void quitMessageLoopOnPause() override { is_paused = false; }

 private:
  static v8_inspector::V8InspectorSession* GetSession(Local<Context> context) {
    InspectorClient* inspector_client = static_cast<InspectorClient*>(
        context->GetAlignedPointerFromEmbedderData(kInspectorClientIndex));
    return inspector_client->session_.get();
  }

  Local<Context> ensureDefaultContextInGroup(int group_id) override {
    DCHECK(isolate_);
    DCHECK_EQ(kContextGroupId, group_id);
    return context_.Get(isolate_);
  }

  static void SendInspectorMessage(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(i::ValidateCallbackInfo(info));
    Isolate* isolate = info.GetIsolate();
    v8::HandleScope handle_scope(isolate);
    Local<Context> context = isolate->GetCurrentContext();
    info.GetReturnValue().Set(Undefined(isolate));
    Local<String> message = info[0]->ToString(context).ToLocalChecked();
    v8_inspector::V8InspectorSession* session =
        InspectorClient::GetSession(context);
    uint32_t length = message->Length();
    std::unique_ptr<uint16_t[]> buffer(new uint16_t[length]);
    message->WriteV2(isolate, 0, length, buffer.get());
    v8_inspector::StringView message_view(buffer.get(), length);
    {
      v8::SealHandleScope seal_handle_scope(isolate);
      session->dispatchProtocolMessage(message_view);
    }
    info.GetReturnValue().Set(True(isolate));
  }

  static const int kContextGroupId = 1;

  std::unique_ptr<v8_inspector::V8Inspector> inspector_;
  std::unique_ptr<v8_inspector::V8InspectorSession> session_;
  std::unique_ptr<v8_inspector::V8Inspector::Channel> channel_;
  bool is_paused = false;
  Global<Context> context_;
  Isolate* isolate_;
};

SourceGroup::~SourceGroup() {
  delete thread_;
  thread_ = nullptr;
}

bool ends_with(const char* input, const char* suffix) {
  size_t input_length = strlen(input);
  size_t suffix_length = strlen(suffix);
  if (suffix_length <= input_length) {
    return strcmp(input + input_length - suffix_length, suffix) == 0;
  }
  return false;
}

bool SourceGroup::Execute(Isolate* isolate) {
  bool success = true;
#ifdef V8_FUZZILLI
  if (fuzzilli_reprl) {
    HandleScope handle_scope(isolate);
    Local<String> file_name =
        String::NewFromUtf8(isolate, "fuzzcode.js", NewStringType::kNormal)
            .ToLocalChecked();

    size_t script_size;
    CHECK_EQ(read(REPRL_CRFD, &script_size, 8), 8);
    char* buffer = new char[script_size + 1];
    char* ptr = buffer;
    size_t remaining = script_size;
    while (remaining > 0) {
      ssize_t rv = read(REPRL_DRFD, ptr, remaining);
      CHECK_GE(rv, 0);
      remaining -= rv;
      ptr += rv;
    }
    buffer[script_size] = 0;

    Local<String> source =
        String::NewFromUtf8(isolate, buffer, NewStringType::kNormal)
            .ToLocalChecked();
    delete[] buffer;
    Shell::set_script_executed();
    if (!Shell::ExecuteString(isolate, source, file_name,
                              Shell::kReportExceptions)) {
      return false;
    }
  }
#endif  // V8_FUZZILLI
  for (int i = begin_offset_; i < end_offset_; ++i) {
    const char* arg = argv_[i];
    if (strcmp(arg, "-e") == 0 && i + 1 < end_offset_) {
      // Execute argument given to -e option directly.
      HandleScope handle_scope(isolate);
      Local<String> file_name = String::NewFromUtf8Literal(isolate, "unnamed");
      Local<String> source =
          String::NewFromUtf8(isolate, argv_[i + 1]).ToLocalChecked();
      Shell::set_script_executed();
      if (!Shell::ExecuteString(isolate, source, file_name,
                                Shell::kReportExceptions)) {
        success = false;
        break;
      }
      ++i;
      continue;
    } else if (ends_with(arg, ".mjs")) {
      Shell::set_script_executed();
      if (!Shell::ExecuteModule(isolate, arg)) {
        success = false;
        break;
      }
      continue;
    } else if (strcmp(arg, "--module") == 0 && i + 1 < end_offset_) {
      // Treat the next file as a module.
      arg = argv_[++i];
      Shell::set_script_executed();
      if (!Shell::ExecuteModule(isolate, arg)) {
        success = false;
        break;
      }
      continue;
    } else if (strcmp(arg, "--json") == 0 && i + 1 < end_offset_) {
      // Treat the next file as a JSON file.
      arg = argv_[++i];
      Shell::set_script_executed();
      if (!Shell::LoadJSON(isolate, arg)) {
        success = false;
        break;
      }
      continue;
    } else if (arg[0] == '-') {
      // Ignore other options. They have been parsed already.
      continue;
    }

    // Use all other arguments as names of files to load and run.
    HandleScope handle_scope(isolate);
    Local<String> file_name =
        String::NewFromUtf8(isolate, arg).ToLocalChecked();
    Local<String> source;
    if (!Shell::ReadFile(isolate, arg).ToLocal(&source)) {
      printf("Error reading '%s'\n", arg);
      base::OS::ExitProcess(1);
    }
    Shell::set_script_executed();
    Shell::update_script_size(source->Length());
    if (!Shell::ExecuteString(isolate, source, file_name,
                              Shell::kReportExceptions)) {
      success = false;
      break;
    }
  }
  return success;
}

SourceGroup::IsolateThread::IsolateThread(SourceGroup* group)
    : base::Thread(GetThreadOptions("IsolateThread")), group_(group) {}

void SourceGroup::ExecuteInThread() {
  Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = Shell::array_buffer_allocator;
  Isolate* isolate = Isolate::New(create_params);

  {
    Isolate::Scope isolate_scope(isolate);
    D8Console console(isolate);
    Shell::Initialize(isolate, &console, false);
    PerIsolateData data(isolate);

    for (int i = 0; i < Shell::options.stress_runs; ++i) {
      next_semaphore_.ParkedWait(
          reinterpret_cast<i::Isolate*>(isolate)->main_thread_local_isolate());
      {
        Global<Context> global_context;
        HandleScope scope(isolate);
        {
          Local<Context> context;
          if (!Shell::CreateEvaluationContext(isolate).ToLocal(&context)) {
            DCHECK(isolate->IsExecutionTerminating());
            break;
          }
          global_context.Reset(isolate, context);
        }
        PerIsolateData::RealmScope realm_scope(isolate, global_context);
        InspectorClient inspector_client(isolate, global_context,
                                         Shell::options.enable_inspector);
        {
          // We cannot use a Context::Scope here, as it keeps a local handle to
          // the context and SourceGroup::Execute may execute a non-nestable
          // task, e.g. a stackless GC.
          global_context.Get(isolate)->Enter();
          Execute(isolate);
          global_context.Get(isolate)->Exit();
        }
        Shell::FinishExecuting(isolate, global_context);
      }
      Shell::CollectGarbage(isolate);
      done_semaphore_.Signal();
    }

    Shell::ResetOnProfileEndListener(isolate);
  }

  isolate->Dispose();
}

void SourceGroup::StartExecuteInThread() {
  if (thread_ == nullptr) {
    thread_ = new IsolateThread(this);
    CHECK(thread_->Start());
  }
  next_semaphore_.Signal();
}

void SourceGroup::WaitForThread(const i::ParkedScope& parked) {
  if (thread_ == nullptr) return;
  done_semaphore_.ParkedWait(parked);
}

void SourceGroup::JoinThread(const i::ParkedScope& parked) {
  USE(parked);
  if (thread_ == nullptr) return;
  thread_->Join();
}

void SerializationDataQueue::Enqueue(std::unique_ptr<SerializationData> data) {
  base::MutexGuard lock_guard(&mutex_);
  data_.push_back(std::move(data));
}

bool SerializationDataQueue::Dequeue(
    std::unique_ptr<SerializationData>* out_data) {
  out_data->reset();
  base::MutexGuard lock_guard(&mutex_);
  if (data_.empty()) return false;
  *out_data = std::move(data_[0]);
  data_.erase(data_.begin());
  return true;
}

bool SerializationDataQueue::IsEmpty() {
  base::MutexGuard lock_guard(&mutex_);
  return data_.empty();
}

void SerializationDataQueue::Clear() {
  base::MutexGuard lock_guard(&mutex_);
  data_.clear();
}

Worker::Worker(Isolate* parent_isolate, const char* script)
    : script_(i::StrDup(script)), parent_isolate_(parent_isolate) {
  state_.store(State::kReady);
}

Worker::~Worker() {
  CHECK(state_.load() == State::kTerminated);
  DCHECK_NULL(isolate_);
  delete thread_;
  thread_ = nullptr;
  delete[] script_;
  script_ = nullptr;
}

bool Worker::is_running() const { return state_.load() == State::kRunning; }

bool Worker::StartWorkerThread(Isolate* requester,
                               std::shared_ptr<Worker> worker,
                               base::Thread::Priority priority) {
  auto expected = State::kReady;
  CHECK(
      worker->state_.compare_exchange_strong(expected, State::kPrepareRunning));
  auto thread = new WorkerThread(worker, priority);
  worker->thread_ = thread;
  if (!thread->Start()) return false;
  // Wait until the worker is ready to receive messages.
  worker->started_semaphore_.ParkedWait(
      reinterpret_cast<i::Isolate*>(requester)->main_thread_local_isolate());
  Shell::AddRunningWorker(std::move(worker));
  return true;
}

void Worker::WorkerThread::Run() {
  // Prevent a lifetime cycle from Worker -> WorkerThread -> Worker.
  // We must clear the worker_ field of the thread, but we keep the
  // worker alive via a stack root until the thread finishes execution
  // and removes itself from the running set. Thereafter the only
  // remaining reference can be from a JavaScript object via a Managed.
  auto worker = std::move(worker_);
  worker_ = nullptr;
  worker->ExecuteInThread();
  Shell::RemoveRunningWorker(worker);
}

class ProcessMessageTask : public i::CancelableTask {
 public:
  ProcessMessageTask(i::CancelableTaskManager* task_manager,
                     std::shared_ptr<Worker> worker,
                     std::unique_ptr<SerializationData> data)
      : i::CancelableTask(task_manager),
        worker_(worker),
        data_(std::move(data)) {}

  void RunInternal() override { worker_->ProcessMessage(std::move(data_)); }

 private:
  std::shared_ptr<Worker> worker_;
  std::unique_ptr<SerializationData> data_;
};

void Worker::PostMessage(std::unique_ptr<SerializationData> data) {
  base::MutexGuard lock_guard(&worker_mutex_);
  if (!is_running()) return;
  std::unique_ptr<v8::Task> task(new ProcessMessageTask(
      task_manager_, shared_from_this(), std::move(data)));
  task_runner_->PostNonNestableTask(std::move(task));
}

class TerminateTask : public i::CancelableTask {
 public:
  TerminateTask(i::CancelableTaskManager* task_manager,
                std::shared_ptr<Worker> worker)
      : i::CancelableTask(task_manager), worker_(worker) {}

  void RunInternal() override {
    auto expected = Worker::State::kTerminating;
    CHECK(worker_->state_.compare_exchange_strong(expected,
                                                  Worker::State::kTerminated));
  }

 private:
  std::shared_ptr<Worker> worker_;
};

std::unique_ptr<SerializationData> Worker::GetMessage(Isolate* requester) {
  std::unique_ptr<SerializationData> result;
  while (!out_queue_.Dequeue(&result)) {
    // If the worker is no longer running, and there are no messages in the
    // queue, don't expect any more messages from it.
    if (!is_running()) break;
    out_semaphore_.ParkedWait(
        reinterpret_cast<i::Isolate*>(requester)->main_thread_local_isolate());
  }
  return result;
}

std::unique_ptr<SerializationData> Worker::TryGetMessage() {
  std::unique_ptr<SerializationData> result;
  if (!out_queue_.Dequeue(&result)) {
    return nullptr;
  }
  return result;
}

void Worker::TerminateAndWaitForThread(const i::ParkedScope& parked) {
  USE(parked);
  Terminate();
  {
    base::MutexGuard lock_guard(&worker_mutex_);
    // Prevent double-joining.
    if (is_joined_) return;
    is_joined_ = true;
  }
  thread_->Join();
}

void Worker::Terminate() {
  base::MutexGuard lock_guard(&worker_mutex_);
  auto expected = State::kRunning;
  if (!state_.compare_exchange_strong(expected, State::kTerminating)) return;
  std::unique_ptr<v8::Task> task(
      new TerminateTask(task_manager_, shared_from_this()));
  task_runner_->PostTask(std::move(task));
  // Also schedule an interrupt in case the worker is running code and never
  // returning to the event queue. Since we checked the state before, and we are
  // holding the {worker_mutex_}, it's safe to access the isolate.
  isolate_->TerminateExecution();
}

void Worker::EnterTerminatedState() {
  base::MutexGuard lock_guard(&worker_mutex_);
  state_.store(State::kTerminated);
  CHECK(!is_running());
  task_runner_.reset();
  task_manager_ = nullptr;
}

void Worker::ProcessMessage(std::unique_ptr<SerializationData> data) {
  if (!is_running()) return;
  DCHECK_NOT_NULL(isolate_);
  HandleScope scope(isolate_);
  Local<Context> context = context_.Get(isolate_);
  Context::Scope context_scope(context);
  Local<Object> global = context->Global();

  // Get the message handler.
  MaybeLocal<Value> maybe_onmessage = global->Get(
      context, String::NewFromUtf8Literal(isolate_, "onmessage",
                                          NewStringType::kInternalized));
  Local<Value> onmessage;
  if (!maybe_onmessage.ToLocal(&onmessage) || !onmessage->IsFunction()) return;
  Local<Function> onmessage_fun = onmessage.As<Function>();

  v8::TryCatch try_catch(isolate_);
  try_catch.SetVerbose(true);
  Local<Value> value;
  if (Shell::DeserializeValue(isolate_, std::move(data)).ToLocal(&value)) {
    DCHECK(!isolate_->IsExecutionTerminating());
    Local<Object> event = Object::New(isolate_);
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
  if (isolate_->IsExecutionTerminating()) {
    // Re-schedule an interrupt in case the worker is going to run more code
    // and never return to the event queue.
    isolate_->TerminateExecution();
  }
}

void Worker::ProcessMessages() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate_);
  i::SaveAndSwitchContext saved_context(i_isolate, i::Context());
  SealHandleScope shs(isolate_);

  TryCatch try_catch(isolate_);
  try_catch.SetVerbose(true);

  while (is_running() && v8::platform::PumpMessageLoop(
                             g_default_platform, isolate_,
                             platform::MessageLoopBehavior::kWaitForWork)) {
    if (try_catch.HasCaught()) return;
    if (is_running()) {
      MicrotasksScope::PerformCheckpoint(isolate_);
    }
  }
}

// static
void Worker::SetCurrentWorker(Worker* worker) {
  CHECK_NULL(current_worker_);
  current_worker_ = worker;
}

// static
Worker* Worker::GetCurrentWorker() { return current_worker_; }

void Worker::ExecuteInThread() {
  Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = Shell::array_buffer_allocator;
  isolate_ = Isolate::New(create_params);

  // Make the Worker instance available to the whole thread.
  SetCurrentWorker(this);

  task_runner_ = g_default_platform->GetForegroundTaskRunner(isolate_);
  task_manager_ =
      reinterpret_cast<i::Isolate*>(isolate_)->cancelable_task_manager();

  auto expected = State::kPrepareRunning;
  CHECK(state_.compare_exchange_strong(expected, State::kRunning));

  // The Worker is now ready to receive messages.
  started_semaphore_.Signal();

  {
    Isolate::Scope isolate_scope(isolate_);
    D8Console console(isolate_);
    Shell::Initialize(isolate_, &console, false);
    PerIsolateData data(isolate_);

    CHECK(context_.IsEmpty());

    {
      HandleScope scope(isolate_);
      Local<Context> context;
      if (Shell::CreateEvaluationContext(isolate_).ToLocal(&context)) {
        context_.Reset(isolate_, context);
        CHECK(!context_.IsEmpty());
      }
    }

    if (!context_.IsEmpty()) {
      {
        bool success;
        PerIsolateData::RealmScope realm_scope(isolate_, context_);
        {
          HandleScope scope(isolate_);
          Local<Context> context = context_.Get(isolate_);
          Context::Scope context_scope(context);

          Local<Object> global = context->Global();
          Local<Value> this_value = External::New(isolate_, this);

          Local<FunctionTemplate> postmessage_fun_template =
              FunctionTemplate::New(isolate_, Worker::PostMessageOut,
                                    this_value);
          Local<Function> postmessage_fun;
          if (postmessage_fun_template->GetFunction(context).ToLocal(
                  &postmessage_fun)) {
            global
                ->Set(
                    context,
                    v8::String::NewFromUtf8Literal(
                        isolate_, "postMessage", NewStringType::kInternalized),
                    postmessage_fun)
                .FromJust();
          }

          Local<FunctionTemplate> close_fun_template =
              FunctionTemplate::New(isolate_, Worker::Close, this_value);
          Local<Function> close_fun;
          if (close_fun_template->GetFunction(context).ToLocal(&close_fun)) {
            global
                ->Set(context,
                      v8::String::NewFromUtf8Literal(
                          isolate_, "close", NewStringType::kInternalized),
                      close_fun)
                .FromJust();
          }

          Local<FunctionTemplate> importScripts_fun_template =
              FunctionTemplate::New(isolate_, Worker::ImportScripts,
                                    this_value);
          Local<Function> importScripts_fun;
          if (importScripts_fun_template->GetFunction(context).ToLocal(
                  &importScripts_fun)) {
            global
                ->Set(context,
                      v8::String::NewFromUtf8Literal(
                          isolate_, "importScripts",
                          NewStringType::kInternalized),
                      importScripts_fun)
                .FromJust();
          }

          // First run the script
          Local<String> file_name =
              String::NewFromUtf8Literal(isolate_, "unnamed");
          Local<String> source =
              String::NewFromUtf8(isolate_, script_).ToLocalChecked();
          success = Shell::ExecuteString(isolate_, source, file_name,
                                         Shell::kReportExceptions);
        }
        if (!Shell::FinishExecuting(isolate_, context_)) success = false;
        if (success) {
          bool handler_present;
          {
            HandleScope scope(isolate_);
            Local<Context> context = context_.Get(isolate_);
            Context::Scope context_scope(context);
            Local<Object> global = context->Global();
            // Check that there's a message handler
            MaybeLocal<Value> maybe_onmessage = global->Get(
                context,
                String::NewFromUtf8Literal(isolate_, "onmessage",
                                           NewStringType::kInternalized));
            Local<Value> onmessage;
            handler_present =
                maybe_onmessage.ToLocal(&onmessage) && onmessage->IsF
"""


```