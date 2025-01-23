Response: The user wants me to summarize the functionality of the C++ code in `v8/src/logging/log.cc`. This is the first part of a two-part file. I need to focus on what this part of the code is doing. I should also provide a JavaScript example if the functionality is related to JavaScript.

Looking at the includes, the code seems to be heavily involved in logging and profiling within the V8 engine. It deals with:

- **Code Events:**  Creation, movement, and disabling of optimized code.
- **Logging Mechanisms:**  Different types of loggers (basic, low-level, JIT).
- **Profiling:**  Sampling and recording execution data.
- **Integration with External Tools:**  Linux perf, ETW (Windows), external code event handlers.
- **WebAssembly:** Logging events related to WebAssembly code.

The code defines various classes for managing these tasks, like `CodeEventLogger`, `LinuxPerfBasicLogger`, `ExternalLogEventListener`, `LowLevelLogger`, `JitLogger`, `Profiler`, and `V8FileLogger`.

Since this is related to V8's internal workings and primarily focuses on logging and profiling, the connection to JavaScript is indirect. JavaScript code execution triggers these logging events. For example, when a JavaScript function is compiled, a `CodeCreateEvent` is likely logged. When the garbage collector moves code around, `CodeMoveEvent` or `BytecodeMoveEvent` might be logged.

Here's a conceptual JavaScript example to illustrate:

```javascript
function myFunction() {
  console.log("Hello from my function");
}

myFunction(); // This call might trigger code creation and execution logging in V8.
```

**Summary of Part 1:**

This part of the `log.cc` file in V8 defines the core infrastructure for logging and profiling engine activities. It provides various classes and methods for capturing events related to code creation, movement, optimization, and deoptimization. Different logging strategies are implemented, catering to specific needs like integration with system profiling tools (perf), low-level logging, and external event handling. It also includes components for sampling and recording execution data for profiling purposes. The code handles logging for both JavaScript and WebAssembly code.
这个C++源代码文件（`v8/src/logging/log.cc` 的第一部分）主要定义了 V8 JavaScript 引擎的**日志和性能分析**的基础框架和核心功能。它提供了多种机制来记录引擎的运行时状态和事件，主要集中在**代码事件**的记录和处理上。

具体来说，这部分代码的功能可以归纳为：

1. **定义了代码事件的结构和枚举:** 包括 `LogEventListener::CodeTag` (代码标签，如 Builtin, Function, Script 等) 和 `LogEventListener::Event` (日志事件类型，如代码创建、移动、禁用优化等)。这些枚举用于标识不同类型的代码活动。

2. **实现了多种代码事件记录器 (CodeEventLogger):**
   - **`CodeEventLogger`:**  作为基类，提供记录代码事件的基本接口，例如 `CodeCreateEvent` (代码创建事件) 和 `RegExpCodeCreateEvent` (正则表达式代码创建事件)。
   - **`LinuxPerfBasicLogger`:**  专门用于与 Linux 的 `perf` 工具集成，以特定格式输出代码信息，用于性能分析。
   - **`ExternalLogEventListener`:**  允许外部程序监听并处理 V8 的代码事件，提供了一个回调机制。
   - **`LowLevelLogger`:**  提供一种低级别的二进制日志记录方式，记录代码的创建和移动，用于更底层的性能分析。
   - **`JitLogger`:**  用于与 JIT 代码事件处理器交互，例如用于生成火焰图等性能分析工具所需的数据。
   - **`ETWJitLogger` (在 Windows 上):**  基于 `JitLogger`，将 JIT 代码事件发送到 Windows 的 ETW (Event Tracing for Windows) 系统。

3. **提供了用于格式化日志消息的工具:** 例如 `CodeEventLogger::NameBuffer` 类，用于构建代码事件的名称字符串。

4. **实现了用于性能采样的 `Profiler` 和 `Ticker` 类:**
   - **`Profiler`:**  负责收集执行时的堆栈信息 (通过 `TickSample`) 并将数据写入缓冲区，由独立的线程处理。
   - **`Ticker`:**  作为一个独立的线程，定期触发采样操作，并将采样结果传递给 `Profiler`。

5. **定义了 `V8FileLogger` 类 (在后续部分可能更详细):**  `V8FileLogger` 似乎是负责将各种日志事件写入到文件的主要类。这部分代码中已经包含了一些 `V8FileLogger` 的方法，例如 `ProfilerBeginEvent`, `StringEvent`, `CodeCreateEvent` 等，用于向日志文件写入特定格式的消息。

**与 JavaScript 的关系 (通过举例说明):**

尽管 `log.cc` 是 C++ 代码，但它记录的事件直接与 JavaScript 代码的执行相关。当 JavaScript 代码在 V8 引擎中运行时，会触发各种代码事件，这些事件会被 `log.cc` 中的记录器捕捉到。

例如，当 V8 编译一个 JavaScript 函数时，会触发 `CodeCreateEvent`。我们可以用一个简单的 JavaScript 函数来说明：

```javascript
function greet(name) {
  return "Hello, " + name + "!";
}

greet("World");
```

当 V8 执行这段代码时，可能会发生以下与 `log.cc` 中功能相关的事件：

1. **代码创建 (Code Creation):**  V8 的编译器（例如 Crankshaft 或 TurboFan）会将 `greet` 函数编译成机器码。这会触发 `CodeCreateEvent`，`log.cc` 会记录下新生成的代码的相关信息，例如代码的起始地址、大小、类型 (Function)、函数名 (`greet`) 等。`LinuxPerfBasicLogger` 可能会将这些信息以 `perf` 工具能识别的格式输出。`JitLogger` 可能会将这些信息传递给 JIT 代码事件处理器。

2. **代码移动 (Code Move):**  在垃圾回收过程中，V8 可能会移动已编译的代码。这会触发 `CodeMoveEvent` 或 `BytecodeMoveEvent` (如果移动的是字节码)，`log.cc` 会记录代码移动前后的地址。`LowLevelLogger` 会记录这些地址变化。

3. **代码优化与反优化 (Code Optimization/Deoptimization):**  V8 可能会对 `greet` 函数进行优化（例如内联）。这会涉及创建新的优化后的代码，并可能触发 `CodeCreateEvent`。如果后续发现优化不成立，会进行反优化，触发 `CodeDisableOptEvent`。

4. **性能采样 (Profiling):**  如果启用了性能分析，`Ticker` 线程会定期触发采样，`Profiler` 会记录下执行 `greet` 函数时的堆栈信息，包括当前的程序计数器 (PC) 和栈指针 (SP)。

总而言之，`v8/src/logging/log.cc` 的第一部分是 V8 引擎内部用于监控和分析 JavaScript 代码执行的关键组件，它记录了 JavaScript 代码在 V8 中编译、执行和优化的各种底层事件。 虽然我们不直接在 JavaScript 中操作这些功能，但 JavaScript 代码的运行会直接触发这些日志和性能分析事件。

### 提示词
```
这是目录为v8/src/logging/log.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/logging/log.h"

#include <atomic>
#include <cstdarg>
#include <memory>
#include <sstream>

#include "include/v8-locker.h"
#include "src/api/api-inl.h"
#include "src/base/functional.h"
#include "src/base/platform/mutex.h"
#include "src/base/platform/platform.h"
#include "src/base/platform/wrappers.h"
#include "src/builtins/profile-data-reader.h"
#include "src/codegen/bailout-reason.h"
#include "src/codegen/compiler.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/source-position-table.h"
#include "src/common/assert-scope.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/diagnostics/perf-jit.h"
#include "src/execution/isolate.h"
#include "src/execution/v8threads.h"
#include "src/execution/vm-state-inl.h"
#include "src/execution/vm-state.h"
#include "src/handles/global-handles.h"
#include "src/heap/combined-heap.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/init/bootstrapper.h"
#include "src/interpreter/bytecodes.h"
#include "src/interpreter/interpreter.h"
#include "src/libsampler/sampler.h"
#include "src/logging/code-events.h"
#include "src/logging/counters.h"
#include "src/logging/log-file.h"
#include "src/logging/log-inl.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/code-kind.h"
#include "src/objects/code.h"
#include "src/profiler/tick-sample.h"
#include "src/snapshot/embedded/embedded-data.h"
#include "src/strings/string-stream.h"
#include "src/strings/unicode-inl.h"
#include "src/tracing/tracing-category-observer.h"
#include "src/utils/memcopy.h"
#include "src/utils/version.h"

#ifdef ENABLE_GDB_JIT_INTERFACE
#include "src/diagnostics/gdb-jit.h"
#endif  // ENABLE_GDB_JIT_INTERFACE

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-import-wrapper-cache.h"
#include "src/wasm/wasm-objects-inl.h"
#endif  // V8_ENABLE_WEBASSEMBLY

#if V8_OS_WIN
#if defined(V8_ENABLE_ETW_STACK_WALKING)
#include "src/diagnostics/etw-jit-win.h"
#endif
#endif  // V8_OS_WIN

namespace v8 {
namespace internal {

static const char* kLogEventsNames[] = {
#define DECLARE_EVENT(ignore1, name) name,
    LOG_EVENT_LIST(DECLARE_EVENT)
#undef DECLARE_EVENT
};
static const char* kCodeTagNames[] = {
#define DECLARE_EVENT(ignore1, name) #name,
    CODE_TYPE_LIST(DECLARE_EVENT)
#undef DECLARE_EVENT
};

std::ostream& operator<<(std::ostream& os, LogEventListener::CodeTag tag) {
  os << kCodeTagNames[static_cast<int>(tag)];
  return os;
}
std::ostream& operator<<(std::ostream& os, LogEventListener::Event event) {
  os << kLogEventsNames[static_cast<int>(event)];
  return os;
}

namespace {

v8::CodeEventType GetCodeEventTypeForTag(LogEventListener::CodeTag tag) {
  switch (tag) {
    case LogEventListener::CodeTag::kLength:
    // Manually create this switch, since v8::CodeEventType is API expose and
    // cannot be easily modified.
    case LogEventListener::CodeTag::kBuiltin:
      return v8::CodeEventType::kBuiltinType;
    case LogEventListener::CodeTag::kCallback:
      return v8::CodeEventType::kCallbackType;
    case LogEventListener::CodeTag::kEval:
      return v8::CodeEventType::kEvalType;
    case LogEventListener::CodeTag::kNativeFunction:
    case LogEventListener::CodeTag::kFunction:
      return v8::CodeEventType::kFunctionType;
    case LogEventListener::CodeTag::kHandler:
      return v8::CodeEventType::kHandlerType;
    case LogEventListener::CodeTag::kBytecodeHandler:
      return v8::CodeEventType::kBytecodeHandlerType;
    case LogEventListener::CodeTag::kRegExp:
      return v8::CodeEventType::kRegExpType;
    case LogEventListener::CodeTag::kNativeScript:
    case LogEventListener::CodeTag::kScript:
      return v8::CodeEventType::kScriptType;
    case LogEventListener::CodeTag::kStub:
      return v8::CodeEventType::kStubType;
  }
  UNREACHABLE();
}

#define CALL_CODE_EVENT_HANDLER(Call) \
  if (listener_) {                    \
    listener_->Call;                  \
  } else {                            \
    PROFILE(isolate_, Call);          \
  }

const char* ComputeMarker(Tagged<SharedFunctionInfo> shared,
                          Tagged<AbstractCode> code) {
  PtrComprCageBase cage_base = GetPtrComprCageBase(shared);
  CodeKind kind = code->kind(cage_base);
  // We record interpreter trampoline builtin copies as having the
  // "interpreted" marker.
  if (v8_flags.interpreted_frames_native_stack && kind == CodeKind::BUILTIN &&
      code->has_instruction_stream(cage_base)) {
    DCHECK_EQ(code->builtin_id(cage_base),
              Builtin::kInterpreterEntryTrampoline);
    kind = CodeKind::INTERPRETED_FUNCTION;
  }
  if (shared->optimization_disabled() &&
      kind == CodeKind::INTERPRETED_FUNCTION) {
    return "";
  }
  return CodeKindToMarker(kind);
}

#if V8_ENABLE_WEBASSEMBLY
const char* ComputeMarker(const wasm::WasmCode* code) {
  switch (code->kind()) {
    case wasm::WasmCode::kWasmFunction:
      return code->is_liftoff() ? "" : "*";
    default:
      return "";
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace

class CodeEventLogger::NameBuffer {
 public:
  NameBuffer() { Reset(); }

  void Reset() { utf8_pos_ = 0; }

  void Init(CodeTag tag) {
    Reset();
    AppendBytes(kCodeTagNames[static_cast<int>(tag)]);
    AppendByte(':');
  }

  void AppendName(Tagged<Name> name) {
    if (IsString(name)) {
      AppendString(Cast<String>(name));
    } else {
      Tagged<Symbol> symbol = Cast<Symbol>(name);
      AppendBytes("symbol(");
      if (!IsUndefined(symbol->description())) {
        AppendBytes("\"");
        AppendString(Cast<String>(symbol->description()));
        AppendBytes("\" ");
      }
      AppendBytes("hash ");
      AppendHex(symbol->hash());
      AppendByte(')');
    }
  }

  void AppendString(Tagged<String> str) {
    if (str.is_null()) return;
    size_t length = 0;
    std::unique_ptr<char[]> c_str = str->ToCString(&length);
    AppendBytes(c_str.get(), length);
  }

  void AppendBytes(const char* bytes, size_t size) {
    size = std::min(size, kUtf8BufferSize - utf8_pos_);
    MemCopy(utf8_buffer_ + utf8_pos_, bytes, size);
    utf8_pos_ += size;
  }

  void AppendBytes(const char* bytes) {
    size_t len = strlen(bytes);
    DCHECK_GE(kMaxInt, len);
    AppendBytes(bytes, static_cast<int>(len));
  }

  void AppendByte(char c) {
    if (utf8_pos_ >= kUtf8BufferSize) return;
    utf8_buffer_[utf8_pos_++] = c;
  }

  void AppendInt(int n) {
    if (utf8_pos_ >= kUtf8BufferSize) return;
    size_t space = kUtf8BufferSize - utf8_pos_;
    base::Vector<char> buffer(utf8_buffer_ + utf8_pos_, space);
    int size = SNPrintF(buffer, "%d", n);
    if (size > 0 && utf8_pos_ + size <= kUtf8BufferSize) {
      utf8_pos_ += size;
    }
  }

  void AppendHex(uint32_t n) {
    if (utf8_pos_ >= kUtf8BufferSize) return;
    size_t space = kUtf8BufferSize - utf8_pos_;
    base::Vector<char> buffer(utf8_buffer_ + utf8_pos_, space);
    int size = SNPrintF(buffer, "%x", n);
    if (size > 0 && utf8_pos_ + size <= kUtf8BufferSize) {
      utf8_pos_ += size;
    }
  }

  const char* get() { return utf8_buffer_; }
  size_t size() const { return utf8_pos_; }

 private:
  static const size_t kUtf8BufferSize = 4096;
  static const size_t kUtf16BufferSize = kUtf8BufferSize;

  size_t utf8_pos_;
  char utf8_buffer_[kUtf8BufferSize];
};

CodeEventLogger::CodeEventLogger(Isolate* isolate)
    : isolate_(isolate), name_buffer_(std::make_unique<NameBuffer>()) {}

CodeEventLogger::~CodeEventLogger() = default;

void CodeEventLogger::CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                                      const char* comment) {
  DCHECK(is_listening_to_code_events());
  name_buffer_->Init(tag);
  name_buffer_->AppendBytes(comment);
  DisallowGarbageCollection no_gc;
  LogRecordedBuffer(*code, MaybeHandle<SharedFunctionInfo>(),
                    name_buffer_->get(), name_buffer_->size());
}

void CodeEventLogger::CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                                      Handle<Name> name) {
  DCHECK(is_listening_to_code_events());
  name_buffer_->Init(tag);
  name_buffer_->AppendName(*name);
  DisallowGarbageCollection no_gc;
  LogRecordedBuffer(*code, MaybeHandle<SharedFunctionInfo>(),
                    name_buffer_->get(), name_buffer_->size());
}

void CodeEventLogger::CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                                      Handle<SharedFunctionInfo> shared,
                                      Handle<Name> script_name) {
  DCHECK(is_listening_to_code_events());
  name_buffer_->Init(tag);
  name_buffer_->AppendBytes(ComputeMarker(*shared, *code));
  name_buffer_->AppendByte(' ');
  name_buffer_->AppendName(*script_name);
  DisallowGarbageCollection no_gc;
  LogRecordedBuffer(*code, shared, name_buffer_->get(), name_buffer_->size());
}

void CodeEventLogger::CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                                      Handle<SharedFunctionInfo> shared,
                                      Handle<Name> script_name, int line,
                                      int column) {
  DCHECK(is_listening_to_code_events());
  name_buffer_->Init(tag);
  name_buffer_->AppendBytes(ComputeMarker(*shared, *code));
  name_buffer_->AppendBytes(shared->DebugNameCStr().get());
  name_buffer_->AppendByte(' ');
  if (IsString(*script_name)) {
    name_buffer_->AppendString(Cast<String>(*script_name));
  } else {
    name_buffer_->AppendBytes("symbol(hash ");
    name_buffer_->AppendHex(Cast<Name>(*script_name)->hash());
    name_buffer_->AppendByte(')');
  }
  name_buffer_->AppendByte(':');
  name_buffer_->AppendInt(line);
  name_buffer_->AppendByte(':');
  name_buffer_->AppendInt(column);
  DisallowGarbageCollection no_gc;
  LogRecordedBuffer(*code, shared, name_buffer_->get(), name_buffer_->size());
}

#if V8_ENABLE_WEBASSEMBLY
void CodeEventLogger::CodeCreateEvent(CodeTag tag, const wasm::WasmCode* code,
                                      wasm::WasmName name,
                                      const char* source_url,
                                      int /*code_offset*/, int /*script_id*/) {
  DCHECK(is_listening_to_code_events());
  name_buffer_->Init(tag);
  DCHECK(!name.empty());
  name_buffer_->AppendBytes(name.begin(), name.length());
  name_buffer_->AppendByte('-');
  if (code->IsAnonymous()) {
    name_buffer_->AppendBytes("<anonymous>");
  } else {
    name_buffer_->AppendInt(code->index());
  }
  name_buffer_->AppendByte('-');
  name_buffer_->AppendBytes(ExecutionTierToString(code->tier()));
  DisallowGarbageCollection no_gc;
  LogRecordedBuffer(code, name_buffer_->get(), name_buffer_->size());
}
#endif  // V8_ENABLE_WEBASSEMBLY

void CodeEventLogger::RegExpCodeCreateEvent(Handle<AbstractCode> code,
                                            Handle<String> source,
                                            RegExpFlags flags) {
  DCHECK(is_listening_to_code_events());
  // Note we don't call Init due to the required pprof demangling hack for
  // regexp patterns.
  name_buffer_->Reset();
  // https://github.com/google/pprof/blob/4cf4322d492d108a9d6526d10844e04792982cbb/internal/symbolizer/symbolizer.go#L312.
  name_buffer_->AppendBytes("RegExp.>");
  name_buffer_->AppendBytes(" src: '");
  name_buffer_->AppendString(*source);
  name_buffer_->AppendBytes("' flags: '");
  Handle<String> flags_str =
      JSRegExp::StringFromFlags(isolate_, JSRegExp::AsJSRegExpFlags(flags));
  name_buffer_->AppendString(*flags_str);
  name_buffer_->AppendBytes("'");
  DisallowGarbageCollection no_gc;
  LogRecordedBuffer(*code, MaybeHandle<SharedFunctionInfo>(),
                    name_buffer_->get(), name_buffer_->size());
}

// Linux perf tool logging support.
#if V8_OS_LINUX
class LinuxPerfBasicLogger : public CodeEventLogger {
 public:
  explicit LinuxPerfBasicLogger(Isolate* isolate);
  ~LinuxPerfBasicLogger() override;

  void CodeMoveEvent(Tagged<InstructionStream> from,
                     Tagged<InstructionStream> to) override {}
  void BytecodeMoveEvent(Tagged<BytecodeArray> from,
                         Tagged<BytecodeArray> to) override {}
  void CodeDisableOptEvent(Handle<AbstractCode> code,
                           Handle<SharedFunctionInfo> shared) override {}

 private:
  void LogRecordedBuffer(Tagged<AbstractCode> code,
                         MaybeHandle<SharedFunctionInfo> maybe_shared,
                         const char* name, size_t length) override;
#if V8_ENABLE_WEBASSEMBLY
  void LogRecordedBuffer(const wasm::WasmCode* code, const char* name,
                         size_t length) override;
#endif  // V8_ENABLE_WEBASSEMBLY
  void WriteLogRecordedBuffer(uintptr_t address, size_t size, const char* name,
                              size_t name_length);

  static base::LazyRecursiveMutex& GetFileMutex();

  // Extension added to V8 log file name to get the low-level log name.
  static const char kFilenameFormatString[];
  static const int kFilenameBufferPadding;

  // Per-process singleton file. We assume that there is one main isolate
  // to determine when it goes away, we keep the reference count.
  static FILE* perf_output_handle_;
  static uint64_t reference_count_;
};

// Extra space for the "perf-%d.map" filename, including the PID.
const int LinuxPerfBasicLogger::kFilenameBufferPadding = 32;

// static
base::LazyRecursiveMutex& LinuxPerfBasicLogger::GetFileMutex() {
  static base::LazyRecursiveMutex file_mutex = LAZY_RECURSIVE_MUTEX_INITIALIZER;
  return file_mutex;
}

// The following static variables are protected by
// LinuxPerfBasicLogger::GetFileMutex().
uint64_t LinuxPerfBasicLogger::reference_count_ = 0;
FILE* LinuxPerfBasicLogger::perf_output_handle_ = nullptr;

LinuxPerfBasicLogger::LinuxPerfBasicLogger(Isolate* isolate)
    : CodeEventLogger(isolate) {
  base::LockGuard<base::RecursiveMutex> guard_file(GetFileMutex().Pointer());
  int process_id_ = base::OS::GetCurrentProcessId();
  reference_count_++;
  // If this is the first logger, open the file.
  if (reference_count_ == 1) {
    CHECK_NULL(perf_output_handle_);
    CHECK_NOT_NULL(v8_flags.perf_basic_prof_path);
    const char* base_dir = v8_flags.perf_basic_prof_path;
    // Open the perf JIT dump file.
    base::ScopedVector<char> perf_dump_name(strlen(base_dir) +
                                            kFilenameBufferPadding);
    int size =
        SNPrintF(perf_dump_name, "%s/perf-%d.map", base_dir, process_id_);
    CHECK_NE(size, -1);
    perf_output_handle_ =
        base::OS::FOpen(perf_dump_name.begin(), base::OS::LogFileOpenMode);
    CHECK_NOT_NULL(perf_output_handle_);
    setvbuf(perf_output_handle_, nullptr, _IOLBF, 0);
  }
}

LinuxPerfBasicLogger::~LinuxPerfBasicLogger() {
  base::LockGuard<base::RecursiveMutex> guard_file(GetFileMutex().Pointer());
  reference_count_--;

  // If this was the last logger, close the file.
  if (reference_count_ == 0) {
    CHECK_NOT_NULL(perf_output_handle_);
    base::Fclose(perf_output_handle_);
    perf_output_handle_ = nullptr;
  }
}

void LinuxPerfBasicLogger::WriteLogRecordedBuffer(uintptr_t address,
                                                  size_t size, const char* name,
                                                  size_t name_length) {
  // Linux perf expects hex literals without a leading 0x, while some
  // implementations of printf might prepend one when using the %p format
  // for pointers, leading to wrongly formatted JIT symbols maps. On the other
  // hand, Android's simpleperf does expect a leading 0x.
  //
  // Instead, we use V8PRIxPTR format string and cast pointer to uintpr_t,
  // so that we have control over the exact output format.
  int int_name_length = static_cast<int>(name_length);
#ifdef V8_OS_ANDROID
  base::OS::FPrint(perf_output_handle_, "0x%" V8PRIxPTR " 0x%zx %.*s\n",
                   address, size, int_name_length, name);
#else
  base::OS::FPrint(perf_output_handle_, "%" V8PRIxPTR " %zx %.*s\n", address,
                   size, int_name_length, name);
#endif
}

void LinuxPerfBasicLogger::LogRecordedBuffer(Tagged<AbstractCode> code,
                                             MaybeHandle<SharedFunctionInfo>,
                                             const char* name, size_t length) {
  DisallowGarbageCollection no_gc;
  PtrComprCageBase cage_base(isolate_);
  if (v8_flags.perf_basic_prof_only_functions &&
      !CodeKindIsBuiltinOrJSFunction(code->kind(cage_base))) {
    return;
  }

  WriteLogRecordedBuffer(
      static_cast<uintptr_t>(code->InstructionStart(cage_base)),
      code->InstructionSize(cage_base), name, length);
}

#if V8_ENABLE_WEBASSEMBLY
void LinuxPerfBasicLogger::LogRecordedBuffer(const wasm::WasmCode* code,
                                             const char* name, size_t length) {
  WriteLogRecordedBuffer(static_cast<uintptr_t>(code->instruction_start()),
                         code->instructions().length(), name, length);
}
#endif  // V8_ENABLE_WEBASSEMBLY
#endif  // V8_OS_LINUX

// External LogEventListener
ExternalLogEventListener::ExternalLogEventListener(Isolate* isolate)
    : is_listening_(false), isolate_(isolate), code_event_handler_(nullptr) {}

ExternalLogEventListener::~ExternalLogEventListener() {
  if (is_listening_) {
    StopListening();
  }
}

void ExternalLogEventListener::LogExistingCode() {
  HandleScope scope(isolate_);
  ExistingCodeLogger logger(isolate_, this);
  logger.LogBuiltins();
  logger.LogCodeObjects();
  logger.LogCompiledFunctions();
}

void ExternalLogEventListener::StartListening(
    CodeEventHandler* code_event_handler) {
  if (is_listening_ || code_event_handler == nullptr) {
    return;
  }
  code_event_handler_ = code_event_handler;
  is_listening_ = isolate_->logger()->AddListener(this);
  if (is_listening_) {
    LogExistingCode();
  }
}

void ExternalLogEventListener::StopListening() {
  if (!is_listening_) {
    return;
  }

  isolate_->logger()->RemoveListener(this);
  is_listening_ = false;
}

void ExternalLogEventListener::CodeCreateEvent(CodeTag tag,
                                               Handle<AbstractCode> code,
                                               const char* comment) {
  PtrComprCageBase cage_base(isolate_);
  CodeEvent code_event;
  code_event.code_start_address =
      static_cast<uintptr_t>(code->InstructionStart(cage_base));
  code_event.code_size = static_cast<size_t>(code->InstructionSize(cage_base));
  code_event.function_name = isolate_->factory()->empty_string();
  code_event.script_name = isolate_->factory()->empty_string();
  code_event.script_line = 0;
  code_event.script_column = 0;
  code_event.code_type = GetCodeEventTypeForTag(tag);
  code_event.comment = comment;

  code_event_handler_->Handle(reinterpret_cast<v8::CodeEvent*>(&code_event));
}

void ExternalLogEventListener::CodeCreateEvent(CodeTag tag,
                                               Handle<AbstractCode> code,
                                               Handle<Name> name) {
  Handle<String> name_string =
      Name::ToFunctionName(isolate_, name).ToHandleChecked();

  PtrComprCageBase cage_base(isolate_);
  CodeEvent code_event;
  code_event.code_start_address =
      static_cast<uintptr_t>(code->InstructionStart(cage_base));
  code_event.code_size = static_cast<size_t>(code->InstructionSize(cage_base));
  code_event.function_name = name_string;
  code_event.script_name = isolate_->factory()->empty_string();
  code_event.script_line = 0;
  code_event.script_column = 0;
  code_event.code_type = GetCodeEventTypeForTag(tag);
  code_event.comment = "";

  code_event_handler_->Handle(reinterpret_cast<v8::CodeEvent*>(&code_event));
}

void ExternalLogEventListener::CodeCreateEvent(
    CodeTag tag, Handle<AbstractCode> code, Handle<SharedFunctionInfo> shared,
    Handle<Name> name) {
  Handle<String> name_string =
      Name::ToFunctionName(isolate_, name).ToHandleChecked();

  PtrComprCageBase cage_base(isolate_);
  CodeEvent code_event;
  code_event.code_start_address =
      static_cast<uintptr_t>(code->InstructionStart(cage_base));
  code_event.code_size = static_cast<size_t>(code->InstructionSize(cage_base));
  code_event.function_name = name_string;
  code_event.script_name = isolate_->factory()->empty_string();
  code_event.script_line = 0;
  code_event.script_column = 0;
  code_event.code_type = GetCodeEventTypeForTag(tag);
  code_event.comment = "";

  code_event_handler_->Handle(reinterpret_cast<v8::CodeEvent*>(&code_event));
}

void ExternalLogEventListener::CodeCreateEvent(
    CodeTag tag, Handle<AbstractCode> code, Handle<SharedFunctionInfo> shared,
    Handle<Name> source, int line, int column) {
  Handle<String> name_string =
      Name::ToFunctionName(isolate_, handle(shared->Name(), isolate_))
          .ToHandleChecked();
  Handle<String> source_string =
      Name::ToFunctionName(isolate_, source).ToHandleChecked();

  PtrComprCageBase cage_base(isolate_);
  CodeEvent code_event;
  code_event.code_start_address =
      static_cast<uintptr_t>(code->InstructionStart(cage_base));
  code_event.code_size = static_cast<size_t>(code->InstructionSize(cage_base));
  code_event.function_name = name_string;
  code_event.script_name = source_string;
  code_event.script_line = line;
  code_event.script_column = column;
  code_event.code_type = GetCodeEventTypeForTag(tag);
  code_event.comment = "";

  code_event_handler_->Handle(reinterpret_cast<v8::CodeEvent*>(&code_event));
}

#if V8_ENABLE_WEBASSEMBLY
void ExternalLogEventListener::CodeCreateEvent(CodeTag tag,
                                               const wasm::WasmCode* code,
                                               wasm::WasmName name,
                                               const char* source_url,
                                               int code_offset, int script_id) {
  // TODO(mmarchini): handle later
}
#endif  // V8_ENABLE_WEBASSEMBLY

void ExternalLogEventListener::RegExpCodeCreateEvent(Handle<AbstractCode> code,
                                                     Handle<String> source,
                                                     RegExpFlags flags) {
  PtrComprCageBase cage_base(isolate_);
  CodeEvent code_event;
  code_event.code_start_address =
      static_cast<uintptr_t>(code->InstructionStart(cage_base));
  code_event.code_size = static_cast<size_t>(code->InstructionSize(cage_base));
  code_event.function_name = source;
  code_event.script_name = isolate_->factory()->empty_string();
  code_event.script_line = 0;
  code_event.script_column = 0;
  code_event.code_type =
      GetCodeEventTypeForTag(LogEventListener::CodeTag::kRegExp);
  code_event.comment = "";

  code_event_handler_->Handle(reinterpret_cast<v8::CodeEvent*>(&code_event));
}

namespace {

void InitializeCodeEvent(Isolate* isolate, CodeEvent* event,
                         Address previous_code_start_address,
                         Address code_start_address, int code_size) {
  event->previous_code_start_address =
      static_cast<uintptr_t>(previous_code_start_address);
  event->code_start_address = static_cast<uintptr_t>(code_start_address);
  event->code_size = static_cast<size_t>(code_size);
  event->function_name = isolate->factory()->empty_string();
  event->script_name = isolate->factory()->empty_string();
  event->script_line = 0;
  event->script_column = 0;
  event->code_type = v8::CodeEventType::kRelocationType;
  event->comment = "";
}

}  // namespace

void ExternalLogEventListener::CodeMoveEvent(Tagged<InstructionStream> from,
                                             Tagged<InstructionStream> to) {
  CodeEvent code_event;
  InitializeCodeEvent(isolate_, &code_event, from->instruction_start(),
                      to->instruction_start(),
                      to->code(kAcquireLoad)->instruction_size());
  code_event_handler_->Handle(reinterpret_cast<v8::CodeEvent*>(&code_event));
}

void ExternalLogEventListener::BytecodeMoveEvent(Tagged<BytecodeArray> from,
                                                 Tagged<BytecodeArray> to) {
  CodeEvent code_event;
  InitializeCodeEvent(isolate_, &code_event, from->GetFirstBytecodeAddress(),
                      to->GetFirstBytecodeAddress(), to->length());
  code_event_handler_->Handle(reinterpret_cast<v8::CodeEvent*>(&code_event));
}

// Low-level logging support.
class LowLevelLogger : public CodeEventLogger {
 public:
  LowLevelLogger(Isolate* isolate, const char* file_name);
  ~LowLevelLogger() override;

  void CodeMoveEvent(Tagged<InstructionStream> from,
                     Tagged<InstructionStream> to) override;
  void BytecodeMoveEvent(Tagged<BytecodeArray> from,
                         Tagged<BytecodeArray> to) override;
  void CodeDisableOptEvent(Handle<AbstractCode> code,
                           Handle<SharedFunctionInfo> shared) override {}
  void SnapshotPositionEvent(Tagged<HeapObject> obj, int pos);
  void CodeMovingGCEvent() override;

 private:
  void LogRecordedBuffer(Tagged<AbstractCode> code,
                         MaybeHandle<SharedFunctionInfo> maybe_shared,
                         const char* name, size_t length) override;
#if V8_ENABLE_WEBASSEMBLY
  void LogRecordedBuffer(const wasm::WasmCode* code, const char* name,
                         size_t length) override;
#endif  // V8_ENABLE_WEBASSEMBLY

  // Low-level profiling event structures.
  struct CodeCreateStruct {
    static const char kTag = 'C';

    int32_t name_size;
    Address code_address;
    int32_t code_size;
  };

  struct CodeMoveStruct {
    static const char kTag = 'M';

    Address from_address;
    Address to_address;
  };

  static const char kCodeMovingGCTag = 'G';

  // Extension added to V8 log file name to get the low-level log name.
  static const char kLogExt[];

  void LogCodeInfo();
  void LogWriteBytes(const char* bytes, size_t size);

  template <typename T>
  void LogWriteStruct(const T& s) {
    char tag = T::kTag;
    LogWriteBytes(reinterpret_cast<const char*>(&tag), sizeof(tag));
    LogWriteBytes(reinterpret_cast<const char*>(&s), sizeof(s));
  }

  FILE* ll_output_handle_;
};

const char LowLevelLogger::kLogExt[] = ".ll";

LowLevelLogger::LowLevelLogger(Isolate* isolate, const char* name)
    : CodeEventLogger(isolate), ll_output_handle_(nullptr) {
  // Open the low-level log file.
  size_t len = strlen(name);
  base::ScopedVector<char> ll_name(static_cast<int>(len + sizeof(kLogExt)));
  MemCopy(ll_name.begin(), name, len);
  MemCopy(ll_name.begin() + len, kLogExt, sizeof(kLogExt));
  ll_output_handle_ =
      base::OS::FOpen(ll_name.begin(), base::OS::LogFileOpenMode);
  setvbuf(ll_output_handle_, nullptr, _IOLBF, 0);

  LogCodeInfo();
}

LowLevelLogger::~LowLevelLogger() {
  base::Fclose(ll_output_handle_);
  ll_output_handle_ = nullptr;
}

void LowLevelLogger::LogCodeInfo() {
#if V8_TARGET_ARCH_IA32
  const char arch[] = "ia32";
#elif V8_TARGET_ARCH_X64 && V8_TARGET_ARCH_64_BIT
  const char arch[] = "x64";
#elif V8_TARGET_ARCH_ARM
  const char arch[] = "arm";
#elif V8_TARGET_ARCH_PPC64
  const char arch[] = "ppc64";
#elif V8_TARGET_ARCH_LOONG64
  const char arch[] = "loong64";
#elif V8_TARGET_ARCH_ARM64
  const char arch[] = "arm64";
#elif V8_TARGET_ARCH_S390X
  const char arch[] = "s390x";
#elif V8_TARGET_ARCH_RISCV64
  const char arch[] = "riscv64";
#elif V8_TARGET_ARCH_RISCV32
  const char arch[] = "riscv32";
#else
  const char arch[] = "unknown";
#endif
  LogWriteBytes(arch, sizeof(arch));
}

void LowLevelLogger::LogRecordedBuffer(Tagged<AbstractCode> code,
                                       MaybeHandle<SharedFunctionInfo>,
                                       const char* name, size_t length) {
  DisallowGarbageCollection no_gc;
  PtrComprCageBase cage_base(isolate_);
  CodeCreateStruct event;
  event.name_size = static_cast<uint32_t>(length);
  event.code_address = code->InstructionStart(cage_base);
  event.code_size = code->InstructionSize(cage_base);
  LogWriteStruct(event);
  LogWriteBytes(name, length);
  LogWriteBytes(
      reinterpret_cast<const char*>(code->InstructionStart(cage_base)),
      code->InstructionSize(cage_base));
}

#if V8_ENABLE_WEBASSEMBLY
void LowLevelLogger::LogRecordedBuffer(const wasm::WasmCode* code,
                                       const char* name, size_t length) {
  CodeCreateStruct event;
  event.name_size = static_cast<uint32_t>(length);
  event.code_address = code->instruction_start();
  event.code_size = code->instructions().length();
  LogWriteStruct(event);
  LogWriteBytes(name, length);
  LogWriteBytes(reinterpret_cast<const char*>(code->instruction_start()),
                code->instructions().length());
}
#endif  // V8_ENABLE_WEBASSEMBLY

void LowLevelLogger::CodeMoveEvent(Tagged<InstructionStream> from,
                                   Tagged<InstructionStream> to) {
  CodeMoveStruct event;
  event.from_address = from->instruction_start();
  event.to_address = to->instruction_start();
  LogWriteStruct(event);
}

void LowLevelLogger::BytecodeMoveEvent(Tagged<BytecodeArray> from,
                                       Tagged<BytecodeArray> to) {
  CodeMoveStruct event;
  event.from_address = from->GetFirstBytecodeAddress();
  event.to_address = to->GetFirstBytecodeAddress();
  LogWriteStruct(event);
}

void LowLevelLogger::LogWriteBytes(const char* bytes, size_t size) {
  size_t rv = fwrite(bytes, 1, size, ll_output_handle_);
  DCHECK_EQ(size, rv);
  USE(rv);
}

void LowLevelLogger::CodeMovingGCEvent() {
  const char tag = kCodeMovingGCTag;

  LogWriteBytes(&tag, sizeof(tag));
}

class JitLogger : public CodeEventLogger {
 public:
  JitLogger(Isolate* isolate, JitCodeEventHandler code_event_handler);

  void CodeMoveEvent(Tagged<InstructionStream> from,
                     Tagged<InstructionStream> to) override;
  void BytecodeMoveEvent(Tagged<BytecodeArray> from,
                         Tagged<BytecodeArray> to) override;
  void CodeDisableOptEvent(Handle<AbstractCode> code,
                           Handle<SharedFunctionInfo> shared) override {}
  void AddCodeLinePosInfoEvent(void* jit_handler_data, int pc_offset,
                               int position,
                               JitCodeEvent::PositionType position_type,
                               JitCodeEvent::CodeType code_type);

  void* StartCodePosInfoEvent(JitCodeEvent::CodeType code_type);
  void EndCodePosInfoEvent(Address start_address, void* jit_handler_data,
                           JitCodeEvent::CodeType code_type);

 private:
  void LogRecordedBuffer(Tagged<AbstractCode> code,
                         MaybeHandle<SharedFunctionInfo> maybe_shared,
                         const char* name, size_t length) override;
#if V8_ENABLE_WEBASSEMBLY
  void LogRecordedBuffer(const wasm::WasmCode* code, const char* name,
                         size_t length) override;
#endif  // V8_ENABLE_WEBASSEMBLY

  JitCodeEventHandler code_event_handler_;
  base::Mutex logger_mutex_;
};

JitLogger::JitLogger(Isolate* isolate, JitCodeEventHandler code_event_handler)
    : CodeEventLogger(isolate), code_event_handler_(code_event_handler) {
  DCHECK_NOT_NULL(code_event_handler);
}

void JitLogger::LogRecordedBuffer(Tagged<AbstractCode> code,
                                  MaybeHandle<SharedFunctionInfo> maybe_shared,
                                  const char* name, size_t length) {
  DisallowGarbageCollection no_gc;
  PtrComprCageBase cage_base(isolate_);
  JitCodeEvent event;
  event.type = JitCodeEvent::CODE_ADDED;
  event.code_start = reinterpret_cast<void*>(code->InstructionStart(cage_base));
  event.code_type = IsCode(code, cage_base) ? JitCodeEvent::JIT_CODE
                                            : JitCodeEvent::BYTE_CODE;
  event.code_len = code->InstructionSize(cage_base);
  Handle<SharedFunctionInfo> shared;
  if (maybe_shared.ToHandle(&shared) &&
      IsScript(shared->script(cage_base), cage_base)) {
    event.script = ToApiHandle<v8::UnboundScript>(shared);
  } else {
    event.script = Local<v8::UnboundScript>();
  }
  event.name.str = name;
  event.name.len = length;
  event.isolate = reinterpret_cast<v8::Isolate*>(isolate_);
  code_event_handler_(&event);
}

#if V8_ENABLE_WEBASSEMBLY
void JitLogger::LogRecordedBuffer(const wasm::WasmCode* code, const char* name,
                                  size_t length) {
  JitCodeEvent event;
  event.type = JitCodeEvent::CODE_ADDED;
  event.code_type = JitCodeEvent::WASM_CODE;
  event.code_start = code->instructions().begin();
  event.code_len = code->instructions().length();
  event.name.str = name;
  event.name.len = length;
  event.isolate = reinterpret_cast<v8::Isolate*>(isolate_);

  if (!code->IsAnonymous()) {  // Skip for WasmCode::Kind::kWasmToJsWrapper.
    wasm::WasmModuleSourceMap* source_map =
        code->native_module()->GetWasmSourceMap();
    wasm::WireBytesRef code_ref =
        code->native_module()->module()->functions[code->index()].code;
    uint32_t code_offset = code_ref.offset();
    uint32_t code_end_offset = code_ref.end_offset();

    std::vector<v8::JitCodeEvent::line_info_t> mapping_info;
    std::string filename;
    std::unique_ptr<JitCodeEvent::wasm_source_info_t> wasm_source_info;

    if (source_map && source_map->IsValid() &&
        source_map->HasSource(code_offset, code_end_offset)) {
      size_t last_line_number = 0;

      for (SourcePositionTableIterator iterator(code->source_positions());
           !iterator.done(); iterator.Advance()) {
        uint32_t offset =
            iterator.source_position().ScriptOffset() + code_offset;
        if (!source_map->HasValidEntry(code_offset, offset)) continue;
        if (filename.empty()) {
          filename = source_map->GetFilename(offset);
        }
        mapping_info.push_back({static_cast<size_t>(iterator.code_offset()),
                                last_line_number, JitCodeEvent::POSITION});
        last_line_number = source_map->GetSourceLine(offset) + 1;
      }

      wasm_source_info = std::make_unique<JitCodeEvent::wasm_source_info_t>();
      wasm_source_info->filename = filename.c_str();
      wasm_source_info->filename_size = filename.size();
      wasm_source_info->line_number_table_size = mapping_info.size();
      wasm_source_info->line_number_table = mapping_info.data();

      event.wasm_source_info = wasm_source_info.get();
    }
  }
  code_event_handler_(&event);
}
#endif  // V8_ENABLE_WEBASSEMBLY

void JitLogger::CodeMoveEvent(Tagged<InstructionStream> from,
                              Tagged<InstructionStream> to) {
  base::MutexGuard guard(&logger_mutex_);

  Tagged<Code> code;
  if (!from->TryGetCodeUnchecked(&code, kAcquireLoad)) {
    // Not yet fully initialized and no CodeCreateEvent has been emitted yet.
    return;
  }

  JitCodeEvent event;
  event.type = JitCodeEvent::CODE_MOVED;
  event.code_type = JitCodeEvent::JIT_CODE;
  event.code_start = reinterpret_cast<void*>(from->instruction_start());
  event.code_len = code->instruction_size();
  event.new_code_start = reinterpret_cast<void*>(to->instruction_start());
  event.isolate = reinterpret_cast<v8::Isolate*>(isolate_);

  code_event_handler_(&event);
}

void JitLogger::BytecodeMoveEvent(Tagged<BytecodeArray> from,
                                  Tagged<BytecodeArray> to) {
  base::MutexGuard guard(&logger_mutex_);

  JitCodeEvent event;
  event.type = JitCodeEvent::CODE_MOVED;
  event.code_type = JitCodeEvent::BYTE_CODE;
  event.code_start = reinterpret_cast<void*>(from->GetFirstBytecodeAddress());
  event.code_len = from->length();
  event.new_code_start = reinterpret_cast<void*>(to->GetFirstBytecodeAddress());
  event.isolate = reinterpret_cast<v8::Isolate*>(isolate_);

  code_event_handler_(&event);
}

void JitLogger::AddCodeLinePosInfoEvent(
    void* jit_handler_data, int pc_offset, int position,
    JitCodeEvent::PositionType position_type,
    JitCodeEvent::CodeType code_type) {
  JitCodeEvent event;
  event.type = JitCodeEvent::CODE_ADD_LINE_POS_INFO;
  event.code_type = code_type;
  event.user_data = jit_handler_data;
  event.line_info.offset = pc_offset;
  event.line_info.pos = position;
  event.line_info.position_type = position_type;
  event.isolate = reinterpret_cast<v8::Isolate*>(isolate_);

  code_event_handler_(&event);
}

void* JitLogger::StartCodePosInfoEvent(JitCodeEvent::CodeType code_type) {
  JitCodeEvent event;
  event.type = JitCodeEvent::CODE_START_LINE_INFO_RECORDING;
  event.code_type = code_type;
  event.isolate = reinterpret_cast<v8::Isolate*>(isolate_);

  code_event_handler_(&event);
  return event.user_data;
}

void JitLogger::EndCodePosInfoEvent(Address start_address,
                                    void* jit_handler_data,
                                    JitCodeEvent::CodeType code_type) {
  JitCodeEvent event;
  event.type = JitCodeEvent::CODE_END_LINE_INFO_RECORDING;
  event.code_type = code_type;
  event.code_start = reinterpret_cast<void*>(start_address);
  event.user_data = jit_handler_data;
  event.isolate = reinterpret_cast<v8::Isolate*>(isolate_);

  code_event_handler_(&event);
}

// TODO(lpy): Keeping sampling thread inside V8 is a workaround currently,
// the reason is to reduce code duplication during migration to sampler library,
// sampling thread, as well as the sampler, will be moved to D8 eventually.
class SamplingThread : public base::Thread {
 public:
  static const int kSamplingThreadStackSize = 64 * KB;

  SamplingThread(sampler::Sampler* sampler, int interval_microseconds)
      : base::Thread(
            base::Thread::Options("SamplingThread", kSamplingThreadStackSize)),
        sampler_(sampler),
        interval_microseconds_(interval_microseconds) {}

  void Run() override {
    while (sampler_->IsActive()) {
      sampler_->DoSample();
      base::OS::Sleep(
          base::TimeDelta::FromMicroseconds(interval_microseconds_));
    }
  }

 private:
  sampler::Sampler* sampler_;
  const int interval_microseconds_;
};

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
class ETWJitLogger : public JitLogger {
 public:
  explicit ETWJitLogger(Isolate* isolate)
      : JitLogger(isolate, i::ETWJITInterface::EventHandler) {}
};
#endif

// The Profiler samples pc and sp values for the main thread.
// Each sample is appended to a circular buffer.
// An independent thread removes data and writes it to the log.
// This design minimizes the time spent in the sampler.
//
class Profiler : public base::Thread {
 public:
  explicit Profiler(Isolate* isolate);
  void Engage();
  void Disengage();

  // Inserts collected profiling data into buffer.
  void Insert(TickSample* sample) {
    if (Succ(head_) == static_cast<int>(base::Acquire_Load(&tail_))) {
      base::Relaxed_Store(&overflow_, true);
    } else {
      buffer_[head_] = *sample;
      head_ = Succ(head_);
      buffer_semaphore_.Signal();  // Tell we have an element.
    }
  }

  void Run() override;

 private:
  // Waits for a signal and removes profiling data.
  bool Remove(TickSample* sample) {
    buffer_semaphore_.Wait();  // Wait for an element.
    *sample = buffer_[base::Relaxed_Load(&tail_)];
    bool result = base::Relaxed_Load(&overflow_);
    base::Release_Store(
        &tail_, static_cast<base::Atomic32>(Succ(base::Relaxed_Load(&tail_))));
    base::Relaxed_Store(&overflow_, false);
    return result;
  }

  // Returns the next index in the cyclic buffer.
  int Succ(int index) { return (index + 1) % kBufferSize; }

  Isolate* isolate_;
  // Cyclic buffer for communicating profiling samples
  // between the signal handler and the worker thread.
  static const int kBufferSize = 128;
  TickSample buffer_[kBufferSize];  // Buffer storage.
  int head_;                        // Index to the buffer head.
  base::Atomic32 tail_;             // Index to the buffer tail.
  base::Atomic32 overflow_;  // Tell whether a buffer overflow has occurred.
  // Semaphore used for buffer synchronization.
  base::Semaphore buffer_semaphore_;

  // Tells whether worker thread should continue running.
  base::Atomic32 running_;
};

//
// Ticker used to provide ticks to the profiler and the sliding state
// window.
//
class Ticker : public sampler::Sampler {
 public:
  Ticker(Isolate* isolate, int interval_microseconds)
      : sampler::Sampler(reinterpret_cast<v8::Isolate*>(isolate)),
        sampling_thread_(
            std::make_unique<SamplingThread>(this, interval_microseconds)),
        perThreadData_(isolate->FindPerThreadDataForThisThread()) {}

  ~Ticker() override {
    if (IsActive()) Stop();
  }

  void SetProfiler(Profiler* profiler) {
    DCHECK_NULL(profiler_);
    profiler_ = profiler;
    if (!IsActive()) Start();
    sampling_thread_->StartSynchronously();
  }

  void ClearProfiler() {
    profiler_ = nullptr;
    if (IsActive()) Stop();
    sampling_thread_->Join();
  }

  void SampleStack(const v8::RegisterState& state) override {
    if (!profiler_) return;
    Isolate* isolate = reinterpret_cast<Isolate*>(this->isolate());
    if (isolate->was_locker_ever_used() &&
        (!isolate->thread_manager()->IsLockedByThread(
             perThreadData_->thread_id()) ||
         perThreadData_->thread_state() != nullptr))
      return;
#if V8_HEAP_USE_PKU_JIT_WRITE_PROTECT
    i::RwxMemoryWriteScope::SetDefaultPermissionsForSignalHandler();
#endif
    TickSample sample;
    sample.Init(isolate, state, TickSample::kIncludeCEntryFrame, true);
    profiler_->Insert(&sample);
  }

 private:
  Profiler* profiler_ = nullptr;
  std::unique_ptr<SamplingThread> sampling_thread_;
  Isolate::PerIsolateThreadData* perThreadData_;
};

//
// Profiler implementation when invoking with --prof.
//
Profiler::Profiler(Isolate* isolate)
    : base::Thread(Options("v8:Profiler")),
      isolate_(isolate),
      head_(0),
      buffer_semaphore_(0) {
  base::Relaxed_Store(&tail_, 0);
  base::Relaxed_Store(&overflow_, false);
  base::Relaxed_Store(&running_, 0);
}

void Profiler::Engage() {
  std::vector<base::OS::SharedLibraryAddress> addresses =
      base::OS::GetSharedLibraryAddresses();
  for (const auto& address : addresses) {
    LOG(isolate_, SharedLibraryEvent(address.library_path, address.start,
                                     address.end, address.aslr_slide));
  }
  LOG(isolate_, SharedLibraryEnd());

  // Start thread processing the profiler buffer.
  base::Relaxed_Store(&running_, 1);
  CHECK(Start());

  // Register to get ticks.
  V8FileLogger* logger = isolate_->v8_file_logger();
  logger->ticker_->SetProfiler(this);

  LOG(isolate_, ProfilerBeginEvent());
}

void Profiler::Disengage() {
  // Stop receiving ticks.
  isolate_->v8_file_logger()->ticker_->ClearProfiler();

  // Terminate the worker thread by setting running_ to false,
  // inserting a fake element in the queue and then wait for
  // the thread to terminate.
  base::Relaxed_Store(&running_, 0);
  TickSample sample;
  Insert(&sample);
  Join();

  LOG(isolate_, UncheckedStringEvent("profiler", "end"));
}

void Profiler::Run() {
  TickSample sample;
  bool overflow = Remove(&sample);
  while (base::Relaxed_Load(&running_)) {
    LOG(isolate_, TickEvent(&sample, overflow));
    overflow = Remove(&sample);
  }
}

//
// V8FileLogger class implementation.
//
#define MSG_BUILDER()                                \
  std::unique_ptr<LogFile::MessageBuilder> msg_ptr = \
      log_file_->NewMessageBuilder();                \
  if (!msg_ptr) return;                              \
  LogFile::MessageBuilder& msg = *msg_ptr.get();

V8FileLogger::V8FileLogger(Isolate* isolate)
    : isolate_(isolate),
      is_logging_(false),
      is_initialized_(false),
      existing_code_logger_(isolate) {}

V8FileLogger::~V8FileLogger() = default;

const LogSeparator V8FileLogger::kNext = LogSeparator::kSeparator;

int64_t V8FileLogger::Time() {
  if (v8_flags.verify_predictable) {
    return isolate_->heap()->MonotonicallyIncreasingTimeInMs() * 1000;
  }
  return timer_.Elapsed().InMicroseconds();
}

// These logger can be called concurrently, so only update the VMState if
// the call is from the main thread.
template <StateTag tag>
class VMStateIfMainThread {
 public:
  explicit VMStateIfMainThread(Isolate* isolate) {
    if (ThreadId::Current() == isolate->thread_id()) {
      vm_state_.emplace(isolate);
    }
  }

 private:
  std::optional<VMState<tag>> vm_state_;
};

void V8FileLogger::ProfilerBeginEvent() {
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  msg << "profiler" << kNext << "begin" << kNext
      << v8_flags.prof_sampling_interval;
  msg.WriteToLogFile();
}

void V8FileLogger::StringEvent(const char* name, const char* value) {
  if (v8_flags.log) UncheckedStringEvent(name, value);
}

void V8FileLogger::UncheckedStringEvent(const char* name, const char* value) {
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  msg << name << kNext << value;
  msg.WriteToLogFile();
}

void V8FileLogger::IntPtrTEvent(const char* name, intptr_t value) {
  if (!v8_flags.log) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  msg << name << kNext;
  msg.AppendFormatString("%" V8PRIdPTR, value);
  msg.WriteToLogFile();
}

void V8FileLogger::SharedLibraryEvent(const std::string& library_path,
                                      uintptr_t start, uintptr_t end,
                                      intptr_t aslr_slide) {
  if (!v8_flags.prof_cpp) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  msg << "shared-library" << kNext << library_path.c_str() << kNext
      << reinterpret_cast<void*>(start) << kNext << reinterpret_cast<void*>(end)
      << kNext << aslr_slide;
  msg.WriteToLogFile();
}

void V8FileLogger::SharedLibraryEnd() {
  if (!v8_flags.prof_cpp) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  msg << "shared-library-end";
  msg.WriteToLogFile();
}

void V8FileLogger::CurrentTimeEvent() {
  VMStateIfMainThread<LOGGING> state(isolate_);
  DCHECK(v8_flags.log_timer_events);
  MSG_BUILDER();
  msg << "current-time" << kNext << Time();
  msg.WriteToLogFile();
}

void V8FileLogger::TimerEvent(v8::LogEventStatus se, const char* name) {
  VMStateIfMainThread<LOGGING> state(isolate_);
  DCHECK(v8_flags.log_timer_events);
  MSG_BUILDER();
  switch (se) {
    case kStart:
      msg << "timer-event-start";
      break;
    case kEnd:
      msg << "timer-event-end";
      break;
    case kLog:
      msg << "timer-event";
  }
  msg << kNext << name << kNext << Time();
  msg.WriteToLogFile();
}

bool V8FileLogger::is_logging() {
  // Disable logging while the CPU profiler is running.
  if (isolate_->is_profiling()) return false;
  return is_logging_.load(std::memory_order_relaxed);
}

// Instantiate template methods.
#define V(TimerName, expose)                                           \
  template void TimerEventScope<TimerEvent##TimerName>::LogTimerEvent( \
      v8::LogEventStatus se);
TIMER_EVENTS_LIST(V)
#undef V

void V8FileLogger::NewEvent(const char* name, void* object, size_t size) {
  if (!v8_flags.log) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  msg << "new" << kNext << name << kNext << object << kNext
      << static_cast<unsigned int>(size);
  msg.WriteToLogFile();
}

void V8FileLogger::DeleteEvent(const char* name, void* object) {
  if (!v8_flags.log) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  msg << "delete" << kNext << name << kNext << object;
  msg.WriteToLogFile();
}

namespace {

void AppendCodeCreateHeader(LogFile::MessageBuilder& msg,
                            LogEventListener::CodeTag tag, CodeKind kind,
                            uint8_t* address, int size, uint64_t time) {
  msg << LogEventListener::Event::kCodeCreation << V8FileLogger::kNext << tag
      << V8FileLogger::kNext << static_cast<int>(kind) << V8FileLogger::kNext
      << time << V8FileLogger::kNext << reinterpret_cast<void*>(address)
      << V8FileLogger::kNext << size << V8FileLogger::kNext;
}

void AppendCodeCreateHeader(Isolate* isolate, LogFile::MessageBuilder& msg,
                            LogEventListener::CodeTag tag,
                            Tagged<AbstractCode> code, uint64_t time) {
  PtrComprCageBase cage_base(isolate);
  AppendCodeCreateHeader(
      msg, tag, code->kind(cage_base),
      reinterpret_cast<uint8_t*>(code->InstructionStart(cage_base)),
      code->InstructionSize(cage_base), time);
}

}  // namespace
// We log source code information in the form:
//
// code-source-info <addr>,<script>,<start>,<end>,<pos>,<inline-pos>,<fns>
//
// where
//   <addr> is code object address
//   <script> is script id
//   <start> is the starting position inside the script
//   <end> is the end position inside the script
//   <pos> is source position table encoded in the string,
//      it is a sequence of C<code-offset>O<script-offset>[I<inlining-id>]
//      where
//        <code-offset> is the offset within the code object
//        <script-offset> is the position within the script
//        <inlining-id> is the offset in the <inlining> table
//   <inlining> table is a sequence of strings of the form
//      F<function-id>O<script-offset>[I<inlining-id>]
//      where
//         <function-id> is an index into the <fns> function table
//   <fns> is the function table encoded as a sequence of strings
//      S<shared-function-info-address>

void V8FileLogger::LogSourceCodeInformation(
    Handle<AbstractCode> code, DirectHandle<SharedFunctionInfo> shared) {
  PtrComprCageBase cage_base(isolate_);
  Tagged<Object> script_object = shared->script(cage_base);
  if (!IsScript(script_object, cage_base)) return;
  Tagged<Script> script = Cast<Script>(script_object);
  EnsureLogScriptSource(script);

  if (!v8_flags.log_source_position) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  msg << "code-source-info" << V8FileLogger::kNext
      << reinterpret_cast<void*>(code->InstructionStart(cage_base))
      << V8FileLogger::kNext << script->id() << V8FileLogger::kNext
      << shared->StartPosition() << V8FileLogger::kNext << shared->EndPosition()
      << V8FileLogger::kNext;
  // TODO(v8:11429): Clean-up baseline-replated code in source position
  // iteration.
  bool hasInlined = false;
  if (code->kind(cage_base) != CodeKind::BASELINE) {
    SourcePositionTableIterator iterator(
        code->SourcePositionTable(isolate_, *shared));
    for (; !iterator.done(); iterator.Advance()) {
      SourcePosition pos = iterator.source_position();
      msg << "C" << iterator.code_offset() << "O" << pos.ScriptOffset();
      if (pos.isInlined()) {
        msg << "I" << pos.InliningId();
        hasInlined = true;
      }
    }
  }
  msg << V8FileLogger::kNext;
  int maxInlinedId = -1;
  if (hasInlined) {
    Tagged<TrustedPodArray<InliningPosition>> inlining_positions =
        Cast<DeoptimizationData>(Cast<Code>(code)->deoptimization_data())
            ->InliningPositions();
    for (int i = 0; i < inlining_positions->length(); i++) {
      InliningPosition inlining_pos = inlining_positions->get(i);
      msg << "F";
      if (inlining_pos.inlined_function_id != -1) {
        msg << inlining_pos.inlined_function_id;
        if (inlining_pos.inlined_function_id > maxInlinedId) {
          maxInlinedId = inlining_pos.inlined_function_id;
        }
      }
      SourcePosition pos = inlining_pos.position;
      msg << "O" << pos.ScriptOffset();
      if (pos.isInlined()) {
        msg << "I" << pos.InliningId();
      }
    }
  }
  msg << V8FileLogger::kNext;
  if (hasInlined) {
    Tagged<DeoptimizationData> deopt_data =
        Cast<DeoptimizationData>(Cast<Code>(code)->deoptimization_data());
    msg << std::hex;
    for (int i = 0; i <= maxInlinedId; i++) {
      msg << "S"
          << reinterpret_cast<void*>(
                 deopt_data->GetInlinedFunction(i).address());
    }
    msg << std::dec;
  }
  msg.WriteToLogFile();
}

void V8FileLogger::LogCodeDisassemble(DirectHandle<AbstractCode> code) {
  if (!v8_flags.log_code_disassemble) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  PtrComprCageBase cage_base(isolate_);
  MSG_BUILDER();
  msg << "code-disassemble" << V8FileLogger::kNext
      << reinterpret_cast<void*>(code->InstructionStart(cage_base))
      << V8FileLogger::kNext << CodeKindToString(code->kind(cage_base))
      << V8FileLogger::kNext;
  {
    std::ostringstream stream;
    if (IsCode(*code, cage_base)) {
#ifdef ENABLE_DISASSEMBLER
      Cast<Code>(*code)->Disassemble(nullptr, stream, isolate_);
#endif
    } else {
      Cast<BytecodeArray>(*code)->Disassemble(stream);
    }
    std::string string = stream.str();
    msg.AppendString(string.c_str(), string.length());
  }
  msg.WriteToLogFile();
}

// Builtins and Bytecode handlers
void V8FileLogger::CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                                   const char* name) {
  if (!is_listening_to_code_events()) return;
  if (!v8_flags.log_code) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  {
    MSG_BUILDER();
    AppendCodeCreateHeader(isolate_, msg, tag, *code, Time());
    msg << name;
    msg.WriteToLogFile();
  }
  LogCodeDisassemble(code);
}

void V8FileLogger::CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                                   Handle<Name> name) {
  if (!is_listening_to_code_events()) return;
  if (!v8_flags.log_code) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  {
    MSG_BUILDER();
    AppendCodeCreateHeader(isolate_, msg, tag, *code, Time());
    msg << *name;
    msg.WriteToLogFile();
  }
  LogCodeDisassemble(code);
}

// Scripts
void V8FileLogger::CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                                   Handle<SharedFunctionInfo> shared,
                                   Handle<Name> script_name) {
  if (!is_listening_to_code_events()) return;
  if (!v8_flags.log_code) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  if (*code ==
      Cast<AbstractCode>(isolate_->builtins()->code(Builtin::kCompileLazy))) {
    return;
  }
  {
    MSG_BUILDER();
    AppendCodeCreateHeader(isolate_, msg, tag, *code, Time());
    msg << *script_name << kNext << reinterpret_cast<void*>(shared->address())
        << kNext << ComputeMarker(*shared, *code);
    msg.WriteToLogFile();
  }
  LogSourceCodeInformation(code, shared);
  LogCodeDisassemble(code);
}

void V8FileLogger::FeedbackVectorEvent(Tagged<FeedbackVector> vector,
                                       Tagged<AbstractCode> code) {
  DisallowGarbageCollection no_gc;
  if (!v8_flags.log_feedback_vector) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  PtrComprCageBase cage_base(isolate_);
  MSG_BUILDER();
  msg << "feedback-vector" << kNext << Time();
  msg << kNext << reinterpret_cast<void*>(vector.address()) << kNext
      << vector->length();
  msg << kNext << reinterpret_cast<void*>(code->InstructionStart(cage_base));
#ifndef V8_ENABLE_LEAPTIERING
  msg << kNext << vector->tiering_state();
  msg << kNext << vector->maybe_has_maglev_code();
  msg << kNext << vector->maybe_has_turbofan_code();
#endif  // !V8_ENABLE_LEAPTIERING
  msg << kNext << vector->invocation_count();

#ifdef OBJECT_PRINT
  std::ostringstream buffer;
  vector->FeedbackVectorPrint(buffer);
  std::string contents = buffer.str();
  msg.AppendString(contents.c_str(), contents.length());
#else
  msg << "object-printing-disabled";
#endif
  msg.WriteToLogFile();
}

// Functions
// Although, it is possible to extract source and line from
// the SharedFunctionInfo object, we left it to caller
// to leave logging functions free from heap allocations.
void V8FileLogger::CodeCreateEvent(CodeTag tag, Handle<AbstractCode> code,
                                   Handle<SharedFunctionInfo> shared,
                                   Handle<Name> script_name, int line,
                                   int column) {
  if (!is_listening_to_code_events()) return;
  if (!v8_flags.log_code) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  {
    MSG_BUILDER();
    AppendCodeCreateHeader(isolate_, msg, tag, *code, Time());
    msg << shared->DebugNameCStr().get() << " " << *script_name << ":" << line
        << ":" << column << kNext << reinterpret_cast<void*>(shared->address())
        << kNext << ComputeMarker(*shared, *code);

    msg.WriteToLogFile();
  }
  LogSourceCodeInformation(code, shared);
  LogCodeDisassemble(code);
}

#if V8_ENABLE_WEBASSEMBLY
void V8FileLogger::CodeCreateEvent(CodeTag tag, const wasm::WasmCode* code,
                                   wasm::WasmName name,
                                   const char* /*source_url*/,
                                   int /*code_offset*/, int /*script_id*/) {
  if (!is_listening_to_code_events()) return;
  if (!v8_flags.log_code) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  AppendCodeCreateHeader(msg, tag, CodeKind::WASM_FUNCTION,
                         code->instructions().begin(),
                         code->instructions().length(), Time());
  DCHECK(!name.empty());
  msg.AppendString(name);

  // We have to add two extra fields that allow the tick processor to group
  // events for the same wasm function, even if it gets compiled again. For
  // normal JS functions, we use the shared function info. For wasm, the pointer
  // to the native module + function index works well enough. For Wasm wrappers,
  // just use the address of the WasmCode.
  // TODO(herhut) Clean up the tick processor code instead.
  const void* tag_ptr =
      code->native_module() != nullptr
          ? reinterpret_cast<uint8_t*>(code->native_module()) + code->index()
          : reinterpret_cast<const uint8_t*>(code);

  msg << kNext << tag_ptr << kNext << ComputeMarker(code);
  msg.WriteToLogFile();
}
#endif  // V8_ENABLE_WEBASSEMBLY

void V8FileLogger::CallbackEventInternal(const char* prefix,
                                         DirectHandle<Name> name,
                                         Address entry_point) {
  if (!v8_flags.log_code) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  msg << Event::kCodeCreation << kNext << CodeTag::kCallback << kNext << -2
      << kNext << Time() << kNext << reinterpret_cast<void*>(entry_point)
      << kNext << 1 << kNext << prefix << *name;
  msg.WriteToLogFile();
}

void V8FileLogger::CallbackEvent(Handle<Name> name, Address entry_point) {
  CallbackEventInternal("", name, entry_point);
}

void V8FileLogger::GetterCallbackEvent(Handle<Name> name, Address entry_point) {
  CallbackEventInternal("get ", name, entry_point);
}

void V8FileLogger::SetterCallbackEvent(Handle<Name> name, Address entry_point) {
  CallbackEventInternal("set ", name, entry_point);
}

void V8FileLogger::RegExpCodeCreateEvent(Handle<AbstractCode> code,
                                         Handle<String> source,
                                         RegExpFlags flags) {
  if (!is_listening_to_code_events()) return;
  if (!v8_flags.log_code) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  AppendCodeCreateHeader(isolate_, msg, LogEventListener::CodeTag::kRegExp,
                         *code, Time());
  msg << *source;
  msg.WriteToLogFile();
}

void V8FileLogger::CodeMoveEvent(Tagged<InstructionStream> from,
                                 Tagged<InstructionStream> to) {
  if (!is_listening_to_code_events()) return;
  MoveEventInternal(Event::kCodeMove, from->instruction_start(),
                    to->instruction_start());
}

void V8FileLogger::BytecodeMoveEvent(Tagged<BytecodeArray> from,
                                     Tagged<BytecodeArray> to) {
  if (!is_listening_to_code_events()) return;
  MoveEventInternal(Event::kCodeMove, from->GetFirstBytecodeAddress(),
                    to->GetFirstBytecodeAddress());
}

void V8FileLogger::SharedFunctionInfoMoveEvent(Address from, Address to) {
  if (!is_listening_to_code_events()) return;
  MoveEventInternal(Event::kSharedFuncMove, from, to);
}

void V8FileLogger::CodeMovingGCEvent() {
  if (!is_listening_to_code_events()) return;
  if (!v8_flags.ll_prof) return;
  base::OS::SignalCodeMovingGC();
}

void V8FileLogger::CodeDisableOptEvent(Handle<AbstractCode> code,
                                       Handle<SharedFunctionInfo> shared) {
  if (!is_listening_to_code_events()) return;
  if (!v8_flags.log_code) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  msg << Event::kCodeDisableOpt << kNext << shared->DebugNameCStr().get()
      << kNext << GetBailoutReason(shared->disabled_optimization_reason());
  msg.WriteToLogFile();
}

void V8FileLogger::ProcessDeoptEvent(DirectHandle<Code> code,
                                     SourcePosition position, const char* kind,
                                     const char* reason) {
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  msg << Event::kCodeDeopt << kNext << Time() << kNext
      << code->InstructionStreamObjectSize() << kNext
      << reinterpret_cast<void*>(code->instruction_start());

  std::ostringstream deopt_location;
  int inlining_id = -1;
  int script_offset = -1;
  if (position.IsKnown()) {
    position.Print(deopt_location, *code);
    inlining_id = position.InliningId();
    script_offset = position.ScriptOffset();
  } else {
    deopt_location << "<unknown>";
  }
  msg << kNext << inlining_id << kNext << script_offset << kNext;
  msg << kind << kNext;
  msg << deopt_location.str().c_str() << kNext << reason;
  msg.WriteToLogFile();
}

void V8FileLogger::CodeDeoptEvent(Handle<Code> code, DeoptimizeKind kind,
                                  Address pc, int fp_to_sp_delta) {
  if (!is_logging() || !v8_flags.log_deopt) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  Deoptimizer::DeoptInfo info = Deoptimizer::GetDeoptInfo(*code, pc);
  ProcessDeoptEvent(code, info.position, Deoptimizer::MessageFor(kind),
                    DeoptimizeReasonToString(info.deopt_reason));
}

void V8FileLogger::CodeDependencyChangeEvent(Handle<Code> code,
                                             Handle<SharedFunctionInfo> sfi,
                                             const char* reason) {
  if (!is_logging() || !v8_flags.log_deopt) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  SourcePosition position(sfi->StartPosition(), -1);
  ProcessDeoptEvent(code, position, "dependency-change", reason);
}

namespace {

void CodeLinePosEvent(JitLogger& jit_logger, Address code_start,
                      SourcePositionTableIterator& iter,
                      JitCodeEvent::CodeType code_type) {
  void* jit_handler_data = jit_logger.StartCodePosInfoEvent(code_type);
  for (; !iter.done(); iter.Advance()) {
    if (iter.is_statement()) {
      jit_logger.AddCodeLinePosInfoEvent(jit_handler_data, iter.code_offset(),
                                         iter.source_position().ScriptOffset(),
                                         JitCodeEvent::STATEMENT_POSITION,
                                         code_type);
    }
    jit_logger.AddCodeLinePosInfoEvent(jit_handler_data, iter.code_offset(),
                                       iter.source_position().ScriptOffset(),
                                       JitCodeEvent::POSITION, code_type);
  }
  jit_logger.EndCodePosInfoEvent(code_start, jit_handler_data, code_type);
}

}  // namespace

void V8FileLogger::CodeLinePosInfoRecordEvent(
    Address code_start, Tagged<TrustedByteArray> source_position_table,
    JitCodeEvent::CodeType code_type) {
  if (!jit_logger_) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  SourcePositionTableIterator iter(source_position_table);
  CodeLinePosEvent(*jit_logger_, code_start, iter, code_type);
}

#if V8_ENABLE_WEBASSEMBLY
void V8FileLogger::WasmCodeLinePosInfoRecordEvent(
    Address code_start, base::Vector<const uint8_t> source_position_table) {
  if (!jit_logger_) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  SourcePositionTableIterator iter(source_position_table);
  CodeLinePosEvent(*jit_logger_, code_start, iter, JitCodeEvent::WASM_CODE);
}
#endif  // V8_ENABLE_WEBASSEMBLY

void V8FileLogger::CodeNameEvent(Address addr, int pos, const char* code_name) {
  if (code_name == nullptr) return;  // Not a code object.
  if (!is_listening_to_code_events()) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  msg << Event::kSnapshotCodeName << kNext << pos << kNext << code_name;
  msg.WriteToLogFile();
}

void V8FileLogger::MoveEventInternal(Event event, Address from, Address to) {
  if (!v8_flags.log_code) return;
  VMStateIfMainThread<LOGGING> state(isolate_);
  MSG_BUILDER();
  msg << event << kNext << reinterpret_cast<void*>(from) << kNext
      << reinterpret_cast<void*>(to);
  msg.WriteToLogFile();
}

namespace {
void AppendFunctionMessage(LogFile::MessageBuilder& msg, const char* reason,
                           int script_id, double time_delta, int start_position,
                           int end_position, uint64_t time) {
  msg << "function" << V8FileLogger::kNext << reason << V8FileLogger::kNext
      << script_id << V8FileLogger::kNext << start_position
      << V8FileLogger::kNext << end_position << V8FileLogger::kNext;
  if (V8_UNLIKELY(v8_flags.predictable)) {
    msg << 0.1;
  } else {
    msg << time_delta;
  }
  msg << V8FileLogger::kNext << time << V8FileLogger::kNext;
}
}  // n
```