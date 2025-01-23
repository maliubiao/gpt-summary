Response:
The user wants a summary of the functionality of the provided C++ code snippet. I should go through the code and identify the key features and purposes of this file.

Here's a breakdown of my thought process:

1. **Identify the file's purpose:** The file is located in `v8/src/logging/log.cc`. The name and location suggest it's related to logging within the V8 engine.

2. **Analyze the includes:** The included headers give a good overview of the file's dependencies and the areas it touches. Keywords here are `logging`, `code`, `execution`, `heap`, `wasm`, `profiler`, `diagnostics`. This reinforces the idea that this file is about logging various events within V8, especially related to code execution.

3. **Examine the global constants:** `kLogEventsNames` and `kCodeTagNames` indicate that the logging system deals with different types of events and code tags.

4. **Look for core classes and functions:**  The presence of classes like `CodeEventLogger`, `LinuxPerfBasicLogger`, `ExternalLogEventListener`, `LowLevelLogger`, and `JitLogger` strongly suggests that this file implements different logging strategies or output formats.

5. **Focus on the `CodeEventLogger`:** This appears to be a central class for managing code-related logging events. Its methods like `CodeCreateEvent` and the `NameBuffer` class point to its responsibility for formatting and storing information about code creation.

6. **Investigate the derived logger classes:**
    * `LinuxPerfBasicLogger`: The name suggests integration with Linux perf tools for performance analysis.
    * `ExternalLogEventListener`:  This likely provides a way for external tools or systems to receive logging information.
    * `LowLevelLogger`:  This probably outputs a more raw, low-level format of the log data.
    * `JitLogger`:  This is likely for logging information specifically related to Just-In-Time (JIT) compiled code.

7. **Check for conditional compilation:** The `#ifdef` blocks for `ENABLE_GDB_JIT_INTERFACE`, `V8_ENABLE_WEBASSEMBLY`, and `V8_OS_LINUX` indicate platform-specific or feature-specific logging mechanisms. The WebAssembly sections are significant.

8. **Look for JavaScript interaction:**  While this is a C++ file, the context is V8, which executes JavaScript. The code logs information *about* the code V8 runs, which includes JavaScript. The `ExternalLogEventListener` seems to be the most direct link for external consumption, possibly by JavaScript tools.

9. **Consider error scenarios:**  The code itself doesn't directly *handle* user programming errors in the way a JavaScript engine's parser would. Instead, it logs events related to how the engine executes code, which could *result* from user errors (e.g., deoptimization).

10. **Address the specific instructions:**
    * `.tq` suffix:  The code explicitly checks for this.
    * JavaScript relationship: Highlight how the logging relates to code execution, which includes JavaScript.
    * Example: Provide a simple JavaScript example that might trigger a logged event (like function compilation).
    * Logic:  The logic here is mostly about formatting and dispatching log events. A simple example would be triggering a `CodeCreateEvent`.
    * Programming errors: Mention how logging can help diagnose errors indirectly.

11. **Synthesize the information:** Combine the observations into a concise summary of the file's purpose and main functionalities.

By following these steps, I can generate a comprehensive and accurate summary of the `v8/src/logging/log.cc` file, addressing all the user's specific requirements.
```cpp
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/logging/log.h"

// ... (rest of the includes and code)
```

Based on the provided code snippet from `v8/src/logging/log.cc`, here's a summary of its functionality as part 1 of 3:

**Core Functionality:**

This C++ source file (`log.cc`) implements the core logging infrastructure for the V8 JavaScript engine. Its primary purpose is to record various events that occur during the execution of JavaScript code within V8. This information can be used for debugging, performance analysis, profiling, and understanding the internal workings of the engine.

**Key Features and Responsibilities:**

* **Event Logging:** It defines mechanisms to log different types of events, particularly those related to code creation, movement, and deoptimization. This includes:
    * Creating compiled code (JIT-compiled functions, built-in functions, bytecode handlers, etc.).
    * Moving code in memory (important for understanding memory management and garbage collection).
    * Disabling optimizations for specific code.
* **Code Metadata Tracking:** It associates logged events with metadata about the code, such as:
    * Code type (e.g., function, builtin, regexp).
    * Function names and script names.
    * Source code locations (line and column numbers).
* **Multiple Logging Strategies:** The file implements different logging approaches, catering to various use cases:
    * **Basic Logging:**  A general-purpose logging mechanism.
    * **Linux Perf Integration:** Specifically designed for use with the Linux `perf` tool for performance analysis.
    * **External Log Listeners:** Allows external applications or tools to subscribe to and receive V8's log events.
    * **Low-Level Logging:**  Outputs a raw, binary format of the log data for detailed analysis.
    * **JIT Logging:**  Provides an interface for external tools to receive detailed information about JIT-compiled code.
* **WebAssembly Support:** The code includes specific logic for logging events related to WebAssembly code execution.
* **String Formatting:** It provides utility functions (like `NameBuffer`) to efficiently format strings and other data for logging output.
* **Thread Safety:** The use of mutexes (`base::Mutex`, `base::RecursiveMutex`) suggests consideration for thread safety when accessing shared logging resources.

**Regarding your specific questions:**

* **`.tq` extension:**  The provided code is a `.cc` file, which indicates a standard C++ source file. If `v8/src/logging/log.cc` had a `.tq` extension, it would indeed be a Torque source file. Torque is V8's internal language for generating built-in functions.

* **Relationship with JavaScript:** This file is fundamentally related to JavaScript functionality. The events being logged are direct consequences of V8 executing JavaScript code. For example, when a JavaScript function is compiled by the JIT compiler, a `CodeCreateEvent` would likely be triggered and handled by this file.

* **Code Logic Inference:** The core logic involves capturing specific events within the V8 engine and formatting them for output based on the chosen logging strategy.

* **User Programming Errors:** While this file doesn't directly *cause* user programming errors, the logging it provides can be invaluable in *diagnosing* them. For example, if a JavaScript function is repeatedly being deoptimized due to type mismatches, the logs generated by this file could reveal this pattern and help developers understand the root cause of performance issues.

**In summary, `v8/src/logging/log.cc` is a crucial component of V8 responsible for recording and managing various events related to code execution. It provides different logging mechanisms to cater to various debugging, profiling, and analysis needs.**

### 提示词
```
这是目录为v8/src/logging/log.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/logging/log.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  event.isolate = reinterpret_ca
```