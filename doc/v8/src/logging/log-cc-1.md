Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the `v8/src/logging/log.cc` file.

Here's a plan to address the request:

1. **Identify Core Functionality:** Analyze the code to determine its main purpose. It seems to be related to logging and profiling events within the V8 engine.
2. **List Key Features:** Break down the functionality into specific features, such as logging code creation, code movement, deoptimization events, profiling data, etc.
3. **Address Specific Questions:**
    - Check if the filename ends with `.tq`.
    - Determine if the code relates to JavaScript functionality and provide an example if it does.
    - Look for code logic that can be explained with input and output.
    - Identify potential programming errors that the code might help diagnose.
4. **Synthesize a Summary:** Combine the identified functionalities and features into a concise summary.
这是 `v8/src/logging/log.cc` 代码的第二部分，延续了第一部分的功能，主要集中在**记录 V8 虚拟机在执行 JavaScript 代码时的各种事件，用于性能分析、调试和诊断**。

以下是这部分代码的主要功能归纳：

**1. JIT 代码日志记录 (JitLogger)**:

*   **`CodeCreateEvent` (WebAssembly):**  当 WebAssembly 代码被创建时记录相关信息，包括代码起始地址、大小、函数名称以及关联的 wasm 模块和函数索引。
*   **`CodeMoveEvent`:** 当 JIT 生成的代码在内存中移动时记录事件，包含代码的起始地址、长度以及新的起始地址。
*   **`BytecodeMoveEvent`:** 当字节码在内存中移动时记录事件，包含字节码的起始地址、长度以及新的起始地址。
*   **`AddCodeLinePosInfoEvent`:** 添加代码的行号信息，用于将 JIT 代码的偏移量映射回源代码的位置。
*   **`StartCodePosInfoEvent` 和 `EndCodePosInfoEvent`:**  用于标记一段代码位置信息记录的开始和结束。

**2. 采样线程 (SamplingThread)**:

*   这是一个内部线程，用于周期性地调用 `sampler::Sampler::DoSample()` 方法，进行 CPU 性能采样。

**3. ETW JIT 日志记录 (ETWJitLogger)**:

*   在 Windows 系统且启用了 ETW stack walking 的情况下，使用 ETW (Event Tracing for Windows) 机制记录 JIT 代码事件。

**4. 分析器 (Profiler)**:

*   **CPU 性能采样:**  `Profiler` 类是一个线程，负责收集 V8 主线程的 PC (程序计数器) 和 SP (堆栈指针) 值，用于生成 CPU 使用率报告。
*   **数据缓冲:** 使用一个环形缓冲区 `buffer_` 来存储采样数据，以减少采样过程中的性能开销。
*   **同步机制:** 使用信号量 `buffer_semaphore_` 来同步采样数据的生产和消费。
*   **启动和停止:** `Engage()` 方法启动分析器线程并开始采样，`Disengage()` 方法停止分析器线程。

**5. 计时器 (Ticker)**:

*   `Ticker` 类继承自 `sampler::Sampler`，负责周期性地触发采样操作。
*   它拥有一个 `SamplingThread` 实例来执行实际的采样。
*   与 `Profiler` 关联: `SetProfiler()` 方法将 `Ticker` 与 `Profiler` 连接起来，使得每次采样时，`Profiler` 能够接收到采样数据。

**6. V8 文件日志记录器 (V8FileLogger)**:

*   **事件记录核心:** `V8FileLogger` 类负责将各种事件信息写入日志文件。
*   **时间戳:**  记录事件发生的时间。
*   **状态管理:**  跟踪日志记录的启动和停止状态。
*   **代码创建事件:** 记录各种类型的代码（Builtins, Bytecode handlers, Scripts, Functions, WebAssembly 代码, RegExp 代码）的创建事件，包括代码地址、大小、名称、源代码信息等。
*   **反馈向量事件 (`FeedbackVectorEvent`)**: 记录反馈向量的信息，用于优化代码执行。
*   **代码移动事件 (`CodeMoveEvent`, `BytecodeMoveEvent`):**  记录代码或字节码在内存中的移动。
*   **共享函数信息移动事件 (`SharedFunctionInfoMoveEvent`):** 记录共享函数信息在内存中的移动。
*   **代码禁用优化事件 (`CodeDisableOptEvent`):** 记录代码由于某些原因被禁用优化的情况。
*   **代码反优化事件 (`CodeDeoptEvent`, `CodeDependencyChangeEvent`):** 记录代码反优化事件以及导致反优化的原因。
*   **代码行号位置信息事件 (`CodeLinePosInfoRecordEvent`, `WasmCodeLinePosInfoRecordEvent`):** 记录代码指令与源代码行号的映射关系。
*   **代码名称事件 (`CodeNameEvent`):**  记录代码对象的名称。
*   **回调事件 (`CallbackEvent`, `GetterCallbackEvent`, `SetterCallbackEvent`):** 记录 JavaScript 回调函数的创建。
*   **正则表达式代码创建事件 (`RegExpCodeCreateEvent`):** 记录正则表达式代码的创建。
*   **共享库事件 (`SharedLibraryEvent`, `SharedLibraryEnd`):** 记录加载的共享库的信息，用于 C++ 性能分析。
*   **计时器事件 (`TimerEvent`):** 记录自定义的计时器事件。

**关于代码特性的回答:**

*   **`.tq` 结尾:**  `v8/src/logging/log.cc` 以 `.cc` 结尾，因此它不是 v8 Torque 源代码。
*   **与 JavaScript 的关系:**  `v8/src/logging/log.cc` 与 JavaScript 的功能密切相关。它记录了 JavaScript 代码的编译、执行、优化和反优化等关键事件。

**JavaScript 举例说明:**

假设以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(1, 2);
```

当 V8 执行这段代码时，`v8/src/logging/log.cc` 中的代码可能会记录以下事件（简化示例）：

*   **`CodeCreateEvent` (Builtin):**  记录创建内置函数 (例如用于执行 `+` 操作的函数) 的事件。
*   **`CodeCreateEvent` (Script):** 记录创建 `add` 函数对应的 JavaScript 代码的事件，包括其在脚本中的位置。
*   **`CodeCreateEvent` (JITed Code):**  记录 `add` 函数被 JIT 编译成机器码的事件。
*   **`CodeMoveEvent`:**  如果 JIT 生成的代码被移动到新的内存地址，则会记录此事件。
*   **`CodeDeoptEvent`:** 如果 `add` 函数的代码因为某些原因被反优化，则会记录此事件。
*   **`ProfilerBeginEvent` 和 `TickEvent`:** 如果启用了分析器，会记录分析器启动和定期的 CPU 采样数据。

**代码逻辑推理 (假设输入与输出):**

考虑 `JitLogger::CodeMoveEvent` 函数。

**假设输入:**

*   `from`: 一个 `InstructionStream` 对象，代表代码移动前的内存地址，例如内存地址 `0x1000`，代码长度为 `100` 字节。
*   `to`: 一个 `InstructionStream` 对象，代表代码移动后的内存地址，例如内存地址 `0x2000`。

**输出:**

会向日志系统发送一个 `JitCodeEvent`，其属性可能如下：

*   `type`: `JitCodeEvent::CODE_MOVED`
*   `code_type`: `JitCodeEvent::JIT_CODE`
*   `code_start`: `0x1000`
*   `code_len`: `100`
*   `new_code_start`: `0x2000`

**用户常见的编程错误:**

虽然 `v8/src/logging/log.cc` 本身不是用来直接捕获用户编程错误的，但它记录的事件可以帮助开发者诊断性能问题，这些问题可能源于常见的编程错误，例如：

*   **频繁的代码反优化:**  如果日志中出现大量的 `CodeDeoptEvent`，可能表明代码存在导致 V8 无法进行有效优化的模式，例如类型不稳定、使用了过多的 `try-catch` 等。
*   **内存泄漏 (间接体现):**  虽然日志本身不直接报告内存泄漏，但通过分析代码创建和垃圾回收事件，可以辅助定位潜在的内存泄漏问题。
*   **性能瓶颈:**  通过分析分析器 (Profiler) 记录的 `TickEvent`，可以找到 CPU 占用率高的代码区域，这些区域可能存在性能瓶颈。

**总结:**

`v8/src/logging/log.cc` 的这部分代码主要负责在 V8 虚拟机运行时记录各种关键事件，包括 JIT 代码的创建和移动、字节码的移动、代码优化和反优化、WebAssembly 代码的创建、CPU 性能采样数据等等。这些日志信息对于理解 V8 的内部工作原理、进行性能分析、调试和诊断问题至关重要。 它通过 `JitLogger` 和 `V8FileLogger` 等类实现，利用线程和同步机制来高效地收集和记录事件信息。

### 提示词
```
这是目录为v8/src/logging/log.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/logging/log.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
st<v8::Isolate*>(isolate_);

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