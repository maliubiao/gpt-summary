Response: The user wants to understand the functionality of the C++ source code file `perfetto-logger.cc`. I need to analyze the code and summarize its purpose. Specifically, I should identify if and how it relates to JavaScript functionality and provide a JavaScript example if a connection exists.

Looking at the includes and the namespace, it's clear that this code is related to tracing and logging within the V8 JavaScript engine, using the Perfetto tracing system.

Key functionalities I can identify:

1. **Integration with Perfetto:** The code uses Perfetto protobuf definitions (e.g., `protos/perfetto/trace/trace_packet.pbzero.h`) and interacts with `CodeDataSource` which seems to be an abstraction for sending code-related events to Perfetto.

2. **Logging Code Events:** The class `PerfettoLogger` implements methods to log various code-related events such as code creation (`CodeCreateEvent`), code movement (`CodeMoveEvent`, `BytecodeMoveEvent`), and deoptimization (`CodeDeoptEvent`).

3. **Isolate Management:** The `IsolateRegistry` class manages the registration and unregistration of `PerfettoLogger` instances for different V8 isolates. This indicates that the logger can track code events in multiple independent JavaScript execution environments.

4. **Differentiating Code Types:** The code distinguishes between different types of code (e.g., JS code, internal code, WASM code, regexp code) and logs specific information for each.

5. **Mapping to JavaScript Concepts:**  The logged events directly correspond to actions happening during JavaScript execution, such as function compilation (different tiers like Ignition, Sparkplug, TurboFan), bytecode execution, and regular expression compilation.

6. **JavaScript Example:** To illustrate the connection, I can show how a simple JavaScript function triggers code creation and potentially optimization events that this logger would capture.
这个C++源代码文件 `perfetto-logger.cc` 的主要功能是**将 V8 JavaScript 引擎中发生的代码相关事件记录到 Perfetto 跟踪系统中**。Perfetto 是一个开源的、跨平台的跟踪和分析工具。

以下是更详细的归纳：

1. **作为 V8 和 Perfetto 之间的桥梁:** 该文件定义了一个 `PerfettoLogger` 类，它实现了 V8 引擎中定义的代码事件监听接口。当 V8 内部发生诸如代码创建、代码移动、代码优化/反优化等事件时，`PerfettoLogger` 会接收到通知，并将这些事件转换成 Perfetto 可以理解的格式并发送出去。

2. **管理不同类型的代码事件:**  `PerfettoLogger` 可以处理多种代码事件，包括：
    * **JavaScript 代码 (`V8JsCode`):**  记录 JavaScript 函数的不同编译层级 (Ignition, Sparkplug, Maglev, TurboFan) 的代码信息，包括起始地址、大小以及实际的字节码或机器码。
    * **V8 内部代码 (`V8InternalCode`):** 记录 V8 引擎内部使用的代码，例如字节码处理器、内置函数、Wasm 相关代码等。
    * **正则表达式代码 (`V8RegExpCode`):**  记录正则表达式编译后的代码信息。
    * **Wasm 代码 (`V8WasmCode`):**  记录 WebAssembly 代码的信息。
    * **代码移动事件 (`CodeMoveEvent`, `BytecodeMoveEvent`):** 记录代码在内存中的移动。
    * **代码优化/反优化事件 (`CodeDisableOptEvent`, `CodeDeoptEvent`):** 记录代码优化和反优化发生的情况。

3. **关联代码与 JavaScript 上下文:**  `PerfettoLogger` 能够将记录的代码事件与 JavaScript 的上下文关联起来，例如：
    * 通过 `SharedFunctionInfo` 关联代码和函数信息。
    * 通过 `Script` 关联代码和脚本文件信息。
    * 记录代码创建时的行号和列号。

4. **多 Isolate 支持:**  通过 `IsolateRegistry` 类，该文件支持在多个 V8 Isolate (独立的 JavaScript 执行环境) 中记录代码事件。

5. **按需记录指令:**  通过检查 `ctx.log_instructions()`，可以控制是否记录实际的机器码或字节码，这在性能敏感的场景下非常有用。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`perfetto-logger.cc` 的功能与 JavaScript 的运行时行为密切相关。 它记录的是 V8 引擎在执行 JavaScript 代码过程中产生的各种事件。 例如，当你定义一个 JavaScript 函数并执行它时，`PerfettoLogger` 可能会记录以下事件：

* **代码创建事件 (`CodeCreateEvent`)：**
    * 当 JavaScript 函数首次被解释执行时，会生成 Ignition 字节码。`PerfettoLogger` 会记录这个字节码的信息。
    * 随着执行次数增加，V8 可能会对函数进行优化编译，生成更高性能的机器码（例如 Sparkplug 或 TurboFan）。 `PerfettoLogger` 会记录这些优化后的代码信息。

* **代码移动事件 (`CodeMoveEvent`, `BytecodeMoveEvent`)：**  在垃圾回收等过程中，代码可能在内存中被移动，`PerfettoLogger` 会记录这些移动。

* **代码反优化事件 (`CodeDeoptEvent`)：** 如果 V8 发现之前的优化假设不再成立，它会将代码反优化回较低的层级，`PerfettoLogger` 会记录这次反优化。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

for (let i = 0; i < 10000; i++) {
  add(i, i + 1);
}
```

在这个简单的 JavaScript 代码中：

1. 当 `add` 函数首次被调用时，V8 会为其生成 Ignition 字节码。`PerfettoLogger` 会记录一个类型为 `V8JsCode`，层级为 `TIER_IGNITION` 的 `CodeCreateEvent`。

2. 由于 `add` 函数在循环中被多次调用，V8 可能会对其进行优化。例如，如果 V8 决定使用 TurboFan 进行优化，`PerfettoLogger` 可能会记录另一个 `CodeCreateEvent`，这次的类型仍然是 `V8JsCode`，但层级会是 `TIER_TURBOFAN`，并且记录的是优化后的机器码信息。

3. 如果由于某些原因，V8 需要将优化后的代码反优化，`PerfettoLogger` 会记录一个 `CodeDeoptEvent`。

**总结:**

`perfetto-logger.cc` 是 V8 引擎中用于将 JavaScript 代码执行过程中的底层细节（例如代码的生成、优化、移动等）暴露给 Perfetto 跟踪系统的关键组件。这对于性能分析、理解 V8 的内部工作机制以及调试 JavaScript 应用程序的性能问题非常有帮助。 通过 Perfetto 提供的工具，开发者可以可视化这些跟踪数据，深入了解 JavaScript 代码的执行情况。

Prompt: 
```
这是目录为v8/src/tracing/perfetto-logger.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/tracing/perfetto-logger.h"

#include <memory>

#include "absl/container/flat_hash_map.h"
#include "protos/perfetto/common/builtin_clock.pbzero.h"
#include "protos/perfetto/trace/chrome/v8.pbzero.h"
#include "protos/perfetto/trace/trace_packet.pbzero.h"
#include "protos/perfetto/trace/trace_packet_defaults.pbzero.h"
#include "src/base/logging.h"
#include "src/base/platform/mutex.h"
#include "src/base/platform/platform.h"
#include "src/base/platform/time.h"
#include "src/builtins/builtins.h"
#include "src/execution/isolate.h"
#include "src/handles/handles.h"
#include "src/heap/spaces.h"
#include "src/logging/log.h"
#include "src/objects/abstract-code.h"
#include "src/objects/code-kind.h"
#include "src/objects/heap-object.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/script.h"
#include "src/objects/string.h"
#include "src/objects/tagged.h"
#include "src/tracing/code-data-source.h"
#include "src/tracing/code-trace-context.h"
#include "src/tracing/perfetto-utils.h"

namespace v8 {
namespace internal {
namespace {

using ::perfetto::protos::pbzero::BuiltinClock;
using ::perfetto::protos::pbzero::TracePacket;
using ::perfetto::protos::pbzero::V8InternalCode;
using ::perfetto::protos::pbzero::V8JsCode;

CodeDataSource::TraceContext::TracePacketHandle NewTracePacket(
    CodeDataSource::TraceContext& context) {
  CodeDataSourceIncrementalState* inc_state = context.GetIncrementalState();
  auto packet = context.NewTracePacket();
  packet->set_timestamp(base::TimeTicks::Now().since_origin().InNanoseconds());

  if (inc_state->is_initialized()) {
    packet->set_sequence_flags(TracePacket::SEQ_NEEDS_INCREMENTAL_STATE);
    return packet;
  }

  inc_state->Init(context);

  packet->set_sequence_flags(TracePacket::SEQ_INCREMENTAL_STATE_CLEARED);

  auto* defaults = packet->set_trace_packet_defaults();
  defaults->set_timestamp_clock_id(BuiltinClock::BUILTIN_CLOCK_MONOTONIC);

  auto* v8_defaults = defaults->set_v8_code_defaults();
  v8_defaults->set_tid(base::OS::GetCurrentThreadId());

  return packet;
}

CodeTraceContext NewCodeTraceContext(CodeDataSource::TraceContext& ctx) {
  return CodeTraceContext(NewTracePacket(ctx), ctx.GetIncrementalState());
}

class IsolateRegistry {
 public:
  static IsolateRegistry& GetInstance() {
    static IsolateRegistry* g_instance = new IsolateRegistry();
    return *g_instance;
  }

  void Register(Isolate* isolate) {
    auto logger = std::make_unique<PerfettoLogger>(isolate);
    base::MutexGuard lock(&mutex_);
    if (num_active_data_sources_ != 0) {
      isolate->logger()->AddListener(logger.get());
    }
    CHECK(isolates_.emplace(isolate, std::move(logger)).second);
  }

  void Unregister(Isolate* isolate) {
    base::MutexGuard lock(&mutex_);
    auto it = isolates_.find(isolate);
    CHECK(it != isolates_.end());
    if (num_active_data_sources_ != 0) {
      isolate->logger()->RemoveListener(it->second.get());
    }
    isolates_.erase(it);
  }

  void OnCodeDataSourceStart() {
    base::MutexGuard lock(&mutex_);
    ++num_active_data_sources_;
    if (num_active_data_sources_ == 1) {
      StartLogging(lock);
    }
    LogExistingCodeForAllIsolates(lock);
  }

  void OnCodeDataSourceStop() {
    base::MutexGuard lock(&mutex_);
    DCHECK_LT(0, num_active_data_sources_);
    --num_active_data_sources_;
    if (num_active_data_sources_ == 0) {
      StopLogging(lock);
    }
  }

 private:
  void StartLogging(const base::MutexGuard&) {
    for (const auto& [isolate, logger] : isolates_) {
      isolate->logger()->AddListener(logger.get());
    }
  }

  void StopLogging(const base::MutexGuard&) {
    for (const auto& [isolate, logger] : isolates_) {
      isolate->logger()->RemoveListener(logger.get());
    }
  }

  void LogExistingCodeForAllIsolates(const base::MutexGuard&) {
    for (const auto& [isolate, listener] : isolates_) {
      isolate->RequestInterrupt(
          [](v8::Isolate*, void* data) {
            PerfettoLogger* listener = reinterpret_cast<PerfettoLogger*>(data);
            listener->LogExistingCode();
          },
          listener.get());
    }
  }

  base::Mutex mutex_;
  int num_active_data_sources_ = 0;
  absl::flat_hash_map<Isolate*, std::unique_ptr<PerfettoLogger>> isolates_;
};

void WriteJsCode(const CodeTraceContext& ctx,
                 Tagged<AbstractCode> abstract_code, V8JsCode& code_proto) {
  if (IsBytecodeArray(abstract_code)) {
    Tagged<BytecodeArray> bytecode = abstract_code->GetBytecodeArray();
    code_proto.set_tier(V8JsCode::TIER_IGNITION);
    code_proto.set_instruction_start(bytecode->GetFirstBytecodeAddress());
    code_proto.set_instruction_size_bytes(bytecode->length());
    if (ctx.log_instructions()) {
      code_proto.set_bytecode(
          reinterpret_cast<const uint8_t*>(bytecode->GetFirstBytecodeAddress()),
          bytecode->length());
    }
    return;
  }

  DCHECK(IsCode(abstract_code));
  Tagged<Code> code = abstract_code->GetCode();

  V8JsCode::Tier tier = V8JsCode::TIER_UNKNOWN;
  switch (code->kind()) {
    case CodeKind::BUILTIN:
      if (code->builtin_id() == Builtin::kInterpreterEntryTrampoline) {
        DCHECK(v8_flags.interpreted_frames_native_stack);
        DCHECK(code->has_instruction_stream());
        tier = V8JsCode::TIER_IGNITION;
        break;
      }

      // kEmptyFunction is used as a placeholder sometimes.
      DCHECK_EQ(code->builtin_id(), Builtin::kEmptyFunction);
      DCHECK(!code->has_instruction_stream());
      return;

    case CodeKind::INTERPRETED_FUNCTION:
      // Handled above.
      UNREACHABLE();

    case CodeKind::BASELINE:
      tier = V8JsCode::TIER_SPARKPLUG;
      break;
    case CodeKind::MAGLEV:
      tier = V8JsCode::TIER_MAGLEV;
      break;
    case CodeKind::TURBOFAN_JS:
      tier = V8JsCode::TIER_TURBOFAN;
      break;

    case CodeKind::BYTECODE_HANDLER:
    case CodeKind::FOR_TESTING:
    case CodeKind::REGEXP:
    case CodeKind::WASM_FUNCTION:
    case CodeKind::WASM_TO_CAPI_FUNCTION:
    case CodeKind::WASM_TO_JS_FUNCTION:
    case CodeKind::JS_TO_WASM_FUNCTION:
    case CodeKind::C_WASM_ENTRY:
      UNREACHABLE();
  }

  code_proto.set_tier(tier);
  code_proto.set_instruction_start(code->instruction_start());
  code_proto.set_instruction_size_bytes(code->instruction_size());
  if (ctx.log_instructions()) {
    code_proto.set_machine_code(
        reinterpret_cast<const uint8_t*>(code->instruction_start()),
        code->instruction_size());
  }
}

}  // namespace

// static
void PerfettoLogger::RegisterIsolate(Isolate* isolate) {
  IsolateRegistry::GetInstance().Register(isolate);
  // TODO(carlscab): Actually if both perfetto and file logging are active the
  // builtins will be logged twice to the file (EmitCodeCreateEvents is called
  // somewhere in the isolate setup code). Probably not very likely to happen
  // but we should find a better way.
  CodeDataSource::CallIfEnabled(
      [isolate](uint32_t) { Builtins::EmitCodeCreateEvents(isolate); });
}

// static
void PerfettoLogger::UnregisterIsolate(Isolate* isolate) {
  IsolateRegistry::GetInstance().Unregister(isolate);
}

// static
void PerfettoLogger::OnCodeDataSourceStart() {
  IsolateRegistry::GetInstance().OnCodeDataSourceStart();
}

// static
void PerfettoLogger::OnCodeDataSourceStop() {
  IsolateRegistry::GetInstance().OnCodeDataSourceStop();
}

void PerfettoLogger::LogExistingCode() {
  HandleScope scope(&isolate_);
  ExistingCodeLogger logger(&isolate_, this);
  logger.LogBuiltins();
  logger.LogCodeObjects();
  logger.LogCompiledFunctions();
}

PerfettoLogger::PerfettoLogger(Isolate* isolate) : isolate_(*isolate) {}
PerfettoLogger::~PerfettoLogger() {}

void PerfettoLogger::CodeCreateEvent(CodeTag tag,
                                     Handle<AbstractCode> abstract_code,
                                     const char* name) {
  DisallowGarbageCollection no_gc;
  if (!IsCode(*abstract_code)) return;
  Tagged<Code> code = abstract_code->GetCode();

  V8InternalCode::Type type = V8InternalCode::TYPE_UNKNOWN;
  switch (code->kind()) {
    case CodeKind::REGEXP:
      RegExpCodeCreateEvent(abstract_code, Handle<String>(), {});
      break;
    case CodeKind::BYTECODE_HANDLER:
      type = V8InternalCode::TYPE_BYTECODE_HANDLER;
      break;
    case CodeKind::FOR_TESTING:
      type = V8InternalCode::TYPE_FOR_TESTING;
      break;
    case CodeKind::BUILTIN:
      type = V8InternalCode::TYPE_BUILTIN;
      break;
    case CodeKind::WASM_FUNCTION:
      type = V8InternalCode::TYPE_WASM_FUNCTION;
      break;
    case CodeKind::WASM_TO_CAPI_FUNCTION:
      type = V8InternalCode::TYPE_WASM_TO_CAPI_FUNCTION;
      break;
    case CodeKind::WASM_TO_JS_FUNCTION:
      type = V8InternalCode::TYPE_WASM_TO_JS_FUNCTION;
      break;
    case CodeKind::JS_TO_WASM_FUNCTION:
      type = V8InternalCode::TYPE_JS_TO_WASM_FUNCTION;
      break;
    case CodeKind::C_WASM_ENTRY:
      type = V8InternalCode::TYPE_C_WASM_ENTRY;
      break;

    case CodeKind::INTERPRETED_FUNCTION:
    case CodeKind::BASELINE:
    case CodeKind::MAGLEV:
    case CodeKind::TURBOFAN_JS:
      UNREACHABLE();
  }

  CodeDataSource::Trace(
      [&](v8::internal::CodeDataSource::TraceContext trace_context) {
        CodeTraceContext ctx = NewCodeTraceContext(trace_context);

        auto* code_proto = ctx.set_v8_internal_code();
        code_proto->set_v8_isolate_iid(ctx.InternIsolate(isolate_));
        code_proto->set_name(name);
        code_proto->set_type(type);
        if (code->is_builtin()) {
          code_proto->set_builtin_id(static_cast<int32_t>(code->builtin_id()));
        }
        code_proto->set_instruction_start(code->instruction_start());
        code_proto->set_instruction_size_bytes(code->instruction_size());
        if (ctx.log_instructions()) {
          code_proto->set_machine_code(
              reinterpret_cast<const uint8_t*>(code->instruction_start()),
              code->instruction_size());
        }
      });
}

void PerfettoLogger::CodeCreateEvent(CodeTag tag,
                                     Handle<AbstractCode> abstract_code,
                                     Handle<Name> name) {
  DisallowGarbageCollection no_gc;
  if (!IsString(*name)) return;
  CodeCreateEvent(tag, abstract_code, Cast<String>(*name)->ToCString().get());
}

void PerfettoLogger::CodeCreateEvent(CodeTag tag,
                                     Handle<AbstractCode> abstract_code,
                                     Handle<SharedFunctionInfo> info,
                                     Handle<Name> script_name) {
  CodeCreateEvent(tag, abstract_code, info, script_name, 0, 0);
}

void PerfettoLogger::CodeCreateEvent(CodeTag tag,
                                     Handle<AbstractCode> abstract_code,
                                     Handle<SharedFunctionInfo> info,
                                     Handle<Name> script_name, int line,
                                     int column) {
  DisallowGarbageCollection no_gc;
  DCHECK(IsScript(info->script()));

  CodeDataSource::Trace(
      [&](v8::internal::CodeDataSource::TraceContext trace_context) {
        CodeTraceContext ctx = NewCodeTraceContext(trace_context);

        auto* code_proto = ctx.set_v8_js_code();
        code_proto->set_v8_isolate_iid(ctx.InternIsolate(isolate_));
        code_proto->set_v8_js_function_iid(ctx.InternJsFunction(
            isolate_, info,
            ctx.InternJsScript(isolate_, Cast<Script>(info->script())), line,
            column));
        WriteJsCode(ctx, *abstract_code, *code_proto);
      });
}
#if V8_ENABLE_WEBASSEMBLY
void PerfettoLogger::CodeCreateEvent(CodeTag tag, const wasm::WasmCode* code,
                                     wasm::WasmName name,
                                     const char* source_url, int code_offset,
                                     int script_id) {
  DisallowGarbageCollection no_gc;

  CodeDataSource::Trace(
      [&](v8::internal::CodeDataSource::TraceContext trace_context) {
        CodeTraceContext ctx = NewCodeTraceContext(trace_context);

        auto* code_proto = ctx.set_v8_wasm_code();
        code_proto->set_v8_isolate_iid(ctx.InternIsolate(isolate_));
        code_proto->set_v8_wasm_script_iid(
            ctx.InternWasmScript(isolate_, script_id, source_url));
        code_proto->set_function_name(name.begin(), name.size());
        // TODO(carlscab): Set tier
        code_proto->set_instruction_start(code->instruction_start());
        code_proto->set_instruction_size_bytes(code->instructions_size());
        if (ctx.log_instructions()) {
          code_proto->set_machine_code(
              reinterpret_cast<const uint8_t*>(code->instruction_start()),
              code->instructions_size());
        }
      });
}
#endif  // V8_ENABLE_WEBASSEMBLY

void PerfettoLogger::CallbackEvent(Handle<Name> name, Address entry_point) {}
void PerfettoLogger::GetterCallbackEvent(Handle<Name> name,
                                         Address entry_point) {}
void PerfettoLogger::SetterCallbackEvent(Handle<Name> name,
                                         Address entry_point) {}
void PerfettoLogger::RegExpCodeCreateEvent(Handle<AbstractCode> abstract_code,
                                           Handle<String> pattern,
                                           RegExpFlags flags) {
  DisallowGarbageCollection no_gc;
  DCHECK(IsCode(*abstract_code));
  Tagged<Code> code = abstract_code->GetCode();
  DCHECK(code->kind() == CodeKind::REGEXP);

  CodeDataSource::Trace(
      [&](v8::internal::CodeDataSource::TraceContext trace_context) {
        CodeTraceContext ctx = NewCodeTraceContext(trace_context);

        auto* code_proto = ctx.set_v8_reg_exp_code();
        code_proto->set_v8_isolate_iid(ctx.InternIsolate(isolate_));

        if (!pattern.is_null()) {
          PerfettoV8String(*pattern).WriteToProto(*code_proto->set_pattern());
        }
        code_proto->set_instruction_start(code->instruction_start());
        code_proto->set_instruction_size_bytes(code->instruction_size());
        if (ctx.log_instructions()) {
          code_proto->set_machine_code(
              reinterpret_cast<const uint8_t*>(code->instruction_start()),
              code->instruction_size());
        }
      });
}

void PerfettoLogger::CodeMoveEvent(Tagged<InstructionStream> from,
                                   Tagged<InstructionStream> to) {
  CodeDataSource::Trace(
      [&](v8::internal::CodeDataSource::TraceContext trace_context) {
        CodeTraceContext ctx = NewCodeTraceContext(trace_context);
        auto* code_move = ctx.set_code_move();
        code_move->set_isolate_iid(ctx.InternIsolate(isolate_));
        code_move->set_from_instruction_start_address(
            from->instruction_start());
        code_move->set_to_instruction_start_address(to->instruction_start());
        Tagged<Code> code = to->code(AcquireLoadTag());
        code_move->set_instruction_size_bytes(code->instruction_size());
        if (ctx.log_instructions()) {
          code_move->set_to_machine_code(
              reinterpret_cast<const uint8_t*>(code->instruction_start()),
              code->instruction_size());
        }
      });
}
void PerfettoLogger::BytecodeMoveEvent(Tagged<BytecodeArray> from,
                                       Tagged<BytecodeArray> to) {
  CodeDataSource::Trace(
      [&](v8::internal::CodeDataSource::TraceContext trace_context) {
        CodeTraceContext ctx = NewCodeTraceContext(trace_context);
        auto* code_move = ctx.set_code_move();
        code_move->set_isolate_iid(ctx.InternIsolate(isolate_));
        code_move->set_from_instruction_start_address(
            from->GetFirstBytecodeAddress());
        code_move->set_to_instruction_start_address(
            to->GetFirstBytecodeAddress());
        code_move->set_instruction_size_bytes(to->length());
        if (ctx.log_instructions()) {
          code_move->set_to_bytecode(
              reinterpret_cast<const uint8_t*>(to->GetFirstBytecodeAddress()),
              to->length());
        }
      });
}

void PerfettoLogger::SharedFunctionInfoMoveEvent(Address from, Address to) {}
void PerfettoLogger::NativeContextMoveEvent(Address from, Address to) {}
void PerfettoLogger::CodeMovingGCEvent() {}
void PerfettoLogger::CodeDisableOptEvent(Handle<AbstractCode> code,
                                         Handle<SharedFunctionInfo> shared) {}
void PerfettoLogger::CodeDeoptEvent(Handle<Code> code, DeoptimizeKind kind,
                                    Address pc, int fp_to_sp_delta) {}
void PerfettoLogger::CodeDependencyChangeEvent(
    Handle<Code> code, Handle<SharedFunctionInfo> shared, const char* reason) {}
void PerfettoLogger::WeakCodeClearEvent() {}

bool PerfettoLogger::is_listening_to_code_events() { return true; }

}  // namespace internal
}  // namespace v8

"""

```