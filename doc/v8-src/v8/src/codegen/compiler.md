Response: The user wants to understand the functionality of the C++ source code file `compiler.cc` within the V8 JavaScript engine.

**Plan:**

1. **High-level overview:** Read through the included headers and the namespace to get a general idea of the file's purpose.
2. **Key data structures:** Identify central classes and structures like `CompilationJob`, `UnoptimizedCompilationJob`, `OptimizedCompilationJob`, `CompilerTracer`, and `OptimizedCodeCache`.
3. **Core functionalities:**  Focus on functions like `CompileToplevel`, `CompileTurbofan`, `CompileMaglev`, and the various tracing and logging functions.
4. **Relationship to JavaScript:**  Look for connections between the compilation process and JavaScript concepts like functions, scripts, optimization, and debugging.
5. **Illustrative JavaScript example:**  If a connection is clear, create a simple JavaScript example that triggers the functionalities described in the C++ code.
这个C++源代码文件 `compiler.cc` 的主要功能是**负责将JavaScript源代码编译成可执行代码**。它是V8引擎中代码生成流程的核心部分，涵盖了从解释执行到优化编译的各个阶段。

具体来说，这个文件的第一部分主要涉及以下功能：

1. **定义了编译过程中的各种数据结构和类：**
    *   `CompilationJob`: 作为编译任务的基类，定义了编译任务的生命周期和通用接口。
    *   `UnoptimizedCompilationJob`:  负责执行非优化编译（通常是解释器代码）。
    *   `OptimizedCompilationJob`: 负责执行优化编译（例如Turbofan或Maglev）。
    *   `CompilerTracer`: 用于在编译过程中输出详细的跟踪信息，方便调试和性能分析。
    *   内部的匿名命名空间定义了一些辅助函数和常量。

2. **提供了编译过程的日志和追踪机制：**
    *   `Compiler::LogFunctionCompilation`: 记录函数编译的信息，包括代码类型、脚本信息、执行时间等。
    *   `CompilerTracer` 中的各种静态方法 (`TraceStartBaselineCompile`, `TraceStartMaglevCompile`, `TraceOptimizeOSRStarted` 等) 用于输出编译过程中的关键事件，例如开始编译、完成编译、OSR（On-Stack Replacement）等。这些跟踪信息可以通过 V8 的命令行标志来启用。

3. **实现了非优化编译的流程框架：**
    *   `UnoptimizedCompilationJob` 的 `ExecuteJob` 和 `FinalizeJob` 方法定义了非优化编译任务的执行和完成阶段。
    *   涉及到解析（parsing）、生成字节码（bytecode）等过程，这些过程在 `UnoptimizedCompilationJob` 的具体实现中完成。

4. **实现了优化编译的流程框架：**
    *   `OptimizedCompilationJob` 的 `PrepareJob`, `ExecuteJob`, `FinalizeJob` 方法定义了优化编译任务的准备、执行和完成阶段。
    *   `TurbofanCompilationJob` 是 `OptimizedCompilationJob` 的一个具体子类，专门负责 Turbofan 优化编译。
    *   `OptimizedCodeCache`:  用于缓存优化后的代码，避免重复编译，提高性能。

5. **处理On-Stack Replacement (OSR) 的逻辑：**
    *   `CompilerTracer` 中包含了针对 OSR 的跟踪方法，例如 `TraceOptimizeOSRStarted`, `TraceOptimizeOSRFinished` 等。
    *   `OptimizedCompilationInfo` 中存储了 OSR 相关的偏移量信息 (`osr_offset`)。

6. **与 WebAssembly (Wasm) 相关的功能 (如果启用)：**
    *   包含对 Asm.js/Wasm 编译的支持 (`UseAsmWasm`)，尽管这部分代码被条件编译包裹。

**与 JavaScript 的功能关系：**

这个文件直接负责将你编写的 JavaScript 代码转换成 V8 引擎可以执行的机器码或字节码。  它处理了不同优化级别的编译，从最初的解释执行所需的字节码生成，到后续通过 Turbofan 或 Maglev 等优化编译器生成高性能的机器码。

**JavaScript 举例说明：**

```javascript
function add(a, b) {
  return a + b;
}

// 第一次调用，可能会通过解释器执行（对应 Compiler 中的非优化编译）
add(1, 2);

// 多次调用后，V8 可能会决定对该函数进行优化编译（对应 Compiler 中的优化编译，例如 Turbofan）
for (let i = 0; i < 10000; i++) {
  add(i, i + 1);
}

// 如果在循环执行过程中，V8 发现 `add` 函数需要在当前栈帧中进行优化（例如，由于代码热点），
// 就会触发 On-Stack Replacement (OSR)。

// 另外，如果这段代码是在 eval 中执行的，Compiler 会处理相应的 eval 编译流程。
eval('function multiply(x, y) { return x * y; } multiply(3, 4);');
```

**解释：**

*   当 `add(1, 2)` 第一次被调用时，V8 可能会使用解释器来执行这段代码。 `compiler.cc` 中与非优化编译相关的部分（例如 `UnoptimizedCompilationJob` 和解释器相关的代码）会被触发，将 JavaScript 源代码转换为字节码并执行。
*   当 `add` 函数在循环中被多次调用后，V8 的优化系统（例如 Crankshaft 或 Turbofan，取决于 V8 的版本和配置）会认为这是一个“热点”函数，并决定对其进行优化编译。 `compiler.cc` 中与优化编译相关的部分（例如 `OptimizedCompilationJob` 和 `TurbofanCompilationJob`）会被调用，将 `add` 函数编译成更高效的机器码。
*   如果在循环执行过程中，V8 决定进行 OSR，`compiler.cc` 中的 OSR 相关逻辑会被触发，允许 V8 在函数执行的过程中切换到优化后的代码。
*   `eval` 函数的调用会触发 V8 的 `eval` 编译流程，`compiler.cc` 中会处理与 `eval` 相关的脚本和函数的编译。

总而言之，`compiler.cc` 是 V8 引擎将 JavaScript 代码“翻译”成计算机可以理解并执行的指令的关键组件。它负责代码生成和优化的核心流程。

Prompt: 
```
这是目录为v8/src/codegen/compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/compiler.h"

#include <algorithm>
#include <memory>
#include <optional>

#include "src/api/api-inl.h"
#include "src/asmjs/asm-js.h"
#include "src/ast/prettyprinter.h"
#include "src/ast/scopes.h"
#include "src/base/logging.h"
#include "src/base/platform/time.h"
#include "src/baseline/baseline.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/codegen/pending-optimization-table.h"
#include "src/codegen/script-details.h"
#include "src/codegen/unoptimized-compilation-info.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/compiler-dispatcher/lazy-compile-dispatcher.h"
#include "src/compiler-dispatcher/optimizing-compile-dispatcher.h"
#include "src/compiler/turbofan.h"
#include "src/debug/debug.h"
#include "src/debug/liveedit.h"
#include "src/diagnostics/code-tracer.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/isolate.h"
#include "src/execution/local-isolate.h"
#include "src/execution/vm-state-inl.h"
#include "src/flags/flags.h"
#include "src/handles/global-handles-inl.h"
#include "src/handles/handles.h"
#include "src/handles/maybe-handles.h"
#include "src/handles/persistent-handles.h"
#include "src/heap/heap-inl.h"
#include "src/heap/local-factory-inl.h"
#include "src/heap/local-heap-inl.h"
#include "src/heap/parked-scope-inl.h"
#include "src/heap/visit-object.h"
#include "src/init/bootstrapper.h"
#include "src/interpreter/interpreter.h"
#include "src/logging/counters-scopes.h"
#include "src/logging/log-inl.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/feedback-cell-inl.h"
#include "src/objects/js-function-inl.h"
#include "src/objects/map.h"
#include "src/objects/object-list-macros.h"
#include "src/objects/objects-body-descriptors-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/string.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parser.h"
#include "src/parsing/parsing.h"
#include "src/parsing/pending-compilation-error-handler.h"
#include "src/parsing/scanner-character-streams.h"
#include "src/snapshot/code-serializer.h"
#include "src/tracing/traced-value.h"
#include "src/utils/ostreams.h"
#include "src/zone/zone-list-inl.h"  // crbug.com/v8/8816

#ifdef V8_ENABLE_MAGLEV
#include "src/maglev/maglev-concurrent-dispatcher.h"
#include "src/maglev/maglev.h"
#endif  // V8_ENABLE_MAGLEV

namespace v8 {
namespace internal {

namespace {

constexpr bool IsOSR(BytecodeOffset osr_offset) { return !osr_offset.IsNone(); }

class CompilerTracer : public AllStatic {
 public:
  static void TraceStartBaselineCompile(
      Isolate* isolate, DirectHandle<SharedFunctionInfo> shared) {
    if (!v8_flags.trace_baseline) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintTracePrefix(scope, "compiling method", shared, CodeKind::BASELINE);
    PrintTraceSuffix(scope);
  }

  static void TraceStartMaglevCompile(Isolate* isolate,
                                      DirectHandle<JSFunction> function,
                                      bool osr, ConcurrencyMode mode) {
    if (!v8_flags.trace_opt) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintTracePrefix(scope, "compiling method", function, CodeKind::MAGLEV);
    if (osr) PrintF(scope.file(), " OSR");
    PrintF(scope.file(), ", mode: %s", ToString(mode));
    PrintTraceSuffix(scope);
  }

  static void TracePrepareJob(Isolate* isolate, OptimizedCompilationInfo* info,
                              ConcurrencyMode mode) {
    if (!v8_flags.trace_opt || !info->IsOptimizing()) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintTracePrefix(scope, "compiling method", info);
    if (info->is_osr()) PrintF(scope.file(), " OSR");
    PrintF(scope.file(), ", mode: %s", ToString(mode));
    PrintTraceSuffix(scope);
  }

  static void TraceOptimizeOSRStarted(Isolate* isolate,
                                      DirectHandle<JSFunction> function,
                                      BytecodeOffset osr_offset,
                                      ConcurrencyMode mode) {
    if (!v8_flags.trace_osr) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintF(
        scope.file(),
        "[OSR - compilation started. function: %s, osr offset: %d, mode: %s]\n",
        function->DebugNameCStr().get(), osr_offset.ToInt(), ToString(mode));
  }

  static void TraceOptimizeOSRFinished(Isolate* isolate,
                                       DirectHandle<JSFunction> function,
                                       BytecodeOffset osr_offset) {
    if (!v8_flags.trace_osr) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintF(scope.file(),
           "[OSR - compilation finished. function: %s, osr offset: %d]\n",
           function->DebugNameCStr().get(), osr_offset.ToInt());
  }

  static void TraceOptimizeOSRAvailable(Isolate* isolate,
                                        DirectHandle<JSFunction> function,
                                        BytecodeOffset osr_offset,
                                        ConcurrencyMode mode) {
    if (!v8_flags.trace_osr) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintF(scope.file(),
           "[OSR - available (compilation completed or cache hit). function: "
           "%s, osr offset: %d, mode: %s]\n",
           function->DebugNameCStr().get(), osr_offset.ToInt(), ToString(mode));
  }

  static void TraceOptimizeOSRUnavailable(Isolate* isolate,
                                          DirectHandle<JSFunction> function,
                                          BytecodeOffset osr_offset,
                                          ConcurrencyMode mode) {
    if (!v8_flags.trace_osr) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintF(scope.file(),
           "[OSR - unavailable (failed or in progress). function: %s, osr "
           "offset: %d, mode: %s]\n",
           function->DebugNameCStr().get(), osr_offset.ToInt(), ToString(mode));
  }

  static void TraceFinishTurbofanCompile(Isolate* isolate,
                                         OptimizedCompilationInfo* info,
                                         double ms_creategraph,
                                         double ms_optimize,
                                         double ms_codegen) {
    DCHECK(v8_flags.trace_opt);
    DCHECK(info->IsOptimizing());
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintTracePrefix(scope, "completed compiling", info);
    if (info->is_osr()) PrintF(scope.file(), " OSR");
    PrintF(scope.file(), " - took %0.3f, %0.3f, %0.3f ms", ms_creategraph,
           ms_optimize, ms_codegen);
    PrintTraceSuffix(scope);
  }

  static void TraceFinishBaselineCompile(
      Isolate* isolate, DirectHandle<SharedFunctionInfo> shared,
      double ms_timetaken) {
    if (!v8_flags.trace_baseline) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintTracePrefix(scope, "completed compiling", shared, CodeKind::BASELINE);
    PrintF(scope.file(), " - took %0.3f ms", ms_timetaken);
    PrintTraceSuffix(scope);
  }

  static void TraceFinishMaglevCompile(Isolate* isolate,
                                       DirectHandle<JSFunction> function,
                                       bool osr, double ms_prepare,
                                       double ms_execute, double ms_finalize) {
    if (!v8_flags.trace_opt) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintTracePrefix(scope, "completed compiling", function, CodeKind::MAGLEV);
    if (osr) PrintF(scope.file(), " OSR");
    PrintF(scope.file(), " - took %0.3f, %0.3f, %0.3f ms", ms_prepare,
           ms_execute, ms_finalize);
    PrintTraceSuffix(scope);
  }

  static void TraceAbortedMaglevCompile(Isolate* isolate,
                                        DirectHandle<JSFunction> function,
                                        BailoutReason bailout_reason) {
    if (!v8_flags.trace_opt) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintTracePrefix(scope, "aborted compiling", function, CodeKind::MAGLEV);
    PrintF(scope.file(), " because: %s", GetBailoutReason(bailout_reason));
    PrintTraceSuffix(scope);
  }

  static void TraceCompletedJob(Isolate* isolate,
                                OptimizedCompilationInfo* info) {
    if (!v8_flags.trace_opt) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintTracePrefix(scope, "completed optimizing", info);
    if (info->is_osr()) PrintF(scope.file(), " OSR");
    PrintTraceSuffix(scope);
  }

  static void TraceAbortedJob(Isolate* isolate, OptimizedCompilationInfo* info,
                              double ms_prepare, double ms_execute,
                              double ms_finalize) {
    if (!v8_flags.trace_opt) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintTracePrefix(scope, "aborted optimizing", info);
    if (info->is_osr()) PrintF(scope.file(), " OSR");
    PrintF(scope.file(), " because: %s",
           GetBailoutReason(info->bailout_reason()));
    PrintF(scope.file(), " - took %0.3f, %0.3f, %0.3f ms", ms_prepare,
           ms_execute, ms_finalize);
    PrintTraceSuffix(scope);
  }

  static void TraceOptimizedCodeCacheHit(Isolate* isolate,
                                         DirectHandle<JSFunction> function,
                                         BytecodeOffset osr_offset,
                                         CodeKind code_kind) {
    if (!v8_flags.trace_opt) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintTracePrefix(scope, "found optimized code for", function, code_kind);
    if (IsOSR(osr_offset)) {
      PrintF(scope.file(), " at OSR bytecode offset %d", osr_offset.ToInt());
    }
    PrintTraceSuffix(scope);
  }

  static void TraceOptimizeForAlwaysOpt(Isolate* isolate,
                                        DirectHandle<JSFunction> function,
                                        CodeKind code_kind) {
    if (!v8_flags.trace_opt) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintTracePrefix(scope, "optimizing", function, code_kind);
    PrintF(scope.file(), " because --always-turbofan");
    PrintTraceSuffix(scope);
  }

  static void TraceMarkForAlwaysOpt(Isolate* isolate,
                                    DirectHandle<JSFunction> function) {
    if (!v8_flags.trace_opt) return;
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintF(scope.file(), "[marking ");
    ShortPrint(*function, scope.file());
    PrintF(scope.file(),
           " for optimized recompilation because --always-turbofan");
    PrintF(scope.file(), "]\n");
  }

 private:
  static void PrintTracePrefix(const CodeTracer::Scope& scope,
                               const char* header,
                               OptimizedCompilationInfo* info) {
    PrintTracePrefix(scope, header, info->closure(), info->code_kind());
  }

  static void PrintTracePrefix(const CodeTracer::Scope& scope,
                               const char* header,
                               DirectHandle<JSFunction> function,
                               CodeKind code_kind) {
    PrintF(scope.file(), "[%s ", header);
    ShortPrint(*function, scope.file());
    PrintF(scope.file(), " (target %s)", CodeKindToString(code_kind));
  }

  static void PrintTracePrefix(const CodeTracer::Scope& scope,
                               const char* header,
                               DirectHandle<SharedFunctionInfo> shared,
                               CodeKind code_kind) {
    PrintF(scope.file(), "[%s ", header);
    ShortPrint(*shared, scope.file());
    PrintF(scope.file(), " (target %s)", CodeKindToString(code_kind));
  }

  static void PrintTraceSuffix(const CodeTracer::Scope& scope) {
    PrintF(scope.file(), "]\n");
  }
};

}  // namespace

// static
void Compiler::LogFunctionCompilation(Isolate* isolate,
                                      LogEventListener::CodeTag code_type,
                                      DirectHandle<Script> script,
                                      Handle<SharedFunctionInfo> shared,
                                      Handle<FeedbackVector> vector,
                                      Handle<AbstractCode> abstract_code,
                                      CodeKind kind, double time_taken_ms) {
  DCHECK_NE(*abstract_code,
            Cast<AbstractCode>(*BUILTIN_CODE(isolate, CompileLazy)));

  // Log the code generation. If source information is available include
  // script name and line number. Check explicitly whether logging is
  // enabled as finding the line number is not free.
  if (!isolate->IsLoggingCodeCreation()) return;

  Script::PositionInfo info;
  Script::GetPositionInfo(script, shared->StartPosition(), &info);
  int line_num = info.line + 1;
  int column_num = info.column + 1;
  Handle<String> script_name(IsString(script->name())
                                 ? Cast<String>(script->name())
                                 : ReadOnlyRoots(isolate).empty_string(),
                             isolate);
  LogEventListener::CodeTag log_tag =
      V8FileLogger::ToNativeByScript(code_type, *script);
  PROFILE(isolate, CodeCreateEvent(log_tag, abstract_code, shared, script_name,
                                   line_num, column_num));
  if (!vector.is_null()) {
    LOG(isolate, FeedbackVectorEvent(*vector, *abstract_code));
  }
  if (!v8_flags.log_function_events) return;

  std::string name;
  switch (kind) {
    case CodeKind::INTERPRETED_FUNCTION:
      name = "interpreter";
      break;
    case CodeKind::BASELINE:
      name = "baseline";
      break;
    case CodeKind::MAGLEV:
      name = "maglev";
      break;
    case CodeKind::TURBOFAN_JS:
      name = "turbofan";
      break;
    default:
      UNREACHABLE();
  }
  switch (code_type) {
    case LogEventListener::CodeTag::kEval:
      name += "-eval";
      break;
    case LogEventListener::CodeTag::kScript:
    case LogEventListener::CodeTag::kFunction:
      break;
    default:
      UNREACHABLE();
  }

  DirectHandle<String> debug_name =
      SharedFunctionInfo::DebugName(isolate, shared);
  DisallowGarbageCollection no_gc;
  LOG(isolate, FunctionEvent(name.c_str(), script->id(), time_taken_ms,
                             shared->StartPosition(), shared->EndPosition(),
                             *debug_name));
}

namespace {

ScriptOriginOptions OriginOptionsForEval(
    Tagged<Object> script, ParsingWhileDebugging parsing_while_debugging) {
  bool is_shared_cross_origin =
      parsing_while_debugging == ParsingWhileDebugging::kYes;
  bool is_opaque = false;
  if (IsScript(script)) {
    auto script_origin_options = Cast<Script>(script)->origin_options();
    if (script_origin_options.IsSharedCrossOrigin()) {
      is_shared_cross_origin = true;
    }
    if (script_origin_options.IsOpaque()) {
      is_opaque = true;
    }
  }
  return ScriptOriginOptions(is_shared_cross_origin, is_opaque);
}

}  // namespace

// ----------------------------------------------------------------------------
// Implementation of UnoptimizedCompilationJob

CompilationJob::Status UnoptimizedCompilationJob::ExecuteJob() {
  // Delegate to the underlying implementation.
  DCHECK_EQ(state(), State::kReadyToExecute);
  base::ScopedTimer t(v8_flags.log_function_events ? &time_taken_to_execute_
                                                   : nullptr);
  return UpdateState(ExecuteJobImpl(), State::kReadyToFinalize);
}

CompilationJob::Status UnoptimizedCompilationJob::FinalizeJob(
    Handle<SharedFunctionInfo> shared_info, Isolate* isolate) {
  DCHECK_EQ(ThreadId::Current(), isolate->thread_id());
  DisallowCodeDependencyChange no_dependency_change;
  DisallowJavascriptExecution no_js(isolate);

  // Delegate to the underlying implementation.
  DCHECK_EQ(state(), State::kReadyToFinalize);
  base::ScopedTimer t(v8_flags.log_function_events ? &time_taken_to_finalize_
                                                   : nullptr);
  return UpdateState(FinalizeJobImpl(shared_info, isolate), State::kSucceeded);
}

CompilationJob::Status UnoptimizedCompilationJob::FinalizeJob(
    Handle<SharedFunctionInfo> shared_info, LocalIsolate* isolate) {
  // Delegate to the underlying implementation.
  DCHECK_EQ(state(), State::kReadyToFinalize);
  base::ScopedTimer t(v8_flags.log_function_events ? &time_taken_to_finalize_
                                                   : nullptr);
  return UpdateState(FinalizeJobImpl(shared_info, isolate), State::kSucceeded);
}

namespace {
void LogUnoptimizedCompilation(Isolate* isolate,
                               Handle<SharedFunctionInfo> shared,
                               LogEventListener::CodeTag code_type,
                               base::TimeDelta time_taken_to_execute,
                               base::TimeDelta time_taken_to_finalize) {
  Handle<AbstractCode> abstract_code;
  if (shared->HasBytecodeArray()) {
    abstract_code =
        handle(Cast<AbstractCode>(shared->GetBytecodeArray(isolate)), isolate);
  } else {
#if V8_ENABLE_WEBASSEMBLY
    DCHECK(shared->HasAsmWasmData());
    abstract_code = Cast<AbstractCode>(BUILTIN_CODE(isolate, InstantiateAsmJs));
#else
    UNREACHABLE();
#endif  // V8_ENABLE_WEBASSEMBLY
  }

  double time_taken_ms = time_taken_to_execute.InMillisecondsF() +
                         time_taken_to_finalize.InMillisecondsF();

  DirectHandle<Script> script(Cast<Script>(shared->script()), isolate);
  Compiler::LogFunctionCompilation(
      isolate, code_type, script, shared, Handle<FeedbackVector>(),
      abstract_code, CodeKind::INTERPRETED_FUNCTION, time_taken_ms);
}

}  // namespace

// ----------------------------------------------------------------------------
// Implementation of OptimizedCompilationJob

CompilationJob::Status OptimizedCompilationJob::PrepareJob(Isolate* isolate) {
  DCHECK_EQ(ThreadId::Current(), isolate->thread_id());
  DisallowJavascriptExecution no_js(isolate);

  // Delegate to the underlying implementation.
  DCHECK_EQ(state(), State::kReadyToPrepare);
  base::ScopedTimer t(&time_taken_to_prepare_);
  return UpdateState(PrepareJobImpl(isolate), State::kReadyToExecute);
}

CompilationJob::Status OptimizedCompilationJob::ExecuteJob(
    RuntimeCallStats* stats, LocalIsolate* local_isolate) {
  DCHECK_IMPLIES(local_isolate && !local_isolate->is_main_thread(),
                 local_isolate->heap()->IsParked());
  // Delegate to the underlying implementation.
  DCHECK_EQ(state(), State::kReadyToExecute);
  base::ScopedTimer t(&time_taken_to_execute_);
  return UpdateState(ExecuteJobImpl(stats, local_isolate),
                     State::kReadyToFinalize);
}

CompilationJob::Status OptimizedCompilationJob::FinalizeJob(Isolate* isolate) {
  DCHECK_EQ(ThreadId::Current(), isolate->thread_id());
  DisallowJavascriptExecution no_js(isolate);

  // Delegate to the underlying implementation.
  DCHECK_EQ(state(), State::kReadyToFinalize);
  base::ScopedTimer t(&time_taken_to_finalize_);
  return UpdateState(FinalizeJobImpl(isolate), State::kSucceeded);
}

GlobalHandleVector<Map> OptimizedCompilationJob::CollectRetainedMaps(
    Isolate* isolate, DirectHandle<Code> code) {
  DCHECK(code->is_optimized_code());

  DisallowGarbageCollection no_gc;
  GlobalHandleVector<Map> maps(isolate->heap());
  PtrComprCageBase cage_base(isolate);
  int const mode_mask = RelocInfo::EmbeddedObjectModeMask();
  for (RelocIterator it(*code, mode_mask); !it.done(); it.next()) {
    DCHECK(RelocInfo::IsEmbeddedObjectMode(it.rinfo()->rmode()));
    Tagged<HeapObject> target_object = it.rinfo()->target_object(cage_base);
    if (code->IsWeakObjectInOptimizedCode(target_object)) {
      if (IsMap(target_object, cage_base)) {
        maps.Push(Cast<Map>(target_object));
      }
    }
  }
  return maps;
}

void OptimizedCompilationJob::RegisterWeakObjectsInOptimizedCode(
    Isolate* isolate, DirectHandle<NativeContext> context,
    DirectHandle<Code> code, GlobalHandleVector<Map> maps) {
  isolate->heap()->AddRetainedMaps(context, std::move(maps));
  code->set_can_have_weak_objects(true);
}

CompilationJob::Status TurbofanCompilationJob::RetryOptimization(
    BailoutReason reason) {
  DCHECK(compilation_info_->IsOptimizing());
  compilation_info_->RetryOptimization(reason);
  return UpdateState(FAILED, State::kFailed);
}

CompilationJob::Status TurbofanCompilationJob::AbortOptimization(
    BailoutReason reason) {
  DCHECK(compilation_info_->IsOptimizing());
  compilation_info_->AbortOptimization(reason);
  return UpdateState(FAILED, State::kFailed);
}

void TurbofanCompilationJob::RecordCompilationStats(ConcurrencyMode mode,
                                                    Isolate* isolate) const {
  DCHECK(compilation_info()->IsOptimizing());
  DirectHandle<SharedFunctionInfo> shared = compilation_info()->shared_info();
  if (v8_flags.trace_opt || v8_flags.trace_opt_stats) {
    double ms_creategraph = time_taken_to_prepare_.InMillisecondsF();
    double ms_optimize = time_taken_to_execute_.InMillisecondsF();
    double ms_codegen = time_taken_to_finalize_.InMillisecondsF();
    if (v8_flags.trace_opt) {
      CompilerTracer::TraceFinishTurbofanCompile(
          isolate, compilation_info(), ms_creategraph, ms_optimize, ms_codegen);
    }
    if (v8_flags.trace_opt_stats) {
      static double compilation_time = 0.0;
      static int compiled_functions = 0;
      static int code_size = 0;

      compilation_time += (ms_creategraph + ms_optimize + ms_codegen);
      compiled_functions++;
      code_size += shared->SourceSize();
      PrintF(
          "[turbofan] Compiled: %d functions with %d byte source size in "
          "%fms.\n",
          compiled_functions, code_size, compilation_time);
    }
  }
  // Don't record samples from machines without high-resolution timers,
  // as that can cause serious reporting issues. See the thread at
  // http://g/chrome-metrics-team/NwwJEyL8odU/discussion for more details.
  if (!base::TimeTicks::IsHighResolution()) return;

  int elapsed_microseconds = static_cast<int>(ElapsedTime().InMicroseconds());
  Counters* const counters = isolate->counters();
  counters->turbofan_ticks()->AddSample(static_cast<int>(
      compilation_info()->tick_counter().CurrentTicks() / 1000));

  if (compilation_info()->is_osr()) {
    counters->turbofan_osr_prepare()->AddSample(
        static_cast<int>(time_taken_to_prepare_.InMicroseconds()));
    counters->turbofan_osr_execute()->AddSample(
        static_cast<int>(time_taken_to_execute_.InMicroseconds()));
    counters->turbofan_osr_finalize()->AddSample(
        static_cast<int>(time_taken_to_finalize_.InMicroseconds()));
    counters->turbofan_osr_total_time()->AddSample(elapsed_microseconds);
    return;
  }

  DCHECK(!compilation_info()->is_osr());
  counters->turbofan_optimize_prepare()->AddSample(
      static_cast<int>(time_taken_to_prepare_.InMicroseconds()));
  counters->turbofan_optimize_execute()->AddSample(
      static_cast<int>(time_taken_to_execute_.InMicroseconds()));
  counters->turbofan_optimize_finalize()->AddSample(
      static_cast<int>(time_taken_to_finalize_.InMicroseconds()));
  counters->turbofan_optimize_total_time()->AddSample(elapsed_microseconds);

  // Compute foreground / background time.
  base::TimeDelta time_background;
  base::TimeDelta time_foreground =
      time_taken_to_prepare_ + time_taken_to_finalize_;
  switch (mode) {
    case ConcurrencyMode::kConcurrent:
      time_background += time_taken_to_execute_;
      counters->turbofan_optimize_concurrent_total_time()->AddSample(
          elapsed_microseconds);
      break;
    case ConcurrencyMode::kSynchronous:
      counters->turbofan_optimize_non_concurrent_total_time()->AddSample(
          elapsed_microseconds);
      time_foreground += time_taken_to_execute_;
      break;
  }
  counters->turbofan_optimize_total_background()->AddSample(
      static_cast<int>(time_background.InMicroseconds()));
  counters->turbofan_optimize_total_foreground()->AddSample(
      static_cast<int>(time_foreground.InMicroseconds()));

  if (v8_flags.profile_guided_optimization &&
      shared->cached_tiering_decision() ==
          CachedTieringDecision::kEarlyMaglev) {
    shared->set_cached_tiering_decision(CachedTieringDecision::kEarlyTurbofan);
  }
}

void TurbofanCompilationJob::RecordFunctionCompilation(
    LogEventListener::CodeTag code_type, Isolate* isolate) const {
  Handle<AbstractCode> abstract_code =
      Cast<AbstractCode>(compilation_info()->code());

  double time_taken_ms = time_taken_to_prepare_.InMillisecondsF() +
                         time_taken_to_execute_.InMillisecondsF() +
                         time_taken_to_finalize_.InMillisecondsF();

  DirectHandle<Script> script(
      Cast<Script>(compilation_info()->shared_info()->script()), isolate);
  Handle<FeedbackVector> feedback_vector(
      compilation_info()->closure()->feedback_vector(), isolate);
  Compiler::LogFunctionCompilation(
      isolate, code_type, script, compilation_info()->shared_info(),
      feedback_vector, abstract_code, compilation_info()->code_kind(),
      time_taken_ms);
}

uint64_t TurbofanCompilationJob::trace_id() const {
  // Xor together the this pointer and the optimization id, to try to make the
  // id more unique on platforms where just the `this` pointer is likely to be
  // reused.
  return reinterpret_cast<uint64_t>(this) ^
         compilation_info_->optimization_id();
}

// ----------------------------------------------------------------------------
// Local helper methods that make up the compilation pipeline.

namespace {

#if V8_ENABLE_WEBASSEMBLY
bool UseAsmWasm(FunctionLiteral* literal, bool asm_wasm_broken) {
  // Check whether asm.js validation is enabled.
  if (!v8_flags.validate_asm) return false;

  // Modules that have validated successfully, but were subsequently broken by
  // invalid module instantiation attempts are off limit forever.
  if (asm_wasm_broken) return false;

  // In stress mode we want to run the validator on everything.
  if (v8_flags.stress_validate_asm) return true;

  // In general, we respect the "use asm" directive.
  return literal->scope()->IsAsmModule();
}
#endif

}  // namespace

void Compiler::InstallInterpreterTrampolineCopy(
    Isolate* isolate, Handle<SharedFunctionInfo> shared_info,
    LogEventListener::CodeTag log_tag) {
  DCHECK(v8_flags.interpreted_frames_native_stack);
  if (!IsBytecodeArray(shared_info->GetTrustedData(isolate))) {
    DCHECK(!shared_info->HasInterpreterData(isolate));
    return;
  }
  DirectHandle<BytecodeArray> bytecode_array(
      shared_info->GetBytecodeArray(isolate), isolate);

  Handle<Code> code =
      Builtins::CreateInterpreterEntryTrampolineForProfiling(isolate);

  DirectHandle<InterpreterData> interpreter_data =
      isolate->factory()->NewInterpreterData(bytecode_array, code);

  if (shared_info->HasBaselineCode()) {
    shared_info->baseline_code(kAcquireLoad)
        ->set_bytecode_or_interpreter_data(*interpreter_data);
  } else {
    // IsBytecodeArray
    shared_info->set_interpreter_data(*interpreter_data);
  }

  DirectHandle<Script> script(Cast<Script>(shared_info->script()), isolate);
  Handle<AbstractCode> abstract_code = Cast<AbstractCode>(code);
  Script::PositionInfo info;
  Script::GetPositionInfo(script, shared_info->StartPosition(), &info);
  int line_num = info.line + 1;
  int column_num = info.column + 1;
  Handle<String> script_name =
      handle(IsString(script->name()) ? Cast<String>(script->name())
                                      : ReadOnlyRoots(isolate).empty_string(),
             isolate);
  PROFILE(isolate, CodeCreateEvent(log_tag, abstract_code, shared_info,
                                   script_name, line_num, column_num));
}

namespace {

template <typename IsolateT>
void InstallUnoptimizedCode(UnoptimizedCompilationInfo* compilation_info,
                            DirectHandle<SharedFunctionInfo> shared_info,
                            IsolateT* isolate) {
  if (compilation_info->has_bytecode_array()) {
    DCHECK(!shared_info->HasBytecodeArray());  // Only compiled once.
    DCHECK(!compilation_info->has_asm_wasm_data());
    DCHECK(!shared_info->HasFeedbackMetadata());

#if V8_ENABLE_WEBASSEMBLY
    // If the function failed asm-wasm compilation, mark asm_wasm as broken
    // to ensure we don't try to compile as asm-wasm.
    if (compilation_info->literal()->scope()->IsAsmModule()) {
      shared_info->set_is_asm_wasm_broken(true);
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    DirectHandle<FeedbackMetadata> feedback_metadata = FeedbackMetadata::New(
        isolate, compilation_info->feedback_vector_spec());
    shared_info->set_feedback_metadata(*feedback_metadata, kReleaseStore);

    shared_info->set_age(0);
    shared_info->set_bytecode_array(*compilation_info->bytecode_array());
  } else {
#if V8_ENABLE_WEBASSEMBLY
    DCHECK(compilation_info->has_asm_wasm_data());
    // We should only have asm/wasm data when finalizing on the main thread.
    DCHECK((std::is_same<IsolateT, Isolate>::value));
    shared_info->set_asm_wasm_data(*compilation_info->asm_wasm_data());
    shared_info->set_feedback_metadata(
        ReadOnlyRoots(isolate).empty_feedback_metadata(), kReleaseStore);
#else
    UNREACHABLE();
#endif  // V8_ENABLE_WEBASSEMBLY
  }
}

template <typename IsolateT>
void EnsureInfosArrayOnScript(DirectHandle<Script> script,
                              ParseInfo* parse_info, IsolateT* isolate) {
  DCHECK(parse_info->flags().is_toplevel());
  if (script->infos()->length() > 0) {
    DCHECK_EQ(script->infos()->length(), parse_info->max_info_id() + 1);
    return;
  }
  DirectHandle<WeakFixedArray> infos(isolate->factory()->NewWeakFixedArray(
      parse_info->max_info_id() + 1, AllocationType::kOld));
  script->set_infos(*infos);
}

void UpdateSharedFunctionFlagsAfterCompilation(FunctionLiteral* literal) {
  Tagged<SharedFunctionInfo> shared_info = *literal->shared_function_info();
  DCHECK_EQ(shared_info->language_mode(), literal->language_mode());

  // These fields are all initialised in ParseInfo from the SharedFunctionInfo,
  // and then set back on the literal after parse. Hence, they should already
  // match.
  DCHECK_EQ(shared_info->requires_instance_members_initializer(),
            literal->requires_instance_members_initializer());
  DCHECK_EQ(shared_info->class_scope_has_private_brand(),
            literal->class_scope_has_private_brand());
  DCHECK_EQ(shared_info->has_static_private_methods_or_accessors(),
            literal->has_static_private_methods_or_accessors());

  shared_info->set_has_duplicate_parameters(
      literal->has_duplicate_parameters());
  shared_info->UpdateAndFinalizeExpectedNofPropertiesFromEstimate(literal);

  shared_info->SetScopeInfo(*literal->scope()->scope_info());
}

// Finalize a single compilation job. This function can return
// RETRY_ON_MAIN_THREAD if the job cannot be finalized off-thread, in which case
// it should be safe to call it again on the main thread with the same job.
template <typename IsolateT>
CompilationJob::Status FinalizeSingleUnoptimizedCompilationJob(
    UnoptimizedCompilationJob* job, Handle<SharedFunctionInfo> shared_info,
    IsolateT* isolate,
    FinalizeUnoptimizedCompilationDataList*
        finalize_unoptimized_compilation_data_list) {
  UnoptimizedCompilationInfo* compilation_info = job->compilation_info();

  CompilationJob::Status status = job->FinalizeJob(shared_info, isolate);
  if (status == CompilationJob::SUCCEEDED) {
    InstallUnoptimizedCode(compilation_info, shared_info, isolate);

    MaybeHandle<CoverageInfo> coverage_info;
    if (compilation_info->has_coverage_info()) {
      SharedMutexGuardIfOffThread<IsolateT, base::kShared> mutex_guard(
          isolate->shared_function_info_access(), isolate);
      if (!shared_info->HasCoverageInfo(
              isolate->GetMainThreadIsolateUnsafe())) {
        coverage_info = compilation_info->coverage_info();
      }
    }

    finalize_unoptimized_compilation_data_list->emplace_back(
        isolate, shared_info, coverage_info, job->time_taken_to_execute(),
        job->time_taken_to_finalize());
  }
  DCHECK_IMPLIES(status == CompilationJob::RETRY_ON_MAIN_THREAD,
                 (std::is_same<IsolateT, LocalIsolate>::value));
  return status;
}

std::unique_ptr<UnoptimizedCompilationJob>
ExecuteSingleUnoptimizedCompilationJob(
    ParseInfo* parse_info, FunctionLiteral* literal, Handle<Script> script,
    AccountingAllocator* allocator,
    std::vector<FunctionLiteral*>* eager_inner_literals,
    LocalIsolate* local_isolate) {
#if V8_ENABLE_WEBASSEMBLY
  if (UseAsmWasm(literal, parse_info->flags().is_asm_wasm_broken())) {
    std::unique_ptr<UnoptimizedCompilationJob> asm_job(
        AsmJs::NewCompilationJob(parse_info, literal, allocator));
    if (asm_job->ExecuteJob() == CompilationJob::SUCCEEDED) {
      return asm_job;
    }
    // asm.js validation failed, fall through to standard unoptimized compile.
    // Note: we rely on the fact that AsmJs jobs have done all validation in the
    // PrepareJob and ExecuteJob phases and can't fail in FinalizeJob with
    // with a validation error or another error that could be solve by falling
    // through to standard unoptimized compile.
  }
#endif
  std::unique_ptr<UnoptimizedCompilationJob> job(
      interpreter::Interpreter::NewCompilationJob(
          parse_info, literal, script, allocator, eager_inner_literals,
          local_isolate));

  if (job->ExecuteJob() != CompilationJob::SUCCEEDED) {
    // Compilation failed, return null.
    return std::unique_ptr<UnoptimizedCompilationJob>();
  }

  return job;
}

template <typename IsolateT>
bool IterativelyExecuteAndFinalizeUnoptimizedCompilationJobs(
    IsolateT* isolate, Handle<Script> script, ParseInfo* parse_info,
    AccountingAllocator* allocator, IsCompiledScope* is_compiled_scope,
    FinalizeUnoptimizedCompilationDataList*
        finalize_unoptimized_compilation_data_list,
    DeferredFinalizationJobDataList*
        jobs_to_retry_finalization_on_main_thread) {
  DeclarationScope::AllocateScopeInfos(parse_info, script, isolate);

  std::vector<FunctionLiteral*> functions_to_compile;
  functions_to_compile.push_back(parse_info->literal());

  bool compilation_succeeded = true;
  while (!functions_to_compile.empty()) {
    FunctionLiteral* literal = functions_to_compile.back();
    functions_to_compile.pop_back();
    Handle<SharedFunctionInfo> shared_info = literal->shared_function_info();
    // It's possible that compilation of an outer function overflowed the stack,
    // so a literal we'd like to compile won't have its SFI yet. Skip compiling
    // the inner function in that case.
    if (shared_info.is_null()) continue;
    if (shared_info->is_compiled()) continue;

    std::unique_ptr<UnoptimizedCompilationJob> job =
        ExecuteSingleUnoptimizedCompilationJob(parse_info, literal, script,
                                               allocator, &functions_to_compile,
                                               isolate->AsLocalIsolate());

    if (!job) {
      // Compilation failed presumably because of stack overflow, make sure
      // the shared function info contains uncompiled data for the next
      // compilation attempts.
      if (!shared_info->HasUncompiledData()) {
        SharedFunctionInfo::CreateAndSetUncompiledData(isolate, literal);
      }
      compilation_succeeded = false;
      // Proceed finalizing other functions in case they don't have uncompiled
      // data.
      continue;
    }

    UpdateSharedFunctionFlagsAfterCompilation(literal);

    auto finalization_status = FinalizeSingleUnoptimizedCompilationJob(
        job.get(), shared_info, isolate,
        finalize_unoptimized_compilation_data_list);

    switch (finalization_status) {
      case CompilationJob::SUCCEEDED:
        if (literal == parse_info->literal()) {
          // Ensure that the top level function is retained.
          *is_compiled_scope = shared_info->is_compiled_scope(isolate);
          DCHECK(is_compiled_scope->is_compiled());
        }
        break;

      case CompilationJob::FAILED:
        compilation_succeeded = false;
        // Proceed finalizing other functions in case they don't have uncompiled
        // data.
        continue;

      case CompilationJob::RETRY_ON_MAIN_THREAD:
        // This should not happen on the main thread.
        DCHECK((!std::is_same<IsolateT, Isolate>::value));
        DCHECK_NOT_NULL(jobs_to_retry_finalization_on_main_thread);

        // Clear the literal and ParseInfo to prevent further attempts to
        // access them.
        job->compilation_info()->ClearLiteral();
        job->ClearParseInfo();
        jobs_to_retry_finalization_on_main_thread->emplace_back(
            isolate, shared_info, std::move(job));
        break;
    }
  }

  // Report any warnings generated during compilation.
  if (parse_info->pending_error_handler()->has_pending_warnings()) {
    parse_info->pending_error_handler()->PrepareWarnings(isolate);
  }

  return compilation_succeeded;
}

bool FinalizeDeferredUnoptimizedCompilationJobs(
    Isolate* isolate, DirectHandle<Script> script,
    DeferredFinalizationJobDataList* deferred_jobs,
    PendingCompilationErrorHandler* pending_error_handler,
    FinalizeUnoptimizedCompilationDataList*
        finalize_unoptimized_compilation_data_list) {
  DCHECK(AllowCompilation::IsAllowed(isolate));

  if (deferred_jobs->empty()) return true;

  // TODO(rmcilroy): Clear native context in debug once AsmJS generates doesn't
  // rely on accessing native context during finalization.

  // Finalize the deferred compilation jobs.
  for (auto&& job : *deferred_jobs) {
    Handle<SharedFunctionInfo> shared_info = job.function_handle();
    if (FinalizeSingleUnoptimizedCompilationJob(
            job.job(), shared_info, isolate,
            finalize_unoptimized_compilation_data_list) !=
        CompilationJob::SUCCEEDED) {
      return false;
    }
  }

  // Report any warnings generated during deferred finalization.
  if (pending_error_handler->has_pending_warnings()) {
    pending_error_handler->PrepareWarnings(isolate);
  }

  return true;
}

// A wrapper to access the optimized code cache slots on the feedback vector.
class OptimizedCodeCache : public AllStatic {
 public:
  static V8_WARN_UNUSED_RESULT MaybeHandle<Code> Get(
      Isolate* isolate, DirectHandle<JSFunction> function,
      BytecodeOffset osr_offset, CodeKind code_kind) {
    DCHECK_IMPLIES(V8_ENABLE_LEAPTIERING_BOOL, IsOSR(osr_offset));
    if (!CodeKindIsStoredInOptimizedCodeCache(code_kind)) return {};
    if (!function->has_feedback_vector()) return {};

    DisallowGarbageCollection no_gc;
    Tagged<SharedFunctionInfo> shared = function->shared();
    RCS_SCOPE(isolate, RuntimeCallCounterId::kCompileGetFromOptimizedCodeMap);

    Tagged<Code> code;
    Tagged<FeedbackVector> feedback_vector = function->feedback_vector();
    if (IsOSR(osr_offset)) {
      Handle<BytecodeArray> bytecode(shared->GetBytecodeArray(isolate),
                                     isolate);
      interpreter::BytecodeArrayIterator it(bytecode, osr_offset.ToInt());
      DCHECK_EQ(it.current_bytecode(), interpreter::Bytecode::kJumpLoop);
      std::optional<Tagged<Code>> maybe_code =
          feedback_vector->GetOptimizedOsrCode(isolate, it.GetSlotOperand(2));
      if (maybe_code.has_value()) code = maybe_code.value();
    } else {
#ifdef V8_ENABLE_LEAPTIERING
      UNREACHABLE();
#else
      feedback_vector->EvictOptimizedCodeMarkedForDeoptimization(
          isolate, shared, "OptimizedCodeCache::Get");
      code = feedback_vector->optimized_code(isolate);
#endif  // V8_ENABLE_LEAPTIERING
    }

    // Normal tierup should never request a code-kind we already have. In case
    // of OSR it can happen that we OSR from ignition to turbofan. This is
    // explicitly allowed here by re-using any larger-kinded than requested
    // code.
    DCHECK_IMPLIES(!code.is_null() && code->kind() > code_kind,
                   IsOSR(osr_offset));
    if (code.is_null() || code->kind() < code_kind) return {};

    DCHECK(!code->marked_for_deoptimization());
    DCHECK(shared->is_compiled());
    DCHECK(CodeKindIsStoredInOptimizedCodeCache(code->kind()));
    DCHECK_IMPLIES(IsOSR(osr_offset), CodeKindCanOSR(code->kind()));

    CompilerTracer::TraceOptimizedCodeCacheHit(isolate, function, osr_offset,
                                               code_kind);
    return handle(code, isolate);
  }

  static void Insert(Isolate* isolate, Tagged<JSFunction> function,
                     BytecodeOffset osr_offset, Tagged<Code> code,
                     bool is_function_context_specializing) {
    DCHECK_IMPLIES(V8_ENABLE_LEAPTIERING_BOOL, IsOSR(osr_offset));
    const CodeKind kind = code->kind();
    if (!CodeKindIsStoredInOptimizedCodeCache(kind)) return;

    Tagged<FeedbackVector> feedback_vector = function->feedback_vector();

    if (IsOSR(osr_offset)) {
      DCHECK(CodeKindCanOSR(kind));
      DCHECK(!is_function_context_specializing);
      Tagged<SharedFunctionInfo> shared = function->shared();
      Handle<BytecodeArray> bytecode(shared->GetBytecodeArray(isolate),
                                     isolate);
      // Bytecode may be different, so just make sure we see the expected
      // opcode. Otherwise fuzzers will complain.
      SBXCHECK_LT(osr_offset.ToInt(), bytecode->length());
      interpreter::BytecodeArrayIterator it(bytecode, osr_offset.ToInt());
      SBXCHECK_EQ(it.current_bytecode(), interpreter::Bytecode::kJumpLoop);
      feedback_vector->SetOptimizedOsrCode(isolate, it.GetSlotOperand(2), code);
      return;
    }

#ifdef V8_ENABLE_LEAPTIERING
    UNREACHABLE();
#else
    DCHECK(!IsOSR(osr_offset));

    if (is_function_context_specializing) {
      // Function context specialization folds-in the function context, so no
      // sharing can occur. Make sure the optimized code cache is cleared.
      // Only do so if the specialized code's kind matches the cached code kind.
      if (feedback_vector->has_optimized_code() &&
          feedback_vector->optimized_code(isolate)->kind() == code->kind()) {
        feedback_vector->ClearOptimizedCode();
      }
      return;
    }

    function->shared()->set_function_context_independent_compiled(true);
    feedback_vector->SetOptimizedCode(isolate, code);
#endif  // V8_ENABLE_LEAPTIERING
  }
};

// Runs PrepareJob in the proper compilation scopes. Handles will be allocated
// in a persistent handle scope that is detached and handed off to the
// {compilation_info} after PrepareJob.
bool PrepareJobWithHandleScope(OptimizedCompilationJob* job, Isolate* isolate,
                               OptimizedCompilationInfo* compilation_info,
                               ConcurrencyMode mode) {
  CompilationHandleScope compilation(isolate, compilation_info);
  CompilerTracer::TracePrepareJob(isolate, compilation_info, mode);
  compilation_info->ReopenAndCanonicalizeHandlesInNewScope(isolate);
  return job->PrepareJob(isolate) == CompilationJob::SUCCEEDED;
}

bool CompileTurbofan_NotConcurrent(Isolate* isolate,
                                   TurbofanCompilationJob* job) {
  OptimizedCompilationInfo* const compilation_info = job->compilation_info();
  DCHECK_EQ(compilation_info->code_kind(), CodeKind::TURBOFAN_JS);

  TimerEventScope<TimerEventRecompileSynchronous> timer(isolate);
  RCS_SCOPE(isolate, RuntimeCallCounterId::kOptimizeNonConcurrent);
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "V8.OptimizeNonConcurrent");

  if (!PrepareJobWithHandleScope(job, isolate, compilation_info,
                                 ConcurrencyMode::kSynchronous)) {
    CompilerTracer::TraceAbortedJob(isolate, compilation_info,
                                    job->prepare_in_ms(), job->execute_in_ms(),
                                    job->finalize_in_ms());
    return false;
  }

  if (job->ExecuteJob(isolate->counters()->runtime_call_stats(),
                      isolate->main_thread_local_isolate())) {
    CompilerTracer::TraceAbortedJob(isolate, compilation_info,
                                    job->prepare_in_ms(), job->execute_in_ms(),
                                    job->finalize_in_ms());
    return false;
  }

  if (job->FinalizeJob(isolate) != CompilationJob::SUCCEEDED) {
    CompilerTracer::TraceAbortedJob(isolate, compilation_info,
                                    job->prepare_in_ms(), job->execute_in_ms(),
                                    job->finalize_in_ms());
    return false;
  }

  // Success!
  job->RecordCompilationStats(ConcurrencyMode::kSynchronous, isolate);
  DCHECK(!isolate->has_exception());
  if (!V8_ENABLE_LEAPTIERING_BOOL || job->compilation_info()->is_osr()) {
    OptimizedCodeCache::Insert(
        isolate, *compilation_info->closure(), compilation_info->osr_offset(),
        *compilation_info->code(),
        compilation_info->function_context_specializing());
  }
  job->RecordFunctionCompilation(LogEventListener::CodeTag::kFunction, isolate);
  return true;
}

bool CompileTurbofan_Concurrent(Isolate* isolate,
                                std::unique_ptr<TurbofanCompilationJob> job) {
  OptimizedCompilationInfo* const compilation_info = job->compilation_info();
  DCHECK_EQ(compilation_info->code_kind(), CodeKind::TURBOFAN_JS);
  DirectHandle<JSFunction> function = compilation_info->closure();

  if (!isolate->optimizing_compile_dispatcher()->IsQueueAvailable()) {
    if (v8_flags.trace_concurrent_recompilation) {
      PrintF("  ** Compilation queue full, will retry optimizing ");
      ShortPrint(*function);
      PrintF(" later.\n");
    }
    return false;
  }

  if (isolate->heap()->HighMemoryPressure()) {
    if (v8_flags.trace_concurrent_recompilation) {
      PrintF("  ** High memory pressure, will retry optimizing ");
      ShortPrint(*function);
      PrintF(" later.\n");
    }
    return false;
  }

  TimerEventScope<TimerEventRecompileSynchronous> timer(isolate);
  RCS_SCOPE(isolate, RuntimeCallCounterId::kOptimizeConcurrentPrepare);
  TRACE_EVENT_WITH_FLOW0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
                         "V8.OptimizeConcurrentPrepare", job->trace_id(),
                         TRACE_EVENT_FLAG_FLOW_OUT);

  if (!PrepareJobWithHandleScope(job.get(), isolate, compilation_info,
                                 ConcurrencyMode::kConcurrent)) {
    return false;
  }

  if (V8_LIKELY(!compilation_info->discard_result_for_testing())) {
    function->SetTieringInProgress(true, compilation_info->osr_offset());
  }

  // The background recompile will own this job.
  isolate->optimizing_compile_dispatcher()->QueueForOptimization(job.release());

  if (v8_flags.trace_concurrent_recompilation) {
    PrintF("  ** Queued ");
    ShortPrint(*function);
    PrintF(" for concurrent optimization.\n");
  }

  DCHECK(compilation_info->shared_info()->HasBytecodeArray());
  return true;
}

enum class CompileResultBehavior {
  // Default behavior, i.e. install the result, insert into caches, etc.
  kDefault,
  // Used only for stress testing. The compilation result should be discarded.
  kDiscardForTesting,
};

bool ShouldOptimize(CodeKind code_kind,
                    DirectHandle<SharedFunctionInfo> shared) {
  DCHECK(CodeKindIsOptimizedJSFunction(code_kind));
  switch (code_kind) {
    case CodeKind::TURBOFAN_JS:
      return v8_flags.turbofan && shared->PassesFilter(v8_flags.turbo_filter);
    case CodeKind::MAGLEV:
      return maglev::IsMaglevEnabled() &&
             shared->PassesFilter(v8_flags.maglev_filter);
    default:
      UNREACHABLE();
  }
}

MaybeHandle<Code> CompileTurbofan(Isolate* isolate, Handle<JSFunction> function,
                                  DirectHandle<SharedFunctionInfo> shared,
                                  ConcurrencyMode mode,
                                  BytecodeOffset osr_offset,
                                  CompileResultBehavior result_behavior) {
  VMState<COMPILER> state(isolate);
  TimerEventScope<TimerEventOptimizeCode> optimize_code_timer(isolate);
  RCS_SCOPE(isolate, RuntimeCallCounterId::kOptimizeCode);
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"), "V8.OptimizeCode");

  DCHECK(!isolate->has_exception());
  PostponeInterruptsScope postpone(isolate);
  const compiler::IsScriptAvailable has_script =
      IsScript(shared->script()) ? compiler::IsScriptAvailable::kYes
                                 : compiler::IsScriptAvailable::kNo;
  // BUG(5946): This DCHECK is necessary to make certain that we won't
  // tolerate the lack of a script without bytecode.
  DCHECK_IMPLIES(has_script == compiler::IsScriptAvailable::kNo,
                 shared->HasBytecodeArray());
  std::unique_ptr<TurbofanCompilationJob> job(
      compiler::NewCompilationJob(isolate, function, has_script, osr_offset));

  if (result_behavior == CompileResultBehavior::kDiscardForTesting) {
    job->compilation_info()->set_discard_result_for_testing();
  }

  if (IsOSR(osr_offset)) {
    isolate->CountUsage(v8::Isolate::kTurboFanOsrCompileStarted);
  }

  // Prepare the job and launch concurrent compilation, or compile now.
  if (IsConcurrent(mode)) {
    if (CompileTurbofan_Concurrent(isolate, std::move(job))) return {};
  } else {
    DCHECK(IsSynchronous(mode));
    if (CompileTurbofan_NotConcurrent(isolate, job.get())) {
      return job->compilation_info()->code();
    }
  }

  if (isolate->has_exception()) isolate->clear_exception();
  return {};
}

#ifdef V8_ENABLE_MAGLEV
// TODO(v8:7700): Record maglev compilations better.
void RecordMaglevFunctionCompilation(Isolate* isolate,
                                     DirectHandle<JSFunction> function,
                                     Handle<AbstractCode> code) {
  PtrComprCageBase cage_base(isolate);
  Handle<SharedFunctionInfo> shared(function->shared(cage_base), isolate);
  DirectHandle<Script> script(Cast<Script>(shared->script(cage_base)), isolate);
  Handle<FeedbackVector> feedback_vector(function->feedback_vector(cage_base),
                                         isolate);

  // Optimistic estimate.
  double time_taken_ms = 0;

  Compiler::LogFunctionCompilation(
      isolate, LogEventListener::CodeTag::kFunction, script, shared,
      feedback_vector, code, code->kind(cage_base), time_taken_ms);
}
#endif  // V8_ENABLE_MAGLEV

MaybeHandle<Code> CompileMaglev(Isolate* isolate, Handle<JSFunction> function,
                                ConcurrencyMode mode, BytecodeOffset osr_offset,
                                CompileResultBehavior result_behavior) {
#ifdef V8_ENABLE_MAGLEV
  DCHECK(maglev::IsMaglevEnabled());
  CHECK(result_behavior == CompileResultBehavior::kDefault);

  // TODO(v8:7700): Tracing, see CompileTurbofan.

  DCHECK(!isolate->has_exception());
  PostponeInterruptsScope postpone(isolate);

  // TODO(v8:7700): See everything in CompileTurbofan_Concurrent.
  // - Tracing,
  // - timers,
  // - aborts on memory pressure,
  // ...

  // Prepare the job.
  auto job = maglev::MaglevCompilationJob::New(isolate, function, osr_offset);

  if (IsConcurrent(mode) &&
      !isolate->maglev_concurrent_dispatcher()->is_enabled()) {
    mode = ConcurrencyMode::kSynchronous;
  }

  {
    TRACE_EVENT_WITH_FLOW0(
        TRACE_DISABLED_BY_DEFAULT("v8.compile"),
        IsSynchronous(mode) ? "V8.MaglevPrepare" : "V8.MaglevConcurrentPrepare",
        job->trace_id(), TRACE_EVENT_FLAG_FLOW_OUT);
    CompilerTracer::TraceStartMaglevCompile(isolate, function, job->is_osr(),
                                            mode);
    CompilationJob::Status status = job->PrepareJob(isolate);
    CHECK_EQ(status, CompilationJob::SUCCEEDED);  // TODO(v8:7700): Use status.
  }

  if (IsSynchronous(mode)) {
    CompilationJob::Status status =
        job->ExecuteJob(isolate->counters()->runtime_call_stats(),
                        isolate->main_thread_local_isolate());
    if (status == CompilationJob::FAILED) {
      return {};
    }
    CHECK_EQ(status, CompilationJob::SUCCEEDED);

    Compiler::FinalizeMaglevCompilationJob(job.get(), isolate);

    return job->code();
  }

  DCHECK(IsConcurrent(mode));

  // Enqueue it.
  isolate->maglev_concurrent_dispatcher()->EnqueueJob(std::move(job));

  // Remember that the function is currently being processed.
  function->SetTieringInProgress(true, osr_offset);
  function->SetInterruptBudget(isolate, CodeKind::MAGLEV);

  return {};
#else   // V8_ENABLE_MAGLEV
  UNREACHABLE();
#endif  // V8_ENABLE_MAGLEV
}

MaybeHandle<Code> GetOrCompileOptimized(
    Isolate* isolate, Handle<JSFunction> function, ConcurrencyMode mode,
    CodeKind code_kind, BytecodeOffset osr_offset = BytecodeOffset::None(),
    CompileResultBehavior result_behavior = CompileResultBehavior::kDefault) {
  DCHECK(CodeKindIsOptimizedJSFunction(code_kind));

  DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate);

  // Clear the optimization marker on the function so that we don't try to
  // re-optimize.
  if (!IsOSR(osr_offset)) {
#ifdef V8_ENABLE_LEAPTIERING
    DCHECK_IMPLIES(code_kind == CodeKind::MAGLEV,
                   !function->ActiveTierIsMaglev(isolate));
    DCHECK_IMPLIES(code_kind == CodeKind::TURBOFAN_JS,
                   !function->ActiveTierIsTurbofan(isolate));
#endif  // !V8_ENABLE_LEAPTIERING
    function->ResetTieringRequests(isolate);
    // Always reset the OSR urgency to ensure we reset it on function entry.
    function->feedback_vector()->reset_osr_urgency();
    int invocation_count =
        function->feedback_vector()->invocation_count(kRelaxedLoad);
    if (!(V8_UNLIKELY(v8_flags.testing_d8_test_runner ||
                      v8_flags.allow_natives_syntax) &&
          ManualOptimizationTable::IsMarkedForManualOptimization(isolate,
                                                                 *function)) &&
        invocation_count < v8_flags.minimum_invocations_before_optimization) {
      function->feedback_vector()->set_invocation_count(invocation_count + 1,
                                                        kRelaxedStore);
      return {};
    }
  }

  // TODO(v8:7700): Distinguish between Maglev and Turbofan.
  if (shared->optimization_disabled() &&
      shared->disabled_optimization_reason() == BailoutReason::kNeverOptimize) {
    return {};
  }

  // Do not optimize when debugger needs to hook into every call.
  if (isolate->debug()->needs_check_on_function_call()) {
    // Reset the OSR urgency to avoid triggering this compilation request on
    // every iteration and thereby skipping other interrupts.
    if (IsOSR(osr_offset)) {
      function->feedback_vector()->reset_osr_urgency();
    }
    return {};
  }

  // Do not optimize if we need to be able to set break points.
  if (shared->HasBreakInfo(isolate)) return {};

  // Do not optimize if optimization is disabled or function doesn't pass
  // turbo_filter.
  if (!ShouldOptimize(code_kind, shared)) return {};

  if (!V8_ENABLE_LEAPTIERING_BOOL || IsOSR(osr_offset)) {
    Handle<Code> cached_code;
    if (OptimizedCodeCache::Get(isolate, function, osr_offset, code_kind)
            .ToHandle(&cached_code)) {
      if (IsOSR(osr_offset)) {
        if (!function->osr_tiering_in_progress()) {
          function->feedback_vector()->reset_osr_urgency();
        }
      } else {
        DCHECK_LE(cached_code->kind(), code_kind);
      }
      return cached_code;
    }

    if (IsOSR(osr_offset)) {
      // One OSR job per function at a time.
      if (function->osr_tiering_in_progress()) {
        return {};
      }
      function->feedback_vector()->reset_osr_urgency();
    }
  }

  DCHECK(shared->is_compiled());

  if (code_kind == CodeKind::TURBOFAN_JS) {
    return CompileTurbofan(isolate, function, shared, mode, osr_offset,
                           result_behavior);
  } else {
    DCHECK_EQ(code_kind, CodeKind::MAGLEV);
    return CompileMaglev(isolate, function, mode, osr_offset, result_behavior);
  }
}

// When --stress-concurrent-inlining is enabled, spawn concurrent jobs in
// addition to non-concurrent compiles to increase coverage in mjsunit tests
// (where most interesting compiles are non-concurrent). The result of the
// compilation is thrown out.
void SpawnDuplicateConcurrentJobForStressTesting(Isolate* isolate,
                                                 Handle<JSFunction> function,
                                                 ConcurrencyMode mode,
                                                 CodeKind code_kind) {
  // TODO(v8:7700): Support Maglev.
  if (code_kind == CodeKind::MAGLEV) return;

  if (function->ActiveTierIsTurbofan(isolate)) return;

  DCHECK(v8_flags.stress_concurrent_inlining &&
         isolate->concurrent_recompilation_enabled() && IsSynchronous(mode) &&
         isolate->node_observer() == nullptr);
  CompileResultBehavior result_behavior =
      v8_flags.stress_concurrent_inlining_attach_code
          ? CompileResultBehavior::kDefault
          : CompileResultBehavior::kDiscardForTesting;
  USE(GetOrCompileOptimized(isolate, function, ConcurrencyMode::kConcurrent,
                            code_kind, BytecodeOffset::None(),
                            result_behavior));
}

bool FailAndClearException(Isolate* isolate) {
  isolate->clear_internal_exception();
  return false;
}

template <typename IsolateT>
bool PrepareException(IsolateT* isolate, ParseInfo* parse_info) {
  if (parse_info->pending_error_handler()->has_pending_error()) {
    parse_info->pending_error_handler()->PrepareErrors(
        isolate, parse_info->ast_value_factory());
  }
  return false;
}

bool FailWithPreparedException(
    Isolate* isolate, Handle<Script> script,
    const PendingCompilationErrorHandler* pending_error_handler,
    Compiler::ClearExceptionFlag flag = Compiler::KEEP_EXCEPTION) {
  if (flag == Compiler::CLEAR_EXCEPTION) {
    return FailAndClearException(isolate);
  }

  if (!isolate->has_exception()) {
    if (pending_error_handler->has_pending_error()) {
      pending_error_handler->ReportErrors(isolate, script);
    } else {
      isolate->StackOverflow();
    }
  }
  return false;
}

bool FailWithException(Isolate* isolate, Handle<Script> script,
                       ParseInfo* parse_info,
                       Compiler::ClearExceptionFlag flag) {
  PrepareException(isolate, parse_info);
  return FailWithPreparedException(isolate, script,
                                   parse_info->pending_error_handler(), flag);
}

void FinalizeUnoptimizedCompilation(
    Isolate* isolate, Handle<Script> script,
    const UnoptimizedCompileFlags& flags,
    const UnoptimizedCompileState* compile_state,
    const FinalizeUnoptimizedCompilationDataList&
        finalize_unoptimized_compilation_data_list) {
  if (compile_state->pending_error_handler()->has_pending_warnings()) {
    compile_state->pending_error_handler()->ReportWarnings(isolate, script);
  }

  bool need_source_positions =
      v8_flags.stress_lazy_source_positions ||
      (!flags.collect_source_positions() && isolate->NeedsSourcePositions());

  for (const auto& finalize_data : finalize_unoptimized_compilation_data_list) {
    Handle<SharedFunctionInfo> shared_info = finalize_data.function_handle();
    // It's unlikely, but possible, that the bytecode was flushed between being
    // allocated and now, so guard against that case, and against it being
    // flushed in the middle of this loop.
    IsCompiledScope is_compiled_scope(*shared_info, isolate);
    if (!is_compiled_scope.is_compiled()) continue;

    if (need_source_positions) {
      SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate, shared_info);
    }
    LogEventListener::CodeTag log_tag;
    if (shared_info->is_toplevel()) {
      log_tag = flags.is_eval() ? LogEventListener::CodeTag::kEval
                                : LogEventListener::CodeTag::kScript;
    } else {
      log_tag = LogEventListener::CodeTag::kFunction;
    }
    log_tag = V8FileLogger::ToNativeByScript(log_tag, *script);
    if (v8_flags.interpreted_frames_native_stack &&
        isolate->logger()->is_listening_to_code_events()) {
      Compiler::InstallInterpreterTrampolineCopy(isolate, shared_info, log_tag);
    }
    Handle<CoverageInfo> coverage_info;
    if (finalize_data.coverage_info().ToHandle(&coverage_info)) {
      isolate->debug()->InstallCoverageInfo(shared_info, coverage_info);
    }

    LogUnoptimizedCompilation(isolate, shared_info, log_tag,
                              finalize_data.time_taken_to_execute(),
                              finalize_data.time_taken_to_finalize());
  }
}

void FinalizeUnoptimizedScriptCompilation(
    Isolate* isolate, Handle<Script> script,
    const UnoptimizedCompileFlags& flags,
    const UnoptimizedCompileState* compile_state,
    const FinalizeUnoptimizedCompilationDataList&
        finalize_unoptimized_compilation_data_list) {
  FinalizeUnoptimizedCompilation(isolate, script, flags, compile_state,
                                 finalize_unoptimized_compilation_data_list);

  script->set_compilation_state(Script::CompilationState::kCompiled);
  DCHECK_IMPLIES(isolate->NeedsSourcePositions(), script->has_line_ends());
}

void CompileAllWithBaseline(Isolate* isolate,
                            const FinalizeUnoptimizedCompilationDataList&
                                finalize_unoptimized_compilation_data_list) {
  for (const auto& finalize_data : finalize_unoptimized_compilation_data_list) {
    Handle<SharedFunctionInfo> shared_info = finalize_data.function_handle();
    IsCompiledScope is_compiled_scope(*shared_info, isolate);
    if (!is_compiled_scope.is_compiled()) continue;
    if (!CanCompileWithBaseline(isolate, *shared_info)) continue;
    Compiler::CompileSharedWithBaseline(
        isolate, shared_info, Compiler::CLEAR_EXCEPTION, &is_compiled_scope);
  }
}

// Create shared function info for top level and shared function infos array for
// inner functions.
template <typename IsolateT>
Handle<SharedFunctionInfo> CreateTopLevelSharedFunctionInfo(
    ParseInfo* parse_info, Handle<Script> script, IsolateT* isolate) {
  EnsureInfosArrayOnScript(script, parse_info, isolate);
  DCHECK_EQ(kNoSourcePosition,
            parse_info->literal()->function_token_position());
  return isolate->factory()->NewSharedFunctionInfoForLiteral(
      parse_info->literal(), script, true);
}

Handle<SharedFunctionInfo> GetOrCreateTopLevelSharedFunctionInfo(
    ParseInfo* parse_info, Handle<Script> script, Isolate* isolate,
    IsCompiledScope* is_compiled_scope) {
  EnsureInfosArrayOnScript(script, parse_info, isolate);
  MaybeHandle<SharedFunctionInfo> maybe_shared =
      Script::FindSharedFunctionInfo(script, isolate, parse_info->literal());
  if (Handle<SharedFunctionInfo> shared; maybe_shared.ToHandle(&shared)) {
    DCHECK_EQ(shared->function_literal_id(),
              parse_info->literal()->function_literal_id());
    *is_compiled_scope = shared->is_compiled_scope(isolate);
    return shared;
  }
  return CreateTopLevelSharedFunctionInfo(parse_info, script, isolate);
}

MaybeHandle<SharedFunctionInfo> CompileToplevel(
    ParseInfo* parse_info, Handle<Script> script,
    MaybeHandle<ScopeInfo> maybe_outer_scope_info, Isolate* isolate,
    IsCompiledScope* is_compiled_scope) {
  TimerEventScope<TimerEventCompileCode> top_level_timer(isolate);
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"), "V8.CompileCode");
  DCHECK_EQ(ThreadId::Current(), isolate->thread_id());

  PostponeInterruptsScope postpone(isolate);
  DCHECK(!isolate->native_context().is_null());
  RCS_SCOPE(isolate, parse_info->flags().is_eval()
                         ? RuntimeCallCounterId::kCompileEval
                         : RuntimeCallCounterId::kCompileScript);
  VMState<BYTECODE_COMPILER> state(isolate);
  if (parse_info->literal() == nullptr &&
      !parsing::ParseProgram(parse_info, script, maybe_outer_scope_info,
                             isolate, parsing::ReportStatisticsMode::kYes)) {
    FailWithException(isolate, script, parse_info,
                      Compiler::ClearExceptionFlag::KEEP_EXCEPTION);
    return MaybeHandle<SharedFunctionInfo>();
  }
  // Measure how long it takes to do the compilation; only take the
  // rest of the function into account to avoid overlap with the
  // parsing statistics.
  NestedTimedHistogram* rate = parse_info->flags().is_eval()
                                   ? isolate->counters()->compile_eval()
                                   : isolate->counters()->compile();
  NestedTimedHistogramScope timer(rate);
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               parse_info->flags().is_eval() ? "V8.CompileEval" : "V8.Compile");

  // Create the SharedFunctionInfo and add it to the script's list.
  Handle<SharedFunctionInfo> shared_info =
      GetOrCreateTopLevelSharedFunctionInfo(parse_info, script, isolate,
                                            is_compiled_scope);

  FinalizeUnoptimizedCompilationDataList
      finalize_unoptimized_compilation_data_list;

  // Prepare and execute compilation of the outer
"""


```