Response:
Let's break down the thought process to analyze the `compiler.h` header file.

**1. Initial Scan and Purpose Identification:**

* The filename `compiler.h` strongly suggests this file defines the core compilation logic within V8.
* The copyright notice and `#ifndef` guards are standard C++ header practices.
* The includes reveal dependencies on various parts of V8, such as AST, base utilities, code generation components, execution, handles, logging, objects, parsing, and snapshotting. This reinforces the idea that this is a central compilation component.

**2. Key Class Identification and Analysis - `Compiler`:**

* The `Compiler` class is the most prominent. The comment "The V8 compiler API" confirms its central role.
* The descriptive text highlights its responsibilities: dispatching to various compilers, choosing the right compiler, and integrating compilation results into the object heap.
* The "General strategy" comment gives a high-level overview of how scripts are handled.
* The public methods are grouped by functionality:
    * **Compilation Methods (`Compile`, `CompileSharedWithBaseline`, `CompileOptimized`, etc.):** These are clearly the core functions for initiating different compilation processes (full, baseline, optimized, OSR). The variations in parameters (e.g., `Isolate*`, `Handle<SharedFunctionInfo>`, `ConcurrencyMode`) suggest different compilation scenarios.
    * **Live Edit (`CompileForLiveEdit`):**  A specific feature related to code modification during debugging.
    * **Source Position Collection (`CollectSourcePositions`):**  A separate step, possibly for debugging or performance analysis.
    * **Background Compilation (`FinalizeBackgroundCompileTask`, `DisposeTurbofanCompilationJob`, etc.):**  Support for asynchronous compilation. The different `Finalize...` methods likely handle different compiler pipelines (Turbofan, Maglev).
    * **Instantiation (`PostInstantiation`):**  A hook during object creation.
    * **Function Creation (`GetFunctionFromEval`, `GetWrappedFunction`, `GetFunctionFromString`, `GetSharedFunctionInfoForScript`, etc.):**  Methods to create `JSFunction` or `SharedFunctionInfo` objects from source code. The variations suggest different input formats (strings, scripts, cached data, streamed data).
    * **Logging (`LogFunctionCompilation`, `InstallInterpreterTrampolineCopy`):**  For tracking and debugging compilation events.
* The private methods hint at internal implementation details, such as tracing.

**3. Key Class Identification and Analysis - Compilation Jobs (`CompilationJob`, `UnoptimizedCompilationJob`, `OptimizedCompilationJob`, `TurbofanCompilationJob`):**

* The comments for `CompilationJob` and its derived classes indicate a design for managing asynchronous compilation tasks.
* The states (`kReadyToPrepare`, `kReadyToExecute`, `kReadyToFinalize`, etc.) and the split into Prepare, Execute, and Finalize phases are characteristic of concurrent task management.
* The different job types (`Unoptimized`, `Optimized`, `Turbofan`) likely correspond to different compilation pipelines or optimization levels.
* The `TurbofanCompilationJob` has specific methods like `RetryOptimization` and `AbortOptimization`, highlighting its role in the advanced optimization pipeline.

**4. Other Important Structures:**

* **`BackgroundCompileTask`:** Manages the details of compiling in a background thread.
* **`ScriptStreamingData`:** Deals with the specifics of compiling scripts from a stream, likely for faster initial loading.
* **`BackgroundDeserializeTask`:** Handles the process of deserializing cached code in the background.
* **`FinalizeUnoptimizedCompilationData` and related structures:** Used for passing data during the finalization of unoptimized compilation.
* **`CompilationHandleScope`:** A RAII wrapper for managing handles during compilation, likely for memory management.

**5. Torque Check:**

* The prompt specifically asks about `.tq` files. Since the filename is `compiler.h`, it's not a Torque file.

**6. Relationship to JavaScript (and Examples):**

* The core purpose of the compiler is to translate JavaScript code into executable code. Many methods directly relate to JavaScript concepts:
    * `Compile`: Compiling JavaScript functions.
    * `GetFunctionFromEval`, `GetFunctionFromString`: Handling `eval()` and dynamic code generation.
    * `GetWrappedFunction`:  Compiling code within a `Function()` constructor.
    * `GetSharedFunctionInfoForScript`: Creating the underlying representation of a JavaScript function from a script.
*  JavaScript Examples:  The examples provided in the initial good answer are spot-on. They illustrate the direct mapping between JavaScript code and the compiler's functions.

**7. Code Logic Inference and Assumptions:**

* The structure with different compilation methods suggests a tiered compilation approach (e.g., baseline -> optimized).
* The separation of Prepare, Execute, and Finalize phases in the compilation jobs points towards concurrency and avoiding long-blocking operations on the main thread.
* The "ClearExceptionFlag" suggests that compilation might sometimes occur in contexts where exceptions need to be handled carefully.

**8. Common Programming Errors:**

*  The potential errors are related to asynchronous operations and incorrect usage of the compilation API. The examples given in the good answer (not waiting for compilation, incorrect context) are relevant.

**Self-Correction/Refinement during the process:**

* Initially, I might just see a bunch of functions. However, by grouping them by their prefixes (`Compile`, `GetFunction`, `Finalize`), the overall structure becomes clearer.
*  Recognizing the "Job" classes and their states is crucial for understanding the asynchronous nature of compilation.
*  Connecting the `SharedFunctionInfo` and `JSFunction` handles to their JavaScript counterparts is key to understanding the high-level purpose.

This iterative process of scanning, identifying key components, analyzing their purpose, and connecting them to JavaScript concepts leads to a comprehensive understanding of the `compiler.h` file.
这个文件是V8 JavaScript引擎中编译器组件的头文件 (`compiler.h`)。它定义了用于将JavaScript源代码编译成可执行机器码的接口和类。

**主要功能概览:**

* **作为 V8 编译器的中心入口点:**  它提供了访问 V8 中各种编译器的统一接口，并负责决定使用哪个编译器以及如何将编译结果整合到 V8 的堆中。
* **管理不同编译阶段:** 它定义了用于同步和异步编译的不同方法，包括：
    * **完整编译:** 将函数或脚本编译成完整的机器码。
    * **基线编译:**  生成更快但可能未完全优化的代码，用于快速启动。
    * **优化编译:** 生成高度优化的代码，用于提高性能。
    * **On-Stack Replacement (OSR):** 在函数执行过程中进行优化编译。
* **处理不同类型的源代码:** 支持编译完整的脚本、`eval()` 调用的代码、`Function()` 构造函数创建的代码等。
* **管理后台编译任务:** 定义了用于在后台线程执行编译任务的类 (`BackgroundCompileTask`)，以避免阻塞主线程。
* **处理代码缓存:** 提供了使用和管理编译代码缓存的机制，以加速后续执行。
* **与解析器和代码生成器交互:** 虽然这个头文件本身不包含解析或代码生成的具体实现，但它定义了与这些组件交互的接口。
* **处理编译错误和异常:**  提供了清除编译过程中产生的异常的机制。
* **支持代码热更新 (LiveEdit):** 允许在运行时修改代码并重新编译。
* **记录编译事件:**  包含用于记录编译过程信息的函数，用于性能分析和调试。

**关于文件名和 Torque:**

该文件的名称是 `compiler.h`，以 `.h` 结尾，这表明它是一个 C++ 头文件。如果文件名以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。Torque 是一种 V8 使用的领域特定语言，用于定义运行时内置函数和一些底层的代码生成逻辑。

**与 JavaScript 功能的关系及示例:**

`compiler.h` 中定义的功能直接关系到 JavaScript 代码的执行。每当 V8 需要执行 JavaScript 代码时，都需要通过编译器将其转换为机器码。

以下是一些与 `compiler.h` 中功能相关的 JavaScript 例子：

1. **普通函数编译:**

   ```javascript
   function add(a, b) {
     return a + b;
   }

   add(1, 2); // 当首次调用 add 时，V8 会编译这个函数。
   ```

   当首次调用 `add` 函数时，V8 的编译器 (通过 `compiler.h` 中定义的接口) 会被触发，将 `add` 函数的 JavaScript 代码转换成机器码。

2. **`eval()` 函数:**

   ```javascript
   let code = 'console.log("Hello from eval!");';
   eval(code); // V8 会在运行时编译 eval 中的字符串。
   ```

   `eval()` 函数允许在运行时执行字符串形式的 JavaScript 代码。V8 的编译器需要能够动态地编译这些字符串，相关的逻辑会在 `compiler.h` 中有所涉及，例如 `GetFunctionFromEval` 方法。

3. **`Function()` 构造函数:**

   ```javascript
   let multiply = new Function('a', 'b', 'return a * b;');
   console.log(multiply(3, 4)); // V8 会编译 Function 构造函数中创建的函数。
   ```

   `Function()` 构造函数也允许动态创建函数。V8 编译器需要处理这种情况，`compiler.h` 中可能包含 `GetWrappedFunction` 等方法来处理这类编译。

4. **优化编译 (TurboFan/Maglev):**

   ```javascript
   function expensiveCalculation(n) {
     let result = 0;
     for (let i = 0; i < n; i++) {
       result += Math.sqrt(i);
     }
     return result;
   }

   // 多次调用 expensiveCalculation 后，V8 可能会对其进行优化编译。
   for (let i = 0; i < 10000; i++) {
     expensiveCalculation(i);
   }
   ```

   对于频繁执行的热点代码，V8 会使用优化编译器 (如 TurboFan 或 Maglev) 进行编译以提高性能。`compiler.h` 中定义的 `CompileOptimized` 和相关的 Job 类（如 `TurbofanCompilationJob`，`MaglevCompilationJob`）负责管理这些优化编译过程。

**代码逻辑推理（假设输入与输出）:**

假设我们有一个简单的 JavaScript 函数：

```javascript
function square(x) {
  return x * x;
}
```

当 V8 首次遇到对 `square` 的调用时，`Compiler::Compile` 方法可能会被调用，输入可能是：

* **输入:**
    * `isolate`: 当前 V8 隔离区的指针。
    * `shared`:  指向 `square` 函数的 `SharedFunctionInfo` 对象的句柄。`SharedFunctionInfo` 包含了函数的元数据，例如函数名、源代码位置等。
    * `flag`: `CLEAR_EXCEPTION` 或 `KEEP_EXCEPTION`，指示是否清除编译过程中可能产生的异常。
    * `is_compiled_scope`:  一个用于跟踪编译状态的结构。

* **输出:**
    * `bool`:  指示编译是否成功。如果成功，`square` 函数的 `SharedFunctionInfo` 对象将被标记为已编译，并且会生成相应的机器码。

**用户常见的编程错误:**

虽然 `compiler.h` 是 V8 内部的头文件，用户不会直接与其交互，但了解其功能可以帮助理解一些与性能相关的常见编程错误：

1. **过早地依赖优化:**  V8 的优化编译器需要一定的“预热”时间才能生效。过早地假设代码已经过优化可能会导致性能分析不准确。

   ```javascript
   function myFunc() {
     // 一些复杂的计算
   }

   console.time('first run');
   myFunc(); // 第一次运行可能没有经过充分优化
   console.timeEnd('first run');

   console.time('second run');
   myFunc(); // 后续运行可能会被优化
   console.timeEnd('second run');
   ```

2. **编写难以优化的代码:**  某些 JavaScript 代码模式可能难以被优化编译器高效处理，例如：
   * **频繁的类型变化:** 导致优化编译器需要生成更多的 guard 代码。
   * **过多的 try-catch 块:**  可能会阻碍某些优化。
   * **使用 `eval()` 或 `Function()` 构造函数过于频繁:**  动态代码生成会增加编译的开销，并且可能难以优化。

   ```javascript
   function add(a, b) {
     if (typeof a === 'number' && typeof b === 'number') {
       return a + b;
     } else {
       return String(a) + String(b); // 类型不一致，可能难以优化
     }
   }
   ```

**总结:**

`v8/src/codegen/compiler.h` 是 V8 编译器组件的核心头文件，它定义了编译器的接口、管理编译流程、处理不同类型的 JavaScript 代码，并与 V8 的其他组件紧密协作，最终将 JavaScript 代码转换为可执行的机器码。理解其功能有助于深入了解 V8 的工作原理和如何编写更高效的 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/codegen/compiler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/compiler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_COMPILER_H_
#define V8_CODEGEN_COMPILER_H_

#include <forward_list>
#include <memory>

#include "src/ast/ast-value-factory.h"
#include "src/base/platform/elapsed-timer.h"
#include "src/base/small-vector.h"
#include "src/base/threaded-list.h"
#include "src/codegen/background-merge-task.h"
#include "src/codegen/bailout-reason.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/execution/local-isolate.h"
#include "src/handles/persistent-handles.h"
#include "src/logging/code-events.h"
#include "src/objects/contexts.h"
#include "src/objects/debug-objects.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/pending-compilation-error-handler.h"
#include "src/snapshot/code-serializer.h"
#include "src/utils/allocation.h"
#include "src/zone/zone.h"

namespace v8 {

namespace tracing {
class TracedValue;
}  // namespace tracing

namespace internal {

// Forward declarations.
class AlignedCachedData;
class BackgroundCompileTask;
class IsCompiledScope;
class OptimizedCompilationInfo;
class ParseInfo;
class RuntimeCallStats;
class TimedHistogram;
class TurbofanCompilationJob;
class UnoptimizedCompilationInfo;
class UnoptimizedCompilationJob;
class UnoptimizedJSFrame;
class WorkerThreadRuntimeCallStats;
struct ScriptDetails;
struct ScriptStreamingData;

namespace maglev {
class MaglevCompilationJob;

static inline bool IsMaglevEnabled() { return v8_flags.maglev; }

static inline bool IsMaglevOsrEnabled() {
  return IsMaglevEnabled() && v8_flags.maglev_osr;
}

}  // namespace maglev

// The V8 compiler API.
//
// This is the central hub for dispatching to the various compilers within V8.
// Logic for which compiler to choose and how to wire compilation results into
// the object heap should be kept inside this class.
//
// General strategy: Scripts are translated into anonymous functions w/o
// parameters which then can be executed. If the source code contains other
// functions, they might be compiled and allocated as part of the compilation
// of the source code or deferred for lazy compilation at a later point.
class V8_EXPORT_PRIVATE Compiler : public AllStatic {
 public:
  enum ClearExceptionFlag { KEEP_EXCEPTION, CLEAR_EXCEPTION };

  // ===========================================================================
  // The following family of methods ensures a given function is compiled. The
  // general contract is that failures will be reported by returning {false},
  // whereas successful compilation ensures the {is_compiled} predicate on the
  // given function holds (except for live-edit, which compiles the world).

  static bool Compile(Isolate* isolate, Handle<SharedFunctionInfo> shared,
                      ClearExceptionFlag flag,
                      IsCompiledScope* is_compiled_scope,
                      CreateSourcePositions create_source_positions_flag =
                          CreateSourcePositions::kNo);
  static bool Compile(Isolate* isolate, Handle<JSFunction> function,
                      ClearExceptionFlag flag,
                      IsCompiledScope* is_compiled_scope);
  static MaybeHandle<SharedFunctionInfo> CompileToplevel(
      ParseInfo* parse_info, Handle<Script> script, Isolate* isolate,
      IsCompiledScope* is_compiled_scope);

  static bool CompileSharedWithBaseline(Isolate* isolate,
                                        Handle<SharedFunctionInfo> shared,
                                        ClearExceptionFlag flag,
                                        IsCompiledScope* is_compiled_scope);
  static bool CompileBaseline(Isolate* isolate,
                              DirectHandle<JSFunction> function,
                              ClearExceptionFlag flag,
                              IsCompiledScope* is_compiled_scope);

  static void CompileOptimized(Isolate* isolate, Handle<JSFunction> function,
                               ConcurrencyMode mode, CodeKind code_kind);

  // Generate and return optimized code for OSR. The empty handle is returned
  // either on failure, or after spawning a concurrent OSR task (in which case
  // a future OSR request will pick up the resulting code object).
  V8_WARN_UNUSED_RESULT static MaybeHandle<Code> CompileOptimizedOSR(
      Isolate* isolate, Handle<JSFunction> function, BytecodeOffset osr_offset,
      ConcurrencyMode mode, CodeKind code_kind);

  V8_WARN_UNUSED_RESULT static MaybeHandle<SharedFunctionInfo>
  CompileForLiveEdit(ParseInfo* parse_info, Handle<Script> script,
                     MaybeHandle<ScopeInfo> outer_scope_info, Isolate* isolate);

  // Collect source positions for a function that has already been compiled to
  // bytecode, but for which source positions were not collected (e.g. because
  // they were not immediately needed).
  static bool CollectSourcePositions(Isolate* isolate,
                                     Handle<SharedFunctionInfo> shared);

  // Finalize and install code from previously run background compile task.
  static bool FinalizeBackgroundCompileTask(BackgroundCompileTask* task,
                                            Isolate* isolate,
                                            ClearExceptionFlag flag);

  // Dispose a job without finalization.
  static void DisposeTurbofanCompilationJob(Isolate* isolate,
                                            TurbofanCompilationJob* job);

  // Finalize and install Turbofan code from a previously run job.
  static void FinalizeTurbofanCompilationJob(TurbofanCompilationJob* job,
                                             Isolate* isolate);

  // Finalize and install Maglev code from a previously run job.
  static void FinalizeMaglevCompilationJob(maglev::MaglevCompilationJob* job,
                                           Isolate* isolate);

  // Dispose a Maglev compile job.
  static void DisposeMaglevCompilationJob(maglev::MaglevCompilationJob* job,
                                          Isolate* isolate);

  // Give the compiler a chance to perform low-latency initialization tasks of
  // the given {function} on its instantiation. Note that only the runtime will
  // offer this chance, optimized closure instantiation will not call this.
  static void PostInstantiation(Isolate* isolate,
                                DirectHandle<JSFunction> function,
                                IsCompiledScope* is_compiled_scope);

  // ===========================================================================
  // The following family of methods instantiates new functions for scripts or
  // function literals. The decision whether those functions will be compiled,
  // is left to the discretion of the compiler.
  //
  // Please note this interface returns shared function infos.  This means you
  // need to call Factory::NewFunctionFromSharedFunctionInfo before you have a
  // real function with a context.

  // Create a (bound) function for a String source within a context for eval.
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSFunction> GetFunctionFromEval(
      Handle<String> source, Handle<SharedFunctionInfo> outer_info,
      Handle<Context> context, LanguageMode language_mode,
      ParseRestriction restriction, int parameters_end_pos, int eval_position,
      ParsingWhileDebugging parsing_while_debugging =
          ParsingWhileDebugging::kNo);

  // Create a function that results from wrapping |source| in a function,
  // with |arguments| being a list of parameters for that function.
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSFunction> GetWrappedFunction(
      Handle<String> source, Handle<Context> context,
      const ScriptDetails& script_details, AlignedCachedData* cached_data,
      v8::ScriptCompiler::CompileOptions compile_options,
      v8::ScriptCompiler::NoCacheReason no_cache_reason);

  // Create a (bound) function for a String source within a context for eval.
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSFunction> GetFunctionFromString(
      Handle<NativeContext> context, Handle<i::Object> source,
      int parameters_end_pos, bool is_code_like);

  // Decompose GetFunctionFromString into two functions, to allow callers to
  // deal seperately with a case of object not handled by the embedder.
  V8_WARN_UNUSED_RESULT static std::pair<MaybeHandle<String>, bool>
  ValidateDynamicCompilationSource(Isolate* isolate,
                                   Handle<NativeContext> context,
                                   Handle<i::Object> source_object,
                                   bool is_code_like = false);
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSFunction>
  GetFunctionFromValidatedString(Handle<NativeContext> context,
                                 MaybeHandle<String> source,
                                 ParseRestriction restriction,
                                 int parameters_end_pos);

  // Create a shared function info object for a String source.
  static MaybeDirectHandle<SharedFunctionInfo> GetSharedFunctionInfoForScript(
      Isolate* isolate, Handle<String> source,
      const ScriptDetails& script_details,
      ScriptCompiler::CompileOptions compile_options,
      ScriptCompiler::NoCacheReason no_cache_reason,
      NativesFlag is_natives_code,
      ScriptCompiler::CompilationDetails* compilation_details);

  // Create a shared function info object for a String source.
  static MaybeDirectHandle<SharedFunctionInfo>
  GetSharedFunctionInfoForScriptWithExtension(
      Isolate* isolate, Handle<String> source,
      const ScriptDetails& script_details, v8::Extension* extension,
      ScriptCompiler::CompileOptions compile_options,
      NativesFlag is_natives_code,
      ScriptCompiler::CompilationDetails* compilation_details);

  // Create a shared function info object for a String source and serialized
  // cached data. The cached data may be rejected, in which case this function
  // will set cached_data->rejected() to true.
  static MaybeDirectHandle<SharedFunctionInfo>
  GetSharedFunctionInfoForScriptWithCachedData(
      Isolate* isolate, Handle<String> source,
      const ScriptDetails& script_details, AlignedCachedData* cached_data,
      ScriptCompiler::CompileOptions compile_options,
      ScriptCompiler::NoCacheReason no_cache_reason,
      NativesFlag is_natives_code,
      ScriptCompiler::CompilationDetails* compilation_details);

  // Create a shared function info object for a String source and a task that
  // has deserialized cached data on a background thread. The cached data from
  // the task may be rejected, in which case this function will set
  // deserialize_task->rejected() to true.
  static MaybeDirectHandle<SharedFunctionInfo>
  GetSharedFunctionInfoForScriptWithDeserializeTask(
      Isolate* isolate, Handle<String> source,
      const ScriptDetails& script_details,
      BackgroundDeserializeTask* deserialize_task,
      ScriptCompiler::CompileOptions compile_options,
      ScriptCompiler::NoCacheReason no_cache_reason,
      NativesFlag is_natives_code,
      ScriptCompiler::CompilationDetails* compilation_details);

  static MaybeDirectHandle<SharedFunctionInfo>
  GetSharedFunctionInfoForScriptWithCompileHints(
      Isolate* isolate, Handle<String> source,
      const ScriptDetails& script_details,
      v8::CompileHintCallback compile_hint_callback,
      void* compile_hint_callback_data,
      ScriptCompiler::CompileOptions compile_options,
      ScriptCompiler::NoCacheReason no_cache_reason,
      NativesFlag is_natives_code,
      ScriptCompiler::CompilationDetails* compilation_details);

  // Create a shared function info object for a Script source that has already
  // been parsed and possibly compiled on a background thread while being loaded
  // from a streamed source. On return, the data held by |streaming_data| will
  // have been released, however the object itself isn't freed and is still
  // owned by the caller.
  static MaybeDirectHandle<SharedFunctionInfo>
  GetSharedFunctionInfoForStreamedScript(
      Isolate* isolate, Handle<String> source,
      const ScriptDetails& script_details, ScriptStreamingData* streaming_data,
      ScriptCompiler::CompilationDetails* compilation_details);

  // Create a shared function info object for the given function literal
  // node (the code may be lazily compiled).
  template <typename IsolateT>
  static DirectHandle<SharedFunctionInfo> GetSharedFunctionInfo(
      FunctionLiteral* node, Handle<Script> script, IsolateT* isolate);

  static void LogFunctionCompilation(Isolate* isolate,
                                     LogEventListener::CodeTag code_type,
                                     DirectHandle<Script> script,
                                     Handle<SharedFunctionInfo> shared,
                                     Handle<FeedbackVector> vector,
                                     Handle<AbstractCode> abstract_code,
                                     CodeKind kind, double time_taken_ms);

  static void InstallInterpreterTrampolineCopy(
      Isolate* isolate, Handle<SharedFunctionInfo> shared_info,
      LogEventListener::CodeTag log_tag);

 private:
  static std::unique_ptr<v8::tracing::TracedValue> AddScriptCompiledTrace(
      Isolate* isolate, DirectHandle<SharedFunctionInfo> shared);
  static void EmitScriptSourceTextTrace(
      Isolate* isolate, DirectHandle<SharedFunctionInfo> shared);
};

// A base class for compilation jobs intended to run concurrent to the main
// thread. The current state of the job can be checked using {state()}.
class V8_EXPORT_PRIVATE CompilationJob {
 public:
  enum Status { SUCCEEDED, FAILED, RETRY_ON_MAIN_THREAD };
  enum class State {
    kReadyToPrepare,
    kReadyToExecute,
    kReadyToFinalize,
    kSucceeded,
    kFailed,
  };

  explicit CompilationJob(State initial_state) : state_(initial_state) {}
  virtual ~CompilationJob() = default;

  State state() const { return state_; }

 protected:
  V8_WARN_UNUSED_RESULT Status UpdateState(Status status, State next_state) {
    switch (status) {
      case SUCCEEDED:
        state_ = next_state;
        break;
      case FAILED:
        state_ = State::kFailed;
        break;
      case RETRY_ON_MAIN_THREAD:
        // Don't change the state, we'll re-try on the main thread.
        break;
    }
    return status;
  }

 private:
  State state_;
};

// A base class for unoptimized compilation jobs.
//
// The job is split into two phases which are called in sequence on
// different threads and with different limitations:
//  1) ExecuteJob:   Runs concurrently. No heap allocation or handle derefs.
//  2) FinalizeJob:  Runs on main thread. No dependency changes.
//
// Either of phases can either fail or succeed.
class UnoptimizedCompilationJob : public CompilationJob {
 public:
  UnoptimizedCompilationJob(uintptr_t stack_limit, ParseInfo* parse_info,
                            UnoptimizedCompilationInfo* compilation_info)
      : CompilationJob(State::kReadyToExecute),
        stack_limit_(stack_limit),
        parse_info_(parse_info),
        compilation_info_(compilation_info) {}

  // Executes the compile job. Can be called on a background thread.
  V8_WARN_UNUSED_RESULT Status ExecuteJob();

  // Finalizes the compile job. Must be called on the main thread.
  V8_WARN_UNUSED_RESULT Status
  FinalizeJob(Handle<SharedFunctionInfo> shared_info, Isolate* isolate);

  // Finalizes the compile job. Can be called on a background thread, and might
  // return RETRY_ON_MAIN_THREAD if the finalization can't be run on the
  // background thread, and should instead be retried on the foreground thread.
  V8_WARN_UNUSED_RESULT Status
  FinalizeJob(Handle<SharedFunctionInfo> shared_info, LocalIsolate* isolate);

  void RecordCompilationStats(Isolate* isolate) const;
  void RecordFunctionCompilation(LogEventListener::CodeTag code_type,
                                 Handle<SharedFunctionInfo> shared,
                                 Isolate* isolate) const;

  ParseInfo* parse_info() const {
    DCHECK_NOT_NULL(parse_info_);
    return parse_info_;
  }
  UnoptimizedCompilationInfo* compilation_info() const {
    return compilation_info_;
  }

  uintptr_t stack_limit() const { return stack_limit_; }

  base::TimeDelta time_taken_to_execute() const {
    return time_taken_to_execute_;
  }
  base::TimeDelta time_taken_to_finalize() const {
    return time_taken_to_finalize_;
  }

  void ClearParseInfo() { parse_info_ = nullptr; }

 protected:
  // Overridden by the actual implementation.
  virtual Status ExecuteJobImpl() = 0;
  virtual Status FinalizeJobImpl(Handle<SharedFunctionInfo> shared_info,
                                 Isolate* isolate) = 0;
  virtual Status FinalizeJobImpl(Handle<SharedFunctionInfo> shared_info,
                                 LocalIsolate* isolate) = 0;

 private:
  uintptr_t stack_limit_;
  ParseInfo* parse_info_;
  UnoptimizedCompilationInfo* compilation_info_;
  base::TimeDelta time_taken_to_execute_;
  base::TimeDelta time_taken_to_finalize_;
};

// A base class for optimized compilation jobs.
//
// The job is split into three phases which are called in sequence on
// different threads and with different limitations:
//  1) PrepareJob:   Runs on main thread. No major limitations.
//  2) ExecuteJob:   Runs concurrently. No heap allocation or handle derefs.
//  3) FinalizeJob:  Runs on main thread. No dependency changes.
//
// Each of the three phases can either fail or succeed.
class OptimizedCompilationJob : public CompilationJob {
 public:
  OptimizedCompilationJob(const char* compiler_name, State initial_state)
      : CompilationJob(initial_state), compiler_name_(compiler_name) {
    timer_.Start();
  }

  // Prepare the compile job. Must be called on the main thread.
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT Status PrepareJob(Isolate* isolate);

  // Executes the compile job. Can be called on a background thread.
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT Status
  ExecuteJob(RuntimeCallStats* stats, LocalIsolate* local_isolate = nullptr);

  // Finalizes the compile job. Must be called on the main thread.
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT Status FinalizeJob(Isolate* isolate);

  const char* compiler_name() const { return compiler_name_; }

  double prepare_in_ms() const {
    return time_taken_to_prepare_.InMillisecondsF();
  }
  double execute_in_ms() const {
    return time_taken_to_execute_.InMillisecondsF();
  }
  double finalize_in_ms() const {
    return time_taken_to_finalize_.InMillisecondsF();
  }

  V8_WARN_UNUSED_RESULT base::TimeDelta ElapsedTime() const {
    return timer_.Elapsed();
  }

 protected:
  // Overridden by the actual implementation.
  virtual Status PrepareJobImpl(Isolate* isolate) = 0;
  virtual Status ExecuteJobImpl(RuntimeCallStats* stats,
                                LocalIsolate* local_heap) = 0;
  virtual Status FinalizeJobImpl(Isolate* isolate) = 0;

  // Register weak object to optimized code dependencies.
  GlobalHandleVector<Map> CollectRetainedMaps(Isolate* isolate,
                                              DirectHandle<Code> code);
  void RegisterWeakObjectsInOptimizedCode(Isolate* isolate,
                                          DirectHandle<NativeContext> context,
                                          DirectHandle<Code> code,
                                          GlobalHandleVector<Map> maps);

  base::TimeDelta time_taken_to_prepare_;
  base::TimeDelta time_taken_to_execute_;
  base::TimeDelta time_taken_to_finalize_;

  base::ElapsedTimer timer_;

 private:
  const char* const compiler_name_;
};

// Thin wrapper to split off Turbofan-specific parts.
class TurbofanCompilationJob : public OptimizedCompilationJob {
 public:
  TurbofanCompilationJob(OptimizedCompilationInfo* compilation_info,
                         State initial_state)
      : OptimizedCompilationJob("Turbofan", initial_state),
        compilation_info_(compilation_info) {}

  OptimizedCompilationInfo* compilation_info() const {
    return compilation_info_;
  }

  // Report a transient failure, try again next time. Should only be called on
  // optimization compilation jobs.
  Status RetryOptimization(BailoutReason reason);

  // Report a persistent failure, disable future optimization on the function.
  // Should only be called on optimization compilation jobs.
  Status AbortOptimization(BailoutReason reason);

  void RecordCompilationStats(ConcurrencyMode mode, Isolate* isolate) const;
  void RecordFunctionCompilation(LogEventListener::CodeTag code_type,
                                 Isolate* isolate) const;

  // Intended for use as a globally unique id in trace events.
  uint64_t trace_id() const;

 private:
  OptimizedCompilationInfo* const compilation_info_;
};

class FinalizeUnoptimizedCompilationData {
 public:
  FinalizeUnoptimizedCompilationData(Isolate* isolate,
                                     Handle<SharedFunctionInfo> function_handle,
                                     MaybeHandle<CoverageInfo> coverage_info,
                                     base::TimeDelta time_taken_to_execute,
                                     base::TimeDelta time_taken_to_finalize)
      : time_taken_to_execute_(time_taken_to_execute),
        time_taken_to_finalize_(time_taken_to_finalize),
        function_handle_(function_handle),
        coverage_info_(coverage_info) {}

  FinalizeUnoptimizedCompilationData(LocalIsolate* isolate,
                                     Handle<SharedFunctionInfo> function_handle,
                                     MaybeHandle<CoverageInfo> coverage_info,
                                     base::TimeDelta time_taken_to_execute,
                                     base::TimeDelta time_taken_to_finalize);

  Handle<SharedFunctionInfo> function_handle() const {
    return function_handle_;
  }

  MaybeHandle<CoverageInfo> coverage_info() const { return coverage_info_; }

  base::TimeDelta time_taken_to_execute() const {
    return time_taken_to_execute_;
  }
  base::TimeDelta time_taken_to_finalize() const {
    return time_taken_to_finalize_;
  }

 private:
  base::TimeDelta time_taken_to_execute_;
  base::TimeDelta time_taken_to_finalize_;
  Handle<SharedFunctionInfo> function_handle_;
  MaybeHandle<CoverageInfo> coverage_info_;
};

using FinalizeUnoptimizedCompilationDataList =
    std::vector<FinalizeUnoptimizedCompilationData>;

class DeferredFinalizationJobData {
 public:
  DeferredFinalizationJobData(Isolate* isolate,
                              DirectHandle<SharedFunctionInfo> function_handle,
                              std::unique_ptr<UnoptimizedCompilationJob> job) {
    UNREACHABLE();
  }
  DeferredFinalizationJobData(LocalIsolate* isolate,
                              Handle<SharedFunctionInfo> function_handle,
                              std::unique_ptr<UnoptimizedCompilationJob> job);

  Handle<SharedFunctionInfo> function_handle() const {
    return function_handle_;
  }

  UnoptimizedCompilationJob* job() const { return job_.get(); }

 private:
  Handle<SharedFunctionInfo> function_handle_;
  std::unique_ptr<UnoptimizedCompilationJob> job_;
};

// A wrapper around a OptimizedCompilationInfo that detaches the Handles from
// the underlying PersistentHandlesScope and stores them in info_ on
// destruction.
class V8_NODISCARD CompilationHandleScope final {
 public:
  explicit CompilationHandleScope(Isolate* isolate,
                                  OptimizedCompilationInfo* info)
      : persistent_(isolate), info_(info) {}
  V8_EXPORT_PRIVATE ~CompilationHandleScope();

 private:
  PersistentHandlesScope persistent_;
  OptimizedCompilationInfo* info_;
};

using DeferredFinalizationJobDataList =
    std::vector<DeferredFinalizationJobData>;

class V8_EXPORT_PRIVATE BackgroundCompileTask {
 public:
  // Creates a new task that when run will parse and compile the streamed
  // script associated with |data| and can be finalized with FinalizeScript.
  // Note: does not take ownership of |data|.
  BackgroundCompileTask(ScriptStreamingData* data, Isolate* isolate,
                        v8::ScriptType type,
                        ScriptCompiler::CompileOptions options,
                        ScriptCompiler::CompilationDetails* compilation_details,
                        CompileHintCallback compile_hint_callback = nullptr,
                        void* compile_hint_callback_data = nullptr);
  BackgroundCompileTask(const BackgroundCompileTask&) = delete;
  BackgroundCompileTask& operator=(const BackgroundCompileTask&) = delete;
  ~BackgroundCompileTask();

  // Creates a new task that when run will parse and compile the non-top-level
  // |shared_info| and can be finalized with FinalizeFunction in
  // Compiler::FinalizeBackgroundCompileTask.
  BackgroundCompileTask(
      Isolate* isolate, Handle<SharedFunctionInfo> shared_info,
      std::unique_ptr<Utf16CharacterStream> character_stream,
      WorkerThreadRuntimeCallStats* worker_thread_runtime_stats,
      TimedHistogram* timer, int max_stack_size);

  void Run();
  void RunOnMainThread(Isolate* isolate);
  void Run(LocalIsolate* isolate,
           ReusableUnoptimizedCompileState* reusable_state);

  MaybeHandle<SharedFunctionInfo> FinalizeScript(
      Isolate* isolate, DirectHandle<String> source,
      const ScriptDetails& script_details,
      MaybeHandle<Script> maybe_cached_script);

  bool FinalizeFunction(Isolate* isolate, Compiler::ClearExceptionFlag flag);

  void AbortFunction();

  UnoptimizedCompileFlags flags() const { return flags_; }

 private:
  void ReportStatistics(Isolate* isolate);

  void ClearFunctionJobPointer();

  bool is_streaming_compilation() const;

  // Data needed for parsing and compilation. These need to be initialized
  // before the compilation starts.
  Isolate* isolate_for_local_isolate_;
  UnoptimizedCompileFlags flags_;
  UnoptimizedCompileState compile_state_;
  std::unique_ptr<Utf16CharacterStream> character_stream_;
  int stack_size_;
  WorkerThreadRuntimeCallStats* worker_thread_runtime_call_stats_;
  TimedHistogram* timer_;
  ScriptCompiler::CompilationDetails* compilation_details_;

  // Data needed for merging onto the main thread after background finalization.
  std::unique_ptr<PersistentHandles> persistent_handles_;
  MaybeIndirectHandle<SharedFunctionInfo> outer_function_sfi_;
  IndirectHandle<Script> script_;
  IsCompiledScope is_compiled_scope_;
  FinalizeUnoptimizedCompilationDataList finalize_unoptimized_compilation_data_;
  DeferredFinalizationJobDataList jobs_to_retry_finalization_on_main_thread_;
  base::SmallVector<v8::Isolate::UseCounterFeature, 8> use_counts_;
  int total_preparse_skipped_ = 0;

  // Single function data for top-level function compilation.
  MaybeIndirectHandle<SharedFunctionInfo> input_shared_info_;
  int start_position_;
  int end_position_;
  int function_literal_id_;

  CompileHintCallback compile_hint_callback_ = nullptr;
  void* compile_hint_callback_data_ = nullptr;
};

// Contains all data which needs to be transmitted between threads for
// background parsing and compiling and finalizing it on the main thread.
struct V8_EXPORT_PRIVATE ScriptStreamingData {
  ScriptStreamingData(
      std::unique_ptr<ScriptCompiler::ExternalSourceStream> source_stream,
      ScriptCompiler::StreamedSource::Encoding encoding);
  ScriptStreamingData(const ScriptStreamingData&) = delete;
  ScriptStreamingData& operator=(const ScriptStreamingData&) = delete;
  ~ScriptStreamingData();

  void Release();

  // Internal implementation of v8::ScriptCompiler::StreamedSource.
  std::unique_ptr<ScriptCompiler::ExternalSourceStream> source_stream;
  ScriptCompiler::StreamedSource::Encoding encoding;

  // Task that performs background parsing and compilation.
  std::unique_ptr<BackgroundCompileTask> task;
};

class V8_EXPORT_PRIVATE BackgroundDeserializeTask {
 public:
  BackgroundDeserializeTask(Isolate* isolate,
                            std::unique_ptr<ScriptCompiler::CachedData> data);

  void Run();

  // Checks the Isolate compilation cache to see whether it will be necessary to
  // merge the newly deserialized objects into an existing Script. This can
  // change the value of ShouldMergeWithExistingScript, and embedders should
  // check the latter after calling this. May only be called on a thread where
  // the Isolate is currently entered.
  void SourceTextAvailable(Isolate* isolate, Handle<String> source_text,
                           const ScriptDetails& script_details);

  // Returns whether the embedder should call MergeWithExistingScript. This
  // function may be called from any thread, any number of times, but its return
  // value is only meaningful after SourceTextAvailable has completed.
  bool ShouldMergeWithExistingScript() const;

  // Partially merges newly deserialized objects into an existing Script with
  // the same source, as provided by SourceTextAvailable, and generates a list
  // of follow-up work for the main thread. May be called from any thread, only
  // once.
  void MergeWithExistingScript();

  MaybeHandle<SharedFunctionInfo> Finish(Isolate* isolate,
                                         DirectHandle<String> source,
                                         const ScriptDetails& script_details);

  bool rejected() const { return cached_data_.rejected(); }

  int64_t background_time_in_microseconds() const {
    return background_time_in_microseconds_;
  }

 private:
  Isolate* isolate_for_local_isolate_;
  AlignedCachedData cached_data_;
  CodeSerializer::OffThreadDeserializeData off_thread_data_;
  BackgroundMergeTask background_merge_task_;
  TimedHistogram* timer_;
  int64_t background_time_in_microseconds_ = 0;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_CODEGEN_COMPILER_H_

"""

```