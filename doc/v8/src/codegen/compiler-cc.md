Response:
The user wants to understand the functionality of the `compiler.cc` file in the V8 JavaScript engine. I need to analyze the provided C++ code and summarize its main responsibilities. The request also includes specific instructions related to file extensions, JavaScript examples, code logic, common errors, and the decomposition into parts.

Here's a breakdown of the thought process to address each point:

1. **List the functionalities:** I'll read through the code, paying attention to included headers, class names, function names, and general code structure. Keywords like "compile," "optimize," "parse," and names like `Compiler`, `CompilationJob`, `TurbofanCompilationJob` are strong indicators of the file's purpose. The presence of tracing and logging mechanisms also hints at debugging and performance analysis features.

2. **Check for `.tq` extension:** The prompt states that if the filename ended in `.tq`, it would be a Torque source file. Since the filename is `compiler.cc`, this condition is not met.

3. **Relate to JavaScript functionality:** This requires identifying parts of the code that directly enable the execution of JavaScript. Compilation (into bytecode or machine code), optimization, and handling of JavaScript-specific concepts (like functions, scripts, and feedback) are key areas. I'll need to provide simple JavaScript examples that illustrate these concepts being handled by the compiler.

4. **Code logic and examples:** The code includes functions that manage compilation jobs and track their status. I can create hypothetical scenarios, like starting a compilation job and it either succeeding or failing, to illustrate the flow. I'll define some simple inputs and expected outputs for these scenarios.

5. **Common programming errors:** I need to identify potential errors that developers might make in their JavaScript code that this compiler would encounter and potentially handle (or trigger other parts of the engine to handle). Examples include syntax errors, type errors, and performance-related issues.

6. **Summarize the functionality:**  Based on the above points, I will condense the key responsibilities of `compiler.cc` into a concise summary. Since this is part 1 of 6, I'll focus on the general overview and the aspects covered in this specific code snippet.

**Pre-computation and Pre-analysis:**

* **Header files:** The included headers provide valuable clues about the file's dependencies and functionalities. For example, `src/ast/*` suggests dealing with Abstract Syntax Trees, `src/codegen/*` indicates code generation, `src/compiler/*` points to optimization stages, and `src/interpreter/*` implies handling interpreted code.
* **Class names:** `Compiler`, `CompilationJob`, `UnoptimizedCompilationJob`, `OptimizedCompilationJob`, and `TurbofanCompilationJob` clearly delineate different stages and types of compilation.
* **Tracing and logging:** The `CompilerTracer` class and calls to `LOG` and `PROFILE` indicate the presence of debugging and performance analysis features.
* **Concurrency:** The use of `ConcurrencyMode` and mentions of background compilation suggest handling compilation tasks in parallel.
* **Optimization tiers:**  References to "baseline," "maglev," and "turbofan" indicate different levels of optimization.

**Putting it all together (Draft 1 - Internal Monologue):**

Okay, this file is definitely about compiling JavaScript code in V8. It seems to handle both unoptimized (likely for initial execution) and optimized compilation (for better performance). The different `CompilationJob` subclasses probably manage the different compilation pipelines. The tracing and logging are for debugging and performance analysis. The code interacts with the AST and generates either bytecode or machine code. JavaScript examples should focus on function definitions and how V8 compiles them. For logic, I can show how a compilation job transitions through states. Common errors could be syntax mistakes. The summary should highlight the core role of compiling JavaScript.

**Refinement (Draft 2 - Addressing Specific Instructions):**

* **Functionality List:** Be more specific. Instead of "compiling," mention parsing, bytecode generation, optimization (baseline, Maglev, Turbofan), and code installation. Also include logging and tracing.
* **`.tq`:** Explicitly state it's not a Torque file.
* **JavaScript examples:**  Provide actual code snippets for simple function compilation and optimization.
* **Code logic:** Use a simple scenario of a compilation job starting and finishing. Include potential failure.
* **Common errors:** Give concrete examples like syntax errors and type errors.
* **Summary:** Focus on `compiler.cc` as the central point for taking JavaScript and turning it into executable code within V8. Emphasize the different compilation tiers.

By following these steps, I can systematically address each part of the user's request and generate a comprehensive and accurate response.
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/compiler.h"

// ... many includes ...

namespace v8 {
namespace internal {

namespace {

// ... (Helper functions and classes) ...

}  // namespace

// static
void Compiler::LogFunctionCompilation(Isolate* isolate,
                                      LogEventListener::CodeTag code_type,
                                      DirectHandle<Script> script,
                                      Handle<SharedFunctionInfo> shared,
                                      Handle<FeedbackVector> vector,
                                      Handle<AbstractCode> abstract_code,
                                      CodeKind kind, double time_taken_ms) {
  // ... (Logging logic) ...
}

namespace {

// ... (Helper function for ScriptOriginOptions) ...

}  // namespace

// ----------------------------------------------------------------------------
// Implementation of UnoptimizedCompilationJob

CompilationJob::Status UnoptimizedCompilationJob::ExecuteJob() {
  // ...
}

CompilationJob::Status UnoptimizedCompilationJob::FinalizeJob(
    Handle<SharedFunctionInfo> shared_info, Isolate* isolate) {
  // ...
}

CompilationJob::Status UnoptimizedCompilationJob::FinalizeJob(
    Handle<SharedFunctionInfo> shared_info, LocalIsolate* isolate) {
  // ...
}

namespace {
void LogUnoptimizedCompilation(Isolate* isolate,
                               Handle<SharedFunctionInfo> shared,
                               LogEventListener::CodeTag code_type,
                               base::TimeDelta time_taken_to_execute,
                               base::TimeDelta time_taken_to_finalize) {
  // ...
}

}  // namespace

// ----------------------------------------------------------------------------
// Implementation of OptimizedCompilationJob

CompilationJob::Status OptimizedCompilationJob::PrepareJob(Isolate* isolate) {
  // ...
}

CompilationJob::Status OptimizedCompilationJob::ExecuteJob(
    RuntimeCallStats* stats, LocalIsolate* local_isolate) {
  // ...
}

CompilationJob::Status OptimizedCompilationJob::FinalizeJob(Isolate* isolate) {
  // ...
}

GlobalHandleVector<Map> OptimizedCompilationJob::CollectRetainedMaps(
    Isolate* isolate, DirectHandle<Code> code) {
  // ...
}

void OptimizedCompilationJob::RegisterWeakObjectsInOptimizedCode(
    Isolate* isolate, DirectHandle<NativeContext> context,
    DirectHandle<Code> code, GlobalHandleVector<Map> maps) {
  // ...
}

CompilationJob::Status TurbofanCompilationJob::RetryOptimization(
    BailoutReason reason) {
  // ...
}

CompilationJob::Status TurbofanCompilationJob::AbortOptimization(
    BailoutReason reason) {
  // ...
}

void TurbofanCompilationJob::RecordCompilationStats(ConcurrencyMode mode,
                                                    Isolate* isolate) const {
  // ...
}

void TurbofanCompilationJob::RecordFunctionCompilation(
    LogEventListener::CodeTag code_type, Isolate* isolate) const {
  // ...
}

uint64_t TurbofanCompilationJob::trace_id() const {
  // ...
}

// ----------------------------------------------------------------------------
// Local helper methods that make up the compilation pipeline.

namespace {

#if V8_ENABLE_WEBASSEMBLY
bool UseAsmWasm(FunctionLiteral* literal, bool asm_wasm_broken) {
  // ...
}
#endif

}  // namespace

void Compiler::InstallInterpreterTrampolineCopy(
    Isolate* isolate, Handle<SharedFunctionInfo> shared_info,
    LogEventListener::CodeTag log_tag) {
  // ...
}

namespace {

template <typename IsolateT>
void InstallUnoptimizedCode(UnoptimizedCompilationInfo* compilation_info,
                            DirectHandle<SharedFunctionInfo> shared_info,
                            IsolateT* isolate) {
  // ...
}

template <typename IsolateT>
void EnsureInfosArrayOnScript(DirectHandle<Script> script,
                              ParseInfo* parse_info, IsolateT* isolate) {
  // ...
}

void UpdateSharedFunctionFlagsAfterCompilation(FunctionLiteral* literal) {
  // ...
}

// Finalize a single compilation job.
template <typename IsolateT>
CompilationJob::Status FinalizeSingleUnoptimizedCompilationJob(
    UnoptimizedCompilationJob* job, Handle<SharedFunctionInfo> shared_info,
    IsolateT* isolate,
    FinalizeUnoptimizedCompilationDataList*
        finalize_unoptimized_compilation_data_list) {
  // ...
}

std::unique_ptr<UnoptimizedCompilationJob>
ExecuteS
```

### 功能列举

根据提供的代码片段，`v8/src/codegen/compiler.cc` 的主要功能包括：

1. **管理代码编译流程:**  它定义了 `CompilationJob` 及其子类 (`UnoptimizedCompilationJob`, `OptimizedCompilationJob`, `TurbofanCompilationJob`)，用于管理不同阶段和级别的代码编译任务。
2. **处理未优化的代码编译:** `UnoptimizedCompilationJob` 负责处理最初的、未经过深度优化的代码编译，通常生成解释器可以执行的字节码。
3. **处理优化代码编译:** `OptimizedCompilationJob` 和 `TurbofanCompilationJob` 负责处理代码的优化编译，例如使用 Turbofan 编译器生成更高效的机器码。
4. **代码安装:**  负责将编译生成的代码（例如字节码或机器码）安装到 `SharedFunctionInfo` 对象中，以便后续执行。
5. **性能追踪和日志记录:** 包含用于追踪编译过程的 `CompilerTracer` 类，以及用于记录编译事件、时间和代码信息的函数 (`LogFunctionCompilation`, `LogUnoptimizedCompilation`)。
6. **处理 WebAssembly 编译 (条件性):**  在启用了 WebAssembly 的情况下，可能包含处理 asm.js 或 WebAssembly 模块编译的逻辑。
7. **管理编译状态:**  `CompilationJob` 类维护编译任务的状态（例如，准备、执行、完成、失败）。
8. **处理函数元数据:**  涉及到更新 `SharedFunctionInfo` 的标志和元数据，例如是否包含重复参数、预期的属性数量等。
9. **处理即时编译 (JIT) 和提前编译 (AOT):** 虽然代码片段没有直接体现 AOT，但其编译框架支持 JIT 编译，并且其结构可以支持 AOT 的集成。
10. **与其他 V8 组件交互:**  它与 AST (Abstract Syntax Tree)、解析器、解释器、优化器 (Turbofan, Maglev 等)、以及内存管理 (Heap) 等 V8 的其他组件紧密合作。
11. **处理代码缓存:**  虽然代码片段中未直接显示，但编译过程会涉及到代码缓存的查找和更新，以避免重复编译。
12. **支持 OSR (On-Stack Replacement):**  `CompilerTracer` 中有关于 OSR 的跟踪信息，表明该文件参与了 OSR 过程，即在函数执行过程中进行优化编译。

### 关于文件扩展名

根据您的描述，如果 `v8/src/codegen/compiler.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。但由于它以 `.cc` 结尾，所以它是一个标准的 C++ 源代码文件。

### 与 JavaScript 功能的关系及示例

`v8/src/codegen/compiler.cc` 与 JavaScript 功能有着核心的关系。它的主要职责是将 JavaScript 代码转换为可以被 V8 执行的形式。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

add(5, 3);
```

当 V8 引擎执行这段 JavaScript 代码时，`compiler.cc` 参与了以下过程：

1. **解析 (Parsing):**  虽然解析不是 `compiler.cc` 的直接职责，但编译过程依赖于解析器生成的抽象语法树 (AST)。
2. **未优化编译 (Baseline Compilation/Interpretation):**  对于首次执行或执行次数较少的函数，V8 可能会使用解释器或 Baseline 编译器快速生成字节码。 `UnoptimizedCompilationJob` 及其相关逻辑会参与这个过程。
3. **优化编译 (Optimization):**  当函数被频繁调用时，V8 会触发优化编译。 `OptimizedCompilationJob` 和 `TurbofanCompilationJob` 负责使用 Turbofan 等优化编译器生成高度优化的机器码，例如：
    * **内联 (Inlining):** 将 `add` 函数的调用替换为函数体本身。
    * **类型推断 (Type Inference):**  如果 V8 确定 `a` 和 `b` 总是数字，它可以生成更高效的加法指令。
    * **逃逸分析 (Escape Analysis):** 确定变量的作用域，以便进行栈上分配等优化。
4. **即时编译 (JIT):**  编译是发生在运行时，因此是即时编译。

**代码逻辑推理及示例**

假设我们有一个简单的函数：

```javascript
function square(x) {
  return x * x;
}
```

**假设输入：**

* 一个 `FunctionLiteral` 对象，表示 `square` 函数的 AST 节点。
* 一个 `SharedFunctionInfo` 对象，用于存储 `square` 函数的元数据。

**代码逻辑推理 (简化版):**

1. 当 `square` 函数首次被调用时，V8 会创建一个 `UnoptimizedCompilationJob` 来编译它。
2. `UnoptimizedCompilationJob::ExecuteJob()`  会调用解释器生成 `square` 函数的字节码。
3. `UnoptimizedCompilationJob::FinalizeJob()` 会将生成的字节码存储到 `SharedFunctionInfo` 中。
4. 如果 `square` 函数被多次调用，V8 会创建一个 `TurbofanCompilationJob` 来进行优化。
5. `TurbofanCompilationJob::PrepareJob()` 会进行优化前的准备工作。
6. `TurbofanCompilationJob::ExecuteJob()` 会调用 Turbofan 编译器生成优化的机器码。
7. `TurbofanCompilationJob::FinalizeJob()` 会将生成的机器码安装到 `SharedFunctionInfo` 中，替换之前的字节码（或者在不同的执行入口点）。

**假设输出：**

* 对于未优化编译：`SharedFunctionInfo` 对象现在包含 `square` 函数的字节码。
* 对于优化编译：`SharedFunctionInfo` 对象现在包含 `square` 函数的优化后的机器码。

### 用户常见的编程错误

`v8/src/codegen/compiler.cc` 在编译过程中可能会遇到由用户编程错误引起的各种情况。以下是一些例子：

1. **语法错误 (SyntaxError):**
   ```javascript
   functoin myFunc() { // 拼写错误 "function"
     console.log("Hello");
   }
   ```
   解析器会首先捕获这些错误，但编译阶段可能会对解析后的 AST 进行进一步的验证。

2. **类型错误 (TypeError) 可能导致的优化失败:**
   ```javascript
   function add(a, b) {
     return a + b;
   }

   add(5, "hello"); // 类型不一致
   ```
   虽然 JavaScript 是动态类型的，但优化编译器会尝试基于观察到的类型进行优化。如果类型不一致，优化可能会失败（bailout），导致回退到未优化的代码。`TurbofanCompilationJob::AbortOptimization()` 可能会被调用。

3. **性能陷阱导致的优化困难:**
   ```javascript
   function processArray(arr) {
     for (let i in arr) { // 遍历数组不推荐使用 for...in
       console.log(arr[i]);
     }
   }
   ```
   使用 `for...in` 遍历数组可能会引入意外的属性，使得优化器难以进行有效的优化。

4. **过早优化:**
   ```javascript
   function complexCalculation() {
     // ... 非常复杂的计算
   }

   // ... 代码的其他部分 ...

   // 假设这段代码只运行一次
   complexCalculation();
   ```
   对于只运行一次的代码进行深度优化可能反而会增加启动时间。V8 的分层编译策略尝试平衡这一点。

### 功能归纳 (第 1 部分)

作为第 1 部分，`v8/src/codegen/compiler.cc` 的主要功能是**定义和管理 V8 引擎中代码编译的核心流程和数据结构**。它负责将 JavaScript 源代码转化为可执行的字节码（用于解释执行）和高度优化的机器码（用于提高性能）。 该文件包含了处理不同编译阶段（未优化和优化）的类和逻辑，并提供了性能追踪和日志记录机制。它与 V8 的其他组件紧密协作，共同实现了 JavaScript 代码的执行。

### 提示词
```
这是目录为v8/src/codegen/compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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
ExecuteS
```