Response:
Let's break down the thought process for analyzing this V8 source code and generating the summary.

1. **Understand the Goal:** The primary goal is to understand the functionality of `v8/src/runtime/runtime-compiler.cc`. We need to extract key aspects, relate it to JavaScript where possible, identify potential errors, and consider the `.tq` extension possibility.

2. **Initial Scan for Keywords and Structure:**  I'd start by skimming the code for obvious clues. Keywords like `Compile`, `Optimization`, `Deoptimize`, `Lazy`, `Baseline`, `Turbofan`, `Maglev`, `OSR`, `Eval`, and function names starting with `Runtime_` are strong indicators of the file's purpose. The `#include` directives at the top also give hints about the areas it interacts with (e.g., `asmjs`, `codegen`, `deoptimizer`, `execution`, `objects`). The `namespace v8::internal` is a standard V8 convention.

3. **Focus on `RUNTIME_FUNCTION` Macros:**  These are the entry points from the JavaScript runtime into the C++ code. Each `RUNTIME_FUNCTION` corresponds to a specific operation. This is a good way to systematically analyze the file's functionality. I would go through each one and try to understand its purpose.

4. **Analyze Individual `RUNTIME_FUNCTION`s:**

   * **`Runtime_CompileLazy`:** The name is very suggestive. The code confirms it's about compiling a function "lazily" when it's first called. The check for stack overflow during compilation is important.
   * **`Runtime_InstallBaselineCode`:**  This deals with "baseline" code, which is a less optimized, but faster-than-interpreted version. The interaction with `FeedbackVector` is a key detail for performance optimization.
   * **`Runtime_InstallSFICode`:** "SFI" likely stands for `SharedFunctionInfo`. This seems to install the code associated with the shared function information. The handling of baseline code within this function is also notable.
   * **`Runtime_StartMaglevOptimizationJob`, `Runtime_StartTurbofanOptimizationJob`, `Runtime_OptimizeMaglevEager`, `Runtime_OptimizeTurbofanEager` (and the non-LEAPTIERING `Runtime_CompileOptimized`):** These functions are clearly about different levels and modes of optimization (Maglev and Turbofan, concurrent and eager). The `LEAPTIERING` preprocessor directives suggest different compilation pipelines.
   * **`Runtime_HealOptimizedCodeSlot`:** The name indicates fixing or dealing with optimized code slots, likely related to deoptimization.
   * **`Runtime_FunctionLogNextExecution`:** This is a simpler function related to logging function executions, triggered by a flag.
   * **`Runtime_InstantiateAsmJs`:**  This is specific to compiling and instantiating asm.js code, with fallback mechanisms if instantiation fails.
   * **`Runtime_NotifyDeoptimized`:**  This is crucial for the deoptimization process. It retrieves information about the deoptimization and potentially invalidates optimized code. The logic around OSR loops is complex but important.
   * **`Runtime_ObserveNode`, `Runtime_VerifyType`, `Runtime_CheckTurboshaftTypeOf`:** These seem to be related to debugging or type checking, likely more relevant in optimized code. The comment "no effect in the interpreter" is a key piece of information.
   * **`Runtime_CompileOptimizedOSR`:** This handles "On-Stack Replacement" (OSR), a technique for optimizing code while it's running in a loop.
   * **`Runtime_CompileOptimizedOSRFromMaglev`, `Runtime_CompileOptimizedOSRFromMaglevInlined`:** These are specific OSR scenarios starting from Maglev-compiled code.
   * **`Runtime_LogOrTraceOptimizedOSREntry`:** This is for logging/tracing when OSR enters optimized code.
   * **`Runtime_ResolvePossiblyDirectEval`:** This handles the intricacies of the `eval()` function, especially the difference between direct and indirect calls.

5. **Identify Core Functionality:**  After analyzing the individual functions, I would group them into broader categories to summarize the file's main functions. This leads to the categories: Compilation, Optimization, Deoptimization, asm.js, and Eval.

6. **Relate to JavaScript:**  For each functional category, think about how it manifests in JavaScript. Lazy compilation is implicit in how JavaScript executes. Optimization happens behind the scenes. Deoptimization can sometimes be observed indirectly through performance changes. `eval()` is a direct JavaScript construct. asm.js is a more specialized case. Provide simple JavaScript examples where possible to illustrate these concepts.

7. **Code Logic Inference (Hypothetical Inputs/Outputs):**  For functions with more complex logic (like `Runtime_NotifyDeoptimized`), consider simplified scenarios and what the expected behavior would be. This helps illustrate the purpose of the code. While detailed tracing isn't possible without running the code, you can make reasoned assumptions based on the function's name and the operations it performs.

8. **Common Programming Errors:** Think about how the functionality in this file relates to things developers might do wrong. Over-reliance on `eval()`, assuming code is always optimized, and not understanding the performance implications of different code structures are relevant here.

9. **Address the `.tq` Question:** Check the provided information about the `.tq` extension. If the file ends in `.tq`, it's Torque code. State this clearly.

10. **Structure the Output:**  Organize the findings logically. Start with a general summary of the file's purpose. Then detail the key functions. Follow with the JavaScript examples, code logic inferences, and common errors. Finally, address the `.tq` question.

11. **Refine and Review:**  Read through the generated summary to ensure accuracy, clarity, and completeness. Correct any errors or omissions. Make sure the language is clear and easy to understand, even for someone who isn't deeply familiar with V8 internals. For instance, initially, I might just list function names. Reviewing would prompt me to explain *what* each function does.

This systematic approach, moving from broad overview to specific details and then back to broader categories, helps to thoroughly analyze the source code and generate a comprehensive and informative summary.
这段代码是 V8 引擎中 `v8/src/runtime/runtime-compiler.cc` 文件的内容。它主要负责 **运行时（runtime）的编译** 相关功能，是 V8 执行 JavaScript 代码的关键部分。

以下是它的主要功能列表：

**核心编译功能:**

* **惰性编译 (Lazy Compilation): `Runtime_CompileLazy`**：  这是最基础的编译形式。当一个函数第一次被调用时，V8 不会立即将其编译成机器码，而是先执行解释器。`Runtime_CompileLazy`  会在稍后的某个时机（通常是函数被调用多次后）将该函数编译成机器码，以提高执行效率。
* **安装基线代码 (Install Baseline Code): `Runtime_InstallBaselineCode`**：在 V8 的分层编译系统中，基线代码是一种轻量级的优化代码，比解释执行快，但不如完全优化后的代码。这个函数负责安装这种基线版本的代码。
* **安装 SFI 代码 (Install SFI Code): `Runtime_InstallSFICode`**: SFI 代表 SharedFunctionInfo。这个函数用于安装与 `SharedFunctionInfo` 关联的代码。这通常发生在函数第一次被编译时。

**优化编译功能 (涉及到 Maglev 和 Turbofan 两个优化编译器):**

* **启动 Maglev 优化任务 (Start Maglev Optimization Job): `Runtime_StartMaglevOptimizationJob`**:  Maglev 是 V8 中一种相对较新的中级优化编译器。此函数启动一个并发任务，将函数编译为 Maglev 代码。
* **启动 Turbofan 优化任务 (Start Turbofan Optimization Job): `Runtime_StartTurbofanOptimizationJob`**: Turbofan 是 V8 中主要的、更激进的优化编译器。此函数启动一个并发任务，将函数编译为 Turbofan 代码。
* **Eager Maglev 优化 (Optimize Maglev Eager): `Runtime_OptimizeMaglevEager`**: 立即（同步地）将函数编译为 Maglev 代码。
* **Eager Turbofan 优化 (Optimize Turbofan Eager): `Runtime_OptimizeTurbofanEager`**: 立即（同步地）将函数编译为 Turbofan 代码。
* **编译优化代码 (Compile Optimized): `Runtime_CompileOptimized` (在没有 `V8_ENABLE_LEAPTIERING` 时)**：根据函数的当前状态（请求 Maglev 或 Turbofan，同步或并发），编译为相应的优化代码。

**代码修复和日志功能:**

* **修复优化代码槽 (Heal Optimized Code Slot): `Runtime_HealOptimizedCodeSlot`**: 当优化代码出现问题需要回退时，这个函数会清除优化的代码槽。
* **函数记录下次执行 (Function Log Next Execution): `Runtime_FunctionLogNextExecution`**: 如果开启了函数事件日志记录，这个函数会记录函数的下一次执行。

**asm.js 相关功能:**

* **实例化 Asm.js (Instantiate AsmJs): `Runtime_InstantiateAsmJs`**:  负责将 asm.js 模块实例化。如果实例化失败，会回退到普通的 JavaScript 执行。

**去优化 (Deoptimization) 功能:**

* **通知已去优化 (Notify Deoptimized): `Runtime_NotifyDeoptimized`**: 当优化后的代码因为某些原因（例如类型假设失败）需要回退到未优化状态时，这个函数会被调用。它会执行清理工作，例如失效优化后的代码。
* **去优化包含去优化退出的所有 OSR 循环 (DeoptAllOsrLoopsContainingDeoptExit)**:  一个辅助函数，用于在发生去优化时，处理与 On-Stack Replacement (OSR) 相关的循环。

**其他运行时支持功能:**

* **观察节点 (ObserveNode): `Runtime_ObserveNode`**:  用于在 TurboFan 编译的代码中跟踪观察节点的更改（主要用于调试和性能分析）。
* **验证类型 (VerifyType): `Runtime_VerifyType`**:  在解释器中没有实际作用，可能在编译后的代码中有类型检查或断言的功能。
* **检查 Turboshaft 类型 (CheckTurboshaftTypeOf): `Runtime_CheckTurboshaftTypeOf`**:  类似于 `Runtime_VerifyType`，可能与 Turboshaft 编译器相关。
* **编译优化 OSR (Compile Optimized OSR): `Runtime_CompileOptimizedOSR`**:  负责在代码正在执行的循环中进行优化（On-Stack Replacement）。
* **从 Maglev 编译优化 OSR (Compile Optimized OSR From Maglev/Inlined): `Runtime_CompileOptimizedOSRFromMaglev`, `Runtime_CompileOptimizedOSRFromMaglevInlined`**:  当从 Maglev 编译的代码进行 OSR 时调用。
* **记录或追踪优化 OSR 进入 (LogOrTraceOptimizedOSREntry): `Runtime_LogOrTraceOptimizedOSREntry`**:  用于记录或追踪进入 OSR 优化代码的事件。

**Eval 相关功能:**

* **解析可能的直接 Eval (ResolvePossiblyDirectEval): `Runtime_ResolvePossiblyDirectEval`**:  处理 `eval()` 函数的调用，区分直接 `eval()` 和间接 `eval()`，并负责编译 `eval()` 中包含的代码。
* **编译全局 Eval (CompileGlobalEval)**: 一个辅助函数，用于实际编译全局 `eval()` 调用的代码。

**关于 .tq 结尾:**

如果 `v8/src/runtime/runtime-compiler.cc` 以 `.tq` 结尾，**那它将是一个 V8 Torque 源代码文件**。 Torque 是一种 V8 自研的类型化的中间语言，用于生成 V8 的内置函数和运行时代码。`.tq` 文件使用 Torque 语法编写。

**与 JavaScript 功能的关系及示例:**

这个文件中的功能直接影响 JavaScript 代码的执行效率和行为。以下是一些与 JavaScript 功能相关的示例：

1. **惰性编译:** 当你第一次调用一个 JavaScript 函数时，V8 可能会先解释执行。多次调用后，V8 会将其编译以提高性能。

   ```javascript
   function add(a, b) {
     return a + b;
   }

   // 第一次调用，可能解释执行
   console.log(add(1, 2));

   // 多次调用后，V8 可能已经将其编译
   for (let i = 0; i < 10000; i++) {
     add(i, i + 1);
   }
   ```

2. **优化编译 (Maglev 和 Turbofan):** V8 会根据代码的执行情况，选择使用 Maglev 或 Turbofan 将热点代码编译成高度优化的机器码。

   ```javascript
   function calculateSum(n) {
     let sum = 0;
     for (let i = 0; i <= n; i++) {
       sum += i;
     }
     return sum;
   }

   // 这个函数如果被频繁调用，可能会被 Turbofan 优化
   console.log(calculateSum(1000));
   ```

3. **去优化:** 当 V8 的优化假设失效时，会进行去优化，回退到解释执行或基线代码。

   ```javascript
   function polymorphicFunction(obj) {
     return obj.x + 1;
   }

   let obj1 = { x: 1 };
   let obj2 = { x: "hello" };

   // 前几次调用 `polymorphicFunction`，V8 可能假设 `obj.x` 是数字并进行优化
   console.log(polymorphicFunction(obj1));
   console.log(polymorphicFunction(obj1));

   // 当传入不同类型的对象时，优化假设失效，可能触发去优化
   console.log(polymorphicFunction(obj2));
   ```

4. **On-Stack Replacement (OSR):** 当一个正在执行的循环变得“热”时，V8 可以在不中断程序执行的情况下，将循环内的代码替换为优化后的版本。

   ```javascript
   function longRunningLoop() {
     let counter = 0;
     for (let i = 0; i < 1000000; i++) {
       counter++;
     }
     return counter;
   }

   // 在循环执行过程中，V8 可能会进行 OSR
   console.log(longRunningLoop());
   ```

5. **`eval()`:** `Runtime_ResolvePossiblyDirectEval` 负责处理 `eval()` 函数的调用。

   ```javascript
   let code = "console.log('Hello from eval!');";
   eval(code); // 调用 Runtime_ResolvePossiblyDirectEval
   ```

**代码逻辑推理 (假设输入与输出):**

以 `Runtime_CompileLazy` 为例：

**假设输入:** 一个未编译的 JavaScript 函数对象 `function myFunc() { ... }`。

**输出:**  该函数的 `Code` 对象，表示该函数已经被编译成机器码。

**逻辑:**

1. `Runtime_CompileLazy` 接收一个 `JSFunction` 对象。
2. 检查是否需要进行编译（例如，函数是否已经被编译过）。
3. 调用 `Compiler::Compile` 尝试编译该函数。
4. 如果编译成功，返回编译后的 `Code` 对象。
5. 如果编译失败，返回一个异常对象。

**涉及用户常见的编程错误:**

1. **过度依赖 `eval()`:**  `eval()` 的编译和执行通常比直接编写的代码效率低，并且存在安全风险。过度使用 `eval()` 会导致性能下降。

   ```javascript
   // 不推荐的做法
   let variableName = "message";
   eval(`console.log(${variableName});`);
   ```

2. **编写类型不稳定的代码:**  V8 的优化器依赖于类型推断。编写类型不稳定的代码（例如，频繁改变变量的类型）会导致优化器难以工作，甚至触发去优化。

   ```javascript
   function example(input) {
     let result = 10;
     if (typeof input === 'number') {
       result += input;
     } else if (typeof input === 'string') {
       result += parseInt(input);
     }
     return result;
   }

   console.log(example(5));
   console.log(example("10")); // 类型不稳定
   ```

3. **创建大量小型函数:** 虽然函数式编程鼓励使用小型函数，但过多的非常小的函数可能会增加编译的开销，抵消掉一些性能优势。

4. **编写过于复杂、难以优化的代码:**  某些复杂的代码模式可能会使优化器难以分析和优化。

总而言之，`v8/src/runtime/runtime-compiler.cc` 是 V8 引擎中负责将 JavaScript 代码转换为可执行机器码的关键组件，涉及到多种编译策略和优化技术，直接影响 JavaScript 代码的执行效率。理解其功能有助于开发者编写更高效的 JavaScript 代码。

### 提示词
```
这是目录为v8/src/runtime/runtime-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/asmjs/asm-js.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/compiler.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/arguments-inl.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/shared-function-info.h"

namespace v8::internal {

namespace {
void LogExecution(Isolate* isolate, DirectHandle<JSFunction> function) {
  DCHECK(v8_flags.log_function_events);
  if (!function->has_feedback_vector()) return;
#ifdef V8_ENABLE_LEAPTIERING
  DCHECK(function->IsLoggingRequested(isolate));
  GetProcessWideJSDispatchTable()->ResetTieringRequest(
      function->dispatch_handle(), isolate);
#else
  if (!function->feedback_vector()->log_next_execution()) return;
#endif
  DirectHandle<SharedFunctionInfo> sfi(function->shared(), isolate);
  DirectHandle<String> name = SharedFunctionInfo::DebugName(isolate, sfi);
  DisallowGarbageCollection no_gc;
  Tagged<SharedFunctionInfo> raw_sfi = *sfi;
  std::string event_name = "first-execution";
  CodeKind kind = function->abstract_code(isolate)->kind(isolate);
  // Not adding "-interpreter" for tooling backwards compatiblity.
  if (kind != CodeKind::INTERPRETED_FUNCTION) {
    event_name += "-";
    event_name += CodeKindToString(kind);
  }
  LOG(isolate, FunctionEvent(
                   event_name.c_str(), Cast<Script>(raw_sfi->script())->id(), 0,
                   raw_sfi->StartPosition(), raw_sfi->EndPosition(), *name));
#ifndef V8_ENABLE_LEAPTIERING
  function->feedback_vector()->set_log_next_execution(false);
#endif  // !V8_ENABLE_LEAPTIERING
}
}  // namespace

RUNTIME_FUNCTION(Runtime_CompileLazy) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSFunction> function = args.at<JSFunction>(0);
  StackLimitCheck check(isolate);
  if (V8_UNLIKELY(
          check.JsHasOverflowed(kStackSpaceRequiredForCompilation * KB))) {
    return isolate->StackOverflow();
  }

  DirectHandle<SharedFunctionInfo> sfi(function->shared(), isolate);

  DCHECK(!function->is_compiled(isolate));
#ifdef DEBUG
  if (v8_flags.trace_lazy && sfi->is_compiled()) {
    PrintF("[unoptimized: %s]\n", function->DebugNameCStr().get());
  }
#endif
  IsCompiledScope is_compiled_scope;
  if (!Compiler::Compile(isolate, function, Compiler::KEEP_EXCEPTION,
                         &is_compiled_scope)) {
    return ReadOnlyRoots(isolate).exception();
  }
#ifndef V8_ENABLE_LEAPTIERING
  if (V8_UNLIKELY(v8_flags.log_function_events)) {
    LogExecution(isolate, function);
  }
#endif  // !V8_ENABLE_LEAPTIERING
  DCHECK(function->is_compiled(isolate));
  return function->code(isolate);
}

RUNTIME_FUNCTION(Runtime_InstallBaselineCode) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);
  DirectHandle<SharedFunctionInfo> sfi(function->shared(), isolate);
  DCHECK(sfi->HasBaselineCode());
  {
    if (!V8_ENABLE_LEAPTIERING_BOOL || !function->has_feedback_vector()) {
      IsCompiledScope is_compiled_scope(*sfi, isolate);
      DCHECK(!function->HasAvailableOptimizedCode(isolate));
      DCHECK(!function->has_feedback_vector());
      JSFunction::CreateAndAttachFeedbackVector(isolate, function,
                                                &is_compiled_scope);
    }
    DisallowGarbageCollection no_gc;
    Tagged<Code> baseline_code = sfi->baseline_code(kAcquireLoad);
    function->UpdateCodeKeepTieringRequests(baseline_code);
#ifdef V8_ENABLE_LEAPTIERING
    return baseline_code;
  }
#else
    if V8_LIKELY (!v8_flags.log_function_events) return baseline_code;
  }
  DCHECK(v8_flags.log_function_events);
  LogExecution(isolate, function);
  // LogExecution might allocate, reload the baseline code
  return sfi->baseline_code(kAcquireLoad);
#endif  // V8_ENABLE_LEAPTIERING
}

RUNTIME_FUNCTION(Runtime_InstallSFICode) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);
  {
    DisallowGarbageCollection no_gc;
    Tagged<SharedFunctionInfo> sfi = function->shared();
    DCHECK(sfi->is_compiled());
    Tagged<Code> sfi_code = sfi->GetCode(isolate);
    if (V8_LIKELY(sfi_code->kind() != CodeKind::BASELINE ||
                  function->has_feedback_vector())) {
      function->UpdateCode(sfi_code);
      return sfi_code;
    }
  }
  // This could be the first time we are installing baseline code so we need to
  // ensure that a feedback vectors is allocated.
  IsCompiledScope is_compiled_scope(function->shared(), isolate);
  DCHECK(!function->HasAvailableOptimizedCode(isolate));
  DCHECK(!function->has_feedback_vector());
  JSFunction::CreateAndAttachFeedbackVector(isolate, function,
                                            &is_compiled_scope);
  Tagged<Code> sfi_code = function->shared()->GetCode(isolate);
  function->UpdateCode(sfi_code);
  return sfi_code;
}

#ifdef V8_ENABLE_LEAPTIERING

namespace {

void CompileOptimized(Handle<JSFunction> function, ConcurrencyMode mode,
                      CodeKind target_kind, Isolate* isolate) {
  // Ensure that the tiering request is reset even if compilation fails.
  function->ResetTieringRequests(isolate);

  // As a pre- and post-condition of CompileOptimized, the function *must* be
  // compiled, i.e. the installed InstructionStream object must not be
  // CompileLazy.
  IsCompiledScope is_compiled_scope(function->shared(), isolate);

  if (V8_UNLIKELY(!is_compiled_scope.is_compiled())) {
    StackLimitCheck check(isolate);
    if (check.JsHasOverflowed(kStackSpaceRequiredForCompilation * KB)) {
      return;
    }
    if (!Compiler::Compile(isolate, function, Compiler::KEEP_EXCEPTION,
                           &is_compiled_scope)) {
      return;
    }
  }
  DCHECK(is_compiled_scope.is_compiled());

  // Concurrent optimization runs on another thread, thus no additional gap.
  const int gap =
      IsConcurrent(mode) ? 0 : kStackSpaceRequiredForCompilation * KB;
  StackLimitCheck check(isolate);
  if (check.JsHasOverflowed(gap)) return;

  Compiler::CompileOptimized(isolate, function, mode, target_kind);

  DCHECK(function->is_compiled(isolate));
}

}  // namespace

RUNTIME_FUNCTION(Runtime_StartMaglevOptimizationJob) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSFunction> function = args.at<JSFunction>(0);
  DCHECK(function->IsOptimizationRequested(isolate));
  CompileOptimized(function, ConcurrencyMode::kConcurrent, CodeKind::MAGLEV,
                   isolate);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_StartTurbofanOptimizationJob) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSFunction> function = args.at<JSFunction>(0);
  DCHECK(function->IsOptimizationRequested(isolate));
  CompileOptimized(function, ConcurrencyMode::kConcurrent,
                   CodeKind::TURBOFAN_JS, isolate);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_OptimizeMaglevEager) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSFunction> function = args.at<JSFunction>(0);
  DCHECK(function->IsOptimizationRequested(isolate));
  CompileOptimized(function, ConcurrencyMode::kSynchronous, CodeKind::MAGLEV,
                   isolate);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_OptimizeTurbofanEager) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSFunction> function = args.at<JSFunction>(0);
  DCHECK(function->IsOptimizationRequested(isolate));
  CompileOptimized(function, ConcurrencyMode::kSynchronous,
                   CodeKind::TURBOFAN_JS, isolate);
  return ReadOnlyRoots(isolate).undefined_value();
}

#else

RUNTIME_FUNCTION(Runtime_CompileOptimized) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<JSFunction> function = args.at<JSFunction>(0);

  CodeKind target_kind;
  ConcurrencyMode mode;
  DCHECK(function->has_feedback_vector());
  switch (function->tiering_state()) {
    case TieringState::kRequestMaglev_Synchronous:
      target_kind = CodeKind::MAGLEV;
      mode = ConcurrencyMode::kSynchronous;
      break;
    case TieringState::kRequestMaglev_Concurrent:
      target_kind = CodeKind::MAGLEV;
      mode = ConcurrencyMode::kConcurrent;
      break;
    case TieringState::kRequestTurbofan_Synchronous:
      target_kind = CodeKind::TURBOFAN_JS;
      mode = ConcurrencyMode::kSynchronous;
      break;
    case TieringState::kRequestTurbofan_Concurrent:
      target_kind = CodeKind::TURBOFAN_JS;
      mode = ConcurrencyMode::kConcurrent;
      break;
    case TieringState::kNone:
    case TieringState::kInProgress:
      UNREACHABLE();
  }

  // As a pre- and post-condition of CompileOptimized, the function *must* be
  // compiled, i.e. the installed InstructionStream object must not be
  // CompileLazy.
  IsCompiledScope is_compiled_scope(function->shared(), isolate);
  DCHECK(is_compiled_scope.is_compiled());

  StackLimitCheck check(isolate);
  // Concurrent optimization runs on another thread, thus no additional gap.
  const int gap =
      IsConcurrent(mode) ? 0 : kStackSpaceRequiredForCompilation * KB;
  if (check.JsHasOverflowed(gap)) return isolate->StackOverflow();

  Compiler::CompileOptimized(isolate, function, mode, target_kind);

  DCHECK(function->is_compiled(isolate));
  if (V8_UNLIKELY(v8_flags.log_function_events)) {
    LogExecution(isolate, function);
  }
  return function->code(isolate);
}

RUNTIME_FUNCTION(Runtime_HealOptimizedCodeSlot) {
  SealHandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);

  DCHECK(function->shared()->is_compiled());

  function->feedback_vector()->EvictOptimizedCodeMarkedForDeoptimization(
      isolate, function->shared(), "Runtime_HealOptimizedCodeSlot");
  return function->code(isolate);
}

#endif  // !V8_ENABLE_LEAPTIERING

RUNTIME_FUNCTION(Runtime_FunctionLogNextExecution) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSFunction> js_function = args.at<JSFunction>(0);
  DCHECK(v8_flags.log_function_events);
  LogExecution(isolate, js_function);
  return js_function->code(isolate);
}

// The enum values need to match "AsmJsInstantiateResult" in
// tools/metrics/histograms/enums.xml.
enum AsmJsInstantiateResult {
  kAsmJsInstantiateSuccess = 0,
  kAsmJsInstantiateFail = 1,
};

RUNTIME_FUNCTION(Runtime_InstantiateAsmJs) {
  HandleScope scope(isolate);
  DCHECK_EQ(args.length(), 4);
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);

  Handle<JSReceiver> stdlib;
  if (IsJSReceiver(args[1])) {
    stdlib = args.at<JSReceiver>(1);
  }
  Handle<JSReceiver> foreign;
  if (IsJSReceiver(args[2])) {
    foreign = args.at<JSReceiver>(2);
  }
  Handle<JSArrayBuffer> memory;
  if (IsJSArrayBuffer(args[3])) {
    memory = args.at<JSArrayBuffer>(3);
  }
  DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate);
#if V8_ENABLE_WEBASSEMBLY
  if (shared->HasAsmWasmData()) {
    DirectHandle<AsmWasmData> data(shared->asm_wasm_data(), isolate);
    MaybeHandle<Object> result = AsmJs::InstantiateAsmWasm(
        isolate, shared, data, stdlib, foreign, memory);
    if (!result.is_null()) {
      isolate->counters()->asmjs_instantiate_result()->AddSample(
          kAsmJsInstantiateSuccess);
      return *result.ToHandleChecked();
    }
    if (isolate->has_exception()) {
      // If instantiation fails, we do not propagate the exception but instead
      // fall back to JS execution. The only exception (to that rule) is the
      // termination exception.
      DCHECK(isolate->is_execution_terminating());
      return ReadOnlyRoots{isolate}.exception();
    }
    isolate->counters()->asmjs_instantiate_result()->AddSample(
        kAsmJsInstantiateFail);

    // Remove wasm data, mark as broken for asm->wasm, replace AsmWasmData on
    // the SFI with UncompiledData and set entrypoint to CompileLazy builtin,
    // and return a smi 0 to indicate failure.
    SharedFunctionInfo::DiscardCompiled(isolate, shared);
  }
  shared->set_is_asm_wasm_broken(true);
#endif
  DCHECK_EQ(function->code(isolate), *BUILTIN_CODE(isolate, InstantiateAsmJs));
  function->UpdateCode(*BUILTIN_CODE(isolate, CompileLazy));
  DCHECK(!isolate->has_exception());
  return Smi::zero();
}

namespace {

bool TryGetOptimizedOsrCode(Isolate* isolate, Tagged<FeedbackVector> vector,
                            const interpreter::BytecodeArrayIterator& it,
                            Tagged<Code>* code_out) {
  std::optional<Tagged<Code>> maybe_code =
      vector->GetOptimizedOsrCode(isolate, it.GetSlotOperand(2));
  if (maybe_code.has_value()) {
    *code_out = maybe_code.value();
    return true;
  }
  return false;
}

// Deoptimize all osr'd loops which is in the same outermost loop with deopt
// exit. For example:
//  for (;;) {
//    for (;;) {
//    }  // Type a: loop start < OSR backedge < deopt exit
//    for (;;) {
//      <- Deopt
//      for (;;) {
//      }  // Type b: deopt exit < loop start < OSR backedge
//    } // Type c: loop start < deopt exit < OSR backedge
//  }  // The outermost loop
void DeoptAllOsrLoopsContainingDeoptExit(Isolate* isolate,
                                         Tagged<JSFunction> function,
                                         BytecodeOffset deopt_exit_offset) {
  DisallowGarbageCollection no_gc;
  DCHECK(!deopt_exit_offset.IsNone());

  if (!v8_flags.use_ic ||
      !function->feedback_vector()->maybe_has_optimized_osr_code()) {
    return;
  }
  Handle<BytecodeArray> bytecode_array(
      function->shared()->GetBytecodeArray(isolate), isolate);
  DCHECK(interpreter::BytecodeArrayIterator::IsValidOffset(
      bytecode_array, deopt_exit_offset.ToInt()));

  interpreter::BytecodeArrayIterator it(bytecode_array,
                                        deopt_exit_offset.ToInt());

  Tagged<FeedbackVector> vector = function->feedback_vector();
  Tagged<Code> code;
  base::SmallVector<Tagged<Code>, 8> osr_codes;
  // Visit before the first loop-with-deopt is found
  for (; !it.done(); it.Advance()) {
    // We're only interested in loop ranges.
    if (it.current_bytecode() != interpreter::Bytecode::kJumpLoop) continue;
    // Is the deopt exit contained in the current loop?
    if (base::IsInRange(deopt_exit_offset.ToInt(), it.GetJumpTargetOffset(),
                        it.current_offset())) {
      break;
    }
    // We've reached nesting level 0, i.e. the current JumpLoop concludes a
    // top-level loop, return as the deopt exit is not in any loop. For example:
    //  <- Deopt
    //  for (;;) {
    //  } // The outermost loop
    const int loop_nesting_level = it.GetImmediateOperand(1);
    if (loop_nesting_level == 0) return;
    if (TryGetOptimizedOsrCode(isolate, vector, it, &code)) {
      // Collect type b osr'd loops
      osr_codes.push_back(code);
    }
  }
  if (it.done()) return;
  for (size_t i = 0, size = osr_codes.size(); i < size; i++) {
    // Deoptimize type b osr'd loops
    Deoptimizer::DeoptimizeFunction(function, osr_codes[i]);
  }
  // Visit after the first loop-with-deopt is found
  int last_deopt_in_range_loop_jump_target;
  for (; !it.done(); it.Advance()) {
    // We're only interested in loop ranges.
    if (it.current_bytecode() != interpreter::Bytecode::kJumpLoop) continue;
    // We've reached a new nesting loop in the case of the deopt exit is in a
    // loop whose outermost loop was removed. For example:
    //  for (;;) {
    //    <- Deopt
    //  } // The non-outermost loop
    //  for (;;) {
    //  } // The outermost loop
    if (it.GetJumpTargetOffset() > deopt_exit_offset.ToInt()) break;
    last_deopt_in_range_loop_jump_target = it.GetJumpTargetOffset();
    if (TryGetOptimizedOsrCode(isolate, vector, it, &code)) {
      // Deoptimize type c osr'd loops
      Deoptimizer::DeoptimizeFunction(function, code);
    }
    // We've reached nesting level 0, i.e. the current JumpLoop concludes a
    // top-level loop.
    const int loop_nesting_level = it.GetImmediateOperand(1);
    if (loop_nesting_level == 0) break;
  }
  if (it.done()) return;
  // Revisit from start of the last deopt in range loop to deopt
  for (it.SetOffset(last_deopt_in_range_loop_jump_target);
       it.current_offset() < deopt_exit_offset.ToInt(); it.Advance()) {
    // We're only interested in loop ranges.
    if (it.current_bytecode() != interpreter::Bytecode::kJumpLoop) continue;
    if (TryGetOptimizedOsrCode(isolate, vector, it, &code)) {
      // Deoptimize type a osr'd loops
      Deoptimizer::DeoptimizeFunction(function, code);
    }
  }
}

}  // namespace

RUNTIME_FUNCTION(Runtime_NotifyDeoptimized) {
  HandleScope scope(isolate);
  DCHECK_EQ(0, args.length());
  Deoptimizer* deoptimizer = Deoptimizer::Grab(isolate);
  DCHECK(CodeKindCanDeoptimize(deoptimizer->compiled_code()->kind()));
  DCHECK(AllowGarbageCollection::IsAllowed());
  DCHECK(isolate->context().is_null());

  TimerEventScope<TimerEventDeoptimizeCode> timer(isolate);
  TRACE_EVENT0("v8", "V8.DeoptimizeCode");
  DirectHandle<JSFunction> function = deoptimizer->function();
  // For OSR the optimized code isn't installed on the function, so get the
  // code object from deoptimizer.
  DirectHandle<Code> optimized_code = deoptimizer->compiled_code();
  const DeoptimizeKind deopt_kind = deoptimizer->deopt_kind();
  const DeoptimizeReason deopt_reason =
      deoptimizer->GetDeoptInfo().deopt_reason;

  // TODO(turbofan): We currently need the native context to materialize
  // the arguments object, but only to get to its map.
  isolate->set_context(deoptimizer->function()->native_context());

  // Make sure to materialize objects before causing any allocation.
  deoptimizer->MaterializeHeapObjects();
  const BytecodeOffset deopt_exit_offset =
      deoptimizer->bytecode_offset_in_outermost_frame();
  delete deoptimizer;

  // Ensure the context register is updated for materialized objects.
  JavaScriptStackFrameIterator top_it(isolate);
  JavaScriptFrame* top_frame = top_it.frame();
  isolate->set_context(Cast<Context>(top_frame->context()));

  // Lazy deopts don't invalidate the underlying optimized code since the code
  // object itself is still valid (as far as we know); the called function
  // caused the deopt, not the function we're currently looking at.
  if (deopt_kind == DeoptimizeKind::kLazy) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  // Some eager deopts also don't invalidate InstructionStream (e.g. when
  // preparing for OSR from Maglev to Turbofan).
  if (IsDeoptimizationWithoutCodeInvalidation(deopt_reason)) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  // Non-OSR'd code is deoptimized unconditionally. If the deoptimization occurs
  // inside the outermost loop containning a loop that can trigger OSR
  // compilation, we remove the OSR code, it will avoid hit the out of date OSR
  // code and soon later deoptimization.
  //
  // For OSR'd code, we keep the optimized code around if deoptimization occurs
  // outside the outermost loop containing the loop that triggered OSR
  // compilation. The reasoning is that OSR is intended to speed up the
  // long-running loop; so if the deoptimization occurs outside this loop it is
  // still worth jumping to the OSR'd code on the next run. The reduced cost of
  // the loop should pay for the deoptimization costs.
  const BytecodeOffset osr_offset = optimized_code->osr_offset();
  if (osr_offset.IsNone()) {
    Deoptimizer::DeoptimizeFunction(*function, *optimized_code);
    DeoptAllOsrLoopsContainingDeoptExit(isolate, *function, deopt_exit_offset);
  } else if (deopt_reason != DeoptimizeReason::kOSREarlyExit &&
             Deoptimizer::DeoptExitIsInsideOsrLoop(
                 isolate, *function, deopt_exit_offset, osr_offset)) {
    Deoptimizer::DeoptimizeFunction(*function, *optimized_code);
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_ObserveNode) {
  // The %ObserveNode intrinsic only tracks the changes to an observed node in
  // code compiled by TurboFan.
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<Object> obj = args.at(0);
  return *obj;
}

RUNTIME_FUNCTION(Runtime_VerifyType) {
  // %VerifyType has no effect in the interpreter.
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<Object> obj = args.at(0);
  return *obj;
}

RUNTIME_FUNCTION(Runtime_CheckTurboshaftTypeOf) {
  // %CheckTurboshaftTypeOf has no effect in the interpreter.
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  DirectHandle<Object> obj = args.at(0);
  return *obj;
}

namespace {

void GetOsrOffsetAndFunctionForOSR(Isolate* isolate, BytecodeOffset* osr_offset,
                                   Handle<JSFunction>* function) {
  DCHECK(osr_offset->IsNone());
  DCHECK(function->is_null());

  // Determine the frame that triggered the OSR request.
  JavaScriptStackFrameIterator it(isolate);
  UnoptimizedJSFrame* frame = UnoptimizedJSFrame::cast(it.frame());
  DCHECK_IMPLIES(frame->is_interpreted(),
                 frame->LookupCode()->is_interpreter_trampoline_builtin());
  DCHECK_IMPLIES(frame->is_baseline(),
                 frame->LookupCode()->kind() == CodeKind::BASELINE);

  *osr_offset = BytecodeOffset(frame->GetBytecodeOffset());
  *function = handle(frame->function(), isolate);

  DCHECK(!osr_offset->IsNone());
  DCHECK((*function)->shared()->HasBytecodeArray());
}

Tagged<Object> CompileOptimizedOSR(Isolate* isolate,
                                   Handle<JSFunction> function,
                                   CodeKind min_opt_level,
                                   BytecodeOffset osr_offset) {
  ConcurrencyMode mode =
      V8_LIKELY(isolate->concurrent_recompilation_enabled() &&
                v8_flags.concurrent_osr)
          ? ConcurrencyMode::kConcurrent
          : ConcurrencyMode::kSynchronous;

  if (V8_UNLIKELY(isolate->EfficiencyModeEnabledForTiering() &&
                  min_opt_level == CodeKind::MAGLEV)) {
    mode = ConcurrencyMode::kSynchronous;
  }

  Handle<Code> result;
  if (!Compiler::CompileOptimizedOSR(
           isolate, function, osr_offset, mode,
           (maglev::IsMaglevOsrEnabled() && min_opt_level == CodeKind::MAGLEV)
               ? CodeKind::MAGLEV
               : CodeKind::TURBOFAN_JS)
           .ToHandle(&result) ||
      result->marked_for_deoptimization()) {
    // An empty result can mean one of two things:
    // 1) we've started a concurrent compilation job - everything is fine.
    // 2) synchronous compilation failed for some reason.

#ifndef V8_ENABLE_LEAPTIERING
    if (!function->HasAttachedOptimizedCode(isolate)) {
      function->UpdateCode(function->shared()->GetCode(isolate));
    }
#endif  // V8_ENABLE_LEAPTIERING

    return Smi::zero();
  }

  DCHECK(!result.is_null());
  DCHECK(result->is_turbofanned() || result->is_maglevved());
  DCHECK(CodeKindIsOptimizedJSFunction(result->kind()));

#ifdef DEBUG
  Tagged<DeoptimizationData> data =
      Cast<DeoptimizationData>(result->deoptimization_data());
  DCHECK_EQ(BytecodeOffset(data->OsrBytecodeOffset().value()), osr_offset);
  DCHECK_GE(data->OsrPcOffset().value(), 0);
#endif  // DEBUG

  // First execution logging happens in LogOrTraceOptimizedOSREntry
  return *result;
}

}  // namespace

RUNTIME_FUNCTION(Runtime_CompileOptimizedOSR) {
  HandleScope handle_scope(isolate);
  DCHECK_EQ(0, args.length());
  DCHECK(v8_flags.use_osr);

  BytecodeOffset osr_offset = BytecodeOffset::None();
  Handle<JSFunction> function;
  GetOsrOffsetAndFunctionForOSR(isolate, &osr_offset, &function);

  return CompileOptimizedOSR(isolate, function, CodeKind::MAGLEV, osr_offset);
}

namespace {

Tagged<Object> CompileOptimizedOSRFromMaglev(Isolate* isolate,
                                             Handle<JSFunction> function,
                                             BytecodeOffset osr_offset) {
  // This path is only relevant for tests (all production configurations enable
  // concurrent OSR). It's quite subtle, if interested read on:
  if (V8_UNLIKELY(!isolate->concurrent_recompilation_enabled() ||
                  !v8_flags.concurrent_osr)) {
    // - Synchronous Turbofan compilation may trigger lazy deoptimization (e.g.
    //   through compilation dependency finalization actions).
    // - Maglev (currently) disallows marking an opcode as both can_lazy_deopt
    //   and can_eager_deopt.
    // - Maglev's JumpLoop opcode (the logical caller of this runtime function)
    //   is marked as can_eager_deopt since OSR'ing to Turbofan involves
    //   deoptimizing to Ignition under the hood.
    // - Thus this runtime function *must not* trigger a lazy deopt, and
    //   therefore cannot trigger synchronous Turbofan compilation (see above).
    //
    // We solve this synchronous OSR case by bailing out early to Ignition, and
    // letting it handle OSR. How do we trigger the early bailout? Returning
    // any non-null InstructionStream from this function triggers the deopt in
    // JumpLoop.
    if (v8_flags.trace_osr) {
      CodeTracer::Scope scope(isolate->GetCodeTracer());
      PrintF(scope.file(),
             "[OSR - Tiering from Maglev to Turbofan failed because "
             "concurrent_osr is disabled. function: %s, osr offset: %d]\n",
             function->DebugNameCStr().get(), osr_offset.ToInt());
    }
    return function->code(isolate);
  }

  if (V8_UNLIKELY(isolate->EfficiencyModeEnabledForTiering() ||
                  isolate->BatterySaverModeEnabled())) {
    function->feedback_vector()->reset_osr_urgency();
    function->SetInterruptBudget(isolate);
    return Smi::zero();
  }

  return CompileOptimizedOSR(isolate, function, CodeKind::TURBOFAN_JS,
                             osr_offset);
}

}  // namespace

RUNTIME_FUNCTION(Runtime_CompileOptimizedOSRFromMaglev) {
  HandleScope handle_scope(isolate);
  DCHECK_EQ(1, args.length());
  DCHECK(v8_flags.use_osr);

  const BytecodeOffset osr_offset(args.positive_smi_value_at(0));

  JavaScriptStackFrameIterator it(isolate);
  MaglevFrame* frame = MaglevFrame::cast(it.frame());
  DCHECK_EQ(frame->LookupCode()->kind(), CodeKind::MAGLEV);
  Handle<JSFunction> function = handle(frame->function(), isolate);

  return CompileOptimizedOSRFromMaglev(isolate, function, osr_offset);
}

RUNTIME_FUNCTION(Runtime_CompileOptimizedOSRFromMaglevInlined) {
  HandleScope handle_scope(isolate);
  DCHECK_EQ(2, args.length());
  DCHECK(v8_flags.use_osr);

  const BytecodeOffset osr_offset(args.positive_smi_value_at(0));
  Handle<JSFunction> function = args.at<JSFunction>(1);

  JavaScriptStackFrameIterator it(isolate);
  MaglevFrame* frame = MaglevFrame::cast(it.frame());
  DCHECK_EQ(frame->LookupCode()->kind(), CodeKind::MAGLEV);

  if (*function != frame->function()) {
    // We are OSRing an inlined function. Mark the top frame one for
    // optimization.
    if (!frame->function()->ActiveTierIsTurbofan(isolate)) {
      isolate->tiering_manager()->MarkForTurboFanOptimization(
          frame->function());
    }
  }

  return CompileOptimizedOSRFromMaglev(isolate, function, osr_offset);
}

RUNTIME_FUNCTION(Runtime_LogOrTraceOptimizedOSREntry) {
  HandleScope handle_scope(isolate);
  DCHECK_EQ(0, args.length());
  CHECK(v8_flags.trace_osr || v8_flags.log_function_events);

  BytecodeOffset osr_offset = BytecodeOffset::None();
  Handle<JSFunction> function;
  GetOsrOffsetAndFunctionForOSR(isolate, &osr_offset, &function);

  if (v8_flags.trace_osr) {
    PrintF(CodeTracer::Scope{isolate->GetCodeTracer()}.file(),
           "[OSR - entry. function: %s, osr offset: %d]\n",
           function->DebugNameCStr().get(), osr_offset.ToInt());
  }
#ifndef V8_ENABLE_LEAPTIERING
  if (V8_UNLIKELY(v8_flags.log_function_events)) {
    LogExecution(isolate, function);
  }
#endif  // !V8_ENABLE_LEAPTIERING
  return ReadOnlyRoots(isolate).undefined_value();
}

static Tagged<Object> CompileGlobalEval(Isolate* isolate,
                                        Handle<i::Object> source_object,
                                        Handle<SharedFunctionInfo> outer_info,
                                        LanguageMode language_mode,
                                        int eval_scope_info_index,
                                        int eval_position) {
  Handle<NativeContext> native_context = isolate->native_context();

  // Check if native context allows code generation from
  // strings. Throw an exception if it doesn't.
  MaybeHandle<String> source;
  bool unknown_object;
  std::tie(source, unknown_object) = Compiler::ValidateDynamicCompilationSource(
      isolate, native_context, source_object);
  // If the argument is an unhandled string time, bounce to GlobalEval.
  if (unknown_object) {
    return native_context->global_eval_fun();
  }
  if (source.is_null()) {
    Handle<Object> error_message =
        native_context->ErrorMessageForCodeGenerationFromStrings();
    Handle<Object> error;
    MaybeHandle<Object> maybe_error = isolate->factory()->NewEvalError(
        MessageTemplate::kCodeGenFromStrings, error_message);
    if (maybe_error.ToHandle(&error)) isolate->Throw(*error);
    return ReadOnlyRoots(isolate).exception();
  }

  // Deal with a normal eval call with a string argument. Compile it
  // and return the compiled function bound in the local context.
  static const ParseRestriction restriction = NO_PARSE_RESTRICTION;
  Handle<JSFunction> compiled;
  Handle<Context> context(isolate->context(), isolate);
  if (!Is<NativeContext>(*context) && v8_flags.reuse_scope_infos) {
    Tagged<WeakFixedArray> array = Cast<Script>(outer_info->script())->infos();
    Tagged<ScopeInfo> stored_info;
    if (array->get(eval_scope_info_index)
            .GetHeapObjectIfWeak(isolate, &stored_info)) {
      CHECK_EQ(stored_info, context->scope_info());
    } else {
      array->set(eval_scope_info_index, MakeWeak(context->scope_info()));
    }
  }
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, compiled,
      Compiler::GetFunctionFromEval(source.ToHandleChecked(), outer_info,
                                    context, language_mode, restriction,
                                    kNoSourcePosition, eval_position),
      ReadOnlyRoots(isolate).exception());
  return *compiled;
}

RUNTIME_FUNCTION(Runtime_ResolvePossiblyDirectEval) {
  HandleScope scope(isolate);
  DCHECK_EQ(6, args.length());

  DirectHandle<Object> callee = args.at(0);

  // If "eval" didn't refer to the original GlobalEval, it's not a
  // direct call to eval.
  if (*callee != isolate->native_context()->global_eval_fun()) {
    return *callee;
  }

  DCHECK(is_valid_language_mode(args.smi_value_at(3)));
  LanguageMode language_mode = static_cast<LanguageMode>(args.smi_value_at(3));
  Handle<SharedFunctionInfo> outer_info(args.at<JSFunction>(2)->shared(),
                                        isolate);
  return CompileGlobalEval(isolate, args.at<Object>(1), outer_info,
                           language_mode, args.smi_value_at(4),
                           args.smi_value_at(5));
}

}  // namespace v8::internal
```