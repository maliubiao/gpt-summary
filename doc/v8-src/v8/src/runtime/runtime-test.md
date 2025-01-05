Response: The user wants a summary of the functionality of the C++ source code file `v8/src/runtime/runtime-test.cc`. They also want to know how this code relates to JavaScript and see examples of the connection.

**Plan:**

1. **Identify the core purpose:** The filename `runtime-test.cc` suggests this file contains runtime functions primarily used for testing V8's functionality.
2. **Analyze included headers:**  The included headers provide clues about the areas of V8 being tested (e.g., `v8-function.h`, `v8-profiler.h`, `compiler.h`, `deoptimizer.h`, `heap/heap-layout-inl.h`, `objects/`).
3. **Examine the defined `RUNTIME_FUNCTION` macros:** These are the exported functions that can be called from JavaScript (via the `%` or `%%` syntax). Categorize these functions based on their apparent functionality.
4. **Infer JavaScript connections:** For each category of runtime functions, think about the corresponding JavaScript features or internal mechanisms they relate to.
5. **Provide JavaScript examples:**  Use the `%` or `%%` syntax to illustrate how these runtime functions can be called from JavaScript and what they might be used for.
6. **Address the "part 1 of 2" instruction:**  Acknowledge that this is the first part and that more functionality might be present in the second part.
这是V8 JavaScript引擎中的一个C++源代码文件，主要功能是**提供了一系列用于测试和调试V8运行时环境的内置函数**。这些函数通常以`Runtime_`开头，并且可以通过特定的JavaScript语法（例如 `%FunctionName` 或 `%%FunctionName`）在JavaScript代码中直接调用。

这些测试用的运行时函数涵盖了V8引擎的多个核心方面，包括：

* **内存管理和堆操作:**  例如，模拟新生代空间填满 (`Runtime_SimulateNewspaceFull`)，获取无法被探测的对象 (`Runtime_GetUndetectable`)，检查对象是否在老生代空间 (`Runtime_InLargeObjectSpace`) 或新生代空间 (`Runtime_InYoungGeneration`)。
* **代码优化和去优化:** 例如，强制去优化函数 (`Runtime_DeoptimizeFunction`, `Runtime_DeoptimizeNow`)，触发函数在下次调用时进行优化 (`Runtime_OptimizeFunctionOnNextCall`, `Runtime_OptimizeMaglevOnNextCall`, `Runtime_OptimizeOsr`)，获取函数的优化状态 (`Runtime_GetOptimizationStatus`)，以及控制优化流程（例如，禁用优化最终化 `Runtime_DisableOptimizationFinalization`，等待后台优化完成 `Runtime_WaitForBackgroundOptimization`）。
* **字符串操作:** 例如，构建不同类型的字符串 (`Runtime_ConstructConsString`, `Runtime_ConstructSlicedString`, `Runtime_ConstructInternalizedString`)，检查字符串是否是扁平的 (`Runtime_StringIsFlat`)。
* **调试和跟踪:** 例如，打印对象信息 (`Runtime_DebugPrint`, `Runtime_DebugPrintPtr`)，打印堆栈跟踪 (`Runtime_DebugTrace`)，设置断点 (`Runtime_SystemBreak`)，以及模拟 `abort()` 调用 (`Runtime_Abort`, `Runtime_AbortJS`).
* **性能分析:** 例如， 清除巨型 Stub 缓存 (`Runtime_ClearMegamorphicStubCache`)。
* **正则表达式:** 例如，检查正则表达式是否有字节码或本地代码 (`Runtime_RegexpHasBytecode`, `Runtime_RegexpHasNativeCode`)，获取正则表达式的类型标签 (`Runtime_RegexpTypeTag`)。
* **数组和对象属性:** 例如，检查对象是否具有特定类型的元素 (`Runtime_HasFastElements`, `Runtime_HasDoubleElements`, `Runtime_HasDictionaryElements` 等) 或属性 (`Runtime_HasFastProperties`)。
* **保护器（Protectors）状态:**  例如，检查各种内建对象的原型链是否完整 (`Runtime_IsConcatSpreadableProtector`, `Runtime_TypedArraySpeciesProtector` 等)。
* **快照序列化和反序列化:**  用于测试快照功能 (`Runtime_SerializeDeserializeNow`).
* **与其他V8内部组件交互:** 例如，获取抽象模块的源代码函数 (`Runtime_GetAbstractModuleSource`)。

**与 JavaScript 的关系及举例说明：**

该文件中的运行时函数是V8引擎内部实现的一部分，但它们通常不会直接暴露给普通的JavaScript代码使用。  然而，V8为了进行内部测试、调试以及提供一些特殊的开发者工具，允许通过特定的语法从JavaScript中调用这些函数。

例如：

1. **代码优化测试:**

   ```javascript
   function add(a, b) {
     return a + b;
   }

   // 准备函数进行优化
   %PrepareFunctionForOptimization(add);
   // 触发函数在下次调用时进行 TurboFan 优化（或者 Maglev，取决于 V8 配置）
   %OptimizeFunctionOnNextCall(add);

   add(1, 2); // 触发优化
   ```
   在这个例子中，`%PrepareFunctionForOptimization` 和 `%OptimizeFunctionOnNextCall` 都是 `runtime-test.cc` 中定义的运行时函数，用于控制V8的优化流程，方便测试代码在不同优化阶段的行为。

2. **调试和对象检查:**

   ```javascript
   let obj = { x: 1, y: 2 };
   %DebugPrint(obj); // 打印 obj 的内部表示，用于调试
   console.log(%HasFastProperties(obj)); // 检查对象是否具有快速属性
   ```
   `%DebugPrint` 和 `%HasFastProperties` 也是 `runtime-test.cc` 中定义的运行时函数，用于输出调试信息或检查对象的内部状态。

3. **内存管理测试:**

   ```javascript
   // 模拟新生代空间已满，用于测试垃圾回收机制
   %SimulateNewspaceFull();
   ```
   `%SimulateNewspaceFull`  是一个在 `runtime-test.cc` 中定义的运行时函数，用于人为地触发某些内存状况，以便测试V8的垃圾回收器。

**总结:**

`v8/src/runtime/runtime-test.cc` 是一个关键的测试基础设施文件，它定义了大量的内置函数，这些函数允许V8的开发者和测试框架深入到引擎的内部运作，控制执行流程，检查内部状态，模拟各种场景，从而确保V8引擎的正确性和性能。虽然普通JavaScript开发者不会直接使用这些函数，但了解它们的存在和功能有助于理解V8引擎的内部机制。

由于这是第一部分，可以预期第二部分会包含更多类似的运行时测试函数，或者与这里列出的功能相关的其他方面。

Prompt: 
```
这是目录为v8/src/runtime/runtime-test.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>

#include <iomanip>
#include <memory>

#include "include/v8-function.h"
#include "include/v8-profiler.h"
#include "src/api/api-inl.h"
#include "src/base/macros.h"
#include "src/base/numbers/double.h"
#include "src/codegen/compiler.h"
#include "src/codegen/pending-optimization-table.h"
#include "src/compiler-dispatcher/lazy-compile-dispatcher.h"
#include "src/compiler-dispatcher/optimizing-compile-dispatcher.h"
#include "src/debug/debug-evaluate.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/arguments-inl.h"
#include "src/execution/frames-inl.h"
#include "src/execution/frames.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/protectors-inl.h"
#include "src/execution/tiering-manager.h"
#include "src/flags/flags.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/heap/pretenuring-handler-inl.h"
#include "src/ic/stub-cache.h"
#include "src/objects/bytecode-array.h"
#include "src/objects/js-collection-inl.h"
#include "src/profiler/heap-profiler.h"
#include "src/utils/utils.h"
#ifdef V8_ENABLE_MAGLEV
#include "src/maglev/maglev-concurrent-dispatcher.h"
#endif  // V8_ENABLE_MAGLEV
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-atomics-synchronization-inl.h"
#include "src/objects/js-function-inl.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/smi.h"
#include "src/profiler/heap-snapshot-generator.h"
#include "src/regexp/regexp.h"
#include "src/snapshot/snapshot.h"

#ifdef V8_ENABLE_MAGLEV
#include "src/maglev/maglev.h"
#endif  // V8_ENABLE_MAGLEV

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-engine.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

namespace {
// This function is mostly used instead of (D)CHECKs for functions exposed to
// fuzzers. TODO(353685107): consider being more permissive in functions using
// this. For example, for fuzzing we could probably allow excess arguments,
V8_WARN_UNUSED_RESULT Tagged<Object> CrashUnlessFuzzing(Isolate* isolate) {
  CHECK(v8_flags.fuzzing);
  return ReadOnlyRoots(isolate).undefined_value();
}

V8_WARN_UNUSED_RESULT bool CrashUnlessFuzzingReturnFalse(Isolate* isolate) {
  CHECK(v8_flags.fuzzing);
  return false;
}

V8_WARN_UNUSED_RESULT bool CheckMarkedForManualOptimization(
    Isolate* isolate, Tagged<JSFunction> function) {
  if (!ManualOptimizationTable::IsMarkedForManualOptimization(isolate,
                                                              function)) {
    PrintF("Error: Function ");
    ShortPrint(function);
    PrintF(
        " should be prepared for optimization with "
        "%%PrepareFunctionForOptimization before  "
        "%%OptimizeFunctionOnNextCall / %%OptimizeMaglevOnNextCall / "
        "%%OptimizeOsr ");
    return false;
  }
  return true;
}

// Returns |value| unless correctness-fuzzer-supressions is enabled,
// otherwise returns undefined_value.
V8_WARN_UNUSED_RESULT Tagged<Object> ReturnFuzzSafe(Tagged<Object> value,
                                                    Isolate* isolate) {
  return v8_flags.correctness_fuzzer_suppressions
             ? ReadOnlyRoots(isolate).undefined_value()
             : value;
}

// Assert that the given argument is a number within the Int32 range
// and convert it to int32_t.  If the argument is not an Int32 we crash if not
// in fuzzing mode.
#define CONVERT_INT32_ARG_FUZZ_SAFE(name, index)                  \
  if (!IsNumber(args[index])) return CrashUnlessFuzzing(isolate); \
  int32_t name = 0;                                               \
  if (!Object::ToInt32(args[index], &name)) return CrashUnlessFuzzing(isolate);

// Cast the given object to a boolean and store it in a variable with
// the given name.  If the object is not a boolean we crash if not in
// fuzzing mode.
#define CONVERT_BOOLEAN_ARG_FUZZ_SAFE(name, index)                 \
  if (!IsBoolean(args[index])) return CrashUnlessFuzzing(isolate); \
  bool name = IsTrue(args[index], isolate);

bool IsAsmWasmFunction(Isolate* isolate, Tagged<JSFunction> function) {
  DisallowGarbageCollection no_gc;
#if V8_ENABLE_WEBASSEMBLY
  // For simplicity we include invalid asm.js functions whose code hasn't yet
  // been updated to CompileLazy but is still the InstantiateAsmJs builtin.
  return function->shared()->HasAsmWasmData() ||
         function->code(isolate)->builtin_id() == Builtin::kInstantiateAsmJs;
#else
  return false;
#endif  // V8_ENABLE_WEBASSEMBLY
}

}  // namespace

RUNTIME_FUNCTION(Runtime_ClearMegamorphicStubCache) {
  HandleScope scope(isolate);
  isolate->load_stub_cache()->Clear();
  isolate->store_stub_cache()->Clear();
  isolate->define_own_stub_cache()->Clear();
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_ConstructDouble) {
  HandleScope scope(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  DCHECK_EQ(args.length(), 2);
  uint32_t hi = NumberToUint32(args[0]);
  uint32_t lo = NumberToUint32(args[1]);
  uint64_t result = (static_cast<uint64_t>(hi) << 32) | lo;
  return *isolate->factory()->NewNumber(base::uint64_to_double(result));
}

RUNTIME_FUNCTION(Runtime_StringIsFlat) {
  HandleScope scope(isolate);
  DCHECK_EQ(args.length(), 1);
  DirectHandle<String> s = args.at<String>(0);
  return isolate->heap()->ToBoolean(s->IsFlat());
}

RUNTIME_FUNCTION(Runtime_ConstructConsString) {
  HandleScope scope(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  DCHECK_EQ(args.length(), 2);
  DirectHandle<String> left = args.at<String>(0);
  DirectHandle<String> right = args.at<String>(1);

  const bool is_one_byte =
      left->IsOneByteRepresentation() && right->IsOneByteRepresentation();
  const int length = left->length() + right->length();
  return *isolate->factory()->NewConsString(left, right, length, is_one_byte);
}

RUNTIME_FUNCTION(Runtime_ConstructSlicedString) {
  HandleScope scope(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  DCHECK_EQ(args.length(), 2);
  Handle<String> string = args.at<String>(0);
  int index = args.smi_value_at(1);

  CHECK_LT(index, string->length());

  DirectHandle<String> sliced_string =
      isolate->factory()->NewSubString(string, index, string->length());
  CHECK(IsSlicedString(*sliced_string));
  return *sliced_string;
}

RUNTIME_FUNCTION(Runtime_ConstructInternalizedString) {
  HandleScope scope(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  DCHECK_EQ(args.length(), 1);
  Handle<String> string = args.at<String>(0);
  CHECK(string->IsOneByteRepresentation());
  DirectHandle<String> internalized =
      isolate->factory()->InternalizeString(string);
  CHECK(IsInternalizedString(*string));
  return *internalized;
}

RUNTIME_FUNCTION(Runtime_ConstructThinString) {
  HandleScope scope(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  DCHECK_EQ(args.length(), 1);
  Handle<String> string = args.at<String>(0);
  if (!IsConsString(*string)) {
    string = isolate->factory()->NewConsString(
        isolate->factory()->empty_string(), string, string->length(),
        string->IsOneByteRepresentation(),
        // Pretenure to ensure it stays thin.
        AllocationType::kOld);
  }
  CHECK(IsConsString(*string));
  DirectHandle<String> internalized =
      isolate->factory()->InternalizeString(string);
  CHECK_NE(*internalized, *string);
  CHECK(IsThinString(*string));
  return *string;
}

RUNTIME_FUNCTION(Runtime_DeoptimizeFunction) {
  HandleScope scope(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }

  Handle<Object> function_object = args.at(0);
  if (!IsJSFunction(*function_object)) return CrashUnlessFuzzing(isolate);
  auto function = Cast<JSFunction>(function_object);

  if (function->HasAttachedOptimizedCode(isolate)) {
    Deoptimizer::DeoptimizeFunction(*function);
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_DeoptimizeNow) {
  HandleScope scope(isolate);

  Handle<JSFunction> function;

  // Find the JavaScript function on the top of the stack.
  JavaScriptStackFrameIterator it(isolate);
  if (!it.done()) function = handle(it.frame()->function(), isolate);
  if (function.is_null()) return CrashUnlessFuzzing(isolate);

  if (function->HasAttachedOptimizedCode(isolate)) {
    Deoptimizer::DeoptimizeFunction(*function);
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_LeakHole) {
  HandleScope scope(isolate);

  // TODO(chromium:1445008): once we have multiple different hole values, we
  // could make this function take a number as argument and return the nth hole
  // value, or a random hole if the argument is undefined.
  return ReadOnlyRoots(isolate).the_hole_value();
}

RUNTIME_FUNCTION(Runtime_RunningInSimulator) {
  SealHandleScope shs(isolate);
#if defined(USE_SIMULATOR)
  return ReadOnlyRoots(isolate).true_value();
#else
  return ReadOnlyRoots(isolate).false_value();
#endif
}

RUNTIME_FUNCTION(Runtime_RuntimeEvaluateREPL) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsString(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<String> source = args.at<String>(0);
  Handle<Object> result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, result,
      DebugEvaluate::Global(isolate, source,
                            debug::EvaluateGlobalMode::kDefault,
                            REPLMode::kYes));

  return *result;
}

RUNTIME_FUNCTION(Runtime_ICsAreEnabled) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(v8_flags.use_ic);
}

RUNTIME_FUNCTION(Runtime_IsConcurrentRecompilationSupported) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      isolate->concurrent_recompilation_enabled());
}

RUNTIME_FUNCTION(Runtime_IsAtomicsWaitAllowed) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(isolate->allow_atomics_wait());
}

namespace {

bool CanOptimizeFunction(CodeKind target_kind, Handle<JSFunction> function,
                         Isolate* isolate, IsCompiledScope* is_compiled_scope) {
  // The following conditions were lifted (in part) from the DCHECK inside
  // JSFunction::MarkForOptimization().

  // If function isn't compiled, compile it now.
  if (!is_compiled_scope->is_compiled() &&
      !Compiler::Compile(isolate, function, Compiler::CLEAR_EXCEPTION,
                         is_compiled_scope)) {
    return CrashUnlessFuzzingReturnFalse(isolate);
  }

  if (target_kind == CodeKind::TURBOFAN_JS && !v8_flags.turbofan) return false;
  if (target_kind == CodeKind::MAGLEV && !maglev::IsMaglevEnabled()) {
    return false;
  }

  if (function->shared()->optimization_disabled() &&
      function->shared()->disabled_optimization_reason() ==
          BailoutReason::kNeverOptimize) {
    return CrashUnlessFuzzingReturnFalse(isolate);
  }

  if (IsAsmWasmFunction(isolate, *function)) {
    return CrashUnlessFuzzingReturnFalse(isolate);
  }

  if (v8_flags.testing_d8_test_runner) {
    if (!CheckMarkedForManualOptimization(isolate, *function)) {
      return CrashUnlessFuzzingReturnFalse(isolate);
    }
  }

  if (function->is_compiled(isolate) &&
      !function->HasAvailableCodeKind(isolate,
                                      CodeKind::INTERPRETED_FUNCTION)) {
    return CrashUnlessFuzzingReturnFalse(isolate);
  }

  if (function->HasAvailableCodeKind(isolate, target_kind) ||
      function->HasAvailableHigherTierCodeThan(isolate, target_kind) ||
      function->tiering_in_progress()) {
    DCHECK(function->HasAttachedOptimizedCode(isolate) ||
           function->ChecksTieringState(isolate));
    return false;
  }

  return true;
}

Tagged<Object> OptimizeFunctionOnNextCall(RuntimeArguments& args,
                                          Isolate* isolate,
                                          CodeKind target_kind) {
  if (args.length() != 1 && args.length() != 2) {
    return CrashUnlessFuzzing(isolate);
  }

  Handle<Object> function_object = args.at(0);
  if (!IsJSFunction(*function_object)) return CrashUnlessFuzzing(isolate);
  Handle<JSFunction> function = Cast<JSFunction>(function_object);

  IsCompiledScope is_compiled_scope(
      function->shared()->is_compiled_scope(isolate));
  if (!CanOptimizeFunction(target_kind, function, isolate,
                           &is_compiled_scope)) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  ConcurrencyMode concurrency_mode = ConcurrencyMode::kSynchronous;
  if (args.length() == 2) {
    Handle<Object> type = args.at(1);
    if (!IsString(*type)) return CrashUnlessFuzzing(isolate);
    if (Cast<String>(type)->IsOneByteEqualTo(
            base::StaticCharVector("concurrent")) &&
        isolate->concurrent_recompilation_enabled()) {
      concurrency_mode = ConcurrencyMode::kConcurrent;
    }
  }

  // This function may not have been lazily compiled yet, even though its shared
  // function has.
  if (!function->is_compiled(isolate)) {
    DCHECK(function->shared()->HasBytecodeArray());
    Tagged<Code> code = *BUILTIN_CODE(isolate, InterpreterEntryTrampoline);
    if (function->shared()->HasBaselineCode()) {
      code = function->shared()->baseline_code(kAcquireLoad);
    }
    function->UpdateCode(code);
  }

  TraceManualRecompile(*function, target_kind, concurrency_mode);
  JSFunction::EnsureFeedbackVector(isolate, function, &is_compiled_scope);
  function->RequestOptimization(isolate, target_kind, concurrency_mode);

  return ReadOnlyRoots(isolate).undefined_value();
}

bool EnsureCompiledAndFeedbackVector(Isolate* isolate,
                                     Handle<JSFunction> function,
                                     IsCompiledScope* is_compiled_scope) {
  *is_compiled_scope =
      function->shared()->is_compiled_scope(function->GetIsolate());

  // If function isn't compiled, compile it now.
  if (!is_compiled_scope->is_compiled()) {
    // Check function allows lazy compilation.
    DCHECK(function->shared()->allows_lazy_compilation());
    if (!Compiler::Compile(isolate, function, Compiler::CLEAR_EXCEPTION,
                           is_compiled_scope)) {
      return false;
    }
  }

  // Ensure function has a feedback vector to hold type feedback for
  // optimization.
  if (!function->shared()->HasFeedbackMetadata()) {
    return false;
  }
  JSFunction::EnsureFeedbackVector(isolate, function, is_compiled_scope);
  return true;
}

}  // namespace

RUNTIME_FUNCTION(Runtime_CompileBaseline) {
  HandleScope scope(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<Object> function_object = args.at(0);
  if (!IsJSFunction(*function_object)) return CrashUnlessFuzzing(isolate);
  Handle<JSFunction> function = Cast<JSFunction>(function_object);

  IsCompiledScope is_compiled_scope =
      function->shared(isolate)->is_compiled_scope(isolate);

  if (!function->shared(isolate)->IsUserJavaScript()) {
    return CrashUnlessFuzzing(isolate);
  }

  // First compile the bytecode, if we have to.
  if (!is_compiled_scope.is_compiled() &&
      !Compiler::Compile(isolate, function, Compiler::CLEAR_EXCEPTION,
                         &is_compiled_scope)) {
    return CrashUnlessFuzzing(isolate);
  }

  if (!Compiler::CompileBaseline(isolate, function, Compiler::CLEAR_EXCEPTION,
                                 &is_compiled_scope)) {
    return CrashUnlessFuzzing(isolate);
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

// TODO(v8:7700): Remove this function once we no longer need it to measure
// maglev compile times. For normal tierup, OptimizeMaglevOnNextCall should be
// used instead.
#ifdef V8_ENABLE_MAGLEV
RUNTIME_FUNCTION(Runtime_BenchMaglev) {
  HandleScope scope(isolate);
  DCHECK_EQ(args.length(), 2);
  Handle<JSFunction> function = args.at<JSFunction>(0);
  int count = args.smi_value_at(1);

  DirectHandle<Code> code;
  base::ElapsedTimer timer;
  timer.Start();
  code = Maglev::Compile(isolate, function, BytecodeOffset::None())
             .ToHandleChecked();
  for (int i = 1; i < count; ++i) {
    HandleScope handle_scope(isolate);
    Maglev::Compile(isolate, function, BytecodeOffset::None());
  }
  PrintF("Maglev compile time: %g ms!\n",
         timer.Elapsed().InMillisecondsF() / count);

  function->UpdateMaybeContextSpecializedCode(isolate, *code);

  return ReadOnlyRoots(isolate).undefined_value();
}
#else
RUNTIME_FUNCTION(Runtime_BenchMaglev) {
  PrintF("Maglev is not enabled.\n");
  return ReadOnlyRoots(isolate).undefined_value();
}
#endif  // V8_ENABLE_MAGLEV

RUNTIME_FUNCTION(Runtime_BenchTurbofan) {
  HandleScope scope(isolate);
  DCHECK_EQ(args.length(), 2);
  Handle<JSFunction> function = args.at<JSFunction>(0);
  int count = args.smi_value_at(1);

  base::ElapsedTimer timer;
  timer.Start();
  Compiler::CompileOptimized(isolate, function, ConcurrencyMode::kSynchronous,
                             CodeKind::TURBOFAN_JS);
  for (int i = 1; i < count; ++i) {
    Compiler::CompileOptimized(isolate, function, ConcurrencyMode::kSynchronous,
                               CodeKind::TURBOFAN_JS);
  }

  double compile_time = timer.Elapsed().InMillisecondsF() / count;

  return *isolate->factory()->NewNumber(compile_time);
}

RUNTIME_FUNCTION(Runtime_ActiveTierIsIgnition) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsJSFunction(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);
  return isolate->heap()->ToBoolean(function->ActiveTierIsIgnition(isolate));
}

RUNTIME_FUNCTION(Runtime_ActiveTierIsSparkplug) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsJSFunction(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);
  return isolate->heap()->ToBoolean(function->ActiveTierIsBaseline(isolate));
}

RUNTIME_FUNCTION(Runtime_ActiveTierIsMaglev) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsJSFunction(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);
  return isolate->heap()->ToBoolean(function->ActiveTierIsMaglev(isolate));
}

RUNTIME_FUNCTION(Runtime_ActiveTierIsTurbofan) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsJSFunction(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);
  return isolate->heap()->ToBoolean(function->ActiveTierIsTurbofan(isolate));
}

RUNTIME_FUNCTION(Runtime_IsSparkplugEnabled) {
  return isolate->heap()->ToBoolean(v8_flags.sparkplug);
}

RUNTIME_FUNCTION(Runtime_IsMaglevEnabled) {
  return isolate->heap()->ToBoolean(maglev::IsMaglevEnabled());
}

RUNTIME_FUNCTION(Runtime_IsTurbofanEnabled) {
  return isolate->heap()->ToBoolean(v8_flags.turbofan);
}

RUNTIME_FUNCTION(Runtime_CurrentFrameIsTurbofan) {
  HandleScope scope(isolate);
  JavaScriptStackFrameIterator it(isolate);
  return isolate->heap()->ToBoolean(it.frame()->is_turbofan());
}

#ifdef V8_ENABLE_MAGLEV
RUNTIME_FUNCTION(Runtime_OptimizeMaglevOnNextCall) {
  HandleScope scope(isolate);
  return OptimizeFunctionOnNextCall(args, isolate, CodeKind::MAGLEV);
}
#else
RUNTIME_FUNCTION(Runtime_OptimizeMaglevOnNextCall) {
  if (!v8_flags.fuzzing) PrintF("Maglev is not enabled.\n");
  return ReadOnlyRoots(isolate).undefined_value();
}
#endif  // V8_ENABLE_MAGLEV

// TODO(jgruber): Rename to OptimizeTurbofanOnNextCall.
RUNTIME_FUNCTION(Runtime_OptimizeFunctionOnNextCall) {
  HandleScope scope(isolate);
  return OptimizeFunctionOnNextCall(
      args, isolate,
      v8_flags.optimize_on_next_call_optimizes_to_maglev
          ? CodeKind::MAGLEV
          : CodeKind::TURBOFAN_JS);
}

RUNTIME_FUNCTION(Runtime_EnsureFeedbackVectorForFunction) {
  HandleScope scope(isolate);
  if (args.length() != 1 || !IsJSFunction(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<JSFunction> function = args.at<JSFunction>(0);
  if (function->has_feedback_vector()) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  IsCompiledScope is_compiled_scope;
  EnsureCompiledAndFeedbackVector(isolate, function, &is_compiled_scope);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_PrepareFunctionForOptimization) {
  HandleScope scope(isolate);
  if ((args.length() != 1 && args.length() != 2) || !IsJSFunction(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<JSFunction> function = args.at<JSFunction>(0);

  IsCompiledScope is_compiled_scope;
  if (!EnsureCompiledAndFeedbackVector(isolate, function, &is_compiled_scope)) {
    return CrashUnlessFuzzing(isolate);
  }

  // If optimization is disabled for the function, return without marking it for
  // manual optimization
  if (function->shared()->optimization_disabled() &&
      function->shared()->disabled_optimization_reason() ==
          BailoutReason::kNeverOptimize) {
    return CrashUnlessFuzzing(isolate);
  }

  if (IsAsmWasmFunction(isolate, *function)) return CrashUnlessFuzzing(isolate);

  // Hold onto the bytecode array between marking and optimization to ensure
  // it's not flushed.
  if (v8_flags.testing_d8_test_runner || v8_flags.allow_natives_syntax) {
    ManualOptimizationTable::MarkFunctionForManualOptimization(
        isolate, function, &is_compiled_scope);
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {

void FinalizeOptimization(Isolate* isolate) {
  DCHECK(isolate->concurrent_recompilation_enabled());
  isolate->optimizing_compile_dispatcher()->AwaitCompileTasks();
  isolate->optimizing_compile_dispatcher()->InstallOptimizedFunctions();
  isolate->optimizing_compile_dispatcher()->set_finalize(true);

#if V8_ENABLE_MAGLEV
  if (isolate->maglev_concurrent_dispatcher()->is_enabled()) {
    isolate->maglev_concurrent_dispatcher()->AwaitCompileJobs();
    isolate->maglev_concurrent_dispatcher()->FinalizeFinishedJobs();
  }
#endif  // V8_ENABLE_MAGLEV
}

BytecodeOffset OffsetOfNextJumpLoop(Isolate* isolate,
                                    Handle<BytecodeArray> bytecode_array,
                                    int current_offset) {
  interpreter::BytecodeArrayIterator it(bytecode_array, current_offset);

  // First, look for a loop that contains the current bytecode offset.
  for (; !it.done(); it.Advance()) {
    if (it.current_bytecode() != interpreter::Bytecode::kJumpLoop) {
      continue;
    }
    if (!base::IsInRange(current_offset, it.GetJumpTargetOffset(),
                         it.current_offset())) {
      continue;
    }

    return BytecodeOffset(it.current_offset());
  }

  // Fall back to any loop after the current offset.
  it.SetOffset(current_offset);
  for (; !it.done(); it.Advance()) {
    if (it.current_bytecode() == interpreter::Bytecode::kJumpLoop) {
      return BytecodeOffset(it.current_offset());
    }
  }

  return BytecodeOffset::None();
}

}  // namespace

RUNTIME_FUNCTION(Runtime_OptimizeOsr) {
  HandleScope handle_scope(isolate);

  Handle<JSFunction> function;

  // The optional parameter determines the frame being targeted.
  int stack_depth = 0;
  if (args.length() == 1) {
    if (!IsSmi(args[0])) return CrashUnlessFuzzing(isolate);
    stack_depth = args.smi_value_at(0);
  }

  // Find the JavaScript function on the top of the stack.
  JavaScriptStackFrameIterator it(isolate);
  while (!it.done() && stack_depth--) it.Advance();
  if (!it.done()) {
    if (it.frame()->is_turbofan()) {
      if (v8_flags.trace_osr) {
        CodeTracer::Scope scope(isolate->GetCodeTracer());
        PrintF(scope.file(),
               "[OSR - %%OptimizeOsr failed because the current function could "
               "not be found.]\n");
      }
      // This can happen if %OptimizeOsr is in inlined function.
      return ReadOnlyRoots(isolate).undefined_value();
    } else if (it.frame()->is_maglev()) {
      function = MaglevFrame::cast(it.frame())->GetInnermostFunction();
    } else {
      function = handle(it.frame()->function(), isolate);
    }
  }
  if (function.is_null()) return CrashUnlessFuzzing(isolate);

  if (V8_UNLIKELY((!v8_flags.turbofan && !maglev::IsMaglevEnabled()) ||
                  (!v8_flags.use_osr && !maglev::IsMaglevOsrEnabled()))) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  if (!function->shared()->allows_lazy_compilation()) {
    return CrashUnlessFuzzing(isolate);
  }

  if (function->shared()->optimization_disabled() &&
      function->shared()->disabled_optimization_reason() ==
          BailoutReason::kNeverOptimize) {
    return CrashUnlessFuzzing(isolate);
  }

  if (v8_flags.testing_d8_test_runner) {
    if (!CheckMarkedForManualOptimization(isolate, *function)) {
      return CrashUnlessFuzzing(isolate);
    }
  }

  if (function->HasAvailableOptimizedCode(isolate) &&
      (!function->code(isolate)->is_maglevved() || !v8_flags.osr_from_maglev)) {
    DCHECK(function->HasAttachedOptimizedCode(isolate) ||
           function->ChecksTieringState(isolate));
    // If function is already optimized, return.
    return ReadOnlyRoots(isolate).undefined_value();
  }

  if (!it.frame()->is_unoptimized() &&
      (!it.frame()->is_maglev() || !v8_flags.osr_from_maglev)) {
    // Nothing to be done.
    return ReadOnlyRoots(isolate).undefined_value();
  }

  IsCompiledScope is_compiled_scope(
      function->shared()->is_compiled_scope(isolate));
  JSFunction::EnsureFeedbackVector(isolate, function, &is_compiled_scope);
  isolate->tiering_manager()->RequestOsrAtNextOpportunity(*function);

  // If concurrent OSR is enabled, the testing workflow is a bit tricky. We
  // must guarantee that the next JumpLoop installs the finished OSR'd code
  // object, but we still want to exercise concurrent code paths. To do so,
  // we attempt to find the next JumpLoop, start an OSR job for it now, and
  // immediately force finalization.
  // If this succeeds and we correctly match up the next JumpLoop, once we
  // reach the JumpLoop we'll hit the OSR cache and install the generated code.
  // If not (e.g. because we enter a nested loop first), the next JumpLoop will
  // see the cached OSR code with a mismatched offset, and trigger
  // non-concurrent OSR compilation and installation.
  // To tier up from Maglev to TF we always do this, because the non-concurrent
  // recompilation in `CompileOptimizedOSRFromMaglev` is broken. See the comment
  // in `runtime-compiler.cc`.
  bool concurrent_osr =
      isolate->concurrent_recompilation_enabled() && v8_flags.concurrent_osr;
  bool is_maglev = false;
  if (it.frame()->is_maglev() || concurrent_osr) {
    BytecodeOffset osr_offset = BytecodeOffset::None();
    if (it.frame()->is_unoptimized()) {
      UnoptimizedJSFrame* frame = UnoptimizedJSFrame::cast(it.frame());
      Handle<BytecodeArray> bytecode_array(frame->GetBytecodeArray(), isolate);
      const int current_offset = frame->GetBytecodeOffset();
      osr_offset =
          OffsetOfNextJumpLoop(isolate, bytecode_array, current_offset);
    } else {
      MaglevFrame* frame = MaglevFrame::cast(it.frame());
      Handle<BytecodeArray> bytecode_array(
          function->shared()->GetBytecodeArray(isolate), isolate);
      const BytecodeOffset current_offset = frame->GetBytecodeOffsetForOSR();
      osr_offset = OffsetOfNextJumpLoop(
          isolate, bytecode_array,
          current_offset.IsNone() ? 0 : current_offset.ToInt());
      is_maglev = true;
    }

    if (osr_offset.IsNone()) {
      // The loop may have been elided by bytecode generation (e.g. for
      // patterns such as `do { ... } while (false);` or we are in an inlined
      // constructor stub.
      return ReadOnlyRoots(isolate).undefined_value();
    }

    // Finalize first to ensure all pending tasks are done (since we can't
    // queue more than one OSR job for each function).
    if (concurrent_osr) {
      FinalizeOptimization(isolate);
    }

    // Queue the job.
    auto unused_result = Compiler::CompileOptimizedOSR(
        isolate, function, osr_offset,
        concurrent_osr ? ConcurrencyMode::kConcurrent
                       : ConcurrencyMode::kSynchronous,
        (maglev::IsMaglevOsrEnabled() && !it.frame()->is_maglev())
            ? CodeKind::MAGLEV
            : CodeKind::TURBOFAN_JS);
    USE(unused_result);

    // Finalize again to finish the queued job. The next call into
    // Runtime::kCompileOptimizedOSR will pick up the cached InstructionStream
    // object.
    if (concurrent_osr) {
      FinalizeOptimization(isolate);
    }

    if (is_maglev) {
      // Maglev ignores the maybe_has_optimized_osr_code flag, thus we also need
      // to set a maximum urgency.
      function->feedback_vector()->set_osr_urgency(
          FeedbackVector::kMaxOsrUrgency);
    }
  }

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_BaselineOsr) {
  HandleScope scope(isolate);

  // Find the JavaScript function on the top of the stack.
  JavaScriptStackFrameIterator it(isolate);
  Handle<JSFunction> function = handle(it.frame()->function(), isolate);
  if (function.is_null()) return CrashUnlessFuzzing(isolate);
  if (!v8_flags.sparkplug || !v8_flags.use_osr) {
    return ReadOnlyRoots(isolate).undefined_value();
  }
  if (!it.frame()->is_unoptimized()) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  IsCompiledScope is_compiled_scope(
      function->shared()->is_compiled_scope(isolate));
  Compiler::CompileBaseline(isolate, function, Compiler::CLEAR_EXCEPTION,
                            &is_compiled_scope);

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_NeverOptimizeFunction) {
  HandleScope scope(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<Object> function_object = args.at(0);
  PtrComprCageBase cage_base(isolate);
  if (!IsJSFunction(*function_object, cage_base)) {
    return CrashUnlessFuzzing(isolate);
  }
  auto function = Cast<JSFunction>(function_object);
  DirectHandle<SharedFunctionInfo> sfi(function->shared(cage_base), isolate);
  CodeKind code_kind = sfi->abstract_code(isolate)->kind(cage_base);
  switch (code_kind) {
    case CodeKind::INTERPRETED_FUNCTION:
      break;
    case CodeKind::BUILTIN:
      if (HeapLayout::InReadOnlySpace(*sfi)) {
        // SFIs for builtin functions are in RO space and thus we cannot set
        // the never-optimize bit. But such SFIs cannot be optimized anyways.
        return CrashUnlessFuzzing(isolate);
      }
      break;
    default:
      return CrashUnlessFuzzing(isolate);
  }

  // Make sure to finish compilation if there is a parallel lazy compilation in
  // progress, to make sure that the compilation finalization doesn't clobber
  // the SharedFunctionInfo's disable_optimization field.
  if (isolate->lazy_compile_dispatcher() &&
      isolate->lazy_compile_dispatcher()->IsEnqueued(sfi)) {
    isolate->lazy_compile_dispatcher()->FinishNow(sfi);
  }

  sfi->DisableOptimization(isolate, BailoutReason::kNeverOptimize);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_GetOptimizationStatus) {
  HandleScope scope(isolate);
  DCHECK_EQ(args.length(), 1);

  int status = 0;
  if (v8_flags.lite_mode || v8_flags.jitless || !V8_ENABLE_TURBOFAN_BOOL) {
    // These modes cannot optimize. Unit tests should handle these the same
    // way.
    status |= static_cast<int>(OptimizationStatus::kLiteMode);
  }
  if (!isolate->use_optimizer()) {
    status |= static_cast<int>(OptimizationStatus::kNeverOptimize);
  }
  if (v8_flags.always_turbofan || v8_flags.prepare_always_turbofan) {
    status |= static_cast<int>(OptimizationStatus::kAlwaysOptimize);
  }
  if (v8_flags.deopt_every_n_times) {
    status |= static_cast<int>(OptimizationStatus::kMaybeDeopted);
  }
  if (v8_flags.optimize_on_next_call_optimizes_to_maglev) {
    status |= static_cast<int>(
        OptimizationStatus::kOptimizeOnNextCallOptimizesToMaglev);
  }

  Handle<Object> function_object = args.at(0);
  if (IsUndefined(*function_object)) return Smi::FromInt(status);
  if (!IsJSFunction(*function_object)) return CrashUnlessFuzzing(isolate);

  auto function = Cast<JSFunction>(function_object);
  status |= static_cast<int>(OptimizationStatus::kIsFunction);

  if (function->has_feedback_vector()) {
    if (function->tiering_in_progress()) {
      status |= static_cast<int>(OptimizationStatus::kOptimizingConcurrently);
    } else if (function->GetRequestedOptimizationIfAny(
                   isolate, ConcurrencyMode::kConcurrent) == CodeKind::MAGLEV) {
      status |= static_cast<int>(
          OptimizationStatus::kMarkedForConcurrentMaglevOptimization);
    } else if (function->GetRequestedOptimizationIfAny(
                   isolate, ConcurrencyMode::kSynchronous) ==
               CodeKind::MAGLEV) {
      status |=
          static_cast<int>(OptimizationStatus::kMarkedForMaglevOptimization);
    } else if (function->GetRequestedOptimizationIfAny(
                   isolate, ConcurrencyMode::kConcurrent) ==
               CodeKind::TURBOFAN_JS) {
      status |= static_cast<int>(
          OptimizationStatus::kMarkedForConcurrentOptimization);
    } else if (function->GetRequestedOptimizationIfAny(
                   isolate, ConcurrencyMode::kSynchronous) ==
               CodeKind::TURBOFAN_JS) {
      status |= static_cast<int>(OptimizationStatus::kMarkedForOptimization);
    }
  }

  if (function->HasAttachedOptimizedCode(isolate)) {
    Tagged<Code> code = function->code(isolate);
    if (code->marked_for_deoptimization()) {
      status |= static_cast<int>(OptimizationStatus::kMarkedForDeoptimization);
    } else {
      status |= static_cast<int>(OptimizationStatus::kOptimized);
    }
    if (code->is_maglevved()) {
      status |= static_cast<int>(OptimizationStatus::kMaglevved);
    } else if (code->is_turbofanned()) {
      status |= static_cast<int>(OptimizationStatus::kTurboFanned);
    }
  }
  if (function->HasAttachedCodeKind(isolate, CodeKind::BASELINE)) {
    status |= static_cast<int>(OptimizationStatus::kBaseline);
  }
  if (function->ActiveTierIsIgnition(isolate)) {
    status |= static_cast<int>(OptimizationStatus::kInterpreted);
  }
  if (!function->is_compiled(isolate)) {
    status |= static_cast<int>(OptimizationStatus::kIsLazy);
  }

  // Additionally, detect activations of this frame on the stack, and report the
  // status of the topmost frame.
  JavaScriptFrame* frame = nullptr;
  JavaScriptStackFrameIterator it(isolate);
  while (!it.done()) {
    if (it.frame()->function() == *function) {
      frame = it.frame();
      break;
    }
    it.Advance();
  }
  if (frame != nullptr) {
    status |= static_cast<int>(OptimizationStatus::kIsExecuting);
    if (frame->is_turbofan()) {
      status |=
          static_cast<int>(OptimizationStatus::kTopmostFrameIsTurboFanned);
    } else if (frame->is_interpreted()) {
      status |=
          static_cast<int>(OptimizationStatus::kTopmostFrameIsInterpreted);
    } else if (frame->is_baseline()) {
      status |= static_cast<int>(OptimizationStatus::kTopmostFrameIsBaseline);
    } else if (frame->is_maglev()) {
      status |= static_cast<int>(OptimizationStatus::kTopmostFrameIsMaglev);
    }
  }

  return Smi::FromInt(status);
}

RUNTIME_FUNCTION(Runtime_GetFunctionForCurrentFrame) {
  HandleScope scope(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  DCHECK_EQ(args.length(), 0);

  JavaScriptStackFrameIterator it(isolate);
  DCHECK(!it.done());
  return it.frame()->function();
}

RUNTIME_FUNCTION(Runtime_DisableOptimizationFinalization) {
  if (isolate->concurrent_recompilation_enabled()) {
    isolate->optimizing_compile_dispatcher()->AwaitCompileTasks();
    isolate->optimizing_compile_dispatcher()->InstallOptimizedFunctions();
    isolate->stack_guard()->ClearInstallCode();
    isolate->optimizing_compile_dispatcher()->set_finalize(false);
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WaitForBackgroundOptimization) {
  if (isolate->concurrent_recompilation_enabled()) {
    isolate->optimizing_compile_dispatcher()->AwaitCompileTasks();
#if V8_ENABLE_MAGLEV
    if (isolate->maglev_concurrent_dispatcher()->is_enabled()) {
      isolate->maglev_concurrent_dispatcher()->AwaitCompileJobs();
    }
#endif  // V8_ENABLE_MAGLEV
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_FinalizeOptimization) {
  if (isolate->concurrent_recompilation_enabled()) {
    FinalizeOptimization(isolate);
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_ForceFlush) {
  HandleScope scope(isolate);
  if (args.length() != 1) return CrashUnlessFuzzing(isolate);

  Handle<Object> function_object = args.at(0);
  if (!IsJSFunction(*function_object)) return CrashUnlessFuzzing(isolate);
  auto function = Cast<JSFunction>(function_object);
  Tagged<SharedFunctionInfo> sfi = function->shared(isolate);

  // Don't try to flush functions that cannot be flushed.
  if (!sfi->CanDiscardCompiled()) {
    return CrashUnlessFuzzing(isolate);
  }

  // Don't flush functions that are active on the stack.
  for (JavaScriptStackFrameIterator it(isolate); !it.done(); it.Advance()) {
    std::vector<Tagged<SharedFunctionInfo>> infos;
    it.frame()->GetFunctions(&infos);
    for (auto it = infos.rbegin(); it != infos.rend(); ++it) {
      if ((*it) == sfi) return CrashUnlessFuzzing(isolate);
    }
  }

  SharedFunctionInfo::DiscardCompiled(isolate, handle(sfi, isolate));
  function->ResetIfCodeFlushed(isolate);
  return ReadOnlyRoots(isolate).undefined_value();
}

static void ReturnNull(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  info.GetReturnValue().SetNull();
}

RUNTIME_FUNCTION(Runtime_GetUndetectable) {
  HandleScope scope(isolate);
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  Local<v8::ObjectTemplate> desc = v8::ObjectTemplate::New(v8_isolate);
  desc->MarkAsUndetectable();
  desc->SetCallAsFunctionHandler(ReturnNull);
  Local<v8::Object> obj =
      desc->NewInstance(v8_isolate->GetCurrentContext()).ToLocalChecked();
  return *Utils::OpenDirectHandle(*obj);
}

namespace {
// Does globalThis[target_function_name](...args).
void call_as_function(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();
  auto context = isolate->GetCurrentContext();
  auto global = context->Global();
  auto target_function_name = info.Data().As<v8::String>();
  v8::Local<v8::Function> target;
  {
    Local<Value> result;
    if (!global->Get(context, target_function_name).ToLocal(&result)) {
      return;
    }
    if (!result->IsFunction()) {
      isolate->ThrowError("Target function is not callable");
      return;
    }
    target = result.As<Function>();
  }
  int argc = info.Length();
  v8::LocalVector<v8::Value> args(isolate, argc);
  for (int i = 0; i < argc; i++) {
    args[i] = info[i];
  }
  Local<Value> result;
  if (!target->Call(context, info.This(), argc, args.data()).ToLocal(&result)) {
    return;
  }
  info.GetReturnValue().Set(result);
}
}  // namespace

RUNTIME_FUNCTION(Runtime_GetAbstractModuleSource) {
  // This isn't exposed to fuzzers. Crash if the native context is been
  // modified.
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  Tagged<JSFunction> abstract_module_source_function =
      isolate->native_context()->abstract_module_source_function();
  CHECK(IsJSFunction(*abstract_module_source_function));
  return abstract_module_source_function;
}

// Returns a callable object which redirects [[Call]] requests to
// globalThis[target_function_name] function.
RUNTIME_FUNCTION(Runtime_GetCallable) {
  HandleScope scope(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<String> target_function_name = args.at<String>(0);
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(v8_isolate);
  Local<v8::ObjectTemplate> instance_template = t->InstanceTemplate();
  instance_template->SetCallAsFunctionHandler(
      call_as_function, v8::Utils::ToLocal(target_function_name));
  v8_isolate->GetCurrentContext();
  Local<v8::Object> instance =
      t->GetFunction(v8_isolate->GetCurrentContext())
          .ToLocalChecked()
          ->NewInstance(v8_isolate->GetCurrentContext())
          .ToLocalChecked();
  return *Utils::OpenDirectHandle(*instance);
}

RUNTIME_FUNCTION(Runtime_ClearFunctionFeedback) {
  HandleScope scope(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  DCHECK_EQ(args.length(), 1);
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);
  function->ClearAllTypeFeedbackInfoForTesting();
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_NotifyContextDisposed) {
  HandleScope scope(isolate);
  isolate->heap()->NotifyContextDisposed(true);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_SetAllocationTimeout) {
  SealHandleScope shs(isolate);
  if (args.length() != 2 && args.length() != 3) {
    return CrashUnlessFuzzing(isolate);
  }
#ifdef V8_ENABLE_ALLOCATION_TIMEOUT
  CONVERT_INT32_ARG_FUZZ_SAFE(interval, 0);
  HeapAllocator::SetAllocationGcInterval(interval);
  CONVERT_INT32_ARG_FUZZ_SAFE(timeout, 1);
  isolate->heap()->set_allocation_timeout(timeout);
#endif
#ifdef DEBUG
  if (args.length() == 3) {
    // Enable/disable inline allocation if requested.
    CONVERT_BOOLEAN_ARG_FUZZ_SAFE(inline_allocation, 2);
    if (inline_allocation) {
      isolate->heap()->EnableInlineAllocation();
    } else {
      isolate->heap()->DisableInlineAllocation();
    }
  }
#endif
  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {

int FixedArrayLenFromSize(int size) {
  return std::min({(size - OFFSET_OF_DATA_START(FixedArray)) / kTaggedSize,
                   FixedArray::kMaxRegularLength});
}

void FillUpOneNewSpacePage(Isolate* isolate, Heap* heap,
                           SemiSpaceNewSpace* space) {
  DCHECK(!v8_flags.single_generation);
  heap->FreeMainThreadLinearAllocationAreas();
  PauseAllocationObserversScope pause_observers(heap);
  while (space->GetSpaceRemainingOnCurrentPageForTesting() > 0) {
    int space_remaining = space->GetSpaceRemainingOnCurrentPageForTesting();
    int length = FixedArrayLenFromSize(space_remaining);
    if (length > 0) {
      DirectHandle<FixedArray> padding =
          isolate->factory()->NewFixedArray(length, AllocationType::kYoung);
      DCHECK(heap->new_space()->Contains(*padding));
      space_remaining -= padding->Size();
    } else {
      // Not enough room to create another fixed array. Create a filler instead.
      space->FillCurrentPageForTesting();
    }
    heap->FreeMainThreadLinearAllocationAreas();
  }
}

}  // namespace

RUNTIME_FUNCTION(Runtime_SimulateNewspaceFull) {
  HandleScope scope(isolate);
  Heap* heap = isolate->heap();
  heap->FreeMainThreadLinearAllocationAreas();
  AlwaysAllocateScopeForTesting always_allocate(heap);
  if (v8_flags.minor_ms) {
    if (heap->minor_sweeping_in_progress()) {
      heap->EnsureYoungSweepingCompleted();
    }
    auto* space = heap->paged_new_space()->paged_space();
    space->AllocatePageUpToCapacityForTesting();
    space->ResetFreeList();
  } else {
    SemiSpaceNewSpace* space = heap->semi_space_new_space();
    do {
      FillUpOneNewSpacePage(isolate, heap, space);
    } while (space->AddFreshPage());
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_ScheduleGCInStackCheck) {
  SealHandleScope shs(isolate);
  isolate->RequestInterrupt(
      [](v8::Isolate* isolate, void*) {
        isolate->RequestGarbageCollectionForTesting(
            v8::Isolate::kFullGarbageCollection);
      },
      nullptr);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_TakeHeapSnapshot) {
  if (v8_flags.fuzzing) {
    // We don't want to create snapshots in fuzzers.
    return ReadOnlyRoots(isolate).undefined_value();
  }

  std::string filename = "heap.heapsnapshot";

  if (args.length() >= 1) {
    HandleScope hs(isolate);
    DirectHandle<String> filename_as_js_string = args.at<String>(0);
    std::unique_ptr<char[]> buffer = filename_as_js_string->ToCString();
    filename = std::string(buffer.get());
  }

  HeapProfiler* heap_profiler = isolate->heap_profiler();
  // Since this API is intended for V8 devs, we do not treat globals as roots
  // here on purpose.
  v8::HeapProfiler::HeapSnapshotOptions options;
  options.numerics_mode = v8::HeapProfiler::NumericsMode::kExposeNumericValues;
  options.snapshot_mode = v8::HeapProfiler::HeapSnapshotMode::kExposeInternals;
  heap_profiler->TakeSnapshotToFile(options, filename);
  return ReadOnlyRoots(isolate).undefined_value();
}

static void DebugPrintImpl(Tagged<MaybeObject> maybe_object, std::ostream& os) {
  if (maybe_object.IsCleared()) {
    os << "[weak cleared]";
  } else {
    Tagged<Object> object = maybe_object.GetHeapObjectOrSmi();
    bool weak = maybe_object.IsWeak();

#ifdef OBJECT_PRINT
    os << "DebugPrint: ";
    if (weak) os << "[weak] ";
    Print(object, os);
    if (IsHeapObject(object)) {
      Print(Cast<HeapObject>(object)->map(), os);
    }
#else
    if (weak) os << "[weak] ";
    // ShortPrint is available in release mode. Print is not.
    os << Brief(object);
#endif
  }
  os << std::endl;
}

RUNTIME_FUNCTION(Runtime_DebugPrint) {
  SealHandleScope shs(isolate);

  if (args.length() == 0) {
    // This runtime method has variable number of arguments, but if there is no
    // argument, undefined behavior may happen.
    return ReadOnlyRoots(isolate).undefined_value();
  }

  // This is exposed to tests / fuzzers; handle variable arguments gracefully.
  std::unique_ptr<std::ostream> output_stream(new StdoutStream());
  if (args.length() >= 2) {
    // Args: object, stream.
    if (IsSmi(args[1])) {
      int output_int = Cast<Smi>(args[1]).value();
      if (output_int == fileno(stderr)) {
        output_stream.reset(new StderrStream());
      }
    }
  }

  Tagged<MaybeObject> maybe_object(*args.address_of_arg_at(0));
  DebugPrintImpl(maybe_object, *output_stream);
  return args[0];
}

RUNTIME_FUNCTION(Runtime_DebugPrintPtr) {
  SealHandleScope shs(isolate);
  StdoutStream os;
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }

  Tagged<MaybeObject> maybe_object(*args.address_of_arg_at(0));
  if (!maybe_object.IsCleared()) {
    Tagged<Object> object = maybe_object.GetHeapObjectOrSmi();
    size_t pointer;
    if (Object::ToIntegerIndex(object, &pointer)) {
      Tagged<MaybeObject> from_pointer(static_cast<Address>(pointer));
      DebugPrintImpl(from_pointer, os);
    }
  }
  // We don't allow the converted pointer to leak out to JavaScript.
  return args[0];
}

RUNTIME_FUNCTION(Runtime_DebugPrintWord) {
  static constexpr int kNum16BitChunks = 4;
  SealHandleScope shs(isolate);

  // Args are: <bits 63-48>, <bits 47-32>, <bits 31-16>, <bits 15-0>, stream.
  if (args.length() != kNum16BitChunks + 1) {
    return CrashUnlessFuzzing(isolate);
  }

  uint64_t value = 0;
  for (int i = 0; i < kNum16BitChunks; ++i) {
    value <<= 16;
    CHECK(IsSmi(args[i]));
    uint32_t chunk = Cast<Smi>(args[i]).value();
    // We encode 16 bit per chunk only!
    CHECK_EQ(chunk & 0xFFFF0000, 0);
    value |= chunk;
  }

  if (!IsSmi(args[4]) || (Cast<Smi>(args[4]).value() == fileno(stderr))) {
    StderrStream os;
    os << "0x" << std::hex << value << std::dec << std::endl;
  } else {
    StdoutStream os;
    os << "0x" << std::hex << value << std::dec << std::endl;
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_DebugPrintFloat) {
  static constexpr int kNum16BitChunks = 4;
  SealHandleScope shs(isolate);

  // Args are: <bits 63-48>, <bits 47-32>, <bits 31-16>, <bits 15-0>, stream.
  if (args.length() != kNum16BitChunks + 1) {
    return CrashUnlessFuzzing(isolate);
  }

  uint64_t value = 0;
  for (int i = 0; i < kNum16BitChunks; ++i) {
    value <<= 16;
    CHECK(IsSmi(args[i]));
    uint32_t chunk = Cast<Smi>(args[i]).value();
    // We encode 16 bit per chunk only!
    CHECK_EQ(chunk & 0xFFFF0000, 0);
    value |= chunk;
  }

  if (!IsSmi(args[4]) || (Cast<Smi>(args[4]).value() == fileno(stderr))) {
    StderrStream os;
    std::streamsize precision = os.precision();
    os << std::setprecision(20) << base::bit_cast<double>(value) << std::endl;
    os.precision(precision);
  } else {
    StdoutStream os;
    std::streamsize precision = os.precision();
    os << std::setprecision(20) << base::bit_cast<double>(value) << std::endl;
    os.precision(precision);
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_PrintWithNameForAssert) {
  SealHandleScope shs(isolate);
  if (args.length() != 2) {
    return CrashUnlessFuzzing(isolate);
  }

  auto name = Cast<String>(args[0]);

  PrintF(" * ");
  StringCharacterStream stream(name);
  while (stream.HasMore()) {
    uint16_t character = stream.GetNext();
    PrintF("%c", character);
  }
  PrintF(": ");
  ShortPrint(args[1]);
  PrintF("\n");

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_DebugTrace) {
  SealHandleScope shs(isolate);
  isolate->PrintStack(stdout);
  return ReadOnlyRoots(isolate).undefined_value();
}

// This will not allocate (flatten the string), but it may run
// very slowly for very deeply nested ConsStrings.  For debugging use only.
RUNTIME_FUNCTION(Runtime_GlobalPrint) {
  SealHandleScope shs(isolate);

  // This is exposed to tests / fuzzers; handle variable arguments gracefully.
  FILE* output_stream = stdout;
  if (args.length() >= 2) {
    // Args: object, stream.
    if (IsSmi(args[1])) {
      int output_int = Cast<Smi>(args[1]).value();
      if (output_int == fileno(stderr)) {
        output_stream = stderr;
      }
    }
  }

  if (!IsString(args[0])) {
    return args[0];
  }

  auto string = Cast<String>(args[0]);
  StringCharacterStream stream(string);
  while (stream.HasMore()) {
    uint16_t character = stream.GetNext();
    PrintF(output_stream, "%c", character);
  }
  fflush(output_stream);
  return string;
}

RUNTIME_FUNCTION(Runtime_SystemBreak) {
  // The code below doesn't create handles, but when breaking here in GDB
  // having a handle scope might be useful.
  HandleScope scope(isolate);
  base::OS::DebugBreak();
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_SetForceSlowPath) {
  SealHandleScope shs(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  Tagged<Object> arg = args[0];
  if (IsTrue(arg, isolate)) {
    isolate->set_force_slow_path(true);
  } else {
    // This function is fuzzer exposed and as such we might not always have an
    // input that IsTrue or IsFalse. In these cases we assume that if !IsTrue
    // then it IsFalse when fuzzing.
    DCHECK(IsFalse(arg, isolate) || v8_flags.fuzzing);
    isolate->set_force_slow_path(false);
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_Abort) {
  SealHandleScope shs(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  int message_id = args.smi_value_at(0);
  const char* message = GetAbortReason(static_cast<AbortReason>(message_id));
  base::OS::PrintError("abort: %s\n", message);
  isolate->PrintStack(stderr);
  base::OS::Abort();
  UNREACHABLE();
}

RUNTIME_FUNCTION(Runtime_AbortJS) {
  HandleScope scope(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<String> message = args.at<String>(0);
  if (v8_flags.disable_abortjs) {
    base::OS::PrintError("[disabled] abort: %s\n", message->ToCString().get());
    return Tagged<Object>();
  }
  base::OS::PrintError("abort: %s\n", message->ToCString().get());
  isolate->PrintStack(stderr);
  base::OS::Abort();
  UNREACHABLE();
}

RUNTIME_FUNCTION(Runtime_AbortCSADcheck) {
  HandleScope scope(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<String> message = args.at<String>(0);
  if (base::ControlledCrashesAreHarmless()) {
    base::OS::PrintError(
        "Safely terminating process due to CSA check failure\n");
    // Also prefix the error message (printed below). This has two purposes:
    // (1) it makes it clear that this error is deemed "safe" (2) it causes
    // fuzzers that pattern-match on stderr output to ignore these failures.
    base::OS::PrintError("The following harmless failure was encountered: %s\n",
                         message->ToCString().get());
  } else {
    base::OS::PrintError("abort: CSA_DCHECK failed: %s\n",
                         message->ToCString().get());
    isolate->PrintStack(stderr);
  }
  base::OS::Abort();
  UNREACHABLE();
}

RUNTIME_FUNCTION(Runtime_DisassembleFunction) {
  HandleScope scope(isolate);
#ifdef DEBUG
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  // Get the function and make sure it is compiled.
  Handle<JSFunction> func = args.at<JSFunction>(0);
  IsCompiledScope is_compiled_scope;
#ifndef V8_ENABLE_LEAPTIERING
  if (!func->is_compiled(isolate) && func->HasAvailableOptimizedCode(isolate)) {
    func->UpdateCode(func->feedback_vector()->optimized_code(isolate));
  }
#endif  // !V8_ENABLE_LEAPTIERING
  CHECK(func->shared()->is_compiled() ||
        Compiler::Compile(isolate, func, Compiler::KEEP_EXCEPTION,
                          &is_compiled_scope));
  StdoutStream os;
  Print(func->code(isolate), os);
  os << std::endl;
#endif  // DEBUG
  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {

int StackSize(Isolate* isolate) {
  int n = 0;
  for (JavaScriptStackFrameIterator it(isolate); !it.done(); it.Advance()) n++;
  return n;
}

void PrintIndentation(int stack_size) {
  const int max_display = 80;
  if (stack_size <= max_display) {
    PrintF("%4d:%*s", stack_size, stack_size, "");
  } else {
    PrintF("%4d:%*s", stack_size, max_display, "...");
  }
}

}  // namespace

RUNTIME_FUNCTION(Runtime_TraceEnter) {
  SealHandleScope shs(isolate);
  PrintIndentation(StackSize(isolate));
  JavaScriptFrame::PrintTop(isolate, stdout, true, false);
  PrintF(" {\n");
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_TraceExit) {
  SealHandleScope shs(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  Tagged<Object> obj = args[0];
  PrintIndentation(StackSize(isolate));
  PrintF("} -> ");
  ShortPrint(obj);
  PrintF("\n");
  return obj;  // return TOS
}

RUNTIME_FUNCTION(Runtime_HaveSameMap) {
  SealHandleScope shs(isolate);
  if (args.length() != 2) {
    return CrashUnlessFuzzing(isolate);
  }
  if (IsSmi(args[0]) || IsSmi(args[1])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto obj1 = Cast<HeapObject>(args[0]);
  auto obj2 = Cast<HeapObject>(args[1]);
  return isolate->heap()->ToBoolean(obj1->map() == obj2->map());
}

RUNTIME_FUNCTION(Runtime_InLargeObjectSpace) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsHeapObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto obj = Cast<HeapObject>(args[0]);
  return isolate->heap()->ToBoolean(
      isolate->heap()->new_lo_space()->Contains(obj) ||
      isolate->heap()->code_lo_space()->Contains(obj) ||
      isolate->heap()->lo_space()->Contains(obj));
}

RUNTIME_FUNCTION(Runtime_HasElementsInALargeObjectSpace) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsJSArray(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto array = Cast<JSArray>(args[0]);
  Tagged<FixedArrayBase> elements = array->elements();
  return isolate->heap()->ToBoolean(
      isolate->heap()->new_lo_space()->Contains(elements) ||
      isolate->heap()->lo_space()->Contains(elements));
}

RUNTIME_FUNCTION(Runtime_HasCowElements) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsJSArray(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto array = Cast<JSArray>(args[0]);
  Tagged<FixedArrayBase> elements = array->elements();
  return isolate->heap()->ToBoolean(elements->IsCowArray());
}

RUNTIME_FUNCTION(Runtime_InYoungGeneration) {
  SealHandleScope shs(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  Tagged<Object> obj = args[0];
  return isolate->heap()->ToBoolean(HeapLayout::InYoungGeneration(obj));
}

// Force pretenuring for the allocation site the passed object belongs to.
RUNTIME_FUNCTION(Runtime_PretenureAllocationSite) {
  DisallowGarbageCollection no_gc;

  if (args.length() != 1) return CrashUnlessFuzzing(isolate);
  Tagged<Object> arg = args[0];
  if (!IsJSObject(arg)) return CrashUnlessFuzzing(isolate);
  Tagged<JSObject> object = Cast<JSObject>(arg);

  Heap* heap = object->GetHeap();
  if (!v8_flags.sticky_mark_bits && !HeapLayout::InYoungGeneration(object)) {
    // Object is not in new space, thus there is no memento and nothing to do.
    return ReturnFuzzSafe(ReadOnlyRoots(isolate).false_value(), isolate);
  }

  PretenuringHandler* pretenuring_handler = heap->pretenuring_handler();
  Tagged<AllocationMemento> memento = PretenuringHandler::FindAllocationMemento<
      PretenuringHandler::kForRuntime>(heap, object->map(), object);
  if (memento.is_null())
    return ReturnFuzzSafe(ReadOnlyRoots(isolate).false_value(), isolate);
  Tagged<AllocationSite> site = memento->GetAllocationSite();
  pretenuring_handler->PretenureAllocationSiteOnNextCollection(site);
  return ReturnFuzzSafe(ReadOnlyRoots(isolate).true_value(), isolate);
}

namespace {

v8::ModifyCodeGenerationFromStringsResult DisallowCodegenFromStringsCallback(
    v8::Local<v8::Context> context, v8::Local<v8::Value> source,
    bool is_code_kind) {
  return {false, {}};
}

}  // namespace

RUNTIME_FUNCTION(Runtime_DisallowCodegenFromStrings) {
  SealHandleScope shs(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  bool flag = Cast<Boolean>(args[0])->ToBool(isolate);
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  v8_isolate->SetModifyCodeGenerationFromStringsCallback(
      flag ? DisallowCodegenFromStringsCallback : nullptr);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_RegexpHasBytecode) {
  SealHandleScope shs(isolate);
  if (args.length() != 2 || !IsJSRegExp(args[0]) || !IsBoolean(args[1])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto regexp = args.at<JSRegExp>(0);
  bool is_latin1 = args.at<Boolean>(1)->ToBool(isolate);
  bool result = false;
  if (regexp->has_data()) {
    Tagged<RegExpData> data = regexp->data(isolate);
    if (data->type_tag() == RegExpData::Type::IRREGEXP) {
      result = Cast<IrRegExpData>(data)->has_bytecode(is_latin1);
    }
  }
  return isolate->heap()->ToBoolean(result);
}

RUNTIME_FUNCTION(Runtime_RegexpHasNativeCode) {
  SealHandleScope shs(isolate);
  if (args.length() != 2 || !IsJSRegExp(args[0]) || !IsBoolean(args[1])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto regexp = args.at<JSRegExp>(0);
  bool is_latin1 = args.at<Boolean>(1)->ToBool(isolate);
  bool result = false;
  if (regexp->has_data()) {
    Tagged<RegExpData> data = regexp->data(isolate);
    if (data->type_tag() == RegExpData::Type::IRREGEXP) {
      result = Cast<IrRegExpData>(data)->has_code(is_latin1);
    }
  }
  return isolate->heap()->ToBoolean(result);
}

RUNTIME_FUNCTION(Runtime_RegexpTypeTag) {
  HandleScope shs(isolate);
  if (args.length() != 1 || !IsJSRegExp(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto regexp = Cast<JSRegExp>(args[0]);
  const char* type_str;
  if (regexp->has_data()) {
    switch (regexp->data(isolate)->type_tag()) {
      case RegExpData::Type::ATOM:
        type_str = "ATOM";
        break;
      case RegExpData::Type::IRREGEXP:
        type_str = "IRREGEXP";
        break;
      case RegExpData::Type::EXPERIMENTAL:
        type_str = "EXPERIMENTAL";
        break;
      default:
        UNREACHABLE();
    }
  } else {
    type_str = "NOT_COMPILED";
  }
  return *isolate->factory()->NewStringFromAsciiChecked(type_str);
}

RUNTIME_FUNCTION(Runtime_RegexpIsUnmodified) {
  HandleScope shs(isolate);
  if (args.length() != 1 || !IsJSRegExp(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<JSRegExp> regexp = args.at<JSRegExp>(0);
  return isolate->heap()->ToBoolean(
      RegExp::IsUnmodifiedRegExp(isolate, regexp));
}

#define ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(Name)    \
  RUNTIME_FUNCTION(Runtime_##Name) {                  \
    if (args.length() != 1 || !IsJSObject(args[0])) { \
      return CrashUnlessFuzzing(isolate);             \
    }                                                 \
    auto obj = args.at<JSObject>(0);                  \
    return isolate->heap()->ToBoolean(obj->Name());   \
  }

ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasFastElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasSmiElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasObjectElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasSmiOrObjectElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasDoubleElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasHoleyElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasDictionaryElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasPackedElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasSloppyArgumentsElements)
// Properties test sitting with elements tests - not fooling anyone.
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasFastProperties)

#undef ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION

#define FIXED_TYPED_ARRAYS_CHECK_RUNTIME_FUNCTION(Type, type, TYPE, ctype) \
  RUNTIME_FUNCTION(Runtime_HasFixed##Type##Elements) {                     \
    if (args.length() != 1 || !IsJSObject(args[0])) {                      \
      return CrashUnlessFuzzing(isolate);                                  \
    }                                                                      \
    auto obj = Cast<JSObject>(args[0]);                                    \
    return isolate->heap()->ToBoolean(obj->HasFixed##Type##Elements());    \
  }

TYPED_ARRAYS(FIXED_TYPED_ARRAYS_CHECK_RUNTIME_FUNCTION)

#undef FIXED_TYPED_ARRAYS_CHECK_RUNTIME_FUNCTION

RUNTIME_FUNCTION(Runtime_IsConcatSpreadableProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsIsConcatSpreadableLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_TypedArraySpeciesProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsTypedArraySpeciesLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_RegExpSpeciesProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsRegExpSpeciesLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_PromiseSpeciesProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsPromiseSpeciesLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_ArraySpeciesProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsArraySpeciesLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_MapIteratorProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsMapIteratorLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_SetIteratorProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsSetIteratorLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_StringIteratorProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsStringIteratorLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_ArrayIteratorProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsArrayIteratorLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_NoElementsProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(Protectors::IsNoElementsIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_StringWrapperToPrimitiveProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsStringWrapperToPrimitiveIntact(isolate));
}

// For use by tests and fuzzers. It
//
// 1. serializes a snapshot of the current isolate,
// 2. deserializes the snapshot,
// 3. and runs VerifyHeap on the resulting isolate.
//
// The current isolate should not be modified by this call and can keep running
// once it completes.
RUNTIME_FUNCTION(Runtime_SerializeDeserializeNow) {
  // TODO(353971258): This function is not currently exposed to fuzzers.
  // Investigate if it should be.
  HandleScope scope(isolate);
  Snapshot::SerializeDeserializeAndVerifyForTesting(isolate,
                                                    isolate->native_context());
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_HeapObjectVerify) {
  HandleScope shs(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<Object> object = args.at(0);
#ifdef VERIF
"""


```