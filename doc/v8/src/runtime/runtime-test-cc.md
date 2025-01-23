Response:
The user wants a summary of the functionalities present in the provided C++ code snippet. Here's a breakdown of the thought process:

1. **Identify the File's Purpose:** The file is named `runtime-test.cc` and resides in `v8/src/runtime/`. This strongly suggests it's part of V8's runtime testing infrastructure. The inclusion of headers like `v8-function.h`, `v8-profiler.h`, and files from `src/codegen/`, `src/debug/`, `src/execution/`, `src/heap/`, `src/objects/`, `src/profiler/`, etc., confirms it interacts with various core V8 components.

2. **Scan for Key Functions/Macros:**  Look for prominent patterns or keywords that indicate specific actions or categories of functionalities. Keywords like `RUNTIME_FUNCTION`, `DCHECK`, and conditional compilation (`#ifdef`) are good starting points.

3. **Analyze `RUNTIME_FUNCTION` Declarations:** Each `RUNTIME_FUNCTION` represents a function callable from JavaScript within the V8 environment (using internal syntax like `%FunctionName`). Go through each one and understand its purpose based on its name and the operations performed within it.

    * **String Manipulation:**  `Runtime_ConstructDouble`, `Runtime_StringIsFlat`, `Runtime_ConstructConsString`, `Runtime_ConstructSlicedString`, `Runtime_ConstructInternalizedString`, `Runtime_ConstructThinString`. These clearly deal with creating and inspecting different string representations.

    * **Deoptimization:** `Runtime_DeoptimizeFunction`, `Runtime_DeoptimizeNow`. These are related to forcing functions out of optimized states.

    * **Internal State Access:** `Runtime_LeakHole`, `Runtime_RunningInSimulator`, `Runtime_ICsAreEnabled`, `Runtime_IsConcurrentRecompilationSupported`, `Runtime_IsAtomicsWaitAllowed`. These expose internal V8 status or values.

    * **Code Optimization & Tiering:**  This is a major theme. Look for functions related to compilation, optimization levels, and on-stack replacement (OSR): `Runtime_CompileBaseline`, `Runtime_BenchMaglev`, `Runtime_BenchTurbofan`, `Runtime_ActiveTierIsIgnition`, `Runtime_ActiveTierIsSparkplug`, `Runtime_ActiveTierIsMaglev`, `Runtime_ActiveTierIsTurbofan`, `Runtime_IsSparkplugEnabled`, `Runtime_IsMaglevEnabled`, `Runtime_IsTurbofanEnabled`, `Runtime_CurrentFrameIsTurbofan`, `Runtime_OptimizeMaglevOnNextCall`, `Runtime_OptimizeFunctionOnNextCall`, `Runtime_EnsureFeedbackVectorForFunction`, `Runtime_PrepareFunctionForOptimization`, `Runtime_OptimizeOsr`, `Runtime_BaselineOsr`, `Runtime_NeverOptimizeFunction`, `Runtime_GetOptimizationStatus`. Notice patterns like "OptimizeOnNextCall", "ActiveTierIs...", "Is...Enabled".

    * **Debugging/Testing Aids:** `Runtime_RuntimeEvaluateREPL`. This suggests the ability to execute code within the V8 runtime, likely for testing or debugging. `Runtime_ClearMegamorphicStubCache` also falls into this category.

4. **Identify Helper Macros/Functions:** Pay attention to macros like `CONVERT_INT32_ARG_FUZZ_SAFE`, `CONVERT_BOOLEAN_ARG_FUZZ_SAFE`, and functions like `CrashUnlessFuzzing`, `CheckMarkedForManualOptimization`, `CanOptimizeFunction`, `OptimizeFunctionOnNextCall`, and `FinalizeOptimization`. These provide context about the intended usage of the runtime functions, particularly in testing and fuzzing scenarios.

5. **Note Conditional Compilation:**  The `#ifdef V8_ENABLE_MAGLEV` and `#if V8_ENABLE_WEBASSEMBLY` blocks indicate features that are only active when specific compilation flags are set.

6. **Address Specific Instructions:**

    * **`.tq` extension:**  The code is `.cc`, so it's C++, not Torque. Explicitly state this.
    * **JavaScript Relationship:**  Many of the runtime functions directly relate to JavaScript concepts (strings, function optimization). Provide relevant JavaScript examples to illustrate this connection.
    * **Code Logic and Assumptions:**  For functions like `Runtime_ConstructDouble`, the input is clearly defined (two 32-bit numbers forming a double). For optimization functions, the input is usually a JS function. Explain the expected input and the general effect.
    * **Common Programming Errors:** Focus on the types of errors the "fuzz-safe" macros are designed to prevent (incorrect argument types). Also, highlight the requirement for preparing a function before optimization.

7. **Synthesize the Summary:** Combine the identified functionalities into a concise overview, grouping related features together. Emphasize the testing and internal nature of the code.

8. **Review and Refine:**  Ensure the summary is accurate, well-organized, and addresses all aspects of the user's request. Double-check for any missed functionalities or misinterpretations. For example, initially, I might focus heavily on optimization, but then realize the string manipulation functions are also a significant group. Also make sure to correctly address the "part 1 of 3" instruction and clearly state this is a summary of the provided snippet *only*.
好的，根据你提供的 v8 源代码文件 `v8/src/runtime/runtime-test.cc` 的内容，以下是它的功能归纳：

**核心功能：V8 引擎的运行时测试辅助工具**

这个 `.cc` 文件定义了一系列 V8 引擎的**运行时函数 (Runtime Functions)**，这些函数主要用于**测试和调试 V8 引擎的内部功能**。它们不是直接给最终用户 JavaScript 代码调用的 API，而是 V8 内部机制的一部分，通常通过特殊的内建语法（例如 `%FunctionName()`）在测试环境中使用。

**具体功能分类：**

1. **对象构造与操作 (主要是字符串)：**
   - 创建特定类型的字符串对象，例如：
     - `Runtime_ConstructDouble`:  根据两个 32 位整数构造一个双精度浮点数。
     - `Runtime_StringIsFlat`:  检查字符串是否是扁平表示。
     - `Runtime_ConstructConsString`: 创建一个连接字符串。
     - `Runtime_ConstructSlicedString`: 创建一个切片字符串。
     - `Runtime_ConstructInternalizedString`: 创建一个内部化字符串。
     - `Runtime_ConstructThinString`: 创建一个 ThinString。

2. **代码优化与反优化控制：**
   - 控制和检查代码的优化状态，用于测试不同的优化流程：
     - `Runtime_DeoptimizeFunction`: 反优化指定的函数。
     - `Runtime_DeoptimizeNow`: 反优化当前栈帧的函数。
     - `Runtime_CompileBaseline`: 强制编译函数的 Baseline 版本。
     - `Runtime_BenchMaglev`:  测试 Maglev 编译器的性能（仅在启用 Maglev 时）。
     - `Runtime_BenchTurbofan`: 测试 Turbofan 编译器的性能。
     - `Runtime_ActiveTierIsIgnition`, `Runtime_ActiveTierIsSparkplug`, `Runtime_ActiveTierIsMaglev`, `Runtime_ActiveTierIsTurbofan`:  检查函数的当前激活优化层级。
     - `Runtime_IsSparkplugEnabled`, `Runtime_IsMaglevEnabled`, `Runtime_IsTurbofanEnabled`:  检查特定优化器是否启用。
     - `Runtime_CurrentFrameIsTurbofan`: 检查当前栈帧是否由 Turbofan 生成。
     - `Runtime_OptimizeMaglevOnNextCall`:  标记函数在下次调用时使用 Maglev 进行优化。
     - `Runtime_OptimizeFunctionOnNextCall`: 标记函数在下次调用时进行优化 (默认可能是 Turbofan 或 Maglev)。
     - `Runtime_EnsureFeedbackVectorForFunction`: 确保函数拥有反馈向量。
     - `Runtime_PrepareFunctionForOptimization`: 准备函数进行优化。
     - `Runtime_OptimizeOsr`:  触发 On-Stack Replacement (OSR) 优化。
     - `Runtime_BaselineOsr`: 触发 Baseline OSR。
     - `Runtime_NeverOptimizeFunction`: 阻止函数被优化。
     - `Runtime_GetOptimizationStatus`: 获取函数的优化状态。

3. **V8 内部状态访问与控制：**
   - 访问或修改 V8 引擎的内部状态，用于测试引擎行为：
     - `Runtime_ClearMegamorphicStubCache`: 清空巨态 Stub 缓存。
     - `Runtime_LeakHole`: 返回 V8 的 `the_hole` 值。
     - `Runtime_RunningInSimulator`:  判断是否运行在模拟器中。
     - `Runtime_ICsAreEnabled`:  检查内联缓存 (ICs) 是否启用。
     - `Runtime_IsConcurrentRecompilationSupported`: 检查是否支持并发重新编译。
     - `Runtime_IsAtomicsWaitAllowed`: 检查是否允许 Atomics.wait 操作。

4. **调试与 REPL 功能：**
   - 提供在运行时评估代码的能力，用于调试：
     - `Runtime_RuntimeEvaluateREPL`: 在 V8 的 REPL 环境中执行代码。

**关于文件类型和 JavaScript 关系：**

- **文件类型:** `v8/src/runtime/runtime-test.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**。 它不是 Torque 源代码文件 (`.tq`)。

- **与 JavaScript 的关系:**  虽然这个文件是 C++ 代码，但它定义的功能直接影响 JavaScript 代码的执行和优化。这些运行时函数可以通过 V8 内部的机制被调用，从而允许测试人员在更底层的层面控制和观察 JavaScript 代码的运行状态。

**JavaScript 示例 (说明部分功能):**

```javascript
// 假设在 V8 的测试环境或使用了允许访问内部语法的标志
function testFunction() {
  return 1 + 2;
}

// 准备函数进行优化
%PrepareFunctionForOptimization(testFunction);

// 触发函数在下次调用时使用 Turbofan 进行优化
%OptimizeFunctionOnNextCall(testFunction);

testFunction(); // 触发优化

// 获取函数的优化状态
const status = %GetOptimizationStatus(testFunction);
console.log("Optimization Status:", status); // 输出优化状态码

// 反优化函数
%DeoptimizeFunction(testFunction);

// 再次获取优化状态
const statusAfterDeopt = %GetOptimizationStatus(testFunction);
console.log("Optimization Status after Deoptimization:", statusAfterDeopt);
```

**代码逻辑推理和假设输入/输出 (示例):**

**函数:** `Runtime_ConstructDouble`

**假设输入:**
- `args[0]` (uint32_t 高位):  `0x4009`
- `args[1]` (uint32_t 低位):  `0x21fb5444`

**代码逻辑:** 将高位左移 32 位，然后与低位进行按位或运算，得到一个 64 位整数，再将其转换为双精度浮点数。

**预期输出:**  一个表示 `Math.PI` 的双精度浮点数 (近似值)。因为 `0x400921fb5444` 是 `PI` 的 IEEE 754 表示。

**用户常见的编程错误 (与部分功能相关):**

- **在优化前未准备函数：**  用户可能期望 `%OptimizeFunctionOnNextCall` 立即生效，但 V8 通常需要在优化前进行一些准备工作。如果在调用 `%OptimizeFunctionOnNextCall` 之前没有调用 `%PrepareFunctionForOptimization`，优化可能不会发生或者行为不符合预期。

  ```javascript
  function myFunc() {
    // ... 一些复杂的逻辑
  }

  // 错误：直接尝试优化，可能不会立即生效
  %OptimizeFunctionOnNextCall(myFunc);
  myFunc();
  ```

**总结：**

`v8/src/runtime/runtime-test.cc` 文件定义了一组底层的 C++ 函数，用于 V8 引擎的内部测试和调试。这些函数允许测试人员控制代码优化、访问内部状态、模拟特定场景等，以确保 V8 引擎的各个组件能够正确运行。它们通常不直接暴露给普通的 JavaScript 开发者使用。

请注意，这只是对提供的代码片段的分析和归纳。完整的 `v8/src/runtime/runtime-test.cc` 文件可能包含更多内容。

### 提示词
```
这是目录为v8/src/runtime/runtime-test.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-test.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```