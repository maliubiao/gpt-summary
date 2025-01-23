Response:
Let's break down the thought process to analyze the provided C++ header file.

1. **Understand the Goal:** The request asks for the *functionality* of the header file, with specific considerations for Torque, JavaScript relevance, logic, and common programming errors. This means going beyond a simple description of the code and explaining its *purpose* in the V8 compilation process.

2. **Initial Scan for Keywords and Structure:**  Quickly read through the code, looking for key terms: `class`, `enum`, `struct`, `public`, `private`, common data types (`int`, `bool`), and V8-specific terms like `Isolate`, `SharedFunctionInfo`, `BytecodeArray`, `Code`, `BailoutReason`, and `OptimizedCompilationInfo`. Notice the `#ifndef` guard, indicating a header file. The `namespace v8::internal` is important for context.

3. **Identify the Core Class:** The central element is the `OptimizedCompilationInfo` class. The comment above it is a strong indicator of its purpose: "encapsulates the information needed to compile optimized code for a given function, and the results of the optimized compilation." This is the starting point for understanding the functionality.

4. **Analyze Member Variables:**  Go through the member variables, trying to understand what kind of information is being stored:
    * `Isolate* isolate_unsafe_`:  Indicates a connection to the V8 isolate.
    * `CodeKind code_kind_`:  Specifies the type of code being compiled (e.g., regular function, WASM).
    * `IndirectHandle<BytecodeArray> bytecode_array_`, `IndirectHandle<SharedFunctionInfo> shared_info_`, `IndirectHandle<JSFunction> closure_`: These handles likely represent the JavaScript function being optimized.
    * `IndirectHandle<Code> code_`:  This likely stores the result of the compilation.
    * `BasicBlockProfilerData* profiler_data_`:  Related to performance profiling.
    * `wasm::WasmCompilationResult wasm_compilation_result_`:  Specific to WebAssembly compilation.
    * `BytecodeOffset osr_offset_`:  For on-stack replacement (OSR) optimization.
    * `Zone* zone_`:  Memory management within the compilation pipeline.
    * `BailoutReason bailout_reason_`:  Why optimization might have failed.
    * `InlinedFunctionList inlined_functions_`:  Information about inlined functions.
    * `TickCounter tick_counter_`:  For tracking execution time.
    * `PersistentHandles ph_`, `CanonicalHandlesMap canonical_handles_`:  Mechanisms for managing V8 objects during compilation.
    * `flags_`: An integer used as a bitmask for various compilation options.

5. **Analyze Enums and Flags:** The `enum Flag` and the associated `FLAGS` macro define various boolean options for the compilation process. These flags control aspects like inlining, source position tracking, and tracing. Understanding these flags is crucial to understanding the configurability of the optimizer.

6. **Analyze Public Methods:**  Focus on the public methods to understand how to interact with the `OptimizedCompilationInfo` object:
    * Constructors: How the object is created. Notice the different constructors for regular functions, stubs, and testing.
    * Getters and Setters:  Provide access to the stored information (e.g., `shared_info()`, `set_code()`, `is_osr()`). Pay attention to those related to flags.
    * Methods related to code management: `SetCode()`, `SetWasmCompilationResult()`, `ReleaseWasmCompilationResult()`.
    * Context accessors: `context()`, `native_context()`, `global_object()`.
    * Methods related to optimization status: `IsOptimizing()`, `IsWasm()`, `IsWasmBuiltin()`.
    * Handle management: `set_persistent_handles()`, `set_canonical_handles()`, `CanonicalHandle()`, `ReopenAndCanonicalizeHandlesInNewScope()`, `DetachPersistentHandles()`, `DetachCanonicalHandles()`. These are complex but indicate careful management of V8 objects.
    * Bailout/Retry methods: `AbortOptimization()`, `RetryOptimization()`.
    * Inlining related methods: `AddInlinedFunction()`.
    * Debugging/Tracing methods: `GetDebugName()`, `trace_turbo_filename()`, `set_trace_turbo_filename()`.
    * Profiling related methods: `profiler_data()`, `set_profiler_data()`.

7. **Consider the Specific Constraints of the Request:**
    * **Torque:** The file ends in `.h`, not `.tq`, so it's *not* a Torque file. State this clearly.
    * **JavaScript Relevance:**  Since this class manages information for *optimized* compilation of JavaScript functions, it's directly related. Think about what happens when JavaScript code is executed: V8 might try to optimize it. The `OptimizedCompilationInfo` holds the data for this process. Consider a simple JavaScript function as an example.
    * **Code Logic/Inference:** Focus on methods that modify the state or have specific logic. `CanonicalHandle()` is a good example of a method with internal logic (checking if a handle already exists). Formulate a simple input/output scenario.
    * **Common Programming Errors:** Think about potential issues when *using* this class (even though developers don't directly instantiate it). Incorrectly handling handles, especially detaching them without proper management, is a plausible error.

8. **Structure the Answer:** Organize the findings into logical sections:
    * Overall Functionality: A high-level summary.
    * Detailed Functionality (grouping related methods).
    * Torque Check.
    * JavaScript Relationship (with an example).
    * Code Logic/Inference (with an example).
    * Common Programming Errors (with an example).

9. **Refine and Clarify:**  Review the answer for clarity, accuracy, and completeness. Ensure that the explanations are easy to understand, even for someone not intimately familiar with the V8 codebase. Use precise language and avoid jargon where possible. For instance, instead of just saying "manages handles," explain *why* and *what kind* of handles.

By following this systematic approach, one can thoroughly analyze the header file and provide a comprehensive and accurate answer to the request. The key is to combine code-level inspection with a higher-level understanding of the purpose and context of the code within the V8 engine.
## 功能列举

`v8/src/codegen/optimized-compilation-info.h` 文件定义了一个名为 `OptimizedCompilationInfo` 的类。这个类的主要功能是 **封装了为给定函数编译优化代码所需的信息以及优化编译的结果**。

更具体地说，它包含了以下信息：

* **编译配置标志 (Compilation Flags):**  一系列控制优化编译行为的布尔标志，例如是否启用内联、循环展开、源位置跟踪等。
* **待编译的函数信息:**  包括 `SharedFunctionInfo`（共享函数信息）、`JSFunction`（闭包）和 `BytecodeArray`（字节码数组）。这些信息描述了要进行优化的 JavaScript 函数。
* **编译目标代码信息:**  存储编译后的优化代码 (`Code` 对象)。
* **编译上下文信息:**  包括 `Context`（上下文）、`NativeContext`（原生上下文）和 `JSGlobalObject`（全局对象）。
* **WebAssembly 相关信息:**  如果正在编译 WebAssembly 代码，则包含 `WasmCompilationResult`。
* **优化过程中的辅助信息:**  例如，OSR（On-Stack Replacement，栈上替换）偏移量、内联函数列表、调试名称、性能分析数据等。
* **Bailout 信息:**  如果优化过程失败，则记录失败的原因 (`BailoutReason`).
* **Handle 管理:**  用于管理在编译过程中创建的 V8 对象句柄 (`PersistentHandles` 和 `CanonicalHandlesMap`)，防止对象被垃圾回收。

**总结来说，`OptimizedCompilationInfo` 是 V8 优化编译器（TurboFan 或 Crankshaft，取决于 V8 版本）的核心数据结构，它承载了优化编译过程的所有关键信息，并贯穿于编译的各个阶段。**

## Torque 源代码判断

`v8/src/codegen/optimized-compilation_info.h` 文件以 `.h` 结尾，而不是 `.tq`。 因此，**它不是一个 V8 Torque 源代码文件**。 Torque 文件通常用于定义 V8 内部的运行时函数和类型，并以 `.tq` 为扩展名。

## 与 JavaScript 功能的关系及示例

`OptimizedCompilationInfo` 类与 JavaScript 功能有着直接且重要的关系。它负责存储和管理优化编译 JavaScript 函数所需的信息。当 V8 发现某个 JavaScript 函数被频繁调用，或者满足某些优化条件时，就会尝试对其进行优化编译，生成更高效的机器码。`OptimizedCompilationInfo` 对象就是在这个优化编译过程中被创建和使用的。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

for (let i = 0; i < 10000; i++) {
  add(i, i + 1); // 多次调用，可能触发优化编译
}
```

在这个简单的例子中，`add` 函数会被多次调用。V8 的优化编译器可能会决定对 `add` 函数进行优化。当优化编译器开始工作时，会创建一个 `OptimizedCompilationInfo` 对象来存储关于 `add` 函数的信息，例如：

* `shared_info`: 指向 `add` 函数的共享信息，包含函数名、源代码位置等。
* `bytecode_array`: 指向 `add` 函数的字节码。
* 编译配置标志：例如是否启用内联，可能决定是否将简单的加法操作直接内联到调用位置。
* 如果优化成功，`code`: 将会指向编译后的优化机器码。
* 如果优化失败，`bailout_reason`: 将会记录失败的原因，例如参数类型不稳定。

**简单来说，`OptimizedCompilationInfo` 是 V8 将我们编写的 JavaScript 代码转换为高效机器码的关键桥梁。**

## 代码逻辑推理及示例

`OptimizedCompilationInfo` 类本身主要是一个数据容器，其核心逻辑在于对内部数据的管理和访问。 我们可以看一个简单的代码逻辑片段：

```c++
  template <typename T>
  IndirectHandle<T> CanonicalHandle(Tagged<T> object, Isolate* isolate) {
    DCHECK_NOT_NULL(canonical_handles_);
    DCHECK(PersistentHandlesScope::IsActive(isolate));
    auto find_result = canonical_handles_->FindOrInsert(object);
    if (!find_result.already_exists) {
      *find_result.entry = IndirectHandle<T>(object, isolate).location();
    }
    return IndirectHandle<T>(*find_result.entry);
  }
```

**假设输入:**

* `object`: 一个 V8 堆中的对象，例如一个字符串 `"hello"`.
* `isolate`: 当前 V8 隔离区 (Isolate) 的指针。
* `canonical_handles_`:  一个 `CanonicalHandlesMap` 对象，用于存储规范化的句柄。

**代码逻辑推理:**

1. `DCHECK_NOT_NULL(canonical_handles_);`: 断言 `canonical_handles_` 不为空。
2. `DCHECK(PersistentHandlesScope::IsActive(isolate));`: 断言当前正处于 `PersistentHandlesScope` 中。
3. `auto find_result = canonical_handles_->FindOrInsert(object);`: 尝试在 `canonical_handles_` 中查找 `object`。如果找到，返回一个迭代器指向已存在的条目，并将 `already_exists` 设置为 `true`。如果没找到，则插入 `object` 并返回一个指向新插入条目的迭代器，并将 `already_exists` 设置为 `false`。
4. `if (!find_result.already_exists) { ... }`: 如果 `object` 是新插入的（之前不存在）：
   * `*find_result.entry = IndirectHandle<T>(object, isolate).location();`: 创建一个指向 `object` 的 `IndirectHandle`，并将其内存地址存储到 `canonical_handles_` 中。
5. `return IndirectHandle<T>(*find_result.entry);`: 返回一个指向 `canonical_handles_` 中存储的地址的 `IndirectHandle`。

**输出:**

* 返回一个 `IndirectHandle<T>`，它指向 `canonical_handles_` 中存储的 `object` 的地址。如果 `object` 之前已经存在于 `canonical_handles_` 中，则返回的是指向之前存储的地址的句柄。

**这个方法的目的是确保对于同一个 V8 对象，在优化编译过程中只存在一个规范的句柄。这有助于节省内存和提高效率。**

## 用户常见的编程错误及示例

虽然开发者通常不会直接操作 `OptimizedCompilationInfo` 对象，但理解其背后的概念可以帮助避免一些与性能相关的编程错误。

**常见编程错误示例 (基于对优化编译原理的理解):**

1. **编写类型不稳定的代码:**  优化编译器通常会对类型稳定的代码进行更积极的优化。如果代码中频繁改变变量的类型，会导致优化失效，甚至触发反优化（deoptimization）。

   ```javascript
   function process(input) {
     let result;
     if (typeof input === 'number') {
       result = input * 2;
     } else if (typeof input === 'string') {
       result = input.toUpperCase();
     }
     return result;
   }

   console.log(process(10));   // 数字
   console.log(process("hello")); // 字符串
   ```

   在这个例子中，`process` 函数的 `input` 参数可以是数字或字符串。这种类型的不确定性会使优化器难以生成高效的代码。更好的做法是编写针对特定类型或使用类型检查并针对不同类型进行优化的代码。

2. **在热点代码中创建大量临时对象:** 频繁创建和销毁对象会增加垃圾回收的压力，影响性能。优化编译器会尝试减少对象的分配，但如果代码本身就存在大量临时对象创建，优化效果会受到限制。

   ```javascript
   function calculateSum(arr) {
     let sum = 0;
     for (let i = 0; i < arr.length; i++) {
       const temp = { value: arr[i] }; // 每次循环创建一个新对象
       sum += temp.value;
     }
     return sum;
   }

   const numbers = [1, 2, 3, 4, 5];
   console.log(calculateSum(numbers));
   ```

   在这个例子中，循环内部每次都创建一个新的对象 `temp`。如果循环次数很多，会产生大量的临时对象。可以考虑避免创建不必要的对象。

3. **过度依赖动态特性:** JavaScript 的动态特性（如动态添加属性）虽然灵活，但也可能阻碍优化。优化编译器更擅长处理结构固定的对象。

   ```javascript
   function createPoint(x, y) {
     const point = {};
     point.x = x;
     point.y = y;
     return point;
   }

   const p1 = createPoint(1, 2);
   p1.z = 3; // 动态添加属性
   ```

   在 `createPoint` 函数创建对象后，又动态地添加了属性 `z`。这会使 V8 难以预测对象的结构，从而影响优化。

**总结:** 了解 `OptimizedCompilationInfo` 以及 V8 优化编译的原理，可以帮助开发者编写更易于优化的 JavaScript 代码，从而提升应用程序的性能。避免类型不稳定、减少临时对象创建、以及谨慎使用动态特性是常见的优化策略。

### 提示词
```
这是目录为v8/src/codegen/optimized-compilation-info.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/optimized-compilation-info.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_OPTIMIZED_COMPILATION_INFO_H_
#define V8_CODEGEN_OPTIMIZED_COMPILATION_INFO_H_

#include <memory>

#include "src/base/vector.h"
#include "src/codegen/bailout-reason.h"
#include "src/codegen/source-position-table.h"
#include "src/codegen/tick-counter.h"
#include "src/common/globals.h"
#include "src/diagnostics/basic-block-profiler.h"
#include "src/execution/frames.h"
#include "src/handles/handles.h"
#include "src/handles/persistent-handles.h"
#include "src/objects/objects.h"
#include "src/objects/tagged.h"
#include "src/utils/identity-map.h"
#include "src/utils/utils.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-builtin-list.h"
#endif

namespace v8 {

namespace tracing {
class TracedValue;
}  // namespace tracing

namespace internal {

class FunctionLiteral;
class Isolate;
class JavaScriptFrame;
class JSGlobalObject;
class Zone;

namespace compiler {
class NodeObserver;
class JSHeapBroker;
}

namespace wasm {
struct WasmCompilationResult;
}  // namespace wasm

// OptimizedCompilationInfo encapsulates the information needed to compile
// optimized code for a given function, and the results of the optimized
// compilation.
class V8_EXPORT_PRIVATE OptimizedCompilationInfo final {
 public:
  // Various configuration flags for a compilation, as well as some properties
  // of the compiled code produced by a compilation.

#define FLAGS(V)                                                      \
  V(FunctionContextSpecializing, function_context_specializing, 0)    \
  V(Inlining, inlining, 1)                                            \
  V(DisableFutureOptimization, disable_future_optimization, 2)        \
  V(Splitting, splitting, 3)                                          \
  V(SourcePositions, source_positions, 4)                             \
  V(BailoutOnUninitialized, bailout_on_uninitialized, 5)              \
  V(LoopPeeling, loop_peeling, 6)                                     \
  V(SwitchJumpTable, switch_jump_table, 7)                            \
  V(CalledWithCodeStartRegister, called_with_code_start_register, 8)  \
  V(AllocationFolding, allocation_folding, 9)                         \
  V(AnalyzeEnvironmentLiveness, analyze_environment_liveness, 10)     \
  V(TraceTurboJson, trace_turbo_json, 11)                             \
  V(TraceTurboGraph, trace_turbo_graph, 12)                           \
  V(TraceTurboScheduled, trace_turbo_scheduled, 13)                   \
  V(TraceTurboAllocation, trace_turbo_allocation, 14)                 \
  V(TraceHeapBroker, trace_heap_broker, 15)                           \
  V(DiscardResultForTesting, discard_result_for_testing, 16)          \
  V(InlineJSWasmCalls, inline_js_wasm_calls, 17)                      \
  V(TurboshaftTraceReduction, turboshaft_trace_reduction, 18)         \
  V(CouldNotInlineAllCandidates, could_not_inline_all_candidates, 19) \
  V(ShadowStackCompliantLazyDeopt, shadow_stack_compliant_lazy_deopt, 20)

  enum Flag {
#define DEF_ENUM(Camel, Lower, Bit) k##Camel = 1 << Bit,
    FLAGS(DEF_ENUM)
#undef DEF_ENUM
  };

#define DEF_GETTER(Camel, Lower, Bit) \
  bool Lower() const {                \
    return GetFlag(k##Camel);         \
  }
  FLAGS(DEF_GETTER)
#undef DEF_GETTER

#define DEF_SETTER(Camel, Lower, Bit) \
  void set_##Lower() {                \
    SetFlag(k##Camel);                \
  }
  FLAGS(DEF_SETTER)
#undef DEF_SETTER

  // Construct a compilation info for optimized compilation.
  OptimizedCompilationInfo(Zone* zone, Isolate* isolate,
                           IndirectHandle<SharedFunctionInfo> shared,
                           IndirectHandle<JSFunction> closure,
                           CodeKind code_kind, BytecodeOffset osr_offset);
  // For testing.
  OptimizedCompilationInfo(Zone* zone, Isolate* isolate,
                           IndirectHandle<SharedFunctionInfo> shared,
                           IndirectHandle<JSFunction> closure,
                           CodeKind code_kind)
      : OptimizedCompilationInfo(zone, isolate, shared, closure, code_kind,
                                 BytecodeOffset::None()) {}
  // Construct a compilation info for stub compilation, Wasm, and testing.
  OptimizedCompilationInfo(base::Vector<const char> debug_name, Zone* zone,
                           CodeKind code_kind,
                           Builtin builtin = Builtin::kNoBuiltinId);

  OptimizedCompilationInfo(const OptimizedCompilationInfo&) = delete;
  OptimizedCompilationInfo& operator=(const OptimizedCompilationInfo&) = delete;

  ~OptimizedCompilationInfo();

  Zone* zone() { return zone_; }
  bool is_osr() const { return !osr_offset_.IsNone(); }
  IndirectHandle<SharedFunctionInfo> shared_info() const {
    return shared_info_;
  }
  bool has_shared_info() const { return !shared_info().is_null(); }
  IndirectHandle<BytecodeArray> bytecode_array() const {
    return bytecode_array_;
  }
  bool has_bytecode_array() const { return !bytecode_array_.is_null(); }
  IndirectHandle<JSFunction> closure() const { return closure_; }
  IndirectHandle<Code> code() const { return code_; }
  CodeKind code_kind() const { return code_kind_; }
  Builtin builtin() const { return builtin_; }
  void set_builtin(Builtin builtin) { builtin_ = builtin; }
  BytecodeOffset osr_offset() const { return osr_offset_; }
  void SetNodeObserver(compiler::NodeObserver* observer) {
    DCHECK_NULL(node_observer_);
    node_observer_ = observer;
  }
  compiler::NodeObserver* node_observer() const { return node_observer_; }

  // Code getters and setters.

  void SetCode(IndirectHandle<Code> code);

#if V8_ENABLE_WEBASSEMBLY
  void SetWasmCompilationResult(std::unique_ptr<wasm::WasmCompilationResult>);
  std::unique_ptr<wasm::WasmCompilationResult> ReleaseWasmCompilationResult();
#endif  // V8_ENABLE_WEBASSEMBLY

  bool has_context() const;
  Tagged<Context> context() const;

  bool has_native_context() const;
  Tagged<NativeContext> native_context() const;

  bool has_global_object() const;
  Tagged<JSGlobalObject> global_object() const;

  // Accessors for the different compilation modes.
  bool IsOptimizing() const {
    return CodeKindIsOptimizedJSFunction(code_kind());
  }
#if V8_ENABLE_WEBASSEMBLY
  bool IsWasm() const { return code_kind() == CodeKind::WASM_FUNCTION; }
  bool IsWasmBuiltin() const {
    return code_kind() == CodeKind::WASM_TO_JS_FUNCTION ||
           code_kind() == CodeKind::WASM_TO_CAPI_FUNCTION ||
           code_kind() == CodeKind::JS_TO_WASM_FUNCTION ||
           (code_kind() == CodeKind::BUILTIN &&
            (builtin() == Builtin::kJSToWasmWrapper ||
             builtin() == Builtin::kJSToWasmHandleReturns ||
             builtin() == Builtin::kWasmToJsWrapperCSA ||
             wasm::BuiltinLookup::IsWasmBuiltinId(builtin())));
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  void set_persistent_handles(
      std::unique_ptr<PersistentHandles> persistent_handles) {
    DCHECK_NULL(ph_);
    ph_ = std::move(persistent_handles);
    DCHECK_NOT_NULL(ph_);
  }

  void set_canonical_handles(
      std::unique_ptr<CanonicalHandlesMap> canonical_handles) {
    DCHECK_NULL(canonical_handles_);
    canonical_handles_ = std::move(canonical_handles);
    DCHECK_NOT_NULL(canonical_handles_);
  }

  template <typename T>
  IndirectHandle<T> CanonicalHandle(Tagged<T> object, Isolate* isolate) {
    DCHECK_NOT_NULL(canonical_handles_);
    DCHECK(PersistentHandlesScope::IsActive(isolate));
    auto find_result = canonical_handles_->FindOrInsert(object);
    if (!find_result.already_exists) {
      *find_result.entry = IndirectHandle<T>(object, isolate).location();
    }
    return IndirectHandle<T>(*find_result.entry);
  }

  void ReopenAndCanonicalizeHandlesInNewScope(Isolate* isolate);

  void AbortOptimization(BailoutReason reason);

  void RetryOptimization(BailoutReason reason);

  BailoutReason bailout_reason() const { return bailout_reason_; }

  int optimization_id() const {
    DCHECK(IsOptimizing());
    return optimization_id_;
  }

  unsigned inlined_bytecode_size() const { return inlined_bytecode_size_; }

  void set_inlined_bytecode_size(unsigned size) {
    inlined_bytecode_size_ = size;
  }

  struct InlinedFunctionHolder {
    IndirectHandle<SharedFunctionInfo> shared_info;
    IndirectHandle<BytecodeArray>
        bytecode_array;  // Explicit to prevent flushing.
    InliningPosition position;

    InlinedFunctionHolder(
        IndirectHandle<SharedFunctionInfo> inlined_shared_info,
        IndirectHandle<BytecodeArray> inlined_bytecode, SourcePosition pos);

    void RegisterInlinedFunctionId(size_t inlined_function_id) {
      position.inlined_function_id = static_cast<int>(inlined_function_id);
    }
  };

  using InlinedFunctionList = std::vector<InlinedFunctionHolder>;
  InlinedFunctionList& inlined_functions() { return inlined_functions_; }

  // Returns the inlining id for source position tracking.
  int AddInlinedFunction(IndirectHandle<SharedFunctionInfo> inlined_function,
                         IndirectHandle<BytecodeArray> inlined_bytecode,
                         SourcePosition pos);

  std::unique_ptr<char[]> GetDebugName() const;

  StackFrame::Type GetOutputStackFrameType() const;

  const char* trace_turbo_filename() const {
    return trace_turbo_filename_.get();
  }

  void set_trace_turbo_filename(std::unique_ptr<char[]> filename) {
    trace_turbo_filename_ = std::move(filename);
  }

  TickCounter& tick_counter() { return tick_counter_; }

  BasicBlockProfilerData* profiler_data() const { return profiler_data_; }
  void set_profiler_data(BasicBlockProfilerData* profiler_data) {
    profiler_data_ = profiler_data;
  }

  std::unique_ptr<PersistentHandles> DetachPersistentHandles() {
    DCHECK_NOT_NULL(ph_);
    return std::move(ph_);
  }

  std::unique_ptr<CanonicalHandlesMap> DetachCanonicalHandles() {
    DCHECK_NOT_NULL(canonical_handles_);
    return std::move(canonical_handles_);
  }

 private:
  void ConfigureFlags();

  void SetFlag(Flag flag) { flags_ |= flag; }
  bool GetFlag(Flag flag) const { return (flags_ & flag) != 0; }

  void SetTracingFlags(bool passes_filter);

  // Storing the raw pointer to the CanonicalHandlesMap is generally not safe.
  // Use DetachCanonicalHandles() to transfer ownership instead.
  // We explicitly allow the JSHeapBroker to store the raw pointer as it is
  // guaranteed that the OptimizedCompilationInfo's lifetime exceeds the
  // lifetime of the broker.
  CanonicalHandlesMap* canonical_handles() { return canonical_handles_.get(); }
  friend class compiler::JSHeapBroker;

  // Compilation flags.
  unsigned flags_ = 0;

  // Take care when accessing this on any background thread.
  Isolate* const isolate_unsafe_;

  const CodeKind code_kind_;
  Builtin builtin_ = Builtin::kNoBuiltinId;

  // We retain a reference the bytecode array specifically to ensure it doesn't
  // get flushed while we are optimizing the code.
  IndirectHandle<BytecodeArray> bytecode_array_;
  IndirectHandle<SharedFunctionInfo> shared_info_;
  IndirectHandle<JSFunction> closure_;

  // The compiled code.
  IndirectHandle<Code> code_;

  // Basic block profiling support.
  BasicBlockProfilerData* profiler_data_ = nullptr;

#if V8_ENABLE_WEBASSEMBLY
  // The WebAssembly compilation result, not published in the NativeModule yet.
  std::unique_ptr<wasm::WasmCompilationResult> wasm_compilation_result_;
#endif  // V8_ENABLE_WEBASSEMBLY

  // Entry point when compiling for OSR, {BytecodeOffset::None} otherwise.
  const BytecodeOffset osr_offset_ = BytecodeOffset::None();

  // The zone from which the compilation pipeline working on this
  // OptimizedCompilationInfo allocates.
  Zone* const zone_;

  compiler::NodeObserver* node_observer_ = nullptr;

  BailoutReason bailout_reason_ = BailoutReason::kNoReason;

  InlinedFunctionList inlined_functions_;

  static constexpr int kNoOptimizationId = -1;
  const int optimization_id_;
  unsigned inlined_bytecode_size_ = 0;

  base::Vector<const char> debug_name_;
  std::unique_ptr<char[]> trace_turbo_filename_;

  TickCounter tick_counter_;

  // 1) PersistentHandles created via PersistentHandlesScope inside of
  //    CompilationHandleScope
  // 2) Owned by OptimizedCompilationInfo
  // 3) Owned by the broker's LocalHeap when entering the LocalHeapScope.
  // 4) Back to OptimizedCompilationInfo when exiting the LocalHeapScope.
  //
  // In normal execution it gets destroyed when PipelineData gets destroyed.
  // There is a special case in GenerateCodeForTesting where the JSHeapBroker
  // will not be retired in that same method. In this case, we need to re-attach
  // the PersistentHandles container to the JSHeapBroker.
  std::unique_ptr<PersistentHandles> ph_;

  // Canonical handles follow the same path as described by the persistent
  // handles above. The only difference is that is created in the
  // CanonicalHandleScope(i.e step 1) is different).
  std::unique_ptr<CanonicalHandlesMap> canonical_handles_;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_CODEGEN_OPTIMIZED_COMPILATION_INFO_H_
```