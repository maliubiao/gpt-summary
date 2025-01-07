Response: Let's break down the thought process for analyzing the C++ code and generating the summary and JavaScript examples.

1. **Initial Skim and Keyword Recognition:**  The first step is a quick read-through, looking for recurring keywords and patterns. Immediately, terms like "JSFunction", "CodeKind", "bytecode", "optimized code", "feedback vector", "tiering", "prototype", "name", and "length" stand out. The `#include` directives also give hints about related areas (e.g., `compiler.h`, `execution/`, `heap/`).

2. **Focusing on the Core Entity:** The file is named `js-function.cc`, so the primary focus is clearly on how V8 represents and manages JavaScript functions internally. The `namespace v8::internal` confirms this is an internal V8 implementation detail.

3. **Analyzing Key Methods and their Functionality:**  The next step is to examine the prominent methods and their purpose. This involves understanding what data they access and what transformations or checks they perform.

    * **`GetAttachedCodeKinds` and `GetAvailableCodeKinds`:** These methods deal with different versions of compiled code (interpreter, baseline, optimized). The "attached" vs. "available" distinction is crucial. "Attached" means the function *currently* has that code, while "available" means it *could* have it (e.g., the bytecode is present).

    * **`HasAttachedOptimizedCode`, `HasAvailableHigherTierCodeThan`, `HasAvailableOptimizedCode`, `HasAttachedCodeKind`, `HasAvailableCodeKind`:** These are all boolean checks related to the presence or availability of different code tiers. The names are fairly self-explanatory.

    * **`GetActiveTier`:** This determines the currently executing version of the function's code. The conditional logic (e.g., `#if V8_ENABLE_WEBASSEMBLY`) hints at platform-specific considerations.

    * **`RequestOptimization`:** This function is clearly about triggering the compilation of a function to a higher tier. The `ConcurrencyMode` argument suggests background compilation.

    * **`CopyNameAndLength`:** This function manages the `name` and `length` properties of JavaScript functions, taking into account things like bound functions and wrapped functions.

    * **`GetName` and `GetLength` (for `JSBoundFunction` and `JSWrappedFunction`):** These handle the specific logic for retrieving the `name` and `length` of bound and wrapped functions, which involve traversing the chain of wrapping/binding.

    * **`Create` (for `JSWrappedFunction`):** This deals with the creation of wrapped functions, used for security and sandboxing.

    * **`EnsureClosureFeedbackCellArray` and `EnsureFeedbackVector`:** These methods are about setting up the feedback mechanisms used by V8's optimizing compilers to gather type information.

    * **`SetPrototype` and `SetInitialMap`:** These are fundamental for object creation in JavaScript, dealing with the `prototype` property and the initial map (shape) of objects created by a constructor.

    * **`GetDerivedMap`:** This is more complex, handling the creation of specialized maps for subclasses.

    * **`ToString`:**  This controls how a JavaScript function is represented as a string, considering native code, class syntax, and source code availability.

    * **`CalculateExpectedNofProperties`:**  This method aims to estimate the number of properties an object created by a constructor will have, influencing the initial size of the object.

4. **Identifying Relationships to JavaScript:** As each method is analyzed, it's important to think about the corresponding JavaScript behavior. For example:

    * Code tiering directly relates to V8's optimization process, which is transparent to the JavaScript developer but affects performance.
    * `name` and `length` are standard JavaScript properties of functions.
    * Bound functions (using `bind()`) and wrapped functions (less common in typical JS but used internally) have specific naming and length behaviors.
    * Prototypes and constructors are core object-oriented concepts in JavaScript.
    * The `toString()` method of functions is a standard part of the language.

5. **Formulating the Summary:** Based on the analysis, the key functionalities can be grouped and summarized. The summary should highlight the main responsibilities of the file, focusing on the management of JavaScript functions within the V8 engine. Emphasizing the connection between internal mechanisms (like code tiering and feedback) and observable JavaScript behavior is important.

6. **Creating JavaScript Examples:**  The examples should be simple and directly illustrate the concepts discussed in the summary. For each major functionality identified, a corresponding JavaScript code snippet can be crafted. It's good to choose examples that are easy to understand and demonstrate the feature clearly. For instance:

    * Code tiering: Show a function being called repeatedly to trigger optimization.
    * `name` and `length`:  Demonstrate accessing these properties.
    * Bound functions:  Use `bind()` and check the resulting function's name and length.
    * Prototypes:  Show how to access and modify the prototype.
    * `toString()`: Call `toString()` on a function to see its representation.

7. **Refining and Iterating:** After drafting the summary and examples, review them for clarity, accuracy, and completeness. Ensure the examples accurately reflect the C++ code's functionality and that the summary provides a good overview. For example, ensure the explanation of "attached" vs. "available" code is clear. Make sure the examples are valid JavaScript and directly relate to the C++ concepts.

This iterative process of skimming, analyzing, connecting to JavaScript, summarizing, and illustrating with examples allows for a comprehensive understanding of the C++ code's role and its relationship to the JavaScript language.
这个C++源代码文件 `v8/src/objects/js-function.cc` 负责实现 **JavaScript 函数 (JSFunction)** 对象在 V8 引擎中的表示和相关操作。它定义了 `JSFunction` 类的结构和方法，这些方法用于管理函数的代码、优化、属性（如 `name` 和 `length`）、原型以及与其他 V8 内部机制的交互。

以下是该文件主要功能的归纳：

**1. 函数代码管理与优化：**

* **代码状态查询:**  提供了多种方法来查询函数当前拥有的代码类型 (解释执行、基线编译、优化编译等) 以及可用的代码类型。例如：
    * `GetAttachedCodeKinds()`: 获取当前附加到函数的代码类型。
    * `GetAvailableCodeKinds()`: 获取当前可用于该函数的代码类型 (可能尚未附加)。
    * `HasAttachedOptimizedCode()`, `HasAvailableOptimizedCode()`:  检查是否拥有或可用优化代码。
    * `GetActiveTier()`:  确定函数当前正在执行的代码层级。
* **优化请求:** 提供了请求 V8 对函数进行优化的机制：
    * `RequestOptimization()`:  触发函数向更高代码层级的编译。
* **代码废弃:** 提供了判断是否可以丢弃已编译代码的方法：
    * `CanDiscardCompiled()`: 判断是否可以安全地丢弃该函数的已编译代码。
* **中断预算:** 管理函数执行的中断预算，用于控制优化和垃圾回收的时机。
    * `SetInterruptBudget()`: 设置函数的中断预算。

**2. 函数属性管理：**

* **`name` 和 `length` 属性:**  实现了获取和设置 JavaScript 函数的 `name` (函数名) 和 `length` (形参个数) 属性的逻辑，包括处理绑定函数和包装函数的特殊情况。
    * `GetName()`: 获取函数名。
    * `GetLength()`: 获取函数形参个数。
    * `CopyNameAndLength()`:  用于复制目标对象的 `name` 和 `length` 属性到当前函数对象。
    * `SetName()`: 设置函数名。
* **`toString()` 方法:**  实现了 JavaScript 函数的 `toString()` 方法，用于返回函数的字符串表示形式，包括处理原生代码和用户定义代码的情况。

**3. 函数原型与对象创建：**

* **原型管理:** 负责管理函数的 `prototype` 属性，这是实现 JavaScript 原型继承的关键。
    * `SetPrototype()`: 设置函数的原型对象。
    * `SetInitialMap()`: 设置构造函数创建的对象的初始 Map (对象形状)。
    * `EnsureHasInitialMap()`: 确保函数拥有初始 Map。
    * `GetDerivedMap()`:  获取派生类构造函数创建对象的 Map。
* **对象大小计算:**  提供了计算函数作为构造函数创建的对象实例大小的方法。
    * `CalculateInstanceSizeHelper()`: 辅助计算实例大小。
    * `ComputeInstanceSizeWithMinSlack()`: 计算实例大小，考虑最小的空闲空间。
    * `CalculateExpectedNofProperties()`: 预测构造函数创建的对象可能拥有的属性数量。

**4. 反馈机制：**

* **反馈向量:**  实现了与反馈向量 (Feedback Vector) 相关的操作，反馈向量用于存储函数执行时的类型信息，帮助 V8 进行优化。
    * `EnsureFeedbackVector()`: 确保函数拥有反馈向量。
    * `CreateAndAttachFeedbackVector()`: 创建并附加反馈向量到函数。
    * `InitializeFeedbackCell()`: 初始化函数的反馈单元。
    * `EnsureClosureFeedbackCellArray()`: 确保函数拥有闭包反馈单元数组。
    * `ClearAllTypeFeedbackInfoForTesting()`:  用于测试，清除所有类型反馈信息。

**5. 其他功能：**

* **绑定函数和包装函数:**  实现了对绑定函数 (`JSBoundFunction`) 和包装函数 (`JSWrappedFunction`) 的特殊处理。
* **本地代码判断:**  用于判断函数是否为原生代码。
* **调试支持:**  提供获取调试名称的方法。
* **WebAssembly 支持:**  在 `#ifdef V8_ENABLE_WEBASSEMBLY` 中包含对 WebAssembly 函数的特殊处理。

**与 JavaScript 功能的关系及 JavaScript 示例：**

该文件是 V8 引擎实现 JavaScript 函数的核心部分，因此其功能与 JavaScript 的函数特性息息相关。以下是一些 JavaScript 示例，展示了该文件中 C++ 代码所支持的 JavaScript 功能：

**1. 代码优化 (涉及 `GetAvailableCodeKinds`, `RequestOptimization`, `GetActiveTier` 等):**

```javascript
function add(a, b) {
  return a + b;
}

// V8 会根据函数的调用次数和执行情况，将其从解释执行逐步优化到基线编译，最终可能优化到 TurboFan。
for (let i = 0; i < 10000; i++) {
  add(i, i + 1);
}
```

**2. `name` 和 `length` 属性 (涉及 `GetName`, `GetLength`):**

```javascript
function myFunction(a, b, c) {
  // ...
}

console.log(myFunction.name);   // 输出 "myFunction"
console.log(myFunction.length); // 输出 3

const boundFunction = myFunction.bind(null, 1);
console.log(boundFunction.name);  // 输出 "bound myFunction" (取决于 V8 版本)
console.log(boundFunction.length); // 输出 2 (因为绑定了一个参数)
```

**3. `prototype` 属性和原型继承 (涉及 `SetPrototype`, `GetDerivedMap`):**

```javascript
function Animal(name) {
  this.name = name;
}

Animal.prototype.speak = function() {
  console.log("Generic animal sound");
};

function Dog(name, breed) {
  Animal.call(this, name);
  this.breed = breed;
}

// 设置 Dog 的原型为 Animal 的实例，实现继承
Dog.prototype = new Animal();
Dog.prototype.constructor = Dog; // 修正 constructor 指向

Dog.prototype.speak = function() {
  console.log("Woof!");
};

const myDog = new Dog("Buddy", "Golden Retriever");
myDog.speak(); // 输出 "Woof!"
```

**4. `toString()` 方法 (涉及 `ToString`):**

```javascript
function greet(name) {
  console.log(`Hello, ${name}!`);
}

console.log(greet.toString());
// 可能输出: "function greet(name) {\n  console.log(`Hello, ${name}!`);\n}"

console.log(Math.sin.toString());
// 可能输出: "function sin() { [native code] }"
```

**5. 绑定函数 (涉及 `JSBoundFunction`):**

```javascript
function multiply(a, b) {
  return a * b;
}

const multiplyByFive = multiply.bind(null, 5);
console.log(multiplyByFive(3)); // 输出 15
```

**总结:**

`v8/src/objects/js-function.cc` 文件是 V8 引擎中关于 JavaScript 函数对象的核心实现。它负责函数的代码管理、优化、属性维护、原型链构建以及与 V8 内部优化机制的集成。理解这个文件的功能有助于深入了解 V8 如何执行和优化 JavaScript 代码。文件中定义的 C++ 类和方法直接支持了 JavaScript 中我们日常使用的函数特性。

Prompt: 
```
这是目录为v8/src/objects/js-function.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/js-function.h"

#include <optional>

#include "src/baseline/baseline-batch-compiler.h"
#include "src/codegen/compiler.h"
#include "src/common/globals.h"
#include "src/diagnostics/code-tracer.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate.h"
#include "src/execution/tiering-manager.h"
#include "src/heap/heap-inl.h"
#include "src/ic/ic.h"
#include "src/init/bootstrapper.h"
#include "src/objects/feedback-cell-inl.h"
#include "src/strings/string-builder-inl.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

CodeKinds JSFunction::GetAttachedCodeKinds(IsolateForSandbox isolate) const {
  const CodeKind kind = code(isolate)->kind();
  if (!CodeKindIsJSFunction(kind)) return {};
  if (CodeKindIsOptimizedJSFunction(kind) &&
      code(isolate)->marked_for_deoptimization()) {
    return {};
  }
  return CodeKindToCodeKindFlag(kind);
}

CodeKinds JSFunction::GetAvailableCodeKinds(IsolateForSandbox isolate) const {
  CodeKinds result = GetAttachedCodeKinds(isolate);

  if ((result & CodeKindFlag::INTERPRETED_FUNCTION) == 0) {
    // The SharedFunctionInfo could have attached bytecode.
    if (shared()->HasBytecodeArray()) {
      result |= CodeKindFlag::INTERPRETED_FUNCTION;
    }
  }

  if ((result & CodeKindFlag::BASELINE) == 0) {
    // The SharedFunctionInfo could have attached baseline code.
    if (shared()->HasBaselineCode()) {
      result |= CodeKindFlag::BASELINE;
    }
  }

#ifndef V8_ENABLE_LEAPTIERING
  // Check the optimized code cache.
  if (has_feedback_vector() && feedback_vector()->has_optimized_code() &&
      !feedback_vector()
           ->optimized_code(isolate)
           ->marked_for_deoptimization()) {
    Tagged<Code> code = feedback_vector()->optimized_code(isolate);
    DCHECK(CodeKindIsOptimizedJSFunction(code->kind()));
    result |= CodeKindToCodeKindFlag(code->kind());
  }
#endif  // !V8_ENABLE_LEAPTIERING

  DCHECK_EQ((result & ~kJSFunctionCodeKindsMask), 0);
  return result;
}

bool JSFunction::HasAttachedOptimizedCode(IsolateForSandbox isolate) const {
  CodeKinds result = GetAttachedCodeKinds(isolate);
  return (result & kOptimizedJSFunctionCodeKindsMask) != 0;
}

bool JSFunction::HasAvailableHigherTierCodeThan(IsolateForSandbox isolate,
                                                CodeKind kind) const {
  return HasAvailableHigherTierCodeThanWithFilter(isolate, kind,
                                                  kJSFunctionCodeKindsMask);
}

bool JSFunction::HasAvailableHigherTierCodeThanWithFilter(
    IsolateForSandbox isolate, CodeKind kind, CodeKinds filter_mask) const {
  const int kind_as_int_flag = static_cast<int>(CodeKindToCodeKindFlag(kind));
  DCHECK(base::bits::IsPowerOfTwo(kind_as_int_flag));
  // Smear right - any higher present bit means we have a higher tier available.
  const int mask = kind_as_int_flag | (kind_as_int_flag - 1);
  const CodeKinds masked_available_kinds =
      GetAvailableCodeKinds(isolate) & filter_mask;
  return (masked_available_kinds & static_cast<CodeKinds>(~mask)) != 0;
}

bool JSFunction::HasAvailableOptimizedCode(IsolateForSandbox isolate) const {
  CodeKinds result = GetAvailableCodeKinds(isolate);
  return (result & kOptimizedJSFunctionCodeKindsMask) != 0;
}

bool JSFunction::HasAttachedCodeKind(IsolateForSandbox isolate,
                                     CodeKind kind) const {
  CodeKinds result = GetAttachedCodeKinds(isolate);
  return (result & CodeKindToCodeKindFlag(kind)) != 0;
}

bool JSFunction::HasAvailableCodeKind(IsolateForSandbox isolate,
                                      CodeKind kind) const {
  CodeKinds result = GetAvailableCodeKinds(isolate);
  return (result & CodeKindToCodeKindFlag(kind)) != 0;
}

namespace {

// Returns false if no highest tier exists (i.e. the function is not compiled),
// otherwise returns true and sets highest_tier.
V8_WARN_UNUSED_RESULT bool HighestTierOf(CodeKinds kinds,
                                         CodeKind* highest_tier) {
  DCHECK_EQ((kinds & ~kJSFunctionCodeKindsMask), 0);
  // Higher tiers > lower tiers.
  static_assert(CodeKind::TURBOFAN_JS > CodeKind::INTERPRETED_FUNCTION);
  if (kinds == 0) return false;
  const int highest_tier_log2 =
      31 - base::bits::CountLeadingZeros(static_cast<uint32_t>(kinds));
  DCHECK(CodeKindIsJSFunction(static_cast<CodeKind>(highest_tier_log2)));
  *highest_tier = static_cast<CodeKind>(highest_tier_log2);
  return true;
}

}  // namespace

std::optional<CodeKind> JSFunction::GetActiveTier(
    IsolateForSandbox isolate) const {
#if V8_ENABLE_WEBASSEMBLY
  // Asm/Wasm functions are currently not supported. For simplicity, this
  // includes invalid asm.js functions whose code hasn't yet been updated to
  // CompileLazy but is still the InstantiateAsmJs builtin.
  if (shared()->HasAsmWasmData() ||
      code(isolate)->builtin_id() == Builtin::kInstantiateAsmJs) {
    return {};
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  CodeKind highest_tier;
  if (!HighestTierOf(GetAvailableCodeKinds(isolate), &highest_tier)) return {};

#ifdef DEBUG
  CHECK(highest_tier == CodeKind::TURBOFAN_JS ||
        highest_tier == CodeKind::BASELINE ||
        highest_tier == CodeKind::MAGLEV ||
        highest_tier == CodeKind::INTERPRETED_FUNCTION);

  if (highest_tier == CodeKind::INTERPRETED_FUNCTION) {
    CHECK(code(isolate)->is_interpreter_trampoline_builtin() ||
          (CodeKindIsOptimizedJSFunction(code(isolate)->kind()) &&
           code(isolate)->marked_for_deoptimization()) ||
          (code(isolate)->builtin_id() == Builtin::kCompileLazy &&
           shared()->HasBytecodeArray() && !shared()->HasBaselineCode()));
  }
#endif  // DEBUG

  return highest_tier;
}

bool JSFunction::ActiveTierIsIgnition(IsolateForSandbox isolate) const {
  return GetActiveTier(isolate) == CodeKind::INTERPRETED_FUNCTION;
}

bool JSFunction::ActiveTierIsBaseline(IsolateForSandbox isolate) const {
  return GetActiveTier(isolate) == CodeKind::BASELINE;
}

bool JSFunction::ActiveTierIsMaglev(IsolateForSandbox isolate) const {
  return GetActiveTier(isolate) == CodeKind::MAGLEV;
}

bool JSFunction::ActiveTierIsTurbofan(IsolateForSandbox isolate) const {
  return GetActiveTier(isolate) == CodeKind::TURBOFAN_JS;
}

bool JSFunction::CanDiscardCompiled(IsolateForSandbox isolate) const {
  // Essentially, what we are asking here is, has this function been compiled
  // from JS code? We can currently tell only indirectly, by looking at
  // available code kinds. If any JS code kind exists, we can discard.
  //
  // Attached optimized code that is marked for deoptimization will not show up
  // in the list of available code kinds, thus we must check for it manually.
  //
  // Note that when the function has not yet been compiled we also return
  // false; that's fine, since nothing must be discarded in that case.
  if (CodeKindIsOptimizedJSFunction(code(isolate)->kind())) return true;
  CodeKinds result = GetAvailableCodeKinds(isolate);
  return (result & kJSFunctionCodeKindsMask) != 0;
}

namespace {

#ifndef V8_ENABLE_LEAPTIERING
constexpr TieringState TieringStateFor(CodeKind target_kind,
                                       ConcurrencyMode mode) {
  DCHECK(target_kind == CodeKind::MAGLEV ||
         target_kind == CodeKind::TURBOFAN_JS);
  return target_kind == CodeKind::MAGLEV
             ? (IsConcurrent(mode) ? TieringState::kRequestMaglev_Concurrent
                                   : TieringState::kRequestMaglev_Synchronous)
             : (IsConcurrent(mode)
                    ? TieringState::kRequestTurbofan_Concurrent
                    : TieringState::kRequestTurbofan_Synchronous);
}
#endif  // !V8_ENABLE_LEAPTIERING

}  // namespace

void JSFunction::RequestOptimization(Isolate* isolate, CodeKind target_kind,
                                     ConcurrencyMode mode) {
  if (!isolate->concurrent_recompilation_enabled() ||
      isolate->bootstrapper()->IsActive()) {
    mode = ConcurrencyMode::kSynchronous;
  }

  DCHECK(CodeKindIsOptimizedJSFunction(target_kind));
  DCHECK(!is_compiled(isolate) || ActiveTierIsIgnition(isolate) ||
         ActiveTierIsBaseline(isolate) || ActiveTierIsMaglev(isolate));
  DCHECK(!ActiveTierIsTurbofan(isolate));
  DCHECK(shared()->HasBytecodeArray());
  DCHECK(shared()->allows_lazy_compilation() ||
         !shared()->optimization_disabled());

  if (IsConcurrent(mode)) {
    if (tiering_in_progress()) {
      if (v8_flags.trace_concurrent_recompilation) {
        PrintF("  ** Not marking ");
        ShortPrint(*this);
        PrintF(" -- already in optimization queue.\n");
      }
      return;
    }
    if (v8_flags.trace_concurrent_recompilation) {
      PrintF("  ** Marking ");
      ShortPrint(*this);
      PrintF(" for concurrent %s recompilation.\n",
             CodeKindToString(target_kind));
    }
  }

#ifdef V8_ENABLE_LEAPTIERING
  JSDispatchTable* jdt = GetProcessWideJSDispatchTable();
  switch (target_kind) {
    case CodeKind::MAGLEV:
      switch (mode) {
        case ConcurrencyMode::kConcurrent:
          DCHECK(!HasAvailableCodeKind(isolate, CodeKind::MAGLEV));
          DCHECK(!HasAvailableCodeKind(isolate, CodeKind::TURBOFAN_JS));
          DCHECK(!IsOptimizationRequested(isolate));
          jdt->SetTieringRequest(dispatch_handle(),
                                 TieringBuiltin::kStartMaglevOptimizationJob,
                                 isolate);
          break;
        case ConcurrencyMode::kSynchronous:
          jdt->SetTieringRequest(dispatch_handle(),
                                 TieringBuiltin::kOptimizeMaglevEager, isolate);
          break;
      }
      break;
    case CodeKind::TURBOFAN_JS:
      switch (mode) {
        case ConcurrencyMode::kConcurrent:
          DCHECK(!IsOptimizationRequested(isolate));
          DCHECK(!HasAvailableCodeKind(isolate, CodeKind::TURBOFAN_JS));
          jdt->SetTieringRequest(dispatch_handle(),
                                 TieringBuiltin::kStartTurbofanOptimizationJob,
                                 isolate);
          break;
        case ConcurrencyMode::kSynchronous:
          jdt->SetTieringRequest(dispatch_handle(),
                                 TieringBuiltin::kOptimizeTurbofanEager,
                                 isolate);
          break;
      }
      break;
    default:
      UNREACHABLE();
  }
#else
  set_tiering_state(isolate, TieringStateFor(target_kind, mode));
#endif  // V8_ENABLE_LEAPTIERING
}

void JSFunction::SetInterruptBudget(
    Isolate* isolate, std::optional<CodeKind> override_active_tier) {
  raw_feedback_cell()->set_interrupt_budget(
      TieringManager::InterruptBudgetFor(isolate, *this, override_active_tier));
}

// static
Maybe<bool> JSFunctionOrBoundFunctionOrWrappedFunction::CopyNameAndLength(
    Isolate* isolate,
    Handle<JSFunctionOrBoundFunctionOrWrappedFunction> function,
    Handle<JSReceiver> target, Handle<String> prefix, int arg_count) {
  // Setup the "length" property based on the "length" of the {target}.
  // If the targets length is the default JSFunction accessor, we can keep the
  // accessor that's installed by default on the
  // JSBoundFunction/JSWrappedFunction. It lazily computes the value from the
  // underlying internal length.
  Handle<AccessorInfo> function_length_accessor =
      isolate->factory()->function_length_accessor();
  LookupIterator length_lookup(isolate, target,
                               isolate->factory()->length_string(), target,
                               LookupIterator::OWN);
  if (!IsJSFunction(*target) ||
      length_lookup.state() != LookupIterator::ACCESSOR ||
      !length_lookup.GetAccessors().is_identical_to(function_length_accessor)) {
    Handle<Object> length(Smi::zero(), isolate);
    Maybe<PropertyAttributes> attributes =
        JSReceiver::GetPropertyAttributes(&length_lookup);
    if (attributes.IsNothing()) return Nothing<bool>();
    if (attributes.FromJust() != ABSENT) {
      Handle<Object> target_length;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, target_length,
                                       Object::GetProperty(&length_lookup),
                                       Nothing<bool>());
      if (IsNumber(*target_length)) {
        length = isolate->factory()->NewNumber(std::max(
            0.0,
            DoubleToInteger(Object::NumberValue(*target_length)) - arg_count));
      }
    }
    LookupIterator it(isolate, function, isolate->factory()->length_string(),
                      function);
    DCHECK_EQ(LookupIterator::ACCESSOR, it.state());
    RETURN_ON_EXCEPTION_VALUE(isolate,
                              JSObject::DefineOwnPropertyIgnoreAttributes(
                                  &it, length, it.property_attributes()),
                              Nothing<bool>());
  }

  // Setup the "name" property based on the "name" of the {target}.
  // If the target's name is the default JSFunction accessor, we can keep the
  // accessor that's installed by default on the
  // JSBoundFunction/JSWrappedFunction. It lazily computes the value from the
  // underlying internal name.
  Handle<AccessorInfo> function_name_accessor =
      isolate->factory()->function_name_accessor();
  LookupIterator name_lookup(isolate, target, isolate->factory()->name_string(),
                             target);
  if (!IsJSFunction(*target) ||
      name_lookup.state() != LookupIterator::ACCESSOR ||
      !name_lookup.GetAccessors().is_identical_to(function_name_accessor) ||
      (name_lookup.IsFound() && !name_lookup.HolderIsReceiver())) {
    Handle<Object> target_name;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, target_name,
                                     Object::GetProperty(&name_lookup),
                                     Nothing<bool>());
    Handle<String> name;
    if (IsString(*target_name)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, name,
          Name::ToFunctionName(isolate, Cast<String>(target_name)),
          Nothing<bool>());
      if (!prefix.is_null()) {
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, name, isolate->factory()->NewConsString(prefix, name),
            Nothing<bool>());
      }
    } else if (prefix.is_null()) {
      name = isolate->factory()->empty_string();
    } else {
      name = prefix;
    }
    LookupIterator it(isolate, function, isolate->factory()->name_string());
    DCHECK_EQ(LookupIterator::ACCESSOR, it.state());
    RETURN_ON_EXCEPTION_VALUE(isolate,
                              JSObject::DefineOwnPropertyIgnoreAttributes(
                                  &it, name, it.property_attributes()),
                              Nothing<bool>());
  }

  return Just(true);
}

// static
MaybeHandle<String> JSBoundFunction::GetName(
    Isolate* isolate, DirectHandle<JSBoundFunction> function) {
  Handle<String> prefix = isolate->factory()->bound__string();
  Handle<String> target_name = prefix;
  Factory* factory = isolate->factory();
  // Concatenate the "bound " up to the last non-bound target.
  while (IsJSBoundFunction(function->bound_target_function())) {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, target_name,
                               factory->NewConsString(prefix, target_name));
    function = handle(Cast<JSBoundFunction>(function->bound_target_function()),
                      isolate);
  }
  if (IsJSWrappedFunction(function->bound_target_function())) {
    DirectHandle<JSWrappedFunction> target(
        Cast<JSWrappedFunction>(function->bound_target_function()), isolate);
    Handle<String> name;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, name,
                               JSWrappedFunction::GetName(isolate, target));
    return factory->NewConsString(target_name, name);
  }
  if (IsJSFunction(function->bound_target_function())) {
    DirectHandle<JSFunction> target(
        Cast<JSFunction>(function->bound_target_function()), isolate);
    Handle<String> name = JSFunction::GetName(isolate, target);
    return factory->NewConsString(target_name, name);
  }
  // This will omit the proper target name for bound JSProxies.
  return target_name;
}

// static
Maybe<int> JSBoundFunction::GetLength(Isolate* isolate,
                                      DirectHandle<JSBoundFunction> function) {
  int nof_bound_arguments = function->bound_arguments()->length();
  while (IsJSBoundFunction(function->bound_target_function())) {
    function = handle(Cast<JSBoundFunction>(function->bound_target_function()),
                      isolate);
    // Make sure we never overflow {nof_bound_arguments}, the number of
    // arguments of a function is strictly limited by the max length of an
    // JSAarray, Smi::kMaxValue is thus a reasonably good overestimate.
    int length = function->bound_arguments()->length();
    if (V8_LIKELY(Smi::kMaxValue - nof_bound_arguments > length)) {
      nof_bound_arguments += length;
    } else {
      nof_bound_arguments = Smi::kMaxValue;
    }
  }
  if (IsJSWrappedFunction(function->bound_target_function())) {
    DirectHandle<JSWrappedFunction> target(
        Cast<JSWrappedFunction>(function->bound_target_function()), isolate);
    int target_length = 0;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, target_length, JSWrappedFunction::GetLength(isolate, target),
        Nothing<int>());
    int length = std::max(0, target_length - nof_bound_arguments);
    return Just(length);
  }
  // All non JSFunction targets get a direct property and don't use this
  // accessor.
  DirectHandle<JSFunction> target(
      Cast<JSFunction>(function->bound_target_function()), isolate);
  int target_length = target->length();

  int length = std::max(0, target_length - nof_bound_arguments);
  return Just(length);
}

// static
Handle<String> JSBoundFunction::ToString(
    DirectHandle<JSBoundFunction> function) {
  Isolate* const isolate = function->GetIsolate();
  return isolate->factory()->function_native_code_string();
}

// static
MaybeHandle<String> JSWrappedFunction::GetName(
    Isolate* isolate, DirectHandle<JSWrappedFunction> function) {
  STACK_CHECK(isolate, MaybeHandle<String>());
  Factory* factory = isolate->factory();
  Handle<String> target_name = factory->empty_string();
  DirectHandle<JSReceiver> target(function->wrapped_target_function(), isolate);
  if (IsJSBoundFunction(*target)) {
    return JSBoundFunction::GetName(
        isolate,
        handle(Cast<JSBoundFunction>(function->wrapped_target_function()),
               isolate));
  } else if (IsJSFunction(*target)) {
    return JSFunction::GetName(
        isolate,
        handle(Cast<JSFunction>(function->wrapped_target_function()), isolate));
  }
  // This will omit the proper target name for bound JSProxies.
  return target_name;
}

// static
Maybe<int> JSWrappedFunction::GetLength(
    Isolate* isolate, DirectHandle<JSWrappedFunction> function) {
  STACK_CHECK(isolate, Nothing<int>());
  Handle<JSReceiver> target =
      handle(function->wrapped_target_function(), isolate);
  if (IsJSBoundFunction(*target)) {
    return JSBoundFunction::GetLength(
        isolate,
        handle(Cast<JSBoundFunction>(function->wrapped_target_function()),
               isolate));
  }
  // All non JSFunction targets get a direct property and don't use this
  // accessor.
  return Just(Cast<JSFunction>(target)->length());
}

// static
Handle<String> JSWrappedFunction::ToString(
    DirectHandle<JSWrappedFunction> function) {
  Isolate* const isolate = function->GetIsolate();
  return isolate->factory()->function_native_code_string();
}

// static
MaybeHandle<Object> JSWrappedFunction::Create(
    Isolate* isolate, DirectHandle<NativeContext> creation_context,
    Handle<JSReceiver> value) {
  // The value must be a callable according to the specification.
  DCHECK(IsCallable(*value));
  // The intermediate wrapped functions are not user-visible. And calling a
  // wrapped function won't cause a side effect in the creation realm.
  // Unwrap here to avoid nested unwrapping at the call site.
  if (IsJSWrappedFunction(*value)) {
    auto target_wrapped = Cast<JSWrappedFunction>(value);
    value =
        Handle<JSReceiver>(target_wrapped->wrapped_target_function(), isolate);
  }

  // 1. Let internalSlotsList be the internal slots listed in Table 2, plus
  // [[Prototype]] and [[Extensible]].
  // 2. Let wrapped be ! MakeBasicObject(internalSlotsList).
  // 3. Set wrapped.[[Prototype]] to
  // callerRealm.[[Intrinsics]].[[%Function.prototype%]].
  // 4. Set wrapped.[[Call]] as described in 2.1.
  // 5. Set wrapped.[[WrappedTargetFunction]] to Target.
  // 6. Set wrapped.[[Realm]] to callerRealm.
  Handle<JSWrappedFunction> wrapped =
      isolate->factory()->NewJSWrappedFunction(creation_context, value);

  // 7. Let result be CopyNameAndLength(wrapped, Target, "wrapped").
  Maybe<bool> is_abrupt =
      JSFunctionOrBoundFunctionOrWrappedFunction::CopyNameAndLength(
          isolate, wrapped, value, Handle<String>(), 0);

  // 8. If result is an Abrupt Completion, throw a TypeError exception.
  if (is_abrupt.IsNothing()) {
    DCHECK(isolate->has_exception());
    DirectHandle<Object> exception(isolate->exception(), isolate);
    isolate->clear_exception();

    // The TypeError thrown is created with creation Realm's TypeError
    // constructor instead of the executing Realm's.
    Handle<JSFunction> type_error_function =
        Handle<JSFunction>(creation_context->type_error_function(), isolate);
    DirectHandle<String> string =
        Object::NoSideEffectsToString(isolate, exception);
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewError(type_error_function, MessageTemplate::kCannotWrap, string),
        {});
  }
  DCHECK(is_abrupt.FromJust());

  // 9. Return wrapped.
  return wrapped;
}

// static
Handle<String> JSFunction::GetName(Isolate* isolate,
                                   DirectHandle<JSFunction> function) {
  if (function->shared()->name_should_print_as_anonymous()) {
    return isolate->factory()->anonymous_string();
  }
  return handle(function->shared()->Name(), isolate);
}

// static
void JSFunction::EnsureClosureFeedbackCellArray(
    DirectHandle<JSFunction> function,
    bool reset_budget_for_feedback_allocation) {
  Isolate* const isolate = function->GetIsolate();
  DCHECK(function->shared()->is_compiled());
  DCHECK(function->shared()->HasFeedbackMetadata());
#if V8_ENABLE_WEBASSEMBLY
  if (function->shared()->HasAsmWasmData()) return;
#endif  // V8_ENABLE_WEBASSEMBLY

  DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate);
  DCHECK(shared->HasBytecodeArray());

  const bool has_closure_feedback_cell_array =
      (function->has_closure_feedback_cell_array() ||
       function->has_feedback_vector());
  // Initialize the interrupt budget to the feedback vector allocation budget
  // when initializing the feedback cell for the first time or after a bytecode
  // flush. We retain the closure feedback cell array on bytecode flush, so
  // reset_budget_for_feedback_allocation is used to reset the budget in these
  // cases.
  if (reset_budget_for_feedback_allocation ||
      !has_closure_feedback_cell_array) {
    function->SetInterruptBudget(isolate);
  }

  if (has_closure_feedback_cell_array) {
    return;
  }

  DirectHandle<ClosureFeedbackCellArray> feedback_cell_array =
      ClosureFeedbackCellArray::New(isolate, shared);
  // Many closure cell is used as a way to specify that there is no
  // feedback cell for this function and a new feedback cell has to be
  // allocated for this function. For ex: for eval functions, we have to create
  // a feedback cell and cache it along with the code. It is safe to use
  // many_closure_cell to indicate this because in regular cases, it should
  // already have a feedback_vector / feedback cell array allocated.
  if (function->raw_feedback_cell() == isolate->heap()->many_closures_cell()) {
    DirectHandle<FeedbackCell> feedback_cell =
        isolate->factory()->NewOneClosureCell(feedback_cell_array);
#ifdef V8_ENABLE_LEAPTIERING
    // This is a rare case where we copy the dispatch entry from a JSFunction
    // to its FeedbackCell instead of the other way around.
    // TODO(42204201): investigate whether this can be avoided so that we only
    // ever copy a dispatch handle from a FeedbackCell to a JSFunction. That
    // would probably require refactoring the way JSFunctions are built so that
    // we always allocate a FeedbackCell up front (if needed).
    DCHECK_NE(function->dispatch_handle(), kNullJSDispatchHandle);
    // The feedback cell should never contain context specialized code.
    DCHECK(!function->code(isolate)->is_context_specialized());
    feedback_cell->set_dispatch_handle(function->dispatch_handle());
#endif  // V8_ENABLE_LEAPTIERING
    function->set_raw_feedback_cell(*feedback_cell, kReleaseStore);
    function->SetInterruptBudget(isolate);
  } else {
    function->raw_feedback_cell()->set_value(*feedback_cell_array,
                                             kReleaseStore);
  }
}

// static
void JSFunction::EnsureFeedbackVector(Isolate* isolate,
                                      DirectHandle<JSFunction> function,
                                      IsCompiledScope* compiled_scope) {
  CHECK(compiled_scope->is_compiled());
  DCHECK(function->shared()->HasFeedbackMetadata());
  if (function->has_feedback_vector()) return;
#if V8_ENABLE_WEBASSEMBLY
  if (function->shared()->HasAsmWasmData()) return;
#endif  // V8_ENABLE_WEBASSEMBLY

  CreateAndAttachFeedbackVector(isolate, function, compiled_scope);
}

// static
void JSFunction::CreateAndAttachFeedbackVector(
    Isolate* isolate, DirectHandle<JSFunction> function,
    IsCompiledScope* compiled_scope) {
  CHECK(compiled_scope->is_compiled());
  DCHECK(function->shared()->HasFeedbackMetadata());
  DCHECK(!function->has_feedback_vector());
#if V8_ENABLE_WEBASSEMBLY
  DCHECK(!function->shared()->HasAsmWasmData());
#endif  // V8_ENABLE_WEBASSEMBLY

  DirectHandle<SharedFunctionInfo> shared(function->shared(), isolate);
  DCHECK(function->shared()->HasBytecodeArray());

  EnsureClosureFeedbackCellArray(function, false);
  DirectHandle<ClosureFeedbackCellArray> closure_feedback_cell_array(
      function->closure_feedback_cell_array(), isolate);
  DirectHandle<FeedbackVector> feedback_vector = FeedbackVector::New(
      isolate, shared, closure_feedback_cell_array,
      direct_handle(function->raw_feedback_cell(isolate), isolate),
      compiled_scope);
  USE(feedback_vector);
  // EnsureClosureFeedbackCellArray should handle the special case where we need
  // to allocate a new feedback cell. Please look at comment in that function
  // for more details.
  DCHECK(function->raw_feedback_cell() !=
         isolate->heap()->many_closures_cell());
  DCHECK_EQ(function->raw_feedback_cell()->value(), *feedback_vector);
  function->SetInterruptBudget(isolate);

#ifndef V8_ENABLE_LEAPTIERING
  DCHECK_EQ(v8_flags.log_function_events,
            feedback_vector->log_next_execution());
#endif

  if (v8_flags.profile_guided_optimization &&
      v8_flags.profile_guided_optimization_for_empty_feedback_vector &&
      function->feedback_vector()->length() == 0) {
    if (function->shared()->cached_tiering_decision() ==
        CachedTieringDecision::kEarlyMaglev) {
      function->RequestOptimization(isolate, CodeKind::MAGLEV,
                                    ConcurrencyMode::kConcurrent);
    } else if (function->shared()->cached_tiering_decision() ==
               CachedTieringDecision::kEarlyTurbofan) {
      function->RequestOptimization(isolate, CodeKind::TURBOFAN_JS,
                                    ConcurrencyMode::kConcurrent);
    }
  }
}

// static
void JSFunction::InitializeFeedbackCell(
    DirectHandle<JSFunction> function, IsCompiledScope* is_compiled_scope,
    bool reset_budget_for_feedback_allocation) {
  Isolate* const isolate = function->GetIsolate();
#if V8_ENABLE_WEBASSEMBLY
  // The following checks ensure that the feedback vectors are compatible with
  // the feedback metadata. For Asm / Wasm functions we never allocate / use
  // feedback vectors, so a mismatch between the metadata and feedback vector is
  // harmless. The checks could fail for functions that has has_asm_wasm_broken
  // set at runtime (for ex: failed instantiation).
  if (function->shared()->HasAsmWasmData()) return;
#endif  // V8_ENABLE_WEBASSEMBLY

  if (function->has_feedback_vector()) {
    CHECK_EQ(function->feedback_vector()->length(),
             function->feedback_vector()->metadata()->slot_count());
    return;
  }

  if (function->has_closure_feedback_cell_array()) {
    CHECK_EQ(
        function->closure_feedback_cell_array()->length(),
        function->shared()->feedback_metadata()->create_closure_slot_count());
  }

  const bool needs_feedback_vector =
      !v8_flags.lazy_feedback_allocation || v8_flags.always_turbofan ||
      // We also need a feedback vector for certain log events, collecting type
      // profile and more precise code coverage.
      v8_flags.log_function_events ||
      !isolate->is_best_effort_code_coverage() ||
      function->shared()->cached_tiering_decision() !=
          CachedTieringDecision::kPending;

  if (needs_feedback_vector) {
    CreateAndAttachFeedbackVector(isolate, function, is_compiled_scope);
  } else {
    EnsureClosureFeedbackCellArray(function,
                                   reset_budget_for_feedback_allocation);
  }
#ifdef V8_ENABLE_SPARKPLUG
  // TODO(jgruber): Unduplicate these conditions from tiering-manager.cc.
  if (function->shared()->cached_tiering_decision() !=
          CachedTieringDecision::kPending &&
      CanCompileWithBaseline(isolate, function->shared()) &&
      function->ActiveTierIsIgnition(isolate)) {
    if (v8_flags.baseline_batch_compilation) {
      isolate->baseline_batch_compiler()->EnqueueFunction(function);
    } else {
      IsCompiledScope is_compiled_scope(
          function->shared()->is_compiled_scope(isolate));
      Compiler::CompileBaseline(isolate, function, Compiler::CLEAR_EXCEPTION,
                                &is_compiled_scope);
    }
  }
#endif  // V8_ENABLE_SPARKPLUG
}

namespace {

void SetInstancePrototype(Isolate* isolate, DirectHandle<JSFunction> function,
                          Handle<JSReceiver> value) {
  // Now some logic for the maps of the objects that are created by using this
  // function as a constructor.
  if (function->has_initial_map()) {
    // If the function has allocated the initial map replace it with a
    // copy containing the new prototype.  Also complete any in-object
    // slack tracking that is in progress at this point because it is
    // still tracking the old copy.
    function->CompleteInobjectSlackTrackingIfActive();

    Handle<Map> initial_map(function->initial_map(), isolate);

    if (!isolate->bootstrapper()->IsActive() &&
        initial_map->instance_type() == JS_OBJECT_TYPE) {
      // Put the value in the initial map field until an initial map is needed.
      // At that point, a new initial map is created and the prototype is put
      // into the initial map where it belongs.
      function->set_prototype_or_initial_map(*value, kReleaseStore);
      if (IsJSObjectThatCanBeTrackedAsPrototype(*value)) {
        // Optimize as prototype to detach it from its transition tree.
        JSObject::OptimizeAsPrototype(Cast<JSObject>(value));
      }
    } else {
      Handle<Map> new_map =
          Map::Copy(isolate, initial_map, "SetInstancePrototype");
      JSFunction::SetInitialMap(isolate, function, new_map, value);
      DCHECK_IMPLIES(!isolate->bootstrapper()->IsActive(),
                     *function != function->native_context()->array_function());
    }

    // Deoptimize all code that embeds the previous initial map.
    DependentCode::DeoptimizeDependencyGroups(
        isolate, *initial_map, DependentCode::kInitialMapChangedGroup);
  } else {
    // Put the value in the initial map field until an initial map is
    // needed.  At that point, a new initial map is created and the
    // prototype is put into the initial map where it belongs.
    function->set_prototype_or_initial_map(*value, kReleaseStore);
    if (IsJSObjectThatCanBeTrackedAsPrototype(*value)) {
      // Optimize as prototype to detach it from its transition tree.
      JSObject::OptimizeAsPrototype(Cast<JSObject>(value));
    }
  }
}

}  // anonymous namespace

void JSFunction::SetPrototype(DirectHandle<JSFunction> function,
                              Handle<Object> value) {
  DCHECK(IsConstructor(*function) ||
         IsGeneratorFunction(function->shared()->kind()));
  Isolate* isolate = function->GetIsolate();
  Handle<JSReceiver> construct_prototype;

  // If the value is not a JSReceiver, store the value in the map's
  // constructor field so it can be accessed.  Also, set the prototype
  // used for constructing objects to the original object prototype.
  // See ECMA-262 13.2.2.
  if (!IsJSReceiver(*value)) {
    // Copy the map so this does not affect unrelated functions.
    // Remove map transitions because they point to maps with a
    // different prototype.
    DirectHandle<Map> new_map =
        Map::Copy(isolate, handle(function->map(), isolate), "SetPrototype");

    // Create a new {constructor, non-instance_prototype} tuple and store it
    // in Map::constructor field.
    DirectHandle<Object> constructor(new_map->GetConstructor(), isolate);
    DirectHandle<Tuple2> non_instance_prototype_constructor_tuple =
        isolate->factory()->NewTuple2(constructor, value, AllocationType::kOld);

    new_map->set_has_non_instance_prototype(true);
    new_map->SetConstructor(*non_instance_prototype_constructor_tuple);

    JSObject::MigrateToMap(isolate, function, new_map);

    FunctionKind kind = function->shared()->kind();
    DirectHandle<Context> native_context(function->native_context(), isolate);

    construct_prototype = Handle<JSReceiver>(
        IsGeneratorFunction(kind)
            ? IsAsyncFunction(kind)
                  ? native_context->initial_async_generator_prototype()
                  : native_context->initial_generator_prototype()
            : native_context->initial_object_prototype(),
        isolate);
  } else {
    construct_prototype = Cast<JSReceiver>(value);
    function->map()->set_has_non_instance_prototype(false);
  }

  SetInstancePrototype(isolate, function, construct_prototype);
}

void JSFunction::SetInitialMap(Isolate* isolate,
                               DirectHandle<JSFunction> function,
                               Handle<Map> map, Handle<JSPrototype> prototype) {
  SetInitialMap(isolate, function, map, prototype, function);
}

void JSFunction::SetInitialMap(Isolate* isolate,
                               DirectHandle<JSFunction> function,
                               Handle<Map> map, Handle<JSPrototype> prototype,
                               DirectHandle<JSFunction> constructor) {
  if (map->prototype() != *prototype) {
    Map::SetPrototype(isolate, map, prototype);
  }
  map->SetConstructor(*constructor);
  function->set_prototype_or_initial_map(*map, kReleaseStore);
  if (v8_flags.log_maps) {
    LOG(isolate, MapEvent("InitialMap", Handle<Map>(), map, "",
                          SharedFunctionInfo::DebugName(
                              isolate, handle(function->shared(), isolate))));
  }
}

void JSFunction::EnsureHasInitialMap(Handle<JSFunction> function) {
  DCHECK(function->has_prototype_slot());
  DCHECK(IsConstructor(*function) ||
         IsResumableFunction(function->shared()->kind()));
  if (function->has_initial_map()) return;
  Isolate* isolate = function->GetIsolate();

  int expected_nof_properties =
      CalculateExpectedNofProperties(isolate, function);

  // {CalculateExpectedNofProperties} can have had the side effect of creating
  // the initial map (e.g. it could have triggered an optimized compilation
  // whose dependency installation reentered {EnsureHasInitialMap}).
  if (function->has_initial_map()) return;

  // Create a new map with the size and number of in-object properties suggested
  // by the function.
  InstanceType instance_type;
  if (IsResumableFunction(function->shared()->kind())) {
    instance_type = IsAsyncGeneratorFunction(function->shared()->kind())
                        ? JS_ASYNC_GENERATOR_OBJECT_TYPE
                        : JS_GENERATOR_OBJECT_TYPE;
  } else {
    instance_type = JS_OBJECT_TYPE;
  }

  int instance_size;
  int inobject_properties;
  CalculateInstanceSizeHelper(instance_type, false, 0, expected_nof_properties,
                              &instance_size, &inobject_properties);

  Handle<NativeContext> creation_context(function->native_context(), isolate);
  Handle<Map> map = isolate->factory()->NewContextfulMap(
      creation_context, instance_type, instance_size,
      TERMINAL_FAST_ELEMENTS_KIND, inobject_properties);

  // Fetch or allocate prototype.
  Handle<JSPrototype> prototype;
  if (function->has_instance_prototype()) {
    prototype = handle(function->instance_prototype(), isolate);
    map->set_prototype(*prototype);
  } else {
    prototype = isolate->factory()->NewFunctionPrototype(function);
    Map::SetPrototype(isolate, map, prototype);
  }
  DCHECK(map->has_fast_object_elements());

  // Finally link initial map and constructor function.
  // This is a CHECK since the prototype could be Null according to the type
  // system.
  // TODO(leszeks): Figure out if this CHECK is needed.
  CHECK(IsJSReceiver(*prototype));
  JSFunction::SetInitialMap(isolate, function, map, prototype);
  map->StartInobjectSlackTracking();
}

namespace {

#ifdef DEBUG
bool CanSubclassHaveInobjectProperties(InstanceType instance_type) {
  switch (instance_type) {
    case JS_API_OBJECT_TYPE:
    case JS_ARRAY_BUFFER_TYPE:
    case JS_ARRAY_ITERATOR_PROTOTYPE_TYPE:
    case JS_ARRAY_TYPE:
    case JS_ASYNC_FROM_SYNC_ITERATOR_TYPE:
    case JS_CONTEXT_EXTENSION_OBJECT_TYPE:
    case JS_DATA_VIEW_TYPE:
    case JS_RAB_GSAB_DATA_VIEW_TYPE:
    case JS_DATE_TYPE:
    case JS_GENERATOR_OBJECT_TYPE:
    case JS_FUNCTION_TYPE:
    case JS_CLASS_CONSTRUCTOR_TYPE:
    case JS_PROMISE_CONSTRUCTOR_TYPE:
    case JS_REG_EXP_CONSTRUCTOR_TYPE:
    case JS_ARRAY_CONSTRUCTOR_TYPE:
    case JS_ASYNC_DISPOSABLE_STACK_TYPE:
    case JS_SYNC_DISPOSABLE_STACK_TYPE:
#define TYPED_ARRAY_CONSTRUCTORS_SWITCH(Type, type, TYPE, Ctype) \
  case TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE:
      TYPED_ARRAYS(TYPED_ARRAY_CONSTRUCTORS_SWITCH)
#undef TYPED_ARRAY_CONSTRUCTORS_SWITCH
    case JS_ITERATOR_PROTOTYPE_TYPE:
    case JS_MAP_ITERATOR_PROTOTYPE_TYPE:
    case JS_OBJECT_PROTOTYPE_TYPE:
    case JS_PROMISE_PROTOTYPE_TYPE:
    case JS_REG_EXP_PROTOTYPE_TYPE:
    case JS_SET_ITERATOR_PROTOTYPE_TYPE:
    case JS_SET_PROTOTYPE_TYPE:
    case JS_STRING_ITERATOR_PROTOTYPE_TYPE:
    case JS_TYPED_ARRAY_PROTOTYPE_TYPE:
#ifdef V8_INTL_SUPPORT
    case JS_COLLATOR_TYPE:
    case JS_DATE_TIME_FORMAT_TYPE:
    case JS_DISPLAY_NAMES_TYPE:
    case JS_DURATION_FORMAT_TYPE:
    case JS_LIST_FORMAT_TYPE:
    case JS_LOCALE_TYPE:
    case JS_NUMBER_FORMAT_TYPE:
    case JS_PLURAL_RULES_TYPE:
    case JS_RELATIVE_TIME_FORMAT_TYPE:
    case JS_SEGMENT_ITERATOR_TYPE:
    case JS_SEGMENTER_TYPE:
    case JS_SEGMENTS_TYPE:
    case JS_V8_BREAK_ITERATOR_TYPE:
#endif
    case JS_ASYNC_FUNCTION_OBJECT_TYPE:
    case JS_ASYNC_GENERATOR_OBJECT_TYPE:
    case JS_MAP_TYPE:
    case JS_MESSAGE_OBJECT_TYPE:
    case JS_OBJECT_TYPE:
    case JS_ERROR_TYPE:
    case JS_FINALIZATION_REGISTRY_TYPE:
    case JS_ARGUMENTS_OBJECT_TYPE:
    case JS_PROMISE_TYPE:
    case JS_REG_EXP_TYPE:
    case JS_SET_TYPE:
    case JS_SHADOW_REALM_TYPE:
    case JS_SPECIAL_API_OBJECT_TYPE:
    case JS_TYPED_ARRAY_TYPE:
    case JS_PRIMITIVE_WRAPPER_TYPE:
    case JS_TEMPORAL_CALENDAR_TYPE:
    case JS_TEMPORAL_DURATION_TYPE:
    case JS_TEMPORAL_INSTANT_TYPE:
    case JS_TEMPORAL_PLAIN_DATE_TYPE:
    case JS_TEMPORAL_PLAIN_DATE_TIME_TYPE:
    case JS_TEMPORAL_PLAIN_MONTH_DAY_TYPE:
    case JS_TEMPORAL_PLAIN_TIME_TYPE:
    case JS_TEMPORAL_PLAIN_YEAR_MONTH_TYPE:
    case JS_TEMPORAL_TIME_ZONE_TYPE:
    case JS_TEMPORAL_ZONED_DATE_TIME_TYPE:
    case JS_WEAK_MAP_TYPE:
    case JS_WEAK_REF_TYPE:
    case JS_WEAK_SET_TYPE:
#if V8_ENABLE_WEBASSEMBLY
    case WASM_GLOBAL_OBJECT_TYPE:
    case WASM_INSTANCE_OBJECT_TYPE:
    case WASM_MEMORY_OBJECT_TYPE:
    case WASM_MODULE_OBJECT_TYPE:
    case WASM_TABLE_OBJECT_TYPE:
    case WASM_VALUE_OBJECT_TYPE:
#endif  // V8_ENABLE_WEBASSEMBLY
      return true;

    case BIGINT_TYPE:
    case OBJECT_BOILERPLATE_DESCRIPTION_TYPE:
    case BYTECODE_ARRAY_TYPE:
    case BYTE_ARRAY_TYPE:
    case CELL_TYPE:
    case INSTRUCTION_STREAM_TYPE:
    case FILLER_TYPE:
    case FIXED_ARRAY_TYPE:
    case SCRIPT_CONTEXT_TABLE_TYPE:
    case FIXED_DOUBLE_ARRAY_TYPE:
    case FEEDBACK_METADATA_TYPE:
    case FOREIGN_TYPE:
    case FREE_SPACE_TYPE:
    case HASH_TABLE_TYPE:
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
    case ORDERED_NAME_DICTIONARY_TYPE:
    case NAME_DICTIONARY_TYPE:
    case GLOBAL_DICTIONARY_TYPE:
    case NUMBER_DICTIONARY_TYPE:
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
    case HEAP_NUMBER_TYPE:
    case JS_BOUND_FUNCTION_TYPE:
    case JS_GLOBAL_OBJECT_TYPE:
    case JS_GLOBAL_PROXY_TYPE:
    case JS_PROXY_TYPE:
    case JS_WRAPPED_FUNCTION_TYPE:
    case MAP_TYPE:
    case ODDBALL_TYPE:
    case PROPERTY_CELL_TYPE:
    case CONTEXT_SIDE_PROPERTY_CELL_TYPE:
    case SHARED_FUNCTION_INFO_TYPE:
    case SYMBOL_TYPE:
    case ALLOCATION_SITE_TYPE:

#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype, size) \
  case FIXED_##TYPE##_ARRAY_TYPE:
#undef TYPED_ARRAY_CASE

#define MAKE_STRUCT_CASE(TYPE, Name, name) case TYPE:
      STRUCT_LIST(MAKE_STRUCT_CASE)
#undef MAKE_STRUCT_CASE
      // We must not end up here for these instance types at all.
      UNREACHABLE();

    default:
      if (InstanceTypeChecker::IsJSApiObject(instance_type)) return true;
      return false;
  }
}
#endif  // DEBUG

bool FastInitializeDerivedMap(Isolate* isolate, Handle<JSFunction> new_target,
                              DirectHandle<JSFunction> constructor,
                              Handle<Map> constructor_initial_map) {
  // Use the default intrinsic prototype instead.
  if (!new_target->has_prototype_slot()) return false;
  // Check that |function|'s initial map still in sync with the |constructor|,
  // otherwise we must create a new initial map for |function|.
  if (new_target->has_initial_map() &&
      new_target->initial_map()->GetConstructor() == *constructor) {
    DCHECK(IsJSReceiver(new_target->instance_prototype()));
    return true;
  }
  InstanceType instance_type = constructor_initial_map->instance_type();
  DCHECK(CanSubclassHaveInobjectProperties(instance_type));
  // Create a new map with the size and number of in-object properties
  // suggested by |function|.

  // Link initial map and constructor function if the new.target is actually a
  // subclass constructor.
  if (!IsDerivedConstructor(new_target->shared()->kind())) return false;

  int instance_size;
  int in_object_properties;
  int embedder_fields =
      JSObject::GetEmbedderFieldCount(*constructor_initial_map);
  // Constructor expects certain number of in-object properties to be in the
  // object. However, CalculateExpectedNofProperties() may return smaller value
  // if 1) the constructor is not in the prototype chain of new_target, or
  // 2) the prototype chain is modified during iteration, or 3) compilation
  // failure occur during prototype chain iteration.
  // So we take the maximum of two values.
  int expected_nof_properties = std::max(
      static_cast<int>(constructor->shared()->expected_nof_properties()),
      JSFunction::CalculateExpectedNofProperties(isolate, new_target));
  JSFunction::CalculateInstanceSizeHelper(
      instance_type, constructor_initial_map->has_prototype_slot(),
      embedder_fields, expected_nof_properties, &instance_size,
      &in_object_properties);

  int pre_allocated = constructor_initial_map->GetInObjectProperties() -
                      constructor_initial_map->UnusedPropertyFields();
  CHECK_LE(constructor_initial_map->UsedInstanceSize(), instance_size);
  int unused_property_fields = in_object_properties - pre_allocated;
  Handle<Map> map =
      Map::CopyInitialMap(isolate, constructor_initial_map, instance_size,
                          in_object_properties, unused_property_fields);
  map->set_new_target_is_base(false);
  Handle<JSPrototype> prototype(new_target->instance_prototype(), isolate);
  JSFunction::SetInitialMap(isolate, new_target, map, prototype, constructor);
  DCHECK(IsJSReceiver(new_target->instance_prototype()));
  map->set_construction_counter(Map::kNoSlackTracking);
  map->StartInobjectSlackTracking();
  return true;
}

}  // namespace

// static
MaybeHandle<Map> JSFunction::GetDerivedMap(Isolate* isolate,
                                           Handle<JSFunction> constructor,
                                           Handle<JSReceiver> new_target) {
  EnsureHasInitialMap(constructor);

  Handle<Map> constructor_initial_map(constructor->initial_map(), isolate);
  if (*new_target == *constructor) return constructor_initial_map;

  DirectHandle<Map> result_map;
  // Fast case, new.target is a subclass of constructor. The map is cacheable
  // (and may already have been cached). new.target.prototype is guaranteed to
  // be a JSReceiver.
  InstanceType new_target_instance_type = new_target->map()->instance_type();
  if (InstanceTypeChecker::IsJSFunction(new_target_instance_type)) {
    Handle<JSFunction> function = Cast<JSFunction>(new_target);
    if (FastInitializeDerivedMap(isolate, function, constructor,
                                 constructor_initial_map)) {
      return handle(function->initial_map(), isolate);
    }
  }

  // Slow path, new.target is either a proxy object or can't cache the map.
  // new.target.prototype is not guaranteed to be a JSReceiver, and may need to
  // fall back to the intrinsicDefaultProto.
  Handle<Object> prototype;
  if (InstanceTypeChecker::IsJSFunction(new_target_instance_type) &&
      Cast<JSFunction>(new_target)->has_prototype_slot()) {
    Handle<JSFunction> function = Cast<JSFunction>(new_target);
    // Make sure the new.target.prototype is cached.
    EnsureHasInitialMap(function);
    prototype = handle(function->prototype(), isolate);
  } else {
    // The new.target is a constructor but it's not a JSFunction with
    // a prototype slot, so get the prototype property.
    Handle<String> prototype_string = isolate->factory()->prototype_string();
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, prototype,
        JSReceiver::GetProperty(isolate, new_target, prototype_string));
    // The above prototype lookup might change the constructor and its
    // prototype, hence we have to reload the initial map.
    EnsureHasInitialMap(constructor);
    constructor_initial_map = handle(constructor->initial_map(), isolate);
  }

  // If prototype is not a JSReceiver, fetch the intrinsicDefaultProto from the
  // correct realm. Rather than directly fetching the .prototype, we fetch the
  // constructor that points to the .prototype. This relies on
  // constructor.prototype being FROZEN for those constructors.
  if (!IsJSReceiver(*prototype)) {
    Handle<NativeContext> native_context;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, native_context,
                               JSReceiver::GetFunctionRealm(new_target));
    DirectHandle<Object> maybe_index = JSReceiver::GetDataProperty(
        isolate, constructor,
        isolate->factory()->native_context_index_symbol());
    int index = IsSmi(*maybe_index) ? Smi::ToInt(*maybe_index)
                                    : Context::OBJECT_FUNCTION_INDEX;
    DirectHandle<JSFunction> realm_constructor(
        Cast<JSFunction>(native_context->get(index)), isolate);
    prototype = handle(realm_constructor->prototype(), isolate);
  }
  DCHECK_EQ(constructor_initial_map->constructor_or_back_pointer(),
            *constructor);
  return Map::GetDerivedMap(isolate, constructor_initial_map,
                            Cast<JSReceiver>(prototype));
}

namespace {

// Assert that the computations in TypedArrayElementsKindToConstructorIndex and
// TypedArrayElementsKindToRabGsabCtorIndex are sound.
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype)                         \
  static_assert(Context::TYPE##_ARRAY_FUN_INDEX ==                        \
                Context::FIRST_FIXED_TYPED_ARRAY_FUN_INDEX +              \
                    ElementsKind::TYPE##_ELEMENTS -                       \
                    ElementsKind::FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND); \
  static_assert(Context::RAB_GSAB_##TYPE##_ARRAY_MAP_INDEX ==             \
                Context::FIRST_RAB_GSAB_TYPED_ARRAY_MAP_INDEX +           \
                    ElementsKind::TYPE##_ELEMENTS -                       \
                    ElementsKind::FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND);

TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

int TypedArrayElementsKindToConstructorIndex(ElementsKind elements_kind) {
  return Context::FIRST_FIXED_TYPED_ARRAY_FUN_INDEX + elements_kind -
         ElementsKind::FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND;
}

int TypedArrayElementsKindToRabGsabCtorIndex(ElementsKind elements_kind) {
  return Context::FIRST_RAB_GSAB_TYPED_ARRAY_MAP_INDEX + elements_kind -
         ElementsKind::FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND;
}

}  // namespace

MaybeHandle<Map> JSFunction::GetDerivedRabGsabTypedArrayMap(
    Isolate* isolate, Handle<JSFunction> constructor,
    Handle<JSReceiver> new_target) {
  MaybeHandle<Map> maybe_map = GetDerivedMap(isolate, constructor, new_target);
  Handle<Map> map;
  if (!maybe_map.ToHandle(&map)) {
    return MaybeHandle<Map>();
  }
  {
    DisallowHeapAllocation no_alloc;
    Tagged<NativeContext> context = isolate->context()->native_context();
    int ctor_index =
        TypedArrayElementsKindToConstructorIndex(map->elements_kind());
    if (*new_target == context->get(ctor_index)) {
      ctor_index =
          TypedArrayElementsKindToRabGsabCtorIndex(map->elements_kind());
      return handle(Cast<Map>(context->get(ctor_index)), isolate);
    }
  }

  // This only happens when subclassing TypedArrays. Create a new map with the
  // corresponding RAB / GSAB ElementsKind. Note: the map is not cached and
  // reused -> every array gets a unique map, making ICs slow.
  Handle<Map> rab_gsab_map = Map::Copy(isolate, map, "RAB / GSAB");
  rab_gsab_map->set_elements_kind(
      GetCorrespondingRabGsabElementsKind(map->elements_kind()));
  return rab_gsab_map;
}

MaybeHandle<Map> JSFunction::GetDerivedRabGsabDataViewMap(
    Isolate* isolate, Handle<JSReceiver> new_target) {
  DirectHandle<Context> context(isolate->context()->native_context(), isolate);
  Handle<JSFunction> constructor(context->data_view_fun(), isolate);
  MaybeHandle<Map> maybe_map = GetDerivedMap(isolate, constructor, new_target);
  Handle<Map> map;
  if (!maybe_map.ToHandle(&map)) {
    return MaybeHandle<Map>();
  }
  if (*map == constructor->initial_map()) {
    return handle(Cast<Map>(context->js_rab_gsab_data_view_map()), isolate);
  }

  // This only happens when subclassing DataViews. Create a new map with the
  // JS_RAB_GSAB_DATA_VIEW instance type. Note: the map is not cached and
  // reused -> every data view gets a unique map, making ICs slow.
  Handle<Map> rab_gsab_map = Map::Copy(isolate, map, "RAB / GSAB");
  rab_gsab_map->set_instance_type(JS_RAB_GSAB_DATA_VIEW_TYPE);
  return rab_gsab_map;
}

int JSFunction::ComputeInstanceSizeWithMinSlack(Isolate* isolate) {
  CHECK(has_initial_map());
  if (initial_map()->IsInobjectSlackTrackingInProgress()) {
    int slack = initial_map()->ComputeMinObjectSlack(isolate);
    return initial_map()->InstanceSizeFromSlack(slack);
  }
  return initial_map()->instance_size();
}

std::unique_ptr<char[]> JSFunction::DebugNameCStr() {
  return shared()->DebugNameCStr();
}

void JSFunction::PrintName(FILE* out) {
  PrintF(out, "%s", DebugNameCStr().get());
}

namespace {

bool UseFastFunctionNameLookup(Isolate* isolate, Tagged<Map> map) {
  DCHECK(IsJSFunctionMap(map));
  if (map->NumberOfOwnDescriptors() <
      JSFunction::kMinDescriptorsForFastBindAndWrap) {
    return false;
  }
  DCHECK(!map->is_dictionary_map());
  Tagged<HeapObject> value;
  ReadOnlyRoots roots(isolate);
  auto descriptors = map->instance_descriptors(isolate);
  InternalIndex kNameIndex{JSFunction::kNameDescriptorIndex};
  if (descriptors->GetKey(kNameIndex) != roots.name_string() ||
      !descriptors->GetValue(kNameIndex)
           .GetHeapObjectIfStrong(isolate, &value)) {
    return false;
  }
  return IsAccessorInfo(value);
}

}  // namespace

Handle<String> JSFunction::GetDebugName(Handle<JSFunction> function) {
  // Below we use the same fast-path that we already established for
  // Function.prototype.bind(), where we avoid a slow "name" property
  // lookup if the DescriptorArray for the |function| still has the
  // "name" property at the original spot and that property is still
  // implemented via an AccessorInfo (which effectively means that
  // it must be the FunctionNameGetter).
  Isolate* isolate = function->GetIsolate();
  if (!UseFastFunctionNameLookup(isolate, function->map())) {
    // Normally there should be an else case for the fast-path check
    // above, which should invoke JSFunction::GetName(), since that's
    // what the FunctionNameGetter does, however GetDataProperty() has
    // never invoked accessors and thus always returned undefined for
    // JSFunction where the "name" property is untouched, so we retain
    // that exact behavior and go with SharedFunctionInfo::DebugName()
    // in case of the fast-path.
    Handle<Object> name =
        GetDataProperty(isolate, function, isolate->factory()->name_string());
    if (IsString(*name)) return Cast<String>(name);
  }
  return SharedFunctionInfo::DebugName(isolate,
                                       handle(function->shared(), isolate));
}

bool JSFunction::SetName(Handle<JSFunction> function, Handle<Name> name,
                         DirectHandle<String> prefix) {
  Isolate* isolate = function->GetIsolate();
  Handle<String> function_name;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, function_name,
                                   Name::ToFunctionName(isolate, name), false);
  if (prefix->length() > 0) {
    IncrementalStringBuilder builder(isolate);
    builder.AppendString(prefix);
    builder.AppendCharacter(' ');
    builder.AppendString(function_name);
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, function_name,
                                     indirect_handle(builder.Finish(), isolate),
                                     false);
  }
  RETURN_ON_EXCEPTION_VALUE(
      isolate,
      JSObject::DefinePropertyOrElementIgnoreAttributes(
          function, isolate->factory()->name_string(), function_name,
          static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY)),
      false);
  return true;
}

namespace {

Handle<String> NativeCodeFunctionSourceString(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared_info) {
  IncrementalStringBuilder builder(isolate);
  builder.AppendCStringLiteral("function ");
  builder.AppendString(handle(shared_info->Name(), isolate));
  builder.AppendCStringLiteral("() { [native code] }");
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

}  // namespace

// static
Handle<String> JSFunction::ToString(DirectHandle<JSFunction> function) {
  Isolate* const isolate = function->GetIsolate();
  DirectHandle<SharedFunctionInfo> shared_info(function->shared(), isolate);

  // Check if {function} should hide its source code.
  if (!shared_info->IsUserJavaScript()) {
    return NativeCodeFunctionSourceString(isolate, shared_info);
  }

  if (IsClassConstructor(shared_info->kind())) {
    // Check if we should print {function} as a class.
    DirectHandle<Object> maybe_class_positions = JSReceiver::GetDataProperty(
        isolate, indirect_handle(function, isolate),
        isolate->factory()->class_positions_symbol());
    if (IsClassPositions(*maybe_class_positions)) {
      Tagged<ClassPositions> class_positions =
          Cast<ClassPositions>(*maybe_class_positions);
      int start_position = class_positions->start();
      int end_position = class_positions->end();
      Handle<String> script_source(
          Cast<String>(Cast<Script>(shared_info->script())->source()), isolate);
      return isolate->factory()->NewSubString(script_source, start_position,
                                              end_position);
    }
  }

  // Check if we have source code for the {function}.
  if (!shared_info->HasSourceCode()) {
    return NativeCodeFunctionSourceString(isolate, shared_info);
  }

  // If this function was compiled from asm.js, use the recorded offset
  // information.
#if V8_ENABLE_WEBASSEMBLY
  if (shared_info->HasWasmExportedFunctionData()) {
    DirectHandle<WasmExportedFunctionData> function_data(
        shared_info->wasm_exported_function_data(), isolate);
    const wasm::WasmModule* module = function_data->instance_data()->module();
    if (is_asmjs_module(module)) {
      std::pair<int, int> offsets =
          module->asm_js_offset_information->GetFunctionOffsets(
              declared_function_index(module, function_data->function_index()));
      Handle<String> source(
          Cast<String>(Cast<Script>(shared_info->script())->source()), isolate);
      return isolate->factory()->NewSubString(source, offsets.first,
                                              offsets.second);
    }
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  if (shared_info->function_token_position() == kNoSourcePosition) {
    // If the function token position isn't valid, return [native code] to
    // ensure calling eval on the returned source code throws rather than
    // giving inconsistent call behaviour.
    isolate->CountUsage(
        v8::Isolate::UseCounterFeature::kFunctionTokenOffsetTooLongForToString);
    return NativeCodeFunctionSourceString(isolate, shared_info);
  }
  return Cast<String>(
      SharedFunctionInfo::GetSourceCodeHarmony(isolate, shared_info));
}

// static
int JSFunction::CalculateExpectedNofProperties(Isolate* isolate,
                                               Handle<JSFunction> function) {
  int expected_nof_properties = 0;
  for (PrototypeIterator iter(isolate, function, kStartAtReceiver);
       !iter.IsAtEnd(); iter.Advance()) {
    Handle<JSReceiver> current =
        PrototypeIterator::GetCurrent<JSReceiver>(iter);
    if (!IsJSFunction(*current)) break;
    Handle<JSFunction> func = Cast<JSFunction>(current);
    // The super constructor should be compiled for the number of expected
    // properties to be available.
    DirectHandle<SharedFunctionInfo> shared(func->shared(), isolate);
    IsCompiledScope is_compiled_scope(shared->is_compiled_scope(isolate));
    if (is_compiled_scope.is_compiled() ||
        Compiler::Compile(isolate, func, Compiler::CLEAR_EXCEPTION,
                          &is_compiled_scope)) {
      DCHECK(shared->is_compiled());
      int count = shared->expected_nof_properties();
      // Check that the estimate is sensible.
      if (expected_nof_properties <= JSObject::kMaxInObjectProperties - count) {
        expected_nof_properties += count;
      } else {
        return JSObject::kMaxInObjectProperties;
      }
    } else {
      // In case there was a compilation error proceed iterating in case there
      // will be a builtin function in the prototype chain that requires
      // certain number of in-object properties.
      continue;
    }
  }
  // Inobject slack tracking will reclaim redundant inobject space
  // later, so we can afford to adjust the estimate generously,
  // meaning we over-allocate by at least 8 slots in the beginning.
  if (expected_nof_properties > 0) {
    expected_nof_properties += 8;
    if (expected_nof_properties > JSObject::kMaxInObjectProperties) {
      expected_nof_properties = JSObject::kMaxInObjectProperties;
    }
  }
  return expected_nof_properties;
}

// static
void JSFunction::CalculateInstanceSizeHelper(InstanceType instance_type,
                                             bool has_prototype_slot,
                                             int requested_embedder_fields,
                                             int requested_in_object_properties,
                                             int* instance_size,
                                             int* in_object_properties) {
  DCHECK_LE(static_cast<unsigned>(requested_embedder_fields),
            JSObject::kMaxEmbedderFields);
  int header_size = JSObject::GetHeaderSize(instance_type, has_prototype_slot);
  requested_embedder_fields *= kEmbedderDataSlotSizeInTaggedSlots;

  int max_nof_fields =
      (JSObject::kMaxInstanceSize - header_size) >> kTaggedSizeLog2;
  CHECK_LE(max_nof_fields, JSObject::kMaxInObjectProperties);
  CHECK_LE(static_cast<unsigned>(requested_embedder_fields),
           static_cast<unsigned>(max_nof_fields));
  *in_object_properties = std::min(requested_in_object_properties,
                                   max_nof_fields - requested_embedder_fields);
  *instance_size =
      header_size +
      ((requested_embedder_fields + *in_object_properties) << kTaggedSizeLog2);
  CHECK_EQ(*in_object_properties,
           ((*instance_size - header_size) >> kTaggedSizeLog2) -
               requested_embedder_fields);
  CHECK_LE(static_cast<unsigned>(*instance_size),
           static_cast<unsigned>(JSObject::kMaxInstanceSize));
}

void JSFunction::ClearAllTypeFeedbackInfoForTesting() {
  Isolate* isolate = GetIsolate();
  ResetIfCodeFlushed(isolate);
  if (has_feedback_vector()) {
    Tagged<FeedbackVector> vector = feedback_vector();
    if (vector->ClearAllSlotsForTesting(isolate)) {
      IC::OnFeedbackChanged(isolate, vector, FeedbackSlot::Invalid(),
                            "ClearAllTypeFeedbackInfoForTesting");
    }
  }
}

}  // namespace v8::internal

#include "src/objects/object-macros-undef.h"

"""

```