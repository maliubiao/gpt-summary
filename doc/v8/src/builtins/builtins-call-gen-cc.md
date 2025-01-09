Response:
Let's break down the thought process for analyzing this V8 C++ source code snippet.

**1. Initial Understanding of the Request:**

The request asks for the functionality of `v8/src/builtins/builtins-call-gen.cc`, treating it as a part of a larger, two-part analysis. Key instructions include identifying its purpose, checking if it would be a Torque file if it ended in `.tq`, relating it to JavaScript functionality with examples, looking for logic with input/output, identifying common programming errors, and summarizing its function for part 1.

**2. High-Level Code Scan and Keyword Identification:**

I first scanned the code for recognizable V8/C++ keywords and patterns:

* **`#include` directives:**  These indicate dependencies on other V8 components like `builtins-inl.h`, `builtins-utils-gen.h`, `macro-assembler.h`, `objects/...h`, and `codegen/...h`. This immediately suggests this file deals with code generation for built-in functions related to calling.
* **`namespace v8::internal`:**  This confirms it's internal V8 implementation code.
* **`Builtins::Generate_...` functions:** These are the core of the file. The naming convention (`Generate_CallFunction`, `Generate_CallBoundFunction`, `Generate_CallVarargs`, `Generate_CallApiCallback`) strongly indicates that this file is responsible for generating the actual machine code instructions for various call scenarios.
* **`MacroAssembler* masm`:**  This confirms that the code is about low-level code generation. `MacroAssembler` is V8's class for emitting machine instructions.
* **`TF_BUILTIN` macro:** This signifies definitions of built-in functions using the TurboFan compiler's code generation capabilities. The names following this macro (e.g., `Call_ReceiverIsNullOrUndefined_Baseline_Compact`) further reinforce the focus on different call scenarios.
* **`CallOrConstructBuiltinsAssembler` class:** This class appears to be a higher-level abstraction built upon `MacroAssembler`, offering more structured ways to generate code for calls and constructions.
* **`TailCallBuiltin`:**  This indicates optimizations where one function call directly jumps to another, avoiding unnecessary stack frames.
* **Keywords like `ConvertReceiverMode`, `CallApiCallbackMode`, `CallOrConstructMode`, `FeedbackVector`, `Context`, `Arguments`, `JSArray`, `FixedArray`, `HeapNumber`, `Map`, etc.:** These point to V8's object model and runtime concepts related to function calls and argument handling.

**3. Deduction of Primary Functionality:**

Based on the keywords and function names, the primary function of `builtins-call-gen.cc` is to *generate the machine code* for different ways functions are called in V8. This includes:

* Regular function calls.
* Calls with specific receiver requirements (null/undefined, not null/undefined, any).
* Calls to bound functions.
* Calls with variable arguments (varargs).
* Forwarding of varargs.
* Calls to API callbacks (functions provided by embedders).
* Optimized and baseline call paths.

**4. Addressing Specific Questions:**

* **`.tq` extension:** The text explicitly states that a `.tq` extension indicates a Torque source file. This is a direct answer.
* **Relationship to JavaScript:** Since this file generates the low-level code for function calls, it's fundamentally related to JavaScript's core execution model. The different `Generate_Call...` functions correspond directly to how JavaScript code invokes functions. I started thinking about common JavaScript call patterns:
    * `function foo() {} foo();` (simple call)
    * `obj.method();` (method call, receiver)
    * `func.call(thisArg, arg1, arg2);` (explicit receiver)
    * `func.apply(thisArg, [arg1, arg2]);` (array-like arguments)
    * `new MyClass();` (constructor call)
    * `...` spread syntax in calls.
    This helped in formulating the JavaScript examples.
* **Code Logic and Input/Output:** The `CallOrConstructWithArrayLike` and `CallOrConstructWithSpread` functions have more involved logic. I looked for branching (`if`, `else`, `GotoIf`) and variable assignments. For `CallOrConstructWithArrayLike`, the input is a target function, an optional `new_target` (for constructors), and an `arguments_list`. The output is a tail call to a specific `CallVarargs` or `ConstructVarargs` builtin. I then considered simple cases to illustrate the flow.
* **Common Programming Errors:**  Given the focus on function calls, I considered common mistakes:
    * Calling a non-callable object.
    * Using `call` or `apply` with an incorrect `this` value.
    * Incorrectly using the spread operator.
* **Summarizing Functionality (Part 1):**  This involves synthesizing the points above into a concise description of the file's purpose.

**5. Iterative Refinement:**

My initial analysis might be slightly less structured. I would then review the code and my notes to:

* **Group related functionalities:** Notice the patterns in `Generate_CallFunction_...`, `Generate_Call_...`, and the different `TF_BUILTIN` variations.
* **Identify key abstractions:** Recognize the roles of `MacroAssembler` and `CallOrConstructBuiltinsAssembler`.
* **Refine the JavaScript examples:** Ensure they clearly illustrate the corresponding C++ functions.
* **Strengthen the input/output analysis:** Make the assumptions and outcomes more explicit.
* **Ensure the common errors are relevant:** Focus on mistakes directly related to function calls.

**Self-Correction Example During the Process:**

Initially, I might have focused too much on the individual `Generate_...` functions without seeing the bigger picture. Realizing that they all contribute to *calling functions* at a low level helped me formulate a better summary. Similarly, I might initially miss the significance of the `ConvertReceiverMode` enum, but upon closer inspection of the function names and their usage, its role becomes clear. The process is about starting with the obvious and gradually digging deeper to understand the relationships and purpose of different code sections.
这是对V8源代码文件 `v8/src/builtins/builtins-call-gen.cc` 功能的详细分析。

**核心功能归纳:**

`v8/src/builtins/builtins-call-gen.cc` 的主要功能是**生成用于执行 JavaScript 函数调用的内置函数的机器码**。  它包含了多种函数调用场景的代码生成逻辑，涵盖了不同的调用模式、参数处理方式以及对 API 回调的支持。

**具体功能分解:**

1. **生成不同调用模式的内置函数:**
   - `Generate_CallFunction_ReceiverIsNullOrUndefined`: 生成当接收者为 `null` 或 `undefined` 时调用函数的机器码。
   - `Generate_CallFunction_ReceiverIsNotNullOrUndefined`: 生成当接收者不为 `null` 或 `undefined` 时调用函数的机器码。
   - `Generate_CallFunction_ReceiverIsAny`: 生成接收者可以是任何值时调用函数的机器码。
   - `Generate_CallBoundFunction`: 生成调用绑定函数的机器码。
   - `Generate_Call_ReceiverIsNullOrUndefined`、`Generate_Call_ReceiverIsNotNullOrUndefined`、`Generate_Call_ReceiverIsAny`: 这些与 `Generate_CallFunction_...` 类似，但可能在内部实现上有所区别，对应不同的调用入口点。

2. **生成处理变长参数的内置函数:**
   - `Generate_CallVarargs`: 生成处理可变数量参数的函数调用的机器码。
   - `Generate_CallForwardVarargs`: 生成将可变数量参数转发给另一个函数的机器码。
   - `Generate_CallFunctionForwardVarargs`:  与上类似，但明确针对函数调用。

3. **生成调用 C++ API 回调的内置函数:**
   - `Generate_CallApiCallbackGeneric`: 生成调用通用 C++ API 回调的机器码。
   - `Generate_CallApiCallbackOptimizedNoProfiling`: 生成调用优化过的、无性能分析的 C++ API 回调的机器码。
   - `Generate_CallApiCallbackOptimized`: 生成调用优化过的 C++ API 回调的机器码。

4. **使用 TurboFan Builtin (TF_BUILTIN) 定义基线和带反馈的调用内置函数:**
   - 例如 `TF_BUILTIN(Call_ReceiverIsNullOrUndefined_Baseline_Compact, ...)` 和 `TF_BUILTIN(Call_ReceiverIsNullOrUndefined_WithFeedback, ...)`。
   - 这些宏定义了使用 TurboFan 编译器生成的内置函数，包含了基线版本（通常更简单更快）和带有运行时反馈的版本（用于优化）。
   - `_Compact` 后缀可能表示更紧凑的代码生成。
   - `_WithFeedback` 版本会收集调用站点的反馈信息，用于后续的优化。

5. **实现 `CallOrConstructBuiltinsAssembler` 类中的高级调用/构造逻辑:**
   - `CallOrConstructWithArrayLike`:  处理使用类似数组的对象作为参数列表进行函数调用或构造的情况。这对应于 JavaScript 中的 `Function.prototype.apply`。
   - `CallOrConstructWithSpread`: 处理使用展开语法 (`...`) 进行函数调用或构造的情况。
   - `CallOrConstructDoubleVarargs`:  专门处理参数为双精度浮点数数组的情况。
   - `GetCompatibleReceiver`: 用于 API 回调中查找兼容的接收者对象。
   - `CallFunctionTemplate`: 用于调用通过 `FunctionTemplate` 创建的 API 回调函数，并进行访问检查和兼容性检查。

**如果 v8/src/builtins/builtins-call-gen.cc 以 .tq 结尾:**

如果该文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是一种 V8 自研的领域特定语言，用于更安全、更易于维护地编写内置函数的代码。Torque 代码会被编译成 C++ 代码，最终生成机器码。

**与 JavaScript 功能的关系及示例:**

这个文件中的代码生成逻辑直接对应于 JavaScript 中各种函数调用的方式。

* **普通函数调用:**
   ```javascript
   function greet(name) {
     console.log("Hello, " + name);
   }
   greet("World"); // 对应 Builtins::Generate_CallFunction_ReceiverIsAny 等
   ```

* **方法调用 (隐式绑定 `this`):**
   ```javascript
   const obj = {
     name: "Object",
     sayHello() {
       console.log("Hello from " + this.name);
     }
   };
   obj.sayHello(); // 对应 Builtins::Generate_CallFunction_ReceiverIsNotNullOrUndefined 等
   ```

* **使用 `call` 或 `apply` (显式绑定 `this`):**
   ```javascript
   function say(greeting) {
     console.log(greeting + ", " + this.name);
   }
   const person = { name: "Alice" };
   say.call(person, "Hi");   // 对应 Builtins::Generate_Call_ReceiverIsNotNullOrUndefined 等
   say.apply(person, ["Greetings"]); // 对应 Builtins::Generate_CallWithArrayLike 等
   ```

* **变长参数 (剩余参数):**
   ```javascript
   function sum(...numbers) {
     return numbers.reduce((a, b) => a + b, 0);
   }
   sum(1, 2, 3, 4); // 对应 Builtins::Generate_CallVarargs 等
   ```

* **展开语法:**
   ```javascript
   function combine(a, b, c) {
     console.log(a, b, c);
   }
   const arr = [10, 20, 30];
   combine(...arr); // 对应 Builtins::Generate_CallWithSpread 等
   ```

* **API 回调 (通常在 Node.js 或浏览器扩展中使用):**
   ```c++
   // C++ 代码中定义一个函数模板
   void MyFunctionCallback(const FunctionCallbackInfo<Value>& args) {
       // ...
   }

   // 将该回调函数关联到 JavaScript 函数
   Local<FunctionTemplate> tpl = FunctionTemplate::New(isolate, MyFunctionCallback);
   ```
   JavaScript 调用这个由 C++ 定义的函数时，会涉及到 `Builtins::Generate_CallApiCallbackGeneric` 等生成的代码。

**代码逻辑推理 (假设输入与输出):**

以 `CallOrConstructWithArrayLike` 为例：

**假设输入:**
- `target`: 一个 JavaScript 函数对象 (例如 `function add(a, b) { return a + b; }`)
- `arguments_list`: 一个类似数组的对象 (例如 `arguments` 对象或一个数组 `[1, 2]`)
- `context`: 当前的执行上下文

**可能的输出:**
- 如果 `arguments_list` 是一个真正的快速 `JSArray`，并且元素是基本类型（非 double），则会尾调用 `Builtin::kCallVarargs`，将参数直接传递给目标函数。
- 如果 `arguments_list` 是一个包含空洞或双精度浮点数的 `JSArray`，或者是一个 `arguments` 对象，或者不是一个 `JSArray`，则可能需要调用 `Runtime::kCreateListFromArrayLike` 将其转换为一个规范的数组。
- 最终会尾调用 `Builtin::kCallVarargs` 或 `Builtin::kConstructVarargs` (如果调用的是构造函数)，将处理后的参数传递给目标函数。

**涉及用户常见的编程错误:**

1. **尝试调用非函数对象:**
   ```javascript
   const notAFunction = {};
   notAFunction(); // TypeError: notAFunction is not a function
   ```
   `builtins-call-gen.cc` 中的代码会检查目标对象是否可调用，并在遇到错误时抛出异常。

2. **在 `call` 或 `apply` 中使用不合适的 `this` 值:**
   ```javascript
   function showName() {
     console.log(this.name);
   }
   const myObj = { name: "My Object" };
   showName.call(null); //  'this' 指向全局对象 (非严格模式) 或 undefined (严格模式)
   showName.call(myObj); // 'this' 指向 myObj
   ```
   `builtins-call-gen.cc` 中对于不同 `ConvertReceiverMode` 的处理，例如 `kNullOrUndefined` 和 `kNotNullOrUndefined`，就与 `call` 和 `apply` 中 `this` 值的传递有关。

3. **`apply` 的参数不是类数组对象:**
   ```javascript
   function sum(a, b) { return a + b; }
   sum.apply(null, 10); // TypeError: CreateListFromArrayLike called on non-object
   ```
   `CallOrConstructWithArrayLike` 函数会检查 `arguments_list` 是否是类数组对象，如果不是，则会触发运行时错误。

4. **展开语法使用错误:**
   ```javascript
   function greet(name, age) {
     console.log(`Hello, ${name}, you are ${age} years old.`);
   }
   const info = { userName: "Bob", userAge: 30 };
   greet(...info); //  结果可能不是预期的，因为展开的是对象的属性
   ```
   `CallOrConstructWithSpread` 函数处理展开语法时，会尝试将展开的对象转换为可迭代对象或数组，如果转换失败可能会导致错误。

**第1部分功能归纳:**

总而言之，`v8/src/builtins/builtins-call-gen.cc` 是 V8 引擎中负责 **生成各种 JavaScript 函数调用场景的底层机器码**的关键组成部分。它定义了不同调用模式、参数处理方式以及 API 回调的实现，并且通过 TurboFan Builtin 提供了优化和基线版本的实现。 这个文件是理解 V8 如何高效执行 JavaScript 函数调用的基础。

Prompt: 
```
这是目录为v8/src/builtins/builtins-call-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-call-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-call-gen.h"

#include <optional>

#include "src/builtins/builtins-inl.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/codegen/macro-assembler.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/execution/protectors.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/arguments.h"
#include "src/objects/property-cell.h"
#include "src/objects/templates.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

void Builtins::Generate_CallFunction_ReceiverIsNullOrUndefined(
    MacroAssembler* masm) {
  Generate_CallFunction(masm, ConvertReceiverMode::kNullOrUndefined);
}

void Builtins::Generate_CallFunction_ReceiverIsNotNullOrUndefined(
    MacroAssembler* masm) {
  Generate_CallFunction(masm, ConvertReceiverMode::kNotNullOrUndefined);
}

void Builtins::Generate_CallFunction_ReceiverIsAny(MacroAssembler* masm) {
  Generate_CallFunction(masm, ConvertReceiverMode::kAny);
}

void Builtins::Generate_CallBoundFunction(MacroAssembler* masm) {
  Generate_CallBoundFunctionImpl(masm);
}

void Builtins::Generate_Call_ReceiverIsNullOrUndefined(MacroAssembler* masm) {
  Generate_Call(masm, ConvertReceiverMode::kNullOrUndefined);
}

void Builtins::Generate_Call_ReceiverIsNotNullOrUndefined(
    MacroAssembler* masm) {
  Generate_Call(masm, ConvertReceiverMode::kNotNullOrUndefined);
}

void Builtins::Generate_Call_ReceiverIsAny(MacroAssembler* masm) {
  Generate_Call(masm, ConvertReceiverMode::kAny);
}

void Builtins::Generate_CallVarargs(MacroAssembler* masm) {
  Generate_CallOrConstructVarargs(masm, Builtins::Call());
}

void Builtins::Generate_CallForwardVarargs(MacroAssembler* masm) {
  Generate_CallOrConstructForwardVarargs(masm, CallOrConstructMode::kCall,
                                         Builtins::Call());
}

void Builtins::Generate_CallFunctionForwardVarargs(MacroAssembler* masm) {
  Generate_CallOrConstructForwardVarargs(masm, CallOrConstructMode::kCall,
                                         Builtins::CallFunction());
}

void Builtins::Generate_CallApiCallbackGeneric(MacroAssembler* masm) {
  Generate_CallApiCallbackImpl(masm, CallApiCallbackMode::kGeneric);
}

void Builtins::Generate_CallApiCallbackOptimizedNoProfiling(
    MacroAssembler* masm) {
  Generate_CallApiCallbackImpl(masm,
                               CallApiCallbackMode::kOptimizedNoProfiling);
}

void Builtins::Generate_CallApiCallbackOptimized(MacroAssembler* masm) {
  Generate_CallApiCallbackImpl(masm, CallApiCallbackMode::kOptimized);
}

// TODO(cbruni): Try reusing code between builtin versions to avoid binary
// overhead.
TF_BUILTIN(Call_ReceiverIsNullOrUndefined_Baseline_Compact,
           CallOrConstructBuiltinsAssembler) {
  auto receiver = UndefinedConstant();
  CallReceiver<Descriptor>(Builtin::kCall_ReceiverIsNullOrUndefined, receiver);
}

TF_BUILTIN(Call_ReceiverIsNullOrUndefined_Baseline,
           CallOrConstructBuiltinsAssembler) {
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);
  auto receiver = UndefinedConstant();
  CallReceiver<Descriptor>(Builtin::kCall_ReceiverIsNullOrUndefined, argc, slot,
                           receiver);
}

TF_BUILTIN(Call_ReceiverIsNotNullOrUndefined_Baseline_Compact,
           CallOrConstructBuiltinsAssembler) {
  CallReceiver<Descriptor>(Builtin::kCall_ReceiverIsNotNullOrUndefined);
}

TF_BUILTIN(Call_ReceiverIsNotNullOrUndefined_Baseline,
           CallOrConstructBuiltinsAssembler) {
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);
  CallReceiver<Descriptor>(Builtin::kCall_ReceiverIsNotNullOrUndefined, argc,
                           slot);
}

TF_BUILTIN(Call_ReceiverIsAny_Baseline_Compact,
           CallOrConstructBuiltinsAssembler) {
  CallReceiver<Descriptor>(Builtin::kCall_ReceiverIsAny);
}

TF_BUILTIN(Call_ReceiverIsAny_Baseline, CallOrConstructBuiltinsAssembler) {
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);
  CallReceiver<Descriptor>(Builtin::kCall_ReceiverIsAny, argc, slot);
}

TF_BUILTIN(Call_ReceiverIsNullOrUndefined_WithFeedback,
           CallOrConstructBuiltinsAssembler) {
  auto target = Parameter<Object>(Descriptor::kFunction);
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto feedback_vector = Parameter<FeedbackVector>(Descriptor::kFeedbackVector);
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  CollectCallFeedback(
      target, [=] { return receiver; }, context, feedback_vector, slot);
  TailCallBuiltin(Builtin::kCall_ReceiverIsNullOrUndefined, context, target,
                  argc);
}

TF_BUILTIN(Call_ReceiverIsNotNullOrUndefined_WithFeedback,
           CallOrConstructBuiltinsAssembler) {
  auto target = Parameter<Object>(Descriptor::kFunction);
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto feedback_vector = Parameter<FeedbackVector>(Descriptor::kFeedbackVector);
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  CollectCallFeedback(
      target, [=] { return receiver; }, context, feedback_vector, slot);
  TailCallBuiltin(Builtin::kCall_ReceiverIsNotNullOrUndefined, context, target,
                  argc);
}

TF_BUILTIN(Call_ReceiverIsAny_WithFeedback, CallOrConstructBuiltinsAssembler) {
  auto target = Parameter<Object>(Descriptor::kFunction);
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto feedback_vector = Parameter<FeedbackVector>(Descriptor::kFeedbackVector);
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  CollectCallFeedback(
      target, [=] { return receiver; }, context, feedback_vector, slot);
  TailCallBuiltin(Builtin::kCall_ReceiverIsAny, context, target, argc);
}

void CallOrConstructBuiltinsAssembler::CallOrConstructWithArrayLike(
    TNode<Object> target, std::optional<TNode<Object>> new_target,
    TNode<Object> arguments_list, TNode<Context> context) {
  Label if_done(this), if_arguments(this), if_array(this),
      if_holey_array(this, Label::kDeferred),
      if_runtime(this, Label::kDeferred);

  // Perform appropriate checks on {target} (and {new_target} first).
  if (!new_target) {
    // Check that {target} is Callable.
    Label if_target_callable(this),
        if_target_not_callable(this, Label::kDeferred);
    GotoIf(TaggedIsSmi(target), &if_target_not_callable);
    Branch(IsCallable(CAST(target)), &if_target_callable,
           &if_target_not_callable);
    BIND(&if_target_not_callable);
    {
      CallRuntime(Runtime::kThrowApplyNonFunction, context, target);
      Unreachable();
    }
    BIND(&if_target_callable);
  } else {
    // Check that {target} is a Constructor.
    Label if_target_constructor(this),
        if_target_not_constructor(this, Label::kDeferred);
    GotoIf(TaggedIsSmi(target), &if_target_not_constructor);
    Branch(IsConstructor(CAST(target)), &if_target_constructor,
           &if_target_not_constructor);
    BIND(&if_target_not_constructor);
    {
      CallRuntime(Runtime::kThrowNotConstructor, context, target);
      Unreachable();
    }
    BIND(&if_target_constructor);

    // Check that {new_target} is a Constructor.
    Label if_new_target_constructor(this),
        if_new_target_not_constructor(this, Label::kDeferred);
    GotoIf(TaggedIsSmi(*new_target), &if_new_target_not_constructor);
    Branch(IsConstructor(CAST(*new_target)), &if_new_target_constructor,
           &if_new_target_not_constructor);
    BIND(&if_new_target_not_constructor);
    {
      CallRuntime(Runtime::kThrowNotConstructor, context, *new_target);
      Unreachable();
    }
    BIND(&if_new_target_constructor);
  }

  GotoIf(TaggedIsSmi(arguments_list), &if_runtime);

  TNode<Map> arguments_list_map = LoadMap(CAST(arguments_list));
  TNode<NativeContext> native_context = LoadNativeContext(context);

  // Check if {arguments_list} is an (unmodified) arguments object.
  TNode<Map> sloppy_arguments_map = CAST(
      LoadContextElement(native_context, Context::SLOPPY_ARGUMENTS_MAP_INDEX));
  GotoIf(TaggedEqual(arguments_list_map, sloppy_arguments_map), &if_arguments);
  TNode<Map> strict_arguments_map = CAST(
      LoadContextElement(native_context, Context::STRICT_ARGUMENTS_MAP_INDEX));
  GotoIf(TaggedEqual(arguments_list_map, strict_arguments_map), &if_arguments);

  // Check if {arguments_list} is a fast JSArray.
  Branch(IsJSArrayMap(arguments_list_map), &if_array, &if_runtime);

  TVARIABLE(FixedArrayBase, var_elements);
  TVARIABLE(Int32T, var_length);
  BIND(&if_array);
  {
    TNode<Int32T> kind = LoadMapElementsKind(arguments_list_map);
    GotoIf(
        IsElementsKindGreaterThan(kind, LAST_ANY_NONEXTENSIBLE_ELEMENTS_KIND),
        &if_runtime);

    TNode<JSObject> js_object = CAST(arguments_list);
    // Try to extract the elements from a JSArray object.
    var_elements = LoadElements(js_object);
    var_length =
        LoadAndUntagToWord32ObjectField(js_object, JSArray::kLengthOffset);

    // Holey arrays and double backing stores need special treatment.
    static_assert(PACKED_SMI_ELEMENTS == 0);
    static_assert(HOLEY_SMI_ELEMENTS == 1);
    static_assert(PACKED_ELEMENTS == 2);
    static_assert(HOLEY_ELEMENTS == 3);
    static_assert(PACKED_DOUBLE_ELEMENTS == 4);
    static_assert(HOLEY_DOUBLE_ELEMENTS == 5);
    static_assert(LAST_FAST_ELEMENTS_KIND == HOLEY_DOUBLE_ELEMENTS);

    Branch(Word32And(kind, Int32Constant(1)), &if_holey_array, &if_done);
  }

  BIND(&if_holey_array);
  {
    // For holey JSArrays we need to check that the array prototype chain
    // protector is intact and our prototype is the Array.prototype actually.
    GotoIfNot(IsPrototypeInitialArrayPrototype(context, arguments_list_map),
              &if_runtime);
    Branch(IsNoElementsProtectorCellInvalid(), &if_runtime, &if_done);
  }

  BIND(&if_arguments);
  {
    TNode<JSArgumentsObject> js_arguments = CAST(arguments_list);
    // Try to extract the elements from a JSArgumentsObject with standard map.
    TNode<Object> length = LoadJSArgumentsObjectLength(context, js_arguments);
    TNode<FixedArrayBase> elements = LoadElements(js_arguments);
    TNode<Smi> elements_length = LoadFixedArrayBaseLength(elements);
    GotoIfNot(TaggedEqual(length, elements_length), &if_runtime);
    var_elements = elements;
    var_length = SmiToInt32(CAST(length));
    Goto(&if_done);
  }

  BIND(&if_runtime);
  {
    // Ask the runtime to create the list (actually a FixedArray).
    var_elements = CAST(CallRuntime(Runtime::kCreateListFromArrayLike, context,
                                    arguments_list));
    var_length = LoadAndUntagToWord32ObjectField(var_elements.value(),
                                                 offsetof(FixedArray, length_));
    Goto(&if_done);
  }

  // Tail call to the appropriate builtin (depending on whether we have
  // a {new_target} passed).
  BIND(&if_done);
  {
    Label if_not_double(this), if_double(this);
    TNode<Int32T> args_count =
        Int32Constant(i::JSParameterCount(0));  // args already on the stack

    TNode<Int32T> length = var_length.value();
    {
      Label normalize_done(this);
      CSA_DCHECK(this, Int32LessThanOrEqual(
                           length, Int32Constant(FixedArray::kMaxLength)));
      GotoIfNot(Word32Equal(length, Int32Constant(0)), &normalize_done);
      // Make sure we don't accidentally pass along the
      // empty_fixed_double_array since the tailed-called stubs cannot handle
      // the normalization yet.
      var_elements = EmptyFixedArrayConstant();
      Goto(&normalize_done);

      BIND(&normalize_done);
    }

    TNode<FixedArrayBase> elements = var_elements.value();
    Branch(IsFixedDoubleArray(elements), &if_double, &if_not_double);

    BIND(&if_not_double);
    {
      if (!new_target) {
        TailCallBuiltin(Builtin::kCallVarargs, context, target, args_count,
                        length, elements);
      } else {
        TailCallBuiltin(Builtin::kConstructVarargs, context, target,
                        *new_target, args_count, length, elements);
      }
    }

    BIND(&if_double);
    {
      // Kind is hardcoded here because CreateListFromArrayLike will only
      // produce holey double arrays.
      CallOrConstructDoubleVarargs(target, new_target, CAST(elements), length,
                                   args_count, context,
                                   Int32Constant(HOLEY_DOUBLE_ELEMENTS));
    }
  }
}

// Takes a FixedArray of doubles and creates a new FixedArray with those doubles
// boxed as HeapNumbers, then tail calls CallVarargs/ConstructVarargs depending
// on whether {new_target} was passed.
void CallOrConstructBuiltinsAssembler::CallOrConstructDoubleVarargs(
    TNode<Object> target, std::optional<TNode<Object>> new_target,
    TNode<FixedDoubleArray> elements, TNode<Int32T> length,
    TNode<Int32T> args_count, TNode<Context> context, TNode<Int32T> kind) {
  const ElementsKind new_kind = PACKED_ELEMENTS;
  const WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER;
  CSA_DCHECK(this, Int32LessThanOrEqual(length,
                                        Int32Constant(FixedArray::kMaxLength)));
  TNode<IntPtrT> intptr_length = ChangeInt32ToIntPtr(length);
  CSA_DCHECK(this, WordNotEqual(intptr_length, IntPtrConstant(0)));

  // Allocate a new FixedArray of Objects.
  TNode<FixedArray> new_elements =
      CAST(AllocateFixedArray(new_kind, intptr_length));
  // CopyFixedArrayElements does not distinguish between holey and packed for
  // its first argument, so we don't need to dispatch on {kind} here.
  CopyFixedArrayElements(PACKED_DOUBLE_ELEMENTS, elements, new_kind,
                         new_elements, intptr_length, intptr_length,
                         barrier_mode);
  if (!new_target) {
    TailCallBuiltin(Builtin::kCallVarargs, context, target, args_count, length,
                    new_elements);
  } else {
    TailCallBuiltin(Builtin::kConstructVarargs, context, target, *new_target,
                    args_count, length, new_elements);
  }
}

void CallOrConstructBuiltinsAssembler::CallOrConstructWithSpread(
    TNode<Object> target, std::optional<TNode<Object>> new_target,
    TNode<Object> spread, TNode<Int32T> args_count, TNode<Context> context) {
  Label if_smiorobject(this), if_double(this),
      if_generic(this, Label::kDeferred);

  TVARIABLE(JSArray, var_js_array);
  TVARIABLE(FixedArrayBase, var_elements);
  TVARIABLE(Int32T, var_elements_kind);

  GotoIf(TaggedIsSmi(spread), &if_generic);
  TNode<Map> spread_map = LoadMap(CAST(spread));
  GotoIfNot(IsJSArrayMap(spread_map), &if_generic);
  TNode<JSArray> spread_array = CAST(spread);

  // Check that we have the original Array.prototype.
  GotoIfNot(IsPrototypeInitialArrayPrototype(context, spread_map), &if_generic);

  // Check that there are no elements on the Array.prototype chain.
  GotoIf(IsNoElementsProtectorCellInvalid(), &if_generic);

  // Check that the Array.prototype hasn't been modified in a way that would
  // affect iteration.
  TNode<PropertyCell> protector_cell = ArrayIteratorProtectorConstant();
  GotoIf(
      TaggedEqual(LoadObjectField(protector_cell, PropertyCell::kValueOffset),
                  SmiConstant(Protectors::kProtectorInvalid)),
      &if_generic);
  {
    // The fast-path accesses the {spread} elements directly.
    TNode<Int32T> spread_kind = LoadMapElementsKind(spread_map);
    var_js_array = spread_array;
    var_elements_kind = spread_kind;
    var_elements = LoadElements(spread_array);

    // Check elements kind of {spread}.
    GotoIf(IsElementsKindLessThanOrEqual(spread_kind, HOLEY_ELEMENTS),
           &if_smiorobject);
    GotoIf(IsElementsKindLessThanOrEqual(spread_kind, LAST_FAST_ELEMENTS_KIND),
           &if_double);
    Branch(IsElementsKindLessThanOrEqual(spread_kind,
                                         LAST_ANY_NONEXTENSIBLE_ELEMENTS_KIND),
           &if_smiorobject, &if_generic);
  }

  BIND(&if_generic);
  {
    Label if_iterator_fn_not_callable(this, Label::kDeferred),
        if_iterator_is_null_or_undefined(this, Label::kDeferred),
        throw_spread_error(this, Label::kDeferred);
    TVARIABLE(Smi, message_id);

    GotoIf(IsNullOrUndefined(spread), &if_iterator_is_null_or_undefined);

    TNode<Object> iterator_fn =
        GetProperty(context, spread, IteratorSymbolConstant());
    GotoIfNot(TaggedIsCallable(iterator_fn), &if_iterator_fn_not_callable);
    TNode<JSArray> list =
        CAST(CallBuiltin(Builtin::kIterableToListMayPreserveHoles, context,
                         spread, iterator_fn));

    var_js_array = list;
    var_elements = LoadElements(list);
    var_elements_kind = LoadElementsKind(list);
    Branch(Int32LessThan(var_elements_kind.value(),
                         Int32Constant(PACKED_DOUBLE_ELEMENTS)),
           &if_smiorobject, &if_double);

    BIND(&if_iterator_fn_not_callable);
    message_id = SmiConstant(
        static_cast<int>(MessageTemplate::kSpreadIteratorSymbolNonCallable)),
    Goto(&throw_spread_error);

    BIND(&if_iterator_is_null_or_undefined);
    message_id = SmiConstant(
        static_cast<int>(MessageTemplate::kNotIterableNoSymbolLoad));
    Goto(&throw_spread_error);

    BIND(&throw_spread_error);
    CallRuntime(Runtime::kThrowSpreadArgError, context, message_id.value(),
                spread);
    Unreachable();
  }

  BIND(&if_smiorobject);
  {
    TNode<Int32T> length = LoadAndUntagToWord32ObjectField(
        var_js_array.value(), JSArray::kLengthOffset);
    TNode<FixedArrayBase> elements = var_elements.value();
    CSA_DCHECK(this, Int32LessThanOrEqual(
                         length, Int32Constant(FixedArray::kMaxLength)));

    if (!new_target) {
      TailCallBuiltin(Builtin::kCallVarargs, context, target, args_count,
                      length, elements);
    } else {
      TailCallBuiltin(Builtin::kConstructVarargs, context, target, *new_target,
                      args_count, length, elements);
    }
  }

  BIND(&if_double);
  {
    TNode<Int32T> length = LoadAndUntagToWord32ObjectField(
        var_js_array.value(), JSArray::kLengthOffset);
    GotoIf(Word32Equal(length, Int32Constant(0)), &if_smiorobject);
    CallOrConstructDoubleVarargs(target, new_target, CAST(var_elements.value()),
                                 length, args_count, context,
                                 var_elements_kind.value());
  }
}

template <class Descriptor>
void CallOrConstructBuiltinsAssembler::CallReceiver(
    Builtin id, std::optional<TNode<Object>> receiver) {
  static_assert(std::is_same<Descriptor,
                             CallTrampoline_Baseline_CompactDescriptor>::value,
                "Incompatible Descriptor");
  auto bitfield = UncheckedParameter<Word32T>(Descriptor::kBitField);
  TNode<Int32T> argc =
      Signed(DecodeWord32<
             CallTrampoline_Baseline_CompactDescriptor::ArgumentCountField>(
          bitfield));
  TNode<UintPtrT> slot = ChangeUint32ToWord(
      DecodeWord32<CallTrampoline_Baseline_CompactDescriptor::SlotField>(
          bitfield));
  CallReceiver<Descriptor>(id, argc, slot, receiver);
}

template <class Descriptor>
void CallOrConstructBuiltinsAssembler::CallReceiver(
    Builtin id, TNode<Int32T> argc, TNode<UintPtrT> slot,
    std::optional<TNode<Object>> maybe_receiver) {
  auto target = Parameter<Object>(Descriptor::kFunction);
  auto context = LoadContextFromBaseline();
  auto feedback_vector = LoadFeedbackVectorFromBaseline();
  LazyNode<Object> receiver = [=, this] {
    if (maybe_receiver) {
      return *maybe_receiver;
    } else {
      CodeStubArguments args(this, argc);
      return args.GetReceiver();
    }
  };

  CollectCallFeedback(target, receiver, context, feedback_vector, slot);
  TailCallBuiltin(id, context, target, argc);
}

TF_BUILTIN(CallWithArrayLike, CallOrConstructBuiltinsAssembler) {
  auto target = Parameter<Object>(Descriptor::kTarget);
  std::optional<TNode<Object>> new_target = std::nullopt;
  auto arguments_list = Parameter<Object>(Descriptor::kArgumentsList);
  auto context = Parameter<Context>(Descriptor::kContext);
  CallOrConstructWithArrayLike(target, new_target, arguments_list, context);
}

// TODO(ishell): not used, consider removing.
TF_BUILTIN(CallWithArrayLike_WithFeedback, CallOrConstructBuiltinsAssembler) {
  auto target = Parameter<Object>(Descriptor::kTarget);
  std::optional<TNode<Object>> new_target = std::nullopt;
  auto arguments_list = Parameter<Object>(Descriptor::kArgumentsList);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto feedback_vector = Parameter<FeedbackVector>(Descriptor::kFeedbackVector);
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  CollectCallFeedback(
      target, [=] { return receiver; }, context, feedback_vector, slot);
  CallOrConstructWithArrayLike(target, new_target, arguments_list, context);
}

TF_BUILTIN(CallWithSpread, CallOrConstructBuiltinsAssembler) {
  auto target = Parameter<Object>(Descriptor::kTarget);
  std::optional<TNode<Object>> new_target = std::nullopt;
  auto spread = Parameter<Object>(Descriptor::kSpread);
  auto args_count = UncheckedParameter<Int32T>(Descriptor::kArgumentsCount);
  auto context = Parameter<Context>(Descriptor::kContext);
  CallOrConstructWithSpread(target, new_target, spread, args_count, context);
}

TF_BUILTIN(CallWithSpread_Baseline, CallOrConstructBuiltinsAssembler) {
  auto target = Parameter<Object>(Descriptor::kTarget);
  std::optional<TNode<Object>> new_target = std::nullopt;
  auto spread = Parameter<Object>(Descriptor::kSpread);
  auto args_count = UncheckedParameter<Int32T>(Descriptor::kArgumentsCount);
  auto context = LoadContextFromBaseline();
  auto feedback_vector = LoadFeedbackVectorFromBaseline();
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);
  CodeStubArguments args(this, args_count);
  CollectCallFeedback(
      target, [=] { return args.GetReceiver(); }, context, feedback_vector,
      slot);
  CallOrConstructWithSpread(target, new_target, spread, args_count, context);
}

TF_BUILTIN(CallWithSpread_WithFeedback, CallOrConstructBuiltinsAssembler) {
  auto target = Parameter<Object>(Descriptor::kTarget);
  std::optional<TNode<Object>> new_target = std::nullopt;
  auto spread = Parameter<Object>(Descriptor::kSpread);
  auto args_count = UncheckedParameter<Int32T>(Descriptor::kArgumentsCount);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto feedback_vector = Parameter<FeedbackVector>(Descriptor::kFeedbackVector);
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  CollectCallFeedback(
      target, [=] { return receiver; }, context, feedback_vector, slot);
  CallOrConstructWithSpread(target, new_target, spread, args_count, context);
}

TNode<JSReceiver> CallOrConstructBuiltinsAssembler::GetCompatibleReceiver(
    TNode<JSReceiver> receiver, TNode<HeapObject> signature,
    TNode<Context> context) {
  // Walk up the hidden prototype chain to find the compatible holder
  // for the {signature}, starting with the {receiver} itself.
  //
  // Be careful, these loops are hand-tuned for (close to) ideal CSA
  // code generation. Especially the sharing of the {var_template}
  // below is intentional (even though it reads a bit funny in the
  // first loop).
  TVARIABLE(HeapObject, var_holder, receiver);
  Label holder_loop(this, &var_holder), holder_found(this, &var_holder),
      holder_next(this, Label::kDeferred);
  Goto(&holder_loop);
  BIND(&holder_loop);
  {
    // Find the template to compare against the {signature}. We don't
    // bother checking that the template is a FunctionTemplateInfo here,
    // but instead do that as part of the template loop below. The only
    // thing we care about is that the template is actually a HeapObject.
    TNode<HeapObject> holder = var_holder.value();
    TVARIABLE(HeapObject, var_template, LoadMap(holder));
    Label template_map_loop(this, &var_template),
        template_loop(this, &var_template),
        template_from_closure(this, &var_template);
    Goto(&template_map_loop);
    BIND(&template_map_loop);
    {
      // Load the constructor field from the current map (in the
      // {var_template} variable), and see if that is a HeapObject.
      // If it's a Smi then it is non-instance prototype on some
      // initial map, which cannot be the case for API instances.
      TNode<Object> constructor =
          LoadObjectField(var_template.value(),
                          Map::kConstructorOrBackPointerOrNativeContextOffset);
      GotoIf(TaggedIsSmi(constructor), &holder_next);

      // Now there are three cases for {constructor} that we care
      // about here:
      //
      //  1. {constructor} is a JSFunction, and we can load the template
      //     from its SharedFunctionInfo::function_data field (which
      //     may not actually be a FunctionTemplateInfo).
      //  2. {constructor} is a Map, in which case it's not a constructor
      //     but a back-pointer and we follow that.
      //  3. {constructor} is a FunctionTemplateInfo (or some other
      //     HeapObject), in which case we can directly use that for
      //     the template loop below (non-FunctionTemplateInfo objects
      //     will be ruled out there).
      //
      var_template = CAST(constructor);
      TNode<Uint16T> template_type = LoadInstanceType(var_template.value());
      GotoIf(IsJSFunctionInstanceType(template_type), &template_from_closure);
      Branch(InstanceTypeEqual(template_type, MAP_TYPE), &template_map_loop,
             &template_loop);
    }

    BIND(&template_from_closure);
    {
      // The first case from above, where we load the template from the
      // SharedFunctionInfo of the closure. We only check that the
      // SharedFunctionInfo::function_data is a HeapObject and blindly
      // use that as a template, since a non-FunctionTemplateInfo objects
      // will be ruled out automatically by the template loop below.
      TNode<SharedFunctionInfo> template_shared =
          LoadObjectField<SharedFunctionInfo>(
              var_template.value(), JSFunction::kSharedFunctionInfoOffset);
      TNode<Object> template_data =
          LoadSharedFunctionInfoUntrustedFunctionData(template_shared);
      GotoIf(TaggedIsSmi(template_data), &holder_next);
      var_template = CAST(template_data);
      Goto(&template_loop);
    }

    BIND(&template_loop);
    {
      // This loop compares the template to the expected {signature},
      // following the chain of parent templates until it hits the
      // end, in which case we continue with the next holder (the
      // hidden prototype) if there's any.
      TNode<HeapObject> current = var_template.value();
      GotoIf(TaggedEqual(current, signature), &holder_found);

      GotoIfNot(IsFunctionTemplateInfoMap(LoadMap(current)), &holder_next);

      TNode<HeapObject> current_rare = LoadObjectField<HeapObject>(
          current, FunctionTemplateInfo::kRareDataOffset);
      GotoIf(IsUndefined(current_rare), &holder_next);
      var_template = LoadObjectField<HeapObject>(
          current_rare, FunctionTemplateRareData::kParentTemplateOffset);
      Goto(&template_loop);
    }

    BIND(&holder_next);
    {
      // Continue with the hidden prototype of the {holder} if it is a
      // JSGlobalProxy (the hidden prototype can either be null or a
      // JSObject in that case), or throw an illegal invocation exception,
      // since the receiver did not pass the {signature} check.
      TNode<Map> holder_map = LoadMap(holder);
      var_holder = LoadMapPrototype(holder_map);
      GotoIf(IsJSGlobalProxyMap(holder_map), &holder_loop);
      ThrowTypeError(context, MessageTemplate::kIllegalInvocation);
    }
  }

  BIND(&holder_found);
  return CAST(var_holder.value());
}

// static
constexpr bool CallOrConstructBuiltinsAssembler::IsAccessCheckRequired(
    CallFunctionTemplateMode mode) {
  switch (mode) {
    case CallFunctionTemplateMode::kGeneric:
    case CallFunctionTemplateMode::kCheckAccess:
    case CallFunctionTemplateMode::kCheckAccessAndCompatibleReceiver:
      return true;

    case CallFunctionTemplateMode::kCheckCompatibleReceiver:
      return false;
  }
}

// This calls an API callback by passing a {FunctionTemplateInfo},
// does appropriate access and compatible receiver checks.
void CallOrConstructBuiltinsAssembler::CallFunctionTemplate(
    CallFunctionTemplateMode mode,
    TNode<FunctionTemplateInfo> function_template_info, TNode<Int32T> argc,
    TNode<Context> context, TNode<Object> topmost_script_having_context) {
  CodeStubArguments args(this, argc);
  Label throw_illegal_invocation(this, Label::kDeferred);

  // For API callbacks the receiver is always a JSReceiver (since
  // they are treated like sloppy mode functions). We might need
  // to perform access checks in the current {context}, depending
  // on whether the "needs access check" bit is set on the receiver
  // _and_ the {function_template_info} doesn't have the "accepts
  // any receiver" bit set.
  TNode<JSReceiver> receiver = CAST(args.GetReceiver());
  if (IsAccessCheckRequired(mode)) {
    TNode<Map> receiver_map = LoadMap(receiver);
    Label receiver_needs_access_check(this, Label::kDeferred),
        receiver_done(this);
    GotoIfNot(IsSetWord32<Map::Bits1::IsAccessCheckNeededBit>(
                  LoadMapBitField(receiver_map)),
              &receiver_done);
    TNode<Uint32T> function_template_info_flags = LoadObjectField<Uint32T>(
        function_template_info, FunctionTemplateInfo::kFlagOffset);
    Branch(IsSetWord32<FunctionTemplateInfo::AcceptAnyReceiverBit>(
               function_template_info_flags),
           &receiver_done, &receiver_needs_access_check);

    BIND(&receiver_needs_access_check);
    {
      CallRuntime(Runtime::kAccessCheck, context, receiver);
      Goto(&receiver_done);
    }

    BIND(&receiver_done);
  }

  // Figure out the API holder for the {receiver} depending on the
  // {mode} and the signature on the {function_template_info}.
  TNode<JSReceiver> holder;
  switch (mode) {
    case CallFunctionTemplateMode::kCheckAccess:
      // We did the access check (including the ToObject) above, so
      // {receiver} is a JSReceiver at this point, and we don't need
      // to perform any "compatible receiver check", so {holder} is
      // actually the {receiver}.
      holder = receiver;
      break;

    case CallFunctionTemplateMode::kCheckAccessAndCompatibleReceiver:
    case CallFunctionTemplateMode::kCheckCompatibleReceiver: {
      // The {function_template_info} has a signature, so look for a compatible
      // holder in the receiver's hidden prototype chain.
      TNode<HeapObject> signature = LoadObjectField<HeapObject>(
          function_template_info, FunctionTemplateInfo::kSignatureOffset);
      CSA_DCHECK(this, Word32BinaryNot(IsUndefined(signature)));
      holder = GetCompatibleReceiver(receiver, signature, context);
      break;
    }
    case CallFunctionTemplateMode::kGeneric: {
      // If the {function_template_info} doesn't specify any signature, we
      // just use the receiver as the holder for the API callback, otherwise
      // we need to look for a compatible holder in the receiver's hidden
      // prototype chain.
      TNode<HeapObject> signature = LoadObjectField<HeapObject>(
          function_template_info, FunctionTemplateInfo::kSignatureOffset);
      holder = Select<JSReceiver>(
          IsUndefined(signature),  // --
          [&]() { return receiver; },
          [&]() {
            return GetCompatibleReceiver(receiver, signature, context);
          });
      break;
    }
  }

  TNode<Object> callback_data = LoadObjectField(
      function_template_info, FunctionTemplateInfo::kCallbackDataOffset);
  // If the function doesn't have an associated C++ code to execute, just
  // return the receiver as would an empty function do (
"""


```