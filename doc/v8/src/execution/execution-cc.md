Response:
Let's break down the thought process for analyzing the `execution.cc` file.

1. **Understand the Goal:** The request asks for the functionality of `execution.cc`, whether it's Torque, its relation to JavaScript, code logic inference, and examples of common programming errors it might help catch.

2. **Initial Assessment (Top-Down):**
   - **Copyright and Includes:** The initial lines confirm it's a V8 source file related to execution. The included headers hint at areas it interacts with: API, debugging, frames, isolates, VM state, logging, and potentially WebAssembly.
   - **Namespace:**  The code is within `v8::internal`, indicating internal V8 implementation details.
   - **Helper Function `NormalizeReceiver`:**  This immediately suggests a focus on function calls and how the `this` context is handled, especially with global objects.

3. **Identify Key Data Structures:** The `InvokeParams` struct is central. Analyze its members:
   - `target`, `receiver`, `argc`, `argv`: Standard function call parameters.
   - `new_target`:  Related to `new` operator and constructor calls.
   - `microtask_queue`: Hints at asynchronous task management.
   - `message_handling`, `exception_out`: Error handling mechanisms.
   - `is_construct`, `execution_target`: Distinguish between regular calls, constructor calls, and microtask execution.
   - The `SetUpFor...` static methods clearly define how to initialize `InvokeParams` for different invocation scenarios.

4. **Analyze Core Functions:**
   - **`JSEntry`:** This function is crucial. It takes an `execution_target` and `is_construct` flag and returns a `Code` object. The calls to `BUILTIN_CODE` strongly suggest it's selecting pre-compiled entry points for different types of JavaScript execution (regular calls, constructor calls, microtask execution).
   - **`NewScriptContext`:**  This function deals with creating a new context for script execution. It involves checking for side effects, managing scope, and handling potential name clashes (redeclarations). This directly relates to how JavaScript code is executed in different scopes.
   - **`Invoke`:** This is the heart of the file. It takes `InvokeParams` and actually *executes* the JavaScript call.
     - It handles API function calls separately as an optimization.
     - It checks for script contexts and creates them if needed.
     - It interacts with the VM state (`VMState<JS>`).
     - It manages JavaScript execution counters and checks for allowed execution.
     - It calls the appropriate `JSEntry` to get the entry point.
     - It performs the actual call using `stub_entry.Call`.
     - It handles exceptions and returns the result.
   - **`InvokeWithTryCatch`:**  This is a wrapper around `Invoke` that adds error handling using `v8::TryCatch`. It's used when the caller wants to catch exceptions.
   - **`Execution::Call`, `Execution::CallScript`, `Execution::CallBuiltin`, `Execution::New`, `Execution::TryCall`, `Execution::TryCallScript`, `Execution::TryRunMicrotasks`:** These are the public interface functions. They simplify calling JavaScript functions in various ways by setting up the `InvokeParams` and calling `Invoke` or `InvokeWithTryCatch`. The `Execution::Call` function has added debugging print statements which is important to note.
   - **`Execution::CallWasm`:** This handles calling WebAssembly functions, which is a distinct execution path.

5. **Identify JavaScript Connections:**
   - The entire file is about *executing* JavaScript code.
   - The parameters to functions like `Call` and `New` directly correspond to JavaScript function call syntax.
   - The handling of `this` (`receiver`) is fundamental to JavaScript.
   - The concept of constructors and the `new` operator is directly supported.
   - The creation of script contexts is how V8 isolates and manages JavaScript code execution.
   - The handling of exceptions and microtasks are core JavaScript features.

6. **Infer Code Logic:**
   - The `InvokeParams` setup methods show clear logic for different call types.
   - `JSEntry` acts as a dispatcher based on the execution target.
   - `NewScriptContext` implements the rules for creating and initializing script-level scopes.
   - `Invoke` follows a specific sequence: setting up the environment, entering JavaScript execution, calling the entry point, and handling results.

7. **Consider Torque:**
   - The prompt explicitly mentions `.tq` files. Scan the code for any indication of Torque. The `#include` directives don't show any Torque-specific headers. The code appears to be written in C++. Therefore, this specific file isn't a Torque file.

8. **Identify Common Programming Errors:**
   - **Type Errors:** Passing the wrong type of object as a callable or constructor.
   - **Incorrect `this` Binding:**  While `NormalizeReceiver` helps, incorrect manual binding can still be an issue.
   - **Argument Mismatch:** Providing the wrong number or type of arguments to a function.
   - **Redeclaration Errors:**  `NewScriptContext` directly addresses this common JavaScript error.
   - **Side Effects in Debug Evaluation:** The check in `NewScriptContext` for `isolate->should_check_side_effects()` points to a potential debugging pitfall.

9. **Construct Examples:** Based on the analysis, create simple JavaScript examples that illustrate the functionality of the C++ code. Focus on:
   - Regular function calls.
   - Constructor calls.
   - The `this` binding.
   - Script execution.
   - Errors like redeclaration and type errors.

10. **Review and Refine:**  Go back through the analysis and ensure all parts of the prompt are addressed. Check for clarity and accuracy in the explanations and examples. For instance, ensure the explanation of `NormalizeReceiver` is clear and concise. Double-check the code logic inferences and ensure they align with the actual code. Make sure the connection to JavaScript features is explicit.

This systematic approach, starting with a broad overview and then diving into specifics, allows for a comprehensive understanding of the `execution.cc` file's purpose and functionality.
`v8/src/execution/execution.cc` 是 V8 JavaScript 引擎中的一个核心文件，它负责处理 JavaScript 代码的执行。以下是它的主要功能：

**核心功能：执行 JavaScript 代码**

1. **调用 JavaScript 函数 (Call):**  `Execution::Call` 函数负责调用 JavaScript 函数。这包括普通函数调用、脚本的调用以及内置函数的调用。它接收要调用的函数对象、接收者（`this` 值）、参数列表等信息，并最终调用底层的执行机制。

2. **构造 JavaScript 对象 (New):** `Execution::New` 函数负责创建新的 JavaScript 对象。它接收构造函数、`new.target` (用于确定原型链) 和构造函数的参数，并调用底层的构造函数执行逻辑。

3. **运行微任务 (Run Microtasks):**  `Execution::TryRunMicrotasks` 函数负责执行 JavaScript 的微任务队列。微任务是在当前 JavaScript 任务执行完毕后，但在控制权返回宿主环境之前执行的短任务。

4. **处理异常 (TryCall/TryCallScript/TryRunMicrotasks):**  `Execution::TryCall` 系列函数提供了带有 `try...catch` 语义的调用机制。它们允许在执行 JavaScript 代码时捕获异常，并返回一个 `MaybeHandle` 来指示成功或失败。

5. **WebAssembly 调用 (CallWasm):** 如果启用了 WebAssembly 支持，`Execution::CallWasm` 函数负责调用 WebAssembly 模块中的函数。

**辅助功能：**

6. **标准化接收者 (NormalizeReceiver):**  该函数用于确保在调用全局对象的方法时，`this` 指向全局代理对象而不是全局对象本身，这是为了符合 JavaScript 的规范。

7. **设置调用参数 (InvokeParams):**  `InvokeParams` 结构体和其 `SetUpFor...` 系列静态方法用于封装不同类型的函数调用所需的参数，例如构造调用、普通调用、脚本调用和微任务运行。这使得 `Invoke` 函数的实现更加通用。

8. **获取执行入口点 (JSEntry):** `JSEntry` 函数根据调用类型（构造调用、普通调用、微任务运行）选择合适的内置代码作为 JavaScript 执行的入口点。

9. **创建脚本上下文 (NewScriptContext):** 当执行一个需要独立作用域的脚本时，`NewScriptContext` 函数会创建一个新的脚本上下文，用于管理脚本的变量和作用域。它还会检查是否存在变量重复声明等错误。

10. **实际执行 (Invoke):** `Invoke` 函数是执行 JavaScript 代码的核心逻辑。它接收 `InvokeParams`，处理 API 函数的特殊情况，设置脚本上下文，进入 JavaScript 执行状态，调用 `JSEntry` 获取入口点，并最终执行代码。

**是否为 Torque 源代码？**

根据描述，如果 `v8/src/execution/execution.cc` 以 `.tq` 结尾，那么它才是 V8 Torque 源代码。由于这里提到的是 `.cc` 结尾，所以它是一个 **C++ 源代码**文件。

**与 JavaScript 功能的关系及 JavaScript 示例：**

`v8/src/execution/execution.cc` 中的所有功能都直接与 JavaScript 的执行密切相关。以下是几个用 JavaScript 举例说明的场景：

1. **函数调用 (Execution::Call):**

   ```javascript
   function greet(name) {
     console.log("Hello, " + name + "!");
     return "greeting";
   }

   let result = greet("World"); // 对应 Execution::Call
   console.log(result);       // 输出 "greeting"
   ```

2. **构造对象 (Execution::New):**

   ```javascript
   class Person {
     constructor(name, age) {
       this.name = name;
       this.age = age;
     }

     sayHello() {
       console.log("My name is " + this.name);
     }
   }

   let person = new Person("Alice", 30); // 对应 Execution::New
   person.sayHello();                    // 输出 "My name is Alice"
   ```

3. **运行微任务 (Execution::TryRunMicrotasks):**

   ```javascript
   console.log("Start");

   Promise.resolve().then(() => {
     console.log("Microtask"); // 对应 Execution::TryRunMicrotasks
   });

   console.log("End");

   // 输出顺序可能为:
   // Start
   // End
   // Microtask
   ```

4. **脚本执行 (Execution::CallScript):** (更底层，一般不由用户直接调用，V8 内部使用)

   ```javascript
   // 假设 V8 内部在执行一段 <script> 标签中的代码
   let globalVar = 10;
   function scriptFunction() {
     console.log("Inside script");
   }
   ```

5. **捕获异常 (Execution::TryCall):**

   ```javascript
   function potentiallyThrow() {
     throw new Error("Something went wrong!");
   }

   try {
     potentiallyThrow(); // 对应 Execution::TryCall
   } catch (e) {
     console.error("Caught an error:", e.message);
   }
   ```

**代码逻辑推理：**

**假设输入：**

* `Execution::Call` 被调用，`callable` 指向一个 JavaScript 函数 `add(a, b)`，`receiver` 是 `null`，`argc` 是 2，`argv` 包含两个表示数字 5 和 3 的 `Handle<Object>`。

**输出：**

* `Execution::Call` 会调用底层的执行机制来执行 `add(5, 3)`。
* 如果执行成功，`Execution::Call` 将返回一个 `MaybeHandle<Object>`，其中包含表示数字 8 的 `Handle<Object>`。
* 如果执行过程中发生异常，`Execution::Call` 将返回一个空的 `MaybeHandle<Object>`，并且 V8 的异常状态会被设置。

**涉及用户常见的编程错误：**

`v8/src/execution/execution.cc` 的设计和实现旨在确保 JavaScript 代码的正确执行，并尽可能地捕获和报告用户常见的编程错误。以下是一些例子：

1. **`TypeError` (类型错误):**

   ```javascript
   let obj = {};
   obj.toUpperCase(); // 错误: obj.toUpperCase is not a function
   ```

   当尝试调用一个对象上不存在或类型不匹配的方法时，V8 的执行流程会检测到这个错误，并抛出一个 `TypeError`。`Execution::Call` 在执行方法调用时会进行类型检查。

2. **`ReferenceError` (引用错误):**

   ```javascript
   console.log(nonExistentVariable); // 错误: nonExistentVariable is not defined
   ```

   当尝试访问一个未声明的变量时，V8 会抛出一个 `ReferenceError`。在执行过程中，如果尝试访问不存在的变量，执行机制会查找作用域链，如果找不到就会报告错误。

3. **`SyntaxError` (语法错误):** (通常在解析阶段捕获，但也可能在执行阶段因动态代码生成等原因出现)

   ```javascript
   eval("function foo() { return }"); // 缺少函数体
   ```

   虽然大部分语法错误在解析阶段就被捕获，但像 `eval` 这样的动态代码执行可能会在执行阶段遇到语法错误。`Execution::CallScript` 或类似的机制在执行动态生成的代码时可能会遇到这些错误。

4. **调用非函数对象:**

   ```javascript
   let notAFunction = 10;
   notAFunction(); // 错误: notAFunction is not a function
   ```

   `Execution::Call` 在尝试执行 `callable` 时会检查它是否是一个可调用的对象。如果不是，将会抛出 `TypeError`。

5. **构造非构造函数:**

   ```javascript
   function regularFunction() {
     return {};
   }
   let obj = new regularFunction(); // 错误: regularFunction is not a constructor
   ```

   `Execution::New` 在执行构造函数调用时会检查 `constructor` 是否是一个合法的构造函数。如果不是，将会抛出 `TypeError`。

**`NewScriptContext` 中涉及的常见错误：**

```javascript
// 在同一个作用域内重复声明 let 或 const 变量
let x = 10;
let x = 20; // SyntaxError: Identifier 'x' has already been declared

const PI = 3.14;
const PI = 3.14159; // SyntaxError: Identifier 'PI' has already been declared

// 在全局作用域中使用 let 或 const 声明的变量与全局对象已有的属性冲突
var globalVar = 5;
let globalVar; // SyntaxError: Identifier 'globalVar' has already been declared
```

`NewScriptContext` 函数会检查新脚本的变量声明是否与当前作用域已有的变量冲突，特别是对于 `let` 和 `const` 这样的块级作用域变量，避免重复声明导致错误。

总而言之，`v8/src/execution/execution.cc` 是 V8 引擎中负责 JavaScript 代码执行的核心组件，它通过一系列函数处理不同类型的调用、对象构造、错误处理以及 WebAssembly 集成，确保 JavaScript 代码能够按照规范正确地运行，并帮助开发者发现和避免常见的编程错误。

Prompt: 
```
这是目录为v8/src/execution/execution.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/execution.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/execution.h"

#include "src/api/api-inl.h"
#include "src/debug/debug.h"
#include "src/execution/frames.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/vm-state-inl.h"
#include "src/logging/runtime-call-stats-scope.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/compiler/wasm-compiler.h"  // Only for static asserts.
#include "src/wasm/code-space-access.h"
#include "src/wasm/wasm-engine.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

namespace {

Handle<Object> NormalizeReceiver(Isolate* isolate, Handle<Object> receiver) {
  // Convert calls on global objects to be calls on the global
  // receiver instead to avoid having a 'this' pointer which refers
  // directly to a global object.
  if (IsJSGlobalObject(*receiver)) {
    return handle(Cast<JSGlobalObject>(receiver)->global_proxy(), isolate);
  }
  return receiver;
}

struct InvokeParams {
  static InvokeParams SetUpForNew(Isolate* isolate, Handle<Object> constructor,
                                  Handle<Object> new_target, int argc,
                                  Handle<Object>* argv);

  static InvokeParams SetUpForCall(Isolate* isolate, Handle<Object> callable,
                                   Handle<Object> receiver, int argc,
                                   Handle<Object>* argv);

  static InvokeParams SetUpForTryCall(
      Isolate* isolate, Handle<Object> callable, Handle<Object> receiver,
      int argc, Handle<Object>* argv,
      Execution::MessageHandling message_handling,
      MaybeHandle<Object>* exception_out);

  static InvokeParams SetUpForRunMicrotasks(Isolate* isolate,
                                            MicrotaskQueue* microtask_queue);

  bool IsScript() const {
    if (!IsJSFunction(*target)) return false;
    auto function = Cast<JSFunction>(target);
    return function->shared()->is_script();
  }

  Handle<FixedArray> GetAndResetHostDefinedOptions() {
    DCHECK(IsScript());
    DCHECK_EQ(argc, 1);
    auto options = Cast<FixedArray>(argv[0]);
    argv = nullptr;
    argc = 0;
    return options;
  }

  Handle<Object> target;
  Handle<Object> receiver;
  int argc;
  Handle<Object>* argv;
  Handle<Object> new_target;

  MicrotaskQueue* microtask_queue;

  Execution::MessageHandling message_handling;
  MaybeHandle<Object>* exception_out;

  bool is_construct;
  Execution::Target execution_target;
};

// static
InvokeParams InvokeParams::SetUpForNew(Isolate* isolate,
                                       Handle<Object> constructor,
                                       Handle<Object> new_target, int argc,
                                       Handle<Object>* argv) {
  InvokeParams params;
  params.target = constructor;
  params.receiver = isolate->factory()->undefined_value();
  DCHECK(!params.IsScript());
  params.argc = argc;
  params.argv = argv;
  params.new_target = new_target;
  params.microtask_queue = nullptr;
  params.message_handling = Execution::MessageHandling::kReport;
  params.exception_out = nullptr;
  params.is_construct = true;
  params.execution_target = Execution::Target::kCallable;
  return params;
}

// static
InvokeParams InvokeParams::SetUpForCall(Isolate* isolate,
                                        Handle<Object> callable,
                                        Handle<Object> receiver, int argc,
                                        Handle<Object>* argv) {
  InvokeParams params;
  params.target = callable;
  params.receiver = NormalizeReceiver(isolate, receiver);
  // Check for host-defined options argument for scripts.
  DCHECK_IMPLIES(params.IsScript(), argc == 1);
  DCHECK_IMPLIES(params.IsScript(), IsFixedArray(*argv[0]));
  params.argc = argc;
  params.argv = argv;
  params.new_target = isolate->factory()->undefined_value();
  params.microtask_queue = nullptr;
  params.message_handling = Execution::MessageHandling::kReport;
  params.exception_out = nullptr;
  params.is_construct = false;
  params.execution_target = Execution::Target::kCallable;
  return params;
}

// static
InvokeParams InvokeParams::SetUpForTryCall(
    Isolate* isolate, Handle<Object> callable, Handle<Object> receiver,
    int argc, Handle<Object>* argv, Execution::MessageHandling message_handling,
    MaybeHandle<Object>* exception_out) {
  InvokeParams params;
  params.target = callable;
  params.receiver = NormalizeReceiver(isolate, receiver);
  // Check for host-defined options argument for scripts.
  DCHECK_IMPLIES(params.IsScript(), argc == 1);
  DCHECK_IMPLIES(params.IsScript(), IsFixedArray(*argv[0]));
  params.argc = argc;
  params.argv = argv;
  params.new_target = isolate->factory()->undefined_value();
  params.microtask_queue = nullptr;
  params.message_handling = message_handling;
  params.exception_out = exception_out;
  params.is_construct = false;
  params.execution_target = Execution::Target::kCallable;
  return params;
}

// static
InvokeParams InvokeParams::SetUpForRunMicrotasks(
    Isolate* isolate, MicrotaskQueue* microtask_queue) {
  auto undefined = isolate->factory()->undefined_value();
  InvokeParams params;
  params.target = undefined;
  params.receiver = undefined;
  params.argc = 0;
  params.argv = nullptr;
  params.new_target = undefined;
  params.microtask_queue = microtask_queue;
  params.message_handling = Execution::MessageHandling::kReport;
  params.exception_out = nullptr;
  params.is_construct = false;
  params.execution_target = Execution::Target::kRunMicrotasks;
  return params;
}

Handle<Code> JSEntry(Isolate* isolate, Execution::Target execution_target,
                     bool is_construct) {
  if (is_construct) {
    DCHECK_EQ(Execution::Target::kCallable, execution_target);
    return BUILTIN_CODE(isolate, JSConstructEntry);
  } else if (execution_target == Execution::Target::kCallable) {
    DCHECK(!is_construct);
    return BUILTIN_CODE(isolate, JSEntry);
  } else if (execution_target == Execution::Target::kRunMicrotasks) {
    DCHECK(!is_construct);
    return BUILTIN_CODE(isolate, JSRunMicrotasksEntry);
  }
  UNREACHABLE();
}

MaybeHandle<Context> NewScriptContext(
    Isolate* isolate, DirectHandle<JSFunction> function,
    DirectHandle<FixedArray> host_defined_options) {
  // TODO(cbruni, 1244145): Use passed in host_defined_options.
  // Creating a script context is a side effect, so abort if that's not
  // allowed.
  if (isolate->should_check_side_effects()) {
    isolate->Throw(*isolate->factory()->NewEvalError(
        MessageTemplate::kNoSideEffectDebugEvaluate));
    return MaybeHandle<Context>();
  }
  SaveAndSwitchContext save(isolate, function->context());
  Tagged<SharedFunctionInfo> sfi = function->shared();
  Handle<Script> script(Cast<Script>(sfi->script()), isolate);
  Handle<ScopeInfo> scope_info(sfi->scope_info(), isolate);
  DirectHandle<NativeContext> native_context(
      Cast<NativeContext>(function->context()), isolate);
  Handle<JSGlobalObject> global_object(native_context->global_object(),
                                       isolate);
  Handle<ScriptContextTable> script_context(
      native_context->script_context_table(), isolate);

  // Find name clashes.
  for (auto it : ScopeInfo::IterateLocalNames(scope_info)) {
    Handle<String> name(it->name(), isolate);
    VariableMode mode = scope_info->ContextLocalMode(it->index());
    VariableLookupResult lookup;
    if (script_context->Lookup(name, &lookup)) {
      if (IsLexicalVariableMode(mode) || IsLexicalVariableMode(lookup.mode)) {
        DirectHandle<Context> context(script_context->get(lookup.context_index),
                                      isolate);
        // If we are trying to re-declare a REPL-mode let as a let, REPL-mode
        // const as a const, REPL-mode using as a using and REPL-mode await
        // using as an await using allow it.
        if (!((mode == lookup.mode && IsLexicalVariableMode(mode)) &&
              scope_info->IsReplModeScope() &&
              context->scope_info()->IsReplModeScope())) {
          // ES#sec-globaldeclarationinstantiation 5.b:
          // If envRec.HasLexicalDeclaration(name) is true, throw a SyntaxError
          // exception.
          MessageLocation location(script, 0, 1);
          isolate->ThrowAt(isolate->factory()->NewSyntaxError(
                               MessageTemplate::kVarRedeclaration, name),
                           &location);
          return MaybeHandle<Context>();
        }
      }
    }

    if (IsLexicalVariableMode(mode)) {
      LookupIterator it(isolate, global_object, name, global_object,
                        LookupIterator::OWN_SKIP_INTERCEPTOR);
      Maybe<PropertyAttributes> maybe = JSReceiver::GetPropertyAttributes(&it);
      // Can't fail since the we looking up own properties on the global object
      // skipping interceptors.
      CHECK(!maybe.IsNothing());
      if ((maybe.FromJust() & DONT_DELETE) != 0) {
        // ES#sec-globaldeclarationinstantiation 5.a:
        // If envRec.HasVarDeclaration(name) is true, throw a SyntaxError
        // exception.
        // ES#sec-globaldeclarationinstantiation 5.d:
        // If hasRestrictedGlobal is true, throw a SyntaxError exception.
        MessageLocation location(script, 0, 1);
        isolate->ThrowAt(isolate->factory()->NewSyntaxError(
                             MessageTemplate::kVarRedeclaration, name),
                         &location);
        return MaybeHandle<Context>();
      }

      JSGlobalObject::InvalidatePropertyCell(global_object, name);
    }
  }

  Handle<Context> result =
      isolate->factory()->NewScriptContext(native_context, scope_info);

  result->Initialize(isolate);
  // In REPL mode, we are allowed to add/modify let/const/using/await using
  // variables. We use the previous defined script context for those.
  const bool ignore_duplicates = scope_info->IsReplModeScope();
  DirectHandle<ScriptContextTable> new_script_context_table =
      ScriptContextTable::Add(isolate, script_context, result,
                              ignore_duplicates);
  native_context->synchronized_set_script_context_table(
      *new_script_context_table);
  return result;
}

V8_WARN_UNUSED_RESULT MaybeHandle<Object> Invoke(Isolate* isolate,
                                                 const InvokeParams& params) {
  RCS_SCOPE(isolate, RuntimeCallCounterId::kInvoke);
  DCHECK(!IsJSGlobalObject(*params.receiver));
  DCHECK_LE(params.argc, FixedArray::kMaxLength);
  DCHECK(!isolate->has_exception());

#if V8_ENABLE_WEBASSEMBLY
  // If we have PKU support for Wasm, ensure that code is currently write
  // protected for this thread.
  DCHECK_IMPLIES(wasm::GetWasmCodeManager()->HasMemoryProtectionKeySupport(),
                 !wasm::GetWasmCodeManager()->MemoryProtectionKeyWritable());
#endif  // V8_ENABLE_WEBASSEMBLY

#ifdef USE_SIMULATOR
  // Simulators use separate stacks for C++ and JS. JS stack overflow checks
  // are performed whenever a JS function is called. However, it can be the case
  // that the C++ stack grows faster than the JS stack, resulting in an overflow
  // there. Add a check here to make that less likely.
  StackLimitCheck check(isolate);
  if (check.HasOverflowed()) {
    isolate->StackOverflow();
    isolate->ReportPendingMessages(params.message_handling ==
                                   Execution::MessageHandling::kReport);
    return MaybeHandle<Object>();
  }
#endif

  // api callbacks can be called directly, unless we want to take the detour
  // through JS to set up a frame for break-at-entry.
  if (IsJSFunction(*params.target)) {
    auto function = Cast<JSFunction>(params.target);
    if ((!params.is_construct || IsConstructor(*function)) &&
        function->shared()->IsApiFunction() &&
        !function->shared()->BreakAtEntry(isolate)) {
      SaveAndSwitchContext save(isolate, function->context());
      DCHECK(IsJSGlobalObject(function->context()->global_object()));

      Handle<Object> receiver = params.is_construct
                                    ? isolate->factory()->the_hole_value()
                                    : params.receiver;
      Handle<FunctionTemplateInfo> fun_data(function->shared()->api_func_data(),
                                            isolate);
      auto value = Builtins::InvokeApiFunction(
          isolate, params.is_construct, fun_data, receiver, params.argc,
          params.argv, Cast<HeapObject>(params.new_target));
      bool has_exception = value.is_null();
      DCHECK_EQ(has_exception, isolate->has_exception());
      if (has_exception) {
        isolate->ReportPendingMessages(params.message_handling ==
                                       Execution::MessageHandling::kReport);
        return MaybeHandle<Object>();
      } else {
        isolate->clear_pending_message();
      }
      return value;
    }
#ifdef DEBUG
    if (function->shared()->is_script()) {
      DCHECK(params.IsScript());
      DCHECK(IsJSGlobalProxy(*params.receiver));
      DCHECK_EQ(params.argc, 1);
      DCHECK(IsFixedArray(*params.argv[0]));
    } else {
      DCHECK(!params.IsScript());
    }
#endif
    // Set up a ScriptContext when running scripts that need it.
    if (function->shared()->needs_script_context()) {
      Handle<Context> context;
      DirectHandle<FixedArray> host_defined_options =
          const_cast<InvokeParams&>(params).GetAndResetHostDefinedOptions();
      if (!NewScriptContext(isolate, function, host_defined_options)
               .ToHandle(&context)) {
        isolate->ReportPendingMessages(params.message_handling ==
                                       Execution::MessageHandling::kReport);
        return MaybeHandle<Object>();
      }

      // We mutate the context if we allocate a script context. This is
      // guaranteed to only happen once in a native context since scripts will
      // always produce name clashes with themselves.
      function->set_context(*context);
    }
  }

  // Entering JavaScript.
  VMState<JS> state(isolate);
  if (!AllowJavascriptExecution::IsAllowed(isolate)) {
    GRACEFUL_FATAL("Invoke in DisallowJavascriptExecutionScope");
  }
  if (!ThrowOnJavascriptExecution::IsAllowed(isolate)) {
    isolate->ThrowIllegalOperation();
    isolate->ReportPendingMessages(params.message_handling ==
                                   Execution::MessageHandling::kReport);
    return MaybeHandle<Object>();
  }
  if (!DumpOnJavascriptExecution::IsAllowed(isolate)) {
    V8::GetCurrentPlatform()->DumpWithoutCrashing();
    return isolate->factory()->undefined_value();
  }
  isolate->IncrementJavascriptExecutionCounter();

  if (params.execution_target == Execution::Target::kCallable) {
    Handle<NativeContext> context = isolate->native_context();
    if (!IsUndefined(context->script_execution_callback(), isolate)) {
      v8::Context::AbortScriptExecutionCallback callback =
          v8::ToCData<v8::Context::AbortScriptExecutionCallback,
                      kApiAbortScriptExecutionCallbackTag>(
              isolate, context->script_execution_callback());
      v8::Isolate* api_isolate = reinterpret_cast<v8::Isolate*>(isolate);
      v8::Local<v8::Context> api_context = v8::Utils::ToLocal(context);
      callback(api_isolate, api_context);
      DCHECK(!isolate->has_exception());
      // Always throw an exception to abort execution, if callback exists.
      isolate->ThrowIllegalOperation();
      return MaybeHandle<Object>();
    }
  }

  // Placeholder for return value.
  Tagged<Object> value;
  DirectHandle<Code> code =
      JSEntry(isolate, params.execution_target, params.is_construct);
  {
    // Save and restore context around invocation and block the
    // allocation of handles without explicit handle scopes.
    SaveContext save(isolate);
    SealHandleScope shs(isolate);

    if (v8_flags.clear_exceptions_on_js_entry) isolate->clear_exception();

    if (params.execution_target == Execution::Target::kCallable) {
      // clang-format off
      // {new_target}, {target}, {receiver}, return value: tagged pointers
      // {argv}: pointer to array of tagged pointers
      using JSEntryFunction = GeneratedCode<Address(
          Address root_register_value, Address new_target, Address target,
          Address receiver, intptr_t argc, Address** argv)>;
      // clang-format on
      JSEntryFunction stub_entry =
          JSEntryFunction::FromAddress(isolate, code->instruction_start());

      Address orig_func = (*params.new_target).ptr();
      Address func = (*params.target).ptr();
      Address recv = (*params.receiver).ptr();
      Address** argv = reinterpret_cast<Address**>(params.argv);
      RCS_SCOPE(isolate, RuntimeCallCounterId::kJS_Execution);
      value = Tagged<Object>(
          stub_entry.Call(isolate->isolate_data()->isolate_root(), orig_func,
                          func, recv, JSParameterCount(params.argc), argv));
    } else {
      DCHECK_EQ(Execution::Target::kRunMicrotasks, params.execution_target);

      // clang-format off
      // return value: tagged pointers
      // {microtask_queue}: pointer to a C++ object
      using JSEntryFunction = GeneratedCode<Address(
          Address root_register_value, MicrotaskQueue* microtask_queue)>;
      // clang-format on
      JSEntryFunction stub_entry =
          JSEntryFunction::FromAddress(isolate, code->instruction_start());

      RCS_SCOPE(isolate, RuntimeCallCounterId::kJS_Execution);
      value = Tagged<Object>(stub_entry.Call(
          isolate->isolate_data()->isolate_root(), params.microtask_queue));
    }
  }

#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) {
    Object::ObjectVerify(value, isolate);
  }
#endif

  // Update the pending exception flag and return the value.
  bool has_exception = IsException(value, isolate);
  DCHECK_EQ(has_exception, isolate->has_exception());
  if (has_exception) {
    isolate->ReportPendingMessages(params.message_handling ==
                                   Execution::MessageHandling::kReport);
    return MaybeHandle<Object>();
  } else {
    isolate->clear_pending_message();
  }

  return Handle<Object>(value, isolate);
}

MaybeHandle<Object> InvokeWithTryCatch(Isolate* isolate,
                                       const InvokeParams& params) {
  DCHECK_IMPLIES(v8_flags.strict_termination_checks,
                 !isolate->is_execution_terminating());
  MaybeHandle<Object> maybe_result;
  if (params.exception_out != nullptr) {
    *params.exception_out = {};
  }

  // Enter a try-block while executing the JavaScript code. To avoid
  // duplicate error printing it must be non-verbose.  Also, to avoid
  // creating message objects during stack overflow we shouldn't
  // capture messages.
  v8::TryCatch catcher(reinterpret_cast<v8::Isolate*>(isolate));
  catcher.SetVerbose(false);
  catcher.SetCaptureMessage(false);

  maybe_result = Invoke(isolate, params);

  if (V8_LIKELY(!maybe_result.is_null())) {
    DCHECK(!isolate->has_exception());
    return maybe_result;
  }

  DCHECK(isolate->has_exception());
  if (isolate->is_execution_terminating()) {
    return maybe_result;
  }

  if (params.exception_out != nullptr) {
    DCHECK(catcher.HasCaught());
    *params.exception_out = v8::Utils::OpenHandle(*catcher.Exception());
  }

  return maybe_result;
}

}  // namespace
#define PRINT_TYPE(x) std::cout << #x << " is of type: " << typeid(x).name() << std::endl

// static
MaybeHandle<Object> Execution::Call(Isolate* isolate, Handle<Object> callable,
                                    Handle<Object> receiver, int argc,
                                    Handle<Object> argv[]) {
  // Use Execution::CallScript instead for scripts:
  DCHECK_IMPLIES(IsJSFunction(*callable),
                 !Cast<JSFunction>(*callable)->shared()->is_script());
  if(IsJSFunction(*callable)) {
    Tagged<SharedFunctionInfo> info = Cast<JSFunction>(*callable)->shared();
    std::unique_ptr<char[]> interface_name = Cast<String>(info->more_scope_info_interface_name())->ToCString();
    std::unique_ptr<char[]> class_name = Cast<String>(info->more_scope_info_class_name())->ToCString();
    if (strlen(interface_name.get()) == 0 && strlen(class_name.get()) == 0) {
      // Local<Object> obj = Local<Object>::Cast(callable);
      std::cout << "receiver: ";
      Cast<HeapObject>(*receiver)->HeapObjectPrint(std::cout);
      std::cout << "callable: ";
      Cast<HeapObject>(*callable)->HeapObjectPrint(std::cout);
    } else {
      std::cout << "interface.class: " 
                << interface_name.get() 
                << "." 
                << class_name.get() 
                << std::endl;
    }
  }
  return Invoke(isolate, InvokeParams::SetUpForCall(isolate, callable, receiver,
                                                  argc, argv));

}

// static
MaybeHandle<Object> Execution::CallScript(Isolate* isolate,
                                          Handle<JSFunction> script_function,
                                          Handle<Object> receiver,
                                          Handle<Object> host_defined_options) {
  DCHECK(script_function->shared()->is_script());
  DCHECK(IsJSGlobalProxy(*receiver) || IsJSGlobalObject(*receiver));
  return Invoke(
      isolate, InvokeParams::SetUpForCall(isolate, script_function, receiver, 1,
                                          &host_defined_options));
}

MaybeHandle<Object> Execution::CallBuiltin(Isolate* isolate,
                                           Handle<JSFunction> builtin,
                                           Handle<Object> receiver, int argc,
                                           Handle<Object> argv[]) {
  DCHECK(builtin->code(isolate)->is_builtin());
  DisableBreak no_break(isolate->debug());
  return Invoke(isolate, InvokeParams::SetUpForCall(isolate, builtin, receiver,
                                                    argc, argv));
}

// static
MaybeHandle<JSReceiver> Execution::New(Isolate* isolate,
                                       Handle<Object> constructor, int argc,
                                       Handle<Object> argv[]) {
  return New(isolate, constructor, constructor, argc, argv);
}

// static
MaybeHandle<JSReceiver> Execution::New(Isolate* isolate,
                                       Handle<Object> constructor,
                                       Handle<Object> new_target, int argc,
                                       Handle<Object> argv[]) {
  return Cast<JSReceiver>(Invoke(
      isolate,
      InvokeParams::SetUpForNew(isolate, constructor, new_target, argc, argv)));
}

// static
MaybeHandle<Object> Execution::TryCallScript(
    Isolate* isolate, Handle<JSFunction> script_function,
    Handle<Object> receiver, Handle<FixedArray> host_defined_options) {
  DCHECK(script_function->shared()->is_script());
  DCHECK(IsJSGlobalProxy(*receiver) || IsJSGlobalObject(*receiver));
  Handle<Object> argument = host_defined_options;
  return InvokeWithTryCatch(
      isolate, InvokeParams::SetUpForTryCall(
                   isolate, script_function, receiver, 1, &argument,
                   MessageHandling::kKeepPending, nullptr));
}

// static
MaybeHandle<Object> Execution::TryCall(Isolate* isolate,
                                       Handle<Object> callable,
                                       Handle<Object> receiver, int argc,
                                       Handle<Object> argv[],
                                       MessageHandling message_handling,
                                       MaybeHandle<Object>* exception_out) {
  // Use Execution::TryCallScript instead for scripts:
  DCHECK_IMPLIES(IsJSFunction(*callable),
                 !Cast<JSFunction>(*callable)->shared()->is_script());
  return InvokeWithTryCatch(
      isolate,
      InvokeParams::SetUpForTryCall(isolate, callable, receiver, argc, argv,
                                    message_handling, exception_out));
}

// static
MaybeHandle<Object> Execution::TryRunMicrotasks(
    Isolate* isolate, MicrotaskQueue* microtask_queue) {
  return InvokeWithTryCatch(
      isolate, InvokeParams::SetUpForRunMicrotasks(isolate, microtask_queue));
}

struct StackHandlerMarker {
  Address next;
  Address padding;
};
static_assert(offsetof(StackHandlerMarker, next) ==
              StackHandlerConstants::kNextOffset);
static_assert(offsetof(StackHandlerMarker, padding) ==
              StackHandlerConstants::kPaddingOffset);
static_assert(sizeof(StackHandlerMarker) == StackHandlerConstants::kSize);

#if V8_ENABLE_WEBASSEMBLY
void Execution::CallWasm(Isolate* isolate, DirectHandle<Code> wrapper_code,
                         WasmCodePointer wasm_call_target,
                         DirectHandle<Object> object_ref, Address packed_args) {
  using WasmEntryStub = GeneratedCode<Address(
      Address target, Address object_ref, Address argv, Address c_entry_fp)>;
  WasmEntryStub stub_entry =
      WasmEntryStub::FromAddress(isolate, wrapper_code->instruction_start());

  // Save and restore context around invocation and block the
  // allocation of handles without explicit handle scopes.
  SaveContext save(isolate);
  SealHandleScope shs(isolate);

  Address saved_c_entry_fp = *isolate->c_entry_fp_address();
  Address saved_js_entry_sp = *isolate->js_entry_sp_address();
  if (saved_js_entry_sp == kNullAddress) {
    *isolate->js_entry_sp_address() = GetCurrentStackPosition();
  }
  StackHandlerMarker stack_handler;
  stack_handler.next = isolate->thread_local_top()->handler_;
#ifdef V8_USE_ADDRESS_SANITIZER
  stack_handler.padding = GetCurrentStackPosition();
#else
  stack_handler.padding = 0;
#endif
  isolate->thread_local_top()->handler_ =
      reinterpret_cast<Address>(&stack_handler);
  trap_handler::SetThreadInWasm();

  {
    RCS_SCOPE(isolate, RuntimeCallCounterId::kJS_Execution);
    static_assert(compiler::CWasmEntryParameters::kCodeEntry == 0);
    static_assert(compiler::CWasmEntryParameters::kObjectRef == 1);
    static_assert(compiler::CWasmEntryParameters::kArgumentsBuffer == 2);
    static_assert(compiler::CWasmEntryParameters::kCEntryFp == 3);
    Address result = stub_entry.Call(wasm_call_target, (*object_ref).ptr(),
                                     packed_args, saved_c_entry_fp);
    if (result != kNullAddress) isolate->set_exception(Tagged<Object>(result));
  }

  // If there was an exception, then the thread-in-wasm flag is cleared
  // already.
  if (trap_handler::IsThreadInWasm()) {
    trap_handler::ClearThreadInWasm();
  }
  isolate->thread_local_top()->handler_ = stack_handler.next;
  if (saved_js_entry_sp == kNullAddress) {
    *isolate->js_entry_sp_address() = saved_js_entry_sp;
  }
  *isolate->c_entry_fp_address() = saved_c_entry_fp;
}
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace internal
}  // namespace v8

"""

```