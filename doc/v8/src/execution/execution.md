Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript examples.

1. **Understand the Goal:** The primary goal is to understand the functionality of `execution.cc` within the V8 JavaScript engine and relate it to JavaScript concepts. This means identifying its core responsibilities and illustrating them with JavaScript.

2. **Initial Skim and Keyword Spotting:**  The first step is a quick read-through, looking for recurring keywords and patterns. Keywords like `Invoke`, `Call`, `New`, `JSEntry`, `ScriptContext`, `Microtasks`, `wasm`, `isolate`, `Handle`, and the various `SetUpFor...` functions immediately stand out. These suggest the file deals with executing JavaScript code, creating execution contexts, handling function calls (both regular and constructors), managing microtasks, and potentially interacting with WebAssembly.

3. **Identify Core Functions:** The functions `Execution::Call`, `Execution::CallScript`, `Execution::New`, `Execution::TryCall`, and `Execution::TryRunMicrotasks` are clearly entry points for various execution scenarios. The presence of `Try...` versions indicates error handling. The `CallScript` variant suggests a specialization for executing scripts.

4. **Focus on `Invoke`:** The `Invoke` function is called by most of the other `Execution::*` functions. This suggests it's the core logic for actually executing code. Analyzing `Invoke` and the `InvokeParams` struct is crucial.

5. **Deconstruct `InvokeParams`:**  This struct bundles the necessary information for an invocation. Understanding each member is key:
    * `target`: The function or code to be executed.
    * `receiver`: The `this` value for the call.
    * `argc`, `argv`: Argument count and array.
    * `new_target`: Used for constructor calls.
    * `microtask_queue`: For running microtasks.
    * `message_handling`: How to handle errors.
    * `exception_out`: Where to store exceptions.
    * `is_construct`:  Boolean indicating constructor call.
    * `execution_target`:  Enum for different execution types (Callable, RunMicrotasks).
    * The `SetUpFor...` static methods clearly define how to populate this struct for different call scenarios (regular call, constructor call, script execution, microtasks).

6. **Trace Execution Flow (Mentally or with a Debugger):**  Imagine the flow when `Execution::Call` is called. It sets up `InvokeParams` using `SetUpForCall` and then calls `Invoke`. `Invoke` then checks the type of `target` (JSFunction, etc.) and dispatches accordingly. The `JSEntry` function appears to be the final entry point into the JavaScript execution engine.

7. **Identify Key Concepts and Relationships:**
    * **Function Calls:**  `Execution::Call` handles standard function calls.
    * **Constructor Calls:** `Execution::New` handles constructor calls.
    * **Script Execution:** `Execution::CallScript` is specifically for executing scripts and involves creating a `ScriptContext`.
    * **Error Handling:** `TryCall` and `TryRunMicrotasks` use `InvokeWithTryCatch` to handle exceptions.
    * **Microtasks:** `TryRunMicrotasks` and the `InvokeParams::SetUpForRunMicrotasks` indicate support for the JavaScript microtask queue.
    * **WebAssembly:** The `#if V8_ENABLE_WEBASSEMBLY` blocks show interaction with the WebAssembly engine, specifically the `CallWasm` function.
    * **Contexts:** The `NewScriptContext` function deals with creating execution contexts for scripts.
    * **Builtins:** `Execution::CallBuiltin` is for calling built-in JavaScript functions.

8. **Relate to JavaScript:**  Now, connect these C++ concepts to their JavaScript equivalents.
    * `Execution::Call` is like calling a regular JavaScript function: `functionCall(arg1, arg2)`.
    * `Execution::New` is like using the `new` keyword: `new Constructor(arg1, arg2)`.
    * `Execution::CallScript` corresponds to executing a `<script>` tag or using `eval()`.
    * Microtasks are related to Promises and `queueMicrotask()`.
    * Built-in functions are things like `Math.sqrt()`, `Array.prototype.map()`, etc.

9. **Craft JavaScript Examples:**  Create concise and illustrative JavaScript examples for each core function or concept identified. Focus on demonstrating the corresponding functionality.

10. **Summarize the Functionality:** Write a clear and concise summary of the `execution.cc` file, highlighting its main responsibilities. Use the identified concepts and relationships to structure the summary.

11. **Refine and Review:** Read through the summary and examples to ensure accuracy, clarity, and completeness. Check for any inconsistencies or missing information. For example, initially, I might have missed the significance of `NormalizeReceiver`, but closer inspection reveals its role in handling `this` for global object calls.

**Self-Correction/Refinement Example During the Process:**

Initially, I might have just thought `Invoke` was a generic function caller. However, noticing the `is_construct` flag and the separate `JSEntry` calls for constructors and regular functions led to a more nuanced understanding: `Invoke` is a central dispatch point, and the actual entry into the JavaScript VM differs based on whether it's a constructor call or not. Similarly, spotting the `needs_script_context` check and the `NewScriptContext` call highlighted the special handling for script execution contexts. The `#ifdef DEBUG` blocks also provided clues about the expected arguments for script execution.

By following this process of skimming, identifying key components, tracing execution, relating to JavaScript concepts, and refining the understanding, it's possible to arrive at a comprehensive and accurate summary of the `execution.cc` file.
这个文件是 V8 JavaScript 引擎中 `execution` 组件的核心部分，主要负责 **执行 JavaScript 代码**。它定义了用于调用 JavaScript 函数、构造对象、运行脚本以及处理微任务的关键接口和实现。

**核心功能归纳:**

1. **JavaScript 代码的调用 (Call):**
   - 提供了 `Execution::Call` 方法，用于调用 JavaScript 函数。
   - 负责设置调用所需的上下文信息，包括接收者 (`this`)、参数等。
   - 内部使用 `Invoke` 函数进行实际的调用操作。

2. **JavaScript 对象的构造 (New):**
   - 提供了 `Execution::New` 方法，用于创建 JavaScript 对象。
   - 负责处理构造函数的调用，包括设置 `new.target`。
   - 同样使用 `Invoke` 函数进行实际的构造过程。

3. **JavaScript 脚本的执行 (CallScript):**
   - 提供了 `Execution::CallScript` 方法，专门用于执行 JavaScript 脚本代码。
   - 涉及到创建和管理脚本执行所需的上下文 (`ScriptContext`)。

4. **内置函数的调用 (CallBuiltin):**
   - 提供了 `Execution::CallBuiltin` 方法，用于调用 V8 引擎内部实现的内置函数。

5. **错误处理 (TryCall, TryCallScript, TryRunMicrotasks):**
   - 提供了 `TryCall` 和 `TryCallScript` 方法，允许在 `try...catch` 块中调用 JavaScript 代码，并捕获可能发生的异常。
   - `TryRunMicrotasks` 用于在错误处理上下文中运行微任务。

6. **微任务的执行 (RunMicrotasks):**
   - 提供了机制来运行 JavaScript 的微任务队列。

7. **与 WebAssembly 的集成 (CallWasm):**
   - 如果启用了 WebAssembly (`V8_ENABLE_WEBASSEMBLY`)，该文件包含 `Execution::CallWasm` 方法，用于调用 WebAssembly 模块中的函数。

8. **JavaScript 入口点 (JSEntry):**
   - 内部使用 `JSEntry` 函数选择合适的代码入口点，例如 `JSConstructEntry` (用于构造函数) 或 `JSEntry` (用于普通函数调用)。

9. **上下文管理:**
   - 负责在 JavaScript 代码执行前后保存和恢复 V8 的执行上下文。

10. **接收者规范化 (NormalizeReceiver):**
    - 提供了 `NormalizeReceiver` 函数，用于处理全局对象作为接收者的情况，将其转换为全局代理对象，以避免 `this` 指向全局对象本身。

**与 JavaScript 的关系及举例说明:**

`execution.cc` 中定义的 C++ 方法直接对应于 JavaScript 中执行代码的各种场景。

**1. 函数调用 (`Execution::Call`):**

```javascript
function greet(name) {
  console.log("Hello, " + name + "!");
}

greet("World"); // 在 V8 内部会调用 Execution::Call
```

在这个例子中，调用 `greet("World")` 会触发 V8 内部调用 `Execution::Call`，传递 `greet` 函数对象、全局对象（作为接收者，因为没有显式指定 `this`）、参数 `"World"` 等信息。

**2. 对象构造 (`Execution::New`):**

```javascript
class Person {
  constructor(name) {
    this.name = name;
  }
}

const person = new Person("Alice"); // 在 V8 内部会调用 Execution::New
console.log(person.name);
```

使用 `new Person("Alice")` 创建 `Person` 类的实例时，V8 内部会调用 `Execution::New`，传递 `Person` 构造函数、新的目标对象等信息。

**3. 脚本执行 (`Execution::CallScript`):**

当浏览器或 Node.js 执行 `<script>` 标签内的代码或者使用 `eval()` 执行代码时，V8 内部会调用 `Execution::CallScript`。例如：

```html
<script>
  console.log("This is a script!"); // 执行时会调用 Execution::CallScript
</script>
```

或者在 Node.js 中：

```javascript
eval('console.log("Evaluated code!");'); // 执行时会调用 Execution::CallScript
```

**4. 内置函数调用 (`Execution::CallBuiltin`):**

```javascript
const sqrtOf16 = Math.sqrt(16); // Math.sqrt 是一个内置函数，调用时会涉及 Execution::CallBuiltin
console.log(sqrtOf16);
```

调用 `Math.sqrt(16)` 时，由于 `Math.sqrt` 是 V8 内部实现的内置函数，V8 会使用 `Execution::CallBuiltin` 来执行它。

**5. 错误处理 (`Execution::TryCall`):**

```javascript
try {
  throw new Error("Something went wrong!");
} catch (e) {
  console.error("Caught an error:", e.message); // 异常会被 V8 的错误处理机制捕获，可能涉及 Execution::TryCall
}
```

当 `try...catch` 块中的代码抛出异常时，V8 的错误处理机制会介入，这可能涉及到 `Execution::TryCall`（如果 `try` 块中是函数调用）。

**总结:**

`v8/src/execution/execution.cc` 是 V8 引擎执行 JavaScript 代码的核心组件。它提供了执行各种 JavaScript 操作（函数调用、对象构造、脚本执行等）的基础设施，并处理相关的上下文管理和错误处理。其内部的 C++ 方法与我们日常编写的 JavaScript 代码的执行过程紧密相关。

### 提示词
```
这是目录为v8/src/execution/execution.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
```