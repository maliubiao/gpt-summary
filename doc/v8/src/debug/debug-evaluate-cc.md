Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding of the Request:**

The request asks for a functional summary of the C++ code, specifically targeting the `v8/src/debug/debug-evaluate.cc` file. Key constraints include:

* Identifying the file's purpose within V8's debugging functionality.
* Checking if the (incomplete) code snippet implies a `.tq` extension (it doesn't).
* Relating the code to JavaScript functionality and providing examples.
* Inferring code logic with example inputs and outputs.
* Identifying common programming errors related to the functionality.
* Providing a concise summary of the file's role.

**2. Examining the `#include` Directives:**

The `#include` directives provide the first clues about the file's purpose. Keywords like "debug," "evaluate," "frames," "scopes," and "script" strongly suggest that this file is involved in evaluating code within a debugging context. The presence of "codegen" hints at compilation-related activities. "execution" points to the runtime execution of code. The inclusion of `src/objects/contexts.h` and related files suggests interaction with V8's object model.

**3. Analyzing the `namespace`:**

The code is within `namespace v8 { namespace internal {` indicating it's part of V8's internal implementation, not the public API. The `debug` namespace further confirms its debugging focus.

**4. Focusing on Key Functions:**

The core functionality is likely within the functions defined in the snippet. The most prominent functions are:

* `DebugEvaluate::Global`: This strongly suggests evaluating code in the global scope.
* `DebugEvaluate::Local`:  This suggests evaluating code within the context of a specific stack frame, likely accessing local variables.
* `DebugEvaluate::WithTopmostArguments`: This hints at evaluating code with access to the arguments of the topmost function on the stack.
* `DebugEvaluate::Evaluate`: This appears to be a core evaluation function, likely called by the other functions.
* `DebugEvaluate::ContextBuilder`: This class likely handles the creation of the appropriate evaluation context.
* `DebugEvaluate::IsSideEffectFreeIntrinsic` and `BytecodeHasNoSideEffect`:  These suggest mechanisms for determining if code execution has side effects.

**5. Deconstructing `DebugEvaluate::Global`:**

* It takes `source` (the code to evaluate), `mode` (controlling break behavior), and `repl_mode`.
* `GetFunctionInfo` compiles the `source` into a `SharedFunctionInfo`.
* It creates a `JSFunction` from the compiled code and the global `NativeContext`.
* It uses `DisableBreak` to control breakpoints during evaluation.
* It has logic for `kDisableBreaksAndThrowOnSideEffect`, indicating a mechanism to detect side effects during global evaluation.
* `Execution::CallScript` performs the actual execution.

**6. Deconstructing `DebugEvaluate::Local`:**

* It takes a `frame_id` and `inlined_jsframe_index` to identify the context.
* It uses `DebuggableStackFrameIterator` to locate the stack frame.
* It has special handling for WebAssembly frames.
* For JavaScript frames, it uses `ContextBuilder` to create the evaluation context, including local variables.
* It calls the `Evaluate` function.
* It updates the local variable values after evaluation using `context_builder.UpdateValues()`.

**7. Deconstructing `DebugEvaluate::WithTopmostArguments`:**

* It gets the topmost stack frame using `JavaScriptStackFrameIterator`.
* It materializes the `arguments` and `this` value into a temporary object.
* It creates a special `DebugEvaluateContext` that includes this materialized object.
* It calls the `Evaluate` function.

**8. Deconstructing `DebugEvaluate::Evaluate`:**

* It uses `Compiler::GetFunctionFromEval` to compile the `source` within the given `context`.
* It uses `Execution::Call` to execute the compiled function.
* It has logic to handle `throw_on_side_effect`.

**9. Deconstructing `DebugEvaluate::ContextBuilder`:**

* It iterates through the scope chain of the stack frame.
* It materializes stack-allocated variables into objects.
* It creates a chain of `DebugEvaluateContext` objects to provide the correct scope for evaluation.
* `UpdateValues` writes back changes to materialized variables.

**10. Deconstructing Side Effect Detection:**

* `IsSideEffectFreeIntrinsic` has a large allowlist of runtime functions deemed side-effect free.
* `BytecodeHasNoSideEffect` has an allowlist of bytecodes considered side-effect free. The logic allows calls and jumps (under specific conditions), suggesting a more nuanced analysis than just opcode presence.

**11. Connecting to JavaScript:**

The functions directly relate to debugging scenarios where developers need to evaluate expressions in the context of their running JavaScript code. The examples provided in the initial response directly illustrate how these functions would be used in a debugger.

**12. Inferring Logic and Examples:**

Based on the function names and parameters, it's possible to infer how these functions work and construct example inputs and outputs. For instance, `DebugEvaluate::Local` clearly takes a frame ID and source code, and the output would be the result of evaluating that code in that frame's context.

**13. Identifying Common Errors:**

The side-effect checking functionality hints at potential issues with evaluating code that modifies program state during debugging. Trying to assign to `const` variables or calling functions with side effects when not expected are common errors.

**14. Summarizing the Functionality:**

The core purpose is to provide the mechanism for evaluating arbitrary JavaScript code within different execution contexts during debugging. This involves compiling the code, setting up the correct scope, executing it, and potentially detecting side effects.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this file just handles simple expression evaluation.
* **Correction:** The presence of `ContextBuilder` and the handling of scope chains indicate a more sophisticated mechanism for accessing local variables and ensuring correct evaluation context.
* **Initial thought:** Side effect detection is just a simple flag.
* **Correction:** The detailed allowlists of intrinsics and bytecodes show a more granular approach to determining side-effect freedom. The inclusion of calls in the bytecode list with conditions suggests an understanding of call semantics.

By following this systematic approach of examining includes, namespaces, key functions, and then drilling down into the details of each function, it's possible to arrive at a comprehensive understanding of the code's purpose and functionality, even with an incomplete snippet. The key is to leverage the naming conventions and the overall structure of the code to infer its intended behavior.
好的，我们来分析一下 `v8/src/debug/debug-evaluate.cc` 这个V8源代码文件（第一部分）。

**功能归纳：**

从提供的代码片段来看，`v8/src/debug/debug-evaluate.cc` 的主要功能是 **在调试环境中执行 JavaScript 代码片段**。它提供了在不同作用域（全局和局部）下动态评估代码的能力，这对于调试器（debugger）的功能至关重要。

**具体功能点：**

1. **全局代码评估 (`DebugEvaluate::Global`)：**
   - 允许在全局作用域中执行一段 JavaScript 代码。
   - 可以选择是否禁用断点 (`debug::EvaluateGlobalMode`)。
   - 可以选择在执行过程中检测副作用 (`debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect`)。
   - 使用 `ScriptCompiler` 编译给定的源代码字符串。
   - 创建一个 `JSFunction` 并使用 `Execution::CallScript` 执行。

2. **局部代码评估 (`DebugEvaluate::Local`)：**
   - 允许在特定的栈帧（`StackFrameId`）的局部作用域中执行一段 JavaScript 代码。
   - 可以指定内联帧的索引 (`inlined_jsframe_index`)。
   - 可以选择在执行过程中抛出副作用异常 (`throw_on_side_effect`)。
   - 使用 `DebuggableStackFrameIterator` 定位到目标栈帧。
   - 通过 `ContextBuilder` 构建一个包含局部变量的执行上下文。
   - 对于 WebAssembly 栈帧有特殊的处理。
   - 调用 `Evaluate` 函数执行代码。
   - 执行后，通过 `context_builder.UpdateValues()` 将局部变量的修改写回。

3. **带顶层参数的代码评估 (`DebugEvaluate::WithTopmostArguments`)：**
   - 允许在当前调用栈顶层函数的上下文中执行代码，可以访问该函数的 `arguments` 和 `this`。
   - 将 `arguments` 和 `this` 物化到一个临时对象上。
   - 创建一个特殊的 `DebugEvaluateContext` 来包含这个临时对象。
   - 调用 `Evaluate` 函数执行代码。

4. **核心评估函数 (`DebugEvaluate::Evaluate`)：**
   - 接收编译好的 `SharedFunctionInfo`、上下文 `Context`、接收者 `receiver` 和源代码字符串 `source`。
   - 使用 `Compiler::GetFunctionFromEval` 将源代码编译成函数。
   - 使用 `Execution::Call` 执行编译后的函数。
   - 根据 `throw_on_side_effect` 参数决定是否开启副作用检查。

5. **上下文构建器 (`DebugEvaluate::ContextBuilder`)：**
   - 用于为局部代码评估构建正确的执行上下文。
   - 遍历栈帧的作用域链。
   - 物化栈上分配的局部变量，使其在评估过程中可访问。
   - 创建一个 `DebugEvaluateContext` 链，将物化对象和原始上下文连接起来。
   - 考虑了作用域链中的变量遮蔽问题。
   - `UpdateValues()` 方法用于将评估过程中对局部变量的修改同步回原始状态。

6. **副作用检查 (`DebugEvaluate::IsSideEffectFreeIntrinsic`, `BytecodeHasNoSideEffect`, `BuiltinGetSideEffectState`)：**
   - 提供了判断某些 V8 内部函数（intrinsics）和字节码是否具有副作用的机制。
   - 这对于调试器的安全性和某些高级调试功能（例如，在不影响程序状态的情况下评估表达式）非常重要。
   - `IsSideEffectFreeIntrinsic` 列出了被认为是无副作用的运行时函数。
   - `BytecodeHasNoSideEffect` 列出了被认为是无副作用的字节码指令。
   - `BuiltinGetSideEffectState` 用于获取内置函数的副作用状态。

**关于文件扩展名和 Torque：**

你提到如果 `v8/src/debug/debug-evaluate.cc` 以 `.tq` 结尾，它将是 V8 Torque 源代码。**这个说法是正确的。** Torque 是 V8 用于生成高效内置函数的领域特定语言。但是，从提供的代码来看，文件扩展名是 `.cc`，表明它是 **C++ 源代码**。

**与 JavaScript 功能的关系及示例：**

`v8/src/debug/debug-evaluate.cc` 的功能直接对应于 JavaScript 调试器提供的 **"在当前上下文中评估表达式"** 或 **"watch 表达式"** 等功能。

**JavaScript 示例：**

假设你在一个断点处暂停了 JavaScript 代码的执行：

```javascript
function myFunction(a, b) {
  let sum = a + b;
  debugger; // 代码在这里暂停
  return sum * 2;
}

myFunction(5, 3);
```

当执行到 `debugger` 语句时，代码会暂停。此时，调试器可以使用 `v8/src/debug/debug-evaluate.cc` 提供的功能来执行以下操作：

1. **在全局作用域评估：** 你可以在调试器的控制台中输入全局变量或表达式，例如：
   ```javascript
   console.log(window.location.href); // 评估全局变量
   console.log(Math.max(10, 20));     // 评估全局函数调用
   ```
   这会调用 `DebugEvaluate::Global` 在全局上下文中执行 `window.location.href` 或 `Math.max(10, 20)`。

2. **在局部作用域评估：** 你可以访问和评估当前函数 `myFunction` 的局部变量：
   ```javascript
   console.log(a);    // 输出 5
   console.log(b);    // 输出 3
   console.log(sum);  // 输出 8
   console.log(a * b); // 输出 15
   ```
   这会调用 `DebugEvaluate::Local` 在 `myFunction` 的栈帧中评估表达式 `a`，`b`，`sum` 或 `a * b`。

3. **评估表达式并观察副作用 (如果调试器允许):**  某些调试器可能允许你在评估表达式时观察其是否会产生副作用。`DebugEvaluate::Evaluate` 中的副作用检查机制就支持这种功能。

**代码逻辑推理和假设输入输出：**

**假设 `DebugEvaluate::Local` 被调用：**

* **输入：**
    - `isolate`: 当前 V8 隔离区指针。
    - `frame_id`:  标识 `myFunction` 栈帧的 ID。
    - `inlined_jsframe_index`:  假设为 0 (非内联帧)。
    - `source`: `"a + b"` (要评估的 JavaScript 代码)。
    - `throw_on_side_effect`: `false`。

* **执行过程 (简化)：**
    1. `DebuggableStackFrameIterator` 定位到 `myFunction` 的栈帧。
    2. `ContextBuilder` 构建一个上下文，该上下文可以访问 `myFunction` 的局部变量 `a` 和 `b`。
    3. `DebugEvaluate::Evaluate` 被调用，在构建的上下文中执行 `"a + b"`。

* **输出：**
    - `MaybeHandle<Object>` 将包含一个代表数字 `8` 的 V8 对象（因为 `a` 是 5，`b` 是 3）。

**用户常见的编程错误：**

1. **在副作用检查模式下尝试修改变量：** 如果调试器启用了副作用检查，并且用户尝试评估一个会修改变量值的表达式（例如，`a = 10`），则可能会抛出异常。这是因为调试评估的目标通常是在不改变程序状态的情况下进行检查。

   **JavaScript 示例（在启用副作用检查的情况下）：**
   ```javascript
   console.log(a = 10); // 可能导致错误，因为这是一个赋值操作
   ```

2. **访问不存在的变量：** 在局部作用域评估时，如果尝试访问当前作用域中不存在的变量，则会得到 `ReferenceError`。

   **JavaScript 示例：**
   ```javascript
   console.log(c); // 如果变量 c 未定义，将抛出 ReferenceError
   ```

3. **在不合适的上下文中评估代码：**  尝试在局部作用域访问全局变量可能会因为作用域链的问题导致意外的结果，尤其是在存在同名局部变量遮蔽全局变量的情况下。

**总结：**

`v8/src/debug/debug-evaluate.cc` 的第一部分代码定义了 V8 中用于在调试环境中执行 JavaScript 代码的核心机制。它提供了在全局和局部作用域中评估代码的能力，并考虑了副作用检查和上下文构建等关键问题，为 V8 的调试功能提供了基础。

Prompt: 
```
这是目录为v8/src/debug/debug-evaluate.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/debug/debug-evaluate.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/debug/debug-evaluate.h"

#include "src/builtins/accessors.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/compiler.h"
#include "src/codegen/reloc-info.h"
#include "src/codegen/script-details.h"
#include "src/common/globals.h"
#include "src/debug/debug-frames.h"
#include "src/debug/debug-scopes.h"
#include "src/debug/debug.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/interpreter/bytecode-array-iterator.h"
#include "src/interpreter/bytecodes.h"
#include "src/objects/code-inl.h"
#include "src/objects/contexts.h"
#include "src/objects/string-set-inl.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/debug/debug-wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

namespace {
static MaybeDirectHandle<SharedFunctionInfo> GetFunctionInfo(
    Isolate* isolate, Handle<String> source, REPLMode repl_mode) {
  ScriptDetails script_details(isolate->factory()->empty_string(),
                               ScriptOriginOptions(true, true));
  script_details.repl_mode = repl_mode;
  ScriptCompiler::CompilationDetails compilation_details;
  return Compiler::GetSharedFunctionInfoForScript(
      isolate, source, script_details, ScriptCompiler::kNoCompileOptions,
      ScriptCompiler::kNoCacheNoReason, NOT_NATIVES_CODE, &compilation_details);
}
}  // namespace

MaybeHandle<Object> DebugEvaluate::Global(Isolate* isolate,
                                          Handle<String> source,
                                          debug::EvaluateGlobalMode mode,
                                          REPLMode repl_mode) {
  DirectHandle<SharedFunctionInfo> shared_info;
  if (!GetFunctionInfo(isolate, source, repl_mode).ToHandle(&shared_info)) {
    return MaybeHandle<Object>();
  }

  Handle<NativeContext> context = isolate->native_context();
  Handle<JSFunction> function =
      Factory::JSFunctionBuilder{isolate, shared_info, context}.Build();

  DisableBreak disable_break_scope(
      isolate->debug(),
      mode == debug::EvaluateGlobalMode::kDisableBreaks ||
          mode ==
              debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect);

  if (mode == debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect) {
    isolate->debug()->StartSideEffectCheckMode();
  }
  // TODO(cbruni, 1244145): Use host-defined options from script context.
  Handle<FixedArray> host_defined_options(
      Cast<Script>(function->shared()->script())->host_defined_options(),
      isolate);
  MaybeHandle<Object> result = Execution::CallScript(
      isolate, function, Handle<JSObject>(context->global_proxy(), isolate),
      host_defined_options);
  if (mode == debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect) {
    isolate->debug()->StopSideEffectCheckMode();
  }
  return result;
}

MaybeHandle<Object> DebugEvaluate::Local(Isolate* isolate,
                                         StackFrameId frame_id,
                                         int inlined_jsframe_index,
                                         Handle<String> source,
                                         bool throw_on_side_effect) {
  // Handle the processing of break.
  DisableBreak disable_break_scope(isolate->debug());

  // Get the frame where the debugging is performed.
  DebuggableStackFrameIterator it(isolate, frame_id);
#if V8_ENABLE_WEBASSEMBLY
  if (it.is_wasm()) {
#if V8_ENABLE_DRUMBRAKE
    // TODO(paolosev@microsoft.com) - Not supported by Wasm interpreter.
    if (it.is_wasm_interpreter_entry()) return {};
#endif  // V8_ENABLE_DRUMBRAKE
    WasmFrame* frame = WasmFrame::cast(it.frame());
    Handle<SharedFunctionInfo> outer_info(
        isolate->native_context()->empty_function()->shared(), isolate);
    Handle<JSObject> context_extension = GetWasmDebugProxy(frame);
    DirectHandle<ScopeInfo> scope_info =
        ScopeInfo::CreateForWithScope(isolate, Handle<ScopeInfo>::null());
    Handle<Context> context = isolate->factory()->NewWithContext(
        isolate->native_context(), scope_info, context_extension);
    return Evaluate(isolate, outer_info, context, context_extension, source,
                    throw_on_side_effect);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  CHECK(it.is_javascript());
  JavaScriptFrame* frame = it.javascript_frame();
  // This is not a lot different than DebugEvaluate::Global, except that
  // variables accessible by the function we are evaluating from are
  // materialized and included on top of the native context. Changes to
  // the materialized object are written back afterwards.
  // Note that the native context is taken from the original context chain,
  // which may not be the current native context of the isolate.
  ContextBuilder context_builder(isolate, frame, inlined_jsframe_index);
  if (isolate->has_exception()) return {};

  Handle<Context> context = context_builder.evaluation_context();
  Handle<JSObject> receiver(context->global_proxy(), isolate);
  MaybeHandle<Object> maybe_result =
      Evaluate(isolate, context_builder.outer_info(), context, receiver, source,
               throw_on_side_effect);
  if (!maybe_result.is_null()) context_builder.UpdateValues();
  return maybe_result;
}

MaybeHandle<Object> DebugEvaluate::WithTopmostArguments(Isolate* isolate,
                                                        Handle<String> source) {
  // Handle the processing of break.
  DisableBreak disable_break_scope(isolate->debug());
  Factory* factory = isolate->factory();
  JavaScriptStackFrameIterator it(isolate);

  // Get context and receiver.
  DirectHandle<Context> native_context(
      Cast<Context>(it.frame()->context())->native_context(), isolate);

  // Materialize arguments as property on an extension object.
  Handle<JSObject> materialized = factory->NewSlowJSObjectWithNullProto();
  Handle<String> arguments_str = factory->arguments_string();
  JSObject::SetOwnPropertyIgnoreAttributes(
      materialized, arguments_str,
      Accessors::FunctionGetArguments(it.frame(), 0), NONE)
      .Check();

  // Materialize receiver.
  Handle<Object> this_value(it.frame()->receiver(), isolate);
  DCHECK_EQ(it.frame()->IsConstructor(), IsTheHole(*this_value, isolate));
  if (!IsTheHole(*this_value, isolate)) {
    Handle<String> this_str = factory->this_string();
    JSObject::SetOwnPropertyIgnoreAttributes(materialized, this_str, this_value,
                                             NONE)
        .Check();
  }

  // Use extension object in a debug-evaluate scope.
  DirectHandle<ScopeInfo> scope_info =
      ScopeInfo::CreateForWithScope(isolate, Handle<ScopeInfo>::null());
  scope_info->SetIsDebugEvaluateScope();
  Handle<Context> evaluation_context = factory->NewDebugEvaluateContext(
      native_context, scope_info, materialized, Handle<Context>());
  Handle<SharedFunctionInfo> outer_info(
      native_context->empty_function()->shared(), isolate);
  Handle<JSObject> receiver(native_context->global_proxy(), isolate);
  const bool throw_on_side_effect = false;
  MaybeHandle<Object> maybe_result =
      Evaluate(isolate, outer_info, evaluation_context, receiver, source,
               throw_on_side_effect);
  return maybe_result;
}

// Compile and evaluate source for the given context.
MaybeHandle<Object> DebugEvaluate::Evaluate(
    Isolate* isolate, Handle<SharedFunctionInfo> outer_info,
    Handle<Context> context, Handle<Object> receiver, Handle<String> source,
    bool throw_on_side_effect) {
  Handle<JSFunction> eval_fun;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, eval_fun,
      Compiler::GetFunctionFromEval(source, outer_info, context,
                                    LanguageMode::kSloppy, NO_PARSE_RESTRICTION,
                                    kNoSourcePosition, kNoSourcePosition,
                                    ParsingWhileDebugging::kYes));

  Handle<Object> result;
  bool success = false;
  if (throw_on_side_effect) isolate->debug()->StartSideEffectCheckMode();
  success = Execution::Call(isolate, eval_fun, receiver, 0, nullptr)
                .ToHandle(&result);
  if (throw_on_side_effect) isolate->debug()->StopSideEffectCheckMode();
  if (!success) DCHECK(isolate->has_exception());
  return success ? result : MaybeHandle<Object>();
}

Handle<SharedFunctionInfo> DebugEvaluate::ContextBuilder::outer_info() const {
  return handle(frame_inspector_.GetFunction()->shared(), isolate_);
}

DebugEvaluate::ContextBuilder::ContextBuilder(Isolate* isolate,
                                              JavaScriptFrame* frame,
                                              int inlined_jsframe_index)
    : isolate_(isolate),
      frame_inspector_(frame, inlined_jsframe_index, isolate),
      scope_iterator_(isolate, &frame_inspector_,
                      ScopeIterator::ReparseStrategy::kScriptIfNeeded) {
  Handle<Context> outer_context(frame_inspector_.GetFunction()->context(),
                                isolate);
  evaluation_context_ = outer_context;
  Factory* factory = isolate->factory();

  if (scope_iterator_.Done()) return;

  // To evaluate as if we were running eval at the point of the debug break,
  // we reconstruct the context chain as follows:
  //  - To make stack-allocated variables visible, we materialize them and
  //    use a debug-evaluate context to wrap both the materialized object and
  //    the original context.
  //  - Each scope from the break position up to the function scope is wrapped
  //    in a debug-evaluate context.
  //  - Between the function scope and the native context, we only resolve
  //    variable names that are guaranteed to not be shadowed by stack-allocated
  //    variables. ScopeInfos between the function scope and the native
  //    context have a blocklist attached to implement that.
  //  - The various block lists are calculated by the ScopeIterator during
  //    iteration.
  // Context::Lookup has special handling for debug-evaluate contexts:
  //  - Look up in the materialized stack variables.
  //  - Look up in the original context.
  //  - Once we have seen a debug-evaluate context we start to take the
  //    block lists into account before moving up the context chain.
  for (; scope_iterator_.InInnerScope(); scope_iterator_.Next()) {
    ScopeIterator::ScopeType scope_type = scope_iterator_.Type();
    if (scope_type == ScopeIterator::ScopeTypeScript) break;
    ContextChainElement context_chain_element;
    if (scope_type == ScopeIterator::ScopeTypeLocal ||
        scope_iterator_.DeclaresLocals(ScopeIterator::Mode::STACK)) {
      context_chain_element.materialized_object =
          scope_iterator_.ScopeObject(ScopeIterator::Mode::STACK);
    }
    if (scope_iterator_.HasContext()) {
      context_chain_element.wrapped_context = scope_iterator_.CurrentContext();
    }
    context_chain_.push_back(context_chain_element);
  }

  Handle<ScopeInfo> scope_info =
      IsNativeContext(*evaluation_context_)
          ? Handle<ScopeInfo>::null()
          : handle(evaluation_context_->scope_info(), isolate);
  for (auto rit = context_chain_.rbegin(); rit != context_chain_.rend();
       rit++) {
    ContextChainElement element = *rit;
    scope_info = ScopeInfo::CreateForWithScope(isolate, scope_info);
    scope_info->SetIsDebugEvaluateScope();

    // In the case where the "paused function scope" is the script scope
    // itself, we don't need (and don't have) a blocklist.
    const bool paused_scope_is_script_scope =
        scope_iterator_.Done() || scope_iterator_.InInnerScope();
    if (rit == context_chain_.rbegin() && !paused_scope_is_script_scope) {
      // The DebugEvaluateContext we create for the closure scope is the only
      // DebugEvaluateContext with a block list. This means we'll retrieve
      // the existing block list from the paused function scope
      // and also associate the temporary scope_info we create here with that
      // blocklist.
      Handle<ScopeInfo> function_scope_info = handle(
          frame_inspector_.GetFunction()->shared()->scope_info(), isolate_);
      Handle<Object> block_list = handle(
          isolate_->LocalsBlockListCacheGet(function_scope_info), isolate_);
      CHECK(IsStringSet(*block_list));
      isolate_->LocalsBlockListCacheSet(scope_info, Handle<ScopeInfo>::null(),
                                        Cast<StringSet>(block_list));
    }

    evaluation_context_ = factory->NewDebugEvaluateContext(
        evaluation_context_, scope_info, element.materialized_object,
        element.wrapped_context);
  }
}

void DebugEvaluate::ContextBuilder::UpdateValues() {
  scope_iterator_.Restart();
  for (ContextChainElement& element : context_chain_) {
    if (!element.materialized_object.is_null()) {
      DirectHandle<FixedArray> keys =
          KeyAccumulator::GetKeys(isolate_, element.materialized_object,
                                  KeyCollectionMode::kOwnOnly,
                                  ENUMERABLE_STRINGS)
              .ToHandleChecked();

      for (int i = 0; i < keys->length(); i++) {
        DCHECK(IsString(keys->get(i)));
        Handle<String> key(Cast<String>(keys->get(i)), isolate_);
        Handle<Object> value = JSReceiver::GetDataProperty(
            isolate_, element.materialized_object, key);
        scope_iterator_.SetVariableValue(key, value);
      }
    }
    scope_iterator_.Next();
  }
}

// static
bool DebugEvaluate::IsSideEffectFreeIntrinsic(Runtime::FunctionId id) {
// Use macro to include only the non-inlined version of an intrinsic.
#define INTRINSIC_ALLOWLIST(V)           \
  /* Conversions */                      \
  V(NumberToStringSlow)                  \
  V(ToBigInt)                            \
  V(ToLength)                            \
  V(ToNumber)                            \
  V(ToObject)                            \
  V(ToString)                            \
  /* Type checks */                      \
  V(IsArray)                             \
  V(IsJSProxy)                           \
  V(IsJSReceiver)                        \
  V(IsSmi)                               \
  /* Loads */                            \
  V(LoadLookupSlotForCall)               \
  V(GetPrivateMember)                    \
  V(GetProperty)                         \
  /* Arrays */                           \
  V(ArraySpeciesConstructor)             \
  V(HasFastPackedElements)               \
  V(NewArray)                            \
  V(NormalizeElements)                   \
  V(TypedArrayGetBuffer)                 \
  /* Errors */                           \
  V(NewTypeError)                        \
  V(ReThrow)                             \
  V(ThrowCalledNonCallable)              \
  V(ThrowInvalidStringLength)            \
  V(ThrowIteratorError)                  \
  V(ThrowIteratorResultNotAnObject)      \
  V(ThrowPatternAssignmentNonCoercible)  \
  V(ThrowReferenceError)                 \
  V(ThrowSymbolIteratorInvalid)          \
  /* Strings */                          \
  V(StringReplaceOneCharWithString)      \
  V(StringSubstring)                     \
  V(StringToNumber)                      \
  /* BigInts */                          \
  V(BigIntEqualToBigInt)                 \
  V(BigIntToNumber)                      \
  /* Literals */                         \
  V(CreateArrayLiteral)                  \
  V(CreateObjectLiteral)                 \
  V(CreateRegExpLiteral)                 \
  V(DefineClass)                         \
  /* Called from builtins */             \
  V(AllocateInYoungGeneration)           \
  V(AllocateInOldGeneration)             \
  V(ArrayIncludes_Slow)                  \
  V(ArrayIndexOf)                        \
  V(ArrayIsArray)                        \
  V(GetFunctionName)                     \
  V(GlobalPrint)                         \
  V(HasProperty)                         \
  V(ObjectCreate)                        \
  V(ObjectEntries)                       \
  V(ObjectEntriesSkipFastPath)           \
  V(ObjectHasOwnProperty)                \
  V(ObjectKeys)                          \
  V(ObjectValues)                        \
  V(ObjectValuesSkipFastPath)            \
  V(ObjectGetOwnPropertyNames)           \
  V(ObjectGetOwnPropertyNamesTryFast)    \
  V(ObjectIsExtensible)                  \
  V(RegExpInitializeAndCompile)          \
  V(StackGuard)                          \
  V(HandleNoHeapWritesInterrupts)        \
  V(StringAdd)                           \
  V(StringCharCodeAt)                    \
  V(StringEqual)                         \
  V(StringParseFloat)                    \
  V(StringParseInt)                      \
  V(SymbolDescriptiveString)             \
  V(ThrowRangeError)                     \
  V(ThrowTypeError)                      \
  V(ToName)                              \
  V(TransitionElementsKind)              \
  /* Misc. */                            \
  V(Call)                                \
  V(CompleteInobjectSlackTrackingForMap) \
  V(HasInPrototypeChain)                 \
  V(IncrementUseCounter)                 \
  V(MaxSmi)                              \
  V(NewObject)                           \
  V(StringMaxLength)                     \
  V(StringToArray)                       \
  V(AsyncFunctionEnter)                  \
  V(AsyncFunctionResolve)                \
  /* Test */                             \
  V(GetOptimizationStatus)               \
  V(OptimizeFunctionOnNextCall)          \
  V(OptimizeOsr)

// Intrinsics with inline versions have to be allowlisted here a second time.
#define INLINE_INTRINSIC_ALLOWLIST(V) \
  V(AsyncFunctionEnter)               \
  V(AsyncFunctionResolve)

#define CASE(Name) case Runtime::k##Name:
#define INLINE_CASE(Name) case Runtime::kInline##Name:
  switch (id) {
    INTRINSIC_ALLOWLIST(CASE)
    INLINE_INTRINSIC_ALLOWLIST(INLINE_CASE)
    return true;
    default:
      if (v8_flags.trace_side_effect_free_debug_evaluate) {
        PrintF("[debug-evaluate] intrinsic %s may cause side effect.\n",
               Runtime::FunctionForId(id)->name);
      }
      return false;
  }

#undef CASE
#undef INLINE_CASE
#undef INTRINSIC_ALLOWLIST
#undef INLINE_INTRINSIC_ALLOWLIST
}

namespace {

bool BytecodeHasNoSideEffect(interpreter::Bytecode bytecode) {
  using interpreter::Bytecode;
  using interpreter::Bytecodes;
  if (Bytecodes::IsWithoutExternalSideEffects(bytecode)) return true;
  if (Bytecodes::IsCallOrConstruct(bytecode)) return true;
  if (Bytecodes::IsJumpIfToBoolean(bytecode)) return true;
  if (Bytecodes::IsPrefixScalingBytecode(bytecode)) return true;
  switch (bytecode) {
    // Allowlist for bytecodes.
    // Loads.
    case Bytecode::kLdaLookupSlot:
    case Bytecode::kLdaGlobal:
    case Bytecode::kGetNamedProperty:
    case Bytecode::kGetKeyedProperty:
    case Bytecode::kLdaGlobalInsideTypeof:
    case Bytecode::kLdaLookupSlotInsideTypeof:
    case Bytecode::kGetIterator:
    // Arithmetics.
    case Bytecode::kAdd:
    case Bytecode::kAddSmi:
    case Bytecode::kSub:
    case Bytecode::kSubSmi:
    case Bytecode::kMul:
    case Bytecode::kMulSmi:
    case Bytecode::kDiv:
    case Bytecode::kDivSmi:
    case Bytecode::kMod:
    case Bytecode::kModSmi:
    case Bytecode::kExp:
    case Bytecode::kExpSmi:
    case Bytecode::kNegate:
    case Bytecode::kBitwiseAnd:
    case Bytecode::kBitwiseAndSmi:
    case Bytecode::kBitwiseNot:
    case Bytecode::kBitwiseOr:
    case Bytecode::kBitwiseOrSmi:
    case Bytecode::kBitwiseXor:
    case Bytecode::kBitwiseXorSmi:
    case Bytecode::kShiftLeft:
    case Bytecode::kShiftLeftSmi:
    case Bytecode::kShiftRight:
    case Bytecode::kShiftRightSmi:
    case Bytecode::kShiftRightLogical:
    case Bytecode::kShiftRightLogicalSmi:
    case Bytecode::kInc:
    case Bytecode::kDec:
    case Bytecode::kLogicalNot:
    case Bytecode::kToBooleanLogicalNot:
    case Bytecode::kTypeOf:
    // Contexts.
    case Bytecode::kCreateBlockContext:
    case Bytecode::kCreateCatchContext:
    case Bytecode::kCreateFunctionContext:
    case Bytecode::kCreateEvalContext:
    case Bytecode::kCreateWithContext:
    // Literals.
    case Bytecode::kCreateArrayLiteral:
    case Bytecode::kCreateEmptyArrayLiteral:
    case Bytecode::kCreateArrayFromIterable:
    case Bytecode::kCreateObjectLiteral:
    case Bytecode::kCreateEmptyObjectLiteral:
    case Bytecode::kCreateRegExpLiteral:
    // Allocations.
    case Bytecode::kCreateClosure:
    case Bytecode::kCreateUnmappedArguments:
    case Bytecode::kCreateRestParameter:
    // Comparisons.
    case Bytecode::kTestEqual:
    case Bytecode::kTestEqualStrict:
    case Bytecode::kTestLessThan:
    case Bytecode::kTestLessThanOrEqual:
    case Bytecode::kTestGreaterThan:
    case Bytecode::kTestGreaterThanOrEqual:
    case Bytecode::kTestInstanceOf:
    case Bytecode::kTestIn:
    case Bytecode::kTestReferenceEqual:
    case Bytecode::kTestUndetectable:
    case Bytecode::kTestTypeOf:
    case Bytecode::kTestUndefined:
    case Bytecode::kTestNull:
    // Conversions.
    case Bytecode::kToObject:
    case Bytecode::kToName:
    case Bytecode::kToNumber:
    case Bytecode::kToNumeric:
    case Bytecode::kToString:
    case Bytecode::kToBoolean:
    // Misc.
    case Bytecode::kIncBlockCounter:  // Coverage counters.
    case Bytecode::kForInEnumerate:
    case Bytecode::kForInPrepare:
    case Bytecode::kForInNext:
    case Bytecode::kForInStep:
    case Bytecode::kJumpLoop:
    case Bytecode::kThrow:
    case Bytecode::kReThrow:
    case Bytecode::kThrowReferenceErrorIfHole:
    case Bytecode::kThrowSuperNotCalledIfHole:
    case Bytecode::kThrowSuperAlreadyCalledIfNotHole:
    case Bytecode::kIllegal:
    case Bytecode::kCallJSRuntime:
    case Bytecode::kReturn:
    case Bytecode::kSetPendingMessage:
      return true;
    default:
      return false;
  }
}

DebugInfo::SideEffectState BuiltinGetSideEffectState(Builtin id) {
  switch (id) {
    // Allowlist for builtins.
    // Object builtins.
    case Builtin::kObjectConstructor:
    case Builtin::kObjectCreate:
    case Builtin::kObjectEntries:
    case Builtin::kObjectGetOwnPropertyDescriptor:
    case Builtin::kObjectGetOwnPropertyDescriptors:
    case Builtin::kObjectGetOwnPropertyNames:
    case Builtin::kObjectGetOwnPropertySymbols:
    case Builtin::kObjectGetPrototypeOf:
    case Builtin::kObjectGroupBy:
    case Builtin::kObjectHasOwn:
    case Builtin::kObjectIs:
    case Builtin::kObjectIsExtensible:
    case Builtin::kObjectIsFrozen:
    case Builtin::kObjectIsSealed:
    case Builtin::kObjectKeys:
    case Builtin::kObjectPrototypeValueOf:
    case Builtin::kObjectValues:
    case Builtin::kObjectPrototypeHasOwnProperty:
    case Builtin::kObjectPrototypeIsPrototypeOf:
    case Builtin::kObjectPrototypePropertyIsEnumerable:
    case Builtin::kObjectPrototypeToString:
    case Builtin::kObjectPrototypeToLocaleString:
    // Array builtins.
    case Builtin::kArrayIsArray:
    case Builtin::kArrayConstructor:
    case Builtin::kArrayFrom:
    case Builtin::kArrayIndexOf:
    case Builtin::kArrayOf:
    case Builtin::kArrayPrototypeValues:
    case Builtin::kArrayIncludes:
    case Builtin::kArrayPrototypeAt:
    case Builtin::kArrayPrototypeConcat:
    case Builtin::kArrayPrototypeEntries:
    case Builtin::kArrayPrototypeFind:
    case Builtin::kArrayPrototypeFindIndex:
    case Builtin::kArrayPrototypeFindLast:
    case Builtin::kArrayPrototypeFindLastIndex:
    case Builtin::kArrayPrototypeFlat:
    case Builtin::kArrayPrototypeFlatMap:
    case Builtin::kArrayPrototypeJoin:
    case Builtin::kArrayPrototypeKeys:
    case Builtin::kArrayPrototypeLastIndexOf:
    case Builtin::kArrayPrototypeSlice:
    case Builtin::kArrayPrototypeToLocaleString:
    case Builtin::kArrayPrototypeToReversed:
    case Builtin::kArrayPrototypeToSorted:
    case Builtin::kArrayPrototypeToSpliced:
    case Builtin::kArrayPrototypeToString:
    case Builtin::kArrayPrototypeWith:
    case Builtin::kArrayForEach:
    case Builtin::kArrayEvery:
    case Builtin::kArraySome:
    case Builtin::kArrayConcat:
    case Builtin::kArrayFilter:
    case Builtin::kArrayMap:
    case Builtin::kArrayReduce:
    case Builtin::kArrayReduceRight:
    // Trace builtins.
    case Builtin::kIsTraceCategoryEnabled:
    case Builtin::kTrace:
    // TypedArray builtins.
    case Builtin::kTypedArrayConstructor:
    case Builtin::kTypedArrayOf:
    case Builtin::kTypedArrayPrototypeAt:
    case Builtin::kTypedArrayPrototypeBuffer:
    case Builtin::kTypedArrayPrototypeByteLength:
    case Builtin::kTypedArrayPrototypeByteOffset:
    case Builtin::kTypedArrayPrototypeLength:
    case Builtin::kTypedArrayPrototypeEntries:
    case Builtin::kTypedArrayPrototypeKeys:
    case Builtin::kTypedArrayPrototypeValues:
    case Builtin::kTypedArrayPrototypeFind:
    case Builtin::kTypedArrayPrototypeFindIndex:
    case Builtin::kTypedArrayPrototypeFindLast:
    case Builtin::kTypedArrayPrototypeFindLastIndex:
    case Builtin::kTypedArrayPrototypeIncludes:
    case Builtin::kTypedArrayPrototypeJoin:
    case Builtin::kTypedArrayPrototypeIndexOf:
    case Builtin::kTypedArrayPrototypeLastIndexOf:
    case Builtin::kTypedArrayPrototypeSlice:
    case Builtin::kTypedArrayPrototypeSubArray:
    case Builtin::kTypedArrayPrototypeEvery:
    case Builtin::kTypedArrayPrototypeSome:
    case Builtin::kTypedArrayPrototypeToLocaleString:
    case Builtin::kTypedArrayPrototypeFilter:
    case Builtin::kTypedArrayPrototypeMap:
    case Builtin::kTypedArrayPrototypeReduce:
    case Builtin::kTypedArrayPrototypeReduceRight:
    case Builtin::kTypedArrayPrototypeForEach:
    case Builtin::kTypedArrayPrototypeToReversed:
    case Builtin::kTypedArrayPrototypeToSorted:
    case Builtin::kTypedArrayPrototypeWith:
    // ArrayBuffer builtins.
    case Builtin::kArrayBufferConstructor:
    case Builtin::kArrayBufferPrototypeGetByteLength:
    case Builtin::kArrayBufferIsView:
    case Builtin::kArrayBufferPrototypeSlice:
    case Builtin::kReturnReceiver:
    // DataView builtins.
    case Builtin::kDataViewConstructor:
    case Builtin::kDataViewPrototypeGetBuffer:
    case Builtin::kDataViewPrototypeGetByteLength:
    case Builtin::kDataViewPrototypeGetByteOffset:
    case Builtin::kDataViewPrototypeGetInt8:
    case Builtin::kDataViewPrototypeGetUint8:
    case Builtin::kDataViewPrototypeGetInt16:
    case Builtin::kDataViewPrototypeGetUint16:
    case Builtin::kDataViewPrototypeGetInt32:
    case Builtin::kDataViewPrototypeGetUint32:
    case Builtin::kDataViewPrototypeGetFloat16:
    case Builtin::kDataViewPrototypeGetFloat32:
    case Builtin::kDataViewPrototypeGetFloat64:
    case Builtin::kDataViewPrototypeGetBigInt64:
    case Builtin::kDataViewPrototypeGetBigUint64:
    // Boolean bulitins.
    case Builtin::kBooleanConstructor:
    case Builtin::kBooleanPrototypeToString:
    case Builtin::kBooleanPrototypeValueOf:
    // Date builtins.
    case Builtin::kDateConstructor:
    case Builtin::kDateNow:
    case Builtin::kDateParse:
    case Builtin::kDatePrototypeGetDate:
    case Builtin::kDatePrototypeGetDay:
    case Builtin::kDatePrototypeGetFullYear:
    case Builtin::kDatePrototypeGetHours:
    case Builtin::kDatePrototypeGetMilliseconds:
    case Builtin::kDatePrototypeGetMinutes:
    case Builtin::kDatePrototypeGetMonth:
    case Builtin::kDatePrototypeGetSeconds:
    case Builtin::kDatePrototypeGetTime:
    case Builtin::kDatePrototypeGetTimezoneOffset:
    case Builtin::kDatePrototypeGetUTCDate:
    case Builtin::kDatePrototypeGetUTCDay:
    case Builtin::kDatePrototypeGetUTCFullYear:
    case Builtin::kDatePrototypeGetUTCHours:
    case Builtin::kDatePrototypeGetUTCMilliseconds:
    case Builtin::kDatePrototypeGetUTCMinutes:
    case Builtin::kDatePrototypeGetUTCMonth:
    case Builtin::kDatePrototypeGetUTCSeconds:
    case Builtin::kDatePrototypeGetYear:
    case Builtin::kDatePrototypeToDateString:
    case Builtin::kDatePrototypeToISOString:
    case Builtin::kDatePrototypeToUTCString:
    case Builtin::kDatePrototypeToString:
#ifdef V8_INTL_SUPPORT
    case Builtin::kDatePrototypeToLocaleString:
    case Builtin::kDatePrototypeToLocaleDateString:
    case Builtin::kDatePrototypeToLocaleTimeString:
#endif
    case Builtin::kDatePrototypeToTimeString:
    case Builtin::kDatePrototypeToJson:
    case Builtin::kDatePrototypeToPrimitive:
    case Builtin::kDatePrototypeValueOf:
    // DisposableStack builtins.
    case Builtin::kDisposableStackConstructor:
    case Builtin::kDisposableStackPrototypeGetDisposed:
    // AsyncDisposableStack builtins.
    case Builtin::kAsyncDisposableStackConstructor:
    case Builtin::kAsyncDisposableStackPrototypeGetDisposed:
    // Map builtins.
    case Builtin::kMapConstructor:
    case Builtin::kMapGroupBy:
    case Builtin::kMapPrototypeForEach:
    case Builtin::kMapPrototypeGet:
    case Builtin::kMapPrototypeHas:
    case Builtin::kMapPrototypeEntries:
    case Builtin::kMapPrototypeGetSize:
    case Builtin::kMapPrototypeKeys:
    case Builtin::kMapPrototypeValues:
    // WeakMap builtins.
    case Builtin::kWeakMapConstructor:
    case Builtin::kWeakMapGet:
    case Builtin::kWeakMapPrototypeHas:
    // Math builtins.
    case Builtin::kMathAbs:
    case Builtin::kMathAcos:
    case Builtin::kMathAcosh:
    case Builtin::kMathAsin:
    case Builtin::kMathAsinh:
    case Builtin::kMathAtan:
    case Builtin::kMathAtanh:
    case Builtin::kMathAtan2:
    case Builtin::kMathCeil:
    case Builtin::kMathCbrt:
    case Builtin::kMathExpm1:
    case Builtin::kMathClz32:
    case Builtin::kMathCos:
    case Builtin::kMathCosh:
    case Builtin::kMathExp:
    case Builtin::kMathFloor:
    case Builtin::kMathF16round:
    case Builtin::kMathFround:
    case Builtin::kMathHypot:
    case Builtin::kMathImul:
    case Builtin::kMathLog:
    case Builtin::kMathLog1p:
    case Builtin::kMathLog2:
    case Builtin::kMathLog10:
    case Builtin::kMathMax:
    case Builtin::kMathMin:
    case Builtin::kMathPow:
    case Builtin::kMathRound:
    case Builtin::kMathSign:
    case Builtin::kMathSin:
    case Builtin::kMathSinh:
    case Builtin::kMathSqrt:
    case Builtin::kMathTan:
    case Builtin::kMathTanh:
    case Builtin::kMathTrunc:
    // Number builtins.
    case Builtin::kNumberConstructor:
    case Builtin::kNumberIsFinite:
    case Builtin::kNumberIsInteger:
    case Builtin::kNumberIsNaN:
    case Builtin::kNumberIsSafeInteger:
    case Builtin::kNumberParseFloat:
    case Builtin::kNumberParseInt:
    case Builtin::kNumberPrototypeToExponential:
    case Builtin::kNumberPrototypeToFixed:
    case Builtin::kNumberPrototypeToPrecision:
    case Builtin::kNumberPrototypeToString:
    case Builtin::kNumberPrototypeToLocaleString:
    case Builtin::kNumberPrototypeValueOf:
    // BigInt builtins.
    case Builtin::kBigIntConstructor:
    case Builtin::kBigIntAsIntN:
    case Builtin::kBigIntAsUintN:
    case Builtin::kBigIntPrototypeToString:
    case Builtin::kBigIntPrototypeValueOf:
    // Set builtins.
    case Builtin::kSetConstructor:
    case Builtin::kSetPrototypeEntries:
    case Builtin::kSetPrototypeForEach:
    case Builtin::kSetPrototypeGetSize:
    case Builtin::kSetPrototypeHas:
    case Builtin::kSetPrototypeValues:
    // WeakSet builtins.
    case Builtin::kWeakSetConstructor:
    case Builtin::kWeakSetPrototypeHas:
    // String builtins. Strings are immutable.
    case Builtin::kStringFromCharCode:
    case Builtin::kStringFromCodePoint:
    case Builtin::kStringConstructor:
    case Builtin::kStringListFromIterable:
    case Builtin::kStringPrototypeAnchor:
    case Builtin::kStringPrototypeAt:
    case Builtin::kStringPrototypeBig:
    case Builtin::kStringPrototypeBlink:
    case Builtin::kStringPrototypeBold:
    case Builtin::kStringPrototypeCharAt:
    case Builtin::kStringPrototypeCharCodeAt:
    case Builtin::kStringPrototypeCodePointAt:
    case Builtin::kStringPrototypeConcat:
    case Builtin::kStringPrototypeEndsWith:
    case Builtin::kStringPrototypeFixed:
    case Builtin::kStringPrototypeFontcolor:
    case Builtin::kStringPrototypeFontsize:
    case Builtin::kStringPrototypeIncludes:
    case Builtin::kStringPrototypeIndexOf:
    case Builtin::kStringPrototypeIsWellFormed:
    case Builtin::kStringPrototypeItalics:
    case Builtin::kStringPrototypeLastIndexOf:
    case Builtin::kStringPrototypeLink:
    case Builtin::kStringPrototypeMatch:
    case Builtin::kStringPrototypeMatchAll:

    case Builtin::kStringPrototypePadEnd:
    case Builtin::kStringPrototypePadStart:
    case Builtin::kStringPrototypeRepeat:
    case Builtin::kStringPrototypeReplace:
    case Builtin::kStringPrototypeReplaceAll:
    case Builtin
"""


```