Response: The user wants to understand the functionality of the C++ code provided, which is part of the V8 JavaScript engine and specifically relates to the `ShadowRealm` feature. I need to:

1. **Summarize the C++ code's purpose:**  Identify the main functionalities implemented in this file.
2. **Explain the connection to JavaScript:**  Describe how the C++ code relates to the `ShadowRealm` API in JavaScript.
3. **Provide JavaScript examples:**  Illustrate the functionalities implemented in the C++ code with corresponding JavaScript usage.

**Plan:**

1. **Analyze the `ShadowRealmConstructor` function:** This seems to be responsible for creating new `ShadowRealm` instances. I'll describe the steps involved in the C++ code and how they relate to the JavaScript constructor.
2. **Analyze the `ShadowRealmPrototypeEvaluate` function:** This function likely implements the `evaluate` method of `ShadowRealm` instances. I'll explain how it takes a string of JavaScript code and executes it within the shadow realm.
3. **Analyze the `GetWrappedValue` function:** This helper function appears to handle the transfer of values between the main realm and the shadow realm, particularly for callable objects (functions).
4. **Connect the C++ functions to JavaScript API:**  Explicitly link the C++ implementations to the corresponding JavaScript syntax and behavior.
5. **Create JavaScript examples:**  Provide clear examples showing how to create a `ShadowRealm` and use its `evaluate` method, highlighting the concepts of isolation and value wrapping.
这个C++源代码文件 `builtins-shadow-realm.cc` 实现了 JavaScript 中 `ShadowRealm` 相关的内置功能。`ShadowRealm` 提案旨在提供一种在 JavaScript 中创建隔离的执行环境的方式，它拥有自己独立的全局对象和内置对象。

**功能归纳:**

1. **`ShadowRealm` 构造函数 (`ShadowRealmConstructor`)**:  实现了 `ShadowRealm` 类的构造过程。
    - 验证 `new.target` 是否已定义，确保它是通过 `new` 关键字调用的。
    - 创建一个新的 Realm Record (`realmRec`)，代表隔离的全局环境。
    - 创建一个新的执行上下文，并将其与 `realmRec` 关联。
    - 设置新 Realm 的全局对象，并初始化其默认绑定。
    - 创建一个新的 `JSShadowRealm` 对象，并将 `realmRec` 和执行上下文存储在其中。

2. **`ShadowRealm.prototype.evaluate` 方法 (`ShadowRealmPrototypeEvaluate`)**:  实现了在 `ShadowRealm` 实例中执行 JavaScript 代码的功能。
    - 验证 `this` 值是否为 `JSShadowRealm` 对象。
    - 检查传入的源代码 `sourceText` 是否为字符串。
    - 获取当前的 Realm (调用者的 Realm) 和目标 `ShadowRealm` 的 Realm。
    - 调用 `PerformShadowRealmEval` 来执行代码。
    - **`PerformShadowRealmEval` 内部逻辑**:
        - 检查宿主环境是否允许在两个 Realm 之间编译字符串。
        - 在目标 `ShadowRealm` 的上下文中解析并执行 `sourceText`。
        - 处理解析错误和执行期间的异常。
        - 如果执行成功，则调用 `GetWrappedValue` 来包装执行结果，以便安全地将其传递回调用者的 Realm。

3. **`GetWrappedValue` 函数**:  这是一个辅助函数，用于处理从 `ShadowRealm` 中返回的值。
    - 如果返回值不是对象，则直接返回。
    - 如果返回值是可调用的对象（函数），则创建一个包装函数 (`JSWrappedFunction`)。这个包装函数允许在调用者的 Realm 中安全地调用 `ShadowRealm` 中的函数，并确保正确的 Realm 上下文。
    - 如果返回值是不可调用的对象，则抛出一个 `TypeError` 异常，该异常是使用 `ShadowRealm` 的 Realm 的 `TypeError` 构造函数创建的。

**与 JavaScript 功能的关系及示例:**

这个 C++ 文件直接实现了 JavaScript 的 `ShadowRealm` API。`ShadowRealm` 允许你在一个隔离的环境中执行代码，这对于运行不受信任的代码或者避免全局作用域污染非常有用。

**JavaScript 示例:**

```javascript
// 创建一个 ShadowRealm 实例
const realm = new ShadowRealm();

// 在 ShadowRealm 中执行代码
const result = realm.evaluate("1 + 1");
console.log(result); // 输出: 2

// 在 ShadowRealm 中定义一个变量
realm.evaluate("globalThis.x = 10;");

// 尝试从主 Realm 访问 ShadowRealm 中定义的变量，会失败
console.log(globalThis.x); // 输出: undefined

// 在主 Realm 中定义一个函数
function mainRealmFunction() {
  console.log("来自主 Realm 的函数");
}

// 将主 Realm 的函数传递到 ShadowRealm 中并调用
const wrappedFunction = realm.evaluate(`
  const func = (() => { return globalThis.mainRealmFunction; })();
  func;
`);
wrappedFunction(); // 输出: 来自主 Realm 的函数

// 在 ShadowRealm 中定义一个函数
realm.evaluate("globalThis.shadowRealmFunction = () => { console.log('来自 ShadowRealm 的函数'); };");

// 尝试从主 Realm 直接调用 ShadowRealm 中的函数，会报错
// globalThis.shadowRealmFunction(); // 会抛出 TypeError

// 通过 evaluate 返回 ShadowRealm 中的函数并调用
const shadowFunc = realm.evaluate("globalThis.shadowRealmFunction");
shadowFunc(); // 输出: 来自 ShadowRealm 的函数
```

**解释示例:**

- `new ShadowRealm()`:  对应 C++ 中的 `ShadowRealmConstructor`，创建一个新的隔离环境。
- `realm.evaluate("1 + 1")`: 对应 C++ 中的 `ShadowRealmPrototypeEvaluate`，在 `realm` 的隔离环境中执行字符串 "1 + 1"。
- 访问 `globalThis.x` 的行为展示了主 Realm 和 `ShadowRealm` 之间的作用域隔离。
- 将主 Realm 的函数通过 `evaluate` 传递到 `ShadowRealm` 中，并通过返回的包装函数调用，演示了 `GetWrappedValue` 的作用，特别是对于可调用对象的处理。
- 尝试直接访问 `ShadowRealm` 中定义的函数会失败，强调了隔离性。
- 通过 `evaluate` 返回 `ShadowRealm` 中的函数并在主 Realm 中调用，也演示了 `GetWrappedValue` 的作用。

总而言之，`builtins-shadow-realm.cc` 文件是 V8 引擎中实现 `ShadowRealm` 核心功能的关键部分，它负责创建隔离的 JavaScript 执行环境，并在这些环境中安全地执行代码和传递值。

Prompt: 
```
这是目录为v8/src/builtins/builtins-shadow-realm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-utils-inl.h"
#include "src/codegen/compiler.h"
#include "src/logging/counters.h"
#include "src/objects/js-shadow-realm-inl.h"

namespace v8 {
namespace internal {

// https://tc39.es/proposal-shadowrealm/#sec-shadowrealm-constructor
BUILTIN(ShadowRealmConstructor) {
  HandleScope scope(isolate);
  // 1. If NewTarget is undefined, throw a TypeError exception.
  if (IsUndefined(*args.new_target(), isolate)) {  // [[Call]]
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kConstructorNotFunction,
                              isolate->factory()->ShadowRealm_string()));
  }
  // [[Construct]]
  Handle<JSFunction> target = args.target();
  Handle<JSReceiver> new_target = Cast<JSReceiver>(args.new_target());

  // 3. Let realmRec be CreateRealm().
  // 5. Let context be a new execution context.
  // 6. Set the Function of context to null.
  // 7. Set the Realm of context to realmRec.
  // 8. Set the ScriptOrModule of context to null.
  // 10. Perform ? SetRealmGlobalObject(realmRec, undefined, undefined).
  // 11. Perform ? SetDefaultGlobalBindings(O.[[ShadowRealm]]).
  // 12. Perform ? HostInitializeShadowRealm(O.[[ShadowRealm]]).
  // These steps are combined in
  // Isolate::RunHostCreateShadowRealmContextCallback and Context::New.
  // The host operation is hoisted for not creating a half-initialized
  // ShadowRealm object, which can fail the heap verification.
  Handle<NativeContext> native_context;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, native_context,
      isolate->RunHostCreateShadowRealmContextCallback());

  // 2. Let O be ? OrdinaryCreateFromConstructor(NewTarget,
  // "%ShadowRealm.prototype%", « [[ShadowRealm]], [[ExecutionContext]] »).
  Handle<JSObject> result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, result,
      JSObject::New(target, new_target, Handle<AllocationSite>::null()));
  auto O = Cast<JSShadowRealm>(result);

  // 4. Set O.[[ShadowRealm]] to realmRec.
  // 9. Set O.[[ExecutionContext]] to context.
  O->set_native_context(*native_context);

  // 13. Return O.
  return *O;
}

namespace {

// https://tc39.es/proposal-shadowrealm/#sec-getwrappedvalue
MaybeHandle<Object> GetWrappedValue(
    Isolate* isolate, DirectHandle<NativeContext> creation_context,
    Handle<Object> value) {
  // 1. If Type(value) is Object, then
  if (!IsJSReceiver(*value)) {
    // 2. Return value.
    return value;
  }
  // 1a. If IsCallable(value) is false, throw a TypeError exception.
  if (!IsCallable(*value)) {
    // The TypeError thrown is created with creation Realm's TypeError
    // constructor instead of the executing Realm's.
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewError(Handle<JSFunction>(creation_context->type_error_function(),
                                    isolate),
                 MessageTemplate::kNotCallable, value),
        {});
  }
  // 1b. Return ? WrappedFunctionCreate(callerRealm, value).
  return JSWrappedFunction::Create(isolate, creation_context,
                                   Cast<JSReceiver>(value));
}

}  // namespace

// https://tc39.es/proposal-shadowrealm/#sec-shadowrealm.prototype.evaluate
BUILTIN(ShadowRealmPrototypeEvaluate) {
  HandleScope scope(isolate);

  Handle<Object> source_text = args.atOrUndefined(isolate, 1);
  // 1. Let O be this value.
  Handle<Object> receiver = args.receiver();

  Factory* factory = isolate->factory();

  // 2. Perform ? ValidateShadowRealmObject(O).
  if (!IsJSShadowRealm(*receiver)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kIncompatibleMethodReceiver));
  }
  auto shadow_realm = Cast<JSShadowRealm>(receiver);

  // 3. If Type(sourceText) is not String, throw a TypeError exception.
  if (!IsString(*source_text)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewTypeError(MessageTemplate::kInvalidShadowRealmEvaluateSourceText));
  }

  // 4. Let callerRealm be the current Realm Record.
  DirectHandle<NativeContext> caller_context = isolate->native_context();

  // 5. Let evalRealm be O.[[ShadowRealm]].
  Handle<NativeContext> eval_context =
      Handle<NativeContext>(shadow_realm->native_context(), isolate);
  // 6. Return ? PerformShadowRealmEval(sourceText, callerRealm, evalRealm).

  // PerformShadowRealmEval
  // https://tc39.es/proposal-shadowrealm/#sec-performshadowrealmeval
  // 1. Perform ? HostEnsureCanCompileStrings(callerRealm, evalRealm).
  // Run embedder pre-checks before executing the source code.
  MaybeHandle<String> validated_source;
  bool unhandled_object;
  std::tie(validated_source, unhandled_object) =
      Compiler::ValidateDynamicCompilationSource(isolate, eval_context,
                                                 source_text);
  if (unhandled_object) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewTypeError(MessageTemplate::kInvalidShadowRealmEvaluateSourceText));
  }

  Handle<JSObject> eval_global_proxy(eval_context->global_proxy(), isolate);
  MaybeHandle<Object> result;
  bool is_parse_failed = false;
  {
    // 8. If runningContext is not already suspended, suspend runningContext.
    // 9. Let evalContext be a new ECMAScript code execution context.
    // 10. Set evalContext's Function to null.
    // 11. Set evalContext's Realm to evalRealm.
    // 12. Set evalContext's ScriptOrModule to null.
    // 13. Set evalContext's VariableEnvironment to varEnv.
    // 14. Set evalContext's LexicalEnvironment to lexEnv.
    // 15. Set evalContext's PrivateEnvironment to null.
    // 16. Push evalContext onto the execution context stack; evalContext is now
    // the running execution context.
    SaveAndSwitchContext save(isolate, *eval_context);

    // 2. Perform the following substeps in an implementation-defined order,
    // possibly interleaving parsing and error detection:
    // 2a. Let script be ParseText(! StringToCodePoints(sourceText), Script).
    // 2b. If script is a List of errors, throw a SyntaxError exception.
    // 2c. If script Contains ScriptBody is false, return undefined.
    // 2d. Let body be the ScriptBody of script.
    // 2e. If body Contains NewTarget is true, throw a SyntaxError
    // exception.
    // 2f. If body Contains SuperProperty is true, throw a SyntaxError
    // exception.
    // 2g. If body Contains SuperCall is true, throw a SyntaxError exception.
    // 3. Let strictEval be IsStrict of script.
    // 4. Let runningContext be the running execution context.
    // 5. Let lexEnv be NewDeclarativeEnvironment(evalRealm.[[GlobalEnv]]).
    // 6. Let varEnv be evalRealm.[[GlobalEnv]].
    // 7. If strictEval is true, set varEnv to lexEnv.
    Handle<JSFunction> function;
    MaybeHandle<JSFunction> maybe_function =
        Compiler::GetFunctionFromValidatedString(eval_context, validated_source,
                                                 NO_PARSE_RESTRICTION,
                                                 kNoSourcePosition);
    if (maybe_function.is_null()) {
      is_parse_failed = true;
    } else {
      function = maybe_function.ToHandleChecked();

      // 17. Let result be EvalDeclarationInstantiation(body, varEnv,
      // lexEnv, null, strictEval).
      // 18. If result.[[Type]] is normal, then
      // 18a. a. Set result to Completion(Evaluation of body).
      // 19. If result.[[Type]] is normal and result.[[Value]] is empty, then
      // 19a. Set result to NormalCompletion(undefined).
      result =
          Execution::Call(isolate, function, eval_global_proxy, 0, nullptr);

      // 20. Suspend evalContext and remove it from the execution context stack.
      // 21. Resume the context that is now on the top of the execution context
      // stack as the running execution context. Done by the scope.
    }
  }

  if (result.is_null()) {
    DCHECK(isolate->has_exception());
    Handle<Object> exception(isolate->exception(), isolate);
    isolate->clear_internal_exception();
    if (is_parse_failed) {
      auto error_object = Cast<JSObject>(exception);
      auto message = Cast<String>(JSReceiver::GetDataProperty(
          isolate, error_object, factory->message_string()));

      return isolate->ReThrow(
          *factory->NewError(isolate->syntax_error_function(), message));
    }
    // 22. If result.[[Type]] is not NORMAL, then
    // 22a. Let copiedError be CreateTypeErrorCopy(callerRealm,
    // result.[[Value]]). 22b. Return ThrowCompletion(copiedError).
    DirectHandle<String> string =
        Object::NoSideEffectsToString(isolate, exception);
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        ShadowRealmNewTypeErrorCopy(
            exception, MessageTemplate::kCallShadowRealmEvaluateThrew, string));
  }
  // 23. Return ? GetWrappedValue(callerRealm, result.[[Value]]).
  Handle<Object> wrapped_result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, wrapped_result,
      GetWrappedValue(isolate, caller_context, result.ToHandleChecked()));
  return *wrapped_result;
}

}  // namespace internal
}  // namespace v8

"""

```