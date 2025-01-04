Response: The user wants a summary of the C++ code in `builtins-shadow-realm-gen.cc`. I need to explain its purpose and how it relates to JavaScript. Specifically, I should provide a JavaScript example if applicable.

Here's a breakdown of the code and its functionality:

1. **Includes:** The file includes necessary V8 headers for built-in functions, code generation, and object manipulation.
2. **Namespace:** It resides within the `v8::internal` namespace.
3. **`ShadowRealmBuiltinsAssembler` class:** This class inherits from `CodeStubAssembler` and provides methods for implementing ShadowRealm-related built-in functions.
4. **`ImportValueFulfilledFunctionContextSlot` enum:** Defines the layout of the context used for the `ImportValueFulfilled` function.
5. **Helper Methods:**
    - `AllocateJSWrappedFunction`: Creates a wrapper object for functions crossing ShadowRealm boundaries.
    - `CreateImportValueFulfilledFunctionContext`: Creates a specialized context for the promise fulfillment handler of `importValue`.
    - `AllocateImportValueFulfilledFunction`: Allocates the function used to handle the successful import of a value.
    - `CheckAccessor`: Checks if a property is an accessor with a specific name.
    - `ShadowRealmThrow`: A helper to throw exceptions specific to ShadowRealms.
    - `ImportValue`: The core logic for handling `importValue` calls in ShadowRealms.
6. **Built-in Functions (using `TF_BUILTIN` macro):**
    - `ShadowRealmGetWrappedValue`:  Handles the wrapping and unwrapping of values when crossing ShadowRealm boundaries. This ensures proper isolation.
    - `CallWrappedFunction`:  Handles calls to functions that have been wrapped when crossing ShadowRealm boundaries.
    - `ShadowRealmPrototypeImportValue`: Implements the `importValue` method on the `ShadowRealm.prototype`.
    - `ShadowRealmImportValueFulfilled`: The fulfillment handler for the promise returned by dynamically importing a value within a ShadowRealm.
    - `ShadowRealmImportValueRejected`: The rejection handler for the promise returned by dynamically importing a value within a ShadowRealm.

**Relationship to JavaScript:**

This C++ code directly implements the behavior of the `ShadowRealm` API in JavaScript. The `ShadowRealm` API allows you to create isolated JavaScript environments. The core functionalities implemented here are:

- **Wrapping/Unwrapping Values:** When you pass values (especially functions) between the main realm and a ShadowRealm, they need to be "wrapped". This wrapping ensures that the ShadowRealm's isolated environment is maintained. `ShadowRealmGetWrappedValue` handles this.
- **Calling Wrapped Functions:** When you call a wrapped function, the call needs to be routed correctly to the original function within its originating realm. `CallWrappedFunction` takes care of this.
- **`importValue`:** This method allows you to import specific exports from modules within a ShadowRealm. The code implements the steps for dynamically importing the module and then retrieving the requested export. The `ImportValueFulfilled` and `ImportValueRejected` functions handle the success and failure cases of this asynchronous operation.

**JavaScript Example:**

I will now create a JavaScript example that demonstrates the functionality implemented in this C++ code.这个C++源代码文件 `builtins-shadow-realm-gen.cc` 实现了 **ShadowRealm** (隔离域) 相关的内置函数。它的主要功能是为 JavaScript 提供创建和操作隔离的全局环境的能力。

**具体功能归纳:**

1. **封装和解封装值 (`ShadowRealmGetWrappedValue`):**  当值需要在主 Realm 和 ShadowRealm 之间传递时，此函数负责将值进行封装或解封装。特别是对于函数，它会创建一个包装器对象，以确保在 ShadowRealm 中调用该函数时，其行为符合隔离的语义。
2. **调用封装函数 (`CallWrappedFunction`):** 当调用一个从主 Realm 传递到 ShadowRealm 的封装函数时，此函数负责处理调用过程，包括正确的 `this` 指向和参数传递，并确保调用发生在原始函数所在的 Realm 中。
3. **`ShadowRealm.prototype.importValue` 的实现 (`ShadowRealmPrototypeImportValue`):**  实现了 `ShadowRealm.prototype.importValue` 方法，允许从 ShadowRealm 中动态导入模块的特定导出。
4. **`importValue` 的核心逻辑 (`ImportValue`):**  处理 `importValue` 的核心流程，包括动态加载模块，并创建 Promise 来处理异步导入的结果。
5. **`importValue` 成功时的处理 (`ShadowRealmImportValueFulfilled`):**  当 `importValue` 成功导入模块时，此函数负责获取指定的导出值，并将其封装后返回给调用方。
6. **`importValue` 失败时的处理 (`ShadowRealmImportValueRejected`):** 当 `importValue` 导入模块失败时，此函数负责抛出相应的错误。
7. **辅助函数:** 提供了一些辅助函数，例如分配封装函数对象 (`AllocateJSWrappedFunction`)，创建特定的上下文 (`CreateImportValueFulfilledFunctionContext`)，检查访问器 (`CheckAccessor`) 和抛出 ShadowRealm 相关的错误 (`ShadowRealmThrow`)。

**与 JavaScript 的关系和示例:**

这个 C++ 文件中的代码是 V8 引擎实现 JavaScript `ShadowRealm` API 的一部分。`ShadowRealm` 允许开发者创建一个新的、隔离的全局对象环境，在这个环境中执行的代码无法直接访问或修改主 Realm 的全局对象和变量，反之亦然。

以下是一个 JavaScript 示例，展示了 `ShadowRealm` 的基本用法以及与 `builtins-shadow-realm-gen.cc` 中功能的关联：

```javascript
const realm = new ShadowRealm();

// 在 ShadowRealm 中执行代码
const result = realm.evaluate('1 + 2');
console.log(result); // 输出: 3

// 在 ShadowRealm 中定义一个函数
realm.evaluate('globalThis.sayHello = function(name) { return "Hello, " + name; }');

// 获取在 ShadowRealm 中定义的函数 (会被封装)
const sayHelloInRealm = realm.globalThis.sayHello;

// 调用封装的函数
const greeting = sayHelloInRealm('World');
console.log(greeting); // 输出: Hello, World

// 导入 ShadowRealm 中的模块导出
async function testImportValue() {
  realm.evaluate('export const message = "Greetings from ShadowRealm";');
  const importedMessage = await realm.importValue('./some-module', 'message'); // 这里假设 './some-module' 在 ShadowRealm 的上下文中
  console.log(importedMessage); // 输出: Greetings from ShadowRealm
}

testImportValue();
```

**解释:**

* **`new ShadowRealm()`:**  在 C++ 中对应于创建 `JSShadowRealm` 对象的代码。
* **`realm.evaluate('...')`:** 在 ShadowRealm 中执行 JavaScript 代码，其执行环境是隔离的。
* **`realm.globalThis.sayHello`:**  访问 ShadowRealm 的全局对象。当从主 Realm 访问 ShadowRealm 的函数时，V8 引擎会使用 `ShadowRealmGetWrappedValue` 创建一个封装函数。
* **`sayHelloInRealm('World')`:** 调用封装的函数，V8 引擎会使用 `CallWrappedFunction` 来处理这个调用，确保调用发生在 ShadowRealm 的环境中。
* **`realm.importValue('./some-module', 'message')`:** 调用 `importValue` 方法，这会触发 `builtins-shadow-realm-gen.cc` 中的 `ShadowRealmPrototypeImportValue` 和 `ImportValue` 函数。如果导入成功，`ShadowRealmImportValueFulfilled` 会被调用，并将封装后的导出值返回。如果失败，则会调用 `ShadowRealmImportValueRejected`。

总而言之，`builtins-shadow-realm-gen.cc` 文件是 V8 引擎中实现 JavaScript `ShadowRealm` API 核心功能的关键部分，它通过 C++ 代码提供了创建隔离环境、封装和调用跨 Realm 的值以及动态导入模块的能力。

Prompt: 
```
这是目录为v8/src/builtins/builtins-shadow-realm-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/objects/descriptor-array.h"
#include "src/objects/js-shadow-realm.h"
#include "src/objects/module.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

class ShadowRealmBuiltinsAssembler : public CodeStubAssembler {
 public:
  explicit ShadowRealmBuiltinsAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  enum ImportValueFulfilledFunctionContextSlot {
    kEvalContextSlot = Context::MIN_CONTEXT_SLOTS,
    kSpecifierSlot,
    kExportNameSlot,
    kContextLength,
  };

 protected:
  TNode<JSObject> AllocateJSWrappedFunction(TNode<Context> context,
                                            TNode<Object> target);
  void CheckAccessor(TNode<DescriptorArray> array, TNode<IntPtrT> index,
                     TNode<Name> name, Label* bailout);
  TNode<Object> ImportValue(TNode<NativeContext> caller_context,
                            TNode<NativeContext> eval_context,
                            TNode<String> specifier, TNode<String> export_name);
  TNode<Context> CreateImportValueFulfilledFunctionContext(
      TNode<NativeContext> caller_context, TNode<NativeContext> eval_context,
      TNode<String> specifier, TNode<String> export_name);
  TNode<JSFunction> AllocateImportValueFulfilledFunction(
      TNode<NativeContext> caller_context, TNode<NativeContext> eval_context,
      TNode<String> specifier, TNode<String> export_name);
  void ShadowRealmThrow(TNode<Context> context,
                        MessageTemplate fallback_message,
                        TNode<Object> exception);
};

TNode<JSObject> ShadowRealmBuiltinsAssembler::AllocateJSWrappedFunction(
    TNode<Context> context, TNode<Object> target) {
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Map> map = CAST(
      LoadContextElement(native_context, Context::WRAPPED_FUNCTION_MAP_INDEX));
  TNode<JSObject> wrapped = AllocateJSObjectFromMap(map);
  StoreObjectFieldNoWriteBarrier(
      wrapped, JSWrappedFunction::kWrappedTargetFunctionOffset, target);
  StoreObjectFieldNoWriteBarrier(wrapped, JSWrappedFunction::kContextOffset,
                                 context);
  return wrapped;
}

TNode<Context>
ShadowRealmBuiltinsAssembler::CreateImportValueFulfilledFunctionContext(
    TNode<NativeContext> caller_context, TNode<NativeContext> eval_context,
    TNode<String> specifier, TNode<String> export_name) {
  const TNode<Context> context = AllocateSyntheticFunctionContext(
      caller_context, ImportValueFulfilledFunctionContextSlot::kContextLength);
  StoreContextElementNoWriteBarrier(
      context, ImportValueFulfilledFunctionContextSlot::kEvalContextSlot,
      eval_context);
  StoreContextElementNoWriteBarrier(
      context, ImportValueFulfilledFunctionContextSlot::kSpecifierSlot,
      specifier);
  StoreContextElementNoWriteBarrier(
      context, ImportValueFulfilledFunctionContextSlot::kExportNameSlot,
      export_name);
  return context;
}

TNode<JSFunction>
ShadowRealmBuiltinsAssembler::AllocateImportValueFulfilledFunction(
    TNode<NativeContext> caller_context, TNode<NativeContext> eval_context,
    TNode<String> specifier, TNode<String> export_name) {
  const TNode<Context> function_context =
      CreateImportValueFulfilledFunctionContext(caller_context, eval_context,
                                                specifier, export_name);
  return AllocateRootFunctionWithContext(
      RootIndex::kShadowRealmImportValueFulfilledSharedFun, function_context,
      {});
}

void ShadowRealmBuiltinsAssembler::CheckAccessor(TNode<DescriptorArray> array,
                                                 TNode<IntPtrT> index,
                                                 TNode<Name> name,
                                                 Label* bailout) {
  TNode<Name> key = LoadKeyByDescriptorEntry(array, index);
  GotoIfNot(TaggedEqual(key, name), bailout);
  TNode<Object> value = LoadValueByDescriptorEntry(array, index);
  GotoIfNot(IsAccessorInfo(CAST(value)), bailout);
}

void ShadowRealmBuiltinsAssembler::ShadowRealmThrow(
    TNode<Context> context, MessageTemplate fallback_message,
    TNode<Object> exception) {
  TNode<Smi> template_index = SmiConstant(static_cast<int>(fallback_message));
  CallRuntime(Runtime::kShadowRealmThrow, context, template_index, exception);
  Unreachable();
}

// https://tc39.es/proposal-shadowrealm/#sec-getwrappedvalue
TF_BUILTIN(ShadowRealmGetWrappedValue, ShadowRealmBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto creation_context = Parameter<Context>(Descriptor::kCreationContext);
  auto target_context = Parameter<Context>(Descriptor::kTargetContext);
  auto value = Parameter<Object>(Descriptor::kValue);

  Label if_primitive(this), if_callable(this), unwrap(this), wrap(this),
      slow_wrap(this, Label::kDeferred), bailout(this, Label::kDeferred);

  // 2. Return value.
  GotoIf(TaggedIsSmi(value), &if_primitive);
  GotoIfNot(JSAnyIsNotPrimitive(CAST(value)), &if_primitive);

  // 1. If Type(value) is Object, then
  // 1a. If IsCallable(value) is false, throw a TypeError exception.
  // 1b. Return ? WrappedFunctionCreate(callerRealm, value).
  Branch(IsCallable(CAST(value)), &if_callable, &bailout);

  BIND(&if_primitive);
  Return(value);

  BIND(&if_callable);
  TVARIABLE(Object, target);
  target = value;
  // WrappedFunctionCreate
  // https://tc39.es/proposal-shadowrealm/#sec-wrappedfunctioncreate
  Branch(IsJSWrappedFunction(CAST(value)), &unwrap, &wrap);

  BIND(&unwrap);
  // The intermediate wrapped functions are not user-visible. And calling a
  // wrapped function won't cause a side effect in the creation realm.
  // Unwrap here to avoid nested unwrapping at the call site.
  TNode<JSWrappedFunction> target_wrapped_function = CAST(value);
  target = LoadObjectField(target_wrapped_function,
                           JSWrappedFunction::kWrappedTargetFunctionOffset);
  Goto(&wrap);

  BIND(&wrap);
  // Disallow wrapping of slow-mode functions. We need to figure out
  // whether the length and name property are in the original state.
  TNode<Map> map = LoadMap(CAST(target.value()));
  GotoIf(IsDictionaryMap(map), &slow_wrap);

  // Check whether the length and name properties are still present as
  // AccessorInfo objects. If so, their value can be recomputed even if
  // the actual value on the object changes.
  TNode<Uint32T> bit_field3 = LoadMapBitField3(map);
  TNode<IntPtrT> number_of_own_descriptors = Signed(
      DecodeWordFromWord32<Map::Bits3::NumberOfOwnDescriptorsBits>(bit_field3));
  GotoIf(IntPtrLessThan(
             number_of_own_descriptors,
             IntPtrConstant(JSFunction::kMinDescriptorsForFastBindAndWrap)),
         &slow_wrap);

  // We don't need to check the exact accessor here because the only case
  // custom accessor arise is with function templates via API, and in that
  // case the object is in dictionary mode
  TNode<DescriptorArray> descriptors = LoadMapInstanceDescriptors(map);
  CheckAccessor(
      descriptors,
      IntPtrConstant(
          JSFunctionOrBoundFunctionOrWrappedFunction::kLengthDescriptorIndex),
      LengthStringConstant(), &slow_wrap);
  CheckAccessor(
      descriptors,
      IntPtrConstant(
          JSFunctionOrBoundFunctionOrWrappedFunction::kNameDescriptorIndex),
      NameStringConstant(), &slow_wrap);

  // Verify that prototype matches the function prototype of the target
  // context.
  TNode<Object> prototype = LoadMapPrototype(map);
  TNode<Object> function_map =
      LoadContextElement(target_context, Context::WRAPPED_FUNCTION_MAP_INDEX);
  TNode<Object> function_prototype = LoadMapPrototype(CAST(function_map));
  GotoIf(TaggedNotEqual(prototype, function_prototype), &slow_wrap);

  // 1. Let internalSlotsList be the internal slots listed in Table 2, plus
  // [[Prototype]] and [[Extensible]].
  // 2. Let wrapped be ! MakeBasicObject(internalSlotsList).
  // 3. Set wrapped.[[Prototype]] to
  // callerRealm.[[Intrinsics]].[[%Function.prototype%]].
  // 4. Set wrapped.[[Call]] as described in 2.1.
  // 5. Set wrapped.[[WrappedTargetFunction]] to Target.
  // 6. Set wrapped.[[Realm]] to callerRealm.
  // 7. Let result be CopyNameAndLength(wrapped, Target, "wrapped").
  // 8. If result is an Abrupt Completion, throw a TypeError exception.
  // Installed with default accessors.
  TNode<JSObject> wrapped =
      AllocateJSWrappedFunction(creation_context, target.value());

  // 9. Return wrapped.
  Return(wrapped);

  BIND(&slow_wrap);
  {
    Return(CallRuntime(Runtime::kShadowRealmWrappedFunctionCreate, context,
                       creation_context, target.value()));
  }

  BIND(&bailout);
  ThrowTypeError(context, MessageTemplate::kNotCallable, value);
}

// https://tc39.es/proposal-shadowrealm/#sec-wrapped-function-exotic-objects-call-thisargument-argumentslist
TF_BUILTIN(CallWrappedFunction, ShadowRealmBuiltinsAssembler) {
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  TNode<IntPtrT> argc_ptr = ChangeInt32ToIntPtr(argc);
  auto wrapped_function = Parameter<JSWrappedFunction>(Descriptor::kFunction);
  auto context = Parameter<Context>(Descriptor::kContext);

  PerformStackCheck(context);

  Label call_exception(this, Label::kDeferred),
      target_not_callable(this, Label::kDeferred);

  // 1. Let target be F.[[WrappedTargetFunction]].
  TNode<JSReceiver> target = CAST(LoadObjectField(
      wrapped_function, JSWrappedFunction::kWrappedTargetFunctionOffset));
  // 2. Assert: IsCallable(target) is true.
  CSA_DCHECK(this, IsCallable(target));

  // 4. Let callerRealm be ? GetFunctionRealm(F).
  TNode<Context> caller_context = LoadObjectField<Context>(
      wrapped_function, JSWrappedFunction::kContextOffset);
  // 3. Let targetRealm be ? GetFunctionRealm(target).
  TNode<Context> target_context =
      GetFunctionRealm(caller_context, target, &target_not_callable);
  // 5. NOTE: Any exception objects produced after this point are associated
  // with callerRealm.

  CodeStubArguments args(this, argc_ptr);
  TNode<Object> receiver = args.GetReceiver();

  // 6. Let wrappedArgs be a new empty List.
  TNode<FixedArray> wrapped_args =
      CAST(AllocateFixedArray(ElementsKind::PACKED_ELEMENTS, argc_ptr));
  // Fill the fixed array so that heap verifier doesn't complain about it.
  FillFixedArrayWithValue(ElementsKind::PACKED_ELEMENTS, wrapped_args,
                          IntPtrConstant(0), argc_ptr,
                          RootIndex::kUndefinedValue);

  // 8. Let wrappedThisArgument to ? GetWrappedValue(targetRealm, thisArgument).
  // Create wrapped value in the target realm.
  TNode<Object> wrapped_receiver =
      CallBuiltin(Builtin::kShadowRealmGetWrappedValue, caller_context,
                  target_context, caller_context, receiver);
  StoreFixedArrayElement(wrapped_args, 0, wrapped_receiver);
  // 7. For each element arg of argumentsList, do
  BuildFastLoop<IntPtrT>(
      IntPtrConstant(0), args.GetLengthWithoutReceiver(),
      [&](TNode<IntPtrT> index) {
        // 7a. Let wrappedValue be ? GetWrappedValue(targetRealm, arg).
        // Create wrapped value in the target realm.
        TNode<Object> wrapped_value =
            CallBuiltin(Builtin::kShadowRealmGetWrappedValue, caller_context,
                        target_context, caller_context, args.AtIndex(index));
        // 7b. Append wrappedValue to wrappedArgs.
        StoreFixedArrayElement(
            wrapped_args, IntPtrAdd(index, IntPtrConstant(1)), wrapped_value);
      },
      1, LoopUnrollingMode::kNo, IndexAdvanceMode::kPost);

  TVARIABLE(Object, var_exception);
  TNode<Object> result;
  {
    compiler::ScopedExceptionHandler handler(this, &call_exception,
                                             &var_exception);
    TNode<Int32T> args_count = Int32Constant(0);  // args already on the stack

    // 9. Let result be the Completion Record of Call(target,
    // wrappedThisArgument, wrappedArgs).
    result = CallBuiltin(Builtin::kCallVarargs, target_context, target,
                         args_count, argc, wrapped_args);
  }

  // 10. If result.[[Type]] is normal or result.[[Type]] is return, then
  // 10a. Return ? GetWrappedValue(callerRealm, result.[[Value]]).
  TNode<Object> wrapped_result =
      CallBuiltin(Builtin::kShadowRealmGetWrappedValue, caller_context,
                  caller_context, target_context, result);
  args.PopAndReturn(wrapped_result);

  // 11. Else,
  BIND(&call_exception);
  // 11a. Throw a TypeError exception.
  ShadowRealmThrow(context, MessageTemplate::kCallWrappedFunctionThrew,
                   var_exception.value());

  BIND(&target_not_callable);
  // A wrapped value should not be non-callable.
  Unreachable();
}

// https://tc39.es/proposal-shadowrealm/#sec-shadowrealm.prototype.importvalue
TF_BUILTIN(ShadowRealmPrototypeImportValue, ShadowRealmBuiltinsAssembler) {
  const char* const kMethodName = "ShadowRealm.prototype.importValue";
  TNode<Context> context = Parameter<Context>(Descriptor::kContext);
  // 1. Let O be this value.
  TNode<Object> O = Parameter<Object>(Descriptor::kReceiver);
  // 2. Perform ? ValidateShadowRealmObject(O).
  ThrowIfNotInstanceType(context, O, JS_SHADOW_REALM_TYPE, kMethodName);

  // 3. Let specifierString be ? ToString(specifier).
  TNode<Object> specifier = Parameter<Object>(Descriptor::kSpecifier);
  TNode<String> specifier_string = ToString_Inline(context, specifier);
  // 4. Let exportNameString be ? ToString(exportName).
  TNode<Object> export_name = Parameter<Object>(Descriptor::kExportName);
  TNode<String> export_name_string = ToString_Inline(context, export_name);
  // 5. Let callerRealm be the current Realm Record.
  TNode<NativeContext> caller_context = LoadNativeContext(context);
  // 6. Let evalRealm be O.[[ShadowRealm]].
  // 7. Let evalContext be O.[[ExecutionContext]].
  TNode<NativeContext> eval_context =
      CAST(LoadObjectField(CAST(O), JSShadowRealm::kNativeContextOffset));
  // 8. Return ? ShadowRealmImportValue(specifierString, exportNameString,
  // callerRealm, evalRealm, evalContext).
  TNode<Object> result = ImportValue(caller_context, eval_context,
                                     specifier_string, export_name_string);
  Return(result);
}

// https://tc39.es/proposal-shadowrealm/#sec-shadowrealmimportvalue
TNode<Object> ShadowRealmBuiltinsAssembler::ImportValue(
    TNode<NativeContext> caller_context, TNode<NativeContext> eval_context,
    TNode<String> specifier, TNode<String> export_name) {
  // 1. Assert: evalContext is an execution context associated to a ShadowRealm
  // instance's [[ExecutionContext]].
  // 2. Let innerCapability be ! NewPromiseCapability(%Promise%).
  // 3. Let runningContext be the running execution context.
  // 4. If runningContext is not already suspended, suspend runningContext.
  // 5. Push evalContext onto the execution context stack; evalContext is now
  // the running execution context.
  // 6. Perform ! HostImportModuleDynamically(null, specifierString,
  // innerCapability).
  // 7. Suspend evalContext and remove it from the execution context stack.
  // 8. Resume the context that is now on the top of the execution context stack
  // as the running execution context.
  TNode<Object> inner_capability =
      CallRuntime(Runtime::kShadowRealmImportValue, eval_context, specifier);

  // 9. Let steps be the steps of an ExportGetter function as described below.
  // 10. Let onFulfilled be ! CreateBuiltinFunction(steps, 1, "", «
  // [[ExportNameString]] », callerRealm).
  // 11. Set onFulfilled.[[ExportNameString]] to exportNameString.
  TNode<JSFunction> on_fulfilled = AllocateImportValueFulfilledFunction(
      caller_context, eval_context, specifier, export_name);

  TNode<JSFunction> on_rejected = CAST(LoadContextElement(
      caller_context, Context::SHADOW_REALM_IMPORT_VALUE_REJECTED_INDEX));
  // 12. Let promiseCapability be ! NewPromiseCapability(%Promise%).
  TNode<JSPromise> promise = NewJSPromise(caller_context);
  // 13. Return ! PerformPromiseThen(innerCapability.[[Promise]], onFulfilled,
  // callerRealm.[[Intrinsics]].[[%ThrowTypeError%]], promiseCapability).
  return CallBuiltin(Builtin::kPerformPromiseThen, caller_context,
                     inner_capability, on_fulfilled, on_rejected, promise);
}

// ExportGetter of
// https://tc39.es/proposal-shadowrealm/#sec-shadowrealmimportvalue
TF_BUILTIN(ShadowRealmImportValueFulfilled, ShadowRealmBuiltinsAssembler) {
  // An ExportGetter function is an anonymous built-in function with a
  // [[ExportNameString]] internal slot. When an ExportGetter function is called
  // with argument exports, it performs the following steps:
  // 8. Let realm be f.[[Realm]].
  TNode<Context> context = Parameter<Context>(Descriptor::kContext);
  TNode<Context> eval_context = CAST(LoadContextElement(
      context, ImportValueFulfilledFunctionContextSlot::kEvalContextSlot));

  Label get_export_exception(this, Label::kDeferred);

  // 2. Let f be the active function object.
  // 3. Let string be f.[[ExportNameString]].
  // 4. Assert: Type(string) is String.
  TNode<String> export_name_string = CAST(LoadContextElement(
      context, ImportValueFulfilledFunctionContextSlot::kExportNameSlot));

  // 1. Assert: exports is a module namespace exotic object.
  TNode<JSModuleNamespace> exports =
      Parameter<JSModuleNamespace>(Descriptor::kExports);

  // 5. Let hasOwn be ? HasOwnProperty(exports, string).
  // 6. If hasOwn is false, throw a TypeError exception.
  // 7. Let value be ? Get(exports, string).

  // The only exceptions thrown by Runtime::kGetModuleNamespaceExport are
  // either the export is not found or the module is not initialized.
  TVARIABLE(Object, var_exception);
  TNode<Object> value;
  {
    compiler::ScopedExceptionHandler handler(this, &get_export_exception,
                                             &var_exception);
    value = CallRuntime(Runtime::kGetModuleNamespaceExport, eval_context,
                        exports, export_name_string);
  }

  // 9. Return ? GetWrappedValue(realm, value).
  TNode<NativeContext> caller_context = LoadNativeContext(context);
  TNode<Object> wrapped_result =
      CallBuiltin(Builtin::kShadowRealmGetWrappedValue, caller_context,
                  caller_context, eval_context, value);
  Return(wrapped_result);

  BIND(&get_export_exception);
  {
    TNode<String> specifier_string = CAST(LoadContextElement(
        context, ImportValueFulfilledFunctionContextSlot::kSpecifierSlot));
    ThrowTypeError(context, MessageTemplate::kUnresolvableExport,
                   specifier_string, export_name_string);
  }
}

TF_BUILTIN(ShadowRealmImportValueRejected, ShadowRealmBuiltinsAssembler) {
  TNode<Context> context = Parameter<Context>(Descriptor::kContext);
  TNode<Object> exception = Parameter<Object>(Descriptor::kException);
  ShadowRealmThrow(context, MessageTemplate::kImportShadowRealmRejected,
                   exception);
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8

"""

```