Response:
Let's break down the thought process for analyzing this V8 code.

1. **Understand the Request:** The primary goal is to describe the functionality of the provided C++ code, which is part of V8, specifically related to `ShadowRealm`. The request also highlights key aspects to look for: connection to JavaScript, potential Torque origins, code logic/input-output, and common user errors.

2. **Initial Scan and Keywords:**  I'd first scan the code for prominent keywords and structures. "ShadowRealm", "builtins", "assembler", "importValue", "WrappedFunction", "Context", "Promise",  `TF_BUILTIN`, and the copyright notice are immediate giveaways. The inclusion of headers like  `builtins-utils-gen.h`, `code-stub-assembler-inl.h`, and `js-shadow-realm.h` reinforces that this is low-level V8 code dealing with built-in functionality.

3. **Identify the Core Functionality:** The repeated mentions of "ShadowRealm", `ShadowRealmGetWrappedValue`, `CallWrappedFunction`, and `ShadowRealmPrototypeImportValue` strongly suggest that this code implements the core mechanics of the ShadowRealm proposal in JavaScript.

4. **Determine the Code Generation Technique:** The class `ShadowRealmBuiltinsAssembler` inheriting from `CodeStubAssembler` is a clear indicator that this code uses the CodeStubAssembler (CSA) within V8. The request explicitly asks about Torque (`.tq`). While this file is `.cc`, the presence of `CodeStubAssembler` means it's *related* to Torque, which is a higher-level language that often compiles down to CSA code. So, the answer should reflect this connection.

5. **Analyze Individual Functions/Methods:**  I'd then go through each `TF_BUILTIN` and key helper functions:

    * **`ShadowRealmGetWrappedValue`:** The comments and logic clearly indicate this function handles the wrapping of values passed between realms. The checks for primitives, callables, and existing wrapped functions are essential to the wrapping/unwrapping process. The slow-path logic involving `Runtime::kShadowRealmWrappedFunctionCreate` suggests complex cases.

    * **`CallWrappedFunction`:** This is where the actual call to a wrapped function happens. The steps involve unwrapping the target, wrapping arguments, and then making the call in the target realm's context. The error handling (`call_exception`) is important.

    * **`ShadowRealmPrototypeImportValue`:**  This is the entry point for the `importValue` method on `ShadowRealm.prototype`. It validates the receiver and initiates the module import process.

    * **`ImportValue`:** This function manages the asynchronous import of a value from a module within a ShadowRealm. The use of promises and `HostImportModuleDynamically` (via `Runtime::kShadowRealmImportValue`) is key.

    * **`ShadowRealmImportValueFulfilled`:** This handles the successful resolution of the imported module. It retrieves the requested export and wraps it.

    * **`ShadowRealmImportValueRejected`:**  This is the error handler for failed module imports.

    * **Helper Functions (e.g., `AllocateJSWrappedFunction`, `CreateImportValueFulfilledFunctionContext`, `CheckAccessor`, `ShadowRealmThrow`):** These provide supporting logic for object creation, context management, and error handling.

6. **Connect to JavaScript Functionality:**  Now, think about how these low-level operations map to JavaScript.

    * `ShadowRealmGetWrappedValue`:  This directly relates to the concept of values crossing the ShadowRealm boundary and being "wrapped" to prevent direct access or side effects in the originating realm.
    * `CallWrappedFunction`: This corresponds to calling a function that was obtained from another ShadowRealm.
    * `ShadowRealm.prototype.importValue`: This is a direct JavaScript API.

7. **Illustrate with JavaScript Examples:** Create simple JavaScript code snippets that demonstrate the use of `ShadowRealm` and its methods to make the connection concrete. Show wrapping of functions and the `importValue` functionality.

8. **Consider Code Logic and Input/Output:**  For `ShadowRealmGetWrappedValue` and `CallWrappedFunction`, think about different input types (primitive, callable, already wrapped) and the expected output (wrapped value, unwrapped target, error). For `ImportValue`, the input is the module specifier and export name, and the output is a promise.

9. **Identify Common User Errors:** Based on the functionality, think about what mistakes a JavaScript developer might make when using ShadowRealms. Trying to directly access unwrapped values, calling non-callable wrapped values, and incorrect usage of `importValue` are common pitfalls.

10. **Address the Torque Question:** Explicitly state that while this file is C++, it's generated or related to Torque, which is a likely source for such built-in implementations.

11. **Structure the Answer:** Organize the findings logically:

    * Start with a concise summary of the file's purpose.
    * Explain the key functionalities in more detail.
    * Provide the JavaScript examples.
    * Describe the code logic with input/output examples.
    * Discuss common user errors.
    * Address the Torque aspect.

12. **Refine and Review:** Read through the generated answer to ensure clarity, accuracy, and completeness. Check that all parts of the initial request have been addressed. For example, initially, I might have just said "wraps functions," but the explanation needs to be more nuanced, covering the checks for slow-mode functions and accessors.

This systematic approach of scanning, identifying core functions, analyzing details, connecting to JavaScript, and providing examples allows for a comprehensive understanding of the provided V8 source code.
`v8/src/builtins/builtins-shadow-realm-gen.cc` 是 V8 JavaScript 引擎中用于实现 **ShadowRealm** 相关 built-in 函数的 C++ 代码。

**主要功能:**

该文件定义并实现了以下与 ShadowRealm 规范相关的核心功能：

1. **`ShadowRealmGetWrappedValue(creation_context, target_context, value)`:**
   - **功能:**  负责将一个值从一个 Realm (执行上下文) 传递到另一个 Realm (通常是 ShadowRealm) 时进行包装。
   - **JavaScript 关系:**  当需要在 ShadowRealm 和其外部 Realm 之间传递函数或其他对象时，V8 会使用这个 built-in 函数来创建“包装器”。这个包装器允许在另一个 Realm 中安全地调用或使用该值，同时防止直接访问内部状态。
   - **代码逻辑推理:**
     - **输入:**  `creation_context` (创建包装器的 Realm 的上下文), `target_context` (被包装的值所在的 Realm 的上下文), `value` (要包装的值)。
     - **输出:**  被包装后的值 (如果需要包装) 或原始值 (如果是不需要包装的原始类型)。
     - **假设输入:**  在外部 Realm 中有一个函数 `foo`，想在 ShadowRealm 中使用它。
     - **输出:**  `ShadowRealmGetWrappedValue` 会返回一个特殊的包装对象，这个对象在 ShadowRealm 中可以被调用，但它的执行仍然会受到限制，并会桥接到原始的 `foo` 函数。
   - **用户常见编程错误:**  用户无法直接访问或修改被包装对象在原始 Realm 中的状态。试图这样做可能会导致错误或意外行为。 例如，如果一个函数被包装传递到 ShadowRealm，然后在 ShadowRealm 中修改了该函数的属性，这种修改不会反映到原始 Realm 中的函数。

2. **`CallWrappedFunction(wrapped_function, ...args)`:**
   - **功能:**  用于调用被 `ShadowRealmGetWrappedValue` 包装过的函数。
   - **JavaScript 关系:**  当你在 ShadowRealm 中调用一个来自外部 Realm 的包装函数时，V8 会使用这个 built-in 函数。
   - **代码逻辑推理:**
     - **输入:** `wrapped_function` (被包装的函数), `args` (调用参数)。
     - **输出:**  包装函数的执行结果，该结果可能也会被包装后返回到调用方 Realm。
     - **假设输入:**  一个通过 `ShadowRealmGetWrappedValue` 包装并传递到 ShadowRealm 的外部函数 `wrappedFoo`，以及一些参数。
     - **输出:**  `CallWrappedFunction` 会在原始 Realm 的上下文中安全地执行原始函数，并将结果（可能再次包装）返回给 ShadowRealm。
   - **用户常见编程错误:**  用户可能会认为在 ShadowRealm 中调用包装函数会直接在 ShadowRealm 的上下文中执行，但实际上它是在原始 Realm 的上下文中执行的。这会影响到 `this` 的绑定以及访问全局变量等行为。

3. **`ShadowRealmPrototypeImportValue(specifier, exportName)`:**
   - **功能:**  实现 `ShadowRealm.prototype.importValue` 方法，用于从 ShadowRealm 中动态导入模块的特定导出。
   - **JavaScript 关系:**  这是 ShadowRealm API 的一部分，允许 ShadowRealm 安全地访问外部 Realm 的模块。
   - **JavaScript 示例:**
     ```javascript
     const realm = new ShadowRealm();
     realm.importValue('my-module', 'myExport')
       .then(myExport => {
         console.log(myExport);
       });
     ```
   - **代码逻辑推理:**
     - **输入:**  `specifier` (模块标识符), `exportName` (要导入的导出名称)。
     - **输出:**  一个 Promise，该 Promise 在导出成功导入并包装后 resolve，或在导入失败时 reject。
     - **假设输入:**  ShadowRealm 尝试导入外部 Realm 中 `my-module` 模块的 `myExport` 导出。
     - **输出:**  如果导入成功，Promise 会 resolve 为 `myExport` 的包装版本。
   - **用户常见编程错误:**
     - 尝试导入不存在的模块或导出。
     - 期望直接访问导入的值，而忘记了它可能被包装了。
     - 忽略 `importValue` 返回的 Promise，导致异步操作的结果无法被处理。

4. **`ImportValue(caller_context, eval_context, specifier, export_name)`:**
   - **功能:**  `ShadowRealmPrototypeImportValue` 的内部实现，处理模块的动态导入和包装。
   - **代码逻辑推理:**  此函数负责启动模块的动态加载过程，并在加载完成后，获取指定的导出并使用 `ShadowRealmGetWrappedValue` 进行包装。它涉及到 Promise 的创建和链式调用。

5. **`ShadowRealmImportValueFulfilled(exports)`:**
   - **功能:**  当模块导入成功时被调用，负责获取指定的导出并进行包装。
   - **代码逻辑推理:**  接收模块的命名空间对象 (`exports`)，然后根据 `exportName` 获取导出的值，并使用 `ShadowRealmGetWrappedValue` 将其包装后返回。

6. **`ShadowRealmImportValueRejected(exception)`:**
   - **功能:**  当模块导入失败时被调用，处理导入拒绝的情况。
   - **代码逻辑推理:**  接收导入过程中产生的异常，并将其传递给错误处理逻辑。

**关于 `.tq` 后缀:**

如果 `v8/src/builtins/builtins-shadow-realm-gen.cc` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码**。 Torque 是 V8 团队开发的一种领域特定语言 (DSL)，用于更安全、更易于维护地编写 built-in 函数。 Torque 代码会被编译成 C++ 代码，最终被 V8 使用。

**总结:**

`v8/src/builtins/builtins-shadow-realm-gen.cc` (或可能的 `.tq` 版本) 是 V8 引擎中实现 ShadowRealm 功能的关键组成部分。它定义了用于在 Realm 之间安全传递值 (通过包装) 以及从 ShadowRealm 中导入模块导出的 built-in 函数。这些 built-in 函数是 JavaScript 中 `ShadowRealm` API 的底层实现基础。

**用户常见编程错误示例 (JavaScript):**

1. **尝试直接访问包装对象:**
   ```javascript
   const realm = new ShadowRealm();
   const func = () => console.log('hello from outside');
   const wrappedFunc = realm.evaluate(`(${func.toString()})`);
   wrappedFunc(); // 正确，可以调用

   // 假设我们错误地认为可以修改包装函数的属性
   wrappedFunc.someProperty = 123;
   console.log(func.someProperty); // undefined，原始函数不受影响
   ```

2. **在错误的 Realm 中使用值:**
   ```javascript
   const realm = new ShadowRealm();
   let outsideValue = { count: 0 };
   const wrappedValue = realm.evaluate(`(() => ({ value: ${outsideValue.toString()} }))()`);
   console.log(wrappedValue.value); // "[object Object]" -  toString() 被调用，而不是直接引用

   // 正确的做法是使用包装器函数来操作外部值（如果需要）
   const increment = () => outsideValue.count++;
   const wrappedIncrement = realm.evaluate(`(${increment.toString()})`);
   wrappedIncrement();
   console.log(outsideValue.count); // 1
   ```

3. **忘记处理 `importValue` 的 Promise:**
   ```javascript
   const realm = new ShadowRealm();
   realm.importValue('my-module', 'myExport'); // 没有 .then 或 await，可能错过处理结果或错误
   ```

理解 `v8/src/builtins/builtins-shadow-realm-gen.cc` 中的功能对于深入了解 JavaScript 的 ShadowRealm API 以及 V8 引擎的内部工作原理至关重要。

### 提示词
```
这是目录为v8/src/builtins/builtins-shadow-realm-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-shadow-realm-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```