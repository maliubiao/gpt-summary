Response: The user wants a summary of the C++ code provided, focusing on its function and relation to JavaScript. Since this is part 5 of 6, it implies the code handles a specific set of functionalities within the larger bootstrapping process.

Looking at the code, it seems to primarily focus on:

1. **Setting up prototypes and constructors for various built-in JavaScript objects**: This includes iterators, sets, promises, atomics, shadow realms, shared structures/arrays, disposable stacks, and typed arrays (Float16Array).
2. **Installing specific methods and properties on these prototypes**:  Examples include `next`, `return`, `reduce`, `toArray` on iterator prototypes, and methods for set operations like `union`, `intersection`, etc.
3. **Handling experimental or harmony features**: The code is gated by flags like `v8_flags.harmony_set_methods`, `v8_flags.harmony_shadow_realm`, etc., indicating the initialization of features not yet standard in JavaScript.
4. **Interacting with the V8 engine's internals**:  The code uses `isolate()`, `factory()`, `native_context()`, and concepts like `Map`, `Builtin`, and `SimpleInstallFunction`, which are internal to V8.

To explain the connection to JavaScript, I should pick a specific example from the code and show how it manifests in JavaScript. The iterator helpers seem like a good choice.

**Plan:**

1. Summarize the main functionalities observed in the code.
2. Explain the relation to JavaScript using the iterator helper functions as an example.
3. Provide a JavaScript code snippet demonstrating the usage of one of the iterator helper methods.
这是 `v8/src/init/bootstrapper.cc` 文件的第五部分，主要负责初始化和配置 JavaScript 的内置对象和功能，特别是与 **迭代器 (Iterators)**、**集合 (Sets)**、**Promise**、**Atomics**、**ShadowRealm**、**共享结构 (SharedStruct)**、**一次性堆栈 (DisposableStack)** 和 **类型化数组 (Typed Arrays)** 相关的原型和方法。 它还处理一些实验性的或处于提案阶段的 JavaScript 特性。

**主要功能归纳:**

1. **初始化迭代器相关的原型和帮助器:**
   - 设置 `%IteratorPrototype%`，并为其安装标准的方法，如 `reduce`, `toArray`, `forEach`, `some`, `every`, `find`。
   - 创建 `%IteratorHelperPrototype%` 作为迭代器帮助器的基础原型。
   - 根据宏定义 (`INSTALL_ITERATOR_HELPER` 和 `ITERATOR_HELPERS`)，为迭代器原型安装各种帮助方法，如 `map`, `filter`, `take`, `drop`, `flatMap`。这些帮助方法返回新的迭代器，允许链式调用进行数据处理。

2. **初始化其他全局对象和特性:**
   - 如果启用了相应的标志，则初始化 `Atomics.pause` 方法。
   - 如果启用了相应的标志，则初始化 `Promise.try` 方法。
   - 如果启用了相应的标志，则为 `Set.prototype` 安装集合操作方法，如 `union`, `intersection`, `difference` 等。
   - 如果启用了相应的标志，则初始化 `ShadowRealm` 及其原型上的 `evaluate` 和 `importValue` 方法。同时设置 `WrappedFunction` 的 Map。
   - 如果启用了相应的标志，则初始化与 `SharedStructType`, `SharedArray`, `Atomics.Mutex`, `Atomics.Condition` 相关的构造函数和方法，用于支持共享内存并发编程。
   - 初始化 `SharedArrayBuffer` 构造函数。
   - 如果启用了相应的标志，则为 `FinalizationRegistry.prototype` 添加 `cleanupSome` 方法。
   - 如果启用了相应的标志，则初始化 `DisposableStack` 和 `AsyncDisposableStack` 构造函数及其原型上的方法，用于管理资源的生命周期。
   - 如果启用了相应的标志，则初始化 `Float16Array` 构造函数，以及 `Math.f16round` 和 `DataView` 上操作 Float16 的方法。
   - 如果启用了相应的标志，则初始化 `%AbstractModuleSource%` 相关的函数和原型，用于处理模块的源代码阶段导入。
   - 如果启用了相应的标志，则为 `RegExp.prototype` 添加 `linear` getter。
   - 如果启用了相应的标志，则设置 `Temporal` 对象的惰性初始化。

3. **创建 `ArrayBuffer` 构造函数:**
   - 创建 `ArrayBuffer` 和 `SharedArrayBuffer` 构造函数及其原型，并安装相关方法，如 `isView`, `byteLength` getter 和 `slice` 方法。

**与 JavaScript 的功能关系 (以迭代器帮助器为例):**

这段 C++ 代码直接负责实现 JavaScript 中迭代器帮助器 (Iterator Helpers) 的底层逻辑。当你在 JavaScript 中使用 `map`, `filter` 等迭代器方法时，V8 引擎会调用这里定义的 C++ 代码来执行相应的操作。

**JavaScript 示例:**

```javascript
const numbers = [1, 2, 3, 4, 5];

// 使用 Array 的迭代器
const doubledArray = numbers.map(x => x * 2);
console.log(doubledArray); // 输出: [2, 4, 6, 8, 10]

// 使用 Set 的迭代器和迭代器帮助器 (需要浏览器或 Node.js 版本支持)
const numberSet = new Set(numbers);
const evenNumbersIterator = numberSet.values().filter(x => x % 2 === 0);

// 将迭代器转换为数组来查看结果
const evenNumbersArray = [...evenNumbersIterator];
console.log(evenNumbersArray); // 输出: [2, 4]

// 使用 take 帮助器获取前两个偶数
const firstTwoEvenNumbers = numberSet.values().filter(x => x % 2 === 0).take(2);
console.log([...firstTwoEvenNumbers]); // 输出: [2, 4]

// 使用 reduce 帮助器计算所有奇数的和
const oddSum = numberSet.values().filter(x => x % 2 !== 0).reduce((sum, num) => sum + num, 0);
console.log(oddSum); // 输出: 9
```

在这个 JavaScript 例子中：

- `numbers.map(x => x * 2)` 使用了数组的 `map` 方法，它不是这里定义的迭代器帮助器，但概念类似。
- `numberSet.values().filter(x => x % 2 === 0)` 使用了 `Set` 的迭代器 (`values()`)，然后尝试使用 `filter` 迭代器帮助器。这里的 `filter` 对应于 C++ 代码中 `Builtin::kIteratorPrototypeFilter` 的实现。
- `take`, `reduce` 等方法也是类似的，它们在 JavaScript 中的调用最终会映射到这段 C++ 代码中定义的内置函数。

**总结:**

这段 C++ 代码是 V8 引擎初始化 JavaScript 运行环境的关键部分，它负责构建和配置许多重要的内置对象和功能，使得 JavaScript 代码能够使用迭代器、集合、Promise 等现代语言特性。 尤其是关于迭代器帮助器的部分，它为 JavaScript 开发者提供了更方便和强大的数据处理能力。

### 提示词
```
这是目录为v8/src/init/bootstrapper.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```
wrap_for_valid_iterator_prototype);
  valid_iterator_wrapper_map->SetConstructor(*iterator_function);
  native_context()->set_valid_iterator_wrapper_map(*valid_iterator_wrapper_map);
  LOG(isolate(), MapDetails(*valid_iterator_wrapper_map));

  // --- %IteratorHelperPrototype%
  Handle<JSObject> iterator_helper_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);
  JSObject::ForceSetPrototype(isolate(), iterator_helper_prototype,
                              iterator_prototype);
  InstallToStringTag(isolate(), iterator_helper_prototype, "Iterator Helper");
  SimpleInstallFunction(isolate(), iterator_helper_prototype, "next",
                        Builtin::kIteratorHelperPrototypeNext, 0, kAdapt);
  SimpleInstallFunction(isolate(), iterator_helper_prototype, "return",
                        Builtin::kIteratorHelperPrototypeReturn, 0, kAdapt);
  SimpleInstallFunction(isolate(), iterator_prototype, "reduce",
                        Builtin::kIteratorPrototypeReduce, 1, kDontAdapt);
  SimpleInstallFunction(isolate(), iterator_prototype, "toArray",
                        Builtin::kIteratorPrototypeToArray, 0, kAdapt);
  SimpleInstallFunction(isolate(), iterator_prototype, "forEach",
                        Builtin::kIteratorPrototypeForEach, 1, kAdapt);
  SimpleInstallFunction(isolate(), iterator_prototype, "some",
                        Builtin::kIteratorPrototypeSome, 1, kAdapt);
  SimpleInstallFunction(isolate(), iterator_prototype, "every",
                        Builtin::kIteratorPrototypeEvery, 1, kAdapt);
  SimpleInstallFunction(isolate(), iterator_prototype, "find",
                        Builtin::kIteratorPrototypeFind, 1, kAdapt);

  // https://github.com/tc39/proposal-iterator-helpers/pull/287
  SimpleInstallGetterSetter(isolate(), iterator_prototype,
                            isolate()->factory()->to_string_tag_symbol(),
                            Builtin::kIteratorPrototypeGetToStringTag,
                            Builtin::kIteratorPrototypeSetToStringTag);

  SimpleInstallGetterSetter(isolate(), iterator_prototype,
                            isolate()->factory()->constructor_string(),
                            Builtin::kIteratorPrototypeGetConstructor,
                            Builtin::kIteratorPrototypeSetConstructor);

  // --- Helper maps
#define INSTALL_ITERATOR_HELPER(lowercase_name, Capitalized_name,              \
                                ALL_CAPS_NAME, argc)                           \
  {                                                                            \
    DirectHandle<Map> map = factory()->NewContextfulMapForCurrentContext(      \
        JS_ITERATOR_##ALL_CAPS_NAME##_HELPER_TYPE,                             \
        JSIterator##Capitalized_name##Helper::kHeaderSize,                     \
        TERMINAL_FAST_ELEMENTS_KIND, 0);                                       \
    Map::SetPrototype(isolate(), map, iterator_helper_prototype);              \
    map->SetConstructor(*iterator_function);                                   \
    native_context()->set_iterator_##lowercase_name##_helper_map(*map);        \
    LOG(isolate(), MapDetails(*map));                                          \
    SimpleInstallFunction(isolate(), iterator_prototype, #lowercase_name,      \
                          Builtin::kIteratorPrototype##Capitalized_name, argc, \
                          kAdapt);                                             \
  }

#define ITERATOR_HELPERS(V)    \
  V(map, Map, MAP, 1)          \
  V(filter, Filter, FILTER, 1) \
  V(take, Take, TAKE, 1)       \
  V(drop, Drop, DROP, 1)       \
  V(flatMap, FlatMap, FLAT_MAP, 1)

  ITERATOR_HELPERS(INSTALL_ITERATOR_HELPER)

#undef INSTALL_ITERATOR_HELPER
#undef ITERATOR_HELPERS
}

void Genesis::InitializeGlobal_js_atomics_pause() {
  if (!v8_flags.js_atomics_pause) return;
  Handle<JSGlobalObject> global(native_context()->global_object(), isolate());
  Handle<JSObject> atomics_object = Cast<JSObject>(
      JSReceiver::GetProperty(isolate(), global, "Atomics").ToHandleChecked());
  InstallFunctionWithBuiltinId(isolate(), atomics_object, "pause",
                               Builtin::kAtomicsPause, 0, kDontAdapt);
}

void Genesis::InitializeGlobal_js_promise_try() {
  if (!v8_flags.js_promise_try) return;
  Handle<JSFunction> promise_fun =
      handle(native_context()->promise_function(), isolate());
  InstallFunctionWithBuiltinId(isolate(), promise_fun, "try",
                               Builtin::kPromiseTry, 1, kDontAdapt);
}

void Genesis::InitializeGlobal_harmony_set_methods() {
  if (!v8_flags.harmony_set_methods) return;

  Handle<JSObject> set_prototype(native_context()->initial_set_prototype(),
                                 isolate());
  SimpleInstallFunction(isolate(), set_prototype, "union",
                        Builtin::kSetPrototypeUnion, 1, kAdapt);
  SimpleInstallFunction(isolate(), set_prototype, "intersection",
                        Builtin::kSetPrototypeIntersection, 1, kAdapt);
  SimpleInstallFunction(isolate(), set_prototype, "difference",
                        Builtin::kSetPrototypeDifference, 1, kAdapt);
  SimpleInstallFunction(isolate(), set_prototype, "symmetricDifference",
                        Builtin::kSetPrototypeSymmetricDifference, 1, kAdapt);
  SimpleInstallFunction(isolate(), set_prototype, "isSubsetOf",
                        Builtin::kSetPrototypeIsSubsetOf, 1, kAdapt);
  SimpleInstallFunction(isolate(), set_prototype, "isSupersetOf",
                        Builtin::kSetPrototypeIsSupersetOf, 1, kAdapt);
  SimpleInstallFunction(isolate(), set_prototype, "isDisjointFrom",
                        Builtin::kSetPrototypeIsDisjointFrom, 1, kAdapt);

  // The fast path in the Set constructor builtin checks for Set.prototype
  // having been modified from its initial state. So, after adding new methods,
  // we should reset the Set.prototype initial map.
  native_context()->set_initial_set_prototype_map(set_prototype->map());
}

void Genesis::InitializeGlobal_harmony_shadow_realm() {
  if (!v8_flags.harmony_shadow_realm) return;
  Factory* factory = isolate()->factory();
  // -- S h a d o w R e a l m
  // #sec-shadowrealm-objects
  Handle<JSGlobalObject> global(native_context()->global_object(), isolate());
  DirectHandle<JSFunction> shadow_realm_fun =
      InstallFunction(isolate_, global, "ShadowRealm", JS_SHADOW_REALM_TYPE,
                      JSShadowRealm::kHeaderSize, 0, factory->the_hole_value(),
                      Builtin::kShadowRealmConstructor, 0, kDontAdapt);

  // Setup %ShadowRealmPrototype%.
  Handle<JSObject> prototype(
      Cast<JSObject>(shadow_realm_fun->instance_prototype()), isolate());

  InstallToStringTag(isolate_, prototype, factory->ShadowRealm_string());

  SimpleInstallFunction(isolate_, prototype, "evaluate",
                        Builtin::kShadowRealmPrototypeEvaluate, 1, kAdapt);
  SimpleInstallFunction(isolate_, prototype, "importValue",
                        Builtin::kShadowRealmPrototypeImportValue, 2, kAdapt);

  {  // --- W r a p p e d F u n c t i o n
    DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_WRAPPED_FUNCTION_TYPE, JSWrappedFunction::kHeaderSize,
        TERMINAL_FAST_ELEMENTS_KIND, 0);
    map->SetConstructor(native_context()->object_function());
    map->set_is_callable(true);
    Handle<JSObject> empty_function(native_context()->function_prototype(),
                                    isolate());
    Map::SetPrototype(isolate(), map, empty_function);

    PropertyAttributes roc_attribs =
        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY);
    Map::EnsureDescriptorSlack(isolate_, map, 2);
    {  // length
      static_assert(
          JSFunctionOrBoundFunctionOrWrappedFunction::kLengthDescriptorIndex ==
          0);
      Descriptor d = Descriptor::AccessorConstant(
          factory->length_string(), factory->wrapped_function_length_accessor(),
          roc_attribs);
      map->AppendDescriptor(isolate(), &d);
    }

    {  // name
      static_assert(
          JSFunctionOrBoundFunctionOrWrappedFunction::kNameDescriptorIndex ==
          1);
      Descriptor d = Descriptor::AccessorConstant(
          factory->name_string(), factory->wrapped_function_name_accessor(),
          roc_attribs);
      map->AppendDescriptor(isolate(), &d);
    }

    native_context()->set_wrapped_function_map(*map);
  }

  // Internal steps of ShadowRealmImportValue
  {
    DirectHandle<JSFunction> shadow_realm_import_value_rejected =
        SimpleCreateFunction(isolate(), factory->empty_string(),
                             Builtin::kShadowRealmImportValueRejected, 1,
                             kAdapt);
    shadow_realm_import_value_rejected->shared()->set_native(false);
    native_context()->set_shadow_realm_import_value_rejected(
        *shadow_realm_import_value_rejected);
  }
}

void Genesis::InitializeGlobal_harmony_struct() {
  if (!v8_flags.harmony_struct) return;

  ReadOnlyRoots roots(isolate());
  Handle<JSGlobalObject> global(native_context()->global_object(), isolate());
  Handle<JSObject> atomics_object = Cast<JSObject>(
      JSReceiver::GetProperty(isolate(), global, "Atomics").ToHandleChecked());

  {
    // Install shared objects @@hasInstance in the native context.
    DirectHandle<JSFunction> has_instance = SimpleCreateFunction(
        isolate(), factory()->empty_string(),
        Builtin::kSharedSpaceJSObjectHasInstance, 1, kDontAdapt);
    native_context()->set_shared_space_js_object_has_instance(*has_instance);
  }

  {  // SharedStructType
    Handle<String> name =
        isolate()->factory()->InternalizeUtf8String("SharedStructType");
    Handle<JSFunction> shared_struct_type_fun = CreateFunctionForBuiltin(
        isolate(), name,
        isolate()->strict_function_with_readonly_prototype_map(),
        Builtin::kSharedStructTypeConstructor, 1, kDontAdapt);
    JSObject::MakePrototypesFast(shared_struct_type_fun, kStartAtReceiver,
                                 isolate());
    shared_struct_type_fun->shared()->set_native(true);
    JSObject::AddProperty(isolate(), global, "SharedStructType",
                          shared_struct_type_fun, DONT_ENUM);

    SimpleInstallFunction(isolate(), shared_struct_type_fun, "isSharedStruct",
                          Builtin::kSharedStructTypeIsSharedStruct, 1, kAdapt);
  }

  {  // SharedArray
    Handle<String> shared_array_str =
        isolate()->factory()->InternalizeUtf8String("SharedArray");
    Handle<JSFunction> shared_array_fun = CreateSharedObjectConstructor(
        isolate(), shared_array_str, roots.js_shared_array_map_handle(),
        Builtin::kSharedArrayConstructor, 0, kAdapt);

    // Install SharedArray constructor.
    JSObject::AddProperty(isolate(), global, "SharedArray", shared_array_fun,
                          DONT_ENUM);

    SimpleInstallFunction(isolate(), shared_array_fun, "isSharedArray",
                          Builtin::kSharedArrayIsSharedArray, 1, kAdapt);
  }

  {  // Atomics.Mutex
    Handle<String> mutex_str =
        isolate()->factory()->InternalizeUtf8String("Mutex");
    Handle<JSFunction> mutex_fun = CreateSharedObjectConstructor(
        isolate(), mutex_str, roots.js_atomics_mutex_map_handle(),
        Builtin::kAtomicsMutexConstructor, 0, kAdapt);
    JSObject::AddProperty(isolate(), atomics_object, mutex_str, mutex_fun,
                          DONT_ENUM);

    SimpleInstallFunction(isolate(), mutex_fun, "lock",
                          Builtin::kAtomicsMutexLock, 2, kAdapt);
    SimpleInstallFunction(isolate(), mutex_fun, "lockWithTimeout",
                          Builtin::kAtomicsMutexLockWithTimeout, 3, kAdapt);
    SimpleInstallFunction(isolate(), mutex_fun, "tryLock",
                          Builtin::kAtomicsMutexTryLock, 2, kAdapt);
    SimpleInstallFunction(isolate(), mutex_fun, "isMutex",
                          Builtin::kAtomicsMutexIsMutex, 1, kAdapt);
    SimpleInstallFunction(isolate(), mutex_fun, "lockAsync",
                          Builtin::kAtomicsMutexLockAsync, 2, kAdapt);
  }

  {  // Atomics.Condition
    Handle<String> condition_str =
        isolate()->factory()->InternalizeUtf8String("Condition");
    Handle<JSFunction> condition_fun = CreateSharedObjectConstructor(
        isolate(), condition_str, roots.js_atomics_condition_map_handle(),
        Builtin::kAtomicsConditionConstructor, 0, kAdapt);
    JSObject::AddProperty(isolate(), atomics_object, condition_str,
                          condition_fun, DONT_ENUM);

    SimpleInstallFunction(isolate(), condition_fun, "wait",
                          Builtin::kAtomicsConditionWait, 2, kDontAdapt);
    SimpleInstallFunction(isolate(), condition_fun, "notify",
                          Builtin::kAtomicsConditionNotify, 2, kDontAdapt);
    SimpleInstallFunction(isolate(), condition_fun, "isCondition",
                          Builtin::kAtomicsConditionIsCondition, 1, kAdapt);
    SimpleInstallFunction(isolate(), condition_fun, "waitAsync",
                          Builtin::kAtomicsConditionWaitAsync, 2, kDontAdapt);
  }
}

void Genesis::InitializeGlobal_sharedarraybuffer() {
  if (v8_flags.enable_sharedarraybuffer_per_context) {
    return;
  }

  Handle<JSGlobalObject> global(native_context()->global_object(), isolate());

  JSObject::AddProperty(isolate_, global, "SharedArrayBuffer",
                        isolate()->shared_array_buffer_fun(), DONT_ENUM);
}

void Genesis::InitializeGlobal_harmony_weak_refs_with_cleanup_some() {
  if (!v8_flags.harmony_weak_refs_with_cleanup_some) return;

  DirectHandle<JSFunction> finalization_registry_fun =
      isolate()->js_finalization_registry_fun();
  Handle<JSObject> finalization_registry_prototype(
      Cast<JSObject>(finalization_registry_fun->instance_prototype()),
      isolate());

  JSObject::AddProperty(isolate(), finalization_registry_prototype,
                        factory()->InternalizeUtf8String("cleanupSome"),
                        isolate()->finalization_registry_cleanup_some(),
                        DONT_ENUM);
}

void Genesis::InitializeGlobal_js_explicit_resource_management() {
  if (!v8_flags.js_explicit_resource_management) return;

  Factory* factory = isolate()->factory();
  Handle<JSGlobalObject> global(native_context()->global_object(), isolate());

  // -- S u p p r e s s e d E r r o r
  InstallError(isolate(), global, factory->SuppressedError_string(),
               Context::SUPPRESSED_ERROR_FUNCTION_INDEX,
               Builtin::kSuppressedErrorConstructor, 3);

  // -- D i s p o s a b l e S t a c k
  DirectHandle<Map> js_disposable_stack_map =
      factory->NewContextfulMapForCurrentContext(
          JS_DISPOSABLE_STACK_BASE_TYPE, JSDisposableStackBase::kHeaderSize);
  js_disposable_stack_map->SetConstructor(native_context()->object_function());
  native_context()->set_js_disposable_stack_map(*js_disposable_stack_map);
  LOG(isolate(), MapDetails(*js_disposable_stack_map));

  // SyncDisposableStack
  Handle<JSObject> sync_disposable_stack_prototype =
      factory->NewJSObject(isolate()->object_function(), AllocationType::kOld);

  Handle<JSFunction> disposable_stack_function = InstallFunction(
      isolate(), global, "DisposableStack", JS_SYNC_DISPOSABLE_STACK_TYPE,
      JSSyncDisposableStack::kHeaderSize, 0, sync_disposable_stack_prototype,
      Builtin::kDisposableStackConstructor, 0, kDontAdapt);
  InstallWithIntrinsicDefaultProto(isolate(), disposable_stack_function,
                                   Context::JS_DISPOSABLE_STACK_FUNCTION_INDEX);
  SimpleInstallFunction(isolate(), sync_disposable_stack_prototype, "use",
                        Builtin::kDisposableStackPrototypeUse, 1, kAdapt);
  DirectHandle<JSFunction> dispose = SimpleInstallFunction(
      isolate(), sync_disposable_stack_prototype, "dispose",
      Builtin::kDisposableStackPrototypeDispose, 0, kAdapt);
  JSObject::AddProperty(isolate(), sync_disposable_stack_prototype,
                        factory->dispose_symbol(), dispose, DONT_ENUM);
  SimpleInstallFunction(isolate(), sync_disposable_stack_prototype, "adopt",
                        Builtin::kDisposableStackPrototypeAdopt, 2, kAdapt);
  SimpleInstallFunction(isolate(), sync_disposable_stack_prototype, "defer",
                        Builtin::kDisposableStackPrototypeDefer, 1, kAdapt);
  SimpleInstallFunction(isolate(), sync_disposable_stack_prototype, "move",
                        Builtin::kDisposableStackPrototypeMove, 0, kAdapt);

  InstallToStringTag(isolate(), sync_disposable_stack_prototype,
                     "DisposableStack");
  SimpleInstallGetter(isolate(), sync_disposable_stack_prototype,
                      factory->disposed_string(),
                      Builtin::kDisposableStackPrototypeGetDisposed, kAdapt);

  // AsyncDisposableStack
  Handle<JSObject> async_disposable_stack_prototype =
      factory->NewJSObject(isolate()->object_function(), AllocationType::kOld);

  Handle<JSFunction> async_disposable_stack_function = InstallFunction(
      isolate(), global, "AsyncDisposableStack", JS_ASYNC_DISPOSABLE_STACK_TYPE,
      JSAsyncDisposableStack::kHeaderSize, 0, async_disposable_stack_prototype,
      Builtin::kAsyncDisposableStackConstructor, 0, kDontAdapt);
  InstallWithIntrinsicDefaultProto(
      isolate(), async_disposable_stack_function,
      Context::JS_ASYNC_DISPOSABLE_STACK_FUNCTION_INDEX);
  SimpleInstallFunction(isolate(), async_disposable_stack_prototype, "use",
                        Builtin::kAsyncDisposableStackPrototypeUse, 1, kAdapt);
  DirectHandle<JSFunction> dispose_async = SimpleInstallFunction(
      isolate(), async_disposable_stack_prototype, "disposeAsync",
      Builtin::kAsyncDisposableStackPrototypeDisposeAsync, 0, kAdapt);
  JSObject::AddProperty(isolate(), async_disposable_stack_prototype,
                        factory->async_dispose_symbol(), dispose_async,
                        DONT_ENUM);
  SimpleInstallFunction(isolate(), async_disposable_stack_prototype, "adopt",
                        Builtin::kAsyncDisposableStackPrototypeAdopt, 2,
                        kAdapt);
  SimpleInstallFunction(isolate(), async_disposable_stack_prototype, "defer",
                        Builtin::kAsyncDisposableStackPrototypeDefer, 1,
                        kAdapt);
  SimpleInstallFunction(isolate(), async_disposable_stack_prototype, "move",
                        Builtin::kAsyncDisposableStackPrototypeMove, 0, kAdapt);

  InstallToStringTag(isolate(), async_disposable_stack_prototype,
                     "AsyncDisposableStack");
  SimpleInstallGetter(
      isolate(), async_disposable_stack_prototype, factory->disposed_string(),
      Builtin::kAsyncDisposableStackPrototypeGetDisposed, kAdapt);

  // Add symbols to iterator prototypes
  Handle<JSObject> iterator_prototype(
      native_context()->initial_iterator_prototype(), isolate());
  InstallFunctionAtSymbol(isolate(), iterator_prototype,
                          factory->dispose_symbol(), "[Symbol.dispose]",
                          Builtin::kIteratorPrototypeDispose, 0, kAdapt);

  Handle<JSObject> async_iterator_prototype(
      native_context()->initial_async_iterator_prototype(), isolate());
  InstallFunctionAtSymbol(
      isolate(), async_iterator_prototype, factory->async_dispose_symbol(),
      "[Symbol.asyncDispose]", Builtin::kAsyncIteratorPrototypeAsyncDispose, 0,
      kAdapt);
}

void Genesis::InitializeGlobal_js_float16array() {
  if (!v8_flags.js_float16array) return;

  Handle<JSGlobalObject> global(native_context()->global_object(), isolate());
  Handle<JSObject> math = Cast<JSObject>(
      JSReceiver::GetProperty(isolate(), global, "Math").ToHandleChecked());

  SimpleInstallFunction(isolate_, math, "f16round", Builtin::kMathF16round, 1,
                        kAdapt);

  Handle<JSObject> dataview_prototype(
      Cast<JSObject>(native_context()->data_view_fun()->instance_prototype()),
      isolate());

  SimpleInstallFunction(isolate_, dataview_prototype, "getFloat16",
                        Builtin::kDataViewPrototypeGetFloat16, 1, kDontAdapt);
  SimpleInstallFunction(isolate_, dataview_prototype, "setFloat16",
                        Builtin::kDataViewPrototypeSetFloat16, 2, kDontAdapt);

  Handle<JSFunction> fun = InstallTypedArray(
      "Float16Array", FLOAT16_ELEMENTS, FLOAT16_TYPED_ARRAY_CONSTRUCTOR_TYPE,
      Context::RAB_GSAB_FLOAT16_ARRAY_MAP_INDEX);

  InstallWithIntrinsicDefaultProto(isolate_, fun,
                                   Context::FLOAT16_ARRAY_FUN_INDEX);
}

void Genesis::InitializeGlobal_js_source_phase_imports() {
  if (!v8_flags.js_source_phase_imports) return;
  Factory* factory = isolate()->factory();
  // -- %AbstractModuleSource%
  // #sec-%abstractmodulesource%
  // https://tc39.es/proposal-source-phase-imports/#sec-%abstractmodulesource%
  Handle<JSFunction> abstract_module_source_fun =
      CreateFunction(isolate_, "AbstractModuleSource", JS_OBJECT_TYPE,
                     JSObject::kHeaderSize, 0, factory->the_hole_value(),
                     Builtin::kIllegalInvocationThrower, 0, kDontAdapt);

  native_context()->set_abstract_module_source_function(
      *abstract_module_source_fun);

  // Setup %AbstractModuleSourcePrototype%.
  Handle<JSObject> abstract_module_source_prototype(
      Cast<JSObject>(abstract_module_source_fun->instance_prototype()),
      isolate());
  native_context()->set_abstract_module_source_prototype(
      *abstract_module_source_prototype);

  SimpleInstallGetter(isolate(), abstract_module_source_prototype,
                      isolate()->factory()->to_string_tag_symbol(),
                      Builtin::kAbstractModuleSourceToStringTag, kAdapt);
}

void Genesis::InitializeGlobal_regexp_linear_flag() {
  if (!v8_flags.enable_experimental_regexp_engine) return;

  DirectHandle<JSFunction> regexp_fun(native_context()->regexp_function(),
                                      isolate());
  Handle<JSObject> regexp_prototype(
      Cast<JSObject>(regexp_fun->instance_prototype()), isolate());
  SimpleInstallGetter(isolate(), regexp_prototype,
                      isolate()->factory()->linear_string(),
                      Builtin::kRegExpPrototypeLinearGetter, kAdapt);

  // Store regexp prototype map again after change.
  native_context()->set_regexp_prototype_map(regexp_prototype->map());
}

void Genesis::InitializeGlobal_harmony_temporal() {
  if (!v8_flags.harmony_temporal) return;

  // The Temporal object is set up lazily upon first access.
  {
    Handle<JSGlobalObject> global(native_context()->global_object(), isolate());
    Handle<String> name = factory()->InternalizeUtf8String("Temporal");
    Handle<AccessorInfo> accessor = Accessors::MakeAccessor(
        isolate(), name, LazyInitializeGlobalThisTemporal, nullptr);
    accessor->set_replace_on_access(true);
    JSObject::SetAccessor(global, name, accessor, DONT_ENUM).Check();
  }

  // Likewise Date.toTemporalInstant.
  {
    DirectHandle<JSFunction> date_func(native_context()->date_function(),
                                       isolate());
    Handle<JSObject> date_prototype(
        Cast<JSObject>(date_func->instance_prototype()), isolate());
    Handle<String> name = factory()->InternalizeUtf8String("toTemporalInstant");
    Handle<AccessorInfo> accessor = Accessors::MakeAccessor(
        isolate(), name, LazyInitializeDateToTemporalInstant, nullptr);
    accessor->set_replace_on_access(true);
    JSObject::SetAccessor(date_prototype, name, accessor, DONT_ENUM).Check();
  }
}

Handle<JSFunction> Genesis::CreateArrayBuffer(
    Handle<String> name, ArrayBufferKind array_buffer_kind) {
  // Create the %ArrayBufferPrototype%
  // Setup the {prototype} with the given {name} for @@toStringTag.
  Handle<JSObject> prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);
  InstallToStringTag(isolate(), prototype, name);

  // Allocate the constructor with the given {prototype}.
  Handle<JSFunction> array_buffer_fun =
      CreateFunction(isolate(), name, JS_ARRAY_BUFFER_TYPE,
                     JSArrayBuffer::kSizeWithEmbedderFields, 0, prototype,
                     Builtin::kArrayBufferConstructor, 1, kAdapt);

  // Install the "constructor" property on the {prototype}.
  JSObject::AddProperty(isolate(), prototype, factory()->constructor_string(),
                        array_buffer_fun, DONT_ENUM);

  switch (array_buffer_kind) {
    case ARRAY_BUFFER:
      InstallFunctionWithBuiltinId(isolate(), array_buffer_fun, "isView",
                                   Builtin::kArrayBufferIsView, 1, kAdapt);

      // Install the "byteLength" getter on the {prototype}.
      SimpleInstallGetter(isolate(), prototype, factory()->byte_length_string(),
                          Builtin::kArrayBufferPrototypeGetByteLength, kAdapt);
      SimpleInstallFunction(isolate(), prototype, "slice",
                            Builtin::kArrayBufferPrototypeSlice, 2, kAdapt);
      break;

    case SHARED_ARRAY_BUFFER:
      // Install the "byteLength" getter on the {prototype}.
      SimpleInstallGetter(isolate(), prototype, factory()->byte_length_string(),
                          Builtin::kSharedArrayBufferPrototypeGetByteLength,
                          kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "slice",
                            Builtin::kSharedArrayBufferPrototypeSlice, 2,
                            kAdapt);
      break;
  }

  return array_buffer_fun;
}

// TODO(jgruber): Refactor this into some kind of meaningful organization. There
// is likely no reason remaining for these objects to be installed here. For
// example, global object setup done in this function could likely move to
// InitializeGlobal.
bool Genesis::InstallABunchOfRandomThings() {
  HandleScope scope(isolate());

  auto fast_template_instantiations_cache =
      isolate()->factory()->NewFixedArrayWithHoles(
          TemplateInfo::kFastTemplateInstantiationsCacheSize);
  native_context()->set_fast_template_instantiations_cache(
      *fast_template_instantiations_cache);

  auto slow_template_instantiations_cache = SimpleNumberDictionary::New(
      isolate(), ApiNatives::kInitialFunctionCacheSize);
  native_context()->set_slow_template_instantiations_cache(
      *slow_template_instantiations_cache);

  auto wasm_debug_maps = isolate()->factory()->empty_fixed_array();
  native_context()->set_wasm_debug_maps(*wasm_debug_maps);

  // Store the map for the %ObjectPrototype% after the natives has been compiled
  // and the Object function has been set up.
  {
    DirectHandle<JSFunction> object_function(
        native_context()->object_function(), isolate());
    DCHECK(Cast<JSObject>(object_function->initial_map()->prototype())
               ->HasFastProperties());
    native_context()->set_object_function_prototype(
        Cast<JSObject>(object_function->initial_map()->prototype()));
    native_context()->set_object_function_prototype_map(
        Cast<HeapObject>(object_function->initial_map()->prototype())->map());
  }

  // Store the map for the %StringPrototype% after the natives has been compiled
  // and the String function has been set up.
  DirectHandle<JSFunction> string_function(native_context()->string_function(),
                                           isolate());
  Tagged<JSObject> string_function_prototype =
      Cast<JSObject>(string_function->initial_map()->prototype());
  DCHECK(string_function_prototype->HasFastProperties());
  native_context()->set_string_function_prototype_map(
      string_function_prototype->map());

  Handle<JSGlobalObject> global_object =
      handle(native_context()->global_object(), isolate());

  // Install Global.decodeURI.
  InstallFunctionWithBuiltinId(isolate(), global_object, "decodeURI",
                               Builtin::kGlobalDecodeURI, 1, kDontAdapt);

  // Install Global.decodeURIComponent.
  InstallFunctionWithBuiltinId(isolate(), global_object, "decodeURIComponent",
                               Builtin::kGlobalDecodeURIComponent, 1,
                               kDontAdapt);

  // Install Global.encodeURI.
  InstallFunctionWithBuiltinId(isolate(), global_object, "encodeURI",
                               Builtin::kGlobalEncodeURI, 1, kDontAdapt);

  // Install Global.encodeURIComponent.
  InstallFunctionWithBuiltinId(isolate(), global_object, "encodeURIComponent",
                               Builtin::kGlobalEncodeURIComponent, 1,
                               kDontAdapt);

  // Install Global.escape.
  InstallFunctionWithBuiltinId(isolate(), global_object, "escape",
                               Builtin::kGlobalEscape, 1, kDontAdapt);

  // Install Global.unescape.
  InstallFunctionWithBuiltinId(isolate(), global_object, "unescape",
                               Builtin::kGlobalUnescape, 1, kDontAdapt);

  // Install Global.eval.
  {
    DirectHandle<JSFunction> eval = SimpleInstallFunction(
        isolate(), global_object, "eval", Builtin::kGlobalEval, 1, kDontAdapt);
    native_context()->set_global_eval_fun(*eval);
  }

  // Install Global.isFinite
  InstallFunctionWithBuiltinId(isolate(), global_object, "isFinite",
                               Builtin::kGlobalIsFinite, 1, kAdapt);

  // Install Global.isNaN
  InstallFunctionWithBuiltinId(isolate(), global_object, "isNaN",
                               Builtin::kGlobalIsNaN, 1, kAdapt);

  // Install Array builtin functions.
  {
    DirectHandle<JSFunction> array_constructor(
        native_context()->array_function(), isolate());
    DirectHandle<JSArray> proto(Cast<JSArray>(array_constructor->prototype()),
                                isolate());

    // Verification of important array prototype properties.
    Tagged<Object> length = proto->length();
    CHECK(IsSmi(length));
    CHECK_EQ(Smi::ToInt(length), 0);
    CHECK(proto->HasSmiOrObjectElements());
    // This is necessary to enable fast checks for absence of elements
    // on Array.prototype and below.
    proto->set_elements(ReadOnlyRoots(heap()).empty_fixed_array());
  }

  // Create a map for accessor property descriptors (a variant of JSObject
  // that predefines four properties get, set, configurable and enumerable).
  {
    // AccessorPropertyDescriptor initial map.
    DirectHandle<Map> map = factory()->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSAccessorPropertyDescriptor::kSize,
        TERMINAL_FAST_ELEMENTS_KIND, 4);
    // Create the descriptor array for the property descriptor object.
    Map::EnsureDescriptorSlack(isolate(), map, 4);

    {  // get
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->get_string(),
                                JSAccessorPropertyDescriptor::kGetIndex, NONE,
                                Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // set
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->set_string(),
                                JSAccessorPropertyDescriptor::kSetIndex, NONE,
                                Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // enumerable
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->enumerable_string(),
                                JSAccessorPropertyDescriptor::kEnumerableIndex,
                                NONE, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // configurable
      Descriptor d = Descriptor::DataField(
          isolate(), factory()->configurable_string(),
          JSAccessorPropertyDescriptor::kConfigurableIndex, NONE,
          Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }

    Map::SetPrototype(isolate(), map, isolate()->initial_object_prototype());
    map->SetConstructor(native_context()->object_function());

    native_context()->set_accessor_property_descriptor_map(*map);
  }

  // Create a map for data property descriptors (a variant of JSObject
  // that predefines four properties value, writable, configurable and
  // enumerable).
  {
    // DataPropertyDescriptor initial map.
    DirectHandle<Map> map = factory()->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSDataPropertyDescriptor::kSize,
        TERMINAL_FAST_ELEMENTS_KIND, 4);
    // Create the descriptor array for the property descriptor object.
    Map::EnsureDescriptorSlack(isolate(), map, 4);

    {  // value
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->value_string(),
                                JSDataPropertyDescriptor::kValueIndex, NONE,
                                Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // writable
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->writable_string(),
                                JSDataPropertyDescriptor::kWritableIndex, NONE,
                                Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // enumerable
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->enumerable_string(),
                                JSDataPropertyDescriptor::kEnumerableIndex,
                                NONE, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // configurable
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->configurable_string(),
                                JSDataPropertyDescriptor::kConfigurableIndex,
                                NONE, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }

    Map::SetPrototype(isolate(), map, isolate()->initial_object_prototype());
    map->SetConstructor(native_context()->object_function());

    native_context()->set_data_property_descriptor_map(*map);
  }

  {
    // -- TemplateLiteral JSArray Map
    DirectHandle<JSFunction> array_function(native_context()->array_function(),
                                            isolate());
    Handle<Map> template_map(array_function->initial_map(), isolate_);
    template_map = Map::CopyAsElementsKind(isolate_, template_map,
                                           PACKED_ELEMENTS, OMIT_TRANSITION);
    DCHECK_GE(TemplateLiteralObject::kHeaderSize,
              template_map->instance_size());
    template_map->set_instance_size(TemplateLiteralObject::kHeaderSize);
    // Temporarily instantiate a full template_literal_object to get the final
    // map.
    auto template_object =
        Cast<JSArray>(factory()->NewJSObjectFromMap(template_map));
    {
      DisallowGarbageCollection no_gc;
      Tagged<JSArray> raw = *template_object;
      raw->set_elements(ReadOnlyRoots(isolate()).empty_fixed_array());
      raw->set_length(Smi::FromInt(0));
    }

    // Install a "raw" data property for {raw_object} on {template_object}.
    // See ES#sec-gettemplateobject.
    PropertyDescriptor raw_desc;
    // Use arbrirary object {template_object} as ".raw" value.
    raw_desc.set_value(template_object);
    raw_desc.set_configurable(false);
    raw_desc.set_enumerable(false);
    raw_desc.set_writable(false);
    JSArray::DefineOwnProperty(isolate(), template_object,
                               factory()->raw_string(), &raw_desc,
                               Just(kThrowOnError))
        .ToChecked();
    // Install private symbol fields for function_literal_id and slot_id.
    raw_desc.set_value(handle(Smi::zero(), isolate()));
    JSArray::DefineOwnProperty(
        isolate(), template_object,
        factory()->template_literal_function_literal_id_symbol(), &raw_desc,
        Just(kThrowOnError))
        .ToChecked();
    JSArray::DefineOwnProperty(isolate(), template_object,
                               factory()->template_literal_slot_id_symbol(),
                               &raw_desc, Just(kThrowOnError))
        .ToChecked();

    // Freeze the {template_object} as well.
    JSObject::SetIntegrityLevel(isolate(), template_object, FROZEN,
                                kThrowOnError)
        .ToChecked();
    {
      DisallowGarbageCollection no_gc;
      Tagged<DescriptorArray> desc =
          template_object->map()->instance_descriptors();
      {
        // Verify TemplateLiteralObject::kRawOffset
        InternalIndex descriptor_index = desc->Search(
            *factory()->raw_string(), desc->number_of_descriptors());
        FieldIndex index =
            FieldIndex::ForDescriptor(template_object->map(), descriptor_index);
        CHECK(index.is_inobject());
        CHECK_EQ(index.offset(), TemplateLiteralObject::kRawOffset);
      }

      {
        // Verify TemplateLiteralObject::kFunctionLiteralIdOffset
        InternalIndex descriptor_index = desc->Search(
            *factory()->template_literal_function_literal_id_symbol(),
            desc->number_of_descriptors());
        FieldIndex index =
            FieldIndex::ForDescriptor(template_object->map(), descriptor_index);
        CHECK(index.is_inobject());
        CHECK_EQ(index.offset(),
                 TemplateLiteralObject::kFunctionLiteralIdOffset);
      }

      {
        // Verify TemplateLiteralObject::kSlotIdOffset
        InternalIndex descriptor_index =
            desc->Search(*factory()->template_literal_slot_id_symbol(),
                         desc->number_of_descriptors());
        FieldIndex index =
            FieldIndex::ForDescriptor(template_object->map(), descriptor_index);
        CHECK(index.is_inobject());
        CHECK_EQ(index.offset(), TemplateLiteralObject::kSlotIdOffset);
      }
    }

    native_context()->set_js_array_template_literal_object_map(
        template_object->map());
  }

  // Create a constructor for RegExp results (a variant of Array that
  // predefines the properties index, input, and groups).
  {
    // JSRegExpResult initial map.
    // Add additional slack to the initial map in case regexp_match_indices
    // are enabled to account for the additional descriptor.
    Handle<Map> initial_map = CreateInitialMapForArraySubclass(
        JSRegExpResult::kSize, JSRegExpResult::kInObjectPropertyCount);

    // index descriptor.
    {
      Descriptor d = Descriptor::DataField(isolate(), factory()->index_string(),
                                           JSRegExpResult::kIndexIndex, NONE,
                                           Representation::Tagged());
      initial_map->AppendDescriptor(isolate(), &d);
    }

    // input descriptor.
    {
      Descriptor d = Descriptor::DataField(isolate(), factory()->input_string(),
                                           JSRegExpResult::kInputIndex, NONE,
                                           Representation::Tagged());
      initial_map->AppendDescriptor(isolate(), &d);
    }

    // groups descriptor.
    {
      Descriptor d = Descriptor::DataField(
          isolate(), factory()->groups_string(), JSRegExpResult::kGroupsIndex,
          NONE, Representation::Tagged());
      initial_map->AppendDescriptor(isolate(), &d);
    }

    // Private internal only fields. All of the remaining fields have special
    // symbols to prevent their use in Javascript.
    {
      PropertyAttributes attribs = DONT_ENUM;

      // names descriptor.
      {
        Descriptor d = Descriptor::DataField(
            isolate(), factory()->regexp_result_names_symbol(),
            JSRegExpResult::kNamesIndex, attribs, Representation::Tagged());
        initial_map->AppendDescriptor(isolate(), &d);
      }

      // regexp_input_index descriptor.
      {
        Descriptor d = Descriptor::DataField(
            isolate(), factory()->regexp_result_regexp_input_symbol(),
            JSRegExpResult::kRegExpInputIndex, attribs,
            Representation::Tagged());
        initial_map->AppendDescriptor(isolate(), &d);
      }

      // regexp_last_index descriptor.
      {
        Descriptor d = Descriptor::DataField(
            isolate(), factory()->regexp_result_regexp_last_index_symbol(),
            JSRegExpResult::kRegExpLastIndex, attribs,
            Representation::Tagged());
        initial_map->AppendDescriptor(isolate(), &d);
      }
    }

    // Set up the map for RegExp results objects for regexps with the /d flag.
    DirectHandle<Map> initial_with_indices_map =
        Map::Copy(isolate(), initial_map, "JSRegExpResult with indices");
    initial_with_indices_map->set_instance_size(
        JSRegExpResultWithIndices::kSize);
    DCHECK_EQ(initial_with_indices_map->GetInObjectProperties(),
              JSRegExpResultWithIndices::kInObjectPropertyCount);

    // indices descriptor
    {
      Descriptor d =
          Descriptor::DataField(isolate(), factory()->indices_string(),
                                JSRegExpResultWithIndices::kIndicesIndex, NONE,
                                Representation::Tagged());
      Map::EnsureDescriptorSlack(isolate(), initial_with_indices_map, 1);
      initial_with_indices_map->AppendDescriptor(isolate(), &d);
    }

    native_context()->set_regexp_result_map(*initial_map);
    native_context()->set_regexp_result_with_indices_map(
        *initial_with_indices_map);
  }

  // Create a constructor for JSRegExpResultIndices (a variant of Array that
  // predefines the groups property).
  {
    // JSRegExpResultIndices initial map.
    DirectHandle<Map> initial_map = CreateInitialMapForArraySubclass(
        JSRegExpResultIndices::kSize,
        JSRegExpResultIndices::kInObjectPropertyCount);

    // groups descriptor.
    {
      Descriptor d = Descriptor::DataField(
          isolate(), factory()->groups_string(),
          JSRegExpResultIndices::kGroupsIndex, NONE, Representation::Tagged());
      initial_map->AppendDescriptor(isolate(), &d);
      DCHECK_EQ(initial_map->LastAdded().as_int(),
                JSRegExpResultIndices::kGroupsDescriptorIndex);
    }

    native_context()->set_regexp_result_indices_map(*initial_map);
  }

  // Add @@iterator method to the arguments object maps.
  {
    PropertyAttributes attribs = DONT_ENUM;
    Handle<AccessorInfo> arguments_iterator =
        factory()->arguments_iterator_accessor();
    {
      Descriptor d = Descriptor::AccessorConstant(factory()->iterator_symbol(),
                                                  arguments_iterator, attribs);
      DirectHandle<Map> map(native_context()->sloppy_arguments_map(),
                            isolate());
      Map::EnsureDescriptorSlack(isolate(), map, 1);
      map->AppendDescriptor(isolate(), &d);
    }
    {
      Descriptor d = Descriptor::AccessorConstant(factory()->iterator_symbol(),
                                                  arguments_iterator, attribs);
      DirectHandle<Map> map(native_context()->fast_aliased_arguments_map(),
                            isolate());
      Map::EnsureDescriptorSlack(isolate(), map, 1);
      map->AppendDescriptor(isolate(), &d);
    }
    {
      Descriptor d = Descriptor::AccessorConstant(factory()->iterator_symbol(),
                                                  arguments_iterator, attribs);
      DirectHandle<Map> map(native_context()->slow_aliased_arguments_map(),
                            isolate());
      Map::EnsureDescriptorSlack(isolate(), map, 1);
      map->AppendDescriptor(isolate(), &d);
    }
    {
      Descriptor d = Descriptor::AccessorConstant(factory()->iterator_symbol(),
                                                  arguments_iterator, attribs);
      DirectHandle<Map> map(native_context()->strict_arguments_map(),
                            isolate());
      Map::EnsureDescriptorSlack(isolate(), map, 1);
      map->AppendDescriptor(isolate(), &d);
    }
  }
  {
    DirectHandle<OrderedHashSet> promises =
        OrderedHashSet::Allocate(isolate(), 0).ToHandleChecked();
    native_context()->set_atomics_waitasync_promises(*promises);
  }

  return true;
}

bool Genesis::InstallExtrasBindings() {
  HandleScope scope(isolate());

  Handle<JSObject> extras_binding = factory()->NewJSObjectWithNullProto();

  // binding.isTraceCategoryEnabled(category)
  SimpleInstallFunction(isolate(), extras_binding, "isTraceCategoryEnabled",
                        Builtin::kIsTraceCategoryEnabled, 1, kAdapt);

  // binding.trace(phase, category, name, id, data)
  SimpleInstallFunction(isolate(), extras_binding, "trace", Builtin::kTrace, 5,
                        kAdapt);

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  // binding.getContinuationPreservedEmbedderData()
  SimpleInstallFunction(
      isolate(), extras_binding, "getContinuationPreservedEmbedderData",
      Builtin::kGetContinuationPreservedEmbedderData, 0, kAdapt);

  // binding.setContinuationPreservedEmbedderData(value)
  SimpleInstallFunction(
      isolate(), extras_binding, "setContinuationPreservedEmbedderData",
      Builtin::kSetContinuationPreservedEmbedderData, 1, kAdapt);
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

  InitializeConsole(extras_binding);

  native_context()->set_extras_binding_object(*extras_binding);

  return true;
}

void Genesis::InitializeMapCaches() {
  {
    DirectHandle<NormalizedMapCache> cache = NormalizedMapCache::New(isolate());
    native_context()->set_normalized_map_cache(*cache);
  }

  {
    DirectHandle<WeakFixedArray> cache = factory()->NewWeakFixedArray(
        JSObject::kMapCacheSize, AllocationType::kOld);

    DisallowGarbageCollection no_gc;
    for (int i = 0; i < JSObject::kMapCacheSize; i++) {
      cache->set(i, ClearedValue(isolate()));
    }
    native_context()->set_map_cache(*cache);
    Tagged<Map> initial = native_context()->object_function()->initial_map();
    cache->set(0, MakeWeak(initial));
    cache->set(initial->GetInObjectProperties(), MakeWeak(initial));
  }
}

bool Bootstrapper::InstallExtensions(DirectHandle<NativeContext> native_context,
                                     v8::ExtensionConfiguration* extensions) {
  // Don't install extensions into the snapshot.
  if (isolate_->serializer_enabled()) return true;
  BootstrapperActive active(this);
  v8::Context::Scope context_scope(Utils::ToLocal(native_context));
  return Genesis::InstallExtensions(isolate_, native_context, extensions) &&
         Genesis::InstallSpecialObjects(isolate_, native_context);
}

bool Genesis::InstallSpecialObjects(
    Isolate* isolate, DirectHandle<NativeContext> native_context) {
  HandleScope scope(isolate);

  // Error.stackTraceLimit.
  {
    Handle<JSObject> Error = isolate->error_function();
    Handle<String> name = isolate->factory()->stackTraceLimit_string();
    DirectHandle<Smi> stack_trace_limit(
        Smi::FromInt(v8_flags.stack_trace_limit), isolate);
    JSObject::AddProperty(isolate, Error, name, stack_trace_limit, NONE);
  }

#if V8_ENABLE_WEBASSEMBLY
  WasmJs::Install(isolate);
#endif  // V8_ENABLE_WEBASSEMBLY

#ifdef V8_ENABLE_MEMORY_CORRUPTION_API
  if (v8_flags.expose_memory_corruption_api) {
    SandboxTesting::InstallMemoryCorruptionApi(isolate);
  }
#endif  // V8_ENABLE_MEMORY_CORRUPTION_API

  return true;
}

static uint32_t Hash(RegisteredExtension* extension) {
  return v8::internal::ComputePointerHash(extension);
}

Genesis::ExtensionStates::ExtensionStates() : map_(8) {}

Genesis::ExtensionTraversalState Genesis::ExtensionStates::get_state(
    RegisteredExtension* extension) {
  base::HashMap::Entry* entry = map_.Lookup(extension, Hash(extension));
  if (entry == nullptr) {
    return UNVISITED;
  }
  return static_cast<ExtensionTraversalState>(
      reinterpret_cast<intptr_t>(entry->value));
}

void Genesis::ExtensionStates::set_state(RegisteredExtension* extension,
                                         ExtensionTraversalState state) {
  map_.LookupOrInsert(extension, Hash(extension))->value =
      reinterpret_cast<void*>(static_cast<intptr_t>(state));
}

bool Genesis::InstallExtensions(Isolate* isolate,
                                DirectHandle<Context> native_context,
                                v8::ExtensionConfiguration* extensions) {
  ExtensionStates extension_states;  // All extensions have state UNVISITED.
  return InstallAutoExtensions(isolate, &extension_states) &&
         (!v8_flags.expose_gc ||
          InstallExtension(isolate, "v8/gc", &extension_states)) &&
         (!v8_flags.expose_externalize_string ||
          InstallExtension(isolate, "v8/externalize", &extension_states)) &&
         (!(v8_flags.expose_statistics ||
            TracingFlags::is_gc_stats_enabled()) ||
          InstallExtension(isolate, "v8/statistics", &extension_states)) &&
         (!v8_flags.expose_trigger_failure ||
          InstallExtension(isolate, "v8/trigger-failure", &extension_states)) &&
         (!v8_flags.expose_ignition_statistics ||
          InstallExtension(isolate, "v8/ignition-statistics",
                           &extension_states)) &&
         (!isValidCpuTraceMarkFunctionName() ||
          InstallExtension(isolate, "v8/cpumark", &extension_states)) &&
#ifdef V8_FUZZILLI
         InstallExtension(isolate, "v8/fuzzilli", &extension_states) &&
#endif
#ifdef ENABLE_VTUNE_TRACEMARK
         (!v8_flags.enable_vtune_domain_support ||
          InstallExtension(isolate, "v8/vtunedomain", &extension_states)) &&
#endif  // ENABLE_VTUNE_TRACEMARK
         InstallRequestedExtensions(isolate, extensions, &extension_states);
}

bool Genesis::InstallAutoExtensions(Isolate* isolate,
                                    ExtensionStates* extension_states) {
  for (v8::RegisteredExtension* it = v8::RegisteredExtension::first_extension();
       it != nullptr; it = it->next()) {
    if (it->extension()->auto_enable() &&
        !InstallExtension(isolate, it, extension_states)) {
      return false;
    }
  }
  return true;
}

bool Genesis::InstallRequestedExtensions(Isolate* isolate,
                                         v8::ExtensionConfiguration* extensions,
                                         ExtensionStates* extension_states) {
  for (const char** it = extensions->begin(); it != extensions->end(); ++it) {
    if (!InstallExtension(isolate, *it, extension_states)) return false;
  }
  return true;
}

// Installs a named extension.  This methods is unoptimized and does
// not scale well if we want to support a large number of extensions.
bool Genesis::InstallExtension(Isolate* isolate, const char* name,
                               ExtensionStates* extension_states) {
  for (v8::RegisteredExtension* it = v8::RegisteredExtension::first_extension();
       it != nullptr; it = it->next()) {
    if (strcmp(name, it->extension()->name()) == 0) {
      return InstallExtension(isolate, it, extension_states);
    }
  }
  return Utils::ApiCheck(false, "v8::Context::New()",
                         "Cannot find required extension");
}

bool Genesis::InstallExtension(Isolate* isolate,
                               v8::RegisteredExtension* current,
                               ExtensionStates* extension_states) {
  HandleScope scope(isolate);

  if (extension_states->get_state(current) == INSTALLED) return true;
  // The current node has already been visited so there must be a
  // cycle in the dependency graph; fail.
  if (!Utils::ApiCheck(extension_states->get_state(current) != VISITED,
                       "v8::Context::New()", "Circular extension dependency")) {
    return false;
  }
  DCHECK(extension_states->get_state(current) == UNVISITED);
  extension_states->set_state(current, VISITED);
  v8::Extension* extension = current->extension();
  // Install the extension's dependencies
  for (int i = 0; i < extension->dependency_count(); i++) {
    if (!InstallExtension(isolate, extension->dependencies()[i],
                          extension_states)) {
      return false;
    }
  }
  if (!CompileExtension(isolate, extension)) {
    // We print out the name of the extension that fail to install.
    // When an error is thrown during bootstrapping we automatically print
    // the line number at which this happened to the console in the isolate
    // error throwing functionality.
    base::OS::PrintError("Error installing extension '%s'.\n",
                         current->extension()->name());
    return false;
  }

  DCHECK(!isolate->has_exception());
  extension_states->set_state(current, INSTALLED);
  return true;
}

bool Genesis::ConfigureGlobalObject(
    v8::Local<v8::ObjectTemplate> global_proxy_template) {
  Handle<JSObject> global_proxy(native_context()->global_proxy(), isolate());
  Handle<JSObject> global_object(native_context()->global_object(), isolate());

  if (!global_proxy_template.IsEmpty()) {
    // Configure the global proxy object.
    Handle<ObjectTemplateInfo> global_proxy_data =
        v8::Utils::OpenHandle(*global_proxy_template);
    if (!ConfigureApiObject(global_proxy, global_proxy_data)) {
      base::OS::PrintError("V8 Error: Failed to configure global_proxy_data\n");
      return false;
    }

    // Configure the global object.
    DirectHandle<FunctionTemplateInfo> proxy_constructor(
        Cast<FunctionTemplateInfo>(global_proxy_data->constructor()),
        isolate());
    if (!IsUndefined(proxy_constructor->GetPrototypeTemplate(), isolate())) {
      Handle<ObjectTemplateInfo> global_object_data(
          Cast<ObjectTemplateInfo>(proxy_constructor->GetPrototypeTemplate()),
          isolate());
      if (!ConfigureApiObject(global_object, global_object_data)) {
        base::OS::PrintError(
            "V8 Error: Failed to configure global_object_data\n");
        return false;
      }
    }
  }

  JSObject::ForceSetPrototype(isolate(), global_proxy, global_object);

  native_context()->set_array_buffer_map(
      native_context()->array_buffer_fun()->initial_map());

  return true;
}

bool Genesis::ConfigureApiObject(Handle<JSObject> object,
                                 Handle<ObjectTemplateInfo> object_template) {
  DCHECK(!object_template.is_null());
  DCHECK(Cast<FunctionTemplateInfo>(object_template->constructor())
             ->IsTemplateFor(object->map()));

  MaybeHandle<JSObject> maybe_obj =
      ApiNatives::InstantiateObject(object->GetIsolate(), object_template);
  Handle<JSObject> instantiated_template;
  if (!maybe_obj.ToHandle(&instantiated_template)) {
    DCHECK(isolate()->has_exception());

    DirectHandle<String> message =
        ErrorUtils::ToString(isolate_, handle(isolate_->exception(), isolate_))
            .ToHandleChecked();
    base::OS::PrintError(
        "V8 Error: Exception in Genesis::ConfigureApiObject: %s\n",
        message->ToCString().get());

    isolate()->clear_exception();
    return false;
  }
  TransferObject(instantiated_template, object);
  return true;
}

static bool PropertyAlreadyExists(Isolate* isolate, Handle<JSObject> to,
                                  Handle<Name> key) {
  LookupIterator it(isolate, to, key, LookupIterator::OWN_SKIP_INTERCEPTOR);
  CHECK_NE(LookupIterator::ACCESS_CHECK, it.state());
  return it.IsFound();
}

void Genesis::TransferNamedProperties(DirectHandle<JSObject> from,
                                      Handle<JSObject> to) {
  // If JSObject::AddProperty asserts due to already existing property,
  // it is likely due to both global objects sharing property name(s).
  // Merging those two global objects is impossible.
  // The global template must not create properties that already exist
  // in the snapshotted global object.
  if (from->HasFastProperties()) {
    DirectHandle<DescriptorArray> descs(
        from->map()->instance_descriptors(isolate()), isolate());
    for (InternalIndex i : from->map()->IterateOwnDescriptors()) {
      PropertyDetails details = descs->GetDetails(i);
      if (details.location() == PropertyLocation::kField) {
        if (details.kind() == PropertyKind::kData) {
          HandleScope inner(isolate());
          Handle<Name> key = Handle<Name>(descs->GetKey(i), isolate());
          // If the property is already there we skip it.
          if (PropertyAlreadyExists(isolate(), to, key)) continue;
          FieldIndex index = FieldIndex::ForDetails(from->map(), details);
          DirectHandle<Object> value = JSObject::FastPropertyAt(
              isolate(), from, details.representation(), index);
          JSObject::AddProperty(isolate(), to, key, value,
                                details.attributes());
        } else {
          DCHECK_EQ(PropertyKind::kAccessor, details.kind());
          UNREACHABLE();
        }

      } else {
        DCHECK_EQ(PropertyLocation::kDescriptor, details.location());
        DCHECK_EQ(PropertyKind::kAccessor, details.kind());
        Handle<Name> key(descs->GetKey(i), isolate());
        // If the property is already there we skip it.
        if (PropertyAlreadyExists(isolate(), to, key)) continue;
        HandleScope inner(isolate());
        DCHECK(!to->HasFastProperties());
        // Add to dictionary.
        Handle<Object> value(descs->GetStrongValue(i), isolate());
        PropertyDetails d(PropertyKind::kAccessor, details.attributes(),
                          PropertyCellType::kMutable);
        JSObject::SetNormalizedProperty(to, key, value, d);
      }
    }
  } else if (IsJSGlobalObject(*from)) {
    // Copy all keys and values in enumeration order.
    Handle<GlobalDictionary> properties(
        Cast<JSGlobalObject>(*from)->global_dictionary(kAcquireLoad),
        isolate());
    DirectHandle<FixedArray> indices =
        GlobalDictionary::IterationIndices(isolate(), properties);
    for (int i = 0; i < indices->length(); i++) {
      InternalIndex index(Smi::ToInt(indices->get(i)));
      DirectHandle<PropertyCell> cell(properties->CellAt(index), isolate());
      Handle<Name> key(cell->name(), isolate());
      // If the property is already there we skip it.
      if (PropertyAlreadyExists(isolate(), to, key)) continue;
      // Set the property.
      Handle<Object> value(cell->value(), isolate());
      if (IsTheHole(*value, isolate())) continue;
      PropertyDetails details = cell->property_details();
      if (details.kind() == PropertyKind::kData) {
        JSObject::AddProperty(isolate(), to, key, value, details.attributes());
      } else {
        DCHECK_EQ(PropertyKind::kAccessor, details.kind());
        DCHECK(!to->HasFastProperties());
        PropertyDetails d(PropertyKind::kAccessor, details.attributes(),
                          PropertyCellType::kMutable);
        JSObject::SetNormalizedProperty(to, key, value, d);
      }
    }

  } else if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    // Copy all keys and values in enumeration order.
    DirectHandle<SwissNameDictionary> properties(
        from->property_dictionary_swiss(), isolate());
    ReadOnlyRoots roots(isolate());
    for (InternalIndex entry : properties->IterateEntriesOrdered()) {
      Tagged<Object> raw_key;
      if (!properties->ToKey(roots, entry, &raw_key)) continue;

      DCHECK(IsName(raw_key));
      Handle<Name> key(Cast<Name>(raw_key), isolate());
      // If the property is already there we skip it.
      if (PropertyAlreadyExists(isolate(), to, key)) continue;
      // Set the property.
      DirectHandle<Object> value(properties->ValueAt(entry), isolate());
      DCHECK(!IsCell(*value));
      DCHECK(!IsTheHole(*value, isolate()));
      PropertyDetails details = properties->DetailsAt(entry);
      DCHECK_EQ(PropertyKind::kData, details.kind());
      JSObject::AddProperty(isolate(), to, key, value, details.attributes());
    }
  } else {
    // Copy all keys and values in enumeration order.
    Handle<NameDictionary> properties =
        Handle<NameDictionary>(from->property_dictionary(), isolate());
    DirectHandle<FixedArray> key_indices =
        NameDictionary::IterationIndices(isolate(), properties);
    ReadOnlyRoots roots(isolate());
    for (int i = 0; i < key_indices->length(); i++) {
      InternalIndex key_index(Smi::ToInt(key_indices->get(i)));
      Tagged<Object> raw_key = properties->KeyAt(key_index);
      DCHECK(properties->IsKey(roots, raw_key));
      DCHECK(IsName(raw_key));
      Handle<Name> key(Cast<Name>(raw_key), isolate());
      // If the property is already there we skip it.
      if (PropertyAlreadyExists(isolate(), to, key)) continue;
      // Set the property.
      DirectHandle<Object> value(properties->ValueAt(key_index), isolate());
      DCHECK(!IsCell(*value));
      DCHECK(!IsTheHole(*value, isolate()));
      PropertyDetails details = properties->DetailsAt(key_index);
      DCHECK_EQ(PropertyKind::kData, details.kind());
      JSObject::AddProperty(isolate(), to, key, value, details.attributes());
    }
  }
}

void Genesis::TransferIndexedProperties(DirectHandle<JSObject> from,
                                        DirectHandle<JSObject> to) {
  // Cloning the elements array is sufficient.
  Handle<FixedArray> from_elements =
      Handle<FixedArray>(Cast<FixedArray>(from->elements()), isolate());
  DirectHandle<FixedArray> to_elements =
      factory()->CopyFixedArray(from_elements);
  to->set_elements(*to_elements);
}

void Genesis::TransferObject(DirectHandle<JSObject> from, Handle<JSObject> to) {
  HandleScope outer(isolate());

  DCHECK(!IsJSArray(*from));
  DCHECK(!IsJSArray(*to));

  TransferNamedProperties(from, to);
  TransferIndexedProperties(from, to);

  // Transfer the prototype (new map is needed).
  Handle<JSPrototype> proto(from->map()->prototype(), isolate());
  JSObject::ForceSetPrototype(isolate(), to, proto);
}

Handle<Map> Genesis::CreateInitialMapForArraySubclass(int size,
                                                      int inobject_properties) {
  // Find global.Array.prototype to inherit from.
  DirectHandle<JSFunction> array_constructor(native_context()->array_function(),
                                             isolate());
  Handle<JSObject> array_prototype(native_context()->initial_array_prototype(),
                                   isolate());

  // Add initial map.
  Handle<Map> initial_map = factory()->NewContextfulMapForCurrentContext(
      JS_ARRAY_TYPE, size, TERMINAL_FAST_ELEMENTS_KIND, inobject_properties);
  initial_map->SetConstructor(*array_constructor);

  // Set prototype on map.
  initial_map->set_has_non_instance_prototype(false);
  Map::SetPrototype(isolate(), initial_map, array_prototype);

  // Update map with length accessor from Array.
  static constexpr int kTheLengthAccessor = 1;
  Map::EnsureDescriptorSlack(isolate(), initial_map,
                             inobject_properties + kTheLengthAccessor);

  // length descriptor.
  {
    Tagged<JSFunction> array_function = native_context()->array_function();
    DirectHandle<DescriptorArray> array_descriptors(
        array_function->initial_map()->instance_descriptors(isolate()),
        isolate());
    Handle<String> length = factory()->length_string();
    InternalIndex old = array_descriptors->SearchWithCache(
        isolate(), *length, array_function->initial_map());
    DCHECK(old.is_found());
    Descriptor d = Descriptor::AccessorConstant(
        length, handle(array_descriptors->GetStrongValue(old), isolate()),
        array_descriptors->GetDetails(old).attributes());
    initial_map->AppendDescriptor(isolate(), &d);
  }
  return initial_map;
}

Genesis::Genesis(Isolate* isolate,
                 MaybeHandle<JSGlobalProxy> maybe_global_proxy,
                 v8::Local<v8::ObjectTemplate> global_proxy_template,
                 size_t context_snapshot_index,
                 DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
                 v8::MicrotaskQueue* microtask_queue)
    : isolate_(isolate), active_(isolate->bootstrapper()) {
  RCS_SCOPE(isolate, RuntimeCallCounterId::kGenesis);
  result_ = {};
  global_proxy_ = {};

  // Before creating the roots we must save the context and restore it
  // on all function exits.
  SaveContext saved_context(isolate);

  // The deserializer needs to hook up references to the global proxy.
  // Create an uninitialized global proxy now if we don't have one
  // and initialize it later in CreateNewGlobals.
  Handle<JSGlobalProxy> global_proxy;
  if (!maybe_global_proxy.ToHandle(&global_proxy)) {
    int instance_size = 0;
    if (context_snapshot_index > 0) {
      // The global proxy function to reinitialize this global proxy is in the
      // context that is yet to be deserialized. We need to prepare a global
      // proxy of the correct size.
      Tagged<Object> size =
          isolate->heap()->serialized_global_proxy_sizes()->get(
              static_cast<int>(context_snapshot_index) -
              SnapshotCreatorImpl::kFirstAddtlContextIndex);
      instance_size = Smi::ToInt(size);
    } else {
      instance_size = JSGlobalProxy::SizeWithEmbedderFields(
          global_proxy_template.IsEmpty()
              ? 0
              : global_proxy_template->InternalFieldCount());
    }
    global_proxy =
        isolate->factory()->NewUninitializedJSGlobalProxy(instance_size);
  }

  // We can only de-serialize a context if the isolate was initialized from
  // a snapshot. Otherwise we have to build the context from scratch.
  // Also create a context from scratch to expose natives, if required by flag.
  DCHECK(native_context_.is_null());
  if (isolate->initialized_from_snapshot()) {
    DirectHandle<Context> context;
    if (Snapshot::NewContextFromSnapshot(isolate, global_proxy,
                                         context_snapshot_index,
                                         embedder_fields_deserializer)
```