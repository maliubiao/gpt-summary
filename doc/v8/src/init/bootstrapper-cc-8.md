Response:
The user wants a summary of the provided C++ code snippet from `v8/src/init/bootstrapper.cc`. The summary should include:

1. **Functionality:**  A description of what the code does.
2. **Torque Check:**  Whether the file would be a Torque file if it had a `.tq` extension.
3. **JavaScript Relationship:** If the code relates to JavaScript functionality, provide JavaScript examples.
4. **Logic Reasoning:** If there's logic, give example inputs and outputs.
5. **Common Errors:**  Examples of common programming errors related to the code.
6. **Overall Function:** A general summary of the code's purpose.

Let's break down the provided code block:

* **Iterator Helpers:**  The code heavily focuses on setting up the prototype for iterators and installing various iterator helper methods (`map`, `filter`, `take`, `drop`, `flatMap`, `reduce`, `toArray`, `forEach`, `some`, `every`, `find`). It also handles the `Symbol.iterator` getter/setter and the constructor getter/setter.
* **Feature Flags:** The code uses `v8_flags` to conditionally initialize global objects and functions based on experimental or harmony features (e.g., `js_atomics_pause`, `js_promise_try`, `harmony_set_methods`, `harmony_shadow_realm`, `harmony_struct`, `harmony_weak_refs_with_cleanup_some`, `js_explicit_resource_management`, `js_float16array`, `js_source_phase_imports`, `regexp_linear_flag`, `harmony_temporal`).
* **Global Object Setup:** It installs functions and objects onto the global object (e.g., `Atomics.pause`, `Promise.try`, Set methods, `ShadowRealm`, `SharedStructType`, `SharedArray`, `Atomics.Mutex`, `Atomics.Condition`, `DisposableStack`, `AsyncDisposableStack`, `Float16Array`).
* **Internal Setup:** It also sets up internal properties within the native context (e.g., `valid_iterator_wrapper_map`, helper maps for iterator helpers).
* **Builtins:** It heavily uses `Builtin::k...` to link JavaScript methods to their C++ implementations.

**Plan:**

1. **Functionality:** Describe the code as initializing iterator helpers and setting up various experimental JavaScript features on the global object.
2. **Torque:** Explain that `.cc` indicates C++ and `.tq` indicates Torque, so this would be a Torque file if the extension was `.tq`.
3. **JavaScript Relationship:** Provide JavaScript examples demonstrating the usage of the installed iterator helper methods (e.g., `map`, `filter`, `reduce`) and the experimental features (e.g., `Promise.try`, Set methods, `ShadowRealm`).
4. **Logic Reasoning:**  For the iterator helpers, show how input arrays and functions lead to specific output arrays.
5. **Common Errors:**  Illustrate common mistakes when using iterators or experimental features.
6. **Overall Function:** Summarize that this part of the `bootstrapper.cc` focuses on extending the core JavaScript language with iterator functionalities and experimental features by installing built-in functions and objects.
好的，我们来分析一下这段 v8 源代码片段的功能。

**功能列举:**

这段代码的主要功能是初始化和安装与 **迭代器 (Iterator)** 相关的特性，以及一些其他的实验性 JavaScript 特性到 V8 的全局环境中。具体来说，它做了以下几件事：

1. **初始化 `ValidIteratorWrapperMap`:**  创建并设置用于存储有效迭代器包装器的 Map。这可能用于跟踪和管理自定义迭代器的原型。

2. **初始化 `%IteratorHelperPrototype%`:**
   - 创建 `Iterator Helper` 的原型对象。
   - 将其原型链设置为标准的 `iterator_prototype`。
   - 安装 `next` 和 `return` 方法，这是所有迭代器都需要的方法。
   - 在标准的 `iterator_prototype` 上安装了一系列迭代器辅助方法，例如 `reduce`、`toArray`、`forEach`、`some`、`every`、`find`。
   - 安装了 `Symbol.toStringTag` 的 getter 和 setter，用于自定义迭代器的字符串表示。
   - 安装了 `constructor` 的 getter 和 setter。

3. **安装迭代器助手 (Iterator Helpers):**
   - 使用宏 `INSTALL_ITERATOR_HELPER` 和 `ITERATOR_HELPERS` 定义并安装了一系列新的迭代器助手方法，如 `map`、`filter`、`take`、`drop`、`flatMap`。
   - 为每个助手方法创建了一个特定的 Map (例如 `iterator_map_helper_map`)，用于存储其内部状态。
   - 将这些助手方法安装到 `iterator_prototype` 上。

4. **初始化实验性全局函数 (基于 Feature Flags):**
   - 根据 V8 的特性标记 (`v8_flags`)，有条件地初始化和安装一些实验性的全局函数和对象：
     - `Atomics.pause`
     - `Promise.try`
     - `Set.prototype` 上的集合操作方法 (`union`, `intersection`, `difference`, `symmetricDifference`, `isSubsetOf`, `isSupersetOf`, `isDisjointFrom`)
     - `ShadowRealm` 及其原型方法 (`evaluate`, `importValue`)
     - 与共享内存相关的 `SharedStructType`, `SharedArray`, `Atomics.Mutex`, `Atomics.Condition`
     - `SharedArrayBuffer` (在特定条件下)
     - `FinalizationRegistry.prototype.cleanupSome`
     - `DisposableStack` 和 `AsyncDisposableStack` 及其原型方法 (`use`, `dispose`, `adopt`, `defer`, `move`)
     - `Float16Array` 及其相关功能
     - 与模块相关的 `AbstractModuleSource`
     - `RegExp.prototype` 的 `linear` getter
     - `Temporal` (惰性初始化) 和 `Date.prototype.toTemporalInstant` (惰性初始化)

**关于 `.tq` 扩展名:**

如果 `v8/src/init/bootstrapper.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。Torque 是 V8 用来编写高性能内置函数的一种领域特定语言。这段代码目前是 C++，它直接操作 V8 的内部结构。如果用 Torque 编写，则会以更抽象的方式描述这些操作，然后 Torque 编译器会生成相应的 C++ 代码。

**与 JavaScript 功能的关系及示例:**

这段代码直接影响了 JavaScript 中迭代器和一些新的语言特性的行为。以下是一些 JavaScript 示例：

**迭代器助手:**

```javascript
const numbers = [1, 2, 3, 4, 5];

// 使用 map 助手
const doubled = numbers.values().map(x => x * 2);
console.log([...doubled]); // 输出: [2, 4, 6, 8, 10]

// 使用 filter 助手
const even = numbers.values().filter(x => x % 2 === 0);
console.log([...even]); // 输出: [2, 4]

// 使用 reduce 助手
const sum = numbers.values().reduce((acc, curr) => acc + curr, 0);
console.log(sum); // 输出: 15
```

**Promise.try:**

```javascript
Promise.try(() => {
  // 可能会抛出异常的代码
  return someAsyncOperation();
}).then(result => {
  console.log("成功:", result);
}).catch(error => {
  console.error("失败:", error);
});
```

**Set 的集合操作:**

```javascript
const set1 = new Set([1, 2, 3]);
const set2 = new Set([3, 4, 5]);

const unionSet = set1.union(set2);
console.log([...unionSet]); // 输出: [1, 2, 3, 4, 5]

const intersectionSet = set1.intersection(set2);
console.log([...intersectionSet]); // 输出: [3]
```

**ShadowRealm:**

```javascript
if (globalThis.ShadowRealm) {
  const realm = new ShadowRealm();
  const result = realm.evaluate("1 + 2");
  console.log(result); // 输出: 3
}
```

**代码逻辑推理及假设输入与输出:**

以 `INSTALL_ITERATOR_HELPER` 宏为例，假设我们正在安装 `map` 助手：

**假设输入:**

- `lowercase_name`: "map"
- `Capitalized_name`: "Map"
- `ALL_CAPS_NAME`: "MAP"
- `argc`: 1

**代码逻辑:**

1. 创建一个新的 Map 对象 (`map`)，其类型为 `JS_ITERATOR_MAP_HELPER_TYPE`。
2. 设置 `map` 的原型为 `iterator_helper_prototype`。
3. 设置 `map` 的构造函数为 `iterator_function`。
4. 将 `map` 存储在 `native_context` 的 `iterator_map_helper_map` 属性中。
5. 在 `iterator_prototype` 上安装一个名为 "map" 的函数，该函数关联到 `Builtin::kIteratorPrototypeMap` 内置函数，接受 1 个参数，并且需要适配调用约定 (`kAdapt`).

**假设输出:**

- 一个新的 `Map` 对象被创建并存储在 V8 的内部上下文中。
- `Iterator.prototype.map` 方法现在可用，并且它的内部实现由 `Builtin::kIteratorPrototypeMap` 定义。

**用户常见的编程错误:**

1. **误解迭代器助手的惰性求值:**  用户可能认为调用 `map` 或 `filter` 等助手方法会立即执行所有操作并返回一个新的数组，但实际上这些方法返回的是一个新的迭代器。需要使用展开运算符 (`...`) 或 `toArray()` 等方法来触发实际的计算。

   ```javascript
   const numbers = [1, 2, 3];
   const doubledIterator = numbers.values().map(x => x * 2);
   console.log(doubledIterator); // 输出: Object [Array Iterator] {} (而不是 [2, 4, 6])
   console.log([...doubledIterator]); // 正确输出: [2, 4, 6]
   ```

2. **在不支持的 JavaScript 环境中使用实验性特性:**  用户可能会在旧版本的浏览器或 Node.js 环境中使用 `ShadowRealm` 或集合操作方法，导致代码出错。应该在使用前进行特性检测。

   ```javascript
   if (Set.prototype.union) {
     const set1 = new Set([1, 2]);
     const set2 = new Set([2, 3]);
     const unionSet = set1.union(set2);
     console.log([...unionSet]);
   } else {
     console.log("当前环境不支持 Set.prototype.union");
   }
   ```

3. **不理解 `DisposableStack` 和 `AsyncDisposableStack` 的生命周期:** 用户可能忘记调用 `dispose()` 或 `disposeAsync()` 来释放资源，或者在使用后继续访问已释放的资源。

   ```javascript
   const stack = new DisposableStack();
   const resource = acquireResource();
   stack.defer(() => releaseResource(resource));
   // ... 使用 resource ...
   // 忘记在不再需要时调用 stack.dispose(); 可能导致资源泄漏
   ```

**归纳其功能 (作为第 9 部分):**

作为引导过程的第 9 部分，这段代码专注于 **扩展 JavaScript 的核心功能，特别是与迭代器相关的能力，并有条件地引入一些新的、实验性的语言特性**。它通过在内置的原型对象上安装方法和创建新的全局对象来实现这一点，从而使得开发者能够在 JavaScript 代码中使用这些新的能力。这一步对于构建一个更强大和更现代的 JavaScript 运行时至关重要。

希望这个详细的分析能够帮助你理解这段代码的功能。

### 提示词
```
这是目录为v8/src/init/bootstrapper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/init/bootstrapper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
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
      map->A
```