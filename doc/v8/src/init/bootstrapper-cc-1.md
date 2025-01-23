Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `v8/src/init/bootstrapper.cc` file. They are asking for it as the second part of an 11-part explanation.

Here's a breakdown of the code's functionality:

1. **Creation of Fundamental Function Objects:** The code initializes and configures basic function objects, including an "empty function". This involves setting up its script, scope, and shared function info.

2. **Creation of Function Maps for Different Modes:**  It generates different `Map` objects (V8's internal representation of object structure) for functions based on whether they are in strict or sloppy mode and whether they have a prototype. This is crucial for V8's optimization and runtime behavior.

3. **Handling `ThrowTypeError` Intrinsic:**  It creates a special function (`ThrowTypeError`) that is used when attempting to perform forbidden operations (like setting properties on non-writable objects). It carefully sets up the properties of this function to be non-configurable.

4. **Creation of the `Object` Constructor:** The code sets up the foundational `Object` constructor function. This includes defining its initial map, creating its prototype object, and setting up the prototype chain. It also creates specialized maps for objects created with `Object.create(null)`.

5. **Creation of Iterator and Async Iterator Related Objects:**  It defines the prototypes and supporting functions for iterators and async iterators, which are essential for `for...of` loops and asynchronous operations.

6. **Creation of Async Function Maps:** Similar to regular functions, it creates specific `Map` objects for async functions.

7. **Creation of Proxy Maps:**  It sets up the maps for `Proxy` objects, distinguishing between callable and constructable proxies.

8. **Helper Functions for Function Creation and Installation:**  The code includes utility functions for creating and installing functions as properties on objects.

9. **Handling Restricted Function Properties:**  It deals with the special "arguments" and "caller" properties of functions, especially in strict mode where they might throw errors if accessed.

10. **Integration with Global Context:**  The code is involved in setting up the global context and the global objects (`globalThis`).

To summarize the functionality for Part 2 of 11, I should focus on the core aspects handled in this specific snippet.这是 `v8/src/init/bootstrapper.cc` 的一部分，主要负责 **创建和初始化 V8 引擎中一些核心的内置函数和对象**。

由于代码中没有 `.tq` 结尾的文件名，因此它不是 V8 Torque 源代码。

这段代码与 JavaScript 的核心功能密切相关，因为它创建了诸如 `Object` 构造函数、不同模式（严格模式和非严格模式）下的函数对象、迭代器和异步迭代器相关的原型和函数等基础结构。这些都是 JavaScript 语言的基础组成部分。

**功能归纳 (针对第 2 部分):**

这段代码片段的主要功能是 **创建和配置 V8 引擎中用于表示函数和对象的基本结构**。这包括：

1. **创建空函数 (Empty Function):**  创建一个基础的空函数对象，作为构建其他函数的基础。
2. **创建不同模式下的函数 Map (Function Maps):**  为不同类型的函数（例如，严格模式函数、非严格模式函数、带有或不带有原型的函数）创建并注册对应的 `Map` 对象。`Map` 在 V8 中用于描述对象的结构和属性，对其性能至关重要。
3. **创建 `ThrowTypeError` 内置函数:**  创建一个特殊的内置函数，用于在违反某些 JavaScript 规范时抛出 `TypeError`。
4. **创建 `Object` 构造函数及其原型:**  创建 JavaScript 中最基础的 `Object` 构造函数及其原型对象。
5. **创建迭代器和异步迭代器相关的原型和函数:**  初始化与迭代器（`Symbol.iterator`）和异步迭代器（`Symbol.asyncIterator`）相关的对象和函数，为 `for...of` 循环和异步编程提供支持。
6. **创建异步函数相关的 Map:**  为异步函数创建特定的 `Map` 对象。
7. **创建 `Proxy` 相关的 Map:**  为 `Proxy` 对象创建不同的 `Map`，区分可调用和可构造的 `Proxy`。
8. **安装全局 `this` 绑定:**  设置全局执行上下文中的 `this` 绑定。
9. **创建全局对象:**  创建和初始化全局对象 (`globalThis` 或 `window`)。
10. **处理受限的函数属性 (`arguments` 和 `caller`):**  为函数对象设置 `arguments` 和 `caller` 属性的访问器，特别是在严格模式下，访问这些属性可能会抛出错误。

**与 JavaScript 功能的关系及示例:**

这段代码创建的基础结构直接影响着我们在 JavaScript 中使用的各种函数和对象：

**1. 创建空函数:**

```javascript
// 这部分功能在 V8 内部，但我们可以理解为创建了类似这样的基础函数
const emptyFunction = function() {};
```

**2. 创建不同模式下的函数 Map:**

```javascript
// 严格模式函数与非严格模式函数在 V8 内部有不同的表示
function sloppyFunction() { return arguments.callee; } // 非严格模式，允许访问 arguments.callee
function strictFunction() { "use strict"; return arguments.callee; } // 严格模式，访问 arguments.callee 会报错
```

**3. 创建 `ThrowTypeError` 内置函数:**

```javascript
Object.preventExtensions({});
const obj = {};
Object.defineProperty(obj, 'p', { writable: false });
obj.p = 10; // 这会触发内部的 ThrowTypeError (严格模式下)

function setter() { "use strict"; this.x = 10; }
const o = Object.defineProperty({}, 'y', { set: setter });
o.y = 20; // 同样可能触发 ThrowTypeError
```

**4. 创建 `Object` 构造函数及其原型:**

```javascript
const obj1 = new Object(); // 使用 Object 构造函数创建对象
const obj2 = {};          // 字面量创建对象，其原型是 Object.prototype

console.log(obj1.__proto__ === Object.prototype); // true
console.log(obj2.__proto__ === Object.prototype); // true
```

**5. 创建迭代器和异步迭代器相关的原型和函数:**

```javascript
// 迭代器示例
const iterable = [1, 2, 3];
const iterator = iterable[Symbol.iterator]();
console.log(iterator.next()); // { value: 1, done: false }

// 异步迭代器示例
async function* asyncGenerator() {
  yield 1;
  await new Promise(resolve => setTimeout(resolve, 100));
  yield 2;
}

const asyncIterator = asyncGenerator();
asyncIterator.next().then(result => console.log(result)); // 输出 Promise，resolve 后打印 { value: 1, done: false }
```

**6. 创建异步函数相关的 Map:**

```javascript
async function myFunction() {
  await Promise.resolve();
  return 'done';
}
```

**7. 创建 `Proxy` 相关的 Map:**

```javascript
const handler = {
  get: function(target, prop, receiver) {
    console.log(`Getting property ${prop}!`);
    return target[prop];
  }
};
const proxy = new Proxy({}, handler);
proxy.a; // 会触发 handler.get
```

**代码逻辑推理与假设输入输出:**

**例子： `CreateSloppyModeFunctionMaps` 函数**

**假设输入：**  一个已经创建好的空函数对象 `empty`。

**代码逻辑：**  该函数内部调用 `factory->CreateSloppyFunctionMap` 来创建不同类型的非严格模式函数的 `Map` 对象，并使用 `native_context()->set_..._map` 将这些 `Map` 对象存储到本地上下文 (native context) 中。不同的 `CreateSloppyFunctionMap` 调用会创建针对不同特性的非严格模式函数的 `Map`，例如是否带有可写原型。

**输出：**  在 `native_context_` 中设置了多个与非严格模式函数相关的 `Map` 对象，例如：
- `sloppy_function_without_prototype_map`
- `sloppy_function_with_readonly_prototype_map`
- `sloppy_function_map` (对应带有可写原型的非严格模式函数)
- `sloppy_function_with_name_map` (对应带有名称和可写原型的非严格模式函数)

**用户常见的编程错误示例:**

与这段代码相关的用户常见编程错误可能不太直接，因为这段代码是在 V8 引擎内部执行的。但是，理解这些底层的结构有助于理解某些 JavaScript 行为和可能出现的错误：

1. **在严格模式下访问 `arguments.callee` 或 `arguments.caller`:**  这是由于 V8 在创建严格模式函数 Map 时，会禁止这些属性的访问，从而在运行时抛出 `TypeError`。

   ```javascript
   function strictModeFunction() {
       "use strict";
       return arguments.callee; // TypeError: 'caller', 'callee', and 'arguments' properties may not be accessed on strict mode functions or the arguments objects for calls to them
   }
   ```

2. **误解原型链:** 理解 `Object` 构造函数及其原型对象的关系是理解 JavaScript 原型继承的关键。对原型链的错误理解可能导致意外的行为或错误。

   ```javascript
   function MyClass() {}
   const instance = new MyClass();
   console.log(instance.__proto__ === MyClass.prototype); // true
   console.log(MyClass.prototype.__proto__ === Object.prototype); // true
   ```

总而言之，这段代码是 V8 引擎启动和初始化过程中的关键部分，它奠定了 JavaScript 运行时的基础结构。了解其功能有助于更深入地理解 JavaScript 的工作原理。

### 提示词
```
这是目录为v8/src/init/bootstrapper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/init/bootstrapper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
ring("() {}");
  DirectHandle<Script> script = factory()->NewScript(source);
  script->set_type(Script::Type::kNative);
  DirectHandle<WeakFixedArray> infos = factory()->NewWeakFixedArray(2);
  script->set_infos(*infos);
  ReadOnlyRoots roots{isolate()};
  Tagged<SharedFunctionInfo> sfi = empty_function->shared();
  sfi->set_raw_scope_info(roots.empty_function_scope_info());
  sfi->SetScript(isolate(), roots, *script, 1);
  sfi->UpdateFunctionMapIndex();

  return empty_function;
}

void Genesis::CreateSloppyModeFunctionMaps(Handle<JSFunction> empty) {
  Factory* factory = isolate_->factory();
  DirectHandle<Map> map;

  //
  // Allocate maps for sloppy functions without prototype.
  //
  map = factory->CreateSloppyFunctionMap(FUNCTION_WITHOUT_PROTOTYPE, empty);
  native_context()->set_sloppy_function_without_prototype_map(*map);

  //
  // Allocate maps for sloppy functions with readonly prototype.
  //
  map =
      factory->CreateSloppyFunctionMap(FUNCTION_WITH_READONLY_PROTOTYPE, empty);
  native_context()->set_sloppy_function_with_readonly_prototype_map(*map);

  //
  // Allocate maps for sloppy functions with writable prototype.
  //
  map = factory->CreateSloppyFunctionMap(FUNCTION_WITH_WRITEABLE_PROTOTYPE,
                                         empty);
  native_context()->set_sloppy_function_map(*map);

  map = factory->CreateSloppyFunctionMap(
      FUNCTION_WITH_NAME_AND_WRITEABLE_PROTOTYPE, empty);
  native_context()->set_sloppy_function_with_name_map(*map);
}

DirectHandle<JSFunction> Genesis::GetThrowTypeErrorIntrinsic() {
  if (!restricted_properties_thrower_.is_null()) {
    return restricted_properties_thrower_;
  }
  Handle<String> name = factory()->empty_string();
  Handle<JSFunction> function = CreateFunctionForBuiltinWithoutPrototype(
      isolate(), name, Builtin::kStrictPoisonPillThrower, 0, kAdapt);

  // %ThrowTypeError% must have a name property with an empty string value. Per
  // spec, ThrowTypeError's name is non-configurable, unlike ordinary functions'
  // name property. To redefine it to be non-configurable, use
  // SetOwnPropertyIgnoreAttributes.
  JSObject::SetOwnPropertyIgnoreAttributes(
      function, factory()->name_string(), factory()->empty_string(),
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY))
      .Assert();

  // length needs to be non configurable.
  Handle<Object> value(Smi::FromInt(function->length()), isolate());
  JSObject::SetOwnPropertyIgnoreAttributes(
      function, factory()->length_string(), value,
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY))
      .Assert();

  if (JSObject::PreventExtensions(isolate_, function, kThrowOnError)
          .IsNothing()) {
    DCHECK(false);
  }

  JSObject::MigrateSlowToFast(function, 0, "Bootstrapping");

  restricted_properties_thrower_ = function;
  return function;
}

void Genesis::CreateStrictModeFunctionMaps(Handle<JSFunction> empty) {
  Factory* factory = isolate_->factory();
  DirectHandle<Map> map;

  //
  // Allocate maps for strict functions without prototype.
  //
  map = factory->CreateStrictFunctionMap(FUNCTION_WITHOUT_PROTOTYPE, empty);
  native_context()->set_strict_function_without_prototype_map(*map);

  map = factory->CreateStrictFunctionMap(METHOD_WITH_NAME, empty);
  native_context()->set_method_with_name_map(*map);

  //
  // Allocate maps for strict functions with writable prototype.
  //
  map = factory->CreateStrictFunctionMap(FUNCTION_WITH_WRITEABLE_PROTOTYPE,
                                         empty);
  native_context()->set_strict_function_map(*map);

  map = factory->CreateStrictFunctionMap(
      FUNCTION_WITH_NAME_AND_WRITEABLE_PROTOTYPE, empty);
  native_context()->set_strict_function_with_name_map(*map);

  //
  // Allocate maps for strict functions with readonly prototype.
  //
  map =
      factory->CreateStrictFunctionMap(FUNCTION_WITH_READONLY_PROTOTYPE, empty);
  native_context()->set_strict_function_with_readonly_prototype_map(*map);

  //
  // Allocate map for class functions.
  //
  map = factory->CreateClassFunctionMap(empty);
  native_context()->set_class_function_map(*map);

  // Now that the strict mode function map is available, set up the
  // restricted "arguments" and "caller" getters.
  AddRestrictedFunctionProperties(empty);
}

void Genesis::CreateObjectFunction(DirectHandle<JSFunction> empty_function) {
  Factory* factory = isolate_->factory();

  // --- O b j e c t ---
  int inobject_properties = JSObject::kInitialGlobalObjectUnusedPropertiesCount;
  int instance_size = JSObject::kHeaderSize + kTaggedSize * inobject_properties;

  DirectHandle<JSFunction> object_fun =
      CreateFunction(isolate_, factory->Object_string(), JS_OBJECT_TYPE,
                     instance_size, inobject_properties, factory->null_value(),
                     Builtin::kObjectConstructor, 1, kDontAdapt);
  native_context()->set_object_function(*object_fun);

  {
    // Finish setting up Object function's initial map.
    Tagged<Map> initial_map = object_fun->initial_map();
    initial_map->set_elements_kind(HOLEY_ELEMENTS);
  }

  // Allocate a new prototype for the object function.
  Handle<JSObject> object_function_prototype =
      factory->NewFunctionPrototype(object_fun);

  {
    DirectHandle<Map> map = Map::Copy(
        isolate(), handle(object_function_prototype->map(), isolate()),
        "EmptyObjectPrototype");
    map->set_is_prototype_map(true);
    // Ban re-setting Object.prototype.__proto__ to prevent Proxy security bug
    map->set_is_immutable_proto(true);
    object_function_prototype->set_map(isolate(), *map);
  }

  // Complete setting up empty function.
  {
    DirectHandle<Map> empty_function_map(empty_function->map(), isolate_);
    Map::SetPrototype(isolate(), empty_function_map, object_function_prototype);
  }

  native_context()->set_initial_object_prototype(*object_function_prototype);
  JSFunction::SetPrototype(object_fun, object_function_prototype);
  object_function_prototype->map()->set_instance_type(JS_OBJECT_PROTOTYPE_TYPE);
  {
    // Set up slow map for Object.create(null) instances without in-object
    // properties.
    Handle<Map> map(object_fun->initial_map(), isolate_);
    map = Map::CopyInitialMapNormalized(isolate(), map);
    Map::SetPrototype(isolate(), map, factory->null_value());
    native_context()->set_slow_object_with_null_prototype_map(*map);

    // Set up slow map for literals with too many properties.
    map = Map::Copy(isolate(), map, "slow_object_with_object_prototype_map");
    Map::SetPrototype(isolate(), map, object_function_prototype);
    native_context()->set_slow_object_with_object_prototype_map(*map);
  }
}

namespace {

Handle<Map> CreateNonConstructorMap(Isolate* isolate, Handle<Map> source_map,
                                    Handle<JSObject> prototype,
                                    const char* reason) {
  Handle<Map> map = Map::Copy(isolate, source_map, reason);
  // Ensure the resulting map has prototype slot (it is necessary for storing
  // inital map even when the prototype property is not required).
  if (!map->has_prototype_slot()) {
    // Re-set the unused property fields after changing the instance size.
    int unused_property_fields = map->UnusedPropertyFields();
    map->set_instance_size(map->instance_size() + kTaggedSize);
    // The prototype slot shifts the in-object properties area by one slot.
    map->SetInObjectPropertiesStartInWords(
        map->GetInObjectPropertiesStartInWords() + 1);
    map->set_has_prototype_slot(true);
    map->SetInObjectUnusedPropertyFields(unused_property_fields);
  }
  map->set_is_constructor(false);
  Map::SetPrototype(isolate, map, prototype);
  return map;
}

}  // namespace

Handle<JSFunction> SimpleInstallFunction(Isolate* isolate,
                                         Handle<JSObject> base,
                                         const char* name, Builtin call,
                                         int len, AdaptArguments adapt,
                                         PropertyAttributes attrs) {
  // Although function name does not have to be internalized the property name
  // will be internalized during property addition anyway, so do it here now.
  Handle<String> internalized_name =
      isolate->factory()->InternalizeUtf8String(name);
  Handle<JSFunction> fun =
      SimpleCreateFunction(isolate, internalized_name, call, len, adapt);
  JSObject::AddProperty(isolate, base, internalized_name, fun, attrs);
  return fun;
}

void Genesis::CreateIteratorMaps(Handle<JSFunction> empty) {
  // Create iterator-related meta-objects.
  Handle<JSObject> iterator_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);

  InstallFunctionAtSymbol(isolate(), iterator_prototype,
                          factory()->iterator_symbol(), "[Symbol.iterator]",
                          Builtin::kReturnReceiver, 0, kAdapt);
  native_context()->set_initial_iterator_prototype(*iterator_prototype);
  CHECK_NE(iterator_prototype->map().ptr(),
           isolate_->initial_object_prototype()->map().ptr());
  iterator_prototype->map()->set_instance_type(JS_ITERATOR_PROTOTYPE_TYPE);

  Handle<JSObject> generator_object_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);
  native_context()->set_initial_generator_prototype(
      *generator_object_prototype);
  JSObject::ForceSetPrototype(isolate(), generator_object_prototype,
                              iterator_prototype);
  Handle<JSObject> generator_function_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);
  JSObject::ForceSetPrototype(isolate(), generator_function_prototype, empty);

  InstallToStringTag(isolate(), generator_function_prototype,
                     "GeneratorFunction");
  JSObject::AddProperty(isolate(), generator_function_prototype,
                        factory()->prototype_string(),
                        generator_object_prototype,
                        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));

  JSObject::AddProperty(isolate(), generator_object_prototype,
                        factory()->constructor_string(),
                        generator_function_prototype,
                        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));
  InstallToStringTag(isolate(), generator_object_prototype, "Generator");
  SimpleInstallFunction(isolate(), generator_object_prototype, "next",
                        Builtin::kGeneratorPrototypeNext, 1, kDontAdapt);
  SimpleInstallFunction(isolate(), generator_object_prototype, "return",
                        Builtin::kGeneratorPrototypeReturn, 1, kDontAdapt);
  SimpleInstallFunction(isolate(), generator_object_prototype, "throw",
                        Builtin::kGeneratorPrototypeThrow, 1, kDontAdapt);

  // Internal version of generator_prototype_next, flagged as non-native such
  // that it doesn't show up in Error traces.
  DirectHandle<JSFunction> generator_next_internal =
      SimpleCreateFunction(isolate(), factory()->next_string(),
                           Builtin::kGeneratorPrototypeNext, 1, kDontAdapt);
  generator_next_internal->shared()->set_native(false);
  native_context()->set_generator_next_internal(*generator_next_internal);

  // Internal version of async module functions, flagged as non-native such
  // that they don't show up in Error traces.
  {
    DirectHandle<JSFunction> async_module_evaluate_internal =
        SimpleCreateFunction(isolate(), factory()->next_string(),
                             Builtin::kAsyncModuleEvaluate, 1, kDontAdapt);
    async_module_evaluate_internal->shared()->set_native(false);
    native_context()->set_async_module_evaluate_internal(
        *async_module_evaluate_internal);
  }

  // Create maps for generator functions and their prototypes.  Store those
  // maps in the native context. The "prototype" property descriptor is
  // writable, non-enumerable, and non-configurable (as per ES6 draft
  // 04-14-15, section 25.2.4.3).
  // Generator functions do not have "caller" or "arguments" accessors.
  DirectHandle<Map> map;
  map = CreateNonConstructorMap(isolate(), isolate()->strict_function_map(),
                                generator_function_prototype,
                                "GeneratorFunction");
  native_context()->set_generator_function_map(*map);

  map = CreateNonConstructorMap(
      isolate(), isolate()->strict_function_with_name_map(),
      generator_function_prototype, "GeneratorFunction with name");
  native_context()->set_generator_function_with_name_map(*map);

  DirectHandle<JSFunction> object_function(native_context()->object_function(),
                                           isolate());
  DirectHandle<Map> generator_object_prototype_map = Map::Create(isolate(), 0);
  Map::SetPrototype(isolate(), generator_object_prototype_map,
                    generator_object_prototype);
  native_context()->set_generator_object_prototype_map(
      *generator_object_prototype_map);
}

void Genesis::CreateAsyncIteratorMaps(Handle<JSFunction> empty) {
  // %AsyncIteratorPrototype%
  // proposal-async-iteration/#sec-asynciteratorprototype
  Handle<JSObject> async_iterator_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);

  InstallFunctionAtSymbol(
      isolate(), async_iterator_prototype, factory()->async_iterator_symbol(),
      "[Symbol.asyncIterator]", Builtin::kReturnReceiver, 0, kAdapt);
  native_context()->set_initial_async_iterator_prototype(
      *async_iterator_prototype);

  // %AsyncFromSyncIteratorPrototype%
  // proposal-async-iteration/#sec-%asyncfromsynciteratorprototype%-object
  Handle<JSObject> async_from_sync_iterator_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);
  SimpleInstallFunction(isolate(), async_from_sync_iterator_prototype, "next",
                        Builtin::kAsyncFromSyncIteratorPrototypeNext, 1,
                        kDontAdapt);
  SimpleInstallFunction(isolate(), async_from_sync_iterator_prototype, "return",
                        Builtin::kAsyncFromSyncIteratorPrototypeReturn, 1,
                        kDontAdapt);
  SimpleInstallFunction(isolate(), async_from_sync_iterator_prototype, "throw",
                        Builtin::kAsyncFromSyncIteratorPrototypeThrow, 1,
                        kDontAdapt);

  InstallToStringTag(isolate(), async_from_sync_iterator_prototype,
                     "Async-from-Sync Iterator");

  JSObject::ForceSetPrototype(isolate(), async_from_sync_iterator_prototype,
                              async_iterator_prototype);

  DirectHandle<Map> async_from_sync_iterator_map =
      factory()->NewContextfulMapForCurrentContext(
          JS_ASYNC_FROM_SYNC_ITERATOR_TYPE,
          JSAsyncFromSyncIterator::kHeaderSize);
  Map::SetPrototype(isolate(), async_from_sync_iterator_map,
                    async_from_sync_iterator_prototype);
  native_context()->set_async_from_sync_iterator_map(
      *async_from_sync_iterator_map);

  // Async Generators
  Handle<JSObject> async_generator_object_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);
  Handle<JSObject> async_generator_function_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);

  // %AsyncGenerator% / %AsyncGeneratorFunction%.prototype
  JSObject::ForceSetPrototype(isolate(), async_generator_function_prototype,
                              empty);

  // The value of AsyncGeneratorFunction.prototype.prototype is the
  //     %AsyncGeneratorPrototype% intrinsic object.
  // This property has the attributes
  //     { [[Writable]]: false, [[Enumerable]]: false, [[Configurable]]: true }.
  JSObject::AddProperty(isolate(), async_generator_function_prototype,
                        factory()->prototype_string(),
                        async_generator_object_prototype,
                        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));
  JSObject::AddProperty(isolate(), async_generator_object_prototype,
                        factory()->constructor_string(),
                        async_generator_function_prototype,
                        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));
  InstallToStringTag(isolate(), async_generator_function_prototype,
                     "AsyncGeneratorFunction");

  // %AsyncGeneratorPrototype%
  JSObject::ForceSetPrototype(isolate(), async_generator_object_prototype,
                              async_iterator_prototype);
  native_context()->set_initial_async_generator_prototype(
      *async_generator_object_prototype);

  InstallToStringTag(isolate(), async_generator_object_prototype,
                     "AsyncGenerator");
  SimpleInstallFunction(isolate(), async_generator_object_prototype, "next",
                        Builtin::kAsyncGeneratorPrototypeNext, 1, kDontAdapt);
  SimpleInstallFunction(isolate(), async_generator_object_prototype, "return",
                        Builtin::kAsyncGeneratorPrototypeReturn, 1, kDontAdapt);
  SimpleInstallFunction(isolate(), async_generator_object_prototype, "throw",
                        Builtin::kAsyncGeneratorPrototypeThrow, 1, kDontAdapt);

  // Create maps for generator functions and their prototypes.  Store those
  // maps in the native context. The "prototype" property descriptor is
  // writable, non-enumerable, and non-configurable (as per ES6 draft
  // 04-14-15, section 25.2.4.3).
  // Async Generator functions do not have "caller" or "arguments" accessors.
  DirectHandle<Map> map;
  map = CreateNonConstructorMap(isolate(), isolate()->strict_function_map(),
                                async_generator_function_prototype,
                                "AsyncGeneratorFunction");
  native_context()->set_async_generator_function_map(*map);

  map = CreateNonConstructorMap(
      isolate(), isolate()->strict_function_with_name_map(),
      async_generator_function_prototype, "AsyncGeneratorFunction with name");
  native_context()->set_async_generator_function_with_name_map(*map);

  DirectHandle<JSFunction> object_function(native_context()->object_function(),
                                           isolate());
  DirectHandle<Map> async_generator_object_prototype_map =
      Map::Create(isolate(), 0);
  Map::SetPrototype(isolate(), async_generator_object_prototype_map,
                    async_generator_object_prototype);
  native_context()->set_async_generator_object_prototype_map(
      *async_generator_object_prototype_map);
}

void Genesis::CreateAsyncFunctionMaps(Handle<JSFunction> empty) {
  // %AsyncFunctionPrototype% intrinsic
  Handle<JSObject> async_function_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);
  JSObject::ForceSetPrototype(isolate(), async_function_prototype, empty);

  InstallToStringTag(isolate(), async_function_prototype, "AsyncFunction");

  DirectHandle<Map> map =
      Map::Copy(isolate(), isolate()->strict_function_without_prototype_map(),
                "AsyncFunction");
  Map::SetPrototype(isolate(), map, async_function_prototype);
  native_context()->set_async_function_map(*map);

  map = Map::Copy(isolate(), isolate()->method_with_name_map(),
                  "AsyncFunction with name");
  Map::SetPrototype(isolate(), map, async_function_prototype);
  native_context()->set_async_function_with_name_map(*map);
}

void Genesis::CreateJSProxyMaps() {
  // Allocate maps for all Proxy types.
  // Next to the default proxy, we need maps indicating callable and
  // constructable proxies.
  Handle<Map> proxy_map = factory()->NewContextfulMapForCurrentContext(
      JS_PROXY_TYPE, JSProxy::kSize, TERMINAL_FAST_ELEMENTS_KIND);
  proxy_map->set_is_dictionary_map(true);
  proxy_map->set_may_have_interesting_properties(true);
  native_context()->set_proxy_map(*proxy_map);
  proxy_map->SetConstructor(native_context()->object_function());

  Handle<Map> proxy_callable_map =
      Map::Copy(isolate_, proxy_map, "callable Proxy");
  proxy_callable_map->set_is_callable(true);
  native_context()->set_proxy_callable_map(*proxy_callable_map);
  proxy_callable_map->SetConstructor(native_context()->function_function());

  DirectHandle<Map> proxy_constructor_map =
      Map::Copy(isolate_, proxy_callable_map, "constructor Proxy");
  proxy_constructor_map->set_is_constructor(true);
  native_context()->set_proxy_constructor_map(*proxy_constructor_map);

  {
    DirectHandle<Map> map = factory()->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSProxyRevocableResult::kSize,
        TERMINAL_FAST_ELEMENTS_KIND, 2);
    Map::EnsureDescriptorSlack(isolate_, map, 2);

    {  // proxy
      Descriptor d = Descriptor::DataField(isolate(), factory()->proxy_string(),
                                           JSProxyRevocableResult::kProxyIndex,
                                           NONE, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // revoke
      Descriptor d = Descriptor::DataField(
          isolate(), factory()->revoke_string(),
          JSProxyRevocableResult::kRevokeIndex, NONE, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }

    Map::SetPrototype(isolate(), map, isolate()->initial_object_prototype());
    map->SetConstructor(native_context()->object_function());

    native_context()->set_proxy_revocable_result_map(*map);
  }
}

namespace {
void ReplaceAccessors(Isolate* isolate, DirectHandle<Map> map,
                      Handle<String> name, PropertyAttributes attributes,
                      Handle<AccessorPair> accessor_pair) {
  Tagged<DescriptorArray> descriptors = map->instance_descriptors(isolate);
  InternalIndex entry = descriptors->SearchWithCache(isolate, *name, *map);
  Descriptor d = Descriptor::AccessorConstant(name, accessor_pair, attributes);
  descriptors->Replace(entry, &d);
}

void InitializeJSArrayMaps(Isolate* isolate,
                           DirectHandle<Context> native_context,
                           Handle<Map> initial_map) {
  // Replace all of the cached initial array maps in the native context with
  // the appropriate transitioned elements kind maps.
  Handle<Map> current_map = initial_map;
  ElementsKind kind = current_map->elements_kind();
  DCHECK_EQ(GetInitialFastElementsKind(), kind);
  DCHECK_EQ(PACKED_SMI_ELEMENTS, kind);
  DCHECK_EQ(Context::ArrayMapIndex(kind),
            Context::JS_ARRAY_PACKED_SMI_ELEMENTS_MAP_INDEX);
  native_context->set(Context::ArrayMapIndex(kind), *current_map,
                      UPDATE_WRITE_BARRIER, kReleaseStore);
  for (int i = GetSequenceIndexFromFastElementsKind(kind) + 1;
       i < kFastElementsKindCount; ++i) {
    Handle<Map> new_map;
    ElementsKind next_kind = GetFastElementsKindFromSequenceIndex(i);
    Tagged<Map> maybe_elements_transition = current_map->ElementsTransitionMap(
        isolate, ConcurrencyMode::kSynchronous);
    if (!maybe_elements_transition.is_null()) {
      new_map = handle(maybe_elements_transition, isolate);
    } else {
      new_map = Map::CopyAsElementsKind(isolate, current_map, next_kind,
                                        INSERT_TRANSITION);
    }
    DCHECK_EQ(next_kind, new_map->elements_kind());
    native_context->set(Context::ArrayMapIndex(next_kind), *new_map,
                        UPDATE_WRITE_BARRIER, kReleaseStore);
    current_map = new_map;
  }
}
}  // namespace

void Genesis::AddRestrictedFunctionProperties(DirectHandle<JSFunction> empty) {
  PropertyAttributes rw_attribs = static_cast<PropertyAttributes>(DONT_ENUM);
  DirectHandle<JSFunction> thrower = GetThrowTypeErrorIntrinsic();
  Handle<AccessorPair> accessors = factory()->NewAccessorPair();
  accessors->set_getter(*thrower);
  accessors->set_setter(*thrower);

  DirectHandle<Map> map(empty->map(), isolate());
  ReplaceAccessors(isolate(), map, factory()->arguments_string(), rw_attribs,
                   accessors);
  ReplaceAccessors(isolate(), map, factory()->caller_string(), rw_attribs,
                   accessors);
}

static void AddToWeakNativeContextList(Isolate* isolate,
                                       Tagged<Context> context) {
  DCHECK(IsNativeContext(context));
  Heap* heap = isolate->heap();
#ifdef DEBUG
  {
    DCHECK(IsUndefined(context->next_context_link(), isolate));
    // Check that context is not in the list yet.
    for (Tagged<Object> current = heap->native_contexts_list();
         !IsUndefined(current, isolate);
         current = Cast<Context>(current)->next_context_link()) {
      DCHECK(current != context);
    }
  }
#endif
  context->set(Context::NEXT_CONTEXT_LINK, heap->native_contexts_list(),
               UPDATE_WRITE_BARRIER);
  heap->set_native_contexts_list(context);
}

void Genesis::CreateRoots() {
  // Allocate the native context FixedArray first and then patch the
  // closure and extension object later (we need the empty function
  // and the global object, but in order to create those, we need the
  // native context).
  native_context_ = factory()->NewNativeContext();

  AddToWeakNativeContextList(isolate(), *native_context());
  isolate()->set_context(*native_context());
}

void Genesis::InstallGlobalThisBinding() {
  DirectHandle<ScopeInfo> scope_info =
      ReadOnlyRoots(isolate()).global_this_binding_scope_info_handle();
  DirectHandle<Context> context =
      factory()->NewScriptContext(native_context(), scope_info);

  // Go ahead and hook it up while we're at it.
  int slot = scope_info->ReceiverContextSlotIndex();
  DCHECK_EQ(slot, Context::MIN_CONTEXT_EXTENDED_SLOTS);
  context->set(slot, native_context()->global_proxy());

  Handle<ScriptContextTable> script_contexts(
      native_context()->script_context_table(), isolate());
  DirectHandle<ScriptContextTable> new_script_contexts =
      ScriptContextTable::Add(isolate(), script_contexts, context, false);
  native_context()->set_script_context_table(*new_script_contexts);
}

Handle<JSGlobalObject> Genesis::CreateNewGlobals(
    v8::Local<v8::ObjectTemplate> global_proxy_template,
    DirectHandle<JSGlobalProxy> global_proxy) {
  // The argument global_proxy_template aka data is an ObjectTemplateInfo.
  // It has a constructor pointer that points at global_constructor which is a
  // FunctionTemplateInfo.
  // The global_proxy_constructor is used to (re)initialize the
  // global_proxy. The global_proxy_constructor also has a prototype_template
  // pointer that points at js_global_object_template which is an
  // ObjectTemplateInfo.
  // That in turn has a constructor pointer that points at
  // js_global_object_constructor which is a FunctionTemplateInfo.
  // js_global_object_constructor is used to make js_global_object_function
  // js_global_object_function is used to make the new global_object.
  //
  // --- G l o b a l ---
  // Step 1: Create a fresh JSGlobalObject.
  DirectHandle<JSFunction> js_global_object_function;
  Handle<ObjectTemplateInfo> js_global_object_template;
  if (!global_proxy_template.IsEmpty()) {
    // Get prototype template of the global_proxy_template.
    DirectHandle<ObjectTemplateInfo> data =
        v8::Utils::OpenDirectHandle(*global_proxy_template);
    DirectHandle<FunctionTemplateInfo> global_constructor(
        Cast<FunctionTemplateInfo>(data->constructor()), isolate());
    Handle<Object> proto_template(global_constructor->GetPrototypeTemplate(),
                                  isolate());
    if (!IsUndefined(*proto_template, isolate())) {
      js_global_object_template = Cast<ObjectTemplateInfo>(proto_template);
    }
  }

  if (js_global_object_template.is_null()) {
    Handle<String> name = factory()->empty_string();
    Handle<JSObject> prototype =
        factory()->NewFunctionPrototype(isolate()->object_function());
    js_global_object_function = CreateFunctionForBuiltinWithPrototype(
        isolate(), name, Builtin::kIllegal, prototype, JS_GLOBAL_OBJECT_TYPE,
        JSGlobalObject::kHeaderSize, 0, MUTABLE, 0, kDontAdapt);
#ifdef DEBUG
    LookupIterator it(isolate(), prototype, factory()->constructor_string(),
                      LookupIterator::OWN_SKIP_INTERCEPTOR);
    DirectHandle<Object> value = Object::GetProperty(&it).ToHandleChecked();
    DCHECK(it.IsFound());
    DCHECK_EQ(*isolate()->object_function(), *value);
#endif
  } else {
    DirectHandle<FunctionTemplateInfo> js_global_object_constructor(
        Cast<FunctionTemplateInfo>(js_global_object_template->constructor()),
        isolate());
    js_global_object_function = ApiNatives::CreateApiFunction(
        isolate(), isolate()->native_context(), js_global_object_constructor,
        factory()->the_hole_value(), JS_GLOBAL_OBJECT_TYPE);
  }

  js_global_object_function->initial_map()->set_is_prototype_map(true);
  js_global_object_function->initial_map()->set_is_dictionary_map(true);
  js_global_object_function->initial_map()->set_may_have_interesting_properties(
      true);
  Handle<JSGlobalObject> global_object =
      factory()->NewJSGlobalObject(js_global_object_function);

  // Step 2: (re)initialize the global proxy object.
  DirectHandle<JSFunction> global_proxy_function;
  if (global_proxy_template.IsEmpty()) {
    Handle<String> name = factory()->empty_string();
    global_proxy_function = CreateFunctionForBuiltinWithPrototype(
        isolate(), name, Builtin::kIllegal, factory()->the_hole_value(),
        JS_GLOBAL_PROXY_TYPE, JSGlobalProxy::SizeWithEmbedderFields(0), 0,
        MUTABLE, 0, kDontAdapt);
  } else {
    DirectHandle<ObjectTemplateInfo> data =
        v8::Utils::OpenDirectHandle(*global_proxy_template);
    DirectHandle<FunctionTemplateInfo> global_constructor(
        Cast<FunctionTemplateInfo>(data->constructor()), isolate());
    global_proxy_function = ApiNatives::CreateApiFunction(
        isolate(), isolate()->native_context(), global_constructor,
        factory()->the_hole_value(), JS_GLOBAL_PROXY_TYPE);
  }
  global_proxy_function->initial_map()->set_is_access_check_needed(true);
  global_proxy_function->initial_map()->set_may_have_interesting_properties(
      true);
  native_context()->set_global_proxy_function(*global_proxy_function);

  // Set the global object as the (hidden) __proto__ of the global proxy after
  // ConfigureGlobalObject
  factory()->ReinitializeJSGlobalProxy(global_proxy, global_proxy_function);

  // Set up the pointer back from the global object to the global proxy.
  global_object->set_global_proxy(*global_proxy);
  // Set the native context of the global proxy.
  global_proxy->map()->set_map(isolate(), native_context()->meta_map());
  // Set the global proxy of the native context. If the native context has been
  // deserialized, the global proxy is already correctly set up by the
  // deserializer. Otherwise it's undefined.
  DCHECK(IsUndefined(native_context()->get(Context::GLOBAL_PROXY_INDEX),
                     isolate()) ||
         native_context()->global_proxy_object() == *global_proxy);
  native_context()->set_global_proxy_object(*global_proxy);

  return global_object;
}

void Genesis::HookUpGlobalProxy(DirectHandle<JSGlobalProxy> global_proxy) {
  // Re-initialize the global proxy with the global proxy function from the
  // snapshot, and then set up the link to the native context.
  DirectHandle<JSFunction> global_proxy_function(
      native_context()->global_proxy_function(), isolate());
  factory()->ReinitializeJSGlobalProxy(global_proxy, global_proxy_function);
  Handle<JSObject> global_object(
      Cast<JSObject>(native_context()->global_object()), isolate());
  JSObject::ForceSetPrototype(isolate(), global_proxy, global_object);
  global_proxy->map()->set_map(isolate(), native_context()->meta_map());
  DCHECK(native_context()->global_proxy() == *global_proxy);
}

void Genesis::HookUpGlobalObject(Handle<JSGlobalObject> global_object) {
  DirectHandle<JSGlobalObject> global_object_from_snapshot(
      Cast<JSGlobalObject>(native_context()->extension()), isolate());
  native_context()->set_extension(*global_object);
  native_context()->set_security_token(*global_object);

  TransferNamedProperties(global_object_from_snapshot, global_object);
  if (global_object_from_snapshot->HasDictionaryElements()) {
    JSObject::NormalizeElements(global_object);
  }
  DCHECK_EQ(global_object_from_snapshot->GetElementsKind(),
            global_object->GetElementsKind());
  TransferIndexedProperties(global_object_from_snapshot, global_object);
}

// See https://tc39.es/ecma262/#sec-ordinarycreatefromconstructor for details
// about intrinsicDefaultProto concept. In short it's about using proper
// prototype object from constructor's realm when
```