Response:
My thinking process to analyze the provided C++ code snippet goes like this:

1. **Identify the Core Functionality:** I start by reading through the code, looking for keywords and function names that suggest the main actions being performed. Keywords like `DefineOwnProperty`, `CreateDataProperty`, `GetOwnPropertyDescriptor`, `SetIntegrityLevel`, `PreventExtensions`, `IsExtensible`, `ToPrimitive`, and `GetOwnValuesOrEntries` immediately jump out. These point to fundamental operations related to JavaScript object properties.

2. **Group Related Functions:**  I notice groups of functions dealing with similar concepts. For instance, there are several variations of `DefineOwnProperty` and `CreateDataProperty`, suggesting different ways to add or modify properties. Similarly, `SetIntegrityLevel`, `PreventExtensions`, and `IsExtensible` are all about controlling the structure and mutability of objects.

3. **Connect to JavaScript Concepts:**  My goal is to explain this C++ code in the context of JavaScript. So, I mentally translate the C++ function names and logic to their corresponding JavaScript equivalents.

    * `DefineOwnProperty` -> `Object.defineProperty()`
    * `CreateDataProperty` -> Directly assigning a property (e.g., `obj.prop = value`)
    * `GetOwnPropertyDescriptor` -> `Object.getOwnPropertyDescriptor()`
    * `SetIntegrityLevel` -> `Object.seal()` and `Object.freeze()`
    * `PreventExtensions` -> `Object.preventExtensions()`
    * `IsExtensible` -> `Object.isExtensible()`
    * `ToPrimitive` -> The implicit conversion of objects to primitive values.
    * `GetOwnValues` and `GetOwnEntries` ->  Related to the iteration of object properties (e.g., through `for...in`, `Object.values()`, `Object.entries()`).

4. **Look for Conditional Logic and Edge Cases:** I pay attention to `if` statements and `switch` statements. These often indicate handling of different object types (e.g., `JSProxy`, `WasmObject`), different scenarios (e.g., checking for existing properties, handling exceptions), or performance optimizations (like the "fast path" in `GetOwnValuesOrEntries`).

5. **Infer Data Structures and Operations:**  Although I don't need to understand the C++ deeply, I note the presence of structures like `PropertyDescriptor` and classes like `LookupIterator`. These give hints about how V8 internally represents and manipulates object properties. The use of `Handle` suggests memory management within V8.

6. **Address Specific Instructions:**  The prompt asks about Torque (`.tq` files), JavaScript examples, code logic, and common errors.

    * **Torque:** I check if the file extension is `.tq`. In this case, it isn't, so I state that.
    * **JavaScript Examples:**  For functions with clear JavaScript equivalents, I provide simple examples demonstrating their usage.
    * **Code Logic:**  For more complex functions like `DefineOwnProperty`, I try to create a simplified scenario with hypothetical inputs and outputs to illustrate the decision-making process within the code (e.g., handling existing properties, different descriptor types).
    * **Common Errors:**  I think about the errors JavaScript developers often make when working with object properties, such as trying to redefine non-configurable properties or setting properties on non-extensible objects.

7. **Synthesize a Summary:** Finally, I combine my observations into a concise summary that captures the overall purpose of the code. I emphasize that this file is about the fundamental mechanisms for working with JavaScript object properties within the V8 engine.

8. **Review and Refine:** I reread my analysis to ensure accuracy, clarity, and completeness, making sure to address all parts of the original prompt. I check if the language is accessible to someone who understands JavaScript but might not be a V8 internals expert. I also ensure the explanation aligns with the provided code snippets. For instance, I see the code explicitly handles cases for `JSProxy` and `WasmObject`, so I make sure to mention those.

By following these steps, I can effectively analyze the C++ code snippet and explain its functionality in a way that is understandable and relevant to the context of JavaScript development.
这是 V8 源代码文件 `v8/src/objects/js-objects.cc` 的第三部分，它主要负责实现 JavaScript 对象的一些核心功能，特别是关于属性操作的部分。

**功能归纳:**

这部分代码主要集中在以下几个核心功能上：

1. **定义和修改对象属性 (`DefineOwnProperty`):**  实现了 JavaScript 中 `Object.defineProperty` 的底层逻辑。它允许定义或修改对象自身属性的特性，例如值、可写性、可枚举性和可配置性。代码详细处理了各种情况，包括属性已存在和不存在，数据属性和访问器属性的定义和修改。

2. **创建数据属性 (`CreateDataProperty`):**  提供了更简化的方式来创建新的数据属性，类似于直接赋值操作 (`object.property = value`)。

3. **添加私有字段 (`AddPrivateField`):**  处理向对象添加私有字段的逻辑，这涉及到不同的对象类型，例如普通对象和 `JSProxy`。

4. **获取自有属性描述符 (`GetOwnPropertyDescriptor`):**  实现了 JavaScript 中 `Object.getOwnPropertyDescriptor` 的底层逻辑。它返回一个对象自身属性的描述符，包含该属性的值和特性。代码中考虑了拦截器 (`Interceptor`) 的情况。

5. **设置对象的完整性级别 (`SetIntegrityLevel`):**  实现了 JavaScript 中 `Object.seal()` 和 `Object.freeze()` 的底层逻辑。它可以防止对象添加新属性 (seal 和 freeze) 并/或阻止删除和修改现有属性的特性 (freeze)。

6. **测试对象的完整性级别 (`TestIntegrityLevel`):**  实现了 JavaScript 中 `Object.isSealed()` 和 `Object.isFrozen()` 的底层逻辑。它检查对象是否已达到特定的完整性级别。

7. **阻止对象扩展 (`PreventExtensions`):**  实现了 JavaScript 中 `Object.preventExtensions()` 的底层逻辑。它可以阻止向对象添加新的属性。

8. **检查对象是否可扩展 (`IsExtensible`):**  实现了 JavaScript 中 `Object.isExtensible()` 的底层逻辑。它检查对象是否可以添加新的属性。

9. **转换为原始值 (`ToPrimitive` 和 `OrdinaryToPrimitive`):**  实现了 JavaScript 中对象到原始值的转换逻辑，这是许多操作符和函数中隐式调用的过程。它涉及到调用对象的 `Symbol.toPrimitive` 方法或 `valueOf` 和 `toString` 方法。

10. **获取自有属性的值或键值对 (`GetOwnValuesOrEntries`):**  实现了类似 `Object.values()` 和 `Object.entries()` 的功能，用于获取对象自身可枚举属性的值或键值对数组。代码中包含了一个优化的快速路径。

11. **设置原型 (`SetPrototype`):** 实现了 JavaScript 中 `Object.setPrototypeOf()` 的底层逻辑，允许修改对象的原型链。

12. **判断原型链中是否存在 Proxy (`HasProxyInPrototype`):**  检查对象的原型链中是否包含 `Proxy` 对象。

13. **判断是否为类代码对象 (`IsCodeLike`):**  用于判断对象是否像代码一样，这与 API 对象和模板有关。

14. **创建新的 JSObject (`New` 和 `NewWithMap`):**  提供了创建新的 `JSObject` 实例的方法，可以指定构造函数、`new.target` 和初始的 Map。

15. **创建没有属性的简单对象 (`ObjectCreate`):**  实现了 JavaScript 中 `Object.create(null)` 的部分底层逻辑，创建没有原型的对象。

16. **确保快速元素可写 (`EnsureWritableFastElements`):**  在需要修改元素时，确保使用写时复制 (COW) 机制的快速元素数组是可写的。

17. **获取对象头大小 (`GetHeaderSize`):**  根据对象的类型返回对象头的字节大小。

**关于 .tq 文件:**

该文件 `v8/src/objects/js-objects.cc` 的扩展名是 `.cc`，表明它是一个 C++ 源文件。如果文件名以 `.tq` 结尾，那么它将是一个 V8 Torque 源文件。Torque 是 V8 使用的一种领域特定语言，用于生成高效的 C++ 代码，特别是在运行时性能关键的部分。

**与 JavaScript 功能的关系及示例:**

这个 C++ 文件中的代码直接支撑着 JavaScript 中关于对象属性操作的各种功能。以下是一些 JavaScript 示例，与代码中的功能相对应：

* **`DefineOwnProperty`:**

```javascript
const obj = {};
Object.defineProperty(obj, 'a', {
  value: 42,
  writable: false,
  enumerable: true,
  configurable: false
});
```

* **`CreateDataProperty`:**

```javascript
const obj = {};
obj.b = 'hello'; // 相当于 CreateDataProperty
```

* **`GetOwnPropertyDescriptor`:**

```javascript
const obj = { c: 10 };
const descriptor = Object.getOwnPropertyDescriptor(obj, 'c');
console.log(descriptor); // 输出：{ value: 10, writable: true, enumerable: true, configurable: true }
```

* **`SetIntegrityLevel`:**

```javascript
const sealedObj = Object.seal({ d: 1 });
const frozenObj = Object.freeze({ e: 2 });
```

* **`PreventExtensions`:**

```javascript
const nonExtensibleObj = Object.preventExtensions({});
nonExtensibleObj.f = 3; // 严格模式下会报错，非严格模式下静默失败
```

* **`IsExtensible`:**

```javascript
const obj1 = {};
console.log(Object.isExtensible(obj1)); // 输出：true

const obj2 = Object.preventExtensions({});
console.log(Object.isExtensible(obj2)); // 输出：false
```

* **`ToPrimitive`:**

```javascript
const obj = {
  valueOf() { return 10; },
  toString() { return 'hello'; }
};
console.log(obj + 5); // 调用 valueOf，输出 15
console.log(String(obj)); // 调用 toString，输出 "hello"
```

* **`GetOwnValues` 和 `GetOwnEntries` (JavaScript 中对应 `Object.values` 和 `Object.entries`):**

```javascript
const obj = { a: 1, b: 2 };
console.log(Object.values(obj)); // 输出：[1, 2]
console.log(Object.entries(obj)); // 输出：[['a', 1], ['b', 2]]
```

* **`SetPrototype`:**

```javascript
const proto = { z: 100 };
const obj = { x: 1 };
Object.setPrototypeOf(obj, proto);
console.log(obj.z); // 输出：100
```

* **`ObjectCreate`:**

```javascript
const nullProtoObj = Object.create(null);
console.log(nullProtoObj.toString); // 输出：undefined
```

**代码逻辑推理 (假设输入与输出):**

以 `DefineOwnProperty` 为例，假设有以下输入：

* `isolate`: V8 的隔离环境。
* `object`: 一个 JavaScript 对象，例如 `{ a: 1 }`。
* `property_name`: 属性名，例如 "a"。
* `desc`: 属性描述符，例如 `{ value: 2, writable: false }`。
* `should_throw`:  一个布尔值，指示操作失败时是否应该抛出错误。

如果对象 `object` 已经有属性 "a"，并且其 `configurable` 特性为 `false`，那么尝试将 "a" 的 `writable` 特性修改为 `false` 将会成功，因为没有违反不可配置的约束。 输出将是 `Just(true)`，表示操作成功。

但是，如果 `object` 的 "a" 属性的 `configurable` 为 `false`，并且尝试修改其 `value`，这在不可配置的情况下是被允许的。

如果 `object` 的 "a" 属性的 `configurable` 为 `false`，并且尝试将其重新定义为访问器属性，或者修改其 `configurable` 特性，那么如果 `should_throw` 为 true，则会抛出一个 `TypeError` 异常；如果 `should_throw` 为 false，则操作失败，输出可能是 `Nothing<bool>()` 或 `Just(false)`，具体取决于 V8 的实现细节。

**用户常见的编程错误:**

* **尝试修改不可配置的属性:**

```javascript
const obj = {};
Object.defineProperty(obj, 'prop', {
  value: 10,
  configurable: false
});

// 错误示例：尝试修改不可配置的属性
Object.defineProperty(obj, 'prop', { value: 20 }); // TypeError: Cannot redefine property: prop
```

* **在不可扩展的对象上添加新属性:**

```javascript
const obj = Object.preventExtensions({});
obj.newProp = 5; // 严格模式下 TypeError，非严格模式下静默失败
```

* **尝试删除不可删除的属性:**

```javascript
const obj = {};
Object.defineProperty(obj, 'prop', {
  value: 10,
  configurable: false
});

delete obj.prop; // 在严格模式下会抛出 TypeError，非严格模式下返回 false
```

* **混淆 `Object.defineProperty` 和直接赋值:**  直接赋值不会影响属性的 `enumerable` 和 `configurable` 特性，而 `Object.defineProperty` 可以精确控制这些特性。

**总结该部分的功能:**

总而言之，`v8/src/objects/js-objects.cc` 的这部分代码是 V8 引擎中处理 JavaScript 对象属性操作的核心实现。它负责属性的定义、修改、查询、删除以及对象完整性级别的管理，这些功能是 JavaScript 语言基础的重要组成部分。它确保了 JavaScript 开发者能够按照语言规范对对象进行各种操作。

### 提示词
```
这是目录为v8/src/objects/js-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
>get())) {
        RETURN_FAILURE(
            isolate, GetShouldThrow(isolate, should_throw),
            NewTypeError(MessageTemplate::kRedefineDisallowed,
                         it != nullptr ? it->GetName() : property_name));
      }
    }
  }

  // 9. If O is not undefined, then:
  if (it != nullptr) {
    // 9a. For each field of Desc that is present, set the corresponding
    // attribute of the property named P of object O to the value of the field.
    PropertyAttributes attrs = NONE;

    if (desc->has_enumerable()) {
      attrs = static_cast<PropertyAttributes>(
          attrs | (desc->enumerable() ? NONE : DONT_ENUM));
    } else {
      attrs = static_cast<PropertyAttributes>(
          attrs | (current->enumerable() ? NONE : DONT_ENUM));
    }
    if (desc->has_configurable()) {
      attrs = static_cast<PropertyAttributes>(
          attrs | (desc->configurable() ? NONE : DONT_DELETE));
    } else {
      attrs = static_cast<PropertyAttributes>(
          attrs | (current->configurable() ? NONE : DONT_DELETE));
    }
    if (desc_is_data_descriptor ||
        (desc_is_generic_descriptor && current_is_data_descriptor)) {
      if (desc->has_writable()) {
        attrs = static_cast<PropertyAttributes>(
            attrs | (desc->writable() ? NONE : READ_ONLY));
      } else {
        attrs = static_cast<PropertyAttributes>(
            attrs | (current->writable() ? NONE : READ_ONLY));
      }
      Handle<Object> value(
          desc->has_value() ? desc->value()
          : current->has_value()
              ? current->value()
              : Cast<Object>(isolate->factory()->undefined_value()));
      return JSObject::DefineOwnPropertyIgnoreAttributes(it, value, attrs,
                                                         should_throw);
    } else {
      DCHECK(desc_is_accessor_descriptor ||
             (desc_is_generic_descriptor &&
              PropertyDescriptor::IsAccessorDescriptor(current)));
      DirectHandle<Object> getter(
          desc->has_get() ? desc->get()
          : current->has_get()
              ? current->get()
              : Cast<Object>(isolate->factory()->null_value()));
      DirectHandle<Object> setter(
          desc->has_set() ? desc->set()
          : current->has_set()
              ? current->set()
              : Cast<Object>(isolate->factory()->null_value()));
      MaybeHandle<Object> result = JSObject::DefineOwnAccessorIgnoreAttributes(
          it, getter, setter, attrs);
      if (result.is_null()) return Nothing<bool>();
    }
  }

  // 10. Return true.
  return Just(true);
}

// static
Maybe<bool> JSReceiver::CreateDataProperty(Isolate* isolate,
                                           Handle<JSReceiver> object,
                                           Handle<Name> key,
                                           Handle<Object> value,
                                           Maybe<ShouldThrow> should_throw) {
  return CreateDataProperty(isolate, object, PropertyKey(isolate, key), value,
                            should_throw);
}

// static
Maybe<bool> JSReceiver::CreateDataProperty(Isolate* isolate,
                                           Handle<JSAny> object,
                                           PropertyKey key,
                                           Handle<Object> value,
                                           Maybe<ShouldThrow> should_throw) {
  if (!IsJSReceiver(*object)) {
    return Object::CannotCreateProperty(isolate, object, key.GetName(isolate),
                                        value, Nothing<ShouldThrow>());
  }
  return CreateDataProperty(isolate, Cast<JSReceiver>(object), key, value,
                            should_throw);
}

// static
Maybe<bool> JSReceiver::CreateDataProperty(Isolate* isolate,
                                           Handle<JSReceiver> object,
                                           PropertyKey key,
                                           Handle<Object> value,
                                           Maybe<ShouldThrow> should_throw) {
  if (IsJSObject(*object)) {
    return JSObject::CreateDataProperty(isolate, Cast<JSObject>(object), key,
                                        value, should_throw);  // Shortcut.
  }

  PropertyDescriptor new_desc;
  new_desc.set_value(Cast<JSAny>(value));
  new_desc.set_writable(true);
  new_desc.set_enumerable(true);
  new_desc.set_configurable(true);

  return JSReceiver::DefineOwnProperty(isolate, object, key.GetName(isolate),
                                       &new_desc, should_throw);
}

// static
Maybe<bool> JSReceiver::AddPrivateField(LookupIterator* it,
                                        Handle<Object> value,
                                        Maybe<ShouldThrow> should_throw) {
  Handle<JSReceiver> receiver = Cast<JSReceiver>(it->GetReceiver());
  DCHECK(!IsAlwaysSharedSpaceJSObject(*receiver));
  Isolate* isolate = it->isolate();
  DCHECK(it->GetName()->IsPrivateName());
  Handle<Symbol> symbol = Cast<Symbol>(it->GetName());

  switch (it->state()) {
    case LookupIterator::JSPROXY: {
      PropertyDescriptor new_desc;
      new_desc.set_value(Cast<JSAny>(value));
      new_desc.set_writable(true);
      new_desc.set_enumerable(true);
      new_desc.set_configurable(true);
      return JSProxy::SetPrivateSymbol(isolate, Cast<JSProxy>(receiver), symbol,
                                       &new_desc, should_throw);
    }
    case LookupIterator::WASM_OBJECT:
      RETURN_FAILURE(isolate, kThrowOnError,
                     NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));
    case LookupIterator::DATA:
    case LookupIterator::INTERCEPTOR:
    case LookupIterator::ACCESSOR:
    case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
      UNREACHABLE();

    case LookupIterator::ACCESS_CHECK: {
      if (!it->HasAccess()) {
        RETURN_ON_EXCEPTION_VALUE(
            isolate,
            it->isolate()->ReportFailedAccessCheck(it->GetHolder<JSObject>()),
            Nothing<bool>());
        UNREACHABLE();
      }
      break;
    }

    case LookupIterator::TRANSITION:
    case LookupIterator::NOT_FOUND:
      break;
  }

  return Object::TransitionAndWriteDataProperty(it, value, NONE, should_throw,
                                                StoreOrigin::kMaybeKeyed);
}

// static
Maybe<bool> JSReceiver::GetOwnPropertyDescriptor(Isolate* isolate,
                                                 Handle<JSReceiver> object,
                                                 Handle<Object> key,
                                                 PropertyDescriptor* desc) {
  DCHECK(IsName(*key) || IsNumber(*key));  // |key| is a PropertyKey.
  PropertyKey lookup_key(isolate, key);
  LookupIterator it(isolate, object, lookup_key, LookupIterator::OWN);
  return GetOwnPropertyDescriptor(&it, desc);
}

namespace {

Maybe<bool> GetPropertyDescriptorWithInterceptor(LookupIterator* it,
                                                 PropertyDescriptor* desc) {
  Handle<InterceptorInfo> interceptor;

  while (it->state() == LookupIterator::ACCESS_CHECK) {
    if (it->HasAccess()) {
      it->Next();
    } else {
      interceptor = it->GetInterceptorForFailedAccessCheck();
      if (interceptor.is_null()) {
        it->Restart();
        return Just(false);
      }
      CHECK(!interceptor.is_null());
      break;
    }
  }
  if (it->state() == LookupIterator::INTERCEPTOR) {
    interceptor = it->GetInterceptor();
  }
  if (interceptor.is_null()) return Just(false);
  Isolate* isolate = it->isolate();
  if (IsUndefined(interceptor->descriptor(), isolate)) return Just(false);

  Handle<JSAny> result;
  DirectHandle<JSObject> holder = it->GetHolder<JSObject>();

  Handle<Object> receiver = it->GetReceiver();
  if (!IsJSReceiver(*receiver)) {
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, receiver,
                                     Object::ConvertReceiver(isolate, receiver),
                                     Nothing<bool>());
  }

  PropertyCallbackArguments args(isolate, interceptor->data(), *receiver,
                                 *holder, Just(kDontThrow));
  if (it->IsElement(*holder)) {
    result = args.CallIndexedDescriptor(interceptor, it->array_index());
  } else {
    result = args.CallNamedDescriptor(interceptor, it->name());
  }
  // An exception was thrown in the interceptor. Propagate.
  RETURN_VALUE_IF_EXCEPTION_DETECTOR(isolate, args, Nothing<bool>());
  if (!result.is_null()) {
    // Request was successfully intercepted, try to set the property
    // descriptor.
    args.AcceptSideEffects();
    Utils::ApiCheck(
        PropertyDescriptor::ToPropertyDescriptor(isolate, result, desc),
        it->IsElement(*holder) ? "v8::IndexedPropertyDescriptorCallback"
                               : "v8::NamedPropertyDescriptorCallback",
        "Invalid property descriptor.");

    return Just(true);
  }

  it->Next();
  return Just(false);
}
}  // namespace

// ES6 9.1.5.1
// Returns true on success, false if the property didn't exist, nothing if
// an exception was thrown.
// static
Maybe<bool> JSReceiver::GetOwnPropertyDescriptor(LookupIterator* it,
                                                 PropertyDescriptor* desc) {
  Isolate* isolate = it->isolate();
  // "Virtual" dispatch.
  if (it->IsFound() && IsJSProxy(*it->GetHolder<JSReceiver>())) {
    return JSProxy::GetOwnPropertyDescriptor(isolate, it->GetHolder<JSProxy>(),
                                             it->GetName(), desc);
  }

  Maybe<bool> intercepted = GetPropertyDescriptorWithInterceptor(it, desc);
  MAYBE_RETURN(intercepted, Nothing<bool>());
  if (intercepted.FromJust()) {
    return Just(true);
  }

  // Request was not intercepted, continue as normal.
  // 1. (Assert)
  // 2. If O does not have an own property with key P, return undefined.
  Maybe<PropertyAttributes> maybe = JSObject::GetPropertyAttributes(it);
  MAYBE_RETURN(maybe, Nothing<bool>());
  PropertyAttributes attrs = maybe.FromJust();
  if (attrs == ABSENT) return Just(false);
  DCHECK(!isolate->has_exception());

  // 3. Let D be a newly created Property Descriptor with no fields.
  DCHECK(desc->is_empty());
  // 4. Let X be O's own property whose key is P.
  // 5. If X is a data property, then
  bool is_accessor_pair = it->state() == LookupIterator::ACCESSOR &&
                          IsAccessorPair(*it->GetAccessors());
  if (!is_accessor_pair) {
    // 5a. Set D.[[Value]] to the value of X's [[Value]] attribute.
    Handle<JSAny> value;
    if (!Cast<JSAny>(Object::GetProperty(it)).ToHandle(&value)) {
      DCHECK(isolate->has_exception());
      return Nothing<bool>();
    }
    desc->set_value(value);
    // 5b. Set D.[[Writable]] to the value of X's [[Writable]] attribute
    desc->set_writable((attrs & READ_ONLY) == 0);
  } else {
    // 6. Else X is an accessor property, so
    auto accessors = Cast<AccessorPair>(it->GetAccessors());
    Handle<NativeContext> holder_realm(
        it->GetHolder<JSReceiver>()->GetCreationContext().value(), isolate);
    // 6a. Set D.[[Get]] to the value of X's [[Get]] attribute.
    desc->set_get(AccessorPair::GetComponent(isolate, holder_realm, accessors,
                                             ACCESSOR_GETTER));
    // 6b. Set D.[[Set]] to the value of X's [[Set]] attribute.
    desc->set_set(AccessorPair::GetComponent(isolate, holder_realm, accessors,
                                             ACCESSOR_SETTER));
  }

  // 7. Set D.[[Enumerable]] to the value of X's [[Enumerable]] attribute.
  desc->set_enumerable((attrs & DONT_ENUM) == 0);
  // 8. Set D.[[Configurable]] to the value of X's [[Configurable]] attribute.
  desc->set_configurable((attrs & DONT_DELETE) == 0);
  // 9. Return D.
  DCHECK(PropertyDescriptor::IsAccessorDescriptor(desc) !=
         PropertyDescriptor::IsDataDescriptor(desc));
  return Just(true);
}
Maybe<bool> JSReceiver::SetIntegrityLevel(Isolate* isolate,
                                          Handle<JSReceiver> receiver,
                                          IntegrityLevel level,
                                          ShouldThrow should_throw) {
  DCHECK(level == SEALED || level == FROZEN);

  if (IsJSObject(*receiver)) {
    Handle<JSObject> object = Cast<JSObject>(receiver);

    if (!object->HasSloppyArgumentsElements() &&
        !IsJSModuleNamespace(*object)) {  // Fast path.
      // Prevent memory leaks by not adding unnecessary transitions.
      Maybe<bool> test = JSObject::TestIntegrityLevel(isolate, object, level);
      MAYBE_RETURN(test, Nothing<bool>());
      if (test.FromJust()) return test;

      if (level == SEALED) {
        return JSObject::PreventExtensionsWithTransition<SEALED>(
            isolate, object, should_throw);
      } else {
        return JSObject::PreventExtensionsWithTransition<FROZEN>(
            isolate, object, should_throw);
      }
    }
  }

  MAYBE_RETURN(JSReceiver::PreventExtensions(isolate, receiver, should_throw),
               Nothing<bool>());

  Handle<FixedArray> keys;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, keys, JSReceiver::OwnPropertyKeys(isolate, receiver),
      Nothing<bool>());

  PropertyDescriptor no_conf;
  no_conf.set_configurable(false);

  PropertyDescriptor no_conf_no_write;
  no_conf_no_write.set_configurable(false);
  no_conf_no_write.set_writable(false);

  if (level == SEALED) {
    for (int i = 0; i < keys->length(); ++i) {
      Handle<Object> key(keys->get(i), isolate);
      MAYBE_RETURN(DefineOwnProperty(isolate, receiver, key, &no_conf,
                                     Just(kThrowOnError)),
                   Nothing<bool>());
    }
    return Just(true);
  }

  for (int i = 0; i < keys->length(); ++i) {
    Handle<Object> key(keys->get(i), isolate);
    PropertyDescriptor current_desc;
    Maybe<bool> owned = JSReceiver::GetOwnPropertyDescriptor(
        isolate, receiver, key, &current_desc);
    MAYBE_RETURN(owned, Nothing<bool>());
    if (owned.FromJust()) {
      PropertyDescriptor desc =
          PropertyDescriptor::IsAccessorDescriptor(&current_desc)
              ? no_conf
              : no_conf_no_write;
      MAYBE_RETURN(
          DefineOwnProperty(isolate, receiver, key, &desc, Just(kThrowOnError)),
          Nothing<bool>());
    }
  }
  return Just(true);
}

namespace {
Maybe<bool> GenericTestIntegrityLevel(Isolate* isolate,
                                      Handle<JSReceiver> receiver,
                                      PropertyAttributes level) {
  DCHECK(level == SEALED || level == FROZEN);

  Maybe<bool> extensible = JSReceiver::IsExtensible(isolate, receiver);
  MAYBE_RETURN(extensible, Nothing<bool>());
  if (extensible.FromJust()) return Just(false);

  Handle<FixedArray> keys;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, keys, JSReceiver::OwnPropertyKeys(isolate, receiver),
      Nothing<bool>());

  for (int i = 0; i < keys->length(); ++i) {
    Handle<Object> key(keys->get(i), isolate);
    PropertyDescriptor current_desc;
    Maybe<bool> owned = JSReceiver::GetOwnPropertyDescriptor(
        isolate, receiver, key, &current_desc);
    MAYBE_RETURN(owned, Nothing<bool>());
    if (owned.FromJust()) {
      if (current_desc.configurable()) return Just(false);
      if (level == FROZEN &&
          PropertyDescriptor::IsDataDescriptor(&current_desc) &&
          current_desc.writable()) {
        return Just(false);
      }
    }
  }
  return Just(true);
}

}  // namespace

Maybe<bool> JSReceiver::TestIntegrityLevel(Isolate* isolate,
                                           Handle<JSReceiver> receiver,
                                           IntegrityLevel level) {
  if (!IsCustomElementsReceiverMap(receiver->map())) {
    return JSObject::TestIntegrityLevel(isolate, Cast<JSObject>(receiver),
                                        level);
  }
  return GenericTestIntegrityLevel(isolate, receiver, level);
}

Maybe<bool> JSReceiver::PreventExtensions(Isolate* isolate,
                                          Handle<JSReceiver> object,
                                          ShouldThrow should_throw) {
  if (IsJSProxy(*object)) {
    return JSProxy::PreventExtensions(Cast<JSProxy>(object), should_throw);
  }
  if (IsWasmObject(*object)) {
    RETURN_FAILURE(isolate, kThrowOnError,
                   NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));
  }
  DCHECK(IsJSObject(*object));
  return JSObject::PreventExtensions(isolate, Cast<JSObject>(object),
                                     should_throw);
}

Maybe<bool> JSReceiver::IsExtensible(Isolate* isolate,
                                     Handle<JSReceiver> object) {
  if (IsJSProxy(*object)) {
    return JSProxy::IsExtensible(Cast<JSProxy>(object));
  }
  if (IsWasmObject(*object)) {
    return Just(false);
  }
  return Just(JSObject::IsExtensible(isolate, Cast<JSObject>(object)));
}

// static
MaybeHandle<Object> JSReceiver::ToPrimitive(Isolate* isolate,
                                            Handle<JSReceiver> receiver,
                                            ToPrimitiveHint hint) {
  Handle<Object> exotic_to_prim;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, exotic_to_prim,
      Object::GetMethod(isolate, receiver,
                        isolate->factory()->to_primitive_symbol()));
  if (!IsUndefined(*exotic_to_prim, isolate)) {
    Handle<Object> hint_string =
        isolate->factory()->ToPrimitiveHintString(hint);
    Handle<Object> result;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, result,
        Execution::Call(isolate, exotic_to_prim, receiver, 1, &hint_string));
    if (IsPrimitive(*result)) return result;
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kCannotConvertToPrimitive));
  }
  return OrdinaryToPrimitive(isolate, receiver,
                             (hint == ToPrimitiveHint::kString)
                                 ? OrdinaryToPrimitiveHint::kString
                                 : OrdinaryToPrimitiveHint::kNumber);
}

// static
MaybeHandle<Object> JSReceiver::OrdinaryToPrimitive(
    Isolate* isolate, Handle<JSReceiver> receiver,
    OrdinaryToPrimitiveHint hint) {
  Handle<String> method_names[2];
  switch (hint) {
    case OrdinaryToPrimitiveHint::kNumber:
      method_names[0] = isolate->factory()->valueOf_string();
      method_names[1] = isolate->factory()->toString_string();
      break;
    case OrdinaryToPrimitiveHint::kString:
      method_names[0] = isolate->factory()->toString_string();
      method_names[1] = isolate->factory()->valueOf_string();
      break;
  }
  for (Handle<String> name : method_names) {
    Handle<Object> method;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, method, JSReceiver::GetProperty(isolate, receiver, name));
    if (IsCallable(*method)) {
      Handle<Object> result;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, result,
          Execution::Call(isolate, method, receiver, 0, nullptr));
      if (IsPrimitive(*result)) return result;
    }
  }
  THROW_NEW_ERROR(isolate,
                  NewTypeError(MessageTemplate::kCannotConvertToPrimitive));
}

V8_WARN_UNUSED_RESULT Maybe<bool> FastGetOwnValuesOrEntries(
    Isolate* isolate, DirectHandle<JSReceiver> receiver, bool get_entries,
    Handle<FixedArray>* result) {
  DirectHandle<Map> map(Cast<JSReceiver>(*receiver)->map(), isolate);

  if (!IsJSObjectMap(*map)) return Just(false);
  if (!map->OnlyHasSimpleProperties()) return Just(false);

  Handle<JSObject> object(Cast<JSObject>(*receiver), isolate);
  Handle<DescriptorArray> descriptors(map->instance_descriptors(isolate),
                                      isolate);

  int number_of_own_descriptors = map->NumberOfOwnDescriptors();
  size_t number_of_own_elements =
      object->GetElementsAccessor()->GetCapacity(*object, object->elements());

  if (number_of_own_elements >
      static_cast<size_t>(FixedArray::kMaxLength - number_of_own_descriptors)) {
    isolate->Throw(*isolate->factory()->NewRangeError(
        MessageTemplate::kInvalidArrayLength));
    return Nothing<bool>();
  }
  // The static cast is safe after the range check right above.
  Handle<FixedArray> values_or_entries = isolate->factory()->NewFixedArray(
      static_cast<int>(number_of_own_descriptors + number_of_own_elements));
  int count = 0;

  if (object->elements() != ReadOnlyRoots(isolate).empty_fixed_array()) {
    MAYBE_RETURN(object->GetElementsAccessor()->CollectValuesOrEntries(
                     isolate, object, values_or_entries, get_entries, &count,
                     ENUMERABLE_STRINGS),
                 Nothing<bool>());
  }

  // We may have already lost stability, if CollectValuesOrEntries had
  // side-effects.
  bool stable = *map == object->map();
  if (stable) {
    descriptors.PatchValue(map->instance_descriptors(isolate));
  }

  for (InternalIndex index : InternalIndex::Range(number_of_own_descriptors)) {
    HandleScope inner_scope(isolate);

    Handle<Name> next_key(descriptors->GetKey(index), isolate);
    if (!IsString(*next_key)) continue;
    Handle<Object> prop_value;

    // Directly decode from the descriptor array if |from| did not change shape.
    if (stable) {
      DCHECK_EQ(object->map(), *map);
      DCHECK_EQ(*descriptors, map->instance_descriptors(isolate));

      PropertyDetails details = descriptors->GetDetails(index);
      if (!details.IsEnumerable()) continue;
      if (details.kind() == PropertyKind::kData) {
        if (details.location() == PropertyLocation::kDescriptor) {
          prop_value = handle(descriptors->GetStrongValue(index), isolate);
        } else {
          Representation representation = details.representation();
          FieldIndex field_index = FieldIndex::ForPropertyIndex(
              *map, details.field_index(), representation);
          prop_value = JSObject::FastPropertyAt(isolate, object, representation,
                                                field_index);
        }
      } else {
        LookupIterator it(isolate, object, next_key,
                          LookupIterator::OWN_SKIP_INTERCEPTOR);
        DCHECK_EQ(LookupIterator::ACCESSOR, it.state());
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, prop_value, Object::GetProperty(&it), Nothing<bool>());
        stable = object->map() == *map;
        descriptors.PatchValue(map->instance_descriptors(isolate));
      }
    } else {
      // If the map did change, do a slower lookup. We are still guaranteed that
      // the object has a simple shape, and that the key is a name.
      LookupIterator it(isolate, object, next_key,
                        LookupIterator::OWN_SKIP_INTERCEPTOR);
      if (!it.IsFound()) continue;
      DCHECK(it.state() == LookupIterator::DATA ||
             it.state() == LookupIterator::ACCESSOR);
      if (!it.IsEnumerable()) continue;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, prop_value, Object::GetProperty(&it), Nothing<bool>());
    }

    if (get_entries) {
      prop_value = MakeEntryPair(isolate, next_key, prop_value);
    }

    values_or_entries->set(count, *prop_value);
    count++;
  }

  DCHECK_LE(count, values_or_entries->length());
  *result = FixedArray::RightTrimOrEmpty(isolate, values_or_entries, count);
  return Just(true);
}

MaybeHandle<FixedArray> GetOwnValuesOrEntries(Isolate* isolate,
                                              Handle<JSReceiver> object,
                                              PropertyFilter filter,
                                              bool try_fast_path,
                                              bool get_entries) {
  Handle<FixedArray> values_or_entries;
  if (try_fast_path && filter == ENUMERABLE_STRINGS) {
    Maybe<bool> fast_values_or_entries = FastGetOwnValuesOrEntries(
        isolate, object, get_entries, &values_or_entries);
    if (fast_values_or_entries.IsNothing()) return MaybeHandle<FixedArray>();
    if (fast_values_or_entries.FromJust()) return values_or_entries;
  }

  PropertyFilter key_filter =
      static_cast<PropertyFilter>(filter & ~ONLY_ENUMERABLE);

  Handle<FixedArray> keys;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, keys,
      KeyAccumulator::GetKeys(isolate, object, KeyCollectionMode::kOwnOnly,
                              key_filter, GetKeysConversion::kConvertToString),
      MaybeHandle<FixedArray>());

  values_or_entries = isolate->factory()->NewFixedArray(keys->length());
  int length = 0;

  for (int i = 0; i < keys->length(); ++i) {
    Handle<Name> key(Cast<Name>(keys->get(i)), isolate);

    if (filter & ONLY_ENUMERABLE) {
      PropertyDescriptor descriptor;
      Maybe<bool> did_get_descriptor = JSReceiver::GetOwnPropertyDescriptor(
          isolate, object, key, &descriptor);
      MAYBE_RETURN(did_get_descriptor, MaybeHandle<FixedArray>());
      if (!did_get_descriptor.FromJust() || !descriptor.enumerable()) continue;
    }

    Handle<Object> value;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, value, Object::GetPropertyOrElement(isolate, object, key),
        MaybeHandle<FixedArray>());

    if (get_entries) {
      DirectHandle<FixedArray> entry_storage =
          isolate->factory()->NewFixedArray(2);
      entry_storage->set(0, *key);
      entry_storage->set(1, *value);
      value = isolate->factory()->NewJSArrayWithElements(entry_storage,
                                                         PACKED_ELEMENTS, 2);
    }

    values_or_entries->set(length, *value);
    length++;
  }
  DCHECK_LE(length, values_or_entries->length());
  return FixedArray::RightTrimOrEmpty(isolate, values_or_entries, length);
}

MaybeHandle<FixedArray> JSReceiver::GetOwnValues(Isolate* isolate,
                                                 Handle<JSReceiver> object,
                                                 PropertyFilter filter,
                                                 bool try_fast_path) {
  return GetOwnValuesOrEntries(isolate, object, filter, try_fast_path, false);
}

MaybeHandle<FixedArray> JSReceiver::GetOwnEntries(Isolate* isolate,
                                                  Handle<JSReceiver> object,
                                                  PropertyFilter filter,
                                                  bool try_fast_path) {
  return GetOwnValuesOrEntries(isolate, object, filter, try_fast_path, true);
}

Maybe<bool> JSReceiver::SetPrototype(Isolate* isolate,
                                     Handle<JSReceiver> object,
                                     Handle<Object> value, bool from_javascript,
                                     ShouldThrow should_throw) {
  if (IsWasmObject(*object)) {
    RETURN_FAILURE(isolate, should_throw,
                   NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));
  }

  if (IsJSProxy(*object)) {
    return JSProxy::SetPrototype(isolate, Cast<JSProxy>(object), value,
                                 from_javascript, should_throw);
  }
  return JSObject::SetPrototype(isolate, Cast<JSObject>(object), value,
                                from_javascript, should_throw);
}

bool JSReceiver::HasProxyInPrototype(Isolate* isolate) {
  for (PrototypeIterator iter(isolate, *this, kStartAtReceiver,
                              PrototypeIterator::END_AT_NULL);
       !iter.IsAtEnd(); iter.AdvanceIgnoringProxies()) {
    if (IsJSProxy(iter.GetCurrent())) return true;
  }
  return false;
}

bool JSReceiver::IsCodeLike(Isolate* isolate) const {
  DisallowGarbageCollection no_gc;
  Tagged<Object> maybe_constructor = map()->GetConstructor();
  if (!IsJSFunction(maybe_constructor)) return false;
  if (!Cast<JSFunction>(maybe_constructor)->shared()->IsApiFunction()) {
    return false;
  }
  Tagged<Object> instance_template = Cast<JSFunction>(maybe_constructor)
                                         ->shared()
                                         ->api_func_data()
                                         ->GetInstanceTemplate();
  if (IsUndefined(instance_template, isolate)) return false;
  return Cast<ObjectTemplateInfo>(instance_template)->code_like();
}

// static
MaybeHandle<JSObject> JSObject::New(Handle<JSFunction> constructor,
                                    Handle<JSReceiver> new_target,
                                    DirectHandle<AllocationSite> site,
                                    NewJSObjectType new_js_object_type) {
  // If called through new, new.target can be:
  // - a subclass of constructor,
  // - a proxy wrapper around constructor, or
  // - the constructor itself.
  // If called through Reflect.construct, it's guaranteed to be a constructor.
  Isolate* const isolate = constructor->GetIsolate();
  DCHECK(IsConstructor(*constructor));
  DCHECK(IsConstructor(*new_target));
  DCHECK(!constructor->has_initial_map() ||
         !InstanceTypeChecker::IsJSFunction(
             constructor->initial_map()->instance_type()));

  Handle<Map> initial_map;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, initial_map,
      JSFunction::GetDerivedMap(isolate, constructor, new_target));
  constexpr int initial_capacity = PropertyDictionary::kInitialCapacity;
  Handle<JSObject> result = isolate->factory()->NewFastOrSlowJSObjectFromMap(
      initial_map, initial_capacity, AllocationType::kYoung, site,
      new_js_object_type);
  return result;
}

// static
MaybeHandle<JSObject> JSObject::NewWithMap(Isolate* isolate,
                                           DirectHandle<Map> initial_map,
                                           DirectHandle<AllocationSite> site,
                                           NewJSObjectType new_js_object_type) {
  constexpr int initial_capacity = PropertyDictionary::kInitialCapacity;
  Handle<JSObject> result = isolate->factory()->NewFastOrSlowJSObjectFromMap(
      initial_map, initial_capacity, AllocationType::kYoung, site,
      new_js_object_type);
  return result;
}

// 9.1.12 ObjectCreate ( proto [ , internalSlotsList ] )
// Notice: This is NOT 19.1.2.2 Object.create ( O, Properties )
MaybeHandle<JSObject> JSObject::ObjectCreate(Isolate* isolate,
                                             Handle<JSPrototype> prototype) {
  // Generate the map with the specified {prototype} based on the Object
  // function's initial map from the current native context.
  // TODO(bmeurer): Use a dedicated cache for Object.create; think about
  // slack tracking for Object.create.
  DirectHandle<Map> map = Map::GetObjectCreateMap(isolate, prototype);

  // Actually allocate the object.
  return isolate->factory()->NewFastOrSlowJSObjectFromMap(map);
}

void JSObject::EnsureWritableFastElements(DirectHandle<JSObject> object) {
  DCHECK(object->HasSmiOrObjectElements() ||
         object->HasFastStringWrapperElements() ||
         object->HasAnyNonextensibleElements());
  Tagged<FixedArray> raw_elems = Cast<FixedArray>(object->elements());
  Isolate* isolate = object->GetIsolate();
  if (raw_elems->map() != ReadOnlyRoots(isolate).fixed_cow_array_map()) return;
  DirectHandle<FixedArray> elems(raw_elems, isolate);
  DirectHandle<FixedArray> writable_elems =
      isolate->factory()->CopyFixedArrayWithMap(
          elems, isolate->factory()->fixed_array_map());
  object->set_elements(*writable_elems);
}

// For FATAL in JSObject::GetHeaderSize
static const char* NonAPIInstanceTypeToString(InstanceType instance_type) {
  DCHECK(!InstanceTypeChecker::IsJSApiObject(instance_type));
  switch (instance_type) {
#define WRITE_TYPE(TYPE) \
  case TYPE:             \
    return #TYPE;
    INSTANCE_TYPE_LIST(WRITE_TYPE)
#undef WRITE_TYPE
  }
  UNREACHABLE();
}

int JSObject::GetHeaderSize(InstanceType type,
                            bool function_has_prototype_slot) {
  switch (type) {
    case JS_SPECIAL_API_OBJECT_TYPE:
    case JS_API_OBJECT_TYPE:
      return JSAPIObjectWithEmbedderSlots::BodyDescriptor::kHeaderSize;
    case JS_ITERATOR_PROTOTYPE_TYPE:
    case JS_MAP_ITERATOR_PROTOTYPE_TYPE:
    case JS_OBJECT_PROTOTYPE_TYPE:
    case JS_OBJECT_TYPE:
    case JS_PROMISE_PROTOTYPE_TYPE:
    case JS_REG_EXP_PROTOTYPE_TYPE:
    case JS_SET_ITERATOR_PROTOTYPE_TYPE:
    case JS_SET_PROTOTYPE_TYPE:
    case JS_STRING_ITERATOR_PROTOTYPE_TYPE:
    case JS_ARRAY_ITERATOR_PROTOTYPE_TYPE:
    case JS_TYPED_ARRAY_PROTOTYPE_TYPE:
    case JS_CONTEXT_EXTENSION_OBJECT_TYPE:
    case JS_ARGUMENTS_OBJECT_TYPE:
    case JS_ERROR_TYPE:
      return JSObject::kHeaderSize;
    case JS_GENERATOR_OBJECT_TYPE:
      return JSGeneratorObject::kHeaderSize;
    case JS_ASYNC_FUNCTION_OBJECT_TYPE:
      return JSAsyncFunctionObject::kHeaderSize;
    case JS_ASYNC_GENERATOR_OBJECT_TYPE:
      return JSAsyncGeneratorObject::kHeaderSize;
    case JS_ASYNC_FROM_SYNC_ITERATOR_TYPE:
      return JSAsyncFromSyncIterator::kHeaderSize;
    case JS_GLOBAL_PROXY_TYPE:
      return JSGlobalProxy::kHeaderSize;
    cas
```