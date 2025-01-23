Response:
The user wants a summary of the functionalities present in the provided C++ code snippet from `v8/src/objects/js-objects.cc`. I need to:

1. **Identify the core functionalities** of the code. These appear to be related to property manipulation on JavaScript objects.
2. **Check if it's a Torque file:** The prompt gives instructions for checking if the file is a Torque file. This code snippet ends with `.cc`, so it's not a Torque file.
3. **Relate to JavaScript:**  Since the code deals with JavaScript objects, I should explain how the functionalities relate to JavaScript concepts. I need to provide JavaScript examples.
4. **Provide code logic reasoning:** For some functions, it might be beneficial to explain the logic with input and output examples.
5. **Mention common programming errors:** If the functionality relates to common JavaScript errors, I need to give examples.
6. **Summarize the functionality:** Finally, I need to summarize the purpose of this code snippet in the context of managing JavaScript object properties.

Let's break down the individual functions:

*   **`tOrCreateIdentityHash`**: Creates a unique hash for an object.
*   **`JSReceiver::DeleteNormalizedProperty`**: Deletes a property from an object's dictionary. It handles different dictionary types (NameDictionary, SwissNameDictionary, GlobalDictionary).
*   **`JSReceiver::DeleteProperty` (various overloads)**:  Implements the `delete` operator in JavaScript. It handles various scenarios like proxies, interceptors, and property attributes (configurable).
*   **`JSReceiver::DeleteElement`**: Deletes an element from an array-like object.
*   **`JSReceiver::DeletePropertyOrElement`**: A generic delete operation that handles both properties and elements.
*   **`JSReceiver::DefineProperty`**: Implements `Object.defineProperty`. It validates input and calls `DefineOwnProperty`.
*   **`JSReceiver::DefineProperties`**: Implements `Object.defineProperties`. It iterates through properties and defines them.
*   **`JSReceiver::DefineOwnProperty`**: The core logic for defining or modifying object properties. It dispatches to specialized handlers for arrays, proxies, typed arrays, module namespaces, and shared objects. It calls `OrdinaryDefineOwnProperty` for regular objects.
*   **`JSReceiver::OrdinaryDefineOwnProperty` (various overloads)**: The default implementation of defining or modifying a property. It handles access checks and calls `ValidateAndApplyPropertyDescriptor`.
*   **`GetPropertyWithInterceptorInternal`**: Handles property access through interceptors.
*   **`GetPropertyAttributesWithInterceptorInternal`**:  Handles getting property attributes through interceptors.
*   **`SetPropertyWithInterceptorInternal`**: Handles setting properties through interceptors.
*   **`DefinePropertyWithInterceptorInternal`**: Handles defining properties through interceptors.
*   **`JSReceiver::OrdinaryDefineOwnProperty` (with PropertyKey)**:  The core logic for defining or modifying a property (implementation). It checks if the property exists, if it's configurable, and applies the provided descriptor.
*   **`JSReceiver::IsCompatiblePropertyDescriptor`**: Checks if a property descriptor is compatible with an existing property.
*   **`JSReceiver::ValidateAndApplyPropertyDescriptor`**:  The central function for validating and applying property descriptors. It handles cases where the property doesn't exist, or when modifying existing properties, taking into account configurability, writability, etc.

Now I can construct the answer based on these identified functionalities.
这是 v8 源代码文件 `v8/src/objects/js-objects.cc` 的第二部分，主要负责实现 JavaScript 对象的属性操作，包括删除属性和定义属性。

**功能归纳:**

本部分代码主要提供了以下功能：

1. **删除属性 (Deleting Properties):**
    *   提供了多种 `DeleteProperty` 方法，用于删除 JavaScript 对象上的属性，包括命名字典中的属性、全局对象中的属性以及通过拦截器删除属性。
    *   `DeleteElement` 方法用于删除数组类型的元素的。
    *   `DeletePropertyOrElement` 是一个更通用的删除方法，可以处理属性名或数组索引。
    *   在删除属性时，会考虑属性的特性（例如，是否可配置），以及是否定义了拦截器。
    *   对于全局对象，删除操作会涉及到清理全局字典和失效 PropertyCell。
    *   对于原型对象的属性删除，会使原型链失效。

2. **定义属性 (Defining Properties):**
    *   `DefineProperty` 方法实现了 `Object.defineProperty()` 的功能，用于精确控制对象属性的特性（例如，是否可写、可枚举、可配置）。
    *   `DefineProperties` 方法实现了 `Object.defineProperties()` 的功能，可以一次定义或修改多个属性。
    *   `DefineOwnProperty` 是定义属性的核心方法，它会根据对象的类型（例如，普通对象、数组、Proxy、TypedArray 等）调用不同的内部实现。
    *   `OrdinaryDefineOwnProperty` 是对于普通 JavaScript 对象定义或修改自有属性的默认实现。它会检查属性是否存在，是否可配置，并根据提供的属性描述符进行更新。

3. **属性描述符的验证和应用 (Property Descriptor Validation and Application):**
    *   `ValidateAndApplyPropertyDescriptor` 是一个核心的辅助函数，用于验证给定的属性描述符是否可以应用到对象上，并实际执行属性的创建或修改。它会考虑属性的可扩展性、可配置性、可写性等因素。
    *   `IsCompatiblePropertyDescriptor` 用于检查一个新的属性描述符是否与现有属性的描述符兼容。

4. **拦截器 (Interceptors):**
    *   代码中包含了处理属性访问、设置和定义拦截器的逻辑 (`GetPropertyWithInterceptorInternal`, `GetPropertyAttributesWithInterceptorInternal`, `SetPropertyWithInterceptorInternal`, `DefinePropertyWithInterceptorInternal`). 拦截器允许 JavaScript 代码介入到对象属性的访问和修改过程中。

**关于 `.tq` 文件：**

代码以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。如果文件名以 `.tq` 结尾，那么它才会被认为是 v8 的 Torque 源代码。

**与 JavaScript 功能的关系及示例：**

本部分代码直接实现了 JavaScript 中对象属性的删除和定义功能。

**删除属性 (delete):**

```javascript
const obj = { x: 1, y: 2 };
delete obj.x; // 调用 JSReceiver::DeleteProperty
console.log(obj.x); // 输出: undefined

const arr = [1, 2, 3];
delete arr[1]; // 调用 JSReceiver::DeleteElement
console.log(arr); // 输出: [ 1, <1 empty item>, 3 ]
console.log(1 in arr); // 输出: false
```

**定义属性 (Object.defineProperty, Object.defineProperties):**

```javascript
const obj = {};

// 使用 Object.defineProperty 定义属性
Object.defineProperty(obj, 'name', {
  value: 'Alice',
  writable: false,
  enumerable: true,
  configurable: false
}); // 调用 JSReceiver::DefineProperty

console.log(obj.name); // 输出: Alice
obj.name = 'Bob'; // 严格模式下会报错，非严格模式下静默失败
console.log(obj.name); // 输出: Alice

// 使用 Object.defineProperties 定义多个属性
Object.defineProperties(obj, {
  age: {
    value: 30,
    enumerable: true
  },
  city: {
    value: 'New York'
  }
}); // 调用 JSReceiver::DefineProperties

console.log(obj.age); // 输出: 30
console.log(obj.city); // 输出: New York
```

**代码逻辑推理示例：**

假设有以下 JavaScript 代码：

```javascript
const obj = { a: 1 };
Object.defineProperty(obj, 'b', { value: 2, configurable: false });
delete obj.b;
```

**假设输入：**

*   `isolate`: 当前 V8 隔离区。
*   `object`: 指向 JavaScript 对象 `{ a: 1, b: 2 }` 的句柄。
*   `name`: 指向字符串 `"b"` 的句柄。
*   `language_mode`: 当前代码的语言模式（例如，严格模式）。

**代码逻辑推理（`JSReceiver::DeleteProperty`）：**

1. 创建一个 `LookupIterator` 来查找对象 `obj` 上名为 `"b"` 的属性。
2. `it->state()` 会指向 `LookupIterator::DATA`，因为属性 `"b"` 是一个数据属性。
3. 检查属性 `"b"` 的可配置性 (`it->IsConfigurable()`)。在这个例子中，`configurable` 为 `false`。
4. 由于语言模式不影响 `delete` 不可配置属性的结果（在严格模式下会抛出 `TypeError`，非严格模式下返回 `false`），会根据语言模式决定是否抛出异常。
5. 最终，由于属性 `"b"` 不可配置，`DeleteProperty` 将返回 `Just(false)`（非严格模式）或抛出 `TypeError`（严格模式）。

**用户常见的编程错误示例：**

1. **尝试删除不可配置的属性：**

    ```javascript
    'use strict';
    const obj = {};
    Object.defineProperty(obj, 'prop', { value: 10, configurable: false });
    delete obj.prop; // TypeError: Cannot delete property 'prop' of #<Object>
    ```

2. **在严格模式下尝试给只读属性赋值：**

    ```javascript
    'use strict';
    const obj = {};
    Object.defineProperty(obj, 'prop', { value: 10, writable: false });
    obj.prop = 20; // TypeError: Cannot assign to read only property 'prop' of object '#<Object>'
    ```

3. **尝试重新定义不可配置的属性的特性：**

    ```javascript
    'use strict';
    const obj = {};
    Object.defineProperty(obj, 'prop', { value: 10, configurable: false });
    Object.defineProperty(obj, 'prop', { enumerable: true }); // TypeError: Cannot redefine property: prop
    ```

**总结：**

这段 `v8/src/objects/js-objects.cc` 的代码是 V8 引擎中处理 JavaScript 对象属性删除和定义的核心部分。它实现了 JavaScript 语言规范中关于属性操作的关键语义，并考虑了各种复杂情况，例如原型链、拦截器以及不同类型的 JavaScript 对象。理解这部分代码有助于深入了解 JavaScript 引擎的工作原理以及如何高效地操作 JavaScript 对象。

### 提示词
```
这是目录为v8/src/objects/js-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
tOrCreateIdentityHash(Isolate* isolate) {
  DisallowGarbageCollection no_gc;

  int hash = GetIdentityHashHelper(*this);
  if (hash != PropertyArray::kNoHashSentinel) {
    return Smi::FromInt(hash);
  }

  return JSReceiver::CreateIdentityHash(isolate, *this);
}

void JSReceiver::DeleteNormalizedProperty(DirectHandle<JSReceiver> object,
                                          InternalIndex entry) {
  DCHECK(!object->HasFastProperties());
  Isolate* isolate = object->GetIsolate();
  DCHECK(entry.is_found());

  if (IsJSGlobalObject(*object)) {
    // If we have a global object, invalidate the cell and remove it from the
    // global object's dictionary.
    Handle<GlobalDictionary> dictionary(
        Cast<JSGlobalObject>(*object)->global_dictionary(kAcquireLoad),
        isolate);

    DirectHandle<PropertyCell> cell(dictionary->CellAt(entry), isolate);

    DirectHandle<GlobalDictionary> new_dictionary =
        GlobalDictionary::DeleteEntry(isolate, dictionary, entry);
    Cast<JSGlobalObject>(*object)->set_global_dictionary(*new_dictionary,
                                                         kReleaseStore);

    cell->ClearAndInvalidate(ReadOnlyRoots(isolate));
  } else {
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      Handle<SwissNameDictionary> dictionary(
          object->property_dictionary_swiss(), isolate);

      dictionary = SwissNameDictionary::DeleteEntry(isolate, dictionary, entry);
      object->SetProperties(*dictionary);
    } else {
      Handle<NameDictionary> dictionary(object->property_dictionary(), isolate);

      dictionary = NameDictionary::DeleteEntry(isolate, dictionary, entry);
      object->SetProperties(*dictionary);
    }
  }
  if (object->map()->is_prototype_map()) {
    // Invalidate prototype validity cell as this may invalidate transitioning
    // store IC handlers.
    JSObject::InvalidatePrototypeChains(object->map());
  }
}

Maybe<bool> JSReceiver::DeleteProperty(LookupIterator* it,
                                       LanguageMode language_mode) {
  it->UpdateProtector();

  Isolate* isolate = it->isolate();

  if (it->state() == LookupIterator::JSPROXY) {
    return JSProxy::DeletePropertyOrElement(it->GetHolder<JSProxy>(),
                                            it->GetName(), language_mode);
  }

  if (IsJSProxy(*it->GetReceiver())) {
    if (it->state() != LookupIterator::NOT_FOUND) {
      DCHECK_EQ(LookupIterator::DATA, it->state());
      DCHECK(it->name()->IsPrivate());
      it->Delete();
    }
    return Just(true);
  }

  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::JSPROXY:
      case LookupIterator::TRANSITION:
        UNREACHABLE();
      case LookupIterator::WASM_OBJECT:
        RETURN_FAILURE(isolate, kThrowOnError,
                       NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));
      case LookupIterator::ACCESS_CHECK:
        if (it->HasAccess()) continue;
        RETURN_ON_EXCEPTION_VALUE(
            isolate,
            isolate->ReportFailedAccessCheck(it->GetHolder<JSObject>()),
            Nothing<bool>());
        UNREACHABLE();
      case LookupIterator::INTERCEPTOR: {
        ShouldThrow should_throw =
            is_sloppy(language_mode) ? kDontThrow : kThrowOnError;
        InterceptorResult result;
        if (!JSObject::DeletePropertyWithInterceptor(it, should_throw)
                 .To(&result)) {
          // An exception was thrown in the interceptor. Propagate.
          return Nothing<bool>();
        }
        switch (result) {
          case InterceptorResult::kFalse:
            return Just(false);
          case InterceptorResult::kTrue:
            return Just(true);
          case InterceptorResult::kNotIntercepted:
            // Proceed lookup.
            continue;
        }
        UNREACHABLE();
      }
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
        return Just(true);
      case LookupIterator::DATA:
      case LookupIterator::ACCESSOR: {
        DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
        if (!it->IsConfigurable() ||
            (IsJSTypedArray(*holder) && it->IsElement(*holder))) {
          // Fail if the property is not configurable if the property is a
          // TypedArray element.
          if (is_strict(language_mode)) {
            isolate->Throw(*isolate->factory()->NewTypeError(
                MessageTemplate::kStrictDeleteProperty, it->GetName(),
                it->GetReceiver()));
            return Nothing<bool>();
          }
          return Just(false);
        }

        it->Delete();

        return Just(true);
      }
      case LookupIterator::NOT_FOUND:
        return Just(true);
    }
    UNREACHABLE();
  }
}

Maybe<bool> JSReceiver::DeleteElement(Isolate* isolate,
                                      Handle<JSReceiver> object, uint32_t index,
                                      LanguageMode language_mode) {
  LookupIterator it(isolate, object, index, object, LookupIterator::OWN);
  return DeleteProperty(&it, language_mode);
}

Maybe<bool> JSReceiver::DeleteProperty(Isolate* isolate,
                                       Handle<JSReceiver> object,
                                       Handle<Name> name,
                                       LanguageMode language_mode) {
  LookupIterator it(isolate, object, name, object, LookupIterator::OWN);
  return DeleteProperty(&it, language_mode);
}

Maybe<bool> JSReceiver::DeletePropertyOrElement(Isolate* isolate,
                                                Handle<JSReceiver> object,
                                                Handle<Name> name,
                                                LanguageMode language_mode) {
  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, object, LookupIterator::OWN);
  return DeleteProperty(&it, language_mode);
}

// ES6 19.1.2.4
// static
Tagged<Object> JSReceiver::DefineProperty(Isolate* isolate,
                                          Handle<Object> object,
                                          Handle<Object> key,
                                          Handle<Object> attributes) {
  // 1. If Type(O) is not Object, throw a TypeError exception.
  if (!IsJSReceiver(*object)) {
    Handle<String> fun_name =
        isolate->factory()->InternalizeUtf8String("Object.defineProperty");
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kCalledOnNonObject, fun_name));
  }
  // 2. Let key be ToPropertyKey(P).
  // 3. ReturnIfAbrupt(key).
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, key,
                                     Object::ToPropertyKey(isolate, key));
  // 4. Let desc be ToPropertyDescriptor(Attributes).
  // 5. ReturnIfAbrupt(desc).
  PropertyDescriptor desc;
  if (!PropertyDescriptor::ToPropertyDescriptor(
          isolate, Cast<JSAny>(attributes), &desc)) {
    return ReadOnlyRoots(isolate).exception();
  }
  // 6. Let success be DefinePropertyOrThrow(O,key, desc).
  Maybe<bool> success = DefineOwnProperty(isolate, Cast<JSReceiver>(object),
                                          key, &desc, Just(kThrowOnError));
  // 7. ReturnIfAbrupt(success).
  MAYBE_RETURN(success, ReadOnlyRoots(isolate).exception());
  CHECK(success.FromJust());
  // 8. Return O.
  return *object;
}

// ES6 19.1.2.3.1
// static
MaybeHandle<Object> JSReceiver::DefineProperties(Isolate* isolate,
                                                 Handle<Object> object,
                                                 Handle<Object> properties) {
  // 1. If Type(O) is not Object, throw a TypeError exception.
  if (!IsJSReceiver(*object)) {
    Handle<String> fun_name =
        isolate->factory()->InternalizeUtf8String("Object.defineProperties");
    THROW_NEW_ERROR(
        isolate, NewTypeError(MessageTemplate::kCalledOnNonObject, fun_name));
  }
  // 2. Let props be ToObject(Properties).
  // 3. ReturnIfAbrupt(props).
  Handle<JSReceiver> props;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, props,
                             Object::ToObject(isolate, properties));

  // 4. Let keys be props.[[OwnPropertyKeys]]().
  // 5. ReturnIfAbrupt(keys).
  Handle<FixedArray> keys;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, keys,
      KeyAccumulator::GetKeys(isolate, props, KeyCollectionMode::kOwnOnly,
                              ALL_PROPERTIES));
  // 6. Let descriptors be an empty List.s
  int capacity = keys->length();
  std::vector<PropertyDescriptor> descriptors(capacity);
  size_t descriptors_index = 0;
  // 7. Repeat for each element nextKey of keys in List order,
  for (int i = 0; i < keys->length(); ++i) {
    Handle<JSAny> next_key(Cast<JSAny>(keys->get(i)), isolate);
    // 7a. Let propDesc be props.[[GetOwnProperty]](nextKey).
    // 7b. ReturnIfAbrupt(propDesc).
    PropertyKey key(isolate, next_key);
    LookupIterator it(isolate, props, key, LookupIterator::OWN);
    Maybe<PropertyAttributes> maybe = JSReceiver::GetPropertyAttributes(&it);
    if (maybe.IsNothing()) return MaybeHandle<Object>();
    PropertyAttributes attrs = maybe.FromJust();
    // 7c. If propDesc is not undefined and propDesc.[[Enumerable]] is true:
    if (attrs == ABSENT) continue;
    if (attrs & DONT_ENUM) continue;
    // 7c i. Let descObj be Get(props, nextKey).
    // 7c ii. ReturnIfAbrupt(descObj).
    Handle<JSAny> desc_obj;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, desc_obj,
                               Cast<JSAny>(Object::GetProperty(&it)));
    // 7c iii. Let desc be ToPropertyDescriptor(descObj).
    bool success = PropertyDescriptor::ToPropertyDescriptor(
        isolate, desc_obj, &descriptors[descriptors_index]);
    // 7c iv. ReturnIfAbrupt(desc).
    if (!success) return MaybeHandle<Object>();
    // 7c v. Append the pair (a two element List) consisting of nextKey and
    //       desc to the end of descriptors.
    descriptors[descriptors_index].set_name(next_key);
    descriptors_index++;
  }
  // 8. For each pair from descriptors in list order,
  for (size_t i = 0; i < descriptors_index; ++i) {
    PropertyDescriptor* desc = &descriptors[i];
    // 8a. Let P be the first element of pair.
    // 8b. Let desc be the second element of pair.
    // 8c. Let status be DefinePropertyOrThrow(O, P, desc).
    Maybe<bool> status =
        DefineOwnProperty(isolate, Cast<JSReceiver>(object), desc->name(), desc,
                          Just(kThrowOnError));
    // 8d. ReturnIfAbrupt(status).
    if (status.IsNothing()) return MaybeHandle<Object>();
    CHECK(status.FromJust());
  }
  // 9. Return o.
  return object;
}

// static
Maybe<bool> JSReceiver::DefineOwnProperty(Isolate* isolate,
                                          Handle<JSReceiver> object,
                                          Handle<Object> key,
                                          PropertyDescriptor* desc,
                                          Maybe<ShouldThrow> should_throw) {
  if (IsJSArray(*object)) {
    return JSArray::DefineOwnProperty(isolate, Cast<JSArray>(object), key, desc,
                                      should_throw);
  }
  if (IsJSProxy(*object)) {
    return JSProxy::DefineOwnProperty(isolate, Cast<JSProxy>(object), key, desc,
                                      should_throw);
  }
  if (IsJSTypedArray(*object)) {
    return JSTypedArray::DefineOwnProperty(isolate, Cast<JSTypedArray>(object),
                                           key, desc, should_throw);
  }
  if (IsJSModuleNamespace(*object)) {
    return JSModuleNamespace::DefineOwnProperty(
        isolate, Cast<JSModuleNamespace>(object), key, desc, should_throw);
  }
  if (IsWasmObject(*object)) {
    RETURN_FAILURE(isolate, kThrowOnError,
                   NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));
  }
  if (IsAlwaysSharedSpaceJSObject(*object)) {
    return AlwaysSharedSpaceJSObject::DefineOwnProperty(
        isolate, Cast<AlwaysSharedSpaceJSObject>(object), key, desc,
        should_throw);
  }

  // OrdinaryDefineOwnProperty, by virtue of calling
  // DefineOwnPropertyIgnoreAttributes, can handle arguments
  // (ES#sec-arguments-exotic-objects-defineownproperty-p-desc).
  return OrdinaryDefineOwnProperty(isolate, Cast<JSObject>(object), key, desc,
                                   should_throw);
}

// static
Maybe<bool> JSReceiver::OrdinaryDefineOwnProperty(
    Isolate* isolate, Handle<JSObject> object, Handle<Object> key,
    PropertyDescriptor* desc, Maybe<ShouldThrow> should_throw) {
  DCHECK(IsName(*key) || IsNumber(*key));  // |key| is a PropertyKey.
  PropertyKey lookup_key(isolate, key);
  return OrdinaryDefineOwnProperty(isolate, object, lookup_key, desc,
                                   should_throw);
}

namespace {

MaybeHandle<JSAny> GetPropertyWithInterceptorInternal(
    LookupIterator* it, Handle<InterceptorInfo> interceptor, bool* done) {
  *done = false;
  Isolate* isolate = it->isolate();
  // Make sure that the top context does not change when doing callbacks or
  // interceptor calls.
  AssertNoContextChange ncc(isolate);

  if (IsUndefined(interceptor->getter(), isolate)) {
    return isolate->factory()->undefined_value();
  }

  DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
  Handle<JSAny> result;
  Handle<Object> receiver = it->GetReceiver();
  if (!IsJSReceiver(*receiver)) {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, receiver,
                               Object::ConvertReceiver(isolate, receiver));
  }
  PropertyCallbackArguments args(isolate, interceptor->data(), *receiver,
                                 *holder, Just(kDontThrow));

  if (it->IsElement(*holder)) {
    result = args.CallIndexedGetter(interceptor, it->array_index());
  } else {
    result = args.CallNamedGetter(interceptor, it->name());
  }
  // An exception was thrown in the interceptor. Propagate.
  RETURN_VALUE_IF_EXCEPTION_DETECTOR(isolate, args, kNullMaybeHandle);
  if (result.is_null()) return isolate->factory()->undefined_value();
  *done = true;
  args.AcceptSideEffects();
  // Rebox handle before return
  return handle(*result, isolate);
}

Maybe<PropertyAttributes> GetPropertyAttributesWithInterceptorInternal(
    LookupIterator* it, Handle<InterceptorInfo> interceptor) {
  Isolate* isolate = it->isolate();
  // Make sure that the top context does not change when doing
  // callbacks or interceptor calls.
  AssertNoContextChange ncc(isolate);
  HandleScope scope(isolate);

  DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
  DCHECK_IMPLIES(!it->IsElement(*holder) && IsSymbol(*it->name()),
                 interceptor->can_intercept_symbols());
  Handle<Object> receiver = it->GetReceiver();
  if (!IsJSReceiver(*receiver)) {
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, receiver,
                                     Object::ConvertReceiver(isolate, receiver),
                                     Nothing<PropertyAttributes>());
  }
  PropertyCallbackArguments args(isolate, interceptor->data(), *receiver,
                                 *holder, Just(kDontThrow));
  if (!IsUndefined(interceptor->query(), isolate)) {
    Handle<Object> result;
    if (it->IsElement(*holder)) {
      result = args.CallIndexedQuery(interceptor, it->array_index());
    } else {
      result = args.CallNamedQuery(interceptor, it->name());
    }
    // An exception was thrown in the interceptor. Propagate.
    RETURN_VALUE_IF_EXCEPTION_DETECTOR(isolate, args,
                                       Nothing<PropertyAttributes>());

    if (!result.is_null()) {
      int32_t value;
      CHECK(Object::ToInt32(*result, &value));
      DCHECK_IMPLIES((value & ~PropertyAttributes::ALL_ATTRIBUTES_MASK) != 0,
                     value == PropertyAttributes::ABSENT);
      // In case of absent property side effects are not allowed.
      // TODO(ishell): PropertyAttributes::ABSENT is not exposed in the Api,
      // so it can't be officially returned. We should fix the tests instead.
      if (value != PropertyAttributes::ABSENT) {
        args.AcceptSideEffects();
      }
      return Just(static_cast<PropertyAttributes>(value));
    }
  } else if (!IsUndefined(interceptor->getter(), isolate)) {
    // TODO(verwaest): Use GetPropertyWithInterceptor?
    Handle<Object> result;
    if (it->IsElement(*holder)) {
      result = args.CallIndexedGetter(interceptor, it->array_index());
    } else {
      result = args.CallNamedGetter(interceptor, it->name());
    }
    // An exception was thrown in the interceptor. Propagate.
    RETURN_VALUE_IF_EXCEPTION_DETECTOR(isolate, args,
                                       Nothing<PropertyAttributes>());

    if (!result.is_null()) {
      args.AcceptSideEffects();
      return Just(DONT_ENUM);
    }
  }
  return Just(ABSENT);
}

Maybe<InterceptorResult> SetPropertyWithInterceptorInternal(
    LookupIterator* it, DirectHandle<InterceptorInfo> interceptor,
    Maybe<ShouldThrow> should_throw, Handle<Object> value) {
  Isolate* isolate = it->isolate();
  // Make sure that the top context does not change when doing callbacks or
  // interceptor calls.
  AssertNoContextChange ncc(isolate);

  if (IsUndefined(interceptor->setter(), isolate)) {
    return Just(InterceptorResult::kNotIntercepted);
  }

  DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
  Handle<Object> receiver = it->GetReceiver();
  if (!IsJSReceiver(*receiver)) {
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, receiver,
                                     Object::ConvertReceiver(isolate, receiver),
                                     Nothing<InterceptorResult>());
  }
  PropertyCallbackArguments args(isolate, interceptor->data(), *receiver,
                                 *holder, should_throw);

  v8::Intercepted intercepted =
      it->IsElement(*holder)
          ? args.CallIndexedSetter(interceptor, it->array_index(), value)
          : args.CallNamedSetter(interceptor, it->name(), value);

  return args.GetBooleanReturnValue(intercepted, "Setter");
}

Maybe<InterceptorResult> DefinePropertyWithInterceptorInternal(
    LookupIterator* it, DirectHandle<InterceptorInfo> interceptor,
    Maybe<ShouldThrow> should_throw, PropertyDescriptor* desc) {
  Isolate* isolate = it->isolate();
  // Make sure that the top context does not change when doing callbacks or
  // interceptor calls.
  AssertNoContextChange ncc(isolate);

  if (IsUndefined(interceptor->definer(), isolate)) {
    return Just(InterceptorResult::kNotIntercepted);
  }

  DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
  Handle<Object> receiver = it->GetReceiver();
  if (!IsJSReceiver(*receiver)) {
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, receiver,
                                     Object::ConvertReceiver(isolate, receiver),
                                     Nothing<InterceptorResult>());
  }

  std::unique_ptr<v8::PropertyDescriptor> descriptor(
      new v8::PropertyDescriptor());
  if (PropertyDescriptor::IsAccessorDescriptor(desc)) {
    Handle<Object> getter = desc->get();
    if (!getter.is_null() && IsFunctionTemplateInfo(*getter)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, getter,
          ApiNatives::InstantiateFunction(
              isolate, Cast<FunctionTemplateInfo>(getter), MaybeHandle<Name>()),
          Nothing<InterceptorResult>());
    }
    Handle<Object> setter = desc->set();
    if (!setter.is_null() && IsFunctionTemplateInfo(*setter)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, setter,
          ApiNatives::InstantiateFunction(
              isolate, Cast<FunctionTemplateInfo>(setter), MaybeHandle<Name>()),
          Nothing<InterceptorResult>());
    }
    descriptor.reset(new v8::PropertyDescriptor(v8::Utils::ToLocal(getter),
                                                v8::Utils::ToLocal(setter)));
  } else if (PropertyDescriptor::IsDataDescriptor(desc)) {
    if (desc->has_writable()) {
      descriptor.reset(new v8::PropertyDescriptor(
          v8::Utils::ToLocal(desc->value()), desc->writable()));
    } else {
      descriptor.reset(
          new v8::PropertyDescriptor(v8::Utils::ToLocal(desc->value())));
    }
  }
  if (desc->has_enumerable()) {
    descriptor->set_enumerable(desc->enumerable());
  }
  if (desc->has_configurable()) {
    descriptor->set_configurable(desc->configurable());
  }

  PropertyCallbackArguments args(isolate, interceptor->data(), *receiver,
                                 *holder, should_throw);

  v8::Intercepted intercepted =
      it->IsElement(*holder)
          ? args.CallIndexedDefiner(interceptor, it->array_index(), *descriptor)
          : args.CallNamedDefiner(interceptor, it->name(), *descriptor);

  return args.GetBooleanReturnValue(intercepted, "Definer");
}

}  // namespace

// ES6 9.1.6.1
// static
Maybe<bool> JSReceiver::OrdinaryDefineOwnProperty(
    Isolate* isolate, Handle<JSObject> object, const PropertyKey& key,
    PropertyDescriptor* desc, Maybe<ShouldThrow> should_throw) {
  LookupIterator it(isolate, object, key, LookupIterator::OWN);

  // Deal with access checks first.
  while (it.state() == LookupIterator::ACCESS_CHECK) {
    if (!it.HasAccess()) {
      RETURN_ON_EXCEPTION_VALUE(
          isolate, isolate->ReportFailedAccessCheck(it.GetHolder<JSObject>()),
          Nothing<bool>());
      UNREACHABLE();
    }
    it.Next();
  }

  // 1. Let current be O.[[GetOwnProperty]](P).
  // 2. ReturnIfAbrupt(current).
  PropertyDescriptor current;
  MAYBE_RETURN(GetOwnPropertyDescriptor(&it, &current), Nothing<bool>());

  // TODO(jkummerow/verwaest): It would be nice if we didn't have to reset
  // the iterator every time. Currently, the reasons why we need it are because
  // GetOwnPropertyDescriptor can have side effects, namely:
  // - Interceptors
  // - Accessors (which might change the holder's map)
  it.Restart();

  // Skip over the access check after restarting -- we've already checked it.
  while (it.state() == LookupIterator::ACCESS_CHECK) {
    DCHECK(it.HasAccess());
    it.Next();
  }

  // Handle interceptor.
  if (it.state() == LookupIterator::INTERCEPTOR) {
    if (it.HolderIsReceiverOrHiddenPrototype()) {
      InterceptorResult result;
      if (!DefinePropertyWithInterceptorInternal(&it, it.GetInterceptor(),
                                                 should_throw, desc)
               .To(&result)) {
        // An exception was thrown in the interceptor. Propagate.
        return Nothing<bool>();
      }
      switch (result) {
        case InterceptorResult::kFalse:
          return Just(false);
        case InterceptorResult::kTrue:
          return Just(true);

        case InterceptorResult::kNotIntercepted:
          // Proceed lookup.
          break;
      }
      // We need to restart the lookup in case the interceptor ran with side
      // effects.
      it.Restart();
    }
  }

  // 3. Let extensible be the value of the [[Extensible]] internal slot of O.
  bool extensible = JSObject::IsExtensible(isolate, object);

  return ValidateAndApplyPropertyDescriptor(
      isolate, &it, extensible, desc, &current, should_throw, Handle<Name>());
}

// ES6 9.1.6.2
// static
Maybe<bool> JSReceiver::IsCompatiblePropertyDescriptor(
    Isolate* isolate, bool extensible, PropertyDescriptor* desc,
    PropertyDescriptor* current, Handle<Name> property_name,
    Maybe<ShouldThrow> should_throw) {
  // 1. Return ValidateAndApplyPropertyDescriptor(undefined, undefined,
  //    Extensible, Desc, Current).
  return ValidateAndApplyPropertyDescriptor(
      isolate, nullptr, extensible, desc, current, should_throw, property_name);
}

// https://tc39.es/ecma262/#sec-validateandapplypropertydescriptor
// static
Maybe<bool> JSReceiver::ValidateAndApplyPropertyDescriptor(
    Isolate* isolate, LookupIterator* it, bool extensible,
    PropertyDescriptor* desc, PropertyDescriptor* current,
    Maybe<ShouldThrow> should_throw, Handle<Name> property_name) {
  // We either need a LookupIterator, or a property name.
  DCHECK((it == nullptr) != property_name.is_null());
  bool desc_is_data_descriptor = PropertyDescriptor::IsDataDescriptor(desc);
  bool desc_is_accessor_descriptor =
      PropertyDescriptor::IsAccessorDescriptor(desc);
  bool desc_is_generic_descriptor =
      PropertyDescriptor::IsGenericDescriptor(desc);
  // 1. (Assert)
  // 2. If current is undefined, then
  if (current->is_empty()) {
    // 2a. If extensible is false, return false.
    if (!extensible) {
      RETURN_FAILURE(
          isolate, GetShouldThrow(isolate, should_throw),
          NewTypeError(MessageTemplate::kDefineDisallowed,
                       it != nullptr ? it->GetName() : property_name));
    }
    // 2c. If IsGenericDescriptor(Desc) or IsDataDescriptor(Desc) is true, then:
    // (This is equivalent to !IsAccessorDescriptor(desc).)
    DCHECK_EQ(desc_is_generic_descriptor || desc_is_data_descriptor,
              !desc_is_accessor_descriptor);
    if (!desc_is_accessor_descriptor) {
      // 2c i. If O is not undefined, create an own data property named P of
      // object O whose [[Value]], [[Writable]], [[Enumerable]] and
      // [[Configurable]] attribute values are described by Desc. If the value
      // of an attribute field of Desc is absent, the attribute of the newly
      // created property is set to its default value.
      if (it != nullptr) {
        if (!desc->has_writable()) desc->set_writable(false);
        if (!desc->has_enumerable()) desc->set_enumerable(false);
        if (!desc->has_configurable()) desc->set_configurable(false);
        Handle<Object> value(
            desc->has_value()
                ? desc->value()
                : Cast<Object>(isolate->factory()->undefined_value()));
        MaybeHandle<Object> result =
            JSObject::DefineOwnPropertyIgnoreAttributes(it, value,
                                                        desc->ToAttributes());
        if (result.is_null()) return Nothing<bool>();
      }
    } else {
      // 2d. Else Desc must be an accessor Property Descriptor,
      DCHECK(desc_is_accessor_descriptor);
      // 2d i. If O is not undefined, create an own accessor property named P
      // of object O whose [[Get]], [[Set]], [[Enumerable]] and
      // [[Configurable]] attribute values are described by Desc. If the value
      // of an attribute field of Desc is absent, the attribute of the newly
      // created property is set to its default value.
      if (it != nullptr) {
        if (!desc->has_enumerable()) desc->set_enumerable(false);
        if (!desc->has_configurable()) desc->set_configurable(false);
        DirectHandle<Object> getter(
            desc->has_get() ? desc->get()
                            : Cast<Object>(isolate->factory()->null_value()));
        DirectHandle<Object> setter(
            desc->has_set() ? desc->set()
                            : Cast<Object>(isolate->factory()->null_value()));
        MaybeHandle<Object> result =
            JSObject::DefineOwnAccessorIgnoreAttributes(it, getter, setter,
                                                        desc->ToAttributes());
        if (result.is_null()) return Nothing<bool>();
      }
    }
    // 2e. Return true.
    return Just(true);
  }
  // 3. If every field in Desc is absent, return true. (This also has a shortcut
  // not in the spec: if every field value matches the current value, return.)
  if ((!desc->has_enumerable() ||
       desc->enumerable() == current->enumerable()) &&
      (!desc->has_configurable() ||
       desc->configurable() == current->configurable()) &&
      !desc->has_value() &&
      (!desc->has_writable() ||
       (current->has_writable() && current->writable() == desc->writable())) &&
      (!desc->has_get() ||
       (current->has_get() &&
        Object::SameValue(*current->get(), *desc->get()))) &&
      (!desc->has_set() ||
       (current->has_set() &&
        Object::SameValue(*current->set(), *desc->set())))) {
    return Just(true);
  }
  // 4. If current.[[Configurable]] is false, then
  if (!current->configurable()) {
    // 4a. If Desc.[[Configurable]] is present and its value is true, return
    // false.
    if (desc->has_configurable() && desc->configurable()) {
      RETURN_FAILURE(
          isolate, GetShouldThrow(isolate, should_throw),
          NewTypeError(MessageTemplate::kRedefineDisallowed,
                       it != nullptr ? it->GetName() : property_name));
    }
    // 4b. If Desc.[[Enumerable]] is present and
    // ! SameValue(Desc.[[Enumerable]], current.[[Enumerable]]) is false, return
    // false.
    if (desc->has_enumerable() && desc->enumerable() != current->enumerable()) {
      RETURN_FAILURE(
          isolate, GetShouldThrow(isolate, should_throw),
          NewTypeError(MessageTemplate::kRedefineDisallowed,
                       it != nullptr ? it->GetName() : property_name));
    }
  }

  bool current_is_data_descriptor =
      PropertyDescriptor::IsDataDescriptor(current);
  // 5. If ! IsGenericDescriptor(Desc) is true, no further validation is
  // required.
  if (desc_is_generic_descriptor) {
    // Nothing to see here.

    // 6. Else if ! SameValue(!IsDataDescriptor(current),
    // !IsDataDescriptor(Desc)) is false, the
  } else if (current_is_data_descriptor != desc_is_data_descriptor) {
    // 6a. If current.[[Configurable]] is false, return false.
    if (!current->configurable()) {
      RETURN_FAILURE(
          isolate, GetShouldThrow(isolate, should_throw),
          NewTypeError(MessageTemplate::kRedefineDisallowed,
                       it != nullptr ? it->GetName() : property_name));
    }
    // 6b. If IsDataDescriptor(current) is true, then:
    if (current_is_data_descriptor) {
      // 6b i. If O is not undefined, convert the property named P of object O
      // from a data property to an accessor property. Preserve the existing
      // values of the converted property's [[Configurable]] and [[Enumerable]]
      // attributes and set the rest of the property's attributes to their
      // default values.
      // --> Folded into step 9
    } else {
      // 6c i. If O is not undefined, convert the property named P of object O
      // from an accessor property to a data property. Preserve the existing
      // values of the converted property’s [[Configurable]] and [[Enumerable]]
      // attributes and set the rest of the property’s attributes to their
      // default values.
      // --> Folded into step 9
    }

    // 7. Else if IsDataDescriptor(current) and IsDataDescriptor(Desc) are both
    // true, then:
  } else if (current_is_data_descriptor && desc_is_data_descriptor) {
    // 7a. If current.[[Configurable]] is false and current.[[Writable]] is
    // false, then
    if (!current->configurable() && !current->writable()) {
      // 7a i. If Desc.[[Writable]] is present and Desc.[[Writable]] is true,
      // return false.
      if (desc->has_writable() && desc->writable()) {
        RETURN_FAILURE(
            isolate, GetShouldThrow(isolate, should_throw),
            NewTypeError(MessageTemplate::kRedefineDisallowed,
                         it != nullptr ? it->GetName() : property_name));
      }
      // 7a ii. If Desc.[[Value]] is present and SameValue(Desc.[[Value]],
      // current.[[Value]]) is false, return false.
      if (desc->has_value()) {
        // We'll succeed applying the property, but the value is already the
        // same and the property is read-only, so skip actually writing the
        // property. Otherwise we may try to e.g., write to frozen elements.
        if (Object::SameValue(*desc->value(), *current->value()))
          return Just(true);
        RETURN_FAILURE(
            isolate, GetShouldThrow(isolate, should_throw),
            NewTypeError(MessageTemplate::kRedefineDisallowed,
                         it != nullptr ? it->GetName() : property_name));
      }
    }
  } else {
    // 8. Else,
    // 8a. Assert: ! IsAccessorDescriptor(current) and
    // ! IsAccessorDescriptor(Desc) are both true.
    DCHECK(PropertyDescriptor::IsAccessorDescriptor(current) &&
           desc_is_accessor_descriptor);
    // 8b. If current.[[Configurable]] is false, then:
    if (!current->configurable()) {
      // 8a i. If Desc.[[Set]] is present and SameValue(Desc.[[Set]],
      // current.[[Set]]) is false, return false.
      if (desc->has_set() &&
          !Object::SameValue(*desc->set(), *current->set())) {
        RETURN_FAILURE(
            isolate, GetShouldThrow(isolate, should_throw),
            NewTypeError(MessageTemplate::kRedefineDisallowed,
                         it != nullptr ? it->GetName() : property_name));
      }
      // 8a ii. If Desc.[[Get]] is present and SameValue(Desc.[[Get]],
      // current.[[Get]]) is false, return false.
      if (desc->has_get() &&
          !Object::SameValue(*desc->get(), *current-
```