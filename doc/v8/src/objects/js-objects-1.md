Response: The user wants a summary of the C++ source code file `v8/src/objects/js-objects.cc`. This is the second of four parts of the file.

Based on the provided code snippet, this part seems to focus on the implementation of core JavaScript object functionalities related to property manipulation, such as:

- Defining properties (including data and accessor properties)
- Creating data properties
- Adding private fields
- Getting property descriptors
- Setting integrity levels (sealing and freezing)
- Checking integrity levels
- Preventing extensions
- Checking extensibility
- Converting objects to primitive values
- Getting own property values and entries
- Setting the prototype of an object

It also includes some utility functions for fast property access and manipulation for optimized scenarios.

To illustrate the connection with JavaScript, I will use examples that directly correspond to the C++ functions being implemented.
这个C++代码文件（`v8/src/objects/js-objects.cc` 的第二部分）主要负责实现 **JavaScript 对象的属性操作相关的核心功能**。它定义了诸如创建、定义、获取和修改对象属性的行为，以及控制对象的扩展性和完整性的方法。

以下是其主要功能的归纳：

1. **定义自有属性 (DefineOwnProperty)**：
    - 实现了 ECMAScript 规范中 `[[DefineOwnProperty]]` 抽象操作，用于在一个对象上定义或修改一个自有属性。
    - 它可以创建新的属性，也可以修改已有的属性（包括数据属性和访问器属性）。
    - 涉及到属性的各种特性，如 `writable`（可写）、`enumerable`（可枚举）、`configurable`（可配置）。

    ```javascript
    const obj = {};

    // 定义一个数据属性
    Object.defineProperty(obj, 'a', {
      value: 1,
      writable: true,
      enumerable: true,
      configurable: true
    });

    // 定义一个访问器属性
    Object.defineProperty(obj, 'b', {
      get() { return this._b; },
      set(value) { this._b = value; },
      enumerable: true,
      configurable: true
    });
    ```

2. **创建数据属性 (CreateDataProperty)**：
    - 提供便捷的方法来创建一个新的数据属性，并设置其默认特性（writable、enumerable、configurable 都为 true）。

    ```javascript
    const obj = {};
    obj.c = 2; // 相当于 JSReceiver::CreateDataProperty

    // 或者使用更明确的方法
    Object.defineProperty(obj, 'd', { value: 3, writable: true, enumerable: true, configurable: true });
    ```

3. **添加私有字段 (AddPrivateField)**：
    - 实现了添加私有字段的功能，这与 JavaScript 中的私有类字段 `#field` 语法相关。

    ```javascript
    class MyClass {
      #privateField = 0;

      increment() {
        this.#privateField++;
      }

      getPrivateField() {
        return this.#privateField;
      }
    }

    const instance = new MyClass();
    instance.increment();
    console.log(instance.getPrivateField()); // 输出 1
    // console.log(instance.#privateField); // 外部无法直接访问私有字段
    ```

4. **获取自有属性描述符 (GetOwnPropertyDescriptor)**：
    - 实现了 ECMAScript 规范中 `[[GetOwnProperty]]` 抽象操作，用于获取对象自有属性的描述符，描述符包含了属性的值和特性。

    ```javascript
    const obj = { e: 4 };
    const descriptor = Object.getOwnPropertyDescriptor(obj, 'e');
    console.log(descriptor); // 输出: { value: 4, writable: true, enumerable: true, configurable: true }
    ```

5. **设置对象的完整性级别 (SetIntegrityLevel)**：
    - 实现了 `Object.seal()` 和 `Object.freeze()` 的底层逻辑，用于阻止对象添加新属性，并分别禁止删除属性和修改数据属性的可写性。

    ```javascript
    const sealedObj = { f: 5 };
    Object.seal(sealedObj);
    sealedObj.g = 6; // 无法添加新属性
    delete sealedObj.f; // 无法删除属性
    sealedObj.f = 7; // 可以修改属性值 (因为 writable 默认是 true)

    const frozenObj = { h: 8 };
    Object.freeze(frozenObj);
    frozenObj.i = 9; // 无法添加新属性
    delete frozenObj.h; // 无法删除属性
    frozenObj.h = 10; // 无法修改属性值 (因为 writable 被设置为 false)
    ```

6. **测试对象的完整性级别 (TestIntegrityLevel)**：
    - 实现了 `Object.isSealed()` 和 `Object.isFrozen()` 的底层逻辑，用于检查对象是否已被密封或冻结。

    ```javascript
    const obj1 = { j: 11 };
    console.log(Object.isSealed(obj1)); // 输出: false
    Object.seal(obj1);
    console.log(Object.isSealed(obj1)); // 输出: true

    const obj2 = { k: 12 };
    console.log(Object.isFrozen(obj2)); // 输出: false
    Object.freeze(obj2);
    console.log(Object.isFrozen(obj2)); // 输出: true
    ```

7. **阻止对象扩展 (PreventExtensions)**：
    - 实现了 `Object.preventExtensions()` 的底层逻辑，阻止向对象添加新的属性。

    ```javascript
    const nonExtensibleObj = { l: 13 };
    Object.preventExtensions(nonExtensibleObj);
    nonExtensibleObj.m = 14; // 尝试添加新属性会失败 (在严格模式下会抛出 TypeError)
    console.log(Object.isExtensible(nonExtensibleObj)); // 输出: false
    ```

8. **判断对象是否可扩展 (IsExtensible)**：
    - 实现了 `Object.isExtensible()` 的底层逻辑，检查对象是否可以添加新的属性。

    ```javascript
    const obj = {};
    console.log(Object.isExtensible(obj)); // 输出: true
    Object.preventExtensions(obj);
    console.log(Object.isExtensible(obj)); // 输出: false
    ```

9. **将对象转换为原始值 (ToPrimitive)**：
    - 实现了 ECMAScript 规范中的 `ToPrimitive` 抽象操作，用于将对象转换为原始值（如字符串或数字）。这与 `valueOf()` 和 `toString()` 方法有关。

    ```javascript
    const obj = {
      valueOf() { return 15; },
      toString() { return 'object'; }
    };

    console.log(Number(obj));   // 输出 15 (优先调用 valueOf)
    console.log(String(obj));   // 输出 'object' (优先调用 toString)
    console.log(`${obj}`);      // 输出 '15' (根据上下文，可能调用 valueOf 或 toString)
    ```

10. **获取自有属性的值或条目 (GetOwnValuesOrEntries)**：
    - 提供了获取对象自身可枚举属性的值或键值对的功能，类似于 `Object.values()` 和 `Object.entries()`。

    ```javascript
    const obj = { n: 16, o: 17 };
    console.log(Object.values(obj));  // 输出: [ 16, 17 ]
    console.log(Object.entries(obj)); // 输出: [ [ 'n', 16 ], [ 'o', 17 ] ]
    ```

11. **设置对象的原型 (SetPrototype)**：
    - 实现了 `Object.setPrototypeOf()` 的底层逻辑，用于设置对象的原型。

    ```javascript
    const proto = { p: 18 };
    const obj = { q: 19 };
    Object.setPrototypeOf(obj, proto);
    console.log(obj.p); // 输出 18 (从原型链继承)
    ```

总而言之，这部分 C++ 代码是 V8 引擎中处理 JavaScript 对象属性的核心部分，其功能与 JavaScript 中用于操作对象属性的内置方法和语法密切相关。它直接影响着 JavaScript 代码在 V8 引擎中的执行方式和效率。
### 提示词
```
这是目录为v8/src/objects/js-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
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
    case JS_GLOBAL_OBJECT_TYPE:
      return JSGlobalObject::kHeaderSize;
    case JS_BOUND_FUNCTION_TYPE:
      return JSBoundFunction::kHeaderSize;
    case JS_FUNCTION_TYPE:
    case JS_CLASS_CONSTRUCTOR_TYPE:
    case JS_PROMISE_CONSTRUCTOR_TYPE:
    case JS_REG_EXP_CONSTRUCTOR_TYPE:
    case JS_ARRAY_CONSTRUCTOR_TYPE:
#define TYPED_ARRAY_CONSTRUCTORS_SWITCH(Type, type, TYPE, Ctype) \
  case TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE:
      TYPED_ARRAYS(TYPED_ARRAY_CONSTRUCTORS_SWITCH)
#undef TYPED_ARRAY_CONSTRUCTORS_SWITCH
      return JSFunction::GetHeaderSize(function_has_prototype_slot);
    case JS_PRIMITIVE_WRAPPER_TYPE:
      return JSPrimitiveWrapper::kHeaderSize;
    case JS_DATE_TYPE:
      return JSDate::kHeaderSize;
    case JS_DISPOSABLE_STACK_BASE_TYPE:
      return JSDisposableStackBase::kHeaderSize;
    case JS_ASYNC_DISPOSABLE_STACK_TYPE:
      return JSAsyncDisposableStack::kHeaderSize;
    case JS_SYNC_DISPOSABLE_STACK_TYPE:
      return JSSyncDisposableStack::kHeaderSize;
    case JS_ARRAY_TYPE:
      return JSArray::kHeaderSize;
    case JS_ARRAY_BUFFER_TYPE:
      return JSArrayBuffer::kHeaderSize;
    case JS_ARRAY_ITERATOR_TYPE:
      return JSArrayIterator::kHeaderSize;
    case JS_TYPED_ARRAY_TYPE:
      return JSTypedArray::kHeaderSize;
    case JS_DATA_VIEW_TYPE:
      return JSDataView::kHeaderSize;
    case JS_RAB_GSAB_DATA_VIEW_TYPE:
      return JSRabGsabDataView::kHeaderSize;
    case JS_SET_TYPE:
      return JSSet::kHeaderSize;
    case JS_MAP_TYPE:
      return JSMap::kHeaderSize;
    case JS_SET_KEY_VALUE_ITERATOR_TYPE:
    case JS_SET_VALUE_ITERATOR_TYPE:
      return JSSetIterator::kHeaderSize;
    case JS_MAP_KEY_ITERATOR_TYPE:
    case JS_MAP_KEY_VALUE_ITERATOR_TYPE:
    case JS_MAP_VALUE_ITERATOR_TYPE:
      return JSMapIterator::kHeaderSize;
    case JS_WEAK_REF_TYPE:
      return JSWeakRef::kHeaderSize;
    case JS_FINALIZATION_REGISTRY_TYPE:
      return JSFinalizationRegistry::kHeaderSize;
    case JS_WEAK_MAP_TYPE:
      return JSWeakMap::kHeaderSize;
    case JS_WEAK_SET_TYPE:
      return JSWeakSet::kHeaderSize;
    case JS_PROMISE_TYPE:
      return JSPromise::kHeaderSize;
    case JS_REG_EXP_TYPE:
      return JSRegExp::kHeaderSize;
    case JS_REG_EXP_STRING_ITERATOR_TYPE:
      return JSRegExpStringIterator::kHeaderSize;
    case JS_MESSAGE_OBJECT_TYPE:
      return JSMessageObject::kHeaderSize;
    case JS_EXTERNAL_OBJECT_TYPE:
      return JSExternalObject::kHeaderSize;
    case JS_SHADOW_REALM_TYPE:
      return JSShadowRealm::kHeaderSize;
    case JS_STRING_ITERATOR_TYPE:
      return JSStringIterator::kHeaderSize;
    case JS_ITERATOR_MAP_HELPER_TYPE:
      return JSIteratorMapHelper::kHeaderSize;
    case JS_ITERATOR_FILTER_HELPER_TYPE:
      return JSIteratorFilterHelper::kHeaderSize;
    case JS_ITERATOR_TAKE_HELPER_TYPE:
      return JSIteratorTakeHelper::kHeaderSize;
    case JS_ITERATOR_DROP_HELPER_TYPE:
      return JSIteratorDropHelper::kHeaderSize;
    case JS_ITERATOR_FLAT_MAP_HELPER_TYPE:
      return JSIteratorFlatMapHelper::kHeaderSize;
    case JS_MODULE_NAMESPACE_TYPE:
      return JSModuleNamespace::kHeaderSize;
    case JS_SHARED_ARRAY_TYPE:
      return JSSharedArray::kHeaderSize;
    case JS_SHARED_STRUCT_TYPE:
      return JSSharedStruct::kHeaderSize;
    case JS_ATOMICS_MUTEX_TYPE:
      return JSAtomicsMutex::kHeaderSize;
    case JS_ATOMICS_CONDITION_TYPE:
      return JSAtomicsCondition::kHeaderSize;
    case JS_TEMPORAL_CALENDAR_TYPE:
      return JSTemporalCalendar::kHeaderSize;
    case JS_TEMPORAL_DURATION_TYPE:
      return JSTemporalDuration::kHeaderSize;
    case JS_TEMPORAL_INSTANT_TYPE:
      return JSTemporalInstant::kHeaderSize;
    case JS_TEMPORAL_PLAIN_DATE_TYPE:
      return JSTemporalPlainDate::kHeaderSize;
    case JS_TEMPORAL_PLAIN_DATE_TIME_TYPE:
      return JSTemporalPlainDateTime::kHeaderSize;
    case JS_TEMPORAL_PLAIN_MONTH_DAY_TYPE:
      return JSTemporalPlainMonthDay::kHeaderSize;
    case JS_TEMPORAL_PLAIN_TIME_TYPE:
      return JSTemporalPlainTime::kHeaderSize;
    case JS_TEMPORAL_PLAIN_YEAR_MONTH_TYPE:
      return JSTemporalPlainYearMonth::kHeaderSize;
    case JS_TEMPORAL_TIME_ZONE_TYPE:
      return JSTemporalTimeZone::kHeaderSize;
    case JS_TEMPORAL_ZONED_DATE_TIME_TYPE:
      return JSTemporalZonedDateTime::kHeaderSize;
    case JS_VALID_ITERATOR_WRAPPER_TYPE:
      return JSValidIteratorWrapper::kHeaderSize;
    case JS_WRAPPED_FUNCTION_TYPE:
      return JSWrappedFunction::kHeaderSize;
    case JS_RAW_JSON_TYPE:
      return JSRawJson::kHeaderSize;
#ifdef V8_INTL_SUPPORT
    case JS_V8_BREAK_ITERATOR_TYPE:
      return JSV8BreakIterator::kHeaderSize;
    case JS_COLLATOR_TYPE:
      return JSCollator::kHeaderSize;
    case JS_DATE_TIME_FORMAT_TYPE:
      return JSDateTimeFormat::kHeaderSize;
    case JS_DISPLAY_NAMES_TYPE:
      return JSDisplayNames::kHeaderSize;
    case JS_DURATION_FORMAT_TYPE:
      return JSDurationFormat::kHeaderSize;
    case JS_LIST_FORMAT_TYPE:
      return JSListFormat::kHeaderSize;
    case JS_LOCALE_TYPE:
      return JSLocale::kHeaderSize;
    case JS_NUMBER_FORMAT_TYPE:
      return JSNumberFormat::kHeaderSize;
    case JS_PLURAL_RULES_TYPE:
      return JSPluralRules::kHeaderSize;
    case JS_RELATIVE_TIME_FORMAT_TYPE:
      return JSRelativeTimeFormat::kHeaderSize;
    case JS_SEGMENT_ITERATOR_TYPE:
      return JSSegmentIterator::kHeaderSize;
    case JS_SEGMENTER_TYPE:
      return JSSegmenter::kHeaderSize;
    case JS_SEGMENTS_TYPE:
      return JSSegments::kHeaderSize;
#endif  // V8_INTL_SUPPORT
#if V8_ENABLE_WEBASSEMBLY
    case WASM_GLOBAL_OBJECT_TYPE:
      return WasmGlobalObject::kHeaderSize;
    case WASM_INSTANCE_OBJECT_TYPE:
      return WasmInstanceObject::kHeaderSize;
    case WASM_MEMORY_OBJECT_TYPE:
      return WasmMemoryObject::kHeaderSize;
    case WASM_MODULE_OBJECT_TYPE:
      return WasmModuleObject::kHeaderSize;
    case WASM_TABLE_OBJECT_TYPE:
      return WasmTableObject::kHeaderSize;
    case WASM_VALUE_OBJECT_TYPE:
      return WasmValueObject::kHeaderSize;
    case WASM_TAG_OBJECT_TYPE:
      return WasmTagObject::kHeaderSize;
    case WASM_EXCEPTION_PACKAGE_TYPE:
      return WasmExceptionPackage::kHeaderSize;
    case WASM_SUSPENDING_OBJECT_TYPE:
      return WasmSuspendingObject::kHeaderSize;
#endif  // V8_ENABLE_WEBASSEMBLY
    default: {
      // Special type check for API Objects because they are in a large variable
      // instance type range.
      if (InstanceTypeChecker::IsJSApiObject(type)) {
        return JSAPIObjectWithEmbedderSlots::BodyDescriptor::kHeaderSize;
      }
      FATAL("unexpected instance type: %s\n", NonAPIInstanceTypeToString(type));
    }
  }
}

MaybeHandle<JSAny> JSObject::GetPropertyWithFailedAccessCheck(
    LookupIterator* it) {
  Isolate* isolate = it->isolate();
  Handle<JSObject> checked = it->GetHolder<JSObject>();
  Handle<InterceptorInfo> interceptor =
      it->GetInterceptorForFailedAccessCheck();
  if (!interceptor.is_null()) {
    Handle<JSAny> result;
    bool done;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, result,
        GetPropertyWithInterceptorInternal(it, interceptor, &done));
    if (done) return result;
  }

  // Cross-Origin [[Get]] of Well-Known Symbols does not throw, and returns
  // undefined.
  DirectHandle<Name> name = it->GetName();
  if (IsSymbol(*name) && Cast<Symbol>(*name)->is_well_known_symbol()) {
    return it->factory()->undefined_value();
  }

  RETURN_ON_EXCEPTION(isolate, isolate->ReportFailedAccessCheck(checked));
  UNREACHABLE();
}

Maybe<PropertyAttributes> JSObject::GetPropertyAttributesWithFailedAccessCheck(
    LookupIterator* it) {
  Isolate* isolate = it->isolate();
  Handle<JSObject> checked = it->GetHolder<JSObject>();
  Handle<InterceptorInfo> interceptor =
      it->GetInterceptorForFailedAccessCheck();
  if (!interceptor.is_null()) {
    Maybe<PropertyAttributes> result =
        GetPropertyAttributesWithInterceptorInternal(it, interceptor);
    if (isolate->has_exception()) return Nothing<PropertyAttributes>();
    if (result.FromMaybe(ABSENT) != ABSENT) return result;
  }
  RETURN_ON_EXCEPTION_VALUE(isolate, isolate->ReportFailedAccessCheck(checked),
                            Nothing<PropertyAttributes>());
  UNREACHABLE();
}

Maybe<bool> JSObject::SetPropertyWithFailedAccessCheck(
    LookupIterator* it, Handle<Object> value, Maybe<ShouldThrow> should_throw) {
  Isolate* isolate = it->isolate();
  Handle<JSObject> checked = it->GetHolder<JSObject>();
  Handle<InterceptorInfo> interceptor =
      it->GetInterceptorForFailedAccessCheck();
  if (!interceptor.is_null()) {
    InterceptorResult result;
    if (!SetPropertyWithInterceptorInternal(it, interceptor, should_throw,
                                            value)
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
        // Fall through to report failed access check.
        break;
    }
  }
  RETURN_ON_EXCEPTION_VALUE(isolate, isolate->ReportFailedAccessCheck(checked),
                            Nothing<bool>());
  UNREACHABLE();
}

void JSObject::SetNormalizedProperty(Handle<JSObject> object, Handle<Name> name,
                                     Handle<Object> value,
                                     PropertyDetails details) {
  DCHECK(!object->HasFastProperties());
  DCHECK(IsUniqueName(*name));
  Isolate* isolate = object->GetIsolate();

  uint32_t hash = name->hash();

  if (IsJSGlobalObject(*object)) {
    auto global_obj = Cast<JSGlobalObject>(object);
    Handle<GlobalDictionary> dictionary(
        global_obj->global_dictionary(kAcquireLoad), isolate);
    ReadOnlyRoots roots(isolate);
    InternalIndex entry = dictionary->FindEntry(isolate, roots, name, hash);

    if (entry.is_not_found()) {
      DCHECK_IMPLIES(global_obj->map()->is_prototype_map(),
                     Map::IsPrototypeChainInvalidated(global_obj->map()));
      auto cell_type = IsUndefined(*value, roots) ? PropertyCellType::kUndefined
                                                  : PropertyCellType::kConstant;
      details = details.set_cell_type(cell_type);
      auto cell = isolate->factory()->NewPropertyCell(name, details, value);
      dictionary =
          GlobalDictionary::Add(isolate, dictionary, name, cell, details);
      global_obj->set_global_dictionary(*dictionary, kReleaseStore);
    } else {
      PropertyCell::PrepareForAndSetValue(isolate, dictionary, entry, value,
                                          details);
      DCHECK_EQ(dictionary->CellAt(entry)->value(), *value);
    }
  } else {
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      Handle<SwissNameDictionary> dictionary(
          object->property_dictionary_swiss(), isolate);
      InternalIndex entry = dictionary->FindEntry(isolate, *name);
      if (entry.is_not_found()) {
        DCHECK_IMPLIES(object->map()->is_prototype_map(),
                       Map::IsPrototypeChainInvalidated(object->map()));
        dictionary =
            SwissNameDictionary::Add(isolate, dictionary, name, value, details);
        object->SetProperties(*dictionary);
      } else {
        dictionary->ValueAtPut(entry, *value);
        dictionary->DetailsAtPut(entry, details);
      }
    } else {
      Handle<NameDictionary> dictionary(object->property_dictionary(), isolate);
      InternalIndex entry = dictionary->FindEntry(isolate, name);
      if (entry.is_not_found()) {
        DCHECK_IMPLIES(object->map()->is_prototype_map(),
                       Map::IsPrototypeChainInvalidated(object->map()));
        dictionary =
            NameDictionary::Add(isolate, dictionary, name, value, details);
        object->SetProperties(*dictionary);
      } else {
        PropertyDetails original_details = dictionary->DetailsAt(entry);
        int enumeration_index = original_details.dictionary_index();
        DCHECK_GT(enumeration_index, 0);
        details = details.set_index(enumeration_index);
        dictionary->SetEntry(entry, *name, *value, details);
      }
      // TODO(pthier): Add flags to swiss dictionaries.
      if (name->IsInteresting(isolate)) {
        dictionary->set_may_have_interesting_properties(true);
      }
    }
  }
}

void JSObject::SetNormalizedElement(Handle<JSObject> object, uint32_t index,
                                    Handle<Object> value,
                                    PropertyDetails details) {
  DCHECK_EQ(object->GetElementsKind(), DICTIONARY_ELEMENTS);

  Isolate* isolate = object->GetIsolate();

  Handle<NumberDictionary> dictionary =
      handle(Cast<NumberDictionary>(object->elements()), isolate);
  dictionary =
      NumberDictionary::Set(isolate, dictionary, index, value, object, details);
  object->set_elements(*dictionary);
}

void JSObject::JSObjectShortPrint(StringStream* accumulator) {
  switch (map()->instance_type()) {
    case JS_ARRAY_TYPE: {
      double length = IsUndefined(Cast<JSArray>(*this)->length())
                          ? 0
                          : Object::NumberValue(Cast<JSArray>(*this)->length());
      accumulator->Add("<JSArray[%u]>", static_cast<uint32_t>(length));
      break;
    }
    case JS_BOUND_FUNCTION_TYPE: {
      Tagged<JSBoundFunction> bound_function = Cast<JSBoundFunction>(*this);
      accumulator->Add("<JSBoundFunction");
      accumulator->Add(" (BoundTargetFunction %p)>",
                       reinterpret_cast<void*>(
                           bound_function->bound_target_function().ptr()));
      break;
    }
    case JS_WEAK_MAP_TYPE: {
      accumulator->Add("<JSWeakMap>");
      break;
    }
    case JS_WEAK_SET_TYPE: {
      accumulator->Add("<JSWeakSet>");
      break;
    }
    case JS_REG_EXP_TYPE: {
      accumulator->Add("<JSRegExp");
      Tagged<JSRegExp> regexp = Cast<JSRegExp>(*this);
      if (IsString(regexp->source())) {
        accumulator->Add(" ");
        Cast<String>(regexp->source())->StringShortPrint(accumulator);
      }
      accumulator->Add(">");

      break;
    }
    case JS_PROMISE_CONSTRUCTOR_TYPE:
    case JS_REG_EXP_CONSTRUCTOR_TYPE:
    case JS_ARRAY_CONSTRUCTOR_TYPE:
#define TYPED_ARRAY_CONSTRUCTORS_SWITCH(Type, type, TYPE, Ctype) \
  case TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE:
      TYPED_ARRAYS(TYPED_ARRAY_CONSTRUCTORS_SWITCH)
#undef TYPED_ARRAY_CONSTRUCTORS_SWITCH
    case JS_CLASS_CONSTRUCTOR_TYPE:
    case JS_FUNCTION_TYPE: {
      Tagged<JSFunction> function = Cast<JSFunction>(*this);
      std::unique_ptr<char[]> fun_name = function->shared()->DebugNameCStr();
      if (fun_name[0] != '\0') {
        accumulator->Add("<JSFunction ");
        accumulator->Add(fun_name.get());
      } else {
        accumulator->Add("<JSFunction");
      }
      if (v8_flags.trace_file_names) {
        Tagged<Object> source_name =
            Cast<Script>(function->shared()->script())->name();
        if (IsString(source_name)) {
          Tagged<String> str = Cast<String>(source_name);
          if (str->length() > 0) {
            accumulator->Add(" <");
            accumulator->Put(str);
            accumulator->Add(">");
          }
        }
      }
      accumulator->Add(" (sfi = %p)",
                       reinterpret_cast<void*>(function->shared().ptr()));
      accumulator->Put('>');
      break;
    }
    case JS_GENERATOR_OBJECT_TYPE: {
      accumulator->Add("<JSGenerator>");
      break;
    }
    case JS_ASYNC_FUNCTION_OBJECT_TYPE: {
      accumulator->Add("<JSAsyncFunctionObject>");
      break;
    }
    case JS_ASYNC_GENERATOR_OBJECT_TYPE: {
      accumulator->Add("<JS AsyncGenerator>");
      break;
    }
    case JS_SHARED_ARRAY_TYPE:
      accumulator->Add("<JSSharedArray>");
      break;
    case JS_SHARED_STRUCT_TYPE:
      accumulator->Add("<JSSharedStruct>");
      break;
    case JS_ATOMICS_MUTEX_TYPE:
      accumulator->Add("<JSAtomicsMutex>");
      break;
    case JS_ATOMICS_CONDITION_TYPE:
      accumulator->Add("<JSAtomicsCondition>");
      break;
    case JS_MESSAGE_OBJECT_TYPE:
      accumulator->Add("<JSMessageObject>");
      break;
    case JS_EXTERNAL_OBJECT_TYPE:
      accumulator->Add("<JSExternalObject>");
      break;

    default: {
      Tagged<Map> map_of_this = map();
      Tagged<Object> constructor = map_of_this->GetConstructor();
      bool printed = false;
      bool is_global_proxy = IsJSGlobalProxy(*this);
      if (IsJSFunction(constructor)) {
        Tagged<SharedFunctionInfo> sfi =
            Cast<JSFunction>(constructor)->shared();
        Tagged<String> constructor_name = sfi->Name();
        if (constructor_name->length() > 0) {
          accumulator->Add(is_global_proxy ? "<GlobalObject " : "<");
          accumulator->Put(constructor_name);
          accumulator->Add(" %smap = %p",
                           map_of_this->is_deprecated() ? "deprecated-" : "",
                           map_of_this);
          printed = true;
        }
      } else if (IsFunctionTemplateInfo(constructor)) {
        accumulator->Add("<RemoteObject>");
        printed = true;
      }
      if (!printed) {
        accumulator->Add("<JS");
        if (is_global_proxy) {
          accumulator->Add("GlobalProxy");
        } else if (IsJSGlobalObject(*this)) {
          accumulator->Add("GlobalObject");
        } else {
          accumulator->Add("Object");
        }
      }
      if (IsJSPrimitiveWrapper(*this)) {
        accumulator->Add(" value = ");
        ShortPrint(Cast<JSPrimitiveWrapper>(*this)->value(), accumulator);
      }
      accumulator->Put('>');
      break;
    }
  }
}

void JSObject::PrintElementsTransition(
    FILE* file, DirectHandle<JSObject> object, ElementsKind from_kind,
    DirectHandle<FixedArrayBase> from_elements, ElementsKind to_kind,
    DirectHandle<FixedArrayBase> to_elements) {
  if (from_kind != to_kind) {
    OFStream os(file);
    os << "elements transition [" << ElementsKindToString(from_kind) << " -> "
       << ElementsKindToString(to_kind) << "] in ";
    JavaScriptFrame::PrintTop(object->GetIsolate(), file, false, true);
    PrintF(file, " for ");
    ShortPrint(*object, file);
    PrintF(file, " from ");
    ShortPrint(*from_elements, file);
    PrintF(file, " to ");
    ShortPrint(*to_elements, file);
    PrintF(file, "\n");
  }
}

void JSObject::PrintInstanceMigration(FILE* file, Tagged<Map> original_map,
                                      Tagged<Map> new_map) {
  if (new_map->is_dictionary_map()) {
    PrintF(file, "[migrating to slow]\n");
    return;
  }
  PrintF(file, "[migrating]");
  Isolate* isolate = GetIsolate();
  Tagged<DescriptorArray> o = original_map->instance_descriptors(isolate);
  Tagged<DescriptorArray> n = new_map->instance_descriptors(isolate);
  for (InternalIndex i : original_map->IterateOwnDescriptors()) {
    Representation o_r = o->GetDetails(i).representation();
    Representation n_r = n->GetDetails(i).representation();
    if (!o_r.Equals(n_r)) {
      Cast<String>(o->GetKey(i))->PrintOn(file);
      PrintF(file, ":%s->%s ", o_r.Mnemonic(), n_r.Mnemonic());
    } else if (o->GetDetails(i).location() == PropertyLocation::kDescriptor &&
               n->GetDetails(i).location() == PropertyLocation::kField) {
      Tagged<Name> name = o->GetKey(i);
      if (IsString(name)) {
        Cast<String>(name)->PrintOn(file);
      } else {
        PrintF(file, "{symbol %p}", reinterpret_cast<void*>(name.ptr()));
      }
      PrintF(file, " ");
    }
  }
  if (original_map->elements_kind() != new_map->elements_kind()) {
    PrintF(file, "elements_kind[%i->%i]", original_map->elements_kind(),
           new_map->elements_kind());
  }
  PrintF(file, "\n");
}

// static
bool JSObject::IsUnmodifiedApiObject(FullObjectSlot o) {
  Tagged<Object> object = *o;
  if (IsSmi(object)) return false;
  Tagged<HeapObject> heap_object = Cast<HeapObject>(object);
  Tagged<Map> map = heap_object->map();
  if (!InstanceTypeChecker::IsJSObject(map)) return false;
  if (!JSObject::IsDroppableApiObject(map)) return false;
  Tagged<Object> maybe_constructor = map->GetConstructor();
  if (!IsJSFunction(maybe_constructor)) return false;
  Tagged<JSObject> js_object = Cast<JSObject>(object);
  if (js_object->elements()->length() != 0) return false;
  // Check that the object is not a key in a WeakMap (over-approximation).
  if (!IsUndefined(js_object->GetIdentityHash())) return false;

  Tagged<JSFunction> constructor = Cast<JSFunction>(maybe_constructor);
  return constructor->initial_map() == map;
}

// static
void JSObject::UpdatePrototypeUserRegistration(DirectHandle<Map> old_map,
                                               DirectHandle<Map> new_map,
                                               Isolate* isolate) {
  DCHECK(old_map->is_prototype_map());
  DCHECK(new_map->is_prototype_map());
  bool was_registered = JSObject::UnregisterPrototypeUser(old_map, isolate);
  new_map->set_prototype_info(old_map->prototype_info(), kReleaseStore);
  old_map->set_prototype_info(Smi::zero(), kReleaseStore);
  if (v8_flags.trace_prototype_users) {
    PrintF("Moving prototype_info %p from map %p to map %p.\n",
           reinterpret_cast<void*>(new_map->prototype_info().ptr()),
           reinterpret_cast<void*>(old_map->ptr()),
           reinterpret_cast<void*>(new_map->ptr()));
  }
  if (was_registered) {
    if (new_map->has_prototype_info()) {
      // The new map isn't registered with its prototype yet; reflect this fact
      // in the PrototypeInfo it just inherited from the old map.
      Cast<PrototypeInfo>(new_map->prototype_info())
          ->set_registry_slot(MemoryChunk::UNREGISTERED);
    }
    JSObject::LazyRegisterPrototypeUser(new_map, isolate);
  }
}

// static
void JSObject::NotifyMapChange(DirectHandle<Map> old_map,
                               DirectHandle<Map> new_map, Isolate* isolate) {
  if (!old_map->is_prototype_map()) return;

  InvalidatePrototypeChains(*old_map);

  // If the map was registered with its prototype before, ensure that it
  // registers with its new prototype now. This preserves the invariant that
  // when a map on a prototype chain is registered with its prototype, then
  // all prototypes further up the chain are also registered with their
  // respective prototypes.
  UpdatePrototypeUserRegistration(old_map, new_map, isolate);
}

namespace {

// To migrate a fast instance to a fast map:
// - First check whether the instance needs to be rewritten. If not, simply
//   change the map.
// - Otherwise, allocate a fixed array large enough to hold all fields, in
//   addition to unused space.
// - Copy all existing properties in, in the following order: backing store
//   properties, unused fields, inobject properties.
// - If all allocation succeeded, commit the state atomically:
//   * Copy inobject properties from the backing store back into the object.
//   * Trim the difference in instance size of the object. This also cleanly
//     frees inobject properties that moved to the backing store.
//   * If there are properties left in the backing store, trim of the space used
//     to temporarily store the inobject properties.
//   * If there are properties left in the backing store, install the backing
//     store.
void MigrateFastToFast(Isolate* isolate, DirectHandle<JSObject> object,
                       DirectHandle<Map> new_map) {
  DirectHandle<Map> old_map(object->map(), isolate);
  // In case of a regular transition.
  if (new_map->GetBackPointer(isolate) == *old_map) {
    // If the map does not add named properties, simply set the map.
    if (old_map->NumberOfOwnDescriptors() ==
        new_map->NumberOfOwnDescriptors()) {
      object->set_map(isolate, *new_map, kReleaseStore);
      return;
    }

    // If the map adds a new kDescriptor property, simply set the map.
    PropertyDetails details = new_map->GetLastDescriptorDetails(isolate);
    if (details.location() == PropertyLocation::kDescriptor) {
      object->set_map(isolate, *new_map, kReleaseStore);
      return;
    }

    // Check if we still have space in the {object}, in which case we
    // can also simply set the map (modulo a special case for mutable
    // double boxes).
    FieldIndex index = FieldIndex::ForDetails(*new_map, details);
    if (index.is_inobject() || index.outobject_array_index() <
                                   object->property_array(isolate)->length()) {
      // Allocate HeapNumbers for double fields.
      if (index.is_double()) {
        auto value = isolate->factory()->NewHeapNumberWithHoleNaN();
        object->FastPropertyAtPut(index, *value);
      }
      object->set_map(isolate, *new_map, kReleaseStore);
      return;
    }

    // This migration is a transition from a map that has run out of property
    // space. Extend the backing store.
    int grow_by = new_map->UnusedPropertyFields() + 1;
    DirectHandle<PropertyArray> old_storage(object->property_array(isolate),
                                            isolate);
    DirectHandle<PropertyArray> new_storage =
        isolate->factory()->CopyPropertyArrayAndGrow(old_storage, grow_by);

    // Properly initialize newly added property.
    DirectHandle<Object> value;
    if (details.representation().IsDouble()) {
      value = isolate->factory()->NewHeapNumberWithHoleNaN();
    } else {
      value = isolate->factory()->uninitialized_value();
    }
    DCHECK_EQ(PropertyLocation::kField, details.location());
    DCHECK_EQ(PropertyKind::kData, details.kind());
    DCHECK(!index.is_inobject());  // Must be a backing store index.
    new_storage->set(index.outobject_array_index(), *value);

    // From here on we cannot fail and we shouldn't GC anymore.
    DisallowGarbageCollection no_gc;

    // Set the new property value and do the map transition.
    object->SetProperties(*new_storage);
    object->set_map(isolate, *new_map, kReleaseStore);
    return;
  }

  int old_number_of_fields;
  int number_of_fields = new_map->NumberOfFields(ConcurrencyMode::kSynchronous);
  int inobject = new_map->GetInObjectProperties();
  int unused = new_map->UnusedPropertyFields();

  // Nothing to do if no functions were converted to fields and no smis were
  // converted to doubles.
  if (!old_map->InstancesNeedRewriting(*new_map, number_of_fields, inobject,
                                       unused, &old_number_of_fields,
                                       ConcurrencyMode::kSynchronous)) {
    object->set_map(isolate, *new_map, kReleaseStore);
    return;
  }

  int total_size = number_of_fields + unused;
  int external = total_size - inobject;
  DirectHandle<PropertyArray> array =
      isolate->factory()->NewPropertyArray(external);

  // We use this array to temporarily store the inobject properties.
  DirectHandle<FixedArray> inobject_props =
      isolate->factory()->NewFixedArray(inobject);

  DirectHandle<DescriptorArray> old_descriptors(
      old_map->instance_descriptors(isolate), isolate);
  DirectHandle<DescriptorArray> new_descriptors(
      new_map->instance_descriptors(isolate), isolate);
  int old_nof = old_map->NumberOfOwnDescriptors();
  int new_nof = new_map->NumberOfOwnDescriptors();

  // This method only supports generalizing instances to at least the same
  // number of properties.
  DCHECK(old_nof <= new_nof);

  for (InternalIndex i : InternalIndex::Range(old_nof)) {
    PropertyDetails details = new_descriptors->GetDetails(i);
    if (details.location() != PropertyLocation::kField) continue;
    DCHECK_EQ(PropertyKind::kData, details.kind());
    PropertyDetails old_details = old_descriptors->GetDetails(i);
    Representation old_representation = old_details.representation();
    Representation representation = details.representation();
    Handle<UnionOf<JSAny, Hole>> value;
    if (old_details.location() == PropertyLocation::kDescriptor) {
      if (old_details.kind() == PropertyKind::kAccessor) {
        // In case of kAccessor -> kData property reconfiguration, the property
        // must already be prepared for data of certain type.
        DCHECK(!details.representation().IsNone());
        if (details.representation().IsDouble()) {
          value = isolate->factory()->NewHeapNumberWithHoleNaN();
        } else {
          value = isolate->factory()->uninitialized_value();
        }
      } else {
        DCHECK_EQ(PropertyKind::kData, old_details.kind());
        value = handle(Cast<JSAny>(old_descriptors->GetStrongValue(isolate, i)),
                       isolate);
        DCHECK(!old_representation.IsDouble() && !representation.IsDouble());
      }
    } else {
      DCHECK_EQ(PropertyLocation::kField, old_details.location());
      FieldIndex index = FieldIndex::ForDetails(*old_map, old_details);
      value = handle(object->RawFastPropertyAt(isolate, index), isolate);
      if (!old_representation.IsDouble() && representation.IsDouble()) {
        DCHECK_IMPLIES(old_representation.IsNone(),
                       IsUninitialized(*value, isolate));
        value = Object::NewStorageFor(isolate, value, representation);
      } else if (old_representation.IsDouble() && !representation.IsDouble()) {
        value = Object::WrapForRead(isolate, Cast<JSAny>(value),
                                    old_representation);
      }
    }
    DCHECK(!(representation.IsDouble() && IsSmi(*value)));
    int target_index = new_descriptors->GetFieldIndex(i);
    if (target_index < inobject) {
      inobject_props->set(target_index, *value);
    } else {
      array->set(target_index - inobject, *value);
    }
  }

  for (InternalIndex i : InternalIndex::Range(old_nof, new_nof)) {
    PropertyDetails details = new_descriptors->GetDetails(i);
    if (details.location() != PropertyLocation::kField) continue;
    DCHECK_EQ(PropertyKind::kData, details.kind());
    DirectHandle<Object> value;
    if (details.representation().IsDouble()) {
      value = isolate->factory()->NewHeapNumberWithHoleNaN();
    } else {
      value = isolate->factory()->uninitialized_value();
    }
    int target_index = new_descriptors->GetFieldIndex(i);
    if (target_index < inobject) {
      inobject_props->set(target_index, *value);
    } else {
      array->set(target_index - inobject, *value);
    }
  }

  // From here on we cannot fail and we shouldn't GC anymore.
  DisallowGarbageCollection no_gc;

  Heap* heap = isolate->heap();

  // Copy (real) inobject properties. If necessary, stop at number_of_fields to
  // avoid overwriting |one_pointer_filler_map|.
  int limit = std::min(inobject, number_of_fields);
  for (int i = 0; i < limit; i++) {
    FieldIndex index = FieldIndex::ForPropertyIndex(*new_map, i);
    Tagged<Object> value = inobject_props->get(i);
    object->FastPropertyAtPut(index, value);
  }

  object->SetProperties(*array);

  // Create filler object past the new instance size.
  int old_instance_size = old_map->instance_size();
  int new_instance_size = new_map->instance_size();
  int instance_size_delta = old_instance_size - new_instance_size;
  DCHECK_GE(instance_size_delta, 0);

  if (instance_size_delta > 0) {
    heap->NotifyObjectSizeChange(*object, old_instance_size, new_instance_size,
                                 ClearRecordedSlots::kYes);
  }

  // We are storing the new map using release store after creating a filler for
  // the left-over space to avoid races with the sweeper thread.
  object->set_map(isolate, *new_map, kReleaseStore);
}

void MigrateFastToSlow(Isolate* isolate, DirectHandle<JSObject> object,
                       DirectHandle<Map> new_map,
                       int expected_additional_properties) {
  // The global object is always normalized.
  DCHECK(!IsJSGlobalObject(*object, isolate));
  // JSGlobalProxy must never be normalized
  DCHECK(!IsJSGlobalProxy(*object, isolate));

  DCHECK_IMPLIES(new_map->is_prototype_map(),
                 Map::IsPrototypeChainInvalidated(*new_map));

  HandleScope scope(isolate);
  DirectHandle<Map> map(object->map(isolate), isolate);

  // Allocate new content.
  int real_size = map->NumberOfOwnDescriptors();
  int property_count = real_size;
  if (expected_additional_properties > 0) {
    property_count += expected_additional_properties;
  } else {
    // Make space for two more properties.
    constexpr int initial_capacity = PropertyDictionary::kInitialCapacity;
    property_count += initial_capacity;
  }

  Handle<NameDictionary> dictionary;
  Handle<SwissNameDictionary> ord_dictionary;
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    ord_dictionary = isolate->factory()->NewSwissNameDictionary(property_count);
  } else {
    dictionary = isolate->factory()->NewNameDictionary(
```