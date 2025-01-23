Response:
My thinking process to analyze the provided C++ code snippet and fulfill the user's request goes like this:

1. **Understand the Goal:** The user wants a functional summary of the given C++ code, specifically focusing on its role within V8, its relationship to JavaScript, and potential errors. They also emphasize the "part 4 of 8" aspect, implying a need for a concise summary of *this specific section*.

2. **Initial Code Scan and Keyword Identification:** I quickly scan the code looking for recognizable patterns and keywords related to object manipulation in JavaScript and V8 internals. I see terms like `Object`, `JSReceiver`, `JSProxy`, `JSArray`, `PropertyDescriptor`, `LookupIterator`, `AddDataProperty`, `SetProperty`, `DefineOwnProperty`, `DeletePropertyOrElement`, `Share`, `AccessorInfo`, `Revoke`, and error-related terms like `TypeError` and `RangeError`. These give me a strong initial sense that the code deals with object property access, manipulation, and the proxy mechanism.

3. **Focus on Core Functionality:** I start grouping the functions based on their apparent purpose.

    * **Property Manipulation (Core):**  Functions like `AddDataProperty`, `TransitionAndWriteDataProperty`, `SetProperty`, `DeletePropertyOrElement`, `DefineOwnProperty` clearly deal with adding, modifying, and removing properties from JavaScript objects. The `LookupIterator` suggests a process for finding properties.

    * **Proxies:** The presence of `JSProxy::IsArray`, `JSProxy::HasProperty`, `JSProxy::SetProperty`, `JSProxy::DeletePropertyOrElement`, `JSProxy::DefineOwnProperty`, `JSProxy::New`, and `JSProxy::Revoke` strongly indicates the code handles the implementation of the JavaScript Proxy object. The numerous checks for revoked proxies and the interaction with the "handler" object confirm this.

    * **Arrays:**  `JSArray::DefineOwnProperty` and `JSArray::ArraySetLength` are specifically for managing properties and the `length` property of JavaScript arrays. The checks involving array indices and the `length` property are key here.

    * **Sharing:**  `Object::ShareSlow` suggests a mechanism for sharing objects, likely related to optimizations or concurrent access in V8.

    * **Accessors:** `AccessorInfo::AppendUnique` appears to deal with managing accessor properties (getters and setters).

4. **Identify JavaScript Relevance:** I connect the C++ concepts to their JavaScript counterparts.

    * **`Object::AddDataProperty` et al.:** These directly implement the internal mechanisms behind JavaScript's property assignment (`object.property = value`), and `Object.defineProperty`.
    * **`JSProxy` functions:**  These are the core of the JavaScript `Proxy` object, handling traps like `get`, `set`, `has`, `deleteProperty`, and `defineProperty`.
    * **`JSArray::DefineOwnProperty` and `JSArray::ArraySetLength`:**  These are involved in the behavior of arrays, especially when setting the `length` property or adding elements.

5. **Infer Code Logic and Potential Errors:** I examine the conditional statements and error handling.

    * **Proxy Revocation:** The checks for `IsRevoked()` indicate a common error: trying to interact with a revoked Proxy.
    * **Non-Extensible Objects:** The code checks for non-extensible objects and throws `TypeError` when attempting to add properties.
    * **Read-Only Properties:** Errors are thrown when trying to modify read-only properties, especially the `length` of arrays.
    * **Proxy Invariants:** The code enforces invariants for Proxies, throwing errors if the trap results violate these invariants (e.g., `has` returning `false` for a non-configurable property).
    * **Array `length` Manipulation:** The checks and error handling around setting the `length` property of arrays highlight the specific rules and potential errors in this area (e.g., invalid length values, shrinking arrays with non-configurable properties).

6. **Construct JavaScript Examples:** For each key functionality, I create simple JavaScript code snippets that would trigger the corresponding C++ code paths. This helps illustrate the connection between the C++ implementation and user-facing JavaScript behavior.

7. **Develop Hypothetical Inputs and Outputs:** For more complex logic (like `AddDataProperty` or Proxy traps), I create simple scenarios with specific inputs and the expected outcome, demonstrating the function's behavior.

8. **Identify Common Programming Errors:** Based on the error checks in the C++ code, I list common JavaScript programming mistakes that would lead to these errors (e.g., setting properties on non-extensible objects, manipulating Proxy objects after revocation).

9. **Summarize the Functionality (Focusing on Part 4):** Finally, I synthesize the information into a concise summary, emphasizing the core functionalities covered in this particular code snippet. Since it's part 4 of 8, I avoid making overly broad generalizations about the *entire* `objects.cc` file and stick to the themes evident in the provided excerpt. I highlight object property manipulation, the Proxy mechanism, and array-specific logic.

10. **Review and Refine:** I review the generated answer to ensure accuracy, clarity, and completeness, making sure it directly addresses all aspects of the user's request. I check for consistency and logical flow.
好的，让我们来分析一下 `v8/src/objects/objects.cc` 的这一部分代码，并归纳它的功能。

**功能概览**

这段代码主要涉及以下几个方面的功能：

1. **对象属性的添加和修改:**  包括了添加数据属性、根据属性描述符定义属性，以及在属性值发生变化时可能触发的类型转换和共享操作。
2. **JSProxy 对象的处理:**  实现了 `JSProxy` 对象的多种操作，例如属性的 `has`、`set`、`deleteProperty`、`defineProperty` 以及 `revoke` 等操作，并处理了 Proxy 的各种陷阱（traps）和不变量（invariants）。
3. **JSArray 对象的特殊处理:**  针对 `JSArray` 对象，实现了 `DefineOwnProperty` 和 `ArraySetLength` 等特殊的方法，用于管理数组的元素和 `length` 属性。
4. **对象共享:**  提供了 `Object::ShareSlow` 方法，用于将某些类型的对象（例如字符串和数字）转换为共享版本，这在多线程环境中可能用到。
5. **访问器属性的管理:**  `AccessorInfo::AppendUnique` 用于管理访问器属性（getter/setter）。

**如果 v8/src/objects/objects.cc 以 .tq 结尾**

如果 `v8/src/objects/objects.cc` 以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码**。Torque 是一种 V8 自研的类型化的中间表示和代码生成器，用于编写性能关键的 V8 内部代码。Torque 代码会被编译成 C++ 代码。

**与 JavaScript 功能的关系及示例**

这段 C++ 代码直接实现了 JavaScript 中关于对象和数组属性操作的核心语义以及 Proxy 对象的行为。

**1. 对象属性的添加和修改:**

```javascript
const obj = {};
obj.name = 'Alice'; // 对应 Object::SetProperty 或 Object::AddDataProperty 等

Object.defineProperty(obj, 'age', {
  value: 30,
  writable: false,
  enumerable: true,
  configurable: false
}); // 对应 Object::DefineOwnProperty
```

**2. JSProxy 对象的处理:**

```javascript
const target = { name: 'Bob' };
const handler = {
  get(target, prop) {
    console.log(`Getting ${prop}`);
    return target[prop];
  },
  set(target, prop, value) {
    console.log(`Setting ${prop} to ${value}`);
    target[prop] = value;
    return true;
  },
  has(target, prop) {
    console.log(`Checking if ${prop} exists`);
    return prop in target;
  },
  deleteProperty(target, prop) {
    console.log(`Deleting ${prop}`);
    delete target[prop];
    return true;
  },
  defineProperty(target, prop, descriptor) {
    console.log(`Defining property ${prop}`);
    Object.defineProperty(target, prop, descriptor);
    return true;
  }
};

const proxy = new Proxy(target, handler);

console.log(proxy.name); // 触发 handler.get
proxy.age = 40;         // 触发 handler.set
'name' in proxy;        // 触发 handler.has
delete proxy.name;       // 触发 handler.deleteProperty
Object.defineProperty(proxy, 'city', { value: 'New York' }); // 触发 handler.defineProperty

// 撤销 Proxy
Proxy.revocable(target, handler).revoke(); // 对应 JSProxy::Revoke
```

**3. JSArray 对象的特殊处理:**

```javascript
const arr = [1, 2, 3];
arr[3] = 4; // 对应 JSArray 的元素添加

Object.defineProperty(arr, 'length', { value: 2 }); // 对应 JSArray::DefineOwnProperty 和 ArraySetLength，缩短数组
```

**代码逻辑推理：假设输入与输出**

**场景：`Object::AddDataProperty`**

**假设输入：**

* `it`: 一个 `LookupIterator` 对象，当前指向一个普通的 JavaScript 对象 `obj`，尝试添加一个名为 `count` 的属性。
* `value`: 一个 `DirectHandle<Object>`，指向数字 `10`。
* `attributes`: 属性特性，例如 `NONE`。
* `should_throw`: `Just(kThrowOnError)`，如果添加失败则抛出错误。
* `store_origin`:  `StoreOrigin::kMaybeKeyed`.
* `semantics`: `EnforceDefineSemantics::kSet`.

**预期输出：**

* 函数返回 `Just(true)`，表示属性添加成功。
* 对象 `obj` 将拥有一个新的数据属性 `count`，其值为 `10`。

**场景：`JSProxy::SetProperty`**

**假设输入：**

* `proxy`: 一个 `DirectHandle<JSProxy>` 指向一个 Proxy 对象。
* `name`: 一个 `Handle<Name>` 指向字符串 `"data"`.
* `value`: 一个 `Handle<Object>` 指向字符串 `"value"`.
* `receiver`: 一个 `Handle<JSAny>` 指向 Proxy 对象自身。
* `should_throw`: `Nothing<ShouldThrow>`.

**假设 Proxy 的 handler 定义了 `set` 陷阱如下：**

```javascript
const handler = {
  set(target, prop, value, receiver) {
    console.log(`Proxy set: ${prop} to ${value}`);
    target[prop] = value.toUpperCase(); // 修改赋值的值
    return true;
  }
};
```

**预期输出：**

* 函数返回 `Just(true)`.
* 目标对象（`target`）的 `"data"` 属性将被设置为 `"VALUE"` (经过 `handler.set` 的处理)。
* 控制台会打印 `"Proxy set: data to value"`.

**用户常见的编程错误及示例**

1. **尝试操作已撤销的 Proxy:**

```javascript
const { proxy, revoke } = Proxy.revocable({}, {});
revoke();
proxy.foo = 'bar'; // TypeError: Cannot perform 'set' on a proxy that has been revoked
```

   这段 C++ 代码中，`JSProxy::SetProperty` 等函数会首先检查 `proxy->IsRevoked()`，如果已撤销则抛出 `TypeError`。

2. **在不可扩展对象上添加属性:**

```javascript
const obj = Object.preventExtensions({});
obj.newProp = 'test'; // TypeError: Cannot add property newProp, object is not extensible
```

   `Object::AddDataProperty` 中会检查 `it->ExtendingNonExtensible(receiver)`，如果对象不可扩展则根据 `semantics` 抛出 `TypeError`。

3. **尝试修改不可写或不可配置的属性:**

```javascript
const obj = {};
Object.defineProperty(obj, 'readOnly', { value: 10, writable: false });
obj.readOnly = 20; // 严格模式下 TypeError，非严格模式下静默失败

Object.defineProperty(obj, 'nonConfigurable', { value: 30, configurable: false });
Object.defineProperty(obj, 'nonConfigurable', { writable: true }); // TypeError: Cannot redefine property: nonConfigurable
```

   `Object::SetProperty` 和 `Object::DefineOwnProperty` 会检查属性的 `writable` 和 `configurable` 特性，并在不符合条件时抛出 `TypeError`。

4. **不遵守 Proxy 的不变量:**

```javascript
const target = { configurableProp: 1 };
const handler = {
  getOwnPropertyDescriptor(target, prop) {
    if (prop === 'configurableProp') {
      return { value: 1, configurable: false };
    }
    return Object.getOwnPropertyDescriptor(target, prop);
  },
  defineProperty(target, prop, descriptor) {
    if (prop === 'configurableProp' && descriptor.configurable === true) {
      // 违反不变量：试图将不可配置的属性设为可配置
      return false; // 或者抛出错误
    }
    Object.defineProperty(target, prop, descriptor);
    return true;
  }
};
const proxy = new Proxy(target, handler);
Object.defineProperty(proxy, 'configurableProp', { configurable: true }); // TypeError: 'defineProperty' on proxy: trap returned falsish
```

   `JSProxy::DefineOwnProperty` 中会进行一系列检查，确保 Proxy 的陷阱返回值不会违反对象固有的属性特性。

**归纳功能（针对提供的代码片段）**

这段 `v8/src/objects/objects.cc` 的代码片段主要负责 **实现 JavaScript 中对象属性的添加、修改、删除等基本操作，并深度集成了 Proxy 对象的行为管理以及数组对象的特殊属性处理**。它确保了 JavaScript 引擎能够正确地执行与对象属性相关的各种操作，并遵循语言规范中定义的行为和约束，包括处理各种可能的错误场景和类型转换。 特别是对于 Proxy，它实现了拦截和控制对象操作的关键机制。 对于数组，它关注于 `length` 属性的特殊性以及元素操作与 `length` 的联动。

请记住，这只是 `objects.cc` 的一部分，整个文件会包含更多关于 V8 对象系统的实现细节。

### 提示词
```
这是目录为v8/src/objects/objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
} else if (!IsNumber(*value) && !IsUndefined(*value, isolate)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, to_assign,
                                       Object::ToNumber(isolate, value),
                                       Nothing<bool>());
      if (V8_UNLIKELY(receiver_ta->IsDetachedOrOutOfBounds() ||
                      it->index() >= receiver_ta->GetLength())) {
        return Just(true);
      }
    }
  }

  DCHECK(!IsWasmObject(*receiver, isolate));
  if (V8_UNLIKELY(IsJSSharedStruct(*receiver, isolate) ||
                  IsJSSharedArray(*receiver, isolate))) {
    // Shared structs can only point to primitives or shared values.
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, to_assign, Object::Share(isolate, to_assign, kThrowOnError),
        Nothing<bool>());
    it->WriteDataValue(to_assign, false);
  } else {
    // Possibly migrate to the most up-to-date map that will be able to store
    // |value| under it->name().
    it->PrepareForDataProperty(to_assign);

    // Write the property value.
    it->WriteDataValue(to_assign, false);
  }

#if VERIFY_HEAP
  if (v8_flags.verify_heap) {
    receiver->HeapObjectVerify(isolate);
  }
#endif
  return Just(true);
}

Maybe<bool> Object::AddDataProperty(LookupIterator* it,
                                    DirectHandle<Object> value,
                                    PropertyAttributes attributes,
                                    Maybe<ShouldThrow> should_throw,
                                    StoreOrigin store_origin,
                                    EnforceDefineSemantics semantics) {
  if (!IsJSReceiver(*it->GetReceiver())) {
    return CannotCreateProperty(it->isolate(), it->GetReceiver(), it->GetName(),
                                value, should_throw);
  }

  // Private symbols should be installed on JSProxy using
  // JSProxy::SetPrivateSymbol.
  if (IsJSProxy(*it->GetReceiver()) && it->GetName()->IsPrivate() &&
      !it->GetName()->IsPrivateName()) {
    RETURN_FAILURE(it->isolate(), GetShouldThrow(it->isolate(), should_throw),
                   NewTypeError(MessageTemplate::kProxyPrivate));
  }

  DCHECK_NE(LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND, it->state());

  Handle<JSReceiver> receiver = it->GetStoreTarget<JSReceiver>();
  DCHECK_IMPLIES(IsJSProxy(*receiver), it->GetName()->IsPrivateName());
  DCHECK_IMPLIES(IsJSProxy(*receiver),
                 it->state() == LookupIterator::NOT_FOUND);

  // If the receiver is a JSGlobalProxy, store on the prototype (JSGlobalObject)
  // instead. If the prototype is Null, the proxy is detached.
  if (IsJSGlobalProxy(*receiver)) return Just(true);

  Isolate* isolate = it->isolate();

  if (it->ExtendingNonExtensible(receiver)) {
    bool is_shared_object = IsAlwaysSharedSpaceJSObject(*receiver);
    RETURN_FAILURE(
        isolate, GetShouldThrow(it->isolate(), should_throw),
        NewTypeError(
            semantics == EnforceDefineSemantics::kDefine
                ? (is_shared_object
                       ? MessageTemplate::kDefineDisallowedFixedLayout
                       : MessageTemplate::kDefineDisallowed)
                : (is_shared_object ? MessageTemplate::kObjectFixedLayout
                                    : MessageTemplate::kObjectNotExtensible),
            it->GetName()));
  }

  if (it->IsElement(*receiver)) {
    if (IsJSArray(*receiver)) {
      Handle<JSArray> array = Cast<JSArray>(receiver);
      if (JSArray::WouldChangeReadOnlyLength(array, it->array_index())) {
        RETURN_FAILURE(isolate, GetShouldThrow(it->isolate(), should_throw),
                       NewTypeError(MessageTemplate::kStrictReadOnlyProperty,
                                    isolate->factory()->length_string(),
                                    Object::TypeOf(isolate, array), array));
      }
    }

    Handle<JSObject> receiver_obj = Cast<JSObject>(receiver);
    MAYBE_RETURN(JSObject::AddDataElement(receiver_obj, it->array_index(),
                                          value, attributes),
                 Nothing<bool>());
    JSObject::ValidateElements(*receiver_obj);
    return Just(true);
  }

  return Object::TransitionAndWriteDataProperty(it, value, attributes,
                                                should_throw, store_origin);
}

// static
Maybe<bool> Object::TransitionAndWriteDataProperty(
    LookupIterator* it, DirectHandle<Object> value,
    PropertyAttributes attributes, Maybe<ShouldThrow> should_throw,
    StoreOrigin store_origin) {
  Handle<JSReceiver> receiver = it->GetStoreTarget<JSReceiver>();
  it->UpdateProtector();
  // Migrate to the most up-to-date map that will be able to store |value|
  // under it->name() with |attributes|.
  it->PrepareTransitionToDataProperty(receiver, value, attributes,
                                      store_origin);
  DCHECK_EQ(LookupIterator::TRANSITION, it->state());
  it->ApplyTransitionToDataProperty(receiver);

  // Write the property value.
  it->WriteDataValue(value, true);

#if VERIFY_HEAP
  if (v8_flags.verify_heap) {
    receiver->HeapObjectVerify(it->isolate());
  }
#endif

  return Just(true);
}
// static
MaybeHandle<Object> Object::ShareSlow(Isolate* isolate,
                                      Handle<HeapObject> value,
                                      ShouldThrow throw_if_cannot_be_shared) {
  // Use Object::Share() if value might already be shared.
  DCHECK(!IsShared(*value));

  SharedObjectSafePublishGuard publish_guard;

  if (IsString(*value)) {
    return String::Share(isolate, Cast<String>(value));
  }

  if (IsHeapNumber(*value)) {
    uint64_t bits = Cast<HeapNumber>(*value)->value_as_bits();
    return isolate->factory()
        ->NewHeapNumberFromBits<AllocationType::kSharedOld>(bits);
  }

  if (throw_if_cannot_be_shared == kThrowOnError) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kCannotBeShared, value));
  }
  return MaybeHandle<Object>();
}

namespace {

template <class T>
int AppendUniqueCallbacks(Isolate* isolate, DirectHandle<ArrayList> callbacks,
                          Handle<typename T::Array> array,
                          int valid_descriptors) {
  int nof_callbacks = callbacks->length();

  // Fill in new callback descriptors.  Process the callbacks from
  // back to front so that the last callback with a given name takes
  // precedence over previously added callbacks with that name.
  for (int i = nof_callbacks - 1; i >= 0; i--) {
    Handle<AccessorInfo> entry(Cast<AccessorInfo>(callbacks->get(i)), isolate);
    Handle<Name> key(Cast<Name>(entry->name()), isolate);
    DCHECK(IsUniqueName(*key));
    // Check if a descriptor with this name already exists before writing.
    if (!T::Contains(key, entry, valid_descriptors, array)) {
      T::Insert(key, entry, valid_descriptors, array);
      valid_descriptors++;
    }
  }

  return valid_descriptors;
}

struct FixedArrayAppender {
  using Array = FixedArray;
  static bool Contains(DirectHandle<Name> key, DirectHandle<AccessorInfo> entry,
                       int valid_descriptors, DirectHandle<FixedArray> array) {
    for (int i = 0; i < valid_descriptors; i++) {
      if (*key == Cast<AccessorInfo>(array->get(i))->name()) return true;
    }
    return false;
  }
  static void Insert(DirectHandle<Name> key, DirectHandle<AccessorInfo> entry,
                     int valid_descriptors, DirectHandle<FixedArray> array) {
    DisallowGarbageCollection no_gc;
    array->set(valid_descriptors, *entry);
  }
};

}  // namespace

int AccessorInfo::AppendUnique(Isolate* isolate, Handle<Object> descriptors,
                               Handle<FixedArray> array,
                               int valid_descriptors) {
  auto callbacks = Cast<ArrayList>(descriptors);
  DCHECK_GE(array->length(), callbacks->length() + valid_descriptors);
  return AppendUniqueCallbacks<FixedArrayAppender>(isolate, callbacks, array,
                                                   valid_descriptors);
}

void JSProxy::Revoke(DirectHandle<JSProxy> proxy) {
  Isolate* isolate = proxy->GetIsolate();
  // ES#sec-proxy-revocation-functions
  if (!proxy->IsRevoked()) {
    // 5. Set p.[[ProxyTarget]] to null.
    proxy->set_target(ReadOnlyRoots(isolate).null_value());
    // 6. Set p.[[ProxyHandler]] to null.
    proxy->set_handler(ReadOnlyRoots(isolate).null_value());
  }
  DCHECK(proxy->IsRevoked());
}

// static
Maybe<bool> JSProxy::IsArray(Handle<JSProxy> proxy) {
  Isolate* isolate = proxy->GetIsolate();
  Handle<JSReceiver> object = Cast<JSReceiver>(proxy);
  for (int i = 0; i < JSProxy::kMaxIterationLimit; i++) {
    proxy = Cast<JSProxy>(object);
    if (proxy->IsRevoked()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyRevoked,
          isolate->factory()->NewStringFromAsciiChecked("IsArray")));
      return Nothing<bool>();
    }
    object = handle(Cast<JSReceiver>(proxy->target()), isolate);
    if (IsJSArray(*object)) return Just(true);
    if (!IsJSProxy(*object)) return Just(false);
  }

  // Too deep recursion, throw a RangeError.
  isolate->StackOverflow();
  return Nothing<bool>();
}

Maybe<bool> JSProxy::HasProperty(Isolate* isolate, DirectHandle<JSProxy> proxy,
                                 Handle<Name> name) {
  DCHECK(!name->IsPrivate());
  STACK_CHECK(isolate, Nothing<bool>());
  // 1. (Assert)
  // 2. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  Handle<Object> handler(proxy->handler(), isolate);
  // 3. If handler is null, throw a TypeError exception.
  // 4. Assert: Type(handler) is Object.
  if (proxy->IsRevoked()) {
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kProxyRevoked, isolate->factory()->has_string()));
    return Nothing<bool>();
  }
  // 5. Let target be the value of the [[ProxyTarget]] internal slot of O.
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  // 6. Let trap be ? GetMethod(handler, "has").
  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap,
      Object::GetMethod(isolate, Cast<JSReceiver>(handler),
                        isolate->factory()->has_string()),
      Nothing<bool>());
  // 7. If trap is undefined, then
  if (IsUndefined(*trap, isolate)) {
    // 7a. Return target.[[HasProperty]](P).
    return JSReceiver::HasProperty(isolate, target, name);
  }
  // 8. Let booleanTrapResult be ToBoolean(? Call(trap, handler, «target, P»)).
  Handle<Object> trap_result_obj;
  Handle<Object> args[] = {target, name};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap_result_obj,
      Execution::Call(isolate, trap, handler, arraysize(args), args),
      Nothing<bool>());
  bool boolean_trap_result = Object::BooleanValue(*trap_result_obj, isolate);
  // 9. If booleanTrapResult is false, then:
  if (!boolean_trap_result) {
    MAYBE_RETURN(JSProxy::CheckHasTrap(isolate, name, target), Nothing<bool>());
  }
  // 10. Return booleanTrapResult.
  return Just(boolean_trap_result);
}

Maybe<bool> JSProxy::CheckHasTrap(Isolate* isolate, Handle<Name> name,
                                  Handle<JSReceiver> target) {
  // 9a. Let targetDesc be ? target.[[GetOwnProperty]](P).
  PropertyDescriptor target_desc;
  Maybe<bool> target_found =
      JSReceiver::GetOwnPropertyDescriptor(isolate, target, name, &target_desc);
  MAYBE_RETURN(target_found, Nothing<bool>());
  // 9b. If targetDesc is not undefined, then:
  if (target_found.FromJust()) {
    // 9b i. If targetDesc.[[Configurable]] is false, throw a TypeError
    //       exception.
    if (!target_desc.configurable()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyHasNonConfigurable, name));
      return Nothing<bool>();
    }
    // 9b ii. Let extensibleTarget be ? IsExtensible(target).
    Maybe<bool> extensible_target = JSReceiver::IsExtensible(isolate, target);
    MAYBE_RETURN(extensible_target, Nothing<bool>());
    // 9b iii. If extensibleTarget is false, throw a TypeError exception.
    if (!extensible_target.FromJust()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyHasNonExtensible, name));
      return Nothing<bool>();
    }
  }
  return Just(true);
}

Maybe<bool> JSProxy::SetProperty(DirectHandle<JSProxy> proxy, Handle<Name> name,
                                 Handle<Object> value, Handle<JSAny> receiver,
                                 Maybe<ShouldThrow> should_throw) {
  DCHECK(!name->IsPrivate());
  Isolate* isolate = proxy->GetIsolate();
  STACK_CHECK(isolate, Nothing<bool>());
  Factory* factory = isolate->factory();
  Handle<String> trap_name = factory->set_string();

  if (proxy->IsRevoked()) {
    isolate->Throw(
        *factory->NewTypeError(MessageTemplate::kProxyRevoked, trap_name));
    return Nothing<bool>();
  }
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  Handle<JSReceiver> handler(Cast<JSReceiver>(proxy->handler()), isolate);

  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap, Object::GetMethod(isolate, handler, trap_name),
      Nothing<bool>());
  if (IsUndefined(*trap, isolate)) {
    PropertyKey key(isolate, name);
    LookupIterator it(isolate, receiver, key, target);

    return Object::SetSuperProperty(&it, value, StoreOrigin::kMaybeKeyed,
                                    should_throw);
  }

  Handle<Object> trap_result;
  Handle<Object> args[] = {target, name, value, receiver};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap_result,
      Execution::Call(isolate, trap, handler, arraysize(args), args),
      Nothing<bool>());
  if (!Object::BooleanValue(*trap_result, isolate)) {
    RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                   NewTypeError(MessageTemplate::kProxyTrapReturnedFalsishFor,
                                trap_name, name));
  }

  MaybeHandle<Object> result =
      JSProxy::CheckGetSetTrapResult(isolate, name, target, value, kSet);

  if (result.is_null()) {
    return Nothing<bool>();
  }
  return Just(true);
}

Maybe<bool> JSProxy::DeletePropertyOrElement(DirectHandle<JSProxy> proxy,
                                             Handle<Name> name,
                                             LanguageMode language_mode) {
  DCHECK(!name->IsPrivate());
  ShouldThrow should_throw =
      is_sloppy(language_mode) ? kDontThrow : kThrowOnError;
  Isolate* isolate = proxy->GetIsolate();
  STACK_CHECK(isolate, Nothing<bool>());
  Factory* factory = isolate->factory();
  Handle<String> trap_name = factory->deleteProperty_string();

  if (proxy->IsRevoked()) {
    isolate->Throw(
        *factory->NewTypeError(MessageTemplate::kProxyRevoked, trap_name));
    return Nothing<bool>();
  }
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  Handle<JSReceiver> handler(Cast<JSReceiver>(proxy->handler()), isolate);

  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap, Object::GetMethod(isolate, handler, trap_name),
      Nothing<bool>());
  if (IsUndefined(*trap, isolate)) {
    return JSReceiver::DeletePropertyOrElement(isolate, target, name,
                                               language_mode);
  }

  Handle<Object> trap_result;
  Handle<Object> args[] = {target, name};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap_result,
      Execution::Call(isolate, trap, handler, arraysize(args), args),
      Nothing<bool>());
  if (!Object::BooleanValue(*trap_result, isolate)) {
    RETURN_FAILURE(isolate, should_throw,
                   NewTypeError(MessageTemplate::kProxyTrapReturnedFalsishFor,
                                trap_name, name));
  }

  // Enforce the invariant.
  return JSProxy::CheckDeleteTrap(isolate, name, target);
}

Maybe<bool> JSProxy::CheckDeleteTrap(Isolate* isolate, Handle<Name> name,
                                     Handle<JSReceiver> target) {
  // 10. Let targetDesc be ? target.[[GetOwnProperty]](P).
  PropertyDescriptor target_desc;
  Maybe<bool> target_found =
      JSReceiver::GetOwnPropertyDescriptor(isolate, target, name, &target_desc);
  MAYBE_RETURN(target_found, Nothing<bool>());
  // 11. If targetDesc is undefined, return true.
  if (target_found.FromJust()) {
    // 12. If targetDesc.[[Configurable]] is false, throw a TypeError exception.
    if (!target_desc.configurable()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyDeletePropertyNonConfigurable, name));
      return Nothing<bool>();
    }
    // 13. Let extensibleTarget be ? IsExtensible(target).
    Maybe<bool> extensible_target = JSReceiver::IsExtensible(isolate, target);
    MAYBE_RETURN(extensible_target, Nothing<bool>());
    // 14. If extensibleTarget is false, throw a TypeError exception.
    if (!extensible_target.FromJust()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyDeletePropertyNonExtensible, name));
      return Nothing<bool>();
    }
  }
  return Just(true);
}

// static
MaybeHandle<JSProxy> JSProxy::New(Isolate* isolate, Handle<Object> target,
                                  Handle<Object> handler) {
  if (!IsJSReceiver(*target)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kProxyNonObject));
  }
  if (!IsJSReceiver(*handler)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kProxyNonObject));
  }
  return isolate->factory()->NewJSProxy(Cast<JSReceiver>(target),
                                        Cast<JSReceiver>(handler));
}

Maybe<PropertyAttributes> JSProxy::GetPropertyAttributes(LookupIterator* it) {
  PropertyDescriptor desc;
  Maybe<bool> found = JSProxy::GetOwnPropertyDescriptor(
      it->isolate(), it->GetHolder<JSProxy>(), it->GetName(), &desc);
  MAYBE_RETURN(found, Nothing<PropertyAttributes>());
  if (!found.FromJust()) return Just(ABSENT);
  return Just(desc.ToAttributes());
}

// TODO(jkummerow): Consider unification with FastAsArrayLength() in
// accessors.cc.
bool PropertyKeyToArrayLength(DirectHandle<Object> value, uint32_t* length) {
  DCHECK(IsNumber(*value) || IsName(*value));
  if (Object::ToArrayLength(*value, length)) return true;
  if (IsString(*value)) return Cast<String>(*value)->AsArrayIndex(length);
  return false;
}

bool PropertyKeyToArrayIndex(DirectHandle<Object> index_obj, uint32_t* output) {
  return PropertyKeyToArrayLength(index_obj, output) && *output != kMaxUInt32;
}

// ES6 9.4.2.1
// static
Maybe<bool> JSArray::DefineOwnProperty(Isolate* isolate, Handle<JSArray> o,
                                       Handle<Object> name,
                                       PropertyDescriptor* desc,
                                       Maybe<ShouldThrow> should_throw) {
  if (IsName(*name)) {
    name = isolate->factory()->InternalizeName(Cast<Name>(name));
  }

  // 1. Assert: IsPropertyKey(P) is true. ("P" is |name|.)
  // 2. If P is "length", then:
  if (*name == ReadOnlyRoots(isolate).length_string()) {
    // 2a. Return ArraySetLength(A, Desc).
    return ArraySetLength(isolate, o, desc, should_throw);
  }
  // 3. Else if P is an array index, then:
  uint32_t index = 0;
  if (PropertyKeyToArrayIndex(name, &index)) {
    // 3a. Let oldLenDesc be OrdinaryGetOwnProperty(A, "length").
    PropertyDescriptor old_len_desc;
    Maybe<bool> success = GetOwnPropertyDescriptor(
        isolate, o, isolate->factory()->length_string(), &old_len_desc);
    // 3b. (Assert)
    DCHECK(success.FromJust());
    USE(success);
    // 3c. Let oldLen be oldLenDesc.[[Value]].
    uint32_t old_len = 0;
    CHECK(Object::ToArrayLength(*old_len_desc.value(), &old_len));
    // 3d. Let index be ToUint32(P).
    // (Already done above.)
    // 3e. (Assert)
    // 3f. If index >= oldLen and oldLenDesc.[[Writable]] is false,
    //     return false.
    if (index >= old_len && old_len_desc.has_writable() &&
        !old_len_desc.writable()) {
      RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                     NewTypeError(MessageTemplate::kDefineDisallowed, name));
    }
    // 3g. Let succeeded be OrdinaryDefineOwnProperty(A, P, Desc).
    Maybe<bool> succeeded =
        OrdinaryDefineOwnProperty(isolate, o, name, desc, should_throw);
    // 3h. Assert: succeeded is not an abrupt completion.
    //     In our case, if should_throw == kThrowOnError, it can be!
    // 3i. If succeeded is false, return false.
    if (succeeded.IsNothing() || !succeeded.FromJust()) return succeeded;
    // 3j. If index >= oldLen, then:
    if (index >= old_len) {
      // 3j i. Set oldLenDesc.[[Value]] to index + 1.
      old_len_desc.set_value(isolate->factory()->NewNumberFromUint(index + 1));
      // 3j ii. Let succeeded be
      //        OrdinaryDefineOwnProperty(A, "length", oldLenDesc).
      succeeded = OrdinaryDefineOwnProperty(isolate, o,
                                            isolate->factory()->length_string(),
                                            &old_len_desc, should_throw);
      // 3j iii. Assert: succeeded is true.
      DCHECK(succeeded.FromJust());
      USE(succeeded);
    }
    // 3k. Return true.
    return Just(true);
  }

  // 4. Return OrdinaryDefineOwnProperty(A, P, Desc).
  return OrdinaryDefineOwnProperty(isolate, o, name, desc, should_throw);
}

// Part of ES6 9.4.2.4 ArraySetLength.
// static
bool JSArray::AnythingToArrayLength(Isolate* isolate,
                                    Handle<Object> length_object,
                                    uint32_t* output) {
  // Fast path: check numbers and strings that can be converted directly
  // and unobservably.
  if (Object::ToArrayLength(*length_object, output)) return true;
  if (IsString(*length_object) &&
      Cast<String>(length_object)->AsArrayIndex(output)) {
    return true;
  }
  // Slow path: follow steps in ES6 9.4.2.4 "ArraySetLength".
  // 3. Let newLen be ToUint32(Desc.[[Value]]).
  Handle<Number> uint32_v;
  if (!Object::ToUint32(isolate, length_object).ToHandle(&uint32_v)) {
    // 4. ReturnIfAbrupt(newLen).
    return false;
  }
  // 5. Let numberLen be ToNumber(Desc.[[Value]]).
  Handle<Number> number_v;
  if (!Object::ToNumber(isolate, length_object).ToHandle(&number_v)) {
    // 6. ReturnIfAbrupt(newLen).
    return false;
  }
  // 7. If newLen != numberLen, throw a RangeError exception.
  if (Object::NumberValue(*uint32_v) != Object::NumberValue(*number_v)) {
    DirectHandle<Object> exception =
        isolate->factory()->NewRangeError(MessageTemplate::kInvalidArrayLength);
    isolate->Throw(*exception);
    return false;
  }
  CHECK(Object::ToArrayLength(*uint32_v, output));
  return true;
}

// ES6 9.4.2.4
// static
Maybe<bool> JSArray::ArraySetLength(Isolate* isolate, Handle<JSArray> a,
                                    PropertyDescriptor* desc,
                                    Maybe<ShouldThrow> should_throw) {
  // 1. If the [[Value]] field of Desc is absent, then
  if (!desc->has_value()) {
    // 1a. Return OrdinaryDefineOwnProperty(A, "length", Desc).
    return OrdinaryDefineOwnProperty(
        isolate, a, isolate->factory()->length_string(), desc, should_throw);
  }
  // 2. Let newLenDesc be a copy of Desc.
  // (Actual copying is not necessary.)
  PropertyDescriptor* new_len_desc = desc;
  // 3. - 7. Convert Desc.[[Value]] to newLen.
  uint32_t new_len = 0;
  if (!AnythingToArrayLength(isolate, desc->value(), &new_len)) {
    DCHECK(isolate->has_exception());
    return Nothing<bool>();
  }
  // 8. Set newLenDesc.[[Value]] to newLen.
  // (Done below, if needed.)
  // 9. Let oldLenDesc be OrdinaryGetOwnProperty(A, "length").
  PropertyDescriptor old_len_desc;
  Maybe<bool> success = GetOwnPropertyDescriptor(
      isolate, a, isolate->factory()->length_string(), &old_len_desc);
  // 10. (Assert)
  DCHECK(success.FromJust());
  USE(success);
  // 11. Let oldLen be oldLenDesc.[[Value]].
  uint32_t old_len = 0;
  CHECK(Object::ToArrayLength(*old_len_desc.value(), &old_len));
  // 12. If newLen >= oldLen, then
  if (new_len >= old_len) {
    // 8. Set newLenDesc.[[Value]] to newLen.
    // 12a. Return OrdinaryDefineOwnProperty(A, "length", newLenDesc).
    new_len_desc->set_value(isolate->factory()->NewNumberFromUint(new_len));
    return OrdinaryDefineOwnProperty(isolate, a,
                                     isolate->factory()->length_string(),
                                     new_len_desc, should_throw);
  }
  // 13. If oldLenDesc.[[Writable]] is false, return false.
  if (!old_len_desc.writable() ||
      // Also handle the {configurable: true} and enumerable changes
      // since we later use JSArray::SetLength instead of
      // OrdinaryDefineOwnProperty to change the length,
      // and it doesn't have access to the descriptor anymore.
      new_len_desc->configurable() ||
      (new_len_desc->has_enumerable() &&
       (old_len_desc.enumerable() != new_len_desc->enumerable()))) {
    RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                   NewTypeError(MessageTemplate::kRedefineDisallowed,
                                isolate->factory()->length_string()));
  }
  // 14. If newLenDesc.[[Writable]] is absent or has the value true,
  // let newWritable be true.
  bool new_writable = false;
  if (!new_len_desc->has_writable() || new_len_desc->writable()) {
    new_writable = true;
  } else {
    // 15. Else,
    // 15a. Need to defer setting the [[Writable]] attribute to false in case
    //      any elements cannot be deleted.
    // 15b. Let newWritable be false. (It's initialized as "false" anyway.)
    // 15c. Set newLenDesc.[[Writable]] to true.
    // (Not needed.)
  }
  // Most of steps 16 through 19 is implemented by JSArray::SetLength.
  MAYBE_RETURN(JSArray::SetLength(a, new_len), Nothing<bool>());
  // Steps 19d-ii, 20.
  if (!new_writable) {
    PropertyDescriptor readonly;
    readonly.set_writable(false);
    success = OrdinaryDefineOwnProperty(isolate, a,
                                        isolate->factory()->length_string(),
                                        &readonly, should_throw);
    DCHECK(success.FromJust());
    USE(success);
  }
  uint32_t actual_new_len = 0;
  CHECK(Object::ToArrayLength(a->length(), &actual_new_len));
  // Steps 19d-v, 21. Return false if there were non-deletable elements.
  bool result = actual_new_len == new_len;
  if (!result) {
    RETURN_FAILURE(
        isolate, GetShouldThrow(isolate, should_throw),
        NewTypeError(MessageTemplate::kStrictDeleteProperty,
                     isolate->factory()->NewNumberFromUint(actual_new_len - 1),
                     a));
  }
  return Just(result);
}

// ES6 9.5.6
// static
Maybe<bool> JSProxy::DefineOwnProperty(Isolate* isolate, Handle<JSProxy> proxy,
                                       Handle<Object> key,
                                       PropertyDescriptor* desc,
                                       Maybe<ShouldThrow> should_throw) {
  STACK_CHECK(isolate, Nothing<bool>());
  if (IsSymbol(*key) && Cast<Symbol>(key)->IsPrivate()) {
    DCHECK(!Cast<Symbol>(key)->IsPrivateName());
    return JSProxy::SetPrivateSymbol(isolate, proxy, Cast<Symbol>(key), desc,
                                     should_throw);
  }
  Handle<String> trap_name = isolate->factory()->defineProperty_string();
  // 1. Assert: IsPropertyKey(P) is true.
  DCHECK(IsName(*key) || IsNumber(*key));
  // 2. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  Handle<Object> handler(proxy->handler(), isolate);
  // 3. If handler is null, throw a TypeError exception.
  // 4. Assert: Type(handler) is Object.
  if (proxy->IsRevoked()) {
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kProxyRevoked, trap_name));
    return Nothing<bool>();
  }
  // 5. Let target be the value of the [[ProxyTarget]] internal slot of O.
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  // 6. Let trap be ? GetMethod(handler, "defineProperty").
  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap,
      Object::GetMethod(isolate, Cast<JSReceiver>(handler), trap_name),
      Nothing<bool>());
  // 7. If trap is undefined, then:
  if (IsUndefined(*trap, isolate)) {
    // 7a. Return target.[[DefineOwnProperty]](P, Desc).
    return JSReceiver::DefineOwnProperty(isolate, target, key, desc,
                                         should_throw);
  }
  // 8. Let descObj be FromPropertyDescriptor(Desc).
  Handle<Object> desc_obj = desc->ToObject(isolate);
  // 9. Let booleanTrapResult be
  //    ToBoolean(? Call(trap, handler, «target, P, descObj»)).
  Handle<Name> property_name =
      IsName(*key) ? Cast<Name>(key)
                   : Cast<Name>(isolate->factory()->NumberToString(key));
  // Do not leak private property names.
  DCHECK(!property_name->IsPrivate());
  Handle<Object> trap_result_obj;
  Handle<Object> args[] = {target, property_name, desc_obj};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap_result_obj,
      Execution::Call(isolate, trap, handler, arraysize(args), args),
      Nothing<bool>());
  // 10. If booleanTrapResult is false, return false.
  if (!Object::BooleanValue(*trap_result_obj, isolate)) {
    RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                   NewTypeError(MessageTemplate::kProxyTrapReturnedFalsishFor,
                                trap_name, property_name));
  }
  // 11. Let targetDesc be ? target.[[GetOwnProperty]](P).
  PropertyDescriptor target_desc;
  Maybe<bool> target_found =
      JSReceiver::GetOwnPropertyDescriptor(isolate, target, key, &target_desc);
  MAYBE_RETURN(target_found, Nothing<bool>());
  // 12. Let extensibleTarget be ? IsExtensible(target).
  Maybe<bool> maybe_extensible = JSReceiver::IsExtensible(isolate, target);
  MAYBE_RETURN(maybe_extensible, Nothing<bool>());
  bool extensible_target = maybe_extensible.FromJust();
  // 13. If Desc has a [[Configurable]] field and if Desc.[[Configurable]]
  //     is false, then:
  // 13a. Let settingConfigFalse be true.
  // 14. Else let settingConfigFalse be false.
  bool setting_config_false = desc->has_configurable() && !desc->configurable();
  // 15. If targetDesc is undefined, then
  if (!target_found.FromJust()) {
    // 15a. If extensibleTarget is false, throw a TypeError exception.
    if (!extensible_target) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyDefinePropertyNonExtensible, property_name));
      return Nothing<bool>();
    }
    // 15b. If settingConfigFalse is true, throw a TypeError exception.
    if (setting_config_false) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyDefinePropertyNonConfigurable, property_name));
      return Nothing<bool>();
    }
  } else {
    // 16. Else targetDesc is not undefined,
    // 16a. If IsCompatiblePropertyDescriptor(extensibleTarget, Desc,
    //      targetDesc) is false, throw a TypeError exception.
    Maybe<bool> valid = IsCompatiblePropertyDescriptor(
        isolate, extensible_target, desc, &target_desc, property_name,
        Just(kDontThrow));
    MAYBE_RETURN(valid, Nothing<bool>());
    if (!valid.FromJust()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyDefinePropertyIncompatible, property_name));
      return Nothing<bool>();
    }
    // 16b. If settingConfigFalse is true and targetDesc.[[Configurable]] is
    //      true, throw a TypeError exception.
    if (setting_config_false && target_desc.configurable()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyDefinePropertyNonConfigurable, property_name));
      return Nothing<bool>();
    }
    // 16c. If IsDataDescriptor(targetDesc) is true,
    // targetDesc.[[Configurable]] is
    //       false, and targetDesc.[[Writable]] is true, then
    if (PropertyDescriptor::IsDataDescriptor(&target_desc) &&
        !target_desc.configurable() && target_desc.writable()) {
      // 16c i. If Desc has a [[Writable]] field and Desc.[[Writable]] is false,
      // throw a TypeError exception.
      if (desc->has_writable() && !desc->writable()) {
        isolate->Throw(*isolate->factory()->NewTypeError(
            MessageTemplate::kProxyDefinePropertyNonConfigurableWritable,
            property_name));
        return Nothing<bool>();
      }
    }
  }
  // 17. Return true.
  return Just(true);
}

// static
Maybe<bool> JSProxy::SetPrivateSymbol(Isolate* isolate, Handle<JSProxy> proxy,
                                      Handle<Symbol> private_name,
                                      PropertyDescriptor* desc,
                                      Maybe<ShouldThrow> should_throw) {
  // Despite the g
```