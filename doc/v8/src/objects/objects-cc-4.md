Response:
The user wants a summary of the functionalities present in the provided C++ code snippet from `v8/src/objects/objects.cc`. I need to identify the key operations and data structures manipulated in this code.

Here's a breakdown of the code's functionality:

1. **`JSProxy` Handling:** The code deals with JavaScript Proxy objects, covering operations like:
    - Adding private data properties (`JSProxy::SetPrivateBrand`).
    - Getting own property descriptors (`JSProxy::GetOwnPropertyDescriptor`).
    - Preventing extensions (`JSProxy::PreventExtensions`).
    - Checking extensibility (`JSProxy::IsExtensible`).

2. **`DescriptorArray` Management:**  This section focuses on manipulating `DescriptorArray` objects, which are used to store property descriptors:
    - Copying and potentially adding attributes (`DescriptorArray::CopyUpToAddAttributes`, `DescriptorArray::CopyUpTo`).
    - Checking equality (`DescriptorArray::IsEqualUpTo`).
    - Allocation (`DescriptorArray::Allocate`).
    - Initialization (`DescriptorArray::Initialize`).
    - Clearing enum cache (`DescriptorArray::ClearEnumCache`).
    - Replacing descriptors (`DescriptorArray::Replace`).
    - Initializing or changing the enum cache (`DescriptorArray::InitializeOrChangeEnumCache`).
    - Copying data from another `DescriptorArray` (`DescriptorArray::CopyFrom`).
    - Sorting (`DescriptorArray::Sort`).
    - Checking for name collisions during insertion (`DescriptorArray::CheckNameCollisionDuringInsertion`).

3. **`PrototypeUsers` Management:** This seems related to tracking objects that inherit from a prototype:
    - Adding users to a weak array list (`PrototypeUsers::Add`).
    - Scanning for empty slots in the weak array list (`PrototypeUsers::ScanForEmptySlots`).
    - Compacting the weak array list (`PrototypeUsers::Compact`).

4. **`AccessorPair` Handling:**  Operations related to getter/setter pairs:
    - Copying `AccessorPair` objects (`AccessorPair::Copy`).
    - Retrieving a component (getter or setter) of an `AccessorPair` (`AccessorPair::GetComponent`).

5. **`Name` Manipulation:**  Functions for converting names to function names:
    - `Name::ToFunctionName` (with and without a prefix).

6. **Garbage Collection Hooks:**  The `Relocatable` class seems to provide a mechanism for post-garbage collection processing.

7. **Array Joining Optimization:**  The `JSArray::ArrayJoinConcatToSequentialString` function implements an optimized way to join array elements into a string.

8. **String Hashing:** The `StringHasher::MakeArrayIndexHash` function creates a hash specifically for array indices.

9. **`Oddball` Initialization:**  The `Oddball::Initialize` function sets up special objects like `undefined` or `null`.

Based on this analysis, I can now formulate the summary and address the user's specific questions.
`v8/src/objects/objects.cc` 的这个代码片段主要负责实现 V8 引擎中多种核心对象的操作和管理，特别是与 **属性描述符 (Property Descriptors)** 和 **代理 (Proxies)** 相关的逻辑。它定义了这些对象在 C++ 层的行为。

**功能列举:**

1. **`JSProxy` 对象操作:**
   - **设置私有属性:** `JSProxy::SetPrivateBrand` 用于在 `JSProxy` 对象上添加私有数据属性。它确保只能添加不可枚举的私有数据属性。
   - **获取自有属性描述符:** `JSProxy::GetOwnPropertyDescriptor` 实现了 ES6 规范中 `[[GetOwnProperty]]` 的代理行为。它会调用代理处理器的 `getOwnPropertyDescriptor` 陷阱（trap），如果未定义陷阱，则会调用目标对象的 `[[GetOwnProperty]]`。它还负责验证陷阱返回的结果是否符合规范。
   - **阻止扩展:** `JSProxy::PreventExtensions` 实现了 ES6 规范中 `PreventExtensions` 的代理行为。它会调用代理处理器的 `preventExtensions` 陷阱，并强制执行一些不变量。
   - **判断是否可扩展:** `JSProxy::IsExtensible` 实现了 ES6 规范中 `IsExtensible` 的代理行为。它会调用代理处理器的 `isExtensible` 陷阱，并强制执行返回结果的一致性。

2. **`DescriptorArray` 对象操作:**
   - **复制:** `DescriptorArray::CopyUpTo` 和 `DescriptorArray::CopyUpToAddAttributes` 用于复制 `DescriptorArray`，后者还可以在复制过程中添加属性。
   - **比较:** `DescriptorArray::IsEqualUpTo` 用于比较两个 `DescriptorArray` 在指定数量的描述符内是否相等。
   - **分配:** `DescriptorArray::Allocate` 用于分配 `DescriptorArray` 的内存。
   - **初始化:** `DescriptorArray::Initialize` 用于初始化 `DescriptorArray` 的内部状态。
   - **清除枚举缓存:** `DescriptorArray::ClearEnumCache` 用于清除 `DescriptorArray` 关联的枚举缓存。
   - **替换:** `DescriptorArray::Replace` 用于替换 `DescriptorArray` 中的特定描述符。
   - **初始化或更改枚举缓存:** `DescriptorArray::InitializeOrChangeEnumCache` 用于初始化或更新 `DescriptorArray` 的枚举缓存。
   - **从另一个 `DescriptorArray` 复制:** `DescriptorArray::CopyFrom` 用于将一个 `DescriptorArray` 中的描述符复制到另一个。
   - **排序:** `DescriptorArray::Sort` 用于对 `DescriptorArray` 中的描述符进行排序。
   - **检查名称冲突:** `DescriptorArray::CheckNameCollisionDuringInsertion` 用于在插入描述符时检查是否存在名称冲突。

3. **`PrototypeUsers` 对象操作:**
   - **添加:** `PrototypeUsers::Add` 用于向 `WeakArrayList` 中添加原型用户（通常是 `Map` 对象）。
   - **扫描空槽:** `PrototypeUsers::ScanForEmptySlots` 用于扫描 `WeakArrayList` 中已清除的弱引用，并标记为空槽。
   - **压缩:** `PrototypeUsers::Compact` 用于压缩 `WeakArrayList`，移除已清除的弱引用。

4. **`AccessorPair` 对象操作:**
   - **复制:** `AccessorPair::Copy` 用于复制 `AccessorPair` 对象（用于存储 getter 和 setter 函数对）。
   - **获取组件:** `AccessorPair::GetComponent` 用于获取 `AccessorPair` 的 getter 或 setter 组件，如果组件是 `FunctionTemplateInfo`，则会实例化为一个 `JSFunction`。

5. **`Name` 对象操作:**
   - **转换为函数名:** `Name::ToFunctionName` 用于将 `Name` 对象（可以是字符串或 Symbol）转换为适合作为函数名的字符串，可以添加前缀。

6. **垃圾回收后处理:**
   - **`Relocatable` 类:**  提供了在垃圾回收后执行特定处理的机制。

7. **数组连接优化:**
   - **`JSArray::ArrayJoinConcatToSequentialString`:** 提供了一种优化的方式将数组元素连接成一个连续的字符串。

8. **字符串哈希:**
   - **`StringHasher::MakeArrayIndexHash`:**  为数组索引生成特定的哈希值。

9. **`Oddball` 对象初始化:**
   - **`Oddball::Initialize`:**  用于初始化特殊的单例对象，如 `undefined` 和 `null`。

**关于 `.tq` 结尾:**

如果 `v8/src/objects/objects.cc` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码**。Torque 是一种 V8 内部使用的领域特定语言，用于定义对象的布局和一些性能关键的操作。

**与 JavaScript 的关系和举例:**

这些 C++ 代码直接支撑着 JavaScript 中对象的行为。以下是一些 JavaScript 例子，展示了与上述 C++ 代码功能相关的操作：

```javascript
// JSProxy 相关
const target = {};
const handler = {
  getOwnPropertyDescriptor(target, prop) {
    console.log(`Getting descriptor for ${prop}`);
    return Object.getOwnPropertyDescriptor(target, prop);
  },
  preventExtensions(target) {
    console.log("Preventing extensions");
    Object.preventExtensions(target);
    return true;
  },
  isExtensible(target) {
    console.log("Checking if extensible");
    return Object.isExtensible(target);
  }
};
const proxy = new Proxy(target, handler);

Object.getOwnPropertyDescriptor(proxy, 'a'); // 触发 handler.getOwnPropertyDescriptor
Object.preventExtensions(proxy); // 触发 handler.preventExtensions
Object.isExtensible(proxy); // 触发 handler.isExtensible

// 私有属性 (Symbol)
const privateKey = Symbol();
proxy[privateKey] = 10;

// 属性描述符
const obj = { a: 1 };
const descriptor = Object.getOwnPropertyDescriptor(obj, 'a');
console.log(descriptor); // 输出属性描述符

// Object.preventExtensions
Object.preventExtensions(obj);
console.log(Object.isExtensible(obj)); // 输出 false

// getter 和 setter
const objWithAccessors = {
  _x: 0,
  get x() {
    return this._x;
  },
  set x(value) {
    this._x = value;
  }
};
console.log(objWithAccessors.x); // 调用 getter
objWithAccessors.x = 5; // 调用 setter

// 数组的 join 方法
const arr = [1, 2, 3];
const joinedString = arr.join('-'); // 内部可能用到 JSArray::ArrayJoinConcatToSequentialString
console.log(joinedString);
```

**代码逻辑推理和假设输入输出:**

**`JSProxy::GetOwnPropertyDescriptor` 示例:**

**假设输入:**

- `proxy`: 一个 `JSProxy` 实例，其 `handler` 定义了 `getOwnPropertyDescriptor` 陷阱。
- `name`: 字符串 "foo"。
- 目标对象 `target` 有一个属性 "foo"，其描述符为 `{ value: 1, writable: true, enumerable: true, configurable: true }`。
- 代理处理器的 `getOwnPropertyDescriptor` 陷阱函数返回 `{ value: 2, writable: false }`。

**输出:**

- `JSProxy::GetOwnPropertyDescriptor` 将返回 `Just(true)`，并且 `desc` 参数会被填充为 `{ value: 2, writable: false, enumerable: true, configurable: true }`。注意，陷阱的结果会覆盖目标对象的属性，并补全缺失的属性。

**用户常见的编程错误:**

1. **在 Proxy 的陷阱中返回不符合规范的值:**  例如，`getOwnPropertyDescriptor` 陷阱应该返回一个对象或 `undefined`。如果返回其他类型的值，V8 会抛出 `TypeError`。

   ```javascript
   const target = {};
   const handler = {
     getOwnPropertyDescriptor() {
       return 123; // 错误：返回了数字
     }
   };
   const proxy = new Proxy(target, handler);
   Object.getOwnPropertyDescriptor(proxy, 'a'); // 抛出 TypeError
   ```

2. **在 `PreventExtensions` 的陷阱中返回 falsy 值，但目标对象仍然可扩展:** 这违反了代理的不变量，会导致 `TypeError`。

   ```javascript
   const target = {};
   const handler = {
     preventExtensions() {
       return false; // 返回 falsy 值
     }
   };
   const proxy = new Proxy(target, handler);
   Object.preventExtensions(proxy); // 抛出 TypeError，因为目标对象默认是可扩展的
   ```

**功能归纳 (第 5 部分，共 8 部分):**

在整个 `v8/src/objects/objects.cc` 文件中，这部分代码主要关注以下核心功能：

- **实现 JavaScript Proxy 对象的底层行为**，包括拦截属性访问、修改对象行为等。
- **管理属性描述符的存储和操作**，通过 `DescriptorArray` 提供高效的属性管理机制。
- **维护原型链的关系**，通过 `PrototypeUsers` 跟踪依赖于特定原型的对象。
- **提供对 getter 和 setter 函数对的管理**。
- **提供一些基础的字符串和名称操作**。
- **提供垃圾回收相关的钩子**。
- **实现一些性能优化的操作**，例如数组连接。

总的来说，这部分代码是 V8 引擎中对象系统的重要组成部分，为 JavaScript 语言中灵活的对象模型提供了底层的 C++ 实现。它处理了对象属性的元信息、代理机制以及与性能相关的优化。

### 提示词
```
这是目录为v8/src/objects/objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
eneric name, this can only add private data properties.
  if (!PropertyDescriptor::IsDataDescriptor(desc) ||
      desc->ToAttributes() != DONT_ENUM) {
    RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                   NewTypeError(MessageTemplate::kProxyPrivate));
  }
  DCHECK(proxy->map()->is_dictionary_map());
  Handle<Object> value =
      desc->has_value() ? desc->value()
                        : Cast<Object>(isolate->factory()->undefined_value());

  LookupIterator it(isolate, proxy, private_name, proxy);

  if (it.IsFound()) {
    DCHECK_EQ(LookupIterator::DATA, it.state());
    DCHECK_EQ(DONT_ENUM, it.property_attributes());
    // We are not tracking constness for private symbols added to JSProxy
    // objects.
    DCHECK_EQ(PropertyConstness::kMutable, it.property_details().constness());
    it.WriteDataValue(value, false);
    return Just(true);
  }

  PropertyDetails details(PropertyKind::kData, DONT_ENUM,
                          PropertyConstness::kMutable);
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    Handle<SwissNameDictionary> dict(proxy->property_dictionary_swiss(),
                                     isolate);
    Handle<SwissNameDictionary> result =
        SwissNameDictionary::Add(isolate, dict, private_name, value, details);
    if (!dict.is_identical_to(result)) proxy->SetProperties(*result);
  } else {
    Handle<NameDictionary> dict(proxy->property_dictionary(), isolate);
    Handle<NameDictionary> result =
        NameDictionary::Add(isolate, dict, private_name, value, details);
    if (!dict.is_identical_to(result)) proxy->SetProperties(*result);
  }
  return Just(true);
}

// ES6 9.5.5
// static
Maybe<bool> JSProxy::GetOwnPropertyDescriptor(Isolate* isolate,
                                              DirectHandle<JSProxy> proxy,
                                              Handle<Name> name,
                                              PropertyDescriptor* desc) {
  DCHECK(!name->IsPrivate());
  STACK_CHECK(isolate, Nothing<bool>());

  Handle<String> trap_name =
      isolate->factory()->getOwnPropertyDescriptor_string();
  // 1. (Assert)
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
  // 6. Let trap be ? GetMethod(handler, "getOwnPropertyDescriptor").
  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap,
      Object::GetMethod(isolate, Cast<JSReceiver>(handler), trap_name),
      Nothing<bool>());
  // 7. If trap is undefined, then
  if (IsUndefined(*trap, isolate)) {
    // 7a. Return target.[[GetOwnProperty]](P).
    return JSReceiver::GetOwnPropertyDescriptor(isolate, target, name, desc);
  }
  // 8. Let trapResultObj be ? Call(trap, handler, «target, P»).
  Handle<JSAny> trap_result_obj;
  Handle<Object> args[] = {target, name};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap_result_obj,
      Cast<JSAny>(
          Execution::Call(isolate, trap, handler, arraysize(args), args)),
      Nothing<bool>());
  // 9. If Type(trapResultObj) is neither Object nor Undefined, throw a
  //    TypeError exception.
  if (!IsJSReceiver(*trap_result_obj) &&
      !IsUndefined(*trap_result_obj, isolate)) {
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kProxyGetOwnPropertyDescriptorInvalid, name));
    return Nothing<bool>();
  }
  // 10. Let targetDesc be ? target.[[GetOwnProperty]](P).
  PropertyDescriptor target_desc;
  Maybe<bool> found =
      JSReceiver::GetOwnPropertyDescriptor(isolate, target, name, &target_desc);
  MAYBE_RETURN(found, Nothing<bool>());
  // 11. If trapResultObj is undefined, then
  if (IsUndefined(*trap_result_obj, isolate)) {
    // 11a. If targetDesc is undefined, return undefined.
    if (!found.FromJust()) return Just(false);
    // 11b. If targetDesc.[[Configurable]] is false, throw a TypeError
    //      exception.
    if (!target_desc.configurable()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyGetOwnPropertyDescriptorUndefined, name));
      return Nothing<bool>();
    }
    // 11c. Let extensibleTarget be ? IsExtensible(target).
    Maybe<bool> extensible_target = JSReceiver::IsExtensible(isolate, target);
    MAYBE_RETURN(extensible_target, Nothing<bool>());
    // 11d. (Assert)
    // 11e. If extensibleTarget is false, throw a TypeError exception.
    if (!extensible_target.FromJust()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyGetOwnPropertyDescriptorNonExtensible, name));
      return Nothing<bool>();
    }
    // 11f. Return undefined.
    return Just(false);
  }
  // 12. Let extensibleTarget be ? IsExtensible(target).
  Maybe<bool> extensible_target = JSReceiver::IsExtensible(isolate, target);
  MAYBE_RETURN(extensible_target, Nothing<bool>());
  // 13. Let resultDesc be ? ToPropertyDescriptor(trapResultObj).
  if (!PropertyDescriptor::ToPropertyDescriptor(isolate, trap_result_obj,
                                                desc)) {
    DCHECK(isolate->has_exception());
    return Nothing<bool>();
  }
  // 14. Call CompletePropertyDescriptor(resultDesc).
  PropertyDescriptor::CompletePropertyDescriptor(isolate, desc);
  // 15. Let valid be IsCompatiblePropertyDescriptor (extensibleTarget,
  //     resultDesc, targetDesc).
  Maybe<bool> valid = IsCompatiblePropertyDescriptor(
      isolate, extensible_target.FromJust(), desc, &target_desc, name,
      Just(kDontThrow));
  MAYBE_RETURN(valid, Nothing<bool>());
  // 16. If valid is false, throw a TypeError exception.
  if (!valid.FromJust()) {
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kProxyGetOwnPropertyDescriptorIncompatible, name));
    return Nothing<bool>();
  }
  // 17. If resultDesc.[[Configurable]] is false, then
  if (!desc->configurable()) {
    // 17a. If targetDesc is undefined or targetDesc.[[Configurable]] is true:
    if (target_desc.is_empty() || target_desc.configurable()) {
      // 17a i. Throw a TypeError exception.
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyGetOwnPropertyDescriptorNonConfigurable,
          name));
      return Nothing<bool>();
    }
    // 17b. If resultDesc has a [[Writable]] field and resultDesc.[[Writable]]
    // is false, then
    if (desc->has_writable() && !desc->writable()) {
      // 17b i. If targetDesc.[[Writable]] is true, throw a TypeError exception.
      if (target_desc.writable()) {
        isolate->Throw(*isolate->factory()->NewTypeError(
            MessageTemplate::
                kProxyGetOwnPropertyDescriptorNonConfigurableWritable,
            name));
        return Nothing<bool>();
      }
    }
  }
  // 18. Return resultDesc.
  return Just(true);
}

Maybe<bool> JSProxy::PreventExtensions(DirectHandle<JSProxy> proxy,
                                       ShouldThrow should_throw) {
  Isolate* isolate = proxy->GetIsolate();
  STACK_CHECK(isolate, Nothing<bool>());
  Factory* factory = isolate->factory();
  Handle<String> trap_name = factory->preventExtensions_string();

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
    return JSReceiver::PreventExtensions(isolate, target, should_throw);
  }

  Handle<Object> trap_result;
  Handle<Object> args[] = {target};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap_result,
      Execution::Call(isolate, trap, handler, arraysize(args), args),
      Nothing<bool>());
  if (!Object::BooleanValue(*trap_result, isolate)) {
    RETURN_FAILURE(
        isolate, should_throw,
        NewTypeError(MessageTemplate::kProxyTrapReturnedFalsish, trap_name));
  }

  // Enforce the invariant.
  Maybe<bool> target_result = JSReceiver::IsExtensible(isolate, target);
  MAYBE_RETURN(target_result, Nothing<bool>());
  if (target_result.FromJust()) {
    isolate->Throw(*factory->NewTypeError(
        MessageTemplate::kProxyPreventExtensionsExtensible));
    return Nothing<bool>();
  }
  return Just(true);
}

Maybe<bool> JSProxy::IsExtensible(DirectHandle<JSProxy> proxy) {
  Isolate* isolate = proxy->GetIsolate();
  STACK_CHECK(isolate, Nothing<bool>());
  Factory* factory = isolate->factory();
  Handle<String> trap_name = factory->isExtensible_string();

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
    return JSReceiver::IsExtensible(isolate, target);
  }

  Handle<Object> trap_result;
  Handle<Object> args[] = {target};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap_result,
      Execution::Call(isolate, trap, handler, arraysize(args), args),
      Nothing<bool>());

  // Enforce the invariant.
  Maybe<bool> target_result = JSReceiver::IsExtensible(isolate, target);
  MAYBE_RETURN(target_result, Nothing<bool>());
  if (target_result.FromJust() != Object::BooleanValue(*trap_result, isolate)) {
    isolate->Throw(
        *factory->NewTypeError(MessageTemplate::kProxyIsExtensibleInconsistent,
                               factory->ToBoolean(target_result.FromJust())));
    return Nothing<bool>();
  }
  return target_result;
}

Handle<DescriptorArray> DescriptorArray::CopyUpTo(
    Isolate* isolate, DirectHandle<DescriptorArray> desc, int enumeration_index,
    int slack) {
  return DescriptorArray::CopyUpToAddAttributes(isolate, desc,
                                                enumeration_index, NONE, slack);
}

Handle<DescriptorArray> DescriptorArray::CopyUpToAddAttributes(
    Isolate* isolate, DirectHandle<DescriptorArray> source_handle,
    int enumeration_index, PropertyAttributes attributes, int slack) {
  if (enumeration_index + slack == 0) {
    return isolate->factory()->empty_descriptor_array();
  }

  int size = enumeration_index;
  Handle<DescriptorArray> copy_handle =
      DescriptorArray::Allocate(isolate, size, slack);

  DisallowGarbageCollection no_gc;
  Tagged<DescriptorArray> source = *source_handle;
  Tagged<DescriptorArray> copy = *copy_handle;

  if (attributes != NONE) {
    for (InternalIndex i : InternalIndex::Range(size)) {
      Tagged<MaybeObject> value_or_field_type = source->GetValue(i);
      Tagged<Name> key = source->GetKey(i);
      PropertyDetails details = source->GetDetails(i);
      // Bulk attribute changes never affect private properties.
      if (!key->IsPrivate()) {
        int mask = DONT_DELETE | DONT_ENUM;
        // READ_ONLY is an invalid attribute for JS setters/getters.
        Tagged<HeapObject> heap_object;
        if (details.kind() != PropertyKind::kAccessor ||
            !(value_or_field_type.GetHeapObjectIfStrong(&heap_object) &&
              IsAccessorPair(heap_object))) {
          mask |= READ_ONLY;
        }
        details = details.CopyAddAttributes(
            static_cast<PropertyAttributes>(attributes & mask));
      }
      copy->Set(i, key, value_or_field_type, details);
    }
  } else {
    for (InternalIndex i : InternalIndex::Range(size)) {
      copy->CopyFrom(i, source);
    }
  }

  if (source->number_of_descriptors() != enumeration_index) copy->Sort();

  return copy_handle;
}

bool DescriptorArray::IsEqualUpTo(Tagged<DescriptorArray> desc,
                                  int nof_descriptors) {
  for (InternalIndex i : InternalIndex::Range(nof_descriptors)) {
    if (GetKey(i) != desc->GetKey(i) || GetValue(i) != desc->GetValue(i)) {
      return false;
    }
    PropertyDetails details = GetDetails(i);
    PropertyDetails other_details = desc->GetDetails(i);
    if (details.kind() != other_details.kind() ||
        details.location() != other_details.location() ||
        !details.representation().Equals(other_details.representation())) {
      return false;
    }
  }
  return true;
}

// static
Handle<WeakArrayList> PrototypeUsers::Add(Isolate* isolate,
                                          Handle<WeakArrayList> array,
                                          DirectHandle<Map> value,
                                          int* assigned_index) {
  int length = array->length();
  if (length == 0) {
    // Uninitialized WeakArrayList; need to initialize empty_slot_index.
    array = WeakArrayList::EnsureSpace(isolate, array, kFirstIndex + 1);
    set_empty_slot_index(*array, kNoEmptySlotsMarker);
    array->Set(kFirstIndex, MakeWeak(*value));
    array->set_length(kFirstIndex + 1);
    if (assigned_index != nullptr) *assigned_index = kFirstIndex;
    return array;
  }

  // If the array has unfilled space at the end, use it.
  if (!array->IsFull()) {
    array->Set(length, MakeWeak(*value));
    array->set_length(length + 1);
    if (assigned_index != nullptr) *assigned_index = length;
    return array;
  }

  // If there are empty slots, use one of them.
  int empty_slot = Smi::ToInt(empty_slot_index(*array));

  if (empty_slot == kNoEmptySlotsMarker) {
    // GCs might have cleared some references, rescan the array for empty slots.
    PrototypeUsers::ScanForEmptySlots(*array);
    empty_slot = Smi::ToInt(empty_slot_index(*array));
  }

  if (empty_slot != kNoEmptySlotsMarker) {
    DCHECK_GE(empty_slot, kFirstIndex);
    CHECK_LT(empty_slot, array->length());
    int next_empty_slot = array->Get(empty_slot).ToSmi().value();

    array->Set(empty_slot, MakeWeak(*value));
    if (assigned_index != nullptr) *assigned_index = empty_slot;

    set_empty_slot_index(*array, next_empty_slot);
    return array;
  } else {
    DCHECK_EQ(empty_slot, kNoEmptySlotsMarker);
  }

  // Array full and no empty slots. Grow the array.
  array = WeakArrayList::EnsureSpace(isolate, array, length + 1);
  array->Set(length, MakeWeak(*value));
  array->set_length(length + 1);
  if (assigned_index != nullptr) *assigned_index = length;
  return array;
}

// static
void PrototypeUsers::ScanForEmptySlots(Tagged<WeakArrayList> array) {
  for (int i = kFirstIndex; i < array->length(); i++) {
    if (array->Get(i).IsCleared()) {
      PrototypeUsers::MarkSlotEmpty(array, i);
    }
  }
}

Tagged<WeakArrayList> PrototypeUsers::Compact(DirectHandle<WeakArrayList> array,
                                              Heap* heap,
                                              CompactionCallback callback,
                                              AllocationType allocation) {
  if (array->length() == 0) {
    return *array;
  }
  int new_length = kFirstIndex + array->CountLiveWeakReferences();
  if (new_length == array->length()) {
    return *array;
  }

  DirectHandle<WeakArrayList> new_array = WeakArrayList::EnsureSpace(
      heap->isolate(),
      handle(ReadOnlyRoots(heap).empty_weak_array_list(), heap->isolate()),
      new_length, allocation);
  // Allocation might have caused GC and turned some of the elements into
  // cleared weak heap objects. Count the number of live objects again.
  int copy_to = kFirstIndex;
  for (int i = kFirstIndex; i < array->length(); i++) {
    Tagged<MaybeObject> element = array->Get(i);
    Tagged<HeapObject> value;
    if (element.GetHeapObjectIfWeak(&value)) {
      callback(value, i, copy_to);
      new_array->Set(copy_to++, element);
    } else {
      DCHECK(element.IsCleared() || element.IsSmi());
    }
  }
  new_array->set_length(copy_to);
  set_empty_slot_index(*new_array, kNoEmptySlotsMarker);
  return *new_array;
}

template <typename IsolateT>
Handle<DescriptorArray> DescriptorArray::Allocate(IsolateT* isolate,
                                                  int nof_descriptors,
                                                  int slack,
                                                  AllocationType allocation) {
  return nof_descriptors + slack == 0
             ? isolate->factory()->empty_descriptor_array()
             : isolate->factory()->NewDescriptorArray(nof_descriptors, slack,
                                                      allocation);
}
template Handle<DescriptorArray> DescriptorArray::Allocate(
    Isolate* isolate, int nof_descriptors, int slack,
    AllocationType allocation);
template Handle<DescriptorArray> DescriptorArray::Allocate(
    LocalIsolate* isolate, int nof_descriptors, int slack,
    AllocationType allocation);

void DescriptorArray::Initialize(Tagged<EnumCache> empty_enum_cache,
                                 Tagged<HeapObject> undefined_value,
                                 int nof_descriptors, int slack,
                                 uint32_t raw_gc_state) {
  DCHECK_GE(nof_descriptors, 0);
  DCHECK_GE(slack, 0);
  DCHECK_LE(nof_descriptors + slack, kMaxNumberOfDescriptors);
  set_number_of_all_descriptors(nof_descriptors + slack);
  set_number_of_descriptors(nof_descriptors);
  set_raw_gc_state(raw_gc_state, kRelaxedStore);
  set_enum_cache(empty_enum_cache, SKIP_WRITE_BARRIER);
  MemsetTagged(GetDescriptorSlot(0), undefined_value,
               number_of_all_descriptors() * kEntrySize);
}

void DescriptorArray::ClearEnumCache() {
  set_enum_cache(GetReadOnlyRoots().empty_enum_cache(), SKIP_WRITE_BARRIER);
}

void DescriptorArray::Replace(InternalIndex index, Descriptor* descriptor) {
  descriptor->SetSortedKeyIndex(GetSortedKeyIndex(index.as_int()));
  Set(index, descriptor);
}

// static
void DescriptorArray::InitializeOrChangeEnumCache(
    DirectHandle<DescriptorArray> descriptors, Isolate* isolate,
    DirectHandle<FixedArray> keys, DirectHandle<FixedArray> indices,
    AllocationType allocation_if_initialize) {
  Tagged<EnumCache> enum_cache = descriptors->enum_cache();
  if (enum_cache == ReadOnlyRoots(isolate).empty_enum_cache()) {
    enum_cache = *isolate->factory()->NewEnumCache(keys, indices,
                                                   allocation_if_initialize);
    descriptors->set_enum_cache(enum_cache);
  } else {
    enum_cache->set_keys(*keys);
    enum_cache->set_indices(*indices);
  }
}

void DescriptorArray::CopyFrom(InternalIndex index,
                               Tagged<DescriptorArray> src) {
  PropertyDetails details = src->GetDetails(index);
  Set(index, src->GetKey(index), src->GetValue(index), details);
}

void DescriptorArray::Sort() {
  // In-place heap sort.
  const int len = number_of_descriptors();
  // Reset sorting since the descriptor array might contain invalid pointers.
  for (int i = 0; i < len; ++i) SetSortedKey(i, i);
  // Bottom-up max-heap construction.
  // Index of the last node with children.
  int max_parent_index = (len / 2) - 1;
  for (int i = max_parent_index; i >= 0; --i) {
    int parent_index = i;
    const uint32_t parent_hash = GetSortedKey(i)->hash();
    while (parent_index <= max_parent_index) {
      int child_index = 2 * parent_index + 1;
      uint32_t child_hash = GetSortedKey(child_index)->hash();
      if (child_index + 1 < len) {
        uint32_t right_child_hash = GetSortedKey(child_index + 1)->hash();
        if (right_child_hash > child_hash) {
          child_index++;
          child_hash = right_child_hash;
        }
      }
      if (child_hash <= parent_hash) break;
      SwapSortedKeys(parent_index, child_index);
      // Now element at child_index could be < its children.
      parent_index = child_index;  // parent_hash remains correct.
    }
  }

  // Extract elements and create sorted array.
  for (int i = len - 1; i > 0; --i) {
    // Put max element at the back of the array.
    SwapSortedKeys(0, i);
    // Shift down the new top element.
    int parent_index = 0;
    const uint32_t parent_hash = GetSortedKey(parent_index)->hash();
    max_parent_index = (i / 2) - 1;
    while (parent_index <= max_parent_index) {
      int child_index = parent_index * 2 + 1;
      uint32_t child_hash = GetSortedKey(child_index)->hash();
      if (child_index + 1 < i) {
        uint32_t right_child_hash = GetSortedKey(child_index + 1)->hash();
        if (right_child_hash > child_hash) {
          child_index++;
          child_hash = right_child_hash;
        }
      }
      if (child_hash <= parent_hash) break;
      SwapSortedKeys(parent_index, child_index);
      parent_index = child_index;
    }
  }
  DCHECK(IsSortedNoDuplicates());
}

void DescriptorArray::CheckNameCollisionDuringInsertion(Descriptor* desc,
                                                        uint32_t desc_hash,
                                                        int insertion_index) {
  DCHECK_GE(insertion_index, 0);
  DCHECK_LE(insertion_index, number_of_all_descriptors());

  if (insertion_index <= 0) return;

  for (int i = insertion_index; i > 0; --i) {
    Tagged<Name> current_key = GetSortedKey(i - 1);
    if (current_key->hash() != desc_hash) return;
    CHECK(current_key != *desc->GetKey());
  }
}

Handle<AccessorPair> AccessorPair::Copy(Isolate* isolate,
                                        DirectHandle<AccessorPair> pair) {
  Handle<AccessorPair> copy = isolate->factory()->NewAccessorPair();
  DisallowGarbageCollection no_gc;
  Tagged<AccessorPair> raw_src = *pair;
  Tagged<AccessorPair> raw_copy = *copy;
  raw_copy->set_getter(raw_src->getter());
  raw_copy->set_setter(raw_src->setter());
  return copy;
}

Handle<JSAny> AccessorPair::GetComponent(
    Isolate* isolate, Handle<NativeContext> native_context,
    DirectHandle<AccessorPair> accessor_pair, AccessorComponent component) {
  Handle<Object> accessor(accessor_pair->get(component), isolate);
  if (IsFunctionTemplateInfo(*accessor)) {
    // TODO(v8:5962): pass the right name here: "get "/"set " + prop.
    Handle<JSFunction> function =
        ApiNatives::InstantiateFunction(isolate, native_context,
                                        Cast<FunctionTemplateInfo>(accessor))
            .ToHandleChecked();
    accessor_pair->set(component, *function, kReleaseStore);
    return function;
  }
  if (IsNull(*accessor, isolate)) {
    return isolate->factory()->undefined_value();
  }
  return Cast<JSAny>(accessor);
}

#ifdef DEBUG
bool DescriptorArray::IsEqualTo(Tagged<DescriptorArray> other) {
  if (number_of_all_descriptors() != other->number_of_all_descriptors()) {
    return false;
  }
  for (InternalIndex i : InternalIndex::Range(number_of_descriptors())) {
    if (GetKey(i) != other->GetKey(i)) return false;
    if (GetDetails(i).AsSmi() != other->GetDetails(i).AsSmi()) return false;
    if (GetValue(i) != other->GetValue(i)) return false;
  }
  return true;
}
#endif

// static
MaybeHandle<String> Name::ToFunctionName(Isolate* isolate, Handle<Name> name) {
  if (IsString(*name)) return Cast<String>(name);
  // ES6 section 9.2.11 SetFunctionName, step 4.
  Handle<Object> description(Cast<Symbol>(name)->description(), isolate);
  if (IsUndefined(*description, isolate)) {
    return isolate->factory()->empty_string();
  }
  IncrementalStringBuilder builder(isolate);
  builder.AppendCharacter('[');
  builder.AppendString(Cast<String>(description));
  builder.AppendCharacter(']');
  return indirect_handle(builder.Finish(), isolate);
}

// static
MaybeHandle<String> Name::ToFunctionName(Isolate* isolate, Handle<Name> name,
                                         DirectHandle<String> prefix) {
  Handle<String> name_string;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, name_string,
                             ToFunctionName(isolate, name));
  IncrementalStringBuilder builder(isolate);
  builder.AppendString(prefix);
  builder.AppendCharacter(' ');
  builder.AppendString(name_string);
  return indirect_handle(builder.Finish(), isolate);
}

void Relocatable::PostGarbageCollectionProcessing(Isolate* isolate) {
  Relocatable* current = isolate->relocatable_top();
  while (current != nullptr) {
    current->PostGarbageCollection();
    current = current->prev_;
  }
}

// Reserve space for statics needing saving and restoring.
int Relocatable::ArchiveSpacePerThread() { return sizeof(Relocatable*); }

// Archive statics that are thread-local.
char* Relocatable::ArchiveState(Isolate* isolate, char* to) {
  *reinterpret_cast<Relocatable**>(to) = isolate->relocatable_top();
  isolate->set_relocatable_top(nullptr);
  return to + ArchiveSpacePerThread();
}

// Restore statics that are thread-local.
char* Relocatable::RestoreState(Isolate* isolate, char* from) {
  isolate->set_relocatable_top(*reinterpret_cast<Relocatable**>(from));
  return from + ArchiveSpacePerThread();
}

char* Relocatable::Iterate(RootVisitor* v, char* thread_storage) {
  Relocatable* top = *reinterpret_cast<Relocatable**>(thread_storage);
  Iterate(v, top);
  return thread_storage + ArchiveSpacePerThread();
}

void Relocatable::Iterate(Isolate* isolate, RootVisitor* v) {
  Iterate(v, isolate->relocatable_top());
}

void Relocatable::Iterate(RootVisitor* v, Relocatable* top) {
  Relocatable* current = top;
  while (current != nullptr) {
    current->IterateInstance(v);
    current = current->prev_;
  }
}

namespace {

template <typename sinkchar>
void WriteFixedArrayToFlat(Tagged<FixedArray> fixed_array, int length,
                           Tagged<String> separator, sinkchar* sink,
                           int sink_length) {
  DisallowGarbageCollection no_gc;
  CHECK_GT(length, 0);
  CHECK_LE(length, fixed_array->length());
#ifdef DEBUG
  sinkchar* sink_end = sink + sink_length;
#endif

  const int separator_length = separator->length();
  const bool use_one_byte_separator_fast_path =
      separator_length == 1 && sizeof(sinkchar) == 1 &&
      StringShape(separator).IsSequentialOneByte();
  uint8_t separator_one_char;
  if (use_one_byte_separator_fast_path) {
    CHECK(StringShape(separator).IsSequentialOneByte());
    CHECK_EQ(separator->length(), 1);
    separator_one_char = Cast<SeqOneByteString>(separator)->GetChars(no_gc)[0];
  }

  uint32_t num_separators = 0;
  uint32_t repeat_last = 0;
  for (int i = 0; i < length; i++) {
    Tagged<Object> element = fixed_array->get(i);
    const bool element_is_special = IsSmi(element);

    // If element is a positive Smi, it represents the number of separators to
    // write. If it is a negative Smi, it reprsents the number of times the last
    // string is repeated.
    if (V8_UNLIKELY(element_is_special)) {
      int count;
      CHECK(Object::ToInt32(element, &count));
      if (count > 0) {
        num_separators = count;
        //  Verify that Smis (number of separators) only occur when necessary:
        //    1) at the beginning
        //    2) at the end
        //    3) when the number of separators > 1
        //      - It is assumed that consecutive Strings will have one
        //      separator,
        //        so there is no need for a Smi.
        DCHECK(i == 0 || i == length - 1 || num_separators > 1);
      } else {
        repeat_last = -count;
        // Repeat is only possible when the previous element is not special.
        DCHECK_GT(i, 0);
        DCHECK(IsString(fixed_array->get(i - 1)));
      }
    }

    // Write separator(s) if necessary.
    if (num_separators > 0 && separator_length > 0) {
      // TODO(pwong): Consider doubling strategy employed by runtime-strings.cc
      //              WriteRepeatToFlat().
      // Fast path for single character, single byte separators.
      if (use_one_byte_separator_fast_path) {
        DCHECK_LE(sink + num_separators, sink_end);
        memset(sink, separator_one_char, num_separators);
        DCHECK_EQ(separator_length, 1);
        sink += num_separators;
      } else {
        for (uint32_t j = 0; j < num_separators; j++) {
          DCHECK_LE(sink + separator_length, sink_end);
          String::WriteToFlat(separator, sink, 0, separator_length);
          sink += separator_length;
        }
      }
      num_separators = 0;
    }

    // Repeat the last written string |repeat_last| times (including
    // separators).
    if (V8_UNLIKELY(repeat_last > 0)) {
      Tagged<Object> last_element = fixed_array->get(i - 1);
      int string_length = Cast<String>(last_element)->length();
      // The implemented logic requires that string length is > 0. Empty strings
      // are handled by repeating the separator (positive smi in the fixed
      // array) already.
      DCHECK_GT(string_length, 0);
      int length_with_sep = string_length + separator_length;
      // Only copy separators between elements, not at the start or beginning.
      sinkchar* copy_end =
          sink + (length_with_sep * repeat_last) - separator_length;
      int copy_length = length_with_sep;
      while (sink < copy_end - copy_length) {
        DCHECK_LE(sink + copy_length, sink_end);
        memcpy(sink, sink - copy_length, copy_length * sizeof(sinkchar));
        sink += copy_length;
        copy_length *= 2;
      }
      int remaining = static_cast<int>(copy_end - sink);
      if (remaining > 0) {
        DCHECK_LE(sink + remaining, sink_end);
        memcpy(sink, sink - remaining - separator_length,
               remaining * sizeof(sinkchar));
        sink += remaining;
      }
      repeat_last = 0;
      num_separators = 1;
    }

    if (V8_LIKELY(!element_is_special)) {
      DCHECK(IsString(element));
      Tagged<String> string = Cast<String>(element);
      const int string_length = string->length();

      DCHECK(string_length == 0 || sink < sink_end);
      String::WriteToFlat(string, sink, 0, string_length);
      sink += string_length;

      // Next string element, needs at least one separator preceding it.
      num_separators = 1;
    }
  }

  // Verify we have written to the end of the sink.
  DCHECK_EQ(sink, sink_end);
}

}  // namespace

// static
Address JSArray::ArrayJoinConcatToSequentialString(Isolate* isolate,
                                                   Address raw_fixed_array,
                                                   intptr_t length,
                                                   Address raw_separator,
                                                   Address raw_dest) {
  DisallowGarbageCollection no_gc;
  DisallowJavascriptExecution no_js(isolate);
  Tagged<FixedArray> fixed_array =
      Cast<FixedArray>(Tagged<Object>(raw_fixed_array));
  Tagged<String> separator = Cast<String>(Tagged<Object>(raw_separator));
  Tagged<String> dest = Cast<String>(Tagged<Object>(raw_dest));
  DCHECK(IsFixedArray(fixed_array));
  DCHECK(StringShape(dest).IsSequentialOneByte() ||
         StringShape(dest).IsSequentialTwoByte());

  if (StringShape(dest).IsSequentialOneByte()) {
    WriteFixedArrayToFlat(fixed_array, static_cast<int>(length), separator,
                          Cast<SeqOneByteString>(dest)->GetChars(no_gc),
                          dest->length());
  } else {
    DCHECK(StringShape(dest).IsSequentialTwoByte());
    WriteFixedArrayToFlat(fixed_array, static_cast<int>(length), separator,
                          Cast<SeqTwoByteString>(dest)->GetChars(no_gc),
                          dest->length());
  }
  return dest.ptr();
}

uint32_t StringHasher::MakeArrayIndexHash(uint32_t value, uint32_t length) {
  // For array indexes mix the length into the hash as an array index could
  // be zero.
  DCHECK_LE(length, String::kMaxArrayIndexSize);
  DCHECK(TenToThe(String::kMaxCachedArrayIndexLength) <
         (1 << String::kArrayIndexValueBits));

  value <<= String::ArrayIndexValueBits::kShift;
  value |= length << String::ArrayIndexLengthBits::kShift;

  DCHECK(String::IsIntegerIndex(value));
  DCHECK_EQ(length <= String::kMaxCachedArrayIndexLength,
            Name::ContainsCachedArrayIndex(value));
  return value;
}

void Oddball::Initialize(Isolate* isolate, DirectHandle<Oddball> oddball,
                         const char* to_string, Handle<Number> to_number,
                         const char* type_of, uint8_t kind) {
  DirectHandle<String> internalized_to_string =
      isolate->factory()->Interna
```