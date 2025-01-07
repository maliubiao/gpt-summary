Response: The user wants a summary of the C++ source code file `v8/src/objects/objects.cc`. This is the third part of a four-part file.

My plan is to:
1. **Identify key classes and functionalities** within this code snippet.
2. **Describe the purpose** of these classes and functions.
3. **Find relationships to JavaScript concepts** and illustrate them with examples. Since this is part 3, I should focus on the concepts present in this specific section.

Looking at the code, I see:
- **`JSProxy`**: Functions related to proxy object behavior (e.g., `GetOwnPropertyDescriptor`, `PreventExtensions`, `IsExtensible`, `SetPrototype`).
- **`DescriptorArray`**: Functions for manipulating descriptor arrays (e.g., `CopyUpTo`, `Allocate`, `Initialize`, `Sort`).
- **`PrototypeUsers`**:  Functions for managing weak lists of prototype users (e.g., `Add`, `ScanForEmptySlots`, `Compact`).
- **`AccessorPair`**: Functions for working with getter/setter pairs (e.g., `Copy`, `GetComponent`).
- **`Name`**: Functions related to names (e.g., `ToFunctionName`).
- **`Relocatable`**:  Functions related to managing relocatable objects during garbage collection.
- **Helper functions**:  `WriteFixedArrayToFlat` for string concatenation.
- **`JSArray`**: Functions related to arrays (e.g., `ArrayJoinConcatToSequentialString`, `Initialize`, `SetLength`, `SetLengthWouldNormalize`, `HasReadOnlyLength`, `WouldChangeReadOnlyLength`).
- **`AllocationSite`**: Functions for tracking object allocation (e.g., `ResetPretenureDecision`, `GetAllocationType`, `IsNested`, `ShouldTrack`).
- **`Symbol`**: Functions related to symbols (e.g., `PrivateSymbolToName`).
- **`JSPromise`**: Functions related to promises (e.g., `status`, `set_status`, `Fulfill`, `Reject`, `Resolve`, `TriggerPromiseReactions`).
- **`Script`**: Functions related to script objects (e.g., `GetEvalPosition`, `GetLineEnds`, `SetSource`, `GetPositionInfo`, `GetScriptHash`, `FindSharedFunctionInfo`).

Now I can start summarizing the functionalities and connecting them to JavaScript.
这是文件 `v8/src/objects/objects.cc` 的第三部分，主要关注以下 V8 内部对象的功能实现，并涉及它们与 JavaScript 功能的关联：

**主要功能归纳：**

1. **`JSProxy` (JavaScript 代理对象):**  这部分代码实现了 `JSProxy` 对象的关键内部方法，这些方法对应了 JavaScript 中 `Proxy` 对象的陷阱 (traps)。具体包括：
    - **`GetOwnPropertyDescriptor`**:  模拟 `Object.getOwnPropertyDescriptor()`  的行为，允许代理拦截对目标对象属性描述符的获取。
    - **`PreventExtensions`**: 模拟 `Object.preventExtensions()` 的行为，允许代理拦截阻止目标对象扩展的操作。
    - **`IsExtensible`**: 模拟 `Object.isExtensible()` 的行为，允许代理拦截检查目标对象是否可扩展的操作。
    - **`SetPrototype`**: 模拟 `Object.setPrototypeOf()` 的行为，允许代理拦截设置目标对象原型链的操作。

2. **`DescriptorArray` (描述符数组):** 这部分代码提供了管理对象属性描述符的数组的各种操作，这些描述符存储了关于对象属性的信息（例如，属性名称、值、特性等）。功能包括：
    - **复制和添加属性**:  创建新的描述符数组，并可以在复制过程中添加或修改属性。
    - **分配**:  为描述符数组分配内存。
    - **初始化**:  设置描述符数组的初始状态。
    - **排序**:  对描述符数组中的描述符进行排序，这在优化属性查找方面很重要。

3. **`PrototypeUsers` (原型使用者列表):**  这段代码实现了用于跟踪哪些 `Map` 对象（用于对象结构和属性查找）共享特定原型的机制。这对于原型链的更改和垃圾回收至关重要。功能包括：
    - **添加使用者**:  向原型的使用者列表中添加新的 `Map`。
    - **扫描空槽**:  在垃圾回收后查找已清除的弱引用。
    - **压缩**:  创建一个新的、更紧凑的使用者列表，移除已清除的引用。

4. **`AccessorPair` (访问器对):**  这部分代码处理 getter 和 setter 函数对。功能包括：
    - **复制**:  创建一个新的 `AccessorPair` 对象。
    - **获取组件**:  获取 getter 或 setter 函数。如果存储的是 `FunctionTemplateInfo`，则会进行实例化。

5. **`Name` (名称):** 提供将内部名称对象转换为可读函数名称的功能。

6. **`Relocatable` (可重定位对象):**  这部分代码涉及在垃圾回收期间处理需要特殊处理的对象（例如，包含指向堆中其他对象的指针）。

7. **字符串连接优化:** 提供了优化的方法 `WriteFixedArrayToFlat`，用于将存储在 `FixedArray` 中的字符串和分隔符高效地连接成一个连续的字符串。`JSArray::ArrayJoinConcatToSequentialString` 使用了这个方法。

8. **`JSArray` (JavaScript 数组对象):**  这部分代码实现了 `JSArray` 对象的一些关键操作：
    - **`Initialize`**: 初始化数组的存储空间。
    - **`SetLength`**: 设置数组的 `length` 属性。
    - **`SetLengthWouldNormalize`**:  检查设置新的 `length` 是否会导致数组的存储方式从快速模式（例如，连续存储）转变为慢速模式（例如，字典模式）。
    - **`HasReadOnlyLength`**: 检查数组的 `length` 属性是否为只读。
    - **`WouldChangeReadOnlyLength`**: 检查修改指定索引是否会影响只读的 `length` 属性。

9. **`AllocationSite` (分配点):**  这部分代码用于跟踪对象的分配情况，以便 V8 可以进行性能优化，例如对象预分配。

10. **`Symbol` (符号):** 提供了将内部私有符号转换为名称的功能。

11. **`JSPromise` (JavaScript Promise 对象):**  这部分代码实现了 Promise 的核心状态管理和生命周期操作：
    - **`status` 和 `set_status`**: 获取和设置 Promise 的状态（pending, fulfilled, rejected）。
    - **`Fulfill`**:  将 Promise 标记为已成功，并执行相应的处理程序。
    - **`Reject`**: 将 Promise 标记为已失败，并执行相应的处理程序。
    - **`Resolve`**:  尝试解析 Promise，这可能涉及递归地处理其他 Promise 或 thenable 对象。
    - **`TriggerPromiseReactions`**:  触发与 Promise 状态变化相关的处理程序。

12. **`Script` (脚本对象):**  这部分代码提供了与 JavaScript 脚本相关的操作：
    - **`GetEvalPosition`**: 获取 `eval()` 调用在源代码中的位置。
    - **`GetLineEnds`**:  计算脚本中行尾的位置，用于源代码位置映射。
    - **`SetSource`**:  设置脚本的源代码。
    - **`GetPositionInfo`**:  根据源代码中的字符偏移量获取行号和列号信息。
    - **`GetScriptHash`**:  计算脚本内容的哈希值。
    - **`FindSharedFunctionInfo`**:  根据函数字面量查找共享的函数信息对象。

**与 JavaScript 功能的关系及示例：**

**1. `JSProxy`:**

```javascript
const target = {};
const handler = {
  getOwnPropertyDescriptor(target, prop) {
    console.log(`Getting description for property: ${prop.toString()}`);
    return Object.getOwnPropertyDescriptor(target, prop);
  },
  preventExtensions(target) {
    console.log('Preventing extensions');
    Object.preventExtensions(target);
    return true;
  },
  isExtensible(target) {
    console.log('Checking if extensible');
    return Object.isExtensible(target);
  },
  setPrototypeOf(target, prototype) {
    console.log('Setting prototype');
    Object.setPrototypeOf(target, prototype);
    return true;
  }
};
const proxy = new Proxy(target, handler);
Object.getOwnPropertyDescriptor(proxy, 'foo'); // 输出 "Getting description for property: foo"
Object.preventExtensions(proxy); // 输出 "Preventing extensions"
Object.isExtensible(proxy); // 输出 "Checking if extensible"
Object.setPrototypeOf(proxy, null); // 输出 "Setting prototype"
```

**2. `JSArray` (字符串连接优化):**

```javascript
const arr = ['a', 'b', 'c'];
const str = arr.join('-'); // V8 内部可能会使用优化的字符串连接方法
console.log(str); // 输出 "a-b-c"
```

**3. `JSArray` (设置 `length`):**

```javascript
const arr = [1, 2, 3, 4, 5];
arr.length = 3; // V8 内部会调用相应的 C++ 方法来调整数组大小
console.log(arr); // 输出 [1, 2, 3]
```

**4. `JSPromise`:**

```javascript
const promise = new Promise((resolve, reject) => {
  setTimeout(() => {
    resolve('Success!');
  }, 1000);
});

promise.then((value) => {
  console.log(value); // 1秒后输出 "Success!"
});
```

**5. `Script` (错误堆栈信息):**

当 JavaScript 代码发生错误时，V8 会使用 `Script` 对象中的信息（如行尾位置）来生成准确的错误堆栈信息，显示错误发生的行号和列号。

**总结:**

这部分 `objects.cc` 文件主要实现了 V8 引擎中一些核心对象和功能的底层逻辑，直接关系到 JavaScript 中 `Proxy`、数组操作、字符串连接优化、Promise 的状态管理以及脚本的元数据信息处理。理解这部分代码有助于深入了解 V8 引擎如何执行和优化 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/objects/objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
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
      isolate->factory()->InternalizeUtf8String(to_string);
  DirectHandle<String> internalized_type_of =
      isolate->factory()->InternalizeUtf8String(type_of);
  if (IsHeapNumber(*to_number)) {
    oddball->set_to_number_raw_as_bits(
        Cast<HeapNumber>(to_number)->value_as_bits());
  } else {
    oddball->set_to_number_raw(Object::NumberValue(*to_number));
  }
  oddball->set_to_number(*to_number);
  oddball->set_to_string(*internalized_to_string);
  oddball->set_type_of(*internalized_type_of);
  oddball->set_kind(kind);
}

// static
int Script::GetEvalPosition(Isolate* isolate, DirectHandle<Script> script) {
  DCHECK(script->compilation_type() == Script::CompilationType::kEval);
  int position = script->eval_from_position();
  if (position < 0) {
    // Due to laziness, the position may not have been translated from code
    // offset yet, which would be encoded as negative integer. In that case,
    // translate and set the position.
    if (!script->has_eval_from_shared()) {
      position = 0;
    } else {
      Handle<SharedFunctionInfo> shared =
          handle(script->eval_from_shared(), isolate);
      SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate, shared);
      position =
          shared->abstract_code(isolate)->SourcePosition(isolate, -position);
    }
    DCHECK_GE(position, 0);
    script->set_eval_from_position(position);
  }
  return position;
}

String::LineEndsVector Script::GetLineEnds(Isolate* isolate,
                                           DirectHandle<Script> script) {
  DCHECK(!script->has_line_ends());
  Tagged<Object> src_obj = script->source();
  if (IsString(src_obj)) {
    Handle<String> src(Cast<String>(src_obj), isolate);
    return String::CalculateLineEndsVector(isolate, src, true);
  }

  return String::LineEndsVector();
}

template <typename IsolateT>
// static
void Script::InitLineEndsInternal(IsolateT* isolate,
                                  DirectHandle<Script> script) {
  DCHECK(!script->has_line_ends());
  DCHECK(script->CanHaveLineEnds());
  Tagged<Object> src_obj = script->source();
  if (!IsString(src_obj)) {
    DCHECK(IsUndefined(src_obj, isolate));
    script->set_line_ends(ReadOnlyRoots(isolate).empty_fixed_array());
  } else {
    DCHECK(IsString(src_obj));
    Handle<String> src(Cast<String>(src_obj), isolate);
    DirectHandle<FixedArray> array =
        String::CalculateLineEnds(isolate, src, true);
    script->set_line_ends(*array);
  }
  DCHECK(IsFixedArray(script->line_ends()));
  DCHECK(script->has_line_ends());
}

void Script::SetSource(Isolate* isolate, DirectHandle<Script> script,
                       DirectHandle<String> source) {
  script->set_source(*source);
  if (isolate->NeedsSourcePositions()) {
    InitLineEnds(isolate, script);
  } else if (script->line_ends() ==
             ReadOnlyRoots(isolate).empty_fixed_array()) {
    DCHECK(script->has_line_ends());
    script->set_line_ends(Smi::zero());
    DCHECK(!script->has_line_ends());
  }
}

template EXPORT_TEMPLATE_DEFINE(
    V8_EXPORT_PRIVATE) void Script::InitLineEndsInternal(Isolate* isolate,
                                                         DirectHandle<Script>
                                                             script);
template EXPORT_TEMPLATE_DEFINE(
    V8_EXPORT_PRIVATE) void Script::InitLineEndsInternal(LocalIsolate* isolate,
                                                         DirectHandle<Script>
                                                             script);

bool Script::GetPositionInfo(DirectHandle<Script> script, int position,
                             PositionInfo* info, OffsetFlag offset_flag) {
#if V8_ENABLE_WEBASSEMBLY
  // For wasm, we do not create an artificial line_ends array, but do the
  // translation directly.
#ifdef DEBUG
  if (script->type() == Type::kWasm) {
    DCHECK(script->has_line_ends());
    DCHECK_EQ(Cast<FixedArray>(script->line_ends())->length(), 0);
  }
#endif  // DEBUG
#endif  // V8_ENABLE_WEBASSEMBLY
  InitLineEnds(script->GetIsolate(), script);
  return script->GetPositionInfo(position, info, offset_flag);
}

bool Script::IsSubjectToDebugging() const {
  switch (type()) {
    case Type::kNormal:
#if V8_ENABLE_WEBASSEMBLY
    case Type::kWasm:
#endif  // V8_ENABLE_WEBASSEMBLY
      return true;
    case Type::kNative:
    case Type::kInspector:
    case Type::kExtension:
      return false;
  }
  UNREACHABLE();
}

bool Script::IsUserJavaScript() const {
  return type() == Script::Type::kNormal;
}

#if V8_ENABLE_WEBASSEMBLY
bool Script::ContainsAsmModule() {
  DisallowGarbageCollection no_gc;
  SharedFunctionInfo::ScriptIterator iter(this->GetIsolate(), *this);
  for (Tagged<SharedFunctionInfo> sfi = iter.Next(); !sfi.is_null();
       sfi = iter.Next()) {
    if (sfi->HasAsmWasmData()) return true;
  }
  return false;
}
#endif  // V8_ENABLE_WEBASSEMBLY

namespace {

template <typename Char>
bool GetPositionInfoSlowImpl(base::Vector<Char> source, int position,
                             Script::PositionInfo* info) {
  DCHECK(DisallowPositionInfoSlow::IsAllowed());
  if (position < 0) {
    position = 0;
  }
  int line = 0;
  const auto begin = std::cbegin(source);
  const auto end = std::cend(source);
  for (auto line_begin = begin; line_begin < end;) {
    const auto line_end = std::find(line_begin, end, '\n');
    if (position <= (line_end - begin)) {
      info->line = line;
      info->column = static_cast<int>((begin + position) - line_begin);
      info->line_start = static_cast<int>(line_begin - begin);
      info->line_end = static_cast<int>(line_end - begin);
      return true;
    }
    ++line;
    line_begin = line_end + 1;
  }
  return false;
}
bool GetPositionInfoSlow(const Tagged<Script> script, int position,
                         const DisallowGarbageCollection& no_gc,
                         Script::PositionInfo* info) {
  if (!IsString(script->source())) {
    return false;
  }
  auto source = Cast<String>(script->source());
  const auto flat = source->GetFlatContent(no_gc);
  return flat.IsOneByte()
             ? GetPositionInfoSlowImpl(flat.ToOneByteVector(), position, info)
             : GetPositionInfoSlowImpl(flat.ToUC16Vector(), position, info);
}

int GetLineEnd(const String::LineEndsVector& vector, int line) {
  return vector[line];
}

int GetLineEnd(const Tagged<FixedArray>& array, int line) {
  return Smi::ToInt(array->get(line));
}

int GetLength(const String::LineEndsVector& vector) {
  return static_cast<int>(vector.size());
}

int GetLength(const Tagged<FixedArray>& array) { return array->length(); }

template <typename LineEndsContainer>
bool GetLineEndsContainerPositionInfo(const LineEndsContainer& ends,
                                      int position, Script::PositionInfo* info,
                                      const DisallowGarbageCollection& no_gc) {
  const int ends_len = GetLength(ends);
  if (ends_len == 0) return false;

  // Return early on invalid positions. Negative positions behave as if 0 was
  // passed, and positions beyond the end of the script return as failure.
  if (position < 0) {
    position = 0;
  } else if (position > GetLineEnd(ends, ends_len - 1)) {
    return false;
  }

  // Determine line number by doing a binary search on the line ends array.
  if (GetLineEnd(ends, 0) >= position) {
    info->line = 0;
    info->line_start = 0;
    info->column = position;
  } else {
    int left = 0;
    int right = ends_len - 1;

    while (right > 0) {
      DCHECK_LE(left, right);
      const int mid = left + (right - left) / 2;
      if (position > GetLineEnd(ends, mid)) {
        left = mid + 1;
      } else if (position <= GetLineEnd(ends, mid - 1)) {
        right = mid - 1;
      } else {
        info->line = mid;
        break;
      }
    }
    DCHECK(GetLineEnd(ends, info->line) >= position &&
           GetLineEnd(ends, info->line - 1) < position);
    info->line_start = GetLineEnd(ends, info->line - 1) + 1;
    info->column = position - info->line_start;
  }

  return true;
}

}  // namespace

void Script::AddPositionInfoOffset(PositionInfo* info,
                                   OffsetFlag offset_flag) const {
  // Add offsets if requested.
  if (offset_flag == OffsetFlag::kWithOffset) {
    if (info->line == 0) {
      info->column += column_offset();
    }
    info->line += line_offset();
  } else {
    DCHECK_EQ(offset_flag, OffsetFlag::kNoOffset);
  }
}

template <typename LineEndsContainer>
bool Script::GetPositionInfoInternal(
    const LineEndsContainer& ends, int position, Script::PositionInfo* info,
    const DisallowGarbageCollection& no_gc) const {
  if (!GetLineEndsContainerPositionInfo(ends, position, info, no_gc))
    return false;

  // Line end is position of the linebreak character.
  info->line_end = GetLineEnd(ends, info->line);
  if (info->line_end > 0) {
    DCHECK(IsString(source()));
    Tagged<String> src = Cast<String>(source());
    if (src->length() >= static_cast<uint32_t>(info->line_end) &&
        src->Get(info->line_end - 1) == '\r') {
      info->line_end--;
    }
  }

  return true;
}

template bool Script::GetPositionInfoInternal<String::LineEndsVector>(
    const String::LineEndsVector& ends, int position,
    Script::PositionInfo* info, const DisallowGarbageCollection& no_gc) const;
template bool Script::GetPositionInfoInternal<Tagged<FixedArray>>(
    const Tagged<FixedArray>& ends, int position, Script::PositionInfo* info,
    const DisallowGarbageCollection& no_gc) const;

bool Script::GetPositionInfo(int position, PositionInfo* info,
                             OffsetFlag offset_flag) const {
  DisallowGarbageCollection no_gc;

#if V8_ENABLE_WEBASSEMBLY
  // For wasm, we use the byte offset as the column.
  if (type() == Script::Type::kWasm) {
    DCHECK_LE(0, position);
    wasm::NativeModule* native_module = wasm_native_module();
    const wasm::WasmModule* module = native_module->module();
    if (module->functions.empty()) return false;
    info->line = 0;
    info->column = position;
    info->line_start = module->functions[0].code.offset();
    info->line_end = module->functions.back().code.end_offset();
    return true;
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  if (!has_line_ends()) {
    // Slow mode: we do not have line_ends. We have to iterate through source.
    if (!GetPositionInfoSlow(*this, position, no_gc, info)) {
      return false;
    }
  } else {
    DCHECK(has_line_ends());
    Tagged<FixedArray> ends = Cast<FixedArray>(line_ends());

    if (!GetPositionInfoInternal(ends, position, info, no_gc)) return false;
  }

  AddPositionInfoOffset(info, offset_flag);

  return true;
}

bool Script::GetPositionInfoWithLineEnds(
    int position, PositionInfo* info, const String::LineEndsVector& line_ends,
    OffsetFlag offset_flag) const {
  DisallowGarbageCollection no_gc;
  if (!GetPositionInfoInternal(line_ends, position, info, no_gc)) return false;

  AddPositionInfoOffset(info, offset_flag);

  return true;
}

bool Script::GetLineColumnWithLineEnds(
    int position, int& line, int& column,
    const String::LineEndsVector& line_ends) {
  DisallowGarbageCollection no_gc;
  PositionInfo info;
  if (!GetLineEndsContainerPositionInfo(line_ends, position, &info, no_gc)) {
    line = -1;
    column = -1;
    return false;
  }

  line = info.line;
  column = info.column;

  return true;
}

int Script::GetColumnNumber(DirectHandle<Script> script, int code_pos) {
  PositionInfo info;
  GetPositionInfo(script, code_pos, &info);
  return info.column;
}

int Script::GetColumnNumber(int code_pos) const {
  PositionInfo info;
  GetPositionInfo(code_pos, &info);
  return info.column;
}

int Script::GetLineNumber(DirectHandle<Script> script, int code_pos) {
  PositionInfo info;
  GetPositionInfo(script, code_pos, &info);
  return info.line;
}

int Script::GetLineNumber(int code_pos) const {
  PositionInfo info;
  GetPositionInfo(code_pos, &info);
  return info.line;
}

Tagged<Object> Script::GetNameOrSourceURL() {
  // Keep in sync with ScriptNameOrSourceURL in messages.js.
  if (!IsUndefined(source_url())) return source_url();
  return name();
}

// static
Handle<String> Script::GetScriptHash(Isolate* isolate,
                                     DirectHandle<Script> script,
                                     bool forceForInspector) {
  if (script->origin_options().IsOpaque() && !forceForInspector) {
    return isolate->factory()->empty_string();
  }

  PtrComprCageBase cage_base(isolate);
  {
    Tagged<Object> maybe_source_hash = script->source_hash(cage_base);
    if (IsString(maybe_source_hash, cage_base)) {
      Handle<String> precomputed(Cast<String>(maybe_source_hash), isolate);
      if (precomputed->length() > 0) {
        return precomputed;
      }
    }
  }

  DirectHandle<String> src_text;
  {
    Tagged<Object> maybe_script_source = script->source(cage_base);

    if (!IsString(maybe_script_source, cage_base)) {
      return isolate->factory()->empty_string();
    }
    src_text = direct_handle(Cast<String>(maybe_script_source), isolate);
  }

  char formatted_hash[kSizeOfFormattedSha256Digest];

  std::unique_ptr<char[]> string_val = src_text->ToCString();
  size_t len = strlen(string_val.get());
  uint8_t hash[kSizeOfSha256Digest];
  SHA256_hash(string_val.get(), len, hash);
  FormatBytesToHex(formatted_hash, kSizeOfFormattedSha256Digest, hash,
                   kSizeOfSha256Digest);
  formatted_hash[kSizeOfSha256Digest * 2] = '\0';

  Handle<String> result =
      isolate->factory()->NewStringFromAsciiChecked(formatted_hash);
  script->set_source_hash(*result);
  return result;
}

template <typename IsolateT>
MaybeHandle<SharedFunctionInfo> Script::FindSharedFunctionInfo(
    DirectHandle<Script> script, IsolateT* isolate,
    FunctionLiteral* function_literal) {
  DCHECK(function_literal->shared_function_info().is_null());
  int function_literal_id = function_literal->function_literal_id();
  CHECK_NE(function_literal_id, kInvalidInfoId);
  // If this check fails, the problem is most probably the function id
  // renumbering done by AstFunctionLiteralIdReindexer; in particular, that
  // AstTraversalVisitor doesn't recurse properly in the construct which
  // triggers the mismatch.
  CHECK_LT(function_literal_id, script->infos()->length());
  Tagged<MaybeObject> shared = script->infos()->get(function_literal_id);
  Tagged<HeapObject> heap_object;
  if (!shared.GetHeapObject(&heap_object) ||
      IsUndefined(heap_object, isolate)) {
    return MaybeHandle<SharedFunctionInfo>();
  }
  Handle<SharedFunctionInfo> result(Cast<SharedFunctionInfo>(heap_object),
                                    isolate);
  function_literal->set_shared_function_info(result);
  return result;
}
template MaybeHandle<SharedFunctionInfo> Script::FindSharedFunctionInfo(
    DirectHandle<Script> script, Isolate* isolate,
    FunctionLiteral* function_literal);
template MaybeHandle<SharedFunctionInfo> Script::FindSharedFunctionInfo(
    DirectHandle<Script> script, LocalIsolate* isolate,
    FunctionLiteral* function_literal);

Script::Iterator::Iterator(Isolate* isolate)
    : iterator_(isolate->heap()->script_list()) {}

Tagged<Script> Script::Iterator::Next() {
  Tagged<Object> o = iterator_.Next();
  if (o != Tagged<Object>()) {
    return Cast<Script>(o);
  }
  return Script();
}

// static
void JSArray::Initialize(DirectHandle<JSArray> array, int capacity,
                         int length) {
  DCHECK_GE(capacity, 0);
  array->GetIsolate()->factory()->NewJSArrayStorage(
      array, length, capacity,
      ArrayStorageAllocationMode::INITIALIZE_ARRAY_ELEMENTS_WITH_HOLE);
}

Maybe<bool> JSArray::SetLength(Handle<JSArray> array, uint32_t new_length) {
  if (array->SetLengthWouldNormalize(new_length)) {
    JSObject::NormalizeElements(array);
  }
  return array->GetElementsAccessor()->SetLength(array, new_length);
}

// ES6: 9.5.2 [[SetPrototypeOf]] (V)
// static
Maybe<bool> JSProxy::SetPrototype(Isolate* isolate, DirectHandle<JSProxy> proxy,
                                  Handle<Object> value, bool from_javascript,
                                  ShouldThrow should_throw) {
  STACK_CHECK(isolate, Nothing<bool>());
  Handle<Name> trap_name = isolate->factory()->setPrototypeOf_string();
  // 1. Assert: Either Type(V) is Object or Type(V) is Null.
  DCHECK(IsJSReceiver(*value) || IsNull(*value, isolate));
  // 2. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  Handle<Object> handler(proxy->handler(), isolate);
  // 3. If handler is null, throw a TypeError exception.
  // 4. Assert: Type(handler) is Object.
  if (proxy->IsRevoked()) {
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kProxyRevoked, trap_name));
    return Nothing<bool>();
  }
  // 5. Let target be the value of the [[ProxyTarget]] internal slot.
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  // 6. Let trap be ? GetMethod(handler, "getPrototypeOf").
  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap,
      Object::GetMethod(isolate, Cast<JSReceiver>(handler), trap_name),
      Nothing<bool>());
  // 7. If trap is undefined, then return target.[[SetPrototypeOf]]().
  if (IsUndefined(*trap, isolate)) {
    return JSReceiver::SetPrototype(isolate, target, value, from_javascript,
                                    should_throw);
  }
  // 8. Let booleanTrapResult be ToBoolean(? Call(trap, handler, «target, V»)).
  Handle<Object> argv[] = {target, value};
  Handle<Object> trap_result;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap_result,
      Execution::Call(isolate, trap, handler, arraysize(argv), argv),
      Nothing<bool>());
  bool bool_trap_result = Object::BooleanValue(*trap_result, isolate);
  // 9. If booleanTrapResult is false, return false.
  if (!bool_trap_result) {
    RETURN_FAILURE(
        isolate, should_throw,
        NewTypeError(MessageTemplate::kProxyTrapReturnedFalsish, trap_name));
  }
  // 10. Let extensibleTarget be ? IsExtensible(target).
  Maybe<bool> is_extensible = JSReceiver::IsExtensible(isolate, target);
  if (is_extensible.IsNothing()) return Nothing<bool>();
  // 11. If extensibleTarget is true, return true.
  if (is_extensible.FromJust()) {
    if (bool_trap_result) return Just(true);
    RETURN_FAILURE(
        isolate, should_throw,
        NewTypeError(MessageTemplate::kProxyTrapReturnedFalsish, trap_name));
  }
  // 12. Let targetProto be ? target.[[GetPrototypeOf]]().
  Handle<Object> target_proto;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, target_proto,
                                   JSReceiver::GetPrototype(isolate, target),
                                   Nothing<bool>());
  // 13. If SameValue(V, targetProto) is false, throw a TypeError exception.
  if (bool_trap_result && !Object::SameValue(*value, *target_proto)) {
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kProxySetPrototypeOfNonExtensible));
    return Nothing<bool>();
  }
  // 14. Return true.
  return Just(true);
}

bool JSArray::SetLengthWouldNormalize(uint32_t new_length) {
  if (!HasFastElements()) return false;
  uint32_t capacity = static_cast<uint32_t>(elements()->length());
  uint32_t new_capacity;
  return JSArray::SetLengthWouldNormalize(GetHeap(), new_length) &&
         ShouldConvertToSlowElements(*this, capacity, new_length - 1,
                                     &new_capacity);
}

void AllocationSite::ResetPretenureDecision() {
  set_pretenure_decision(kUndecided);
  set_memento_found_count(0);
  set_memento_create_count(0);
}

AllocationType AllocationSite::GetAllocationType() const {
  PretenureDecision mode = pretenure_decision();
  // Zombie objects "decide" to be untenured.
  return mode == kTenure ? AllocationType::kOld : AllocationType::kYoung;
}

bool AllocationSite::IsNested() {
  DCHECK(v8_flags.trace_track_allocation_sites);
  Tagged<Object> current = boilerplate()->GetHeap()->allocation_sites_list();
  while (IsAllocationSite(current)) {
    Tagged<AllocationSite> current_site = Cast<AllocationSite>(current);
    if (current_site->nested_site() == *this) {
      return true;
    }
    current = current_site->weak_next();
  }
  return false;
}

bool AllocationSite::ShouldTrack(ElementsKind from, ElementsKind to) {
  if (!V8_ALLOCATION_SITE_TRACKING_BOOL) return false;
  return IsMoreGeneralElementsKindTransition(from, to);
}

const char* AllocationSite::PretenureDecisionName(PretenureDecision decision) {
  switch (decision) {
    case kUndecided:
      return "undecided";
    case kDontTenure:
      return "don't tenure";
    case kMaybeTenure:
      return "maybe tenure";
    case kTenure:
      return "tenure";
    case kZombie:
      return "zombie";
    default:
      UNREACHABLE();
  }
}

// static
bool JSArray::MayHaveReadOnlyLength(Tagged<Map> js_array_map) {
  DCHECK(IsJSArrayMap(js_array_map));
  if (js_array_map->is_dictionary_map()) return true;

  // Fast path: "length" is the first fast property of arrays with non
  // dictionary properties. Since it's not configurable, it's guaranteed to be
  // the first in the descriptor array.
  InternalIndex first(0);
  DCHECK(js_array_map->instance_descriptors()->GetKey(first) ==
         js_array_map->GetReadOnlyRoots().length_string());
  return js_array_map->instance_descriptors()->GetDetails(first).IsReadOnly();
}

bool JSArray::HasReadOnlyLength(Handle<JSArray> array) {
  Tagged<Map> map = array->map();

  // If map guarantees that there can't be a read-only length, we are done.
  if (!MayHaveReadOnlyLength(map)) return false;

  // Look at the object.
  Isolate* isolate = array->GetIsolate();
  LookupIterator it(isolate, array, isolate->factory()->length_string(), array,
                    LookupIterator::OWN_SKIP_INTERCEPTOR);
  CHECK_EQ(LookupIterator::ACCESSOR, it.state());
  return it.IsReadOnly();
}

bool JSArray::WouldChangeReadOnlyLength(Handle<JSArray> array, uint32_t index) {
  uint32_t length = 0;
  CHECK(Object::ToArrayLength(array->length(), &length));
  if (length <= index) return HasReadOnlyLength(array);
  return false;
}

const char* Symbol::PrivateSymbolToName() const {
  ReadOnlyRoots roots = GetReadOnlyRoots();
#define SYMBOL_CHECK_AND_PRINT(_, name) \
  if (this == roots.name()) return #name;
  PRIVATE_SYMBOL_LIST_GENERATOR(SYMBOL_CHECK_AND_PRINT, /* not used */)
#undef SYMBOL_CHECK_AND_PRINT
  return "UNKNOWN";
}

v8::Promise::PromiseState JSPromise::status() const {
  int value = flags() & StatusBits::kMask;
  DCHECK(value == 0 || value == 1 || value == 2);
  return static_cast<v8::Promise::PromiseState>(value);
}

void JSPromise::set_status(Promise::PromiseState status) {
  int value = flags() & ~StatusBits::kMask;
  set_flags(value | status);
}

// static
const char* JSPromise::Status(v8::Promise::PromiseState status) {
  switch (status) {
    case v8::Promise::kFulfilled:
      return "fulfilled";
    case v8::Promise::kPending:
      return "pending";
    case v8::Promise::kRejected:
      return "rejected";
  }
  UNREACHABLE();
}

// static
Handle<Object> JSPromise::Fulfill(DirectHandle<JSPromise> promise,
                                  DirectHandle<Object> value) {
  Isolate* const isolate = promise->GetIsolate();

#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  if (isolate->HasContextPromiseHooks()) {
    isolate->raw_native_context()->RunPromiseHook(
        PromiseHookType::kResolve, indirect_handle(promise, isolate),
        isolate->factory()->undefined_value());
  }
#endif

  // 1. Assert: The value of promise.[[PromiseState]] is "pending".
  CHECK_EQ(Promise::kPending, promise->status());

  // 2. Let reactions be promise.[[PromiseFulfillReactions]].
  DirectHandle<Object> reactions(promise->reactions(), isolate);

  // 3. Set promise.[[PromiseResult]] to value.
  // 4. Set promise.[[PromiseFulfillReactions]] to undefined.
  // 5. Set promise.[[PromiseRejectReactions]] to undefined.
  promise->set_reactions_or_result(Cast<JSAny>(*value));

  // 6. Set promise.[[PromiseState]] to "fulfilled".
  promise->set_status(Promise::kFulfilled);

  // 7. Return TriggerPromiseReactions(reactions, value).
  return TriggerPromiseReactions(isolate, reactions, value,
                                 PromiseReaction::kFulfill);
}

static void MoveMessageToPromise(Isolate* isolate, Handle<JSPromise> promise) {
  if (!isolate->has_pending_message()) return;

  if (isolate->debug()->is_active()) {
    Handle<Object> message = handle(isolate->pending_message(), isolate);
    Handle<Symbol> key = isolate->factory()->promise_debug_message_symbol();
    Object::SetProperty(isolate, promise, key, message,
                        StoreOrigin::kMaybeKeyed,
                        Just(ShouldThrow::kThrowOnError))
        .Assert();
  }

  // The message object for a rejected promise was only stored for this purpose.
  // Clear it, otherwise we might leak memory.
  isolate->clear_pending_message();
}

// static
Handle<Object> JSPromise::Reject(Handle<JSPromise> promise,
                                 Handle<Object> reason, bool debug_event) {
  Isolate* const isolate = promise->GetIsolate();
  DCHECK(
      !reinterpret_cast<v8::Isolate*>(isolate)->GetCurrentContext().IsEmpty());

  MoveMessageToPromise(isolate, promise);

  if (debug_event) isolate->debug()->OnPromiseReject(promise, reason);
  isolate->RunAllPromiseHooks(PromiseHookType::kResolve, promise,
                              isolate->factory()->undefined_value());

  // 1. Assert: The value of promise.[[PromiseState]] is "pending".
  CHECK_EQ(Promise::kPending, promise->status());

  // 2. Let reactions be promise.[[PromiseRejectReactions]].
  DirectHandle<Object> reactions(promise->reactions(), isolate);

  // 3. Set promise.[[PromiseResult]] to reason.
  // 4. Set promise.[[PromiseFulfillReactions]] to undefined.
  // 5. Set promise.[[PromiseRejectReactions]] to undefined.
  promise->set_reactions_or_result(Cast<JSAny>(*reason));

  // 6. Set promise.[[PromiseState]] to "rejected".
  promise->set_status(Promise::kRejected);

  // 7. If promise.[[PromiseIsHandled]] is false, perform
  //    HostPromiseRejectionTracker(promise, "reject").
  if (!promise->has_handler()) {
    isolate->ReportPromiseReject(promise, reason, kPromiseRejectWithNoHandler);
  }

  // 8. Return TriggerPromiseReactions(reactions, reason).
  return TriggerPromiseReactions(isolate, reactions, reason,
                                 PromiseReaction::kReject);
}

// https://tc39.es/ecma262/#sec-promise-resolve-functions
// static
MaybeHandle<Object> JSPromise::Resolve(Handle<JSPromise> promise,
                                       Handle<Object> resolution_obj) {
  Isolate* const isolate = promise->GetIsolate();
  DCHECK(
      !reinterpret_cast<v8::Isolate*>(isolate)->GetCurrentContext().IsEmpty());

  isolate->RunPromiseHook(PromiseHookType::kResolve, promise,
                          isolate->factory()->undefined_value());

  // 7. If SameValue(resolution, promise) is true, then
  if (promise.is_identical_to(resolution_obj)) {
    // a. Let selfResolutionError be a newly created TypeError object.
    Handle<Object> self_resolution_error = isolate->factory()->NewTypeError(
        MessageTemplate::kPromiseCyclic, resolution_obj);
    // b. Return RejectPromise(promise, selfResolutionError).
    return Reject(promise, self_resolution_error);
  }

  // 8. If Type(resolution) is not Object, then
  Handle<JSReceiver> resolution_recv;
  if (!TryCast<JSReceiver>(resolution_obj, &resolution_recv)) {
    // a. Return FulfillPromise(promise, resolution).
    return Fulfill(promise, resolution_obj);
  }

  // 9. Let then be Get(resolution, "then").
  MaybeHandle<Object> then;

  // Make sure a lookup of "then" on any JSPromise whose [[Prototype]] is the
  // initial %PromisePrototype% yields the initial method. In addition this
  // protector also guards the negative lookup of "then" on the intrinsic
  // %ObjectPrototype%, meaning that such lookups are guaranteed to yield
  // undefined without triggering any side-effects.
  if (IsJSPromise(*resolution_recv) &&
      resolution_recv->map()->prototype()->map()->instance_type() ==
          JS_PROMISE_PROTOTYPE_TYPE &&
      Protectors::IsPromiseThenLookupChainIntact(isolate)) {
    // We can skip the "then" lookup on {resolution} if its [[Prototype]]
    // is the (initial) Promise.prototype and the Promise#then protector
    // is intact, as that guards the lookup path for the "then" property
    // on JSPromise instances which have the (initial) %PromisePrototype%.
    then = isolate->promise_then();
  } else {
    then = JSReceiver::GetProperty(isolate, resolution_recv,
                                   isolate->factory()->then_string());
  }

  // 10. If then is an abrupt completion, then
  Handle<Object> then_action;
  if (!then.ToHandle(&then_action)) {
    // The "then" lookup can cause termination.
    if (!isolate->is_catchable_by_javascript(isolate->exception())) {
      return kNullMaybeHandle;
    }

    // a. Return RejectPromise(promise, then.[[Value]]).
    Handle<Object> reason(isolate->exception(), isolate);
    isolate->clear_exception();
    return Reject(promise, reason, false);
  }

  // 11. Let thenAction be then.[[Value]].
  // 12. If IsCallable(thenAction) is false, then
  if (!IsCallable(*then_action)) {
    // a. Return FulfillPromise(promise, resolution).
    return Fulfill(promise, resolution_recv);
  }

  // 13. Let job be NewPromiseResolveThenableJob(promise, resolution,
  //                                             thenAction).
  Handle<NativeContext> then_context;
  if (!JSReceiver::GetContextForMicrotask(Cast<JSReceiver>(then_action))
           .ToHandle(&then_context)) {
    then_context = isolate->native_context();
  }

  DirectHandle<PromiseResolveThenableJobTask> task =
      isolate->factory()->NewPromiseResolveThenableJobTask(
          promise, resolution_recv, Cast<JSReceiver>(then_action),
          then_context);
  if (isolate->debug()->is_active() && IsJSPromise(*resolution_recv)) {
    // Mark the dependency of the new {promise} on the {resolution}.
    Object::SetProperty(isolate, resolution_recv,
                        isolate->factory()->promise_handled_by_symbol(),
                        promise)
        .Check();
  }
  MicrotaskQueue* microtask_queue = then_context->microtask_queue();
  if (microtask_queue) microtask_queue->EnqueueMicrotask(*task);

  // 15. Return undefined.
  return isolate->factory()->undefined_value();
}

// static
Handle<Object> JSPromise::TriggerPromiseReactions(
    Isolate* isolate, DirectHandle<Object> reactions,
    DirectHandle<Object> argument, PromiseReaction::Type type) {
  CHECK(IsSmi(*reactions) || IsPromiseReaction(*reactions));

  // We need to reverse the {reactions} here, since we record them
  // on the JSPromise in the reverse order.
  {
    DisallowGarbageCollection no_gc;
    Tagged<UnionOf<Smi, PromiseReaction>> current =
        Cast<UnionOf<Smi, PromiseReaction>>(*reactions);
    Tagged<UnionOf<Smi, PromiseReaction>> reversed = Smi::zero();
    while (!IsSmi(current)) {
      Tagged<UnionOf<Smi, PromiseReaction>> next =
          Cast<PromiseReaction>(current)->next();
      Cast<PromiseReaction>(current)->set_next(reversed);
      reversed = current;
      current = next;
    }
    reactions = direct_handle(reversed, isolate);
  }

  // Morph the {reactions} into PromiseReactionJobTasks
  // and push them onto the microtask queue.
  while (!IsSmi(*reactions)) {
    auto task = Cast<HeapObject>(reactions);
    auto reaction = Cast<PromiseReaction>(task);
    reactions = direct_handle(reaction->next(), isolate);

    // According to HTML, we use the context of the appropriate handler as the
    // context of the microtask. See step 3 of HTML's EnqueueJob:
    // https://html.spec.whatwg.org/C/#enqueuejob(queuename,-job,-arguments)
    DirectHandle<NativeContext> handler_context;

    DirectHandle<UnionOf<Undefined, JSCallable>> primary_handler;
    DirectHandle<UnionOf<Undefined, JSCallable>> secondary_handler;
    if (type == PromiseReaction::kFulfill) {
      primary_handler = direct_handle(reaction->fulfill_handler(), isolate);
      secondary_handler = direct_handle(reaction->reject_handler(), isolate);
    } else {
      primary_handler = direct_handle(reaction->reject_handler(), isolate);
      secondary_handler = direct_handle(reaction->fulfill_handler(), isolate);
    }

    bool has_handler_context = false;
    if (IsJSReceiver(*primary_handler)) {
      has_handler_context =
          JSReceiver::GetContextForMicrotask(Cast<JSReceiver>(primary_handler))
              .ToHandle(&handler_context);
    }
    if (!has_handler_context && IsJSReceiver(*secondary_handler)) {
      has_handler_context = JSReceiver::GetContextForMicrotask(
 
"""


```