Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/codegen/code-stub-assembler.cc`. They have specific requirements for the explanation:

1. **List the functionalities:**  What does this code do?
2. **Torque check:** Does the filename imply it's Torque code?
3. **JavaScript relation:** If related to JavaScript, provide a JavaScript example.
4. **Logic reasoning:**  Provide input/output examples for code logic.
5. **Common errors:** Mention common programming mistakes related to the code.
6. **Summary:**  Summarize the functionality of this specific part (part 14 of 23).

Let's break down the code snippet and address each requirement.

**Code Analysis:**

The code snippet contains various functions related to property access and method retrieval in JavaScript within the V8 engine's code stub assembler framework. Here's a breakdown:

* **`GetCreationContext`:**  This function retrieves the creation context of an object. It handles cases for proxies, bound functions, and wrapped functions by recursively looking up their targets until a simple object is found.
* **`DescriptorLookup` and `TransitionLookup`:** These functions perform lookups in DescriptorArrays and TransitionArrays, respectively. These arrays are used to store information about object properties and transitions between object shapes.
* **`Lookup`:** A template function used by `DescriptorLookup` and `TransitionLookup` to perform either a linear or binary search within an array.
* **`TryLookupPropertyInSimpleObject`:**  Looks for a property in a simple JavaScript object, checking both fast properties (in descriptors) and slow properties (in the dictionary).
* **`TryLookupProperty`:** A more general property lookup that handles simple objects and special objects like global objects.
* **`TryHasOwnProperty`:** Checks if an object directly owns a property.
* **`GetMethod`:** Retrieves a method of an object, returning `undefined` or `null` if not found.
* **`GetIteratorMethod`:** Specifically retrieves the `@@iterator` method.
* **`CreateAsyncFromSyncIterator`:** Creates an asynchronous iterator from a synchronous one.
* **`LoadPropertyFromFastObject`:** Loads a property value from a fast object based on its descriptor information. It handles in-object properties and properties in the backing store, including double representations.
* **`LoadPropertyFromDictionary`:** Loads a property value from a dictionary (slow properties).
* **`LoadPropertyFromGlobalDictionary`:** Loads a property value from a global object's dictionary.
* **`CallGetterIfAccessor`:** If a property is an accessor (getter/setter), this function calls the getter. It handles different types of accessors (AccessorPair, AccessorInfo) and considers cases with FunctionTemplateInfo.
* **`TryGetOwnProperty`:** Attempts to get the own property of an object, handling fast properties, dictionary properties, and accessors.
* **`InitializePropertyDescriptorObject`:**  Initializes a `PropertyDescriptorObject` with information about a property (value, getter/setter, attributes).
* **`AllocatePropertyDescriptorObject`:** Allocates a new `PropertyDescriptorObject`.
* **`IsInterestingProperty`:** Checks if a property name is considered "interesting" (e.g., `@@toStringTag`, `@@toPrimitive`).
* **`GetInterestingProperty`:**  Retrieves an interesting property by traversing the prototype chain.

**Addressing the Requirements:**

1. **Functionalities:** The code handles:
    * Finding the creation context of objects.
    * Looking up properties in various object structures (descriptors, dictionaries).
    * Checking for own properties.
    * Retrieving methods and iterator methods.
    * Creating asynchronous iterators from synchronous ones.
    * Loading property values from fast and slow objects, including handling accessors.
    * Getting and calling property getters.
    * Initializing property descriptor objects.
    * Identifying and retrieving "interesting" properties.

2. **Torque check:** The comment explicitly states "这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码". Since the file extension is `.cc`, it's **not** a Torque source file. Torque files end with `.tq`.

3. **JavaScript relation:** This code is fundamental to how JavaScript property access works in V8. Many JavaScript operations rely on these underlying mechanisms.

   ```javascript
   const obj = { x: 10, get y() { return this.x * 2; } };
   console.log(obj.x); // Accessing a data property
   console.log(obj.y); // Accessing a getter
   console.log(obj.hasOwnProperty('x')); // Checking own property
   console.log(obj[Symbol.iterator]); // Accessing the iterator method

   const proxy = new Proxy({}, { get(target, prop) { return `Accessed ${prop}`; } });
   console.log(proxy.someProperty); // Property access on a proxy
   ```

4. **Logic reasoning:**

   **`GetCreationContext` Example:**

   * **Input:** A `JSObject` representing a simple object.
   * **Output:** The native context associated with that object's map.

   * **Input:** A `JSProxy` object.
   * **Output:** The native context of the proxy's target object (after recursively resolving the proxy).

   **`TryHasOwnProperty` Example:**

   * **Input:**
     * `object`: `{ a: 1 }` (represented as a `JSObject`)
     * `map`: The map of the object.
     * `instance_type`: The instance type of the object.
     * `unique_name`: The string "a" (represented as a `Name`).
   * **Output:** Jumps to the `if_found` label.

   * **Input:**
     * `object`: `{ a: 1 }`
     * `unique_name`: The string "b".
   * **Output:** Jumps to the `if_not_found` label.

5. **Common errors:**

   * **Incorrectly assuming property existence:**  JavaScript allows accessing properties that don't exist, resulting in `undefined`. Developers might forget to check for property existence before using it. The `TryHasOwnProperty` function is related to this.

     ```javascript
     const obj = { a: 1 };
     console.log(obj.b.toUpperCase()); // TypeError: Cannot read properties of undefined (reading 'toUpperCase')
     if (obj.hasOwnProperty('b')) { // Proper way to check
       console.log(obj.b.toUpperCase());
     }
     ```

   * **Not handling proxy revocation:** When working with proxies, developers need to be aware that a proxy can be revoked. Accessing a revoked proxy will throw an error. The `GetCreationContext` function explicitly checks for revoked proxies.

     ```javascript
     const handler = { get() { return 'value'; } };
     const proxy = new Proxy({}, handler);
     console.log(proxy.prop); // "value"
     Proxy.revoke(proxy);
     // console.log(proxy.prop); // TypeError: Cannot perform 'get' on a proxy that has been revoked
     ```

6. **Summary of Functionality (Part 14/23):** This section of `code-stub-assembler.cc` focuses on the core mechanisms for **resolving and accessing properties** in JavaScript objects within the V8 engine. It implements logic for traversing the prototype chain, handling different object types (simple objects, proxies, bound functions), and dealing with both fast and slow property storage. It also includes functionality for retrieving methods, especially the iterator method, and for creating asynchronous iterators. Finally, it covers the creation and initialization of property descriptor objects used when defining or inspecting object properties.

这是 `v8/src/codegen/code-stub-assembler.cc` 源代码的第 14 部分，主要功能集中在 **属性查找、方法获取和与属性描述符相关的操作**。以下是更详细的列举：

**功能列表:**

1. **获取对象的创建上下文 (`GetCreationContext`)**:
   - 确定给定对象的创建时的上下文环境。
   - 特别处理了 `JSProxy`、`JSBoundFunction` 和 `JSWrappedFunction`，通过迭代地访问它们的内部目标对象来找到最终的创建上下文。

2. **描述符查找 (`DescriptorLookup`)**:
   - 在 `DescriptorArray` 中查找特定的属性名。
   - 用于快速对象（fast object）的属性查找。

3. **转换查找 (`TransitionLookup`)**:
   - 在 `TransitionArray` 中查找特定的属性名。
   - 用于查找对象形状（map）转换。

4. **数组查找 (`Lookup`)**:
   - 这是一个模板函数，被 `DescriptorLookup` 和 `TransitionLookup` 调用。
   - 实现了线性查找和二分查找两种策略，根据数组大小选择合适的查找方式。

5. **尝试在简单对象中查找属性 (`TryLookupPropertyInSimpleObject`)**:
   - 尝试在“简单”的 JavaScript 对象中查找属性。
   - 区分快速属性（存储在描述符数组中）和慢属性（存储在字典中）。

6. **尝试查找属性 (`TryLookupProperty`)**:
   - 更通用的属性查找函数，处理简单对象和特殊对象（如全局对象）。
   - 对于全局对象，会检查拦截器和访问检查。

7. **尝试判断是否拥有自身属性 (`TryHasOwnProperty`)**:
   - 判断一个对象是否直接拥有某个属性，不包括原型链上的属性。

8. **获取方法 (`GetMethod`)**:
   - 获取对象的指定方法。
   - 如果方法不存在或为 `undefined` 或 `null`，则跳转到指定的标签。

9. **获取迭代器方法 (`GetIteratorMethod`)**:
   - 获取对象的 `@@iterator` 方法。

10. **创建异步迭代器 (`CreateAsyncFromSyncIterator`)**:
    - 将一个同步迭代器转换为异步迭代器。

11. **从快速对象加载属性 (`LoadPropertyFromFastObject`)**:
    - 从快速对象中加载属性值。
    - 处理属性存储在对象内 (in-object) 和存储在外部属性数组 (backing store) 的情况。
    - 区分不同的属性表示方式（例如，Tagged 和 Double）。

12. **从字典加载属性 (`LoadPropertyFromDictionary`)**:
    - 从字典对象（用于存储慢属性）中加载属性值。

13. **从全局字典加载属性 (`LoadPropertyFromGlobalDictionary`)**:
    - 从全局对象的字典中加载属性值。
    - 检查属性单元是否被删除。

14. **如果为访问器则调用 Getter (`CallGetterIfAccessor`)**:
    - 如果属性是一个访问器（getter 或 setter），则调用其 getter 方法。
    - 处理 `AccessorPair` 和 `AccessorInfo` 两种类型的访问器。
    - 针对不同的对象类型（数组、函数、包装对象）和访问器类型进行特殊处理。

15. **尝试获取自身属性 (`TryGetOwnProperty`)**:
    - 尝试获取对象的自身属性值。
    - 综合使用快速属性查找、字典查找和访问器调用。

16. **初始化属性描述符对象 (`InitializePropertyDescriptorObject`)**:
    - 初始化一个 `PropertyDescriptorObject`，用于描述属性的特性（例如，可枚举性、可配置性、可写性）。

17. **分配属性描述符对象 (`AllocatePropertyDescriptorObject`)**:
    - 分配一个新的 `PropertyDescriptorObject` 实例。

18. **判断是否为感兴趣的属性 (`IsInterestingProperty`)**:
    - 判断一个属性名是否是“感兴趣的”特殊符号或字符串（例如，`@@toStringTag`，`@@toPrimitive`）。

19. **获取感兴趣的属性 (`GetInterestingProperty`)**:
    - 获取对象及其原型链上的“感兴趣的”属性。

**关于文件名和 Torque:**

根据您提供的信息，`v8/src/codegen/code-stub-assembler.cc` 的扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。如果它是 Torque 源代码，那么它的扩展名应该是 `.tq`。

**与 JavaScript 的关系和示例:**

这些代码直接对应了 JavaScript 中属性访问和操作的底层实现。

```javascript
const obj = {
  x: 10,
  get y() {
    return this.x * 2;
  },
  set z(value) {
    this.x = value / 2;
  }
};

// 对应 TryHasOwnProperty
console.log(obj.hasOwnProperty('x')); // true
console.log(obj.hasOwnProperty('toString')); // false

// 对应 GetMethod
console.log(obj.y); // 调用 getter，对应 CallGetterIfAccessor

// 对应 GetIteratorMethod
console.log(obj[Symbol.iterator]);

// 对应属性描述符
const descriptor = Object.getOwnPropertyDescriptor(obj, 'x');
console.log(descriptor); // { value: 10, writable: true, enumerable: true, configurable: true }

// 对应 Proxy 的处理
const proxy = new Proxy(obj, {});
console.log(proxy.x); // 对应 GetCreationContext 中对 JSProxy 的处理
```

**代码逻辑推理示例:**

**假设输入 `GetCreationContext`:**

* `current.value()` 是一个 `JSProxy` 对象，其 `handler` 指向另一个实现了代理行为的对象。

**输出 `GetCreationContext`:**

* 函数会加载 `JSProxy` 的 `handler` 和 `target`。
* 如果 `handler` 是一个 `JSReceiver` (表示代理未被撤销)，则会将 `current` 更新为 `target` 并继续循环。
* 最终，当 `current.value()` 不是 `JSProxy`、`JSBoundFunction` 或 `JSWrappedFunction` 时，会调用 `GetCreationContextFromMap` 返回创建上下文。
* 如果代理被撤销，则会抛出 `TypeError`。

**用户常见的编程错误示例:**

1. **假设属性一定存在而直接访问:**

   ```javascript
   function processObject(obj) {
     // 假设 obj 有一个名为 'name' 的属性
     console.log(obj.name.toUpperCase()); // 如果 obj 没有 'name' 属性，会报错
   }

   processObject({ id: 1 }); // 运行时错误：Cannot read properties of undefined (reading 'toUpperCase')
   ```

   这段代码在 `processObject` 被调用时，如果传入的对象 `obj` 没有 `name` 属性，则 `obj.name` 将是 `undefined`，尝试访问 `undefined` 的 `toUpperCase` 属性会导致 `TypeError`。`TryHasOwnProperty` 这样的功能可以在底层帮助避免这类错误，开发者应该使用 `hasOwnProperty` 或可选链等方式来安全地访问属性。

2. **没有正确处理代理被撤销的情况:**

   ```javascript
   const target = {};
   const handler = {
     get: function(obj, prop) {
       return prop in obj ? obj[prop] : "不存在";
     }
   };
   const proxy = new Proxy(target, handler);

   console.log(proxy.a); // "不存在"

   Proxy.revoke(proxy);

   try {
     console.log(proxy.a); // 运行时错误：Cannot perform 'get' on a proxy that has been revoked
   } catch (e) {
     console.error("代理已被撤销:", e);
   }
   ```

   这段代码展示了代理被撤销后尝试访问代理属性会抛出错误。`GetCreationContext` 中对 `proxy_revoked` 的处理反映了 V8 引擎在底层对此类情况的处理。开发者在使用 `Proxy` 时需要注意其生命周期。

**第 14 部分的功能归纳:**

总而言之，`v8/src/codegen/code-stub-assembler.cc` 的第 14 部分主要实现了 V8 引擎中 **对象属性的查找和访问机制**。它涵盖了从简单的属性查找，到处理特殊对象类型（如代理和绑定函数），再到与属性描述符相关的操作。这些功能是 JavaScript 引擎实现对象模型和属性访问语义的关键组成部分。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第14部分，共23部分，请归纳一下它的功能
```

### 源代码
```cpp
GotoIf(InstanceTypeEqual(instance_type, JS_PROXY_TYPE), &if_proxy);
    GotoIf(InstanceTypeEqual(instance_type, JS_BOUND_FUNCTION_TYPE),
           &if_bound_function);
    GotoIf(InstanceTypeEqual(instance_type, JS_WRAPPED_FUNCTION_TYPE),
           &if_wrapped_function);
    Goto(&if_simple_case);
  }

  BIND(&if_proxy);
  {
    TNode<JSProxy> proxy = CAST(current.value());
    TNode<HeapObject> handler =
        CAST(LoadObjectField(proxy, JSProxy::kHandlerOffset));
    // Proxy is revoked.
    GotoIfNot(IsJSReceiver(handler), &proxy_revoked);
    TNode<JSReceiver> target =
        CAST(LoadObjectField(proxy, JSProxy::kTargetOffset));
    current = target;
    Goto(&loop);
  }

  BIND(&proxy_revoked);
  { ThrowTypeError(context, MessageTemplate::kProxyRevoked, "apply"); }

  BIND(&if_bound_function);
  {
    TNode<JSBoundFunction> bound_function = CAST(current.value());
    TNode<JSReceiver> target = CAST(LoadObjectField(
        bound_function, JSBoundFunction::kBoundTargetFunctionOffset));
    current = target;
    Goto(&loop);
  }

  BIND(&if_wrapped_function);
  {
    TNode<JSWrappedFunction> wrapped_function = CAST(current.value());
    TNode<JSReceiver> target = CAST(LoadObjectField(
        wrapped_function, JSWrappedFunction::kWrappedTargetFunctionOffset));
    current = target;
    Goto(&loop);
  }

  BIND(&if_simple_case);
  {
    // Load native context from the meta map.
    return GetCreationContextFromMap(current_map.value(), if_bailout);
  }
}

void CodeStubAssembler::DescriptorLookup(TNode<Name> unique_name,
                                         TNode<DescriptorArray> descriptors,
                                         TNode<Uint32T> bitfield3,
                                         Label* if_found,
                                         TVariable<IntPtrT>* var_name_index,
                                         Label* if_not_found) {
  Comment("DescriptorArrayLookup");
  TNode<Uint32T> nof =
      DecodeWord32<Map::Bits3::NumberOfOwnDescriptorsBits>(bitfield3);
  Lookup<DescriptorArray>(unique_name, descriptors, nof, if_found,
                          var_name_index, if_not_found);
}

void CodeStubAssembler::TransitionLookup(TNode<Name> unique_name,
                                         TNode<TransitionArray> transitions,
                                         Label* if_found,
                                         TVariable<IntPtrT>* var_name_index,
                                         Label* if_not_found) {
  Comment("TransitionArrayLookup");
  TNode<Uint32T> number_of_valid_transitions =
      NumberOfEntries<TransitionArray>(transitions);
  Lookup<TransitionArray>(unique_name, transitions, number_of_valid_transitions,
                          if_found, var_name_index, if_not_found);
}

template <typename Array>
void CodeStubAssembler::Lookup(TNode<Name> unique_name, TNode<Array> array,
                               TNode<Uint32T> number_of_valid_entries,
                               Label* if_found,
                               TVariable<IntPtrT>* var_name_index,
                               Label* if_not_found) {
  Comment("ArrayLookup");
  if (!number_of_valid_entries) {
    number_of_valid_entries = NumberOfEntries(array);
  }
  GotoIf(Word32Equal(number_of_valid_entries, Int32Constant(0)), if_not_found);
  Label linear_search(this), binary_search(this);
  const int kMaxElementsForLinearSearch = 32;
  Branch(Uint32LessThanOrEqual(number_of_valid_entries,
                               Int32Constant(kMaxElementsForLinearSearch)),
         &linear_search, &binary_search);
  BIND(&linear_search);
  {
    LookupLinear<Array>(unique_name, array, number_of_valid_entries, if_found,
                        var_name_index, if_not_found);
  }
  BIND(&binary_search);
  {
    LookupBinary<Array>(unique_name, array, number_of_valid_entries, if_found,
                        var_name_index, if_not_found);
  }
}

void CodeStubAssembler::TryLookupPropertyInSimpleObject(
    TNode<JSObject> object, TNode<Map> map, TNode<Name> unique_name,
    Label* if_found_fast, Label* if_found_dict,
    TVariable<HeapObject>* var_meta_storage, TVariable<IntPtrT>* var_name_index,
    Label* if_not_found, Label* bailout) {
  CSA_DCHECK(this, IsSimpleObjectMap(map));
  CSA_DCHECK(this, IsUniqueNameNoCachedIndex(unique_name));

  TNode<Uint32T> bit_field3 = LoadMapBitField3(map);
  Label if_isfastmap(this), if_isslowmap(this);
  Branch(IsSetWord32<Map::Bits3::IsDictionaryMapBit>(bit_field3), &if_isslowmap,
         &if_isfastmap);
  BIND(&if_isfastmap);
  {
    TNode<DescriptorArray> descriptors = LoadMapDescriptors(map);
    *var_meta_storage = descriptors;

    DescriptorLookup(unique_name, descriptors, bit_field3, if_found_fast,
                     var_name_index, if_not_found);
  }
  BIND(&if_isslowmap);
  {
    TNode<PropertyDictionary> dictionary = CAST(LoadSlowProperties(object));
    *var_meta_storage = dictionary;

    NameDictionaryLookup<PropertyDictionary>(
        dictionary, unique_name, if_found_dict, var_name_index, if_not_found);
  }
}

void CodeStubAssembler::TryLookupProperty(
    TNode<HeapObject> object, TNode<Map> map, TNode<Int32T> instance_type,
    TNode<Name> unique_name, Label* if_found_fast, Label* if_found_dict,
    Label* if_found_global, TVariable<HeapObject>* var_meta_storage,
    TVariable<IntPtrT>* var_name_index, Label* if_not_found,
    Label* if_bailout) {
  Label if_objectisspecial(this);
  GotoIf(IsSpecialReceiverInstanceType(instance_type), &if_objectisspecial);

  TryLookupPropertyInSimpleObject(CAST(object), map, unique_name, if_found_fast,
                                  if_found_dict, var_meta_storage,
                                  var_name_index, if_not_found, if_bailout);

  BIND(&if_objectisspecial);
  {
    // Handle global object here and bailout for other special objects.
    GotoIfNot(InstanceTypeEqual(instance_type, JS_GLOBAL_OBJECT_TYPE),
              if_bailout);

    // Handle interceptors and access checks in runtime.
    TNode<Int32T> bit_field = LoadMapBitField(map);
    int mask = Map::Bits1::HasNamedInterceptorBit::kMask |
               Map::Bits1::IsAccessCheckNeededBit::kMask;
    GotoIf(IsSetWord32(bit_field, mask), if_bailout);

    TNode<GlobalDictionary> dictionary = CAST(LoadSlowProperties(CAST(object)));
    *var_meta_storage = dictionary;

    NameDictionaryLookup<GlobalDictionary>(
        dictionary, unique_name, if_found_global, var_name_index, if_not_found);
  }
}

void CodeStubAssembler::TryHasOwnProperty(TNode<HeapObject> object,
                                          TNode<Map> map,
                                          TNode<Int32T> instance_type,
                                          TNode<Name> unique_name,
                                          Label* if_found, Label* if_not_found,
                                          Label* if_bailout) {
  Comment("TryHasOwnProperty");
  CSA_DCHECK(this, IsUniqueNameNoCachedIndex(unique_name));
  TVARIABLE(HeapObject, var_meta_storage);
  TVARIABLE(IntPtrT, var_name_index);

  Label if_found_global(this);
  TryLookupProperty(object, map, instance_type, unique_name, if_found, if_found,
                    &if_found_global, &var_meta_storage, &var_name_index,
                    if_not_found, if_bailout);

  BIND(&if_found_global);
  {
    TVARIABLE(Object, var_value);
    TVARIABLE(Uint32T, var_details);
    // Check if the property cell is not deleted.
    LoadPropertyFromGlobalDictionary(CAST(var_meta_storage.value()),
                                     var_name_index.value(), &var_details,
                                     &var_value, if_not_found);
    Goto(if_found);
  }
}

TNode<Object> CodeStubAssembler::GetMethod(TNode<Context> context,
                                           TNode<Object> object,
                                           Handle<Name> name,
                                           Label* if_null_or_undefined) {
  TNode<Object> method = GetProperty(context, object, name);

  GotoIf(IsUndefined(method), if_null_or_undefined);
  GotoIf(IsNull(method), if_null_or_undefined);

  return method;
}

TNode<Object> CodeStubAssembler::GetIteratorMethod(
    TNode<Context> context, TNode<HeapObject> heap_obj,
    Label* if_iteratorundefined) {
  return GetMethod(context, heap_obj, isolate()->factory()->iterator_symbol(),
                   if_iteratorundefined);
}

TNode<Object> CodeStubAssembler::CreateAsyncFromSyncIterator(
    TNode<Context> context, TNode<Object> sync_iterator) {
  Label not_receiver(this, Label::kDeferred);
  Label done(this);
  TVARIABLE(Object, return_value);

  GotoIf(TaggedIsSmi(sync_iterator), &not_receiver);
  GotoIfNot(IsJSReceiver(CAST(sync_iterator)), &not_receiver);

  const TNode<Object> next =
      GetProperty(context, sync_iterator, factory()->next_string());
  return_value =
      CreateAsyncFromSyncIterator(context, CAST(sync_iterator), next);
  Goto(&done);

  BIND(&not_receiver);
  {
    return_value = CallRuntime(Runtime::kThrowSymbolIteratorInvalid, context);

    // Unreachable due to the Throw in runtime call.
    Goto(&done);
  }

  BIND(&done);
  return return_value.value();
}

TNode<JSObject> CodeStubAssembler::CreateAsyncFromSyncIterator(
    TNode<Context> context, TNode<JSReceiver> sync_iterator,
    TNode<Object> next) {
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Map> map = CAST(LoadContextElement(
      native_context, Context::ASYNC_FROM_SYNC_ITERATOR_MAP_INDEX));
  const TNode<JSObject> iterator = AllocateJSObjectFromMap(map);

  StoreObjectFieldNoWriteBarrier(
      iterator, JSAsyncFromSyncIterator::kSyncIteratorOffset, sync_iterator);
  StoreObjectFieldNoWriteBarrier(iterator, JSAsyncFromSyncIterator::kNextOffset,
                                 next);
  return iterator;
}

void CodeStubAssembler::LoadPropertyFromFastObject(
    TNode<HeapObject> object, TNode<Map> map,
    TNode<DescriptorArray> descriptors, TNode<IntPtrT> name_index,
    TVariable<Uint32T>* var_details, TVariable<Object>* var_value) {
  TNode<Uint32T> details = LoadDetailsByKeyIndex(descriptors, name_index);
  *var_details = details;

  LoadPropertyFromFastObject(object, map, descriptors, name_index, details,
                             var_value);
}

void CodeStubAssembler::LoadPropertyFromFastObject(
    TNode<HeapObject> object, TNode<Map> map,
    TNode<DescriptorArray> descriptors, TNode<IntPtrT> name_index,
    TNode<Uint32T> details, TVariable<Object>* var_value) {
  Comment("[ LoadPropertyFromFastObject");

  TNode<Uint32T> location =
      DecodeWord32<PropertyDetails::LocationField>(details);

  Label if_in_field(this), if_in_descriptor(this), done(this);
  Branch(Word32Equal(location, Int32Constant(static_cast<int32_t>(
                                   PropertyLocation::kField))),
         &if_in_field, &if_in_descriptor);
  BIND(&if_in_field);
  {
    TNode<IntPtrT> field_index =
        Signed(DecodeWordFromWord32<PropertyDetails::FieldIndexField>(details));
    TNode<Uint32T> representation =
        DecodeWord32<PropertyDetails::RepresentationField>(details);

    // TODO(ishell): support WasmValues.
    CSA_DCHECK(this, Word32NotEqual(representation,
                                    Int32Constant(Representation::kWasmValue)));
    field_index =
        IntPtrAdd(field_index, LoadMapInobjectPropertiesStartInWords(map));
    TNode<IntPtrT> instance_size_in_words = LoadMapInstanceSizeInWords(map);

    Label if_inobject(this), if_backing_store(this);
    TVARIABLE(Float64T, var_double_value);
    Label rebox_double(this, &var_double_value);
    Branch(UintPtrLessThan(field_index, instance_size_in_words), &if_inobject,
           &if_backing_store);
    BIND(&if_inobject);
    {
      Comment("if_inobject");
      TNode<IntPtrT> field_offset = TimesTaggedSize(field_index);

      Label if_double(this), if_tagged(this);
      Branch(Word32NotEqual(representation,
                            Int32Constant(Representation::kDouble)),
             &if_tagged, &if_double);
      BIND(&if_tagged);
      {
        *var_value = LoadObjectField(object, field_offset);
        Goto(&done);
      }
      BIND(&if_double);
      {
        TNode<HeapNumber> heap_number =
            CAST(LoadObjectField(object, field_offset));
        var_double_value = LoadHeapNumberValue(heap_number);
        Goto(&rebox_double);
      }
    }
    BIND(&if_backing_store);
    {
      Comment("if_backing_store");
      TNode<HeapObject> properties = LoadFastProperties(CAST(object), true);
      field_index = Signed(IntPtrSub(field_index, instance_size_in_words));
      TNode<Object> value =
          LoadPropertyArrayElement(CAST(properties), field_index);

      Label if_double(this), if_tagged(this);
      Branch(Word32NotEqual(representation,
                            Int32Constant(Representation::kDouble)),
             &if_tagged, &if_double);
      BIND(&if_tagged);
      {
        *var_value = value;
        Goto(&done);
      }
      BIND(&if_double);
      {
        var_double_value = LoadHeapNumberValue(CAST(value));
        Goto(&rebox_double);
      }
    }
    BIND(&rebox_double);
    {
      Comment("rebox_double");
      TNode<HeapNumber> heap_number =
          AllocateHeapNumberWithValue(var_double_value.value());
      *var_value = heap_number;
      Goto(&done);
    }
  }
  BIND(&if_in_descriptor);
  {
    *var_value = LoadValueByKeyIndex(descriptors, name_index);
    Goto(&done);
  }
  BIND(&done);

  Comment("] LoadPropertyFromFastObject");
}

template <typename Dictionary>
void CodeStubAssembler::LoadPropertyFromDictionary(
    TNode<Dictionary> dictionary, TNode<IntPtrT> name_index,
    TVariable<Uint32T>* var_details, TVariable<Object>* var_value) {
  Comment("LoadPropertyFromNameDictionary");
  *var_details = LoadDetailsByKeyIndex(dictionary, name_index);
  *var_value = LoadValueByKeyIndex(dictionary, name_index);

  Comment("] LoadPropertyFromNameDictionary");
}

void CodeStubAssembler::LoadPropertyFromGlobalDictionary(
    TNode<GlobalDictionary> dictionary, TNode<IntPtrT> name_index,
    TVariable<Uint32T>* var_details, TVariable<Object>* var_value,
    Label* if_deleted) {
  Comment("[ LoadPropertyFromGlobalDictionary");
  TNode<PropertyCell> property_cell =
      CAST(LoadFixedArrayElement(dictionary, name_index));

  TNode<Object> value =
      LoadObjectField(property_cell, PropertyCell::kValueOffset);
  GotoIf(TaggedEqual(value, PropertyCellHoleConstant()), if_deleted);

  *var_value = value;

  TNode<Uint32T> details = Unsigned(LoadAndUntagToWord32ObjectField(
      property_cell, PropertyCell::kPropertyDetailsRawOffset));
  *var_details = details;

  Comment("] LoadPropertyFromGlobalDictionary");
}

template void CodeStubAssembler::LoadPropertyFromDictionary(
    TNode<NameDictionary> dictionary, TNode<IntPtrT> name_index,
    TVariable<Uint32T>* var_details, TVariable<Object>* var_value);

template void CodeStubAssembler::LoadPropertyFromDictionary(
    TNode<SwissNameDictionary> dictionary, TNode<IntPtrT> name_index,
    TVariable<Uint32T>* var_details, TVariable<Object>* var_value);

// |value| is the property backing store's contents, which is either a value or
// an accessor pair, as specified by |details|. |holder| is a JSObject or a
// PropertyCell (TODO: use Union). Returns either the original value, or the
// result of the getter call.
TNode<Object> CodeStubAssembler::CallGetterIfAccessor(
    TNode<Object> value, TNode<HeapObject> holder, TNode<Uint32T> details,
    TNode<Context> context, TNode<Object> receiver, TNode<Object> name,
    Label* if_bailout, GetOwnPropertyMode mode,
    ExpectedReceiverMode expected_receiver_mode) {
  TVARIABLE(Object, var_value, value);
  Label done(this), if_accessor_info(this, Label::kDeferred);

  TNode<Uint32T> kind = DecodeWord32<PropertyDetails::KindField>(details);
  GotoIf(
      Word32Equal(kind, Int32Constant(static_cast<int>(PropertyKind::kData))),
      &done);

  // Accessor case.
  GotoIfNot(IsAccessorPair(CAST(value)), &if_accessor_info);

  // AccessorPair case.
  {
    if (mode == kCallJSGetterUseCachedName ||
        mode == kCallJSGetterDontUseCachedName) {
      Label if_callable(this), if_function_template_info(this);
      TNode<AccessorPair> accessor_pair = CAST(value);
      TNode<HeapObject> getter =
          CAST(LoadObjectField(accessor_pair, AccessorPair::kGetterOffset));
      TNode<Map> getter_map = LoadMap(getter);

      GotoIf(IsCallableMap(getter_map), &if_callable);
      GotoIf(IsFunctionTemplateInfoMap(getter_map), &if_function_template_info);

      // Return undefined if the {getter} is not callable.
      var_value = UndefinedConstant();
      Goto(&done);

      BIND(&if_callable);
      {
        // Call the accessor. No need to check side-effect mode here, since it
        // will be checked later in DebugOnFunctionCall.
        // It's too early to convert receiver to JSReceiver at this point
        // (the Call builtin will do the conversion), so we ignore the
        // |expected_receiver_mode| here.
        var_value = Call(context, getter, receiver);
        Goto(&done);
      }

      BIND(&if_function_template_info);
      {
        Label use_cached_property(this);
        TNode<HeapObject> cached_property_name = LoadObjectField<HeapObject>(
            getter, FunctionTemplateInfo::kCachedPropertyNameOffset);

        Label* has_cached_property = mode == kCallJSGetterUseCachedName
                                         ? &use_cached_property
                                         : if_bailout;
        GotoIfNot(IsTheHole(cached_property_name), has_cached_property);

        TNode<JSReceiver> js_receiver;
        switch (expected_receiver_mode) {
          case kExpectingJSReceiver:
            js_receiver = CAST(receiver);
            break;
          case kExpectingAnyReceiver:
            // TODO(ishell): in case the function template info has a signature
            // and receiver is not a JSReceiver the signature check in
            // CallFunctionTemplate builtin will fail anyway, so we can short
            // cut it here and throw kIllegalInvocation immediately.
            js_receiver = ToObject_Inline(context, receiver);
            break;
        }
        TNode<NativeContext> creation_context =
            GetCreationContext(CAST(holder), if_bailout);
        TNode<Context> caller_context = context;
        var_value = CallBuiltin(
            Builtin::kCallFunctionTemplate_Generic, creation_context, getter,
            Int32Constant(i::JSParameterCount(0)), caller_context, js_receiver);
        Goto(&done);

        if (mode == kCallJSGetterUseCachedName) {
          Bind(&use_cached_property);

          var_value = GetProperty(context, holder, cached_property_name);

          Goto(&done);
        }
      }
    } else {
      DCHECK_EQ(mode, kReturnAccessorPair);
      Goto(&done);
    }
  }

  // AccessorInfo case.
  BIND(&if_accessor_info);
  {
    TNode<AccessorInfo> accessor_info = CAST(value);
    Label if_array(this), if_function(this), if_wrapper(this);

    // Dispatch based on {holder} instance type.
    TNode<Map> holder_map = LoadMap(holder);
    TNode<Uint16T> holder_instance_type = LoadMapInstanceType(holder_map);
    GotoIf(IsJSArrayInstanceType(holder_instance_type), &if_array);
    GotoIf(IsJSFunctionInstanceType(holder_instance_type), &if_function);
    Branch(IsJSPrimitiveWrapperInstanceType(holder_instance_type), &if_wrapper,
           if_bailout);

    // JSArray AccessorInfo case.
    BIND(&if_array);
    {
      // We only deal with the "length" accessor on JSArray.
      GotoIfNot(IsLengthString(
                    LoadObjectField(accessor_info, AccessorInfo::kNameOffset)),
                if_bailout);
      TNode<JSArray> array = CAST(holder);
      var_value = LoadJSArrayLength(array);
      Goto(&done);
    }

    // JSFunction AccessorInfo case.
    BIND(&if_function);
    {
      // We only deal with the "prototype" accessor on JSFunction here.
      GotoIfNot(IsPrototypeString(
                    LoadObjectField(accessor_info, AccessorInfo::kNameOffset)),
                if_bailout);

      TNode<JSFunction> function = CAST(holder);
      GotoIfPrototypeRequiresRuntimeLookup(function, holder_map, if_bailout);
      var_value = LoadJSFunctionPrototype(function, if_bailout);
      Goto(&done);
    }

    // JSPrimitiveWrapper AccessorInfo case.
    BIND(&if_wrapper);
    {
      // We only deal with the "length" accessor on JSPrimitiveWrapper string
      // wrappers.
      GotoIfNot(IsLengthString(
                    LoadObjectField(accessor_info, AccessorInfo::kNameOffset)),
                if_bailout);
      TNode<Object> holder_value = LoadJSPrimitiveWrapperValue(CAST(holder));
      GotoIfNot(TaggedIsNotSmi(holder_value), if_bailout);
      GotoIfNot(IsString(CAST(holder_value)), if_bailout);
      var_value = LoadStringLengthAsSmi(CAST(holder_value));
      Goto(&done);
    }
  }

  BIND(&done);
  return var_value.value();
}

void CodeStubAssembler::TryGetOwnProperty(
    TNode<Context> context, TNode<Object> receiver, TNode<JSReceiver> object,
    TNode<Map> map, TNode<Int32T> instance_type, TNode<Name> unique_name,
    Label* if_found_value, TVariable<Object>* var_value, Label* if_not_found,
    Label* if_bailout, ExpectedReceiverMode expected_receiver_mode) {
  TryGetOwnProperty(context, receiver, object, map, instance_type, unique_name,
                    if_found_value, var_value, nullptr, nullptr, if_not_found,
                    if_bailout,
                    receiver == object ? kCallJSGetterUseCachedName
                                       : kCallJSGetterDontUseCachedName,
                    expected_receiver_mode);
}

void CodeStubAssembler::TryGetOwnProperty(
    TNode<Context> context, TNode<Object> receiver, TNode<JSReceiver> object,
    TNode<Map> map, TNode<Int32T> instance_type, TNode<Name> unique_name,
    Label* if_found_value, TVariable<Object>* var_value,
    TVariable<Uint32T>* var_details, TVariable<Object>* var_raw_value,
    Label* if_not_found, Label* if_bailout, GetOwnPropertyMode mode,
    ExpectedReceiverMode expected_receiver_mode) {
  DCHECK_EQ(MachineRepresentation::kTagged, var_value->rep());
  Comment("TryGetOwnProperty");
  if (receiver == object) {
    // If |receiver| is exactly the same Node as the |object| which is
    // guaranteed to be JSReceiver override the |expected_receiver_mode|.
    expected_receiver_mode = kExpectingJSReceiver;
  }
  CSA_DCHECK(this, IsUniqueNameNoCachedIndex(unique_name));
  TVARIABLE(HeapObject, var_meta_storage);
  TVARIABLE(IntPtrT, var_entry);

  Label if_found_fast(this), if_found_dict(this), if_found_global(this);

  TVARIABLE(Uint32T, local_var_details);
  if (!var_details) {
    var_details = &local_var_details;
  }
  Label if_found(this);

  TryLookupProperty(object, map, instance_type, unique_name, &if_found_fast,
                    &if_found_dict, &if_found_global, &var_meta_storage,
                    &var_entry, if_not_found, if_bailout);
  BIND(&if_found_fast);
  {
    TNode<DescriptorArray> descriptors = CAST(var_meta_storage.value());
    TNode<IntPtrT> name_index = var_entry.value();

    LoadPropertyFromFastObject(object, map, descriptors, name_index,
                               var_details, var_value);
    Goto(&if_found);
  }
  BIND(&if_found_dict);
  {
    TNode<PropertyDictionary> dictionary = CAST(var_meta_storage.value());
    TNode<IntPtrT> entry = var_entry.value();
    LoadPropertyFromDictionary(dictionary, entry, var_details, var_value);

    Goto(&if_found);
  }
  BIND(&if_found_global);
  {
    TNode<GlobalDictionary> dictionary = CAST(var_meta_storage.value());
    TNode<IntPtrT> entry = var_entry.value();

    LoadPropertyFromGlobalDictionary(dictionary, entry, var_details, var_value,
                                     if_not_found);
    Goto(&if_found);
  }
  // Here we have details and value which could be an accessor.
  BIND(&if_found);
  {
    // TODO(ishell): Execute C++ accessor in case of accessor info
    if (var_raw_value) {
      *var_raw_value = *var_value;
    }
    TNode<Object> value = CallGetterIfAccessor(
        var_value->value(), object, var_details->value(), context, receiver,
        unique_name, if_bailout, mode, expected_receiver_mode);
    *var_value = value;
    Goto(if_found_value);
  }
}

void CodeStubAssembler::InitializePropertyDescriptorObject(
    TNode<PropertyDescriptorObject> descriptor, TNode<Object> value,
    TNode<Uint32T> details, Label* if_bailout) {
  Label if_data_property(this), if_accessor_property(this),
      test_configurable(this), test_property_type(this), done(this);
  TVARIABLE(Smi, flags,
            SmiConstant(PropertyDescriptorObject::HasEnumerableBit::kMask |
                        PropertyDescriptorObject::HasConfigurableBit::kMask));

  {  // test enumerable
    TNode<Uint32T> dont_enum =
        Uint32Constant(DONT_ENUM << PropertyDetails::AttributesField::kShift);
    GotoIf(Word32And(details, dont_enum), &test_configurable);
    flags =
        SmiOr(flags.value(),
              SmiConstant(PropertyDescriptorObject::IsEnumerableBit::kMask));
    Goto(&test_configurable);
  }

  BIND(&test_configurable);
  {
    TNode<Uint32T> dont_delete =
        Uint32Constant(DONT_DELETE << PropertyDetails::AttributesField::kShift);
    GotoIf(Word32And(details, dont_delete), &test_property_type);
    flags =
        SmiOr(flags.value(),
              SmiConstant(PropertyDescriptorObject::IsConfigurableBit::kMask));
    Goto(&test_property_type);
  }

  BIND(&test_property_type);
  BranchIfAccessorPair(value, &if_accessor_property, &if_data_property);

  BIND(&if_accessor_property);
  {
    Label done_get(this), store_fields(this);
    TNode<AccessorPair> accessor_pair = CAST(value);

    auto BailoutIfTemplateInfo = [this, &if_bailout](TNode<HeapObject> value) {
      TVARIABLE(HeapObject, result);

      Label bind_undefined(this), return_result(this);
      GotoIf(IsNull(value), &bind_undefined);
      result = value;
      TNode<Map> map = LoadMap(value);
      // TODO(ishell): probe template instantiations cache.
      GotoIf(IsFunctionTemplateInfoMap(map), if_bailout);
      Goto(&return_result);

      BIND(&bind_undefined);
      result = UndefinedConstant();
      Goto(&return_result);

      BIND(&return_result);
      return result.value();
    };

    TNode<HeapObject> getter =
        LoadObjectField<HeapObject>(accessor_pair, AccessorPair::kGetterOffset);
    TNode<HeapObject> setter =
        LoadObjectField<HeapObject>(accessor_pair, AccessorPair::kSetterOffset);
    getter = BailoutIfTemplateInfo(getter);
    setter = BailoutIfTemplateInfo(setter);

    Label bind_undefined(this, Label::kDeferred), return_result(this);
    flags = SmiOr(flags.value(),
                  SmiConstant(PropertyDescriptorObject::HasGetBit::kMask |
                              PropertyDescriptorObject::HasSetBit::kMask));
    StoreObjectField(descriptor, PropertyDescriptorObject::kFlagsOffset,
                     flags.value());
    StoreObjectField(descriptor, PropertyDescriptorObject::kValueOffset,
                     NullConstant());
    StoreObjectField(descriptor, PropertyDescriptorObject::kGetOffset,
                     BailoutIfTemplateInfo(getter));
    StoreObjectField(descriptor, PropertyDescriptorObject::kSetOffset,
                     BailoutIfTemplateInfo(setter));
    Goto(&done);
  }

  BIND(&if_data_property);
  {
    Label store_fields(this);
    flags = SmiOr(flags.value(),
                  SmiConstant(PropertyDescriptorObject::HasValueBit::kMask |
                              PropertyDescriptorObject::HasWritableBit::kMask));
    TNode<Uint32T> read_only =
        Uint32Constant(READ_ONLY << PropertyDetails::AttributesField::kShift);
    GotoIf(Word32And(details, read_only), &store_fields);
    flags = SmiOr(flags.value(),
                  SmiConstant(PropertyDescriptorObject::IsWritableBit::kMask));
    Goto(&store_fields);

    BIND(&store_fields);
    StoreObjectField(descriptor, PropertyDescriptorObject::kFlagsOffset,
                     flags.value());
    StoreObjectField(descriptor, PropertyDescriptorObject::kValueOffset, value);
    StoreObjectField(descriptor, PropertyDescriptorObject::kGetOffset,
                     NullConstant());
    StoreObjectField(descriptor, PropertyDescriptorObject::kSetOffset,
                     NullConstant());
    Goto(&done);
  }

  BIND(&done);
}

TNode<PropertyDescriptorObject>
CodeStubAssembler::AllocatePropertyDescriptorObject(TNode<Context> context) {
  TNode<HeapObject> result = Allocate(PropertyDescriptorObject::kSize);
  TNode<Map> map = GetInstanceTypeMap(PROPERTY_DESCRIPTOR_OBJECT_TYPE);
  StoreMapNoWriteBarrier(result, map);
  TNode<Smi> zero = SmiConstant(0);
  StoreObjectFieldNoWriteBarrier(result, PropertyDescriptorObject::kFlagsOffset,
                                 zero);
  TNode<Hole> the_hole = TheHoleConstant();
  StoreObjectFieldNoWriteBarrier(result, PropertyDescriptorObject::kValueOffset,
                                 the_hole);
  StoreObjectFieldNoWriteBarrier(result, PropertyDescriptorObject::kGetOffset,
                                 the_hole);
  StoreObjectFieldNoWriteBarrier(result, PropertyDescriptorObject::kSetOffset,
                                 the_hole);
  return CAST(result);
}

TNode<BoolT> CodeStubAssembler::IsInterestingProperty(TNode<Name> name) {
  TVARIABLE(BoolT, var_result);
  Label return_false(this), return_true(this), return_generic(this);
  // TODO(ishell): consider using ReadOnlyRoots::IsNameForProtector() trick for
  // these strings and interesting symbols.
  GotoIf(IsToJSONString(name), &return_true);
  GotoIf(IsGetString(name), &return_true);
  GotoIfNot(InstanceTypeEqual(LoadMapInstanceType(LoadMap(name)), SYMBOL_TYPE),
            &return_false);
  Branch(IsSetWord32<Symbol::IsInterestingSymbolBit>(
             LoadObjectField<Uint32T>(name, offsetof(Symbol, flags_))),
         &return_true, &return_false);

  BIND(&return_false);
  var_result = BoolConstant(false);
  Goto(&return_generic);

  BIND(&return_true);
  var_result = BoolConstant(true);
  Goto(&return_generic);

  BIND(&return_generic);
  return var_result.value();
}

TNode<Object> CodeStubAssembler::GetInterestingProperty(
    TNode<Context> context, TNode<JSReceiver> receiver, TNode<Name> name,
    Label* if_not_found) {
  TVARIABLE(HeapObject, var_holder, receiver);
  TVARIABLE(Map, var_holder_map, LoadMap(receiver));

  return GetInterestingProperty(context, receiver, &var_holder, &var_holder_map,
                                name, if_not_found);
}

TNode<Object> CodeStubAssembler::GetInterestingProperty(
    TNode<Context> context, TNode<Object> receiver,
    TVariable<HeapObject>* var_holder, TVariable<Map>* var_holder_map,
    TNode<Name> name, Label* if_not_found) {
  CSA_DCHECK(this, IsInterestingProperty(name));
  // The lookup starts at the var_holder and var_holder_map must contain
  // var_holder's map.
  CSA_DCHECK(this, TaggedEqual(LoadMap((*var_holder).value()),
                               (*var_holder_map).value()));
  TVARIABLE(Object, var_result, UndefinedConstant());

  // Check if all relevant maps (including the prototype maps) don't
  // have any interesting properties (i.e. that none of them have the
  // @@toStringTag or @@toPrimitive property).
  Label loop(this, {var_holder, var_holder_map}),
      lookup(this, Label::kDeferred);
  Goto(&loop);
  BIND(&loop);
  {
    Label interesting_properties(this);
    TNode<HeapObject> holder = (*var_holder).value();
    TNode<Map> holder_map = (*var_holder_map).value();
    GotoIf(IsNull(holder), if_not_found);
    TNode<Uint32T> holder_bit_field3 = LoadMapBitField3(holder_map);
    GotoIf(IsSetWord32<Map::Bits3::MayHaveInterestingPropertiesBit>(
               holder_bit_field3),
           &interesting_properties);
    *var_holder = LoadMapPrototype(holder_map);
    *var_holder_map = LoadMap((*var_holder).value());
    Goto(&loop);
    BIND(&interesting_properties);
    {
      // Check flags for dictionary objects.
      GotoIf(IsClearWord32<Map::Bits3::IsDictionaryMapBit>(holder_bit_field3),
             &lookup);
      // JSProxy has dictionary properties but has to be handled in runtime.
      GotoIf(InstanceTypeEqual(LoadMapInstanceType(holder_map), JS_PROXY_TYPE),
             &lookup);
      TNode<Object> properties =
          LoadObjectField(holder, JSObject::kPropertiesOrHashOffset);
      CSA_DCHECK(this, TaggedIsNotSmi(properties));
      CSA_DCHECK(this, IsPropertyDictionary(CAST(properties)));
      // TODO(pthier): Support swiss dictionaries.
      if constexpr (!V8_ENABL
```