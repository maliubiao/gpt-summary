Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/lookup.cc`. I need to identify the main purpose of this code. It seems to revolve around property lookup and manipulation in JavaScript objects within the V8 engine.

Here's a breakdown of how to approach the request:

1. **Identify Key Classes/Functions:**  Look for prominent class names and function names that suggest the code's function. `LookupIterator` is a strong indicator. Functions like `DeleteProperty`, `TransitionToAccessorProperty`, `FetchValue`, `WriteDataValue`, and `LookupInRegularHolder` are important.

2. **Infer Overall Purpose:** The name `LookupIterator` strongly suggests the code is involved in the process of finding properties on JavaScript objects. The various functions likely handle different scenarios encountered during this lookup process.

3. **Analyze Function Logic:** Briefly examine what each key function seems to do:
    * `DeleteProperty`:  Deletes a property from an object.
    * `TransitionToAccessorProperty`:  Changes a property to an accessor (getter/setter).
    * `FetchValue`: Retrieves the value of a property.
    * `WriteDataValue`: Sets the value of a data property.
    * `LookupInRegularHolder`:  Looks for a property in the object's own properties.

4. **Relate to JavaScript Concepts:** Connect the C++ code to corresponding JavaScript concepts:
    * "Deleting a property" in C++ maps directly to the `delete` operator in JavaScript.
    * "Accessor properties" in C++ are the same as getter/setter functions in JavaScript.
    * "Fetching a value" corresponds to accessing a property using dot notation (`object.property`) or bracket notation (`object['property']`).
    * "Writing a data value" corresponds to assigning a value to a property.

5. **Identify Potential Torque (.tq) Relationship:**  The prompt mentions `.tq` files. Although this snippet is `.cc`, I need to remember that some parts of V8's object model and property access might be defined in Torque and then used here.

6. **Consider Error Scenarios:** Think about common JavaScript programming errors related to properties (e.g., trying to delete non-configurable properties).

7. **Code Logic Inference:** Look for conditional logic (like `if/else`) and how it branches based on object state (e.g., fast vs. slow properties, prototype maps).

8. **Focus on Summarization:**  The request specifically asks for a summary of the *functionality*. I should avoid going into extreme detail about the implementation.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* v8/src/objects/lookup.cc以.tq结尾: No (this snippet is .cc, but the prompt requires me to acknowledge the possibility and its implication)
* v8 torque源代码: No (for this snippet)
* 与javascript的功能有关系: Yes
* 用javascript举例说明: Yes
* 代码逻辑推理: Yes
* 给出假设输入与输出: Yes (simple cases)
* 涉及用户常见的编程错误: Yes
* 举例说明: Yes
* 这是第2部分，共3部分: Acknowledge this.
* 请归纳一下它的功能: Yes

Confidence Score: 5/5 - I can confidently address all the requirements based on the code snippet.

**Mental Sandbox Simulation:**

I imagine a user trying to access a property on a JavaScript object. The `LookupIterator` steps through the object's properties, its prototype chain, and potentially uses interceptors to find the requested property. I also see functions that modify the object's property structure (like changing a regular property to an accessor). The code seems designed for efficiency, with distinctions between "fast" and "slow" properties.

Strategizing complete. I will now generate the response based on the above analysis.
这是 `v8/src/objects/lookup.cc` 源代码的第二部分，其主要功能是**实现 JavaScript 对象的属性查找和操作的迭代器 `LookupIterator` 的核心逻辑**。  它定义了如何在 V8 引擎内部查找、获取、设置和删除 JavaScript 对象的属性，并处理各种复杂的情况，例如原型链、访问器属性、拦截器等。

**功能归纳:**

延续第一部分的 `LookupIterator` 初始化和状态管理，第二部分主要关注以下功能：

1. **属性删除 (`DeleteProperty`)**:
   - 提供了删除对象自身属性的逻辑。
   - 区分了快属性（在对象自身布局中）和慢属性（存储在字典中）的删除方式。
   - 对于原型对象上的删除操作，会进行特定的性能计数和优化。
   - 如果对象具有快速属性，可能会触发属性的规范化（`NormalizeProperties`）。
   - 删除后可能会触发原型链的重新优化 (`ReoptimizeIfPrototype`).

2. **转换为访问器属性 (`TransitionToAccessorProperty`, `TransitionToAccessorPair`)**:
   - 允许将一个数据属性转换为访问器属性（包含 getter 和 setter 函数）。
   - 处理不同情况下的转换，包括：
     -  Receiver 对象是自身 holder。
     -  需要更新 Map 信息。
     -  处理已存在的访问器属性，避免重复创建。
   - 如果 receiver 不是字典模式，会尝试进行 Map 转换以存储访问器信息。
   - 如果 receiver 是字典模式，则直接在字典中设置访问器。
   - 涉及到 `AccessorPair` 对象的创建和管理。
   - 对于数组索引，会使用 `NumberDictionary` 来存储访问器。

3. **属性值获取 (`FetchValue`)**:
   - 根据当前迭代器的状态（属性的位置和类型）获取属性值。
   - 处理不同类型的属性存储位置：
     -  元素 (Elements)：在对象的元素存储区查找。
     -  全局对象 (JSGlobalObject)：在全局字典中查找。
     -  快速属性：直接从对象的字段中读取。
     -  慢属性（字典）：从属性字典中读取。
     -  描述符 (Descriptor)：从 Map 的描述符数组中读取。
   - 针对 double 类型的字段，在禁止分配内存的情况下，可能会返回 undefined。

4. **常量属性检查 (`CanStayConst`, `DictCanStayConst`)**:
   - 用于检查一个属性是否可以保持常量状态。这通常用于对象字面量初始化等场景。
   - 区分了快速属性和慢属性（字典属性）的检查逻辑。
   - 考虑了未初始化值的情况。
   - 对于 double 类型的快速属性，会检查当前值是否是 hole 值，以允许初始化赋值。

5. **获取属性信息的索引 (`GetFieldDescriptorIndex`, `GetAccessorIndex`, `GetFieldIndex`)**:
   - 提供了获取属性在对象内部存储结构中索引的方法。
   - 根据属性的类型（字段、访问器）和存储位置（快速、慢速）返回不同的索引。

6. **获取 PropertyCell (`GetPropertyCell`)**:
   - 用于获取全局对象属性的 `PropertyCell`，其中存储了属性的值和元数据。

7. **获取访问器 (`GetAccessors`) 和数据值 (`GetDataValue`)**:
   - 提供了便捷的方法来获取当前迭代器指向的访问器对象或数据值。
   - `GetDataValue` 可以指定内存分配策略，用于避免在某些性能敏感的场景中触发垃圾回收。
   - 提供了针对共享数组/结构体的原子操作版本 (`GetDataValue(SeqCstAccessTag)`)。

8. **写入数据值 (`WriteDataValue`)**:
   - 提供设置属性值的逻辑。
   - 区分了不同类型的对象和属性存储方式：
     -  元素：使用 `ElementsAccessor` 设置。
     -  快速属性：直接写入对象的字段。
     -  全局对象：写入到 `PropertyCell`。
     -  慢属性（字典）：写入到属性字典。
   - 对于常量属性，在非初始化赋值时会进行额外的检查。
   - 提供了针对共享数组/结构体的原子写入版本 (`WriteDataValue(SeqCstAccessTag)`)。

9. **原子交换和比较交换 (`SwapDataValue`, `CompareAndSwapDataValue`)**:
   - 提供了针对共享数组/结构体的原子操作，用于并发编程。

10. **拦截器处理 (`SkipInterceptor`)**:
    -  在属性查找过程中，如果遇到拦截器（interceptor），会根据拦截器的类型和状态决定是否跳过。
    -  区分了命名拦截器和索引拦截器。
    -  考虑了符号属性和私有属性的拦截。

11. **原型链遍历 (`NextHolder`)**:
    -  提供了遍历原型链以查找属性的方法。
    -  如果禁用了原型链检查，或者当前 Map 是全局代理的 Map，则不会继续向上查找。

12. **未找到属性的处理 (`NotFound`)**:
    -  定义了当属性未找到时的处理逻辑。
    -  对于 `TypedArray`，会区分是索引未找到还是属性名未找到。

13. **在特定 Holder 中查找 (`LookupInSpecialHolder`, `LookupInRegularHolder`)**:
    -  `LookupInSpecialHolder` 处理一些特殊类型的 Holder，例如代理对象 (JSProxy)、WebAssembly 对象 (WasmObject) 以及需要访问权限检查的对象。
    -  `LookupInRegularHolder` 处理普通 JavaScript 对象的属性查找，区分了元素属性和命名属性，以及快速属性和慢速属性。

14. **内部标记属性检查 (`HasInternalMarkerProperty`)**:
    -  提供了一个静态方法来检查对象是否具有特定的内部标记属性。

15. **获取访问检查失败的拦截器 (`GetInterceptorForFailedAccessCheck`)**:
    -  当访问检查失败时，尝试获取相应的拦截器信息。

16. **查找缓存的属性 (`TryLookupCachedProperty`)**:
    -  尝试利用 V8 的缓存机制来加速属性查找，特别是对于访问器属性。
    -  检查 holder 是否是 receiver 或其隐藏原型，以及 lookup 的起始对象是否一致。
    -  对于 getter 是 `JSFunction` 的情况，会进行额外的校验。

17. **并发查找优化 (`ConcurrentLookupIterator::TryGetOwnCowElement`, `ConcurrentLookupIterator::TryGetOwnConstantElement`)**:
    -  提供了一些针对并发场景下的属性查找优化，例如针对 Copy-on-Write 数组和常量元素的查找。
    -  这些方法使用了原子操作和无锁技术来保证线程安全。

**如果 `v8/src/objects/lookup.cc` 以 `.tq` 结尾:**

如果 `v8/src/objects/lookup.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是一种用于 V8 内部实现的领域特定语言，它允许开发者以更类型安全和更接近硬件的方式编写代码。

在这种情况下，文件中的代码将不再是 C++，而是 Torque 代码。 Torque 代码会被编译成 C++ 代码，然后参与 V8 的编译过程。  通常，Torque 用于实现一些核心的、性能关键的操作，例如对象的创建、属性的访问等。

**与 JavaScript 的功能关系及举例:**

`v8/src/objects/lookup.cc` (或其可能的 `.tq` 版本) 中的代码直接支撑着 JavaScript 中对象属性的各种操作。以下是一些 JavaScript 例子，以及它们在 V8 内部如何与 `LookupIterator` 相关联：

```javascript
const obj = { a: 1, get b() { return this.a + 1; } };

// 属性访问
console.log(obj.a); // LookupIterator 会查找 'a' 属性，并返回其值 1
console.log(obj.b); // LookupIterator 会找到 'b' 是一个访问器，并执行其 getter 函数

// 属性设置
obj.a = 2;         // LookupIterator 会找到 'a' 属性，并设置其值为 2

// 属性删除
delete obj.a;      // LookupIterator 的 DeleteProperty 方法会被调用

// 判断属性是否存在
console.log('b' in obj); // LookupIterator 会在 obj 及其原型链上查找 'b'

// 获取对象的所有属性
for (let key in obj) {
  console.log(key); // LookupIterator 用于遍历对象的属性
}

// 定义访问器属性
Object.defineProperty(obj, 'c', {
  get() { return 10; },
  set(value) { console.log('设置 c 为', value); }
}); // LookupIterator 的 TransitionToAccessorProperty 方法会被间接调用
```

**代码逻辑推理及假设输入输出:**

假设有以下 JavaScript 对象和代码：

```javascript
const proto = { p: 10 };
const obj = Object.create(proto);
obj.a = 5;
```

现在，在 V8 内部执行 `console.log(obj.a)` 时，`LookupIterator` 的行为可能如下：

**假设输入:**
- `receiver_`:  指向 `obj` 对象的句柄。
- `name_`:  指向字符串 "a" 的句柄。

**执行步骤:**
1. `LookupIterator` 初始化，从 `obj` 开始查找 "a"。
2. `LookupInRegularHolder` 被调用，在 `obj` 自身的属性中查找。
3. 找到属性 "a"，类型为数据属性，值为 5。
4. `FetchValue` 被调用，返回属性值 5。

**输出:**
- `FetchValue` 返回指向数字 5 的句柄。

如果执行 `console.log(obj.p)`：

**假设输入:**
- `receiver_`: 指向 `obj` 对象的句柄。
- `name_`: 指向字符串 "p" 的句柄。

**执行步骤:**
1. `LookupIterator` 初始化，从 `obj` 开始查找 "p"。
2. `LookupInRegularHolder` 被调用，在 `obj` 自身的属性中查找，未找到。
3. `NextHolder` 被调用，移动到 `obj` 的原型 `proto`。
4. `LookupInRegularHolder` 被调用，在 `proto` 的属性中查找。
5. 找到属性 "p"，类型为数据属性，值为 10。
6. `FetchValue` 被调用，返回属性值 10。

**输出:**
- `FetchValue` 返回指向数字 10 的句柄。

**用户常见的编程错误:**

1. **尝试删除不可配置的属性:**
   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'x', { value: 1, configurable: false });
   delete obj.x; // 在严格模式下会抛出 TypeError，非严格模式下返回 false
   ```
   `LookupIterator::DeleteProperty` 会检查属性的 `configurable` 属性，如果为 `false` 则不会删除。

2. **误解原型链的查找顺序:**
   ```javascript
   const proto = { a: 1 };
   const obj = Object.create(proto);
   obj.a = 2;
   console.log(obj.a); // 输出 2，因为 obj 自身有属性 'a'，屏蔽了原型上的 'a'
   ```
   `LookupIterator` 会先在对象自身查找，然后再到原型链上查找。

3. **在不期望的情况下访问到原型链上的属性:**
   ```javascript
   const Parent = function() { this.name = 'parent'; };
   const Child = function() { this.age = 10; };
   Child.prototype = new Parent();
   const child = new Child();
   console.log(child.name); // 输出 'parent'
   ```
   `LookupIterator` 会沿着 `child` 的原型链找到 `name` 属性。

4. **忘记处理 `in` 操作符和 `hasOwnProperty` 的区别:**
   ```javascript
   const proto = { a: 1 };
   const obj = Object.create(proto);
   console.log('a' in obj); // 输出 true，因为原型链上有 'a'
   console.log(obj.hasOwnProperty('a')); // 输出 false，因为 'a' 不是 obj 自身的属性
   ```
   `LookupIterator` 在实现 `in` 操作符时会遍历原型链，而 `hasOwnProperty` 只检查对象自身的属性。

这部分 `v8/src/objects/lookup.cc` 代码是 V8 引擎实现 JavaScript 对象模型和属性操作的核心组成部分。它处理了属性查找的各种复杂情况，并为 JavaScript 代码的正确执行提供了基础。

Prompt: 
```
这是目录为v8/src/objects/lookup.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/lookup.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
mber_);
  } else {
    DCHECK(!name()->IsPrivateName());
    bool is_prototype_map = holder->map(isolate_)->is_prototype_map();
    RCS_SCOPE(isolate_,
              is_prototype_map
                  ? RuntimeCallCounterId::kPrototypeObject_DeleteProperty
                  : RuntimeCallCounterId::kObject_DeleteProperty);

    PropertyNormalizationMode mode =
        is_prototype_map ? KEEP_INOBJECT_PROPERTIES : CLEAR_INOBJECT_PROPERTIES;

    if (holder->HasFastProperties(isolate_)) {
      JSObject::NormalizeProperties(isolate_, Cast<JSObject>(holder), mode, 0,
                                    "DeletingProperty");
      ReloadPropertyInformation<false>();
    }
    JSReceiver::DeleteNormalizedProperty(holder, dictionary_entry());
    if (IsJSObject(*holder, isolate_)) {
      JSObject::ReoptimizeIfPrototype(Cast<JSObject>(holder));
    }
  }
  state_ = NOT_FOUND;
}

void LookupIterator::TransitionToAccessorProperty(
    DirectHandle<Object> getter, DirectHandle<Object> setter,
    PropertyAttributes attributes) {
  DCHECK(!IsNull(*getter, isolate_) || !IsNull(*setter, isolate_));
  // Can only be called when the receiver is a JSObject. JSProxy has to be
  // handled via a trap. Adding properties to primitive values is not
  // observable.
  Handle<JSObject> receiver = GetStoreTarget<JSObject>();
  if (!IsElement() && name()->IsPrivate()) {
    attributes = static_cast<PropertyAttributes>(attributes | DONT_ENUM);
  }

  if (!IsElement(*receiver) && !receiver->map(isolate_)->is_dictionary_map()) {
    Handle<Map> old_map(receiver->map(isolate_), isolate_);

    if (!holder_.is_identical_to(receiver)) {
      holder_ = receiver;
      state_ = NOT_FOUND;
    } else if (state_ == INTERCEPTOR) {
      LookupInRegularHolder<false>(*old_map, *holder_);
    }
    // The case of IsFound() && number_.is_not_found() can occur for
    // interceptors.
    DCHECK_IMPLIES(!IsFound(), number_.is_not_found());

    DirectHandle<Map> new_map = Map::TransitionToAccessorProperty(
        isolate_, old_map, name_, number_, getter, setter, attributes);
    bool simple_transition =
        new_map->GetBackPointer(isolate_) == receiver->map(isolate_);
    JSObject::MigrateToMap(isolate_, receiver, new_map);

    if (simple_transition) {
      number_ = new_map->LastAdded();
      property_details_ = new_map->GetLastDescriptorDetails(isolate_);
      state_ = ACCESSOR;
      return;
    }

    ReloadPropertyInformation<false>();
    if (!new_map->is_dictionary_map()) return;
  }

  Handle<AccessorPair> pair;
  if (state() == ACCESSOR && IsAccessorPair(*GetAccessors(), isolate_)) {
    pair = Cast<AccessorPair>(GetAccessors());
    // If the component and attributes are identical, nothing has to be done.
    if (pair->Equals(*getter, *setter)) {
      if (property_details().attributes() == attributes) {
        if (!IsElement(*receiver)) JSObject::ReoptimizeIfPrototype(receiver);
        return;
      }
    } else {
      pair = AccessorPair::Copy(isolate(), pair);
      pair->SetComponents(*getter, *setter);
    }
  } else {
    pair = factory()->NewAccessorPair();
    pair->SetComponents(*getter, *setter);
  }

  TransitionToAccessorPair(pair, attributes);

#if VERIFY_HEAP
  if (v8_flags.verify_heap) {
    receiver->JSObjectVerify(isolate());
  }
#endif
}

void LookupIterator::TransitionToAccessorPair(Handle<Object> pair,
                                              PropertyAttributes attributes) {
  Handle<JSObject> receiver = GetStoreTarget<JSObject>();
  holder_ = receiver;

  PropertyDetails details(PropertyKind::kAccessor, attributes,
                          PropertyCellType::kMutable);

  if (IsElement(*receiver)) {
    // TODO(verwaest): Move code into the element accessor.
    isolate_->CountUsage(v8::Isolate::kIndexAccessor);
    Handle<NumberDictionary> dictionary = JSObject::NormalizeElements(receiver);

    dictionary = NumberDictionary::Set(isolate_, dictionary, array_index(),
                                       pair, receiver, details);
    receiver->RequireSlowElements(*dictionary);

    if (receiver->HasSlowArgumentsElements(isolate_)) {
      Tagged<SloppyArgumentsElements> parameter_map =
          Cast<SloppyArgumentsElements>(receiver->elements(isolate_));
      uint32_t length = parameter_map->length();
      if (number_.is_found() && number_.as_uint32() < length) {
        parameter_map->set_mapped_entries(
            number_.as_int(), ReadOnlyRoots(isolate_).the_hole_value());
      }
      parameter_map->set_arguments(*dictionary);
    } else {
      receiver->set_elements(*dictionary);
    }

    ReloadPropertyInformation<true>();
  } else {
    PropertyNormalizationMode mode = CLEAR_INOBJECT_PROPERTIES;
    if (receiver->map(isolate_)->is_prototype_map()) {
      JSObject::InvalidatePrototypeChains(receiver->map(isolate_));
      mode = KEEP_INOBJECT_PROPERTIES;
    }

    // Normalize object to make this operation simple.
    JSObject::NormalizeProperties(isolate_, receiver, mode, 0,
                                  "TransitionToAccessorPair");

    JSObject::SetNormalizedProperty(receiver, name_, pair, details);
    JSObject::ReoptimizeIfPrototype(receiver);

    ReloadPropertyInformation<false>();
  }
}

bool LookupIterator::HolderIsReceiver() const {
  DCHECK(has_property_ || state_ == INTERCEPTOR || state_ == JSPROXY);
  // Optimization that only works if configuration_ is not mutable.
  if (!check_prototype_chain()) return true;
  return *receiver_ == *holder_;
}

bool LookupIterator::HolderIsReceiverOrHiddenPrototype() const {
  DCHECK(has_property_ || state_ == INTERCEPTOR || state_ == JSPROXY);
  // Optimization that only works if configuration_ is not mutable.
  if (!check_prototype_chain()) return true;
  if (*receiver_ == *holder_) return true;
  if (!IsJSGlobalProxy(*receiver_, isolate_)) return false;
  return Cast<JSGlobalProxy>(receiver_)->map(isolate_)->prototype(isolate_) ==
         *holder_;
}

Handle<Object> LookupIterator::FetchValue(
    AllocationPolicy allocation_policy) const {
  Tagged<Object> result;
  DCHECK(!IsWasmObject(*holder_));
  if (IsElement(*holder_)) {
    Handle<JSObject> holder = GetHolder<JSObject>();
    ElementsAccessor* accessor = holder->GetElementsAccessor(isolate_);
    return accessor->Get(isolate_, holder, number_);
  } else if (IsJSGlobalObject(*holder_, isolate_)) {
    DirectHandle<JSGlobalObject> holder = GetHolder<JSGlobalObject>();
    result = holder->global_dictionary(isolate_, kAcquireLoad)
                 ->ValueAt(isolate_, dictionary_entry());
  } else if (!holder_->HasFastProperties(isolate_)) {
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      result = holder_->property_dictionary_swiss(isolate_)->ValueAt(
          dictionary_entry());
    } else {
      result = holder_->property_dictionary(isolate_)->ValueAt(
          isolate_, dictionary_entry());
    }
  } else if (property_details_.location() == PropertyLocation::kField) {
    DCHECK_EQ(PropertyKind::kData, property_details_.kind());
    DirectHandle<JSObject> holder = GetHolder<JSObject>();
    FieldIndex field_index =
        FieldIndex::ForDetails(holder->map(isolate_), property_details_);
    if (allocation_policy == AllocationPolicy::kAllocationDisallowed &&
        field_index.is_inobject() && field_index.is_double()) {
      return isolate_->factory()->undefined_value();
    }
    return JSObject::FastPropertyAt(
        isolate_, holder, property_details_.representation(), field_index);
  } else {
    result =
        holder_->map(isolate_)->instance_descriptors(isolate_)->GetStrongValue(
            isolate_, descriptor_number());
  }
  return handle(result, isolate_);
}

bool LookupIterator::CanStayConst(Tagged<Object> value) const {
  DCHECK(!holder_.is_null());
  DCHECK(!IsElement(*holder_));
  DCHECK(holder_->HasFastProperties(isolate_));
  DCHECK_EQ(PropertyLocation::kField, property_details_.location());
  DCHECK_EQ(PropertyConstness::kConst, property_details_.constness());
  if (IsUninitialized(value, isolate())) {
    // Storing uninitialized value means that we are preparing for a computed
    // property value in an object literal. The initializing store will follow
    // and it will properly update constness based on the actual value.
    return true;
  }
  DirectHandle<JSObject> holder = GetHolder<JSObject>();
  FieldIndex field_index =
      FieldIndex::ForDetails(holder->map(isolate_), property_details_);
  if (property_details_.representation().IsDouble()) {
    if (!IsNumber(value, isolate_)) return false;
    uint64_t bits;
    Tagged<Object> current_value =
        holder->RawFastPropertyAt(isolate_, field_index);
    DCHECK(IsHeapNumber(current_value, isolate_));
    bits = Cast<HeapNumber>(current_value)->value_as_bits();
    // Use bit representation of double to check for hole double, since
    // manipulating the signaling NaN used for the hole in C++, e.g. with
    // base::bit_cast or value(), will change its value on ia32 (the x87
    // stack is used to return values and stores to the stack silently clear the
    // signalling bit).
    // Only allow initializing stores to double to stay constant.
    return bits == kHoleNanInt64;
  }

  Tagged<Object> current_value =
      holder->RawFastPropertyAt(isolate_, field_index);
  return IsUninitialized(current_value, isolate());
}

bool LookupIterator::DictCanStayConst(Tagged<Object> value) const {
  DCHECK(!holder_.is_null());
  DCHECK(!IsElement(*holder_));
  DCHECK(!holder_->HasFastProperties(isolate_));
  DCHECK(!IsJSGlobalObject(*holder_));
  DCHECK(!IsJSProxy(*holder_));
  DCHECK_EQ(PropertyConstness::kConst, property_details_.constness());

  DisallowHeapAllocation no_gc;

  if (IsUninitialized(value, isolate())) {
    // Storing uninitialized value means that we are preparing for a computed
    // property value in an object literal. The initializing store will follow
    // and it will properly update constness based on the actual value.
    return true;
  }
  DirectHandle<JSReceiver> holder = GetHolder<JSReceiver>();
  Tagged<Object> current_value;
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    Tagged<SwissNameDictionary> dict = holder->property_dictionary_swiss();
    current_value = dict->ValueAt(dictionary_entry());
  } else {
    Tagged<NameDictionary> dict = holder->property_dictionary();
    current_value = dict->ValueAt(dictionary_entry());
  }

  return IsUninitialized(current_value, isolate());
}

int LookupIterator::GetFieldDescriptorIndex() const {
  DCHECK(has_property_);
  DCHECK(holder_->HasFastProperties());
  DCHECK_EQ(PropertyLocation::kField, property_details_.location());
  DCHECK_EQ(PropertyKind::kData, property_details_.kind());
  // TODO(jkummerow): Propagate InternalIndex further.
  return descriptor_number().as_int();
}

int LookupIterator::GetAccessorIndex() const {
  DCHECK(has_property_);
  DCHECK(holder_->HasFastProperties(isolate_));
  DCHECK_EQ(PropertyLocation::kDescriptor, property_details_.location());
  DCHECK_EQ(PropertyKind::kAccessor, property_details_.kind());
  return descriptor_number().as_int();
}

FieldIndex LookupIterator::GetFieldIndex() const {
  DCHECK(has_property_);
  DCHECK(!holder_.is_null());
  DCHECK(holder_->HasFastProperties(isolate_));
  DCHECK_EQ(PropertyLocation::kField, property_details_.location());
  DCHECK(!IsElement(*holder_));
  return FieldIndex::ForDetails(holder_->map(isolate_), property_details_);
}

Handle<PropertyCell> LookupIterator::GetPropertyCell() const {
  DCHECK(!holder_.is_null());
  DCHECK(!IsElement(*holder_));
  DirectHandle<JSGlobalObject> holder = GetHolder<JSGlobalObject>();
  return handle(holder->global_dictionary(isolate_, kAcquireLoad)
                    ->CellAt(isolate_, dictionary_entry()),
                isolate_);
}

Handle<Object> LookupIterator::GetAccessors() const {
  DCHECK_EQ(ACCESSOR, state_);
  return FetchValue();
}

Handle<Object> LookupIterator::GetDataValue(
    AllocationPolicy allocation_policy) const {
  DCHECK_EQ(DATA, state_);
  Handle<Object> value = FetchValue(allocation_policy);
  return value;
}

Handle<Object> LookupIterator::GetDataValue(SeqCstAccessTag tag) const {
  DCHECK_EQ(DATA, state_);
  // Currently only shared structs and arrays support sequentially consistent
  // access.
  DCHECK(IsJSSharedStruct(*holder_, isolate_) ||
         IsJSSharedArray(*holder_, isolate_));
  Handle<JSObject> holder = GetHolder<JSObject>();
  if (IsElement(*holder)) {
    ElementsAccessor* accessor = holder->GetElementsAccessor(isolate_);
    return accessor->GetAtomic(isolate_, holder, number_, kSeqCstAccess);
  }
  DCHECK_EQ(PropertyLocation::kField, property_details_.location());
  DCHECK_EQ(PropertyKind::kData, property_details_.kind());
  FieldIndex field_index =
      FieldIndex::ForDetails(holder->map(isolate_), property_details_);
  return JSObject::FastPropertyAt(
      isolate_, holder, property_details_.representation(), field_index, tag);
}

void LookupIterator::WriteDataValue(DirectHandle<Object> value,
                                    bool initializing_store) {
  DCHECK_EQ(DATA, state_);
  // WriteDataValueToWasmObject() must be used instead for writing to
  // WasmObjects.
  DCHECK(!IsWasmObject(*holder_, isolate_));
  DCHECK_IMPLIES(IsJSSharedStruct(*holder_), IsShared(*value));

  Handle<JSReceiver> holder = GetHolder<JSReceiver>();
  if (IsElement(*holder)) {
    Handle<JSObject> object = Cast<JSObject>(holder);
    ElementsAccessor* accessor = object->GetElementsAccessor(isolate_);
    accessor->Set(object, number_, *value);
  } else if (holder->HasFastProperties(isolate_)) {
    DCHECK(IsJSObject(*holder, isolate_));
    if (property_details_.location() == PropertyLocation::kField) {
      // Check that in case of VariableMode::kConst field the existing value is
      // equal to |value|.
      DCHECK_IMPLIES(!initializing_store && property_details_.constness() ==
                                                PropertyConstness::kConst,
                     CanStayConst(*value));
      Cast<JSObject>(*holder)->WriteToField(descriptor_number(),
                                            property_details_, *value);
    } else {
      DCHECK_EQ(PropertyLocation::kDescriptor, property_details_.location());
      DCHECK_EQ(PropertyConstness::kConst, property_details_.constness());
    }
  } else if (IsJSGlobalObject(*holder, isolate_)) {
    // PropertyCell::PrepareForAndSetValue already wrote the value into the
    // cell.
#ifdef DEBUG
    Tagged<GlobalDictionary> dictionary =
        Cast<JSGlobalObject>(*holder)->global_dictionary(isolate_,
                                                         kAcquireLoad);
    Tagged<PropertyCell> cell =
        dictionary->CellAt(isolate_, dictionary_entry());
    DCHECK(cell->value() == *value ||
           (IsString(cell->value()) && IsString(*value) &&
            Cast<String>(cell->value())->Equals(Cast<String>(*value))));
#endif  // DEBUG
  } else {
    DCHECK_IMPLIES(IsJSProxy(*holder, isolate_), name()->IsPrivate());
    // Check similar to fast mode case above.
    DCHECK_IMPLIES(
        V8_DICT_PROPERTY_CONST_TRACKING_BOOL && !initializing_store &&
            property_details_.constness() == PropertyConstness::kConst,
        IsJSProxy(*holder, isolate_) || DictCanStayConst(*value));

    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      Tagged<SwissNameDictionary> dictionary =
          holder->property_dictionary_swiss(isolate_);
      dictionary->ValueAtPut(dictionary_entry(), *value);
    } else {
      Tagged<NameDictionary> dictionary = holder->property_dictionary(isolate_);
      dictionary->ValueAtPut(dictionary_entry(), *value);
    }
  }
}

void LookupIterator::WriteDataValue(DirectHandle<Object> value,
                                    SeqCstAccessTag tag) {
  DCHECK_EQ(DATA, state_);
  // Currently only shared structs and arrays support sequentially consistent
  // access.
  DCHECK(IsJSSharedStruct(*holder_, isolate_) ||
         IsJSSharedArray(*holder_, isolate_));
  Handle<JSObject> holder = GetHolder<JSObject>();
  if (IsElement(*holder)) {
    ElementsAccessor* accessor = holder->GetElementsAccessor(isolate_);
    accessor->SetAtomic(holder, number_, *value, kSeqCstAccess);
    return;
  }
  DCHECK_EQ(PropertyLocation::kField, property_details_.location());
  DCHECK_EQ(PropertyKind::kData, property_details_.kind());
  DisallowGarbageCollection no_gc;
  FieldIndex field_index =
      FieldIndex::ForDescriptor(holder->map(isolate_), descriptor_number());
  holder->FastPropertyAtPut(field_index, *value, tag);
}

Handle<Object> LookupIterator::SwapDataValue(DirectHandle<Object> value,
                                             SeqCstAccessTag tag) {
  DCHECK_EQ(DATA, state_);
  // Currently only shared structs and arrays support sequentially consistent
  // access.
  DCHECK(IsJSSharedStruct(*holder_, isolate_) ||
         IsJSSharedArray(*holder_, isolate_));
  Handle<JSObject> holder = GetHolder<JSObject>();
  if (IsElement(*holder)) {
    ElementsAccessor* accessor = holder->GetElementsAccessor(isolate_);
    return accessor->SwapAtomic(isolate_, holder, number_, *value,
                                kSeqCstAccess);
  }
  DCHECK_EQ(PropertyLocation::kField, property_details_.location());
  DCHECK_EQ(PropertyKind::kData, property_details_.kind());
  DisallowGarbageCollection no_gc;
  FieldIndex field_index =
      FieldIndex::ForDescriptor(holder->map(isolate_), descriptor_number());
  return handle(holder->RawFastPropertyAtSwap(field_index, *value, tag),
                isolate_);
}

Handle<Object> LookupIterator::CompareAndSwapDataValue(
    DirectHandle<Object> expected, DirectHandle<Object> value,
    SeqCstAccessTag tag) {
  DCHECK_EQ(DATA, state_);
  // Currently only shared structs and arrays support sequentially consistent
  // access.
  DCHECK(IsJSSharedStruct(*holder_, isolate_) ||
         IsJSSharedArray(*holder_, isolate_));
  DisallowGarbageCollection no_gc;
  Handle<JSObject> holder = GetHolder<JSObject>();
  if (IsElement(*holder)) {
    ElementsAccessor* accessor = holder->GetElementsAccessor(isolate_);
    return accessor->CompareAndSwapAtomic(isolate_, holder, number_, *expected,
                                          *value, kSeqCstAccess);
  }
  DCHECK_EQ(PropertyLocation::kField, property_details_.location());
  DCHECK_EQ(PropertyKind::kData, property_details_.kind());
  FieldIndex field_index =
      FieldIndex::ForDescriptor(holder->map(isolate_), descriptor_number());
  return handle(holder->RawFastPropertyAtCompareAndSwap(field_index, *expected,
                                                        *value, tag),
                isolate_);
}

template <bool is_element>
bool LookupIterator::SkipInterceptor(Tagged<JSObject> holder) {
  Tagged<InterceptorInfo> info = GetInterceptor<is_element>(holder);
  if (!is_element && IsSymbol(*name_, isolate_) &&
      !info->can_intercept_symbols()) {
    return true;
  }
  if (info->non_masking()) {
    switch (interceptor_state_) {
      case InterceptorState::kUninitialized:
        interceptor_state_ = InterceptorState::kSkipNonMasking;
        [[fallthrough]];
      case InterceptorState::kSkipNonMasking:
        return true;
      case InterceptorState::kProcessNonMasking:
        return false;
    }
  }
  return interceptor_state_ == InterceptorState::kProcessNonMasking;
}

Tagged<JSReceiver> LookupIterator::NextHolder(Tagged<Map> map) {
  DisallowGarbageCollection no_gc;
  if (map->prototype(isolate_) == ReadOnlyRoots(isolate_).null_value()) {
    return JSReceiver();
  }
  if (!check_prototype_chain() && !IsJSGlobalProxyMap(map)) {
    return JSReceiver();
  }
  return Cast<JSReceiver>(map->prototype(isolate_));
}

LookupIterator::State LookupIterator::NotFound(
    Tagged<JSReceiver> const holder) const {
  if (!IsJSTypedArray(holder, isolate_)) return NOT_FOUND;
  if (IsElement()) return TYPED_ARRAY_INDEX_NOT_FOUND;
  if (!IsString(*name_, isolate_)) return NOT_FOUND;
  return IsSpecialIndex(Cast<String>(*name_)) ? TYPED_ARRAY_INDEX_NOT_FOUND
                                              : NOT_FOUND;
}

namespace {

template <bool is_element>
bool HasInterceptor(Tagged<Map> map, size_t index) {
  if (is_element) {
    if (index > JSObject::kMaxElementIndex) {
      // There is currently no way to install interceptors on an object with
      // typed array elements.
      DCHECK(!map->has_typed_array_or_rab_gsab_typed_array_elements());
      return map->has_named_interceptor();
    }
    return map->has_indexed_interceptor();
  } else {
    return map->has_named_interceptor();
  }
}

}  // namespace

template <bool is_element>
LookupIterator::State LookupIterator::LookupInSpecialHolder(
    Tagged<Map> const map, Tagged<JSReceiver> const holder) {
  static_assert(INTERCEPTOR == BEFORE_PROPERTY);
  switch (state_) {
    case NOT_FOUND:
      if (IsJSProxyMap(map)) {
        if (is_element || !name_->IsPrivate()) return JSPROXY;
      }
#if V8_ENABLE_WEBASSEMBLY
      if (IsWasmObjectMap(map)) return WASM_OBJECT;
#endif  // V8_ENABLE_WEBASSEMBLY
      if (map->is_access_check_needed()) {
        if (is_element || !name_->IsPrivate() || name_->IsPrivateName())
          return ACCESS_CHECK;
      }
      [[fallthrough]];
    case ACCESS_CHECK:
      if (check_interceptor() && HasInterceptor<is_element>(map, index_) &&
          !SkipInterceptor<is_element>(Cast<JSObject>(holder))) {
        if (is_element || !name_->IsPrivate()) return INTERCEPTOR;
      }
      [[fallthrough]];
    case INTERCEPTOR:
      if (IsJSGlobalObjectMap(map) && !is_js_array_element(is_element)) {
        Tagged<GlobalDictionary> dict =
            Cast<JSGlobalObject>(holder)->global_dictionary(isolate_,
                                                            kAcquireLoad);
        number_ = dict->FindEntry(isolate(), name_);
        if (number_.is_not_found()) return NOT_FOUND;
        Tagged<PropertyCell> cell = dict->CellAt(isolate_, number_);
        if (IsPropertyCellHole(cell->value(isolate_), isolate_)) {
          return NOT_FOUND;
        }
        property_details_ = cell->property_details();
        has_property_ = true;
        switch (property_details_.kind()) {
          case v8::internal::PropertyKind::kData:
            return DATA;
          case v8::internal::PropertyKind::kAccessor:
            return ACCESSOR;
        }
      }
      return LookupInRegularHolder<is_element>(map, holder);
    case ACCESSOR:
    case DATA:
      return NOT_FOUND;
    case TYPED_ARRAY_INDEX_NOT_FOUND:
    case JSPROXY:
    case WASM_OBJECT:
    case TRANSITION:
      UNREACHABLE();
  }
  UNREACHABLE();
}

template <bool is_element>
LookupIterator::State LookupIterator::LookupInRegularHolder(
    Tagged<Map> const map, Tagged<JSReceiver> const holder) {
  DisallowGarbageCollection no_gc;
  if (interceptor_state_ == InterceptorState::kProcessNonMasking) {
    return NOT_FOUND;
  }
  DCHECK(!IsWasmObject(holder, isolate_));
  if (is_element && IsElement(holder)) {
    Tagged<JSObject> js_object = Cast<JSObject>(holder);
    ElementsAccessor* accessor = js_object->GetElementsAccessor(isolate_);
    Tagged<FixedArrayBase> backing_store = js_object->elements(isolate_);
    number_ =
        accessor->GetEntryForIndex(isolate_, js_object, backing_store, index_);
    if (number_.is_not_found()) {
      return IsJSTypedArray(holder, isolate_) ? TYPED_ARRAY_INDEX_NOT_FOUND
                                              : NOT_FOUND;
    }
    property_details_ = accessor->GetDetails(js_object, number_);
    if (map->has_frozen_elements()) {
      property_details_ = property_details_.CopyAddAttributes(FROZEN);
    } else if (map->has_sealed_elements()) {
      property_details_ = property_details_.CopyAddAttributes(SEALED);
    }
  } else if (!map->is_dictionary_map()) {
    Tagged<DescriptorArray> descriptors = map->instance_descriptors(isolate_);
    number_ = descriptors->SearchWithCache(isolate_, *name_, map);
    if (number_.is_not_found()) return NotFound(holder);
    property_details_ = descriptors->GetDetails(number_);
  } else {
    DCHECK_IMPLIES(IsJSProxy(holder, isolate_), name()->IsPrivate());
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      Tagged<SwissNameDictionary> dict =
          holder->property_dictionary_swiss(isolate_);
      number_ = dict->FindEntry(isolate(), *name_);
      if (number_.is_not_found()) return NotFound(holder);
      property_details_ = dict->DetailsAt(number_);
    } else {
      Tagged<NameDictionary> dict = holder->property_dictionary(isolate_);
      number_ = dict->FindEntry(isolate(), name_);
      if (number_.is_not_found()) return NotFound(holder);
      property_details_ = dict->DetailsAt(number_);
    }
  }
  has_property_ = true;
  switch (property_details_.kind()) {
    case v8::internal::PropertyKind::kData:
      return DATA;
    case v8::internal::PropertyKind::kAccessor:
      return ACCESSOR;
  }

  UNREACHABLE();
}

// This is a specialization of function LookupInRegularHolder above
// which is tailored to test whether an object has an internal marker
// property.
// static
bool LookupIterator::HasInternalMarkerProperty(Isolate* isolate,
                                               Tagged<JSReceiver> const holder,
                                               Handle<Symbol> const marker) {
  DisallowGarbageCollection no_gc;
  Tagged<Map> map = holder->map(isolate);
  if (map->is_dictionary_map()) {
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      Tagged<SwissNameDictionary> dict =
          holder->property_dictionary_swiss(isolate);
      InternalIndex entry = dict->FindEntry(isolate, marker);
      return entry.is_found();
    } else {
      Tagged<NameDictionary> dict = holder->property_dictionary(isolate);
      InternalIndex entry = dict->FindEntry(isolate, marker);
      return entry.is_found();
    }
  } else {
    Tagged<DescriptorArray> descriptors = map->instance_descriptors(isolate);
    InternalIndex entry = descriptors->SearchWithCache(isolate, *marker, map);
    return entry.is_found();
  }
}

Handle<InterceptorInfo> LookupIterator::GetInterceptorForFailedAccessCheck()
    const {
  DCHECK_EQ(ACCESS_CHECK, state_);
  // Skip the interceptors for private
  if (IsPrivateName()) {
    return Handle<InterceptorInfo>();
  }

  DisallowGarbageCollection no_gc;
  Tagged<AccessCheckInfo> access_check_info =
      AccessCheckInfo::Get(isolate_, Cast<JSObject>(holder_));
  if (!access_check_info.is_null()) {
    // There is currently no way to create objects with typed array elements
    // and access checks.
    DCHECK(!holder_->map()->has_typed_array_or_rab_gsab_typed_array_elements());
    Tagged<Object> interceptor = is_js_array_element(IsElement())
                                     ? access_check_info->indexed_interceptor()
                                     : access_check_info->named_interceptor();
    if (interceptor != Tagged<Object>()) {
      return handle(Cast<InterceptorInfo>(interceptor), isolate_);
    }
  }
  return Handle<InterceptorInfo>();
}

bool LookupIterator::TryLookupCachedProperty(
    DirectHandle<AccessorPair> accessor) {
  DCHECK_EQ(state(), LookupIterator::ACCESSOR);
  return LookupCachedProperty(accessor);
}

bool LookupIterator::TryLookupCachedProperty() {
  if (state() != LookupIterator::ACCESSOR) return false;

  Handle<Object> accessor_pair = GetAccessors();
  return IsAccessorPair(*accessor_pair, isolate_) &&
         LookupCachedProperty(Cast<AccessorPair>(accessor_pair));
}

bool LookupIterator::LookupCachedProperty(
    DirectHandle<AccessorPair> accessor_pair) {
  if (!HolderIsReceiverOrHiddenPrototype()) return false;
  if (!lookup_start_object_.is_identical_to(receiver_) &&
      !lookup_start_object_.is_identical_to(holder_)) {
    return false;
  }

  DCHECK_EQ(state(), LookupIterator::ACCESSOR);
  DCHECK(IsAccessorPair(*GetAccessors(), isolate_));

  Tagged<Object> getter = accessor_pair->getter(isolate_);
  std::optional<Tagged<Name>> maybe_name =
      FunctionTemplateInfo::TryGetCachedPropertyName(isolate(), getter);
  if (!maybe_name.has_value()) return false;

  if (IsJSFunction(getter)) {
    // If the getter was a JSFunction there's no guarantee that the holder
    // actually has a property with the cached name. In that case look it up to
    // make sure.
    LookupIterator it(isolate_, holder_, handle(maybe_name.value(), isolate_));
    if (it.state() != DATA) return false;
    name_ = it.name();
  } else {
    name_ = handle(maybe_name.value(), isolate_);
  }

  // We have found a cached property! Modify the iterator accordingly.
  Restart();
  CHECK_EQ(state(), LookupIterator::DATA);
  return true;
}

// static
std::optional<Tagged<Object>> ConcurrentLookupIterator::TryGetOwnCowElement(
    Isolate* isolate, Tagged<FixedArray> array_elements,
    ElementsKind elements_kind, int array_length, size_t index) {
  DisallowGarbageCollection no_gc;

  CHECK_EQ(array_elements->map(), ReadOnlyRoots(isolate).fixed_cow_array_map());
  DCHECK(IsFastElementsKind(elements_kind) &&
         IsSmiOrObjectElementsKind(elements_kind));
  USE(elements_kind);
  DCHECK_GE(array_length, 0);

  //  ________________________________________
  // ( Check against both JSArray::length and )
  // ( FixedArray::length.                    )
  //  ----------------------------------------
  //         o   ^__^
  //          o  (oo)\_______
  //             (__)\       )\/\
  //                 ||----w |
  //                 ||     ||
  // The former is the source of truth, but due to concurrent reads it may not
  // match the given `array_elements`.
  if (index >= static_cast<size_t>(array_length)) return {};
  if (index >= static_cast<size_t>(array_elements->length())) return {};

  Tagged<Object> result = array_elements->get(static_cast<int>(index));

  //  ______________________________________
  // ( Filter out holes irrespective of the )
  // ( elements kind.                       )
  //  --------------------------------------
  //         o   ^__^
  //          o  (..)\_______
  //             (__)\       )\/\
  //                 ||----w |
  //                 ||     ||
  // The elements kind may not be consistent with the given elements backing
  // store.
  if (result == ReadOnlyRoots(isolate).the_hole_value()) return {};

  return result;
}

// static
ConcurrentLookupIterator::Result
ConcurrentLookupIterator::TryGetOwnConstantElement(
    Tagged<Object>* result_out, Isolate* isolate, LocalIsolate* local_isolate,
    Tagged<JSObject> holder, Tagged<FixedArrayBase> elements,
    ElementsKind elements_kind, size_t index) {
  DisallowGarbageCollection no_gc;

  DCHECK_LE(index, JSObject::kMaxElementIndex);

  // Own 'constant' elements (PropertyAttributes READ_ONLY|DONT_DELETE) occur in
  // three main cases:
  //
  // 1. Frozen elements: guaranteed constant.
  // 2. Dictionary elements: may be constant.
  // 3. String wrapper elements: guaranteed constant.

  // Interesting field reads below:
  //
  // - elements.length (immutable on FixedArrays).
  // - elements[i] (immutable if constant; be careful around dictionaries).
  // - holder.AsJSPrimitiveWrapper.value.AsString.length (immutable).
  // - holder.AsJSPrimitiveWrapper.value.AsString[i] (immutable).
  // - single_character_string_table()->get().

  if (IsFrozenElementsKind(elements_kind)) {
    if (!IsFixedArray(elements)) return kGaveUp;
    Tagged<FixedArray> elements_fixed_array = Cast<FixedArray>(elements);
    if (index >= static_cast<uint32_t>(elements_fixed_array->length())) {
      return kGaveUp;
    }
    Tagged<Object> result = elements_fixed_array->get(static_cast<int>(index));
    if (IsHoleyElementsKindForRead(elements_kind) &&
        result == ReadOnlyRoots(isolate).the_hole_value()) {
      return kNotPresent;
    }
    *result_out = result;
    return kPresent;
  } else if (IsDictionaryElementsKind(elements_kind)) {
    if (!IsNumberDictionary(elements)) return kGaveUp;
    // TODO(jgruber, v8:7790): Add support. Dictionary elements require racy
    // NumberDictionary lookups. This should be okay in general (slot iteration
    // depends only on the dict's capacity), but 1. we'd need to update
    // NumberDictionary methods to do atomic reads, and 2. the dictionary
    // elements case isn't very important for callers of this function.
    return kGaveUp;
  } else if (IsStringWrapperElementsKind(elements_kind)) {
    // In this case we don't care about the actual `elements`. All in-bounds
    // reads are redirected to the wrapped String.

    Tagged<JSPrimitiveWrapper> js_value = Cast<JSPrimitiveWrapper>(holder);
    Tagged<String> wrapped_string = Cast<String>(js_value->value());
    return ConcurrentLookupIterator::TryGetOwn
"""


```