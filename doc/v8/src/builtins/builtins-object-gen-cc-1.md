Response:
The user wants a summary of the provided C++ code snippet from `v8/src/builtins/builtins-object-gen.cc`.
The request includes several sub-constraints:
1. **List the functionalities:**  Identify what the code does.
2. **Torque source check:** Determine if the file would be a Torque file if its name ended in `.tq`.
3. **JavaScript relation and example:** If the code relates to JavaScript features, provide a JavaScript example.
4. **Code logic with input/output:** If there's logical deduction, illustrate with hypothetical input and output.
5. **Common programming errors:** Highlight potential user errors related to the functionality.
6. **Concise summary:**  Provide a brief overview of the code's purpose.

Let's break down the code snippet function by function:

* **`GetOwnPropertyKeys`:**  This function seems to retrieve the own property keys of an object. It has different paths for "fast" and "slow" object enumeration.
* **`ObjectValues` and `ObjectEntries`:** These builtins seem to use `GetOwnValuesOrEntries` to get the values or entries of an object's own properties.
* **`ObjectPrototypeIsPrototypeOf`:** This implements the `isPrototypeOf` method.
* **`ObjectToString`:** This implements the `toString` method. It handles different object types and the `@@toStringTag` symbol.
* **`ObjectCreate`:** This implements the `Object.create` method, allowing the creation of objects with a specified prototype.
* **`ObjectIs`:**  This implements the `Object.is` method for comparing values.
* **`CreateIterResultObject`:**  This seems to create an object conforming to the iterator result interface.
* **`HasProperty`:** This checks if an object has a specific property.
* **`InstanceOf` and related:** These implement the `instanceof` operator.
* **`OrdinaryHasInstance`:**  This seems to be the internal implementation of `instanceof`.
* **`CreateGeneratorObject`:** This creates generator objects.
* **`OrdinaryGetOwnPropertyDescriptor`:** This retrieves the property descriptor of an own property.
* **`ObjectGetOwnPropertyDescriptor`:**  This implements the `Object.getOwnPropertyDescriptor` method.
* **Helper functions (`AddToDictionaryIf`, `FromPropertyDescriptor`):** These seem to be internal utility functions for property manipulation.

Now, let's address each sub-constraint.

**Functionalities:** The code implements several built-in functions related to JavaScript objects.

**Torque Source Check:** Yes, the presence of `TF_BUILTIN` and the overall structure suggest that if the file ended in `.tq`, it would be a V8 Torque source file.

**JavaScript Relation and Example:**  The functions directly correspond to JavaScript's built-in `Object` methods and functionalities.

**Code Logic with Input/Output:** Consider `GetOwnPropertyKeys`. If the input is a simple object like `{a: 1, b: 2}`, the output should be an array `["a", "b"]`. For an object with no enumerable properties, the output would be an empty array.

**Common Programming Errors:** A common error related to `isPrototypeOf` is misunderstanding how prototype chains work. For example, checking if a primitive value is the prototype of an object will always return false.

**Summary:** The code defines the implementation of several core JavaScript `Object` built-in methods within the V8 engine.
这是目录为 `v8/src/builtins/builtins-object-gen.cc` 的一个 V8 源代码文件的部分内容。根据代码内容，可以归纳出以下功能：

**核心功能:**

这段代码主要实现了与 JavaScript `Object` 对象相关的内置函数，涵盖了属性的获取、原型链的判断、对象类型的识别、对象的创建以及属性描述符的获取等核心功能。

**具体功能列表:**

1. **`GetOwnPropertyKeys`**:  获取一个对象自身的可枚举属性的键名（字符串或 Symbol）。它尝试快速路径（`try_fast`），如果失败则回退到运行时调用（`if_slow`）。对于没有可枚举属性的对象，会返回一个空数组（`if_empty`）。

2. **`ObjectValues`**: 实现 `Object.values()` 方法，返回一个由给定对象自身的所有可枚举属性值组成的数组。

3. **`ObjectEntries`**: 实现 `Object.entries()` 方法，返回一个给定对象自身可枚举属性的键值对 `[key, value]` 数组。

4. **`ObjectPrototypeIsPrototypeOf`**: 实现 `Object.prototype.isPrototypeOf()` 方法，用于检测一个对象是否存在于另一个对象的原型链上。

5. **`ObjectToString`**: 实现 `Object.prototype.toString()` 方法，返回一个表示该对象的字符串。它可以根据对象的类型返回不同的字符串，例如 `"[object Object]"`，`"[object Array]"`，`"[object Function]"` 等。它还会检查 `@@toStringTag` Symbol 以允许自定义字符串表示。

6. **`ObjectCreate`**: 实现 `Object.create()` 方法，创建一个新对象，使用现有的对象来提供新创建的对象的原型。它针对没有属性的情况（`no_properties`）进行了优化，并尝试从原型信息中加载 `ObjectCreateMap` 以提高性能。

7. **`ObjectIs`**: 实现 `Object.is()` 方法，判断两个值是否是相同的值。

8. **`CreateIterResultObject`**:  创建一个符合迭代器结果协议的对象，通常用于实现迭代器。

9. **`HasProperty`**:  实现检查对象是否拥有指定属性的功能，对应 JavaScript 中的 `in` 运算符。

10. **`InstanceOf` 及相关 (`InstanceOf_WithFeedback`, `InstanceOf_Baseline`)**: 实现 `instanceof` 运算符，用于检测构造函数的 `prototype` 属性是否出现在对象的原型链中的任何位置。 `_WithFeedback` 和 `_Baseline` 版本可能涉及性能优化和反馈机制。

11. **`OrdinaryHasInstance`**:  `instanceof` 运算符的内部实现。

12. **`CreateGeneratorObject`**:  创建一个生成器对象。

13. **`OrdinaryGetOwnPropertyDescriptor`**:  获取对象自身属性的属性描述符的内部实现。

14. **`ObjectGetOwnPropertyDescriptor`**: 实现 `Object.getOwnPropertyDescriptor()` 方法，返回一个对象自身属性的描述符。

15. **辅助函数 (`AddToDictionaryIf`, `FromPropertyDescriptor`)**: 提供了一些内部辅助功能，例如在满足条件时向字典添加元素，以及从属性描述符对象创建 JavaScript 对象。

**关于 `.tq` 结尾:**

如果 `v8/src/builtins/builtins-object-gen.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。Torque 是 V8 用来定义内置函数的一种领域特定语言，它允许以更类型安全和结构化的方式编写内置函数。

**与 JavaScript 功能的关系及示例:**

这段 C++ 代码直接实现了 JavaScript 的 `Object` 对象的一些核心内置方法。以下是一些 JavaScript 示例，对应了代码中的功能：

```javascript
const obj = { a: 1, b: 2 };

// 对应 GetOwnPropertyKeys
console.log(Object.keys(obj)); // 输出: ["a", "b"]

// 对应 ObjectValues
console.log(Object.values(obj)); // 输出: [1, 2]

// 对应 ObjectEntries
console.log(Object.entries(obj)); // 输出: [["a", 1], ["b", 2]]

const proto = {};
const myObj = Object.create(proto);

// 对应 ObjectPrototypeIsPrototypeOf
console.log(proto.isPrototypeOf(myObj)); // 输出: true

// 对应 ObjectToString
console.log(obj.toString()); // 输出: "[object Object]"

// 对应 ObjectCreate
const newObj = Object.create({ x: 1 });
console.log(newObj.x); // 输出: 1

// 对应 ObjectIs
console.log(Object.is(NaN, NaN)); // 输出: true
console.log(Object.is(0, -0));   // 输出: false

// 对应 HasProperty
console.log('a' in obj); // 输出: true

function MyClass() {}
const instance = new MyClass();

// 对应 InstanceOf
console.log(instance instanceof MyClass); // 输出: true

// 对应 ObjectGetOwnPropertyDescriptor
console.log(Object.getOwnPropertyDescriptor(obj, 'a'));
// 输出: { value: 1, writable: true, enumerable: true, configurable: true }
```

**代码逻辑推理及假设输入与输出:**

以 `GetOwnPropertyKeys` 函数为例：

**假设输入:** 一个 JavaScript 对象 `const input = { a: 1, b: 2, [Symbol('c')]: 3 };`

**预期输出:** 一个包含可枚举属性键名的 JavaScript 数组 `["a", "b"]`。Symbol 类型的键名由于不是可枚举属性，所以不会包含在输出中。

**涉及用户常见的编程错误:**

1. **错误地假设 `Object.keys()` 会返回所有属性:**  用户可能会错误地认为 `Object.keys()` 会返回包括 Symbol 属性在内的所有自身属性，但它只返回可枚举的字符串键名。
    ```javascript
    const obj = { a: 1, [Symbol('b')]: 2 };
    console.log(Object.keys(obj)); // 输出: ["a"]，Symbol 属性被忽略
    ```
2. **混淆 `isPrototypeOf` 和 `instanceof`:**  用户可能会混淆这两个方法的使用场景。`isPrototypeOf` 用于检查一个对象是否存在于另一个对象的原型链上，而 `instanceof` 用于检查对象的原型链上是否存在构造函数的 `prototype` 属性。
    ```javascript
    function Animal() {}
    function Dog() {}
    Dog.prototype = Object.create(Animal.prototype);
    const myDog = new Dog();

    console.log(Animal.prototype.isPrototypeOf(myDog)); // 输出: true
    console.log(myDog instanceof Animal);             // 输出: true
    ```
    错误使用场景可能发生在不理解原型链结构时。
3. **不理解 `Object.is()` 和 `===` 的区别:** 用户可能仍然使用 `===` 进行比较，而忽略 `Object.is()` 在处理 `NaN` 和 `-0` 时的特殊行为。
    ```javascript
    console.log(NaN === NaN);     // 输出: false
    console.log(Object.is(NaN, NaN)); // 输出: true

    console.log(0 === -0);       // 输出: true
    console.log(Object.is(0, -0));   // 输出: false
    ```
4. **在 `Object.create()` 中传递非 `null` 或对象的原型参数:**  `Object.create()` 的第一个参数必须是 `null` 或者一个对象。如果传递其他类型的值，会导致错误或意外行为。

**归纳其功能 (第2部分):**

这段代码是 V8 引擎中实现 JavaScript `Object` 对象相关内置函数的关键部分。它包含了获取对象属性（键和值）、判断原型链关系、获取对象字符串表示、创建新对象以及获取属性描述符的底层实现。这些功能是 JavaScript 语言核心特性的基础，并被广泛应用于各种 JavaScript 编程场景中。这段代码的实现考虑了性能优化，例如 `GetOwnPropertyKeys` 中的快速路径和慢速路径处理，以及 `ObjectCreate` 中对原型信息的利用。

### 提示词
```
这是目录为v8/src/builtins/builtins-object-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-object-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
Map> array_map =
        LoadJSArrayElementsMap(PACKED_ELEMENTS, native_context);
    TNode<IntPtrT> object_enum_length_intptr = Signed(object_enum_length);
    TNode<Smi> array_length = SmiTag(object_enum_length_intptr);
    std::tie(array, elements) = AllocateUninitializedJSArrayWithElements(
        PACKED_ELEMENTS, array_map, array_length, std::nullopt,
        object_enum_length_intptr);
    CopyFixedArrayElements(PACKED_ELEMENTS, object_enum_keys, elements,
                           object_enum_length_intptr, SKIP_WRITE_BARRIER);
    Return(array);
  }

  BIND(&try_fast);
  {
    // Let the runtime compute the elements and try initializing enum cache.
    TNode<FixedArray> elements = CAST(CallRuntime(
        Runtime::kObjectGetOwnPropertyNamesTryFast, context, object));
    var_length = LoadObjectField<Smi>(elements, offsetof(FixedArray, length_));
    var_elements = elements;
    Goto(&if_join);
  }

  BIND(&if_empty);
  {
    // The {object} doesn't have any enumerable keys.
    var_length = SmiConstant(0);
    var_elements = EmptyFixedArrayConstant();
    Goto(&if_join);
  }

  BIND(&if_slow);
  {
    // Let the runtime compute the elements.
    TNode<FixedArray> elements =
        CAST(CallRuntime(Runtime::kObjectGetOwnPropertyNames, context, object));
    var_length = LoadObjectField<Smi>(elements, offsetof(FixedArray, length_));
    var_elements = elements;
    Goto(&if_join);
  }

  BIND(&if_join);
  {
    // Wrap the elements into a proper JSArray and return that.
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<Map> array_map =
        LoadJSArrayElementsMap(PACKED_ELEMENTS, native_context);
    TNode<JSArray> array =
        AllocateJSArray(array_map, var_elements.value(), var_length.value());
    Return(array);
  }
}

TF_BUILTIN(ObjectValues, ObjectEntriesValuesBuiltinsAssembler) {
  auto object = UncheckedParameter<JSObject>(Descriptor::kObject);
  auto context = UncheckedParameter<Context>(Descriptor::kContext);
  GetOwnValuesOrEntries(context, object, CollectType::kValues);
}

TF_BUILTIN(ObjectEntries, ObjectEntriesValuesBuiltinsAssembler) {
  auto object = UncheckedParameter<JSObject>(Descriptor::kObject);
  auto context = UncheckedParameter<Context>(Descriptor::kContext);
  GetOwnValuesOrEntries(context, object, CollectType::kEntries);
}

// ES #sec-object.prototype.isprototypeof
TF_BUILTIN(ObjectPrototypeIsPrototypeOf, ObjectBuiltinsAssembler) {
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto context = Parameter<Context>(Descriptor::kContext);
  Label if_receiverisnullorundefined(this, Label::kDeferred),
      if_valueisnotreceiver(this, Label::kDeferred);

  // We only check whether {value} is a Smi here, so that the
  // prototype chain walk below can safely access the {value}s
  // map. We don't rule out Primitive {value}s, since all of
  // them have null as their prototype, so the chain walk below
  // immediately aborts and returns false anyways.
  GotoIf(TaggedIsSmi(value), &if_valueisnotreceiver);

  {
    TNode<HeapObject> value_heap_object = CAST(value);

    // Check if {receiver} is either null or undefined and in that case,
    // invoke the ToObject builtin, which raises the appropriate error.
    // Otherwise we don't need to invoke ToObject, since {receiver} is
    // either already a JSReceiver, in which case ToObject is a no-op,
    // or it's a Primitive and ToObject would allocate a fresh
    // JSPrimitiveWrapper wrapper, which wouldn't be identical to any existing
    // JSReceiver found in the prototype chain of {value}, hence it will return
    // false no matter if we search for the Primitive {receiver} or
    // a newly allocated JSPrimitiveWrapper wrapper for {receiver}.
    GotoIf(IsNull(receiver), &if_receiverisnullorundefined);
    GotoIf(IsUndefined(receiver), &if_receiverisnullorundefined);

    // Loop through the prototype chain looking for the {receiver}.
    Return(HasInPrototypeChain(context, value_heap_object, receiver));

    BIND(&if_receiverisnullorundefined);
    {
      // If {value} is a primitive HeapObject, we need to return
      // false instead of throwing an exception per order of the
      // steps in the specification, so check that first here.
      GotoIfNot(JSAnyIsNotPrimitive(value_heap_object), &if_valueisnotreceiver);

      // Simulate the ToObject invocation on {receiver}.
      ToObject(context, receiver);
      Unreachable();
    }
  }

  BIND(&if_valueisnotreceiver);
  Return(FalseConstant());
}

TF_BUILTIN(ObjectToString, ObjectBuiltinsAssembler) {
  TVARIABLE(String, var_default);
  TVARIABLE(HeapObject, var_holder);
  TVARIABLE(Map, var_holder_map);

  Label checkstringtag(this), if_arguments(this), if_array(this),
      if_boolean(this), if_date(this), if_error(this), if_function(this),
      if_number(this, Label::kDeferred), if_object(this), if_primitive(this),
      if_proxy(this, {&var_holder, &var_holder_map}, Label::kDeferred),
      if_regexp(this), if_string(this), if_symbol(this, Label::kDeferred),
      if_value(this), if_bigint(this, Label::kDeferred);

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto context = Parameter<Context>(Descriptor::kContext);

  // This is arranged to check the likely cases first.
  GotoIf(TaggedIsSmi(receiver), &if_number);

  TNode<HeapObject> receiver_heap_object = CAST(receiver);
  TNode<Map> receiver_map = LoadMap(receiver_heap_object);
  var_holder = receiver_heap_object;
  var_holder_map = receiver_map;
  TNode<Uint16T> receiver_instance_type = LoadMapInstanceType(receiver_map);
  GotoIf(IsPrimitiveInstanceType(receiver_instance_type), &if_primitive);
  GotoIf(IsFunctionInstanceType(receiver_instance_type), &if_function);
  const struct {
    InstanceType value;
    Label* label;
  } kJumpTable[] = {{JS_OBJECT_TYPE, &if_object},
                    {JS_ARRAY_TYPE, &if_array},
                    {JS_REG_EXP_TYPE, &if_regexp},
                    {JS_ARGUMENTS_OBJECT_TYPE, &if_arguments},
                    {JS_DATE_TYPE, &if_date},
                    {JS_API_OBJECT_TYPE, &if_object},
                    {JS_SPECIAL_API_OBJECT_TYPE, &if_object},
                    {JS_PROXY_TYPE, &if_proxy},
                    {JS_ERROR_TYPE, &if_error},
                    {JS_PRIMITIVE_WRAPPER_TYPE, &if_value}};
  size_t const kNumCases = arraysize(kJumpTable);
  Label* case_labels[kNumCases];
  int32_t case_values[kNumCases];
  for (size_t i = 0; i < kNumCases; ++i) {
    case_labels[i] = kJumpTable[i].label;
    case_values[i] = kJumpTable[i].value;
  }
  Switch(receiver_instance_type, &if_object, case_values, case_labels,
         arraysize(case_values));

  BIND(&if_arguments);
  {
    var_default = ArgumentsToStringConstant();
    Goto(&checkstringtag);
  }

  BIND(&if_array);
  {
    var_default = ArrayToStringConstant();
    Goto(&checkstringtag);
  }

  BIND(&if_boolean);
  {
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<JSFunction> boolean_constructor = CAST(
        LoadContextElement(native_context, Context::BOOLEAN_FUNCTION_INDEX));
    TNode<Map> boolean_initial_map = LoadObjectField<Map>(
        boolean_constructor, JSFunction::kPrototypeOrInitialMapOffset);
    TNode<HeapObject> boolean_prototype =
        LoadObjectField<HeapObject>(boolean_initial_map, Map::kPrototypeOffset);
    var_default = BooleanToStringConstant();
    var_holder = boolean_prototype;
    var_holder_map = LoadMap(boolean_prototype);
    Goto(&checkstringtag);
  }

  BIND(&if_date);
  {
    var_default = DateToStringConstant();
    Goto(&checkstringtag);
  }

  BIND(&if_error);
  {
    var_default = ErrorToStringConstant();
    Goto(&checkstringtag);
  }

  BIND(&if_function);
  {
    var_default = FunctionToStringConstant();
    Goto(&checkstringtag);
  }

  BIND(&if_number);
  {
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<JSFunction> number_constructor = CAST(
        LoadContextElement(native_context, Context::NUMBER_FUNCTION_INDEX));
    TNode<Map> number_initial_map = LoadObjectField<Map>(
        number_constructor, JSFunction::kPrototypeOrInitialMapOffset);
    TNode<HeapObject> number_prototype =
        LoadObjectField<HeapObject>(number_initial_map, Map::kPrototypeOffset);
    var_default = NumberToStringConstant();
    var_holder = number_prototype;
    var_holder_map = LoadMap(number_prototype);
    Goto(&checkstringtag);
  }

  BIND(&if_object);
  {
    CSA_DCHECK(this, IsJSReceiver(CAST(receiver)));
    var_default = ObjectToStringConstant();
    Goto(&checkstringtag);
  }

  BIND(&if_primitive);
  {
    Label return_undefined(this);

    GotoIf(IsStringInstanceType(receiver_instance_type), &if_string);
    GotoIf(IsBigIntInstanceType(receiver_instance_type), &if_bigint);
    GotoIf(IsBooleanMap(receiver_map), &if_boolean);
    GotoIf(IsHeapNumberMap(receiver_map), &if_number);
    GotoIf(IsSymbolMap(receiver_map), &if_symbol);
    GotoIf(IsUndefined(receiver), &return_undefined);
    CSA_DCHECK(this, IsNull(receiver));
    Return(NullToStringConstant());

    BIND(&return_undefined);
    Return(UndefinedToStringConstant());
  }

  BIND(&if_regexp);
  {
    var_default = RegexpToStringConstant();
    Goto(&checkstringtag);
  }

  BIND(&if_string);
  {
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<JSFunction> string_constructor = CAST(
        LoadContextElement(native_context, Context::STRING_FUNCTION_INDEX));
    TNode<Map> string_initial_map = LoadObjectField<Map>(
        string_constructor, JSFunction::kPrototypeOrInitialMapOffset);
    TNode<HeapObject> string_prototype =
        LoadObjectField<HeapObject>(string_initial_map, Map::kPrototypeOffset);
    var_default = StringToStringConstant();
    var_holder = string_prototype;
    var_holder_map = LoadMap(string_prototype);
    Goto(&checkstringtag);
  }

  BIND(&if_symbol);
  {
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<JSFunction> symbol_constructor = CAST(
        LoadContextElement(native_context, Context::SYMBOL_FUNCTION_INDEX));
    TNode<Map> symbol_initial_map = LoadObjectField<Map>(
        symbol_constructor, JSFunction::kPrototypeOrInitialMapOffset);
    TNode<HeapObject> symbol_prototype =
        LoadObjectField<HeapObject>(symbol_initial_map, Map::kPrototypeOffset);
    var_default = ObjectToStringConstant();
    var_holder = symbol_prototype;
    var_holder_map = LoadMap(symbol_prototype);
    Goto(&checkstringtag);
  }

  BIND(&if_bigint);
  {
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<JSFunction> bigint_constructor = CAST(
        LoadContextElement(native_context, Context::BIGINT_FUNCTION_INDEX));
    TNode<Map> bigint_initial_map = LoadObjectField<Map>(
        bigint_constructor, JSFunction::kPrototypeOrInitialMapOffset);
    TNode<HeapObject> bigint_prototype =
        LoadObjectField<HeapObject>(bigint_initial_map, Map::kPrototypeOffset);
    var_default = ObjectToStringConstant();
    var_holder = bigint_prototype;
    var_holder_map = LoadMap(bigint_prototype);
    Goto(&checkstringtag);
  }

  BIND(&if_value);
  {
    Label if_value_is_number(this, Label::kDeferred),
        if_value_is_boolean(this, Label::kDeferred),
        if_value_is_symbol(this, Label::kDeferred),
        if_value_is_bigint(this, Label::kDeferred),
        if_value_is_string(this, Label::kDeferred);

    TNode<Object> receiver_value =
        LoadJSPrimitiveWrapperValue(CAST(receiver_heap_object));
    // We need to start with the object to see if the value was a subclass
    // which might have interesting properties.
    GotoIf(TaggedIsSmi(receiver_value), &if_value_is_number);
    TNode<Map> receiver_value_map = LoadMap(CAST(receiver_value));
    GotoIf(IsHeapNumberMap(receiver_value_map), &if_value_is_number);
    GotoIf(IsBooleanMap(receiver_value_map), &if_value_is_boolean);
    GotoIf(IsSymbolMap(receiver_value_map), &if_value_is_symbol);
    TNode<Uint16T> receiver_value_instance_type =
        LoadMapInstanceType(receiver_value_map);
    GotoIf(IsBigIntInstanceType(receiver_value_instance_type),
           &if_value_is_bigint);
    CSA_DCHECK(this, IsStringInstanceType(receiver_value_instance_type));
    Goto(&if_value_is_string);

    BIND(&if_value_is_number);
    {
      var_default = NumberToStringConstant();
      Goto(&checkstringtag);
    }

    BIND(&if_value_is_boolean);
    {
      var_default = BooleanToStringConstant();
      Goto(&checkstringtag);
    }

    BIND(&if_value_is_string);
    {
      var_default = StringToStringConstant();
      Goto(&checkstringtag);
    }

    BIND(&if_value_is_bigint);
    {
      var_default = ObjectToStringConstant();
      Goto(&checkstringtag);
    }

    BIND(&if_value_is_symbol);
    {
      var_default = ObjectToStringConstant();
      Goto(&checkstringtag);
    }
  }

  BIND(&checkstringtag);
  {
    Label return_default(this);
    TNode<Object> tag =
        GetInterestingProperty(context, receiver, &var_holder, &var_holder_map,
                               ToStringTagSymbolConstant(), &return_default);
    GotoIf(TaggedIsSmi(tag), &return_default);
    GotoIfNot(IsString(CAST(tag)), &return_default);
    ReturnToStringFormat(context, CAST(tag));

    BIND(&return_default);
    Return(var_default.value());
  }

  BIND(&if_proxy);
  {
    receiver_heap_object = var_holder.value();
    receiver_map = var_holder_map.value();
    // Check if the proxy has been revoked.
    Label throw_proxy_handler_revoked(this, Label::kDeferred);
    TNode<HeapObject> handler =
        CAST(LoadObjectField(receiver_heap_object, JSProxy::kHandlerOffset));
    CSA_DCHECK(this, IsNullOrJSReceiver(handler));
    GotoIfNot(JSAnyIsNotPrimitive(handler), &throw_proxy_handler_revoked);

    // If {receiver_heap_object} is a proxy for a JSArray, we default to
    // "[object Array]", otherwise we default to "[object Object]" or "[object
    // Function]" here, depending on whether the {receiver_heap_object} is
    // callable. The order matters here, i.e. we need to execute the
    // %ArrayIsArray check before the [[Get]] below, as the exception is
    // observable.
    TNode<Object> receiver_is_array =
        CallRuntime(Runtime::kArrayIsArray, context, receiver_heap_object);
    TNode<String> builtin_tag = Select<String>(
        IsTrue(receiver_is_array), [=, this] { return ArrayStringConstant(); },
        [=, this] {
          return Select<String>(
              IsCallableMap(receiver_map),
              [=, this] { return FunctionStringConstant(); },
              [=, this] { return ObjectStringConstant(); });
        });

    // Lookup the @@toStringTag property on the {receiver_heap_object}.
    TVARIABLE(Object, var_tag,
              GetProperty(context, receiver_heap_object,
                          isolate()->factory()->to_string_tag_symbol()));
    Label if_tagisnotstring(this), if_tagisstring(this);
    GotoIf(TaggedIsSmi(var_tag.value()), &if_tagisnotstring);
    Branch(IsString(CAST(var_tag.value())), &if_tagisstring,
           &if_tagisnotstring);
    BIND(&if_tagisnotstring);
    {
      var_tag = builtin_tag;
      Goto(&if_tagisstring);
    }
    BIND(&if_tagisstring);
    ReturnToStringFormat(context, CAST(var_tag.value()));

    BIND(&throw_proxy_handler_revoked);
    {
      ThrowTypeError(context, MessageTemplate::kProxyRevoked,
                     "Object.prototype.toString");
    }
  }
}

// ES #sec-object.create
TF_BUILTIN(ObjectCreate, ObjectBuiltinsAssembler) {
  int const kPrototypeArg = 0;
  int const kPropertiesArg = 1;

  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  CodeStubArguments args(this, argc);

  TNode<Object> prototype = args.GetOptionalArgumentValue(kPrototypeArg);
  TNode<Object> properties = args.GetOptionalArgumentValue(kPropertiesArg);
  auto native_context = Parameter<NativeContext>(Descriptor::kContext);

  Label call_runtime(this, Label::kDeferred), prototype_valid(this),
      no_properties(this);

  {
    Comment("Argument 1 check: prototype");
    GotoIf(IsNull(prototype), &prototype_valid);
    BranchIfJSReceiver(prototype, &prototype_valid, &call_runtime);
  }

  BIND(&prototype_valid);
  {
    Comment("Argument 2 check: properties");
    // Check that we have a simple object
    GotoIf(TaggedIsSmi(properties), &call_runtime);
    // Undefined implies no properties.
    GotoIf(IsUndefined(properties), &no_properties);
    TNode<Map> properties_map = LoadMap(CAST(properties));
    GotoIf(IsSpecialReceiverMap(properties_map), &call_runtime);
    // Stay on the fast path only if there are no elements.
    GotoIfNot(
        TaggedEqual(LoadElements(CAST(properties)), EmptyFixedArrayConstant()),
        &call_runtime);
    // Handle dictionary objects or fast objects with properties in runtime.
    TNode<Uint32T> bit_field3 = LoadMapBitField3(properties_map);
    GotoIf(IsSetWord32<Map::Bits3::IsDictionaryMapBit>(bit_field3),
           &call_runtime);
    Branch(IsSetWord32<Map::Bits3::NumberOfOwnDescriptorsBits>(bit_field3),
           &call_runtime, &no_properties);
  }

  // Create a new object with the given prototype.
  BIND(&no_properties);
  {
    TVARIABLE(Map, map);
    TVARIABLE(HeapObject, new_properties);
    Label null_proto(this), non_null_proto(this), instantiate_map(this);

    Branch(IsNull(prototype), &null_proto, &non_null_proto);

    BIND(&null_proto);
    {
      map = LoadSlowObjectWithNullPrototypeMap(native_context);
      new_properties =
          AllocatePropertyDictionary(PropertyDictionary::kInitialCapacity);
      Goto(&instantiate_map);
    }

    BIND(&non_null_proto);
    {
      new_properties = EmptyFixedArrayConstant();
      map = LoadObjectFunctionInitialMap(native_context);
      GotoIf(TaggedEqual(prototype, LoadMapPrototype(map.value())),
             &instantiate_map);
      // Try loading the prototype info.
      TNode<PrototypeInfo> prototype_info =
          LoadMapPrototypeInfo(LoadMap(CAST(prototype)), &call_runtime);
      Comment("Load ObjectCreateMap from PrototypeInfo");
      TNode<HeapObject> derived_maps = CAST(
          LoadObjectField(prototype_info, PrototypeInfo::kDerivedMapsOffset));
      // In case it exists, derived maps is a weak array list where the first
      // element is the object create map.
      GotoIf(TaggedEqual(derived_maps, UndefinedConstant()), &call_runtime);
      CSA_DCHECK(this, InstanceTypeEqual(LoadInstanceType(derived_maps),
                                         WEAK_ARRAY_LIST_TYPE));
      TNode<MaybeObject> maybe_map = UncheckedCast<MaybeObject>(LoadObjectField(
          derived_maps, IntPtrConstant(WeakArrayList::kHeaderSize)));
      map = CAST(GetHeapObjectAssumeWeak(maybe_map, &call_runtime));
      Goto(&instantiate_map);
    }

    BIND(&instantiate_map);
    {
      TNode<JSObject> instance =
          AllocateJSObjectFromMap(map.value(), new_properties.value());
      args.PopAndReturn(instance);
    }
  }

  BIND(&call_runtime);
  {
    TNode<Object> result = CallRuntime(Runtime::kObjectCreate, native_context,
                                       prototype, properties);
    args.PopAndReturn(result);
  }
}

// ES #sec-object.is
TF_BUILTIN(ObjectIs, ObjectBuiltinsAssembler) {
  const auto left = Parameter<Object>(Descriptor::kLeft);
  const auto right = Parameter<Object>(Descriptor::kRight);

  Label return_true(this), return_false(this);
  BranchIfSameValue(left, right, &return_true, &return_false);

  BIND(&return_true);
  Return(TrueConstant());

  BIND(&return_false);
  Return(FalseConstant());
}

TF_BUILTIN(CreateIterResultObject, ObjectBuiltinsAssembler) {
  const auto value = Parameter<Object>(Descriptor::kValue);
  const auto done = Parameter<Boolean>(Descriptor::kDone);
  const auto context = Parameter<Context>(Descriptor::kContext);

  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Map> map = CAST(
      LoadContextElement(native_context, Context::ITERATOR_RESULT_MAP_INDEX));

  const TNode<JSObject> result = AllocateJSObjectFromMap(map);

  StoreObjectFieldNoWriteBarrier(result, JSIteratorResult::kValueOffset, value);
  StoreObjectFieldNoWriteBarrier(result, JSIteratorResult::kDoneOffset, done);

  Return(result);
}

TF_BUILTIN(HasProperty, ObjectBuiltinsAssembler) {
  auto key = Parameter<Object>(Descriptor::kKey);
  auto object = Parameter<Object>(Descriptor::kObject);
  auto context = Parameter<Context>(Descriptor::kContext);

  Return(HasProperty(context, object, key, kHasProperty));
}

TF_BUILTIN(InstanceOf, ObjectBuiltinsAssembler) {
  auto object = Parameter<Object>(Descriptor::kLeft);
  auto callable = Parameter<Object>(Descriptor::kRight);
  auto context = Parameter<Context>(Descriptor::kContext);

  Return(InstanceOf(object, callable, context));
}

TF_BUILTIN(InstanceOf_WithFeedback, ObjectBuiltinsAssembler) {
  auto object = Parameter<Object>(Descriptor::kLeft);
  auto callable = Parameter<Object>(Descriptor::kRight);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto feedback_vector = Parameter<HeapObject>(Descriptor::kFeedbackVector);
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);

  CollectInstanceOfFeedback(callable, context, feedback_vector, slot);
  Return(InstanceOf(object, callable, context));
}

TF_BUILTIN(InstanceOf_Baseline, ObjectBuiltinsAssembler) {
  auto object = Parameter<Object>(Descriptor::kLeft);
  auto callable = Parameter<Object>(Descriptor::kRight);
  auto context = LoadContextFromBaseline();
  auto feedback_vector = LoadFeedbackVectorFromBaseline();
  auto slot = UncheckedParameter<UintPtrT>(Descriptor::kSlot);

  CollectInstanceOfFeedback(callable, context, feedback_vector, slot);
  Return(InstanceOf(object, callable, context));
}

// ES6 section 7.3.19 OrdinaryHasInstance ( C, O )
TF_BUILTIN(OrdinaryHasInstance, ObjectBuiltinsAssembler) {
  auto constructor = Parameter<Object>(Descriptor::kLeft);
  auto object = Parameter<Object>(Descriptor::kRight);
  auto context = Parameter<Context>(Descriptor::kContext);

  Return(OrdinaryHasInstance(context, constructor, object));
}

TF_BUILTIN(CreateGeneratorObject, ObjectBuiltinsAssembler) {
  auto closure = Parameter<JSFunction>(Descriptor::kClosure);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto context = Parameter<Context>(Descriptor::kContext);

  // Get the initial map from the function, jumping to the runtime if we don't
  // have one.
  Label done(this), runtime(this);
  GotoIfForceSlowPath(&runtime);
  GotoIfNot(IsFunctionWithPrototypeSlotMap(LoadMap(closure)), &runtime);
  TNode<HeapObject> maybe_map = LoadObjectField<HeapObject>(
      closure, JSFunction::kPrototypeOrInitialMapOffset);
  GotoIf(DoesntHaveInstanceType(maybe_map, MAP_TYPE), &runtime);
  TNode<Map> map = CAST(maybe_map);

  TNode<SharedFunctionInfo> shared = LoadObjectField<SharedFunctionInfo>(
      closure, JSFunction::kSharedFunctionInfoOffset);
  // TODO(40931165): load bytecode array from function's dispatch table entry
  // when available instead of shared function info.
  TNode<BytecodeArray> bytecode_array =
      LoadSharedFunctionInfoBytecodeArray(shared);

  TNode<IntPtrT> parameter_count = Signed(ChangeUint32ToWord(
      LoadBytecodeArrayParameterCountWithoutReceiver(bytecode_array)));

  TNode<IntPtrT> frame_size = ChangeInt32ToIntPtr(
      LoadObjectField<Int32T>(bytecode_array, BytecodeArray::kFrameSizeOffset));
  TNode<IntPtrT> length =
      IntPtrAdd(WordSar(frame_size, IntPtrConstant(kSystemPointerSizeLog2)),
                parameter_count);
  TNode<FixedArrayBase> parameters_and_registers =
      AllocateFixedArray(HOLEY_ELEMENTS, length);
  FillFixedArrayWithValue(HOLEY_ELEMENTS, parameters_and_registers,
                          IntPtrConstant(0), length,
                          RootIndex::kUndefinedValue);
  // TODO(cbruni): support start_offset to avoid double initialization.
  TNode<JSObject> result =
      AllocateJSObjectFromMap(map, std::nullopt, std::nullopt,
                              AllocationFlag::kNone, kWithSlackTracking);
  StoreObjectFieldNoWriteBarrier(result, JSGeneratorObject::kFunctionOffset,
                                 closure);
  StoreObjectFieldNoWriteBarrier(result, JSGeneratorObject::kContextOffset,
                                 context);
  StoreObjectFieldNoWriteBarrier(result, JSGeneratorObject::kReceiverOffset,
                                 receiver);
  StoreObjectFieldNoWriteBarrier(
      result, JSGeneratorObject::kParametersAndRegistersOffset,
      parameters_and_registers);
  TNode<Smi> resume_mode = SmiConstant(JSGeneratorObject::ResumeMode::kNext);
  StoreObjectFieldNoWriteBarrier(result, JSGeneratorObject::kResumeModeOffset,
                                 resume_mode);
  TNode<Smi> executing = SmiConstant(JSGeneratorObject::kGeneratorExecuting);
  StoreObjectFieldNoWriteBarrier(result, JSGeneratorObject::kContinuationOffset,
                                 executing);
  GotoIfNot(InstanceTypeEqual(LoadMapInstanceType(map),
                              JS_ASYNC_GENERATOR_OBJECT_TYPE),
            &done);
  StoreObjectFieldNoWriteBarrier(
      result, JSAsyncGeneratorObject::kIsAwaitingOffset, SmiConstant(0));
  Goto(&done);

  BIND(&done);
  { Return(result); }

  BIND(&runtime);
  {
    Return(CallRuntime(Runtime::kCreateJSGeneratorObject, context, closure,
                       receiver));
  }
}

TF_BUILTIN(OrdinaryGetOwnPropertyDescriptor, ObjectBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto object = Parameter<JSReceiver>(Descriptor::kReceiver);
  auto name = Parameter<Name>(Descriptor::kKey);
  CSA_DCHECK(this, Word32BinaryNot(IsSpecialReceiverInstanceType(
                       LoadMapInstanceType(LoadMap(object)))));

  Label if_notunique_name(this), if_iskeyunique(this), done(this),
      if_keyisindex(this), call_runtime(this);

  TVARIABLE(IntPtrT, var_index, IntPtrConstant(0));
  TVARIABLE(Name, var_name, name);
  TVARIABLE(HeapObject, result, UndefinedConstant());

  TryToName(name, &if_keyisindex, &var_index, &if_iskeyunique, &var_name,
            &call_runtime, &if_notunique_name);

  BIND(&if_notunique_name);
  {
    Label not_in_string_table(this);
    // If the string was not found in the string table, then no regular
    // object can have a property with that name, so return |undefined|.
    TryInternalizeString(CAST(name), &if_keyisindex, &var_index,
                         &if_iskeyunique, &var_name, &done, &call_runtime);
  }

  BIND(&if_iskeyunique);
  {
    Label if_found_value(this), if_not_found(this);

    TVARIABLE(Object, var_value);
    TVARIABLE(Uint32T, var_details);
    TVARIABLE(Object, var_raw_value);
    TNode<Map> map = LoadMap(object);
    TNode<Int32T> instance_type = LoadMapInstanceType(map);

    TryGetOwnProperty(context, object, object, map, instance_type,
                      var_name.value(), &if_found_value, &var_value,
                      &var_details, &var_raw_value, &done, &call_runtime,
                      kReturnAccessorPair);

    BIND(&if_found_value);

    // 4. Return FromPropertyDetails(desc).
    result = AllocatePropertyDescriptorObject(context);
    InitializePropertyDescriptorObject(CAST(result.value()), var_value.value(),
                                       var_details.value(), &call_runtime);
    Goto(&done);
  }

  BIND(&done);
  Return(result.value());

  BIND(&if_keyisindex);
  Goto(&call_runtime);

  BIND(&call_runtime);
  TailCallRuntime(Runtime::kGetOwnPropertyDescriptorObject, context, object,
                  var_name.value());
}

// ES6 section 19.1.2.7 Object.getOwnPropertyDescriptor ( O, P )
TF_BUILTIN(ObjectGetOwnPropertyDescriptor, ObjectBuiltinsAssembler) {
  auto argc = UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
  auto context = Parameter<Context>(Descriptor::kContext);
  CSA_DCHECK(this, IsUndefined(Parameter<Object>(Descriptor::kJSNewTarget)));

  CodeStubArguments args(this, argc);
  TNode<Object> object_input = args.GetOptionalArgumentValue(0);
  TNode<Object> key = args.GetOptionalArgumentValue(1);

  // 1. Let obj be ? ToObject(O).
  TNode<JSReceiver> object = ToObject_Inline(context, object_input);

  // 2. Let key be ? ToPropertyKey(P).
  key = CallBuiltin(Builtin::kToName, context, key);

  // 3. Let desc be ? obj.[[GetOwnProperty]](key).
  TNode<Object> desc =
      CallBuiltin(Builtin::kGetOwnPropertyDescriptor, context, object, key);

  // 4. Return FromPropertyDescriptor(desc).
  TNode<HeapObject> result = FromPropertyDescriptor(context, desc);

  args.PopAndReturn(result);
}

// TODO(v8:11167) remove remove |context| and |object| parameters once
// OrderedNameDictionary supported.
void ObjectBuiltinsAssembler::AddToDictionaryIf(
    TNode<BoolT> condition, TNode<Context> context, TNode<Object> object,
    TNode<HeapObject> name_dictionary, Handle<Name> name, TNode<Object> value,
    Label* bailout) {
  Label done(this);
  GotoIfNot(condition, &done);

  AddToDictionary<PropertyDictionary>(CAST(name_dictionary),
                                      HeapConstantNoHole(name), value, bailout);
  Goto(&done);

  BIND(&done);
}

TNode<JSObject> ObjectBuiltinsAssembler::FromPropertyDescriptor(
    TNode<Context> context, TNode<PropertyDescriptorObject> desc) {
  TVARIABLE(JSObject, js_descriptor);

  TNode<Int32T> flags = LoadAndUntagToWord32ObjectField(
      desc, PropertyDescriptorObject::kFlagsOffset);

  TNode<Int32T> has_flags =
      Word32And(flags, Int32Constant(PropertyDescriptorObject::kHasMask));

  Label if_accessor_desc(this), if_data_desc(this), if_generic_desc(this),
      return_desc(this);
  GotoIf(
      Word32Equal(has_flags,
                  Int32Constant(
                      PropertyDescriptorObject::kRegularAccessorPropertyBits)),
      &if_accessor_desc);
  GotoIf(Word32Equal(
             has_flags,
             Int32Constant(PropertyDescriptorObject::kRegularDataPropertyBits)),
         &if_data_desc);
  Goto(&if_generic_desc);

  BIND(&if_accessor_desc);
  {
    js_descriptor = ConstructAccessorDescriptor(
        context, LoadObjectField(desc, PropertyDescriptorObject::kGetOffset),
        LoadObjectField(desc, PropertyDescriptorObject::kSetOffset),
        IsSetWord32<PropertyDescriptorObject::IsEnumerableBit>(flags),
        IsSetWord32<PropertyDescriptorObject::IsConfigurableBit>(flags));
    Goto(&return_desc);
  }

  BIND(&if_data_desc);
  {
    js_descriptor = ConstructDataDescriptor(
        context, LoadObjectField(desc, PropertyDescriptorObject::kValueOffset),
        IsSetWord32<PropertyDescriptorObject::IsWritableBit>(flags),
        IsSetWord32<PropertyDescriptorObject::IsEnumerableBit>(flags),
        IsSetWord32<PropertyDescriptorObject::IsConfigurableBit>(flags));
    Goto(&return_desc);
  }

  BIND(&if_generic_desc);
  {
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<Map> map = CAST(LoadContextElement(
        native_context, Context::SLOW_OBJECT_WITH_OBJECT_PROTOTYPE_MAP));
    // We want to preallocate the slots for value, writable, get, set,
    // enumerable and configurable - a total of 6
    TNode<HeapObject> properties = AllocatePropertyDictionary(6);
    TNode<JSObject> js_desc = AllocateJSObjectFromMap(map, properties);

    Label bailout(this, Label::kDeferred);

    Factory* factory = isolate()->factory();
    TNode<Object> value =
        LoadObjectField(desc, PropertyDescriptorObject::kValueOffset);
    AddToDictionaryIf(IsNotTheHole(value), context, js_desc, properties,
                      factory->value_string(), value, &bailout);
    AddToDictionaryIf(
        IsSetWord32<PropertyDescriptorObject::HasWritableBit>(flags), context,
        js_desc, properties, factory->writable_string(),
        SelectBooleanConstant(
            IsSetWord32<PropertyDescriptorObject::IsWritableBit>(flags)),
        &bailout);

    TNode<Object> get =
        LoadObjectField(desc, PropertyDescriptorObject::kGetOffset);
    AddToDictionaryIf(IsNotTheHole(get), context, js_desc, properties,
                      factory->get_string(), get, &bailout);
    TNode<Object> set =
        LoadObjectField(desc, PropertyDescriptorObject::kSetOffset);
    AddToDictionaryIf(IsNotTheHole(set), context, js_desc, properties,
                      factory->set_string(), set, &bailout);

    AddToDictionaryIf(
        IsSetWord32<PropertyDescriptorObject::HasEnumerableBit>(flags), context,
        js_desc, properties, factory->enumerable_string(),
        SelectBooleanConstant(
            IsSetWord32<PropertyDescriptorObject::IsEnumerableBit>(flag
```