Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `v8/src/json/json-stringifier.cc`.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Purpose:** The file name `json-stringifier.cc` strongly suggests its primary function is to convert JavaScript objects into JSON strings.

2. **Analyze Key Data Structures and Methods:**
    * The class `JsonStringifier` is central. Its methods like `Serialize`, `SerializeValue`, `SerializeJSObject`, `SerializeJSArray`, and `SerializeString` are strong indicators of the core functionality.
    * The presence of `StackPush` and `StackPop` hints at handling circular references to prevent infinite recursion.
    * The `replacer_function_` member suggests support for custom transformation of values during serialization.
    * `gap_` and indentation-related methods (`Indent`, `Unindent`, `NewLine`) point towards pretty-printing/formatting of the output JSON.

3. **Examine the `SerializeValue` Method:** This method seems like the entry point for serializing different JavaScript types. The `switch` statement based on `instance_type` confirms this and reveals how different JavaScript types (numbers, booleans, null, arrays, objects, strings, etc.) are handled.

4. **Investigate Specific Serialization Methods:**
    * `SerializeJSArray`:  Handles serialization of JavaScript arrays, including handling sparse arrays and potential interruptions for long arrays.
    * `SerializeJSObject`: Handles serialization of JavaScript objects, including handling custom `toJSON` methods and property enumeration.
    * `SerializeString`:  Handles escaping special characters in strings to comply with JSON format.
    * `SerializeJSPrimitiveWrapper`: Handles the serialization of primitive wrapper objects (e.g., `new String("hello")`).

5. **Consider Error Handling and Edge Cases:**
    * The code explicitly throws `TypeError` for trying to serialize `BigInt` values.
    * Checks for maximum string length are present to prevent excessive memory allocation.
    * Handling of `NaN` and `Infinity` by converting them to `"null"`.
    * Special handling for `JSRawJson` objects.

6. **Relate to JavaScript Functionality:** The code is clearly implementing the `JSON.stringify()` method in JavaScript. Examples of how `JSON.stringify()` works would be relevant here.

7. **Infer Potential User Errors:** Common mistakes when using `JSON.stringify()` include:
    * Trying to stringify circular objects.
    * Trying to stringify objects with `BigInt` values.
    * Expecting non-enumerable properties to be included.
    * Not understanding the effect of the `replacer` function.

8. **Address Specific Questions from the Prompt:**
    * **`.tq` extension:** The code is `.cc`, so it's not Torque.
    * **JavaScript relation:** Yes, it's the implementation of `JSON.stringify()`.
    * **Code logic inference:**  Provide input/output examples for different types.
    * **User errors:**  Provide examples of common `JSON.stringify()` usage errors.

9. **Structure the Summary:** Organize the findings logically, starting with the main purpose and then detailing specific aspects.

10. **Review and Refine:** Ensure the summary is clear, concise, and addresses all aspects of the prompt. Pay attention to the "This is part 2" instruction and focus on summarizing the *provided* code, assuming part 1 covered initialization and overall structure.

By following these steps, we can systematically analyze the code and construct a comprehensive summary of its functionality. The focus is on understanding the core tasks, the mechanisms used to achieve them, and how they relate to the corresponding JavaScript functionality.
好的，我们来归纳一下 `v8/src/json/json-stringifier.cc` 代码片段的功能。

**核心功能归纳:**

这段代码是 V8 引擎中 `JSON.stringify()` 方法的核心实现部分，负责将 JavaScript 的各种数据类型转换为符合 JSON 格式的字符串。

**具体功能点:**

* **类型分发和序列化:**
    * `SerializeValue` 方法根据输入对象的类型 (`instance_type`) 分发到不同的序列化方法。
    * 支持序列化基本类型（数字、布尔值、null）、字符串、数组和普通对象。
    * 针对特殊类型如 `BigInt`，会抛出 `TypeError` 异常，因为 JSON 不支持 `BigInt`。
    * 对于 `Symbol` 类型，会返回 `UNCHANGED`，意味着在 JSON 序列化中会被忽略（或根据上下文处理）。
    * 特殊处理了 `JSRawJson` 类型，直接将其内部的 JSON 字符串取出并拼接。
    * 对于 `JSPrimitiveWrapper` 对象（例如 `new String("abc")`），会提取其原始值进行序列化。

* **数组序列化 (`SerializeJSArray`):**
    * 高效地处理数组的序列化，包括稀疏数组。
    * 针对不同元素类型的数组（Packed Smi, Holey Smi, Packed, Holey, Packed Double, Holey Double），采取不同的优化路径进行序列化。
    * 实现了中断检查 (`SerializeFixedArrayWithInterruptCheck`)，防止在序列化大型数组时阻塞 JavaScript 引擎。
    * 可以处理在序列化过程中数组长度或元素类型发生变化的情况 (`SerializeFixedArrayWithPossibleTransitions`)。
    * 对于数组中的 `hole` (未赋值的元素)，默认情况下会被序列化为 `null`。

* **对象序列化 (`SerializeJSObject`, `SerializeJSReceiverSlow`):**
    * 区分快速属性对象和慢速属性对象，采取不同的序列化策略以提高性能。
    * `SerializeJSObject` 处理拥有快速属性的对象，直接遍历其描述符进行序列化。
    * `SerializeJSReceiverSlow` 处理拥有慢速属性或需要访问检查的对象，通过 `KeyAccumulator` 获取可枚举的属性名。
    * 忽略不可枚举的属性。

* **字符串序列化 (`SerializeString`):**
    * 对字符串中的特殊字符进行转义，以符合 JSON 格式的要求（例如，`"`, `\`, 换行符等）。
    * 区分 One-Byte 字符串和 Two-Byte 字符串，并进行相应的处理。
    * 优化了简单属性键的序列化 (`TrySerializeSimplePropertyKey`)，对于符合特定条件的字符串键可以避免完整的转义过程。

* **`toJSON()` 方法支持:**  虽然这段代码中没有直接体现对 `toJSON()` 方法的调用，但可以推断出，在 `SerializeValue` 的其他分支或调用 `SerializeJSObject` 的过程中，会检查对象是否定义了 `toJSON()` 方法，并优先使用该方法的结果进行序列化。

* **循环引用处理 (`StackPush`, `StackPop`):**  通过维护一个栈来跟踪当前正在序列化的对象，检测并防止循环引用导致的无限递归。

* **缩进和格式化 (`Indent`, `Unindent`, `NewLine`):**  支持对输出的 JSON 字符串进行缩进和格式化，使其更易读 (如果提供了 `gap` 参数，即 `JSON.stringify(value, replacer, space)` 中的 `space`)。

* **`replacer` 函数支持:** 虽然这段代码没有直接展示 `replacer_function_` 的调用逻辑，但可以推断出在属性值被序列化之前，会先调用 `replacer` 函数对值进行转换。

* **`JSRawJson` 类型处理:** 专门处理 `JSON.rawJSON()` 返回的对象，直接提取其内部的 JSON 字符串，避免再次序列化。

**与 JavaScript 功能的关系和示例:**

这段 C++ 代码直接实现了 JavaScript 中的 `JSON.stringify()` 方法。以下 JavaScript 示例展示了它所实现的功能：

```javascript
const obj = {
  a: 1,
  b: "hello",
  c: true,
  d: null,
  e: [1, 2, 3],
  f: { g: "world" },
  h: undefined, // 会被忽略
  i: Symbol('sym'), // 会被忽略
  toJSON: function() { return "customized"; }
};

const arr = [1, , 3]; // 稀疏数组

console.log(JSON.stringify(obj));
// 输出: {"a":1,"b":"hello","c":true,"d":null,"e":[1,2,3],"f":{"g":"world"},"toJSON":"customized"}

console.log(JSON.stringify(arr));
// 输出: [1,null,3]

console.log(JSON.stringify({ key: JSON.rawJSON('"raw json string"') }));
// 输出: {"key":"raw json string"}
```

**代码逻辑推理的假设输入与输出:**

**假设输入:**  一个 JavaScript 对象 `{ x: 10, y: "test" }`

**预期输出:**  字符串 `"{\"x\":10,\"y\":\"test\"}"`

**代码逻辑推演:**

1. `JSON.stringify()` 在 C++ 层调用 `JsonStringifier::Serialize`。
2. `Serialize` 方法调用 `SerializeValue` 处理根对象。
3. `SerializeValue` 识别对象类型为 `JS_OBJECT_TYPE`。
4. 调用 `SerializeJSObject` 方法。
5. `SerializeJSObject` 遍历对象的属性 `x` 和 `y`。
6. 对于属性 `x`，键 `"x"` 被序列化，值 `10` (NUMBER_TYPE) 被 `SerializeHeapNumber` 或 `SerializeSmi` 序列化为 `"10"`。
7. 对于属性 `y`，键 `"y"` 被序列化，值 `"test"` (STRING_TYPE) 被 `SerializeString` 序列化为 `"\"test\""` (注意双引号被转义)。
8. 最终拼接成 `"{\"x\":10,\"y\":\"test\"}"`。

**涉及用户常见的编程错误:**

1. **尝试序列化包含循环引用的对象:**

   ```javascript
   const circularObj = {};
   circularObj.self = circularObj;
   JSON.stringify(circularObj); // 报错: Converting circular structure to JSON
   ```
   V8 的 `JsonStringifier` 会通过 `StackPush` 和 `StackPop` 检测到循环引用并抛出错误。

2. **尝试序列化包含 `BigInt` 的对象:**

   ```javascript
   const objWithBigInt = { n: 9007199254740991n };
   JSON.stringify(objWithBigInt); // 报错: Do not know how to serialize a BigInt
   ```
   `SerializeValue` 中会针对 `BIGINT_TYPE` 抛出 `TypeError`。

3. **期望序列化 `undefined`、`Symbol` 或函数:**

   ```javascript
   const objWithUndefined = { a: undefined, b: function() {} };
   JSON.stringify(objWithUndefined); // 输出: {}
   ```
   `SerializeValue` 中对于 `SYMBOL_TYPE` 返回 `UNCHANGED`，在对象属性中会被忽略。`undefined` 值也会被忽略。

4. **忘记 `JSON.stringify()` 不会序列化不可枚举的属性:**

   ```javascript
   const nonEnumObj = {};
   Object.defineProperty(nonEnumObj, 'a', { value: 1, enumerable: false });
   JSON.stringify(nonEnumObj); // 输出: {}
   ```
   `SerializeJSObject` 或 `SerializeJSReceiverSlow` 中会检查属性的 `enumerable` 特性。

**总结这段代码的功能：**

这段 `v8/src/json/json-stringifier.cc` 代码是 V8 引擎中 `JSON.stringify()` 方法的关键实现，负责将 JavaScript 对象转换为 JSON 字符串。它通过类型分发、针对不同类型的优化序列化策略、循环引用检测、以及对特殊类型的处理，实现了 JavaScript 中 `JSON.stringify()` 的核心功能。它还支持格式化输出和 `replacer` 函数，并处理了用户常见的与 JSON 序列化相关的编程错误。

### 提示词
```
这是目录为v8/src/json/json-stringifier.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/json/json-stringifier.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
InstanceType instance_type =
      Cast<HeapObject>(*object)->map(cage_base)->instance_type();
  switch (instance_type) {
    case HEAP_NUMBER_TYPE:
      if (deferred_string_key) SerializeDeferredKey(comma, key);
      return SerializeHeapNumber(Cast<HeapNumber>(object));
    case BIGINT_TYPE:
      isolate_->Throw(
          *factory()->NewTypeError(MessageTemplate::kBigIntSerializeJSON));
      return EXCEPTION;
    case ODDBALL_TYPE:
      switch (Cast<Oddball>(*object)->kind()) {
        case Oddball::kFalse:
          if (deferred_string_key) SerializeDeferredKey(comma, key);
          AppendCStringLiteral("false");
          return SUCCESS;
        case Oddball::kTrue:
          if (deferred_string_key) SerializeDeferredKey(comma, key);
          AppendCStringLiteral("true");
          return SUCCESS;
        case Oddball::kNull:
          if (deferred_string_key) SerializeDeferredKey(comma, key);
          AppendCStringLiteral("null");
          return SUCCESS;
        default:
          return UNCHANGED;
      }
    case JS_ARRAY_TYPE:
      if (deferred_string_key) SerializeDeferredKey(comma, key);
      return SerializeJSArray(Cast<JSArray>(object), key);
    case JS_PRIMITIVE_WRAPPER_TYPE:
      if (!need_stack_) {
        need_stack_ = true;
        return NEED_STACK;
      }
      if (deferred_string_key) SerializeDeferredKey(comma, key);
      return SerializeJSPrimitiveWrapper(Cast<JSPrimitiveWrapper>(object), key);
    case SYMBOL_TYPE:
      return UNCHANGED;
    case JS_RAW_JSON_TYPE:
      if (deferred_string_key) SerializeDeferredKey(comma, key);
      {
        Handle<JSRawJson> raw_json_obj = Cast<JSRawJson>(object);
        Handle<String> raw_json;
        if (raw_json_obj->HasInitialLayout(isolate_)) {
          // Fast path: the object returned by JSON.rawJSON has its initial map
          // intact.
          raw_json = Cast<String>(handle(
              raw_json_obj->InObjectPropertyAt(JSRawJson::kRawJsonInitialIndex),
              isolate_));
        } else {
          // Slow path: perform a property get for "rawJSON". Because raw JSON
          // objects are created frozen, it is still guaranteed that there will
          // be a property named "rawJSON" that is a String. Their initial maps
          // only change due to VM-internal operations like being optimized for
          // being used as a prototype.
          raw_json = Cast<String>(
              JSObject::GetProperty(isolate_, raw_json_obj,
                                    isolate_->factory()->raw_json_string())
                  .ToHandleChecked());
        }
        AppendString(raw_json);
      }
      return SUCCESS;
    case HOLE_TYPE:
      UNREACHABLE();
#if V8_ENABLE_WEBASSEMBLY
    case WASM_STRUCT_TYPE:
    case WASM_ARRAY_TYPE:
      return UNCHANGED;
#endif
    default:
      if (InstanceTypeChecker::IsString(instance_type)) {
        if (deferred_string_key) SerializeDeferredKey(comma, key);
        SerializeString<false>(Cast<String>(object));
        return SUCCESS;
      } else {
        // Make sure that we have a JSReceiver before we cast it to one.
        // If we ever leak an internal object that is not a JSReceiver it could
        // end up here and lead to a type confusion.
        CHECK(IsJSReceiver(*object));
        if (IsCallable(Cast<HeapObject>(*object), cage_base)) return UNCHANGED;
        // Go to slow path for global proxy and objects requiring access checks.
        if (deferred_string_key) SerializeDeferredKey(comma, key);
        if (InstanceTypeChecker::IsJSProxy(instance_type)) {
          return SerializeJSProxy(Cast<JSProxy>(object), key);
        }
        // WASM_{STRUCT,ARRAY}_TYPE are handled in `case:` blocks above.
        DCHECK(IsJSObject(*object));
        return SerializeJSObject(Cast<JSObject>(object), key);
      }
  }

  UNREACHABLE();
}

JsonStringifier::Result JsonStringifier::SerializeJSPrimitiveWrapper(
    Handle<JSPrimitiveWrapper> object, Handle<Object> key) {
  Tagged<Object> raw = object->value();
  if (IsString(raw)) {
    Handle<Object> value;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate_, value, Object::ToString(isolate_, object), EXCEPTION);
    SerializeString<false>(Cast<String>(value));
  } else if (IsNumber(raw)) {
    Handle<Object> value;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate_, value, Object::ToNumber(isolate_, object), EXCEPTION);
    if (IsSmi(*value)) return SerializeSmi(Cast<Smi>(*value));
    SerializeHeapNumber(Cast<HeapNumber>(value));
  } else if (IsBigInt(raw)) {
    isolate_->Throw(
        *factory()->NewTypeError(MessageTemplate::kBigIntSerializeJSON));
    return EXCEPTION;
  } else if (IsBoolean(raw)) {
    if (IsTrue(raw, isolate_)) {
      AppendCStringLiteral("true");
    } else {
      AppendCStringLiteral("false");
    }
  } else {
    // ES6 24.3.2.1 step 10.c, serialize as an ordinary JSObject.
    return SerializeJSObject(object, key);
  }
  return SUCCESS;
}

JsonStringifier::Result JsonStringifier::SerializeSmi(Tagged<Smi> object) {
  static_assert(Smi::kMaxValue <= 2147483647);
  static_assert(Smi::kMinValue >= -2147483648);
  // sizeof(string) includes \0.
  static const int kBufferSize = sizeof("-2147483648");
  char chars[kBufferSize];
  base::Vector<char> buffer(chars, kBufferSize);
  AppendCString(IntToCString(object.value(), buffer));
  return SUCCESS;
}

JsonStringifier::Result JsonStringifier::SerializeDouble(double number) {
  if (std::isinf(number) || std::isnan(number)) {
    AppendCStringLiteral("null");
    return SUCCESS;
  }
  static const int kBufferSize = 100;
  char chars[kBufferSize];
  base::Vector<char> buffer(chars, kBufferSize);
  AppendCString(DoubleToCString(number, buffer));
  return SUCCESS;
}

namespace {

bool CanTreatHoleAsUndefined(Isolate* isolate, Tagged<JSArray> object) {
  // If the no elements protector is intact, Array.prototype and
  // Object.prototype are guaranteed to not have elements in any native context.
  if (!Protectors::IsNoElementsIntact(isolate)) return false;
  Tagged<Map> map = object->map(isolate);
  Tagged<NativeContext> native_context = map->map(isolate)->native_context();
  Tagged<HeapObject> proto = map->prototype();
  return native_context->get(Context::INITIAL_ARRAY_PROTOTYPE_INDEX) == proto;
}

}  // namespace

JsonStringifier::Result JsonStringifier::SerializeJSArray(
    Handle<JSArray> object, Handle<Object> key) {
  uint32_t length = 0;
  CHECK(Object::ToArrayLength(object->length(), &length));
  DCHECK(!IsAccessCheckNeeded(*object));
  if (length == 0) {
    AppendCStringLiteral("[]");
    return SUCCESS;
  }

  Result stack_push = StackPush(object, key);
  if (stack_push != SUCCESS) return stack_push;

  AppendCharacter('[');
  Indent();
  uint32_t slow_path_index = 0;
  Result result = UNCHANGED;
  if (replacer_function_.is_null()) {
#define CASE_WITH_INTERRUPT(kind)                                           \
  case kind:                                                                \
    result = SerializeFixedArrayWithInterruptCheck<kind>(object, length,    \
                                                         &slow_path_index); \
    break;
#define CASE_WITH_TRANSITION(kind)                             \
  case kind:                                                   \
    result = SerializeFixedArrayWithPossibleTransitions<kind>( \
        object, length, &slow_path_index);                     \
    break;

    switch (object->GetElementsKind()) {
      CASE_WITH_INTERRUPT(PACKED_SMI_ELEMENTS)
      CASE_WITH_INTERRUPT(HOLEY_SMI_ELEMENTS)
      CASE_WITH_TRANSITION(PACKED_ELEMENTS)
      CASE_WITH_TRANSITION(HOLEY_ELEMENTS)
      CASE_WITH_INTERRUPT(PACKED_DOUBLE_ELEMENTS)
      CASE_WITH_INTERRUPT(HOLEY_DOUBLE_ELEMENTS)
      default:
        break;
    }

#undef CASE_WITH_TRANSITION
#undef CASE_WITH_INTERRUPT
  }
  if (result == UNCHANGED) {
    // Slow path for non-fast elements and fall-back in edge cases.
    result = SerializeArrayLikeSlow(object, slow_path_index, length);
  }
  if (result != SUCCESS) return result;
  Unindent();
  NewLine();
  AppendCharacter(']');
  StackPop();
  return SUCCESS;
}

template <ElementsKind kind>
JsonStringifier::Result JsonStringifier::SerializeFixedArrayWithInterruptCheck(
    DirectHandle<JSArray> array, uint32_t length, uint32_t* slow_path_index) {
  static_assert(IsSmiElementsKind(kind) || IsDoubleElementsKind(kind));
  using ArrayT = typename std::conditional<IsDoubleElementsKind(kind),
                                           FixedDoubleArray, FixedArray>::type;

  StackLimitCheck interrupt_check(isolate_);
  constexpr uint32_t kInterruptLength = 4000;
  uint32_t limit = std::min(length, kInterruptLength);
  constexpr uint32_t kMaxAllowedFastPackedLength =
      std::numeric_limits<uint32_t>::max() - kInterruptLength;
  static_assert(FixedArray::kMaxLength < kMaxAllowedFastPackedLength);

  constexpr bool is_holey = IsHoleyElementsKind(kind);
  bool bailout_on_hole =
      is_holey ? !CanTreatHoleAsUndefined(isolate_, *array) : true;

  uint32_t i = 0;
  while (true) {
    for (; i < limit; i++) {
      Result result = SerializeFixedArrayElement<kind>(
          Cast<ArrayT>(array->elements()), i, *array, bailout_on_hole);
      if constexpr (is_holey) {
        if (result != SUCCESS) {
          *slow_path_index = i;
          return result;
        }
      } else {
        USE(result);
        DCHECK_EQ(result, SUCCESS);
      }
    }
    if (i >= length) return SUCCESS;
    DCHECK_LT(limit, kMaxAllowedFastPackedLength);
    limit = std::min(length, limit + kInterruptLength);
    if (interrupt_check.InterruptRequested() &&
        IsException(isolate_->stack_guard()->HandleInterrupts(), isolate_)) {
      return EXCEPTION;
    }
  }
  return SUCCESS;
}

template <ElementsKind kind>
JsonStringifier::Result
JsonStringifier::SerializeFixedArrayWithPossibleTransitions(
    DirectHandle<JSArray> array, uint32_t length, uint32_t* slow_path_index) {
  static_assert(IsObjectElementsKind(kind));

  HandleScope handle_scope(isolate_);
  DirectHandle<Object> old_length(array->length(), isolate_);
  constexpr bool is_holey = IsHoleyElementsKind(kind);
  bool should_check_treat_hole_as_undefined = true;
  for (uint32_t i = 0; i < length; i++) {
    if (array->length() != *old_length || kind != array->GetElementsKind()) {
      // Array was modified during SerializeElement.
      *slow_path_index = i;
      return UNCHANGED;
    }
    Tagged<Object> current_element =
        Cast<FixedArray>(array->elements())->get(i);
    if (is_holey && IsTheHole(current_element)) {
      if (should_check_treat_hole_as_undefined) {
        if (!CanTreatHoleAsUndefined(isolate_, *array)) {
          *slow_path_index = i;
          return UNCHANGED;
        }
        should_check_treat_hole_as_undefined = false;
      }
      Separator(i == 0);
      AppendCStringLiteral("null");
    } else {
      Separator(i == 0);
      Result result = SerializeElement(
          isolate_, handle(Cast<JSAny>(current_element), isolate_), i);
      if (result == UNCHANGED) {
        AppendCStringLiteral("null");
      } else if (result != SUCCESS) {
        return result;
      }
      if constexpr (is_holey) {
        should_check_treat_hole_as_undefined = true;
      }
    }
  }
  return SUCCESS;
}

template <ElementsKind kind, typename T>
JsonStringifier::Result JsonStringifier::SerializeFixedArrayElement(
    Tagged<T> elements, uint32_t i, Tagged<JSArray> array,
    bool bailout_on_hole) {
  if constexpr (IsHoleyElementsKind(kind)) {
    if (elements->is_the_hole(isolate_, i)) {
      if (bailout_on_hole) return UNCHANGED;
      Separator(i == 0);
      AppendCStringLiteral("null");
      return SUCCESS;
    }
  }
  DCHECK(!elements->is_the_hole(isolate_, i));
  Separator(i == 0);
  if constexpr (IsSmiElementsKind(kind)) {
    SerializeSmi(Cast<Smi>(elements->get(i)));
  } else if constexpr (IsDoubleElementsKind(kind)) {
    SerializeDouble(elements->get_scalar(i));
  } else {
    UNREACHABLE();
  }
  return SUCCESS;
}

JsonStringifier::Result JsonStringifier::SerializeArrayLikeSlow(
    Handle<JSReceiver> object, uint32_t start, uint32_t length) {
  if (!need_stack_) {
    need_stack_ = true;
    return NEED_STACK;
  }
  // We need to write out at least two characters per array element.
  static const int kMaxSerializableArrayLength = String::kMaxLength / 2;
  if (length > kMaxSerializableArrayLength) {
    isolate_->Throw(*isolate_->factory()->NewInvalidStringLengthError());
    return EXCEPTION;
  }
  HandleScope handle_scope(isolate_);
  for (uint32_t i = start; i < length; i++) {
    Separator(i == 0);
    Handle<Object> element;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate_, element, JSReceiver::GetElement(isolate_, object, i),
        EXCEPTION);
    Result result = SerializeElement(isolate_, Cast<JSAny>(element), i);
    if (result == SUCCESS) continue;
    if (result == UNCHANGED) {
      // Detect overflow sooner for large sparse arrays.
      if (overflowed_) {
        isolate_->Throw(*isolate_->factory()->NewInvalidStringLengthError());
        return EXCEPTION;
      }
      AppendCStringLiteral("null");
    } else {
      return result;
    }
  }
  return SUCCESS;
}

namespace {
V8_INLINE bool CanFastSerializeJSObject(PtrComprCageBase cage_base,
                                        Tagged<JSObject> raw_object,
                                        Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  if (IsCustomElementsReceiverMap(raw_object->map(cage_base))) return false;
  if (!raw_object->HasFastProperties(cage_base)) return false;
  auto roots = ReadOnlyRoots(isolate);
  auto elements = raw_object->elements(cage_base);
  return elements == roots.empty_fixed_array() ||
         elements == roots.empty_slow_element_dictionary();
}
}  // namespace

JsonStringifier::Result JsonStringifier::SerializeJSObject(
    Handle<JSObject> object, Handle<Object> key) {
  PtrComprCageBase cage_base(isolate_);
  HandleScope handle_scope(isolate_);

  if (!property_list_.is_null() ||
      !CanFastSerializeJSObject(cage_base, *object, isolate_)) {
    if (!need_stack_) {
      need_stack_ = true;
      return NEED_STACK;
    }
    Result stack_push = StackPush(object, key);
    if (stack_push != SUCCESS) return stack_push;
    Result result = SerializeJSReceiverSlow(object);
    if (result != SUCCESS) return result;
    StackPop();
    return SUCCESS;
  }

  DCHECK(!IsJSGlobalProxy(*object));
  DCHECK(!object->HasIndexedInterceptor());
  DCHECK(!object->HasNamedInterceptor());

  DirectHandle<Map> map(object->map(cage_base), isolate_);
  if (map->NumberOfOwnDescriptors() == 0) {
    AppendCStringLiteral("{}");
    return SUCCESS;
  }

  Result stack_push = StackPush(object, key);
  if (stack_push != SUCCESS) return stack_push;
  AppendCharacter('{');
  Indent();
  bool comma = false;
  for (InternalIndex i : map->IterateOwnDescriptors()) {
    Handle<String> key_name;
    PropertyDetails details = PropertyDetails::Empty();
    {
      DisallowGarbageCollection no_gc;
      Tagged<DescriptorArray> descriptors =
          map->instance_descriptors(cage_base);
      Tagged<Name> name = descriptors->GetKey(i);
      // TODO(rossberg): Should this throw?
      if (!IsString(name, cage_base)) continue;
      key_name = handle(Cast<String>(name), isolate_);
      details = descriptors->GetDetails(i);
    }
    if (details.IsDontEnum()) continue;
    Handle<JSAny> property;
    if (details.location() == PropertyLocation::kField &&
        *map == object->map(cage_base)) {
      DCHECK_EQ(PropertyKind::kData, details.kind());
      FieldIndex field_index = FieldIndex::ForDetails(*map, details);
      if (replacer_function_.is_null()) {
        // If there's no replacer function, read the raw property to avoid
        // reboxing doubles in mutable boxes.
        property = handle(object->RawFastPropertyAt(field_index), isolate_);
      } else {
        // Rebox the value if there is a replacer function since it could change
        // the value in the box.
        property = JSObject::FastPropertyAt(
            isolate_, object, details.representation(), field_index);
      }
    } else {
      if (!need_stack_) {
        need_stack_ = true;
        return NEED_STACK;
      }
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate_, property,
          Cast<JSAny>(Object::GetPropertyOrElement(isolate_, object, key_name)),
          EXCEPTION);
    }
    Result result = SerializeProperty(property, comma, key_name);
    if (!comma && result == SUCCESS) comma = true;
    if (result == EXCEPTION || result == NEED_STACK) return result;
  }
  Unindent();
  if (comma) NewLine();
  AppendCharacter('}');
  StackPop();
  return SUCCESS;
}

JsonStringifier::Result JsonStringifier::SerializeJSReceiverSlow(
    Handle<JSReceiver> object) {
  Handle<FixedArray> contents = property_list_;
  if (contents.is_null()) {
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate_, contents,
        KeyAccumulator::GetKeys(isolate_, object, KeyCollectionMode::kOwnOnly,
                                ENUMERABLE_STRINGS,
                                GetKeysConversion::kConvertToString),
        EXCEPTION);
  }
  AppendCharacter('{');
  Indent();
  bool comma = false;
  for (int i = 0; i < contents->length(); i++) {
    Handle<String> key(Cast<String>(contents->get(i)), isolate_);
    Handle<Object> property;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate_, property, Object::GetPropertyOrElement(isolate_, object, key),
        EXCEPTION);
    Result result = SerializeProperty(Cast<JSAny>(property), comma, key);
    if (!comma && result == SUCCESS) comma = true;
    if (result == EXCEPTION || result == NEED_STACK) return result;
  }
  Unindent();
  if (comma) NewLine();
  AppendCharacter('}');
  return SUCCESS;
}

JsonStringifier::Result JsonStringifier::SerializeJSProxy(
    Handle<JSProxy> object, Handle<Object> key) {
  HandleScope scope(isolate_);
  Result stack_push = StackPush(object, key);
  if (stack_push != SUCCESS) return stack_push;
  Maybe<bool> is_array = Object::IsArray(object);
  if (is_array.IsNothing()) return EXCEPTION;
  if (is_array.FromJust()) {
    Handle<Object> length_object;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate_, length_object,
        Object::GetLengthFromArrayLike(isolate_, Cast<JSReceiver>(object)),
        EXCEPTION);
    uint32_t length;
    if (!Object::ToUint32(*length_object, &length)) {
      // Technically, we need to be able to handle lengths outside the
      // uint32_t range. However, we would run into string size overflow
      // if we tried to stringify such an array.
      isolate_->Throw(*isolate_->factory()->NewInvalidStringLengthError());
      return EXCEPTION;
    }
    AppendCharacter('[');
    Indent();
    Result result = SerializeArrayLikeSlow(object, 0, length);
    if (result != SUCCESS) return result;
    Unindent();
    if (length > 0) NewLine();
    AppendCharacter(']');
  } else {
    Result result = SerializeJSReceiverSlow(object);
    if (result != SUCCESS) return result;
  }
  StackPop();
  return SUCCESS;
}

template <typename SrcChar, typename DestChar, bool raw_json>
bool JsonStringifier::SerializeStringUnchecked_(
    base::Vector<const SrcChar> src, NoExtendBuilder<DestChar>* dest) {
  // Assert that base::uc16 character is not truncated down to 8 bit.
  // The <base::uc16, char> version of this method must not be called.
  DCHECK(sizeof(DestChar) >= sizeof(SrcChar));
  bool required_escaping = false;
  int prev_escaped_offset = -1;
  for (int i = 0; i < src.length(); i++) {
    SrcChar c = src[i];
    if (raw_json || DoNotEscape(c)) {
      continue;
    } else if (sizeof(SrcChar) != 1 &&
               base::IsInRange(c, static_cast<SrcChar>(0xD800),
                               static_cast<SrcChar>(0xDFFF))) {
      // The current character is a surrogate.
      required_escaping = true;
      dest->AppendSubstring(src.data(), prev_escaped_offset + 1, i);
      if (c <= 0xDBFF) {
        // The current character is a leading surrogate.
        if (i + 1 < src.length()) {
          // There is a next character.
          SrcChar next = src[i + 1];
          if (base::IsInRange(next, static_cast<SrcChar>(0xDC00),
                              static_cast<SrcChar>(0xDFFF))) {
            // The next character is a trailing surrogate, meaning this is a
            // surrogate pair.
            dest->Append(c);
            dest->Append(next);
            i++;
          } else {
            // The next character is not a trailing surrogate. Thus, the
            // current character is a lone leading surrogate.
            dest->AppendCString("\\u");
            char* const hex = DoubleToRadixCString(c, 16);
            dest->AppendCString(hex);
            DeleteArray(hex);
          }
        } else {
          // There is no next character. Thus, the current character is a lone
          // leading surrogate.
          dest->AppendCString("\\u");
          char* const hex = DoubleToRadixCString(c, 16);
          dest->AppendCString(hex);
          DeleteArray(hex);
        }
      } else {
        // The current character is a lone trailing surrogate. (If it had been
        // preceded by a leading surrogate, we would've ended up in the other
        // branch earlier on, and the current character would've been handled
        // as part of the surrogate pair already.)
        dest->AppendCString("\\u");
        char* const hex = DoubleToRadixCString(c, 16);
        dest->AppendCString(hex);
        DeleteArray(hex);
      }
      prev_escaped_offset = i;
    } else {
      required_escaping = true;
      dest->AppendSubstring(src.data(), prev_escaped_offset + 1, i);
      DCHECK_LT(c, 0x60);
      dest->AppendCString(&JsonEscapeTable[c * kJsonEscapeTableEntrySize]);
      prev_escaped_offset = i;
    }
  }
  dest->AppendSubstring(src.data(), prev_escaped_offset + 1, src.length());
  return required_escaping;
}

template <typename SrcChar, typename DestChar, bool raw_json>
bool JsonStringifier::SerializeString_(Tagged<String> string,
                                       const DisallowGarbageCollection& no_gc) {
  bool required_escaping = false;
  if (!raw_json) Append<uint8_t, DestChar>('"');
  // We might be able to fit the whole escaped string in the current string
  // part, or we might need to allocate.
  base::Vector<const SrcChar> vector = string->GetCharVector<SrcChar>(no_gc);
  if V8_LIKELY (EscapedLengthIfCurrentPartFits(vector.length())) {
    NoExtendBuilder<DestChar> no_extend(
        reinterpret_cast<DestChar*>(part_ptr_) + current_index_,
        &current_index_);
    required_escaping = SerializeStringUnchecked_<SrcChar, DestChar, raw_json>(
        vector, &no_extend);
  } else {
    DCHECK(encoding_ == String::TWO_BYTE_ENCODING ||
           (string->IsFlat() && string->IsOneByteRepresentation()));
    int prev_escaped_offset = -1;
    for (int i = 0; i < vector.length(); i++) {
      SrcChar c = vector.at(i);
      if (raw_json || DoNotEscape(c)) {
        continue;
      } else if (sizeof(SrcChar) != 1 &&
                 base::IsInRange(c, static_cast<SrcChar>(0xD800),
                                 static_cast<SrcChar>(0xDFFF))) {
        // The current character is a surrogate.
        required_escaping = true;
        AppendSubstring(vector.data(), prev_escaped_offset + 1, i);
        if (c <= 0xDBFF) {
          // The current character is a leading surrogate.
          if (i + 1 < vector.length()) {
            // There is a next character.
            SrcChar next = vector.at(i + 1);
            if (base::IsInRange(next, static_cast<SrcChar>(0xDC00),
                                static_cast<SrcChar>(0xDFFF))) {
              // The next character is a trailing surrogate, meaning this is a
              // surrogate pair.
              Append<SrcChar, DestChar>(c);
              Append<SrcChar, DestChar>(next);
              i++;
            } else {
              // The next character is not a trailing surrogate. Thus, the
              // current character is a lone leading surrogate.
              AppendCStringLiteral("\\u");
              char* const hex = DoubleToRadixCString(c, 16);
              AppendCString(hex);
              DeleteArray(hex);
            }
          } else {
            // There is no next character. Thus, the current character is a
            // lone leading surrogate.
            AppendCStringLiteral("\\u");
            char* const hex = DoubleToRadixCString(c, 16);
            AppendCString(hex);
            DeleteArray(hex);
          }
        } else {
          // The current character is a lone trailing surrogate. (If it had
          // been preceded by a leading surrogate, we would've ended up in the
          // other branch earlier on, and the current character would've been
          // handled as part of the surrogate pair already.)
          AppendCStringLiteral("\\u");
          char* const hex = DoubleToRadixCString(c, 16);
          AppendCString(hex);
          DeleteArray(hex);
        }
        prev_escaped_offset = i;
      } else {
        required_escaping = true;
        AppendSubstring(vector.data(), prev_escaped_offset + 1, i);
        DCHECK_LT(c, 0x60);
        AppendCString(&JsonEscapeTable[c * kJsonEscapeTableEntrySize]);
        prev_escaped_offset = i;
      }
    }
    AppendSubstring(vector.data(), prev_escaped_offset + 1, vector.length());
  }
  if (!raw_json) Append<uint8_t, DestChar>('"');
  return required_escaping;
}

template <typename DestChar>
bool JsonStringifier::TrySerializeSimplePropertyKey(
    Tagged<String> key, const DisallowGarbageCollection& no_gc) {
  ReadOnlyRoots roots(isolate_);
  if (key->map() != roots.internalized_one_byte_string_map()) {
    return false;
  }
  if (!key_cache_.Contains(key)) {
    return false;
  }
  int length = key->length();
  int copy_length = length;
  if constexpr (sizeof(DestChar) == 1) {
    // CopyChars has fast paths for small integer lengths, and is generally a
    // little faster if we round the length up to the nearest 4. This is still
    // within the bounds of the object on the heap, because object alignment is
    // never less than 4 for any build configuration.
    constexpr int kRounding = 4;
    static_assert(kRounding <= kObjectAlignment);
    copy_length = RoundUp(length, kRounding);
  }
  // Add three for the quote marks and colon, to determine how much output space
  // is needed. We might actually require a little less output space than this,
  // depending on how much rounding happened above, but it's more important to
  // compute the requirement quickly than to be precise.
  int required_length = copy_length + 3;
  if (!CurrentPartCanFit(required_length)) {
    return false;
  }
  NoExtendBuilder<DestChar> no_extend(
      reinterpret_cast<DestChar*>(part_ptr_) + current_index_, &current_index_);
  no_extend.Append('"');
  base::Vector<const uint8_t> chars(
      Cast<SeqOneByteString>(key)->GetChars(no_gc), copy_length);
  DCHECK_LE(reinterpret_cast<Address>(chars.end()),
            key.address() + key->Size());
#if DEBUG
  for (int i = 0; i < length; ++i) {
    DCHECK(DoNotEscape(chars[i]));
  }
#endif  // DEBUG
  no_extend.AppendChars(chars, length);
  no_extend.Append('"');
  no_extend.Append(':');
  return true;
}

template <>
bool JsonStringifier::DoNotEscape(uint8_t c) {
  // https://tc39.github.io/ecma262/#table-json-single-character-escapes
  return JsonDoNotEscapeFlagTable[c];
}

template <>
bool JsonStringifier::DoNotEscape(uint16_t c) {
  // https://tc39.github.io/ecma262/#table-json-single-character-escapes
  return (c >= 0x20 && c <= 0x21) ||
         (c >= 0x23 && c != 0x5C && (c < 0xD800 || c > 0xDFFF));
}

void JsonStringifier::NewLine() {
  if (gap_ == nullptr) return;
  NewLineOutline();
}

void JsonStringifier::NewLineOutline() {
  AppendCharacter('\n');
  for (int i = 0; i < indent_; i++) AppendCString(gap_);
}

void JsonStringifier::Separator(bool first) {
  if (!first) AppendCharacter(',');
  NewLine();
}

void JsonStringifier::SerializeDeferredKey(bool deferred_comma,
                                           Handle<Object> deferred_key) {
  Separator(!deferred_comma);
  Handle<String> string_key = Cast<String>(deferred_key);
  bool wrote_simple = false;
  {
    DisallowGarbageCollection no_gc;
    wrote_simple =
        encoding_ == String::ONE_BYTE_ENCODING
            ? TrySerializeSimplePropertyKey<uint8_t>(*string_key, no_gc)
            : TrySerializeSimplePropertyKey<base::uc16>(*string_key, no_gc);
  }

  if (!wrote_simple) {
    bool required_escaping = SerializeString<false>(string_key);
    if (!required_escaping) {
      key_cache_.TryInsert(*string_key);
    }
    AppendCharacter(':');
  }

  if (gap_ != nullptr) AppendCharacter(' ');
}

template <bool raw_json>
bool JsonStringifier::SerializeString(Handle<String> object) {
  object = String::Flatten(isolate_, object);
  DisallowGarbageCollection no_gc;
  auto string = *object;
  if (encoding_ == String::ONE_BYTE_ENCODING) {
    if (string->IsOneByteRepresentation()) {
      return SerializeString_<uint8_t, uint8_t, raw_json>(string, no_gc);
    } else {
      ChangeEncoding();
    }
  }
  DCHECK_EQ(encoding_, String::TWO_BYTE_ENCODING);
  if (string->IsOneByteRepresentation()) {
    return SerializeString_<uint8_t, base::uc16, raw_json>(string, no_gc);
  } else {
    return SerializeString_<base::uc16, base::uc16, raw_json>(string, no_gc);
  }
}

void JsonStringifier::Extend() {
  if (part_length_ >= String::kMaxLength) {
    // Set the flag and carry on. Delay throwing the exception till the end.
    current_index_ = 0;
    overflowed_ = true;
    return;
  }
  part_length_ *= kPartLengthGrowthFactor;
  if (encoding_ == String::ONE_BYTE_ENCODING) {
    uint8_t* tmp_ptr = new uint8_t[part_length_];
    memcpy(tmp_ptr, one_byte_ptr_, current_index_);
    if (one_byte_ptr_ != one_byte_array_) delete[] one_byte_ptr_;
    one_byte_ptr_ = tmp_ptr;
    part_ptr_ = one_byte_ptr_;
  } else {
    base::uc16* tmp_ptr = new base::uc16[part_length_];
    for (uint32_t i = 0; i < current_index_; i++) {
      tmp_ptr[i] = two_byte_ptr_[i];
    }
    delete[] two_byte_ptr_;
    two_byte_ptr_ = tmp_ptr;
    part_ptr_ = two_byte_ptr_;
  }
}

void JsonStringifier::ChangeEncoding() {
  encoding_ = String::TWO_BYTE_ENCODING;
  two_byte_ptr_ = new base::uc16[part_length_];
  for (uint32_t i = 0; i < current_index_; i++) {
    two_byte_ptr_[i] = one_byte_ptr_[i];
  }
  part_ptr_ = two_byte_ptr_;
  if (one_byte_ptr_ != one_byte_array_) delete[] one_byte_ptr_;
  one_byte_ptr_ = nullptr;
}

}  // namespace internal
}  // namespace v8
```