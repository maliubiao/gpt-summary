Response:
The user wants a summary of the functionality of the provided C++ code snippet from V8's `builtins-array.cc` file.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The code is within `builtins-array.cc`, suggesting it implements built-in JavaScript array methods. The presence of `ArrayConcat` hints at the `concat` method.

2. **Analyze the functions:**
    * `EstimateElementCount`:  This function iterates through an array and counts the number of actual elements (not holes). It handles various element kinds (PACKED, HOLEY, DICTIONARY, TYPED ARRAYS).
    * `CollectElementIndices`: This function gathers the indices of elements within a given range. It handles different element storage types and also considers the prototype chain.
    * `IterateElementsSlow`:  This is a fallback for iterating array elements when optimizations aren't possible. It uses `JSReceiver::HasElement` and `JSReceiver::GetElement`.
    * `IterateElements`: This function is the primary mechanism for iterating over array elements. It handles both fast (PACKED/HOLEY) and slow (DICTIONARY) array types, checking for holes and prototype properties.
    * `IsConcatSpreadable`: Checks if an object is "concat-spreadable" (whether its elements should be treated as individual items during concatenation). It looks for the `@@isConcatSpreadable` symbol.
    * `Slow_ArrayConcat`: This implements the `concat` method using a slower approach. It estimates the result size, handles different element kinds, and uses `ArrayConcatVisitor` to build the new array. It also handles non-array arguments.
    * `IsSimpleArray`:  Checks if an array is a simple, standard array (not a subclass with extra properties).
    * `Fast_ArrayConcat`: This implements an optimized, faster version of `concat` for simple arrays. It avoids unnecessary overhead.
    * `ArrayConcat`: This is the main entry point for the `Array.prototype.concat` built-in. It decides whether to use the fast or slow path based on array properties and the `@@species` constructor.

3. **Infer the context (from the filename and function names):** The code is clearly related to the `Array.prototype.concat()` JavaScript method.

4. **Connect C++ concepts to JavaScript behavior:**
    * Element kinds (PACKED, HOLEY, DICTIONARY) represent V8's internal optimizations for storing array elements. These directly affect the performance of JavaScript array operations.
    * The handling of "holes" (`IsTheHole`) is crucial for understanding how sparse arrays are treated in JavaScript.
    * The prototype chain interaction demonstrates how inherited properties are considered during concatenation.
    * The `@@isConcatSpreadable` symbol is a standard JavaScript mechanism that affects `concat`.
    * The distinction between `Fast_ArrayConcat` and `Slow_ArrayConcat` highlights V8's optimization strategies.

5. **Illustrate with JavaScript examples:** Provide concrete JavaScript code snippets that demonstrate the functionality of the C++ code. Focus on the `concat` method and the concepts of holes, spreadability, and custom array types.

6. **Identify potential user errors:** Think about common mistakes developers make when working with arrays, especially in the context of concatenation. This includes issues with non-array arguments, unexpected behavior with sparse arrays, and misunderstandings about `@@isConcatSpreadable`.

7. **Formulate assumptions for input/output:** Create simple scenarios with example array inputs and the expected output of the `concat` operation. This helps illustrate the code's logical flow.

8. **Address the ".tq" question:** Explain that if the file ended in `.tq`, it would be written in V8's Torque language, which is used for defining built-ins in a more structured way.

9. **Structure the answer:** Organize the information logically, starting with a general overview and then diving into the details of each function, JavaScript examples, potential errors, and input/output.

10. **Review and refine:** Ensure the explanation is clear, accurate, and addresses all aspects of the user's request. Double-check the JavaScript examples and the assumptions for input/output.

By following this thought process, the goal is to provide a comprehensive and understandable explanation of the provided V8 C++ code in relation to its corresponding JavaScript functionality.
```javascript
// 假设这是 JavaScript 代码，用于演示与提供的 C++ 代码片段相关的功能

// 1. 估计数组中元素的数量
function estimateElementCountJS(arr) {
  let count = 0;
  for (let i = 0; i < arr.length; i++) {
    if (arr[i] !== undefined) { // 模拟 C++ 中的 IsTheHole 检查
      count++;
    }
  }
  return count;
}

// 示例用法
const array1 = [1, 2, , 4]; // 稀疏数组
console.log("估计 array1 的元素数量:", estimateElementCountJS(array1)); // 输出: 3

const array2 = [1, 2, 3, 4];
console.log("估计 array2 的元素数量:", estimateElementCountJS(array2)); // 输出: 4

// 2. 收集数组元素的索引
function collectElementIndicesJS(arr, range) {
  const indices = [];
  const limit = Math.min(arr.length, range);
  for (let i = 0; i < limit; i++) {
    if (arr[i] !== undefined) {
      indices.push(i);
    }
  }
  return indices;
}

// 示例用法
const array3 = [10, , 30, , 50];
console.log("收集 array3 在范围 5 内的索引:", collectElementIndicesJS(array3, 5)); // 输出: [0, 2, 4]
console.log("收集 array3 在范围 3 内的索引:", collectElementIndicesJS(array3, 3)); // 输出: [0, 2]

// 3. 模拟 Array.prototype.concat 的慢速版本
function slowArrayConcatJS(...args) {
  const result = [];
  for (const arg of args) {
    if (Array.isArray(arg)) {
      for (const item of arg) {
        result.push(item);
      }
    } else {
      result.push(arg);
    }
  }
  return result;
}

console.log("慢速 concat 示例:", slowArrayConcatJS([1, 2], 3, [4, 5])); // 输出: [1, 2, 3, 4, 5]

// 4. 模拟 Array.prototype.concat 的快速版本 (针对简单数组)
function fastArrayConcatJS(...args) {
  const result = [];
  for (const arg of args) {
    if (Array.isArray(arg)) {
      for (let i = 0; i < arg.length; i++) {
        result.push(arg[i]);
      }
    } else {
      result.push(arg);
    }
  }
  return result;
}

console.log("快速 concat 示例:", fastArrayConcatJS([1, 2], 3, [4, 5])); // 输出: [1, 2, 3, 4, 5]

// 用户常见的编程错误示例

// 1. 误以为 concat 会修改原始数组
const originalArray = [1, 2];
const concatenatedArray = originalArray.concat(3, [4, 5]);
console.log("原始数组:", originalArray); // 输出: [1, 2] (未被修改)
console.log("连接后的数组:", concatenatedArray); // 输出: [1, 2, 3, 4, 5]

// 2. 对非数组使用 concat，期望像数组一样连接
const notAnArray = { 0: 'a', 1: 'b', length: 2 };
// @ts-ignore  concat 通常用于数组，这样使用可能不会得到期望的结果
const attemptedConcat = Array.prototype.concat.call(notAnArray, 'c');
console.log("尝试连接非数组:", attemptedConcat); // 输出: [{ '0': 'a', '1': 'b', length: 2 }, 'c']

// 3. 忘记 concat 返回一个新的数组
function modifyAndConcat(arr, item) {
  arr.push(item); // 直接修改了原始数组
  return arr.concat(item + 1); // 返回一个新的数组
}
const initialArray = [10];
const resultOfFunction = modifyAndConcat(initialArray, 20);
console.log("函数操作后的原始数组:", initialArray); // 输出: [10, 20] (已被修改)
console.log("函数返回的新数组:", resultOfFunction); // 输出: [10, 20, 21]

// 假设输入与输出 (针对 EstimateElementCount)
const inputEstimate1 = [1, , 3];
const outputEstimate1 = 2; // 有两个实际的元素

const inputEstimate2 = [undefined, null, 5];
const outputEstimate2 = 2; // undefined 被认为是 hole，null 和 5 是实际元素

// 假设输入与输出 (针对 CollectElementIndices)
const inputArray1 = [10, 20, , 40];
const range1 = 4;
const outputIndices1 = [0, 1, 3];

const inputArray2 = ['a', , 'c'];
const range2 = 2;
const outputIndices2 = [0];

// 假设输入与输出 (针对 Slow_ArrayConcat / Fast_ArrayConcat)
const concatInput1 = [[1, 2], 3, [4, 5]];
const concatOutput1 = [1, 2, 3, 4, 5];

const concatInput2 = [10, [20, 30], 'abc'];
const concatOutput2 = [10, 20, 30, 'abc'];
```

## 对 `v8/src/builtins/builtins-array.cc` 代码片段的功能归纳 (第 2 部分):

这段 C++ 代码是 V8 引擎中实现 JavaScript `Array.prototype.concat` 方法的关键部分。它包含了用于高效连接多个数组和非数组值的逻辑。主要功能可以归纳为：

1. **高效地估计数组中实际存在的元素数量 (`EstimateElementCount`)**:  这段代码能够快速确定数组中非空（非 hole）元素的个数。它会根据数组的不同存储方式（例如，紧密存储、稀疏存储、字典存储等）进行优化。这对于预先分配足够大小的内存来存储连接后的数组非常重要。

2. **收集指定范围内的元素索引 (`CollectElementIndices`)**:  此功能用于获取数组中指定范围内的有效索引。它同样考虑了不同类型的元素存储，并能处理原型链上的继承属性。这在需要按顺序访问数组元素时非常有用。

3. **实现 `Array.prototype.concat` 的核心逻辑 (`Slow_ArrayConcat` 和 `Fast_ArrayConcat`)**:
   - **慢速路径 (`Slow_ArrayConcat`)**:  处理更复杂的情况，例如当参数中包含非数组对象，或者需要考虑 `@@isConcatSpreadable` 符号时。它会逐步遍历所有参数，并将它们的元素添加到结果数组中。
   - **快速路径 (`Fast_ArrayConcat`)**:  针对简单、规范的数组进行了优化。如果所有参数都是简单的 JSArray 并且满足特定条件（例如，没有访问器属性），V8 可以使用更高效的方式进行连接，避免额外的开销。

4. **判断对象是否可展开连接 (`IsConcatSpreadable`)**:  检查一个对象是否可以像数组一样被 `concat` 方法展开。这涉及到检查对象的 `@@isConcatSpreadable` 符号。

5. **确定数组是否简单 (`IsSimpleArray`)**:  判断一个数组是否是标准的 JavaScript 数组，而非自定义子类或具有特殊属性的数组。这对于选择快速的连接路径至关重要。

**与 JavaScript 功能的关系:**

这段 C++ 代码直接实现了 JavaScript 中 `Array.prototype.concat` 方法的功能。当你在 JavaScript 中调用 `[1, 2].concat(3, [4, 5])` 时，V8 引擎最终会执行类似于这段 C++ 代码的逻辑来创建并返回一个新的数组 `[1, 2, 3, 4, 5]`。

**代码逻辑推理 (结合第 1 部分):**

- **输入**: 多个 JavaScript 值，作为 `concat` 方法的参数。
- **处理**:
    - 首先，V8 会尝试使用 `Fast_ArrayConcat` 进行快速连接。这需要满足一系列条件，例如所有参数都是简单的数组。
    - 如果无法使用快速路径，V8 会使用 `Slow_ArrayConcat`。
    - 在 `Slow_ArrayConcat` 中，会估计最终数组的长度和元素数量，并根据参数的类型和是否可展开来逐个添加元素。
- **输出**:  一个新的 JavaScript 数组，包含所有输入参数的元素（或参数本身，如果参数不可展开）。

**用户常见的编程错误:**

- **误解 `concat` 不会修改原始数组**: 开发者可能会错误地认为 `concat` 会直接修改调用它的数组，但实际上它总是返回一个新的数组。
- **对非数组对象使用 `concat` 并期望像数组一样连接**:  如果对一个类似数组的对象（例如，拥有 `length` 属性和数字索引属性的对象）使用 `concat`，但该对象没有被标记为可展开，那么该对象会被整体作为一个元素添加到结果数组中，而不是将其内部的元素展开。
- **忘记 `concat` 返回新数组，并尝试直接修改原始数组**: 开发者可能在调用 `concat` 后继续使用原始数组，而没有意识到连接操作的结果存储在新数组中。

**总结:**

这段 `v8/src/builtins/builtins-array.cc` 代码片段是 V8 引擎实现 `Array.prototype.concat` 方法的核心。它包含了用于优化连接操作的多种策略，能够处理不同类型的数组和非数组参数，并确保了 `concat` 方法的正确性和性能。通过估计元素数量、收集索引以及区分快速和慢速连接路径，V8 尽可能高效地完成了数组的连接操作。

### 提示词
```
这是目录为v8/src/builtins/builtins-array.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-array.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
tatic_cast<uint32_t>(Object::NumberValue(array->length()));
  int element_count = 0;
  switch (array->GetElementsKind()) {
    case PACKED_SMI_ELEMENTS:
    case HOLEY_SMI_ELEMENTS:
    case PACKED_ELEMENTS:
    case PACKED_FROZEN_ELEMENTS:
    case PACKED_SEALED_ELEMENTS:
    case PACKED_NONEXTENSIBLE_ELEMENTS:
    case HOLEY_FROZEN_ELEMENTS:
    case HOLEY_SEALED_ELEMENTS:
    case HOLEY_NONEXTENSIBLE_ELEMENTS:
    case HOLEY_ELEMENTS: {
      // Fast elements can't have lengths that are not representable by
      // a 32-bit signed integer.
      DCHECK_GE(static_cast<int32_t>(FixedArray::kMaxLength), 0);
      int fast_length = static_cast<int>(length);
      Tagged<FixedArray> elements = Cast<FixedArray>(array->elements());
      for (int i = 0; i < fast_length; i++) {
        if (!IsTheHole(elements->get(i), isolate)) element_count++;
      }
      break;
    }
    case PACKED_DOUBLE_ELEMENTS:
    case HOLEY_DOUBLE_ELEMENTS: {
      // Fast elements can't have lengths that are not representable by
      // a 32-bit signed integer.
      DCHECK_GE(static_cast<int32_t>(FixedDoubleArray::kMaxLength), 0);
      int fast_length = static_cast<int>(length);
      if (IsFixedArray(array->elements())) {
        DCHECK_EQ(Cast<FixedArray>(array->elements())->length(), 0);
        break;
      }
      Tagged<FixedDoubleArray> elements =
          Cast<FixedDoubleArray>(array->elements());
      for (int i = 0; i < fast_length; i++) {
        if (!elements->is_the_hole(i)) element_count++;
      }
      break;
    }
    case DICTIONARY_ELEMENTS: {
      Tagged<NumberDictionary> dictionary =
          Cast<NumberDictionary>(array->elements());
      ReadOnlyRoots roots(isolate);
      for (InternalIndex i : dictionary->IterateEntries()) {
        Tagged<Object> key = dictionary->KeyAt(i);
        if (dictionary->IsKey(roots, key)) {
          element_count++;
        }
      }
      break;
    }
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) case TYPE##_ELEMENTS:

      TYPED_ARRAYS(TYPED_ARRAY_CASE)
      RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
      // External arrays are always dense.
      return length;

#undef TYPED_ARRAY_CASE
    case NO_ELEMENTS:
      return 0;
    case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
    case SLOW_SLOPPY_ARGUMENTS_ELEMENTS:
    case FAST_STRING_WRAPPER_ELEMENTS:
    case SLOW_STRING_WRAPPER_ELEMENTS:
    case WASM_ARRAY_ELEMENTS:
    case SHARED_ARRAY_ELEMENTS:
      UNREACHABLE();
  }
  // As an estimate, we assume that the prototype doesn't contain any
  // inherited elements.
  return element_count;
}

void CollectElementIndices(Isolate* isolate, Handle<JSObject> object,
                           uint32_t range, std::vector<uint32_t>* indices) {
  ElementsKind kind = object->GetElementsKind();
  switch (kind) {
    case PACKED_SMI_ELEMENTS:
    case PACKED_ELEMENTS:
    case PACKED_FROZEN_ELEMENTS:
    case PACKED_SEALED_ELEMENTS:
    case PACKED_NONEXTENSIBLE_ELEMENTS:
    case HOLEY_SMI_ELEMENTS:
    case HOLEY_FROZEN_ELEMENTS:
    case HOLEY_SEALED_ELEMENTS:
    case HOLEY_NONEXTENSIBLE_ELEMENTS:
    case HOLEY_ELEMENTS: {
      DisallowGarbageCollection no_gc;
      Tagged<FixedArray> elements = Cast<FixedArray>(object->elements());
      uint32_t length = static_cast<uint32_t>(elements->length());
      if (range < length) length = range;
      for (uint32_t i = 0; i < length; i++) {
        if (!IsTheHole(elements->get(i), isolate)) {
          indices->push_back(i);
        }
      }
      break;
    }
    case HOLEY_DOUBLE_ELEMENTS:
    case PACKED_DOUBLE_ELEMENTS: {
      if (IsFixedArray(object->elements())) {
        DCHECK_EQ(object->elements()->length(), 0);
        break;
      }
      DirectHandle<FixedDoubleArray> elements(
          Cast<FixedDoubleArray>(object->elements()), isolate);
      uint32_t length = static_cast<uint32_t>(elements->length());
      if (range < length) length = range;
      for (uint32_t i = 0; i < length; i++) {
        if (!elements->is_the_hole(i)) {
          indices->push_back(i);
        }
      }
      break;
    }
    case DICTIONARY_ELEMENTS: {
      DisallowGarbageCollection no_gc;
      Tagged<NumberDictionary> dict =
          Cast<NumberDictionary>(object->elements());
      uint32_t capacity = dict->Capacity();
      ReadOnlyRoots roots(isolate);
      FOR_WITH_HANDLE_SCOPE(isolate, uint32_t, j = 0, j, j < capacity, j++, {
        Tagged<Object> k = dict->KeyAt(InternalIndex(j));
        if (!dict->IsKey(roots, k)) continue;
        DCHECK(IsNumber(k));
        uint32_t index = static_cast<uint32_t>(Object::NumberValue(k));
        if (index < range) {
          indices->push_back(index);
        }
      });
      break;
    }
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) case TYPE##_ELEMENTS:

      TYPED_ARRAYS(TYPED_ARRAY_CASE) RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE) {
        size_t length = Cast<JSTypedArray>(object)->GetLength();
        if (range <= length) {
          length = range;
          // We will add all indices, so we might as well clear it first
          // and avoid duplicates.
          indices->clear();
        }
        // {range} puts a cap on {length}.
        DCHECK_LE(length, std::numeric_limits<uint32_t>::max());
        for (uint32_t i = 0; i < length; i++) {
          indices->push_back(i);
        }
        if (length == range) return;  // All indices accounted for already.
        break;
      }

#undef TYPED_ARRAY_CASE
    case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
    case SLOW_SLOPPY_ARGUMENTS_ELEMENTS: {
      DisallowGarbageCollection no_gc;
      DisableGCMole no_gc_mole;
      Tagged<FixedArrayBase> elements = object->elements();
      Tagged<JSObject> raw_object = *object;
      ElementsAccessor* accessor = object->GetElementsAccessor();
      for (uint32_t i = 0; i < range; i++) {
        if (accessor->HasElement(raw_object, i, elements)) {
          indices->push_back(i);
        }
      }
      break;
    }
    case FAST_STRING_WRAPPER_ELEMENTS:
    case SLOW_STRING_WRAPPER_ELEMENTS: {
      DCHECK(IsJSPrimitiveWrapper(*object));
      auto js_value = Cast<JSPrimitiveWrapper>(object);
      DCHECK(IsString(js_value->value()));
      DirectHandle<String> string(Cast<String>(js_value->value()), isolate);
      uint32_t length = static_cast<uint32_t>(string->length());
      uint32_t i = 0;
      uint32_t limit = std::min(length, range);
      for (; i < limit; i++) {
        indices->push_back(i);
      }
      ElementsAccessor* accessor = object->GetElementsAccessor();
      for (; i < range; i++) {
        if (accessor->HasElement(*object, i)) {
          indices->push_back(i);
        }
      }
      break;
    }
    case WASM_ARRAY_ELEMENTS:
      // TODO(ishell): implement
      UNIMPLEMENTED();
    case SHARED_ARRAY_ELEMENTS: {
      uint32_t length = Cast<JSSharedArray>(object)->elements()->length();
      if (range <= length) {
        length = range;
        indices->clear();
      }
      for (uint32_t i = 0; i < length; i++) {
        // JSSharedArrays are created non-resizable and do not have holes.
        SLOW_DCHECK(object->GetElementsAccessor()->HasElement(
            *object, i, object->elements()));
        indices->push_back(i);
      }
      if (length == range) return;
      break;
    }
    case NO_ELEMENTS:
      break;
  }

  PrototypeIterator iter(isolate, object);
  if (!iter.IsAtEnd()) {
    // The prototype will usually have no inherited element indices,
    // but we have to check.
    // Casting to JSObject is safe because we ran {HasOnlySimpleElements} on
    // the receiver before, which checks the prototype chain.
    CollectElementIndices(
        isolate, PrototypeIterator::GetCurrent<JSObject>(iter), range, indices);
  }
}

bool IterateElementsSlow(Isolate* isolate, Handle<JSReceiver> receiver,
                         uint32_t length, ArrayConcatVisitor* visitor) {
  FOR_WITH_HANDLE_SCOPE(isolate, uint32_t, i = 0, i, i < length, ++i, {
    Maybe<bool> maybe = JSReceiver::HasElement(isolate, receiver, i);
    if (maybe.IsNothing()) return false;
    if (maybe.FromJust()) {
      Handle<Object> element_value;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, element_value, JSReceiver::GetElement(isolate, receiver, i),
          false);
      if (!visitor->visit(i, element_value)) return false;
    }
  });
  visitor->increase_index_offset(length);
  return true;
}
/**
 * A helper function that visits "array" elements of a JSReceiver in numerical
 * order.
 *
 * The visitor argument called for each existing element in the array
 * with the element index and the element's value.
 * Afterwards it increments the base-index of the visitor by the array
 * length.
 * Returns false if any access threw an exception, otherwise true.
 */
bool IterateElements(Isolate* isolate, Handle<JSReceiver> receiver,
                     ArrayConcatVisitor* visitor) {
  uint32_t length = 0;

  if (IsJSArray(*receiver)) {
    auto array = Cast<JSArray>(receiver);
    length = static_cast<uint32_t>(Object::NumberValue(array->length()));
  } else {
    Handle<Object> val;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, val, Object::GetLengthFromArrayLike(isolate, receiver), false);
    if (visitor->index_offset() + Object::NumberValue(*val) > kMaxSafeInteger) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kInvalidArrayLength));
      return false;
    }
    // TODO(caitp): Support larger element indexes (up to 2^53-1).
    if (!Object::ToUint32(*val, &length)) {
      length = 0;
    }
    // TODO(cbruni): handle other element kind as well
    return IterateElementsSlow(isolate, receiver, length, visitor);
  }

  if (!visitor->has_simple_elements() ||
      !HasOnlySimpleElements(isolate, *receiver)) {
    return IterateElementsSlow(isolate, receiver, length, visitor);
  }
  Handle<JSArray> array = Cast<JSArray>(receiver);

  switch (array->GetElementsKind()) {
    case PACKED_SMI_ELEMENTS:
    case PACKED_ELEMENTS:
    case PACKED_FROZEN_ELEMENTS:
    case PACKED_SEALED_ELEMENTS:
    case PACKED_NONEXTENSIBLE_ELEMENTS:
    case HOLEY_SMI_ELEMENTS:
    case HOLEY_FROZEN_ELEMENTS:
    case HOLEY_SEALED_ELEMENTS:
    case HOLEY_NONEXTENSIBLE_ELEMENTS:
    case HOLEY_ELEMENTS: {
      // Disallow execution so the cached elements won't change mid execution.
      DisallowJavascriptExecution no_js(isolate);

      // Run through the elements FixedArray and use HasElement and GetElement
      // to check the prototype for missing elements.
      DirectHandle<FixedArray> elements(Cast<FixedArray>(array->elements()),
                                        isolate);
      int fast_length = static_cast<int>(length);
      DCHECK(fast_length <= elements->length());
      FOR_WITH_HANDLE_SCOPE(isolate, int, j = 0, j, j < fast_length, j++, {
        Handle<Object> element_value(elements->get(j), isolate);
        if (!IsTheHole(*element_value, isolate)) {
          if (!visitor->visit(j, element_value)) return false;
        } else {
          Maybe<bool> maybe = JSReceiver::HasElement(isolate, array, j);
          if (maybe.IsNothing()) return false;
          if (maybe.FromJust()) {
            // Call GetElement on array, not its prototype, or getters won't
            // have the correct receiver.
            ASSIGN_RETURN_ON_EXCEPTION_VALUE(
                isolate, element_value,
                JSReceiver::GetElement(isolate, array, j), false);
            if (!visitor->visit(j, element_value)) return false;
          }
        }
      });
      break;
    }
    case HOLEY_DOUBLE_ELEMENTS:
    case PACKED_DOUBLE_ELEMENTS: {
      // Disallow execution so the cached elements won't change mid execution.
      DisallowJavascriptExecution no_js(isolate);

      // Empty array is FixedArray but not FixedDoubleArray.
      if (length == 0) break;
      // Run through the elements FixedArray and use HasElement and GetElement
      // to check the prototype for missing elements.
      if (IsFixedArray(array->elements())) {
        DCHECK_EQ(array->elements()->length(), 0);
        break;
      }
      DirectHandle<FixedDoubleArray> elements(
          Cast<FixedDoubleArray>(array->elements()), isolate);
      int fast_length = static_cast<int>(length);
      DCHECK(fast_length <= elements->length());
      FOR_WITH_HANDLE_SCOPE(isolate, int, j = 0, j, j < fast_length, j++, {
        if (!elements->is_the_hole(j)) {
          double double_value = elements->get_scalar(j);
          Handle<Object> element_value =
              isolate->factory()->NewNumber(double_value);
          if (!visitor->visit(j, element_value)) return false;
        } else {
          Maybe<bool> maybe = JSReceiver::HasElement(isolate, array, j);
          if (maybe.IsNothing()) return false;
          if (maybe.FromJust()) {
            // Call GetElement on array, not its prototype, or getters won't
            // have the correct receiver.
            Handle<Object> element_value;
            ASSIGN_RETURN_ON_EXCEPTION_VALUE(
                isolate, element_value,
                JSReceiver::GetElement(isolate, array, j), false);
            if (!visitor->visit(j, element_value)) return false;
          }
        }
      });
      break;
    }

    case DICTIONARY_ELEMENTS: {
      // Disallow execution so the cached dictionary won't change mid execution.
      DisallowJavascriptExecution no_js(isolate);

      DirectHandle<NumberDictionary> dict(array->element_dictionary(), isolate);
      std::vector<uint32_t> indices;
      indices.reserve(dict->Capacity() / 2);

      // Collect all indices in the object and the prototypes less
      // than length. This might introduce duplicates in the indices list.
      CollectElementIndices(isolate, array, length, &indices);
      std::sort(indices.begin(), indices.end());
      size_t n = indices.size();
      FOR_WITH_HANDLE_SCOPE(isolate, size_t, j = 0, j, j < n, (void)0, {
        uint32_t index = indices[j];
        Handle<Object> element;
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, element, JSReceiver::GetElement(isolate, array, index),
            false);
        if (!visitor->visit(index, element)) return false;
        // Skip to next different index (i.e., omit duplicates).
        do {
          j++;
        } while (j < n && indices[j] == index);
      });
      break;
    }
    case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
    case SLOW_SLOPPY_ARGUMENTS_ELEMENTS: {
      FOR_WITH_HANDLE_SCOPE(
          isolate, uint32_t, index = 0, index, index < length, index++, {
            Handle<Object> element;
            ASSIGN_RETURN_ON_EXCEPTION_VALUE(
                isolate, element, JSReceiver::GetElement(isolate, array, index),
                false);
            if (!visitor->visit(index, element)) return false;
          });
      break;
    }
    case WASM_ARRAY_ELEMENTS:
      // TODO(ishell): implement
      UNIMPLEMENTED();
    case NO_ELEMENTS:
      break;
      // JSArrays cannot have the following elements kinds:
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) case TYPE##_ELEMENTS:
      TYPED_ARRAYS(TYPED_ARRAY_CASE)
      RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
    case FAST_STRING_WRAPPER_ELEMENTS:
    case SLOW_STRING_WRAPPER_ELEMENTS:
    case SHARED_ARRAY_ELEMENTS:
      UNREACHABLE();
  }
  visitor->increase_index_offset(length);
  return true;
}

static Maybe<bool> IsConcatSpreadable(Isolate* isolate, Handle<Object> obj) {
  HandleScope handle_scope(isolate);
  Handle<JSReceiver> receiver;
  if (!TryCast<JSReceiver>(obj, &receiver)) return Just(false);
  if (!Protectors::IsIsConcatSpreadableLookupChainIntact(isolate) ||
      receiver->HasProxyInPrototype(isolate)) {
    // Slow path if @@isConcatSpreadable has been used.
    Handle<Symbol> key(isolate->factory()->is_concat_spreadable_symbol());
    Handle<Object> value;
    MaybeHandle<Object> maybeValue =
        i::Runtime::GetObjectProperty(isolate, receiver, key);
    if (!maybeValue.ToHandle(&value)) return Nothing<bool>();
    if (!IsUndefined(*value, isolate))
      return Just(Object::BooleanValue(*value, isolate));
  }
  return Object::IsArray(receiver);
}

Tagged<Object> Slow_ArrayConcat(BuiltinArguments* args, Handle<Object> species,
                                Isolate* isolate) {
  int argument_count = args->length();

  bool is_array_species = *species == isolate->context()->array_function();

  // Pass 1: estimate the length and number of elements of the result.
  // The actual length can be larger if any of the arguments have getters
  // that mutate other arguments (but will otherwise be precise).
  // The number of elements is precise if there are no inherited elements.

  ElementsKind kind = PACKED_SMI_ELEMENTS;

  uint32_t estimate_result_length = 0;
  uint32_t estimate_nof = 0;
  FOR_WITH_HANDLE_SCOPE(isolate, int, i = 0, i, i < argument_count, i++, {
    Handle<Object> obj = args->at(i);
    uint32_t length_estimate;
    uint32_t element_estimate;
    if (IsJSArray(*obj)) {
      auto array = Cast<JSArray>(obj);
      length_estimate =
          static_cast<uint32_t>(Object::NumberValue(array->length()));
      if (length_estimate != 0) {
        ElementsKind array_kind =
            GetPackedElementsKind(array->GetElementsKind());
        if (IsAnyNonextensibleElementsKind(array_kind)) {
          array_kind = PACKED_ELEMENTS;
        }
        kind = GetMoreGeneralElementsKind(kind, array_kind);
      }
      element_estimate = EstimateElementCount(isolate, array);
    } else {
      if (IsHeapObject(*obj)) {
        kind = GetMoreGeneralElementsKind(
            kind, IsNumber(*obj) ? PACKED_DOUBLE_ELEMENTS : PACKED_ELEMENTS);
      }
      length_estimate = 1;
      element_estimate = 1;
    }
    // Avoid overflows by capping at kMaxArrayLength.
    if (JSArray::kMaxArrayLength - estimate_result_length < length_estimate) {
      estimate_result_length = JSArray::kMaxArrayLength;
    } else {
      estimate_result_length += length_estimate;
    }
    if (JSArray::kMaxArrayLength - estimate_nof < element_estimate) {
      estimate_nof = JSArray::kMaxArrayLength;
    } else {
      estimate_nof += element_estimate;
    }
  });

  // If estimated number of elements is more than half of length, a
  // fixed array (fast case) is more time and space-efficient than a
  // dictionary.
  bool fast_case = is_array_species &&
                   (estimate_nof * 2) >= estimate_result_length &&
                   Protectors::IsIsConcatSpreadableLookupChainIntact(isolate);

  if (fast_case && kind == PACKED_DOUBLE_ELEMENTS) {
    Handle<FixedArrayBase> storage =
        isolate->factory()->NewFixedDoubleArray(estimate_result_length);
    int j = 0;
    bool failure = false;
    if (estimate_result_length > 0) {
      auto double_storage = Cast<FixedDoubleArray>(storage);
      for (int i = 0; i < argument_count; i++) {
        DirectHandle<Object> obj = args->at(i);
        if (IsSmi(*obj)) {
          double_storage->set(j, Smi::ToInt(*obj));
          j++;
        } else if (IsNumber(*obj)) {
          double_storage->set(j, Object::NumberValue(*obj));
          j++;
        } else {
          DisallowGarbageCollection no_gc;
          Tagged<JSArray> array = Cast<JSArray>(*obj);
          uint32_t length =
              static_cast<uint32_t>(Object::NumberValue(array->length()));
          switch (array->GetElementsKind()) {
            case HOLEY_DOUBLE_ELEMENTS:
            case PACKED_DOUBLE_ELEMENTS: {
              // Empty array is FixedArray but not FixedDoubleArray.
              if (length == 0) break;
              Tagged<FixedDoubleArray> elements =
                  Cast<FixedDoubleArray>(array->elements());
              for (uint32_t k = 0; k < length; k++) {
                if (elements->is_the_hole(k)) {
                  // TODO(jkummerow/verwaest): We could be a bit more clever
                  // here: Check if there are no elements/getters on the
                  // prototype chain, and if so, allow creation of a holey
                  // result array.
                  // Same thing below (holey smi case).
                  failure = true;
                  break;
                }
                double double_value = elements->get_scalar(k);
                double_storage->set(j, double_value);
                j++;
              }
              break;
            }
            case HOLEY_SMI_ELEMENTS:
            case PACKED_SMI_ELEMENTS: {
              Tagged<Object> the_hole = ReadOnlyRoots(isolate).the_hole_value();
              Tagged<FixedArray> elements(Cast<FixedArray>(array->elements()));
              for (uint32_t k = 0; k < length; k++) {
                Tagged<Object> element = elements->get(k);
                if (element == the_hole) {
                  failure = true;
                  break;
                }
                int32_t int_value = Smi::ToInt(element);
                double_storage->set(j, int_value);
                j++;
              }
              break;
            }
            case HOLEY_ELEMENTS:
            case HOLEY_FROZEN_ELEMENTS:
            case HOLEY_SEALED_ELEMENTS:
            case HOLEY_NONEXTENSIBLE_ELEMENTS:
            case PACKED_ELEMENTS:
            case PACKED_FROZEN_ELEMENTS:
            case PACKED_SEALED_ELEMENTS:
            case PACKED_NONEXTENSIBLE_ELEMENTS:
            case DICTIONARY_ELEMENTS:
            case NO_ELEMENTS:
              DCHECK_EQ(0u, length);
              break;
            default:
              UNREACHABLE();
          }
        }
        if (failure) {
#ifdef VERIFY_HEAP
          // The allocated storage may contain uninitialized values which will
          // cause FixedDoubleArray::FixedDoubleArrayVerify to fail, when the
          // heap is verified (see: crbug.com/1415071). To prevent this, we
          // initialize the array with holes.
          if (v8_flags.verify_heap) {
            double_storage->FillWithHoles(0, estimate_result_length);
          }
#endif  // VERIFY_HEAP
          break;
        }
      }
    }
    if (!failure) {
      return *isolate->factory()->NewJSArrayWithElements(storage, kind, j);
    }
    // In case of failure, fall through.
  }

  DirectHandle<UnionOf<JSReceiver, FixedArray, NumberDictionary>> storage;
  if (fast_case) {
    // The backing storage array must have non-existing elements to preserve
    // holes across concat operations.
    storage =
        isolate->factory()->NewFixedArrayWithHoles(estimate_result_length);
  } else if (is_array_species) {
    storage = NumberDictionary::New(isolate, estimate_nof);
  } else {
    DCHECK(IsConstructor(*species));
    Handle<Object> length(Smi::zero(), isolate);
    Handle<JSReceiver> storage_object;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, storage_object,
        Execution::New(isolate, species, species, 1, &length));
    storage = storage_object;
  }

  ArrayConcatVisitor visitor(isolate, storage, fast_case);

  for (int i = 0; i < argument_count; i++) {
    Handle<Object> obj = args->at(i);
    Maybe<bool> spreadable = IsConcatSpreadable(isolate, obj);
    MAYBE_RETURN(spreadable, ReadOnlyRoots(isolate).exception());
    if (spreadable.FromJust()) {
      Handle<JSReceiver> object = Cast<JSReceiver>(obj);
      if (!IterateElements(isolate, object, &visitor)) {
        return ReadOnlyRoots(isolate).exception();
      }
    } else {
      if (!visitor.visit(0, obj)) return ReadOnlyRoots(isolate).exception();
      visitor.increase_index_offset(1);
    }
  }

  if (visitor.exceeds_array_limit()) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kInvalidArrayLength));
  }

  if (is_array_species) {
    return *visitor.ToArray();
  } else {
    RETURN_RESULT_OR_FAILURE(isolate, visitor.ToJSReceiver());
  }
}

bool IsSimpleArray(Isolate* isolate, DirectHandle<JSArray> obj) {
  DisallowGarbageCollection no_gc;
  Tagged<Map> map = obj->map();
  // If there is only the 'length' property we are fine.
  if (map->prototype() ==
          isolate->native_context()->initial_array_prototype() &&
      map->NumberOfOwnDescriptors() == 1) {
    return true;
  }
  // TODO(cbruni): slower lookup for array subclasses and support slow
  // @@IsConcatSpreadable lookup.
  return false;
}

MaybeHandle<JSArray> Fast_ArrayConcat(Isolate* isolate,
                                      BuiltinArguments* args) {
  if (!Protectors::IsIsConcatSpreadableLookupChainIntact(isolate)) {
    return MaybeHandle<JSArray>();
  }
  // We shouldn't overflow when adding another len.
  const int kHalfOfMaxInt = 1 << (kBitsPerInt - 2);
  static_assert(FixedArray::kMaxLength < kHalfOfMaxInt);
  static_assert(FixedDoubleArray::kMaxLength < kHalfOfMaxInt);
  USE(kHalfOfMaxInt);

  int n_arguments = args->length();
  int result_len = 0;
  {
    DisallowGarbageCollection no_gc;
    // Iterate through all the arguments performing checks
    // and calculating total length.
    for (int i = 0; i < n_arguments; i++) {
      Tagged<Object> arg = (*args)[i];
      if (!IsJSArray(arg)) return MaybeHandle<JSArray>();
      if (!HasOnlySimpleReceiverElements(isolate, Cast<JSObject>(arg))) {
        return MaybeHandle<JSArray>();
      }
      // TODO(cbruni): support fast concatenation of DICTIONARY_ELEMENTS.
      if (!Cast<JSObject>(arg)->HasFastElements()) {
        return MaybeHandle<JSArray>();
      }
      DirectHandle<JSArray> array(Cast<JSArray>(arg), isolate);
      if (!IsSimpleArray(isolate, array)) {
        return MaybeHandle<JSArray>();
      }
      // The Array length is guaranted to be <= kHalfOfMaxInt thus we won't
      // overflow.
      result_len += Smi::ToInt(array->length());
      DCHECK_GE(result_len, 0);
      // Throw an Error if we overflow the FixedArray limits
      if (FixedDoubleArray::kMaxLength < result_len ||
          FixedArray::kMaxLength < result_len) {
        AllowGarbageCollection gc;
        THROW_NEW_ERROR(isolate,
                        NewRangeError(MessageTemplate::kInvalidArrayLength));
      }
    }
  }
  return ElementsAccessor::Concat(isolate, args, n_arguments, result_len);
}

}  // namespace

// ES6 22.1.3.1 Array.prototype.concat
BUILTIN(ArrayConcat) {
  HandleScope scope(isolate);

  Handle<JSAny> receiver = args.receiver();
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, receiver,
      Object::ToObject(isolate, args.receiver(), "Array.prototype.concat"));
  BuiltinArguments::ChangeValueScope set_receiver_value_scope(
      isolate, &args, BuiltinArguments::kReceiverIndex, *receiver);

  Handle<JSArray> result_array;

  // Avoid a real species read to avoid extra lookups to the array constructor
  if (V8_LIKELY(IsJSArray(*receiver) &&
                Cast<JSArray>(receiver)->HasArrayPrototype(isolate) &&
                Protectors::IsArraySpeciesLookupChainIntact(isolate))) {
    if (Fast_ArrayConcat(isolate, &args).ToHandle(&result_array)) {
      return *result_array;
    }
    if (isolate->has_exception()) return ReadOnlyRoots(isolate).exception();
  }
  // Reading @@species happens before anything else with a side effect, so
  // we can do it here to determine whether to take the fast path.
  Handle<Object> species;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, species, Object::ArraySpeciesConstructor(isolate, receiver));
  if (*species == *isolate->array_function()) {
    if (Fast_ArrayConcat(isolate, &args).ToHandle(&result_array)) {
      return *result_array;
    }
    if (isolate->has_exception()) return ReadOnlyRoots(isolate).exception();
  }
  return Slow_ArrayConcat(&args, species, isolate);
}

}  // namespace internal
}  // namespace v8
```