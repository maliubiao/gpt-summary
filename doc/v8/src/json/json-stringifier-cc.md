Response:
Let's break down the thought process for analyzing this V8 source code snippet.

**1. Initial Understanding and Context:**

* **File Path:** `v8/src/json/json-stringifier.cc` immediately tells us this code is responsible for JSON serialization within the V8 JavaScript engine. The `.cc` extension confirms it's C++ code.
* **Copyright Notice:**  Standard V8 copyright, indicating this is official V8 code.
* **Includes:**  The included headers give clues about the functionality:
    * `"src/json/json-stringifier.h"`: The corresponding header file, likely containing class declarations.
    * `"src/base/strings.h"`: Basic string manipulation.
    * `"src/common/assert-scope.h"`: Assertions for debugging.
    * `"src/common/message-template.h"`:  For generating error messages.
    * `"src/execution/protectors-inl.h"`: Likely related to performance optimizations or security checks.
    * `"src/numbers/conversions.h"`: Converting numbers to strings.
    * `"src/objects/*"`:  A lot of includes related to V8's internal object representation (arrays, numbers, strings, etc.). This strongly suggests the code deals with traversing and converting JavaScript objects to JSON.

**2. Core Class: `JsonStringifier`:**

* **Constructor and Destructor:**  The constructor initializes members, and the destructor cleans up allocated memory ( `one_byte_ptr_`, `two_byte_ptr_`, `gap_`). This suggests the class manages its own buffers.
* **`Stringify` Method:** This is the main entry point. It takes a JavaScript object, a replacer function/array, and a gap (for indentation) as input and returns a JSON string. The `MaybeHandle<Object>` return type indicates it can return a JavaScript string or an exception.
* **Private Helper Methods:** The numerous private methods reveal the steps involved in serialization:
    * `InitializeReplacer`, `InitializeGap`:  Handle the optional `replacer` and `gap` arguments of `JSON.stringify`.
    * `ApplyToJsonFunction`, `ApplyReplacerFunction`: Implement the logic for the `toJSON()` method and the `replacer` function.
    * `SerializeObject`, `SerializeElement`, `SerializeProperty`: Core serialization logic for different types of data within the JavaScript object.
    * `Append*`: Methods for building the JSON string in the internal buffer. The presence of both `one_byte_ptr_` and `two_byte_ptr_` suggests the string builder handles both ASCII and Unicode characters efficiently.
    * `SerializeSmi`, `SerializeDouble`, `SerializeHeapNumber`, `SerializeJS*`: Handle serialization of specific JavaScript types.
    * `SerializeString`:  Handles the escaping of special characters within strings.
    * `StackPush`, `StackPop`:  Crucial for detecting and handling circular references.
    * Helper classes like `SimplePropertyKeyCache` and `NoExtendBuilder` indicate optimizations for common scenarios.

**3. Key Functionality Deduction:**

Based on the methods and includes, we can deduce the core functionalities:

* **JSON Serialization:**  The primary goal is to convert JavaScript values into their JSON string representation.
* **Handling `replacer`:** The code correctly implements the `replacer` argument, which can be either a function or an array of allowed keys.
* **Handling `gap`:**  Implements the `gap` argument for pretty-printing JSON output with indentation.
* **Type Handling:** The code has specific logic for handling various JavaScript types: primitives (numbers, strings, booleans, null), arrays, and objects.
* **Circular Reference Detection:** The `StackPush` and `StackPop` methods, along with the `stack_` member, are clearly designed to detect and report circular references, a common issue with JSON serialization.
* **String Building and Efficiency:** The class manages its own string buffers (`one_byte_`, `two_byte_`) and employs strategies like `AppendStringByCopy` and `SimplePropertyKeyCache` to optimize string building.
* **Error Handling:** The use of `MaybeHandle` and checks for `isolate_->has_exception()` indicate proper error handling.

**4. Answering the Specific Questions:**

* **Functionality Listing:**  Now we can list the functionalities in a structured way.
* **`.tq` Extension:** The code clearly uses `.cc`, so it's C++, not Torque.
* **JavaScript Relation and Examples:**  We connect the C++ code to the corresponding `JSON.stringify()` JavaScript function and provide relevant examples.
* **Code Logic Reasoning and Assumptions:**  For circular references, we can create an example JavaScript object and explain how the stack mechanism would detect the cycle. For replacer functions, we can show input and expected output.
* **Common Programming Errors:**  Circular references are the most prominent error this code addresses. We can provide an example of such an error in JavaScript.
* **Part 1 Summary:** We summarize the main responsibilities of the code based on our analysis so far.

**5. Iterative Refinement (Self-Correction):**

* **Initially, I might focus too much on individual methods.**  It's important to step back and see the bigger picture – the overall process of serialization.
* **I might miss the significance of certain data structures.** For example, the `SimplePropertyKeyCache` is an optimization. Recognizing its purpose improves the understanding of the code's efficiency considerations.
* **I need to ensure the JavaScript examples accurately reflect the C++ logic.** This requires careful consideration of how the `replacer` and `gap` parameters work.
* **The circular reference detection logic is crucial.**  It's important to explain how the stack is used to track visited objects and how the error message is constructed.

By following this thought process, combining code reading with knowledge of JSON serialization and V8 internals, we can arrive at a comprehensive understanding of the provided code snippet and accurately answer the given questions.
这是目录为`v8/src/json/json-stringifier.cc`的一个V8源代码，主要负责实现JavaScript中的`JSON.stringify()`功能。

**功能归纳:**

`v8/src/json/json-stringifier.cc` 文件的主要功能是将 JavaScript 对象转换为 JSON 字符串。 它处理了 `JSON.stringify()` 函数的各种方面，包括：

1. **基本类型序列化:**  将 JavaScript 的基本类型 (如数字、字符串、布尔值、null) 转换为相应的 JSON 表示。
2. **对象序列化:**  遍历 JavaScript 对象的属性，并将它们转换为 JSON 格式的键值对。
3. **数组序列化:**  遍历 JavaScript 数组的元素，并将它们转换为 JSON 格式的数组。
4. **`toJSON()` 方法处理:**  如果对象具有 `toJSON()` 方法，则调用该方法以获取要序列化的值。
5. **`replacer` 参数处理:**
    * 如果 `replacer` 是一个函数，则在序列化每个属性之前调用该函数，以允许修改或过滤要包含在 JSON 字符串中的值。
    * 如果 `replacer` 是一个数组，则只序列化数组中指定的属性。
6. **`gap` 参数处理:**  如果提供了 `gap` 参数（字符串或数字），则在输出的 JSON 字符串中添加缩进和换行符，使其更易读。
7. **循环引用检测:**  检测对象中的循环引用，以防止无限递归并抛出 `TypeError`。
8. **字符串转义:**  正确地转义 JSON 字符串中需要转义的字符 (例如 `\`, `"`, 换行符等)。
9. **性能优化:**  使用各种技巧来提高序列化过程的性能，例如缓存简单属性键。
10. **错误处理:**  处理可能发生的错误，例如堆栈溢出或无效的字符串长度。

**关于文件类型:**

`v8/src/json/json-stringifier.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**。 如果它以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。

**与 JavaScript 功能的关系和示例:**

`v8/src/json/json-stringifier.cc` 中的代码直接实现了 JavaScript 的 `JSON.stringify()` 方法。

**JavaScript 示例:**

```javascript
const obj = {
  name: "John Doe",
  age: 30,
  city: "New York",
  hobbies: ["reading", "coding"]
};

const jsonString = JSON.stringify(obj);
console.log(jsonString);
// 输出: {"name":"John Doe","age":30,"city":"New York","hobbies":["reading","coding"]}

const objWithToJson = {
  data: "some data",
  toJSON: function() {
    return { customData: this.data.toUpperCase() };
  }
};

const jsonStringWithToJson = JSON.stringify(objWithToJson);
console.log(jsonStringWithToJson);
// 输出: {"customData":"SOME DATA"}

const objWithReplacerFunction = { a: 1, b: '2', c: 3 };
const jsonStringWithReplacerFunction = JSON.stringify(objWithReplacerFunction, (key, value) => {
  if (typeof value === 'number') {
    return value * 2;
  }
  return value;
});
console.log(jsonStringWithReplacerFunction);
// 输出: {"a":2,"b":"2","c":6}

const objWithReplacerArray = { a: 1, b: '2', c: 3 };
const jsonStringWithReplacerArray = JSON.stringify(objWithReplacerArray, ['a', 'c']);
console.log(jsonStringWithReplacerArray);
// 输出: {"a":1,"c":3}

const objWithGap = { a: 1, b: 2 };
const jsonStringWithGap = JSON.stringify(objWithGap, null, 2);
console.log(jsonStringWithGap);
// 输出:
// {
//   "a": 1,
//   "b": 2
// }

const circularObj = {};
circularObj.self = circularObj;
try {
  JSON.stringify(circularObj);
} catch (error) {
  console.error(error); // 输出 TypeError: Converting circular structure to JSON
}
```

**代码逻辑推理和假设输入与输出:**

**假设输入:**

```javascript
const inputObject = {
  name: "Alice",
  details: {
    age: 25,
    occupation: "Engineer"
  }
};
```

**代码逻辑推理 (简化):**

1. `Stringify` 方法会被调用，传入 `inputObject`。
2. `SerializeObject` 方法会被调用来处理顶层对象。
3. 对于 `name` 属性：
   - `SerializeProperty` 会被调用，`deferred_key` 为 "name"。
   - `Serialize_<true>` 模板方法会被调用。
   - `SerializeString` 或其变体会被调用，将 "Alice" 转义为 JSON 字符串 `"Alice"`。
   - 输出缓冲区会追加 `"name":"Alice"`。
4. 对于 `details` 属性：
   - `SerializeProperty` 会被调用，`deferred_key` 为 "details"。
   - `Serialize_<true>` 模板方法会被调用。
   - 由于 `details` 是一个对象，`SerializeJSObject` 会被调用。
   - 递归地处理 `details` 对象的属性 (age, occupation)。
   - 输出缓冲区会追加 `"details":{...}`。
5. 最终，输出缓冲区的内容会组合成 JSON 字符串。

**假设输出:**

```json
{"name":"Alice","details":{"age":25,"occupation":"Engineer"}}
```

**用户常见的编程错误:**

1. **循环引用:**  在对象中创建循环引用会导致 `JSON.stringify()` 抛出 `TypeError`。

   ```javascript
   const a = {};
   const b = { a: a };
   a.b = b;
   try {
     JSON.stringify(a); // 抛出 TypeError
   } catch (e) {
     console.error(e);
   }
   ```

2. **尝试序列化包含 `undefined`、Symbol 或函数属性的对象:**  `JSON.stringify()` 会忽略这些属性或将其转换为 `null` (对于数组元素)。

   ```javascript
   const objWithUndefined = { a: 1, b: undefined };
   console.log(JSON.stringify(objWithUndefined)); // 输出: {"a":1}

   const objWithSymbol = { a: 1, b: Symbol('test') };
   console.log(JSON.stringify(objWithSymbol)); // 输出: {"a":1}

   const objWithFunction = { a: 1, b: function() {} };
   console.log(JSON.stringify(objWithFunction)); // 输出: {"a":1}

   const arrWithUndefined = [1, undefined, 3];
   console.log(JSON.stringify(arrWithUndefined)); // 输出: [1,null,3]
   ```

3. **假设 `JSON.stringify()` 可以序列化所有 JavaScript 对象而不丢失信息:** 某些类型的对象（例如 `Map`、`Set`）默认情况下不会被 `JSON.stringify()` 正确序列化，除非提供了自定义的 `toJSON()` 方法。

   ```javascript
   const map = new Map();
   map.set('key', 'value');
   console.log(JSON.stringify(map)); // 输出: {} (空对象)

   const set = new Set([1, 2, 3]);
   console.log(JSON.stringify(set)); // 输出: {} (空对象)
   ```

**总结 `v8/src/json/json-stringifier.cc` 的功能 (第 1 部分):**

`v8/src/json/json-stringifier.cc` 文件的主要职责是实现 V8 引擎中 `JSON.stringify()` 的核心逻辑。 它负责将各种 JavaScript 数据类型转换为符合 JSON 规范的字符串表示形式，并处理 `replacer` 和 `gap` 等可选参数，同时检测和防止循环引用。 该文件是 V8 引擎中处理 JSON 序列化的关键组件。

### 提示词
```
这是目录为v8/src/json/json-stringifier.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/json/json-stringifier.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/json/json-stringifier.h"

#include "src/base/strings.h"
#include "src/common/assert-scope.h"
#include "src/common/message-template.h"
#include "src/execution/protectors-inl.h"
#include "src/numbers/conversions.h"
#include "src/objects/elements-kind.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-raw-json-inl.h"
#include "src/objects/lookup.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball-inl.h"
#include "src/objects/ordered-hash-table.h"
#include "src/objects/smi.h"
#include "src/objects/tagged.h"
#include "src/strings/string-builder-inl.h"

namespace v8 {
namespace internal {

class JsonStringifier {
 public:
  explicit JsonStringifier(Isolate* isolate);

  ~JsonStringifier() {
    if (one_byte_ptr_ != one_byte_array_) delete[] one_byte_ptr_;
    if (two_byte_ptr_) delete[] two_byte_ptr_;
    DeleteArray(gap_);
  }

  V8_WARN_UNUSED_RESULT MaybeHandle<Object> Stringify(Handle<JSAny> object,
                                                      Handle<JSAny> replacer,
                                                      Handle<Object> gap);

 private:
  enum Result { UNCHANGED, SUCCESS, EXCEPTION, NEED_STACK };

  bool InitializeReplacer(Handle<JSAny> replacer);
  bool InitializeGap(Handle<Object> gap);

  V8_WARN_UNUSED_RESULT MaybeHandle<JSAny> ApplyToJsonFunction(
      Handle<JSAny> object, Handle<Object> key);
  V8_WARN_UNUSED_RESULT MaybeHandle<JSAny> ApplyReplacerFunction(
      Handle<JSAny> value, Handle<Object> key,
      DirectHandle<Object> initial_holder);

  // Entry point to serialize the object.
  V8_INLINE Result SerializeObject(Handle<JSAny> obj) {
    return Serialize_<false>(obj, false, factory()->empty_string());
  }

  // Serialize an array element.
  // The index may serve as argument for the toJSON function.
  V8_INLINE Result SerializeElement(Isolate* isolate, Handle<JSAny> object,
                                    int i) {
    return Serialize_<false>(object, false,
                             Handle<Object>(Smi::FromInt(i), isolate));
  }

  // Serialize an object property.
  // The key may or may not be serialized depending on the property.
  // The key may also serve as argument for the toJSON function.
  V8_INLINE Result SerializeProperty(Handle<JSAny> object, bool deferred_comma,
                                     Handle<String> deferred_key) {
    DCHECK(!deferred_key.is_null());
    return Serialize_<true>(object, deferred_comma, deferred_key);
  }

  template <typename SrcChar, typename DestChar>
  V8_INLINE void Append(SrcChar c) {
    DCHECK_EQ(encoding_ == String::ONE_BYTE_ENCODING, sizeof(DestChar) == 1);
    if (sizeof(DestChar) == 1) {
      DCHECK_EQ(String::ONE_BYTE_ENCODING, encoding_);
      one_byte_ptr_[current_index_++] = c;
    } else {
      DCHECK_EQ(String::TWO_BYTE_ENCODING, encoding_);
      // Make sure to use unsigned extension even when SrcChar == char.
      two_byte_ptr_[current_index_++] =
          static_cast<std::make_unsigned_t<SrcChar>>(c);
    }
    if V8_UNLIKELY (current_index_ == part_length_) Extend();
  }

  V8_INLINE void AppendCharacter(uint8_t c) {
    if (encoding_ == String::ONE_BYTE_ENCODING) {
      Append<uint8_t, uint8_t>(c);
    } else {
      Append<uint8_t, base::uc16>(c);
    }
  }

  template <int N>
  V8_INLINE void AppendCStringLiteral(const char (&literal)[N]) {
    // Note that the literal contains the zero char.
    const int length = N - 1;
    static_assert(length > 0);
    if (length == 1) return AppendCharacter(literal[0]);
    if (encoding_ == String::ONE_BYTE_ENCODING && CurrentPartCanFit(N)) {
      const uint8_t* chars = reinterpret_cast<const uint8_t*>(literal);
      CopyChars<uint8_t, uint8_t>(one_byte_ptr_ + current_index_, chars,
                                  length);
      current_index_ += length;
      if (current_index_ == part_length_) Extend();
      DCHECK(HasValidCurrentIndex());
      return;
    }
    return AppendCString(literal);
  }

  template <typename SrcChar>
  V8_INLINE void AppendCString(const SrcChar* s) {
    if (encoding_ == String::ONE_BYTE_ENCODING) {
      while (*s != '\0') Append<SrcChar, uint8_t>(*s++);
    } else {
      while (*s != '\0') Append<SrcChar, base::uc16>(*s++);
    }
  }

  V8_INLINE bool CurrentPartCanFit(uint32_t length) {
    return part_length_ - current_index_ > length;
  }

  // We make a rough estimate to find out if the current string can be
  // serialized without allocating a new string part. The worst case length of
  // an escaped character is 6. Shifting the remaining string length right by 3
  // is a more pessimistic estimate, but faster to calculate.
  V8_INLINE bool EscapedLengthIfCurrentPartFits(uint32_t length) {
    if (length > kMaxPartLength) return false;
    static_assert(kMaxPartLength <= (String::kMaxLength >> 3));
    // This shift will not overflow because length is already less than the
    // maximum part length.
    return CurrentPartCanFit(length << 3);
  }

  void AppendStringByCopy(Tagged<String> string, uint32_t length,
                          const DisallowGarbageCollection& no_gc) {
    DCHECK_EQ(length, string->length());
    DCHECK(encoding_ == String::TWO_BYTE_ENCODING ||
           (string->IsFlat() && string->IsOneByteRepresentation()));
    DCHECK(CurrentPartCanFit(length + 1));
    String::FlatContent flat = string->GetFlatContent(no_gc);
    if (encoding_ == String::ONE_BYTE_ENCODING) {
      if (flat.IsOneByte()) {
        CopyChars<uint8_t, uint8_t>(one_byte_ptr_ + current_index_,
                                    flat.ToOneByteVector().begin(), length);
      } else {
        ChangeEncoding();
        CopyChars<uint16_t, uint16_t>(two_byte_ptr_ + current_index_,
                                      flat.ToUC16Vector().begin(), length);
      }
    } else {
      if (flat.IsOneByte()) {
        CopyChars<uint8_t, uint16_t>(two_byte_ptr_ + current_index_,
                                     flat.ToOneByteVector().begin(), length);
      } else {
        CopyChars<uint16_t, uint16_t>(two_byte_ptr_ + current_index_,
                                      flat.ToUC16Vector().begin(), length);
      }
    }
    current_index_ += length;
    DCHECK(current_index_ <= part_length_);
  }

  V8_NOINLINE void AppendString(Handle<String> string_handle) {
    {
      DisallowGarbageCollection no_gc;
      Tagged<String> string = *string_handle;
      const bool representation_ok =
          encoding_ == String::TWO_BYTE_ENCODING ||
          (string->IsFlat() && string->IsOneByteRepresentation());
      if (representation_ok) {
        uint32_t length = string->length();
        while (!CurrentPartCanFit(length + 1)) Extend();
        AppendStringByCopy(string, length, no_gc);
        return;
      }
    }
    SerializeString<true>(string_handle);
  }

  template <typename SrcChar>
  void AppendSubstringByCopy(const SrcChar* src, int count) {
    DCHECK(CurrentPartCanFit(count + 1));
    if (encoding_ == String::ONE_BYTE_ENCODING) {
      if (sizeof(SrcChar) == 1) {
        CopyChars<SrcChar, uint8_t>(one_byte_ptr_ + current_index_, src, count);
      } else {
        ChangeEncoding();
        CopyChars<SrcChar, base::uc16>(two_byte_ptr_ + current_index_, src,
                                       count);
      }
    } else {
      CopyChars<SrcChar, base::uc16>(two_byte_ptr_ + current_index_, src,
                                     count);
    }
    current_index_ += count;
    DCHECK_LE(current_index_, part_length_);
  }

  template <typename SrcChar>
  V8_NOINLINE void AppendSubstring(const SrcChar* src, size_t from, size_t to) {
    if (from == to) return;
    DCHECK_LT(from, to);
    uint32_t count = static_cast<uint32_t>(to - from);
    while (!CurrentPartCanFit(count + 1)) Extend();
    AppendSubstringByCopy(src + from, count);
  }

  bool HasValidCurrentIndex() const { return current_index_ < part_length_; }

  template <bool deferred_string_key>
  Result Serialize_(Handle<JSAny> object, bool comma, Handle<Object> key);

  V8_INLINE void SerializeDeferredKey(bool deferred_comma,
                                      Handle<Object> deferred_key);

  Result SerializeSmi(Tagged<Smi> object);

  Result SerializeDouble(double number);
  V8_INLINE Result SerializeHeapNumber(DirectHandle<HeapNumber> object) {
    return SerializeDouble(object->value());
  }

  Result SerializeJSPrimitiveWrapper(Handle<JSPrimitiveWrapper> object,
                                     Handle<Object> key);

  V8_INLINE Result SerializeJSArray(Handle<JSArray> object, Handle<Object> key);
  V8_INLINE Result SerializeJSObject(Handle<JSObject> object,
                                     Handle<Object> key);

  Result SerializeJSProxy(Handle<JSProxy> object, Handle<Object> key);
  Result SerializeJSReceiverSlow(Handle<JSReceiver> object);
  template <ElementsKind kind>
  V8_INLINE Result SerializeFixedArrayWithInterruptCheck(
      DirectHandle<JSArray> array, uint32_t length, uint32_t* slow_path_index);
  template <ElementsKind kind>
  V8_INLINE Result SerializeFixedArrayWithPossibleTransitions(
      DirectHandle<JSArray> array, uint32_t length, uint32_t* slow_path_index);
  template <ElementsKind kind, typename T>
  V8_INLINE Result SerializeFixedArrayElement(Tagged<T> elements, uint32_t i,
                                              Tagged<JSArray> array,
                                              bool can_treat_hole_as_undefined);
  Result SerializeArrayLikeSlow(Handle<JSReceiver> object, uint32_t start,
                                uint32_t length);

  // Returns whether any escape sequences were used.
  template <bool raw_json>
  bool SerializeString(Handle<String> object);

  template <typename DestChar>
  class NoExtendBuilder {
   public:
    NoExtendBuilder(DestChar* start, size_t* current_index)
        : current_index_(current_index), start_(start), cursor_(start) {}
    ~NoExtendBuilder() { *current_index_ += cursor_ - start_; }

    V8_INLINE void Append(DestChar c) { *(cursor_++) = c; }
    V8_INLINE void AppendCString(const char* s) {
      const uint8_t* u = reinterpret_cast<const uint8_t*>(s);
      while (*u != '\0') Append(*(u++));
    }

    // Appends all of the chars from the provided span, but only increases the
    // cursor by `length`. This allows oversizing the span to the nearest
    // convenient multiple, allowing CopyChars to run slightly faster.
    V8_INLINE void AppendChars(base::Vector<const uint8_t> chars,
                               size_t length) {
      DCHECK_GE(chars.size(), length);
      CopyChars(cursor_, chars.begin(), chars.size());
      cursor_ += length;
    }

    template <typename SrcChar>
    V8_INLINE void AppendSubstring(const SrcChar* src, size_t from, size_t to) {
      if (from == to) return;
      DCHECK_LT(from, to);
      int count = static_cast<int>(to - from);
      CopyChars(cursor_, src + from, count);
      cursor_ += count;
    }

   private:
    size_t* current_index_;
    DestChar* start_;
    DestChar* cursor_;
  };

  // A cache of recently seen property keys which were simple. Simple means:
  //
  // - Internalized, sequential, one-byte string
  // - Contains no characters which need escaping
  //
  // This can be helpful because it's common for JSON to have lists of similar
  // objects. Since property keys are internalized, we will see identical key
  // pointers again and again, and we can use a fast path to copy those keys to
  // the output. However, strings can be externalized any time JS runs, so the
  // caller is responsible for checking whether a string is still the expected
  // type. This cache is cleared on GC, since the GC could move those strings.
  // Using Handles for the cache has been tried, but is too expensive to set up
  // when JSON.stringify is called for tiny inputs.
  class SimplePropertyKeyCache {
   public:
    explicit SimplePropertyKeyCache(Isolate* isolate) : isolate_(isolate) {
      Clear();
      isolate->main_thread_local_heap()->AddGCEpilogueCallback(
          UpdatePointersCallback, this);
    }

    ~SimplePropertyKeyCache() {
      isolate_->main_thread_local_heap()->RemoveGCEpilogueCallback(
          UpdatePointersCallback, this);
    }

    void TryInsert(Tagged<String> string) {
      ReadOnlyRoots roots(isolate_);
      if (string->map() == roots.internalized_one_byte_string_map()) {
        keys_[GetIndex(string)] = MaybeCompress(string);
      }
    }

    bool Contains(Tagged<String> string) {
      return keys_[GetIndex(string)] == MaybeCompress(string);
    }

   private:
    size_t GetIndex(Tagged<String> string) {
      // Short strings are 16 bytes long in pointer-compression builds, so the
      // lower four bits of the pointer may not provide much entropy.
      return (string.ptr() >> 4) & kIndexMask;
    }

    Tagged_t MaybeCompress(Tagged<String> string) {
      return COMPRESS_POINTERS_BOOL
                 ? V8HeapCompressionScheme::CompressObject(string.ptr())
                 : static_cast<Tagged_t>(string.ptr());
    }

    void Clear() { MemsetTagged(keys_, Smi::zero(), kSize); }

    static void UpdatePointersCallback(void* cache) {
      reinterpret_cast<SimplePropertyKeyCache*>(cache)->Clear();
    }

    static constexpr size_t kSizeBits = 6;
    static constexpr size_t kSize = 1 << kSizeBits;
    static constexpr size_t kIndexMask = kSize - 1;

    Isolate* isolate_;
    Tagged_t keys_[kSize];
  };

  // Returns whether any escape sequences were used.
  template <typename SrcChar, typename DestChar, bool raw_json>
  V8_INLINE static bool SerializeStringUnchecked_(
      base::Vector<const SrcChar> src, NoExtendBuilder<DestChar>* dest);

  // Returns whether any escape sequences were used.
  template <typename SrcChar, typename DestChar, bool raw_json>
  V8_INLINE bool SerializeString_(Tagged<String> string,
                                  const DisallowGarbageCollection& no_gc);

  // Tries to do fast-path serialization for a property key, and returns whether
  // it was successful.
  template <typename DestChar>
  bool TrySerializeSimplePropertyKey(Tagged<String> string,
                                     const DisallowGarbageCollection& no_gc);

  template <typename Char>
  V8_INLINE static bool DoNotEscape(Char c);

  V8_INLINE void NewLine();
  V8_NOINLINE void NewLineOutline();
  V8_INLINE void Indent() { indent_++; }
  V8_INLINE void Unindent() { indent_--; }
  V8_INLINE void Separator(bool first);

  Handle<JSReceiver> CurrentHolder(DirectHandle<Object> value,
                                   DirectHandle<Object> inital_holder);

  Result StackPush(Handle<Object> object, Handle<Object> key);
  void StackPop();

  // Uses the current stack_ to provide a detailed error message of
  // the objects involved in the circular structure.
  Handle<String> ConstructCircularStructureErrorMessage(
      DirectHandle<Object> last_key, size_t start_index);
  // The prefix and postfix count do NOT include the starting and
  // closing lines of the error message.
  static const int kCircularErrorMessagePrefixCount = 2;
  static const int kCircularErrorMessagePostfixCount = 1;

  static const size_t kInitialPartLength = 2048;
  static const size_t kMaxPartLength = 16 * 1024;
  static const size_t kPartLengthGrowthFactor = 2;

  Factory* factory() { return isolate_->factory(); }

  V8_NOINLINE void Extend();
  V8_NOINLINE void ChangeEncoding();

  Isolate* isolate_;
  String::Encoding encoding_;
  Handle<FixedArray> property_list_;
  Handle<JSReceiver> replacer_function_;
  uint8_t* one_byte_ptr_;
  base::uc16* gap_;
  base::uc16* two_byte_ptr_;
  void* part_ptr_;
  int indent_;
  size_t part_length_;
  size_t current_index_;
  int stack_nesting_level_;
  bool overflowed_;
  bool need_stack_;

  using KeyObject = std::pair<Handle<Object>, Handle<Object>>;
  std::vector<KeyObject> stack_;

  SimplePropertyKeyCache key_cache_;
  uint8_t one_byte_array_[kInitialPartLength];

  static const int kJsonEscapeTableEntrySize = 8;
  static const char* const JsonEscapeTable;
  static const bool JsonDoNotEscapeFlagTable[];
};

MaybeHandle<Object> JsonStringify(Isolate* isolate, Handle<JSAny> object,
                                  Handle<JSAny> replacer, Handle<Object> gap) {
  JsonStringifier stringifier(isolate);
  return stringifier.Stringify(object, replacer, gap);
}

// Translation table to escape Latin1 characters.
// Table entries start at a multiple of 8 and are null-terminated.
const char* const JsonStringifier::JsonEscapeTable =
    "\\u0000\0 \\u0001\0 \\u0002\0 \\u0003\0 "
    "\\u0004\0 \\u0005\0 \\u0006\0 \\u0007\0 "
    "\\b\0     \\t\0     \\n\0     \\u000b\0 "
    "\\f\0     \\r\0     \\u000e\0 \\u000f\0 "
    "\\u0010\0 \\u0011\0 \\u0012\0 \\u0013\0 "
    "\\u0014\0 \\u0015\0 \\u0016\0 \\u0017\0 "
    "\\u0018\0 \\u0019\0 \\u001a\0 \\u001b\0 "
    "\\u001c\0 \\u001d\0 \\u001e\0 \\u001f\0 "
    " \0      !\0      \\\"\0     #\0      "
    "$\0      %\0      &\0      '\0      "
    "(\0      )\0      *\0      +\0      "
    ",\0      -\0      .\0      /\0      "
    "0\0      1\0      2\0      3\0      "
    "4\0      5\0      6\0      7\0      "
    "8\0      9\0      :\0      ;\0      "
    "<\0      =\0      >\0      ?\0      "
    "@\0      A\0      B\0      C\0      "
    "D\0      E\0      F\0      G\0      "
    "H\0      I\0      J\0      K\0      "
    "L\0      M\0      N\0      O\0      "
    "P\0      Q\0      R\0      S\0      "
    "T\0      U\0      V\0      W\0      "
    "X\0      Y\0      Z\0      [\0      "
    "\\\\\0     ]\0      ^\0      _\0      ";

const bool JsonStringifier::JsonDoNotEscapeFlagTable[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};

JsonStringifier::JsonStringifier(Isolate* isolate)
    : isolate_(isolate),
      encoding_(String::ONE_BYTE_ENCODING),
      gap_(nullptr),
      two_byte_ptr_(nullptr),
      indent_(0),
      part_length_(kInitialPartLength),
      current_index_(0),
      stack_nesting_level_(0),
      overflowed_(false),
      need_stack_(false),
      stack_(),
      key_cache_(isolate) {
  one_byte_ptr_ = one_byte_array_;
  part_ptr_ = one_byte_ptr_;
}

MaybeHandle<Object> JsonStringifier::Stringify(Handle<JSAny> object,
                                               Handle<JSAny> replacer,
                                               Handle<Object> gap) {
  if (!InitializeReplacer(replacer)) {
    CHECK(isolate_->has_exception());
    return MaybeHandle<Object>();
  }
  if (!IsUndefined(*gap, isolate_) && !InitializeGap(gap)) {
    CHECK(isolate_->has_exception());
    return MaybeHandle<Object>();
  }
  Result result = SerializeObject(object);
  if (result == NEED_STACK) {
    indent_ = 0;
    current_index_ = 0;
    result = SerializeObject(object);
  }
  if (result == UNCHANGED) return factory()->undefined_value();
  if (result == SUCCESS) {
    if (overflowed_ || current_index_ > String::kMaxLength) {
      THROW_NEW_ERROR(isolate_, NewInvalidStringLengthError());
    }
    if (encoding_ == String::ONE_BYTE_ENCODING) {
      return isolate_->factory()
          ->NewStringFromOneByte(base::OneByteVector(
              reinterpret_cast<char*>(one_byte_ptr_), current_index_))
          .ToHandleChecked();
    } else {
      return isolate_->factory()->NewStringFromTwoByte(
          base::Vector<const base::uc16>(two_byte_ptr_, current_index_));
    }
  }
  DCHECK(result == EXCEPTION);
  CHECK(isolate_->has_exception());
  return MaybeHandle<Object>();
}

bool JsonStringifier::InitializeReplacer(Handle<JSAny> replacer) {
  DCHECK(property_list_.is_null());
  DCHECK(replacer_function_.is_null());
  Maybe<bool> is_array = Object::IsArray(replacer);
  if (is_array.IsNothing()) return false;
  if (is_array.FromJust()) {
    HandleScope handle_scope(isolate_);
    Handle<OrderedHashSet> set = factory()->NewOrderedHashSet();
    Handle<Object> length_obj;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate_, length_obj,
        Object::GetLengthFromArrayLike(isolate_, Cast<JSReceiver>(replacer)),
        false);
    uint32_t length;
    if (!Object::ToUint32(*length_obj, &length)) length = kMaxUInt32;
    for (uint32_t i = 0; i < length; i++) {
      Handle<Object> element;
      Handle<String> key;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate_, element, Object::GetElement(isolate_, replacer, i), false);
      if (IsNumber(*element) || IsString(*element)) {
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate_, key, Object::ToString(isolate_, element), false);
      } else if (IsJSPrimitiveWrapper(*element)) {
        DirectHandle<Object> value(Cast<JSPrimitiveWrapper>(element)->value(),
                                   isolate_);
        if (IsNumber(*value) || IsString(*value)) {
          ASSIGN_RETURN_ON_EXCEPTION_VALUE(
              isolate_, key, Object::ToString(isolate_, element), false);
        }
      }
      if (key.is_null()) continue;
      // Object keys are internalized, so do it here.
      key = factory()->InternalizeString(key);
      MaybeHandle<OrderedHashSet> set_candidate =
          OrderedHashSet::Add(isolate_, set, key);
      if (!set_candidate.ToHandle(&set)) {
        CHECK(isolate_->has_exception());
        return false;
      }
    }
    property_list_ = OrderedHashSet::ConvertToKeysArray(
        isolate_, set, GetKeysConversion::kKeepNumbers);
    property_list_ = handle_scope.CloseAndEscape(property_list_);
  } else if (IsCallable(*replacer)) {
    replacer_function_ = Cast<JSReceiver>(replacer);
  }
  return true;
}

bool JsonStringifier::InitializeGap(Handle<Object> gap) {
  DCHECK_NULL(gap_);
  HandleScope scope(isolate_);
  if (IsJSPrimitiveWrapper(*gap)) {
    DirectHandle<Object> value(Cast<JSPrimitiveWrapper>(gap)->value(),
                               isolate_);
    if (IsString(*value)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate_, gap,
                                       Object::ToString(isolate_, gap), false);
    } else if (IsNumber(*value)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate_, gap,
                                       Object::ToNumber(isolate_, gap), false);
    }
  }

  if (IsString(*gap)) {
    auto gap_string = Cast<String>(gap);
    if (gap_string->length() > 0) {
      uint32_t gap_length = std::min(gap_string->length(), 10u);
      gap_ = NewArray<base::uc16>(gap_length + 1);
      String::WriteToFlat(*gap_string, gap_, 0, gap_length);
      for (uint32_t i = 0; i < gap_length; i++) {
        if (gap_[i] > String::kMaxOneByteCharCode) {
          ChangeEncoding();
          break;
        }
      }
      gap_[gap_length] = '\0';
    }
  } else if (IsNumber(*gap)) {
    double value = std::min(Object::NumberValue(*gap), 10.0);
    if (value > 0) {
      uint32_t gap_length = DoubleToUint32(value);
      gap_ = NewArray<base::uc16>(gap_length + 1);
      for (uint32_t i = 0; i < gap_length; i++) gap_[i] = ' ';
      gap_[gap_length] = '\0';
    }
  }
  return true;
}

MaybeHandle<JSAny> JsonStringifier::ApplyToJsonFunction(Handle<JSAny> object,
                                                        Handle<Object> key) {
  HandleScope scope(isolate_);

  // Retrieve toJSON function. The LookupIterator automatically handles
  // the ToObject() equivalent ("GetRoot") if {object} is a BigInt.
  Handle<Object> fun;
  LookupIterator it(isolate_, object, factory()->toJSON_string(),
                    LookupIterator::PROTOTYPE_CHAIN_SKIP_INTERCEPTOR);
  ASSIGN_RETURN_ON_EXCEPTION(isolate_, fun, Object::GetProperty(&it));
  if (!IsCallable(*fun)) return object;

  // Call toJSON function.
  if (IsSmi(*key)) key = factory()->NumberToString(key);
  Handle<Object> argv[] = {key};
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate_, object,
      Cast<JSAny>(Execution::Call(isolate_, fun, object, 1, argv)));
  return scope.CloseAndEscape(object);
}

MaybeHandle<JSAny> JsonStringifier::ApplyReplacerFunction(
    Handle<JSAny> value, Handle<Object> key,
    DirectHandle<Object> initial_holder) {
  HandleScope scope(isolate_);
  if (IsSmi(*key)) key = factory()->NumberToString(key);
  Handle<Object> argv[] = {key, value};
  Handle<JSReceiver> holder = CurrentHolder(value, initial_holder);
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate_, value,
      Cast<JSAny>(
          Execution::Call(isolate_, replacer_function_, holder, 2, argv)));
  return scope.CloseAndEscape(value);
}

Handle<JSReceiver> JsonStringifier::CurrentHolder(
    DirectHandle<Object> value, DirectHandle<Object> initial_holder) {
  if (stack_.empty()) {
    Handle<JSObject> holder =
        factory()->NewJSObject(isolate_->object_function());
    JSObject::AddProperty(isolate_, holder, factory()->empty_string(),
                          initial_holder, NONE);
    return holder;
  } else {
    return Handle<JSReceiver>(Cast<JSReceiver>(*stack_.back().second),
                              isolate_);
  }
}

JsonStringifier::Result JsonStringifier::StackPush(Handle<Object> object,
                                                   Handle<Object> key) {
  if (!need_stack_) {
    ++stack_nesting_level_;
    if V8_UNLIKELY (stack_nesting_level_ > 10) {
      need_stack_ = true;
      return NEED_STACK;
    }
    return SUCCESS;
  }
  StackLimitCheck check(isolate_);
  if (check.HasOverflowed()) {
    isolate_->StackOverflow();
    return EXCEPTION;
  }

  {
    DisallowGarbageCollection no_gc;
    Tagged<Object> raw_obj = *object;
    size_t size = stack_.size();
    for (size_t i = 0; i < size; ++i) {
      if (*stack_[i].second == raw_obj) {
        AllowGarbageCollection allow_to_return_error;
        Handle<String> circle_description =
            ConstructCircularStructureErrorMessage(key, i);
        DirectHandle<Object> error = factory()->NewTypeError(
            MessageTemplate::kCircularStructure, circle_description);
        isolate_->Throw(*error);
        return EXCEPTION;
      }
    }
  }
  stack_.emplace_back(key, object);
  return SUCCESS;
}

void JsonStringifier::StackPop() {
  if V8_LIKELY (!need_stack_) {
    --stack_nesting_level_;
    return;
  }
  stack_.pop_back();
}

class CircularStructureMessageBuilder {
 public:
  explicit CircularStructureMessageBuilder(Isolate* isolate)
      : builder_(isolate) {}

  void AppendStartLine(Handle<Object> start_object) {
    builder_.AppendCString(kStartPrefix);
    builder_.AppendCStringLiteral("starting at object with constructor ");
    AppendConstructorName(start_object);
  }

  void AppendNormalLine(DirectHandle<Object> key, Handle<Object> object) {
    builder_.AppendCString(kLinePrefix);
    AppendKey(key);
    builder_.AppendCStringLiteral(" -> object with constructor ");
    AppendConstructorName(object);
  }

  void AppendClosingLine(DirectHandle<Object> closing_key) {
    builder_.AppendCString(kEndPrefix);
    AppendKey(closing_key);
    builder_.AppendCStringLiteral(" closes the circle");
  }

  void AppendEllipsis() {
    builder_.AppendCString(kLinePrefix);
    builder_.AppendCStringLiteral("...");
  }

  MaybeDirectHandle<String> Finish() { return builder_.Finish(); }

 private:
  void AppendConstructorName(Handle<Object> object) {
    builder_.AppendCharacter('\'');
    DirectHandle<String> constructor_name = JSReceiver::GetConstructorName(
        builder_.isolate(), Cast<JSReceiver>(object));
    builder_.AppendString(constructor_name);
    builder_.AppendCharacter('\'');
  }

  // A key can either be a string, the empty string or a Smi.
  void AppendKey(DirectHandle<Object> key) {
    if (IsSmi(*key)) {
      builder_.AppendCStringLiteral("index ");
      AppendSmi(Cast<Smi>(*key));
      return;
    }

    CHECK(IsString(*key));
    DirectHandle<String> key_as_string = Cast<String>(key);
    if (key_as_string->length() == 0) {
      builder_.AppendCStringLiteral("<anonymous>");
    } else {
      builder_.AppendCStringLiteral("property '");
      builder_.AppendString(key_as_string);
      builder_.AppendCharacter('\'');
    }
  }

  void AppendSmi(Tagged<Smi> smi) {
    static_assert(Smi::kMaxValue <= 2147483647);
    static_assert(Smi::kMinValue >= -2147483648);
    // sizeof(string) includes \0.
    static const int kBufferSize = sizeof("-2147483648");
    char chars[kBufferSize];
    base::Vector<char> buffer(chars, kBufferSize);
    builder_.AppendCString(IntToCString(smi.value(), buffer));
  }

  IncrementalStringBuilder builder_;
  static constexpr const char* kStartPrefix = "\n    --> ";
  static constexpr const char* kEndPrefix = "\n    --- ";
  static constexpr const char* kLinePrefix = "\n    |     ";
};

Handle<String> JsonStringifier::ConstructCircularStructureErrorMessage(
    DirectHandle<Object> last_key, size_t start_index) {
  DCHECK(start_index < stack_.size());
  CircularStructureMessageBuilder builder(isolate_);

  // We track the index to be printed next for better readability.
  size_t index = start_index;
  const size_t stack_size = stack_.size();

  builder.AppendStartLine(stack_[index++].second);

  // Append a maximum of kCircularErrorMessagePrefixCount normal lines.
  const size_t prefix_end =
      std::min(stack_size, index + kCircularErrorMessagePrefixCount);
  for (; index < prefix_end; ++index) {
    builder.AppendNormalLine(stack_[index].first, stack_[index].second);
  }

  // If the circle consists of too many objects, we skip them and just
  // print an ellipsis.
  if (stack_size > index + kCircularErrorMessagePostfixCount) {
    builder.AppendEllipsis();
  }

  // Since we calculate the postfix lines from the back of the stack,
  // we have to ensure that lines are not printed twice.
  index = std::max(index, stack_size - kCircularErrorMessagePostfixCount);
  for (; index < stack_size; ++index) {
    builder.AppendNormalLine(stack_[index].first, stack_[index].second);
  }

  builder.AppendClosingLine(last_key);

  Handle<String> result;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate_, result,
                                   indirect_handle(builder.Finish(), isolate_),
                                   factory()->empty_string());
  return result;
}

bool MayHaveInterestingProperties(Isolate* isolate, Tagged<JSReceiver> object) {
  for (PrototypeIterator iter(isolate, object, kStartAtReceiver);
       !iter.IsAtEnd(); iter.Advance()) {
    if (iter.GetCurrent()->map()->may_have_interesting_properties()) {
      return true;
    }
  }
  return false;
}

template <bool deferred_string_key>
JsonStringifier::Result JsonStringifier::Serialize_(Handle<JSAny> object,
                                                    bool comma,
                                                    Handle<Object> key) {
  StackLimitCheck interrupt_check(isolate_);
  if (interrupt_check.InterruptRequested() &&
      IsException(isolate_->stack_guard()->HandleInterrupts(), isolate_)) {
    return EXCEPTION;
  }

  DirectHandle<JSAny> initial_value = object;
  PtrComprCageBase cage_base(isolate_);
  if (!IsSmi(*object)) {
    InstanceType instance_type =
        Cast<HeapObject>(*object)->map(cage_base)->instance_type();
    if ((InstanceTypeChecker::IsJSReceiver(instance_type) &&
         MayHaveInterestingProperties(isolate_, Cast<JSReceiver>(*object))) ||
        InstanceTypeChecker::IsBigInt(instance_type)) {
      if (!need_stack_ && stack_nesting_level_ > 0) {
        need_stack_ = true;
        return NEED_STACK;
      }
      need_stack_ = true;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate_, object, ApplyToJsonFunction(object, key), EXCEPTION);
    }
  }
  if (!replacer_function_.is_null()) {
    need_stack_ = true;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate_, object, ApplyReplacerFunction(object, key, initial_value),
        EXCEPTION);
  }

  if (IsSmi(*object)) {
    if (deferred_string_key) SerializeDeferredKey(comma, key);
    return SerializeSmi(Cast<Smi>(*object));
  }
```