Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript's `JSON.stringify`.

1. **Understand the Goal:** The core request is to understand the functionality of `json-stringifier.cc` and how it relates to JavaScript's `JSON.stringify`. This means identifying the key actions the code performs and drawing parallels.

2. **Identify the Core Class:**  The code immediately presents the `JsonStringifier` class. This is the central actor, and its methods will likely contain the main logic.

3. **Analyze the Public Interface:** The `public` section of `JsonStringifier` is a good starting point. The most important method here is `Stringify`. The function signature `MaybeHandle<Object> Stringify(Handle<JSAny> object, Handle<JSAny> replacer, Handle<Object> gap)` strongly suggests this is the entry point for the JSON serialization process. The parameters `object`, `replacer`, and `gap` directly correspond to the arguments of `JSON.stringify` in JavaScript.

4. **Examine Key Private Methods:**  The private methods reveal the steps involved in the stringification process. Look for verbs and nouns that describe actions.

    * `InitializeReplacer`, `InitializeGap`: These suggest handling the optional `replacer` function and `space` (gap) argument from JavaScript.
    * `ApplyToJsonFunction`, `ApplyReplacerFunction`:  These indicate how the `toJSON` method of an object and the `replacer` function are invoked, mimicking JavaScript behavior.
    * `SerializeObject`, `SerializeElement`, `SerializeProperty`: These are the core serialization logic, handling different types of data within the object. The template parameter `<bool deferred_string_key>` in `Serialize_` suggests different handling based on whether the key needs to be written immediately.
    * `Append...` methods:  These are responsible for building the output string, managing buffer allocation and encoding.
    * `SerializeSmi`, `SerializeDouble`, `SerializeHeapNumber`, etc.:  These handle the serialization of specific JavaScript primitive types.
    * `SerializeJSArray`, `SerializeJSObject`, `SerializeJSProxy`: These deal with the structure of arrays and objects.
    * `SerializeString`:  This handles the escaping and formatting of string values.
    * `StackPush`, `StackPop`: These clearly manage a stack to detect and handle circular references.

5. **Connect to JavaScript Semantics:** As you identify the functionality of the C++ methods, consciously relate them back to the behavior of `JSON.stringify` in JavaScript.

    * **`replacer`:** The `InitializeReplacer` and `ApplyReplacerFunction` methods directly implement the logic for the `replacer` argument. Mention the two possible forms of the replacer (function and array).
    * **`space` (gap):** `InitializeGap` manages the indentation. Explain how numbers and strings are treated for this argument.
    * **`toJSON`:** `ApplyToJsonFunction` demonstrates the call to the `toJSON` method.
    * **Circular References:** The `StackPush`, `StackPop`, and `ConstructCircularStructureErrorMessage` methods are the core of circular reference detection and error reporting.
    * **Data Type Handling:**  Go through the `Serialize...` methods and explain how each JavaScript type (numbers, strings, booleans, null, arrays, objects) is handled and formatted according to JSON rules. Note the special handling of `NaN` and `Infinity`.
    * **String Escaping:** The `SerializeString` methods and the `JsonEscapeTable` are responsible for correctly escaping characters in strings.
    * **Property Enumeration:** Explain how object properties are iterated and the impact of the `replacer` array.

6. **Provide Concrete JavaScript Examples:** For each connection you make, illustrate it with a short, clear JavaScript example. This solidifies the link between the C++ code and the JavaScript functionality. Focus on demonstrating the specific behavior you're describing.

7. **Summarize the Core Functionality:**  Provide a concise summary of the file's purpose at the beginning.

8. **Structure the Answer Logically:** Organize your findings into clear sections (e.g., Core Functionality, Relationship to JavaScript, Examples). This makes the information easier to understand.

9. **Refine and Elaborate:** Review your initial analysis. Are there any nuances you missed? Can you provide more detail on specific aspects? For example, explain the purpose of the `SimplePropertyKeyCache`.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the `Append` methods are just simple string concatenation.
* **Correction:**  Realize they need to handle different encodings (one-byte vs. two-byte) and buffer management to avoid overflow.
* **Initial thought:** The `replacer` is just a function.
* **Correction:** Recognize the array form of the replacer and how it filters properties.
* **Initial thought:** The stack is just for general processing.
* **Correction:** Realize its specific purpose in detecting circular references.

By following this iterative process of examining the code, connecting it to JavaScript behavior, and providing illustrative examples, you can arrive at a comprehensive and accurate understanding of the `json-stringifier.cc` file.
这个C++源代码文件 `v8/src/json/json-stringifier.cc` 的主要功能是 **将 JavaScript 对象序列化为 JSON 字符串**。它是 V8 JavaScript 引擎中实现 `JSON.stringify()` 方法的核心部分。

**功能归纳:**

1. **实现 `JSON.stringify()` 的核心逻辑:**  该文件中的 `JsonStringifier` 类包含了将各种 JavaScript 数据类型（如对象、数组、基本类型）转换为符合 JSON 格式的字符串的算法。

2. **处理 `replacer` 参数:** 它实现了 `JSON.stringify()` 的可选 `replacer` 参数的功能。`replacer` 可以是一个函数或一个数组。
   - **函数 `replacer`:**  对于对象的每个属性，`replacer` 函数都会被调用，其返回值将决定该属性是否被包含在 JSON 字符串中，以及它的值如何被转换。
   - **数组 `replacer`:**  只有数组中列出的属性名（键）才会被包含在最终的 JSON 字符串中。

3. **处理 `space` (gap) 参数:** 它实现了 `JSON.stringify()` 的可选 `space` 参数（在代码中被称为 `gap`）的功能。`space` 参数用于在输出的 JSON 字符串中插入空白符，以提高可读性。

4. **处理 `toJSON()` 方法:** 它会检查被序列化的对象是否定义了 `toJSON()` 方法。如果定义了，该方法会被调用，其返回值将作为序列化的值。

5. **处理循环引用:**  它实现了检测和处理对象之间循环引用的机制，以防止无限递归。当检测到循环引用时，会抛出一个 `TypeError`。

6. **处理各种 JavaScript 数据类型:** 它针对不同的 JavaScript 数据类型（例如：`null`, `boolean`, `number`, `string`, `Array`, `Object` 等）实现了特定的序列化逻辑。

7. **字符串转义:** 它负责将字符串中的特殊字符（如双引号、反斜杠、控制字符等）转义为 JSON 允许的格式。

8. **性能优化:** 代码中包含了一些针对性能的优化，例如使用 `SimplePropertyKeyCache` 来缓存常见的属性键，以加速序列化过程。

**与 JavaScript 功能的关系以及 JavaScript 示例:**

`v8/src/json/json-stringifier.cc` 文件直接实现了 JavaScript 的全局方法 `JSON.stringify()`。  以下 JavaScript 示例展示了 `JSON.stringify()` 的不同用法，而这些用法的底层实现就在 `json-stringifier.cc` 中：

**1. 基本对象序列化:**

```javascript
const obj = { name: "John Doe", age: 30, city: "New York" };
const jsonString = JSON.stringify(obj);
console.log(jsonString); // 输出: {"name":"John Doe","age":30,"city":"New York"}
```

在 C++ 代码中，`SerializeJSObject` 方法会处理这个过程，遍历对象的属性，并将键值对转换为 JSON 格式的字符串。

**2. 使用 `replacer` 函数:**

```javascript
const obj = { a: 1, b: 'hello', c: [1, 2, 3] };
const jsonString = JSON.stringify(obj, (key, value) => {
  if (typeof value === 'string') {
    return undefined; // 移除字符串属性
  }
  return value * 2; // 数字属性乘以 2
});
console.log(jsonString); // 输出: {"a":2,"c":[2,4,6]}
```

C++ 代码中的 `InitializeReplacer` 和 `ApplyReplacerFunction` 方法会处理 `replacer` 函数的初始化和调用，根据其返回值决定如何序列化属性。

**3. 使用 `replacer` 数组:**

```javascript
const obj = { a: 1, b: 'hello', c: [1, 2, 3] };
const jsonString = JSON.stringify(obj, ['a', 'c']);
console.log(jsonString); // 输出: {"a":1,"c":[1,2,3]}
```

`InitializeReplacer` 方法会解析 `replacer` 数组，并创建一个属性列表，只有该列表中的属性才会在 `SerializeJSObject` 中被处理。

**4. 使用 `space` 参数进行格式化:**

```javascript
const obj = { name: "John Doe", age: 30 };
const jsonStringIndented = JSON.stringify(obj, null, 2); // 使用 2 个空格缩进
console.log(jsonStringIndented);
/* 输出:
{
  "name": "John Doe",
  "age": 30
}
*/
```

C++ 代码中的 `InitializeGap` 方法会解析 `space` 参数，并在 `NewLineOutline` 等方法中插入相应的空白符。

**5. 对象定义 `toJSON()` 方法:**

```javascript
const obj = {
  data: "原始数据",
  toJSON: function() {
    return { customData: this.data.toUpperCase() };
  }
};
const jsonString = JSON.stringify(obj);
console.log(jsonString); // 输出: {"customData":"原始数据"}
```

C++ 代码中的 `ApplyToJsonFunction` 方法会检测到 `toJSON()` 方法并调用它，使用其返回值进行序列化。

**6. 循环引用的处理:**

```javascript
const obj1 = {};
const obj2 = { link: obj1 };
obj1.link = obj2;

try {
  JSON.stringify(obj1);
} catch (error) {
  console.error(error); // 输出: TypeError: Converting circular structure to JSON
}
```

C++ 代码中的 `StackPush` 方法会检测到循环引用，并通过 `ConstructCircularStructureErrorMessage` 构建错误信息并抛出异常。

总而言之，`v8/src/json/json-stringifier.cc` 是 V8 引擎中负责实现 `JSON.stringify()` 功能的关键 C++ 代码，它处理了 JSON 序列化的各种细节，包括参数处理、数据类型转换、循环引用检测和字符串转义等，确保 JavaScript 的 `JSON.stringify()` 方法能够按照规范正确地将 JavaScript 对象转换为 JSON 字符串。

Prompt: 
```
这是目录为v8/src/json/json-stringifier.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```