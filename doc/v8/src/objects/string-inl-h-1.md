Response:
Let's break down the thought process for analyzing this C++ header file and generating the summary.

**1. Initial Understanding of the Request:**

The request asks for a functional summary of the provided C++ header file (`string-inl.h`) within the V8 JavaScript engine. It also has specific instructions about how to handle certain scenarios (Torque, JavaScript relevance, code logic, common errors). The fact that it's part 2 of 2 indicates that there's likely a corresponding `.h` file with declarations.

**2. High-Level Overview of the Code:**

My first pass involves skimming the code to identify key classes and methods. I see classes like `String`, `SeqOneByteString`, `SeqTwoByteString`, `SlicedString`, `ConsString`, `ThinString`, `ExternalOneByteString`, `ExternalTwoByteString`, `ConsStringIterator`, and `StringCharacterStream`. This immediately tells me the file is about different string representations within V8. The "inl.h" suffix strongly suggests this file contains inline implementations of methods declared in a corresponding `.h` file.

**3. Analyzing Core String Classes:**

I'll focus on the primary string classes and their relationships:

* **`String`:** This is the base class. It likely contains common functionalities for all string types. I note methods like `IsFlat`, `IsShared`, `GetUnderlying`, `VisitFlat`, `Utf8Length`, `IsWellFormedUnicode`, `AsArrayIndex`, and `AsIntegerIndex`. These suggest operations like checking string structure, accessing underlying data, converting to UTF-8, checking for valid Unicode, and converting to numeric indices.

* **`SeqOneByteString` and `SeqTwoByteString`:** These represent the most basic, sequential string storage. The names clearly indicate single-byte (ASCII-like) and two-byte (UTF-16) character encoding. I look for methods to get/set individual characters, get the underlying character array, and calculate the required memory size.

* **`SlicedString`:** This appears to be an optimization for creating substrings without copying the entire string. It refers to a "parent" string and an "offset."

* **`ConsString`:**  This likely represents concatenated strings. It holds references to two other strings (`first` and `second`). The `IsFlat` method is interesting – it suggests that a `ConsString` can be "flattened" into a single contiguous string.

* **`ThinString`:** This seems like another optimization, possibly for deduplication or indirection. It has an `actual()` method, suggesting it points to the real underlying string.

* **`ExternalOneByteString` and `ExternalTwoByteString`:** These represent strings whose data is stored outside of V8's managed heap. They involve `Resource` objects and methods for managing these external resources.

**4. Analyzing Helper Classes:**

* **`ConsStringIterator`:** This class is clearly designed to iterate through the potentially nested structure of `ConsString` objects.

* **`StringCharacterStream`:**  This appears to be a higher-level abstraction for iterating through the characters of a string, handling the different underlying string representations transparently. The `VisitOneByteString` and `VisitTwoByteString` methods are callbacks used during the flattening process.

* **`SubStringRange`:** This class provides an iterator-like interface for working with substrings.

**5. Addressing Specific Instructions:**

* **`.tq` suffix:** The file ends in `.h`, so this condition doesn't apply. I'll note this explicitly.

* **JavaScript Relevance:** I need to connect the C++ concepts to their JavaScript equivalents. String manipulation in JavaScript is a direct analogy. Concatenation (`+`), slicing (`substring`, `slice`), and accessing characters by index are key areas.

* **Code Logic and Examples:** For methods like `IsFlat`, I can create simple scenarios with `ConsString` to demonstrate the concept. For `VisitFlat`, I can illustrate how it traverses different string types.

* **Common Programming Errors:**  I'll think about typical string-related mistakes in JavaScript, like off-by-one errors in indexing or incorrect assumptions about string immutability (although the C++ layer *does* have mutable string types). The discussion of `SharedStringAccessGuardIfNeeded` hints at potential issues with concurrent access.

**6. Structuring the Summary:**

I'll organize the summary into logical sections:

* **Overall Function:** A brief description of the file's purpose.
* **Core Concepts:** Explanation of the different string representations and their trade-offs.
* **Key Classes and Functionality:**  Detailed breakdown of each important class and its methods. This is where I'll incorporate the code logic examples and JavaScript analogies.
* **Specific Instructions:**  Explicitly address the `.tq` check, JavaScript relevance, code logic, and common errors.
* **Summary/Conclusion:** A concise recap of the file's role.

**7. Refinement and Detail:**

During the writing process, I'll:

* **Use precise terminology:**  "Sequential strings," "concatenated strings," "external strings," etc.
* **Explain the *why*:**  Why are there so many string representations? (Optimization for different scenarios).
* **Pay attention to details:**  The purpose of `DisallowGarbageCollection`, the meaning of "flat," the implications of shared strings.
* **Ensure clarity:**  Use simple language and avoid jargon where possible.

By following this systematic approach, I can effectively analyze the C++ header file and generate a comprehensive and informative summary that addresses all aspects of the request. The iterative process of skimming, analyzing specific components, and then synthesizing the information is crucial for understanding complex codebases.
这是对`v8/src/objects/string-inl.h` 文件功能的归纳总结。

**功能归纳：**

`v8/src/objects/string-inl.h` 文件包含了 V8 JavaScript 引擎中各种字符串对象类型（如 `SeqOneByteString`, `SeqTwoByteString`, `ConsString`, `SlicedString`, `ThinString`, `ExternalOneByteString`, `ExternalTwoByteString` 等）的内联（inline）方法实现。

这个文件的核心功能是提供高效的、底层的字符串操作方法，这些方法直接操作字符串对象的内部数据结构。由于是内联实现，这些方法通常会被编译器直接嵌入到调用代码中，从而避免函数调用的开销，提高性能。

**具体功能点包括：**

* **字符串类型判断和状态查询：**
    * 判断字符串是否是扁平的（`IsFlat`）。
    * 判断字符串是否是共享的（`IsShared`）。
    * 获取底层字符串（`GetUnderlying`），这通常用于解开 `SlicedString` 或 `ThinString`。

* **扁平化字符串访问：**
    * 提供 `VisitFlat` 模板方法，用于遍历和访问不同类型的字符串，将其视为扁平的连续内存块。这是处理组合字符串（如 `ConsString`）的关键，它能将逻辑上连接的字符串片段视为一个整体进行访问。

* **获取 UTF-8 长度：**
    * 提供 `Utf8Length` 静态方法，用于计算字符串的 UTF-8 编码长度。

* **检查 Unicode 格式是否良好：**
    * 提供 `IsWellFormedUnicode` 静态方法，用于判断字符串是否包含不成对的 surrogate 代码点。

* **获取字符向量：**
    * 提供 `GetCharVector` 模板方法，用于获取字符串的字符数组（`uint8_t` 或 `base::uc16`）。

* **顺序字符串操作（`SeqOneByteString`, `SeqTwoByteString`）：**
    * 获取指定索引的字符（`Get`）。
    * 设置指定索引的字符（`SeqOneByteStringSet`, `SeqTwoByteStringSet`）。
    * 批量设置字符（`SeqOneByteStringSetChars`）。
    * 获取字符数组的起始地址（`GetCharsAddress`）。
    * 获取可修改的字符数组（`GetChars`）。
    * 计算数据大小和对齐后的大小（`DataSizeFor`, `SizeFor`）。
    * 判断 Map 是否兼容（`IsCompatibleMap`）。
    * 获取分配的大小（`AllocatedSize`）。
    * 结构体内存布局描述 (`BodyDescriptor`).
    * 清除填充内存 (`clear_padding_destructively`).

* **切片字符串操作（`SlicedString`）：**
    * 获取和设置父字符串（`parent`, `set_parent`）。
    * 获取和设置偏移量（`offset`, `set_offset`）。

* **组合字符串操作（`ConsString`）：**
    * 获取和设置左右子字符串（`first`, `second`, `set_first`, `set_second`）。
    * 判断是否已扁平化（`IsFlat`）。

* **精简字符串操作（`ThinString`）：**
    * 获取和设置实际的字符串（`actual`, `set_actual`）。

* **外部字符串操作（`ExternalOneByteString`, `ExternalTwoByteString`）：**
    * 判断是否未缓存（`is_uncached`）。
    * 初始化外部指针字段（`InitExternalPointerFields`）。
    * 访问外部指针（`VisitExternalPointers`）。
    * 获取和设置资源地址（`resource_as_address`, `set_address_as_resource`）。
    * 获取和设置反序列化/序列化时的资源引用（`GetResourceRefForDeserialization`, `SetResourceRefForSerialization`）。
    * 释放资源（`DisposeResource`）。
    * 获取 `Resource` 对象（`resource`, `mutable_resource`）。
    * 更新数据缓存（`update_data_cache`）。
    * 设置 `Resource` 对象（`SetResource`, `set_resource`）。
    * 获取字符数组（`GetChars`）。

* **组合字符串迭代器（`ConsStringIterator`）：**
    * 用于遍历 `ConsString` 的内部结构。

* **字符串字符流（`StringCharacterStream`）：**
    * 提供一个流式接口来访问字符串中的字符，可以处理不同类型的字符串。

* **字符串到数组索引的转换：**
    * 提供 `AsArrayIndex` 和 `AsIntegerIndex` 方法，尝试将字符串转换为数字索引。

* **子字符串范围（`SubStringRange`）：**
    * 提供一个方便的方式来迭代字符串的某个子区间。

* **判断字符串是否可以进行原地内部化：**
    * 提供 `IsInPlaceInternalizable` 静态方法来判断字符串是否可以在不重新分配内存的情况下进行内部化（interning）。

**关于 .tq 结尾：**

如果 `v8/src/objects/string-inl.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。`.tq` 文件会被编译成 C++ 代码。由于这里的文件名是 `.h`，所以它不是 Torque 源代码。

**与 JavaScript 功能的关系：**

`v8/src/objects/string-inl.h` 中定义的方法是 V8 引擎实现 JavaScript 字符串功能的底层基础。JavaScript 中的字符串操作最终会调用到这些 C++ 方法。

**JavaScript 示例：**

```javascript
const str1 = "hello";
const str2 = "world";
const combined = str1 + str2; // JavaScript 的字符串连接，底层可能使用 ConsString

const sub = combined.substring(2, 7); // JavaScript 的 substring，底层可能使用 SlicedString

const charCode = combined.charCodeAt(4); // JavaScript 获取字符编码，底层可能调用 Get 方法

console.log(combined.length); // JavaScript 获取字符串长度

// 判断字符串是否包含特定子串等操作，都会用到这里定义的底层方法。
```

**代码逻辑推理与示例：**

**假设输入：** 一个 `ConsString` 对象，其 `first_` 指向 "abc"，`second_` 指向 "def"。

**调用：** `string->IsFlat()`

**代码逻辑：** `IsFlat` 方法会检查 `ConsString` 的 `second()` 字符串的长度是否为 0。

**输出：**  在这种情况下，`second()` 的长度为 3 ("def")，所以 `IsFlat()` 返回 `false`。

**假设输入：** 一个 `SlicedString` 对象，其 `parent_` 指向 "abcdefg"，`offset_` 为 2。

**调用：** `string->GetUnderlying()`

**代码逻辑：** `GetUnderlying` 方法会直接返回 `SlicedString` 的 `parent_` 指针。

**输出：** 返回指向 "abcdefg" 字符串的指针。

**用户常见的编程错误示例：**

* **错误的索引访问：** 在 JavaScript 中访问字符串时，如果索引超出范围，会返回 `undefined` 或导致错误。在底层 C++ 中，直接访问字符数组时如果索引越界，可能导致内存访问错误，这是非常危险的。

  ```javascript
  const str = "hello";
  // 错误：索引超出范围
  // console.log(str.charCodeAt(10)); // JavaScript 返回 undefined 或抛出错误

  // 在 C++ 底层，如果直接使用越界索引访问 chars()，可能导致崩溃。
  ```

* **误解字符串的不可变性：** JavaScript 的字符串是不可变的。虽然在 V8 的底层实现中有可修改的字符串类型（例如用于构建字符串的中间状态），但 JavaScript 代码无法直接修改字符串内容。 开发者可能会尝试修改字符串的某个字符，但这在 JavaScript 中是不允许的。

  ```javascript
  let str = "hello";
  // 错误：尝试修改字符串，JavaScript 中字符串是不可变的
  // str[0] = 'H'; // 不生效
  // str.charAt(0) = 'H'; // 不生效
  ```

**总结：**

`v8/src/objects/string-inl.h` 是 V8 引擎中实现高效字符串操作的关键组成部分。它定义了各种字符串类型的内联方法，用于执行底层的字符访问、类型判断、结构操作等。这些方法直接支撑着 JavaScript 中各种字符串操作的实现。理解这个文件中的代码有助于深入了解 V8 引擎的内部工作原理，特别是字符串的表示和处理方式。

Prompt: 
```
这是目录为v8/src/objects/string-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/string-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
nst {
  if (!StringShape(this).IsCons()) return true;
  return Cast<ConsString>(this)->IsFlat();
}

bool String::IsShared() const {
  const bool result = StringShape(this).IsShared();
  DCHECK_IMPLIES(result, HeapLayout::InAnySharedSpace(this));
  return result;
}

Tagged<String> String::GetUnderlying() const {
  // Giving direct access to underlying string only makes sense if the
  // wrapping string is already flattened.
  DCHECK(IsFlat());
  DCHECK(StringShape(this).IsIndirect());
  static_assert(offsetof(ConsString, first_) ==
                offsetof(SlicedString, parent_));
  static_assert(offsetof(ConsString, first_) == offsetof(ThinString, actual_));

  return static_cast<const SlicedString*>(this)->parent();
}

template <class Visitor>
Tagged<ConsString> String::VisitFlat(Visitor* visitor, Tagged<String> string,
                                     const int offset) {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(string));
  return VisitFlat(visitor, string, offset,
                   SharedStringAccessGuardIfNeeded::NotNeeded());
}

template <class Visitor>
Tagged<ConsString> String::VisitFlat(
    Visitor* visitor, Tagged<String> string, const int offset,
    const SharedStringAccessGuardIfNeeded& access_guard) {
  DisallowGarbageCollection no_gc;
  int slice_offset = offset;
  const uint32_t length = string->length();
  DCHECK_LE(offset, length);
  while (true) {
    int32_t tag = StringShape(string).representation_and_encoding_tag();
    switch (tag) {
      case kSeqOneByteStringTag:
        visitor->VisitOneByteString(
            Cast<SeqOneByteString>(string)->GetChars(no_gc, access_guard) +
                slice_offset,
            length - offset);
        return Tagged<ConsString>();

      case kSeqTwoByteStringTag:
        visitor->VisitTwoByteString(
            Cast<SeqTwoByteString>(string)->GetChars(no_gc, access_guard) +
                slice_offset,
            length - offset);
        return Tagged<ConsString>();

      case kExternalOneByteStringTag:
        visitor->VisitOneByteString(
            Cast<ExternalOneByteString>(string)->GetChars() + slice_offset,
            length - offset);
        return Tagged<ConsString>();

      case kExternalTwoByteStringTag:
        visitor->VisitTwoByteString(
            Cast<ExternalTwoByteString>(string)->GetChars() + slice_offset,
            length - offset);
        return Tagged<ConsString>();

      case kSlicedStringTag | kOneByteStringTag:
      case kSlicedStringTag | kTwoByteStringTag: {
        Tagged<SlicedString> slicedString = Cast<SlicedString>(string);
        slice_offset += slicedString->offset();
        string = slicedString->parent();
        continue;
      }

      case kConsStringTag | kOneByteStringTag:
      case kConsStringTag | kTwoByteStringTag:
        return Cast<ConsString>(string);

      case kThinStringTag | kOneByteStringTag:
      case kThinStringTag | kTwoByteStringTag:
        string = Cast<ThinString>(string)->actual();
        continue;

      default:
        UNREACHABLE();
    }
  }
}

// static
size_t String::Utf8Length(Isolate* isolate, Handle<String> string) {
  string = Flatten(isolate, string);

  DisallowGarbageCollection no_gc;
  FlatContent content = string->GetFlatContent(no_gc);
  DCHECK(content.IsFlat());
  size_t utf8_length = 0;
  if (content.IsOneByte()) {
    for (uint8_t c : content.ToOneByteVector()) {
      utf8_length += unibrow::Utf8::LengthOneByte(c);
    }
  } else {
    uint16_t last_character = unibrow::Utf16::kNoPreviousCharacter;
    for (uint16_t c : content.ToUC16Vector()) {
      utf8_length += unibrow::Utf8::Length(c, last_character);
      last_character = c;
    }
  }
  return utf8_length;
}

bool String::IsWellFormedUnicode(Isolate* isolate, Handle<String> string) {
  // One-byte strings are definitionally well formed and cannot have unpaired
  // surrogates.
  if (string->IsOneByteRepresentation()) return true;

  // TODO(v8:13557): The two-byte case can be optimized by extending the
  // InstanceType. See
  // https://docs.google.com/document/d/15f-1c_Ysw3lvjy_Gx0SmmD9qeO8UuXuAbWIpWCnTDO8/
  string = Flatten(isolate, string);
  if (string->IsOneByteRepresentation()) return true;
  DisallowGarbageCollection no_gc;
  String::FlatContent flat = string->GetFlatContent(no_gc);
  DCHECK(flat.IsFlat());
  const uint16_t* data = flat.ToUC16Vector().begin();
  return !unibrow::Utf16::HasUnpairedSurrogate(data, string->length());
}

template <>
inline base::Vector<const uint8_t> String::GetCharVector(
    const DisallowGarbageCollection& no_gc) {
  String::FlatContent flat = GetFlatContent(no_gc);
  DCHECK(flat.IsOneByte());
  return flat.ToOneByteVector();
}

template <>
inline base::Vector<const base::uc16> String::GetCharVector(
    const DisallowGarbageCollection& no_gc) {
  String::FlatContent flat = GetFlatContent(no_gc);
  DCHECK(flat.IsTwoByte());
  return flat.ToUC16Vector();
}

uint8_t SeqOneByteString::Get(uint32_t index) const {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  return Get(index, SharedStringAccessGuardIfNeeded::NotNeeded());
}

uint8_t SeqOneByteString::Get(
    uint32_t index, const SharedStringAccessGuardIfNeeded& access_guard) const {
  USE(access_guard);
  DCHECK(index >= 0 && index < length());
  return chars()[index];
}

void SeqOneByteString::SeqOneByteStringSet(uint32_t index, uint16_t value) {
  DisallowGarbageCollection no_gc;
  DCHECK_GE(index, 0);
  DCHECK_LT(index, length());
  DCHECK_LE(value, kMaxOneByteCharCode);
  chars()[index] = value;
}

void SeqOneByteString::SeqOneByteStringSetChars(uint32_t index,
                                                const uint8_t* string,
                                                uint32_t string_length) {
  DisallowGarbageCollection no_gc;
  DCHECK_LT(index + string_length, length());
  void* address = static_cast<void*>(&chars()[index]);
  memcpy(address, string, string_length);
}

Address SeqOneByteString::GetCharsAddress() const {
  return reinterpret_cast<Address>(&chars()[0]);
}

uint8_t* SeqOneByteString::GetChars(const DisallowGarbageCollection& no_gc) {
  USE(no_gc);
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  return chars();
}

uint8_t* SeqOneByteString::GetChars(
    const DisallowGarbageCollection& no_gc,
    const SharedStringAccessGuardIfNeeded& access_guard) {
  USE(no_gc);
  USE(access_guard);
  return chars();
}

Address SeqTwoByteString::GetCharsAddress() const {
  return reinterpret_cast<Address>(&chars()[0]);
}

base::uc16* SeqTwoByteString::GetChars(const DisallowGarbageCollection& no_gc) {
  USE(no_gc);
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  return chars();
}

base::uc16* SeqTwoByteString::GetChars(
    const DisallowGarbageCollection& no_gc,
    const SharedStringAccessGuardIfNeeded& access_guard) {
  USE(no_gc);
  USE(access_guard);
  return chars();
}

uint16_t SeqTwoByteString::Get(
    uint32_t index, const SharedStringAccessGuardIfNeeded& access_guard) const {
  USE(access_guard);
  DCHECK(index >= 0 && index < length());
  return chars()[index];
}

void SeqTwoByteString::SeqTwoByteStringSet(uint32_t index, uint16_t value) {
  DisallowGarbageCollection no_gc;
  DCHECK(index >= 0 && index < length());
  chars()[index] = value;
}

// static
V8_INLINE constexpr int32_t SeqOneByteString::DataSizeFor(int32_t length) {
  return sizeof(SeqOneByteString) + length * sizeof(Char);
}

// static
V8_INLINE constexpr int32_t SeqTwoByteString::DataSizeFor(int32_t length) {
  return sizeof(SeqTwoByteString) + length * sizeof(Char);
}

// static
V8_INLINE constexpr int32_t SeqOneByteString::SizeFor(int32_t length) {
  return OBJECT_POINTER_ALIGN(SeqOneByteString::DataSizeFor(length));
}

// static
V8_INLINE constexpr int32_t SeqTwoByteString::SizeFor(int32_t length) {
  return OBJECT_POINTER_ALIGN(SeqTwoByteString::DataSizeFor(length));
}

// Due to ThinString rewriting, concurrent visitors need to read the length with
// acquire semantics.
inline int SeqOneByteString::AllocatedSize() const {
  return SizeFor(length(kAcquireLoad));
}
inline int SeqTwoByteString::AllocatedSize() const {
  return SizeFor(length(kAcquireLoad));
}

// static
bool SeqOneByteString::IsCompatibleMap(Tagged<Map> map, ReadOnlyRoots roots) {
  return map == roots.seq_one_byte_string_map() ||
         map == roots.shared_seq_one_byte_string_map();
}

// static
bool SeqTwoByteString::IsCompatibleMap(Tagged<Map> map, ReadOnlyRoots roots) {
  return map == roots.seq_two_byte_string_map() ||
         map == roots.shared_seq_two_byte_string_map();
}

inline Tagged<String> SlicedString::parent() const { return parent_.load(); }

void SlicedString::set_parent(Tagged<String> parent, WriteBarrierMode mode) {
  DCHECK(IsSeqString(parent) || IsExternalString(parent));
  parent_.store(this, parent, mode);
}

inline int32_t SlicedString::offset() const { return offset_.load().value(); }

void SlicedString::set_offset(int32_t value) {
  offset_.store(this, Smi::FromInt(value), SKIP_WRITE_BARRIER);
}

inline Tagged<String> ConsString::first() const { return first_.load(); }
inline void ConsString::set_first(Tagged<String> value, WriteBarrierMode mode) {
  first_.store(this, value, mode);
}

inline Tagged<String> ConsString::second() const { return second_.load(); }
inline void ConsString::set_second(Tagged<String> value,
                                   WriteBarrierMode mode) {
  second_.store(this, value, mode);
}

Tagged<Object> ConsString::unchecked_first() const { return first_.load(); }

Tagged<Object> ConsString::unchecked_second() const {
  return second_.Relaxed_Load();
}

bool ConsString::IsFlat() const { return second()->length() == 0; }

inline Tagged<String> ThinString::actual() const { return actual_.load(); }
inline void ThinString::set_actual(Tagged<String> value,
                                   WriteBarrierMode mode) {
  actual_.store(this, value, mode);
}

Tagged<HeapObject> ThinString::unchecked_actual() const {
  return actual_.load();
}

bool ExternalString::is_uncached() const {
  InstanceType type = map()->instance_type();
  return (type & kUncachedExternalStringMask) == kUncachedExternalStringTag;
}

void ExternalString::InitExternalPointerFields(Isolate* isolate) {
  resource_.Init(address(), isolate, kNullAddress);
  if (is_uncached()) return;
  resource_data_.Init(address(), isolate, kNullAddress);
}

void ExternalString::VisitExternalPointers(ObjectVisitor* visitor) {
  visitor->VisitExternalPointer(this, ExternalPointerSlot(&resource_));
  if (is_uncached()) return;
  visitor->VisitExternalPointer(this, ExternalPointerSlot(&resource_data_));
}

Address ExternalString::resource_as_address() const {
  IsolateForSandbox isolate = GetIsolateForSandbox(this);
  return resource_.load(isolate);
}

void ExternalString::set_address_as_resource(Isolate* isolate, Address value) {
  resource_.store(isolate, value);
  if (IsExternalOneByteString(this)) {
    Cast<ExternalOneByteString>(this)->update_data_cache(isolate);
  } else {
    Cast<ExternalTwoByteString>(this)->update_data_cache(isolate);
  }
}

uint32_t ExternalString::GetResourceRefForDeserialization() {
  return static_cast<uint32_t>(resource_.load_encoded());
}

void ExternalString::SetResourceRefForSerialization(uint32_t ref) {
  resource_.store_encoded(static_cast<ExternalPointer_t>(ref));
  if (is_uncached()) return;
  resource_data_.store_encoded(kNullExternalPointer);
}

void ExternalString::DisposeResource(Isolate* isolate) {
  Address value = resource_.load(isolate);
  v8::String::ExternalStringResourceBase* resource =
      reinterpret_cast<v8::String::ExternalStringResourceBase*>(value);

  // Dispose of the C++ object if it has not already been disposed.
  if (resource != nullptr) {
    if (!IsShared() && !HeapLayout::InWritableSharedSpace(this)) {
      resource->Unaccount(reinterpret_cast<v8::Isolate*>(isolate));
    }
    resource->Dispose();
    resource_.store(isolate, kNullAddress);
  }
}

const ExternalOneByteString::Resource* ExternalOneByteString::resource() const {
  return reinterpret_cast<const Resource*>(resource_as_address());
}

ExternalOneByteString::Resource* ExternalOneByteString::mutable_resource() {
  return reinterpret_cast<Resource*>(resource_as_address());
}

void ExternalOneByteString::update_data_cache(Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  if (is_uncached()) {
    if (resource()->IsCacheable()) mutable_resource()->UpdateDataCache();
  } else {
    resource_data_.store(isolate,
                         reinterpret_cast<Address>(resource()->data()));
  }
}

void ExternalOneByteString::SetResource(
    Isolate* isolate, const ExternalOneByteString::Resource* resource) {
  set_resource(isolate, resource);
  size_t new_payload = resource == nullptr ? 0 : resource->length();
  if (new_payload > 0) {
    isolate->heap()->UpdateExternalString(this, 0, new_payload);
  }
}

void ExternalOneByteString::set_resource(
    Isolate* isolate, const ExternalOneByteString::Resource* resource) {
  resource_.store(isolate, reinterpret_cast<Address>(resource));
  if (resource != nullptr) update_data_cache(isolate);
}

const uint8_t* ExternalOneByteString::GetChars() const {
  DisallowGarbageCollection no_gc;
  auto res = resource();
  if (is_uncached()) {
    if (res->IsCacheable()) {
      // TODO(solanes): Teach TurboFan/CSA to not bailout to the runtime to
      // avoid this call.
      return reinterpret_cast<const uint8_t*>(res->cached_data());
    }
#if DEBUG
    // Check that this method is called only from the main thread if we have an
    // uncached string with an uncacheable resource.
    {
      Isolate* isolate;
      DCHECK_IMPLIES(GetIsolateFromHeapObject(this, &isolate),
                     ThreadId::Current() == isolate->thread_id());
    }
#endif
  }

  return reinterpret_cast<const uint8_t*>(res->data());
}

uint8_t ExternalOneByteString::Get(
    uint32_t index, const SharedStringAccessGuardIfNeeded& access_guard) const {
  USE(access_guard);
  DCHECK(index >= 0 && index < length());
  return GetChars()[index];
}

const ExternalTwoByteString::Resource* ExternalTwoByteString::resource() const {
  return reinterpret_cast<const Resource*>(resource_as_address());
}

ExternalTwoByteString::Resource* ExternalTwoByteString::mutable_resource() {
  return reinterpret_cast<Resource*>(resource_as_address());
}

void ExternalTwoByteString::update_data_cache(Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  if (is_uncached()) {
    if (resource()->IsCacheable()) mutable_resource()->UpdateDataCache();
  } else {
    resource_data_.store(isolate,
                         reinterpret_cast<Address>(resource()->data()));
  }
}

void ExternalTwoByteString::SetResource(
    Isolate* isolate, const ExternalTwoByteString::Resource* resource) {
  set_resource(isolate, resource);
  size_t new_payload = resource == nullptr ? 0 : resource->length() * 2;
  if (new_payload > 0) {
    isolate->heap()->UpdateExternalString(this, 0, new_payload);
  }
}

void ExternalTwoByteString::set_resource(
    Isolate* isolate, const ExternalTwoByteString::Resource* resource) {
  resource_.store(isolate, reinterpret_cast<Address>(resource));
  if (resource != nullptr) update_data_cache(isolate);
}

const uint16_t* ExternalTwoByteString::GetChars() const {
  DisallowGarbageCollection no_gc;
  auto res = resource();
  if (is_uncached()) {
    if (res->IsCacheable()) {
      // TODO(solanes): Teach TurboFan/CSA to not bailout to the runtime to
      // avoid this call.
      return res->cached_data();
    }
#if DEBUG
    // Check that this method is called only from the main thread if we have an
    // uncached string with an uncacheable resource.
    {
      Isolate* isolate;
      DCHECK_IMPLIES(GetIsolateFromHeapObject(this, &isolate),
                     ThreadId::Current() == isolate->thread_id());
    }
#endif
  }

  return res->data();
}

uint16_t ExternalTwoByteString::Get(
    uint32_t index, const SharedStringAccessGuardIfNeeded& access_guard) const {
  USE(access_guard);
  DCHECK(index >= 0 && index < length());
  return GetChars()[index];
}

const uint16_t* ExternalTwoByteString::ExternalTwoByteStringGetData(
    uint32_t start) {
  return GetChars() + start;
}

int ConsStringIterator::OffsetForDepth(int depth) { return depth & kDepthMask; }

void ConsStringIterator::PushLeft(Tagged<ConsString> string) {
  frames_[depth_++ & kDepthMask] = string;
}

void ConsStringIterator::PushRight(Tagged<ConsString> string) {
  // Inplace update.
  frames_[(depth_ - 1) & kDepthMask] = string;
}

void ConsStringIterator::AdjustMaximumDepth() {
  if (depth_ > maximum_depth_) maximum_depth_ = depth_;
}

void ConsStringIterator::Pop() {
  DCHECK_GT(depth_, 0);
  DCHECK(depth_ <= maximum_depth_);
  depth_--;
}

class StringCharacterStream {
 public:
  inline explicit StringCharacterStream(Tagged<String> string, int offset = 0);
  StringCharacterStream(const StringCharacterStream&) = delete;
  StringCharacterStream& operator=(const StringCharacterStream&) = delete;
  inline uint16_t GetNext();
  inline bool HasMore();
  inline void Reset(Tagged<String> string, int offset = 0);
  inline void VisitOneByteString(const uint8_t* chars, int length);
  inline void VisitTwoByteString(const uint16_t* chars, int length);

 private:
  ConsStringIterator iter_;
  bool is_one_byte_;
  union {
    const uint8_t* buffer8_;
    const uint16_t* buffer16_;
  };
  const uint8_t* end_;
  SharedStringAccessGuardIfNeeded access_guard_;
};

uint16_t StringCharacterStream::GetNext() {
  DCHECK(buffer8_ != nullptr && end_ != nullptr);
  // Advance cursor if needed.
  if (buffer8_ == end_) HasMore();
  DCHECK(buffer8_ < end_);
  return is_one_byte_ ? *buffer8_++ : *buffer16_++;
}

// TODO(solanes, v8:7790, chromium:1166095): Assess if we need to use
// Isolate/LocalIsolate and pipe them through, instead of using the slow
// version of the SharedStringAccessGuardIfNeeded.
StringCharacterStream::StringCharacterStream(Tagged<String> string, int offset)
    : is_one_byte_(false), access_guard_(string) {
  Reset(string, offset);
}

void StringCharacterStream::Reset(Tagged<String> string, int offset) {
  buffer8_ = nullptr;
  end_ = nullptr;

  Tagged<ConsString> cons_string =
      String::VisitFlat(this, string, offset, access_guard_);
  iter_.Reset(cons_string, offset);
  if (!cons_string.is_null()) {
    string = iter_.Next(&offset);
    if (!string.is_null())
      String::VisitFlat(this, string, offset, access_guard_);
  }
}

bool StringCharacterStream::HasMore() {
  if (buffer8_ != end_) return true;
  int offset;
  Tagged<String> string = iter_.Next(&offset);
  DCHECK_EQ(offset, 0);
  if (string.is_null()) return false;
  String::VisitFlat(this, string, 0, access_guard_);
  DCHECK(buffer8_ != end_);
  return true;
}

void StringCharacterStream::VisitOneByteString(const uint8_t* chars,
                                               int length) {
  is_one_byte_ = true;
  buffer8_ = chars;
  end_ = chars + length;
}

void StringCharacterStream::VisitTwoByteString(const uint16_t* chars,
                                               int length) {
  is_one_byte_ = false;
  buffer16_ = chars;
  end_ = reinterpret_cast<const uint8_t*>(chars + length);
}

bool String::AsArrayIndex(uint32_t* index) {
  DisallowGarbageCollection no_gc;
  uint32_t field = raw_hash_field();
  if (ContainsCachedArrayIndex(field)) {
    *index = ArrayIndexValueBits::decode(field);
    return true;
  }
  if (IsHashFieldComputed(field) && !IsIntegerIndex(field)) {
    return false;
  }
  return SlowAsArrayIndex(index);
}

bool String::AsIntegerIndex(size_t* index) {
  uint32_t field = raw_hash_field();
  if (ContainsCachedArrayIndex(field)) {
    *index = ArrayIndexValueBits::decode(field);
    return true;
  }
  if (IsHashFieldComputed(field) && !IsIntegerIndex(field)) {
    return false;
  }
  return SlowAsIntegerIndex(index);
}

SubStringRange::SubStringRange(Tagged<String> string,
                               const DisallowGarbageCollection& no_gc,
                               int first, int length)
    : string_(string),
      first_(first),
      length_(length == -1 ? string->length() : length),
      no_gc_(no_gc) {}

class SubStringRange::iterator final {
 public:
  using iterator_category = std::forward_iterator_tag;
  using difference_type = int;
  using value_type = base::uc16;
  using pointer = base::uc16*;
  using reference = base::uc16&;

  iterator(const iterator& other) = default;

  base::uc16 operator*() { return content_.Get(offset_); }
  bool operator==(const iterator& other) const {
    return content_.UsesSameString(other.content_) && offset_ == other.offset_;
  }
  bool operator!=(const iterator& other) const {
    return !content_.UsesSameString(other.content_) || offset_ != other.offset_;
  }
  iterator& operator++() {
    ++offset_;
    return *this;
  }
  iterator operator++(int);

 private:
  friend class String;
  friend class SubStringRange;
  iterator(Tagged<String> from, int offset,
           const DisallowGarbageCollection& no_gc)
      : content_(from->GetFlatContent(no_gc)), offset_(offset) {}
  String::FlatContent content_;
  int offset_;
};

SubStringRange::iterator SubStringRange::begin() {
  return SubStringRange::iterator(string_, first_, no_gc_);
}

SubStringRange::iterator SubStringRange::end() {
  return SubStringRange::iterator(string_, first_ + length_, no_gc_);
}

void SeqOneByteString::clear_padding_destructively(uint32_t length) {
  // Ensure we are not killing the map word, which is already set at this point
  static_assert(SizeFor(0) >= kObjectAlignment + kTaggedSize);
  memset(reinterpret_cast<void*>(reinterpret_cast<char*>(this) +
                                 SizeFor(length) - kObjectAlignment),
         0, kObjectAlignment);
}

void SeqTwoByteString::clear_padding_destructively(uint32_t length) {
  // Ensure we are not killing the map word, which is already set at this point
  static_assert(SizeFor(0) >= kObjectAlignment + kTaggedSize);
  memset(reinterpret_cast<void*>(reinterpret_cast<char*>(this) +
                                 SizeFor(length) - kObjectAlignment),
         0, kObjectAlignment);
}

// static
bool String::IsInPlaceInternalizable(Tagged<String> string) {
  return IsInPlaceInternalizable(string->map()->instance_type());
}

// static
bool String::IsInPlaceInternalizable(InstanceType instance_type) {
  switch (instance_type) {
    case SEQ_TWO_BYTE_STRING_TYPE:
    case SEQ_ONE_BYTE_STRING_TYPE:
    case SHARED_SEQ_TWO_BYTE_STRING_TYPE:
    case SHARED_SEQ_ONE_BYTE_STRING_TYPE:
    case EXTERNAL_TWO_BYTE_STRING_TYPE:
    case EXTERNAL_ONE_BYTE_STRING_TYPE:
    case SHARED_EXTERNAL_TWO_BYTE_STRING_TYPE:
    case SHARED_EXTERNAL_ONE_BYTE_STRING_TYPE:
      return true;
    default:
      return false;
  }
}

// static
bool String::IsInPlaceInternalizableExcludingExternal(
    InstanceType instance_type) {
  return IsInPlaceInternalizable(instance_type) &&
         !InstanceTypeChecker::IsExternalString(instance_type);
}

class SeqOneByteString::BodyDescriptor final : public DataOnlyBodyDescriptor {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return UncheckedCast<SeqOneByteString>(raw_object)->AllocatedSize();
  }
};

class SeqTwoByteString::BodyDescriptor final : public DataOnlyBodyDescriptor {
 public:
  static inline int SizeOf(Tagged<Map> map, Tagged<HeapObject> raw_object) {
    return UncheckedCast<SeqTwoByteString>(raw_object)->AllocatedSize();
  }
};

}  // namespace v8::internal

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_STRING_INL_H_

"""


```