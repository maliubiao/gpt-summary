Response:
My thinking process to analyze the provided C++ header file and generate the explanation involved the following steps:

1. **Understand the Goal:** The request asks for an explanation of the `v8/src/objects/dictionary.h` file's functionality within the V8 JavaScript engine. It also asks to address specific points: Torque source, JavaScript relevance, logic examples, and common programming errors.

2. **Initial Scan and Identification of Key Components:** I started by scanning the file for keywords and structure:
    * `#ifndef`, `#define`, `#include`: Standard C++ header guards and inclusion directives. These tell me it's a header file defining interfaces and data structures.
    * `namespace v8::internal`:  Indicates this is internal V8 implementation, not exposed directly to JavaScript.
    * `class Dictionary`, `class NameDictionary`, `class GlobalDictionary`, `class NumberDictionary`, `class SimpleNumberDictionary`:  These are the core classes being defined. The naming suggests they are different types of dictionaries optimized for specific use cases.
    * `HashTable`: The base class for `Dictionary`. This is a fundamental data structure in V8.
    * `PropertyDetails`:  Appears to hold metadata about properties.
    * `Handle`, `Tagged`, `ObjectSlot`, `Isolate`:  Core V8 types for managing memory and objects.
    * `kIsOrderedDictionaryType`, `kPrefixSize`, `kEntrySize`, `kInitialCapacity`: Constants indicating properties of the dictionary implementations.
    * Method names like `ValueAt`, `ValueAtPut`, `DeleteEntry`, `Add`, `Shrink`, `Set`, `GetMap`: Suggest standard dictionary operations.

3. **Inferring Functionality from Class Names and Methods:** Based on the identified components, I started to infer the purpose of each dictionary type:
    * **`Dictionary` (template):** A generic base class for hash-based dictionaries. The template parameters suggest it can be customized with different key and shape types.
    * **`NameDictionary`:** Likely used for storing string-based property names and their associated values. The presence of `PropertyDetails` suggests it's used for general object properties.
    * **`GlobalDictionary`:**  Possibly a specialized dictionary for storing global object properties. The `PropertyCell` type might indicate a connection to property access and modification.
    * **`NumberDictionary`:**  Intended for storing properties where the keys are numbers (array indices or numeric property names). The `UpdateMaxNumberKey` and `requires_slow_elements` members point to optimizations for array-like structures.
    * **`SimpleNumberDictionary`:** A lighter-weight version of `NumberDictionary`, potentially without the overhead of `PropertyDetails`.

4. **Analyzing Key Methods:** I looked at some of the prominent methods to understand the core operations:
    * `ValueAt`, `ValueAtPut`: Accessing and setting values associated with keys.
    * `DeleteEntry`: Removing entries from the dictionary.
    * `Add`: Inserting new key-value pairs.
    * `Shrink`: Optimizing memory usage by reducing dictionary size.
    * `Set`:  A type-specific way to add or update entries (especially for number-based dictionaries).
    * `GetMap`:  Retrieving the `Map` object associated with the dictionary, crucial for V8's object model.

5. **Addressing Specific Questions:**

    * **Torque Source (.tq):** I explicitly noted that the file ends in `.h`, indicating it's a C++ header file, not a Torque source file.
    * **JavaScript Relevance:** This was a crucial point. I connected the dictionaries to how JavaScript objects are implemented internally. I highlighted that they are used as backing stores for object properties, both named and indexed. I then formulated JavaScript examples to illustrate the underlying dictionary behavior (adding properties, accessing them, and how numeric keys might lead to `NumberDictionary`).
    * **Code Logic Inference:** For this, I chose a simple scenario: adding a property to an object. I provided a step-by-step logical flow, including assumptions about dictionary growth and hashing. The input was the object and the property, and the output was the modified dictionary.
    * **Common Programming Errors:** I focused on errors related to JavaScript object manipulation that could indirectly relate to the dictionary implementation. Examples included adding too many properties (leading to dictionary mode), relying on property order (which dictionaries don't guarantee), and performance implications of non-numeric keys in array-like objects.

6. **Structuring the Explanation:** I organized the information logically:

    * Start with a general overview of the file's purpose.
    * Explain the core classes and their likely functions.
    * Address the specific points from the request (Torque, JavaScript, logic, errors) in separate sections.
    * Provide clear JavaScript examples and logical flow explanations.
    * Use clear and concise language.

7. **Refinement and Review:** I reviewed the generated explanation to ensure accuracy, clarity, and completeness. I made sure the JavaScript examples were relevant and easy to understand. I also checked that the logical flow was reasonable and addressed the input/output aspect.

Essentially, my approach was to start with the concrete (the code), infer the abstract (the functionality), and then connect the abstract back to the concrete and the higher-level context (JavaScript). Understanding the fundamental role of dictionaries in implementing JavaScript objects was key to answering many parts of the request.
好的，让我们来分析一下 `v8/src/objects/dictionary.h` 这个 V8 源代码文件。

**文件功能概述**

`v8/src/objects/dictionary.h` 文件定义了 V8 引擎中各种**字典（Dictionary）**类的接口和结构。字典是一种用于存储键值对的数据结构，在 V8 中被广泛用于实现 JavaScript 对象的属性存储。

更具体地说，这个头文件定义了以下核心内容：

1. **`Dictionary` 模板类:** 这是一个通用的字典基类，使用了模板，可以根据不同的键类型和形状（Shape）进行实例化。它提供了字典的基本操作，例如查找、插入、删除和更新键值对。

2. **各种具体的字典子类:** 基于 `Dictionary` 模板，定义了针对不同场景优化的字典子类：
   - **`NameDictionary`:** 用于存储字符串类型的属性名及其属性信息（值和属性描述符）。这是最常用的字典类型，用于普通 JavaScript 对象的属性存储。
   - **`GlobalDictionary`:**  用于存储全局对象的属性。它与 `NameDictionary` 类似，但有一些针对全局环境的优化。
   - **`NumberDictionary`:** 用于存储数字索引属性（例如数组元素）。它针对数字键进行了优化，并可以存储额外的元数据，例如数组的长度信息。
   - **`SimpleNumberDictionary`:** `NumberDictionary` 的一个简化版本，可能用于更轻量级的数字索引存储场景。

3. **形状（Shape）相关的类:** 如 `BaseDictionaryShape`, `BaseNameDictionaryShape`, `NameDictionaryShape` 等。这些类定义了字典的布局和特性，例如是否存储属性描述符，以及键的匹配和哈希方式。V8 使用形状（也称为 Map 或 DescriptorArray）来优化对象的属性访问。

4. **辅助方法和常量:**  定义了用于操作字典的各种内联方法、静态方法和常量，例如获取或设置特定位置的值、删除条目、调整字典大小、计算哈希值等。

**关于 .tq 扩展名**

你提到如果文件以 `.tq` 结尾，则它是 V8 Torque 源代码。  `v8/src/objects/dictionary.h`  **以 `.h` 结尾**，这意味着它是一个标准的 **C++ 头文件**，而不是 Torque 文件。 Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的 C++ 代码。通常，与 `.h` 文件对应的 Torque 文件（如果存在）会包含一些性能关键的操作的 Torque 实现。

**与 JavaScript 功能的关系**

`v8/src/objects/dictionary.h` 中定义的字典类是 V8 引擎实现 JavaScript 对象属性存储的核心机制之一。

**JavaScript 示例：**

当你创建一个 JavaScript 对象并为其添加属性时，V8 内部很可能会使用这些字典类来存储这些属性：

```javascript
const obj = {}; // 创建一个空对象

// 添加字符串类型的属性
obj.name = 'Alice';
obj.age = 30;

// 添加数字类型的属性（数组索引）
obj[0] = 'first';
obj[1] = 'second';
```

在 V8 内部：

- 对于 `obj.name` 和 `obj.age` 这样的字符串属性，V8 可能会使用 `NameDictionary` 来存储键（"name", "age"）和对应的值（'Alice', 30）以及可能的属性描述符（例如，是否可枚举、可写等）。
- 对于 `obj[0]` 和 `obj[1]` 这样的数字索引属性，V8 可能会使用 `NumberDictionary` 来存储键（0, 1）和对应的值（'first', 'second'）。

**代码逻辑推理**

假设我们有一个 `NameDictionary` 实例，并且我们想向其中添加一个新的属性 `key = "city"`, `value = "New York"`。

**假设输入：**

- `dictionary`: 一个 `NameDictionary` 对象的句柄。
- `key`:  一个 `Handle<Name>`，其值为字符串 "city"。
- `value`: 一个 `Handle<Object>`，其值为字符串 "New York"。
- `details`: 一个 `PropertyDetails` 对象，包含属性的元数据（例如，是否可枚举）。

**代码逻辑（简化）：**

1. **计算哈希值:**  根据 `key` ("city") 计算出一个哈希值。
2. **查找空闲或匹配的槽位:** 使用哈希值在 `dictionary` 的内部哈希表中查找一个空闲的槽位，或者一个已经存在相同 `key` 的槽位。
3. **插入或更新条目:**
   - 如果找到空闲槽位，则在该槽位插入 `key`、`value` 和 `details`。
   - 如果找到匹配的槽位（说明该属性已存在），则更新该槽位的 `value` 和 `details`。
4. **可能需要扩容:** 如果字典已满，并且没有找到空闲槽位，则需要创建一个新的、更大的字典，并将旧字典中的所有条目复制到新字典中。

**假设输出：**

- 如果插入成功，`dictionary` 对象会包含一个新的条目，其中键为 "city"，值为 "New York"，并且具有指定的属性描述符。
- 返回值可能是一个新的 `Handle<NameDictionary>`，如果发生了扩容，则指向新的字典对象；否则，指向原来的字典对象。

**用户常见的编程错误**

虽然开发者通常不会直接操作这些底层的字典类，但理解它们有助于理解一些与 JavaScript 对象操作相关的常见错误和性能问题：

1. **过度添加属性导致性能下降:**  当一个对象的属性数量过多时，字典可能会变得很大，导致属性查找的效率降低。这与使用大型的、未经优化的哈希表类似。

2. **依赖属性的插入顺序:**  在某些情况下，开发者可能会错误地依赖对象属性的插入顺序。虽然在现代 JavaScript 引擎中，对象的属性是有序的（插入顺序），但这并不总是保证的，并且依赖它可能会导致代码在不同环境或 V8 版本中表现不一致。字典的内部实现是基于哈希表的，其内部顺序不应被依赖。

3. **在性能敏感的代码中频繁添加或删除属性:**  频繁地添加或删除对象的属性可能会导致字典频繁地调整大小（扩容或收缩），这会带来性能开销。

4. **使用非字符串或 Symbol 作为对象键:** 虽然 JavaScript 允许使用数字作为属性名（会被转换为字符串），但过度使用非字符串键可能会影响 V8 的内部优化。V8 会根据键的类型选择不同的字典实现或优化策略。

**示例：依赖属性插入顺序的错误**

```javascript
const obj = {};
obj.a = 1;
obj.b = 2;
obj.c = 3;

// 错误地假设属性会始终按照 a, b, c 的顺序出现
for (const key in obj) {
  console.log(key); // 输出顺序可能不是总是 a, b, c，尤其是在旧版本的 JavaScript 引擎中
}
```

**总结**

`v8/src/objects/dictionary.h` 是 V8 引擎中至关重要的头文件，它定义了用于实现 JavaScript 对象属性存储的各种字典类。理解这些字典的工作原理有助于我们更好地理解 JavaScript 对象的内部结构和性能特性。虽然开发者不会直接操作这些类，但了解它们可以帮助我们避免一些常见的编程错误和性能陷阱。

Prompt: 
```
这是目录为v8/src/objects/dictionary.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/dictionary.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_DICTIONARY_H_
#define V8_OBJECTS_DICTIONARY_H_

#include <optional>

#include "src/base/export-template.h"
#include "src/common/globals.h"
#include "src/objects/hash-table.h"
#include "src/objects/property-array.h"
#include "src/objects/smi.h"
#include "src/roots/roots.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

#ifdef V8_ENABLE_SWISS_NAME_DICTIONARY
class SwissNameDictionary;
using PropertyDictionary = SwissNameDictionary;
#else
using PropertyDictionary = NameDictionary;
#endif

template <typename Derived, typename Shape>
class EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE) Dictionary
    : public HashTable<Derived, Shape> {
  using DerivedHashTable = HashTable<Derived, Shape>;

 public:
  using TodoShape = Shape;
  using Key = typename TodoShape::Key;
  inline Tagged<Object> ValueAt(InternalIndex entry);
  inline Tagged<Object> ValueAt(PtrComprCageBase cage_base,
                                InternalIndex entry);
  inline Tagged<Object> ValueAt(InternalIndex entry, SeqCstAccessTag);
  inline Tagged<Object> ValueAt(PtrComprCageBase cage_base, InternalIndex entry,
                                SeqCstAccessTag);
  // Returns {} if we would be reading out of the bounds of the object.
  inline std::optional<Tagged<Object>> TryValueAt(InternalIndex entry);

  // Set the value for entry.
  inline void ValueAtPut(InternalIndex entry, Tagged<Object> value);
  inline void ValueAtPut(InternalIndex entry, Tagged<Object> value,
                         SeqCstAccessTag);

  // Swap the value for the entry.
  inline Tagged<Object> ValueAtSwap(InternalIndex entry, Tagged<Object> value,
                                    SeqCstAccessTag);

  // Compare and swap the value for the entry.
  inline Tagged<Object> ValueAtCompareAndSwap(InternalIndex entry,
                                              Tagged<Object> expected,
                                              Tagged<Object> value,
                                              SeqCstAccessTag);

  // Returns the property details for the property at entry.
  inline PropertyDetails DetailsAt(InternalIndex entry);

  // Set the details for entry.
  inline void DetailsAtPut(InternalIndex entry, PropertyDetails value);

  static const bool kIsOrderedDictionaryType = false;

  // Delete a property from the dictionary.
  V8_WARN_UNUSED_RESULT static Handle<Derived> DeleteEntry(
      Isolate* isolate, Handle<Derived> dictionary, InternalIndex entry);

  // Attempt to shrink the dictionary after deletion of key.
  V8_WARN_UNUSED_RESULT static inline Handle<Derived> Shrink(
      Isolate* isolate, Handle<Derived> dictionary) {
    return DerivedHashTable::Shrink(isolate, dictionary);
  }

  int NumberOfEnumerableProperties();

  // Returns the key (slow).
  Tagged<Object> SlowReverseLookup(Tagged<Object> value);

  inline void ClearEntry(InternalIndex entry);

  // Sets the entry to (key, value) pair.
  inline void SetEntry(InternalIndex entry, Tagged<Object> key,
                       Tagged<Object> value, PropertyDetails details);

  // Garbage collection support.
  inline ObjectSlot RawFieldOfValueAt(InternalIndex entry);

  template <typename IsolateT, AllocationType key_allocation =
                                   std::is_same<IsolateT, Isolate>::value
                                       ? AllocationType::kYoung
                                       : AllocationType::kOld>
  V8_WARN_UNUSED_RESULT static Handle<Derived> Add(
      IsolateT* isolate, Handle<Derived> dictionary, Key key,
      DirectHandle<Object> value, PropertyDetails details,
      InternalIndex* entry_out = nullptr);

  // This method is only safe to use when it is guaranteed that the dictionary
  // doesn't need to grow.
  // The number of elements stored is not updated. Use
  // |SetInitialNumberOfElements| to update the number in one go.
  template <typename IsolateT, AllocationType key_allocation =
                                   std::is_same<IsolateT, Isolate>::value
                                       ? AllocationType::kYoung
                                       : AllocationType::kOld>
  static void UncheckedAdd(IsolateT* isolate, Handle<Derived> dictionary,
                           Key key, DirectHandle<Object> value,
                           PropertyDetails details);

  static Handle<Derived> ShallowCopy(
      Isolate* isolate, Handle<Derived> dictionary,
      AllocationType allocation = AllocationType::kYoung);

 protected:
  // Generic at put operation.
  V8_WARN_UNUSED_RESULT static Handle<Derived> AtPut(Isolate* isolate,
                                                     Handle<Derived> dictionary,
                                                     Key key,
                                                     Handle<Object> value,
                                                     PropertyDetails details);
  static void UncheckedAtPut(Isolate* isolate, Handle<Derived> dictionary,
                             Key key, Handle<Object> value,
                             PropertyDetails details);
};

#define EXTERN_DECLARE_DICTIONARY(DERIVED, SHAPE)                  \
  EXTERN_DECLARE_HASH_TABLE(DERIVED, SHAPE)                        \
  extern template class EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE) \
      Dictionary<DERIVED, SHAPE>;

template <typename Key>
class BaseDictionaryShape : public BaseShape<Key> {
 public:
  static const bool kHasDetails = true;
  template <typename Dictionary>
  static inline PropertyDetails DetailsAt(Tagged<Dictionary> dict,
                                          InternalIndex entry);

  template <typename Dictionary>
  static inline void DetailsAtPut(Tagged<Dictionary> dict, InternalIndex entry,
                                  PropertyDetails value);
};

class BaseNameDictionaryShape : public BaseDictionaryShape<Handle<Name>> {
 public:
  static inline bool IsMatch(DirectHandle<Name> key, Tagged<Object> other);
  static inline uint32_t Hash(ReadOnlyRoots roots, DirectHandle<Name> key);
  static inline uint32_t HashForObject(ReadOnlyRoots roots,
                                       Tagged<Object> object);
  template <AllocationType allocation = AllocationType::kYoung>
  static inline Handle<Object> AsHandle(Isolate* isolate, Handle<Name> key);
  template <AllocationType allocation = AllocationType::kOld>
  static inline Handle<Object> AsHandle(LocalIsolate* isolate,
                                        Handle<Name> key);
  static const int kEntryValueIndex = 1;
};

class NameDictionaryShape : public BaseNameDictionaryShape {
 public:
  static const int kPrefixSize = 3;
  static const int kEntrySize = 3;
  static const bool kMatchNeedsHoleCheck = false;
};

template <typename Derived, typename Shape>
class EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE) BaseNameDictionary
    : public Dictionary<Derived, Shape> {
  using Key = typename Shape::Key;

 public:
  static const int kNextEnumerationIndexIndex =
      HashTableBase::kPrefixStartIndex;
  static const int kObjectHashIndex = kNextEnumerationIndexIndex + 1;
  static const int kEntryValueIndex = 1;

  inline void SetHash(int hash);
  inline int Hash() const;

  // Creates a new dictionary.
  template <typename IsolateT>
  V8_WARN_UNUSED_RESULT static Handle<Derived> New(
      IsolateT* isolate, int at_least_space_for,
      AllocationType allocation = AllocationType::kYoung,
      MinimumCapacity capacity_option = USE_DEFAULT_MINIMUM_CAPACITY);

  // Allocate the next enumeration index. Possibly updates all enumeration
  // indices in the table.
  static int NextEnumerationIndex(Isolate* isolate, Handle<Derived> dictionary);
  // Accessors for next enumeration index.
  inline int next_enumeration_index();
  inline void set_next_enumeration_index(int index);

  // Return the key indices sorted by its enumeration index.
  static Handle<FixedArray> IterationIndices(Isolate* isolate,
                                             Handle<Derived> dictionary);

  template <typename IsolateT>
  V8_WARN_UNUSED_RESULT static Handle<Derived> AddNoUpdateNextEnumerationIndex(
      IsolateT* isolate, Handle<Derived> dictionary, Key key,
      Handle<Object> value, PropertyDetails details,
      InternalIndex* entry_out = nullptr);

  V8_WARN_UNUSED_RESULT static Handle<Derived> Add(
      Isolate* isolate, Handle<Derived> dictionary, Key key,
      Handle<Object> value, PropertyDetails details,
      InternalIndex* entry_out = nullptr);

  // Exposed for NameDictionaryLookupForwardedString slow path for forwarded
  // strings.
  using Dictionary<Derived, Shape>::FindInsertionEntry;
};

#define EXTERN_DECLARE_BASE_NAME_DICTIONARY(DERIVED, SHAPE)        \
  EXTERN_DECLARE_DICTIONARY(DERIVED, SHAPE)                        \
  extern template class EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE) \
      BaseNameDictionary<DERIVED, SHAPE>;

EXTERN_DECLARE_BASE_NAME_DICTIONARY(NameDictionary, NameDictionaryShape)

class V8_EXPORT_PRIVATE NameDictionary
    : public BaseNameDictionary<NameDictionary, NameDictionaryShape> {
 public:
  static inline Handle<Map> GetMap(ReadOnlyRoots roots);

  DECL_PRINTER(NameDictionary)

  static const int kFlagsIndex = kObjectHashIndex + 1;
  static const int kEntryValueIndex = 1;
  static const int kEntryDetailsIndex = 2;
  static const int kInitialCapacity = 2;

  inline Tagged<Name> NameAt(InternalIndex entry);
  inline Tagged<Name> NameAt(PtrComprCageBase cage_base, InternalIndex entry);

  inline void set_hash(int hash);
  inline int hash() const;

  // Note: Flags are stored as smi, so only 31 bits are usable.
  using MayHaveInterestingPropertiesBit = base::BitField<bool, 0, 1, uint32_t>;
  DECL_BOOLEAN_ACCESSORS(may_have_interesting_properties)

  static constexpr int kFlagsDefault = 0;

  inline uint32_t flags() const;
  inline void set_flags(uint32_t flags);

  // Creates a new NameDictionary.
  template <typename IsolateT>
  V8_WARN_UNUSED_RESULT static Handle<NameDictionary> New(
      IsolateT* isolate, int at_least_space_for,
      AllocationType allocation = AllocationType::kYoung,
      MinimumCapacity capacity_option = USE_DEFAULT_MINIMUM_CAPACITY);
};

class V8_EXPORT_PRIVATE GlobalDictionaryShape : public BaseNameDictionaryShape {
 public:
  static inline bool IsMatch(DirectHandle<Name> key, Tagged<Object> other);
  static inline uint32_t HashForObject(ReadOnlyRoots roots,
                                       Tagged<Object> object);

  static const bool kMatchNeedsHoleCheck = true;
  static const int kPrefixSize = 2;
  static const int kEntrySize = 1;

  template <typename Dictionary>
  static inline PropertyDetails DetailsAt(Tagged<Dictionary> dict,
                                          InternalIndex entry);

  template <typename Dictionary>
  static inline void DetailsAtPut(Tagged<Dictionary> dict, InternalIndex entry,
                                  PropertyDetails value);

  static inline Tagged<Object> Unwrap(Tagged<Object> key);
};

EXTERN_DECLARE_BASE_NAME_DICTIONARY(GlobalDictionary, GlobalDictionaryShape)

class V8_EXPORT_PRIVATE GlobalDictionary
    : public BaseNameDictionary<GlobalDictionary, GlobalDictionaryShape> {
 public:
  static inline Handle<Map> GetMap(ReadOnlyRoots roots);

  DECL_PRINTER(GlobalDictionary)

  inline Tagged<Object> ValueAt(InternalIndex entry);
  inline Tagged<Object> ValueAt(PtrComprCageBase cage_base,
                                InternalIndex entry);
  inline Tagged<PropertyCell> CellAt(InternalIndex entry);
  inline Tagged<PropertyCell> CellAt(PtrComprCageBase cage_base,
                                     InternalIndex entry);
  inline void SetEntry(InternalIndex entry, Tagged<Object> key,
                       Tagged<Object> value, PropertyDetails details);
  inline void ClearEntry(InternalIndex entry);
  inline Tagged<Name> NameAt(InternalIndex entry);
  inline Tagged<Name> NameAt(PtrComprCageBase cage_base, InternalIndex entry);
  inline void ValueAtPut(InternalIndex entry, Tagged<Object> value);

  std::optional<Tagged<PropertyCell>>
  TryFindPropertyCellForConcurrentLookupIterator(Isolate* isolate,
                                                 DirectHandle<Name> name,
                                                 RelaxedLoadTag tag);
};

class NumberDictionaryBaseShape : public BaseDictionaryShape<uint32_t> {
 public:
  static inline bool IsMatch(uint32_t key, Tagged<Object> other);
  template <AllocationType allocation = AllocationType::kYoung>
  static inline Handle<Object> AsHandle(Isolate* isolate, uint32_t key);
  template <AllocationType allocation = AllocationType::kOld>
  static inline Handle<Object> AsHandle(LocalIsolate* isolate, uint32_t key);

  static inline uint32_t Hash(ReadOnlyRoots roots, uint32_t key);
  static inline uint32_t HashForObject(ReadOnlyRoots roots,
                                       Tagged<Object> object);

  static const bool kMatchNeedsHoleCheck = true;
};

class NumberDictionaryShape : public NumberDictionaryBaseShape {
 public:
  static const int kPrefixSize = 1;
  static const int kEntrySize = 3;
};

class SimpleNumberDictionaryShape : public NumberDictionaryBaseShape {
 public:
  static const bool kHasDetails = false;
  static const int kPrefixSize = 0;
  static const int kEntrySize = 2;

  template <typename Dictionary>
  static inline PropertyDetails DetailsAt(Tagged<Dictionary> dict,
                                          InternalIndex entry) {
    UNREACHABLE();
  }

  template <typename Dictionary>
  static inline void DetailsAtPut(Tagged<Dictionary> dict, InternalIndex entry,
                                  PropertyDetails value) {
    UNREACHABLE();
  }
};

EXTERN_DECLARE_DICTIONARY(SimpleNumberDictionary, SimpleNumberDictionaryShape)

// SimpleNumberDictionary is used to map number to an entry.
class SimpleNumberDictionary
    : public Dictionary<SimpleNumberDictionary, SimpleNumberDictionaryShape> {
 public:
  static inline Handle<Map> GetMap(ReadOnlyRoots roots);

  // Type specific at put (default NONE attributes is used when adding).
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static Handle<SimpleNumberDictionary>
  Set(Isolate* isolate, Handle<SimpleNumberDictionary> dictionary, uint32_t key,
      Handle<Object> value);

  static const int kEntryValueIndex = 1;
};

EXTERN_DECLARE_DICTIONARY(NumberDictionary, NumberDictionaryShape)

// NumberDictionary is used as elements backing store and provides a bitfield
// and stores property details for every entry.
class NumberDictionary
    : public Dictionary<NumberDictionary, NumberDictionaryShape> {
 public:
  static inline Handle<Map> GetMap(ReadOnlyRoots roots);

  DECL_PRINTER(NumberDictionary)

  // Type specific at put (default NONE attributes is used when adding).
  V8_WARN_UNUSED_RESULT static Handle<NumberDictionary> Set(
      Isolate* isolate, Handle<NumberDictionary> dictionary, uint32_t key,
      Handle<Object> value,
      Handle<JSObject> dictionary_holder = Handle<JSObject>::null(),
      PropertyDetails details = PropertyDetails::Empty());
  // This method is only safe to use when it is guaranteed that the dictionary
  // doesn't need to grow.
  // The number of elements stored and the maximum index is not updated. Use
  // |SetInitialNumberOfElements| and |UpdateMaxNumberKey| to update the number
  // in one go.
  static void UncheckedSet(Isolate* isolate,
                           Handle<NumberDictionary> dictionary, uint32_t key,
                           Handle<Object> value);

  static const int kMaxNumberKeyIndex = kPrefixStartIndex;
  void UpdateMaxNumberKey(uint32_t key, Handle<JSObject> dictionary_holder);

  // Sorting support
  void CopyValuesTo(Tagged<FixedArray> elements);

  // If slow elements are required we will never go back to fast-case
  // for the elements kept in this dictionary.  We require slow
  // elements if an element has been added at an index larger than
  // kRequiresSlowElementsLimit or set_requires_slow_elements() has been called
  // when defining a getter or setter with a number key.
  inline bool requires_slow_elements();
  inline void set_requires_slow_elements();

  // Get the value of the max number key that has been added to this
  // dictionary.  max_number_key can only be called if
  // requires_slow_elements returns false.
  inline uint32_t max_number_key();

  static const int kEntryValueIndex = 1;
  static const int kEntryDetailsIndex = 2;

  // Bit masks.
  static const int kRequiresSlowElementsMask = 1;
  static const int kRequiresSlowElementsTagSize = 1;
  static const uint32_t kRequiresSlowElementsLimit = (1 << 29) - 1;

  // JSObjects prefer dictionary elements if the dictionary saves this much
  // memory compared to a fast elements backing store.
  static const uint32_t kPreferFastElementsSizeFactor = 3;
};

// The comparator is passed two indices |a| and |b|, and it returns < 0 when the
// property at index |a| comes before the property at index |b| in the
// enumeration order.
template <typename Dictionary>
struct EnumIndexComparator {
  explicit EnumIndexComparator(Tagged<Dictionary> dict) : dict(dict) {}
  bool operator()(Tagged_t a, Tagged_t b) {
    PropertyDetails da(dict->DetailsAt(
        InternalIndex(Tagged<Smi>(static_cast<Address>(a)).value())));
    PropertyDetails db(dict->DetailsAt(
        InternalIndex(Tagged<Smi>(static_cast<Address>(b)).value())));
    return da.dictionary_index() < db.dictionary_index();
  }
  Tagged<Dictionary> dict;
};

}  // namespace v8::internal

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_DICTIONARY_H_

"""

```