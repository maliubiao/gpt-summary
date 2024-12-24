Response: Let's break down the thought process for summarizing the C++ code.

1. **Understand the Goal:** The core request is to summarize the functionality of the C++ file `v8/tools/debug_helper/get-object-properties.cc`. This means identifying the main purpose of the code and its key functionalities.

2. **Initial Scan for Keywords and Namespaces:**  A quick scan reveals important namespaces: `v8::internal` and `v8::internal::debug_helper_internal`. The filename itself, `get-object-properties.cc`, strongly suggests the file is about retrieving properties of objects. Keywords like `TaggedValue`, `Smi`, `HeapObject`, `String`, and `StackFrame` stand out as core V8 concepts related to object representation.

3. **Identify Core Data Structures:**  The code defines structs like `TypedObject` and result types like `ObjectPropertiesResult` and `StackFrameResult`. These signal the main data being manipulated and returned by the functions in the file.

4. **Focus on Publicly Exported Functions:** The `extern "C"` block with `V8_DEBUG_HELPER_EXPORT` is a crucial indicator of the file's public interface. The functions `_v8_debug_helper_GetObjectProperties` and `_v8_debug_helper_GetStackFrame` are the entry points for external use. Their names directly reflect their purposes. The corresponding `_v8_debug_helper_Free_*` functions are for memory management of the returned results.

5. **Analyze the `GetObjectProperties` Function:**
    * **Input:** `uintptr_t address`, `d::MemoryAccessor`, `d::HeapAddresses`, `const char* type_hint`. These suggest the function takes an object's address, a way to access memory, information about the V8 heap, and an optional type suggestion.
    * **Logic:**  The code handles different object types:
        * **Weak References:**  Checks for weak references.
        * **Heap Objects:** Calls `GetHeapObjectPropertiesMaybeCompressed`. The "MaybeCompressed" suggests handling of pointer compression in V8. This sub-function likely deals with dereferencing the object's map to determine its type and then retrieving its properties based on that type. It uses Torque-generated code (`Tq...`) for accessing object fields.
        * **Smis (Small Integers):** Handles Smi values directly.
    * **Output:** Returns an `ObjectPropertiesResult` which contains information about the object's type, a brief description, properties, and potentially guessed types.

6. **Analyze the `GetStackFrame` Function:**
    * **Input:** `uintptr_t frame_pointer`, `d::MemoryAccessor`. This suggests it takes a stack frame's address and a way to access memory.
    * **Logic:**  It reads information from the stack frame, specifically looking for context or frame type markers. If it's a context, it tries to extract information about the currently executing JavaScript function (name, script name, line/column).
    * **Output:** Returns a `StackFrameResult` containing properties related to the stack frame.

7. **Identify Helper Functions and Their Roles:** Notice functions like:
    * `GetTypedHeapObject`:  Determines the specific type of a heap object, potentially using type hints or information from the object's map.
    * `ReadStringVisitor`:  Extracts string content, handling various string encodings and storage methods (sequential, cons, sliced, external).
    * `AddInfoVisitor`:  Provides additional descriptive information and properties for certain object types (like JSObject's in-object properties).
    * `AppendAddressAndType`, `JoinWithSpace`: Utility functions for formatting output.

8. **Infer the Overall Purpose:**  Based on the exported functions and the helper functions, the file's main purpose is to provide a mechanism for inspecting the properties of V8 objects and stack frames for debugging purposes. It handles different object representations, including heap objects (with type detection), Smis, and weak references. It also deals with pointer compression. For stack frames, it aims to extract information about the currently executing function.

9. **Structure the Summary:** Organize the findings into a clear and concise summary. Start with a high-level overview, then detail the main functions and their inputs/outputs. Mention important data structures and the role of helper functions. Conclude with the overall purpose of the file.

10. **Refine and Polish:** Review the summary for clarity, accuracy, and completeness. Ensure the language is accessible and avoids unnecessary technical jargon. For instance, instead of just saying "uses Torque-generated code," explain *why* (for accessing object fields).

Self-Correction/Refinement during the process:

* **Initial thought:** "It's just about getting object properties."  **Correction:** Recognize the `GetStackFrame` function and realize it has a broader scope than *just* object properties in the heap.
* **Initial thought:** "The code directly reads memory." **Correction:** Emphasize the role of `d::MemoryAccessor` as an abstraction for memory access.
* **Initial thought:** "Focus on every single helper function." **Correction:** Prioritize the key helper functions that are central to the main functionalities and provide context. Minor utility functions can be mentioned more briefly.
* **Initial thought:** "Use very technical V8 terms." **Correction:**  Explain V8-specific concepts (like Smis, Heap Objects, Maps, Torque) in a way that someone with general C++ and some JavaScript debugging knowledge can understand.

By following this structured approach, analyzing the code in layers, and refining the understanding, a comprehensive and accurate summary can be produced.
这个C++源代码文件 `get-object-properties.cc` 的主要功能是**为V8 JavaScript引擎的调试工具提供获取V8堆中对象属性和栈帧信息的能力**。

更具体地说，它提供了以下核心功能：

1. **获取堆对象属性 (`GetObjectProperties`)**:
   - 接收一个内存地址，并尝试将其识别为V8堆中的对象。
   - 根据地址的标签 (tag) 判断是否是Smi (小整数) 或堆对象。
   - 对于堆对象，它会尝试确定对象的具体类型：
     - 首先尝试通过对象的Map指针来获取InstanceType。
     - 如果Map指针不可读，则会尝试使用提供的类型提示 (type hint)。
     - 如果仍然无法确定，则会返回一个通用的 `HeapObject` 类型。
   - 利用 Torque 生成的代码 (`Tq...`)，根据对象的类型访问其成员变量，并将其作为属性返回。
   - 对于字符串类型，它会尝试读取字符串的内容，并以截断形式展示。它还会尝试提供指向原始字符数组的指针。
   - 对于 `JSObject`，它会尝试识别并展示其内联属性。
   - 它还会处理弱引用对象。
   - 如果启用了指针压缩，它会尝试解压缩指针。
   - 它会利用预先存在的已知对象列表来提供更友好的描述。
   - 返回一个 `ObjectPropertiesResult` 结构，包含对象的类型、简短描述、属性列表以及可能的猜测类型。

2. **获取栈帧信息 (`GetStackFrame`)**:
   - 接收一个栈帧指针。
   - 尝试读取栈帧中的信息，特别是上下文或帧类型。
   - 如果是一个标准的JavaScript帧，它会尝试提取当前执行的 JavaScript 函数的相关信息，例如函数名、脚本名、脚本源码等，并将其作为属性返回。
   - 返回一个 `StackFrameResult` 结构，包含栈帧的属性列表。

**核心技术和概念:**

* **V8 内部结构:** 代码深入了解 V8 引擎的内部结构，例如 `TaggedValue`，`Smi`，`HeapObject`，`Map`，`InstanceType`，以及不同类型的字符串 (SeqString, ConsString, SlicedString, ExternalString) 等。
* **Torque:** 使用 Torque 生成的代码 (`torque-generated/class-debug-readers.h`) 来访问 V8 对象的成员变量。这使得代码能够以类型安全的方式读取对象的数据。
* **内存访问:** 使用 `d::MemoryAccessor` 抽象类来访问调试目标进程的内存，允许安全地读取目标进程中的数据。
* **类型推断:** 尝试根据内存中的数据和提供的类型提示来推断对象的具体类型。
* **字符串处理:**  专门处理不同类型的字符串，以正确地读取和展示字符串内容。
* **弱引用处理:** 能够识别和处理弱引用对象。
* **指针压缩:** 考虑了 V8 的指针压缩机制，并尝试解压缩指针以便正确访问对象。
* **已知对象列表:** 利用预先存在的已知对象列表，为某些特定的 V8 对象提供更具描述性的名称。

**目的:**

这个文件的主要目的是为外部调试工具 (例如 V8 的 Inspector) 提供一种机制，可以深入了解 V8 引擎的内部状态，包括堆中对象的结构和栈帧的信息。这对于调试 JavaScript 代码和理解 V8 引擎的运行机制至关重要。

**对外接口:**

该文件通过 C 接口 (`extern "C"`) 提供了两个主要的导出函数：

* `_v8_debug_helper_GetObjectProperties`:  用于获取堆对象的属性。
* `_v8_debug_helper_GetStackFrame`: 用于获取栈帧的信息。

以及对应的释放内存的函数：

* `_v8_debug_helper_Free_ObjectPropertiesResult`
* `_v8_debug_helper_Free_StackFrameResult`

这些导出的函数允许外部工具调用这些功能，而无需直接了解 C++ 的复杂性。

总而言之，`get-object-properties.cc` 是 V8 调试工具链中的一个关键组件，它弥合了外部调试工具和 V8 引擎内部表示之间的鸿沟，使得开发者能够有效地检查和理解 V8 的运行时状态。

Prompt: ```这是目录为v8/tools/debug_helper/get-object-properties.cc的一个c++源代码文件， 请归纳一下它的功能

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <sstream>

#include "debug-helper-internal.h"
#include "heap-constants.h"
#include "include/v8-internal.h"
#include "src/execution/frame-constants.h"
#include "src/execution/frames.h"
#include "src/execution/isolate-utils.h"
#include "src/objects/string-inl.h"
#include "src/sandbox/external-pointer.h"
#include "src/strings/unicode-inl.h"
#include "torque-generated/class-debug-readers.h"
#include "torque-generated/debug-macros.h"

namespace i = v8::internal;

namespace v8::internal::debug_helper_internal {

constexpr char kTaggedValue[] = "v8::internal::TaggedValue";
constexpr char kSmi[] = "v8::internal::Smi";
constexpr char kHeapObject[] = "v8::internal::HeapObject";
constexpr char kObjectAsStoredInHeap[] =
    "v8::internal::TaggedMember<v8::internal::Object>";

std::string AppendAddressAndType(const std::string& brief, uintptr_t address,
                                 const char* type) {
  std::stringstream brief_stream;
  brief_stream << "0x" << std::hex << address << " <" << type << ">";
  return brief.empty() ? brief_stream.str()
                       : brief + " (" + brief_stream.str() + ")";
}

std::string JoinWithSpace(const std::string& a, const std::string& b) {
  return a.empty() || b.empty() ? a + b : a + " " + b;
}

struct TypedObject {
  TypedObject(d::TypeCheckResult type_check_result,
              std::unique_ptr<TqObject> object)
      : type_check_result(type_check_result), object(std::move(object)) {}

  // How we discovered the object's type, or why we failed to do so.
  d::TypeCheckResult type_check_result;

  // Pointer to some TqObject subclass, representing the most specific known
  // type for the object.
  std::unique_ptr<TqObject> object;

  // Collection of other guesses at more specific types than the one represented
  // by |object|.
  std::vector<TypedObject> possible_types;
};

TypedObject GetTypedObjectByHint(uintptr_t address,
                                 std::string type_hint_string) {
#define TYPE_NAME_CASE(ClassName, ...)                   \
  if (type_hint_string == "v8::internal::" #ClassName) { \
    return {d::TypeCheckResult::kUsedTypeHint,           \
            std::make_unique<Tq##ClassName>(address)};   \
  }

  TORQUE_INSTANCE_CHECKERS_SINGLE_FULLY_DEFINED(TYPE_NAME_CASE)
  TORQUE_INSTANCE_CHECKERS_RANGE_FULLY_DEFINED(TYPE_NAME_CASE)
  STRING_CLASS_TYPES(TYPE_NAME_CASE)

#undef TYPE_NAME_CASE

  return {d::TypeCheckResult::kUnknownTypeHint,
          std::make_unique<TqHeapObject>(address)};
}

TypedObject GetTypedObjectForString(uintptr_t address, i::InstanceType type,
                                    d::TypeCheckResult type_source) {
  class StringGetDispatcher : public i::AllStatic {
   public:
#define DEFINE_METHOD(ClassName)                                    \
  static inline TypedObject Handle##ClassName(                      \
      uintptr_t address, d::TypeCheckResult type_source) {          \
    return {type_source, std::make_unique<Tq##ClassName>(address)}; \
  }
    STRING_CLASS_TYPES(DEFINE_METHOD)
#undef DEFINE_METHOD
    static inline TypedObject HandleInvalidString(
        uintptr_t address, d::TypeCheckResult type_source) {
      return {d::TypeCheckResult::kUnknownInstanceType,
              std::make_unique<TqString>(address)};
    }
  };

  return i::StringShape(type)
      .DispatchToSpecificTypeWithoutCast<StringGetDispatcher, TypedObject>(
          address, type_source);
}

TypedObject GetTypedObjectByInstanceType(uintptr_t address,
                                         i::InstanceType type,
                                         d::TypeCheckResult type_source) {
  switch (type) {
#define INSTANCE_TYPE_CASE(ClassName, INSTANCE_TYPE) \
  case i::INSTANCE_TYPE:                             \
    return {type_source, std::make_unique<Tq##ClassName>(address)};
    TORQUE_INSTANCE_CHECKERS_SINGLE_FULLY_DEFINED(INSTANCE_TYPE_CASE)
    TORQUE_INSTANCE_CHECKERS_MULTIPLE_FULLY_DEFINED(INSTANCE_TYPE_CASE)
#undef INSTANCE_TYPE_CASE

    default:

      // Special case: concrete subtypes of String are not included in the
      // main instance type list because they use the low bits of the instance
      // type enum as flags.
      if (type <= i::LAST_STRING_TYPE) {
        return GetTypedObjectForString(address, type, type_source);
      }

#define INSTANCE_RANGE_CASE(ClassName, FIRST_TYPE, LAST_TYPE)       \
  if (type >= i::FIRST_TYPE && type <= i::LAST_TYPE) {              \
    return {type_source, std::make_unique<Tq##ClassName>(address)}; \
  }
      TORQUE_INSTANCE_CHECKERS_RANGE_FULLY_DEFINED(INSTANCE_RANGE_CASE)
#undef INSTANCE_RANGE_CASE

      return {d::TypeCheckResult::kUnknownInstanceType,
              std::make_unique<TqHeapObject>(address)};
  }
}

bool IsTypedHeapObjectInstanceTypeOf(uintptr_t address,
                                     d::MemoryAccessor accessor,
                                     i::InstanceType instance_type) {
  auto heap_object = std::make_unique<TqHeapObject>(address);
  Value<uintptr_t> map_ptr = heap_object->GetMapValue(accessor);

  if (map_ptr.validity == d::MemoryAccessResult::kOk) {
    Value<i::InstanceType> type =
        TqMap(map_ptr.value).GetInstanceTypeValue(accessor);
    if (type.validity == d::MemoryAccessResult::kOk) {
      return instance_type == type.value;
    }
  }

  return false;
}

TypedObject GetTypedHeapObject(uintptr_t address, d::MemoryAccessor accessor,
                               const char* type_hint,
                               const d::HeapAddresses& heap_addresses) {
  auto heap_object = std::make_unique<TqHeapObject>(address);
  Value<uintptr_t> map_ptr = heap_object->GetMapValue(accessor);

  if (map_ptr.validity != d::MemoryAccessResult::kOk) {
    // If we can't read the Map pointer from the object, then we likely can't
    // read anything else, so there's not any point in attempting to use the
    // type hint. Just return a failure.
    return {map_ptr.validity == d::MemoryAccessResult::kAddressNotValid
                ? d::TypeCheckResult::kObjectPointerInvalid
                : d::TypeCheckResult::kObjectPointerValidButInaccessible,
            std::move(heap_object)};
  }

  Value<i::InstanceType> type =
      TqMap(map_ptr.value).GetInstanceTypeValue(accessor);
  if (type.validity == d::MemoryAccessResult::kOk) {
    return GetTypedObjectByInstanceType(address, type.value,
                                        d::TypeCheckResult::kUsedMap);
  }

  // We can't read the Map, so check whether it is in the list of known Maps,
  // as another way to get its instance type.
  KnownInstanceType known_map_type =
      FindKnownMapInstanceTypes(map_ptr.value, heap_addresses);
  if (known_map_type.confidence == KnownInstanceType::Confidence::kHigh) {
    DCHECK_EQ(known_map_type.types.size(), 1);
    return GetTypedObjectByInstanceType(address, known_map_type.types[0],
                                        d::TypeCheckResult::kKnownMapPointer);
  }

  // Create a basic result that says that the object is a HeapObject and we
  // couldn't read its Map.
  TypedObject result = {
      type.validity == d::MemoryAccessResult::kAddressNotValid
          ? d::TypeCheckResult::kMapPointerInvalid
          : d::TypeCheckResult::kMapPointerValidButInaccessible,
      std::move(heap_object)};

  // If a type hint is available, it may give us something more specific than
  // HeapObject. However, a type hint of Object would be even less specific, so
  // we'll only use the type hint if it's a subclass of HeapObject.
  if (type_hint != nullptr) {
    TypedObject hint_result = GetTypedObjectByHint(address, type_hint);
    if (result.object->IsSuperclassOf(hint_result.object.get())) {
      result = std::move(hint_result);
    }
  }

  // If low-confidence results are available from known Maps, include them only
  // if they don't contradict the primary type and would provide some additional
  // specificity.
  for (const i::InstanceType type_guess : known_map_type.types) {
    TypedObject guess_result = GetTypedObjectByInstanceType(
        address, type_guess, d::TypeCheckResult::kKnownMapPointer);
    if (result.object->IsSuperclassOf(guess_result.object.get())) {
      result.possible_types.push_back(std::move(guess_result));
    }
  }

  return result;
}

// An object visitor that accumulates the first few characters of a string.
class ReadStringVisitor : public TqObjectVisitor {
 public:
  struct Result {
    std::optional<std::string> maybe_truncated_string;
    std::unique_ptr<ObjectProperty> maybe_raw_characters_property;
  };
  static Result Visit(d::MemoryAccessor accessor,
                      const d::HeapAddresses& heap_addresses,
                      const TqString* object) {
    ReadStringVisitor visitor(accessor, heap_addresses);
    object->Visit(&visitor);
    return {visitor.GetString(), visitor.GetRawCharactersProperty()};
  }

  // Returns the result as UTF-8 once visiting is complete.
  std::optional<std::string> GetString() {
    if (failed_) return {};
    std::vector<char> result(
        string_.size() * unibrow::Utf16::kMaxExtraUtf8BytesForOneUtf16CodeUnit);
    unsigned write_index = 0;
    int prev_char = unibrow::Utf16::kNoPreviousCharacter;
    for (size_t read_index = 0; read_index < string_.size(); ++read_index) {
      uint16_t character = string_[read_index];
      write_index +=
          unibrow::Utf8::Encode(result.data() + write_index, character,
                                prev_char, /*replace_invalid=*/true);
      prev_char = character;
    }
    return std::string(result.data(), write_index);
  }

  // Returns a property referring to the address of the flattened character
  // array, if possible, once visiting is complete.
  std::unique_ptr<ObjectProperty> GetRawCharactersProperty() {
    if (failed_ || raw_characters_address_ == 0) return {};
    DCHECK(size_per_character_ == 1 || size_per_character_ == 2);
    const char* type = size_per_character_ == 1 ? "char" : "char16_t";
    return std::make_unique<ObjectProperty>(
        "raw_characters", type, raw_characters_address_, num_characters_,
        size_per_character_, std::vector<std::unique_ptr<StructProperty>>(),
        d::PropertyKind::kArrayOfKnownSize);
  }

  template <typename T>
  Value<T> ReadValue(uintptr_t data_address, int32_t index = 0) {
    T value{};
    d::MemoryAccessResult validity =
        accessor_(data_address + index * sizeof(T),
                  reinterpret_cast<uint8_t*>(&value), sizeof(value));
    return {validity, value};
  }

  template <typename TChar>
  void ReadStringCharacters(const TqString* object, uintptr_t data_address) {
    int32_t length = GetOrFinish(object->GetLengthValue(accessor_));
    if (string_.size() == 0) {
      raw_characters_address_ = data_address + index_ * sizeof(TChar);
      size_per_character_ = sizeof(TChar);
      num_characters_ = std::min(length, limit_) - index_;
    }
    for (; index_ < length && index_ < limit_ && !done_; ++index_) {
      static_assert(sizeof(TChar) <= sizeof(char16_t));
      char16_t c = static_cast<char16_t>(
          GetOrFinish(ReadValue<TChar>(data_address, index_)));
      if (!done_) AddCharacter(c);
    }
  }

  template <typename TChar, typename TString>
  void ReadSeqString(const TString* object) {
    ReadStringCharacters<TChar>(object, object->GetCharsAddress());
  }

  void VisitSeqOneByteString(const TqSeqOneByteString* object) override {
    ReadSeqString<char>(object);
  }

  void VisitSeqTwoByteString(const TqSeqTwoByteString* object) override {
    ReadSeqString<char16_t>(object);
  }

  void VisitConsString(const TqConsString* object) override {
    uintptr_t first_address = GetOrFinish(object->GetFirstValue(accessor_));
    if (done_) return;
    auto first =
        GetTypedHeapObject(first_address, accessor_, nullptr, heap_addresses_)
            .object;
    first->Visit(this);
    // Cons strings don't have all of their characters in a contiguous memory
    // region, so it would be confusing to show the user a raw pointer to the
    // character storage for only part of the cons string.
    raw_characters_address_ = 0;
    if (done_) return;
    int32_t first_length = GetOrFinish(
        static_cast<TqString*>(first.get())->GetLengthValue(accessor_));
    uintptr_t second = GetOrFinish(object->GetSecondValue(accessor_));
    if (done_) return;
    IndexModifier modifier(this, -first_length, -first_length);
    GetTypedHeapObject(second, accessor_, nullptr, heap_addresses_)
        .object->Visit(this);
  }

  void VisitSlicedString(const TqSlicedString* object) override {
    uintptr_t parent = GetOrFinish(object->GetParentValue(accessor_));
    int32_t length = GetOrFinish(object->GetLengthValue(accessor_));
    int32_t offset = i::PlatformSmiTagging::SmiToInt(
        GetOrFinish(object->GetOffsetValue(accessor_)));
    if (done_) return;
    int32_t limit_adjust = offset + length - limit_;
    IndexModifier modifier(this, offset, limit_adjust < 0 ? limit_adjust : 0);
    GetTypedHeapObject(parent, accessor_, nullptr, heap_addresses_)
        .object->Visit(this);
  }

  void VisitThinString(const TqThinString* object) override {
    uintptr_t actual = GetOrFinish(object->GetActualValue(accessor_));
    if (done_) return;
    GetTypedHeapObject(actual, accessor_, nullptr, heap_addresses_)
        .object->Visit(this);
  }

  bool IsExternalStringCached(const TqExternalString* object) {
    // The safest way to get the instance type is to use known map pointers, in
    // case the map data is not available.
    Value<uintptr_t> map_ptr = object->GetMapValue(accessor_);
    DCHECK_IMPLIES(map_ptr.validity == d::MemoryAccessResult::kOk,
                   !v8::internal::MapWord::IsPacked(map_ptr.value));
    uintptr_t map = GetOrFinish(map_ptr);
    if (done_) return false;
    auto instance_types = FindKnownMapInstanceTypes(map, heap_addresses_);
    // Exactly one of the matched instance types should be a string type,
    // because all maps for string types are in the same space (read-only
    // space). The "uncached" flag on that instance type tells us whether it's
    // safe to read the cached data.
    for (const auto& type : instance_types.types) {
      if ((type & i::kIsNotStringMask) == i::kStringTag &&
          (type & i::kStringRepresentationMask) == i::kExternalStringTag) {
        return (type & i::kUncachedExternalStringMask) !=
               i::kUncachedExternalStringTag;
      }
    }

    // If for some reason we can't find an external string type here (maybe the
    // caller provided an external string type as the type hint, but it doesn't
    // actually match the in-memory map pointer), then we can't safely use the
    // cached data.
    return false;
  }

  template <typename TChar>
  void ReadExternalString(const TqExternalString* object) {
    // Uncached external strings require knowledge of the embedder. For now, we
    // only read cached external strings.
    if (IsExternalStringCached(object)) {
      ExternalPointer_t resource_data =
          GetOrFinish(object->GetResourceDataValue(accessor_));
#ifdef V8_ENABLE_SANDBOX
      Address memory_chunk =
          MemoryChunk::FromAddress(object->GetMapAddress())->address();
      uint32_t metadata_index = GetOrFinish(ReadValue<uint32_t>(
          memory_chunk + MemoryChunk::MetadataIndexOffset()));
      Address metadata_address = GetOrFinish(ReadValue<Address>(
          heap_addresses_.metadata_pointer_table, metadata_index));
      Address heap = GetOrFinish(ReadValue<Address>(
          metadata_address + MemoryChunkMetadata::HeapOffset()));
      Isolate* isolate = Isolate::FromHeap(reinterpret_cast<Heap*>(heap));
      Address external_pointer_table_address_address =
          isolate->shared_external_pointer_table_address_address();
      Address external_pointer_table_address = GetOrFinish(
          ReadValue<Address>(external_pointer_table_address_address));
      Address external_pointer_table =
          GetOrFinish(ReadValue<Address>(external_pointer_table_address));
      int32_t index =
          static_cast<int32_t>(resource_data >> kExternalPointerIndexShift);
      Address tagged_data =
          GetOrFinish(ReadValue<Address>(external_pointer_table, index));
      Address data_address = tagged_data & ~kExternalStringResourceDataTag;
#else
      uintptr_t data_address = static_cast<uintptr_t>(resource_data);
#endif  // V8_ENABLE_SANDBOX
      if (done_) return;
      ReadStringCharacters<TChar>(object, data_address);
    } else {
      // TODO(v8:9376): Come up with some way that a caller with full knowledge
      // of a particular embedder could provide a callback function for getting
      // uncached string data.
      AddEllipsisAndFinish();
    }
  }

  void VisitExternalOneByteString(
      const TqExternalOneByteString* object) override {
    ReadExternalString<char>(object);
  }

  void VisitExternalTwoByteString(
      const TqExternalTwoByteString* object) override {
    ReadExternalString<char16_t>(object);
  }

  void VisitObject(const TqObject* object) override {
    // If we fail to find a specific type for a sub-object within a cons string,
    // sliced string, or thin string, we will end up here.
    AddEllipsisAndFinish();
  }

 private:
  ReadStringVisitor(d::MemoryAccessor accessor,
                    const d::HeapAddresses& heap_addresses)
      : accessor_(accessor),
        heap_addresses_(heap_addresses),
        index_(0),
        limit_(INT32_MAX),
        done_(false),
        failed_(false) {}

  // Unpacks a value that was fetched from the debuggee. If the value indicates
  // that it couldn't successfully fetch memory, then prevents further work.
  template <typename T>
  T GetOrFinish(Value<T> value) {
    if (value.validity != d::MemoryAccessResult::kOk) {
      AddEllipsisAndFinish();
    }
    return value.value;
  }

  void AddEllipsisAndFinish() {
    if (!done_) {
      done_ = true;
      if (string_.empty()) {
        failed_ = true;
      } else {
        string_ += u"...";
      }
    }
  }

  void AddCharacter(char16_t c) {
    if (string_.size() >= kMaxCharacters) {
      AddEllipsisAndFinish();
    } else {
      string_.push_back(c);
    }
  }

  // Temporarily adds offsets to both index_ and limit_, to handle ConsString
  // and SlicedString.
  class IndexModifier {
   public:
    IndexModifier(ReadStringVisitor* that, int32_t index_adjust,
                  int32_t limit_adjust)
        : that_(that),
          index_adjust_(index_adjust),
          limit_adjust_(limit_adjust) {
      that_->index_ += index_adjust_;
      that_->limit_ += limit_adjust_;
    }
    IndexModifier(const IndexModifier&) = delete;
    IndexModifier& operator=(const IndexModifier&) = delete;
    ~IndexModifier() {
      that_->index_ -= index_adjust_;
      that_->limit_ -= limit_adjust_;
    }

   private:
    ReadStringVisitor* that_;
    int32_t index_adjust_;
    int32_t limit_adjust_;
  };

  static constexpr int kMaxCharacters = 80;  // How many characters to print.

  std::u16string string_;  // Result string.
  d::MemoryAccessor accessor_;
  const d::HeapAddresses& heap_addresses_;
  int32_t index_;  // Index of next char to read.
  int32_t limit_;  // Don't read past this index (set by SlicedString).
  bool done_;      // Whether to stop further work.
  bool failed_;    // Whether an error was encountered before any valid data.

  // If the string's characters are in a contiguous block of memory (including
  // sequential strings, external strings where we could determine the raw data
  // location, and thin or sliced strings pointing to either of those), then
  // after this visitor has run, the character data's address, size per
  // character, and number of characters will be present in the following
  // fields.
  Address raw_characters_address_ = 0;
  int32_t size_per_character_ = 0;
  int32_t num_characters_ = 0;
};

// An object visitor that supplies extra information for some types.
class AddInfoVisitor : public TqObjectVisitor {
 public:
  // Returns a descriptive string and a list of properties for the given object.
  // Both may be empty, and are meant as an addition or a replacement for,
  // the Torque-generated data about the object.
  static std::pair<std::string, std::vector<std::unique_ptr<ObjectProperty>>>
  Visit(const TqObject* object, d::MemoryAccessor accessor,
        const d::HeapAddresses& heap_addresses) {
    AddInfoVisitor visitor(accessor, heap_addresses);
    object->Visit(&visitor);
    return {std::move(visitor.brief_), std::move(visitor.properties_)};
  }

  void VisitStringImpl(const TqString* object, bool is_sequential) {
    auto visit_result =
        ReadStringVisitor::Visit(accessor_, heap_addresses_, object);
    auto str = visit_result.maybe_truncated_string;
    if (str.has_value()) {
      brief_ = "\"" + *str + "\"";
    }
    // Sequential strings already have a "chars" property based on the Torque
    // type definition, so there's no need to duplicate it. Otherwise, it is
    // useful to display a pointer to the flattened character data if possible.
    if (!is_sequential && visit_result.maybe_raw_characters_property) {
      properties_.push_back(
          std::move(visit_result.maybe_raw_characters_property));
    }
  }

  void VisitString(const TqString* object) override {
    VisitStringImpl(object, /*is_sequential=*/false);
  }

  void VisitSeqString(const TqSeqString* object) override {
    VisitStringImpl(object, /*is_sequential=*/true);
  }

  void VisitJSObject(const TqJSObject* object) override {
    // JSObject and its subclasses can be followed directly by an array of
    // property values. The start and end offsets of those values are described
    // by a pair of values in its Map.
    auto map_ptr = object->GetMapValue(accessor_);
    if (map_ptr.validity != d::MemoryAccessResult::kOk) {
      return;  // Can't read the JSObject. Nothing useful to do.
    }
    DCHECK(!v8::internal::MapWord::IsPacked(map_ptr.value));
    TqMap map(map_ptr.value);

    // On JSObject instances, this value is the start of in-object properties.
    // The constructor function index option is only for primitives.
    auto start_offset =
        map.GetInobjectPropertiesStartOrConstructorFunctionIndexValue(
            accessor_);

    // The total size of the object in memory. This may include over-allocated
    // expansion space that doesn't correspond to any user-accessible property.
    auto instance_size = map.GetInstanceSizeInWordsValue(accessor_);

    if (start_offset.validity != d::MemoryAccessResult::kOk ||
        instance_size.validity != d::MemoryAccessResult::kOk) {
      return;  // Can't read the Map. Nothing useful to do.
    }
    int num_properties = instance_size.value - start_offset.value;
    if (num_properties > 0) {
      properties_.push_back(std::make_unique<ObjectProperty>(
          "in-object properties", kObjectAsStoredInHeap,
          object->GetMapAddress() + start_offset.value * i::kTaggedSize,
          num_properties, i::kTaggedSize,
          std::vector<std::unique_ptr<StructProperty>>(),
          d::PropertyKind::kArrayOfKnownSize));
    }
  }

 private:
  AddInfoVisitor(d::MemoryAccessor accessor,
                 const d::HeapAddresses& heap_addresses)
      : accessor_(accessor), heap_addresses_(heap_addresses) {}

  // Inputs used by this visitor:

  d::MemoryAccessor accessor_;
  const d::HeapAddresses& heap_addresses_;

  // Outputs generated by this visitor:

  // A brief description of the object.
  std::string brief_;
  // A list of extra properties to append after the automatic ones that are
  // created for all Torque-defined class fields.
  std::vector<std::unique_ptr<ObjectProperty>> properties_;
};

std::unique_ptr<ObjectPropertiesResult> GetHeapObjectPropertiesNotCompressed(
    uintptr_t address, d::MemoryAccessor accessor, const char* type_hint,
    const d::HeapAddresses& heap_addresses) {
  // Regardless of whether we can read the object itself, maybe we can find its
  // pointer in the list of known objects.
  std::string brief = FindKnownObject(address, heap_addresses);

  TypedObject typed =
      GetTypedHeapObject(address, accessor, type_hint, heap_addresses);
  auto props = typed.object->GetProperties(accessor);

  // Use the AddInfoVisitor to get any extra properties or descriptive text that
  // can't be directly derived from Torque class definitions.
  auto extra_info =
      AddInfoVisitor::Visit(typed.object.get(), accessor, heap_addresses);
  brief = JoinWithSpace(brief, extra_info.first);

  // Overwrite existing properties if they have the same name.
  for (size_t i = 0; i < extra_info.second.size(); i++) {
    bool overwrite = false;
    for (size_t j = 0; j < props.size(); j++) {
      if (strcmp(props[j]->GetPublicView()->name,
                 extra_info.second[i]->GetPublicView()->name) == 0) {
        props[j] = std::move(extra_info.second[i]);
        overwrite = true;
        break;
      }
    }
    if (overwrite) continue;
    props.push_back(std::move(extra_info.second[i]));
  }

  brief = AppendAddressAndType(brief, address, typed.object->GetName());

  // Convert the low-confidence guessed types to a list of strings as expected
  // for the response.
  std::vector<std::string> guessed_types;
  for (const auto& guess : typed.possible_types) {
    guessed_types.push_back(guess.object->GetName());
  }

  return std::make_unique<ObjectPropertiesResult>(
      typed.type_check_result, brief, typed.object->GetName(), std::move(props),
      std::move(guessed_types));
}

std::unique_ptr<ObjectPropertiesResult> GetHeapObjectPropertiesMaybeCompressed(
    uintptr_t address, d::MemoryAccessor memory_accessor,
    d::HeapAddresses heap_addresses, const char* type_hint) {
  // Try to figure out the heap range, for pointer compression (this is unused
  // if pointer compression is disabled).
  uintptr_t any_uncompressed_ptr = 0;
  if (!IsPointerCompressed(address)) any_uncompressed_ptr = address;
  if (any_uncompressed_ptr == 0)
    any_uncompressed_ptr = heap_addresses.any_heap_pointer;
  if (any_uncompressed_ptr == 0)
    any_uncompressed_ptr = heap_addresses.map_space_first_page;
  if (any_uncompressed_ptr == 0)
    any_uncompressed_ptr = heap_addresses.old_space_first_page;
  if (any_uncompressed_ptr == 0)
    any_uncompressed_ptr = heap_addresses.read_only_space_first_page;
#ifdef V8_COMPRESS_POINTERS
  Address base =
      V8HeapCompressionScheme::GetPtrComprCageBaseAddress(any_uncompressed_ptr);
  if (base != V8HeapCompressionScheme::base()) {
    V8HeapCompressionScheme::InitBase(base);
  }
#endif  // V8_COMPRESS_POINTERS
  FillInUnknownHeapAddresses(&heap_addresses, any_uncompressed_ptr);
  if (any_uncompressed_ptr == 0) {
    // We can't figure out the heap range. Just check for known objects.
    std::string brief = FindKnownObject(address, heap_addresses);
    brief = AppendAddressAndType(brief, address, kTaggedValue);
    return std::make_unique<ObjectPropertiesResult>(
        d::TypeCheckResult::kUnableToDecompress, brief, kTaggedValue);
  }

  address = EnsureDecompressed(address, any_uncompressed_ptr);

  return GetHeapObjectPropertiesNotCompressed(address, memory_accessor,
                                              type_hint, heap_addresses);
}

std::unique_ptr<ObjectPropertiesResult> GetObjectProperties(
    uintptr_t address, d::MemoryAccessor memory_accessor,
    const d::HeapAddresses& heap_addresses, const char* type_hint) {
  if (static_cast<uint32_t>(address) == i::kClearedWeakHeapObjectLower32) {
    return std::make_unique<ObjectPropertiesResult>(
        d::TypeCheckResult::kWeakRef, "cleared weak ref", kHeapObject);
  }
  bool is_weak = (address & i::kHeapObjectTagMask) == i::kWeakHeapObjectTag;
  if (is_weak) {
    address &= ~i::kWeakHeapObjectMask;
  }
  if (i::Internals::HasHeapObjectTag(address)) {
    std::unique_ptr<ObjectPropertiesResult> result =
        GetHeapObjectPropertiesMaybeCompressed(address, memory_accessor,
                                               heap_addresses, type_hint);
    if (is_weak) {
      result->Prepend("weak ref to ");
    }
    return result;
  }

  // For smi values, construct a response with a description representing the
  // untagged value.
  int32_t value = i::PlatformSmiTagging::SmiToInt(address);
  std::stringstream stream;
  stream << value << " (0x" << std::hex << value << ")";
  return std::make_unique<ObjectPropertiesResult>(d::TypeCheckResult::kSmi,
                                                  stream.str(), kSmi);
}

std::unique_ptr<StackFrameResult> GetStackFrame(
    uintptr_t frame_pointer, d::MemoryAccessor memory_accessor) {
  // Read the data at frame_pointer + kContextOrFrameTypeOffset.
  intptr_t context_or_frame_type = 0;
  d::MemoryAccessResult validity = memory_accessor(
      frame_pointer + CommonFrameConstants::kContextOrFrameTypeOffset,
      reinterpret_cast<void*>(&context_or_frame_type), sizeof(intptr_t));
  auto props = std::vector<std::unique_ptr<ObjectProperty>>();
  if (validity == d::MemoryAccessResult::kOk) {
    // If it is context, not frame marker then add new property
    // "currently_executing_function".
    if (!StackFrame::IsTypeMarker(context_or_frame_type)) {
      props.push_back(std::make_unique<ObjectProperty>(
          "currently_executing_jsfunction",
          CheckTypeName<v8::internal::Tagged<v8::internal::JSFunction>>(
              "v8::internal::Tagged<v8::internal::JSFunction>"),
          frame_pointer + StandardFrameConstants::kFunctionOffset, 1,
          sizeof(v8::internal::JSFunction),
          std::vector<std::unique_ptr<StructProperty>>(),
          d::PropertyKind::kSingle));
      // Add more items in the Locals pane representing the JS function name,
      // source file name, and line & column numbers within the source file, so
      // that the user doesn’t need to dig through the shared_function_info to
      // find them.
      intptr_t js_function_ptr = 0;
      validity = memory_accessor(
          frame_pointer + StandardFrameConstants::kFunctionOffset,
          reinterpret_cast<void*>(&js_function_ptr), sizeof(intptr_t));
      if (validity == d::MemoryAccessResult::kOk) {
        TqJSFunction js_function(js_function_ptr);
        auto shared_function_info_ptr =
            js_function.GetSharedFunctionInfoValue(memory_accessor);
        if (shared_function_info_ptr.validity == d::MemoryAccessResult::kOk) {
          TqSharedFunctionInfo shared_function_info(
              shared_function_info_ptr.value);
          auto script_ptr =
              shared_function_info.GetScriptValue(memory_accessor);
          if (script_ptr.validity == d::MemoryAccessResult::kOk) {
            // Make sure script_ptr is script.
            auto address = script_ptr.value;
            if (IsTypedHeapObjectInstanceTypeOf(address, memory_accessor,
                                                i::InstanceType::SCRIPT_TYPE)) {
              TqScript script(script_ptr.value);
              props.push_back(std::make_unique<ObjectProperty>(
                  "script_name", kObjectAsStoredInHeap, script.GetNameAddress(),
                  1, i::kTaggedSize,
                  std::vector<std::unique_ptr<StructProperty>>(),
                  d::PropertyKind::kSingle));
              props.push_back(std::make_unique<ObjectProperty>(
                  "script_source", kObjectAsStoredInHeap,
                  script.GetSourceAddress(), 1, i::kTaggedSize,
                  std::vector<std::unique_ptr<StructProperty>>(),
                  d::PropertyKind::kSingle));
            }
          }
          auto name_or_scope_info_ptr =
              shared_function_info.GetNameOrScopeInfoValue(memory_accessor);
          if (name_or_scope_info_ptr.validity == d::MemoryAccessResult::kOk) {
            auto scope_info_address = name_or_scope_info_ptr.value;
            // Make sure name_or_scope_info_ptr is scope info.
            if (IsTypedHeapObjectInstanceTypeOf(
                    scope_info_address, memory_accessor,
                    i::InstanceType::SCOPE_INFO_TYPE)) {
              auto indexed_field_slice_function_variable_info =
                  TqDebugFieldSliceScopeInfoFunctionVariableInfo(
                      memory_accessor, scope_info_address);
              if (indexed_field_slice_function_variable_info.validity ==
                  d::MemoryAccessResult::kOk) {
                props.push_back(std::make_unique<ObjectProperty>(
                    "function_name", kObjectAsStoredInHeap,
                    scope_info_address - i::kHeapObjectTag +
                        std::get<1>(
                            indexed_field_slice_function_variable_info.value),
                    std::get<2>(
                        indexed_field_slice_function_variable_info.value),
                    i::kTaggedSize,
                    std::vector<std::unique_ptr<StructProperty>>(),
                    d::PropertyKind::kSingle));
              }
              std::vector<std::unique_ptr<StructProperty>>
                  position_info_struct_field_list;
              position_info_struct_field_list.push_back(
                  std::make_unique<StructProperty>(
                      "start", kObjectAsStoredInHeap, 0, 0, 0));
              position_info_struct_field_list.push_back(
                  std::make_unique<StructProperty>("end", kObjectAsStoredInHeap,
                                                   4, 0, 0));
              TqScopeInfo scope_info(scope_info_address);
              props.push_back(std::make_unique<ObjectProperty>(
                  "function_character_offset", "",
                  scope_info.GetPositionInfoAddress(), 1, 2 * i::kTaggedSize,
                  std::move(position_info_struct_field_list),
                  d::PropertyKind::kSingle));
            }
          }
        }
      }
    }
  }

  return std::make_unique<StackFrameResult>(std::move(props));
}

}  // namespace v8::internal::debug_helper_internal

namespace di = v8::internal::debug_helper_internal;

extern "C" {
V8_DEBUG_HELPER_EXPORT d::ObjectPropertiesResult*
_v8_debug_helper_GetObjectProperties(uintptr_t object,
                                     d::MemoryAccessor memory_accessor,
                                     const d::HeapAddresses& heap_addresses,
                                     const char* type_hint) {
  return di::GetObjectProperties(object, memory_accessor, heap_addresses,
                                 type_hint)
      .release()
      ->GetPublicView();
}
V8_DEBUG_HELPER_EXPORT void _v8_debug_helper_Free_ObjectPropertiesResult(
    d::ObjectPropertiesResult* result) {
  std::unique_ptr<di::ObjectPropertiesResult> ptr(
      static_cast<di::ObjectPropertiesResultExtended*>(result)->base);
}

V8_DEBUG_HELPER_EXPORT d::StackFrameResult* _v8_debug_helper_GetStackFrame(
    uintptr_t frame_pointer, d::MemoryAccessor memory_accessor) {
  return di::GetStackFrame(frame_pointer, memory_accessor)
      .release()
      ->GetPublicView();
}
V8_DEBUG_HELPER_EXPORT void _v8_debug_helper_Free_StackFrameResult(
    d::StackFrameResult* result) {
  std::unique_ptr<di::StackFrameResult> ptr(
      static_cast<di::StackFrameResultExtended*>(result)->base);
}
}

"""
```