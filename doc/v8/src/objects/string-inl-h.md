Response:
Let's break down the thought process for analyzing the provided C++ header file.

1. **Initial Understanding of the Request:** The request asks for a functional summary of `v8/src/objects/string-inl.h`. It also includes specific instructions related to Torque, JavaScript relevance, code logic, and common errors. The "part 1 of 2" suggests this is a limited scope.

2. **File Extension Check:** The first and easiest check is the filename extension. It ends with `.h`, *not* `.tq`. Therefore, it's a standard C++ header file, not a Torque source file. This immediately addresses one of the specific instructions.

3. **Copyright and Header Guards:**  The standard boilerplate at the top (`// Copyright...`, `#ifndef V8_OBJECTS_STRING_INL_H_`, `#define V8_OBJECTS_STRING_INL_H_`) confirms this is a C++ header file and serves its usual purpose of preventing multiple inclusions.

4. **Includes - Identifying Dependencies:**  The `#include` directives are crucial for understanding the file's purpose. Let's categorize them:
    * **Core V8:**  Includes like `"src/common/assert-scope.h"`, `"src/common/globals.h"`, `"src/execution/isolate-utils.h"`, `"src/handles/handles-inl.h"`, `"src/heap/factory.h"`, `"src/heap/heap-layout-inl.h"`, `"src/objects/instance-type-inl.h"`, `"src/objects/name-inl.h"`, `"src/objects/objects-body-descriptors.h"`, `"src/objects/smi-inl.h"`, `"src/objects/string-table-inl.h"`, `"src/objects/string.h"`. These strongly indicate this file is deeply integrated within V8's object system, specifically dealing with strings. The `-inl.h` suffix often signifies inline implementations.
    * **String Specific:** `"src/strings/string-hasher-inl.h"`, `"src/strings/unicode-inl.h"`. Confirms a focus on string manipulation and hashing.
    * **Sandbox:** `"src/sandbox/external-pointer-inl.h"`, `"src/sandbox/external-pointer.h"`, `"src/sandbox/isolate.h"`. Suggests interaction with V8's sandboxing mechanism, potentially for external string representations.
    * **Torque Runtime:** `"src/torque/runtime-macro-shims.h"`, `"src/torque/runtime-support.h"`. Although not a Torque *source* file, it *includes* Torque-related headers, hinting at its potential usage within Torque-generated code or interaction with Torque runtime.
    * **Utilities:** `"src/utils/utils.h"`. General utility functions.
    * **Object Macros:** `"src/objects/object-macros.h"`. This is a very important V8-specific include, providing macros for defining object layouts and accessors. Its presence firmly establishes this file's role in defining the internal structure of V8 strings.

5. **Namespace:**  The `namespace v8::internal { ... }` clearly indicates this code is part of V8's internal implementation details, not meant for direct external consumption.

6. **`SharedStringAccessGuardIfNeeded` Class:** This class is about thread-safety. It uses `SharedMutexGuard` to protect access to string data, especially for internalized strings accessed from background threads. The logic for determining when a guard is needed (checking for background threads and read-only heaps) is important.

7. **`String` Class Methods (Inline):** The code defines inline methods for the `String` class, such as `length()`, `set_length()`. This means these methods are likely small and performance-critical, suitable for inlining directly at the call site. The `AcquireLoadTag` and `ReleaseStoreTag` hint at atomic operations for thread-safe length access.

8. **`StringShape` Class:** This class is interesting. It appears to be a lightweight way to quickly determine the type and characteristics of a string (e.g., whether it's internalized, cons, thin, sliced, external, sequential, one-byte, two-byte). The bitmask operations (`&`, `|`) are key to understanding how it extracts this information from the `instance_type`. The `DispatchToSpecificType` templates demonstrate a pattern for handling different string types efficiently, likely using a form of virtual dispatch without the overhead of virtual functions.

9. **String Table Keys (`SequentialStringKey`, `SeqSubStringKey`):** These classes are involved in V8's string interning mechanism. They provide ways to hash and compare strings efficiently when looking them up in the string table. The `PrepareForInsertion` method shows how new strings are created and internalized.

10. **String Comparison (`Equals`, `IsEqualTo`):** These functions handle string equality checks, taking into account different string representations (sequential, sliced, cons, thin, external). The `IsEqualToImpl` function shows the logic for comparing character data based on the string's encoding.

11. **String Flattening (`SlowFlatten`, `Flatten`):** Cons strings are a way to represent string concatenation lazily. The flattening functions convert a cons string into a contiguous sequential string. The logic handles different allocation types and optimizes for already-flat strings.

12. **`FlatContent` Class:** This class provides a way to access the raw character data of a string without keeping the entire `String` object alive. It's likely used in performance-critical string processing operations. The checksum mechanism suggests a focus on data integrity and debugging.

13. **String Sharing (`Share`):** This relates to V8's shared string table feature, where strings can be shared across isolates. The different `StringTransitionStrategy` values indicate how the sharing is implemented.

14. **Character Access (`Get`, `Set`):**  These methods provide access to individual characters within a string, handling different encoding types.

15. **Inline Implementation:** The `.inl.h` suffix and the presence of inline functions strongly suggest that this file provides inline implementations of methods declared in the corresponding `.h` file (presumably `v8/src/objects/string.h`).

16. **Synthesizing the Summary:** Based on the above analysis, we can now synthesize a functional summary, focusing on the key responsibilities and how the different parts interact. The summary should highlight the inline implementations, string type management, thread safety, interning, comparison, flattening, and raw data access.

17. **Addressing Specific Instructions:**
    * **Torque:** Confirm it's *not* a Torque source file but has Torque-related includes.
    * **JavaScript Relevance:**  Connect the C++ concepts (like string types, flattening, interning) to their observable effects in JavaScript (string creation, concatenation, equality). Provide concrete JavaScript examples.
    * **Code Logic:**  Choose a relevant piece of code (e.g., `IsEqualToImpl`) and provide a simple input and expected output to illustrate its behavior.
    * **Common Errors:** Think about what could go wrong when working with strings in JavaScript that might relate to the underlying C++ implementation (e.g., performance issues with heavy string concatenation, unexpected behavior with string comparison).

18. **Review and Refine:**  Read through the generated summary and examples to ensure they are accurate, clear, and address all aspects of the request. Make sure the language is appropriate for the intended audience.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_STRING_INL_H_
#define V8_OBJECTS_STRING_INL_H_

#include <optional>

#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/execution/isolate-utils.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory.h"
#include "src/heap/heap-layout-inl.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/name-inl.h"
#include "src/objects/objects-body-descriptors.h"
#include "src/objects/smi-inl.h"
#include "src/objects/string-table-inl.h"
#include "src/objects/string.h"
#include "src/sandbox/external-pointer-inl.h"
#include "src/sandbox/external-pointer.h"
#include "src/sandbox/isolate.h"
#include "src/strings/string-hasher-inl.h"
#include "src/strings/unicode-inl.h"
#include "src/torque/runtime-macro-shims.h"
#include "src/torque/runtime-support.h"
#include "src/utils/utils.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

class V8_NODISCARD SharedStringAccessGuardIfNeeded {
 public:
  // Creates no SharedMutexGuard<kShared> for the string access since it was
  // called from the main thread.
  explicit SharedStringAccessGuardIfNeeded(Isolate* isolate) {}

  // Creates a SharedMutexGuard<kShared> for the string access if it was called
  // from a background thread.
  explicit SharedStringAccessGuardIfNeeded(LocalIsolate* local_isolate) {
    if (IsNeeded(local_isolate)) {
      mutex_guard.emplace(local_isolate->internalized_string_access());
    }
  }

  // Slow version which gets the isolate from the String.
  explicit SharedStringAccessGuardIfNeeded(Tagged<String> str) {
    Isolate* isolate = GetIsolateIfNeeded(str);
    if (isolate != nullptr) {
      mutex_guard.emplace(isolate->internalized_string_access());
    }
  }

  SharedStringAccessGuardIfNeeded(Tagged<String> str,
                                  LocalIsolate* local_isolate) {
    if (IsNeeded(str, local_isolate)) {
      mutex_guard.emplace(local_isolate->internalized_string_access());
    }
  }

  static SharedStringAccessGuardIfNeeded NotNeeded() {
    return SharedStringAccessGuardIfNeeded();
  }

  static bool IsNeeded(Tagged<String> str, LocalIsolate* local_isolate) {
    return IsNeeded(local_isolate) && IsNeeded(str, false);
  }

  static bool IsNeeded(Tagged<String> str, bool check_local_heap = true) {
    if (check_local_heap) {
      LocalHeap* local_heap = LocalHeap::Current();
      if (!local_heap || local_heap->is_main_thread()) {
        // Don't acquire the lock for the main thread.
        return false;
      }
    }

    if (ReadOnlyHeap::Contains(str)) {
      // Don't acquire lock for strings in ReadOnlySpace.
      return false;
    }

    return true;
  }

  static bool IsNeeded(LocalIsolate* local_isolate) {
    // TODO(leszeks): Remove the nullptr check for local_isolate.
    return local_isolate && !local_isolate->heap()->is_main_thread();
  }

 private:
  // Default constructor and move constructor required for the NotNeeded()
  // static constructor.
  constexpr SharedStringAccessGuardIfNeeded() = default;
  constexpr SharedStringAccessGuardIfNeeded(SharedStringAccessGuardIfNeeded&&)
      V8_NOEXCEPT {
    DCHECK(!mutex_guard.has_value());
  }

  // Returns the Isolate from the String if we need it for the lock.
  static Isolate* GetIsolateIfNeeded(Tagged<String> str) {
    if (!IsNeeded(str)) return nullptr;

    Isolate* isolate;
    if (!GetIsolateFromHeapObject(str, &isolate)) {
      // If we can't get the isolate from the String, it must be read-only.
      DCHECK(ReadOnlyHeap::Contains(str));
      return nullptr;
    }
    return isolate;
  }

  std::optional<base::SharedMutexGuard<base::kShared>> mutex_guard;
};

uint32_t String::length() const { return length_; }

uint32_t String::length(AcquireLoadTag) const {
  return base::AsAtomic32::Acquire_Load(&length_);
}

void String::set_length(uint32_t value) { length_ = value; }

void String::set_length(uint32_t value, ReleaseStoreTag) {
  base::AsAtomic32::Release_Store(&length_, value);
}

static_assert(kTaggedCanConvertToRawObjects);

StringShape::StringShape(const Tagged<String> str)
    : type_(str->map(kAcquireLoad)->instance_type()) {
  set_valid();
  DCHECK_EQ(type_ & kIsNotStringMask, kStringTag);
}

StringShape::StringShape(const Tagged<String> str, PtrComprCageBase cage_base)
    : type_(str->map(kAcquireLoad)->instance_type()) {
  set_valid();
  DCHECK_EQ(type_ & kIsNotStringMask, kStringTag);
}

StringShape::StringShape(Tagged<Map> map) : type_(map->instance_type()) {
  set_valid();
  DCHECK_EQ(type_ & kIsNotStringMask, kStringTag);
}

StringShape::StringShape(InstanceType t) : type_(static_cast<uint32_t>(t)) {
  set_valid();
  DCHECK_EQ(type_ & kIsNotStringMask, kStringTag);
}

bool StringShape::IsInternalized() const {
  DCHECK(valid());
  static_assert(kNotInternalizedTag != 0);
  return (type_ & (kIsNotStringMask | kIsNotInternalizedMask)) ==
         (kStringTag | kInternalizedTag);
}

bool StringShape::IsCons() const {
  return (type_ & kStringRepresentationMask) == kConsStringTag;
}

bool StringShape::IsThin() const {
  return (type_ & kStringRepresentationMask) == kThinStringTag;
}

bool StringShape::IsSliced() const {
  return (type_ & kStringRepresentationMask) == kSlicedStringTag;
}

bool StringShape::IsIndirect() const {
  return (type_ & kIsIndirectStringMask) == kIsIndirectStringTag;
}

bool StringShape::IsDirect() const { return !IsIndirect(); }

bool StringShape::IsExternal() const {
  return (type_ & kStringRepresentationMask) == kExternalStringTag;
}

bool StringShape::IsSequential() const {
  return (type_ & kStringRepresentationMask) == kSeqStringTag;
}

bool StringShape::IsUncachedExternal() const {
  return (type_ & kUncachedExternalStringMask) == kUncachedExternalStringTag;
}

bool StringShape::IsShared() const {
  // TODO(v8:12007): Set is_shared to true on internalized string when
  // v8_flags.shared_string_table is removed.
  return (type_ & kSharedStringMask) == kSharedStringTag ||
         (v8_flags.shared_string_table && IsInternalized());
}

StringRepresentationTag StringShape::representation_tag() const {
  uint32_t tag = (type_ & kStringRepresentationMask);
  return static_cast<StringRepresentationTag>(tag);
}

uint32_t StringShape::encoding_tag() const {
  return type_ & kStringEncodingMask;
}

uint32_t StringShape::representation_and_encoding_tag() const {
  return (type_ & (kStringRepresentationAndEncodingMask));
}

uint32_t StringShape::representation_encoding_and_shared_tag() const {
  return (type_ & (kStringRepresentationEncodingAndSharedMask));
}

static_assert((kStringRepresentationAndEncodingMask) ==
              Internals::kStringRepresentationAndEncodingMask);

static_assert(static_cast<uint32_t>(kStringEncodingMask) ==
              Internals::kStringEncodingMask);

bool StringShape::IsSequentialOneByte() const {
  return representation_and_encoding_tag() == kSeqOneByteStringTag;
}

bool StringShape::IsSequentialTwoByte() const {
  return representation_and_encoding_tag() == kSeqTwoByteStringTag;
}

bool StringShape::IsExternalOneByte() const {
  return representation_and_encoding_tag() == kExternalOneByteStringTag;
}

static_assert(kExternalOneByteStringTag ==
              Internals::kExternalOneByteRepresentationTag);

static_assert(v8::String::ONE_BYTE_ENCODING == kOneByteStringTag);

bool StringShape::IsExternalTwoByte() const {
  return representation_and_encoding_tag() == kExternalTwoByteStringTag;
}

static_assert(kExternalTwoByteStringTag ==
              Internals::kExternalTwoByteRepresentationTag);

static_assert(v8::String::TWO_BYTE_ENCODING == kTwoByteStringTag);

template <typename TDispatcher, typename TResult, typename... TArgs>
inline TResult StringShape::DispatchToSpecificTypeWithoutCast(TArgs&&... args) {
  switch (representation_and_encoding_tag()) {
    case kSeqStringTag | kOneByteStringTag:
      return TDispatcher::HandleSeqOneByteString(std::forward<TArgs>(args)...);
    case kSeqStringTag | kTwoByteStringTag:
      return TDispatcher::HandleSeqTwoByteString(std::forward<TArgs>(args)...);
    case kConsStringTag | kOneByteStringTag:
    case kConsStringTag | kTwoByteStringTag:
      return TDispatcher::HandleConsString(std::forward<TArgs>(args)...);
    case kExternalStringTag | kOneByteStringTag:
      return TDispatcher::HandleExternalOneByteString(
          std::forward<TArgs>(args)...);
    case kExternalStringTag | kTwoByteStringTag:
      return TDispatcher::HandleExternalTwoByteString(
          std::forward<TArgs>(args)...);
    case kSlicedStringTag | kOneByteStringTag:
    case kSlicedStringTag | kTwoByteStringTag:
      return TDispatcher::HandleSlicedString(std::forward<TArgs>(args)...);
    case kThinStringTag | kOneByteStringTag:
    case kThinStringTag | kTwoByteStringTag:
      return TDispatcher::HandleThinString(std::forward<TArgs>(args)...);
    default:
      return TDispatcher::HandleInvalidString(std::forward<TArgs>(args)...);
  }
}

// All concrete subclasses of String (leaves of the inheritance tree).
#define STRING_CLASS_TYPES(V) \
  V(SeqOneByteString)         \
  V(SeqTwoByteString)         \
  V(ConsString)               \
  V(ExternalOneByteString)    \
  V(ExternalTwoByteString)    \
  V(SlicedString)             \
  V(ThinString)

template <typename TDispatcher, typename TResult, typename... TArgs>
inline TResult StringShape::DispatchToSpecificType(Tagged<String> str,
                                                   TArgs&&... args) {
  class CastingDispatcher : public AllStatic {
   public:
#define DEFINE_METHOD(Type)                                                 \
  static inline TResult Handle##Type(Tagged<String> str, TArgs&&... args) { \
    return TDispatcher::Handle##Type(Cast<Type>(str),                       \
                                     std::forward<TArgs>(args)...);         \
  }
    STRING_CLASS_TYPES(DEFINE_METHOD)
#undef DEFINE_METHOD
    static inline TResult HandleInvalidString(Tagged<String> str,
                                              TArgs&&... args) {
      return TDispatcher::HandleInvalidString(str,
                                              std::forward<TArgs>(args)...);
    }
  };

  return DispatchToSpecificTypeWithoutCast<CastingDispatcher, TResult>(
      str, std::forward<TArgs>(args)...);
}

bool String::IsOneByteRepresentation() const {
  return InstanceTypeChecker::IsOneByteString(map());
}

bool String::IsTwoByteRepresentation() const {
  return InstanceTypeChecker::IsTwoByteString(map());
}

base::uc32 FlatStringReader::Get(uint32_t index) const {
  if (is_one_byte_) {
    return Get<uint8_t>(index);
  } else {
    return Get<base::uc16>(index);
  }
}

template <typename Char>
Char FlatStringReader::Get(uint32_t index) const {
  DCHECK_EQ(is_one_byte_, sizeof(Char) == 1);
  DCHECK_LT(index, length_);
  if (sizeof(Char) == 1) {
    return static_cast<Char>(static_cast<const uint8_t*>(start_)[index]);
  } else {
    return static_cast<Char>(static_cast<const base::uc16*>(start_)[index]);
  }
}

template <typename Char>
class SequentialStringKey final : public StringTableKey {
 public:
  SequentialStringKey(base::Vector<const Char> chars, uint64_t seed,
                      bool convert = false)
      : SequentialStringKey(StringHasher::HashSequentialString<Char>(
                                chars.begin(), chars.length(), seed),
                            chars, convert) {}

  SequentialStringKey(int raw_hash_field, base::Vector<const Char> chars,
                      bool convert = false)
      : StringTableKey(raw_hash_field, chars.length()),
        chars_(chars),
        convert_(convert) {}

  template <typename IsolateT>
  bool IsMatch(IsolateT* isolate, Tagged<String> s) {
    return s->IsEqualTo<String::EqualityType::kNoLengthCheck>(chars_, isolate);
  }

  template <typename IsolateT>
  void PrepareForInsertion(IsolateT* isolate) {
    if (sizeof(Char) == 1) {
      internalized_string_ = isolate->factory()->NewOneByteInternalizedString(
          base::Vector<const uint8_t>::cast(chars_), raw_hash_field());
    } else if (convert_) {
      internalized_string_ =
          isolate->factory()->NewOneByteInternalizedStringFromTwoByte(
              base::Vector<const uint16_t>::cast(chars_), raw_hash_field());
    } else {
      internalized_string_ = isolate->factory()->NewTwoByteInternalizedString(
          base::Vector<const uint16_t>::cast(chars_), raw_hash_field());
    }
  }

  Handle<String> GetHandleForInsertion(Isolate* isolate) {
    DCHECK(!internalized_string_.is_null());
    return internalized_string_;
  }

 private:
  base::Vector<const Char> chars_;
  bool convert_;
  Handle<String> internalized_string_;
};

using OneByteStringKey = SequentialStringKey<uint8_t>;
using TwoByteStringKey = SequentialStringKey<uint16_t>;

template <typename SeqString>
class SeqSubStringKey final : public StringTableKey {
 public:
  using Char = typename SeqString::Char;
// VS 2017 on official builds gives this spurious warning:
// warning C4789: buffer 'key' of size 16 bytes will be overrun; 4 bytes will
// be written starting at offset 16
// https://bugs.chromium.org/p/v8/issues/detail?id=6068
#if defined(V8_CC_MSVC)
#pragma warning(push)
#pragma warning(disable : 4789)
#endif
  SeqSubStringKey(Isolate* isolate, Handle<SeqString> string, int from, int len,
                  bool convert = false)
      : StringTableKey(0, len),
        string_(string),
        from_(from),
        convert_(convert) {
    // We have to set the hash later.
    DisallowGarbageCollection no_gc;
    uint32_t raw_hash_field = StringHasher::HashSequentialString(
        string->GetChars(no_gc) + from, len, HashSeed(isolate));
    set_raw_hash_field(raw_hash_field);

    DCHECK_LE(0, length());
    DCHECK_LE(from_ + length(), string_->length());
    DCHECK_EQ(IsSeqOneByteString(*string_), sizeof(Char) == 1);
    DCHECK_EQ(IsSeqTwoByteString(*string_), sizeof(Char) == 2);
  }
#if defined(V8_CC_MSVC)
#pragma warning(pop)
#endif

  bool IsMatch(Isolate* isolate, Tagged<String> string) {
    DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(string));
    DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(*string_));
    DisallowGarbageCollection no_gc;
    return string->IsEqualTo<String::EqualityType::kNoLengthCheck>(
        base::Vector<const Char>(string_->GetChars(no_gc) + from_, length()),
        isolate);
  }

  void PrepareForInsertion(Isolate* isolate) {
    if (sizeof(Char) == 1 || (sizeof(Char) == 2 && convert_)) {
      Handle<SeqOneByteString> result =
          isolate->factory()->AllocateRawOneByteInternalizedString(
              length(), raw_hash_field());
      DisallowGarbageCollection no_gc;
      CopyChars(result->GetChars(no_gc), string_->GetChars(no_gc) + from_,
                length());
      internalized_string_ = result;
    } else {
      Handle<SeqTwoByteString> result =
          isolate->factory()->AllocateRawTwoByteInternalizedString(
              length(), raw_hash_field());
      DisallowGarbageCollection no_gc;
      CopyChars(result->GetChars(no_gc), string_->GetChars(no_gc) + from_,
                length());
      internalized_string_ = result;
    }
  }

  Handle<String> GetHandleForInsertion(Isolate* isolate) {
    DCHECK(!internalized_string_.is_null());
    return internalized_string_;
  }

 private:
  Handle<typename CharTraits<Char>::String> string_;
  int from_;
  bool convert_;
  Handle<String> internalized_string_;
};

using SeqOneByteSubStringKey = SeqSubStringKey<SeqOneByteString>;
using SeqTwoByteSubStringKey = SeqSubStringKey<SeqTwoByteString>;

bool String::Equals(Tagged<String> other) const {
  if (other == this) return true;
  if (IsInternalizedString(this) && IsInternalizedString(other)) {
    return false;
  }
  return SlowEquals(other);
}

// static
bool String::Equals(Isolate* isolate, Handle<String> one, Handle<String> two) {
  if (one.is_identical_to(two)) return true;
  if (IsInternalizedString(*one) && IsInternalizedString(*two)) {
    return false;
  }
  return SlowEquals(isolate, one, two);
}

template <String::EqualityType kEqType, typename Char>
bool String::IsEqualTo(base::Vector<const Char> str, Isolate* isolate) const {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  return IsEqualToImpl<kEqType>(str,
                                SharedStringAccessGuardIfNeeded::NotNeeded());
}

template <String::EqualityType kEqType, typename Char>
bool String::IsEqualTo(base::Vector<const Char> str) const {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  return IsEqualToImpl<kEqType>(str,
                                SharedStringAccessGuardIfNeeded::NotNeeded());
}

template <String::EqualityType kEqType, typename Char>
bool String::IsEqualTo(base::Vector<const Char> str,
                       LocalIsolate* isolate) const {
  SharedStringAccessGuardIfNeeded access_guard(isolate);
  return IsEqualToImpl<kEqType>(str, access_guard);
}

template <String::EqualityType kEqType, typename Char>
bool String::IsEqualToImpl(
    base::Vector<const Char> str,
    const SharedStringAccessGuardIfNeeded& access_guard) const {
  size_t len = str.size();
  switch (kEqType) {
    case EqualityType::kWholeString:
      if (static_cast<size_t>(length()) != len) return false;
      break;
    case EqualityType::kPrefix:
      if (static_cast<size_t>(length()) < len) return false;
      break;
    case EqualityType::kNoLengthCheck:
      DCHECK_EQ(length(), len);
      break;
  }

  DisallowGarbageCollection no_gc;

  int slice_offset = 0;
  Tagged<String> string = this;
  const Char* data = str.data();
  while (true) {
    int32_t type = string->map()->instance_type();
    switch (type & kStringRepresentationAndEncodingMask) {
      case kSeqOneByteStringTag:
        return CompareCharsEqual(
            Cast<SeqOneByteString>(string)->GetChars(no_gc, access_guard) +
                slice_offset,
            data, len);
      case kSeqTwoByteStringTag:
        return CompareCharsEqual(
            Cast<SeqTwoByteString>(string)->GetChars(no_gc, access_guard) +
                slice_offset,
            data, len);
      case kExternalOneByteStringTag:
        return CompareCharsEqual(
            Cast<ExternalOneByteString>(string)->GetChars() + slice_offset,
            data, len);
      case kExternalTwoByteStringTag:
        return CompareCharsEqual(
            Cast<ExternalTwoByteString>(string)->GetChars() + slice_offset,
            data, len);

      case kSlicedStringTag | kOneByteStringTag:
      case kSlicedStringTag | kTwoByteStringTag: {
        Tagged<SlicedString> slicedString = Cast<SlicedString>(string);
        slice_offset += slicedString->offset();
        string = slicedString->parent();
        continue;
      }

      case kConsStringTag | kOneByteStringTag:
      case kConsStringTag | kTwoByteStringTag: {
        // The ConsString path is more complex and rare, so call out to an
        // out-of-line handler.
        // Slices cannot refer to ConsStrings, so there cannot be a non-zero
        // slice offset here.
        DCHECK_EQ(slice_offset, 0);
        return IsConsStringEqualToImpl<Char>(Cast<ConsString>(string), str,
                                             access_guard);
      }

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
template <typename Char>
bool String::IsConsStringEqualToImpl(
    Tagged<ConsString> string, base::Vector<const Char> str,
    const SharedStringAccessGuardIfNeeded& access_guard) {
  // Already checked the len in IsEqualToImpl. Check GE rather than EQ in case
  // this is a prefix check.
  DCHECK_GE(string->length(), str.size());

  ConsStringIterator iter(Cast<ConsString>(string));
  base::Vector<const Char> remaining_str = str;
  int offset;
  for (Tagged<String> segment = iter.Next(&offset); !segment.is_null();
       segment = iter.Next(&offset)) {
    // We create the iterator without an offset, so we should never have a
    // per-segment offset.
    DCHECK_EQ(offset, 0);
    // Compare the individual segment against the appropriate subvector of the
    // remaining string.
    size_t len = std::min<size_t>(segment->length(), remaining_str.size());
    base::Vector<const Char> sub_str = remaining_str.SubVector(0, len);
    if (!segment->IsEqualToImpl<EqualityType::kNoLengthCheck>(sub_str,
                                                              access_guard)) {
      return false;
    }
    remaining_str += len;
    if (remaining_str.empty()) break;
  }
  DCHECK_EQ(remaining_str.data(), str.end());
  DCHECK_EQ(remaining_str.size(), 0);
  return true;
}

bool String::IsOneByteEqualTo(base::Vector<const char> str) {
  return IsEqualTo(str);
}

template <typename Char>
const Char* String::GetDirectStringChars(
    const DisallowGarbageCollection& no_gc) const {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  DCHECK(StringShape(this).IsDirect());
  return StringShape(this).IsExternal()
             ? Cast<typename CharTraits<Char>::ExternalString>(this).GetChars()
             : Cast<typename CharTraits<Char>::String>(this).GetChars(no_gc);
}

template <typename Char>
const Char* String::GetDirectStringChars(
    const DisallowGarbageCollection& no_gc,
    const SharedStringAccessGuardIfNeeded& access_guard) const {
  DCHECK(StringShape(this).IsDirect());
  return StringShape(this).IsExternal()
             ? Cast<typename CharTraits<Char>::ExternalString>(this)->GetChars()
             : Cast<typename CharTraits<Char>::String>(this)->GetChars(
                   no_gc, access_guard);
}

// static
Handle<String> String::SlowFlatten(Isolate* isolate, Handle<ConsString> cons,
                                   AllocationType allocation) {
  DCHECK(!cons->IsFlat());
  DCHECK_NE(cons->second()->length(), 0);  // Equivalent to !IsFlat.
  DCHECK(!HeapLayout::InAnySharedSpace(*cons));

  bool is_one_byte_representation;
  uint32_t length;

  {
    DisallowGarbageCollection no_gc;
    Tagged<ConsString> raw_cons = *cons;

    // TurboFan can create cons strings with empty first parts. Canonicalize the
    // cons shape here. Note this case is very rare in practice.
    if (V8_UNLIKELY(raw_cons->first()->length() ==
Prompt: 
```
这是目录为v8/src/objects/string-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/string-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_STRING_INL_H_
#define V8_OBJECTS_STRING_INL_H_

#include <optional>

#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/execution/isolate-utils.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory.h"
#include "src/heap/heap-layout-inl.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/name-inl.h"
#include "src/objects/objects-body-descriptors.h"
#include "src/objects/smi-inl.h"
#include "src/objects/string-table-inl.h"
#include "src/objects/string.h"
#include "src/sandbox/external-pointer-inl.h"
#include "src/sandbox/external-pointer.h"
#include "src/sandbox/isolate.h"
#include "src/strings/string-hasher-inl.h"
#include "src/strings/unicode-inl.h"
#include "src/torque/runtime-macro-shims.h"
#include "src/torque/runtime-support.h"
#include "src/utils/utils.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

class V8_NODISCARD SharedStringAccessGuardIfNeeded {
 public:
  // Creates no SharedMutexGuard<kShared> for the string access since it was
  // called from the main thread.
  explicit SharedStringAccessGuardIfNeeded(Isolate* isolate) {}

  // Creates a SharedMutexGuard<kShared> for the string access if it was called
  // from a background thread.
  explicit SharedStringAccessGuardIfNeeded(LocalIsolate* local_isolate) {
    if (IsNeeded(local_isolate)) {
      mutex_guard.emplace(local_isolate->internalized_string_access());
    }
  }

  // Slow version which gets the isolate from the String.
  explicit SharedStringAccessGuardIfNeeded(Tagged<String> str) {
    Isolate* isolate = GetIsolateIfNeeded(str);
    if (isolate != nullptr) {
      mutex_guard.emplace(isolate->internalized_string_access());
    }
  }

  SharedStringAccessGuardIfNeeded(Tagged<String> str,
                                  LocalIsolate* local_isolate) {
    if (IsNeeded(str, local_isolate)) {
      mutex_guard.emplace(local_isolate->internalized_string_access());
    }
  }

  static SharedStringAccessGuardIfNeeded NotNeeded() {
    return SharedStringAccessGuardIfNeeded();
  }

  static bool IsNeeded(Tagged<String> str, LocalIsolate* local_isolate) {
    return IsNeeded(local_isolate) && IsNeeded(str, false);
  }

  static bool IsNeeded(Tagged<String> str, bool check_local_heap = true) {
    if (check_local_heap) {
      LocalHeap* local_heap = LocalHeap::Current();
      if (!local_heap || local_heap->is_main_thread()) {
        // Don't acquire the lock for the main thread.
        return false;
      }
    }

    if (ReadOnlyHeap::Contains(str)) {
      // Don't acquire lock for strings in ReadOnlySpace.
      return false;
    }

    return true;
  }

  static bool IsNeeded(LocalIsolate* local_isolate) {
    // TODO(leszeks): Remove the nullptr check for local_isolate.
    return local_isolate && !local_isolate->heap()->is_main_thread();
  }

 private:
  // Default constructor and move constructor required for the NotNeeded()
  // static constructor.
  constexpr SharedStringAccessGuardIfNeeded() = default;
  constexpr SharedStringAccessGuardIfNeeded(SharedStringAccessGuardIfNeeded&&)
      V8_NOEXCEPT {
    DCHECK(!mutex_guard.has_value());
  }

  // Returns the Isolate from the String if we need it for the lock.
  static Isolate* GetIsolateIfNeeded(Tagged<String> str) {
    if (!IsNeeded(str)) return nullptr;

    Isolate* isolate;
    if (!GetIsolateFromHeapObject(str, &isolate)) {
      // If we can't get the isolate from the String, it must be read-only.
      DCHECK(ReadOnlyHeap::Contains(str));
      return nullptr;
    }
    return isolate;
  }

  std::optional<base::SharedMutexGuard<base::kShared>> mutex_guard;
};

uint32_t String::length() const { return length_; }

uint32_t String::length(AcquireLoadTag) const {
  return base::AsAtomic32::Acquire_Load(&length_);
}

void String::set_length(uint32_t value) { length_ = value; }

void String::set_length(uint32_t value, ReleaseStoreTag) {
  base::AsAtomic32::Release_Store(&length_, value);
}

static_assert(kTaggedCanConvertToRawObjects);

StringShape::StringShape(const Tagged<String> str)
    : type_(str->map(kAcquireLoad)->instance_type()) {
  set_valid();
  DCHECK_EQ(type_ & kIsNotStringMask, kStringTag);
}

StringShape::StringShape(const Tagged<String> str, PtrComprCageBase cage_base)
    : type_(str->map(kAcquireLoad)->instance_type()) {
  set_valid();
  DCHECK_EQ(type_ & kIsNotStringMask, kStringTag);
}

StringShape::StringShape(Tagged<Map> map) : type_(map->instance_type()) {
  set_valid();
  DCHECK_EQ(type_ & kIsNotStringMask, kStringTag);
}

StringShape::StringShape(InstanceType t) : type_(static_cast<uint32_t>(t)) {
  set_valid();
  DCHECK_EQ(type_ & kIsNotStringMask, kStringTag);
}

bool StringShape::IsInternalized() const {
  DCHECK(valid());
  static_assert(kNotInternalizedTag != 0);
  return (type_ & (kIsNotStringMask | kIsNotInternalizedMask)) ==
         (kStringTag | kInternalizedTag);
}

bool StringShape::IsCons() const {
  return (type_ & kStringRepresentationMask) == kConsStringTag;
}

bool StringShape::IsThin() const {
  return (type_ & kStringRepresentationMask) == kThinStringTag;
}

bool StringShape::IsSliced() const {
  return (type_ & kStringRepresentationMask) == kSlicedStringTag;
}

bool StringShape::IsIndirect() const {
  return (type_ & kIsIndirectStringMask) == kIsIndirectStringTag;
}

bool StringShape::IsDirect() const { return !IsIndirect(); }

bool StringShape::IsExternal() const {
  return (type_ & kStringRepresentationMask) == kExternalStringTag;
}

bool StringShape::IsSequential() const {
  return (type_ & kStringRepresentationMask) == kSeqStringTag;
}

bool StringShape::IsUncachedExternal() const {
  return (type_ & kUncachedExternalStringMask) == kUncachedExternalStringTag;
}

bool StringShape::IsShared() const {
  // TODO(v8:12007): Set is_shared to true on internalized string when
  // v8_flags.shared_string_table is removed.
  return (type_ & kSharedStringMask) == kSharedStringTag ||
         (v8_flags.shared_string_table && IsInternalized());
}

StringRepresentationTag StringShape::representation_tag() const {
  uint32_t tag = (type_ & kStringRepresentationMask);
  return static_cast<StringRepresentationTag>(tag);
}

uint32_t StringShape::encoding_tag() const {
  return type_ & kStringEncodingMask;
}

uint32_t StringShape::representation_and_encoding_tag() const {
  return (type_ & (kStringRepresentationAndEncodingMask));
}

uint32_t StringShape::representation_encoding_and_shared_tag() const {
  return (type_ & (kStringRepresentationEncodingAndSharedMask));
}

static_assert((kStringRepresentationAndEncodingMask) ==
              Internals::kStringRepresentationAndEncodingMask);

static_assert(static_cast<uint32_t>(kStringEncodingMask) ==
              Internals::kStringEncodingMask);

bool StringShape::IsSequentialOneByte() const {
  return representation_and_encoding_tag() == kSeqOneByteStringTag;
}

bool StringShape::IsSequentialTwoByte() const {
  return representation_and_encoding_tag() == kSeqTwoByteStringTag;
}

bool StringShape::IsExternalOneByte() const {
  return representation_and_encoding_tag() == kExternalOneByteStringTag;
}

static_assert(kExternalOneByteStringTag ==
              Internals::kExternalOneByteRepresentationTag);

static_assert(v8::String::ONE_BYTE_ENCODING == kOneByteStringTag);

bool StringShape::IsExternalTwoByte() const {
  return representation_and_encoding_tag() == kExternalTwoByteStringTag;
}

static_assert(kExternalTwoByteStringTag ==
              Internals::kExternalTwoByteRepresentationTag);

static_assert(v8::String::TWO_BYTE_ENCODING == kTwoByteStringTag);

template <typename TDispatcher, typename TResult, typename... TArgs>
inline TResult StringShape::DispatchToSpecificTypeWithoutCast(TArgs&&... args) {
  switch (representation_and_encoding_tag()) {
    case kSeqStringTag | kOneByteStringTag:
      return TDispatcher::HandleSeqOneByteString(std::forward<TArgs>(args)...);
    case kSeqStringTag | kTwoByteStringTag:
      return TDispatcher::HandleSeqTwoByteString(std::forward<TArgs>(args)...);
    case kConsStringTag | kOneByteStringTag:
    case kConsStringTag | kTwoByteStringTag:
      return TDispatcher::HandleConsString(std::forward<TArgs>(args)...);
    case kExternalStringTag | kOneByteStringTag:
      return TDispatcher::HandleExternalOneByteString(
          std::forward<TArgs>(args)...);
    case kExternalStringTag | kTwoByteStringTag:
      return TDispatcher::HandleExternalTwoByteString(
          std::forward<TArgs>(args)...);
    case kSlicedStringTag | kOneByteStringTag:
    case kSlicedStringTag | kTwoByteStringTag:
      return TDispatcher::HandleSlicedString(std::forward<TArgs>(args)...);
    case kThinStringTag | kOneByteStringTag:
    case kThinStringTag | kTwoByteStringTag:
      return TDispatcher::HandleThinString(std::forward<TArgs>(args)...);
    default:
      return TDispatcher::HandleInvalidString(std::forward<TArgs>(args)...);
  }
}

// All concrete subclasses of String (leaves of the inheritance tree).
#define STRING_CLASS_TYPES(V) \
  V(SeqOneByteString)         \
  V(SeqTwoByteString)         \
  V(ConsString)               \
  V(ExternalOneByteString)    \
  V(ExternalTwoByteString)    \
  V(SlicedString)             \
  V(ThinString)

template <typename TDispatcher, typename TResult, typename... TArgs>
inline TResult StringShape::DispatchToSpecificType(Tagged<String> str,
                                                   TArgs&&... args) {
  class CastingDispatcher : public AllStatic {
   public:
#define DEFINE_METHOD(Type)                                                 \
  static inline TResult Handle##Type(Tagged<String> str, TArgs&&... args) { \
    return TDispatcher::Handle##Type(Cast<Type>(str),                       \
                                     std::forward<TArgs>(args)...);         \
  }
    STRING_CLASS_TYPES(DEFINE_METHOD)
#undef DEFINE_METHOD
    static inline TResult HandleInvalidString(Tagged<String> str,
                                              TArgs&&... args) {
      return TDispatcher::HandleInvalidString(str,
                                              std::forward<TArgs>(args)...);
    }
  };

  return DispatchToSpecificTypeWithoutCast<CastingDispatcher, TResult>(
      str, std::forward<TArgs>(args)...);
}

bool String::IsOneByteRepresentation() const {
  return InstanceTypeChecker::IsOneByteString(map());
}

bool String::IsTwoByteRepresentation() const {
  return InstanceTypeChecker::IsTwoByteString(map());
}

base::uc32 FlatStringReader::Get(uint32_t index) const {
  if (is_one_byte_) {
    return Get<uint8_t>(index);
  } else {
    return Get<base::uc16>(index);
  }
}

template <typename Char>
Char FlatStringReader::Get(uint32_t index) const {
  DCHECK_EQ(is_one_byte_, sizeof(Char) == 1);
  DCHECK_LT(index, length_);
  if (sizeof(Char) == 1) {
    return static_cast<Char>(static_cast<const uint8_t*>(start_)[index]);
  } else {
    return static_cast<Char>(static_cast<const base::uc16*>(start_)[index]);
  }
}

template <typename Char>
class SequentialStringKey final : public StringTableKey {
 public:
  SequentialStringKey(base::Vector<const Char> chars, uint64_t seed,
                      bool convert = false)
      : SequentialStringKey(StringHasher::HashSequentialString<Char>(
                                chars.begin(), chars.length(), seed),
                            chars, convert) {}

  SequentialStringKey(int raw_hash_field, base::Vector<const Char> chars,
                      bool convert = false)
      : StringTableKey(raw_hash_field, chars.length()),
        chars_(chars),
        convert_(convert) {}

  template <typename IsolateT>
  bool IsMatch(IsolateT* isolate, Tagged<String> s) {
    return s->IsEqualTo<String::EqualityType::kNoLengthCheck>(chars_, isolate);
  }

  template <typename IsolateT>
  void PrepareForInsertion(IsolateT* isolate) {
    if (sizeof(Char) == 1) {
      internalized_string_ = isolate->factory()->NewOneByteInternalizedString(
          base::Vector<const uint8_t>::cast(chars_), raw_hash_field());
    } else if (convert_) {
      internalized_string_ =
          isolate->factory()->NewOneByteInternalizedStringFromTwoByte(
              base::Vector<const uint16_t>::cast(chars_), raw_hash_field());
    } else {
      internalized_string_ = isolate->factory()->NewTwoByteInternalizedString(
          base::Vector<const uint16_t>::cast(chars_), raw_hash_field());
    }
  }

  Handle<String> GetHandleForInsertion(Isolate* isolate) {
    DCHECK(!internalized_string_.is_null());
    return internalized_string_;
  }

 private:
  base::Vector<const Char> chars_;
  bool convert_;
  Handle<String> internalized_string_;
};

using OneByteStringKey = SequentialStringKey<uint8_t>;
using TwoByteStringKey = SequentialStringKey<uint16_t>;

template <typename SeqString>
class SeqSubStringKey final : public StringTableKey {
 public:
  using Char = typename SeqString::Char;
// VS 2017 on official builds gives this spurious warning:
// warning C4789: buffer 'key' of size 16 bytes will be overrun; 4 bytes will
// be written starting at offset 16
// https://bugs.chromium.org/p/v8/issues/detail?id=6068
#if defined(V8_CC_MSVC)
#pragma warning(push)
#pragma warning(disable : 4789)
#endif
  SeqSubStringKey(Isolate* isolate, Handle<SeqString> string, int from, int len,
                  bool convert = false)
      : StringTableKey(0, len),
        string_(string),
        from_(from),
        convert_(convert) {
    // We have to set the hash later.
    DisallowGarbageCollection no_gc;
    uint32_t raw_hash_field = StringHasher::HashSequentialString(
        string->GetChars(no_gc) + from, len, HashSeed(isolate));
    set_raw_hash_field(raw_hash_field);

    DCHECK_LE(0, length());
    DCHECK_LE(from_ + length(), string_->length());
    DCHECK_EQ(IsSeqOneByteString(*string_), sizeof(Char) == 1);
    DCHECK_EQ(IsSeqTwoByteString(*string_), sizeof(Char) == 2);
  }
#if defined(V8_CC_MSVC)
#pragma warning(pop)
#endif

  bool IsMatch(Isolate* isolate, Tagged<String> string) {
    DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(string));
    DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(*string_));
    DisallowGarbageCollection no_gc;
    return string->IsEqualTo<String::EqualityType::kNoLengthCheck>(
        base::Vector<const Char>(string_->GetChars(no_gc) + from_, length()),
        isolate);
  }

  void PrepareForInsertion(Isolate* isolate) {
    if (sizeof(Char) == 1 || (sizeof(Char) == 2 && convert_)) {
      Handle<SeqOneByteString> result =
          isolate->factory()->AllocateRawOneByteInternalizedString(
              length(), raw_hash_field());
      DisallowGarbageCollection no_gc;
      CopyChars(result->GetChars(no_gc), string_->GetChars(no_gc) + from_,
                length());
      internalized_string_ = result;
    } else {
      Handle<SeqTwoByteString> result =
          isolate->factory()->AllocateRawTwoByteInternalizedString(
              length(), raw_hash_field());
      DisallowGarbageCollection no_gc;
      CopyChars(result->GetChars(no_gc), string_->GetChars(no_gc) + from_,
                length());
      internalized_string_ = result;
    }
  }

  Handle<String> GetHandleForInsertion(Isolate* isolate) {
    DCHECK(!internalized_string_.is_null());
    return internalized_string_;
  }

 private:
  Handle<typename CharTraits<Char>::String> string_;
  int from_;
  bool convert_;
  Handle<String> internalized_string_;
};

using SeqOneByteSubStringKey = SeqSubStringKey<SeqOneByteString>;
using SeqTwoByteSubStringKey = SeqSubStringKey<SeqTwoByteString>;

bool String::Equals(Tagged<String> other) const {
  if (other == this) return true;
  if (IsInternalizedString(this) && IsInternalizedString(other)) {
    return false;
  }
  return SlowEquals(other);
}

// static
bool String::Equals(Isolate* isolate, Handle<String> one, Handle<String> two) {
  if (one.is_identical_to(two)) return true;
  if (IsInternalizedString(*one) && IsInternalizedString(*two)) {
    return false;
  }
  return SlowEquals(isolate, one, two);
}

template <String::EqualityType kEqType, typename Char>
bool String::IsEqualTo(base::Vector<const Char> str, Isolate* isolate) const {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  return IsEqualToImpl<kEqType>(str,
                                SharedStringAccessGuardIfNeeded::NotNeeded());
}

template <String::EqualityType kEqType, typename Char>
bool String::IsEqualTo(base::Vector<const Char> str) const {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  return IsEqualToImpl<kEqType>(str,
                                SharedStringAccessGuardIfNeeded::NotNeeded());
}

template <String::EqualityType kEqType, typename Char>
bool String::IsEqualTo(base::Vector<const Char> str,
                       LocalIsolate* isolate) const {
  SharedStringAccessGuardIfNeeded access_guard(isolate);
  return IsEqualToImpl<kEqType>(str, access_guard);
}

template <String::EqualityType kEqType, typename Char>
bool String::IsEqualToImpl(
    base::Vector<const Char> str,
    const SharedStringAccessGuardIfNeeded& access_guard) const {
  size_t len = str.size();
  switch (kEqType) {
    case EqualityType::kWholeString:
      if (static_cast<size_t>(length()) != len) return false;
      break;
    case EqualityType::kPrefix:
      if (static_cast<size_t>(length()) < len) return false;
      break;
    case EqualityType::kNoLengthCheck:
      DCHECK_EQ(length(), len);
      break;
  }

  DisallowGarbageCollection no_gc;

  int slice_offset = 0;
  Tagged<String> string = this;
  const Char* data = str.data();
  while (true) {
    int32_t type = string->map()->instance_type();
    switch (type & kStringRepresentationAndEncodingMask) {
      case kSeqOneByteStringTag:
        return CompareCharsEqual(
            Cast<SeqOneByteString>(string)->GetChars(no_gc, access_guard) +
                slice_offset,
            data, len);
      case kSeqTwoByteStringTag:
        return CompareCharsEqual(
            Cast<SeqTwoByteString>(string)->GetChars(no_gc, access_guard) +
                slice_offset,
            data, len);
      case kExternalOneByteStringTag:
        return CompareCharsEqual(
            Cast<ExternalOneByteString>(string)->GetChars() + slice_offset,
            data, len);
      case kExternalTwoByteStringTag:
        return CompareCharsEqual(
            Cast<ExternalTwoByteString>(string)->GetChars() + slice_offset,
            data, len);

      case kSlicedStringTag | kOneByteStringTag:
      case kSlicedStringTag | kTwoByteStringTag: {
        Tagged<SlicedString> slicedString = Cast<SlicedString>(string);
        slice_offset += slicedString->offset();
        string = slicedString->parent();
        continue;
      }

      case kConsStringTag | kOneByteStringTag:
      case kConsStringTag | kTwoByteStringTag: {
        // The ConsString path is more complex and rare, so call out to an
        // out-of-line handler.
        // Slices cannot refer to ConsStrings, so there cannot be a non-zero
        // slice offset here.
        DCHECK_EQ(slice_offset, 0);
        return IsConsStringEqualToImpl<Char>(Cast<ConsString>(string), str,
                                             access_guard);
      }

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
template <typename Char>
bool String::IsConsStringEqualToImpl(
    Tagged<ConsString> string, base::Vector<const Char> str,
    const SharedStringAccessGuardIfNeeded& access_guard) {
  // Already checked the len in IsEqualToImpl. Check GE rather than EQ in case
  // this is a prefix check.
  DCHECK_GE(string->length(), str.size());

  ConsStringIterator iter(Cast<ConsString>(string));
  base::Vector<const Char> remaining_str = str;
  int offset;
  for (Tagged<String> segment = iter.Next(&offset); !segment.is_null();
       segment = iter.Next(&offset)) {
    // We create the iterator without an offset, so we should never have a
    // per-segment offset.
    DCHECK_EQ(offset, 0);
    // Compare the individual segment against the appropriate subvector of the
    // remaining string.
    size_t len = std::min<size_t>(segment->length(), remaining_str.size());
    base::Vector<const Char> sub_str = remaining_str.SubVector(0, len);
    if (!segment->IsEqualToImpl<EqualityType::kNoLengthCheck>(sub_str,
                                                              access_guard)) {
      return false;
    }
    remaining_str += len;
    if (remaining_str.empty()) break;
  }
  DCHECK_EQ(remaining_str.data(), str.end());
  DCHECK_EQ(remaining_str.size(), 0);
  return true;
}

bool String::IsOneByteEqualTo(base::Vector<const char> str) {
  return IsEqualTo(str);
}

template <typename Char>
const Char* String::GetDirectStringChars(
    const DisallowGarbageCollection& no_gc) const {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  DCHECK(StringShape(this).IsDirect());
  return StringShape(this).IsExternal()
             ? Cast<typename CharTraits<Char>::ExternalString>(this).GetChars()
             : Cast<typename CharTraits<Char>::String>(this).GetChars(no_gc);
}

template <typename Char>
const Char* String::GetDirectStringChars(
    const DisallowGarbageCollection& no_gc,
    const SharedStringAccessGuardIfNeeded& access_guard) const {
  DCHECK(StringShape(this).IsDirect());
  return StringShape(this).IsExternal()
             ? Cast<typename CharTraits<Char>::ExternalString>(this)->GetChars()
             : Cast<typename CharTraits<Char>::String>(this)->GetChars(
                   no_gc, access_guard);
}

// static
Handle<String> String::SlowFlatten(Isolate* isolate, Handle<ConsString> cons,
                                   AllocationType allocation) {
  DCHECK(!cons->IsFlat());
  DCHECK_NE(cons->second()->length(), 0);  // Equivalent to !IsFlat.
  DCHECK(!HeapLayout::InAnySharedSpace(*cons));

  bool is_one_byte_representation;
  uint32_t length;

  {
    DisallowGarbageCollection no_gc;
    Tagged<ConsString> raw_cons = *cons;

    // TurboFan can create cons strings with empty first parts. Canonicalize the
    // cons shape here. Note this case is very rare in practice.
    if (V8_UNLIKELY(raw_cons->first()->length() == 0)) {
      Tagged<String> second = raw_cons->second();
      raw_cons->set_first(second);
      raw_cons->set_second(ReadOnlyRoots(isolate).empty_string());
      DCHECK(raw_cons->IsFlat());
      if (StringShape{second}.IsSequential()) {
        return handle(second, isolate);
      }
      // Note that the remaining subtree may still be non-flat and we thus
      // need to continue below.
    }

    if (V8_LIKELY(allocation != AllocationType::kSharedOld)) {
      if (!HeapLayout::InYoungGeneration(raw_cons)) {
        allocation = AllocationType::kOld;
      }
    }
    length = raw_cons->length();
    is_one_byte_representation = cons->IsOneByteRepresentation();
  }

  DCHECK_EQ(length, cons->length());
  DCHECK_EQ(is_one_byte_representation, cons->IsOneByteRepresentation());
  DCHECK(AllowGarbageCollection::IsAllowed());

  Handle<SeqString> result;
  if (is_one_byte_representation) {
    Handle<SeqOneByteString> flat =
        isolate->factory()
            ->NewRawOneByteString(length, allocation)
            .ToHandleChecked();
    // When the ConsString had a forwarding index, it is possible that it was
    // transitioned to a ThinString (and eventually shortcutted to
    // InternalizedString) during GC.
    if constexpr (v8_flags.always_use_string_forwarding_table.value()) {
      if (!IsConsString(*cons)) {
        DCHECK(IsInternalizedString(*cons) || IsThinString(*cons));
        return String::Flatten(isolate, cons, allocation);
      }
    }
    DisallowGarbageCollection no_gc;
    Tagged<ConsString> raw_cons = *cons;
    WriteToFlat(raw_cons, flat->GetChars(no_gc), 0, length);
    raw_cons->set_first(*flat);
    raw_cons->set_second(ReadOnlyRoots(isolate).empty_string());
    result = flat;
  } else {
    Handle<SeqTwoByteString> flat =
        isolate->factory()
            ->NewRawTwoByteString(length, allocation)
            .ToHandleChecked();
    // When the ConsString had a forwarding index, it is possible that it was
    // transitioned to a ThinString (and eventually shortcutted to
    // InternalizedString) during GC.
    if constexpr (v8_flags.always_use_string_forwarding_table.value()) {
      if (!IsConsString(*cons)) {
        DCHECK(IsInternalizedString(*cons) || IsThinString(*cons));
        return String::Flatten(isolate, cons, allocation);
      }
    }
    DisallowGarbageCollection no_gc;
    Tagged<ConsString> raw_cons = *cons;
    WriteToFlat(raw_cons, flat->GetChars(no_gc), 0, length);
    raw_cons->set_first(*flat);
    raw_cons->set_second(ReadOnlyRoots(isolate).empty_string());
    result = flat;
  }
  DCHECK(result->IsFlat());
  DCHECK(cons->IsFlat());
  return result;
}

// Note that RegExpExecInternal currently relies on this to in-place flatten
// the input `string`.
// static
Handle<String> String::Flatten(Isolate* isolate, Handle<String> string,
                               AllocationType allocation) {
  DisallowGarbageCollection no_gc;  // Unhandlified code.
  Tagged<String> s = *string;
  StringShape shape(s);

  // Shortcut already-flat strings.
  if (V8_LIKELY(shape.IsDirect())) return string;

  if (shape.IsCons()) {
    DCHECK(!HeapLayout::InAnySharedSpace(s));
    Tagged<ConsString> cons = Cast<ConsString>(s);
    if (!cons->IsFlat()) {
      AllowGarbageCollection yes_gc;
      DCHECK_EQ(*string, s);
      Handle<String> result =
          SlowFlatten(isolate, Cast<ConsString>(string), allocation);
      DCHECK(result->IsFlat());
      DCHECK(string->IsFlat());  // In-place flattened.
      return result;
    }
    s = cons->first();
    shape = StringShape(s);
  }

  if (shape.IsThin()) {
    s = Cast<ThinString>(s)->actual();
    DCHECK(!IsConsString(s));
  }

  DCHECK(s->IsFlat());
  DCHECK(string->IsFlat());  // In-place flattened.
  return handle(s, isolate);
}

// static
Handle<String> String::Flatten(LocalIsolate* isolate, Handle<String> string,
                               AllocationType allocation) {
  // We should never pass non-flat strings to String::Flatten when off-thread.
  DCHECK(string->IsFlat());
  return string;
}

// static
std::optional<String::FlatContent> String::TryGetFlatContentFromDirectString(
    const DisallowGarbageCollection& no_gc, Tagged<String> string,
    uint32_t offset, uint32_t length,
    const SharedStringAccessGuardIfNeeded& access_guard) {
  DCHECK_LE(offset + length, string->length());
  switch (StringShape{string}.representation_and_encoding_tag()) {
    case kSeqOneByteStringTag:
      return FlatContent(
          Cast<SeqOneByteString>(string)->GetChars(no_gc, access_guard) +
              offset,
          length, no_gc);
    case kSeqTwoByteStringTag:
      return FlatContent(
          Cast<SeqTwoByteString>(string)->GetChars(no_gc, access_guard) +
              offset,
          length, no_gc);
    case kExternalOneByteStringTag:
      return FlatContent(
          Cast<ExternalOneByteString>(string)->GetChars() + offset, length,
          no_gc);
    case kExternalTwoByteStringTag:
      return FlatContent(
          Cast<ExternalTwoByteString>(string)->GetChars() + offset, length,
          no_gc);
    default:
      return {};
  }
  UNREACHABLE();
}

String::FlatContent String::GetFlatContent(
    const DisallowGarbageCollection& no_gc) {
  return GetFlatContent(no_gc, SharedStringAccessGuardIfNeeded::NotNeeded());
}

String::FlatContent::FlatContent(const uint8_t* start, uint32_t length,
                                 const DisallowGarbageCollection& no_gc)
    : onebyte_start(start), length_(length), state_(ONE_BYTE), no_gc_(no_gc) {
#ifdef ENABLE_SLOW_DCHECKS
  checksum_ = ComputeChecksum();
#endif
}

String::FlatContent::FlatContent(const base::uc16* start, uint32_t length,
                                 const DisallowGarbageCollection& no_gc)
    : twobyte_start(start), length_(length), state_(TWO_BYTE), no_gc_(no_gc) {
#ifdef ENABLE_SLOW_DCHECKS
  checksum_ = ComputeChecksum();
#endif
}

String::FlatContent::~FlatContent() {
  // When ENABLE_SLOW_DCHECKS, check the string contents did not change during
  // the lifetime of the FlatContent. To avoid extra memory use, only the hash
  // is checked instead of snapshotting the full character data.
  //
  // If you crashed here, it means something changed the character data of this
  // FlatContent during its lifetime (e.g. GC relocated the string). This is
  // almost always a bug. If you are certain it is not a bug, you can disable
  // the checksum verification in the caller by calling
  // UnsafeDisableChecksumVerification().
  SLOW_DCHECK(checksum_ == kChecksumVerificationDisabled ||
              checksum_ == ComputeChecksum());
}

#ifdef ENABLE_SLOW_DCHECKS
uint32_t String::FlatContent::ComputeChecksum() const {
  constexpr uint64_t hashseed = 1;
  uint32_t hash;
  if (state_ == ONE_BYTE) {
    hash = StringHasher::HashSequentialString(onebyte_start, length_, hashseed);
  } else {
    DCHECK_EQ(TWO_BYTE, state_);
    hash = StringHasher::HashSequentialString(twobyte_start, length_, hashseed);
  }
  DCHECK_NE(kChecksumVerificationDisabled, hash);
  return hash;
}
#endif

String::FlatContent String::GetFlatContent(
    const DisallowGarbageCollection& no_gc,
    const SharedStringAccessGuardIfNeeded& access_guard) {
  std::optional<FlatContent> flat_content =
      TryGetFlatContentFromDirectString(no_gc, this, 0, length(), access_guard);
  if (flat_content.has_value()) return flat_content.value();
  return SlowGetFlatContent(no_gc, access_guard);
}

Handle<String> String::Share(Isolate* isolate, Handle<String> string) {
  DCHECK(v8_flags.shared_string_table);
  MaybeDirectHandle<Map> new_map;
  switch (
      isolate->factory()->ComputeSharingStrategyForString(string, &new_map)) {
    case StringTransitionStrategy::kCopy:
      return SlowShare(isolate, string);
    case StringTransitionStrategy::kInPlace:
      // A relaxed write is sufficient here, because at this point the string
      // has not yet escaped the current thread.
      DCHECK(HeapLayout::InAnySharedSpace(*string));
      string->set_map_no_write_barrier(isolate, *new_map.ToHandleChecked());
      return string;
    case StringTransitionStrategy::kAlreadyTransitioned:
      return string;
  }
}

uint16_t String::Get(uint32_t index) const {
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(this));
  return GetImpl(index, SharedStringAccessGuardIfNeeded::NotNeeded());
}

uint16_t String::Get(uint32_t index, Isolate* isolate) const {
  SharedStringAccessGuardIfNeeded scope(isolate);
  return GetImpl(index, scope);
}

uint16_t String::Get(uint32_t index, LocalIsolate* local_isolate) const {
  SharedStringAccessGuardIfNeeded scope(local_isolate);
  return GetImpl(index, scope);
}

uint16_t String::Get(
    uint32_t index, const SharedStringAccessGuardIfNeeded& access_guard) const {
  return GetImpl(index, access_guard);
}

uint16_t String::GetImpl(
    uint32_t index, const SharedStringAccessGuardIfNeeded& access_guard) const {
  DCHECK(index >= 0 && index < length());

  class StringGetDispatcher : public AllStatic {
   public:
#define DEFINE_METHOD(Type)                                  \
  static inline uint16_t Handle##Type(                       \
      Tagged<Type> str, int index,                           \
      const SharedStringAccessGuardIfNeeded& access_guard) { \
    return str->Get(index, access_guard);                    \
  }
    STRING_CLASS_TYPES(DEFINE_METHOD)
#undef DEFINE_METHOD
    static inline uint16_t HandleInvalidString(
        Tagged<String> str, int index,
        const SharedStringAccessGuardIfNeeded& access_guard) {
      UNREACHABLE();
    }
  };

  return StringShape(Tagged<String>(this))
      .DispatchToSpecificType<StringGetDispatcher, uint16_t>(this, index,
                                                             access_guard);
}

void String::Set(uint32_t index, uint16_t value) {
  DCHECK(index >= 0 && index < length());
  DCHECK(StringShape(this).IsSequential());

  return IsOneByteRepresentation()
             ? Cast<SeqOneByteString>(this)->SeqOneByteStringSet(index, value)
             : Cast<SeqTwoByteString>(this)->SeqTwoByteStringSet(index, value);
}

bool String::IsFlat() co
"""


```