Response:
Let's break down the thought process for analyzing this V8 header file.

**1. Initial Understanding of the Request:**

The core request is to analyze the functionality of `v8/src/objects/objects-inl.h`. The prompt specifically asks to consider:

*   Its role within V8.
*   Whether it's Torque (based on file extension).
*   Its relationship to JavaScript functionality (with examples).
*   Code logic (with hypothetical inputs/outputs).
*   Common programming errors it relates to.
*   A concise summary of its purpose.

**2. First Pass - File Name and Extension:**

The filename ends in `.h`, not `.tq`. This immediately tells us it's a C++ header file, not a Torque file. This is a crucial piece of information and directly addresses one of the prompt's conditions.

**3. Analyzing the Includes:**

The `#include` directives provide significant clues about the file's purpose. I scanned the list, looking for patterns and familiar V8 components. Key observations:

*   `include/v8-internal.h`: This indicates internal V8 functionality, not exposed to external users.
*   `src/base/...`:  Includes from the `base` directory suggest low-level utilities, memory management, and fundamental data types.
*   `src/builtins/builtins.h`: Hints at connections to built-in JavaScript functions.
*   `src/handles/handles-inl.h`:  Strong indication that this file deals with managing V8 objects on the heap.
*   `src/heap/...`:  Heavy emphasis on heap management, garbage collection, and object allocation.
*   `src/objects/...`: The file's own directory, suggesting it defines and manipulates core object structures within V8. Many specific object types are included (e.g., `heap-number-inl.h`, `js-proxy-inl.h`).
*   `src/sandbox/...`:  Mentions of sandboxing, which is related to security and isolation within V8.

From these includes, a primary function of this file emerges: **Defining and providing inline accessors and predicates for various V8 object types, crucial for internal V8 operations, especially those related to heap management and object manipulation.**

**4. Examining the Code Content:**

I then scanned the actual code within the file, looking for common patterns:

*   **Macros:** The initial comments mention the use of macros for optimization. I looked for `#define` statements and instances where macros are used to generate code (like `IS_TYPE_FUNCTION_DEF`). This confirms the optimization aspect.
*   **`Is...` Functions:** A very prominent pattern is the large number of functions starting with `Is`. These are clearly type-checking predicates, determining the specific type of a V8 object. This reinforces the idea that the file is about object type identification.
*   **Inline Functions:** The `.inl.h` suffix signifies inline functions. This means the code is intended to be substituted directly at the call site for performance. The macros likely contribute to this inlining strategy.
*   **`CastTraits`:** This template structure appears to provide a mechanism for safe downcasting between V8 object types.
*   **`HeapObject` methods:** Methods like `Relaxed_ReadField`, `Relaxed_WriteField`, `Acquire_ReadField`, and `SeqCst_CompareAndSwapField` indicate low-level, potentially atomic, operations on object fields. This is related to memory access and concurrency control within V8.
*   **`Object::...` static methods:**  These methods (like `NumberValue`, `SameNumberValue`, `ToNumber`, `ToString`, `GetProperty`, `SetElement`) reveal functionality related to JavaScript type conversions and property access. This connects the file to higher-level JavaScript semantics.
*   **`DEF_HEAP_OBJECT_PREDICATE`:** This macro is used to define many of the `Is...` predicates in a concise way, further emphasizing the file's role in type checking.

**5. Connecting to JavaScript:**

The `Object::...` methods provide the most direct link to JavaScript. I considered how these methods would be used when executing JavaScript code:

*   **Type Conversions:**  JavaScript's dynamic typing requires implicit and explicit type conversions. Methods like `ToNumber`, `ToString`, `ToObject` are directly involved in this process. I thought of simple JavaScript examples that would trigger these conversions (e.g., `1 + "2"`, `Number("10")`, `Object(1)`).
*   **Property Access:**  `GetProperty` and `SetElement` are fundamental to how JavaScript interacts with objects and arrays. I visualized simple JavaScript property accesses (`obj.prop`, `arr[0]`).
*   **Type Checking:** Although not directly exposed in JavaScript syntax, the underlying `Is...` checks are vital for V8's internal logic when handling different JavaScript types.

**6. Identifying Potential Programming Errors:**

Based on the low-level nature of the file and the type-checking mechanisms, I considered common errors:

*   **Incorrect Type Assumptions:**  Developers working on V8 internals might make assumptions about an object's type without proper checking, leading to crashes or unexpected behavior. The numerous `Is...` checks are designed to prevent this. Casting errors are a direct consequence of this.

**7. Structuring the Answer:**

Finally, I organized the findings into the requested sections:

*   **Functionality:** Summarized the core role of providing inline accessors and predicates.
*   **Torque:** Clearly stated that it's not a Torque file.
*   **JavaScript Relationship:** Used `Object::ToNumber` as a concrete example to illustrate the connection between the C++ code and JavaScript type conversions.
*   **Code Logic:**  Simplified the logic of an `Is...` function and provided a straightforward input/output example.
*   **Common Errors:** Focused on the risk of incorrect casting due to type mismatches.
*   **Summary:**  Reiterated the key purpose of efficient object manipulation and type checking.

**Self-Correction/Refinement during the process:**

*   Initially, I might have focused too much on the heap management aspects. However, recognizing the importance of the `Object::...` methods and their direct link to JavaScript semantics helped me balance the analysis.
*   I made sure to explicitly address all the points raised in the prompt, even the negative case about Torque.
*   I aimed for clarity and conciseness in the explanation, avoiding overly technical jargon where possible, while still being accurate. The JavaScript examples needed to be simple and directly relevant to the C++ functions.
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Review notes:
//
// - The use of macros in these inline functions may seem superfluous
// but it is absolutely needed to make sure gcc generates optimal
// code. gcc is not happy when attempting to inline too deep.
//

#ifndef V8_OBJECTS_OBJECTS_INL_H_
#define V8_OBJECTS_OBJECTS_INL_H_

#include "include/v8-internal.h"
#include "src/base/bits.h"
#include "src/base/memory.h"
#include "src/base/numbers/double.h"
#include "src/builtins/builtins.h"
#include "src/common/globals.h"
#include "src/common/ptr-compr-inl.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-verifier.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/heap/read-only-heap-inl.h"
#include "src/numbers/conversions-inl.h"
#include "src/objects/casting.h"
#include "src/objects/deoptimization-data.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/heap-object.h"
#include "src/objects/hole-inl.h"
#include "src/objects/instance-type-checker.h"
#include "src/objects/js-proxy-inl.h"  // TODO(jkummerow): Drop.
#include "src/objects/keys.h"
#include "src/objects/literal-objects.h"
#include "src/objects/lookup-inl.h"  // TODO(jkummerow): Drop.
#include "src/objects/object-list-macros.h"
#include "src/objects/objects.h"
#include "src/objects/oddball-inl.h"
#include "src/objects/property-details.h"
#include "src/objects/property.h"
#include "src/objects/regexp-match-info-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/slots-inl.h"
#include "src/objects/slots.h"
#include "src/objects/smi-inl.h"
#include "src/objects/tagged-field-inl.h"
#include "src/objects/tagged-impl-inl.h"
#include "src/objects/tagged-index.h"
#include "src/objects/templates.h"
#include "src/roots/roots.h"
#include "src/sandbox/bounded-size-inl.h"
#include "src/sandbox/code-pointer-inl.h"
#include "src/sandbox/cppheap-pointer-inl.h"
#include "src/sandbox/external-pointer-inl.h"
#include "src/sandbox/indirect-pointer-inl.h"
#include "src/sandbox/isolate-inl.h"
#include "src/sandbox/isolate.h"
#include "src/sandbox/sandboxed-pointer-inl.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

template <typename T>
class Managed;
template <typename T>
class TrustedManaged;

PropertyDetails::PropertyDetails(Tagged<Smi> smi) { value_ = smi.value(); }

Tagged<Smi> PropertyDetails::AsSmi() const {
  // Ensure the upper 2 bits have the same value by sign extending it. This is
  // necessary to be able to use the 31st bit of the property details.
  int value = value_ << 1;
  return Smi::FromInt(value >> 1);
}

int PropertyDetails::field_width_in_words() const {
  DCHECK_EQ(location(), PropertyLocation::kField);
  return 1;
}

bool IsTaggedIndex(Tagged<Object> obj) {
  return IsSmi(obj) &&
         TaggedIndex::IsValid(Tagged<TaggedIndex>(obj.ptr()).value());
}

bool IsJSObjectThatCanBeTrackedAsPrototype(Tagged<Object> obj) {
  return IsHeapObject(obj) &&
         IsJSObjectThatCanBeTrackedAsPrototype(Cast<HeapObject>(obj));
}

#define IS_TYPE_FUNCTION_DEF(type_)                                          \
  bool Is##type_(Tagged<Object> obj) {                                       \
    return IsHeapObject(obj) && Is##type_(Cast<HeapObject>(obj));            \
  }                                                                          \
  bool Is##type_(Tagged<Object> obj, PtrComprCageBase cage_base) {           \
    return IsHeapObject(obj) && Is##type_(Cast<HeapObject>(obj), cage_base); \
  }                                                                          \
  bool Is##type_(HeapObject obj) {                                           \
    static_assert(kTaggedCanConvertToRawObjects);                            \
    return Is##type_(Tagged<HeapObject>(obj));                               \
  }                                                                          \
  bool Is##type_(HeapObject obj, PtrComprCageBase cage_base) {               \
    static_assert(kTaggedCanConvertToRawObjects);                            \
    return Is##type_(Tagged<HeapObject>(obj), cage_base);                    \
  }                                                                          \
  bool Is##type_(const HeapObjectLayout* obj) {                              \
    return Is##type_(Tagged<HeapObject>(obj));                               \
  }                                                                          \
  bool Is##type_(const HeapObjectLayout* obj, PtrComprCageBase cage_base) {  \
    return Is##type_(Tagged<HeapObject>(obj), cage_base);                    \
  }
HEAP_OBJECT_TYPE_LIST(IS_TYPE_FUNCTION_DEF)
IS_TYPE_FUNCTION_DEF(HashTableBase)
IS_TYPE_FUNCTION_DEF(SmallOrderedHashTable)
IS_TYPE_FUNCTION_DEF(PropertyDictionary)
#undef IS_TYPE_FUNCTION_DEF

bool IsAnyHole(Tagged<Object> obj, PtrComprCageBase cage_base) {
  return IsHole(obj, cage_base);
}

bool IsAnyHole(Tagged<Object> obj) { return IsHole(obj); }

#define IS_TYPE_FUNCTION_DEF(Type, Value, _)                     \
  bool Is##Type(Tagged<Object> obj, Isolate* isolate) {          \
    return Is##Type(obj, ReadOnlyRoots(isolate));                \
  }                                                              \
  bool Is##Type(Tagged<Object> obj, LocalIsolate* isolate) {     \
    return Is##Type(obj, ReadOnlyRoots(isolate));                \
  }                                                              \
  bool Is##Type(Tagged<Object> obj) {                            \
    return IsHeapObject(obj) && Is##Type(Cast<HeapObject>(obj)); \
  }                                                              \
  bool Is##Type(Tagged<HeapObject> obj) {                        \
    return Is##Type(obj, obj->GetReadOnlyRoots());               \
  }                                                              \
  bool Is##Type(HeapObject obj) {                                \
    static_assert(kTaggedCanConvertToRawObjects);                \
    return Is##Type(Tagged<HeapObject>(obj));                    \
  }                                                              \
  bool Is##Type(const HeapObjectLayout* obj, Isolate* isolate) { \
    return Is##Type(Tagged<HeapObject>(obj), isolate);           \
  }                                                              \
  bool Is##Type(const HeapObjectLayout* obj) {                   \
    return Is##Type(Tagged<HeapObject>(obj));                    \
  }
ODDBALL_LIST(IS_TYPE_FUNCTION_DEF)
HOLE_LIST(IS_TYPE_FUNCTION_DEF)
#undef IS_TYPE_FUNCTION_DEF

#if V8_STATIC_ROOTS_BOOL
#define IS_TYPE_FUNCTION_DEF(Type, Value, CamelName)                           \
  bool Is##Type(Tagged<Object> obj, ReadOnlyRoots roots) {                     \
    SLOW_DCHECK(CheckObjectComparisonAllowed(obj.ptr(), roots.Value().ptr())); \
    return V8HeapCompressionScheme::CompressObject(obj.ptr()) ==               \
           StaticReadOnlyRoot::k##CamelName;                                   \
  }
#else
#define IS_TYPE_FUNCTION_DEF(Type, Value, _)               \
  bool Is##Type(Tagged<Object> obj, ReadOnlyRoots roots) { \
    return obj == roots.Value();                           \
  }
#endif
ODDBALL_LIST(IS_TYPE_FUNCTION_DEF)
HOLE_LIST(IS_TYPE_FUNCTION_DEF)
#undef IS_TYPE_FUNCTION_DEF

bool IsNullOrUndefined(Tagged<Object> obj, Isolate* isolate) {
  return IsNullOrUndefined(obj, ReadOnlyRoots(isolate));
}

bool IsNullOrUndefined(Tagged<Object> obj, LocalIsolate* local_isolate) {
  return IsNullOrUndefined(obj, ReadOnlyRoots(local_isolate));
}

bool IsNullOrUndefined(Tagged<Object> obj, ReadOnlyRoots roots) {
  return IsNull(obj, roots) || IsUndefined(obj, roots);
}

bool IsNullOrUndefined(Tagged<Object> obj) {
  return IsHeapObject(obj) && IsNullOrUndefined(Cast<HeapObject>(obj));
}

bool IsNullOrUndefined(Tagged<HeapObject> obj) {
  return IsNullOrUndefined(obj, obj->GetReadOnlyRoots());
}

bool IsZero(Tagged<Object> obj) { return obj == Smi::zero(); }

bool IsPublicSymbol(Tagged<Object> obj) {
  return IsSymbol(obj) && !Cast<Symbol>(obj)->is_private();
}
bool IsPrivateSymbol(Tagged<Object> obj) {
  return IsSymbol(obj) && Cast<Symbol>(obj)->is_private();
}

bool IsNoSharedNameSentinel(Tagged<Object> obj) {
  return obj == SharedFunctionInfo::kNoSharedNameSentinel;
}

// TODO(leszeks): Expand Is<T> to all types.
#define IS_HELPER_DEF(Type, ...)                             \
  template <>                                                \
  struct CastTraits<Type> {                                  \
    static inline bool AllowFrom(Tagged<Object> value) {     \
      return Is##Type(value);                                \
    }                                                        \
    static inline bool AllowFrom(Tagged<HeapObject> value) { \
      return Is##Type(value);                                \
    }                                                        \
  };
HEAP_OBJECT_ORDINARY_TYPE_LIST(IS_HELPER_DEF)
HEAP_OBJECT_TRUSTED_TYPE_LIST(IS_HELPER_DEF)
ODDBALL_LIST(IS_HELPER_DEF)

#define IS_HELPER_DEF_STRUCT(NAME, Name, name) IS_HELPER_DEF(Name)
STRUCT_LIST(IS_HELPER_DEF_STRUCT)
#undef IS_HELPER_DEF_STRUCT

IS_HELPER_DEF(Number)
#undef IS_HELPER_DEF

template <typename... T>
struct CastTraits<Union<T...>> {
  static inline bool AllowFrom(Tagged<Object> value) {
    return (Is<T>(value) || ...);
  }
  static inline bool AllowFrom(Tagged<HeapObject> value) {
    return (Is<T>(value) || ...);
  }
};
template <>
struct CastTraits<JSPrimitive> {
  static inline bool AllowFrom(Tagged<Object> value) {
    return IsPrimitive(value);
  }
  static inline bool AllowFrom(Tagged<HeapObject> value) {
    return IsPrimitive(value);
  }
};
template <>
struct CastTraits<JSAny> {
  static inline bool AllowFrom(Tagged<Object> value) {
    return IsPrimitive(value) || IsJSReceiver(value);
  }
  static inline bool AllowFrom(Tagged<HeapObject> value) {
    return IsPrimitive(value) || IsJSReceiver(value);
  }
};

template <>
struct CastTraits<FieldType> {
  static inline bool AllowFrom(Tagged<Object> value) {
    return value == FieldType::None() || value == FieldType::Any() ||
           IsMap(value);
  }
  static inline bool AllowFrom(Tagged<HeapObject> value) {
    return IsMap(value);
  }
};

template <typename T>
struct CastTraits<Managed<T>> : public CastTraits<Foreign> {};
template <typename T>
struct CastTraits<TrustedManaged<T>> : public CastTraits<TrustedForeign> {};
template <typename T>
struct CastTraits<PodArray<T>> : public CastTraits<ByteArray> {};
template <typename T>
struct CastTraits<TrustedPodArray<T>> : public CastTraits<TrustedByteArray> {};
template <typename T, typename Base>
struct CastTraits<FixedIntegerArrayBase<T, Base>> : public CastTraits<Base> {};
template <typename Base>
struct CastTraits<FixedAddressArrayBase<Base>> : public CastTraits<Base> {};

template <>
struct CastTraits<JSRegExpResultIndices> : public CastTraits<JSArray> {};
template <>
struct CastTraits<DeoptimizationLiteralArray>
    : public CastTraits<TrustedWeakFixedArray> {};
template <>
struct CastTraits<FreshlyAllocatedBigInt> : public CastTraits<BigInt> {};
template <>
struct CastTraits<JSIteratorResult> : public CastTraits<JSObject> {};

template <>
struct CastTraits<DeoptimizationFrameTranslation>
    : public CastTraits<TrustedByteArray> {};

template <class T, typename std::enable_if_t<
                       (std::is_arithmetic_v<T> ||
                        std::is_enum_v<T>)&&!std::is_floating_point_v<T>,
                       int>>
T HeapObject::Relaxed_ReadField(size_t offset) const {
  // Pointer compression causes types larger than kTaggedSize to be
  // unaligned. Atomic loads must be aligned.
  DCHECK_IMPLIES(COMPRESS_POINTERS_BOOL, sizeof(T) <= kTaggedSize);
  using AtomicT = typename base::AtomicTypeFromByteWidth<sizeof(T)>::type;
  return static_cast<T>(base::AsAtomicImpl<AtomicT>::Relaxed_Load(
      reinterpret_cast<AtomicT*>(field_address(offset))));
}

template <class T, typename std::enable_if_t<
                       (std::is_arithmetic_v<T> ||
                        std::is_enum_v<T>)&&!std::is_floating_point_v<T>,
                       int>>
void HeapObject::Relaxed_WriteField(size_t offset, T value) {
  // Pointer compression causes types larger than kTaggedSize to be
  // unaligned. Atomic stores must be aligned.
  DCHECK_IMPLIES(COMPRESS_POINTERS_BOOL, sizeof(T) <= kTaggedSize);
  using AtomicT = typename base::AtomicTypeFromByteWidth<sizeof(T)>::type;
  base::AsAtomicImpl<AtomicT>::Relaxed_Store(
      reinterpret_cast<AtomicT*>(field_address(offset)),
      static_cast<AtomicT>(value));
}

template <class T, typename std::enable_if_t<
                       (std::is_arithmetic_v<T> ||
                        std::is_enum_v<T>)&&!std::is_floating_point_v<T>,
                       int>>
T HeapObject::Acquire_ReadField(size_t offset) const {
  // Pointer compression causes types larger than kTaggedSize to be
  // unaligned. Atomic loads must be aligned.
  DCHECK_IMPLIES(COMPRESS_POINTERS_BOOL, sizeof(T) <= kTaggedSize);
  using AtomicT = typename base::AtomicTypeFromByteWidth<sizeof(T)>::type;
  return static_cast<T>(base::AsAtomicImpl<AtomicT>::Acquire_Load(
      reinterpret_cast<AtomicT*>(field_address(offset))));
}

// static
template <typename CompareAndSwapImpl>
Tagged<Object> HeapObject::SeqCst_CompareAndSwapField(
    Tagged<Object> expected, Tagged<Object> value,
    CompareAndSwapImpl compare_and_swap_impl) {
  Tagged<Object> actual_expected = expected;
  do {
    Tagged<Object> old_value = compare_and_swap_impl(actual_expected, value);
    if (old_value == actual_expected || !IsNumber(old_value) ||
        !IsNumber(actual_expected)) {
      return old_value;
    }
    if (!Object::SameNumberValue(
            Object::NumberValue(Cast<Number>(old_value)),
            Object::NumberValue(Cast<Number>(actual_expected)))) {
      return old_value;
    }
    // The pointer comparison failed, but the numbers are equal. This can
    // happen even if both numbers are HeapNumbers with the same value.
    // Try again in the next iteration.
    actual_expected = old_value;
  } while (true);
}

constexpr bool FastInReadOnlySpaceOrSmallSmi(Tagged_t obj) {
#if V8_STATIC_ROOTS_BOOL
  // The following assert ensures that the page size check covers all our static
  // roots. This is not strictly necessary and can be relaxed in future as the
  // most prominent static roots are anyways allocated at the beginning of the
  // first page.
  static_assert(StaticReadOnlyRoot::kLastAllocatedRoot < kRegularPageSize);
  return obj < kRegularPageSize;
#else   // !V8_STATIC_ROOTS_BOOL
  return false;
#endif  // !V8_STATIC_ROOTS_BOOL
}

constexpr bool FastInReadOnlySpaceOrSmallSmi(Tagged<MaybeObject> obj) {
#ifdef V8_COMPRESS_POINTERS
  // This check is only valid for objects in the main cage.
  DCHECK(obj.IsSmi() || obj.IsInMainCageBase());
  return FastInReadOnlySpaceOrSmallSmi(
      V8HeapCompressionScheme::CompressAny(obj.ptr()));
#else   // V8_COMPRESS_POINTERS
  return false;
#endif  // V8_COMPRESS_POINTERS
}

bool OutsideSandboxOrInReadonlySpace(Tagged<HeapObject> obj) {
#ifdef V8_ENABLE_SANDBOX
  return !InsideSandbox(obj.address()) ||
         MemoryChunk::FromHeapObject(obj)->SandboxSafeInReadOnlySpace();
#else
  return true;
#endif
}

bool IsJSObjectThatCanBeTrackedAsPrototype(Tagged<HeapObject> obj) {
  // Do not optimize objects in the shared heap because it is not
  // threadsafe. Objects in the shared heap have fixed layouts and their maps
  // never change.
  return IsJSObject(obj) && !HeapLayout::InWritableSharedSpace(*obj);
}

bool IsJSApiWrapperObject(Tagged<Map> map) {
  const InstanceType instance_type = map->instance_type();
  return InstanceTypeChecker::IsJSAPIObjectWithEmbedderSlots(instance_type) ||
         InstanceTypeChecker::IsJSSpecialObject(instance_type);
}

bool IsJSApiWrapperObject(Tagged<HeapObject> js_obj) {
  return IsJSApiWrapperObject(js_obj->map());
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsUniqueName) {
  return IsInternalizedString(obj, cage_base) || IsSymbol(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsCallable) {
  return obj->map(cage_base)->is_callable();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsCallableJSProxy) {
  return IsCallable(obj, cage_base) && IsJSProxy(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsCallableApiObject) {
  InstanceType type = obj->map(cage_base)->instance_type();
  return IsCallable(obj, cage_base) &&
         (type == JS_API_OBJECT_TYPE || type == JS_SPECIAL_API_OBJECT_TYPE);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsNonNullForeign) {
  return IsForeign(obj, cage_base) &&
         Cast<Foreign>(obj)->foreign_address_unchecked() != kNullAddress;
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsConstructor) {
  return obj->map(cage_base)->is_constructor();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsSourceTextModuleInfo) {
  return obj->map(cage_base) == obj->GetReadOnlyRoots().module_info_map();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsConsString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsCons();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsThinString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsThin();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsSlicedString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsSliced();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsSeqString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsSequential();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsSeqOneByteString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsSequentialOneByte();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsSeqTwoByteString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsSequentialTwoByte();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsExternalOneByteString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsExternalOneByte();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsExternalTwoByteString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsExternalTwoByte();
}

bool IsNumber(Tagged<Object> obj) {
  if (IsSmi(obj)) return true;
  Tagged<HeapObject> heap_object = Cast<HeapObject>(obj);
  PtrComprCageBase cage_base = GetPtrComprCageBase(heap_object);
  return IsHeapNumber(heap_object, cage_base);
}

bool IsNumber(Tagged<Object> obj, PtrComprCageBase cage_base) {
  return obj.IsSmi() || IsHeapNumber(obj, cage_base);
}

bool IsNumeric(Tagged<Object> obj) {
  if (IsSmi(obj)) return true;
  Tagged<HeapObject> heap_object = Cast<HeapObject>(obj);
  PtrComprCageBase cage_base = GetPtrComprCageBase(heap_object);
  return IsHeapNumber(heap_object, cage_base) ||
         IsBigInt(heap_object, cage_base);
}

bool IsNumeric(Tagged<Object> obj, PtrComprCageBase cage_base) {
  return IsNumber(obj, cage_base) || IsBigInt(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsTemplateLiteralObject) {
  return IsJSArray(obj, cage_base);
}

#if V8_INTL_SUPPORT
DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsJSSegmentDataObject) {
  return IsJSObject(obj, cage_base);
}
DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsJSSegmentDataObjectWithIsWordLike) {
  return IsJSObject(obj, cage_base);
}
#endif  // V8_INTL_SUPPORT

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsDeoptimizationData) {
  // Must be a (protected) fixed array.
  if (!IsProtectedFixedArray(obj, cage_base)) return false;

  // There's no sure way to detect the difference between a fixed array and
  // a deoptimization data array. Since this is used for asserts we can
  // check that the length is zero or else the fixed size plus a multiple of
  // the entry size.
  int length = Cast<ProtectedFixedArray>(obj)->length();
  if (length == 0) return true;

  length -= DeoptimizationData::kFirstDeoptEntryIndex;
  return length >= 0 && length % DeoptimizationData::kDeoptEntrySize == 0;
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsHandlerTable) {
  return IsFixedArrayExact(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsDependentCode) {
  return IsWeakArrayList(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsOSROptimizedCodeCache) {
  return IsWeakFixedArray(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsStringWrapper) {
  return IsJSPrimitiveWrapper(obj, cage_base) &&
         IsString(Cast<JSPrimitiveWrapper>(obj)->value(), cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsBooleanWrapper) {
  return IsJSPrimitiveWrapper(obj, cage_base) &&
         IsBoolean(Cast<JSPrimitiveWrapper>(obj)->value(), cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsScriptWrapper) {
  return IsJSPrimitiveWrapper(obj, cage_base) &&
         IsScript(Cast<JSPrimitiveWrapper>(obj)->value(), cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsNumberWrapper) {
  return IsJSPrimitiveWrapper(obj, cage_base) &&
         IsNumber(Cast<JSPrimitiveWrapper>(obj)->value(), cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsBigIntWrapper) {
  return IsJSPrimitiveWrapper(obj, cage_base) &&
         IsBigInt(Cast<JSPrimitiveWrapper>(obj)->value(), cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsSymbolWrapper) {
  return IsJSPrimitiveWrapper(obj, cage_base) &&
         IsSymbol(Cast<JSPrimitiveWrapper>(obj)->value(), cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsStringSet) {
  return IsHashTable(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsObjectHashSet) {
  return IsHashTable(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsCompilationCacheTable) {
  return IsHashTable(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsMapCache) {
  return IsHashTable(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsObjectHashTable) {
  return IsHashTable(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsObjectTwoHashTable) {
  return IsHashTable(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsHashTableBase) {
  return IsHashTable(obj, cage_base);
}

// static
bool IsPrimitive(Tagged
Prompt: 
```
这是目录为v8/src/objects/objects-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/objects-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Review notes:
//
// - The use of macros in these inline functions may seem superfluous
// but it is absolutely needed to make sure gcc generates optimal
// code. gcc is not happy when attempting to inline too deep.
//

#ifndef V8_OBJECTS_OBJECTS_INL_H_
#define V8_OBJECTS_OBJECTS_INL_H_

#include "include/v8-internal.h"
#include "src/base/bits.h"
#include "src/base/memory.h"
#include "src/base/numbers/double.h"
#include "src/builtins/builtins.h"
#include "src/common/globals.h"
#include "src/common/ptr-compr-inl.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-verifier.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/heap/read-only-heap-inl.h"
#include "src/numbers/conversions-inl.h"
#include "src/objects/casting.h"
#include "src/objects/deoptimization-data.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/heap-object.h"
#include "src/objects/hole-inl.h"
#include "src/objects/instance-type-checker.h"
#include "src/objects/js-proxy-inl.h"  // TODO(jkummerow): Drop.
#include "src/objects/keys.h"
#include "src/objects/literal-objects.h"
#include "src/objects/lookup-inl.h"  // TODO(jkummerow): Drop.
#include "src/objects/object-list-macros.h"
#include "src/objects/objects.h"
#include "src/objects/oddball-inl.h"
#include "src/objects/property-details.h"
#include "src/objects/property.h"
#include "src/objects/regexp-match-info-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/slots-inl.h"
#include "src/objects/slots.h"
#include "src/objects/smi-inl.h"
#include "src/objects/tagged-field-inl.h"
#include "src/objects/tagged-impl-inl.h"
#include "src/objects/tagged-index.h"
#include "src/objects/templates.h"
#include "src/roots/roots.h"
#include "src/sandbox/bounded-size-inl.h"
#include "src/sandbox/code-pointer-inl.h"
#include "src/sandbox/cppheap-pointer-inl.h"
#include "src/sandbox/external-pointer-inl.h"
#include "src/sandbox/indirect-pointer-inl.h"
#include "src/sandbox/isolate-inl.h"
#include "src/sandbox/isolate.h"
#include "src/sandbox/sandboxed-pointer-inl.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

template <typename T>
class Managed;
template <typename T>
class TrustedManaged;

PropertyDetails::PropertyDetails(Tagged<Smi> smi) { value_ = smi.value(); }

Tagged<Smi> PropertyDetails::AsSmi() const {
  // Ensure the upper 2 bits have the same value by sign extending it. This is
  // necessary to be able to use the 31st bit of the property details.
  int value = value_ << 1;
  return Smi::FromInt(value >> 1);
}

int PropertyDetails::field_width_in_words() const {
  DCHECK_EQ(location(), PropertyLocation::kField);
  return 1;
}

bool IsTaggedIndex(Tagged<Object> obj) {
  return IsSmi(obj) &&
         TaggedIndex::IsValid(Tagged<TaggedIndex>(obj.ptr()).value());
}

bool IsJSObjectThatCanBeTrackedAsPrototype(Tagged<Object> obj) {
  return IsHeapObject(obj) &&
         IsJSObjectThatCanBeTrackedAsPrototype(Cast<HeapObject>(obj));
}

#define IS_TYPE_FUNCTION_DEF(type_)                                          \
  bool Is##type_(Tagged<Object> obj) {                                       \
    return IsHeapObject(obj) && Is##type_(Cast<HeapObject>(obj));            \
  }                                                                          \
  bool Is##type_(Tagged<Object> obj, PtrComprCageBase cage_base) {           \
    return IsHeapObject(obj) && Is##type_(Cast<HeapObject>(obj), cage_base); \
  }                                                                          \
  bool Is##type_(HeapObject obj) {                                           \
    static_assert(kTaggedCanConvertToRawObjects);                            \
    return Is##type_(Tagged<HeapObject>(obj));                               \
  }                                                                          \
  bool Is##type_(HeapObject obj, PtrComprCageBase cage_base) {               \
    static_assert(kTaggedCanConvertToRawObjects);                            \
    return Is##type_(Tagged<HeapObject>(obj), cage_base);                    \
  }                                                                          \
  bool Is##type_(const HeapObjectLayout* obj) {                              \
    return Is##type_(Tagged<HeapObject>(obj));                               \
  }                                                                          \
  bool Is##type_(const HeapObjectLayout* obj, PtrComprCageBase cage_base) {  \
    return Is##type_(Tagged<HeapObject>(obj), cage_base);                    \
  }
HEAP_OBJECT_TYPE_LIST(IS_TYPE_FUNCTION_DEF)
IS_TYPE_FUNCTION_DEF(HashTableBase)
IS_TYPE_FUNCTION_DEF(SmallOrderedHashTable)
IS_TYPE_FUNCTION_DEF(PropertyDictionary)
#undef IS_TYPE_FUNCTION_DEF

bool IsAnyHole(Tagged<Object> obj, PtrComprCageBase cage_base) {
  return IsHole(obj, cage_base);
}

bool IsAnyHole(Tagged<Object> obj) { return IsHole(obj); }

#define IS_TYPE_FUNCTION_DEF(Type, Value, _)                     \
  bool Is##Type(Tagged<Object> obj, Isolate* isolate) {          \
    return Is##Type(obj, ReadOnlyRoots(isolate));                \
  }                                                              \
  bool Is##Type(Tagged<Object> obj, LocalIsolate* isolate) {     \
    return Is##Type(obj, ReadOnlyRoots(isolate));                \
  }                                                              \
  bool Is##Type(Tagged<Object> obj) {                            \
    return IsHeapObject(obj) && Is##Type(Cast<HeapObject>(obj)); \
  }                                                              \
  bool Is##Type(Tagged<HeapObject> obj) {                        \
    return Is##Type(obj, obj->GetReadOnlyRoots());               \
  }                                                              \
  bool Is##Type(HeapObject obj) {                                \
    static_assert(kTaggedCanConvertToRawObjects);                \
    return Is##Type(Tagged<HeapObject>(obj));                    \
  }                                                              \
  bool Is##Type(const HeapObjectLayout* obj, Isolate* isolate) { \
    return Is##Type(Tagged<HeapObject>(obj), isolate);           \
  }                                                              \
  bool Is##Type(const HeapObjectLayout* obj) {                   \
    return Is##Type(Tagged<HeapObject>(obj));                    \
  }
ODDBALL_LIST(IS_TYPE_FUNCTION_DEF)
HOLE_LIST(IS_TYPE_FUNCTION_DEF)
#undef IS_TYPE_FUNCTION_DEF

#if V8_STATIC_ROOTS_BOOL
#define IS_TYPE_FUNCTION_DEF(Type, Value, CamelName)                           \
  bool Is##Type(Tagged<Object> obj, ReadOnlyRoots roots) {                     \
    SLOW_DCHECK(CheckObjectComparisonAllowed(obj.ptr(), roots.Value().ptr())); \
    return V8HeapCompressionScheme::CompressObject(obj.ptr()) ==               \
           StaticReadOnlyRoot::k##CamelName;                                   \
  }
#else
#define IS_TYPE_FUNCTION_DEF(Type, Value, _)               \
  bool Is##Type(Tagged<Object> obj, ReadOnlyRoots roots) { \
    return obj == roots.Value();                           \
  }
#endif
ODDBALL_LIST(IS_TYPE_FUNCTION_DEF)
HOLE_LIST(IS_TYPE_FUNCTION_DEF)
#undef IS_TYPE_FUNCTION_DEF

bool IsNullOrUndefined(Tagged<Object> obj, Isolate* isolate) {
  return IsNullOrUndefined(obj, ReadOnlyRoots(isolate));
}

bool IsNullOrUndefined(Tagged<Object> obj, LocalIsolate* local_isolate) {
  return IsNullOrUndefined(obj, ReadOnlyRoots(local_isolate));
}

bool IsNullOrUndefined(Tagged<Object> obj, ReadOnlyRoots roots) {
  return IsNull(obj, roots) || IsUndefined(obj, roots);
}

bool IsNullOrUndefined(Tagged<Object> obj) {
  return IsHeapObject(obj) && IsNullOrUndefined(Cast<HeapObject>(obj));
}

bool IsNullOrUndefined(Tagged<HeapObject> obj) {
  return IsNullOrUndefined(obj, obj->GetReadOnlyRoots());
}

bool IsZero(Tagged<Object> obj) { return obj == Smi::zero(); }

bool IsPublicSymbol(Tagged<Object> obj) {
  return IsSymbol(obj) && !Cast<Symbol>(obj)->is_private();
}
bool IsPrivateSymbol(Tagged<Object> obj) {
  return IsSymbol(obj) && Cast<Symbol>(obj)->is_private();
}

bool IsNoSharedNameSentinel(Tagged<Object> obj) {
  return obj == SharedFunctionInfo::kNoSharedNameSentinel;
}

// TODO(leszeks): Expand Is<T> to all types.
#define IS_HELPER_DEF(Type, ...)                             \
  template <>                                                \
  struct CastTraits<Type> {                                  \
    static inline bool AllowFrom(Tagged<Object> value) {     \
      return Is##Type(value);                                \
    }                                                        \
    static inline bool AllowFrom(Tagged<HeapObject> value) { \
      return Is##Type(value);                                \
    }                                                        \
  };
HEAP_OBJECT_ORDINARY_TYPE_LIST(IS_HELPER_DEF)
HEAP_OBJECT_TRUSTED_TYPE_LIST(IS_HELPER_DEF)
ODDBALL_LIST(IS_HELPER_DEF)

#define IS_HELPER_DEF_STRUCT(NAME, Name, name) IS_HELPER_DEF(Name)
STRUCT_LIST(IS_HELPER_DEF_STRUCT)
#undef IS_HELPER_DEF_STRUCT

IS_HELPER_DEF(Number)
#undef IS_HELPER_DEF

template <typename... T>
struct CastTraits<Union<T...>> {
  static inline bool AllowFrom(Tagged<Object> value) {
    return (Is<T>(value) || ...);
  }
  static inline bool AllowFrom(Tagged<HeapObject> value) {
    return (Is<T>(value) || ...);
  }
};
template <>
struct CastTraits<JSPrimitive> {
  static inline bool AllowFrom(Tagged<Object> value) {
    return IsPrimitive(value);
  }
  static inline bool AllowFrom(Tagged<HeapObject> value) {
    return IsPrimitive(value);
  }
};
template <>
struct CastTraits<JSAny> {
  static inline bool AllowFrom(Tagged<Object> value) {
    return IsPrimitive(value) || IsJSReceiver(value);
  }
  static inline bool AllowFrom(Tagged<HeapObject> value) {
    return IsPrimitive(value) || IsJSReceiver(value);
  }
};

template <>
struct CastTraits<FieldType> {
  static inline bool AllowFrom(Tagged<Object> value) {
    return value == FieldType::None() || value == FieldType::Any() ||
           IsMap(value);
  }
  static inline bool AllowFrom(Tagged<HeapObject> value) {
    return IsMap(value);
  }
};

template <typename T>
struct CastTraits<Managed<T>> : public CastTraits<Foreign> {};
template <typename T>
struct CastTraits<TrustedManaged<T>> : public CastTraits<TrustedForeign> {};
template <typename T>
struct CastTraits<PodArray<T>> : public CastTraits<ByteArray> {};
template <typename T>
struct CastTraits<TrustedPodArray<T>> : public CastTraits<TrustedByteArray> {};
template <typename T, typename Base>
struct CastTraits<FixedIntegerArrayBase<T, Base>> : public CastTraits<Base> {};
template <typename Base>
struct CastTraits<FixedAddressArrayBase<Base>> : public CastTraits<Base> {};

template <>
struct CastTraits<JSRegExpResultIndices> : public CastTraits<JSArray> {};
template <>
struct CastTraits<DeoptimizationLiteralArray>
    : public CastTraits<TrustedWeakFixedArray> {};
template <>
struct CastTraits<FreshlyAllocatedBigInt> : public CastTraits<BigInt> {};
template <>
struct CastTraits<JSIteratorResult> : public CastTraits<JSObject> {};

template <>
struct CastTraits<DeoptimizationFrameTranslation>
    : public CastTraits<TrustedByteArray> {};

template <class T, typename std::enable_if_t<
                       (std::is_arithmetic_v<T> ||
                        std::is_enum_v<T>)&&!std::is_floating_point_v<T>,
                       int>>
T HeapObject::Relaxed_ReadField(size_t offset) const {
  // Pointer compression causes types larger than kTaggedSize to be
  // unaligned. Atomic loads must be aligned.
  DCHECK_IMPLIES(COMPRESS_POINTERS_BOOL, sizeof(T) <= kTaggedSize);
  using AtomicT = typename base::AtomicTypeFromByteWidth<sizeof(T)>::type;
  return static_cast<T>(base::AsAtomicImpl<AtomicT>::Relaxed_Load(
      reinterpret_cast<AtomicT*>(field_address(offset))));
}

template <class T, typename std::enable_if_t<
                       (std::is_arithmetic_v<T> ||
                        std::is_enum_v<T>)&&!std::is_floating_point_v<T>,
                       int>>
void HeapObject::Relaxed_WriteField(size_t offset, T value) {
  // Pointer compression causes types larger than kTaggedSize to be
  // unaligned. Atomic stores must be aligned.
  DCHECK_IMPLIES(COMPRESS_POINTERS_BOOL, sizeof(T) <= kTaggedSize);
  using AtomicT = typename base::AtomicTypeFromByteWidth<sizeof(T)>::type;
  base::AsAtomicImpl<AtomicT>::Relaxed_Store(
      reinterpret_cast<AtomicT*>(field_address(offset)),
      static_cast<AtomicT>(value));
}

template <class T, typename std::enable_if_t<
                       (std::is_arithmetic_v<T> ||
                        std::is_enum_v<T>)&&!std::is_floating_point_v<T>,
                       int>>
T HeapObject::Acquire_ReadField(size_t offset) const {
  // Pointer compression causes types larger than kTaggedSize to be
  // unaligned. Atomic loads must be aligned.
  DCHECK_IMPLIES(COMPRESS_POINTERS_BOOL, sizeof(T) <= kTaggedSize);
  using AtomicT = typename base::AtomicTypeFromByteWidth<sizeof(T)>::type;
  return static_cast<T>(base::AsAtomicImpl<AtomicT>::Acquire_Load(
      reinterpret_cast<AtomicT*>(field_address(offset))));
}

// static
template <typename CompareAndSwapImpl>
Tagged<Object> HeapObject::SeqCst_CompareAndSwapField(
    Tagged<Object> expected, Tagged<Object> value,
    CompareAndSwapImpl compare_and_swap_impl) {
  Tagged<Object> actual_expected = expected;
  do {
    Tagged<Object> old_value = compare_and_swap_impl(actual_expected, value);
    if (old_value == actual_expected || !IsNumber(old_value) ||
        !IsNumber(actual_expected)) {
      return old_value;
    }
    if (!Object::SameNumberValue(
            Object::NumberValue(Cast<Number>(old_value)),
            Object::NumberValue(Cast<Number>(actual_expected)))) {
      return old_value;
    }
    // The pointer comparison failed, but the numbers are equal. This can
    // happen even if both numbers are HeapNumbers with the same value.
    // Try again in the next iteration.
    actual_expected = old_value;
  } while (true);
}

constexpr bool FastInReadOnlySpaceOrSmallSmi(Tagged_t obj) {
#if V8_STATIC_ROOTS_BOOL
  // The following assert ensures that the page size check covers all our static
  // roots. This is not strictly necessary and can be relaxed in future as the
  // most prominent static roots are anyways allocated at the beginning of the
  // first page.
  static_assert(StaticReadOnlyRoot::kLastAllocatedRoot < kRegularPageSize);
  return obj < kRegularPageSize;
#else   // !V8_STATIC_ROOTS_BOOL
  return false;
#endif  // !V8_STATIC_ROOTS_BOOL
}

constexpr bool FastInReadOnlySpaceOrSmallSmi(Tagged<MaybeObject> obj) {
#ifdef V8_COMPRESS_POINTERS
  // This check is only valid for objects in the main cage.
  DCHECK(obj.IsSmi() || obj.IsInMainCageBase());
  return FastInReadOnlySpaceOrSmallSmi(
      V8HeapCompressionScheme::CompressAny(obj.ptr()));
#else   // V8_COMPRESS_POINTERS
  return false;
#endif  // V8_COMPRESS_POINTERS
}

bool OutsideSandboxOrInReadonlySpace(Tagged<HeapObject> obj) {
#ifdef V8_ENABLE_SANDBOX
  return !InsideSandbox(obj.address()) ||
         MemoryChunk::FromHeapObject(obj)->SandboxSafeInReadOnlySpace();
#else
  return true;
#endif
}

bool IsJSObjectThatCanBeTrackedAsPrototype(Tagged<HeapObject> obj) {
  // Do not optimize objects in the shared heap because it is not
  // threadsafe. Objects in the shared heap have fixed layouts and their maps
  // never change.
  return IsJSObject(obj) && !HeapLayout::InWritableSharedSpace(*obj);
}

bool IsJSApiWrapperObject(Tagged<Map> map) {
  const InstanceType instance_type = map->instance_type();
  return InstanceTypeChecker::IsJSAPIObjectWithEmbedderSlots(instance_type) ||
         InstanceTypeChecker::IsJSSpecialObject(instance_type);
}

bool IsJSApiWrapperObject(Tagged<HeapObject> js_obj) {
  return IsJSApiWrapperObject(js_obj->map());
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsUniqueName) {
  return IsInternalizedString(obj, cage_base) || IsSymbol(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsCallable) {
  return obj->map(cage_base)->is_callable();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsCallableJSProxy) {
  return IsCallable(obj, cage_base) && IsJSProxy(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsCallableApiObject) {
  InstanceType type = obj->map(cage_base)->instance_type();
  return IsCallable(obj, cage_base) &&
         (type == JS_API_OBJECT_TYPE || type == JS_SPECIAL_API_OBJECT_TYPE);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsNonNullForeign) {
  return IsForeign(obj, cage_base) &&
         Cast<Foreign>(obj)->foreign_address_unchecked() != kNullAddress;
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsConstructor) {
  return obj->map(cage_base)->is_constructor();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsSourceTextModuleInfo) {
  return obj->map(cage_base) == obj->GetReadOnlyRoots().module_info_map();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsConsString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsCons();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsThinString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsThin();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsSlicedString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsSliced();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsSeqString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsSequential();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsSeqOneByteString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsSequentialOneByte();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsSeqTwoByteString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsSequentialTwoByte();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsExternalOneByteString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsExternalOneByte();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsExternalTwoByteString) {
  if (!IsString(obj, cage_base)) return false;
  return StringShape(Cast<String>(obj)->map()).IsExternalTwoByte();
}

bool IsNumber(Tagged<Object> obj) {
  if (IsSmi(obj)) return true;
  Tagged<HeapObject> heap_object = Cast<HeapObject>(obj);
  PtrComprCageBase cage_base = GetPtrComprCageBase(heap_object);
  return IsHeapNumber(heap_object, cage_base);
}

bool IsNumber(Tagged<Object> obj, PtrComprCageBase cage_base) {
  return obj.IsSmi() || IsHeapNumber(obj, cage_base);
}

bool IsNumeric(Tagged<Object> obj) {
  if (IsSmi(obj)) return true;
  Tagged<HeapObject> heap_object = Cast<HeapObject>(obj);
  PtrComprCageBase cage_base = GetPtrComprCageBase(heap_object);
  return IsHeapNumber(heap_object, cage_base) ||
         IsBigInt(heap_object, cage_base);
}

bool IsNumeric(Tagged<Object> obj, PtrComprCageBase cage_base) {
  return IsNumber(obj, cage_base) || IsBigInt(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsTemplateLiteralObject) {
  return IsJSArray(obj, cage_base);
}

#if V8_INTL_SUPPORT
DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsJSSegmentDataObject) {
  return IsJSObject(obj, cage_base);
}
DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsJSSegmentDataObjectWithIsWordLike) {
  return IsJSObject(obj, cage_base);
}
#endif  // V8_INTL_SUPPORT

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsDeoptimizationData) {
  // Must be a (protected) fixed array.
  if (!IsProtectedFixedArray(obj, cage_base)) return false;

  // There's no sure way to detect the difference between a fixed array and
  // a deoptimization data array.  Since this is used for asserts we can
  // check that the length is zero or else the fixed size plus a multiple of
  // the entry size.
  int length = Cast<ProtectedFixedArray>(obj)->length();
  if (length == 0) return true;

  length -= DeoptimizationData::kFirstDeoptEntryIndex;
  return length >= 0 && length % DeoptimizationData::kDeoptEntrySize == 0;
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsHandlerTable) {
  return IsFixedArrayExact(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsDependentCode) {
  return IsWeakArrayList(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsOSROptimizedCodeCache) {
  return IsWeakFixedArray(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsStringWrapper) {
  return IsJSPrimitiveWrapper(obj, cage_base) &&
         IsString(Cast<JSPrimitiveWrapper>(obj)->value(), cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsBooleanWrapper) {
  return IsJSPrimitiveWrapper(obj, cage_base) &&
         IsBoolean(Cast<JSPrimitiveWrapper>(obj)->value(), cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsScriptWrapper) {
  return IsJSPrimitiveWrapper(obj, cage_base) &&
         IsScript(Cast<JSPrimitiveWrapper>(obj)->value(), cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsNumberWrapper) {
  return IsJSPrimitiveWrapper(obj, cage_base) &&
         IsNumber(Cast<JSPrimitiveWrapper>(obj)->value(), cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsBigIntWrapper) {
  return IsJSPrimitiveWrapper(obj, cage_base) &&
         IsBigInt(Cast<JSPrimitiveWrapper>(obj)->value(), cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsSymbolWrapper) {
  return IsJSPrimitiveWrapper(obj, cage_base) &&
         IsSymbol(Cast<JSPrimitiveWrapper>(obj)->value(), cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsStringSet) {
  return IsHashTable(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsObjectHashSet) {
  return IsHashTable(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsCompilationCacheTable) {
  return IsHashTable(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsMapCache) {
  return IsHashTable(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsObjectHashTable) {
  return IsHashTable(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsObjectTwoHashTable) {
  return IsHashTable(obj, cage_base);
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsHashTableBase) {
  return IsHashTable(obj, cage_base);
}

// static
bool IsPrimitive(Tagged<Object> obj) {
  if (obj.IsSmi()) return true;
  Tagged<HeapObject> this_heap_object = Cast<HeapObject>(obj);
  PtrComprCageBase cage_base = GetPtrComprCageBase(this_heap_object);
  return IsPrimitiveMap(this_heap_object->map(cage_base));
}

// static
bool IsPrimitive(Tagged<Object> obj, PtrComprCageBase cage_base) {
  return obj.IsSmi() || IsPrimitiveMap(Cast<HeapObject>(obj)->map(cage_base));
}

// static
Maybe<bool> Object::IsArray(Handle<Object> object) {
  if (IsSmi(*object)) return Just(false);
  auto heap_object = Cast<HeapObject>(object);
  if (IsJSArray(*heap_object)) return Just(true);
  if (!IsJSProxy(*heap_object)) return Just(false);
  return JSProxy::IsArray(Cast<JSProxy>(object));
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsUndetectable) {
  return obj->map(cage_base)->is_undetectable();
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsAccessCheckNeeded) {
  if (IsJSGlobalProxy(obj, cage_base)) {
    const Tagged<JSGlobalProxy> proxy = Cast<JSGlobalProxy>(obj);
    Tagged<JSGlobalObject> global =
        proxy->GetIsolate()->context()->global_object();
    return proxy->IsDetachedFrom(global);
  }
  return obj->map(cage_base)->is_access_check_needed();
}

#define MAKE_STRUCT_PREDICATE(NAME, Name, name)                             \
  bool Is##Name(Tagged<Object> obj) {                                       \
    return IsHeapObject(obj) && Is##Name(Cast<HeapObject>(obj));            \
  }                                                                         \
  bool Is##Name(Tagged<Object> obj, PtrComprCageBase cage_base) {           \
    return IsHeapObject(obj) && Is##Name(Cast<HeapObject>(obj), cage_base); \
  }                                                                         \
  bool Is##Name(HeapObject obj) {                                           \
    static_assert(kTaggedCanConvertToRawObjects);                           \
    return Is##Name(Tagged<HeapObject>(obj));                               \
  }                                                                         \
  bool Is##Name(HeapObject obj, PtrComprCageBase cage_base) {               \
    static_assert(kTaggedCanConvertToRawObjects);                           \
    return Is##Name(Tagged<HeapObject>(obj), cage_base);                    \
  }
// static
STRUCT_LIST(MAKE_STRUCT_PREDICATE)
#undef MAKE_STRUCT_PREDICATE

// static
double Object::NumberValue(Tagged<Number> obj) {
  DCHECK(IsNumber(obj));
  return IsSmi(obj) ? static_cast<double>(UncheckedCast<Smi>(obj).value())
                    : UncheckedCast<HeapNumber>(obj)->value();
}
// TODO(leszeks): Remove in favour of Tagged<Number>
// static
double Object::NumberValue(Tagged<Object> obj) {
  return NumberValue(Cast<Number>(obj));
}
double Object::NumberValue(Tagged<HeapNumber> obj) {
  return NumberValue(Cast<Number>(obj));
}
double Object::NumberValue(Tagged<Smi> obj) {
  return NumberValue(Cast<Number>(obj));
}

// static
bool Object::SameNumberValue(double value1, double value2) {
  // Compare values bitwise, to cover -0 being different from 0 -- we'd need to
  // look at sign bits anyway if we'd done a double comparison, so we may as
  // well compare bitwise immediately.
  uint64_t value1_bits = base::bit_cast<uint64_t>(value1);
  uint64_t value2_bits = base::bit_cast<uint64_t>(value2);
  if (value1_bits == value2_bits) {
    return true;
  }
  // SameNumberValue(NaN, NaN) is true even for NaNs with different bit
  // representations.
  return std::isnan(value1) && std::isnan(value2);
}

// static
bool IsNaN(Tagged<Object> obj) {
  return IsHeapNumber(obj) && std::isnan(Cast<HeapNumber>(obj)->value());
}

// static
bool IsMinusZero(Tagged<Object> obj) {
  return IsHeapNumber(obj) && i::IsMinusZero(Cast<HeapNumber>(obj)->value());
}

// static
bool Object::HasValidElements(Tagged<Object> obj) {
  // Dictionary is covered under FixedArray. ByteArray is used
  // for the JSTypedArray backing stores.
  return IsFixedArray(obj) || IsFixedDoubleArray(obj) || IsByteArray(obj);
}

// static
bool Object::FilterKey(Tagged<Object> obj, PropertyFilter filter) {
  DCHECK(!IsPropertyCell(obj));
  if (filter == PRIVATE_NAMES_ONLY) {
    if (!IsSymbol(obj)) return true;
    return !Cast<Symbol>(obj)->is_private_name();
  } else if (IsSymbol(obj)) {
    if (filter & SKIP_SYMBOLS) return true;

    if (Cast<Symbol>(obj)->is_private()) return true;
  } else {
    if (filter & SKIP_STRINGS) return true;
  }
  return false;
}

// static
Representation Object::OptimalRepresentation(Tagged<Object> obj,
                                             PtrComprCageBase cage_base) {
  if (IsSmi(obj)) {
    return Representation::Smi();
  }
  Tagged<HeapObject> heap_object = Cast<HeapObject>(obj);
  if (IsHeapNumber(heap_object, cage_base)) {
    return Representation::Double();
  } else if (IsUninitialized(heap_object,
                             heap_object->GetReadOnlyRoots(cage_base))) {
    return Representation::None();
  }
  return Representation::HeapObject();
}

// static
ElementsKind Object::OptimalElementsKind(Tagged<Object> obj,
                                         PtrComprCageBase cage_base) {
  if (IsSmi(obj)) return PACKED_SMI_ELEMENTS;
  if (IsNumber(obj, cage_base)) return PACKED_DOUBLE_ELEMENTS;
  return PACKED_ELEMENTS;
}

// static
bool Object::FitsRepresentation(Tagged<Object> obj,
                                Representation representation,
                                bool allow_coercion) {
  if (representation.IsSmi()) {
    return IsSmi(obj);
  } else if (representation.IsDouble()) {
    return allow_coercion ? IsNumber(obj) : IsHeapNumber(obj);
  } else if (representation.IsHeapObject()) {
    return IsHeapObject(obj);
  } else if (representation.IsNone()) {
    return false;
  }
  return true;
}

// static
bool Object::ToUint32(Tagged<Object> obj, uint32_t* value) {
  if (IsSmi(obj)) {
    int num = Smi::ToInt(obj);
    if (num < 0) return false;
    *value = static_cast<uint32_t>(num);
    return true;
  }
  if (IsHeapNumber(obj)) {
    double num = Cast<HeapNumber>(obj)->value();
    return DoubleToUint32IfEqualToSelf(num, value);
  }
  return false;
}

// static
MaybeHandle<JSReceiver> Object::ToObject(Isolate* isolate,
                                         Handle<Object> object,
                                         const char* method_name) {
  if (IsJSReceiver(*object)) return Cast<JSReceiver>(object);
  return ToObjectImpl(isolate, object, method_name);
}

// static
MaybeHandle<Name> Object::ToName(Isolate* isolate, Handle<Object> input) {
  if (IsName(*input)) return Cast<Name>(input);
  return ConvertToName(isolate, input);
}

// static
MaybeHandle<Object> Object::ToPropertyKey(Isolate* isolate,
                                          Handle<Object> value) {
  if (IsSmi(*value) || IsName(Cast<HeapObject>(*value))) return value;
  return ConvertToPropertyKey(isolate, value);
}

// static
MaybeHandle<Object> Object::ToPrimitive(Isolate* isolate, Handle<Object> input,
                                        ToPrimitiveHint hint) {
  if (IsPrimitive(*input)) return input;
  return JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(input), hint);
}

// static
MaybeHandle<Number> Object::ToNumber(Isolate* isolate, Handle<Object> input) {
  if (IsNumber(*input)) return Cast<Number>(input);  // Shortcut.
  return ConvertToNumber(isolate, input);
}

// static
MaybeHandle<Object> Object::ToNumeric(Isolate* isolate, Handle<Object> input) {
  if (IsNumber(*input) || IsBigInt(*input)) return input;  // Shortcut.
  return ConvertToNumeric(isolate, input);
}

// static
MaybeHandle<Number> Object::ToInteger(Isolate* isolate, Handle<Object> input) {
  if (IsSmi(*input)) return Cast<Smi>(input);
  return ConvertToInteger(isolate, input);
}

// static
MaybeHandle<Number> Object::ToInt32(Isolate* isolate, Handle<Object> input) {
  if (IsSmi(*input)) return Cast<Smi>(input);
  return ConvertToInt32(isolate, input);
}

// static
MaybeHandle<Number> Object::ToUint32(Isolate* isolate, Handle<Object> input) {
  if (IsSmi(*input)) {
    return handle(Smi::ToUint32Smi(Cast<Smi>(*input)), isolate);
  }
  return ConvertToUint32(isolate, input);
}

// static
template <typename T, typename>
MaybeHandle<String> Object::ToString(Isolate* isolate, Handle<T> input) {
  // T should be a subtype of Object, which is enforced by the second template
  // argument.
  if (IsString(*input)) return Cast<String>(input);
  return ConvertToString(isolate, input);
}

template <typename T, typename>
MaybeDirectHandle<String> Object::ToString(Isolate* isolate,
                                           DirectHandle<T> input) {
  if (IsString(*input)) return Cast<String>(input);
  return ConvertToString(isolate, indirect_handle(input, isolate));
}

// static
MaybeHandle<Object> Object::ToLength(Isolate* isolate, Handle<Object> input) {
  if (IsSmi(*input)) {
    int value = std::max(Smi::ToInt(*input), 0);
    return handle(Smi::FromInt(value), isolate);
  }
  return ConvertToLength(isolate, input);
}

// static
MaybeHandle<Object> Object::ToIndex(Isolate* isolate, Handle<Object> input,
                                    MessageTemplate error_index) {
  if (IsSmi(*input) && Smi::ToInt(*input) >= 0) return input;
  return ConvertToIndex(isolate, input, error_index);
}

MaybeHandle<Object> Object::GetProperty(Isolate* isolate, Handle<JSAny> object,
                                        Handle<Name> name) {
  LookupIterator it(isolate, object, name);
  if (!it.IsFound()) return it.factory()->undefined_value();
  return GetProperty(&it);
}

MaybeHandle<Object> Object::GetElement(Isolate* isolate, Handle<JSAny> object,
                                       uint32_t index) {
  LookupIterator it(isolate, object, index);
  if (!it.IsFound()) return it.factory()->undefined_value();
  return GetProperty(&it);
}

MaybeHandle<Object> Object::SetElement(Isolate* isolate, Handle<JSAny> object,
                                       uint32_t index, Handle<Object> value,
                                       ShouldThrow should_throw) {
  LookupIterator it(isolate, object, index);
  MAYBE_RETURN_NULL(
      SetProperty(&it, value, StoreOrigin::kMaybeKeyed, Just(should_throw)));
  return value;
}

Address HeapObject::ReadSandboxedPointerField(
    siz
"""


```