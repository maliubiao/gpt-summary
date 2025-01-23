Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Scan and Purpose Identification:**

   - The filename `instance-type-inl.h` immediately suggests it's related to the types of objects within V8. The `.inl` suffix signifies an inline header, meaning it contains function definitions meant to be included directly in other compilation units for potential performance benefits.
   - The copyright notice confirms it's a V8 project file.
   - The `#ifndef` guards are standard C++ header protection.
   - The includes provide hints: `<optional>`, `bounds.h`, `isolate-utils-inl.h`, `instance-type-checker.h`, `instance-type.h`, and especially `object-macros.h`. These point towards managing object types, memory layout, and potentially some metaprogramming.

2. **High-Level Structure Analysis:**

   - The code is organized within the `v8::internal` namespace.
   - There's a nested `InstanceTypeChecker` namespace, clearly indicating its purpose.
   - Within `InstanceTypeChecker`, there's another nested `InstanceTypeTraits`. This separation suggests a distinction between the core type checking logic and potentially some way to enumerate or categorize types.
   - The use of macros like `INSTANCE_TYPE_CHECKERS`, `UNIQUE_INSTANCE_TYPE_MAP_LIST_GENERATOR`, `INSTANCE_TYPE_CHECKERS_SINGLE`, and `INSTANCE_TYPE_CHECKERS_RANGE` is a strong signal of code generation or metaprogramming techniques being used.

3. **Key Functionality Identification - "What does it *do*?":**

   - **Type Checking:** The core purpose is clearly to determine the type of a V8 object. The functions named `IsSomething` (e.g., `IsHeapObject`, `IsString`, `IsJSReceiver`) are the primary evidence.
   - **Instance Types:** The inclusion of `instance-type.h` and the constant definitions (via macros) strongly suggest it defines and works with an enumeration or set of distinct object types within the V8 heap.
   - **Maps:**  The frequent mention of `Map` (e.g., `Tagged<Map>`, `UniqueMapOfInstanceTypeCheck`) indicates a connection between instance types and "maps." In V8, a `Map` is a hidden object associated with each object, describing its structure and properties.
   - **Optimization (Static Roots):** The `#if V8_STATIC_ROOTS_BOOL` sections point towards a conditional compilation feature likely related to performance. The use of `StaticReadOnlyRoot` suggests precomputed, immutable values used for faster lookups. The idea of "unique maps" and "unique map ranges" for instance types reinforces this optimization goal.
   - **Macros for Code Generation:** The repetitive patterns in the `INSTANCE_TYPE_CHECKER` and `INSTANCE_TYPE_CHECKER_RANGE` macros strongly indicate a desire to avoid writing similar code multiple times. These macros likely expand to generate the `IsSomething` functions for various instance types.

4. **Connecting to JavaScript:**

   - The core concept of object types in V8 directly relates to JavaScript's dynamic typing system. Every JavaScript object internally has a type.
   - Examples of JavaScript operations that rely on these internal type checks include:
     - `typeof`:  Determines the high-level type (e.g., "object", "string", "number").
     - `instanceof`: Checks if an object belongs to a particular class hierarchy.
     - Language operators (e.g., `+`, `.`):  Their behavior depends on the types of the operands.
     - Internal V8 optimizations: Knowing the precise type of an object allows for more efficient operations.

5. **Torque Connection:**

   - The presence of `TORQUE_INSTANCE_CHECKERS_MULTIPLE_FULLY_DEFINED` and `TORQUE_INSTANCE_CHECKERS_MULTIPLE_ONLY_DECLARED` strongly indicates that this header interacts with V8's Torque language. Torque is a domain-specific language used for writing optimized V8 built-in functions. If the file had a `.tq` extension, it *would* be a Torque source file. Since it's `.h`, it's likely being used *by* Torque-generated code.

6. **Code Logic and Assumptions:**

   - **`UniqueMapOfInstanceType`:** The logic here is to try and find a single, unique `Map` object associated with a given `InstanceType`. This allows for a very fast type check by comparing the object's map against this known value.
   - **`UniqueMapRangeOfInstanceTypeRange`:** This extends the unique map idea to ranges of instance types that share a contiguous block of `Map` objects in read-only memory. This enables checking a range of types efficiently.
   - **`MayHaveMapCheckFastCase`:** This function likely acts as a preliminary check to see if the fast-path (unique map or unique map range) optimization is applicable for a given instance type.
   - **`CheckInstanceMap` and `CheckInstanceMapRange`:** These are the core comparison functions used in the optimized type checks. They compare the compressed pointer of an object's map with the known unique map or range boundaries.

7. **Common Programming Errors:**

   - **Incorrect Type Assumptions:** Developers working with the V8 API or contributing to V8 might make assumptions about the type of an object without proper checking. This could lead to crashes or unexpected behavior. The `IsSomething` functions in this header are the correct way to perform these checks.
   - **Ignoring V8's Internal Types:**  Understanding V8's internal object model (including `Maps` and `InstanceTypes`) is crucial for writing efficient and correct code that interacts with V8 at a lower level. Failing to do so can lead to performance issues or subtle bugs.
   - **Misusing Type Checks:**  Using the wrong type checking function or performing checks at the wrong time can lead to errors. For instance, checking the `instance_type` directly might be faster in some cases, but checking the `Map` is often preferred due to the static roots optimization.

8. **Refinement and Organization:**

   - After the initial exploration, organize the findings into clear categories: Functionality, JavaScript relationship, Torque, Logic, and Errors.
   - Provide specific code examples where applicable (both C++ and JavaScript).
   - Use clear and concise language.

By following this thought process, combining static analysis of the code structure and naming conventions with knowledge of V8's architecture and JavaScript's behavior, we can effectively understand the purpose and functionality of this header file.
这个头文件 `v8/src/objects/instance-type-inl.h` 的主要功能是：**为 V8 引擎中的各种对象类型提供高效的类型检查机制。**  它定义了一系列的内联函数（inline functions），用于判断一个给定的实例类型（`InstanceType`）或者一个对象的 Map 是否属于特定的类型或类型范围。

下面是更详细的功能分解：

**1. 定义和使用 `InstanceType` 枚举：**

- 该文件依赖于 `src/objects/instance-type.h` 中定义的 `InstanceType` 枚举。这个枚举列举了 V8 引擎中所有可能的堆对象类型，例如 `JS_OBJECT_TYPE`，`STRING_TYPE`，`NUMBER_TYPE` 等。

**2. 提供快速的类型检查函数：**

- 文件中定义了大量的内联函数，以 `Is` 开头，例如 `IsString(InstanceType)`，`IsJSObject(InstanceType)`，`IsNumber(Tagged<Map>)` 等。
- 这些函数用于判断一个给定的 `InstanceType` 或者一个对象的 `Map` 是否属于特定的类型。
- 为了提高性能，特别是当启用了静态根（`V8_STATIC_ROOTS_BOOL`）时，这些函数会尝试直接比较对象的 `Map` 指针与预先计算好的静态根值或范围。这避免了每次都去读取 `Map` 中的 `instance_type` 字段，从而加快了类型检查速度。

**3. 利用 `Map` 对象进行优化：**

- V8 中的每个堆对象都有一个关联的 `Map` 对象，它描述了对象的结构和类型。
- 该文件中的一些类型检查函数接受 `Tagged<Map>` 作为参数，允许基于 `Map` 对象进行类型判断。
- 当启用了静态根时，对于某些具有唯一 `Map` 或 `Map` 范围的类型，可以直接比较 `Map` 的地址，实现极快的类型检查。

**4. 支持类型范围检查：**

- 除了检查单个类型，该文件还提供了一些机制来检查类型是否在一个给定的范围内，例如 `IsString` 函数可以判断一个 `InstanceType` 是否属于所有字符串类型。

**5. 辅助宏定义：**

- 该文件使用了大量的宏 (`INSTANCE_TYPE_CHECKERS`, `INSTANCE_TYPE_CHECKER1`, `INSTANCE_TYPE_CHECKER_RANGE2` 等) 来简化类型检查函数的定义。这些宏会根据预定义的类型列表自动生成相应的 `Is` 函数。

**如果 `v8/src/objects/instance-type-inl.h` 以 `.tq` 结尾：**

- 如果该文件以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码文件**。
- **Torque** 是 V8 开发的一种领域特定语言，用于编写高性能的运行时代码，特别是内置函数（built-ins）。
- 在 Torque 文件中，你可以使用类似 C++ 的语法来定义函数和数据结构，但 Torque 编译器会将这些代码转换成更底层的 V8 代码，并进行优化。
- 如果该文件是 Torque 文件，它仍然会执行类似的功能：提供类型检查，但实现方式和使用场景可能会更偏向于 V8 内部的实现细节。

**与 JavaScript 功能的关系：**

这个头文件中的代码直接支撑着 JavaScript 的类型系统。在 JavaScript 运行时，V8 需要频繁地检查对象的类型以执行正确的操作。以下是一些与 JavaScript 功能相关的示例：

**示例 1: `typeof` 运算符**

```javascript
const str = "hello";
const num = 123;
const obj = {};

console.log(typeof str); // "string"
console.log(typeof num); // "number"
console.log(typeof obj); // "object"
```

在 V8 内部实现 `typeof` 运算符时，会使用类似于 `IsString`、`IsNumber`、`IsJSObject` 这样的函数来判断 JavaScript 值的类型，最终返回相应的字符串。

**示例 2: 运算符的行为**

```javascript
const a = 5;
const b = "10";
const c = a + b; // "510" (字符串拼接)

const d = 5;
const e = 10;
const f = d + e; // 15 (数字加法)
```

当执行加法运算符 `+` 时，V8 需要检查操作数的类型。如果一个是数字，另一个是字符串，则会执行字符串拼接。如果两个都是数字，则执行数字加法。`instance-type-inl.h` 中定义的类型检查函数就是用来完成这种类型判断的关键。

**示例 3: `instanceof` 运算符**

```javascript
class MyClass {}
const obj = new MyClass();

console.log(obj instanceof MyClass); // true
console.log(obj instanceof Object);  // true
```

`instanceof` 运算符检查一个对象是否是某个构造函数的实例。在 V8 的实现中，需要遍历对象的原型链，并检查原型链上的对象类型。这也会涉及到使用 `instance-type-inl.h` 中定义的类型检查函数。

**代码逻辑推理示例（假设输入与输出）：**

**假设输入：** 一个 `InstanceType` 枚举值 `STRING_TYPE`。

**代码片段：**

```c++
V8_INLINE constexpr bool IsString(InstanceType instance_type) {
  return (instance_type & kIsNotStringMask) == 0;
}
```

**推理：**

- `kIsNotStringMask` 是一个位掩码，用于判断一个 `InstanceType` 是否不是字符串类型。
- 如果 `instance_type` 与 `kIsNotStringMask` 进行按位与运算的结果为 0，则说明 `instance_type` 中表示“不是字符串”的位没有被设置，因此该 `instance_type` 是一个字符串类型。

**输出：**

- 如果输入是 `STRING_TYPE`，则 `IsString(STRING_TYPE)` 返回 `true`。
- 如果输入是 `NUMBER_TYPE`，则 `IsString(NUMBER_TYPE)` 返回 `false`。

**用户常见的编程错误示例：**

**错误示例 1：不进行类型检查就执行特定操作**

```javascript
function processValue(value) {
  // 假设 value 是一个字符串，直接使用字符串方法
  console.log(value.toUpperCase());
}

processValue("hello"); // 正常工作
processValue(123);     // 运行时错误：value.toUpperCase is not a function
```

**说明：**  用户没有检查 `value` 的类型就直接调用字符串方法 `toUpperCase()`。如果 `value` 不是字符串，就会抛出运行时错误。V8 内部会使用类似 `IsString` 的函数来避免这种错误，但在 JavaScript 代码中，开发者需要显式地进行类型检查或使用类型安全的编程方式。

**错误示例 2：错误地假设对象的类型**

```javascript
function processObject(obj) {
  // 假设 obj 是一个具有 'name' 属性的对象
  console.log(obj.name.toUpperCase());
}

processObject({ name: "Alice" }); // 正常工作
processObject({ id: 1 });        // 运行时错误：Cannot read properties of undefined (reading 'toUpperCase')
```

**说明：** 用户假设 `obj` 总是具有 `name` 属性，但实际上并非如此。V8 内部的类型系统确保对象的结构符合其类型定义，但 JavaScript 的动态性允许对象在运行时具有不同的属性。

总之，`v8/src/objects/instance-type-inl.h` 是 V8 引擎中一个非常核心的文件，它定义了高效的对象类型检查机制，这是支撑 JavaScript 语言运行时行为的关键基础设施。它通过内联函数和优化的 `Map` 比较，实现了快速的类型判断，避免了常见的编程错误，并直接影响着 JavaScript 代码的执行效率。

### 提示词
```
这是目录为v8/src/objects/instance-type-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/instance-type-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_INSTANCE_TYPE_INL_H_
#define V8_OBJECTS_INSTANCE_TYPE_INL_H_

#include <optional>

#include "src/base/bounds.h"
#include "src/execution/isolate-utils-inl.h"
#include "src/objects/instance-type-checker.h"
#include "src/objects/instance-type.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

namespace InstanceTypeChecker {

// INSTANCE_TYPE_CHECKERS macro defines some "types" that do not have
// respective C++ classes (see TypedArrayConstructor, FixedArrayExact) or
// the respective C++ counterpart is actually a template (see HashTable).
// So in order to be able to customize IsType() implementations for specific
// types, we declare a parallel set of "types" that can be compared using
// std::is_same<>.
namespace InstanceTypeTraits {

#define DECL_TYPE(type, ...) class type;
INSTANCE_TYPE_CHECKERS(DECL_TYPE)
TORQUE_INSTANCE_CHECKERS_MULTIPLE_FULLY_DEFINED(DECL_TYPE)
TORQUE_INSTANCE_CHECKERS_MULTIPLE_ONLY_DECLARED(DECL_TYPE)
HEAP_OBJECT_TYPE_LIST(DECL_TYPE)
#undef DECL_TYPE

}  // namespace InstanceTypeTraits

// Instance types which are associated with one unique map.

template <class type>
V8_INLINE constexpr std::optional<RootIndex> UniqueMapOfInstanceTypeCheck() {
  return {};
}

#define INSTANCE_TYPE_MAP(V, rootIndexName, rootAccessorName, class_name) \
  template <>                                                             \
  V8_INLINE constexpr std::optional<RootIndex>                            \
  UniqueMapOfInstanceTypeCheck<InstanceTypeTraits::class_name>() {        \
    return {RootIndex::k##rootIndexName};                                 \
  }
UNIQUE_INSTANCE_TYPE_MAP_LIST_GENERATOR(INSTANCE_TYPE_MAP, _)
#undef INSTANCE_TYPE_MAP

V8_INLINE constexpr std::optional<RootIndex> UniqueMapOfInstanceType(
    InstanceType type) {
#define INSTANCE_TYPE_CHECK(it, forinstancetype)              \
  if (type == forinstancetype) {                              \
    return InstanceTypeChecker::UniqueMapOfInstanceTypeCheck< \
        InstanceTypeChecker::InstanceTypeTraits::it>();       \
  }
  INSTANCE_TYPE_CHECKERS_SINGLE(INSTANCE_TYPE_CHECK);
#undef INSTANCE_TYPE_CHECK

  return Map::TryGetMapRootIdxFor(type);
}

template <InstanceType type>
constexpr bool kHasUniqueMapOfInstanceType =
    UniqueMapOfInstanceType(type).has_value();

template <InstanceType type>
constexpr RootIndex kUniqueMapOfInstanceType =
    kHasUniqueMapOfInstanceType<type> ? *UniqueMapOfInstanceType(type)
                                      : RootIndex::kRootListLength;

// Manually curated list of instance type ranges which are associated with a
// unique range of map addresses on the read only heap. Both ranges are
// inclusive.

using InstanceTypeRange = std::pair<InstanceType, InstanceType>;
using TaggedAddressRange = std::pair<Tagged_t, Tagged_t>;

#if V8_STATIC_ROOTS_BOOL
constexpr std::array<std::pair<InstanceTypeRange, TaggedAddressRange>, 9>
    kUniqueMapRangeOfInstanceTypeRangeList = {
        {{{ALLOCATION_SITE_TYPE, ALLOCATION_SITE_TYPE},
          {StaticReadOnlyRoot::kAllocationSiteWithWeakNextMap,
           StaticReadOnlyRoot::kAllocationSiteWithoutWeakNextMap}},
         {{FIRST_STRING_TYPE, LAST_STRING_TYPE},
          {InstanceTypeChecker::kStringMapLowerBound,
           InstanceTypeChecker::kStringMapUpperBound}},
         {{FIRST_NAME_TYPE, LAST_NAME_TYPE},
          {StaticReadOnlyRoot::kSeqTwoByteStringMap,
           StaticReadOnlyRoot::kSymbolMap}},
         {{ODDBALL_TYPE, ODDBALL_TYPE},
          {StaticReadOnlyRoot::kUndefinedMap, StaticReadOnlyRoot::kBooleanMap}},
         {{HEAP_NUMBER_TYPE, ODDBALL_TYPE},
          {StaticReadOnlyRoot::kUndefinedMap,
           StaticReadOnlyRoot::kHeapNumberMap}},
         {{BIGINT_TYPE, HEAP_NUMBER_TYPE},
          {StaticReadOnlyRoot::kHeapNumberMap, StaticReadOnlyRoot::kBigIntMap}},
         {{FIRST_SMALL_ORDERED_HASH_TABLE_TYPE,
           LAST_SMALL_ORDERED_HASH_TABLE_TYPE},
          {StaticReadOnlyRoot::kSmallOrderedHashMapMap,
           StaticReadOnlyRoot::kSmallOrderedNameDictionaryMap}},
         {{FIRST_ABSTRACT_INTERNAL_CLASS_TYPE,
           LAST_ABSTRACT_INTERNAL_CLASS_TYPE},
          {StaticReadOnlyRoot::kAbstractInternalClassSubclass1Map,
           StaticReadOnlyRoot::kAbstractInternalClassSubclass2Map}},
         {{FIRST_TURBOFAN_TYPE_TYPE, LAST_TURBOFAN_TYPE_TYPE},
          {StaticReadOnlyRoot::kTurbofanBitsetTypeMap,
           StaticReadOnlyRoot::kTurbofanOtherNumberConstantTypeMap}}}};

struct kUniqueMapRangeOfStringType {
  static constexpr TaggedAddressRange kSeqString = {
      InstanceTypeChecker::kStringMapLowerBound,
      StaticReadOnlyRoot::kInternalizedOneByteStringMap};
  static constexpr TaggedAddressRange kInternalizedString = {
      StaticReadOnlyRoot::kInternalizedTwoByteStringMap,
      StaticReadOnlyRoot::kUncachedExternalInternalizedOneByteStringMap};
  static constexpr TaggedAddressRange kExternalString = {
      StaticReadOnlyRoot::kExternalInternalizedTwoByteStringMap,
      StaticReadOnlyRoot::kSharedExternalOneByteStringMap};
  static constexpr TaggedAddressRange kUncachedExternalString = {
      StaticReadOnlyRoot::kUncachedExternalInternalizedTwoByteStringMap,
      StaticReadOnlyRoot::kSharedUncachedExternalOneByteStringMap};
  static constexpr TaggedAddressRange kConsString = {
      StaticReadOnlyRoot::kConsTwoByteStringMap,
      StaticReadOnlyRoot::kConsOneByteStringMap};
  static constexpr TaggedAddressRange kSlicedString = {
      StaticReadOnlyRoot::kSlicedTwoByteStringMap,
      StaticReadOnlyRoot::kSlicedOneByteStringMap};
  static constexpr TaggedAddressRange kThinString = {
      StaticReadOnlyRoot::kThinTwoByteStringMap,
      StaticReadOnlyRoot::kThinOneByteStringMap};
};

// This one is very sneaky. String maps are laid out sequentially, and
// alternate between two-byte and one-byte. Since they're sequential, each
// address is one Map::kSize larger than the previous. This means that the LSB
// of the map size alternates being set and unset for alternating string map
// addresses, and therefore is on/off for all two-byte/one-byte strings. Which
// of the two has the on-bit depends on the current RO heap layout, so just
// sniff this by checking an arbitrary one-byte map's value.
static constexpr int kStringMapEncodingMask =
    1 << base::bits::CountTrailingZerosNonZero(Map::kSize);
static constexpr int kOneByteStringMapBit =
    StaticReadOnlyRoot::kSeqOneByteStringMap & kStringMapEncodingMask;
static constexpr int kTwoByteStringMapBit =
    StaticReadOnlyRoot::kSeqTwoByteStringMap & kStringMapEncodingMask;

inline constexpr std::optional<TaggedAddressRange>
UniqueMapRangeOfInstanceTypeRange(InstanceType first, InstanceType last) {
  // Doesn't use range based for loop due to LLVM <11 bug re. constexpr
  // functions.
  for (size_t i = 0; i < kUniqueMapRangeOfInstanceTypeRangeList.size(); ++i) {
    if (kUniqueMapRangeOfInstanceTypeRangeList[i].first.first == first &&
        kUniqueMapRangeOfInstanceTypeRangeList[i].first.second == last) {
      return {kUniqueMapRangeOfInstanceTypeRangeList[i].second};
    }
  }
  return {};
}

constexpr inline TaggedAddressRange NULL_ADDRESS_RANGE{kNullAddress,
                                                       kNullAddress};

template <InstanceType first, InstanceType last>
constexpr bool kHasUniqueMapRangeOfInstanceTypeRange =
    UniqueMapRangeOfInstanceTypeRange(first, last).has_value();

template <InstanceType first, InstanceType last>
constexpr TaggedAddressRange kUniqueMapRangeOfInstanceTypeRange =
    kHasUniqueMapRangeOfInstanceTypeRange<first, last>
        ? *UniqueMapRangeOfInstanceTypeRange(first, last)
        : NULL_ADDRESS_RANGE;

inline constexpr std::optional<TaggedAddressRange> UniqueMapRangeOfInstanceType(
    InstanceType type) {
  return UniqueMapRangeOfInstanceTypeRange(type, type);
}

template <InstanceType type>
constexpr bool kHasUniqueMapRangeOfInstanceType =
    UniqueMapRangeOfInstanceType(type).has_value();

template <InstanceType type>
constexpr TaggedAddressRange kUniqueMapRangeOfInstanceType =
    kHasUniqueMapRangeOfInstanceType<type> ? *UniqueMapRangeOfInstanceType(type)
                                           : NULL_ADDRESS_RANGE;

inline bool MayHaveMapCheckFastCase(InstanceType type) {
  if (UniqueMapOfInstanceType(type)) return true;
  for (auto& el : kUniqueMapRangeOfInstanceTypeRangeList) {
    if (el.first.first <= type && type <= el.first.second) {
      return true;
    }
  }
  return false;
}

inline bool CheckInstanceMap(RootIndex expected, Tagged<Map> map) {
  return V8HeapCompressionScheme::CompressObject(map.ptr()) ==
         StaticReadOnlyRootsPointerTable[static_cast<size_t>(expected)];
}

inline bool CheckInstanceMapRange(TaggedAddressRange expected,
                                  Tagged<Map> map) {
  Tagged_t ptr = V8HeapCompressionScheme::CompressObject(map.ptr());
  return base::IsInRange(ptr, expected.first, expected.second);
}

#else

inline bool MayHaveMapCheckFastCase(InstanceType type) { return false; }

#endif  // V8_STATIC_ROOTS_BOOL

// Define type checkers for classes with single instance type.
// INSTANCE_TYPE_CHECKER1 is to be used if the instance type is already loaded.
// INSTANCE_TYPE_CHECKER2 is preferred since it can sometimes avoid loading the
// instance type from the map, if the checked instance type corresponds to a
// known map or range of maps.

#define INSTANCE_TYPE_CHECKER1(type, forinstancetype)             \
  V8_INLINE constexpr bool Is##type(InstanceType instance_type) { \
    return instance_type == forinstancetype;                      \
  }

#if V8_STATIC_ROOTS_BOOL

#define INSTANCE_TYPE_CHECKER2(type, forinstancetype_)                   \
  V8_INLINE bool Is##type(Tagged<Map> map_object) {                      \
    constexpr InstanceType forinstancetype =                             \
        static_cast<InstanceType>(forinstancetype_);                     \
    if constexpr (kHasUniqueMapOfInstanceType<forinstancetype>) {        \
      return CheckInstanceMap(kUniqueMapOfInstanceType<forinstancetype>, \
                              map_object);                               \
    }                                                                    \
    if constexpr (kHasUniqueMapRangeOfInstanceType<forinstancetype>) {   \
      return CheckInstanceMapRange(                                      \
          kUniqueMapRangeOfInstanceType<forinstancetype>, map_object);   \
    }                                                                    \
    return Is##type(map_object->instance_type());                        \
  }

#else

#define INSTANCE_TYPE_CHECKER2(type, forinstancetype) \
  V8_INLINE bool Is##type(Tagged<Map> map_object) {   \
    return Is##type(map_object->instance_type());     \
  }

#endif  // V8_STATIC_ROOTS_BOOL

INSTANCE_TYPE_CHECKERS_SINGLE(INSTANCE_TYPE_CHECKER1)
INSTANCE_TYPE_CHECKERS_SINGLE(INSTANCE_TYPE_CHECKER2)
#undef INSTANCE_TYPE_CHECKER1
#undef INSTANCE_TYPE_CHECKER2

// Checks if value is in range [lower_limit, higher_limit] using a single
// branch. Assumes that the input instance type is valid.
template <InstanceType lower_limit, InstanceType upper_limit>
struct InstanceRangeChecker {
  static constexpr bool Check(InstanceType value) {
    return base::IsInRange(value, lower_limit, upper_limit);
  }
};
template <InstanceType upper_limit>
struct InstanceRangeChecker<FIRST_TYPE, upper_limit> {
  static constexpr bool Check(InstanceType value) {
    DCHECK_LE(FIRST_TYPE, value);
    return value <= upper_limit;
  }
};
template <InstanceType lower_limit>
struct InstanceRangeChecker<lower_limit, LAST_TYPE> {
  static constexpr bool Check(InstanceType value) {
    DCHECK_GE(LAST_TYPE, value);
    return value >= lower_limit;
  }
};

// Define type checkers for classes with ranges of instance types.
// INSTANCE_TYPE_CHECKER_RANGE1 is to be used if the instance type is already
// loaded. INSTANCE_TYPE_CHECKER_RANGE2 is preferred since it can sometimes
// avoid loading the instance type from the map, if the checked instance type
// range corresponds to a known range of maps.

#define INSTANCE_TYPE_CHECKER_RANGE1(type, first_instance_type,            \
                                     last_instance_type)                   \
  V8_INLINE constexpr bool Is##type(InstanceType instance_type) {          \
    return InstanceRangeChecker<first_instance_type,                       \
                                last_instance_type>::Check(instance_type); \
  }

#if V8_STATIC_ROOTS_BOOL

#define INSTANCE_TYPE_CHECKER_RANGE2(type, first_instance_type,                \
                                     last_instance_type)                       \
  V8_INLINE bool Is##type(Tagged<Map> map_object) {                            \
    if constexpr (kHasUniqueMapRangeOfInstanceTypeRange<first_instance_type,   \
                                                        last_instance_type>) { \
      return CheckInstanceMapRange(                                            \
          kUniqueMapRangeOfInstanceTypeRange<first_instance_type,              \
                                             last_instance_type>,              \
          map_object);                                                         \
    }                                                                          \
    return Is##type(map_object->instance_type());                              \
  }

#else

#define INSTANCE_TYPE_CHECKER_RANGE2(type, first_instance_type, \
                                     last_instance_type)        \
  V8_INLINE bool Is##type(Tagged<Map> map_object) {             \
    return Is##type(map_object->instance_type());               \
  }

#endif  // V8_STATIC_ROOTS_BOOL

INSTANCE_TYPE_CHECKERS_RANGE(INSTANCE_TYPE_CHECKER_RANGE1)
INSTANCE_TYPE_CHECKERS_RANGE(INSTANCE_TYPE_CHECKER_RANGE2)
#undef INSTANCE_TYPE_CHECKER_RANGE1
#undef INSTANCE_TYPE_CHECKER_RANGE2

V8_INLINE constexpr bool IsHeapObject(InstanceType instance_type) {
  return true;
}

V8_INLINE constexpr bool IsInternalizedString(InstanceType instance_type) {
  static_assert(kNotInternalizedTag != 0);
  return (instance_type & (kIsNotStringMask | kIsNotInternalizedMask)) ==
         (kStringTag | kInternalizedTag);
}

V8_INLINE bool IsInternalizedString(Tagged<Map> map_object) {
#if V8_STATIC_ROOTS_BOOL
  return CheckInstanceMapRange(kUniqueMapRangeOfStringType::kInternalizedString,
                               map_object);
#else
  return IsInternalizedString(map_object->instance_type());
#endif
}

V8_INLINE constexpr bool IsSeqString(InstanceType instance_type) {
  return (instance_type & (kIsNotStringMask | kStringRepresentationMask)) ==
         kSeqStringTag;
}

V8_INLINE bool IsSeqString(Tagged<Map> map_object) {
#if V8_STATIC_ROOTS_BOOL
  return CheckInstanceMapRange(kUniqueMapRangeOfStringType::kSeqString,
                               map_object);
#else
  return IsSeqString(map_object->instance_type());
#endif
}

V8_INLINE constexpr bool IsExternalString(InstanceType instance_type) {
  return (instance_type & (kIsNotStringMask | kStringRepresentationMask)) ==
         kExternalStringTag;
}

V8_INLINE bool IsExternalString(Tagged<Map> map_object) {
#if V8_STATIC_ROOTS_BOOL
  return CheckInstanceMapRange(kUniqueMapRangeOfStringType::kExternalString,
                               map_object);
#else
  return IsExternalString(map_object->instance_type());
#endif
}

V8_INLINE constexpr bool IsUncachedExternalString(InstanceType instance_type) {
  return (instance_type & (kIsNotStringMask | kUncachedExternalStringMask |
                           kStringRepresentationMask)) ==
         (kExternalStringTag | kUncachedExternalStringTag);
}

V8_INLINE bool IsUncachedExternalString(Tagged<Map> map_object) {
#if V8_STATIC_ROOTS_BOOL
  return CheckInstanceMapRange(
      kUniqueMapRangeOfStringType::kUncachedExternalString, map_object);
#else
  return IsUncachedExternalString(map_object->instance_type());
#endif
}

V8_INLINE constexpr bool IsConsString(InstanceType instance_type) {
  return (instance_type & kStringRepresentationMask) == kConsStringTag;
}

V8_INLINE bool IsConsString(Tagged<Map> map_object) {
#if V8_STATIC_ROOTS_BOOL
  return CheckInstanceMapRange(kUniqueMapRangeOfStringType::kConsString,
                               map_object);
#else
  return IsConsString(map_object->instance_type());
#endif
}

V8_INLINE constexpr bool IsSlicedString(InstanceType instance_type) {
  return (instance_type & kStringRepresentationMask) == kSlicedStringTag;
}

V8_INLINE bool IsSlicedString(Tagged<Map> map_object) {
#if V8_STATIC_ROOTS_BOOL
  return CheckInstanceMapRange(kUniqueMapRangeOfStringType::kSlicedString,
                               map_object);
#else
  return IsSlicedString(map_object->instance_type());
#endif
}

V8_INLINE constexpr bool IsThinString(InstanceType instance_type) {
  return (instance_type & kStringRepresentationMask) == kThinStringTag;
}

V8_INLINE bool IsThinString(Tagged<Map> map_object) {
#if V8_STATIC_ROOTS_BOOL
  return CheckInstanceMapRange(kUniqueMapRangeOfStringType::kThinString,
                               map_object);
#else
  return IsThinString(map_object->instance_type());
#endif
}

V8_INLINE constexpr bool IsOneByteString(InstanceType instance_type) {
  DCHECK(IsString(instance_type));
  return (instance_type & kStringEncodingMask) == kOneByteStringTag;
}

V8_INLINE bool IsOneByteString(Tagged<Map> map_object) {
#if V8_STATIC_ROOTS_BOOL
  DCHECK(IsStringMap(map_object));

  Tagged_t ptr = V8HeapCompressionScheme::CompressObject(map_object.ptr());
  return (ptr & kStringMapEncodingMask) == kOneByteStringMapBit;
#else
  return IsOneByteString(map_object->instance_type());
#endif
}

V8_INLINE constexpr bool IsTwoByteString(InstanceType instance_type) {
  DCHECK(IsString(instance_type));
  return (instance_type & kStringEncodingMask) == kTwoByteStringTag;
}

V8_INLINE bool IsTwoByteString(Tagged<Map> map_object) {
#if V8_STATIC_ROOTS_BOOL
  DCHECK(IsStringMap(map_object));

  Tagged_t ptr = V8HeapCompressionScheme::CompressObject(map_object.ptr());
  return (ptr & kStringMapEncodingMask) == kTwoByteStringMapBit;
#else
  return IsTwoByteString(map_object->instance_type());
#endif
}

V8_INLINE constexpr bool IsReferenceComparable(InstanceType instance_type) {
  return !IsString(instance_type) && !IsBigInt(instance_type) &&
         instance_type != HEAP_NUMBER_TYPE;
}

V8_INLINE constexpr bool IsGcSafeCode(InstanceType instance_type) {
  return IsCode(instance_type);
}

V8_INLINE bool IsGcSafeCode(Tagged<Map> map_object) {
  return IsCode(map_object);
}

V8_INLINE constexpr bool IsAbstractCode(InstanceType instance_type) {
  return IsBytecodeArray(instance_type) || IsCode(instance_type);
}

V8_INLINE bool IsAbstractCode(Tagged<Map> map_object) {
  return IsAbstractCode(map_object->instance_type());
}

V8_INLINE constexpr bool IsFreeSpaceOrFiller(InstanceType instance_type) {
  return instance_type == FREE_SPACE_TYPE || instance_type == FILLER_TYPE;
}

V8_INLINE bool IsFreeSpaceOrFiller(Tagged<Map> map_object) {
  return IsFreeSpaceOrFiller(map_object->instance_type());
}

V8_INLINE constexpr bool IsPropertyDictionary(InstanceType instance_type) {
  return instance_type == PROPERTY_DICTIONARY_TYPE;
}

V8_INLINE bool IsPropertyDictionary(Tagged<Map> map_object) {
  return IsPropertyDictionary(map_object->instance_type());
}

// Returns true for those heap object types that must be tied to some native
// context.
V8_INLINE constexpr bool IsNativeContextSpecific(InstanceType instance_type) {
  // All context map are tied to some native context.
  if (IsContext(instance_type)) return true;
  // All non-JSReceivers are never tied to any native context.
  if (!IsJSReceiver(instance_type)) return false;

  // Most of the JSReceivers are tied to some native context modulo the
  // following exceptions.
  if (instance_type == JS_MESSAGE_OBJECT_TYPE ||
      instance_type == JS_EXTERNAL_OBJECT_TYPE) {
    // These JSObject types are wrappers around a set of primitive values
    // and exist only for the purpose of passing the data across V8 Api.
    // Thus they are not tied to any native context.
    return false;

  } else if (InstanceTypeChecker::IsAlwaysSharedSpaceJSObject(instance_type)) {
    // JSObjects allocated in shared space are never tied to a native context.
    return false;
  }
  return true;
}

V8_INLINE bool IsNativeContextSpecificMap(Tagged<Map> map_object) {
  return IsNativeContextSpecific(map_object->instance_type());
}

}  // namespace InstanceTypeChecker

#define TYPE_CHECKER(type, ...)                \
  bool Is##type##Map(Tagged<Map> map) {        \
    return InstanceTypeChecker::Is##type(map); \
  }

INSTANCE_TYPE_CHECKERS(TYPE_CHECKER)
#undef TYPE_CHECKER

}  // namespace v8::internal

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_INSTANCE_TYPE_INL_H_
```