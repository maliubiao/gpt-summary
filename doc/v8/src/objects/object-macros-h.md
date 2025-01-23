Response:
My thinking process to analyze the provided C++ header file (`object-macros.h`) and answer the user's request goes like this:

1. **Understand the Core Request:** The user wants to know the functionality of this header file within the V8 JavaScript engine. They also have specific questions about file extensions, JavaScript relevance, logical reasoning, common errors, and a final summarization.

2. **Initial Skim and Keyword Spotting:** I quickly read through the code, looking for repeating patterns, keywords, and familiar concepts related to object-oriented programming and low-level memory management. Keywords like `V8_OBJECT`, `ACCESSORS`, `FIELD_OFFSET`, `READ_FIELD`, `WRITE_FIELD`, `RelaxedLoadTag`, `AcquireLoadTag`, `ReleaseStoreTag`, `WriteBarrierMode`, and pragmas for packing stand out.

3. **Identify the Primary Purpose:** The frequent use of `V8_OBJECT` and related macros (`V8_OBJECT_PUSH`, `V8_OBJECT_POP`, `V8_OBJECT_END`) immediately suggests this file is about *defining the structure and layout of V8 objects in memory*. The pragmas confirm this, as they are used to control how compilers arrange data within structures to minimize padding and ensure specific alignment.

4. **Analyze Key Macro Groups:** I start to categorize the different groups of macros and understand their individual roles:

    * **Object Definition Macros (`V8_OBJECT`, `V8_OBJECT_END`, etc.):**  These are clearly for marking the beginning and end of object definitions and handling compiler-specific alignment and padding settings.
    * **Constructor Macros (`OBJECT_CONSTRUCTORS`, `OBJECT_CONSTRUCTORS_IMPL`):**  These define constructors, including a special one for `constexpr` and another taking an `Address` (likely for low-level memory manipulation). The `operator->` overload is interesting, suggesting a smooth transition between object types and their tagged pointer representations.
    * **Read-Only Space Macros (`NEVER_READ_ONLY_SPACE`, `NEVER_READ_ONLY_SPACE_IMPL`):** These are constraints on where certain objects can be allocated in memory, preventing them from residing in read-only regions.
    * **Primitive Accessor Macros (`DECL_PRIMITIVE_GETTER`, `DECL_PRIMITIVE_SETTER`, etc.):** These define convenient inline functions to get and set simple data types (booleans, integers, etc.) within the objects.
    * **General Accessor Macros (`DECL_GETTER`, `DEF_GETTER`, `DECL_SETTER`, `DECL_ACCESSORS`, etc.):**  These are more general mechanisms for accessing object members, potentially handling tagged pointers (`Tagged<Type>`) and memory barriers for thread safety. The variations with `RELAXED_`, `ACQUIRE_`, and `RELEASE_` prefixes clearly indicate support for concurrent access.
    * **Field Offset Macros (`DECL_FIELD_OFFSET_TQ`):** These define constants for the memory offsets of specific fields within objects. The `TQ_FIELD_TYPE` suggests potential integration with Torque.
    * **Bit Field Accessor Macros (`BIT_FIELD_ACCESSORS2`):** These are for accessing individual bits or groups of bits within larger integer fields.
    * **Pointer Accessor Macros (`DECL_EXTERNAL_POINTER_ACCESSORS`, `TRUSTED_POINTER_ACCESSORS`, `PROTECTED_POINTER_ACCESSORS`, `CODE_POINTER_ACCESSORS`):**  These handle access to different types of pointers, including external pointers, trusted pointers (likely for internal V8 objects with stricter security), and code pointers. The `RELEASE_ACQUIRE` variants further reinforce the concurrency aspect.

5. **Address Specific Questions:**

    * **`.tq` extension:** The code doesn't end with `.tq`. I explicitly state this and explain what it would mean if it did.
    * **JavaScript Relation:** I look for connections to high-level concepts. The macros are about *how* objects are laid out, which directly impacts how the JavaScript engine can read and write object properties. I provide a JavaScript example demonstrating the concept of object properties and how V8 would internally manage them using these macros.
    * **Code Logic and Assumptions:** Since this is a header file of macros, direct code logic *execution* isn't present. The logic is about code *generation*. I explain the assumptions behind the memory barrier macros (concurrent access) and provide a hypothetical scenario to illustrate the input and output of the accessor macros (setting and getting a field).
    * **Common Programming Errors:** I consider common errors related to manual memory management and concurrency, such as incorrect alignment, padding issues, and race conditions. I tie these back to the purpose of the macros in preventing these errors.

6. **Summarize the Functionality:** Based on the analysis, I synthesize a concise summary that highlights the key functions of the header file: defining object structure, ensuring memory layout, providing accessors, and supporting thread safety.

7. **Structure the Response:** I organize the information logically, addressing each part of the user's request clearly and using headings for better readability. I use code snippets and explanations to illustrate the concepts.

8. **Refine and Review:** I reread my response to ensure accuracy, clarity, and completeness. I double-check that I've addressed all aspects of the user's query.

By following this process, I can systematically dissect the C++ header file and provide a comprehensive explanation of its functionality within the context of the V8 JavaScript engine. The focus is on understanding the *intent* and *purpose* of the macros rather than getting bogged down in the low-level details of each individual macro.
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Note 1: Any file that includes this one should include object-macros-undef.h
// at the bottom.

// Note 2: This file is deliberately missing the include guards (the undeffing
// approach wouldn't work otherwise).
//
// PRESUBMIT_INTENTIONALLY_MISSING_INCLUDE_GUARD

// The accessors with RELAXED_, ACQUIRE_, and RELEASE_ prefixes should be used
// for fields that can be written to and read from multiple threads at the same
// time. See comments in src/base/atomicops.h for the memory ordering sematics.

#include "src/base/memory.h"

// V8 objects are defined as:
//
//     V8_OBJECT class Foo : public Base {
//       ...
//     } V8_OBJECT_END;
//
// These macros are to enable packing down to 4-byte alignment (i.e. int32
// alignment, since we have int32 fields), and to add warnings which ensure that
// there is no unwanted within-object padding.
#if V8_CC_GNU
#define V8_OBJECT_PUSH                                                    \
  _Pragma("pack(push)") _Pragma("pack(4)") _Pragma("GCC diagnostic push") \
      _Pragma("GCC diagnostic error \"-Wpadded\"")
#define V8_OBJECT_POP _Pragma("pack(pop)") _Pragma("GCC diagnostic pop")
#elif V8_CC_MSVC
#define V8_OBJECT_PUSH                                           \
  __pragma(pack(push)) __pragma(pack(4)) __pragma(warning(push)) \
      __pragma(warning(default : 4820))
#define V8_OBJECT_POP __pragma(pack(pop)) __pragma(warning(pop))
#else
#error Unsupported compiler
#endif

#define V8_OBJECT V8_OBJECT_PUSH
// Compilers wants the pragmas to be a new statement, but we prefer to have
// V8_OBJECT_END look like part of the definition. Insert a semicolon before the
// pragma to make the compilers happy, and use static_assert(true) to swallow
// the next semicolon.
#define V8_OBJECT_END \
  ;                   \
  V8_OBJECT_POP static_assert(true)

#define V8_OBJECT_INNER_CLASS V8_OBJECT_POP
#define V8_OBJECT_INNER_CLASS_END \
  ;                               \
  V8_OBJECT_PUSH static_assert(true)

// Since this changes visibility, it should always be last in a class
// definition.
#define OBJECT_CONSTRUCTORS(Type, ...)                                         \
 public:                                                                       \
  constexpr Type() : __VA_ARGS__() {}                                          \
                                                                               \
  /* For every object, add a `->` operator which returns a pointer to this     \
     object. This will allow smoother transition between T and Tagged<T>. */   \
  Type* operator->() { return this; }                                          \
  const Type* operator->() const { return this; }                              \
                                                                               \
 protected:                                                                    \
  friend class Tagged<Type>;                                                   \
                                                                               \
  /* Special constructor for constexpr construction which allows skipping type \
   * checks. */                                                                \
  explicit constexpr V8_INLINE Type(Address ptr, HeapObject::SkipTypeCheckTag) \
      : __VA_ARGS__(ptr, HeapObject::SkipTypeCheckTag()) {}                    \
                                                                               \
  inline void CheckTypeOnCast();                                               \
  explicit inline Type(Address ptr)

#define OBJECT_CONSTRUCTORS_IMPL(Type, Super)                           \
  inline void Type::CheckTypeOnCast() { SLOW_DCHECK(Is##Type(*this)); } \
  inline Type::Type(Address ptr) : Super(ptr) { CheckTypeOnCast(); }

#define NEVER_READ_ONLY_SPACE   \
  inline Heap* GetHeap() const; \
  inline Isolate* GetIsolate() const;

// TODO(leszeks): Add checks in the factory that we never allocate these
// objects in RO space.
#define NEVER_READ_ONLY_SPACE_IMPL(Type)                                   \
  Heap* Type::GetHeap() const { return GetHeapFromWritableObject(*this); } \
  Isolate* Type::GetIsolate() const {                                      \
    return GetIsolateFromWritableObject(*this);                            \
  }

// ... (rest of the macros)
```

## 功能列举

`v8/src/objects/object-macros.h` 是一个 C++ 头文件，它定义了一系列**宏**，用于简化 V8 引擎中 **对象 (object)** 的定义和操作。其主要功能可以归纳为以下几点：

1. **定义 V8 对象结构和内存布局:**
   - 使用 `V8_OBJECT` 和 `V8_OBJECT_END` 宏来包裹 V8 对象的类定义。
   - 通过编译器指令 (`#pragma pack`) 强制对象按照 **4 字节对齐** 进行内存布局，以优化内存使用并满足 V8 内部对齐的要求。
   - 启用编译器警告 (`-Wpadded` on GCC, warning 4820 on MSVC) 来检测对象内部是否存在不必要的填充 (padding)，帮助开发者优化对象大小。

2. **简化构造函数定义:**
   - 提供 `OBJECT_CONSTRUCTORS` 宏来自动生成常用的构造函数，包括默认构造函数、接受 `Address` 指针的构造函数（用于类型转换或低级操作），以及重载 `operator->` 方便 `T` 和 `Tagged<T>` 之间的转换。

3. **控制对象在内存中的分配:**
   - `NEVER_READ_ONLY_SPACE` 和 `NEVER_READ_ONLY_SPACE_IMPL` 宏用于标记某些类型的对象不应该被分配在只读内存空间中。

4. **提供便捷的成员访问方式 (Getters 和 Setters):**
   - 定义了多种宏来声明和实现对象的成员访问器 (getters 和 setters)，包括：
     - `DECL_PRIMITIVE_ACCESSORS`: 用于基本数据类型 (int, bool 等)。
     - `DECL_GETTER`, `DECL_SETTER`, `DECL_ACCESSORS`:  更通用的访问器声明。
     - `DEF_GETTER`: 用于实现 getter。
     - 以及各种变体，如 `RELAXED_ACCESSORS`, `ACQUIRE_ACCESSORS`, `RELEASE_ACCESSORS`，用于处理多线程环境下的并发访问，控制内存屏障 (memory barrier)。
   - 这些宏能够自动生成内联函数，提高性能。

5. **处理不同类型的成员:**
   - 针对不同类型的成员（如基本类型、指针、Tagged 指针、外部指针、受信任指针、代码指针、保护指针、位域）提供了专门的访问宏，例如：
     - `DECL_INT_ACCESSORS`, `DECL_BOOLEAN_ACCESSORS`
     - `DECL_TRUSTED_POINTER_ACCESSORS`, `TRUSTED_POINTER_ACCESSORS`
     - `DECL_CODE_POINTER_ACCESSORS`, `CODE_POINTER_ACCESSORS`
     - `BIT_FIELD_ACCESSORS2`

6. **支持并发访问控制:**
   - 引入了带有 `RELAXED_`, `ACQUIRE_`, `RELEASE_` 前缀的访问器宏，用于处理多线程环境下的数据竞争问题。这些宏对应于不同的内存序语义，确保数据访问的正确性。

7. **定义字段偏移量:**
   - `DECL_FIELD_OFFSET_TQ` 宏用于定义对象成员在内存中的偏移量，并可能与 Torque 代码生成相关联。

## 关于 .tq 扩展名

如果 `v8/src/objects/object-macros.h` 以 `.tq` 结尾，那么你的判断是正确的，它会是一个 **V8 Torque 源代码**文件。 Torque 是 V8 使用的一种领域特定语言，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时功能。

然而，根据你提供的文件路径和内容，`v8/src/objects/object-macros.h` **是 C++ 头文件** (`.h`)，而不是 Torque 文件 (`.tq`)。

## 与 JavaScript 的关系

`v8/src/objects/object-macros.h` 中定义的宏直接影响着 V8 如何在 C++ 层表示和管理 JavaScript 对象。

**JavaScript 对象的内部表示：** 当你在 JavaScript 中创建一个对象时，V8 引擎会在底层分配一块内存来存储该对象的信息。 `object-macros.h` 中定义的宏，特别是 `V8_OBJECT` 和各种访问器宏，就参与了定义这些内存块的结构以及如何访问其中的属性。

**属性访问：** 当你在 JavaScript 中访问对象的属性（例如 `obj.name`），V8 引擎需要能够快速定位到存储该属性值的位置。 `object-macros.h` 中定义的访问器宏提供了高效的内联函数来实现这些访问操作。

**类型和内存管理：** V8 需要跟踪 JavaScript 对象的类型和进行内存管理（例如垃圾回收）。 `object-macros.h` 中的宏，配合其他 V8 的机制，确保了对象在内存中的正确布局和访问，这对于类型检查和垃圾回收至关重要。

**JavaScript 示例:**

```javascript
// JavaScript 代码
const person = {
  name: "Alice",
  age: 30
};

console.log(person.name); // 访问 name 属性
person.age = 31;         // 设置 age 属性
```

在 V8 内部，当执行上述 JavaScript 代码时，`object-macros.h` 中定义的宏生成的 C++ 代码会被调用，用于：

- **创建 `person` 对象:**  `V8_OBJECT` 相关的宏确保 `person` 对象在内存中按照预定的结构排列。
- **访问 `person.name`:**  类似于 `ACCESSORS` 宏生成的 getter 函数会被调用，根据预定义的偏移量读取 `name` 属性的值。
- **设置 `person.age`:**  类似于 `ACCESSORS` 宏生成的 setter 函数会被调用，将新的年龄值写入 `age` 属性对应的内存位置。

## 代码逻辑推理

`object-macros.h` 本身不包含直接的业务逻辑，它定义的是用于生成代码的宏。  其“逻辑”体现在如何利用这些宏来定义和操作对象。

**假设输入：**

假设我们使用 `V8_OBJECT` 宏定义了一个名为 `MyObject` 的类，并使用 `INT32_ACCESSORS` 宏定义了一个名为 `value` 的 `int32_t` 成员：

```cpp
// 假设在某个 .h 文件中
#include "src/objects/object-macros.h"

V8_OBJECT class MyObject : public HeapObject {
 public:
  INT32_ACCESSORS(value, kValueOffset); // 假设 kValueOffset 已定义

  // ... 其他成员 ...

  OBJECT_CONSTRUCTORS(MyObject, HeapObject);
} V8_OBJECT_END;

#include "src/objects/object-macros-undef.h"
```

**假设输出（生成的 C++ 代码片段）：**

`INT32_ACCESSORS(value, kValueOffset)` 宏会展开成类似下面的 C++ 代码：

```cpp
int32_t MyObject::value() const {
  return ReadField<int32_t>(kValueOffset);
}
void MyObject::set_value(int32_t value) {
  WriteField<int32_t>(kValueOffset, value);
}
```

**逻辑推理:**

1. 当创建一个 `MyObject` 实例后，它会在内存中分配空间。
2. 调用 `myObject->value()` 时，`ReadField<int32_t>(kValueOffset)` 会根据 `kValueOffset` 读取对象内存中对应的 4 个字节，并将其解释为 `int32_t` 返回。
3. 调用 `myObject->set_value(123)` 时，`WriteField<int32_t>(kValueOffset, 123)` 会将值 `123` 写入到 `myObject` 内存中 `kValueOffset` 指定的位置。

## 用户常见的编程错误

使用这些宏可以帮助避免一些常见的 C++ 编程错误，但如果使用不当，仍然可能出现问题：

1. **内存布局错误:** 如果手动计算偏移量 `kValueOffset` 错误，或者在修改类结构后忘记更新偏移量，会导致读写到错误的内存位置，造成程序崩溃或数据损坏。

2. **并发访问错误 (Race Conditions):**  如果在多线程环境下，没有正确使用 `RELAXED_`, `ACQUIRE_`, `RELEASE_` 等并发控制的访问器，可能会发生数据竞争，导致程序行为不可预测。

**示例 (并发访问错误):**

假设没有使用原子操作或适当的内存屏障，在多线程环境下同时读写 `MyObject` 的 `value` 属性：

```cpp
// 线程 1
myObject->set_value(10);

// 线程 2
int currentValue = myObject->value();
```

如果没有适当的同步机制，`线程 2` 读取到的 `currentValue` 可能不是 `10`，而是旧的值，或者一个不完整的值（如果写操作还没有完全完成），这就是典型的 **数据竞争**。

`object-macros.h` 中提供的 `RELAXED_INT32_ACCESSORS` 等宏可以帮助开发者更安全地处理这种情况：

```cpp
// 使用 relaxed 访问器
// 线程 1
myObject->set_value(10, std::memory_order_relaxed);

// 线程 2
int currentValue = myObject->value(std::memory_order_relaxed);
```

虽然 `relaxed` 语义是最宽松的，但在某些特定场景下可以使用。更严格的语义如 `acquire` 和 `release` 可以提供更强的保证。

## 功能归纳 (第 1 部分)

总而言之，`v8/src/objects/object-macros.h` 的主要功能是为 V8 引擎提供一套 **声明式** 的宏，用于 **规范化** 和 **简化** C++ 对象的定义和操作，特别是与内存布局、成员访问和并发控制相关的方面。它旨在：

- **提高代码的可读性和一致性。**
- **减少重复代码。**
- **通过编译器指令和警告，帮助开发者避免常见的内存布局错误。**
- **提供处理多线程并发访问的基础设施。**

这些宏是 V8 内部实现的核心组成部分，使得 V8 能够高效且可靠地管理 JavaScript 对象。

### 提示词
```
这是目录为v8/src/objects/object-macros.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/object-macros.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Note 1: Any file that includes this one should include object-macros-undef.h
// at the bottom.

// Note 2: This file is deliberately missing the include guards (the undeffing
// approach wouldn't work otherwise).
//
// PRESUBMIT_INTENTIONALLY_MISSING_INCLUDE_GUARD

// The accessors with RELAXED_, ACQUIRE_, and RELEASE_ prefixes should be used
// for fields that can be written to and read from multiple threads at the same
// time. See comments in src/base/atomicops.h for the memory ordering sematics.

#include "src/base/memory.h"

// V8 objects are defined as:
//
//     V8_OBJECT class Foo : public Base {
//       ...
//     } V8_OBJECT_END;
//
// These macros are to enable packing down to 4-byte alignment (i.e. int32
// alignment, since we have int32 fields), and to add warnings which ensure that
// there is no unwanted within-object padding.
#if V8_CC_GNU
#define V8_OBJECT_PUSH                                                    \
  _Pragma("pack(push)") _Pragma("pack(4)") _Pragma("GCC diagnostic push") \
      _Pragma("GCC diagnostic error \"-Wpadded\"")
#define V8_OBJECT_POP _Pragma("pack(pop)") _Pragma("GCC diagnostic pop")
#elif V8_CC_MSVC
#define V8_OBJECT_PUSH                                           \
  __pragma(pack(push)) __pragma(pack(4)) __pragma(warning(push)) \
      __pragma(warning(default : 4820))
#define V8_OBJECT_POP __pragma(pack(pop)) __pragma(warning(pop))
#else
#error Unsupported compiler
#endif

#define V8_OBJECT V8_OBJECT_PUSH
// Compilers wants the pragmas to be a new statement, but we prefer to have
// V8_OBJECT_END look like part of the definition. Insert a semicolon before the
// pragma to make the compilers happy, and use static_assert(true) to swallow
// the next semicolon.
#define V8_OBJECT_END \
  ;                   \
  V8_OBJECT_POP static_assert(true)

#define V8_OBJECT_INNER_CLASS V8_OBJECT_POP
#define V8_OBJECT_INNER_CLASS_END \
  ;                               \
  V8_OBJECT_PUSH static_assert(true)

// Since this changes visibility, it should always be last in a class
// definition.
#define OBJECT_CONSTRUCTORS(Type, ...)                                         \
 public:                                                                       \
  constexpr Type() : __VA_ARGS__() {}                                          \
                                                                               \
  /* For every object, add a `->` operator which returns a pointer to this     \
     object. This will allow smoother transition between T and Tagged<T>. */   \
  Type* operator->() { return this; }                                          \
  const Type* operator->() const { return this; }                              \
                                                                               \
 protected:                                                                    \
  friend class Tagged<Type>;                                                   \
                                                                               \
  /* Special constructor for constexpr construction which allows skipping type \
   * checks. */                                                                \
  explicit constexpr V8_INLINE Type(Address ptr, HeapObject::SkipTypeCheckTag) \
      : __VA_ARGS__(ptr, HeapObject::SkipTypeCheckTag()) {}                    \
                                                                               \
  inline void CheckTypeOnCast();                                               \
  explicit inline Type(Address ptr)

#define OBJECT_CONSTRUCTORS_IMPL(Type, Super)                           \
  inline void Type::CheckTypeOnCast() { SLOW_DCHECK(Is##Type(*this)); } \
  inline Type::Type(Address ptr) : Super(ptr) { CheckTypeOnCast(); }

#define NEVER_READ_ONLY_SPACE   \
  inline Heap* GetHeap() const; \
  inline Isolate* GetIsolate() const;

// TODO(leszeks): Add checks in the factory that we never allocate these
// objects in RO space.
#define NEVER_READ_ONLY_SPACE_IMPL(Type)                                   \
  Heap* Type::GetHeap() const { return GetHeapFromWritableObject(*this); } \
  Isolate* Type::GetIsolate() const {                                      \
    return GetIsolateFromWritableObject(*this);                            \
  }

#define DECL_PRIMITIVE_GETTER(name, type) inline type name() const;

#define DECL_PRIMITIVE_SETTER(name, type) inline void set_##name(type value);

#define DECL_PRIMITIVE_ACCESSORS(name, type) \
  DECL_PRIMITIVE_GETTER(name, type)          \
  DECL_PRIMITIVE_SETTER(name, type)

#define DECL_BOOLEAN_ACCESSORS(name) DECL_PRIMITIVE_ACCESSORS(name, bool)

#define DECL_INT_ACCESSORS(name) DECL_PRIMITIVE_ACCESSORS(name, int)

#define DECL_INT32_ACCESSORS(name) DECL_PRIMITIVE_ACCESSORS(name, int32_t)

#define DECL_SANDBOXED_POINTER_ACCESSORS(name, type) \
  DECL_PRIMITIVE_GETTER(name, type)                  \
  DECL_PRIMITIVE_SETTER(name, type)

#define DECL_UINT16_ACCESSORS(name) DECL_PRIMITIVE_ACCESSORS(name, uint16_t)

#define DECL_INT16_ACCESSORS(name) DECL_PRIMITIVE_ACCESSORS(name, int16_t)

#define DECL_UINT8_ACCESSORS(name) DECL_PRIMITIVE_ACCESSORS(name, uint8_t)

#define DECL_RELAXED_PRIMITIVE_ACCESSORS(name, type) \
  inline type name(RelaxedLoadTag) const;            \
  inline void set_##name(type value, RelaxedStoreTag);

#define DECL_RELAXED_INT32_ACCESSORS(name) \
  DECL_RELAXED_PRIMITIVE_ACCESSORS(name, int32_t)

#define DECL_RELAXED_UINT32_ACCESSORS(name) \
  DECL_RELAXED_PRIMITIVE_ACCESSORS(name, uint32_t)

#define DECL_RELAXED_UINT16_ACCESSORS(name) \
  DECL_RELAXED_PRIMITIVE_ACCESSORS(name, uint16_t)

#define DECL_RELAXED_UINT8_ACCESSORS(name) \
  DECL_RELAXED_PRIMITIVE_ACCESSORS(name, uint8_t)

#define DECL_GETTER(name, ...)     \
  inline __VA_ARGS__ name() const; \
  inline __VA_ARGS__ name(PtrComprCageBase cage_base) const;

#define DEF_GETTER(holder, name, ...)                        \
  __VA_ARGS__ holder::name() const {                         \
    PtrComprCageBase cage_base = GetPtrComprCageBase(*this); \
    return holder::name(cage_base);                          \
  }                                                          \
  __VA_ARGS__ holder::name(PtrComprCageBase cage_base) const

#define DEF_RELAXED_GETTER(holder, name, ...)                \
  __VA_ARGS__ holder::name(RelaxedLoadTag tag) const {       \
    PtrComprCageBase cage_base = GetPtrComprCageBase(*this); \
    return holder::name(cage_base, tag);                     \
  }                                                          \
  __VA_ARGS__ holder::name(PtrComprCageBase cage_base, RelaxedLoadTag) const

#define DEF_ACQUIRE_GETTER(holder, name, ...)                \
  __VA_ARGS__ holder::name(AcquireLoadTag tag) const {       \
    PtrComprCageBase cage_base = GetPtrComprCageBase(*this); \
    return holder::name(cage_base, tag);                     \
  }                                                          \
  __VA_ARGS__ holder::name(PtrComprCageBase cage_base, AcquireLoadTag) const

#define DEF_HEAP_OBJECT_PREDICATE(holder, name)            \
  bool name(Tagged<holder> obj) {                          \
    PtrComprCageBase cage_base = GetPtrComprCageBase(obj); \
    return name(obj, cage_base);                           \
  }                                                        \
  bool name(Tagged<holder> obj, PtrComprCageBase cage_base)

#define TQ_FIELD_TYPE(name, tq_type) \
  static constexpr const char* k##name##TqFieldType = tq_type;

#define DECL_FIELD_OFFSET_TQ(name, value, tq_type) \
  static const int k##name##Offset = value;        \
  TQ_FIELD_TYPE(name, tq_type)

#define DECL_SETTER(name, ...)              \
  inline void set_##name(__VA_ARGS__ value, \
                         WriteBarrierMode mode = UPDATE_WRITE_BARRIER);

#define DECL_ACCESSORS(name, ...) \
  DECL_GETTER(name, __VA_ARGS__)  \
  DECL_SETTER(name, __VA_ARGS__)

#define DECL_ACCESSORS_LOAD_TAG(name, type, tag_type) \
  inline UNPAREN(type) name(tag_type tag) const;      \
  inline UNPAREN(type) name(PtrComprCageBase cage_base, tag_type) const;

#define DECL_ACCESSORS_STORE_TAG(name, type, tag_type)  \
  inline void set_##name(UNPAREN(type) value, tag_type, \
                         WriteBarrierMode mode = UPDATE_WRITE_BARRIER);

#define DECL_RELAXED_GETTER(name, ...) \
  DECL_ACCESSORS_LOAD_TAG(name, (__VA_ARGS__), RelaxedLoadTag)

#define DECL_RELAXED_SETTER(name, ...) \
  DECL_ACCESSORS_STORE_TAG(name, (__VA_ARGS__), RelaxedStoreTag)

#define DECL_RELAXED_ACCESSORS(name, ...) \
  DECL_RELAXED_GETTER(name, __VA_ARGS__)  \
  DECL_RELAXED_SETTER(name, __VA_ARGS__)

#define DECL_ACQUIRE_GETTER(name, ...) \
  DECL_ACCESSORS_LOAD_TAG(name, (__VA_ARGS__), AcquireLoadTag)

#define DECL_RELEASE_SETTER(name, ...) \
  DECL_ACCESSORS_STORE_TAG(name, (__VA_ARGS__), ReleaseStoreTag)

#define DECL_RELEASE_ACQUIRE_ACCESSORS(name, ...) \
  DECL_ACQUIRE_GETTER(name, __VA_ARGS__)          \
  DECL_RELEASE_SETTER(name, __VA_ARGS__)

#define DEF_PRIMITIVE_ACCESSORS(holder, name, offset, type)     \
  type holder::name() const { return ReadField<type>(offset); } \
  void holder::set_##name(type value) { WriteField<type>(offset, value); }

#define INT_ACCESSORS(holder, name, offset) \
  DEF_PRIMITIVE_ACCESSORS(holder, name, offset, int)

#define INT32_ACCESSORS(holder, name, offset) \
  DEF_PRIMITIVE_ACCESSORS(holder, name, offset, int32_t)

#define UINT16_ACCESSORS(holder, name, offset) \
  DEF_PRIMITIVE_ACCESSORS(holder, name, offset, uint16_t)

#define UINT8_ACCESSORS(holder, name, offset) \
  DEF_PRIMITIVE_ACCESSORS(holder, name, offset, uint8_t)

#define RELAXED_INT32_ACCESSORS(holder, name, offset)       \
  int32_t holder::name(RelaxedLoadTag) const {              \
    return RELAXED_READ_INT32_FIELD(*this, offset);         \
  }                                                         \
  void holder::set_##name(int32_t value, RelaxedStoreTag) { \
    RELAXED_WRITE_INT32_FIELD(*this, offset, value);        \
  }

#define RELAXED_UINT32_ACCESSORS(holder, name, offset)       \
  uint32_t holder::name(RelaxedLoadTag) const {              \
    return RELAXED_READ_UINT32_FIELD(*this, offset);         \
  }                                                          \
  void holder::set_##name(uint32_t value, RelaxedStoreTag) { \
    RELAXED_WRITE_UINT32_FIELD(*this, offset, value);        \
  }

#define RELAXED_UINT16_ACCESSORS(holder, name, offset)       \
  uint16_t holder::name(RelaxedLoadTag) const {              \
    return RELAXED_READ_UINT16_FIELD(*this, offset);         \
  }                                                          \
  void holder::set_##name(uint16_t value, RelaxedStoreTag) { \
    RELAXED_WRITE_UINT16_FIELD(*this, offset, value);        \
  }

#define RELAXED_UINT8_ACCESSORS(holder, name, offset)       \
  uint8_t holder::name(RelaxedLoadTag) const {              \
    return RELAXED_READ_UINT8_FIELD(*this, offset);         \
  }                                                         \
  void holder::set_##name(uint8_t value, RelaxedStoreTag) { \
    RELAXED_WRITE_UINT8_FIELD(*this, offset, value);        \
  }

#define ACCESSORS_CHECKED2(holder, name, type, offset, get_condition,   \
                           set_condition)                               \
  DEF_GETTER(holder, name, UNPAREN(type)) {                             \
    UNPAREN(type)                                                       \
    value = TaggedField<UNPAREN(type), offset>::load(cage_base, *this); \
    DCHECK(get_condition);                                              \
    return value;                                                       \
  }                                                                     \
  void holder::set_##name(UNPAREN(type) value, WriteBarrierMode mode) { \
    DCHECK(set_condition);                                              \
    TaggedField<UNPAREN(type), offset>::store(*this, value);            \
    CONDITIONAL_WRITE_BARRIER(*this, offset, value, mode);              \
  }

#define ACCESSORS_CHECKED(holder, name, type, offset, condition) \
  ACCESSORS_CHECKED2(holder, name, type, offset, condition, condition)

#define ACCESSORS(holder, name, type, offset) \
  ACCESSORS_CHECKED(holder, name, type, offset, true)

// TODO(jgruber): Eventually, all accessors should be ported to the NOCAGE
// variant (which doesn't define a PtrComprCageBase overload). Once that's
// done, remove the cage-ful macros (e.g. ACCESSORS) and rename the cage-less
// macros (e.g. ACCESSORS_NOCAGE).
#define ACCESSORS_NOCAGE(holder, name, type, offset)           \
  type holder::name() const {                                  \
    PtrComprCageBase cage_base = GetPtrComprCageBase(*this);   \
    return TaggedField<type, offset>::load(cage_base, *this);  \
  }                                                            \
  void holder::set_##name(type value, WriteBarrierMode mode) { \
    TaggedField<type, offset>::store(*this, value);            \
    CONDITIONAL_WRITE_BARRIER(*this, offset, value, mode);     \
  }

#define RENAME_TORQUE_ACCESSORS(holder, name, torque_name, type)      \
  inline type holder::name() const {                                  \
    return TorqueGeneratedClass::torque_name();                       \
  }                                                                   \
  inline type holder::name(PtrComprCageBase cage_base) const {        \
    return TorqueGeneratedClass::torque_name(cage_base);              \
  }                                                                   \
  inline void holder::set_##name(type value, WriteBarrierMode mode) { \
    TorqueGeneratedClass::set_##torque_name(value, mode);             \
  }

#define RENAME_PRIMITIVE_TORQUE_ACCESSORS(holder, name, torque_name, type)  \
  type holder::name() const { return TorqueGeneratedClass::torque_name(); } \
  void holder::set_##name(type value) {                                     \
    TorqueGeneratedClass::set_##torque_name(value);                         \
  }

#define ACCESSORS_RELAXED_CHECKED2(holder, name, type, offset, get_condition, \
                                   set_condition)                             \
  type holder::name() const {                                                 \
    PtrComprCageBase cage_base = GetPtrComprCageBase(*this);                  \
    return holder::name(cage_base);                                           \
  }                                                                           \
  type holder::name(PtrComprCageBase cage_base) const {                       \
    type value = TaggedField<type, offset>::Relaxed_Load(cage_base, *this);   \
    DCHECK(get_condition);                                                    \
    return value;                                                             \
  }                                                                           \
  void holder::set_##name(type value, WriteBarrierMode mode) {                \
    DCHECK(set_condition);                                                    \
    TaggedField<type, offset>::Relaxed_Store(*this, value);                   \
    CONDITIONAL_WRITE_BARRIER(*this, offset, value, mode);                    \
  }

#define ACCESSORS_RELAXED_CHECKED(holder, name, type, offset, condition) \
  ACCESSORS_RELAXED_CHECKED2(holder, name, type, offset, condition, condition)

#define ACCESSORS_RELAXED(holder, name, type, offset) \
  ACCESSORS_RELAXED_CHECKED(holder, name, type, offset, true)

// Similar to ACCESSORS_RELAXED above but with respective relaxed tags.
#define RELAXED_ACCESSORS_CHECKED2(holder, name, type, offset, get_condition, \
                                   set_condition)                             \
  DEF_RELAXED_GETTER(holder, name, UNPAREN(type)) {                           \
    UNPAREN(type)                                                             \
    value =                                                                   \
        TaggedField<UNPAREN(type), offset>::Relaxed_Load(cage_base, *this);   \
    DCHECK(get_condition);                                                    \
    return value;                                                             \
  }                                                                           \
  void holder::set_##name(UNPAREN(type) value, RelaxedStoreTag,               \
                          WriteBarrierMode mode) {                            \
    DCHECK(set_condition);                                                    \
    TaggedField<UNPAREN(type), offset>::Relaxed_Store(*this, value);          \
    CONDITIONAL_WRITE_BARRIER(*this, offset, value, mode);                    \
  }

#define RELAXED_ACCESSORS_CHECKED(holder, name, type, offset, condition) \
  RELAXED_ACCESSORS_CHECKED2(holder, name, type, offset, condition, condition)

#define RELAXED_ACCESSORS(holder, name, type, offset) \
  RELAXED_ACCESSORS_CHECKED(holder, name, type, offset, true)

#define RELEASE_ACQUIRE_GETTER_CHECKED(holder, name, type, offset,          \
                                       get_condition)                       \
  DEF_ACQUIRE_GETTER(holder, name, UNPAREN(type)) {                         \
    UNPAREN(type)                                                           \
    value =                                                                 \
        TaggedField<UNPAREN(type), offset>::Acquire_Load(cage_base, *this); \
    DCHECK(get_condition);                                                  \
    return value;                                                           \
  }

#define RELEASE_ACQUIRE_SETTER_CHECKED(holder, name, type, offset,   \
                                       set_condition)                \
  void holder::set_##name(UNPAREN(type) value, ReleaseStoreTag,      \
                          WriteBarrierMode mode) {                   \
    DCHECK(set_condition);                                           \
    TaggedField<UNPAREN(type), offset>::Release_Store(*this, value); \
    CONDITIONAL_WRITE_BARRIER(*this, offset, value, mode);           \
  }

#define RELEASE_ACQUIRE_ACCESSORS_CHECKED2(holder, name, type, offset,      \
                                           get_condition, set_condition)    \
  RELEASE_ACQUIRE_GETTER_CHECKED(holder, name, type, offset, get_condition) \
  RELEASE_ACQUIRE_SETTER_CHECKED(holder, name, type, offset, set_condition)

#define RELEASE_ACQUIRE_ACCESSORS_CHECKED(holder, name, type, offset,       \
                                          condition)                        \
  RELEASE_ACQUIRE_ACCESSORS_CHECKED2(holder, name, type, offset, condition, \
                                     condition)

#define RELEASE_ACQUIRE_ACCESSORS(holder, name, type, offset) \
  RELEASE_ACQUIRE_ACCESSORS_CHECKED(holder, name, type, offset, true)

// Getter that returns a Smi as an int and writes an int as a Smi.
#define SMI_ACCESSORS_CHECKED(holder, name, offset, condition)   \
  int holder::name() const {                                     \
    DCHECK(condition);                                           \
    Tagged<Smi> value = TaggedField<Smi, offset>::load(*this);   \
    return value.value();                                        \
  }                                                              \
  void holder::set_##name(int value) {                           \
    DCHECK(condition);                                           \
    TaggedField<Smi, offset>::store(*this, Smi::FromInt(value)); \
  }

#define SMI_ACCESSORS(holder, name, offset) \
  SMI_ACCESSORS_CHECKED(holder, name, offset, true)

#define DECL_RELEASE_ACQUIRE_INT_ACCESSORS(name) \
  inline int name(AcquireLoadTag) const;         \
  inline void set_##name(int value, ReleaseStoreTag);

#define RELEASE_ACQUIRE_SMI_ACCESSORS(holder, name, offset)              \
  int holder::name(AcquireLoadTag) const {                               \
    Tagged<Smi> value = TaggedField<Smi, offset>::Acquire_Load(*this);   \
    return value.value();                                                \
  }                                                                      \
  void holder::set_##name(int value, ReleaseStoreTag) {                  \
    TaggedField<Smi, offset>::Release_Store(*this, Smi::FromInt(value)); \
  }

#define DECL_RELAXED_INT_ACCESSORS(name) \
  inline int name(RelaxedLoadTag) const; \
  inline void set_##name(int value, RelaxedStoreTag);

#define RELAXED_SMI_ACCESSORS(holder, name, offset)                      \
  int holder::name(RelaxedLoadTag) const {                               \
    Tagged<Smi> value = TaggedField<Smi, offset>::Relaxed_Load(*this);   \
    return value.value();                                                \
  }                                                                      \
  void holder::set_##name(int value, RelaxedStoreTag) {                  \
    TaggedField<Smi, offset>::Relaxed_Store(*this, Smi::FromInt(value)); \
  }

#define BOOL_GETTER(holder, field, name, offset) \
  bool holder::name() const { return BooleanBit::get(field(), offset); }

#define BOOL_ACCESSORS(holder, field, name, offset)                      \
  bool holder::name() const { return BooleanBit::get(field(), offset); } \
  void holder::set_##name(bool value) {                                  \
    set_##field(BooleanBit::set(field(), offset, value));                \
  }

#define DECL_RELAXED_BOOL_ACCESSORS(name) \
  inline bool name(RelaxedLoadTag) const; \
  inline void set_##name(bool value, RelaxedStoreTag);

#define RELAXED_BOOL_ACCESSORS(holder, field, name, offset)          \
  bool holder::name(RelaxedLoadTag) const {                          \
    return BooleanBit::get(field(kRelaxedLoad), offset);             \
  }                                                                  \
  void holder::set_##name(bool value, RelaxedStoreTag) {             \
    set_##field(BooleanBit::set(field(kRelaxedLoad), offset, value), \
                kRelaxedStore);                                      \
  }

// Host objects in ReadOnlySpace can't define the isolate-less accessor.
#define DECL_EXTERNAL_POINTER_ACCESSORS_MAYBE_READ_ONLY_HOST(name, type) \
  inline type name(i::IsolateForSandbox isolate) const;                  \
  inline void init_##name(i::IsolateForSandbox isolate,                  \
                          const type initial_value);                     \
  inline void set_##name(i::IsolateForSandbox isolate, const type value);

// Host objects in ReadOnlySpace can't define the isolate-less accessor.
#define EXTERNAL_POINTER_ACCESSORS_MAYBE_READ_ONLY_HOST(holder, name, type, \
                                                        offset, tag)        \
  type holder::name(i::IsolateForSandbox isolate) const {                   \
    /* This is a workaround for MSVC error C2440 not allowing  */           \
    /* reinterpret casts to the same type. */                               \
    struct C2440 {};                                                        \
    Address result =                                                        \
        HeapObject::ReadExternalPointerField<tag>(offset, isolate);         \
    return reinterpret_cast<type>(reinterpret_cast<C2440*>(result));        \
  }                                                                         \
  void holder::init_##name(i::IsolateForSandbox isolate,                    \
                           const type initial_value) {                      \
    /* This is a workaround for MSVC error C2440 not allowing  */           \
    /* reinterpret casts to the same type. */                               \
    struct C2440 {};                                                        \
    Address the_value = reinterpret_cast<Address>(                          \
        reinterpret_cast<const C2440*>(initial_value));                     \
    HeapObject::InitExternalPointerField<tag>(offset, isolate, the_value);  \
  }                                                                         \
  void holder::set_##name(i::IsolateForSandbox isolate, const type value) { \
    /* This is a workaround for MSVC error C2440 not allowing  */           \
    /* reinterpret casts to the same type. */                               \
    struct C2440 {};                                                        \
    Address the_value =                                                     \
        reinterpret_cast<Address>(reinterpret_cast<const C2440*>(value));   \
    HeapObject::WriteExternalPointerField<tag>(offset, isolate, the_value); \
  }

#define DECL_EXTERNAL_POINTER_ACCESSORS(name, type) \
  inline type name() const;                         \
  DECL_EXTERNAL_POINTER_ACCESSORS_MAYBE_READ_ONLY_HOST(name, type)

#define EXTERNAL_POINTER_ACCESSORS(holder, name, type, offset, tag)           \
  type holder::name() const {                                                 \
    i::IsolateForSandbox isolate = GetIsolateForSandbox(*this);               \
    return holder::name(isolate);                                             \
  }                                                                           \
  EXTERNAL_POINTER_ACCESSORS_MAYBE_READ_ONLY_HOST(holder, name, type, offset, \
                                                  tag)

#define DECL_TRUSTED_POINTER_GETTERS(name, type)                             \
  /* Trusted pointers currently always have release-acquire semantics. */    \
  /* However, we still expose explicit release-acquire accessors so it */    \
  /* can be made clear when they are required. */                            \
  /* If desired, we could create separate {Read|Write}TrustedPointer */      \
  /* routines for relaxed- and release-acquire semantics in the future. */   \
  inline Tagged<type> name(IsolateForSandbox isolate) const;                 \
  inline Tagged<type> name(IsolateForSandbox isolate, AcquireLoadTag) const; \
  inline bool has_##name() const;

#define DECL_TRUSTED_POINTER_SETTERS(name, type)                           \
  /* Trusted pointers currently always have release-acquire semantics. */  \
  /* However, we still expose explicit release-acquire accessors so it */  \
  /* can be made clear when they are required. */                          \
  /* If desired, we could create separate {Read|Write}TrustedPointer */    \
  /* routines for relaxed- and release-acquire semantics in the future. */ \
  inline void set_##name(Tagged<type> value,                               \
                         WriteBarrierMode mode = UPDATE_WRITE_BARRIER);    \
  inline void set_##name(Tagged<type> value, ReleaseStoreTag,              \
                         WriteBarrierMode mode = UPDATE_WRITE_BARRIER);    \
  inline void clear_##name();

#define DECL_TRUSTED_POINTER_ACCESSORS(name, type) \
  DECL_TRUSTED_POINTER_GETTERS(name, type)         \
  DECL_TRUSTED_POINTER_SETTERS(name, type)

#define TRUSTED_POINTER_ACCESSORS(holder, name, type, offset, tag)             \
  Tagged<type> holder::name(IsolateForSandbox isolate) const {                 \
    return name(isolate, kAcquireLoad);                                        \
  }                                                                            \
  Tagged<type> holder::name(IsolateForSandbox isolate, AcquireLoadTag) const { \
    DCHECK(has_##name());                                                      \
    return Cast<type>(ReadTrustedPointerField<tag>(offset, isolate));          \
  }                                                                            \
  void holder::set_##name(Tagged<type> value, WriteBarrierMode mode) {         \
    set_##name(value, kReleaseStore, mode);                                    \
  }                                                                            \
  void holder::set_##name(Tagged<type> value, ReleaseStoreTag,                 \
                          WriteBarrierMode mode) {                             \
    WriteTrustedPointerField<tag>(offset, value);                              \
    CONDITIONAL_TRUSTED_POINTER_WRITE_BARRIER(*this, offset, tag, value,       \
                                              mode);                           \
  }                                                                            \
  bool holder::has_##name() const {                                            \
    return !IsTrustedPointerFieldEmpty(offset);                                \
  }                                                                            \
  void holder::clear_##name() { ClearTrustedPointerField(offset); }

#define DECL_CODE_POINTER_ACCESSORS(name) \
  DECL_TRUSTED_POINTER_ACCESSORS(name, Code)
#define CODE_POINTER_ACCESSORS(holder, name, offset) \
  TRUSTED_POINTER_ACCESSORS(holder, name, Code, offset, kCodeIndirectPointerTag)

// Accessors for "protected" pointers, i.e. references from one trusted object
// to another trusted object. For these pointers it can be assumed that neither
// the pointer nor the pointed-to object can be manipulated by an attacker.
#define DECL_PROTECTED_POINTER_ACCESSORS(name, type)                    \
  inline Tagged<type> name() const;                                     \
  inline void set_##name(Tagged<type> value,                            \
                         WriteBarrierMode mode = UPDATE_WRITE_BARRIER); \
  inline bool has_##name() const;                                       \
  inline void clear_##name();

#define PROTECTED_POINTER_ACCESSORS(holder, name, type, offset)              \
  static_assert(std::is_base_of<TrustedObject, holder>::value);              \
  Tagged<type> holder::name() const {                                        \
    DCHECK(has_##name());                                                    \
    return Cast<type>(ReadProtectedPointerField(offset));                    \
  }                                                                          \
  void holder::set_##name(Tagged<type> value, WriteBarrierMode mode) {       \
    WriteProtectedPointerField(offset, value);                               \
    CONDITIONAL_PROTECTED_POINTER_WRITE_BARRIER(*this, offset, value, mode); \
  }                                                                          \
  bool holder::has_##name() const {                                          \
    return !IsProtectedPointerFieldEmpty(offset);                            \
  }                                                                          \
  void holder::clear_##name() { return ClearProtectedPointerField(offset); }

#define DECL_RELEASE_ACQUIRE_PROTECTED_POINTER_ACCESSORS(name, type)    \
  inline Tagged<type> name(AcquireLoadTag) const;                       \
  inline void set_##name(Tagged<type> value, ReleaseStoreTag,           \
                         WriteBarrierMode mode = UPDATE_WRITE_BARRIER); \
  inline bool has_##name(AcquireLoadTag) const;                         \
  inline void clear_##name(ReleaseStoreTag);

#define RELEASE_ACQUIRE_PROTECTED_POINTER_ACCESSORS(holder, name, type,      \
                                                    offset)                  \
  static_assert(std::is_base_of<TrustedObject, holder>::value);              \
  Tagged<type> holder::name(AcquireLoadTag tag) const {                      \
    DCHECK(has_##name(tag));                                                 \
    return Cast<type>(ReadProtectedPointerField(offset, tag));               \
  }                                                                          \
  void holder::set_##name(Tagged<type> value, ReleaseStoreTag tag,           \
                          WriteBarrierMode mode) {                           \
    WriteProtectedPointerField(offset, value, tag);                          \
    CONDITIONAL_PROTECTED_POINTER_WRITE_BARRIER(*this, offset, value, mode); \
  }                                                                          \
  bool holder::has_##name(AcquireLoadTag tag) const {                        \
    return !IsProtectedPointerFieldEmpty(offset, tag);                       \
  }                                                                          \
  void holder::clear_##name(ReleaseStoreTag tag) {                           \
    return ClearProtectedPointerField(offset, tag);                          \
  }

#define BIT_FIELD_ACCESSORS2(holder, get_field, set_field, name, BitField) \
  typename BitField::FieldType holder::name() const {                      \
    return BitField::decode(get_field());                                  \
  }
```