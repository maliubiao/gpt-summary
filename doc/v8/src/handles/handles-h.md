Response:
Let's break down the thought process for analyzing this C++ header file (`handles.h`) from V8.

**1. Initial Scan and High-Level Understanding:**

* **Copyright and License:**  The first lines are standard copyright and license information, indicating this is V8 project code under a BSD-style license. This tells us it's open-source and we can expect standard coding practices.
* **Include Guards:** `#ifndef V8_HANDLES_HANDLES_H_` and `#define V8_HANDLES_HANDLES_H_` are standard include guards to prevent multiple inclusions.
* **Includes:** A quick glance at the `#include` directives reveals dependencies on standard C++ libraries (`<type_traits>`, `<vector>`) and V8-specific headers (`"src/base/..."`, `"src/common/..."`, `"src/objects/..."`, `"v8-handle-base.h"`). This immediately signals that this file is about memory management and object representation within the V8 engine. The presence of `"v8-handle-base.h"` strongly suggests the core concept is "handles".
* **Namespace:** The code is within the `v8::internal` namespace, indicating this is internal implementation detail of the V8 engine and not part of the public API.

**2. Identifying Key Concepts and Structures:**

* **`HandleBase`:** This is clearly a foundational class. The comments indicate "Base class for Handle instantiations. Don't use directly."  The methods like `is_identical_to`, `is_null`, `address`, and `location` hint at its purpose: managing a reference to an object in memory. The `location_` member is a crucial piece of information.
* **`Handle<T>`:**  The comment "A Handle provides a reference to an object that survives relocation by the garbage collector" is a key insight. This tells us handles are the core mechanism for interacting with V8 objects safely in the presence of garbage collection. The template parameter `T` suggests handles are type-safe. The methods like `New`, the constructors, `operator->`, `operator*`, `PatchValue` all point to its role as a smart pointer to V8 objects. The mention of `HandleScope` in the comments further suggests a lifetime management aspect.
* **`HandleScope`:**  The comment "A stack-allocated class that governs a number of local handles" clarifies its function. It's a mechanism for managing the lifetime of handles, preventing dangling pointers after garbage collection. The methods like `CreateHandle`, `CloseAndEscape`, and the destructor `~HandleScope()` confirm this.
* **`SealHandleScope`:** This seems like a way to restrict handle creation within a certain scope.
* **`DirectHandle<T>`:** The `#ifdef V8_ENABLE_DIRECT_HANDLE` block immediately draws attention. This indicates a conditional feature. The comments state "A DirectHandle provides a reference to an object without an intermediate pointer."  This suggests an optimization or an alternative way of managing object references, likely with different trade-offs compared to `Handle`. The symmetrical methods with `Handle` suggest they serve a similar purpose but with a different underlying implementation. The comments about conservative stack scanning are a significant detail.
* **`DirectHandleVector<T>`:** This appears to be a container for `DirectHandle` objects, similar to `std::vector`.

**3. Analyzing Functionality of Core Components:**

* **`HandleBase`:** Focus on the purpose of its methods. `is_identical_to` compares object identity, `is_null` checks for a null handle, `address` gets the memory location of the handle itself, and `location` gets the memory location of the *object* the handle points to. The protected members and friend classes indicate internal usage and controlled access.
* **`Handle<T>`:** Understand how it interacts with `HandleBase`. It inherits from `HandleBase` and adds type safety. The constructors show how handles are created from raw pointers or `Tagged<T>` objects. `New` is a static factory method. The operators `->` and `*` provide convenient access to the underlying object. `PatchValue` allows modifying the object the handle points to.
* **`HandleScope`:**  The constructor and destructor clearly mark the beginning and end of a handle scope. `CreateHandle` is how new handles are allocated within a scope. `CloseAndEscape` is an important mechanism for transferring a handle's ownership to an outer scope.
* **`DirectHandle<T>`:**  Understand the conditional compilation and the implications of direct handles (potential performance benefits, but requires conservative stack scanning). Note the similar methods to `Handle`, but without the indirection.

**4. Considering the "Why" - The Problem Handles Solve:**

* The primary problem handles address is **garbage collection safety**. Without handles, raw pointers to V8 objects would become invalid when the garbage collector moves objects in memory. Handles provide a level of indirection, ensuring that even if an object moves, the handle still points to it. `HandleScope` is crucial for managing the lifetime of these handles and preventing memory leaks.

**5. Thinking about JavaScript Relevance (as requested):**

* Although this is C++ code, it's the *foundation* for how JavaScript objects are managed in V8. When JavaScript code creates an object, V8 internally uses handles to represent and track that object. The garbage collector's ability to move objects without breaking JavaScript's references relies on this handle mechanism. The concept of a `HandleScope` is related to the lifetime of JavaScript variables within functions.

**6. Addressing Specific Requests in the Prompt:**

* **Listing Functions:**  Systematically go through each class and list its public methods.
* **Torque Source:** Check the file extension (.h vs .tq).
* **JavaScript Relationship:** Explain the underlying connection between handles and JavaScript object management. Provide a simple JavaScript example where object creation and variable assignment implicitly use handles.
* **Code Logic Inference:** For methods with clear logic (e.g., `is_null`), provide simple input/output examples.
* **Common Programming Errors:** Think about what could go wrong if handles are misused. Forgetting to use `HandleScope`, accessing handles after their scope ends, and mixing raw pointers with managed objects are common pitfalls.
* **Summarizing Functionality:**  Condense the findings into a concise overview of the header file's purpose.

**7. Iterative Refinement:**

* Review the initial analysis and add more detail. For example, explain the purpose of `SealHandleScope`.
* Ensure the explanations are clear and accurate.
* Double-check the code for any missed details or subtleties. For example, the static asserts and friend declarations.

By following this structured approach, systematically examining the code, and considering the "why" behind the design, we can effectively understand the functionality of this crucial V8 header file. The key is to start with a high-level overview and then progressively delve into the details of each component.
好的，让我们来分析一下 `v8/src/handles/handles.h` 这个 V8 源代码文件的功能。

**文件类型判断：**

由于该文件以 `.h` 结尾，而不是 `.tq`，所以它是一个 **C++ 头文件**，而不是 V8 Torque 源代码。

**功能概览：**

`v8/src/handles/handles.h` 文件定义了 V8 引擎中用于安全管理对象引用的核心机制—— **Handles（句柄）**。 Handles 允许在垃圾回收器移动对象时，仍然能够安全地访问这些对象。 该文件主要定义了以下关键概念和类：

* **`HandleBase`**:  作为所有 Handle 类型的基类，提供了 Handle 的基本操作，例如比较两个 Handle 是否指向同一个对象、判断 Handle 是否为空以及获取 Handle 存储的地址。用户不应直接使用此类。
* **`Handle<T>`**:  模板类，表示一个指向类型为 `T` 的对象的强引用 Handle。这是最常用的 Handle 类型。它确保了所引用的对象在 Handle 的生命周期内不会被垃圾回收器回收。
* **`HandleScope`**:  一个栈分配的类，用于管理一组局部 Handle 的生命周期。当 `HandleScope` 对象被创建时，所有在该作用域内创建的 Handle 都会在该作用域结束时被释放。这是一种管理 Handle 生命周期的重要机制，防止内存泄漏。
* **`SealHandleScope`**:  用于密封当前的 `HandleScope`，阻止在该作用域内创建新的 Handle，除非创建新的 `HandleScope`。这可以用于在特定阶段限制 Handle 的分配。
* **`DirectHandle<T>`**:  （在 `V8_ENABLE_DIRECT_HANDLE` 宏定义下可用）模板类，表示一个直接指向类型为 `T` 的对象的引用，没有中间指针。与 `Handle<T>` 相比，`DirectHandle<T>` 提供了更高的性能，但使用时需要注意垃圾回收的影响，通常与保守式栈扫描一起使用。
* **`DirectHandleVector<T>`**:  （在 `V8_ENABLE_DIRECT_HANDLE` 宏定义下可用）一个用于存储 `DirectHandle<T>` 对象的向量容器。

**与 JavaScript 的关系：**

`v8/src/handles/handles.h` 中定义的 Handles 机制是 V8 引擎实现 JavaScript 内存管理的关键组成部分。当 JavaScript 代码创建对象（例如，通过 `new` 关键字或字面量）时，V8 内部会创建相应的 Handle 来管理这些对象的生命周期。

**JavaScript 示例：**

```javascript
let obj1 = { value: 1 }; // 在 V8 内部，obj1 可能会关联一个 Handle
let obj2 = obj1;         // obj2 可能会关联与 obj1 相同的 Handle (或指向相同对象的另一个 Handle)

function processObject(obj) { // 函数参数传递也可能涉及 Handle 的传递
  console.log(obj.value);
}

processObject(obj2);
```

在这个 JavaScript 例子中：

* 当 `{ value: 1 }` 被创建时，V8 会在堆上分配内存来存储这个对象，并创建一个 Handle 来指向它。
* 当 `obj1` 被赋值时，这个 Handle 会与 `obj1` 这个 JavaScript 变量关联起来。
* 当 `obj2 = obj1` 时，`obj2` 也会关联到同一个 Handle（或者指向相同对象的另一个 Handle）。
* 当 `processObject(obj2)` 被调用时，传递给函数的参数 `obj` 在 V8 内部也是通过 Handle 来传递的。

**代码逻辑推理：**

让我们来看一个简单的代码逻辑推理，以 `Handle<T>` 的构造函数为例：

**假设输入：**

* `object`: 一个指向堆上 `T` 类型对象的原始指针地址。
* `isolate`: 一个指向当前 V8 隔离区的指针。

**`Handle(Tagged<T> object, Isolate* isolate);`**  （简化后的构造函数）

**代码逻辑（推测）：**

1. **分配 Handle 存储空间：**  `Handle` 的构造函数可能会在当前 `HandleScope` 中分配一块内存来存储这个新的 Handle。
2. **存储对象地址：** 将传入的 `object` 的地址存储到新分配的 Handle 的内部位置 (`location_`)。
3. **关联 Isolate：**  Handle 可能需要知道它属于哪个 `Isolate`，以便在垃圾回收时进行正确的处理。

**输出：**

* 一个新的 `Handle<T>` 对象，其内部的 `location_` 指向了传入的 `object`。

**用户常见的编程错误：**

涉及到 Handle 时，用户（通常是 V8 引擎的开发者或嵌入 V8 的开发者）常见的编程错误包括：

1. **忘记使用 `HandleScope`：**  如果在没有活跃的 `HandleScope` 的情况下创建 Handle，当函数返回时，Handle 指向的内存可能会被垃圾回收，导致悬挂指针。

   ```c++
   v8::Local<v8::String> createString(v8::Isolate* isolate, const char* str) {
       // 错误：没有使用 HandleScope
       return v8::String::NewFromUtf8(isolate, str).ToLocalChecked();
   }

   void foo(v8::Isolate* isolate) {
       v8::Local<v8::String> str = createString(isolate, "hello");
       // str 可能在 createString 返回后就变成无效的了
       // ... 使用 str 可能会导致错误
   }
   ```

   **正确做法：**

   ```c++
   v8::Local<v8::String> createString(v8::Isolate* isolate, const char* str) {
       v8::HandleScope handle_scope(isolate); // 创建 HandleScope
       return v8::String::NewFromUtf8(isolate, str).ToLocalChecked();
   }

   void foo(v8::Isolate* isolate) {
       v8::HandleScope handle_scope(isolate);
       v8::Local<v8::String> str = createString(isolate, "hello");
       // str 在 handle_scope 结束前都是有效的
       // ... 使用 str
   }
   ```

2. **在 `HandleScope` 结束后访问 Handle：**  当 `HandleScope` 对象析构时，该作用域内创建的 Handle 可能会失效。

   ```c++
   v8::Local<v8::String> str;
   void foo(v8::Isolate* isolate) {
       {
           v8::HandleScope handle_scope(isolate);
           str = v8::String::NewFromUtf8(isolate, "hello").ToLocalChecked();
       } // handle_scope 结束，str 指向的内存可能被回收
       // ... 访问 str 可能会导致错误
       isolate->ThrowException(str); // 错误的使用
   }
   ```

   **正确做法：** 如果需要在 `HandleScope` 外部使用 Handle，可以使用 `Persistent` Handle 或者通过 `CloseAndEscape` 将 Handle 转移到外部的 `HandleScope`。

3. **混合使用原始指针和 Handle：**  在垃圾回收的环境中，使用原始指针来管理对象是非常危险的，因为对象可能会被移动。应该尽可能使用 Handle 来安全地引用对象。

**功能归纳（第 1 部分）：**

`v8/src/handles/handles.h` 的主要功能是定义了 V8 引擎中用于安全管理对象引用的 **Handles 机制**。它定义了 `HandleBase`、`Handle<T>`、`HandleScope` 和 `SealHandleScope` 等核心类，这些类共同协作，确保在垃圾回收过程中，V8 引擎能够安全可靠地访问和操作 JavaScript 对象。  该文件是 V8 内存管理的基础，对于理解 V8 如何与 JavaScript 对象交互至关重要。 在启用了 `V8_ENABLE_DIRECT_HANDLE` 的情况下，还引入了 `DirectHandle<T>` 和 `DirectHandleVector<T>` 作为性能优化的替代方案，但需要更谨慎地处理垃圾回收的影响。

### 提示词
```
这是目录为v8/src/handles/handles.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/handles/handles.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HANDLES_HANDLES_H_
#define V8_HANDLES_HANDLES_H_

#include <type_traits>
#include <vector>

#include "src/base/functional.h"
#include "src/base/macros.h"
#include "src/common/checks.h"
#include "src/common/globals.h"
#include "src/objects/casting.h"
#include "src/objects/tagged.h"
#include "v8-handle-base.h"  // NOLINT(build/include_directory)

#ifdef V8_ENABLE_DIRECT_HANDLE
#include "src/flags/flags.h"
#endif

namespace v8 {

class HandleScope;

namespace internal {

// Forward declarations.
#ifdef V8_ENABLE_DIRECT_HANDLE
class DirectHandleBase;
template <typename T>
class DirectHandleUnchecked;
#endif
class HandleScopeImplementer;
class Isolate;
class LocalHeap;
class LocalIsolate;
class TaggedIndex;
class Object;
class OrderedHashMap;
class OrderedHashSet;
class OrderedNameDictionary;
class RootVisitor;
class SmallOrderedHashMap;
class SmallOrderedHashSet;
class SmallOrderedNameDictionary;
class SwissNameDictionary;
class WasmExportedFunctionData;
class ZoneAllocationPolicy;

constexpr Address kTaggedNullAddress = 0x1;

// ----------------------------------------------------------------------------
// Base class for Handle instantiations. Don't use directly.
class HandleBase {
 public:
  // Check if this handle refers to the exact same object as the other handle.
  V8_INLINE bool is_identical_to(const HandleBase& that) const;
#ifdef V8_ENABLE_DIRECT_HANDLE
  V8_INLINE bool is_identical_to(const DirectHandleBase& that) const;
#endif
  V8_INLINE bool is_null() const { return location_ == nullptr; }

  // Returns the raw address where this handle is stored. This should only be
  // used for hashing handles; do not ever try to dereference it.
  V8_INLINE Address address() const {
    return reinterpret_cast<Address>(location_);
  }

  // Returns the address to where the raw pointer is stored.
  // TODO(leszeks): This should probably be a const Address*, to encourage using
  // PatchValue for modifying the handle's value.
  V8_INLINE Address* location() const {
    SLOW_DCHECK(location_ == nullptr || IsDereferenceAllowed());
    return location_;
  }

#ifdef V8_ENABLE_DIRECT_HANDLE
  V8_INLINE ValueHelper::InternalRepresentationType repr() const {
    return location_ ? *location_ : ValueHelper::kEmpty;
  }
#else
  V8_INLINE ValueHelper::InternalRepresentationType repr() const {
    return location_;
  }
#endif  // V8_ENABLE_DIRECT_HANDLE

 protected:
#ifdef V8_ENABLE_DIRECT_HANDLE
  friend class DirectHandleBase;

  static Address* indirect_handle(Address object);
  static Address* indirect_handle(Address object, Isolate* isolate);
  static Address* indirect_handle(Address object, LocalIsolate* isolate);
  static Address* indirect_handle(Address object, LocalHeap* local_heap);

  template <typename T>
  friend IndirectHandle<T> indirect_handle(DirectHandle<T> handle);
  template <typename T>
  friend IndirectHandle<T> indirect_handle(DirectHandle<T> handle,
                                           Isolate* isolate);
  template <typename T>
  friend IndirectHandle<T> indirect_handle(DirectHandle<T> handle,
                                           LocalIsolate* isolate);
  template <typename T>
  friend IndirectHandle<T> indirect_handle(DirectHandle<T> handle,
                                           LocalHeap* local_heap);
#endif  // V8_ENABLE_DIRECT_HANDLE

  V8_INLINE explicit HandleBase(Address* location) : location_(location) {}
  V8_INLINE explicit HandleBase(Address object, Isolate* isolate);
  V8_INLINE explicit HandleBase(Address object, LocalIsolate* isolate);
  V8_INLINE explicit HandleBase(Address object, LocalHeap* local_heap);

#ifdef DEBUG
  V8_EXPORT_PRIVATE bool IsDereferenceAllowed() const;
#else
  V8_INLINE bool IsDereferenceAllowed() const { return true; }
#endif  // DEBUG

  // This uses type Address* as opposed to a pointer type to a typed
  // wrapper class, because it doesn't point to instances of such a
  // wrapper class. Design overview: https://goo.gl/Ph4CGz
  Address* location_;
};

// ----------------------------------------------------------------------------
// A Handle provides a reference to an object that survives relocation by
// the garbage collector.
//
// Handles are only valid within a HandleScope. When a handle is created
// for an object a cell is allocated in the current HandleScope.
//
// Also note that Handles do not provide default equality comparison or hashing
// operators on purpose. Such operators would be misleading, because intended
// semantics is ambiguous between Handle location and object identity. Instead
// use either {is_identical_to} or {location} explicitly.
template <typename T>
class Handle final : public HandleBase {
 public:
  // Handles denote strong references.
  static_assert(!is_maybe_weak_v<T>);

  V8_INLINE Handle() : HandleBase(nullptr) {}

  V8_INLINE explicit Handle(Address* location) : HandleBase(location) {
    // TODO(jkummerow): Runtime type check here as a SLOW_DCHECK?
  }

  V8_INLINE Handle(Tagged<T> object, Isolate* isolate);
  V8_INLINE Handle(Tagged<T> object, LocalIsolate* isolate);
  V8_INLINE Handle(Tagged<T> object, LocalHeap* local_heap);

  // Allocate a new handle for the object.
  V8_INLINE static Handle<T> New(Tagged<T> object, Isolate* isolate);

  // Constructor for handling automatic up casting.
  // Ex. Handle<JSFunction> can be passed when Handle<Object> is expected.
  template <typename S, typename = std::enable_if_t<is_subtype_v<S, T>>>
  V8_INLINE Handle(Handle<S> handle) : HandleBase(handle) {}

  // Access a member of the T object referenced by this handle.
  //
  // This is actually a double dereference -- first it dereferences the Handle
  // pointing to a Tagged<T>, and then continues through Tagged<T>::operator->.
  // This means that this is only permitted for Tagged<T> with an operator->,
  // i.e. for on-heap object T.
  V8_INLINE Tagged<T> operator->() const {
    // For non-HeapObjects, there's no on-heap object to dereference, so
    // disallow using operator->.
    //
    // If you got an error here and want to access the Tagged<T>, use
    // operator* -- e.g. for `Tagged<Smi>::value()`, use `(*handle).value()`.
    static_assert(
        is_subtype_v<T, HeapObject>,
        "This handle does not reference a heap object. Use `(*handle).foo`.");
    return **this;
  }

  V8_INLINE Tagged<T> operator*() const {
    // This static type check also fails for forward class declarations. We
    // check on access instead of on construction to allow Handles to forward
    // declared types.
    static_assert(is_taggable_v<T>, "static type violation");
    // Direct construction of Tagged from address, without a type check, because
    // we rather trust Handle<T> to contain a T than include all the respective
    // -inl.h headers for SLOW_DCHECKs.
    SLOW_DCHECK(IsDereferenceAllowed());
    return Tagged<T>(*location());
  }

  // Consider declaring values that contain empty handles as
  // MaybeHandle to force validation before being used as handles.
  static const Handle<T> null() { return Handle<T>(); }

  // Location equality.
  bool equals(Handle<T> other) const { return address() == other.address(); }

  // Patches this Handle's value, in-place, with a new value. All handles with
  // the same location will see this update.
  void PatchValue(Tagged<T> new_value) {
    SLOW_DCHECK(location_ != nullptr && IsDereferenceAllowed());
    *location_ = new_value.ptr();
  }

  // Provide function object for location equality comparison.
  struct equal_to {
    V8_INLINE bool operator()(Handle<T> lhs, Handle<T> rhs) const {
      return lhs.equals(rhs);
    }
  };

  // Provide function object for location hashing.
  struct hash {
    V8_INLINE size_t operator()(Handle<T> const& handle) const {
      return base::hash<Address>()(handle.address());
    }
  };

 private:
  // Handles of different classes are allowed to access each other's location_.
  template <typename>
  friend class Handle;
  // MaybeHandle is allowed to access location_.
  template <typename>
  friend class MaybeHandle;
  // Casts are allowed to access location_.
  template <typename To, typename From>
  friend inline Handle<To> UncheckedCast(Handle<From> value);
};

template <typename T>
std::ostream& operator<<(std::ostream& os, Handle<T> handle);

// ----------------------------------------------------------------------------
// A stack-allocated class that governs a number of local handles.
// After a handle scope has been created, all local handles will be
// allocated within that handle scope until either the handle scope is
// deleted or another handle scope is created.  If there is already a
// handle scope and a new one is created, all allocations will take
// place in the new handle scope until it is deleted.  After that,
// new handles will again be allocated in the original handle scope.
//
// After the handle scope of a local handle has been deleted the
// garbage collector will no longer track the object stored in the
// handle and may deallocate it.  The behavior of accessing a handle
// for which the handle scope has been deleted is undefined.
class V8_NODISCARD HandleScope {
 public:
  explicit V8_INLINE HandleScope(Isolate* isolate);
  inline HandleScope(HandleScope&& other) V8_NOEXCEPT;
  HandleScope(const HandleScope&) = delete;
  HandleScope& operator=(const HandleScope&) = delete;

  // Allow placement new.
  void* operator new(size_t size, void* storage) {
    return ::operator new(size, storage);
  }

  // Prevent heap allocation or illegal handle scopes.
  void* operator new(size_t size) = delete;
  void operator delete(void* size_t) = delete;

  V8_INLINE ~HandleScope();

  inline HandleScope& operator=(HandleScope&& other) V8_NOEXCEPT;

  // Counts the number of allocated handles.
  V8_EXPORT_PRIVATE static int NumberOfHandles(Isolate* isolate);

  // Creates a new handle with the given value.
  V8_INLINE static Address* CreateHandle(Isolate* isolate, Address value);

  // Deallocates any extensions used by the current scope.
  V8_EXPORT_PRIVATE static void DeleteExtensions(Isolate* isolate);

  static Address current_next_address(Isolate* isolate);
  static Address current_limit_address(Isolate* isolate);
  static Address current_level_address(Isolate* isolate);

  // Closes the HandleScope (invalidating all handles
  // created in the scope of the HandleScope) and returns
  // a Handle backed by the parent scope holding the
  // value of the argument handle.
  //
  // TODO(42203211): When direct handles are enabled, the version with
  // HandleType = DirectHandle does not need to be called, as it simply
  // closes the scope (which is done by the scope's destructor anyway)
  // and returns its parameter. This will be cleaned up after direct
  // handles ship.
  template <typename T, template <typename> typename HandleType,
            typename = std::enable_if_t<
                std::is_convertible_v<HandleType<T>, DirectHandle<T>>>>
  HandleType<T> CloseAndEscape(HandleType<T> handle_value);

  Isolate* isolate() { return isolate_; }

  // Limit for number of handles with --check-handle-count. This is
  // large enough to compile natives and pass unit tests with some
  // slack for future changes to natives.
  static const int kCheckHandleThreshold = 30 * 1024;

 private:
  Isolate* isolate_;
  Address* prev_next_;
  Address* prev_limit_;

#ifdef V8_ENABLE_CHECKS
  int scope_level_ = 0;
#endif

  // Close the handle scope resetting limits to a previous state.
  static V8_INLINE void CloseScope(Isolate* isolate, Address* prev_next,
                                   Address* prev_limit);

  // Extend the handle scope making room for more handles.
  V8_EXPORT_PRIVATE V8_NOINLINE static Address* Extend(Isolate* isolate);

#ifdef ENABLE_HANDLE_ZAPPING
  // Zaps the handles in the half-open interval [start, end).
  V8_EXPORT_PRIVATE static void ZapRange(Address* start, Address* end);
#endif

  friend class v8::HandleScope;
  friend class HandleScopeImplementer;
  friend class Isolate;
  friend class LocalHandles;
  friend class LocalHandleScope;
  friend class PersistentHandles;
};

// Forward declaration for CanonicalHandlesMap.
template <typename V, class AllocationPolicy>
class IdentityMap;

using CanonicalHandlesMap = IdentityMap<Address*, ZoneAllocationPolicy>;

// Seal off the current HandleScope so that new handles can only be created
// if a new HandleScope is entered.
class V8_NODISCARD SealHandleScope final {
 public:
#ifndef DEBUG
  explicit SealHandleScope(Isolate* isolate) {}
  ~SealHandleScope() = default;
#else
  explicit inline SealHandleScope(Isolate* isolate);
  inline ~SealHandleScope();

 private:
  Isolate* isolate_;
  Address* prev_limit_;
  int prev_sealed_level_;
#endif
};

struct HandleScopeData final {
  static constexpr uint32_t kSizeInBytes =
      2 * kSystemPointerSize + 2 * kInt32Size;

  Address* next;
  Address* limit;
  int level;
  int sealed_level;

  void Initialize() {
    next = limit = nullptr;
    sealed_level = level = 0;
  }
};

static_assert(HandleScopeData::kSizeInBytes == sizeof(HandleScopeData));

template <typename T>
struct is_direct_handle : public std::false_type {};
template <typename T>
static constexpr bool is_direct_handle_v = is_direct_handle<T>::value;

#ifdef V8_ENABLE_DIRECT_HANDLE
// Direct handles should not be used without conservative stack scanning,
// as this would break the correctness of the GC.
static_assert(V8_ENABLE_CONSERVATIVE_STACK_SCANNING_BOOL);

// ----------------------------------------------------------------------------
// Base class for DirectHandle instantiations. Don't use directly.
class V8_TRIVIAL_ABI DirectHandleBase :
#ifdef DEBUG
    public api_internal::StackAllocated<true>
#else
    public api_internal::StackAllocated<false>
#endif
{
 public:
  // Check if this handle refers to the exact same object as the other handle.
  V8_INLINE bool is_identical_to(const HandleBase& that) const;
  V8_INLINE bool is_identical_to(const DirectHandleBase& that) const;
  V8_INLINE bool is_null() const { return obj_ == kTaggedNullAddress; }

  V8_INLINE Address address() const { return obj_; }

  V8_INLINE ValueHelper::InternalRepresentationType repr() const {
    return obj_;
  }

#ifdef DEBUG
  // Counts the number of allocated handles for the current thread that are
  // below the stack marker. The number is only accurate if
  // V8_HAS_ATTRIBUTE_TRIVIAL_ABI, otherwise it's zero.
  V8_INLINE static int NumberOfHandles() { return number_of_handles_; }

  // Scope to temporarily reset the number of allocated handles.
  class V8_NODISCARD ResetNumberOfHandlesScope {
   public:
    ResetNumberOfHandlesScope() : saved_number_of_handles_(number_of_handles_) {
      number_of_handles_ = 0;
    }
    ~ResetNumberOfHandlesScope() {
      number_of_handles_ = saved_number_of_handles_;
    }

   private:
    int saved_number_of_handles_;
  };
#else
  class V8_NODISCARD ResetNumberOfHandlesScope {};
#endif  // DEBUG

 protected:
  friend class HandleBase;

#if defined(DEBUG) && V8_HAS_ATTRIBUTE_TRIVIAL_ABI
  // In this case, DirectHandleBase becomes not trivially copyable.
  V8_INLINE DirectHandleBase(const DirectHandleBase& other) V8_NOEXCEPT
      : obj_(other.obj_) {
    Register();
  }
  DirectHandleBase& operator=(const DirectHandleBase&) V8_NOEXCEPT = default;
  V8_INLINE ~DirectHandleBase() V8_NOEXCEPT { Unregister(); }
#endif

  V8_INLINE explicit DirectHandleBase(Address object) : obj_(object) {
    Register();
  }

#ifdef DEBUG
  V8_EXPORT_PRIVATE bool IsDereferenceAllowed() const;
#else
  V8_INLINE bool IsDereferenceAllowed() const { return true; }
#endif  // DEBUG

  DirectHandleBase(Address obj, no_checking_tag do_not_check)
      : StackAllocated(do_not_check), obj_(obj) {
    Register();
  }

  // This is a direct pointer to either a tagged object or SMI. Design overview:
  // https://docs.google.com/document/d/1uRGYQM76vk1fc_aDqDH3pm2qhaJtnK2oyzeVng4cS6I/
  Address obj_;

 private:
  V8_INLINE void Register() {
#if defined(DEBUG) && V8_HAS_ATTRIBUTE_TRIVIAL_ABI
    ++number_of_handles_;
#endif
  }

  V8_INLINE void Unregister() {
#if defined(DEBUG) && V8_HAS_ATTRIBUTE_TRIVIAL_ABI
    DCHECK_LT(0, number_of_handles_);
    --number_of_handles_;
#endif
  }

#ifdef DEBUG
  inline static thread_local int number_of_handles_ = 0;
#endif
};

// ----------------------------------------------------------------------------
// A DirectHandle provides a reference to an object without an intermediate
// pointer.
//
// A DirectHandle is a simple wrapper around a tagged pointer to a heap object
// or a SMI. Its methods are symmetrical with Handle, so that Handles can be
// easily migrated.
//
// DirectHandles are intended to be used with conservative stack scanning, as
// they do not provide a mechanism for keeping an object alive across a garbage
// collection.
//
// Further motivation is explained in the design doc:
// https://docs.google.com/document/d/1uRGYQM76vk1fc_aDqDH3pm2qhaJtnK2oyzeVng4cS6I/
template <typename T>
class DirectHandle : public DirectHandleBase {
 public:
  // Handles denote strong references.
  static_assert(!is_maybe_weak_v<T>);

  V8_INLINE DirectHandle() : DirectHandle(kTaggedNullAddress) {}

  V8_INLINE explicit DirectHandle(Address object) : DirectHandleBase(object) {}

  V8_INLINE DirectHandle(Tagged<T> object, Isolate* isolate)
      : DirectHandle(object) {}
  V8_INLINE DirectHandle(Tagged<T> object, LocalIsolate* isolate)
      : DirectHandle(object) {}
  V8_INLINE DirectHandle(Tagged<T> object, LocalHeap* local_heap)
      : DirectHandle(object) {}

  V8_INLINE explicit DirectHandle(Address* address)
      : DirectHandle(address == nullptr ? kTaggedNullAddress : *address) {}

  V8_INLINE static DirectHandle<T> New(Tagged<T> object, Isolate* isolate) {
    return DirectHandle<T>(object);
  }

  // Constructor for handling automatic up casting.
  // Ex. DirectHandle<JSFunction> can be passed when DirectHandle<Object> is
  // expected.
  template <typename S, typename = std::enable_if_t<is_subtype_v<S, T>>>
  V8_INLINE DirectHandle(DirectHandle<S> handle) : DirectHandle(handle.obj_) {}

  template <typename S, typename = std::enable_if_t<is_subtype_v<S, T>>>
  V8_INLINE DirectHandle(Handle<S> handle)
      : DirectHandle(handle.location() != nullptr ? *handle.location()
                                                  : kTaggedNullAddress) {}

  V8_INLINE Tagged<T> operator->() const {
    if constexpr (is_subtype_v<T, HeapObject>) {
      return **this;
    } else {
      // For non-HeapObjects, there's no on-heap object to dereference, so
      // disallow using operator->.
      //
      // If you got an error here and want to access the Tagged<T>, use
      // operator* -- e.g. for `Tagged<Smi>::value()`, use `(*handle).value()`.
      static_assert(
          false,
          "This handle does not reference a heap object. Use `(*handle).foo`.");
    }
  }

  V8_INLINE Tagged<T> operator*() const {
    // This static type check also fails for forward class declarations. We
    // check on access instead of on construction to allow DirectHandles to
    // forward declared types.
    static_assert(is_taggable_v<T>, "static type violation");
    // Direct construction of Tagged from address, without a type check, because
    // we rather trust DirectHandle<T> to contain a T than include all the
    // respective -inl.h headers for SLOW_DCHECKs.
    SLOW_DCHECK(IsDereferenceAllowed());
    return Tagged<T>(address());
  }

  // Consider declaring values that contain empty handles as
  // MaybeDirectHandle to force validation before being used as handles.
  V8_INLINE static const DirectHandle<T> null() { return DirectHandle<T>(); }

  // Address equality.
  bool equals(DirectHandle<T> other) const {
    return address() == other.address();
  }

  // Sets this DirectHandle's value. This is equivalent to handle assignment,
  // except for the check that is equivalent to that performed in
  // Handle<T>::PatchValue.
  void PatchValue(Tagged<T> new_value) {
    SLOW_DCHECK(obj_ != kTaggedNullAddress && IsDereferenceAllowed());
    obj_ = new_value.ptr();
  }

 private:
  // DirectHandles of different classes are allowed to access each other's
  // obj_.
  template <typename>
  friend class DirectHandle;
  // MaybeDirectHandle is allowed to access obj_.
  template <typename>
  friend class MaybeDirectHandle;
  friend class DirectHandleUnchecked<T>;
  // Casts are allowed to access obj_.
  template <typename To, typename From>
  friend inline DirectHandle<To> UncheckedCast(DirectHandle<From> value);

  V8_INLINE explicit DirectHandle(Tagged<T> object);

  explicit DirectHandle(no_checking_tag do_not_check)
      : DirectHandleBase(kTaggedNullAddress, do_not_check) {}
  explicit DirectHandle(const DirectHandle<T>& other,
                        no_checking_tag do_not_check)
      : DirectHandleBase(other.obj_, do_not_check) {}
};

template <typename T>
IndirectHandle<T> indirect_handle(DirectHandle<T> handle) {
  if (handle.is_null()) return IndirectHandle<T>();
  return IndirectHandle<T>(HandleBase::indirect_handle(handle.address()));
}

template <typename T>
IndirectHandle<T> indirect_handle(DirectHandle<T> handle, Isolate* isolate) {
  if (handle.is_null()) return IndirectHandle<T>();
  return IndirectHandle<T>(
      HandleBase::indirect_handle(handle.address(), isolate));
}

template <typename T>
IndirectHandle<T> indirect_handle(DirectHandle<T> handle,
                                  LocalIsolate* isolate) {
  if (handle.is_null()) return IndirectHandle<T>();
  return IndirectHandle<T>(
      HandleBase::indirect_handle(handle.address(), isolate));
}

template <typename T>
IndirectHandle<T> indirect_handle(DirectHandle<T> handle,
                                  LocalHeap* local_heap) {
  if (handle.is_null()) return IndirectHandle<T>();
  return IndirectHandle<T>(
      HandleBase::indirect_handle(handle.address(), local_heap));
}

// A variant of DirectHandle that is suitable for off-stack allocation.
// Used internally by DirectHandleVector<T>. Not to be used directly!
template <typename T>
class V8_TRIVIAL_ABI DirectHandleUnchecked final : public DirectHandle<T> {
 public:
  DirectHandleUnchecked() : DirectHandle<T>(DirectHandle<T>::do_not_check) {}

#if defined(DEBUG) && V8_HAS_ATTRIBUTE_TRIVIAL_ABI
  // In this case, the check is also enforced in the copy constructor and we
  // need to suppress it.
  DirectHandleUnchecked(const DirectHandleUnchecked& other) V8_NOEXCEPT
      : DirectHandle<T>(other, DirectHandle<T>::do_not_check) {}
  DirectHandleUnchecked& operator=(const DirectHandleUnchecked&)
      V8_NOEXCEPT = default;
#endif

  // Implicit conversion from DirectHandle.
  DirectHandleUnchecked(const DirectHandle<T>& other)
      V8_NOEXCEPT  // NOLINT(runtime/explicit)
      : DirectHandle<T>(other, DirectHandle<T>::do_not_check) {}
};

// Off-stack allocated direct handles must be registered as strong roots.
// For off-stack indirect handles, this is not necessary.
template <typename T>
class StrongRootAllocator<DirectHandleUnchecked<T>>
    : public StrongRootAllocatorBase {
 public:
  using value_type = DirectHandleUnchecked<T>;
  static_assert(std::is_standard_layout_v<value_type>);
  static_assert(sizeof(value_type) == sizeof(Address));

  template <typename HeapOrIsolateT>
  explicit StrongRootAllocator(HeapOrIsolateT* heap_or_isolate)
      : StrongRootAllocatorBase(heap_or_isolate) {}
  template <typename U>
  StrongRootAllocator(const StrongRootAllocator<U>& other) noexcept
      : StrongRootAllocatorBase(other) {}

  value_type* allocate(size_t n) {
    return reinterpret_cast<value_type*>(allocate_impl(n));
  }
  void deallocate(value_type* p, size_t n) noexcept {
    return deallocate_impl(reinterpret_cast<Address*>(p), n);
  }
};

template <typename T>
class DirectHandleVector {
 private:
  using element_type = internal::DirectHandleUnchecked<T>;

  using allocator_type = internal::StrongRootAllocator<element_type>;

  template <typename IsolateT>
  static allocator_type make_allocator(IsolateT* isolate) noexcept {
    return allocator_type(isolate);
  }

  using vector_type = std::vector<element_type, allocator_type>;

 public:
  using value_type = DirectHandle<T>;
  using reference = value_type&;
  using const_reference = const value_type&;
  using size_type = size_t;
  using difference_type = ptrdiff_t;
  using iterator = internal::WrappedIterator<typename vector_type::iterator,
                                             DirectHandle<T>>;
  using const_iterator =
      internal::WrappedIterator<typename vector_type::const_iterator,
                                const DirectHandle<T>>;

  template <typename IsolateT>
  explicit DirectHandleVector(IsolateT* isolate)
      : backing_(make_allocator(isolate)) {}
  template <typename IsolateT>
  DirectHandleVector(IsolateT* isolate, size_t n)
      : backing_(n, make_allocator(isolate)) {}
  template <typename IsolateT>
  DirectHandleVector(IsolateT* isolate,
                     std::initializer_list<DirectHandle<T>> init)
      : backing_(make_allocator(isolate)) {
    if (init.size() == 0) return;
    backing_.reserve(init.size());
    backing_.insert(backing_.end(), init.begin(), init.end());
  }

  iterator begin() noexcept { return iterator(backing_.begin()); }
  const_iterator begin() const noexcept {
    return const_iterator(backing_.begin());
  }
  iterator end() noexcept { return iterator(backing_.end()); }
  const_iterator end() const noexcept { return const_iterator(backing_.end()); }

  size_t size() const noexcept { return backing_.size(); }
  bool empty() const noexcept { return backing_.empty(); }
  void reserve(size_t n) { backing_.reserve(n); }
  void shrink_to_fit() { backing_.shrink_to_fit(); }

  DirectHandle<T>& operator[](size_t n) { return backing_[n]; }
  const DirectHandle<T>& operator[](size_t n) const { return backing_[n]; }

  DirectHandle<T>& at(size_t n) { return backing_.at(n); }
  const DirectHandle<T>& at(size_t n) const { return backing_.at(n); }

  DirectHandle<T>& front() { return backing_.front(); }
  const DirectHandle<T>& front() const { return backing_.front(); }
  DirectHandle<T>& back() { return backing_.back(); }
  const DirectHandle<T>& back() const { return backing_.back(); }

  DirectHandle<T>* data() noexcept { return backing_.data(); }
  const DirectHandle<T>* data() const noexcept { return backing_.data(); }

  iterator insert(const_iterator pos, const DirectHandle<T>& value) {
    return iterator(backing_.insert(pos.base(), value));
  }

  template <typename InputIt>
  iterator insert(const_iterator pos, InputIt first, InputIt last) {
    return iterator(backing_.insert(pos.base(), first, last));
  }

  iterator insert(const_iterator pos,
                  std::initializer_list<DirectHandle<T>> init) {
    return iterator(backing_.insert(pos.base(), init.begin(), init.end()));
  }

  DirectHandleVector<T>& operator=(
      std::initializer_list<DirectHandle<T>> init) {
    backing_.clear();
    backing_.reserve(init.size());
    backing_.insert(backing_.end(), init.begin(), init.end());
    return *this;
  }

  void push_back(const DirectHandle<T>& x) { backing_.push_back(x); }
  void pop_back() { backing_.pop_back(); }

  template <typename... Args>
  void emplace_back(Args&&... args) {
    backing_.push_back(value_type{std::forward<Args>(args)...});
  }

  void clear() noexcept { backing_.clear(); }
  void resize(size_t n) { backing_.resize(n); }
  void swap(DirectHandleVector<T>& other) { backing_.swap(other.backing_); }

  friend bool operator==(const DirectHandleVector<T>& x,
                         const DirectHandleVector<T>& y) {
    return x.backing_ == y.backing_;
  }
  friend bool operator!=(const DirectHandleVector<T>& x,
                         const DirectHandleVector<T>& y) {
    return x.backing_ != y.backing_;
  }
  friend bool operator<(const DirectHandleVector<T>& x,
                        const DirectHandleVector<T>& y) {
    return x.backing_ < y.backing_;
  }
  friend bool operator>(const DirectHandleVector<T>& x,
                        const DirectHandleVector<T>& y) {
    return x.backing_ > y.backing_;
  }
  friend bool operator<=(const DirectHandleVector<T>& x,
                         const DirectHandleVector<T>& y) {
    return x.backing_ <= y.backing_;
  }
  friend bool operator>=(const DirectHandleVector<T>& x,
                         const DirectHandleVector<T>& y) {
    return x.backing_ >= y.backing_;
  }

 private:
  vector_type backing_;
};
#else   // !V8_ENABLE_DIRECT_HANDLE

// ----------------------------------------------------------------------------
// When conservative stack scanning is disabled, DirectHandle is a wrapper
// around IndirectHandle (i.e. Handle). To preserve conservative stack scanning
// semantics, DirectHandle be implicitly created from an IndirectHandle, but
// does not implicitly convert to an IndirectHandle.
template <typename T>
class DirectHandle {
 public:
  V8_INLINE static const DirectHandle null() {
    return DirectHandle(Handle<T>::null());
  }
  V8_INLINE static DirectHandle<T> New(Tagged<T> object, Isolate* isolate) {
    return DirectHandle(Handle<T>::New(object, isolate));
  }

  V8_INLINE DirectHandle() = default;

  V8_INLINE DirectHandle(Tagged<T> object, Isolate* isolate)
      : handle_(object, isolate) {}
  V8_INLINE DirectHandle(Tagged<T> object, LocalIsolate* isolate)
      : handle_(object, isolate) {}
  V8_INLINE DirectHandle(Tagged<T> object, LocalHeap* local_heap)
      : handle_(object, local_heap) {}

  template <typename S, typename = std::enable_if_t<is_subtype_v<S, T>>>
  V8_INLINE DirectHandle(DirectHandle<S> handle) : handle_(handle.handle_) {}

  template <typename S, typename = std::enable_if_t<is_subtype_v<S, T>>>
  V8_INLINE DirectHandle(IndirectHandle<S> handle) : handle_(handle) {}

  V8_INLINE IndirectHandle<T> operator->() const { return handle_; }
  V8_INLINE Tagged<T> operator*() const { return *handle_; }
  V8_INLINE bool is_null() const { return handle_.is_null(); }
  V8_INLINE Address* location() const { return handle_.location(); }
  V8_INLINE void PatchValue(Tagged<T> new_value) {
    handle_.PatchValue(new_value);
  }
  V8_INLINE bool equals(DirectHandle<T> other) const {
    return handle_.equals(other.handle_);
  }
  V8_INLINE bool is_identical_to(DirectHandle<T> other) const {
    return handle_.is_identical_to(other.handle_);
  }

 private:
  // DirectHandles of different classes are allowed to access each other's
  // handle_.
  template <typename>
  friend class DirectHandle;
  // MaybeDirectHandle is allowed to access handle_.
  template <typename>
  friend class MaybeDirectHandle;
  // Casts are allowed to access handle_.
  template <typename To, typename From>
  friend inline DirectHandle<To> UncheckedCast(DirectHandle<From> value);
  template <typename U>
  friend inline IndirectHandle<U> indirect_handle(DirectHandle<U>);
  template <typename U>
  friend inline IndirectHandle<U> indirect_handle(DirectHandle<U>, Isolate*);
  template <typename U>
  friend inline IndirectHandle<U> indirect_handle(DirectHandle<U>,
                                                  LocalIsolate*);
  template <typename U>
  friend inline IndirectHandle<U> indirect_handle(DirectHandle<U>, LocalHeap*);

  IndirectHandle<T> handle_;
};

template <typename T>
V8_INLINE IndirectHandle<T> indirect_handle(DirectHandle<T> handle) {
  return handle.handle_;
}

template <typename T>
V8_INLINE IndirectHandle<T> indirect_handle(DirectHandle<T> handle,
                                            Isolate* isolate) {
  return handle.handle_;
}

template <typename T>
V8_INLINE IndirectHandle<T> indirect_handle(DirectHandle<T> handle,
                                            LocalIsolate* isolate) {
  return handle.handle_;
}

template <typename T>
V8_INLINE IndirectHandle<T> indirect_handle(DirectHandle<T> handle,
                                            LocalHeap* local_heap) {
  return handle.handle_;
}

template <typename T>
class DirectHandleVector : public std::vector<DirectHandle<T>> {
 public:
  template <typename IsolateT>
  explicit DirectHandleVector(IsolateT* isolate)
      : std::vector<DirectHandle<T>>() {}
  template <typename IsolateT>
  DirectHandleVector(IsolateT* isolate, size_t n)
      : std::vector<DirectHandle<T>>(n) {}
  template <typename IsolateT>
  DirectHandleVector(IsolateT* isolate,
                     std::initializer_list<DirectHandle<T>> init)
      : std::vector<DirectHandle<T>>(init) {}
};
#endif  // V8_ENABLE_
```