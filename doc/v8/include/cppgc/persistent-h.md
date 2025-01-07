Response:
Let's break down the thought process for analyzing the `persistent.h` header file.

**1. Initial Scan and High-Level Understanding:**

First, I'd quickly read through the comments and class/template names to get a general idea of the file's purpose. Keywords like "Persistent," "WeakPersistent," "strong pointer," "weak pointer," "GC root" immediately jump out. This tells me it's about managing object lifetimes and garbage collection.

**2. Examining the `PersistentBase` Class:**

* **Purpose:** The comment "PersistentBase always refers to the object as const object..." suggests it's a foundation for the more specialized persistent types. It manages the raw pointer and a `PersistentNode`.
* **Members:** `raw_` (the actual pointer) and `node_` (related to GC management). The `mutable` keyword is interesting – it allows modification even in `const` contexts.
* **Methods:** `GetValue`, `SetValue`, `GetNode`, `SetNode`, `ClearFromGC`. These are basic accessors and manipulators. `ClearFromGC` being separate suggests a distinction between general clearing and GC-specific clearing.

**3. Deep Dive into the `BasicPersistent` Template:**

This is the core of the file. The template parameters are a key focus:

* `T`: The type of the pointed-to object.
* `WeaknessPolicy`:  Strong or weak persistence. This is crucial.
* `LocationPolicy`: Seems related to where the persistent handle is created (source location).
* `CheckingPolicy`:  Likely for debugging or assertions.

**Constructor Analysis:**

I'd go through each constructor and understand its purpose:

* **Null/Sentinel constructors:** Creating empty or invalid persistent handles.
* **Raw pointer/reference constructors:** Creating a persistent handle from an existing object. The allocation of a `PersistentNode` here is important for GC interaction.
* **Copy/Move constructors:** Standard C++ practices, but the handling of the `PersistentNode` in the move constructor is noteworthy (transferring ownership).
* **Heterogeneous constructor:** Allowing assignment from persistent handles of base classes.
* **Constructor from `BasicMember`:**  Integration with another type of pointer/reference within the `cppgc` system.

**Method Analysis:**

* **Destructor (`~BasicPersistent`)**:  Crucially calls `Clear()` to release resources.
* **Assignment Operators (`=`):**  Handling both copy and move semantics, as well as assignment from raw pointers and other persistent types. The reuse or allocation of `PersistentNode` is a key detail.
* **`operator bool()`, `operator T*()`, `operator->()`, `operator*()`:** Providing convenient ways to access the underlying object.
* **`Get()`:**  The primary way to get the raw pointer. The comment about `const_cast` and `static_cast` explains how const correctness is maintained.
* **`Clear()`:** Releases the `PersistentNode` and sets the raw pointer to null.
* **`Release()`:**  Returns the raw pointer and then clears the persistent handle.
* **`To()`:**  Allows casting to a persistent handle of a base class.
* **`TraceAsRoot()`:**  A static method essential for the garbage collector to identify this persistent handle as a root.
* **`IsValid()`:** Checks if the persistent handle is currently pointing to a valid object.
* **`Assign()`:**  Handles the core logic of setting the pointer and managing the `PersistentNode`, including reuse when possible.
* **`ClearFromGC()`:**  Similar to the `PersistentBase` method, clearing the raw pointer and node.
* **`GetFromGC()`:** Another way to get the raw pointer, specifically used by the GC.

**Template Specialization (`IsWeak`):**

This confirms that `WeakPersistent` is indeed considered a weak reference.

**Type Aliases (`Persistent`, `WeakPersistent`):**

These simplify the usage of `BasicPersistent` with the appropriate `WeaknessPolicy`.

**4. Addressing Specific Questions from the Prompt:**

* **Functionality:**  Summarize the core purpose and mechanisms of `Persistent` and `WeakPersistent`.
* **`.tq` Extension:**  Explicitly state that `.h` indicates a C++ header file, not Torque.
* **JavaScript Relation:** This requires thinking about how V8 exposes C++ objects to JavaScript. The concept of garbage collection and object lifetime management is key. Examples using closures and the need to keep objects alive would be relevant.
* **Code Logic Inference:**  Choose a specific method (e.g., the constructor or assignment operator) and trace its execution with hypothetical inputs, focusing on `PersistentNode` management.
* **Common Programming Errors:** Think about scenarios where incorrect usage of persistent handles could lead to problems, such as dangling pointers, memory leaks (though `Persistent` aims to prevent this), and accessing collected objects with `WeakPersistent`.

**5. Structuring the Output:**

Organize the findings clearly, using headings and bullet points. Provide code examples in both C++ and JavaScript where applicable. Explain the reasoning behind the answers.

**Self-Correction/Refinement During Analysis:**

* **Initial Assumption:**  I might initially assume `LocationPolicy` and `CheckingPolicy` are more complex, but a quick look at their usage suggests they are relatively simple.
* **Focus on Core Concepts:**  Ensure the explanation emphasizes the garbage collection aspects and the difference between strong and weak persistence.
* **Clarity of Examples:**  Make sure the JavaScript examples are concise and directly illustrate the concept being explained.
* **Accuracy of Technical Details:** Double-check the behavior of constructors, assignment operators, and the role of `PersistentNode`.

By following these steps, I can systematically analyze the `persistent.h` file and provide a comprehensive and accurate explanation of its functionality.
This C++ header file, `v8/include/cppgc/persistent.h`, defines smart pointer-like types called `Persistent` and `WeakPersistent` for managing the lifetime of heap-allocated C++ objects within the V8 garbage collection system (`cppgc`).

Here's a breakdown of its functionality:

**Core Functionality:**

* **Managing Object Lifetimes:**  The primary purpose is to control how long objects allocated on the V8 garbage-collected heap remain alive.
* **`Persistent<T>` (Strong Persistent Handle):**  Creates a strong reference to an object of type `T`. As long as a `Persistent<T>` instance exists and is reachable, the garbage collector will **not** collect the pointed-to object. It essentially roots the object, making it a starting point for reachability analysis.
* **`WeakPersistent<T>` (Weak Persistent Handle):** Creates a weak reference to an object of type `T`. A `WeakPersistent<T>` does **not** prevent the garbage collector from collecting the pointed-to object if there are no other strong references. After the object is collected, the `WeakPersistent<T>` will automatically be set to null.
* **Integration with `cppgc`:** These types are designed to work seamlessly with V8's garbage collection mechanism. They inform the collector about which objects need to be kept alive and which can be collected.
* **Off-Heap to On-Heap Relationships:**  `Persistent` and `WeakPersistent` are typically used when an object living outside the garbage-collected heap (e.g., a stack-allocated object or a global variable) needs to hold a reference to an object within the heap.
* **Thread Safety:** The comments indicate that `Persistent` and `WeakPersistent` must be constructed and destructed in the same thread.

**Detailed Breakdown of Classes and Templates:**

* **`PersistentBase`:**  A base class that handles the underlying storage of the raw pointer (`raw_`) and a `PersistentNode` (`node_`) which is likely used by the garbage collector to track these persistent handles. It deals with basic operations like getting and setting the value and the node.
* **`BasicPersistent<T, WeaknessPolicy, LocationPolicy, CheckingPolicy>`:**  A template class that forms the basis for both `Persistent` and `WeakPersistent`.
    * **`T`:** The type of the object being pointed to.
    * **`WeaknessPolicy`:**  Determines whether the handle is strong (`internal::StrongPersistentPolicy`) or weak (`internal::WeakPersistentPolicy`). This is the key differentiator between `Persistent` and `WeakPersistent`.
    * **`LocationPolicy`:**  Likely tracks the source code location where the persistent handle was created (for debugging or analysis).
    * **`CheckingPolicy`:** Might involve runtime checks or assertions related to the persistent handle's state.
    * **Constructors:**  Provides various ways to create persistent handles: from raw pointers, references, null pointers, other persistent handles (copy and move), and even from members of other managed objects.
    * **Assignment Operators:**  Overloads the `=` operator to allow assigning raw pointers, null pointers, and other persistent handles.
    * **`operator bool()`, `operator T*()`, `operator->()`, `operator*()`:**  Provides convenient ways to access the underlying object, making `Persistent` and `WeakPersistent` behave somewhat like raw pointers.
    * **`Get()`:** Returns the underlying raw pointer to the object.
    * **`Clear()`:**  Releases the reference to the object. For strong persistents, this might involve informing the GC that this root is no longer active. For weak persistents, it just clears the pointer.
    * **`Release()`:** Returns the raw pointer and then clears the persistent handle.
    * **`To<U>()`:** Allows casting the persistent handle to a persistent handle of a base class.
    * **`TraceAsRoot()` (static):**  A crucial method called by the garbage collector. For strong persistents, this tells the GC to consider the pointed-to object as a root, preventing its collection.
    * **`IsValid()`:** Checks if the persistent handle is currently pointing to a valid object (not null and not the sentinel pointer).
    * **`Assign()`:**  Handles the logic of setting the pointer and updating the garbage collector's internal structures.
    * **`ClearFromGC()`:**  A version of `Clear` specifically intended for use by the garbage collector.
    * **`GetFromGC()`:**  A version of `Get` specifically intended for use by the garbage collector.
* **Type Aliases:**
    * **`Persistent<T>`:**  A convenient alias for `BasicPersistent<T, internal::StrongPersistentPolicy>`.
    * **`WeakPersistent<T>`:** A convenient alias for `BasicPersistent<T, internal::WeakPersistentPolicy>`.

**Is `v8/include/cppgc/persistent.h` a Torque source file?**

No. The file extension `.h` indicates that it's a standard C++ header file. Torque source files typically have the extension `.tq`.

**Relationship with JavaScript and Examples:**

`Persistent` and `WeakPersistent` are crucial for bridging the gap between V8's C++ implementation and the JavaScript environment. V8 often needs to create C++ objects that represent or manage JavaScript objects or their internal state. These C++ objects need to be kept alive as long as the corresponding JavaScript objects are reachable.

**Example (Illustrative, might not be directly compilable without surrounding V8 context):**

```javascript
// Imagine a C++ class representing a native object accessible from JavaScript
class NativeCounter {
public:
  NativeCounter() : count_(0) {}
  void increment() { ++count_; }
  int getCount() const { return count_; }
private:
  int count_;
};

// In C++ (within a V8 context):
#include "cppgc/persistent.h"

namespace my_native_module {

cppgc::Persistent<NativeCounter> global_counter;

// Function called when a JavaScript NativeCounter object is created
void CreateNativeCounter() {
  global_counter = cppgc::MakeGarbageCollected<NativeCounter>();
}

// Function called when the JavaScript NativeCounter object is being finalized
void DestroyNativeCounter() {
  global_counter.Reset(); // Or simply let it go out of scope
}

// Function accessible from JavaScript to increment the counter
void IncrementCounter() {
  if (global_counter) {
    global_counter->increment();
  }
}

// Function accessible from JavaScript to get the counter value
int GetCounterValue() {
  if (global_counter) {
    return global_counter->getCount();
  }
  return -1; // Or some error indication
}

} // namespace my_native_module

// In JavaScript:
let counter = new NativeCounter(); // Assuming NativeCounter is exposed
counter.increment();
console.log(counter.getCount());

// The 'global_counter' Persistent in C++ ensures that the C++ NativeCounter
// instance stays alive as long as the JavaScript 'counter' object is reachable.
```

**Explanation of the Example:**

* The C++ code uses `cppgc::Persistent<NativeCounter>` to hold a pointer to a `NativeCounter` object.
* When the JavaScript `new NativeCounter()` is invoked (through some V8 binding mechanism), the C++ `CreateNativeCounter()` function is called, creating a `NativeCounter` on the garbage-collected heap and storing it in `global_counter`.
* The `global_counter` `Persistent` acts as a root, preventing the C++ `NativeCounter` from being collected as long as `global_counter` itself is alive.
* JavaScript can then call methods like `increment()` and `getCount()`, which delegate to the corresponding C++ methods via the `global_counter` pointer.
* If `global_counter` were a `WeakPersistent`, the C++ `NativeCounter` could be collected even if the JavaScript `counter` object exists, potentially leading to crashes or unexpected behavior when trying to access the native object.

**Code Logic Inference (Hypothetical):**

**Scenario:** Creating and assigning a strong persistent handle.

**Assumption:** We have a garbage-collected class `MyObject`.

**Input:**
```c++
#include "cppgc/persistent.h"
#include "cppgc/garbage-collected.h"

class MyObject : public cppgc::GarbageCollected<MyObject> {
public:
  int value;
};

void test() {
  cppgc::Persistent<MyObject> persistent_obj; // Initially null
  MyObject* raw_obj = cppgc::MakeGarbageCollected<MyObject>();
  raw_obj->value = 42;
  persistent_obj = raw_obj;
  // ...
}
```

**Output/Inference:**

1. **`cppgc::Persistent<MyObject> persistent_obj;`**:
   - The default constructor of `BasicPersistent` (with `StrongPersistentPolicy`) is called.
   - `persistent_obj.GetValue()` will be `nullptr`.
   - `persistent_obj.GetNode()` will be `nullptr`.

2. **`MyObject* raw_obj = cppgc::MakeGarbageCollected<MyObject>();`**:
   - An instance of `MyObject` is allocated on the garbage-collected heap.
   - `raw_obj` points to this newly allocated object.

3. **`persistent_obj = raw_obj;`**:
   - The assignment operator `BasicPersistent& operator=(T* other)` is called.
   - Inside `Assign(raw_obj)`:
     - `IsValid()` is false (initially `persistent_obj` was null).
     - `WeaknessPolicy::GetPersistentRegion(raw_obj)` retrieves the persistent region associated with the allocated object.
     - `AllocateNode(this, &TraceAsRoot)` is called on the persistent region. This allocates a `PersistentNode` and associates it with `persistent_obj`. The `TraceAsRoot` function is registered to be called during garbage collection.
     - `SetValue(raw_obj)` sets `persistent_obj.raw_` to the value of `raw_obj`.
     - `SetNode(allocated_node)` sets `persistent_obj.node_` to the newly allocated node.
     - `CheckPointer(Get())` might perform some runtime checks.
   - After the assignment:
     - `persistent_obj.GetValue()` will be equal to `raw_obj`.
     - `persistent_obj.GetNode()` will point to the newly allocated `PersistentNode`.

**Garbage Collection Implication:** When the garbage collector runs, it will see the `persistent_obj` (assuming it's reachable) and call `TraceAsRoot` on it. `TraceAsRoot` will then mark the `MyObject` instance pointed to by `persistent_obj` as live, preventing its collection.

**Common Programming Errors:**

1. **Dangling Pointers with `WeakPersistent`:**
   ```c++
   void test_weak() {
     cppgc::WeakPersistent<MyObject> weak_obj;
     {
       cppgc::Persistent<MyObject> strong_obj = cppgc::MakeGarbageCollected<MyObject>();
       weak_obj = strong_obj;
       // strong_obj goes out of scope here, but the MyObject is still alive
     }
     // Later in the code:
     MyObject* obj = weak_obj.Get(); // obj might be nullptr if the GC ran
     if (obj) {
       // Accessing members of obj - potential crash if obj was collected
       int value = obj->value;
     }
   }
   ```
   **Error:** Assuming that the object pointed to by a `WeakPersistent` will always be valid. You must always check if `Get()` returns a non-null pointer before dereferencing.

2. **Memory Leaks (Less Common with `Persistent` but possible in complex scenarios):** While `Persistent` prevents immediate garbage collection, if a `Persistent` handle remains reachable indefinitely without a need to keep the object alive, it can effectively lead to a memory leak from the perspective of the application. This usually happens with global or long-lived persistent handles that are no longer necessary.

3. **Incorrect Threading:** Constructing or destructing `Persistent` or `WeakPersistent` objects in different threads than they were created in can lead to undefined behavior and crashes due to the internal management of the persistent node and interaction with the garbage collector.

4. **Over-reliance on `Persistent`:**  Using `Persistent` unnecessarily can prevent objects from being garbage collected, leading to increased memory usage. `WeakPersistent` should be preferred when the object's lifetime doesn't strictly need to be tied to the lifetime of the handle.

5. **Forgetting to Clear or Reset `Persistent` Handles:** If a `Persistent` handle is no longer needed, explicitly clearing it (`persistent_obj.Clear();` or `persistent_obj = nullptr;`) allows the garbage collector to reclaim the associated object when it's no longer referenced elsewhere.

Understanding `Persistent` and `WeakPersistent` is crucial for writing correct and efficient C++ code within the V8 environment that interacts with JavaScript and its garbage collection mechanisms.

Prompt: 
```
这是目录为v8/include/cppgc/persistent.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/cppgc/persistent.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_CPPGC_PERSISTENT_H_
#define INCLUDE_CPPGC_PERSISTENT_H_

#include <type_traits>

#include "cppgc/internal/persistent-node.h"
#include "cppgc/internal/pointer-policies.h"
#include "cppgc/sentinel-pointer.h"
#include "cppgc/source-location.h"
#include "cppgc/type-traits.h"
#include "cppgc/visitor.h"
#include "v8config.h"  // NOLINT(build/include_directory)

namespace cppgc {
namespace internal {

// PersistentBase always refers to the object as const object and defers to
// BasicPersistent on casting to the right type as needed.
class PersistentBase {
 protected:
  PersistentBase() = default;
  explicit PersistentBase(const void* raw) : raw_(raw) {}

  const void* GetValue() const { return raw_; }
  void SetValue(const void* value) { raw_ = value; }

  PersistentNode* GetNode() const { return node_; }
  void SetNode(PersistentNode* node) { node_ = node; }

  // Performs a shallow clear which assumes that internal persistent nodes are
  // destroyed elsewhere.
  void ClearFromGC() const {
    raw_ = nullptr;
    node_ = nullptr;
  }

 protected:
  mutable const void* raw_ = nullptr;
  mutable PersistentNode* node_ = nullptr;

  friend class PersistentRegionBase;
};

// The basic class from which all Persistent classes are generated.
template <typename T, typename WeaknessPolicy, typename LocationPolicy,
          typename CheckingPolicy>
class BasicPersistent final : public PersistentBase,
                              public LocationPolicy,
                              private WeaknessPolicy,
                              private CheckingPolicy {
 public:
  using typename WeaknessPolicy::IsStrongPersistent;
  using PointeeType = T;

  // Null-state/sentinel constructors.
  BasicPersistent(  // NOLINT
      const SourceLocation& loc = SourceLocation::Current())
      : LocationPolicy(loc) {}

  BasicPersistent(std::nullptr_t,  // NOLINT
                  const SourceLocation& loc = SourceLocation::Current())
      : LocationPolicy(loc) {}

  BasicPersistent(  // NOLINT
      SentinelPointer s, const SourceLocation& loc = SourceLocation::Current())
      : PersistentBase(s), LocationPolicy(loc) {}

  // Raw value constructors.
  BasicPersistent(T* raw,  // NOLINT
                  const SourceLocation& loc = SourceLocation::Current())
      : PersistentBase(raw), LocationPolicy(loc) {
    if (!IsValid()) return;
    SetNode(WeaknessPolicy::GetPersistentRegion(GetValue())
                .AllocateNode(this, &TraceAsRoot));
    this->CheckPointer(Get());
  }

  BasicPersistent(T& raw,  // NOLINT
                  const SourceLocation& loc = SourceLocation::Current())
      : BasicPersistent(&raw, loc) {}

  // Copy ctor.
  BasicPersistent(const BasicPersistent& other,
                  const SourceLocation& loc = SourceLocation::Current())
      : BasicPersistent(other.Get(), loc) {}

  // Heterogeneous ctor.
  template <typename U, typename OtherWeaknessPolicy,
            typename OtherLocationPolicy, typename OtherCheckingPolicy,
            typename = std::enable_if_t<std::is_base_of<T, U>::value>>
  // NOLINTNEXTLINE
  BasicPersistent(
      const BasicPersistent<U, OtherWeaknessPolicy, OtherLocationPolicy,
                            OtherCheckingPolicy>& other,
      const SourceLocation& loc = SourceLocation::Current())
      : BasicPersistent(other.Get(), loc) {}

  // Move ctor. The heterogeneous move ctor is not supported since e.g.
  // persistent can't reuse persistent node from weak persistent.
  BasicPersistent(
      BasicPersistent&& other,
      const SourceLocation& loc = SourceLocation::Current()) noexcept
      : PersistentBase(std::move(other)), LocationPolicy(std::move(other)) {
    if (!IsValid()) return;
    GetNode()->UpdateOwner(this);
    other.SetValue(nullptr);
    other.SetNode(nullptr);
    this->CheckPointer(Get());
  }

  // Constructor from member.
  template <typename U, typename MemberBarrierPolicy,
            typename MemberWeaknessTag, typename MemberCheckingPolicy,
            typename MemberStorageType,
            typename = std::enable_if_t<std::is_base_of<T, U>::value>>
  // NOLINTNEXTLINE
  BasicPersistent(const internal::BasicMember<
                      U, MemberBarrierPolicy, MemberWeaknessTag,
                      MemberCheckingPolicy, MemberStorageType>& member,
                  const SourceLocation& loc = SourceLocation::Current())
      : BasicPersistent(member.Get(), loc) {}

  ~BasicPersistent() { Clear(); }

  // Copy assignment.
  BasicPersistent& operator=(const BasicPersistent& other) {
    return operator=(other.Get());
  }

  template <typename U, typename OtherWeaknessPolicy,
            typename OtherLocationPolicy, typename OtherCheckingPolicy,
            typename = std::enable_if_t<std::is_base_of<T, U>::value>>
  BasicPersistent& operator=(
      const BasicPersistent<U, OtherWeaknessPolicy, OtherLocationPolicy,
                            OtherCheckingPolicy>& other) {
    return operator=(other.Get());
  }

  // Move assignment.
  BasicPersistent& operator=(BasicPersistent&& other) noexcept {
    if (this == &other) return *this;
    Clear();
    PersistentBase::operator=(std::move(other));
    LocationPolicy::operator=(std::move(other));
    if (!IsValid()) return *this;
    GetNode()->UpdateOwner(this);
    other.SetValue(nullptr);
    other.SetNode(nullptr);
    this->CheckPointer(Get());
    return *this;
  }

  // Assignment from member.
  template <typename U, typename MemberBarrierPolicy,
            typename MemberWeaknessTag, typename MemberCheckingPolicy,
            typename MemberStorageType,
            typename = std::enable_if_t<std::is_base_of<T, U>::value>>
  BasicPersistent& operator=(
      const internal::BasicMember<U, MemberBarrierPolicy, MemberWeaknessTag,
                                  MemberCheckingPolicy, MemberStorageType>&
          member) {
    return operator=(member.Get());
  }

  BasicPersistent& operator=(T* other) {
    Assign(other);
    return *this;
  }

  BasicPersistent& operator=(std::nullptr_t) {
    Clear();
    return *this;
  }

  BasicPersistent& operator=(SentinelPointer s) {
    Assign(s);
    return *this;
  }

  explicit operator bool() const { return Get(); }
  // Historically we allow implicit conversions to T*.
  // NOLINTNEXTLINE
  operator T*() const { return Get(); }
  T* operator->() const { return Get(); }
  T& operator*() const { return *Get(); }

  // CFI cast exemption to allow passing SentinelPointer through T* and support
  // heterogeneous assignments between different Member and Persistent handles
  // based on their actual types.
  V8_CLANG_NO_SANITIZE("cfi-unrelated-cast") T* Get() const {
    // The const_cast below removes the constness from PersistentBase storage.
    // The following static_cast re-adds any constness if specified through the
    // user-visible template parameter T.
    return static_cast<T*>(const_cast<void*>(GetValue()));
  }

  void Clear() {
    // Simplified version of `Assign()` to allow calling without a complete type
    // `T`.
    if (IsValid()) {
      WeaknessPolicy::GetPersistentRegion(GetValue()).FreeNode(GetNode());
      SetNode(nullptr);
    }
    SetValue(nullptr);
  }

  T* Release() {
    T* result = Get();
    Clear();
    return result;
  }

  template <typename U, typename OtherWeaknessPolicy = WeaknessPolicy,
            typename OtherLocationPolicy = LocationPolicy,
            typename OtherCheckingPolicy = CheckingPolicy>
  BasicPersistent<U, OtherWeaknessPolicy, OtherLocationPolicy,
                  OtherCheckingPolicy>
  To() const {
    return BasicPersistent<U, OtherWeaknessPolicy, OtherLocationPolicy,
                           OtherCheckingPolicy>(static_cast<U*>(Get()));
  }

 private:
  static void TraceAsRoot(RootVisitor& root_visitor, const void* ptr) {
    root_visitor.Trace(*static_cast<const BasicPersistent*>(ptr));
  }

  bool IsValid() const {
    // Ideally, handling kSentinelPointer would be done by the embedder. On the
    // other hand, having Persistent aware of it is beneficial since no node
    // gets wasted.
    return GetValue() != nullptr && GetValue() != kSentinelPointer;
  }

  void Assign(T* ptr) {
    if (IsValid()) {
      if (ptr && ptr != kSentinelPointer) {
        // Simply assign the pointer reusing the existing node.
        SetValue(ptr);
        this->CheckPointer(ptr);
        return;
      }
      WeaknessPolicy::GetPersistentRegion(GetValue()).FreeNode(GetNode());
      SetNode(nullptr);
    }
    SetValue(ptr);
    if (!IsValid()) return;
    SetNode(WeaknessPolicy::GetPersistentRegion(GetValue())
                .AllocateNode(this, &TraceAsRoot));
    this->CheckPointer(Get());
  }

  void ClearFromGC() const {
    if (IsValid()) {
      WeaknessPolicy::GetPersistentRegion(GetValue()).FreeNode(GetNode());
      PersistentBase::ClearFromGC();
    }
  }

  // Set Get() for details.
  V8_CLANG_NO_SANITIZE("cfi-unrelated-cast")
  T* GetFromGC() const {
    return static_cast<T*>(const_cast<void*>(GetValue()));
  }

  friend class internal::RootVisitor;
};

template <typename T1, typename WeaknessPolicy1, typename LocationPolicy1,
          typename CheckingPolicy1, typename T2, typename WeaknessPolicy2,
          typename LocationPolicy2, typename CheckingPolicy2>
bool operator==(const BasicPersistent<T1, WeaknessPolicy1, LocationPolicy1,
                                      CheckingPolicy1>& p1,
                const BasicPersistent<T2, WeaknessPolicy2, LocationPolicy2,
                                      CheckingPolicy2>& p2) {
  return p1.Get() == p2.Get();
}

template <typename T1, typename WeaknessPolicy1, typename LocationPolicy1,
          typename CheckingPolicy1, typename T2, typename WeaknessPolicy2,
          typename LocationPolicy2, typename CheckingPolicy2>
bool operator!=(const BasicPersistent<T1, WeaknessPolicy1, LocationPolicy1,
                                      CheckingPolicy1>& p1,
                const BasicPersistent<T2, WeaknessPolicy2, LocationPolicy2,
                                      CheckingPolicy2>& p2) {
  return !(p1 == p2);
}

template <typename T1, typename PersistentWeaknessPolicy,
          typename PersistentLocationPolicy, typename PersistentCheckingPolicy,
          typename T2, typename MemberWriteBarrierPolicy,
          typename MemberWeaknessTag, typename MemberCheckingPolicy,
          typename MemberStorageType>
bool operator==(
    const BasicPersistent<T1, PersistentWeaknessPolicy,
                          PersistentLocationPolicy, PersistentCheckingPolicy>&
        p,
    const BasicMember<T2, MemberWeaknessTag, MemberWriteBarrierPolicy,
                      MemberCheckingPolicy, MemberStorageType>& m) {
  return p.Get() == m.Get();
}

template <typename T1, typename PersistentWeaknessPolicy,
          typename PersistentLocationPolicy, typename PersistentCheckingPolicy,
          typename T2, typename MemberWriteBarrierPolicy,
          typename MemberWeaknessTag, typename MemberCheckingPolicy,
          typename MemberStorageType>
bool operator!=(
    const BasicPersistent<T1, PersistentWeaknessPolicy,
                          PersistentLocationPolicy, PersistentCheckingPolicy>&
        p,
    const BasicMember<T2, MemberWeaknessTag, MemberWriteBarrierPolicy,
                      MemberCheckingPolicy, MemberStorageType>& m) {
  return !(p == m);
}

template <typename T1, typename MemberWriteBarrierPolicy,
          typename MemberWeaknessTag, typename MemberCheckingPolicy,
          typename MemberStorageType, typename T2,
          typename PersistentWeaknessPolicy, typename PersistentLocationPolicy,
          typename PersistentCheckingPolicy>
bool operator==(
    const BasicMember<T2, MemberWeaknessTag, MemberWriteBarrierPolicy,
                      MemberCheckingPolicy, MemberStorageType>& m,
    const BasicPersistent<T1, PersistentWeaknessPolicy,
                          PersistentLocationPolicy, PersistentCheckingPolicy>&
        p) {
  return m.Get() == p.Get();
}

template <typename T1, typename MemberWriteBarrierPolicy,
          typename MemberWeaknessTag, typename MemberCheckingPolicy,
          typename MemberStorageType, typename T2,
          typename PersistentWeaknessPolicy, typename PersistentLocationPolicy,
          typename PersistentCheckingPolicy>
bool operator!=(
    const BasicMember<T2, MemberWeaknessTag, MemberWriteBarrierPolicy,
                      MemberCheckingPolicy, MemberStorageType>& m,
    const BasicPersistent<T1, PersistentWeaknessPolicy,
                          PersistentLocationPolicy, PersistentCheckingPolicy>&
        p) {
  return !(m == p);
}

template <typename T, typename LocationPolicy, typename CheckingPolicy>
struct IsWeak<BasicPersistent<T, internal::WeakPersistentPolicy, LocationPolicy,
                              CheckingPolicy>> : std::true_type {};
}  // namespace internal

/**
 * Persistent is a way to create a strong pointer from an off-heap object to
 * another on-heap object. As long as the Persistent handle is alive the GC will
 * keep the object pointed to alive. The Persistent handle is always a GC root
 * from the point of view of the GC. Persistent must be constructed and
 * destructed in the same thread.
 */
template <typename T>
using Persistent =
    internal::BasicPersistent<T, internal::StrongPersistentPolicy>;

/**
 * WeakPersistent is a way to create a weak pointer from an off-heap object to
 * an on-heap object. The pointer is automatically cleared when the pointee gets
 * collected. WeakPersistent must be constructed and destructed in the same
 * thread.
 */
template <typename T>
using WeakPersistent =
    internal::BasicPersistent<T, internal::WeakPersistentPolicy>;

}  // namespace cppgc

#endif  // INCLUDE_CPPGC_PERSISTENT_H_

"""

```