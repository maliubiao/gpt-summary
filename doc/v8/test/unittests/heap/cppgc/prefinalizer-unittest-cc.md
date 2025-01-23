Response:
Let's break down the thought process for analyzing the C++ code and generating the explanation.

1. **Understanding the Goal:** The primary goal is to understand the functionality of `prefinalizer-unittest.cc`. The name strongly suggests it's about testing "prefinalizers" in the `cppgc` (C++ garbage collection) system of V8. The prompt specifically asks for functionality, relationships to JavaScript (if any), logic with examples, and common programming errors.

2. **Initial Code Scan - Identifying Key Elements:**  Quickly scan the code for keywords and patterns:
    * `#include`:  Indicates dependencies. `cppgc/prefinalizer.h` is a crucial one.
    * `namespace cppgc`, `namespace internal`, `namespace {`:  Namespace structure.
    * `class PrefinalizerTest`: A test fixture, suggesting this file contains unit tests.
    * `CPPGC_USING_PRE_FINALIZER`:  A macro that appears important.
    * `PreFinalizer()`:  A method name that's frequently used, likely the prefinalizer itself.
    * `MakeGarbageCollected`:  Function for allocating garbage-collected objects.
    * `PreciseGC()`:  Triggers garbage collection.
    * `Persistent`:  A smart pointer that prevents garbage collection.
    * `Member`: Another smart pointer, likely for holding references within GC'd objects.
    * `EXPECT_EQ`, `EXPECT_DEATH_IF_SUPPORTED`:  Assertions from the testing framework (gtest).
    * `Trace(Visitor*)`:  Standard method in garbage collection systems for marking reachable objects.

3. **Focusing on the Core Concept - Prefinalizers:** The `CPPGC_USING_PRE_FINALIZER` macro and the `PreFinalizer()` methods are central. It's clear these methods are called *before* an object is fully garbage collected. This is the core functionality to investigate.

4. **Analyzing the Test Cases:**  Each `TEST_F` block demonstrates a specific aspect of prefinalizers. Go through each test and understand what it's verifying:
    * `PrefinalizerCalledOnDeadObject`:  Confirms the prefinalizer is called when an object is no longer referenced.
    * `PrefinalizerNotCalledOnLiveObject`: Verifies the prefinalizer isn't called for reachable objects.
    * Tests involving `Mixin`: Show prefinalizers work with mixin classes.
    * `PrefinalizerInvocationPreservesOrder`: Demonstrates the order in which prefinalizers are called in inheritance hierarchies.
    * `PrefinalizerCanRewireGraphWithLiveObjects`:  Shows prefinalizers can modify the object graph during their execution.
    * Tests involving `AllocatingPrefinalizer`:  Investigate the safety and behavior of allocating memory within a prefinalizer (often restricted).
    * Tests involving `RessurectingPrefinalizer`: Examine the ability (and often the prevention) of prefinalizers making objects reachable again.
    * `VirtualPrefinalizer`:  Checks how virtual functions work for prefinalizers in inheritance.

5. **Inferring Functionality:** Based on the test cases, the primary function of prefinalizers is to perform actions *just before* a garbage-collected object is reclaimed. These actions might involve:
    * Releasing external resources.
    * Logging or recording information.
    * Potentially modifying the object graph (with constraints).

6. **JavaScript Relationship (or Lack Thereof):** The code is C++ and deals with the internal garbage collection of V8. While JavaScript relies on V8's GC, this specific code is about the *implementation* of that GC. There's no direct JavaScript interaction in *this particular file*. The connection is that prefinalizers in C++ help manage the lifecycle of C++ objects managed by V8's GC, which indirectly supports JavaScript object management.

7. **Logic and Examples:**  For each test, identify the setup, the action (garbage collection), and the expected outcome (prefinalizer call count). This naturally leads to the "Assumptions and Outputs" sections. Use the test case logic to create simple scenarios.

8. **Common Programming Errors:** Think about potential pitfalls when using prefinalizers:
    * **Ressurrection:** Making a dead object alive again can cause issues.
    * **Allocation (if disallowed):** Allocating memory within a prefinalizer might lead to deadlocks or unexpected behavior.
    * **Long-running prefinalizers:**  Blocking the garbage collection process.
    * **Incorrect assumptions about object state:**  Prefinalizers are called on objects about to be freed.

9. **Torque Check:** The prompt specifically asks about `.tq` files. Since the file ends in `.cc`, it's C++, not Torque.

10. **Structuring the Explanation:** Organize the findings into logical sections: Functionality, JavaScript relation, Logic Examples, Programming Errors. This makes the explanation clear and easy to follow.

11. **Refinement and Clarity:** Review the generated explanation for clarity, accuracy, and completeness. Ensure the examples are simple and illustrative. Use precise terminology (e.g., "garbage-collected," "reachable," "unreachable").

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe prefinalizers are like JavaScript finalizers. **Correction:** While conceptually similar, they operate at a lower level in C++ within V8. Emphasize the C++ nature.
* **Considering edge cases:** What if multiple prefinalizers are defined? The "Invocation Order" test addresses this.
* **Thinking about the "why":** Why would you use a prefinalizer? Resource management and cleanup are key motivators.
* **Double-checking assumptions:** The prompt mentions `.tq`. Always verify file extensions.

By following these steps, combining code analysis with an understanding of garbage collection principles, and structuring the information effectively, we arrive at the comprehensive explanation provided in the initial example.
The C++ source code file `v8/test/unittests/heap/cppgc/prefinalizer-unittest.cc` is a unit test file for the prefinalizer feature in V8's `cppgc` (C++ garbage collection) system. Here's a breakdown of its functionality:

**Functionality:**

The primary function of this file is to test the behavior of prefinalizers in the `cppgc` system. Prefinalizers are functions that are called on garbage-collected objects *just before* they are actually reclaimed by the garbage collector. This allows for cleanup actions or finalization logic to be executed.

Specifically, the tests in this file verify the following aspects of prefinalizers:

* **Basic Prefinalizer Invocation:**
    * Ensures that the prefinalizer function is called when a garbage-collected object becomes unreachable and is being collected.
    * Confirms that the prefinalizer is *not* called for objects that are still reachable (live).

* **Prefinalizers with Mixins:**
    * Tests that prefinalizers work correctly when defined in mixin classes (classes used for multiple inheritance).
    * Verifies the prefinalizer is called on dead objects and not on live ones, even with mixins.

* **Prefinalizer Invocation Order in Inheritance:**
    * Checks the order in which prefinalizers are invoked when multiple prefinalizers are defined in a class hierarchy (base class and derived classes). It ensures a specific order of execution.

* **Prefinalizers and Object Graph Mutation:**
    * Demonstrates that prefinalizers can safely modify the object graph during their execution, allowing for actions like removing objects from linked lists.
    * Explores scenarios where prefinalizers rewire the graph with both live and dead objects, and checks for potential issues (especially in debug builds).

* **Restrictions on Allocations within Prefinalizers:**
    * Tests the behavior when a prefinalizer attempts to allocate new garbage-collected objects. This is often restricted or discouraged to avoid issues during the garbage collection process itself. The behavior might differ based on build configurations (`CPPGC_ALLOW_ALLOCATIONS_IN_PREFINALIZERS`).

* **Preventing Object Resurrection:**
    * Verifies that prefinalizers cannot easily "resurrect" an object by making it reachable again from a persistent handle or another live object. This is a crucial safety mechanism to ensure proper garbage collection.

* **Virtual Prefinalizers:**
    * Tests the behavior of prefinalizers when declared as virtual functions in a base class and overridden in derived classes. It verifies that the correct overridden prefinalizer is called.

**Is it a Torque file?**

No, the file ends with `.cc`, which is the standard extension for C++ source files. If it ended with `.tq`, it would be a Torque file.

**Relationship to JavaScript:**

While this specific file is C++ code for testing the underlying garbage collection mechanism, prefinalizers in `cppgc` are relevant to JavaScript in the following way:

* **Supporting Native Bindings:** V8, the JavaScript engine, often needs to manage C++ objects that are exposed to JavaScript through native bindings. These C++ objects are managed by `cppgc`. Prefinalizers allow these C++ objects to perform necessary cleanup (e.g., releasing resources, closing files, freeing memory allocated outside of `cppgc`) when they are no longer referenced by JavaScript and become garbage-collectible.

**Example using JavaScript (conceptual):**

Imagine you have a C++ object representing a file handle that's exposed to JavaScript.

```javascript
// JavaScript code
let file = new NativeFile("my_document.txt"); // 'NativeFile' is a binding to a C++ class

// ... use the file ...

file = null; // The JavaScript reference is gone, the C++ object becomes garbage-collectible
```

In the corresponding C++ code for `NativeFile`, a prefinalizer could be used to ensure the file handle is closed when the object is garbage collected:

```c++
// C++ code (simplified)
class NativeFile : public GarbageCollected<NativeFile> {
  CPPGC_USING_PRE_FINALIZER(NativeFile, CloseFile);

 public:
  NativeFile(const std::string& filename) : file_handle_(open(filename)) {}
  ~NativeFile() {
    // Destructor might not always be called immediately by the GC
    // Avoid critical cleanup here, use the prefinalizer instead.
  }

 private:
  void CloseFile() {
    if (file_handle_ != INVALID_HANDLE_VALUE) {
      close(file_handle_);
      file_handle_ = INVALID_HANDLE_VALUE;
      // Potentially log the closure
    }
  }

  HANDLE file_handle_;
};
```

In this example, when the JavaScript `file` object is no longer referenced, the `cppgc` garbage collector will eventually reclaim the `NativeFile` C++ object. Before doing so, it will call the `CloseFile` prefinalizer, ensuring the underlying file handle is properly closed.

**Code Logic and Assumptions/Outputs:**

Let's take the `PrefinalizerCalledOnDeadObject` test as an example:

**Assumptions:**

1. `GCed::prefinalizer_callcount` is initialized to 0.
2. `MakeGarbageCollected<GCed>(GetAllocationHandle())` successfully allocates an object of type `GCed`.
3. `PreciseGC()` triggers a full garbage collection cycle.

**Code Flow:**

1. `GCed::prefinalizer_callcount` is set to 0.
2. A `GCed` object is created and assigned to `object`.
3. `USE(object)` prevents the compiler from optimizing away the object's creation.
4. `EXPECT_EQ(0u, GCed::prefinalizer_callcount)`:  Asserts that the prefinalizer has not been called yet (the object is still reachable).
5. `PreciseGC()` is called. Since there are no persistent references to `object` after the `USE(object)` line, the object becomes garbage-collectible. The garbage collector will identify it as such and call its prefinalizer.
6. `EXPECT_EQ(1u, GCed::prefinalizer_callcount)`: Asserts that the prefinalizer (`GCed::PreFinalizer`) has been called exactly once.
7. `PreciseGC()` is called again. The object is already dead, so the prefinalizer should not be called again.
8. `EXPECT_EQ(1u, GCed::prefinalizer_callcount)`: Asserts that the prefinalizer call count remains 1.

**Common Programming Errors Related to Prefinalizers (and Similar Concepts like Finalizers):**

1. **Resurrecting Objects:**  Trying to make a dying object reachable again from within the prefinalizer can lead to complex lifecycle management issues and potential memory leaks if not handled very carefully (and is often restricted by the garbage collection system). The tests in this file specifically address this.

   ```c++
   // Incorrect and potentially dangerous
   class MyObject : public GarbageCollected<MyObject> {
     CPPGC_USING_PRE_FINALIZER(MyObject, Resurrect);
    public:
     static Persistent<MyObject> resurrected_object;

    private:
     void Resurrect() {
       resurrected_object = this; // Trying to keep the object alive
     }
   };
   Persistent<MyObject> MyObject::resurrected_object;
   ```

2. **Performing Long-Running or Blocking Operations:** Prefinalizers should be lightweight and execute quickly. If a prefinalizer takes too long or blocks, it can stall the garbage collection process and negatively impact performance.

3. **Relying on Prefinalizers for Critical Cleanup (Without External Synchronization):** While prefinalizers are useful for cleanup, the exact timing of their execution is not deterministic. For resources that require immediate and guaranteed release, mechanisms like RAII (Resource Acquisition Is Initialization) or explicit cleanup methods are generally preferred. Prefinalizers are more for "best effort" cleanup.

4. **Accessing Potentially Invalid State:** Inside a prefinalizer, the object is in its final stages of life. Accessing members that might have already been deallocated or in an inconsistent state can lead to crashes or undefined behavior.

5. **Allocating Memory in Prefinalizers (If Disallowed):** As tested in the file, allocating new garbage-collected objects within a prefinalizer can be problematic and might be restricted by the garbage collection system to avoid re-entrant garbage collection cycles or other issues.

This unit test file plays a crucial role in ensuring the correctness and reliability of the prefinalizer feature in V8's `cppgc`, which is essential for managing the lifecycle of C++ objects within the JavaScript engine.

### 提示词
```
这是目录为v8/test/unittests/heap/cppgc/prefinalizer-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/prefinalizer-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/cppgc/prefinalizer.h"

#include "include/cppgc/allocation.h"
#include "include/cppgc/garbage-collected.h"
#include "include/cppgc/persistent.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/heap.h"
#include "test/unittests/heap/cppgc/tests.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cppgc {
namespace internal {

namespace {

class PrefinalizerTest : public testing::TestWithHeap {};

class GCed : public GarbageCollected<GCed> {
  CPPGC_USING_PRE_FINALIZER(GCed, PreFinalizer);

 public:
  void Trace(Visitor*) const {}
  void PreFinalizer() { ++prefinalizer_callcount; }

  static size_t prefinalizer_callcount;
};
size_t GCed::prefinalizer_callcount = 0;

}  // namespace

TEST_F(PrefinalizerTest, PrefinalizerCalledOnDeadObject) {
  GCed::prefinalizer_callcount = 0;
  auto* object = MakeGarbageCollected<GCed>(GetAllocationHandle());
  USE(object);
  EXPECT_EQ(0u, GCed::prefinalizer_callcount);
  PreciseGC();
  EXPECT_EQ(1u, GCed::prefinalizer_callcount);
  PreciseGC();
  EXPECT_EQ(1u, GCed::prefinalizer_callcount);
}

TEST_F(PrefinalizerTest, PrefinalizerNotCalledOnLiveObject) {
  GCed::prefinalizer_callcount = 0;
  {
    Persistent<GCed> object = MakeGarbageCollected<GCed>(GetAllocationHandle());
    EXPECT_EQ(0u, GCed::prefinalizer_callcount);
    PreciseGC();
    EXPECT_EQ(0u, GCed::prefinalizer_callcount);
  }
  PreciseGC();
  EXPECT_EQ(1u, GCed::prefinalizer_callcount);
}

namespace {

class Mixin : public GarbageCollectedMixin {
  CPPGC_USING_PRE_FINALIZER(Mixin, PreFinalizer);

 public:
  void PreFinalizer() { ++prefinalizer_callcount; }

  static size_t prefinalizer_callcount;
};
size_t Mixin::prefinalizer_callcount = 0;

class GCedWithMixin : public GarbageCollected<GCedWithMixin>, public Mixin {};

}  // namespace

TEST_F(PrefinalizerTest, PrefinalizerCalledOnDeadMixinObject) {
  Mixin::prefinalizer_callcount = 0;
  auto* object = MakeGarbageCollected<GCedWithMixin>(GetAllocationHandle());
  USE(object);
  EXPECT_EQ(0u, Mixin::prefinalizer_callcount);
  PreciseGC();
  EXPECT_EQ(1u, Mixin::prefinalizer_callcount);
  PreciseGC();
  EXPECT_EQ(1u, Mixin::prefinalizer_callcount);
}

TEST_F(PrefinalizerTest, PrefinalizerNotCalledOnLiveMixinObject) {
  Mixin::prefinalizer_callcount = 0;
  {
    Persistent<GCedWithMixin> object =
        MakeGarbageCollected<GCedWithMixin>(GetAllocationHandle());
    EXPECT_EQ(0u, Mixin::prefinalizer_callcount);
    PreciseGC();
    EXPECT_EQ(0u, Mixin::prefinalizer_callcount);
  }
  PreciseGC();
  EXPECT_EQ(1u, Mixin::prefinalizer_callcount);
}

namespace {

class BaseMixin : public GarbageCollectedMixin {
  CPPGC_USING_PRE_FINALIZER(BaseMixin, PreFinalizer);

 public:
  void PreFinalizer();

  static size_t prefinalizer_callcount;
};
size_t BaseMixin::prefinalizer_callcount = 0;

class InheritingMixin : public BaseMixin {
  CPPGC_USING_PRE_FINALIZER(InheritingMixin, PreFinalizer);

 public:
  void PreFinalizer();

  static size_t prefinalizer_callcount;
};
size_t InheritingMixin::prefinalizer_callcount = 0;

class GCedWithMixins : public GarbageCollected<GCedWithMixins>,
                       public InheritingMixin {
  CPPGC_USING_PRE_FINALIZER(GCedWithMixins, PreFinalizer);

 public:
  void PreFinalizer();

  static size_t prefinalizer_callcount;
};
size_t GCedWithMixins::prefinalizer_callcount = 0;

void BaseMixin::PreFinalizer() {
  EXPECT_EQ(1u, GCedWithMixins::prefinalizer_callcount);
  EXPECT_EQ(1u, InheritingMixin::prefinalizer_callcount);
  EXPECT_EQ(0u, BaseMixin::prefinalizer_callcount);
  ++BaseMixin::prefinalizer_callcount;
}

void InheritingMixin::PreFinalizer() {
  EXPECT_EQ(1u, GCedWithMixins::prefinalizer_callcount);
  EXPECT_EQ(0u, InheritingMixin::prefinalizer_callcount);
  EXPECT_EQ(0u, BaseMixin::prefinalizer_callcount);
  InheritingMixin::prefinalizer_callcount = true;
}

void GCedWithMixins::PreFinalizer() {
  EXPECT_EQ(0u, GCedWithMixins::prefinalizer_callcount);
  EXPECT_EQ(0u, InheritingMixin::prefinalizer_callcount);
  EXPECT_EQ(0u, BaseMixin::prefinalizer_callcount);
  GCedWithMixins::prefinalizer_callcount = true;
}
}  // namespace

TEST_F(PrefinalizerTest, PrefinalizerInvocationPreservesOrder) {
  BaseMixin::prefinalizer_callcount = 0;
  InheritingMixin::prefinalizer_callcount = 0;
  GCedWithMixins::prefinalizer_callcount = 0;
  auto* object = MakeGarbageCollected<GCedWithMixins>(GetAllocationHandle());
  USE(object);
  EXPECT_EQ(0u, GCedWithMixins::prefinalizer_callcount);
  EXPECT_EQ(0u, InheritingMixin::prefinalizer_callcount);
  EXPECT_EQ(0u, BaseMixin::prefinalizer_callcount);
  PreciseGC();
  EXPECT_EQ(1u, GCedWithMixins::prefinalizer_callcount);
  EXPECT_EQ(1u, InheritingMixin::prefinalizer_callcount);
  EXPECT_EQ(1u, BaseMixin::prefinalizer_callcount);
  PreciseGC();
  EXPECT_EQ(1u, GCedWithMixins::prefinalizer_callcount);
  EXPECT_EQ(1u, InheritingMixin::prefinalizer_callcount);
  EXPECT_EQ(1u, BaseMixin::prefinalizer_callcount);
}

namespace {

class LinkedNode final : public GarbageCollected<LinkedNode> {
 public:
  explicit LinkedNode(LinkedNode* next) : next_(next) {}

  void Trace(Visitor* visitor) const { visitor->Trace(next_); }

  LinkedNode* next() const { return next_; }

  void RemoveNext() {
    CHECK(next_);
    next_ = next_->next_;
  }

 private:
  Member<LinkedNode> next_;
};

class MutatingPrefinalizer final
    : public GarbageCollected<MutatingPrefinalizer> {
  CPPGC_USING_PRE_FINALIZER(MutatingPrefinalizer, PreFinalizer);

 public:
  void PreFinalizer() {
    // Pre-finalizers are generally used to mutate the object graph. The API
    // does not allow distinguishing between live and dead objects. It is
    // generally safe to re-write the dead *or* the live object graph. Adding
    // a dead object to the live graph must not happen.
    //
    // RemoveNext() must not trigger a write barrier. In the case all LinkedNode
    // objects die at the same time, the graph is mutated with a dead object.
    // This is only safe when the dead object is added to a dead subgraph.
    parent_node_->RemoveNext();
  }

  explicit MutatingPrefinalizer(LinkedNode* parent) : parent_node_(parent) {}

  void Trace(Visitor* visitor) const { visitor->Trace(parent_node_); }

 private:
  Member<LinkedNode> parent_node_;
};

}  // namespace

TEST_F(PrefinalizerTest, PrefinalizerCanRewireGraphWithLiveObjects) {
  Persistent<LinkedNode> root{MakeGarbageCollected<LinkedNode>(
      GetAllocationHandle(),
      MakeGarbageCollected<LinkedNode>(
          GetAllocationHandle(),
          MakeGarbageCollected<LinkedNode>(GetAllocationHandle(), nullptr)))};
  CHECK(root->next());
  MakeGarbageCollected<MutatingPrefinalizer>(GetAllocationHandle(), root.Get());
  PreciseGC();
}

namespace {

class PrefinalizerDeathTest : public testing::TestWithHeap {};

class AllocatingPrefinalizer : public GarbageCollected<AllocatingPrefinalizer> {
  CPPGC_USING_PRE_FINALIZER(AllocatingPrefinalizer, PreFinalizer);

 public:
  explicit AllocatingPrefinalizer(cppgc::Heap* heap) : heap_(heap) {}
  void Trace(Visitor*) const {}
  void PreFinalizer() {
    MakeGarbageCollected<GCed>(heap_->GetAllocationHandle());
  }

 private:
  cppgc::Heap* heap_;
};

}  // namespace

#ifdef CPPGC_ALLOW_ALLOCATIONS_IN_PREFINALIZERS
TEST_F(PrefinalizerTest, PrefinalizerDoesNotFailOnAllcoation) {
  auto* object = MakeGarbageCollected<AllocatingPrefinalizer>(
      GetAllocationHandle(), GetHeap());
  PreciseGC();
  USE(object);
}
#else
#ifdef DEBUG
TEST_F(PrefinalizerDeathTest, PrefinalizerFailsOnAllcoation) {
  auto* object = MakeGarbageCollected<AllocatingPrefinalizer>(
      GetAllocationHandle(), GetHeap());
  USE(object);
  EXPECT_DEATH_IF_SUPPORTED(PreciseGC(), "");
}
#endif  // DEBUG
#endif  // CPPGC_ALLOW_ALLOCATIONS_IN_PREFINALIZERS

namespace {

template <template <typename T> class RefType>
class RessurectingPrefinalizer
    : public GarbageCollected<RessurectingPrefinalizer<RefType>> {
  CPPGC_USING_PRE_FINALIZER(RessurectingPrefinalizer, PreFinalizer);

 public:
  explicit RessurectingPrefinalizer(RefType<GCed>& ref, GCed* obj)
      : ref_(ref), obj_(obj) {}
  void Trace(Visitor*) const {}
  void PreFinalizer() { ref_ = obj_; }

 private:
  RefType<GCed>& ref_;
  GCed* obj_;
};

class GCedHolder : public GarbageCollected<GCedHolder> {
 public:
  void Trace(Visitor* v) const { v->Trace(member_); }

  Member<GCed> member_;
};

}  // namespace

#if DEBUG
#ifdef CPPGC_VERIFY_HEAP

TEST_F(PrefinalizerDeathTest, PrefinalizerCanRewireGraphWithDeadObjects) {
  // Prefinalizers are allowed to rewire dead object to dead objects as that
  // doesn't affect the live object graph.
  Persistent<LinkedNode> root{MakeGarbageCollected<LinkedNode>(
      GetAllocationHandle(),
      MakeGarbageCollected<LinkedNode>(
          GetAllocationHandle(),
          MakeGarbageCollected<LinkedNode>(GetAllocationHandle(), nullptr)))};
  CHECK(root->next());
  MakeGarbageCollected<MutatingPrefinalizer>(GetAllocationHandle(), root.Get());
  // All LinkedNode objects will die on the following GC. The pre-finalizer may
  // still operate with them but not add them to a live object.
  root.Clear();
  PreciseGC();
}

#ifdef CPPGC_ENABLE_SLOW_API_CHECKS

TEST_F(PrefinalizerDeathTest, PrefinalizerCantRessurectObjectOnStack) {
  Persistent<GCed> persistent;
  MakeGarbageCollected<RessurectingPrefinalizer<Persistent>>(
      GetAllocationHandle(), persistent,
      MakeGarbageCollected<GCed>(GetAllocationHandle()));
  EXPECT_DEATH_IF_SUPPORTED(PreciseGC(), "");
}

#endif  // CPPGC_ENABLE_SLOW_API_CHECKS

TEST_F(PrefinalizerDeathTest, PrefinalizerCantRessurectObjectOnHeap) {
  Persistent<GCedHolder> persistent(
      MakeGarbageCollected<GCedHolder>(GetAllocationHandle()));
  MakeGarbageCollected<RessurectingPrefinalizer<Member>>(
      GetAllocationHandle(), persistent->member_,
      MakeGarbageCollected<GCed>(GetAllocationHandle()));
  EXPECT_DEATH_IF_SUPPORTED(PreciseGC(), "");
}

#endif  // CPPGC_VERIFY_HEAP
#endif  // DEBUG

#ifdef CPPGC_ALLOW_ALLOCATIONS_IN_PREFINALIZERS
TEST_F(PrefinalizerTest, AllocatingPrefinalizersInMultipleGCCycles) {
  auto* object = MakeGarbageCollected<AllocatingPrefinalizer>(
      GetAllocationHandle(), GetHeap());
  PreciseGC();
  auto* other_object = MakeGarbageCollected<AllocatingPrefinalizer>(
      GetAllocationHandle(), GetHeap());
  PreciseGC();
  USE(object);
  USE(other_object);
}
#endif

class GCedBase : public GarbageCollected<GCedBase> {
  CPPGC_USING_PRE_FINALIZER(GCedBase, PreFinalize);

 public:
  void Trace(Visitor*) const {}
  virtual void PreFinalize() { ++prefinalizer_count_; }
  static size_t prefinalizer_count_;
};
size_t GCedBase::prefinalizer_count_ = 0u;

class GCedInherited : public GCedBase {
 public:
  void PreFinalize() override { ++prefinalizer_count_; }
  static size_t prefinalizer_count_;
};
size_t GCedInherited::prefinalizer_count_ = 0u;

TEST_F(PrefinalizerTest, VirtualPrefinalizer) {
  MakeGarbageCollected<GCedInherited>(GetAllocationHandle());
  GCedBase::prefinalizer_count_ = 0u;
  GCedInherited::prefinalizer_count_ = 0u;
  PreciseGC();
  EXPECT_EQ(0u, GCedBase::prefinalizer_count_);
  EXPECT_LT(0u, GCedInherited::prefinalizer_count_);
}

}  // namespace internal
}  // namespace cppgc
```