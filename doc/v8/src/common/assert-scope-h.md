Response:
Let's break down the thought process for analyzing the provided C++ header file `assert-scope.h`.

**1. Initial Scan and Purpose Identification:**

The first thing I do is skim the file for keywords and patterns that give clues about its purpose. I see:

* `#ifndef`, `#define`, `#include`: Standard C++ header file guards.
* `namespace v8::internal`:  Indicates this is internal V8 code.
* `assert`:  Appears frequently in class names and comments (e.g., `PerThreadAssertScope`, `SAFEPOINTS_ASSERT`). This strongly suggests the file is related to assertions or validation.
* `Isolate`:  A fundamental V8 concept, hinting at per-isolate checks.
* `PerThread`:  Another key term, pointing to per-thread assertions.
* `Allow`, `Disallow`: These prefixes in class names suggest enabling/disabling certain behaviors or checks.
* Comments like "Scope to document where we do not expect..." further solidify the assertion purpose.

Based on this initial scan, I hypothesize that this file provides mechanisms for defining scopes where certain conditions (related to memory management, execution, etc.) are expected or not expected to occur, primarily for debugging and internal validation within V8.

**2. Deeper Dive into Core Concepts:**

Now, I start looking at the core building blocks:

* **`PerThreadAssertType` enum:** This enum lists the specific conditions being tracked/asserted. I note the different types: `SAFEPOINTS_ASSERT`, `HEAP_ALLOCATION_ASSERT`, `HANDLE_ALLOCATION_ASSERT`, etc. This tells me *what* kind of assertions are possible.
* **`PerThreadAsserts`:** This uses `base::EnumSet` to represent a set of `PerThreadAssertType` values. This means multiple assertions can be active simultaneously within a scope.
* **`PerThreadAssertScopeEmpty`:**  The comment "Empty assert scope, used for debug-only scopes in release mode" is crucial. This indicates a strategy for disabling assertions in release builds for performance. The template structure allows differentiation even when empty (important for `GC_MOLE`).
* **`PerThreadAssertScope`:** This is the main per-thread scope class. It inherits from the empty one and stores `old_data_`. The constructor/destructor pair, along with `Release()`, suggests a mechanism for saving and restoring the assertion state.
* **Macros (`PER_ISOLATE_DCHECK_TYPE`, `PER_ISOLATE_CHECK_TYPE`, etc.):**  These are used to generate code for per-isolate assertions. The `V` parameter and the different prefixes (`Allow`, `Disallow`) reveal a pattern for creating pairs of enabling/disabling scopes. The `enable` parameter further emphasizes the on/off nature of these assertions.

**3. Understanding Per-Isolate Assertions:**

I focus on the macros related to isolates. The `PER_ISOLATE_ASSERT_SCOPE_DECLARATION` macro defines the basic structure of the per-isolate assertion scope classes. Key observations:

* They take an `Isolate*` in the constructor.
* They have `IsAllowed(Isolate*)` to check the current state.
* `Open` and `Close` methods suggest a way to temporarily modify the assertion state.

The `PER_ISOLATE_DCHECK_TYPE` and `PER_ISOLATE_CHECK_TYPE` macros define specific per-isolate assertions related to JavaScript execution, deoptimization, compilation, and exceptions. The distinction between `DCHECK` and `CHECK` hints at different severity levels or contexts for these assertions.

**4. Per-Thread Assertion Scopes (Specific Types):**

I go through the various `using` declarations for per-thread scopes: `DisallowHandleAllocation`, `AllowSafepoints`, etc. The naming convention is clear: `Allow...` enables an assertion, while `Disallow...` disables it. The template parameters in `PerThreadAssertScopeDebugOnly` specify which `PerThreadAssertType` is being controlled. The use of `DebugOnly` again reinforces the debug-build emphasis.

**5. Advanced Constructs:**

I examine the more complex parts:

* **`DISALLOW_GARBAGE_COLLECTION` macro:** This shows a pattern for conditional compilation, only defining a member in debug builds.
* **`DisallowHeapAccessIf`:** This introduces conditional disabling of heap access based on a runtime condition.
* **`NoGarbageCollectionMutexGuard`:** This combines a mutex lock with a `DisallowGarbageCollection` scope, ensuring no GC occurs while the mutex is held. This is important for maintaining data consistency.

**6. Answering the Specific Questions:**

With a good understanding of the code, I can now address the prompt's questions:

* **Functionality:** Summarize the purpose as creating scopes for enabling/disabling internal V8 assertions for debugging and validation.
* **`.tq` extension:**  Explain that this file is a standard C++ header, not Torque.
* **JavaScript Relation:** Connect the assertions to potential JavaScript-related errors (e.g., unexpected deoptimization). Provide JavaScript examples that might trigger these assertions if the corresponding C++ code were executed.
* **Code Logic Reasoning:**  Choose a simple example (like `DisallowHeapAllocation`) and demonstrate the before/after state of the assertion flag.
* **Common Programming Errors:**  Link the assertions to typical mistakes in concurrent programming, memory management, etc., and provide concrete C++ examples that would violate the assertion conditions.

**7. Refinement and Organization:**

Finally, I organize my findings into a clear and structured answer, using headings and bullet points to improve readability. I double-check for accuracy and completeness. I strive to explain the concepts in a way that is understandable even to someone not intimately familiar with the V8 codebase.

This systematic approach, starting with a high-level overview and progressively drilling down into details, allows for a comprehensive understanding of the code's purpose and functionality. The key is to identify the core concepts, understand the relationships between different parts of the code, and then connect those concepts to the specific questions being asked.
This header file, `v8/src/common/assert-scope.h`, in the V8 JavaScript engine serves as a **mechanism for defining scopes within the V8 codebase where certain conditions are expected or explicitly *not* expected to occur.**  These scopes are primarily used for **internal debugging and verification** during development. They help catch potential bugs and enforce internal invariants.

Here's a breakdown of its functionality:

**Core Concepts:**

* **Assertion Scopes:** The central idea is to create temporary scopes where specific types of assertions are either enabled or disabled. When entering a scope, the state of the assertion is modified, and when exiting the scope, the original state is restored.
* **Per-Thread Assertions:**  Some assertions are tracked on a per-thread basis. This means each thread can have its own set of active assertions.
* **Per-Isolate Assertions:** Other assertions are tracked on a per-isolate basis. An isolate in V8 is an independent instance of the JavaScript engine.
* **Assertion Types (`PerThreadAssertType` enum):**  This enum defines the different categories of conditions being asserted. Examples include:
    * `SAFEPOINTS_ASSERT`: Whether the code should encounter safepoints (points where the garbage collector can safely pause execution).
    * `HEAP_ALLOCATION_ASSERT`: Whether memory allocation on the heap is allowed.
    * `HANDLE_ALLOCATION_ASSERT`: Whether the allocation of handles (pointers to V8 objects) is allowed.
    * `DisallowJavascriptExecution`: Whether JavaScript execution is expected within the scope.
    * And many more...
* **Enabling and Disabling:**  For each assertion type, there are often corresponding "Allow" and "Disallow" scope classes (e.g., `AllowHeapAllocation`, `DisallowHeapAllocation`).

**Key Functionalities:**

1. **Documenting Expectations:** These scopes act as documentation within the code, clearly indicating what the developers expect (or don't expect) to happen in a particular section.
2. **Internal Debugging:** During development (especially in debug builds), these scopes trigger assertions if the expected conditions are violated. This helps identify bugs early.
3. **Enforcing Invariants:** They help ensure that internal V8 logic adheres to certain rules and constraints.
4. **Conditional Compilation (Debug vs. Release):**  Many of these assertion scopes are active only in debug builds. In release builds, they might become no-ops or have minimal overhead to avoid performance impact. This is evident in the use of `PerThreadAssertScopeDebugOnly` and the conditional `#ifdef DEBUG` blocks.

**If `v8/src/common/assert-scope.h` ended with `.tq`, it would be a V8 Torque source file.**

Torque is V8's internal language for writing highly optimized runtime functions. While this header file defines the *mechanism* for assertions, a `.tq` file could potentially *use* these assertion scopes within its generated C++ code.

**Relationship with JavaScript and Examples:**

While this header file is primarily C++ code for internal V8 debugging, the assertions it defines are often related to the execution of JavaScript code. Here are some examples:

* **`DisallowHeapAllocation`:**  If V8 developers know that a particular internal operation *should not* involve allocating new memory on the heap, they can wrap that code in a `DisallowHeapAllocation` scope. If, during execution, a heap allocation unexpectedly occurs within that scope (in a debug build), an assertion will fail, indicating a potential bug.

   **JavaScript Example (indirectly related):**  Consider a highly optimized built-in function like `String.prototype.charCodeAt`. V8 developers might use `DisallowHeapAllocation` in parts of its implementation because they aim for a fast, allocation-free path. If a change introduces an unexpected allocation, the assertion would catch it.

* **`DisallowJavascriptExecution`:** There are scenarios within V8's execution (e.g., during certain phases of garbage collection or compilation) where JavaScript code is not expected to be running.

   **JavaScript Example (indirectly related):** Imagine a garbage collection routine in V8. While the GC is running and trying to reclaim memory, allowing arbitrary JavaScript code to execute could lead to inconsistencies and crashes. `DisallowJavascriptExecution` scopes would be used within the GC implementation to enforce this. If a bug caused JavaScript execution to be triggered during GC, the assertion would fail.

* **`AllowDeoptimization` / `DisallowDeoptimization`:** V8 optimizes JavaScript code using techniques like Just-in-Time (JIT) compilation. Sometimes, for various reasons, optimized code needs to be "deoptimized" back to a less optimized state.

   **JavaScript Example:**

   ```javascript
   function add(a, b) {
     return a + b;
   }

   // Initially, V8 might optimize `add` for numbers.
   add(1, 2);
   add(3, 4);

   // If we later call `add` with strings, V8 might deoptimize it.
   add("hello", "world");
   ```

   V8 developers might use `DisallowDeoptimization` in code that *should not* cause deoptimization under normal circumstances. If unexpected deoptimization happens, the assertion would trigger.

**Code Logic Reasoning (Example with Assumptions):**

Let's consider the `DisallowHeapAllocation` scope:

**Assumptions:**

1. We are in a debug build of V8.
2. We have a piece of internal V8 code that we expect to run without allocating memory on the heap.

**Input:**

* The `DisallowHeapAllocation` scope is entered. This sets a flag (or counter) internally indicating that heap allocation is disallowed for the current thread.
* Within the scope, a function is called that *unintentionally* allocates memory on the heap (e.g., creating a new object or string).

**Output:**

* When the allocation occurs, V8's internal allocation routines check the current assertion state.
* Because `DisallowHeapAllocation` is active, an assertion failure is triggered (likely a `DCHECK` in V8's codebase). This would typically halt execution or log an error message, helping developers identify the problematic allocation.

**Common User Programming Errors (Indirectly Related):**

While users don't directly interact with these assertion scopes, the kinds of errors they help catch in V8 can be related to common programming mistakes:

1. **Memory Leaks:** If V8 code unexpectedly allocates memory without a corresponding deallocation, assertions like `DisallowHeapAllocation` in strategic locations can help pinpoint the source of the leak.

   **C++ Example (illustrative, not direct user code):**

   ```c++
   void buggy_function() {
     v8::internal::AllowHeapAllocation allocation_scope; // Incorrectly allowing allocation

     char* data = new char[1024];
     // ... forgot to delete[] data;
   }
   ```

2. **Race Conditions and Concurrency Issues:** Assertions related to safepoints or handle usage on all threads can help detect problems where different threads are interacting in unexpected ways, potentially leading to data corruption or crashes.

3. **Incorrect Assumptions about Object Lifecycles:** If V8 code assumes an object will remain valid but it gets garbage collected prematurely, assertions related to handle dereferencing might catch this.

**In summary, `v8/src/common/assert-scope.h` is a crucial piece of V8's internal debugging infrastructure. It allows developers to express expectations about the behavior of their code and provides a mechanism to automatically detect violations of those expectations during development, ultimately leading to a more robust and reliable JavaScript engine.**

### 提示词
```
这是目录为v8/src/common/assert-scope.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/common/assert-scope.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMMON_ASSERT_SCOPE_H_
#define V8_COMMON_ASSERT_SCOPE_H_

#include <stdint.h>

#include <optional>

#include "src/base/macros.h"
#include "src/base/platform/mutex.h"
#include "src/common/globals.h"

namespace v8 {
namespace internal {

// Forward declarations.
class Isolate;

enum PerThreadAssertType {
  // Dummy type for indicating a valid PerThreadAsserts data. This is
  // represented by an always-on bit, and is cleared when a scope's saved data
  // is zeroed -- it should never be set or cleared on the actual per-thread
  // data by a scope.
  ASSERT_TYPE_IS_VALID_MARKER,

  SAFEPOINTS_ASSERT,
  HEAP_ALLOCATION_ASSERT,
  HANDLE_ALLOCATION_ASSERT,
  HANDLE_DEREFERENCE_ASSERT,
  HANDLE_USAGE_ON_ALL_THREADS_ASSERT,
  CODE_DEPENDENCY_CHANGE_ASSERT,
  CODE_ALLOCATION_ASSERT,
  // Dummy type for disabling GC mole.
  GC_MOLE,
  POSITION_INFO_SLOW_ASSERT,
};

using PerThreadAsserts = base::EnumSet<PerThreadAssertType, uint32_t>;

// Empty assert scope, used for debug-only scopes in release mode so that
// the release-enabled PerThreadAssertScope is always an alias for, or a
// subclass of PerThreadAssertScopeDebugOnly, and can be used in place of it.
// This class is also templated so that it still has distinct instances for each
// debug scope -- this is necessary for GCMole to be able to recognise
// DisableGCMole scopes as distinct from other assert scopes.
template <bool kAllow, PerThreadAssertType... kTypes>
class V8_NODISCARD PerThreadAssertScopeEmpty {
 public:
  // Define a constructor to avoid unused variable warnings.
  // NOLINTNEXTLINE
  PerThreadAssertScopeEmpty() {}
  void Release() {}
};

template <bool kAllow, PerThreadAssertType... kTypes>
class V8_NODISCARD PerThreadAssertScope
    : public PerThreadAssertScopeEmpty<kAllow, kTypes...> {
 public:
  V8_EXPORT_PRIVATE PerThreadAssertScope();
  V8_EXPORT_PRIVATE ~PerThreadAssertScope();

  PerThreadAssertScope(const PerThreadAssertScope&) = delete;
  PerThreadAssertScope& operator=(const PerThreadAssertScope&) = delete;

  V8_EXPORT_PRIVATE static bool IsAllowed();

  void Release();

 private:
  PerThreadAsserts old_data_;
};

// Per-isolate assert scopes.

#define PER_ISOLATE_DCHECK_TYPE(V, enable)                              \
  /* Scope to document where we do not expect javascript execution. */  \
  /* Scope to introduce an exception to DisallowJavascriptExecution. */ \
  V(AllowJavascriptExecution, DisallowJavascriptExecution,              \
    javascript_execution_assert, enable)                                \
  /* Scope to document where we do not expect deoptimization. */        \
  /* Scope to introduce an exception to DisallowDeoptimization. */      \
  V(AllowDeoptimization, DisallowDeoptimization, deoptimization_assert, \
    enable)                                                             \
  /* Scope to document where we do not expect deoptimization. */        \
  /* Scope to introduce an exception to DisallowDeoptimization. */      \
  V(AllowCompilation, DisallowCompilation, compilation_assert, enable)  \
  /* Scope to document where we do not expect exceptions. */            \
  /* Scope to introduce an exception to DisallowExceptions. */          \
  V(AllowExceptions, DisallowExceptions, no_exception_assert, enable)

#define PER_ISOLATE_CHECK_TYPE(V, enable)                                    \
  /* Scope in which javascript execution leads to exception being thrown. */ \
  /* Scope to introduce an exception to ThrowOnJavascriptExecution. */       \
  V(NoThrowOnJavascriptExecution, ThrowOnJavascriptExecution,                \
    javascript_execution_throws, enable)                                     \
  /* Scope in which javascript execution causes dumps. */                    \
  /* Scope in which javascript execution doesn't cause dumps. */             \
  V(NoDumpOnJavascriptExecution, DumpOnJavascriptExecution,                  \
    javascript_execution_dump, enable)

#define PER_ISOLATE_ASSERT_SCOPE_DECLARATION(ScopeType)              \
  class V8_NODISCARD ScopeType {                                     \
   public:                                                           \
    V8_EXPORT_PRIVATE explicit ScopeType(Isolate* isolate);          \
    ScopeType(const ScopeType&) = delete;                            \
    ScopeType& operator=(const ScopeType&) = delete;                 \
    V8_EXPORT_PRIVATE ~ScopeType();                                  \
                                                                     \
    static bool IsAllowed(Isolate* isolate);                         \
                                                                     \
    V8_EXPORT_PRIVATE static void Open(Isolate* isolate,             \
                                       bool* was_execution_allowed); \
    V8_EXPORT_PRIVATE static void Close(Isolate* isolate,            \
                                        bool was_execution_allowed); \
                                                                     \
   private:                                                          \
    Isolate* isolate_;                                               \
    bool old_data_;                                                  \
  };

#define PER_ISOLATE_ASSERT_ENABLE_SCOPE(EnableType, _1, _2, _3) \
  PER_ISOLATE_ASSERT_SCOPE_DECLARATION(EnableType)

#define PER_ISOLATE_ASSERT_DISABLE_SCOPE(_1, DisableType, _2, _3) \
  PER_ISOLATE_ASSERT_SCOPE_DECLARATION(DisableType)

PER_ISOLATE_DCHECK_TYPE(PER_ISOLATE_ASSERT_ENABLE_SCOPE, true)
PER_ISOLATE_CHECK_TYPE(PER_ISOLATE_ASSERT_ENABLE_SCOPE, true)
PER_ISOLATE_DCHECK_TYPE(PER_ISOLATE_ASSERT_DISABLE_SCOPE, false)
PER_ISOLATE_CHECK_TYPE(PER_ISOLATE_ASSERT_DISABLE_SCOPE, false)

#ifdef DEBUG
#define PER_ISOLATE_DCHECK_ENABLE_SCOPE(EnableType, DisableType, field, _)    \
  class EnableType##DebugOnly : public EnableType {                           \
   public:                                                                    \
    explicit EnableType##DebugOnly(Isolate* isolate) : EnableType(isolate) {} \
  };
#else
#define PER_ISOLATE_DCHECK_ENABLE_SCOPE(EnableType, DisableType, field, _) \
  class V8_NODISCARD EnableType##DebugOnly {                               \
   public:                                                                 \
    explicit EnableType##DebugOnly(Isolate* isolate) {}                    \
  };
#endif

#ifdef DEBUG
#define PER_ISOLATE_DCHECK_DISABLE_SCOPE(EnableType, DisableType, field, _) \
  class DisableType##DebugOnly : public DisableType {                       \
   public:                                                                  \
    explicit DisableType##DebugOnly(Isolate* isolate)                       \
        : DisableType(isolate) {}                                           \
  };
#else
#define PER_ISOLATE_DCHECK_DISABLE_SCOPE(EnableType, DisableType, field, _) \
  class V8_NODISCARD DisableType##DebugOnly {                               \
   public:                                                                  \
    explicit DisableType##DebugOnly(Isolate* isolate) {}                    \
  };
#endif

PER_ISOLATE_DCHECK_TYPE(PER_ISOLATE_DCHECK_ENABLE_SCOPE, true)
PER_ISOLATE_DCHECK_TYPE(PER_ISOLATE_DCHECK_DISABLE_SCOPE, false)

#ifdef DEBUG
template <bool kAllow, PerThreadAssertType... kTypes>
using PerThreadAssertScopeDebugOnly = PerThreadAssertScope<kAllow, kTypes...>;
#else
template <bool kAllow, PerThreadAssertType... kTypes>
using PerThreadAssertScopeDebugOnly =
    PerThreadAssertScopeEmpty<kAllow, kTypes...>;
#endif

// Per-thread assert scopes.

// Scope to document where we do not expect handles to be created.
using DisallowHandleAllocation =
    PerThreadAssertScopeDebugOnly<false, HANDLE_ALLOCATION_ASSERT>;

// Scope to introduce an exception to DisallowHandleAllocation.
using AllowHandleAllocation =
    PerThreadAssertScopeDebugOnly<true, HANDLE_ALLOCATION_ASSERT>;

// Scope to document where we do not expect safepoints to be entered.
using DisallowSafepoints =
    PerThreadAssertScopeDebugOnly<false, SAFEPOINTS_ASSERT>;

// Scope to introduce an exception to DisallowSafepoints.
using AllowSafepoints = PerThreadAssertScopeDebugOnly<true, SAFEPOINTS_ASSERT>;

// Scope to document where we do not expect any allocation.
using DisallowHeapAllocation =
    PerThreadAssertScopeDebugOnly<false, HEAP_ALLOCATION_ASSERT>;

// Scope to introduce an exception to DisallowHeapAllocation.
using AllowHeapAllocation =
    PerThreadAssertScopeDebugOnly<true, HEAP_ALLOCATION_ASSERT>;

// Like AllowHeapAllocation, but enabled in release builds.
using AllowHeapAllocationInRelease =
    PerThreadAssertScope<true, HEAP_ALLOCATION_ASSERT>;

// Scope to document where we do not expect any handle dereferences.
using DisallowHandleDereference =
    PerThreadAssertScopeDebugOnly<false, HANDLE_DEREFERENCE_ASSERT>;

// Scope to introduce an exception to DisallowHandleDereference.
using AllowHandleDereference =
    PerThreadAssertScopeDebugOnly<true, HANDLE_DEREFERENCE_ASSERT>;

// Explicitly allow handle dereference and creation for all threads/isolates on
// one particular thread.
using AllowHandleUsageOnAllThreads =
    PerThreadAssertScopeDebugOnly<true, HANDLE_USAGE_ON_ALL_THREADS_ASSERT>;

// Scope to document where we do not expect code dependencies to change.
using DisallowCodeDependencyChange =
    PerThreadAssertScopeDebugOnly<false, CODE_DEPENDENCY_CHANGE_ASSERT>;

// Scope to introduce an exception to DisallowCodeDependencyChange.
using AllowCodeDependencyChange =
    PerThreadAssertScopeDebugOnly<true, CODE_DEPENDENCY_CHANGE_ASSERT>;

// Scope to document where we do not expect code to be allocated.
using DisallowCodeAllocation =
    PerThreadAssertScopeDebugOnly<false, CODE_ALLOCATION_ASSERT>;

// Scope to introduce an exception to DisallowCodeAllocation.
using AllowCodeAllocation =
    PerThreadAssertScopeDebugOnly<true, CODE_ALLOCATION_ASSERT>;

// Scope to document where we do not expect garbage collections. It differs from
// DisallowHeapAllocation by also forbidding safepoints.
using DisallowGarbageCollection =
    PerThreadAssertScopeDebugOnly<false, SAFEPOINTS_ASSERT,
                                  HEAP_ALLOCATION_ASSERT>;

// Like DisallowGarbageCollection, but enabled in release builds.
using DisallowGarbageCollectionInRelease =
    PerThreadAssertScope<false, SAFEPOINTS_ASSERT, HEAP_ALLOCATION_ASSERT>;

// Scope to skip gc mole verification in places where we do tricky raw
// work.
using DisableGCMole = PerThreadAssertScopeDebugOnly<false, GC_MOLE>;

// Scope to ensure slow path for obtaining position info is not called
using DisallowPositionInfoSlow =
    PerThreadAssertScopeDebugOnly<false, POSITION_INFO_SLOW_ASSERT>;

// Scope to add an exception to disallowing position info slow path
using AllowPositionInfoSlow =
    PerThreadAssertScopeDebugOnly<true, POSITION_INFO_SLOW_ASSERT>;

// The DISALLOW_GARBAGE_COLLECTION macro can be used to define a
// DisallowGarbageCollection field in classes that isn't present in release
// builds.
#ifdef DEBUG
#define DISALLOW_GARBAGE_COLLECTION(name) DisallowGarbageCollection name;
#else
#define DISALLOW_GARBAGE_COLLECTION(name)
#endif

// Scope to introduce an exception to DisallowGarbageCollection.
using AllowGarbageCollection =
    PerThreadAssertScopeDebugOnly<true, SAFEPOINTS_ASSERT,
                                  HEAP_ALLOCATION_ASSERT>;

// Like AllowGarbageCollection, but enabled in release builds.
using AllowGarbageCollectionInRelease =
    PerThreadAssertScope<true, SAFEPOINTS_ASSERT, HEAP_ALLOCATION_ASSERT>;

// Scope to document where we do not expect any access to the heap.
using DisallowHeapAccess = PerThreadAssertScopeDebugOnly<
    false, CODE_DEPENDENCY_CHANGE_ASSERT, HANDLE_DEREFERENCE_ASSERT,
    HANDLE_ALLOCATION_ASSERT, HEAP_ALLOCATION_ASSERT>;

// Scope to introduce an exception to DisallowHeapAccess.
using AllowHeapAccess = PerThreadAssertScopeDebugOnly<
    true, CODE_DEPENDENCY_CHANGE_ASSERT, HANDLE_DEREFERENCE_ASSERT,
    HANDLE_ALLOCATION_ASSERT, HEAP_ALLOCATION_ASSERT>;

class DisallowHeapAccessIf {
 public:
  explicit DisallowHeapAccessIf(bool condition) {
    if (condition) maybe_disallow_.emplace();
  }

 private:
  std::optional<DisallowHeapAccess> maybe_disallow_;
};

// Like MutexGuard but also asserts that no garbage collection happens while
// we're holding the mutex.
class V8_NODISCARD NoGarbageCollectionMutexGuard {
 public:
  explicit NoGarbageCollectionMutexGuard(base::Mutex* mutex)
      : guard_(mutex), mutex_(mutex), no_gc_(std::in_place) {}

  void Unlock() {
    mutex_->Unlock();
    no_gc_.reset();
  }
  void Lock() {
    mutex_->Lock();
    no_gc_.emplace();
  }

 private:
  base::MutexGuard guard_;
  base::Mutex* mutex_;
  std::optional<DisallowGarbageCollection> no_gc_;
};

// Explicit instantiation declarations.
extern template class PerThreadAssertScope<false, HEAP_ALLOCATION_ASSERT>;
extern template class PerThreadAssertScope<true, HEAP_ALLOCATION_ASSERT>;
extern template class PerThreadAssertScope<false, SAFEPOINTS_ASSERT>;
extern template class PerThreadAssertScope<true, SAFEPOINTS_ASSERT>;
extern template class PerThreadAssertScope<false, HANDLE_ALLOCATION_ASSERT>;
extern template class PerThreadAssertScope<true, HANDLE_ALLOCATION_ASSERT>;
extern template class PerThreadAssertScope<false, HANDLE_DEREFERENCE_ASSERT>;
extern template class PerThreadAssertScope<true, HANDLE_DEREFERENCE_ASSERT>;
extern template class PerThreadAssertScope<false,
                                           CODE_DEPENDENCY_CHANGE_ASSERT>;
extern template class PerThreadAssertScope<true, CODE_DEPENDENCY_CHANGE_ASSERT>;
extern template class PerThreadAssertScope<false, CODE_ALLOCATION_ASSERT>;
extern template class PerThreadAssertScope<true, CODE_ALLOCATION_ASSERT>;
extern template class PerThreadAssertScope<false, GC_MOLE>;
extern template class PerThreadAssertScope<false, POSITION_INFO_SLOW_ASSERT>;
extern template class PerThreadAssertScope<true, POSITION_INFO_SLOW_ASSERT>;
extern template class PerThreadAssertScope<false, SAFEPOINTS_ASSERT,
                                           HEAP_ALLOCATION_ASSERT>;
extern template class PerThreadAssertScope<true, SAFEPOINTS_ASSERT,
                                           HEAP_ALLOCATION_ASSERT>;
extern template class PerThreadAssertScope<
    false, CODE_DEPENDENCY_CHANGE_ASSERT, HANDLE_DEREFERENCE_ASSERT,
    HANDLE_ALLOCATION_ASSERT, HEAP_ALLOCATION_ASSERT>;
extern template class PerThreadAssertScope<
    true, CODE_DEPENDENCY_CHANGE_ASSERT, HANDLE_DEREFERENCE_ASSERT,
    HANDLE_ALLOCATION_ASSERT, HEAP_ALLOCATION_ASSERT>;

}  // namespace internal
}  // namespace v8

#endif  // V8_COMMON_ASSERT_SCOPE_H_
```