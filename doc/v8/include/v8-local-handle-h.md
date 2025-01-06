Response:
Let's break down the thought process for analyzing the `v8-local-handle.h` file.

1. **Understanding the Request:** The core request is to understand the *functionality* of the header file. The prompt also includes specific constraints: check if it's Torque, relate to JavaScript, provide examples, illustrate logical reasoning, and show common user errors.

2. **Initial Scan and Keyword Recognition:**  I start by skimming the code, looking for key terms and patterns. I see:
    * `#ifndef INCLUDE_V8_LOCAL_HANDLE_H_`, `#define INCLUDE_V8_LOCAL_HANDLE_H_`, `#include`: This indicates a standard C++ header file. The `.h` extension confirms this, and the prompt's hint about `.tq` ending becomes irrelevant.
    * `namespace v8`:  This clearly defines the scope of the code.
    * `class V8_EXPORT V8_NODISCARD HandleScope`:  `HandleScope` stands out as a central concept. The comments provide immediate context: managing local handles.
    * `template <class T> class LocalBase`, `template <class T> class Local`: The `Local` template and its base class are clearly related to object references. The comments explain the concepts of local vs. persistent handles.
    * `template <class T> class MaybeLocal`: This suggests a wrapper for `Local` that might represent the absence of a valid handle.
    * Various other class declarations like `Eternal`, `Global`, `Persistent`, `Boolean`, `Context`, `String`, etc.: These are likely V8's representation of JavaScript types or related concepts.
    * `Isolate`: This is a fundamental V8 concept, representing an isolated JavaScript execution environment.
    * Comments like "object reference managed by the v8 garbage collector":  This points to the memory management aspect.

3. **Deconstructing Key Classes:** I focus on the core classes and their responsibilities:
    * **`HandleScope`:**  The primary mechanism for managing the lifetime of local handles. It's stack-allocated and automatically cleans up handles when it goes out of scope. This is crucial for preventing memory leaks.
    * **`LocalBase`:** An implementation detail, likely handling the underlying representation of the handle (direct or indirect pointer). The user doesn't interact with this directly.
    * **`Local<T>`:** The core local handle class. It's a lightweight, temporary reference to a V8 object. The comments about garbage collection are important here.
    * **`MaybeLocal<T>`:**  Handles the possibility of operations failing (returning no valid object). This is essential for error handling in the V8 API.
    * **`EscapableHandleScope`:**  Allows a local handle to "escape" the current scope and be used in an outer scope. This is needed for returning values from callbacks, for example.

4. **Relating to JavaScript:** This is a crucial part of the request. I connect the C++ concepts to their JavaScript counterparts:
    * `Local<Object>` represents a JavaScript object.
    * `Local<String>` represents a JavaScript string.
    * `Local<Number>` represents a JavaScript number.
    * `Local<Boolean>` represents a JavaScript boolean.
    * `Local<Context>` represents a JavaScript execution context.
    * The handle mechanism is invisible to JavaScript developers but is fundamental to how V8 manages JavaScript objects in memory.

5. **Providing JavaScript Examples:**  I think about scenarios where these concepts would be used when embedding V8 in a C++ application:
    * Creating and using local variables within a function call (the `HandleScope` context).
    * Returning values from C++ functions called by JavaScript (using `EscapableHandleScope`).
    * Handling potential errors when calling V8 API functions (using `MaybeLocal`).

6. **Logical Reasoning and Examples:** I consider the implications of handle scopes and local handles:
    * **Input:** Creating a `Local` within a `HandleScope`.
    * **Output:** The `Local` is valid within the scope.
    * **Input:** Accessing the `Local` after the `HandleScope` has been destroyed.
    * **Output:** Undefined behavior (likely a crash or accessing garbage memory). This directly leads to a common programming error.

7. **Common Programming Errors:**  Based on my understanding of handle scopes and lifetimes, the most obvious errors are:
    * Accessing a `Local` after its `HandleScope` has been destroyed (use-after-free).
    * Incorrectly assuming `Local` handles persist indefinitely.
    * Forgetting to use `EscapableHandleScope` when returning `Local` handles from callbacks.
    * Ignoring the possibility of `MaybeLocal` being empty, leading to crashes when calling `ToLocalChecked` without checking.

8. **Torque Check:** The prompt specifically asks about Torque. The absence of `.tq` and the presence of standard C++ constructs confirms that this is a C++ header.

9. **Structuring the Output:** I organize the information logically:
    * Start with a general overview of the file's purpose.
    * Explain the core classes (`HandleScope`, `Local`, `MaybeLocal`, `EscapableHandleScope`).
    * Provide JavaScript examples to illustrate the concepts.
    * Describe the logical reasoning behind handle scopes and their lifetime.
    * List common programming errors related to handle management.
    * Explicitly address the Torque question.

10. **Refinement:** I review the explanation for clarity, accuracy, and completeness, ensuring it addresses all aspects of the prompt. I make sure the examples are simple and illustrative. I double-check the explanation of `MaybeLocal` and error handling.

This iterative process of scanning, deconstructing, connecting to JavaScript, providing examples, and considering error scenarios helps to generate a comprehensive understanding of the `v8-local-handle.h` file.
`v8/include/v8-local-handle.h` 是 V8 JavaScript 引擎中定义本地句柄（Local Handle）相关类型的头文件。它的主要功能是提供一种安全且高效的方式来管理 V8 堆上的 JavaScript 对象引用。

**功能列表:**

1. **定义 `HandleScope` 类:**
   - `HandleScope` 是一个栈分配的类，用于管理本地句柄的生命周期。
   - 当创建一个 `HandleScope` 时，所有新分配的本地句柄都会在这个作用域内进行管理。
   - 当 `HandleScope` 被销毁时，其管理的本地句柄也会失效，V8 的垃圾回收器可以回收这些句柄所引用的对象。
   - 这是一种 RAII (Resource Acquisition Is Initialization) 模式的应用，确保资源（本地句柄）的自动释放，防止内存泄漏。

2. **定义 `Local<T>` 模板类:**
   - `Local<T>` 是一个模板类，表示对 V8 堆上类型为 `T` 的对象的本地句柄。
   - 本地句柄是轻量级的、临时的引用，只能在创建它的 `HandleScope` 的生命周期内有效。
   - `Local<T>` 提供了对所引用对象的安全访问方式。由于垃圾回收器可能会移动对象，直接使用原始指针是不安全的，而 `Local<T>` 会在对象移动时自动更新其内部的引用。
   - 它重载了 `operator->` 和 `operator*`，使得使用本地句柄就像使用原始指针一样方便。
   - 提供了比较运算符 (`==`, `!=`) 来比较两个句柄是否引用相同的对象。
   - 提供了类型转换方法 `Cast` 和 `As`，用于在继承关系的类型之间转换句柄。

3. **定义 `MaybeLocal<T>` 模板类:**
   - `MaybeLocal<T>` 是一个包装了 `Local<T>` 的模板类，用于表示可能为空的本地句柄。
   - 当 V8 API 函数可能因为异常或其他原因无法返回有效的对象时，会返回 `MaybeLocal<T>`。
   - 使用 `MaybeLocal<T>` 可以强制开发者在访问句柄之前检查其是否为空，从而避免潜在的错误。
   - 提供了 `IsEmpty()`, `ToLocal()`, `ToLocalChecked()`, `FromMaybe()` 等方法来处理可能为空的情况。

4. **定义 `EscapableHandleScope` 类:**
   - `EscapableHandleScope` 继承自 `HandleScope`，并添加了允许本地句柄“逃逸”当前作用域的功能。
   - 通过 `Escape()` 方法，可以将一个在当前 `EscapableHandleScope` 中创建的本地句柄传递到外部的作用域，使其在外部作用域也有效。这通常用于从回调函数中返回本地句柄。

5. **定义 `SealHandleScope` 类:**
   - `SealHandleScope` 用于创建一个不允许分配新本地句柄的作用域。
   - 这主要用于调试，帮助检测潜在的句柄泄漏问题。

6. **定义 `LocalVector<T>` 模板类:**
   - `LocalVector<T>` 提供了一种管理本地句柄数组的方式，类似于 `std::vector`，但存储的是 `Local<T>` 类型的句柄。
   - 它负责管理内部存储，并在需要时进行内存分配和释放。

**关于文件扩展名和 Torque:**

- `v8/include/v8-local-handle.h` 的文件扩展名是 `.h`，这表明它是一个标准的 C++ 头文件。
- 如果文件以 `.tq` 结尾，那么它才是 V8 Torque 的源代码。Torque 是 V8 用于编写其内部运行时代码的领域特定语言。

**与 JavaScript 功能的关系 (使用 JavaScript 举例):**

`v8-local-handle.h` 中定义的类型是 V8 引擎内部用来管理 JavaScript 对象的关键机制。虽然 JavaScript 开发者不会直接操作这些类型，但它们直接影响着 JavaScript 对象的创建、使用和销毁。

例如，当你在 JavaScript 中创建一个新的对象时：

```javascript
const myObject = {};
```

在 V8 引擎的 C++ 代码中，会创建一个对应的 `Local<Object>` 句柄来引用这个新创建的 JavaScript 对象。这个 `Local<Object>` 会在当前的 `HandleScope` 的管理下。

当你在 JavaScript 函数中返回一个对象时：

```javascript
function createObject() {
  return {};
}

const returnedObject = createObject();
```

V8 可能会使用 `EscapableHandleScope` 来确保在 `createObject` 函数内部创建的 `Local<Object>` 句柄能够安全地传递到外部作用域，以便 `returnedObject` 能够引用该对象。

**代码逻辑推理 (假设输入与输出):**

假设有以下 C++ 代码片段：

```c++
#include "v8.h"
#include <iostream>

v8::Local<v8::String> createV8String(v8::Isolate* isolate, const char* str) {
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::String> result = v8::String::NewFromUtf8(
      isolate, str, v8::NewStringType::kNormal).ToLocalChecked();
  return result; // 错误：result 是在 handle_scope 内创建的，离开作用域后会失效
}

int main() {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator =
      v8::ArrayBuffer::Allocator::NewDefaultAllocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);

    v8::Local<v8::String> myString = createV8String(isolate, "Hello");
    if (!myString.IsEmpty()) {
      v8::String::Utf8Value utf8(isolate, myString);
      std::cout << *utf8 << std::endl; // 可能会输出乱码或崩溃
    }
  }
  isolate->Dispose();
  delete create_params.array_buffer_allocator;
  return 0;
}
```

**假设输入:** `createV8String` 函数被调用，传入一个 `v8::Isolate` 指针和一个字符串 "Hello"。

**预期输出 (错误):**  由于 `createV8String` 函数返回了一个在 `HandleScope` 内部创建的 `Local<v8::String>` 句柄，当 `createV8String` 函数返回时，其内部的 `handle_scope` 被销毁，`result` 句柄变得无效。在 `main` 函数中尝试使用这个无效的句柄 `myString` 可能会导致程序崩溃或输出乱码，因为该句柄指向的内存可能已经被回收或重新分配。

**正确的做法是使用 `EscapableHandleScope`:**

```c++
v8::Local<v8::String> createV8String(v8::Isolate* isolate, const char* str) {
  v8::EscapableHandleScope handle_scope(isolate);
  v8::Local<v8::String> result = v8::String::NewFromUtf8(
      isolate, str, v8::NewStringType::kNormal).ToLocalChecked();
  return handle_scope.Escape(result); // 正确：将句柄传递到外部作用域
}
```

**涉及用户常见的编程错误:**

1. **在 `HandleScope` 之外使用本地句柄:** 这是最常见的错误。开发者可能会忘记本地句柄的生命周期与创建它的 `HandleScope` 相关联，并在 `HandleScope` 销毁后继续使用该句柄。

   ```c++
   v8::Local<v8::Object> createObject(v8::Isolate* isolate) {
     v8::HandleScope handle_scope(isolate);
     v8::Local<v8::Object> obj = v8::Object::New(isolate);
     return obj; // 错误：obj 在 handle_scope 结束后失效
   }

   void processObject(v8::Isolate* isolate) {
     v8::Local<v8::Object> myObj = createObject(isolate);
     // 尝试在 createObject 的 HandleScope 结束后使用 myObj
     if (!myObj.IsEmpty()) { // 可能会崩溃或行为异常
       // ...
     }
   }
   ```

2. **忘记使用 `EscapableHandleScope` 从回调函数或局部作用域返回本地句柄:** 当需要在外部作用域中使用在内部作用域创建的本地句柄时，必须使用 `EscapableHandleScope` 的 `Escape()` 方法。

   ```c++
   v8::Local<v8::Value> myCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
     v8::Isolate* isolate = info.GetIsolate();
     v8::HandleScope handle_scope(isolate);
     v8::Local<v8::String> result = v8::String::NewFromUtf8(
         isolate, "Callback Result", v8::NewStringType::kNormal).ToLocalChecked();
     return result; // 错误：result 在回调函数返回后失效
   }

   // 正确的做法：
   v8::Local<v8::Value> myCallbackCorrect(const v8::FunctionCallbackInfo<v8::Value>& info) {
     v8::Isolate* isolate = info.GetIsolate();
     v8::EscapableHandleScope handle_scope(isolate);
     v8::Local<v8::String> result = v8::String::NewFromUtf8(
         isolate, "Callback Result", v8::NewStringType::kNormal).ToLocalChecked();
     return handle_scope.Escape(result);
   }
   ```

3. **不检查 `MaybeLocal` 的状态就直接使用 `ToLocalChecked()`:** 如果一个 V8 API 函数返回 `MaybeLocal<T>`，表示操作可能失败并返回空句柄。直接调用 `ToLocalChecked()` 而不检查 `IsEmpty()` 会导致程序在操作失败时崩溃。

   ```c++
   v8::MaybeLocal<v8::String> maybeString = v8::String::NewFromUtf8(isolate, nullptr); // 模拟操作失败
   v8::Local<v8::String> myString = maybeString.ToLocalChecked(); // 错误：maybeString 为空，会崩溃
   ```

   **正确的做法:**

   ```c++
   v8::MaybeLocal<v8::String> maybeString = v8::String::NewFromUtf8(isolate, nullptr);
   v8::Local<v8::String> myString;
   if (!maybeString.IsEmpty()) {
     myString = maybeString.ToLocalChecked();
     // ... 使用 myString
   } else {
     // 处理操作失败的情况
   }
   ```

理解 `v8-local-handle.h` 中定义的类型和它们的作用域规则对于编写正确的 V8 嵌入代码至关重要。正确地使用 `HandleScope`、`Local`、`MaybeLocal` 和 `EscapableHandleScope` 可以有效地防止内存泄漏和程序崩溃。

Prompt: 
```
这是目录为v8/include/v8-local-handle.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-local-handle.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_LOCAL_HANDLE_H_
#define INCLUDE_V8_LOCAL_HANDLE_H_

#include <stddef.h>

#include <type_traits>
#include <vector>

#include "v8-handle-base.h"  // NOLINT(build/include_directory)
#include "v8-internal.h"     // NOLINT(build/include_directory)

namespace v8 {

template <class T>
class LocalBase;
template <class T>
class Local;
template <class T>
class LocalVector;
template <class F>
class MaybeLocal;

template <class T>
class Eternal;
template <class T>
class Global;

template <class T>
class NonCopyablePersistentTraits;
template <class T>
class PersistentBase;
template <class T, class M = NonCopyablePersistentTraits<T>>
class Persistent;

class TracedReferenceBase;
template <class T>
class BasicTracedReference;
template <class F>
class TracedReference;

class Boolean;
class Context;
class EscapableHandleScope;
template <class F>
class FunctionCallbackInfo;
class Isolate;
class Object;
template <class F1, class F2, class F3>
class PersistentValueMapBase;
class Primitive;
class Private;
template <class F>
class PropertyCallbackInfo;
template <class F>
class ReturnValue;
class String;
template <class F>
class Traced;
class TypecheckWitness;
class Utils;

namespace debug {
class ConsoleCallArguments;
}

namespace internal {
template <typename T>
class CustomArguments;
template <typename T>
class LocalUnchecked;
class SamplingHeapProfiler;
}  // namespace internal

namespace api_internal {
// Called when ToLocalChecked is called on an empty Local.
V8_EXPORT void ToLocalEmpty();
}  // namespace api_internal

/**
 * A stack-allocated class that governs a number of local handles.
 * After a handle scope has been created, all local handles will be
 * allocated within that handle scope until either the handle scope is
 * deleted or another handle scope is created.  If there is already a
 * handle scope and a new one is created, all allocations will take
 * place in the new handle scope until it is deleted.  After that,
 * new handles will again be allocated in the original handle scope.
 *
 * After the handle scope of a local handle has been deleted the
 * garbage collector will no longer track the object stored in the
 * handle and may deallocate it.  The behavior of accessing a handle
 * for which the handle scope has been deleted is undefined.
 */
class V8_EXPORT V8_NODISCARD HandleScope {
 public:
  explicit HandleScope(Isolate* isolate);

  ~HandleScope();

  /**
   * Counts the number of allocated handles.
   */
  static int NumberOfHandles(Isolate* isolate);

  V8_INLINE Isolate* GetIsolate() const {
    return reinterpret_cast<Isolate*>(i_isolate_);
  }

  HandleScope(const HandleScope&) = delete;
  void operator=(const HandleScope&) = delete;

  static internal::Address* CreateHandleForCurrentIsolate(
      internal::Address value);

 protected:
  V8_INLINE HandleScope() = default;

  void Initialize(Isolate* isolate);

  static internal::Address* CreateHandle(internal::Isolate* i_isolate,
                                         internal::Address value);

 private:
  // Declaring operator new and delete as deleted is not spec compliant.
  // Therefore declare them private instead to disable dynamic alloc
  void* operator new(size_t size);
  void* operator new[](size_t size);
  void operator delete(void*, size_t);
  void operator delete[](void*, size_t);

  internal::Isolate* i_isolate_;
  internal::Address* prev_next_;
  internal::Address* prev_limit_;
#ifdef V8_ENABLE_CHECKS
  int scope_level_ = 0;
#endif

  // LocalBase<T>::New uses CreateHandle with an Isolate* parameter.
  template <typename T>
  friend class LocalBase;

  // Object::GetInternalField and Context::GetEmbedderData use CreateHandle with
  // a HeapObject in their shortcuts.
  friend class Object;
  friend class Context;
};

/**
 * A base class for local handles.
 * Its implementation depends on whether direct handle support is enabled.
 * When it is, a local handle contains a direct pointer to the referenced
 * object, otherwise it contains an indirect pointer.
 */
#ifdef V8_ENABLE_DIRECT_HANDLE

template <typename T>
class LocalBase : public api_internal::DirectHandleBase {
 protected:
  template <class F>
  friend class Local;

  V8_INLINE LocalBase() = default;

  V8_INLINE explicit LocalBase(internal::Address ptr) : DirectHandleBase(ptr) {}

  template <typename S>
  V8_INLINE LocalBase(const LocalBase<S>& other) : DirectHandleBase(other) {}

  V8_INLINE static LocalBase<T> New(Isolate* isolate, internal::Address value) {
    return LocalBase<T>(value);
  }

  V8_INLINE static LocalBase<T> New(Isolate* isolate, T* that) {
    return LocalBase<T>::New(isolate,
                             internal::ValueHelper::ValueAsAddress(that));
  }

  V8_INLINE static LocalBase<T> FromSlot(internal::Address* slot) {
    return LocalBase<T>(*slot);
  }

  V8_INLINE static LocalBase<T> FromRepr(
      internal::ValueHelper::InternalRepresentationType repr) {
    return LocalBase<T>(repr);
  }
};

#else  // !V8_ENABLE_DIRECT_HANDLE

template <typename T>
class LocalBase : public api_internal::IndirectHandleBase {
 protected:
  template <class F>
  friend class Local;

  V8_INLINE LocalBase() = default;

  V8_INLINE explicit LocalBase(internal::Address* location)
      : IndirectHandleBase(location) {}

  template <typename S>
  V8_INLINE LocalBase(const LocalBase<S>& other) : IndirectHandleBase(other) {}

  V8_INLINE static LocalBase<T> New(Isolate* isolate, internal::Address value) {
    return LocalBase(HandleScope::CreateHandle(
        reinterpret_cast<internal::Isolate*>(isolate), value));
  }

  V8_INLINE static LocalBase<T> New(Isolate* isolate, T* that) {
    if (internal::ValueHelper::IsEmpty(that)) return LocalBase<T>();
    return LocalBase<T>::New(isolate,
                             internal::ValueHelper::ValueAsAddress(that));
  }

  V8_INLINE static LocalBase<T> FromSlot(internal::Address* slot) {
    return LocalBase<T>(slot);
  }

  V8_INLINE static LocalBase<T> FromRepr(
      internal::ValueHelper::InternalRepresentationType repr) {
    return LocalBase<T>(repr);
  }
};

#endif  // V8_ENABLE_DIRECT_HANDLE

/**
 * An object reference managed by the v8 garbage collector.
 *
 * All objects returned from v8 have to be tracked by the garbage collector so
 * that it knows that the objects are still alive.  Also, because the garbage
 * collector may move objects, it is unsafe to point directly to an object.
 * Instead, all objects are stored in handles which are known by the garbage
 * collector and updated whenever an object moves.  Handles should always be
 * passed by value (except in cases like out-parameters) and they should never
 * be allocated on the heap.
 *
 * There are two types of handles: local and persistent handles.
 *
 * Local handles are light-weight and transient and typically used in local
 * operations.  They are managed by HandleScopes. That means that a HandleScope
 * must exist on the stack when they are created and that they are only valid
 * inside of the HandleScope active during their creation. For passing a local
 * handle to an outer HandleScope, an EscapableHandleScope and its Escape()
 * method must be used.
 *
 * Persistent handles can be used when storing objects across several
 * independent operations and have to be explicitly deallocated when they're no
 * longer used.
 *
 * It is safe to extract the object stored in the handle by dereferencing the
 * handle (for instance, to extract the Object* from a Local<Object>); the value
 * will still be governed by a handle behind the scenes and the same rules apply
 * to these values as to their handles.
 */
template <class T>
class V8_TRIVIAL_ABI Local : public LocalBase<T>,
#ifdef V8_ENABLE_LOCAL_OFF_STACK_CHECK
                             public api_internal::StackAllocated<true>
#else
                             public api_internal::StackAllocated<false>
#endif
{
 public:
  V8_INLINE Local() = default;

  template <class S>
  V8_INLINE Local(Local<S> that) : LocalBase<T>(that) {
    /**
     * This check fails when trying to convert between incompatible
     * handles. For example, converting from a Local<String> to a
     * Local<Number>.
     */
    static_assert(std::is_base_of<T, S>::value, "type check");
  }

  V8_INLINE T* operator->() const { return this->template value<T>(); }

  V8_INLINE T* operator*() const { return this->operator->(); }

  /**
   * Checks whether two handles are equal or different.
   * They are equal iff they are both empty or they are both non-empty and the
   * objects to which they refer are physically equal.
   *
   * If both handles refer to JS objects, this is the same as strict
   * non-equality. For primitives, such as numbers or strings, a `true` return
   * value does not indicate that the values aren't equal in the JavaScript
   * sense. Use `Value::StrictEquals()` to check primitives for equality.
   */

  template <class S>
  V8_INLINE bool operator==(const Local<S>& that) const {
    return internal::HandleHelper::EqualHandles(*this, that);
  }

  template <class S>
  V8_INLINE bool operator==(const PersistentBase<S>& that) const {
    return internal::HandleHelper::EqualHandles(*this, that);
  }

  template <class S>
  V8_INLINE bool operator!=(const Local<S>& that) const {
    return !operator==(that);
  }

  template <class S>
  V8_INLINE bool operator!=(const Persistent<S>& that) const {
    return !operator==(that);
  }

  /**
   * Cast a handle to a subclass, e.g. Local<Value> to Local<Object>.
   * This is only valid if the handle actually refers to a value of the
   * target type.
   */
  template <class S>
  V8_INLINE static Local<T> Cast(Local<S> that) {
#ifdef V8_ENABLE_CHECKS
    // If we're going to perform the type check then we have to check
    // that the handle isn't empty before doing the checked cast.
    if (that.IsEmpty()) return Local<T>();
    T::Cast(that.template value<S>());
#endif
    return Local<T>(LocalBase<T>(that));
  }

  /**
   * Calling this is equivalent to Local<S>::Cast().
   * In particular, this is only valid if the handle actually refers to a value
   * of the target type.
   */
  template <class S>
  V8_INLINE Local<S> As() const {
    return Local<S>::Cast(*this);
  }

  /**
   * Create a local handle for the content of another handle.
   * The referee is kept alive by the local handle even when
   * the original handle is destroyed/disposed.
   */
  V8_INLINE static Local<T> New(Isolate* isolate, Local<T> that) {
    return New(isolate, that.template value<T, true>());
  }

  V8_INLINE static Local<T> New(Isolate* isolate,
                                const PersistentBase<T>& that) {
    return New(isolate, that.template value<T, true>());
  }

  V8_INLINE static Local<T> New(Isolate* isolate,
                                const BasicTracedReference<T>& that) {
    return New(isolate, that.template value<T, true>());
  }

 private:
  friend class TracedReferenceBase;
  friend class Utils;
  template <class F>
  friend class Eternal;
  template <class F>
  friend class Global;
  template <class F>
  friend class Local;
  template <class F>
  friend class MaybeLocal;
  template <class F, class M>
  friend class Persistent;
  template <class F>
  friend class FunctionCallbackInfo;
  template <class F>
  friend class PropertyCallbackInfo;
  friend class String;
  friend class Object;
  friend class Context;
  friend class Isolate;
  friend class Private;
  template <class F>
  friend class internal::CustomArguments;
  friend Local<Primitive> Undefined(Isolate* isolate);
  friend Local<Primitive> Null(Isolate* isolate);
  friend Local<Boolean> True(Isolate* isolate);
  friend Local<Boolean> False(Isolate* isolate);
  friend class HandleScope;
  friend class EscapableHandleScope;
  friend class InternalEscapableScope;
  template <class F1, class F2, class F3>
  friend class PersistentValueMapBase;
  template <class F>
  friend class ReturnValue;
  template <class F>
  friend class Traced;
  friend class internal::SamplingHeapProfiler;
  friend class internal::HandleHelper;
  friend class debug::ConsoleCallArguments;
  friend class internal::LocalUnchecked<T>;

  explicit Local(no_checking_tag do_not_check)
      : LocalBase<T>(), StackAllocated(do_not_check) {}
  explicit Local(const Local<T>& other, no_checking_tag do_not_check)
      : LocalBase<T>(other), StackAllocated(do_not_check) {}

  V8_INLINE explicit Local(const LocalBase<T>& other) : LocalBase<T>(other) {}

  V8_INLINE static Local<T> FromRepr(
      internal::ValueHelper::InternalRepresentationType repr) {
    return Local<T>(LocalBase<T>::FromRepr(repr));
  }

  V8_INLINE static Local<T> FromSlot(internal::Address* slot) {
    return Local<T>(LocalBase<T>::FromSlot(slot));
  }

#ifdef V8_ENABLE_DIRECT_HANDLE
  friend class TypecheckWitness;

  V8_INLINE static Local<T> FromAddress(internal::Address ptr) {
    return Local<T>(LocalBase<T>(ptr));
  }
#endif  // V8_ENABLE_DIRECT_HANDLE

  V8_INLINE static Local<T> New(Isolate* isolate, internal::Address value) {
    return Local<T>(LocalBase<T>::New(isolate, value));
  }

  V8_INLINE static Local<T> New(Isolate* isolate, T* that) {
    return Local<T>(LocalBase<T>::New(isolate, that));
  }

  // Unsafe cast, should be avoided.
  template <class S>
  V8_INLINE Local<S> UnsafeAs() const {
    return Local<S>(LocalBase<S>(*this));
  }
};

namespace internal {
// A local variant that is suitable for off-stack allocation.
// Used internally by LocalVector<T>. Not to be used directly!
template <typename T>
class V8_TRIVIAL_ABI LocalUnchecked : public Local<T> {
 public:
  LocalUnchecked() : Local<T>(Local<T>::do_not_check) {}

#if defined(V8_ENABLE_LOCAL_OFF_STACK_CHECK) && V8_HAS_ATTRIBUTE_TRIVIAL_ABI
  // In this case, the check is also enforced in the copy constructor and we
  // need to suppress it.
  LocalUnchecked(
      const LocalUnchecked& other) noexcept  // NOLINT(runtime/explicit)
      : Local<T>(other, Local<T>::do_not_check) {}
  LocalUnchecked& operator=(const LocalUnchecked&) noexcept = default;
#endif

  // Implicit conversion from Local.
  LocalUnchecked(const Local<T>& other) noexcept  // NOLINT(runtime/explicit)
      : Local<T>(other, Local<T>::do_not_check) {}
};

#ifdef V8_ENABLE_DIRECT_HANDLE
// Off-stack allocated direct locals must be registered as strong roots.
// For off-stack indirect locals, this is not necessary.

template <typename T>
class StrongRootAllocator<LocalUnchecked<T>> : public StrongRootAllocatorBase {
 public:
  using value_type = LocalUnchecked<T>;
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
#endif  // V8_ENABLE_DIRECT_HANDLE
}  // namespace internal

template <typename T>
class LocalVector {
 private:
  using element_type = internal::LocalUnchecked<T>;

#ifdef V8_ENABLE_DIRECT_HANDLE
  using allocator_type = internal::StrongRootAllocator<element_type>;

  static allocator_type make_allocator(Isolate* isolate) noexcept {
    return allocator_type(isolate);
  }
#else
  using allocator_type = std::allocator<element_type>;

  static allocator_type make_allocator(Isolate* isolate) noexcept {
    return allocator_type();
  }
#endif  // V8_ENABLE_DIRECT_HANDLE

  using vector_type = std::vector<element_type, allocator_type>;

 public:
  using value_type = Local<T>;
  using reference = value_type&;
  using const_reference = const value_type&;
  using size_type = size_t;
  using difference_type = ptrdiff_t;
  using iterator =
      internal::WrappedIterator<typename vector_type::iterator, Local<T>>;
  using const_iterator =
      internal::WrappedIterator<typename vector_type::const_iterator,
                                const Local<T>>;

  explicit LocalVector(Isolate* isolate) : backing_(make_allocator(isolate)) {}
  LocalVector(Isolate* isolate, size_t n)
      : backing_(n, make_allocator(isolate)) {}
  explicit LocalVector(Isolate* isolate, std::initializer_list<Local<T>> init)
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

  Local<T>& operator[](size_t n) { return backing_[n]; }
  const Local<T>& operator[](size_t n) const { return backing_[n]; }

  Local<T>& at(size_t n) { return backing_.at(n); }
  const Local<T>& at(size_t n) const { return backing_.at(n); }

  Local<T>& front() { return backing_.front(); }
  const Local<T>& front() const { return backing_.front(); }
  Local<T>& back() { return backing_.back(); }
  const Local<T>& back() const { return backing_.back(); }

  Local<T>* data() noexcept { return backing_.data(); }
  const Local<T>* data() const noexcept { return backing_.data(); }

  iterator insert(const_iterator pos, const Local<T>& value) {
    return iterator(backing_.insert(pos.base(), value));
  }

  template <typename InputIt>
  iterator insert(const_iterator pos, InputIt first, InputIt last) {
    return iterator(backing_.insert(pos.base(), first, last));
  }

  iterator insert(const_iterator pos, std::initializer_list<Local<T>> init) {
    return iterator(backing_.insert(pos.base(), init.begin(), init.end()));
  }

  LocalVector<T>& operator=(std::initializer_list<Local<T>> init) {
    backing_.clear();
    backing_.reserve(init.size());
    backing_.insert(backing_.end(), init.begin(), init.end());
    return *this;
  }

  void push_back(const Local<T>& x) { backing_.push_back(x); }
  void pop_back() { backing_.pop_back(); }

  template <typename... Args>
  void emplace_back(Args&&... args) {
    backing_.push_back(value_type{std::forward<Args>(args)...});
  }

  void clear() noexcept { backing_.clear(); }
  void resize(size_t n) { backing_.resize(n); }
  void swap(LocalVector<T>& other) { backing_.swap(other.backing_); }

  friend bool operator==(const LocalVector<T>& x, const LocalVector<T>& y) {
    return x.backing_ == y.backing_;
  }
  friend bool operator!=(const LocalVector<T>& x, const LocalVector<T>& y) {
    return x.backing_ != y.backing_;
  }
  friend bool operator<(const LocalVector<T>& x, const LocalVector<T>& y) {
    return x.backing_ < y.backing_;
  }
  friend bool operator>(const LocalVector<T>& x, const LocalVector<T>& y) {
    return x.backing_ > y.backing_;
  }
  friend bool operator<=(const LocalVector<T>& x, const LocalVector<T>& y) {
    return x.backing_ <= y.backing_;
  }
  friend bool operator>=(const LocalVector<T>& x, const LocalVector<T>& y) {
    return x.backing_ >= y.backing_;
  }

 private:
  vector_type backing_;
};

#if !defined(V8_IMMINENT_DEPRECATION_WARNINGS)
// Handle is an alias for Local for historical reasons.
template <class T>
using Handle = Local<T>;
#endif

/**
 * A MaybeLocal<> is a wrapper around Local<> that enforces a check whether
 * the Local<> is empty before it can be used.
 *
 * If an API method returns a MaybeLocal<>, the API method can potentially fail
 * either because an exception is thrown, or because an exception is pending,
 * e.g. because a previous API call threw an exception that hasn't been caught
 * yet, or because a TerminateExecution exception was thrown. In that case, an
 * empty MaybeLocal is returned.
 */
template <class T>
class MaybeLocal {
 public:
  V8_INLINE MaybeLocal() : local_() {}
  template <class S>
  V8_INLINE MaybeLocal(Local<S> that) : local_(that) {}

  V8_INLINE bool IsEmpty() const { return local_.IsEmpty(); }

  /**
   * Converts this MaybeLocal<> to a Local<>. If this MaybeLocal<> is empty,
   * |false| is returned and |out| is assigned with nullptr.
   */
  template <class S>
  V8_WARN_UNUSED_RESULT V8_INLINE bool ToLocal(Local<S>* out) const {
    *out = local_;
    return !IsEmpty();
  }

  /**
   * Converts this MaybeLocal<> to a Local<>. If this MaybeLocal<> is empty,
   * V8 will crash the process.
   */
  V8_INLINE Local<T> ToLocalChecked() {
    if (V8_UNLIKELY(IsEmpty())) api_internal::ToLocalEmpty();
    return local_;
  }

  /**
   * Converts this MaybeLocal<> to a Local<>, using a default value if this
   * MaybeLocal<> is empty.
   */
  template <class S>
  V8_INLINE Local<S> FromMaybe(Local<S> default_value) const {
    return IsEmpty() ? default_value : Local<S>(local_);
  }

  /**
   * Cast a handle to a subclass, e.g. MaybeLocal<Value> to MaybeLocal<Object>.
   * This is only valid if the handle actually refers to a value of the target
   * type.
   */
  template <class S>
  V8_INLINE static MaybeLocal<T> Cast(MaybeLocal<S> that) {
#ifdef V8_ENABLE_CHECKS
    // If we're going to perform the type check then we have to check
    // that the handle isn't empty before doing the checked cast.
    if (that.IsEmpty()) return MaybeLocal<T>();
    T::Cast(that.local_.template value<S>());
#endif
    return MaybeLocal<T>(that.local_);
  }

  /**
   * Calling this is equivalent to MaybeLocal<S>::Cast().
   * In particular, this is only valid if the handle actually refers to a value
   * of the target type.
   */
  template <class S>
  V8_INLINE MaybeLocal<S> As() const {
    return MaybeLocal<S>::Cast(*this);
  }

 private:
  Local<T> local_;

  template <typename S>
  friend class MaybeLocal;
};

/**
 * A HandleScope which first allocates a handle in the current scope
 * which will be later filled with the escape value.
 */
class V8_EXPORT V8_NODISCARD EscapableHandleScopeBase : public HandleScope {
 public:
  explicit EscapableHandleScopeBase(Isolate* isolate);
  V8_INLINE ~EscapableHandleScopeBase() = default;

  EscapableHandleScopeBase(const EscapableHandleScopeBase&) = delete;
  void operator=(const EscapableHandleScopeBase&) = delete;
  void* operator new(size_t size) = delete;
  void* operator new[](size_t size) = delete;
  void operator delete(void*, size_t) = delete;
  void operator delete[](void*, size_t) = delete;

 protected:
  /**
   * Pushes the value into the previous scope and returns a handle to it.
   * Cannot be called twice.
   */
  internal::Address* EscapeSlot(internal::Address* escape_value);

 private:
  internal::Address* escape_slot_;
};

class V8_EXPORT V8_NODISCARD EscapableHandleScope
    : public EscapableHandleScopeBase {
 public:
  explicit EscapableHandleScope(Isolate* isolate)
      : EscapableHandleScopeBase(isolate) {}
  V8_INLINE ~EscapableHandleScope() = default;
  template <class T>
  V8_INLINE Local<T> Escape(Local<T> value) {
#ifdef V8_ENABLE_DIRECT_HANDLE
    return value;
#else
    if (value.IsEmpty()) return value;
    return Local<T>::FromSlot(EscapeSlot(value.slot()));
#endif
  }

  template <class T>
  V8_INLINE MaybeLocal<T> EscapeMaybe(MaybeLocal<T> value) {
    return Escape(value.FromMaybe(Local<T>()));
  }
};

/**
 * A SealHandleScope acts like a handle scope in which no handle allocations
 * are allowed. It can be useful for debugging handle leaks.
 * Handles can be allocated within inner normal HandleScopes.
 */
class V8_EXPORT V8_NODISCARD SealHandleScope {
 public:
  explicit SealHandleScope(Isolate* isolate);
  ~SealHandleScope();

  SealHandleScope(const SealHandleScope&) = delete;
  void operator=(const SealHandleScope&) = delete;
  void* operator new(size_t size) = delete;
  void* operator new[](size_t size) = delete;
  void operator delete(void*, size_t) = delete;
  void operator delete[](void*, size_t) = delete;

 private:
  internal::Isolate* const i_isolate_;
  internal::Address* prev_limit_;
  int prev_sealed_level_;
};

}  // namespace v8

#endif  // INCLUDE_V8_LOCAL_HANDLE_H_

"""

```