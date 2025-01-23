Response:
Let's break down the thought process for analyzing this C++ header file for V8.

1. **Initial Scan for Obvious Clues:**  The first thing I do is quickly scan the file for comments and keywords. I see "Copyright 2021 the V8 project authors," "Persistent," "Handle," "WeakCallback," "Global," "Local." These words immediately tell me this file is about memory management within the V8 JavaScript engine, specifically concerning object lifetimes.

2. **Filename and Extension Check:** The prompt asks specifically about the filename. It's `v8-persistent-handle.h`. The `.h` extension clearly indicates a C++ header file. The prompt also mentions a hypothetical `.tq` extension, indicating a Torque file. Since it's `.h`, it's standard C++.

3. **Purpose of the Header:** Based on the keywords, the file likely defines classes and functions for managing object references that persist beyond the scope of a `Local` handle. `Persistent` and `Global` strongly suggest this. The "WeakCallback" hints at mechanisms for managing resources associated with these persistent handles when the referenced objects are no longer actively used.

4. **Core Classes Identification:** I start identifying the main classes: `Eternal`, `PersistentBase`, `Persistent`, and `Global`.

5. **`Eternal` Class Analysis:**
    * "Eternal handles are set-once handles that live for the lifetime of the isolate." This is the key piece of information.
    * It has `Set` and `Get` methods. `Set` takes a `Local` and makes it eternal. `Get` retrieves the eternal handle as a `Local`.
    * The comment about not needing to open a handle in `Get` is an internal optimization detail.

6. **`PersistentBase` Class Analysis:**
    * "An object reference that is independent of any handle scope." This confirms the earlier hypothesis.
    * `Reset()`: Explicitly disposes of the handle.
    * `Get()`: Retrieves the persistent handle as a `Local`.
    * Overloaded `==` and `!=`:  Comparison operators.
    * `SetWeak()`:  Crucial for garbage collection. Allows associating a callback when the object is about to be collected. The warning about no guarantees is important.
    * `ClearWeak()`:  Removes the weak callback.
    * `AnnotateStrongRetainer()`:  For debugging and heap snapshots.
    * `IsWeak()`:  Checks if the handle is weak.
    * `SetWrapperClassId()` and `WrapperClassId()`:  Metadata associated with the handle.

7. **`Persistent` Class Analysis:**
    * Inherits from `PersistentBase`.
    * Introduces the concept of "traits" (`NonCopyablePersistentTraits`).
    * The comments about copy constructors, assignment operators, and the destructor are important for understanding its behavior and potential pitfalls (memory leaks). The suggestion to use `Global` is significant.

8. **`Global` Class Analysis:**
    * Also inherits from `PersistentBase`.
    * Emphasizes move semantics (move constructor, move assignment).
    * The destructor calls `Reset()`, ensuring cleanup.
    * The "Pass()" method is for returning the `Global` by value.
    * Explicitly deletes the copy constructor and assignment operator, enforcing move-only semantics.

9. **`PersistentHandleVisitor`:** An interface for iterating over persistent handles. Useful for tools and debugging.

10. **Internal Details and Helper Functions:**  The `api_internal` namespace contains low-level functions for manipulating the underlying storage of the handles. Functions like `Eternalize`, `CopyGlobalReference`, `DisposeGlobal`, `MakeWeak`, `ClearWeak`, etc., are crucial but generally not used directly by V8 embedders.

11. **Relationship to JavaScript:**  Persistent handles are fundamental to how V8 manages JavaScript objects in the C++ layer. When a JavaScript object needs to be accessed or kept alive beyond the scope of a function call, persistent handles are used.

12. **JavaScript Examples (Mental Model):** I start thinking about scenarios in JavaScript that would require persistent handles in the underlying C++:
    * **Global variables:**  These need to persist for the lifetime of the script.
    * **Objects passed to native (C++) functions:** V8 needs a way to refer to these objects reliably.
    * **Callbacks:** When a native function needs to call back into JavaScript later, it needs a persistent reference to the JavaScript function.

13. **Common Programming Errors:** I consider common mistakes related to manual memory management in C++, which are relevant to persistent handles:
    * **Forgetting to `Reset()`:** This leads to memory leaks.
    * **Using a `Local` handle after its `HandleScope` has been destroyed:** This leads to crashes.
    * **Misunderstanding weak handles:** Not realizing that the object can be collected even if there's a weak handle to it.
    * **Calling V8 API functions within weak callbacks without proper setup:** This is explicitly warned against in the comments.

14. **Code Logic Inference:** The `Reset()` methods, the constructors, and the `Copy` method (for `Persistent`) involve managing the underlying storage. The `SetWeak` and `ClearWeak` methods clearly manipulate the weak reference status. The `Global` class's move semantics are standard C++ features.

15. **Structure the Answer:** Finally, I organize the information into logical sections as requested by the prompt: functionalities, Torque check, JavaScript relation with examples, code logic, and common errors. I try to use clear and concise language.
## 功能列举

`v8/include/v8-persistent-handle.h` 文件定义了 V8 JavaScript 引擎中用于管理对象生命周期的持久句柄（Persistent Handles）相关的类和接口。与局部句柄（Local Handles）不同，持久句柄的生命周期独立于任何作用域，可以跨越多个 JavaScript 执行阶段。

其主要功能包括：

1. **定义持久句柄基类 `PersistentBase<T>`:**
   - 提供了创建、销毁和管理底层存储单元的功能。
   - 允许将局部句柄转换为持久句柄。
   - 提供了获取持久句柄所指向对象的局部句柄的方法 (`Get()`)。
   - 支持比较操作 (`==`, `!=`)。
   - 提供了设置和清除弱回调 (weak callback) 的机制，用于在对象即将被垃圾回收时得到通知。
   - 支持将持久句柄标记为弱引用 (weak reference)。
   - 允许为持久句柄关联一个包装类 ID。
   - 提供了在堆快照中标记强引用持有者 (`AnnotateStrongRetainer`) 的功能。

2. **定义可复制的持久句柄类 `Persistent<T, M>`:**
   - 继承自 `PersistentBase<T>`。
   - 允许通过复制构造函数和赋值运算符创建新的持久句柄。
   - 其复制、赋值和析构行为由模板参数 `M` (traits 类) 控制。

3. **定义具有移动语义的全局句柄类 `Global<T>` (以及别名 `UniquePersistent<T>`)：**
   - 继承自 `PersistentBase<T>`。
   - 提供了移动构造函数和移动赋值运算符，避免不必要的拷贝。
   - 其析构函数会自动释放底层存储单元。
   - 适用于需要明确管理对象生命周期且希望避免拷贝的场景。

4. **定义一次性设置的永恒句柄类 `Eternal<T>`:**
   - 用于存储在 Isolate 生命周期内都存在的对象。
   - 只能被设置一次。
   - 获取时无需打开 HandleScope，性能更高。

5. **定义了与持久句柄相关的内部辅助函数 (`namespace api_internal`)：**
   - 用于底层操作，如创建、销毁、设置弱引用等。
   - 例如 `Eternalize`, `CopyGlobalReference`, `DisposeGlobal`, `MakeWeak`, `ClearWeak` 等。

6. **定义了用于遍历堆中所有持久句柄的接口 `PersistentHandleVisitor`。**

## Torque 源代码判断

如果 `v8/include/v8-persistent-handle.h` 以 `.tq` 结尾，那么它将是 V8 的 Torque 源代码。当前来看，它以 `.h` 结尾，所以是 C++ 头文件。Torque 是一种用于定义 V8 内部运行时函数的类型化中间语言。

## 与 JavaScript 的关系及 JavaScript 示例

持久句柄在 V8 内部用于管理 JavaScript 对象的生命周期，并允许 C++ 代码持有对 JavaScript 对象的引用，即使在 JavaScript 执行上下文结束之后。这在以下场景中至关重要：

- **嵌入 V8 的应用程序需要与 JavaScript 对象交互:** C++ 代码需要持久地持有对 JavaScript 对象的引用，以便稍后调用其方法或访问其属性。
- **实现 Native 模块:** Native 模块可能需要在 JavaScript 执行期间创建的对象在 Native 代码中保持有效，即使在创建这些对象的 JavaScript 函数返回之后。
- **实现 Finalization 机制:** 通过弱回调，C++ 代码可以在 JavaScript 对象即将被垃圾回收时得到通知，并执行清理操作。

**JavaScript 示例：**

假设我们有一个 C++ 函数，它接收一个 JavaScript 对象作为参数，并需要在后续的某个时刻调用该对象的方法。

```javascript
// JavaScript 代码

const myObject = {
  message: "Hello from JavaScript!",
  sayHello: function() {
    console.log(this.message);
  }
};

// 假设有一个名为 callObjectMethodLater 的 C++ 函数，
// 它接收一个 JavaScript 对象并存储它以供后续使用。
callObjectMethodLater(myObject);

// ... 一段时间后，C++ 代码可能会调用 myObject 的 sayHello 方法。
```

在 C++ 的 `callObjectMethodLater` 函数内部，就需要使用持久句柄来存储 `myObject` 的引用，因为 `myObject` 是在 JavaScript 的上下文中创建的，局部句柄的生命周期有限。

```c++
// C++ 代码 (简化示例)
#include "v8.h"

v8::Global<v8::Object> persistentObject; // 使用 Global 持有 JavaScript 对象

void callObjectMethodLater(const v8::Local<v8::Object>& object) {
  v8::Isolate* isolate = object->GetIsolate();
  persistentObject.Reset(isolate, object); // 将 Local 转换为 Global
}

void someTimeLater() {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Context> context = isolate->GetCurrentContext();

  if (!persistentObject.IsEmpty()) {
    v8::Local<v8::Object> obj = persistentObject.Get(isolate);
    v8::Local<v8::String> functionName =
        v8::String::NewFromUtf8Literal(isolate, "sayHello");
    v8::Local<v8::Value> functionValue;
    if (obj->Get(context, functionName).ToLocal(&functionValue) &&
        functionValue->IsFunction()) {
      v8::Local<v8::Function> function = functionValue.As<v8::Function>();
      v8::Local<v8::Value> receiver = obj; // 'this' 上下文
      v8::Local<v8::Value> args[0];
      function->Call(context, receiver, 0, args);
    }
  }
}
```

在这个例子中，`persistentObject` 就是一个 `v8::Global<v8::Object>` 类型的持久句柄，它允许 C++ 代码在 `callObjectMethodLater` 函数返回后仍然持有对 JavaScript 对象的引用。

## 代码逻辑推理

**假设输入：**

1. 在 JavaScript 中创建了一个对象 `myObj`.
2. 将 `myObj` 传递给一个 C++ 函数 `StoreObject(Local<Object> obj)`.
3. C++ 函数 `StoreObject` 将 `obj` 存储在一个 `Global<Object>` 类型的成员变量 `storedObj`.

**代码逻辑：**

在 `StoreObject` 函数中，会调用 `storedObj.Reset(isolate, obj);`。

-   如果 `storedObj` 之前为空，则会创建一个新的存储单元，并将 `obj` 的内容复制到该存储单元中。
-   如果 `storedObj` 之前已经持有一个对象，则会先销毁旧的存储单元，然后创建一个新的存储单元并复制 `obj` 的内容。

**输出：**

-   `storedObj` 将持有一个指向 `myObj` 的持久引用。
-   即使 `StoreObject` 函数返回，`myObj` 不会被垃圾回收，因为 `storedObj` 持有一个强引用。

**假设输入（弱引用）：**

1. 在 JavaScript 中创建了一个对象 `weakObj`.
2. 将 `weakObj` 传递给一个 C++ 函数 `SetWeakObject(Local<Object> obj)`.
3. C++ 函数 `SetWeakObject` 创建一个 `Global<Object>` 类型的成员变量 `weakStoredObj` 并存储 `obj`，然后调用 `weakStoredObj.SetWeak(...)` 设置一个弱回调。

**代码逻辑：**

在 `SetWeakObject` 函数中，会调用 `weakStoredObj.Reset(isolate, obj);`，然后调用 `weakStoredObj.SetWeak(...)`，传递一个回调函数和一个用户数据指针。

**输出：**

-   `weakStoredObj` 持有一个指向 `weakObj` 的弱引用。
-   当 V8 的垃圾回收器检测到 `weakObj` 不再被强引用时，即使 `weakStoredObj` 仍然存在，`weakObj` 仍然可能被回收。
-   在 `weakObj` 被回收之前（或在回收期间），设置的弱回调函数会被调用，用户数据指针也会被传递给回调函数。回调函数通常会调用 `weakStoredObj.Reset()` 来释放资源。

## 用户常见的编程错误

1. **忘记 `Reset()` 持久句柄导致内存泄漏:**
    ```c++
    void createPersistentLeak(v8::Isolate* isolate) {
      v8::Persistent<v8::Object> leak;
      {
        v8::HandleScope handle_scope(isolate);
        v8::Local<v8::Object> obj = v8::Object::New(isolate);
        leak.Reset(isolate, obj);
        // ... 在这里 leak 被创建并指向一个对象，但是函数结束时没有调用 Reset()
      }
      // leak 仍然持有对象，但已经无法访问和释放，导致内存泄漏。
    }
    ```

2. **在弱回调中调用 V8 API 而没有正确的上下文:**
    ```c++
    void weakCallback(const v8::WeakCallbackInfo<void>& data) {
      // 错误的做法：直接调用 V8 API 而没有 HandleScope 或 Context
      // v8::String::NewFromUtf8Literal(v8::Isolate::GetCurrent(), "Error"); // 可能会崩溃

      // 正确的做法：如果需要调用 V8 API，需要确保在 V8 线程中，并有有效的 Isolate、HandleScope 和 Context。
    }

    void setWeakHandle(v8::Isolate* isolate, v8::Local<v8::Object> obj) {
      v8::Global<v8::Object> weakHandle;
      weakHandle.Reset(isolate, obj);
      weakHandle.SetWeak(nullptr, weakCallback, v8::WeakCallbackType::kParameter);
    }
    ```

3. **在 `Local` 句柄的作用域之外使用它:** 持久句柄正是为了解决这个问题而存在的。尝试在 `HandleScope` 结束后使用 `Local` 句柄会导致崩溃。

4. **混淆 `Local` 和 `Persistent`/`Global` 的生命周期:**  不理解 `Local` 句柄的临时性，错误地认为 `Local` 句柄可以像持久句柄一样使用。

5. **在析构函数中忘记 `Reset()` 可复制的 `Persistent` 句柄 (如果 traits 没有设置 `kResetInDestructor`):**  虽然现在 `NonCopyablePersistentTraits` 的 `kResetInDestructor` 是 `false`，但如果自定义 traits 没有正确设置，可能会导致内存泄漏。通常建议使用 `Global`，因为它默认在析构函数中 `Reset()`。

理解和正确使用持久句柄对于 V8 嵌入式开发和 Native 模块的编写至关重要，可以有效地管理 JavaScript 对象的生命周期，并实现 C++ 和 JavaScript 之间的安全交互。

### 提示词
```
这是目录为v8/include/v8-persistent-handle.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-persistent-handle.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_PERSISTENT_HANDLE_H_
#define INCLUDE_V8_PERSISTENT_HANDLE_H_

#include "v8-internal.h"            // NOLINT(build/include_directory)
#include "v8-local-handle.h"        // NOLINT(build/include_directory)
#include "v8-weak-callback-info.h"  // NOLINT(build/include_directory)
#include "v8config.h"               // NOLINT(build/include_directory)

namespace v8 {

class Isolate;
template <class K, class V, class T>
class PersistentValueMapBase;
template <class T>
class Global;
template <class T>
class PersistentBase;
template <class K, class V, class T>
class PersistentValueMap;
class Value;

namespace api_internal {
V8_EXPORT internal::Address* Eternalize(v8::Isolate* isolate, Value* handle);
V8_EXPORT internal::Address* CopyGlobalReference(internal::Address* from);
V8_EXPORT void DisposeGlobal(internal::Address* global_handle);
V8_EXPORT void MakeWeak(internal::Address** location_addr);
V8_EXPORT void* ClearWeak(internal::Address* location);
V8_EXPORT void AnnotateStrongRetainer(internal::Address* location,
                                      const char* label);
V8_EXPORT internal::Address* GlobalizeReference(internal::Isolate* isolate,
                                                internal::Address value);
V8_EXPORT void MoveGlobalReference(internal::Address** from,
                                   internal::Address** to);
}  // namespace api_internal

/**
 * Eternal handles are set-once handles that live for the lifetime of the
 * isolate.
 */
template <class T>
class Eternal : public api_internal::IndirectHandleBase {
 public:
  V8_INLINE Eternal() = default;

  template <class S>
  V8_INLINE Eternal(Isolate* isolate, Local<S> handle) {
    Set(isolate, handle);
  }

  // Can only be safely called if already set.
  V8_INLINE Local<T> Get(Isolate* isolate) const {
    // The eternal handle will never go away, so as with the roots, we don't
    // even need to open a handle.
    return Local<T>::FromSlot(slot());
  }

  template <class S>
  void Set(Isolate* isolate, Local<S> handle) {
    static_assert(std::is_base_of<T, S>::value, "type check");
    slot() =
        api_internal::Eternalize(isolate, *handle.template UnsafeAs<Value>());
  }
};

namespace api_internal {
V8_EXPORT void MakeWeak(internal::Address* location, void* data,
                        WeakCallbackInfo<void>::Callback weak_callback,
                        WeakCallbackType type);
}  // namespace api_internal

/**
 * An object reference that is independent of any handle scope.  Where
 * a Local handle only lives as long as the HandleScope in which it was
 * allocated, a PersistentBase handle remains valid until it is explicitly
 * disposed using Reset().
 *
 * A persistent handle contains a reference to a storage cell within
 * the V8 engine which holds an object value and which is updated by
 * the garbage collector whenever the object is moved.  A new storage
 * cell can be created using the constructor or PersistentBase::Reset and
 * existing handles can be disposed using PersistentBase::Reset.
 *
 */
template <class T>
class PersistentBase : public api_internal::IndirectHandleBase {
 public:
  /**
   * If non-empty, destroy the underlying storage cell
   * IsEmpty() will return true after this call.
   */
  V8_INLINE void Reset();

  /**
   * If non-empty, destroy the underlying storage cell
   * and create a new one with the contents of other if other is non empty
   */
  template <class S>
  V8_INLINE void Reset(Isolate* isolate, const Local<S>& other);

  /**
   * If non-empty, destroy the underlying storage cell
   * and create a new one with the contents of other if other is non empty
   */
  template <class S>
  V8_INLINE void Reset(Isolate* isolate, const PersistentBase<S>& other);

  V8_INLINE Local<T> Get(Isolate* isolate) const {
    return Local<T>::New(isolate, *this);
  }

  template <class S>
  V8_INLINE bool operator==(const PersistentBase<S>& that) const {
    return internal::HandleHelper::EqualHandles(*this, that);
  }

  template <class S>
  V8_INLINE bool operator==(const Local<S>& that) const {
    return internal::HandleHelper::EqualHandles(*this, that);
  }

  template <class S>
  V8_INLINE bool operator!=(const PersistentBase<S>& that) const {
    return !operator==(that);
  }

  template <class S>
  V8_INLINE bool operator!=(const Local<S>& that) const {
    return !operator==(that);
  }

  /**
   * Install a finalization callback on this object.
   * NOTE: There is no guarantee as to *when* or even *if* the callback is
   * invoked. The invocation is performed solely on a best effort basis.
   * As always, GC-based finalization should *not* be relied upon for any
   * critical form of resource management!
   *
   * The callback is supposed to reset the handle. No further V8 API may be
   * called in this callback. In case additional work involving V8 needs to be
   * done, a second callback can be scheduled using
   * WeakCallbackInfo<void>::SetSecondPassCallback.
   */
  template <typename P>
  V8_INLINE void SetWeak(P* parameter,
                         typename WeakCallbackInfo<P>::Callback callback,
                         WeakCallbackType type);

  /**
   * Turns this handle into a weak phantom handle without finalization callback.
   * The handle will be reset automatically when the garbage collector detects
   * that the object is no longer reachable.
   */
  V8_INLINE void SetWeak();

  template <typename P>
  V8_INLINE P* ClearWeak();

  // TODO(dcarney): remove this.
  V8_INLINE void ClearWeak() { ClearWeak<void>(); }

  /**
   * Annotates the strong handle with the given label, which is then used by the
   * heap snapshot generator as a name of the edge from the root to the handle.
   * The function does not take ownership of the label and assumes that the
   * label is valid as long as the handle is valid.
   */
  V8_INLINE void AnnotateStrongRetainer(const char* label);

  /** Returns true if the handle's reference is weak.  */
  V8_INLINE bool IsWeak() const;

  /**
   * Assigns a wrapper class ID to the handle.
   */
  V8_INLINE void SetWrapperClassId(uint16_t class_id);

  /**
   * Returns the class ID previously assigned to this handle or 0 if no class ID
   * was previously assigned.
   */
  V8_INLINE uint16_t WrapperClassId() const;

  PersistentBase(const PersistentBase& other) = delete;
  void operator=(const PersistentBase&) = delete;

 private:
  friend class Isolate;
  friend class Utils;
  template <class F>
  friend class Local;
  template <class F1, class F2>
  friend class Persistent;
  template <class F>
  friend class Global;
  template <class F>
  friend class PersistentBase;
  template <class F>
  friend class ReturnValue;
  template <class F1, class F2, class F3>
  friend class PersistentValueMapBase;
  friend class Object;
  friend class internal::ValueHelper;

  V8_INLINE PersistentBase() = default;

  V8_INLINE explicit PersistentBase(internal::Address* location)
      : IndirectHandleBase(location) {}

  V8_INLINE static internal::Address* New(Isolate* isolate, T* that);
};

/**
 * Default traits for Persistent. This class does not allow
 * use of the copy constructor or assignment operator.
 * At present kResetInDestructor is not set, but that will change in a future
 * version.
 */
template <class T>
class NonCopyablePersistentTraits {
 public:
  using NonCopyablePersistent = Persistent<T, NonCopyablePersistentTraits<T>>;
  static const bool kResetInDestructor = false;
  template <class S, class M>
  V8_INLINE static void Copy(const Persistent<S, M>& source,
                             NonCopyablePersistent* dest) {
    static_assert(sizeof(S) < 0,
                  "NonCopyablePersistentTraits::Copy is not instantiable");
  }
};

/**
 * A PersistentBase which allows copy and assignment.
 *
 * Copy, assignment and destructor behavior is controlled by the traits
 * class M.
 *
 * CAVEAT: Persistent objects do not have proper destruction behavior by default
 * and as such will leak the object without explicit clear. Consider using
 * `v8::Global` instead which has proper destruction and move semantics.
 */
template <class T, class M>
class Persistent : public PersistentBase<T> {
 public:
  /**
   * A Persistent with no storage cell.
   */
  V8_INLINE Persistent() = default;

  /**
   * Construct a Persistent from a Local.
   * When the Local is non-empty, a new storage cell is created
   * pointing to the same object, and no flags are set.
   */
  template <class S>
  V8_INLINE Persistent(Isolate* isolate, Local<S> that)
      : PersistentBase<T>(
            PersistentBase<T>::New(isolate, that.template value<S>())) {
    static_assert(std::is_base_of<T, S>::value, "type check");
  }

  /**
   * Construct a Persistent from a Persistent.
   * When the Persistent is non-empty, a new storage cell is created
   * pointing to the same object, and no flags are set.
   */
  template <class S, class M2>
  V8_INLINE Persistent(Isolate* isolate, const Persistent<S, M2>& that)
      : PersistentBase<T>(
            PersistentBase<T>::New(isolate, that.template value<S>())) {
    static_assert(std::is_base_of<T, S>::value, "type check");
  }

  /**
   * The copy constructors and assignment operator create a Persistent
   * exactly as the Persistent constructor, but the Copy function from the
   * traits class is called, allowing the setting of flags based on the
   * copied Persistent.
   */
  V8_INLINE Persistent(const Persistent& that) : PersistentBase<T>() {
    Copy(that);
  }
  template <class S, class M2>
  V8_INLINE Persistent(const Persistent<S, M2>& that) : PersistentBase<T>() {
    Copy(that);
  }
  V8_INLINE Persistent& operator=(const Persistent& that) {
    Copy(that);
    return *this;
  }
  template <class S, class M2>
  V8_INLINE Persistent& operator=(const Persistent<S, M2>& that) {
    Copy(that);
    return *this;
  }

  /**
   * The destructor will dispose the Persistent based on the
   * kResetInDestructor flags in the traits class.  Since not calling dispose
   * can result in a memory leak, it is recommended to always set this flag.
   */
  V8_INLINE ~Persistent() {
    if (M::kResetInDestructor) this->Reset();
  }

  // TODO(dcarney): this is pretty useless, fix or remove
  template <class S, class M2>
  V8_INLINE static Persistent<T, M>& Cast(const Persistent<S, M2>& that) {
#ifdef V8_ENABLE_CHECKS
    // If we're going to perform the type check then we have to check
    // that the handle isn't empty before doing the checked cast.
    if (!that.IsEmpty()) T::Cast(that.template value<S>());
#endif
    return reinterpret_cast<Persistent<T, M>&>(
        const_cast<Persistent<S, M2>&>(that));
  }

  // TODO(dcarney): this is pretty useless, fix or remove
  template <class S, class M2>
  V8_INLINE Persistent<S, M2>& As() const {
    return Persistent<S, M2>::Cast(*this);
  }

 private:
  friend class Isolate;
  friend class Utils;
  template <class F>
  friend class Local;
  template <class F1, class F2>
  friend class Persistent;
  template <class F>
  friend class ReturnValue;

  template <class S, class M2>
  V8_INLINE void Copy(const Persistent<S, M2>& that);
};

/**
 * A PersistentBase which has move semantics.
 *
 * Note: Persistent class hierarchy is subject to future changes.
 */
template <class T>
class Global : public PersistentBase<T> {
 public:
  /**
   * A Global with no storage cell.
   */
  V8_INLINE Global() = default;

  /**
   * Construct a Global from a Local.
   * When the Local is non-empty, a new storage cell is created
   * pointing to the same object, and no flags are set.
   */
  template <class S>
  V8_INLINE Global(Isolate* isolate, Local<S> that)
      : PersistentBase<T>(
            PersistentBase<T>::New(isolate, that.template value<S>())) {
    static_assert(std::is_base_of<T, S>::value, "type check");
  }

  /**
   * Construct a Global from a PersistentBase.
   * When the Persistent is non-empty, a new storage cell is created
   * pointing to the same object, and no flags are set.
   */
  template <class S>
  V8_INLINE Global(Isolate* isolate, const PersistentBase<S>& that)
      : PersistentBase<T>(
            PersistentBase<T>::New(isolate, that.template value<S>())) {
    static_assert(std::is_base_of<T, S>::value, "type check");
  }

  /**
   * Move constructor.
   */
  V8_INLINE Global(Global&& other);

  V8_INLINE ~Global() { this->Reset(); }

  /**
   * Move via assignment.
   */
  template <class S>
  V8_INLINE Global& operator=(Global<S>&& rhs);

  /**
   * Pass allows returning uniques from functions, etc.
   */
  Global Pass() { return static_cast<Global&&>(*this); }

  /*
   * For compatibility with Chromium's base::Bind (base::Passed).
   */
  using MoveOnlyTypeForCPP03 = void;

  Global(const Global&) = delete;
  void operator=(const Global&) = delete;

 private:
  template <class F>
  friend class ReturnValue;
};

// UniquePersistent is an alias for Global for historical reason.
template <class T>
using UniquePersistent = Global<T>;

/**
 * Interface for iterating through all the persistent handles in the heap.
 */
class V8_EXPORT PersistentHandleVisitor {
 public:
  virtual ~PersistentHandleVisitor() = default;
  virtual void VisitPersistentHandle(Persistent<Value>* value,
                                     uint16_t class_id) {}
};

template <class T>
internal::Address* PersistentBase<T>::New(Isolate* isolate, T* that) {
  if (internal::ValueHelper::IsEmpty(that)) return nullptr;
  return api_internal::GlobalizeReference(
      reinterpret_cast<internal::Isolate*>(isolate),
      internal::ValueHelper::ValueAsAddress(that));
}

template <class T, class M>
template <class S, class M2>
void Persistent<T, M>::Copy(const Persistent<S, M2>& that) {
  static_assert(std::is_base_of<T, S>::value, "type check");
  this->Reset();
  if (that.IsEmpty()) return;
  this->slot() = api_internal::CopyGlobalReference(that.slot());
  M::Copy(that, this);
}

template <class T>
bool PersistentBase<T>::IsWeak() const {
  using I = internal::Internals;
  if (this->IsEmpty()) return false;
  return I::GetNodeState(this->slot()) == I::kNodeStateIsWeakValue;
}

template <class T>
void PersistentBase<T>::Reset() {
  if (this->IsEmpty()) return;
  api_internal::DisposeGlobal(this->slot());
  this->Clear();
}

/**
 * If non-empty, destroy the underlying storage cell
 * and create a new one with the contents of other if other is non empty
 */
template <class T>
template <class S>
void PersistentBase<T>::Reset(Isolate* isolate, const Local<S>& other) {
  static_assert(std::is_base_of<T, S>::value, "type check");
  Reset();
  if (other.IsEmpty()) return;
  this->slot() = New(isolate, *other);
}

/**
 * If non-empty, destroy the underlying storage cell
 * and create a new one with the contents of other if other is non empty
 */
template <class T>
template <class S>
void PersistentBase<T>::Reset(Isolate* isolate,
                              const PersistentBase<S>& other) {
  static_assert(std::is_base_of<T, S>::value, "type check");
  Reset();
  if (other.IsEmpty()) return;
  this->slot() = New(isolate, other.template value<S>());
}

template <class T>
template <typename P>
V8_INLINE void PersistentBase<T>::SetWeak(
    P* parameter, typename WeakCallbackInfo<P>::Callback callback,
    WeakCallbackType type) {
  using Callback = WeakCallbackInfo<void>::Callback;
#if (__GNUC__ >= 8) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
  api_internal::MakeWeak(this->slot(), parameter,
                         reinterpret_cast<Callback>(callback), type);
#if (__GNUC__ >= 8) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
}

template <class T>
void PersistentBase<T>::SetWeak() {
  api_internal::MakeWeak(&this->slot());
}

template <class T>
template <typename P>
P* PersistentBase<T>::ClearWeak() {
  return reinterpret_cast<P*>(api_internal::ClearWeak(this->slot()));
}

template <class T>
void PersistentBase<T>::AnnotateStrongRetainer(const char* label) {
  api_internal::AnnotateStrongRetainer(this->slot(), label);
}

template <class T>
void PersistentBase<T>::SetWrapperClassId(uint16_t class_id) {
  using I = internal::Internals;
  if (this->IsEmpty()) return;
  uint8_t* addr = reinterpret_cast<uint8_t*>(slot()) + I::kNodeClassIdOffset;
  *reinterpret_cast<uint16_t*>(addr) = class_id;
}

template <class T>
uint16_t PersistentBase<T>::WrapperClassId() const {
  using I = internal::Internals;
  if (this->IsEmpty()) return 0;
  uint8_t* addr = reinterpret_cast<uint8_t*>(slot()) + I::kNodeClassIdOffset;
  return *reinterpret_cast<uint16_t*>(addr);
}

template <class T>
Global<T>::Global(Global&& other) : PersistentBase<T>(other.slot()) {
  if (!other.IsEmpty()) {
    api_internal::MoveGlobalReference(&other.slot(), &this->slot());
    other.Clear();
  }
}

template <class T>
template <class S>
Global<T>& Global<T>::operator=(Global<S>&& rhs) {
  static_assert(std::is_base_of<T, S>::value, "type check");
  if (this != &rhs) {
    this->Reset();
    if (!rhs.IsEmpty()) {
      this->slot() = rhs.slot();
      api_internal::MoveGlobalReference(&rhs.slot(), &this->slot());
      rhs.Clear();
    }
  }
  return *this;
}

}  // namespace v8

#endif  // INCLUDE_V8_PERSISTENT_HANDLE_H_
```