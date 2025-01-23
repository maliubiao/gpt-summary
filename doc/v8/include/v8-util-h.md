Response:
Let's break down the thought process for analyzing this C++ header file (`v8-util.h`).

1. **Initial Scan and Keywords:**  First, I'd quickly scan the file looking for familiar C++ constructs and keywords related to V8 or memory management. I'd spot: `#ifndef`, `#define`, `namespace v8`, `template`, `class`, `typedef`, `enum`, `static`, `Persistent`, `Global`, `Local`, `Isolate`, `WeakCallback`, `map`, `vector`. These give a high-level idea that the file deals with utility classes, likely related to managing V8 objects, potentially in a way that interacts with garbage collection.

2. **Preamble Analysis:**  The initial comments are crucial. They clearly state the purpose: "Support for Persistent containers."  The comment about C++11 and pre-C++11 differences is a big clue. It suggests the classes are designed to help embedders manage V8 `Global` handles (which represent persistent JavaScript objects) in scenarios where standard C++ containers might have issues due to move semantics (before C++11).

3. **`PersistentContainerValue` and `kPersistentContainerNotFound`:** These immediately stand out. `uintptr_t` suggests they are dealing with memory addresses or some form of identifier. `kPersistentContainerNotFound` strongly implies a way to represent the absence of a value in the container. This points to a custom implementation of a map-like structure.

4. **`PersistentContainerCallbackType`:** The `enum` hints at different ways these persistent containers can interact with V8's garbage collection through weak callbacks. The mention of `v8::WeakCallbackType` confirms this connection.

5. **Template Structure -  Traits Pattern:** The heavy use of templates and the `Traits` suffix on class names (`StdMapTraits`, `DefaultPersistentValueMapTraits`, `DefaultGlobalMapTraits`) signals the use of the *traits pattern*. This is a key design decision. The traits classes encapsulate specific behaviors (like the underlying storage mechanism, weak callback handling, and disposal logic), allowing the core `PersistentValueMapBase`, `PersistentValueMap`, and `GlobalValueMap` classes to be more generic.

6. **Analyzing the Trait Classes:**  I'd examine each trait class in detail:
    * **`StdMapTraits`:**  This is clearly the foundation, using `std::map` as the backing store. The static methods like `Empty`, `Size`, `Set`, `Get`, `Remove` map directly to `std::map` operations. This makes sense – it provides a basic, standard implementation.
    * **`DefaultPersistentValueMapTraits`:** This inherits from `StdMapTraits` and introduces the concept of weak callbacks. The `kCallbackType = kNotWeak` indicates this *specific* trait doesn't use weak persistence. The empty implementations of `WeakCallbackParameter`, `MapFromWeakCallbackInfo`, etc., reinforce this.
    * **`DefaultGlobalMapTraits`:** Similar to `DefaultPersistentValueMapTraits`, but potentially with differences in the weak callback handling (note the separate `OnWeakCallback` and `DisposeWeak`).

7. **Analyzing the Core Container Classes:**
    * **`PersistentValueMapBase`:** This is the base class providing common functionality. Key things to note:
        * It holds an `Isolate*`, indicating it's tied to a specific V8 isolate.
        * The `Get`, `Contains`, `SetReturnValue`, `Remove`, `Clear` methods are standard map-like operations.
        * The `PersistentValueReference` inner class is interesting. It seems to offer a way to get a "fast" reference to a value, but with caveats about its validity. This suggests performance optimizations.
        * The `FromVal`, `ClearAndLeak`, `Leak`, and `Release` methods are crucial for the interaction between the container and V8's persistent handles. They manage the conversion between the internal `PersistentContainerValue` and `Global<V>`.
    * **`PersistentValueMap`:** This class builds on the base class, specifically dealing with `Persistent` handles. The `Set` and `SetUnique` methods show how values are added to the map, and importantly, how weak callbacks are set up when `Traits::kCallbackType` indicates they should be. The `WeakCallback` static method is the actual callback invoked by V8's garbage collector.
    * **`GlobalValueMap`:** Similar to `PersistentValueMap`, but it likely deals with `Global` handles in a slightly different way, possibly with a two-pass weak callback mechanism (see `OnWeakCallback` and `SecondWeakCallback`).

8. **Concrete Implementations:**
    * **`StdPersistentValueMap` and `StdGlobalValueMap`:** These are simple typedefs that instantiate the `PersistentValueMap` and `GlobalValueMap` with the default `StdMapTraits`. This provides ready-to-use map implementations backed by `std::map`.

9. **Connecting to JavaScript:**  Since these classes manage `Global` handles, which are persistent references to JavaScript objects, the connection to JavaScript is direct. I'd think about scenarios where embedders need to store and retrieve JavaScript objects. Examples would be storing callbacks, managing object lifecycles tied to native objects, or caching results of JavaScript computations.

10. **Considering Errors:** Based on the complexity of managing persistent handles and weak callbacks, I'd think about common errors:
    * **Dangling pointers:** If the embedder holds onto the raw pointer obtained from a `Local` handle after the `Local` goes out of scope.
    * **Use-after-free:** If a weakly held object is garbage collected, and the embedder tries to access it.
    * **Incorrect weak callback handling:** Not properly disposing of resources in the weak callback.
    * **Mixing strong and weak references incorrectly.**

11. **Torque Check:** Finally, I'd check the file extension. Since it's `.h`, it's a C++ header file, not a Torque file.

By following this kind of detailed examination, focusing on the purpose, the design patterns (traits), and the interaction with V8's core concepts (isolates, handles, garbage collection), I can arrive at a comprehensive understanding of the functionality of `v8-util.h`.
`v8/include/v8-util.h` is a C++ header file in the V8 JavaScript engine. It provides utility classes for managing persistent references to V8 objects, particularly designed for embedders (applications that embed the V8 engine).

Here's a breakdown of its functionalities:

**Core Functionality: Managing Persistent Handles**

The primary goal of this header file is to offer convenient ways to store and retrieve V8 `Global` handles (which are persistent references to V8 objects) in C++ containers, especially in environments where C++11 features (like move semantics with standard containers holding `Global`) might not be available or preferred.

**Key Classes and Concepts:**

1. **`PersistentValueMapBase<K, V, Traits>`:**
   - This is the base class for the persistent value maps.
   - It provides the core logic for storing key-value pairs where the values are V8 objects (represented by `Global<V>`).
   - It handles the underlying storage mechanism (delegated to the `Traits` template parameter).
   - It manages the interaction with V8's persistent handles, including creating, accessing, and releasing them.
   - It offers methods like `Get`, `Contains`, `SetReturnValue`, `Remove`, and `Clear`.
   - It introduces `PersistentValueReference` for potentially faster access to values within certain constraints.

2. **`PersistentValueMap<K, V, Traits>`:**
   - Inherits from `PersistentValueMapBase`.
   - Specifically designed for managing `Persistent` handles.
   - Provides `Set` methods to add or update key-value pairs, taking either `Local<V>` or `Global<V>` as input.
   - **Crucially, it handles weak callbacks.** If the `Traits` indicate weak persistence, it sets up a weak callback that will be triggered when the associated V8 object is garbage collected. This allows embedders to clean up resources when a JavaScript object is no longer needed.

3. **`GlobalValueMap<K, V, Traits>`:**
   - Also inherits from `PersistentValueMapBase`.
   - Intended for managing `Global` handles, potentially with slightly different weak callback semantics compared to `PersistentValueMap`. It often involves a two-pass weak callback mechanism.

4. **Traits (`StdMapTraits`, `DefaultPersistentValueMapTraits`, `DefaultGlobalMapTraits`):**
   - The `Traits` template parameter allows for customization of the underlying storage and behavior of the maps.
   - **`StdMapTraits`:** Provides a basic implementation using `std::map` as the backing store. This is a simple, non-weak implementation.
   - **`DefaultPersistentValueMapTraits`:** Inherits from `StdMapTraits` and provides default behavior for `PersistentValueMap`, typically non-weak.
   - **`DefaultGlobalMapTraits`:** Similar to `DefaultPersistentValueMapTraits` but for `GlobalValueMap`, also typically non-weak by default, but sets the stage for weak handling.
   - Custom traits can be implemented to use different backing stores or to customize weak callback behavior.

5. **`StdPersistentValueMap<K, V, Traits>` and `StdGlobalValueMap<K, V, Traits>`:**
   - These are convenience typedefs that create `PersistentValueMap` and `GlobalValueMap` instances using `StdMapTraits` as the default, providing a readily usable map backed by `std::map` with non-weak references.

**Functionality Breakdown:**

* **Storing Persistent References:**  Allows embedders to store pointers to V8 JavaScript objects in a way that prevents them from being prematurely garbage collected (when using strong references).
* **Weak References and Garbage Collection:** Provides mechanisms (through weak callbacks) to be notified when JavaScript objects stored in the map are garbage collected. This is essential for managing resources associated with those objects in the embedding application.
* **Abstraction over Handle Management:** Simplifies the process of working with V8's `Persistent` and `Global` handles, reducing boilerplate code.
* **Customizable Storage:** The `Traits` pattern allows developers to choose or implement different underlying storage mechanisms if `std::map` is not suitable.

**Is `v8/include/v8-util.h` a Torque source file?**

No, the filename ends with `.h`, which is the standard convention for C++ header files. If it were a Torque source file, it would end with `.tq`.

**Relationship to JavaScript and Examples:**

This header file is directly related to managing the lifecycle of JavaScript objects within a V8 embedding. Here are some examples of how its functionalities can be used, illustrated with conceptual JavaScript:

**Scenario 1: Storing a JavaScript callback function:**

```cpp
// C++
#include "v8.h"
#include "v8-util.h"

v8::Isolate* isolate = /* ... your isolate ... */;
v8::StdPersistentValueMap<std::string, v8::Function> callbackMap(isolate);

// ... later, when a JavaScript function is provided ...
v8::Local<v8::String> key = v8::String::NewFromUtf8(isolate, "myCallback").ToLocalChecked();
v8::Local<v8::Function> jsCallback = /* ... the JavaScript function ... */;
callbackMap.Set(*key, jsCallback);

// ... later, when you need to call the callback ...
v8::Local<v8::String> retrieveKey = v8::String::NewFromUtf8(isolate, "myCallback").ToLocalChecked();
v8::Local<v8::Function> retrievedCallback = callbackMap.Get(*retrieveKey);
if (!retrievedCallback.IsEmpty()) {
  v8::Function::Call(isolate->GetCurrentContext(), retrievedCallback, isolate->GetCurrentContext()->Global(), 0, nullptr);
}
```

```javascript
// JavaScript (example of the function being stored)
function doSomething() {
  console.log("Callback invoked from C++!");
}
```

**Scenario 2: Associating a C++ object with a JavaScript object and using weak references for cleanup:**

```cpp
// C++
#include "v8.h"
#include "v8-util.h"

class MyNativeObject {
public:
  // ... native object data and methods ...
  ~MyNativeObject() {
    // Clean up native resources when the associated JS object is GC'd
    std::cout << "MyNativeObject destroyed!" << std::endl;
  }
};

// Custom traits for weak persistence
template <typename K, typename V>
class WeakPersistentMapTraits : public v8::StdMapTraits<K, V> {
public:
  static const v8::PersistentContainerCallbackType kCallbackType =
      v8::kWeakWithParameter;
  typedef WeakPersistentMapTraits<K, V> ThisType;
  typedef v8::PersistentValueMap<K, v8::Object, ThisType> MapType;
  typedef MyNativeObject* WeakCallbackDataType;

  static WeakCallbackDataType* WeakCallbackParameter(
      MapType* map, const K& key, v8::Local<v8::Object> value) {
    // Assuming you have a way to get the MyNativeObject associated with the key
    return /* pointer to your MyNativeObject */;
  }

  static MapType* MapFromWeakCallbackInfo(
      const v8::WeakCallbackInfo<WeakCallbackDataType>& data) {
    // Not directly used in this simple example, but useful in more complex scenarios
    return static_cast<MapType*>(data.GetInternalHolder()); // Assuming you set the holder
  }

  static K KeyFromWeakCallbackInfo(
      const v8::WeakCallbackInfo<WeakCallbackDataType>& data) {
    // You'd need a way to recover the key, perhaps by storing it in the holder
    return K(); // Placeholder
  }

  static void DisposeCallbackData(WeakCallbackDataType* data) {
    delete data; // Clean up the associated native object
  }

  static void Dispose(v8::Isolate* isolate, v8::Global<v8::Object> value, K key) {
    // No special disposal needed for the Global itself in this case
  }
};

v8::Isolate* isolate = /* ... your isolate ... */;
v8::PersistentValueMap<MyNativeObject*, v8::Object, WeakPersistentMapTraits<MyNativeObject*, v8::Object>> nativeObjectMap(isolate);

// ... when creating a new JavaScript object and its associated native object ...
MyNativeObject* nativeObj = new MyNativeObject();
v8::Local<v8::Object> jsObj = v8::Object::New(isolate);
nativeObjectMap.Set(nativeObj, jsObj);

// When the JavaScript object is garbage collected, the weak callback in
// WeakPersistentMapTraits will be triggered, and the MyNativeObject will be deleted.
```

```javascript
// JavaScript (example of the object being associated)
let myObject = {};
// ... myObject might be used and eventually become unreachable ...
```

**Code Logic Inference (with assumptions):**

Let's consider the `PersistentValueMap::SetUnique` method assuming `Traits::kCallbackType` is `kWeakWithParameter`.

**Assumed Input:**

* `key`: An instance of type `K` (e.g., an integer). Let's say `key = 10`.
* `persistent`: A pointer to a `v8::Global<v8::Object>` representing a JavaScript object. Let's assume this `Global` currently points to a valid JavaScript object.
* `this`: An instance of `PersistentValueMap<int, v8::Object, MyWeakTraits>`, where `MyWeakTraits` has `kCallbackType = kWeakWithParameter`.
* `Traits::WeakCallbackParameter(this, key, value)`:  Let's assume this function, for this specific `key` and `value`, returns a pointer to an integer `new int(123)`.

**Expected Output & Logic:**

1. **Weak Callback Setup:**
   - `callback_type` will be `WeakCallbackType::kParameter`.
   - `value` will be a `Local<v8::Object>` created from the `persistent` `Global`.
   - `persistent->SetWeak(new int(123), WeakCallback, WeakCallbackType::kParameter)` will be called. This associates the `WeakCallback` function with the `Global`, and the `new int(123)` will be passed as the parameter to the callback when the object is garbage collected.

2. **Storing in the Map:**
   - `this->ClearAndLeak(persistent)` will:
     - Get the internal memory slot of the `persistent` handle.
     - Call `persistent->Clear()` which *doesn't* immediately destroy the object but releases the strong hold.
     - Return the memory address as a `PersistentContainerValue`.
   - `Traits::Set(this->impl(), key, /* the leaked address */)` will store the `key` (10) and the leaked address in the underlying map (likely `std::map` based on the default traits).

3. **Return Value:**
   - `this->Release(old_value)`: Since this is a `Set`, `old_value` would be the previous value associated with `key` (10) in the map, or `kPersistentContainerNotFound` if it's a new entry. `Release` converts the `PersistentContainerValue` back to a `Global` (if it's not `NotFound`).

**User-Common Programming Errors:**

1. **Dangling Pointers:**
   ```cpp
   v8::Local<v8::Value> GetValue(v8::Isolate* isolate, v8::StdPersistentValueMap<int, v8::Value>& map, int key) {
     return map.Get(key); // Potential problem!
   }

   // ... later ...
   v8::Isolate* isolate = /* ... */;
   v8::StdPersistentValueMap<int, v8::Value> myMap(isolate);
   myMap.Set(1, v8::String::NewFromUtf8(isolate, "hello").ToLocalChecked());
   v8::Local<v8::Value> val = GetValue(isolate, myMap, 1);
   // If myMap goes out of scope here, the Global inside it is destroyed.
   // 'val' might become a dangling pointer if not used carefully within the same scope.
   ```
   **Explanation:**  The `Get` method returns a `Local` handle. `Local` handles are managed by a handle scope and are only valid within that scope. If the `PersistentValueMap` goes out of scope or is cleared, the underlying `Global` is destroyed, and the `Local` returned by `Get` becomes invalid.

2. **Forgetting to Clear Persistent Maps:**
   ```cpp
   void processData(v8::Isolate* isolate) {
     v8::StdPersistentValueMap<int, v8::Object> tempObjects(isolate);
     // ... add some objects to tempObjects ...
     // Forgetting to call tempObjects.Clear() here can lead to memory leaks
     // as the Global handles inside tempObjects will persist.
   }
   ```
   **Explanation:**  If you create persistent maps within a function and don't explicitly call `Clear()` on them before they go out of scope, the `Global` handles held within the map will persist, potentially leading to memory leaks. The destructor of the map *does* call `Clear()`, but it's good practice to be explicit.

3. **Incorrectly Handling Weak Callbacks:**
   ```cpp
   // ... (using WeakPersistentMapTraits from the earlier example) ...

   void MyWeakPersistentMapTraits::DisposeCallbackData(MyNativeObject* data) {
     // Potential error: double-free if 'data' is not managed carefully elsewhere
     delete data;
   }
   ```
   **Explanation:**  The weak callback is invoked when the JavaScript object is garbage collected. It's crucial to ensure that the resources being cleaned up in the callback are valid and haven't already been freed elsewhere. Incorrectly managing the lifecycle of the `WeakCallbackDataType` can lead to double-frees or use-after-free errors.

This comprehensive explanation covers the key functionalities of `v8-util.h`, its relationship to JavaScript, and potential pitfalls for developers.

### 提示词
```
这是目录为v8/include/v8-util.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-util.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_UTIL_H_
#define V8_UTIL_H_

#include <assert.h>

#include <map>
#include <vector>

#include "v8-function-callback.h"  // NOLINT(build/include_directory)
#include "v8-persistent-handle.h"  // NOLINT(build/include_directory)

/**
 * Support for Persistent containers.
 *
 * C++11 embedders can use STL containers with Global values,
 * but pre-C++11 does not support the required move semantic and hence
 * may want these container classes.
 */
namespace v8 {

template <typename K, typename V, typename Traits>
class GlobalValueMap;

typedef uintptr_t PersistentContainerValue;
static const uintptr_t kPersistentContainerNotFound = 0;
enum PersistentContainerCallbackType {
  kNotWeak,
  // These correspond to v8::WeakCallbackType
  kWeakWithParameter,
  kWeakWithInternalFields
};

/**
 * A default trait implementation for PersistentValueMap which uses std::map
 * as a backing map.
 *
 * Users will have to implement their own weak callbacks & dispose traits.
 */
template<typename K, typename V>
class StdMapTraits {
 public:
  // STL map & related:
  typedef std::map<K, PersistentContainerValue> Impl;
  typedef typename Impl::iterator Iterator;

  static bool Empty(Impl* impl) { return impl->empty(); }
  static size_t Size(Impl* impl) { return impl->size(); }
  static void Swap(Impl& a, Impl& b) { std::swap(a, b); }
  static Iterator Begin(Impl* impl) { return impl->begin(); }
  static Iterator End(Impl* impl) { return impl->end(); }
  static K Key(Iterator it) { return it->first; }
  static PersistentContainerValue Value(Iterator it) { return it->second; }
  static PersistentContainerValue Set(Impl* impl, K key,
      PersistentContainerValue value) {
    std::pair<Iterator, bool> res = impl->insert(std::make_pair(key, value));
    PersistentContainerValue old_value = kPersistentContainerNotFound;
    if (!res.second) {
      old_value = res.first->second;
      res.first->second = value;
    }
    return old_value;
  }
  static PersistentContainerValue Get(Impl* impl, K key) {
    Iterator it = impl->find(key);
    if (it == impl->end()) return kPersistentContainerNotFound;
    return it->second;
  }
  static PersistentContainerValue Remove(Impl* impl, K key) {
    Iterator it = impl->find(key);
    if (it == impl->end()) return kPersistentContainerNotFound;
    PersistentContainerValue value = it->second;
    impl->erase(it);
    return value;
  }
};


/**
 * A default trait implementation for PersistentValueMap, which inherits
 * a std:map backing map from StdMapTraits and holds non-weak persistent
 * objects and has no special Dispose handling.
 *
 * You should not derive from this class, since MapType depends on the
 * surrounding class, and hence a subclass cannot simply inherit the methods.
 */
template<typename K, typename V>
class DefaultPersistentValueMapTraits : public StdMapTraits<K, V> {
 public:
  // Weak callback & friends:
  static const PersistentContainerCallbackType kCallbackType = kNotWeak;
  typedef PersistentValueMap<K, V, DefaultPersistentValueMapTraits<K, V> >
      MapType;
  typedef void WeakCallbackDataType;

  static WeakCallbackDataType* WeakCallbackParameter(
      MapType* map, const K& key, Local<V> value) {
    return nullptr;
  }
  static MapType* MapFromWeakCallbackInfo(
      const WeakCallbackInfo<WeakCallbackDataType>& data) {
    return nullptr;
  }
  static K KeyFromWeakCallbackInfo(
      const WeakCallbackInfo<WeakCallbackDataType>& data) {
    return K();
  }
  static void DisposeCallbackData(WeakCallbackDataType* data) { }
  static void Dispose(Isolate* isolate, Global<V> value, K key) {}
};


template <typename K, typename V>
class DefaultGlobalMapTraits : public StdMapTraits<K, V> {
 private:
  template <typename T>
  struct RemovePointer;

 public:
  // Weak callback & friends:
  static const PersistentContainerCallbackType kCallbackType = kNotWeak;
  typedef GlobalValueMap<K, V, DefaultGlobalMapTraits<K, V> > MapType;
  typedef void WeakCallbackDataType;

  static WeakCallbackDataType* WeakCallbackParameter(MapType* map, const K& key,
                                                     Local<V> value) {
    return nullptr;
  }
  static MapType* MapFromWeakCallbackInfo(
      const WeakCallbackInfo<WeakCallbackDataType>& data) {
    return nullptr;
  }
  static K KeyFromWeakCallbackInfo(
      const WeakCallbackInfo<WeakCallbackDataType>& data) {
    return K();
  }
  static void DisposeCallbackData(WeakCallbackDataType* data) {}
  static void OnWeakCallback(
      const WeakCallbackInfo<WeakCallbackDataType>& data) {}
  static void Dispose(Isolate* isolate, Global<V> value, K key) {}
  // This is a second pass callback, so SetSecondPassCallback cannot be called.
  static void DisposeWeak(const WeakCallbackInfo<WeakCallbackDataType>& data) {}

 private:
  template <typename T>
  struct RemovePointer<T*> {
    typedef T Type;
  };
};


/**
 * A map wrapper that allows using Global as a mapped value.
 * C++11 embedders don't need this class, as they can use Global
 * directly in std containers.
 *
 * The map relies on a backing map, whose type and accessors are described
 * by the Traits class. The backing map will handle values of type
 * PersistentContainerValue, with all conversion into and out of V8
 * handles being transparently handled by this class.
 */
template <typename K, typename V, typename Traits>
class PersistentValueMapBase {
 public:
  Isolate* GetIsolate() { return isolate_; }

  /**
   * Return size of the map.
   */
  size_t Size() { return Traits::Size(&impl_); }

  /**
   * Return whether the map holds weak persistents.
   */
  bool IsWeak() { return Traits::kCallbackType != kNotWeak; }

  /**
   * Get value stored in map.
   */
  Local<V> Get(const K& key) {
    V* p = FromVal(Traits::Get(&impl_, key));
#ifdef V8_ENABLE_DIRECT_HANDLE
    if (p == nullptr) return Local<V>();
#endif
    return Local<V>::New(isolate_, p);
  }

  /**
   * Check whether a value is contained in the map.
   */
  bool Contains(const K& key) {
    return Traits::Get(&impl_, key) != kPersistentContainerNotFound;
  }

  /**
   * Get value stored in map and set it in returnValue.
   * Return true if a value was found.
   */
  bool SetReturnValue(const K& key,
      ReturnValue<Value> returnValue) {
    return SetReturnValueFromVal(&returnValue, Traits::Get(&impl_, key));
  }

  /**
   * Return value for key and remove it from the map.
   */
  Global<V> Remove(const K& key) {
    return Release(Traits::Remove(&impl_, key)).Pass();
  }

  /**
  * Traverses the map repeatedly,
  * in case side effects of disposal cause insertions.
  **/
  void Clear() {
    typedef typename Traits::Iterator It;
    HandleScope handle_scope(isolate_);
    // TODO(dcarney): figure out if this swap and loop is necessary.
    while (!Traits::Empty(&impl_)) {
      typename Traits::Impl impl;
      Traits::Swap(impl_, impl);
      for (It i = Traits::Begin(&impl); i != Traits::End(&impl); ++i) {
        Traits::Dispose(isolate_, Release(Traits::Value(i)).Pass(),
                        Traits::Key(i));
      }
    }
  }

  /**
   * Helper class for GetReference/SetWithReference. Do not use outside
   * that context.
   */
  class PersistentValueReference {
   public:
    PersistentValueReference() : value_(kPersistentContainerNotFound) { }
    PersistentValueReference(const PersistentValueReference& other)
        : value_(other.value_) { }

    Local<V> NewLocal(Isolate* isolate) const {
      return Local<V>::New(isolate,
                           internal::ValueHelper::SlotAsValue<V>(
                               reinterpret_cast<internal::Address*>(value_)));
    }
    bool IsEmpty() const {
      return value_ == kPersistentContainerNotFound;
    }
    template<typename T>
    bool SetReturnValue(ReturnValue<T> returnValue) {
      return SetReturnValueFromVal(&returnValue, value_);
    }
    void Reset() {
      value_ = kPersistentContainerNotFound;
    }
    void operator=(const PersistentValueReference& other) {
      value_ = other.value_;
    }

   private:
    friend class PersistentValueMapBase;
    friend class PersistentValueMap<K, V, Traits>;
    friend class GlobalValueMap<K, V, Traits>;

    explicit PersistentValueReference(PersistentContainerValue value)
        : value_(value) { }

    void operator=(PersistentContainerValue value) {
      value_ = value;
    }

    PersistentContainerValue value_;
  };

  /**
   * Get a reference to a map value. This enables fast, repeated access
   * to a value stored in the map while the map remains unchanged.
   *
   * Careful: This is potentially unsafe, so please use with care.
   * The value will become invalid if the value for this key changes
   * in the underlying map, as a result of Set or Remove for the same
   * key; as a result of the weak callback for the same key; or as a
   * result of calling Clear() or destruction of the map.
   */
  PersistentValueReference GetReference(const K& key) {
    return PersistentValueReference(Traits::Get(&impl_, key));
  }

 protected:
  explicit PersistentValueMapBase(Isolate* isolate)
      : isolate_(isolate), label_(nullptr) {}
  PersistentValueMapBase(Isolate* isolate, const char* label)
      : isolate_(isolate), label_(label) {}

  ~PersistentValueMapBase() { Clear(); }

  Isolate* isolate() { return isolate_; }
  typename Traits::Impl* impl() { return &impl_; }

  static V* FromVal(PersistentContainerValue v) {
    return internal::ValueHelper::SlotAsValue<V>(
        reinterpret_cast<internal::Address*>(v));
  }

  static PersistentContainerValue ClearAndLeak(Global<V>* persistent) {
    internal::Address* address = persistent->slot();
    persistent->Clear();
    return reinterpret_cast<PersistentContainerValue>(address);
  }

  static PersistentContainerValue Leak(Global<V>* persistent) {
    return reinterpret_cast<PersistentContainerValue>(persistent->slot());
  }

  /**
   * Return a container value as Global and make sure the weak
   * callback is properly disposed of. All remove functionality should go
   * through this.
   */
  static Global<V> Release(PersistentContainerValue v) {
    Global<V> p;
    p.slot() = reinterpret_cast<internal::Address*>(v);
    if (Traits::kCallbackType != kNotWeak && p.IsWeak()) {
      Traits::DisposeCallbackData(
          p.template ClearWeak<typename Traits::WeakCallbackDataType>());
    }
    return p.Pass();
  }

  void RemoveWeak(const K& key) {
    Global<V> p;
    p.slot() =
        reinterpret_cast<internal::Address*>(Traits::Remove(&impl_, key));
    p.Reset();
  }

  void AnnotateStrongRetainer(Global<V>* persistent) {
    persistent->AnnotateStrongRetainer(label_);
  }

 private:
  PersistentValueMapBase(PersistentValueMapBase&);
  void operator=(PersistentValueMapBase&);

  static bool SetReturnValueFromVal(ReturnValue<Value>* returnValue,
                                    PersistentContainerValue value) {
    bool hasValue = value != kPersistentContainerNotFound;
    if (hasValue) {
      returnValue->SetInternal(*reinterpret_cast<internal::Address*>(value));
    }
    return hasValue;
  }

  Isolate* isolate_;
  typename Traits::Impl impl_;
  const char* label_;
};

template <typename K, typename V, typename Traits>
class PersistentValueMap : public PersistentValueMapBase<K, V, Traits> {
 public:
  explicit PersistentValueMap(Isolate* isolate)
      : PersistentValueMapBase<K, V, Traits>(isolate) {}
  PersistentValueMap(Isolate* isolate, const char* label)
      : PersistentValueMapBase<K, V, Traits>(isolate, label) {}

  typedef
      typename PersistentValueMapBase<K, V, Traits>::PersistentValueReference
          PersistentValueReference;

  /**
   * Put value into map. Depending on Traits::kIsWeak, the value will be held
   * by the map strongly or weakly.
   * Returns old value as Global.
   */
  Global<V> Set(const K& key, Local<V> value) {
    Global<V> persistent(this->isolate(), value);
    return SetUnique(key, &persistent);
  }

  /**
   * Put value into map, like Set(const K&, Local<V>).
   */
  Global<V> Set(const K& key, Global<V> value) {
    return SetUnique(key, &value);
  }

  /**
   * Put the value into the map, and set the 'weak' callback when demanded
   * by the Traits class.
   */
  Global<V> SetUnique(const K& key, Global<V>* persistent) {
    if (Traits::kCallbackType == kNotWeak) {
      this->AnnotateStrongRetainer(persistent);
    } else {
      WeakCallbackType callback_type =
          Traits::kCallbackType == kWeakWithInternalFields
              ? WeakCallbackType::kInternalFields
              : WeakCallbackType::kParameter;
      auto value = Local<V>::New(this->isolate(), *persistent);
      persistent->template SetWeak<typename Traits::WeakCallbackDataType>(
          Traits::WeakCallbackParameter(this, key, value), WeakCallback,
          callback_type);
    }
    PersistentContainerValue old_value =
        Traits::Set(this->impl(), key, this->ClearAndLeak(persistent));
    return this->Release(old_value).Pass();
  }

  /**
   * Put a value into the map and update the reference.
   * Restrictions of GetReference apply here as well.
   */
  Global<V> Set(const K& key, Global<V> value,
                PersistentValueReference* reference) {
    *reference = this->Leak(&value);
    return SetUnique(key, &value);
  }

 private:
  static void WeakCallback(
      const WeakCallbackInfo<typename Traits::WeakCallbackDataType>& data) {
    if (Traits::kCallbackType != kNotWeak) {
      PersistentValueMap<K, V, Traits>* persistentValueMap =
          Traits::MapFromWeakCallbackInfo(data);
      K key = Traits::KeyFromWeakCallbackInfo(data);
      Traits::Dispose(data.GetIsolate(),
                      persistentValueMap->Remove(key).Pass(), key);
      Traits::DisposeCallbackData(data.GetParameter());
    }
  }
};


template <typename K, typename V, typename Traits>
class GlobalValueMap : public PersistentValueMapBase<K, V, Traits> {
 public:
  explicit GlobalValueMap(Isolate* isolate)
      : PersistentValueMapBase<K, V, Traits>(isolate) {}
  GlobalValueMap(Isolate* isolate, const char* label)
      : PersistentValueMapBase<K, V, Traits>(isolate, label) {}

  typedef
      typename PersistentValueMapBase<K, V, Traits>::PersistentValueReference
          PersistentValueReference;

  /**
   * Put value into map. Depending on Traits::kIsWeak, the value will be held
   * by the map strongly or weakly.
   * Returns old value as Global.
   */
  Global<V> Set(const K& key, Local<V> value) {
    Global<V> persistent(this->isolate(), value);
    return SetUnique(key, &persistent);
  }

  /**
   * Put value into map, like Set(const K&, Local<V>).
   */
  Global<V> Set(const K& key, Global<V> value) {
    return SetUnique(key, &value);
  }

  /**
   * Put the value into the map, and set the 'weak' callback when demanded
   * by the Traits class.
   */
  Global<V> SetUnique(const K& key, Global<V>* persistent) {
    if (Traits::kCallbackType == kNotWeak) {
      this->AnnotateStrongRetainer(persistent);
    } else {
      WeakCallbackType callback_type =
          Traits::kCallbackType == kWeakWithInternalFields
              ? WeakCallbackType::kInternalFields
              : WeakCallbackType::kParameter;
      auto value = Local<V>::New(this->isolate(), *persistent);
      persistent->template SetWeak<typename Traits::WeakCallbackDataType>(
          Traits::WeakCallbackParameter(this, key, value), OnWeakCallback,
          callback_type);
    }
    PersistentContainerValue old_value =
        Traits::Set(this->impl(), key, this->ClearAndLeak(persistent));
    return this->Release(old_value).Pass();
  }

  /**
   * Put a value into the map and update the reference.
   * Restrictions of GetReference apply here as well.
   */
  Global<V> Set(const K& key, Global<V> value,
                PersistentValueReference* reference) {
    *reference = this->Leak(&value);
    return SetUnique(key, &value);
  }

 private:
  static void OnWeakCallback(
      const WeakCallbackInfo<typename Traits::WeakCallbackDataType>& data) {
    if (Traits::kCallbackType != kNotWeak) {
      auto map = Traits::MapFromWeakCallbackInfo(data);
      K key = Traits::KeyFromWeakCallbackInfo(data);
      map->RemoveWeak(key);
      Traits::OnWeakCallback(data);
      data.SetSecondPassCallback(SecondWeakCallback);
    }
  }

  static void SecondWeakCallback(
      const WeakCallbackInfo<typename Traits::WeakCallbackDataType>& data) {
    Traits::DisposeWeak(data);
  }
};


/**
 * A map that uses Global as value and std::map as the backing
 * implementation. Persistents are held non-weak.
 *
 * C++11 embedders don't need this class, as they can use
 * Global directly in std containers.
 */
template<typename K, typename V,
    typename Traits = DefaultPersistentValueMapTraits<K, V> >
class StdPersistentValueMap : public PersistentValueMap<K, V, Traits> {
 public:
  explicit StdPersistentValueMap(Isolate* isolate)
      : PersistentValueMap<K, V, Traits>(isolate) {}
};


/**
 * A map that uses Global as value and std::map as the backing
 * implementation. Globals are held non-weak.
 *
 * C++11 embedders don't need this class, as they can use
 * Global directly in std containers.
 */
template <typename K, typename V,
          typename Traits = DefaultGlobalMapTraits<K, V> >
class StdGlobalValueMap : public GlobalValueMap<K, V, Traits> {
 public:
  explicit StdGlobalValueMap(Isolate* isolate)
      : GlobalValueMap<K, V, Traits>(isolate) {}
};

}  // namespace v8

#endif  // V8_UTIL_H
```