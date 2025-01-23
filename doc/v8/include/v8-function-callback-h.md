Response:
Let's break down the thought process for analyzing this V8 header file.

1. **Understand the Goal:** The request asks for a comprehensive overview of `v8-function-callback.h`. This means identifying its purpose, core components, relationships to JavaScript, potential errors, and any special considerations (like `.tq` files).

2. **Initial Scan for Keywords and Structure:**  Quickly read through the file, looking for familiar terms and structural elements. Keywords like `callback`, `arguments`, `ReturnValue`, `Set`, `Get`, `Isolate`, `Local`, `Global`, `Object`, `Value`, and template usage jump out. The `#ifndef` and `#define` indicate a header guard. The `namespace v8` is also immediately apparent.

3. **Identify Core Classes:** Notice the key classes: `ReturnValue`, `FunctionCallbackInfo`, and `PropertyCallbackInfo`. These are clearly central to the file's purpose. Pay attention to their template parameters (especially `<typename T>`), which suggest they are designed for flexibility in return types.

4. **Analyze `ReturnValue`:**
    * **Purpose:** The name itself is highly suggestive. It's about returning values from callbacks.
    * **Key Methods:** Focus on methods like `Set()`, `SetNonEmpty()`, `SetNull()`, `SetUndefined()`, `Get()`, and `GetIsolate()`. These reveal how values are set and retrieved. The overloaded `Set()` methods for various primitive types are interesting. The private `SetInternal()` hints at the underlying mechanism.
    * **Template Usage:**  The `<typename T>` implies different return types are handled. The `static_assert` within the constructor and `Set()` methods confirms type safety.
    * **Potential Issues:** The comment about the pointer setter being "uncompilable" is a strong indicator of a potential user error.

5. **Analyze `FunctionCallbackInfo`:**
    * **Purpose:** The documentation clearly states this is "the argument information given to function call callbacks."
    * **Key Methods:**  `Length()`, `operator[]`, `This()`, `Holder()`, `NewTarget()`, `IsConstructCall()`, `Data()`, `GetIsolate()`, `GetReturnValue()`. These provide access to all the crucial context of a function call.
    * **`Holder()` Deprecation:** The `V8_DEPRECATED` macro is extremely important. Note the reason and the recommended alternative (`This()`). This signals a breaking change concern.
    * **Constructor and Internal Structure:** The private constructor and the `internal::Address*` members suggest this class is closely tied to V8's internal workings. The static constexpr members reveal internal indexing and size information.

6. **Analyze `PropertyCallbackInfo`:**
    * **Purpose:** Similar to `FunctionCallbackInfo`, but for property access callbacks.
    * **Key Methods:** `GetIsolate()`, `Data()`, `This()`, `Holder()`, `HolderV2()`, `GetReturnValue()`, `ShouldThrowOnError()`. Notice the similarities and differences with `FunctionCallbackInfo`.
    * **`Holder()` Deprecation:**  Again, the deprecation of `Holder()` is significant. `HolderV2()` is the new recommendation.
    * **`ShouldThrowOnError()`:**  This method relates directly to JavaScript's strict mode.

7. **Identify Connections to JavaScript:**
    * **Callbacks:** The very term "callback" is a fundamental concept in JavaScript. These headers define how native C++ code interacts with JavaScript function calls and property accesses.
    * **`this` Keyword:**  The `This()` method directly relates to the JavaScript `this` keyword.
    * **`new.target`:** The `NewTarget()` method connects to the JavaScript `new.target` meta-property in constructors.
    * **Strict Mode:** `ShouldThrowOnError()` ties into JavaScript's strict mode.
    * **Properties:**  `PropertyCallbackInfo` is all about how JavaScript properties are accessed and manipulated.

8. **Consider the `.tq` Extension:** The request specifically asks about `.tq`. Recognize that Torque is V8's internal language and that a `.tq` file would represent a Torque source file, which generates C++ code.

9. **Infer Functionality and Relationships:** Based on the individual class analyses, synthesize the overall purpose: this header provides the interface for native C++ code to be called from JavaScript and to interact with JavaScript objects and their properties.

10. **Construct Examples:** Based on the identified functionalities, create simple JavaScript examples to demonstrate the concepts. Focus on function calls, property access, getters/setters, and the `this` keyword.

11. **Identify Potential Errors:**  Think about common mistakes developers might make when using these APIs. Misunderstanding `this`, incorrect return value handling, and ignoring deprecation warnings are good candidates.

12. **Organize and Refine:** Structure the answer logically with clear headings and bullet points. Ensure the language is clear and concise. Review for accuracy and completeness. Specifically address all parts of the initial request.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "Are these classes used directly by JavaScript developers?"  **Correction:**  No, these are *internal* V8 APIs used by those writing native extensions or embedding V8. JavaScript developers interact *through* the abstractions these APIs enable.
* **Considering the `.tq`:** "Is every header file with `.tq` a direct mapping to this C++ header?" **Correction:** Not necessarily. Torque might generate code that *uses* these C++ structures, but the `.tq` file itself is a different source file.
* **Deprecation:**  "Should I just mention the deprecation or emphasize its importance?" **Refinement:**  Emphasize its importance as it signals potential future breaking changes.

By following this detailed thinking process, combining code analysis with domain knowledge of JavaScript and V8, a comprehensive and accurate answer can be constructed.
`v8/include/v8-function-callback.h` 是 V8 引擎中定义函数和属性回调机制的关键头文件。它定义了用于在 C++ 代码中实现 JavaScript 函数和对象属性操作回调的接口。由于该文件名以 `.h` 结尾，它是一个标准的 C++ 头文件，而不是 Torque 源代码。

以下是该头文件的主要功能：

**1. 定义了 `ReturnValue<T>` 模板类:**

* **功能:**  用于设置和获取从 C++ 回调函数返回到 JavaScript 的值。`T` 是返回值的类型。
* **JavaScript 关联:** 当 C++ 函数被 JavaScript 调用时，C++ 代码需要将结果返回给 JavaScript。`ReturnValue` 提供了一种类型安全的方式来设置这个返回值。
* **代码逻辑推理:**
    * **假设输入:** 一个 C++ 回调函数计算两个数字的和。
    * **输出:** `ReturnValue<v8::Number>` 对象被设置为计算结果。
* **用户常见编程错误:**
    * **错误地设置了返回值的类型:** 例如，试图将一个字符串 `Local<v8::String>` 设置给一个期望 `ReturnValue<v8::Number>` 的回调。
    * **忘记设置返回值:**  如果回调函数没有设置返回值，JavaScript 端会收到 `undefined`。

**2. 定义了 `FunctionCallbackInfo<T>` 模板类:**

* **功能:** 提供了关于当前 JavaScript 函数调用上下文的信息。`T` 通常是 `v8::Value`，表示回调函数的返回值类型。
* **JavaScript 关联:**  当 JavaScript 调用一个绑定到 C++ 的函数时，V8 会创建一个 `FunctionCallbackInfo` 对象并传递给 C++ 回调函数。这个对象包含了调用函数的参数、接收者 (`this`)、是否是构造调用 (`new`) 等信息。
* **代码逻辑推理:**
    * **假设输入:**  JavaScript 代码 `myObject.myFunction(1, "hello")` 调用了一个 C++ 实现的回调函数。
    * **输出:**  `FunctionCallbackInfo` 对象将包含：
        * `Length()` 返回 2 (参数个数)。
        * `operator[](0)` 返回表示数字 1 的 `Local<v8::Value>`。
        * `operator[](1)` 返回表示字符串 "hello" 的 `Local<v8::Value>`。
        * `This()` 返回 `myObject` 的 `Local<v8::Object>`。
* **用户常见编程错误:**
    * **访问越界的参数:** 例如，如果函数只传递了一个参数，却尝试访问 `info[1]`。
    * **错误地理解 `This()` 的含义:**  在不同的调用上下文中，`this` 的指向可能不同。
* **JavaScript 示例:**
  ```javascript
  const myObject = {
    value: 10,
    myFunction: function(a, b) {
      // 这里的 this 指向 myObject
      console.log("this.value:", this.value);
      console.log("Argument a:", a);
      console.log("Argument b:", b);
      return a + b;
    }
  };

  myObject.myFunction(5, 7); // 当 myFunction 是一个 C++ 回调时，FunctionCallbackInfo 会提供这些信息
  ```

**3. 定义了 `PropertyCallbackInfo<T>` 模板类:**

* **功能:** 提供了关于属性访问（get、set、query 等）回调的上下文信息。`T` 是属性值的类型。
* **JavaScript 关联:** 当 JavaScript 代码尝试访问或修改绑定到 C++ 对象的属性时，V8 会创建一个 `PropertyCallbackInfo` 对象并传递给相应的 C++ 回调函数。
* **代码逻辑推理:**
    * **假设输入:** JavaScript 代码 `myObject.myProperty = "new value";` 触发了一个 C++ 实现的属性 setter 回调。
    * **输出:** `PropertyCallbackInfo` 对象将包含：
        * `This()` 返回 `myObject` 的 `Local<v8::Object>`。
        * `Data()` 返回在属性处理配置中设置的数据。
        * `GetReturnValue()` 可以用来设置属性 setter 的返回值（通常用于指示成功或失败）。
* **用户常见编程错误:**
    * **在 getter 中修改对象状态:** 违反了 getter 的只读语义。
    * **在 setter 中忘记设置返回值（如果需要）：**  对于某些属性操作，可能需要设置返回值以指示操作是否成功。
* **JavaScript 示例:**
  ```javascript
  const myObject = {};
  Object.defineProperty(myObject, 'myProperty', {
    get: function() {
      console.log("Getting myProperty");
      return this._myProperty;
    },
    set: function(value) {
      console.log("Setting myProperty to:", value);
      this._myProperty = value;
    }
  });

  myObject.myProperty; // 触发 getter 回调
  myObject.myProperty = "example"; // 触发 setter 回调
  ```

**4. `FunctionCallback` 类型定义:**

* **功能:** 定义了一个指向函数的指针类型，该函数接受一个 `const FunctionCallbackInfo<Value>&` 类型的参数。这是定义普通函数回调的标准签名。

**关于 `.tq` 扩展名:**

文件中明确使用了 `#ifndef INCLUDE_V8_FUNCTION_CALLBACK_H_` 和 `#define INCLUDE_V8_FUNCTION_CALLBACK_H_`，以及 `.h` 的文件扩展名，这表明它是一个标准的 C++ 头文件。如果该文件以 `.tq` 结尾，那么它确实会是一个 V8 Torque 源代码文件。Torque 是一种用于在 V8 中生成高效 C++ 代码的领域特定语言。

**总结:**

`v8/include/v8-function-callback.h` 是 V8 中连接 JavaScript 和 C++ 代码的关键桥梁。它通过 `ReturnValue`, `FunctionCallbackInfo`, 和 `PropertyCallbackInfo` 这几个核心类，为 C++ 开发者提供了与 JavaScript 运行时环境交互所需的必要信息和机制。理解这些类的作用对于编写 V8 扩展、嵌入 V8 或进行 V8 内部开发至关重要。

### 提示词
```
这是目录为v8/include/v8-function-callback.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-function-callback.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_FUNCTION_CALLBACK_H_
#define INCLUDE_V8_FUNCTION_CALLBACK_H_

#include <cstdint>
#include <limits>

#include "v8-internal.h"      // NOLINT(build/include_directory)
#include "v8-local-handle.h"  // NOLINT(build/include_directory)
#include "v8-primitive.h"     // NOLINT(build/include_directory)
#include "v8config.h"         // NOLINT(build/include_directory)

namespace v8 {

template <typename T>
class BasicTracedReference;
template <typename T>
class Global;
class Object;
class Value;

namespace internal {
class FunctionCallbackArguments;
class PropertyCallbackArguments;
class Builtins;
}  // namespace internal

namespace debug {
class ConsoleCallArguments;
}  // namespace debug

namespace api_internal {
V8_EXPORT v8::Local<v8::Value> GetFunctionTemplateData(
    v8::Isolate* isolate, v8::Local<v8::Data> raw_target);
}  // namespace api_internal

template <typename T>
class ReturnValue {
 public:
  template <class S>
  V8_INLINE ReturnValue(const ReturnValue<S>& that) : value_(that.value_) {
    static_assert(std::is_base_of<T, S>::value, "type check");
  }
  // Handle-based setters.
  template <typename S>
  V8_INLINE void Set(const Global<S>& handle);
  template <typename S>
  V8_INLINE void SetNonEmpty(const Global<S>& handle);
  template <typename S>
  V8_INLINE void Set(const BasicTracedReference<S>& handle);
  template <typename S>
  V8_INLINE void SetNonEmpty(const BasicTracedReference<S>& handle);
  template <typename S>
  V8_INLINE void Set(const Local<S> handle);
  template <typename S>
  V8_INLINE void SetNonEmpty(const Local<S> handle);
  // Fast primitive number setters.
  V8_INLINE void Set(bool value);
  V8_INLINE void Set(double i);
  V8_INLINE void Set(int16_t i);
  V8_INLINE void Set(int32_t i);
  V8_INLINE void Set(int64_t i);
  V8_INLINE void Set(uint16_t i);
  V8_INLINE void Set(uint32_t i);
  V8_INLINE void Set(uint64_t i);
  // Fast JS primitive setters
  V8_INLINE void SetNull();
  V8_INLINE void SetUndefined();
  V8_INLINE void SetFalse();
  V8_INLINE void SetEmptyString();
  // Convenience getter for Isolate
  V8_INLINE Isolate* GetIsolate() const;

  // Pointer setter: Uncompilable to prevent inadvertent misuse.
  template <typename S>
  V8_INLINE void Set(S* whatever);

  // Getter. Creates a new Local<> so it comes with a certain performance
  // hit. If the ReturnValue was not yet set, this will return the undefined
  // value.
  V8_INLINE Local<Value> Get() const;

 private:
  template <class F>
  friend class ReturnValue;
  template <class F>
  friend class FunctionCallbackInfo;
  template <class F>
  friend class PropertyCallbackInfo;
  template <class F, class G, class H>
  friend class PersistentValueMapBase;
  V8_INLINE void SetInternal(internal::Address value);
  // Default value depends on <T>:
  //  - <void> -> true_value,
  //  - <v8::Boolean> -> true_value,
  //  - <v8::Integer> -> 0,
  //  - <v8::Value> -> undefined_value,
  //  - <v8::Array> -> undefined_value.
  V8_INLINE void SetDefaultValue();
  V8_INLINE explicit ReturnValue(internal::Address* slot);

  // See FunctionCallbackInfo.
  static constexpr int kIsolateValueIndex = -2;

  internal::Address* value_;
};

/**
 * The argument information given to function call callbacks.  This
 * class provides access to information about the context of the call,
 * including the receiver, the number and values of arguments, and
 * the holder of the function.
 */
template <typename T>
class FunctionCallbackInfo {
 public:
  /** The number of available arguments. */
  V8_INLINE int Length() const;
  /**
   * Accessor for the available arguments. Returns `undefined` if the index
   * is out of bounds.
   */
  V8_INLINE Local<Value> operator[](int i) const;
  /** Returns the receiver. This corresponds to the "this" value. */
  V8_INLINE Local<Object> This() const;
  /**
   * If the callback was created without a Signature, this is the same
   * value as This(). If there is a signature, and the signature didn't match
   * This() but one of its hidden prototypes, this will be the respective
   * hidden prototype.
   *
   * Note that this is not the prototype of This() on which the accessor
   * referencing this callback was found (which in V8 internally is often
   * referred to as holder [sic]).
   */
  V8_DEPRECATED(
      "V8 will stop providing access to hidden prototype (i.e. "
      "JSGlobalObject). Use This() instead. \n"
      "DO NOT try to workaround this by accessing JSGlobalObject via "
      "v8::Object::GetPrototype() - it'll be deprecated soon too. \n"
      "See http://crbug.com/333672197. ")
  V8_INLINE Local<Object> Holder() const;
  /** For construct calls, this returns the "new.target" value. */
  V8_INLINE Local<Value> NewTarget() const;
  /** Indicates whether this is a regular call or a construct call. */
  V8_INLINE bool IsConstructCall() const;
  /** The data argument specified when creating the callback. */
  V8_INLINE Local<Value> Data() const;
  /** The current Isolate. */
  V8_INLINE Isolate* GetIsolate() const;
  /** The ReturnValue for the call. */
  V8_INLINE ReturnValue<T> GetReturnValue() const;

  // This is a temporary replacement for Holder() added just for the purpose
  // of testing the deprecated Holder() machinery until it's removed for real.
  // DO NOT use it.
  V8_INLINE Local<Object> HolderSoonToBeDeprecated() const;

 private:
  friend class internal::FunctionCallbackArguments;
  friend class internal::CustomArguments<FunctionCallbackInfo>;
  friend class debug::ConsoleCallArguments;
  friend void internal::PrintFunctionCallbackInfo(void*);

  static constexpr int kHolderIndex = 0;
  static constexpr int kIsolateIndex = 1;
  static constexpr int kContextIndex = 2;
  static constexpr int kReturnValueIndex = 3;
  static constexpr int kTargetIndex = 4;
  static constexpr int kNewTargetIndex = 5;
  static constexpr int kArgsLength = 6;

  static constexpr int kArgsLengthWithReceiver = kArgsLength + 1;

  // Codegen constants:
  static constexpr int kSize = 3 * internal::kApiSystemPointerSize;
  static constexpr int kImplicitArgsOffset = 0;
  static constexpr int kValuesOffset =
      kImplicitArgsOffset + internal::kApiSystemPointerSize;
  static constexpr int kLengthOffset =
      kValuesOffset + internal::kApiSystemPointerSize;

  static constexpr int kThisValuesIndex = -1;
  static_assert(ReturnValue<Value>::kIsolateValueIndex ==
                kIsolateIndex - kReturnValueIndex);

  V8_INLINE FunctionCallbackInfo(internal::Address* implicit_args,
                                 internal::Address* values, int length);

  // TODO(https://crbug.com/326505377): flatten the v8::FunctionCallbackInfo
  // object to avoid indirect loads through values_ and implicit_args_ and
  // reduce the number of instructions in the CallApiCallback builtin.
  internal::Address* implicit_args_;
  internal::Address* values_;
  internal::Address length_;
};

/**
 * The information passed to a property callback about the context
 * of the property access.
 */
template <typename T>
class PropertyCallbackInfo {
 public:
  /**
   * \return The isolate of the property access.
   */
  V8_INLINE Isolate* GetIsolate() const;

  /**
   * \return The data set in the configuration, i.e., in
   * `NamedPropertyHandlerConfiguration` or
   * `IndexedPropertyHandlerConfiguration.`
   */
  V8_INLINE Local<Value> Data() const;

  /**
   * \return The receiver. In many cases, this is the object on which the
   * property access was intercepted. When using
   * `Reflect.get`, `Function.prototype.call`, or similar functions, it is the
   * object passed in as receiver or thisArg.
   *
   * \code
   *  void GetterCallback(Local<Name> name,
   *                      const v8::PropertyCallbackInfo<v8::Value>& info) {
   *     auto context = info.GetIsolate()->GetCurrentContext();
   *
   *     v8::Local<v8::Value> a_this =
   *         info.This()
   *             ->GetRealNamedProperty(context, v8_str("a"))
   *             .ToLocalChecked();
   *     v8::Local<v8::Value> a_holder =
   *         info.Holder()
   *             ->GetRealNamedProperty(context, v8_str("a"))
   *             .ToLocalChecked();
   *
   *    CHECK(v8_str("r")->Equals(context, a_this).FromJust());
   *    CHECK(v8_str("obj")->Equals(context, a_holder).FromJust());
   *
   *    info.GetReturnValue().Set(name);
   *  }
   *
   *  v8::Local<v8::FunctionTemplate> templ =
   *  v8::FunctionTemplate::New(isolate);
   *  templ->InstanceTemplate()->SetHandler(
   *      v8::NamedPropertyHandlerConfiguration(GetterCallback));
   *  LocalContext env;
   *  env->Global()
   *      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
   *                                           .ToLocalChecked()
   *                                           ->NewInstance(env.local())
   *                                           .ToLocalChecked())
   *      .FromJust();
   *
   *  CompileRun("obj.a = 'obj'; var r = {a: 'r'}; Reflect.get(obj, 'x', r)");
   * \endcode
   */
  V8_INLINE Local<Object> This() const;

  /**
   * \return The object in the prototype chain of the receiver that has the
   * interceptor. Suppose you have `x` and its prototype is `y`, and `y`
   * has an interceptor. Then `info.This()` is `x` and `info.Holder()` is `y`.
   * The Holder() could be a hidden object (the global object, rather
   * than the global proxy).
   *
   * \note For security reasons, do not pass the object back into the runtime.
   */
  V8_DEPRECATE_SOON(
      "V8 will stop providing access to hidden prototype (i.e. "
      "JSGlobalObject). Use HolderV2() instead. \n"
      "DO NOT try to workaround this by accessing JSGlobalObject via "
      "v8::Object::GetPrototype() - it'll be deprecated soon too. \n"
      "See http://crbug.com/333672197. ")
  V8_INLINE Local<Object> Holder() const;

  /**
   * \return The object in the prototype chain of the receiver that has the
   * interceptor. Suppose you have `x` and its prototype is `y`, and `y`
   * has an interceptor. Then `info.This()` is `x` and `info.Holder()` is `y`.
   * In case the property is installed on the global object the Holder()
   * would return the global proxy.
   */
  V8_INLINE Local<Object> HolderV2() const;

  /**
   * \return The return value of the callback.
   * Can be changed by calling Set().
   * \code
   * info.GetReturnValue().Set(...)
   * \endcode
   *
   */
  V8_INLINE ReturnValue<T> GetReturnValue() const;

  /**
   * \return True if the intercepted function should throw if an error occurs.
   * Usually, `true` corresponds to `'use strict'`.
   *
   * \note Always `false` when intercepting `Reflect.set()`
   * independent of the language mode.
   */
  V8_INLINE bool ShouldThrowOnError() const;

 private:
  template <typename U>
  friend class PropertyCallbackInfo;
  friend class MacroAssembler;
  friend class internal::PropertyCallbackArguments;
  friend class internal::CustomArguments<PropertyCallbackInfo>;
  friend void internal::PrintPropertyCallbackInfo(void*);

  static constexpr int kPropertyKeyIndex = 0;
  static constexpr int kShouldThrowOnErrorIndex = 1;
  static constexpr int kHolderIndex = 2;
  static constexpr int kIsolateIndex = 3;
  static constexpr int kHolderV2Index = 4;
  static constexpr int kReturnValueIndex = 5;
  static constexpr int kDataIndex = 6;
  static constexpr int kThisIndex = 7;
  static constexpr int kArgsLength = 8;

  static constexpr int kSize = kArgsLength * internal::kApiSystemPointerSize;

  PropertyCallbackInfo() = default;

  mutable internal::Address args_[kArgsLength];
};

using FunctionCallback = void (*)(const FunctionCallbackInfo<Value>& info);

// --- Implementation ---

template <typename T>
ReturnValue<T>::ReturnValue(internal::Address* slot) : value_(slot) {}

template <typename T>
void ReturnValue<T>::SetInternal(internal::Address value) {
#if V8_STATIC_ROOTS_BOOL
  using I = internal::Internals;
  // Ensure that the upper 32-bits are not modified. Compiler should be
  // able to optimize this to a store of a lower 32-bits of the value.
  // This is fine since the callback can return only JavaScript values which
  // are either Smis or heap objects allocated in the main cage.
  *value_ = I::DecompressTaggedField(*value_, I::CompressTagged(value));
#else
  *value_ = value;
#endif  // V8_STATIC_ROOTS_BOOL
}

template <typename T>
template <typename S>
void ReturnValue<T>::Set(const Global<S>& handle) {
  static_assert(std::is_base_of<T, S>::value, "type check");
  if (V8_UNLIKELY(handle.IsEmpty())) {
    SetDefaultValue();
  } else {
    SetInternal(handle.ptr());
  }
}

template <typename T>
template <typename S>
void ReturnValue<T>::SetNonEmpty(const Global<S>& handle) {
  static_assert(std::is_base_of<T, S>::value, "type check");
#ifdef V8_ENABLE_CHECKS
  internal::VerifyHandleIsNonEmpty(handle.IsEmpty());
#endif  // V8_ENABLE_CHECKS
  SetInternal(handle.ptr());
}

template <typename T>
template <typename S>
void ReturnValue<T>::Set(const BasicTracedReference<S>& handle) {
  static_assert(std::is_base_of<T, S>::value, "type check");
  if (V8_UNLIKELY(handle.IsEmpty())) {
    SetDefaultValue();
  } else {
    SetInternal(handle.ptr());
  }
}

template <typename T>
template <typename S>
void ReturnValue<T>::SetNonEmpty(const BasicTracedReference<S>& handle) {
  static_assert(std::is_base_of<T, S>::value, "type check");
#ifdef V8_ENABLE_CHECKS
  internal::VerifyHandleIsNonEmpty(handle.IsEmpty());
#endif  // V8_ENABLE_CHECKS
  SetInternal(handle.ptr());
}

template <typename T>
template <typename S>
void ReturnValue<T>::Set(const Local<S> handle) {
  // "V8_DEPRECATE_SOON" this method if |T| is |void|.
#ifdef V8_IMMINENT_DEPRECATION_WARNINGS
  static constexpr bool is_allowed_void = false;
  static_assert(!std::is_void<T>::value,
                "ReturnValue<void>::Set(const Local<S>) is deprecated. "
                "Do nothing to indicate that the operation succeeded or use "
                "SetFalse() to indicate that the operation failed (don't "
                "forget to handle info.ShouldThrowOnError()). "
                "See http://crbug.com/348660658 for details.");
#else
  static constexpr bool is_allowed_void = std::is_void<T>::value;
#endif  // V8_IMMINENT_DEPRECATION_WARNINGS
  static_assert(is_allowed_void || std::is_base_of<T, S>::value, "type check");
  if (V8_UNLIKELY(handle.IsEmpty())) {
    SetDefaultValue();
  } else if constexpr (is_allowed_void) {
    // Simulate old behaviour for "v8::AccessorSetterCallback" for which
    // it was possible to set the return value even for ReturnValue<void>.
    Set(handle->BooleanValue(GetIsolate()));
  } else {
    SetInternal(handle.ptr());
  }
}

template <typename T>
template <typename S>
void ReturnValue<T>::SetNonEmpty(const Local<S> handle) {
  // "V8_DEPRECATE_SOON" this method if |T| is |void|.
#ifdef V8_IMMINENT_DEPRECATION_WARNINGS
  static constexpr bool is_allowed_void = false;
  static_assert(!std::is_void<T>::value,
                "ReturnValue<void>::SetNonEmpty(const Local<S>) is deprecated. "
                "Do nothing to indicate that the operation succeeded or use "
                "SetFalse() to indicate that the operation failed (don't "
                "forget to handle info.ShouldThrowOnError()). "
                "See http://crbug.com/348660658 for details.");
#else
  static constexpr bool is_allowed_void = std::is_void<T>::value;
#endif  // V8_IMMINENT_DEPRECATION_WARNINGS
  static_assert(is_allowed_void || std::is_base_of<T, S>::value, "type check");
#ifdef V8_ENABLE_CHECKS
  internal::VerifyHandleIsNonEmpty(handle.IsEmpty());
#endif  // V8_ENABLE_CHECKS
  if constexpr (is_allowed_void) {
    // Simulate old behaviour for "v8::AccessorSetterCallback" for which
    // it was possible to set the return value even for ReturnValue<void>.
    Set(handle->BooleanValue(GetIsolate()));
  } else {
    SetInternal(handle.ptr());
  }
}

template <typename T>
void ReturnValue<T>::Set(double i) {
  static_assert(std::is_base_of<T, Number>::value, "type check");
  SetNonEmpty(Number::New(GetIsolate(), i));
}

template <typename T>
void ReturnValue<T>::Set(int16_t i) {
  static_assert(std::is_base_of<T, Integer>::value, "type check");
  using I = internal::Internals;
  static_assert(I::IsValidSmi(std::numeric_limits<int16_t>::min()));
  static_assert(I::IsValidSmi(std::numeric_limits<int16_t>::max()));
  SetInternal(I::IntegralToSmi(i));
}

template <typename T>
void ReturnValue<T>::Set(int32_t i) {
  static_assert(std::is_base_of<T, Integer>::value, "type check");
  if (const auto result = internal::Internals::TryIntegralToSmi(i)) {
    SetInternal(*result);
    return;
  }
  SetNonEmpty(Integer::New(GetIsolate(), i));
}

template <typename T>
void ReturnValue<T>::Set(int64_t i) {
  static_assert(std::is_base_of<T, Integer>::value, "type check");
  if (const auto result = internal::Internals::TryIntegralToSmi(i)) {
    SetInternal(*result);
    return;
  }
  SetNonEmpty(Number::New(GetIsolate(), static_cast<double>(i)));
}

template <typename T>
void ReturnValue<T>::Set(uint16_t i) {
  static_assert(std::is_base_of<T, Integer>::value, "type check");
  using I = internal::Internals;
  static_assert(I::IsValidSmi(std::numeric_limits<uint16_t>::min()));
  static_assert(I::IsValidSmi(std::numeric_limits<uint16_t>::max()));
  SetInternal(I::IntegralToSmi(i));
}

template <typename T>
void ReturnValue<T>::Set(uint32_t i) {
  static_assert(std::is_base_of<T, Integer>::value, "type check");
  if (const auto result = internal::Internals::TryIntegralToSmi(i)) {
    SetInternal(*result);
    return;
  }
  SetNonEmpty(Integer::NewFromUnsigned(GetIsolate(), i));
}

template <typename T>
void ReturnValue<T>::Set(uint64_t i) {
  static_assert(std::is_base_of<T, Integer>::value, "type check");
  if (const auto result = internal::Internals::TryIntegralToSmi(i)) {
    SetInternal(*result);
    return;
  }
  SetNonEmpty(Number::New(GetIsolate(), static_cast<double>(i)));
}

template <typename T>
void ReturnValue<T>::Set(bool value) {
  static_assert(std::is_void<T>::value || std::is_base_of<T, Boolean>::value,
                "type check");
  using I = internal::Internals;
#if V8_STATIC_ROOTS_BOOL
#ifdef V8_ENABLE_CHECKS
  internal::PerformCastCheck(
      internal::ValueHelper::SlotAsValue<Value, true>(value_));
#endif  // V8_ENABLE_CHECKS
  SetInternal(value ? I::StaticReadOnlyRoot::kTrueValue
                    : I::StaticReadOnlyRoot::kFalseValue);
#else
  int root_index;
  if (value) {
    root_index = I::kTrueValueRootIndex;
  } else {
    root_index = I::kFalseValueRootIndex;
  }
  *value_ = I::GetRoot(GetIsolate(), root_index);
#endif  // V8_STATIC_ROOTS_BOOL
}

template <typename T>
void ReturnValue<T>::SetDefaultValue() {
  using I = internal::Internals;
  if constexpr (std::is_same_v<void, T> || std::is_same_v<v8::Boolean, T>) {
    Set(true);
  } else if constexpr (std::is_same_v<v8::Integer, T>) {
    SetInternal(I::IntegralToSmi(0));
  } else {
    static_assert(std::is_same_v<v8::Value, T> || std::is_same_v<v8::Array, T>);
#if V8_STATIC_ROOTS_BOOL
    SetInternal(I::StaticReadOnlyRoot::kUndefinedValue);
#else
    *value_ = I::GetRoot(GetIsolate(), I::kUndefinedValueRootIndex);
#endif  // V8_STATIC_ROOTS_BOOL
  }
}

template <typename T>
void ReturnValue<T>::SetNull() {
  static_assert(std::is_base_of<T, Primitive>::value, "type check");
  using I = internal::Internals;
#if V8_STATIC_ROOTS_BOOL
#ifdef V8_ENABLE_CHECKS
  internal::PerformCastCheck(
      internal::ValueHelper::SlotAsValue<Value, true>(value_));
#endif  // V8_ENABLE_CHECKS
  SetInternal(I::StaticReadOnlyRoot::kNullValue);
#else
  *value_ = I::GetRoot(GetIsolate(), I::kNullValueRootIndex);
#endif  // V8_STATIC_ROOTS_BOOL
}

template <typename T>
void ReturnValue<T>::SetUndefined() {
  static_assert(std::is_base_of<T, Primitive>::value, "type check");
  using I = internal::Internals;
#if V8_STATIC_ROOTS_BOOL
#ifdef V8_ENABLE_CHECKS
  internal::PerformCastCheck(
      internal::ValueHelper::SlotAsValue<Value, true>(value_));
#endif  // V8_ENABLE_CHECKS
  SetInternal(I::StaticReadOnlyRoot::kUndefinedValue);
#else
  *value_ = I::GetRoot(GetIsolate(), I::kUndefinedValueRootIndex);
#endif  // V8_STATIC_ROOTS_BOOL
}

template <typename T>
void ReturnValue<T>::SetFalse() {
  static_assert(std::is_void<T>::value || std::is_base_of<T, Boolean>::value,
                "type check");
  using I = internal::Internals;
#if V8_STATIC_ROOTS_BOOL
#ifdef V8_ENABLE_CHECKS
  internal::PerformCastCheck(
      internal::ValueHelper::SlotAsValue<Value, true>(value_));
#endif  // V8_ENABLE_CHECKS
  SetInternal(I::StaticReadOnlyRoot::kFalseValue);
#else
  *value_ = I::GetRoot(GetIsolate(), I::kFalseValueRootIndex);
#endif  // V8_STATIC_ROOTS_BOOL
}

template <typename T>
void ReturnValue<T>::SetEmptyString() {
  static_assert(std::is_base_of<T, String>::value, "type check");
  using I = internal::Internals;
#if V8_STATIC_ROOTS_BOOL
#ifdef V8_ENABLE_CHECKS
  internal::PerformCastCheck(
      internal::ValueHelper::SlotAsValue<Value, true>(value_));
#endif  // V8_ENABLE_CHECKS
  SetInternal(I::StaticReadOnlyRoot::kEmptyString);
#else
  *value_ = I::GetRoot(GetIsolate(), I::kEmptyStringRootIndex);
#endif  // V8_STATIC_ROOTS_BOOL
}

template <typename T>
Isolate* ReturnValue<T>::GetIsolate() const {
  return *reinterpret_cast<Isolate**>(&value_[kIsolateValueIndex]);
}

template <typename T>
Local<Value> ReturnValue<T>::Get() const {
  return Local<Value>::New(GetIsolate(),
                           internal::ValueHelper::SlotAsValue<Value>(value_));
}

template <typename T>
template <typename S>
void ReturnValue<T>::Set(S* whatever) {
  static_assert(sizeof(S) < 0, "incompilable to prevent inadvertent misuse");
}

template <typename T>
FunctionCallbackInfo<T>::FunctionCallbackInfo(internal::Address* implicit_args,
                                              internal::Address* values,
                                              int length)
    : implicit_args_(implicit_args), values_(values), length_(length) {}

template <typename T>
Local<Value> FunctionCallbackInfo<T>::operator[](int i) const {
  // values_ points to the first argument (not the receiver).
  if (i < 0 || Length() <= i) return Undefined(GetIsolate());
  return Local<Value>::FromSlot(values_ + i);
}

template <typename T>
Local<Object> FunctionCallbackInfo<T>::This() const {
  // values_ points to the first argument (not the receiver).
  return Local<Object>::FromSlot(values_ + kThisValuesIndex);
}

template <typename T>
Local<Object> FunctionCallbackInfo<T>::HolderSoonToBeDeprecated() const {
  return Local<Object>::FromSlot(&implicit_args_[kHolderIndex]);
}

template <typename T>
Local<Object> FunctionCallbackInfo<T>::Holder() const {
  return HolderSoonToBeDeprecated();
}

template <typename T>
Local<Value> FunctionCallbackInfo<T>::NewTarget() const {
  return Local<Value>::FromSlot(&implicit_args_[kNewTargetIndex]);
}

template <typename T>
Local<Value> FunctionCallbackInfo<T>::Data() const {
  auto target = Local<v8::Data>::FromSlot(&implicit_args_[kTargetIndex]);
  return api_internal::GetFunctionTemplateData(GetIsolate(), target);
}

template <typename T>
Isolate* FunctionCallbackInfo<T>::GetIsolate() const {
  return *reinterpret_cast<Isolate**>(&implicit_args_[kIsolateIndex]);
}

template <typename T>
ReturnValue<T> FunctionCallbackInfo<T>::GetReturnValue() const {
  return ReturnValue<T>(&implicit_args_[kReturnValueIndex]);
}

template <typename T>
bool FunctionCallbackInfo<T>::IsConstructCall() const {
  return !NewTarget()->IsUndefined();
}

template <typename T>
int FunctionCallbackInfo<T>::Length() const {
  return static_cast<int>(length_);
}

template <typename T>
Isolate* PropertyCallbackInfo<T>::GetIsolate() const {
  return *reinterpret_cast<Isolate**>(&args_[kIsolateIndex]);
}

template <typename T>
Local<Value> PropertyCallbackInfo<T>::Data() const {
  return Local<Value>::FromSlot(&args_[kDataIndex]);
}

template <typename T>
Local<Object> PropertyCallbackInfo<T>::This() const {
  return Local<Object>::FromSlot(&args_[kThisIndex]);
}

template <typename T>
Local<Object> PropertyCallbackInfo<T>::Holder() const {
  return Local<Object>::FromSlot(&args_[kHolderIndex]);
}

namespace api_internal {
// Returns JSGlobalProxy if holder is JSGlobalObject or unmodified holder
// otherwise.
V8_EXPORT internal::Address ConvertToJSGlobalProxyIfNecessary(
    internal::Address holder);
}  // namespace api_internal

template <typename T>
Local<Object> PropertyCallbackInfo<T>::HolderV2() const {
  using I = internal::Internals;
  if (!I::HasHeapObjectTag(args_[kHolderV2Index])) {
    args_[kHolderV2Index] =
        api_internal::ConvertToJSGlobalProxyIfNecessary(args_[kHolderIndex]);
  }
  return Local<Object>::FromSlot(&args_[kHolderV2Index]);
}

template <typename T>
ReturnValue<T> PropertyCallbackInfo<T>::GetReturnValue() const {
  return ReturnValue<T>(&args_[kReturnValueIndex]);
}

template <typename T>
bool PropertyCallbackInfo<T>::ShouldThrowOnError() const {
  using I = internal::Internals;
  if (args_[kShouldThrowOnErrorIndex] !=
      I::IntegralToSmi(I::kInferShouldThrowMode)) {
    return args_[kShouldThrowOnErrorIndex] != I::IntegralToSmi(I::kDontThrow);
  }
  return v8::internal::ShouldThrowOnError(
      reinterpret_cast<v8::internal::Isolate*>(GetIsolate()));
}

}  // namespace v8

#endif  // INCLUDE_V8_FUNCTION_CALLBACK_H_
```