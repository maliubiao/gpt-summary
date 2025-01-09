Response:
Let's break down the thought process for analyzing this C++ header file and fulfilling the prompt's requirements.

**1. Initial Understanding (Skimming & Comments):**

The first step is a quick skim to grasp the high-level purpose. The file name `api-arguments-inl.h` and the namespace `v8::internal` strongly suggest this file deals with the internal representation of arguments passed to and from V8's API, especially callbacks. The copyright notice confirms it's a V8 source file. The `#ifndef` guards are standard C++ header practices. The includes point to related V8 internal headers, further reinforcing the API and internal nature of the code. Comments like "Copyright" and explanations about specific macros provide initial clues.

**2. Identifying Key Structures and Classes:**

The next step is to identify the core building blocks. The file defines `CustomArgumentsBase` and a template `CustomArguments<T>`. This suggests a base class for handling arguments and a templated version for specific argument types. The presence of `PropertyCallbackArguments` and `FunctionCallbackArguments` signals that these are likely specialized classes for different callback types.

**3. Analyzing Class Members and Methods:**

Now, let's delve into the details of the classes.

* **`CustomArgumentsBase`:** The constructor taking an `Isolate*` indicates it's tied to a V8 isolate, which represents an independent execution environment.
* **`CustomArguments<T>`:**  The destructor setting a `kHandleZapValue` in a `slot_at` suggests memory management or cleanup. The `GetReturnValue` method clearly deals with retrieving a value returned from a callback. The use of `Handle<V>` suggests V8's handle system for managing JavaScript objects.
* **`PropertyCallbackArguments` and `FunctionCallbackArguments`:**  The `holder()` and `receiver()` methods indicate access to the object on which the property is being accessed or the function is being called.

**4. Deciphering Macros:**

The file contains several macros: `DCHECK_NAME_COMPATIBLE`, `PREPARE_CALLBACK_INFO_ACCESSOR`, and `PREPARE_CALLBACK_INFO_INTERCEPTOR`. Macros often encapsulate repetitive code patterns.

* **`DCHECK_NAME_COMPATIBLE`:** The `DCHECK` statements within this macro strongly suggest it's for runtime assertions to ensure the compatibility of an interceptor and a property name (handling private symbols, etc.).
* **`PREPARE_CALLBACK_INFO_ACCESSOR` and `PREPARE_CALLBACK_INFO_INTERCEPTOR`:** The names and the code within these macros suggest they are responsible for setting up the necessary context and information before invoking an accessor or interceptor callback. They deal with side-effect checks and creating `PropertyCallbackInfo`.

**5. Understanding Functionality through Method Names and Code:**

Methods like `CallOrConstruct`, `GetBooleanReturnValue`, `CallNamedEnumerator`, `CallNamedQuery`, `CallNamedGetter`, `CallNamedSetter`, `CallIndexedGetter`, `CallAccessorGetter`, `CallAccessorSetter`, etc., provide direct insight into the file's functionality. They clearly relate to invoking different types of callbacks (function, property accessors, interceptors) with various operations (get, set, query, delete, enumerate). The names are very descriptive.

**6. Connecting to JavaScript:**

The key here is to recognize the connection between the C++ code and JavaScript concepts. Property getters/setters, function calls, and interceptors are all fundamental JavaScript features. The C++ code provides the underlying mechanisms for implementing these features within the V8 engine.

**7. Considering Edge Cases and Errors:**

The code includes `DCHECK` statements and mentions potential errors like "Unexpected side effect detected."  The `GetBooleanReturnValue` method's comments about Node.js and potential exceptions indicate awareness of real-world issues. This prompts the inclusion of common programming errors in the explanation.

**8. Structuring the Answer:**

Finally, the information needs to be organized according to the prompt's requirements:

* **Functionality:**  Start with a high-level summary and then break down the key responsibilities related to callback argument handling, property access, interceptors, and function calls.
* **Torque:** Explicitly state that the file is C++ and not Torque due to the `.h` extension.
* **JavaScript Examples:** Provide concrete JavaScript examples that demonstrate the concepts handled by the C++ code (getters/setters, function calls, interceptors). Keep the examples simple and focused.
* **Code Logic and Assumptions:** Choose a specific function (like `GetReturnValue`) and illustrate its behavior with hypothetical input and output. Explain the assumptions made.
* **Common Programming Errors:**  Focus on errors related to callback behavior, such as not returning a value, throwing exceptions incorrectly in interceptors, or causing unexpected side effects. Provide brief, clear examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file is *only* about property callbacks. **Correction:**  The presence of `FunctionCallbackArguments` broadens the scope.
* **Initial thought:** The macros are just for convenience. **Refinement:**  They play a crucial role in setting up the callback environment, including side-effect checks.
* **Initial thought:**  Just list the methods. **Refinement:**  Group related methods and explain their purpose in the context of JavaScript features.
* **Initial thought:** The JavaScript examples should be very complex. **Refinement:** Keep the examples simple and focused on the core concepts illustrated by the C++ code.

By following this structured analysis and iterative refinement process, one can effectively understand the functionality of a complex C++ header file like the one provided and address all aspects of the prompt.
This C++ header file, `v8/src/api/api-arguments-inl.h`, defines inline functions and templates related to handling arguments passed to and from V8's C++ API, particularly in the context of callbacks from JavaScript to C++.

Here's a breakdown of its functionality:

**1. Core Purpose: Managing Arguments for V8 API Callbacks**

The primary function of this file is to provide efficient ways to access and manipulate arguments within various callback scenarios in the V8 JavaScript engine. These callbacks are the mechanism through which JavaScript code can interact with native C++ code.

**2. Key Classes and Templates:**

* **`CustomArgumentsBase`:** A base class for custom argument handling, providing a foundation for more specific argument types.
* **`CustomArguments<T>`:** A template class inheriting from `Relocatable`, designed to hold and manage arguments. It includes functionality to get the return value of a callback.
* **`PropertyCallbackArguments`:**  Specifically designed for callbacks related to property access (getters, setters, etc.). It provides methods to access the holder object, the receiver object, and the property name/index.
* **`FunctionCallbackArguments`:**  Used for callbacks associated with function calls. It offers methods to call or construct JavaScript functions from within the callback.

**3. Accessing Callback Information:**

The file provides inline functions like `holder()` and `receiver()` within `PropertyCallbackArguments` and `FunctionCallbackArguments` to efficiently retrieve commonly needed information during callback execution.

**4. Handling Return Values:**

The `GetReturnValue` method in `CustomArguments` is crucial for retrieving the value returned by a JavaScript callback function back to the C++ side.

**5. Interceptor and Accessor Callback Handling:**

The code contains functions for calling various types of interceptor and accessor callbacks:
    * **Named Interceptors:** `CallNamedEnumerator`, `CallNamedQuery`, `CallNamedGetter`, `CallNamedSetter`, `CallNamedDefiner`, `CallNamedDeleter`. These handle property access based on string names.
    * **Indexed Interceptors:** `CallIndexedEnumerator`, `CallIndexedQuery`, `CallIndexedGetter`, `CallIndexedSetter`, `CallIndexedDefiner`, `CallIndexedDeleter`. These handle property access based on numeric indices.
    * **Accessors:** `CallAccessorGetter`, `CallAccessorSetter`. These handle calls to getter and setter functions defined on JavaScript objects.

**6. Macros for Callback Setup:**

Macros like `PREPARE_CALLBACK_INFO_ACCESSOR` and `PREPARE_CALLBACK_INFO_INTERCEPTOR` are used to streamline the setup process before invoking a callback. This includes checking for side effects in debug mode and creating the necessary `callback_info` object.

**7. Side Effect Checks:**

The code incorporates checks for side effects, particularly in debug builds. This helps ensure that callbacks behave as expected and don't inadvertently modify the state in unexpected ways.

**If `v8/src/api/api-arguments-inl.h` had a `.tq` extension:**

If the file ended with `.tq`, it would indeed be a **V8 Torque source file**. Torque is a domain-specific language used within V8 for implementing runtime functions and built-in objects in a more type-safe and performant way compared to directly writing C++.

**Relationship to JavaScript and Examples:**

This file is directly related to how JavaScript interacts with native code. The callbacks defined and managed here are the bridge between the two worlds.

**Example 1: Property Getter Callback**

```javascript
// JavaScript
let myObject = {
  get myProperty() {
    console.log("Getter called!");
    return "Hello from getter";
  }
};

console.log(myObject.myProperty); // Triggers the getter callback
```

On the C++ side, the `CallAccessorGetter` function in `api-arguments-inl.h` would be involved when the JavaScript engine needs to execute the `get myProperty()` code. It would set up the necessary context and call the corresponding C++ function associated with this getter.

**Example 2: Function Callback**

```javascript
// JavaScript
function myFunction(arg1, arg2) {
  console.log("Function called with:", arg1, arg2);
  return arg1 + arg2;
}

// Assume this function is registered as a callback in V8
```

When `myFunction` is called from C++, the `FunctionCallbackArguments` class would be used to access the arguments `arg1` and `arg2`. The `CallOrConstruct` method would be used if the callback needs to invoke another JavaScript function or constructor.

**Code Logic and Assumptions:**

Let's consider the `GetReturnValue` function:

```c++
template <typename T>
template <typename V>
Handle<V> CustomArguments<T>::GetReturnValue(Isolate* isolate) const {
  // Check the ReturnValue.
  FullObjectSlot slot = slot_at(kReturnValueIndex);
  DCHECK(Is<JSAny>(*slot));
  return Cast<V>(Handle<Object>(slot.location()));
}
```

**Assumptions:**

* **Input:** The `CustomArguments` object has been used in a callback context where a JavaScript function has returned a value.
* **Internal State:** The `kReturnValueIndex` slot within the `CustomArguments` object holds the returned JavaScript value.
* **Type Safety:** The caller of `GetReturnValue` knows the expected return type (`V`).

**Logic:**

1. **Access Return Value Slot:** It retrieves the memory slot (`FullObjectSlot`) where the return value is stored.
2. **Assertion:** It uses `DCHECK` to assert that the value in the slot is a valid JavaScript value (`JSAny`). This is a debug-time check.
3. **Casting:** It casts the raw memory location of the return value to a `Handle<V>`, which is V8's way of managing JavaScript objects in C++. The `Cast<V>` performs a type check (in debug builds) to ensure the returned value is of the expected type.
4. **Output:** It returns a `Handle<V>` representing the JavaScript return value.

**Example: Assume a JavaScript function returns a number `42`.**

* **Input:** A `CustomArguments` object associated with that function call.
* **Internal State:** The `kReturnValueIndex` slot holds the Smi (small integer representation) for `42`.
* **Call:** `GetReturnValue<Integer>(isolate)` is called.
* **Output:** A `Handle<Integer>` pointing to the Smi representing `42`.

**Common Programming Errors:**

1. **Incorrect Return Value Handling in Callbacks:**
   * **JavaScript Side:** Forgetting to return a value from a JavaScript function that's used as a callback. This can lead to `undefined` being returned unexpectedly on the C++ side.
   ```javascript
   // JavaScript - potential error
   function myCallback() {
     console.log("Callback executed");
     // No explicit return statement
   }
   ```
   * **C++ Side:** Not checking for `undefined` or the expected type of the return value when retrieving it using `GetReturnValue`.

2. **Type Mismatches in Callbacks:**
   * **JavaScript Side:** Returning a value of a different type than what the C++ code expects.
   ```javascript
   // JavaScript - potential error (expecting a number, returning a string)
   function myCallback() {
     return "This is not a number";
   }
   ```
   * **C++ Side:** Using the wrong template parameter with `GetReturnValue` (e.g., expecting an `Integer` but the JavaScript function returns a `String`). This might not cause a crash in release builds but can lead to unexpected behavior or errors later.

3. **Side Effects in Unexpected Places (Especially in Interceptors):**
   * Interceptor callbacks (like `CallNamedGetter`) are often expected to be relatively lightweight and not cause significant side effects. If they do, it can violate assumptions within the V8 engine and lead to inconsistencies or crashes. The `PREPARE_CALLBACK_INFO_INTERCEPTOR` macro includes checks for this in debug mode.

4. **Incorrect Use of `PropertyCallbackInfo`:**
   *  Forgetting to set the return value using the `PropertyCallbackInfo` object within a property accessor or interceptor callback. This can lead to the default value being returned instead of the intended one.

In summary, `v8/src/api/api-arguments-inl.h` plays a vital role in the efficient and correct handling of arguments and return values when JavaScript code interacts with native C++ code through V8's API callbacks. It provides the foundational structures and mechanisms for this crucial interaction.

Prompt: 
```
这是目录为v8/src/api/api-arguments-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api-arguments-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_API_API_ARGUMENTS_INL_H_
#define V8_API_API_ARGUMENTS_INL_H_

#include "src/api/api-arguments.h"
#include "src/api/api-inl.h"
#include "src/debug/debug.h"
#include "src/execution/vm-state-inl.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/instance-type.h"
#include "src/objects/slots-inl.h"

namespace v8 {
namespace internal {

CustomArgumentsBase::CustomArgumentsBase(Isolate* isolate)
    : Relocatable(isolate) {}

template <typename T>
CustomArguments<T>::~CustomArguments() {
  slot_at(kReturnValueIndex).store(Tagged<Object>(kHandleZapValue));
}

template <typename T>
template <typename V>
Handle<V> CustomArguments<T>::GetReturnValue(Isolate* isolate) const {
  // Check the ReturnValue.
  FullObjectSlot slot = slot_at(kReturnValueIndex);
  DCHECK(Is<JSAny>(*slot));
  return Cast<V>(Handle<Object>(slot.location()));
}

inline Tagged<JSObject> PropertyCallbackArguments::holder() const {
  return Cast<JSObject>(*slot_at(T::kHolderIndex));
}

inline Tagged<Object> PropertyCallbackArguments::receiver() const {
  return *slot_at(T::kThisIndex);
}

inline Tagged<JSReceiver> FunctionCallbackArguments::holder() const {
  return Cast<JSReceiver>(*slot_at(T::kHolderIndex));
}

#define DCHECK_NAME_COMPATIBLE(interceptor, name) \
  DCHECK(interceptor->is_named());                \
  DCHECK(!name->IsPrivate());                     \
  DCHECK_IMPLIES(IsSymbol(*name), interceptor->can_intercept_symbols());

#define PREPARE_CALLBACK_INFO_ACCESSOR(ISOLATE, F, API_RETURN_TYPE,            \
                                       ACCESSOR_INFO, RECEIVER, ACCESSOR_KIND, \
                                       EXCEPTION_CONTEXT)                      \
  if (ISOLATE->should_check_side_effects() &&                                  \
      !ISOLATE->debug()->PerformSideEffectCheckForAccessor(                    \
          ACCESSOR_INFO, RECEIVER, ACCESSOR_KIND)) {                           \
    return {};                                                                 \
  }                                                                            \
  const PropertyCallbackInfo<API_RETURN_TYPE>& callback_info =                 \
      GetPropertyCallbackInfo<API_RETURN_TYPE>();                              \
  ExternalCallbackScope call_scope(ISOLATE, FUNCTION_ADDR(F),                  \
                                   EXCEPTION_CONTEXT, &callback_info);

#define PREPARE_CALLBACK_INFO_INTERCEPTOR(ISOLATE, F, API_RETURN_TYPE,         \
                                          INTERCEPTOR_INFO, EXCEPTION_CONTEXT) \
  if (ISOLATE->should_check_side_effects() &&                                  \
      !ISOLATE->debug()->PerformSideEffectCheckForInterceptor(                 \
          INTERCEPTOR_INFO)) {                                                 \
    return {};                                                                 \
  }                                                                            \
  const PropertyCallbackInfo<API_RETURN_TYPE>& callback_info =                 \
      GetPropertyCallbackInfo<API_RETURN_TYPE>();                              \
  ExternalCallbackScope call_scope(ISOLATE, FUNCTION_ADDR(F),                  \
                                   EXCEPTION_CONTEXT, &callback_info);

Handle<Object> FunctionCallbackArguments::CallOrConstruct(
    Tagged<FunctionTemplateInfo> function, bool is_construct) {
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kFunctionCallback);
  v8::FunctionCallback f =
      reinterpret_cast<v8::FunctionCallback>(function->callback(isolate));
  if (isolate->should_check_side_effects() &&
      !isolate->debug()->PerformSideEffectCheckForCallback(
          handle(function, isolate))) {
    return {};
  }
  FunctionCallbackInfo<v8::Value> info(values_, argv_, argc_);
  ExternalCallbackScope call_scope(isolate, FUNCTION_ADDR(f),
                                   is_construct ? ExceptionContext::kConstructor
                                                : ExceptionContext::kOperation,
                                   &info);
  f(info);
  return GetReturnValue<Object>(isolate);
}

PropertyCallbackArguments::~PropertyCallbackArguments(){
#ifdef DEBUG
// TODO(chromium:1310062): enable this check.
// if (javascript_execution_counter_) {
//   CHECK_WITH_MSG(javascript_execution_counter_ ==
//                      isolate()->javascript_execution_counter(),
//                  "Unexpected side effect detected");
// }
#endif  // DEBUG
}

Maybe<InterceptorResult> PropertyCallbackArguments::GetBooleanReturnValue(
    v8::Intercepted intercepted, const char* callback_kind_for_error_message,
    bool ignore_return_value) {
  Isolate* isolate = this->isolate();
  if (isolate->has_exception()) {
    // TODO(ishell, 328490288): fix Node.js which has Setter/Definer
    // interceptor callbacks not returning v8::Intercepted::kYes on exceptions.
    if ((false) && DEBUG_BOOL && (intercepted == v8::Intercepted::kNo)) {
      FATAL(
          "Check failed: %s interceptor callback has thrown an "
          "exception but hasn't returned v8::Intercepted::kYes.",
          callback_kind_for_error_message);
    }
    return Nothing<InterceptorResult>();
  }

  if (intercepted == v8::Intercepted::kNo) {
    // Not intercepted, there must be no side effects including exceptions.
    DCHECK(!isolate->has_exception());
    return Just(InterceptorResult::kNotIntercepted);
  }
  DCHECK_EQ(intercepted, v8::Intercepted::kYes);
  AcceptSideEffects();

  if (ignore_return_value) return Just(InterceptorResult::kTrue);

  bool result = IsTrue(*GetReturnValue<Boolean>(isolate), isolate);

  // TODO(ishell, 348688196): ensure callbacks comply with this and
  // enable the check.
  if ((false) && DEBUG_BOOL && !result && ShouldThrowOnError()) {
    FATAL(
        "Check failed: %s interceptor callback hasn't thrown an "
        "exception on failure as requested.",
        callback_kind_for_error_message);
  }
  return Just(result ? InterceptorResult::kTrue : InterceptorResult::kFalse);
}

// -------------------------------------------------------------------------
// Named Interceptor callbacks.

Handle<JSObjectOrUndefined> PropertyCallbackArguments::CallNamedEnumerator(
    Handle<InterceptorInfo> interceptor) {
  DCHECK(interceptor->is_named());
  RCS_SCOPE(isolate(), RuntimeCallCounterId::kNamedEnumeratorCallback);
  return CallPropertyEnumerator(interceptor);
}

// TODO(ishell): return std::optional<PropertyAttributes>.
Handle<Object> PropertyCallbackArguments::CallNamedQuery(
    Handle<InterceptorInfo> interceptor, Handle<Name> name) {
  DCHECK_NAME_COMPATIBLE(interceptor, name);
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kNamedQueryCallback);
  slot_at(kPropertyKeyIndex).store(*name);
  slot_at(kReturnValueIndex).store(Smi::FromInt(v8::None));
  NamedPropertyQueryCallback f =
      ToCData<NamedPropertyQueryCallback, kApiNamedPropertyQueryCallbackTag>(
          isolate, interceptor->query());
  PREPARE_CALLBACK_INFO_INTERCEPTOR(isolate, f, v8::Integer, interceptor,
                                    ExceptionContext::kNamedQuery);
  v8::Intercepted intercepted = f(v8::Utils::ToLocal(name), callback_info);
  if (intercepted == v8::Intercepted::kNo) return {};
  return GetReturnValue<Object>(isolate);
}

Handle<JSAny> PropertyCallbackArguments::CallNamedGetter(
    Handle<InterceptorInfo> interceptor, Handle<Name> name) {
  DCHECK_NAME_COMPATIBLE(interceptor, name);
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kNamedGetterCallback);
  slot_at(kPropertyKeyIndex).store(*name);
  slot_at(kReturnValueIndex).store(ReadOnlyRoots(isolate).undefined_value());
  NamedPropertyGetterCallback f =
      ToCData<NamedPropertyGetterCallback, kApiNamedPropertyGetterCallbackTag>(
          isolate, interceptor->getter());
  PREPARE_CALLBACK_INFO_INTERCEPTOR(isolate, f, v8::Value, interceptor,
                                    ExceptionContext::kNamedGetter);
  v8::Intercepted intercepted = f(v8::Utils::ToLocal(name), callback_info);
  if (intercepted == v8::Intercepted::kNo) return {};
  return GetReturnValue<JSAny>(isolate);
}

Handle<JSAny> PropertyCallbackArguments::CallNamedDescriptor(
    Handle<InterceptorInfo> interceptor, Handle<Name> name) {
  DCHECK_NAME_COMPATIBLE(interceptor, name);
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kNamedDescriptorCallback);
  slot_at(kPropertyKeyIndex).store(*name);
  slot_at(kReturnValueIndex).store(ReadOnlyRoots(isolate).undefined_value());
  NamedPropertyDescriptorCallback f =
      ToCData<NamedPropertyDescriptorCallback,
              kApiNamedPropertyDescriptorCallbackTag>(
          isolate, interceptor->descriptor());
  PREPARE_CALLBACK_INFO_INTERCEPTOR(isolate, f, v8::Value, interceptor,
                                    ExceptionContext::kNamedDescriptor);
  v8::Intercepted intercepted = f(v8::Utils::ToLocal(name), callback_info);
  if (intercepted == v8::Intercepted::kNo) return {};
  return GetReturnValue<JSAny>(isolate);
}

v8::Intercepted PropertyCallbackArguments::CallNamedSetter(
    DirectHandle<InterceptorInfo> interceptor, Handle<Name> name,
    Handle<Object> value) {
  DCHECK_NAME_COMPATIBLE(interceptor, name);
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kNamedSetterCallback);
  slot_at(kPropertyKeyIndex).store(*name);
  slot_at(kReturnValueIndex).store(ReadOnlyRoots(isolate).true_value());
  NamedPropertySetterCallback f =
      ToCData<NamedPropertySetterCallback, kApiNamedPropertySetterCallbackTag>(
          isolate, interceptor->setter());
  Handle<InterceptorInfo> has_side_effects;
  PREPARE_CALLBACK_INFO_INTERCEPTOR(isolate, f, void, has_side_effects,
                                    ExceptionContext::kNamedSetter);
  v8::Intercepted intercepted =
      f(v8::Utils::ToLocal(name), v8::Utils::ToLocal(value), callback_info);
  return intercepted;
}

v8::Intercepted PropertyCallbackArguments::CallNamedDefiner(
    DirectHandle<InterceptorInfo> interceptor, Handle<Name> name,
    const v8::PropertyDescriptor& desc) {
  DCHECK_NAME_COMPATIBLE(interceptor, name);
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kNamedDefinerCallback);
  slot_at(kPropertyKeyIndex).store(*name);
  slot_at(kReturnValueIndex).store(ReadOnlyRoots(isolate).true_value());
  NamedPropertyDefinerCallback f = ToCData<NamedPropertyDefinerCallback,
                                           kApiNamedPropertyDefinerCallbackTag>(
      isolate, interceptor->definer());
  Handle<InterceptorInfo> has_side_effects;
  PREPARE_CALLBACK_INFO_INTERCEPTOR(isolate, f, void, has_side_effects,
                                    ExceptionContext::kNamedDefiner);
  v8::Intercepted intercepted =
      f(v8::Utils::ToLocal(name), desc, callback_info);
  return intercepted;
}

v8::Intercepted PropertyCallbackArguments::CallNamedDeleter(
    DirectHandle<InterceptorInfo> interceptor, Handle<Name> name) {
  DCHECK_NAME_COMPATIBLE(interceptor, name);
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kNamedDeleterCallback);
  slot_at(kPropertyKeyIndex).store(*name);
  slot_at(kReturnValueIndex).store(ReadOnlyRoots(isolate).true_value());
  NamedPropertyDeleterCallback f = ToCData<NamedPropertyDeleterCallback,
                                           kApiNamedPropertyDeleterCallbackTag>(
      isolate, interceptor->deleter());
  Handle<InterceptorInfo> has_side_effects;
  PREPARE_CALLBACK_INFO_INTERCEPTOR(isolate, f, v8::Boolean, has_side_effects,
                                    ExceptionContext::kNamedDeleter);
  v8::Intercepted intercepted = f(v8::Utils::ToLocal(name), callback_info);
  return intercepted;
}

// -------------------------------------------------------------------------
// Indexed Interceptor callbacks.

Handle<JSObjectOrUndefined> PropertyCallbackArguments::CallIndexedEnumerator(
    Handle<InterceptorInfo> interceptor) {
  DCHECK(!interceptor->is_named());
  RCS_SCOPE(isolate(), RuntimeCallCounterId::kIndexedEnumeratorCallback);
  return CallPropertyEnumerator(interceptor);
}

// TODO(ishell): return std::optional<PropertyAttributes>.
Handle<Object> PropertyCallbackArguments::CallIndexedQuery(
    Handle<InterceptorInfo> interceptor, uint32_t index) {
  DCHECK(!interceptor->is_named());
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kIndexedQueryCallback);
  index_ = index;
  slot_at(kPropertyKeyIndex).store(Smi::zero());  // indexed callback marker
  slot_at(kReturnValueIndex).store(Smi::FromInt(v8::None));
  IndexedPropertyQueryCallbackV2 f =
      ToCData<IndexedPropertyQueryCallbackV2,
              kApiIndexedPropertyQueryCallbackTag>(isolate,
                                                   interceptor->query());
  PREPARE_CALLBACK_INFO_INTERCEPTOR(isolate, f, v8::Integer, interceptor,
                                    ExceptionContext::kIndexedQuery);
  v8::Intercepted intercepted = f(index, callback_info);
  if (intercepted == v8::Intercepted::kNo) return {};
  return GetReturnValue<Object>(isolate);
}

Handle<JSAny> PropertyCallbackArguments::CallIndexedGetter(
    Handle<InterceptorInfo> interceptor, uint32_t index) {
  DCHECK(!interceptor->is_named());
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kNamedGetterCallback);
  index_ = index;
  slot_at(kPropertyKeyIndex).store(Smi::zero());  // indexed callback marker
  slot_at(kReturnValueIndex).store(ReadOnlyRoots(isolate).undefined_value());
  IndexedPropertyGetterCallbackV2 f =
      ToCData<IndexedPropertyGetterCallbackV2,
              kApiIndexedPropertyGetterCallbackTag>(isolate,
                                                    interceptor->getter());
  PREPARE_CALLBACK_INFO_INTERCEPTOR(isolate, f, v8::Value, interceptor,
                                    ExceptionContext::kIndexedGetter);
  v8::Intercepted intercepted = f(index, callback_info);
  if (intercepted == v8::Intercepted::kNo) return {};
  return GetReturnValue<JSAny>(isolate);
}

Handle<JSAny> PropertyCallbackArguments::CallIndexedDescriptor(
    Handle<InterceptorInfo> interceptor, uint32_t index) {
  DCHECK(!interceptor->is_named());
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kIndexedDescriptorCallback);
  index_ = index;
  slot_at(kPropertyKeyIndex).store(Smi::zero());  // indexed callback marker
  slot_at(kReturnValueIndex).store(ReadOnlyRoots(isolate).undefined_value());
  IndexedPropertyDescriptorCallbackV2 f =
      ToCData<IndexedPropertyDescriptorCallbackV2,
              kApiIndexedPropertyDescriptorCallbackTag>(
          isolate, interceptor->descriptor());
  PREPARE_CALLBACK_INFO_INTERCEPTOR(isolate, f, v8::Value, interceptor,
                                    ExceptionContext::kIndexedDescriptor);
  v8::Intercepted intercepted = f(index, callback_info);
  if (intercepted == v8::Intercepted::kNo) return {};
  return GetReturnValue<JSAny>(isolate);
}

v8::Intercepted PropertyCallbackArguments::CallIndexedSetter(
    DirectHandle<InterceptorInfo> interceptor, uint32_t index,
    Handle<Object> value) {
  DCHECK(!interceptor->is_named());
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kIndexedSetterCallback);
  index_ = index;
  slot_at(kPropertyKeyIndex).store(Smi::zero());  // indexed callback marker
  slot_at(kReturnValueIndex).store(ReadOnlyRoots(isolate).true_value());
  IndexedPropertySetterCallbackV2 f =
      ToCData<IndexedPropertySetterCallbackV2,
              kApiIndexedPropertySetterCallbackTag>(isolate,
                                                    interceptor->setter());
  Handle<InterceptorInfo> has_side_effects;
  PREPARE_CALLBACK_INFO_INTERCEPTOR(isolate, f, void, has_side_effects,
                                    ExceptionContext::kIndexedSetter);
  v8::Intercepted intercepted =
      f(index, v8::Utils::ToLocal(value), callback_info);
  return intercepted;
}

v8::Intercepted PropertyCallbackArguments::CallIndexedDefiner(
    DirectHandle<InterceptorInfo> interceptor, uint32_t index,
    const v8::PropertyDescriptor& desc) {
  DCHECK(!interceptor->is_named());
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kIndexedDefinerCallback);
  index_ = index;
  slot_at(kPropertyKeyIndex).store(Smi::zero());  // indexed callback marker
  slot_at(kReturnValueIndex).store(ReadOnlyRoots(isolate).true_value());
  IndexedPropertyDefinerCallbackV2 f =
      ToCData<IndexedPropertyDefinerCallbackV2,
              kApiIndexedPropertyDefinerCallbackTag>(isolate,
                                                     interceptor->definer());
  Handle<InterceptorInfo> has_side_effects;
  PREPARE_CALLBACK_INFO_INTERCEPTOR(isolate, f, void, has_side_effects,
                                    ExceptionContext::kIndexedDefiner);
  v8::Intercepted intercepted = f(index, desc, callback_info);
  return intercepted;
}

v8::Intercepted PropertyCallbackArguments::CallIndexedDeleter(
    Handle<InterceptorInfo> interceptor, uint32_t index) {
  DCHECK(!interceptor->is_named());
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kIndexedDeleterCallback);
  index_ = index;
  slot_at(kPropertyKeyIndex).store(Smi::zero());  // indexed callback marker
  slot_at(kReturnValueIndex).store(ReadOnlyRoots(isolate).true_value());
  IndexedPropertyDeleterCallbackV2 f =
      ToCData<IndexedPropertyDeleterCallbackV2,
              kApiIndexedPropertyDeleterCallbackTag>(isolate,
                                                     interceptor->deleter());
  PREPARE_CALLBACK_INFO_INTERCEPTOR(isolate, f, v8::Boolean, interceptor,
                                    ExceptionContext::kIndexedDeleter);
  v8::Intercepted intercepted = f(index, callback_info);
  return intercepted;
}

Handle<JSObjectOrUndefined> PropertyCallbackArguments::CallPropertyEnumerator(
    Handle<InterceptorInfo> interceptor) {
  // Named and indexed enumerator callbacks have same signatures.
  static_assert(std::is_same<NamedPropertyEnumeratorCallback,
                             IndexedPropertyEnumeratorCallback>::value);
  Isolate* isolate = this->isolate();
  slot_at(kPropertyKeyIndex).store(Smi::zero());  // not relevant
  // Enumerator callback's return value is initialized with undefined even
  // though it's supposed to return v8::Array.
  slot_at(kReturnValueIndex).store(ReadOnlyRoots(isolate).undefined_value());
  // TODO(ishell): consider making it return v8::Intercepted to indicate
  // whether the result was set or not.
  IndexedPropertyEnumeratorCallback f =
      v8::ToCData<IndexedPropertyEnumeratorCallback,
                  kApiIndexedPropertyEnumeratorCallbackTag>(
          isolate, interceptor->enumerator());
  PREPARE_CALLBACK_INFO_INTERCEPTOR(isolate, f, v8::Array, interceptor,
                                    ExceptionContext::kNamedEnumerator);
  f(callback_info);
  Handle<JSAny> result = GetReturnValue<JSAny>(isolate);
  DCHECK(IsUndefined(*result) || IsJSObject(*result));
  return Cast<JSObjectOrUndefined>(result);
}

// -------------------------------------------------------------------------
// Accessors

Handle<JSAny> PropertyCallbackArguments::CallAccessorGetter(
    DirectHandle<AccessorInfo> info, Handle<Name> name) {
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kAccessorGetterCallback);
  // Unlike interceptor callbacks we know that the property exists, so
  // the callback is allowed to have side effects.
  AcceptSideEffects();

  slot_at(kPropertyKeyIndex).store(*name);
  slot_at(kReturnValueIndex).store(ReadOnlyRoots(isolate).undefined_value());
  AccessorNameGetterCallback f =
      reinterpret_cast<AccessorNameGetterCallback>(info->getter(isolate));
  PREPARE_CALLBACK_INFO_ACCESSOR(isolate, f, v8::Value, info,
                                 handle(receiver(), isolate), ACCESSOR_GETTER,
                                 ExceptionContext::kAttributeGet);
  f(v8::Utils::ToLocal(name), callback_info);
  return GetReturnValue<JSAny>(isolate);
}

bool PropertyCallbackArguments::CallAccessorSetter(
    DirectHandle<AccessorInfo> accessor_info, Handle<Name> name,
    Handle<Object> value) {
  Isolate* isolate = this->isolate();
  RCS_SCOPE(isolate, RuntimeCallCounterId::kAccessorSetterCallback);
  // Unlike interceptor callbacks we know that the property exists, so
  // the callback is allowed to have side effects.
  AcceptSideEffects();

  slot_at(kPropertyKeyIndex).store(*name);
  slot_at(kReturnValueIndex).store(ReadOnlyRoots(isolate).true_value());
  // The actual type of setter callback is either
  // v8::AccessorNameSetterCallback or
  // i::Accesors::AccessorNameBooleanSetterCallback, depending on whether the
  // AccessorInfo was created by the API or internally (see accessors.cc).
  // Here we handle both cases using the AccessorNameSetterCallback signature
  // and checking whether the returned result is set to default value
  // (the undefined value).
  // TODO(ishell, 348660658): update V8 Api to allow setter callbacks provide
  // the result of [[Set]] operation according to JavaScript semantics.
  AccessorNameSetterCallback f = reinterpret_cast<AccessorNameSetterCallback>(
      accessor_info->setter(isolate));
  PREPARE_CALLBACK_INFO_ACCESSOR(isolate, f, void, accessor_info,
                                 handle(receiver(), isolate), ACCESSOR_SETTER,
                                 ExceptionContext::kAttributeSet);
  f(v8::Utils::ToLocal(name), v8::Utils::ToLocal(value), callback_info);
  // Historically, in case of v8::AccessorNameSetterCallback it wasn't allowed
  // to set the result and not setting the result was treated as successful
  // execution.
  // During interceptors Api refactoring it was temporarily allowed to call
  // v8::ReturnValue<void>::Set[NonEmpty](Local<S>) and the result was just
  // converted to v8::Boolean which was then treated as a result of [[Set]].
  // In case of AccessorNameBooleanSetterCallback, the result is always
  // set to v8::Boolean or an exception is be thrown (in which case the
  // result is ignored anyway). So, regardless of whether the signature was
  // v8::AccessorNameSetterCallback or AccessorNameBooleanSetterCallback
  // the result is guaranteed to be v8::Boolean value indicating success or
  // failure.
  DirectHandle<Boolean> result = GetReturnValue<Boolean>(isolate);
  return IsTrue(*result, isolate);
}

#undef PREPARE_CALLBACK_INFO_ACCESSOR
#undef PREPARE_CALLBACK_INFO_INTERCEPTOR

}  // namespace internal
}  // namespace v8

#endif  // V8_API_API_ARGUMENTS_INL_H_

"""

```