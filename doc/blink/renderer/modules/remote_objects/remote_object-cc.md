Response:
Let's break down the thought process for analyzing the `remote_object.cc` file and generating the response.

**1. Initial Understanding of the File's Purpose:**

The filename `remote_object.cc` and the namespace `blink::remote_objects` immediately suggest this code deals with communication or interaction with objects that are not directly within the current JavaScript environment. The "remote" aspect is key.

**2. Examining Key Includes and Namespaces:**

* `#include "third_party/blink/renderer/modules/remote_objects/remote_object.h"`: This is the header file for the current source file, confirming its core role.
* `#include "base/numerics/safe_conversions.h"`: Indicates a need for safe type conversions, suggesting potential data exchange.
* `#include "gin/converter.h"`:  "Gin" is a Chromium project for binding C++ objects to V8 JavaScript. This is a strong indicator that `RemoteObject` is exposed to JavaScript.
* `#include "third_party/blink/public/web/blink.h"`:  A general Blink header, less specific but shows it's part of the rendering engine.
* `#include "third_party/blink/renderer/platform/bindings/v8_binding.h"` and `#include "third_party/blink/renderer/platform/bindings/v8_private_property.h"`:  These confirm tight integration with the V8 JavaScript engine, including using private properties.
* `namespace blink { ... namespace { ... } ... namespace blink {`:  Standard C++ namespacing for organization. The anonymous namespace `{}` contains helper functions not meant for external use.

**3. Analyzing Core Class `RemoteObject`:**

* **Inheritance:** `gin::NamedPropertyInterceptor`. This is crucial. It means `RemoteObject` can dynamically handle property access in JavaScript. When JavaScript tries to access a property that isn't directly defined on the `RemoteObject` in C++, this interceptor gets called.
* **Members:**
    * `gateway_`:  A pointer to a `RemoteObjectGatewayImpl`. This strongly suggests a pattern where `RemoteObject` is managed by a central gateway.
    * `object_id_`: An integer ID. This is likely how the remote object is identified on the other side of the communication channel.
    * `object_`: A `mojo::Remote`. Mojo is Chromium's inter-process communication (IPC) system. `mojo::Remote` indicates an interface to communicate with a remote process or component. The type `mojom::blink::RemoteObject` further specifies the interface used.
* **Constructor and Destructor:** The constructor takes a `gateway` and `object_id`. The destructor releases the object through the gateway and potentially notifies the remote end.

**4. Examining Key Functions and Logic:**

* **`RemoteObjectInvokeCallback`:** This is a V8 callback function. Its signature (`const v8::FunctionCallbackInfo<v8::Value>& info`) is typical for functions called from JavaScript. It handles method calls on the `RemoteObject` from the JavaScript side. Key steps involve:
    * Checking for constructor calls (disallowed).
    * Extracting the method name.
    * Using a method cache to optimize repeated calls.
    * Converting JavaScript arguments to Mojo types (`JSValueToMojom`).
    * Invoking the method on the remote object via the Mojo interface.
    * Converting the Mojo result back to a JavaScript value (`MojomToJSValue`).
    * Handling errors.
* **`GetNamedProperty`:** This is the core of the `NamedPropertyInterceptor`. When JavaScript accesses a property on a `RemoteObject`, this function is called.
    * It checks the method cache.
    * If not found, it queries the remote object using `object_->HasMethod`.
    * If the method exists remotely, it creates a JavaScript function (`RemoteObjectInvokeCallback`) dynamically and caches it.
* **`EnumerateNamedProperties`:**  Handles `Object.keys()` or `for...in` style iteration over the properties of the `RemoteObject`. It fetches the method names from the remote object.
* **`JSValueToMojom`:**  This crucial function converts various JavaScript values (numbers, booleans, strings, arrays, typed arrays, other `RemoteObject`s) into Mojo data structures that can be sent over the IPC channel. It handles different JavaScript types and has logic to prevent infinite recursion for nested objects/arrays.
* **`MojomToJSValue`:**  The reverse of `JSValueToMojom`, converting Mojo results back to JavaScript values.

**5. Identifying Relationships with JavaScript, HTML, and CSS:**

The presence of `gin::Converter` and the V8 callback functions clearly links this code to JavaScript. The functionality allows JavaScript to interact with remote objects, which can represent underlying browser functionalities or even objects in other processes.

While the code itself doesn't directly manipulate HTML or CSS, the *purpose* of these remote objects often relates to them. For example, a remote object could represent a DOM element in another process, and JavaScript could call methods on that remote object to modify its properties (which could include styles).

**6. Inferring User and Programming Errors:**

The error messages defined at the beginning of the file (`kMethodInvocationAsConstructorDisallowed`, etc.) directly point to common usage errors. The `JSValueToMojom` function's complexity suggests potential issues with unsupported or incorrectly converted data types.

**7. Constructing the Debugging Scenario:**

To illustrate how a user action might lead to this code, a simple scenario involving a WebView and JavaScript interaction with a remotely implemented feature is a good starting point.

**8. Refining and Structuring the Response:**

Finally, the information is organized into clear sections (Functionality, Relationships, Logical Reasoning, Common Errors, Debugging) with bullet points and examples for better readability and understanding. The language is kept concise and focuses on the key aspects of the code. The initial assumptions based on naming conventions are validated by the code itself.
这个文件 `blink/renderer/modules/remote_objects/remote_object.cc` 是 Chromium Blink 渲染引擎中 `RemoteObject` 类的实现。 `RemoteObject` 的主要功能是**允许 JavaScript 代码与在浏览器进程（或可能的其他进程）中运行的 Java (或其他语言) 对象进行交互**。 这是一种桥接机制，使得 Web 内容能够调用原生功能。

以下是该文件的功能列表以及与 JavaScript、HTML、CSS 的关系说明：

**功能列表:**

1. **创建和管理 JavaScript 中可访问的远程对象代理:**  `RemoteObject` 类充当了在 JavaScript 环境中表示远程（非 JavaScript）对象的代理。当 JavaScript 代码获取到一个远程对象时，实际上获取的是一个 `RemoteObject` 的实例。

2. **方法调用桥接:**  核心功能是允许 JavaScript 调用远程对象的方法。当 JavaScript 代码在一个 `RemoteObject` 实例上调用方法时，这个文件中的代码负责将方法名和参数序列化并通过 IPC（进程间通信）发送到拥有实际对象的进程。

3. **方法调用结果返回:**  接收来自远程进程的方法调用结果，并将结果转换回 JavaScript 可以理解的值。

4. **属性访问桥接 (通过方法模拟):**  虽然代码中没有直接处理属性的 get/set，但通过 `NamedPropertyInterceptor` 接口，它拦截 JavaScript 对 `RemoteObject` 实例的属性访问。如果访问的“属性”实际上是远程对象的一个方法，它会动态地创建一个 JavaScript 函数来调用该方法。

5. **方法缓存:**  为了优化性能，它会缓存已经调用过的远程方法，避免每次都通过 IPC 查询方法是否存在。

6. **类型转换:**  提供 JavaScript 值到 Mojo 数据类型（用于 IPC）以及 Mojo 数据类型到 JavaScript 值的相互转换。这包括数字、布尔值、字符串、null、undefined、数组、TypedArray 以及其他的 `RemoteObject` 实例。

7. **错误处理:**  处理远程方法调用过程中可能发生的错误，并将错误信息抛给 JavaScript。

**与 JavaScript, HTML, CSS 的关系说明:**

*   **JavaScript:**  `RemoteObject` 的主要目标就是服务于 JavaScript。它使得 JavaScript 能够突破自身的沙箱限制，调用浏览器或底层系统的功能。
    *   **举例:** 假设 Java 端有一个名为 `DeviceInfo` 的类，它有一个方法 `getBatteryLevel()`。通过 `RemoteObject` 机制，JavaScript 可以获取到 `DeviceInfo` 的远程代理，并在其上调用 `getBatteryLevel()` 方法，获取电池电量信息。
    *   **假设输入与输出:**
        *   **假设输入 (JavaScript):**  `remoteDeviceInfo.getBatteryLevel();`  其中 `remoteDeviceInfo` 是一个 `RemoteObject` 实例。
        *   **假设输出 (JavaScript):**  一个表示电池电量的数字，例如 `0.85`。
*   **HTML:**  `RemoteObject` 本身不直接操作 HTML 结构或元素。但是，通过它桥接的 Java 代码可以访问和操作渲染树，从而影响 HTML 的呈现。
    *   **举例:**  一个 Java 方法可能返回当前页面中某个特定元素的属性值。JavaScript 通过 `RemoteObject` 调用这个方法，从而间接地获取 HTML 信息。
*   **CSS:**  类似于 HTML，`RemoteObject` 不直接操作 CSS 样式。然而，远程的 Java 代码可以获取和修改元素的样式信息，而 JavaScript 可以通过 `RemoteObject` 调用这些方法来间接地影响 CSS 的应用。
    *   **举例:**  一个 Java 方法可以获取某个元素当前应用的背景颜色。JavaScript 可以通过 `RemoteObject` 调用该方法来获取这个 CSS 属性值。

**逻辑推理与假设输入输出:**

*   **场景:** JavaScript 调用远程对象的 `calculateSum` 方法，该方法接收两个数字参数并返回它们的和。
    *   **假设输入 (JavaScript):**  `remoteCalculator.calculateSum(5, 10);`  其中 `remoteCalculator` 是一个 `RemoteObject` 实例。
    *   **逻辑推理:**
        1. JavaScript 调用 `calculateSum` 方法。
        2. `RemoteObjectInvokeCallback` 被调用。
        3. 参数 `5` 和 `10` 被 `JSValueToMojom` 转换为 Mojo 的数字类型。
        4. 方法名 "calculateSum" 和转换后的参数通过 IPC 发送到拥有实际 `calculateSum` 方法的进程。
        5. 远程进程执行 `calculateSum(5, 10)`，得到结果 `15`。
        6. 结果 `15` 被转换成 Mojo 的数字类型并通过 IPC 返回。
        7. `MojomToJSValue` 将 Mojo 的数字类型转换回 JavaScript 的数字类型。
        8. JavaScript 接收到返回结果 `15`。
    *   **假设输出 (JavaScript):**  `15`

**用户或编程常见的使用错误:**

1. **尝试将远程方法作为构造函数调用:**  `kMethodInvocationAsConstructorDisallowed` 错误消息表明不允许使用 `new` 关键字调用远程对象的方法。这是因为远程方法通常不是 JavaScript 构造函数。
    *   **错误示例 (JavaScript):** `new remoteObject.someMethod();`
2. **调用不存在的远程方法:**  `kMethodInvocationNonexistentMethod` 错误消息表示尝试调用的方法在远程对象上不存在。这可能是因为拼写错误、远程对象没有实现该方法，或者远程接口发生了变化。
    *   **错误示例 (JavaScript):** `remoteObject.nonExistentMethod();`
3. **在非注入对象上调用远程方法:**  `kMethodInvocationOnNonInjectedObjectDisallowed` 错误消息意味着尝试在一个并非通过远程对象机制创建的对象上调用远程方法。这通常发生在错误的 `this` 上下文中使用远程方法时。
4. **参数类型不匹配:**  `RemoteInvocationError::NON_ASSIGNABLE_TYPES` 错误表明传递给远程方法的 JavaScript 参数类型与远程方法期望的参数类型不兼容。例如，远程方法期望一个字符串，但传递了一个数字。
    *   **错误示例 (JavaScript):**  如果远程方法 `processString` 期望一个字符串，但调用时传递了数字： `remoteObject.processString(123);`
5. **远程方法抛出异常:**  `RemoteInvocationError::EXCEPTION_THROWN` 表明远程方法执行过程中抛出了一个异常。这个异常会被传递回 JavaScript。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户操作触发 JavaScript 代码执行:** 用户在网页上进行交互，例如点击按钮、填写表单等，这些操作会触发相应的 JavaScript 代码执行。

2. **JavaScript 代码尝试访问或调用远程对象:**  JavaScript 代码中存在对一个 `RemoteObject` 实例的属性访问或方法调用。这个 `RemoteObject` 实例通常是通过某种方式 (例如，通过一个特定的 API 或事件) 从浏览器内核传递到 JavaScript 环境的。

3. **`GetNamedProperty` 或 `RemoteObjectInvokeCallback` 被调用:**
    *   如果 JavaScript 代码尝试访问 `remoteObject.someProperty`，并且 `someProperty` 实际上是远程对象的一个方法，那么 `GetNamedProperty` 会被调用，它会动态地创建一个 JavaScript 函数来代理远程方法调用。
    *   如果 JavaScript 代码尝试调用 `remoteObject.someMethod(args)`，那么之前创建的代理函数（或直接调用，如果已经缓存）会执行，最终调用到 `RemoteObjectInvokeCallback`。

4. **参数转换 (`JSValueToMojom`):**  `RemoteObjectInvokeCallback` 会将 JavaScript 传递的参数转换为 Mojo 数据类型，以便通过 IPC 发送。

5. **IPC 通信:**  方法名和转换后的参数通过 Mojo IPC 机制发送到拥有实际对象的浏览器进程（或其他进程）。

6. **远程方法执行:**  在浏览器进程中，实际的 Java (或其他语言) 对象接收到调用请求，并执行相应的方法。

7. **结果返回和转换 (`MojomToJSValue`):**  远程方法执行的结果被转换为 Mojo 数据类型，并通过 IPC 返回到渲染进程。渲染进程中的 `RemoteObjectInvokeCallback` 接收到结果，并使用 `MojomToJSValue` 将其转换回 JavaScript 可以理解的值。

8. **JavaScript 代码接收结果:**  JavaScript 代码最终接收到远程方法调用的结果。

**调试线索:**

*   **检查 JavaScript 代码:** 确认 JavaScript 代码中对 `RemoteObject` 的使用是否正确，包括方法名、参数类型和调用方式。
*   **查看开发者工具的 Console:**  如果发生错误，通常会在 Console 中打印相关的错误消息，例如上面列出的那些错误。
*   **使用断点调试 JavaScript:** 在 JavaScript 代码中设置断点，逐步执行，查看 `RemoteObject` 实例的值，以及方法调用时的参数。
*   **检查浏览器内核日志:**  如果需要更深入的调试，可能需要查看浏览器内核的日志，以了解 IPC 通信的细节以及远程方法执行过程中是否发生了错误。这通常涉及到 Chromium 的内部调试机制。
*   **检查远程对象实现:**  确认远程对象（例如 Java 类）的方法实现是否正确，是否按照预期工作，以及是否抛出了异常。

总而言之，`remote_object.cc` 是连接 JavaScript 世界和浏览器内核中原生功能的关键桥梁，它使得 Web 内容能够利用更强大的系统能力。

Prompt: 
```
这是目录为blink/renderer/modules/remote_objects/remote_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/remote_objects/remote_object.h"

#include <tuple>

#include "base/numerics/safe_conversions.h"
#include "gin/converter.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/bindings/v8_private_property.h"

namespace blink {

gin::WrapperInfo RemoteObject::kWrapperInfo = {gin::kEmbedderNativeGin};

namespace {

const char kMethodInvocationAsConstructorDisallowed[] =
    "Java bridge method can't be invoked as a constructor";
const char kMethodInvocationNonexistentMethod[] =
    "Java bridge method does not exist for this object";
const char kMethodInvocationOnNonInjectedObjectDisallowed[] =
    "Java bridge method can't be invoked on a non-injected object";
const char kMethodInvocationErrorMessage[] =
    "Java bridge method invocation error";

String RemoteInvocationErrorToString(
    mojom::blink::RemoteInvocationError value) {
  switch (value) {
    case mojom::blink::RemoteInvocationError::METHOD_NOT_FOUND:
      return "method not found";
    case mojom::blink::RemoteInvocationError::OBJECT_GET_CLASS_BLOCKED:
      return "invoking Object.getClass() is not permitted";
    case mojom::blink::RemoteInvocationError::EXCEPTION_THROWN:
      return "an exception was thrown";
    case mojom::blink::RemoteInvocationError::NON_ASSIGNABLE_TYPES:
      return "an incompatible object type passed to method parameter";
    default:
      return String::Format("unknown RemoteInvocationError value: %d",
                            static_cast<int>(value));
  }
}

v8::Local<v8::Object> GetMethodCache(v8::Isolate* isolate,
                                     v8::Local<v8::Object> object) {
  static const V8PrivateProperty::SymbolKey kMethodCacheKey;
  V8PrivateProperty::Symbol method_cache_symbol =
      V8PrivateProperty::GetSymbol(isolate, kMethodCacheKey);
  v8::Local<v8::Value> result;
  if (!method_cache_symbol.GetOrUndefined(object).ToLocal(&result))
    return v8::Local<v8::Object>();

  if (result->IsUndefined()) {
    result = v8::Object::New(isolate, v8::Null(isolate), nullptr, nullptr, 0);
    std::ignore = method_cache_symbol.Set(object, result);
  }

  DCHECK(result->IsObject());
  return result.As<v8::Object>();
}

mojom::blink::RemoteInvocationArgumentPtr JSValueToMojom(
    const v8::Local<v8::Value>& js_value,
    v8::Isolate* isolate) {
  if (js_value->IsNumber()) {
    return mojom::blink::RemoteInvocationArgument::NewNumberValue(
        js_value->NumberValue(isolate->GetCurrentContext()).ToChecked());
  }

  if (js_value->IsBoolean()) {
    return mojom::blink::RemoteInvocationArgument::NewBooleanValue(
        js_value->BooleanValue(isolate));
  }

  if (js_value->IsString()) {
    return mojom::blink::RemoteInvocationArgument::NewStringValue(
        ToCoreString(isolate, js_value.As<v8::String>()));
  }

  if (js_value->IsNull()) {
    return mojom::blink::RemoteInvocationArgument::NewSingletonValue(
        mojom::blink::SingletonJavaScriptValue::kNull);
  }

  if (js_value->IsUndefined()) {
    return mojom::blink::RemoteInvocationArgument::NewSingletonValue(
        mojom::blink::SingletonJavaScriptValue::kUndefined);
  }

  if (js_value->IsArray()) {
    auto array = js_value.As<v8::Array>();
    WTF::Vector<mojom::blink::RemoteInvocationArgumentPtr> nested_arguments;
    for (uint32_t i = 0; i < array->Length(); ++i) {
      v8::Local<v8::Value> element_v8;

      if (!array->Get(isolate->GetCurrentContext(), i).ToLocal(&element_v8))
        return nullptr;

      // The array length might change during iteration. Set the output array
      // elements to null for nonexistent input array elements.
      if (!array->HasRealIndexedProperty(isolate->GetCurrentContext(), i)
               .FromMaybe(false)) {
        nested_arguments.push_back(
            mojom::blink::RemoteInvocationArgument::NewSingletonValue(
                mojom::blink::SingletonJavaScriptValue::kNull));
      } else {
        mojom::blink::RemoteInvocationArgumentPtr nested_argument;

        // This code prevents infinite recursion on the sender side.
        // Null value is sent according to the Java-side conversion rules for
        // expected parameter types:
        // - multi-dimensional and object arrays are not allowed and are
        // converted to nulls;
        // - for primitive arrays, the null value will be converted to primitive
        // zero;
        // - for string arrays, the null value will be converted to a null
        // string. See RemoteObjectImpl.convertArgument() in
        // content/public/android/java/src/org/chromium/content/browser/remoteobjects/RemoteObjectImpl.java
        if (element_v8->IsObject()) {
          nested_argument =
              mojom::blink::RemoteInvocationArgument::NewSingletonValue(
                  mojom::blink::SingletonJavaScriptValue::kNull);
        } else {
          nested_argument = JSValueToMojom(element_v8, isolate);
        }

        if (!nested_argument)
          return nullptr;

        nested_arguments.push_back(std::move(nested_argument));
      }
    }

    return mojom::blink::RemoteInvocationArgument::NewArrayValue(
        std::move(nested_arguments));
  }

  if (js_value->IsTypedArray()) {
    auto typed_array = js_value.As<v8::TypedArray>();
    mojom::blink::RemoteArrayType array_type;
    if (typed_array->IsInt8Array()) {
      array_type = mojom::blink::RemoteArrayType::kInt8Array;
    } else if (typed_array->IsUint8Array() ||
               typed_array->IsUint8ClampedArray()) {
      array_type = mojom::blink::RemoteArrayType::kUint8Array;
    } else if (typed_array->IsInt16Array()) {
      array_type = mojom::blink::RemoteArrayType::kInt16Array;
    } else if (typed_array->IsUint16Array()) {
      array_type = mojom::blink::RemoteArrayType::kUint16Array;
    } else if (typed_array->IsInt32Array()) {
      array_type = mojom::blink::RemoteArrayType::kInt32Array;
    } else if (typed_array->IsUint32Array()) {
      array_type = mojom::blink::RemoteArrayType::kUint32Array;
    } else if (typed_array->IsFloat32Array()) {
      array_type = mojom::blink::RemoteArrayType::kFloat32Array;
    } else if (typed_array->IsFloat64Array()) {
      array_type = mojom::blink::RemoteArrayType::kFloat64Array;
    } else {
      return nullptr;
    }

    auto remote_typed_array = mojom::blink::RemoteTypedArray::New();
    mojo_base::BigBuffer buffer(typed_array->ByteLength());
    typed_array->CopyContents(buffer.data(), buffer.size());

    remote_typed_array->buffer = std::move(buffer);
    remote_typed_array->type = array_type;

    return mojom::blink::RemoteInvocationArgument::NewTypedArrayValue(
        std::move(remote_typed_array));
  }

  if (js_value->IsArrayBuffer() || js_value->IsArrayBufferView()) {
    // If ArrayBuffer or ArrayBufferView is not a TypedArray, we should treat it
    // as undefined.
    return mojom::blink::RemoteInvocationArgument::NewSingletonValue(
        mojom::blink::SingletonJavaScriptValue::kUndefined);
  }

  if (js_value->IsObject()) {
    v8::Local<v8::Object> object_val = js_value.As<v8::Object>();

    RemoteObject* remote_object = nullptr;
    if (gin::ConvertFromV8(isolate, object_val, &remote_object)) {
      return mojom::blink::RemoteInvocationArgument::NewObjectIdValue(
          remote_object->object_id());
    }

    v8::Local<v8::Value> length_value;
    v8::TryCatch try_catch(isolate);
    v8::MaybeLocal<v8::Value> maybe_length_value = object_val->Get(
        isolate->GetCurrentContext(), V8AtomicString(isolate, "length"));
    if (try_catch.HasCaught() || !maybe_length_value.ToLocal(&length_value)) {
      length_value = v8::Null(isolate);
      try_catch.Reset();
    }

    if (!length_value->IsNumber()) {
      return mojom::blink::RemoteInvocationArgument::NewSingletonValue(
          mojom::blink::SingletonJavaScriptValue::kUndefined);
    }

    double length = length_value.As<v8::Number>()->Value();
    if (length < 0 || length > std::numeric_limits<int32_t>::max()) {
      return mojom::blink::RemoteInvocationArgument::NewSingletonValue(
          mojom::blink::SingletonJavaScriptValue::kNull);
    }

    v8::Local<v8::Array> property_names;
    if (!object_val->GetOwnPropertyNames(isolate->GetCurrentContext())
             .ToLocal(&property_names)) {
      return mojom::blink::RemoteInvocationArgument::NewSingletonValue(
          mojom::blink::SingletonJavaScriptValue::kNull);
    }

    WTF::Vector<mojom::blink::RemoteInvocationArgumentPtr> nested_arguments(
        base::checked_cast<wtf_size_t>(length));
    for (uint32_t i = 0; i < property_names->Length(); ++i) {
      v8::Local<v8::Value> key;
      if (!property_names->Get(isolate->GetCurrentContext(), i).ToLocal(&key) ||
          key->IsString()) {
        try_catch.Reset();
        continue;
      }

      if (!key->IsNumber()) {
        NOTREACHED() << "Key \"" << *v8::String::Utf8Value(isolate, key)
                     << "\" is not a number";
      }

      uint32_t key_value;
      if (!key->Uint32Value(isolate->GetCurrentContext()).To(&key_value))
        continue;

      v8::Local<v8::Value> value_v8;
      v8::MaybeLocal<v8::Value> maybe_value =
          object_val->Get(isolate->GetCurrentContext(), key);
      if (try_catch.HasCaught() || !maybe_value.ToLocal(&value_v8)) {
        value_v8 = v8::Null(isolate);
        try_catch.Reset();
      }

      auto nested_argument = JSValueToMojom(value_v8, isolate);
      if (!nested_argument)
        continue;
      nested_arguments[key_value] = std::move(nested_argument);
    }

    // Ensure that the vector has a null value.
    for (wtf_size_t i = 0; i < nested_arguments.size(); i++) {
      if (!nested_arguments[i]) {
        nested_arguments[i] =
            mojom::blink::RemoteInvocationArgument::NewSingletonValue(
                mojom::blink::SingletonJavaScriptValue::kNull);
      }
    }

    return mojom::blink::RemoteInvocationArgument::NewArrayValue(
        std::move(nested_arguments));
  }

  return nullptr;
}

v8::Local<v8::Value> MojomToJSValue(
    const mojom::blink::RemoteInvocationResultValuePtr& result_value,
    v8::Isolate* isolate) {
  if (result_value->is_number_value()) {
    return v8::Number::New(isolate, result_value->get_number_value());
  }

  if (result_value->is_boolean_value()) {
    return v8::Boolean::New(isolate, result_value->get_boolean_value());
  }

  if (result_value->is_string_value()) {
    return V8String(isolate, result_value->get_string_value());
  }

  switch (result_value->get_singleton_value()) {
    case mojom::blink::SingletonJavaScriptValue::kNull:
      return v8::Null(isolate);
    case mojom::blink::SingletonJavaScriptValue::kUndefined:
      return v8::Undefined(isolate);
  }

  return v8::Local<v8::Value>();
}
}  // namespace

RemoteObject::RemoteObject(v8::Isolate* isolate,
                           RemoteObjectGatewayImpl* gateway,
                           int32_t object_id)
    : gin::NamedPropertyInterceptor(isolate, this),
      gateway_(gateway),
      object_id_(object_id) {}

RemoteObject::~RemoteObject() {
  if (gateway_) {
    gateway_->ReleaseObject(object_id_, this);

    if (object_)
      object_->NotifyReleasedObject();
  }
}

gin::ObjectTemplateBuilder RemoteObject::GetObjectTemplateBuilder(
    v8::Isolate* isolate) {
  return gin::Wrappable<RemoteObject>::GetObjectTemplateBuilder(isolate)
      .AddNamedPropertyInterceptor();
}

void RemoteObject::RemoteObjectInvokeCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  if (info.IsConstructCall()) {
    // This is not a constructor. Throw and return.
    isolate->ThrowException(v8::Exception::Error(
        V8String(isolate, kMethodInvocationAsConstructorDisallowed)));
    return;
  }

  RemoteObject* remote_object;
  if (!gin::ConvertFromV8(isolate, info.This(), &remote_object)) {
    // Someone messed with the |this| pointer. Throw and return.
    isolate->ThrowException(v8::Exception::Error(
        V8String(isolate, kMethodInvocationOnNonInjectedObjectDisallowed)));
    return;
  }

  String method_name = ToCoreString(isolate, info.Data().As<v8::String>());

  v8::Local<v8::Object> method_cache = GetMethodCache(
      isolate, remote_object->GetWrapper(isolate).ToLocalChecked());
  if (method_cache.IsEmpty())
    return;

  v8::Local<v8::Value> cached_method =
      method_cache
          ->Get(isolate->GetCurrentContext(), info.Data().As<v8::String>())
          .ToLocalChecked();

  if (cached_method->IsUndefined()) {
    isolate->ThrowException(v8::Exception::Error(
        V8String(isolate, kMethodInvocationNonexistentMethod)));
    return;
  }

  WTF::Vector<mojom::blink::RemoteInvocationArgumentPtr> arguments;
  arguments.ReserveInitialCapacity(info.Length());

  for (int i = 0; i < info.Length(); i++) {
    auto argument = JSValueToMojom(info[i], isolate);
    if (!argument)
      return;

    arguments.push_back(std::move(argument));
  }

  remote_object->EnsureRemoteIsBound();
  mojom::blink::RemoteInvocationResultPtr result;
  remote_object->object_->InvokeMethod(method_name, std::move(arguments),
                                       &result);

  if (result->error != mojom::blink::RemoteInvocationError::OK) {
    String message = String::Format("%s : ", kMethodInvocationErrorMessage) +
                     RemoteInvocationErrorToString(result->error);
    isolate->ThrowException(v8::Exception::Error(V8String(isolate, message)));
    return;
  }

  if (!result->value)
    return;

  if (result->value->is_object_id()) {
    RemoteObject* object_result = remote_object->gateway_->GetRemoteObject(
        info.GetIsolate(), result->value->get_object_id());
    gin::Handle<RemoteObject> controller =
        gin::CreateHandle(isolate, object_result);
    if (controller.IsEmpty())
      info.GetReturnValue().SetUndefined();
    else
      info.GetReturnValue().Set(controller.ToV8());
  } else {
    info.GetReturnValue().Set(MojomToJSValue(result->value, isolate));
  }
}

void RemoteObject::EnsureRemoteIsBound() {
  if (!object_.is_bound()) {
    gateway_->BindRemoteObjectReceiver(object_id_,
                                       object_.BindNewPipeAndPassReceiver());
  }
}

v8::Local<v8::Value> RemoteObject::GetNamedProperty(
    v8::Isolate* isolate,
    const std::string& property) {
  auto wtf_property = WTF::String::FromUTF8(property);

  v8::Local<v8::String> v8_property = V8AtomicString(isolate, wtf_property);
  v8::Local<v8::Object> method_cache =
      GetMethodCache(isolate, GetWrapper(isolate).ToLocalChecked());
  if (method_cache.IsEmpty())
    return v8::Local<v8::Value>();

  v8::Local<v8::Value> cached_method =
      method_cache->Get(isolate->GetCurrentContext(), v8_property)
          .ToLocalChecked();

  if (!cached_method->IsUndefined())
    return cached_method;

  // if not in the cache, ask the browser
  EnsureRemoteIsBound();
  bool method_exists = false;
  object_->HasMethod(wtf_property, &method_exists);

  if (!method_exists) {
    return v8::Local<v8::Value>();
  }

  auto function = v8::Function::New(isolate->GetCurrentContext(),
                                    RemoteObjectInvokeCallback, v8_property)
                      .ToLocalChecked();

  std::ignore = method_cache->CreateDataProperty(isolate->GetCurrentContext(),
                                                 v8_property, function);
  return function;
}

std::vector<std::string> RemoteObject::EnumerateNamedProperties(
    v8::Isolate* isolate) {
  EnsureRemoteIsBound();
  WTF::Vector<WTF::String> methods;
  object_->GetMethods(&methods);
  std::vector<std::string> result;
  for (const auto& method : methods)
    result.push_back(method.Utf8());
  return result;
}

}  // namespace blink

"""

```