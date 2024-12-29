Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the Chromium Blink engine. The file is `v8_binding_for_core.cc`.

I need to analyze the code and identify its main responsibilities. It seems to be related to the interaction between the V8 JavaScript engine and the core Blink rendering engine.

Here's a breakdown of the likely functionalities:

1. **Type Conversion:**  The code contains numerous functions (e.g., `ToInt8`, `ToUInt32Slow`, `ToFloat`, `ToDouble`) that handle the conversion of JavaScript values to C++ types.
2. **V8 Context Handling:** Functions like `ToLocalDOMWindow`, `ToExecutionContext`, `ToV8Context`, and `ToScriptState` manage the relationship between Blink's execution contexts (frames, workers) and V8's contexts and script states.
3. **String Manipulation:** Functions like `ReplaceUnmatchedSurrogates` deal with ensuring the validity of strings passed between JavaScript and C++.
4. **Iteration:** Functions like `GetEsIteratorMethod` and `HasCallableIteratorSymbol` seem to be related to handling JavaScript iterators in the C++ code.
5. **Error Handling:** The code uses `ExceptionState` to manage and propagate errors that occur during the interaction between JavaScript and C++.
6. **Object Property Access:** The `V8SetReturnValue` function and `GetOwnPropertyNames` suggest functionality related to getting and setting properties of JavaScript objects from C++.

I should also consider the relationship to HTML, CSS, and JavaScript:

* **JavaScript:** This file is fundamentally about bridging the gap between Blink's C++ codebase and JavaScript execution within V8. All the type conversion and context management directly relate to this.
* **HTML:** The `LocalDOMWindow` and `Element` classes mentioned in the includes and function names indicate a close relationship with the Document Object Model (DOM), which represents HTML structure.
* **CSS:** While not directly apparent in the function names, the ability to interact with DOM elements implies that this code could be indirectly involved in aspects of CSS, as CSS styles are applied to DOM elements.

Finally, I need to provide a concise summary for the "Part 1" request.
这个C++代码文件 `v8_binding_for_core.cc` 的主要功能是**提供了一系列用于在Chromium Blink引擎中连接 V8 JavaScript 引擎和核心渲染引擎的工具函数和类型转换方法。**  它充当了一个桥梁，使得C++代码能够安全、有效地与JavaScript代码进行交互。

以下是更详细的功能归纳：

1. **JavaScript值到C++类型的转换：**
    *   文件中定义了 `ToInt8`, `ToUInt8`, `ToInt16`, `ToUInt16`, `ToInt32Slow`, `ToUInt32Slow`, `ToInt64Slow`, `ToUInt64Slow`, `ToFloat`, `ToDouble`, `ToRestrictedFloat`, `ToRestrictedDouble` 等函数，用于将V8中的JavaScript值转换为C++中的各种数值类型 (int8_t, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t, uint64_t, float, double)。
    *   这些转换函数会处理各种情况，例如类型检查、范围限制（通过 `IntegerConversionConfiguration` 枚举控制）、错误处理（使用 `ExceptionState`）。

    **与JavaScript的关系举例：**
    *   **假设输入 (JavaScript):**  在JavaScript中调用一个C++绑定的函数，并传递一个数字 `10.5` 作为参数。
    *   **处理过程 (C++):**  C++绑定代码可能会使用 `ToInt32` 或 `ToDouble` 函数将JavaScript的 `10.5` 转换为C++中的 `int32_t` (结果为 `10`) 或 `double` (结果为 `10.5`)。

2. **V8上下文和Blink执行上下文的管理：**
    *   提供了 `ToLocalDOMWindow`, `ToExecutionContext`, `ToV8Context`, `ToScriptState` 等函数，用于在V8的上下文 (`v8::Context`)、Blink的执行上下文 (例如 `LocalDOMWindow`, `WorkerGlobalScope`) 和脚本状态 (`ScriptState`) 之间进行转换和访问。
    *   这些函数对于确定当前执行的JavaScript代码属于哪个Frame或Worker至关重要。

    **与HTML的关系举例：**
    *   当浏览器加载一个HTML页面时，会创建一个 `LocalDOMWindow` 对象来表示该页面的窗口。
    *   `ToLocalDOMWindow(v8::Local<v8::Context> context)` 函数可以将与该HTML页面关联的V8上下文转换为对应的 `LocalDOMWindow` 对象，从而允许C++代码访问和操作该页面的DOM。

3. **字符串处理：**
    *   `ReplaceUnmatchedSurrogates` 函数用于处理包含不成对的 surrogate 字符的字符串，将其替换为 Unicode 替换字符 (U+FFFD)，以确保字符串的有效性。

    **与HTML的关系举例：**
    *   HTML文档中的文本内容可能会包含格式错误的 Unicode 字符。当 JavaScript 代码尝试读取这些文本时，Blink 可能会使用 `ReplaceUnmatchedSurrogates` 来清理字符串，避免出现解析错误或安全问题。

4. **枚举值校验：**
    *   `IsValidEnum` 函数用于验证一个字符串值是否是某个预定义枚举类型的有效值。

    **与CSS的关系举例：**
    *   在处理CSS样式时，例如 `display` 属性，其值只能是预定义的几个关键字 (例如 "block", "inline", "flex")。C++ 代码可能会使用 `IsValidEnum` 来验证 JavaScript 设置的 `display` 值是否有效。
    *   **假设输入 (JavaScript):**  `element.style.display = "invalid-value";`
    *   **处理过程 (C++):**  当C++代码接收到要设置的 `display` 值时，会调用 `IsValidEnum` 并传入预定义的有效值列表。由于 "invalid-value" 不在列表中，`IsValidEnum` 将会返回 `false` 并抛出一个 `TypeError` 异常。

5. **JavaScript迭代器处理：**
    *   `GetEsIteratorMethod`, `GetEsIteratorWithMethod`, `HasCallableIteratorSymbol` 等函数用于获取和检查 JavaScript 对象的迭代器方法，这对于在 C++ 中遍历 JavaScript 可迭代对象非常有用。

    **与JavaScript的关系举例：**
    *   **假设输入 (JavaScript):**  一个 JavaScript `Set` 对象 `const mySet = new Set([1, 2, 3]);`
    *   **处理过程 (C++):**  C++ 代码可以使用 `GetEsIteratorMethod` 获取 `mySet` 对象的 `Symbol.iterator` 方法，然后使用该方法创建一个迭代器，并逐步访问 `Set` 中的元素。

6. **获取对象属性名：**
    *   `GetOwnPropertyNames` 函数用于获取 JavaScript 对象自身拥有的属性名。

    **与JavaScript的关系举例：**
    *   **假设输入 (JavaScript):**  一个 JavaScript 对象 `const obj = {a: 1, b: 2};`
    *   **处理过程 (C++):**  C++ 代码可以调用 `GetOwnPropertyNames` 获取 `obj` 的属性名，返回一个包含字符串 "a" 和 "b" 的列表。

7. **设置属性描述符：**
    *   `V8SetReturnValue` 函数用于创建一个包含属性描述符信息的 JavaScript 对象，例如 `configurable`, `enumerable`, `value`, `writable`, `get`, `set`。

    **与JavaScript的关系举例：**
    *   C++ 代码可能需要向 JavaScript 返回一个对象，该对象描述了另一个 JavaScript 对象的某个属性的特性，例如该属性是否可配置或可枚举。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中与网页进行交互：** 例如，用户点击了一个按钮、提交了一个表单、或者页面上的某个 JavaScript 代码正在执行。
2. **JavaScript 代码需要访问或操作底层浏览器功能：** 例如，JavaScript 代码想要修改一个 DOM 元素的属性，或者发起一个网络请求。
3. **JavaScript 调用了 C++ 绑定的接口：** Blink 引擎会将 JavaScript 的调用路由到相应的 C++ 代码。
4. **C++ 绑定代码需要将 JavaScript 的值转换为 C++ 类型：** 在这一步，`v8_binding_for_core.cc` 中定义的 `ToXXX` 函数会被调用，将 JavaScript 的参数转换为 C++ 函数可以理解的类型。
5. **如果涉及到上下文信息，例如访问特定 Frame 的 DOM：** `ToLocalDOMWindow`, `ToExecutionContext` 等函数会被使用，以确保操作的是正确的上下文。

**用户或编程常见的使用错误举例：**

*   **类型不匹配：**  JavaScript 代码传递了一个字符串给一个期望接收整数的 C++ 函数。由于 C++ 代码中使用了 `ToInt32` 等类型转换函数，并且配置了 `kEnforceRange` 或默认行为，这会导致一个类型错误异常 (TypeError) 在 JavaScript 中抛出。
    *   **假设输入 (JavaScript):**  C++ 绑定的函数期望一个数字，但 JavaScript 代码传递了字符串 `"abc"`.
    *   **错误:**  `ToInt32` 函数会尝试将 `"abc"` 转换为数字，但会失败，并抛出一个 `TypeError`。
*   **枚举值错误：** JavaScript 代码尝试将一个 CSS 属性设置为一个无效的值。
    *   **假设输入 (JavaScript):** `element.style.display = "wrong";`
    *   **错误:**  C++ 代码使用 `IsValidEnum` 检查 "wrong" 是否是 `display` 属性的有效值，结果为 `false`，会抛出一个 `TypeError`。
*   **在错误的上下文中操作：** 尝试在 Worker 线程中访问 DOM 对象，由于 Worker 线程没有关联的 DOMWindow，`ToLocalDOMWindow` 可能会返回空指针，导致后续的 C++ 代码崩溃或产生未定义的行为。

**这是第1部分，共2部分，请归纳一下它的功能：**

总而言之，`v8_binding_for_core.cc` 的主要功能是**在Chromium Blink引擎中，为C++代码安全可靠地操作和转换来自V8 JavaScript引擎的数据和上下文提供核心基础设施。** 它涵盖了 JavaScript 值到 C++ 类型的转换、V8 上下文与 Blink 执行上下文的管理、字符串处理以及枚举值校验等关键方面，是连接 JavaScript 和 Blink 核心功能的基石。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/v8_binding_for_core.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2017 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"

#include "base/debug/dump_without_crashing.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_state_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_element.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_event_target.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_html_link_element.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_script_runner.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_window.h"
#include "third_party/blink/renderer/bindings/core/v8/window_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/window_proxy_manager.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/shadow_realm/shadow_realm_global_scope.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/workers/worker_or_worklet_global_scope.h"
#include "third_party/blink/renderer/core/workers/worklet_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/runtime_call_stats.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding_macros.h"
#include "third_party/blink/renderer/platform/bindings/v8_object_constructor.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/traced_value.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"

namespace blink {

void V8SetReturnValue(const v8::PropertyCallbackInfo<v8::Value>& info,
                      const v8::PropertyDescriptor& descriptor) {
  DCHECK(descriptor.has_configurable());
  DCHECK(descriptor.has_enumerable());
  if (descriptor.has_value()) {
    // Data property
    DCHECK(descriptor.has_writable());
    info.GetReturnValue().Set(
        V8ObjectBuilder(ScriptState::ForCurrentRealm(info))
            .AddBoolean("configurable", descriptor.configurable())
            .AddBoolean("enumerable", descriptor.enumerable())
            .AddV8Value("value", descriptor.value())
            .AddBoolean("writable", descriptor.writable())
            .V8Value());
    return;
  }
  // Accessor property
  DCHECK(descriptor.has_get() || descriptor.has_set());
  info.GetReturnValue().Set(
      V8ObjectBuilder(ScriptState::ForCurrentRealm(info))
          .AddBoolean("configurable", descriptor.configurable())
          .AddBoolean("enumerable", descriptor.enumerable())
          .AddV8Value("get", descriptor.get())
          .AddV8Value("set", descriptor.set())
          .V8Value());
}

const int32_t kMaxInt32 = 0x7fffffff;
const int32_t kMinInt32 = -kMaxInt32 - 1;
const uint32_t kMaxUInt32 = 0xffffffff;
const int64_t kJSMaxInteger =
    0x20000000000000LL -
    1;  // 2^53 - 1, maximum uniquely representable integer in ECMAScript.

static double EnforceRange(double x,
                           double minimum,
                           double maximum,
                           const char* type_name,
                           ExceptionState& exception_state) {
  if (!std::isfinite(x)) {
    exception_state.ThrowTypeError(
        "Value is" + String(std::isinf(x) ? " infinite and" : "") +
        " not of type '" + String(type_name) + "'.");
    return 0;
  }
  x = trunc(x);
  if (x < minimum || x > maximum) {
    exception_state.ThrowTypeError("Value is outside the '" +
                                   String(type_name) + "' value range.");
    return 0;
  }
  return x;
}

template <typename T>
struct IntTypeNumberOfValues {
  static constexpr unsigned value =
      1 << (std::numeric_limits<T>::digits + std::is_signed<T>::value);
};

template <typename T>
struct IntTypeLimits {};

template <>
struct IntTypeLimits<int8_t> {
  static constexpr int8_t kMinValue = std::numeric_limits<int8_t>::min();
  static constexpr int8_t kMaxValue = std::numeric_limits<int8_t>::max();
  static constexpr unsigned kNumberOfValues =
      IntTypeNumberOfValues<int8_t>::value;  // 2^8
};

template <>
struct IntTypeLimits<uint8_t> {
  static constexpr uint8_t kMaxValue = std::numeric_limits<uint8_t>::max();
  static constexpr unsigned kNumberOfValues =
      IntTypeNumberOfValues<uint8_t>::value;  // 2^8
};

template <>
struct IntTypeLimits<int16_t> {
  static constexpr int16_t kMinValue = std::numeric_limits<int16_t>::min();
  static constexpr int16_t kMaxValue = std::numeric_limits<int16_t>::max();
  static constexpr unsigned kNumberOfValues =
      IntTypeNumberOfValues<int16_t>::value;  // 2^16
};

template <>
struct IntTypeLimits<uint16_t> {
  static constexpr uint16_t kMaxValue = std::numeric_limits<uint16_t>::max();
  static constexpr unsigned kNumberOfValues =
      IntTypeNumberOfValues<uint16_t>::value;  // 2^16
};

template <typename T>
static inline T ToSmallerInt(v8::Isolate* isolate,
                             v8::Local<v8::Value> value,
                             IntegerConversionConfiguration configuration,
                             const char* type_name,
                             ExceptionState& exception_state) {
  typedef IntTypeLimits<T> LimitsTrait;

  // Fast case. The value is already a 32-bit integer in the right range.
  if (value->IsInt32()) {
    int32_t result = value.As<v8::Int32>()->Value();
    if (result >= LimitsTrait::kMinValue && result <= LimitsTrait::kMaxValue)
      return static_cast<T>(result);
    if (configuration == kEnforceRange) {
      exception_state.ThrowTypeError("Value is outside the '" +
                                     String(type_name) + "' value range.");
      return 0;
    }
    if (configuration == kClamp)
      return ClampTo<T>(result);
    result %= LimitsTrait::kNumberOfValues;
    return static_cast<T>(result > LimitsTrait::kMaxValue
                              ? result - LimitsTrait::kNumberOfValues
                              : result);
  }

  v8::Local<v8::Number> number_object;
  if (value->IsNumber()) {
    number_object = value.As<v8::Number>();
  } else {
    // Can the value be converted to a number?
    TryRethrowScope rethrow_scope(isolate, exception_state);
    if (!value->ToNumber(isolate->GetCurrentContext())
             .ToLocal(&number_object)) {
      return 0;
    }
  }
  DCHECK(!number_object.IsEmpty());

  if (configuration == kEnforceRange) {
    return EnforceRange(number_object->Value(), LimitsTrait::kMinValue,
                        LimitsTrait::kMaxValue, type_name, exception_state);
  }

  double number_value = number_object->Value();
  if (std::isnan(number_value) || !number_value)
    return 0;

  if (configuration == kClamp)
    return ClampTo<T>(number_value);

  if (std::isinf(number_value))
    return 0;

  // Confine number to (-kNumberOfValues, kNumberOfValues).
  number_value =
      number_value < 0 ? -floor(fabs(number_value)) : floor(fabs(number_value));
  number_value = fmod(number_value, LimitsTrait::kNumberOfValues);

  // Adjust range to [-kMinValue, kMaxValue].
  if (number_value < LimitsTrait::kMinValue)
    number_value += LimitsTrait::kNumberOfValues;
  else if (LimitsTrait::kMaxValue < number_value)
    number_value -= LimitsTrait::kNumberOfValues;

  return static_cast<T>(number_value);
}

template <typename T>
static inline T ToSmallerUInt(v8::Isolate* isolate,
                              v8::Local<v8::Value> value,
                              IntegerConversionConfiguration configuration,
                              const char* type_name,
                              ExceptionState& exception_state) {
  typedef IntTypeLimits<T> LimitsTrait;

  // Fast case. The value is a 32-bit signed integer - possibly positive?
  if (value->IsInt32()) {
    int32_t result = value.As<v8::Int32>()->Value();
    if (result >= 0 && result <= LimitsTrait::kMaxValue)
      return static_cast<T>(result);
    if (configuration == kEnforceRange) {
      exception_state.ThrowTypeError("Value is outside the '" +
                                     String(type_name) + "' value range.");
      return 0;
    }
    if (configuration == kClamp)
      return ClampTo<T>(result);
    return static_cast<T>(result);
  }

  v8::Local<v8::Number> number_object;
  if (value->IsNumber()) {
    number_object = value.As<v8::Number>();
  } else {
    // Can the value be converted to a number?
    TryRethrowScope rethrow_scope(isolate, exception_state);
    if (!value->ToNumber(isolate->GetCurrentContext())
             .ToLocal(&number_object)) {
      return 0;
    }
  }
  DCHECK(!number_object.IsEmpty());

  if (configuration == kEnforceRange) {
    return EnforceRange(number_object->Value(), 0, LimitsTrait::kMaxValue,
                        type_name, exception_state);
  }

  double number_value = number_object->Value();

  if (std::isnan(number_value) || !number_value)
    return 0;

  if (configuration == kClamp)
    return ClampTo<T>(number_value);

  if (std::isinf(number_value))
    return 0;

  // Confine number to (-kNumberOfValues, kNumberOfValues).
  double number = fmod(trunc(number_value), LimitsTrait::kNumberOfValues);

  // Adjust range to [0, kNumberOfValues).
  if (number < 0)
    number += LimitsTrait::kNumberOfValues;

  return static_cast<T>(number);
}

int8_t ToInt8(v8::Isolate* isolate,
              v8::Local<v8::Value> value,
              IntegerConversionConfiguration configuration,
              ExceptionState& exception_state) {
  return ToSmallerInt<int8_t>(isolate, value, configuration, "byte",
                              exception_state);
}

uint8_t ToUInt8(v8::Isolate* isolate,
                v8::Local<v8::Value> value,
                IntegerConversionConfiguration configuration,
                ExceptionState& exception_state) {
  return ToSmallerUInt<uint8_t>(isolate, value, configuration, "octet",
                                exception_state);
}

int16_t ToInt16(v8::Isolate* isolate,
                v8::Local<v8::Value> value,
                IntegerConversionConfiguration configuration,
                ExceptionState& exception_state) {
  return ToSmallerInt<int16_t>(isolate, value, configuration, "short",
                               exception_state);
}

uint16_t ToUInt16(v8::Isolate* isolate,
                  v8::Local<v8::Value> value,
                  IntegerConversionConfiguration configuration,
                  ExceptionState& exception_state) {
  return ToSmallerUInt<uint16_t>(isolate, value, configuration,
                                 "unsigned short", exception_state);
}

int32_t ToInt32Slow(v8::Isolate* isolate,
                    v8::Local<v8::Value> value,
                    IntegerConversionConfiguration configuration,
                    ExceptionState& exception_state) {
  DCHECK(!value->IsInt32());
  // Can the value be converted to a number?
  TryRethrowScope rethrow_scope(isolate, exception_state);
  v8::Local<v8::Number> number_object;
  if (!value->ToNumber(isolate->GetCurrentContext()).ToLocal(&number_object)) {
    return 0;
  }

  DCHECK(!number_object.IsEmpty());

  double number_value = number_object->Value();
  if (configuration == kEnforceRange) {
    return EnforceRange(number_value, kMinInt32, kMaxInt32, "long",
                        exception_state);
  }

  if (std::isnan(number_value))
    return 0;

  if (configuration == kClamp)
    return ClampTo<int32_t>(number_value);

  if (std::isinf(number_value))
    return 0;

  int32_t result;
  if (!number_object->Int32Value(isolate->GetCurrentContext()).To(&result)) {
    return 0;
  }
  return result;
}

uint32_t ToUInt32Slow(v8::Isolate* isolate,
                      v8::Local<v8::Value> value,
                      IntegerConversionConfiguration configuration,
                      ExceptionState& exception_state) {
  DCHECK(!value->IsUint32());
  if (value->IsInt32()) {
    DCHECK_NE(configuration, kNormalConversion);
    int32_t result = value.As<v8::Int32>()->Value();
    if (result >= 0)
      return result;
    if (configuration == kEnforceRange) {
      exception_state.ThrowTypeError(
          "Value is outside the 'unsigned long' value range.");
      return 0;
    }
    DCHECK_EQ(configuration, kClamp);
    return ClampTo<uint32_t>(result);
  }

  // Can the value be converted to a number?
  TryRethrowScope rethrow_scope(isolate, exception_state);
  v8::Local<v8::Number> number_object;
  if (!value->ToNumber(isolate->GetCurrentContext()).ToLocal(&number_object)) {
    return 0;
  }
  DCHECK(!number_object.IsEmpty());

  if (configuration == kEnforceRange) {
    return EnforceRange(number_object->Value(), 0, kMaxUInt32, "unsigned long",
                        exception_state);
  }

  double number_value = number_object->Value();

  if (std::isnan(number_value))
    return 0;

  if (configuration == kClamp)
    return ClampTo<uint32_t>(number_value);

  if (std::isinf(number_value))
    return 0;

  uint32_t result;
  if (!number_object->Uint32Value(isolate->GetCurrentContext()).To(&result)) {
    return 0;
  }
  return result;
}

int64_t ToInt64Slow(v8::Isolate* isolate,
                    v8::Local<v8::Value> value,
                    IntegerConversionConfiguration configuration,
                    ExceptionState& exception_state) {
  DCHECK(!value->IsInt32());

  v8::Local<v8::Number> number_object;
  // Can the value be converted to a number?
  TryRethrowScope rethrow_scope(isolate, exception_state);
  if (!value->ToNumber(isolate->GetCurrentContext()).ToLocal(&number_object)) {
    return 0;
  }
  DCHECK(!number_object.IsEmpty());

  double number_value = number_object->Value();

  if (configuration == kEnforceRange) {
    return EnforceRange(number_value, -kJSMaxInteger, kJSMaxInteger,
                        "long long", exception_state);
  }

  return DoubleToInteger(number_value);
}

uint64_t ToUInt64Slow(v8::Isolate* isolate,
                      v8::Local<v8::Value> value,
                      IntegerConversionConfiguration configuration,
                      ExceptionState& exception_state) {
  DCHECK(!value->IsUint32());
  if (value->IsInt32()) {
    DCHECK(configuration != kNormalConversion);
    int32_t result = value.As<v8::Int32>()->Value();
    if (result >= 0)
      return result;
    if (configuration == kEnforceRange) {
      exception_state.ThrowTypeError(
          "Value is outside the 'unsigned long long' value range.");
      return 0;
    }
    DCHECK_EQ(configuration, kClamp);
    return ClampTo<uint64_t>(result);
  }

  v8::Local<v8::Number> number_object;
  // Can the value be converted to a number?
  TryRethrowScope rethrow_scope(isolate, exception_state);
  if (!value->ToNumber(isolate->GetCurrentContext()).ToLocal(&number_object)) {
    return 0;
  }
  DCHECK(!number_object.IsEmpty());

  double number_value = number_object->Value();

  if (configuration == kEnforceRange) {
    return EnforceRange(number_value, 0, kJSMaxInteger, "unsigned long long",
                        exception_state);
  }

  if (std::isnan(number_value))
    return 0;

  if (configuration == kClamp)
    return ClampTo<uint64_t>(number_value);

  return DoubleToInteger(number_value);
}

float ToRestrictedFloat(v8::Isolate* isolate,
                        v8::Local<v8::Value> value,
                        ExceptionState& exception_state) {
  float number_value = ToFloat(isolate, value, exception_state);
  if (exception_state.HadException())
    return 0;
  if (!std::isfinite(number_value)) {
    exception_state.ThrowTypeError("The provided float value is non-finite.");
    return 0;
  }
  return number_value;
}

double ToDoubleSlow(v8::Isolate* isolate,
                    v8::Local<v8::Value> value,
                    ExceptionState& exception_state) {
  DCHECK(!value->IsNumber());
  TryRethrowScope rethrow_scope(isolate, exception_state);
  v8::Local<v8::Number> number_value;
  if (!value->ToNumber(isolate->GetCurrentContext()).ToLocal(&number_value)) {
    return 0;
  }
  return number_value->Value();
}

double ToRestrictedDouble(v8::Isolate* isolate,
                          v8::Local<v8::Value> value,
                          ExceptionState& exception_state) {
  double number_value = ToDouble(isolate, value, exception_state);
  if (exception_state.HadException())
    return 0;
  if (!std::isfinite(number_value)) {
    exception_state.ThrowTypeError("The provided double value is non-finite.");
    return 0;
  }
  return number_value;
}

static bool HasUnmatchedSurrogates(const String& string) {
  // By definition, 8-bit strings are confined to the Latin-1 code page and
  // have no surrogates, matched or otherwise.
  if (string.empty() || string.Is8Bit())
    return false;

  const UChar* characters = string.Characters16();
  const unsigned length = string.length();

  for (unsigned i = 0; i < length; ++i) {
    UChar c = characters[i];
    if (U16_IS_SINGLE(c))
      continue;
    if (U16_IS_TRAIL(c))
      return true;
    DCHECK(U16_IS_LEAD(c));
    if (i == length - 1)
      return true;
    UChar d = characters[i + 1];
    if (!U16_IS_TRAIL(d))
      return true;
    ++i;
  }
  return false;
}

// Replace unmatched surrogates with REPLACEMENT CHARACTER U+FFFD.
String ReplaceUnmatchedSurrogates(String string) {
  // This roughly implements https://webidl.spec.whatwg.org/#dfn-obtain-unicode
  // but since Blink strings are 16-bits internally, the output is simply
  // re-encoded to UTF-16.

  // The concept of surrogate pairs is explained at:
  // http://www.unicode.org/versions/Unicode6.2.0/ch03.pdf#G2630

  // Blink-specific optimization to avoid making an unnecessary copy.
  if (!HasUnmatchedSurrogates(string))
    return string;
  DCHECK(!string.Is8Bit());

  // 1. Let S be the DOMString value.
  const UChar* s = string.Characters16();

  // 2. Let n be the length of S.
  const unsigned n = string.length();

  // 3. Initialize i to 0.
  unsigned i = 0;

  // 4. Initialize U to be an empty sequence of Unicode characters.
  StringBuffer<UChar> result(n);
  UChar* u = result.Characters();

  // 5. While i < n:
  while (i < n) {
    // 1. Let c be the code unit in S at index i.
    UChar c = s[i];
    // 2. Depending on the value of c:
    if (U16_IS_SINGLE(c)) {
      // c < 0xD800 or c > 0xDFFF
      // Append to U the Unicode character with code point c.
      u[i] = c;
    } else if (U16_IS_TRAIL(c)) {
      // 0xDC00 <= c <= 0xDFFF
      // Append to U a U+FFFD REPLACEMENT CHARACTER.
      u[i] = kReplacementCharacter;
    } else {
      // 0xD800 <= c <= 0xDBFF
      DCHECK(U16_IS_LEAD(c));
      if (i == n - 1) {
        // 1. If i = n-1, then append to U a U+FFFD REPLACEMENT CHARACTER.
        u[i] = kReplacementCharacter;
      } else {
        // 2. Otherwise, i < n-1:
        DCHECK_LT(i, n - 1);
        // ....1. Let d be the code unit in S at index i+1.
        UChar d = s[i + 1];
        if (U16_IS_TRAIL(d)) {
          // 2. If 0xDC00 <= d <= 0xDFFF, then:
          // ..1. Let a be c & 0x3FF.
          // ..2. Let b be d & 0x3FF.
          // ..3. Append to U the Unicode character with code point
          //      2^16+2^10*a+b.
          u[i++] = c;
          u[i] = d;
        } else {
          // 3. Otherwise, d < 0xDC00 or d > 0xDFFF. Append to U a U+FFFD
          //    REPLACEMENT CHARACTER.
          u[i] = kReplacementCharacter;
        }
      }
    }
    // 3. Set i to i+1.
    ++i;
  }

  // 6. Return U.
  DCHECK_EQ(i, string.length());
  return String::Adopt(result);
}

LocalDOMWindow* ToLocalDOMWindow(const ScriptState* script_state) {
  return DynamicTo<LocalDOMWindow>(ToExecutionContext(script_state));
}

ExecutionContext* ToExecutionContext(const ScriptState* script_state) {
  RUNTIME_CALL_TIMER_SCOPE_DISABLED_BY_DEFAULT(
      script_state->GetIsolate(),
      RuntimeCallStats::CounterId::kToExecutionContext);
  return static_cast<const ScriptStateImpl*>(script_state)
      ->GetExecutionContext();
}

LocalDOMWindow* ToLocalDOMWindow(v8::Local<v8::Context> context) {
  if (context.IsEmpty())
    return nullptr;
  return DynamicTo<LocalDOMWindow>(ToExecutionContext(context));
}

LocalDOMWindow* EnteredDOMWindow(v8::Isolate* isolate) {
  LocalDOMWindow* window =
      ToLocalDOMWindow(isolate->GetEnteredOrMicrotaskContext());
  DCHECK(window);
  return window;
}

LocalDOMWindow* IncumbentDOMWindow(v8::Isolate* isolate) {
  LocalDOMWindow* window = ToLocalDOMWindow(isolate->GetIncumbentContext());
  DCHECK(window);
  return window;
}

LocalDOMWindow* CurrentDOMWindow(v8::Isolate* isolate) {
  return ToLocalDOMWindow(isolate->GetCurrentContext());
}

ExecutionContext* ToExecutionContext(v8::Local<v8::Context> context) {
  DCHECK(!context.IsEmpty());
  v8::Isolate* isolate = context->GetIsolate();
  ScriptState* script_state = ScriptState::MaybeFrom(isolate, context);
  return script_state ? ToExecutionContext(script_state) : nullptr;
}

ExecutionContext* CurrentExecutionContext(v8::Isolate* isolate) {
  return ToExecutionContext(isolate->GetCurrentContext());
}

LocalFrame* ToLocalFrameIfNotDetached(v8::Local<v8::Context> context) {
  LocalDOMWindow* window = ToLocalDOMWindow(context);
  if (window && window->IsCurrentlyDisplayedInFrame())
    return window->GetFrame();
  // We return 0 here because |context| is detached from the Frame. If we
  // did return |frame| we could get in trouble because the frame could be
  // navigated to another security origin.
  return nullptr;
}

static ScriptState* ToScriptStateImpl(LocalFrame* frame,
                                      DOMWrapperWorld& world) {
  if (!frame)
    return nullptr;
  v8::Local<v8::Context> context = ToV8ContextEvenIfDetached(frame, world);
  if (context.IsEmpty())
    return nullptr;
  v8::Isolate* isolate = context->GetIsolate();
  ScriptState* script_state = ScriptState::From(isolate, context);
  if (!script_state->ContextIsValid())
    return nullptr;
  DCHECK_EQ(frame, ToLocalFrameIfNotDetached(context));
  return script_state;
}

v8::Local<v8::Context> ToV8Context(ExecutionContext* context,
                                   DOMWrapperWorld& world) {
  DCHECK(context);
  if (LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(context)) {
    if (LocalFrame* frame = window->GetFrame())
      return ToV8Context(frame, world);
  } else if (auto* scope = DynamicTo<WorkerOrWorkletGlobalScope>(context)) {
    if (WorkerOrWorkletScriptController* script = scope->ScriptController()) {
      if (ScriptState* script_state = script->GetScriptState()) {
        if (script_state->ContextIsValid())
          return script_state->GetContext();
      }
    }
  }
  return v8::Local<v8::Context>();
}

v8::Local<v8::Context> ToV8Context(LocalFrame* frame, DOMWrapperWorld& world) {
  ScriptState* script_state = ToScriptStateImpl(frame, world);
  if (!script_state)
    return v8::Local<v8::Context>();
  return script_state->GetContext();
}

// TODO(ishell): return ScriptState* in order to avoid unnecessary hops
// script_state -> context -> script_state on caller side.
v8::Local<v8::Context> ToV8ContextEvenIfDetached(LocalFrame* frame,
                                                 DOMWrapperWorld& world) {
  // TODO(yukishiino): this method probably should not force context creation,
  // but it does through WindowProxy() call.
  DCHECK(frame);

  // TODO(crbug.com/1046282): The following bailout is a temporary fix
  // introduced due to crbug.com/1037985 .  Remove this temporary fix once
  // the root cause is fixed.
  if (!frame->IsDetached() && frame->IsProvisional()) {
    DCHECK(false);
    base::debug::DumpWithoutCrashing();
    return v8::Local<v8::Context>();
  }

  return frame->WindowProxy(world)->ContextIfInitialized();
}

v8::Local<v8::Context> ToV8ContextMaybeEmpty(LocalFrame* frame,
                                             DOMWrapperWorld& world) {
  DCHECK(frame);

  // TODO(crbug.com/1046282): The following bailout is a temporary fix
  // introduced due to crbug.com/1037985 .  Remove this temporary fix once
  // the root cause is fixed.
  if (frame->IsProvisional()) {
    DCHECK(false);
    base::debug::DumpWithoutCrashing();
    return v8::Local<v8::Context>();
  }
  DCHECK(frame->WindowProxyMaybeUninitialized(world));
  v8::Local<v8::Context> context =
      frame->WindowProxyMaybeUninitialized(world)->ContextIfInitialized();

  DCHECK(context.IsEmpty() || frame == ToLocalFrameIfNotDetached(context));
  return context;
}

ScriptState* ToScriptState(ExecutionContext* context, DOMWrapperWorld& world) {
  DCHECK(context);
  if (LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(context)) {
    return ToScriptState(window->GetFrame(), world);
  } else if (auto* scope = DynamicTo<WorkerOrWorkletGlobalScope>(context)) {
    if (WorkerOrWorkletScriptController* script = scope->ScriptController()) {
      if (ScriptState* script_state = script->GetScriptState()) {
        if (script_state->ContextIsValid())
          return script_state;
      }
    }
  }
  return nullptr;
}

ScriptState* ToScriptState(LocalFrame* frame, DOMWrapperWorld& world) {
  if (!frame)
    return nullptr;
  v8::HandleScope handle_scope(ToIsolate(frame));
  return ToScriptStateImpl(frame, world);
}

ScriptState* ToScriptStateForMainWorld(LocalFrame* frame) {
  if (!frame) {
    return nullptr;
  }
  auto* isolate = ToIsolate(frame);
  v8::HandleScope handle_scope(isolate);
  return ToScriptStateImpl(frame, DOMWrapperWorld::MainWorld(isolate));
}

ScriptState* ToScriptStateForMainWorld(ExecutionContext* context) {
  DCHECK(context);
  return ToScriptState(context,
                       DOMWrapperWorld::MainWorld(context->GetIsolate()));
}

bool IsValidEnum(const String& value,
                 const char* const* valid_values,
                 size_t length,
                 const String& enum_name,
                 ExceptionState& exception_state) {
  for (size_t i = 0; i < length; ++i) {
    // Avoid the strlen inside String::operator== (because of the StringView).
    if (WTF::EqualToCString(value.Impl(), valid_values[i])) {
      return true;
    }
  }
  exception_state.ThrowTypeError("The provided value '" + value +
                                 "' is not a valid enum value of type " +
                                 enum_name + ".");
  return false;
}

bool IsValidEnum(const Vector<String>& values,
                 const char* const* valid_values,
                 size_t length,
                 const String& enum_name,
                 ExceptionState& exception_state) {
  for (auto value : values) {
    if (!IsValidEnum(value, valid_values, length, enum_name, exception_state))
      return false;
  }
  return true;
}

v8::Local<v8::Function> GetEsIteratorMethod(v8::Isolate* isolate,
                                            v8::Local<v8::Object> object,
                                            ExceptionState& exception_state) {
  const v8::Local<v8::Value> key = v8::Symbol::GetIterator(isolate);

  TryRethrowScope rethrow_scope(isolate, exception_state);
  v8::Local<v8::Value> iterator_method;
  if (!object->Get(isolate->GetCurrentContext(), key)
           .ToLocal(&iterator_method)) {
    return v8::Local<v8::Function>();
  }

  if (iterator_method->IsNullOrUndefined())
    return v8::Local<v8::Function>();

  if (!iterator_method->IsFunction()) {
    exception_state.ThrowTypeError("Iterator must be callable function");
    return v8::Local<v8::Function>();
  }

  return iterator_method.As<v8::Function>();
}

v8::Local<v8::Object> GetEsIteratorWithMethod(
    v8::Isolate* isolate,
    v8::Local<v8::Function> getter_function,
    v8::Local<v8::Object> object,
    ExceptionState& exception_state) {
  TryRethrowScope rethrow_scope(isolate, exception_state);
  v8::Local<v8::Value> iterator;
  if (!V8ScriptRunner::CallFunction(
           getter_function, ToExecutionContext(isolate->GetCurrentContext()),
           object, 0, nullptr, isolate)
           .ToLocal(&iterator)) {
    return v8::Local<v8::Object>();
  }
  if (!iterator->IsObject()) {
    exception_state.ThrowTypeError("Iterator is not an object.");
    return v8::Local<v8::Object>();
  }
  return iterator.As<v8::Object>();
}

bool HasCallableIteratorSymbol(v8::Isolate* isolate,
                               v8::Local<v8::Value> value,
                               ExceptionState& exception_state) {
  if (!value->IsObject())
    return false;
  v8::Local<v8::Function> iterator_method =
      GetEsIteratorMethod(isolate, value.As<v8::Object>(), exception_state);
  return !iterator_method.IsEmpty();
}

v8::Isolate* ToIsolate(const LocalFrame* frame) {
  DCHECK(frame);
  return frame->GetWindowProxyManager()->GetIsolate();
}

v8::Local<v8::Value> FromJSONString(ScriptState* script_state,
                                    const String& stringified_json) {
  auto v8_string = V8String(script_state->GetIsolate(), stringified_json);
  v8::Local<v8::Value> parsed;
  std::ignore =
      v8::JSON::Parse(script_state->GetContext(), v8_string).ToLocal(&parsed);
  return parsed;
}

Vector<String> GetOwnPropertyNames(v8::Isolate* isolate,
                                   const v8::Local<v8::Object>& object,
                                   ExceptionState& exception_state) {
  if (object.IsEmpty())
    return Vector<String>();

  TryRethrowScope rethrow_scope(isolate, exception_state);
  v8::Local<v8::Array> property_names;
  if (!object->GetOwnPropertyNames(isolate->GetCurrentContext())
"""


```