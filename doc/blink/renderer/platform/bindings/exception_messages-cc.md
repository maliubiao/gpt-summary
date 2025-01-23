Response:
Let's break down the thought process for analyzing this C++ code file.

1. **Understand the Goal:** The core request is to understand the functionality of `exception_messages.cc` within the Chromium Blink rendering engine, especially its relation to web technologies (JavaScript, HTML, CSS) and common errors.

2. **Initial Scan and Keywords:** Quickly scan the code for recognizable patterns and keywords. I see:
    * `#include`: Indicates dependencies on other files.
    * `namespace blink`:  Confirms it's part of the Blink engine.
    * `String`:  Suggests it deals with text.
    * `ExceptionMessages`: The central class of interest.
    * `FailedTo...`, `NotA...`, `Invalid...`: These function names strongly imply error message generation.
    * `v8::ExceptionContext`: Links it to V8, the JavaScript engine used in Chromium.
    * Mentions of "property," "attribute," "index," "named," "constructor," "method," "argument":  These are common terms in programming, particularly related to objects and function calls.

3. **Identify the Core Functionality:** The most obvious function of this file is to generate standardized error messages. The consistent naming pattern of the functions (`FailedTo...`, etc.) and the `AddContextToMessage` function strongly suggest this.

4. **Connect to Web Technologies:**  The presence of `v8::ExceptionContext` is a crucial link to JavaScript. This means the error messages generated here are often triggered by JavaScript code. Consider the different contexts:
    * `kConstructor`:  Relates to `new` keyword in JavaScript.
    * `kOperation`:  Likely involves calling methods on JavaScript objects.
    * `kAttributeGet/Set`: Accessing properties of JavaScript objects.
    * `kIndexedGetter/Setter`: Accessing array elements or array-like objects in JavaScript.
    * `kNamedGetter/Setter`: Accessing properties of JavaScript objects by name.

5. **Analyze Key Functions in Detail:**

    * **`AddContextToMessage`:** This function acts as a central dispatcher. It takes an `ExceptionContext` and a base message and prepends context-specific information. This is important for providing more informative error messages.

    * **`FailedToConstruct`:**  Directly relates to errors during object creation in JavaScript using `new`.

    * **`FailedToExecute`:**  Covers errors when calling methods on JavaScript objects.

    * **`FailedToGet`/`FailedToSet` (and their Indexed/Named variants):** Handle errors when accessing or modifying properties in JavaScript. The distinction between "indexed" and "named" is important for understanding how JavaScript accesses object members.

    * **Other `FailedTo...` functions:**  Cover enumeration and deletion of properties.

    * **Helper Functions (e.g., `optionalNameProperty`, `optionalIndexProperty`):**  These refine the error messages by conditionally adding details.

    * **Functions like `ConstructorNotCallableAsFunction`, `ConstructorCalledAsFunction`:** Target specific common JavaScript usage errors.

    * **Functions related to arguments (`InvalidArity`, `ArgumentNullOrIncorrectType`, `NotEnoughArguments`):**  Focus on errors related to function calls in JavaScript.

    * **Functions related to number validation (`NotAFiniteNumber`):**  Address potential issues with numerical values in JavaScript.

    * **Functions related to index/range checking (`IndexExceedsMaximumBound`, `IndexOutsideRange`):**  Important for array/string manipulation in JavaScript.

    * **Functions like `ReadOnly`, `SharedArrayBufferNotAllowed`, `ResizableArrayBufferNotAllowed`, `ValueNotOfType`:** Handle specific constraints and type errors often encountered in web APIs.

6. **Provide Concrete Examples:**  For each major category of functions, think of simple JavaScript, HTML, or CSS snippets that could trigger these errors. This makes the explanation more tangible.

    * **JavaScript:** Errors related to `new`, method calls, property access, function arguments, array access, etc.
    * **HTML:** While this file doesn't directly parse HTML, JavaScript interacting with the DOM (manipulating HTML elements) could trigger these errors. Think of trying to access a non-existent element property.
    * **CSS:** Similarly, JavaScript interacting with CSS styles could lead to errors if invalid values are used or properties are accessed incorrectly.

7. **Logical Reasoning (Input/Output):** For key functions like `AddContextToMessage`, it's helpful to show how the input (exception context, class name, property, message) transforms into the output error message. This demonstrates the logic of the function.

8. **Common User/Programming Errors:**  Based on the error message types, list the common mistakes developers might make in JavaScript that would result in these errors. This makes the explanation more practical.

9. **Structure and Clarity:** Organize the information logically using headings and bullet points. Use clear and concise language. Avoid overly technical jargon where possible.

10. **Review and Refine:**  Read through the explanation to ensure it's accurate, comprehensive, and easy to understand. Check for any inconsistencies or areas that could be clearer. For instance, initially, I might focus heavily on JavaScript, but then realize I need to explicitly mention the indirect connections to HTML and CSS via DOM manipulation.

This structured approach, moving from a general understanding to specific details and examples, helps to thoroughly analyze the C++ code and explain its functionality in a way that is relevant to web development.
这个文件 `exception_messages.cc` 的主要功能是 **为 Chromium Blink 引擎中的各种异常情况生成格式化的错误消息字符串**。 这些错误消息通常会在 JavaScript 代码执行过程中发生，并帮助开发者理解错误的原因。

以下是该文件的详细功能分解：

**1. 提供各种预定义的错误消息生成函数:**

该文件定义了一系列的静态函数，用于生成特定类型的错误消息。这些函数涵盖了常见的 JavaScript 操作错误，例如：

* **对象构造失败:** `FailedToConstruct`
* **方法执行失败:** `FailedToExecute`
* **属性获取失败:** `FailedToGet`, `FailedToGetIndexed`, `FailedToGetNamed`
* **属性设置失败:** `FailedToSet`, `FailedToSetIndexed`, `FailedToSetNamed`
* **属性删除失败:** `FailedToDelete`, `FailedToDeleteIndexed`, `FailedToDeleteNamed`
* **属性枚举失败:** `FailedToEnumerate`
* **类型转换失败:** `FailedToConvertJSValue`
* **参数错误:** `InvalidArity`, `ArgumentNullOrIncorrectType`, `ArgumentNotOfType`, `NotEnoughArguments`
* **数字范围错误:** `NotAFiniteNumber`, `IndexExceedsMaximumBound`, `IndexExceedsMinimumBound`, `IndexOutsideRange`
* **构造函数调用方式错误:** `ConstructorNotCallableAsFunction`, `ConstructorCalledAsFunction`
* **属性类型错误:** `IncorrectPropertyType`
* **只读属性错误:** `ReadOnly`
* **不允许使用的 ArrayBuffer 类型错误:** `SharedArrayBufferNotAllowed`, `ResizableArrayBufferNotAllowed`
* **值类型错误:** `ValueNotOfType`

**2. 提供上下文相关的错误消息生成:**

`AddContextToMessage` 函数接收一个 `v8::ExceptionContext` 枚举值，该枚举值描述了异常发生的上下文（例如，在构造函数中，在方法调用中，在属性访问中）。根据上下文，该函数会调用相应的预定义错误消息生成函数，并包含类名和属性名等信息，从而提供更详细的错误描述。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件直接服务于 JavaScript 运行时环境，因为它处理的是 JavaScript 代码执行过程中产生的异常。 虽然它不直接处理 HTML 或 CSS 的解析或渲染，但 JavaScript 代码通常用于操作 DOM (HTML) 和 CSS 样式，因此，当这些操作失败时，可能会通过这里的函数生成错误消息。

**JavaScript 示例:**

* **构造函数调用方式错误:**
    * **假设输入:**  JavaScript 代码 `HTMLDivElement()` (忘记使用 `new` 关键字)
    * **输出:**  `Please use the 'new' operator, this DOM object constructor cannot be called as a function.` (由 `ConstructorCalledAsFunction` 生成)

* **方法执行失败:**
    * **假设输入:** JavaScript 代码 `document.getElementById("nonexistent").textContent = "hello";` (尝试访问一个不存在的元素)
    * **输出:**  `Failed to execute 'textContent' on 'null': Cannot set properties of null (setting 'textContent')` (可能由 `FailedToExecute` 生成，并结合 V8 引擎提供的更具体的错误信息)

* **属性设置失败:**
    * **假设输入:** JavaScript 代码 `window.innerHeight = 500;` (尝试设置只读属性)
    * **输出:**  `Failed to set the 'innerHeight' property on 'Window': This object is read-only.` (由 `FailedToSet` 和 `ReadOnly` 生成)

* **参数错误:**
    * **假设输入:** JavaScript 代码 `setTimeout("alert('hello')", "abc");` (`setTimeout` 的第二个参数应该是数字)
    * **输出:**  可能由其他 V8 机制报告类型错误，但如果 Blink 需要更具体的错误消息，可能会使用 `ArgumentNotOfType` 等函数。例如，如果某个 Blink 提供的 API 期望一个特定的对象类型，而用户传递了错误类型，则可能输出类似 `parameter 2 is not of type 'number'.` 的消息。

* **数组越界访问:**
    * **假设输入:** JavaScript 代码 `let arr = [1, 2, 3]; console.log(arr[5]);`
    * **输出:**  虽然 V8 通常会返回 `undefined`，但在某些 Blink 提供的 Array-like 对象或特殊操作中，越界访问可能会触发错误，并可能使用 `FailedToGetIndexed` 生成类似 `Failed to read an indexed property [5] from 'MyCustomArray': Index out of bounds.` 的消息。

**HTML 示例 (通过 JavaScript 交互):**

* **获取不存在的元素属性:**
    * **假设输入:** JavaScript 代码 `document.getElementById("myDiv").nonExistentAttribute;`
    * **输出:** 虽然 V8 通常返回 `undefined`，但如果 Blink 内部需要更明确的错误，可能会使用 `FailedToGetNamed` 生成类似 `Failed to read a named property 'nonExistentAttribute' from 'HTMLDivElement': Not found.` 的消息。

**CSS 示例 (通过 JavaScript 交互):**

* **设置无效的 CSS 属性值:**
    * **假设输入:** JavaScript 代码 `document.getElementById("myDiv").style.width = "abc";`
    * **输出:** 浏览器通常会忽略无效的 CSS 值，但如果 Blink 内部在设置样式时进行了更严格的验证，可能会使用 `FailedToSetNamed` 或类似的函数生成错误消息，例如 `Failed to set a named property 'width' on 'CSSStyleDeclaration': The string 'abc' is not a valid CSS value.`

**逻辑推理的假设输入与输出:**

以 `AddContextToMessage` 函数为例：

* **假设输入:**
    * `type`: `v8::ExceptionContext::kAttributeGet`
    * `class_name`: `"HTMLDivElement"`
    * `property_name`: `"textContent"`
    * `message`: `"Element is null"`
* **输出:** `"Failed to read the 'textContent' property from 'HTMLDivElement': Element is null"`

以 `FailedToConstruct` 函数为例：

* **假设输入:**
    * `type`: `"MyCustomObject"`
    * `detail`: `"Initialization failed"`
* **输出:** `"Failed to construct 'MyCustomObject': Initialization failed"`

**用户或编程常见的使用错误举例:**

* **忘记使用 `new` 关键字来创建对象。** （触发 `ConstructorCalledAsFunction`）
* **尝试访问或修改不存在的对象属性。** （可能触发 `FailedToGetNamed` 或 `FailedToSetNamed`）
* **调用函数时传递了错误数量或类型的参数。** （触发 `InvalidArity`, `ArgumentNullOrIncorrectType`, `ArgumentNotOfType`, `NotEnoughArguments`）
* **尝试修改只读属性。** （触发 `ReadOnly`）
* **在需要数字的地方使用了非数字的值。** （触发 `NotAFiniteNumber`）
* **访问数组时使用了超出范围的索引。** （可能触发 `FailedToGetIndexed` 或 `FailedToSetIndexed`）
* **尝试对 null 或 undefined 的对象执行操作。** （经常会导致 `FailedToExecute`，并包含类似 "Cannot read properties of null" 的详细信息，但这部分详细信息可能由 V8 引擎提供，而 Blink 的这个文件负责提供更通用的 "Failed to execute" 上下文。）

总而言之，`exception_messages.cc` 是 Blink 引擎中一个关键的模块，它负责生成用户友好的、信息丰富的错误消息，帮助开发者调试 JavaScript 代码，并理解在与浏览器环境交互时可能遇到的问题。它通过提供一系列预定义的错误消息模板和上下文添加机制，使得错误报告更加一致和易于理解。

### 提示词
```
这是目录为blink/renderer/platform/bindings/exception_messages.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/bindings/exception_messages.h"

#include "base/notreached.h"
#include "third_party/blink/renderer/platform/bindings/exception_context.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/wtf/decimal.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

String optionalNameProperty(const String& property) {
  if (property.empty()) {
    return String();
  }
  return " '" + property + "'";
}

String optionalIndexProperty(const String& property) {
  if (!property) {
    return String();
  }
  return " [" + property + "]";
}

}  //  namespace

String ExceptionMessages::AddContextToMessage(v8::ExceptionContext type,
                                              const char* class_name,
                                              const String& property_name,
                                              const String& message) {
  switch (type) {
    case v8::ExceptionContext::kConstructor:
      return ExceptionMessages::FailedToConstruct(class_name, message);
    case v8::ExceptionContext::kOperation:
      return ExceptionMessages::FailedToExecute(property_name, class_name,
                                                message);
    case v8::ExceptionContext::kAttributeGet:
      return ExceptionMessages::FailedToGet(property_name, class_name, message);
    case v8::ExceptionContext::kAttributeSet:
      return ExceptionMessages::FailedToSet(property_name, class_name, message);
    case v8::ExceptionContext::kNamedEnumerator:
      return ExceptionMessages::FailedToEnumerate(class_name, message);
    case v8::ExceptionContext::kIndexedGetter:
    case v8::ExceptionContext::kIndexedDescriptor:
    case v8::ExceptionContext::kIndexedQuery:
      return ExceptionMessages::FailedToGetIndexed(property_name, class_name,
                                                   message);
    case v8::ExceptionContext::kIndexedSetter:
    case v8::ExceptionContext::kIndexedDefiner:
      return ExceptionMessages::FailedToSetIndexed(property_name, class_name,
                                                   message);
    case v8::ExceptionContext::kIndexedDeleter:
      return ExceptionMessages::FailedToDeleteIndexed(property_name, class_name,
                                                      message);
    case v8::ExceptionContext::kNamedGetter:
    case v8::ExceptionContext::kNamedDescriptor:
    case v8::ExceptionContext::kNamedQuery:
      return ExceptionMessages::FailedToGetNamed(property_name, class_name,
                                                 message);
    case v8::ExceptionContext::kNamedSetter:
    case v8::ExceptionContext::kNamedDefiner:
      return ExceptionMessages::FailedToSetNamed(property_name, class_name,
                                                 message);
    case v8::ExceptionContext::kNamedDeleter:
      return ExceptionMessages::FailedToDeleteNamed(property_name, class_name,
                                                    message);
    case v8::ExceptionContext::kUnknown:
      return message;
  }
  NOTREACHED();
}

String ExceptionMessages::FailedToConvertJSValue(const char* type) {
  return String::Format("Failed to convert value to '%s'.", type);
}

String ExceptionMessages::FailedToConstruct(const char* type,
                                            const String& detail) {
  String type_string = String(type);
  if (type_string.empty()) {
    return detail;
  }
  return "Failed to construct '" + type_string +
         (!detail.empty() ? String("': " + detail) : String("'"));
}

String ExceptionMessages::FailedToEnumerate(const char* type,
                                            const String& detail) {
  return "Failed to enumerate the properties of '" + String(type) +
         (!detail.empty() ? String("': " + detail) : String("'"));
}

String ExceptionMessages::FailedToExecute(const String& method,
                                          const char* type,
                                          const String& detail) {
  return "Failed to execute '" + method + "' on '" + String(type) +
         (!detail.empty() ? String("': " + detail) : String("'"));
}

String ExceptionMessages::FailedToGet(const String& property,
                                      const char* type,
                                      const String& detail) {
  return "Failed to read the '" + property + "' property from '" +
         String(type) + "': " + detail;
}

String ExceptionMessages::FailedToSet(const String& property,
                                      const char* type,
                                      const String& detail) {
  return "Failed to set the '" + property + "' property on '" + String(type) +
         "': " + detail;
}

String ExceptionMessages::FailedToDelete(const String& property,
                                         const char* type,
                                         const String& detail) {
  return "Failed to delete the '" + property + "' property from '" +
         String(type) + "': " + detail;
}

String ExceptionMessages::FailedToGetIndexed(const String& property,
                                             const char* type,
                                             const String& detail) {
  return "Failed to read an indexed property" +
         optionalIndexProperty(property) + " from '" + String(type) +
         "': " + detail;
}

String ExceptionMessages::FailedToSetIndexed(const String& property,
                                             const char* type,
                                             const String& detail) {
  return "Failed to set an indexed property" + optionalIndexProperty(property) +
         " on '" + String(type) + "': " + detail;
}

String ExceptionMessages::FailedToDeleteIndexed(const String& property,
                                                const char* type,
                                                const String& detail) {
  return "Failed to delete an indexed property" +
         optionalIndexProperty(property) + " from '" + String(type) +
         "': " + detail;
}

String ExceptionMessages::FailedToGetNamed(const String& property,
                                           const char* type,
                                           const String& detail) {
  return "Failed to read a named property" + optionalNameProperty(property) +
         " from '" + String(type) + "': " + detail;
}

String ExceptionMessages::FailedToSetNamed(const String& property,
                                           const char* type,
                                           const String& detail) {
  return "Failed to set a named property" + optionalNameProperty(property) +
         " on '" + String(type) + "': " + detail;
}

String ExceptionMessages::FailedToDeleteNamed(const String& property,
                                              const char* type,
                                              const String& detail) {
  return "Failed to delete a named property" + optionalNameProperty(property) +
         " from '" + String(type) + "': " + detail;
}

String ExceptionMessages::ConstructorNotCallableAsFunction(const char* type) {
  return FailedToConstruct(type,
                           "Please use the 'new' operator, this DOM object "
                           "constructor cannot be called as a function.");
}

String ExceptionMessages::ConstructorCalledAsFunction() {
  return (
      "Please use the 'new' operator, this DOM object constructor cannot "
      "be called as a function.");
}

String ExceptionMessages::IncorrectPropertyType(const String& property,
                                                const String& detail) {
  return "The '" + property + "' property " + detail;
}

String ExceptionMessages::InvalidArity(const char* expected,
                                       unsigned provided) {
  return "Valid arities are: " + String(expected) + ", but " +
         String::Number(provided) + " arguments provided.";
}

String ExceptionMessages::ArgumentNullOrIncorrectType(
    int argument_index,
    const String& expected_type) {
  return "The " + OrdinalNumber(argument_index) +
         " argument provided is either null, or an invalid " + expected_type +
         " object.";
}

String ExceptionMessages::ArgumentNotOfType(int argument_index,
                                            const char* expected_type) {
  return String::Format("parameter %d is not of type '%s'.", argument_index + 1,
                        expected_type);
}

String ExceptionMessages::NotASequenceTypeProperty(
    const String& property_name) {
  return "'" + property_name +
         "' property is neither an array, nor does it have indexed properties.";
}

String ExceptionMessages::NotEnoughArguments(unsigned expected,
                                             unsigned provided) {
  return String::Number(expected) + " argument" + (expected > 1 ? "s" : "") +
         " required, but only " + String::Number(provided) + " present.";
}

String ExceptionMessages::NotAFiniteNumber(double value, const char* name) {
  DCHECK(!std::isfinite(value));
  return String::Format("The %s is %s.", name,
                        std::isinf(value) ? "infinite" : "not a number");
}

String ExceptionMessages::NotAFiniteNumber(const Decimal& value,
                                           const char* name) {
  DCHECK(!value.IsFinite());
  return String::Format("The %s is %s.", name,
                        value.IsInfinity() ? "infinite" : "not a number");
}

String ExceptionMessages::OrdinalNumber(int number) {
  String suffix("th");
  switch (number % 10) {
    case 1:
      if (number % 100 != 11)
        suffix = "st";
      break;
    case 2:
      if (number % 100 != 12)
        suffix = "nd";
      break;
    case 3:
      if (number % 100 != 13)
        suffix = "rd";
      break;
  }
  return String::Number(number) + suffix;
}

String ExceptionMessages::IndexExceedsMaximumBound(const char* name,
                                                   bool eq,
                                                   const String& given,
                                                   const String& bound) {
  StringBuilder result;
  result.Append("The ");
  result.Append(name);
  result.Append(" provided (");
  result.Append(given);
  result.Append(") is greater than ");
  result.Append(eq ? "or equal to " : "");
  result.Append("the maximum bound (");
  result.Append(bound);
  result.Append(").");
  return result.ToString();
}

String ExceptionMessages::IndexExceedsMinimumBound(const char* name,
                                                   bool eq,
                                                   const String& given,
                                                   const String& bound) {
  StringBuilder result;
  result.Append("The ");
  result.Append(name);
  result.Append(" provided (");
  result.Append(given);
  result.Append(") is less than ");
  result.Append(eq ? "or equal to " : "");
  result.Append("the minimum bound (");
  result.Append(bound);
  result.Append(").");
  return result.ToString();
}

String ExceptionMessages::IndexOutsideRange(const char* name,
                                            const String& given,
                                            const String& lower_bound,
                                            BoundType lower_type,
                                            const String& upper_bound,
                                            BoundType upper_type) {
  StringBuilder result;
  result.Append("The ");
  result.Append(name);
  result.Append(" provided (");
  result.Append(given);
  result.Append(") is outside the range ");
  result.Append(lower_type == kExclusiveBound ? '(' : '[');
  result.Append(lower_bound);
  result.Append(", ");
  result.Append(upper_bound);
  result.Append(upper_type == kExclusiveBound ? ')' : ']');
  result.Append('.');
  return result.ToString();
}

String ExceptionMessages::ReadOnly(const char* detail) {
  DEFINE_STATIC_LOCAL(String, read_only, ("This object is read-only."));
  return detail
             ? String::Format("This object is read-only, because %s.", detail)
             : read_only;
}

String ExceptionMessages::SharedArrayBufferNotAllowed(
    const char* expected_type) {
  return String::Format("The provided %s value must not be shared.",
                        expected_type);
}

String ExceptionMessages::ResizableArrayBufferNotAllowed(
    const char* expected_type) {
  return String::Format("The provided %s value must not be resizable.",
                        expected_type);
}

String ExceptionMessages::ValueNotOfType(const char* expected_type) {
  return String::Format("The provided value is not of type '%s'.",
                        expected_type);
}

template <>
String ExceptionMessages::FormatNumber<float>(float number) {
  return FormatPotentiallyNonFiniteNumber(number);
}

template <>
String ExceptionMessages::FormatNumber<double>(double number) {
  return FormatPotentiallyNonFiniteNumber(number);
}

}  // namespace blink
```