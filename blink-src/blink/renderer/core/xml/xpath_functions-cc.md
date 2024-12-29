Response:
Let's break down the thought process for analyzing the `xpath_functions.cc` file.

**1. Initial Scan and High-Level Understanding:**

* **Keywords:** The filename `xpath_functions.cc` immediately tells us this file is about XPath functions.
* **Copyright Notice:**  Indicates it's part of the Chromium Blink rendering engine and has been around for a while.
* **Includes:**  Looking at the included headers provides clues about dependencies and functionalities:
    * `dom/attr.h`, `dom/element.h`, `dom/processing_instruction.h`, `dom/tree_scope.h`:  Clearly related to the DOM structure.
    * `xml/xpath_util.h`, `xml/xpath_value.h`:  XPath specific utilities and value representation.
    * `xml_names.h`:  XML specific names (likely for attributes like `xml:lang`).
    * `platform/wtf/...`:  WTF (Web Template Framework) utilities for strings, math, and data structures.
* **Namespace:** The code is within the `blink::xpath` namespace, confirming its purpose.
* **Function-like Structures:**  There are many class definitions inheriting from a base `Function` class (e.g., `FunLast`, `FunPosition`, `FunString`). This strongly suggests the file implements various XPath functions.
* **`Evaluate` Method:** Each function class has an `Evaluate` method, which is likely the core logic for executing the function.
* **`ResultType` Method:**  Indicates the data type returned by each function (number, string, boolean, nodeset).
* **`DEFINE_FUNCTION_CREATOR` Macros:**  This pattern hints at a factory or registration mechanism for the functions.
* **`g_function_map`:** A static hash map likely stores the mapping between function names (strings) and their implementation details.

**2. Deeper Dive and Function Identification:**

* **Iterate through the `Fun...` Classes:**  Go through each class definition. The names are descriptive (e.g., `FunLast`, `FunStringLength`, `FunBoolean`).
* **Connect to XPath Standard:**  Recognize the names as standard XPath 1.0 functions. This helps in understanding their purpose without looking at the detailed implementation.
* **Analyze `Evaluate` Methods (Briefly):**  Quickly skim the `Evaluate` methods to get a general idea of what they do. For example:
    * `FunLast`: Returns `context.size` (likely the size of the current node-set).
    * `FunPosition`: Returns `context.position` (the position of the current node in the node-set).
    * `FunString`:  Converts something to a string.
    * `FunConcat`: Concatenates strings.
    * `FunStartsWith`: Checks if a string starts with another.
* **Examine `CreateFunction`:** This function seems to be the entry point for creating function objects based on a name and arguments. It uses the `g_function_map`.
* **Analyze `CreateFunctionMap`:** This function populates the `g_function_map` with the available XPath functions and their corresponding creation functions and argument counts.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **XPath in Browsers:** Recall that XPath is used in web browsers, primarily through JavaScript's DOM API. Specifically, methods like `document.evaluate()`.
* **Relate Functions to DOM Manipulation:**  Think about how each XPath function might be used to query or manipulate the DOM structure represented by HTML.
    * **Node Selection:** Functions like `id()`, `local-name()`, `namespace-uri()`, `name()` are used to select specific nodes based on their properties.
    * **String Manipulation:** Functions like `string()`, `concat()`, `substring()`, `starts-with()`, `contains()`, `normalize-space()`, `translate()` are used to work with the text content of nodes or attributes.
    * **Boolean Logic:** Functions like `boolean()`, `not()`, `true()`, `false()`, `lang()` are used in XPath expressions to create conditional logic for selecting nodes.
    * **Numerical Operations:** Functions like `number()`, `sum()`, `floor()`, `ceiling()`, `round()`, `count()`, `position()`, `last()` are used for calculations related to nodes or their properties.
* **CSS Selectors (Indirect Relationship):** While not directly related, understand that XPath provides more powerful selection capabilities than CSS selectors. Browsers internally use XPath engines for certain tasks.

**4. Examples, Assumptions, and Errors:**

* **Choose Representative Functions:** Select a few key functions to illustrate with examples. `string()`, `concat()`, `substring()`, `count()`, `starts-with()`, `id()` are good choices.
* **Construct Simple HTML Snippets:** Create minimal HTML examples to demonstrate the XPath queries.
* **Formulate XPath Expressions:** Write corresponding XPath expressions that would use the functions.
* **Predict Input and Output:**  Based on the HTML and XPath, reason about what the functions would return.
* **Consider Common Errors:** Think about typical mistakes developers make when using XPath, such as:
    * Incorrect argument types.
    * Off-by-one errors with string indices.
    * Misunderstanding context nodes.
    * Issues with whitespace.
    * Case sensitivity (or lack thereof).

**5. Debugging Scenario:**

* **Start with a Trigger:** Imagine a user interacting with a web page in a way that would eventually lead to XPath evaluation. A common trigger is JavaScript code using `document.evaluate()`.
* **Trace the Call Stack (Hypothetically):**  Outline the steps involved, moving from user action to JavaScript to the browser's internal XPath engine.
* **Pinpoint the File's Role:** Explain how `xpath_functions.cc` is involved in the evaluation process.

**Self-Correction/Refinement during the process:**

* **Initially, I might focus too much on the low-level C++ details.** Realize that the request is also about the *functionality* and how it relates to web technologies. Shift the focus to the purpose of the functions and their connection to JavaScript, HTML, and CSS.
* **I might initially miss the connection to `document.evaluate()` in JavaScript.**  Remember the primary way XPath is used in web browsers.
* **I might struggle with concrete examples.**  Take the time to create simple but illustrative HTML snippets and XPath expressions.
* **I might forget common user errors.**  Actively brainstorm common mistakes developers make with XPath.

By following these steps, moving from a broad understanding to specific details, and constantly connecting the code to its real-world usage, a comprehensive and accurate analysis of `xpath_functions.cc` can be achieved.
这是 Chromium Blink 引擎中 `blink/renderer/core/xml/xpath_functions.cc` 文件的功能列表和相关说明：

**主要功能:**

该文件实现了 XPath 1.0 标准中定义的内置函数。这些函数可以在 XPath 表达式中使用，用于操作和查询 XML 文档中的数据。

**具体功能 (对应代码中的类):**

* **节点集函数:**
    * **`FunLast`:** 返回当前上下文节点列表中的最后一个节点的索引（大小）。
    * **`FunPosition`:** 返回当前上下文节点在当前上下文节点列表中的位置。
    * **`FunCount`:** 返回节点集中的节点数量。
    * **`FunId`:**  根据给定的 ID (或以空格分隔的 ID 列表) 查找元素。

* **字符串函数:**
    * **`FunLocalName`:** 返回节点的本地名称（不包含命名空间前缀）。
    * **`FunNamespaceURI`:** 返回节点的命名空间 URI。
    * **`FunName`:** 返回节点的扩展名称（包含命名空间前缀，如果存在）。
    * **`FunString`:** 将参数转换为字符串。如果没有参数，则将上下文节点转换为字符串值。
    * **`FunConcat`:** 将两个或多个字符串连接在一起。
    * **`FunStartsWith`:** 检查一个字符串是否以另一个字符串开头。
    * **`FunContains`:** 检查一个字符串是否包含另一个字符串。
    * **`FunSubstringBefore`:** 返回一个字符串在另一个字符串中第一次出现指定字符串之前的部分。
    * **`FunSubstringAfter`:** 返回一个字符串在另一个字符串中第一次出现指定字符串之后的部分。
    * **`FunSubstring`:** 返回字符串的子串。
    * **`FunStringLength`:** 返回字符串的长度。
    * **`FunNormalizeSpace`:** 通过去除前导和尾随空格以及将中间的多个空格替换为单个空格来规范化字符串。
    * **`FunTranslate`:** 将字符串中的某些字符替换为其他字符。

* **布尔函数:**
    * **`FunBoolean`:** 将参数转换为布尔值。
    * **`FunNot`:** 对布尔值取反。
    * **`FunTrue`:** 返回布尔值 true。
    * **`FunFalse`:** 返回布尔值 false。
    * **`FunLang`:** 检查上下文节点的语言是否与指定的语言匹配。

* **数值函数:**
    * **`FunNumber`:** 将参数转换为数字。
    * **`FunSum`:** 计算节点集中所有节点的字符串值的数字之和。
    * **`FunFloor`:** 返回不大于参数的最大整数。
    * **`FunCeiling`:** 返回不小于参数的最小整数。
    * **`FunRound`:** 返回最接近参数的整数。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

该文件中的 XPath 函数主要通过 JavaScript 的 DOM API 与 HTML 和 CSS 产生关系。

* **JavaScript:** JavaScript 代码可以使用 `document.evaluate()` 方法执行 XPath 表达式。这些 XPath 表达式中就可以使用 `xpath_functions.cc` 中实现的函数。

   **举例说明:**

   ```javascript
   // HTML 结构: <div id="myDiv"><span>Hello</span> World</div>

   // JavaScript 代码
   let element = document.getElementById('myDiv');
   let result = document.evaluate('string-length(.)', element, null, XPathResult.STRING_TYPE, null);
   console.log(result.stringValue); // 输出 17 (包含空格)

   let spanTextLength = document.evaluate('string-length(span)', element, null, XPathResult.NUMBER_TYPE, null);
   console.log(spanTextLength.numberValue); // 输出 5

   let containsWorld = document.evaluate('contains(., "World")', element, null, XPathResult.BOOLEAN_TYPE, null);
   console.log(containsWorld.booleanValue); // 输出 true
   ```

* **HTML:** XPath 表达式是针对 HTML 文档的 DOM 树进行求值的。`xpath_functions.cc` 中的函数操作的就是 DOM 树中的节点和它们的属性、文本内容等。

   **举例说明:**

   XPath 表达式 `//div[@id='myDiv']/span/text()` 使用了隐式的字符串转换，而 `string()` 函数可以显式转换。例如，`string(//div[@id='myDiv']/span)` 会将 `<span>Hello</span>` 节点转换为字符串 `"Hello"`.

* **CSS:** 虽然 CSS 选择器本身不是 XPath，但在某些情况下，浏览器内部可能会使用类似 XPath 的机制进行样式计算和匹配。此外，一些高级 CSS 选择器（例如，使用属性选择器和伪类）的概念与 XPath 的某些功能有相似之处。

   **举例说明（间接关系）：**

   虽然不能直接用 CSS 调用 `string-length()`，但 CSS 的属性选择器可以根据属性值的存在或特定值进行选择，这与 XPath 的某些功能类似。例如，CSS `a[href^="https"]` 类似于 XPath `//a[starts-with(@href, "https")]`.

**逻辑推理的假设输入与输出:**

假设我们有一个简单的 XML/HTML 片段：

```xml
<root>
  <item id="item1">Value One</item>
  <item id="item2">Value Two</item>
  <item>Another Value</item>
</root>
```

* **假设输入:** XPath 表达式 `count(//item)`
   * **逻辑推理:** `count()` 函数计算 `//item` 选择的节点集中的节点数量。`//item` 会选中所有名为 `item` 的元素。
   * **输出:**  `3`

* **假设输入:** XPath 表达式 `string-length(//item[@id='item1'])`
   * **逻辑推理:** `//item[@id='item1']` 选择 `id` 属性为 `item1` 的 `item` 元素。`string-length()` 计算该元素的字符串值长度，即 "Value One" 的长度。
   * **输出:** `9`

* **假设输入:** XPath 表达式 `substring(//item[@id='item2'], 7)`
   * **逻辑推理:** `//item[@id='item2']` 选择 `id` 属性为 `item2` 的 `item` 元素，其字符串值为 "Value Two"。`substring()` 从第 7 个字符开始提取子串（XPath 索引从 1 开始）。
   * **输出:** `"Two"`

**用户或编程常见的使用错误举例说明:**

* **`substring()` 函数的索引错误:** XPath 的 `substring()` 函数的起始位置是从 1 开始的，而不是像很多编程语言那样从 0 开始。

   **错误示例:** 假设用户想提取 "Value Two" 中的 "Two"，可能会错误地使用 `substring(//item[@id='item2'], 6)`. 这会导致结果不符合预期（可能是 "wo"）。正确的用法是 `substring(//item[@id='item2'], 7)`.

* **类型不匹配:**  XPath 函数对参数类型有要求。传递错误的类型可能会导致错误或意外结果。

   **错误示例:** `sum(//item)` 期望 `//item` 返回的节点集的字符串值可以转换为数字。如果 `item` 元素包含无法转换为数字的文本，`sum()` 函数的结果可能是 NaN。

* **对节点集使用字符串函数的误解:** 当对节点集使用字符串函数（如 `string-length()`）且节点集包含多个节点时，通常只会处理节点集中的第一个节点。

   **错误示例:**  `string-length(//item)` 通常只会返回第一个 `item` 元素的字符串长度，而不是所有 `item` 元素的长度之和或长度列表。

* **`id()` 函数的使用限制:** `id()` 函数只能用于查找具有唯一 ID 的元素。如果文档中存在重复的 ID，行为可能不确定。

**用户操作如何一步步地到达这里，作为调试线索:**

1. **用户操作 (例如在网页上点击一个按钮)：** 用户与网页进行交互，触发 JavaScript 代码的执行。
2. **JavaScript 代码执行:** 网页的 JavaScript 代码使用 `document.evaluate()` 方法执行一个包含 XPath 函数的表达式。
   ```javascript
   let result = document.evaluate('count(//div[@class="my-class"])', document, null, XPathResult.NUMBER_TYPE, null);
   ```
3. **Blink 引擎接收 XPath 查询:**  浏览器内核（Blink 引擎）接收到来自 JavaScript 的 XPath 查询请求。
4. **XPath 解析和编译:** Blink 引擎的 XPath 解析器会解析该 XPath 表达式，并将其编译成内部表示。
5. **函数调用:**  在执行编译后的 XPath 表达式时，当遇到 `count()` 这样的函数时，Blink 引擎会调用 `blink::xpath::CreateFunction("count", ...)` 来创建相应的函数对象（`FunCount` 的实例）。
6. **`Evaluate` 方法执行:** 最终，当需要求值该函数时，会调用 `FunCount::Evaluate(EvaluationContext& context)` 方法。在这个方法中，会获取参数（即 `//div[@class="my-class"]` 的求值结果，一个节点集），并返回该节点集的数量。

**调试线索:**

如果开发者在调试涉及 XPath 的功能时遇到问题，可以考虑以下线索：

* **检查 JavaScript 代码中的 XPath 表达式:**  确认 XPath 表达式是否正确，函数名和参数是否符合预期。
* **查看 `document.evaluate()` 的调用:**  确认调用是否正确，特别是 `XPathResult` 类型是否与 XPath 表达式的预期返回值类型一致。
* **使用浏览器开发者工具的 "Elements" 面板:**  检查 HTML 结构是否符合 XPath 表达式的选择条件。
* **在断点调试器中跟踪 `document.evaluate()` 的执行:** 可以设置断点在 `document.evaluate()` 调用前后，查看传递的 XPath 表达式和返回结果。
* **在 Blink 源代码中设置断点:** 如果需要深入了解 Blink 内部的 XPath 函数执行过程，可以在 `xpath_functions.cc` 中相关的 `Evaluate` 方法中设置断点，例如 `FunCount::Evaluate`，查看执行时的上下文和参数。

总之，`blink/renderer/core/xml/xpath_functions.cc` 是 Blink 引擎中实现 XPath 标准内置函数的关键文件，它通过 JavaScript 的 DOM API 与 HTML 和 CSS 产生联系，为开发者提供了强大的 XML/HTML 数据查询和操作能力。理解其功能和常见错误有助于更好地使用 XPath 并进行相关问题的调试。

Prompt: 
```
这是目录为blink/renderer/core/xml/xpath_functions.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2005 Frerich Raabe <raabe@kde.org>
 * Copyright (C) 2006, 2009 Apple Inc.
 * Copyright (C) 2007 Alexey Proskuryakov <ap@webkit.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/xml/xpath_functions.h"

#include <algorithm>

#include "third_party/blink/renderer/core/dom/attr.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/processing_instruction.h"
#include "third_party/blink/renderer/core/dom/tree_scope.h"
#include "third_party/blink/renderer/core/xml/xpath_util.h"
#include "third_party/blink/renderer/core/xml/xpath_value.h"
#include "third_party/blink/renderer/core/xml_names.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

#include <algorithm>
#include <limits>

namespace blink::xpath {

static inline bool IsWhitespace(UChar c) {
  return c == ' ' || c == '\n' || c == '\r' || c == '\t';
}

#define DEFINE_FUNCTION_CREATOR(Class) \
  static Function* Create##Class() { return MakeGarbageCollected<Class>(); }

class Interval {
 public:
  static const int kInf = -1;

  Interval();
  Interval(int value);
  Interval(int min, int max);

  bool Contains(int value) const;

 private:
  int min_;
  int max_;
};

struct FunctionRec {
  typedef Function* (*FactoryFn)();
  FactoryFn factory_fn;
  Interval args;
};

static HashMap<String, FunctionRec>* g_function_map;

class FunLast final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kNumberValue; }

 public:
  FunLast() { SetIsContextSizeSensitive(true); }
};

class FunPosition final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kNumberValue; }

 public:
  FunPosition() { SetIsContextPositionSensitive(true); }
};

class FunCount final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kNumberValue; }
};

class FunId final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kNodeSetValue; }
};

class FunLocalName final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kStringValue; }

 public:
  FunLocalName() {
    SetIsContextNodeSensitive(true);
  }  // local-name() with no arguments uses context node.
};

class FunNamespaceURI final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kStringValue; }

 public:
  FunNamespaceURI() {
    SetIsContextNodeSensitive(true);
  }  // namespace-uri() with no arguments uses context node.
};

class FunName final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kStringValue; }

 public:
  FunName() {
    SetIsContextNodeSensitive(true);
  }  // name() with no arguments uses context node.
};

class FunString final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kStringValue; }

 public:
  FunString() {
    SetIsContextNodeSensitive(true);
  }  // string() with no arguments uses context node.
};

class FunConcat final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kStringValue; }
};

class FunStartsWith final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kBooleanValue; }
};

class FunContains final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kBooleanValue; }
};

class FunSubstringBefore final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kStringValue; }
};

class FunSubstringAfter final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kStringValue; }
};

class FunSubstring final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kStringValue; }
};

class FunStringLength final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kNumberValue; }

 public:
  FunStringLength() {
    SetIsContextNodeSensitive(true);
  }  // string-length() with no arguments uses context node.
};

class FunNormalizeSpace final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kStringValue; }

 public:
  FunNormalizeSpace() {
    SetIsContextNodeSensitive(true);
  }  // normalize-space() with no arguments uses context node.
};

class FunTranslate final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kStringValue; }
};

class FunBoolean final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kBooleanValue; }
};

class FunNot final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kBooleanValue; }
};

class FunTrue final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kBooleanValue; }
};

class FunFalse final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kBooleanValue; }
};

class FunLang final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kBooleanValue; }

 public:
  FunLang() {
    SetIsContextNodeSensitive(true);
  }  // lang() always works on context node.
};

class FunNumber final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kNumberValue; }

 public:
  FunNumber() {
    SetIsContextNodeSensitive(true);
  }  // number() with no arguments uses context node.
};

class FunSum final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kNumberValue; }
};

class FunFloor final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kNumberValue; }
};

class FunCeiling final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kNumberValue; }
};

class FunRound final : public Function {
  Value Evaluate(EvaluationContext&) const override;
  Value::Type ResultType() const override { return Value::kNumberValue; }

 public:
  static double Round(double);
};

DEFINE_FUNCTION_CREATOR(FunLast)
DEFINE_FUNCTION_CREATOR(FunPosition)
DEFINE_FUNCTION_CREATOR(FunCount)
DEFINE_FUNCTION_CREATOR(FunId)
DEFINE_FUNCTION_CREATOR(FunLocalName)
DEFINE_FUNCTION_CREATOR(FunNamespaceURI)
DEFINE_FUNCTION_CREATOR(FunName)

DEFINE_FUNCTION_CREATOR(FunString)
DEFINE_FUNCTION_CREATOR(FunConcat)
DEFINE_FUNCTION_CREATOR(FunStartsWith)
DEFINE_FUNCTION_CREATOR(FunContains)
DEFINE_FUNCTION_CREATOR(FunSubstringBefore)
DEFINE_FUNCTION_CREATOR(FunSubstringAfter)
DEFINE_FUNCTION_CREATOR(FunSubstring)
DEFINE_FUNCTION_CREATOR(FunStringLength)
DEFINE_FUNCTION_CREATOR(FunNormalizeSpace)
DEFINE_FUNCTION_CREATOR(FunTranslate)

DEFINE_FUNCTION_CREATOR(FunBoolean)
DEFINE_FUNCTION_CREATOR(FunNot)
DEFINE_FUNCTION_CREATOR(FunTrue)
DEFINE_FUNCTION_CREATOR(FunFalse)
DEFINE_FUNCTION_CREATOR(FunLang)

DEFINE_FUNCTION_CREATOR(FunNumber)
DEFINE_FUNCTION_CREATOR(FunSum)
DEFINE_FUNCTION_CREATOR(FunFloor)
DEFINE_FUNCTION_CREATOR(FunCeiling)
DEFINE_FUNCTION_CREATOR(FunRound)

#undef DEFINE_FUNCTION_CREATOR

inline Interval::Interval() : min_(kInf), max_(kInf) {}

inline Interval::Interval(int value) : min_(value), max_(value) {}

inline Interval::Interval(int min, int max) : min_(min), max_(max) {}

inline bool Interval::Contains(int value) const {
  if (min_ == kInf && max_ == kInf)
    return true;

  if (min_ == kInf)
    return value <= max_;

  if (max_ == kInf)
    return value >= min_;

  return value >= min_ && value <= max_;
}

void Function::SetArguments(HeapVector<Member<Expression>>& args) {
  DCHECK(!SubExprCount());

  // Some functions use context node as implicit argument, so when explicit
  // arguments are added, they may no longer be context node sensitive.
  if (name_ != "lang" && !args.empty())
    SetIsContextNodeSensitive(false);

  for (Expression* arg : args)
    AddSubExpression(arg);
}

Value FunLast::Evaluate(EvaluationContext& context) const {
  return context.size;
}

Value FunPosition::Evaluate(EvaluationContext& context) const {
  return context.position;
}

Value FunId::Evaluate(EvaluationContext& context) const {
  Value a = Arg(0)->Evaluate(context);
  StringBuilder id_list;  // A whitespace-separated list of IDs

  if (a.IsNodeSet()) {
    for (const auto& node : a.ToNodeSet(&context)) {
      id_list.Append(StringValue(node));
      id_list.Append(' ');
    }
  } else {
    id_list.Append(a.ToString());
  }

  TreeScope& context_scope = context.node->GetTreeScope();
  NodeSet* result(NodeSet::Create());
  HeapHashSet<Member<Node>> result_set;

  unsigned start_pos = 0;
  unsigned length = id_list.length();
  while (true) {
    while (start_pos < length && IsWhitespace(id_list[start_pos]))
      ++start_pos;

    if (start_pos == length)
      break;

    unsigned end_pos = start_pos;
    while (end_pos < length && !IsWhitespace(id_list[end_pos]))
      ++end_pos;

    // If there are several nodes with the same id, id() should return the first
    // one.  In WebKit, getElementById behaves so, too, although its behavior in
    // this case is formally undefined.
    Node* node = context_scope.getElementById(
        AtomicString(id_list.Substring(start_pos, end_pos - start_pos)));
    if (node && result_set.insert(node).is_new_entry)
      result->Append(node);

    start_pos = end_pos;
  }

  result->MarkSorted(false);

  return Value(result, Value::kAdopt);
}

static inline String ExpandedNameLocalPart(Node* node) {
  // The local part of an XPath expanded-name matches DOM local name for most
  // node types, except for namespace nodes and processing instruction nodes.
  // But note that Blink does not support namespace nodes.
  switch (node->getNodeType()) {
    case Node::kElementNode:
      return To<Element>(node)->localName();
    case Node::kAttributeNode:
      return To<Attr>(node)->localName();
    case Node::kProcessingInstructionNode:
      return To<ProcessingInstruction>(node)->target();
    default:
      return String();
  }
}

static inline String ExpandedNamespaceURI(Node* node) {
  switch (node->getNodeType()) {
    case Node::kElementNode:
      return To<Element>(node)->namespaceURI();
    case Node::kAttributeNode:
      return To<Attr>(node)->namespaceURI();
    default:
      return String();
  }
}

static inline String ExpandedName(Node* node) {
  AtomicString prefix;

  switch (node->getNodeType()) {
    case Node::kElementNode:
      prefix = To<Element>(node)->prefix();
      break;
    case Node::kAttributeNode:
      prefix = To<Attr>(node)->prefix();
      break;
    default:
      break;
  }

  return prefix.empty() ? ExpandedNameLocalPart(node)
                        : prefix + ":" + ExpandedNameLocalPart(node);
}

Value FunLocalName::Evaluate(EvaluationContext& context) const {
  if (ArgCount() > 0) {
    Value a = Arg(0)->Evaluate(context);
    if (!a.IsNodeSet())
      return "";

    Node* node = a.ToNodeSet(&context).FirstNode();
    return node ? ExpandedNameLocalPart(node) : "";
  }

  return ExpandedNameLocalPart(context.node);
}

Value FunNamespaceURI::Evaluate(EvaluationContext& context) const {
  if (ArgCount() > 0) {
    Value a = Arg(0)->Evaluate(context);
    if (!a.IsNodeSet())
      return "";

    Node* node = a.ToNodeSet(&context).FirstNode();
    return node ? ExpandedNamespaceURI(node) : "";
  }

  return ExpandedNamespaceURI(context.node);
}

Value FunName::Evaluate(EvaluationContext& context) const {
  if (ArgCount() > 0) {
    Value a = Arg(0)->Evaluate(context);
    if (!a.IsNodeSet())
      return "";

    Node* node = a.ToNodeSet(&context).FirstNode();
    return node ? ExpandedName(node) : "";
  }

  return ExpandedName(context.node);
}

Value FunCount::Evaluate(EvaluationContext& context) const {
  Value a = Arg(0)->Evaluate(context);

  return double(a.ToNodeSet(&context).size());
}

Value FunString::Evaluate(EvaluationContext& context) const {
  if (!ArgCount())
    return Value(context.node).ToString();
  return Arg(0)->Evaluate(context).ToString();
}

Value FunConcat::Evaluate(EvaluationContext& context) const {
  StringBuilder result;
  result.ReserveCapacity(1024);

  unsigned count = ArgCount();
  for (unsigned i = 0; i < count; ++i) {
    EvaluationContext cloned_context(context);
    result.Append(Arg(i)->Evaluate(cloned_context).ToString());
  }

  return result.ToString();
}

Value FunStartsWith::Evaluate(EvaluationContext& context) const {
  EvaluationContext cloned_context(context);
  String s1 = Arg(0)->Evaluate(context).ToString();
  String s2 = Arg(1)->Evaluate(cloned_context).ToString();

  if (s2.empty())
    return true;

  return s1.StartsWith(s2);
}

Value FunContains::Evaluate(EvaluationContext& context) const {
  EvaluationContext cloned_context(context);
  String s1 = Arg(0)->Evaluate(context).ToString();
  String s2 = Arg(1)->Evaluate(cloned_context).ToString();

  if (s2.empty())
    return true;

  return s1.Contains(s2) != 0;
}

Value FunSubstringBefore::Evaluate(EvaluationContext& context) const {
  EvaluationContext cloned_context(context);
  String s1 = Arg(0)->Evaluate(context).ToString();
  String s2 = Arg(1)->Evaluate(cloned_context).ToString();

  if (s2.empty())
    return "";

  wtf_size_t i = s1.Find(s2);

  if (i == kNotFound)
    return "";

  return s1.Left(i);
}

Value FunSubstringAfter::Evaluate(EvaluationContext& context) const {
  EvaluationContext cloned_context(context);
  String s1 = Arg(0)->Evaluate(context).ToString();
  String s2 = Arg(1)->Evaluate(cloned_context).ToString();

  wtf_size_t i = s1.Find(s2);
  if (i == kNotFound)
    return "";

  return s1.Substring(i + s2.length());
}

// Computes the 1-based start and end (exclusive) string indices for
// substring. This is all the positions [1, maxLen (inclusive)] where
// start <= position < start + len
static std::pair<unsigned, unsigned> ComputeSubstringStartEnd(double start,
                                                              double len,
                                                              double max_len) {
  DCHECK(std::isfinite(max_len));
  const double end = start + len;
  if (std::isnan(start) || std::isnan(end))
    return std::make_pair(1, 1);
  // Neither start nor end are NaN, but may still be +/- Inf
  const double clamped_start = std::clamp<double>(start, 1, max_len + 1);
  const double clamped_end = std::clamp(end, clamped_start, max_len + 1);
  return std::make_pair(static_cast<unsigned>(clamped_start),
                        static_cast<unsigned>(clamped_end));
}

// substring(string, number pos, number? len)
//
// Characters in string are indexed from 1. Numbers are doubles and
// substring is specified to work with IEEE-754 infinity, NaN, and
// XPath's bespoke rounding function, round.
//
// <https://www.w3.org/TR/xpath/#function-substring>
Value FunSubstring::Evaluate(EvaluationContext& context) const {
  EvaluationContext cloned_context1(context);
  EvaluationContext cloned_context2(context);
  String source_string = Arg(0)->Evaluate(context).ToString();
  const double pos =
      FunRound::Round(Arg(1)->Evaluate(cloned_context1).ToNumber());
  const double len =
      ArgCount() == 3
          ? FunRound::Round(Arg(2)->Evaluate(cloned_context2).ToNumber())
          : std::numeric_limits<double>::infinity();
  const auto bounds =
      ComputeSubstringStartEnd(pos, len, source_string.length());
  if (bounds.second <= bounds.first)
    return "";
  return source_string.Substring(bounds.first - 1,
                                 bounds.second - bounds.first);
}

Value FunStringLength::Evaluate(EvaluationContext& context) const {
  if (!ArgCount())
    return Value(context.node).ToString().length();
  return Arg(0)->Evaluate(context).ToString().length();
}

Value FunNormalizeSpace::Evaluate(EvaluationContext& context) const {
  // https://www.w3.org/TR/1999/REC-xpath-19991116/#function-normalize-space
  String s = (ArgCount() == 0 ? Value(context.node) : Arg(0)->Evaluate(context))
                 .ToString();
  return s.SimplifyWhiteSpace(IsXMLSpace);
}

Value FunTranslate::Evaluate(EvaluationContext& context) const {
  EvaluationContext cloned_context1(context);
  EvaluationContext cloned_context2(context);
  String s1 = Arg(0)->Evaluate(context).ToString();
  String s2 = Arg(1)->Evaluate(cloned_context1).ToString();
  String s3 = Arg(2)->Evaluate(cloned_context2).ToString();
  StringBuilder result;

  for (unsigned i1 = 0; i1 < s1.length(); ++i1) {
    UChar ch = s1[i1];
    wtf_size_t i2 = s2.find(ch);

    if (i2 == kNotFound)
      result.Append(ch);
    else if (i2 < s3.length())
      result.Append(s3[i2]);
  }

  return result.ToString();
}

Value FunBoolean::Evaluate(EvaluationContext& context) const {
  return Arg(0)->Evaluate(context).ToBoolean();
}

Value FunNot::Evaluate(EvaluationContext& context) const {
  return !Arg(0)->Evaluate(context).ToBoolean();
}

Value FunTrue::Evaluate(EvaluationContext&) const {
  return true;
}

Value FunLang::Evaluate(EvaluationContext& context) const {
  String lang = Arg(0)->Evaluate(context).ToString();

  const Attribute* language_attribute = nullptr;
  Node* node = context.node;
  while (node) {
    if (auto* element = DynamicTo<Element>(node))
      language_attribute = element->Attributes().Find(xml_names::kLangAttr);

    if (language_attribute)
      break;
    node = node->parentNode();
  }

  if (!language_attribute)
    return false;

  String lang_value = language_attribute->Value();
  return lang_value.StartsWithIgnoringASCIICase(lang) &&
         (lang.length() == lang_value.length() ||
          lang_value[lang.length()] == '-');
}

Value FunFalse::Evaluate(EvaluationContext&) const {
  return false;
}

Value FunNumber::Evaluate(EvaluationContext& context) const {
  if (!ArgCount())
    return Value(context.node).ToNumber();
  return Arg(0)->Evaluate(context).ToNumber();
}

Value FunSum::Evaluate(EvaluationContext& context) const {
  Value a = Arg(0)->Evaluate(context);
  if (!a.IsNodeSet())
    return 0.0;

  double sum = 0.0;
  const NodeSet& nodes = a.ToNodeSet(&context);
  // To be really compliant, we should sort the node-set, as floating point
  // addition is not associative.  However, this is unlikely to ever become a
  // practical issue, and sorting is slow.

  for (const auto& node : nodes)
    sum += Value(StringValue(node)).ToNumber();

  return sum;
}

Value FunFloor::Evaluate(EvaluationContext& context) const {
  return floor(Arg(0)->Evaluate(context).ToNumber());
}

Value FunCeiling::Evaluate(EvaluationContext& context) const {
  return ceil(Arg(0)->Evaluate(context).ToNumber());
}

double FunRound::Round(double val) {
  if (std::isfinite(val)) {
    if (std::signbit(val) && val >= -0.5)
      val *= 0;  // negative zero
    else
      val = floor(val + 0.5);
  }
  return val;
}

Value FunRound::Evaluate(EvaluationContext& context) const {
  return Round(Arg(0)->Evaluate(context).ToNumber());
}

struct FunctionMapping {
  const char* name;
  FunctionRec function;
};

static void CreateFunctionMap() {
  DCHECK(!g_function_map);
  const FunctionMapping functions[] = {
      {"boolean", {&CreateFunBoolean, 1}},
      {"ceiling", {&CreateFunCeiling, 1}},
      {"concat", {&CreateFunConcat, Interval(2, Interval::kInf)}},
      {"contains", {&CreateFunContains, 2}},
      {"count", {&CreateFunCount, 1}},
      {"false", {&CreateFunFalse, 0}},
      {"floor", {&CreateFunFloor, 1}},
      {"id", {&CreateFunId, 1}},
      {"lang", {&CreateFunLang, 1}},
      {"last", {&CreateFunLast, 0}},
      {"local-name", {&CreateFunLocalName, Interval(0, 1)}},
      {"name", {&CreateFunName, Interval(0, 1)}},
      {"namespace-uri", {&CreateFunNamespaceURI, Interval(0, 1)}},
      {"normalize-space", {&CreateFunNormalizeSpace, Interval(0, 1)}},
      {"not", {&CreateFunNot, 1}},
      {"number", {&CreateFunNumber, Interval(0, 1)}},
      {"position", {&CreateFunPosition, 0}},
      {"round", {&CreateFunRound, 1}},
      {"starts-with", {&CreateFunStartsWith, 2}},
      {"string", {&CreateFunString, Interval(0, 1)}},
      {"string-length", {&CreateFunStringLength, Interval(0, 1)}},
      {"substring", {&CreateFunSubstring, Interval(2, 3)}},
      {"substring-after", {&CreateFunSubstringAfter, 2}},
      {"substring-before", {&CreateFunSubstringBefore, 2}},
      {"sum", {&CreateFunSum, 1}},
      {"translate", {&CreateFunTranslate, 3}},
      {"true", {&CreateFunTrue, 0}},
  };

  g_function_map = new HashMap<String, FunctionRec>;
  for (const auto& function : functions)
    g_function_map->Set(function.name, function.function);
}

Function* CreateFunction(const String& name) {
  HeapVector<Member<Expression>> args;
  return CreateFunction(name, args);
}

Function* CreateFunction(const String& name,
                         HeapVector<Member<Expression>>& args) {
  if (!g_function_map)
    CreateFunctionMap();

  HashMap<String, FunctionRec>::iterator function_map_iter =
      g_function_map->find(name);
  FunctionRec* function_rec = nullptr;

  if (function_map_iter == g_function_map->end() ||
      !(function_rec = &function_map_iter->value)->args.Contains(args.size()))
    return nullptr;

  Function* function = function_rec->factory_fn();
  function->SetArguments(args);
  function->SetName(name);
  return function;
}

}  // namespace blink::xpath

"""

```