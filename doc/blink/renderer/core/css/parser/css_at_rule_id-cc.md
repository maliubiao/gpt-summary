Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Understanding the Core Task:**

The request asks for an explanation of the functionality of the `css_at_rule_id.cc` file in the Chromium Blink engine. The core function seems to be identifying and categorizing CSS at-rules. The keyword "ID" in the filename strongly suggests a mapping or identification process.

**2. Initial Code Scan and Keyword Identification:**

I'd start by quickly scanning the code for key elements:

* **Includes:**  `css_parser_context.h`, `web_feature.h`, `use_counter.h`, `runtime_enabled_features.h`. These suggest the file is involved in parsing CSS, tracking features, and checking if certain experimental features are enabled.
* **Namespace:** `blink`. Confirms it's part of the Blink rendering engine.
* **Functions:** `CssAtRuleID(StringView name)`, `CssAtRuleIDToString(CSSAtRuleID id)`, `CountAtRule(const CSSParserContext* context, CSSAtRuleID rule_id)`. These are the main entry points for understanding the file's actions.
* **`CSSAtRuleID` Enum/Type:**  This is central. It represents the identified at-rule type.
* **`EqualIgnoringASCIICase`:**  Indicates case-insensitive string comparison, crucial for CSS parsing.
* **`RuntimeEnabledFeatures::...Enabled()`:**  Highlights feature gating – certain at-rules are only recognized if a corresponding flag is enabled.
* **`WebFeature` Enum:** Used for tracking usage of specific CSS features.
* **`UseCounter::Count`:** Confirms the file contributes to usage statistics.
* **`switch` statements:** Used for mapping between at-rule names (strings) and their `CSSAtRuleID` values, and vice-versa.

**3. Deconstructing `CssAtRuleID(StringView name)`:**

This function is the core identification logic.

* **Input:**  A `StringView` called `name`, representing the name of the at-rule (e.g., "media", "keyframes").
* **Logic:**  A series of `if` statements using `EqualIgnoringASCIICase` to compare the input `name` against known at-rule names.
* **Conditional Feature Checks:** The `RuntimeEnabledFeatures::...Enabled()` checks are important. This means some at-rules are only recognized if the corresponding feature is enabled in the browser. This points to experimental or non-standard CSS features.
* **Output:** Returns a value of the `CSSAtRuleID` enum, representing the identified at-rule. If no match is found, it defaults to `CSSAtRuleID::kCSSAtRuleInvalid`.

**4. Deconstructing `CssAtRuleIDToString(CSSAtRuleID id)`:**

This is the reverse of the previous function.

* **Input:** A `CSSAtRuleID` value.
* **Logic:** A `switch` statement maps each `CSSAtRuleID` value back to its corresponding string representation (the at-rule name).
* **Output:** A `StringView` containing the at-rule name (e.g., "@media", "@keyframes").
* **`NOTREACHED()`:**  This indicates a potential programming error. Ideally, all valid `CSSAtRuleID` values should be handled.

**5. Deconstructing `CountAtRule(const CSSParserContext* context, CSSAtRuleID rule_id)`:**

This function is for tracking usage.

* **Input:** A `CSSParserContext` (likely containing information about the parsing process) and a `CSSAtRuleID`.
* **Logic:**  It calls the internal `AtRuleFeature` function (namespace-scoped) to get the corresponding `WebFeature` enum value for the given `CSSAtRuleID`. If a `WebFeature` exists, it then calls `context->Count(*feature)` to record the usage of that feature.
* **Output:**  None explicitly, but it has the side effect of incrementing usage counters.

**6. Analyzing the `AtRuleFeature` Helper Function:**

This function connects the `CSSAtRuleID` to a specific `WebFeature`. This is how the system knows *what* feature is being used when a particular at-rule is encountered.

**7. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This involves understanding how CSS at-rules are used in web development:

* **CSS:** The most direct connection. At-rules are fundamental constructs in CSS.
* **HTML:**  CSS is applied to HTML elements through `<style>` tags, linked stylesheets, and inline styles. The parser encounters these at-rules while processing CSS.
* **JavaScript:** JavaScript can dynamically manipulate CSS styles, including adding or modifying stylesheets that contain at-rules. It can also query the computed styles of elements, which involves understanding the effect of at-rules.

**8. Constructing Examples and Scenarios:**

This is where I'd think about concrete uses of these at-rules and how they relate to the code:

* **Basic CSS usage:**  `@media`, `@keyframes`, `@import`, `@font-face`. These are common and straightforward.
* **Feature gating:**  `@view-transition` being dependent on `ViewTransitionOnNavigationEnabled()`. This demonstrates how new or experimental features are controlled.
* **User errors:** Incorrectly spelling at-rule names, or using at-rules that are not supported in the current browser (or without the necessary flags enabled).

**9. Thinking About Debugging:**

The path to this code usually involves the CSS parsing process. When the browser encounters an at-rule in a stylesheet, the parser needs to identify it. This function is a key part of that identification process. The debugger scenario outlines a likely sequence of events.

**10. Structuring the Answer:**

Finally, I would organize the information into logical sections as presented in the initial example answer:  Functionality, Relationships, Logical Reasoning, User Errors, Debugging. This makes the explanation clear and easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the file directly *parses* the at-rule content. **Correction:** The code focuses on *identifying* the at-rule type, not parsing its content. The `CSSParserContext` suggests the broader parsing process.
* **Realization:** The `RuntimeEnabledFeatures` checks are crucial for understanding why certain at-rules might not be recognized in all situations. This should be emphasized.
* **Considering edge cases:** What happens with unknown at-rules? The code explicitly handles this with `kCSSAtRuleInvalid`.

By following these steps, combining code analysis with knowledge of web technologies, and thinking about common use cases and debugging scenarios,  a comprehensive explanation of the `css_at_rule_id.cc` file can be constructed.
这个文件 `blink/renderer/core/css/parser/css_at_rule_id.cc` 的主要功能是 **识别和分类 CSS at-rules (也称为 at-directives)**。 它接收一个表示 at-rule 名称的字符串，并将其映射到一个预定义的枚举类型 `CSSAtRuleID`。

以下是该文件的详细功能分解：

**1. At-rule 名称到 ID 的映射:**

* `CSSAtRuleID CssAtRuleID(StringView name)` 函数是该文件的核心。它接收一个 `StringView` 类型的参数 `name`，代表 CSS 规则中 `@` 符号后面的标识符，例如 "media"、"keyframes"、"import" 等。
* 函数内部通过一系列的 `if` 语句，使用 `EqualIgnoringASCIICase` 函数（忽略大小写）将输入的 `name` 与已知的 CSS at-rule 名称进行比较。
* 如果找到匹配的 at-rule 名称，则返回相应的 `CSSAtRuleID` 枚举值，例如 `CSSAtRuleID::kCSSAtRuleMedia` 代表 `@media` 规则。
* 如果输入的 `name` 与任何已知的 at-rule 名称都不匹配，则返回 `CSSAtRuleID::kCSSAtRuleInvalid`。
* **运行时特性开关:**  需要注意的是，某些 at-rule 的识别依赖于运行时特性开关的状态。例如，`@view-transition` 只有在 `RuntimeEnabledFeatures::ViewTransitionOnNavigationEnabled()` 返回 true 时才会被识别为 `CSSAtRuleID::kCSSAtRuleViewTransition`。这允许 Chromium 控制某些实验性或仍在开发中的 CSS 特性的启用。

**2. At-rule ID 到字符串的转换:**

* `StringView CssAtRuleIDToString(CSSAtRuleID id)` 函数的功能与 `CssAtRuleID` 函数相反。它接收一个 `CSSAtRuleID` 枚举值作为参数。
* 通过一个 `switch` 语句，将输入的 `CSSAtRuleID` 映射回其对应的字符串表示形式，例如 `CSSAtRuleID::kCSSAtRuleMedia` 会被转换回字符串 "@media"。

**3. 统计 At-rule 的使用情况:**

* `void CountAtRule(const CSSParserContext* context, CSSAtRuleID rule_id)` 函数用于统计特定 at-rule 的使用情况。
* 它首先调用内部的 `AtRuleFeature` 函数，根据 `CSSAtRuleID` 获取对应的 `WebFeature` 枚举值。
* 如果找到了对应的 `WebFeature`，则调用 `context->Count(*feature)`，这会将该特性的使用次数记录下来，用于 Chromium 的使用统计。

**与 JavaScript, HTML, CSS 的关系:**

该文件直接与 **CSS** 功能密切相关。它负责解析 CSS 样式表时识别不同的 at-rules。

* **CSS:**  当浏览器解析 CSS 样式表（无论是嵌入在 HTML 中的 `<style>` 标签内，还是通过 `<link>` 标签引入的外部样式表）时，遇到以 `@` 开头的规则时，就会调用这里的代码来识别是哪种类型的 at-rule。
    * **举例:** 当 CSS 解析器遇到 `@media screen and (max-width: 600px) { ... }` 时，会提取 "media" 字符串，并调用 `CssAtRuleID("media")`，该函数会返回 `CSSAtRuleID::kCSSAtRuleMedia`。

* **HTML:**  HTML 通过 `<style>` 标签或者 `<link>` 标签引入 CSS。浏览器在加载和解析 HTML 时，会遇到这些 CSS 代码，并触发 CSS 解析器的运行，从而间接地使用到这个文件。
    * **举例:**  在 HTML 中包含 `<style> @import "style.css"; </style>`，浏览器解析到 `@import` 时，会调用 `CssAtRuleID("import")`。

* **JavaScript:** JavaScript 可以动态地操作 CSS。例如，可以使用 JavaScript 创建新的 `<style>` 元素并添加到 DOM 中，或者修改现有样式表的内容。当这些操作涉及到添加或修改包含 at-rules 的 CSS 代码时，底层的 CSS 解析器会使用到这个文件。
    * **举例:**  JavaScript 代码 `document.styleSheets[0].insertRule("@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }", 0);`  在执行时，CSS 解析器会识别 "@keyframes" 并调用 `CssAtRuleID("keyframes")`。

**逻辑推理示例:**

**假设输入:** 字符串 "font-face"

**输出:** `CSSAtRuleID::kCSSAtRuleFontFace`

**推理过程:** `CssAtRuleID("font-face")` 函数会遍历一系列 `if` 语句，当执行到 `if (EqualIgnoringASCIICase(name, "font-face"))` 时，由于 "font-face" (输入) 和 "font-face" (比较值) 忽略大小写后相等，该条件成立，函数返回 `CSSAtRuleID::kCSSAtRuleFontFace`。

**用户或编程常见的使用错误:**

* **拼写错误:**  如果用户在 CSS 中错误地拼写了 at-rule 的名称，例如 `@mdeia` 而不是 `@media`，那么 `CssAtRuleID("mdeia")` 将不会匹配任何已知的 at-rule 名称，并返回 `CSSAtRuleID::kCSSAtRuleInvalid`。 这会导致 CSS 解析器无法正确理解该规则，可能会将其忽略或产生错误。
    * **例子:** 用户在 CSS 文件中写了 `@font-fase { ... }`，这将不会被识别为 `@font-face` 规则。
* **使用未支持的或需要特定标志的 at-rule:** 用户可能使用了浏览器当前版本不支持的 at-rule，或者使用了需要特定运行时特性开关才能启用的 at-rule。
    * **例子:**  在默认情况下，如果 `RuntimeEnabledFeatures::ViewTransitionOnNavigationEnabled()` 为 false，即使 CSS 中使用了 `@view-transition`，`CssAtRuleID("view-transition")` 也不会返回 `CSSAtRuleID::kCSSAtRuleViewTransition`。

**用户操作到达此处的调试线索:**

1. **用户编写 HTML、CSS 或使用 JavaScript 操作样式:** 用户在网页开发过程中，编写了包含 CSS at-rules 的样式代码。
2. **浏览器加载网页并解析 HTML:** 当用户访问包含这些代码的网页时，浏览器开始加载 HTML 文档。
3. **HTML 解析器遇到 `<style>` 标签或 `<link>` 标签:**  HTML 解析器解析到 `<style>` 标签内的 CSS 代码或者 `<link>` 标签引用的外部 CSS 文件。
4. **CSS 解析器开始解析 CSS 代码:**  Blink 引擎的 CSS 解析器开始读取和解析这些 CSS 代码。
5. **CSS 解析器遇到 `@` 符号:** 当解析器遇到以 `@` 开头的标识符时，它知道这是一个 at-rule。
6. **提取 at-rule 名称:** 解析器提取 `@` 符号后面的名称，例如 "media"、"keyframes" 等。
7. **调用 `CssAtRuleID` 函数:**  解析器调用 `blink::CssAtRuleID(name)` 函数，并将提取出的 at-rule 名称作为参数传递进去。
8. **`CssAtRuleID` 函数执行查找和匹配:**  该函数在内部进行字符串比较，以确定 at-rule 的类型。
9. **返回 `CSSAtRuleID`:** 函数返回相应的 `CSSAtRuleID` 枚举值。
10. **后续处理:**  CSS 解析器根据返回的 `CSSAtRuleID` 值，知道如何进一步解析和处理该 at-rule 的内容。

**调试线索:**

如果在调试 CSS 解析相关的错误，你可能需要关注以下几点，这些点可能最终会追踪到 `css_at_rule_id.cc` 文件：

* **CSS 解析错误信息:** 浏览器开发者工具的控制台可能会显示与 CSS 解析相关的错误信息，例如 "Invalid at-rule" 或 "Unknown at-rule"。
* **样式不生效:** 某些 CSS 规则没有按照预期生效，可能是因为 at-rule 没有被正确识别。
* **断点调试 CSS 解析器:**  在 Chromium 的源代码中，可以设置断点在 CSS 解析器的相关代码中，查看当遇到 `@` 符号时，提取出的名称是什么，以及 `CssAtRuleID` 函数的返回值。
* **检查运行时特性开关状态:** 如果涉及到实验性的 at-rule，需要检查相关的运行时特性开关是否已启用。

总而言之，`css_at_rule_id.cc` 文件在 Blink 引擎的 CSS 解析过程中扮演着至关重要的角色，它负责将 CSS at-rule 的字符串表示转换为内部的枚举类型，以便后续的解析和处理。

### 提示词
```
这是目录为blink/renderer/core/css/parser/css_at_rule_id.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/css_at_rule_id.h"

#include <optional>

#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

CSSAtRuleID CssAtRuleID(StringView name) {
  if (RuntimeEnabledFeatures::ViewTransitionOnNavigationEnabled() &&
      EqualIgnoringASCIICase(name, "view-transition")) {
    return CSSAtRuleID::kCSSAtRuleViewTransition;
  }
  if (EqualIgnoringASCIICase(name, "charset")) {
    return CSSAtRuleID::kCSSAtRuleCharset;
  }
  if (EqualIgnoringASCIICase(name, "font-face")) {
    return CSSAtRuleID::kCSSAtRuleFontFace;
  }
  if (EqualIgnoringASCIICase(name, "font-palette-values")) {
    return CSSAtRuleID::kCSSAtRuleFontPaletteValues;
  }
  if (EqualIgnoringASCIICase(name, "font-feature-values")) {
    return CSSAtRuleID::kCSSAtRuleFontFeatureValues;
  }
  if (EqualIgnoringASCIICase(name, "stylistic")) {
    return CSSAtRuleID::kCSSAtRuleStylistic;
  }
  if (EqualIgnoringASCIICase(name, "styleset")) {
    return CSSAtRuleID::kCSSAtRuleStyleset;
  }
  if (EqualIgnoringASCIICase(name, "character-variant")) {
    return CSSAtRuleID::kCSSAtRuleCharacterVariant;
  }
  if (EqualIgnoringASCIICase(name, "swash")) {
    return CSSAtRuleID::kCSSAtRuleSwash;
  }
  if (EqualIgnoringASCIICase(name, "ornaments")) {
    return CSSAtRuleID::kCSSAtRuleOrnaments;
  }
  if (EqualIgnoringASCIICase(name, "annotation")) {
    return CSSAtRuleID::kCSSAtRuleAnnotation;
  }
  if (EqualIgnoringASCIICase(name, "import")) {
    return CSSAtRuleID::kCSSAtRuleImport;
  }
  if (EqualIgnoringASCIICase(name, "keyframes")) {
    return CSSAtRuleID::kCSSAtRuleKeyframes;
  }
  if (EqualIgnoringASCIICase(name, "layer")) {
    return CSSAtRuleID::kCSSAtRuleLayer;
  }
  if (EqualIgnoringASCIICase(name, "media")) {
    return CSSAtRuleID::kCSSAtRuleMedia;
  }
  if (EqualIgnoringASCIICase(name, "namespace")) {
    return CSSAtRuleID::kCSSAtRuleNamespace;
  }
  if (EqualIgnoringASCIICase(name, "page")) {
    return CSSAtRuleID::kCSSAtRulePage;
  }
  if (EqualIgnoringASCIICase(name, "position-try")) {
    return CSSAtRuleID::kCSSAtRulePositionTry;
  }
  if (EqualIgnoringASCIICase(name, "property")) {
    return CSSAtRuleID::kCSSAtRuleProperty;
  }
  if (EqualIgnoringASCIICase(name, "container")) {
    return CSSAtRuleID::kCSSAtRuleContainer;
  }
  if (EqualIgnoringASCIICase(name, "counter-style")) {
    return CSSAtRuleID::kCSSAtRuleCounterStyle;
  }
  if (EqualIgnoringASCIICase(name, "scope")) {
    return CSSAtRuleID::kCSSAtRuleScope;
  }
  if (EqualIgnoringASCIICase(name, "supports")) {
    return CSSAtRuleID::kCSSAtRuleSupports;
  }
  if (EqualIgnoringASCIICase(name, "starting-style")) {
    return CSSAtRuleID::kCSSAtRuleStartingStyle;
  }
  if (EqualIgnoringASCIICase(name, "-webkit-keyframes")) {
    return CSSAtRuleID::kCSSAtRuleWebkitKeyframes;
  }

  if (RuntimeEnabledFeatures::PageMarginBoxesEnabled()) {
    // https://www.w3.org/TR/css-page-3/#syntax-page-selector
    if (EqualIgnoringASCIICase(name, "top-left-corner")) {
      return CSSAtRuleID::kCSSAtRuleTopLeftCorner;
    }
    if (EqualIgnoringASCIICase(name, "top-left")) {
      return CSSAtRuleID::kCSSAtRuleTopLeft;
    }
    if (EqualIgnoringASCIICase(name, "top-center")) {
      return CSSAtRuleID::kCSSAtRuleTopCenter;
    }
    if (EqualIgnoringASCIICase(name, "top-right")) {
      return CSSAtRuleID::kCSSAtRuleTopRight;
    }
    if (EqualIgnoringASCIICase(name, "top-right-corner")) {
      return CSSAtRuleID::kCSSAtRuleTopRightCorner;
    }
    if (EqualIgnoringASCIICase(name, "bottom-left-corner")) {
      return CSSAtRuleID::kCSSAtRuleBottomLeftCorner;
    }
    if (EqualIgnoringASCIICase(name, "bottom-left")) {
      return CSSAtRuleID::kCSSAtRuleBottomLeft;
    }
    if (EqualIgnoringASCIICase(name, "bottom-center")) {
      return CSSAtRuleID::kCSSAtRuleBottomCenter;
    }
    if (EqualIgnoringASCIICase(name, "bottom-right")) {
      return CSSAtRuleID::kCSSAtRuleBottomRight;
    }
    if (EqualIgnoringASCIICase(name, "bottom-right-corner")) {
      return CSSAtRuleID::kCSSAtRuleBottomRightCorner;
    }
    if (EqualIgnoringASCIICase(name, "left-top")) {
      return CSSAtRuleID::kCSSAtRuleLeftTop;
    }
    if (EqualIgnoringASCIICase(name, "left-middle")) {
      return CSSAtRuleID::kCSSAtRuleLeftMiddle;
    }
    if (EqualIgnoringASCIICase(name, "left-bottom")) {
      return CSSAtRuleID::kCSSAtRuleLeftBottom;
    }
    if (EqualIgnoringASCIICase(name, "right-top")) {
      return CSSAtRuleID::kCSSAtRuleRightTop;
    }
    if (EqualIgnoringASCIICase(name, "right-middle")) {
      return CSSAtRuleID::kCSSAtRuleRightMiddle;
    }
    if (EqualIgnoringASCIICase(name, "right-bottom")) {
      return CSSAtRuleID::kCSSAtRuleRightBottom;
    }
  }
  if (RuntimeEnabledFeatures::CSSFunctionsEnabled() &&
      EqualIgnoringASCIICase(name, "function")) {
    return CSSAtRuleID::kCSSAtRuleFunction;
  }
  if (RuntimeEnabledFeatures::CSSMixinsEnabled()) {
    if (EqualIgnoringASCIICase(name, "mixin")) {
      return CSSAtRuleID::kCSSAtRuleMixin;
    }
    if (EqualIgnoringASCIICase(name, "apply")) {
      return CSSAtRuleID::kCSSAtRuleApplyMixin;
    }
  }

  return CSSAtRuleID::kCSSAtRuleInvalid;
}

StringView CssAtRuleIDToString(CSSAtRuleID id) {
  switch (id) {
    case CSSAtRuleID::kCSSAtRuleViewTransition:
      return "@view-transition";
    case CSSAtRuleID::kCSSAtRuleCharset:
      return "@charset";
    case CSSAtRuleID::kCSSAtRuleFontFace:
      return "@font-face";
    case CSSAtRuleID::kCSSAtRuleFontPaletteValues:
      return "@font-palette-values";
    case CSSAtRuleID::kCSSAtRuleImport:
      return "@import";
    case CSSAtRuleID::kCSSAtRuleKeyframes:
      return "@keyframes";
    case CSSAtRuleID::kCSSAtRuleLayer:
      return "@layer";
    case CSSAtRuleID::kCSSAtRuleMedia:
      return "@media";
    case CSSAtRuleID::kCSSAtRuleNamespace:
      return "@namespace";
    case CSSAtRuleID::kCSSAtRulePage:
      return "@page";
    case CSSAtRuleID::kCSSAtRulePositionTry:
      return "@position-try";
    case CSSAtRuleID::kCSSAtRuleProperty:
      return "@property";
    case CSSAtRuleID::kCSSAtRuleContainer:
      return "@container";
    case CSSAtRuleID::kCSSAtRuleCounterStyle:
      return "@counter-style";
    case CSSAtRuleID::kCSSAtRuleScope:
      return "@scope";
    case CSSAtRuleID::kCSSAtRuleStartingStyle:
      return "@starting-style";
    case CSSAtRuleID::kCSSAtRuleSupports:
      return "@supports";
    case CSSAtRuleID::kCSSAtRuleWebkitKeyframes:
      return "@-webkit-keyframes";
    case CSSAtRuleID::kCSSAtRuleAnnotation:
      return "@annotation";
    case CSSAtRuleID::kCSSAtRuleCharacterVariant:
      return "@character-variant";
    case CSSAtRuleID::kCSSAtRuleFontFeatureValues:
      return "@font-feature-values";
    case CSSAtRuleID::kCSSAtRuleOrnaments:
      return "@ornaments";
    case CSSAtRuleID::kCSSAtRuleStylistic:
      return "@stylistic";
    case CSSAtRuleID::kCSSAtRuleStyleset:
      return "@styleset";
    case CSSAtRuleID::kCSSAtRuleSwash:
      return "@swash";
    case CSSAtRuleID::kCSSAtRuleTopLeftCorner:
      return "@top-left-corner";
    case CSSAtRuleID::kCSSAtRuleTopLeft:
      return "@top-left";
    case CSSAtRuleID::kCSSAtRuleTopCenter:
      return "@top-center";
    case CSSAtRuleID::kCSSAtRuleTopRight:
      return "@top-right";
    case CSSAtRuleID::kCSSAtRuleTopRightCorner:
      return "@top-right-corner";
    case CSSAtRuleID::kCSSAtRuleBottomLeftCorner:
      return "@bottom-left-corner";
    case CSSAtRuleID::kCSSAtRuleBottomLeft:
      return "@bottom-left";
    case CSSAtRuleID::kCSSAtRuleBottomCenter:
      return "@bottom-center";
    case CSSAtRuleID::kCSSAtRuleBottomRight:
      return "@bottom-right";
    case CSSAtRuleID::kCSSAtRuleBottomRightCorner:
      return "@bottom-right-corner";
    case CSSAtRuleID::kCSSAtRuleLeftTop:
      return "@left-top";
    case CSSAtRuleID::kCSSAtRuleLeftMiddle:
      return "@left-middle";
    case CSSAtRuleID::kCSSAtRuleLeftBottom:
      return "@left-bottom";
    case CSSAtRuleID::kCSSAtRuleRightTop:
      return "@right-top";
    case CSSAtRuleID::kCSSAtRuleRightMiddle:
      return "@right-middle";
    case CSSAtRuleID::kCSSAtRuleRightBottom:
      return "@right-bottom";
    case CSSAtRuleID::kCSSAtRuleFunction:
      return "@function";
    case CSSAtRuleID::kCSSAtRuleMixin:
      return "@mixin";
    case CSSAtRuleID::kCSSAtRuleApplyMixin:
      return "@apply";
    case CSSAtRuleID::kCSSAtRuleInvalid:
      NOTREACHED();
  };
}

namespace {

std::optional<WebFeature> AtRuleFeature(CSSAtRuleID rule_id) {
  switch (rule_id) {
    case CSSAtRuleID::kCSSAtRuleAnnotation:
      return WebFeature::kCSSAtRuleAnnotation;
    case CSSAtRuleID::kCSSAtRuleViewTransition:
      return WebFeature::kCSSAtRuleViewTransition;
    case CSSAtRuleID::kCSSAtRuleCharset:
      return WebFeature::kCSSAtRuleCharset;
    case CSSAtRuleID::kCSSAtRuleCharacterVariant:
      return WebFeature::kCSSAtRuleCharacterVariant;
    case CSSAtRuleID::kCSSAtRuleFontFace:
      return WebFeature::kCSSAtRuleFontFace;
    case CSSAtRuleID::kCSSAtRuleFontPaletteValues:
      return WebFeature::kCSSAtRuleFontPaletteValues;
    case CSSAtRuleID::kCSSAtRuleFontFeatureValues:
      return WebFeature::kCSSAtRuleFontFeatureValues;
    case CSSAtRuleID::kCSSAtRuleImport:
      return WebFeature::kCSSAtRuleImport;
    case CSSAtRuleID::kCSSAtRuleKeyframes:
      return WebFeature::kCSSAtRuleKeyframes;
    case CSSAtRuleID::kCSSAtRuleLayer:
      return WebFeature::kCSSCascadeLayers;
    case CSSAtRuleID::kCSSAtRuleMedia:
      return WebFeature::kCSSAtRuleMedia;
    case CSSAtRuleID::kCSSAtRuleNamespace:
      return WebFeature::kCSSAtRuleNamespace;
    case CSSAtRuleID::kCSSAtRulePage:
      return WebFeature::kCSSAtRulePage;
    case CSSAtRuleID::kCSSAtRuleTopLeftCorner:
    case CSSAtRuleID::kCSSAtRuleTopLeft:
    case CSSAtRuleID::kCSSAtRuleTopCenter:
    case CSSAtRuleID::kCSSAtRuleTopRight:
    case CSSAtRuleID::kCSSAtRuleTopRightCorner:
    case CSSAtRuleID::kCSSAtRuleBottomLeftCorner:
    case CSSAtRuleID::kCSSAtRuleBottomLeft:
    case CSSAtRuleID::kCSSAtRuleBottomCenter:
    case CSSAtRuleID::kCSSAtRuleBottomRight:
    case CSSAtRuleID::kCSSAtRuleBottomRightCorner:
    case CSSAtRuleID::kCSSAtRuleLeftTop:
    case CSSAtRuleID::kCSSAtRuleLeftMiddle:
    case CSSAtRuleID::kCSSAtRuleLeftBottom:
    case CSSAtRuleID::kCSSAtRuleRightTop:
    case CSSAtRuleID::kCSSAtRuleRightMiddle:
    case CSSAtRuleID::kCSSAtRuleRightBottom:
      return WebFeature::kCSSAtRulePageMargin;
    case CSSAtRuleID::kCSSAtRuleProperty:
      return WebFeature::kCSSAtRuleProperty;
    case CSSAtRuleID::kCSSAtRuleContainer:
      return WebFeature::kCSSAtRuleContainer;
    case CSSAtRuleID::kCSSAtRuleCounterStyle:
      return WebFeature::kCSSAtRuleCounterStyle;
    case CSSAtRuleID::kCSSAtRuleOrnaments:
      return WebFeature::kCSSAtRuleOrnaments;
    case CSSAtRuleID::kCSSAtRuleScope:
      return WebFeature::kCSSAtRuleScope;
    case CSSAtRuleID::kCSSAtRuleStartingStyle:
      return WebFeature::kCSSAtRuleStartingStyle;
    case CSSAtRuleID::kCSSAtRuleStyleset:
      return WebFeature::kCSSAtRuleStylistic;
    case CSSAtRuleID::kCSSAtRuleStylistic:
      return WebFeature::kCSSAtRuleStylistic;
    case CSSAtRuleID::kCSSAtRuleSwash:
      return WebFeature::kCSSAtRuleSwash;
    case CSSAtRuleID::kCSSAtRuleSupports:
      return WebFeature::kCSSAtRuleSupports;
    case CSSAtRuleID::kCSSAtRulePositionTry:
      return WebFeature::kCSSAnchorPositioning;
    case CSSAtRuleID::kCSSAtRuleWebkitKeyframes:
      return WebFeature::kCSSAtRuleWebkitKeyframes;
    case CSSAtRuleID::kCSSAtRuleFunction:
      return WebFeature::kCSSFunctions;
    case CSSAtRuleID::kCSSAtRuleMixin:
    case CSSAtRuleID::kCSSAtRuleApplyMixin:
      return WebFeature::kCSSMixins;
    case CSSAtRuleID::kCSSAtRuleInvalid:
      NOTREACHED();
  }
}

}  // namespace

void CountAtRule(const CSSParserContext* context, CSSAtRuleID rule_id) {
  if (std::optional<WebFeature> feature = AtRuleFeature(rule_id)) {
    context->Count(*feature);
  }
}

}  // namespace blink
```