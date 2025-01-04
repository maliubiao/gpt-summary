Response:
Let's break down the thought process for analyzing the `focusgroup_flags.cc` file.

1. **Understand the Goal:** The primary goal is to explain the functionality of this specific Chromium/Blink source code file. This involves identifying its purpose, its relationship to web technologies (HTML, CSS, JavaScript), potential user errors, and debugging strategies.

2. **Initial Scan and Keywords:**  Start by quickly reading through the code, looking for prominent keywords and structures. Notice terms like `FocusgroupFlags`, `ParseFocusgroup`, `extend`, `inline`, `block`, `grid`, `wrap`, `flow`, `ConsoleMessage`, and references to `Element` and `Document`. This gives a high-level idea that the file is involved in parsing and interpreting attributes related to focus behavior within a web page.

3. **Identify Core Functions:** The code contains two main functions:
    * `FindNearestFocusgroupAncestorFlags`: This strongly suggests a hierarchical search, likely looking up the DOM tree for an ancestor element that has defined focus group properties.
    * `ParseFocusgroup`: This function takes an `Element` and a string `input` (likely the value of a focus-related attribute) and returns a `FocusgroupFlags` object. This is the core parsing logic.

4. **Analyze `ParseFocusgroup` in Detail:** This is where the bulk of the logic resides. Go through the steps within the function:
    * **Input Parsing:** The code splits the input string by spaces and iterates through the tokens. It checks for keywords like "extend", "inline", "block", "grid", "wrap", and various combinations. This indicates it's parsing a space-separated list of focus group modifiers.
    * **Flag Setting:** Based on the parsed tokens, boolean flags (`has_extend`, `has_inline`, etc.) are set. These flags directly correspond to potential focus group behaviors.
    * **Error Handling (Console Messages):** The code includes numerous `element->GetDocument().AddConsoleMessage(...)` calls. This is a crucial aspect. It means the code actively checks for invalid or conflicting focus group attribute values and reports them to the browser's developer console. This is a direct link to helping developers debug their HTML.
    * **Extend Logic:** The code handles the "extend" keyword, which allows a focus group to inherit properties from an ancestor. It also checks for invalid extensions (e.g., extending a grid focus group).
    * **Grid Logic:** The code specifically handles the "grid" keyword and related "wrap" and "flow" variations. It enforces rules specific to grid focus groups.
    * **Linear Focus Group Logic:** If "grid" isn't present, it's treated as a linear focus group, with its own set of rules and handling of "inline" and "block".
    * **Wrap and Flow Logic:** The code determines how focus should wrap within the group (horizontally, vertically, or both) and the direction of focus traversal ("flow").
    * **Inheritance:**  The code handles the inheritance of wrap behavior when using "extend".

5. **Connect to Web Technologies:**  Now, explicitly link the code's functionality to HTML, CSS, and JavaScript:
    * **HTML:** The `focusgroup` attribute itself (or a similar attribute this code is designed to parse) would be directly embedded in HTML elements. The code parses the *values* of these attributes.
    * **CSS:** While this specific file doesn't directly *apply* CSS styles, the parsed `FocusgroupFlags` will likely influence how the browser renders and handles focus, which *can* be indirectly affected by CSS (e.g., `display: grid`).
    * **JavaScript:** JavaScript could be used to dynamically set or modify the `focusgroup` attribute (or its equivalent), triggering this parsing logic. JavaScript event listeners could also be used to observe or manipulate focus behavior within these groups.

6. **Hypothesize Inputs and Outputs:**  Create concrete examples. Think about different combinations of `focusgroup` attribute values and what the expected `FocusgroupFlags` would be. Include cases with errors to demonstrate the console message functionality.

7. **Identify User Errors:** Based on the error messages in the code, list common mistakes a web developer might make when using the `focusgroup` attribute.

8. **Trace User Actions:**  Imagine a user interacting with a web page and how those actions might lead to this code being executed. Focus on the sequence of events that involve focus movement.

9. **Debugging Strategies:** Think about how a developer could use the information in this file (and the console messages it generates) to debug focus-related issues.

10. **Structure the Explanation:** Organize the findings logically, starting with a general overview of the file's purpose and then diving into specifics. Use clear headings and examples to make the explanation easy to understand.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file probably just sets some flags."  **Correction:** Realize it's more complex, involving parsing, validation, and inheritance.
* **Misinterpretation:**  Initially might think it directly manipulates focus. **Correction:** Understand it *parses the instructions* that will later be used by other parts of the engine to manage focus.
* **Overlooking detail:** Might miss the different types of focus groups (linear vs. grid). **Correction:** Pay close attention to the conditional logic related to the "grid" keyword.
* **Vague connection to web techs:** Simply stating "it's related to HTML." **Correction:** Provide specific examples of how the attribute would be used in HTML.

By following these steps and continuously refining the understanding through close examination of the code, a comprehensive and accurate explanation can be generated.
这是 `blink/renderer/core/dom/focusgroup_flags.cc` 文件的功能分析：

**功能概述:**

该文件定义了与 HTML 元素的 `focusgroup` 属性相关的解析和标志管理逻辑。其主要功能是：

1. **解析 `focusgroup` 属性值:**  该文件中的 `ParseFocusgroup` 函数负责解析 HTML 元素上 `focusgroup` 属性的字符串值。这个字符串值可以包含多个以空格分隔的关键词，用于指定 focusgroup 的行为方式。
2. **管理 Focusgroup 标志:**  `ParseFocusgroup` 函数根据解析出的关键词，设置 `FocusgroupFlags` 枚举类型的标志。这些标志用于表示 focusgroup 的各种特性，例如是否可以扩展自父 focusgroup，以及在哪个方向上进行焦点导航（行内、块级、或者两者都支持）。
3. **提供查找最近父 Focusgroup 的功能:** `FindNearestFocusgroupAncestorFlags` 函数用于在 DOM 树中向上查找最近的祖先元素，并且该祖先元素具有非空的 `focusgroup` 标志。这用于实现 `extend` 关键词的功能，允许子 focusgroup 继承父 focusgroup 的某些特性。
4. **提供错误和警告信息:** 当解析 `focusgroup` 属性时遇到无效的关键词或配置冲突时，该文件会向浏览器的开发者控制台输出错误或警告信息，帮助开发者调试。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**
    * **关系：**  该文件直接处理 HTML 元素的 `focusgroup` 属性。HTML 中使用该属性来定义和配置 focusgroup。
    * **举例：**
        ```html
        <div focusgroup="inline wrap">第一个焦点组</div>
        <div focusgroup="block extend">第二个焦点组，继承父级的特性</div>
        <table focusgroup="grid row-wrap">表格焦点组</table>
        ```
        当浏览器解析到这些 HTML 元素时，会调用 `ParseFocusgroup` 函数来解析 `focusgroup` 属性的值，并设置相应的 `FocusgroupFlags`。

* **JavaScript:**
    * **关系：** JavaScript 可以读取和修改 HTML 元素的 `focusgroup` 属性。通过 JavaScript 修改该属性，会触发 `ParseFocusgroup` 函数的重新解析。
    * **举例：**
        ```javascript
        const element = document.querySelector('#myElement');
        element.setAttribute('focusgroup', 'block flow');
        ```
        这段 JavaScript 代码将 `id` 为 `myElement` 的元素的 `focusgroup` 属性设置为 "block flow"。浏览器会重新解析该属性值。

* **CSS:**
    * **关系：**  虽然此文件本身不直接处理 CSS，但 `focusgroup` 的概念和其行为（例如焦点导航）会影响元素的布局和渲染，这与 CSS 相关。例如，一个 `focusgroup="grid"` 的元素可能需要配合特定的 CSS 布局来实现预期的焦点导航行为。
    * **举例：**  CSS 可以用来视觉上区分不同的 focusgroup，或者修改焦点元素的样式，但 CSS 本身不参与 `focusgroup` 属性的解析和逻辑处理。

**逻辑推理、假设输入与输出:**

**假设输入:**  一个 HTML 元素及其 `focusgroup` 属性值。

**场景 1：简单线性 focusgroup**

* **输入:** `<div focusgroup="inline"></div>`
* **输出 (FocusgroupFlags):** `FocusgroupFlags::kInline | FocusgroupFlags::kWrapInline` (假设默认会开启 wrap)
* **推理:** 解析到 "inline"，设置 `kInline` 标志。因为没有明确指定 "wrap" 或 "flow"，且是线性 focusgroup，默认会开启行内方向的 wrap。

**场景 2：扩展自父 focusgroup**

* **假设输入:**
    ```html
    <div focusgroup="block wrap" id="parent">
        <button>Parent Button</button>
        <div focusgroup="extend inline" id="child">
            <button>Child Button</button>
        </div>
    </div>
    ```
* **解析父元素 "parent" 的输出 (FocusgroupFlags):** `FocusgroupFlags::kBlock | FocusgroupFlags::kWrapBlock`
* **解析子元素 "child" 的输出 (FocusgroupFlags):** `FocusgroupFlags::kExtend | FocusgroupFlags::kInline | FocusgroupFlags::kWrapInline`
* **推理:**
    * 解析父元素时，"block" 设置 `kBlock`，"wrap" 设置 `kWrapBlock`。
    * 解析子元素时，"extend" 设置 `kExtend`，并且会调用 `FindNearestFocusgroupAncestorFlags` 找到父元素的标志。 "inline" 设置 `kInline`。因为父元素是块级 wrap，子元素是行内，所以子元素会开启行内 wrap。

**场景 3：无效的 focusgroup 属性值**

* **输入:** `<div focusgroup="invalid-token inline"></div>`
* **输出 (FocusgroupFlags):** `FocusgroupFlags::kInline | FocusgroupFlags::kWrapInline`
* **副作用:**  控制台会输出错误信息："Unrecognized focusgroup attribute values: invalid-token"
* **推理:**  解析到 "invalid-token" 时，会将其识别为无效，并输出错误信息。 "inline" 依然会被正确解析。

**用户或编程常见的使用错误:**

1. **拼写错误或使用无效关键词:**
   * **例子:** `<div focusgroup="inlien"></div>` (拼写错误) 或 `<div focusgroup="center"></div>` (无效关键词)
   * **结果:**  `ParseFocusgroup` 会输出 "Unrecognized focusgroup attribute values: inlien" 或 "Unrecognized focusgroup attribute values: center" 到控制台，并且该无效关键词不会产生任何效果。

2. **在 grid focusgroup 中使用线性布局相关的关键词:**
   * **例子:** `<table focusgroup="grid inline"></table>`
   * **结果:** `ParseFocusgroup` 会输出错误信息："Focusgroup attribute value 'inline' present, but has no effect on grid focusgroups."，表示 "inline" 在 grid focusgroup 中无效。

3. **在非 grid focusgroup 中使用 grid 相关的关键词:**
   * **例子:** `<div focusgroup="row-wrap"></div>`
   * **结果:** `ParseFocusgroup` 会输出错误信息："Focusgroup attribute value 'row-wrap' present, but has no effect on linear focusgroups."

4. **`extend` 关键词但没有父 focusgroup:**
   * **例子:**
     ```html
     <div focusgroup="extend"></div>
     ```
   * **结果:** `ParseFocusgroup` 会输出错误信息："Focusgroup attribute value 'extend' present, but no parent focusgroup found. Ignoring 'extend'."

5. **`extend` 关键词但父 focusgroup 是 grid 类型:**
   * **例子:**
     ```html
     <table focusgroup="grid">
         <div focusgroup="extend"></div>
     </table>
     ```
   * **结果:** `ParseFocusgroup` 会输出错误信息："Focusgroup attribute value 'extend' present, but grid focusgroups cannot be extended. Ignoring focusgroup."

6. **同时使用冲突的关键词:**
   * **例子:** `<div focusgroup="inline block"></div>`
   * **结果:** `ParseFocusgroup` 会输出警告信息："'inline' and 'block' focusgroup attribute values used together are redundant (this is the default behavior) and can be omitted."

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在 HTML 中编写了带有 `focusgroup` 属性的元素。**
2. **浏览器加载并解析 HTML 文档。**
3. **当解析器遇到带有 `focusgroup` 属性的元素时，会调用 Blink 渲染引擎的相关代码来处理该属性。**
4. **Blink 渲染引擎会创建或更新该元素的表示 (Element 对象)。**
5. **在处理 `focusgroup` 属性时，会调用 `element->GetFocusgroupFlags()` 方法，或者在属性值发生变化时，会调用 `ParseFocusgroup(element, attribute_value)` 函数。**
6. **`ParseFocusgroup` 函数会根据 `focusgroup` 属性的值进行解析，并设置 `FocusgroupFlags`。**
7. **如果解析过程中发现错误或警告，会通过 `element->GetDocument().AddConsoleMessage(...)` 将信息输出到浏览器的开发者控制台。**

**作为调试线索:**

* **查看控制台输出:** 如果用户报告了与焦点导航相关的奇怪行为，开发者可以首先检查浏览器的开发者控制台，查看是否有与 "focusgroup" 相关的错误或警告信息。这些信息通常能直接指出 `focusgroup` 属性值中的问题。
* **检查元素的 `focusgroup` 属性值:** 使用浏览器的开发者工具，检查相关元素的 `focusgroup` 属性值，确认其是否符合预期，是否存在拼写错误或使用了不适用的关键词。
* **逐步测试 `focusgroup` 的效果:**  可以尝试修改 `focusgroup` 属性值，观察焦点导航行为的变化，逐步理解不同关键词的作用。
* **检查父元素的 `focusgroup` 属性 (如果使用了 `extend`):**  如果一个 focusgroup 使用了 `extend` 关键词，需要检查其父元素的 `focusgroup` 属性，确保父元素存在并且类型允许被扩展。
* **理解 `FocusgroupFlags` 的含义:**  虽然开发者通常不需要直接操作 `FocusgroupFlags`，但了解这些标志的含义可以帮助理解 `focusgroup` 属性值是如何被解析和应用的。

总而言之，`blink/renderer/core/dom/focusgroup_flags.cc` 文件是 Blink 渲染引擎中处理 HTML `focusgroup` 属性的核心部分，负责解析属性值、管理焦点组的特性标志，并提供错误和警告信息，帮助开发者正确使用该属性。

Prompt: 
```
这是目录为blink/renderer/core/dom/focusgroup_flags.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/focusgroup_flags.h"

#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/space_split_string.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink::focusgroup {

FocusgroupFlags FindNearestFocusgroupAncestorFlags(const Element* element) {
  Element* ancestor = FlatTreeTraversal::ParentElement(*element);
  while (ancestor) {
    FocusgroupFlags ancestor_flags = ancestor->GetFocusgroupFlags();
    // When this is true, we found the focusgroup to extend.
    if (ancestor_flags != FocusgroupFlags::kNone) {
      return ancestor_flags;
    }
    ancestor = FlatTreeTraversal::ParentElement(*ancestor);
  }
  return FocusgroupFlags::kNone;
}

FocusgroupFlags ParseFocusgroup(const Element* element,
                                const AtomicString& input) {
  DCHECK(element);
  ExecutionContext* context = element->GetExecutionContext();
  DCHECK(RuntimeEnabledFeatures::FocusgroupEnabled(context));

  UseCounter::Count(context, WebFeature::kFocusgroup);

  // 1. Parse the input.
  bool has_extend = false;
  bool has_inline = false;
  bool has_block = false;
  bool has_grid = false;
  bool has_wrap = false;
  bool has_row_wrap = false;
  bool has_col_wrap = false;
  bool has_flow = false;
  bool has_row_flow = false;
  bool has_col_flow = false;
  StringBuilder invalid_tokens;

  SpaceSplitString tokens(input);
  for (unsigned i = 0; i < tokens.size(); i++) {
    AtomicString lowercase_token = tokens[i].LowerASCII();
    if (lowercase_token == "extend") {
      has_extend = true;
    } else if (lowercase_token == "inline") {
      has_inline = true;
    } else if (lowercase_token == "block") {
      has_block = true;
    } else if (lowercase_token == "grid") {
      has_grid = true;
    } else if (lowercase_token == "wrap") {
      has_wrap = true;
    } else if (lowercase_token == "row-wrap") {
      has_row_wrap = true;
    } else if (lowercase_token == "col-wrap") {
      has_col_wrap = true;
    } else if (lowercase_token == "flow") {
      has_flow = true;
    } else if (lowercase_token == "row-flow") {
      has_row_flow = true;
    } else if (lowercase_token == "col-flow") {
      has_col_flow = true;
    } else {
      if (!invalid_tokens.empty())
        invalid_tokens.Append(", ");

      // We don't use |lowercase_token| here since that string value will be
      // logged in the console and we want it to match the input.
      invalid_tokens.Append(tokens[i]);
    }
  }

  if (!invalid_tokens.empty()) {
    element->GetDocument().AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kOther,
            mojom::blink::ConsoleMessageLevel::kError,
            "Unrecognized focusgroup attribute values: " +
                invalid_tokens.ReleaseString()));
  }

  FocusgroupFlags flags = FocusgroupFlags::kNone;

  // 2. Apply the extend logic. A focusgroup can extend another one explicitly
  // when the author specifies "extend" or implicitly when a focusgroup has the
  // "gridcells" role.
  FocusgroupFlags ancestor_flags = FocusgroupFlags::kNone;
  if (has_extend) {
    // Focusgroups should only be allowed to extend when they have a focusgroup
    // ancestor and the focusgroup ancestor isn't a grid focusgroup.
    ancestor_flags = FindNearestFocusgroupAncestorFlags(element);
    if (ancestor_flags != FocusgroupFlags::kNone) {
      flags |= FocusgroupFlags::kExtend;
      if (ancestor_flags & FocusgroupFlags::kGrid) {
        element->GetDocument().AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::blink::ConsoleMessageSource::kOther,
                mojom::blink::ConsoleMessageLevel::kError,
                "Focusgroup attribute value 'extend' present, but grid "
                "focusgroups cannot be extended. Ignoring focusgroup."));
        return FocusgroupFlags::kNone;
      }
    } else {
      element->GetDocument().AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kOther,
              mojom::blink::ConsoleMessageLevel::kError,
              "Focusgroup attribute value 'extend' present, but no parent "
              "focusgroup found. Ignoring 'extend'."));
    }
  }

  // 3. Apply the grid focusgroup logic:
  //     * 'grid' can only be set on an HTML table element.
  //     * The grid-related wrap/flown can only be set on a grid focusgroup.
  if (has_grid) {
    if (has_extend) {
      element->GetDocument().AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kOther,
              mojom::blink::ConsoleMessageLevel::kError,
              "Focusgroup attribute values 'extend' and 'grid' present, but "
              "grid focusgroup cannot extend. Ignoring focusgroup."));
      return FocusgroupFlags::kNone;
    }

    flags |= FocusgroupFlags::kGrid;

    // Set the wrap/flow flags, if specified.
    if (has_wrap) {
      flags |= FocusgroupFlags::kWrapInline | FocusgroupFlags::kWrapBlock;
      if (has_row_wrap) {
        element->GetDocument().AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::blink::ConsoleMessageSource::kOther,
                mojom::blink::ConsoleMessageLevel::kWarning,
                "Focusgroup attribute value 'row-wrap' present, but can be "
                "omitted because focusgroup already wraps in both axes."));
      }
      if (has_col_wrap) {
        element->GetDocument().AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::blink::ConsoleMessageSource::kOther,
                mojom::blink::ConsoleMessageLevel::kWarning,
                "Focusgroup attribute value 'col-wrap' present, but can be "
                "omitted because focusgroup already wraps in both axes."));
      }
    } else {
      if (has_row_wrap)
        flags |= FocusgroupFlags::kWrapInline;
      if (has_col_wrap)
        flags |= FocusgroupFlags::kWrapBlock;

      if (has_row_wrap && has_col_wrap) {
        element->GetDocument().AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::blink::ConsoleMessageSource::kOther,
                mojom::blink::ConsoleMessageLevel::kWarning,
                "Focusgroup attribute values 'row-wrap col-wrap' should be "
                "replaced by 'wrap'."));
      }
    }

    if (has_flow) {
      if (flags & FocusgroupFlags::kWrapInline ||
          flags & FocusgroupFlags::kWrapBlock) {
        element->GetDocument().AddConsoleMessage(MakeGarbageCollected<
                                                 ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kOther,
            mojom::blink::ConsoleMessageLevel::kError,
            "Focusgroup attribute value 'flow' present, but focusgroup already "
            "set to wrap in at least one axis."));
      } else {
        flags |= FocusgroupFlags::kRowFlow | FocusgroupFlags::kColFlow;
        if (has_row_flow) {
          element->GetDocument().AddConsoleMessage(
              MakeGarbageCollected<ConsoleMessage>(
                  mojom::blink::ConsoleMessageSource::kOther,
                  mojom::blink::ConsoleMessageLevel::kWarning,
                  "Focusgroup attribute value 'row-flow' present, but can be "
                  "omitted because focusgroup already flows in both axes."));
        }
        if (has_col_flow) {
          element->GetDocument().AddConsoleMessage(
              MakeGarbageCollected<ConsoleMessage>(
                  mojom::blink::ConsoleMessageSource::kOther,
                  mojom::blink::ConsoleMessageLevel::kWarning,
                  "Focusgroup attribute value 'col-flow' present, but can be "
                  "omitted because focusgroup already flows in both axes."));
        }
      }
    } else {
      if (has_row_flow) {
        if (flags & FocusgroupFlags::kWrapInline) {
          element->GetDocument().AddConsoleMessage(
              MakeGarbageCollected<ConsoleMessage>(
                  mojom::blink::ConsoleMessageSource::kOther,
                  mojom::blink::ConsoleMessageLevel::kError,
                  "Focusgroup attribute value 'row-flow' present, but "
                  "focusgroup already wraps in the row axis."));
        } else {
          flags |= FocusgroupFlags::kRowFlow;
        }
      }
      if (has_col_flow) {
        if (flags & FocusgroupFlags::kWrapBlock) {
          element->GetDocument().AddConsoleMessage(
              MakeGarbageCollected<ConsoleMessage>(
                  mojom::blink::ConsoleMessageSource::kOther,
                  mojom::blink::ConsoleMessageLevel::kError,
                  "Focusgroup attribute value 'col-flow' present, but "
                  "focusgroup already wraps in the column axis."));
        } else {
          flags |= FocusgroupFlags::kColFlow;
        }
      }
      if (flags & FocusgroupFlags::kRowFlow &&
          flags & FocusgroupFlags::kColFlow) {
        element->GetDocument().AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::blink::ConsoleMessageSource::kOther,
                mojom::blink::ConsoleMessageLevel::kWarning,
                "Focusgroup attribute values 'row-flow col-flow' should be "
                "replaced by 'flow'."));
      }
    }

    // These values are reserved for linear focusgroups.
    if (has_inline) {
      element->GetDocument().AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kOther,
              mojom::blink::ConsoleMessageLevel::kError,
              "Focusgroup attribute value 'inline' present, but has no effect "
              "on grid focusgroups."));
    }
    if (has_block) {
      element->GetDocument().AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kOther,
              mojom::blink::ConsoleMessageLevel::kError,
              "Focusgroup attribute value 'block' present, but has no effect "
              "on grid focusgroups."));
    }

    return flags;
  }

  // At this point, we are necessarily in a linear focusgroup. Any grid
  // focusgroup should have returned above.

  if (has_row_wrap) {
    element->GetDocument().AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kOther,
            mojom::blink::ConsoleMessageLevel::kError,
            "Focusgroup attribute value 'row-wrap' present, but has no effect "
            "on linear focusgroups."));
  }
  if (has_col_wrap) {
    element->GetDocument().AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kOther,
            mojom::blink::ConsoleMessageLevel::kError,
            "Focusgroup attribute value 'col-wrap' present, but has no effect "
            "on linear focusgroups."));
  }
  if (has_flow) {
    element->GetDocument().AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kOther,
            mojom::blink::ConsoleMessageLevel::kError,
            "Focusgroup attribute value 'flow' present, but has no effect on "
            "linear focusgroups."));
  }
  if (has_row_flow) {
    element->GetDocument().AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kOther,
            mojom::blink::ConsoleMessageLevel::kError,
            "Focusgroup attribute value 'row-flow' present, but has no effect "
            "on linear focusgroups."));
  }
  if (has_col_flow) {
    element->GetDocument().AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kOther,
            mojom::blink::ConsoleMessageLevel::kError,
            "Focusgroup attribute value 'col-flow' present, but has no effect "
            "on linear focusgroups."));
  }

  // 4. Set the axis supported on that focusgroup.
  if (has_inline) {
    flags |= FocusgroupFlags::kInline;
  }
  if (has_block) {
    flags |= FocusgroupFlags::kBlock;
  }

  // When no axis is specified, it means that the focusgroup should handle
  // both.
  if (!has_inline && !has_block) {
    flags |= FocusgroupFlags::kInline | FocusgroupFlags::kBlock;
  }

  if (has_inline && has_block) {
    element->GetDocument().AddConsoleMessage(MakeGarbageCollected<
                                             ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kWarning,
        "'inline' and 'block' focusgroup attribute values used together "
        "are redundant (this is the default behavior) and can be omitted."));
  }

  // 6. Determine in what axis a focusgroup should wrap. This needs to be
  // performed once the supported axes are final.
  if (has_wrap) {
    if (flags & FocusgroupFlags::kExtend) {
      bool extends_inline = flags & FocusgroupFlags::kInline &&
                            ancestor_flags & FocusgroupFlags::kInline;
      if (!extends_inline && flags & FocusgroupFlags::kInline) {
        flags |= FocusgroupFlags::kWrapInline;
      }
      bool extends_block = flags & FocusgroupFlags::kBlock &&
                           ancestor_flags & FocusgroupFlags::kBlock;
      if (!extends_block && flags & FocusgroupFlags::kBlock) {
        flags |= FocusgroupFlags::kWrapBlock;
      }

      if (extends_inline && extends_block) {
        element->GetDocument().AddConsoleMessage(MakeGarbageCollected<
                                                 ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kOther,
            mojom::blink::ConsoleMessageLevel::kWarning,
            "Focusgroup attribute value 'wrap' present but ignored. 'wrap' has "
            "no effect when set on a focusgroup that extends another one in "
            "both axes."));
      }
    } else {
      if (flags & FocusgroupFlags::kInline) {
        flags |= FocusgroupFlags::kWrapInline;
      }
      if (flags & FocusgroupFlags::kBlock) {
        flags |= FocusgroupFlags::kWrapBlock;
      }
    }
  }

  // When a focusgroup extends another one, inherit the ancestor's wrap behavior
  // for the descendant's supported axes.
  if (flags & FocusgroupFlags::kExtend) {
    DCHECK(ancestor_flags != FocusgroupFlags::kNone);
    if ((flags & FocusgroupFlags::kWrapInline) ==
            (ancestor_flags & FocusgroupFlags::kWrapInline) &&
        (flags & FocusgroupFlags::kWrapBlock) ==
            (ancestor_flags & FocusgroupFlags::kWrapBlock)) {
      element->GetDocument().AddConsoleMessage(MakeGarbageCollected<
                                               ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kOther,
          mojom::blink::ConsoleMessageLevel::kWarning,
          "Focusgroup attribute value 'wrap' present but ignored. 'wrap' is "
          "inherited from the extended parent focusgroup."));
    }
    if (flags & FocusgroupFlags::kInline) {
      flags |= (ancestor_flags & FocusgroupFlags::kWrapInline);
    }
    if (flags & FocusgroupFlags::kBlock) {
      flags |= (ancestor_flags & FocusgroupFlags::kWrapBlock);
    }
  }

  return flags;
}

}  // namespace blink::focusgroup

"""

```