Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The request asks for a functional overview of a specific C++ source file (`css_parsing_utils.cc`) within the Chromium Blink engine. It also asks for connections to web technologies (JavaScript, HTML, CSS), examples, logical reasoning explanations, common errors, debugging steps, and a summary as the 8th part of a 9-part series.

2. **Initial Analysis of the Code Snippet:** I scanned the provided code, noting the function names and their signatures. Keywords like `Consume`, `Grid`, `Template`, `Path`, `Transform`, `Transition`, `Border`, etc., immediately suggest the file deals with parsing CSS property values. The presence of `CSSParserTokenStream` and `CSSParserContext` reinforces this idea.

3. **Categorize Functionality:** I mentally grouped the functions based on the CSS properties or concepts they seemed to handle. This resulted in categories like:
    * **Grid Layout:** `ConsumeGridLine`, `ConsumeGridTemplateShorthand`
    * **Shapes and Paths:** `ConsumeMasonrySlack`, `ConsumePathStringArg`, `ConsumeBasicShapePath`, `ConsumePathFunction`, `ConsumeRay`, `ConsumeBasicShape`
    * **Box Model and Sizing:** `ConsumeMaxWidthOrHeight`, `ConsumeWidthOrHeight`, `ConsumeMarginOrOffset`, `ConsumeScrollPadding`, `ConsumeScrollStart`
    * **Text Properties:** `ConsumeHyphenateLimitChars`, `ConsumeTextDecorationLine`, `ConsumeTextBoxEdge`, `ConsumeTextBoxTrim`, `ConsumeAutospace`, `ConsumeSpacingTrim`, `ConsumeInitialLetter`
    * **Break Properties:** `ConsumeFromPageBreakBetween`, `ConsumeFromColumnBreakBetween`, `ConsumeFromColumnOrPageBreakInside`
    * **Transforms:** `ConsumeTransformValue`, `ConsumeTransformList`
    * **Transitions:** `ConsumeTransitionProperty`, `IsValidPropertyList`, `IsValidTransitionBehavior`, `IsValidTransitionBehaviorList`
    * **Borders:** `ConsumeBorderColorSide`, `ConsumeBorderWidth`
    * **Containers:** `ConsumeSingleContainerName` (the snippet ends mid-function)
    * **Generic Value Consumption:**  Functions that consume specific CSS value types like angles, lengths, identifiers, etc. (implicitly present in the calls to other `Consume` functions).

4. **Identify Connections to Web Technologies:**
    * **CSS:**  The file's primary purpose is parsing CSS values. Every function directly relates to a specific CSS property or value type. I could link specific functions to corresponding CSS properties (e.g., `ConsumeGridTemplateShorthand` to the `grid-template` property).
    * **HTML:** While not directly parsing HTML, the parsed CSS styles are applied to HTML elements. I needed to provide examples of how these CSS properties would be used in HTML (e.g., using `grid-template` on a `div`).
    * **JavaScript:** JavaScript can interact with CSS in several ways. It can dynamically modify CSS properties using the CSSOM, which relies on the parsing logic in this file. I included examples of JavaScript setting styles (e.g., `element.style.gridTemplate = ...`).

5. **Generate Examples and Logical Reasoning:** For each category, I thought of simple CSS examples and how the corresponding `Consume` function would process them. For logical reasoning, I considered what input the function expects and what output it produces (e.g., for `ConsumeGridLine`, inputting a valid grid line name should output a `CSSValue`).

6. **Identify Common Errors:** Based on my understanding of CSS syntax and common developer mistakes, I listed potential errors related to the parsing functions (e.g., incorrect syntax for grid templates, invalid path strings).

7. **Outline Debugging Steps:** I described a typical debugging flow, starting from user interaction, navigating through browser internals, and potentially reaching the CSS parsing stage.

8. **Synthesize the Summary (Part 8 of 9):**  I focused on the overarching role of the file in CSS parsing and its contribution to the rendering engine. Given it's part 8 of 9, I emphasized its function within the broader process.

9. **Refine and Organize:** I structured the answer logically, using headings and bullet points for readability. I ensured that each part of the request was addressed clearly and concisely. I also reviewed the examples to make sure they were accurate and illustrative.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on the low-level C++ details.
* **Correction:** Shift focus to the *functionality* and its impact on web technologies. The request is about *what* it does, not necessarily *how* in extreme detail.
* **Initial thought:**  Provide very technical, code-heavy examples.
* **Correction:** Simplify examples to be more understandable for a broader audience, including those less familiar with Blink internals. Focus on the *CSS* perspective.
* **Initial thought:**  Treat each `Consume` function in isolation.
* **Correction:** Recognize that these functions work together as a system for parsing complex CSS values. Highlight this interconnectedness in the summary.
* **Realization:** The prompt explicitly asked for *assumptions* in logical reasoning. I made sure to explicitly state the input and expected output as assumptions.

By following these steps and iteratively refining my understanding and the generated content, I aimed to provide a comprehensive and accurate answer to the request.
这是第8部分，共9部分，关于 `blink/renderer/core/css/properties/css_parsing_utils.cc` 文件的功能，我们可以根据提供的代码片段来归纳其核心功能：

**核心功能归纳：**

这个文件的核心功能是提供一系列 **用于解析各种复杂 CSS 属性值的实用工具函数**。  这些函数以 `Consume` 开头，表明它们负责从 CSS 语法解析器（`CSSParserTokenStream`）中读取并解释特定的 CSS 语法结构，并将其转换为 Blink 引擎内部使用的 `CSSValue` 对象。

**具体功能点 (基于提供的代码片段)：**

* **解析 Grid 布局相关属性:**
    * `ConsumeGridLine`:  解析 Grid 布局中的网格线名称或编号。
    * `ConsumeGridTemplateShorthand`: 解析 `grid-template` 缩写属性，涉及到行、列和区域的定义。
* **解析形状和路径相关属性:**
    * `ConsumeMasonrySlack`: 解析 Masonry 布局的 `masonry-auto-flow` 属性中的 `pack: <masonry-slack>` 值。
    * `ConsumePathStringArg`: 解析 SVG 路径字符串参数。
    * `ConsumeBasicShapePath`: 解析 `path()` 函数定义的形状。
    * `ConsumePathFunction`: 解析 `path()` 函数。
    * `ConsumeRay`: 解析 `ray()` 函数定义的形状。
    * `ConsumeBasicShape`:  作为一个入口点，根据函数名调用不同的基本形状解析函数（`circle`, `ellipse`, `polygon`, `inset`, `path`, `rect`, `xywh`）。
* **解析尺寸和间距相关属性:**
    * `ConsumeMaxWidthOrHeight`: 解析 `max-width` 和 `max-height` 属性的值。
    * `ConsumeWidthOrHeight`: 解析 `width` 和 `height` 属性的值。
    * `ConsumeMarginOrOffset`: 解析 margin 和 offset 相关的属性值。
    * `ConsumeScrollPadding`: 解析 `scroll-padding` 属性的值。
    * `ConsumeScrollStart`: 解析 `scroll-start` 属性的值。
* **解析文本相关属性:**
    * `ConsumeHyphenateLimitChars`: 解析 `hyphenate-limit-chars` 属性的值。
    * `ConsumeTextDecorationLine`: 解析 `text-decoration-line` 属性的值。
    * `ConsumeTextBoxEdge`: 解析 `text-box-edge` 属性的值。
    * `ConsumeTextBoxTrim`: 解析 `text-box-trim` 属性的值。
    * `ConsumeAutospace`: 解析 `autospace` 属性的值。
    * `ConsumeSpacingTrim`: 解析 `spacing-trim` 属性的值。
    * `ConsumeInitialLetter`: 解析 `initial-letter` 属性的值。
* **解析断点相关属性:**
    * `ConsumeFromPageBreakBetween`: 解析与分页符相关的属性值。
    * `ConsumeFromColumnBreakBetween`: 解析与分列符相关的属性值。
    * `ConsumeFromColumnOrPageBreakInside`: 解析与元素内部断点相关的属性值。
* **解析变换 (Transform) 相关属性:**
    * `ConsumeTransformValue`: 解析单个 CSS 变换函数（如 `rotate`, `scale`, `translate`）。
    * `ConsumeTransformList`: 解析 `transform` 属性，它包含一个或多个变换函数。
* **解析过渡 (Transition) 相关属性:**
    * `ConsumeTransitionProperty`: 解析 `transition-property` 属性，用于指定哪些 CSS 属性参与过渡。
    * `IsValidPropertyList`: 验证属性列表是否有效。
    * `IsValidTransitionBehavior`: 验证单个过渡行为值是否有效。
    * `IsValidTransitionBehaviorList`: 验证过渡行为值列表是否有效。
* **解析边框 (Border) 相关属性:**
    * `ConsumeBorderColorSide`: 解析边框颜色值。
    * `ConsumeBorderWidth`: 解析边框宽度值。
    * `ConsumeRadii`: 解析 `border-radius` 属性的圆角半径值。
* **解析偏移路径 (Offset Path) 相关属性:**
    * `ConsumeOffsetPath`: 解析 `offset-path` 属性的值。
    * `ConsumePathOrNone`: 解析 `path()` 函数或 `none` 关键字。
    * `ConsumeOffsetRotate`: 解析 `offset-rotate` 属性的值。
* **解析间距 (Spacing) 相关属性:**
    * `ParseSpacing`: 解析 `word-spacing` 和 `letter-spacing` 属性的值。
* **解析容器查询 (Container Queries) 相关属性:**
    * `ConsumeSingleContainerName`: 解析单个容器名称。 (代码片段在这里被截断)

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:**  这个文件是 Blink 引擎解析 CSS 样式的核心组成部分。它直接负责理解 CSS 语法并将其转换为内部数据结构，以便后续应用于 HTML 元素。例如，`ConsumeGridTemplateShorthand` 函数确保浏览器能够正确理解和渲染使用 `grid-template` 属性定义的网格布局。
* **HTML:**  HTML 结构和 CSS 样式是紧密结合的。当浏览器加载 HTML 页面并遇到 `<style>` 标签或外部 CSS 文件时，会调用 CSS 解析器。这个文件中的函数负责解析这些 CSS 规则，并将其关联到相应的 HTML 元素。例如，如果 HTML 中有一个 `<div>` 元素应用了 `width: 100px;` 样式，`ConsumeWidthOrHeight` 函数会解析 "100px" 并将其存储为该 `<div>` 元素的宽度信息。
* **JavaScript:**  JavaScript 可以通过 DOM API 与 CSS 进行交互。例如，可以使用 `element.style.width = '200px';` 来动态修改元素的样式。虽然 JavaScript 不直接调用这些 `Consume` 函数，但当 JavaScript 修改样式时，底层的渲染引擎可能需要重新解析这些新的样式值，间接地涉及到这些解析工具函数。

**逻辑推理示例 (假设输入与输出):**

**假设输入 (对于 `ConsumeGridLine`):**

```css
.container {
  grid-row-start: my-line-name 2;
}
```

* **输入:**  `CSSParserTokenStream` 指向 "my-line-name" 标识符和 "2" 数字 token。
* **预期输出:**  一个 `CSSValue` 对象，可能是一个 `CSSGridLineNamesValue` 包含 "my-line-name"， 紧跟着一个 `CSSIdentifierValue` 或 `CSSNumericLiteralValue` 表示数字 2。

**假设输入 (对于 `ConsumeWidthOrHeight`):**

```css
.element {
  width: calc(100% - 20px);
}
```

* **输入:** `CSSParserTokenStream` 指向 "calc" 函数 token。
* **预期输出:** 一个 `CSSCalcValue` 对象，表示 `100% - 20px` 的计算表达式。

**用户或编程常见的使用错误举例说明:**

* **错误使用 Grid 布局语法 (导致 `ConsumeGridTemplateShorthand` 解析失败):**
    ```css
    .container {
      grid-template: [row-start] 100px / 200px; /* 缺少行结束的方括号 */
    }
    ```
    在这种情况下，`ConsumeGridTemplateShorthand` 函数可能会返回 `false`，表示解析失败，浏览器可能无法正确渲染 Grid 布局。

* **在 `path()` 函数中使用无效的 SVG 路径字符串 (导致 `ConsumeBasicShapePath` 解析失败):**
    ```css
    .clip {
      clip-path: path("M 10 10 L 90 90 Z invalid-command");
    }
    ```
    如果 `invalid-command` 不是有效的 SVG 路径命令，`ConsumeBasicShapePath` 将返回 `nullptr`。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入网址或点击链接。**
2. **浏览器下载 HTML、CSS 和其他资源。**
3. **HTML 解析器解析 HTML 结构，构建 DOM 树。**
4. **CSS 解析器开始解析 `<style>` 标签或外部 CSS 文件中的样式规则。**
5. **当 CSS 解析器遇到需要解析复杂值的属性时（例如 `grid-template`, `clip-path`, `transform` 等），会调用 `css_parsing_utils.cc` 文件中相应的 `Consume` 函数。**
6. **例如，如果正在解析 `grid-template: 1fr 1fr / auto auto;`，则会调用 `ConsumeGridTemplateShorthand` 函数。**
7. **在调试器中，可以在这些 `Consume` 函数处设置断点，查看 `CSSParserTokenStream` 中的 token 流，以及解析过程中的中间变量值，从而了解 CSS 解析的详细过程。**

**总结:**

`blink/renderer/core/css/properties/css_parsing_utils.cc` 文件是 Blink 引擎中负责解析复杂 CSS 属性值的关键组成部分。它提供了一组工具函数，用于从 CSS 语法流中提取并解释各种 CSS 语法结构，将其转换为内部表示，最终用于渲染网页。理解这个文件中的功能对于深入了解浏览器如何解析和应用 CSS 样式至关重要。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/css_parsing_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共9部分，请归纳一下它的功能

"""
                           CSSValue*& start_value,
                                      CSSValue*& end_value) {
  // Input should be nullptrs.
  DCHECK(!start_value);
  DCHECK(!end_value);

  start_value = ConsumeGridLine(stream, context);
  if (!start_value) {
    return false;
  }

  if (ConsumeSlashIncludingWhitespace(stream)) {
    end_value = ConsumeGridLine(stream, context);
    if (!end_value) {
      return false;
    }
  } else {
    end_value = start_value->IsCustomIdentValue()
                    ? start_value
                    : CSSIdentifierValue::Create(CSSValueID::kAuto);
  }

  return true;
}

bool ConsumeGridTemplateShorthand(bool important,
                                  CSSParserTokenStream& stream,
                                  const CSSParserContext& context,
                                  const CSSValue*& template_rows,
                                  const CSSValue*& template_columns,
                                  const CSSValue*& template_areas) {
  DCHECK(!template_rows);
  DCHECK(!template_columns);
  DCHECK(!template_areas);

  DCHECK_EQ(gridTemplateShorthand().length(), 3u);

  {
    // 1- <grid-template-rows> / <grid-template-columns>
    CSSParserSavePoint savepoint(stream);
    template_rows = ConsumeIdent<CSSValueID::kNone>(stream);
    if (!template_rows) {
      template_rows = ConsumeGridTemplatesRowsOrColumns(stream, context);
    }

    if (template_rows && ConsumeSlashIncludingWhitespace(stream)) {
      template_columns = ConsumeGridTemplatesRowsOrColumns(stream, context);
      if (template_columns) {
        template_areas = CSSIdentifierValue::Create(CSSValueID::kNone);
        savepoint.Release();
        return true;
      }
    }

    template_rows = nullptr;
    template_columns = nullptr;
    template_areas = nullptr;
  }

  {
    // 2- [ <line-names>? <string> <track-size>? <line-names>? ]+
    // [ / <track-list> ]?
    CSSParserSavePoint savepoint(stream);
    if (ConsumeGridTemplateRowsAndAreasAndColumns(
            important, stream, context, template_rows, template_columns,
            template_areas)) {
      savepoint.Release();
      return true;
    }
  }

  // 3- 'none' alone case. This must come after the others, since “none“
  // could also be the start of case 1.
  template_rows = ConsumeIdent<CSSValueID::kNone>(stream);
  if (template_rows) {
    template_rows = CSSIdentifierValue::Create(CSSValueID::kNone);
    template_columns = CSSIdentifierValue::Create(CSSValueID::kNone);
    template_areas = CSSIdentifierValue::Create(CSSValueID::kNone);
    return true;
  }

  return false;
}

CSSValue* ConsumeMasonrySlack(CSSParserTokenStream& stream,
                              const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kNormal) {
    return ConsumeIdent(stream);
  }
  return ConsumeLengthOrPercent(stream, context,
                                CSSPrimitiveValue::ValueRange::kNonNegative);
}

CSSValue* ConsumeHyphenateLimitChars(CSSParserTokenStream& stream,
                                     const CSSParserContext& context) {
  CSSValueList* const list = CSSValueList::CreateSpaceSeparated();
  while (!stream.AtEnd() && list->length() < 3) {
    if (const CSSPrimitiveValue* value = ConsumeIntegerOrNumberCalc(
            stream, context, CSSPrimitiveValue::ValueRange::kPositiveInteger)) {
      list->Append(*value);
      continue;
    }
    if (const CSSIdentifierValue* ident =
            ConsumeIdent<CSSValueID::kAuto>(stream)) {
      list->Append(*ident);
      continue;
    }
    break;
  }
  if (list->length()) {
    return list;
  }
  return nullptr;
}

bool ConsumeFromPageBreakBetween(CSSParserTokenStream& stream,
                                 CSSValueID& value) {
  if (!ConsumeCSSValueId(stream, value)) {
    return false;
  }

  if (value == CSSValueID::kAlways) {
    value = CSSValueID::kPage;
    return true;
  }
  return value == CSSValueID::kAuto || value == CSSValueID::kAvoid ||
         value == CSSValueID::kLeft || value == CSSValueID::kRight;
}

bool ConsumeFromColumnBreakBetween(CSSParserTokenStream& stream,
                                   CSSValueID& value) {
  if (!ConsumeCSSValueId(stream, value)) {
    return false;
  }

  if (value == CSSValueID::kAlways) {
    value = CSSValueID::kColumn;
    return true;
  }
  return value == CSSValueID::kAuto || value == CSSValueID::kAvoid;
}

bool ConsumeFromColumnOrPageBreakInside(CSSParserTokenStream& stream,
                                        CSSValueID& value) {
  if (!ConsumeCSSValueId(stream, value)) {
    return false;
  }
  return value == CSSValueID::kAuto || value == CSSValueID::kAvoid;
}

bool ValidWidthOrHeightKeyword(CSSValueID id, const CSSParserContext& context) {
  // The keywords supported here should be kept in sync with
  // CalculationExpressionSizingKeywordNode::Keyword and the things that use
  // it.
  // TODO(https://crbug.com/353538495): This should also be kept in sync with
  // FlexBasis::ParseSingleValue, although we should eventually make it use
  // this function instead.
  if (id == CSSValueID::kWebkitMinContent ||
      id == CSSValueID::kWebkitMaxContent ||
      id == CSSValueID::kWebkitFillAvailable ||
      id == CSSValueID::kWebkitFitContent || id == CSSValueID::kMinContent ||
      id == CSSValueID::kMaxContent || id == CSSValueID::kFitContent) {
    switch (id) {
      case CSSValueID::kWebkitMinContent:
        context.Count(WebFeature::kCSSValuePrefixedMinContent);
        break;
      case CSSValueID::kWebkitMaxContent:
        context.Count(WebFeature::kCSSValuePrefixedMaxContent);
        break;
      case CSSValueID::kWebkitFillAvailable:
        context.Count(WebFeature::kCSSValuePrefixedFillAvailable);
        break;
      case CSSValueID::kWebkitFitContent:
        context.Count(WebFeature::kCSSValuePrefixedFitContent);
        break;
      default:
        break;
    }
    return true;
  }
  if (RuntimeEnabledFeatures::LayoutStretchEnabled() &&
      id == CSSValueID::kStretch) {
    return true;
  }
  return false;
}

std::optional<SVGPathByteStream> ConsumePathStringArg(
    CSSParserTokenStream& args) {
  if (args.Peek().GetType() != kStringToken) {
    return std::nullopt;
  }

  CSSParserToken path = args.ConsumeIncludingWhitespace();
  SVGPathByteStreamBuilder builder;
  if (BuildByteStreamFromString(path.Value(), builder) !=
      SVGParseStatus::kNoError) {
    return std::nullopt;
  }

  return builder.CopyByteStream();
}

cssvalue::CSSPathValue* ConsumeBasicShapePath(CSSParserTokenStream& args) {
  auto wind_rule = RULE_NONZERO;

  if (IdentMatches<CSSValueID::kEvenodd, CSSValueID::kNonzero>(
          args.Peek().Id())) {
    wind_rule = args.ConsumeIncludingWhitespace().Id() == CSSValueID::kEvenodd
                    ? RULE_EVENODD
                    : RULE_NONZERO;
    if (!ConsumeCommaIncludingWhitespace(args)) {
      return nullptr;
    }
  }

  auto byte_stream = ConsumePathStringArg(args);
  // https://drafts.csswg.org/css-shapes-1/#funcdef-basic-shape-path
  // A path data string that does not conform to the to the grammar
  // and parsing rules of SVG 1.1, or that does conform but defines
  // an empty path, is invalid and causes the entire path() to be invalid.
  if (!byte_stream || !args.AtEnd() ||
      (RuntimeEnabledFeatures::ClipPathRejectEmptyPathsEnabled() &&
       byte_stream->IsEmpty())) {
    return nullptr;
  }

  return MakeGarbageCollected<cssvalue::CSSPathValue>(std::move(*byte_stream),
                                                      wind_rule);
}

CSSValue* ConsumePathFunction(CSSParserTokenStream& stream,
                              EmptyPathStringHandling empty_handling) {
  // FIXME: Add support for <url>, <basic-shape>, <geometry-box>.
  if (stream.Peek().FunctionId() != CSSValueID::kPath) {
    return nullptr;
  }

  CSSValue* value;
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();

    std::optional<SVGPathByteStream> byte_stream = ConsumePathStringArg(stream);
    if (!byte_stream || !stream.AtEnd()) {
      return nullptr;
    }

    // https://drafts.csswg.org/css-shapes-1/#funcdef-basic-shape-path
    // A path data string that does not conform to the to the grammar
    // and parsing rules of SVG 1.1, or that does conform but defines
    // an empty path, is invalid and causes the entire path() to be invalid.
    if (byte_stream->IsEmpty()) {
      if (empty_handling == EmptyPathStringHandling::kTreatAsNone) {
        value = CSSIdentifierValue::Create(CSSValueID::kNone);
      } else {
        return nullptr;
      }
    } else {
      value =
          MakeGarbageCollected<cssvalue::CSSPathValue>(std::move(*byte_stream));
    }

    guard.Release();
  }
  stream.ConsumeWhitespace();
  return value;
}

CSSValue* ConsumeRay(CSSParserTokenStream& stream,
                     const CSSParserContext& context) {
  if (stream.Peek().FunctionId() != CSSValueID::kRay) {
    return nullptr;
  }

  CSSValue* value;
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();

    CSSPrimitiveValue* angle = nullptr;
    CSSIdentifierValue* size = nullptr;
    CSSIdentifierValue* contain = nullptr;
    bool position = false;
    CSSValue* x = nullptr;
    CSSValue* y = nullptr;
    while (!stream.AtEnd()) {
      if (!angle) {
        angle = ConsumeAngle(stream, context, std::optional<WebFeature>());
        if (angle) {
          continue;
        }
      }
      if (!size) {
        size =
            ConsumeIdent<CSSValueID::kClosestSide, CSSValueID::kClosestCorner,
                         CSSValueID::kFarthestSide, CSSValueID::kFarthestCorner,
                         CSSValueID::kSides>(stream);
        if (size) {
          continue;
        }
      }
      if (!contain) {
        contain = ConsumeIdent<CSSValueID::kContain>(stream);
        if (contain) {
          continue;
        }
      }
      if (!position && ConsumeIdent<CSSValueID::kAt>(stream)) {
        position = ConsumePosition(stream, context, UnitlessQuirk::kForbid,
                                   std::optional<WebFeature>(), x, y);
        if (position) {
          continue;
        }
      }
      return nullptr;
    }
    if (!angle) {
      return nullptr;
    }
    guard.Release();
    if (!size) {
      size = CSSIdentifierValue::Create(CSSValueID::kClosestSide);
    }
    value = MakeGarbageCollected<cssvalue::CSSRayValue>(*angle, *size, contain,
                                                        x, y);
  }
  stream.ConsumeWhitespace();
  return value;
}

CSSValue* ConsumeMaxWidthOrHeight(CSSParserTokenStream& stream,
                                  const CSSParserContext& context,
                                  UnitlessQuirk unitless) {
  if (stream.Peek().Id() == CSSValueID::kNone ||
      ValidWidthOrHeightKeyword(stream.Peek().Id(), context)) {
    return ConsumeIdent(stream);
  }
  return ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative, unitless,
      static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchorSize),
      AllowCalcSize::kAllowWithoutAuto);
}

CSSValue* ConsumeWidthOrHeight(CSSParserTokenStream& stream,
                               const CSSParserContext& context,
                               UnitlessQuirk unitless) {
  if (stream.Peek().Id() == CSSValueID::kAuto ||
      ValidWidthOrHeightKeyword(stream.Peek().Id(), context)) {
    return ConsumeIdent(stream);
  }
  return ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative, unitless,
      static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchorSize),
      AllowCalcSize::kAllowWithAuto);
}

CSSValue* ConsumeMarginOrOffset(CSSParserTokenStream& stream,
                                const CSSParserContext& context,
                                UnitlessQuirk unitless,
                                CSSAnchorQueryTypes allowed_anchor_queries) {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return ConsumeIdent(stream);
  }
  return ConsumeLengthOrPercent(stream, context,
                                CSSPrimitiveValue::ValueRange::kAll, unitless,
                                allowed_anchor_queries);
}

CSSValue* ConsumeScrollPadding(CSSParserTokenStream& stream,
                               const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return ConsumeIdent(stream);
  }
  CSSParserContext::ParserModeOverridingScope scope(context, kHTMLStandardMode);
  return ConsumeLengthOrPercent(stream, context,
                                CSSPrimitiveValue::ValueRange::kNonNegative,
                                UnitlessQuirk::kForbid);
}

CSSValue* ConsumeScrollStart(CSSParserTokenStream& stream,
                             const CSSParserContext& context) {
  if (CSSIdentifierValue* ident =
          ConsumeIdent<CSSValueID::kAuto, CSSValueID::kStart,
                       CSSValueID::kCenter, CSSValueID::kEnd, CSSValueID::kTop,
                       CSSValueID::kBottom, CSSValueID::kLeft,
                       CSSValueID::kRight>(stream)) {
    return ident;
  }
  return ConsumeLengthOrPercent(stream, context,
                                CSSPrimitiveValue::ValueRange::kNonNegative);
}

CSSValue* ConsumeOffsetPath(CSSParserTokenStream& stream,
                            const CSSParserContext& context) {
  if (CSSValue* none = ConsumeIdent<CSSValueID::kNone>(stream)) {
    return none;
  }
  CSSValue* coord_box = ConsumeCoordBox(stream);

  CSSValue* offset_path = ConsumeRay(stream, context);
  if (!offset_path) {
    offset_path = ConsumeBasicShape(stream, context, AllowPathValue::kForbid);
  }
  if (!offset_path) {
    offset_path = ConsumeUrl(stream, context);
  }
  if (!offset_path) {
    offset_path =
        ConsumePathFunction(stream, EmptyPathStringHandling::kFailure);
  }

  if (!coord_box) {
    coord_box = ConsumeCoordBox(stream);
  }

  if (!offset_path && !coord_box) {
    return nullptr;
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (offset_path) {
    list->Append(*offset_path);
  }
  if (!offset_path ||
      (coord_box && To<CSSIdentifierValue>(coord_box)->GetValueID() !=
                        CSSValueID::kBorderBox)) {
    list->Append(*coord_box);
  }

  // Count when we receive a valid path other than 'none'.
  context.Count(WebFeature::kCSSOffsetInEffect);

  return list;
}

CSSValue* ConsumePathOrNone(CSSParserTokenStream& stream) {
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kNone) {
    return ConsumeIdent(stream);
  }

  return ConsumePathFunction(stream, EmptyPathStringHandling::kTreatAsNone);
}

CSSValue* ConsumeOffsetRotate(CSSParserTokenStream& stream,
                              const CSSParserContext& context) {
  CSSValue* angle = ConsumeAngle(stream, context, std::optional<WebFeature>());
  CSSValue* keyword =
      ConsumeIdent<CSSValueID::kAuto, CSSValueID::kReverse>(stream);
  if (!angle && !keyword) {
    return nullptr;
  }

  if (!angle) {
    angle = ConsumeAngle(stream, context, std::optional<WebFeature>());
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (keyword) {
    list->Append(*keyword);
  }
  if (angle) {
    list->Append(*angle);
  }
  return list;
}

CSSValue* ConsumeInitialLetter(CSSParserTokenStream& stream,
                               const CSSParserContext& context) {
  if (ConsumeIdent<CSSValueID::kNormal>(stream)) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }

  CSSValueList* const list = CSSValueList::CreateSpaceSeparated();
  // ["drop" | "raise"] number[1,Inf]
  if (auto* sink_type =
          ConsumeIdent<CSSValueID::kDrop, CSSValueID::kRaise>(stream)) {
    if (auto* size = ConsumeNumber(
            stream, context, CSSPrimitiveValue::ValueRange::kNonNegative)) {
      auto* numeric_size = DynamicTo<CSSNumericLiteralValue>(size);
      if (numeric_size && numeric_size->DoubleValue() < 1) {
        return nullptr;
      }
      list->Append(*size);
      list->Append(*sink_type);
      return list;
    }
    return nullptr;
  }

  // number[1, Inf]
  // number[1, Inf] ["drop" | "raise"]
  // number[1, Inf] integer[1, Inf]
  if (auto* size = ConsumeNumber(stream, context,
                                 CSSPrimitiveValue::ValueRange::kNonNegative)) {
    auto* numeric_size = DynamicTo<CSSNumericLiteralValue>(size);
    if (numeric_size && numeric_size->DoubleValue() < 1) {
      return nullptr;
    }
    list->Append(*size);
    if (auto* sink_type =
            ConsumeIdent<CSSValueID::kDrop, CSSValueID::kRaise>(stream)) {
      list->Append(*sink_type);
      return list;
    }
    if (auto* sink = ConsumeIntegerOrNumberCalc(
            stream, context, CSSPrimitiveValue::ValueRange::kPositiveInteger)) {
      list->Append(*sink);
      return list;
    }
    return list;
  }

  return nullptr;
}

bool ConsumeRadii(std::array<CSSValue*, 4>& horizontal_radii,
                  std::array<CSSValue*, 4>& vertical_radii,
                  CSSParserTokenStream& stream,
                  const CSSParserContext& context,
                  bool use_legacy_parsing) {
  unsigned horizontal_value_count = 0;
  for (;
       horizontal_value_count < 4 && stream.Peek().GetType() != kDelimiterToken;
       ++horizontal_value_count) {
    horizontal_radii[horizontal_value_count] = ConsumeLengthOrPercent(
        stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
    if (!horizontal_radii[horizontal_value_count]) {
      break;
    }
  }
  if (!horizontal_radii[0]) {
    return false;
  }
  if (ConsumeSlashIncludingWhitespace(stream)) {
    for (unsigned i = 0; i < 4; ++i) {
      vertical_radii[i] = ConsumeLengthOrPercent(
          stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
      if (!vertical_radii[i]) {
        break;
      }
    }
    if (!vertical_radii[0]) {
      return false;
    }
  } else {
    // Legacy syntax: -webkit-border-radius: l1 l2; is equivalent to
    // border-radius: l1 / l2;
    if (use_legacy_parsing && horizontal_value_count == 2) {
      vertical_radii[0] = horizontal_radii[1];
      horizontal_radii[1] = nullptr;
    } else {
      Complete4Sides(horizontal_radii);
      for (unsigned i = 0; i < 4; ++i) {
        vertical_radii[i] = horizontal_radii[i];
      }
      return true;
    }
  }
  Complete4Sides(horizontal_radii);
  Complete4Sides(vertical_radii);
  return true;
}

CSSValue* ConsumeBasicShape(CSSParserTokenStream& stream,
                            const CSSParserContext& context,
                            AllowPathValue allow_path,
                            AllowBasicShapeRectValue allow_rect,
                            AllowBasicShapeXYWHValue allow_xywh) {
  CSSValue* shape = nullptr;
  if (stream.Peek().GetType() != kFunctionToken) {
    return nullptr;
  }
  CSSValueID id = stream.Peek().FunctionId();
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();
    if (id == CSSValueID::kCircle) {
      shape = ConsumeBasicShapeCircle(stream, context);
    } else if (id == CSSValueID::kEllipse) {
      shape = ConsumeBasicShapeEllipse(stream, context);
    } else if (id == CSSValueID::kPolygon) {
      shape = ConsumeBasicShapePolygon(stream, context);
    } else if (id == CSSValueID::kInset) {
      shape = ConsumeBasicShapeInset(stream, context);
    } else if (id == CSSValueID::kPath &&
               allow_path == AllowPathValue::kAllow) {
      shape = ConsumeBasicShapePath(stream);
    } else if (id == CSSValueID::kRect &&
               allow_rect == AllowBasicShapeRectValue::kAllow) {
      shape = ConsumeBasicShapeRect(stream, context);
    } else if (id == CSSValueID::kXywh &&
               allow_xywh == AllowBasicShapeXYWHValue::kAllow) {
      shape = ConsumeBasicShapeXYWH(stream, context);
    }
    if (!shape || !stream.AtEnd()) {
      return nullptr;
    }

    context.Count(WebFeature::kCSSBasicShape);
    guard.Release();
  }
  stream.ConsumeWhitespace();
  return shape;
}

// none | [ underline || overline || line-through || blink ] | spelling-error |
// grammar-error
CSSValue* ConsumeTextDecorationLine(CSSParserTokenStream& stream) {
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kNone) {
    return ConsumeIdent(stream);
  }

  if (id == CSSValueID::kSpellingError || id == CSSValueID::kGrammarError) {
    // Note that StyleBuilderConverter::ConvertFlags() requires that values
    // other than 'none' appear in a CSSValueList.
    CSSValueList* list = CSSValueList::CreateSpaceSeparated();
    list->Append(*ConsumeIdent(stream));
    return list;
  }

  CSSIdentifierValue* underline = nullptr;
  CSSIdentifierValue* overline = nullptr;
  CSSIdentifierValue* line_through = nullptr;
  CSSIdentifierValue* blink = nullptr;

  while (true) {
    id = stream.Peek().Id();
    if (id == CSSValueID::kUnderline && !underline) {
      underline = ConsumeIdent(stream);
    } else if (id == CSSValueID::kOverline && !overline) {
      overline = ConsumeIdent(stream);
    } else if (id == CSSValueID::kLineThrough && !line_through) {
      line_through = ConsumeIdent(stream);
    } else if (id == CSSValueID::kBlink && !blink) {
      blink = ConsumeIdent(stream);
    } else {
      break;
    }
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (underline) {
    list->Append(*underline);
  }
  if (overline) {
    list->Append(*overline);
  }
  if (line_through) {
    list->Append(*line_through);
  }
  if (blink) {
    list->Append(*blink);
  }

  if (!list->length()) {
    return nullptr;
  }
  return list;
}

// Consume the `text-box-edge` production.
CSSValue* ConsumeTextBoxEdge(CSSParserTokenStream& stream) {
  if (CSSIdentifierValue* auto_value =
          ConsumeIdent<CSSValueID::kAuto>(stream)) {
    return auto_value;
  }

  CSSIdentifierValue* over_type =
      ConsumeIdent<CSSValueID::kText, CSSValueID::kCap, CSSValueID::kEx>(
          stream);
  if (!over_type) {
    return nullptr;
  }
  const auto over = over_type->ConvertTo<TextBoxEdge::Type>();
  const std::optional<TextBoxEdge::Type> default_under =
      TextBoxEdge::UnderForOver(over);

  // The second parameter is optional, the first parameter will be used for
  // both if the second parameter is not provided.
  if (CSSIdentifierValue* under_type =
          ConsumeIdent<CSSValueID::kText, CSSValueID::kAlphabetic>(stream)) {
    // Align with the CSS specification: "If only one value is specified,
    // both edges are assigned that same keyword if possible".
    // If the `default_under` has a value, and if it's the specified `under'
    // value, the `under` value can be omitted.
    if (default_under == under_type->ConvertTo<TextBoxEdge::Type>()) {
      return over_type;
    }

    CSSValueList* const list = CSSValueList::CreateSpaceSeparated();
    list->Append(*over_type);
    list->Append(*under_type);
    return list;
  }

  // If the `default_under` has a value; i.e., if the `under` can be omitted,
  // return the `over` value.
  if (default_under) {
    return over_type;
  }

  // Fail if the `under` is required but it's missing.
  return nullptr;
}

// Consume the `text-box-trim` production.
CSSValue* ConsumeTextBoxTrim(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kNone, CSSValueID::kTrimStart,
                      CSSValueID::kTrimEnd, CSSValueID::kTrimBoth>(stream);
}

// Consume the `autospace` production.
// https://drafts.csswg.org/css-text-4/#typedef-autospace
CSSValue* ConsumeAutospace(CSSParserTokenStream& stream) {
  // Currently, only `no-autospace` is supported.
  return ConsumeIdent<CSSValueID::kNoAutospace>(stream);
}

// Consume the `spacing-trim` production.
// https://drafts.csswg.org/css-text-4/#typedef-spacing-trim
CSSValue* ConsumeSpacingTrim(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kTrimStart, CSSValueID::kSpaceAll,
                      CSSValueID::kSpaceFirst>(stream);
}

CSSValue* ConsumeTransformValue(CSSParserTokenStream& stream,
                                const CSSParserContext& context,
                                bool use_legacy_parsing) {
  CSSValueID function_id = stream.Peek().FunctionId();
  if (!IsValidCSSValueID(function_id)) {
    return nullptr;
  }
  CSSFunctionValue* transform_value = nullptr;
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();
    if (stream.AtEnd()) {
      return nullptr;
    }
    transform_value = MakeGarbageCollected<CSSFunctionValue>(function_id);
    CSSValue* parsed_value = nullptr;
    switch (function_id) {
      case CSSValueID::kRotate:
      case CSSValueID::kRotateX:
      case CSSValueID::kRotateY:
      case CSSValueID::kRotateZ:
      case CSSValueID::kSkewX:
      case CSSValueID::kSkewY:
      case CSSValueID::kSkew:
        parsed_value = ConsumeAngle(stream, context,
                                    WebFeature::kUnitlessZeroAngleTransform);
        if (!parsed_value) {
          return nullptr;
        }
        if (function_id == CSSValueID::kSkew &&
            ConsumeCommaIncludingWhitespace(stream)) {
          transform_value->Append(*parsed_value);
          parsed_value = ConsumeAngle(stream, context,
                                      WebFeature::kUnitlessZeroAngleTransform);
          if (!parsed_value) {
            return nullptr;
          }
        }
        break;
      case CSSValueID::kScaleX:
      case CSSValueID::kScaleY:
      case CSSValueID::kScaleZ:
      case CSSValueID::kScale:
        parsed_value = ConsumeNumberOrPercent(
            stream, context, CSSPrimitiveValue::ValueRange::kAll);
        if (!parsed_value) {
          return nullptr;
        }
        if (function_id == CSSValueID::kScale &&
            ConsumeCommaIncludingWhitespace(stream)) {
          transform_value->Append(*parsed_value);
          parsed_value = ConsumeNumberOrPercent(
              stream, context, CSSPrimitiveValue::ValueRange::kAll);
          if (!parsed_value) {
            return nullptr;
          }
        }
        break;
      case CSSValueID::kPerspective:
        if (!ConsumePerspective(stream, context, transform_value,
                                use_legacy_parsing)) {
          return nullptr;
        }
        break;
      case CSSValueID::kTranslateX:
      case CSSValueID::kTranslateY:
      case CSSValueID::kTranslate:
        parsed_value = ConsumeLengthOrPercent(
            stream, context, CSSPrimitiveValue::ValueRange::kAll);
        if (!parsed_value) {
          return nullptr;
        }
        if (function_id == CSSValueID::kTranslate &&
            ConsumeCommaIncludingWhitespace(stream)) {
          transform_value->Append(*parsed_value);
          parsed_value = ConsumeLengthOrPercent(
              stream, context, CSSPrimitiveValue::ValueRange::kAll);
          if (!parsed_value) {
            return nullptr;
          }
        }
        break;
      case CSSValueID::kTranslateZ:
        parsed_value =
            ConsumeLength(stream, context, CSSPrimitiveValue::ValueRange::kAll);
        break;
      case CSSValueID::kMatrix:
      case CSSValueID::kMatrix3d:
        if (!ConsumeNumbers(stream, context, transform_value,
                            (function_id == CSSValueID::kMatrix3d) ? 16 : 6)) {
          return nullptr;
        }
        break;
      case CSSValueID::kScale3d:
        if (!ConsumeNumbersOrPercents(stream, context, transform_value, 3)) {
          return nullptr;
        }
        break;
      case CSSValueID::kRotate3d:
        if (!ConsumeNumbers(stream, context, transform_value, 3) ||
            !ConsumeCommaIncludingWhitespace(stream)) {
          return nullptr;
        }
        parsed_value = ConsumeAngle(stream, context,
                                    WebFeature::kUnitlessZeroAngleTransform);
        if (!parsed_value) {
          return nullptr;
        }
        break;
      case CSSValueID::kTranslate3d:
        if (!ConsumeTranslate3d(stream, context, transform_value)) {
          return nullptr;
        }
        break;
      default:
        return nullptr;
    }
    if (parsed_value) {
      transform_value->Append(*parsed_value);
    }
    if (!stream.AtEnd()) {
      return nullptr;
    }
    guard.Release();
  }
  stream.ConsumeWhitespace();
  return transform_value;
}

CSSValue* ConsumeTransformList(CSSParserTokenStream& stream,
                               const CSSParserContext& context,
                               const CSSParserLocalContext& local_context) {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return ConsumeIdent(stream);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  do {
    CSSValue* parsed_transform_value =
        ConsumeTransformValue(stream, context, local_context.UseAliasParsing());
    if (!parsed_transform_value) {
      break;
    }
    list->Append(*parsed_transform_value);
  } while (!stream.AtEnd());

  if (list->length() == 0) {
    return nullptr;
  }

  return list;
}

CSSValue* ConsumeTransitionProperty(CSSParserTokenStream& stream,
                                    const CSSParserContext& context) {
  const CSSParserToken& token = stream.Peek();
  if (token.GetType() != kIdentToken) {
    return nullptr;
  }
  if (token.Id() == CSSValueID::kNone) {
    return ConsumeIdent(stream);
  }
  const auto* execution_context = context.GetExecutionContext();
  CSSPropertyID unresolved_property =
      token.ParseAsUnresolvedCSSPropertyID(execution_context);
  if (unresolved_property != CSSPropertyID::kInvalid &&
      unresolved_property != CSSPropertyID::kVariable) {
#if DCHECK_IS_ON()
    DCHECK(CSSProperty::Get(ResolveCSSPropertyID(unresolved_property))
               .IsWebExposed(execution_context));
#endif
    stream.ConsumeIncludingWhitespace();
    return MakeGarbageCollected<CSSCustomIdentValue>(unresolved_property);
  }
  return ConsumeCustomIdent(stream, context);
}

bool IsValidPropertyList(const CSSValueList& value_list) {
  if (value_list.length() < 2) {
    return true;
  }
  for (auto& value : value_list) {
    auto* identifier_value = DynamicTo<CSSIdentifierValue>(value.Get());
    if (identifier_value &&
        identifier_value->GetValueID() == CSSValueID::kNone) {
      return false;
    }
  }
  return true;
}

bool IsValidTransitionBehavior(const CSSValueID& value) {
  switch (value) {
    case CSSValueID::kNormal:
    case CSSValueID::kAllowDiscrete:
      return true;
    default:
      return false;
  }
}

bool IsValidTransitionBehaviorList(const CSSValueList& value_list) {
  for (auto& value : value_list) {
    auto* ident_value = DynamicTo<CSSIdentifierValue>(value.Get());
    if (!ident_value) {
      return false;
    }
    if (!IsValidTransitionBehavior(ident_value->GetValueID())) {
      return false;
    }
  }
  return true;
}

CSSValue* ConsumeBorderColorSide(CSSParserTokenStream& stream,
                                 const CSSParserContext& context,
                                 const CSSParserLocalContext& local_context) {
  CSSPropertyID shorthand = local_context.CurrentShorthand();
  bool allow_quirky_colors = IsQuirksModeBehavior(context.Mode()) &&
                             (shorthand == CSSPropertyID::kInvalid ||
                              shorthand == CSSPropertyID::kBorderColor);
  return ConsumeColorInternal(stream, context, allow_quirky_colors,
                              AllowedColors::kAll);
}

CSSValue* ConsumeBorderWidth(CSSParserTokenStream& stream,
                             const CSSParserContext& context,
                             UnitlessQuirk unitless) {
  return ConsumeLineWidth(stream, context, unitless);
}

CSSValue* ParseSpacing(CSSParserTokenStream& stream,
                       const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kNormal) {
    return ConsumeIdent(stream);
  }
  // TODO(timloh): allow <percentage>s in word-spacing.
  return ConsumeLength(stream, context, CSSPrimitiveValue::ValueRange::kAll,
                       UnitlessQuirk::kAllow);
}

CSSValue* ConsumeSingleContainerName(CSSParserTokenStream& stream,
                                     const CSSParserContext& context) {
  if (stream.Peek().GetType() != kIdentToken) {
    return nullptr;
  }
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return nullptr;
  }
  if (EqualIgnoringASCIICase(stream.Peek().Value(), "not")) {
    return nullptr;
  }
  if (EqualIgnoringASCIICase(stream.Peek().Value(), "and")) {
    return nullptr;
  }
  if (EqualIgnoringASCIICase(stream.Peek().Value(), "or")) {
    return nullptr;
  }
  return ConsumeCustomIdent(stream, context);
}

CSSValue* ConsumeContainerNa
"""


```