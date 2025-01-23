Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The request asks for a functional summary of the provided C++ code snippet, focusing on its relationship to web technologies (HTML, CSS, JavaScript), providing examples, logical inferences with inputs/outputs, common usage errors, debugging context, and a final concise summary of its function within the larger file.

2. **Initial Code Scan and Keyword Spotting:** I quickly scan the code for recognizable keywords and function names related to CSS parsing and calculations. Keywords like `CSSValueID`, `Consume`, `Parse`, `CSSMathExpression`, `calc`, `min`, `max`, `clamp`, `round`, `anchor`, `progress`, `container`, `media`, `size`, `sibling`, `function`, `numeric`, `percentage`, `length`, etc., immediately jump out. These provide high-level clues about the code's purpose.

3. **Identify Key Functionalities:**  Based on the keywords, I start to group related code blocks. I see sections dedicated to:
    * Parsing `anchor()` functions for positioning.
    * Parsing `progress()`-like functions (`media-progress()`, `container-progress()`).
    * Parsing `calcSize()` (a less common or experimental function).
    * Parsing `siblingIndex()` and `siblingCount()` functions.
    * Parsing standard math functions like `min()`, `max()`, `clamp()`, `sin()`, `cos()`, `tan()`, `pow()`, `log()`, `round()`, `mod()`, `rem()`, `abs()`, `sign()`.
    * Parsing basic value terms (numbers, percentages, dimensions, keywords).
    * Handling arithmetic operations (+, -, *, /).

4. **Relate to Web Technologies (CSS, HTML, JavaScript):**  Now I connect these functionalities to how they are used in web development:
    * **CSS:** The entire file is about parsing CSS math expressions, so the direct connection to CSS is obvious. I think about *where* these expressions appear in CSS: property values, animations, transitions, etc.
    * **HTML:**  While this C++ code doesn't directly manipulate the HTML DOM, the *results* of these calculations often affect the rendering of HTML elements (size, position, etc.). The connection is indirect but crucial.
    * **JavaScript:** JavaScript can interact with CSS in several ways. It can *read* computed style values (which might involve these calculations) and it can *set* style values (potentially using CSS math functions). JavaScript frameworks might also use these calculations internally for layout or animation logic.

5. **Construct Examples:** For each identified functionality, I come up with simple, illustrative CSS examples. This clarifies the connection to CSS and helps explain *how* these features are used.

6. **Infer Logic and Provide Input/Output:** I look at how the parsing functions work. For example, `ParseAnchorQuery` clearly takes a token stream and produces a `CSSMathExpressionAnchorQuery` object. I can hypothesize simple input like `anchor(top)` and the output would be a representation of that parsed anchor query. Similarly, for arithmetic operations, I can provide simple calc expressions as input and infer the resulting `CSSMathExpressionOperation` structure.

7. **Identify Common Usage Errors:** I consider what mistakes developers might make when using these CSS features:
    * Incorrect syntax within `calc()`.
    * Type mismatches in math functions (e.g., adding a length to an angle).
    * Incorrect number of arguments for functions.
    * Using experimental or less common features like `calcSize` without knowing browser support.
    * Issues with units in calculations.

8. **Debugging Context (User Actions to Code):** I try to trace back how a user action might lead to this code being executed. A user editing CSS in the browser's DevTools, a website's CSS being loaded, or JavaScript manipulating styles are all potential triggers. The key is that *any* CSS that involves math functions will likely go through this parsing logic.

9. **Address the "Part 5 of 6" and Summarize:** I acknowledge the context of being part of a larger file and provide a concise summary of the code's overall function within that context – parsing CSS math expressions.

10. **Refine and Structure:**  Finally, I organize my thoughts into the requested categories, ensuring clarity and providing sufficient detail without overwhelming the reader. I use formatting (like bullet points and code blocks) to improve readability. I review my answer to make sure it addresses all parts of the prompt.

Essentially, my process involves understanding the code's purpose, connecting it to the broader web development context, providing concrete examples, inferring the underlying logic, and considering practical usage scenarios and debugging implications. The iterative nature of this process is important – I might revisit earlier steps as I gain a deeper understanding of the code.
好的，根据您提供的代码片段，以及它是 blink 渲染引擎中 `blink/renderer/core/css/css_math_expression_node.cc` 文件的第五部分，我们可以归纳一下这部分代码的主要功能：

**这部分代码的主要功能是解析 CSS 数学表达式中的各种函数。**  它专注于处理除基本的加减乘除之外的更复杂的数学函数，以及一些与 CSS 新特性相关的特殊函数。

更具体地说，它负责解析以下类型的 CSS 函数：

* **锚点定位函数 (`anchor()`):** 用于根据另一个元素（锚点）的特定边缘或尺寸来定位元素。
* **进度指示函数 (`progress()`, `media-progress()`, `container-progress()`):**  用于基于某种进度或媒体/容器的特定状态计算值。
* **尺寸计算函数 (`calcSize()`):**  用于更精细地控制尺寸计算，允许指定一个基础值和一个计算表达式。
* **兄弟元素索引/计数函数 (`siblingIndex()`, `siblingCount()`):** 用于获取元素在其兄弟节点中的索引或计数。
* **标准数学函数 (`min()`, `max()`, `clamp()`, `sin()`, `cos()`, `tan()`, `asin()`, `acos()`, `atan()`, `pow()`, `exp()`, `sqrt()`, `hypot()`, `log()`, `round()`, `mod()`, `rem()`, `atan2()`, `abs()`, `sign()`):**  提供各种常用的数学运算。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:** 这部分代码直接服务于 CSS 解析。当浏览器遇到包含上述数学函数的 CSS 属性值时，就会调用这里的代码来解析这些函数，并将它们转换为内部的数学表达式树。

    * **例 1 (锚点定位):**
      ```css
      .positioned {
        position: absolute;
        top: anchor(--target top); /* 将 .positioned 的顶部与 --target 的顶部对齐 */
        left: anchor(--target start, 10px); /* 将 .positioned 的左侧与 --target 的起始位置对齐，并偏移 10px */
      }
      ```
      这段 CSS 中使用了 `anchor()` 函数，这段代码会解析 `anchor(--target top)` 和 `anchor(--target start, 10px)`。

    * **例 2 (进度指示):**
      ```css
      .progress-bar {
        width: progress(50%) ; /* 简单的进度值 */
      }

      @media (min-width: media-progress(from 0 to 1000px)) {
         /* 当视口宽度从 0 变为 1000px 时应用样式 */
      }

      .container {
        container-name: my-container;
        container-type: inline-size;
      }
      .element {
        font-size: container-progress(width of my-container from 12px to 24px);
      }
      ```
      这里展示了 `progress()`, `media-progress()`, 和 `container-progress()` 的用法，这段代码会解析这些进度函数的参数。

    * **例 3 (尺寸计算):**
      ```css
      .box {
        width: calcSize(auto, 100% - 20px); /* 如果内容不溢出则为 auto，否则为 100% - 20px */
      }
      ```
      `calcSize()` 函数会被这里的代码解析。

    * **例 4 (标准数学函数):**
      ```css
      .element {
        margin-left: max(10px, 5vw); /* 使用 10px 和 5vw 中的较大值 */
        transform: rotate(calc(45deg * sin(0.5))); /* 嵌套使用 calc 和 sin 函数 */
      }
      ```
      `max()` 和 `sin()` 函数会被解析。

* **HTML:** HTML 定义了元素的结构，而 CSS 负责元素的样式，包括使用这些数学函数来确定元素的尺寸、位置等。当浏览器解析 HTML 并应用 CSS 时，会用到这部分代码。

* **JavaScript:** JavaScript 可以读取和修改元素的样式。如果 JavaScript 获取到的样式值中包含这些数学函数，那么这些函数在 CSS 解析阶段就已经被处理过了。此外，一些 JavaScript 动画库或框架可能会在内部使用类似的数学计算，但通常不会直接调用 Blink 引擎的这部分代码。

**逻辑推理、假设输入与输出:**

假设输入是一个 CSS 属性值，例如：`width: calc(min(100%, 300px) + 20px);`

1. **输入:**  `calc(min(100%, 300px) + 20px)` 字符串被传递到解析器。
2. **解析 `calc()`:**  `ParseMathFunction` 函数被调用，`function_id` 为 `CSSValueID::kCalc`。
3. **解析 `min()`:** 在 `calc()` 的参数中遇到 `min(100%, 300px)`，再次调用 `ParseMathFunction`，`function_id` 为 `CSSValueID::kMin`。
4. **解析参数:** `ParseValueExpression` 被调用来解析 `100%` 和 `300px`，生成两个 `CSSMathExpressionNode` 对象，分别表示百分比和像素值。
5. **创建 `min()` 节点:**  `CSSMathExpressionOperation::CreateComparisonFunctionSimplified` 创建一个表示 `min()` 运算的 `CSSMathExpressionNode`。
6. **解析加法:** 返回到 `calc()` 的解析，遇到 `+ 20px`。
7. **解析 `20px`:** `ParseValueExpression` 解析 `20px`，生成一个表示像素值的 `CSSMathExpressionNode`。
8. **创建加法节点:** `CSSMathExpressionOperation::CreateArithmeticOperationSimplified` 创建一个表示加法运算的 `CSSMathExpressionNode`，其左侧是 `min()` 节点的输出，右侧是 `20px` 的节点。
9. **输出:** 返回一个表示整个 `calc()` 表达式的 `CSSMathExpressionNode` 树形结构。

**用户或编程常见的使用错误:**

1. **`calc()` 函数内部语法错误:**
   ```css
   width: calc(100% +20px); /* 缺少空格 */
   height: calc(100% * 20px); /* 百分比乘以长度单位没有意义 */
   ```
   这段代码会因为语法错误而导致解析失败。

2. **数学函数参数类型错误或数量错误:**
   ```css
   transform: rotate(min(45deg, 100px)); /* 角度和长度不能直接比较 */
   border-radius: round(10px); /* round 函数缺少第二个参数（舍入间隔） */
   ```
   这段代码中的 `min()` 和 `round()` 函数使用不当，会导致解析或计算错误。

3. **使用了浏览器不支持的函数或特性:**
   如果使用了较新的 CSS 数学函数，而用户的浏览器版本过低，这些函数可能无法被解析或生效。例如，早期的浏览器不支持 `anchor()` 或 `container-progress()`。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在 HTML 文件中编写 CSS 代码，或者在外部 CSS 文件中编写 CSS 代码。**  这些 CSS 代码中包含了上述提到的数学函数，例如 `width: calc(100% - 20px);`。
2. **用户通过浏览器访问包含这些 CSS 的网页。**
3. **浏览器开始解析 HTML 和 CSS。**
4. **当 CSS 解析器遇到包含数学函数的属性值时，会调用 Blink 渲染引擎中相应的 CSS 解析代码。**
5. **如果遇到 `calc()` 函数，`CSSMathExpressionNode::Parse` 方法会被调用。**
6. **在 `Parse` 方法内部，会根据遇到的不同函数名（如 `min`, `max`, `anchor`, `progress` 等）调用相应的解析函数，例如 `ParseMathFunction`。**
7. **在 `ParseMathFunction` 中，会根据 `function_id` (例如 `CSSValueID::kAnchor`, `CSSValueID::kProgress`) 进入到这段代码中相应的 `if` 分支，执行特定的解析逻辑。**
8. **代码会逐个读取 CSS 词法单元 (tokens)，例如数字、单位、标识符等，并根据 CSS 语法规则构建 `CSSMathExpressionNode` 树。**
9. **如果解析过程中遇到语法错误或不支持的特性，会返回 `nullptr` 或抛出错误。**

因此，调试时，如果怀疑 CSS 数学表达式解析有问题，可以在 Blink 引擎的 CSS 解析相关代码中设置断点，例如在这个文件的 `ParseMathFunction` 函数入口处，或者在特定的函数解析逻辑中，观察解析过程中的变量值和调用堆栈，从而定位问题。

**总结这部分代码的功能:**

这部分 `css_math_expression_node.cc` 代码是 Chromium Blink 引擎中负责解析复杂 CSS 数学表达式函数的核心部分。它识别并解析诸如锚点定位、进度指示、尺寸计算、兄弟元素索引/计数以及各种标准数学运算等函数，将 CSS 文本转换为可供渲染引擎理解和计算的内部数据结构，从而实现 CSS 的动态和灵活的样式控制。

### 提示词
```
这是目录为blink/renderer/core/css/css_math_expression_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
CSSValueID::kStart, CSSValueID::kEnd, CSSValueID::kSelfStart,
            CSSValueID::kSelfEnd, CSSValueID::kCenter>(stream);
        if (!value) {
          value = css_parsing_utils::ConsumePercent(
              stream, context_, CSSPrimitiveValue::ValueRange::kAll);
        }
        break;
      case CSSAnchorQueryType::kAnchorSize:
        value = css_parsing_utils::ConsumeIdent<
            CSSValueID::kWidth, CSSValueID::kHeight, CSSValueID::kBlock,
            CSSValueID::kInline, CSSValueID::kSelfBlock,
            CSSValueID::kSelfInline>(stream);
        break;
    }
    if (!value && function_id == CSSValueID::kAnchor) {
      return nullptr;
    }

    stream.ConsumeWhitespace();
    // |anchor_specifier| may appear after the <anchor-side> / <anchor-size>.
    if (!anchor_specifier) {
      anchor_specifier =
          css_parsing_utils::ConsumeDashedIdent(stream, context_);
    }

    bool expect_comma = anchor_specifier || value;
    const CSSPrimitiveValue* fallback = nullptr;
    if (!expect_comma ||
        css_parsing_utils::ConsumeCommaIncludingWhitespace(stream)) {
      fallback = css_parsing_utils::ConsumeLengthOrPercent(
          stream, context_, CSSPrimitiveValue::ValueRange::kAll,
          css_parsing_utils::UnitlessQuirk::kForbid, allowed_anchor_queries_);
      if (expect_comma && !fallback) {
        return nullptr;
      }
    }

    stream.ConsumeWhitespace();
    if (!stream.AtEnd()) {
      return nullptr;
    }
    return MakeGarbageCollected<CSSMathExpressionAnchorQuery>(
        anchor_query_type, anchor_specifier, value, fallback);
  }

  bool ParseProgressNotationFromTo(
      CSSParserTokenStream& stream,
      State state,
      CSSMathExpressionOperation::Operands& nodes) {
    if (stream.Peek().Id() != CSSValueID::kFrom) {
      return false;
    }
    stream.ConsumeIncludingWhitespace();
    if (CSSMathExpressionNode* node = ParseValueExpression(stream, state)) {
      nodes.push_back(node);
    }
    if (stream.Peek().Id() != CSSValueID::kTo) {
      return false;
    }
    stream.ConsumeIncludingWhitespace();
    if (CSSMathExpressionNode* node = ParseValueExpression(stream, state)) {
      nodes.push_back(node);
    }
    return true;
  }

  // https://drafts.csswg.org/css-values-5/#progress-func
  // https://drafts.csswg.org/css-values-5/#media-progress-func
  // https://drafts.csswg.org/css-values-5/#container-progress-func
  CSSMathExpressionNode* ParseProgressNotation(CSSValueID function_id,
                                               CSSParserTokenStream& stream,
                                               State state) {
    if (function_id != CSSValueID::kProgress &&
        function_id != CSSValueID::kMediaProgress &&
        function_id != CSSValueID::kContainerProgress) {
      return nullptr;
    }
    // <media-progress()> = media-progress(<media-feature> from <calc-sum> to
    // <calc-sum>)
    CSSMathExpressionOperation::Operands nodes;
    stream.ConsumeWhitespace();
    if (function_id == CSSValueID::kMediaProgress) {
      if (CSSMathExpressionKeywordLiteral* node = ParseKeywordLiteral(
              stream,
              CSSMathExpressionKeywordLiteral::Context::kMediaProgress)) {
        nodes.push_back(node);
      }
    } else if (function_id == CSSValueID::kContainerProgress) {
      // <container-progress()> = container-progress(<size-feature> [ of
      // <container-name> ]? from <calc-sum> to <calc-sum>)
      const CSSIdentifierValue* size_feature =
          css_parsing_utils::ConsumeIdent(stream);
      if (!size_feature) {
        return nullptr;
      }
      if (stream.Peek().Id() == CSSValueID::kOf) {
        stream.ConsumeIncludingWhitespace();
        const CSSCustomIdentValue* container_name =
            css_parsing_utils::ConsumeCustomIdent(stream, context_);
        if (!container_name) {
          return nullptr;
        }
        nodes.push_back(MakeGarbageCollected<CSSMathExpressionContainerFeature>(
            size_feature, container_name));
      } else {
        nodes.push_back(MakeGarbageCollected<CSSMathExpressionContainerFeature>(
            size_feature, nullptr));
      }
    } else if (CSSMathExpressionNode* node =
                   ParseValueExpression(stream, state)) {
      // <progress()> = progress(<calc-sum> from <calc-sum> to <calc-sum>)
      nodes.push_back(node);
    }
    if (!ParseProgressNotationFromTo(stream, state, nodes)) {
      return nullptr;
    }
    if (nodes.size() != 3u || !stream.AtEnd() ||
        !CheckProgressFunctionTypes(function_id, nodes)) {
      return nullptr;
    }
    // Note: we don't need to resolve percents in such case,
    // as all the operands are numeric literals,
    // so p% / (t% - f%) will lose %.
    // Note: we can not simplify media-progress.
    ProgressArgsSimplificationStatus status =
        CanEagerlySimplifyProgressArgs(nodes);
    if (function_id == CSSValueID::kProgress &&
        status != ProgressArgsSimplificationStatus::kCanNotSimplify) {
      Vector<double> double_values;
      double_values.reserve(nodes.size());
      for (const CSSMathExpressionNode* operand : nodes) {
        if (status ==
            ProgressArgsSimplificationStatus::kAllArgsResolveToCanonical) {
          std::optional<double> canonical_value =
              operand->ComputeValueInCanonicalUnit();
          CHECK(canonical_value.has_value());
          double_values.push_back(canonical_value.value());
        } else {
          CHECK(HasDoubleValue(operand->ResolvedUnitType()));
          double_values.push_back(operand->DoubleValue());
        }
      }
      double progress_value = (double_values[0] - double_values[1]) /
                              (double_values[2] - double_values[1]);
      return CSSMathExpressionNumericLiteral::Create(
          progress_value, CSSPrimitiveValue::UnitType::kNumber);
    }
    return MakeGarbageCollected<CSSMathExpressionOperation>(
        CalculationResultCategory::kCalcNumber, std::move(nodes),
        CSSValueIDToCSSMathOperator(function_id));
  }

  CSSMathExpressionNode* ParseCalcSize(CSSValueID function_id,
                                       CSSParserTokenStream& stream,
                                       State state) {
    if (function_id != CSSValueID::kCalcSize ||
        !parsing_flags_.Has(Flag::AllowCalcSize)) {
      return nullptr;
    }

    DCHECK(RuntimeEnabledFeatures::CSSCalcSizeFunctionEnabled());

    stream.ConsumeWhitespace();

    CSSMathExpressionNode* basis = nullptr;

    CSSValueID id = stream.Peek().Id();
    bool basis_is_any = id == CSSValueID::kAny;
    if (id != CSSValueID::kInvalid &&
        (id == CSSValueID::kAny ||
         (id == CSSValueID::kAuto &&
          parsing_flags_.Has(Flag::AllowAutoInCalcSize)) ||
         (id == CSSValueID::kContent &&
          parsing_flags_.Has(Flag::AllowContentInCalcSize)) ||
         css_parsing_utils::ValidWidthOrHeightKeyword(id, context_))) {
      // TODO(https://crbug.com/353538495): Right now 'flex-basis'
      // accepts fewer keywords than other width properties.  So for
      // now specifically exclude the ones that it doesn't accept,
      // based off the flag for accepting 'content'.
      if (parsing_flags_.Has(Flag::AllowContentInCalcSize) &&
          !css_parsing_utils::IdentMatches<
              CSSValueID::kAny, CSSValueID::kAuto, CSSValueID::kContent,
              CSSValueID::kMinContent, CSSValueID::kMaxContent,
              CSSValueID::kFitContent, CSSValueID::kStretch>(id)) {
        return nullptr;
      }

      // Note: We don't want to accept 'none' (for 'max-*' properties) since
      // it's not meaningful for animation, since it's equivalent to infinity.
      stream.ConsumeIncludingWhitespace();
      basis = CSSMathExpressionKeywordLiteral::Create(
          id, CSSMathExpressionKeywordLiteral::Context::kCalcSize);
    } else {
      basis = ParseValueExpression(stream, state);
      if (!basis) {
        return nullptr;
      }
    }

    if (!css_parsing_utils::ConsumeCommaIncludingWhitespace(stream)) {
      return nullptr;
    }

    state.allow_size_keyword = !basis_is_any;
    CSSMathExpressionNode* calculation = ParseValueExpression(stream, state);
    if (!calculation) {
      return nullptr;
    }

    return CSSMathExpressionOperation::CreateCalcSizeOperation(basis,
                                                               calculation);
  }

  CSSMathExpressionNode* ParseSiblingIndexOrCount(CSSValueID function_id,
                                                  CSSParserTokenStream& stream,
                                                  State state) {
    if (function_id != CSSValueID::kSiblingCount &&
        function_id != CSSValueID::kSiblingIndex) {
      return nullptr;
    }
    if (!stream.AtEnd()) {
      // These do not take any arguments.
      return nullptr;
    }
    return MakeGarbageCollected<CSSMathExpressionSiblingFunction>(function_id);
  }

  CSSMathExpressionNode* ParseMathFunction(CSSValueID function_id,
                                           CSSParserTokenStream& stream,
                                           State state) {
    if (!IsSupportedMathFunction(function_id)) {
      return nullptr;
    }
    if (auto* anchor_query = ParseAnchorQuery(function_id, stream)) {
      context_.Count(WebFeature::kCSSAnchorPositioning);
      return anchor_query;
    }
    if (RuntimeEnabledFeatures::CSSProgressNotationEnabled()) {
      if (CSSMathExpressionNode* progress =
              ParseProgressNotation(function_id, stream, state)) {
        return progress;
      }
    }
    if (RuntimeEnabledFeatures::CSSCalcSizeFunctionEnabled()) {
      if (CSSMathExpressionNode* calc_size =
              ParseCalcSize(function_id, stream, state)) {
        context_.Count(WebFeature::kCSSCalcSizeFunction);
        return calc_size;
      }
    }
    if (RuntimeEnabledFeatures::CSSSiblingFunctionsEnabled()) {
      if (CSSMathExpressionNode* sibling_function =
              ParseSiblingIndexOrCount(function_id, stream, state)) {
        return sibling_function;
      }
    }

    // "arguments" refers to comma separated ones.
    wtf_size_t min_argument_count = 1;
    wtf_size_t max_argument_count = std::numeric_limits<wtf_size_t>::max();

    switch (function_id) {
      case CSSValueID::kCalc:
      case CSSValueID::kWebkitCalc:
        max_argument_count = 1;
        break;
      case CSSValueID::kMin:
      case CSSValueID::kMax:
        break;
      case CSSValueID::kClamp:
        min_argument_count = 3;
        max_argument_count = 3;
        break;
      case CSSValueID::kSin:
      case CSSValueID::kCos:
      case CSSValueID::kTan:
      case CSSValueID::kAsin:
      case CSSValueID::kAcos:
      case CSSValueID::kAtan:
        max_argument_count = 1;
        break;
      case CSSValueID::kPow:
        DCHECK(RuntimeEnabledFeatures::CSSExponentialFunctionsEnabled());
        max_argument_count = 2;
        min_argument_count = 2;
        break;
      case CSSValueID::kExp:
      case CSSValueID::kSqrt:
        DCHECK(RuntimeEnabledFeatures::CSSExponentialFunctionsEnabled());
        max_argument_count = 1;
        break;
      case CSSValueID::kHypot:
        DCHECK(RuntimeEnabledFeatures::CSSExponentialFunctionsEnabled());
        max_argument_count = kMaxExpressionDepth;
        break;
      case CSSValueID::kLog:
        DCHECK(RuntimeEnabledFeatures::CSSExponentialFunctionsEnabled());
        max_argument_count = 2;
        break;
      case CSSValueID::kRound:
        DCHECK(RuntimeEnabledFeatures::CSSSteppedValueFunctionsEnabled());
        max_argument_count = 3;
        min_argument_count = 1;
        break;
      case CSSValueID::kMod:
      case CSSValueID::kRem:
        DCHECK(RuntimeEnabledFeatures::CSSSteppedValueFunctionsEnabled());
        max_argument_count = 2;
        min_argument_count = 2;
        break;
      case CSSValueID::kAtan2:
        max_argument_count = 2;
        min_argument_count = 2;
        break;
      case CSSValueID::kAbs:
      case CSSValueID::kSign:
        DCHECK(RuntimeEnabledFeatures::CSSSignRelatedFunctionsEnabled());
        max_argument_count = 1;
        min_argument_count = 1;
        break;
      // TODO(crbug.com/1284199): Support other math functions.
      default:
        break;
    }

    HeapVector<Member<const CSSMathExpressionNode>> nodes;
    // Parse the initial (optional) <rounding-strategy> argument to the round()
    // function.
    if (function_id == CSSValueID::kRound) {
      CSSMathExpressionNode* rounding_strategy = ParseRoundingStrategy(stream);
      if (rounding_strategy) {
        nodes.push_back(rounding_strategy);
      }
    }

    while (!stream.AtEnd() && nodes.size() < max_argument_count) {
      if (nodes.size()) {
        if (!css_parsing_utils::ConsumeCommaIncludingWhitespace(stream)) {
          return nullptr;
        }
      }

      stream.ConsumeWhitespace();
      CSSMathExpressionNode* node = ParseValueExpression(stream, state);
      if (!node) {
        return nullptr;
      }

      nodes.push_back(node);
    }

    if (!stream.AtEnd() || nodes.size() < min_argument_count) {
      return nullptr;
    }

    switch (function_id) {
      case CSSValueID::kCalc:
      case CSSValueID::kWebkitCalc: {
        const CSSMathExpressionNode* node = nodes.front();
        if (node->Category() == kCalcIntrinsicSize) {
          return nullptr;
        }
        return const_cast<CSSMathExpressionNode*>(node);
      }
      case CSSValueID::kMin:
      case CSSValueID::kMax:
      case CSSValueID::kClamp: {
        CSSMathOperator op = CSSMathOperator::kMin;
        if (function_id == CSSValueID::kMax) {
          op = CSSMathOperator::kMax;
        }
        if (function_id == CSSValueID::kClamp) {
          op = CSSMathOperator::kClamp;
        }
        CSSMathExpressionNode* node =
            CSSMathExpressionOperation::CreateComparisonFunctionSimplified(
                std::move(nodes), op);
        if (node) {
          context_.Count(WebFeature::kCSSComparisonFunctions);
        }
        return node;
      }
      case CSSValueID::kSin:
      case CSSValueID::kCos:
      case CSSValueID::kTan:
      case CSSValueID::kAsin:
      case CSSValueID::kAcos:
      case CSSValueID::kAtan:
      case CSSValueID::kAtan2: {
        CSSMathExpressionNode* node =
            CSSMathExpressionOperation::CreateTrigonometricFunctionSimplified(
                std::move(nodes), function_id);
        if (node) {
          context_.Count(WebFeature::kCSSTrigFunctions);
        }
        return node;
      }
      case CSSValueID::kPow:
      case CSSValueID::kSqrt:
      case CSSValueID::kHypot:
      case CSSValueID::kLog:
      case CSSValueID::kExp: {
        DCHECK(RuntimeEnabledFeatures::CSSExponentialFunctionsEnabled());
        CSSMathExpressionNode* node =
            CSSMathExpressionOperation::CreateExponentialFunction(
                std::move(nodes), function_id);
        if (node) {
          context_.Count(WebFeature::kCSSExponentialFunctions);
        }
        return node;
      }
      case CSSValueID::kRound:
      case CSSValueID::kMod:
      case CSSValueID::kRem: {
        DCHECK(RuntimeEnabledFeatures::CSSSteppedValueFunctionsEnabled());
        CSSMathOperator op;
        if (function_id == CSSValueID::kRound) {
          DCHECK_GE(nodes.size(), 1u);
          DCHECK_LE(nodes.size(), 3u);
          // If the first argument is a rounding strategy, use the specified
          // operation and drop the argument from the list of operands.
          const auto* maybe_rounding_strategy =
              DynamicTo<CSSMathExpressionOperation>(*nodes[0]);
          if (maybe_rounding_strategy &&
              maybe_rounding_strategy->IsRoundingStrategyKeyword()) {
            op = maybe_rounding_strategy->OperatorType();
            nodes.EraseAt(0);
          } else {
            op = CSSMathOperator::kRoundNearest;
          }
          if (!CanonicalizeRoundArguments(nodes)) {
            return nullptr;
          }
        } else if (function_id == CSSValueID::kMod) {
          op = CSSMathOperator::kMod;
        } else {
          op = CSSMathOperator::kRem;
        }
        DCHECK_EQ(nodes.size(), 2u);
        context_.Count(WebFeature::kCSSRoundModRemFunctions);
        return CSSMathExpressionOperation::CreateSteppedValueFunction(
            std::move(nodes), op);
      }
      case CSSValueID::kAbs:
      case CSSValueID::kSign:
        // TODO(seokho): Relative and Percent values cannot be evaluated at the
        // parsing time. So we should implement cannot be simplified value
        // using CalculationExpressionNode
        DCHECK(RuntimeEnabledFeatures::CSSSignRelatedFunctionsEnabled());
        return CSSMathExpressionOperation::CreateSignRelatedFunction(
            std::move(nodes), function_id);

      case CSSValueID::kSiblingIndex:
      case CSSValueID::kSiblingCount:
        // Handled above.
        return nullptr;

      // TODO(crbug.com/1284199): Support other math functions.
      default:
        return nullptr;
    }
  }

 private:
  CSSMathExpressionNode* ParseValue(CSSParserTokenStream& stream,
                                    State state,
                                    bool& whitespace_after_token) {
    CSSParserToken token = stream.Consume();
    whitespace_after_token = stream.Peek().GetType() == kWhitespaceToken;
    stream.ConsumeWhitespace();
    if (token.Id() == CSSValueID::kInfinity) {
      context_.Count(WebFeature::kCSSCalcConstants);
      return CSSMathExpressionNumericLiteral::Create(
          std::numeric_limits<double>::infinity(),
          CSSPrimitiveValue::UnitType::kNumber);
    }
    if (token.Id() == CSSValueID::kNegativeInfinity) {
      context_.Count(WebFeature::kCSSCalcConstants);
      return CSSMathExpressionNumericLiteral::Create(
          -std::numeric_limits<double>::infinity(),
          CSSPrimitiveValue::UnitType::kNumber);
    }
    if (token.Id() == CSSValueID::kNan) {
      context_.Count(WebFeature::kCSSCalcConstants);
      return CSSMathExpressionNumericLiteral::Create(
          std::numeric_limits<double>::quiet_NaN(),
          CSSPrimitiveValue::UnitType::kNumber);
    }
    if (token.Id() == CSSValueID::kPi) {
      context_.Count(WebFeature::kCSSCalcConstants);
      return CSSMathExpressionNumericLiteral::Create(
          M_PI, CSSPrimitiveValue::UnitType::kNumber);
    }
    if (token.Id() == CSSValueID::kE) {
      context_.Count(WebFeature::kCSSCalcConstants);
      return CSSMathExpressionNumericLiteral::Create(
          M_E, CSSPrimitiveValue::UnitType::kNumber);
    }
    if (state.allow_size_keyword && token.Id() == CSSValueID::kSize) {
      return CSSMathExpressionKeywordLiteral::Create(
          CSSValueID::kSize,
          CSSMathExpressionKeywordLiteral::Context::kCalcSize);
    }
    if (!(token.GetType() == kNumberToken ||
          (token.GetType() == kPercentageToken &&
           parsing_flags_.Has(Flag::AllowPercent)) ||
          token.GetType() == kDimensionToken)) {
      // For relative color syntax.
      // If the associated values of color channels are known, swap them in
      // here. e.g. color(from color(srgb 1 0 0) calc(r * 2) 0 0) should
      // swap in "1" for the value of "r" in the calc expression.
      // If channel values are not known, create keyword literals for valid
      // channel names instead.
      if (auto it = color_channel_map_.find(token.Id());
          it != color_channel_map_.end()) {
        const std::optional<double>& channel = it->value;
        if (channel.has_value()) {
          return CSSMathExpressionNumericLiteral::Create(
              channel.value(), CSSPrimitiveValue::UnitType::kNumber);
        } else {
          return CSSMathExpressionKeywordLiteral::Create(
              token.Id(),
              CSSMathExpressionKeywordLiteral::Context::kColorChannel);
        }
      }
      return nullptr;
    }

    CSSPrimitiveValue::UnitType type = token.GetUnitType();
    if (UnitCategory(type) == kCalcOther) {
      return nullptr;
    }

    return CSSMathExpressionNumericLiteral::Create(
        CSSNumericLiteralValue::Create(token.NumericValue(), type));
  }

  CSSMathExpressionNode* ParseRoundingStrategy(CSSParserTokenStream& stream) {
    CSSMathOperator rounding_op = CSSMathOperator::kInvalid;
    switch (stream.Peek().Id()) {
      case CSSValueID::kNearest:
        rounding_op = CSSMathOperator::kRoundNearest;
        break;
      case CSSValueID::kUp:
        rounding_op = CSSMathOperator::kRoundUp;
        break;
      case CSSValueID::kDown:
        rounding_op = CSSMathOperator::kRoundDown;
        break;
      case CSSValueID::kToZero:
        rounding_op = CSSMathOperator::kRoundToZero;
        break;
      default:
        return nullptr;
    }
    stream.ConsumeIncludingWhitespace();
    return MakeGarbageCollected<CSSMathExpressionOperation>(
        CalculationResultCategory::kCalcNumber, rounding_op);
  }

  CSSMathExpressionNode* ParseValueTerm(CSSParserTokenStream& stream,
                                        State state,
                                        bool& whitespace_after_token) {
    if (stream.AtEnd()) {
      return nullptr;
    }

    if (stream.Peek().GetType() == kLeftParenthesisToken ||
        stream.Peek().FunctionId() == CSSValueID::kCalc) {
      CSSMathExpressionNode* result;
      {
        CSSParserTokenStream::BlockGuard guard(stream);
        stream.ConsumeWhitespace();
        result = ParseValueExpression(stream, state);
        if (!result || !stream.AtEnd()) {
          return nullptr;
        }
        result->SetIsNestedCalc();
      }
      whitespace_after_token = stream.Peek().GetType() == kWhitespaceToken;
      stream.ConsumeWhitespace();
      return result;
    }

    if (stream.Peek().GetType() == kFunctionToken) {
      CSSMathExpressionNode* result;
      CSSValueID function_id = stream.Peek().FunctionId();
      {
        CSSParserTokenStream::BlockGuard guard(stream);
        stream.ConsumeWhitespace();
        result = ParseMathFunction(function_id, stream, state);
      }
      whitespace_after_token = stream.Peek().GetType() == kWhitespaceToken;
      stream.ConsumeWhitespace();
      return result;
    }

    if (stream.Peek().GetBlockType() != CSSParserToken::kNotBlock) {
      return nullptr;
    }

    return ParseValue(stream, state, whitespace_after_token);
  }

  CSSMathExpressionNode* ParseValueMultiplicativeExpression(
      CSSParserTokenStream& stream,
      State state,
      bool& whitespace_after_last) {
    if (stream.AtEnd()) {
      return nullptr;
    }

    CSSMathExpressionNode* result =
        ParseValueTerm(stream, state, whitespace_after_last);
    if (!result) {
      return nullptr;
    }

    while (!stream.AtEnd()) {
      CSSMathOperator math_operator = ParseCSSArithmeticOperator(stream.Peek());
      if (math_operator != CSSMathOperator::kMultiply &&
          math_operator != CSSMathOperator::kDivide) {
        break;
      }
      stream.ConsumeIncludingWhitespace();

      CSSMathExpressionNode* rhs =
          ParseValueTerm(stream, state, whitespace_after_last);
      if (!rhs) {
        return nullptr;
      }

      result = CSSMathExpressionOperation::CreateArithmeticOperationSimplified(
          result, rhs, math_operator);

      if (!result) {
        return nullptr;
      }
    }

    return result;
  }

  CSSMathExpressionNode* ParseAdditiveValueExpression(
      CSSParserTokenStream& stream,
      State state) {
    if (stream.AtEnd()) {
      return nullptr;
    }

    bool whitespace_after_expr = false;  // Initialized only as paranoia.
    CSSMathExpressionNode* result = ParseValueMultiplicativeExpression(
        stream, state, whitespace_after_expr);
    if (!result) {
      return nullptr;
    }

    while (!stream.AtEnd()) {
      CSSMathOperator math_operator = ParseCSSArithmeticOperator(stream.Peek());
      if (math_operator != CSSMathOperator::kAdd &&
          math_operator != CSSMathOperator::kSubtract) {
        break;
      }
      if (!whitespace_after_expr) {
        return nullptr;  // calc(1px+ 2px) is invalid
      }
      stream.Consume();
      if (stream.Peek().GetType() != kWhitespaceToken) {
        return nullptr;  // calc(1px +2px) is invalid
      }
      stream.ConsumeIncludingWhitespace();

      CSSMathExpressionNode* rhs = ParseValueMultiplicativeExpression(
          stream, state, whitespace_after_expr);
      if (!rhs) {
        return nullptr;
      }

      result = CSSMathExpressionOperation::CreateArithmeticOperationSimplified(
          result, rhs, math_operator);

      if (!result) {
        return nullptr;
      }
    }

    if (auto* operation = DynamicTo<CSSMathExpressionOperation>(result)) {
      if (operation->IsAddOrSubtract()) {
        result = MaybeSimplifySumNode(operation);
      }
    }

    return result;
  }

  CSSMathExpressionKeywordLiteral* ParseKeywordLiteral(
      CSSParserTokenStream& stream,
      CSSMathExpressionKeywordLiteral::Context context) {
    const CSSParserToken token = stream.Peek();
    if (token.GetType() == kIdentToken) {
      stream.ConsumeIncludingWhitespace();
      return CSSMathExpressionKeywordLiteral::Create(token.Id(), context);
    }
    return nullptr;
  }

  CSSMathExpressionNode* ParseValueExpression(CSSParserTokenStream& stream,
                                              State state) {
    if (++state.depth > kMaxExpressionDepth) {
      return nullptr;
    }
    return ParseAdditiveValueExpression(stream, state);
  }

  const CSSParserContext& context_;
  const CSSAnchorQueryTypes allowed_anchor_queries_;
  const Flags parsing_flags_;
  const CSSColorChannelMap& color_channel_map_;
};

scoped_refptr<const CalculationValue> CSSMathExpressionNode::ToCalcValue(
    const CSSLengthResolver& length_resolver,
    Length::ValueRange range,
    bool allows_negative_percentage_reference) const {
  if (auto maybe_pixels_and_percent = ToPixelsAndPercent(length_resolver)) {
    // Clamping if pixels + percent could result in NaN. In special case,
    // inf px + inf % could evaluate to nan when
    // allows_negative_percentage_reference is true.
    if (IsNaN(*maybe_pixels_and_percent,
              allows_negative_percentage_reference)) {
      maybe_pixels_and_percent = CreateClampedSamePixelsAndPercent(
          std::numeric_limits<float>::quiet_NaN());
    } else {
      maybe_pixels_and_percent->pixels =
          CSSValueClampingUtils::ClampLength(maybe_pixels_and_percent->pixels);
      maybe_pixels_and_percent->percent =
          CSSValueClampingUtils::ClampLength(maybe_pixels_and_percent->percent);
    }
    return CalculationValue::Create(*maybe_pixels_and_percent, range);
  }

  auto value = ToCalculationExpression(length_resolver);
  std::optional<PixelsAndPercent> evaluated_value =
      EvaluateValueIfNaNorInfinity(value, allows_negative_percentage_reference);
  if (evaluated_value.has_value()) {
    return CalculationValue::Create(evaluated_value.value(), range);
  }
  return CalculationValue::CreateSimplified(value, range);
}

// static
CSSMathExpressionNode* CSSMathExpressionNode::Create(
    const CalculationValue& calc) {
  if (calc.IsExpression()) {
    return Create(*calc.GetOrCreateExpression());
  }
  return Create(calc.GetPixelsAndPercent());
}

// static
CSSMathExpressionNode* CSSMathExpressionNode::Create(PixelsAndPercent value) {
  double percent = value.percent;
  double pixels = value.pixels;
  if (!value.has_explicit_pixels) {
    CHECK(!pixels);
    return CSSMathExpressionNumericLiteral::Create(
        percent, CSSPrimitiveValue::UnitType::kPercentage);
  }
  if (!value.has_explicit_percent) {
    CHECK(!percent);
    return CSSMathExpressionNumericLiteral::Create(
        pixels, CSSPrimitiveValue::UnitType::kPixels);
  }
  CSSMathOperator op = CSSMathOperator::kAdd;
  if (pixels < 0) {
    pixels = -pixels;
    op = CSSMathOperator::kSubtract;
  }
  return CSSMathExpressionOperation::CreateArithmeticOperation(
      CSSMathExpressionNumericLiteral::Create(CSSNumericLiteralValue::Create(
          percent, CSSPrimitiveValue::UnitType::kPercentage)),
      CSSMathExpressionNumericLiteral::Create(CSSNumericLiteralValue::Create(
          pixels, CSSPrimitiveValue::UnitType::kPixels)),
      op);
}

// static
CSSMathExpressionNode* CSSMathExpressionNode::Create(
    const CalculationExpressionNode& node) {
  if (const auto* pixels_and_percent =
          DynamicTo<CalculationExpressionPixelsAndPercentNode>(node)) {
    return Create(pixels_and_percent->GetPixelsAndPercent());
  }

  if (const auto* identifier =
          DynamicTo<CalculationExpressionIdentifierNode>(node)) {
    return CSSMathExpressionIdentifierLiteral::Create(identifier->Value());
  }

  if (const auto* sizing_keyword =
          DynamicTo<CalculationExpressionSizingKeywordNode>(node)) {
    return CSSMathExpressionKeywordLiteral::Create(
        SizingKeywordToCSSValueID(sizing_keyword->Value()),
        CSSMathExpressionKeywordLiteral::Context::kCalcSize);
  }

  if (const auto* color_channel_keyword =
          DynamicTo<CalculationExpressionColorChannelKeywordNode>(node)) {
    return CSSMathExpressionKeywordLiteral::Create(
        ColorChannelKeywordToCSSValueID(color_channel_keyword->Value()),
        CSSMathExpressionKeywordLiteral::Context::kColorChannel);
  }

  if (const auto* number = DynamicTo<CalculationExpressionNumberNode>(node)) {
    return CSSMathExpressionNumericLiteral::Create(
        number->Value(), CSSPrimitiveValue::UnitType::kNumber);
  }

  DCHECK(node.IsOperation());

  const auto& operation = To<CalculationExpressionOperationNode>(node);
  const auto& children = operation.GetChildren();
  const auto calc_op = operation.GetOperator();
  switch (calc_op) {
    case CalculationOperator::kMultiply: {
      DCHECK_EQ(children.size(), 2u);
      return CSSMathExpressionOperation::CreateArithmeticOperation(
          Create(*children.front()), Create(*children.back()),
          CSSMathOperator::kMultiply);
    }
    case CalculationOperator::kInvert: {
      DCHECK_EQ(children.size(), 1u);
      return CSSMathExpressionOperation::CreateArithmeticOperation(
          CSSMathExpressionNumericLiteral::Create(
              1, CSSPrimitiveValue::UnitType::kNumber),
          Create(*children.front()), CSSMathOperator::kDivide);
    }
    case CalculationOperator::kAdd:
    case CalculationOperator::kSubtract: {
      DCHECK_EQ(children.size(), 2u);
      auto* lhs = Create(*children[0]);
      auto* rhs = Create(*children[1]);
      CSSMathOperator op = (calc_op == CalculationOperator::kAdd)
                               ? CSSMathOperator::kAdd
                               : CSSMathOperator::kSubtract;
      return CSSMathExpressionOperation::CreateArithmeticOperation(lhs, rhs,
                                                                   op);
    }
    case CalculationOperator::kMin:
    case CalculationOperator::kMax: {
      DCHECK(children.size());
      CSSMathExpressionOperation::Operands operands;
      for (const auto& child : children) {
        operands.push_back(Create(*child));
      }
      CSSMathOperator op = (calc_op == CalculationOperator::kMin)
                               ? CSSMathOperator::kMin
                               : CSSMathOperator::kMax;
      return CSSMathExpressionOperation::CreateComparisonFunction(
          std::move(operands), op);
    }
    case CalculationOperator::kClamp: {
      DCHECK_EQ(children.size(), 3u);
      CSSMathExpressionOperation::Operands operands;
      for (const auto& child : children) {
        operands.push_back(Create(*child));
      }
      return CSSMathExpressionOperation::CreateComparisonFunction(
          std::move(operands), CSSMathOperator::kClamp);
    }
    case CalculationOperator::kRoundNearest:
    case CalculationOperator::kRoundUp:
    case CalculationOperator::kRoundDown:
    case CalculationOperator::kRoundToZero:
    case CalculationOperator::kMod:
    case CalculationOperator::kRem: {
      DCHECK_EQ(children.size(), 2u);
      CSSMathExpressionOperation::Operands operands;
      for (const auto& child : children) {
        operands.push_back(Create(*child));
      }
      CSSMathOperator op;
      if (calc_op == CalculationOperator::kRoundNearest) {
        op = CSSMathOperator::kRoundNearest;
      } else if (calc_op == CalculationOperator::kRoundUp) {
        op = CSSMathOperator::kRoundUp;
      } else if (calc_op == CalculationOperator::kRoundDown) {
        op = CSSMathOperator::kRoundDown;
      } else if (calc_op == CalculationOperator::kRoundToZero) {
        op = CSSMathOperator::kRoundToZero;
      } else if (c
```