Response:
The user wants to understand the functionality of the provided C++ code snippet from `css_selector_parser.cc`. This is part 2 of 3, so I should focus on the functionality within this specific section and provide a summary at the end.

Here's a breakdown of the code:

1. **`ParsePseudoType` function (continued):**  This function is responsible for identifying and classifying CSS pseudo-classes and pseudo-elements based on the input string. It handles deprecated syntax for custom state pseudo-classes and logs deprecation warnings to the console.
2. **Anonymous namespace with helper functions for parsing legacy pseudo-elements:**
    *   `ParsePseudoElementLegacy`: Parses pseudo-elements using the older single-colon syntax.
    *   `ParsePseudoElementArgument`: Extracts the argument of a pseudo-element function.
3. **`CSSSelectorParser::ParsePseudoElement` function:** This is the main function for parsing pseudo-elements. It checks if the "full pseudo-element parser" feature is enabled. If not, it uses the legacy parsing functions. Otherwise, it uses the standard CSS selector parser. It handles special cases for certain pseudo-elements and extracts arguments if present.
4. **Anonymous namespace with helper functions for validating pseudo-classes after pseudo-elements:**
    *   `IsScrollbarPseudoClass`: Checks if a given pseudo-class is related to scrollbars.
    *   `IsUserActionPseudoClass`: Checks if a given pseudo-class represents a user action.
    *   `IsPseudoClassValidAfterPseudoElement`: Determines if a pseudo-class is valid following a specific pseudo-element.
    *   `IsSimpleSelectorValidAfterPseudoElement`: Checks if a simple selector (which might be a pseudo-class) is valid after a pseudo-element.
    *   `IsPseudoClassValidWithinHasArgument`: Restricts the types of pseudo-classes allowed within the `:has()` pseudo-class.
5. **`CSSSelectorParser::ConsumeCompoundSelector` function:**  This function parses a compound selector, which is a sequence of simple selectors. It handles tag names, universal selectors, IDs, classes, attributes, and pseudo-classes/elements. It also manages namespace handling and prepends type selectors when needed.
6. **`CSSSelectorParser::ConsumeSimpleSelector` function:** This function consumes a single simple selector (like an ID, class, attribute, or pseudo-class/element). It uses the helper functions for specific selector types.
7. **`CSSSelectorParser::ConsumeName` function:** Parses a name, which can be a tag name or attribute name, and handles namespaces.
8. **`CSSSelectorParser::ConsumeId` function:** Parses an ID selector (`#id`).
9. **`CSSSelectorParser::ConsumeClass` function:** Parses a class selector (`.class`).
10. **`CSSSelectorParser::ConsumeAttribute` function:** Parses an attribute selector (`[attribute]`, `[attribute=value]`, etc.).
11. **`CSSSelectorParser::ConsumePseudo` function:** This is a core function for parsing pseudo-classes and pseudo-elements. It handles both identifier-based and functional pseudo-selectors, including complex ones like `:is()`, `:where()`, `:not()`, and `:has()`. It also handles arguments for pseudo-classes and pseudo-elements.

Based on this analysis, the primary functionality of this code snippet is **parsing CSS selectors, particularly focusing on pseudo-classes and pseudo-elements**. It also includes logic for handling deprecated syntax, validating selector combinations, and managing namespaces.这是`blink/renderer/core/css/parser/css_selector_parser.cc`文件的第二部分，主要负责 **解析 CSS 选择器中的伪类 (pseudo-classes) 和伪元素 (pseudo-elements)**，以及处理复合选择器 (compound selectors) 和简单选择器 (simple selectors)。

**功能归纳:**

1. **解析伪类和伪元素:**
    *   `ParsePseudoType`:  识别并分类伪类和伪元素，包括处理过时的语法（例如自定义状态伪类 `:--name` 到 `:state(name)` 的转变），并输出相应的警告信息到控制台。
    *   `ParsePseudoElementLegacy`: 使用旧的单冒号语法解析伪元素。
    *   `ParsePseudoElement`:  作为解析伪元素的主要入口，根据特性开关决定使用新的标准解析器还是旧的解析器。它可以解析出伪元素的 ID，并提取出伪元素的参数（如果有）。

2. **解析复合选择器和简单选择器:**
    *   `ConsumeCompoundSelector`:  解析由一系列简单选择器组成的复合选择器（例如 `div.class#id`）。它会处理标签名、通用选择器、命名空间，并调用 `ConsumeSimpleSelector` 来解析每个简单的部分。
    *   `ConsumeSimpleSelector`:  解析单个简单选择器，例如 ID 选择器 (`#id`)、类选择器 (`.class`)、属性选择器 (`[attribute]`) 和伪类/伪元素选择器 (`:hover`, `::before`)。
    *   `ConsumeName`:  解析名称，这通常是标签名或属性名，并处理命名空间前缀。
    *   `ConsumeId`:  解析 ID 选择器。
    *   `ConsumeClass`:  解析类选择器。
    *   `ConsumeAttribute`:  解析属性选择器，包括不同的匹配模式（例如等于、包含、起始于等）和大小写敏感性。
    *   `ConsumePseudo`:  解析伪类和伪元素，包括带参数和不带参数的情况。对于带参数的伪类/伪元素，它会递归地调用其他的解析函数来处理参数部分的选择器。

3. **验证选择器组合:**
    *   `IsScrollbarPseudoClass`, `IsUserActionPseudoClass`, `IsPseudoClassValidAfterPseudoElement`, `IsSimpleSelectorValidAfterPseudoElement`, `IsPseudoClassValidWithinHasArgument`:  这些辅助函数用于验证特定伪类在特定伪元素之后是否有效，以及在 `:has()` 伪类内部的参数中允许使用的伪类类型，以符合 CSS 规范。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **CSS:**  此代码直接负责解析 CSS 样式规则中的选择器。
    *   **举例:**  当 CSS 规则中包含伪类 `:hover` 时，`ParsePseudoType` 函数会识别出 `hover` 并返回对应的伪类类型。当 CSS 规则包含伪元素 `::before` 时，`ParsePseudoElement` 会识别并返回 `kPseudoIdBefore`。
    *   **举例:**  对于 CSS 选择器 `div.active:hover`, `ConsumeCompoundSelector` 会先处理 `div`，然后调用 `ConsumeClass` 处理 `.active`，最后调用 `ConsumePseudo` 处理 `:hover`。

*   **HTML:** CSS 选择器用于选取 HTML 元素以应用样式。
    *   **举例:**  CSS 规则 `.my-button:hover { background-color: red; }` 中，`.my-button:hover` 选择器会选取所有带有 `my-button` 类的 HTML 元素，并在鼠标悬停时应用背景色为红色的样式。`CSSSelectorParser` 会解析这个选择器，以便浏览器知道要选择哪些元素。

*   **JavaScript:** JavaScript 可以操作 DOM 结构和 CSS 样式。
    *   **举例:**  `document.querySelector('.my-button:hover')` 在 JavaScript 中使用 CSS 选择器选取元素。虽然 JavaScript 本身不直接调用 `CSSSelectorParser`，但浏览器在执行这类 JavaScript 代码时，底层会使用类似 `CSSSelectorParser` 的组件来解析提供的 CSS 选择器。
    *   **举例:**  JavaScript 可以通过修改元素的 `className` 属性来动态添加或移除类，从而触发不同的 CSS 伪类样式 (例如 `:hover`, `:active`)。`CSSSelectorParser` 确保这些动态变化的样式能够被正确解析和应用。

**逻辑推理的假设输入与输出:**

*   **假设输入 (ParsePseudoType):** 字符串 `hover`
    *   **输出:** `CSSSelector::PseudoType::kPseudoHover`
*   **假设输入 (ParsePseudoType):** 字符串 `--my-state` (在启用旧语法的情况下)
    *   **输出:** `CSSSelector::PseudoType::kPseudoStateDeprecatedSyntax`，并可能输出控制台警告。
*   **假设输入 (ParsePseudoElement):** 字符串 `::before`
    *   **输出:** `kPseudoIdBefore`, `argument` 为空。
*   **假设输入 (ParsePseudoElement):** 字符串 `::part(my-part)`
    *   **输出:** `kPseudoIdPart`, `argument` 为 `"my-part"`。
*   **假设输入 (ConsumeCompoundSelector):**  CSS 选择器字符串 `"div.my-class#my-id"`
    *   **输出:** 一个 `CSSSelector` 对象的列表，分别代表 `div` (标签选择器), `.my-class` (类选择器), `#my-id` (ID 选择器)，并且它们之间的关系被设置为 `kSubSelector`。

**用户或编程常见的使用错误举例说明:**

*   **错误的自定义状态伪类语法:**
    *   **用户错误:**  在不再支持旧语法的情况下，用户仍然使用 `:--my-state`。
    *   **结果:**  `ParsePseudoType` 会识别为未知伪类，或者在支持旧语法时，会输出弃用警告。
*   **在不支持的上下文中使用了伪类/伪元素:**
    *   **用户错误:**  在 CSS 中将伪类放在伪元素之后，但该伪类不允许在该伪元素之后出现，例如 `div::before:hover` (`:hover` 不允许在 `::before` 之后直接出现)。
    *   **结果:** `IsPseudoClassValidAfterPseudoElement` 或 `IsSimpleSelectorValidAfterPseudoElement` 会返回 `false`，导致选择器解析失败。
*   **`:` 和 `::` 的混淆:**
    *   **用户错误:**  将伪元素写成单冒号形式，例如 `:before`。
    *   **结果:**  在支持新语法的浏览器中，可能会被解析为伪类，导致样式不生效。`ParsePseudoElement` 会尝试按不同的方式解析。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户编写 HTML, CSS 代码:** 用户在 HTML 文件中链接 CSS 文件，或者在 `<style>` 标签中编写 CSS 样式规则。
2. **浏览器加载和解析 HTML:** 浏览器开始解析 HTML 文件，构建 DOM 树。
3. **浏览器解析 CSS:** 当遇到 `<link>` 标签或 `<style>` 标签时，浏览器会启动 CSS 解析器来解析 CSS 样式规则。
4. **解析选择器:** 在解析 CSS 规则时，`CSSSelectorParser` 被调用来解析选择器部分 (例如 `div.my-class:hover`)。
5. **`ConsumeCompoundSelector` 入口:**  对于复杂的选择器，解析过程通常从 `ConsumeCompoundSelector` 开始。
6. **`ConsumeSimpleSelector` 和 `ConsumePseudo` 调用:**  `ConsumeCompoundSelector` 会根据选择器的结构，依次调用 `ConsumeSimpleSelector` 来处理类名、ID 等，并调用 `ConsumePseudo` 来处理伪类和伪元素。
7. **`ParsePseudoType` 或 `ParsePseudoElement` 执行:** `ConsumePseudo` 内部会调用 `ParsePseudoType` 来识别伪类的类型，或者调用 `ParsePseudoElement` 来解析伪元素。
8. **验证函数执行:**  在解析过程中，诸如 `IsPseudoClassValidAfterPseudoElement` 等验证函数会被调用，以确保选择器的语法正确。
9. **构建内部数据结构:** 解析器会将解析结果存储在内部的数据结构中，以便后续的样式匹配和应用。

**这是第2部分，共3部分，请归纳一下它的功能:**

这部分代码的核心功能是 **解析 CSS 选择器中的伪类和伪元素，并处理复合选择器和简单选择器的语法**。它负责识别不同类型的伪类和伪元素，提取它们的参数，并验证选择器语法的正确性。这是浏览器理解和应用 CSS 样式的关键步骤。

Prompt: 
```
这是目录为blink/renderer/core/css/parser/css_selector_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
ateDeprecatedSyntax);
    }
    if (RuntimeEnabledFeatures::CSSCustomStateDeprecatedSyntaxEnabled()) {
      if (document) {
        // TODO(crbug.com/1514397): Add DevTools deprecations here as well
        document->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kDeprecation,
            mojom::ConsoleMessageLevel::kError,
            "Custom state pseudo classes are changing from \":--" +
                custom_name + "\" to \":state(" + custom_name +
                ")\" soon. See more"
                " here: https://github.com/w3c/csswg-drafts/issues/4805"));
      }
      return CSSSelector::PseudoType::kPseudoStateDeprecatedSyntax;
    } else if (document) {
      document->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::ConsoleMessageSource::kDeprecation,
          mojom::ConsoleMessageLevel::kError,
          "Custom state pseudo classes have been changed from \":--" +
              custom_name + "\" to \":state(" + custom_name +
              ")\". See more here: "
              "https://github.com/w3c/csswg-drafts/issues/4805"));
    }
  }

  return CSSSelector::PseudoType::kPseudoUnknown;
}

namespace {
PseudoId ParsePseudoElementLegacy(const String& selector_string,
                                  const Node* parent) {
  CSSParserTokenStream stream(selector_string);

  int number_of_colons = 0;
  while (!stream.AtEnd() && stream.Peek().GetType() == kColonToken) {
    number_of_colons++;
    stream.Consume();
  }

  // TODO(crbug.com/1197620): allowing 0 or 1 preceding colons is not aligned
  // with specs.
  if (stream.AtEnd() || number_of_colons > 2) {
    return kPseudoIdNone;
  }

  if (stream.Peek().GetType() == kIdentToken) {
    CSSParserToken selector_name_token = stream.Consume();
    PseudoId pseudo_id =
        CSSSelector::GetPseudoId(CSSSelectorParser::ParsePseudoType(
            selector_name_token.Value().ToAtomicString(),
            /*has_arguments=*/false,
            parent ? &parent->GetDocument() : nullptr));

    if (stream.AtEnd() && PseudoElement::IsWebExposed(pseudo_id, parent)) {
      return pseudo_id;
    } else {
      return kPseudoIdNone;
    }
  }

  if (stream.Peek().GetType() == kFunctionToken) {
    CSSParserToken selector_name_token = stream.Peek();
    PseudoId pseudo_id =
        CSSSelector::GetPseudoId(CSSSelectorParser::ParsePseudoType(
            selector_name_token.Value().ToAtomicString(),
            /*has_arguments=*/true, parent ? &parent->GetDocument() : nullptr));

    if (!PseudoElementHasArguments(pseudo_id) ||
        !PseudoElement::IsWebExposed(pseudo_id, parent)) {
      return kPseudoIdNone;
    }

    {
      CSSParserTokenStream::BlockGuard guard(stream);
      if (stream.Peek().GetType() != kIdentToken) {
        return kPseudoIdNone;
      }
      stream.Consume();
      if (!stream.AtEnd()) {
        return kPseudoIdNone;
      }
    }
    return stream.AtEnd() ? pseudo_id : kPseudoIdNone;
  }

  return kPseudoIdNone;
}

AtomicString ParsePseudoElementArgument(const String& selector_string) {
  CSSParserTokenStream stream(selector_string);

  int number_of_colons = 0;
  while (!stream.AtEnd() && stream.Peek().GetType() == kColonToken) {
    number_of_colons++;
    stream.Consume();
  }

  // TODO(crbug.com/1197620): allowing 0 or 1 preceding colons is not aligned
  // with specs.
  if (number_of_colons > 2 || stream.Peek().GetType() != kFunctionToken) {
    return g_null_atom;
  }

  AtomicString ret;
  {
    CSSParserTokenStream::BlockGuard guard(stream);
    if (stream.Peek().GetType() != kIdentToken) {
      return g_null_atom;
    }
    ret = stream.Consume().Value().ToAtomicString();
    if (!stream.AtEnd()) {
      return g_null_atom;
    }
  }
  if (!stream.AtEnd()) {
    return g_null_atom;
  }
  return ret;
}
}  // namespace

// static
PseudoId CSSSelectorParser::ParsePseudoElement(const String& selector_string,
                                               const Node* parent,
                                               AtomicString& argument) {
  if (!RuntimeEnabledFeatures::
          CSSComputedStyleFullPseudoElementParserEnabled()) {
    PseudoId pseudo_id = ParsePseudoElementLegacy(selector_string, parent);
    if (PseudoElementHasArguments(pseudo_id)) {
      argument = ParsePseudoElementArgument(selector_string);
    }
    return pseudo_id;
  }

  // For old pseudos (before, after, first-letter, first-line), we
  // allow the legacy behavior of single-colon / no-colon.
  {
    CSSParserTokenStream stream(selector_string);
    stream.EnsureLookAhead();
    int num_colons = 0;
    if (stream.Peek().GetType() == kColonToken) {
      stream.Consume();
      ++num_colons;
    }
    if (stream.Peek().GetType() == kColonToken) {
      stream.Consume();
      ++num_colons;
    }

    CSSParserToken selector_name_token = stream.Peek();
    if (selector_name_token.GetType() == kIdentToken) {
      stream.Consume();
      if (!selector_name_token.Value().ContainsOnlyASCIIOrEmpty()) {
        return kPseudoIdInvalid;
      }
      if (stream.Peek().GetType() != kEOFToken) {
        return kPseudoIdInvalid;
      }

      CSSSelector::PseudoType pseudo_type = ParsePseudoType(
          selector_name_token.Value().ToAtomicString(),
          /*has_arguments=*/false, parent ? &parent->GetDocument() : nullptr);

      PseudoId pseudo_id = CSSSelector::GetPseudoId(pseudo_type);
      if (pseudo_id == kPseudoIdCheck || pseudo_id == kPseudoIdBefore ||
          pseudo_id == kPseudoIdAfter || pseudo_id == kPseudoIdSelectArrow ||
          pseudo_id == kPseudoIdFirstLetter ||
          pseudo_id == kPseudoIdFirstLine) {
        return pseudo_id;
      }

      // For ::-webkit-* and ::-internal-* pseudo-elements, act like there's
      // no pseudo-element provided and (at least for getComputedStyle, our
      // most significant caller) use the element style instead.
      // TODO(https://crbug.com/363015176): We should either do something
      // correct or treat them as unsupported.
      if ((pseudo_type == CSSSelector::PseudoType::kPseudoWebKitCustomElement ||
           pseudo_type ==
               CSSSelector::PseudoType::kPseudoBlinkInternalElement ||
           (!RuntimeEnabledFeatures::
                PseudoElementsCorrectInGetComputedStyleEnabled() &&
            (pseudo_type == CSSSelector::PseudoType::kPseudoCue ||
             pseudo_type == CSSSelector::PseudoType::kPseudoPlaceholder ||
             pseudo_type ==
                 CSSSelector::PseudoType::kPseudoFileSelectorButton))) &&
          num_colons == 2) {
        return kPseudoIdNone;
      }
    }

    if (num_colons != 2) {
      return num_colons == 1 ? kPseudoIdInvalid : kPseudoIdNone;
    }
  }

  // Otherwise, we use the standard pseudo-selector parser.
  // A restart is OK here, since this function is called only from
  // getComputedStyle() and similar, not the main parsing path.
  HeapVector<CSSSelector> arena;
  CSSSelectorParser parser(
      StrictCSSParserContext(SecureContextMode::kInsecureContext),
      /*parent_rule_for_nesting=*/nullptr,
      /*is_within_scope=*/false, /*semicolon_aborts_nested_selector=*/false,
      /*style_sheet=*/nullptr, arena);

  ResetVectorAfterScope reset_vector(parser.output_);
  CSSParserTokenStream stream(selector_string);
  ResultFlags result_flags = 0;
  if (!parser.ConsumePseudo(stream, result_flags)) {
    return kPseudoIdInvalid;
  }

  auto selector = reset_vector.AddedElements();
  if (selector.size() != 1 || !stream.AtEnd()) {
    return kPseudoIdInvalid;
  }

  const CSSSelector& result = selector[0];
  if (!result.MatchesPseudoElement()) {
    return kPseudoIdInvalid;
  }

  PseudoId pseudo_id = result.GetPseudoId(result.GetPseudoType());
  if (!PseudoElement::IsWebExposed(pseudo_id, parent)) {
    return kPseudoIdInvalid;
  }

  switch (pseudo_id) {
    case kPseudoIdHighlight: {
      argument = result.Argument();
      return pseudo_id;
    }

    case kPseudoIdViewTransitionGroup:
    case kPseudoIdViewTransitionImagePair:
    case kPseudoIdViewTransitionOld:
    case kPseudoIdViewTransitionNew: {
      if (result.IdentList().size() != 1 ||
          result.IdentList()[0] == CSSSelector::UniversalSelectorAtom()) {
        return kPseudoIdInvalid;
      }
      argument = result.IdentList()[0];
      return pseudo_id;
    }

    default:
      return pseudo_id;
  }
}

namespace {

bool IsScrollbarPseudoClass(CSSSelector::PseudoType pseudo) {
  switch (pseudo) {
    case CSSSelector::kPseudoEnabled:
    case CSSSelector::kPseudoDisabled:
    case CSSSelector::kPseudoHover:
    case CSSSelector::kPseudoActive:
    case CSSSelector::kPseudoHorizontal:
    case CSSSelector::kPseudoVertical:
    case CSSSelector::kPseudoDecrement:
    case CSSSelector::kPseudoIncrement:
    case CSSSelector::kPseudoStart:
    case CSSSelector::kPseudoEnd:
    case CSSSelector::kPseudoDoubleButton:
    case CSSSelector::kPseudoSingleButton:
    case CSSSelector::kPseudoNoButton:
    case CSSSelector::kPseudoCornerPresent:
    case CSSSelector::kPseudoWindowInactive:
      return true;
    default:
      return false;
  }
}

bool IsUserActionPseudoClass(CSSSelector::PseudoType pseudo) {
  switch (pseudo) {
    case CSSSelector::kPseudoHover:
    case CSSSelector::kPseudoFocus:
    case CSSSelector::kPseudoFocusVisible:
    case CSSSelector::kPseudoFocusWithin:
    case CSSSelector::kPseudoActive:
      return true;
    default:
      return false;
  }
}

bool IsPseudoClassValidAfterPseudoElement(
    CSSSelector::PseudoType pseudo_class,
    CSSSelector::PseudoType compound_pseudo_element) {
  // NOTE: pseudo-class rules for ::part() and element-backed pseudo-elements
  // do not need to be handled here; they should be handled in
  // CSSSelector::IsAllowedAfterPart() instead.
  switch (compound_pseudo_element) {
    case CSSSelector::kPseudoResizer:
    case CSSSelector::kPseudoScrollbar:
    case CSSSelector::kPseudoScrollbarCorner:
    case CSSSelector::kPseudoScrollbarButton:
    case CSSSelector::kPseudoScrollbarThumb:
    case CSSSelector::kPseudoScrollbarTrack:
    case CSSSelector::kPseudoScrollbarTrackPiece:
      return IsScrollbarPseudoClass(pseudo_class);
    case CSSSelector::kPseudoSelection:
      return pseudo_class == CSSSelector::kPseudoWindowInactive;
    case CSSSelector::kPseudoWebKitCustomElement:
    case CSSSelector::kPseudoBlinkInternalElement:
    case CSSSelector::kPseudoFileSelectorButton:
      return IsUserActionPseudoClass(pseudo_class);
    case CSSSelector::kPseudoViewTransitionGroup:
    case CSSSelector::kPseudoViewTransitionImagePair:
    case CSSSelector::kPseudoViewTransitionOld:
    case CSSSelector::kPseudoViewTransitionNew:
      return pseudo_class == CSSSelector::kPseudoOnlyChild;
    case CSSSelector::kPseudoSearchText:
      return pseudo_class == CSSSelector::kPseudoCurrent;
    case CSSSelector::kPseudoScrollMarker:
    case CSSSelector::kPseudoScrollNextButton:
    case CSSSelector::kPseudoScrollPrevButton:
      // TODO(crbug.com/40824273): User action pseudos should be allowed more
      // generally after pseudo elements.
      return pseudo_class == CSSSelector::kPseudoFocus ||
             pseudo_class == CSSSelector::kPseudoChecked;
    default:
      return false;
  }
}

bool IsSimpleSelectorValidAfterPseudoElement(
    const CSSSelector& simple_selector,
    CSSSelector::PseudoType compound_pseudo_element) {
  switch (compound_pseudo_element) {
    case CSSSelector::kPseudoColumn:
      return simple_selector.GetPseudoType() ==
             CSSSelector::kPseudoScrollMarker;
    case CSSSelector::kPseudoUnknown:
      return true;
    case CSSSelector::kPseudoSelectArrow:
    case CSSSelector::kPseudoAfter:
    case CSSSelector::kPseudoBefore:
    case CSSSelector::kPseudoCheck:
      if (simple_selector.GetPseudoType() == CSSSelector::kPseudoMarker &&
          RuntimeEnabledFeatures::CSSMarkerNestedPseudoElementEnabled()) {
        return true;
      }
      break;
    case CSSSelector::kPseudoSlotted:
      return simple_selector.IsTreeAbidingPseudoElement();
    default:
      break;
  }
  if ((compound_pseudo_element == CSSSelector::kPseudoPart ||
       CSSSelector::IsElementBackedPseudoElement(compound_pseudo_element)) &&
      simple_selector.IsAllowedAfterPart()) {
    return true;
  }
  if (simple_selector.Match() != CSSSelector::kPseudoClass) {
    return false;
  }
  CSSSelector::PseudoType pseudo = simple_selector.GetPseudoType();
  switch (pseudo) {
    case CSSSelector::kPseudoIs:
    case CSSSelector::kPseudoWhere:
    case CSSSelector::kPseudoNot:
      // These pseudo-classes are themselves always valid.
      // CSSSelectorParser::restricting_pseudo_element_ ensures that invalid
      // nested selectors will be dropped if they are invalid according to
      // this function.
      return true;
    case CSSSelector::kPseudoHas:
      if (!RuntimeEnabledFeatures::CSSPartAllowsMoreSelectorsAfterEnabled()) {
        return true;
      }
      [[fallthrough]];
    default:
      break;
  }
  return IsPseudoClassValidAfterPseudoElement(pseudo, compound_pseudo_element);
}

bool IsPseudoClassValidWithinHasArgument(CSSSelector& selector) {
  DCHECK_EQ(selector.Match(), CSSSelector::kPseudoClass);
  switch (selector.GetPseudoType()) {
    // Limited nested :has() to avoid increasing :has() invalidation complexity.
    case CSSSelector::kPseudoHas:
      return false;
    default:
      return true;
  }
}

}  // namespace

base::span<CSSSelector> CSSSelectorParser::ConsumeCompoundSelector(
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    ResultFlags& result_flags) {
  ResetVectorAfterScope reset_vector(output_);
  wtf_size_t start_pos = output_.size();
  base::AutoReset<CSSSelector::PseudoType> reset_restricting(
      &restricting_pseudo_element_, restricting_pseudo_element_);
  base::AutoReset<bool> reset_found_host_in_compound(&found_host_in_compound_,
                                                     false);

  // See if the compound selector starts with a tag name, universal selector
  // or the likes (these can only be at the beginning). Note that we don't
  // add this to output_ yet, because there are situations where it should
  // be ignored (like if we have a universal selector and don't need it;
  // e.g. *:hover is the same as :hover). Thus, we just keep its data around
  // and prepend it if needed.
  //
  // TODO(sesse): In 99% of cases, we should add this, so the prepending logic
  // gets very complex with having to deal with both the explicit and the
  // implicit case. Consider just inserting it, and then removing it
  // afterwards if we really don't need it.
  AtomicString namespace_prefix;
  AtomicString element_name;
  const bool has_q_name = ConsumeName(stream, element_name, namespace_prefix);
  if (context_->IsHTMLDocument()) {
    element_name = element_name.LowerASCII();
  }

  // A tag name is not valid following a pseudo-element. This can happen for
  // e.g. :::part(x):is(div).
  if (restricting_pseudo_element_ != CSSSelector::kPseudoUnknown &&
      has_q_name) {
    failed_parsing_ = true;
    return {};  // Failure.
  }

  // Consume all the simple selectors that are not tag names.
  while (ConsumeSimpleSelector(stream, result_flags)) {
    const CSSSelector& simple_selector = output_.back();
    if (simple_selector.Match() == CSSSelector::kPseudoElement) {
      restricting_pseudo_element_ = simple_selector.GetPseudoType();
    }
    output_.back().SetRelation(CSSSelector::kSubSelector);
  }

  // While inside a nested selector like :is(), the default namespace shall
  // be ignored when [1]:
  //
  // - The compound selector represents the subject [2], and
  // - The compound selector does not contain a type/universal selector.
  //
  // [1] https://drafts.csswg.org/selectors/#matches
  // [2] https://drafts.csswg.org/selectors/#selector-subject
  base::AutoReset<bool> ignore_namespace(
      &ignore_default_namespace_,
      ignore_default_namespace_ || (resist_default_namespace_ && !has_q_name &&
                                    AtEndIgnoringWhitespace(stream)));

  if (reset_vector.AddedElements().empty()) {
    // No simple selectors except for the tag name.
    // TODO(sesse): Does this share too much code with
    // PrependTypeSelectorIfNeeded()?
    if (!has_q_name) {
      // No tag name either, so we fail parsing of this selector.
      return {};
    }
    DCHECK(has_q_name);
    AtomicString namespace_uri = DetermineNamespace(namespace_prefix);
    if (namespace_uri.IsNull()) {
      context_->Count(WebFeature::kCSSUnknownNamespacePrefixInSelector);
      failed_parsing_ = true;
      return {};
    }
    if (namespace_uri == DefaultNamespace()) {
      namespace_prefix = g_null_atom;
    }
    context_->Count(WebFeature::kHasIDClassTagAttribute);
    output_.push_back(CSSSelector(
        QualifiedName(namespace_prefix, element_name, namespace_uri)));
    return reset_vector.CommitAddedElements();
  }

  // Prepend a tag selector if we have one, either explicitly or implicitly.
  // One could be added implicitly e.g. if we are in a non-default namespace
  // and have no tag selector already, we may need to convert .foo to
  // (ns|*).foo, with an implicit universal selector prepended before .foo.
  // The explicit case is when we simply have a tag; e.g. if someone wrote
  // div.foo.bar, we've added .foo.bar earlier and are prepending div now.
  //
  // TODO(futhark@chromium.org): Prepending a type selector to the compound is
  // unnecessary if this compound is an argument to a pseudo selector like
  // :not(), since a type selector will be prepended at the top level of the
  // selector if necessary. We need to propagate that context information here
  // to tell if we are at the top level.
  PrependTypeSelectorIfNeeded(namespace_prefix, has_q_name, element_name,
                              start_pos);

  // The relationship between all of these are that they are sub-selectors.
  for (CSSSelector& selector : reset_vector.AddedElements().first(
           reset_vector.AddedElements().size() - 1)) {
    selector.SetRelation(CSSSelector::kSubSelector);
  }

  SplitCompoundAtImplicitShadowCrossingCombinator(reset_vector.AddedElements());
  return reset_vector.CommitAddedElements();
}

bool CSSSelectorParser::ConsumeSimpleSelector(CSSParserTokenStream& stream,
                                              ResultFlags& result_flags) {
  ResultFlags local_result_flags = 0;
  const CSSParserToken& token = stream.Peek();
  bool ok;
  if (token.GetType() == kHashToken) {
    ok = ConsumeId(stream);
  } else if (token.GetType() == kDelimiterToken && token.Delimiter() == '.') {
    ok = ConsumeClass(stream);
  } else if (token.GetType() == kLeftBracketToken) {
    ok = ConsumeAttribute(stream);
  } else if (token.GetType() == kColonToken) {
    ok = ConsumePseudo(stream, local_result_flags);
    if (ok) {
      local_result_flags |= kContainsPseudo;
    }
  } else if (token.GetType() == kDelimiterToken && token.Delimiter() == '&') {
    ok = ConsumeNestingParent(stream, local_result_flags);
  } else {
    return false;
  }
  // TODO(futhark@chromium.org): crbug.com/578131
  // The UASheetMode check is a work-around to allow this selector in
  // mediaControls(New).css:
  // video::-webkit-media-text-track-region-container.scrolling
  if (!ok || (context_->Mode() != kUASheetMode &&
              !IsSimpleSelectorValidAfterPseudoElement(
                  output_.back(), restricting_pseudo_element_))) {
    failed_parsing_ = true;
    return false;
  }
  if (local_result_flags & kContainsScopeOrParent) {
    output_.back().SetScopeContaining(true);
  }
  result_flags |= local_result_flags;
  return true;
}

bool CSSSelectorParser::ConsumeName(CSSParserTokenStream& stream,
                                    AtomicString& name,
                                    AtomicString& namespace_prefix) {
  name = g_null_atom;
  namespace_prefix = g_null_atom;

  const CSSParserToken& first_token = stream.Peek();
  if (first_token.GetType() == kIdentToken) {
    name = first_token.Value().ToAtomicString();
    stream.Consume();
  } else if (first_token.GetType() == kDelimiterToken &&
             first_token.Delimiter() == '*') {
    name = CSSSelector::UniversalSelectorAtom();
    stream.Consume();
  } else if (first_token.GetType() == kDelimiterToken &&
             first_token.Delimiter() == '|') {
    // This is an empty namespace, which'll get assigned this value below
    name = g_empty_atom;
  } else {
    return false;
  }

  if (stream.Peek().GetType() != kDelimiterToken ||
      stream.Peek().Delimiter() != '|') {
    return true;
  }

  CSSParserSavePoint savepoint(stream);
  stream.Consume();

  namespace_prefix =
      name == CSSSelector::UniversalSelectorAtom() ? g_star_atom : name;
  if (stream.Peek().GetType() == kIdentToken) {
    name = stream.Consume().Value().ToAtomicString();
  } else if (stream.Peek().GetType() == kDelimiterToken &&
             stream.Peek().Delimiter() == '*') {
    stream.Consume();
    name = CSSSelector::UniversalSelectorAtom();
  } else {
    name = g_null_atom;
    namespace_prefix = g_null_atom;
    return false;
  }

  savepoint.Release();
  return true;
}

bool CSSSelectorParser::ConsumeId(CSSParserTokenStream& stream) {
  DCHECK_EQ(stream.Peek().GetType(), kHashToken);
  if (stream.Peek().GetHashTokenType() != kHashTokenId) {
    return false;
  }
  CSSSelector selector;
  selector.SetMatch(CSSSelector::kId);
  AtomicString value = stream.Consume().Value().ToAtomicString();
  selector.SetValue(value, IsQuirksModeBehavior(context_->Mode()));
  output_.push_back(std::move(selector));
  context_->Count(WebFeature::kHasIDClassTagAttribute);
  return true;
}

bool CSSSelectorParser::ConsumeClass(CSSParserTokenStream& stream) {
  DCHECK_EQ(stream.Peek().GetType(), kDelimiterToken);
  DCHECK_EQ(stream.Peek().Delimiter(), '.');
  stream.Consume();
  if (stream.Peek().GetType() != kIdentToken) {
    return false;
  }
  CSSSelector selector;
  selector.SetMatch(CSSSelector::kClass);
  AtomicString value = stream.Consume().Value().ToAtomicString();
  selector.SetValue(value, IsQuirksModeBehavior(context_->Mode()));
  output_.push_back(std::move(selector));
  context_->Count(WebFeature::kHasIDClassTagAttribute);
  return true;
}

bool CSSSelectorParser::ConsumeAttribute(CSSParserTokenStream& stream) {
  DCHECK_EQ(stream.Peek().GetType(), kLeftBracketToken);
  CSSParserTokenStream::BlockGuard guard(stream);
  stream.ConsumeWhitespace();

  AtomicString namespace_prefix;
  AtomicString attribute_name;
  if (!ConsumeName(stream, attribute_name, namespace_prefix)) {
    return false;
  }
  if (attribute_name == CSSSelector::UniversalSelectorAtom()) {
    return false;
  }
  stream.ConsumeWhitespace();

  if (context_->IsHTMLDocument()) {
    attribute_name = attribute_name.LowerASCII();
  }

  AtomicString namespace_uri = DetermineNamespace(namespace_prefix);
  if (namespace_uri.IsNull()) {
    return false;
  }

  QualifiedName qualified_name =
      namespace_prefix.IsNull()
          ? QualifiedName(attribute_name)
          : QualifiedName(namespace_prefix, attribute_name, namespace_uri);

  if (stream.AtEnd()) {
    CSSSelector selector(CSSSelector::kAttributeSet, qualified_name,
                         CSSSelector::AttributeMatchType::kCaseSensitive);
    output_.push_back(std::move(selector));
    context_->Count(WebFeature::kHasIDClassTagAttribute);
    return true;
  }

  CSSSelector::MatchType match_type = ConsumeAttributeMatch(stream);

  CSSParserToken attribute_value = stream.Peek();
  if (attribute_value.GetType() != kIdentToken &&
      attribute_value.GetType() != kStringToken) {
    return false;
  }
  stream.ConsumeIncludingWhitespace();
  CSSSelector::AttributeMatchType case_sensitivity =
      ConsumeAttributeFlags(stream);
  if (!stream.AtEnd()) {
    return false;
  }

  CSSSelector selector(match_type, qualified_name, case_sensitivity,
                       attribute_value.Value().ToAtomicString());
  output_.push_back(std::move(selector));
  context_->Count(WebFeature::kHasIDClassTagAttribute);
  return true;
}

bool CSSSelectorParser::ConsumePseudo(CSSParserTokenStream& stream,
                                      ResultFlags& result_flags) {
  DCHECK_EQ(stream.Peek().GetType(), kColonToken);
  stream.Consume();

  int colons = 1;
  if (stream.Peek().GetType() == kColonToken) {
    stream.Consume();
    colons++;
  }

  const CSSParserToken& token = stream.Peek();
  if (token.GetType() != kIdentToken && token.GetType() != kFunctionToken) {
    return false;
  }

  CSSSelector selector;
  selector.SetMatch(colons == 1 ? CSSSelector::kPseudoClass
                                : CSSSelector::kPseudoElement);

  bool has_arguments = token.GetType() == kFunctionToken;
  selector.UpdatePseudoType(token.Value().ToAtomicString(), *context_,
                            has_arguments, context_->Mode());

  if (selector.Match() == CSSSelector::kPseudoElement) {
    switch (selector.GetPseudoType()) {
      case CSSSelector::kPseudoBefore:
      case CSSSelector::kPseudoAfter:
        context_->Count(WebFeature::kHasBeforeOrAfterPseudoElement);
        break;
      case CSSSelector::kPseudoMarker:
        if (context_->Mode() != kUASheetMode) {
          context_->Count(WebFeature::kHasMarkerPseudoElement);
        }
        break;
      case CSSSelector::kPseudoSpellingError:
      case CSSSelector::kPseudoGrammarError:
        if (context_->Mode() != kUASheetMode) {
          context_->Count(WebFeature::kHasSpellingOrGrammarErrorPseudoElement);
        }
        break;
      default:
        break;
    }
  }

  if (selector.Match() == CSSSelector::kPseudoElement &&
      disallow_pseudo_elements_) {
    return false;
  }

  if (is_inside_has_argument_) {
    DCHECK(disallow_pseudo_elements_);
    if (!IsPseudoClassValidWithinHasArgument(selector)) {
      return false;
    }
  }

  if (token.GetType() == kIdentToken) {
    stream.Consume();
    if (selector.GetPseudoType() == CSSSelector::kPseudoUnknown) {
      return false;
    }
    if (selector.GetPseudoType() == CSSSelector::kPseudoHost) {
      found_host_in_compound_ = true;
    }
    if (selector.GetPseudoType() == CSSSelector::kPseudoScope) {
      result_flags |= kContainsScopeOrParent;
    }
    output_.push_back(std::move(selector));
    return true;
  }

  CSSParserTokenStream::BlockGuard guard(stream);
  stream.ConsumeWhitespace();
  if (selector.GetPseudoType() == CSSSelector::kPseudoUnknown) {
    return false;
  }

  switch (selector.GetPseudoType()) {
    case CSSSelector::kPseudoIs: {
      DisallowPseudoElementsScope scope(this);
      base::AutoReset<bool> resist_namespace(&resist_default_namespace_, true);
      CSSSelectorList* selector_list =
          ConsumeForgivingNestedSelectorList(stream, result_flags);
      if (!selector_list || !stream.AtEnd()) {
        return false;
      }
      selector.SetSelectorList(selector_list);
      output_.push_back(std::move(selector));
      return true;
    }
    case CSSSelector::kPseudoWhere: {
      DisallowPseudoElementsScope scope(this);
      base::AutoReset<bool> resist_namespace(&resist_default_namespace_, true);
      CSSSelectorList* selector_list =
          ConsumeForgivingNestedSelectorList(stream, result_flags);
      if (!selector_list || !stream.AtEnd()) {
        return false;
      }
      selector.SetSelectorList(selector_list);
      output_.push_back(std::move(selector));
      return true;
    }
    case CSSSelector::kPseudoHost:
    case CSSSelector::kPseudoHostContext:
      found_host_in_compound_ = true;
      [[fallthrough]];
    case CSSSelector::kPseudoAny:
    case CSSSelector::kPseudoCue: {
      DisallowPseudoElementsScope scope(this);
      base::AutoReset<bool> inside_compound(&inside_compound_pseudo_, true);
      base::AutoReset<bool> ignore_namespace(
          &ignore_default_namespace_,
          ignore_default_namespace_ ||
              selector.GetPseudoType() == CSSSelector::kPseudoCue);

      CSSSelectorList* selector_list =
          ConsumeCompoundSelectorList(stream, result_flags);
      if (!selector_list || !selector_list->IsValid() || !stream.AtEnd()) {
        return false;
      }

      if (!selector_list->IsSingleComplexSelector()) {
        if (selector.GetPseudoType() == CSSSelector::kPseudoHost) {
          return false;
        }
        if (selector.GetPseudoType() == CSSSelector::kPseudoHostContext) {
          return false;
        }
      }

      selector.SetSelectorList(selector_list);
      output_.push_back(std::move(selector));
      return true;
    }
    case CSSSelector::kPseudoHas: {
      DisallowPseudoElementsScope scope(this);
      base::AutoReset<bool> resist_namespace(&resist_default_namespace_, true);

      base::AutoReset<bool> is_inside_has_argument(&is_inside_has_argument_,
                                                   true);
      ResultFlags local_result_flags = 0;
      CSSSelectorList* selector_list;
      selector_list = ConsumeRelativeSelectorList(stream, local_result_flags);
      if (!selector_list || !selector_list->IsValid() || !stream.AtEnd()) {
        return false;
      }
      selector.SetSelectorList(selector_list);
      if (local_result_flags & kContainsPseudo) {
        selector.SetContainsPseudoInsideHasPseudoClass();
      }
      if (local_result_flags & kContainsComplexSelector) {
        selector.SetContainsComplexLogicalCombinationsInsideHasPseudoClass();
      }
      if (found_host_in_compound_) {
        selector.SetHasArgumentMatchInShadowTree();
      }
      output_.push_back(std::move(selector));
      result_flags |= local_result_flags;
      return true;
    }
    case CSSSelector::kPseudoNot: {
      DisallowPseudoElementsScope scope(this);
      base::AutoReset<bool> resist_namespace(&resist_default_namespace_, true);
      CSSSelectorList* selector_list =
          ConsumeNestedSelectorList(stream, result_flags);
      if (!selector_list || !selector_list->IsValid() || !stream.AtEnd()) {
        return false;
      }

      selector.SetSelectorList(selector_list);
      output_.push_back(std::move(selector));
      return true;
    }
    case CSSSelector::kPseudoPicker:
      if (!RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
        return false;
      }
      [[fallthrough]];
    case CSSSelector::kPseudoDir:
    case CSSSelector::kPseudoState: {
      CHECK(selector.GetPseudoType() != CSSSelector::kPseudoState ||
            RuntimeEnabledFeatures::CSSCustomStateNewSyntaxEnabled());
      const CSSParserToken& ident = stream.Peek();
      if (ident.GetType() != kIdentToken) {
        return false;
      }
      selector.SetArgument(ident.Value().ToAtomicString());
      stream.ConsumeIncludingWhitespace();
      if (!stream.AtEnd()) {
        return false;
      }
      output_.push_back(std::move(selector));
      return true;
    }
    case CSSSelector::kPseudoPart: {
      Vector<AtomicString> parts;
      do {
        const CSSParserToken& ident = stream.Peek();
        if (ident.GetType() != kIdentToken) {
          return false;
        }
        parts.push_back(ident.Value().ToAtomicString());
        stream.ConsumeIncludingWhitespace();
      } while (!stream.AtEnd());
      selector.SetIdentList(std::make_unique<Vector<AtomicString>>(parts));
      output_.push_back(std::move(selector));
      return true;
    }
    case CSSSelector::kPseudoActiveViewTransitionType: {
      if (!RuntimeEnabledFeatures::ViewTransitionTypesEnabled()) {
        return false;
      }

      Vector<AtomicString> types;
      for (;;) {
        const CSSParserToken& ident = stream.Peek();
        if (ident.GetType() != kIdentToken) {
          return false;
        }
        types.push_back(ident.Value().ToAtomicString());
        stream.ConsumeIncludingWhitespace();

        if (stream.AtEnd()) {
          break;
        }

        const CSSParserToken& comma = stream.Peek();
        if (comma.GetType() != kCommaToken) {
          return false;
        }
        stream.ConsumeIncludingWhitespace();
        if (stream.AtEnd()) {
          return false;
        }
      }
      selector.SetIdentList(std::make_unique<Vector<AtomicString>>(types));
      output_.push_back(std::move(selector));
      return true;
    }
    case CSSSelector::kPseudoViewTransitionGroup:
    case CSSSelector::kPseudoViewTransitionImagePair:
    case CSSSelector::kPseudoViewTransitionOld:
    case CSSSelector::kPseudoViewTransitionNew: {
      std::unique_ptr<Vector<AtomicString>> name_and_classes =
          std::make_unique<Vector<AtomicString>>();
      if (RuntimeEnabledFeatures::CS
"""


```