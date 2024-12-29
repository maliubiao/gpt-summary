Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/css/css_selector.cc`. This is the second part of a three-part request. The focus should be on the operations related to CSS selectors, particularly pseudo-classes and pseudo-elements.

Here's a breakdown of the code's actions:

1. **Handles Pseudo-Class/Element Matching**: The code checks the `Match()` result to determine if it's a pseudo-class or pseudo-element and performs actions based on the specific type.
2. **Sets Pseudo-Type**:  It sets the `PseudoTypeField` within the `bits_` member.
3. **User-Agent Sheet Mode Check**: For certain pseudo-classes/elements, it verifies if the current mode is `kUASheetMode` (User-Agent stylesheet mode).
4. **`fallthrough`**: It uses `fallthrough` for shared logic between some pseudo-classes.
5. **`SetUnparsedPlaceholder`**:  This function is used to store unparsed pseudo-class information.
6. **`GetNestingType`**: Determines the nesting type of the selector (e.g., `:parent`, `:scope`).
7. **`SetWhere`**: Sets the selector type to `:where()` and associates a selector list.
8. **`SerializeIdentifierOrAny` and `SerializeNamespacePrefixIfNeeded`**: These are helper functions for serializing CSS selector components into strings.
9. **`SerializeSelectorList`**:  Serializes a list of CSS selectors.
10. **`SelectorText` and `SelectorTextExpandingPseudoParent`**: These methods return the textual representation of the CSS selector, with an option to expand the `:parent` pseudo-class.
11. **`SerializeSimpleSelector`**:  Serializes a single, simple CSS selector component.
12. **`SerializeCompound`**:  Serializes a compound CSS selector.
13. **`SelectorTextInternal`**: The core function for generating the textual representation of the selector, handling different relations (descendant, child, etc.).
14. **`SimpleSelectorTextForDebug`**:  Provides a debug-friendly string representation of a simple selector.
15. **Setters for various properties**:  Functions like `SetArgument`, `SetSelectorList`, `SetContainsPseudoInsideHasPseudoClass`, etc., to modify the selector's properties.
16. **`ValidateSubSelector`**: Checks if a given selector is valid as a sub-selector.
17. **`IsCompound`**: Determines if the selector is a compound selector.
18. **`HasLinkOrVisited`**: Checks if the selector includes `:link` or `:visited` pseudo-classes.
19. **`SetNth`**: Sets the `a` and `b` values for `:nth-*` pseudo-classes.
20. **`MatchNth`**: Determines if an element matches the `:nth-*` criteria.
21. **`MatchesPseudoElement`**: Checks if the selector includes a pseudo-element.
22. **`IsAllowedInParentPseudo`**: Checks if the selector is allowed within a `:parent` pseudo-class.
23. **`IsTreeAbidingPseudoElement`**: Checks if the pseudo-element is "tree-abiding" (generates a box in the render tree).
24. **`IsElementBackedPseudoElement`**: Checks if the pseudo-element is backed by a real element.
25. **`IsAllowedAfterPart`**: Determines if the selector is allowed after a `::part()` pseudo-element.
26. **`IsOrContainsHostPseudoClass`**: Checks if the selector includes `:host` or `:host-context()`.
27. **`ForAnyInComplexSelector`**:  Applies a function to every selector within a complex selector.
28. **`FollowsPart` and `FollowsSlotted`**: Checks if the selector immediately follows `::part()` or `::slotted()`.
29. **`CrossesTreeScopes`**:  Checks if the selector crosses shadow DOM boundaries.
30. **`FormatPseudoTypeForDebugging`**:  Provides a string representation of a pseudo-type for debugging.
31. **`RareData`**:  A nested class to hold less frequently used selector data.
32. **`MatchNth` (in RareData)**:  The actual implementation of the `:nth-*` matching logic.
33. **`SetIdentList`**: Sets a list of identifiers associated with the selector.

**Summary for Part 2**: This part of the `CSSSelector` code focuses on **processing and representing specific types of CSS selectors, namely pseudo-classes and pseudo-elements**. It includes logic for:

* **Identifying and classifying** various pseudo-classes and pseudo-elements.
* **Storing and managing** data specific to these selectors (e.g., arguments for `:nth-child`, selector lists for `:is()`).
* **Serializing** these selectors into their textual CSS representation.
* **Validating** the usage and combinations of these selectors.
* **Determining specific properties** related to their behavior (e.g., whether they cross shadow DOM boundaries, if they are allowed in certain contexts).
这是 blink 引擎中 `CSSSelector` 类的源代码片段，主要负责处理 **CSS 伪类 (pseudo-classes) 和 伪元素 (pseudo-elements)** 的相关逻辑。

**功能归纳:**

这部分代码的核心功能是：

1. **识别和区分各种伪类和伪元素:** 代码通过 `switch` 语句处理了大量的 `case`，每个 `case` 对应一个特定的伪类或伪元素枚举值 (例如 `kPseudoSelectArrow`, `kPseudoChecked`, `kPseudoBackdrop`, `kPseudoActive`, `kPseudoHover` 等)。
2. **验证伪类和伪元素的使用场景:**  代码会根据当前解析模式 (`mode`) 和匹配结果 (`Match()`) 来验证某些伪类或伪元素是否在允许的上下文中使用。例如，`kPseudoBlinkInternalElement` 仅在用户代理样式表模式 (`kUASheetMode`) 下有效。
3. **设置伪类和伪元素的状态:**  如果验证失败，代码会设置 `bits_.set<PseudoTypeField>(kPseudoUnknown)`，表明这是一个未知的或无效的伪类/伪元素。
4. **处理 `:unparsed` 伪类:**  `SetUnparsedPlaceholder` 函数用于存储未解析的伪类的相关信息。
5. **获取嵌套类型:** `GetNestingType` 函数用于判断选择器是否表示嵌套关系（如 `:parent`）或作用域（如 `:scope`）。
6. **设置 `:where` 伪类:** `SetWhere` 函数将选择器类型设置为 `:where`，并关联一个选择器列表。
7. **序列化伪类和伪元素到文本:** 代码包含将伪类和伪元素转换回 CSS 文本表示的逻辑，例如在 `SerializeSimpleSelector` 函数中，会根据 `GetPseudoType()` 的值添加 `:` 或 `::` 前缀，并处理带参数的伪类（如 `:nth-child(n)`）。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:** 这部分代码直接处理 CSS 语法中的伪类和伪元素。
    * **例子:** 代码中列举的 `kPseudoHover`, `kPseudoActive`, `kPseudoNthChild` 等都直接对应 CSS 中的 `:hover`, `:active`, `:nth-child()` 等伪类。
    * **例子:** `kPseudoBefore`, `kPseudoAfter` 对应 CSS 中的 `::before`, `::after` 伪元素。
* **HTML:** 伪类和伪元素应用于 HTML 元素。
    * **例子:**  `:checked` 伪类用于匹配被选中的 HTML 表单元素（如 `<input type="checkbox">`）。
    * **例子:** `::placeholder` 伪元素用于设置 HTML 表单元素的占位符文本样式（如 `<input placeholder="请输入内容">`）。
* **JavaScript:**  JavaScript 可以通过 DOM API 获取和操作元素的样式，间接地与这里处理的伪类和伪元素相关。
    * **例子:** JavaScript 可以通过 `element.classList.add('active')` 添加一个类，然后 CSS 规则中定义了 `.active:hover` 的样式，那么当鼠标悬停在添加了 `active` 类的元素上时，相关的样式会被应用。虽然 JavaScript 没有直接操作伪类，但它可以通过改变元素的状态或属性来触发伪类的匹配。

**逻辑推理、假设输入与输出:**

假设输入一个 CSS 选择器片段，例如 `:hover`:

* **输入:**  当解析器遇到 `:hover` 时，会创建一个 `CSSSelector` 对象。
* **逻辑推理:** 代码会进入 `switch (GetPseudoType())` 语句，匹配到 `case kPseudoHover:`。由于 `Match()` 返回的是 `kPseudoClass` (因为 `:hover` 是伪类)，并且没有额外的条件，所以不会设置 `kPseudoUnknown`。
* **输出:**  该 `CSSSelector` 对象会被标记为匹配伪类 `kPseudoHover`。在序列化时，会输出 `:hover` 字符串。

假设输入一个带有非法模式的伪元素，例如在非用户代理样式表中使用了内部伪元素 `::-blink-internal-element`:

* **输入:** 解析器遇到 `::-blink-internal-element`。
* **逻辑推理:** 代码会进入 `case kPseudoBlinkInternalElement:`。如果当前的 `mode` 不是 `kUASheetMode`，条件 `mode != kUASheetMode` 为真。
* **输出:** `bits_.set<PseudoTypeField>(kPseudoUnknown)` 会被调用，将该伪元素标记为未知或无效。

**用户或编程常见的使用错误:**

* **使用了不兼容的伪类/伪元素:**  例如，在旧版本的浏览器中使用了新的伪元素，或者在不允许的上下文中使用了某些伪类（代码中的 `mode != kUASheetMode` 的检查就是为了防止这类错误）。
* **拼写错误:** 伪类的名称拼写错误会导致无法匹配，例如写成 `:hoover` 而不是 `:hover`。这会被解析器识别为未知伪类。
* **参数错误:** 对于带参数的伪类，例如 `:nth-child(abc)`，参数不是有效的数字或表达式，会导致解析错误。虽然这段代码没有直接处理参数解析，但后续的处理会检测参数的有效性。
* **伪元素使用单冒号:**  混淆了伪类和伪元素的语法，将伪元素写成单冒号形式，例如 `:before` 而不是 `::before`。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入网址或点击链接:**  浏览器开始加载网页。
2. **浏览器下载 HTML、CSS 和 JavaScript 资源:**  CSS 文件会被解析。
3. **CSS 解析器开始解析 CSS 规则:** 当解析器遇到包含伪类或伪元素的 CSS 规则时，例如 `div:hover { ... }` 或 `p::first-line { ... }`。
4. **创建 `CSSSelector` 对象:**  解析器会为每个选择器创建一个 `CSSSelector` 对象。
5. **设置伪类或伪元素的类型:**  相关的代码会被调用，根据解析到的伪类或伪元素的名称设置 `PseudoTypeField`。例如，对于 `:hover`，会执行到 `case kPseudoHover:`。
6. **进行验证:**  代码可能会进行上下文验证，例如检查 `kPseudoBlinkInternalElement` 是否在用户代理样式表中。
7. **存储选择器信息:**  `CSSSelector` 对象存储了选择器的各种信息，包括伪类/伪元素的类型。

作为调试线索，如果发现页面样式没有按预期生效，并且怀疑是伪类或伪元素的问题，可以：

* **查看开发者工具的 "Elements" 面板:**  检查元素的样式是否应用了预期的伪类样式。
* **查看 "Computed" 面板:**  查看最终计算出的样式，确认伪类是否被成功匹配。
* **使用 "Sources" 面板查看 CSS 源代码:**  确认 CSS 规则的语法是否正确，伪类的名称是否拼写正确。
* **在 blink 引擎的调试版本中设置断点:**  在 `css_selector.cc` 文件的相关代码处设置断点，例如在 `switch (GetPseudoType())` 语句中，观察代码的执行流程，查看 `Match()` 的返回值和 `mode` 的值，从而判断伪类/伪元素是否被正确识别和验证。

总而言之，这部分代码是 Blink 引擎中处理 CSS 选择器中伪类和伪元素的核心部分，负责识别、验证和表示这些特殊的选择器类型。

Prompt: 
```
这是目录为blink/renderer/core/css/css_selector.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
    case kPseudoSelectArrow:
    case kPseudoCheck:
    case kPseudoBackdrop:
    case kPseudoCue:
    case kPseudoMarker:
    case kPseudoPart:
    case kPseudoPlaceholder:
    case kPseudoFileSelectorButton:
    case kPseudoResizer:
    case kPseudoScrollbar:
    case kPseudoScrollbarCorner:
    case kPseudoScrollbarButton:
    case kPseudoScrollbarThumb:
    case kPseudoScrollbarTrack:
    case kPseudoScrollbarTrackPiece:
    case kPseudoScrollMarker:
    case kPseudoScrollMarkerGroup:
    case kPseudoScrollNextButton:
    case kPseudoScrollPrevButton:
    case kPseudoColumn:
    case kPseudoPicker:
    case kPseudoSelection:
    case kPseudoWebKitCustomElement:
    case kPseudoSlotted:
    case kPseudoSearchText:
    case kPseudoTargetText:
    case kPseudoHighlight:
    case kPseudoSpellingError:
    case kPseudoGrammarError:
    case kPseudoViewTransition:
    case kPseudoViewTransitionGroup:
    case kPseudoViewTransitionImagePair:
    case kPseudoViewTransitionOld:
    case kPseudoViewTransitionNew:
    case kPseudoDetailsContent:
      if (Match() != kPseudoElement) {
        bits_.set<PseudoTypeField>(kPseudoUnknown);
      }
      break;
    case kPseudoBlinkInternalElement:
      if (Match() != kPseudoElement || mode != kUASheetMode) {
        bits_.set<PseudoTypeField>(kPseudoUnknown);
      }
      break;
    case kPseudoHasDatalist:
    case kPseudoHostHasNonAutoAppearance:
    case kPseudoIsHtml:
    case kPseudoListBox:
    case kPseudoMultiSelectFocus:
    case kPseudoSpatialNavigationFocus:
    case kPseudoVideoPersistent:
    case kPseudoVideoPersistentAncestor:
      if (mode != kUASheetMode) {
        bits_.set<PseudoTypeField>(kPseudoUnknown);
        break;
      }
      [[fallthrough]];
    // For pseudo classes
    case kPseudoActive:
    case kPseudoActiveViewTransition:
    case kPseudoActiveViewTransitionType:
    case kPseudoAny:
    case kPseudoAnyLink:
    case kPseudoAutofill:
    case kPseudoAutofillPreviewed:
    case kPseudoAutofillSelected:
    case kPseudoChecked:
    case kPseudoClosed:
    case kPseudoCornerPresent:
    case kPseudoCurrent:
    case kPseudoDecrement:
    case kPseudoDefault:
    case kPseudoDefined:
    case kPseudoDialogInTopLayer:
    case kPseudoDir:
    case kPseudoDisabled:
    case kPseudoDoubleButton:
    case kPseudoDrag:
    case kPseudoEmpty:
    case kPseudoEnabled:
    case kPseudoEnd:
    case kPseudoFirstChild:
    case kPseudoFirstOfType:
    case kPseudoFocus:
    case kPseudoFocusVisible:
    case kPseudoFocusWithin:
    case kPseudoFullPageMedia:
    case kPseudoFullScreen:
    case kPseudoFullScreenAncestor:
    case kPseudoFullscreen:
    case kPseudoFutureCue:
    case kPseudoHas:
    case kPseudoHasSlotted:
    case kPseudoHorizontal:
    case kPseudoHost:
    case kPseudoHostContext:
    case kPseudoHover:
    case kPseudoInRange:
    case kPseudoIncrement:
    case kPseudoIndeterminate:
    case kPseudoInvalid:
    case kPseudoIs:
    case kPseudoLang:
    case kPseudoLastChild:
    case kPseudoLastOfType:
    case kPseudoLink:
    case kPseudoModal:
    case kPseudoNoButton:
    case kPseudoNot:
    case kPseudoNthChild:
    case kPseudoNthLastChild:
    case kPseudoNthLastOfType:
    case kPseudoNthOfType:
    case kPseudoOnlyChild:
    case kPseudoOnlyOfType:
    case kPseudoOpen:
    case kPseudoOptional:
    case kPseudoOutOfRange:
    case kPseudoParent:
    case kPseudoPastCue:
    case kPseudoPaused:
    case kPseudoPermissionElementInvalidStyle:
    case kPseudoPermissionElementOccluded:
    case kPseudoPermissionGranted:
    case kPseudoPictureInPicture:
    case kPseudoPlaceholderShown:
    case kPseudoPlaying:
    case kPseudoPopoverInTopLayer:
    case kPseudoPopoverOpen:
    case kPseudoReadOnly:
    case kPseudoReadWrite:
    case kPseudoRelativeAnchor:
    case kPseudoRequired:
    case kPseudoRoot:
    case kPseudoScope:
    case kPseudoSelectorFragmentAnchor:
    case kPseudoSingleButton:
    case kPseudoStart:
    case kPseudoState:
    case kPseudoStateDeprecatedSyntax:
    case kPseudoTarget:
    case kPseudoUnknown:
    case kPseudoUnparsed:
    case kPseudoUserInvalid:
    case kPseudoUserValid:
    case kPseudoValid:
    case kPseudoVertical:
    case kPseudoVisited:
    case kPseudoWebKitAutofill:
    case kPseudoWebkitAnyLink:
    case kPseudoWhere:
    case kPseudoWindowInactive:
    case kPseudoXrOverlay:
      if (Match() != kPseudoClass) {
        bits_.set<PseudoTypeField>(kPseudoUnknown);
      }
      break;
    case kPseudoFirstPage:
    case kPseudoLeftPage:
    case kPseudoRightPage:
      bits_.set<PseudoTypeField>(kPseudoUnknown);
      break;
  }
}

void CSSSelector::SetUnparsedPlaceholder(CSSNestingType unparsed_nesting_type,
                                         const AtomicString& value) {
  DCHECK(Match() == kPseudoClass);
  SetPseudoType(kPseudoUnparsed);
  CreateRareData();
  SetValue(value);
  data_.rare_data_->bits_.unparsed_nesting_type_ = unparsed_nesting_type;
}

CSSNestingType CSSSelector::GetNestingType() const {
  switch (GetPseudoType()) {
    case CSSSelector::kPseudoParent:
      return CSSNestingType::kNesting;
    case CSSSelector::kPseudoUnparsed:
      return data_.rare_data_->bits_.unparsed_nesting_type_;
    case CSSSelector::kPseudoScope:
      // TODO(crbug.com/1280240): Handle unparsed :scope.
      return CSSNestingType::kScope;
    default:
      return CSSNestingType::kNone;
  }
}

void CSSSelector::SetWhere(CSSSelectorList* selector_list) {
  SetMatch(kPseudoClass);
  SetPseudoType(kPseudoWhere);
  SetSelectorList(selector_list);
}

static void SerializeIdentifierOrAny(const AtomicString& identifier,
                                     const AtomicString& any,
                                     StringBuilder& builder) {
  if (identifier != any) {
    SerializeIdentifier(identifier, builder);
  } else {
    builder.Append(g_star_atom);
  }
}

static void SerializeNamespacePrefixIfNeeded(const AtomicString& prefix,
                                             const AtomicString& any,
                                             StringBuilder& builder,
                                             bool is_attribute_selector) {
  if (prefix.IsNull() || (prefix.empty() && is_attribute_selector)) {
    return;
  }
  SerializeIdentifierOrAny(prefix, any, builder);
  builder.Append('|');
}

// static
template <bool expand_pseudo_parent>
void CSSSelector::SerializeSelectorList(const CSSSelectorList* selector_list,
                                        StringBuilder& builder) {
  const CSSSelector* first_sub_selector = selector_list->First();
  for (const CSSSelector* sub_selector = first_sub_selector; sub_selector;
       sub_selector = CSSSelectorList::Next(*sub_selector)) {
    if (sub_selector != first_sub_selector) {
      builder.Append(", ");
    }
    builder.Append(sub_selector->SelectorTextInternal<expand_pseudo_parent>());
  }
}

String CSSSelector::SelectorText() const {
  return SelectorTextInternal<!kExpandPseudoParent>();
}

String CSSSelector::SelectorTextExpandingPseudoParent() const {
  return SelectorTextInternal<kExpandPseudoParent>();
}

template <bool expand_pseudo_parent>
bool CSSSelector::SerializeSimpleSelector(StringBuilder& builder) const {
  bool suppress_selector_list = false;
  if (Match() == kId) {
    builder.Append('#');
    SerializeIdentifier(SerializingValue(), builder);
  } else if (Match() == kClass) {
    builder.Append('.');
    SerializeIdentifier(SerializingValue(), builder);
  } else if (Match() == kPseudoClass || Match() == kPagePseudoClass) {
    if (GetPseudoType() == kPseudoUnparsed) {
      builder.Append(Value());
    } else if (GetPseudoType() != kPseudoStateDeprecatedSyntax &&
               GetPseudoType() != kPseudoParent) {
      builder.Append(':');
      builder.Append(SerializingValue());
    }

    switch (GetPseudoType()) {
      case kPseudoNthChild:
      case kPseudoNthLastChild:
      case kPseudoNthOfType:
      case kPseudoNthLastOfType: {
        builder.Append('(');

        // https://drafts.csswg.org/css-syntax/#serializing-anb
        int a = data_.rare_data_->NthAValue();
        int b = data_.rare_data_->NthBValue();
        if (a == 0) {
          builder.Append(String::Number(b));
        } else {
          if (a == 1) {
            builder.Append('n');
          } else if (a == -1) {
            builder.Append("-n");
          } else {
            builder.AppendFormat("%dn", a);
          }

          if (b < 0) {
            builder.Append(String::Number(b));
          } else if (b > 0) {
            builder.AppendFormat("+%d", b);
          }
        }

        // Only relevant for :nth-child, not :nth-of-type.
        if (data_.rare_data_->selector_list_ != nullptr) {
          builder.Append(" of ");
          SerializeSelectorList<expand_pseudo_parent>(
              data_.rare_data_->selector_list_, builder);
          suppress_selector_list = true;
        }

        builder.Append(')');
        break;
      }
      case kPseudoDir:
      case kPseudoLang:
      case kPseudoState:
        builder.Append('(');
        SerializeIdentifier(Argument(), builder);
        builder.Append(')');
        break;
      case kPseudoHas:
      case kPseudoNot:
        DCHECK(SelectorList());
        break;
      case kPseudoStateDeprecatedSyntax:
        builder.Append(':');
        SerializeIdentifier(SerializingValue(), builder);
        break;
      case kPseudoHost:
      case kPseudoHostContext:
      case kPseudoAny:
      case kPseudoIs:
      case kPseudoWhere:
        break;
      case kPseudoParent:
        if constexpr (expand_pseudo_parent) {
          // Replace parent pseudo with equivalent :is() pseudo.
          builder.Append(":is");
          if (auto* parent = SelectorListOrParent()) {
            builder.Append('(');
            builder.Append(parent->SelectorTextExpandingPseudoParent());
            builder.Append(')');
          }
        } else {
          builder.Append('&');
        }
        break;
      case kPseudoRelativeAnchor:
        NOTREACHED();
      case kPseudoActiveViewTransitionType: {
        CHECK(!IdentList().empty());
        String separator = "(";
        for (AtomicString type : IdentList()) {
          builder.Append(separator);
          if (separator == "(") {
            separator = ", ";
          }
          SerializeIdentifier(type, builder);
        }
        builder.Append(')');
        break;
      }
      default:
        break;
    }
  } else if (Match() == kPseudoElement) {
    builder.Append("::");
    SerializeIdentifier(SerializingValue(), builder);
    switch (GetPseudoType()) {
      case kPseudoPart: {
        char separator = '(';
        for (AtomicString part : IdentList()) {
          builder.Append(separator);
          if (separator == '(') {
            separator = ' ';
          }
          SerializeIdentifier(part, builder);
        }
        builder.Append(')');
        break;
      }
      case kPseudoHighlight: {
        builder.Append('(');
        builder.Append(Argument());
        builder.Append(')');
        break;
      }
      case kPseudoViewTransitionGroup:
      case kPseudoViewTransitionImagePair:
      case kPseudoViewTransitionNew:
      case kPseudoViewTransitionOld: {
        builder.Append('(');
        bool first = true;
        for (const AtomicString& name_or_class : IdentList()) {
          if (!first) {
            builder.Append('.');
          }

          first = false;
          if (name_or_class == UniversalSelectorAtom()) {
            builder.Append(g_star_atom);
          } else {
            SerializeIdentifier(name_or_class, builder);
          }
        }
        builder.Append(')');
        break;
      }
      default:
        break;
    }
  } else if (IsAttributeSelector()) {
    builder.Append('[');
    SerializeNamespacePrefixIfNeeded(Attribute().Prefix(), g_star_atom, builder,
                                     IsAttributeSelector());
    SerializeIdentifier(Attribute().LocalName(), builder);
    switch (Match()) {
      case kAttributeExact:
        builder.Append('=');
        break;
      case kAttributeSet:
        // set has no operator or value, just the attrName
        builder.Append(']');
        break;
      case kAttributeList:
        builder.Append("~=");
        break;
      case kAttributeHyphen:
        builder.Append("|=");
        break;
      case kAttributeBegin:
        builder.Append("^=");
        break;
      case kAttributeEnd:
        builder.Append("$=");
        break;
      case kAttributeContain:
        builder.Append("*=");
        break;
      default:
        break;
    }
    if (Match() != kAttributeSet) {
      SerializeString(SerializingValue(), builder);
      if (AttributeMatch() == AttributeMatchType::kCaseInsensitive) {
        builder.Append(" i");
      } else if (AttributeMatch() == AttributeMatchType::kCaseSensitiveAlways) {
        DCHECK(RuntimeEnabledFeatures::CSSCaseSensitiveSelectorEnabled());
        builder.Append(" s");
      }
      builder.Append(']');
    }
  }

  if (SelectorList() && !suppress_selector_list) {
    builder.Append('(');
    SerializeSelectorList<expand_pseudo_parent>(SelectorList(), builder);
    builder.Append(')');
  }
  return true;
}

template <bool expand_pseudo_parent>
const CSSSelector* CSSSelector::SerializeCompound(
    StringBuilder& builder) const {
  if (Match() == kTag && !IsImplicit()) {
    SerializeNamespacePrefixIfNeeded(TagQName().Prefix(), g_star_atom, builder,
                                     IsAttributeSelector());
    SerializeIdentifierOrAny(TagQName().LocalName(), UniversalSelectorAtom(),
                             builder);
  }

  for (const CSSSelector* simple_selector = this; simple_selector;
       simple_selector = simple_selector->NextSimpleSelector()) {
    if (!simple_selector->SerializeSimpleSelector<expand_pseudo_parent>(
            builder)) {
      return nullptr;
    }
    if (simple_selector->Relation() != kSubSelector) {
      return simple_selector;
    }
  }
  return nullptr;
}

template <bool expand_pseudo_parent>
String CSSSelector::SelectorTextInternal() const {
  String result;
  for (const CSSSelector* compound = this; compound;
       compound = compound->NextSimpleSelector()) {
    StringBuilder builder;
    compound = compound->SerializeCompound<expand_pseudo_parent>(builder);
    if (!compound) {
      return builder.ReleaseString() + result;
    }

    RelationType relation = compound->Relation();
    DCHECK_NE(relation, kSubSelector);

    const CSSSelector* next_compound = compound->NextSimpleSelector();
    DCHECK(next_compound);

    // If we are combining with an implicit :scope, it is as if we
    // used a relative combinator.
    if (!next_compound || (next_compound->Match() == kPseudoClass &&
                           next_compound->GetPseudoType() == kPseudoScope &&
                           next_compound->IsImplicit())) {
      relation = ConvertRelationToRelative(relation);
    }

    switch (relation) {
      case kDescendant:
        result = " " + builder.ReleaseString() + result;
        break;
      case kChild:
        result = " > " + builder.ReleaseString() + result;
        break;
      case kDirectAdjacent:
        result = " + " + builder.ReleaseString() + result;
        break;
      case kIndirectAdjacent:
        result = " ~ " + builder.ReleaseString() + result;
        break;
      case kSubSelector:
      case kShadowPart:
      case kUAShadow:
      case kShadowSlot:
        result = builder.ReleaseString() + result;
        break;
      case kRelativeDescendant:
        return builder.ReleaseString() + result;
      case kRelativeChild:
        return "> " + builder.ReleaseString() + result;
      case kRelativeDirectAdjacent:
        return "+ " + builder.ReleaseString() + result;
      case kRelativeIndirectAdjacent:
        return "~ " + builder.ReleaseString() + result;
    }
  }
  NOTREACHED();
}

String CSSSelector::SimpleSelectorTextForDebug() const {
  StringBuilder builder;
  if (Match() == kTag && !IsImplicit()) {
    SerializeNamespacePrefixIfNeeded(TagQName().Prefix(), g_star_atom, builder,
                                     IsAttributeSelector());
    SerializeIdentifierOrAny(TagQName().LocalName(), UniversalSelectorAtom(),
                             builder);
  } else {
    SerializeSimpleSelector<!kExpandPseudoParent>(builder);
  }
  return builder.ToString();
}

void CSSSelector::SetArgument(const AtomicString& value) {
  CreateRareData();
  data_.rare_data_->argument_ = value;
}

void CSSSelector::SetSelectorList(CSSSelectorList* selector_list) {
  CreateRareData();
  data_.rare_data_->selector_list_ = selector_list;
}

void CSSSelector::SetContainsPseudoInsideHasPseudoClass() {
  CreateRareData();
  data_.rare_data_->bits_.has_.contains_pseudo_ = true;
}

void CSSSelector::SetContainsComplexLogicalCombinationsInsideHasPseudoClass() {
  CreateRareData();
  data_.rare_data_->bits_.has_.contains_complex_logical_combinations_ = true;
}

void CSSSelector::SetHasArgumentMatchInShadowTree() {
  CreateRareData();
  data_.rare_data_->bits_.has_.argument_match_in_shadow_tree_ = true;
}

static bool ValidateSubSelector(const CSSSelector* selector) {
  switch (selector->Match()) {
    case CSSSelector::kTag:
    case CSSSelector::kId:
    case CSSSelector::kClass:
    case CSSSelector::kAttributeExact:
    case CSSSelector::kAttributeSet:
    case CSSSelector::kAttributeList:
    case CSSSelector::kAttributeHyphen:
    case CSSSelector::kAttributeContain:
    case CSSSelector::kAttributeBegin:
    case CSSSelector::kAttributeEnd:
      return true;
    case CSSSelector::kPseudoElement:
    case CSSSelector::kUnknown:
      return false;
    case CSSSelector::kPagePseudoClass:
    case CSSSelector::kPseudoClass:
      break;
    case CSSSelector::kInvalidList:
      NOTREACHED();
  }

  switch (selector->GetPseudoType()) {
    case CSSSelector::kPseudoEmpty:
    case CSSSelector::kPseudoLink:
    case CSSSelector::kPseudoVisited:
    case CSSSelector::kPseudoTarget:
    case CSSSelector::kPseudoEnabled:
    case CSSSelector::kPseudoDisabled:
    case CSSSelector::kPseudoChecked:
    case CSSSelector::kPseudoIndeterminate:
    case CSSSelector::kPseudoNthChild:
    case CSSSelector::kPseudoNthLastChild:
    case CSSSelector::kPseudoNthOfType:
    case CSSSelector::kPseudoNthLastOfType:
    case CSSSelector::kPseudoFirstChild:
    case CSSSelector::kPseudoLastChild:
    case CSSSelector::kPseudoFirstOfType:
    case CSSSelector::kPseudoLastOfType:
    case CSSSelector::kPseudoOnlyOfType:
    case CSSSelector::kPseudoHost:
    case CSSSelector::kPseudoHostContext:
    case CSSSelector::kPseudoNot:
    case CSSSelector::kPseudoSpatialNavigationFocus:
    case CSSSelector::kPseudoHasDatalist:
    case CSSSelector::kPseudoIsHtml:
    case CSSSelector::kPseudoListBox:
    case CSSSelector::kPseudoHostHasNonAutoAppearance:
      // TODO(https://crbug.com/1346456): Many pseudos should probably be
      // added to this list.  The default: case below should also be removed
      // so that those adding new pseudos know they need to choose one path or
      // the other here.
      //
      // However, it's not clear why a pseudo should be in one list or the
      // other.  It's also entirely possible that this entire switch() should
      // be removed and all cases should return true.
      return true;
    default:
      return false;
  }
}

bool CSSSelector::IsCompound() const {
  if (!ValidateSubSelector(this)) {
    return false;
  }

  const CSSSelector* prev_sub_selector = this;
  const CSSSelector* sub_selector = NextSimpleSelector();

  while (sub_selector) {
    if (prev_sub_selector->Relation() != kSubSelector) {
      return false;
    }
    if (!ValidateSubSelector(sub_selector)) {
      return false;
    }

    prev_sub_selector = sub_selector;
    sub_selector = sub_selector->NextSimpleSelector();
  }

  return true;
}

bool CSSSelector::HasLinkOrVisited() const {
  for (const CSSSelector* current = this; current;
       current = current->NextSimpleSelector()) {
    CSSSelector::PseudoType pseudo = current->GetPseudoType();
    if (pseudo == CSSSelector::kPseudoLink ||
        pseudo == CSSSelector::kPseudoVisited) {
      return true;
    }
    if (const CSSSelectorList* list = current->SelectorList()) {
      for (const CSSSelector* sub_selector = list->First(); sub_selector;
           sub_selector = CSSSelectorList::Next(*sub_selector)) {
        if (sub_selector->HasLinkOrVisited()) {
          return true;
        }
      }
    }
  }
  return false;
}

void CSSSelector::SetNth(int a, int b, CSSSelectorList* sub_selectors) {
  CreateRareData();
  data_.rare_data_->bits_.nth_.a_ = a;
  data_.rare_data_->bits_.nth_.b_ = b;
  data_.rare_data_->selector_list_ = sub_selectors;
}

bool CSSSelector::MatchNth(unsigned count) const {
  DCHECK(HasRareData());
  return data_.rare_data_->MatchNth(count);
}

bool CSSSelector::MatchesPseudoElement() const {
  for (const CSSSelector* current = this; current;
       current = current->NextSimpleSelector()) {
    if (current->Match() == kPseudoElement) {
      return true;
    }
    if (current->Relation() != kSubSelector) {
      return false;
    }
  }
  return false;
}

bool CSSSelector::IsAllowedInParentPseudo() const {
  // Pseudo-elements are not allowed (parse-time) within :is(), but using
  // nesting you can still get effectively that same situation using
  // e.g. "div, ::before { & {} }". Since '::before' is "contextually invalid",
  // it should not contribute to specificity.
  //
  // https://github.com/w3c/csswg-drafts/issues/9600
  return !MatchesPseudoElement();
}

bool CSSSelector::IsTreeAbidingPseudoElement() const {
  return Match() == CSSSelector::kPseudoElement &&
         (GetPseudoType() == kPseudoCheck || GetPseudoType() == kPseudoBefore ||
          GetPseudoType() == kPseudoAfter ||
          GetPseudoType() == kPseudoSelectArrow ||
          GetPseudoType() == kPseudoMarker ||
          GetPseudoType() == kPseudoPlaceholder ||
          GetPseudoType() == kPseudoFileSelectorButton ||
          GetPseudoType() == kPseudoBackdrop ||
          GetPseudoType() == kPseudoViewTransition ||
          GetPseudoType() == kPseudoViewTransitionGroup ||
          GetPseudoType() == kPseudoViewTransitionImagePair ||
          GetPseudoType() == kPseudoViewTransitionOld ||
          GetPseudoType() == kPseudoViewTransitionNew ||
          IsElementBackedPseudoElement(GetPseudoType()));
}

/* static */ bool CSSSelector::IsElementBackedPseudoElement(
    CSSSelector::PseudoType pseudo) {
  return pseudo == kPseudoDetailsContent || pseudo == kPseudoPicker;
}

bool CSSSelector::IsElementBackedPseudoElement() const {
  return Match() == CSSSelector::kPseudoElement &&
         IsElementBackedPseudoElement(GetPseudoType());
}

bool CSSSelector::IsAllowedAfterPart() const {
  if (Match() != CSSSelector::kPseudoElement &&
      Match() != CSSSelector::kPseudoClass) {
    return false;
  }
  switch (GetPseudoType()) {
    // Pseudo-elements
    //
    // All pseudo-elements other than ::part() should be allowed after
    // ::part().
    case kPseudoCheck:
    case kPseudoBefore:
    case kPseudoAfter:
    case kPseudoSelectArrow:
    case kPseudoPlaceholder:
    case kPseudoFileSelectorButton:
    case kPseudoFirstLine:
    case kPseudoFirstLetter:
    case kPseudoPicker:
    case kPseudoSelection:
    case kPseudoSearchText:
    case kPseudoTargetText:
    case kPseudoHighlight:
    case kPseudoSpellingError:
    case kPseudoGrammarError:
      return true;

    case kPseudoBackdrop:
    case kPseudoCue:
    case kPseudoMarker:
    case kPseudoResizer:
    case kPseudoScrollbar:
    case kPseudoScrollbarButton:
    case kPseudoScrollbarCorner:
    case kPseudoScrollbarThumb:
    case kPseudoScrollbarTrack:
    case kPseudoScrollbarTrackPiece:
    case kPseudoScrollMarker:
    case kPseudoScrollMarkerGroup:
    case kPseudoScrollNextButton:
    case kPseudoColumn:
    case kPseudoScrollPrevButton:
    case kPseudoWebKitCustomElement:
    case kPseudoBlinkInternalElement:
    case kPseudoDetailsContent:
    case kPseudoViewTransition:
    case kPseudoViewTransitionGroup:
    case kPseudoViewTransitionImagePair:
    case kPseudoViewTransitionNew:
    case kPseudoViewTransitionOld:
      return RuntimeEnabledFeatures::CSSPartAllowsMoreSelectorsAfterEnabled();

    // It's possible that we should support ::slotted() after ::part().
    // (WebKit accepts it at parse time but it doesn't appear to work;
    // Gecko doesn't accept it.)  However, making it work isn't trivial.
    // https://github.com/w3c/csswg-drafts/issues/10807
    case kPseudoSlotted:
      return false;

    case kPseudoPart:
      return false;

    // Pseudo-classes
    //
    // TODO(https://crbug.com/40623497): Eventually all non-structural
    // pseudo-classes should be allowed, and structural pseudo-classes should
    // be forbidden.
    case kPseudoAutofill:
    case kPseudoAutofillPreviewed:
    case kPseudoAutofillSelected:
    case kPseudoWebKitAutofill:
      return true;

    case kPseudoActive:
    case kPseudoActiveViewTransition:
    case kPseudoActiveViewTransitionType:
    case kPseudoAnyLink:
    case kPseudoChecked:
    case kPseudoDefault:
    case kPseudoDialogInTopLayer:
    case kPseudoDisabled:
    case kPseudoDrag:
    case kPseudoEnabled:
    case kPseudoFocus:
    case kPseudoFocusVisible:
    case kPseudoFocusWithin:
    case kPseudoFullPageMedia:
    case kPseudoHasSlotted:
    case kPseudoHover:
    case kPseudoIndeterminate:
    case kPseudoInvalid:
    case kPseudoLang:
    case kPseudoLink:
    case kPseudoModal:
    case kPseudoOptional:
    case kPseudoPermissionElementInvalidStyle:
    case kPseudoPermissionElementOccluded:
    case kPseudoPermissionGranted:
    case kPseudoPlaceholderShown:
    case kPseudoReadOnly:
    case kPseudoReadWrite:
    case kPseudoRequired:
    case kPseudoSelectorFragmentAnchor:
    case kPseudoState:
    case kPseudoStateDeprecatedSyntax:
    case kPseudoTarget:
    case kPseudoUserInvalid:
    case kPseudoUserValid:
    case kPseudoValid:
    case kPseudoVisited:
    case kPseudoWebkitAnyLink:
    case kPseudoWindowInactive:
    case kPseudoFullScreen:
    case kPseudoFullScreenAncestor:
    case kPseudoFullscreen:
    case kPseudoInRange:
    case kPseudoOutOfRange:
    case kPseudoPaused:
    case kPseudoPictureInPicture:
    case kPseudoPlaying:
    case kPseudoXrOverlay:
    case kPseudoClosed:
    case kPseudoDefined:
    case kPseudoDir:
    case kPseudoFutureCue:
    case kPseudoIsHtml:
    case kPseudoListBox:
    case kPseudoMultiSelectFocus:
    case kPseudoOpen:
    case kPseudoPastCue:
    case kPseudoPopoverInTopLayer:
    case kPseudoPopoverOpen:
    case kPseudoRelativeAnchor:
    case kPseudoSpatialNavigationFocus:
    case kPseudoVideoPersistent:
    case kPseudoVideoPersistentAncestor:
      return RuntimeEnabledFeatures::CSSPartAllowsMoreSelectorsAfterEnabled();

    // IsSimpleSelectorValidAfterPseudoElement allows these selectors after
    // ::part() regardless of what we do here.  However, since they are in
    // fact allowed, tell the truth here.
    case kPseudoIs:
    case kPseudoNot:
    case kPseudoWhere:
      return RuntimeEnabledFeatures::CSSPartAllowsMoreSelectorsAfterEnabled();

    // :-webkit-any() should in theory be allowed too like :is() and :where(),
    // but it's a legacy feature so just leave it disallowed.
    case kPseudoAny:
      return false;

    // TODO(https://crbug.com/40623497): Figure out what to do with this.
    case kPseudoParent:
      return false;

    // These are supported only after ::webkit-scrollbar, which *maybe* makes
    // them structural?  Leave them unsupported for now
    case kPseudoHorizontal:
    case kPseudoVertical:
    case kPseudoDecrement:
    case kPseudoIncrement:
    case kPseudoStart:
    case kPseudoEnd:
    case kPseudoDoubleButton:
    case kPseudoSingleButton:
    case kPseudoNoButton:
    case kPseudoCornerPresent:
    // Likewise, this matches only after ::search-text.
    case kPseudoCurrent:
      return false;

    // These are supported only on @page, so not allowed after ::part().
    case kPseudoFirstPage:
    case kPseudoLeftPage:
    case kPseudoRightPage:
      return false;

    // These are structural pseudo-classes, which should not be allowed.
    case kPseudoEmpty:
    case kPseudoFirstChild:
    case kPseudoFirstOfType:
    case kPseudoLastChild:
    case kPseudoLastOfType:
    case kPseudoNthChild:
    case kPseudoNthLastChild:
    case kPseudoNthLastOfType:
    case kPseudoNthOfType:
    case kPseudoOnlyChild:
    case kPseudoOnlyOfType:
    case kPseudoRoot:
      return false;

    // These are other pseudo-classes that match based on tree information
    // rather than local element information, which should not be allowed.
    case kPseudoHas:
    case kPseudoHasDatalist:
    case kPseudoHost:
    case kPseudoHostContext:
    case kPseudoHostHasNonAutoAppearance:
    case kPseudoScope:
      return false;

    case kPseudoUnparsed:
    case kPseudoUnknown:
      return false;
  }
}

bool CSSSelector::IsOrContainsHostPseudoClass() const {
  if (IsHostPseudoClass()) {
    return true;
  }
  // Accept selector lists like :is(:host, .foo).
  for (const CSSSelector* sub_selector = SelectorListOrParent(); sub_selector;
       sub_selector = CSSSelectorList::Next(*sub_selector)) {
    if (sub_selector->IsOrContainsHostPseudoClass()) {
      return true;
    }
  }
  return false;
}

template <typename Functor>
static bool ForAnyInComplexSelector(const Functor& functor,
                                    const CSSSelector& selector) {
  for (const CSSSelector* current = &selector; current;
       current = current->NextSimpleSelector()) {
    if (functor(*current)) {
      return true;
    }
    if (const CSSSelectorList* selector_list = current->SelectorList()) {
      for (const CSSSelector* sub_selector = selector_list->First();
           sub_selector; sub_selector = CSSSelectorList::Next(*sub_selector)) {
        if (ForAnyInComplexSelector(functor, *sub_selector)) {
          return true;
        }
      }
    }
  }

  return false;
}

bool CSSSelector::FollowsPart() const {
  const CSSSelector* previous = NextSimpleSelector();
  if (!previous) {
    return false;
  }
  return previous->GetPseudoType() == kPseudoPart;
}

bool CSSSelector::FollowsSlotted() const {
  const CSSSelector* previous = NextSimpleSelector();
  if (!previous) {
    return false;
  }
  return previous->GetPseudoType() == kPseudoSlotted;
}

bool CSSSelector::CrossesTreeScopes() const {
  for (const CSSSelector* s = this; s; s = s->NextSimpleSelector()) {
    switch (s->Relation()) {
      case kShadowPart:
      case kUAShadow:
      case kShadowSlot:
        return true;
      default:
        break;
    }
  }
  return false;
}

String CSSSelector::FormatPseudoTypeForDebugging(PseudoType type) {
  for (const auto& s : kPseudoTypeWithoutArgumentsMap) {
    if (s.type == type) {
      return s.string;
    }
  }
  for (const auto& s : kPseudoTypeWithArgumentsMap) {
    if (s.type == type) {
      return s.string;
    }
  }
  StringBuilder builder;
  builder.Append("pseudo-");
  builder.AppendNumber(static_cast<int>(type));
  return builder.ReleaseString();
}

CSSSelector::RareData::RareData(const AtomicString& value)
    : matching_value_(value),
      serializing_value_(value),
      bits_(),
      attribute_(AnyQName()),
      argument_(g_null_atom) {}

CSSSelector::RareData::~RareData() = default;

// a helper function for checking nth-arguments
bool CSSSelector::RareData::MatchNth(unsigned unsigned_count) {
  // These very large values for aN + B or count can't ever match, so
  // give up immediately if we see them.
  int max_value = std::numeric_limits<int>::max() / 2;
  int min_value = std::numeric_limits<int>::min() / 2;
  if (unsigned_count > static_cast<unsigned>(max_value) ||
      NthAValue() > max_value || NthAValue() < min_value ||
      NthBValue() > max_value || NthBValue() < min_value) [[unlikely]] {
    return false;
  }

  int count = static_cast<int>(unsigned_count);
  if (!NthAValue()) {
    return count == NthBValue();
  }
  if (NthAValue() > 0) {
    if (count < NthBValue()) {
      return false;
    }
    return (count - NthBValue()) % NthAValue() == 0;
  }
  if (count > NthBValue()) {
    return false;
  }
  return (NthBValue() - count) % (-NthAValue()) == 0;
}

void CSSSelector::SetIdentList(
    std::unique_ptr<Vector<AtomicString>> ident_list) {
  CreateRareData();
  data_.rare_data_->ident_list_ = std::move(ident_list);
}

void CSSSelector::Trace(V
"""


```