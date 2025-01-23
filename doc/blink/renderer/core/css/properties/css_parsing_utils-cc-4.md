Response:
The user wants a summary of the functionality of the provided C++ code snippet from a Chromium Blink engine file. I need to identify the main purpose of this code, its relation to web technologies (JavaScript, HTML, CSS), provide examples, hypothetical inputs/outputs, common user/programming errors, and debugging steps.

**Functionality Identification:**

The code primarily deals with parsing and processing CSS property values. It contains functions to:
- Count the usage of specific CSS keywords and properties.
- Warn about the usage of deprecated or invalid keywords.
- Parse different types of CSS values (longhand properties, shorthands, keywords, etc.).
- Consume specific CSS value components (like `scroll()`, `view()`, animation related values, background properties, etc.).
- Manage lists of CSS values.

**Relationship to Web Technologies:**

- **CSS:** This is directly related to CSS parsing, interpreting CSS syntax and values.
- **JavaScript:** While this code is in C++, the parsed CSS styles are eventually used by the rendering engine, which can be influenced by JavaScript through DOM manipulation and setting inline styles.
- **HTML:** The parsed CSS styles are applied to HTML elements, determining their visual presentation.

**Examples, Hypothetical Inputs/Outputs, Errors, and Debugging:**

I will create examples focusing on the functions present in this specific code snippet.
这是 `blink/renderer/core/css/properties/css_parsing_utils.cc` 文件的第 5 部分，主要包含以下功能：

**核心功能：解析和消费各种 CSS 属性的特定值和语法结构。**

这一部分代码定义了许多辅助函数，用于从 CSS 解析器令牌流 (`CSSParserTokenStream`) 中提取和验证特定的 CSS 值。这些函数涵盖了多种 CSS 特性和语法，例如：

* **计数 CSS 特性使用情况:** `CountKeywordOnlyPropertyUsage` 函数用于记录特定 CSS 属性和值的组合被使用的次数，这对于跟踪 Web 功能的使用情况非常重要。
* **警告无效的关键字属性用法:** `WarnInvalidKeywordPropertyUsage` 函数会在控制台中输出警告信息，提示开发者使用了已弃用或即将移除的 CSS 关键字。
* **解析 Longhand 属性:** `ParseLonghand` 函数负责解析非简写的 CSS 属性值。它会根据属性的类型调用相应的解析逻辑。
* **解析 Shorthand 属性（通过 Longhand）：** `ConsumeShorthandVia2Longhands`、`ConsumeShorthandVia4Longhands` 和 `ConsumeShorthandGreedilyViaLonghands` 函数处理简写属性的解析，它们将简写属性拆解成多个 Longhand 属性并分别解析。
* **添加展开的属性:** `AddExpandedPropertyForValue` 函数用于将一个 CSS 值应用到多个相关的 Longhand 属性上，通常用于处理简写属性。
* **判断关键字类型:**  一系列 `Is...Keyword` 函数用于判断给定的 CSS 值 ID 或字符串是否属于特定的关键字类型（例如，基线关键字、自定位关键字、内容定位关键字、CSS 宽关键字等）。
* **消费 CSS 宽关键字:** `ConsumeCSSWideKeyword` 函数用于从令牌流中提取并创建 `initial`, `inherit`, `unset`, `revert`, `revert-layer` 等全局 CSS 关键字的 CSSValue 对象。
* **消费特定类型的 CSS 值:**
    * `ConsumeSelfPositionOverflowPosition`, `ConsumeContentDistributionOverflowPosition`: 处理 flexbox 和 grid 布局中 `justify-content` 和 `align-items` 等属性的关键字组合。
    * `ConsumeAnimationIterationCount`, `ConsumeAnimationName`, `ConsumeAnimationTimeline`, `ConsumeAnimationTimingFunction`, `ConsumeAnimationDuration`, `ConsumeAnimationDelay`, `ConsumeAnimationRange`:  解析与 CSS 动画相关的各种属性值。
    * `ConsumeScrollFunction`, `ConsumeViewFunction`:  解析 `scroll()` 和 `view()` 等函数形式的 CSS 值，用于滚动捕捉和视口片段。
    * `ConsumeBackgroundAttachment`, `ConsumeBackgroundBlendMode`, `ConsumeBackgroundBox`, `ConsumeBackgroundBoxOrText`, `ConsumeMaskComposite`, `ConsumePrefixedMaskComposite`, `ConsumeMaskMode`, `ConsumeBackgroundSize`, `ConsumeBackgroundPosition`, `ConsumePrefixedBackgroundBox`: 解析与背景和遮罩相关的属性值。
* **消费动画简写属性:** `ConsumeAnimationShorthand` 函数处理 `animation` 简写属性的解析，它会尝试解析各个子属性，并处理未解析的子属性的默认值。
* **消费 Timeline 相关的属性值:** `ConsumeSingleTimelineAxis`, `ConsumeSingleTimelineName`, `ConsumeSingleTimelineInset` 用于解析与滚动时间线相关的属性值。
* **处理 CSS 值列表:** `GetSingleValueOrMakeList` 函数用于根据解析出的值的数量，返回单个值或创建一个 CSSValueList 对象。

**与 JavaScript, HTML, CSS 的关系和举例:**

* **CSS:**  这个文件直接负责 CSS 的解析。例如，当浏览器遇到以下 CSS 规则时：

   ```css
   .element {
       display: contents;
       overflow-x: overlay;
       writing-mode: vertical-rl;
       appearance: slider-vertical; /* 已弃用 */
       -webkit-user-modify: read-write;
       animation-name: slide-in;
       animation-duration: 1s;
       background-size: cover;
       background-position: center top;
   }
   ```

   `css_parsing_utils.cc` 中的函数会被调用来解析这些属性的值：

   * `ConsumeIdent` 会被用于解析 `contents`, `overlay`, `vertical-rl`, `cover`, `center`, `top` 等关键字。
   * `CountKeywordOnlyPropertyUsage` 会记录 `display: contents`, `overflow-x: overlay`, `writing-mode: vertical-rl`, `-webkit-user-modify: read-write` 的使用。
   * `WarnInvalidKeywordPropertyUsage` 会在开发者工具的控制台中输出关于 `appearance: slider-vertical` 已弃用的警告。
   * `ConsumeAnimationName` 会解析 `slide-in`。
   * `ConsumeAnimationDuration` 会解析 `1s`。
   * `ConsumeBackgroundSize` 会解析 `cover`。
   * `ConsumeBackgroundPosition` 会解析 `center top`。

* **JavaScript:** JavaScript 可以通过 DOM API 操作元素的样式，例如：

   ```javascript
   const element = document.querySelector('.element');
   element.style.display = 'contents';
   ```

   当 JavaScript 设置这些样式时，底层的渲染引擎仍然会调用类似的 CSS 解析逻辑，最终会涉及到 `css_parsing_utils.cc` 中的函数。

* **HTML:** HTML 结构与 CSS 样式关联，CSS 规则会应用到相应的 HTML 元素上。例如，上面的 CSS 规则会影响所有 class 为 `element` 的 HTML 元素。

**逻辑推理、假设输入与输出:**

**假设输入:**  CSS 属性和值的令牌流，例如，对于 `animation-timing-function: cubic-bezier(0.25, 0.1, 0.25, 1.0)`，输入的令牌可能是 `IDENT(cubic-bezier)`, `LPAREN`, `NUMBER(0.25)`, `COMMA`, `NUMBER(0.1)`, `COMMA`, `NUMBER(0.25)`, `COMMA`, `NUMBER(1.0)`, `RPAREN`。

**输出:**  对于 `ConsumeAnimationTimingFunction` 函数，如果输入的令牌流匹配 `cubic-bezier` 函数的语法，输出将是一个指向 `CSSCubicBezierValue` 对象的指针，该对象包含了四个控制点的坐标值。如果语法不正确，则输出 `nullptr`。

**用户或编程常见的使用错误及举例:**

* **使用已弃用的关键字:**  例如，在较新的 Chrome 版本中使用 `appearance: slider-vertical` 会触发 `WarnInvalidKeywordPropertyUsage` 并输出警告信息。
* **拼写错误的 CSS 属性或值:** 例如，`dispay: flex` (拼写错误) 会导致解析失败。相关的解析函数会返回 `nullptr`。
* **使用了不兼容的 CSS 特性:** 例如，在不支持 `display: contents` 的旧浏览器中使用该属性，会导致该属性被忽略。虽然 `css_parsing_utils.cc` 负责解析，但最终渲染结果会受到浏览器支持的影响。
* **动画简写属性中缺少必要的值:** 例如，`animation: slide-in;`  缺少 `animation-duration`，这可能会导致动画行为不符合预期，`ConsumeAnimationShorthand` 会为缺失的属性设置初始值。

**用户操作到达这里的调试线索:**

1. **用户加载一个包含 CSS 样式的网页:**  当浏览器加载 HTML 文件并解析到 `<style>` 标签或外部 CSS 文件时，CSS 解析器开始工作。
2. **CSS 解析器将 CSS 文本转换为令牌流:**  例如，对于 `div { display: flex; }`，解析器会生成 `IDENT(div)`, `LBRACE`, `IDENT(display)`, `COLON`, `IDENT(flex)`, `SEMICOLON`, `RBRACE` 等令牌。
3. **解析器遇到需要解析的属性值:** 例如，当解析到 `display: flex;` 时，会调用与 `display` 属性相关的解析函数。
4. **特定的解析函数被调用:**  对于 `display: flex;`，可能会调用处理 `display` 属性的函数，该函数可能会进一步调用 `ConsumeIdent` 来解析 `flex` 关键字。
5. **在 `css_parsing_utils.cc` 中查找对应的解析逻辑:**  开发者可以通过断点调试或代码审查，追踪 CSS 解析的流程，最终定位到 `css_parsing_utils.cc` 中处理特定属性值的函数。例如，如果想调试 `display: contents;` 的解析过程，可能会关注 `CountKeywordOnlyPropertyUsage` 函数的调用。
6. **检查控制台警告信息:**  如果用户使用了已弃用的特性，开发者工具的控制台可能会显示由 `WarnInvalidKeywordPropertyUsage` 生成的警告信息，从而引导开发者查看相关代码。

**总结第 5 部分的功能:**

第 5 部分的 `css_parsing_utils.cc` 主要负责 **解析和消费各种具体的 CSS 属性值和语法结构**。它提供了一系列工具函数，用于从 CSS 令牌流中提取、验证和创建代表不同 CSS 值的对象。这部分代码覆盖了包括布局、动画、背景、遮罩等多种 CSS 特性，并且包含了用于记录特性使用情况和警告无效用法的机制。 它是 CSS 解析流程中至关重要的一部分，将文本形式的 CSS 转换为浏览器可以理解和应用的内部数据结构。

### 提示词
```
这是目录为blink/renderer/core/css/properties/css_parsing_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
} else {
          feature = WebFeature::kCSSValueAppearanceOthers;
        }
      }
      context.Count(feature);
      break;
    }

    case CSSPropertyID::kWebkitUserModify: {
      switch (value_id) {
        case CSSValueID::kReadOnly:
          context.Count(WebFeature::kCSSValueUserModifyReadOnly);
          break;
        case CSSValueID::kReadWrite:
          context.Count(WebFeature::kCSSValueUserModifyReadWrite);
          break;
        case CSSValueID::kReadWritePlaintextOnly:
          context.Count(WebFeature::kCSSValueUserModifyReadWritePlaintextOnly);
          break;
        default:
          NOTREACHED();
      }
      break;
    }
    case CSSPropertyID::kDisplay:
      if (value_id == CSSValueID::kContents) {
        context.Count(WebFeature::kCSSValueDisplayContents);
      }
      break;
    case CSSPropertyID::kOverflowX:
    case CSSPropertyID::kOverflowY:
      if (value_id == CSSValueID::kOverlay) {
        context.Count(WebFeature::kCSSValueOverflowOverlay);
      }
      break;
    case CSSPropertyID::kWritingMode:
    case CSSPropertyID::kWebkitWritingMode:
      if (value_id == CSSValueID::kVerticalRl || value_id == CSSValueID::kTb ||
          value_id == CSSValueID::kTbRl) {
        context.Count(WebFeature::kCssValueWritingModeVerticalRl);
      } else if (value_id == CSSValueID::kVerticalLr) {
        context.Count(WebFeature::kCssValueWritingModeVerticalLr);
      } else if (value_id == CSSValueID::kSidewaysRl) {
        context.Count(WebFeature::kCssValueWritingModeSidewaysRl);
      } else if (value_id == CSSValueID::kSidewaysLr) {
        context.Count(WebFeature::kCssValueWritingModeSidewaysLr);
      }
      break;
    default:
      break;
  }
}

void WarnInvalidKeywordPropertyUsage(CSSPropertyID property,
                                     const CSSParserContext& context,
                                     CSSValueID value_id) {
  if (!context.IsUseCounterRecordingEnabled()) {
    return;
  }
  switch (property) {
    case CSSPropertyID::kAppearance:
    case CSSPropertyID::kAliasWebkitAppearance: {
      // TODO(crbug.com/924486, crbug.com/1426629): Remove warnings after
      // shipping.
      if ((!RuntimeEnabledFeatures::
               NonStandardAppearanceValueSliderVerticalEnabled() &&
           value_id == CSSValueID::kSliderVertical)) {
        if (const auto* document = context.GetDocument()) {
          document->AddConsoleMessage(
              MakeGarbageCollected<ConsoleMessage>(
                  mojom::blink::ConsoleMessageSource::kOther,
                  mojom::blink::ConsoleMessageLevel::kWarning,
                  "The keyword 'slider-vertical' used on the 'appearance' "
                  "property was deprecated and has now been removed. It will "
                  "no longer have any effect."),
              true);
        }
      }
      break;
    }
    default:
      break;
  }
}

const CSSValue* ParseLonghand(CSSPropertyID unresolved_property,
                              CSSPropertyID current_shorthand,
                              const CSSParserContext& context,
                              CSSParserTokenStream& stream) {
  CSSPropertyID property_id = ResolveCSSPropertyID(unresolved_property);
  CSSValueID value_id = stream.Peek().Id();
  DCHECK(!CSSProperty::Get(property_id).IsShorthand());
  if (CSSParserFastPaths::IsHandledByKeywordFastPath(property_id)) {
    if (CSSParserFastPaths::IsValidKeywordPropertyAndValue(
            property_id, stream.Peek().Id(), context.Mode())) {
      CountKeywordOnlyPropertyUsage(property_id, context, value_id);
      return ConsumeIdent(stream);
    }
    WarnInvalidKeywordPropertyUsage(property_id, context, value_id);
    return nullptr;
  }

  const auto local_context =
      CSSParserLocalContext()
          .WithAliasParsing(IsPropertyAlias(unresolved_property))
          .WithCurrentShorthand(current_shorthand);

  const CSSValue* result =
      To<Longhand>(CSSProperty::Get(property_id))
          .ParseSingleValue(stream, context, local_context);
  return result;
}

bool ConsumeShorthandVia2Longhands(
    const StylePropertyShorthand& shorthand,
    bool important,
    const CSSParserContext& context,
    CSSParserTokenStream& stream,
    HeapVector<CSSPropertyValue, 64>& properties) {
  const StylePropertyShorthand::Properties& longhands = shorthand.properties();
  DCHECK_EQ(longhands.size(), 2u);

  const CSSValue* start = ParseLonghand(longhands[0]->PropertyID(),
                                        shorthand.id(), context, stream);

  if (!start) {
    return false;
  }

  const CSSValue* end = ParseLonghand(longhands[1]->PropertyID(),
                                      shorthand.id(), context, stream);

  if (shorthand.id() == CSSPropertyID::kOverflow && start && end) {
    context.Count(WebFeature::kTwoValuedOverflow);
  }

  if (!end) {
    end = start;
  }
  AddProperty(longhands[0]->PropertyID(), shorthand.id(), *start, important,
              IsImplicitProperty::kNotImplicit, properties);
  AddProperty(longhands[1]->PropertyID(), shorthand.id(), *end, important,
              IsImplicitProperty::kNotImplicit, properties);

  return true;
}

bool ConsumeShorthandVia4Longhands(
    const StylePropertyShorthand& shorthand,
    bool important,
    const CSSParserContext& context,
    CSSParserTokenStream& stream,
    HeapVector<CSSPropertyValue, 64>& properties) {
  const StylePropertyShorthand::Properties& longhands = shorthand.properties();
  DCHECK_EQ(longhands.size(), 4u);
  const CSSValue* top = ParseLonghand(longhands[0]->PropertyID(),
                                      shorthand.id(), context, stream);

  if (!top) {
    return false;
  }

  const CSSValue* right = ParseLonghand(longhands[1]->PropertyID(),
                                        shorthand.id(), context, stream);

  const CSSValue* bottom = nullptr;
  const CSSValue* left = nullptr;
  if (right) {
    bottom = ParseLonghand(longhands[2]->PropertyID(), shorthand.id(), context,
                           stream);
    if (bottom) {
      left = ParseLonghand(longhands[3]->PropertyID(), shorthand.id(), context,
                           stream);
    }
  }

  if (!right) {
    right = top;
  }
  if (!bottom) {
    bottom = top;
  }
  if (!left) {
    left = right;
  }

  AddProperty(longhands[0]->PropertyID(), shorthand.id(), *top, important,
              IsImplicitProperty::kNotImplicit, properties);
  AddProperty(longhands[1]->PropertyID(), shorthand.id(), *right, important,
              IsImplicitProperty::kNotImplicit, properties);
  AddProperty(longhands[2]->PropertyID(), shorthand.id(), *bottom, important,
              IsImplicitProperty::kNotImplicit, properties);
  AddProperty(longhands[3]->PropertyID(), shorthand.id(), *left, important,
              IsImplicitProperty::kNotImplicit, properties);

  return true;
}

bool ConsumeShorthandGreedilyViaLonghands(
    const StylePropertyShorthand& shorthand,
    bool important,
    const CSSParserContext& context,
    CSSParserTokenStream& stream,
    HeapVector<CSSPropertyValue, 64>& properties,
    bool use_initial_value_function) {
  // Existing shorthands have at most 6 longhands.
  DCHECK_LE(shorthand.length(), 6u);
  std::array<const CSSValue*, 6> longhands = {nullptr};
  const StylePropertyShorthand::Properties& shorthand_properties =
      shorthand.properties();
  bool found_any = false;
  bool found_longhand;
  do {
    found_longhand = false;
    for (size_t i = 0; i < shorthand.length(); ++i) {
      if (longhands[i]) {
        continue;
      }
      longhands[i] = ParseLonghand(shorthand_properties[i]->PropertyID(),
                                   shorthand.id(), context, stream);

      if (longhands[i]) {
        found_longhand = true;
        found_any = true;
        break;
      }
    }
  } while (found_longhand && !stream.AtEnd());

  if (!found_any) {
    return false;
  }

  for (size_t i = 0; i < shorthand.length(); ++i) {
    if (longhands[i]) {
      AddProperty(shorthand_properties[i]->PropertyID(), shorthand.id(),
                  *longhands[i], important, IsImplicitProperty::kNotImplicit,
                  properties);
    } else {
      const CSSValue* value =
          use_initial_value_function
              ? To<Longhand>(shorthand_properties[i])->InitialValue()
              : CSSInitialValue::Create();
      AddProperty(shorthand_properties[i]->PropertyID(), shorthand.id(), *value,
                  important, IsImplicitProperty::kNotImplicit, properties);
    }
  }
  return true;
}

void AddExpandedPropertyForValue(CSSPropertyID property,
                                 const CSSValue& value,
                                 bool important,
                                 HeapVector<CSSPropertyValue, 64>& properties) {
  const StylePropertyShorthand& shorthand = shorthandForProperty(property);
  const StylePropertyShorthand::Properties& longhands = shorthand.properties();
  DCHECK(longhands.size());
  for (const CSSProperty* const longhand : longhands) {
    AddProperty(longhand->PropertyID(), property, value, important,
                IsImplicitProperty::kNotImplicit, properties);
  }
}

bool IsBaselineKeyword(CSSValueID id) {
  return IdentMatches<CSSValueID::kFirst, CSSValueID::kLast,
                      CSSValueID::kBaseline>(id);
}

bool IsSelfPositionKeyword(CSSValueID id) {
  return IdentMatches<CSSValueID::kStart, CSSValueID::kEnd, CSSValueID::kCenter,
                      CSSValueID::kSelfStart, CSSValueID::kSelfEnd,
                      CSSValueID::kFlexStart, CSSValueID::kFlexEnd,
                      CSSValueID::kAnchorCenter>(id);
}

bool IsSelfPositionOrLeftOrRightKeyword(CSSValueID id) {
  return IsSelfPositionKeyword(id) || IsLeftOrRightKeyword(id);
}

bool IsContentPositionKeyword(CSSValueID id) {
  return IdentMatches<CSSValueID::kStart, CSSValueID::kEnd, CSSValueID::kCenter,
                      CSSValueID::kFlexStart, CSSValueID::kFlexEnd>(id);
}

bool IsContentPositionOrLeftOrRightKeyword(CSSValueID id) {
  return IsContentPositionKeyword(id) || IsLeftOrRightKeyword(id);
}

// https://drafts.csswg.org/css-values-4/#css-wide-keywords
bool IsCSSWideKeyword(CSSValueID id) {
  return id == CSSValueID::kInherit || id == CSSValueID::kInitial ||
         id == CSSValueID::kUnset || id == CSSValueID::kRevert ||
         id == CSSValueID::kRevertLayer;
  // This function should match the overload after it.
}

// https://drafts.csswg.org/css-values-4/#css-wide-keywords
bool IsCSSWideKeyword(StringView keyword) {
  return EqualIgnoringASCIICase(keyword, "initial") ||
         EqualIgnoringASCIICase(keyword, "inherit") ||
         EqualIgnoringASCIICase(keyword, "unset") ||
         EqualIgnoringASCIICase(keyword, "revert") ||
         EqualIgnoringASCIICase(keyword, "revert-layer");
  // This function should match the overload before it.
}

// https://drafts.csswg.org/css-cascade/#default
bool IsRevertKeyword(StringView keyword) {
  return EqualIgnoringASCIICase(keyword, "revert");
}

// https://drafts.csswg.org/css-values-4/#identifier-value
bool IsDefaultKeyword(StringView keyword) {
  return EqualIgnoringASCIICase(keyword, "default");
}

// https://drafts.csswg.org/css-syntax/#typedef-hash-token
bool IsHashIdentifier(const CSSParserToken& token) {
  return token.GetType() == kHashToken &&
         token.GetHashTokenType() == kHashTokenId;
}

bool IsDashedIdent(const CSSParserToken& token) {
  if (token.GetType() != kIdentToken) {
    return false;
  }
  DCHECK(!IsCSSWideKeyword(token.Value()));
  return token.Value().ToString().StartsWith(kTwoDashes);
}

CSSValue* ConsumeCSSWideKeyword(CSSParserTokenStream& stream) {
  if (!IsCSSWideKeyword(stream.Peek().Id())) {
    return nullptr;
  }
  switch (stream.ConsumeIncludingWhitespace().Id()) {
    case CSSValueID::kInitial:
      return CSSInitialValue::Create();
    case CSSValueID::kInherit:
      return CSSInheritedValue::Create();
    case CSSValueID::kUnset:
      return cssvalue::CSSUnsetValue::Create();
    case CSSValueID::kRevert:
      return cssvalue::CSSRevertValue::Create();
    case CSSValueID::kRevertLayer:
      return cssvalue::CSSRevertLayerValue::Create();
    default:
      NOTREACHED();
  }
}

bool IsTimelineName(const CSSParserToken& token) {
  if (token.GetType() == kStringToken) {
    return true;
  }
  return token.GetType() == kIdentToken &&
         IsCustomIdent<CSSValueID::kNone>(token.Id());
}

CSSValue* ConsumeSelfPositionOverflowPosition(
    CSSParserTokenStream& stream,
    IsPositionKeyword is_position_keyword) {
  DCHECK(is_position_keyword);
  CSSValueID id = stream.Peek().Id();
  if (IsAuto(id) || IsNormalOrStretch(id)) {
    return ConsumeIdent(stream);
  }

  if (CSSValue* baseline = ConsumeBaseline(stream)) {
    return baseline;
  }

  CSSIdentifierValue* overflow_position =
      ConsumeOverflowPositionKeyword(stream);
  if (!is_position_keyword(stream.Peek().Id())) {
    return nullptr;
  }
  CSSIdentifierValue* self_position = ConsumeIdent(stream);
  if (overflow_position) {
    return MakeGarbageCollected<CSSValuePair>(
        overflow_position, self_position, CSSValuePair::kDropIdenticalValues);
  }
  return self_position;
}

CSSValue* ConsumeContentDistributionOverflowPosition(
    CSSParserTokenStream& stream,
    IsPositionKeyword is_position_keyword) {
  DCHECK(is_position_keyword);
  CSSValueID id = stream.Peek().Id();
  if (IdentMatches<CSSValueID::kNormal>(id)) {
    return MakeGarbageCollected<cssvalue::CSSContentDistributionValue>(
        CSSValueID::kInvalid, stream.ConsumeIncludingWhitespace().Id(),
        CSSValueID::kInvalid);
  }

  if (CSSValue* baseline = ConsumeFirstBaseline(stream)) {
    return MakeGarbageCollected<cssvalue::CSSContentDistributionValue>(
        CSSValueID::kInvalid, GetBaselineKeyword(*baseline),
        CSSValueID::kInvalid);
  }

  if (IsContentDistributionKeyword(id)) {
    return MakeGarbageCollected<cssvalue::CSSContentDistributionValue>(
        stream.ConsumeIncludingWhitespace().Id(), CSSValueID::kInvalid,
        CSSValueID::kInvalid);
  }

  CSSParserSavePoint savepoint(stream);
  CSSValueID overflow = IsOverflowKeyword(id)
                            ? stream.ConsumeIncludingWhitespace().Id()
                            : CSSValueID::kInvalid;
  if (is_position_keyword(stream.Peek().Id())) {
    savepoint.Release();
    return MakeGarbageCollected<cssvalue::CSSContentDistributionValue>(
        CSSValueID::kInvalid, stream.ConsumeIncludingWhitespace().Id(),
        overflow);
  }

  return nullptr;
}

CSSValue* ConsumeAnimationIterationCount(CSSParserTokenStream& stream,
                                         const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kInfinite) {
    return ConsumeIdent(stream);
  }
  return ConsumeNumber(stream, context,
                       CSSPrimitiveValue::ValueRange::kNonNegative);
}

CSSValue* ConsumeAnimationName(CSSParserTokenStream& stream,
                               const CSSParserContext& context,
                               bool allow_quoted_name) {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return ConsumeIdent(stream);
  }

  if (allow_quoted_name && stream.Peek().GetType() == kStringToken) {
    // Legacy support for strings in prefixed animations.
    context.Count(WebFeature::kQuotedAnimationName);

    const CSSParserToken& token = stream.ConsumeIncludingWhitespace();
    if (EqualIgnoringASCIICase(token.Value(), "none")) {
      return CSSIdentifierValue::Create(CSSValueID::kNone);
    }
    return MakeGarbageCollected<CSSCustomIdentValue>(
        token.Value().ToAtomicString());
  }

  return ConsumeCustomIdent(stream, context);
}

CSSValue* ConsumeScrollFunction(CSSParserTokenStream& stream,
                                const CSSParserContext& context) {
  if (stream.Peek().FunctionId() != CSSValueID::kScroll) {
    return nullptr;
  }

  CSSValue* scroller = nullptr;
  CSSIdentifierValue* axis = nullptr;

  {
    CSSParserTokenStream::BlockGuard guard(stream);
    stream.ConsumeWhitespace();
    while (!scroller || !axis) {
      if (stream.AtEnd()) {
        break;
      }
      if (!scroller) {
        if ((scroller = ConsumeIdent<CSSValueID::kRoot, CSSValueID::kNearest,
                                     CSSValueID::kSelf>(stream))) {
          continue;
        }
      }
      if (!axis) {
        if ((axis = ConsumeIdent<CSSValueID::kBlock, CSSValueID::kInline,
                                 CSSValueID::kX, CSSValueID::kY>(stream))) {
          continue;
        }
      }
      return nullptr;
    }
    if (!stream.AtEnd()) {
      return nullptr;
    }
    // Nullify default values.
    // https://drafts.csswg.org/scroll-animations-1/#valdef-scroll-nearest
    if (scroller && IsIdent(*scroller, CSSValueID::kNearest)) {
      scroller = nullptr;
    }
    // https://drafts.csswg.org/scroll-animations-1/#valdef-scroll-block
    if (axis && IsIdent(*axis, CSSValueID::kBlock)) {
      axis = nullptr;
    }
  }
  stream.ConsumeWhitespace();
  return MakeGarbageCollected<cssvalue::CSSScrollValue>(scroller, axis);
}

CSSValue* ConsumeViewFunction(CSSParserTokenStream& stream,
                              const CSSParserContext& context) {
  if (stream.Peek().FunctionId() != CSSValueID::kView) {
    return nullptr;
  }

  CSSIdentifierValue* axis = nullptr;
  CSSValue* inset = nullptr;

  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();
    while (!axis || !inset) {
      if (stream.AtEnd()) {
        break;
      }
      if (!axis) {
        if ((axis = ConsumeIdent<CSSValueID::kBlock, CSSValueID::kInline,
                                 CSSValueID::kX, CSSValueID::kY>(stream))) {
          continue;
        }
      }
      if (!inset) {
        if ((inset = ConsumeSingleTimelineInset(stream, context))) {
          continue;
        }
      }
      return nullptr;
    }

    if (!stream.AtEnd()) {
      return nullptr;
    }
    guard.Release();
  }
  stream.ConsumeWhitespace();

  // Nullify default values.
  // https://drafts.csswg.org/scroll-animations-1/#valdef-scroll-block
  if (axis && IsIdent(*axis, CSSValueID::kBlock)) {
    axis = nullptr;
  }
  if (inset) {
    auto* inset_pair = DynamicTo<CSSValuePair>(inset);
    if (IsIdent(inset_pair->First(), CSSValueID::kAuto) &&
        IsIdent(inset_pair->Second(), CSSValueID::kAuto)) {
      inset = nullptr;
    }
  }

  return MakeGarbageCollected<cssvalue::CSSViewValue>(axis, inset);
}

CSSValue* ConsumeAnimationTimeline(CSSParserTokenStream& stream,
                                   const CSSParserContext& context) {
  if (auto* value =
          ConsumeIdent<CSSValueID::kNone, CSSValueID::kAuto>(stream)) {
    return value;
  }
  if (auto* value = ConsumeDashedIdent(stream, context)) {
    return value;
  }
  if (auto* value = ConsumeViewFunction(stream, context)) {
    return value;
  }
  return ConsumeScrollFunction(stream, context);
}

CSSValue* ConsumeAnimationTimingFunction(CSSParserTokenStream& stream,
                                         const CSSParserContext& context) {
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kEase || id == CSSValueID::kLinear ||
      id == CSSValueID::kEaseIn || id == CSSValueID::kEaseOut ||
      id == CSSValueID::kEaseInOut || id == CSSValueID::kStepStart ||
      id == CSSValueID::kStepEnd) {
    return ConsumeIdent(stream);
  }

  CSSValueID function = stream.Peek().FunctionId();
  if (function == CSSValueID::kLinear) {
    return ConsumeLinear(stream, context);
  }
  if (function == CSSValueID::kSteps) {
    return ConsumeSteps(stream, context);
  }
  if (function == CSSValueID::kCubicBezier) {
    return ConsumeCubicBezier(stream, context);
  }
  return nullptr;
}

CSSValue* ConsumeAnimationDuration(CSSParserTokenStream& stream,
                                   const CSSParserContext& context) {
  if (RuntimeEnabledFeatures::ScrollTimelineEnabled()) {
    if (CSSValue* ident = ConsumeIdent<CSSValueID::kAuto>(stream)) {
      return ident;
    }
  }
  return ConsumeTime(stream, context,
                     CSSPrimitiveValue::ValueRange::kNonNegative);
}

CSSValue* ConsumeTimelineRangeName(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kContain, CSSValueID::kCover,
                      CSSValueID::kEntry, CSSValueID::kEntryCrossing,
                      CSSValueID::kExit, CSSValueID::kExitCrossing>(stream);
}

CSSValue* ConsumeTimelineRangeNameAndPercent(CSSParserTokenStream& stream,
                                             const CSSParserContext& context) {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  CSSValue* range_name = ConsumeTimelineRangeName(stream);
  if (!range_name) {
    return nullptr;
  }
  list->Append(*range_name);
  CSSValue* percentage =
      ConsumePercent(stream, context, CSSPrimitiveValue::ValueRange::kAll);
  if (!percentage) {
    return nullptr;
  }
  list->Append(*percentage);
  return list;
}

CSSValue* ConsumeAnimationDelay(CSSParserTokenStream& stream,
                                const CSSParserContext& context) {
  return ConsumeTime(stream, context, CSSPrimitiveValue::ValueRange::kAll);
}

CSSValue* ConsumeAnimationRange(CSSParserTokenStream& stream,
                                const CSSParserContext& context,
                                double default_offset_percent) {
  DCHECK(RuntimeEnabledFeatures::ScrollTimelineEnabled());
  if (CSSValue* ident = ConsumeIdent<CSSValueID::kNormal>(stream)) {
    return ident;
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  CSSValue* range_name = ConsumeTimelineRangeName(stream);
  if (range_name) {
    list->Append(*range_name);
  }
  CSSPrimitiveValue* percentage = ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
  if (percentage &&
      !(range_name && percentage->IsPercentage() &&
        percentage->GetValue<double>() == default_offset_percent)) {
    list->Append(*percentage);
  } else if (!range_name) {
    return nullptr;
  }
  return list;
}

bool ConsumeAnimationShorthand(
    const StylePropertyShorthand& shorthand,
    HeapVector<Member<CSSValueList>, kMaxNumAnimationLonghands>& longhands,
    ConsumeAnimationItemValue consumeLonghandItem,
    IsResetOnlyFunction is_reset_only,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    bool use_legacy_parsing) {
  DCHECK(consumeLonghandItem);
  const unsigned longhand_count = shorthand.length();
  DCHECK_LE(longhand_count, kMaxNumAnimationLonghands);

  for (unsigned i = 0; i < longhand_count; ++i) {
    longhands[i] = CSSValueList::CreateCommaSeparated();
  }

  do {
    std::array<bool, kMaxNumAnimationLonghands> parsed_longhand = {false};
    bool found_any = false;
    do {
      bool found_property = false;
      for (unsigned i = 0; i < longhand_count; ++i) {
        if (parsed_longhand[i]) {
          continue;
        }

        CSSValue* value =
            consumeLonghandItem(shorthand.properties()[i]->PropertyID(), stream,
                                context, use_legacy_parsing);
        if (value) {
          parsed_longhand[i] = true;
          found_property = true;
          found_any = true;
          longhands[i]->Append(*value);
          break;
        }
      }
      if (!found_property) {
        break;
      }
    } while (!stream.AtEnd() && stream.Peek().GetType() != kCommaToken);

    if (!found_any) {
      return false;
    }

    for (unsigned i = 0; i < longhand_count; ++i) {
      const Longhand& longhand = *To<Longhand>(shorthand.properties()[i]);
      if (!parsed_longhand[i]) {
        // For each longhand that doesn't parse, add the initial (list-item)
        // value instead. However, we only do this *once* for reset-only
        // properties to end up with the initial value for the property as
        // a whole.
        //
        // Example:
        //
        //  animation: anim1, anim2;
        //
        // Should expand to (ignoring longhands other than name and timeline):
        //
        //   animation-name: anim1, anim2;
        //   animation-timeline: auto;
        //
        // It should *not* expand to:
        //
        //   animation-name: anim1, anim2;
        //   animation-timeline: auto, auto;
        //
        if (!is_reset_only(longhand.PropertyID()) || !longhands[i]->length()) {
          longhands[i]->Append(*longhand.InitialValue());
        }
      }
      parsed_longhand[i] = false;
    }
  } while (ConsumeCommaIncludingWhitespace(stream));

  return true;
}

CSSValue* ConsumeSingleTimelineAxis(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kBlock, CSSValueID::kInline, CSSValueID::kX,
                      CSSValueID::kY>(stream);
}

CSSValue* ConsumeSingleTimelineName(CSSParserTokenStream& stream,
                                    const CSSParserContext& context) {
  if (CSSValue* value = ConsumeIdent<CSSValueID::kNone>(stream)) {
    return value;
  }
  return ConsumeDashedIdent(stream, context);
}

namespace {

CSSValue* ConsumeSingleTimelineInsetSide(CSSParserTokenStream& stream,
                                         const CSSParserContext& context) {
  if (CSSValue* ident = ConsumeIdent<CSSValueID::kAuto>(stream)) {
    return ident;
  }
  return ConsumeLengthOrPercent(stream, context,
                                CSSPrimitiveValue::ValueRange::kAll);
}

}  // namespace

CSSValue* ConsumeSingleTimelineInset(CSSParserTokenStream& stream,
                                     const CSSParserContext& context) {
  CSSValue* start = ConsumeSingleTimelineInsetSide(stream, context);
  if (!start) {
    return nullptr;
  }
  CSSValue* end = ConsumeSingleTimelineInsetSide(stream, context);
  if (!end) {
    end = start;
  }
  return MakeGarbageCollected<CSSValuePair>(start, end,
                                            CSSValuePair::kDropIdenticalValues);
}

const CSSValue* GetSingleValueOrMakeList(
    CSSValue::ValueListSeparator list_separator,
    HeapVector<Member<const CSSValue>, 4> values) {
  if (values.size() == 1u) {
    return values.front().Get();
  }
  return MakeGarbageCollected<CSSValueList>(list_separator, std::move(values));
}

CSSValue* ConsumeBackgroundAttachment(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kScroll, CSSValueID::kFixed,
                      CSSValueID::kLocal>(stream);
}

CSSValue* ConsumeBackgroundBlendMode(CSSParserTokenStream& stream) {
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kNormal || id == CSSValueID::kOverlay ||
      (id >= CSSValueID::kMultiply && id <= CSSValueID::kLuminosity)) {
    return ConsumeIdent(stream);
  }
  return nullptr;
}

CSSValue* ConsumeBackgroundBox(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kBorderBox, CSSValueID::kPaddingBox,
                      CSSValueID::kContentBox>(stream);
}

CSSValue* ConsumeBackgroundBoxOrText(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kBorderBox, CSSValueID::kPaddingBox,
                      CSSValueID::kContentBox, CSSValueID::kText>(stream);
}

CSSValue* ConsumeMaskComposite(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kAdd, CSSValueID::kSubtract,
                      CSSValueID::kIntersect, CSSValueID::kExclude>(stream);
}

CSSValue* ConsumePrefixedMaskComposite(CSSParserTokenStream& stream) {
  return ConsumeIdentRange(stream, CSSValueID::kClear,
                           CSSValueID::kPlusLighter);
}

CSSValue* ConsumeMaskMode(CSSParserTokenStream& stream) {
  return ConsumeIdent<CSSValueID::kAlpha, CSSValueID::kLuminance,
                      CSSValueID::kMatchSource>(stream);
}

CSSPrimitiveValue* ConsumeLengthOrPercentCountNegative(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    std::optional<WebFeature> negative_size) {
  CSSPrimitiveValue* result = ConsumeLengthOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative,
      UnitlessQuirk::kForbid);
  if (!result && negative_size) {
    context.Count(*negative_size);
  }
  return result;
}

CSSValue* ConsumeBackgroundSize(CSSParserTokenStream& stream,
                                const CSSParserContext& context,
                                std::optional<WebFeature> negative_size,
                                ParsingStyle parsing_style) {
  if (IdentMatches<CSSValueID::kContain, CSSValueID::kCover>(
          stream.Peek().Id())) {
    return ConsumeIdent(stream);
  }

  CSSValue* horizontal = ConsumeIdent<CSSValueID::kAuto>(stream);
  if (!horizontal) {
    horizontal =
        ConsumeLengthOrPercentCountNegative(stream, context, negative_size);
  }
  if (!horizontal) {
    return nullptr;
  }

  CSSValue* vertical = nullptr;
  if (!stream.AtEnd()) {
    if (stream.Peek().Id() == CSSValueID::kAuto) {  // `auto' is the default
      stream.ConsumeIncludingWhitespace();
    } else {
      vertical =
          ConsumeLengthOrPercentCountNegative(stream, context, negative_size);
    }
  } else if (parsing_style == ParsingStyle::kLegacy) {
    // Legacy syntax: "-webkit-background-size: 10px" is equivalent to
    // "background-size: 10px 10px".
    vertical = horizontal;
  }
  if (!vertical) {
    return horizontal;
  }
  return MakeGarbageCollected<CSSValuePair>(horizontal, vertical,
                                            CSSValuePair::kKeepIdenticalValues);
}

static void SetAllowsNegativePercentageReference(CSSValue* value) {
  if (auto* math_value = DynamicTo<CSSMathFunctionValue>(value)) {
    math_value->SetAllowsNegativePercentageReference();
  }
}

bool ConsumeBackgroundPosition(CSSParserTokenStream& stream,
                               const CSSParserContext& context,
                               UnitlessQuirk unitless,
                               std::optional<WebFeature> three_value_position,
                               const CSSValue*& result_x,
                               const CSSValue*& result_y) {
  HeapVector<Member<const CSSValue>, 4> values_x;
  HeapVector<Member<const CSSValue>, 4> values_y;

  do {
    CSSValue* position_x = nullptr;
    CSSValue* position_y = nullptr;
    if (!ConsumePosition(stream, context, unitless, three_value_position,
                         position_x, position_y)) {
      return false;
    }
    // TODO(crbug.com/825895): So far, 'background-position' is the only
    // property that allows resolving a percentage against a negative value. If
    // we have more of such properties, we should instead pass an additional
    // argument to ask the parser to set this flag.
    SetAllowsNegativePercentageReference(position_x);
    SetAllowsNegativePercentageReference(position_y);
    values_x.push_back(position_x);
    values_y.push_back(position_y);
  } while (ConsumeCommaIncludingWhitespace(stream));

  // To conserve memory we don't wrap single values in lists.
  result_x =
      GetSingleValueOrMakeList(CSSValue::kCommaSeparator, std::move(values_x));
  result_y =
      GetSingleValueOrMakeList(CSSValue::kCommaSeparator, std::move(values_y));

  return true;
}

CSSValue* ConsumePrefixedBackgroundBox(CSSParserTokenStream& stream,
                                       AllowTextValue allow_text_value) {
  // The values 'border', 'padding' and 'content' are deprecated and do not
  // apply to the version of the property that has the -webkit- prefix removed.
  if (CSSValue* value = ConsumeIdentRange(stream, CSSValueID::kBorder,
                                          CSSValueID::kPaddingBox)) {
    return value;
  }
  if (allow_text_value == AllowTextValue::kAllow &&
      stream.Peek().Id() == CSSValueID::kText) {
    return ConsumeIdent(stream);
  }
  return nullptr;
}

CSSValue* ParseBackgroundBox(CSSParserTokenStream& stream,
                             const CSSParserLocalContext& local_context,
                             AllowTextValue alias_allow_text_value) {
  // This is legacy behavior that does not match spec, see crbug.com/604023
  if (local_context.UseAliasParsing()) {
    return ConsumeCommaSeparatedList(ConsumePrefixedBackgroundBox, stream,
                                     alias_allow_text_value);
  }
  return ConsumeCommaSeparatedList(ConsumeBackgroundBox, stream);
}

CSSValue* ParseBackgroundSize(CSSParserTokenStream& stream,
                              const CSSParserContext& context,
                              const CSSParserLocalContext& local_context,
                              std::optional<WebFeature> negative_size) {
  return ConsumeCommaSeparatedList(
      static_cast<CSSValue* (*)(CSSParserTokenStream&, const CSSParserContext&,
                                std::optional<WebFeature>, ParsingStyle)>(
          ConsumeBackgroundSize)
```