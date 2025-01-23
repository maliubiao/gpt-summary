Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. This code resides in `blink/renderer/core/css/parser/css_parser_impl.cc`.

I need to:
1. **Identify the primary function of the code.**  The function names strongly suggest this code is responsible for parsing different types of CSS at-rules and qualified rules.
2. **Explain the relationship to web technologies (HTML, CSS, Javascript).**  This code directly parses CSS, which styles HTML and can be manipulated by Javascript.
3. **Provide examples of logical inference with inputs and outputs.** I can take specific functions like `ConsumeAtRuleContents` and show how it dispatches to different parsing functions based on the `@` rule type.
4. **Give examples of common user/programming errors.** These would involve incorrect CSS syntax that would be caught by this parsing code.
5. **Explain how a user action might lead to this code being executed.**  This involves the browser loading a web page with CSS.
6. **Summarize the overall function of this code snippet.**
这是第2部分代码，延续了对CSS规则的解析功能。以下是这段代码的功能归纳：

**核心功能：解析各种CSS at-rules（以@开头的规则）和 qualified rules（普通的选择器规则），并创建相应的 StyleRule 对象。**

**具体功能点：**

1. **`ConsumeAtRuleContents` 函数:**
   - **功能:**  根据给定的 `@` 规则 ID ( `CSSAtRuleID` )，进一步解析 `@` 规则的内容。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** `id = CSSAtRuleID::kCSSAtRuleMedia`,  `stream` 指向 `@media screen and (max-width: 600px) { ... }` 的开始。
     - **输出:**  调用 `ConsumeMediaRule` 函数，并返回一个 `StyleRuleMedia` 对象，该对象包含了媒体查询条件和内部的 CSS 规则。
   - **与 CSS 的关系:**  直接解析各种 `@media`, `@supports`, `@import` 等 CSS 规则。
   - **用户/编程常见错误:**
     - 在不允许嵌套的 `@` 规则内部使用了其他 `@` 规则（例如，在 `@keyframes` 内部使用 `@media`）。 代码会调用 `ConsumeErroneousAtRule` 并返回 `nullptr`。
     - `@charset`, `@import`, `@namespace` 等规则的位置不正确（例如，不在样式表的开头）。
   - **用户操作如何到达这里:** 当浏览器解析 `<style>` 标签或外部 CSS 文件时，遇到一个 `@` 符号，会识别出这是一个 at-rule，并调用相应的解析流程最终到达 `ConsumeAtRuleContents`。

2. **`ConsumeQualifiedRule` 函数:**
   - **功能:** 解析普通的 CSS 选择器规则（qualified rules）。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** `allowed_rules = kRegularRules`, `stream` 指向 `.container { color: blue; }` 的开始。
     - **输出:** 调用 `ConsumeStyleRule` 函数，并返回一个 `StyleRule` 对象，其中包含了选择器 `.container` 和属性 `color: blue;`。
   - **与 CSS 的关系:** 解析页面中大部分的 CSS 样式规则。
   - **用户/编程常见错误:**  编写了错误的 CSS 选择器语法或属性语法。

3. **特定 `@` 规则的解析函数 (例如 `ConsumePageMarginRule`, `ConsumeCharsetRule`, `ConsumeImportRule`, `ConsumeNamespaceRule` 等):**
   - **功能:**  针对特定的 `@` 规则，解析其特有的语法结构和内容。
   - **与 CSS 的关系:**  对应于 CSS 规范中定义的各种 `@page`, `@charset`, `@import`, `@namespace` 规则。
   - **用户/编程常见错误:**
     - `@charset` 规则后缺少字符串表示的编码方式。
     - `@import` 规则中 URI 缺失或格式错误。
     - `@namespace` 规则中缺少命名空间前缀或 URI。

4. **`CreateImplicitNestedRule` 函数:**
   - **功能:**  在 CSS 嵌套特性未启用时，为嵌套规则创建隐式的父规则。
   - **与 CSS 的关系:**  处理 CSS 嵌套的兼容性问题。

5. **`CreateNestedDeclarationsRule` 和 `EmitNestedDeclarationsRuleIfNeeded` 函数:**
   - **功能:** 在 CSS 嵌套声明特性启用时，创建表示嵌套声明的规则对象。
   - **与 CSS 的关系:**  处理 CSS 嵌套声明的语法，例如 `.parent { color: red; { font-size: 16px; } }`。

6. **`ConsumeMediaRule`, `ConsumeSupportsRule`, `ConsumeStartingStyleRule` 等函数:**
   - **功能:** 解析特定的条件型 `@` 规则，并递归地解析其内部包含的规则。
   - **与 CSS 的关系:**  处理 `@media`, `@supports`, `@starting-style` 等规则及其内部的样式应用逻辑。

7. **`ConsumeFontFaceRule` 函数:**
   - **功能:** 解析 `@font-face` 规则，定义自定义字体。
   - **与 CSS 的关系:**  处理网页中自定义字体的加载和使用。

8. **`ConsumeKeyframesRule` 函数:**
   - **功能:** 解析 `@keyframes` 规则，定义 CSS 动画的关键帧。
   - **与 CSS 的关系:**  处理网页中的动画效果。

9. **`ConsumeFontFeatureRule` 函数:**
   - **功能:** 解析以 `@stylistic`, `@styleset` 等开头的与 OpenType 字体特性相关的规则。
   - **与 CSS 的关系:**  处理高级字体排版特性。

**调试线索 - 用户操作如何一步步到达这里:**

1. **用户在浏览器中打开一个网页。**
2. **浏览器开始解析 HTML 文档。**
3. **浏览器遇到 `<style>` 标签或 `<link>` 标签引用外部 CSS 文件。**
4. **Blink 引擎的 CSS 解析器开始工作。**
5. **解析器读取 CSS 代码，并逐个识别 token (词法分析)。**
6. **当解析器遇到 `@` 符号时，会判断这是一个 at-rule，然后根据 `@` 后的关键词 (例如 `media`, `import`) 确定 `CSSAtRuleID`。**
7. **调用 `ConsumeAtRule` 函数，根据 `CSSAtRuleID` 分发到对应的解析函数，例如 `ConsumeMediaRule` 或 `ConsumeImportRule`。**
8. **如果遇到普通的选择器，则会调用 `ConsumeQualifiedRule`，最终调用 `ConsumeStyleRule` 来解析样式规则。**

**总结:**

这段代码是 Chromium Blink 引擎 CSS 解析器的核心部分，负责解析各种类型的 CSS 规则（包括 at-rules 和 qualified rules），并构建相应的内部数据结构 ( `StyleRule` 及其子类 )，以便后续的样式计算和渲染。它深入处理了 CSS 的各种语法细节，并能识别和处理一些常见的 CSS 错误。

### 提示词
```
这是目录为blink/renderer/core/css/parser/css_parser_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ID(name);
  return ConsumeAtRuleContents(id, stream, allowed_rules, nesting_type,
                               parent_rule_for_nesting, is_within_scope);
}

StyleRuleBase* CSSParserImpl::ConsumeAtRuleContents(
    CSSAtRuleID id,
    CSSParserTokenStream& stream,
    AllowedRulesType allowed_rules,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope) {
  if (allowed_rules == kNestedGroupRules) {
    if (id != CSSAtRuleID::kCSSAtRuleMedia &&      // [css-conditional-3]
        id != CSSAtRuleID::kCSSAtRuleSupports &&   // [css-conditional-3]
        id != CSSAtRuleID::kCSSAtRuleContainer &&  // [css-contain-3]
        id != CSSAtRuleID::kCSSAtRuleLayer &&      // [css-cascade-5]
        id != CSSAtRuleID::kCSSAtRuleScope &&      // [css-cascade-6]
        id != CSSAtRuleID::kCSSAtRuleStartingStyle &&
        id != CSSAtRuleID::kCSSAtRuleViewTransition &&
        id != CSSAtRuleID::kCSSAtRuleApplyMixin &&
        (id < CSSAtRuleID::kCSSAtRuleTopLeftCorner ||
         id > CSSAtRuleID::kCSSAtRuleRightBottom)) {
      ConsumeErroneousAtRule(stream, id);
      return nullptr;
    }
    allowed_rules = kRegularRules;
  }

  // @import rules have a URI component that is not technically part of the
  // prelude.
  AtomicString import_prelude_uri;
  if (allowed_rules <= kAllowImportRules &&
      id == CSSAtRuleID::kCSSAtRuleImport) {
    import_prelude_uri = ConsumeStringOrURI(stream);
  }

  if (id != CSSAtRuleID::kCSSAtRuleInvalid &&
      context_->IsUseCounterRecordingEnabled()) {
    CountAtRule(context_, id);
  }

  if (allowed_rules == kKeyframeRules || allowed_rules == kNoRules) {
    // Parse error, no at-rules supported inside @keyframes,
    // or blocks supported inside declaration lists.
    ConsumeErroneousAtRule(stream, id);
    return nullptr;
  }

  stream.EnsureLookAhead();
  if (allowed_rules == kAllowCharsetRules &&
      id == CSSAtRuleID::kCSSAtRuleCharset) {
    return ConsumeCharsetRule(stream);
  } else if (allowed_rules <= kAllowImportRules &&
             id == CSSAtRuleID::kCSSAtRuleImport) {
    return ConsumeImportRule(std::move(import_prelude_uri), stream);
  } else if (allowed_rules <= kAllowNamespaceRules &&
             id == CSSAtRuleID::kCSSAtRuleNamespace) {
    return ConsumeNamespaceRule(stream);
  } else if (allowed_rules == kFontFeatureRules) {
    if (id == CSSAtRuleID::kCSSAtRuleStylistic ||
        id == CSSAtRuleID::kCSSAtRuleStyleset ||
        id == CSSAtRuleID::kCSSAtRuleCharacterVariant ||
        id == CSSAtRuleID::kCSSAtRuleSwash ||
        id == CSSAtRuleID::kCSSAtRuleOrnaments ||
        id == CSSAtRuleID::kCSSAtRuleAnnotation) {
      return ConsumeFontFeatureRule(id, stream);
    } else {
      return nullptr;
    }
  } else if (allowed_rules == kPageMarginRules) {
    if (id < CSSAtRuleID::kCSSAtRuleTopLeftCorner ||
        id > CSSAtRuleID::kCSSAtRuleRightBottom) {
      ConsumeErroneousAtRule(stream, id);
      return nullptr;
    }
    return ConsumePageMarginRule(id, stream);
  } else {
    DCHECK_LE(allowed_rules, kRegularRules);

    switch (id) {
      case CSSAtRuleID::kCSSAtRuleViewTransition:
        return ConsumeViewTransitionRule(stream);
      case CSSAtRuleID::kCSSAtRuleContainer:
        return ConsumeContainerRule(stream, nesting_type,
                                    parent_rule_for_nesting, is_within_scope);
      case CSSAtRuleID::kCSSAtRuleMedia:
        return ConsumeMediaRule(stream, nesting_type, parent_rule_for_nesting,
                                is_within_scope);
      case CSSAtRuleID::kCSSAtRuleSupports:
        return ConsumeSupportsRule(stream, nesting_type,
                                   parent_rule_for_nesting, is_within_scope);
      case CSSAtRuleID::kCSSAtRuleStartingStyle:
        return ConsumeStartingStyleRule(
            stream, nesting_type, parent_rule_for_nesting, is_within_scope);
      case CSSAtRuleID::kCSSAtRuleFontFace:
        return ConsumeFontFaceRule(stream);
      case CSSAtRuleID::kCSSAtRuleFontPaletteValues:
        return ConsumeFontPaletteValuesRule(stream);
      case CSSAtRuleID::kCSSAtRuleFontFeatureValues:
        return ConsumeFontFeatureValuesRule(stream);
      case CSSAtRuleID::kCSSAtRuleWebkitKeyframes:
        return ConsumeKeyframesRule(true, stream);
      case CSSAtRuleID::kCSSAtRuleKeyframes:
        return ConsumeKeyframesRule(false, stream);
      case CSSAtRuleID::kCSSAtRuleLayer:
        return ConsumeLayerRule(stream, nesting_type, parent_rule_for_nesting,
                                is_within_scope);
      case CSSAtRuleID::kCSSAtRulePage:
        return ConsumePageRule(stream);
      case CSSAtRuleID::kCSSAtRuleProperty:
        return ConsumePropertyRule(stream);
      case CSSAtRuleID::kCSSAtRuleScope:
        return ConsumeScopeRule(stream, nesting_type, parent_rule_for_nesting,
                                is_within_scope);
      case CSSAtRuleID::kCSSAtRuleCounterStyle:
        return ConsumeCounterStyleRule(stream);
      case CSSAtRuleID::kCSSAtRuleFunction:
        return ConsumeFunctionRule(stream);
      case CSSAtRuleID::kCSSAtRuleMixin:
        return ConsumeMixinRule(stream);
      case CSSAtRuleID::kCSSAtRuleApplyMixin:
        return ConsumeApplyMixinRule(stream);
      case CSSAtRuleID::kCSSAtRulePositionTry:
        return ConsumePositionTryRule(stream);
      case CSSAtRuleID::kCSSAtRuleInvalid:
      case CSSAtRuleID::kCSSAtRuleCharset:
      case CSSAtRuleID::kCSSAtRuleImport:
      case CSSAtRuleID::kCSSAtRuleNamespace:
      case CSSAtRuleID::kCSSAtRuleStylistic:
      case CSSAtRuleID::kCSSAtRuleStyleset:
      case CSSAtRuleID::kCSSAtRuleCharacterVariant:
      case CSSAtRuleID::kCSSAtRuleSwash:
      case CSSAtRuleID::kCSSAtRuleOrnaments:
      case CSSAtRuleID::kCSSAtRuleAnnotation:
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
        ConsumeErroneousAtRule(stream, id);
        return nullptr;  // Parse error, unrecognised or not-allowed at-rule
    }
  }
}

StyleRuleBase* CSSParserImpl::ConsumeQualifiedRule(
    CSSParserTokenStream& stream,
    AllowedRulesType allowed_rules,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope) {
  if (allowed_rules <= kRegularRules) {
    bool invalid_rule_error_ignored = false;  // Only relevant when nested.
    return ConsumeStyleRule(stream, nesting_type, parent_rule_for_nesting,
                            is_within_scope,
                            /* nested */ false, invalid_rule_error_ignored);
  }

  if (allowed_rules == kKeyframeRules) {
    stream.EnsureLookAhead();
    const wtf_size_t prelude_offset_start = stream.LookAheadOffset();
    std::unique_ptr<Vector<KeyframeOffset>> key_list =
        ConsumeKeyframeKeyList(context_, stream);
    stream.ConsumeWhitespace();
    const RangeOffset prelude_offset(prelude_offset_start,
                                     stream.LookAheadOffset());

    if (stream.Peek().GetType() != kLeftBraceToken) {
      key_list = nullptr;  // Parse error, junk after prelude
      stream.SkipUntilPeekedTypeIs<kLeftBraceToken>();
    }
    if (stream.AtEnd()) {
      return nullptr;  // Parse error, EOF instead of qualified rule block
    }

    CSSParserTokenStream::BlockGuard guard(stream);
    return ConsumeKeyframeStyleRule(std::move(key_list), prelude_offset,
                                    stream);
  }
  if (allowed_rules == kFontFeatureRules) {
    // We get here if something other than an at rule (e.g. @swash,
    // @ornaments... ) was found within @font-feature-values. As we don't
    // support font-display in @font-feature-values, we try to it by scanning
    // until the at-rule or until the block may end. Compare
    // https://drafts.csswg.org/css-fonts-4/#ex-invalid-ignored
    stream.EnsureLookAhead();
    stream.SkipUntilPeekedTypeIs<kAtKeywordToken>();
    return nullptr;
  }

  NOTREACHED();
}

StyleRulePageMargin* CSSParserImpl::ConsumePageMarginRule(
    CSSAtRuleID rule_id,
    CSSParserTokenStream& stream) {
  wtf_size_t header_start = stream.LookAheadOffset();
  // NOTE: @page-margin prelude should be empty.
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream, rule_id)) {
    return nullptr;
  }
  wtf_size_t header_end = stream.LookAheadOffset();

  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kPageMargin, header_start);
    observer_->EndRuleHeader(header_end);
    observer_->StartRuleBody(stream.Offset());
  }

  ConsumeBlockContents(stream, StyleRule::kPageMargin, CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       /*child_rules=*/nullptr);

  if (observer_) {
    observer_->EndRuleBody(stream.LookAheadOffset());
  }

  return MakeGarbageCollected<StyleRulePageMargin>(
      rule_id, CreateCSSPropertyValueSet(parsed_properties_, context_->Mode(),
                                         context_->GetDocument()));
}

StyleRuleCharset* CSSParserImpl::ConsumeCharsetRule(
    CSSParserTokenStream& stream) {
  const CSSParserToken& string = stream.Peek();
  if (string.GetType() != kStringToken || !stream.AtEnd()) {
    // Parse error, expected a single string.
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleCharset);
    return nullptr;
  }
  stream.ConsumeIncludingWhitespace();
  if (!ConsumeEndOfPreludeForAtRuleWithoutBlock(
          stream, CSSAtRuleID::kCSSAtRuleCharset)) {
    return nullptr;
  }

  return MakeGarbageCollected<StyleRuleCharset>();
}

StyleRuleImport* CSSParserImpl::ConsumeImportRule(
    const AtomicString& uri,
    CSSParserTokenStream& stream) {
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();

  if (uri.IsNull()) {
    // Parse error, expected string or URI.
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleImport);
    return nullptr;
  }

  StyleRuleBase::LayerName layer;
  if (stream.Peek().GetType() == kIdentToken &&
      stream.Peek().Id() == CSSValueID::kLayer) {
    stream.ConsumeIncludingWhitespace();
    layer = StyleRuleBase::LayerName({g_empty_atom});
  } else if (stream.Peek().GetType() == kFunctionToken &&
             stream.Peek().FunctionId() == CSSValueID::kLayer) {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();
    StyleRuleBase::LayerName name = ConsumeCascadeLayerName(stream);
    if (name.size() && stream.AtEnd()) {
      layer = std::move(name);
      guard.Release();
    } else {
      // Invalid layer() function can still be parsed as <general-enclosed>
    }
  }
  if (layer.size()) {
    context_->Count(WebFeature::kCSSCascadeLayers);
  }

  stream.ConsumeWhitespace();

  // https://drafts.csswg.org/css-cascade-5/#at-import
  //
  // <import-conditions> =
  //     [ supports([ <supports-condition> | <declaration> ]) ]?
  //     <media-query-list>?
  StringView supports_string = g_null_atom;
  CSSSupportsParser::Result supported = CSSSupportsParser::Result::kSupported;
  if (RuntimeEnabledFeatures::CSSSupportsForImportRulesEnabled() &&
      stream.Peek().GetType() == kFunctionToken &&
      stream.Peek().FunctionId() == CSSValueID::kSupports) {
    {
      CSSParserTokenStream::BlockGuard guard(stream);
      stream.ConsumeWhitespace();
      wtf_size_t supports_offset_start = stream.Offset();

      // First, try parsing as <declaration>.
      CSSParserTokenStream::State savepoint = stream.Save();
      if (stream.Peek().GetType() == kIdentToken &&
          CSSParserImpl::ConsumeSupportsDeclaration(stream)) {
        supported = CSSSupportsParser::Result::kSupported;
      } else {
        // Rewind and try parsing as <supports-condition>.
        stream.Restore(savepoint);
        supported = CSSSupportsParser::ConsumeSupportsCondition(stream, *this);
      }
      wtf_size_t supports_offset_end = stream.Offset();
      supports_string = stream.StringRangeAt(
          supports_offset_start, supports_offset_end - supports_offset_start);
    }
    if (supported == CSSSupportsParser::Result::kParseFailure) {
      ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleImport);
      return nullptr;
    }
  }
  stream.ConsumeWhitespace();

  const StyleScope* style_scope = nullptr;
  if (RuntimeEnabledFeatures::CSSScopeImportEnabled() &&
      stream.Peek().FunctionId() == CSSValueID::kScope) {
    {
      CSSParserTokenStream::RestoringBlockGuard guard(stream);
      stream.ConsumeWhitespace();
      style_scope = StyleScope::Parse(stream, context_, CSSNestingType::kNone,
                                      /*parent_rule_for_nesting=*/nullptr,
                                      /*is_within_scope=*/false, style_sheet_);
      if (!guard.Release()) {
        style_scope = nullptr;
      }
    }
  }
  stream.ConsumeWhitespace();

  // Parse the rest of the prelude as a media query.
  // TODO(sesse): When the media query parser becomes streaming,
  // we can just parse media queries here instead.
  wtf_size_t media_query_offset_start = stream.Offset();
  stream.SkipUntilPeekedTypeIs<kLeftBraceToken, kSemicolonToken>();
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  StringView media_query_string = stream.StringRangeAt(
      media_query_offset_start, prelude_offset_end - media_query_offset_start);

  MediaQuerySet* media_query_set = MediaQueryParser::ParseMediaQuerySet(
      media_query_string.ToString(), context_->GetExecutionContext());

  if (!ConsumeEndOfPreludeForAtRuleWithoutBlock(
          stream, CSSAtRuleID::kCSSAtRuleImport)) {
    return nullptr;
  }

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kImport, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(prelude_offset_end);
    observer_->EndRuleBody(prelude_offset_end);
  }

  return MakeGarbageCollected<StyleRuleImport>(
      uri, std::move(layer), style_scope,
      supported == CSSSupportsParser::Result::kSupported,
      supports_string.ToString(), media_query_set,
      context_->IsOriginClean() ? OriginClean::kTrue : OriginClean::kFalse);
}

StyleRuleNamespace* CSSParserImpl::ConsumeNamespaceRule(
    CSSParserTokenStream& stream) {
  AtomicString namespace_prefix;
  if (stream.Peek().GetType() == kIdentToken) {
    namespace_prefix =
        stream.ConsumeIncludingWhitespace().Value().ToAtomicString();
  }

  AtomicString uri(ConsumeStringOrURI(stream));
  if (uri.IsNull()) {
    // Parse error, expected string or URI.
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleNamespace);
    return nullptr;
  }
  if (!ConsumeEndOfPreludeForAtRuleWithoutBlock(
          stream, CSSAtRuleID::kCSSAtRuleNamespace)) {
    return nullptr;
  }

  return MakeGarbageCollected<StyleRuleNamespace>(namespace_prefix, uri);
}

StyleRule* CSSParserImpl::CreateImplicitNestedRule(
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting) {
  DCHECK(!RuntimeEnabledFeatures::CSSNestedDeclarationsEnabled());

  constexpr bool kNotImplicit =
      false;  // The rule is implicit, but the &/:scope is not.

  CHECK(nesting_type == CSSNestingType::kNesting ||
        nesting_type == CSSNestingType::kScope);
  CSSSelector selector =
      (nesting_type == CSSNestingType::kNesting)
          ? CSSSelector(parent_rule_for_nesting, kNotImplicit)
          : CSSSelector(AtomicString("scope"), kNotImplicit);
  selector.SetLastInComplexSelector(true);
  selector.SetLastInSelectorList(true);
  selector.SetScopeContaining(true);

  return StyleRule::Create(
      base::span<CSSSelector>(&selector, 1u),
      CreateCSSPropertyValueSet(parsed_properties_, context_->Mode(),
                                context_->GetDocument()));
}

namespace {

// Returns a :where(:scope) selector.
//
// Nested declaration rules within @scope behave as :where(:scope) rules.
//
// https://github.com/w3c/csswg-drafts/issues/10431
HeapVector<CSSSelector> WhereScopeSelector() {
  HeapVector<CSSSelector> selectors;

  CSSSelector inner[1] = {
      CSSSelector(AtomicString("scope"), /* implicit */ false)};
  inner[0].SetLastInComplexSelector(true);
  inner[0].SetLastInSelectorList(true);
  CSSSelectorList* inner_list =
      CSSSelectorList::AdoptSelectorVector(base::span<CSSSelector>(inner));

  CSSSelector where;
  where.SetWhere(inner_list);
  where.SetScopeContaining(true);
  selectors.push_back(where);

  selectors.back().SetLastInComplexSelector(true);
  selectors.back().SetLastInSelectorList(true);

  return selectors;
}

}  // namespace

StyleRuleNestedDeclarations* CSSParserImpl::CreateNestedDeclarationsRule(
    CSSNestingType nesting_type,
    const CSSSelector* selector_list,
    wtf_size_t start_index,
    wtf_size_t end_index) {
  DCHECK(RuntimeEnabledFeatures::CSSNestedDeclarationsEnabled());
  DCHECK(selector_list || (nesting_type != CSSNestingType::kNesting));
  DCHECK_LE(start_index, end_index);

  // Create a nested declarations rule containing all declarations
  // in [start_index, end_index).
  HeapVector<CSSPropertyValue, 64> declarations;
  declarations.AppendRange(parsed_properties_.begin() + start_index,
                           parsed_properties_.begin() + end_index);

  // Create the selector for StyleRuleNestedDeclarations's inner StyleRule.

  HeapVector<CSSSelector> selectors;

  switch (nesting_type) {
    case CSSNestingType::kNone:
      NOTREACHED();
    case CSSNestingType::kNesting:
      // For regular nesting, the nested declarations rule should match
      // exactly what the parent rule matches, with top-level specificity
      // behavior. This means the selector list is copied rather than just
      // being referenced with '&'.
      selectors = CSSSelectorList::Copy(selector_list);
      break;
    case CSSNestingType::kScope:
      // For direct nesting within @scope
      // (e.g. .foo { @scope (...) { color:green } }),
      // the nested declarations rule should match like a :where(:scope) rule.
      //
      // https://github.com/w3c/csswg-drafts/issues/10431
      selectors = WhereScopeSelector();
      break;
  }

  return MakeGarbageCollected<StyleRuleNestedDeclarations>(StyleRule::Create(
      base::span<CSSSelector>{selectors.begin(), selectors.size()},
      CreateCSSPropertyValueSet(declarations, context_->Mode(),
                                context_->GetDocument())));
}

void CSSParserImpl::EmitNestedDeclarationsRuleIfNeeded(
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    wtf_size_t start_index,
    HeapVector<Member<StyleRuleBase>, 4>& child_rules) {
  if (!RuntimeEnabledFeatures::CSSNestedDeclarationsEnabled()) {
    return;
  }
  if (!parent_rule_for_nesting && nesting_type != CSSNestingType::kScope) {
    // This can happen for @page, which behaves similarly to CSS Nesting
    // (and cares about child rules), but doesn't have a parent style rule.
    //
    // Note that CSSNestedDeclarations emitted under CSSNestingType::kScope
    // do not reference the parent selector (see CreateNestedDeclarationsRule).
    return;
  }
  wtf_size_t end_index = parsed_properties_.size();
  if (start_index == kNotFound) {
    return;
  }
  // The spec only allows creating non-empty rules, however, the inspector needs
  // empty rules to appear as well. This has no effect on the styles seen by
  // the page (the styles parsed with an `observer_` are for local use in the
  // inspector only).
  const bool emit_empty_rule = observer_;
  if (start_index >= end_index && !emit_empty_rule) {
    return;
  }

  StyleRuleNestedDeclarations* nested_declarations_rule =
      CreateNestedDeclarationsRule(
          nesting_type,
          parent_rule_for_nesting ? parent_rule_for_nesting->FirstSelector()
                                  : nullptr,
          start_index, end_index);
  DCHECK(nested_declarations_rule);
  child_rules.push_back(nested_declarations_rule);

  if (observer_) {
    observer_->ObserveNestedDeclarations(
        /* insert_rule_index */ child_rules.size() - 1);
  }

  // The declarations held by the nested declarations rule
  // should not *also* appear in the main style declarations of the parent rule.
  parsed_properties_.resize(start_index);
}

StyleRuleMedia* CSSParserImpl::ConsumeMediaRule(
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope) {
  // Consume the prelude.

  // First just get the string for the prelude to see if we've got a cached
  // version of this. (This is mainly to save memory in certain page with
  // lots of duplicate media queries.)
  CSSParserTokenStream::State savepoint = stream.Save();
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  stream.SkipUntilPeekedTypeIs<kLeftBraceToken, kSemicolonToken>();
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();

  String prelude_string =
      stream
          .StringRangeAt(prelude_offset_start,
                         prelude_offset_end - prelude_offset_start)
          .ToString();
  const MediaQuerySet* media;
  Member<const MediaQuerySet>& cached_media =
      media_query_cache_.insert(prelude_string, nullptr).stored_value->value;
  if (cached_media) {
    media = cached_media.Get();
  } else {
    // Not in the cache, so we'll have to rewind and actually parse it.
    // Note that the media query set grammar doesn't really have an idea
    // of when the stream should end; if it sees something it doesn't
    // understand (which includes a left brace), it will just forward to
    // the next comma, skipping over the entire stylesheet until the end.
    // The grammar is generally written in the understanding that the prelude
    // is extracted as a string and only then parsed, whereas we do fully
    // streaming prelude parsing. Thus, we need to set some boundaries
    // here ourselves to make sure we end when the prelude does; the alternative
    // would be to teach the media query set parser to stop there itself.
    stream.Restore(savepoint);
    CSSParserTokenStream::Boundary boundary(stream, kLeftBraceToken);
    CSSParserTokenStream::Boundary boundary2(stream, kSemicolonToken);
    media = MediaQueryParser::ParseMediaQuerySet(
        stream, context_->GetExecutionContext());
  }
  DCHECK(media);

  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream,
                                             CSSAtRuleID::kCSSAtRuleMedia)) {
    return nullptr;
  }

  cached_media = media;

  // Consume the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kMedia, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  if (style_sheet_) {
    style_sheet_->SetHasMediaQueries();
  }

  HeapVector<Member<StyleRuleBase>, 4> rules;
  ConsumeRuleListOrNestedDeclarationList(
      stream,
      /* is_nested_group_rule */ nesting_type == CSSNestingType::kNesting,
      nesting_type, parent_rule_for_nesting, is_within_scope, &rules);

  if (observer_) {
    observer_->EndRuleBody(stream.Offset());
  }

  // NOTE: There will be a copy of rules here, to deal with the different inline
  // size.
  return MakeGarbageCollected<StyleRuleMedia>(media, std::move(rules));
}

StyleRuleSupports* CSSParserImpl::ConsumeSupportsRule(
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope) {
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  CSSSupportsParser::Result supported =
      CSSSupportsParser::ConsumeSupportsCondition(stream, *this);
  if (supported == CSSSupportsParser::Result::kParseFailure) {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleSupports);
    return nullptr;
  }
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream,
                                             CSSAtRuleID::kCSSAtRuleSupports)) {
    return nullptr;
  }
  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kSupports, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  const auto prelude_serialized =
      stream
          .StringRangeAt(prelude_offset_start,
                         prelude_offset_end - prelude_offset_start)
          .ToString()
          .SimplifyWhiteSpace();

  HeapVector<Member<StyleRuleBase>, 4> rules;
  ConsumeRuleListOrNestedDeclarationList(
      stream,
      /* is_nested_group_rule */ nesting_type == CSSNestingType::kNesting,
      nesting_type, parent_rule_for_nesting, is_within_scope, &rules);

  if (observer_) {
    observer_->EndRuleBody(stream.Offset());
  }

  // NOTE: There will be a copy of rules here, to deal with the different inline
  // size.
  return MakeGarbageCollected<StyleRuleSupports>(
      prelude_serialized, supported == CSSSupportsParser::Result::kSupported,
      std::move(rules));
}

StyleRuleStartingStyle* CSSParserImpl::ConsumeStartingStyleRule(
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope) {
  // NOTE: @starting-style prelude should be empty.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(
          stream, CSSAtRuleID::kCSSAtRuleStartingStyle)) {
    return nullptr;
  }
  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kStartingStyle, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  HeapVector<Member<StyleRuleBase>, 4> rules;
  ConsumeRuleListOrNestedDeclarationList(
      stream,
      /* is_nested_group_rule */ nesting_type == CSSNestingType::kNesting,
      nesting_type, parent_rule_for_nesting, is_within_scope, &rules);

  if (observer_) {
    observer_->EndRuleBody(stream.Offset());
  }

  // NOTE: There will be a copy of rules here, to deal with the different inline
  // size.
  return MakeGarbageCollected<StyleRuleStartingStyle>(std::move(rules));
}

StyleRuleFontFace* CSSParserImpl::ConsumeFontFaceRule(
    CSSParserTokenStream& stream) {
  // Consume the prelude.
  // NOTE: @font-face prelude should be empty.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(stream,
                                             CSSAtRuleID::kCSSAtRuleFontFace)) {
    return nullptr;
  }

  // Consume the actual block.
  CSSParserTokenStream::BlockGuard guard(stream);
  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kFontFace, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    // TODO(sesse): Is this really right?
    observer_->StartRuleBody(prelude_offset_end);
    observer_->EndRuleBody(prelude_offset_end);
  }

  if (style_sheet_) {
    style_sheet_->SetHasFontFaceRule();
  }

  base::AutoReset<CSSParserObserver*> disable_observer(&observer_, nullptr);
  ConsumeBlockContents(stream, StyleRule::kFontFace, CSSNestingType::kNone,
                       /*parent_rule_for_nesting=*/nullptr,
                       /*is_within_scope=*/false,
                       /*nested_declarations_start_index=*/kNotFound,
                       /*child_rules=*/nullptr);

  return MakeGarbageCollected<StyleRuleFontFace>(CreateCSSPropertyValueSet(
      parsed_properties_, kCSSFontFaceRuleMode, context_->GetDocument()));
}

StyleRuleKeyframes* CSSParserImpl::ConsumeKeyframesRule(
    bool webkit_prefixed,
    CSSParserTokenStream& stream) {
  // Parse the prelude, expecting a single non-whitespace token.
  wtf_size_t prelude_offset_start = stream.LookAheadOffset();
  const CSSParserToken& name_token = stream.Peek();
  String name;
  if (name_token.GetType() == kIdentToken) {
    name = name_token.Value().ToString();
  } else if (name_token.GetType() == kStringToken && webkit_prefixed) {
    context_->Count(WebFeature::kQuotedKeyframesRule);
    name = name_token.Value().ToString();
  } else {
    ConsumeErroneousAtRule(stream, CSSAtRuleID::kCSSAtRuleKeyframes);
    return nullptr;  // Parse error; expected ident token in @keyframes header
  }
  stream.ConsumeIncludingWhitespace();
  wtf_size_t prelude_offset_end = stream.LookAheadOffset();
  if (!ConsumeEndOfPreludeForAtRuleWithBlock(
          stream, CSSAtRuleID::kCSSAtRuleKeyframes)) {
    return nullptr;
  }

  // Parse the body.
  CSSParserTokenStream::BlockGuard guard(stream);

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kKeyframes, prelude_offset_start);
    observer_->EndRuleHeader(prelude_offset_end);
    observer_->StartRuleBody(stream.Offset());
  }

  auto* keyframe_rule = MakeGarbageCollected<StyleRuleKeyframes>();
  ConsumeRuleList(
      stream, kKeyframesRuleList, CSSNestingType::kNone,
      /*parent_rule_for_nesting=*/nullptr,
      /*is_within_scope=*/false,
      [keyframe_rule](StyleRuleBase* keyframe, wtf_size_t) {
        keyframe_rule->ParserAppendKeyframe(To<StyleRuleKeyframe>(keyframe));
      });
  keyframe_rule->SetName(name);
  keyframe_rule->SetVendorPrefixed(webkit_prefixed);

  if (observer_) {
    observer_->EndRuleBody(stream.Offset());
  }

  return keyframe_rule;
}

StyleRuleFontFeature* CSSParserImpl::ConsumeFontFeatureRule(
    CSSAtRuleID rule_id,
    CSSParserTokenStream& stream) {
  std::optional<StyleRuleFontFeature::FeatureType> feature_type =
      ToStyleRuleFontFeatureType(rule_id);
  if (!feature_type) {
    return nullptr;
  }

  wtf_size_t max_allowed_values = 1;
  if (feature_type == StyleRuleFontFeature::FeatureType::kCharacterVariant) {
    max_allowed_values = 2;
  }
  if (feature_type == StyleRuleFontFeature::FeatureType::kStyleset) {
    max_allowed_values = std::numeric_limits<wtf_size_t>::max();
  }

  stream.ConsumeWhitespace();

  if (stream.Peek().GetType() != kLeftBraceToken) {
    return nullptr;
  }

  CSSParserTokenStream::BlockGuard guard(stream);
  stream.ConsumeWhitespace();

  auto* font_feature_rule =
      MakeGarbageCollected<StyleRuleFontFeature>(*feature_type);

  while (!stream.AtEnd()) {
    const CSSParserToken& alias_token = stream.Peek();

    if (alias_token.GetType() != kIdentToken) {
      return nullptr;
    }
    AtomicString alias =
        stream.ConsumeIncludingWhitespace().Value().ToAtomicString();

    const CSSParserToken& colon_token = stream.Peek();

    if (colon_token.GetType() != kColonToken) {
      return nullptr;
    }

    stream.UncheckedConsume();
    stream.ConsumeWhitespace();

    CSSValueList* numbers = CSSValueList::CreateSpaceSeparated();

    stream.ConsumeWhitespace();

    do {
      if (numbers->length() == max_allowed_values) {
        return nullptr;
      }
      CSSPrimitiveValue* parsed_number =
          css_parsing_utils::ConsumeIntegerOrNumberCalc(
              stream, *context_,
              CSSPrimitiveValue::ValueRange::kNonNegativeInteger);
      if (!parsed_number) {
        return nullptr;
      }
      numbers->Append(*parsed_number);
    } while (stream.Peek().GetType() != kSemicolonToken && !stream.AtEnd());

    if (!stream.AtEnd()) {
      stream.ConsumeIncludingWhitespace();  // kSemicolonToken
    }

    if (!numbers->length()) {
      return nullptr;
    }

    Vector<uint32_t> parsed_numbers;
    for (auto value : *numbers) {
      const CSSPrimitiveValue* number_value =
          DynamicTo<CSSPrimitiveValue>(*value);
      if (!number_value) {
        return nullptr;
      }
      parsed_numbers.push_back(number_value->GetIntValue());
    }

    const CSSParserToken& expected_semicolon = stream.Peek();
    if (expected_semicolon.GetType() == kSemicolonToken) {
      stream.UncheckedConsume();
    }
    stream.ConsumeWh
```