Response:
The user wants a summary of the functionality of the provided C++ code file, `inspector_style_sheet.cc`, within the Chromium Blink rendering engine. The summary should specifically address its relationship to JavaScript, HTML, and CSS, including illustrative examples. Logical inferences should be accompanied by hypothetical input and output scenarios. Common user or programming errors related to the code should be highlighted with examples. This is the final part of a three-part request, so the summary should integrate and conclude the understanding of the file's purpose.

Here's a plan to address this:

1. **Identify Core Functionality:**  Analyze the methods and data structures to determine the primary responsibilities of the `InspectorStyleSheet` class.
2. **Relate to Web Technologies:**  Connect the identified functionalities to how they interact with JavaScript, HTML, and CSS within a browser context. Provide concrete examples.
3. **Logical Reasoning and Scenarios:** For key logical operations, construct hypothetical inputs and predict the corresponding outputs.
4. **Common Errors:** Based on the code, identify potential pitfalls for users or developers interacting with this functionality (even indirectly through DevTools).
5. **Synthesize a Comprehensive Summary:** Integrate the findings from the previous steps into a concise and informative summary, keeping in mind this is the final part of the request.
好的，这是 `blink/renderer/core/inspector/inspector_style_sheet.cc` 文件的功能归纳，并结合 JavaScript、HTML 和 CSS 进行说明：

**功能归纳：**

`InspectorStyleSheet.cc` 文件的主要职责是**为 Chrome DevTools 提供 CSS 样式表信息的抽象和访问接口**。它充当 Blink 渲染引擎中 CSS 样式表与其在开发者工具中的表示之间的桥梁。该文件负责：

1. **构建 CSS 样式表的元数据对象：**  将 Blink 内部的 `CSSStyleSheet` 对象的信息转换为 DevTools 协议中定义的 `CSSStyleSheetHeader` 对象。这包括样式表的 ID、来源（例如，作者样式、用户代理样式）、是否禁用、URL、标题、所属的 Frame、是否是内联样式或通过 JavaScript 构建、起始和结束位置、以及可能的 SourceMap URL 等信息。

2. **提取和组织 CSS 规则信息：**  解析 CSS 样式表中的各个 CSS 规则（例如 `CSSStyleRule`, `CSSMediaRule`, `CSSKeyframeRule` 等），并将这些规则的信息构建成 DevTools 协议中的 `CSSRule` 对象。这包括选择器列表、样式声明、来源等。

3. **处理选择器信息：**  解析 CSS 规则的选择器，并提供更详细的选择器信息，如特异性（specificity）和在源代码中的位置范围。

4. **提供样式声明信息：**  将 CSS 规则中的样式声明（属性和值）转换为 DevTools 协议中的 `CSSStyle` 对象，并提供每个属性的来源信息（例如，来自哪个样式表）。

5. **支持源代码映射（Source Maps）：**  处理 CSS 样式表关联的 Source Map 文件，以便在 DevTools 中可以将转换后的 CSS 代码映射回原始的源代码。

6. **处理不同类型的样式表：**  区分和处理不同来源的样式表，例如常规的 CSS 文件、内联样式、通过 JavaScript 构建的样式表以及用户代理样式表等。

7. **提供样式表文本内容：**  允许 DevTools 获取样式表的完整文本内容。

8. **跟踪样式规则的使用情况：**  支持 DevTools 跟踪哪些 CSS 规则被实际应用到页面元素上。

9. **支持动态修改：**  允许 DevTools 修改样式表的文本内容和内联样式。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:**
    * **构建样式表 (`isConstructed`)：** 当 JavaScript 使用 `new CSSStyleSheet()` 或导入 CSS 模块时，`InspectorStyleSheet` 可以识别并标记这些通过 JavaScript 构建的样式表。
        * **假设输入：**  JavaScript 代码 `const sheet = new CSSStyleSheet(); document.adoptedStyleSheets = [sheet];`
        * **输出：** `BuildObjectForStyleSheetInfo` 方法会设置 `isConstructed` 为 `true`。
    * **SourceURL：**  对于通过 JavaScript 动态创建的样式，`InspectorStyleSheet` 可以尝试从样式表文本中的 `/*# sourceURL=... */` 注释中提取源代码 URL。
        * **假设输入：** JavaScript 创建的样式表文本包含 `/*# sourceURL=my-dynamic-styles.js */`。
        * **输出：** `SourceURL()` 方法会返回 `"my-dynamic-styles.js"`。

* **HTML:**
    * **内联样式 (`isInline`)：** 当样式直接写在 HTML 元素的 `style` 属性中时，`InspectorStyleSheet` 可以识别并标记为内联样式。
        * **假设输入：** HTML 代码 `<div style="color: red;"></div>`
        * **输出：**  针对该内联样式创建的 `InspectorStyleSheet` 对象的 `BuildObjectForStyleSheetInfo` 方法会设置 `isInline` 为 `true`。
    * **`<style>` 标签：**  对于 HTML 中的 `<style>` 标签，`InspectorStyleSheet` 会解析其内容并提供样式规则信息。
        * **假设输入：** HTML 代码 `<style> body { margin: 0; } </style>`
        * **输出：** `BuildObjectForRuleWithoutAncestorData` 会为 `body { margin: 0; }` 创建一个 `CSSRule` 对象。

* **CSS:**
    * **解析 CSS 规则和选择器：**  `InspectorStyleSheet` 负责解析 CSS 样式表中的规则（例如，选择器、属性和值），并将其转换为 DevTools 可以理解的结构。
        * **假设输入：** CSS 规则 `.container > p { font-size: 16px; }`
        * **输出：** `BuildObjectForSelectorList` 会解析出选择器 `.container > p`，并提供其文本表示和特异性信息。
    * **Source Maps (`sourceMapURL`)：**  如果 CSS 文件中包含指向 Source Map 文件的注释 (`/*# sourceMappingURL=... */`)，`InspectorStyleSheet` 会提取该 URL。
        * **假设输入：** CSS 文件末尾包含 `/*# sourceMappingURL=styles.css.map */`
        * **输出：** `SourceMapURL()` 方法会返回 `"styles.css.map"`。

**逻辑推理的假设输入与输出：**

* **场景：计算文本位置**
    * **假设输入：**
        * `offset` (字符偏移量): 15
        * `line_endings` (行尾偏移量数组): `{5, 10, 20}` (表示第一行结束于偏移量 5，第二行结束于 10，第三行结束于 20)
        * `start_position` (起始位置): `line: 1, column: 5` (假设文本不是从文件开头开始的)
    * **逻辑：** `TextPositionFromOffsetAndLineEndingsRelativeToStartPosition` 函数会计算相对于 `start_position` 的文本位置。首先根据 `offset` 和 `line_endings` 找到绝对位置 (第 3 行，第 6 列)。然后由于 `start_position` 的列不为零，且计算出的行是第一行，需要加上 `start_position` 的列偏移量。
    * **输出：** `TextPosition(line: 3, column: 6 + 5 = 11)`

* **场景：判断是否需要加载样式表文本**
    * **假设输入：** `origin_` 为 `protocol::CSS::StyleSheetOriginEnum::Regular`，并且样式表有一个外部 URL (`page_style_sheet_->href()` 返回一个非空字符串)。
    * **逻辑：** `UpdateText()` 方法会检查 `origin_`，并判断是否是常规样式表。然后会检查是否有外部 URL。
    * **输出：** `ResourceStyleSheetText()` 方法会被调用，尝试从网络加载样式表的内容。

**涉及用户或者编程常见的使用错误举例说明：**

* **Source Map URL 错误：**  开发者在 CSS 文件中提供了错误的 Source Map URL，例如文件路径错误或文件名拼写错误。
    * **后果：**  DevTools 无法加载 Source Map 文件，导致在 Elements 面板的 Styles 标签中无法将样式规则映射回原始的 Sass、Less 或其他预处理器源代码，影响调试体验。
* **修改内联样式时语法错误：**  用户通过 DevTools 修改元素的内联样式时，输入了无效的 CSS 语法。
    * **后果：** `SetText` 方法中的 `VerifyStyleText` 可能会检测到语法错误，并抛出 `DOMException`，导致修改失败。
* **假设样式表文本总是可用：**  在某些情况下，例如网络请求失败或跨域问题，样式表的文本内容可能无法获取。开发者如果假设 `GetText()` 总是返回 `true` 并直接使用返回的字符串，可能会导致程序错误或崩溃。
    * **正确做法：**  在调用 `GetText()` 后应该检查返回值，以确保成功获取了样式表文本。

**总结 `InspectorStyleSheet.cc` 的功能:**

总而言之，`InspectorStyleSheet.cc` 是 Blink 渲染引擎中一个至关重要的组件，它专注于将内部的 CSS 样式表信息以结构化的、符合 DevTools 协议的方式暴露出来。它处理了各种类型和来源的样式表，并支持诸如源代码映射和动态修改等高级特性。理解 `InspectorStyleSheet.cc` 的功能有助于理解 Chrome DevTools 是如何与渲染引擎交互，并为开发者提供强大的样式调试和检查能力的。这个文件在幕后做了大量的工作，使得开发者能够方便地查看、编辑和理解网页的样式。

Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_style_sheet.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
on& start_position) {
  TextPosition position =
      TextPosition::FromOffsetAndLineEndings(offset, line_endings);
  unsigned column = position.column_.ZeroBasedInt();
  // A non-zero `start_position.column_` means that the text started in the
  // middle of a line, so the start column position must be added if `offset`
  // translates to a `position` in the first line of the text.
  if (position.line_.ZeroBasedInt() == 0) {
    column += start_position.column_.ZeroBasedInt();
  }
  unsigned line_index =
      start_position.line_.ZeroBasedInt() + position.line_.ZeroBasedInt();
  return TextPosition(OrdinalNumber::FromZeroBasedInt(line_index),
                      OrdinalNumber::FromZeroBasedInt(column));
}

}  // namespace

std::unique_ptr<protocol::CSS::CSSStyleSheetHeader>
InspectorStyleSheet::BuildObjectForStyleSheetInfo() {
  CSSStyleSheet* style_sheet = PageStyleSheet();
  if (!style_sheet)
    return nullptr;

  Document* document = style_sheet->OwnerDocument();
  LocalFrame* frame = document ? document->GetFrame() : nullptr;
  const LineEndings* line_endings = GetLineEndings();
  TextPosition start = style_sheet->StartPositionInSource();
  TextPosition end = start;
  unsigned text_length = 0;
  if (line_endings->size() > 0) {
    text_length = line_endings->back();
    end = TextPositionFromOffsetAndLineEndingsRelativeToStartPosition(
        text_length, *line_endings, start);
  }

  // DevTools needs to be able to distinguish between constructed
  // stylesheets created with `new` and constructed stylesheets
  // imported as a CSS module. Only the latter have a separate
  // source file to display.
  // For constructed stylesheets created with `new`, Url()
  // returns the URL of the document in which the sheet was created,
  // which may confuse the client. Only set the URL if we have a
  // proper URL of the source of the stylesheet.
  const String& source_url =
      (style_sheet->IsConstructed() && !style_sheet->IsForCSSModuleScript())
          ? SourceURL()
          : Url();

  std::unique_ptr<protocol::CSS::CSSStyleSheetHeader> result =
      protocol::CSS::CSSStyleSheetHeader::create()
          .setStyleSheetId(Id())
          .setOrigin(origin_)
          .setDisabled(style_sheet->disabled())
          .setSourceURL(source_url)
          .setTitle(style_sheet->title())
          .setFrameId(frame ? IdentifiersFactory::FrameId(frame) : "")
          .setIsInline(style_sheet->IsInline() && !StartsAtZero())
          .setIsConstructed(style_sheet->IsConstructed())
          .setIsMutable(style_sheet->Contents()->IsMutable())
          .setStartLine(start.line_.ZeroBasedInt())
          .setStartColumn(start.column_.ZeroBasedInt())
          .setLength(text_length)
          .setEndLine(end.line_.ZeroBasedInt())
          .setEndColumn(end.column_.ZeroBasedInt())
          .build();

  if (HasSourceURL())
    result->setHasSourceURL(true);

  if (request_failed_to_load_.has_value()) {
    result->setLoadingFailed(*request_failed_to_load_);
  }

  if (style_sheet->ownerNode()) {
    result->setOwnerNode(
        IdentifiersFactory::IntIdForNode(style_sheet->ownerNode()));
  }

  String source_map_url_value = SourceMapURL();
  if (!source_map_url_value.empty())
    result->setSourceMapURL(source_map_url_value);
  return result;
}

std::unique_ptr<protocol::Array<protocol::CSS::Value>>
InspectorStyleSheet::SelectorsFromSource(CSSRuleSourceData* source_data,
                                         const String& sheet_text,
                                         CSSStyleRule* rule) {
  ScriptRegexp* comment = nullptr;
  if (page_style_sheet_->OwnerDocument()) {
    comment = MakeGarbageCollected<ScriptRegexp>(
        page_style_sheet_->OwnerDocument()->GetAgent().isolate(),
        "/\\*[^]*?\\*/", kTextCaseSensitive, MultilineMode::kMultilineEnabled);
  }
  auto result = std::make_unique<protocol::Array<protocol::CSS::Value>>();
  const Vector<SourceRange>& ranges = source_data->selector_ranges;
  const CSSSelector* obj_selector = rule->GetStyleRule()->FirstSelector();

  for (wtf_size_t i = 0, size = ranges.size(); i < size && obj_selector;
       ++i, obj_selector = CSSSelectorList::Next(*obj_selector)) {
    const SourceRange& range = ranges.at(i);
    String selector = sheet_text.Substring(range.start, range.length());

    if (comment) {
      // We don't want to see any comments in the selector components, only the
      // meaningful parts.
      int match_length;
      int offset = 0;
      while ((offset = comment->Match(selector, offset, &match_length)) >= 0) {
        selector.replace(offset, match_length, "");
      }
    }

    std::unique_ptr<protocol::CSS::Value> simple_selector =
        protocol::CSS::Value::create()
            .setText(selector.StripWhiteSpace())
            .build();
    simple_selector->setRange(BuildSourceRangeObject(range));

    std::array<uint8_t, 3> specificity_tuple = obj_selector->SpecificityTuple();
    simple_selector->setSpecificity(protocol::CSS::Specificity::create()
                                        .setA(specificity_tuple[0])
                                        .setB(specificity_tuple[1])
                                        .setC(specificity_tuple[2])
                                        .build());

    result->emplace_back(std::move(simple_selector));
  }
  return result;
}

std::unique_ptr<protocol::CSS::SelectorList>
InspectorStyleSheet::BuildObjectForSelectorList(CSSStyleRule* rule) {
  CSSRuleSourceData* source_data = SourceDataForRule(rule);
  std::unique_ptr<protocol::Array<protocol::CSS::Value>> selectors;

  // This intentionally does not rely on the source data to avoid catching the
  // trailing comments (before the declaration starting '{').
  String selector_text = rule->selectorText();

  if (source_data) {
    selectors = SelectorsFromSource(source_data, text_, rule);
  } else {
    selectors = std::make_unique<protocol::Array<protocol::CSS::Value>>();
    for (const CSSSelector* selector = rule->GetStyleRule()->FirstSelector();
         selector; selector = CSSSelectorList::Next(*selector)) {
      std::array<uint8_t, 3> specificity_tuple = selector->SpecificityTuple();

      std::unique_ptr<protocol::CSS::Specificity> reworked_specificity =
          protocol::CSS::Specificity::create()
              .setA(specificity_tuple[0])
              .setB(specificity_tuple[1])
              .setC(specificity_tuple[2])
              .build();

      std::unique_ptr<protocol::CSS::Value> simple_selector =
          protocol::CSS::Value::create()
              .setText(selector->SelectorText())
              .setSpecificity(std::move(reworked_specificity))
              .build();

      selectors->emplace_back(std::move(simple_selector));
    }
  }
  return protocol::CSS::SelectorList::create()
      .setSelectors(std::move(selectors))
      .setText(selector_text)
      .build();
}

static bool CanBind(const String& origin) {
  return origin != protocol::CSS::StyleSheetOriginEnum::UserAgent &&
         origin != protocol::CSS::StyleSheetOriginEnum::Injected;
}

std::unique_ptr<protocol::CSS::CSSRule>
InspectorStyleSheet::BuildObjectForRuleWithoutAncestorData(
    CSSStyleRule* rule,
    Element* element,
    PseudoId pseudo_id,
    const AtomicString& pseudo_argument) {
  std::unique_ptr<protocol::CSS::CSSRule> result =
      protocol::CSS::CSSRule::create()
          .setSelectorList(BuildObjectForSelectorList(rule))
          .setOrigin(origin_)
          .setStyle(BuildObjectForStyle(rule->style(), element, pseudo_id,
                                        pseudo_argument))
          .build();

  if (CanBind(origin_)) {
    if (!Id().empty())
      result->setStyleSheetId(Id());
  }

  return result;
}

std::unique_ptr<protocol::CSS::RuleUsage>
InspectorStyleSheet::BuildObjectForRuleUsage(CSSRule* rule, bool was_used) {
  CSSRuleSourceData* source_data = SourceDataForRule(rule);

  if (!source_data)
    return nullptr;

  SourceRange whole_rule_range(source_data->rule_header_range.start,
                               source_data->rule_body_range.end + 1);
  auto type = rule->GetType();
  if (type == CSSRule::kMediaRule || type == CSSRule::kSupportsRule ||
      type == CSSRule::kScopeRule || type == CSSRule::kContainerRule ||
      type == CSSRule::kStartingStyleRule) {
    whole_rule_range.end = source_data->rule_header_range.end + 1;
  }

  std::unique_ptr<protocol::CSS::RuleUsage> result =
      protocol::CSS::RuleUsage::create()
          .setStyleSheetId(Id())
          .setStartOffset(whole_rule_range.start)
          .setEndOffset(whole_rule_range.end)
          .setUsed(was_used)
          .build();

  return result;
}

std::unique_ptr<protocol::CSS::CSSPositionTryRule>
InspectorStyleSheet::BuildObjectForPositionTryRule(
    CSSPositionTryRule* position_try_rule,
    bool active) {
  std::unique_ptr<protocol::CSS::Value> name =
      protocol::CSS::Value::create().setText(position_try_rule->name()).build();
  if (CSSRuleSourceData* source_data = SourceDataForRule(position_try_rule)) {
    name->setRange(BuildSourceRangeObject(source_data->rule_header_range));
  }
  std::unique_ptr<protocol::CSS::CSSPositionTryRule> result =
      protocol::CSS::CSSPositionTryRule::create()
          .setName(std::move(name))
          .setOrigin(origin_)
          .setStyle(BuildObjectForStyle(position_try_rule->style(), nullptr))
          .setActive(active)
          .build();
  if (CanBind(origin_) && !Id().empty()) {
    result->setStyleSheetId(Id());
  }
  return result;
}

std::unique_ptr<protocol::CSS::CSSFontPaletteValuesRule>
InspectorStyleSheet::BuildObjectForFontPaletteValuesRule(
    CSSFontPaletteValuesRule* values_rule) {
  std::unique_ptr<protocol::CSS::Value> name_text =
      protocol::CSS::Value::create().setText(values_rule->name()).build();
  CSSRuleSourceData* source_data = SourceDataForRule(values_rule);
  if (source_data)
    name_text->setRange(BuildSourceRangeObject(source_data->rule_header_range));
  std::unique_ptr<protocol::CSS::CSSFontPaletteValuesRule> result =
      protocol::CSS::CSSFontPaletteValuesRule::create()
          .setFontPaletteName(std::move(name_text))
          .setOrigin(origin_)
          .setStyle(BuildObjectForStyle(values_rule->Style(), nullptr))
          .build();
  if (CanBind(origin_) && !Id().empty())
    result->setStyleSheetId(Id());
  return result;
}

std::unique_ptr<protocol::CSS::CSSPropertyRule>
InspectorStyleSheet::BuildObjectForPropertyRule(
    CSSPropertyRule* property_rule) {
  std::unique_ptr<protocol::CSS::Value> name_text =
      protocol::CSS::Value::create().setText(property_rule->name()).build();
  CSSRuleSourceData* source_data = SourceDataForRule(property_rule);
  if (source_data)
    name_text->setRange(BuildSourceRangeObject(source_data->rule_header_range));
  std::unique_ptr<protocol::CSS::CSSPropertyRule> result =
      protocol::CSS::CSSPropertyRule::create()
          .setPropertyName(std::move(name_text))
          .setOrigin(origin_)
          .setStyle(BuildObjectForStyle(property_rule->Style(), nullptr))
          .build();
  if (CanBind(origin_) && !Id().empty())
    result->setStyleSheetId(Id());
  return result;
}

std::unique_ptr<protocol::CSS::CSSKeyframeRule>
InspectorStyleSheet::BuildObjectForKeyframeRule(CSSKeyframeRule* keyframe_rule,
                                                Element* element) {
  std::unique_ptr<protocol::CSS::Value> key_text =
      protocol::CSS::Value::create().setText(keyframe_rule->keyText()).build();
  CSSRuleSourceData* source_data = SourceDataForRule(keyframe_rule);
  if (source_data)
    key_text->setRange(BuildSourceRangeObject(source_data->rule_header_range));
  std::unique_ptr<protocol::CSS::CSSKeyframeRule> result =
      protocol::CSS::CSSKeyframeRule::create()
          // TODO(samli): keyText() normalises 'from' and 'to' keyword values.
          .setKeyText(std::move(key_text))
          .setOrigin(origin_)
          .setStyle(BuildObjectForStyle(keyframe_rule->style(), element))
          .build();
  if (CanBind(origin_) && !Id().empty())
    result->setStyleSheetId(Id());
  return result;
}

bool InspectorStyleSheet::GetText(String* result) {
  if (source_data_) {
    *result = text_;
    return true;
  }
  return false;
}

std::unique_ptr<protocol::CSS::SourceRange>
InspectorStyleSheet::RuleHeaderSourceRange(CSSRule* rule) {
  if (!source_data_)
    return nullptr;
  CSSRuleSourceData* source_data = SourceDataForRule(rule);
  if (!source_data)
    return nullptr;
  return BuildSourceRangeObject(source_data->rule_header_range);
}

std::unique_ptr<protocol::CSS::SourceRange>
InspectorStyleSheet::MediaQueryExpValueSourceRange(
    CSSRule* rule,
    wtf_size_t media_query_index,
    wtf_size_t media_query_exp_index) {
  if (!source_data_)
    return nullptr;
  CSSRuleSourceData* source_data = SourceDataForRule(rule);
  if (!source_data || !source_data->HasMedia() ||
      media_query_index >= source_data->media_query_exp_value_ranges.size())
    return nullptr;
  const Vector<SourceRange>& media_query_exp_data =
      source_data->media_query_exp_value_ranges[media_query_index];
  if (media_query_exp_index >= media_query_exp_data.size())
    return nullptr;
  return BuildSourceRangeObject(media_query_exp_data[media_query_exp_index]);
}

InspectorStyle* InspectorStyleSheet::GetInspectorStyle(
    CSSStyleDeclaration* style) {
  return style ? MakeGarbageCollected<InspectorStyle>(
                     style, SourceDataForRule(style->parentRule()), this)
               : nullptr;
}

String InspectorStyleSheet::SourceURL() {
  if (!source_url_.IsNull())
    return source_url_;
  if (origin_ != protocol::CSS::StyleSheetOriginEnum::Regular) {
    source_url_ = "";
    return source_url_;
  }

  String style_sheet_text;
  bool success = GetText(&style_sheet_text);
  if (success) {
    String comment_value = FindMagicComment(style_sheet_text, "sourceURL");
    if (!comment_value.empty()) {
      source_url_ = comment_value;
      return comment_value;
    }
  }
  source_url_ = "";
  return source_url_;
}

String InspectorStyleSheet::Url() {
  // "sourceURL" is present only for regular rules, otherwise "origin" should be
  // used in the frontend.
  if (origin_ != protocol::CSS::StyleSheetOriginEnum::Regular)
    return String();

  CSSStyleSheet* style_sheet = PageStyleSheet();
  if (!style_sheet)
    return String();

  if (HasSourceURL())
    return SourceURL();

  if (style_sheet->IsInline() && StartsAtZero())
    return String();

  return FinalURL();
}

bool InspectorStyleSheet::HasSourceURL() {
  return !SourceURL().empty();
}

bool InspectorStyleSheet::StartsAtZero() {
  CSSStyleSheet* style_sheet = PageStyleSheet();
  if (!style_sheet)
    return true;

  return style_sheet->StartPositionInSource() ==
         TextPosition::MinimumPosition();
}

String InspectorStyleSheet::SourceMapURL() {
  if (origin_ != protocol::CSS::StyleSheetOriginEnum::Regular)
    return String();

  String style_sheet_text;
  bool success = GetText(&style_sheet_text);
  if (success) {
    String comment_value =
        FindMagicComment(style_sheet_text, "sourceMappingURL");
    if (!comment_value.empty())
      return comment_value;
  }
  return page_style_sheet_->Contents()->SourceMapURL();
}

const Document* InspectorStyleSheet::GetDocument() {
  return CSSStyleSheet::SingleOwnerDocument(
      InspectorStyleSheet::PageStyleSheet());
}

CSSRuleSourceData* InspectorStyleSheet::FindRuleByHeaderRange(
    const SourceRange& source_range) {
  if (!source_data_)
    return nullptr;

  for (wtf_size_t i = 0; i < source_data_->size(); ++i) {
    CSSRuleSourceData* rule_source_data = source_data_->at(i).Get();
    if (rule_source_data->rule_header_range.start == source_range.start &&
        rule_source_data->rule_header_range.end == source_range.end) {
      return rule_source_data;
    }
  }
  return nullptr;
}

CSSRuleSourceData* InspectorStyleSheet::FindRuleByDeclarationsRange(
    const SourceRange& source_range) {
  if (!source_data_)
    return nullptr;

  for (wtf_size_t i = 0; i < source_data_->size(); ++i) {
    CSSRuleSourceData* rule_source_data = source_data_->at(i).Get();
    if (rule_source_data->rule_declarations_range.start == source_range.start &&
        rule_source_data->rule_declarations_range.end == source_range.end) {
      return rule_source_data;
    }
  }
  return nullptr;
}

CSSRule* InspectorStyleSheet::RuleForSourceData(
    CSSRuleSourceData* source_data) {
  if (!source_data_ || !source_data)
    return nullptr;

  RemapSourceDataToCSSOMIfNecessary();

  wtf_size_t index = source_data_->Find(source_data);
  if (index == kNotFound)
    return nullptr;
  InspectorIndexMap::iterator it = source_data_to_rule_.find(index);
  if (it == source_data_to_rule_.end())
    return nullptr;

  DCHECK_LT(it->value, cssom_flat_rules_.size());

  // Check that CSSOM did not mutate this rule.
  CSSRule* result = cssom_flat_rules_.at(it->value);
  if (CanonicalCSSText(parsed_flat_rules_.at(index)) !=
      CanonicalCSSText(result))
    return nullptr;
  return result;
}

CSSRuleSourceData* InspectorStyleSheet::SourceDataForRule(CSSRule* rule) {
  if (!source_data_ || !rule)
    return nullptr;

  RemapSourceDataToCSSOMIfNecessary();

  wtf_size_t index = cssom_flat_rules_.Find(rule);
  if (index == kNotFound)
    return nullptr;
  InspectorIndexMap::iterator it = rule_to_source_data_.find(index);
  if (it == rule_to_source_data_.end())
    return nullptr;

  DCHECK_LT(it->value, source_data_->size());

  // Check that CSSOM did not mutate this rule.
  CSSRule* parsed_rule = parsed_flat_rules_.at(it->value);
  if (CanonicalCSSText(rule) != CanonicalCSSText(parsed_rule))
    return nullptr;
  return source_data_->at(it->value).Get();
}

void InspectorStyleSheet::RemapSourceDataToCSSOMIfNecessary() {
  CSSRuleVector cssom_rules;
  CollectFlatRules(page_style_sheet_.Get(), &cssom_rules);

  if (cssom_rules.size() != cssom_flat_rules_.size()) {
    MapSourceDataToCSSOM();
    return;
  }

  for (wtf_size_t i = 0; i < cssom_flat_rules_.size(); ++i) {
    if (cssom_flat_rules_.at(i) != cssom_rules.at(i)) {
      MapSourceDataToCSSOM();
      return;
    }
  }
}

void InspectorStyleSheet::MapSourceDataToCSSOM() {
  rule_to_source_data_.clear();
  source_data_to_rule_.clear();

  cssom_flat_rules_.clear();
  CSSRuleVector& cssom_rules = cssom_flat_rules_;
  CollectFlatRules(page_style_sheet_.Get(), &cssom_rules);

  if (!source_data_)
    return;

  CSSRuleVector& parsed_rules = parsed_flat_rules_;

  Vector<String> cssom_rules_text = Vector<String>();
  Vector<String> parsed_rules_text = Vector<String>();
  for (wtf_size_t i = 0; i < cssom_rules.size(); ++i)
    cssom_rules_text.push_back(CanonicalCSSText(cssom_rules.at(i)));
  for (wtf_size_t j = 0; j < parsed_rules.size(); ++j)
    parsed_rules_text.push_back(CanonicalCSSText(parsed_rules.at(j)));

  InspectorDiff::FindLCSMapping(cssom_rules_text, parsed_rules_text,
                                &rule_to_source_data_, &source_data_to_rule_);
}

const CSSRuleVector& InspectorStyleSheet::FlatRules() {
  RemapSourceDataToCSSOMIfNecessary();
  return cssom_flat_rules_;
}

bool InspectorStyleSheet::ResourceStyleSheetText(String* result,
                                                 bool* loadingFailed) {
  if (origin_ == protocol::CSS::StyleSheetOriginEnum::Injected ||
      origin_ == protocol::CSS::StyleSheetOriginEnum::UserAgent)
    return false;

  if (!page_style_sheet_->OwnerDocument())
    return false;

  // Original URL defined in CSS.
  String href = page_style_sheet_->href();

  // Not a resource style sheet.
  if (!href)
    return false;

  // FinalURL() is a URL after redirects, whereas, href is not.
  // FinalURL() is used to call resource_container_->StoreStyleSheetContent
  // so it has to be used for lookups.
  if (resource_container_->LoadStyleSheetContent(KURL(FinalURL()), result))
    return true;

  bool base64_encoded;
  bool success = network_agent_->FetchResourceContent(
      page_style_sheet_->OwnerDocument(), KURL(href), result, &base64_encoded,
      loadingFailed);
  return success && !base64_encoded;
}

Element* InspectorStyleSheet::OwnerStyleElement() {
  Node* owner_node = page_style_sheet_->ownerNode();
  auto* owner_element = DynamicTo<Element>(owner_node);
  if (!owner_element)
    return nullptr;

  if (!IsA<HTMLStyleElement>(owner_element) &&
      !IsA<SVGStyleElement>(owner_element))
    return nullptr;
  return owner_element;
}

String InspectorStyleSheet::CollectStyleSheetRules() {
  StringBuilder builder;
  for (unsigned i = 0; i < page_style_sheet_->length(); i++) {
    builder.Append(page_style_sheet_->ItemInternal(i)->cssText());
    builder.Append('\n');
  }
  return builder.ToString();
}

bool InspectorStyleSheet::CSSOMStyleSheetText(String* result) {
  if (origin_ != protocol::CSS::StyleSheetOriginEnum::Regular) {
    return false;
  }
  *result = CollectStyleSheetRules();
  return true;
}

void InspectorStyleSheet::Reset() {
  ResetLineEndings();
  if (source_data_)
    source_data_->clear();
  cssom_flat_rules_.clear();
  parsed_flat_rules_.clear();
  rule_to_source_data_.clear();
  source_data_to_rule_.clear();
}

void InspectorStyleSheet::SyncTextIfNeeded() {
  if (!marked_for_sync_)
    return;
  Reset();
  UpdateText();
  marked_for_sync_ = false;
}

void InspectorStyleSheet::UpdateText() {
  String text;
  request_failed_to_load_.reset();
  bool success = InspectorStyleSheetText(&text);
  if (!success)
    success = InlineStyleSheetText(&text);
  if (!success) {
    bool loadingFailed = false;
    success = ResourceStyleSheetText(&text, &loadingFailed);
    request_failed_to_load_ = loadingFailed;
  }
  if (!success)
    success = CSSOMStyleSheetText(&text);
  if (success)
    InnerSetText(text, false);
}

bool InspectorStyleSheet::IsMutable() const {
  return page_style_sheet_->Contents()->IsMutable();
}

bool InspectorStyleSheet::InlineStyleSheetText(String* out) {
  Element* owner_element = OwnerStyleElement();
  bool result = false;
  if (!owner_element)
    return result;

  result = resource_container_->LoadStyleElementContent(
      owner_element->GetDomNodeId(), out);

  if (!result) {
    *out = owner_element->textContent();
    result = true;
  }

  if (result && IsMutable()) {
    ParseText(*out);
    *out = MergeCSSOMRulesWithText(*out);
  }

  return result;
}

bool InspectorStyleSheet::InspectorStyleSheetText(String* result) {
  if (origin_ != protocol::CSS::StyleSheetOriginEnum::Inspector)
    return false;
  if (!page_style_sheet_->OwnerDocument())
    return false;
  if (resource_container_->LoadStyleElementContent(
          page_style_sheet_->OwnerDocument()->GetDomNodeId(), result)) {
    return true;
  }
  *result = "";
  return true;
}

InspectorStyleSheetForInlineStyle::InspectorStyleSheetForInlineStyle(
    Element* element,
    Listener* listener)
    : InspectorStyleSheetBase(listener, IdentifiersFactory::CreateIdentifier()),
      element_(element) {
  DCHECK(element_);
}

void InspectorStyleSheetForInlineStyle::DidModifyElementAttribute() {
  inspector_style_.Clear();
  OnStyleSheetTextChanged();
}

bool InspectorStyleSheetForInlineStyle::SetText(
    const String& text,
    ExceptionState& exception_state) {
  if (!VerifyStyleText(&element_->GetDocument(), text)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Style text is not valid.");
    return false;
  }

  {
    InspectorCSSAgent::InlineStyleOverrideScope override_scope(
        element_->GetExecutionContext());
    element_->SetAttributeWithValidation(html_names::kStyleAttr,
                                         AtomicString(text), exception_state);
  }
  if (!exception_state.HadException())
    OnStyleSheetTextChanged();
  return !exception_state.HadException();
}

bool InspectorStyleSheetForInlineStyle::GetText(String* result) {
  *result = ElementStyleText();
  return true;
}

InspectorStyle* InspectorStyleSheetForInlineStyle::GetInspectorStyle(
    CSSStyleDeclaration* style) {
  if (!inspector_style_) {
    inspector_style_ = MakeGarbageCollected<InspectorStyle>(
        element_->style(), RuleSourceData(), this);
  }

  return inspector_style_.Get();
}

CSSRuleSourceData* InspectorStyleSheetForInlineStyle::RuleSourceData() {
  const String& text = ElementStyleText();
  CSSRuleSourceData* rule_source_data = nullptr;
  if (text.empty()) {
    rule_source_data =
        MakeGarbageCollected<CSSRuleSourceData>(StyleRule::kStyle);
    rule_source_data->rule_body_range.start = 0;
    rule_source_data->rule_body_range.end = 0;
  } else {
    CSSRuleSourceDataList* rule_source_data_result =
        MakeGarbageCollected<CSSRuleSourceDataList>();
    InspectorCSSParserObserver observer(text, &element_->GetDocument(),
                                        rule_source_data_result);
    CSSParser::ParseDeclarationListForInspector(
        ParserContextForDocument(&element_->GetDocument()), text, observer);
    rule_source_data = rule_source_data_result->front();
  }
  return rule_source_data;
}

CSSStyleDeclaration* InspectorStyleSheetForInlineStyle::InlineStyle() {
  return element_->style();
}

const String& InspectorStyleSheetForInlineStyle::ElementStyleText() {
  return element_->getAttribute(html_names::kStyleAttr).GetString();
}

void InspectorStyleSheetForInlineStyle::Trace(Visitor* visitor) const {
  visitor->Trace(element_);
  visitor->Trace(inspector_style_);
  InspectorStyleSheetBase::Trace(visitor);
}

const Document* InspectorStyleSheetForInlineStyle::GetDocument() {
  return &InspectorStyleSheetForInlineStyle::element_->GetDocument();
}

}  // namespace blink

"""


```