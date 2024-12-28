Response:
The user wants a summary of the provided C++ code snippet from `html_tree_builder.cc`. This code handles the processing of HTML start tags during the parsing process.

Here's a breakdown of how to approach this:

1. **Identify the Core Functionality:** The code is within the `HTMLTreeBuilder::ProcessStartTag` function and a few related helper functions. Its main job is to handle different HTML start tags based on the current parsing state (insertion mode).

2. **Categorize by HTML Tags:** The code uses a `switch` statement based on the `HTMLTag` enum. This suggests the core logic revolves around how specific HTML tags are handled.

3. **Analyze Individual Cases:** Go through each `case` in the `switch` statements and understand what action is being taken. Look for interactions with:
    * `tree_`: This represents the DOM tree being built. Actions like `InsertHTMLElement`, `InsertSelfClosingHTMLElementDestroyingToken`, `InsertForeignElement`, `ReconstructTheActiveFormattingElements`, `GenerateImpliedEndTags`, `OpenElements()`, `PopUntil()`, etc., are key.
    * `options_`:  Used for checking scripting flags (`options_.scripting_flag`).
    * `RuntimeEnabledFeatures`:  Used to enable or disable certain parsing behaviors (`SelectParserRelaxationEnabled`, `PermissionElementEnabled`).
    * `template_insertion_modes_`: Manages the state when parsing `<template>` elements.
    * `fragment_context_`:  Used when parsing HTML fragments.
    * `frameset_ok_`: Tracks whether framesets are allowed.
    * `ParseError()`:  Indicates the parser encountered an error.
    * `ProcessFakeEndTag()`, `ProcessFakeStartTag()`:  Handle implicit tag closures or openings.
    * `AdjustMathMLAttributes()`, `AdjustSVGAttributes()`, `AdjustForeignAttributes()`: Handle attributes for MathML and SVG elements.
    * `UseCounter::Count()`: Tracks usage of certain HTML features.
    * Console messages:  Used to output warnings or errors.

4. **Identify Relationships to HTML, CSS, and JavaScript:**
    * **HTML:** The entire code deals with parsing HTML tags, so the relationship is fundamental. Examples will be the specific tags handled (like `<script>`, `<style>`, `<div>`, `<table>`, etc.).
    * **CSS:**  The `<style>` tag handling is a direct link to CSS.
    * **JavaScript:** The `<script>` and `<noscript>` tag handling shows the interaction with JavaScript. The `options_.scripting_flag` is also relevant here. The console messages sometimes refer to JavaScript errors.

5. **Look for Logic and Assumptions:**
    * **Insertion Modes:** The code relies heavily on the concept of insertion modes. The `switch (GetInsertionMode())` structure is central.
    * **Stack of Open Elements:** The `tree_.OpenElements()` methods indicate the importance of maintaining the current state of open tags.
    * **Active Formatting Elements:**  The `tree_.ActiveFormattingElements()` calls show how formatting elements (like `<b>`, `<i>`) are tracked.

6. **Identify Potential User/Programming Errors:**  The `ParseError()` calls are clear indicators of potential errors. Look for specific scenarios that trigger these errors, like nested `<select>` tags or misplaced tags.

7. **Focus on the Provided Snippet:** The user explicitly provided a section of the code. Concentrate on the functionality within this specific part, but keep in mind the broader context.

8. **Structure the Summary:** Organize the findings into clear categories: core functionality, HTML/CSS/JavaScript relationships, logic/assumptions, and potential errors. Use examples where possible.

9. **Address the "Part 2 of 4" instruction:**  Indicate that this summary specifically covers the provided code snippet and is part of a larger file.

**(Self-Correction during thought process):** Initially, I might focus too much on the individual tag handling. It's important to step back and recognize the overarching pattern of using insertion modes to determine how each tag should be processed. Also, remember to connect the code actions back to the user-facing aspects of HTML, CSS, and JavaScript. The console messages are valuable clues for understanding error scenarios.
这是 `blink/renderer/core/html/parser/html_tree_builder.cc` 文件的第二部分代码片段，主要负责处理 HTML **起始标签 (Start Tag)** 的解析逻辑。它根据当前的 **插入模式 (Insertion Mode)** 和解析到的标签类型，执行相应的 DOM 树构建操作。

**主要功能归纳:**

1. **处理各种 HTML 起始标签:**  根据解析器生成的 `AtomicHTMLToken`，判断标签类型，并执行不同的处理逻辑。涵盖了常见的 HTML 标签，如 `script`, `noscript`, `select`, `option`, `optgroup`, 表格相关标签 (`caption`, `col`, `colgroup`, `tbody`, `tfoot`, `thead`, `th`, `td`, `tr`),  以及 `template` 等。

2. **根据插入模式进行不同的处理:**  `ProcessStartTag` 函数是核心入口，它根据当前的 `InsertionMode` 调用不同的处理分支，例如 `ProcessStartTagForInHead`, `ProcessStartTagForInBody`, `ProcessStartTagForInTable` 等。这体现了 HTML 解析的上下文敏感性。

3. **维护 DOM 树的状态:**  通过调用 `tree_` 对象的方法，修改正在构建的 DOM 树，包括插入元素 (`InsertHTMLElement`, `InsertForeignElement`), 插入自闭合元素 (`InsertSelfClosingHTMLElementDestroyingToken`), 重建活动的格式化元素 (`ReconstructTheActiveFormattingElements`),  生成隐含的结束标签 (`GenerateImpliedEndTags`) 等。

4. **处理 `<template>` 标签:**  专门有 `ProcessTemplateStartTag` 和 `ProcessTemplateEndTag` 来处理模板元素，涉及到 `template_insertion_modes_` 栈的管理，以及 `DocumentFragment` 的创建和关联。

5. **处理表格相关的标签:**  在不同的表格插入模式下 (`kInTableMode`, `kInCaptionMode`, `kInColumnGroupMode`, `kInTableBodyMode`, `kInRowMode`, `kInCellMode`)，针对表格的结构性标签进行特殊的处理，以确保表格结构的正确性。

6. **处理 `<select>`, `<option>`, `<optgroup>` 标签:**  对于选择框相关的标签，会处理嵌套情况，并根据 `SelectParserRelaxationEnabled` 特性进行不同的容错处理。

7. **处理 `<script>` 和 `<noscript>` 标签:**  根据是否启用脚本 (`options_.scripting_flag`)，对 `<noscript>` 标签进行不同的处理。  `<script>` 标签的处理会调用 `ProcessStartTagForInHead`。

8. **处理 MathML 和 SVG 标签:**  当遇到 MathML 或 SVG 的起始标签时，会调用 `AdjustMathMLAttributes` 和 `AdjustSVGAttributes` 来调整属性，并使用 `InsertForeignElement` 插入到 DOM 树中。

9. **处理自定义元素:**  在插入自定义元素之前会调用 `tree_.Flush()`，这可能导致已排队的任务执行，从而可能重新进入解析器。

10. **错误处理:**  当遇到不符合 HTML 规范的情况时，会调用 `ParseError(token)` 来记录解析错误。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  该代码的核心功能就是解析 HTML 结构。它识别各种 HTML 标签，并根据标签的语义和上下文将其正确地插入到 DOM 树中。例如，当解析到 `<div>` 标签时，会调用 `tree_.InsertHTMLElement(token)` 在当前位置插入一个 `div` 元素。

* **JavaScript:**
    * **`<script>` 标签:** 当解析到 `<script>` 标签时，会调用 `ProcessStartTagForInHead(token)`，这会触发脚本的加载和执行。
    * **`<noscript>` 标签:**  代码中判断了 `options_.scripting_flag`，如果脚本被禁用，`<noscript>` 标签内的内容会被正常解析并插入到 DOM 树中；否则，`<noscript>` 标签及其内容会被忽略。
    * **事件处理:** 虽然这段代码本身不直接处理 JavaScript 事件，但它构建的 DOM 树是 JavaScript 事件机制的基础。

* **CSS:**
    * **`<style>` 标签:** 当解析到 `<style>` 标签时，会调用 `ProcessStartTagForInHead(token)`，这会触发 CSS 样式的解析和应用。

**逻辑推理及假设输入与输出:**

**假设输入 (HTML 片段):**

```html
<div>
  <select>
    <option>Option 1</option>
    <select>
      <option>Nested Option</option>
    </select>
  </select>
</div>
```

**处理逻辑 (部分):**

当解析到第二个 `<select>` 标签时，由于 `RuntimeEnabledFeatures::SelectParserRelaxationEnabled()` 为 `true` 且当前已存在一个 `<select>` 标签在作用域内，代码会执行以下操作：

1. 调用 `tree_.OpenElements()->TopNode()->AddConsoleMessage(...)`，在控制台输出一个警告信息，提示嵌套的 `<select>` 标签。
2. 调用 `ParseError(token)` 记录一个解析错误。
3. 调用 `ProcessFakeEndTag(HTMLTag::kSelect)`，相当于插入一个 `</select>` 结束标签。
4. 接着才会将当前的 `<select>` 标签作为新的元素插入。

**假设输出 (部分 DOM 树结构变化):**

原本预期的嵌套 `<select>` 结构会被修正为兄弟关系的 `<select>` 结构，并会产生一个控制台警告。

```
<div>
  <select>
    <option>Option 1</option>
  </select>
  <select>
    <option>Nested Option</option>
  </select>
</div>
```

**用户或编程常见的使用错误举例说明:**

1. **嵌套 `<select>` 标签:**  如上述例子所示，HTML 规范不允许嵌套的 `<select>` 标签。这段代码会检测到这种情况并进行修正，同时输出警告信息。

2. **在不应该出现的地方使用特定标签:** 例如，在 `kInCaptionMode` 下遇到表格的结构性标签 (`<td>`, `<tr>` 等) 是不合法的。代码会调用 `ParseError(token)` 进行标记，并尝试进行修正，例如提前结束 `<caption>` 标签。

3. **`<option>` 或 `<optgroup>` 标签不在 `<select>` 标签内:**  代码会检查作用域内是否存在 `<select>` 标签，如果不存在，则可能产生解析错误。

**本部分功能归纳:**

这段代码片段主要负责 HTML 解析过程中**起始标签**的处理。它根据当前的解析状态 (插入模式) 和标签类型，执行相应的 DOM 树构建操作，包括插入元素、处理特殊标签 (如 `template`, `select`, `script`)、处理 MathML 和 SVG 标签，以及进行错误处理。它确保了 HTML 结构能够被正确地解析和构建成 DOM 树，这直接关系到网页的结构呈现以及 JavaScript 和 CSS 的执行。

Prompt: 
```
这是目录为blink/renderer/core/html/parser/html_tree_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
ericRawTextStartTag(token);
      break;
    case HTMLTag::kNoembed:
      ProcessGenericRawTextStartTag(token);
      break;
    case HTMLTag::kNoscript:
      if (options_.scripting_flag) {
        ProcessGenericRawTextStartTag(token);
      } else {
        tree_.ReconstructTheActiveFormattingElements();
        tree_.InsertHTMLElement(token);
      }
      break;
    case HTMLTag::kSelect:
      if (RuntimeEnabledFeatures::SelectParserRelaxationEnabled() &&
          tree_.OpenElements()->InScope(HTMLTag::kSelect)) {
        tree_.OpenElements()->TopNode()->AddConsoleMessage(
            mojom::blink::ConsoleMessageSource::kJavaScript,
            mojom::blink::ConsoleMessageLevel::kWarning,
            "A <select> tag was parsed within another <select> tag and was converted into </select><select>. Please add the missing </select> end tag.");
        // Don't allow nested <select>s. This is the exact same logic as
        // <button>s.
        ParseError(token);
        ProcessFakeEndTag(HTMLTag::kSelect);
      }
      tree_.ReconstructTheActiveFormattingElements();
      tree_.InsertHTMLElement(token);
      frameset_ok_ = false;
      // When SelectParserRelaxation is enabled, we don't want to enter
      // InSelectMode or InSelectInTableMode.
      if (!RuntimeEnabledFeatures::SelectParserRelaxationEnabled()) {
        if (GetInsertionMode() == kInTableMode ||
            GetInsertionMode() == kInCaptionMode ||
            GetInsertionMode() == kInColumnGroupMode ||
            GetInsertionMode() == kInTableBodyMode ||
            GetInsertionMode() == kInRowMode ||
            GetInsertionMode() == kInCellMode) {
          SetInsertionMode(kInSelectInTableMode);
        } else {
          SetInsertionMode(kInSelectMode);
        }
      }
      break;
    case HTMLTag::kOptgroup:
    case HTMLTag::kOption:
      if (RuntimeEnabledFeatures::SelectParserRelaxationEnabled() &&
          tree_.OpenElements()->InScope(HTMLTag::kSelect)) {
        // TODO(crbug.com/1511354): Remove this if by separating the optgroup
        // and option cases when the SelectParserRelaxation flag is removed.
        if (token->GetHTMLTag() == HTMLTag::kOption) {
          tree_.GenerateImpliedEndTagsWithExclusion(
              HTMLTokenName(HTMLTag::kOptgroup));
          if (tree_.OpenElements()->InScope(HTMLTag::kOption)) {
            ParseError(token);
          }
        } else {
          tree_.GenerateImpliedEndTags();
          if (tree_.OpenElements()->InScope(HTMLTag::kOption) ||
              tree_.OpenElements()->InScope(HTMLTag::kOptgroup)) {
            ParseError(token);
          }
        }
      } else {
        if (tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kOption)) {
          AtomicHTMLToken end_option(HTMLToken::kEndTag, HTMLTag::kOption);
          ProcessEndTag(&end_option);
        }
        tree_.ReconstructTheActiveFormattingElements();
      }
      tree_.InsertHTMLElement(token);
      break;
    case HTMLTag::kRb:
    case HTMLTag::kRTC:
      if (tree_.OpenElements()->InScope(HTMLTag::kRuby)) {
        tree_.GenerateImpliedEndTags();
        if (!tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kRuby))
          ParseError(token);
      }
      tree_.InsertHTMLElement(token);
      break;
    case HTMLTag::kRt:
    case HTMLTag::kRp:
      if (tree_.OpenElements()->InScope(HTMLTag::kRuby)) {
        tree_.GenerateImpliedEndTagsWithExclusion(HTMLTokenName(HTMLTag::kRTC));
        if (!tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kRuby) &&
            !tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kRTC))
          ParseError(token);
      }
      tree_.InsertHTMLElement(token);
      break;
    case HTMLTag::kCaption:
    case HTMLTag::kCol:
    case HTMLTag::kColgroup:
    case HTMLTag::kFrame:
    case HTMLTag::kHead:
    case HTMLTag::kTbody:
    case HTMLTag::kTfoot:
    case HTMLTag::kThead:
    case HTMLTag::kTh:
    case HTMLTag::kTd:
    case HTMLTag::kTr:
      ParseError(token);
      break;
    case HTMLTag::kPermissionOrUnknown:
      if (RuntimeEnabledFeatures::PermissionElementEnabled(
              tree_.OwnerDocumentForCurrentNode().GetExecutionContext())) {
        tree_.ReconstructTheActiveFormattingElements();
        tree_.InsertSelfClosingHTMLElementDestroyingToken(token);
        frameset_ok_ = false;
        break;
      }
      [[fallthrough]];
    default:
      if (token->GetName() == mathml_names::kMathTag.LocalName()) {
        tree_.ReconstructTheActiveFormattingElements();
        AdjustMathMLAttributes(token);
        AdjustForeignAttributes(token);
        tree_.InsertForeignElement(token, mathml_names::kNamespaceURI);
      } else if (token->GetName() == svg_names::kSVGTag.LocalName()) {
        tree_.ReconstructTheActiveFormattingElements();
        AdjustSVGAttributes(token);
        AdjustForeignAttributes(token);
        tree_.InsertForeignElement(token, svg_names::kNamespaceURI);
      } else {
        tree_.ReconstructTheActiveFormattingElements();
        // Flush before creating custom elements. NOTE: Flush() can cause any
        // queued tasks to execute, possibly re-entering the parser.
        tree_.Flush();
        tree_.InsertHTMLElement(token);
      }
      break;
  }
}

namespace {
String DeclarativeShadowRootModeFromToken(AtomicHTMLToken* token,
                                          const Document& document,
                                          bool include_shadow_roots) {
  Attribute* mode_attribute =
      token->GetAttributeItem(html_names::kShadowrootmodeAttr);
  if (!mode_attribute) {
    return String();
  }
  if (!include_shadow_roots) {
    document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kWarning,
        "Found declarative shadowrootmode attribute on a template, but "
        "declarative Shadow DOM is not being parsed. Use setHTMLUnsafe() "
        "or parseHTMLUnsafe() instead."));
    return String();
  }
  return mode_attribute->Value();
}
}  // namespace

void HTMLTreeBuilder::ProcessTemplateStartTag(AtomicHTMLToken* token) {
  tree_.ActiveFormattingElements()->AppendMarker();
  tree_.InsertHTMLTemplateElement(
      token,
      DeclarativeShadowRootModeFromToken(
          token, tree_.OwnerDocumentForCurrentNode(), include_shadow_roots_));
  frameset_ok_ = false;
  template_insertion_modes_.push_back(kTemplateContentsMode);
  SetInsertionMode(kTemplateContentsMode);
}

bool HTMLTreeBuilder::ProcessTemplateEndTag(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetName(), html_names::kTemplateTag.LocalName());
  if (!tree_.OpenElements()->HasTemplateInHTMLScope()) {
    DCHECK(template_insertion_modes_.empty() ||
           (template_insertion_modes_.size() == 1 &&
            IsA<HTMLTemplateElement>(fragment_context_.ContextElement())));
    ParseError(token);
    return false;
  }
  tree_.GenerateImpliedEndTags();
  if (!tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kTemplate))
    ParseError(token);
  tree_.OpenElements()->PopUntil(HTMLTag::kTemplate);
  HTMLStackItem* template_stack_item = tree_.OpenElements()->TopStackItem();
  tree_.OpenElements()->Pop();
  tree_.ActiveFormattingElements()->ClearToLastMarker();
  template_insertion_modes_.pop_back();
  ResetInsertionModeAppropriately();
  if (template_stack_item) {
    DCHECK(template_stack_item->IsElementNode());
    HTMLTemplateElement* template_element =
        DynamicTo<HTMLTemplateElement>(template_stack_item->GetElement());
    if (DocumentFragment* template_content = template_element->getContent()) {
      tree_.FinishedTemplateElement(template_content);
    }
  }
  return true;
}

bool HTMLTreeBuilder::ProcessEndOfFileForInTemplateContents(
    AtomicHTMLToken* token) {
  AtomicHTMLToken end_template(HTMLToken::kEndTag, HTMLTag::kTemplate);
  if (!ProcessTemplateEndTag(&end_template))
    return false;

  ProcessEndOfFile(token);
  return true;
}

bool HTMLTreeBuilder::ProcessColgroupEndTagForInColumnGroup() {
  if (tree_.CurrentIsRootNode() ||
      IsA<HTMLTemplateElement>(*tree_.CurrentNode())) {
    DCHECK(IsParsingFragmentOrTemplateContents());
    // FIXME: parse error
    return false;
  }
  tree_.OpenElements()->Pop();
  SetInsertionMode(kInTableMode);
  return true;
}

// http://www.whatwg.org/specs/web-apps/current-work/#adjusted-current-node
HTMLStackItem* HTMLTreeBuilder::AdjustedCurrentStackItem() const {
  DCHECK(!tree_.IsEmpty());
  if (IsParsingFragment() && tree_.OpenElements()->HasOnlyOneElement())
    return fragment_context_.ContextElementStackItem();

  return tree_.CurrentStackItem();
}

// http://www.whatwg.org/specs/web-apps/current-work/multipage/tokenization.html#close-the-cell
void HTMLTreeBuilder::CloseTheCell() {
  DCHECK_EQ(GetInsertionMode(), kInCellMode);
  if (tree_.OpenElements()->InTableScope(HTMLTag::kTd)) {
    DCHECK(!tree_.OpenElements()->InTableScope(HTMLTag::kTh));
    ProcessFakeEndTag(HTMLTag::kTd);
    return;
  }
  DCHECK(tree_.OpenElements()->InTableScope(HTMLTag::kTh));
  ProcessFakeEndTag(HTMLTag::kTh);
  DCHECK_EQ(GetInsertionMode(), kInRowMode);
}

void HTMLTreeBuilder::ProcessStartTagForInTable(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kStartTag);
  switch (token->GetHTMLTag()) {
    case HTMLTag::kCaption:
      tree_.OpenElements()->PopUntilTableScopeMarker();
      tree_.ActiveFormattingElements()->AppendMarker();
      tree_.InsertHTMLElement(token);
      SetInsertionMode(kInCaptionMode);
      return;
    case HTMLTag::kColgroup:
      tree_.OpenElements()->PopUntilTableScopeMarker();
      tree_.InsertHTMLElement(token);
      SetInsertionMode(kInColumnGroupMode);
      return;
    case HTMLTag::kCol:
      ProcessFakeStartTag(HTMLTag::kColgroup);
      DCHECK(kInColumnGroupMode);
      ProcessStartTag(token);
      return;
    case HTMLTag::kTbody:
    case HTMLTag::kTfoot:
    case HTMLTag::kThead:
      tree_.OpenElements()->PopUntilTableScopeMarker();
      tree_.InsertHTMLElement(token);
      SetInsertionMode(kInTableBodyMode);
      return;
    case HTMLTag::kTd:
    case HTMLTag::kTh:
    case HTMLTag::kTr:
      ProcessFakeStartTag(HTMLTag::kTbody);
      DCHECK_EQ(GetInsertionMode(), kInTableBodyMode);
      ProcessStartTag(token);
      return;
    case HTMLTag::kTable:
      ParseError(token);
      if (!ProcessTableEndTagForInTable()) {
        DCHECK(IsParsingFragmentOrTemplateContents());
        return;
      }
      ProcessStartTag(token);
      return;
    case HTMLTag::kStyle:
    case HTMLTag::kScript:
      ProcessStartTagForInHead(token);
      return;
    case HTMLTag::kInput: {
      Attribute* type_attribute =
          token->GetAttributeItem(html_names::kTypeAttr);
      if (type_attribute &&
          EqualIgnoringASCIICase(type_attribute->Value(), "hidden")) {
        ParseError(token);
        tree_.InsertSelfClosingHTMLElementDestroyingToken(token);
        return;
      }
      // break to hit "anything else" case.
      break;
    }
    case HTMLTag::kForm:
      ParseError(token);
      if (tree_.IsFormElementPointerNonNull() && !IsParsingTemplateContents())
        return;
      tree_.InsertHTMLFormElement(token, true);
      tree_.OpenElements()->Pop();
      return;
    case HTMLTag::kTemplate:
      ProcessTemplateStartTag(token);
      return;
    default:
      break;
  }
  ParseError(token);
  HTMLConstructionSite::RedirectToFosterParentGuard redirecter(tree_);
  ProcessStartTagForInBody(token);
}

void HTMLTreeBuilder::ProcessStartTag(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kStartTag);
  const HTMLTag tag = token->GetHTMLTag();
  switch (GetInsertionMode()) {
    case kInitialMode:
      DefaultForInitial();
      [[fallthrough]];
    case kBeforeHTMLMode:
      DCHECK_EQ(GetInsertionMode(), kBeforeHTMLMode);
      if (tag == HTMLTag::kHTML) {
        tree_.InsertHTMLHtmlStartTagBeforeHTML(token);
        SetInsertionMode(kBeforeHeadMode);
        return;
      }
      DefaultForBeforeHTML();
      [[fallthrough]];
    case kBeforeHeadMode:
      DCHECK_EQ(GetInsertionMode(), kBeforeHeadMode);
      if (tag == HTMLTag::kHTML) {
        ProcessHtmlStartTagForInBody(token);
        return;
      }
      if (tag == HTMLTag::kHead) {
        tree_.InsertHTMLHeadElement(token);
        SetInsertionMode(kInHeadMode);
        return;
      }
      DefaultForBeforeHead();
      [[fallthrough]];
    case kInHeadMode:
      DCHECK_EQ(GetInsertionMode(), kInHeadMode);
      if (ProcessStartTagForInHead(token))
        return;
      DefaultForInHead();
      [[fallthrough]];
    case kAfterHeadMode:
      DCHECK_EQ(GetInsertionMode(), kAfterHeadMode);
      switch (tag) {
        case HTMLTag::kHTML:
          ProcessHtmlStartTagForInBody(token);
          return;
        case HTMLTag::kBody:
          frameset_ok_ = false;
          tree_.InsertHTMLBodyElement(token);
          SetInsertionMode(kInBodyMode);
          return;
        case HTMLTag::kFrameset:
          tree_.InsertHTMLElement(token);
          SetInsertionMode(kInFramesetMode);
          return;
        case HTMLTag::kBase:
        case HTMLTag::kBasefont:
        case HTMLTag::kBgsound:
        case HTMLTag::kLink:
        case HTMLTag::kMeta:
        case HTMLTag::kNoframes:
        case HTMLTag::kScript:
        case HTMLTag::kStyle:
        case HTMLTag::kTemplate:
        case HTMLTag::kTitle:
          ParseError(token);
          DCHECK(tree_.Head());
          tree_.OpenElements()->PushHTMLHeadElement(tree_.HeadStackItem());
          ProcessStartTagForInHead(token);
          tree_.OpenElements()->RemoveHTMLHeadElement(tree_.Head());
          return;
        case HTMLTag::kHead:
          ParseError(token);
          return;
        default:
          break;
      }
      DefaultForAfterHead();
      [[fallthrough]];
    case kInBodyMode:
      DCHECK_EQ(GetInsertionMode(), kInBodyMode);
      ProcessStartTagForInBody(token);
      break;

    case kInTableMode:
      ProcessStartTagForInTable(token);
      break;
    case kInCaptionMode:
      switch (tag) {
        case CAPTION_COL_OR_COLGROUP_CASES:
        case TABLE_BODY_CONTEXT_CASES:
        case TABLE_CELL_CONTEXT_CASES:
        case HTMLTag::kTr:
          ParseError(token);
          if (!ProcessCaptionEndTagForInCaption()) {
            DCHECK(IsParsingFragment());
            return;
          }
          ProcessStartTag(token);
          return;
        default:
          break;
      }
      ProcessStartTagForInBody(token);
      break;
    case kInColumnGroupMode:
      switch (tag) {
        case HTMLTag::kHTML:
          ProcessHtmlStartTagForInBody(token);
          return;
        case HTMLTag::kCol:
          tree_.InsertSelfClosingHTMLElementDestroyingToken(token);
          return;
        case HTMLTag::kTemplate:
          ProcessTemplateStartTag(token);
          return;
        default:
          break;
      }
      if (!ProcessColgroupEndTagForInColumnGroup()) {
        DCHECK(IsParsingFragmentOrTemplateContents());
        return;
      }
      ProcessStartTag(token);
      break;
    case kInTableBodyMode:
      switch (tag) {
        case HTMLTag::kTr:
          // How is there ever anything to pop?
          tree_.OpenElements()->PopUntilTableBodyScopeMarker();
          tree_.InsertHTMLElement(token);
          SetInsertionMode(kInRowMode);
          return;
        case TABLE_CELL_CONTEXT_CASES:
          ParseError(token);
          ProcessFakeStartTag(HTMLTag::kTr);
          DCHECK_EQ(GetInsertionMode(), kInRowMode);
          ProcessStartTag(token);
          return;
        case CAPTION_COL_OR_COLGROUP_CASES:
        case TABLE_BODY_CONTEXT_CASES:
          // FIXME: This is slow.
          if (!tree_.OpenElements()->InTableScope(HTMLTag::kTbody) &&
              !tree_.OpenElements()->InTableScope(HTMLTag::kThead) &&
              !tree_.OpenElements()->InTableScope(HTMLTag::kTfoot)) {
            DCHECK(IsParsingFragmentOrTemplateContents());
            ParseError(token);
            return;
          }
          tree_.OpenElements()->PopUntilTableBodyScopeMarker();
          DCHECK(IsTableBodyContextTag(tree_.CurrentStackItem()->GetHTMLTag()));
          ProcessFakeEndTag(*tree_.CurrentStackItem());
          ProcessStartTag(token);
          return;
        default:
          break;
      }
      ProcessStartTagForInTable(token);
      break;
    case kInRowMode:
      switch (tag) {
        case TABLE_CELL_CONTEXT_CASES:
          tree_.OpenElements()->PopUntilTableRowScopeMarker();
          tree_.InsertHTMLElement(token);
          SetInsertionMode(kInCellMode);
          tree_.ActiveFormattingElements()->AppendMarker();
          return;
        case HTMLTag::kTr:
        case CAPTION_COL_OR_COLGROUP_CASES:
        case TABLE_BODY_CONTEXT_CASES:
          if (!ProcessTrEndTagForInRow()) {
            DCHECK(IsParsingFragmentOrTemplateContents());
            return;
          }
          DCHECK_EQ(GetInsertionMode(), kInTableBodyMode);
          ProcessStartTag(token);
          return;
        default:
          break;
      }
      ProcessStartTagForInTable(token);
      break;
    case kInCellMode:
      switch (tag) {
        case CAPTION_COL_OR_COLGROUP_CASES:
        case TABLE_CELL_CONTEXT_CASES:
        case HTMLTag::kTr:
        case TABLE_BODY_CONTEXT_CASES:
          // FIXME: This could be more efficient.
          if (!tree_.OpenElements()->InTableScope(HTMLTag::kTd) &&
              !tree_.OpenElements()->InTableScope(HTMLTag::kTh)) {
            DCHECK(IsParsingFragment());
            ParseError(token);
            return;
          }
          CloseTheCell();
          ProcessStartTag(token);
          return;
        default:
          break;
      }
      ProcessStartTagForInBody(token);
      break;
    case kAfterBodyMode:
    case kAfterAfterBodyMode:
      if (tag == HTMLTag::kHTML) {
        ProcessHtmlStartTagForInBody(token);
        return;
      }
      SetInsertionMode(kInBodyMode);
      ProcessStartTag(token);
      break;
    case kInHeadNoscriptMode:
      switch (tag) {
        case HTMLTag::kHTML:
          ProcessHtmlStartTagForInBody(token);
          return;
        case HTMLTag::kBasefont:
        case HTMLTag::kBgsound:
        case HTMLTag::kLink:
        case HTMLTag::kMeta:
        case HTMLTag::kNoframes:
        case HTMLTag::kStyle: {
          bool did_process = ProcessStartTagForInHead(token);
          DCHECK(did_process);
          return;
        }
        case HTMLTag::kNoscript:
          ParseError(token);
          return;
        default:
          break;
      }
      DefaultForInHeadNoscript();
      ProcessToken(token);
      break;
    case kInFramesetMode:
      switch (tag) {
        case HTMLTag::kHTML:
          ProcessHtmlStartTagForInBody(token);
          return;
        case HTMLTag::kFrameset:
          tree_.InsertHTMLElement(token);
          return;
        case HTMLTag::kFrame:
          tree_.InsertSelfClosingHTMLElementDestroyingToken(token);
          return;
        case HTMLTag::kNoframes:
          ProcessStartTagForInHead(token);
          return;
        default:
          break;
      }
      ParseError(token);
      break;
    case kAfterFramesetMode:
    case kAfterAfterFramesetMode:
      if (tag == HTMLTag::kHTML) {
        ProcessHtmlStartTagForInBody(token);
        return;
      }
      if (tag == HTMLTag::kNoframes) {
        ProcessStartTagForInHead(token);
        return;
      }
      ParseError(token);
      break;
    case kInSelectInTableMode:
      switch (tag) {
        case HTMLTag::kCaption:
        case HTMLTag::kTable:
        case TABLE_BODY_CONTEXT_CASES:
        case HTMLTag::kTr:
        case TABLE_CELL_CONTEXT_CASES: {
          ParseError(token);
          AtomicHTMLToken end_select(HTMLToken::kEndTag, HTMLTag::kSelect);
          ProcessEndTag(&end_select);
          ProcessStartTag(token);
          return;
        }
        default:
          break;
      }
      [[fallthrough]];
    case kInSelectMode:
      switch (tag) {
        case HTMLTag::kHTML:
          ProcessHtmlStartTagForInBody(token);
          return;
        case HTMLTag::kOption:
          if (tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kOption)) {
            AtomicHTMLToken end_option(HTMLToken::kEndTag, HTMLTag::kOption);
            ProcessEndTag(&end_option);
          }
          tree_.InsertHTMLElement(token);
          return;
        case HTMLTag::kOptgroup:
          if (tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kOption)) {
            AtomicHTMLToken end_option(HTMLToken::kEndTag, HTMLTag::kOption);
            ProcessEndTag(&end_option);
          }
          if (tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kOptgroup)) {
            AtomicHTMLToken end_optgroup(HTMLToken::kEndTag,
                                         HTMLTag::kOptgroup);
            ProcessEndTag(&end_optgroup);
          }
          tree_.InsertHTMLElement(token);
          return;
        case HTMLTag::kHr:
          if (tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kOption)) {
            AtomicHTMLToken end_option(HTMLToken::kEndTag, HTMLTag::kOption);
            ProcessEndTag(&end_option);
          }
          if (tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kOptgroup)) {
            AtomicHTMLToken end_optgroup(HTMLToken::kEndTag,
                                         HTMLTag::kOptgroup);
            ProcessEndTag(&end_optgroup);
          }
          tree_.InsertSelfClosingHTMLElementDestroyingToken(token);
          return;
        case HTMLTag::kSelect: {
          tree_.OpenElements()->TopNode()->AddConsoleMessage(
            mojom::blink::ConsoleMessageSource::kJavaScript,
            mojom::blink::ConsoleMessageLevel::kError,
            "A <select> tag was parsed within another <select> tag and was converted into </select>. This behavior will change in a future browser version. Please add the missing </select> end tag.");
          ParseError(token);
          AtomicHTMLToken end_select(HTMLToken::kEndTag, HTMLTag::kSelect);
          ProcessEndTag(&end_select);
          return;
        }
        case HTMLTag::kInput:
          // TODO(crbug.com/1511354): Remove this UseCounter when the
          // SelectParserRelaxation/CustomizableSelect flags are removed.
          UseCounter::Count(tree_.CurrentNode()->GetDocument(),
                            WebFeature::kHTMLInputInSelect);
          [[fallthrough]];
        case HTMLTag::kKeygen:
        case HTMLTag::kTextarea: {
          if (RuntimeEnabledFeatures::SelectParserRelaxationEnabled()) {
            ProcessStartTagForInBody(token);
          } else {
            ParseError(token);
            if (!tree_.OpenElements()->InSelectScope(HTMLTag::kSelect)) {
              DCHECK(IsParsingFragment());
              return;
            }
            AtomicHTMLToken end_select(HTMLToken::kEndTag, HTMLTag::kSelect);
            ProcessEndTag(&end_select);
            ProcessStartTag(token);

            tree_.OpenElements()->TopNode()->AddConsoleMessage(
                mojom::blink::ConsoleMessageSource::kJavaScript,
                mojom::blink::ConsoleMessageLevel::kWarning,
                "A " + token->GetName() +
                    " tag was parsed inside of a <select> which caused a "
                    "</select> to be inserted before this tag. "
                    "This is not valid HTML and the behavior may be changed in "
                    "future versions of chrome.");
          }
          return;
        }
        case HTMLTag::kScript: {
          bool did_process = ProcessStartTagForInHead(token);
          DCHECK(did_process);
          return;
        }
        case HTMLTag::kTemplate:
          ProcessTemplateStartTag(token);
          return;
        case HTMLTag::kButton:
          if (!RuntimeEnabledFeatures::SelectParserRelaxationEnabled()) {
            // TODO(crbug.com/1511354): Remove this UseCounter when the
            // SelectParserRelaxation/CustomizableSelect flags are removed.
            UseCounter::Count(tree_.CurrentNode()->GetDocument(),
                              WebFeature::kHTMLButtonInSelect);
          }
          [[fallthrough]];
        case HTMLTag::kDatalist:
          if (tag == HTMLTag::kDatalist &&
              !RuntimeEnabledFeatures::SelectParserRelaxationEnabled()) {
            // TODO(crbug.com/1511354): Remove this UseCounter when the
            // SelectParserRelaxation/CustomizableSelect flags are removed.
            UseCounter::Count(tree_.CurrentNode()->GetDocument(),
                              WebFeature::kHTMLDatalistInSelect);
          }
          [[fallthrough]];
        default:
          if (RuntimeEnabledFeatures::SelectParserRelaxationEnabled()) {
            ProcessStartTagForInBody(token);
          } else {
            // TODO(crbug.com/1511354): Remove this UseCounter when the
            // SelectParserRelaxation/CustomizableSelect flags are removed.
            UseCounter::Count(tree_.CurrentNode()->GetDocument(),
                              WebFeature::kSelectParserDroppedTag);
            tree_.OpenElements()->TopNode()->AddConsoleMessage(
                mojom::blink::ConsoleMessageSource::kJavaScript,
                mojom::blink::ConsoleMessageLevel::kWarning,
                "A " + token->GetName() +
                    " tag was parsed inside of a <select> which was not "
                    "inserted into the document. This is not valid HTML and "
                    "the behavior may be changed in future versions of "
                    "chrome.");
          }
          break;
      }
      break;
    case kInTableTextMode:
      DefaultForInTableText();
      ProcessStartTag(token);
      break;
    case kTextMode:
      NOTREACHED();
    case kTemplateContentsMode:
      switch (tag) {
        case HTMLTag::kTemplate:
          ProcessTemplateStartTag(token);
          return;
        case HTMLTag::kLink:
        case HTMLTag::kScript:
        case HTMLTag::kStyle:
        case HTMLTag::kMeta:
          ProcessStartTagForInHead(token);
          return;
        default:
          break;
      }

      InsertionMode insertion_mode = kTemplateContentsMode;
      switch (tag) {
        case HTMLTag::kCol:
          insertion_mode = kInColumnGroupMode;
          break;
        case HTMLTag::kCaption:
        case HTMLTag::kColgroup:
        case TABLE_BODY_CONTEXT_CASES:
          insertion_mode = kInTableMode;
          break;
        case HTMLTag::kTr:
          insertion_mode = kInTableBodyMode;
          break;
        case TABLE_CELL_CONTEXT_CASES:
          insertion_mode = kInRowMode;
          break;
        default:
          insertion_mode = kInBodyMode;
          break;
      }

      DCHECK_NE(insertion_mode, kTemplateContentsMode);
      DCHECK_EQ(template_insertion_modes_.back(), kTemplateContentsMode);
      template_insertion_modes_.back() = insertion_mode;
      SetInsertionMode(insertion_mode);

      ProcessStartTag(token);
      break;
  }
}

void HTMLTreeBuilder::ProcessHtmlStartTagForInBody(AtomicHTMLToken* token) {
  ParseError(token);
  if (tree_.OpenElements()->HasTemplateInHTMLScope()) {
    DCHECK(IsParsingTemplateContents());
    return;
  }
  tree_.InsertHTMLHtmlStartTagInBody(token);
}

bool HTMLTreeBuilder::ProcessBodyEndTagForInBody(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kEndTag);
  DCHECK_EQ(token->GetHTMLTag(), HTMLTag::kBody);
  if (!tree_.OpenElements()->InScope(HTMLTag::kBody)) {
    ParseError(token);
    return false;
  }
  // Emit a more specific parse error based on stack contents.
  DVLOG(1) << "Not implemented.";
  SetInsertionMode(kAfterBodyMode);
  return true;
}

void HTMLTreeBuilder::ProcessAnyOtherEndTagForInBody(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kEndTag);
  HTMLStackItem* item = tree_.OpenElements()->TopStackItem();
  while (true) {
    if (item->MatchesHTMLTag(token->GetTokenName())) {
      tree_.GenerateImpliedEndTagsWithExclusion(token->GetTokenName());
      if (!tree_.CurrentStackItem()->MatchesHTMLTag(token->GetTokenName()))
        ParseError(token);
      tree_.OpenElements()->PopUntilPopped(item->GetElement());
      return;
    }
    if (item->IsSpecialNode()) {
      ParseError(token);
      return;
    }
    item = item->NextItemInStack();
  }
}

// http://www.whatwg.org/specs/web-apps/current-work/multipage/tokenization.html#parsing-main-inbody
void HTMLTreeBuilder::CallTheAdoptionAgency(AtomicHTMLToken* token) {
  // The adoption agency algorithm is N^2. We limit the number of iterations
  // to stop from hanging the whole browser. This limit is specified in the
  // adoption agency algorithm:
  // https://html.spec.whatwg.org/multipage/parsing.html#adoption-agency-algorithm
  static const int kOuterIterationLimit = 8;
  static const int kInnerIterationLimit = 3;

  // 2. If the current node is an HTML element whose tag name is subject,
  // and the current node is not in the list of active formatting elements,
  // then pop the current node off the stack of open elements and return.
  if (!tree_.IsEmpty() && tree_.CurrentStackItem()->IsElementNode() &&
      tree_.CurrentElement()->HasLocalName(token->GetName()) &&
      !tree_.ActiveFormattingElements()->Contains(tree_.CurrentElement())) {
    tree_.OpenElements()->Pop();
    return;
  }

  // 1, 2, 3 and 16 are covered by the for() loop.
  for (int i = 0; i < kOuterIterationLimit; ++i) {
    // 4.
    // ClosestElementInScopeWithName() returns null for non-html tags.
    if (!token->IsValidHTMLTag())
      return ProcessAnyOtherEndTagForInBody(token);
    Element* formatting_element =
        tree_.ActiveFormattingElements()->ClosestElementInScopeWithName(
            token->GetName());
    // 4.a
    if (!formatting_element)
      return ProcessAnyOtherEndTagForInBody(token);
    // 4.c
    if ((tree_.OpenElements()->Contains(formatting_element)) &&
        !tree_.OpenElements()->InScope(formatting_element)) {
      ParseError(token);
      // Check the stack of open elements for a more specific parse error.
      DVLOG(1) << "Not implemented.";
      return;
    }
    // 4.b
    HTMLStackItem* formatting_element_item =
        tree_.OpenElements()->Find(formatting_element);
    if (!formatting_element_item) {
      ParseError(token);
      tree_.ActiveFormattingElements()->Remove(formatting_element);
      return;
    }
    // 4.d
    if (formatting_element != tree_.CurrentElement())
      ParseError(token);
    // 5.
    HTMLStackItem* furthest_block =
        tree_.OpenElements()->FurthestBlockForFormattingElement(
            formatting_element);
    // 6.
    if (!furthest_block) {
      tree_.OpenElements()->PopUntilPopped(formatting_element);
      tree_.ActiveFormattingElements()->Remove(formatting_element);
      return;
    }
    // 7.
    DCHECK(furthest_block->IsAboveItemInStack(formatting_element_item));
    HTMLStackItem* common_ancestor = formatting_element_item->NextItemInStack();
    // 8.
    HTMLFormattingElementList::Bookmark bookmark =
        tree_.ActiveFormattingElements()->BookmarkFor(formatting_element);
    // 9.
    HTMLStackItem* node = furthest_block;
    HTMLStackItem* next_node = node->NextItemInStack();
    HTMLStackItem* last_node = furthest_block;
    // 9.1, 9.2, 9.3 and 9.11 are covered by the for() loop.
    for (int j = 0; j < kInnerIterationLimit; ++j) {
      // 9.4
      node = next_node;
      DCHECK(node);
      // Save node->next() for the next iteration in case node is deleted in
      // 9.5.
      next_node = node->NextItemInStack();
      // 9.5
      if (!tree_.ActiveFormattingElements()->Contains(node->GetElement())) {
        tree_.OpenElements()->Remove(node->GetElement());
        node = nullptr;
        continue;
      }
      // 9.6
      if (node == formatting_element_item) {
        break;
      }
      // 9.7
      HTMLStackItem* new_item = tree_.CreateElementFromSavedToken(node);

      HTMLFormattingElementList::Entry* node_entry =
          tree_.ActiveFormattingElements()->Find(node->GetElement());
      node_entry->ReplaceElement(new_item);
      tree_.OpenElements()->Replace(node, new_item);
      node = new_item;

      // 9.8
      if (last_node == furthest_block)
        bookmark.MoveToAfter(node_entry);
      // 9.9
      tree_.Reparent(node, last_node);
      // 9.10
      last_node = node;
    }
    // 10.
    tree_.InsertAlreadyParsedChild(common_ancestor, last_node);
    // 11.
    HTMLStackItem* new_item =
        tree_.CreateElementFromSavedToken(formatting_element_item);
    // 12.
    tree_.TakeAllChildren(new_item, furthest_block);

"""


```