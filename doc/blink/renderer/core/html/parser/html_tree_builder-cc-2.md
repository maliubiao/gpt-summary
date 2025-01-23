Response:
The user wants to understand the functionality of the provided C++ code snippet from the Chromium Blink engine. This snippet is a part of the `HTMLTreeBuilder` class, specifically handling end tags during HTML parsing.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Function:** The code focuses on processing HTML end tags (`</tag>`). The surrounding methods (`ProcessEndTagFor...`) and the main `ProcessEndTag` method clearly indicate this.

2. **Deconstruct the Code by Insertion Mode:** The `ProcessEndTag` method uses a `switch` statement based on the current `insertion_mode_`. This is the key to understanding how the code handles different contexts within an HTML document. Group the functionalities based on these insertion modes.

3. **Analyze Functionality within Each Mode:**
    * **Common Actions:** Notice recurring actions like `ParseError`, `tree_.OpenElements()->Pop()`, `SetInsertionMode()`, `tree_.GenerateImpliedEndTags()`, `tree_.ActiveFormattingElements()->ClearToLastMarker()`. These are fundamental operations in HTML parsing.
    * **Tag-Specific Logic:**  Each `case` within the `switch` often has a nested `switch` based on the specific HTML tag being processed. This reveals how different end tags are handled in that particular insertion mode.
    * **Error Handling:** The `ParseError(token)` calls highlight the code's role in validating HTML syntax.
    * **State Management:**  `SetInsertionMode()` is crucial for transitioning between parsing states.
    * **DOM Manipulation:**  Methods like `tree_.OpenElements()->Pop()` and inserting elements (though not directly shown in this snippet) indicate DOM construction.

4. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The code directly manipulates HTML elements and their structure. Examples can be drawn from the tag-specific handling (e.g., `<body>`, `<div>`, `<table>`).
    * **CSS:** While this code doesn't directly handle CSS parsing, the structure it builds is the foundation upon which CSS is applied. Mention how incorrect parsing can affect CSS selectors and styling.
    * **JavaScript:** Similar to CSS, JavaScript interacts with the DOM built by this parser. Incorrect parsing can lead to JavaScript errors when trying to access or manipulate elements.

5. **Infer Logical Reasoning (Input/Output):**  Focus on the impact of specific end tags in different contexts.
    * **Example:** Consider encountering `</body>` in `kInBodyMode`. The code should pop the `body` element from the stack and potentially transition to `kAfterBodyMode`.

6. **Identify User/Programming Errors:**  Think about common mistakes developers make in HTML and how the parser reacts.
    * **Mismatched Tags:**  The parser frequently checks if the end tag matches the current open element.
    * **Incorrect Nesting:**  The insertion modes and error handling help detect and sometimes correct invalid nesting.

7. **Address the "Part 3" and Summarization Request:** Synthesize the findings into a concise summary, emphasizing the core function of processing end tags and managing parsing state.

8. **Refine and Organize:** Structure the response clearly with headings and bullet points for better readability. Use specific code examples where possible.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on individual tag handling.
* **Correction:** Realize that the insertion mode is the primary organizational principle. Group by insertion mode first, then detail tag-specific logic.
* **Initial thought:**  Only describe what the code *does*.
* **Correction:**  Explain *why* it does it (the purpose of HTML parsing, error handling, state management).
* **Initial thought:**  Provide very technical, code-level explanations.
* **Correction:**  Balance technical details with explanations understandable to someone familiar with web development concepts. Provide clear examples related to HTML, CSS, and JavaScript.

By following these steps, the detailed and informative answer addressing all aspects of the user's request can be constructed.
这是对 `blink/renderer/core/html/parser/html_tree_builder.cc` 文件中 `HTMLTreeBuilder` 类的部分代码的分析，主要关注了 **处理 HTML 结束标签** 的功能。

**功能归纳（基于提供的代码片段）：**

这段代码的主要功能是 **根据当前的解析状态（Insertion Mode）处理遇到的 HTML 结束标签**。 它负责：

* **维护和更新解析状态：**  根据遇到的结束标签，可能会切换到不同的 Insertion Mode，以确保按照 HTML 规范正确解析。
* **操作开放元素栈（Open Elements Stack）：**  遇到正确的结束标签时，会将对应的元素从开放元素栈中弹出。
* **处理错误：**  如果遇到不符合规范的结束标签（例如，没有对应的开始标签，或者嵌套错误），会调用 `ParseError` 方法报告错误。
* **处理特定标签的特殊逻辑：**  对于某些特定的结束标签（例如 `body`, `html`, 表格相关的标签），有特殊的处理逻辑，以符合 HTML 规范的要求。
* **处理格式化元素：**  在某些情况下，会清除活跃的格式化元素列表。
* **处理模板元素：**  涉及到 `template` 标签的结束处理。
* **处理表单元素：**  涉及到 `form` 标签的结束处理。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这段代码是 HTML 解析器的核心部分，它负责将 HTML 文本转换为浏览器可以理解的 DOM 树。这个过程直接影响着 JavaScript、HTML 和 CSS 的功能：

* **HTML:**  这是最直接的关系。这段代码处理 HTML 标签的结束，确保 HTML 结构正确。
    * **举例：** 当解析到 `</body>` 结束标签时，代码会从开放元素栈中弹出 `body` 元素，并可能切换到 `kAfterBodyMode` 解析状态，这保证了 HTML 文档结构的正确性。如果 `</body>` 出现在不应该出现的位置，代码会报错。
* **CSS:**  CSS 依赖于正确的 DOM 结构来应用样式。如果 HTML 结构解析错误，CSS 选择器可能无法正确匹配元素，导致样式显示异常。
    * **举例：** 如果一个 `<div>` 标签没有正确的结束标签 `</div>`，解析器可能会提前关闭该 `div` 或将其作为其他元素的子元素处理，导致后续针对该 `div` 的 CSS 样式无法正确应用。
* **JavaScript:** JavaScript 通常通过 DOM API 操作 HTML 元素。如果 HTML 结构解析错误，JavaScript 代码可能无法找到预期的元素，或者操作了错误的元素，导致逻辑错误或页面行为异常。
    * **举例：**  JavaScript 代码 `document.getElementById('myDiv')` 依赖于 ID 为 `myDiv` 的元素在 DOM 树中存在且唯一。如果解析器因为 HTML 错误没有正确创建或识别该元素，这段 JavaScript 代码将会返回 `null`，导致后续操作失败。

**逻辑推理的假设输入与输出：**

**假设输入 1:**

当前 Insertion Mode: `kInBodyMode`
遇到的 Token: `</p>` (End Tag for `<p>`)
开放元素栈顶部元素: `<p>`

**逻辑推理:**

代码会进入 `ProcessEndTagForInBody` 方法，然后匹配到 `HTMLTag::kP` 的 case。由于开放元素栈中存在 `<p>` 元素，代码会生成隐含的结束标签，如果栈顶元素不是 `<p>` 则报错，然后将 `<p>` 从开放元素栈中弹出。

**预期输出 1:**

开放元素栈顶部元素被弹出。

**假设输入 2:**

当前 Insertion Mode: `kInBodyMode`
遇到的 Token: `</div>` (End Tag for `<div>`)
开放元素栈顶部元素: `<span>` (假设没有正确的嵌套)

**逻辑推理:**

代码会进入 `ProcessEndTagForInBody` 方法，然后匹配到 `HTMLTag::kDiv` 的 case。由于开放元素栈顶部不是 `<div>`，且不在作用域内，代码会调用 `ParseError(token)` 报告错误。

**预期输出 2:**

产生一个解析错误。开放元素栈可能不会发生变化，或者会根据错误恢复机制进行调整。

**涉及用户或编程常见的使用错误及举例说明：**

* **标签不匹配：**  用户或程序员忘记写结束标签，或者结束标签与开始标签不一致。
    * **举例：**  `<div><span>This is some text.`  缺少 `</span>` 和 `</div>`。解析器在遇到后续的标签时可能会尝试自动闭合，或者产生错误，导致 DOM 结构与预期不符。
* **标签嵌套错误：**  标签的嵌套顺序不符合 HTML 规范。
    * **举例：**  `<p><div>This is some text.</p></div>`。 `p` 标签不能包含块级元素 `div`。解析器会尝试修正这种错误，但结果可能不是预期的。
* **在不允许的位置使用特定标签：**  某些标签只能在特定的上下文中使用。
    * **举例：**  在 `<td>` 标签外使用 `<tr>` 标签。解析器会报错并可能忽略该标签。

**功能归纳（针对提供的代码片段）：**

总而言之，这段代码是 `HTMLTreeBuilder` 类中处理 HTML 结束标签的核心逻辑，它根据当前的解析状态和遇到的具体标签，负责维护 DOM 树的结构，并在遇到不符合规范的 HTML 时进行错误处理，以尽可能地构建一个合理的 DOM 树供浏览器使用。它确保了 HTML 的基本结构正确性，这对于后续的 CSS 样式应用和 JavaScript 代码执行至关重要。

### 提示词
```
这是目录为blink/renderer/core/html/parser/html_tree_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// 13.
    tree_.Reparent(furthest_block, new_item);
    // 14.
    tree_.ActiveFormattingElements()->SwapTo(formatting_element, new_item,
                                             bookmark);
    // 15.
    tree_.OpenElements()->Remove(formatting_element);
    tree_.OpenElements()->InsertAbove(new_item, furthest_block);
  }
}

void HTMLTreeBuilder::ResetInsertionModeAppropriately() {
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/parsing.html#reset-the-insertion-mode-appropriately
  bool last = false;
  HTMLStackItem* item = tree_.OpenElements()->TopStackItem();
  while (true) {
    if (item->GetNode() == tree_.OpenElements()->RootNode()) {
      last = true;
      if (IsParsingFragment())
        item = fragment_context_.ContextElementStackItem();
    }
    const HTMLTag tag = item->GetHTMLTag();
    if (item->IsHTMLNamespace()) {
      switch (tag) {
        case HTMLTag::kTemplate:
          return SetInsertionMode(template_insertion_modes_.back());
        case HTMLTag::kSelect:
          if (RuntimeEnabledFeatures::SelectParserRelaxationEnabled()) {
            break;
          }
          if (!last) {
            while (item->GetNode() != tree_.OpenElements()->RootNode() &&
                   !item->MatchesHTMLTag(HTMLTag::kTemplate)) {
              item = item->NextItemInStack();
              if (item->MatchesHTMLTag(HTMLTag::kTable))
                return SetInsertionMode(kInSelectInTableMode);
            }
          }
          return SetInsertionMode(kInSelectMode);
        case HTMLTag::kTd:
        case HTMLTag::kTh:
          return SetInsertionMode(kInCellMode);
        case HTMLTag::kTr:
          return SetInsertionMode(kInRowMode);
        case HTMLTag::kTbody:
        case HTMLTag::kThead:
        case HTMLTag::kTfoot:
          return SetInsertionMode(kInTableBodyMode);
        case HTMLTag::kCaption:
          return SetInsertionMode(kInCaptionMode);
        case HTMLTag::kColgroup:
          return SetInsertionMode(kInColumnGroupMode);
        case HTMLTag::kTable:
          return SetInsertionMode(kInTableMode);
        case HTMLTag::kHead:
          if (!fragment_context_.Fragment() ||
              fragment_context_.ContextElement() != item->GetNode())
            return SetInsertionMode(kInHeadMode);
          return SetInsertionMode(kInBodyMode);
        case HTMLTag::kBody:
          return SetInsertionMode(kInBodyMode);
        case HTMLTag::kFrameset:
          return SetInsertionMode(kInFramesetMode);
        case HTMLTag::kHTML:
          if (tree_.HeadStackItem())
            return SetInsertionMode(kAfterHeadMode);

          DCHECK(IsParsingFragment());
          return SetInsertionMode(kBeforeHeadMode);
        default:
          break;
      }
    }
    if (last) {
      DCHECK(IsParsingFragment());
      return SetInsertionMode(kInBodyMode);
    }
    item = item->NextItemInStack();
  }
}

void HTMLTreeBuilder::ProcessEndTagForInTableBody(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kEndTag);
  const HTMLTag tag = token->GetHTMLTag();
  switch (tag) {
    case TABLE_BODY_CONTEXT_CASES:
      if (!tree_.OpenElements()->InTableScope(tag)) {
        ParseError(token);
        return;
      }
      tree_.OpenElements()->PopUntilTableBodyScopeMarker();
      tree_.OpenElements()->Pop();
      SetInsertionMode(kInTableMode);
      return;
    case HTMLTag::kTable:
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
      ProcessEndTag(token);
      return;
    case HTMLTag::kBody:
    case CAPTION_COL_OR_COLGROUP_CASES:
    case HTMLTag::kHTML:
    case TABLE_CELL_CONTEXT_CASES:
    case HTMLTag::kTr:
      ParseError(token);
      return;
    default:
      break;
  }
  ProcessEndTagForInTable(token);
}

void HTMLTreeBuilder::ProcessEndTagForInRow(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kEndTag);
  const HTMLTag tag = token->GetHTMLTag();
  switch (tag) {
    case HTMLTag::kTr:
      ProcessTrEndTagForInRow();
      return;
    case HTMLTag::kTable:
      if (!ProcessTrEndTagForInRow()) {
        DCHECK(IsParsingFragmentOrTemplateContents());
        return;
      }
      DCHECK_EQ(GetInsertionMode(), kInTableBodyMode);
      ProcessEndTag(token);
      return;
    case TABLE_BODY_CONTEXT_CASES:
      if (!tree_.OpenElements()->InTableScope(tag)) {
        ParseError(token);
        return;
      }
      ProcessFakeEndTag(HTMLTag::kTr);
      DCHECK_EQ(GetInsertionMode(), kInTableBodyMode);
      ProcessEndTag(token);
      return;
    case HTMLTag::kBody:
    case CAPTION_COL_OR_COLGROUP_CASES:
    case HTMLTag::kHTML:
    case TABLE_CELL_CONTEXT_CASES:
      ParseError(token);
      return;
    default:
      break;
  }
  ProcessEndTagForInTable(token);
}

void HTMLTreeBuilder::ProcessEndTagForInCell(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kEndTag);
  const HTMLTag tag = token->GetHTMLTag();
  switch (tag) {
    case TABLE_CELL_CONTEXT_CASES:
      if (!tree_.OpenElements()->InTableScope(tag)) {
        ParseError(token);
        return;
      }
      tree_.GenerateImpliedEndTags();
      if (!tree_.CurrentStackItem()->MatchesHTMLTag(tag))
        ParseError(token);
      tree_.OpenElements()->PopUntilPopped(tag);
      tree_.ActiveFormattingElements()->ClearToLastMarker();
      SetInsertionMode(kInRowMode);
      return;
    case HTMLTag::kBody:
    case CAPTION_COL_OR_COLGROUP_CASES:
    case HTMLTag::kHTML:
      ParseError(token);
      return;
    case HTMLTag::kTable:
    case HTMLTag::kTr:
    case TABLE_BODY_CONTEXT_CASES:
      if (!tree_.OpenElements()->InTableScope(tag)) {
        DCHECK(IsTableBodyContextTag(tag) ||
               tree_.OpenElements()->InTableScope(HTMLTag::kTemplate) ||
               IsParsingFragment());
        ParseError(token);
        return;
      }
      CloseTheCell();
      ProcessEndTag(token);
      return;
    default:
      break;
  }
  ProcessEndTagForInBody(token);
}

void HTMLTreeBuilder::ProcessEndTagForInBody(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kEndTag);
  const HTMLTag tag = token->GetHTMLTag();
  switch (tag) {
    case HTMLTag::kBody:
      ProcessBodyEndTagForInBody(token);
      return;
    case HTMLTag::kHTML: {
      AtomicHTMLToken end_body(HTMLToken::kEndTag, HTMLTag::kBody);
      if (ProcessBodyEndTagForInBody(&end_body))
        ProcessEndTag(token);
      return;
    }
      // https://html.spec.whatwg.org/multipage/parsing.html#:~:text=An%20end%20tag%20whose%20tag%20name%20is%20one%20of%3A%20%22address%22%2C
    case HTMLTag::kAddress:
    case HTMLTag::kArticle:
    case HTMLTag::kAside:
    case HTMLTag::kBlockquote:
    case HTMLTag::kButton:
    case HTMLTag::kCenter:
    case HTMLTag::kDetails:
    case HTMLTag::kDialog:
    case HTMLTag::kDir:
    case HTMLTag::kDiv:
    case HTMLTag::kDl:
    case HTMLTag::kFieldset:
    case HTMLTag::kFigcaption:
    case HTMLTag::kFigure:
    case HTMLTag::kFooter:
    case HTMLTag::kHeader:
    case HTMLTag::kHgroup:
    case HTMLTag::kListing:
    case HTMLTag::kMain:
    case HTMLTag::kMenu:
    case HTMLTag::kNav:
    case HTMLTag::kOl:
    case HTMLTag::kPre:
    case HTMLTag::kSearch:
    case HTMLTag::kSection:
    case HTMLTag::kSummary:
    case HTMLTag::kSelect:
    case HTMLTag::kUl:
      if (!tree_.OpenElements()->InScope(tag)) {
        ParseError(token);
        return;
      }
      tree_.GenerateImpliedEndTags();
      if (!tree_.CurrentStackItem()->MatchesHTMLTag(tag))
        ParseError(token);
      tree_.OpenElements()->PopUntilPopped(tag);
      return;
    case HTMLTag::kForm:
      if (!IsParsingTemplateContents()) {
        Element* node = tree_.TakeForm();
        if (!node || !tree_.OpenElements()->InScope(node)) {
          ParseError(token);
          return;
        }
        tree_.GenerateImpliedEndTags();
        if (tree_.CurrentElement() != node)
          ParseError(token);
        tree_.OpenElements()->Remove(node);
        if (RuntimeEnabledFeatures::CorrectTemplateFormParsingEnabled()) {
          return;
        }
      }
      if (RuntimeEnabledFeatures::CorrectTemplateFormParsingEnabled()) {
        if (!tree_.OpenElements()->InScope(tag)) {
          ParseError(token);
          return;
        }
        tree_.GenerateImpliedEndTags();
        if (!tree_.CurrentStackItem()->MatchesHTMLTag(tag)) {
          ParseError(token);
        }
        tree_.OpenElements()->PopUntilPopped(tag);
        return;
      }
      break;
    case HTMLTag::kP:
      if (!tree_.OpenElements()->InButtonScope(tag)) {
        ParseError(token);
        ProcessFakeStartTag(HTMLTag::kP);
        DCHECK(tree_.OpenElements()->InScope(tag));
        ProcessEndTag(token);
        return;
      }
      tree_.GenerateImpliedEndTagsWithExclusion(token->GetTokenName());
      if (!tree_.CurrentStackItem()->MatchesHTMLTag(tag))
        ParseError(token);
      tree_.OpenElements()->PopUntilPopped(tag);
      return;
    case HTMLTag::kLi:
      if (!tree_.OpenElements()->InListItemScope(tag)) {
        ParseError(token);
        return;
      }
      tree_.GenerateImpliedEndTagsWithExclusion(token->GetTokenName());
      if (!tree_.CurrentStackItem()->MatchesHTMLTag(tag))
        ParseError(token);
      tree_.OpenElements()->PopUntilPopped(tag);
      return;
    case HTMLTag::kDd:
    case HTMLTag::kDt:
      if (!tree_.OpenElements()->InScope(tag)) {
        ParseError(token);
        return;
      }
      tree_.GenerateImpliedEndTagsWithExclusion(token->GetTokenName());
      if (!tree_.CurrentStackItem()->MatchesHTMLTag(tag))
        ParseError(token);
      tree_.OpenElements()->PopUntilPopped(tag);
      return;
    case HTMLTag::kH1:
    case HTMLTag::kH2:
    case HTMLTag::kH3:
    case HTMLTag::kH4:
    case HTMLTag::kH5:
    case HTMLTag::kH6:
      if (!tree_.OpenElements()->HasNumberedHeaderElementInScope()) {
        ParseError(token);
        return;
      }
      tree_.GenerateImpliedEndTags();
      if (!tree_.CurrentStackItem()->MatchesHTMLTag(tag))
        ParseError(token);
      tree_.OpenElements()->PopUntilNumberedHeaderElementPopped();
      return;
    case HTMLTag::kA:
    case HTMLTag::kNobr:
    case HTMLTag::kB:
    case HTMLTag::kBig:
    case HTMLTag::kCode:
    case HTMLTag::kEm:
    case HTMLTag::kFont:
    case HTMLTag::kI:
    case HTMLTag::kS:
    case HTMLTag::kSmall:
    case HTMLTag::kStrike:
    case HTMLTag::kStrong:
    case HTMLTag::kTt:
    case HTMLTag::kU:
      CallTheAdoptionAgency(token);
      return;
    case HTMLTag::kApplet:
    case HTMLTag::kMarquee:
    case HTMLTag::kObject:
      if (!tree_.OpenElements()->InScope(tag)) {
        ParseError(token);
        return;
      }
      tree_.GenerateImpliedEndTags();
      if (!tree_.CurrentStackItem()->MatchesHTMLTag(tag))
        ParseError(token);
      tree_.OpenElements()->PopUntilPopped(tag);
      tree_.ActiveFormattingElements()->ClearToLastMarker();
      return;
    case HTMLTag::kBr:
      ParseError(token);
      ProcessFakeStartTag(HTMLTag::kBr);
      return;
    case HTMLTag::kTemplate:
      ProcessTemplateEndTag(token);
      return;
    default:
      break;
  }
  ProcessAnyOtherEndTagForInBody(token);
}

bool HTMLTreeBuilder::ProcessCaptionEndTagForInCaption() {
  if (!tree_.OpenElements()->InTableScope(HTMLTag::kCaption)) {
    DCHECK(IsParsingFragment());
    // FIXME: parse error
    return false;
  }
  tree_.GenerateImpliedEndTags();
  // FIXME: parse error if
  // (!tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kCaption))
  tree_.OpenElements()->PopUntilPopped(HTMLTag::kCaption);
  tree_.ActiveFormattingElements()->ClearToLastMarker();
  SetInsertionMode(kInTableMode);
  return true;
}

bool HTMLTreeBuilder::ProcessTrEndTagForInRow() {
  if (!tree_.OpenElements()->InTableScope(HTMLTag::kTr)) {
    DCHECK(IsParsingFragmentOrTemplateContents());
    // FIXME: parse error
    return false;
  }
  tree_.OpenElements()->PopUntilTableRowScopeMarker();
  DCHECK(tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kTr));
  tree_.OpenElements()->Pop();
  SetInsertionMode(kInTableBodyMode);
  return true;
}

bool HTMLTreeBuilder::ProcessTableEndTagForInTable() {
  if (!tree_.OpenElements()->InTableScope(HTMLTag::kTable)) {
    DCHECK(IsParsingFragmentOrTemplateContents());
    // FIXME: parse error.
    return false;
  }
  tree_.OpenElements()->PopUntilPopped(HTMLTag::kTable);
  ResetInsertionModeAppropriately();
  return true;
}

void HTMLTreeBuilder::ProcessEndTagForInTable(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kEndTag);
  switch (token->GetHTMLTag()) {
    case HTMLTag::kTable:
      ProcessTableEndTagForInTable();
      return;
    case HTMLTag::kBody:
    case CAPTION_COL_OR_COLGROUP_CASES:
    case HTMLTag::kHTML:
    case TABLE_BODY_CONTEXT_CASES:
    case TABLE_CELL_CONTEXT_CASES:
    case HTMLTag::kTr:
      ParseError(token);
      return;
    default:
      break;
  }
  ParseError(token);
  // Is this redirection necessary here?
  HTMLConstructionSite::RedirectToFosterParentGuard redirecter(tree_);
  ProcessEndTagForInBody(token);
}

void HTMLTreeBuilder::ProcessEndTag(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kEndTag);
  const HTMLTag tag = token->GetHTMLTag();
  switch (GetInsertionMode()) {
    case kInitialMode:
      DefaultForInitial();
      [[fallthrough]];
    case kBeforeHTMLMode:
      switch (tag) {
        case HTMLTag::kHead:
        case HTMLTag::kBody:
        case HTMLTag::kHTML:
        case HTMLTag::kBr:
          break;
        default:
          ParseError(token);
          return;
      }
      DefaultForBeforeHTML();
      [[fallthrough]];
    case kBeforeHeadMode:
      switch (tag) {
        case HTMLTag::kHead:
        case HTMLTag::kBody:
        case HTMLTag::kHTML:
        case HTMLTag::kBr:
          break;
        default:
          ParseError(token);
          return;
      }
      DefaultForBeforeHead();
      [[fallthrough]];
    case kInHeadMode:
      // FIXME: This case should be broken out into processEndTagForInHead,
      // because other end tag cases now refer to it ("process the token for
      // using the rules of the "in head" insertion mode"). but because the
      // logic falls through to AfterHeadMode, that gets a little messy.
      switch (tag) {
        case HTMLTag::kTemplate:
          ProcessTemplateEndTag(token);
          return;
        case HTMLTag::kHead:
          tree_.OpenElements()->PopHTMLHeadElement();
          SetInsertionMode(kAfterHeadMode);
          return;
        case HTMLTag::kBody:
        case HTMLTag::kHTML:
        case HTMLTag::kBr:
          break;
        default:
          ParseError(token);
          return;
      }
      DefaultForInHead();
      [[fallthrough]];
    case kAfterHeadMode:
      switch (tag) {
        case HTMLTag::kBody:
        case HTMLTag::kHTML:
        case HTMLTag::kBr:
          break;
        default:
          ParseError(token);
          return;
      }
      DefaultForAfterHead();
      [[fallthrough]];
    case kInBodyMode:
      ProcessEndTagForInBody(token);
      break;
    case kInTableMode:
      ProcessEndTagForInTable(token);
      break;
    case kInCaptionMode:
      switch (tag) {
        case HTMLTag::kCaption:
          ProcessCaptionEndTagForInCaption();
          return;
        case HTMLTag::kTable:
          ParseError(token);
          if (!ProcessCaptionEndTagForInCaption()) {
            DCHECK(IsParsingFragment());
            return;
          }
          ProcessEndTag(token);
          return;
        case HTMLTag::kBody:
        case HTMLTag::kCol:
        case HTMLTag::kColgroup:
        case HTMLTag::kHTML:
        case TABLE_BODY_CONTEXT_CASES:
        case TABLE_CELL_CONTEXT_CASES:
        case HTMLTag::kTr:
          ParseError(token);
          return;
        default:
          break;
      }
      ProcessEndTagForInBody(token);
      break;
    case kInColumnGroupMode:
      switch (tag) {
        case HTMLTag::kColgroup:
          ProcessColgroupEndTagForInColumnGroup();
          return;
        case HTMLTag::kCol:
          ParseError(token);
          return;
        case HTMLTag::kTemplate:
          ProcessTemplateEndTag(token);
          return;
        default:
          break;
      }
      if (!ProcessColgroupEndTagForInColumnGroup()) {
        DCHECK(IsParsingFragmentOrTemplateContents());
        return;
      }
      ProcessEndTag(token);
      break;
    case kInRowMode:
      ProcessEndTagForInRow(token);
      break;
    case kInCellMode:
      ProcessEndTagForInCell(token);
      break;
    case kInTableBodyMode:
      ProcessEndTagForInTableBody(token);
      break;
    case kAfterBodyMode:
      if (tag == HTMLTag::kHTML) {
        if (IsParsingFragment()) {
          ParseError(token);
          return;
        }
        SetInsertionMode(kAfterAfterBodyMode);
        return;
      }
      [[fallthrough]];
    case kAfterAfterBodyMode:
      ParseError(token);
      SetInsertionMode(kInBodyMode);
      ProcessEndTag(token);
      break;
    case kInHeadNoscriptMode:
      if (tag == HTMLTag::kNoscript) {
        DCHECK(tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kNoscript));
        tree_.OpenElements()->Pop();
        DCHECK(tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kHead));
        SetInsertionMode(kInHeadMode);
        return;
      }
      if (tag != HTMLTag::kBr) {
        ParseError(token);
        return;
      }
      DefaultForInHeadNoscript();
      ProcessToken(token);
      break;
    case kTextMode:
      if (tag == HTMLTag::kScript &&
          tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kScript)) {
        // Pause ourselves so that parsing stops until the script can be
        // processed by the caller.
        if (ScriptingContentIsAllowed(tree_.GetParserContentPolicy()))
          script_to_process_ = tree_.CurrentElement();
        tree_.OpenElements()->Pop();
        SetInsertionMode(original_insertion_mode_);

        // We must set the tokenizer's state to DataState explicitly if the
        // tokenizer didn't have a chance to.
        parser_->tokenizer().SetState(HTMLTokenizer::kDataState);
        return;
      }
      tree_.OpenElements()->Pop();
      SetInsertionMode(original_insertion_mode_);
      break;
    case kInFramesetMode:
      if (tag == HTMLTag::kFrameset) {
        bool ignore_frameset_for_fragment_parsing = tree_.CurrentIsRootNode();
        ignore_frameset_for_fragment_parsing =
            ignore_frameset_for_fragment_parsing ||
            tree_.OpenElements()->HasTemplateInHTMLScope();
        if (ignore_frameset_for_fragment_parsing) {
          DCHECK(IsParsingFragmentOrTemplateContents());
          ParseError(token);
          return;
        }
        tree_.OpenElements()->Pop();
        if (!IsParsingFragment() &&
            !tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kFrameset)) {
          SetInsertionMode(kAfterFramesetMode);
        }
        return;
      }
      break;
    case kAfterFramesetMode:
      if (tag == HTMLTag::kHTML) {
        SetInsertionMode(kAfterAfterFramesetMode);
        return;
      }
      [[fallthrough]];
    case kAfterAfterFramesetMode:
      ParseError(token);
      break;
    case kInSelectInTableMode:
      switch (tag) {
        case HTMLTag::kCaption:
        case HTMLTag::kTable:
        case TABLE_BODY_CONTEXT_CASES:
        case HTMLTag::kTr:
        case TABLE_CELL_CONTEXT_CASES:
          ParseError(token);
          if (tree_.OpenElements()->InTableScope(tag)) {
            AtomicHTMLToken end_select(HTMLToken::kEndTag, HTMLTag::kSelect);
            ProcessEndTag(&end_select);
            ProcessEndTag(token);
          }
          return;
        default:
          break;
      }
      [[fallthrough]];
    case kInSelectMode:
      CHECK(!RuntimeEnabledFeatures::SelectParserRelaxationEnabled());
      switch (tag) {
        case HTMLTag::kOptgroup:
          if (tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kOption) &&
              tree_.OneBelowTop() &&
              tree_.OneBelowTop()->MatchesHTMLTag(HTMLTag::kOptgroup))
            ProcessFakeEndTag(HTMLTag::kOption);
          if (tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kOptgroup)) {
            tree_.OpenElements()->Pop();
            return;
          }
          ParseError(token);
          return;
        case HTMLTag::kOption:
          if (tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kOption)) {
            tree_.OpenElements()->Pop();
            return;
          }
          ParseError(token);
          return;
        case HTMLTag::kSelect:
          if (!tree_.OpenElements()->InSelectScope(tag)) {
            DCHECK(IsParsingFragment());
            ParseError(token);
            return;
          }
          tree_.OpenElements()->PopUntilPopped(HTMLTag::kSelect);
          ResetInsertionModeAppropriately();
          return;
        case HTMLTag::kTemplate:
          ProcessTemplateEndTag(token);
          return;
        default:
          break;
      }
      break;
    case kInTableTextMode:
      DefaultForInTableText();
      ProcessEndTag(token);
      break;
    case kTemplateContentsMode:
      if (tag == HTMLTag::kTemplate) {
        ProcessTemplateEndTag(token);
        return;
      }
      break;
  }
}

void HTMLTreeBuilder::ProcessComment(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kComment);
  if (GetInsertionMode() == kInitialMode ||
      GetInsertionMode() == kBeforeHTMLMode ||
      GetInsertionMode() == kAfterAfterBodyMode ||
      GetInsertionMode() == kAfterAfterFramesetMode) {
    tree_.InsertCommentOnDocument(token);
    return;
  }
  if (GetInsertionMode() == kAfterBodyMode) {
    tree_.InsertCommentOnHTMLHtmlElement(token);
    return;
  }
  if (GetInsertionMode() == kInTableTextMode) {
    DefaultForInTableText();
    ProcessComment(token);
    return;
  }
  tree_.InsertComment(token);
}

void HTMLTreeBuilder::ProcessDOMPart(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kDOMPart);
  DCHECK(tree_.InParsePartsScope());
  tree_.InsertDOMPart(token);
}

void HTMLTreeBuilder::ProcessCharacter(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kCharacter);
  CharacterTokenBuffer buffer(token);
  ProcessCharacterBuffer(buffer);
}

void HTMLTreeBuilder::ProcessCharacterBuffer(CharacterTokenBuffer& buffer) {
ReprocessBuffer:
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tokenization.html#parsing-main-inbody
  // Note that this logic is different than the generic \r\n collapsing
  // handled in the input stream preprocessor. This logic is here as an
  // "authoring convenience" so folks can write:
  //
  // <pre>
  // lorem ipsum
  // lorem ipsum
  // </pre>
  //
  // without getting an extra newline at the start of their <pre> element.
  if (should_skip_leading_newline_) {
    should_skip_leading_newline_ = false;
    buffer.SkipAtMostOneLeadingNewline();
    if (buffer.IsEmpty())
      return;
  }

  switch (GetInsertionMode()) {
    case kInitialMode: {
      buffer.SkipLeadingWhitespace();
      if (buffer.IsEmpty())
        return;
      DefaultForInitial();
      [[fallthrough]];
    }
    case kBeforeHTMLMode: {
      buffer.SkipLeadingWhitespace();
      if (buffer.IsEmpty())
        return;
      DefaultForBeforeHTML();
      if (parser_->IsStopped()) {
        buffer.SkipRemaining();
        return;
      }
      [[fallthrough]];
    }
    case kBeforeHeadMode: {
      buffer.SkipLeadingWhitespace();
      if (buffer.IsEmpty())
        return;
      DefaultForBeforeHead();
      [[fallthrough]];
    }
    case kInHeadMode: {
      auto leading_whitespace = buffer.TakeLeadingWhitespace();
      if (!leading_whitespace.string.empty()) {
        tree_.InsertTextNode(leading_whitespace.string,
                             leading_whitespace.whitespace_mode);
      }
      if (buffer.IsEmpty())
        return;
      DefaultForInHead();
      [[fallthrough]];
    }
    case kAfterHeadMode: {
      auto leading_whitespace = buffer.TakeLeadingWhitespace();
      if (!leading_whitespace.string.empty()) {
        tree_.InsertTextNode(leading_whitespace.string,
                             leading_whitespace.whitespace_mode);
      }
      if (buffer.IsEmpty())
        return;
      DefaultForAfterHead();
      [[fallthrough]];
    }
    case kInBodyMode:
    case kInCaptionMode:
    case kTemplateContentsMode:
    case kInCellMode: {
      ProcessCharacterBufferForInBody(buffer);
      break;
    }
    case kInTableMode:
    case kInTableBodyMode:
    case kInRowMode: {
      DCHECK(pending_table_characters_.empty());
      if (tree_.CurrentStackItem()->IsElementNode() &&
          (tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kTable) ||
           tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kTbody) ||
           tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kTfoot) ||
           tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kThead) ||
           tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kTr))) {
        original_insertion_mode_ = insertion_mode_;
        SetInsertionMode(kInTableTextMode);
        // Note that we fall through to the InTableTextMode case below.
      } else {
        HTMLConstructionSite::RedirectToFosterParentGuard redirecter(tree_);
        ProcessCharacterBufferForInBody(buffer);
        break;
      }
      [[fallthrough]];
    }
    case kInTableTextMode: {
      buffer.GiveRemainingTo(pending_table_characters_);
      break;
    }
    case kInColumnGroupMode: {
      auto leading_whitespace = buffer.TakeLeadingWhitespace();
      if (!leading_whitespace.string.empty()) {
        tree_.InsertTextNode(leading_whitespace.string,
                             leading_whitespace.whitespace_mode);
      }
      if (buffer.IsEmpty())
        return;
      if (!ProcessColgroupEndTagForInColumnGroup()) {
        DCHECK(IsParsingFragmentOrTemplateContents());
        // The spec tells us to drop these characters on the floor.
        buffer.SkipLeadingNonWhitespace();
        if (buffer.IsEmpty())
          return;
      }
      goto ReprocessBuffer;
    }
    case kAfterBodyMode:
    case kAfterAfterBodyMode: {
      // FIXME: parse error
      auto leading_whitespace = buffer.TakeLeadingWhitespace();
      if (!leading_whitespace.string.empty()) {
        InsertionMode mode = GetInsertionMode();
        SetInsertionMode(kInBodyMode);
        tree_.InsertTextNode(leading_whitespace.string,
                             leading_whitespace.whitespace_mode);
        SetInsertionMode(mode);
      }
      if (buffer.IsEmpty())
        return;
      SetInsertionMode(kInBodyMode);
      goto ReprocessBuffer;
    }
    case kTextMode: {
      tree_.InsertTextNode(buffer.TakeRemaining());
      break;
    }
    case kInHeadNoscriptMode: {
      auto leading_whitespace = buffer.TakeLeadingWhitespace();
      if (!leading_whitespace.string.empty()) {
        tree_.InsertTextNode(leading_whitespace.string,
                             leading_whitespace.whitespace_mode);
      }
      if (buffer.IsEmpty()) {
        return;
      }
      DefaultForInHeadNoscript();
      goto ReprocessBuffer;
    }
    case kInFramesetMode:
    case kAfterFramesetMode: {
      auto leading_whitespace = buffer.TakeRemainingWhitespace();
      if (!leading_whitespace.string.empty()) {
        tree_.InsertTextNode(leading_whitespace.string,
                             leading_whitespace.whitespace_mode);
      }
      // FIXME: We should generate a parse error if we skipped over any
      // non-whitespace characters.
      break;
    }
    case kInSelectInTableMode:
    case kInSelectMode: {
      tree_.InsertTextNode(buffer.TakeRemaining());
      break;
    }
    case kAfterAfterFramesetMode: {
      auto leading_whitespace = buffer.TakeRemainingWhitespace();
      if (!leading_whitespace.string.empty()) {
        tree_.ReconstructTheActiveFormattingElements();
        tree_.InsertTextNode(leading_whitespace.string,
                             leading_whitespace.whitespace_mode);
      }
      // FIXME: We should generate a parse error if we skipped over any
      // non-whitespace characters.
      break;
    }
  }
}

void HTMLTreeBuilder::ProcessCharacterBufferForInBody(
    CharacterTokenBuffer& buffer) {
  tree_.ReconstructTheActiveFormattingElements();
  StringView characters = buffer.TakeRemaining();
  tree_.InsertTextNode(characters);
  if (frameset_ok_ && !IsAllWhitespaceOrReplacementCharacters(characters))
    frameset_ok_ = false;
}

void HTMLTreeBuilder::ProcessEndOfFile(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kEndOfFile);
  switch (GetInsertionMode()) {
    case kInitialMode:
      DefaultForInitial();
      [[fallthrough]];
    case kBeforeHTMLMode:
      DefaultForBeforeHTML();
      [[fallthrough]];
    case kBeforeHeadMode:
      DefaultForBeforeHead();
      [[fallthrough]];
    case kInHeadMode:
      DefaultForInHead();
      [[fallthrough]];
    case kAfterHeadMode:
      DefaultForAfterHead();
      [[fallthrough]];
    case kInBodyMode:
    case kInCellMode:
    case kInCaptionMode:
    case kInRowMode:
      // Emit parse error based on what elements are still open.
      DVLOG(1) << "Not implemented.";
      if (!template_insertion_modes_.empty() &&
          ProcessEndOfFileForInTemplateContents(token))
        return;
      break;
    case kAfterBodyMode:
    case kAfterAfterBodyMode:
      break;
    case kInHeadNoscriptMode:
      DefaultForInHeadNoscript();
      ProcessEndOfFile(token);
      return;
    case kAfterFramesetMode:
    case kAfterAfterFramesetMode:
      break;
    case kInColumnGroupMode:
      if (tree_.CurrentIsRootNode()) {
        DCHECK(IsParsingFragment());
        return;  // FIXME: Should we break here instead of returning?
      }
      DCHECK(tree_.CurrentNode()->HasTagName(html_names::kColgroupTag) ||
             IsA<HTMLTemplateElement>(tree_.CurrentNode()));
      ProcessColgroupEndTagForInColumnGroup();
      [[fallthrough]];
    case kInFramesetMode:
    case kInTableMode:
    case kInTableBodyMode:
    case kInSelectInTableMode:
    case kInSelectMode:
      if (tree_.CurrentNode() != tree_.OpenElements()->RootNode())
        ParseError(token);
      if (!template_insertion_modes_.empty() &&
          ProcessEndOfFileForInTemplateContents(token))
        return;
      break;
    case kInTableTextMode:
      DefaultForInTableText();
      ProcessEndOfFile(token);
      return;
    case kTextMode: {
      ParseError(token);
      if (tree_.CurrentStackItem()->MatchesHTMLTag(HTMLTag::kScript)) {
        // Mark the script element as "already started".
        DVLOG(1) << "Not implemented.";
      }
      Element* el = tree_.OpenElements()->Top();
      if (IsA<HTMLTextAreaElement>(el))
        To<HTMLFormControlElement>(el)->SetBlocksFormSubmission(true);
      tree_.OpenElements()->Pop();
      DCHECK_NE(original_insertion_mode_, kTextMode);
      SetInsertionMode(original_insertion_mode_);
      ProcessEndOfFile(token);
      return;
    }
    case kTemplateContentsMode:
      if (ProcessEndOfFileForInTemplateContents(token))
        return;
      break;
  }
  tree_.ProcessEndOfFile();
}

void HTMLTreeBuilder::DefaultForInitial() {
  DVLOG(1) << "Not implemented.";
  tree_.SetDefaultCompatibilityMode();
  // FIXME: parse error
  SetInsertionMode(kBeforeHTMLMode);
}

void HTMLTreeBuilder::DefaultForBeforeHTML() {
  AtomicHTMLToken start_html(HTMLToken::kStartTag, HTMLTag::kHTML);
  tree_.InsertHTMLHtmlStartTagBeforeHTML(&start_html);
  SetInsertionMode(kBeforeHeadMode);
}

void HTMLTreeBuilder::DefaultForBeforeHead() {
  AtomicHTMLToken start_head(HTMLToken::kStartTag, HTMLTag::kHead);
  ProcessStartTag(&start_head);
}

void HTMLTreeBuilder::DefaultForInHead() {
  AtomicHTMLToken end_head(HTMLToken::kEndTag, HTMLTag::kHead);
  ProcessEndTag(&end_head);
}

void HTMLTreeBuilder::DefaultForInHeadNoscript() {
  AtomicHTMLToken end_noscript(HTMLToken::kEndTag, HTMLTag::kNoscript);
  ProcessEndTag(&end_noscript);
}

void HTMLTreeBuilder::DefaultForAfterHead() {
  AtomicHTMLToken start_body(HTMLToken::kStartTag, HTMLTag::kBody);
  ProcessStartTag(&start_body)
```