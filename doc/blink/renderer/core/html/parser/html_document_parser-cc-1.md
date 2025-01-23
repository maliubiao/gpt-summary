Response:
The user wants a summary of the functionality of the `HTMLDocumentParser.cc` file, specifically focusing on:

1. **General Functionality:**  What does this code do?
2. **Relationship with Web Technologies:** How does it interact with JavaScript, HTML, and CSS? Provide examples.
3. **Logic and Reasoning:**  Are there logical steps or inferences made in the code?  If so, illustrate with hypothetical inputs and outputs.
4. **Common User/Programming Errors:**  Are there scenarios where incorrect usage could lead to problems? Give examples.
5. **Summary of Functionality (Part 2):**  Synthesize the information from the provided code snippet.

**Mental Model for Processing the Snippet:**

The code snippet primarily deals with the `PumpTokenizer` function and the scheduling/handling of parsing tasks. It also touches on preloading.

**Plan:**

1. **Analyze `PumpTokenizer`:**  Break down the loop and its conditions. Identify the core tasks: tokenization, tree construction, script execution, and yielding.
2. **Identify Web Technology Relationships:** Connect the actions in `PumpTokenizer` (tokenization, tree construction, script handling) to HTML, CSS, and JavaScript.
3. **Infer Logic and Reasoning:**  Focus on the conditional logic within the loop (budget checks, yielding conditions). Create simple scenarios to illustrate how these conditions affect parsing flow.
4. **Consider Potential Errors:**  Think about what could go wrong if the parser gets stuck, doesn't yield, or if preloading fails.
5. **Summarize Part 2:** Concisely describe the actions within the provided code block.
这是 `blink/renderer/core/html/parser/html_document_parser.cc` 文件的一部分，主要负责 HTML 文档的解析工作。结合你提供的代码片段，我们可以归纳一下它的功能：

**主要功能 (基于提供的代码片段):**

这段代码主要实现了 `HTMLDocumentParser::PumpTokenizer` 函数，其核心功能是驱动 HTML 词法分析器（Tokenizer）从输入流中读取 HTML 标记（Tokens），并将这些标记传递给 HTML 树构建器（Tree Builder）来构建 DOM 树。此外，它还涉及性能优化、资源预加载以及与脚本执行的协调。

**功能细分和与 Web 技术的关系：**

1. **驱动词法分析 (Tokenization):**
   - `PumpTokenizer` 函数的核心是一个循环，不断调用 `tokenizer_->NextToken(atomic_html_token)` 从输入流中提取下一个 HTML 标记。
   - **与 HTML 的关系:** 这是将 HTML 文本转换为结构化数据的首要步骤。输入的 HTML 文本会被分解成各种标记，例如开始标签 (`<p>`)，结束标签 (`</p>`)，文本内容，注释等等。
   - **假设输入:**  HTML 字符串 `"<div>Hello</div>"`
   - **输出:**  词法分析器会依次产生 `<div>` 开始标签的 Token，`Hello` 文本内容的 Token，`</div>` 结束标签的 Token。

2. **构建 DOM 树 (Tree Building):**
   -  `ConstructTreeFromToken(atomic_html_token)` 函数负责接收词法分析器产生的标记，并将其插入到 DOM 树中。 `tree_builder_->ConstructTree(&atomic_html_token)` 是实际进行 DOM 树构建的地方。
   - **与 HTML 的关系:**  这是将 HTML 标记转化为浏览器可理解和渲染的 DOM 结构的关键步骤。不同的 HTML 标记会导致在 DOM 树中创建不同的节点（例如，`<div>` 创建 `HTMLDivElement` 节点）。
   - **假设输入:**  `<div>` 开始标签的 Token
   - **输出:**  在当前的 DOM 树上下文中创建一个 `HTMLDivElement` 节点。

3. **处理 JavaScript (Script Execution):**
   - 代码中通过 `IsPaused()` 和 `IsExecutingScript()` 检查当前是否因为脚本执行而暂停了解析。
   - 当遇到 `<script>` 标签时，解析过程可能会暂停，等待脚本加载和执行。`time_executing_script` 变量用于记录脚本执行的时间，以便在性能监控中扣除。
   - **与 JavaScript 的关系:** HTML 解析器需要与 JavaScript 执行引擎协调，确保脚本在正确的时机执行，并且脚本的执行可能会影响 DOM 树的构建。
   - **假设场景:**  HTML 中包含 `<script src="my.js"></script>`。
   - **逻辑推理:**  解析器遇到 `<script>` 标签后，可能会暂停解析，直到 `my.js` 加载并执行完毕。

4. **处理 CSS (Stylesheet Blocking):**
   - `CheckIfBlockingStylesheetAdded()` 函数检查是否有阻塞渲染的 CSS 样式表被添加到文档中。如果存在，解析器可能会暂停，等待样式表加载和解析完成，以避免在样式应用前渲染不完整的页面。
   - **与 CSS 的关系:** CSS 样式会影响页面的渲染，因此 HTML 解析器需要考虑 CSS 的加载和解析状态。阻塞渲染的 CSS 会延迟页面的首次绘制。
   - **假设场景:**  HTML 中包含 `<link rel="stylesheet" href="style.css">` 并且 `style.css` 是一个外部样式表。
   - **逻辑推理:** 解析器在处理到这个 `<link>` 标签时，可能会检查 `style.css` 的加载状态。如果该样式表被认为是阻塞渲染的，解析器可能会暂停。

5. **性能优化 (Time Budget and Yielding):**
   - 代码中使用了 `timed_budget` 和 `budget` 来控制解析器运行的时间或标记数量。当达到预算限制时，解析器会主动让出执行权 (`should_yield = true`)，避免长时间阻塞主线程，提高用户体验。
   - `scheduler_->ShouldYieldForHighPriorityWork()` 和 `task_runner_state_->ShouldYieldForPreloads()` 等函数也用于判断是否需要为更高优先级的工作或预加载让步。
   - **假设场景:** 正在解析一个非常大的 HTML 文件。
   - **逻辑推理:**  `PumpTokenizer` 函数会根据设定的时间或标记预算，周期性地暂停解析，让浏览器有机会处理其他任务（例如渲染、用户交互）。

6. **资源预加载 (Preloading):**
   - 当解析器处于空闲状态 (`IsPaused()`) 并且存在预加载器 (`preloader_`) 时，代码会尝试使用 `preload_scanner_` 扫描后续的 HTML 内容，提前发现并加载资源（例如图片、脚本、样式表），以加速页面加载速度。
   - **与 HTML 的关系:**  预加载器会扫描 HTML 结构，查找可以提前加载的资源链接。
   - **假设场景:**  解析器解析到 `<body>` 标签后，由于某个脚本正在加载而暂停。
   - **逻辑推理:**  此时，`preload_scanner_` 可能会扫描 `<body>` 标签之后的 HTML 内容，发现 `<img>` 标签，并提前发起图片资源的加载请求。

7. **错误处理和状态检查:**
   - 代码中包含 `CHECK(!IsStopped())` 等断言，用于在开发阶段检测代码的逻辑错误。
   - `IsStopped()` 和 `IsParsingFragment()` 等函数用于检查解析器的当前状态，避免在错误的状态下执行操作。

**用户或编程常见的使用错误举例：**

1. **编写了阻塞渲染的 JavaScript 或 CSS:**  如果 HTML 中引入了大量的同步 JavaScript 或 CSS，会导致解析器长时间阻塞，页面出现白屏或加载缓慢。浏览器会尝试优化，但过多的阻塞资源仍然会影响性能。
   - **假设输入:**  HTML 中包含 `<script>document.write('...')</script>` 或引入了非常大的同步 CSS 文件。
   - **结果:**  `PumpTokenizer` 函数可能会因为等待脚本执行或 CSS 加载而长时间运行，导致页面渲染延迟。

2. **在 `document.write()` 中插入大量内容:**  虽然代码中考虑了 `insert()` 方法，但在解析过程中过度使用 `document.write()` 动态插入内容可能会导致解析器的状态复杂化，影响性能，甚至引发不可预测的行为。

3. **不合理的预加载策略:**  如果预加载的资源过多或者策略不当，可能会浪费带宽，反而降低页面加载速度。浏览器会尽力优化预加载，但开发者仍然需要注意预加载资源的合理性。

**总结 (基于提供的代码片段):**

`HTMLDocumentParser::PumpTokenizer`  是 HTML 文档解析过程中的核心驱动函数。它循环地从输入流中读取 HTML 标记，并将这些标记传递给树构建器来构建 DOM 树。为了提高性能和用户体验，它还会考虑时间预算，并在必要时让出执行权。此外，当解析器处于空闲状态时，它会利用预加载扫描器提前发现并加载资源。这段代码还体现了 HTML 解析器与 JavaScript 和 CSS 之间的紧密联系，需要协调脚本的执行和处理阻塞渲染的样式表。

请注意，这只是 `HTMLDocumentParser.cc` 文件的一部分功能，更完整的功能还包括错误处理、字符编码处理、各种 HTML 语法规则的实现等等。

### 提示词
```
这是目录为blink/renderer/core/html/parser/html_document_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
timer occasionally.
          if (ShouldCheckTimeBudget(next_token_status,
                                    atomic_html_token.GetHTMLTag(),
                                    newly_consumed_characters, tokens_parsed)) {
            elapsed_time = chunk_parsing_timer.Elapsed();
          }
        } else {
          elapsed_time = chunk_parsing_timer.Elapsed();
        }
        should_yield = elapsed_time >= timed_budget;
      } else {
        should_yield = budget <= 0;
      }
      should_yield |= scheduler_->ShouldYieldForHighPriorityWork();
      should_yield &= task_runner_state_->HaveExitedHeader();
      // Yield for preloads even if we haven't exited the header, since they
      // should be dispatched as soon as possible.
      if (task_runner_state_->ShouldYieldForPreloads()) {
        should_yield |= HasPendingPreloads();
      }

      if (should_yield)
        break;
    }
  }

  base::TimeDelta pump_tokenizer_elapsed_time = pump_tokenizer_timer.Elapsed();
  if (metrics_sub_sampler_.ShouldSample(0.01)) {
    base::UmaHistogramTimes("Blink.PumpTokenizerTime",
                            pump_tokenizer_elapsed_time);
  }
  if (metrics_reporter_) {
    metrics_reporter_->AddPumpTokenizerTime(
        pump_tokenizer_elapsed_time.InMicroseconds());
  }

  if (is_tracing) {
    TRACE_EVENT_END2("blink", "HTMLDocumentParser::PumpTokenizer",
                     "parsed_tokens", tokens_parsed, "parsed_bytes",
                     starting_bytes - input_.length());
  }

  const bool is_stopped_or_parsing_fragment =
      IsStopped() || IsParsingFragment();

  if (!is_stopped_or_parsing_fragment) {
    // There should only be PendingText left since the tree-builder always
    // flushes the task queue before returning. In case that ever changes,
    // crash.
    tree_builder_->Flush();
    CHECK(!IsStopped());
  }

  if (tokens_parsed && metrics_reporter_) {
    metrics_reporter_->AddChunk(
        chunk_parsing_timer.Elapsed() - time_executing_script, tokens_parsed);
  }

  if (is_stopped_or_parsing_fragment)
    return false;

  if (IsPaused() && preloader_ && !background_scanner_ &&
      !should_skip_preload_scan_) {
    if (!preload_scanner_) {
      preload_scanner_ =
          CreatePreloadScanner(TokenPreloadScanner::ScannerType::kMainDocument);
      preload_scanner_->AppendToEnd(input_.Current());
    }
    ScanAndPreload(preload_scanner_.get());
  }

  // should_run_until_completion implies that we should not yield
  CHECK(!should_run_until_completion || !should_yield);
  if (should_yield)
    task_runner_state_->MarkYield();

  return should_yield;
}

void HTMLDocumentParser::SchedulePumpTokenizer(bool from_finish_append) {
  TRACE_EVENT_WITH_FLOW0("blink", "HTMLDocumentParser::SchedulePumpTokenizer",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  DCHECK(!IsStopped());
  DCHECK(!task_runner_state_->InPumpSession());
  DCHECK(!task_runner_state_->ShouldComplete());
  if (task_runner_state_->IsScheduled()) {
    // If the parser is already scheduled, there's no need to do anything.
    return;
  }
  base::TimeDelta delay = base::Milliseconds(0);
  if (RuntimeEnabledFeatures::HTMLParserYieldAndDelayOftenForTestingEnabled()) {
    delay = base::Milliseconds(10);
  }
  loading_task_runner_->PostDelayedTask(
      FROM_HERE,
      WTF::BindOnce(&HTMLDocumentParser::DeferredPumpTokenizerIfPossible,
                    WrapPersistent(this), from_finish_append,
                    base::TimeTicks::Now()),
      delay);
  task_runner_state_->SetState(
      HTMLDocumentParserState::DeferredParserState::kScheduled);

  yield_timer_ = std::make_unique<base::ElapsedTimer>();
}

void HTMLDocumentParser::ScheduleEndIfDelayed() {
  TRACE_EVENT_WITH_FLOW0("blink", "HTMLDocumentParser::ScheduleEndIfDelayed",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  DCHECK(!IsStopped());
  DCHECK(!task_runner_state_->InPumpSession());
  DCHECK(!task_runner_state_->ShouldComplete());

  // Schedule a pump callback if needed.
  if (!task_runner_state_->IsScheduled()) {
    loading_task_runner_->PostTask(
        FROM_HERE,
        WTF::BindOnce(&HTMLDocumentParser::DeferredPumpTokenizerIfPossible,
                      WrapPersistent(this),
                      /*from_finish_append=*/false, base::TimeTicks::Now()));
    yield_timer_ = std::make_unique<base::ElapsedTimer>();
  }
  // If a pump is already scheduled, it's OK to just upgrade it to one
  // which calls EndIfDelayed afterwards.
  task_runner_state_->SetState(
      HTMLDocumentParserState::DeferredParserState::kScheduledWithEndIfDelayed);
}

void HTMLDocumentParser::ConstructTreeFromToken(AtomicHTMLToken& atomic_token) {
  DCHECK(!GetDocument()->IsPrefetchOnly());

  // Check whether we've exited the header.
  if (!task_runner_state_->HaveExitedHeader()) {
    if (GetDocument()->body()) {
      task_runner_state_->SetExitedHeader();
    }
  }

  tree_builder_->ConstructTree(&atomic_token);
  CheckIfBlockingStylesheetAdded();
}

bool HTMLDocumentParser::HasInsertionPoint() {
  // FIXME: The wasCreatedByScript() branch here might not be fully correct. Our
  // model of the EOF character differs slightly from the one in the spec
  // because our treatment is uniform between network-sourced and script-sourced
  // input streams whereas the spec treats them differently.
  return input_.HasInsertionPoint() ||
         (WasCreatedByScript() && !input_.HaveSeenEndOfFile());
}

void HTMLDocumentParser::insert(const String& source) {
  // No need to do any processing if the supplied text is empty.
  if (IsStopped() || source.empty())
    return;

  TRACE_EVENT_WITH_FLOW2(
      "blink", "HTMLDocumentParser::insert", TRACE_ID_LOCAL(this),
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT, "source_length",
      source.length(), "parser", (void*)this);

  SegmentedString excluded_line_number_source(source);
  excluded_line_number_source.SetExcludeLineNumbers();
  input_.InsertAtCurrentInsertionPoint(excluded_line_number_source);

  // Pump the the tokenizer to build the document from the given insert point.
  // Should process everything available and not defer anything.
  ShouldCompleteScope should_complete(task_runner_state_);
  EndIfDelayedForbiddenScope should_not_end_if_delayed(task_runner_state_);
  // Call EndIfDelayed manually at the end to maintain preload behaviour.
  PumpTokenizerIfPossible();

  if (IsPaused() && !should_skip_preload_scan_) {
    // Check the document.write() output with a separate preload scanner as
    // the main scanner can't deal with insertions.
    if (!insertion_preload_scanner_) {
      insertion_preload_scanner_ =
          CreatePreloadScanner(TokenPreloadScanner::ScannerType::kInsertion);
    }
    insertion_preload_scanner_->AppendToEnd(source);
    if (preloader_) {
      ScanAndPreload(insertion_preload_scanner_.get());
    }
  }
  EndIfDelayed();
}

void HTMLDocumentParser::Append(const String& input_source) {
  TRACE_EVENT_WITH_FLOW2("blink", "HTMLDocumentParser::append",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "size", input_source.length(), "parser", (void*)this);

  if (IsStopped())
    return;

  const SegmentedString source(input_source);

  ScanInBackground(input_source);

  if (!background_scanner_ && !preload_scanner_ && preloader_ &&
      GetDocument()->Url().IsValid() && !should_skip_preload_scan_ &&
      (!task_runner_state_->IsSynchronous() ||
       GetDocument()->IsPrefetchOnly() || IsPaused())) {
    // If we're operating with a budget, we need to create a preload scanner to
    // make sure that parser-blocking Javascript requests are dispatched in
    // plenty of time, which prevents unnecessary delays.
    // When parsing without a budget (e.g. for HTML fragment parsing), it's
    // additional overhead to scan the string unless the parser's already
    // paused whilst executing a script.
    preload_scanner_ =
        CreatePreloadScanner(TokenPreloadScanner::ScannerType::kMainDocument);
  }

  if (GetDocument()->IsPrefetchOnly()) {
    if (preload_scanner_) {
      preload_scanner_->AppendToEnd(source);
      // TODO(Richard.Townsend@arm.com): add test coverage of this branch.
      // The crash in crbug.com/1166786 indicates that text documents are being
      // speculatively prefetched.
      ScanAndPreload(preload_scanner_.get());
    }

    // Return after the preload scanner, do not actually parse the document.
    return;
  }
  if (preload_scanner_) {
    preload_scanner_->AppendToEnd(source);
    if (task_runner_state_->GetMode() == kAllowDeferredParsing &&
        (IsPaused() || !task_runner_state_->SeenFirstByte())) {
      // Should scan and preload if the parser's paused waiting for a resource,
      // or if we're starting a document for the first time (we want to at least
      // prefetch anything that's in the <head> section).
      ScanAndPreload(preload_scanner_.get());
    }
  }

  input_.AppendToEnd(source);
  task_runner_state_->MarkSeenFirstByte();

  // Add input_source.length() to "file size" metric.
  if (metrics_reporter_)
    metrics_reporter_->AddInput(input_source.length());

  if (task_runner_state_->InPumpSession()) {
    // We've gotten data off the network in a nested write. We don't want to
    // consume any more of the input stream now.  Do not worry.  We'll consume
    // this data in a less-nested write().
    return;
  }

  // If we are preloading, FinishAppend() will be called later in
  // CommitPreloadedData().
  if (IsPreloading())
    return;

  FinishAppend();
}

void HTMLDocumentParser::FinishAppend() {
  TRACE_EVENT_WITH_FLOW0("blink", "HTMLDocumentParser::FinishAppend",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  if (ShouldPumpTokenizerNowForFinishAppend())
    PumpTokenizerIfPossible();
  else
    SchedulePumpTokenizer(/*from_finish_append=*/true);
}

void HTMLDocumentParser::CommitPreloadedData() {
  TRACE_EVENT_WITH_FLOW0("blink", "HTMLDocumentParser::CommitPreloadedData",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  if (!IsPreloading())
    return;

  SetIsPreloading(false);
  if (task_runner_state_->SeenFirstByte() && !IsStopped())
    FinishAppend();
}

void HTMLDocumentParser::end() {
  DCHECK(!IsDetached());

  // Informs the the rest of WebCore that parsing is really finished (and
  // deletes this).
  tree_builder_->Finished();

  // All preloads should be done.
  preloader_ = nullptr;

  DocumentParser::StopParsing();
}

void HTMLDocumentParser::AttemptToRunDeferredScriptsAndEnd() {
  DCHECK(IsStopping());
  DCHECK(!HasInsertionPoint());
  if (script_runner_ && !script_runner_->ExecuteScriptsWaitingForParsing())
    return;
  end();
}

bool HTMLDocumentParser::ShouldDelayEnd() const {
  return task_runner_state_->InPumpSession() || IsPaused() ||
         IsExecutingScript() || task_runner_state_->IsScheduled();
}

void HTMLDocumentParser::AttemptToEnd() {
  // finish() indicates we will not receive any more data. If we are waiting on
  // an external script to load, we can't finish parsing quite yet.
  TRACE_EVENT_WITH_FLOW1("blink", "HTMLDocumentParser::AttemptToEnd",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "parser", (void*)this);
  DCHECK(task_runner_state_->ShouldAttemptToEndOnEOF());
  AttemptToEndForbiddenScope should_not_attempt_to_end(task_runner_state_);
  // We should only be in this state once after calling Finish.
  // If there are pending scripts, future control flow should pass to
  // EndIfDelayed.
  if (ShouldDelayEnd()) {
    task_runner_state_->SetEndWasDelayed(true);
    return;
  }
  PrepareToStopParsing();
}

void HTMLDocumentParser::EndIfDelayed() {
  TRACE_EVENT_WITH_FLOW1("blink", "HTMLDocumentParser::EndIfDelayed",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "parser", (void*)this);
  ShouldCompleteScope should_complete(task_runner_state_);
  EndIfDelayedForbiddenScope should_not_end_if_delayed(task_runner_state_);
  // If we've already been detached, don't bother ending.
  if (IsDetached())
    return;

  if (!task_runner_state_->EndWasDelayed() || ShouldDelayEnd())
    return;

  task_runner_state_->SetEndWasDelayed(false);
  PrepareToStopParsing();
}

void HTMLDocumentParser::Finish() {
  ShouldCompleteScope should_complete(task_runner_state_);
  EndIfDelayedForbiddenScope should_not_end_if_delayed(task_runner_state_);
  Flush();
  if (IsDetached())
    return;

  // We're not going to get any more data off the network, so we tell the input
  // stream we've reached the end of file. finish() can be called more than
  // once, if the first time does not call end().
  if (!input_.HaveSeenEndOfFile()) {
    input_.MarkEndOfFile();
  }

  // If there's any deferred work remaining, signal that we
  // want to end the document once all work's complete.
  task_runner_state_->SetAttemptToEndOnEOF();
  if (task_runner_state_->IsScheduled() && !GetDocument()->IsPrefetchOnly()) {
    return;
  }

  AttemptToEnd();
}

bool HTMLDocumentParser::IsExecutingScript() const {
  if (!script_runner_)
    return false;
  return script_runner_->IsExecutingScript();
}

OrdinalNumber HTMLDocumentParser::LineNumber() const {
  return input_.Current().CurrentLine();
}

TextPosition HTMLDocumentParser::GetTextPosition() const {
  const SegmentedString& current_string = input_.Current();
  OrdinalNumber line = current_string.CurrentLine();
  OrdinalNumber column = current_string.CurrentColumn();

  return TextPosition(line, column);
}

bool HTMLDocumentParser::IsWaitingForScripts() const {
  if (IsParsingFragment()) {
    // HTMLTreeBuilder may have a parser blocking script element, but we
    // ignore it during fragment parsing.
    DCHECK(!(tree_builder_->HasParserBlockingScript() ||
             (script_runner_ && script_runner_->HasParserBlockingScript()) ||
             reentry_permit_->ParserPauseFlag()));
    return false;
  }

  // When the TreeBuilder encounters a </script> tag, it returns to the
  // HTMLDocumentParser where the script is transfered from the treebuilder to
  // the script runner. The script runner will hold the script until its loaded
  // and run. During any of this time, we want to count ourselves as "waiting
  // for a script" and thus run the preload scanner, as well as delay completion
  // of parsing.
  bool tree_builder_has_blocking_script =
      tree_builder_->HasParserBlockingScript();
  bool script_runner_has_blocking_script =
      script_runner_ && script_runner_->HasParserBlockingScript();
  // Since the parser is paused while a script runner has a blocking script, it
  // should never be possible to end up with both objects holding a blocking
  // script.
  DCHECK(
      !(tree_builder_has_blocking_script && script_runner_has_blocking_script));
  // If either object has a blocking script, the parser should be paused.
  return tree_builder_has_blocking_script ||
         script_runner_has_blocking_script ||
         reentry_permit_->ParserPauseFlag();
}

void HTMLDocumentParser::ResumeParsingAfterPause() {
  // This function runs after a parser-blocking script has completed.
  TRACE_EVENT_WITH_FLOW1("blink", "HTMLDocumentParser::ResumeParsingAfterPause",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "parser", (void*)this);
  DCHECK(!IsExecutingScript());
  DCHECK(!IsPaused());

  CheckIfBlockingStylesheetAdded();
  if (IsStopped() || IsPaused() || IsDetached())
    return;

  insertion_preload_scanner_.reset();
  if (task_runner_state_->GetMode() == kAllowDeferredParsing &&
      !task_runner_state_->ShouldComplete() &&
      !task_runner_state_->InPumpSession()) {
    SchedulePumpTokenizer(/*from_finish_append=*/false);
  } else {
    ShouldCompleteScope should_complete(task_runner_state_);
    PumpTokenizerIfPossible();
  }
}

void HTMLDocumentParser::AppendCurrentInputStreamToPreloadScannerAndScan() {
  TRACE_EVENT_WITH_FLOW1(
      "blink",
      "HTMLDocumentParser::AppendCurrentInputStreamToPreloadScannerAndScan",
      TRACE_ID_LOCAL(this),
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT, "parser",
      (void*)this);
  if (preload_scanner_) {
    DCHECK(preloader_);
    preload_scanner_->AppendToEnd(input_.Current());
    ScanAndPreload(preload_scanner_.get());
  }
}

void HTMLDocumentParser::NotifyScriptLoaded() {
  TRACE_EVENT_WITH_FLOW1("blink", "HTMLDocumentParser::NotifyScriptLoaded",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "parser", (void*)this);
  DCHECK(script_runner_);
  DCHECK(!IsExecutingScript());

  scheduler::CooperativeSchedulingManager::AllowedStackScope
      allowed_stack_scope(scheduler::CooperativeSchedulingManager::Instance());

  if (IsStopped()) {
    return;
  }

  if (IsStopping()) {
    AttemptToRunDeferredScriptsAndEnd();
    return;
  }

  script_runner_->ExecuteScriptsWaitingForLoad();
  if (!IsPaused())
    ResumeParsingAfterPause();
}

// static
void HTMLDocumentParser::ResetCachedFeaturesForTesting() {
  ThreadedPreloadScannerEnabled(FeatureResetMode::kResetForTesting);
  PrecompileInlineScriptsEnabled(FeatureResetMode::kResetForTesting);
}

// static
void HTMLDocumentParser::FlushPreloadScannerThreadForTesting() {
  base::RunLoop run_loop;
  GetPreloadScannerThread()->GetTaskRunner()->PostTask(FROM_HERE,
                                                       run_loop.QuitClosure());
  run_loop.Run();
}

void HTMLDocumentParser::ExecuteScriptsWaitingForResources() {
  TRACE_EVENT_WITH_FLOW0(
      "blink", "HTMLDocumentParser::ExecuteScriptsWaitingForResources",
      TRACE_ID_LOCAL(this),
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  if (IsStopped())
    return;

  DCHECK(GetDocument()->IsScriptExecutionReady());

  if (task_runner_state_->WaitingForStylesheets())
    task_runner_state_->SetWaitingForStylesheets(false);

  if (IsStopping()) {
    AttemptToRunDeferredScriptsAndEnd();
    return;
  }

  // Document only calls this when the Document owns the DocumentParser so this
  // will not be called in the DocumentFragment case.
  DCHECK(script_runner_);
  script_runner_->ExecuteScriptsWaitingForResources();
  if (!IsPaused())
    ResumeParsingAfterPause();
}

void HTMLDocumentParser::DidAddPendingParserBlockingStylesheet() {
  // In-body CSS doesn't block painting. The parser needs to pause so that
  // the DOM doesn't include any elements that may depend on the CSS for style.
  // The stylesheet can be added and removed during the parsing of a single
  // token so don't actually set the bit to block parsing here, just track
  // the state of the added sheet in case it does persist beyond a single
  // token.
  task_runner_state_->SetAddedPendingParserBlockingStylesheet(true);
}

void HTMLDocumentParser::DidLoadAllPendingParserBlockingStylesheets() {
  // Just toggle the stylesheet flag here (mostly for synchronous sheets).
  // The document will also call into executeScriptsWaitingForResources
  // which is when the parser will re-start, otherwise it will attempt to
  // resume twice which could cause state machine issues.
  task_runner_state_->SetAddedPendingParserBlockingStylesheet(false);
}

void HTMLDocumentParser::CheckIfBlockingStylesheetAdded() {
  if (task_runner_state_->AddedPendingParserBlockingStylesheet()) {
    task_runner_state_->SetAddedPendingParserBlockingStylesheet(false);
    task_runner_state_->SetWaitingForStylesheets(true);
  }
}

void HTMLDocumentParser::ParseDocumentFragment(
    const String& source,
    DocumentFragment* fragment,
    Element* context_element,
    ParserContentPolicy parser_content_policy) {
  auto* parser = MakeGarbageCollected<HTMLDocumentParser>(
      fragment, context_element, parser_content_policy);

  if (RuntimeEnabledFeatures::DOMPartsAPIEnabled()) {
    // Within templates containing the `parseparts` attribute, allow parsing
    // DOM Parts. Otherwise do not parse any DOM Part content.
    DOMPartsAllowed parts_allowed{DOMPartsAllowed::kNever};
    if (auto* template_element =
            DynamicTo<HTMLTemplateElement>(context_element);
        template_element &&
        template_element->hasAttribute(html_names::kParsepartsAttr)) {
      parts_allowed = DOMPartsAllowed::kAlways;
    }
    parser->tree_builder_->SetDOMPartsAllowedState(parts_allowed);
  }

  parser->Append(source);
  parser->Finish();
  // Allows ~DocumentParser to assert it was detached before destruction.
  parser->Detach();
}

void HTMLDocumentParser::AppendBytes(base::span<const uint8_t> data) {
  TRACE_EVENT_WITH_FLOW2(
      "blink", "HTMLDocumentParser::appendBytes", TRACE_ID_LOCAL(this),
      TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT, "size",
      static_cast<unsigned>(data.size()), "parser", (void*)this);

  DCHECK(IsMainThread());

  if (data.empty() || IsStopped()) {
    return;
  }

  DecodedDataDocumentParser::AppendBytes(data);
}

void HTMLDocumentParser::Flush() {
  TRACE_EVENT_WITH_FLOW1("blink", "HTMLDocumentParser::Flush",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "parser", (void*)this);
  // If we've got no decoder, we never received any data.
  if (IsDetached() || NeedsDecoder())
    return;
  DecodedDataDocumentParser::Flush();
}

void HTMLDocumentParser::SetDecoder(
    std::unique_ptr<TextResourceDecoder> decoder) {
  DecodedDataDocumentParser::SetDecoder(std::move(decoder));
}

void HTMLDocumentParser::DocumentElementAvailable() {
  TRACE_EVENT_WITH_FLOW0("blink,loading",
                         "HTMLDocumentParser::DocumentElementAvailable",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  Document* document = GetDocument();
  DCHECK(document);
  DCHECK(document->documentElement());
  Element* documentElement = GetDocument()->documentElement();
  if (documentElement->hasAttribute(AtomicString(u"\u26A1")) ||
      documentElement->hasAttribute(AtomicString("amp")) ||
      documentElement->hasAttribute(AtomicString("i-amphtml-layout"))) {
    // The DocumentLoader fetches a main resource and handles the result.
    // But it may not be available if JavaScript appends HTML to the page later
    // in the page's lifetime. This can happen both from in-page JavaScript and
    // from extensions. See example callstacks linked from crbug.com/931330.
    if (document->Loader()) {
      document->Loader()->DidObserveLoadingBehavior(
          kLoadingBehaviorAmpDocumentLoaded);
    }
  }
  MaybeFetchQueuedPreloads();
}

std::unique_ptr<HTMLPreloadScanner> HTMLDocumentParser::CreatePreloadScanner(
    TokenPreloadScanner::ScannerType scanner_type) {
#if DCHECK_IS_ON()
  if (scanner_type == TokenPreloadScanner::ScannerType::kMainDocument) {
    // A main document scanner should never be created if scanning is already
    // happening in the background.
    DCHECK(!background_scanner_);
    // If background scanning is enabled, the main document scanner is used when
    // the parser is paused, for prefetch documents, or if preload scanning is
    // disabled in tests (HTMLPreloadScanner internally handles this setting).
    DCHECK(!ThreadedPreloadScannerEnabled() || IsPaused() ||
           GetDocument()->IsPrefetchOnly() ||
           !IsPreloadScanningEnabled(GetDocument()));
  }
#endif
  return HTMLPreloadScanner::Create(*GetDocument(), options_, scanner_type);
}

void HTMLDocumentParser::ScanAndPreload(HTMLPreloadScanner* scanner) {
  TRACE_EVENT_WITH_FLOW0("blink", "HTMLDocumentParser::ScanAndPreload",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  CHECK(preloader_);
  base::ElapsedTimer timer_before_scan;
  std::unique_ptr<PendingPreloadData> preload_data =
      scanner->Scan(GetDocument()->ValidBaseElementURL());
  const base::TimeDelta scan_time = timer_before_scan.Elapsed();
  base::UmaHistogramMicrosecondsTimes(
      base::StrCat(
          {kHistogramScanAndPreloadTime, ".Scan", GetPreloadHistogramSuffix()}),
      scan_time);
  base::ElapsedTimer timer_after_scan;
  ProcessPreloadData(std::move(preload_data));
  const base::TimeDelta scan_and_preload_time = timer_before_scan.Elapsed();
  const base::TimeDelta preload_time = timer_after_scan.Elapsed();
  base::UmaHistogramMicrosecondsTimes(
      base::StrCat({kHistogramScanAndPreloadTime, GetPreloadHistogramSuffix()}),
      scan_and_preload_time);
  // Keep old histogram until next expiry date.
  base::UmaHistogramTimes(
      base::StrCat({"Blink.ScanAndPreloadTime", GetPreloadHistogramSuffix()}),
      scan_and_preload_time);
  base::UmaHistogramMicrosecondsTimes(
      base::StrCat({kHistogramScanAndPreloadTime, ".Preload",
                    GetPreloadHistogramSuffix()}),
      preload_time);
  if (metrics_reporter_) {
    metrics_reporter_->AddScanTime(scan_time.InMicroseconds());
    metrics_reporter_->AddScanAndPreloadTime(
        scan_and_preload_time.InMicroseconds());
    metrics_reporter_->AddPreloadTime(preload_time.InMicroseconds());
  }
}

void HTMLDocumentParser::ProcessPreloadData(
    std::unique_ptr<PendingPreloadData> preload_data) {
  for (const auto& value : preload_data->meta_ch_values) {
    HTMLMetaElement::ProcessMetaCH(*GetDocument(), value.value, value.type,
                                   value.is_doc_preloader,
                                   /*is_sync_parser=*/false);
  }

  // Make sure that the viewport is up-to-date, so that the correct viewport
  // dimensions will be fed to the preload scanner.
  if (GetDocument()->Loader() &&
      task_runner_state_->GetMode() == kAllowDeferredParsing) {
    if (preload_data->viewport.has_value()) {
      GetDocument()->GetStyleEngine().UpdateViewport();
    }
    if (task_runner_state_->NeedsLinkHeaderPreloadsDispatch()) {
      {
        TRACE_EVENT_WITH_FLOW0(
            "blink", "HTMLDocumentParser::DispatchLinkHeaderPreloads",
            TRACE_ID_LOCAL(this),
            TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
        GetDocument()->Loader()->DispatchLinkHeaderPreloads(
            base::OptionalToPtr(preload_data->viewport),
            PreloadHelper::LoadLinksFromHeaderMode::
                kDocumentAfterCommitWithViewport);
      }
      if (base::FeatureList::IsEnabled(
              blink::features::kLCPPFontURLPredictor)) {
        TRACE_EVENT_WITH_FLOW0(
            "blink", "HTMLDocumentParser::DispatchLcppFontPreloads",
            TRACE_ID_LOCAL(this),
            TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
        GetDocument()->Loader()->DispatchLcppFontPreloads(
            base::OptionalToPtr(preload_data->viewport),
            PreloadHelper::LoadLinksFromHeaderMode::
                kSubresourceNotFromMemoryCache);
      }
      if (GetDocument()->Loader()->GetPrefetchedSignedExchangeManager()) {
        TRACE_EVENT_WITH_FLOW0(
            "blink", "HTMLDocumentParser::DispatchSignedExchangeManager",
            TRACE_ID_LOCAL(this),
            TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
        // Link header preloads for prefetched signed exchanges won't be started
        // until StartPrefetchedLinkHeaderPreloads() is called. See the header
        // comment of PrefetchedSignedExchangeManager.
        GetDocument()
            ->Loader()
            ->GetPrefetchedSignedExchangeManager()
            ->StartPrefetchedLinkHeaderPreloads();
      }
      task_runner_state_->DispatchedLinkHeaderPreloads();
    }
  }

  seen_csp_meta_tags_ += preload_data->csp_meta_tag_count;
  for (auto& request : preload_data->requests) {
    queued_preloads_.push_back(std::move(request));
    if (metrics_reporter_) {
      metrics_reporter_->IncrementPreloadRequestCount();
    }
  }

  if (base::FeatureList::IsEnabled(features::kDelayAsyncScriptExecution) &&
      features::kDelayAsyncScriptExecutionWhenLcpFoundInHtml.Get()) {
    // If LCP element is found during preload scanning of main document,
    // start/continue delaying async script execution on the document until the
    // configured  milestone.
    Document* document = GetDocument();
    LocalFrame* frame = document->GetFrame();
    if (preload_data->has_located_potential_lcp_element && frame &&
        frame->IsMainFrame()) {
      document->SetLcpElementFoundInHtml(true);
      document->DelayAsyncScriptExecution();
    }
  }

  if (base::FeatureList::IsEnabled(
          features::kLowPriorityAsyncScriptExecution) &&
      features::kLowPriorityAsyncScriptExecutionDisableWhenLcpNotInHtmlParam
          .Get()) {
    // Update main document whether LCP element was discovered in HTML.
    Document* document = GetDocument();
    LocalFrame* frame = document->GetFrame();
    if (preload_data->has_located_potential_lcp_element && frame &&
        frame->IsMainFrame()) {
      document->SetLcpElementFoundInHtml(true);
    }
  }

  MaybeFetchQueuedPreloads();
}

void HTMLDocumentParser::MaybeFetchQueuedPreloads() {
  TRACE_EVENT_WITH_FLOW0("blink,devtools.timeline",
                         "HTMLDocumentParser::MaybeFetchQueuedPreloads",
                         TRACE_ID_LOCAL(this),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);

  if (!AllowPreloading()) {
    return;
  }

  base::ElapsedTimer timer;
  preloader_->TakeAndPreload(queued_preloads_);
  base::TimeDelta elapsed_time = timer.Elapsed();
  base::UmaHistogramTimes(base::StrCat({"Blink.FetchQueuedPreloadsTime",
                                        GetPreloadHistogramSuffix()}),
                          elapsed_time);
  if (metrics_reporter_) {
    metrics_reporter_->AddFetchQueuedPreloadsTime(
        elapsed_time.InMicroseconds());
  }
}

std::string HTMLDocumentParser::GetPreloadHistogramSuffix() {
  bool is_outermost_main_frame =
      GetDocument() && GetDocument()->IsInOutermostMainFrame();
  bool have_seen_first_byte = task_runner_state_->SeenFirstByte();
  return base::StrCat({is_outermost_main_frame ? ".MainFrame" : ".Subframe",
                       have_seen_first_byte ? ".NonInitial" : ".Initial"});
}

DocumentParser::BackgroundScanCallback
HTMLDocumentParser::TakeBackgroundScanCallback() {
  if (!background_scan_fn_)
    return BackgroundScanCallback();
  return CrossThreadBindRepeating(std::move(background_scan_fn_), KURL());
}

void HTMLDocumentParser::ScanInBackground(const String& source) {
  if (task_runner_state_->IsSynchronous() || !GetDocument()->Url().IsValid())
    return;

  if (ThreadedPreloadScannerEnabled() && preloader_ &&
      // TODO(crbug.com/1329535): Support scanning prefetch documents in the
      // background.
      !GetDocument()->IsPrefetchOnly() &&
      IsPreloadScanningEnabled(GetDocument()) && !should_skip_preload_scan_) {
    // The background scanner should never be created if a main thread scanner
    // is already available.
    DCHECK(!preload_scanner_);
    if (!background_scanner_) {
      // See comment on NavigationBodyLoader::StartLoadingBodyInBackground() for
      // details on how the preload scanner flow works when the body data is
      // being loaded in the background.
      background_scanner_ = HTMLPreloadScanner::CreateBackground(
          this, options_, GetPreloadScannerThread()->GetTaskRunner(),
          CrossThreadBindRepeating(
              &HTMLDocumentParser::AddPreloadDataOnBackgroundThread,
              MakeCrossThreadWeakHandle(this), this->pending_preloads_,
              GetDocument()->GetTaskRunner(TaskType::kInternalLoading)));

      background_scan_fn_ = CrossThreadBindRepeating(
          [](base::WeakPtr<HTMLPreloadScanner> scanner,
             scoped_refptr<base::SingleThreadTaskRunner> task_runner,
             const KURL& url, const String& data) {
            PostCrossThreadTask(
                *task_runner, FROM_HERE,
                CrossThreadBindOnce(&HTMLPreloadScanner::ScanInBackground,
                                    std::move(scanner), data, url));
          },
          background_scanner_->AsWeakPtr(),
          GetPreloadSca
```