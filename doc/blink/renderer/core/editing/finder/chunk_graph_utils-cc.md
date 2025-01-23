Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The primary request is to understand the functionality of `chunk_graph_utils.cc` within the Chromium Blink rendering engine, specifically its relation to text finding/searching, and potential connections to JavaScript, HTML, and CSS. The request also asks for examples, logic, potential errors, and debugging hints.

2. **Identify Key Entities and Concepts:**  The code itself reveals several core components:
    * **`ChunkGraphBuilder`:**  This class seems to be the central logic for constructing something called a "chunk graph."
    * **`CorpusChunk`:** Represents a chunk of content, likely text. It stores text and links to other chunks.
    * **`TextOrChar`:**  A simple structure holding either a `Text` node pointer or a single character. This suggests the chunking process might handle both text nodes and special characters.
    * **Levels (`kAnyLevel`, `kBaseLevel`, `CreateLevel`):**  These suggest a hierarchical or categorized structure for the chunks. The delimiter hints at a way to navigate this hierarchy.
    * **Ruby Support (`FindOuterMostRubyContainerInBlockContainer`, `IsParentRubyContainer`, `HandleAnnotationStart`, etc.):**  Explicit handling of `<ruby>` tags is a significant clue.
    * **Flat Tree Traversal:** The extensive use of `FlatTreeTraversal` indicates the code operates on the flattened DOM tree structure.
    * **`FindBuffer`:** The interaction with `FindBuffer` implies this code is part of the text finding functionality.

3. **High-Level Functionality Deduction:** Based on the class names and their interactions, the primary function appears to be: *To break down a portion of the DOM tree (likely within a block element) into a graph of text chunks, with special handling for Ruby annotations.* This graph likely assists in the text searching process.

4. **Analyze Key Functions:**  Examine the core methods of `ChunkGraphBuilder`:
    * **`Build()`:** This is the main entry point. It iterates through the DOM, creating and linking `CorpusChunk` objects. The `end_node` parameter suggests it processes a range of nodes. The logic around `did_see_range_start_node` and `did_see_range_end_node` confirms this.
    * **`PushChunk()`, `PushBaseChunk()`, `PushBaseChunkAndLink()`:** These manage the creation and linking of `CorpusChunk` objects, incorporating the level information.
    * **`HandleAnnotationStart()`, `HandleAnnotationEnd()`, `HandleRubyContainerStart()`, `HandleRubyContainerEnd()`:**  These methods are crucial for understanding how Ruby annotations are processed and integrated into the chunk graph. They seem to create a separate "level" or branch in the graph for the annotation.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **HTML:** The code directly operates on DOM nodes, which are created from HTML. The Ruby handling is a direct connection to specific HTML elements (`<ruby>`, `<rt>`, `<rb>`).
    * **CSS:**  `ComputedStyle` is heavily used to determine the `display` and `visibility` of elements. This directly influences which nodes are included in the chunk graph and how the graph is structured (e.g., handling `display: contents`, and skipping invisible elements).
    * **JavaScript:** While the C++ code itself doesn't directly interact with JavaScript, it's part of the rendering engine that *supports* JavaScript functionality. JavaScript can manipulate the DOM, which in turn would affect how this chunk graph is built. User actions in the browser (initiated by JavaScript events) can trigger the text finding process.

6. **Consider Logic and Examples:** Think about how the Ruby handling works. Imagine a simple Ruby example and trace how the `Build()` method might process it, leading to different levels in the chunk graph. This leads to the provided Ruby example and the explanation of levels.

7. **Identify Potential Errors:**  Look for areas where assumptions are made or where incorrect usage could lead to problems. The `FindNext()` method's error handling (returning `nullptr`) when a level isn't found suggests a potential issue with graph construction. The handling of `display: contents` and visibility are also areas where subtle bugs could occur.

8. **Trace User Actions (Debugging Hints):**  Think about the user flow that leads to the text finding functionality. The most obvious path is the user initiating a "find in page" operation (Ctrl+F or Cmd+F). The steps involved in this process are good debugging clues.

9. **Structure the Answer:** Organize the findings into clear sections (Functionality, Relationships, Logic, Errors, Debugging). Use clear and concise language. Provide concrete examples where possible.

10. **Refine and Review:**  Read through the generated answer. Does it accurately reflect the code's functionality? Are the explanations clear? Are the examples helpful?  Are there any areas that could be explained better? For instance, initially, the explanation of levels might be a bit abstract. Adding a more concrete visual or analogy could improve clarity. Similarly, ensuring the connection to the "find in page" feature is explicit is important.

By following this systematic approach, combining code analysis with an understanding of web technologies and user interaction, a comprehensive and accurate explanation of the `chunk_graph_utils.cc` file can be generated.
这个文件 `chunk_graph_utils.cc` 的主要功能是构建用于文本查找的“块图”(Chunk Graph)。这个块图是一种优化的数据结构，旨在加速在网页内容中查找指定文本的过程，尤其是在处理包含复杂布局（例如，Ruby 注释）的文本时。

以下是该文件更具体的功能点：

**核心功能：构建块图 (Chunk Graph)**

* **`BuildChunkGraph` 函数:** 这是构建块图的主要入口点。它接收以下参数：
    * `first_visible_text_node`: 查找范围内的第一个可见文本节点。
    * `end_node`:  查找范围的结束节点（可以是 `nullptr`，表示查找到文档末尾）。
    * `block_ancestor`:  包含查找范围的块级祖先元素。
    * `just_after_block`:  块级祖先元素之后的节点（用于限定查找范围）。
* **`ChunkGraphBuilder` 类:**  这是一个辅助类，负责实际的块图构建过程。它遍历 DOM 树，并将文本内容组织成 `CorpusChunk` 的链表结构。
* **`CorpusChunk` 类:**  表示块图中的一个节点，包含一段文本内容 (`text_list_`) 和指向下一个块的链接 (`next_list_`)。每个 `CorpusChunk` 还有一个 `level_` 属性，用于表示其在块图中的层次结构，这对于处理 Ruby 注释等复杂布局至关重要。
* **`TextOrChar` 结构体:**  用于存储文本节点 (`Text*`) 或单个字符 (`UChar`)，以便在构建块图时处理特殊情况。

**处理复杂布局：Ruby 注释**

* **`FindOuterMostRubyContainerInBlockContainer` 函数:** 查找给定节点在指定块容器内的最外层 Ruby 容器元素 (`<ruby>`)。
* **`IsParentRubyContainer` 函数:** 检查给定节点的父元素是否为 Ruby 容器。
* **`HandleAnnotationStart`，`HandleAnnotationEnd`，`HandleRubyContainerStart`，`HandleRubyContainerEnd` 函数:**  这些方法在 `ChunkGraphBuilder` 中用于专门处理 Ruby 注释 (`<rt>`) 和 Ruby 基础文本 (`<rb>`)。它们会在块图中创建特殊的层次结构 (`level_`) 来区分 Ruby 注释和基础文本，以便在查找时能够正确匹配。

**与 JavaScript, HTML, CSS 的关系**

这个文件主要处理渲染引擎内部的文本查找优化，与 JavaScript、HTML 和 CSS 的关系体现在它所操作的数据基础上：

* **HTML:** 该代码直接操作 HTML 结构（通过 DOM 节点）。`BuildChunkGraph` 接收的参数都是 DOM 节点。对于像 `<ruby>` 这样的特定 HTML 元素，代码有专门的处理逻辑。
    * **例子:**  当 HTML 中存在 `<ruby><rb>中文</rb><rt>zhōng wén</rt></ruby>` 时，`ChunkGraphBuilder` 会识别出 Ruby 容器和注释，并创建带有不同 `level_` 的 `CorpusChunk`，例如一个 `CorpusChunk` 包含 "中文"，另一个包含 "zhōng wén"，并用 `level_` 信息将它们关联起来。
* **CSS:**  CSS 的样式会影响文本的可见性和布局，从而影响块图的构建。
    * **`FindBuffer::ShouldIgnoreContents(*node)`:** 这个函数可能会检查 CSS 的 `display` 或 `visibility` 属性，以确定是否应该忽略某个节点的内容。例如，`display: none` 的元素会被忽略。
    * **`node->GetComputedStyleForElementOrLayoutObject()`:** 获取节点的计算样式，用于判断元素的显示类型 (`EDisplay`)，例如判断是否是 Ruby 容器 (`EDisplay::kRuby` 或 `EDisplay::kBlockRuby`) 或 Ruby 注释 (`EDisplay::kRubyText`)。
    * **例子:** 如果一个文本节点的 CSS 样式是 `visibility: hidden`，`BuildChunkGraph` 在遍历时可能会跳过这个节点，因为它不可见。
* **JavaScript:**  JavaScript 可以动态地修改 DOM 结构和 CSS 样式。这些修改会影响到下一次文本查找时构建的块图。
    * **例子:**  JavaScript 可以通过 `document.createElement()` 创建新的包含文本的 HTML 元素，或者通过修改元素的 `style` 属性来改变其可见性。当用户执行查找操作时，这些由 JavaScript 引起的 DOM 变化会反映在 `BuildChunkGraph` 生成的块图中。

**逻辑推理：假设输入与输出**

假设我们有以下简单的 HTML 片段：

```html
<div>
  <p>This is some <b>bold</b> text.</p>
</div>
```

我们想在包含 "This is some bold text." 的范围内构建块图。

**假设输入:**

* `first_visible_text_node`: 指向 "This is some " 文本节点的 DOM 节点。
* `end_node`: 指向 " text." 文本节点的 DOM 节点。
* `block_ancestor`: 指向 `<div>` 元素的 DOM 节点。
* `just_after_block`: `nullptr` (假设查找到块的末尾)。

**推断的输出 (简化):**

`BuildChunkGraph` 可能会生成以下 `CorpusChunk` 链表（简化表示，忽略 `level_` 等细节）：

1. `CorpusChunk`: 包含文本 "This is some "
2. `CorpusChunk`: 包含文本 "bold"
3. `CorpusChunk`: 包含文本 " text."

这些 `CorpusChunk` 将通过 `next_list_` 链接在一起。

**涉及用户或编程常见的使用错误**

* **查找范围不正确:**  如果传递给 `BuildChunkGraph` 的 `first_visible_text_node` 和 `end_node` 没有正确地限定要查找的范围，可能会导致块图包含不期望的内容或遗漏期望的内容。
    * **例子:**  开发者在实现查找功能时，错误地计算了起始和结束节点，导致实际构建块图的范围超出了用户选择的文本范围。
* **忽略了 `FindBuffer::ShouldIgnoreContents` 的影响:**  如果开发者在其他地方进行文本处理时，没有考虑到某些节点可能因为样式等原因被 `FindBuffer::ShouldIgnoreContents` 忽略，可能会导致不一致的行为。
    * **例子:**  开发者尝试直接遍历 DOM 获取所有文本内容进行查找，但没有使用块图，导致忽略了 `visibility: hidden` 的内容，而块图的构建会正确处理这种情况。
* **假设块图始终是最新的:**  DOM 结构可能会动态变化。如果在一个过时的块图上进行查找，可能会得到错误的结果。
    * **例子:**  JavaScript 代码在用户执行查找操作后修改了 DOM，但查找功能仍然使用了之前构建的块图，导致查找到的内容与当前页面不符。

**用户操作是如何一步步到达这里，作为调试线索**

1. **用户发起查找操作:** 用户通常通过按下 `Ctrl+F` (Windows/Linux) 或 `Cmd+F` (macOS) 快捷键，或者通过浏览器菜单中的 "查找" 功能来启动页面内的文本查找。
2. **浏览器接收用户输入:** 浏览器会弹出一个查找框，用户在其中输入要查找的文本。
3. **渲染引擎开始查找:** 当用户开始输入或点击 "查找下一个" 等按钮时，渲染引擎会启动查找过程。
4. **确定查找范围:** 渲染引擎需要确定在哪个 DOM 范围内进行查找。通常，这会涉及到当前可见的文档内容。
5. **构建块图 (可能):** 为了优化查找性能，渲染引擎可能会调用 `BuildChunkGraph` 来为当前的查找范围构建块图。
    * 此时，`first_visible_text_node` 和 `end_node` 会根据当前的查找范围确定。
    * `block_ancestor` 会是包含查找范围的最近的块级元素。
6. **在块图中进行查找:**  构建好块图后，查找算法会在这个图结构中高效地搜索用户输入的文本。
7. **高亮显示结果:**  如果找到匹配的文本，浏览器会在页面上高亮显示。

**调试线索:**

* **检查 `BuildChunkGraph` 的参数:**  在调试器中查看 `BuildChunkGraph` 被调用时的参数值，特别是 `first_visible_text_node`、`end_node` 和 `block_ancestor`，可以帮助确定查找的范围是否正确。
* **单步执行 `ChunkGraphBuilder::Build`:**  单步执行 `ChunkGraphBuilder::Build` 方法，观察它是如何遍历 DOM 树，以及如何创建和链接 `CorpusChunk`，可以帮助理解块图的构建过程，并发现潜在的错误。
* **查看生成的块图:**  如果可能，在调试过程中查看生成的 `CorpusChunk` 链表结构及其包含的文本内容和 `level_` 信息，可以帮助验证块图是否正确地表示了页面的内容和结构。
* **关注 Ruby 注释的处理:** 如果页面包含 Ruby 注释，重点关注 `HandleAnnotationStart` 和 `HandleAnnotationEnd` 等方法的执行流程，确保 Ruby 元素的层次结构被正确地反映在块图中。
* **检查 `FindBuffer::ShouldIgnoreContents` 的行为:**  确认是否有节点因为某些原因被 `FindBuffer::ShouldIgnoreContents` 忽略，这可能导致查找结果不完整。

总而言之，`chunk_graph_utils.cc` 是 Chromium Blink 引擎中用于优化文本查找功能的重要组成部分，它通过构建块图这种高效的数据结构来加速在复杂 HTML 结构中查找文本的过程，并特别处理了像 Ruby 注释这样的特殊布局。它的工作依赖于对 HTML 结构和 CSS 样式的理解。

### 提示词
```
这是目录为blink/renderer/core/editing/finder/chunk_graph_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/finder/chunk_graph_utils.h"

#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/node_computed_style.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/finder/find_buffer.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"

namespace blink {

namespace {

constexpr LChar kAnyLevel[] = "*";
constexpr LChar kBaseLevel[] = "0";
constexpr UChar kLevelDelimiter = kComma;

const Node* FindOuterMostRubyContainerInBlockContainer(const Node& node,
                                                       const Node& block) {
  const Element* ruby_container = nullptr;
  for (const auto& ancestor : FlatTreeTraversal::AncestorsOf(node)) {
    const Element* element = DynamicTo<Element>(ancestor);
    if (!element) {
      CHECK(ancestor.IsDocumentNode());
      break;
    }
    if (const ComputedStyle* style = element->GetComputedStyle()) {
      if (style->Display() == EDisplay::kRuby ||
          style->Display() == EDisplay::kBlockRuby) {
        ruby_container = element;
      }
      if (&ancestor == &block) {
        break;
      }
    }
  }
  return ruby_container;
}

bool IsParentRubyContainer(const Node& node) {
  const Element* parent = FlatTreeTraversal::ParentElement(node);
  if (!parent->GetComputedStyle()) {
    return false;
  }
  for (; parent; parent = FlatTreeTraversal::ParentElement(*parent)) {
    EDisplay display = parent->ComputedStyleRef().Display();
    if (display == EDisplay::kContents) {
      continue;
    }
    return display == EDisplay::kRuby || display == EDisplay::kBlockRuby;
  }
  return false;
}

String CreateLevel(
    const Vector<std::pair<wtf_size_t, wtf_size_t>>& depth_context) {
  StringBuilder builder;
  String delimiter;
  for (const auto [max, current] : depth_context) {
    builder.Append(delimiter);
    delimiter = String(base::span_from_ref(kLevelDelimiter));
    builder.AppendNumber(max - current + 1);
  }
  return builder.ToString();
}

class ChunkGraphBuilder {
  STACK_ALLOCATED();

 public:
  const Node* Build(const Node& first_visible_text_node,
                    const Node* end_node,
                    const Node& block_ancestor,
                    const Node* just_after_block) {
    bool did_see_range_start_node = false;
    bool did_see_range_end_node = false;
    const Node* node = &first_visible_text_node;
    if (const Node* ruby_container = FindOuterMostRubyContainerInBlockContainer(
            first_visible_text_node, block_ancestor)) {
      // If the range starts inside a <ruby>, we need to start analyzing the
      // <ruby>. We don't record Text nodes until first_visible_text_node.
      node = ruby_container;
    }
    // Used for checking if we reached a new block.
    const Node* last_added_text_node = nullptr;
    // This is a std::optional because nullptr is a valid value.
    std::optional<const Node*> next_start;

    parent_chunk_ = MakeGarbageCollected<CorpusChunk>();
    corpus_chunk_list_.push_back(parent_chunk_);

    while (node && node != just_after_block) {
      if (FindBuffer::ShouldIgnoreContents(*node)) {
        const Node* next = FlatTreeTraversal::NextSkippingChildren(*node);
        if (end_node && (end_node == node ||
                         FlatTreeTraversal::IsDescendantOf(*end_node, *node))) {
          did_see_range_end_node = true;
          if (!next_start) {
            next_start = next;
          }
        }
        if (std::optional<UChar> ch = FindBuffer::CharConstantForNode(*node)) {
          if (did_see_range_start_node && !did_see_range_end_node) {
            chunk_text_list_.push_back(TextOrChar(nullptr, *ch));
          }
        }
        node = next;
        continue;
      }
      const ComputedStyle* style =
          node->GetComputedStyleForElementOrLayoutObject();
      if (!style) {
        const Node* next = FlatTreeTraversal::NextSkippingChildren(*node);
        if (end_node && (end_node == node ||
                         FlatTreeTraversal::IsDescendantOf(*end_node, *node))) {
          did_see_range_end_node = true;
          if (!next_start) {
            next_start = next;
          }
        }
        node = next;
        continue;
      }

      EDisplay display = style->Display();
      if (IsA<Element>(*node)) {
        if (const Node* child = FlatTreeTraversal::FirstChild(*node)) {
          if (display == EDisplay::kContents) {
            node = child;
            continue;
          } else if (display == EDisplay::kRubyText) {
            HandleAnnotationStart(*node);
            node = child;
            continue;
          } else if (display == EDisplay::kRuby ||
                     display == EDisplay::kBlockRuby) {
            HandleRubyContainerStart();
            node = child;
            continue;
          }
        }
      }
      if (style->Visibility() == EVisibility::kVisible &&
          node->GetLayoutObject()) {
        // `node` is in its own sub-block separate from our starting position.
        if (last_added_text_node && !FindBuffer::IsInSameUninterruptedBlock(
                                        *last_added_text_node, *node)) {
          did_see_range_end_node = true;
          if (depth_context_.empty() && ruby_depth_ == 0) {
            break;
          }
          if (!next_start) {
            next_start = node;
          }
        }

        if (IsA<Element>(*node)) {
          if (const Node* child = FlatTreeTraversal::FirstChild(*node)) {
            node = child;
            continue;
          }
        }

        if (const auto* text = DynamicTo<Text>(*node)) {
          if (!did_see_range_start_node && first_visible_text_node == text) {
            did_see_range_start_node = true;
          }
          if (did_see_range_start_node && !did_see_range_end_node) {
            chunk_text_list_.push_back(TextOrChar(text, 0));
            last_added_text_node = node;
          }
        }
      }

      if (node == end_node) {
        did_see_range_end_node = true;
        if (!next_start) {
          next_start = FlatTreeTraversal::Next(*node);
        }
        if (depth_context_.empty() && ruby_depth_ == 0) {
          break;
        }
        // If the range ends inside a <ruby>, we need to continue analyzing the
        // <ruby>. We don't record Text nodes after end_node.
      }

      while (!FlatTreeTraversal::NextSibling(*node) &&
             node != &block_ancestor) {
        node = FlatTreeTraversal::ParentElement(*node);
        display = EDisplay::kNone;
        if ((style = node->GetComputedStyleForElementOrLayoutObject())) {
          display = style->Display();
        }
        if (display == EDisplay::kRubyText) {
          if (HandleAnnotationEnd(*node, did_see_range_end_node)) {
            break;
          }
        } else if (display == EDisplay::kRuby ||
                   display == EDisplay::kBlockRuby) {
          if (HandleRubyContainerEnd(did_see_range_end_node)) {
            break;
          }
        }
      }
      if (node == &block_ancestor) {
        node = FlatTreeTraversal::NextSkippingChildren(*node);
        break;
      }
      node = FlatTreeTraversal::NextSibling(*node);
    }
    if (chunk_text_list_.size() > 0) {
      parent_chunk_->Link(PushChunk(String(kAnyLevel)));
    }
    return next_start.value_or(node ? node : just_after_block);
  }

  const HeapVector<Member<CorpusChunk>>& ChunkList() const {
    return corpus_chunk_list_;
  }
  Vector<String> TakeLevelList() { return std::move(level_list_); }

 private:
  CorpusChunk* PushChunk(const String& level) {
    auto* new_chunk =
        MakeGarbageCollected<CorpusChunk>(chunk_text_list_, level);
    corpus_chunk_list_.push_back(new_chunk);
    chunk_text_list_.resize(0);
    return new_chunk;
  }

  CorpusChunk* PushBaseChunk() {
    if (depth_context_.size() > 0) {
      return PushChunk(CreateLevel(depth_context_));
    } else if (ruby_depth_ == 0) {
      return PushChunk(String(kAnyLevel));
    } else {
      return PushChunk(String(kBaseLevel));
    }
  }

  void PushBaseChunkAndLink() {
    auto* new_base_chunk = PushBaseChunk();
    parent_chunk_->Link(new_base_chunk);
    parent_chunk_ = new_base_chunk;
  }

  void HandleAnnotationStart(const Node& node) {
    CorpusChunk* new_base_chunk = PushBaseChunk();
    parent_chunk_->Link(new_base_chunk);
    if (IsParentRubyContainer(node)) {
      parent_chunk_ = parent_chunk_stack_.back();
      parent_chunk_stack_.pop_back();
    } else {
      parent_chunk_ = new_base_chunk;
      OpenRubyContainer();
      new_base_chunk = PushBaseChunk();
      parent_chunk_->Link(new_base_chunk);
    }
    base_last_chunk_stack_.push_back(new_base_chunk);
    depth_context_.push_back(std::make_pair(max_ruby_depth_, ruby_depth_));
    max_ruby_depth_ = 0;
    ruby_depth_ = 0;
    String level = CreateLevel(depth_context_);
    if (!level_list_.Contains(level)) {
      level_list_.push_back(level);
    }
  }

  // Returns true if we should exit the loop.
  bool HandleAnnotationEnd(const Node& node, bool did_see_range_end_node) {
    auto* rt_last_chunk = PushChunk(CreateLevel(depth_context_));
    parent_chunk_->Link(rt_last_chunk);

    CorpusChunk* base_last_chunk = base_last_chunk_stack_.back();
    base_last_chunk_stack_.pop_back();
    auto* void_chunk = MakeGarbageCollected<CorpusChunk>();
    corpus_chunk_list_.push_back(void_chunk);
    base_last_chunk->Link(void_chunk);
    rt_last_chunk->Link(void_chunk);
    parent_chunk_ = void_chunk;
    parent_chunk_stack_.push_back(parent_chunk_);

    auto pair = depth_context_.back();
    depth_context_.pop_back();
    max_ruby_depth_ = pair.first;
    ruby_depth_ = pair.second;
    if (ruby_depth_ == 1) {
      max_ruby_depth_ = 1;
    }
    return !IsParentRubyContainer(node) &&
           CloseRubyContainer(did_see_range_end_node);
  }

  void HandleRubyContainerStart() {
    if (chunk_text_list_.size() > 0) {
      PushBaseChunkAndLink();
    }
    // Save to use it on the start of the corresponding ruby-text.
    parent_chunk_stack_.push_back(parent_chunk_);

    OpenRubyContainer();
  }

  // Returns true if we should exit the loop.
  bool HandleRubyContainerEnd(bool did_see_range_end_node) {
    if (chunk_text_list_.size() > 0) {
      PushBaseChunkAndLink();
    }
    return CloseRubyContainer(did_see_range_end_node);
  }

  void OpenRubyContainer() {
    if (ruby_depth_ == 0) {
      max_ruby_depth_ = 1;
    }
    ++ruby_depth_;
    max_ruby_depth_ = std::max(ruby_depth_, max_ruby_depth_);
  }

  // Returns true if we should exit the loop.
  bool CloseRubyContainer(bool did_see_range_end_node) {
    parent_chunk_stack_.pop_back();
    if (--ruby_depth_ == 0) {
      max_ruby_depth_ = 0;
      if (depth_context_.empty() && did_see_range_end_node) {
        return true;
      }
    }
    return false;
  }

  // `corpus_chunk_list_` and `level_list_` are the deliverables of this class.
  HeapVector<Member<CorpusChunk>> corpus_chunk_list_;
  Vector<String> level_list_;

  // Fields required for intermediate data.
  CorpusChunk* parent_chunk_ = nullptr;
  wtf_size_t ruby_depth_ = 0;
  wtf_size_t max_ruby_depth_ = 0;
  Vector<std::pair<wtf_size_t, wtf_size_t>> depth_context_;
  HeapVector<Member<CorpusChunk>> parent_chunk_stack_;
  HeapVector<Member<CorpusChunk>> base_last_chunk_stack_;
  HeapVector<TextOrChar> chunk_text_list_;
};

}  // namespace

void TextOrChar::Trace(Visitor* visitor) const {
  visitor->Trace(text);
}

CorpusChunk::CorpusChunk() : level_(String(kAnyLevel)) {}

CorpusChunk::CorpusChunk(const HeapVector<TextOrChar>& text_list,
                         const String& level)
    : level_(level) {
  text_list_ = text_list;
}

void CorpusChunk::Trace(Visitor* visitor) const {
  visitor->Trace(text_list_);
  visitor->Trace(next_list_);
}

void CorpusChunk::Link(CorpusChunk* next_chunk) {
  next_list_.push_back(next_chunk);
}

const CorpusChunk* CorpusChunk::FindNext(const String& level) const {
  if (next_list_.empty()) {
    return nullptr;
  }
  const CorpusChunk* annotation_next = nullptr;
  for (const auto& chunk : next_list_) {
    if (chunk->level_ == kAnyLevel) {
      return chunk;
    } else if (level.empty() && chunk->level_ == kBaseLevel) {
      return chunk;
    } else if (chunk->level_ == level) {
      annotation_next = chunk;
    }
  }
  if (annotation_next) {
    return annotation_next;
  }
  // A single "base" link should be assumed as "any".  The "base" doesn't have
  // the requested level of an annotation.
  if (next_list_.size() == 1 && next_list_[0]->level_ == kBaseLevel) {
    return next_list_[0];
  }
  wtf_size_t delimiter_index = level.ReverseFind(kLevelDelimiter);
  if (delimiter_index == kNotFound) {
    // No link for `level`. It means the graph is incorrect.
    return nullptr;
  }
  return FindNext(level.Substring(0, delimiter_index));
}

std::tuple<HeapVector<Member<CorpusChunk>>, Vector<String>, const Node*>
BuildChunkGraph(const Node& first_visible_text_node,
                const Node* end_node,
                const Node& block_ancestor,
                const Node* just_after_block) {
  ChunkGraphBuilder builder;
  const Node* next_node = builder.Build(first_visible_text_node, end_node,
                                        block_ancestor, just_after_block);
  return {builder.ChunkList(), builder.TakeLevelList(), next_node};
}

}  // namespace blink
```