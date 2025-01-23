Response:
Let's break down the thought process for analyzing the given C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `SortedDocumentMarkerListEditor` class, its relationship to web technologies (JavaScript, HTML, CSS), examples of its use, potential errors, and how a user's action might lead to its invocation.

2. **Initial Code Scan and Keyword Identification:** Quickly scan the code, looking for class names, method names, data structures, and included headers. This gives a high-level overview. Keywords like "Marker," "List," "Sorted," "Add," "Move," "Remove," "Shift," "Intersecting," and "Offset" stand out. The inclusion of `<algorithm>` and `base/numerics/safe_conversions.h` hints at sorting and potentially index/offset manipulation. `SpellCheckMarkerListImpl.h` suggests a specific use case.

3. **Analyze Each Method:**  Go through each method of the class and understand its purpose:

    * **`AddMarkerWithoutMergingOverlapping`:**  The name suggests adding markers while ensuring no overlap. The code confirms this by using `std::lower_bound` to find the correct insertion point and `DCHECK` statements to assert non-overlapping conditions.

    * **`MoveMarkers`:**  This method moves markers from one list to another, likely due to text content being moved. The `length` parameter is crucial, indicating the range of the move. Trimming of markers to fit the destination is also important.

    * **`RemoveMarkers`:** This method removes markers within a given offset range. `std::upper_bound` and `std::lower_bound` are used to find the boundaries of the markers to be removed.

    * **`ShiftMarkersContentDependent`:**  This is more complex. The name suggests shifting markers based on content changes. The logic involves iterating through markers and either removing them if they fall within the modified content range or shifting their offsets.

    * **`ShiftMarkersContentIndependent`:** This seems similar to the previous one but handles shifting in a way that *doesn't* assume the content within the marked range is always removed. The `ComputeOffsetsAfterShift` method (though not defined in this file) is key, suggesting it calculates new offsets based on insertion or deletion.

    * **`FirstMarkerIntersectingRange`:** This method finds the first marker that overlaps with a given range. `std::lower_bound` is used efficiently.

    * **`MarkersIntersectingRange`:** This finds *all* markers overlapping a given range, again using `std::lower_bound` and `std::upper_bound` for efficient filtering.

4. **Infer Functionality and Purpose:** Based on the individual method analysis, the overall purpose of `SortedDocumentMarkerListEditor` becomes clear: it manages a *sorted* list of `DocumentMarker` objects. The sorting is based on the start offset. The class provides operations for adding, moving, removing, and shifting these markers, considering potential overlaps and content modifications.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**  This is where you connect the C++ code to the browser's rendering and interaction with web pages.

    * **Markers Represent Visual Annotations:** Think about what a "marker" could represent visually. Spellcheck underlines, grammar suggestions, find-in-page highlights, accessibility annotations, and even selection highlights are good candidates.

    * **HTML/DOM Connection:** Markers are associated with specific ranges *within* the text content of the HTML document (the DOM). The offsets directly relate to the character positions in text nodes.

    * **CSS Styling:**  While the core logic isn't CSS, the *effects* of these markers are often achieved through CSS. Adding a `<span>` with a specific class to apply underlines, background colors, etc. is a common implementation detail.

    * **JavaScript Interaction:** JavaScript code often triggers actions that lead to marker manipulation. Typing, spellchecking (triggered by JavaScript APIs or browser features), find-in-page functionality, and even programmatic text editing using JavaScript APIs could all interact with this C++ code indirectly.

6. **Create Examples:**  Illustrate the functionality with concrete examples. For each method, consider a simple scenario and how the input and output would look. Focus on the key parameters like offsets and lengths.

7. **Identify Potential Errors:** Think about common programming mistakes or user actions that could cause issues. Incorrect offset calculations, off-by-one errors, attempting to add overlapping markers when not allowed, and race conditions (though not directly evident in this code snippet) are all possibilities.

8. **Trace User Actions:**  Connect user interactions in the browser to the underlying C++ code. Imagine a user typing, right-clicking for spellcheck, using "Find," or pasting text. Explain how these actions might eventually lead to the execution of methods in `SortedDocumentMarkerListEditor`. This is about creating a plausible "call stack" or sequence of events.

9. **Structure and Refine:** Organize the information logically. Start with the general functionality, then detail each method, and then discuss the connections to web technologies, examples, errors, and user actions. Use clear and concise language. Ensure the examples are easy to understand.

10. **Review and Iterate:** Read through your analysis to ensure accuracy and completeness. Are there any ambiguities? Can the explanations be clearer? Have you addressed all parts of the request?  For example, double-checking the `DCHECK` conditions in `AddMarkerWithoutMergingOverlapping` reinforces the non-overlapping constraint.

This iterative process of code analysis, inference, connecting to broader concepts, and creating concrete examples is crucial for understanding complex codebases like Blink.
这个文件 `sorted_document_marker_list_editor.cc` 属于 Chromium Blink 渲染引擎，主要负责对文档中的标记（`DocumentMarker`）列表进行编辑和管理，并保持列表的排序状态。 这些标记可能代表了各种各样的信息，例如拼写错误、语法建议、查找结果高亮等。由于列表需要保持排序，以便高效地查找和操作标记，这个编辑器提供了一系列操作来维护这个排序特性。

以下是该文件的主要功能：

**核心功能：管理和编辑排序的文档标记列表**

1. **`AddMarkerWithoutMergingOverlapping(MarkerList* list, DocumentMarker* marker)`:**
   - **功能:** 向已排序的标记列表 `list` 中添加一个新的 `DocumentMarker`，但前提是新标记不会与列表中已有的标记重叠。如果列表为空或新标记的起始位置在列表末尾标记的结束位置之后，则直接添加到末尾。否则，使用二分查找 (`std::lower_bound`) 找到合适的插入位置，并插入。
   - **排序保证:**  该方法保证插入后列表仍然按照 `StartOffset` 升序排列。
   - **重叠检查:** 通过 `DCHECK` 宏进行断言检查，确保要添加的标记不会与已有的标记重叠。
   - **假设输入与输出:**
     - **输入:** 一个已排序的 `MarkerList`，例如 `[{start: 10, end: 20}, {start: 30, end: 40}]`，以及一个新的 `DocumentMarker`，例如 `{start: 25, end: 28}`。
     - **输出:**  修改后的 `MarkerList`: `[{start: 10, end: 20}, {start: 25, end: 28}, {start: 30, end: 40}]`。
     - **假设输入导致错误:** 如果输入的 `MarkerList` 为 `[{start: 10, end: 20}, {start: 30, end: 40}]`，而要添加的 `DocumentMarker` 是 `{start: 15, end: 25}`，由于与现有标记重叠，会触发 `DCHECK` 失败，程序通常会在调试版本中断。

2. **`MoveMarkers(MarkerList* src_list, int length, DocumentMarkerList* dst_list)`:**
   - **功能:** 将源标记列表 `src_list` 中前 `length` 范围内的标记移动到目标标记列表 `dst_list` 中。
   - **范围限制:**  只移动起始位置在 `length` 范围内的标记。
   - **修剪标记:** 如果移动的标记的结束位置超出 `length`，则会将其修剪到 `length`。
   - **删除源标记:** 移动完成后，从源列表中移除已移动的标记。
   - **假设输入与输出:**
     - **假设输入:** `src_list` 为 `[{start: 5, end: 10}, {start: 12, end: 15}, {start: 18, end: 22}]`， `length` 为 16， `dst_list` 为空。
     - **假设输出:** `src_list` 变为 `[{start: 18, end: 22}]`， `dst_list` 变为 `[{start: 5, end: 10}, {start: 12, end: 15}]`。 注意第二个标记没有被修剪。
     - **假设输入导致行为改变:** 如果 `length` 为 8，则只有第一个标记会被移动，且不会被修剪。

3. **`RemoveMarkers(MarkerList* list, unsigned start_offset, int length)`:**
   - **功能:** 从标记列表 `list` 中移除指定范围内的标记。
   - **范围定义:** 移除起始于 `start_offset`，长度为 `length` 的文本范围所覆盖的标记。
   - **查找边界:** 使用 `std::upper_bound` 和 `std::lower_bound` 找到需要移除的标记的起始和结束迭代器。
   - **假设输入与输出:**
     - **假设输入:** `list` 为 `[{start: 5, end: 10}, {start: 8, end: 12}, {start: 15, end: 20}]`， `start_offset` 为 7， `length` 为 6。
     - **假设输出:** `list` 变为 `[{start: 15, end: 20}]`。  起始位置在 7 之前结束位置在 7+6=13 之前的标记都被移除。
     - **逻辑推理:**  第一个标记的结束位置 (10) 大于 `start_offset` (7)，第二个标记的起始位置 (8) 小于 `start_offset + length` (13)。因此这两个标记都被移除。

4. **`ShiftMarkersContentDependent(MarkerList* list, unsigned offset, unsigned old_length, unsigned new_length)`:**
   - **功能:** 根据文档内容的变化来调整标记列表中标记的位置。当文档中某个范围的文本被替换时，会影响到后续标记的位置。
   - **内容依赖:** 如果标记的起始位置在被修改的文本范围内，则该标记会被移除。
   - **偏移调整:** 如果标记的起始位置在被修改的文本范围之后，则其起始和结束偏移量会根据新旧长度的差异进行调整 (`new_length - old_length`)。
   - **查找起始点:** 使用 `std::upper_bound` 找到第一个结束位置在 `offset` 之后的标记，减少遍历范围。
   - **假设输入与输出:**
     - **假设输入:** `list` 为 `[{start: 5, end: 10}, {start: 8, end: 12}, {start: 15, end: 20}]`， `offset` 为 7， `old_length` 为 4， `new_length` 为 6 (表示从偏移 7 开始，长度为 4 的文本被长度为 6 的文本替换)。
     - **假设输出:** `list` 变为 `[{start: 17, end: 22}]`。
     - **逻辑推理:**
       - 第一个标记的结束位置 (10) 大于 `offset` (7)。
       - 第二个标记的起始位置 (8) 在被修改的范围内 (7 到 7 + 4 = 11)，因此被移除。
       - 第三个标记的起始位置 (15) 在被修改的范围之后，偏移量增加 `6 - 4 = 2`。

5. **`ShiftMarkersContentIndependent(MarkerList* list, unsigned offset, unsigned old_length, unsigned new_length)`:**
   - **功能:**  与 `ShiftMarkersContentDependent` 类似，也用于调整标记的位置，但它不直接移除位于被修改范围内的标记，而是根据 `DocumentMarker::ComputeOffsetsAfterShift` 的结果来决定如何处理标记。
   - **内容独立:** 即使标记在被修改的范围内，也可能通过 `ComputeOffsetsAfterShift` 计算出新的偏移量，而不是直接被移除。
   - **`ComputeOffsetsAfterShift`:**  这是一个 `DocumentMarker` 类的方法（此处未定义），它封装了具体的偏移量计算逻辑。如果该方法返回 `std::nullopt`，则表示该标记应该被移除。
   - **假设输入与输出:**
     - **假设输入:** `list` 为 `[{start: 5, end: 10}, {start: 8, end: 12}, {start: 15, end: 20}]`， `offset` 为 7， `old_length` 为 4， `new_length` 为 6。 假设 `DocumentMarker::ComputeOffsetsAfterShift` 对于起始位置为 8 的标记返回 `std::nullopt`。
     - **假设输出:** `list` 可能变为 `[{start: 5, end: 10}, {start: 17, end: 22}]`。
     - **逻辑推理:**
       - 第一个标记不受影响。
       - 第二个标记通过 `ComputeOffsetsAfterShift` 返回 `std::nullopt`，因此被移除。
       - 第三个标记的偏移量根据 `ComputeOffsetsAfterShift` 的计算结果进行调整（假设计算结果为起始位置 +2）。

6. **`FirstMarkerIntersectingRange(const MarkerList& list, unsigned start_offset, unsigned end_offset)`:**
   - **功能:**  在已排序的标记列表 `list` 中查找第一个与指定范围 `[start_offset, end_offset)` 相交的标记。
   - **二分查找:** 使用 `std::lower_bound` 高效地找到可能相交的第一个标记。
   - **相交判断:**  判断找到的标记是否与给定的范围存在重叠。
   - **假设输入与输出:**
     - **假设输入:** `list` 为 `[{start: 5, end: 10}, {start: 12, end: 15}, {start: 18, end: 22}]`， `start_offset` 为 9， `end_offset` 为 14。
     - **假设输出:** 指向 `{start: 5, end: 10}` 的指针。
     - **逻辑推理:**  通过 `lower_bound` 找到第一个结束位置不小于 `start_offset` (9) 的标记，即第一个标记。然后判断该标记的起始位置 (5) 是否小于 `end_offset` (14)，结果为真，返回该标记。

7. **`MarkersIntersectingRange(const MarkerList& list, unsigned start_offset, unsigned end_offset)`:**
   - **功能:**  在已排序的标记列表 `list` 中查找所有与指定范围 `[start_offset, end_offset)` 相交的标记。
   - **范围查找:** 使用 `std::lower_bound` 找到第一个可能相交的标记，使用 `std::upper_bound` 找到第一个结束相交的标记之后的位置。
   - **返回结果:** 返回一个包含所有相交标记的 `HeapVector`。
   - **假设输入与输出:**
     - **假设输入:** `list` 为 `[{start: 5, end: 10}, {start: 8, end: 12}, {start: 11, end: 14}, {start: 16, end: 20}]`， `start_offset` 为 9， `end_offset` 为 13。
     - **假设输出:**  包含 `{start: 5, end: 10}`， `{start: 8, end: 12}` 和 `{start: 11, end: 14}` 的 `HeapVector`。
     - **逻辑推理:**
       - `lower_bound` 找到第一个结束位置不小于 9 的标记 (第一个标记)。
       - `upper_bound` 找到第一个起始位置不小于 13 的标记 (第四个标记)。
       - 返回这两个迭代器之间的所有标记。

**与 JavaScript, HTML, CSS 的关系：**

虽然这个 C++ 文件本身不包含 JavaScript, HTML 或 CSS 代码，但它在浏览器渲染引擎中扮演着关键角色，处理与这些技术相关的标记信息：

* **拼写检查/语法检查:**
    - **用户操作:** 用户在 HTML `textarea` 或 `contenteditable` 元素中输入文本时，拼写检查和语法检查功能可能会被触发。
    - **C++ 交互:**  当检测到拼写或语法错误时，Blink 引擎会创建 `DocumentMarker` 对象来标记这些错误。`SortedDocumentMarkerListEditor` 用于管理这些标记的列表。
    - **CSS 渲染:**  通常，这些标记会通过 CSS 进行视觉呈现，例如在错误单词下方绘制红色波浪线。JavaScript 可以用来监听用户的操作，并可能与浏览器的拼写检查 API 交互。
    - **例子:** 用户在输入框中输入 "Thsi is a eror."。拼写检查器会识别 "Thsi" 和 "eror" 是错误的，并在内部创建相应的 `DocumentMarker`，并通过 `SortedDocumentMarkerListEditor` 添加到文档的标记列表中。然后，渲染引擎会根据这些标记的信息，应用 CSS 样式，例如在 "Thsi" 和 "eror" 下方显示红色波浪线。

* **查找功能 (Find in Page):**
    - **用户操作:** 用户按下 Ctrl+F (或 Cmd+F) 并输入要查找的文本。
    - **C++ 交互:**  Blink 引擎会在当前页面中搜索匹配的文本，并为每个匹配项创建一个 `DocumentMarker`，表示查找结果的高亮范围。`SortedDocumentMarkerListEditor` 用于管理这些高亮标记。
    - **CSS 渲染:**  查找结果通常会通过 CSS 高亮显示，例如使用不同的背景颜色。JavaScript 可以用来控制查找对话框的显示和与用户的交互。
    - **例子:** 用户在一个包含 "example text" 的页面中查找 "exam"。Blink 引擎会找到 "exam" 的匹配项，创建一个 `DocumentMarker` 标记 "exam" 的范围，并使用 `SortedDocumentMarkerListEditor` 管理该标记。然后，渲染引擎会应用 CSS 样式，将 "exam" 这部分文本高亮显示。

* **文本选择:**
    - **用户操作:** 用户使用鼠标拖动或键盘操作选择页面上的文本。
    - **C++ 交互:**  Blink 引擎会创建 `DocumentMarker` 来表示当前选中的文本范围。
    - **CSS 渲染:**  选中的文本通常会通过 CSS 应用特殊的背景色和文本颜色来突出显示。JavaScript 可以用来获取或设置当前的文本选择。
    - **例子:** 用户选中了 HTML 文档中的一段文字。Blink 引擎会创建一个 `DocumentMarker` 来标记这个选区，并使用 `SortedDocumentMarkerListEditor` 进行管理。渲染引擎会应用 CSS 样式，高亮显示选中的文本。

* **其他类型的文档注解/标记:**
    - 开发者工具中的代码断点、Linter 或 IDE 的警告/错误标记等，也可以通过类似的机制在渲染引擎中实现。

**用户或编程常见的使用错误：**

1. **尝试添加重叠的标记 (对于不允许重叠的列表):**
   - **错误场景:**  在调用 `AddMarkerWithoutMergingOverlapping` 时，如果提供的 `marker` 与列表中已有的标记在起始或结束位置上有重叠，将会触发 `DCHECK` 失败，这通常发生在开发或调试版本中。
   - **用户操作导致:**  例如，一个拼写检查器在同一个单词上发现了两个不同的错误（例如，拼写错误和语法错误），如果尝试将这两个错误作为不重叠的标记添加到同一个列表中，就会发生错误。
   - **调试线索:**  如果在调试器中看到 `DCHECK` 相关的错误信息，并且涉及到 `SortedDocumentMarkerListEditor::AddMarkerWithoutMergingOverlapping`，则需要检查添加标记的逻辑，确保不会添加重叠的标记，或者考虑使用允许重叠的列表管理方式。

2. **错误的偏移量计算导致标记错位或丢失:**
   - **错误场景:** 在使用 `ShiftMarkersContentDependent` 或 `ShiftMarkersContentIndependent` 时，如果传递的 `offset`, `old_length`, `new_length` 参数不正确，可能导致标记的位置计算错误，甚至被错误地移除。
   - **用户操作导致:**  当用户在文本编辑器中进行复杂的编辑操作（例如，插入、删除、替换多行文本）时，如果相关代码没有正确地计算偏移量变化，就可能导致标记管理出现问题。
   - **调试线索:**  如果用户报告拼写错误或查找高亮等标记显示位置不正确，或者在文本编辑后标记突然消失，可以检查 `ShiftMarkers...` 相关函数的调用参数是否正确，以及 `DocumentMarker::ComputeOffsetsAfterShift` 的实现逻辑是否符合预期。

3. **在多线程环境下并发修改标记列表而没有适当的同步措施:**
   - **错误场景:**  虽然代码片段本身没有显式地展示多线程问题，但在实际的 Blink 渲染引擎中，可能会有多个线程同时访问和修改文档标记列表。如果没有适当的锁或其他同步机制，可能导致数据竞争和未定义的行为。
   - **用户操作导致:**  这通常不是直接由用户的单一操作触发，而是由于浏览器内部的复杂并发操作导致的。例如，用户正在输入文本，同时后台线程可能正在进行拼写检查或同步操作。
   - **调试线索:**  如果出现难以复现的崩溃或数据异常，并且涉及到文档标记列表的修改，需要仔细检查相关的线程安全性和同步机制。

**用户操作如何一步步的到达这里，作为调试线索:**

以拼写检查为例，说明用户操作如何一步步地触发 `SortedDocumentMarkerListEditor` 的使用：

1. **用户在可编辑区域输入文本:** 用户在一个带有 `contenteditable` 属性的 HTML 元素或者一个 `<textarea>` 中输入文字，例如输入 "MisspelledWord".
2. **拼写检查器触发:** 浏览器内置的拼写检查功能（或由 JavaScript 触发的外部拼写检查 API）会分析用户输入的文本。
3. **检测到拼写错误:** 拼写检查器识别出 "MisspelledWord" 是一个拼写错误的单词。
4. **创建 `DocumentMarker`:** Blink 引擎会创建一个 `DocumentMarker` 对象，用于标记 "MisspelledWord" 这个范围，并指定标记的类型为拼写错误。这个 `DocumentMarker` 会包含起始和结束的偏移量信息。
5. **调用 `SortedDocumentMarkerListEditor::AddMarkerWithoutMergingOverlapping`:**  Blink 引擎会获取当前文本节点的标记列表，并调用 `SortedDocumentMarkerListEditor::AddMarkerWithoutMergingOverlapping` 方法，将新创建的拼写错误标记添加到列表中。
6. **渲染引擎更新显示:** 渲染引擎会遍历文档的标记列表，并根据标记的类型和位置应用相应的样式。对于拼写错误标记，通常会在错误单词下方绘制红色波浪线。

**调试线索:** 如果在上述过程中出现问题，例如拼写错误没有被标记出来，或者标记的位置不正确，可以按照以下线索进行调试：

* **断点:** 在 `SortedDocumentMarkerListEditor::AddMarkerWithoutMergingOverlapping` 方法入口处设置断点，查看是否有新的拼写错误标记被尝试添加，以及标记的偏移量是否正确。
* **检查 `DocumentMarker` 的创建:**  向上追溯调用堆栈，查看 `DocumentMarker` 对象是在哪里创建的，以及创建时的偏移量信息是否正确。
* **检查拼写检查器的输出:**  查看拼写检查器是否正确地识别出了拼写错误，并输出了正确的错误范围信息。
* **查看标记列表的内容:** 在添加标记前后，检查标记列表的内容，确认标记是否被正确地添加和排序。
* **检查渲染逻辑:** 查看渲染引擎是如何根据标记列表的信息来绘制拼写错误下划线的，确认 CSS 样式是否正确应用。

通过理解 `SortedDocumentMarkerListEditor` 的功能和它在 Blink 引擎中的作用，可以更好地理解浏览器是如何处理文档中的各种标记信息的，并为调试相关问题提供有力的支持。

### 提示词
```
这是目录为blink/renderer/core/editing/markers/sorted_document_marker_list_editor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/markers/sorted_document_marker_list_editor.h"

#include <algorithm>

#include "base/numerics/safe_conversions.h"
#include "third_party/blink/renderer/core/editing/markers/spell_check_marker_list_impl.h"

namespace blink {

void SortedDocumentMarkerListEditor::AddMarkerWithoutMergingOverlapping(
    MarkerList* list,
    DocumentMarker* marker) {
  if (list->empty() || list->back()->EndOffset() <= marker->StartOffset()) {
    list->push_back(marker);
    return;
  }

  auto const pos = std::lower_bound(
      list->begin(), list->end(), marker,
      [](const Member<DocumentMarker>& marker_in_list,
         const DocumentMarker* marker_to_insert) {
        return marker_in_list->StartOffset() < marker_to_insert->StartOffset();
      });

  // DCHECK that we're not trying to add a marker that overlaps an existing one
  // (this method only works for lists which don't allow overlapping markers)
  if (pos != list->end())
    DCHECK_LE(marker->EndOffset(), (*pos)->StartOffset());

  if (pos != list->begin())
    DCHECK_GE(marker->StartOffset(), (*std::prev(pos))->EndOffset());

  list->insert(base::checked_cast<wtf_size_t>(pos - list->begin()), marker);
}

bool SortedDocumentMarkerListEditor::MoveMarkers(MarkerList* src_list,
                                                 int length,
                                                 DocumentMarkerList* dst_list) {
  DCHECK_GT(length, 0);
  unsigned num_moved = 0;
  unsigned end_offset = length - 1;

  for (auto marker : *src_list) {
    if (marker->StartOffset() > end_offset) {
      break;
    }

    // Trim the marker to fit in dst_list's text node
    if (marker->EndOffset() > end_offset) {
      marker->SetEndOffset(end_offset);
    }

    dst_list->Add(marker);
    num_moved++;
  }

  // Remove the range of markers that were moved to dstNode
  src_list->EraseAt(0, num_moved);

  return num_moved;
}

bool SortedDocumentMarkerListEditor::RemoveMarkers(MarkerList* list,
                                                   unsigned start_offset,
                                                   int length) {
  const unsigned end_offset = start_offset + length;
  MarkerList::iterator start_pos = std::upper_bound(
      list->begin(), list->end(), start_offset,
      [](size_t start_offset, const Member<DocumentMarker>& marker) {
        return start_offset < marker->EndOffset();
      });

  MarkerList::iterator end_pos = std::lower_bound(
      list->begin(), list->end(), end_offset,
      [](const Member<DocumentMarker>& marker, size_t end_offset) {
        return marker->StartOffset() < end_offset;
      });

  list->EraseAt(base::checked_cast<wtf_size_t>(start_pos - list->begin()),
                base::checked_cast<wtf_size_t>(end_pos - start_pos));
  return start_pos != end_pos;
}

bool SortedDocumentMarkerListEditor::ShiftMarkersContentDependent(
    MarkerList* list,
    unsigned offset,
    unsigned old_length,
    unsigned new_length) {
  // Find first marker that ends after the start of the region being edited.
  // Markers before this one can be left untouched. This saves us some time over
  // scanning the entire list linearly if the edit region is near the end of the
  // text node.
  const MarkerList::iterator& shift_range_begin =
      std::upper_bound(list->begin(), list->end(), offset,
                       [](size_t offset, const Member<DocumentMarker>& marker) {
                         return offset < marker->EndOffset();
                       });

  wtf_size_t num_removed = 0;
  bool did_shift_marker = false;

  auto begin_offset =
      base::checked_cast<wtf_size_t>(shift_range_begin - list->begin());
  auto num_after_begin = list->size() - begin_offset;
  auto sub_span = base::span(*list).subspan(begin_offset, num_after_begin);
  for (auto marker : sub_span) {
    // marked text is (potentially) changed by edit, remove marker
    if (marker->StartOffset() < offset + old_length) {
      num_removed++;
      did_shift_marker = true;
      continue;
    }

    // marked text is shifted but not changed
    marker->ShiftOffsets(new_length - old_length);
    did_shift_marker = true;
  }

  // Note: shift_range_begin could point at a marker being shifted instead of
  // deleted, but if this is the case, we don't need to delete any markers, and
  // EraseAt() will get 0 for the length param
  list->EraseAt(begin_offset, num_removed);
  return did_shift_marker;
}

bool SortedDocumentMarkerListEditor::ShiftMarkersContentIndependent(
    MarkerList* list,
    unsigned offset,
    unsigned old_length,
    unsigned new_length) {
  // Find first marker that ends after the start of the region being edited.
  // Markers before this one can be left untouched. This saves us some time over
  // scanning the entire list linearly if the edit region is near the end of the
  // text node.
  const MarkerList::iterator& shift_range_begin =
      std::upper_bound(list->begin(), list->end(), offset,
                       [](size_t offset, const Member<DocumentMarker>& marker) {
                         return offset < marker->EndOffset();
                       });

  auto position =
      base::checked_cast<wtf_size_t>(shift_range_begin - list->begin());
  auto num_to_adjust = list->size() - position;
  auto sub_span = base::span(*list).subspan(position, num_to_adjust);

  wtf_size_t erase_start_index = 0;
  wtf_size_t num_to_erase = 0;
  bool did_shift_marker = false;

  for (auto marker : sub_span) {
    std::optional<DocumentMarker::MarkerOffsets> result =
        marker->ComputeOffsetsAfterShift(offset, old_length, new_length);
    if (result == std::nullopt) {
      if (!num_to_erase) {
        erase_start_index = position;
      }
      num_to_erase++;
      did_shift_marker = true;
      position++;
      continue;
    }

    if (marker->StartOffset() != result.value().start_offset ||
        marker->EndOffset() != result.value().end_offset) {
      did_shift_marker = true;
      marker->SetStartOffset(result.value().start_offset);
      marker->SetEndOffset(result.value().end_offset);
    }
    position++;
  }

  list->EraseAt(erase_start_index, num_to_erase);
  return did_shift_marker;
}

DocumentMarker* SortedDocumentMarkerListEditor::FirstMarkerIntersectingRange(
    const MarkerList& list,
    unsigned start_offset,
    unsigned end_offset) {
  DCHECK_LE(start_offset, end_offset);

  auto const marker_it =
      std::lower_bound(list.begin(), list.end(), start_offset,
                       [](const DocumentMarker* marker, unsigned start_offset) {
                         return marker->EndOffset() <= start_offset;
                       });
  if (marker_it == list.end())
    return nullptr;

  DocumentMarker* marker = *marker_it;
  if (marker->StartOffset() >= end_offset)
    return nullptr;
  return marker;
}

HeapVector<Member<DocumentMarker>>
SortedDocumentMarkerListEditor::MarkersIntersectingRange(const MarkerList& list,
                                                         unsigned start_offset,
                                                         unsigned end_offset) {
  DCHECK_LE(start_offset, end_offset);

  auto const start_it =
      std::lower_bound(list.begin(), list.end(), start_offset,
                       [](const DocumentMarker* marker, unsigned start_offset) {
                         return marker->EndOffset() <= start_offset;
                       });
  auto const end_it =
      std::upper_bound(list.begin(), list.end(), end_offset,
                       [](unsigned end_offset, const DocumentMarker* marker) {
                         return end_offset <= marker->StartOffset();
                       });

  HeapVector<Member<DocumentMarker>> results;
  std::copy(start_it, end_it, std::back_inserter(results));
  return results;
}

}  // namespace blink
```