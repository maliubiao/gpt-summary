Response:
Let's break down the thought process for analyzing the `inspector_diff.cc` file.

1. **Understand the Core Purpose:** The file name `inspector_diff.cc` immediately suggests it's about finding differences between two things within the context of the Chromium inspector. The `#include` statements confirm this, bringing in inspector-related headers and general utility headers.

2. **Identify the Key Algorithm:** The comment at the top mentions "MyersDiff" and points to its origin in V8's live edit feature. This is a crucial piece of information. Knowing it's Myers Algorithm gives a solid foundation for understanding the code's intent. A quick mental note (or actual note) should be made that this algorithm finds the shortest edit script to transform one sequence into another.

3. **Dissect the Main Class: `MyersDiffer`:**  This class is the heart of the file. Break it down section by section:

    * **Nested Structures:**  `Point`, `EditGraphArea`, `Path`, `Snake`. These represent the fundamental concepts of the Myers algorithm applied to the edit graph. Understanding their relationships is key. The comments are very helpful here. For instance, the definition of a "snake" is important.

    * **`FurthestReaching`:** This looks like an optimization. The comments explain it's for tracking the furthest reaching path for each k-diagonal. The use of negative indexing is a bit unusual, so pay attention to the implementation details (`index >= 0 ? index : v_.size() + index`).

    * **`ResultWriter`:** This class's purpose is clear from its name and the comment: converting the edit path into a source mapping.

    * **Private Members:** `input_`, `output_`, `fr_forward_`, `fr_reverse_`. These are the data the algorithm operates on and the intermediate/final results.

    * **Core Logic Functions:**
        * `FindEditPath`:  Recursively finds the edit path using the "divide and conquer" approach based on the middle snake.
        * `FindMiddleSnake`: Implements the core of Myers algorithm, finding the middle snake where the forward and reverse paths meet. This is the most complex part.
        * `ShortestEditForward`, `ShortestEditReverse`:  These functions calculate the furthest reaching paths in the forward and reverse directions for a given edit distance `d`.
        * `WriteResult`: Takes the calculated path and uses the `ResultWriter` to generate the output.
        * `WalkDiagonal`:  A helper function to handle diagonal moves.

4. **Analyze the `MappingInput` and `MappingOutput` Classes:**  These classes adapt the generic `MyersDiffer` to work with lists of strings. They implement the `InspectorDiff::Input` and `InspectorDiff::Output` interfaces, providing the specific logic for comparing strings and recording matches. The `start_offset` and `end_offset` suggest an optimization for handling common prefixes and suffixes.

5. **Examine the Public Interface:** `InspectorDiff::CalculateMatches` and `InspectorDiff::FindLCSMapping`. `CalculateMatches` directly uses `MyersDiffer`. `FindLCSMapping` performs the prefix/suffix optimization and then uses `CalculateMatches` for the remaining middle part. The acronym LCS (Longest Common Subsequence) is significant here.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):** Now, think about where this diffing functionality would be useful in a browser inspector.

    * **JavaScript:** Comparing versions of JavaScript code after edits (live edit functionality). The input would be lines of code.
    * **HTML:**  Comparing DOM tree structures or the textual representation of HTML. The input could be tag names and attributes.
    * **CSS:** Comparing CSS rule sets. The input could be CSS property-value pairs or lines of CSS code.

7. **Construct Examples and Scenarios:**  Think about simple cases to illustrate the algorithm's behavior. This helps in understanding the "logic reasoning" aspect.

8. **Consider Potential User/Programming Errors:**  What could go wrong when using this code?  Focus on the assumptions and constraints.

    * Incorrect input format for `FindLCSMapping`.
    * Misinterpreting the meaning of the `InspectorIndexMap`.
    * Performance issues with very large inputs (though the algorithm is designed to be efficient).

9. **Structure the Output:** Organize the findings logically, starting with the high-level functionality and then diving into details, examples, and potential issues. Use clear headings and bullet points for readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Is this just about text diffing?"  **Correction:** Realize the `MappingInput` and `MappingOutput` allow it to work with lists of *any* strings, making it more general for comparing sequences.
* **Confusion about diagonals:**  Double-check the comments and the logic in `ShortestEditForward` and `ShortestEditReverse` to fully grasp the k-diagonal and l-diagonal concepts and how the forward and reverse searches interact.
* **Overlooking the prefix/suffix optimization:** Initially focus on `MyersDiffer`. **Correction:** Notice the `FindLCSMapping` function and its prefix/suffix handling, recognizing it as an important optimization.

By following these steps, systematically dissecting the code, and connecting it to the broader context of web development, you can effectively analyze the functionality of the `inspector_diff.cc` file.
这个文件 `blink/renderer/core/inspector/inspector_diff.cc` 的主要功能是**计算两个序列之间的差异**，并提供一种方式来**映射这两个序列中相同的部分**。它使用了 **Myers 差分算法**，这是一种高效的算法，用于找到将一个序列转换为另一个序列所需的最小编辑操作（插入和删除）。

以下是更详细的功能列表：

**核心功能:**

1. **实现 Myers 差分算法:**  文件中 `MyersDiffer` 类实现了 Myers 差分算法，用于找到两个序列（由 `InspectorDiff::Input` 提供）之间的最短编辑脚本。这个算法的核心是找到编辑图中的最短路径。

2. **计算最短编辑路径:** `FindEditPath` 方法递归地找到两个给定点之间的最短编辑路径，通过不断寻找“中间蛇形”（middle snake）来分割问题。

3. **寻找中间蛇形 (Middle Snake):** `FindMiddleSnake` 方法是 Myers 算法的关键部分，它通过同时从起点和终点搜索来找到中间的匹配段，从而有效地分割问题。

4. **正向和反向最短编辑路径计算:** `ShortestEditForward` 和 `ShortestEditReverse` 方法分别计算从起点和终点出发的最短编辑路径，用于找到中间蛇形。

5. **结果写入:** `WriteResult` 方法将计算出的编辑路径转换为 `InspectorDiff::Output` 对象可以理解的格式，通常是标记哪些部分是匹配的。

**与 JavaScript, HTML, CSS 的关系:**

虽然这个文件本身是用 C++ 编写的，但它的功能直接服务于浏览器开发者工具 (Inspector)，而开发者工具经常需要比较不同状态的 JavaScript 代码、HTML 结构和 CSS 样式。

* **JavaScript:**
    * **功能:**  可以用于比较两个版本的 JavaScript 代码，例如在代码编辑器中进行实时编辑时，或者在调试过程中查看代码修改历史。
    * **举例:** 假设用户在 Inspector 的 Sources 面板中修改了一段 JavaScript 代码。`inspector_diff.cc` 可以用来计算修改前后的代码差异，从而高亮显示哪些行被添加、删除或修改。
    * **假设输入:** 原始 JavaScript 代码字符串列表 `["const a = 1;", "console.log(a);"]`，修改后的代码字符串列表 `["let a = 1;", "console.log(a + 1);"]`。
    * **假设输出:**  指示第一行发生了修改（"const" 变为 "let"），第二行也发生了修改（增加了 " + 1"）。

* **HTML:**
    * **功能:**  可以用于比较两个版本的 DOM 树结构或 HTML 字符串，例如在 Elements 面板中查看元素属性的变化，或者比较不同状态下的 HTML 结构。
    * **举例:**  在 Inspector 的 Elements 面板中，用户可能通过 JavaScript 修改了某个元素的 class 属性。`inspector_diff.cc` 可以用来比较修改前后的 class 属性值。
    * **假设输入:** 原始 HTML 属性字符串列表 `["class=\"old-class\"", "id=\"my-element\""]`，修改后的 HTML 属性字符串列表 `["class=\"new-class\"", "id=\"my-element\""]`。
    * **假设输出:** 指示第一个属性值发生了修改（"old-class" 变为 "new-class"），第二个属性值没有变化。

* **CSS:**
    * **功能:**  可以用于比较两个版本的 CSS 规则或样式属性，例如在 Styles 面板中查看样式变化，或者比较不同 CSS 文件之间的差异。
    * **举例:**  在 Inspector 的 Styles 面板中，用户可能修改了某个元素的 CSS 样式，例如改变了颜色值。`inspector_diff.cc` 可以用来比较修改前后的 CSS 属性值。
    * **假设输入:** 原始 CSS 属性字符串列表 `["color: red;", "font-size: 16px;"]`，修改后的 CSS 属性字符串列表 `["color: blue;", "font-size: 16px;"]`。
    * **假设输出:** 指示第一个属性值发生了修改（"red" 变为 "blue"），第二个属性值没有变化。

**逻辑推理的例子:**

`MyersDiffer` 类中的 `FindMiddleSnake` 方法就是一个逻辑推理的例子。

* **假设输入:** 两个字符串 `A = "ABCX"` 和 `B = "AYC"`。
* **逻辑推理:**  算法会逐步构建编辑图，并寻找从 (0,0) 到 (4,3) 的最短路径。它会尝试不同的插入、删除和匹配操作。例如，它会发现 'A' 是匹配的，然后考虑 'B' 的插入或 'Y' 的插入，等等。通过迭代计算正向和反向的最短路径，最终找到一个“中间蛇形”，表示一个共同的子序列。
* **假设输出:**  找到的中间蛇形可能表示 'A' 是一个匹配，或者 'C' 是一个匹配。这个中间蛇形将问题分解为两个更小的子问题：比较 "BC" 和 "Y"，以及比较 "X" 和空字符串。

**用户或编程常见的使用错误:**

1. **输入数据类型不匹配:** `InspectorDiff` 需要 `InspectorDiff::Input` 接口的实现来提供要比较的数据。如果传递了错误的数据类型或者没有正确实现接口，会导致程序崩溃或产生错误的结果。
    * **举例:**  期望输入是字符串列表，但却传递了整数列表。

2. **假设两个序列可以完全匹配:** Myers 算法旨在找到将一个序列转换为另一个序列所需的最小编辑操作。如果假设两个序列应该完全相同，但实际上存在差异，则输出将指示这些差异，这可能与用户的预期不符。
    * **举例:**  比较两个几乎相同的 HTML 文档，但用户期望它们完全相同，而忽略了细微的空格或属性顺序差异。

3. **忽略性能考虑:** 对于非常大的序列，Myers 算法虽然相对高效，但仍然需要一定的计算时间。如果频繁地对大型数据进行差异计算，可能会影响性能。
    * **举例:**  实时比较非常大的代码文件，可能会导致 Inspector 界面卡顿。

4. **误解 `InspectorIndexMap` 的含义:** `FindLCSMapping` 使用 `InspectorIndexMap` 来记录最长公共子序列中元素的对应关系。如果开发者不理解这个映射的含义，可能会错误地使用它。
    * **举例:**  认为 `a_to_b` 中的映射是所有相同元素的映射，而实际上它只包含最长公共子序列中的元素的映射。

总而言之，`inspector_diff.cc` 提供了一个强大的工具，用于在浏览器开发者工具中进行各种差异比较操作，特别是针对 JavaScript、HTML 和 CSS 等 Web 技术。理解 Myers 算法的原理以及如何正确使用 `InspectorDiff` 接口是至关重要的。

Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_diff.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The MyersDiff was taken from v8/src/debug/liveedit-diff.cc

#include "third_party/blink/renderer/core/inspector/inspector_diff.h"

#include <cmath>
#include <map>
#include <optional>
#include <vector>

#include "base/check.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {

namespace {

// Implements Myer's Algorithm from
// "An O(ND) Difference Algorithm and Its Variations", particularly the
// linear space refinement mentioned in section 4b.
//
// The differ is input agnostic.
//
// The algorithm works by finding the shortest edit string (SES) in the edit
// graph. The SES describes how to get from a string A of length N to a string
// B of length M via deleting from A and inserting from B.
//
// Example: A = "abbaa", B = "abab"
//
//                  A
//
//          a   b   b   a    a
//        o---o---o---o---o---o
//      a | \ |   |   | \ | \ |
//        o---o---o---o---o---o
//      b |   | \ | \ |   |   |
//  B     o---o---o---o---o---o
//      a | \ |   |   | \ | \ |
//        o---o---o---o---o---o
//      b |   | \ | \ |   |   |
//        o---o---o---o---o---o
//
// The edit graph is constructed with the characters from string A on the x-axis
// and the characters from string B on the y-axis. Starting from (0, 0) we can:
//
//     - Move right, which is equivalent to deleting from A
//     - Move downwards, which is equivalent to inserting from B
//     - Move diagonally if the characters from string A and B match, which
//       means no insertion or deletion.
//
// Any path from (0, 0) to (N, M) describes a valid edit string, but we try to
// find the path with the most diagonals, conversely that is the path with the
// least insertions or deletions.
// Note that a path with "D" insertions/deletions is called a D-path.
class MyersDiffer {
 private:
  // A point in the edit graph.
  struct Point {
    int x, y;

    // Less-than for a point in the edit graph is defined as less than in both
    // components (i.e. at least one diagonal away).
    bool operator<(const Point& other) const {
      return x < other.x && y < other.y;
    }
  };

  // Describes a rectangle in the edit graph.
  struct EditGraphArea {
    Point top_left, bottom_right;

    int width() const { return bottom_right.x - top_left.x; }
    int height() const { return bottom_right.y - top_left.y; }
    int size() const { return width() + height(); }
    int delta() const { return width() - height(); }
  };

  // A path or path-segment through the edit graph. Not all points along
  // the path are necessarily listed since it is trivial to figure out all
  // the concrete points along a snake.
  struct Path {
    Vector<Point> points;

    void Add(const Point& p) { points.push_back(p); }
    void Add(const Path& p) { points.AppendVector(p.points); }
  };

  // A snake is a path between two points that is either:
  //
  //     - A single right or down move followed by a (possibly empty) list of
  //       diagonals (in the normal case).
  //     - A (possibly empty) list of diagonals followed by a single right or
  //       or down move (in the reverse case).
  struct Snake {
    Point from, to;
  };

  // A thin wrapper around Vector<int> that allows negative indexing.
  //
  // This class stores the x-value of the furthest reaching path
  // for each k-diagonal. k-diagonals are numbered from -M to N and defined
  // by y(x) = x - k.
  //
  // We only store the x-value instead of the full point since we can
  // calculate y via y = x - k.
  class FurthestReaching {
   public:
    explicit FurthestReaching(wtf_size_t size) : v_(size) {}

    int& operator[](int index) {
      const wtf_size_t idx = index >= 0 ? index : v_.size() + index;
      return v_[idx];
    }

    const int& operator[](int index) const {
      const wtf_size_t idx = index >= 0 ? index : v_.size() + index;
      return v_[idx];
    }

   private:
    Vector<int> v_;
  };

  class ResultWriter;

  InspectorDiff::Input* input_;
  InspectorDiff::Output* output_;

  // Stores the x-value of the furthest reaching path for each k-diagonal.
  // k-diagonals are numbered from '-height' to 'width', centered on (0,0) and
  // are defined by y(x) = x - k.
  FurthestReaching fr_forward_;

  // Stores the x-value of the furthest reaching reverse path for each
  // l-diagonal. l-diagonals are numbered from '-width' to 'height' and centered
  // on 'bottom_right' of the edit graph area.
  // k-diagonals and l-diagonals represent the same diagonals. While we refer to
  // the diagonals as k-diagonals when calculating SES from (0,0), we refer to
  // the diagonals as l-diagonals when calculating SES from (M,N).
  // The corresponding k-diagonal name of an l-diagonal is: k = l + delta
  // where delta = width -height.
  FurthestReaching fr_reverse_;

  MyersDiffer(InspectorDiff::Input* input, InspectorDiff::Output* output)
      : input_(input),
        output_(output),
        fr_forward_(input->GetLength1() + input->GetLength2() + 1),
        fr_reverse_(input->GetLength1() + input->GetLength2() + 1) {
    // Length1 + Length2 + 1 is the upper bound for our work arrays.
    // We allocate the work arrays once and re-use them for all invocations of
    // `FindMiddleSnake`.
  }

  std::optional<Path> FindEditPath() {
    return FindEditPath(Point{0, 0},
                        Point{input_->GetLength1(), input_->GetLength2()});
  }

  // Returns the path of the SES between `from` and `to`.
  std::optional<Path> FindEditPath(Point from, Point to) {
    // Divide the area described by `from` and `to` by finding the
    // middle snake ...
    std::optional<Snake> snake = FindMiddleSnake(from, to);

    if (!snake) {
      return std::nullopt;
    }

    // ... and then conquer the two resulting sub-areas.
    std::optional<Path> head = FindEditPath(from, snake->from);
    std::optional<Path> tail = FindEditPath(snake->to, to);

    // Combine `head` and `tail` or use the snake start/end points for
    // zero-size areas.
    Path result;
    if (head) {
      result.Add(*head);
    } else {
      result.Add(snake->from);
    }

    if (tail) {
      result.Add(*tail);
    } else {
      result.Add(snake->to);
    }
    return result;
  }

  // Returns the snake in the middle of the area described by `from` and `to`.
  //
  // Incrementally calculates the D-paths (starting from 'from') and the
  // "reverse" D-paths (starting from 'to') until we find a "normal" and a
  // "reverse" path that overlap. That is we first calculate the normal
  // and reverse 0-path, then the normal and reverse 1-path and so on.
  //
  // If a step from a (d-1)-path to a d-path overlaps with a reverse path on
  // the same diagonal (or the other way around), then we consider that step
  // our middle snake and return it immediately.
  std::optional<Snake> FindMiddleSnake(Point from, Point to) {
    EditGraphArea area{from, to};
    if (area.size() == 0) {
      return std::nullopt;
    }

    // Initialise the furthest reaching vectors with an "artificial" edge
    // from (0, -1) -> (0, 0) and (N, -M) -> (N, M) to serve as the initial
    // snake when d = 0.
    fr_forward_[1] = area.top_left.x;
    fr_reverse_[-1] = area.bottom_right.x;

    for (int d = 0; d <= std::ceil(area.size() / 2.0f); ++d) {
      if (auto snake = ShortestEditForward(area, d)) {
        return snake;
      }
      if (auto snake = ShortestEditReverse(area, d)) {
        return snake;
      }
    }

    return std::nullopt;
  }

  // Greedily calculates the furthest reaching `d`-paths for each k-diagonal
  // where k is in [-d, d].  For each k-diagonal we look at the furthest
  // reaching `d-1`-path on the `k-1` and `k+1` depending on which is further
  // along the x-axis we either add an insertion from the `k+1`-diagonal or
  // a deletion from the `k-1`-diagonal. Then we follow all possible diagonal
  // moves and finally record the result as the furthest reaching path on the
  // k-diagonal.
  std::optional<Snake> ShortestEditForward(const EditGraphArea& area, int d) {
    Point from, to;
    // We alternate between looking at odd and even k-diagonals. That is
    // because when we extend a `d-path` by a single move we can at most move
    // one diagonal over. That is either move from `k-1` to `k` or from `k+1` to
    // `k`. That is if `d` is even (odd) then we require only the odd (even)
    // k-diagonals calculated in step `d-1`.
    for (int k = -d; k <= d; k += 2) {
      if (k == -d || (k != d && fr_forward_[k - 1] < fr_forward_[k + 1])) {
        // Move downwards, i.e. add an insertion, because either we are at the
        // edge and downwards is the only way we can move, or because the
        // `d-1`-path along the `k+1` diagonal reaches further on the x-axis
        // than the `d-1`-path along the `k-1` diagonal.
        from.x = to.x = fr_forward_[k + 1];
      } else {
        // Move right, i.e. add a deletion.
        from.x = fr_forward_[k - 1];
        to.x = from.x + 1;
      }

      // Calculate y via y = x - k. We need to adjust k though since the k=0
      // diagonal is centered on `area.top_left` and not (0, 0).
      to.y = area.top_left.y + (to.x - area.top_left.x) - k;
      from.y = (d == 0 || from.x != to.x) ? to.y : to.y - 1;

      // Extend the snake diagonally as long as we can.
      while (to < area.bottom_right && input_->Equals(to.x, to.y)) {
        ++to.x;
        ++to.y;
      }

      fr_forward_[k] = to.x;

      // Check whether there is a reverse path on this k-diagonal which we
      // are overlapping with. If yes, that is our snake.
      const bool odd = area.delta() % 2 != 0;
      const int l = k - area.delta();
      if (odd && l >= (-d + 1) && l <= d - 1 && to.x >= fr_reverse_[l]) {
        return Snake{from, to};
      }
    }
    return std::nullopt;
  }

  // Greedily calculates the furthest reaching reverse `d`-paths for each
  // l-diagonal where l is in [-d, d].
  // Works the same as `ShortestEditForward` but we move upwards and left
  // instead.
  std::optional<Snake> ShortestEditReverse(const EditGraphArea& area, int d) {
    Point from, to;
    // We alternate between looking at odd and even l-diagonals. That is
    // because when we extend a `d-path` by a single move we can at most move
    // one diagonal over. That is either move from `l-1` to `l` or from `l+1` to
    // `l`. That is if `d` is even (odd) then we require only the odd (even)
    // l-diagonals calculated in step `d-1`.
    for (int l = d; l >= -d; l -= 2) {
      if (l == d || (l != -d && fr_reverse_[l - 1] > fr_reverse_[l + 1])) {
        // Move upwards, i.e. add an insertion, because either we are at the
        // edge and upwards is the only way we can move, or because the
        // `d-1`-path along the `l-1` diagonal reaches further on the x-axis
        // than the `d-1`-path along the `l+1` diagonal.
        from.x = to.x = fr_reverse_[l - 1];
      } else {
        // Move left, i.e. add a deletion.
        from.x = fr_reverse_[l + 1];
        to.x = from.x - 1;
      }

      // Calculate y via y = x - k. We need to adjust k though since the k=0
      // diagonal is centered on `area.top_left` and not (0, 0).
      const int k = l + area.delta();
      to.y = area.top_left.y + (to.x - area.top_left.x) - k;
      from.y = (d == 0 || from.x != to.x) ? to.y : to.y + 1;

      // Extend the snake diagonally as long as we can.
      while (area.top_left < to && input_->Equals(to.x - 1, to.y - 1)) {
        --to.x;
        --to.y;
      }

      fr_reverse_[l] = to.x;

      // Check whether there is a path on this k-diagonal which we
      // are overlapping with. If yes, that is our snake.
      const bool even = area.delta() % 2 == 0;
      if (even && k >= -d && k <= d && to.x <= fr_forward_[k]) {
        // Invert the points so the snake goes left to right, top to bottom.
        return Snake{to, from};
      }
    }
    return std::nullopt;
  }

  // Small helper class that converts a "shortest edit script" path into a
  // source mapping. The result is a list of "chunks" where each "chunk"
  // describes a range in the input string and where it can now be found
  // in the output string.
  //
  // The list of chunks can be calculated in a simple pass over all the points
  // of the edit path:
  //
  //     - For any diagonal we close and report the current chunk if there is
  //       one open at the moment.
  //     - For an insertion or deletion we open a new chunk if none is ongoing.
  class ResultWriter {
   public:
    explicit ResultWriter(InspectorDiff::Output* output) : output_(output) {}

    void RecordNoModification(const Point& from) {
      output_->AddMatch(from.x, from.y);
    }

   private:
    InspectorDiff::Output* output_;
  };

  // Takes an edit path and "fills in the blanks". That is we notify the
  // `ResultWriter` after each single downwards, left or diagonal move.
  void WriteResult(const Path& path) {
    ResultWriter writer(output_);

    for (wtf_size_t i = 1; i < path.points.size(); ++i) {
      Point p1 = path.points[i - 1];
      Point p2 = path.points[i];

      p1 = WalkDiagonal(writer, p1, p2);
      const int cmp = (p2.x - p1.x) - (p2.y - p1.y);
      if (cmp == -1) {
        p1.y++;
      } else if (cmp == 1) {
        p1.x++;
      }

      p1 = WalkDiagonal(writer, p1, p2);
      DCHECK(p1.x == p2.x && p1.y == p2.y);
    }
  }

  Point WalkDiagonal(ResultWriter& writer, Point p1, Point p2) {
    while (p1.x < p2.x && p1.y < p2.y && input_->Equals(p1.x, p1.y)) {
      writer.RecordNoModification(p1);
      p1.x++;
      p1.y++;
    }
    return p1;
  }

 public:
  static void MyersDiff(InspectorDiff::Input* input,
                        InspectorDiff::Output* output) {
    MyersDiffer differ(input, output);
    auto result = differ.FindEditPath();
    if (!result) {
      return;  // Empty input doesn't produce a path.
    }

    differ.WriteResult(*result);
  }
};

class MappingInput : public InspectorDiff::Input {
 public:
  MappingInput(const Vector<String>& list_a,
               const Vector<String>& list_b,
               int start_offset,
               int end_offset)
      : list_a_(list_a),
        list_b_(list_b),
        start_offset_(start_offset),
        end_offset_(end_offset) {}

  int GetLength1() override {
    return list_a_.size() - start_offset_ - end_offset_;
  }
  int GetLength2() override {
    return list_b_.size() - start_offset_ - end_offset_;
  }
  bool Equals(int index1, int index2) override {
    return list_a_.at(index1 + start_offset_) ==
           list_b_.at(index2 + start_offset_);
  }

 private:
  const Vector<String>& list_a_;
  const Vector<String>& list_b_;
  int start_offset_;
  int end_offset_;
};

// AddChunk is called whenever a chunk is different in two lists.
// For example, for [1, 8, 2, 3] and [4, 2, 5] It is called with these chunks:
// * pos1 = 0, pos2 = 0; len1 = 2, len2 = 1
// meaning that starting from index 0 there are 2 elements different in list_a
// and starting from index 0 there is 1 element different in list_b
// * pos1 = 3, pos2 = 2; len1 = 1, len2 = 1
// meaning that starting from index 3, there is 1 element different in list_a
// and starting from index 2 there are 1 element different in list_b
// Using this property shows that the elements between two difference chunks
// are the same.
// For the example, initial difference chunk ends at 2nd index for list_a
// and starts at 3rd index in the next difference chunk. Meaning that, 2nd index
// does not belong to a difference chunk.
class MappingOutput : public InspectorDiff::Output {
 public:
  MappingOutput(int start_offset,
                InspectorIndexMap* a_to_b,
                InspectorIndexMap* b_to_a)
      : a_to_b_(a_to_b), b_to_a_(b_to_a), start_offset_(start_offset) {}

  void AddMatch(int pos1, int pos2) override {
    a_to_b_->Set(pos1 + start_offset_, pos2 + start_offset_);
    b_to_a_->Set(pos2 + start_offset_, pos1 + start_offset_);
  }

 private:
  InspectorIndexMap* a_to_b_;
  InspectorIndexMap* b_to_a_;
  int start_offset_;
};

}  // namespace

void InspectorDiff::CalculateMatches(InspectorDiff::Input* input,
                                     InspectorDiff::Output* result_writer) {
  MyersDiffer::MyersDiff(input, result_writer);
}

// Finds the longest common subsequence of list_a and list_b
// then creates a mapping from a_to_b and b_to_a that holds
// which element in list_a exists in the longest common subsequence
// and corresponds to which index in list_b.
void InspectorDiff::FindLCSMapping(const Vector<String>& list_a,
                                   const Vector<String>& list_b,
                                   InspectorIndexMap* a_to_b,
                                   InspectorIndexMap* b_to_a) {
  // Cut of common prefix.
  wtf_size_t start_offset = 0;
  while (start_offset < list_a.size() && start_offset < list_b.size()) {
    if (list_a.at(start_offset) != list_b.at(start_offset)) {
      break;
    }
    a_to_b->Set(start_offset, start_offset);
    b_to_a->Set(start_offset, start_offset);
    ++start_offset;
  }

  // Cut of common suffix.
  wtf_size_t end_offset = 0;
  while (end_offset < list_a.size() - start_offset &&
         end_offset < list_b.size() - start_offset) {
    wtf_size_t index_a = list_a.size() - end_offset - 1;
    wtf_size_t index_b = list_b.size() - end_offset - 1;
    if (list_a.at(index_a) != list_b.at(index_b)) {
      break;
    }
    a_to_b->Set(index_a, index_b);
    b_to_a->Set(index_b, index_a);
    ++end_offset;
  }

  wtf_size_t n = list_a.size() - start_offset - end_offset;
  wtf_size_t m = list_b.size() - start_offset - end_offset;

  // If we mapped either of arrays, we have no more work to do.
  if (n == 0 || m == 0) {
    return;
  }

  // Find the LCS between list_a and list_b starting from start offset and
  // ending at end_offset
  MappingInput input(list_a, list_b, start_offset, end_offset);
  MappingOutput output(start_offset, a_to_b, b_to_a);
  InspectorDiff::CalculateMatches(&input, &output);
}

}  // namespace blink

"""

```