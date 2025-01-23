Response:
The user wants a summary of the provided C++ code file. The file is a test suite for `PaintPropertyNode` in the Chromium Blink engine.

Here's a breakdown of the thinking process to generate the summary:

1. **Identify the core purpose:** The filename `paint_property_node_test.cc` clearly indicates this is a test file for the `PaintPropertyNode` class.

2. **Recognize the testing framework:** The code uses `testing::gtest::include::gtest/gtest.h`, confirming it's a Google Test suite.

3. **Understand the tested class:** The code includes `<third_party/blink/renderer/platform/graphics/paint/paint_property_node.h>`, meaning the tests focus on the functionality of `PaintPropertyNode` and its derived classes (`TransformPaintPropertyNode`, `ClipPaintPropertyNode`, `EffectPaintPropertyNode`).

4. **Analyze the test structure:** The `PaintPropertyNodeTest` class sets up a hierarchical tree of these property nodes (`root`, `ancestor`, `child1`, `child2`, `grandchild1`, `grandchild2`). This tree structure is central to understanding the tests.

5. **Identify common test patterns:**  Look for recurring patterns in the test cases. The `SetUp` method initializes the tree. The `ResetAllChanged` and `ExpectInitialState`/`ExpectUnchangedState` functions establish a baseline and verify states. Many tests involve calling `Update` on a node and then using `EXPECT_CHANGE_EQ` (or similar checks) to verify the changed status of various nodes in the tree.

6. **Infer the testing goals:** Based on the test names and the operations performed, deduce what aspects of `PaintPropertyNode` are being tested. This includes:
    * **Lowest Common Ancestor:**  The `LowestCommonAncestor` test directly checks this functionality.
    * **Change Tracking:**  The tests involving `Update` and `Changed` are verifying how changes to a node propagate through the tree and how different types of changes are detected.
    * **Different Node Types:** Tests are performed for `TransformPaintPropertyNode`, `ClipPaintPropertyNode`, and `EffectPaintPropertyNode`, indicating that type-specific behaviors are being tested.
    * **Animation and Compositing:** Tests involving `CompositingReason` and `AnimationState` show the interaction of property nodes with compositing and animations.

7. **Connect to web technologies (JavaScript, HTML, CSS):**  Consider how these paint property nodes relate to concepts in web development. Transformations, clipping, and effects are directly related to CSS properties. Changes to these properties can trigger repaints or trigger composited animations, which are performance optimizations handled by the browser.

8. **Identify potential errors:** Think about common mistakes developers might make when working with these types of systems. Incorrectly assuming a change has propagated, not understanding the different change types, or mishandling animation states are possibilities.

9. **Structure the summary:** Organize the findings into logical categories: core functionality, relationships to web technologies, logical reasoning (input/output examples), and potential errors.

10. **Refine the language:** Use clear and concise language, avoiding overly technical jargon where possible. Provide specific examples to illustrate the points.

By following these steps, the comprehensive summary provided previously can be generated. The key is to understand the underlying purpose of the code and how it relates to the broader context of a web browser engine.
```
文件功能归纳（第1部分）
```

这个C++源代码文件 `paint_property_node_test.cc` 是 Chromium Blink 渲染引擎中用于测试 `PaintPropertyNode` 及其子类（例如 `TransformPaintPropertyNode`, `ClipPaintPropertyNode`, `EffectPaintPropertyNode`）功能的单元测试文件。

**主要功能可以归纳为:**

1. **测试 `PaintPropertyNode` 及其子类的基本功能:**
   - **创建和管理属性节点树:** 代码创建了一个包含不同类型属性节点的树形结构，模拟了渲染对象属性的层级关系。
   - **检测属性节点的改变:**  测试用例验证了当属性节点的状态发生变化时，能够正确地检测到这些变化，并标记受影响的节点。
   - **判断变化的类型:** 测试用例区分了不同类型的变化，例如：
     - `kChangedOnlySimpleValues`:  只有简单的数值发生了变化。
     - `kChangedOnlyValues`:  值发生了变化。
     - `kChangedOnlyCompositedValues`:  只有与合成相关的值发生了变化。
     - `kChangedOnlyNonRerasterValues`:  只改变了非重绘的值。
     - `kNodeAddedOrRemoved`:  节点被添加或移除。
     - `kUnchanged`:  节点没有发生变化。
   - **查找最近公共祖先 (Lowest Common Ancestor):** 测试了 `LowestCommonAncestor` 方法，用于找到两个节点在树中的最近公共祖先。

2. **测试属性节点变化对子树的影响:**
   - 测试了当父节点或祖先节点的属性发生变化时，子节点是否能够正确地检测到这些变化。
   - 测试了不同节点之间的变化检测，例如，一个节点的改变如何影响另一个非祖先/子孙节点。

3. **测试特定类型属性节点的功能:**
   - **`TransformPaintPropertyNode`:**  测试了变换属性的变化，例如平移、旋转、缩放，以及变换原点的变化。还测试了在合成动画期间变换属性的变化。
   - **`ClipPaintPropertyNode`:** 测试了裁剪属性的变化，例如裁剪矩形和圆角矩形的变化。
   - **`EffectPaintPropertyNode`:** 测试了效果属性的变化，例如不透明度的变化，包括在合成动画期间和使用 `will-change` 属性时的变化。

**与 JavaScript, HTML, CSS 的功能关系:**

这些 `PaintPropertyNode` 类在浏览器渲染引擎中扮演着关键角色，它们直接对应于 CSS 属性，并影响着网页的布局和渲染。

* **`TransformPaintPropertyNode`:**  与 CSS 的 `transform` 属性直接相关。例如，CSS 中的 `transform: translateX(10px);` 会导致创建一个 `TransformPaintPropertyNode` 并设置相应的变换矩阵。
    * **举例:**
        * **HTML:** `<div style="transform: translateX(10px);">Hello</div>`
        * **CSS:** `.my-div { transform: rotate(45deg); }`
        * 这些 CSS 规则会导致浏览器创建或更新 `TransformPaintPropertyNode` 来表示这些变换。

* **`ClipPaintPropertyNode`:** 与 CSS 的 `clip-path` 和 `overflow: hidden` 等属性相关。`clip-path` 可以定义复杂的裁剪区域，而 `overflow: hidden` 会导致内容超出元素边界时被裁剪。
    * **举例:**
        * **HTML:** `<div style="clip-path: circle(50px);">Image</div>`
        * **CSS:** `.clipped { overflow: hidden; border-radius: 10px; }`
        * 这些 CSS 规则会影响 `ClipPaintPropertyNode` 的状态，定义了如何裁剪元素的内容。

* **`EffectPaintPropertyNode`:** 与 CSS 的 `opacity`, `filter` (部分)，以及 `will-change` 属性相关。`opacity` 控制元素的不透明度，而 `filter` 可以应用各种视觉效果。 `will-change` 属性可以提示浏览器哪些属性可能会发生变化，以便进行优化。
    * **举例:**
        * **HTML:** `<div style="opacity: 0.5;">半透明文本</div>`
        * **CSS:** `.fade-in { will-change: opacity; transition: opacity 1s; opacity: 0; } .fade-in.visible { opacity: 1; }` (JavaScript 可以添加 `visible` 类)
        * 当 `opacity` 属性改变或使用了 `will-change: opacity` 时，`EffectPaintPropertyNode` 会记录这些变化。

**逻辑推理的假设输入与输出 (部分例子):**

* **假设输入:** 修改 `transform.ancestor` 节点的变换矩阵。
* **输出:**
    * `transform.ancestor` 的 `NodeChanged()` 返回 `PaintPropertyChangeType::kChangedOnlySimpleValues` (或其他相关的变化类型)。
    * `transform.child1` 和 `transform.grandchild1` 的 `NodeChanged()` 返回 `PaintPropertyChangeType::kNodeAddedOrRemoved` 或 `kChangedOnlySimpleValues`，具体取决于测试用例的具体逻辑和变化类型。
    * `transform.child2` 和 `transform.grandchild2` 的 `NodeChanged()` 也可能返回相应的变化类型，因为它们也受到祖先节点变化的影响。

* **假设输入:** 修改 `effect.child1` 节点的不透明度。
* **输出:**
    * `effect.child1` 的 `NodeChanged()` 返回 `PaintPropertyChangeType::kChangedOnlyValues` 或 `kChangedOnlySimpleValues`。
    * `effect.grandchild1` 的 `NodeChanged()` 返回相应的变化类型。
    * `effect.ancestor`, `effect.child2`, `effect.grandchild2` 的 `NodeChanged()` 可能返回 `kUnchanged`，除非测试用例有特定的逻辑来触发它们的变化。

**涉及用户或编程常见的使用错误 (可能在测试中覆盖，但此处是推断):**

虽然这个测试文件主要关注引擎内部逻辑，但它可以间接帮助避免以下常见错误：

* **错误地假设 CSS 属性变化不会影响子元素:**  `PaintPropertyNode` 的测试确保了父节点的变化能够正确地通知到子节点，这反映了 CSS 属性的继承和层叠行为。如果开发者错误地认为修改父元素的 `transform` 不会影响其子元素的位置，那么浏览器的渲染结果可能会与预期不符。
* **不理解 `will-change` 的作用:** 测试用例涉及到 `will-change` 属性，帮助验证浏览器对于声明了 `will-change` 的属性的优化行为。开发者可能错误地使用 `will-change`，或者不理解其对性能的影响。
* **在动画过程中修改非合成属性导致性能问题:**  测试中包含了对合成动画期间属性变化的测试，这有助于确保浏览器能够有效地处理这些情况。开发者如果在动画过程中修改了会触发重绘的属性，可能会导致页面卡顿。

总而言之，`paint_property_node_test.cc` 是 Blink 渲染引擎中一个重要的测试文件，它验证了用于管理和跟踪渲染属性变化的 `PaintPropertyNode` 及其子类的正确性，这对于浏览器正确、高效地渲染网页至关重要，并间接地与 HTML、CSS 和 JavaScript 的功能息息相关。

### 提示词
```
这是目录为blink/renderer/platform/graphics/paint/paint_property_node_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/paint/paint_property_node.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/paint/property_tree_state.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"

namespace blink {

class PaintPropertyNodeTest : public testing::Test {
 protected:
  template <typename NodeType>
  struct Tree {
    Persistent<const NodeType> root;
    Persistent<NodeType> ancestor;
    Persistent<NodeType> child1;
    Persistent<NodeType> child2;
    Persistent<NodeType> grandchild1;
    Persistent<NodeType> grandchild2;
  };

  void SetUp() override {
    //          root
    //           |
    //        ancestor
    //         /   \
    //     child1   child2
    //       |        |
    // grandchild1 grandchild2

    transform.root = &TransformPaintPropertyNode::Root();
    transform.ancestor = Create2DTranslation(*transform.root, 0, 0);
    transform.child1 = Create2DTranslation(*transform.ancestor, 0, 0);
    transform.child2 = Create2DTranslation(*transform.ancestor, 0, 0);
    transform.grandchild1 = Create2DTranslation(*transform.child1, 0, 0);
    transform.grandchild2 = Create2DTranslation(*transform.child2, 0, 0);

    clip.root = &ClipPaintPropertyNode::Root();
    clip.ancestor =
        CreateClip(*clip.root, *transform.ancestor, FloatRoundedRect());
    clip.child1 =
        CreateClip(*clip.ancestor, *transform.child1, FloatRoundedRect());
    clip.child2 =
        CreateClip(*clip.ancestor, *transform.child2, FloatRoundedRect());
    clip.grandchild1 =
        CreateClip(*clip.child1, *transform.grandchild1, FloatRoundedRect());
    clip.grandchild2 =
        CreateClip(*clip.child2, *transform.grandchild2, FloatRoundedRect());

    effect.root = &EffectPaintPropertyNode::Root();
    effect.ancestor = CreateOpacityEffect(*effect.root, *transform.ancestor,
                                          clip.ancestor.Get(), 0.5);
    effect.child1 = CreateOpacityEffect(*effect.ancestor, *transform.child1,
                                        clip.child1.Get(), 0.5);
    effect.child2 = CreateOpacityEffect(*effect.ancestor, *transform.child2,
                                        clip.child2.Get(), 0.5);
    effect.grandchild1 = CreateOpacityEffect(
        *effect.child1, *transform.grandchild1, clip.grandchild1.Get(), 0.5);
    effect.grandchild2 = CreateOpacityEffect(
        *effect.child2, *transform.grandchild2, clip.grandchild2.Get(), 0.5);
  }

  template <typename NodeType>
  void ResetAllChanged(Tree<NodeType>& tree) {
    tree.grandchild1->ClearChangedToRoot(sequence_number);
    tree.grandchild2->ClearChangedToRoot(sequence_number);
  }

  void ResetAllChanged() {
    sequence_number++;
    ResetAllChanged(transform);
    ResetAllChanged(clip);
    ResetAllChanged(effect);
  }

  template <typename NodeType>
  void ExpectInitialState(const Tree<NodeType>& tree) {
    EXPECT_EQ(PaintPropertyChangeType::kUnchanged, tree.root->NodeChanged());
    EXPECT_EQ(PaintPropertyChangeType::kNodeAddedOrRemoved,
              tree.ancestor->NodeChanged());
    EXPECT_EQ(PaintPropertyChangeType::kNodeAddedOrRemoved,
              tree.child1->NodeChanged());
    EXPECT_EQ(PaintPropertyChangeType::kNodeAddedOrRemoved,
              tree.child2->NodeChanged());
    EXPECT_EQ(PaintPropertyChangeType::kNodeAddedOrRemoved,
              tree.grandchild1->NodeChanged());
    EXPECT_EQ(PaintPropertyChangeType::kNodeAddedOrRemoved,
              tree.grandchild2->NodeChanged());
  }

  template <typename NodeType>
  void ExpectUnchangedState(const Tree<NodeType>& tree) {
    EXPECT_EQ(PaintPropertyChangeType::kUnchanged, tree.root->NodeChanged());
    EXPECT_EQ(PaintPropertyChangeType::kUnchanged,
              tree.ancestor->NodeChanged());
    EXPECT_EQ(PaintPropertyChangeType::kUnchanged, tree.child1->NodeChanged());
    EXPECT_EQ(PaintPropertyChangeType::kUnchanged, tree.child2->NodeChanged());
    EXPECT_EQ(PaintPropertyChangeType::kUnchanged,
              tree.grandchild1->NodeChanged());
    EXPECT_EQ(PaintPropertyChangeType::kUnchanged,
              tree.grandchild2->NodeChanged());
  }

  void ExpectUnchangedState() {
    ExpectUnchangedState(transform);
    ExpectUnchangedState(clip);
    ExpectUnchangedState(effect);
  }

  template <typename NodeType>
  PaintPropertyChangeType NodeChanged(const NodeType& node) {
    return node.NodeChanged();
  }

  Tree<TransformPaintPropertyNode> transform;
  Tree<ClipPaintPropertyNode> clip;
  Tree<EffectPaintPropertyNode> effect;
  int sequence_number = 1;
};

#define STATE(node) PropertyTreeState(*transform.node, *clip.node, *effect.node)
#define EXPECT_CHANGE_EQ(expected_value, node, ...)                           \
  do {                                                                        \
    if (expected_value != PaintPropertyChangeType::kUnchanged) {              \
      for (int change_type = 0;                                               \
           change_type <= static_cast<int>(expected_value); ++change_type) {  \
        SCOPED_TRACE(testing::Message() << "change_type=" << change_type);    \
        EXPECT_TRUE(                                                          \
            node->Changed(static_cast<PaintPropertyChangeType>(change_type),  \
                          ##__VA_ARGS__));                                    \
      }                                                                       \
    }                                                                         \
    for (int change_type = static_cast<int>(expected_value) + 1;              \
         change_type <=                                                       \
         static_cast<int>(PaintPropertyChangeType::kNodeAddedOrRemoved);      \
         ++change_type) {                                                     \
      SCOPED_TRACE(testing::Message() << "change_type=" << change_type);      \
      EXPECT_FALSE(node->Changed(                                             \
          static_cast<PaintPropertyChangeType>(change_type), ##__VA_ARGS__)); \
    }                                                                         \
  } while (false)

TEST_F(PaintPropertyNodeTest, LowestCommonAncestor) {
  EXPECT_EQ(transform.ancestor,
            &transform.ancestor->LowestCommonAncestor(*transform.ancestor));
  EXPECT_EQ(transform.root,
            &transform.root->LowestCommonAncestor(*transform.root));

  EXPECT_EQ(transform.ancestor, &transform.grandchild1->LowestCommonAncestor(
                                    *transform.grandchild2));
  EXPECT_EQ(transform.ancestor,
            &transform.grandchild1->LowestCommonAncestor(*transform.child2));
  EXPECT_EQ(transform.root,
            &transform.grandchild1->LowestCommonAncestor(*transform.root));
  EXPECT_EQ(transform.child1,
            &transform.grandchild1->LowestCommonAncestor(*transform.child1));

  EXPECT_EQ(transform.ancestor, &transform.grandchild2->LowestCommonAncestor(
                                    *transform.grandchild1));
  EXPECT_EQ(transform.ancestor,
            &transform.grandchild2->LowestCommonAncestor(*transform.child1));
  EXPECT_EQ(transform.root,
            &transform.grandchild2->LowestCommonAncestor(*transform.root));
  EXPECT_EQ(transform.child2,
            &transform.grandchild2->LowestCommonAncestor(*transform.child2));

  EXPECT_EQ(transform.ancestor,
            &transform.child1->LowestCommonAncestor(*transform.child2));
  EXPECT_EQ(transform.ancestor,
            &transform.child2->LowestCommonAncestor(*transform.child1));
}

TEST_F(PaintPropertyNodeTest, InitialStateAndReset) {
  ExpectInitialState(transform);
  ResetAllChanged(transform);
  ExpectUnchangedState(transform);
}

TEST_F(PaintPropertyNodeTest, TransformChangeAncestor) {
  ResetAllChanged();
  ExpectUnchangedState();
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
            transform.ancestor->Update(*transform.root,
                                       TransformPaintPropertyNode::State{
                                           {MakeTranslationMatrix(1, 2)}}));

  // Test descendant->Changed(ancestor).
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.ancestor, *transform.root);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, transform.ancestor,
                   *transform.ancestor);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.child1, *transform.root);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, transform.child1,
                   *transform.ancestor);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.grandchild1, *transform.root);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, transform.grandchild1,
                   *transform.ancestor);

  // Test property->Changed(non-ancestor-property). Should combine the changed
  // flags of the two paths to the root.
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.grandchild1, *transform.child2);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.grandchild1, *transform.grandchild2);

  ResetAllChanged();
  ExpectUnchangedState();
}

TEST_F(PaintPropertyNodeTest, ClipChangeAncestor) {
  ResetAllChanged();
  ExpectUnchangedState();
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyValues,
            clip.ancestor->Update(
                *clip.root, ClipPaintPropertyNode::State(
                                *transform.ancestor, gfx::RectF(1, 2, 3, 4),
                                FloatRoundedRect(1, 2, 3, 4))));

  // Test descendant->Changed(ancestor).
  EXPECT_TRUE(clip.ancestor->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(root), nullptr));
  EXPECT_FALSE(clip.ancestor->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(ancestor), nullptr));
  EXPECT_TRUE(clip.child1->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                   STATE(root), nullptr));
  EXPECT_FALSE(clip.child1->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                    STATE(ancestor), nullptr));
  EXPECT_TRUE(clip.grandchild1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(root), nullptr));
  EXPECT_FALSE(clip.grandchild1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(ancestor), nullptr));

  // Test property->Changed(non-ancestor-property).
  // Simply walk to the root.
  EXPECT_TRUE(clip.grandchild1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(child2), nullptr));
  EXPECT_TRUE(
      clip.grandchild1->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                STATE(grandchild2), nullptr));

  ResetAllChanged();
  ExpectUnchangedState();
}

TEST_F(PaintPropertyNodeTest, EffectChangeAncestor) {
  ResetAllChanged();
  ExpectUnchangedState();
  EffectPaintPropertyNode::State state{transform.ancestor, clip.ancestor};
  state.compositor_element_id = effect.ancestor->GetCompositorElementId();

  // The initial test starts with opacity 0.5, and we're changing it to 0.9
  // here.
  state.opacity = 0.9;
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
            effect.ancestor->Update(*effect.root, std::move(state)));

  // Test descendant->Changed(ancestor).
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   effect.ancestor, STATE(root), nullptr);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, effect.ancestor,
                   STATE(ancestor), nullptr);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   effect.child1, STATE(root), nullptr);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, effect.child1,
                   STATE(ancestor), nullptr);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   effect.grandchild1, STATE(root), nullptr);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, effect.grandchild1,
                   STATE(ancestor), nullptr);
  // Test property->Changed(non-ancestor-property).
  // Simply walk to the root.
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   effect.grandchild1, STATE(child2), nullptr);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   effect.grandchild1, STATE(grandchild2), nullptr);

  ResetAllChanged();
  ExpectUnchangedState();
}

TEST_F(PaintPropertyNodeTest, ChangeOpacityDuringCompositedAnimation) {
  ResetAllChanged();
  ExpectUnchangedState();

  EffectPaintPropertyNode::State state{transform.child1, clip.child1};
  state.compositor_element_id = effect.child1->GetCompositorElementId();
  // The initial test starts with opacity 0.5, and we're changing it to 0.9
  // here.
  state.opacity = 0.9;

  EffectPaintPropertyNode::AnimationState animation_state;
  animation_state.is_running_opacity_animation_on_compositor = true;

  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyCompositedValues,
            effect.child1->Update(*effect.ancestor, std::move(state),
                                  animation_state));

  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlyCompositedValues,
                   effect.child1, STATE(root), nullptr);

  ResetAllChanged();
  ExpectUnchangedState();
}

TEST_F(PaintPropertyNodeTest, EffectOpacityChangesToOneAndFromOne) {
  ResetAllChanged();
  ExpectUnchangedState();

  {
    EffectPaintPropertyNode::State state{transform.ancestor, clip.ancestor};
    // The initial test starts with opacity 0.5, and we're changing it to 1
    // here.
    state.opacity = 1.f;
    EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyValues,
              effect.ancestor->Update(*effect.root, std::move(state)));
  }

  // Test descendant->Changed(ancestor).
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlyValues, effect.ancestor,
                   STATE(root), nullptr);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, effect.ancestor,
                   STATE(ancestor), nullptr);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlyValues, effect.child1,
                   STATE(root), nullptr);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, effect.child1,
                   STATE(ancestor), nullptr);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlyValues,
                   effect.grandchild1, STATE(root), nullptr);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, effect.grandchild1,
                   STATE(ancestor), nullptr);

  // Test property->Changed(non-ancestor-property).
  // Simply walk to the root.
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlyValues,
                   effect.grandchild1, STATE(child2), nullptr);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlyValues,
                   effect.grandchild1, STATE(grandchild2), nullptr);

  {
    EffectPaintPropertyNode::State state{transform.ancestor.Get(),
                                         clip.ancestor.Get()};
    state.opacity = 0.7f;
    EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyValues,
              effect.ancestor->Update(*effect.root, std::move(state)));
  }

  ResetAllChanged();
  ExpectUnchangedState();
}

TEST_F(PaintPropertyNodeTest, EffectWillChangeOpacityChangesToAndFromOne) {
  // TODO(crbug.com/1285498): Optimize for will-change: opacity.
  {
    EffectPaintPropertyNode::State state{transform.ancestor, clip.ancestor};
    state.opacity = 0.5f;  // Same as the initial opacity of |effect.ancestor|.
    state.direct_compositing_reasons = CompositingReason::kWillChangeOpacity;
    EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyNonRerasterValues,
              effect.ancestor->Update(*effect.root, std::move(state)));
  }
  {
    EffectPaintPropertyNode::State state{transform.ancestor,
                                         clip.ancestor.Get()};
    // Change only opacity to 1.
    state.opacity = 1.f;
    state.direct_compositing_reasons = CompositingReason::kWillChangeOpacity;
    EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyValues,
              effect.ancestor->Update(*effect.root, std::move(state)));
  }
  {
    EffectPaintPropertyNode::State state{transform.ancestor.Get(),
                                         clip.ancestor.Get()};
    state.direct_compositing_reasons = CompositingReason::kWillChangeOpacity;
    // Change only opacity to 0.7f.
    state.opacity = 0.7f;
    EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyValues,
              effect.ancestor->Update(*effect.root, std::move(state)));
  }
}

TEST_F(PaintPropertyNodeTest, EffectAnimatingOpacityChangesToAndFromOne) {
  {
    EffectPaintPropertyNode::State state{transform.ancestor.Get(),
                                         clip.ancestor.Get()};
    state.opacity = 0.5f;  // Same as the initial opacity of |effect.ancestor|.
    state.direct_compositing_reasons |=
        CompositingReason::kActiveOpacityAnimation;
    EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyNonRerasterValues,
              effect.ancestor->Update(*effect.root, std::move(state)));
  }
  {
    EffectPaintPropertyNode::State state1{transform.ancestor.Get(),
                                          clip.ancestor.Get()};
    state1.opacity = 1.f;
    state1.direct_compositing_reasons |=
        CompositingReason::kActiveOpacityAnimation;
    EXPECT_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
              effect.ancestor->Update(*effect.root, std::move(state1)));
  }
  {
    EffectPaintPropertyNode::State state2{transform.ancestor.Get(),
                                          clip.ancestor.Get()};
    state2.opacity = 0.7f;
    state2.direct_compositing_reasons |=
        CompositingReason::kActiveOpacityAnimation;
    EXPECT_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
              effect.ancestor->Update(*effect.root, std::move(state2)));
  }
}

TEST_F(PaintPropertyNodeTest, ChangeDirectCompositingReason) {
  ResetAllChanged();
  ExpectUnchangedState();
  {
    TransformPaintPropertyNode::State state;
    state.direct_compositing_reasons = CompositingReason::kWillChangeTransform;
    EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyValues,
              transform.child1->Update(*transform.ancestor, std::move(state)));
    EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlyValues,
                     transform.child1, *transform.root);
  }

  {
    TransformPaintPropertyNode::State state;
    state.direct_compositing_reasons =
        CompositingReason::kWillChangeTransform |
        CompositingReason::kBackfaceVisibilityHidden;
    EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyNonRerasterValues,
              transform.child1->Update(*transform.ancestor, std::move(state)));
    // The previous change is more significant.
    EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlyValues,
                     transform.child1, *transform.root);
  }

  ResetAllChanged();
  ExpectUnchangedState();
}

TEST_F(PaintPropertyNodeTest, ChangeTransformDuringCompositedAnimation) {
  ResetAllChanged();
  ExpectUnchangedState();
  TransformPaintPropertyNode::AnimationState animation_state;
  animation_state.is_running_animation_on_compositor = true;
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyCompositedValues,
            transform.child1->Update(
                *transform.ancestor,
                TransformPaintPropertyNode::State{{MakeScaleMatrix(2)}},
                animation_state));

  EXPECT_FALSE(transform.child1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, *transform.root));
  EXPECT_FALSE(transform.child1->Changed(
      PaintPropertyChangeType::kChangedOnlyNonRerasterValues, *transform.root));
  EXPECT_TRUE(transform.child1->Changed(
      PaintPropertyChangeType::kChangedOnlyCompositedValues, *transform.root));

  ResetAllChanged();
  ExpectUnchangedState();
}

TEST_F(PaintPropertyNodeTest, ChangeTransformOriginDuringCompositedAnimation) {
  ResetAllChanged();
  ExpectUnchangedState();
  TransformPaintPropertyNode::AnimationState animation_state;
  animation_state.is_running_animation_on_compositor = true;
  EXPECT_EQ(
      PaintPropertyChangeType::kChangedOnlySimpleValues,
      transform.child1->Update(*transform.ancestor,
                               TransformPaintPropertyNode::State{
                                   {gfx::Transform(), gfx::Point3F(1, 2, 3)}},
                               animation_state));

  EXPECT_TRUE(transform.child1->Changed(
      PaintPropertyChangeType::kChangedOnlySimpleValues, *transform.root));

  ResetAllChanged();
  ExpectUnchangedState();
}

TEST_F(PaintPropertyNodeTest,
       ChangeTransform2dAxisAlignmentAndOriginDuringCompositedAnimation) {
  ResetAllChanged();
  ExpectUnchangedState();
  TransformPaintPropertyNode::AnimationState animation_state;
  animation_state.is_running_animation_on_compositor = true;
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
            transform.child1->Update(
                *transform.ancestor,
                TransformPaintPropertyNode::State{
                    {MakeRotationMatrix(2), gfx::Point3F(1, 2, 3)}},
                animation_state));

  EXPECT_TRUE(transform.child1->Changed(
      PaintPropertyChangeType::kChangedOnlySimpleValues, *transform.root));

  ResetAllChanged();
  ExpectUnchangedState();
}

TEST_F(PaintPropertyNodeTest, StickyTranslationChange) {
  ResetAllChanged();
  ExpectUnchangedState();
  TransformPaintPropertyNode::State state;
  state.direct_compositing_reasons = CompositingReason::kStickyPosition;
  // The change affects RequiresCullRectExpansion().
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyValues,
            transform.child1->Update(*transform.ancestor, std::move(state)));

  // Change sticky translation.
  TransformPaintPropertyNode::State state1{{MakeTranslationMatrix(10, 20)}};
  state1.direct_compositing_reasons = CompositingReason::kStickyPosition;
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyCompositedValues,
            transform.child1->Update(*transform.ancestor, std::move(state1)));

  ResetAllChanged();
  ExpectUnchangedState();
}

TEST_F(PaintPropertyNodeTest, TransformChangeOneChild) {
  ResetAllChanged();
  ExpectUnchangedState();
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
            transform.child1->Update(*transform.ancestor,
                                     TransformPaintPropertyNode::State{
                                         {MakeTranslationMatrix(1, 2)}}));

  // Test descendant->Changed(ancestor).
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, transform.ancestor,
                   *transform.root);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, transform.ancestor,
                   *transform.ancestor);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.child1, *transform.root);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.child1, *transform.ancestor);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.grandchild1, *transform.ancestor);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, transform.grandchild1,
                   *transform.child1);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, transform.child2,
                   *transform.ancestor);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, transform.grandchild2,
                   *transform.ancestor);

  // Test property->Changed(non-ancestor-property). Need to combine the changed
  // flags of the two paths to the root.
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.child2, *transform.child1);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.child1, *transform.child2);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.child2, *transform.grandchild1);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.child1, *transform.grandchild2);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.grandchild1, *transform.child2);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.grandchild1, *transform.grandchild2);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.grandchild2, *transform.child1);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
                   transform.grandchild2, *transform.grandchild1);

  ResetAllChanged();
  ExpectUnchangedState();
}

TEST_F(PaintPropertyNodeTest, ClipChangeOneChild) {
  ResetAllChanged();
  ExpectUnchangedState();
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyValues,
            clip.child1->Update(*clip.root,
                                ClipPaintPropertyNode::State(
                                    *transform.ancestor, gfx::RectF(1, 2, 3, 4),
                                    FloatRoundedRect(1, 2, 3, 4))));

  // Test descendant->Changed(ancestor).
  EXPECT_FALSE(clip.ancestor->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(root), nullptr));
  EXPECT_FALSE(clip.ancestor->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(ancestor), nullptr));
  EXPECT_TRUE(clip.child1->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                   STATE(root), nullptr));
  EXPECT_TRUE(clip.child1->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                   STATE(ancestor), nullptr));
  EXPECT_TRUE(clip.grandchild1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(ancestor), nullptr));
  EXPECT_FALSE(clip.grandchild1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(child1), nullptr));
  EXPECT_FALSE(clip.child2->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                    STATE(ancestor), nullptr));
  EXPECT_FALSE(clip.grandchild2->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(ancestor), nullptr));

  // Test property->Changed(PaintPropertyChangeType::kChangedOnlyValues,
  // non-ancestor-property). Simply walk to the root, regardless of
  // relative_to_state's path.
  EXPECT_FALSE(clip.child2->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                    STATE(child1), nullptr));
  EXPECT_TRUE(clip.child1->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                   STATE(child2), nullptr));
  EXPECT_FALSE(clip.child2->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                    STATE(grandchild1), nullptr));
  EXPECT_TRUE(clip.child1->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                   STATE(grandchild2), nullptr));
  EXPECT_TRUE(clip.grandchild1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(child2), nullptr));
  EXPECT_TRUE(
      clip.grandchild1->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                STATE(grandchild2), nullptr));
  EXPECT_FALSE(clip.grandchild2->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(child1), nullptr));
  EXPECT_FALSE(
      clip.grandchild2->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                STATE(grandchild1), nullptr));

  ResetAllChanged();
  ExpectUnchangedState();
}

TEST_F(PaintPropertyNodeTest, EffectChangeOneChild) {
  ResetAllChanged();
  ExpectUnchangedState();
  EffectPaintPropertyNode::State state{transform.ancestor, clip.ancestor};
  state.opacity = 0.9;
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyValues,
            effect.child1->Update(*effect.root, std::move(state)));

  // Test descendant->Changed(PaintPropertyChangeType::kChangedOnlyValues,
  // ancestor).
  EXPECT_FALSE(effect.ancestor->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(root), nullptr));
  EXPECT_FALSE(effect.ancestor->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(ancestor), nullptr));
  EXPECT_TRUE(effect.child1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(root), nullptr));
  EXPECT_TRUE(effect.child1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(ancestor), nullptr));
  EXPECT_TRUE(effect.grandchild1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(ancestor), nullptr));
  EXPECT_FALSE(effect.grandchild1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(child1), nullptr));
  EXPECT_FALSE(effect.child2->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(ancestor), nullptr));
  EXPECT_FALSE(effect.grandchild2->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(ancestor), nullptr));

  // Test property->Changed(PaintPropertyChangeType::kChangedOnlyValues,
  // non-ancestor-property). Simply walk to the root, regardless of
  // relative_to_state's path.
  EXPECT_FALSE(effect.child2->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(child1), nullptr));
  EXPECT_TRUE(effect.child1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(child2), nullptr));
  EXPECT_FALSE(
      effect.child2->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                             STATE(grandchild1), nullptr));
  EXPECT_TRUE(
      effect.child1->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                             STATE(grandchild2), nullptr));
  EXPECT_TRUE(effect.grandchild1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(child2), nullptr));
  EXPECT_TRUE(
      effect.grandchild1->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                  STATE(grandchild2), nullptr));
  EXPECT_FALSE(effect.grandchild2->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, STATE(child1), nullptr));
  EXPECT_FALSE(
      effect.grandchild2->Changed(PaintPropertyChangeType::kChangedOnlyValues,
                                  STATE(grandchild1), nullptr));

  ResetAllChanged();
  ExpectUnchangedState();
}

TEST_F(PaintPropertyNodeTest, TransformReparent) {
  ResetAllChanged();
  ExpectUnchangedState();
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlyValues,
            transform.child1->Update(*transform.child2,
                                     TransformPaintPropertyNode::State{
                                         {MakeTranslationMatrix(1, 2)}}));
  EXPECT_FALSE(transform.ancestor->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, *transform.root));
  EXPECT_TRUE(transform.child1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, *transform.ancestor));
  EXPECT_TRUE(transform.child1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, *transform.child2));
  EXPECT_FALSE(transform.child2->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, *transform.ancestor));
  EXPECT_TRUE(transform.grandchild1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, *transform.ancestor));
  EXPECT_FALSE(transform.grandchild1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, *transform.child1));
  EXPECT_TRUE(transform.grandchild1->Changed(
      PaintPropertyChangeType::kChangedOnlyValues, *transform.child2));

  ResetAllChanged();
  ExpectUnchangedState();
}

TEST_F(PaintPropertyNodeTest, ClipLocalTransformSpaceChange) {
  ResetAllChanged();
  ExpectUnchangedState();
  EXPECT_EQ(PaintPropertyChangeType::kChangedOnlySimpleValues,
            transform.child1->Update(*transform.ancestor,
                                     TransformPaintPropertyNode::State{
                                         {MakeTranslationMatrix(1, 2)}}));

  // We check that we detect the change from the transform. However, right now
  // we report simple value change which may be a bit confusing. See
  // crbug.com/948695 for a task to fix this.
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, clip.ancestor,
                   STATE(root), nullptr);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kUnchanged, clip.ancestor,
                   STATE(ancestor), nullptr);
  EXPECT_CHANGE_EQ(PaintPropertyChangeType::kChangedOnlySimpleVal
```