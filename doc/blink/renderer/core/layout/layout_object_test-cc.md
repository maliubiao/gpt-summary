Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is a test file for `LayoutObject` in the Chromium Blink rendering engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Subject:** The file name `layout_object_test.cc` and the class `LayoutObjectTest` clearly indicate that this file contains tests for the `LayoutObject` class.

2. **Scan for Key Concepts:**  Look for recurring terms and test names that reveal the aspects of `LayoutObject` being tested. Keywords like "CommonAncestor", "Display", "ContainingBlock", "PaintingLayer", "PaintInvalidation", ":first-letter" are prominent.

3. **Group Related Tests:**  Organize the observations based on the functionalities being tested. For example, several tests relate to the `display` CSS property, others to how containing blocks are determined, and another group to painting and invalidation.

4. **Infer Functionality from Tests:**  Understand what each group of tests aims to verify. For instance, the "CommonAncestor" tests check the logic for finding the common ancestor of two layout objects. "Display" tests verify the creation of layout objects based on the `display` property.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Relate the tested functionalities to their corresponding roles in web development. `LayoutObject` is a core component of the rendering process, directly influenced by HTML structure and CSS styles.

6. **Look for Logic and Assumptions:** While the provided code is primarily tests, some tests implicitly demonstrate assumptions about how the layout engine works. For instance, the containing block tests verify the rules for establishing containing blocks based on CSS positioning.

7. **Identify Potential User/Programming Errors:**  Consider what mistakes developers might make that these tests implicitly safeguard against. For example, incorrect assumptions about containing block behavior or misunderstanding how `display: none` affects the layout tree.

8. **Address the "Part 1" Instruction:**  Focus on summarizing the functionalities evident in the provided code *only*. Avoid speculating about what might be in the subsequent parts.

9. **Structure the Summary:** Organize the findings into clear categories like "Core Functionality," "Relationship to Web Technologies," "Logic and Assumptions," and "Potential Errors." Use bullet points for readability.

10. **Refine and Clarify:** Ensure the language is precise and easy to understand, avoiding jargon where possible or explaining it briefly.

**(Self-Correction during the process):**

* Initially, I might focus too much on the individual test cases. The key is to abstract and find the underlying *functionality* being tested.
* I need to be careful not to interpret the test code as the actual implementation of `LayoutObject`. The tests verify the *behavior* of `LayoutObject`.
* While considering "logic," I should stick to the assumptions *demonstrated* by the tests rather than delving into the internal implementation details.
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/layout_object.h"

#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/svg/svg_g_element.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "ui/gfx/geometry/decomposed_transform.h"

namespace blink {

using testing::Return;
using testing::MatchesRegex;

class LayoutObjectTest : public RenderingTest {
 public:
  LayoutObjectTest()
      : RenderingTest(MakeGarbageCollected<EmptyLocalFrameClient>()) {}

 protected:
  template <bool should_have_wrapper>
  void ExpectAnonymousInlineWrapperFor(Node*);
};

class LayoutObjectTestWithCompositing : public LayoutObjectTest {
 public:
  LayoutObjectTestWithCompositing() = default;

 protected:
  void SetUp() override {
    EnableCompositing();
    LayoutObjectTest::SetUp();
  }
};

template <bool should_have_wrapper>
void LayoutObjectTest::ExpectAnonymousInlineWrapperFor(Node* node) {
  ASSERT_TRUE(node);
  EXPECT_TRUE(node->IsTextNode());
  LayoutObject* text_layout = node->GetLayoutObject();
  ASSERT_TRUE(text_layout);
  LayoutObject* text_parent = text_layout->Parent();
  ASSERT_TRUE(text_parent);
  if (should_have_wrapper) {
    EXPECT_TRUE(text_parent->IsAnonymous());
    EXPECT_TRUE(text_parent->IsInline());
  } else {
    EXPECT_FALSE(text_parent->IsAnonymous());
  }
}

TEST_F(LayoutObjectTest, CommonAncestor) {
  SetBodyInnerHTML(R"HTML(
    <div id="container">
      <div id="child1">
        <div id="child1_1"></div>
      </div>
      <div id="child2">
        <div id="child2_1">
          <div id="child2_1_1"></div>
        </div>
      </div>
    </div>
  )HTML");
  LayoutObject* container = GetLayoutObjectByElementId("container");
  LayoutObject* child1 = GetLayoutObjectByElementId("child1");
  LayoutObject* child1_1 = GetLayoutObjectByElementId("child1_1");
  LayoutObject* child2 = GetLayoutObjectByElementId("child2");
  LayoutObject* child2_1 = GetLayoutObjectByElementId("child2_1");
  LayoutObject* child2_1_1 = GetLayoutObjectByElementId("child2_1_1");

  EXPECT_EQ(container->CommonAncestor(*container), container);

  EXPECT_EQ(child1->CommonAncestor(*child2), container);
  EXPECT_EQ(child2->CommonAncestor(*child1), container);
  EXPECT_TRUE(child1->IsBeforeInPreOrder(*child2));
  EXPECT_FALSE(child2->IsBeforeInPreOrder(*child1));

  EXPECT_EQ(child1->CommonAncestor(*child1_1), child1);
  EXPECT_EQ(child1_1->CommonAncestor(*child1), child1);
  EXPECT_TRUE(child1->IsBeforeInPreOrder(*child1_1));
  EXPECT_FALSE(child1_1->IsBeforeInPreOrder(*child1));

  EXPECT_EQ(child1_1->CommonAncestor(*child2_1), container);
  EXPECT_EQ(child2_1->CommonAncestor(*child1_1), container);
  EXPECT_TRUE(child1_1->IsBeforeInPreOrder(*child2_1));
  EXPECT_FALSE(child2_1->IsBeforeInPreOrder(*child1_1));

  EXPECT_EQ(child1_1->CommonAncestor(*child2_1_1), container);
  EXPECT_EQ(child2_1_1->CommonAncestor(*child1_1), container);
  EXPECT_TRUE(child1_1->IsBeforeInPreOrder(*child2_1_1));
  EXPECT_FALSE(child2_1_1->IsBeforeInPreOrder(*child1_1));
}

TEST_F(LayoutObjectTest, LayoutDecoratedNameCalledWithPositionedObject) {
  SetBodyInnerHTML("<div id='div' style='position: fixed'>test</div>");
  Element* div = GetElementById("div");
  DCHECK(div);
  LayoutObject* obj = div->GetLayoutObject();
  DCHECK(obj);
  EXPECT_THAT(
      obj->DecoratedName().Ascii(),
      MatchesRegex("LayoutN?G?BlockFlow \\(positioned, children-inline\\)"));
}

// Some display checks.
TEST_F(LayoutObjectTest, DisplayNoneCreateObject) {
  SetBodyInnerHTML("<div style='display:none'></div>");
  EXPECT_EQ(nullptr, GetDocument().body()->firstChild()->GetLayoutObject());
}

TEST_F(LayoutObjectTest, DisplayBlockCreateObject) {
  SetBodyInnerHTML("<foo style='display:block'></foo>");
  LayoutObject* layout_object =
      GetDocument().body()->firstChild()->GetLayoutObject();
  EXPECT_NE(nullptr, layout_object);
  EXPECT_TRUE(layout_object->IsLayoutBlockFlow());
  EXPECT_FALSE(layout_object->IsInline());
}

TEST_F(LayoutObjectTest, DisplayInlineBlockCreateObject) {
  SetBodyInnerHTML("<foo style='display:inline-block'></foo>");
  LayoutObject* layout_object =
      GetDocument().body()->firstChild()->GetLayoutObject();
  EXPECT_NE(nullptr, layout_object);
  EXPECT_TRUE(layout_object->IsLayoutBlockFlow());
  EXPECT_TRUE(layout_object->IsInline());
}

TEST_F(LayoutObjectTest, BackdropFilterAsGroupingProperty) {
  SetBodyInnerHTML(R"HTML(
    <style> div { transform-style: preserve-3d; } </style>
    <div id=target1 style="backdrop-filter: blur(2px)"></div>
    <div id=target2 style="will-change: backdrop-filter"></div>
    <div id=target3 style="position: relative"></div>
  )HTML");
  EXPECT_TRUE(GetLayoutObjectByElementId("target1")
                  ->StyleRef()
                  .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target2")
                  ->StyleRef()
                  .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_FALSE(GetLayoutObjectByElementId("target1")->StyleRef().Preserves3D());
  EXPECT_FALSE(GetLayoutObjectByElementId("target2")->StyleRef().Preserves3D());

  EXPECT_FALSE(GetLayoutObjectByElementId("target3")
                   ->StyleRef()
                   .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target3")->StyleRef().Preserves3D());
}

TEST_F(LayoutObjectTest, BlendModeAsGroupingProperty) {
  SetBodyInnerHTML(R"HTML(
    <style> div { transform-style: preserve-3d; } </style>
    <div id=target1 style="mix-blend-mode: multiply"></div>
    <div id=target2 style="position: relative"></div>
  )HTML");
  EXPECT_TRUE(GetLayoutObjectByElementId("target1")
                  ->StyleRef()
                  .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_FALSE(GetLayoutObjectByElementId("target1")->StyleRef().Preserves3D());

  EXPECT_FALSE(GetLayoutObjectByElementId("target2")
                   ->StyleRef()
                   .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target2")->StyleRef().Preserves3D());
}

TEST_F(LayoutObjectTest, CSSClipAsGroupingProperty) {
  SetBodyInnerHTML(R"HTML(
    <style> div { transform-style: preserve-3d; } </style>
    <div id=target1 style="clip: rect(1px, 2px, 3px, 4px)"></div>
    <div id=target2 style="position: absolute; clip: rect(1px, 2px, 3px, 4px)">
    </div>
    <div id=target3 style="position: relative"></div>
  )HTML");
  EXPECT_FALSE(GetLayoutObjectByElementId("target1")
                   ->StyleRef()
                   .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target1")->StyleRef().Preserves3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target2")
                  ->StyleRef()
                  .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_FALSE(GetLayoutObjectByElementId("target2")->StyleRef().Preserves3D());

  EXPECT_FALSE(GetLayoutObjectByElementId("target3")
                   ->StyleRef()
                   .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target3")->StyleRef().Preserves3D());
}

TEST_F(LayoutObjectTest, ClipPathAsGroupingProperty) {
  SetBodyInnerHTML(R"HTML(
    <style> div { transform-style: preserve-3d; } </style>
    <div id=target1 style="clip-path: circle(40%)"></div>
    <div id=target2 style="position: relative"></div>
  )HTML");
  EXPECT_TRUE(GetLayoutObjectByElementId("target1")
                  ->StyleRef()
                  .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_FALSE(GetLayoutObjectByElementId("target1")->StyleRef().Preserves3D());

  EXPECT_FALSE(GetLayoutObjectByElementId("target2")
                   ->StyleRef()
                   .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target2")->StyleRef().Preserves3D());
}

TEST_F(LayoutObjectTest, IsolationAsGroupingProperty) {
  SetBodyInnerHTML(R"HTML(
    <style> div { transform-style: preserve-3d; } </style>
    <div id=target1 style="isolation: isolate"></div>
    <div id=target2 style="position: relative"></div>
  )HTML");
  EXPECT_TRUE(GetLayoutObjectByElementId("target1")
                  ->StyleRef()
                  .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_FALSE(GetLayoutObjectByElementId("target1")->StyleRef().Preserves3D());

  EXPECT_FALSE(GetLayoutObjectByElementId("target2")
                   ->StyleRef()
                   .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target2")->StyleRef().Preserves3D());
}

TEST_F(LayoutObjectTest, MaskAsGroupingProperty) {
  SetBodyInnerHTML(R"HTML(
    <style> div { transform-style: preserve-3d; } </style>
    <div id=target1 style="-webkit-mask:linear-gradient(black,transparent)">
    </div>
    <div id=target2 style="position: relative"></div>
  )HTML");
  EXPECT_TRUE(GetLayoutObjectByElementId("target1")
                  ->StyleRef()
                  .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_FALSE(GetLayoutObjectByElementId("target1")->StyleRef().Preserves3D());

  EXPECT_FALSE(GetLayoutObjectByElementId("target2")
                   ->StyleRef()
                   .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target2")->StyleRef().Preserves3D());
}

TEST_F(LayoutObjectTest, UseCountContainWithoutContentVisibility) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .cv { content-visibility: auto }
      .strict { contain: strict }
      .all { contain: size paint layout style }
    </style>
    <div id=target class=cv></div>
  )HTML");
  auto* target = GetElementById("target");

  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainAllWithoutContentVisibility));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainStrictWithoutContentVisibility));

  target->classList().Add(AtomicString("all"));
  UpdateAllLifecyclePhasesForTest();

  // With content-visibility, we don't count the features.
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainAllWithoutContentVisibility));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainStrictWithoutContentVisibility));

  target->classList().Remove(AtomicString("cv"));
  target->classList().Remove(AtomicString("all"));
  target->classList().Add(AtomicString("strict"));
  UpdateAllLifecyclePhasesForTest();

  // Strict should register, and all is counted.
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainAllWithoutContentVisibility));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainStrictWithoutContentVisibility));

  target->classList().Remove(AtomicString("strict"));
  target->classList().Add(AtomicString("all"));
  UpdateAllLifecyclePhasesForTest();

  // Everything should be counted now.
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainAllWithoutContentVisibility));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainStrictWithoutContentVisibility));
}

// Containing block test.
TEST_F(LayoutObjectTest, ContainingBlockLayoutViewShouldBeNull) {
  EXPECT_EQ(nullptr, GetLayoutView().ContainingBlock());
}

TEST_F(LayoutObjectTest, ContainingBlockBodyShouldBeDocumentElement) {
  EXPECT_EQ(GetDocument().body()->GetLayoutObject()->ContainingBlock(),
            GetDocument().documentElement()->GetLayoutObject());
}

TEST_F(LayoutObjectTest, ContainingBlockDocumentElementShouldBeLayoutView) {
  EXPECT_EQ(
      GetDocument().documentElement()->GetLayoutObject()->ContainingBlock(),
      GetLayoutView());
}

TEST_F(LayoutObjectTest, ContainingBlockStaticLayoutObjectShouldBeParent) {
  SetBodyInnerHTML("<foo style='position:static'></foo>");
  LayoutObject* body_layout_object = GetDocument().body()->GetLayoutObject();
  LayoutObject* layout_object = body_layout_object->SlowFirstChild();
  EXPECT_EQ(layout_object->ContainingBlock(), body_layout_object);
}

TEST_F(LayoutObjectTest,
       ContainingBlockAbsoluteLayoutObjectShouldBeLayoutView) {
  SetBodyInnerHTML("<foo style='position:absolute'></foo>");
  LayoutObject* layout_object =
      GetDocument().body()->GetLayoutObject()->SlowFirstChild();
  EXPECT_EQ(layout_object->ContainingBlock(), GetLayoutView());
}

TEST_F(
    LayoutObjectTest,
    ContainingBlockAbsoluteLayoutObjectShouldBeNonStaticallyPositionedBlockAncestor) {
  SetBodyInnerHTML(R"HTML(
    <div style='position:relative; left:20px'>
      <bar style='position:absolute; left:2px; top:10px'></bar>
    </div>
  )HTML");
  LayoutObject* containing_blocklayout_object =
      GetDocument().body()->GetLayoutObject()->SlowFirstChild();
  LayoutObject* layout_object = containing_blocklayout_object->SlowFirstChild();
  EXPECT_TRUE(
      containing_blocklayout_object->CanContainOutOfFlowPositionedElement(
          EPosition::kAbsolute));
  EXPECT_FALSE(
      containing_blocklayout_object->CanContainOutOfFlowPositionedElement(
          EPosition::kFixed));
  EXPECT_EQ(layout_object->Container(), containing_blocklayout_object);
  EXPECT_EQ(layout_object->ContainingBlock(), containing_blocklayout_object);
  EXPECT_EQ(layout_object->ContainingBlockForAbsolutePosition(),
            containing_blocklayout_object);
  EXPECT_EQ(layout_object->ContainingBlockForFixedPosition(), GetLayoutView());
  auto offset =
      layout_object->OffsetFromContainer(containing_blocklayout_object);
  EXPECT_EQ(PhysicalOffset(2, 10), offset);
}

TEST_F(LayoutObjectTest, ContainingBlockFixedPosUnderFlattened3D) {
  SetBodyInnerHTML(R"HTML(
    <div id=container style='transform-style: preserve-3d; opacity: 0.9'>
      <div id=target style='position:fixed'></div>
    </div>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  LayoutObject* container = GetLayoutObjectByElementId("container");
  EXPECT_EQ(container, target->Container());
}

TEST_F(LayoutObjectTest, ContainingBlockFixedLayoutObjectInTransformedDiv) {
  SetBodyInnerHTML(R"HTML(
    <div style='transform:translateX(0px)'>
      <bar style='position:fixed'></bar>
    </div>
  )HTML");
  LayoutObject* containing_blocklayout_object =
      GetDocument().body()->GetLayoutObject()->SlowFirstChild();
  LayoutObject* layout_object = containing_blocklayout_object->SlowFirstChild();
  EXPECT_TRUE(
      containing_blocklayout_object->CanContainOutOfFlowPositionedElement(
          EPosition::kAbsolute));
  EXPECT_TRUE(
      containing_blocklayout_object->CanContainOutOfFlowPositionedElement(
          EPosition::kFixed));
  EXPECT_EQ(layout_object->Container(), containing_blocklayout_object);
  EXPECT_EQ(layout_object->ContainingBlock(), containing_blocklayout_object);
  EXPECT_EQ(layout_object->ContainingBlockForAbsolutePosition(),
            containing_blocklayout_object);
  EXPECT_EQ(layout_object->ContainingBlockForFixedPosition(),
            containing_blocklayout_object);
}

TEST_F(LayoutObjectTest, ContainingBlockFixedLayoutObjectInBody) {
  SetBodyInnerHTML("<div style='position:fixed'></div>");
  LayoutObject* layout_object =
      GetDocument().body()->GetLayoutObject()->SlowFirstChild();
  EXPECT_TRUE(layout_object->CanContainOutOfFlowPositionedElement(
      EPosition::kAbsolute));
  EXPECT_FALSE(
      layout_object->CanContainOutOfFlowPositionedElement(EPosition::kFixed));
  EXPECT_EQ(layout_object->Container(), GetLayoutView());
  EXPECT_EQ(layout_object->ContainingBlock(), GetLayoutView());
  EXPECT_EQ(layout_object->ContainingBlockForAbsolutePosition(),
            GetLayoutView());
  EXPECT_EQ(layout_object->ContainingBlockForFixedPosition(), GetLayoutView());
}

TEST_F(LayoutObjectTest, ContainingBlockAbsoluteLayoutObjectInBody) {
  SetBodyInnerHTML("<div style='position:absolute'></div>");
  LayoutObject* layout_object =
      GetDocument().body()->GetLayoutObject()->SlowFirstChild();
  EXPECT_TRUE(layout_object->CanContainOutOfFlowPositionedElement(
      EPosition::kAbsolute));
  EXPECT_FALSE(
      layout_object->CanContainOutOfFlowPositionedElement(EPosition::kFixed));
  EXPECT_EQ(layout_object->Container(), GetLayoutView());
  EXPECT_EQ(layout_object->ContainingBlock(), GetLayoutView());
  EXPECT_EQ(layout_object->ContainingBlockForAbsolutePosition(),
            GetLayoutView());
  EXPECT_EQ(layout_object->ContainingBlockForFixedPosition(), GetLayoutView());
}

TEST_F(
    LayoutObjectTest,
    ContainingBlockAbsoluteLayoutObjectShouldNotBeNonStaticallyPositionedInlineAncestor) {
  // Test note: We can't use a raw string literal here, since extra whitespace
  // causes failures.
  SetBodyInnerHTML(
      "<span style='position:relative; top:1px; left:2px'><bar "
      "style='position:absolute; top:10px; left:20px;'></bar></span>");
  LayoutObject* body_layout_object = GetDocument().body()->GetLayoutObject();
  LayoutObject* span_layout_object = body_layout_object->SlowFirstChild();
  LayoutObject* layout_object = span_layout_object->SlowFirstChild();

  EXPECT_TRUE(span_layout_object->CanContainOutOfFlowPositionedElement(
      EPosition::kAbsolute));
  EXPECT_FALSE(span_layout_object->CanContainOutOfFlowPositionedElement(
      EPosition::kFixed));

  auto offset = layout_object->OffsetFromContainer(span_layout_object);
  EXPECT_EQ(PhysicalOffset(22, 11), offset);

  // Sanity check: Make sure we don't generate anonymous objects.
  EXPECT_EQ(nullptr, body_layout_object->SlowFirstChild()->NextSibling());
  EXPECT_EQ(nullptr, layout_object->SlowFirstChild());
  EXPECT_EQ(nullptr, layout_object->NextSibling());

  EXPECT_EQ(layout_object->Container(), span_layout_object);
  EXPECT_EQ(layout_object->ContainingBlock(), body_layout_object);
  EXPECT_EQ(layout_object->ContainingBlockForAbsolutePosition(),
            body_layout_object);
  EXPECT_EQ(layout_object->ContainingBlockForFixedPosition(), GetLayoutView());
}

TEST_F(LayoutObjectTest, PaintingLayerOfOverflowClipLayerUnderColumnSpanAll) {
  SetBodyInnerHTML(R"HTML(
    <div id='columns' style='position: relative; columns: 3'>
      <div style='column-span: all'>
        <div id='overflow-clip-layer' style='height: 100px; overflow:
    hidden'></div>
      </div>
    </div>
  )HTML");

  LayoutObject* overflow_clip_object =
      GetLayoutObjectByElementId("overflow-clip-layer");
  LayoutBlock* columns = To<LayoutBlock>(GetLayoutObjectByElementId("columns"));
  EXPECT_EQ(columns->Layer(), overflow_clip_object->PaintingLayer());
}

TEST_F(LayoutObjectTest, FloatUnderBlock) {
  SetBodyInnerHTML(R"HTML(
    <div id='layered-div' style='position: absolute'>
      <div id='container'>
        <div id='floating' style='float: left'>FLOAT</div>
      </div>
    </div>
  )HTML");

  auto* layered_div =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("layered-div"));
  auto* container =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("container"));
  LayoutObject* floating = GetLayoutObjectByElementId("floating");

  EXPECT_EQ(layered_div->Layer(), layered_div->PaintingLayer());
  EXPECT_EQ(layered_div->Layer(), floating->PaintingLayer());
  EXPECT_EQ(container, floating->Container());
  EXPECT_EQ(container, floating->ContainingBlock());
}

TEST_F(LayoutObjectTest, InlineFloatMismatch) {
  SetBodyInnerHTML(R"HTML(
    <span id=span style='position: relative; left: 40px; width: 100px; height: 100px'>
      <div id=float_obj style='float: left; margin-left: 10px;'>
      </div>
    </span>
  )HTML");

  LayoutObject* float_obj = GetLayoutObjectByElementId("float_obj");
  LayoutObject* span = GetLayoutObjectByElementId("span");
  // 10px for margin + 40px for inset.
  EXPECT_EQ(PhysicalOffset(50, 0), float_obj->OffsetFromAncestor(span));
}

TEST_F(LayoutObjectTest, FloatUnderInline) {
  SetBodyInnerHTML(R"HTML(
    <div id='layered-div' style='position: absolute'>
      <div id='container'>
        <span id='layered-span' style='position: relative'>
          <div id='floating' style='float: left'>FLOAT</div>
        </span>
      </div>
    </div>
  )HTML");

  auto* layered_div =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("layered-div"));
  auto* container =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("container"));
  auto* layered_span =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("layered-span"));
  LayoutObject* floating = GetLayoutObjectByElementId("floating");

  EXPECT_EQ(layered_div->Layer(), layered_div->PaintingLayer());
  EXPECT_EQ(layered_span->Layer(), layered_span->PaintingLayer());
  // Inline-level floats are children of their inline-level containers. As such
  // LayoutNG paints these within the correct inline-level layer.
  EXPECT_EQ(layered_span->Layer(), floating->PaintingLayer());
  EXPECT_EQ(layered_span, floating->Container());
  EXPECT_EQ(container, floating->ContainingBlock());

  LayoutObject::AncestorSkipInfo skip_info(layered_span);
  EXPECT_EQ(layered_span, floating->Container(&skip_info));
  EXPECT_FALSE(skip_info.AncestorSkipped());
}

TEST_F(LayoutObjectTest, MutableForPaintingClearPaintFlags) {
  LayoutObject* object = GetDocument().body()->GetLayoutObject();
  object->SetShouldDoFullPaintInvalidation();
  EXPECT_true(object->ShouldDoFullPaintInvalidation());
  EXPECT_true(object->ShouldCheckLayoutForPaintInvalidation());
  object->SetShouldCheckForPaintInvalidation();
  EXPECT_true(object->ShouldCheckForPaintInvalidation());
  object->SetSubtreeShouldCheckForPaintInvalidation();
  EXPECT_true(object->SubtreeShouldCheckForPaintInvalidation());
  object->SetMayNeedPaintInvalidationAnimatedBackgroundImage();
  EXPECT_true(object->MayNeedPaintInvalidationAnimatedBackgroundImage());
  object->SetShouldInvalidateSelection();
  EXPECT_true(object->ShouldInvalidateSelection());
  object->SetBackgroundNeedsFullPaintInvalidation();
  EXPECT_true(object->BackgroundNeedsFullPaintInvalidation());
  object->SetNeedsPaintPropertyUpdate();
  EXPECT_true(object->NeedsPaintPropertyUpdate());
  EXPECT_true(object->Parent()->DescendantNeedsPaintPropertyUpdate());
  object->bitfields_.SetDescendantNeedsPaintPropertyUpdate(true);
  EXPECT_true(object->DescendantNeedsPaintPropertyUpdate());

  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInPrePaint);
  object->GetMutableForPainting().ClearPaintFlags();

  EXPECT_false(object->ShouldDoFullPaintInvalidation());
  EXPECT_false(object->ShouldCheckForPaintInvalidation());
  EXPECT_false(object->SubtreeShouldCheckForPaintInvalidation());
  EXPECT_false(object->MayNeedPaintInvalidationAnimatedBackgroundImage());
  EXPECT_false(object->ShouldInvalidateSelection());
  EXPECT_false(object->BackgroundNeedsFullPaintInvalidation());
  EXPECT_false(object->NeedsPaintPropertyUpdate());
  EXPECT_false(object->DescendantNeedsPaintPropertyUpdate());
}

TEST_F(LayoutObjectTest, DelayFullPaintInvalidation) {
  LayoutObject* object = GetDocument().body()->GetLayoutObject();
  object->SetShouldDoFullPaintInvalidation();
  object->SetShouldDelayFullPaintInvalidation();
  EXPECT_false(object->ShouldDoFullPaintInvalidation());
  EXPECT_true(object->ShouldDelayFullPaintInvalidation());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_false(object->ShouldDoFullPaintInvalidation());
  // ShouldDelayFullPaintInvalidation is not preserved.
  EXPECT_true(object->ShouldDelayFullPaintInvalidation());

  object->SetShouldDoFullPaintInvalidation();
  EXPECT_true(object->ShouldDoFullPaintInvalidation());
  // ShouldDelayFullPaintInvalidation is reset by
  // SetShouldDoFullPaintInvalidation().
  EXPECT_false(object->ShouldDelayFullPaintInvalidation());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_false(object->ShouldDoFullPaintInvalidation());
  EXPECT_false(object->ShouldDelayFullPaintInvalidation());
}

TEST_F(LayoutObjectTest, SubtreeAndDelayFullPaintInvalidation) {
  LayoutObject* object = GetDocument().body()->GetLayoutObject();
  object->SetShouldDoFullPaintInvalidation();
  object->SetShouldDelayFullPaintInvalidation();
  object->SetSubtreeShouldDoFullPaintInvalidation();
  EXPECT_true(object->SubtreeShouldDoFullPaintInvalidation());
  EXPECT_true(object->ShouldDoFullPaintInvalidation());
  EXPECT_false(object->ShouldDelayFullPaintInvalidation());

  object->SetShouldDelayFullPaintInvalidation();
  EXPECT_true(object->SubtreeShouldDoFullPaintInvalidation());
  EXPECT_true(object->ShouldDoFullPaintInvalidation());
  EXPECT_false(object->ShouldDelayFullPaintInvalidation());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_false(object->SubtreeShouldDoFullPaintInvalidation());
  EXPECT_false(object->ShouldDoFullPaintInvalidation());
  EXPECT_false(object->ShouldDelayFullPaintInvalidation());
}

TEST_F(LayoutObjectTest, SubtreePaintPropertyUpdateReasons) {
  LayoutObject* object = GetDocument().body()->GetLayoutObject();
  // Just pick a random reason.
  object->AddSubtreePaintPropertyUpdateReason(
      SubtreePaintPropertyUpdateReason::kPreviouslySkipped);
  EXPECT_true(object->SubtreePaintPropertyUpdateReasons());
  EXPECT_true(object->NeedsPaintPropertyUpdate());
  EXPECT_true(object->Parent()->DescendantNeedsPaintPropertyUpdate());

  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInPrePaint);
  object->GetMutableForPainting().ClearPaintFlags();

  EXPECT_false(object->SubtreePaintPropertyUpdateReasons());
  EXPECT_false(object->NeedsPaintPropertyUpdate());
}

TEST_F(LayoutObjectTest, ShouldCheckLayoutForPaintInvalidation)
### 提示词
```
这是目录为blink/renderer/core/layout/layout_object_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/layout_object.h"

#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/svg/svg_g_element.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "ui/gfx/geometry/decomposed_transform.h"

namespace blink {

using testing::Return;
using testing::MatchesRegex;

class LayoutObjectTest : public RenderingTest {
 public:
  LayoutObjectTest()
      : RenderingTest(MakeGarbageCollected<EmptyLocalFrameClient>()) {}

 protected:
  template <bool should_have_wrapper>
  void ExpectAnonymousInlineWrapperFor(Node*);
};

class LayoutObjectTestWithCompositing : public LayoutObjectTest {
 public:
  LayoutObjectTestWithCompositing() = default;

 protected:
  void SetUp() override {
    EnableCompositing();
    LayoutObjectTest::SetUp();
  }
};

template <bool should_have_wrapper>
void LayoutObjectTest::ExpectAnonymousInlineWrapperFor(Node* node) {
  ASSERT_TRUE(node);
  EXPECT_TRUE(node->IsTextNode());
  LayoutObject* text_layout = node->GetLayoutObject();
  ASSERT_TRUE(text_layout);
  LayoutObject* text_parent = text_layout->Parent();
  ASSERT_TRUE(text_parent);
  if (should_have_wrapper) {
    EXPECT_TRUE(text_parent->IsAnonymous());
    EXPECT_TRUE(text_parent->IsInline());
  } else {
    EXPECT_FALSE(text_parent->IsAnonymous());
  }
}

TEST_F(LayoutObjectTest, CommonAncestor) {
  SetBodyInnerHTML(R"HTML(
    <div id="container">
      <div id="child1">
        <div id="child1_1"></div>
      </div>
      <div id="child2">
        <div id="child2_1">
          <div id="child2_1_1"></div>
        </div>
      </div>
    </div>
  )HTML");
  LayoutObject* container = GetLayoutObjectByElementId("container");
  LayoutObject* child1 = GetLayoutObjectByElementId("child1");
  LayoutObject* child1_1 = GetLayoutObjectByElementId("child1_1");
  LayoutObject* child2 = GetLayoutObjectByElementId("child2");
  LayoutObject* child2_1 = GetLayoutObjectByElementId("child2_1");
  LayoutObject* child2_1_1 = GetLayoutObjectByElementId("child2_1_1");

  EXPECT_EQ(container->CommonAncestor(*container), container);

  EXPECT_EQ(child1->CommonAncestor(*child2), container);
  EXPECT_EQ(child2->CommonAncestor(*child1), container);
  EXPECT_TRUE(child1->IsBeforeInPreOrder(*child2));
  EXPECT_FALSE(child2->IsBeforeInPreOrder(*child1));

  EXPECT_EQ(child1->CommonAncestor(*child1_1), child1);
  EXPECT_EQ(child1_1->CommonAncestor(*child1), child1);
  EXPECT_TRUE(child1->IsBeforeInPreOrder(*child1_1));
  EXPECT_FALSE(child1_1->IsBeforeInPreOrder(*child1));

  EXPECT_EQ(child1_1->CommonAncestor(*child2_1), container);
  EXPECT_EQ(child2_1->CommonAncestor(*child1_1), container);
  EXPECT_TRUE(child1_1->IsBeforeInPreOrder(*child2_1));
  EXPECT_FALSE(child2_1->IsBeforeInPreOrder(*child1_1));

  EXPECT_EQ(child1_1->CommonAncestor(*child2_1_1), container);
  EXPECT_EQ(child2_1_1->CommonAncestor(*child1_1), container);
  EXPECT_TRUE(child1_1->IsBeforeInPreOrder(*child2_1_1));
  EXPECT_FALSE(child2_1_1->IsBeforeInPreOrder(*child1_1));
}

TEST_F(LayoutObjectTest, LayoutDecoratedNameCalledWithPositionedObject) {
  SetBodyInnerHTML("<div id='div' style='position: fixed'>test</div>");
  Element* div = GetElementById("div");
  DCHECK(div);
  LayoutObject* obj = div->GetLayoutObject();
  DCHECK(obj);
  EXPECT_THAT(
      obj->DecoratedName().Ascii(),
      MatchesRegex("LayoutN?G?BlockFlow \\(positioned, children-inline\\)"));
}

// Some display checks.
TEST_F(LayoutObjectTest, DisplayNoneCreateObject) {
  SetBodyInnerHTML("<div style='display:none'></div>");
  EXPECT_EQ(nullptr, GetDocument().body()->firstChild()->GetLayoutObject());
}

TEST_F(LayoutObjectTest, DisplayBlockCreateObject) {
  SetBodyInnerHTML("<foo style='display:block'></foo>");
  LayoutObject* layout_object =
      GetDocument().body()->firstChild()->GetLayoutObject();
  EXPECT_NE(nullptr, layout_object);
  EXPECT_TRUE(layout_object->IsLayoutBlockFlow());
  EXPECT_FALSE(layout_object->IsInline());
}

TEST_F(LayoutObjectTest, DisplayInlineBlockCreateObject) {
  SetBodyInnerHTML("<foo style='display:inline-block'></foo>");
  LayoutObject* layout_object =
      GetDocument().body()->firstChild()->GetLayoutObject();
  EXPECT_NE(nullptr, layout_object);
  EXPECT_TRUE(layout_object->IsLayoutBlockFlow());
  EXPECT_TRUE(layout_object->IsInline());
}

TEST_F(LayoutObjectTest, BackdropFilterAsGroupingProperty) {
  SetBodyInnerHTML(R"HTML(
    <style> div { transform-style: preserve-3d; } </style>
    <div id=target1 style="backdrop-filter: blur(2px)"></div>
    <div id=target2 style="will-change: backdrop-filter"></div>
    <div id=target3 style="position: relative"></div>
  )HTML");
  EXPECT_TRUE(GetLayoutObjectByElementId("target1")
                  ->StyleRef()
                  .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target2")
                  ->StyleRef()
                  .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_FALSE(GetLayoutObjectByElementId("target1")->StyleRef().Preserves3D());
  EXPECT_FALSE(GetLayoutObjectByElementId("target2")->StyleRef().Preserves3D());

  EXPECT_FALSE(GetLayoutObjectByElementId("target3")
                   ->StyleRef()
                   .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target3")->StyleRef().Preserves3D());
}

TEST_F(LayoutObjectTest, BlendModeAsGroupingProperty) {
  SetBodyInnerHTML(R"HTML(
    <style> div { transform-style: preserve-3d; } </style>
    <div id=target1 style="mix-blend-mode: multiply"></div>
    <div id=target2 style="position: relative"></div>
  )HTML");
  EXPECT_TRUE(GetLayoutObjectByElementId("target1")
                  ->StyleRef()
                  .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_FALSE(GetLayoutObjectByElementId("target1")->StyleRef().Preserves3D());

  EXPECT_FALSE(GetLayoutObjectByElementId("target2")
                   ->StyleRef()
                   .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target2")->StyleRef().Preserves3D());
}

TEST_F(LayoutObjectTest, CSSClipAsGroupingProperty) {
  SetBodyInnerHTML(R"HTML(
    <style> div { transform-style: preserve-3d; } </style>
    <div id=target1 style="clip: rect(1px, 2px, 3px, 4px)"></div>
    <div id=target2 style="position: absolute; clip: rect(1px, 2px, 3px, 4px)">
    </div>
    <div id=target3 style="position: relative"></div>
  )HTML");
  EXPECT_FALSE(GetLayoutObjectByElementId("target1")
                   ->StyleRef()
                   .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target1")->StyleRef().Preserves3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target2")
                  ->StyleRef()
                  .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_FALSE(GetLayoutObjectByElementId("target2")->StyleRef().Preserves3D());

  EXPECT_FALSE(GetLayoutObjectByElementId("target3")
                   ->StyleRef()
                   .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target3")->StyleRef().Preserves3D());
}

TEST_F(LayoutObjectTest, ClipPathAsGroupingProperty) {
  SetBodyInnerHTML(R"HTML(
    <style> div { transform-style: preserve-3d; } </style>
    <div id=target1 style="clip-path: circle(40%)"></div>
    <div id=target2 style="position: relative"></div>
  )HTML");
  EXPECT_TRUE(GetLayoutObjectByElementId("target1")
                  ->StyleRef()
                  .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_FALSE(GetLayoutObjectByElementId("target1")->StyleRef().Preserves3D());

  EXPECT_FALSE(GetLayoutObjectByElementId("target2")
                   ->StyleRef()
                   .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target2")->StyleRef().Preserves3D());
}

TEST_F(LayoutObjectTest, IsolationAsGroupingProperty) {
  SetBodyInnerHTML(R"HTML(
    <style> div { transform-style: preserve-3d; } </style>
    <div id=target1 style="isolation: isolate"></div>
    <div id=target2 style="position: relative"></div>
  )HTML");
  EXPECT_TRUE(GetLayoutObjectByElementId("target1")
                  ->StyleRef()
                  .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_FALSE(GetLayoutObjectByElementId("target1")->StyleRef().Preserves3D());

  EXPECT_FALSE(GetLayoutObjectByElementId("target2")
                   ->StyleRef()
                   .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target2")->StyleRef().Preserves3D());
}

TEST_F(LayoutObjectTest, MaskAsGroupingProperty) {
  SetBodyInnerHTML(R"HTML(
    <style> div { transform-style: preserve-3d; } </style>
    <div id=target1 style="-webkit-mask:linear-gradient(black,transparent)">
    </div>
    <div id=target2 style="position: relative"></div>
  )HTML");
  EXPECT_TRUE(GetLayoutObjectByElementId("target1")
                  ->StyleRef()
                  .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_FALSE(GetLayoutObjectByElementId("target1")->StyleRef().Preserves3D());

  EXPECT_FALSE(GetLayoutObjectByElementId("target2")
                   ->StyleRef()
                   .HasGroupingPropertyForUsedTransformStyle3D());
  EXPECT_TRUE(GetLayoutObjectByElementId("target2")->StyleRef().Preserves3D());
}

TEST_F(LayoutObjectTest, UseCountContainWithoutContentVisibility) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .cv { content-visibility: auto }
      .strict { contain: strict }
      .all { contain: size paint layout style }
    </style>
    <div id=target class=cv></div>
  )HTML");
  auto* target = GetElementById("target");

  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainAllWithoutContentVisibility));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainStrictWithoutContentVisibility));

  target->classList().Add(AtomicString("all"));
  UpdateAllLifecyclePhasesForTest();

  // With content-visibility, we don't count the features.
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainAllWithoutContentVisibility));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainStrictWithoutContentVisibility));

  target->classList().Remove(AtomicString("cv"));
  target->classList().Remove(AtomicString("all"));
  target->classList().Add(AtomicString("strict"));
  UpdateAllLifecyclePhasesForTest();

  // Strict should register, and all is counted.
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainAllWithoutContentVisibility));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainStrictWithoutContentVisibility));

  target->classList().Remove(AtomicString("strict"));
  target->classList().Add(AtomicString("all"));
  UpdateAllLifecyclePhasesForTest();

  // Everything should be counted now.
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainAllWithoutContentVisibility));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kCSSContainStrictWithoutContentVisibility));
}

// Containing block test.
TEST_F(LayoutObjectTest, ContainingBlockLayoutViewShouldBeNull) {
  EXPECT_EQ(nullptr, GetLayoutView().ContainingBlock());
}

TEST_F(LayoutObjectTest, ContainingBlockBodyShouldBeDocumentElement) {
  EXPECT_EQ(GetDocument().body()->GetLayoutObject()->ContainingBlock(),
            GetDocument().documentElement()->GetLayoutObject());
}

TEST_F(LayoutObjectTest, ContainingBlockDocumentElementShouldBeLayoutView) {
  EXPECT_EQ(
      GetDocument().documentElement()->GetLayoutObject()->ContainingBlock(),
      GetLayoutView());
}

TEST_F(LayoutObjectTest, ContainingBlockStaticLayoutObjectShouldBeParent) {
  SetBodyInnerHTML("<foo style='position:static'></foo>");
  LayoutObject* body_layout_object = GetDocument().body()->GetLayoutObject();
  LayoutObject* layout_object = body_layout_object->SlowFirstChild();
  EXPECT_EQ(layout_object->ContainingBlock(), body_layout_object);
}

TEST_F(LayoutObjectTest,
       ContainingBlockAbsoluteLayoutObjectShouldBeLayoutView) {
  SetBodyInnerHTML("<foo style='position:absolute'></foo>");
  LayoutObject* layout_object =
      GetDocument().body()->GetLayoutObject()->SlowFirstChild();
  EXPECT_EQ(layout_object->ContainingBlock(), GetLayoutView());
}

TEST_F(
    LayoutObjectTest,
    ContainingBlockAbsoluteLayoutObjectShouldBeNonStaticallyPositionedBlockAncestor) {
  SetBodyInnerHTML(R"HTML(
    <div style='position:relative; left:20px'>
      <bar style='position:absolute; left:2px; top:10px'></bar>
    </div>
  )HTML");
  LayoutObject* containing_blocklayout_object =
      GetDocument().body()->GetLayoutObject()->SlowFirstChild();
  LayoutObject* layout_object = containing_blocklayout_object->SlowFirstChild();
  EXPECT_TRUE(
      containing_blocklayout_object->CanContainOutOfFlowPositionedElement(
          EPosition::kAbsolute));
  EXPECT_FALSE(
      containing_blocklayout_object->CanContainOutOfFlowPositionedElement(
          EPosition::kFixed));
  EXPECT_EQ(layout_object->Container(), containing_blocklayout_object);
  EXPECT_EQ(layout_object->ContainingBlock(), containing_blocklayout_object);
  EXPECT_EQ(layout_object->ContainingBlockForAbsolutePosition(),
            containing_blocklayout_object);
  EXPECT_EQ(layout_object->ContainingBlockForFixedPosition(), GetLayoutView());
  auto offset =
      layout_object->OffsetFromContainer(containing_blocklayout_object);
  EXPECT_EQ(PhysicalOffset(2, 10), offset);
}

TEST_F(LayoutObjectTest, ContainingBlockFixedPosUnderFlattened3D) {
  SetBodyInnerHTML(R"HTML(
    <div id=container style='transform-style: preserve-3d; opacity: 0.9'>
      <div id=target style='position:fixed'></div>
    </div>
  )HTML");

  LayoutObject* target = GetLayoutObjectByElementId("target");
  LayoutObject* container = GetLayoutObjectByElementId("container");
  EXPECT_EQ(container, target->Container());
}

TEST_F(LayoutObjectTest, ContainingBlockFixedLayoutObjectInTransformedDiv) {
  SetBodyInnerHTML(R"HTML(
    <div style='transform:translateX(0px)'>
      <bar style='position:fixed'></bar>
    </div>
  )HTML");
  LayoutObject* containing_blocklayout_object =
      GetDocument().body()->GetLayoutObject()->SlowFirstChild();
  LayoutObject* layout_object = containing_blocklayout_object->SlowFirstChild();
  EXPECT_TRUE(
      containing_blocklayout_object->CanContainOutOfFlowPositionedElement(
          EPosition::kAbsolute));
  EXPECT_TRUE(
      containing_blocklayout_object->CanContainOutOfFlowPositionedElement(
          EPosition::kFixed));
  EXPECT_EQ(layout_object->Container(), containing_blocklayout_object);
  EXPECT_EQ(layout_object->ContainingBlock(), containing_blocklayout_object);
  EXPECT_EQ(layout_object->ContainingBlockForAbsolutePosition(),
            containing_blocklayout_object);
  EXPECT_EQ(layout_object->ContainingBlockForFixedPosition(),
            containing_blocklayout_object);
}

TEST_F(LayoutObjectTest, ContainingBlockFixedLayoutObjectInBody) {
  SetBodyInnerHTML("<div style='position:fixed'></div>");
  LayoutObject* layout_object =
      GetDocument().body()->GetLayoutObject()->SlowFirstChild();
  EXPECT_TRUE(layout_object->CanContainOutOfFlowPositionedElement(
      EPosition::kAbsolute));
  EXPECT_FALSE(
      layout_object->CanContainOutOfFlowPositionedElement(EPosition::kFixed));
  EXPECT_EQ(layout_object->Container(), GetLayoutView());
  EXPECT_EQ(layout_object->ContainingBlock(), GetLayoutView());
  EXPECT_EQ(layout_object->ContainingBlockForAbsolutePosition(),
            GetLayoutView());
  EXPECT_EQ(layout_object->ContainingBlockForFixedPosition(), GetLayoutView());
}

TEST_F(LayoutObjectTest, ContainingBlockAbsoluteLayoutObjectInBody) {
  SetBodyInnerHTML("<div style='position:absolute'></div>");
  LayoutObject* layout_object =
      GetDocument().body()->GetLayoutObject()->SlowFirstChild();
  EXPECT_TRUE(layout_object->CanContainOutOfFlowPositionedElement(
      EPosition::kAbsolute));
  EXPECT_FALSE(
      layout_object->CanContainOutOfFlowPositionedElement(EPosition::kFixed));
  EXPECT_EQ(layout_object->Container(), GetLayoutView());
  EXPECT_EQ(layout_object->ContainingBlock(), GetLayoutView());
  EXPECT_EQ(layout_object->ContainingBlockForAbsolutePosition(),
            GetLayoutView());
  EXPECT_EQ(layout_object->ContainingBlockForFixedPosition(), GetLayoutView());
}

TEST_F(
    LayoutObjectTest,
    ContainingBlockAbsoluteLayoutObjectShouldNotBeNonStaticallyPositionedInlineAncestor) {
  // Test note: We can't use a raw string literal here, since extra whitespace
  // causes failures.
  SetBodyInnerHTML(
      "<span style='position:relative; top:1px; left:2px'><bar "
      "style='position:absolute; top:10px; left:20px;'></bar></span>");
  LayoutObject* body_layout_object = GetDocument().body()->GetLayoutObject();
  LayoutObject* span_layout_object = body_layout_object->SlowFirstChild();
  LayoutObject* layout_object = span_layout_object->SlowFirstChild();

  EXPECT_TRUE(span_layout_object->CanContainOutOfFlowPositionedElement(
      EPosition::kAbsolute));
  EXPECT_FALSE(span_layout_object->CanContainOutOfFlowPositionedElement(
      EPosition::kFixed));

  auto offset = layout_object->OffsetFromContainer(span_layout_object);
  EXPECT_EQ(PhysicalOffset(22, 11), offset);

  // Sanity check: Make sure we don't generate anonymous objects.
  EXPECT_EQ(nullptr, body_layout_object->SlowFirstChild()->NextSibling());
  EXPECT_EQ(nullptr, layout_object->SlowFirstChild());
  EXPECT_EQ(nullptr, layout_object->NextSibling());

  EXPECT_EQ(layout_object->Container(), span_layout_object);
  EXPECT_EQ(layout_object->ContainingBlock(), body_layout_object);
  EXPECT_EQ(layout_object->ContainingBlockForAbsolutePosition(),
            body_layout_object);
  EXPECT_EQ(layout_object->ContainingBlockForFixedPosition(), GetLayoutView());
}

TEST_F(LayoutObjectTest, PaintingLayerOfOverflowClipLayerUnderColumnSpanAll) {
  SetBodyInnerHTML(R"HTML(
    <div id='columns' style='position: relative; columns: 3'>
      <div style='column-span: all'>
        <div id='overflow-clip-layer' style='height: 100px; overflow:
    hidden'></div>
      </div>
    </div>
  )HTML");

  LayoutObject* overflow_clip_object =
      GetLayoutObjectByElementId("overflow-clip-layer");
  LayoutBlock* columns = To<LayoutBlock>(GetLayoutObjectByElementId("columns"));
  EXPECT_EQ(columns->Layer(), overflow_clip_object->PaintingLayer());
}

TEST_F(LayoutObjectTest, FloatUnderBlock) {
  SetBodyInnerHTML(R"HTML(
    <div id='layered-div' style='position: absolute'>
      <div id='container'>
        <div id='floating' style='float: left'>FLOAT</div>
      </div>
    </div>
  )HTML");

  auto* layered_div =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("layered-div"));
  auto* container =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("container"));
  LayoutObject* floating = GetLayoutObjectByElementId("floating");

  EXPECT_EQ(layered_div->Layer(), layered_div->PaintingLayer());
  EXPECT_EQ(layered_div->Layer(), floating->PaintingLayer());
  EXPECT_EQ(container, floating->Container());
  EXPECT_EQ(container, floating->ContainingBlock());
}

TEST_F(LayoutObjectTest, InlineFloatMismatch) {
  SetBodyInnerHTML(R"HTML(
    <span id=span style='position: relative; left: 40px; width: 100px; height: 100px'>
      <div id=float_obj style='float: left; margin-left: 10px;'>
      </div>
    </span>
  )HTML");

  LayoutObject* float_obj = GetLayoutObjectByElementId("float_obj");
  LayoutObject* span = GetLayoutObjectByElementId("span");
  // 10px for margin + 40px for inset.
  EXPECT_EQ(PhysicalOffset(50, 0), float_obj->OffsetFromAncestor(span));
}

TEST_F(LayoutObjectTest, FloatUnderInline) {
  SetBodyInnerHTML(R"HTML(
    <div id='layered-div' style='position: absolute'>
      <div id='container'>
        <span id='layered-span' style='position: relative'>
          <div id='floating' style='float: left'>FLOAT</div>
        </span>
      </div>
    </div>
  )HTML");

  auto* layered_div =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("layered-div"));
  auto* container =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("container"));
  auto* layered_span =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("layered-span"));
  LayoutObject* floating = GetLayoutObjectByElementId("floating");

  EXPECT_EQ(layered_div->Layer(), layered_div->PaintingLayer());
  EXPECT_EQ(layered_span->Layer(), layered_span->PaintingLayer());
  // Inline-level floats are children of their inline-level containers. As such
  // LayoutNG paints these within the correct inline-level layer.
  EXPECT_EQ(layered_span->Layer(), floating->PaintingLayer());
  EXPECT_EQ(layered_span, floating->Container());
  EXPECT_EQ(container, floating->ContainingBlock());

  LayoutObject::AncestorSkipInfo skip_info(layered_span);
  EXPECT_EQ(layered_span, floating->Container(&skip_info));
  EXPECT_FALSE(skip_info.AncestorSkipped());
}

TEST_F(LayoutObjectTest, MutableForPaintingClearPaintFlags) {
  LayoutObject* object = GetDocument().body()->GetLayoutObject();
  object->SetShouldDoFullPaintInvalidation();
  EXPECT_TRUE(object->ShouldDoFullPaintInvalidation());
  EXPECT_TRUE(object->ShouldCheckLayoutForPaintInvalidation());
  object->SetShouldCheckForPaintInvalidation();
  EXPECT_TRUE(object->ShouldCheckForPaintInvalidation());
  object->SetSubtreeShouldCheckForPaintInvalidation();
  EXPECT_TRUE(object->SubtreeShouldCheckForPaintInvalidation());
  object->SetMayNeedPaintInvalidationAnimatedBackgroundImage();
  EXPECT_TRUE(object->MayNeedPaintInvalidationAnimatedBackgroundImage());
  object->SetShouldInvalidateSelection();
  EXPECT_TRUE(object->ShouldInvalidateSelection());
  object->SetBackgroundNeedsFullPaintInvalidation();
  EXPECT_TRUE(object->BackgroundNeedsFullPaintInvalidation());
  object->SetNeedsPaintPropertyUpdate();
  EXPECT_TRUE(object->NeedsPaintPropertyUpdate());
  EXPECT_TRUE(object->Parent()->DescendantNeedsPaintPropertyUpdate());
  object->bitfields_.SetDescendantNeedsPaintPropertyUpdate(true);
  EXPECT_TRUE(object->DescendantNeedsPaintPropertyUpdate());

  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInPrePaint);
  object->GetMutableForPainting().ClearPaintFlags();

  EXPECT_FALSE(object->ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(object->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(object->SubtreeShouldCheckForPaintInvalidation());
  EXPECT_FALSE(object->MayNeedPaintInvalidationAnimatedBackgroundImage());
  EXPECT_FALSE(object->ShouldInvalidateSelection());
  EXPECT_FALSE(object->BackgroundNeedsFullPaintInvalidation());
  EXPECT_FALSE(object->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(object->DescendantNeedsPaintPropertyUpdate());
}

TEST_F(LayoutObjectTest, DelayFullPaintInvalidation) {
  LayoutObject* object = GetDocument().body()->GetLayoutObject();
  object->SetShouldDoFullPaintInvalidation();
  object->SetShouldDelayFullPaintInvalidation();
  EXPECT_FALSE(object->ShouldDoFullPaintInvalidation());
  EXPECT_TRUE(object->ShouldDelayFullPaintInvalidation());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(object->ShouldDoFullPaintInvalidation());
  // ShouldDelayFullPaintInvalidation is not preserved.
  EXPECT_TRUE(object->ShouldDelayFullPaintInvalidation());

  object->SetShouldDoFullPaintInvalidation();
  EXPECT_TRUE(object->ShouldDoFullPaintInvalidation());
  // ShouldDelayFullPaintInvalidation is reset by
  // SetShouldDoFullPaintInvalidation().
  EXPECT_FALSE(object->ShouldDelayFullPaintInvalidation());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(object->ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(object->ShouldDelayFullPaintInvalidation());
}

TEST_F(LayoutObjectTest, SubtreeAndDelayFullPaintInvalidation) {
  LayoutObject* object = GetDocument().body()->GetLayoutObject();
  object->SetShouldDoFullPaintInvalidation();
  object->SetShouldDelayFullPaintInvalidation();
  object->SetSubtreeShouldDoFullPaintInvalidation();
  EXPECT_TRUE(object->SubtreeShouldDoFullPaintInvalidation());
  EXPECT_TRUE(object->ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(object->ShouldDelayFullPaintInvalidation());

  object->SetShouldDelayFullPaintInvalidation();
  EXPECT_TRUE(object->SubtreeShouldDoFullPaintInvalidation());
  EXPECT_TRUE(object->ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(object->ShouldDelayFullPaintInvalidation());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(object->SubtreeShouldDoFullPaintInvalidation());
  EXPECT_FALSE(object->ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(object->ShouldDelayFullPaintInvalidation());
}

TEST_F(LayoutObjectTest, SubtreePaintPropertyUpdateReasons) {
  LayoutObject* object = GetDocument().body()->GetLayoutObject();
  // Just pick a random reason.
  object->AddSubtreePaintPropertyUpdateReason(
      SubtreePaintPropertyUpdateReason::kPreviouslySkipped);
  EXPECT_TRUE(object->SubtreePaintPropertyUpdateReasons());
  EXPECT_TRUE(object->NeedsPaintPropertyUpdate());
  EXPECT_TRUE(object->Parent()->DescendantNeedsPaintPropertyUpdate());

  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInPrePaint);
  object->GetMutableForPainting().ClearPaintFlags();

  EXPECT_FALSE(object->SubtreePaintPropertyUpdateReasons());
  EXPECT_FALSE(object->NeedsPaintPropertyUpdate());
}

TEST_F(LayoutObjectTest, ShouldCheckLayoutForPaintInvalidation) {
  LayoutObject* object = GetDocument().body()->GetLayoutObject();
  LayoutObject* parent = object->Parent();

  object->SetShouldDoFullPaintInvalidation();
  EXPECT_TRUE(object->ShouldDoFullPaintInvalidation());
  EXPECT_EQ(PaintInvalidationReason::kLayout,
            object->PaintInvalidationReasonForPrePaint());
  EXPECT_TRUE(object->ShouldCheckLayoutForPaintInvalidation());
  EXPECT_TRUE(parent->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(parent->ShouldCheckLayoutForPaintInvalidation());
  EXPECT_TRUE(parent->DescendantShouldCheckLayoutForPaintInvalidation());
  object->ClearPaintInvalidationFlags();
  EXPECT_FALSE(object->ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(object->ShouldCheckLayoutForPaintInvalidation());
  parent->ClearPaintInvalidationFlags();
  EXPECT_FALSE(parent->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(parent->ShouldCheckLayoutForPaintInvalidation());
  EXPECT_FALSE(parent->DescendantShouldCheckLayoutForPaintInvalidation());

  object->SetShouldCheckForPaintInvalidation();
  EXPECT_TRUE(object->ShouldCheckForPaintInvalidation());
  EXPECT_TRUE(object->ShouldCheckLayoutForPaintInvalidation());
  EXPECT_TRUE(parent->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(parent->ShouldCheckLayoutForPaintInvalidation());
  EXPECT_TRUE(parent->DescendantShouldCheckLayoutForPaintInvalidation());
  object->ClearPaintInvalidationFlags();
  EXPECT_FALSE(object->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(object->ShouldCheckLayoutForPaintInvalidation());
  parent->ClearPaintInvalidationFlags();
  EXPECT_FALSE(parent->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(parent->ShouldCheckLayoutForPaintInvalidation());
  EXPECT_FALSE(parent->DescendantShouldCheckLayoutForPaintInvalidation());

  object->SetShouldDoFullPaintInvalidationWithoutLayoutChange(
      PaintInvalidationReason::kStyle);
  EXPECT_EQ(PaintInvalidationReason::kStyle,
            object->PaintInvalidationReasonForPrePaint());
  EXPECT_TRUE(object->ShouldDoFullPaintInvalidation());
  EXPECT_FALSE(object->ShouldCheckLayoutForPaintInvalidation());
  EXPECT_TRUE(parent->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(parent->ShouldCheckLayoutForPaintInvalidation());
  EXPECT_FALSE(parent->DescendantShouldCheckLayoutForPaintInvalidation());
  object->SetShouldCheckForPaintInvalidation();
  EXPECT_TRUE(object->ShouldCheckLayoutForPaintInvalidation());
  EXPECT_TRUE(parent->DescendantShouldCheckLayoutForPaintInvalidation());
  object->ClearPaintInvalidationFlags();
  EXPECT_FALSE(object->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(object->ShouldCheckLayoutForPaintInvalidation());
  parent->ClearPaintInvalidationFlags();
  EXPECT_FALSE(parent->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(parent->DescendantShouldCheckLayoutForPaintInvalidation());

  object->SetShouldCheckForPaintInvalidationWithoutLayoutChange();
  EXPECT_TRUE(object->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(object->ShouldCheckLayoutForPaintInvalidation());
  EXPECT_TRUE(parent->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(parent->DescendantShouldCheckLayoutForPaintInvalidation());
  object->SetShouldCheckForPaintInvalidation();
  EXPECT_TRUE(object->ShouldCheckLayoutForPaintInvalidation());
  EXPECT_TRUE(parent->DescendantShouldCheckLayoutForPaintInvalidation());
  object->ClearPaintInvalidationFlags();
  EXPECT_FALSE(object->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(object->ShouldCheckLayoutForPaintInvalidation());
  parent->ClearPaintInvalidationFlags();
  EXPECT_FALSE(parent->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(parent->DescendantShouldCheckLayoutForPaintInvalidation());
}

TEST_F(LayoutObjectTest, AssociatedLayoutObjectOfFirstLetterPunctuations) {
  const char* body_content =
      "<style>p:first-letter {color:red;}</style><p id=sample>(a)bc</p>";
  SetBodyInnerHTML(body_content);

  Node* sample = GetElementById("sample");
  Node* text = sample->firstChild();

  const auto* layout_object0 =
      To<LayoutTextFragment>(AssociatedLayoutObjectOf(*text, 0));
  EXPECT_FALSE(layout_object0->IsRemainingTextLayoutObject());

  const auto* layout_object1 =
      To<LayoutTextFragment>(AssociatedLayoutObjectOf(*text, 1));
  EXPECT_EQ(layout_object0, layout_object1)
      << "A character 'a' should be part of first letter.";

  const auto* layout_object2 =
      To<LayoutTextFragment>(AssociatedLayoutObjectOf(*text, 2));
  EXPECT_EQ(layout_object0, layout_object2)
      << "close parenthesis should be part of first letter.";

  const auto* layout_object3 =
      To<LayoutTextFragment>(AssociatedLayoutObjectOf(*text, 3));
  EXPECT_TRUE(layout_object3->IsRemainingTextLayoutObject());
}

TEST_F(LayoutObjectTest, AssociatedLayoutObjectOfFirstLetterSplit) {
  V8TestingScope scope;

  const char* body_content =
      "<style>p:first-letter {color:red;}</style><p id=sample>abc</p>";
  SetBodyInnerHTML(body_content);

  Node* sample = GetElementById("sample");
  Node* first_letter = sample->firstChild();
  // Split "abc" into "a" "bc"
  To<Text>(first_letter)->splitText(1, ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  const auto* layout_object0 =
      To<LayoutTextFragment>(AssociatedLayoutObjectOf(*first_letter, 0));
  EXPECT_FALSE(layout_object0->IsRemainingTextLayoutObject());

  const auto* layout_object1 =
      To<LayoutTextFragment>(AssociatedLayoutObjectOf(*first_letter, 1));
  EXPECT_EQ(layout_object0, layout_object1);
}

TEST_F(LayoutObjectTest,
       AssociatedLayoutObjectOfFirstLetterWithTrailingWhitespace) {
  const char* body_content = R"HTML(
    <style>
      div:first-letter {
        color:red;
      }
    </style>
    <div id=sample>a
      <div></div>
    </div>
  )HTML";
  SetBodyInnerHTML(body_content);

  Node* sample = GetElementById("sample");
  Node* text = sample->firstChild()
```