Response:

Prompt: 
```
这是目录为blink/renderer/core/editing/layout_selection_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/layout_selection.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_shadow_root_init.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

static LayoutTextFragment* FirstLetterPartFor(
    const LayoutObject* layout_object) {
  if (const auto* layout_text = DynamicTo<LayoutText>(layout_object))
    return DynamicTo<LayoutTextFragment>(layout_text->GetFirstLetterPart());
  return nullptr;
}

class LayoutSelectionTestBase : public EditingTestBase {
 protected:
  static void PrintText(std::ostream& ostream, const Text& text) {
    ostream << "'" << text.data().Utf8() << "'";
  }

  static void PrintLayoutTextInfo(const FrameSelection& selection,
                                  std::ostream& ostream,
                                  const LayoutText& layout_text,
                                  SelectionState state) {
    if (layout_text.IsInLayoutNGInlineFormattingContext()) {
      InlineCursor cursor(*layout_text.FragmentItemsContainer());
      cursor.MoveTo(layout_text);
      if (!cursor)
        return;
      const unsigned text_start = cursor.Current().TextStartOffset();
      for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
        const LayoutSelectionStatus status =
            selection.ComputeLayoutSelectionStatus(cursor);
        if (state == SelectionState::kNone && status.start == status.end)
          continue;
        ostream << "(" << status.start - text_start << ","
                << status.end - text_start << ")";
      }
      return;
    }

    const LayoutTextSelectionStatus& status =
        selection.ComputeLayoutSelectionStatus(layout_text);
    if (state == SelectionState::kNone && status.start == status.end)
      return;
    ostream << "(" << status.start << "," << status.end << ")";
  }

  static void PrintLayoutObjectInfo(const FrameSelection& selection,
                                    std::ostream& ostream,
                                    LayoutObject* layout_object) {
    const SelectionState& state = layout_object->GetSelectionState();
    ostream << ", " << state;
    if (layout_object->IsText()) {
      PrintLayoutTextInfo(selection, ostream, To<LayoutText>(*layout_object),
                          state);
    }

    ostream << (layout_object->ShouldInvalidateSelection()
                    ? ", ShouldInvalidate "
                    : ", NotInvalidate ");
  }
  static void PrintSelectionInfo(const FrameSelection& selection,
                                 std::ostream& ostream,
                                 const Node& node,
                                 wtf_size_t depth) {
    if (const Text* text = DynamicTo<Text>(node))
      PrintText(ostream, *text);
    else if (const auto* element = DynamicTo<Element>(node))
      ostream << element->tagName().Utf8();
    else
      ostream << node;

    LayoutObject* layout_object = node.GetLayoutObject();
    if (!layout_object) {
      ostream << ", <null LayoutObject> ";
      return;
    }
    PrintLayoutObjectInfo(selection, ostream, layout_object);
    if (LayoutTextFragment* first_letter = FirstLetterPartFor(layout_object)) {
      ostream << std::endl
              << RepeatString("  ", depth + 1).Utf8() << ":first-letter";
      PrintLayoutObjectInfo(selection, ostream, first_letter);
    }
  }

  static void PrintDOMTreeInternal(const FrameSelection& selection,
                                   std::ostream& ostream,
                                   const Node& node,
                                   wtf_size_t depth) {
    ostream << RepeatString("  ", depth).Utf8();
    if (IsA<HTMLStyleElement>(node)) {
      ostream << "<style> ";
      return;
    }
    PrintSelectionInfo(selection, ostream, node, depth);
    if (ShadowRoot* shadow_root = node.GetShadowRoot()) {
      ostream << std::endl << RepeatString("  ", depth + 1).Utf8();
      ostream << "#shadow-root ";
      for (Node* child = shadow_root->firstChild(); child;
           child = child->nextSibling()) {
        ostream << std::endl;
        PrintDOMTreeInternal(selection, ostream, *child, depth + 2);
      }
    }

    for (Node* child = node.firstChild(); child; child = child->nextSibling()) {
      ostream << std::endl;
      PrintDOMTreeInternal(selection, ostream, *child, depth + 1);
    }
  }

#ifndef NDEBUG
  void PrintDOMTreeForDebug() {
    std::stringstream stream;
    stream << "\nPrintDOMTreeForDebug";
    PrintDOMTreeInternal(Selection(), stream, *GetDocument().body(), 0u);
    LOG(INFO) << stream.str();
  }
#endif

  std::string DumpSelectionInfo() {
    std::stringstream stream;
    PrintDOMTreeInternal(Selection(), stream, *GetDocument().body(), 0u);
    return stream.str();
  }
};

class LayoutSelectionTest : public LayoutSelectionTestBase {
 protected:
  LayoutSelectionTest() = default;
};

TEST_F(LayoutSelectionTest, TraverseLayoutObject) {
  SetBodyContent("foo<br>bar");
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .SelectAllChildren(*GetDocument().body())
                               .Build(),
                           SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(0,3), ShouldInvalidate \n"
      "  BR, Inside(0,1), ShouldInvalidate \n"
      "  'bar', End(0,3), ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, TraverseLayoutObjectTruncateVisibilityHidden) {
  SetBodyContent(
      "<span style='visibility:hidden;'>before</span>"
      "foo"
      "<span style='visibility:hidden;'>after</span>");
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .SelectAllChildren(*GetDocument().body())
                               .Build(),
                           SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  SPAN, None, NotInvalidate \n"
      "    'before', None, NotInvalidate \n"
      "  'foo', StartAndEnd(0,3), ShouldInvalidate \n"
      "  SPAN, None, NotInvalidate \n"
      "    'after', None, NotInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, TraverseLayoutObjectBRs) {
  SetBodyContent("<br><br>foo<br><br>");
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .SelectAllChildren(*GetDocument().body())
                               .Build(),
                           SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  BR, Start(0,1), ShouldInvalidate \n"
      "  BR, Inside(0,1), ShouldInvalidate \n"
      "  'foo', Inside(0,3), ShouldInvalidate \n"
      "  BR, Inside(0,1), ShouldInvalidate \n"
      "  BR, End(0,1), ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, TraverseLayoutObjectListStyleImage) {
  SetBodyContent(
      "<style>ul {list-style-image:url(data:"
      "image/gif;base64,R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs=)}"
      "</style>"
      "<ul><li>foo<li>bar</ul>");
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .SelectAllChildren(*GetDocument().body())
                               .Build(),
                           SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  <style> \n"
      "  UL, Contain, NotInvalidate \n"
      "    LI, Contain, NotInvalidate \n"
      "      'foo', Start(0,3), ShouldInvalidate \n"
      "    LI, Contain, NotInvalidate \n"
      "      'bar', End(0,3), ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, TraverseLayoutObjectCrossingShadowBoundary) {
  Selection().SetSelection(
      SetSelectionTextToBody(
          "^foo"
          "<div>"
          "<template data-mode=open>"
          "Foo<slot name=s2></slot><slot name=s1></slot>"
          "</template>"
          // Set selection at SPAN@0 instead of "bar1"@0
          "<span slot=s1><!--|-->bar1</span><span slot=s2>bar2</span>"
          "</div>"),
      SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(0,3), ShouldInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    #shadow-root \n"
      "      'Foo', Inside(0,3), ShouldInvalidate \n"
      "      SLOT, <null LayoutObject> \n"
      "      SLOT, <null LayoutObject> \n"
      "    SPAN, None, NotInvalidate \n"
      "      'bar1', None, NotInvalidate \n"
      "    SPAN, Contain, NotInvalidate \n"
      "      'bar2', End(0,4), ShouldInvalidate ",
      DumpSelectionInfo());
}

// crbug.com/752715
TEST_F(LayoutSelectionTest,
       InvalidationShouldNotChangeRefferedLayoutObjectState) {
  SetBodyContent(
      "<div id='d1'>div1</div><div id='d2'>foo<span>bar</span>baz</div>");
  Node* span = GetDocument().QuerySelector(AtomicString("span"));
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(span->firstChild(), 0),
                            Position(span->firstChild(), 3))
          .Build(),
      SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  DIV, None, NotInvalidate \n"
      "    'div1', None, NotInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    'foo', None, NotInvalidate \n"
      "    SPAN, Contain, NotInvalidate \n"
      "      'bar', StartAndEnd(0,3), ShouldInvalidate \n"
      "    'baz', None, NotInvalidate ",
      DumpSelectionInfo());

  Node* d1 = GetDocument().QuerySelector(AtomicString("#d1"));
  Node* d2 = GetDocument().QuerySelector(AtomicString("#d2"));
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(d1, 0), Position(d2, 0))
          .Build(),
      SetSelectionOptions());
  // This commit should not crash.
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    'div1', StartAndEnd(0,4), ShouldInvalidate \n"
      "  DIV, None, NotInvalidate \n"
      "    'foo', None, NotInvalidate \n"
      "    SPAN, None, NotInvalidate \n"
      "      'bar', None, ShouldInvalidate \n"
      "    'baz', None, NotInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, TraverseLayoutObjectLineWrap) {
  SetBodyContent("bar\n");
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .SelectAllChildren(*GetDocument().body())
                               .Build(),
                           SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'bar\n', StartAndEnd(0,3), ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, FirstLetter) {
  SetBodyContent(
      "<style>::first-letter { color: red; }</style>"
      "<span>foo</span>");
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .SelectAllChildren(*GetDocument().body())
                               .Build(),
                           SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  <style> \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'foo', StartAndEnd(0,2), ShouldInvalidate \n"
      "      :first-letter, None(0,1), ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, FirstLetterMultiple) {
  Selection().SetSelection(
      SetSelectionTextToBody("<style>::first-letter { color: red; }</style>"
                             "<span> [^f]o|o</span>"),
      SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  <style> \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    ' [f]oo', StartAndEnd(0,1), ShouldInvalidate \n"
      "      :first-letter, None(1,3), ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, FirstLetterClearSeletion) {
  InsertStyleElement("div::first-letter { color: red; }");
  Selection().SetSelection(SetSelectionTextToBody("fo^o<div>bar</div>b|az"),
                           SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(2,3), ShouldInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    'bar', Inside(0,2), ShouldInvalidate \n"
      "      :first-letter, None(0,1), ShouldInvalidate \n"
      "  'baz', End(0,1), ShouldInvalidate ",
      DumpSelectionInfo());

  Selection().Clear();
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, None, NotInvalidate \n"
      "  'foo', None, ShouldInvalidate \n"
      "  DIV, None, NotInvalidate \n"
      "    'bar', None, ShouldInvalidate \n"
      "      :first-letter, None, ShouldInvalidate \n"
      "  'baz', None, ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, FirstLetterUpdateSeletion) {
  SetBodyContent(
      "<style>div::first-letter { color: red; }</style>"
      "foo<div>bar</div>baz");
  Node* const foo = GetDocument().body()->firstChild()->nextSibling();
  Node* const baz = GetDocument()
                        .body()
                        ->firstChild()
                        ->nextSibling()
                        ->nextSibling()
                        ->nextSibling();
  // <div>fo^o</div><div>bar</div>b|az
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .SetBaseAndExtent({foo, 2}, {baz, 1})
                               .Build(),
                           SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  <style> \n"
      "  'foo', Start(2,3), ShouldInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    'bar', Inside(0,2), ShouldInvalidate \n"
      "      :first-letter, None(0,1), ShouldInvalidate \n"
      "  'baz', End(0,1), ShouldInvalidate ",
      DumpSelectionInfo());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  <style> \n"
      "  'foo', Start(2,3), NotInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    'bar', Inside(0,2), NotInvalidate \n"
      "      :first-letter, None(0,1), NotInvalidate \n"
      "  'baz', End(0,1), NotInvalidate ",
      DumpSelectionInfo());
  UpdateAllLifecyclePhasesForTest();

  // <div>foo</div><div>bar</div>ba^z|
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .SetBaseAndExtent({baz, 2}, {baz, 3})
                               .Build(),
                           SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  <style> \n"
      "  'foo', None, ShouldInvalidate \n"
      "  DIV, None, NotInvalidate \n"
      "    'bar', None, ShouldInvalidate \n"
      "      :first-letter, None, ShouldInvalidate \n"
      "  'baz', StartAndEnd(2,3), ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, CommitAppearanceIfNeededNotCrash) {
  Selection().SetSelection(
      SetSelectionTextToBody(
          "<div>"
          "<template data-mode=open>foo</template>"
          "<span>|bar<span>"  // <span> is not appeared in flat tree.
          "</div>"
          "<div>baz^</div>"),
      SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
}

TEST_F(LayoutSelectionTest, SelectImage) {
  const SelectionInDOMTree& selection =
      SetSelectionTextToBody("^<img style=\"width:100px; height:100px\"/>|");
  Selection().SetSelection(selection, SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  IMG, StartAndEnd, ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, MoveOnSameNode_Start) {
  const SelectionInDOMTree& selection =
      SetSelectionTextToBody("f^oo<span>b|ar</span>");
  Selection().SetSelection(selection, SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(1,3), ShouldInvalidate \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'bar', End(0,1), ShouldInvalidate ",
      DumpSelectionInfo());

  // Paint virtually and clear ShouldInvalidate flag.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(1,3), NotInvalidate \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'bar', End(0,1), NotInvalidate ",
      DumpSelectionInfo());

  // "fo^o<span>b|ar</span>"
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent({selection.Anchor().AnchorNode(), 2},
                            selection.Focus())
          .Build(),
      SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  // Only "foo" should be invalidated.
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(2,3), ShouldInvalidate \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'bar', End(0,1), NotInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, MoveOnSameNode_End) {
  const SelectionInDOMTree& selection =
      SetSelectionTextToBody("f^oo<span>b|ar</span>");
  Selection().SetSelection(selection, SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(1,3), ShouldInvalidate \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'bar', End(0,1), ShouldInvalidate ",
      DumpSelectionInfo());

  // Paint virtually and clear ShouldInvalidate flag.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(1,3), NotInvalidate \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'bar', End(0,1), NotInvalidate ",
      DumpSelectionInfo());

  // "fo^o<span>ba|r</span>"
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(selection.Anchor(),
                            {selection.Focus().AnchorNode(), 2})
          .Build(),
      SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  // Only "bar" should be invalidated.
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(1,3), NotInvalidate \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'bar', End(0,2), ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, MoveOnSameNode_StartAndEnd) {
  const SelectionInDOMTree& selection = SetSelectionTextToBody("f^oob|ar");
  Selection().SetSelection(selection, SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foobar', StartAndEnd(1,4), ShouldInvalidate ",
      DumpSelectionInfo());

  // Paint virtually and clear ShouldInvalidate flag.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foobar', StartAndEnd(1,4), NotInvalidate ",
      DumpSelectionInfo());

  // "f^ooba|r"
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(selection.Anchor(),
                            {selection.Focus().AnchorNode(), 5})
          .Build(),
      SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  // "foobar" should be invalidated.
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foobar', StartAndEnd(1,5), ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, MoveOnSameNode_StartAndEnd_Collapse) {
  const SelectionInDOMTree& selection = SetSelectionTextToBody("f^oob|ar");
  Selection().SetSelection(selection, SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foobar', StartAndEnd(1,4), ShouldInvalidate ",
      DumpSelectionInfo());

  // Paint virtually and clear ShouldInvalidate flag.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foobar', StartAndEnd(1,4), NotInvalidate ",
      DumpSelectionInfo());

  // "foo^|bar"
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .Collapse({selection.Anchor().AnchorNode(), 3})
                               .Build(),
                           SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  // "foobar" should be invalidated.
  EXPECT_EQ(
      "BODY, None, NotInvalidate \n"
      "  'foobar', None, ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, ContentEditableButton) {
  SetBodyContent("<input type=button value=foo contenteditable>");
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .SelectAllChildren(*GetDocument().body())
                               .Build(),
                           SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  INPUT, Contain, NotInvalidate \n"
      "    #shadow-root \n"
      "      'foo', StartAndEnd(0,3), ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, ClearSelection) {
  Selection().SetSelection(SetSelectionTextToBody("<div>f^o|o</div>"),
                           SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    'foo', StartAndEnd(1,2), ShouldInvalidate ",
      DumpSelectionInfo());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    'foo', StartAndEnd(1,2), NotInvalidate ",
      DumpSelectionInfo());

  Selection().Clear();
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, None, NotInvalidate \n"
      "  DIV, None, NotInvalidate \n"
      "    'foo', None, ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, SVG) {
  const SelectionInDOMTree& selection =
      SetSelectionTextToBody("<svg><text x=10 y=10>fo^o|bar</text></svg>");
  Selection().SetSelection(selection, SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  // LayoutSVGText should be invalidate though it is kContain.
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  svg, Contain, NotInvalidate \n"
      "    text, Contain, ShouldInvalidate \n"
      "      'foobar', StartAndEnd(2,3), ShouldInvalidate ",
      DumpSelectionInfo());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  svg, Contain, NotInvalidate \n"
      "    text, Contain, NotInvalidate \n"
      "      'foobar', StartAndEnd(2,3), NotInvalidate ",
      DumpSelectionInfo());

  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(selection.Anchor(),
                            {selection.Focus().AnchorNode(), 4})
          .Build(),
      SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  svg, Contain, NotInvalidate \n"
      "    text, Contain, ShouldInvalidate \n"
      "      'foobar', StartAndEnd(2,4), ShouldInvalidate ",
      DumpSelectionInfo());
}

// crbug.com/781705
TEST_F(LayoutSelectionTest, SVGAncestor) {
  const SelectionInDOMTree& selection = SetSelectionTextToBody(
      "<svg><text x=10 y=10><tspan>fo^o|bar</tspan></text></svg>");
  Selection().SetSelection(selection, SetSelectionOptions());
  // LayoutSVGText should be invalidated.
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  svg, Contain, NotInvalidate \n"
      "    text, Contain, ShouldInvalidate \n"
      "      tspan, Contain, NotInvalidate \n"
      "        'foobar', StartAndEnd(2,3), ShouldInvalidate ",
      DumpSelectionInfo());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  svg, Contain, NotInvalidate \n"
      "    text, Contain, NotInvalidate \n"
      "      tspan, Contain, NotInvalidate \n"
      "        'foobar', StartAndEnd(2,3), NotInvalidate ",
      DumpSelectionInfo());

  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(selection.Anchor(),
                            {selection.Focus().AnchorNode(), 4})
          .Build(),
      SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  svg, Contain, NotInvalidate \n"
      "    text, Contain, ShouldInvalidate \n"
      "      tspan, Contain, NotInvalidate \n"
      "        'foobar', StartAndEnd(2,4), ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, Embed) {
  Selection().SetSelection(
      SetSelectionTextToBody("^<embed type=foobar></embed>|"),
      SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  EMBED, StartAndEnd, ShouldInvalidate \n"
      "    #shadow-root \n"
      "      SLOT, <null LayoutObject> ",
      DumpSelectionInfo());
}

// http:/crbug.com/843144
TEST_F(LayoutSelectionTest, Ruby) {
  Selection().SetSelection(
      SetSelectionTextToBody("^<ruby>foo<rt>bar</rt></ruby>|"),
      SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  RUBY, Contain, NotInvalidate \n"
      "    'foo', Start(0,3), ShouldInvalidate \n"
      "    RT, Contain, NotInvalidate \n"
      "      'bar', End(0,3), ShouldInvalidate ",
      DumpSelectionInfo());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  RUBY, Contain, NotInvalidate \n"
      "    'foo', Start(0,3), NotInvalidate \n"
      "    RT, Contain, NotInvalidate \n"
      "      'bar', End(0,3), NotInvalidate ",
      DumpSelectionInfo());

  Selection().Clear();
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, None, NotInvalidate \n"
      "  RUBY, None, NotInvalidate \n"
      "    'foo', None, ShouldInvalidate \n"
      "    RT, None, NotInvalidate \n"
      "      'bar', None, ShouldInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, ClearByRemoveNode) {
  Selection().SetSelection(SetSelectionTextToBody("^foo<span>bar</span>baz|"),
                           SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(0,3), ShouldInvalidate \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'bar', Inside(0,3), ShouldInvalidate \n"
      "  'baz', End(0,3), ShouldInvalidate ",
      DumpSelectionInfo());

  Node* baz = GetDocument().body()->lastChild();
  baz->remove();
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(0,3), ShouldInvalidate \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'bar', End(0,3), ShouldInvalidate ",
      DumpSelectionInfo());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(0,3), NotInvalidate \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'bar', End(0,3), NotInvalidate ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, ClearByRemoveLayoutObject) {
  Selection().SetSelection(
      SetSelectionTextToBody("^foo<span>bar</span><span>baz</span>|"),
      SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(0,3), ShouldInvalidate \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'bar', Inside(0,3), ShouldInvalidate \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'baz', End(0,3), ShouldInvalidate ",
      DumpSelectionInfo());

  auto* span_baz = To<Element>(GetDocument().body()->lastChild());
  span_baz->SetInlineStyleProperty(CSSPropertyID::kDisplay, CSSValueID::kNone);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(0,3), ShouldInvalidate \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'bar', End(0,3), ShouldInvalidate \n"
      "  SPAN, <null LayoutObject> \n"
      "    'baz', <null LayoutObject> ",
      DumpSelectionInfo());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  'foo', Start(0,3), NotInvalidate \n"
      "  SPAN, Contain, NotInvalidate \n"
      "    'bar', End(0,3), NotInvalidate \n"
      "  SPAN, <null LayoutObject> \n"
      "    'baz', <null LayoutObject> ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, ClearBySlotChange) {
  Selection().SetSelection(SetSelectionTextToBody("<div>"
                                                  "<template data-mode=open>"
                                                  "^Foo<slot name=s1></slot>|"
                                                  "</template>"
                                                  "baz<span slot=s1>bar</span>"
                                                  "</div>"),
                           SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    #shadow-root \n"
      "      'Foo', Start(0,3), ShouldInvalidate \n"
      "      SLOT, <null LayoutObject> \n"
      "    'baz', <null LayoutObject> \n"
      "    SPAN, Contain, NotInvalidate \n"
      "      'bar', End(0,3), ShouldInvalidate ",
      DumpSelectionInfo());
  Element* slot =
      GetDocument().body()->firstChild()->GetShadowRoot()->QuerySelector(
          AtomicString("slot"));
  slot->setAttribute(html_names::kNameAttr, AtomicString("s2"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    #shadow-root \n"
      "      'Foo', StartAndEnd(0,3), ShouldInvalidate \n"
      "      SLOT, <null LayoutObject> \n"
      "    'baz', <null LayoutObject> \n"
      "    SPAN, <null LayoutObject> \n"
      "      'bar', <null LayoutObject> ",
      DumpSelectionInfo());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    #shadow-root \n"
      "      'Foo', StartAndEnd(0,3), NotInvalidate \n"
      "      SLOT, <null LayoutObject> \n"
      "    'baz', <null LayoutObject> \n"
      "    SPAN, <null LayoutObject> \n"
      "      'bar', <null LayoutObject> ",
      DumpSelectionInfo());
}

TEST_F(LayoutSelectionTest, MoveNode) {
  Selection().SetSelection(
      SetSelectionTextToBody(
          "<div id='div1'></div><div id='div2'>^foo<b>ba|r</b></div>"),
      SetSelectionOptions());
  Selection().CommitAppearanceIfNeeded();
  EXPECT_EQ(
      "BODY, Contain, NotInvalidate \n"
      "  DIV, None, NotInvalidate \n"
      "  DIV, Contain, NotInvalidate \n"
      "    'foo', Start(0,3), ShouldInvalidate \n"
      "    B, Contain, NotInvalidate \n"
      "      'bar', End(0,2), ShouldInvalidate ",
      DumpSelectionInfo());
  Node* div1 = GetDocument().QuerySelector(AtomicString("#div
"""


```