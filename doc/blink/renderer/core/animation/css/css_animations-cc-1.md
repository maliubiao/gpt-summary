Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. They specifically asked for:

1. **General functionality:** What does this code do?
2. **Relationship to web technologies:** How does it interact with JavaScript, HTML, and CSS? Provide examples.
3. **Logical inferences:**  Demonstrate the code's logic with hypothetical input and output.
4. **Common errors:** Point out potential user or programming mistakes related to this code.
5. **Overall summary:** A concise recap of the code's purpose, considering this is part 2 of 5.

**Thinking Process:**

1. **High-level understanding:** The code seems to be responsible for managing CSS Animations, specifically focusing on the concept of "timelines". It defines classes like `SpecifiedTimelines`, `SpecifiedScrollTimelines`, and `SpecifiedViewTimelines`, suggesting it deals with different types of animation timelines. The presence of functions like `CalculateScrollTimelineUpdate`, `CalculateViewTimelineUpdate`, and `CalculateDeferredTimelineUpdate` confirms this.

2. **Detailed analysis of classes and functions:**
    * **`SpecifiedTimelines` and its subclasses:** These classes extract timeline information (name, axis, inset) from the `ComputedStyleBuilder`. The iterator pattern in `SpecifiedTimelines` suggests a way to iterate over defined timelines.
    * **`ForEachTimeline`:** This template function iterates through existing and changed timelines, applying a callback function. This is a common pattern for processing collections.
    * **`NullifyExistingTimelines`:**  This function creates a map where existing timeline names are associated with null pointers. This likely represents an initial state where all timelines are assumed to be removed, and then the nulls are cleared for the timelines that persist.
    * **`GetTimeline` and `GetTimelineAttachment`:** These functions retrieve specific timelines or their attachments based on name or the timeline itself.
    * **`ResolveReferenceElement`, `ComputeReferenceType`, `ComputeAxis`:** These functions translate CSS timeline properties (like `scroll()`, `view()`, `nearest`, `root`, `block`, `inline`) into internal representations (`ScrollTimeline::ReferenceType`, `ScrollTimeline::ScrollAxis`).
    * **`CSSScrollTimelineOptions`, `CSSViewTimelineOptions`:** These structs group the necessary parameters for creating or matching scroll and view timelines.
    * **`TimelineMatches`:** These functions check if an existing timeline matches the given options, avoiding the creation of duplicate timelines.
    * **`PropertiesForTransitionAll`:** This function seems related to the `transition: all` CSS property, determining which properties are affected by transitions.
    * **`Calculate*TimelineUpdate` functions:** These are the core functions responsible for determining which timelines need to be created, updated, or removed based on style changes. They utilize the `Specified*Timelines` classes and the `TimelineMatches` functions.
    * **`CalculateChangedTimelineAttachments`:**  This function handles the association between "attaching" timelines (like ScrollTimeline, ViewTimeline) and "attached" timelines (DeferredTimeline).
    * **`FindTimelineForNode`, `FindAncestorTimeline`, `FindDeferredTimeline`:** These functions search for existing timelines in the element's hierarchy.
    * **`ComputeTimeline`:** This function is the central point for creating or retrieving animation timelines based on the `StyleTimeline` data.
    * **`CalculateCompositorAnimationUpdate`:** This function seems to deal with updating animations on the compositor thread, potentially for performance reasons. It checks for changes that might require recalculating keyframes.
    * **`CalculateAnimationUpdate`:** This function appears to be the main entry point for calculating animation updates, orchestrating the calls to other `Calculate*` functions.

3. **Relating to web technologies:**
    * **CSS:** The code directly parses and interprets CSS properties related to animations like `scroll-timeline`, `view-timeline`, `timeline-scope`, `scroll-axis`, `view-timeline-axis`, and `view-timeline-inset`. The `transition: all` functionality is also handled.
    * **JavaScript:** While the code is C++, it's part of the Blink rendering engine, which is what the browser uses to interpret and render web pages. JavaScript animation APIs would interact with the underlying mechanisms implemented in this code. For example, a JavaScript animation using the Web Animations API might eventually trigger the creation or modification of timelines managed by this code.
    * **HTML:** The code operates on the DOM (Document Object Model), which represents the HTML structure. The `Element` class is central to the logic, as animations are applied to HTML elements.

4. **Hypothetical input and output:** Focus on illustrating the core logic of timeline creation and matching.

5. **Common errors:** Think about how developers might misuse the related CSS properties or how the engine might handle edge cases.

6. **Overall summary (Part 2 context):** This part focuses specifically on the *calculation* of timeline updates. It's responsible for figuring out the changes needed to the animation timelines based on style changes.

By following this process, I can generate a comprehensive and accurate summary that addresses all the user's requirements.
这是对Chromium Blink引擎源代码文件 `blink/renderer/core/animation/css/css_animations.cc` 的第二部分功能归纳。这部分代码主要负责**计算和管理CSS动画的Timeline（时间轴）的更新**。它涵盖了不同类型的Timeline，包括Scroll Timeline、View Timeline 和 Deferred Timeline。

以下是这部分代码功能的详细归纳：

**1. Timeline的抽象和表示:**

*   **`SpecifiedTimelines` 及其子类 (`SpecifiedScrollTimelines`, `SpecifiedViewTimelines`)**:  用于从 `ComputedStyleBuilder` 中提取并表示CSS样式中指定的Timeline信息。这包括Timeline的名称、轴向（axis）和内边距（inset，仅用于View Timeline）。
*   **迭代器模式**: `SpecifiedTimelines` 使用迭代器模式 (`begin()`, `end()`, `operator++()`, `operator==()`, `operator!=()`) 来遍历定义的Timeline。

**2. Timeline更新的核心逻辑:**

*   **`CalculateScrollTimelineUpdate`**:  计算指定元素的Scroll Timeline的更新。它会检查样式构建器中是否定义了新的Scroll Timeline，并与已存在的Scroll Timeline进行比较，以确定是否需要创建、更新或移除Timeline。
*   **`CalculateViewTimelineUpdate`**:  与 `CalculateScrollTimelineUpdate` 类似，但针对的是View Timeline。
*   **`CalculateDeferredTimelineUpdate`**:  计算Deferred Timeline的更新。Deferred Timeline通常与 `<timeline-scope>` CSS属性关联。
*   **`CalculateChangedScrollTimelines`**:  具体实现Scroll Timeline的变更计算。它会遍历样式中定义的Scroll Timeline，并判断是否已存在匹配的Timeline。如果不存在或不匹配，则创建新的Scroll Timeline。
*   **`CalculateChangedViewTimelines`**:  具体实现View Timeline的变更计算，逻辑与 `CalculateChangedScrollTimelines` 类似。
*   **`CalculateChangedDeferredTimelines`**:  具体实现Deferred Timeline的变更计算。
*   **`NullifyExistingTimelines`**:  辅助函数，创建一个映射，其中包含现有Timeline的名称，但值为空指针。这用于标记初始状态，表示假设所有Timeline都将被移除，然后在后续步骤中取消标记仍然存在的Timeline。
*   **`GetTimeline`**:  从Timeline映射中根据名称获取Timeline对象。

**3. Timeline的匹配和重用:**

*   **`CSSScrollTimelineOptions`, `CSSViewTimelineOptions`**:  结构体，用于存储创建或匹配Scroll Timeline和View Timeline所需的参数。
*   **`TimelineMatches`**:  函数，用于比较现有的Timeline对象是否与给定的选项匹配。如果匹配，则可以重用现有的Timeline，避免创建重复的Timeline对象，提高性能。

**4. Timeline的查找:**

*   **`FindTimelineForNode`**:  在给定的节点及其祖先中查找匹配名称的Timeline（可以是Scroll Timeline, View Timeline 或 Deferred Timeline）。
*   **`FindAncestorTimeline`**:  递归地在元素的祖先元素中查找具有给定名称的Timeline。
*   **`FindDeferredTimeline`**:  专门查找祖先元素中的 Deferred Timeline。

**5. 与CSS功能的关系举例:**

*   **`scroll-timeline`**:  `CalculateScrollTimelineUpdate` 和 `CalculateChangedScrollTimelines` 的主要功能就是处理 `scroll-timeline` CSS属性。
    *   **假设输入**: CSS 样式为 `.animated { animation-timeline: my-scroll-timeline; scroll-timeline: my-scroll-timeline; scroll-timeline-axis: y; }`。
    *   **逻辑推理**: `CalculateChangedScrollTimelines` 会解析 `scroll-timeline: my-scroll-timeline` 和 `scroll-timeline-axis: y`，创建一个名为 "my-scroll-timeline" 且监听垂直滚动的 `ScrollTimeline` 对象。
*   **`view-timeline`**: `CalculateViewTimelineUpdate` 和 `CalculateChangedViewTimelines` 处理 `view-timeline` 相关的 CSS 属性。
    *   **假设输入**: CSS 样式为 `.animated { animation-timeline: my-view-timeline; view-timeline: my-view-timeline; view-timeline-axis: block; }`。
    *   **逻辑推理**: `CalculateChangedViewTimelines` 会解析 `view-timeline: my-view-timeline` 和 `view-timeline-axis: block`，创建一个名为 "my-view-timeline" 且监听块轴的 `ViewTimeline` 对象。
*   **`timeline-scope`**: `CalculateDeferredTimelineUpdate` 和 `CalculateChangedDeferredTimelines` 处理 `timeline-scope` CSS属性。
    *   **假设输入**: CSS 样式为 `.container { timeline-scope: my-deferred-timeline; } .animated { animation-timeline: my-deferred-timeline; }`。
    *   **逻辑推理**: `CalculateChangedDeferredTimelines` 会在 `.container` 元素上创建一个名为 "my-deferred-timeline" 的 `DeferredTimeline` 对象。当处理 `.animated` 元素的动画时，`FindAncestorTimeline` 会找到这个 Deferred Timeline。

**6. 与JavaScript功能的关系举例:**

虽然这段代码是C++，但它直接支持了通过JavaScript Web Animations API 创建基于CSS定义的Timeline的动画。

*   **假设输入**: JavaScript 代码 `element.animate({ opacity: [0, 1] }, { timeline: CSS.timeline('my-scroll-timeline') });`，且CSS中定义了 `scroll-timeline: my-scroll-timeline;`。
*   **逻辑推理**: Blink引擎会解析CSS中的 `scroll-timeline` 定义，创建相应的 `ScrollTimeline` 对象。当JavaScript代码尝试使用名为 "my-scroll-timeline" 的Timeline时，引擎会找到之前创建的 `ScrollTimeline` 对象，并将其用于驱动动画。

**7. 用户或编程常见的使用错误举例:**

*   **命名冲突**:  在CSS中定义了多个同名的Timeline，可能导致动画绑定到错误的Timeline上。
    *   **假设错误输入**:
        ```css
        .container1 { scroll-timeline: my-timeline; }
        .container2 { view-timeline: my-timeline; }
        .animated { animation-timeline: my-timeline; }
        ```
    *   **可能结果**:  `animation-timeline: my-timeline;` 可能会错误地绑定到 `scroll-timeline` 或 `view-timeline` 中的一个，导致非预期的动画效果。Blink引擎的逻辑会尝试找到最近的匹配项，但这可能不是用户想要的。
*   **Timeline未定义**: 在JavaScript中使用了未在CSS中定义的Timeline名称。
    *   **假设错误输入**:  JavaScript 代码 `element.animate({ opacity: [0, 1] }, { timeline: CSS.timeline('non-existent-timeline') });`，但CSS中没有定义名为 "non-existent-timeline" 的Timeline。
    *   **可能结果**: 动画可能无法正常工作，或者会回退到文档的默认Timeline。

**8. 总结 (针对第2部分):**

这部分代码专注于 **CSS动画Timeline的生命周期管理**，特别是 **Timeline的创建、更新和查找**。它解析CSS样式中的Timeline定义，并根据样式变化计算出需要对Timeline进行的变更。这种精细化的管理使得浏览器能够高效地处理各种基于CSS Timeline的动画，并确保动画能够正确地绑定到其指定的时间轴上。这部分是整个CSS动画机制中至关重要的一环，它连接了CSS样式定义和底层的动画执行。

Prompt: 
```
这是目录为blink/renderer/core/animation/css/css_animations.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
      : (*insets)[std::min(index_, insets->size() - 1)];

      return std::make_tuple(name, axis, inset);
    }

    void operator++() { index_ = timelines_.SkipPastNullptr(index_ + 1); }

    bool operator==(const Iterator& o) const { return index_ == o.index_; }
    bool operator!=(const Iterator& o) const { return index_ != o.index_; }

   private:
    wtf_size_t index_;
    const SpecifiedTimelines& timelines_;
  };

  Iterator begin() const { return Iterator(SkipPastNullptr(0), *this); }

  Iterator end() const { return Iterator(Size(), *this); }

 private:
  wtf_size_t Size() const { return names_ ? names_->size() : 0; }

  wtf_size_t SkipPastNullptr(wtf_size_t start) const {
    wtf_size_t size = Size();
    wtf_size_t index = start;
    DCHECK_LE(index, size);
    while (index < size && !(*names_)[index]) {
      ++index;
    }
    return index;
  }

  const HeapVector<Member<const ScopedCSSName>>* names_;
  const Vector<TimelineAxis>& axes_;
  const Vector<TimelineInset>* insets_;
};

class SpecifiedScrollTimelines : public SpecifiedTimelines {
  STACK_ALLOCATED();

 public:
  explicit SpecifiedScrollTimelines(const ComputedStyleBuilder& style_builder)
      : SpecifiedTimelines(style_builder.ScrollTimelineName(),
                           style_builder.ScrollTimelineAxis(),
                           /* insets */ nullptr) {}
};

class SpecifiedViewTimelines : public SpecifiedTimelines {
  STACK_ALLOCATED();

 public:
  explicit SpecifiedViewTimelines(const ComputedStyleBuilder& style_builder)
      : SpecifiedTimelines(style_builder.ViewTimelineName(),
                           style_builder.ViewTimelineAxis(),
                           &style_builder.ViewTimelineInset()) {}
};

// Invokes `callback` for each timeline we would end up with had
// `changed_timelines` been applied to `existing_timelines`.
template <typename TimelineType, typename CallbackFunc>
void ForEachTimeline(const CSSTimelineMap<TimelineType>* existing_timelines,
                     const CSSTimelineMap<TimelineType>* changed_timelines,
                     CallbackFunc callback) {
  // First, search through existing named timelines.
  if (existing_timelines) {
    for (auto [name, value] : *existing_timelines) {
      // Skip timelines that are changed; they will be handled by the next
      // for-loop.
      if (changed_timelines && changed_timelines->Contains(name)) {
        continue;
      }
      callback(*name, value.Get());
    }
  }

  // Search through timelines created or modified this CSSAnimationUpdate.
  if (changed_timelines) {
    for (auto [name, value] : *changed_timelines) {
      if (!value) {
        // A value of nullptr means that a currently existing timeline
        // was removed.
        continue;
      }
      callback(*name, value.Get());
    }
  }
}

// When calculating timeline updates, we initially assume that all timelines
// are going to be removed, and then erase the nullptr entries for timelines
// where we discover that this doesn't apply.
template <typename MapType>
MapType NullifyExistingTimelines(const MapType* existing_timelines) {
  MapType map;
  if (existing_timelines) {
    for (const auto& key : existing_timelines->Keys()) {
      map.Set(key, nullptr);
    }
  }
  return map;
}

template <typename TimelineType>
TimelineType* GetTimeline(const CSSTimelineMap<TimelineType>* timelines,
                          const ScopedCSSName& name) {
  if (!timelines) {
    return nullptr;
  }
  auto i = timelines->find(&name);
  return i != timelines->end() ? i->value.Get() : nullptr;
}

DeferredTimeline* GetTimelineAttachment(
    const TimelineAttachmentMap* timeline_attachments,
    ScrollSnapshotTimeline* timeline) {
  if (!timeline_attachments) {
    return nullptr;
  }
  auto i = timeline_attachments->find(timeline);
  return i != timeline_attachments->end() ? i->value.Get() : nullptr;
}

Element* ParentElementForTimelineTraversal(Node& node) {
  return RuntimeEnabledFeatures::CSSTreeScopedTimelinesEnabled()
             ? node.ParentOrShadowHostElement()
             : LayoutTreeBuilderTraversal::ParentElement(node);
}

Element* ResolveReferenceElement(Document& document,
                                 TimelineScroller scroller,
                                 Element* reference_element) {
  switch (scroller) {
    case TimelineScroller::kNearest:
    case TimelineScroller::kSelf:
      return reference_element;
    case TimelineScroller::kRoot:
      return document.ScrollingElementNoLayout();
  }
}

ScrollTimeline::ReferenceType ComputeReferenceType(TimelineScroller scroller) {
  switch (scroller) {
    case TimelineScroller::kNearest:
      return ScrollTimeline::ReferenceType::kNearestAncestor;
    case TimelineScroller::kRoot:
    case TimelineScroller::kSelf:
      return ScrollTimeline::ReferenceType::kSource;
  }
}

ScrollTimeline::ScrollAxis ComputeAxis(TimelineAxis axis) {
  switch (axis) {
    case TimelineAxis::kBlock:
      return ScrollTimeline::ScrollAxis::kBlock;
    case TimelineAxis::kInline:
      return ScrollTimeline::ScrollAxis::kInline;
    case TimelineAxis::kX:
      return ScrollTimeline::ScrollAxis::kX;
    case TimelineAxis::kY:
      return ScrollTimeline::ScrollAxis::kY;
  }

  NOTREACHED();
}

// The CSSScrollTimelineOptions and CSSViewTimelineOptions structs exist
// in order to avoid creating a new Scroll/ViewTimeline when doing so
// would anyway result in exactly the same Scroll/ViewTimeline that we
// already have. (See TimelineMatches functions).

struct CSSScrollTimelineOptions {
  STACK_ALLOCATED();

 public:
  CSSScrollTimelineOptions(Document& document,
                           TimelineScroller scroller,
                           Element* reference_element,
                           TimelineAxis axis)
      : reference_type(ComputeReferenceType(scroller)),
        reference_element(
            ResolveReferenceElement(document, scroller, reference_element)),
        axis(ComputeAxis(axis)) {}

  ScrollTimeline::ReferenceType reference_type;
  Element* reference_element;
  ScrollTimeline::ScrollAxis axis;
};

struct CSSViewTimelineOptions {
  STACK_ALLOCATED();

 public:
  CSSViewTimelineOptions(Element* subject,
                         TimelineAxis axis,
                         TimelineInset inset)
      : subject(subject), axis(ComputeAxis(axis)), inset(inset) {}

  Element* subject;
  ScrollTimeline::ScrollAxis axis;
  TimelineInset inset;
};

bool TimelineMatches(const ScrollTimeline& timeline,
                     const CSSScrollTimelineOptions& options) {
  return timeline.Matches(options.reference_type, options.reference_element,
                          options.axis);
}

bool TimelineMatches(const ViewTimeline& timeline,
                     const CSSViewTimelineOptions& options) {
  return timeline.Matches(options.subject, options.axis, options.inset);
}

Vector<const CSSProperty*> PropertiesForTransitionAll(
    bool with_discrete,
    const ExecutionContext* execution_context) {
  Vector<const CSSProperty*> properties;
  for (CSSPropertyID id : CSSPropertyIDList()) {
    // Avoid creating overlapping transitions with perspective-origin and
    // transition-origin.
    // transition:all shouldn't expand to itself
    if (id == CSSPropertyID::kWebkitPerspectiveOriginX ||
        id == CSSPropertyID::kWebkitPerspectiveOriginY ||
        id == CSSPropertyID::kWebkitTransformOriginX ||
        id == CSSPropertyID::kWebkitTransformOriginY ||
        id == CSSPropertyID::kWebkitTransformOriginZ ||
        id == CSSPropertyID::kAll) {
      continue;
    }
    const CSSProperty& property = CSSProperty::Get(id);
    if (!with_discrete && !property.IsInterpolable()) {
      continue;
    }
    if (CSSAnimations::IsAnimationAffectingProperty(property) ||
        property.IsShorthand()) {
      DCHECK(with_discrete);
      continue;
    }
    if (!property.IsWebExposed(execution_context)) {
      continue;
    }

    properties.push_back(&property);
  }
  return properties;
}

const StylePropertyShorthand& PropertiesForTransitionAllDiscrete(
    const ExecutionContext* execution_context) {
  DEFINE_STATIC_LOCAL(Vector<const CSSProperty*>, properties,
                      (PropertiesForTransitionAll(true, execution_context)));
  DEFINE_STATIC_LOCAL(StylePropertyShorthand, property_shorthand,
                      (CSSPropertyID::kInvalid, properties));
  return property_shorthand;
}

const StylePropertyShorthand& PropertiesForTransitionAllNormal(
    const ExecutionContext* execution_context) {
  DEFINE_STATIC_LOCAL(Vector<const CSSProperty*>, properties,
                      (PropertiesForTransitionAll(false, execution_context)));
  DEFINE_STATIC_LOCAL(StylePropertyShorthand, property_shorthand,
                      (CSSPropertyID::kInvalid, properties));
  return property_shorthand;
}

}  // namespace

void CSSAnimations::CalculateScrollTimelineUpdate(
    CSSAnimationUpdate& update,
    Element& animating_element,
    const ComputedStyleBuilder& style_builder) {
  const CSSAnimations::TimelineData* timeline_data =
      GetTimelineData(animating_element);
  const CSSScrollTimelineMap* existing_scroll_timelines =
      (timeline_data && !timeline_data->GetScrollTimelines().empty())
          ? &timeline_data->GetScrollTimelines()
          : nullptr;
  if (style_builder.ScrollTimelineName() || existing_scroll_timelines) {
    update.SetChangedScrollTimelines(CalculateChangedScrollTimelines(
        animating_element, existing_scroll_timelines, style_builder));
  }
}

void CSSAnimations::CalculateViewTimelineUpdate(
    CSSAnimationUpdate& update,
    Element& animating_element,
    const ComputedStyleBuilder& style_builder) {
  const CSSAnimations::TimelineData* timeline_data =
      GetTimelineData(animating_element);
  const CSSViewTimelineMap* existing_view_timelines =
      (timeline_data && !timeline_data->GetViewTimelines().empty())
          ? &timeline_data->GetViewTimelines()
          : nullptr;
  if (style_builder.ViewTimelineName() || existing_view_timelines) {
    update.SetChangedViewTimelines(CalculateChangedViewTimelines(
        animating_element, existing_view_timelines, style_builder));
  }
}

void CSSAnimations::CalculateDeferredTimelineUpdate(
    CSSAnimationUpdate& update,
    Element& animating_element,
    const ComputedStyleBuilder& style_builder) {
  const CSSAnimations::TimelineData* timeline_data =
      GetTimelineData(animating_element);
  const CSSDeferredTimelineMap* existing_deferred_timelines =
      (timeline_data && !timeline_data->GetDeferredTimelines().empty())
          ? &timeline_data->GetDeferredTimelines()
          : nullptr;
  if (style_builder.TimelineScope() || existing_deferred_timelines) {
    update.SetChangedDeferredTimelines(CalculateChangedDeferredTimelines(
        animating_element, existing_deferred_timelines, style_builder));
  }
}

CSSScrollTimelineMap CSSAnimations::CalculateChangedScrollTimelines(
    Element& animating_element,
    const CSSScrollTimelineMap* existing_scroll_timelines,
    const ComputedStyleBuilder& style_builder) {
  CSSScrollTimelineMap changed_timelines =
      NullifyExistingTimelines(existing_scroll_timelines);

  Document& document = animating_element.GetDocument();

  for (auto [name, axis, inset] : SpecifiedScrollTimelines(style_builder)) {
    // Note: ScrollTimeline does not use insets.
    ScrollTimeline* existing_timeline =
        GetTimeline(existing_scroll_timelines, *name);
    CSSScrollTimelineOptions options(document, TimelineScroller::kSelf,
                                     &animating_element, axis);
    if (existing_timeline && TimelineMatches(*existing_timeline, options)) {
      changed_timelines.erase(name);
      continue;
    }
    ScrollTimeline* new_timeline = MakeGarbageCollected<ScrollTimeline>(
        &document, options.reference_type, options.reference_element,
        options.axis);
    new_timeline->ServiceAnimations(kTimingUpdateOnDemand);
    changed_timelines.Set(name, new_timeline);
  }

  return changed_timelines;
}

CSSViewTimelineMap CSSAnimations::CalculateChangedViewTimelines(
    Element& animating_element,
    const CSSViewTimelineMap* existing_view_timelines,
    const ComputedStyleBuilder& style_builder) {
  CSSViewTimelineMap changed_timelines =
      NullifyExistingTimelines(existing_view_timelines);

  for (auto [name, axis, inset] : SpecifiedViewTimelines(style_builder)) {
    ViewTimeline* existing_timeline =
        GetTimeline(existing_view_timelines, *name);
    CSSViewTimelineOptions options(&animating_element, axis, inset);
    if (existing_timeline && TimelineMatches(*existing_timeline, options)) {
      changed_timelines.erase(name);
      continue;
    }
    ViewTimeline* new_timeline = MakeGarbageCollected<ViewTimeline>(
        &animating_element.GetDocument(), options.subject, options.axis,
        options.inset);
    new_timeline->ServiceAnimations(kTimingUpdateOnDemand);
    changed_timelines.Set(name, new_timeline);
  }

  return changed_timelines;
}

CSSDeferredTimelineMap CSSAnimations::CalculateChangedDeferredTimelines(
    Element& animating_element,
    const CSSDeferredTimelineMap* existing_deferred_timelines,
    const ComputedStyleBuilder& style_builder) {
  CSSDeferredTimelineMap changed_timelines =
      NullifyExistingTimelines(existing_deferred_timelines);

  if (const ScopedCSSNameList* name_list = style_builder.TimelineScope()) {
    for (const Member<const ScopedCSSName>& name : name_list->GetNames()) {
      if (GetTimeline(existing_deferred_timelines, *name)) {
        changed_timelines.erase(name);
        continue;
      }
      DeferredTimeline* new_timeline = MakeGarbageCollected<DeferredTimeline>(
          &animating_element.GetDocument());
      new_timeline->ServiceAnimations(kTimingUpdateOnDemand);
      changed_timelines.Set(name, new_timeline);
    }
  }

  return changed_timelines;
}

template <>
const CSSScrollTimelineMap*
CSSAnimations::GetExistingTimelines<CSSScrollTimelineMap>(
    const TimelineData* data) {
  return data ? &data->GetScrollTimelines() : nullptr;
}

template <>
const CSSScrollTimelineMap*
CSSAnimations::GetChangedTimelines<CSSScrollTimelineMap>(
    const CSSAnimationUpdate* update) {
  return update ? &update->ChangedScrollTimelines() : nullptr;
}

template <>
const CSSViewTimelineMap*
CSSAnimations::GetExistingTimelines<CSSViewTimelineMap>(
    const TimelineData* data) {
  return data ? &data->GetViewTimelines() : nullptr;
}

template <>
const CSSViewTimelineMap*
CSSAnimations::GetChangedTimelines<CSSViewTimelineMap>(
    const CSSAnimationUpdate* update) {
  return update ? &update->ChangedViewTimelines() : nullptr;
}

template <>
const CSSDeferredTimelineMap*
CSSAnimations::GetExistingTimelines<CSSDeferredTimelineMap>(
    const TimelineData* data) {
  return data ? &data->GetDeferredTimelines() : nullptr;
}

template <>
const CSSDeferredTimelineMap*
CSSAnimations::GetChangedTimelines<CSSDeferredTimelineMap>(
    const CSSAnimationUpdate* update) {
  return update ? &update->ChangedDeferredTimelines() : nullptr;
}

template <typename TimelineType, typename CallbackFunc>
void CSSAnimations::ForEachTimeline(const TimelineData* timeline_data,
                                    const CSSAnimationUpdate* update,
                                    CallbackFunc callback) {
  blink::ForEachTimeline<TimelineType, CallbackFunc>(
      GetExistingTimelines<CSSTimelineMap<TimelineType>>(timeline_data),
      GetChangedTimelines<CSSTimelineMap<TimelineType>>(update), callback);
}

template <typename TimelineType>
void CSSAnimations::CalculateChangedTimelineAttachments(
    Element& animating_element,
    const TimelineData* timeline_data,
    const CSSAnimationUpdate& update,
    const TimelineAttachmentMap* existing_attachments,
    TimelineAttachmentMap& result) {
  ForEachTimeline<TimelineType>(
      timeline_data, &update,
      [&animating_element, &update, &existing_attachments, &result](
          const ScopedCSSName& name, TimelineType* attaching_timeline) {
        DeferredTimeline* new_deferred_timeline =
            FindDeferredTimeline(name, &animating_element, &update);
        DeferredTimeline* existing_deferred_timeline =
            GetTimelineAttachment(existing_attachments, attaching_timeline);
        if (existing_deferred_timeline == new_deferred_timeline) {
          // No change, remove explicit nullptr previously added by
          // CalculateTimelineAttachmentUpdate.
          result.erase(attaching_timeline);
        } else {
          result.Set(attaching_timeline, new_deferred_timeline);
        }
      });
}

void CSSAnimations::CalculateTimelineAttachmentUpdate(
    CSSAnimationUpdate& update,
    Element& animating_element) {
  const CSSAnimations::TimelineData* timeline_data =
      GetTimelineData(animating_element);

  if (update.ChangedScrollTimelines().empty() &&
      update.ChangedViewTimelines().empty() &&
      (!timeline_data || timeline_data->IsEmpty())) {
    return;
  }

  // We initially assume that all existing timeline attachments will be removed.
  // This is represented by  populating the TimelineAttachmentMap with explicit
  // nullptr values for each existing attachment.
  const TimelineAttachmentMap* existing_attachments =
      timeline_data ? &timeline_data->GetTimelineAttachments() : nullptr;
  TimelineAttachmentMap changed_attachments =
      NullifyExistingTimelines(existing_attachments);

  // Then, for each Scroll/ViewTimeline, we find the corresponding attachment
  // (i.e. DeferredTimeline), and either erase the explicit nullptr from
  // `changed_attachments` if it matched the existing timeline, or just add it
  // otherwise.
  CalculateChangedTimelineAttachments<ScrollTimeline>(
      animating_element, timeline_data, update, existing_attachments,
      changed_attachments);
  CalculateChangedTimelineAttachments<ViewTimeline>(
      animating_element, timeline_data, update, existing_attachments,
      changed_attachments);

  update.SetChangedTimelineAttachments(std::move(changed_attachments));
}

const CSSAnimations::TimelineData* CSSAnimations::GetTimelineData(
    const Element& element) {
  const ElementAnimations* element_animations = element.GetElementAnimations();
  return element_animations
             ? &element_animations->CssAnimations().timeline_data_
             : nullptr;
}

namespace {

// Assuming that `inner` is an inclusive descendant of `outer`, returns
// the distance (in the number of TreeScopes) between `inner` and `outer`.
//
// Returns std::numeric_limits::max() if `inner` is not an inclusive
// descendant of `outer`.
size_t TreeScopeDistance(const TreeScope* outer, const TreeScope* inner) {
  size_t distance = 0;

  const TreeScope* current = inner;

  do {
    if (current == outer) {
      return distance;
    }
    ++distance;
  } while (current && (current = current->ParentTreeScope()));

  return std::numeric_limits<size_t>::max();
}

// Update the matching timeline if the candidate is a more proximate match
// than the existing match.
template <typename TimelineType>
void UpdateMatchingTimeline(const ScopedCSSName& target_name,
                            const ScopedCSSName& candidate_name,
                            TimelineType* candidate,
                            TimelineType*& matching_timeline,
                            size_t& matching_distance) {
  if (target_name.GetName() != candidate_name.GetName()) {
    return;
  }
  if (RuntimeEnabledFeatures::CSSTreeScopedTimelinesEnabled()) {
    size_t distance = TreeScopeDistance(candidate_name.GetTreeScope(),
                                        target_name.GetTreeScope());
    if (distance < matching_distance) {
      matching_timeline = candidate;
      matching_distance = distance;
    }
  } else {
    matching_timeline = candidate;
  }
}

}  // namespace

ScrollSnapshotTimeline* CSSAnimations::FindTimelineForNode(
    const ScopedCSSName& name,
    Node* node,
    const CSSAnimationUpdate* update) {
  Element* element = DynamicTo<Element>(node);
  if (!element)
    return nullptr;
  const TimelineData* timeline_data = GetTimelineData(*element);
  if (ScrollTimeline* timeline =
          FindTimelineForElement<ScrollTimeline>(name, timeline_data, update)) {
    return timeline;
  }
  if (ViewTimeline* timeline =
          FindTimelineForElement<ViewTimeline>(name, timeline_data, update)) {
    return timeline;
  }
  return FindTimelineForElement<DeferredTimeline>(name, timeline_data, update);
}

template <typename TimelineType>
TimelineType* CSSAnimations::FindTimelineForElement(
    const ScopedCSSName& target_name,
    const TimelineData* timeline_data,
    const CSSAnimationUpdate* update) {
  TimelineType* matching_timeline = nullptr;
  size_t matching_distance = std::numeric_limits<size_t>::max();

  ForEachTimeline<TimelineType>(
      timeline_data, update,
      [&target_name, &matching_timeline, &matching_distance](
          const ScopedCSSName& name, TimelineType* candidate_timeline) {
        UpdateMatchingTimeline(target_name, name, candidate_timeline,
                               matching_timeline, matching_distance);
      });

  return matching_timeline;
}

// Find a ScrollSnapshotTimeline in inclusive ancestors.
//
// The reason `update` is provided from the outside rather than just fetching
// it from ElementAnimations, is that for the current node we're resolving style
// for, the update hasn't actually been stored on ElementAnimations yet.
ScrollSnapshotTimeline* CSSAnimations::FindAncestorTimeline(
    const ScopedCSSName& name,
    Node* node,
    const CSSAnimationUpdate* update) {
  DCHECK(node);

  if (ScrollSnapshotTimeline* timeline =
          FindTimelineForNode(name, node, update)) {
    return timeline;
  }

  Element* parent_element = ParentElementForTimelineTraversal(*node);
  if (!parent_element) {
    return nullptr;
  }
  return FindAncestorTimeline(name, parent_element,
                              GetPendingAnimationUpdate(*parent_element));
}

// Like FindAncestorTimeline, but only looks for DeferredTimelines.
// This is used to attach Scroll/ViewTimelines to any matching DeferredTimelines
// in the ancestor chain.
DeferredTimeline* CSSAnimations::FindDeferredTimeline(
    const ScopedCSSName& name,
    Element* element,
    const CSSAnimationUpdate* update) {
  DCHECK(element);
  const TimelineData* timeline_data = GetTimelineData(*element);
  if (DeferredTimeline* timeline = FindTimelineForElement<DeferredTimeline>(
          name, timeline_data, update)) {
    return timeline;
  }
  Element* parent_element = ParentElementForTimelineTraversal(*element);
  if (!parent_element) {
    return nullptr;
  }
  return FindDeferredTimeline(name, parent_element,
                              GetPendingAnimationUpdate(*parent_element));
}

namespace {

ScrollTimeline* ComputeScrollFunctionTimeline(
    Element* element,
    const StyleTimeline::ScrollData& scroll_data,
    AnimationTimeline* existing_timeline) {
  Document& document = element->GetDocument();
  UseCounter::Count(element->GetDocument(),
                    WebFeature::kScrollFunctionTimeline);
  CSSScrollTimelineOptions options(document, scroll_data.GetScroller(),
                                   /* reference_element */ element,
                                   scroll_data.GetAxis());
  if (auto* scroll_timeline = DynamicTo<ScrollTimeline>(existing_timeline);
      scroll_timeline && TimelineMatches(*scroll_timeline, options)) {
    return scroll_timeline;
  }
  // TODO(crbug.com/1356482): Cache/re-use timelines created from scroll().
  return MakeGarbageCollected<ScrollTimeline>(&document, options.reference_type,
                                              options.reference_element,
                                              options.axis);
}

AnimationTimeline* ComputeViewFunctionTimeline(
    Element* element,
    const StyleTimeline::ViewData& view_data,
    AnimationTimeline* existing_timeline) {
  UseCounter::Count(element->GetDocument(), WebFeature::kViewFunctionTimeline);
  TimelineAxis axis = view_data.GetAxis();
  const TimelineInset& inset = view_data.GetInset();
  CSSViewTimelineOptions options(element, axis, inset);

  if (auto* view_timeline = DynamicTo<ViewTimeline>(existing_timeline);
      view_timeline && TimelineMatches(*view_timeline, options)) {
    return view_timeline;
  }

  ViewTimeline* new_timeline = MakeGarbageCollected<ViewTimeline>(
      &element->GetDocument(), options.subject, options.axis, options.inset);
  return new_timeline;
}

}  // namespace

AnimationTimeline* CSSAnimations::ComputeTimeline(
    Element* element,
    const StyleTimeline& style_timeline,
    const CSSAnimationUpdate& update,
    AnimationTimeline* existing_timeline) {
  Document& document = element->GetDocument();
  if (style_timeline.IsKeyword()) {
    if (style_timeline.GetKeyword() == CSSValueID::kAuto)
      return &document.Timeline();
    DCHECK_EQ(style_timeline.GetKeyword(), CSSValueID::kNone);
    return nullptr;
  }
  if (style_timeline.IsName()) {
    return FindAncestorTimeline(style_timeline.GetName(), element, &update);
  }
  if (style_timeline.IsView()) {
    return ComputeViewFunctionTimeline(element, style_timeline.GetView(),
                                       existing_timeline);
  }
  DCHECK(style_timeline.IsScroll());
  return ComputeScrollFunctionTimeline(element, style_timeline.GetScroll(),
                                       existing_timeline);
}

CSSAnimations::CSSAnimations() = default;

namespace {

const KeyframeEffectModelBase* GetKeyframeEffectModelBase(
    const AnimationEffect* effect) {
  if (!effect)
    return nullptr;
  const EffectModel* model = nullptr;
  if (auto* keyframe_effect = DynamicTo<KeyframeEffect>(effect))
    model = keyframe_effect->Model();
  else if (auto* inert_effect = DynamicTo<InertEffect>(effect))
    model = inert_effect->Model();
  if (!model || !model->IsKeyframeEffectModel())
    return nullptr;
  return To<KeyframeEffectModelBase>(model);
}

bool ComputedValuesEqual(const PropertyHandle& property,
                         const ComputedStyle& a,
                         const ComputedStyle& b) {
  // If zoom hasn't changed, compare internal values (stored with zoom applied)
  // for speed. Custom properties are never zoomed so they are checked here too.
  if (a.EffectiveZoom() == b.EffectiveZoom() ||
      property.IsCSSCustomProperty()) {
    return CSSPropertyEquality::PropertiesEqual(property, a, b);
  }

  // If zoom has changed, we must construct and compare the unzoomed
  // computed values.
  if (property.GetCSSProperty().PropertyID() == CSSPropertyID::kTransform) {
    // Transform lists require special handling in this case to deal with
    // layout-dependent interpolation which does not yet have a CSSValue.
    return a.Transform().Zoom(1 / a.EffectiveZoom()) ==
           b.Transform().Zoom(1 / b.EffectiveZoom());
  } else {
    const CSSValue* a_val =
        ComputedStyleUtils::ComputedPropertyValue(property.GetCSSProperty(), a);
    const CSSValue* b_val =
        ComputedStyleUtils::ComputedPropertyValue(property.GetCSSProperty(), b);
    // Computed values can be null if not able to parse.
    if (a_val && b_val)
      return *a_val == *b_val;
    // Fallback to the zoom-unaware comparator if either value could not be
    // parsed.
    return CSSPropertyEquality::PropertiesEqual(property, a, b);
  }
}

}  // namespace

void CSSAnimations::CalculateCompositorAnimationUpdate(
    CSSAnimationUpdate& update,
    const Element& animating_element,
    Element& element,
    const ComputedStyle& style,
    const ComputedStyle* parent_style,
    bool was_viewport_resized,
    bool force_update) {
  ElementAnimations* element_animations =
      animating_element.GetElementAnimations();

  // If the change in style is only due to the Blink-side animation update, we
  // do not need to update the compositor-side animations. The compositor is
  // already changing the same properties and as such this update would provide
  // no new information.
  if (!element_animations || element_animations->IsAnimationStyleChange())
    return;

  const ComputedStyle* old_style = animating_element.GetComputedStyle();
  if (!old_style || old_style->IsEnsuredInDisplayNone() ||
      (!old_style->HasCurrentCompositableAnimation() &&
       !element_animations->HasCompositedPaintWorkletAnimation())) {
    return;
  }

  bool transform_zoom_changed =
      (old_style->HasCurrentTranslateAnimation() ||
       old_style->HasCurrentTransformAnimation()) &&
      old_style->EffectiveZoom() != style.EffectiveZoom();

  const auto& snapshot = [&](AnimationEffect* effect) {
    const KeyframeEffectModelBase* keyframe_effect =
        GetKeyframeEffectModelBase(effect);
    if (!keyframe_effect)
      return false;

    if (force_update ||
        ((transform_zoom_changed || was_viewport_resized) &&
         (keyframe_effect->Affects(PropertyHandle(GetCSSPropertyTransform())) ||
          keyframe_effect->Affects(PropertyHandle(GetCSSPropertyTranslate())))))
      keyframe_effect->InvalidateCompositorKeyframesSnapshot();

    if (keyframe_effect->SnapshotAllCompositorKeyframesIfNecessary(
            element, style, parent_style)) {
      return true;
    } else if (keyframe_effect->HasSyntheticKeyframes() &&
               keyframe_effect->SnapshotNeutralCompositorKeyframes(
                   element, *old_style, style, parent_style)) {
      return true;
    }
    return false;
  };

  for (auto& entry : element_animations->Animations()) {
    Animation& animation = *entry.key;
    if (snapshot(animation.effect())) {
      update.UpdateCompositorKeyframes(&animation);
    } else if (NativePaintImageGenerator::
                   NativePaintWorkletAnimationsEnabled()) {
      element_animations->RecalcCompositedStatusForKeyframeChange(
          element, animation.effect());
    }
  }

  for (auto& entry : element_animations->GetWorkletAnimations()) {
    WorkletAnimationBase& animation = *entry;
    if (snapshot(animation.GetEffect()))
      animation.InvalidateCompositingState();
  }
}

void CSSAnimations::CalculateTimelineUpdate(
    CSSAnimationUpdate& update,
    Element& animating_element,
    const ComputedStyleBuilder& style_builder) {
  CalculateScrollTimelineUpdate(update, animating_element, style_builder);
  CalculateViewTimelineUpdate(update, animating_element, style_builder);
  CalculateDeferredTimelineUpdate(update, animating_element, style_builder);
  CalculateTimelineAttachmentUpdate(update, animating_element);
}

void CSSAnimations::CalculateAnimationUpdate(
    CSSAnimationUpdate& update,
    Element& animating_element,
    Element& element,
    const ComputedStyleBuilder& style_builder,
    const ComputedStyle* parent_style,
    StyleResolver* resolver,
    bool can_trigger_animations) {
  ElementAnimations* element_animations =
      animating_element.GetElementAnimations();

  bool is_animation_style_change =
      !can_trigger_animations ||
      (element_animations && element_animations->IsAnimationStyleChange());

#if !DCHECK_IS_ON()
  // If we're in an animation style change, no animations can have started, been
  // cancelled or changed play state. When DCHECK is enabled, we verify this
  // optimization.
  if (is_animation_style_change) {
    CalculateAnimationActiveInterpolations(update, animating_element);
    return;
  }
#endif

  const WritingDirectionMode writing_direction =
      style_builder.GetWritingDirection();

  // Rebuild the keyframe model for a CSS animation if it may have been
  // invalidated by a change to the text direction or writing mode.
  const ComputedStyle* old_style = animating_element.GetComputedStyle();
  bool logical_property_mapping_change =
      !old_style || old_style->GetWritingDirection() != writing_direction;

  if (logical_property_mapping_change && element_animations) {
    // Update computed keyframes for any running animations that depend on
    // logical properties.
    for (auto& entry : element_animations->Animations()) {
      Animation* animation = entry.key;
      if (auto* keyframe_effect =
              DynamicTo<KeyframeEffect>(animation->effect())) {
        keyframe_effect->SetLogicalPropertyResolutionContext(writing_direction);
        animation->UpdateIfNecessary();
      }
    }
  }

  const CSSAnimationData* animation_data = style_builder.Animations();
  const CSSAnimations* css_animations =
      element_animations ? &element_animations->CssAnimations() : nullptr;

  Vector<bool> cancel_running_animation_flags(
      css_animations ? css_animations->running_animations_.size() : 0);
  for (bool& flag : cancel_running_animation_flags)
    flag = true;

  if (anima
"""


```