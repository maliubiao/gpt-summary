Response:
The user wants to understand the functionality of the provided C++ source code file `content_capture_test.cc`. The request asks for several things:

1. **List of functionalities:** A summary of what the code does.
2. **Relationship to web technologies:** How it relates to JavaScript, HTML, and CSS.
3. **Logic with input/output:** Examples of logical reasoning within the code.
4. **Common usage errors:** Examples of mistakes developers might make when using this code.
5. **User journey to this code:** Steps a user might take that would trigger this code.
6. **Concise summary:** A brief overview of the file's purpose.

Based on the file content, I can deduce the following:

* **Testing framework:** The file uses Google Test (`TEST_P`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT`) and the `SimTest` framework from Chromium. This strongly indicates it's a test file.
* **Content Capture:**  The file imports classes like `ContentCaptureManager`, `ContentCaptureTask`, `WebContentHolder`, and `WebContentCaptureClient`. These names suggest the file is testing the "Content Capture" feature within Blink.
* **Simulating web page behavior:** It sets up a basic HTML structure (`SetHtmlInnerHTML`), interacts with DOM nodes, and simulates scrolling.
* **Mocking and Verification:** It uses a `WebContentCaptureClientTestHelper` to intercept and verify data passed from the Content Capture system.
* **Testing different scenarios:** The tests cover basic capture, scrolling, pausing/resuming, node removal, and histogram reporting.
* **Feature flags:** The use of `base::test::ScopedFeatureList` and `features::kContentCaptureConstantStreaming` indicates that the tests might run with different configurations of the Content Capture feature.

Now I can structure the answer to address each of the user's requests.
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/content_capture/content_capture_manager.h"

#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/web/web_content_capture_client.h"
#include "third_party/blink/public/web/web_content_holder.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html_element_type_helpers.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"

namespace blink {

namespace {

gfx::Rect GetRect(LayoutObject* layout_object) {
  return ToEnclosingRect(VisualRectInDocument(*layout_object));
}

void FindNodeVectorsDiff(const Vector<Persistent<Node>>& a,
                         const Vector<Persistent<Node>>& b,
                         Vector<Persistent<Node>>& a_diff_b) {
  for (auto& i : a) {
    if (!b.Contains(i))
      a_diff_b.push_back(i);
  }
}

void FindNodeVectorsDiff(const Vector<Persistent<Node>>& a,
                         const Vector<Persistent<Node>>& b,
                         Vector<Persistent<Node>>& a_diff_b,
                         Vector<Persistent<Node>>& b_diff_a) {
  FindNodeVectorsDiff(a, b, a_diff_b);
  FindNodeVectorsDiff(b, a, b_diff_a);
}

void FindNodeVectorsUnion(const Vector<Persistent<Node>>& a,
                          const Vector<Persistent<Node>>& b,
                          HashSet<Persistent<Node>>& a_and_b) {
  for (auto& n : a) {
    a_and_b.insert(n);
  }
  for (auto& n : b) {
    a_and_b.insert(n);
  }
}

void ToNodeIds(const Vector<Persistent<Node>>& nodes,
               Vector<int64_t>& node_ids) {
  for (auto& v : nodes) {
    node_ids.push_back(reinterpret_cast<int64_t>(static_cast<Node*>(v)));
  }
}

void ToNodeTexts(const Vector<Persistent<Node>>& nodes, Vector<String>& texts) {
  for (auto& n : nodes)
    texts.push_back(n->nodeValue());
}

}  // namespace

class WebContentCaptureClientTestHelper : public WebContentCaptureClient {
 public:
  ~WebContentCaptureClientTestHelper() override = default;

  base::TimeDelta GetTaskInitialDelay() const override {
    return base::Milliseconds(500);
  }

  void DidCaptureContent(const WebVector<WebContentHolder>& data,
                         bool first_data) override {
    data_ = data;
    first_data_ = first_data;
    for (auto& d : data) {
      auto text = d.GetValue();
      all_text_.push_back(text);
      captured_text_.push_back(text);
    }
  }

  void DidUpdateContent(const WebVector<WebContentHolder>& data) override {
    updated_data_ = data;
    for (auto& d : data)
      updated_text_.push_back(d.GetValue());
  }

  void DidRemoveContent(WebVector<int64_t> data) override {
    removed_data_ = data;
  }

  bool FirstData() const { return first_data_; }

  const WebVector<WebContentHolder>& Data() const { return data_; }

  const WebVector<WebContentHolder>& UpdatedData() const {
    return updated_data_;
  }

  const Vector<String>& AllText() const { return all_text_; }

  const Vector<String>& CapturedText() const { return captured_text_; }

  const Vector<String>& UpdatedText() const { return updated_text_; }

  const WebVector<int64_t>& RemovedData() const { return removed_data_; }

  void ResetResults() {
    first_data_ = false;
    data_.clear();
    updated_data_.clear();
    removed_data_.clear();
    captured_text_.clear();
  }

 private:
  bool first_data_ = false;
  WebVector<WebContentHolder> data_;
  WebVector<WebContentHolder> updated_data_;
  WebVector<int64_t> removed_data_;
  Vector<String> all_text_;
  Vector<String> updated_text_;
  Vector<String> captured_text_;
};

class ContentCaptureLocalFrameClientHelper : public EmptyLocalFrameClient {
 public:
  ContentCaptureLocalFrameClientHelper(WebContentCaptureClient& client)
      : client_(client) {}

  WebContentCaptureClient* GetWebContentCaptureClient() const override {
    return &client_;
  }

 private:
  WebContentCaptureClient& client_;
};

class ContentCaptureTest : public PageTestBase,
                           public ::testing::WithParamInterface<
                               std::vector<base::test::FeatureRef>> {
 public:
  ContentCaptureTest()
      : PageTestBase(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {
    EnablePlatform();
    feature_list_.InitWithFeatures(
        GetParam(),
        /*disabled_features=*/std::vector<base::test::FeatureRef>());
  }

  void SetUp() override {
    content_capture_client_ =
        std::make_unique<WebContentCaptureClientTestHelper>();
    local_frame_client_ =
        MakeGarbageCollected<ContentCaptureLocalFrameClientHelper>(
            *content_capture_client_);
    SetupPageWithClients(nullptr, local_frame_client_);
    SetHtmlInnerHTML(
        "<!DOCTYPE HTML>"
        "<p id='p1'>1</p>"
        "<p id='p2'>2</p>"
        "<p id='p3'>3</p>"
        "<p id='p4'>4</p>"
        "<p id='p5'>5</p>"
        "<p id='p6'>6</p>"
        "<p id='p7'>7</p>"
        "<p id='p8'>8</p>"
        "<div id='d1'></div>"
        "<p id='invisible'>invisible</p>");
    InitNodeHolders();
    // Setup captured content to ContentCaptureTask, it isn't necessary once
    // ContentCaptureManager is created by LocalFrame.
    GetOrResetContentCaptureManager()
        ->GetContentCaptureTaskForTesting()
        ->SetCapturedContentForTesting(node_ids_);
    InitScrollingTestData();
  }

  void SimulateScrolling(wtf_size_t step) {
    CHECK_LT(step, 4u);
    GetOrResetContentCaptureManager()
        ->GetContentCaptureTaskForTesting()
        ->SetCapturedContentForTesting(scrolling_node_ids_[step]);
    GetOrResetContentCaptureManager()->OnScrollPositionChanged();
  }

  void CreateTextNodeAndNotifyManager() {
    Document& doc = GetDocument();
    Node* node = doc.createTextNode("New Text");
    Element* element = MakeGarbageCollected<Element>(html_names::kPTag, &doc);
    element->appendChild(node);
    Element* div_element = GetElementById("d1");
    div_element->appendChild(element);
    UpdateAllLifecyclePhasesForTest();
    GetOrResetContentCaptureManager()->ScheduleTaskIfNeeded(*node);
    created_node_id_ = DOMNodeIds::IdForNode(node);
    Vector<cc::NodeInfo> captured_content{
        cc::NodeInfo(created_node_id_, GetRect(node->GetLayoutObject()))};
    GetOrResetContentCaptureManager()
        ->GetContentCaptureTaskForTesting()
        ->SetCapturedContentForTesting(captured_content);
  }

  ContentCaptureManager* GetOrResetContentCaptureManager() {
    if (content_capture_manager_ == nullptr)
      content_capture_manager_ = GetFrame().GetOrResetContentCaptureManager();
    return content_capture_manager_;
  }

  WebContentCaptureClientTestHelper* GetWebContentCaptureClient() const {
    return content_capture_client_.get();
  }

  ContentCaptureTask* GetContentCaptureTask() {
    return GetOrResetContentCaptureManager()->GetContentCaptureTaskForTesting();
  }

  void RunContentCaptureTask() {
    ResetResult();
    FastForwardBy(GetWebContentCaptureClient()->GetTaskInitialDelay());
  }

  void RunNextContentCaptureTask() {
    ResetResult();
    FastForwardBy(
        GetContentCaptureTask()->GetTaskDelayForTesting().GetNextTaskDelay());
  }

  void RemoveNode(Node* node) {
    // Remove the node.
    node->remove();
    GetOrResetContentCaptureManager()->OnLayoutTextWillBeDestroyed(*node);
  }

  void RemoveUnsentNode(const WebVector<WebContentHolder>& sent_nodes) {
    // Find a node isn't in sent_nodes
    for (auto node : nodes_) {
      bool found_in_sent = false;
      for (auto& sent : sent_nodes) {
        found_in_sent = (node->nodeValue().Utf8().c_str() == sent.GetValue());
        if (found_in_sent)
          break;
      }
      if (!found_in_sent) {
        RemoveNode(node);
        return;
      }
    }
    // Didn't find unsent nodes.
    NOTREACHED();
  }

  size_t GetExpectedFirstResultSize() { return ContentCaptureTask::kBatchSize; }

  size_t GetExpectedSecondResultSize() {
    return node_ids_.size() - GetExpectedFirstResultSize();
  }

  const Vector<cc::NodeInfo>& NodeIds() const { return node_ids_; }
  const Vector<Persistent<Node>> Nodes() const { return nodes_; }

  Node& invisible_node() const { return *invisible_node_; }

  const Vector<Vector<String>>& scrolling_expected_captured_nodes() {
    return scrolling_expected_captured_nodes_;
  }

  const Vector<Vector<int64_t>>& scrolling_expected_removed_nodes() {
    return scrolling_expected_removed_nodes_;
  }

 private:
  void ResetResult() {
    GetWebContentCaptureClient()->ResetResults();
  }

  void BuildNodesInfo(const Vector<String>& ids,
                      Vector<Persistent<Node>>& nodes,
                      Vector<cc::NodeInfo>& node_ids) {
    for (auto id : ids) {
      Node* node = GetDocument().getElementById(AtomicString(id))->firstChild();
      CHECK(node);
      LayoutObject* layout_object = node->GetLayoutObject();
      CHECK(layout_object);
      CHECK(layout_object->IsText());
      nodes.push_back(node);
      GetOrResetContentCaptureManager()->ScheduleTaskIfNeeded(*node);
      node_ids.push_back(
          cc::NodeInfo(node->GetDomNodeId(), GetRect(layout_object)));
    }
  }

  // TODO(michaelbai): Remove this once integrate with LayoutText.
  void InitNodeHolders() {
    BuildNodesInfo(
        Vector<String>{"p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8"}, nodes_,
        node_ids_);
    invisible_node_ = GetElementById("invisible")->firstChild();
    DCHECK(invisible_node_.Get());
  }

  void InitScrollingTestData() {
    Vector<Vector<Persistent<Node>>> nodes{4};
    BuildNodesInfo(Vector<String>{"p1", "p2", "p3"}, nodes[0],
                   scrolling_node_ids_[0]);
    BuildNodesInfo(Vector<String>{"p3", "p4", "p5"}, nodes[1],
                   scrolling_node_ids_[1]);
    BuildNodesInfo(Vector<String>{"p6", "p7", "p8"}, nodes[2],
                   scrolling_node_ids_[2]);
    BuildNodesInfo(Vector<String>{"p2", "p3"}, nodes[3],
                   scrolling_node_ids_[3]);
    // Build expected result.
    if (base::FeatureList::IsEnabled(
            features::kContentCaptureConstantStreaming)) {
      for (int i = 0; i < 4; ++i) {
        Vector<Persistent<Node>> a_diff_b;
        Vector<Persistent<Node>> b_diff_a;
        FindNodeVectorsDiff(nodes[i],
                            i == 0 ? Vector<Persistent<Node>>() : nodes[i - 1],
                            a_diff_b, b_diff_a);
        ToNodeTexts(a_diff_b, scrolling_expected_captured_nodes_[i]);
        ToNodeIds(b_diff_a, scrolling_expected_removed_nodes_[i]);
      }
    } else {
      HashSet<Persistent<Node>> sent;
      for (int i = 0; i < 4; ++i) {
        Vector<Persistent<Node>> a_diff_b;
        Vector<Persistent<Node>> b(sent);
        FindNodeVectorsDiff(nodes[i], b, a_diff_b);
        ToNodeTexts(a_diff_b, scrolling_expected_captured_nodes_[i]);
        sent.clear();
        FindNodeVectorsUnion(b, nodes[i], sent);
      }
    }
  }

  Vector<Persistent<Node>> nodes_;
  Vector<cc::NodeInfo> node_ids_;
  Persistent<Node> invisible_node_;
  Vector<Vector<String>> scrolling_expected_captured_nodes_{4};
  Vector<Vector<int64_t>> scrolling_expected_removed_nodes_{4};
  Vector<Vector<cc::NodeInfo>> scrolling_node_ids_{4};
  std::unique_ptr<WebContentCaptureClientTestHelper> content_capture_client_;
  Persistent<ContentCaptureManager> content_capture_manager_;
  Persistent<ContentCaptureLocalFrameClientHelper> local_frame_client_;
  DOMNodeId created_node_id_ = kInvalidDOMNodeId;
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(
    ,
    ContentCaptureTest,
    testing::Values(std::vector<base::test::FeatureRef>{},
                    std::vector<base::test::FeatureRef>{
                        features::kContentCaptureConstantStreaming}));

TEST_P(ContentCaptureTest, Basic) {
  RunContentCaptureTask();
  EXPECT_EQ(ContentCaptureTask::TaskState::kStop,
            GetContentCaptureTask()->GetTaskStateForTesting());
  EXPECT_FALSE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_EQ(GetExpectedSecondResultSize(),
            GetWebContentCaptureClient()->Data().size());
}

TEST_P(ContentCaptureTest, Scrolling) {
  for (wtf_size_t step = 0; step < 4; ++step) {
    SimulateScrolling(step);
    RunContentCaptureTask();
    EXPECT_EQ(ContentCaptureTask::TaskState::kStop,
              GetContentCaptureTask()->GetTaskStateForTesting());
    EXPECT_THAT(GetWebContentCaptureClient()->CapturedText(),
                testing::UnorderedElementsAreArray(
                    scrolling_expected_captured_nodes()[step]))
        << "at step " << step;
    EXPECT_THAT(GetWebContentCaptureClient()->RemovedData(),
                testing::UnorderedElementsAreArray(
                    scrolling_expected_removed_nodes()[step]))
        << "at step " << step;
  }
}

TEST_P(ContentCaptureTest, PauseAndResume) {
  // The task stops before captures content.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kCaptureContent);
  RunContentCaptureTask();
  EXPECT_FALSE(GetWebContentCaptureClient()->FirstData());
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->RemovedData().empty());

  // The task stops before sends the captured content out.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessCurrentSession);
  RunContentCaptureTask();
  EXPECT_FALSE(GetWebContentCaptureClient()->FirstData());
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->RemovedData().empty());

  // The task should be stop at kProcessRetryTask because the captured content
  // needs to be sent with 2 batch.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessRetryTask);
  RunContentCaptureTask();
  EXPECT_TRUE(GetWebContentCaptureClient()->FirstData());
  EXPECT_FALSE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->RemovedData().empty());
  EXPECT_EQ(GetExpectedFirstResultSize(),
            GetWebContentCaptureClient()->Data().size());

  // Run task until it stops, task will not capture content, because there is no
  // content change, so we have 3 NodeHolders.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kStop);
  RunContentCaptureTask();
  EXPECT_FALSE(GetWebContentCaptureClient()->FirstData());
  EXPECT_FALSE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->RemovedData().empty());
  EXPECT_EQ(GetExpectedSecondResultSize(),
            GetWebContentCaptureClient()->Data().size());
}

TEST_P(ContentCaptureTest, NodeOnlySendOnce) {
  // Send all nodes
  RunContentCaptureTask();
  EXPECT_FALSE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_EQ(GetExpectedSecondResultSize(),
            GetWebContentCaptureClient()->Data().size());

  GetOrResetContentCaptureManager()->OnScrollPositionChanged();
  RunContentCaptureTask();
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->RemovedData().empty());
}

TEST_P(ContentCaptureTest, UnsentNode) {
  // Send all nodes expect |invisible_node_|.
  RunContentCaptureTask();
  EXPECT_FALSE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_EQ(GetExpectedSecondResultSize(),
            GetWebContentCaptureClient()->Data().size());

  // Simulates the |invisible_node_| being changed, and verifies no content
  // change because |invisible_node_| wasn't captured.
  GetOrResetContentCaptureManager()->OnNodeTextChanged(invisible_node());
  RunContentCaptureTask();
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->UpdatedData().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->RemovedData().empty());

  // Simulates the |invisible_node_| being removed, and verifies no content
  // change because |invisible_node_| wasn't captured.
  GetOrResetContentCaptureManager()->OnLayoutTextWillBeDestroyed(
      invisible_node());
  RunContentCaptureTask();
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->UpdatedData().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->RemovedData().empty());
}

TEST_P(ContentCaptureTest, RemoveNodeBeforeSendingOut) {
  // Capture the content, but didn't send them.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessCurrentSession);
  RunContentCaptureTask();
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());

  // Remove the node and sent the captured content out.
  RemoveNode(Nodes().at(0));
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessRetryTask);
  RunContentCaptureTask();
  EXPECT_EQ(GetExpectedFirstResultSize(),
            GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());
  RunContentCaptureTask();
  // Total 7 content returned instead of 8.
  EXPECT_EQ(GetExpectedSecondResultSize() - 1,
            GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());
  RunContentCaptureTask();
  // No removed node because it hasn't been sent out.
  EXPECT_EQ(0u, GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());
}

TEST_P(ContentCaptureTest, RemoveNodeInBetweenSendingOut) {
  // Capture the content, but didn't send them.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessCurrentSession);
  RunContentCaptureTask();
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());

  // Sends first batch.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessRetryTask);
  RunContentCaptureTask();
  EXPECT_EQ(GetExpectedFirstResultSize(),
            GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());

  // This relies on each node to have different value.
  RemoveUnsentNode(GetWebContentCaptureClient()->Data());
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessRetryTask);
  RunContentCaptureTask();
  // Total 7 content returned instead of 8.
  EXPECT_EQ(GetExpectedSecondResultSize() - 1,
            GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());
  RunContentCaptureTask();
  // No removed node because it hasn't been sent out.
  EXPECT_EQ(0u, GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());
}

TEST_P(ContentCaptureTest, RemoveNodeAfterSendingOut) {
  // Captures the content, but didn't send them.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessCurrentSession);
  RunContentCaptureTask();
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());

  // Sends first batch.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessRetryTask);
  RunContentCaptureTask();
  EXPECT_EQ(GetExpectedFirstResultSize(),
            GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());

  // Sends second batch.
  RunContentCaptureTask();
  EXPECT_EQ(GetExpectedSecondResultSize(),
            GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());

  // Remove the node.
  RemoveNode(Nodes().at(0));
  RunContentCaptureTask();
  EXPECT_EQ(0u, GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(1u, GetWebContentCaptureClient()->RemovedData().size());
}

TEST_P(ContentCaptureTest, TaskHistogramReporter) {
  // This performs gc for all DocumentSession, flushes the existing
  // SentContentCount and give a clean baseline for histograms.
  // We are not sure if it always work, maybe still be the source of flaky.
  ThreadState::Current()->CollectAllGarbageForTesting();
  base::HistogramTester histograms;

  // The task stops before captures content.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kCaptureContent);
  RunContentCaptureTask();
  // Verify no histogram reported yet.
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentTime, 0u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSendContentTime, 0u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentDelayTime, 0u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSentContentCount, 0u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kTaskRunsPerCapture, 0u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kTaskDelayInMs, 1u);

  // The task stops before sends the captured content out.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessCurrentSession);
  RunContentCaptureTask();
  // Verify has one CaptureContentTime record.
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentTime, 1u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSendContentTime, 0u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentDelayTime, 0u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSentContentCount, 0u);

  // The task stops at kProcessRetryTask because the captured content
  // needs to be sent with 2 batch.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessRetryTask);
  RunContentCaptureTask();
  // Verify has one CaptureContentTime, one SendContentTime and one
  // CaptureContentDelayTime record.
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentTime, 1u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSendContentTime, 1u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentDelayTime, 1u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSentContentCount, 0u);

  // Run task until it stops, task will not capture content, because there is no
  // content change.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kStop);
  RunContentCaptureTask();
  // Verify has two SendContentTime records.
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentTime, 1u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSendContentTime, 2u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentDelayTime, 1u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSentContentCount, 0u);

  // Verify retry task won't count to TaskDelay metrics.
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kTaskDelayInMs, 1u);

  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kTaskRunsPerCapture, 1u);
  // Verify the task ran 4 times, first run stopped before capturing content
  // and 2nd run captured content, 3rd and 4th run sent the content out.
  histograms.ExpectBucketCount(
      ContentCaptureTaskHistogramReporter::kTaskRunsPerCapture, 4u, 1u);

  // Create a node and run task until it stops.
  CreateTextNodeAndNotifyManager();
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kStop);
  RunNextContentCaptureTask();
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentTime, 2u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSendContentTime, 3u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentDelayTime, 2u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSentContentCount, 0u);

  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kTaskRunsPerCapture, 2u);
  // Verify the task ran 1 times for this session because we didn't explicitly
  // stop it.
  histograms.ExpectBucketCount(
      ContentCaptureTaskHistogramReporter::kTaskRunsPerCapture, 1u, 1u);

  GetContentCaptureTask()->ClearDocumentSessionsForTesting();
  ThreadState::Current()->CollectAllGarbageForTesting();
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentTime, 2u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSendContentTime, 3u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentDelayTime, 2u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSentContentCount, 1u);
  // Verify total content has been sent.
  histograms.ExpectBucketCount(
      ContentCaptureTaskHistogramReporter::kSentContentCount, 9u, 1u);

  // Verify TaskDelay was recorded again for node change.
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kTaskDelayInMs, 2u);
}

TEST_P(ContentCaptureTest, RescheduleTask) {
  // This test assumes test runs much faster than task's long delay which is 5s.
  Persistent<ContentCaptureTask> task = GetContentCaptureTask();
  task->CancelTaskForTesting();
  EXPECT_TRUE(task->GetTaskNextFireIntervalForTesting().is_zero());
  task->Schedule(
      ContentCaptureTask::ScheduleReason::kNonUserActivatedContentChange);
  base::TimeDelta interval1 = task->GetTaskNextFireIntervalForTesting();
  task->Schedule(ContentCaptureTask::ScheduleReason::kScrolling);
  base::TimeDelta interval2 = task->GetTaskNextFireIntervalForTesting();
  EXPECT_LE(interval1, GetWebContentCaptureClient()->GetTaskInitialDelay());
  EXPECT_LE(interval2, interval1);
}

TEST_P(ContentCaptureTest, NotRescheduleTask) {
  // This test assumes test runs much faster than task's long delay which is 5s.
  Persistent<ContentCaptureTask> task = GetContentCaptureTask();
  task->CancelTaskForTesting();
  EXPECT_TRUE(task->GetTaskNextFireIntervalForTesting().is_zero());
  task->Schedule(
      ContentCaptureTask::ScheduleReason::kNonUserActivatedContentChange);
  auto begin = base::TimeTicks::Now();
  base::TimeDelta interval1 = task->GetTaskNextFireIntervalForTesting();
  task->Schedule(
      ContentCaptureTask::ScheduleReason::kNonUserActivatedContentChange);
  base::TimeDelta interval2 = task->GetTaskNextFireIntervalForTesting();
  auto test_running_time = base::TimeTicks::Now() - begin;
  EXPECT_GE(interval1, interval2);
  EXPECT_LE(interval1 - test_running_time, interval2);
}

// TODO(michaelbai): use RenderingTest instead of PageTestBase for multiple

### 提示词
```
这是目录为blink/renderer/core/content_capture/content_capture_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/content_capture/content_capture_manager.h"

#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/web/web_content_capture_client.h"
#include "third_party/blink/public/web/web_content_holder.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html_element_type_helpers.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"

namespace blink {

namespace {

gfx::Rect GetRect(LayoutObject* layout_object) {
  return ToEnclosingRect(VisualRectInDocument(*layout_object));
}

void FindNodeVectorsDiff(const Vector<Persistent<Node>>& a,
                         const Vector<Persistent<Node>>& b,
                         Vector<Persistent<Node>>& a_diff_b) {
  for (auto& i : a) {
    if (!b.Contains(i))
      a_diff_b.push_back(i);
  }
}

void FindNodeVectorsDiff(const Vector<Persistent<Node>>& a,
                         const Vector<Persistent<Node>>& b,
                         Vector<Persistent<Node>>& a_diff_b,
                         Vector<Persistent<Node>>& b_diff_a) {
  FindNodeVectorsDiff(a, b, a_diff_b);
  FindNodeVectorsDiff(b, a, b_diff_a);
}

void FindNodeVectorsUnion(const Vector<Persistent<Node>>& a,
                          const Vector<Persistent<Node>>& b,
                          HashSet<Persistent<Node>>& a_and_b) {
  for (auto& n : a) {
    a_and_b.insert(n);
  }
  for (auto& n : b) {
    a_and_b.insert(n);
  }
}

void ToNodeIds(const Vector<Persistent<Node>>& nodes,
               Vector<int64_t>& node_ids) {
  for (auto& v : nodes) {
    node_ids.push_back(reinterpret_cast<int64_t>(static_cast<Node*>(v)));
  }
}

void ToNodeTexts(const Vector<Persistent<Node>>& nodes, Vector<String>& texts) {
  for (auto& n : nodes)
    texts.push_back(n->nodeValue());
}

}  // namespace

class WebContentCaptureClientTestHelper : public WebContentCaptureClient {
 public:
  ~WebContentCaptureClientTestHelper() override = default;

  base::TimeDelta GetTaskInitialDelay() const override {
    return base::Milliseconds(500);
  }

  void DidCaptureContent(const WebVector<WebContentHolder>& data,
                         bool first_data) override {
    data_ = data;
    first_data_ = first_data;
    for (auto& d : data) {
      auto text = d.GetValue();
      all_text_.push_back(text);
      captured_text_.push_back(text);
    }
  }

  void DidUpdateContent(const WebVector<WebContentHolder>& data) override {
    updated_data_ = data;
    for (auto& d : data)
      updated_text_.push_back(d.GetValue());
  }

  void DidRemoveContent(WebVector<int64_t> data) override {
    removed_data_ = data;
  }

  bool FirstData() const { return first_data_; }

  const WebVector<WebContentHolder>& Data() const { return data_; }

  const WebVector<WebContentHolder>& UpdatedData() const {
    return updated_data_;
  }

  const Vector<String>& AllText() const { return all_text_; }

  const Vector<String>& CapturedText() const { return captured_text_; }

  const Vector<String>& UpdatedText() const { return updated_text_; }

  const WebVector<int64_t>& RemovedData() const { return removed_data_; }

  void ResetResults() {
    first_data_ = false;
    data_.clear();
    updated_data_.clear();
    removed_data_.clear();
    captured_text_.clear();
  }

 private:
  bool first_data_ = false;
  WebVector<WebContentHolder> data_;
  WebVector<WebContentHolder> updated_data_;
  WebVector<int64_t> removed_data_;
  Vector<String> all_text_;
  Vector<String> updated_text_;
  Vector<String> captured_text_;
};

class ContentCaptureLocalFrameClientHelper : public EmptyLocalFrameClient {
 public:
  ContentCaptureLocalFrameClientHelper(WebContentCaptureClient& client)
      : client_(client) {}

  WebContentCaptureClient* GetWebContentCaptureClient() const override {
    return &client_;
  }

 private:
  WebContentCaptureClient& client_;
};

class ContentCaptureTest : public PageTestBase,
                           public ::testing::WithParamInterface<
                               std::vector<base::test::FeatureRef>> {
 public:
  ContentCaptureTest()
      : PageTestBase(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {
    EnablePlatform();
    feature_list_.InitWithFeatures(
        GetParam(),
        /*disabled_features=*/std::vector<base::test::FeatureRef>());
  }

  void SetUp() override {
    content_capture_client_ =
        std::make_unique<WebContentCaptureClientTestHelper>();
    local_frame_client_ =
        MakeGarbageCollected<ContentCaptureLocalFrameClientHelper>(
            *content_capture_client_);
    SetupPageWithClients(nullptr, local_frame_client_);
    SetHtmlInnerHTML(
        "<!DOCTYPE HTML>"
        "<p id='p1'>1</p>"
        "<p id='p2'>2</p>"
        "<p id='p3'>3</p>"
        "<p id='p4'>4</p>"
        "<p id='p5'>5</p>"
        "<p id='p6'>6</p>"
        "<p id='p7'>7</p>"
        "<p id='p8'>8</p>"
        "<div id='d1'></div>"
        "<p id='invisible'>invisible</p>");
    InitNodeHolders();
    // Setup captured content to ContentCaptureTask, it isn't necessary once
    // ContentCaptureManager is created by LocalFrame.
    GetOrResetContentCaptureManager()
        ->GetContentCaptureTaskForTesting()
        ->SetCapturedContentForTesting(node_ids_);
    InitScrollingTestData();
  }

  void SimulateScrolling(wtf_size_t step) {
    CHECK_LT(step, 4u);
    GetOrResetContentCaptureManager()
        ->GetContentCaptureTaskForTesting()
        ->SetCapturedContentForTesting(scrolling_node_ids_[step]);
    GetOrResetContentCaptureManager()->OnScrollPositionChanged();
  }

  void CreateTextNodeAndNotifyManager() {
    Document& doc = GetDocument();
    Node* node = doc.createTextNode("New Text");
    Element* element = MakeGarbageCollected<Element>(html_names::kPTag, &doc);
    element->appendChild(node);
    Element* div_element = GetElementById("d1");
    div_element->appendChild(element);
    UpdateAllLifecyclePhasesForTest();
    GetOrResetContentCaptureManager()->ScheduleTaskIfNeeded(*node);
    created_node_id_ = DOMNodeIds::IdForNode(node);
    Vector<cc::NodeInfo> captured_content{
        cc::NodeInfo(created_node_id_, GetRect(node->GetLayoutObject()))};
    GetOrResetContentCaptureManager()
        ->GetContentCaptureTaskForTesting()
        ->SetCapturedContentForTesting(captured_content);
  }

  ContentCaptureManager* GetOrResetContentCaptureManager() {
    if (content_capture_manager_ == nullptr)
      content_capture_manager_ = GetFrame().GetOrResetContentCaptureManager();
    return content_capture_manager_;
  }

  WebContentCaptureClientTestHelper* GetWebContentCaptureClient() const {
    return content_capture_client_.get();
  }

  ContentCaptureTask* GetContentCaptureTask() {
    return GetOrResetContentCaptureManager()->GetContentCaptureTaskForTesting();
  }

  void RunContentCaptureTask() {
    ResetResult();
    FastForwardBy(GetWebContentCaptureClient()->GetTaskInitialDelay());
  }

  void RunNextContentCaptureTask() {
    ResetResult();
    FastForwardBy(
        GetContentCaptureTask()->GetTaskDelayForTesting().GetNextTaskDelay());
  }

  void RemoveNode(Node* node) {
    // Remove the node.
    node->remove();
    GetOrResetContentCaptureManager()->OnLayoutTextWillBeDestroyed(*node);
  }

  void RemoveUnsentNode(const WebVector<WebContentHolder>& sent_nodes) {
    // Find a node isn't in sent_nodes
    for (auto node : nodes_) {
      bool found_in_sent = false;
      for (auto& sent : sent_nodes) {
        found_in_sent = (node->nodeValue().Utf8().c_str() == sent.GetValue());
        if (found_in_sent)
          break;
      }
      if (!found_in_sent) {
        RemoveNode(node);
        return;
      }
    }
    // Didn't find unsent nodes.
    NOTREACHED();
  }

  size_t GetExpectedFirstResultSize() { return ContentCaptureTask::kBatchSize; }

  size_t GetExpectedSecondResultSize() {
    return node_ids_.size() - GetExpectedFirstResultSize();
  }

  const Vector<cc::NodeInfo>& NodeIds() const { return node_ids_; }
  const Vector<Persistent<Node>> Nodes() const { return nodes_; }

  Node& invisible_node() const { return *invisible_node_; }

  const Vector<Vector<String>>& scrolling_expected_captured_nodes() {
    return scrolling_expected_captured_nodes_;
  }

  const Vector<Vector<int64_t>>& scrolling_expected_removed_nodes() {
    return scrolling_expected_removed_nodes_;
  }

 private:
  void ResetResult() {
    GetWebContentCaptureClient()->ResetResults();
  }

  void BuildNodesInfo(const Vector<String>& ids,
                      Vector<Persistent<Node>>& nodes,
                      Vector<cc::NodeInfo>& node_ids) {
    for (auto id : ids) {
      Node* node = GetDocument().getElementById(AtomicString(id))->firstChild();
      CHECK(node);
      LayoutObject* layout_object = node->GetLayoutObject();
      CHECK(layout_object);
      CHECK(layout_object->IsText());
      nodes.push_back(node);
      GetOrResetContentCaptureManager()->ScheduleTaskIfNeeded(*node);
      node_ids.push_back(
          cc::NodeInfo(node->GetDomNodeId(), GetRect(layout_object)));
    }
  }

  // TODO(michaelbai): Remove this once integrate with LayoutText.
  void InitNodeHolders() {
    BuildNodesInfo(
        Vector<String>{"p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8"}, nodes_,
        node_ids_);
    invisible_node_ = GetElementById("invisible")->firstChild();
    DCHECK(invisible_node_.Get());
  }

  void InitScrollingTestData() {
    Vector<Vector<Persistent<Node>>> nodes{4};
    BuildNodesInfo(Vector<String>{"p1", "p2", "p3"}, nodes[0],
                   scrolling_node_ids_[0]);
    BuildNodesInfo(Vector<String>{"p3", "p4", "p5"}, nodes[1],
                   scrolling_node_ids_[1]);
    BuildNodesInfo(Vector<String>{"p6", "p7", "p8"}, nodes[2],
                   scrolling_node_ids_[2]);
    BuildNodesInfo(Vector<String>{"p2", "p3"}, nodes[3],
                   scrolling_node_ids_[3]);
    // Build expected result.
    if (base::FeatureList::IsEnabled(
            features::kContentCaptureConstantStreaming)) {
      for (int i = 0; i < 4; ++i) {
        Vector<Persistent<Node>> a_diff_b;
        Vector<Persistent<Node>> b_diff_a;
        FindNodeVectorsDiff(nodes[i],
                            i == 0 ? Vector<Persistent<Node>>() : nodes[i - 1],
                            a_diff_b, b_diff_a);
        ToNodeTexts(a_diff_b, scrolling_expected_captured_nodes_[i]);
        ToNodeIds(b_diff_a, scrolling_expected_removed_nodes_[i]);
      }
    } else {
      HashSet<Persistent<Node>> sent;
      for (int i = 0; i < 4; ++i) {
        Vector<Persistent<Node>> a_diff_b;
        Vector<Persistent<Node>> b(sent);
        FindNodeVectorsDiff(nodes[i], b, a_diff_b);
        ToNodeTexts(a_diff_b, scrolling_expected_captured_nodes_[i]);
        sent.clear();
        FindNodeVectorsUnion(b, nodes[i], sent);
      }
    }
  }

  Vector<Persistent<Node>> nodes_;
  Vector<cc::NodeInfo> node_ids_;
  Persistent<Node> invisible_node_;
  Vector<Vector<String>> scrolling_expected_captured_nodes_{4};
  Vector<Vector<int64_t>> scrolling_expected_removed_nodes_{4};
  Vector<Vector<cc::NodeInfo>> scrolling_node_ids_{4};
  std::unique_ptr<WebContentCaptureClientTestHelper> content_capture_client_;
  Persistent<ContentCaptureManager> content_capture_manager_;
  Persistent<ContentCaptureLocalFrameClientHelper> local_frame_client_;
  DOMNodeId created_node_id_ = kInvalidDOMNodeId;
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(
    ,
    ContentCaptureTest,
    testing::Values(std::vector<base::test::FeatureRef>{},
                    std::vector<base::test::FeatureRef>{
                        features::kContentCaptureConstantStreaming}));

TEST_P(ContentCaptureTest, Basic) {
  RunContentCaptureTask();
  EXPECT_EQ(ContentCaptureTask::TaskState::kStop,
            GetContentCaptureTask()->GetTaskStateForTesting());
  EXPECT_FALSE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_EQ(GetExpectedSecondResultSize(),
            GetWebContentCaptureClient()->Data().size());
}

TEST_P(ContentCaptureTest, Scrolling) {
  for (wtf_size_t step = 0; step < 4; ++step) {
    SimulateScrolling(step);
    RunContentCaptureTask();
    EXPECT_EQ(ContentCaptureTask::TaskState::kStop,
              GetContentCaptureTask()->GetTaskStateForTesting());
    EXPECT_THAT(GetWebContentCaptureClient()->CapturedText(),
                testing::UnorderedElementsAreArray(
                    scrolling_expected_captured_nodes()[step]))
        << "at step " << step;
    EXPECT_THAT(GetWebContentCaptureClient()->RemovedData(),
                testing::UnorderedElementsAreArray(
                    scrolling_expected_removed_nodes()[step]))
        << "at step " << step;
  }
}

TEST_P(ContentCaptureTest, PauseAndResume) {
  // The task stops before captures content.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kCaptureContent);
  RunContentCaptureTask();
  EXPECT_FALSE(GetWebContentCaptureClient()->FirstData());
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->RemovedData().empty());

  // The task stops before sends the captured content out.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessCurrentSession);
  RunContentCaptureTask();
  EXPECT_FALSE(GetWebContentCaptureClient()->FirstData());
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->RemovedData().empty());

  // The task should be stop at kProcessRetryTask because the captured content
  // needs to be sent with 2 batch.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessRetryTask);
  RunContentCaptureTask();
  EXPECT_TRUE(GetWebContentCaptureClient()->FirstData());
  EXPECT_FALSE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->RemovedData().empty());
  EXPECT_EQ(GetExpectedFirstResultSize(),
            GetWebContentCaptureClient()->Data().size());

  // Run task until it stops, task will not capture content, because there is no
  // content change, so we have 3 NodeHolders.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kStop);
  RunContentCaptureTask();
  EXPECT_FALSE(GetWebContentCaptureClient()->FirstData());
  EXPECT_FALSE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->RemovedData().empty());
  EXPECT_EQ(GetExpectedSecondResultSize(),
            GetWebContentCaptureClient()->Data().size());
}

TEST_P(ContentCaptureTest, NodeOnlySendOnce) {
  // Send all nodes
  RunContentCaptureTask();
  EXPECT_FALSE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_EQ(GetExpectedSecondResultSize(),
            GetWebContentCaptureClient()->Data().size());

  GetOrResetContentCaptureManager()->OnScrollPositionChanged();
  RunContentCaptureTask();
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->RemovedData().empty());
}

TEST_P(ContentCaptureTest, UnsentNode) {
  // Send all nodes expect |invisible_node_|.
  RunContentCaptureTask();
  EXPECT_FALSE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_EQ(GetExpectedSecondResultSize(),
            GetWebContentCaptureClient()->Data().size());

  // Simulates the |invisible_node_| being changed, and verifies no content
  // change because |invisible_node_| wasn't captured.
  GetOrResetContentCaptureManager()->OnNodeTextChanged(invisible_node());
  RunContentCaptureTask();
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->UpdatedData().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->RemovedData().empty());

  // Simulates the |invisible_node_| being removed, and verifies no content
  // change because |invisible_node_| wasn't captured.
  GetOrResetContentCaptureManager()->OnLayoutTextWillBeDestroyed(
      invisible_node());
  RunContentCaptureTask();
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->UpdatedData().empty());
  EXPECT_TRUE(GetWebContentCaptureClient()->RemovedData().empty());
}

TEST_P(ContentCaptureTest, RemoveNodeBeforeSendingOut) {
  // Capture the content, but didn't send them.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessCurrentSession);
  RunContentCaptureTask();
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());

  // Remove the node and sent the captured content out.
  RemoveNode(Nodes().at(0));
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessRetryTask);
  RunContentCaptureTask();
  EXPECT_EQ(GetExpectedFirstResultSize(),
            GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());
  RunContentCaptureTask();
  // Total 7 content returned instead of 8.
  EXPECT_EQ(GetExpectedSecondResultSize() - 1,
            GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());
  RunContentCaptureTask();
  // No removed node because it hasn't been sent out.
  EXPECT_EQ(0u, GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());
}

TEST_P(ContentCaptureTest, RemoveNodeInBetweenSendingOut) {
  // Capture the content, but didn't send them.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessCurrentSession);
  RunContentCaptureTask();
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());

  // Sends first batch.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessRetryTask);
  RunContentCaptureTask();
  EXPECT_EQ(GetExpectedFirstResultSize(),
            GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());

  // This relies on each node to have different value.
  RemoveUnsentNode(GetWebContentCaptureClient()->Data());
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessRetryTask);
  RunContentCaptureTask();
  // Total 7 content returned instead of 8.
  EXPECT_EQ(GetExpectedSecondResultSize() - 1,
            GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());
  RunContentCaptureTask();
  // No removed node because it hasn't been sent out.
  EXPECT_EQ(0u, GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());
}

TEST_P(ContentCaptureTest, RemoveNodeAfterSendingOut) {
  // Captures the content, but didn't send them.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessCurrentSession);
  RunContentCaptureTask();
  EXPECT_TRUE(GetWebContentCaptureClient()->Data().empty());

  // Sends first batch.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessRetryTask);
  RunContentCaptureTask();
  EXPECT_EQ(GetExpectedFirstResultSize(),
            GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());

  // Sends second batch.
  RunContentCaptureTask();
  EXPECT_EQ(GetExpectedSecondResultSize(),
            GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(0u, GetWebContentCaptureClient()->RemovedData().size());

  // Remove the node.
  RemoveNode(Nodes().at(0));
  RunContentCaptureTask();
  EXPECT_EQ(0u, GetWebContentCaptureClient()->Data().size());
  EXPECT_EQ(1u, GetWebContentCaptureClient()->RemovedData().size());
}

TEST_P(ContentCaptureTest, TaskHistogramReporter) {
  // This performs gc for all DocumentSession, flushes the existing
  // SentContentCount and give a clean baseline for histograms.
  // We are not sure if it always work, maybe still be the source of flaky.
  ThreadState::Current()->CollectAllGarbageForTesting();
  base::HistogramTester histograms;

  // The task stops before captures content.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kCaptureContent);
  RunContentCaptureTask();
  // Verify no histogram reported yet.
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentTime, 0u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSendContentTime, 0u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentDelayTime, 0u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSentContentCount, 0u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kTaskRunsPerCapture, 0u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kTaskDelayInMs, 1u);

  // The task stops before sends the captured content out.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessCurrentSession);
  RunContentCaptureTask();
  // Verify has one CaptureContentTime record.
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentTime, 1u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSendContentTime, 0u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentDelayTime, 0u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSentContentCount, 0u);

  // The task stops at kProcessRetryTask because the captured content
  // needs to be sent with 2 batch.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kProcessRetryTask);
  RunContentCaptureTask();
  // Verify has one CaptureContentTime, one SendContentTime and one
  // CaptureContentDelayTime record.
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentTime, 1u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSendContentTime, 1u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentDelayTime, 1u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSentContentCount, 0u);

  // Run task until it stops, task will not capture content, because there is no
  // content change.
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kStop);
  RunContentCaptureTask();
  // Verify has two SendContentTime records.
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentTime, 1u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSendContentTime, 2u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentDelayTime, 1u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSentContentCount, 0u);

  // Verify retry task won't count to TaskDelay metrics.
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kTaskDelayInMs, 1u);

  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kTaskRunsPerCapture, 1u);
  // Verify the task ran 4 times, first run stopped before capturing content
  // and 2nd run captured content, 3rd and 4th run sent the content out.
  histograms.ExpectBucketCount(
      ContentCaptureTaskHistogramReporter::kTaskRunsPerCapture, 4u, 1u);

  // Create a node and run task until it stops.
  CreateTextNodeAndNotifyManager();
  GetContentCaptureTask()->SetTaskStopForTesting(
      ContentCaptureTask::TaskState::kStop);
  RunNextContentCaptureTask();
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentTime, 2u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSendContentTime, 3u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentDelayTime, 2u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSentContentCount, 0u);

  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kTaskRunsPerCapture, 2u);
  // Verify the task ran 1 times for this session because we didn't explicitly
  // stop it.
  histograms.ExpectBucketCount(
      ContentCaptureTaskHistogramReporter::kTaskRunsPerCapture, 1u, 1u);

  GetContentCaptureTask()->ClearDocumentSessionsForTesting();
  ThreadState::Current()->CollectAllGarbageForTesting();
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentTime, 2u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSendContentTime, 3u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kCaptureContentDelayTime, 2u);
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kSentContentCount, 1u);
  // Verify total content has been sent.
  histograms.ExpectBucketCount(
      ContentCaptureTaskHistogramReporter::kSentContentCount, 9u, 1u);

  // Verify TaskDelay was recorded again for node change.
  histograms.ExpectTotalCount(
      ContentCaptureTaskHistogramReporter::kTaskDelayInMs, 2u);
}

TEST_P(ContentCaptureTest, RescheduleTask) {
  // This test assumes test runs much faster than task's long delay which is 5s.
  Persistent<ContentCaptureTask> task = GetContentCaptureTask();
  task->CancelTaskForTesting();
  EXPECT_TRUE(task->GetTaskNextFireIntervalForTesting().is_zero());
  task->Schedule(
      ContentCaptureTask::ScheduleReason::kNonUserActivatedContentChange);
  base::TimeDelta interval1 = task->GetTaskNextFireIntervalForTesting();
  task->Schedule(ContentCaptureTask::ScheduleReason::kScrolling);
  base::TimeDelta interval2 = task->GetTaskNextFireIntervalForTesting();
  EXPECT_LE(interval1, GetWebContentCaptureClient()->GetTaskInitialDelay());
  EXPECT_LE(interval2, interval1);
}

TEST_P(ContentCaptureTest, NotRescheduleTask) {
  // This test assumes test runs much faster than task's long delay which is 5s.
  Persistent<ContentCaptureTask> task = GetContentCaptureTask();
  task->CancelTaskForTesting();
  EXPECT_TRUE(task->GetTaskNextFireIntervalForTesting().is_zero());
  task->Schedule(
      ContentCaptureTask::ScheduleReason::kNonUserActivatedContentChange);
  auto begin = base::TimeTicks::Now();
  base::TimeDelta interval1 = task->GetTaskNextFireIntervalForTesting();
  task->Schedule(
      ContentCaptureTask::ScheduleReason::kNonUserActivatedContentChange);
  base::TimeDelta interval2 = task->GetTaskNextFireIntervalForTesting();
  auto test_running_time = base::TimeTicks::Now() - begin;
  EXPECT_GE(interval1, interval2);
  EXPECT_LE(interval1 - test_running_time, interval2);
}

// TODO(michaelbai): use RenderingTest instead of PageTestBase for multiple
// frame test.
class ContentCaptureSimTest : public SimTest {
 public:
  static const char* kEditableContent;

  ContentCaptureSimTest() : client_(), child_client_() {}
  void SetUp() override {
    SimTest::SetUp();
    MainFrame().SetContentCaptureClient(&client_);
    SetupPage();
  }

  void RunContentCaptureTaskUntil(ContentCaptureTask::TaskState state) {
    Client().ResetResults();
    ChildClient().ResetResults();
    GetDocument()
        .GetFrame()
        ->LocalFrameRoot()
        .GetOrResetContentCaptureManager()
        ->GetContentCaptureTaskForTesting()
        ->RunTaskForTestingUntil(state);
    // Cancels the scheduled task to simulate that the task is running by
    // scheduler.
    GetOrResetContentCaptureManager()
        ->GetContentCaptureTaskForTesting()
        ->CancelTaskForTesting();
  }

  WebContentCaptureClientTestHelper& Client() { return client_; }
  WebContentCaptureClientTestHelper& ChildClient() { return child_client_; }

  enum class ContentType { kAll, kMainFrame, kChildFrame };
  void SetCapturedContent(ContentType type) {
    if (type == ContentType::kMainFrame) {
      SetCapturedContent(main_frame_content_);
    } else if (type == ContentType::kChildFrame) {
      SetCapturedContent(child_frame_content_);
    } else if (type == ContentType::kAll) {
      Vector<cc::NodeInfo> holders(main_frame_content_);
      holders.AppendRange(child_frame_content_.begin(),
                          child_frame_content_.end());
      SetCapturedContent(holders);
    }
  }

  void AddOneNodeToMainFrame() {
    AddNodeToDocument(GetDocument(), main_frame_content_);
    main_frame_expected_text_.push_back("New Text");
  }

  void AddOneNodeToChildFrame() {
    AddNodeToDocument(*child_document_, child_frame_content_);
    child_frame_expected_text_.push_back("New Text");
  }

  void InsertMainFrameEditableContent(const String& content, unsigned offset) {
    InsertNodeContent(GetDocument(), "editable_id", content, offset);
  }

  void DeleteMainFrameEditableContent(unsigned offset, unsigned length) {
    DeleteNodeContent(GetDocument(), "editable_id", offset, length);
  }

  const Vector<String>& MainFrameExpectedText() const {
    return main_frame_expected_text_;
  }

  const Vector<String>& ChildFrameExpectedText() const {
    return child_frame_expected_text_;
  }

  void ReplaceMainFrameExpectedText(const String& old_text,
                                    const String& new_text) {
    std::replace(main_frame_expected_text_.begin(),
                 main_frame_expected_text_.end(), old_text, new_text);
  }

  ContentCaptureManager* GetOrResetContentCaptureManager() {
    return DynamicTo<LocalFrame>(LocalFrameRoot().GetFrame())
        ->GetOrResetContentCaptureManager();
  }

  void SimulateUserInputOnMainFrame() {
    GetOrResetContentCaptureManager()->NotifyInputEvent(
        WebInputEvent::Type::kMouseDown,
        *DynamicTo<LocalFrame>(MainFrame().GetFrame()));
  }

  void SimulateUserInputOnChildFrame() {
    GetOrResetContentCaptureManager()->NotifyInputEvent(
        WebInputEvent::Type::kMouseDown, *child_document_->GetFrame());
  }

  base::TimeDelta GetNextTaskDelay() {
    return GetOrResetContentCaptureManager()
        ->GetContentCaptureTaskForTesting()
        ->GetTaskDelayForTesting()
        .GetNextTaskDelay();
  }

  base::TimeDelta GetTaskNextFireInterval() {
    return GetOrResetContentCaptureManager()
        ->GetContentCaptureTaskForTesting()
        ->GetTaskNextFireIntervalForTesting();
  }

 private:
  void SetupPage() {
    SimRequest main_resource("https://example.com/test.html", "text/html");
    SimRequest frame_resource("https://example.com/frame.html", "text/html");
    LoadURL("https://example.com/test.html");
    WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 6000));
    main_resource.Complete(R"HTML(
      <!DOCTYPE html>
      <body style='background: white'>
      <iframe id=frame name='frame' src=frame.html></iframe>
      <p id='p1'>Hello World1</p>
      <p id='p2'>Hello World2</p>
      <p id='p3'>Hello World3</p>
      <p id='p4'>Hello World4</p>
      <p id='p5'>Hello World5</p>
      <p id='p6'>Hello World6</p>
      <p id='p7'>Hello World7</p>
      <div id='editable_id'>editable</div>
      <svg>
      <text id="s8">Hello World8</text>
      </svg>
      <div id='d1'></div>
      )HTML");
    auto frame1 = Compositor().BeginFrame();
    frame_resource.Complete(R"HTML(
      <!DOCTYPE html>
      <p id='c1'>Hello World11</p>
      <p id='c2'>Hello World12</p>
      <div id='d1'></div>
      )HTML");

    static_cast<WebLocalFrame*>(MainFrame().FindFrameByName("frame")
```