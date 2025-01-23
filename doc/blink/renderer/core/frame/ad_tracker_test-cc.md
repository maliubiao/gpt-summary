Response:
The user wants a summary of the functionality of the `ad_tracker_test.cc` file in the Chromium Blink engine. The summary should include:
1. **Core functionality:** What does this test file do?
2. **Relationship to web technologies:** How does it relate to JavaScript, HTML, and CSS? Provide examples.
3. **Logic and assumptions:**  If there's any logical inference, provide assumed inputs and outputs.
4. **Common errors:**  Point out potential user or programming mistakes related to the tested functionality.
5. **Concise summary:** A brief overall summary of the file's purpose.

**Plan:**
1. **Analyze the includes:** Identify the key classes and functionalities being tested (e.g., `AdTracker`, `LocalFrame`, `HTMLImageElement`).
2. **Examine the test cases:**  Go through each `TEST_F` function and understand what aspect of `AdTracker` it's verifying.
3. **Relate to web technologies:**  Connect the tested scenarios to how ads interact with JavaScript, HTML, and CSS (e.g., loading scripts, embedding iframes, loading stylesheets and images).
4. **Identify assumptions and logic:**  Look for tests that make specific assumptions about how the `AdTracker` should behave under certain conditions (e.g., a script loaded by an ad script is also considered an ad script).
5. **Infer potential errors:** Consider common mistakes developers might make when dealing with ad tracking or resource loading.
6. **Synthesize the information:**  Combine the findings into a structured summary addressing each of the user's requests.
```
功能归纳：

`ad_tracker_test.cc` 文件是 Chromium Blink 引擎中 `AdTracker` 类的单元测试文件。其主要功能是测试 `AdTracker` 类的各种功能，以确保其能够正确地识别和跟踪网页中的广告相关资源和脚本执行。

**核心功能：**

1. **判断脚本是否为广告脚本：** 测试 `AdTracker` 是否能正确判断当前正在执行的脚本是否被标记为广告脚本。这包括基于 URL、脚本 ID 以及执行上下文的判断。
2. **跟踪异步任务的广告归属：** 测试 `AdTracker` 是否能正确跟踪由广告脚本创建和执行的异步任务，并将这些任务标记为与广告相关。
3. **识别由广告脚本加载的子资源：** 测试 `AdTracker` 是否能正确识别由广告脚本加载的各种子资源（如脚本、图片、iframe 等），并将这些资源标记为广告资源。
4. **识别由广告上下文加载的资源：** 测试 `AdTracker` 是否能识别在被标记为广告的 frame 或其上下文中加载的资源。
5. **跟踪 iframe 的广告归属：** 测试 `AdTracker` 是否能正确判断 iframe 是否由广告脚本创建，并标记该 iframe 为广告 frame。
6. **处理重定向：** 测试 `AdTracker` 在资源重定向的情况下，是否能正确识别最终的广告资源。
7. **处理跨域场景：** 虽然这个文件中的测试案例没有明确展示跨域，但其设计的目的是为了覆盖各种场景，包括跨域下的广告识别。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript：**  `AdTracker` 的核心功能之一就是识别广告 JavaScript 脚本。
    * **举例：**  测试用例 `ScriptLoadedWhileExecutingAdScript` 模拟了在一个被标记为广告的脚本 (`ad_script.js`) 中动态创建并加载另一个脚本 (`vanilla_script.js`) 的场景。`AdTracker` 需要能够识别出 `vanilla_script.js` 也应被标记为广告脚本，因为它是由广告脚本加载的。
    * **假设输入：** 一个包含如下 HTML 的页面，其中 `ad_script.js` 被 `AdTracker` 标记为广告脚本。
      ```html
      <body><script src="ad_script.js"></script></body>
      ```
      `ad_script.js` 内容如下：
      ```javascript
      script = document.createElement("script");
      script.src = "vanilla_script.js";
      document.body.appendChild(script);
      ```
    * **预期输出：** `AdTracker` 会将 `vanilla_script.js` 也标记为广告脚本。

* **HTML：** `AdTracker` 需要分析 HTML 结构来识别广告相关的元素，特别是 iframe。
    * **举例：** 测试用例 `FrameLoadedWhileExecutingAdScript` 模拟了广告脚本动态创建一个 iframe 的场景。`AdTracker` 需要能够识别这个 iframe 是由广告脚本创建的。
    * **假设输入：** 一个包含如下 HTML 的页面，其中 `ad_script.js` 被 `AdTracker` 标记为广告脚本。
      ```html
      <body><script src="ad_script.js"></script></body>
      ```
      `ad_script.js` 内容如下：
      ```javascript
      iframe = document.createElement("iframe");
      iframe.src = "vanilla_page.html";
      document.body.appendChild(iframe);
      ```
    * **预期输出：** `AdTracker` 会将创建的 iframe (指向 `vanilla_page.html`) 标记为由广告脚本创建。

* **CSS：** 虽然这个文件中的测试主要关注 JavaScript 和 HTML，但 `AdTracker` 的设计理念也涵盖了 CSS 资源。可以通过 URL 参数等方式来标记 CSS 文件是否为广告相关。
    * **举例（基于代码）：**  代码中定义了 `kPageWithAdExternalStylesheet` 和 `kStylesheetWithAdResources` 这样的常量，模拟了带有 `?ad=true` 参数的 CSS 文件，这暗示了 `AdTracker` 可以通过检查 URL 来判断 CSS 资源是否为广告资源。
    * **假设输入：** 加载了以下 HTML 的页面：
      ```html
      <head><link rel="stylesheet" href="style.css?ad=true"></head>
      <body><div class="test">Test</div></body>
      ```
    * **预期输出：** `AdTracker` 可能会将 `style.css?ad=true` 这个 CSS 文件标记为广告相关的。

**逻辑推理的假设输入与输出：**

* **假设输入：**  一个函数调用栈，其中最底部的脚本 (`scriptA.js`) 被标记为广告脚本。之后调用了另一个非广告脚本 (`scriptB.js`)。
* **预期输出：** `AnyExecutingScriptsTaggedAsAdResource()` 会返回 `true`，因为函数调用栈中存在被标记为广告的脚本。 `BottommostAdScript()` 会返回 `scriptA.js` 的相关信息。

**涉及用户或者编程常见的使用错误：**

1. **错误地假设所有通过广告脚本加载的资源都立即会被标记为广告：**  资源加载可能是异步的，`AdTracker` 需要正确处理异步场景。例如，一个图片可能在广告脚本执行后才开始加载。
    * **举例：** 用户可能认为在广告脚本执行完后，通过该脚本加载的图片就一定会被立即标记为广告。但是，如果图片加载是异步的，那么在图片加载完成并被 `AdTracker` 检测到之前，可能无法立即获取到其广告标记。测试用例 `ImageLoadedWhileExecutingAdScriptAsyncEnabled` 就覆盖了这种情况。
2. **混淆了 "由广告脚本创建" 和 "在广告上下文中执行" 的概念：** 一个脚本可能在一个非广告的 frame 中执行，但其创建者是广告脚本。
    * **举例：** 用户可能会错误地认为，只有在被标记为广告的 frame 中执行的脚本才是广告脚本。但实际上，如果一个脚本是由广告脚本创建的，即使它在非广告 frame 中运行，也可能被 `AdTracker` 标记为与广告相关。测试用例 `InlineAdScriptRunningInNonAdContext` 就演示了这种情况，广告脚本在主 frame 中创建了一个新的 iframe。

**功能归纳：**

总而言之，`ad_tracker_test.cc` 文件旨在全面测试 Chromium Blink 引擎中 `AdTracker` 类的功能，确保其能够准确地识别和跟踪网页中的广告相关活动，包括脚本执行、资源加载以及 iframe 的创建，涵盖了同步和异步场景，以及不同执行上下文的情况，为浏览器的广告拦截和隐私保护功能提供基础保障。
```
### 提示词
```
这是目录为blink/renderer/core/frame/ad_tracker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/ad_tracker.h"

#include <memory>

#include "base/containers/contains.h"
#include "base/run_loop.h"
#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/probe/async_task_context.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

const unsigned char kSmallGifData[] = {0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01,
                                       0x00, 0x01, 0x00, 0x00, 0xff, 0x00, 0x2c,
                                       0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
                                       0x00, 0x00, 0x02, 0x00, 0x3b};

// The pages include a div with class="test" to ensure the resources in the
// stylesheet are loaded.
const char kPageWithVanillaExternalStylesheet[] = R"HTML(
    <head><link rel="stylesheet" href="style.css"></head>
    <body><div class="test">Test</div></body>
    )HTML";
const char kPageWithAdExternalStylesheet[] = R"HTML(
    <head><link rel="stylesheet" href="style.css?ad=true"></head>
    <body><div class="test">Test</div></body>
    )HTML";
const char kPageWithVanillaScript[] = R"HTML(
    <head><script defer src="script.js"></script></head>
    <body><div class="test">Test</div></body>
    )HTML";
const char kPageWithAdScript[] = R"HTML(
    <head><script defer src="script.js?ad=true"></script></head>
    <body><div class="test">Test</div></body>
    )HTML";
const char kPageWithFrame[] = R"HTML(
    <head></head>
    <body><div class="test">Test</div><iframe src="frame.html"></iframe></body>
    )HTML";
const char kPageWithStyleTagLoadingVanillaResources[] = R"HTML(
    <head><style>
      @font-face {
        font-family: "Vanilla";
        src: url("font.woff2") format("woff2");
      }
      .test {
        font-family: "Vanilla";
        background-image: url("pixel.png");
      }
    </style></head>
    <body><div class="test">Test</div></body>
    )HTML";

const char kStylesheetWithVanillaResources[] = R"CSS(
    @font-face {
      font-family: "Vanilla";
      src: url("font.woff2") format("woff2");
    }
    .test {
      font-family: "Vanilla";
      background-image: url("pixel.png");
    }
    )CSS";
const char kStylesheetWithAdResources[] = R"CSS(
    @font-face {
      font-family: "Ad";
      src: url("font.woff2?ad=true") format("woff2");
    }
    .test {
      font-family: "Ad";
      background-image: url("pixel.png?ad=true");
    }
    )CSS";

class TestAdTracker : public AdTracker {
 public:
  explicit TestAdTracker(LocalFrame* frame) : AdTracker(frame) {}
  void SetScriptAtTopOfStack(const String& url) { script_at_top_ = url; }
  void SetExecutionContext(ExecutionContext* execution_context) {
    execution_context_ = execution_context;
  }

  void SetAdSuffix(const String& ad_suffix) { ad_suffix_ = ad_suffix; }
  ~TestAdTracker() override {}

  void Trace(Visitor* visitor) const override {
    visitor->Trace(execution_context_);
    AdTracker::Trace(visitor);
  }

  bool RequestWithUrlTaggedAsAd(const String& url) const {
    DCHECK(is_ad_.Contains(url));
    return is_ad_.at(url);
  }

  bool UrlHasBeenRequested(const String& url) const {
    return is_ad_.Contains(url);
  }

  void SetSimTest() { sim_test_ = true; }

  void WaitForSubresource(const String& url) {
    if (base::Contains(is_ad_, url)) {
      return;
    }
    url_to_wait_for_ = url;
    base::RunLoop run_loop;
    quit_closure_ = run_loop.QuitClosure();
    run_loop.Run();
  }

 protected:
  String ScriptAtTopOfStack() override {
    if (sim_test_ && !script_at_top_)
      return AdTracker::ScriptAtTopOfStack();
    return script_at_top_;
  }

  ExecutionContext* GetCurrentExecutionContext() override {
    if (!execution_context_)
      return AdTracker::GetCurrentExecutionContext();

    return execution_context_.Get();
  }

  bool CalculateIfAdSubresource(ExecutionContext* execution_context,
                                const KURL& request_url,
                                ResourceType resource_type,
                                const FetchInitiatorInfo& initiator_info,
                                bool ad_request) override {
    if (!ad_suffix_.empty() && request_url.GetString().EndsWith(ad_suffix_)) {
      ad_request = true;
    }

    ad_request = AdTracker::CalculateIfAdSubresource(
        execution_context, request_url, resource_type, initiator_info,
        ad_request);

    String resource_url = request_url.GetString();
    is_ad_.insert(resource_url, ad_request);

    if (quit_closure_ && url_to_wait_for_ == resource_url) {
      std::move(quit_closure_).Run();
    }
    return ad_request;
  }

 private:
  HashMap<String, bool> is_ad_;
  String script_at_top_;
  Member<ExecutionContext> execution_context_;
  String ad_suffix_;
  bool sim_test_ = false;

  base::OnceClosure quit_closure_;
  String url_to_wait_for_;
};

void SetIsAdFrame(LocalFrame* frame) {
  DCHECK(frame);
  blink::FrameAdEvidence ad_evidence(frame->Parent() &&
                                     frame->Parent()->IsAdFrame());
  ad_evidence.set_created_by_ad_script(
      mojom::FrameCreationStackEvidence::kCreatedByAdScript);
  ad_evidence.set_is_complete();
  frame->SetAdEvidence(ad_evidence);
}

}  // namespace

class AdTrackerTest : public testing::Test {
 protected:
  void SetUp() override;
  void TearDown() override;
  LocalFrame* GetFrame() const {
    return page_holder_->GetDocument().GetFrame();
  }

  void CreateAdTracker() {
    if (ad_tracker_)
      ad_tracker_->Shutdown();
    ad_tracker_ = MakeGarbageCollected<TestAdTracker>(GetFrame());
    ad_tracker_->SetExecutionContext(GetExecutionContext());
  }

  void WillExecuteScript(const String& script_url,
                         int script_id = v8::Message::kNoScriptIdInfo) {
    auto* execution_context = GetExecutionContext();
    ad_tracker_->WillExecuteScript(
        execution_context, execution_context->GetIsolate()->GetCurrentContext(),
        String(script_url), script_id);
  }

  ExecutionContext* GetExecutionContext() {
    return page_holder_->GetFrame().DomWindow();
  }

  void DidExecuteScript() { ad_tracker_->DidExecuteScript(); }

  bool AnyExecutingScriptsTaggedAsAdResource() {
    return AnyExecutingScriptsTaggedAsAdResourceWithStackType(
        AdTracker::StackType::kBottomAndTop);
  }

  bool AnyExecutingScriptsTaggedAsAdResourceWithStackType(
      AdTracker::StackType stack_type) {
    return ad_tracker_->IsAdScriptInStack(stack_type);
  }

  std::optional<AdScriptIdentifier> BottommostAdScript() {
    std::optional<AdScriptIdentifier> bottom_most_ad_script;
    ad_tracker_->IsAdScriptInStack(AdTracker::StackType::kBottomAndTop,
                                   /*out_ad_script=*/&bottom_most_ad_script);
    return bottom_most_ad_script;
  }

  void AppendToKnownAdScripts(const String& url) {
    ad_tracker_->AppendToKnownAdScripts(*GetExecutionContext(), url);
  }

  void AppendToKnownAdScripts(int script_id) {
    // Matches AdTracker's inline script encoding
    AppendToKnownAdScripts(String::Format("{ id %d }", script_id));
  }

  test::TaskEnvironment task_environment_;
  Persistent<TestAdTracker> ad_tracker_;
  std::unique_ptr<DummyPageHolder> page_holder_;
};

void AdTrackerTest::SetUp() {
  page_holder_ = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  page_holder_->GetDocument().SetURL(KURL("https://example.com/foo"));
  CreateAdTracker();
}

void AdTrackerTest::TearDown() {
  ad_tracker_->Shutdown();
}

TEST_F(AdTrackerTest, AnyExecutingScriptsTaggedAsAdResource) {
  String ad_script_url("https://example.com/bar.js");
  AppendToKnownAdScripts(ad_script_url);

  WillExecuteScript("https://example.com/foo.js");
  WillExecuteScript("https://example.com/bar.js");
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
}

TEST_F(AdTrackerTest, BottomScriptTaggedAsAdResource) {
  AppendToKnownAdScripts("https://example.com/ad.js");

  WillExecuteScript("https://example.com/ad.js");
  ad_tracker_->SetScriptAtTopOfStack("https://example.com/vanilla.js");
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResourceWithStackType(
      AdTracker::StackType::kBottomAndTop));
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResourceWithStackType(
      AdTracker::StackType::kBottomOnly));
}

TEST_F(AdTrackerTest, TopScriptTaggedAsAdResource) {
  AppendToKnownAdScripts("https://example.com/ad.js");

  WillExecuteScript("https://example.com/vanilla.js");
  ad_tracker_->SetScriptAtTopOfStack("https://example.com/ad.js");

  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResourceWithStackType(
      AdTracker::StackType::kBottomAndTop));
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResourceWithStackType(
      AdTracker::StackType::kBottomOnly));
}

// Tests that if neither script in the stack is an ad,
// AnyExecutingScriptsTaggedAsAdResource should return false.
TEST_F(AdTrackerTest, AnyExecutingScriptsTaggedAsAdResource_False) {
  WillExecuteScript("https://example.com/foo.js");
  WillExecuteScript("https://example.com/bar.js");
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());
}

TEST_F(AdTrackerTest, TopOfStackIncluded) {
  String ad_script_url("https://example.com/ad.js");
  AppendToKnownAdScripts(ad_script_url);

  WillExecuteScript("https://example.com/foo.js");
  WillExecuteScript("https://example.com/bar.js");
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());

  ad_tracker_->SetScriptAtTopOfStack("https://www.example.com/baz.js");
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());

  ad_tracker_->SetScriptAtTopOfStack(ad_script_url);
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResourceWithStackType(
      AdTracker::StackType::kBottomOnly));

  ad_tracker_->SetScriptAtTopOfStack("https://www.example.com/baz.js");
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());

  ad_tracker_->SetScriptAtTopOfStack("");
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());

  ad_tracker_->SetScriptAtTopOfStack(String());
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());

  WillExecuteScript(ad_script_url);
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
}

TEST_F(AdTrackerTest, AdStackFrameCounting) {
  AppendToKnownAdScripts("https://example.com/ad.js");

  WillExecuteScript("https://example.com/vanilla.js");
  WillExecuteScript("https://example.com/vanilla.js");
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());

  WillExecuteScript("https://example.com/ad.js");
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());

  DidExecuteScript();
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());

  WillExecuteScript("https://example.com/ad.js");
  WillExecuteScript("https://example.com/ad.js");
  WillExecuteScript("https://example.com/vanilla.js");
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());

  DidExecuteScript();
  DidExecuteScript();
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());

  DidExecuteScript();
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());

  DidExecuteScript();
  DidExecuteScript();
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());

  WillExecuteScript("https://example.com/ad.js");
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
}

TEST_F(AdTrackerTest, AsyncTagging) {
  CreateAdTracker();

  // Put an ad script on the stack.
  AppendToKnownAdScripts("https://example.com/ad.js");
  WillExecuteScript("https://example.com/ad.js");
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());

  // Create a fake task void*.
  probe::AsyncTaskContext async_task_context;

  // Create an async task while ad script is running.
  ad_tracker_->DidCreateAsyncTask(&async_task_context);

  // Finish executing the ad script.
  DidExecuteScript();
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());

  // Start and stop the async task created by the ad script.
  ad_tracker_->DidStartAsyncTask(&async_task_context);
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
  ad_tracker_->DidFinishAsyncTask(&async_task_context);
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());

  // Do it again.
  ad_tracker_->DidStartAsyncTask(&async_task_context);
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
  ad_tracker_->DidFinishAsyncTask(&async_task_context);
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());

  // Call the task recursively.
  ad_tracker_->DidStartAsyncTask(&async_task_context);
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
  ad_tracker_->DidStartAsyncTask(&async_task_context);
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
  ad_tracker_->DidFinishAsyncTask(&async_task_context);
  EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
  ad_tracker_->DidFinishAsyncTask(&async_task_context);
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());
}

TEST_F(AdTrackerTest, BottommostAdScript) {
  AppendToKnownAdScripts("https://example.com/ad.js");
  AppendToKnownAdScripts("https://example.com/ad2.js");
  AppendToKnownAdScripts(/*script_id=*/5);
  EXPECT_FALSE(BottommostAdScript().has_value());

  WillExecuteScript("https://example.com/vanilla.js", /*script_id=*/1);
  EXPECT_FALSE(BottommostAdScript().has_value());

  WillExecuteScript("https://example.com/ad.js", /*script_id=*/2);
  ASSERT_TRUE(BottommostAdScript().has_value());
  EXPECT_EQ(BottommostAdScript()->id, 2);

  // Additional scripts (ad or not) don't change the bottommost ad script.
  WillExecuteScript("https://example.com/vanilla.js", /*script_id=*/3);
  ASSERT_TRUE(BottommostAdScript().has_value());
  EXPECT_EQ(BottommostAdScript()->id, 2);
  DidExecuteScript();

  WillExecuteScript("https://example.com/ad2.js", /*script_id=*/4);
  ASSERT_TRUE(BottommostAdScript().has_value());
  EXPECT_EQ(BottommostAdScript()->id, 2);
  DidExecuteScript();

  // The bottommost ad script can have an empty name.
  DidExecuteScript();
  EXPECT_FALSE(BottommostAdScript().has_value());

  WillExecuteScript("", /*script_id=*/5);
  ASSERT_TRUE(BottommostAdScript().has_value());
  EXPECT_EQ(BottommostAdScript()->id, 5);
}

TEST_F(AdTrackerTest, BottommostAsyncAdScript) {
  CreateAdTracker();

  // Put an ad script on the stack.
  AppendToKnownAdScripts("https://example.com/ad.js");
  AppendToKnownAdScripts("https://example.com/ad2.js");

  EXPECT_FALSE(BottommostAdScript().has_value());

  // Create a couple of async tasks while ad script is running.
  WillExecuteScript("https://example.com/ad.js", 1);
  probe::AsyncTaskContext async_task_context1;
  ad_tracker_->DidCreateAsyncTask(&async_task_context1);
  DidExecuteScript();
  EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());

  WillExecuteScript("https://example.com/ad2.js", 2);
  probe::AsyncTaskContext async_task_context2;
  ad_tracker_->DidCreateAsyncTask(&async_task_context2);
  DidExecuteScript();

  // Start and stop the async task created by the ad script.
  {
    ad_tracker_->DidStartAsyncTask(&async_task_context1);
    EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
    EXPECT_TRUE(BottommostAdScript().has_value());
    EXPECT_EQ(BottommostAdScript()->id, 1);

    ad_tracker_->DidFinishAsyncTask(&async_task_context1);
    EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());
    EXPECT_FALSE(BottommostAdScript().has_value());
  }

  // Run two async tasks
  {
    ad_tracker_->DidStartAsyncTask(&async_task_context1);
    EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
    EXPECT_TRUE(BottommostAdScript().has_value());
    EXPECT_EQ(BottommostAdScript()->id, 1);

    ad_tracker_->DidStartAsyncTask(&async_task_context2);
    EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
    EXPECT_TRUE(BottommostAdScript().has_value());
    EXPECT_EQ(BottommostAdScript()->id, 1);

    ad_tracker_->DidFinishAsyncTask(&async_task_context2);
    EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
    EXPECT_TRUE(BottommostAdScript().has_value());
    EXPECT_EQ(BottommostAdScript()->id, 1);

    ad_tracker_->DidFinishAsyncTask(&async_task_context1);
    EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());
    EXPECT_FALSE(BottommostAdScript().has_value());
  }

  // Run an async task followed by sync.
  {
    ad_tracker_->DidStartAsyncTask(&async_task_context2);
    EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
    EXPECT_TRUE(BottommostAdScript().has_value());
    EXPECT_EQ(BottommostAdScript()->id, 2);

    WillExecuteScript("https://example.com/ad.js");
    EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
    EXPECT_TRUE(BottommostAdScript().has_value());
    EXPECT_EQ(BottommostAdScript()->id, 2);

    ad_tracker_->DidStartAsyncTask(&async_task_context1);
    EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
    EXPECT_TRUE(BottommostAdScript().has_value());
    EXPECT_EQ(BottommostAdScript()->id, 2);

    ad_tracker_->DidFinishAsyncTask(&async_task_context1);
    EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
    EXPECT_TRUE(BottommostAdScript().has_value());
    EXPECT_EQ(BottommostAdScript()->id, 2);

    DidExecuteScript();
    EXPECT_TRUE(AnyExecutingScriptsTaggedAsAdResource());
    EXPECT_TRUE(BottommostAdScript().has_value());
    EXPECT_EQ(BottommostAdScript()->id, 2);

    ad_tracker_->DidFinishAsyncTask(&async_task_context2);
    EXPECT_FALSE(AnyExecutingScriptsTaggedAsAdResource());
    EXPECT_FALSE(BottommostAdScript().has_value());
  }
}

class AdTrackerSimTest : public SimTest {
 protected:
  void SetUp() override {
    SimTest::SetUp();
    main_resource_ = std::make_unique<SimRequest>(
        "https://example.com/test.html", "text/html");

    LoadURL("https://example.com/test.html");
    ad_tracker_ = MakeGarbageCollected<TestAdTracker>(GetDocument().GetFrame());
    ad_tracker_->SetSimTest();
    GetDocument().GetFrame()->SetAdTrackerForTesting(ad_tracker_);
  }

  void TearDown() override {
    ad_tracker_->Shutdown();
    SimTest::TearDown();
  }

  bool IsKnownAdScript(ExecutionContext* execution_context, const String& url) {
    return ad_tracker_->IsKnownAdScript(execution_context, url);
  }

  std::unique_ptr<SimRequest> main_resource_;
  Persistent<TestAdTracker> ad_tracker_;
};

// Script loaded by ad script is tagged as ad.
TEST_F(AdTrackerSimTest, ScriptLoadedWhileExecutingAdScript) {
  const char kAdUrl[] = "https://example.com/ad_script.js";
  const char kVanillaUrl[] = "https://example.com/vanilla_script.js";
  SimSubresourceRequest ad_resource(kAdUrl, "text/javascript");
  SimSubresourceRequest vanilla_script(kVanillaUrl, "text/javascript");

  ad_tracker_->SetAdSuffix("ad_script.js");

  main_resource_->Complete("<body></body><script src=ad_script.js></script>");

  ad_resource.Complete(R"SCRIPT(
    script = document.createElement("script");
    script.src = "vanilla_script.js";
    document.body.appendChild(script);
    )SCRIPT");

  // Wait for script to run.
  base::RunLoop().RunUntilIdle();

  vanilla_script.Complete("");

  EXPECT_TRUE(IsKnownAdScript(GetDocument().GetExecutionContext(), kAdUrl));
  EXPECT_TRUE(
      IsKnownAdScript(GetDocument().GetExecutionContext(), kVanillaUrl));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(kAdUrl));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(kVanillaUrl));
}

// Unknown script running in an ad context should be labeled as ad script.
TEST_F(AdTrackerSimTest, ScriptDetectedByContext) {
  // Create an iframe that's considered an ad.
  main_resource_->Complete("<body><iframe></iframe></body>");
  auto* child_frame =
      To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild());
  SetIsAdFrame(child_frame);

  // Now run unknown script in the child's context. It should be considered an
  // ad based on context alone.
  ad_tracker_->SetExecutionContext(child_frame->DomWindow());
  ad_tracker_->SetScriptAtTopOfStack("foo.js");
  EXPECT_TRUE(
      ad_tracker_->IsAdScriptInStack(AdTracker::StackType::kBottomAndTop));
}

TEST_F(AdTrackerSimTest, EventHandlerForPostMessageFromAdFrame_NoAdInStack) {
  const char kAdScriptUrl[] = "https://example.com/ad_script.js";
  SimSubresourceRequest ad_script(kAdScriptUrl, "text/javascript");
  const char kVanillaUrl[] = "https://example.com/vanilla_script.js";
  SimSubresourceRequest vanilla_script(kVanillaUrl, "text/javascript");

  SimSubresourceRequest image_resource("https://example.com/image.gif",
                                       "image/gif");

  ad_tracker_->SetAdSuffix("ad_script.js");

  // Create an iframe that's considered an ad.
  main_resource_->Complete(R"(<body>
    <script src='vanilla_script.js'></script>
    <script src='ad_script.js'></script>
    </body>)");

  // Register a postMessage handler which is not considered to be ad script,
  // which loads an image.
  vanilla_script.Complete(R"SCRIPT(
    window.addEventListener('message', e => {
      image = document.createElement("img");
      image.src = "image.gif";
      document.body.appendChild(image);
    });)SCRIPT");

  // Post message from an ad iframe to the non-ad script in the parent frame.
  ad_script.Complete(R"SCRIPT(
    frame = document.createElement("iframe");
    document.body.appendChild(frame);
    iframeDocument = frame.contentWindow.document;
    iframeDocument.open();
    iframeDocument.write(
      "<html><script>window.parent.postMessage('a', '*');</script></html>");
    iframeDocument.close();
    )SCRIPT");

  // Wait for script to run.
  base::RunLoop().RunUntilIdle();

  image_resource.Complete("data");

  // The image should not be considered an ad even if it was loaded in response
  // to an ad initiated postMessage.
  EXPECT_FALSE(
      ad_tracker_->RequestWithUrlTaggedAsAd("https://example.com/image.gif"));
}

TEST_F(AdTrackerSimTest, RedirectToAdUrl) {
  SimRequest::Params params;
  params.redirect_url = "https://example.com/ad_script.js";
  SimSubresourceRequest redirect_script(
      "https://example.com/redirect_script.js", "text/javascript", params);
  SimSubresourceRequest ad_script("https://example.com/ad_script.js",
                                  "text/javascript");

  ad_tracker_->SetAdSuffix("ad_script.js");

  main_resource_->Complete(
      "<body><script src='redirect_script.js'></script></body>");

  ad_script.Complete("");

  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(
      "https://example.com/redirect_script.js"));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(
      "https://example.com/ad_script.js"));
}

TEST_F(AdTrackerSimTest, AdResourceDetectedByContext) {
  SimRequest ad_frame("https://example.com/ad_frame.html", "text/html");
  SimSubresourceRequest foo_css("https://example.com/foo.css", "text/style");

  // Create an iframe that's considered an ad.
  main_resource_->Complete(
      "<body><iframe src='ad_frame.html'></iframe></body>");
  auto* child_frame =
      To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild());
  SetIsAdFrame(child_frame);

  // Load a resource from the frame. It should be detected as an ad resource due
  // to its context.
  ad_frame.Complete(R"HTML(
    <link rel="stylesheet" href="foo.css">
    )HTML");

  foo_css.Complete("");

  EXPECT_TRUE(
      ad_tracker_->RequestWithUrlTaggedAsAd("https://example.com/foo.css"));
}

// When inline script in an ad frame inserts an iframe into a non-ad frame, the
// new frame should be considered as created by ad script (and would therefore
// be tagged as an ad).
TEST_F(AdTrackerSimTest, InlineAdScriptRunningInNonAdContext) {
  SimSubresourceRequest ad_script("https://example.com/ad_script.js",
                                  "text/javascript");
  SimRequest ad_iframe("https://example.com/ad_frame.html", "text/html");
  ad_tracker_->SetAdSuffix("ad_script.js");

  main_resource_->Complete("<body><script src='ad_script.js'></script></body>");
  ad_script.Complete(R"SCRIPT(
    frame = document.createElement("iframe");
    frame.src = "ad_frame.html";
    document.body.appendChild(frame);
    )SCRIPT");

  // Wait for script to run.
  base::RunLoop().RunUntilIdle();

  auto* child_frame =
      To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild());

  // Verify that the new frame is considered created by ad script then set it
  // as an ad subframe. This emulates the embedder tagging a frame as an ad.
  EXPECT_TRUE(child_frame->IsFrameCreatedByAdScript());
  SetIsAdFrame(child_frame);

  // Create a new sibling frame to the ad frame. The ad context calls the non-ad
  // context's (top frame) appendChild.
  ad_iframe.Complete(R"HTML(
    <script>
      frame = document.createElement("iframe");
      frame.name = "ad_sibling";
      parent.document.body.appendChild(frame);
    </script>
    )HTML");

  // The new sibling frame should also be identified as created by ad script.
  EXPECT_TRUE(To<LocalFrame>(GetDocument().GetFrame()->Tree().ScopedChild(
                                 AtomicString("ad_sibling")))
                  ->IsFrameCreatedByAdScript());
}

// Image loaded by ad script is tagged as ad.
TEST_F(AdTrackerSimTest, ImageLoadedWhileExecutingAdScriptAsyncEnabled) {
  // Reset the AdTracker so that it gets the latest base::Feature value on
  // construction.
  ad_tracker_ = MakeGarbageCollected<TestAdTracker>(GetDocument().GetFrame());
  GetDocument().GetFrame()->SetAdTrackerForTesting(ad_tracker_);

  const char kAdUrl[] = "https://example.com/ad_script.js";
  const char kVanillaUrl[] = "https://example.com/vanilla_image.gif";
  SimSubresourceRequest ad_resource(kAdUrl, "text/javascript");
  SimSubresourceRequest vanilla_image(kVanillaUrl, "image/gif");

  ad_tracker_->SetAdSuffix("ad_script.js");

  main_resource_->Complete("<body></body><script src=ad_script.js></script>");

  ad_resource.Complete(R"SCRIPT(
    image = document.createElement("img");
    image.src = "vanilla_image.gif";
    document.body.appendChild(image);
    )SCRIPT");

  // Wait for script to run.
  base::RunLoop().RunUntilIdle();

  // Put the gif bytes in a Vector to avoid difficulty with
  // non null-terminated char*.
  Vector<char> gif;
  gif.Append(kSmallGifData, sizeof(kSmallGifData));

  vanilla_image.Complete(gif);

  EXPECT_TRUE(IsKnownAdScript(GetDocument().GetExecutionContext(), kAdUrl));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(kAdUrl));

  // Image loading is async, so we should catch this when async stacks are
  // monitored.
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(kVanillaUrl));

  // Walk through the DOM to get the image element.
  Element* doc_element = GetDocument().documentElement();
  Element* body_element = Traversal<Element>::LastChild(*doc_element);
  HTMLImageElement* image_element =
      Traversal<HTMLImageElement>::FirstChild(*body_element);

  // When async stacks are monitored, we should also tag the
  // HTMLImageElement as ad-related.
  ASSERT_TRUE(image_element);
  EXPECT_TRUE(image_element->IsAdRelated());
}

// Image loaded by ad script is tagged as ad.
TEST_F(AdTrackerSimTest, DataURLImageLoadedWhileExecutingAdScriptAsyncEnabled) {
  // Reset the AdTracker so that it gets the latest base::Feature value on
  // construction.
  ad_tracker_ = MakeGarbageCollected<TestAdTracker>(GetDocument().GetFrame());
  GetDocument().GetFrame()->SetAdTrackerForTesting(ad_tracker_);

  const char kAdUrl[] = "https://example.com/ad_script.js";
  SimSubresourceRequest ad_resource(kAdUrl, "text/javascript");

  ad_tracker_->SetAdSuffix("ad_script.js");

  main_resource_->Complete("<body></body><script src=ad_script.js></script>");

  ad_resource.Complete(R"SCRIPT(
    image = document.createElement("img");
    image.src = "data:image/gif;base64,R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs=";
    document.body.appendChild(image);
    )SCRIPT");

  // Wait for script to run.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(IsKnownAdScript(GetDocument().GetExecutionContext(), kAdUrl));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(kAdUrl));

  // Walk through the DOM to get the image element.
  Element* doc_element = GetDocument().documentElement();
  Element* body_element = Traversal<Element>::LastChild(*doc_element);
  HTMLImageElement* image_element =
      Traversal<HTMLImageElement>::FirstChild(*body_element);

  // When async stacks are monitored, we should also tag the
  // HTMLImageElement as ad-related.
  ASSERT_TRUE(image_element);
  EXPECT_TRUE(image_element->IsAdRelated());
}

// Frame loaded by ad script is considered created by ad script.
TEST_F(AdTrackerSimTest, FrameLoadedWhileExecutingAdScript) {
  const char kAdUrl[] = "https://example.com/ad_script.js";
  const char kVanillaUrl[] = "https://example.com/vanilla_page.html";
  const char kVanillaImgUrl[] = "https://example.com/vanilla_img.jpg";
  SimSubresourceRequest ad_resource(kAdUrl, "text/javascript");
  SimRequest vanilla_page(kVanillaUrl, "text/html");
  SimSubresourceRequest vanilla_image(kVanillaImgUrl, "image/jpeg");

  ad_tracker_->SetAdSuffix("ad_script.js");

  main_resource_->Complete("<body></body><script src=ad_script.js></script>");

  ad_resource.Complete(R"SCRIPT(
    iframe = document.createElement("iframe");
    iframe.src = "vanilla_page.html";
    document.body.appendChild(iframe);
    )SCRIPT");

  // Wait for script to run.
  base::RunLoop().RunUntilIdle();

  auto* child_frame =
      To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild());

  // Verify that the new frame is considered created by ad script then set it
  // as an ad subframe. This emulates the SubresourceFilterAgent's tagging.
  EXPECT_TRUE(child_frame->IsFrameCreatedByAdScript());
  SetIsAdFrame(child_frame);

  vanilla_page.Complete("<img src=vanilla_img.jpg></img>");
  vanilla_image.Complete("");

  EXPECT_TRUE(IsKnownAdScript(GetDocument().GetExecutionContext(), kAdUrl));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(kAdUrl));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(kVanillaImgUrl));
}

// A script tagged as an ad in one frame shouldn't cause it to be considered
// an ad when executed in another frame.
TEST_F(AdTrackerSimTest, Contexts) {
  // Load a page that loads library.js. It also creates an iframe that also
  // loads library.js (where it gets tagged as an ad). Even though library.js
  // gets tagged as an ad script in the subframe, that shouldn't cause it to
  // be treated as an ad in the main frame.
  SimRequest iframe_resource("https://example.com/iframe.html", "text/html");
  SimSubresourceRequest library_resource("https://example.com/library.js",
                                         "text/javascript");

  main_resource_->Complete(R"HTML(
    <script src=library.js></script>
    <iframe src=iframe.html></iframe>
    )HTML");

  // Complete the main frame's library.js.
  library_resource.Complete("");

  // The library script is loaded for a second time, this time in the
  // subframe. Mark it as an ad.
  SimSubresourceRequest library_resource_for_subframe(
      "https://example.com/library.js", "text/javascript");
  ad_tracker_->SetAdSuffix("library.js");

  iframe_resource.Complete(R"HTML(
    <script src="library.js"></script>
    )HTML");
  library_resource_for_subframe.Complete("");

  // Verify that library.js is an ad script in the subframe's context but not
  // in the main frame's context.
  Frame* subframe = GetDocument().GetFrame()->Tree().FirstChild();
  auto* local_subframe = To<LocalFrame>(subframe);
  EXPECT_TRUE(
      IsKnownAdScript(local_subframe->GetDocument()->GetExecutionContext(),
                      String("https://example.com/library.js")));

  EXPECT_FALSE(IsKnownAdScript(GetDocument().GetExecutionContext(),
                               String("https://example.com/library.js")));
}

TEST_F(AdTrackerSimTest, SameOriginSubframeFromAdScript) {
  SimSubresourceRequest ad_resource("https://example.com/ad_script.js",
                                    "text/javascript");
  SimRequest iframe_resource("https://example.com/iframe.html", "text/html")
```