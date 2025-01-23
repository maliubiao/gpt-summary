Response:
The user wants a summary of the provided C++ code snippet from a Chromium Blink engine file. I need to identify the functionalities demonstrated in the code and explain their relevance to web technologies (JavaScript, HTML, CSS). I should also look for examples of logical reasoning within the tests (input/output) and potential user/programming errors. Finally, I need to summarize the overall purpose of this specific part of the file, considering it's the 16th part of 19.

Here's a breakdown of the code's functionalities:

1. **Global object reuse:** Tests related to whether the JavaScript global object is reused across navigations in different frame scenarios (main frame with/without opener, child frames). This is directly related to JavaScript execution and security.

2. **Saving images from data URLs:**  Tests involving saving images referenced by data URLs. This involves handling blob registration and download requests, linking to how browsers handle image resources and the `data:` URL scheme.

3. **Saving images with image maps:** Tests focused on saving images that have associated image maps. This relates to HTML's `<map>` and `<area>` elements and how they interact with image saving.

4. **Loading JavaScript URLs:** Tests how the browser handles navigation triggered by `javascript:` URLs. This is a core JavaScript execution mechanism within the browser.

5. **Discarding frames:** Tests the functionality of discarding a frame, which clears its content. This is related to the browser's frame management.

6. **Empty JavaScript frame URLs:**  Tests how iframes with empty `javascript:` URLs are handled. This is a specific edge case in JavaScript URL handling within iframes.

7. **Resource priority:** Tests how the browser prioritizes resource loading based on factors like being in the viewport or the type of script tag (`async`, `defer`). This is related to browser performance optimization when loading HTML, CSS, and JavaScript.

8. **Handling image decode errors:** Tests how the browser handles cases where an image resource cannot be decoded. This is part of the browser's resource loading and error handling for image formats.

9. **Root layer minimum height:** Tests that the root layout maintains a minimum height corresponding to the viewport even if content is smaller. This is related to CSS layout and viewport handling, especially on mobile.

10. **Scrolling before layout:** Tests that scrolling actions don't cause crashes even if the layout hasn't been performed yet. This relates to the robustness of the browser's rendering pipeline.

11. **Clearing tooltips on mouseover:** Tests that tooltips are correctly cleared when the mouse moves to a different element. This relates to how browsers handle UI interactions and tooltip display.

12. **Hit testing with clipping:** Tests how hit testing works when considering or ignoring clipping boundaries, particularly at negative offsets. This is relevant to event handling and element selection within the browser's rendering.

13. **Find in page functionality:** Tests the "find in page" feature, including getting tickmarks for matches and selecting the next match. This relates to browser user interface elements and text searching within web pages.

Based on these functionalities, the overall purpose of this section seems to be testing various aspects of `WebFrame`'s behavior related to resource loading, JavaScript execution, layout, user interaction, and frame management within the Blink rendering engine.
这是 `blink/renderer/core/frame/web_frame_test.cc` 文件的第 16 部分，主要关注于 `WebFrame` 类的各种功能测试，特别是与页面导航、资源加载、JavaScript 执行、用户交互以及框架生命周期管理相关的方面。

以下是该部分代码的具体功能及其与 JavaScript、HTML 和 CSS 的关系，以及逻辑推理和常见错误的示例：

**功能列表:**

1. **测试全局对象重用策略:**  这部分代码测试了 Blink 引擎在不同场景下是否重用 JavaScript 全局对象 (global object) 的策略。
    * **与 JavaScript 的关系:**  JavaScript 代码在全局对象上定义变量和函数。如果全局对象被重用，这些变量和函数在导航后仍然存在。
    * **与 HTML 的关系:** 这涉及到不同 HTML 页面之间的导航和框架（iframe）的加载。
    * **逻辑推理:**
        * **假设输入:**  一个主框架加载了一个页面，定义了一个全局变量。然后导航到另一个同源或跨域的页面。
        * **预期输出:** 根据配置和框架类型，全局变量可能存在或不存在于新页面的 JavaScript 上下文中。例如，无 opener 的主框架在初始导航时不应重用全局对象。
    * **举例说明:**
        ```javascript
        // 初始页面
        window.myGlobal = 'hello';
        ```
        导航后，测试会检查 `window.myGlobal` 是否仍然存在。

2. **测试保存 Data URL 图像:**  测试了 `SaveImageAt` 功能，该功能允许用户通过点击坐标来保存图片，特别是当图片资源是 Data URL 时。
    * **与 HTML 的关系:**  HTML `<img>` 标签可以包含 Data URL 作为 `src` 属性。
    * **与 CSS 的关系:**  CSS 样式也可以使用 Data URL 作为背景图片。
    * **与 JavaScript 的关系:** JavaScript 可以动态创建包含 Data URL 的 `<img>` 元素。
    * **逻辑推理:**
        * **假设输入:**  一个包含 Data URL 图片的 HTML 页面，以及一个点击坐标。
        * **预期输出:**  `DownloadURL` 方法会被调用，并且传递的 `data_url_blob` 包含原始 Data URL 的内容。测试通过 `TestLocalFrameHostForSaveImageFromDataURL` 拦截 `DownloadURL` 调用并验证 Data URL 的内容。
    * **举例说明:**  页面包含 `<img src="data:image/gif;base64,...">`，测试点击图片上的某个点，验证保存操作是否正确提取了 Data URL。

3. **测试保存带有 Image Map 的图像:** 测试了 `SaveImageAt` 功能在处理带有 `<map>` 标签定义的图像映射时的行为。
    * **与 HTML 的关系:**  `<map>` 和 `<area>` 标签定义了图片的不同区域及其链接。
    * **逻辑推理:**
        * **假设输入:**  一个带有 `<map>` 的 HTML 页面，以及图片上不同区域的点击坐标。
        * **预期输出:**  只有点击到实际图像部分时，才会触发保存操作，点击到 `<area>` 定义的链接区域则不会。
    * **举例说明:**  页面包含一个带有 image map 的图片，测试点击图像的不同区域，验证是否只在图像本身被点击时才触发保存。

4. **测试加载 JavaScript URL:** 测试了通过 `LoadJavaScriptURL` 方法加载 `javascript:` URL 的行为。
    * **与 JavaScript 的关系:** `javascript:` URL 允许在浏览器地址栏或链接中执行 JavaScript 代码。
    * **逻辑推理:**
        * **假设输入:**  一个包含 `javascript:` URL 的字符串。
        * **预期输出:**  浏览器会执行该 JavaScript 代码，通常会导致页面导航或修改当前页面。
    * **举例说明:**  测试加载 `javascript:location='http://example.com'`，验证页面是否导航到 `http://example.com`。

5. **测试丢弃 Frame:** 测试了 `Discard` 方法，该方法用于清除框架的内容。
    * **与 HTML 的关系:**  丢弃框架会移除其加载的 HTML 内容。
    * **逻辑推理:**
        * **假设输入:**  一个已经加载内容的框架。
        * **预期输出:**  框架的文档内容会被清空。
    * **举例说明:**  加载一个包含文本的页面，然后调用 `Discard`，验证页面内容是否为空。

6. **测试空的 JavaScript Frame URL:** 测试了 `<iframe>` 的 `src` 属性设置为 `javascript:''` 的情况。
    * **与 JavaScript 的关系:**  这是一个特殊的 `javascript:` URL 用法。
    * **与 HTML 的关系:**  涉及到 `<iframe>` 标签。
    * **逻辑推理:**
        * **假设输入:**  一个包含 `<iframe src="javascript:''"></iframe>` 的 HTML 页面。
        * **预期输出:**  子框架的 URL 应该是 `about:blank`。

7. **测试更改资源优先级:**  测试了在页面加载过程中动态更改资源加载优先级的功能。
    * **与 HTML 的关系:**  这涉及到 HTML 中引用的各种资源，如图片和脚本。
    * **与 JavaScript 的关系:** JavaScript 可以触发资源加载。
    * **逻辑推理:**
        * **假设输入:**  一个包含图片的 HTML 页面，其中某些图片在视口内，某些在视口外。
        * **预期输出:**  视口内的图片资源优先级应该被提升。
    * **举例说明:**  页面加载时，视口内的图片的请求优先级会高于视口外的图片。

8. **测试脚本优先级:** 测试了不同类型的脚本标签（如 `defer`, `async`, 头部脚本, `document.write` 脚本, 动态注入的脚本）的加载优先级。
    * **与 HTML 的关系:**  涉及到 `<script>` 标签的不同属性和位置。
    * **与 JavaScript 的关系:**  脚本的加载和执行顺序影响 JavaScript 代码的行为。
    * **逻辑推理:**
        * **假设输入:**  一个包含各种类型 `<script>` 标签的 HTML 页面。
        * **预期输出:**  不同类型的脚本应该按照预期的优先级进行加载。

9. **测试图片文档解码错误:** 测试了当加载的资源不是有效的图片格式时，`ImageDocument` 的处理情况。
    * **与 HTML 的关系:**  当浏览器尝试将一个非图片资源作为 `ImageDocument` 加载时。
    * **逻辑推理:**
        * **假设输入:**  加载一个 `Content-Type` 为 `image/x-icon` 但内容不是有效 ICO 文件的资源。
        * **预期输出:**  `ImageDocument` 会进入解码错误状态。

10. **测试根层最小高度:** 测试了根布局视图 (root LayoutView) 是否保持与视口 (viewport) 匹配的最小高度，即使内容比视口小。
    * **与 HTML 的关系:**  涉及到页面的结构。
    * **与 CSS 的关系:**  涉及到 CSS 布局和视口元标签。
    * **逻辑推理:**
        * **假设输入:**  一个内容高度小于视口高度的页面。
        * **预期输出:**  根布局视图的高度应该等于视口高度。

11. **测试布局前滚动不崩溃:** 测试了在布局发生之前尝试滚动页面是否会导致崩溃。
    * **与 HTML 的关系:** 涉及到页面的加载和渲染流程。
    * **与 JavaScript 的关系:** JavaScript 可以触发滚动操作。
    * **逻辑推理:**
        * **假设输入:**  一个页面被加载，但在布局完成之前尝试触发滚动事件。
        * **预期输出:**  不应该发生崩溃。

12. **测试鼠标悬停在不同节点上清除工具提示:** 测试了当鼠标从一个带有 `title` 属性的元素移动到另一个元素时，浏览器的工具提示是否会正确更新。
    * **与 HTML 的关系:**  涉及到元素的 `title` 属性。
    * **逻辑推理:**
        * **假设输入:**  鼠标首先悬停在一个带有 `title` 属性的 `div` 上，然后移动到另一个带有 `title` 属性的 `div` 上。
        * **预期输出:**  工具提示会从第一个 `div` 的标题更新为第二个 `div` 的标题。

13. **测试忽略裁剪的命中测试:** 测试了在执行命中测试 (hit testing) 时忽略裁剪区域的情况，特别是在负偏移量的情况下。
    * **与 HTML 的关系:** 涉及到页面元素的布局和位置。
    * **与 CSS 的关系:**  元素的 `position` 和 `overflow` 属性会影响裁剪。
    * **逻辑推理:**
        * **假设输入:**  鼠标坐标位于一个被裁剪的元素区域内，但目标元素在裁剪区域外。
        * **预期输出:**  如果设置了忽略裁剪，命中测试应该返回目标元素。

14. **测试文档相对的标记点 (Tickmarks):** 测试了 "在页面中查找" 功能的标记点是否相对于文档进行定位，即使页面已经滚动。
    * **与 HTML 的关系:**  涉及到页面内容。
    * **与 JavaScript 的关系:**  "在页面中查找" 功能通常通过 JavaScript 实现。
    * **逻辑推理:**
        * **假设输入:**  一个可以滚动的页面，其中包含要查找的文本，并且页面已经滚动了一定距离。
        * **预期输出:**  查找结果的标记点应该相对于文档的起始位置，而不是视口的起始位置。

15. **测试 "在页面中查找" 功能的选择下一个匹配项 (Android 特定):**  测试了在 Android 平台上 "在页面中查找" 功能选择下一个匹配项的行为。
    * **与 HTML 的关系:**  涉及到页面内容。
    * **与 JavaScript 的关系:**  "在页面中查找" 功能通常通过 JavaScript 实现。
    * **逻辑推理:**
        * **假设输入:**  一个包含多个匹配项的页面，并且已经找到一个匹配项。
        * **预期输出:**  调用 "选择下一个匹配项" 后，浏览器应该滚动到并高亮显示下一个匹配项。

**用户或编程常见的使用错误示例:**

* **全局对象重用:**  开发者可能错误地假设全局变量在页面导航后仍然存在，导致代码在新页面上运行时出现错误。例如，在一个页面中设置了 `window.myVar = 1;`，并在另一个页面中直接使用而没有检查其是否存在。
* **Data URL 处理:**  开发者可能错误地构造或解码 Data URL，导致图片无法加载或保存失败。
* **Image Map 坐标错误:**  在定义 `<area>` 标签时，开发者可能提供错误的坐标，导致链接区域不正确。
* **JavaScript URL 的滥用:**  过度或不恰当使用 `javascript:` URL 可能导致安全问题或难以维护的代码。

**归纳一下它的功能:**

这部分 `web_frame_test.cc` 主要集中在对 `WebFrame` 的行为进行细致的单元测试，涵盖了从基础的页面导航和资源加载，到更复杂的 JavaScript 执行环境、用户交互和框架生命周期管理。 这些测试确保了 Blink 引擎在处理各种 Web 技术（HTML, CSS, JavaScript）时的正确性和鲁棒性，并验证了其在不同场景下的预期行为。 作为总共 19 个部分中的第 16 部分，它表明测试范围已经相当深入，正在涵盖各种边缘情况和特定功能的细节。

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第16部分，共19部分，请归纳一下它的功能
```

### 源代码
```cpp
ldReuseGlobalForUnownedMainFrame(true);
}

// A main frame with no opener should have a unique security origin. Thus, the
// global should never be reused on the initial navigation.
TEST(WebFrameGlobalReuseTest, MainFrameWithNoOpener) {
  test::TaskEnvironment task_environment;
  frame_test_helpers::WebViewHelper helper;
  helper.Initialize();

  WebLocalFrame* main_frame = helper.LocalMainFrame();
  v8::HandleScope scope(helper.GetAgentGroupScheduler().Isolate());
  main_frame->ExecuteScript(WebScriptSource("hello = 'world';"));
  frame_test_helpers::LoadFrame(main_frame, "data:text/html,new page");
  v8::Local<v8::Value> result =
      main_frame->ExecuteScriptAndReturnValue(WebScriptSource("hello"));
  EXPECT_TRUE(result.IsEmpty());
}

// Child frames should never reuse the global on a cross-origin navigation, even
// if the setting is enabled. It's not safe to since the parent could have
// injected script before the initial navigation.
TEST(WebFrameGlobalReuseTest, ChildFrame) {
  test::TaskEnvironment task_environment;
  frame_test_helpers::WebViewHelper helper;
  helper.Initialize(nullptr, nullptr, EnableGlobalReuseForUnownedMainFrames);

  WebLocalFrame* main_frame = helper.LocalMainFrame();
  frame_test_helpers::LoadFrame(main_frame, "data:text/html,<iframe></iframe>");

  WebLocalFrame* child_frame = main_frame->FirstChild()->ToWebLocalFrame();
  v8::HandleScope scope(helper.GetAgentGroupScheduler().Isolate());
  child_frame->ExecuteScript(WebScriptSource("hello = 'world';"));
  frame_test_helpers::LoadFrame(child_frame, "data:text/html,new page");
  v8::Local<v8::Value> result =
      child_frame->ExecuteScriptAndReturnValue(WebScriptSource("hello"));
  EXPECT_TRUE(result.IsEmpty());
}

// A main frame with an opener should never reuse the global on a cross-origin
// navigation, even if the setting is enabled. It's not safe to since the opener
// could have injected script.
TEST(WebFrameGlobalReuseTest, MainFrameWithOpener) {
  test::TaskEnvironment task_environment;
  frame_test_helpers::WebViewHelper opener_helper;
  opener_helper.Initialize();
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeWithOpener(opener_helper.GetWebView()->MainFrame(), nullptr,
                              nullptr, EnableGlobalReuseForUnownedMainFrames);

  WebLocalFrame* main_frame = helper.LocalMainFrame();
  v8::HandleScope scope(helper.GetAgentGroupScheduler().Isolate());
  main_frame->ExecuteScript(WebScriptSource("hello = 'world';"));
  frame_test_helpers::LoadFrame(main_frame, "data:text/html,new page");
  v8::Local<v8::Value> result =
      main_frame->ExecuteScriptAndReturnValue(WebScriptSource("hello"));
  EXPECT_TRUE(result.IsEmpty());
}

// A main frame that is unrelated to any other frame /can/ reuse the global if
// the setting is enabled. In this case, it's impossible for any other frames to
// have touched the global. Only the embedder could have injected script, and
// the embedder enabling this setting is a signal that the injected script needs
// to persist on the first navigation away from the initial empty document.
TEST(WebFrameGlobalReuseTest, ReuseForMainFrameIfEnabled) {
  test::TaskEnvironment task_environment;
  frame_test_helpers::WebViewHelper helper;
  helper.Initialize(nullptr, nullptr, EnableGlobalReuseForUnownedMainFrames);

  WebLocalFrame* main_frame = helper.LocalMainFrame();
  v8::Isolate* isolate = helper.GetAgentGroupScheduler().Isolate();
  v8::HandleScope scope(isolate);
  main_frame->ExecuteScript(WebScriptSource("hello = 'world';"));
  frame_test_helpers::LoadFrame(main_frame, "data:text/html,new page");
  v8::Local<v8::Value> result =
      main_frame->ExecuteScriptAndReturnValue(WebScriptSource("hello"));
  ASSERT_TRUE(result->IsString());
  EXPECT_EQ("world",
            ToCoreString(isolate,
                         result->ToString(main_frame->MainWorldScriptContext())
                             .ToLocalChecked()));
}

// This class intercepts the registration of Blob instances.
//
// Given that the content of the Blob is known (data URL)
// it gets the data from the DataElement's BytesProvider, and creates
// FakeBlob's accordingly.
class BlobRegistryForSaveImageFromDataURL : public mojom::blink::BlobRegistry {
 public:
  void Register(mojo::PendingReceiver<mojom::blink::Blob> blob,
                const String& uuid,
                const String& content_type,
                const String& content_disposition,
                Vector<mojom::blink::DataElementPtr> elements,
                RegisterCallback callback) override {
    DCHECK_EQ(elements.size(), 1u);
    DCHECK(elements[0]->is_bytes());

    auto& element0 = elements[0];
    const auto& bytes = element0->get_bytes();
    auto length = bytes->length;
    String body(
        base::span(*bytes->embedded_data).first(static_cast<uint32_t>(length)));
    mojo::MakeSelfOwnedReceiver(std::make_unique<FakeBlob>(uuid, body),
                                std::move(blob));
    std::move(callback).Run();
  }

  void RegisterFromStream(
      const String& content_type,
      const String& content_disposition,
      uint64_t expected_length,
      mojo::ScopedDataPipeConsumerHandle,
      mojo::PendingAssociatedRemote<mojom::blink::ProgressClient>,
      RegisterFromStreamCallback) override {
    NOTREACHED();
  }
};

// blink::mojom::LocalFrameHost instance that intecepts DownloadURL() mojo
// calls and reads the blob data URL sent by the renderer accordingly.
class TestLocalFrameHostForSaveImageFromDataURL : public FakeLocalFrameHost {
 public:
  TestLocalFrameHostForSaveImageFromDataURL()
      : blob_registry_receiver_(
            &blob_registry_,
            blob_registry_remote_.BindNewPipeAndPassReceiver()) {
    BlobDataHandle::SetBlobRegistryForTesting(blob_registry_remote_.get());
  }
  ~TestLocalFrameHostForSaveImageFromDataURL() override {
    BlobDataHandle::SetBlobRegistryForTesting(nullptr);
  }

  // FakeLocalFrameHost:
  void DownloadURL(mojom::blink::DownloadURLParamsPtr params) override {
    mojo::Remote<mojom::blink::Blob> blob(std::move(params->data_url_blob));
    mojo::ScopedDataPipeProducerHandle producer_handle;
    mojo::ScopedDataPipeConsumerHandle consumer_handle;
    auto result =
        mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle);
    DCHECK(result == MOJO_RESULT_OK);

    blob->ReadAll(std::move(producer_handle), mojo::NullRemote());

    DataPipeDrainerClient client(&data_url_);
    auto data_pipe_drainer = std::make_unique<mojo::DataPipeDrainer>(
        &client, std::move(consumer_handle));
    client.Run();
  }

  const String& Result() const { return data_url_; }
  void Reset() { data_url_ = String(); }

 private:
  // Helper class to copy a blob to a string.
  class DataPipeDrainerClient : public mojo::DataPipeDrainer::Client {
   public:
    explicit DataPipeDrainerClient(String* output)
        : run_loop_(base::RunLoop::Type::kNestableTasksAllowed),
          output_(output) {}
    void Run() { run_loop_.Run(); }

    void OnDataAvailable(base::span<const uint8_t> data) override {
      *output_ = String(data);
    }
    void OnDataComplete() override { run_loop_.Quit(); }

   private:
    base::RunLoop run_loop_;
    String* output_;
  };

  BlobRegistryForSaveImageFromDataURL blob_registry_;
  mojo::Remote<mojom::blink::BlobRegistry> blob_registry_remote_;
  mojo::Receiver<mojom::blink::BlobRegistry> blob_registry_receiver_;

  // Data URL retrieved from the blob.
  String data_url_;
};

TEST_F(WebFrameTest, SaveImageAt) {
  std::string url = base_url_ + "image-with-data-url.html";
  // TODO(crbug.com/751425): We should use the mock functionality
  // via the WebViewHelper instance in each test case.
  RegisterMockedURLLoadFromBase(base_url_, "image-with-data-url.html");
  url_test_helpers::RegisterMockedURLLoad(
      ToKURL("http://test"), test::CoreTestDataPath("white-1x1.png"));

  TestLocalFrameHostForSaveImageFromDataURL frame_host;
  frame_test_helpers::TestWebFrameClient web_frame_client;
  frame_host.Init(web_frame_client.GetRemoteNavigationAssociatedInterfaces());
  frame_test_helpers::WebViewHelper web_view_helper;
  RunPendingTasks();

  WebViewImpl* web_view =
      web_view_helper.InitializeAndLoad(url, &web_frame_client);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(400, 400));
  UpdateAllLifecyclePhases(web_view);

  LocalFrame* local_frame = To<LocalFrame>(web_view->GetPage()->MainFrame());

  frame_host.Reset();
  local_frame->SaveImageAt(gfx::Point(1, 1));
  // Note that in this test does not use RunPendingTasks() since
  // TestLocalFrameHostForSaveImageFromDataURL trigger its own loops, so nesting
  // must be allowed.
  base::RunLoop(base::RunLoop::Type::kNestableTasksAllowed).RunUntilIdle();

  EXPECT_EQ(
      String::FromUTF8("data:image/gif;base64"
                       ",R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs="),
      frame_host.Result());

  frame_host.Reset();

  local_frame->SaveImageAt(gfx::Point(1, 2));
  base::RunLoop(base::RunLoop::Type::kNestableTasksAllowed).RunUntilIdle();
  EXPECT_EQ(String(), frame_host.Result());

  web_view->SetPageScaleFactor(4);
  web_view->SetVisualViewportOffset(gfx::PointF(1, 1));

  frame_host.Reset();
  local_frame->SaveImageAt(gfx::Point(3, 3));
  base::RunLoop(base::RunLoop::Type::kNestableTasksAllowed).RunUntilIdle();
  EXPECT_EQ(
      String::FromUTF8("data:image/gif;base64"
                       ",R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs="),
      frame_host.Result());

  // Explicitly reset to break dependency on locally scoped client.
  web_view_helper.Reset();
}

TEST_F(WebFrameTest, SaveImageWithImageMap) {
  std::string url = base_url_ + "image-map.html";
  // TODO(crbug.com/751425): We should use the mock functionality
  // via the WebViewHelper instance in each test case.
  RegisterMockedURLLoadFromBase(base_url_, "image-map.html");

  TestLocalFrameHostForSaveImageFromDataURL frame_host;
  frame_test_helpers::WebViewHelper helper;
  frame_test_helpers::TestWebFrameClient client;
  frame_host.Init(client.GetRemoteNavigationAssociatedInterfaces());
  WebViewImpl* web_view = helper.InitializeAndLoad(url, &client);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(400, 400));
  RunPendingTasks();

  LocalFrame* local_frame = To<LocalFrame>(web_view->GetPage()->MainFrame());

  frame_host.Reset();
  local_frame->SaveImageAt(gfx::Point(25, 25));
  base::RunLoop(base::RunLoop::Type::kNestableTasksAllowed).RunUntilIdle();
  EXPECT_EQ(
      String::FromUTF8("data:image/gif;base64"
                       ",R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs="),
      frame_host.Result());

  frame_host.Reset();
  local_frame->SaveImageAt(gfx::Point(75, 25));
  base::RunLoop(base::RunLoop::Type::kNestableTasksAllowed).RunUntilIdle();
  EXPECT_EQ(
      String::FromUTF8("data:image/gif;base64"
                       ",R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs="),
      frame_host.Result());

  frame_host.Reset();
  local_frame->SaveImageAt(gfx::Point(125, 25));
  base::RunLoop(base::RunLoop::Type::kNestableTasksAllowed).RunUntilIdle();
  EXPECT_EQ(String(), frame_host.Result());

  // Explicitly reset to break dependency on locally scoped client.
  helper.Reset();
}

TEST_F(WebFrameTest, CopyImageWithImageMap) {
  std::string url = base_url_ + "image-map.html";
  // TODO(crbug.com/751425): We should use the mock functionality
  // via the WebViewHelper instance in each test case.
  RegisterMockedURLLoadFromBase(base_url_, "image-map.html");

  TestLocalFrameHostForSaveImageFromDataURL frame_host;
  frame_test_helpers::WebViewHelper helper;
  frame_test_helpers::TestWebFrameClient client;
  frame_host.Init(client.GetRemoteNavigationAssociatedInterfaces());
  WebViewImpl* web_view = helper.InitializeAndLoad(url, &client);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(400, 400));
  RunPendingTasks();

  frame_host.Reset();
  LocalFrame* local_frame = To<LocalFrame>(web_view->GetPage()->MainFrame());
  local_frame->SaveImageAt(gfx::Point(25, 25));
  base::RunLoop(base::RunLoop::Type::kNestableTasksAllowed).RunUntilIdle();
  EXPECT_EQ(
      String::FromUTF8("data:image/gif;base64"
                       ",R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs="),
      frame_host.Result());

  frame_host.Reset();
  local_frame->SaveImageAt(gfx::Point(75, 25));
  base::RunLoop(base::RunLoop::Type::kNestableTasksAllowed).RunUntilIdle();
  EXPECT_EQ(
      String::FromUTF8("data:image/gif;base64"
                       ",R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs="),
      frame_host.Result());

  frame_host.Reset();
  local_frame->SaveImageAt(gfx::Point(125, 25));
  base::RunLoop(base::RunLoop::Type::kNestableTasksAllowed).RunUntilIdle();
  EXPECT_EQ(String(), frame_host.Result());
  // Explicitly reset to break dependency on locally scoped client.
  helper.Reset();
}

TEST_F(WebFrameTest, LoadJavascriptURLInNewFrame) {
  frame_test_helpers::WebViewHelper helper;
  helper.Initialize();

  std::string redirect_url = base_url_ + "foo.html";
  KURL javascript_url = ToKURL("javascript:location='" + redirect_url + "'");
  url_test_helpers::RegisterMockedURLLoad(ToKURL(redirect_url),
                                          test::CoreTestDataPath("foo.html"));
  helper.LocalMainFrame()->GetFrame()->LoadJavaScriptURL(javascript_url);
  RunPendingTasks();

  // The result of the JS url replaces the existing contents on the
  // Document, but the JS-triggered navigation should still occur.
  EXPECT_NE("", To<LocalFrame>(helper.GetWebView()->GetPage()->MainFrame())
                    ->GetDocument()
                    ->documentElement()
                    ->innerText());
  EXPECT_EQ(ToKURL(redirect_url),
            To<LocalFrame>(helper.GetWebView()->GetPage()->MainFrame())
                ->GetDocument()
                ->Url());
}

TEST_F(WebFrameTest, DiscardFrame) {
  DisableRendererSchedulerThrottling();
  RegisterMockedHttpURLLoad("foo.html");

  frame_test_helpers::WebViewHelper helper;
  helper.InitializeAndLoad(base_url_ + "foo.html");

  EXPECT_NE("", To<LocalFrame>(helper.GetWebView()->GetPage()->MainFrame())
                    ->GetDocument()
                    ->documentElement()
                    ->innerText());

  helper.LocalMainFrame()->GetFrame()->Discard();
  RunPendingTasks();

  // Discarding should replace the contents of the document.
  EXPECT_EQ("", To<LocalFrame>(helper.GetWebView()->GetPage()->MainFrame())
                    ->GetDocument()
                    ->documentElement()
                    ->innerText());
}

TEST_F(WebFrameTest, EmptyJavascriptFrameUrl) {
  std::string url = "data:text/html,<iframe src=\"javascript:''\"></iframe>";
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeAndLoad(url);
  RunPendingTasks();

  LocalFrame* child = To<LocalFrame>(
      helper.GetWebView()->GetPage()->MainFrame()->Tree().FirstChild());
  EXPECT_EQ(BlankURL(), child->GetDocument()->Url());
  EXPECT_EQ(BlankURL(), child->Loader().GetDocumentLoader()->Url());
}

class TestResourcePriorityWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  class ExpectedRequest {
   public:
    ExpectedRequest(const KURL& url, WebURLRequest::Priority priority)
        : url(url), priority(priority), seen(false) {}

    KURL url;
    WebURLRequest::Priority priority;
    bool seen;
  };

  TestResourcePriorityWebFrameClient() = default;
  ~TestResourcePriorityWebFrameClient() override = default;

  // frame_test_helpers::TestWebFrameClient:
  void FinalizeRequest(WebURLRequest& request) override {
    ExpectedRequest* expected_request = expected_requests_.at(request.Url());
    DCHECK(expected_request);
    EXPECT_EQ(expected_request->priority, request.GetPriority());
    expected_request->seen = true;
  }

  void AddExpectedRequest(const KURL& url, WebURLRequest::Priority priority) {
    expected_requests_.insert(url,
                              std::make_unique<ExpectedRequest>(url, priority));
  }

  void VerifyAllRequests() {
    for (const auto& request : expected_requests_)
      EXPECT_TRUE(request.value->seen);
  }

 private:
  HashMap<KURL, std::unique_ptr<ExpectedRequest>> expected_requests_;
};

// TODO(crbug.com/1314493): This test is flaky with the TimedHTMLParserBudget
// feature enabled.
TEST_F(WebFrameTest, DISABLED_ChangeResourcePriority) {
  TestResourcePriorityWebFrameClient client;
  RegisterMockedHttpURLLoad("promote_img_in_viewport_priority.html");
  RegisterMockedHttpURLLoad("image_slow.pl");
  RegisterMockedHttpURLLoad("image_slow_out_of_viewport.pl");
  client.AddExpectedRequest(ToKURL("http://internal.test/image_slow.pl"),
                            WebURLRequest::Priority::kLow);
  client.AddExpectedRequest(
      ToKURL("http://internal.test/image_slow_out_of_viewport.pl"),
      WebURLRequest::Priority::kLow);

  frame_test_helpers::WebViewHelper helper;
  helper.Initialize(&client);
  helper.Resize(gfx::Size(640, 480));
  frame_test_helpers::LoadFrame(
      helper.GetWebView()->MainFrameImpl(),
      base_url_ + "promote_img_in_viewport_priority.html");

  // Ensure the image in the viewport got promoted after the request was sent.
  Resource* image = To<WebLocalFrameImpl>(helper.GetWebView()->MainFrame())
                        ->GetFrame()
                        ->GetDocument()
                        ->Fetcher()
                        ->AllResources()
                        .at(ToKURL("http://internal.test/image_slow.pl"));
  DCHECK(image);
  EXPECT_EQ(ResourceLoadPriority::kHigh,
            image->GetResourceRequest().Priority());

  client.VerifyAllRequests();
}

TEST_F(WebFrameTest, ScriptPriority) {
  TestResourcePriorityWebFrameClient client;
  RegisterMockedHttpURLLoad("script_priority.html");
  RegisterMockedHttpURLLoad("priorities/defer.js");
  RegisterMockedHttpURLLoad("priorities/async.js");
  RegisterMockedHttpURLLoad("priorities/head.js");
  RegisterMockedHttpURLLoad("priorities/document-write.js");
  RegisterMockedHttpURLLoad("priorities/injected.js");
  RegisterMockedHttpURLLoad("priorities/injected-async.js");
  RegisterMockedHttpURLLoad("priorities/body.js");
  client.AddExpectedRequest(ToKURL("http://internal.test/priorities/defer.js"),
                            WebURLRequest::Priority::kLow);
  client.AddExpectedRequest(ToKURL("http://internal.test/priorities/async.js"),
                            WebURLRequest::Priority::kLow);
  client.AddExpectedRequest(ToKURL("http://internal.test/priorities/head.js"),
                            WebURLRequest::Priority::kHigh);
  client.AddExpectedRequest(
      ToKURL("http://internal.test/priorities/document-write.js"),
      WebURLRequest::Priority::kHigh);
  client.AddExpectedRequest(
      ToKURL("http://internal.test/priorities/injected.js"),
      WebURLRequest::Priority::kLow);
  client.AddExpectedRequest(
      ToKURL("http://internal.test/priorities/injected-async.js"),
      WebURLRequest::Priority::kLow);
  client.AddExpectedRequest(ToKURL("http://internal.test/priorities/body.js"),
                            WebURLRequest::Priority::kHigh);

  frame_test_helpers::WebViewHelper helper;
  helper.InitializeAndLoad(base_url_ + "script_priority.html", &client);
  client.VerifyAllRequests();
}

class MultipleDataChunkDelegate : public URLLoaderTestDelegate {
 public:
  MultipleDataChunkDelegate() = default;
  ~MultipleDataChunkDelegate() override = default;

  // URLLoaderTestDelegate:
  void DidReceiveData(URLLoaderClient* original_client,
                      base::span<const char> data) override {
    EXPECT_GT(data.size(), 16u);
    const auto [first, rest] = data.split_at<16>();
    original_client->DidReceiveDataForTesting(first);
    // This didReceiveData call shouldn't crash due to a failed assertion.
    original_client->DidReceiveDataForTesting(rest);
  }
};

TEST_F(WebFrameTest, ImageDocumentDecodeError) {
  std::string url = base_url_ + "not_an_image.ico";
  url_test_helpers::RegisterMockedURLLoad(
      ToKURL(url), test::CoreTestDataPath("not_an_image.ico"), "image/x-icon");
  MultipleDataChunkDelegate delegate;
  url_test_helpers::SetLoaderDelegate(&delegate);
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeAndLoad(url);
  url_test_helpers::SetLoaderDelegate(nullptr);

  Document* document =
      To<LocalFrame>(helper.GetWebView()->GetPage()->MainFrame())
          ->GetDocument();
  EXPECT_TRUE(IsA<ImageDocument>(document));
  EXPECT_EQ(ResourceStatus::kDecodeError,
            To<ImageDocument>(document)->CachedImage()->GetContentStatus());
}

// Ensure that the root LayoutView maintains a minimum height matching the
// viewport in cases where the content is smaller.
TEST_F(WebFrameTest, RootLayerMinimumHeight) {
  constexpr int kViewportWidth = 320;
  constexpr int kViewportHeight = 640;
  constexpr int kBrowserControlsHeight = 100;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, nullptr, ConfigureAndroid);
  WebViewImpl* web_view = web_view_helper.GetWebView();
  web_view->ResizeWithBrowserControls(
      gfx::Size(kViewportWidth, kViewportHeight - kBrowserControlsHeight),
      kBrowserControlsHeight, 0, true);

  InitializeWithHTML(
      *web_view->MainFrameImpl()->GetFrame(),
      "<!DOCTYPE html>"
      "<meta name='viewport' content='width=device-width, initial-scale=1'>"
      "<style>"
      "  html, body {width:100%;height:540px;margin:0px}"
      "  #elem {"
      "    overflow: scroll;"
      "    width: 100px;"
      "    height: 10px;"
      "    position: fixed;"
      "    left: 0px;"
      "    bottom: 0px;"
      "  }"
      "</style>"
      "<div id='elem'></div>");
  UpdateAllLifecyclePhases(web_view);

  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  LocalFrameView* frame_view = web_view->MainFrameImpl()->GetFrameView();
  const auto* layout_view = frame_view->GetLayoutView();
  EXPECT_EQ(kViewportHeight - kBrowserControlsHeight,
            layout_view->ViewRect().Height());
  EXPECT_EQ(kViewportHeight - kBrowserControlsHeight,
            layout_view->BackgroundRect().Height());

  document->View()->SetTracksRasterInvalidations(true);

  web_view->ResizeWithBrowserControls(
      gfx::Size(kViewportWidth, kViewportHeight), kBrowserControlsHeight, 0,
      false);
  UpdateAllLifecyclePhases(web_view);

  EXPECT_EQ(kViewportHeight, layout_view->ViewRect().Height());
  EXPECT_EQ(kViewportHeight, layout_view->BackgroundRect().Height());
}

// Load a page with display:none set and try to scroll it. It shouldn't crash
// due to lack of layoutObject. crbug.com/653327.
TEST_F(WebFrameTest, ScrollBeforeLayoutDoesntCrash) {
  RegisterMockedHttpURLLoad("display-none.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "display-none.html");
  WebViewImpl* web_view = web_view_helper.GetWebView();
  web_view_helper.Resize(gfx::Size(640, 480));

  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  document->documentElement()->SetLayoutObject(nullptr);

  WebGestureEvent begin_event(
      WebInputEvent::Type::kGestureScrollBegin, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), WebGestureDevice::kTouchpad);
  WebGestureEvent update_event(
      WebInputEvent::Type::kGestureScrollUpdate, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), WebGestureDevice::kTouchpad);
  WebGestureEvent end_event(
      WebInputEvent::Type::kGestureScrollEnd, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), WebGestureDevice::kTouchpad);

  // Try GestureScrollEnd and GestureScrollUpdate first to make sure that not
  // seeing a Begin first doesn't break anything. (This currently happens).
  auto* widget = web_view_helper.GetMainFrameWidget();
  widget->DispatchThroughCcInputHandler(end_event);
  widget->DispatchThroughCcInputHandler(update_event);
  web_view_helper.GetLayerTreeHost()->CompositeForTest(
      base::TimeTicks::Now(), false, base::OnceClosure());

  // Try a full Begin/Update/End cycle.
  widget->DispatchThroughCcInputHandler(begin_event);
  widget->DispatchThroughCcInputHandler(update_event);
  widget->DispatchThroughCcInputHandler(end_event);
  web_view_helper.GetLayerTreeHost()->CompositeForTest(
      base::TimeTicks::Now(), false, base::OnceClosure());
}

TEST_F(WebFrameTest, MouseOverDifferntNodeClearsTooltip) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();
  web_view_helper.Resize(gfx::Size(200, 200));
  WebViewImpl* web_view = web_view_helper.GetWebView();

  InitializeWithHTML(
      *web_view->MainFrameImpl()->GetFrame(),
      "<head>"
      "  <style type='text/css'>"
      "   div"
      "    {"
      "      width: 200px;"
      "      height: 100px;"
      "      background-color: #eeeeff;"
      "    }"
      "    div:hover"
      "    {"
      "      background-color: #ddddff;"
      "    }"
      "  </style>"
      "</head>"
      "<body>"
      "  <div id='div1' title='Title Attribute Value'>Hover HERE</div>"
      "  <div id='div2' title='Title Attribute Value'>Then HERE</div>"
      "  <br><br><br>"
      "</body>");
  UpdateAllLifecyclePhases(web_view);

  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  Element* div1_tag = document->getElementById(AtomicString("div1"));

  HitTestResult hit_test_result =
      web_view->MainFrameViewWidget()->CoreHitTestResultAt(
          gfx::PointF(div1_tag->OffsetLeft() + 5, div1_tag->OffsetTop() + 5));

  EXPECT_TRUE(hit_test_result.InnerElement());

  // Mouse over link. Mouse cursor should be hand.
  WebMouseEvent mouse_move_over_link_event(
      WebInputEvent::Type::kMouseMove,
      gfx::PointF(div1_tag->OffsetLeft() + 5, div1_tag->OffsetTop() + 5),
      gfx::PointF(div1_tag->OffsetLeft() + 5, div1_tag->OffsetTop() + 5),
      WebPointerProperties::Button::kNoButton, 0, WebInputEvent::kNoModifiers,
      base::TimeTicks::Now());
  mouse_move_over_link_event.SetFrameScale(1);
  document->GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_over_link_event, Vector<WebMouseEvent>(),
      Vector<WebMouseEvent>());

  EXPECT_EQ(
      document->HoverElement(),
      document->GetFrame()->GetChromeClient().LastSetTooltipNodeForTesting());
  EXPECT_EQ(
      div1_tag,
      document->GetFrame()->GetChromeClient().LastSetTooltipNodeForTesting());

  Element* div2_tag = document->getElementById(AtomicString("div2"));

  WebMouseEvent mouse_move_event(
      WebInputEvent::Type::kMouseMove,
      gfx::PointF(div2_tag->OffsetLeft() + 5, div2_tag->OffsetTop() + 5),
      gfx::PointF(div2_tag->OffsetLeft() + 5, div2_tag->OffsetTop() + 5),
      WebPointerProperties::Button::kNoButton, 0, WebInputEvent::kNoModifiers,
      base::TimeTicks::Now());
  mouse_move_event.SetFrameScale(1);
  document->GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());

  EXPECT_EQ(
      document->HoverElement(),
      document->GetFrame()->GetChromeClient().LastSetTooltipNodeForTesting());
  EXPECT_EQ(
      div2_tag,
      document->GetFrame()->GetChromeClient().LastSetTooltipNodeForTesting());
}

class WebFrameSimTest : public SimTest {
 public:
  void UseAndroidSettings() {
    WebView().GetPage()->GetSettings().SetViewportMetaEnabled(true);
    WebView().GetPage()->GetSettings().SetViewportEnabled(true);
    WebView().GetPage()->GetSettings().SetMainFrameResizesAreOrientationChanges(
        true);
    WebView().GetPage()->GetSettings().SetViewportStyle(
        mojom::blink::ViewportStyle::kMobile);
    WebView().GetSettings()->SetAutoZoomFocusedEditableToLegibleScale(true);
    WebView().GetSettings()->SetShrinksViewportContentToFit(true);
    WebView().SetDefaultPageScaleLimits(0.25f, 5);
  }
};

TEST_F(WebFrameSimTest, HitTestWithIgnoreClippingAtNegativeOffset) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);

  SimRequest r("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  r.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        body, html {
          width: 100%;
          height: 1000px;
          margin: 0;
        }
        #top {
          position: absolute;
          top: 500px;
          height: 100px;
          width: 100%;

        }
        #bottom {
          position: absolute;
          top: 600px;
          width: 100%;
          height: 500px;
        }
      </style>
      <div id="top"></div>
      <div id="bottom"></div>
  )HTML");

  Compositor().BeginFrame();

  auto* frame_view = To<LocalFrame>(WebView().GetPage()->MainFrame())->View();

  frame_view->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0, 600), mojom::blink::ScrollType::kProgrammatic);
  Compositor().BeginFrame();

  HitTestRequest request = HitTestRequest::kMove | HitTestRequest::kReadOnly |
                           HitTestRequest::kActive |
                           HitTestRequest::kIgnoreClipping;
  HitTestLocation location(
      frame_view->ConvertFromRootFrame(PhysicalOffset(100, -50)));
  HitTestResult result(request, location);
  frame_view->GetLayoutView()->HitTest(location, result);

  EXPECT_EQ(GetDocument().getElementById(AtomicString("top")),
            result.InnerNode());
}

TEST_F(WebFrameSimTest, TickmarksDocumentRelative) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        body, html {
          width: 4000px;
          height: 4000px;
          margin: 0;
        }
        div {
          position: absolute;
          left: 800px;
          top: 2000px;
        }
      </style>
      <div>test</div>
  )HTML");

  Compositor().BeginFrame();

  auto* frame = To<WebLocalFrameImpl>(WebView().MainFrame());
  auto* frame_view = To<LocalFrame>(WebView().GetPage()->MainFrame())->View();

  frame_view->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(3000, 1000), mojom::blink::ScrollType::kProgrammatic);
  auto options = mojom::blink::FindOptions::New();
  options->run_synchronously_for_testing = true;
  WebString search_text = WebString::FromUTF8("test");
  const int kFindIdentifier = 12345;
  EXPECT_TRUE(frame->GetFindInPage()->FindInternal(kFindIdentifier, search_text,
                                                   *options, false));

  frame->EnsureTextFinder().ResetMatchCount();
  frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                      search_text, *options);

  // Get the tickmarks for the original find request.
  Vector<gfx::Rect> original_tickmarks =
      frame_view->LayoutViewport()->GetTickmarks();
  EXPECT_EQ(1u, original_tickmarks.size());

  EXPECT_EQ(gfx::Point(800, 2000), original_tickmarks[0].origin());
}

#if BUILDFLAG(IS_ANDROID)
TEST_F(WebFrameSimTest, FindInPageSelectNextMatch) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        body, html {
          width: 4000px;
          height: 4000px;
          margin: 0;
        }
        #box1 {
          position: absolute;
          left: 800px;
          top: 2000px;
        }

        #box2 {
          position: absolute;
          left: 1000px;
          top: 3000px;
        }
      </style>
      <div id="box1">test</div>
      <div id="box2">test</div>
  )HTML");

  Compositor().BeginFrame();

  auto* frame = To<WebLocalFrameImpl>(WebView().MainFrame());
  auto* local_frame = To<LocalFrame>(WebView().GetPage()->MainFrame());
  auto* frame_view = local_frame->View();

  Element* box1 = GetDocument().getElementById(AtomicString("box1"));
  Element* box2 = GetDocument().getElementById(AtomicString("box2"));

  gfx::Rect box1_rect = box1->GetLayoutObject()->AbsoluteBoundingBoxRect();
  gfx::Rect box2_rect = box2->GetLayoutObject()->AbsoluteBoundingBoxRect();

  frame_view->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(3000, 1000), mojom::blink::ScrollType::kProgrammatic);
  auto options = mojom::blink::FindOptions::New();
  options->run_synchronously_for_testing = true;
  WebString search_text = WebString::FromUTF8("test"
```